// Copyright © 2026 Znewco, Inc. (d/b/a Zcash Open Development Lab)
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of ZODL OHTTP.
//
// ZODL OHTTP is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License,
// version 3 only, as published by the Free Software Foundation.
//
// ZODL OHTTP is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Affero General Public License for more details.
//
// Commercial licensing: see COMMERCIAL-LICENSE.md.

// HPKE (Hybrid Public Key Encryption) — RFC 9180, as used by OHTTP (RFC 9458)
//
// Cipher suite:
// - KEM:  DHKEM(X25519, HKDF-SHA256) (0x0020)
// - KDF:  HKDF-SHA256                (0x0001)
// - AEAD: AES-128-GCM                (0x0001)

use crate::config::Config;
use anyhow::{anyhow, Context, Result};
use hkdf::Hkdf;
use hpke::{
    aead::AesGcm128, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem, OpModeR,
    Serializable,
};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use tracing::{info, warn};

/// Opens one request chunk: `(ciphertext, aad) -> plaintext`.
pub(crate) type ChunkOpener = Box<dyn FnMut(&[u8], &[u8]) -> Result<Vec<u8>> + Send>;

type OhttpKem = X25519HkdfSha256;
type OhttpKdf = HkdfSha256;
type OhttpAead = AesGcm128;

pub const KEM_ID: u16 = 0x0020;
pub const KDF_ID: u16 = 0x0001;
pub const AEAD_ID: u16 = 0x0001;

/// AES-128-GCM key size (Nk).
pub const N_K: usize = 16;
/// AES-GCM nonce size (Nn).
pub const N_N: usize = 12;
/// X25519 encapsulated key size (Nenc).
pub const N_ENC: usize = 32;

struct SingleKey {
    key_id: u8,
    private_key: <OhttpKem as Kem>::PrivateKey,
    public_key: <OhttpKem as Kem>::PublicKey,
}

pub struct KeyState {
    /// The advertised keys. First key is the preferred key (advertised first in /ohttp-configs).
    keys: Vec<SingleKey>,
    /// HPKE_ACCEPT_ONLY_KEYS: accepted for decapsulation, never advertised (key rotation).
    accept_only: Vec<SingleKey>,
}

fn parse_key(key_id: u8, hex_key: &str, var: &str) -> Result<SingleKey> {
    let key_bytes = hex::decode(hex_key.trim())
        .with_context(|| format!("Invalid {} hex for key_id {}", var, key_id))?;
    let sk = <OhttpKem as Kem>::PrivateKey::from_bytes(&key_bytes).map_err(|_| {
        anyhow!(
            "Invalid X25519 private key in {} for key_id {} (expected 32 bytes)",
            var,
            key_id
        )
    })?;
    let pk = OhttpKem::sk_to_pk(&sk);
    Ok(SingleKey {
        key_id,
        private_key: sk,
        public_key: pk,
    })
}

/// Parses advertised keys in the `HPKE_KEYS` format, preferred first, and logs their public keys.
fn parse_advertised_keys(keys: &[(u8, String)]) -> Result<Vec<SingleKey>> {
    let parsed_keys = keys
        .iter()
        .map(|(key_id, hex_key)| parse_key(*key_id, hex_key, "HPKE_KEYS"))
        .collect::<Result<Vec<_>>>()?;
    info!("Loaded {} HPKE keys from HPKE_KEYS", parsed_keys.len());
    for key in &parsed_keys {
        info!(
            "  Key ID {}: {}",
            key.key_id,
            hex::encode(key.public_key.to_bytes())
        );
    }
    Ok(parsed_keys)
}

/// Per-request state needed to seal the chunked response (draft-ietf-ohai-chunked-ohttp-08 §6.2).
#[derive(Debug)]
pub struct ResponseContext {
    pub(crate) enc: Vec<u8>,
    pub(crate) secret: Vec<u8>,
}

impl KeyState {
    pub fn new(config: &Config) -> Result<Self> {
        Self::with_accept_only(config, &crate::config::hpke_accept_only_keys_from_env()?)
    }

    /// [`Self::new`] with `accept_only` as the HPKE_ACCEPT_ONLY_KEYS entries.
    pub fn with_accept_only(config: &Config, accept_only: &[(u8, String)]) -> Result<Self> {
        let keys = if !config.hpke_keys.is_empty() {
            // Multi-key mode (HPKE_KEYS takes precedence)
            parse_advertised_keys(&config.hpke_keys)?
        } else if let Some(hex_key) = &config.hpke_private_key {
            // Single-key mode (legacy compat)
            let key_bytes = hex::decode(hex_key.trim()).context("Invalid HPKE_PRIVATE_KEY hex")?;
            let sk = <OhttpKem as Kem>::PrivateKey::from_bytes(&key_bytes)
                .map_err(|_| anyhow!("Invalid X25519 private key (expected 32 bytes)"))?;
            let pk = OhttpKem::sk_to_pk(&sk);
            info!(
                "Loaded HPKE private key from HPKE_PRIVATE_KEY (key_id {})",
                config.hpke_key_id
            );
            info!("HPKE public key: {}", hex::encode(pk.to_bytes()));
            vec![SingleKey {
                key_id: config.hpke_key_id,
                private_key: sk,
                public_key: pk,
            }]
        } else {
            // In OHTTP mode ephemeral keys are a misconfiguration: persistent keys are required
            if config.mode == "ohttp" {
                anyhow::bail!(
                    "HPKE_KEYS (or HPKE_PRIVATE_KEY) is required in OHTTP mode. \
                     Ephemeral keys force clients to re-fetch /ohttp-configs after every restart, \
                     breaking the production threat model. Generate a persistent key: openssl rand -hex 32"
                );
            }

            // Ephemeral mode (proxy mode only, for testing)
            let mut sk_bytes = [0u8; 32];
            OsRng.fill_bytes(&mut sk_bytes);
            let sk = <OhttpKem as Kem>::PrivateKey::from_bytes(&sk_bytes)
                .map_err(|_| anyhow!("Failed to derive X25519 private key"))?;
            let pk = OhttpKem::sk_to_pk(&sk);
            warn!("HPKE_PRIVATE_KEY not set — generated ephemeral keypair (testing only, clients must re-fetch /ohttp-configs after every restart)");
            info!(
                "HPKE public key (ephemeral): {}",
                hex::encode(pk.to_bytes())
            );
            vec![SingleKey {
                key_id: config.hpke_key_id,
                private_key: sk,
                public_key: pk,
            }]
        };

        Self::from_parsed(keys, accept_only)
    }

    /// A key state for a caller that has the key lists at hand but no [`Config`], such as a test
    /// or a crate that embeds the gateway: `keys` are the advertised keys, preferred first, and
    /// `accept_only` the keys accepted for decapsulation but not advertised (the "accept" and
    /// "wait" steps of a key rotation), each as `(key_id, hex X25519 private key)`, in the
    /// formats of `HPKE_KEYS` and `HPKE_ACCEPT_ONLY_KEYS`.
    ///
    /// Reads no environment variable, and never generates a key: `keys` must hold at least one
    /// key, and every key id must be distinct across both lists. [`Self::new`] and
    /// [`Self::with_accept_only`] check their keys the same way.
    pub fn from_keys(keys: &[(u8, String)], accept_only: &[(u8, String)]) -> Result<Self> {
        Self::from_parsed(parse_advertised_keys(keys)?, accept_only)
    }

    /// The checks every constructor shares: at least one advertised key, the accept-only keys
    /// parsed, and no key id twice.
    fn from_parsed(keys: Vec<SingleKey>, accept_only: &[(u8, String)]) -> Result<Self> {
        if keys.is_empty() {
            anyhow::bail!("No HPKE keys configured (HPKE_KEYS or HPKE_PRIVATE_KEY required)");
        }

        let accept_only = accept_only
            .iter()
            .map(|(key_id, hex_key)| parse_key(*key_id, hex_key, "HPKE_ACCEPT_ONLY_KEYS"))
            .collect::<Result<Vec<_>>>()?;
        for key in &accept_only {
            info!(
                "  Key ID {} (accepted, not advertised): {}",
                key.key_id,
                hex::encode(key.public_key.to_bytes())
            );
        }

        // Check for duplicate key IDs, advertised and accept-only together: a request names its
        // key by id only.
        let mut seen_ids = std::collections::HashSet::new();
        for key in keys.iter().chain(&accept_only) {
            if !seen_ids.insert(key.key_id) {
                anyhow::bail!(
                    "Duplicate key_id {} in HPKE_KEYS / HPKE_ACCEPT_ONLY_KEYS",
                    key.key_id
                );
            }
        }

        Ok(Self { keys, accept_only })
    }

    #[allow(dead_code)] // Reserved for future logging/debugging use
    pub fn key_id(&self) -> u8 {
        // Return the preferred key (first in the list)
        self.keys[0].key_id
    }

    /// `application/ohttp-keys` document (RFC 9458 §3.1): all advertised key configs (accept-only
    /// keys are not listed), length-prefixed.
    ///
    /// Each key config (43 bytes for x25519/HKDF-SHA256/AES-128-GCM):
    /// ```text
    /// Length(16) || Key ID(8) || KEM ID(16) || Public Key(32 bytes)
    ///            || Symmetric Algorithms Length(16) || (KDF ID(16) || AEAD ID(16))*
    /// ```
    ///
    /// The first key is the preferred key (RFC 9458 §3.1: "The first entry... SHOULD be selected").
    pub fn public_config(&self) -> Vec<u8> {
        let mut doc = Vec::new();

        for key in &self.keys {
            let mut key_config = Vec::with_capacity(41);
            key_config.push(key.key_id);
            key_config.extend_from_slice(&KEM_ID.to_be_bytes());
            key_config.extend_from_slice(&key.public_key.to_bytes());
            key_config.extend_from_slice(&4u16.to_be_bytes()); // one symmetric suite = 4 bytes
            key_config.extend_from_slice(&KDF_ID.to_be_bytes());
            key_config.extend_from_slice(&AEAD_ID.to_be_bytes());

            // Length-prefix this key config
            doc.extend_from_slice(&(key_config.len() as u16).to_be_bytes());
            doc.extend_from_slice(&key_config);
        }

        doc
    }

    /// The advertised key ids, preferred first.
    pub fn key_ids(&self) -> Vec<u8> {
        self.keys.iter().map(|k| k.key_id).collect()
    }

    /// The ids of the keys accepted but not advertised (HPKE_ACCEPT_ONLY_KEYS).
    pub fn accept_only_key_ids(&self) -> Vec<u8> {
        self.accept_only.iter().map(|k| k.key_id).collect()
    }

    /// First 16 hex characters of SHA-256 of [`Self::public_config`]: a quick check that origins
    /// advertise the same key document (logged at startup, `ohttp_key_config_info`).
    pub fn fingerprint(&self) -> String {
        use sha2::Digest;
        let digest = Sha256::digest(self.public_config());
        hex::encode(&digest[..8])
    }

    /// Decapsulate chunked request header and return context for chunk decryption.
    /// This is a helper for ohttp_chunked to avoid exposing HPKE context types.
    pub(crate) fn setup_chunked_decapsulation(
        &self,
        key_id: u8,
        hdr: &[u8],
        enc: &[u8],
    ) -> Result<(ChunkOpener, Vec<u8>)> {
        let key = self
            .keys
            .iter()
            .chain(&self.accept_only)
            .find(|k| k.key_id == key_id)
            .ok_or_else(|| {
                anyhow!(
                    "Unknown key_id {} (configured keys: {:?}, accept-only: {:?})",
                    key_id,
                    self.key_ids(),
                    self.accept_only_key_ids()
                )
            })?;

        let mut info = Vec::with_capacity(36);
        info.extend_from_slice(b"message/bhttp chunked request");
        info.push(0x00);
        info.extend_from_slice(hdr);

        let encapped_key = <OhttpKem as Kem>::EncappedKey::from_bytes(enc)
            .map_err(|_| anyhow!("Invalid encapsulated key"))?;

        let mut ctx = hpke::setup_receiver::<OhttpAead, OhttpKdf, OhttpKem>(
            &OpModeR::Base,
            &key.private_key,
            &encapped_key,
            &info,
        )
        .map_err(|e| anyhow!("HPKE setup_receiver failed: {:?}", e))?;

        // Export secret for response encryption
        let response_label = b"message/bhttp chunked response";
        let mut secret = vec![0u8; N_K];
        ctx.export(response_label, &mut secret)
            .map_err(|e| anyhow!("HPKE export failed: {:?}", e))?;

        // Return a closure that captures the context
        let open_fn = Box::new(move |ciphertext: &[u8], aad: &[u8]| {
            ctx.open(ciphertext, aad)
                .map_err(|e| anyhow!("HPKE open failed: {:?}", e))
        });

        Ok((open_fn, secret))
    }
}

impl ResponseContext {
    /// Derive AEAD key and nonce for chunked response encryption (draft-ietf-ohai-chunked-ohttp-08 §6.2).
    ///
    /// ```text
    /// secret = context.Export("message/bhttp chunked response", Nk)
    /// salt = enc || response_nonce
    /// prk = Extract(salt, secret)
    /// aead_key = Expand(prk, "key", Nk)
    /// aead_nonce = Expand(prk, "nonce", Nn)
    /// ```
    pub fn derive_chunked_keys(&self, response_nonce: &[u8]) -> Result<([u8; N_K], [u8; N_N])> {
        let mut salt = self.enc.clone();
        salt.extend_from_slice(response_nonce);

        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &self.secret);
        let mut aead_key = [0u8; N_K];
        hkdf.expand(b"key", &mut aead_key)
            .map_err(|_| anyhow!("HKDF expand (key) failed"))?;
        let mut aead_nonce = [0u8; N_N];
        hkdf.expand(b"nonce", &mut aead_nonce)
            .map_err(|_| anyhow!("HKDF expand (nonce) failed"))?;

        Ok((aead_key, aead_nonce))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config {
            port: 8080,
            lwd_addr: "".to_string(),
            mode: "ohttp".to_string(),
            relay_secrets: vec![],
            hpke_private_key: None,
            hpke_key_id: 1,
            hpke_keys: vec![],
            lwd_timeout_secs: 80,
            long_poll_max_initial_silence_secs: 25,
            long_poll_idle_secs: 3,
            sse_keepalive_secs: 20,
            redis_url: "".to_string(),
            redis_security_url: "".to_string(),
            cache_local_redis_url: String::new(),
            backends: std::collections::HashMap::new(),
            backend_headers: std::collections::HashMap::new(),
            backends_policy: std::collections::HashMap::new(),
            backends_policy_default_allow: false,
            max_inflight_lwd: 128,
            max_inflight_lwd_heavy: 32,
            lwd_heavy_block_range: 100,
            redis_op_timeout_ms: 250,
            max_cache_get_concurrency: 64,
            max_large_response_concurrency: 2,
            large_response_threshold: 8 * 1024 * 1024,
            max_upstream_response_bytes: 64 * 1024 * 1024,
            max_inflight_upstream: 256,
            max_inflight_per_backend: 64,
            max_block_range: 1000,
            allow_unauthenticated_relay: false,
            proxy_allow_suffixes: vec![],
            network: "testnet".to_string(),
            log_outer_header_names: false,
            gateway_hosts: vec![],
            configs_signing_seed: None,
            chunk_size: 16384,
            chunk_flush_ms: 50,
            flexa_publishable_key: None,
            flexa_alias: None,
            near_alias: None,
            relay_secret_on_key_config: crate::config::RelaySecretOnKeyConfig::Off,
            lwd_permit_wait_ms: 2000,
            lwd_permit_max_waiters: 0,
        }
    }

    /// A request whose first chunk declares a huge length must be refused, not allocated: a
    /// declared length such as `varint(2^62 - 1)` must not reach an allocation.
    #[tokio::test]
    async fn test_chunked_request_with_a_huge_declared_chunk_is_refused() {
        let mut config = test_config();
        config.hpke_keys = vec![(
            1,
            "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
        )];
        let state = KeyState::new(&config).unwrap();
        let doc = state.public_config();
        // key_id || kem 0x0020 || kdf 0x0001 || aead 0x0001 || enc (the gateway's own public key,
        // a valid X25519 point), then an 8-byte varint with the largest value.
        let mut body = vec![doc[2], 0x00, 0x20, 0x00, 0x01, 0x00, 0x01];
        body.extend_from_slice(&doc[5..37]);
        body.extend_from_slice(&[0xff; 8]);
        let result =
            crate::ohttp_chunked::decapsulate_chunked_request(std::io::Cursor::new(body), &state)
                .await;
        assert!(result.is_err(), "a huge declared chunk must be refused");
    }

    /// Key rotation: an accept-only key opens requests but is not in `/ohttp-configs`, so it can be
    /// accepted before it is advertised and after it stops being advertised.
    #[test]
    fn test_accept_only_keys_decapsulate_but_are_not_advertised() {
        let key1_hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let key2_hex = "0000000000000000000000000000000000000000000000000000000000000002";
        let mut config = test_config();
        config.hpke_keys = vec![(1, key1_hex.to_string())];
        let only1 = KeyState::with_accept_only(&config, &[]).unwrap();
        let both = KeyState::with_accept_only(&config, &[(2, key2_hex.to_string())]).unwrap();
        assert_eq!(
            both.public_config(),
            only1.public_config(),
            "key 2 is not advertised"
        );
        assert_eq!(both.fingerprint(), only1.fingerprint());
        assert_eq!(both.key_ids(), vec![1]);
        assert_eq!(both.accept_only_key_ids(), vec![2]);

        config.hpke_keys = vec![(2, key2_hex.to_string())];
        let key2_doc = KeyState::with_accept_only(&config, &[])
            .unwrap()
            .public_config();
        let enc = &key2_doc[5..37];
        let hdr = [2u8, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01];
        assert!(both.setup_chunked_decapsulation(2, &hdr, enc).is_ok());
        assert!(only1.setup_chunked_decapsulation(2, &hdr, enc).is_err());
        assert!(both.setup_chunked_decapsulation(3, &hdr, enc).is_err());

        // One id names one key.
        config.hpke_keys = vec![(1, key1_hex.to_string())];
        assert!(KeyState::with_accept_only(&config, &[(1, key2_hex.to_string())]).is_err());
    }

    /// `from_keys` builds the same key state as a `Config` with the same keys, without a `Config`
    /// or the environment, and applies the same checks.
    #[test]
    fn test_from_keys_matches_the_config_constructor() {
        let key1_hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let key2_hex = "0000000000000000000000000000000000000000000000000000000000000002";
        let key3_hex = "0000000000000000000000000000000000000000000000000000000000000003";
        let keys = vec![(1, key1_hex.to_string()), (2, key2_hex.to_string())];
        let accept_only = vec![(3, key3_hex.to_string())];
        let mut config = test_config();
        config.hpke_keys = keys.clone();
        let via_config = KeyState::with_accept_only(&config, &accept_only).unwrap();
        let direct = KeyState::from_keys(&keys, &accept_only).unwrap();
        assert_eq!(direct.public_config(), via_config.public_config());
        assert_eq!(direct.key_ids(), vec![1, 2], "preferred key first");
        assert_eq!(direct.accept_only_key_ids(), vec![3]);

        // At least one advertised key, never an ephemeral one.
        assert!(KeyState::from_keys(&[], &[]).is_err());
        assert!(KeyState::from_keys(&[], &accept_only).is_err());
        // One id names one key, across both lists.
        assert!(KeyState::from_keys(&keys, &[(2, key3_hex.to_string())]).is_err());
        assert!(KeyState::from_keys(&[(1, key1_hex.into()), (1, key2_hex.into())], &[]).is_err());
        // Malformed keys are refused.
        assert!(KeyState::from_keys(&[(1, "zz".into())], &[]).is_err());
        assert!(KeyState::from_keys(&[(1, "00".into())], &[]).is_err());
    }

    #[test]
    fn test_fingerprint_follows_the_key_document() {
        let key1_hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let key2_hex = "0000000000000000000000000000000000000000000000000000000000000002";
        let mk = |keys: Vec<(u8, String)>| {
            let mut config = test_config();
            config.hpke_keys = keys;
            KeyState::new(&config).unwrap()
        };
        let a = mk(vec![(0, key1_hex.to_string()), (1, key2_hex.to_string())]);
        let b = mk(vec![(0, key1_hex.to_string()), (1, key2_hex.to_string())]);
        assert_eq!(a.fingerprint().len(), 16);
        assert_eq!(
            a.fingerprint(),
            b.fingerprint(),
            "same keys, same fingerprint"
        );
        // Another key, another key id, or another order: a client would get a different document.
        assert_ne!(
            a.fingerprint(),
            mk(vec![(0, key1_hex.to_string())]).fingerprint()
        );
        assert_ne!(
            a.fingerprint(),
            mk(vec![(1, key1_hex.to_string()), (0, key2_hex.to_string())]).fingerprint()
        );
        assert_ne!(
            a.fingerprint(),
            mk(vec![(1, key2_hex.to_string()), (0, key1_hex.to_string())]).fingerprint()
        );
        {
            use sha2::Digest;
            assert_eq!(
                a.fingerprint(),
                hex::encode(&Sha256::digest(a.public_config())[..8])
            );
        }
    }

    #[test]
    fn test_multi_key_config() {
        let key1_hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let key2_hex = "0000000000000000000000000000000000000000000000000000000000000002";

        let config = Config {
            port: 8080,
            lwd_addr: "".to_string(),
            mode: "ohttp".to_string(),
            relay_secrets: vec![],
            hpke_private_key: None,
            hpke_key_id: 1,
            hpke_keys: vec![(0, key1_hex.to_string()), (1, key2_hex.to_string())],
            lwd_timeout_secs: 80,
            long_poll_max_initial_silence_secs: 25,
            long_poll_idle_secs: 3,
            sse_keepalive_secs: 20,
            redis_url: "".to_string(),
            redis_security_url: "".to_string(),
            cache_local_redis_url: String::new(),
            backends: std::collections::HashMap::new(),
            backend_headers: std::collections::HashMap::new(),
            backends_policy: std::collections::HashMap::new(),
            backends_policy_default_allow: false,
            max_inflight_lwd: 128,
            max_inflight_lwd_heavy: 32,
            lwd_heavy_block_range: 100,
            redis_op_timeout_ms: 250,
            max_cache_get_concurrency: 64,
            max_large_response_concurrency: 2,
            large_response_threshold: 8 * 1024 * 1024,
            max_upstream_response_bytes: 64 * 1024 * 1024,
            max_inflight_upstream: 256,
            max_inflight_per_backend: 64,
            max_block_range: 1000,
            allow_unauthenticated_relay: false,
            proxy_allow_suffixes: vec![],
            network: "testnet".to_string(),
            log_outer_header_names: false,
            gateway_hosts: vec![],
            configs_signing_seed: None,
            chunk_size: 16384,
            chunk_flush_ms: 50,
            flexa_publishable_key: None,
            flexa_alias: None,
            near_alias: None,
            relay_secret_on_key_config: crate::config::RelaySecretOnKeyConfig::Off,
            lwd_permit_wait_ms: 2000,
            lwd_permit_max_waiters: 0,
        };

        let state = KeyState::new(&config).unwrap();
        assert_eq!(state.keys.len(), 2);
        assert_eq!(state.keys[0].key_id, 0);
        assert_eq!(state.keys[1].key_id, 1);
        assert_eq!(state.key_id(), 0); // First key is preferred

        // public_config should contain both keys (2 × 43 bytes = 86 bytes)
        let doc = state.public_config();
        assert_eq!(doc.len(), 2 * 43);

        // First key config length prefix (2 bytes)
        let len1 = u16::from_be_bytes([doc[0], doc[1]]);
        assert_eq!(len1, 41);
        // First key ID
        assert_eq!(doc[2], 0);

        // Second key config starts at byte 43
        let len2 = u16::from_be_bytes([doc[43], doc[44]]);
        assert_eq!(len2, 41);
        // Second key ID
        assert_eq!(doc[45], 1);
    }

    #[test]
    fn test_decapsulate_with_second_key() {
        // The chunked decapsulation looks the request's key id up in the whole ring, not just
        // the preferred key; an id outside the ring is the "Unknown key_id" error.
        let key1_hex = "a000000000000000000000000000000000000000000000000000000000000001";
        let key2_hex = "b000000000000000000000000000000000000000000000000000000000000002";

        let config = Config {
            port: 8080,
            lwd_addr: "".to_string(),
            mode: "ohttp".to_string(),
            relay_secrets: vec![],
            hpke_private_key: None,
            hpke_key_id: 1,
            hpke_keys: vec![(5, key1_hex.to_string()), (10, key2_hex.to_string())],
            lwd_timeout_secs: 80,
            long_poll_max_initial_silence_secs: 25,
            long_poll_idle_secs: 3,
            sse_keepalive_secs: 20,
            redis_url: "".to_string(),
            redis_security_url: "".to_string(),
            cache_local_redis_url: String::new(),
            backends: std::collections::HashMap::new(),
            backend_headers: std::collections::HashMap::new(),
            backends_policy: std::collections::HashMap::new(),
            backends_policy_default_allow: false,
            max_inflight_lwd: 128,
            max_inflight_lwd_heavy: 32,
            lwd_heavy_block_range: 100,
            redis_op_timeout_ms: 250,
            max_cache_get_concurrency: 64,
            max_large_response_concurrency: 2,
            large_response_threshold: 8 * 1024 * 1024,
            max_upstream_response_bytes: 64 * 1024 * 1024,
            max_inflight_upstream: 256,
            max_inflight_per_backend: 64,
            max_block_range: 1000,
            allow_unauthenticated_relay: false,
            proxy_allow_suffixes: vec![],
            network: "testnet".to_string(),
            log_outer_header_names: false,
            gateway_hosts: vec![],
            configs_signing_seed: None,
            chunk_size: 16384,
            chunk_flush_ms: 50,
            flexa_publishable_key: None,
            flexa_alias: None,
            near_alias: None,
            relay_secret_on_key_config: crate::config::RelaySecretOnKeyConfig::Off,
            lwd_permit_wait_ms: 2000,
            lwd_permit_max_waiters: 0,
        };

        let state = KeyState::new(&config).unwrap();

        let hdr = [10, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01]; // key_id=10, rest is KEM/KDF/AEAD
        let enc = vec![0u8; 32]; // Not a usable encapsulated key, but the key lookup happens first.
        if let Err(e) = state.setup_chunked_decapsulation(10, &hdr, &enc) {
            assert!(!e.to_string().contains("Unknown key_id"), "{e}");
        }
        let unknown = state
            .setup_chunked_decapsulation(99, &[99, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01], &enc)
            .err()
            .expect("an unknown key id is refused");
        assert!(unknown.to_string().contains("Unknown key_id"), "{unknown}");
    }
}

#[test]
fn test_duplicate_key_ids_rejected() {
    let key1_hex = "a000000000000000000000000000000000000000000000000000000000000001";
    let config = Config {
        port: 8080,
        lwd_addr: "".to_string(),
        mode: "ohttp".to_string(),
        relay_secrets: vec![],
        hpke_private_key: None,
        hpke_key_id: 1,
        hpke_keys: vec![(5, key1_hex.to_string()), (5, key1_hex.to_string())],
        lwd_timeout_secs: 80,
        long_poll_max_initial_silence_secs: 25,
        long_poll_idle_secs: 3,
        sse_keepalive_secs: 20,
        redis_url: "".to_string(),
        redis_security_url: "".to_string(),
            cache_local_redis_url: String::new(),
        backends: std::collections::HashMap::new(),
        backend_headers: std::collections::HashMap::new(),
        backends_policy: std::collections::HashMap::new(),
        backends_policy_default_allow: false,
        max_inflight_lwd: 128,
        max_inflight_lwd_heavy: 32,
        lwd_heavy_block_range: 100,
        redis_op_timeout_ms: 250,
        max_cache_get_concurrency: 64,
        max_large_response_concurrency: 2,
        large_response_threshold: 8 * 1024 * 1024,
        max_upstream_response_bytes: 64 * 1024 * 1024,
        max_inflight_upstream: 256,
        max_inflight_per_backend: 64,
        max_block_range: 1000,
        allow_unauthenticated_relay: false,
        proxy_allow_suffixes: vec![],
        network: "testnet".to_string(),
        log_outer_header_names: false,
        gateway_hosts: vec![],
        configs_signing_seed: None,
        chunk_size: 16384,
        chunk_flush_ms: 50,
        flexa_publishable_key: None,
        flexa_alias: None,
        near_alias: None,
        relay_secret_on_key_config: crate::config::RelaySecretOnKeyConfig::Off,
        lwd_permit_wait_ms: 2000,
        lwd_permit_max_waiters: 0,
    };

    let result = KeyState::new(&config);
    assert!(result.is_err());
    let err_msg = format!("{:?}", result.err().unwrap());
    assert!(err_msg.contains("Duplicate key_id"));
}

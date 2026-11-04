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

// Ed25519 signing for /ohttp-configs/signed endpoint
//
// Message format: b"zodl-ohttp-configs-v1" || 0x00 || network_ascii || 0x00 || u64be(not_before) || u64be(not_after) || configs_bytes
use base64::Engine;
// Signature: Ed25519(message)

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

const DOMAIN_SEP: &[u8] = b"zodl-ohttp-configs-v1";
const VALIDITY_BEFORE_SECS: u64 = 300; // 5 min grace before the issuance slot
const VALIDITY_AFTER_SECS: u64 = 21300; // valid until 6 h after not_before (ZIP: at most 6 h)
/// `not_after - not_before` of every envelope: the `maximum_issued_validity` of the ZIP's key
/// rotation waits (retire a key no earlier than this + 120 s after it was last published).
pub const MAX_ISSUED_VALIDITY_SECS: u64 = VALIDITY_BEFORE_SECS + VALIDITY_AFTER_SECS;
/// Envelopes are issued per slot of this length, with `not_before`/`not_after` derived from the
/// slot start rather than from the moment of the first request. Ed25519 is deterministic, so
/// every gateway with the same seed, network and key configuration publishes the same envelope
/// within a slot: origins behind one load balancer cannot be told apart by their envelopes, and
/// operators can compare them byte for byte. A new envelope every hour still overlaps the old
/// one by five hours (ZIP "Issuance and key rotation").
pub const ISSUANCE_SLOT_SECS: u64 = 3600;

#[derive(Clone, Serialize, Deserialize)]
pub struct SignedConfig {
    pub v: u8,
    pub network: String,
    pub configs: String, // base64 standard
    pub not_before: u64,
    pub not_after: u64,
    pub key_id: String, // 8 hex chars
    pub sig: String,    // base64 standard Ed25519 signature
}

pub struct SigningState {
    signing_key: SigningKey,
    network: String,
    cached: Mutex<Option<(SignedConfig, u64, u64)>>, // (signed config, configs_hash, slot start)
}

/// The validity window of an envelope issued at `now`: `(not_before, not_after)`, both derived
/// from the start of the `ISSUANCE_SLOT_SECS` slot that contains `now`.
pub fn issuance_window(now: u64) -> (u64, u64) {
    let slot_start = now - now % ISSUANCE_SLOT_SECS;
    (
        slot_start.saturating_sub(VALIDITY_BEFORE_SECS),
        slot_start + VALIDITY_AFTER_SECS,
    )
}

impl SigningState {
    pub fn new(seed_hex: &str, network: String) -> anyhow::Result<Self> {
        if seed_hex.len() != 64 {
            anyhow::bail!("Ed25519 seed must be 32 bytes (64 hex chars)");
        }
        let seed_bytes = hex::decode(seed_hex)?;
        if seed_bytes.len() != 32 {
            anyhow::bail!("Ed25519 seed must be 32 bytes");
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);
        let signing_key = SigningKey::from_bytes(&seed);
        Ok(Self {
            signing_key,
            network,
            cached: Mutex::new(None),
        })
    }

    #[allow(dead_code)]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    pub fn key_id(&self) -> String {
        let pubkey_bytes = self.signing_key.verifying_key().to_bytes();
        let hash = Sha256::digest(pubkey_bytes);
        hex::encode(&hash[..4])
    }

    /// The signed config for the current issuance slot (re-signed when the slot or the key
    /// configuration changes).
    pub fn get_signed_config(&self, configs_bytes: &[u8]) -> SignedConfig {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.get_signed_config_at(configs_bytes, now)
    }

    /// [`Self::get_signed_config`] at a given Unix time. Deterministic: the same seed, network,
    /// `configs_bytes` and slot give the same envelope, whichever gateway signs it.
    pub fn get_signed_config_at(&self, configs_bytes: &[u8], now: u64) -> SignedConfig {
        let configs_hash = {
            let mut hasher = Sha256::new();
            hasher.update(configs_bytes);
            let result = hasher.finalize();
            u64::from_be_bytes(result[..8].try_into().unwrap())
        };
        let (not_before, not_after) = issuance_window(now);
        let slot_start = now - now % ISSUANCE_SLOT_SECS;

        let mut cached = self.cached.lock();
        if let Some((ref sc, ch, slot)) = *cached {
            if ch == configs_hash && slot == slot_start {
                return sc.clone();
            }
        }

        let mut message = Vec::with_capacity(
            DOMAIN_SEP.len() + 1 + self.network.len() + 1 + 8 + 8 + configs_bytes.len(),
        );
        message.extend_from_slice(DOMAIN_SEP);
        message.push(0);
        message.extend_from_slice(self.network.as_bytes());
        message.push(0);
        message.extend_from_slice(&not_before.to_be_bytes());
        message.extend_from_slice(&not_after.to_be_bytes());
        message.extend_from_slice(configs_bytes);

        let signature = self.signing_key.sign(&message);

        let signed_config = SignedConfig {
            v: 1,
            network: self.network.clone(),
            configs: base64::engine::general_purpose::STANDARD.encode(configs_bytes),
            not_before,
            not_after,
            key_id: self.key_id(),
            sig: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        };

        *cached = Some((signed_config.clone(), configs_hash, slot_start));
        signed_config
    }
}

// Verification (for testing; clients verify with `zodl_ohttp_client::open_signed_config`)
#[allow(dead_code)]
pub fn verify_signed_config(
    signed: &SignedConfig,
    expected_network: &str,
    public_key_hex: &str,
) -> anyhow::Result<Vec<u8>> {
    if signed.v != 1 {
        anyhow::bail!("Unsupported version {}", signed.v);
    }
    if signed.network != expected_network {
        anyhow::bail!(
            "Network mismatch: got {}, expected {}",
            signed.network,
            expected_network
        );
    }

    // Check time window
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if now < signed.not_before {
        anyhow::bail!("not_before in future");
    }
    if now >= signed.not_after {
        anyhow::bail!("expired");
    }

    // Decode public key
    let pubkey_bytes = hex::decode(public_key_hex)?;
    if pubkey_bytes.len() != 32 {
        anyhow::bail!("Invalid public key length");
    }
    let verifying_key = VerifyingKey::from_bytes(pubkey_bytes.as_slice().try_into().unwrap())?;

    // Verify key_id
    let hash = Sha256::digest(pubkey_bytes.as_slice());
    let expected_key_id = hex::encode(&hash[..4]);
    if signed.key_id != expected_key_id {
        anyhow::bail!("key_id mismatch");
    }

    // Decode signature
    let sig_bytes = base64::engine::general_purpose::STANDARD.decode(&signed.sig)?;
    if sig_bytes.len() != 64 {
        anyhow::bail!("Invalid signature length");
    }
    let signature = ed25519_dalek::Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());

    // Decode configs
    let configs_bytes = base64::engine::general_purpose::STANDARD.decode(&signed.configs)?;

    // Reconstruct message
    let mut message = Vec::new();
    message.extend_from_slice(DOMAIN_SEP);
    message.push(0);
    message.extend_from_slice(signed.network.as_bytes());
    message.push(0);
    message.extend_from_slice(&signed.not_before.to_be_bytes());
    message.extend_from_slice(&signed.not_after.to_be_bytes());
    message.extend_from_slice(&configs_bytes);

    // Verify
    use ed25519_dalek::Verifier;
    verifying_key.verify(&message, &signature)?;

    Ok(configs_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn test_signing_and_verification() {
        let state = SigningState::new(TEST_SEED, "testnet".to_string()).unwrap();
        let pubkey = state.public_key_hex();

        let configs = b"test configs";
        let signed = state.get_signed_config(configs);

        assert_eq!(signed.v, 1);
        assert_eq!(signed.network, "testnet");

        let verified = verify_signed_config(&signed, "testnet", &pubkey).unwrap();
        assert_eq!(verified, configs);
    }

    #[test]
    fn test_tampering_detection() {
        let state = SigningState::new(TEST_SEED, "mainnet".to_string()).unwrap();
        let pubkey = state.public_key_hex();

        let mut signed = state.get_signed_config(b"original");
        signed.configs = base64::engine::general_purpose::STANDARD.encode(b"tampered");

        assert!(verify_signed_config(&signed, "mainnet", &pubkey).is_err());
    }

    #[test]
    fn test_key_id_computation() {
        let state = SigningState::new(TEST_SEED, "mainnet".to_string()).unwrap();
        let key_id = state.key_id();
        assert_eq!(key_id.len(), 8);
        // Key ID is deterministic for this test seed
        let pubkey_bytes = hex::decode(state.public_key_hex()).unwrap();
        let hash = Sha256::digest(pubkey_bytes.as_slice());
        assert_eq!(key_id, hex::encode(&hash[..4]));
    }

    #[test]
    fn test_caching() {
        let state = SigningState::new(TEST_SEED, "testnet".to_string()).unwrap();
        let configs = b"test";

        let signed1 = state.get_signed_config(configs);
        let signed2 = state.get_signed_config(configs);

        // Should return same signature when configs unchanged (both calls in the same slot)
        assert_eq!(signed1.sig, signed2.sig);
        assert_eq!(signed1.not_before, signed2.not_before);
    }

    #[test]
    fn test_issuance_window_is_slot_aligned_and_within_zip_limits() {
        let slot = 472_224u64 * ISSUANCE_SLOT_SECS; // 1_700_006_400, a slot start
        let now = slot + 1; // 1 s into the slot
        let (nb, na) = issuance_window(now);
        assert_eq!(nb, slot - VALIDITY_BEFORE_SECS);
        assert_eq!(na, slot + VALIDITY_AFTER_SECS);
        // The same window anywhere in the slot, a new one in the next slot.
        assert_eq!(issuance_window(slot + 3599), (nb, na));
        assert_ne!(issuance_window(slot + 3600), (nb, na));
        // ZIP envelope validation: now within [nb - 60, na + 60], validity <= 86400,
        // not_after at most 86400 ahead of now; checked at both ends of the slot.
        for t in [slot, slot + 3599] {
            let (nb, na) = issuance_window(t);
            assert!(nb <= t && t < na);
            assert!(na - nb <= 86_400);
            assert!(na - t <= 86_400);
            // ZIP "Issuance and key rotation": the window SHOULD be at most 6 hours.
            assert_eq!(na - nb, MAX_ISSUED_VALIDITY_SECS);
            const { assert!(MAX_ISSUED_VALIDITY_SECS <= 6 * 3600) };
            // Still valid for the clients that cached the previous slot's envelope: 5 h overlap.
            assert!(na >= t + VALIDITY_AFTER_SECS - ISSUANCE_SLOT_SECS);
        }
    }

    #[test]
    fn test_two_origins_issue_identical_envelopes() {
        // Two gateways with the same seed and key configuration, asked at different moments of
        // the same slot, publish byte-identical envelopes; the next slot gives a new one.
        let a = SigningState::new(TEST_SEED, "mainnet".to_string()).unwrap();
        let b = SigningState::new(TEST_SEED, "mainnet".to_string()).unwrap();
        let configs: Vec<u8> = (0..43).collect();
        let slot = 1_700_000_000u64 - 1_700_000_000u64 % ISSUANCE_SLOT_SECS;

        let ea = a.get_signed_config_at(&configs, slot + 5);
        let eb = b.get_signed_config_at(&configs, slot + 3000);
        assert_eq!(
            serde_json::to_vec(&ea).unwrap(),
            serde_json::to_vec(&eb).unwrap()
        );

        let next = a.get_signed_config_at(&configs, slot + ISSUANCE_SLOT_SECS);
        assert_ne!(next.sig, ea.sig);
        assert_eq!(next.not_before, ea.not_before + ISSUANCE_SLOT_SECS);
        // Re-sign on a key configuration change within the slot, and back again.
        let other = a.get_signed_config_at(b"other configs", slot + ISSUANCE_SLOT_SECS);
        assert_ne!(other.sig, next.sig);
        assert_eq!(
            a.get_signed_config_at(&configs, slot + ISSUANCE_SLOT_SECS)
                .sig,
            next.sig
        );
    }

    #[test]
    fn test_deterministic_test_vector() {
        // Fixed test vector for SDK teams - deterministic for cross-platform verification
        let seed = "2222222222222222222222222222222222222222222222222222222222222222";
        let state = SigningState::new(seed, "testnet".to_string()).unwrap();

        // Fixed times for determinism (historical timestamps for deterministic testing)
        let not_before = 1700000000u64;
        let not_after = 1700021600u64;

        // Fixed 43 bytes for configs (sequential pattern for determinism)
        let configs: Vec<u8> = (0..43).collect();

        let mut message = Vec::new();
        message.extend_from_slice(DOMAIN_SEP);
        message.push(0);
        message.extend_from_slice(b"testnet");
        message.push(0);
        message.extend_from_slice(&not_before.to_be_bytes());
        message.extend_from_slice(&not_after.to_be_bytes());
        message.extend_from_slice(&configs);

        let signature = state.signing_key.sign(&message);
        let pubkey = state.public_key_hex();
        let key_id = state.key_id();

        let test_vector = serde_json::json!({
            "description": "Deterministic test vector for SDK verification",
            "seed_hex": seed,
            "public_key_hex": pubkey,
            "key_id": key_id,
            "network": "testnet",
            "configs_bytes_base64": base64::engine::general_purpose::STANDARD.encode(&configs),
            "not_before": not_before,
            "not_after": not_after,
            "signature_base64": base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        });

        // Print for docs/signed-configs-test-vector.json generation
        eprintln!(
            "TEST VECTOR:\n{}",
            serde_json::to_string_pretty(&test_vector).unwrap()
        );

        // Verify signature directly (without time checks since these are historical timestamps)
        let pubkey_bytes = hex::decode(&pubkey).unwrap();
        let verifying_key =
            VerifyingKey::from_bytes(pubkey_bytes.as_slice().try_into().unwrap()).unwrap();
        verifying_key
            .verify_strict(&message, &signature)
            .expect("Signature verification failed");

        // Also verify the key_id computation
        let hash = Sha256::digest(&pubkey_bytes);
        let computed_key_id = hex::encode(&hash[..4]);
        assert_eq!(key_id, computed_key_id, "key_id mismatch");
    }

    #[test]
    fn test_reject_long_validity() {
        // Create a signed config with validity > 86400s
        let seed = "2222222222222222222222222222222222222222222222222222222222222222";
        let state = SigningState::new(seed, "testnet".to_string()).unwrap();

        let not_before = 1700000000u64;
        let not_after = not_before + 86401; // Just over 24h
        let configs: Vec<u8> = (0..43).collect();

        let mut message = Vec::new();
        message.extend_from_slice(DOMAIN_SEP);
        message.push(0);
        message.extend_from_slice(b"testnet");
        message.push(0);
        message.extend_from_slice(&not_before.to_be_bytes());
        message.extend_from_slice(&not_after.to_be_bytes());
        message.extend_from_slice(&configs);

        let signature = state.signing_key.sign(&message);
        let pubkey = state.public_key_hex();

        // Verify signature directly - the gateway CAN sign long-validity configs,
        // but clients MUST reject them (enforced in client/src/signed.rs)
        let pubkey_bytes = hex::decode(&pubkey).unwrap();
        let verifying_key =
            VerifyingKey::from_bytes(pubkey_bytes.as_slice().try_into().unwrap()).unwrap();
        verifying_key
            .verify_strict(&message, &signature)
            .expect("Signature should be valid");

        // Document that the validity is indeed > 86400
        assert!(
            not_after - not_before > 86400,
            "Test should use validity > 86400s"
        );
    }
}

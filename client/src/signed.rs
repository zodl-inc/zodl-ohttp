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

//! The gateway's signed key-configuration envelope (`/ohttp-configs/signed`).

use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD as BASE64};
use base64::engine::DecodePaddingMode;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer as _};
use sha2::{Digest, Sha256};

use crate::{Error, MAX_KEY_CONFIG_BYTES};

/// The envelope's domain separator.
const DOMAIN: &[u8] = b"zodl-ohttp-configs-v1";
/// The longest validity an envelope may claim, and how far past now it may end: a day.
const MAX_VALIDITY_SECS: u64 = 86_400;
/// The clock skew the ZIP allows on each side of an envelope's validity window.
pub const CLOCK_SKEW_SECS: u64 = 60;
/// The most bytes of `configs`, decoded, that are ever read, whatever the policy says: a
/// document of 4096 configurations of the one suite is under 200 KiB.
const HARD_MAX_CONFIGS_BYTES: usize = 1 << 20;
/// An Ed25519 signature in base64, padded.
const MAX_SIG_BASE64_CHARS: usize = 88;
/// The envelope's fields.
const ENVELOPE_FIELDS: [&str; 7] = [
    "v",
    "network",
    "configs",
    "not_before",
    "not_after",
    "key_id",
    "sig",
];

/// Base64 the way `java.util.Base64.getDecoder()` reads it: padding optional, stray trailing
/// bits allowed.
const LENIENT_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// The gateway's configuration-signing key for mainnet, raw Ed25519, hex, as the build set it
/// (`ZODL_OHTTP_SIGNING_PUBKEY_MAINNET`). `None` when unset: no mainnet envelope verifies
/// against a built-in key and the built-in mainnet configuration is off.
pub const MAINNET_SIGNING_KEY_HEX: Option<&str> = crate::relays::SIGNING_PUBKEY_MAINNET;
/// The gateway's configuration-signing key for testnet, raw Ed25519, hex, as the build set it
/// (`ZODL_OHTTP_SIGNING_PUBKEY_TESTNET`). `None` when unset: no testnet envelope verifies
/// against a built-in key and the built-in testnet configuration is off.
pub const TESTNET_SIGNING_KEY_HEX: Option<&str> = crate::relays::SIGNING_PUBKEY_TESTNET;

/// The network a gateway serves, which picks the signing key an envelope is checked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    /// `mainnet`.
    Mainnet,
    /// `testnet`.
    Testnet,
}

impl Network {
    /// The name the envelope carries.
    pub const fn as_str(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
        }
    }

    /// The network named `name`, `mainnet` or `testnet`.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "mainnet" => Some(Network::Mainnet),
            "testnet" => Some(Network::Testnet),
            _ => None,
        }
    }

    /// The pinned key of the gateway's envelope signer for this network, as the build set it
    /// (`ZODL_OHTTP_SIGNING_PUBKEY_*`). An error when the build did not set one (OHTTP off for
    /// this network) or the value is not an Ed25519 point.
    pub fn pinned_signing_key(self) -> Result<VerifyingKey, Error> {
        signing_key_from_hex(
            self,
            crate::relays::Endpoints::BUILT_IN
                .network(self)
                .signing_key_hex,
        )
    }
}

/// The verifying key in `hex_key`, the configured key of `network`.
fn signing_key_from_hex(network: Network, hex_key: Option<&str>) -> Result<VerifyingKey, Error> {
    let refused = |why: &str| {
        Error::KeyConfig(format!(
            "{why} signing key for {} (ZODL_OHTTP_SIGNING_PUBKEY_{})",
            network.as_str(),
            network.as_str().to_ascii_uppercase()
        ))
    };
    let hex_key = hex_key.ok_or_else(|| refused("no OHTTP"))?;
    let bytes: [u8; 32] = hex::decode(hex_key)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| refused("malformed"))?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| refused("invalid"))
}

/// How a gateway host name picks its [`Network`]. The clients differ here, and the choice
/// decides which signing key an envelope is trusted under, so it is explicit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkRule {
    /// Exactly the build's mainnet gateway host (`ZODL_OHTTP_GATEWAY_HOST_MAINNET`) is mainnet
    /// and exactly its testnet gateway host (`ZODL_OHTTP_GATEWAY_HOST_TESTNET`) testnet; any
    /// other host, and every host of a network whose gateway host the build left unset, is
    /// refused. Every preset uses it (the network comes from the static configuration, never
    /// the host name).
    KnownHosts,
    /// A host containing `-testnet` (after lower-casing) is testnet, every other host
    /// mainnet (what iOS did before the ZIP required the static network binding). Not used
    /// by any preset: the ZIP forbids inferring the network from the host name.
    ContainsDashTestnetElseMainnet,
    /// A host containing `testnet` (case-sensitively) is testnet, every other host mainnet
    /// (what Slipstream did before the static network binding). Not used by any preset.
    ContainsTestnetElseMainnet,
}

impl NetworkRule {
    /// The network of `gateway_host` under this rule.
    pub fn network_for(self, gateway_host: &str) -> Result<Network, Error> {
        self.network_in(&crate::relays::Endpoints::BUILT_IN, gateway_host)
    }

    /// [`NetworkRule::network_for`] against the endpoint configuration `endpoints`.
    fn network_in(
        self,
        endpoints: &crate::relays::Endpoints,
        gateway_host: &str,
    ) -> Result<Network, Error> {
        match self {
            NetworkRule::KnownHosts => endpoints.network_of_host(gateway_host).ok_or_else(|| {
                Error::KeyConfig(format!(
                    "no OHTTP network configured for gateway host {gateway_host}"
                ))
            }),
            NetworkRule::ContainsDashTestnetElseMainnet => {
                Ok(if gateway_host.to_lowercase().contains("-testnet") {
                    Network::Testnet
                } else {
                    Network::Mainnet
                })
            }
            NetworkRule::ContainsTestnetElseMainnet => Ok(if gateway_host.contains("testnet") {
                Network::Testnet
            } else {
                Network::Mainnet
            }),
        }
    }
}

/// What to do with envelope fields this crate does not know.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnknownFields {
    /// Ignore them.
    Ignore,
    /// Refuse the envelope.
    Reject,
}

/// Which repeated top-level JSON keys refuse an envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DuplicateKeys {
    /// A repeated envelope field (`serde`'s rule); a repeated unknown key is ignored.
    KnownFields,
    /// Any repeated top-level key.
    AnyTopLevel,
}

/// How strictly base64 is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Base64Decoding {
    /// Canonical, padded standard base64.
    Strict,
    /// Padding optional and non-zero trailing bits tolerated, as `java.util.Base64` does.
    Lenient,
}

/// Which Ed25519 verification is run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureCheck {
    /// `verify_strict`: also refuses a weak (small-order) key or signature point.
    Strict,
    /// RFC 8032 verification, as `ed25519-dalek`'s `verify`, BouncyCastle and CryptoKit do.
    Standard,
}

/// The rules [`verify_signed_config`] applies beyond the signature. Where the three wallet
/// clients differed when this was written, each has a preset ([`crate::ClientProfile`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedConfigPolicy {
    /// Seconds of clock skew allowed on both ends of the validity window.
    pub skew_tolerance_secs: u64,
    /// Whether an envelope is still valid at exactly `not_after` plus the tolerance.
    pub not_after_inclusive: bool,
    /// The longest `not_after - not_before` accepted.
    pub max_validity_secs: u64,
    /// How far past now `not_after` may be, if that is checked.
    pub max_not_after_ahead_secs: Option<u64>,
    /// The most bytes the whole envelope (the JSON text) may have, checked before it is
    /// parsed; every preset uses [`crate::MAX_KEY_CONFIG_BYTES`].
    pub max_envelope_bytes: Option<usize>,
    /// The most bytes the decoded `application/ohttp-keys` document may have, if capped.
    pub max_configs_bytes: Option<usize>,
    /// Envelope fields beyond the seven known. Every preset ignores them, so that the gateway
    /// can add a field without a client release.
    pub unknown_fields: UnknownFields,
    /// Repeated keys.
    pub duplicate_keys: DuplicateKeys,
    /// Base64 reading, for `configs` and `sig`.
    pub base64: Base64Decoding,
    /// The signature check.
    pub signature: SignatureCheck,
}

impl SignedConfigPolicy {
    /// The rules of the ZIP's "Envelope validation", which every preset shares: 60 s of clock
    /// skew on each side (so `now` in `[not_before - 60, not_after + 60]`, both ends included),
    /// `not_after - not_before` at most 86400 s, `not_after` at most 86400 s ahead of now,
    /// decoded `configs` at most 4096 bytes, unknown fields ignored (`v` is 1), any repeated
    /// field name refused.
    const ZIP: SignedConfigPolicy = SignedConfigPolicy {
        skew_tolerance_secs: CLOCK_SKEW_SECS,
        not_after_inclusive: true,
        max_validity_secs: MAX_VALIDITY_SECS,
        max_not_after_ahead_secs: Some(MAX_VALIDITY_SECS),
        max_envelope_bytes: Some(MAX_KEY_CONFIG_BYTES),
        max_configs_bytes: Some(4096),
        unknown_fields: UnknownFields::Ignore,
        duplicate_keys: DuplicateKeys::AnyTopLevel,
        base64: Base64Decoding::Strict,
        signature: SignatureCheck::Strict,
    };
    /// This library's own rules (what [`open_signed_config`] applies): the ZIP's, with strict
    /// base64 and `verify_strict`. Its skew allowance is 60 s like every preset's, so that no
    /// caller can end up with none by accident.
    pub const LIBRARY: SignedConfigPolicy = SignedConfigPolicy::ZIP;
    /// The Android SDK (`OhttpSignedConfigVerifier`): the ZIP's rules, lenient base64 and the
    /// standard signature check (BouncyCastle).
    pub const ANDROID: SignedConfigPolicy = SignedConfigPolicy {
        base64: Base64Decoding::Lenient,
        signature: SignatureCheck::Standard,
        ..SignedConfigPolicy::ZIP
    };
    /// The Swift SDK (`OHTTPSignedConfigVerifier`): the ZIP's rules, canonical base64 (not
    /// verified against Foundation: the Swift SDK's migration adds a macOS unit test pinning
    /// it) and the standard signature check (CryptoKit).
    pub const IOS: SignedConfigPolicy = SignedConfigPolicy {
        signature: SignatureCheck::Standard,
        ..SignedConfigPolicy::ZIP
    };
    /// Slipstream (`verify_signed_config`): the ZIP's rules and the standard signature check.
    pub const SLIPSTREAM: SignedConfigPolicy = SignedConfigPolicy {
        signature: SignatureCheck::Standard,
        ..SignedConfigPolicy::ZIP
    };
}

/// The envelope, as the gateway serves it.
#[derive(Deserialize)]
struct Envelope {
    v: u8,
    network: String,
    /// The `application/ohttp-keys` document, base64.
    configs: String,
    not_before: u64,
    not_after: u64,
    /// The first four bytes of the signing key's SHA-256, hex.
    key_id: String,
    /// Ed25519 over `DOMAIN || 0 || network || 0 || u64be(not_before) || u64be(not_after)
    /// || configs`, base64.
    sig: String,
}

/// The key-configuration document of a checked envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedKeys {
    /// The `application/ohttp-keys` document, for [`crate::KeyConfig::select`].
    pub document: Vec<u8>,
    /// The end of the envelope's validity, in Unix seconds: fetch a new one from then on.
    pub not_after: u64,
}

/// The key configurations in the envelope `json`, once it is checked: version 1, signed for
/// `network` by `signer`, valid at `now` (Unix seconds), for a day at most and ending at most
/// a day from now. The rules are [`SignedConfigPolicy::LIBRARY`].
pub fn open_signed_config(
    json: &[u8],
    network: &str,
    signer: &VerifyingKey,
    now: u64,
) -> Result<SignedKeys, Error> {
    verify_signed_config_with(json, network, signer, now, &SignedConfigPolicy::LIBRARY)
}

/// The key configurations in the envelope `json`, once it is checked under `policy`: signed
/// for `network` by the key pinned for it ([`Network::pinned_signing_key`]).
pub fn verify_signed_config(
    json: &[u8],
    network: Network,
    now: u64,
    policy: &SignedConfigPolicy,
) -> Result<SignedKeys, Error> {
    verify_signed_config_with(
        json,
        network.as_str(),
        &network.pinned_signing_key()?,
        now,
        policy,
    )
}

/// [`verify_signed_config`] against a `signer` of the caller's choosing, for tests that sign
/// with a key of their own.
pub fn verify_signed_config_with(
    json: &[u8],
    network: &str,
    signer: &VerifyingKey,
    now: u64,
    policy: &SignedConfigPolicy,
) -> Result<SignedKeys, Error> {
    let refused = |why: String| Error::KeyConfig(why);
    if policy
        .max_envelope_bytes
        .is_some_and(|max| json.len() > max)
    {
        return Err(refused(format!(
            "envelope of more than {} bytes",
            policy.max_envelope_bytes.unwrap_or_default()
        )));
    }
    if policy.unknown_fields == UnknownFields::Reject
        || policy.duplicate_keys == DuplicateKeys::AnyTopLevel
    {
        let keys =
            top_level_keys(json).map_err(|e| refused(format!("not a signed envelope: {e}")))?;
        for (i, key) in keys.iter().enumerate() {
            if policy.duplicate_keys == DuplicateKeys::AnyTopLevel && keys[..i].contains(key) {
                return Err(refused(format!("duplicate JSON key {key}")));
            }
            if policy.unknown_fields == UnknownFields::Reject
                && !ENVELOPE_FIELDS.contains(&key.as_str())
            {
                return Err(refused(format!("unknown envelope field {key}")));
            }
        }
    }
    let envelope: Envelope =
        serde_json::from_slice(json).map_err(|e| refused(format!("not a signed envelope: {e}")))?;
    if envelope.v != 1 {
        return Err(refused(format!("envelope version {}", envelope.v)));
    }
    if envelope.network != network {
        return Err(refused(format!(
            "signed for {}, not {network}",
            envelope.network
        )));
    }
    if envelope.not_before >= envelope.not_after {
        return Err(refused("not_before is not before not_after".into()));
    }
    let tolerance = policy.skew_tolerance_secs;
    let not_yet = now < envelope.not_before.saturating_sub(tolerance);
    let latest = envelope.not_after.saturating_add(tolerance);
    let over = if policy.not_after_inclusive {
        now > latest
    } else {
        now >= latest
    };
    if not_yet || over {
        return Err(refused("outside its validity window".into()));
    }
    if envelope.not_after - envelope.not_before > policy.max_validity_secs
        || policy
            .max_not_after_ahead_secs
            .is_some_and(|ahead| envelope.not_after > now.saturating_add(ahead))
    {
        return Err(refused("valid for longer than a day".into()));
    }
    // The key id is public (a label for the pinned key), so this comparison needs no constant
    // time; the signature below is checked by `ed25519-dalek`, which does its own.
    let key_id = hex::encode(&Sha256::digest(signer.as_bytes())[..4]);
    if envelope.key_id != key_id {
        return Err(refused(format!(
            "signed by key {}, not {key_id}",
            envelope.key_id
        )));
    }
    let decode = |field: &str, text: &str| {
        match policy.base64 {
            Base64Decoding::Strict => BASE64.decode(text),
            Base64Decoding::Lenient => LENIENT_BASE64.decode(text),
        }
        .map_err(|e| refused(format!("{field}: {e}")))
    };
    // Bound the text before decoding it: no decoded buffer is allocated for an oversized field.
    let max_configs = policy
        .max_configs_bytes
        .unwrap_or(HARD_MAX_CONFIGS_BYTES)
        .min(HARD_MAX_CONFIGS_BYTES);
    if envelope.configs.len() > max_configs.div_ceil(3).saturating_mul(4) {
        return Err(refused(format!("configs of more than {max_configs} bytes")));
    }
    let document = decode("configs", &envelope.configs)?;
    if document.len() > max_configs {
        return Err(refused(format!(
            "configs of {} bytes, more than {max_configs}",
            document.len()
        )));
    }
    if envelope.sig.len() > MAX_SIG_BASE64_CHARS {
        return Err(refused("sig: too long".into()));
    }
    let sig = decode("sig", &envelope.sig)?;
    let sig = Signature::from_slice(&sig).map_err(|e| refused(format!("sig: {e}")))?;
    let mut message = DOMAIN.to_vec();
    message.push(0);
    message.extend_from_slice(envelope.network.as_bytes());
    message.push(0);
    message.extend_from_slice(&envelope.not_before.to_be_bytes());
    message.extend_from_slice(&envelope.not_after.to_be_bytes());
    message.extend_from_slice(&document);
    match policy.signature {
        SignatureCheck::Strict => signer.verify_strict(&message, &sig),
        SignatureCheck::Standard => signer.verify(&message, &sig),
    }
    .map_err(|_| refused("bad signature".into()))?;
    Ok(SignedKeys {
        document,
        not_after: envelope.not_after,
    })
}

/// The top-level keys of the JSON object `json`, repeats included.
fn top_level_keys(json: &[u8]) -> Result<Vec<String>, serde_json::Error> {
    struct Keys;
    impl<'de> Visitor<'de> for Keys {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a JSON object")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Vec<String>, A::Error> {
            let mut keys = Vec::new();
            while let Some(key) = map.next_key::<String>()? {
                map.next_value::<IgnoredAny>()?;
                keys.push(key);
            }
            Ok(keys)
        }
    }
    let mut de = serde_json::Deserializer::from_slice(json);
    let keys = de.deserialize_map(Keys)?;
    de.end()?;
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `docs/signed-configs-test-vector.json`.
    const VECTOR: &str = include_str!("../../docs/signed-configs-test-vector.json");

    #[derive(Deserialize)]
    struct Vector {
        public_key_hex: String,
        key_id: String,
        network: String,
        configs_bytes_base64: String,
        not_before: u64,
        not_after: u64,
        signature_base64: String,
    }

    fn vector() -> Vector {
        serde_json::from_str(VECTOR).unwrap()
    }

    fn envelope(v: &Vector, network: &str, sig: &str) -> Vec<u8> {
        serde_json::json!({
            "v": 1,
            "network": network,
            "configs": v.configs_bytes_base64,
            "not_before": v.not_before,
            "not_after": v.not_after,
            "key_id": v.key_id,
            "sig": sig,
        })
        .to_string()
        .into_bytes()
    }

    fn signer(v: &Vector) -> VerifyingKey {
        let bytes: [u8; 32] = hex::decode(&v.public_key_hex).unwrap().try_into().unwrap();
        VerifyingKey::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn the_test_vector_opens() {
        let v = vector();
        let keys = open_signed_config(
            &envelope(&v, &v.network, &v.signature_base64),
            &v.network,
            &signer(&v),
            v.not_before + 60,
        )
        .unwrap();
        assert_eq!(
            keys.document,
            BASE64.decode(&v.configs_bytes_base64).unwrap()
        );
        assert_eq!(keys.not_after, v.not_after);
    }

    #[test]
    fn an_envelope_is_refused_off_network_out_of_its_window_or_tampered() {
        let v = vector();
        let signer = signer(&v);
        let good = envelope(&v, &v.network, &v.signature_base64);
        let now = v.not_before + 60;
        let Err(Error::KeyConfig(_)) = open_signed_config(&good, "mainnet", &signer, now) else {
            panic!("an envelope opened for another network");
        };
        let Err(Error::KeyConfig(_)) =
            open_signed_config(&good, &v.network, &signer, v.not_after + 61)
        else {
            panic!("an expired envelope opened");
        };
        let Err(Error::KeyConfig(_)) =
            open_signed_config(&good, &v.network, &signer, v.not_before - 61)
        else {
            panic!("an envelope opened before its window");
        };
        let mut sig = BASE64.decode(&v.signature_base64).unwrap();
        sig[0] ^= 1;
        let tampered = envelope(&v, &v.network, &BASE64.encode(sig));
        let Err(Error::KeyConfig(_)) = open_signed_config(&tampered, &v.network, &signer, now)
        else {
            panic!("a tampered envelope opened");
        };
        let other = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        let Err(Error::KeyConfig(_)) = open_signed_config(&good, &v.network, &other, now) else {
            panic!("an envelope opened under another key");
        };
    }

    #[test]
    fn known_hosts_take_the_network_from_the_configuration() {
        use crate::relays::tests::EXAMPLE;
        let rule = NetworkRule::KnownHosts;
        assert_eq!(
            rule.network_in(&EXAMPLE, "ohttp-gateway.example").unwrap(),
            Network::Mainnet
        );
        assert_eq!(
            rule.network_in(&EXAMPLE, "ohttp-gateway-testnet.example")
                .unwrap(),
            Network::Testnet
        );
        for host in [
            "OHTTP-GATEWAY-TESTNET.example",
            "ohttp-gateway.example.evil.example",
            "testnet.example",
            "",
        ] {
            assert!(rule.network_in(&EXAMPLE, host).is_err(), "{host}");
        }
        let mut unset = EXAMPLE;
        unset.testnet.gateway_host = None;
        assert!(rule
            .network_in(&unset, "ohttp-gateway-testnet.example")
            .is_err());
    }

    #[test]
    fn a_missing_or_malformed_signing_key_is_an_error() {
        let v = vector();
        let key = signing_key_from_hex(Network::Testnet, Some(v.public_key_hex.as_str())).unwrap();
        assert_eq!(key, signer(&v));
        for bad in [None, Some(""), Some("00"), Some("zz")] {
            let Err(Error::KeyConfig(_)) = signing_key_from_hex(Network::Mainnet, bad) else {
                panic!("{bad:?} gave a key");
            };
        }
        // The library's own key is whatever the build set, or an error.
        for network in [Network::Mainnet, Network::Testnet] {
            assert_eq!(
                network.pinned_signing_key().is_ok(),
                crate::relays::Endpoints::BUILT_IN
                    .network(network)
                    .signing_key_hex
                    .is_some()
            );
        }
    }
}

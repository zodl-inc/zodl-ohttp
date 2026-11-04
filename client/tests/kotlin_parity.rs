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

//! Tests ensuring parity with the deleted Kotlin SDK OHTTP implementation.
//!
//! When the Kotlin implementation was replaced by this crate, these tests were removed from
//! the Android SDK. This file verifies the crate covers the same scenarios.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zodl_ohttp_client::{
    verify_signed_config_with, Error, Network, SignedConfigPolicy, MAINNET_SIGNING_KEY_HEX,
};

const NOW: u64 = 1_800_000_000;

fn test_signer() -> SigningKey {
    SigningKey::from_bytes(&[2; 32])
}

fn key_id(key: &VerifyingKey) -> String {
    Sha256::digest(key.as_bytes())[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Builds a signed envelope with the given parameters.
fn build_envelope(
    signer: &SigningKey,
    network: &str,
    not_before: u64,
    not_after: u64,
    configs: &[u8],
    envelope_key_id: &str,
) -> Vec<u8> {
    let mut message = b"zodl-ohttp-configs-v1\0".to_vec();
    message.extend_from_slice(network.as_bytes());
    message.push(0);
    message.extend_from_slice(&not_before.to_be_bytes());
    message.extend_from_slice(&not_after.to_be_bytes());
    message.extend_from_slice(configs);
    let sig = signer.sign(&message).to_bytes();
    format!(
        r#"{{"v":1,"network":"{}","configs":"{}","not_before":{},"not_after":{},"key_id":"{}","sig":"{}"}}"#,
        network,
        STANDARD.encode(configs),
        not_before,
        not_after,
        envelope_key_id,
        STANDARD.encode(sig)
    )
    .into_bytes()
}

// ---- Signed key-config validity ----

// Covered by the tests in signed_policy.rs:
// - validity > 24h: a_validity_over_a_day_is_refused_by_all
// - not_after too far: not_after_more_than_a_day_ahead_is_refused_by_every_preset
// - not_before in future: the_clock_skew_is_exactly_60_seconds_each_side_for_every_preset
// - expired: the_clock_skew_is_exactly_60_seconds_each_side_for_every_preset
// - wrong version: a_wrong_version_or_a_non_integer_timestamp_is_refused_by_every_preset
// - malformed base64: an_oversized_or_malformed_envelope_is_an_error_not_a_panic
// - wrong signer/network/non-JSON/unknown host: the_wrong_network_key_or_signature_is_refused_by_all
//    and the_gateway_host_picks_the_network_as_each_client_does

/// key_id mismatch between envelope and the actual signing key is rejected.
///
/// The envelope's `key_id` must match the first 8 hex chars of SHA-256(signing public key).
#[test]
fn key_id_mismatch_is_rejected_by_all() {
    let signer = test_signer();
    let key = signer.verifying_key();
    let correct_key_id = key_id(&key);
    let wrong_key_id = "deadbeef";
    assert_ne!(correct_key_id, wrong_key_id);

    let configs: Vec<u8> = (0..40).collect();
    let json = build_envelope(
        &signer,
        "testnet",
        NOW - 300,
        NOW + 21_600,
        &configs,
        wrong_key_id,
    );

    // Every profile refuses an envelope signed by one key but claiming another key_id.
    for (name, policy) in [
        ("library", SignedConfigPolicy::LIBRARY),
        ("android", SignedConfigPolicy::ANDROID),
        ("ios", SignedConfigPolicy::IOS),
        ("slipstream", SignedConfigPolicy::SLIPSTREAM),
    ] {
        let result = verify_signed_config_with(&json, "testnet", &key, NOW, &policy);
        assert!(
            matches!(result, Err(Error::KeyConfig(_))),
            "{name}: expected KeyConfig error for key_id mismatch, got {result:?}"
        );
        if let Err(Error::KeyConfig(msg)) = result {
            assert!(
                msg.contains(&correct_key_id) || msg.contains("key") || msg.contains("Key"),
                "{name}: error message should mention key mismatch: {msg}"
            );
        }
    }
}

/// The embedded signing public key is the one the build set, and a valid Ed25519
/// point. The Kotlin SDK hardcoded its key; this crate takes it from the build
/// (`ZODL_OHTTP_SIGNING_PUBKEY_MAINNET`), and without one no mainnet envelope verifies.
#[test]
fn embedded_mainnet_key_is_the_configured_one() {
    let Some(hex_key) = MAINNET_SIGNING_KEY_HEX else {
        assert!(Network::Mainnet.pinned_signing_key().is_err());
        return;
    };
    let bytes = hex::decode(hex_key).expect("mainnet key is valid hex");
    assert_eq!(bytes.len(), 32, "Ed25519 public key is 32 bytes");
    let configured = VerifyingKey::from_bytes(&bytes.try_into().expect("mainnet key is 32 bytes"))
        .expect("mainnet key is a valid Ed25519 point");
    let key = Network::Mainnet
        .pinned_signing_key()
        .expect("the configured key is pinned");
    assert_eq!(key, configured);
    assert_eq!(key_id(&key).len(), 8);
}

// ---- RFC 9180 test vectors ----

// RFC 9180 Appendix A.1.1 test vectors are covered by
// client/tests/sans_io.rs::rfc_9180_a_1_1_known_answers, which tests:
// - DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, mode base
// - Setup (encapsulated key matches test vector)
// - First three encryptions (sequence numbers 0, 1, 2)
// - Exported secrets
// The test uses the hpke crate API directly since the crate does not expose
// a way to inject deterministic ephemeral keys. The internal key schedule
// (key, base_nonce) is not directly accessible through the hpke crate's
// public API, so it is not compared here.

// ---- Response opener zeroization ----

// The response opener zeroizes its secret on drop.
// This is verified by code inspection in client/src/chunked.rs: `ChunkedResponseOpener` and
// `ChunkedResponseDecoder` hold the exported secret as `Zeroizing<[u8; N_K]>`.
// The Zeroizing wrapper from the zeroize crate automatically zeros the secret on drop.

// Host -> network matching: the legacy `NetworkRule::ContainsDashTestnetElseMainnet` (what iOS
// did before the static network binding) lower-cases the host; every current preset uses
// `NetworkRule::KnownHosts`. Case handling of every rule is tested in
// signed_policy.rs::the_gateway_host_picks_the_network_as_each_client_does.

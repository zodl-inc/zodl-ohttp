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

//! The signed-envelope options: each difference between the wallet clients is one assertion.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zodl_ohttp_client::{
    open_signed_config, verify_signed_config, verify_signed_config_with, ClientProfile, Error,
    Network, NetworkRule, SignedConfigPolicy, GATEWAY_HOST_MAINNET, GATEWAY_HOST_TESTNET,
};

const NOW: u64 = 1_800_000_000;
const PROFILES: [(&str, SignedConfigPolicy); 4] = [
    ("library", SignedConfigPolicy::LIBRARY),
    ("android", SignedConfigPolicy::ANDROID),
    ("ios", SignedConfigPolicy::IOS),
    ("slipstream", SignedConfigPolicy::SLIPSTREAM),
];

struct Spec {
    not_before: u64,
    not_after: u64,
    configs: Vec<u8>,
    extra: &'static str,
    unpadded: bool,
}

impl Default for Spec {
    fn default() -> Self {
        Spec {
            not_before: NOW - 300,
            not_after: NOW + 21_600,
            configs: (0..40).collect(),
            extra: "",
            unpadded: false,
        }
    }
}

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[2; 32])
}

fn key_id(key: &VerifyingKey) -> String {
    Sha256::digest(key.as_bytes())[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn envelope(spec: &Spec) -> Vec<u8> {
    let mut message = b"zodl-ohttp-configs-v1\0testnet\0".to_vec();
    message.extend_from_slice(&spec.not_before.to_be_bytes());
    message.extend_from_slice(&spec.not_after.to_be_bytes());
    message.extend_from_slice(&spec.configs);
    let sig = signer().sign(&message).to_bytes();
    let b64 = |bytes: &[u8]| {
        let text = STANDARD.encode(bytes);
        if spec.unpadded {
            text.trim_end_matches('=').to_string()
        } else {
            text
        }
    };
    format!(
        r#"{{"v":1,"network":"testnet","configs":"{}","not_before":{},"not_after":{},"key_id":"{}","sig":"{}"{}}}"#,
        b64(&spec.configs),
        spec.not_before,
        spec.not_after,
        key_id(&signer().verifying_key()),
        b64(&sig),
        spec.extra
    )
    .into_bytes()
}

fn verdicts(json: &[u8], now: u64) -> Vec<(&'static str, bool)> {
    let key = signer().verifying_key();
    PROFILES
        .iter()
        .map(|(name, policy)| {
            (
                *name,
                verify_signed_config_with(json, "testnet", &key, now, policy).is_ok(),
            )
        })
        .collect()
}

/// Which profiles accept.
fn accepting(json: &[u8], now: u64) -> Vec<&'static str> {
    verdicts(json, now)
        .into_iter()
        .filter_map(|(name, ok)| ok.then_some(name))
        .collect()
}

#[test]
fn a_well_formed_envelope_opens_under_every_profile() {
    let json = envelope(&Spec::default());
    assert_eq!(
        accepting(&json, NOW),
        ["library", "android", "ios", "slipstream"]
    );
    let keys = verify_signed_config_with(
        &json,
        "testnet",
        &signer().verifying_key(),
        NOW,
        &SignedConfigPolicy::IOS,
    )
    .unwrap();
    assert_eq!(keys.not_after, NOW + 21_600);
    assert_eq!(keys.document, (0..40).collect::<Vec<u8>>());
    // `open_signed_config` is the library policy.
    assert!(open_signed_config(&json, "testnet", &signer().verifying_key(), NOW).is_ok());
}

const ALL: [&str; 4] = ["library", "android", "ios", "slipstream"];

/// ZIP, "Envelope validation" rule 3: `now` in `[not_before - 60, not_after + 60]`, exactly 60
/// s on each side, for every preset and the library default.
#[test]
fn the_clock_skew_is_exactly_60_seconds_each_side_for_every_preset() {
    assert_eq!(zodl_ohttp_client::CLOCK_SKEW_SECS, 60);
    for (name, policy) in PROFILES {
        assert_eq!(policy.skew_tolerance_secs, 60, "{name}");
        assert!(policy.not_after_inclusive, "{name}");
    }
    let spec = Spec::default();
    let json = envelope(&spec);
    assert_eq!(accepting(&json, spec.not_before), ALL);
    assert_eq!(accepting(&json, spec.not_before - 1), ALL);
    assert_eq!(accepting(&json, spec.not_before - 60), ALL);
    assert!(accepting(&json, spec.not_before - 61).is_empty());
    assert_eq!(accepting(&json, spec.not_after), ALL);
    assert_eq!(accepting(&json, spec.not_after + 60), ALL);
    assert!(accepting(&json, spec.not_after + 61).is_empty());
    // `open_signed_config` (the library default) is the same.
    let key = signer().verifying_key();
    for (now, ok) in [
        (spec.not_before - 60, true),
        (spec.not_before - 61, false),
        (spec.not_after + 60, true),
        (spec.not_after + 61, false),
    ] {
        assert_eq!(
            open_signed_config(&json, "testnet", &key, now).is_ok(),
            ok,
            "{now}"
        );
    }
}

/// Rule 2: `not_after` more than 86400 s ahead of now is refused by every preset, even inside
/// the skew band.
#[test]
fn not_after_more_than_a_day_ahead_is_refused_by_every_preset() {
    // A day-long window that starts 100 s from now, seen 60 s before it starts: not_after is
    // 86460 s away.
    let json = envelope(&Spec {
        not_before: NOW + 100,
        not_after: NOW + 100 + 86_400,
        ..Spec::default()
    });
    assert!(accepting(&json, NOW + 40).is_empty());
    assert!(accepting(&json, NOW + 99).is_empty());
    // At exactly a day ahead it is accepted by all.
    assert_eq!(accepting(&json, NOW + 100), ALL);
}

#[test]
fn a_validity_over_a_day_is_refused_by_all() {
    let json = envelope(&Spec {
        not_before: NOW - 100,
        not_after: NOW - 100 + 86_401,
        ..Spec::default()
    });
    assert!(accepting(&json, NOW).is_empty());
    let json = envelope(&Spec {
        not_before: NOW - 100,
        not_after: NOW - 100 + 86_400,
        ..Spec::default()
    });
    assert_eq!(accepting(&json, NOW).len(), 4);
}

#[test]
fn the_configs_cap_is_4096_for_every_preset() {
    let json = envelope(&Spec {
        configs: vec![7; 4097],
        ..Spec::default()
    });
    assert!(accepting(&json, NOW).is_empty());
    let json = envelope(&Spec {
        configs: vec![7; 4096],
        ..Spec::default()
    });
    assert_eq!(accepting(&json, NOW).len(), 4);
}

#[test]
fn unknown_json_keys_are_ignored_and_repeated_ones_refused() {
    // An extra field is ignored by every profile (the gateway may add one; iOS used to
    // refuse it).
    let json = envelope(&Spec {
        extra: r#","note":"x""#,
        ..Spec::default()
    });
    assert_eq!(
        accepting(&json, NOW),
        ["library", "android", "ios", "slipstream"]
    );
    // A repeated field name, unknown ones included, is refused by every profile (ZIP rule 1).
    let json = envelope(&Spec {
        extra: r#","note":"x","note":"y""#,
        ..Spec::default()
    });
    assert!(accepting(&json, NOW).is_empty());
    // A repeated known key: every profile refuses it.
    let json = envelope(&Spec {
        extra: r#","v":1"#,
        ..Spec::default()
    });
    assert!(accepting(&json, NOW).is_empty());
}

#[test]
fn unpadded_base64_is_android_only() {
    let json = envelope(&Spec {
        unpadded: true,
        ..Spec::default()
    });
    assert_eq!(accepting(&json, NOW), ["android"]);
}

#[test]
fn a_weak_key_passes_the_standard_signature_check_only() {
    // The identity point as a key and as a signature's R, with S = 0, verifies for any
    // message under RFC 8032's equation; `verify_strict` refuses the weak key.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let weak = VerifyingKey::from_bytes(&identity).unwrap();
    let mut sig = [0u8; 64];
    sig[0] = 1;
    let configs: Vec<u8> = (0..40).collect();
    let json = format!(
        r#"{{"v":1,"network":"testnet","configs":"{}","not_before":{},"not_after":{},"key_id":"{}","sig":"{}"}}"#,
        STANDARD.encode(&configs),
        NOW - 300,
        NOW + 21_600,
        key_id(&weak),
        STANDARD.encode(sig)
    );
    let ok =
        |policy| verify_signed_config_with(json.as_bytes(), "testnet", &weak, NOW, &policy).is_ok();
    assert!(!ok(SignedConfigPolicy::LIBRARY));
    assert!(ok(SignedConfigPolicy::ANDROID));
    assert!(ok(SignedConfigPolicy::IOS));
    assert!(ok(SignedConfigPolicy::SLIPSTREAM));
}

#[test]
fn the_wrong_network_key_or_signature_is_refused_by_all() {
    let key = signer().verifying_key();
    let json = envelope(&Spec::default());
    for (_, policy) in PROFILES {
        assert!(matches!(
            verify_signed_config_with(&json, "mainnet", &key, NOW, &policy),
            Err(Error::KeyConfig(_))
        ));
        let other = SigningKey::from_bytes(&[3; 32]).verifying_key();
        assert!(matches!(
            verify_signed_config_with(&json, "testnet", &other, NOW, &policy),
            Err(Error::KeyConfig(_))
        ));
        // Signed by the test key, so not by the pinned testnet key.
        assert!(matches!(
            verify_signed_config(&json, Network::Testnet, NOW, &policy),
            Err(Error::KeyConfig(_))
        ));
    }
    let mut tampered = envelope(&Spec::default());
    let at = tampered.windows(5).position(|w| w == b"\"sig\"").unwrap() + 8;
    tampered[at] = if tampered[at] == b'A' { b'B' } else { b'A' };
    for (_, policy) in PROFILES {
        assert!(verify_signed_config_with(&tampered, "testnet", &key, NOW, &policy).is_err());
    }
}

#[test]
fn every_preset_takes_the_network_from_the_known_hosts_only() {
    for (name, profile) in [
        ("android", ClientProfile::ANDROID),
        ("ios", ClientProfile::IOS),
        ("slipstream", ClientProfile::SLIPSTREAM),
        ("slipstream-http", ClientProfile::SLIPSTREAM_HTTP),
        ("library", ClientProfile::LIBRARY),
    ] {
        assert_eq!(profile.network_rule, NetworkRule::KnownHosts, "{name}");
        assert!(
            profile
                .network_rule
                .network_for("ohttp.example.org")
                .is_err(),
            "{name}"
        );
        assert!(
            profile
                .network_rule
                .network_for("evil-testnet.example")
                .is_err(),
            "{name}"
        );
    }
}

#[test]
fn the_gateway_host_picks_the_network_as_each_client_does() {
    use Network::{Mainnet, Testnet};
    let rules = |host| {
        [
            NetworkRule::KnownHosts,
            NetworkRule::ContainsDashTestnetElseMainnet,
            NetworkRule::ContainsTestnetElseMainnet,
        ]
        .map(|rule| rule.network_for(host).ok())
    };
    // KnownHosts knows only the hosts the build configured (`ZODL_OHTTP_GATEWAY_HOST_*`).
    let known = |host: &str| {
        if GATEWAY_HOST_MAINNET == Some(host) {
            Some(Mainnet)
        } else if GATEWAY_HOST_TESTNET == Some(host) {
            Some(Testnet)
        } else {
            None
        }
    };
    if let Some(host) = GATEWAY_HOST_MAINNET {
        assert_eq!(rules(host)[0], Some(Mainnet));
    }
    if let Some(host) = GATEWAY_HOST_TESTNET {
        assert_eq!(rules(host)[0], Some(Testnet));
    }
    assert_eq!(
        rules("ohttp-gateway.example"),
        [known("ohttp-gateway.example"), Some(Mainnet), Some(Mainnet)]
    );
    assert_eq!(
        rules("ohttp-gateway-testnet.example"),
        [
            known("ohttp-gateway-testnet.example"),
            Some(Testnet),
            Some(Testnet)
        ]
    );
    // Another host: KnownHosts refuses, both legacy host-name rules take mainnet.
    assert_eq!(
        rules("ohttp.example.org"),
        [None, Some(Mainnet), Some(Mainnet)]
    );
    // Case and the dash: ContainsDashTestnetElseMainnet lower-cases and wants the dash,
    // ContainsTestnetElseMainnet wants `testnet` exactly (neither is a preset's rule).
    assert_eq!(
        rules("OHTTP-GATEWAY-TESTNET.example"),
        [None, Some(Testnet), Some(Mainnet)]
    );
    assert_eq!(
        rules("testnet.example"),
        [None, Some(Mainnet), Some(Testnet)]
    );
}

#[test]
fn an_oversized_or_malformed_envelope_is_an_error_not_a_panic() {
    let key = signer().verifying_key();
    // Megabytes of base64 in `configs` are refused before they are decoded, under every policy.
    let big = format!(
        r#"{{"v":1,"network":"testnet","configs":"{}","not_before":{},"not_after":{},"key_id":"{}","sig":"AAAA"}}"#,
        "A".repeat(4 << 20),
        NOW - 300,
        NOW + 21_600,
        key_id(&key),
    );
    for (_, policy) in PROFILES {
        assert!(matches!(
            verify_signed_config_with(big.as_bytes(), "testnet", &key, NOW, &policy),
            Err(Error::KeyConfig(_))
        ));
    }
    // A signature of the wrong size, and non-UTF-8 and non-JSON input.
    for junk in [
        &b""[..],
        b"{",
        b"[]",
        b"null",
        b"\xff\xfe\x00",
        br#"{"v":1}"#,
        br#"{"v":"1","network":1}"#,
    ] {
        for (_, policy) in PROFILES {
            assert!(matches!(
                verify_signed_config_with(junk, "testnet", &key, NOW, &policy),
                Err(Error::KeyConfig(_))
            ));
        }
    }
    let long_sig = String::from_utf8(envelope(&Spec::default()))
        .unwrap()
        .replace(r#""sig":""#, &format!(r#""sig":"{}"#, "A".repeat(400)));
    for (_, policy) in PROFILES {
        assert!(
            verify_signed_config_with(long_sig.as_bytes(), "testnet", &key, NOW, &policy).is_err()
        );
    }
}

/// The whole envelope is capped at 64 KiB for every policy, checked before it is parsed.
#[test]
fn the_envelope_cap_is_exact() {
    let base = envelope(&Spec::default());
    // Pad with an unknown field (ignored by every policy) to an exact total length.
    let padded = |total: usize| {
        let mut json = String::from_utf8(base.clone()).unwrap();
        json.pop(); // the closing brace
        let filler = total - json.len() - r#","pad":"""#.len() - 1;
        json.push_str(&format!(r#","pad":"{}"}}"#, "x".repeat(filler)));
        assert_eq!(json.len(), total);
        json.into_bytes()
    };
    let cap = zodl_ohttp_client::MAX_KEY_CONFIG_BYTES;
    assert_eq!(cap, 65_536);
    assert_eq!(
        accepting(&padded(cap), NOW),
        ["library", "android", "ios", "slipstream"]
    );
    assert!(accepting(&padded(cap + 1), NOW).is_empty());
    // And the refusal is a typed error, not a parse error further in.
    let key = signer().verifying_key();
    for (_, policy) in PROFILES {
        let Err(Error::KeyConfig(why)) =
            verify_signed_config_with(&padded(cap + 1), "testnet", &key, NOW, &policy)
        else {
            panic!("an oversized envelope was not refused");
        };
        assert!(why.contains("envelope of more than 65536"), "{why}");
    }
}

/// ZIP rule 1: `v` must be 1, and a timestamp must be an integer.
#[test]
fn a_wrong_version_or_a_non_integer_timestamp_is_refused_by_every_preset() {
    let good = String::from_utf8(envelope(&Spec::default())).unwrap();
    let nb = (NOW - 300).to_string();
    for bad in [
        good.replace(r#""v":1"#, r#""v":2"#),
        good.replace(r#""v":1"#, r#""v":"1""#),
        good.replace(r#""v":1"#, r#""v":1.5"#),
        good.replace(
            &format!(r#""not_before":{nb}"#),
            &format!(r#""not_before":{nb}.5"#),
        ),
        good.replace(
            &format!(r#""not_before":{nb}"#),
            &format!(r#""not_before":"{nb}""#),
        ),
        good.replace(&format!(r#""not_before":{nb}"#), r#""not_before":-1"#),
    ] {
        assert_ne!(bad, good);
        assert!(accepting(bad.as_bytes(), NOW).is_empty(), "{bad}");
    }
}

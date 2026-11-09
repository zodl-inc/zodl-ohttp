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

//! The signed key-configuration envelope under every client's policy. First byte even: the
//! rest is the envelope as received (signed or not). Odd: the rest is `network selector (1)
//! || not_before (8) || not_after (8) || configs`, signed with the test vector's key, so
//! the checks after the signature are reached.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use ohttp_fuzz::{signed_envelope, VECTOR_NOW, VECTOR_SEED};
use zodl_ohttp_client::{
    verify_signed_config, verify_signed_config_with, KeyConfig, Network, OhttpConfig,
    OhttpConfigParams, OhttpNetworks, SignedConfigPolicy,
};

const POLICIES: [SignedConfigPolicy; 4] = [
    SignedConfigPolicy::LIBRARY,
    SignedConfigPolicy::ANDROID,
    SignedConfigPolicy::IOS,
    SignedConfigPolicy::SLIPSTREAM,
];

/// Seeds of the example signing keys; neither is the test vector's.
const OTHER_SEEDS: [u8; 2] = [0x33, 0x44];
const _: () = assert!(VECTOR_SEED[0] != OTHER_SEEDS[0] && VECTOR_SEED[0] != OTHER_SEEDS[1]);

/// An example configuration of `host` whose signing key is that of `seed`.
fn config(host: &str, seed: [u8; 32]) -> OhttpConfig {
    let key = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    OhttpConfig::new(OhttpConfigParams {
        gateway_host: host,
        relay_url: &format!("https://{host}/relay"),
        keys_dns_name: &format!("keys.{host}"),
        signing_pubkey: &hex::encode(key.as_bytes()),
    })
    .expect("a valid example configuration")
}

/// Both networks configured with keys other than the test vector's (`[0]`), and testnet
/// configured with the test vector's key (`[1]`); built once.
fn networks() -> &'static [OhttpNetworks; 2] {
    static NETWORKS: OnceLock<[OhttpNetworks; 2]> = OnceLock::new();
    NETWORKS.get_or_init(|| {
        let mainnet = || Some(config("ohttp-gateway.example", [OTHER_SEEDS[0]; 32]));
        [
            OhttpNetworks::new(
                mainnet(),
                Some(config(
                    "ohttp-gateway-testnet.example",
                    [OTHER_SEEDS[1]; 32],
                )),
            )
            .expect("distinct example configurations"),
            OhttpNetworks::new(
                mainnet(),
                Some(config("ohttp-gateway-testnet.example", VECTOR_SEED)),
            )
            .expect("distinct example configurations"),
        ]
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let signer = ed25519_dalek::SigningKey::from_bytes(&VECTOR_SEED).verifying_key();
    let [others, vector] = networks();
    let (json, signed) = if mode & 1 == 0 {
        (rest.to_vec(), None)
    } else {
        let Some((head, configs)) = rest.split_at_checked(17) else {
            return;
        };
        let network = ["testnet", "mainnet", "regtest", ""][usize::from(head[0] & 3)];
        let not_before = u64::from_be_bytes(head[1..9].try_into().unwrap());
        let not_after = u64::from_be_bytes(head[9..17].try_into().unwrap());
        (
            signed_envelope(network, not_before, not_after, configs),
            Some((not_after, configs)),
        )
    };
    for policy in &POLICIES {
        for now in [VECTOR_NOW, 0, u64::MAX] {
            let direct = verify_signed_config_with(&json, "testnet", &signer, now, policy);
            // The configured testnet key behaves exactly as that key passed directly.
            let configured = verify_signed_config(vector, &json, Network::Testnet, now, policy);
            assert_eq!(
                configured.as_ref().ok(),
                direct.as_ref().ok(),
                "configured and direct verification differ"
            );
            if let Ok(keys) = direct {
                if let Some((not_after, configs)) = signed {
                    assert_eq!(keys.not_after, not_after);
                    assert_eq!(keys.document, configs);
                }
                let _ = KeyConfig::select(&keys.document);
            }
        }
        // Not signed by the configured keys, or no configuration: must never verify.
        for network in [Network::Mainnet, Network::Testnet] {
            assert!(verify_signed_config(others, &json, network, VECTOR_NOW, policy).is_err());
            assert!(verify_signed_config(
                &OhttpNetworks::default(),
                &json,
                network,
                VECTOR_NOW,
                policy
            )
            .is_err());
        }
    }
});

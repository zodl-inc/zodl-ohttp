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

//! The sans-IO core against the gateway's own code (`ohttp-gateway`'s library): its key
//! configuration document, its chunked request decapsulation, its streaming response encoder
//! and its signed envelope, under every client profile.

use std::collections::HashMap;
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;
use ohttp_gateway::chunked_stream::{
    collected_upstream, encode_response_stream, split_grpc_trailers,
};
use ohttp_gateway::config::Config;
use ohttp_gateway::hpke::{KeyState, ResponseContext};
use ohttp_gateway::ohttp::{self as gateway, InnerResponse};
use ohttp_gateway::ohttp_chunked::decapsulate_chunked_request;
use ohttp_gateway::signing::SigningState;
use zodl_ohttp_client::{
    encapsulate_chunked_request, encode_bhttp_request, verify_signed_config_with, BhttpRequest,
    ChunkedResponseOpener, ClientProfile, KeyConfig,
};

const SIGNING_SEED: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const PROFILES: [ClientProfile; 4] = [
    ClientProfile::LIBRARY,
    ClientProfile::ANDROID,
    ClientProfile::IOS,
    ClientProfile::SLIPSTREAM,
];

/// The gateway's configuration with only its HPKE keys set, as its own tests build it.
fn gateway_config(keys: Vec<(u8, String)>) -> Config {
    Config {
        port: 0,
        lwd_addr: String::new(),
        mode: "ohttp".to_string(),
        relay_secrets: vec![],
        hpke_private_key: None,
        hpke_key_id: keys[0].0,
        hpke_keys: keys,
        lwd_timeout_secs: 80,
        long_poll_max_initial_silence_secs: 25,
        long_poll_idle_secs: 3,
        sse_keepalive_secs: 20,
        redis_url: String::new(),
        redis_security_url: String::new(),
        backends: HashMap::new(),
        backend_headers: HashMap::new(),
        backends_policy: HashMap::new(),
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
        relay_secret_on_key_config: ohttp_gateway::config::RelaySecretOnKeyConfig::Off,
        lwd_permit_wait_ms: 2000,
        lwd_permit_max_waiters: 0,
    }
}

fn private_key(key_id: u8) -> String {
    format!("{:064x}", u64::from(key_id) + 0xa0)
}

/// `request` encoded under the profile's options and sealed as a chunked request to `key`.
fn seal(
    key: &KeyConfig,
    request: &BhttpRequest,
    profile: &ClientProfile,
) -> (Vec<u8>, ChunkedResponseOpener) {
    let plain = encode_bhttp_request(request, &profile.encode).unwrap();
    encapsulate_chunked_request(key, &plain).unwrap()
}

/// A collected inner response sealed the way the gateway's handler seals one: the `grpc-*`
/// fields split off into the trailers, then `encode_response_stream` over one upstream frame.
async fn gateway_answers(ctx: ResponseContext, response: InnerResponse) -> Vec<u8> {
    let (headers, trailers) = split_grpc_trailers(response.headers);
    let wire: Vec<Bytes> = encode_response_stream(
        ctx,
        response.status,
        headers,
        collected_upstream(response.body, trailers),
        16384,
        Duration::from_millis(50),
        "testnet".to_string(),
    )
    .map(|r| r.unwrap())
    .collect()
    .await;
    wire.iter().flat_map(|b| b.to_vec()).collect()
}

#[tokio::test]
async fn every_profile_selects_the_gateways_preferred_key_and_round_trips() {
    // Two keys, as during a rotation: the first listed is the preferred one.
    let keys = KeyState::new(&gateway_config(vec![
        (7, private_key(7)),
        (8, private_key(8)),
    ]))
    .unwrap();
    let document = keys.public_config();

    for profile in PROFILES {
        let key = KeyConfig::select_with(&document, &profile.key_selection).unwrap();
        assert_eq!(key.key_id(), 7);

        let request = BhttpRequest::new("POST", "lwd.example", "/v1/thing?x=1")
            .header("Content-Type", "application/json")
            .body(br#"{"a":1}"#.to_vec());
        let (sealed, opener) = seal(&key, &request, &profile);

        let (plain, context) = decapsulate_chunked_request(&sealed[..], &keys)
            .await
            .unwrap();
        let inner = gateway::parse_inner_request(&plain).unwrap();
        assert_eq!(inner.method, "POST");
        assert_eq!(inner.authority, "lwd.example");
        assert_eq!(inner.path, "/v1/thing?x=1");
        assert_eq!(inner.body, br#"{"a":1}"#);
        // Lower-cased or as given, by the profile.
        let want = if profile.encode.lowercase_header_names {
            "content-type"
        } else {
            "Content-Type"
        };
        assert!(inner
            .headers
            .iter()
            .any(|(k, v)| k == want && v == "application/json"));

        let answer = gateway_answers(
            context,
            InnerResponse {
                status: 404,
                headers: vec![
                    ("content-type".into(), "text/plain".into()),
                    ("grpc-status".into(), "12".into()),
                ],
                body: b"not here".to_vec(),
            },
        )
        .await;
        let response = opener.open_response(&answer).unwrap();
        assert_eq!(response.status, 404);
        assert_eq!(response.body, b"not here");
        assert_eq!(response.header("Grpc-Status"), Some("12"));
        assert_eq!(
            response.headers,
            vec![
                ("content-type".to_string(), "text/plain".to_string()),
                ("grpc-status".to_string(), "12".to_string())
            ]
        );
    }
}

#[test]
fn the_gateways_signed_envelope_opens_under_every_profile() {
    let keys = KeyState::new(&gateway_config(vec![(7, private_key(7))])).unwrap();
    let document = keys.public_config();
    let signing = SigningState::new(SIGNING_SEED, "testnet".to_string()).unwrap();
    let json = serde_json::to_vec(&signing.get_signed_config(&document)).unwrap();
    let seed: [u8; 32] = hex::decode(SIGNING_SEED).unwrap().try_into().unwrap();
    let signer = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    for profile in PROFILES {
        let signed =
            verify_signed_config_with(&json, "testnet", &signer, now, &profile.signed_config)
                .unwrap();
        assert_eq!(signed.document, document);
        assert!(signed.not_after > now);
        let key = KeyConfig::select_with(&signed.document, &profile.key_selection).unwrap();
        assert_eq!(key.key_id(), 7);
    }
}

#[tokio::test]
async fn an_unknown_key_id_is_a_request_the_gateway_cannot_open() {
    // The sans-IO half of a rotation: a request sealed to a key the gateway no longer holds
    // is one it cannot open, and the gateway's error names the key id.
    let old = KeyState::new(&gateway_config(vec![(1, private_key(1))])).unwrap();
    let new = KeyState::new(&gateway_config(vec![(2, private_key(2))])).unwrap();
    let key = KeyConfig::select(&old.public_config()).unwrap();
    let (sealed, _) = seal(
        &key,
        &BhttpRequest::new("GET", "a.example", "/"),
        &ClientProfile::LIBRARY,
    );
    let Err(error) = decapsulate_chunked_request(&sealed[..], &new).await else {
        panic!("a request sealed to a retired key opened");
    };
    assert!(error.to_string().contains("Unknown key_id"));
}

#[tokio::test]
async fn every_client_profile_is_fresh_at_the_gateway() {
    use ohttp_gateway::freshness;
    let keys = KeyState::new(&gateway_config(vec![(7, private_key(7))])).unwrap();
    let document = keys.public_config();
    for (profile, stamps) in [
        (ClientProfile::SLIPSTREAM, true),
        (ClientProfile::SLIPSTREAM_HTTP, true),
        (ClientProfile::LIBRARY, true),
        // The SDKs' own OHTTP path (voting, third-party backends, Tor) uses these two.
        (ClientProfile::ANDROID, true),
        (ClientProfile::IOS, true),
    ] {
        let key = KeyConfig::select_with(&document, &profile.key_selection).unwrap();
        let request = BhttpRequest::new(
            "POST",
            "lwd.example",
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock",
        );
        let (sealed, _) = seal(&key, &request, &profile);
        let (plain, _) = decapsulate_chunked_request(&sealed[..], &keys)
            .await
            .unwrap();
        let inner = gateway::parse_inner_request(&plain).unwrap();
        let verdict = freshness::check(
            &inner.headers,
            freshness::now_unix(),
            freshness::DEFAULT_WINDOW_SECS,
        );
        if stamps {
            assert_eq!(verdict, freshness::Verdict::Fresh, "{profile:?}");
        } else {
            assert_eq!(verdict, freshness::Verdict::Missing, "{profile:?}");
        }
    }
}

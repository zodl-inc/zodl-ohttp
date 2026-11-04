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

//! Fixtures shared by the fuzz targets and the corpus generator (`examples/gen_corpus.rs`):
//! one gateway configuration and key, a deterministic random source, and the request
//! pipeline the gateway runs on an opened inner request.

use std::sync::OnceLock;

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use ohttp_gateway::{
    block_cache::{BlockRangeRequest, GET_BLOCK_RANGE_PATH},
    chunked_stream::ChunkSealer,
    config::Config,
    enforcement, freshness, health,
    hpke::{KeyState, ResponseContext},
    lwd, ohttp, origin, padding,
    proxy::{self, BackendTarget},
    rpc_cache,
    subtree_cache::SubtreeRootsRequest,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zodl_ohttp_client::{ChunkedResponseOpener, KeyConfig};

pub const KEY_ID: u8 = 7;
pub const PRIVATE_KEY_HEX: &str =
    "00000000000000000000000000000000000000000000000000000000000000a7";
pub const GATEWAY_HOST: &str = "gateway.example";
pub const LWD_ADDR: &str = "lwd:9067";
/// An alias with a policy, one with a wildcard policy, one without (denied by default).
pub const ALIASES: [&str; 3] = ["api1.example.com", "near.example", "vote.example"];
pub const MAX_BLOCK_RANGE: u32 = 1000;
/// The gateway clock the targets judge freshness against.
pub const NOW: i64 = 1_760_000_000;
/// The signed-configs test vector (docs/signed-configs-test-vector.json).
pub const VECTOR_SEED: [u8; 32] = [0x22; 32];
pub const VECTOR_NOW: u64 = 1_700_000_100;
/// The response nonce the targets seal responses with.
pub const RESPONSE_NONCE: [u8; 16] = [0x42; 16];

const ENV: [(&str, &str); 6] = [
    ("GATEWAY_HOSTS", "gateway.example,gateway-testnet.example"),
    ("LWD_ADDR", LWD_ADDR),
    ("ALLOW_UNAUTHENTICATED_RELAY", "true"),
    (
        "BACKENDS",
        "api1.example.com=https://prices-upstream.example,\
         near.example=https://swap-upstream.example,\
         vote.example=http://vote-upstream.example:8080/base",
    ),
    (
        "BACKENDS_POLICY",
        "api1.example.com=GET /v1/cryptocurrency/quotes/latest,GET /v2/*;\
         near.example=* /*;\
         gateway.example=POST /cash.z.wallet.sdk.rpc.CompactTxStreamer/*",
    ),
    ("MAX_BLOCK_RANGE", "1000"),
];

/// The gateway's configuration, from the environment as in production.
pub fn config() -> &'static Config {
    static CONFIG: OnceLock<Config> = OnceLock::new();
    CONFIG.get_or_init(|| {
        std::env::set_var("HPKE_KEYS", format!("{KEY_ID}:{PRIVATE_KEY_HEX}"));
        for (name, value) in ENV {
            std::env::set_var(name, value);
        }
        Config::from_env().expect("the fuzz gateway configuration parses")
    })
}

pub fn key_state() -> &'static KeyState {
    static KEYS: OnceLock<KeyState> = OnceLock::new();
    KEYS.get_or_init(|| KeyState::with_accept_only(config(), &[]).expect("the fuzz HPKE key"))
}

pub fn key_config() -> KeyConfig {
    KeyConfig::select(&key_state().public_config()).expect("the gateway's own key configuration")
}

/// xorshift64*, so that sealed seeds and crash inputs reproduce.
pub struct FixedRng(pub u64);

impl RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        for chunk in dst.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

impl CryptoRng for FixedRng {}

/// `plaintext` sealed to the gateway's key as a chunked request, deterministically.
pub fn seal_request(plaintext: &[u8]) -> (Vec<u8>, ChunkedResponseOpener) {
    zodl_ohttp_client::encapsulate_chunked_request_with_rng(
        &key_config(),
        plaintext,
        &mut FixedRng(0x9e37_79b9_7f4a_7c15),
    )
    .expect("sealing to the gateway's key")
}

pub fn block_on<F: std::future::Future>(future: F) -> F::Output {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("a tokio runtime")
        })
        .block_on(future)
}

pub fn decapsulate(sealed: &[u8]) -> anyhow::Result<(Vec<u8>, ResponseContext)> {
    block_on(ohttp_gateway::ohttp_chunked::decapsulate_chunked_request(
        sealed,
        key_state(),
    ))
}

/// One fixed exchange: the gateway's response context and the client's opener for it.
pub fn exchange() -> &'static (ResponseContext, ChunkedResponseOpener) {
    static EXCHANGE: OnceLock<(ResponseContext, ChunkedResponseOpener)> = OnceLock::new();
    EXCHANGE.get_or_init(|| {
        let plaintext = b"\x00\x04POST\x05https\x0fgateway.example\x01/\x00\x00\x00";
        let (sealed, opener) = seal_request(plaintext);
        let (opened, ctx) = decapsulate(&sealed).expect("the gateway opens its own request");
        assert_eq!(opened, plaintext);
        (ctx, opener)
    })
}

/// `RESPONSE_NONCE || chunks...` sealed under the fixed exchange: every part but the last a
/// non-final chunk (empty ones skipped), the last the final chunk.
pub fn seal_response(parts: &[&[u8]]) -> Vec<u8> {
    let mut sealer = ChunkSealer::new(&exchange().0, &RESPONSE_NONCE).expect("chunk sealer");
    let mut out = RESPONSE_NONCE.to_vec();
    let (last, rest): (&[u8], &[&[u8]]) = match parts.split_last() {
        Some((last, rest)) => (last, rest),
        None => (&[], &[]),
    };
    for part in rest.iter().filter(|p| !p.is_empty()) {
        out.extend_from_slice(&sealer.seal(part, false).expect("non-final chunk"));
    }
    out.extend_from_slice(&sealer.seal(last, true).expect("final chunk"));
    out
}

/// A signed key-configuration envelope as the gateway serves it, signed with the test
/// vector's key whatever its fields say.
pub fn signed_envelope(network: &str, not_before: u64, not_after: u64, configs: &[u8]) -> Vec<u8> {
    let key = SigningKey::from_bytes(&VECTOR_SEED);
    let mut message = b"zodl-ohttp-configs-v1".to_vec();
    message.push(0);
    message.extend_from_slice(network.as_bytes());
    message.push(0);
    message.extend_from_slice(&not_before.to_be_bytes());
    message.extend_from_slice(&not_after.to_be_bytes());
    message.extend_from_slice(configs);
    let b64 = base64::engine::general_purpose::STANDARD;
    let key_id = hex::encode(&Sha256::digest(key.verifying_key().as_bytes())[..4]);
    serde_json::to_vec(&serde_json::json!({
        "v": 1,
        "network": network,
        "configs": b64.encode(configs),
        "not_before": not_before,
        "not_after": not_after,
        "key_id": key_id,
        "sig": b64.encode(key.sign(&message).to_bytes()),
    }))
    .expect("an envelope")
}

/// What the gateway does with an opened inner request before anything goes upstream
/// (main.rs `handle_ohttp`), with the invariants that keep a request on its upstream.
pub fn inner_request(plaintext: &[u8]) {
    let Ok(request) = ohttp::parse_inner_request(plaintext) else {
        return;
    };
    let config = config();

    let target = proxy::resolve_backend(config, &request);
    if let BackendTarget::Upstream { uri, label } = &target {
        let uri: http::Uri = uri.parse().expect("a resolved upstream URI parses");
        let expected = if label == "lwd" {
            LWD_ADDR.to_string()
        } else {
            let base: http::Uri = config.backends[label]
                .parse()
                .expect("a configured backend");
            base.authority().expect("backend authority").to_string()
        };
        assert_eq!(
            uri.authority().map(|a| a.as_str()),
            Some(expected.as_str()),
            "the inner request left its upstream"
        );
        assert_eq!(
            uri.path_and_query().map(|p| p.as_str()),
            Some(request.path.as_str()),
            "the path is not exactly the request's"
        );
    }
    let _ = proxy::policy_denies(config, &request);
    let _ = proxy::gateway_host_policy_denies(config, &request);
    let _ = freshness::check(&request.headers, NOW, freshness::DEFAULT_WINDOW_SECS);

    for (name, value) in lwd::client_grpc_headers(&request.headers) {
        http::HeaderName::from_bytes(name.as_bytes()).expect("a forwarded header name");
        http::HeaderValue::from_str(&value).expect("a forwarded header value");
    }
    if let Ok(uri) = lwd::lwd_uri(LWD_ADDR, &request.path) {
        assert_eq!(uri.authority().map(|a| a.as_str()), Some(LWD_ADDR));
    }

    let range_ok =
        enforcement::check_block_range(&request.path, &request.body, MAX_BLOCK_RANGE).is_ok();
    if let Some(range) = BlockRangeRequest::parse(&request.body) {
        if request.path == GET_BLOCK_RANGE_PATH {
            assert!(range_ok || range.start.abs_diff(range.end) >= u64::from(MAX_BLOCK_RANGE));
            if range_ok {
                assert!(range.start.abs_diff(range.end) < u64::from(MAX_BLOCK_RANGE));
                let _ = range.heights();
            }
        }
        let _ = range.pool_key();
    }
    let _ = SubtreeRootsRequest::parse(&request.body);
    let content_type = request
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let _ = rpc_cache::policy(
        "fuzz:",
        &request.method,
        content_type,
        &request.path,
        &request.body,
        Some(&[1u8, 2, 3][..]),
    );
    let _ = health::normalize_rpc_name(&request.path, &request.method);
    let _ = health::normalize_method(&request.method);
    let _ = health::normalize_backend(&request.authority, &config.gateway_hosts, &config.backends);
    for mode in [
        padding::Mode::On,
        padding::Mode::Sensitive,
        padding::Mode::Off,
    ] {
        let _ = mode.pads(Some(&request.path));
    }
    static ROUTES: OnceLock<origin::ReadRoutes> = OnceLock::new();
    let _ = ROUTES
        .get_or_init(origin::ReadRoutes::default_list)
        .classify(
            target.is_lwd(),
            &request.authority,
            &request.method,
            &request.path,
        );
}

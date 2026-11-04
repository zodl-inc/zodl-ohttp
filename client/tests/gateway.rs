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

//! The client against the gateway's own key configuration, signed envelopes, chunked
//! decapsulation and streaming response encapsulation (`ohttp-gateway`'s library), served
//! in-process as relay and gateway in one, in front of an echo backend.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response as AxumResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use ed25519_dalek::{SigningKey, VerifyingKey};
use ohttp_gateway::chunked_stream::{collected_upstream, encode_response_stream};
use ohttp_gateway::config::Config;
use ohttp_gateway::hpke::KeyState;
use ohttp_gateway::ohttp::{self as gateway, InnerResponse};
use ohttp_gateway::ohttp_chunked::decapsulate_chunked_request;
use ohttp_gateway::signing::SigningState;
use zodl_ohttp_client::{Client, Error, KeyConfig, KeyConfigSource, Request};

const TIMEOUT: Duration = Duration::from_secs(10);
const NETWORK: &str = "testnet";
const SIGNING_SEED: &str = "2222222222222222222222222222222222222222222222222222222222222222";

/// The gateway's configuration with only its HPKE keys set, as its own tests build it.
fn gateway_config(key_id: u8, private_key_hex: &str) -> Config {
    Config {
        port: 0,
        lwd_addr: String::new(),
        mode: "ohttp".to_string(),
        relay_secrets: vec![],
        hpke_private_key: None,
        hpke_key_id: key_id,
        hpke_keys: vec![(key_id, private_key_hex.to_string())],
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
        network: NETWORK.to_string(),
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

fn key_state(key_id: u8) -> KeyState {
    KeyState::new(&gateway_config(key_id, &private_key(key_id))).unwrap()
}

/// Relay and gateway in one.
struct TestGateway {
    /// The key the gateway opens requests with.
    opens_with: Mutex<Arc<KeyState>>,
    /// The key its configuration endpoints advertise: `opens_with`, unless a test makes it
    /// advertise a key it no longer holds.
    advertises: Mutex<Arc<KeyState>>,
    signing: SigningState,
    /// The outer status the relay answers every post with instead of forwarding it.
    refuse_with: Mutex<Option<StatusCode>>,
    /// An outer answer given to the next post only, before the relay goes back to forwarding.
    refuse_once: Mutex<Option<(StatusCode, Vec<u8>)>>,
    /// The `Retry-After` of that answer, if any.
    retry_after: Mutex<Option<&'static str>>,
    /// The `Cache-Control` of the unsigned configuration endpoint, if any.
    cache_control: Mutex<Option<&'static str>>,
    /// The media type the relay labels its answers with.
    answer_type: Mutex<&'static str>,
    config_fetches: AtomicUsize,
    posts: AtomicUsize,
    /// How many of the next opened requests the gateway refuses as stale (inner 400,
    /// `ohttp-freshness: rejected`).
    refuse_stale: Mutex<usize>,
}

impl TestGateway {
    fn rotate(&self, key_id: u8) {
        let keys = Arc::new(key_state(key_id));
        *self.opens_with.lock().unwrap() = keys.clone();
        *self.advertises.lock().unwrap() = keys;
    }

    fn signer(&self) -> VerifyingKey {
        let seed: [u8; 32] = hex::decode(SIGNING_SEED).unwrap().try_into().unwrap();
        SigningKey::from_bytes(&seed).verifying_key()
    }
}

async fn configs(State(gw): State<Arc<TestGateway>>) -> AxumResponse {
    gw.config_fetches.fetch_add(1, Ordering::SeqCst);
    let document = gw.advertises.lock().unwrap().public_config();
    let cache_control = *gw.cache_control.lock().unwrap();
    let mut response =
        ([(header::CONTENT_TYPE, "application/ohttp-keys")], document).into_response();
    if let Some(value) = cache_control {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, value.parse().unwrap());
    }
    response
}

async fn signed_configs(State(gw): State<Arc<TestGateway>>) -> AxumResponse {
    gw.config_fetches.fetch_add(1, Ordering::SeqCst);
    let document = gw.advertises.lock().unwrap().public_config();
    Json(gw.signing.get_signed_config(&document)).into_response()
}

/// The gateway's handling of a sealed request, as its `/gateway` route does it: an unknown
/// key id is `422`, any other failure to open `400`; the inner request goes to `echo`.
async fn relay(State(gw): State<Arc<TestGateway>>, body: Bytes) -> AxumResponse {
    gw.posts.fetch_add(1, Ordering::SeqCst);
    if let Some(status) = *gw.refuse_with.lock().unwrap() {
        return status.into_response();
    }
    if let Some((status, body)) = gw.refuse_once.lock().unwrap().take() {
        let mut response = (status, body).into_response();
        if let Some(value) = *gw.retry_after.lock().unwrap() {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, value.parse().unwrap());
        }
        return response;
    }
    let keys = gw.opens_with.lock().unwrap().clone();
    let (plain, context) = match decapsulate_chunked_request(&body[..], &keys).await {
        Ok(opened) => opened,
        Err(e) if e.to_string().contains("Unknown key_id") => {
            return StatusCode::UNPROCESSABLE_ENTITY.into_response()
        }
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let inner = gateway::parse_inner_request(&plain).unwrap();
    let stale = {
        let mut left = gw.refuse_stale.lock().unwrap();
        let refuse = *left > 0;
        *left = left.saturating_sub(1);
        refuse
    };
    let answer = if stale {
        InnerResponse {
            status: 400,
            headers: vec![
                ("content-type".into(), "text/plain".into()),
                ("ohttp-freshness".into(), "rejected".into()),
                ("ohttp-server-time".into(), "1800000000".into()),
            ],
            body: b"Request timestamp outside the freshness window".to_vec(),
        }
    } else {
        echo(&inner)
    };
    let sealed = encode_response_stream(
        context,
        answer.status,
        answer.headers,
        collected_upstream(answer.body, vec![]),
        16384,
        Duration::from_millis(50),
        "test".to_string(),
    );
    let answer_type = *gw.answer_type.lock().unwrap();
    (
        [(header::CONTENT_TYPE, answer_type)],
        axum::body::Body::from_stream(sealed),
    )
        .into_response()
}

/// The backend: answers with the status the `x-status` header asks for, the request's
/// method, authority and path as header fields, and its body.
fn echo(inner: &gateway::InnerRequest) -> InnerResponse {
    let asked = inner
        .headers
        .iter()
        .find(|(k, _)| k == "x-status")
        .map(|(_, v)| v.parse().unwrap());
    InnerResponse {
        status: asked.unwrap_or(200),
        headers: vec![
            ("content-type".into(), "application/json".into()),
            ("x-method".into(), inner.method.clone()),
            ("x-authority".into(), inner.authority.clone()),
            ("x-path".into(), inner.path.clone()),
        ],
        body: inner.body.clone(),
    }
}

async fn spawn() -> (String, Arc<TestGateway>) {
    let keys = Arc::new(key_state(1));
    let gw = Arc::new(TestGateway {
        opens_with: Mutex::new(keys.clone()),
        advertises: Mutex::new(keys),
        signing: SigningState::new(SIGNING_SEED, NETWORK.to_string()).unwrap(),
        refuse_with: Mutex::new(None),
        refuse_once: Mutex::new(None),
        retry_after: Mutex::new(None),
        cache_control: Mutex::new(None),
        answer_type: Mutex::new("message/ohttp-chunked-res"),
        config_fetches: AtomicUsize::new(0),
        posts: AtomicUsize::new(0),
        refuse_stale: Mutex::new(0),
    });
    let app = Router::new()
        .route("/ohttp-configs", get(configs))
        .route("/ohttp-configs/signed", get(signed_configs))
        .route("/relay", post(relay))
        .route("/relay-rate-limited", post(relay))
        .with_state(gw.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), gw)
}

fn plain_client(base: &str) -> Client {
    Client::new(
        format!("{base}/relay"),
        KeyConfigSource::Plain {
            url: format!("{base}/ohttp-configs"),
        },
    )
}

fn json_post() -> Request {
    Request::new("POST", "backend.example", "/v1/slots/ab/entries?since=3")
        .header("content-type", "application/json")
        .body(br#"{"payload":"aGk="}"#.to_vec())
}

#[tokio::test]
async fn a_request_reaches_the_backend_and_its_answer_opens() {
    let (base, gw) = spawn().await;
    let client = plain_client(&base);
    let response = client.send(&json_post(), TIMEOUT).await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.header("x-method"), Some("POST"));
    assert_eq!(response.header("x-authority"), Some("backend.example"));
    assert_eq!(
        response.header("x-path"),
        Some("/v1/slots/ab/entries?since=3")
    );
    assert_eq!(response.body, br#"{"payload":"aGk="}"#);

    // The configuration is kept.
    client
        .send(&Request::new("GET", "backend.example", "/v1/info"), TIMEOUT)
        .await
        .unwrap();
    assert_eq!(gw.config_fetches.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_freshness_refusal_is_sent_once_more_and_only_once() {
    let (base, gw) = spawn().await;
    let client = plain_client(&base);

    *gw.refuse_stale.lock().unwrap() = 1;
    let response = client.send(&json_post(), TIMEOUT).await.unwrap();
    assert_eq!(response.status, 200, "the retry is answered");
    assert_eq!(response.header("x-method"), Some("POST"));
    assert_eq!(gw.posts.load(Ordering::SeqCst), 2);

    *gw.refuse_stale.lock().unwrap() = 2;
    let response = client.send(&json_post(), TIMEOUT).await.unwrap();
    assert_eq!(
        response.status, 400,
        "a second refusal is returned as it is"
    );
    assert_eq!(response.header("ohttp-freshness"), Some("rejected"));
    assert_eq!(
        gw.posts.load(Ordering::SeqCst),
        4,
        "never more than one retry"
    );
    // The refusal set the offset to the test gateway's clock; put it back for other tests.
    zodl_ohttp_client::freshness::observe_response_headers(&[(
        "ohttp-server-time",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string(),
    )]);
}

#[tokio::test]
async fn a_backend_error_is_an_answer() {
    let (base, _gw) = spawn().await;
    let request = Request::new("GET", "backend.example", "/v1/slots/ab").header("x-status", "404");
    let response = plain_client(&base).send(&request, TIMEOUT).await.unwrap();
    assert_eq!(response.status, 404);
}

#[tokio::test]
async fn a_signed_configuration_is_checked_against_the_pinned_key() {
    let (base, gw) = spawn().await;
    let signed = |signer| {
        Client::new(
            format!("{base}/relay"),
            KeyConfigSource::Signed {
                url: format!("{base}/ohttp-configs/signed"),
                network: NETWORK.to_string(),
                signer,
            },
        )
    };
    let response = signed(gw.signer())
        .send(&json_post(), TIMEOUT)
        .await
        .unwrap();
    assert_eq!(response.status, 200);

    let impostor = SigningKey::from_bytes(&[7; 32]).verifying_key();
    let Err(Error::KeyConfig(_)) = signed(impostor).send(&json_post(), TIMEOUT).await else {
        panic!("an envelope signed by another key was used");
    };
}

#[tokio::test]
async fn a_rotated_key_is_fetched_again_once() {
    let (base, gw) = spawn().await;
    let client = plain_client(&base);
    client.send(&json_post(), TIMEOUT).await.unwrap();
    gw.rotate(2);
    let response = client.send(&json_post(), TIMEOUT).await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(gw.config_fetches.load(Ordering::SeqCst), 2);
    // The first, the refused one under the old key, the one under the new key.
    assert_eq!(gw.posts.load(Ordering::SeqCst), 3);

    // A gateway that keeps refusing the key it advertises is refused once, not looped on.
    *gw.opens_with.lock().unwrap() = Arc::new(key_state(3));
    let Err(Error::Refused { status: 422 }) = client.send(&json_post(), TIMEOUT).await else {
        panic!("a refused key was not reported");
    };
    assert_eq!(gw.posts.load(Ordering::SeqCst), 5);
}

/// ZIP, "Outer response contract": an outer 400 or 422 with any body refetches the key
/// configuration and retries once, sealed afresh; a second one is permanent.
#[tokio::test]
async fn an_outer_400_or_422_with_any_body_is_refetched_once() {
    for status in [StatusCode::BAD_REQUEST, StatusCode::UNPROCESSABLE_ENTITY] {
        for body in [&b""[..], b"anything at all", b"\xff\xfe"] {
            let (base, gw) = spawn().await;
            let client = plain_client(&base);
            client.send(&json_post(), TIMEOUT).await.unwrap();
            assert_eq!(gw.config_fetches.load(Ordering::SeqCst), 1);
            *gw.refuse_once.lock().unwrap() = Some((status, body.to_vec()));
            let response = client.send(&json_post(), TIMEOUT).await.unwrap();
            assert_eq!(response.status, 200);
            // The kept configuration was discarded and fetched again; the refused post and
            // the retry are two posts beyond the first.
            assert_eq!(gw.config_fetches.load(Ordering::SeqCst), 2, "{status}");
            assert_eq!(gw.posts.load(Ordering::SeqCst), 3, "{status}");

            // The second one in a row is permanent: no third post.
            *gw.refuse_with.lock().unwrap() = Some(status);
            let Err(Error::Refused { status: got }) = client.send(&json_post(), TIMEOUT).await
            else {
                panic!("a repeated {status} was not reported");
            };
            assert_eq!(got, status.as_u16());
            assert_eq!(gw.posts.load(Ordering::SeqCst), 5, "{status}");
        }
    }
}

/// ZIP, "Retrieval, caching and rotation": an unsigned configuration is kept for its
/// `max-age`, or 5 minutes without one.
#[tokio::test]
async fn an_unsigned_configuration_is_kept_for_its_max_age() {
    let (base, gw) = spawn().await;
    *gw.cache_control.lock().unwrap() = Some("public, max-age=0");
    let client = plain_client(&base);
    for _ in 0..2 {
        client.send(&json_post(), TIMEOUT).await.unwrap();
    }
    assert_eq!(gw.config_fetches.load(Ordering::SeqCst), 2);
    *gw.cache_control.lock().unwrap() = Some("max-age=3600");
    client.send(&json_post(), TIMEOUT).await.unwrap();
    client.send(&json_post(), TIMEOUT).await.unwrap();
    assert_eq!(gw.config_fetches.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn an_outer_refusal_is_reported() {
    let (base, gw) = spawn().await;
    *gw.refuse_with.lock().unwrap() = Some(StatusCode::SERVICE_UNAVAILABLE);
    let Err(Error::Refused { status: 503 }) = plain_client(&base).send(&json_post(), TIMEOUT).await
    else {
        panic!("a refusal by the relay was not reported");
    };
}

/// ZIP, "Outer response contract": a `Retry-After` on a 429 holds every later request through
/// that relay, which is not posted to until the pause has run.
#[tokio::test]
async fn a_rate_limited_relay_is_not_posted_to_until_its_pause_has_run() {
    let (base, gw) = spawn().await;
    // Its own relay path: the pause lives in the process-wide table, keyed by relay URL, and
    // outlives this test, while a later test may get the same ephemeral port.
    let rate_limited_client = || {
        Client::new(
            format!("{base}/relay-rate-limited"),
            KeyConfigSource::Plain {
                url: format!("{base}/ohttp-configs"),
            },
        )
    };
    let client = rate_limited_client();
    *gw.refuse_once.lock().unwrap() = Some((StatusCode::TOO_MANY_REQUESTS, Vec::new()));
    *gw.retry_after.lock().unwrap() = Some("30");
    let Err(Error::Refused { status: 429 }) = client.send(&json_post(), TIMEOUT).await else {
        panic!("a 429 was not reported");
    };
    assert_eq!(gw.posts.load(Ordering::SeqCst), 1);
    // Another client of the same relay waits too, and nothing is posted.
    let Err(Error::Backoff { wait }) = rate_limited_client().send(&json_post(), TIMEOUT).await
    else {
        panic!("the relay's pause was not kept");
    };
    assert!(wait > Duration::from_secs(25) && wait <= Duration::from_secs(30));
    assert_eq!(gw.posts.load(Ordering::SeqCst), 1);
}

/// ZIP, "Outer request to the Relay": a sealed request over 10 MiB is refused before it is
/// posted, as an outer 413 would be.
#[tokio::test]
async fn an_oversized_request_is_not_posted() {
    let (base, gw) = spawn().await;
    let request = Request::new("POST", "backend.example", "/v1/upload")
        .header("content-type", "application/octet-stream")
        .body(vec![0u8; 10 * 1024 * 1024]);
    let Err(Error::Refused { status: 413 }) = plain_client(&base).send(&request, TIMEOUT).await
    else {
        panic!("an oversized request was not refused");
    };
    assert_eq!(gw.posts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_answer_that_is_not_a_sealed_response_is_refused() {
    let (base, gw) = spawn().await;
    *gw.answer_type.lock().unwrap() = "text/html; charset=UTF-8";
    let Err(Error::MediaType(_)) = plain_client(&base).send(&json_post(), TIMEOUT).await else {
        panic!("an HTML answer was opened");
    };
    // Parameters and case do not matter.
    *gw.answer_type.lock().unwrap() = "Message/OHTTP-chunked-res; x=1";
    plain_client(&base)
        .send(&json_post(), TIMEOUT)
        .await
        .unwrap();
}

#[tokio::test]
async fn the_gateways_preferred_key_is_used_and_either_opens() {
    let (base, gw) = spawn().await;
    let mut config = gateway_config(5, &private_key(5));
    config.hpke_keys = vec![(5, private_key(5)), (6, private_key(6))];
    let two_keys = Arc::new(KeyState::new(&config).unwrap());
    *gw.opens_with.lock().unwrap() = two_keys.clone();
    *gw.advertises.lock().unwrap() = two_keys.clone();
    assert_eq!(
        KeyConfig::select(&two_keys.public_config())
            .unwrap()
            .key_id(),
        5
    );
    plain_client(&base)
        .send(&json_post(), TIMEOUT)
        .await
        .unwrap();

    // A client still holding the second key is served too.
    *gw.advertises.lock().unwrap() = Arc::new(key_state(6));
    plain_client(&base)
        .send(&json_post(), TIMEOUT)
        .await
        .unwrap();
    assert_eq!(gw.posts.load(Ordering::SeqCst), 2);
}

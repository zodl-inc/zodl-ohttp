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
//!
//! The test server speaks plain HTTP on the loopback interface, so every client here is built
//! with `Client::insecure_for_local_testing`; most use the unsigned source (feature
//! `insecure-plain-key-config`) to exercise the cache rules of `/ohttp-configs`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response as AxumResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use ed25519_dalek::{SigningKey, VerifyingKey};
use futures_util::stream::BoxStream;
use futures_util::StreamExt;
use ohttp_gateway::chunked_stream::{collected_upstream, encode_response_stream, UpFrame};
use ohttp_gateway::config::Config;
use ohttp_gateway::hpke::KeyState;
use ohttp_gateway::ohttp::{self as gateway, InnerResponse};
use ohttp_gateway::ohttp_chunked::decapsulate_chunked_request;
use ohttp_gateway::signing::SigningState;
use zodl_ohttp_client::{
    is_unknown_authority, Client, Error, HostListAnswer, HostListScope, HttpErrorKind, KeyConfig,
    KeyConfigSource, Network, NoHostList, OuterHeaders, RefreshOutcome, Request, ThirdPartyHosts,
};

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
        dynamic_hosts: Default::default(),
        host_list: Default::default(),
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
    /// The request headers of every key-configuration fetch and post, with the route.
    seen_headers: Mutex<Vec<(&'static str, HeaderMap)>>,
    /// The gateway configuration the third-party host list is answered from, by the gateway's
    /// own `host_list` code. `None`: every request goes to the echo backend.
    third_party: Mutex<Option<Config>>,
    /// The gateway answers the host list request with a body larger than a wallet accepts.
    oversized_host_list: AtomicBool,
    /// The relay does not answer a post for a long time.
    stall: AtomicBool,
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

async fn configs(State(gw): State<Arc<TestGateway>>, headers: HeaderMap) -> AxumResponse {
    gw.config_fetches.fetch_add(1, Ordering::SeqCst);
    gw.seen_headers.lock().unwrap().push(("configs", headers));
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

async fn signed_configs(State(gw): State<Arc<TestGateway>>, headers: HeaderMap) -> AxumResponse {
    gw.config_fetches.fetch_add(1, Ordering::SeqCst);
    gw.seen_headers.lock().unwrap().push(("signed", headers));
    let document = gw.advertises.lock().unwrap().public_config();
    Json(gw.signing.get_signed_config(&document)).into_response()
}

/// The gateway's handling of a sealed request, as its `/gateway` route does it: an unknown
/// key id is `422`, any other failure to open `400`; the inner request goes to `echo`.
async fn relay(
    State(gw): State<Arc<TestGateway>>,
    headers: HeaderMap,
    body: Bytes,
) -> AxumResponse {
    gw.posts.fetch_add(1, Ordering::SeqCst);
    gw.seen_headers.lock().unwrap().push(("relay", headers));
    if gw.stall.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
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
    } else if let Some(answer) = third_party_answer(&gw, &inner) {
        answer
    } else {
        echo(&inner)
    };
    // The oversized host list never ends: after more than a wallet reads, nothing follows,
    // not even the final chunk. A client that waited for the end would run into its timeout.
    let never_ends =
        gw.oversized_host_list.load(Ordering::SeqCst) && answer.body.len() > OVERSIZED_BYTES / 2;
    let upstream: BoxStream<'static, anyhow::Result<UpFrame>> = if never_ends {
        collected_upstream(answer.body, vec![])
            .chain(futures_util::stream::pending())
            .boxed()
    } else {
        collected_upstream(answer.body, vec![]).boxed()
    };
    let sealed = encode_response_stream(
        context,
        answer.status,
        answer.headers,
        upstream,
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

/// What the gateway itself answers when it has third-party hosts configured: the host list
/// (its own `host_list::is_request` / `host_list::answer`), and the refusal of an authority it
/// does not carry. `None`: forwarded (here: to the echo backend).
fn third_party_answer(gw: &TestGateway, inner: &gateway::InnerRequest) -> Option<InnerResponse> {
    let guard = gw.third_party.lock().unwrap();
    let config = guard.as_ref()?;
    if ohttp_gateway::host_list::is_request(config, inner) {
        if gw.oversized_host_list.load(Ordering::SeqCst) {
            // What the gateway itself never sends: more than a wallet reads.
            return Some(InnerResponse {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())],
                body: vec![b' '; OVERSIZED_BYTES],
            });
        }
        return Some(ohttp_gateway::host_list::answer(config, inner));
    }
    let refusal = |status: u16, body: &[u8]| {
        Some(InnerResponse {
            status,
            headers: vec![("content-type".into(), "text/plain".into())],
            body: body.to_vec(),
        })
    };
    use ohttp_gateway::proxy::BackendTarget;
    match ohttp_gateway::proxy::resolve_backend(config, inner) {
        BackendTarget::Upstream { .. } => None,
        BackendTarget::Rejected => refusal(403, b"unknown authority"),
        // A malformed authority (upper case, for one) or path: refused, not forwarded.
        BackendTarget::MalformedAuthority(_) => refusal(403, b"forbidden"),
        BackendTarget::MalformedPath(_) => refusal(400, b"bad request"),
    }
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
        seen_headers: Mutex::new(Vec::new()),
        third_party: Mutex::new(None),
        oversized_host_list: AtomicBool::new(false),
        stall: AtomicBool::new(false),
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
    Client::insecure_for_local_testing(
        format!("{base}/relay"),
        KeyConfigSource::Plain {
            url: format!("{base}/ohttp-configs"),
        },
    )
    .unwrap()
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

/// `Client::new` refuses plain-HTTP URLs and the unsigned source before anything is sent.
#[tokio::test]
async fn a_client_refuses_plain_http() {
    let (base, gw) = spawn().await;
    let sources = [
        KeyConfigSource::Plain {
            url: format!("{base}/ohttp-configs"),
        },
        KeyConfigSource::Signed {
            url: format!("{base}/ohttp-configs/signed"),
            network: Network::Testnet,
            signer: gw.signer(),
        },
    ];
    for keys in sources {
        let Err(Error::Setup { .. }) = Client::new(format!("{base}/relay"), keys) else {
            panic!("a plain-HTTP client was built");
        };
    }
    assert_eq!(gw.config_fetches.load(Ordering::SeqCst), 0);
    assert_eq!(gw.posts.load(Ordering::SeqCst), 0);
}

/// What the relay sees of `Client`: exactly the headers of `OuterHeaders::LIBRARY` (the set
/// every preset shares) on the post and the signed fetch, beside those the HTTP stack adds for
/// the connection and the body; `Accept: application/ohttp-keys` on the unsigned fetch.
#[tokio::test]
async fn the_relay_sees_the_presets_headers_and_nothing_more() {
    let (base, gw) = spawn().await;
    let signed = Client::insecure_for_local_testing(
        format!("{base}/relay"),
        KeyConfigSource::Signed {
            url: format!("{base}/ohttp-configs/signed"),
            network: Network::Testnet,
            signer: gw.signer(),
        },
    )
    .unwrap();
    signed.send(&json_post(), TIMEOUT).await.unwrap();
    plain_client(&base)
        .send(&json_post(), TIMEOUT)
        .await
        .unwrap();
    let expected = |pairs: Vec<(&'static str, String)>| -> Vec<(String, String)> {
        let mut pairs: Vec<_> = pairs
            .into_iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect();
        pairs.sort();
        pairs
    };
    let seen = gw.seen_headers.lock().unwrap();
    let routes: Vec<_> = seen.iter().map(|(route, _)| *route).collect();
    assert_eq!(routes, ["signed", "relay", "configs", "relay"]);
    for (route, headers) in seen.iter() {
        let mut got: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap().to_string()))
            .filter(|(k, _)| !matches!(k.as_str(), "host" | "content-length"))
            .collect();
        got.sort();
        let want = match *route {
            "relay" => expected(OuterHeaders::LIBRARY.relay_post(None)),
            "signed" => expected(OuterHeaders::LIBRARY.key_fetch_signed(None)),
            _ => expected(OuterHeaders::LIBRARY.key_fetch_plain(None)),
        };
        assert_eq!(got, want, "{route}");
    }
}

/// A transport error shows its kind only: no URL, host, address, port or path.
fn assert_shows_no_peer(error: &Error, base: &str) {
    let shown = format!("{error} | {error:?}");
    let authority = base.trim_start_matches("http://");
    let (host, port) = authority.split_once(':').unwrap();
    for part in [
        base,
        authority,
        host,
        port,
        "/ohttp-configs",
        "/relay",
        "http:",
    ] {
        assert!(!shown.contains(part), "{shown} shows {part}");
    }
}

#[tokio::test]
async fn a_transport_error_shows_its_kind_only() {
    // A port reserved for this test (bound, never listening), so a connection is refused and no
    // other test can take the port meanwhile.
    let reserved = tokio::net::TcpSocket::new_v4().unwrap();
    reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let base = format!("http://{}", reserved.local_addr().unwrap());
    let Err(error @ Error::Http(_)) = plain_client(&base).send(&json_post(), TIMEOUT).await else {
        panic!("a closed port answered");
    };
    let Error::Http(http) = &error else {
        unreachable!()
    };
    assert_eq!(http.kind(), HttpErrorKind::Connect);
    assert_shows_no_peer(&error, &base);

    // An error status on the key-configuration fetch.
    let (base, _gw) = spawn().await;
    let missing = Client::insecure_for_local_testing(
        format!("{base}/relay"),
        KeyConfigSource::Plain {
            url: format!("{base}/ohttp-configs/missing"),
        },
    )
    .unwrap();
    let Err(error @ Error::Http(_)) = missing.send(&json_post(), TIMEOUT).await else {
        panic!("a 404 key configuration was used");
    };
    let Error::Http(http) = &error else {
        unreachable!()
    };
    assert_eq!(http.kind(), HttpErrorKind::Status(404));
    assert_shows_no_peer(&error, &base);
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
        Client::insecure_for_local_testing(
            format!("{base}/relay"),
            KeyConfigSource::Signed {
                url: format!("{base}/ohttp-configs/signed"),
                network: Network::Testnet,
                signer,
            },
        )
        .unwrap()
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
        Client::insecure_for_local_testing(
            format!("{base}/relay-rate-limited"),
            KeyConfigSource::Plain {
                url: format!("{base}/ohttp-configs"),
            },
        )
        .unwrap()
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

const GATEWAY_HOST: &str = "ohttp-gateway.example";
/// The body of the oversized host list of the test gateway: several times what a wallet reads.
const OVERSIZED_BYTES: usize = 2 * 1024 * 1024;

/// A gateway configuration that carries `aliases` (each on `GET /*`) and publishes its host
/// list in `mode`.
fn third_party_config(aliases: &[&str], mode: ohttp_gateway::host_list::PublishMode) -> Config {
    let mut config = gateway_config(1, &private_key(1));
    config.gateway_hosts = vec![GATEWAY_HOST.to_string()];
    config.lwd_addr = "lwd.example:9067".to_string();
    for alias in aliases {
        config
            .backends
            .insert(alias.to_string(), format!("https://upstream-of-{alias}"));
        config.backends_policy.insert(
            alias.to_string(),
            vec![("GET".to_string(), "/*".to_string())],
        );
    }
    config.host_list = ohttp_gateway::host_list::HostListSettings {
        mode,
        max_age_secs: 300,
    };
    config
}

#[tokio::test]
async fn the_gateways_host_list_is_fetched_revalidated_and_followed() {
    use ohttp_gateway::host_list::PublishMode;
    let (base, gw) = spawn().await;
    let client = plain_client(&base);
    *gw.third_party.lock().unwrap() = Some(third_party_config(
        &["api.example.org", "query.example.org:8443"],
        PublishMode::All,
    ));

    // The list, as the gateway's own code writes it.
    let answer = client
        .third_party_hosts(GATEWAY_HOST, None, TIMEOUT)
        .await
        .unwrap();
    let HostListAnswer::List(list) = answer else {
        panic!("a list");
    };
    assert_eq!(list.scope, HostListScope::All);
    assert_eq!(list.max_age_secs, 300);
    assert_eq!(list.revision.len(), 16);
    let names: Vec<&str> = list.hosts.iter().map(|h| h.host.as_str()).collect();
    assert_eq!(names, ["api.example.org", "query.example.org:8443"]);
    assert_eq!(list.hosts[0].routes, ["GET /*"]);
    // The alias targets are the gateway's business.
    assert!(!format!("{list:?}").contains("upstream"));

    // Revalidated with the revision held: not modified.
    assert_eq!(
        client
            .third_party_hosts(GATEWAY_HOST, Some(&list.revision), TIMEOUT)
            .await
            .unwrap(),
        HostListAnswer::NotModified
    );

    // The holder: the bootstrap list until the first fetch, then the gateway's list.
    let hosts = ThirdPartyHosts::new(["compiled-only.example.org", "api.example.org"]);
    assert!(hosts.is_carried("compiled-only.example.org"));
    assert!(!hosts.is_carried("query.example.org:8443"));
    assert_eq!(
        hosts.refresh(&client, GATEWAY_HOST, TIMEOUT).await,
        RefreshOutcome::Updated
    );
    assert_eq!(hosts.revision().as_deref(), Some(list.revision.as_str()));
    assert!(hosts.is_carried("api.example.org") && hosts.is_carried("QUERY.example.org:8443"));
    assert!(
        !hosts.is_carried("compiled-only.example.org"),
        "scope all: exactly the list"
    );
    // Fresh: nothing is sent.
    let posts = gw.posts.load(Ordering::SeqCst);
    assert_eq!(
        hosts.refresh(&client, GATEWAY_HOST, TIMEOUT).await,
        RefreshOutcome::NotDue
    );
    assert_eq!(gw.posts.load(Ordering::SeqCst), posts);

    // Servers of a service: the ones the gateway carries are used, the rest dropped.
    let servers = hosts.filter_servers([
        "https://api.example.org",
        "https://added-later.example.org",
        "https://query.example.org:8443/",
    ]);
    let kept: Vec<(&str, &str)> = servers
        .carried
        .iter()
        .map(|server| (server.url, server.authority.as_str()))
        .collect();
    assert_eq!(
        kept,
        [
            ("https://api.example.org", "api.example.org"),
            ("https://query.example.org:8443/", "query.example.org:8443"),
        ]
    );
    // The authority returned is the one the gateway knows: a request with it is forwarded.
    let forwarded = client
        .send(&Request::new("GET", kept[1].1, "/v1/info"), TIMEOUT)
        .await
        .unwrap();
    assert_eq!(forwarded.status, 200);
    assert_eq!(servers.dropped, 1);

    // The gateway adds a host. A request for it is refused by the gateway until then with
    // `403 unknown authority`; the old revision now gets the new document.
    let refused = client
        .send(
            &Request::new("GET", "added-later.example.org", "/v1/info"),
            TIMEOUT,
        )
        .await
        .unwrap();
    assert!(is_unknown_authority(&refused));
    *gw.third_party.lock().unwrap() = Some(third_party_config(
        &[
            "api.example.org",
            "query.example.org:8443",
            "added-later.example.org",
        ],
        PublishMode::All,
    ));
    let HostListAnswer::List(grown) = client
        .third_party_hosts(GATEWAY_HOST, Some(&list.revision), TIMEOUT)
        .await
        .unwrap()
    else {
        panic!("the new list");
    };
    assert_ne!(grown.revision, list.revision);
    assert_eq!(grown.hosts.len(), 3);
    // The holder learns it with one refresh before refusing (its list is seconds old here, so
    // the refresh is asked for through a reported unknown authority of a listed host instead).
    assert!(!hosts.is_carried("added-later.example.org"));
    assert!(hosts.report_unknown_authority("api.example.org"));
    assert_eq!(
        hosts.refresh(&client, GATEWAY_HOST, TIMEOUT).await,
        RefreshOutcome::Updated
    );
    assert!(hosts.is_carried("added-later.example.org"));
    assert_eq!(hosts.revision().as_deref(), Some(grown.revision.as_str()));
    let carried = client
        .send(
            &Request::new("GET", "added-later.example.org", "/v1/info"),
            TIMEOUT,
        )
        .await
        .unwrap();
    assert_eq!(carried.status, 200);
}

#[tokio::test]
async fn a_dynamic_scope_list_adds_to_the_bootstrap_list() {
    use ohttp_gateway::host_list::PublishMode;
    let (base, gw) = spawn().await;
    let client = plain_client(&base);
    // `dynamic`: the static aliases are not published; this gateway has no dynamic source.
    *gw.third_party.lock().unwrap() = Some(third_party_config(
        &["api.example.org"],
        PublishMode::Dynamic,
    ));
    let hosts = ThirdPartyHosts::new(["api.example.org"]);
    assert_eq!(
        hosts.refresh(&client, GATEWAY_HOST, TIMEOUT).await,
        RefreshOutcome::Updated
    );
    let held = hosts.held().unwrap();
    assert_eq!(held.scope, HostListScope::Dynamic);
    assert!(held.hosts.is_empty());
    assert!(
        hosts.is_carried("api.example.org"),
        "the compiled list stays in force"
    );
}

#[tokio::test]
async fn a_gateway_without_a_list_leaves_what_is_held() {
    use ohttp_gateway::dynamic_hosts::{DynamicHosts, Reserved, Settings};
    use ohttp_gateway::host_list::PublishMode;
    let (base, gw) = spawn().await;
    let client = plain_client(&base);
    let hosts = ThirdPartyHosts::new(["compiled.example.org"]);

    // Publishing off: the path is not the gateway's (here it reaches the echo backend, whose
    // answer is no host list document).
    *gw.third_party.lock().unwrap() =
        Some(third_party_config(&["api.example.org"], PublishMode::Off));
    let error = client
        .third_party_hosts(GATEWAY_HOST, None, TIMEOUT)
        .await
        .unwrap_err();
    assert!(
        matches!(error, Error::NoHostList(NoHostList::Malformed)),
        "{error}"
    );
    assert_eq!(
        hosts.refresh(&client, GATEWAY_HOST, TIMEOUT).await,
        RefreshOutcome::Kept(Some(NoHostList::Malformed))
    );
    assert!(hosts.held().is_none() && hosts.is_carried("compiled.example.org"));

    // Publishing on, but a source of the gateway was not read yet: the gateway's own 503.
    let mut starting = third_party_config(&["api.example.org"], PublishMode::All);
    starting.dynamic_hosts = DynamicHosts::parse(
        r#"[{"name":"servers","url":"https://config.example.org/servers.json",
             "lists":[{"pointer":"/servers","routes":"GET /*"}]}]"#,
        Reserved::default(),
        Settings::new(NETWORK, 4),
    )
    .unwrap();
    *gw.third_party.lock().unwrap() = Some(starting);
    let error = client
        .third_party_hosts(GATEWAY_HOST, None, TIMEOUT)
        .await
        .unwrap_err();
    assert!(
        matches!(error, Error::NoHostList(NoHostList::Status(503))),
        "{error}"
    );
    // The error names the status, not the gateway or a host.
    let shown = format!("{error} {error:?}");
    assert!(
        !shown.contains("example") && !shown.contains("127.0.0.1"),
        "{shown}"
    );
    // The holder is in its backoff after the first failure: nothing is sent, nothing changes.
    let posts = gw.posts.load(Ordering::SeqCst);
    assert_eq!(
        hosts.refresh(&client, GATEWAY_HOST, TIMEOUT).await,
        RefreshOutcome::NotDue
    );
    assert_eq!(gw.posts.load(Ordering::SeqCst), posts);
    assert!(hosts.is_carried("compiled.example.org") && !hosts.is_carried("api.example.org"));

    // An unreachable relay: the exchange fails, the holder keeps its list.
    let unreachable = plain_client("http://127.0.0.1:1");
    let fresh = ThirdPartyHosts::new(["compiled.example.org"]);
    assert_eq!(
        fresh.refresh(&unreachable, GATEWAY_HOST, TIMEOUT).await,
        RefreshOutcome::Kept(None)
    );
    assert!(fresh.is_carried("compiled.example.org"));
}

#[tokio::test]
async fn an_oversized_host_list_is_refused_while_it_streams() {
    use ohttp_gateway::host_list::PublishMode;
    let (base, gw) = spawn().await;
    let client = plain_client(&base);
    *gw.third_party.lock().unwrap() =
        Some(third_party_config(&["api.example.org"], PublishMode::All));
    gw.oversized_host_list.store(true, Ordering::SeqCst);
    // The answer never ends (the test gateway stalls after its oversized body), so only a
    // client that stops reading at the cap answers before the timeout, and with `TooLarge`.
    let started = std::time::Instant::now();
    let error = client
        .third_party_hosts(GATEWAY_HOST, None, TIMEOUT)
        .await
        .unwrap_err();
    assert!(
        matches!(error, Error::NoHostList(NoHostList::TooLarge)),
        "{error}"
    );
    assert!(started.elapsed() < TIMEOUT / 2, "{:?}", started.elapsed());
    let hosts = ThirdPartyHosts::new(["compiled.example.org"]);
    assert_eq!(
        hosts.refresh(&client, GATEWAY_HOST, TIMEOUT).await,
        RefreshOutcome::Kept(Some(NoHostList::TooLarge))
    );
    assert!(hosts.held().is_none() && hosts.is_carried("compiled.example.org"));
    // Any other request through the same client is unaffected by that limit.
    gw.oversized_host_list.store(false, Ordering::SeqCst);
    let answer = client
        .third_party_hosts(GATEWAY_HOST, None, TIMEOUT)
        .await
        .unwrap();
    assert!(matches!(answer, HostListAnswer::List(_)));
}

#[tokio::test]
async fn a_refresh_that_stalls_or_is_dropped_does_not_block_the_next() {
    use ohttp_gateway::host_list::PublishMode;
    let (base, gw) = spawn().await;
    let client = plain_client(&base);
    *gw.third_party.lock().unwrap() =
        Some(third_party_config(&["api.example.org"], PublishMode::All));
    // One exchange first, so that the client holds the key configuration and a connection.
    client
        .third_party_hosts(GATEWAY_HOST, None, TIMEOUT)
        .await
        .unwrap();
    gw.stall.store(true, Ordering::SeqCst);

    // The exchange runs into its timeout: a failure, what is held stays, nothing is running.
    let hosts = ThirdPartyHosts::new(["compiled.example.org"]);
    assert_eq!(
        hosts
            .refresh(&client, GATEWAY_HOST, Duration::from_millis(300))
            .await,
        RefreshOutcome::Kept(None)
    );
    assert!(!hosts.is_refreshing() && hosts.is_carried("compiled.example.org"));

    // While one refresh runs, another sends nothing and says that one is running.
    let busy = ThirdPartyHosts::new(["compiled.example.org"]);
    let posts = gw.posts.load(Ordering::SeqCst);
    let (first, second) = tokio::join!(
        busy.refresh(&client, GATEWAY_HOST, Duration::from_secs(4)),
        async {
            // Not before the first one's request is at the relay (which then stalls it), and
            // not for ever should that request never get there.
            while gw.posts.load(Ordering::SeqCst) == posts && busy.is_refreshing() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(busy.is_refreshing());
            busy.refresh(&client, GATEWAY_HOST, TIMEOUT).await
        }
    );
    assert_eq!(first, RefreshOutcome::Kept(None));
    assert_eq!(second, RefreshOutcome::Running);
    assert_eq!(gw.posts.load(Ordering::SeqCst), posts + 1, "one exchange");

    // The caller drops the refresh while its exchange runs: given up at once, counted as a
    // failure (the backoff runs), and the next refresh is not blocked behind it.
    let dropped = ThirdPartyHosts::new(["compiled.example.org"]);
    let cancelled = tokio::time::timeout(
        Duration::from_millis(300),
        dropped.refresh(&client, GATEWAY_HOST, TIMEOUT),
    )
    .await;
    assert!(cancelled.is_err(), "the refresh was still running");
    assert!(!dropped.is_refreshing());
    gw.stall.store(false, Ordering::SeqCst);
    assert_eq!(
        dropped.refresh(&client, GATEWAY_HOST, TIMEOUT).await,
        RefreshOutcome::NotDue
    );
    assert!(dropped.held().is_none() && dropped.is_carried("compiled.example.org"));
}

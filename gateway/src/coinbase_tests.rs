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

//! The coinbase alias against a stub upstream that records every request exactly as received.

use std::collections::HashMap;
use std::convert::Infallible;

use base64::Engine;
use ed25519_dalek::{SigningKey, Verifier};
use serde_json::{json, Value};
use zodl_ohttp_integrations::coinbase::{Country, SecretSource, Settings};

use super::*;

/// The address of the test key [`T1_KEY`] (made for the tests, no real funds; the published
/// test vector's key), compressed.
const T1: &str = "t1RwUkDxFKCydymAzBtTwHtVyH9Tvf6CiiL";
const T1_KEY: [u8; 32] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32,
];
/// Another test key.
const OTHER_KEY: [u8; 32] = [0x22; 32];
const REF: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const KEY_ID: &str = "00000000-0000-4000-8000-0000000000aa";

/// One request as the stub got it.
#[derive(Clone, Debug)]
pub(crate) struct Seen {
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

pub(crate) type Log = Arc<parking_lot::Mutex<Vec<Seen>>>;

struct Fixed;

impl NonceSource for Fixed {
    fn fill(&self, out: &mut [u8]) {
        out.fill(0x5a);
    }
}

/// A test key (a fixed seed; no real credential) and its CDP key document (64-byte pair).
fn test_key() -> (SigningKey, String) {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let mut pair = key.to_bytes().to_vec();
    pair.extend_from_slice(key.verifying_key().as_bytes());
    let document = format!(
        r#"{{"id":"{KEY_ID}","privateKey":"{}"}}"#,
        base64::engine::general_purpose::STANDARD.encode(&pair)
    );
    (key, document)
}

pub(crate) const ALIAS: &str = "onramp.example";

/// The settings of a test integration (its secret is never read: the signer is made here).
fn settings(upstream: &str, label: &str, enabled: bool, caps: (&str, &str)) -> Settings {
    Settings {
        label: label.to_string(),
        alias: ALIAS.to_string(),
        upstream: upstream.to_string(),
        secret: SecretSource {
            name: "cdp_key".to_string(),
            env: None,
            file: Some("/nonexistent/cdp_key".to_string()),
        },
        read_key: true,
        ttl_secs: 120,
        enabled,
        redirect_url: Some("wallet://onramp/return".to_string()),
        countries: [(
            "US".to_string(),
            Country {
                buy: true,
                sell: true,
            },
        )]
        .into(),
        rate_limit: caps.0.to_string(),
        status_rate_limit: caps.1.to_string(),
    }
}

/// A test integration with the caps `caps` (session, status), with or without its key.
pub(crate) fn entry_with(
    upstream: &str,
    label: &str,
    enabled: bool,
    keyed: bool,
    caps: (&str, &str),
) -> Entry {
    let (_, document) = test_key();
    let settings = settings(upstream, label, enabled, caps);
    let (signer, key) = if keyed {
        (
            Some(JwtEdDsa::from_cdp_json(&document, 120).unwrap()),
            KeyState::Loaded,
        )
    } else {
        (None, KeyState::Invalid("no key in this test".to_string()))
    };
    let provider = Coinbase::new(&settings, signer, Arc::new(Fixed)).unwrap();
    Entry::new(provider, key, "cdp_key")
}

/// [`entry_with`] with generous caps.
pub(crate) fn entry(upstream: &str, label: &str, enabled: bool, keyed: bool) -> Entry {
    entry_with(upstream, label, enabled, keyed, ("100/60s", "100/60s"))
}

/// A gateway with the coinbase alias of `entry` and `global_permits` upstream permits.
fn gateway_state(upstream: &str, entry: Entry, global_permits: usize) -> Arc<AppState> {
    gateway_state_shared(
        upstream,
        Integrations::from_entries(vec![entry]),
        global_permits,
    )
}

/// [`gateway_state`] over `integrations` (shared with another state).
fn gateway_state_shared(
    upstream: &str,
    integrations: Integrations,
    global_permits: usize,
) -> Arc<AppState> {
    let mut config = crate::config::test_config();
    config.backends = [(ALIAS.to_string(), upstream.to_string())].into();
    config.backends_policy = [(
        ALIAS.to_string(),
        zodl_ohttp_integrations::coinbase::ROUTES
            .iter()
            .map(|(m, p)| (m.to_string(), p.to_string()))
            .collect(),
    )]
    .into();
    config.coinbase = integrations;
    let lwd_semaphore = Arc::new(tokio::sync::Semaphore::new(128));
    let sources = Arc::new(crate::lwd::LwdSources::new(
        config.clone(),
        lwd_semaphore.clone(),
    ));
    let flights = Arc::new(crate::singleflight::RpcFlights::new(
        sources.clone(),
        config.network.clone(),
    ));
    let mempool = Arc::new(crate::mempool::MempoolFanout::new(
        sources.clone(),
        config.network.clone(),
    ));
    Arc::new(AppState {
        config,
        origin: crate::origin::OriginSettings::default(),
        cache: None,
        hpke: None,
        block_cache: None,
        subtree_cache: None,
        follower: None,
        mempool,
        flights,
        sources,
        signing: None,
        lwd_semaphore,
        global_semaphore: Arc::new(tokio::sync::Semaphore::new(global_permits)),
        cache_get_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
        large_response_semaphore: Arc::new(tokio::sync::Semaphore::new(2)),
        third_party: Default::default(),
        per_backend_semaphores: Arc::new(parking_lot::RwLock::new(HashMap::new())),
        request_semaphore: Arc::new(tokio::sync::Semaphore::new(1024)),
        write_forward: None,
    })
}

/// An inner request to the alias, with client headers that must never reach the upstream.
fn request(method: &str, path: &str, body: &str) -> InnerRequest {
    InnerRequest {
        method: method.to_string(),
        path: path.to_string(),
        authority: ALIAS.to_string(),
        headers: [
            ("content-type", "application/json"),
            ("authorization", "Bearer client-token"),
            ("cookie", "session=1"),
            ("x-forwarded-for", "192.0.2.7"),
            ("user-agent", "wallet/1.0 (device)"),
            ("x-api-key", "client-key"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect(),
        body: body.as_bytes().to_vec(),
    }
}

/// The base64 signature of `key` for `address` at `timestamp` (compressed key header).
fn sign(key: &[u8; 32], address: &str, timestamp: u64) -> String {
    use zodl_ohttp_integrations::coinbase::signature;
    let key = k256::ecdsa::SigningKey::from_slice(key).unwrap();
    let digest = signature::message_hash(signature::message(address, timestamp).as_bytes());
    let (sig, recovery) = key.sign_prehash_recoverable(&digest).unwrap();
    let mut bytes = vec![31 + recovery.to_byte()];
    bytes.extend_from_slice(&sig.to_bytes());
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A buy session body for [`T1`] with `fields`, claiming `timestamp`, signed by `key` at
/// `signed_at`.
fn session_signed(fields: &str, key: &[u8; 32], signed_at: u64, timestamp: u64) -> String {
    let sig = sign(key, T1, signed_at);
    format!(
        r#"{{"flow":"buy","address":"{T1}","ref":"{REF}"{fields},"timestamp":"{timestamp}","signature":"{sig}"}}"#
    )
}

/// A buy session body for [`T1`] with `fields`, signed by its key now.
pub(crate) fn session(fields: &str) -> String {
    let now = unix_now().unwrap();
    session_signed(fields, &T1_KEY, now, now)
}

async fn ask(state: &Arc<AppState>, req: &InnerRequest) -> (u16, Value, Vec<(String, String)>) {
    let provider = state.config.coinbase.get(&req.authority).unwrap();
    let resp = answer(state, req, &provider).await;
    let json = serde_json::from_slice(&resp.body).unwrap_or(Value::Null);
    (resp.status, json, resp.headers)
}

fn counter(name: &str, labels: &[(&str, &str)]) -> f64 {
    crate::health::REGISTRY
        .gather()
        .iter()
        .filter(|f| f.get_name() == name)
        .flat_map(|f| f.get_metric().iter())
        .filter(|m| {
            labels.iter().all(|(n, v)| {
                m.get_label()
                    .iter()
                    .any(|l| l.get_name() == *n && l.get_value() == *v)
            })
        })
        .map(|m| m.get_counter().get_value())
        .sum()
}

fn decode(part: &str) -> Vec<u8> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .unwrap()
}

/// The claims of `authorization` (`Bearer <jwt>`), its signature verified with the test key.
pub(crate) fn claims(authorization: &str) -> Value {
    let token = authorization.strip_prefix("Bearer ").unwrap();
    let (input, sig) = token.rsplit_once('.').unwrap();
    let sig = ed25519_dalek::Signature::from_slice(&decode(sig)).unwrap();
    let (key, _) = test_key();
    key.verifying_key().verify(input.as_bytes(), &sig).unwrap();
    // Not signed by another key.
    let other = SigningKey::from_bytes(&[8u8; 32]);
    assert!(other
        .verifying_key()
        .verify(input.as_bytes(), &sig)
        .is_err());
    let header: Value = serde_json::from_slice(&decode(input.split('.').next().unwrap())).unwrap();
    assert_eq!(header["kid"], KEY_ID);
    serde_json::from_slice(&decode(input.split('.').nth(1).unwrap())).unwrap()
}

fn header_names(seen: &Seen) -> Vec<&str> {
    let mut names: Vec<&str> = seen.headers.iter().map(|(k, _)| k.as_str()).collect();
    names.sort_unstable();
    names
}

fn header<'a>(seen: &'a Seen, name: &str) -> Option<&'a str> {
    seen.headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

#[tokio::test]
async fn a_session_goes_upstream_exactly_as_the_provider_built_it() {
    crate::health::init_metrics();
    let (url, log) = stub_with(200, br#"{"token":"tok+en/1=","channel_id":""}"#).await;
    let state = gateway_state(&url, entry(&url, "onramp-session", true, true), 256);
    let (status, json, headers) = ask(
        &state,
        &request(
            "POST",
            "/v1/session",
            &session(r#","fiat":"USD","amount":"50""#),
        ),
    )
    .await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(
        headers,
        vec![("content-type".to_string(), "application/json".to_string())]
    );
    let url_out = json["url"].as_str().unwrap();
    assert_eq!(
        url_out,
        format!("https://pay.coinbase.com/buy/select-asset?sessionToken=tok%2Ben%2F1%3D&defaultAsset=ZEC&defaultNetwork=zcash&partnerUserRef={REF}&redirectUrl=wallet%3A%2F%2Fonramp%2Freturn&fiatCurrency=USD&presetFiatAmount=50")
    );
    assert!(json["expires_at"].as_u64().unwrap() > 1_700_000_000);

    let seen = log.lock().clone();
    assert_eq!(seen.len(), 1);
    let seen = &seen[0];
    assert_eq!(
        (seen.method.as_str(), seen.target.as_str()),
        ("POST", "/onramp/v1/token")
    );
    // Exactly these headers: nothing of the client's (its credential, cookie, forwarding
    // header, user agent, key header).
    assert_eq!(
        header_names(seen),
        vec![
            "accept",
            "authorization",
            "content-length",
            "content-type",
            "host",
            "user-agent"
        ]
    );
    assert_eq!(header(seen, "accept"), Some("application/json"));
    assert_eq!(header(seen, "content-type"), Some("application/json"));
    assert_eq!(header(seen, "user-agent"), Some("ohttp-gateway/1.0"));
    let all = format!("{:?}", seen.headers);
    for client in [
        "client-token",
        "session=1",
        "192.0.2.7",
        "wallet/1.0",
        "client-key",
    ] {
        assert!(!all.contains(client), "{client} leaked: {all}");
    }
    let body: Value = serde_json::from_slice(&seen.body).unwrap();
    assert_eq!(
        body,
        json!({"addresses": [{"address": T1, "blockchains": ["zcash"]}], "assets": ["ZEC"]})
    );
    assert!(!String::from_utf8_lossy(&seen.body).contains("clientIp"));
    let host = url.strip_prefix("http://").unwrap();
    let c = claims(header(seen, "authorization").unwrap());
    assert_eq!(c["uri"], format!("POST {host}/onramp/v1/token"));
    assert_eq!(c["iss"], "cdp");
    assert_eq!(c["sub"], KEY_ID);
    assert_eq!(c["exp"].as_u64().unwrap() - c["nbf"].as_u64().unwrap(), 120);
}

/// A stub upstream: records each request as received, answers `status` and `body`.
pub(crate) async fn stub_with(status: u16, body: &'static [u8]) -> (String, Log) {
    stub_full(status, body, None).await
}

/// [`stub_with`], with a `retry-after` header when given.
async fn stub_full(
    status: u16,
    body: &'static [u8],
    retry_after: Option<&'static str>,
) -> (String, Log) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let log: Log = Default::default();
    let recorded = log.clone();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let recorded = recorded.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let recorded = recorded.clone();
                        async move {
                            let method = req.method().to_string();
                            let target = req
                                .uri()
                                .path_and_query()
                                .map(|pq| pq.as_str().to_string())
                                .unwrap_or_default();
                            let headers = req
                                .headers()
                                .iter()
                                .map(|(k, v)| {
                                    (
                                        k.as_str().to_string(),
                                        String::from_utf8_lossy(v.as_bytes()).into_owned(),
                                    )
                                })
                                .collect();
                            let received = req.into_body().collect().await.unwrap().to_bytes();
                            recorded.lock().push(Seen {
                                method,
                                target,
                                headers,
                                body: received.to_vec(),
                            });
                            let mut response =
                                hyper::Response::new(Full::new(Bytes::from_static(body)));
                            *response.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
                            if let Some(v) = retry_after {
                                response.headers_mut().insert(
                                    "retry-after",
                                    hyper::header::HeaderValue::from_static(v),
                                );
                            }
                            Ok::<_, Infallible>(response)
                        }
                    },
                );
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(hyper_util::rt::TokioIo::new(sock), service)
                .await;
            });
        }
    });
    (url, log)
}

#[tokio::test]
async fn a_sell_status_is_a_get_without_body_and_its_answer_is_rebuilt() {
    let (url, log) = stub_with(
        200,
        br#"{"transactions":[{"status":"TRANSACTION_STATUS_STARTED","asset":"ZEC","network":"zcash","to_address":"t3JZcvsuaXE6ygokL4XUiZSTrQBUoPYFnXJ","sell_amount":{"value":"0.5","currency":"ZEC"},"tx_hash":"","user_id":"u-1","created_at":"2026-11-20T12:00:00Z"}]}"#,
    )
    .await;
    let state = gateway_state(&url, entry(&url, "onramp-status", true, true), 256);
    let (status, json, _) = ask(
        &state,
        &request("POST", "/v1/sell/status", &format!(r#"{{"ref":"{REF}"}}"#)),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        json,
        json!({"status": "started", "asset": "ZEC", "network": "zcash",
            "to_address": "t3JZcvsuaXE6ygokL4XUiZSTrQBUoPYFnXJ", "sell_amount": "0.5"})
    );
    let seen = log.lock().clone();
    let seen = &seen[0];
    assert_eq!(
        (seen.method.as_str(), seen.target.as_str()),
        (
            "GET",
            format!("/onramp/v1/sell/user/{REF}/transactions").as_str()
        )
    );
    assert!(seen.body.is_empty());
    assert_eq!(
        header_names(seen),
        vec!["accept", "authorization", "host", "user-agent"]
    );
    let host = url.strip_prefix("http://").unwrap();
    assert_eq!(
        claims(header(seen, "authorization").unwrap())["uri"],
        format!("GET {host}/onramp/v1/sell/user/{REF}/transactions")
    );
}

#[tokio::test]
async fn refusals_and_local_answers_never_reach_the_upstream() {
    crate::health::init_metrics();
    let (url, log) = stub_with(200, br#"{"token":"t"}"#).await;
    let label = "onramp-refusals";
    let state = gateway_state(&url, entry(&url, label, true, true), 256);
    let denied = |reason: &str| {
        counter(
            "ohttp_integration_denied_total",
            &[("integration", label), ("reason", reason)],
        )
    };
    // The availability document, from the configuration.
    let (status, json, _) = ask(&state, &request("GET", "/v1/availability", "")).await;
    assert_eq!(status, 200);
    assert_eq!(
        json,
        json!({"enabled": true, "countries": {"US": {"buy": true, "sell": true}}})
    );
    // A testnet address, a P2SH address, a client IP, a bad ref.
    for (body, code) in [
        (
            session("").replace(T1, "tm9iMLAuYMzJ6jtFLcA7rzUmfreGuKvr7Ma"),
            "invalid_address",
        ),
        (
            session("").replace(T1, "t3JZcvsuaXE6ygokL4XUiZSTrQBUoPYFnXJ"),
            "invalid_address",
        ),
        (session(r#","clientIp":"192.0.2.1""#), "invalid_request"),
        (session("").replace(REF, "short"), "invalid_request"),
    ] {
        let (status, json, _) = ask(&state, &request("POST", "/v1/session", &body)).await;
        assert_eq!((status, json), (400, json!({ "error": code })), "{body}");
    }
    assert_eq!(denied("invalid_address"), 2.0);
    assert_eq!(denied("invalid_request"), 2.0);
    // Not a route: the gateway's own policy answer.
    let resp = answer(
        &state,
        &request("POST", "/onramp/v1/token", "{}"),
        &state.config.coinbase.get(ALIAS).unwrap(),
    )
    .await;
    assert_eq!(
        (resp.status, resp.body.as_slice()),
        (403, &b"policy denied"[..])
    );
    assert_eq!(denied("policy"), 1.0);
    assert!(log.lock().is_empty(), "nothing went upstream");
}

#[tokio::test]
async fn a_session_without_the_wallets_signature_never_reaches_the_upstream() {
    crate::health::init_metrics();
    let (url, log) = stub_with(200, br#"{"token":"t"}"#).await;
    let label = "onramp-signature";
    let state = gateway_state(&url, entry(&url, label, true, true), 256);
    let denied = |reason: &str| {
        counter(
            "ohttp_integration_denied_total",
            &[("integration", label), ("reason", reason)],
        )
    };
    let now = unix_now().unwrap();
    let good = sign(&T1_KEY, T1, now);
    let mut bytes = base64::engine::general_purpose::STANDARD
        .decode(&good)
        .unwrap();
    // The malleated (high-S) copy of the valid signature.
    let sig = k256::ecdsa::Signature::from_slice(&bytes[1..]).unwrap();
    let s: k256::Scalar = *sig.s().as_ref();
    let mut high = bytes.clone();
    high[0] = 27 + ((high[0] - 27) ^ 1);
    high[33..].copy_from_slice(&(-s).to_bytes());
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let with_signature = |sig: &str| {
        format!(
            r#"{{"flow":"buy","address":"{T1}","ref":"{REF}","timestamp":"{now}","signature":"{sig}"}}"#
        )
    };
    let mut refused_signature = vec![
        // Another key's signature, a tampered timestamp.
        session_signed("", &OTHER_KEY, now, now),
        session_signed("", &T1_KEY, now, now - 1),
        // Malleated, unpadded, not 65 bytes.
        with_signature(&b64(&high)),
        with_signature(good.trim_end_matches('=')),
        with_signature(&b64(&bytes[..64])),
    ];
    // The uncompressed key encoding's header (another address), a header byte out of range.
    bytes[0] -= 4;
    refused_signature.push(with_signature(&b64(&bytes)));
    bytes[0] = 35;
    refused_signature.push(with_signature(&b64(&bytes)));
    for body in &refused_signature {
        let (status, json, headers) = ask(&state, &request("POST", "/v1/session", body)).await;
        assert_eq!(
            (status, json),
            (401, json!({"error": "invalid_signature"})),
            "{body}"
        );
        // A fixed answer: its content type only (no CORS header, nothing of the request).
        assert_eq!(
            headers,
            vec![("content-type".to_string(), "application/json".to_string())]
        );
    }
    // Expired and ahead (signed correctly at that time; well past the window, so a second
    // boundary during the test cannot make one fresh: the exact edges are the provider's tests).
    for at in [now - 400, now + 400, now - 3600, 0] {
        let (status, json, _) = ask(
            &state,
            &request("POST", "/v1/session", &session_signed("", &T1_KEY, at, at)),
        )
        .await;
        assert_eq!((status, json), (401, json!({"error": "invalid_signature"})));
    }
    // Missing, extra, repeated or malformed members are body problems.
    let invalid_request = [
        format!(r#"{{"flow":"buy","address":"{T1}","ref":"{REF}","timestamp":"{now}"}}"#),
        format!(r#"{{"flow":"buy","address":"{T1}","ref":"{REF}","signature":"{good}"}}"#),
        session(r#","nonce":"1""#),
        session(r#","timestamp":"1""#),
        format!(
            r#"{{"flow":"buy","address":"{T1}","ref":"{REF}","timestamp":{now},"signature":"{good}"}}"#
        ),
        format!(
            r#"{{"flow":"buy","address":"{T1}","ref":"{REF}","timestamp":"0{now}","signature":"{good}"}}"#
        ),
    ];
    for body in &invalid_request {
        let (status, json, _) = ask(&state, &request("POST", "/v1/session", body)).await;
        assert_eq!(
            (status, json),
            (400, json!({"error": "invalid_request"})),
            "{body}"
        );
    }
    assert_eq!(denied("invalid_signature"), refused_signature.len() as f64);
    assert_eq!(denied("stale_timestamp"), 4.0);
    assert_eq!(denied("invalid_request"), invalid_request.len() as f64);
    assert!(log.lock().is_empty(), "nothing went upstream");
    // The same request signed correctly goes upstream once, with nothing of the signature.
    let (status, _, _) = ask(&state, &request("POST", "/v1/session", &session(""))).await;
    assert_eq!(status, 200);
    let seen = log.lock().clone();
    assert_eq!(seen.len(), 1);
    let sent = String::from_utf8_lossy(&seen[0].body).to_string();
    assert!(
        !sent.contains("signature") && !sent.contains("timestamp"),
        "{sent}"
    );
    assert_eq!(outcome_label(401), "invalid_signature");
}

#[test]
fn a_clock_before_the_epoch_reads_as_none() {
    let epoch = SystemTime::UNIX_EPOCH;
    assert_eq!(unix_seconds(epoch), Some(0));
    assert_eq!(
        unix_seconds(epoch + Duration::from_secs(1_700_000_000)),
        Some(1_700_000_000)
    );
    assert_eq!(unix_seconds(epoch - Duration::from_secs(1)), None);
    assert!(unix_now().is_some());
}

#[tokio::test]
async fn switched_off_or_without_a_key_it_answers_unavailable() {
    crate::health::init_metrics();
    let (url, log) = stub_with(200, br#"{"token":"t"}"#).await;
    let off = gateway_state(&url, entry(&url, "onramp-off", false, true), 256);
    let (status, json, _) = ask(&off, &request("POST", "/v1/session", &session(""))).await;
    assert_eq!((status, json), (503, json!({"error": "unavailable"})));
    let (status, json, _) = ask(&off, &request("GET", "/v1/availability", "")).await;
    assert_eq!(
        (status, json),
        (200, json!({"enabled": false, "countries": {}}))
    );
    assert_eq!(
        counter(
            "ohttp_integration_denied_total",
            &[("integration", "onramp-off"), ("reason", "disabled")]
        ),
        1.0
    );
    let keyless = gateway_state(&url, entry(&url, "onramp-keyless", true, false), 256);
    let (status, json, _) = ask(&keyless, &request("POST", "/v1/session", &session(""))).await;
    assert_eq!((status, json), (503, json!({"error": "unavailable"})));
    assert_eq!(
        counter(
            "ohttp_integration_sign_failures_total",
            &[("integration", "onramp-keyless")]
        ),
        1.0
    );
    assert!(log.lock().is_empty(), "nothing went upstream");
}

#[tokio::test]
async fn upstream_errors_are_scrubbed() {
    // CDP's 400 echoes the address.
    let echo: &'static [u8] =
        br#"{"message":"address [t1RwUkDxFKCydymAzBtTwHtVyH9Tvf6CiiL] is not valid for blockchain [zcash]"}"#;
    for (status, expected_status, code) in [
        (400, 502, "upstream"),
        (401, 502, "upstream"),
        (500, 502, "upstream"),
        (429, 429, "rate_limited"),
    ] {
        let (url, log) = stub_with(status, echo).await;
        let state = gateway_state(&url, entry(&url, "onramp-scrub", true, true), 256);
        let req = request("POST", "/v1/session", &session(""));
        let resp = answer(&state, &req, &state.config.coinbase.get(ALIAS).unwrap()).await;
        assert_eq!(resp.status, expected_status, "{status}");
        assert_eq!(
            serde_json::from_slice::<Value>(&resp.body).unwrap(),
            json!({ "error": code })
        );
        assert!(!String::from_utf8_lossy(&resp.body).contains(T1));
        assert_eq!(log.lock().len(), 1);
    }
    // A 200 that is not the expected shape.
    let (url, _) = stub_with(200, b"<html>").await;
    let state = gateway_state(&url, entry(&url, "onramp-scrub", true, true), 256);
    let (status, json, _) = ask(&state, &request("POST", "/v1/session", &session(""))).await;
    assert_eq!((status, json), (502, json!({"error": "upstream"})));
    // Nobody listening.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let state = gateway_state(&closed, entry(&closed, "onramp-scrub", true, true), 256);
    let (status, json, _) = ask(&state, &request("POST", "/v1/session", &session(""))).await;
    assert_eq!((status, json), (502, json!({"error": "upstream"})));
}

#[tokio::test]
async fn each_route_has_its_cap_and_only_upstream_calls_spend_it() {
    crate::health::init_metrics();
    let (url, log) = stub_with(200, br#"{"token":"t"}"#).await;
    let label = "onramp-cap";
    let state = gateway_state(
        &url,
        entry_with(&url, label, true, true, ("1/60s", "2/60s")),
        256,
    );
    // Refused bodies and the availability document spend nothing.
    for _ in 0..3 {
        let (status, _, _) = ask(&state, &request("POST", "/v1/session", "{}")).await;
        assert_eq!(status, 400);
        let (status, _, _) = ask(&state, &request("GET", "/v1/availability", "")).await;
        assert_eq!(status, 200);
    }
    let (status, _, _) = ask(&state, &request("POST", "/v1/session", &session(""))).await;
    assert_eq!(status, 200);
    let (status, json, headers) = ask(&state, &request("POST", "/v1/session", &session(""))).await;
    assert_eq!((status, json), (429, json!({"error": "rate_limited"})));
    assert!(
        headers.iter().any(|(k, _)| k == "retry-after"),
        "{headers:?}"
    );
    // The status route has its own budget.
    let status_req = request("POST", "/v1/sell/status", &format!(r#"{{"ref":"{REF}"}}"#));
    for expected in [502, 502, 429] {
        // The stub's token document is no transaction list: a 502, but an upstream call.
        let (status, _, _) = ask(&state, &status_req).await;
        assert_eq!(status, expected);
    }
    assert_eq!(log.lock().len(), 3);
    assert_eq!(
        counter(
            "ohttp_integration_denied_total",
            &[("integration", label), ("reason", "rate_limited")]
        ),
        2.0
    );
}

#[tokio::test]
async fn no_budget_is_spent_on_a_503() {
    let (url, log) = stub_with(200, br#"{"token":"t"}"#).await;
    // One integration (one cap of one call) under two gateways: one without upstream permits.
    let shared = Integrations::from_entries(vec![entry_with(
        &url,
        "onramp-permits",
        true,
        true,
        ("1/60s", "1/60s"),
    )]);
    let busy = gateway_state_shared(&url, shared.clone(), 0);
    let free = gateway_state_shared(&url, shared, 256);
    for _ in 0..3 {
        let (status, json, _) = ask(&busy, &request("POST", "/v1/session", &session(""))).await;
        assert_eq!((status, json), (503, json!({"error": "unavailable"})));
    }
    let (status, _, _) = ask(&free, &request("POST", "/v1/session", &session(""))).await;
    assert_eq!(status, 200, "the cap was not spent by the 503s");
    // Without a key neither.
    let keyless = Integrations::from_entries(vec![entry_with(
        &url,
        "onramp-keyless-cap",
        true,
        false,
        ("1/60s", "1/60s"),
    )]);
    let state = gateway_state_shared(&url, keyless, 256);
    for _ in 0..3 {
        let (status, _, _) = ask(&state, &request("POST", "/v1/session", &session(""))).await;
        assert_eq!(status, 503);
    }
    assert_eq!(log.lock().len(), 1);
}

#[tokio::test]
async fn an_upstream_429_is_answered_with_a_bounded_retry_after() {
    for (header, expected) in [(Some("7"), "7"), (Some("86400"), "300"), (None, "60")] {
        let (url, log) = stub_full(429, b"{\"message\":\"slow down\"}", header).await;
        let state = gateway_state(&url, entry(&url, "onramp-429", true, true), 256);
        let (status, json, headers) =
            ask(&state, &request("POST", "/v1/session", &session(""))).await;
        assert_eq!((status, json), (429, json!({"error": "rate_limited"})));
        assert!(
            headers.contains(&("retry-after".to_string(), expected.to_string())),
            "{headers:?}"
        );
        assert_eq!(log.lock().len(), 1);
    }
}

#[tokio::test]
async fn the_generic_forward_never_takes_a_coinbase_alias() {
    let (url, log) = stub_with(200, br#"{"token":"t"}"#).await;
    let state = gateway_state(&url, entry(&url, "onramp-generic", true, true), 256);
    let req = request("POST", "/v1/session", &session(""));
    let resp = crate::proxy::forward_to_backend(&state, &req)
        .await
        .unwrap();
    assert_eq!(
        (resp.status, resp.body.as_slice()),
        (403, &b"policy denied"[..])
    );
    match crate::proxy::forward_to_backend_stream(&state, &req, uuid::Uuid::new_v4(), None).await {
        Ok((status, _, _)) => assert_eq!(status, 403),
        Err(e) => panic!("{e}"),
    }
    assert!(log.lock().is_empty(), "nothing went upstream");
}

#[test]
fn the_providers_come_from_a_file_in_force_only() {
    let _guard = crate::config::test_env_lock();
    let (_, document) = test_key();
    let bad = r#"{"id":"k","privateKey":"c2VjcmV0LXZhbHVl"}"#;
    let rendered = |read_key: bool| {
        json!([{
            "label": "onramp", "alias": "onramp.example", "upstream": "https://cdp-api.example",
            "secret": {"name": "cdp_key", "env": null, "file": "/run/secrets/cdp_key"},
            "read_key": read_key, "ttl_secs": 120, "enabled": true, "redirect_url": "wallet://r",
            "countries": {}, "rate_limit": "1/1s", "status_rate_limit": "1/1s",
        }])
        .to_string()
    };
    // No file: none, whatever the environment holds under that name.
    std::env::set_var(COINBASE_RENDERED, rendered(true));
    assert!(Integrations::from_policy("mainnet").unwrap().is_empty());
    std::env::remove_var(COINBASE_RENDERED);
    // The rendered policy, and the secret values the files read (`key`: that of cdp_key).
    let scoped = |value: String, network: &str, key: Option<&str>| {
        let values: BTreeMap<String, zeroize::Zeroizing<String>> = key
            .map(|k| {
                (
                    "cdp_key".to_string(),
                    zeroize::Zeroizing::new(k.to_string()),
                )
            })
            .into_iter()
            .collect();
        crate::config_source::with_secret_values(Arc::new(values), || {
            crate::config_source::with_policy(
                [(COINBASE_RENDERED.to_string(), value)].into(),
                || Integrations::from_policy(network),
            )
        })
    };
    let set = scoped(rendered(true), "mainnet", Some(&document)).unwrap();
    let e = set.get("ONRAMP.example").unwrap();
    assert!(e.provider.has_signer() && e.provider.enabled());
    assert_eq!((e.key.clone(), e.key_problem()), (KeyState::Loaded, None));
    assert!(set.contains("onramp.example"));
    // Mainnet only.
    let text = format!(
        "{:#}",
        scoped(rendered(true), "testnet", Some(&document)).unwrap_err()
    );
    assert!(text.contains("mainnet gateway only"), "{text}");
    // A key that was not read (`--secrets=skip`).
    let set = scoped(rendered(false), "mainnet", None).unwrap();
    let e = set.get("onramp.example").unwrap();
    assert_eq!(e.key, KeyState::Skipped);
    assert!(!e.provider.has_signer() && e.key_problem().is_none());
    // A key document that is no key, or none read: a provider without a signer, the problem
    // named by the secret, never the value.
    for key in [Some(bad), None] {
        let set = scoped(rendered(true), "mainnet", key).unwrap();
        let e = set.get("onramp.example").unwrap();
        assert!(!e.provider.has_signer());
        let problem = e.key_problem().unwrap();
        assert!(
            problem.contains("secret 'cdp_key'") && !problem.contains("c2VjcmV0"),
            "{problem}"
        );
    }
    // An upstream that is not https: refused.
    let http = rendered(true).replace("https://cdp-api.example", "http://cdp-api.example");
    assert!(scoped(http, "mainnet", Some(&document)).is_err());
    // The debug form names no key.
    let debug = format!("{set:?}");
    assert!(!debug.contains("privateKey"), "{debug}");
}

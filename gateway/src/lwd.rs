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

// lwd — Lightweight lightwalletd helper calls.
//
// These functions reuse the same h2c call pattern as proxy.rs but are
// standalone (no Axum AppState) so they can be used from both the gateway
// binary for cache tip polling.

use crate::{config::Config, ohttp::InnerResponse};
use anyhow::{anyhow, Result};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioTimer},
};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::time::timeout;

const GRPC_CONTENT_TYPE: &str = "application/grpc";

/// The HTTP/2 client for a lightwalletd call. By default a new one per call, so every request
/// opens its own connection: behind a load-balanced service address that spreads connections over
/// several lightwalletd instances, a new call does not reuse a connection to an instance that has
/// already been taken out of service, which keeps failed calls during rolling restarts rare (the
/// connect retry of [`request`] covers an address that is joining or leaving).
///
/// `LWD_CONNECTION_POOL=1` shares one pooled client instead (idle connections kept 60 s, HTTP/2
/// PINGs every 20 s), which saves the TCP handshake, one round trip, per call. For a gateway far
/// from lightwalletd that is one long round trip per cache miss and per SendTransaction. The
/// trade-off: a pooled connection stays on one instance until it closes, so a call in flight
/// when that instance exits fails.
pub(crate) fn lwd_client() -> Client<HttpConnector, Full<axum::body::Bytes>> {
    static POOLED: OnceLock<Option<Client<HttpConnector, Full<axum::body::Bytes>>>> =
        OnceLock::new();
    let pooled = POOLED.get_or_init(|| {
        let on = std::env::var("LWD_CONNECTION_POOL")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "on"))
            .unwrap_or(false);
        on.then(|| {
            Client::builder(TokioExecutor::new())
                .http2_only(true)
                .pool_timer(TokioTimer::new())
                .pool_idle_timeout(Duration::from_secs(60))
                .timer(TokioTimer::new())
                .http2_keep_alive_interval(Duration::from_secs(20))
                .http2_keep_alive_while_idle(true)
                .build_http()
        })
    });
    match pooled {
        Some(client) => client.clone(),
        None => Client::builder(TokioExecutor::new())
            .http2_only(true)
            .build_http(),
    }
}

/// Pause before the one retry of [`request`].
const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(50);

/// Send `req` to lightwalletd, once more if the connection could not be established. A connect
/// error means no byte of the request reached lightwalletd, so the retry cannot execute anything
/// twice (WRITE requests included). It covers the moment a lightwalletd instance joins or leaves
/// a load-balanced service address during a rollout, when a connection can land on an address that
/// does not accept yet or any more.
pub(crate) async fn request(
    client: &Client<HttpConnector, Full<axum::body::Bytes>>,
    req: Request<Full<axum::body::Bytes>>,
) -> Result<hyper::Response<hyper::body::Incoming>, hyper_util::client::legacy::Error> {
    let mut again = Request::new(req.body().clone());
    *again.method_mut() = req.method().clone();
    *again.uri_mut() = req.uri().clone();
    *again.version_mut() = req.version();
    *again.headers_mut() = req.headers().clone();
    match client.request(req).await {
        Err(e) if e.is_connect() => {
            tracing::warn!(error = %e, "lightwalletd connect failed, retrying once");
            crate::health::record_lwd_connect_retry();
            tokio::time::sleep(CONNECT_RETRY_DELAY).await;
            client.request(again).await
        }
        other => other,
    }
}

fn grpc_wrap(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + body.len());
    out.push(0u8);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// `http://{addr}{path}`, built from its parts so that the path can only be a path (ZIP "Gateway
/// behaviour" rule 5).
pub fn lwd_uri(addr: &str, path: &str) -> Result<hyper::Uri> {
    if !path.starts_with('/') {
        return Err(anyhow!("lightwalletd path must start with '/': {path:?}"));
    }
    hyper::Uri::builder()
        .scheme("http")
        .authority(addr)
        .path_and_query(path)
        .build()
        .map_err(|e| anyhow!("lightwalletd URI from {addr:?} and {path:?}: {e}"))
}

async fn call_lwd(config: &Config, path: &str, body: Vec<u8>) -> Result<InnerResponse> {
    use axum::body::Bytes;
    let client: Client<HttpConnector, Full<Bytes>> = lwd_client();

    // The gateway's own call: a fresh request id for lightwalletd's logs.
    let request_id = uuid::Uuid::new_v4().to_string();
    let req = Request::builder()
        .method("POST")
        .uri(lwd_uri(&config.lwd_addr, path)?)
        .header("content-type", GRPC_CONTENT_TYPE)
        .header("te", "trailers")
        .header("x-request-id", &request_id)
        .header("grpc-request-id", &request_id)
        .body(Full::new(Bytes::from(body)))
        .map_err(|e| anyhow!("request build: {e}"))?;

    let overall = Duration::from_secs(config.lwd_timeout_secs);
    let deadline = Instant::now() + overall;

    let resp = timeout(overall, request(&client, req))
        .await
        .map_err(|_| anyhow!("LWD timeout"))?
        .map_err(|e| anyhow!("HTTP: {e}"))?;

    let status = resp.status().as_u16();
    let mut headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .filter(|(k, _)| {
            let l = k.as_str().to_ascii_lowercase();
            l == "content-type" || l == "date" || l.starts_with("grpc-")
        })
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let mut body_out = resp.into_body();
    let mut body_bytes: Vec<u8> = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(anyhow!("LWD response deadline"));
        }
        match timeout(remaining, body_out.frame()).await {
            Ok(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => body_bytes.extend_from_slice(&data),
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        for (k, v) in trailers.iter() {
                            headers.push((k.to_string(), v.to_str().unwrap_or("").to_string()));
                        }
                    }
                }
            },
            Ok(Some(Err(e))) => return Err(anyhow!("body error: {e}")),
            Ok(None) => break,
            // The deadline passed mid-body: what arrived so far is not the answer.
            Err(_) => return Err(anyhow!("LWD response deadline")),
        }
    }

    Ok(InnerResponse {
        status,
        headers,
        body: body_bytes,
    })
}

/// Call `GetLatestBlock` and return the current chain-tip (height, hash).
pub async fn fetch_latest_block(config: &Config) -> Result<(u64, Vec<u8>)> {
    use prost::Message;

    // BlockID proto definition (matches cache.rs)
    #[derive(Clone, PartialEq, prost::Message)]
    struct BlockId {
        #[prost(uint64, tag = "1")]
        height: u64,
        #[prost(bytes, tag = "2")]
        hash: Vec<u8>,
    }

    let resp = call_lwd(
        config,
        "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock",
        grpc_wrap(&[]),
    )
    .await?;

    // Parse protobuf (skip 5-byte gRPC frame header)
    let body = &resp.body;
    if body.len() < 5 {
        return Err(anyhow!(
            "GetLatestBlock response too short ({} bytes)",
            body.len()
        ));
    }

    let compressed = body[0];
    if compressed != 0 {
        return Err(anyhow!("GetLatestBlock: compressed response not supported"));
    }

    let length = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    if body.len() < 5 + length {
        return Err(anyhow!("GetLatestBlock: frame truncated"));
    }

    let protobuf_data = &body[5..5 + length];
    let block_id = BlockId::decode(protobuf_data)
        .map_err(|e| anyhow!("GetLatestBlock: protobuf decode error: {}", e))?;

    Ok((block_id.height, block_id.hash))
}

/// Call `GetLatestBlock` and return the current chain-tip height only (legacy compat).
#[allow(dead_code)]
pub async fn fetch_latest_height(config: &Config) -> Result<u64> {
    let (height, _) = fetch_latest_block(config).await?;
    Ok(height)
}

#[allow(dead_code)]
fn encode_block_range(start: u64, end: u64) -> Vec<u8> {
    fn encode_block_id(height: u64) -> Vec<u8> {
        let mut v = vec![0x08u8];
        let mut h = height;
        loop {
            let byte = (h & 0x7f) as u8;
            h >>= 7;
            if h == 0 {
                v.push(byte);
                break;
            } else {
                v.push(byte | 0x80);
            }
        }
        v
    }
    let start_id = encode_block_id(start);
    let end_id = encode_block_id(end);
    let mut msg = Vec::new();
    msg.push(0x0a);
    msg.push(start_id.len() as u8);
    msg.extend_from_slice(&start_id);
    msg.push(0x12);
    msg.push(end_id.len() as u8);
    msg.extend_from_slice(&end_id);
    msg
}

#[allow(dead_code)]
/// Call `GetBlockRange(start, end)` and return `(cache_key_body, serialized_InnerResponse)`.
pub async fn fetch_block_range_bytes(
    config: &Config,
    start: u64,
    end: u64,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let proto = encode_block_range(start, end);
    let body = grpc_wrap(&proto);
    let resp = call_lwd(
        config,
        "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlockRange",
        body.clone(),
    )
    .await?;
    let serialized = serde_json::to_vec(&resp)?;
    Ok((body, serialized))
}

#[cfg(test)]
mod tests {
    use prost::Message;

    // Regression test: CompactBlock wire-format field tags
    #[test]
    fn test_compactblock_proto_tags_fixed() {
        // Synthetic CompactBlock protobuf bytes in the lightwalletd wire format
        // Format: tag 2 (height) = 12345, tag 3 (hash) = 32 bytes of 0xAA
        let mut real_compact_block = vec![
            0x10, // Field 2 (height): tag=2, wire_type=varint
            0xB9, // 12345 in varint encoding
            0x60, 0x1A, // Field 3 (hash): tag=3, wire_type=length-delimited
            32,   // length
        ];
        real_compact_block.extend_from_slice(&[0xAA; 32]); // 32 bytes of 0xAA

        // Before fix: CompactBlock had tags 1/12, so decoding real data gives (0, [])
        // After fix: CompactBlock has tags 2/3, so decoding works correctly

        #[derive(Clone, PartialEq, prost::Message)]
        struct CompactBlockBroken {
            #[prost(uint64, tag = "1")]
            height: u64,
            #[prost(bytes, tag = "12")]
            hash: Vec<u8>,
        }

        #[derive(Clone, PartialEq, prost::Message)]
        struct CompactBlockFixed {
            #[prost(uint64, tag = "2")]
            height: u64,
            #[prost(bytes, tag = "3")]
            hash: Vec<u8>,
        }

        // Broken version decodes to (0, [])
        let broken = CompactBlockBroken::decode(&real_compact_block[..]).unwrap();
        assert_eq!(
            broken.height, 0,
            "BEFORE FIX: Wrong tags decode height to 0 (ancestry check never fires)"
        );
        assert_eq!(
            broken.hash.len(),
            0,
            "BEFORE FIX: Wrong tags decode hash to empty"
        );

        // Fixed version decodes correctly
        let fixed = CompactBlockFixed::decode(&real_compact_block[..]).unwrap();
        assert_eq!(fixed.height, 12345, "AFTER FIX: Correct tags decode height");
        assert_eq!(fixed.hash.len(), 32, "AFTER FIX: Correct tags decode hash");
        assert_eq!(fixed.hash[0], 0xAA);
    }

    #[test]
    fn lwd_uri_is_built_from_its_parts() {
        let path = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock";
        let uri = super::lwd_uri("lightwalletd:9067", path).unwrap();
        assert_eq!(uri.authority().unwrap().as_str(), "lightwalletd:9067");
        assert_eq!(uri.path(), path);
        // A path that would re-parse as another authority stays a path.
        let uri = super::lwd_uri("lightwalletd:9067", "//evil.example/x").unwrap();
        assert_eq!(uri.authority().unwrap().as_str(), "lightwalletd:9067");
        assert!(super::lwd_uri("lightwalletd:9067", "@evil.example/x").is_err());
        assert!(super::lwd_uri("lightwalletd:9067", "/a b").is_err());
    }

    #[test]
    fn client_grpc_metadata_goes_to_lightwalletd_except_what_the_gateway_owns() {
        let h = |k: &str, v: &str| (k.to_string(), v.to_string());
        let inner = vec![
            h("content-type", "application/grpc"),
            h("te", "trailers"),
            h("user-agent", "wallet/1.0"),
            h("Grpc-Timeout", "5S"),
            h("grpc-encoding", "identity"),
            h("grpc-accept-encoding", "gzip"),
            h("grpc-request-id", "client-chosen"),
            h("grpc-bad", "line\nbreak"),
            h("ohttp-freshness", "1760000000"),
        ];
        assert_eq!(
            super::client_grpc_headers(&inner),
            vec![
                h("content-type", "application/grpc"),
                h("grpc-timeout", "5S"),
                h("grpc-encoding", "identity")
            ]
        );
        let text = vec![h("content-type", "text/plain")];
        assert!(super::client_grpc_headers(&text).is_empty());
    }

    #[tokio::test]
    async fn permit_wait_succeeds_when_slot_frees_within_timeout() {
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let waiters = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // Hold the only permit.
        let _held = sem.clone().try_acquire_owned().unwrap();

        // Spawn a waiter.
        let sem_clone = sem.clone();
        let waiters_clone = waiters.clone();
        let waiter = tokio::spawn(async move {
            super::LwdSources::acquire_with_wait(
                sem_clone,
                1000,
                10,
                &waiters_clone,
                "mainnet",
                "general",
            )
            .await
        });

        // Wait a bit to let the waiter start.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(waiters.load(std::sync::atomic::Ordering::SeqCst), 1);

        // Release the permit.
        drop(_held);

        // Waiter should succeed.
        let result = waiter.await.unwrap();
        assert!(result.is_ok());
        assert_eq!(waiters.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn permit_wait_times_out_when_no_slot_frees() {
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let waiters = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // Hold the only permit.
        let _held = sem.clone().try_acquire_owned().unwrap();

        // Try to wait with a short timeout.
        let result = super::LwdSources::acquire_with_wait(
            sem.clone(),
            50,
            10,
            &waiters,
            "mainnet",
            "general",
        )
        .await;

        assert!(result.is_err());
        assert_eq!(waiters.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn permit_wait_rejects_immediately_when_waiter_cap_reached() {
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let waiters = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // Hold the only permit.
        let _held = sem.clone().try_acquire_owned().unwrap();

        // Fill the waiter cap.
        waiters.store(5, std::sync::atomic::Ordering::SeqCst);

        // Next waiter should be rejected immediately.
        let start = std::time::Instant::now();
        let result = super::LwdSources::acquire_with_wait(
            sem.clone(),
            1000,
            5,
            &waiters,
            "mainnet",
            "general",
        )
        .await;

        assert!(result.is_err());
        assert!(start.elapsed() < std::time::Duration::from_millis(100));
        assert_eq!(waiters.load(std::sync::atomic::Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn permit_wait_zero_ms_keeps_immediate_rejection() {
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let waiters = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // Hold the only permit.
        let _held = sem.clone().try_acquire_owned().unwrap();

        // With wait_ms=0, should reject immediately.
        let start = std::time::Instant::now();
        let result = super::LwdSources::acquire_with_wait(
            sem.clone(),
            0,
            10,
            &waiters,
            "mainnet",
            "general",
        )
        .await;

        assert!(result.is_err());
        assert!(start.elapsed() < std::time::Duration::from_millis(10));
        assert_eq!(waiters.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn waiter_cap_defaults_to_four_times_heavy_permit_count() {
        use super::Config;

        let config = Config {
            max_inflight_lwd: 128,
            max_inflight_lwd_heavy: 4,
            lwd_permit_wait_ms: 1000,
            lwd_permit_max_waiters: 0,
            network: "mainnet".to_string(),
            lwd_heavy_block_range: 100,
            ..test_config()
        };

        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(128));
        let sources = super::LwdSources::new(config.clone(), sem.clone());

        // Hold all heavy permits.
        let _heavy_held: Vec<_> = (0..4)
            .map(|_| sources.heavy.clone().try_acquire_owned().unwrap())
            .collect();

        // The heavy waiter cap should be 4 * 4 = 16.
        // Fill it.
        for _ in 0..16 {
            sources
                .heavy_waiters
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }

        // Next acquire should reject immediately (waiter cap reached).
        let start = std::time::Instant::now();
        let result = super::LwdSources::acquire_with_wait(
            sources.heavy.clone(),
            config.lwd_permit_wait_ms,
            if config.lwd_permit_max_waiters == 0 {
                config.max_inflight_lwd_heavy.saturating_mul(4).max(1)
            } else {
                config.lwd_permit_max_waiters
            },
            &sources.heavy_waiters,
            &config.network,
            "heavy",
        )
        .await;

        assert!(result.is_err());
        assert!(start.elapsed() < std::time::Duration::from_millis(100));
    }

    /// A lightwalletd (h2) that sends the response head and part of the body, then stalls.
    async fn stalling_lwd() -> String {
        use hyper::body::Frame;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let service = hyper::service::service_fn(
                    |_req: hyper::Request<hyper::body::Incoming>| async move {
                        let frames = futures_util::stream::unfold(0u8, |n| async move {
                            match n {
                                0 => Some((
                                    Ok::<_, std::convert::Infallible>(Frame::data(
                                        axum::body::Bytes::from_static(&[0, 0, 0, 0, 10, 1, 2]),
                                    )),
                                    1,
                                )),
                                _ => {
                                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                                    None
                                }
                            }
                        });
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(200)
                                .header("content-type", "application/grpc")
                                .body(http_body_util::StreamBody::new(frames))
                                .unwrap(),
                        )
                    },
                );
                tokio::spawn(async move {
                    let _ = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
                });
            }
        });
        addr.to_string()
    }

    #[tokio::test]
    async fn body_read_timeout_is_an_error_not_a_partial_body() {
        let mut config = test_config();
        config.lwd_addr = stalling_lwd().await;
        config.lwd_timeout_secs = 1;
        let start = std::time::Instant::now();
        let result = super::call_lwd(
            &config,
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock",
            super::grpc_wrap(&[]),
        )
        .await;
        assert!(
            result.is_err(),
            "a body cut by the deadline must not be returned as a success"
        );
        assert!(start.elapsed() < std::time::Duration::from_secs(10));
        assert!(
            super::fetch_latest_block(&config).await.is_err(),
            "callers see the upstream failure"
        );
    }

    fn test_config() -> crate::config::Config {
        crate::config::Config {
            port: 8080,
            lwd_addr: "localhost:9067".to_string(),
            mode: "ohttp".to_string(),
            relay_secrets: Vec::new(),
            hpke_private_key: None,
            hpke_key_id: 1,
            hpke_keys: Vec::new(),
            lwd_timeout_secs: 80,
            long_poll_max_initial_silence_secs: 25,
            long_poll_idle_secs: 3,
            sse_keepalive_secs: 20,
            redis_url: String::new(),
            redis_security_url: String::new(),
            backends: std::collections::HashMap::new(),
            backend_headers: std::collections::HashMap::new(),
            backends_policy: std::collections::HashMap::new(),
            backends_policy_default_allow: false,
            max_upstream_response_bytes: 64 * 1024 * 1024,
            max_inflight_upstream: 256,
            max_inflight_per_backend: 64,
            max_inflight_lwd: 128,
            max_inflight_lwd_heavy: 32,
            lwd_heavy_block_range: 100,
            max_block_range: 10000,
            redis_op_timeout_ms: 250,
            max_cache_get_concurrency: 64,
            max_large_response_concurrency: 2,
            large_response_threshold: 8 * 1024 * 1024,
            allow_unauthenticated_relay: false,
            proxy_allow_suffixes: Vec::new(),
            network: "mainnet".to_string(),
            log_outer_header_names: false,
            gateway_hosts: Vec::new(),
            configs_signing_seed: None,
            chunk_size: 16384,
            chunk_flush_ms: 50,
            flexa_publishable_key: None,
            flexa_alias: None,
            near_alias: None,
            relay_secret_on_key_config: super::super::config::RelaySecretOnKeyConfig::Off,
            lwd_permit_wait_ms: 2000,
            lwd_permit_max_waiters: 0,
        }
    }
}

/// How long a streamed call may run. `overall` None = no deadline;
/// `idle` Some = a long poll closed cleanly (grpc-status 0) after that much silence.
#[derive(Clone, Copy, Debug)]
pub struct StreamOpts {
    pub overall: Option<Duration>,
    pub idle: Option<Duration>,
}

/// The error a source returns when the lightwalletd concurrency limit is reached.
pub const BUSY: &str = "lightwalletd concurrency limit reached";
/// Contains BUSY, so callers that match on BUSY answer it the same way (inner UNAVAILABLE).
pub const BUSY_HEAVY: &str = "lightwalletd concurrency limit reached (heavy calls)";

/// Call lightwalletd and return the response status, the response headers (content-type, date
/// and `grpc-*`) and a stream of body frames and trailers, under the deadlines `opts` gives
/// (each frame waits at most the remaining overall deadline; a long poll is closed cleanly after
/// the idle time without data).
///
/// `request_id` is forwarded as `X-Request-Id` and `grpc-request-id` so gateway and lightwalletd
/// logs can be matched (a fresh one for the gateway's own calls); `client_headers` are the
/// Client's gRPC request metadata ([`client_grpc_headers`]).
pub async fn call_lwd_stream_with(
    config: &Config,
    path: &str,
    body: Vec<u8>,
    request_id: Option<uuid::Uuid>,
    client_headers: Vec<(String, String)>,
    opts: StreamOpts,
) -> Result<(
    u16,
    Vec<(String, String)>,
    impl futures_util::Stream<Item = Result<crate::chunked_stream::UpFrame>> + Send + 'static,
)> {
    use axum::body::Bytes;
    use http_body_util::BodyExt;

    let client: Client<HttpConnector, Full<Bytes>> = lwd_client();

    let content_type = client_headers
        .iter()
        .find(|(name, _)| name == "content-type")
        .map_or(GRPC_CONTENT_TYPE, |(_, value)| value.as_str());
    let request_id = request_id.unwrap_or_else(uuid::Uuid::new_v4);
    let mut builder = Request::builder()
        .method("POST")
        .uri(lwd_uri(&config.lwd_addr, path)?)
        .header("content-type", content_type)
        .header("te", "trailers")
        .header("grpc-accept-encoding", "identity")
        .header("user-agent", "ohttp-gateway/1.0")
        .header("x-request-id", request_id.to_string())
        .header("grpc-request-id", request_id.to_string());
    for (name, value) in client_headers
        .iter()
        .filter(|(name, _)| name != "content-type")
    {
        builder = builder.header(name.as_str(), value.as_str());
    }
    let req = builder.body(Full::new(Bytes::from(body)))?;

    // Connecting and getting the head never waits longer than the configured timeout.
    let connect = Duration::from_secs(config.lwd_timeout_secs);
    let deadline = opts.overall.map(|d| Instant::now() + d);
    let idle = opts.idle;

    let resp = timeout(connect, request(&client, req)).await??;
    let status = resp.status().as_u16();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .filter(|(k, _)| {
            let l = k.as_str().to_ascii_lowercase();
            l == "content-type" || l == "date" || l.starts_with("grpc-")
        })
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let body_stream = resp.into_body();

    let frame_stream = async_stream::stream! {
        use crate::chunked_stream::UpFrame;
        let mut body_out = body_stream;
        // A long wait when nothing bounds the frame (tokio cannot represent Duration::MAX).
        let unbounded = Duration::from_secs(3600 * 24 * 365);

        loop {
            let remaining = match deadline {
                Some(d) => {
                    let r = d.saturating_duration_since(Instant::now());
                    if r.is_zero() {
                        yield Err(anyhow!("LWD response deadline"));
                        break;
                    }
                    r
                }
                None => unbounded,
            };
            let wait = match idle {
                Some(i) => remaining.min(i),
                None => remaining,
            };
            match timeout(wait, body_out.frame()).await {
                Ok(Some(Ok(frame))) => {
                    match frame.into_data() {
                        Ok(data) => {
                            yield Ok(UpFrame::Data(data));
                        }
                        Err(frame) => {
                            if let Ok(trailers) = frame.into_trailers() {
                                let trailer_vec: Vec<(String, String)> = trailers
                                    .iter()
                                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                                    .collect();
                                if !trailer_vec.is_empty() {
                                    yield Ok(UpFrame::Trailers(trailer_vec));
                                }
                            }
                        }
                    }
                }
                Ok(Some(Err(e))) => {
                    yield Err(anyhow!("body error: {e}"));
                    break;
                }
                Ok(None) => break,
                Err(_) => {
                    if idle.is_some_and(|i| wait == i) {
                        // A long poll: close it with what arrived, as a success.
                        yield Ok(UpFrame::Trailers(vec![("grpc-status".to_string(), "0".to_string())]));
                        break;
                    }
                    yield Err(anyhow!("frame timeout"));
                    break;
                }
            }
        }
    };

    Ok((status, headers, frame_stream))
}

/// The Client's gRPC request metadata that goes to lightwalletd (ZIP "Gateway behaviour" rule 5):
/// a gRPC `content-type` (`application/grpc`, `application/grpc+proto`, ...) and every `grpc-*`
/// field except `grpc-accept-encoding` (the gateway asks for `identity`: the caches store,
/// validate and re-chunk plaintext) and `grpc-request-id` (the gateway sends its own). Names or
/// values that are not valid HTTP fields are dropped.
pub fn client_grpc_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            let name = name.to_ascii_lowercase();
            let grpc_content_type =
                name == "content-type" && value.to_ascii_lowercase().starts_with(GRPC_CONTENT_TYPE);
            let forwarded = (grpc_content_type || name.starts_with("grpc-"))
                && !matches!(name.as_str(), "grpc-accept-encoding" | "grpc-request-id")
                && hyper::header::HeaderName::from_bytes(name.as_bytes()).is_ok()
                && hyper::header::HeaderValue::from_str(value).is_ok();
            forwarded.then(|| (name, value.clone()))
        })
        .collect()
}

/// Longest an upstream mempool stream is held before the fan-out reopens it.
const MEMPOOL_STREAM_MAX: Duration = Duration::from_secs(20 * 60);

/// The gateway's own lightwalletd as every upstream the caches need. Each call takes a permit of the
/// lightwalletd concurrency limit for the life of its response stream; heavy calls
/// (`enforcement::is_heavy_lwd_call`) also take one of the smaller heavy limit, so heavy calls
/// alone cannot use up the permits that SendTransaction and the tip need (as long as the heavy
/// limit is below the general one).
pub struct LwdSources {
    config: Config,
    semaphore: std::sync::Arc<tokio::sync::Semaphore>,
    heavy: std::sync::Arc<tokio::sync::Semaphore>,
    general_waiters: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    heavy_waiters: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl LwdSources {
    pub fn new(config: Config, semaphore: std::sync::Arc<tokio::sync::Semaphore>) -> Self {
        let heavy = std::sync::Arc::new(tokio::sync::Semaphore::new(
            config.max_inflight_lwd_heavy.max(1),
        ));
        Self {
            config,
            semaphore,
            heavy,
            general_waiters: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            heavy_waiters: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Same, without a separate heavy cap (the backfill: all of its calls are long ranges).
    pub fn new_unclassed(
        config: Config,
        semaphore: std::sync::Arc<tokio::sync::Semaphore>,
    ) -> Self {
        let heavy =
            std::sync::Arc::new(tokio::sync::Semaphore::new(config.max_inflight_lwd.max(1)));
        Self {
            config,
            semaphore,
            heavy,
            general_waiters: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            heavy_waiters: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Wait for a permit with bounds: reject immediately if the waiter count is at its cap, else
    /// wait up to `wait_ms` (0 = try_acquire, no wait). On success, record the wait time.
    async fn acquire_with_wait(
        semaphore: std::sync::Arc<tokio::sync::Semaphore>,
        wait_ms: u64,
        max_waiters: usize,
        waiters: &std::sync::Arc<std::sync::atomic::AtomicUsize>,
        network: &str,
        class: &str,
    ) -> Result<tokio::sync::OwnedSemaphorePermit> {
        use std::sync::atomic::Ordering;

        // Immediate rejection if no wait configured.
        if wait_ms == 0 {
            return semaphore
                .clone()
                .try_acquire_owned()
                .map_err(|_| anyhow!("lightwalletd concurrency limit reached"));
        }

        // Try immediate first (the common path when permits are available).
        if let Ok(p) = semaphore.clone().try_acquire_owned() {
            return Ok(p);
        }

        // Check waiter cap.
        let current_waiters = waiters.fetch_add(1, Ordering::SeqCst);
        if current_waiters >= max_waiters {
            waiters.fetch_sub(1, Ordering::SeqCst);
            return Err(anyhow!("lightwalletd concurrency limit reached"));
        }

        // Guard decrements the waiter count on drop (timeout, cancellation, success).
        struct WaiterGuard {
            waiters: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        }
        impl Drop for WaiterGuard {
            fn drop(&mut self) {
                self.waiters
                    .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let _guard = WaiterGuard {
            waiters: waiters.clone(),
        };

        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_millis(wait_ms);

        match tokio::time::timeout(timeout, semaphore.acquire_owned()).await {
            Ok(Ok(p)) => {
                let wait_seconds = start.elapsed().as_secs_f64();
                crate::health::record_lwd_permit_wait(network, class, wait_seconds);
                Ok(p)
            }
            Ok(Err(_)) => {
                // Semaphore closed (never happens here, but handle it).
                Err(anyhow!("lightwalletd concurrency limit reached"))
            }
            Err(_) => {
                // Timeout
                Err(anyhow!("lightwalletd concurrency limit reached"))
            }
        }
    }

    fn stream(
        &self,
        path: String,
        body: Vec<u8>,
        request_id: Option<uuid::Uuid>,
        client_headers: Vec<(String, String)>,
        opts: StreamOpts,
    ) -> futures_util::future::BoxFuture<'static, Result<crate::singleflight::RpcResponse>> {
        let config = self.config.clone();
        let semaphore = self.semaphore.clone();
        let heavy_sem = self.heavy.clone();
        let general_waiters = self.general_waiters.clone();
        let heavy_waiters = self.heavy_waiters.clone();
        let is_heavy =
            crate::enforcement::is_heavy_lwd_call(&path, &body, config.lwd_heavy_block_range);

        Box::pin(async move {
            // Heavy class first, so a refused or waiting heavy call never holds a general permit.
            let heavy_permit = if is_heavy {
                let max_waiters = if config.lwd_permit_max_waiters == 0 {
                    config.max_inflight_lwd_heavy.saturating_mul(4).max(1)
                } else {
                    config.lwd_permit_max_waiters
                };
                match Self::acquire_with_wait(
                    heavy_sem,
                    config.lwd_permit_wait_ms,
                    max_waiters,
                    &heavy_waiters,
                    &config.network,
                    "heavy",
                )
                .await
                {
                    Ok(p) => Some(p),
                    Err(_) => {
                        crate::health::record_lwd_shed(&config.network, "heavy");
                        return Err(anyhow!(BUSY_HEAVY));
                    }
                }
            } else {
                None
            };

            // General permit.
            let max_waiters = if config.lwd_permit_max_waiters == 0 {
                config.max_inflight_lwd.saturating_mul(4).max(1)
            } else {
                config.lwd_permit_max_waiters
            };
            let general_permit = match Self::acquire_with_wait(
                semaphore,
                config.lwd_permit_wait_ms,
                max_waiters,
                &general_waiters,
                &config.network,
                "general",
            )
            .await
            {
                Ok(p) => p,
                Err(_) => {
                    crate::health::record_lwd_shed(&config.network, "general");
                    return Err(if is_heavy {
                        anyhow!(BUSY_HEAVY)
                    } else {
                        anyhow!(BUSY)
                    });
                }
            };

            let (status, headers, stream) =
                call_lwd_stream_with(&config, &path, body, request_id, client_headers, opts)
                    .await?;
            use futures_util::StreamExt as _;
            let body = crate::chunked_stream::hold_permit(stream, general_permit).boxed();
            let body = match heavy_permit {
                Some(h) => crate::chunked_stream::hold_permit(body, h).boxed(),
                None => body,
            };
            Ok(crate::singleflight::RpcResponse {
                status,
                headers,
                body,
            })
        })
    }

    fn default_opts(&self, path: &str) -> StreamOpts {
        StreamOpts {
            overall: Some(Duration::from_secs(self.config.lwd_timeout_secs)),
            idle: path
                .ends_with("/GetMempoolStream")
                .then(|| Duration::from_secs(self.config.long_poll_idle_secs)),
        }
    }
}

impl crate::singleflight::RpcSource for LwdSources {
    fn call(
        &self,
        path: String,
        body: Vec<u8>,
        request_id: Option<uuid::Uuid>,
    ) -> futures_util::future::BoxFuture<'static, Result<crate::singleflight::RpcResponse>> {
        let opts = self.default_opts(&path);
        self.stream(path, body, request_id, Vec::new(), opts)
    }

    fn call_with_headers(
        &self,
        path: String,
        body: Vec<u8>,
        request_id: Option<uuid::Uuid>,
        headers: Vec<(String, String)>,
    ) -> futures_util::future::BoxFuture<'static, Result<crate::singleflight::RpcResponse>> {
        let opts = self.default_opts(&path);
        self.stream(path, body, request_id, headers, opts)
    }
}

impl crate::block_cache::BlockSource for LwdSources {
    fn fetch(
        &self,
        body: Vec<u8>,
    ) -> futures_util::future::BoxFuture<'static, Result<crate::block_cache::UpstreamResponse>>
    {
        let path = crate::block_cache::GET_BLOCK_RANGE_PATH.to_string();
        let opts = self.default_opts(&path);
        let fut = self.stream(path, body, None, Vec::new(), opts);
        Box::pin(async move {
            let r = fut.await?;
            Ok(crate::block_cache::UpstreamResponse {
                status: r.status,
                headers: r.headers,
                body: r.body,
            })
        })
    }
}

impl crate::chain::ChainSource for LwdSources {
    fn latest(&self) -> futures_util::future::BoxFuture<'static, Result<crate::store::Tip>> {
        let config = self.config.clone();
        let semaphore = self.semaphore.clone();
        let general_waiters = self.general_waiters.clone();

        Box::pin(async move {
            let max_waiters = if config.lwd_permit_max_waiters == 0 {
                config.max_inflight_lwd.saturating_mul(4).max(1)
            } else {
                config.lwd_permit_max_waiters
            };
            let _permit = Self::acquire_with_wait(
                semaphore,
                config.lwd_permit_wait_ms,
                max_waiters,
                &general_waiters,
                &config.network,
                "general",
            )
            .await
            .map_err(|_| {
                crate::health::record_lwd_shed(&config.network, "general");
                anyhow!(BUSY)
            })?;
            let (height, hash) = fetch_latest_block(&config).await?;
            Ok(crate::store::Tip { height, hash })
        })
    }

    fn blocks(
        &self,
        start: u64,
        end: u64,
    ) -> futures_util::future::BoxFuture<'static, Result<Vec<crate::block_cache::FetchedBlock>>>
    {
        use crate::block_cache::{BlockRangeRequest, FetchedBlock, GrpcSplitter};
        use crate::chunked_stream::UpFrame;
        use futures_util::StreamExt;
        let path = crate::block_cache::GET_BLOCK_RANGE_PATH.to_string();
        let opts = self.default_opts(&path);
        let fut = self.stream(
            path,
            BlockRangeRequest::grpc_body(start, end, &[]),
            None,
            Vec::new(),
            opts,
        );
        Box::pin(async move {
            let r = fut.await?;
            if r.status != 200 {
                return Err(anyhow!("GetBlockRange answered HTTP {}", r.status));
            }
            let mut splitter = GrpcSplitter::default();
            let mut blocks = Vec::new();
            let mut trailers: Vec<(String, String)> = Vec::new();
            let mut body = r.body;
            while let Some(frame) = body.next().await {
                match frame? {
                    UpFrame::Data(d) => {
                        for f in splitter.push(&d) {
                            blocks.push(FetchedBlock::from_frame(f));
                        }
                    }
                    UpFrame::Trailers(t) => trailers.extend(t),
                }
            }
            let status = trailers
                .iter()
                .chain(r.headers.iter())
                .find(|(k, _)| k.eq_ignore_ascii_case("grpc-status"))
                .map(|(_, v)| v.as_str());
            if status != Some("0") {
                return Err(anyhow!(
                    "GetBlockRange({start},{end}) grpc-status {}",
                    status.unwrap_or("missing")
                ));
            }
            Ok(blocks)
        })
    }
}

impl crate::mempool::MempoolSource for LwdSources {
    fn open(
        &self,
    ) -> futures_util::future::BoxFuture<'static, Result<crate::singleflight::RpcResponse>> {
        self.stream(
            crate::mempool::GET_MEMPOOL_STREAM_PATH.to_string(),
            grpc_wrap(&[]),
            None,
            Vec::new(),
            StreamOpts {
                overall: Some(MEMPOOL_STREAM_MAX),
                idle: None,
            },
        )
    }
}

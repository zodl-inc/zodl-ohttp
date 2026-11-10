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
/// connect retry of [`crate::lwd_endpoints::request`] covers an address that is joining or leaving).
///
/// `LWD_CONNECTION_POOL=1` shares one pooled client instead (idle connections kept 60 s, HTTP/2
/// PINGs every 20 s, a connection whose PING is not answered within 5 s is closed), which saves
/// the TCP handshake, one round trip, per call. For a gateway far from lightwalletd that is one
/// long round trip per cache miss and per SendTransaction. The trade-off: a pooled connection
/// stays on one instance until it closes, so a call in flight when that instance exits fails,
/// and an instance that hangs keeps getting calls until the PING closes the connection; a call
/// that runs into its deadline therefore replaces the pooled client ([`reset_pool`]).
pub(crate) fn lwd_client() -> Client<HttpConnector, Full<axum::body::Bytes>> {
    match pooled() {
        Some(client) => (**client.load()).clone(),
        None => crate::lwd_endpoints::fresh_client(),
    }
}

type LwdClient = Client<HttpConnector, Full<axum::body::Bytes>>;

fn pooled() -> &'static Option<arc_swap::ArcSwap<LwdClient>> {
    static POOLED: OnceLock<Option<arc_swap::ArcSwap<LwdClient>>> = OnceLock::new();
    POOLED.get_or_init(|| {
        let on = std::env::var("LWD_CONNECTION_POOL")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "on"))
            .unwrap_or(false);
        on.then(|| arc_swap::ArcSwap::from_pointee(new_pooled_client()))
    })
}

fn new_pooled_client() -> LwdClient {
    Client::builder(TokioExecutor::new())
        .http2_only(true)
        .pool_timer(TokioTimer::new())
        .pool_idle_timeout(Duration::from_secs(60))
        .timer(TokioTimer::new())
        .http2_keep_alive_interval(Duration::from_secs(20))
        .http2_keep_alive_timeout(Duration::from_secs(5))
        .http2_keep_alive_while_idle(true)
        .build(crate::lwd_endpoints::connector())
}

/// Shortest time between two replacements of the pooled client.
const POOL_RESET_MIN_INTERVAL: Duration = Duration::from_secs(5);

/// A call ran into its deadline: replace the pooled client (no-op without the pool), so that
/// new calls open new connections instead of queueing on one to an instance that may hang.
/// Calls in flight keep their connection. At most once per [`POOL_RESET_MIN_INTERVAL`].
pub(crate) fn reset_pool(network: &str) {
    static LAST: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);
    let Some(pool) = pooled() else { return };
    let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
    if last.is_some_and(|t| t.elapsed() < POOL_RESET_MIN_INTERVAL) {
        return;
    }
    *last = Some(Instant::now());
    pool.store(std::sync::Arc::new(new_pooled_client()));
    crate::health::record_lwd_pool_reset(network);
    tracing::warn!(
        network,
        "lightwalletd call ran into its deadline: pooled connections replaced"
    );
}

/// Per-class deadlines of a lightwalletd call, below the overall `LWD_TIMEOUT_SECS`.
///
/// - `LWD_UNARY_TIMEOUT_SECS` (default 10): the whole call of an RPC with one answer
///   (`GetLatestBlock`, `GetTreeState`, `GetTransaction`, `SendTransaction`, ...).
/// - `LWD_STREAM_IDLE_SECS` (default 20): for a server-streaming RPC (`GetBlockRange`,
///   `GetSubtreeRoots`, ...) the wait for the response head and for each next frame; a stream
///   that keeps sending runs up to `LWD_TIMEOUT_SECS`. The mempool long poll keeps its own rules.
/// - Transparent-address RPCs ([`LWD_ADDRESS_RPCS`]) keep `LWD_TIMEOUT_SECS` for their first
///   answer (a node's address query can be slow), streams of them get the idle bound after it.
///
/// A lightwalletd that accepts connections but does not answer (a hung process) thus costs a
/// read at most these bounds instead of `LWD_TIMEOUT_SECS`, and the client's retry (a fresh
/// request) can land on another instance. Calls cut by them are counted in
/// `ohttp_lwd_timeouts_total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LwdDeadlines {
    pub unary: Duration,
    pub stream_idle: Duration,
}

pub const DEFAULT_LWD_UNARY_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_LWD_STREAM_IDLE: Duration = Duration::from_secs(20);

impl Default for LwdDeadlines {
    fn default() -> Self {
        Self {
            unary: DEFAULT_LWD_UNARY_TIMEOUT,
            stream_idle: DEFAULT_LWD_STREAM_IDLE,
        }
    }
}

impl LwdDeadlines {
    pub fn parse(unary: Option<&str>, stream_idle: Option<&str>) -> Result<Self> {
        let secs = |name: &str, v: Option<&str>, default: Duration| -> Result<Duration> {
            match v.map(str::trim).filter(|v| !v.is_empty()) {
                None => Ok(default),
                Some(v) => match v.parse::<u64>() {
                    Ok(n) if n > 0 => Ok(Duration::from_secs(n)),
                    _ => Err(anyhow!("{name} must be a positive integer, got '{v}'")),
                },
            }
        };
        Ok(Self {
            unary: secs("LWD_UNARY_TIMEOUT_SECS", unary, DEFAULT_LWD_UNARY_TIMEOUT)?,
            stream_idle: secs("LWD_STREAM_IDLE_SECS", stream_idle, DEFAULT_LWD_STREAM_IDLE)?,
        })
    }

    pub fn from_env() -> Result<Self> {
        Self::parse(
            std::env::var("LWD_UNARY_TIMEOUT_SECS").ok().as_deref(),
            std::env::var("LWD_STREAM_IDLE_SECS").ok().as_deref(),
        )
    }
}

static DEADLINES: OnceLock<LwdDeadlines> = OnceLock::new();

/// Set the deadlines once at startup (main); later calls are ignored.
pub fn init_deadlines(d: LwdDeadlines) {
    let _ = DEADLINES.set(d);
}

/// The deadlines in force (the defaults when `init_deadlines` was not called, as in tests).
pub fn deadlines() -> LwdDeadlines {
    DEADLINES.get().copied().unwrap_or_default()
}

/// The server-streaming RPCs of lightwalletd's `CompactTxStreamer` (service.proto); every other
/// RPC has one answer.
pub const LWD_STREAMING_RPCS: &[&str] = &[
    "GetBlockRange",
    "GetBlockRangeNullifiers",
    "GetTaddressTxids",
    "GetTaddressTransactions",
    "GetMempoolTx",
    "GetMempoolStream",
    "GetSubtreeRoots",
    "GetAddressUtxosStream",
];

/// Whether `path` (`/<service>/<method>`) is a server-streaming RPC.
pub fn is_streaming_rpc(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .is_some_and(|m| LWD_STREAMING_RPCS.contains(&m))
}

/// RPCs whose first answer waits for a transparent-address index query of the node, which can
/// take long for a busy address: their head (or, for one answer, the whole call) keeps
/// `LWD_TIMEOUT_SECS`; a stream of them still gets the idle bound between frames.
pub const LWD_ADDRESS_RPCS: &[&str] = &[
    "GetTaddressTxids",
    "GetTaddressTransactions",
    "GetTaddressBalance",
    "GetTaddressBalanceStream",
    "GetAddressUtxos",
    "GetAddressUtxosStream",
];

fn is_address_rpc(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .is_some_and(|m| LWD_ADDRESS_RPCS.contains(&m))
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

    // One answer: the unary deadline bounds the whole call.
    let overall = Duration::from_secs(config.lwd_timeout_secs).min(deadlines().unary);
    let deadline = Instant::now() + overall;

    let opts = crate::lwd_endpoints::CallOpts {
        network: &config.network,
        head: overall,
        class: Some("unary"),
        pooled: pooled().is_some(),
    };
    let resp = match crate::lwd_endpoints::request(req, opts).await {
        Ok(r) => r,
        Err(crate::lwd_endpoints::RequestError::Timeout) => return Err(anyhow!("LWD timeout")),
        Err(e) => return Err(anyhow!("HTTP: {e}")),
    };

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
            crate::health::record_lwd_timeout(&config.network, "unary", "body");
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
            Err(_) => {
                crate::health::record_lwd_timeout(&config.network, "unary", "body");
                reset_pool(&config.network);
                return Err(anyhow!("LWD response deadline"));
            }
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

    /// A lightwalletd that accepts connections and never answers (a stopped process: the
    /// kernel still completes the handshake).
    async fn hung_lwd() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        addr.to_string()
    }

    /// A lightwalletd (h2) that answers with `frames` data frames, one every `every`, then a
    /// clean grpc-status 0.
    async fn trickling_lwd(frames: u8, every: std::time::Duration) -> String {
        use hyper::body::Frame;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let service = hyper::service::service_fn(
                    move |_req: hyper::Request<hyper::body::Incoming>| async move {
                        let body = futures_util::stream::unfold(0u8, move |n| async move {
                            if n > frames {
                                return None;
                            }
                            tokio::time::sleep(every).await;
                            let frame = if n == frames {
                                let mut t = hyper::HeaderMap::new();
                                t.insert("grpc-status", "0".parse().unwrap());
                                Frame::trailers(t)
                            } else {
                                Frame::data(axum::body::Bytes::from_static(&[0, 0, 0, 0, 1, 7]))
                            };
                            Some((Ok::<_, std::convert::Infallible>(frame), n + 1))
                        });
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(200)
                                .header("content-type", "application/grpc")
                                .body(http_body_util::StreamBody::new(body))
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

    const TREE_STATE: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTreeState";
    const BLOCK_RANGE: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlockRange";
    const SHORT: super::LwdDeadlines = super::LwdDeadlines {
        unary: std::time::Duration::from_secs(1),
        stream_idle: std::time::Duration::from_secs(1),
    };

    fn opts_for(path: &str) -> super::StreamOpts {
        super::StreamOpts::for_path(
            path,
            std::time::Duration::from_secs(80),
            std::time::Duration::from_secs(3),
            SHORT,
        )
    }

    /// What `call_lwd_stream_with` returns.
    type Streamed<S> = anyhow::Result<(u16, Vec<(String, String)>, S)>;

    /// Drain a streamed call: Ok(frames) when it ended cleanly, Err at the first error.
    async fn drain<S>(r: Streamed<S>) -> anyhow::Result<usize>
    where
        S: futures_util::Stream<Item = anyhow::Result<crate::chunked_stream::UpFrame>>,
    {
        use futures_util::StreamExt;
        let (_, _, body) = r?;
        let mut body = std::pin::pin!(body);
        let mut n = 0;
        while let Some(f) = body.next().await {
            f?;
            n += 1;
        }
        Ok(n)
    }

    #[test]
    fn rpc_classes_and_their_deadlines() {
        assert!(super::is_streaming_rpc(BLOCK_RANGE));
        assert!(super::is_streaming_rpc(
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetSubtreeRoots"
        ));
        assert!(!super::is_streaming_rpc(TREE_STATE));
        assert!(!super::is_streaming_rpc(
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/SendTransaction"
        ));
        assert!(!super::is_streaming_rpc(
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTaddressBalanceStream"
        ));
        let unary = opts_for(TREE_STATE);
        assert_eq!(unary.overall, Some(SHORT.unary));
        assert_eq!(unary.head, Some(SHORT.unary));
        assert_eq!((unary.gap, unary.idle), (None, None));
        let stream = opts_for(BLOCK_RANGE);
        assert_eq!(stream.overall, Some(std::time::Duration::from_secs(80)));
        assert_eq!(stream.head, Some(SHORT.stream_idle));
        assert_eq!(stream.gap, Some(SHORT.stream_idle));
        // Transparent-address queries keep the overall timeout for their first answer.
        let balance = opts_for("/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTaddressBalance");
        assert_eq!(balance.overall, Some(std::time::Duration::from_secs(80)));
        assert_eq!(balance.head, None);
        let txids = opts_for("/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTaddressTxids");
        assert_eq!(txids.head, Some(std::time::Duration::from_secs(80)));
        assert_eq!(txids.gap, Some(SHORT.stream_idle));
        let poll = opts_for("/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetMempoolStream");
        assert_eq!(poll.idle, Some(std::time::Duration::from_secs(3)));
        assert_eq!((poll.head, poll.gap, poll.class), (None, None, None));
        // LWD_TIMEOUT_SECS stays the upper bound.
        let tight = super::StreamOpts::for_path(
            TREE_STATE,
            std::time::Duration::from_millis(500),
            std::time::Duration::from_secs(3),
            SHORT,
        );
        assert_eq!(tight.overall, Some(std::time::Duration::from_millis(500)));
    }

    #[test]
    fn deadlines_parse() {
        assert_eq!(
            super::LwdDeadlines::parse(None, None).unwrap(),
            super::LwdDeadlines::default()
        );
        let d = super::LwdDeadlines::parse(Some("4"), Some(" 9 ")).unwrap();
        assert_eq!(d.unary, std::time::Duration::from_secs(4));
        assert_eq!(d.stream_idle, std::time::Duration::from_secs(9));
        assert!(super::LwdDeadlines::parse(Some("0"), None).is_err());
        assert!(super::LwdDeadlines::parse(None, Some("x")).is_err());
    }

    #[tokio::test]
    async fn a_hung_lightwalletd_costs_a_unary_call_its_deadline_only() {
        let mut config = test_config();
        config.lwd_addr = hung_lwd().await;
        let start = std::time::Instant::now();
        let r = super::call_lwd_stream_with(
            &config,
            TREE_STATE,
            super::grpc_wrap(&[]),
            None,
            Vec::new(),
            opts_for(TREE_STATE),
        )
        .await;
        assert!(r.is_err());
        let took = start.elapsed();
        assert!(
            took >= std::time::Duration::from_millis(900)
                && took < std::time::Duration::from_secs(3),
            "{took:?}"
        );
    }

    #[tokio::test]
    async fn a_hung_lightwalletd_costs_a_stream_its_idle_bound_only() {
        let mut config = test_config();
        config.lwd_addr = hung_lwd().await;
        let start = std::time::Instant::now();
        let r = super::call_lwd_stream_with(
            &config,
            BLOCK_RANGE,
            super::grpc_wrap(&[]),
            None,
            Vec::new(),
            opts_for(BLOCK_RANGE),
        )
        .await;
        assert!(r.is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(3));
    }

    #[tokio::test]
    async fn a_stream_that_goes_silent_ends_after_the_idle_bound() {
        let mut config = test_config();
        // One frame, then silence for 30 s.
        config.lwd_addr = stalling_lwd().await;
        let start = std::time::Instant::now();
        let r = drain(
            super::call_lwd_stream_with(
                &config,
                BLOCK_RANGE,
                super::grpc_wrap(&[]),
                None,
                Vec::new(),
                opts_for(BLOCK_RANGE),
            )
            .await,
        )
        .await;
        assert!(
            r.is_err(),
            "a silent stream is an error, not a short answer"
        );
        assert!(start.elapsed() < std::time::Duration::from_secs(3));
    }

    #[tokio::test]
    async fn a_stream_that_keeps_sending_runs_past_the_idle_bound() {
        let mut config = test_config();
        // 12 frames 250 ms apart: 3 s in total, three times the 1 s idle bound.
        config.lwd_addr = trickling_lwd(12, std::time::Duration::from_millis(250)).await;
        let start = std::time::Instant::now();
        let n = drain(
            super::call_lwd_stream_with(
                &config,
                BLOCK_RANGE,
                super::grpc_wrap(&[]),
                None,
                Vec::new(),
                opts_for(BLOCK_RANGE),
            )
            .await,
        )
        .await
        .unwrap();
        assert_eq!(n, 13, "12 data frames + the trailers");
        assert!(start.elapsed() >= std::time::Duration::from_millis(2900));
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
            cache_local_redis_url: String::new(),
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
/// `idle` Some = a long poll closed cleanly (grpc-status 0) after that much silence;
/// `head` Some = the response head must arrive within this (else `LWD_TIMEOUT_SECS`);
/// `gap` Some = no frame for this long ends the call with an error (a stream that went silent).
/// `class` labels the deadlines in `ohttp_lwd_timeouts_total` (None = not counted).
#[derive(Clone, Copy, Debug, Default)]
pub struct StreamOpts {
    pub overall: Option<Duration>,
    pub idle: Option<Duration>,
    pub head: Option<Duration>,
    pub gap: Option<Duration>,
    pub class: Option<&'static str>,
}

impl StreamOpts {
    /// The deadlines of a call to `path` (see [`LwdDeadlines`]): a unary RPC is bounded as a
    /// whole by the unary deadline; a server-streaming one waits at most the stream idle bound
    /// for its head and for each frame, and runs up to `lwd_timeout`; the mempool long poll is
    /// closed cleanly after `long_poll_idle` of silence, as before.
    pub fn for_path(
        path: &str,
        lwd_timeout: Duration,
        long_poll_idle: Duration,
        d: LwdDeadlines,
    ) -> Self {
        if path.ends_with("/GetMempoolStream") {
            return Self {
                overall: Some(lwd_timeout),
                idle: Some(long_poll_idle),
                ..Self::default()
            };
        }
        let address = is_address_rpc(path);
        if is_streaming_rpc(path) {
            let idle = d.stream_idle.min(lwd_timeout);
            return Self {
                overall: Some(lwd_timeout),
                head: Some(if address { lwd_timeout } else { idle }),
                gap: Some(idle),
                class: Some("stream"),
                ..Self::default()
            };
        }
        if address {
            return Self {
                overall: Some(lwd_timeout),
                class: Some("unary"),
                ..Self::default()
            };
        }
        let unary = d.unary.min(lwd_timeout);
        Self {
            overall: Some(unary),
            head: Some(unary),
            class: Some("unary"),
            ..Self::default()
        }
    }
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

    // Connecting and getting the head never waits longer than the configured timeout, or the
    // call's own head deadline.
    let connect = Duration::from_secs(config.lwd_timeout_secs);
    let connect = opts.head.map_or(connect, |h| h.min(connect));
    let deadline = opts.overall.map(|d| Instant::now() + d);
    let idle = opts.idle;
    let gap = opts.gap;
    let class = opts.class;
    let network = config.network.clone();

    let call = crate::lwd_endpoints::CallOpts {
        network: &network,
        head: connect,
        class,
        pooled: pooled().is_some(),
    };
    let resp = crate::lwd_endpoints::request(req, call).await?;
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
                        if let Some(class) = class {
                            crate::health::record_lwd_timeout(&network, class, "body");
                        }
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
            let wait = match gap {
                Some(g) => wait.min(g),
                None => wait,
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
                    if let Some(class) = class {
                        let phase = if gap.is_some_and(|g| wait == g) { "gap" } else { "body" };
                        crate::health::record_lwd_timeout(&network, class, phase);
                        reset_pool(&network);
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
        StreamOpts::for_path(
            path,
            Duration::from_secs(self.config.lwd_timeout_secs),
            Duration::from_secs(self.config.long_poll_idle_secs),
            deadlines(),
        )
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
                ..StreamOpts::default()
            },
        )
    }
}

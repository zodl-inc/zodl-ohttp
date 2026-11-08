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

//! How a lightwalletd call reaches an instance, and its one retry.
//!
//! Every call to the gateway's own lightwalletd (`LWD_ADDR`) goes through [`request`]:
//!
//! - **Connect timeout** (`LWD_CONNECT_TIMEOUT_MS`, default 2000): a connection that is not
//!   established in time is a connect error. An instance whose network is cut drops the SYN
//!   instead of refusing it, and without a bound the call waited for its whole deadline.
//! - **Instances** (`LWD_ENDPOINTS`, optional): a `host:port` name that resolves to one address
//!   per lightwalletd instance (for example a headless service). The gateway resolves it (again
//!   after [`RESOLVE_EVERY`]) and sends each call to one of the addresses at random, skipping an
//!   address whose last attempt failed less than [`EJECT_FOR`] ago (unless every address did).
//!   `LWD_ADDR` stays the logical name (logs, the chain follower's namespace); it is used as before
//!   when `LWD_ENDPOINTS` is unset or has not resolved yet. Without it, a retry is a new
//!   connection to `LWD_ADDR`, which a load-balanced address may or may not send elsewhere.
//! - **One retry**:
//!   - after a connect error, for every call (no byte of the request reached lightwalletd, so
//!     nothing can run twice, `SendTransaction` included);
//!   - for an idempotent call (every `CompactTxStreamer` RPC except `SendTransaction`) also after
//!     a transport error, and when the response head does not arrive within half of the call's
//!     head deadline (the other half is left for the retry; not for `GetMempoolStream` and the
//!     transparent-address RPCs, whose head may take long). A `SendTransaction` is never sent
//!     twice by the gateway.
//!
//!   Every attempt cut by its deadline counts in `ohttp_lwd_timeouts_total`, also when its retry
//!   answers: a hung instance stays visible while the retries hide it from the clients.
//!
//!   The retry goes to another instance when `LWD_ENDPOINTS` has one, always on a new connection.
//!   Only the phase up to the response head is retried: a call that fails after its head arrived
//!   is not (part of the answer may already be on its way to the client).
//! - **Outcome** of every call to the own lightwalletd (after the retry) goes to the `/healthz`
//!   error window (`health::record_lwd_call`).

use axum::body::Bytes;
use http_body_util::Full;
use hyper::Request;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

type LwdClient = Client<HttpConnector, Full<Bytes>>;

/// How often the instance addresses of `LWD_ENDPOINTS` are resolved again.
pub const RESOLVE_EVERY: Duration = Duration::from_secs(5);
/// How long an address whose attempt failed is skipped while another one is available.
pub const EJECT_FOR: Duration = Duration::from_secs(30);
/// Bound on one resolution of `LWD_ENDPOINTS`.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(1);
/// Pause before the retry after a connect error.
const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(50);

pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_millis(2000);

/// `LWD_ADDR`, `LWD_ENDPOINTS` and `LWD_CONNECT_TIMEOUT_MS`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// `LWD_ADDR`: requests to this authority are the gateway's own lightwalletd calls.
    pub lwd_addr: String,
    /// `LWD_ENDPOINTS`: `host:port` resolving to one address per instance.
    pub endpoints: Option<String>,
    pub connect_timeout: Duration,
}

impl Settings {
    pub fn parse(
        lwd_addr: &str,
        endpoints: Option<&str>,
        connect_timeout_ms: Option<&str>,
    ) -> anyhow::Result<Self> {
        let endpoints = match endpoints.map(str::trim).filter(|v| !v.is_empty()) {
            None => None,
            Some(v) => {
                let port_ok = v
                    .rsplit_once(':')
                    .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok());
                if !port_ok || v.contains('/') {
                    anyhow::bail!("LWD_ENDPOINTS must be host:port, got '{v}'");
                }
                Some(v.to_string())
            }
        };
        let connect_timeout = match connect_timeout_ms.map(str::trim).filter(|v| !v.is_empty()) {
            None => DEFAULT_CONNECT_TIMEOUT,
            Some(v) => match v.parse::<u64>() {
                Ok(n) if n > 0 => Duration::from_millis(n),
                _ => anyhow::bail!("LWD_CONNECT_TIMEOUT_MS must be a positive integer, got '{v}'"),
            },
        };
        Ok(Self {
            lwd_addr: lwd_addr.to_string(),
            endpoints,
            connect_timeout,
        })
    }

    pub fn from_env(lwd_addr: &str) -> anyhow::Result<Self> {
        Self::parse(
            lwd_addr,
            std::env::var("LWD_ENDPOINTS").ok().as_deref(),
            std::env::var("LWD_CONNECT_TIMEOUT_MS").ok().as_deref(),
        )
    }
}

struct Transport {
    settings: Settings,
    endpoints: Option<EndpointSet>,
}

static TRANSPORT: OnceLock<Transport> = OnceLock::new();

/// Set once at startup (main); later calls are ignored. Without it (tests) no request counts as
/// a call to the own lightwalletd: no instance choice, no read retry, no `/healthz` outcome.
pub fn init(settings: Settings) {
    let endpoints = settings.endpoints.clone().map(EndpointSet::new);
    let _ = TRANSPORT.set(Transport {
        settings,
        endpoints,
    });
}

/// The connect timeout in force.
pub fn connect_timeout() -> Duration {
    TRANSPORT
        .get()
        .map_or(DEFAULT_CONNECT_TIMEOUT, |t| t.settings.connect_timeout)
}

/// An HTTP connector with the connect timeout and `TCP_NODELAY`.
pub fn connector() -> HttpConnector {
    let mut c = HttpConnector::new();
    c.set_connect_timeout(Some(connect_timeout()));
    c.set_nodelay(true);
    c
}

/// A client of its own (a new connection), HTTP/2 only.
pub fn fresh_client() -> LwdClient {
    Client::builder(hyper_util::rt::TokioExecutor::new())
        .http2_only(true)
        .build(connector())
}

/// Whether `path` may be sent twice: a `CompactTxStreamer` RPC other than `SendTransaction`
/// (all of them only read).
pub fn is_idempotent(path: &str) -> bool {
    match path.strip_prefix("/cash.z.wallet.sdk.rpc.CompactTxStreamer/") {
        Some(method) => !method.is_empty() && !method.contains('/') && method != "SendTransaction",
        None => false,
    }
}

/// Reads whose response head may take most of the call's deadline: the mempool long poll and
/// the transparent-address queries (`lwd::LWD_ADDRESS_RPCS`).
fn waits_for_its_head(path: &str) -> bool {
    let method = path.rsplit('/').next().unwrap_or("");
    method == "GetMempoolStream" || crate::lwd::LWD_ADDRESS_RPCS.contains(&method)
}

/// The resolved instance addresses of `LWD_ENDPOINTS` and the ones that failed recently.
pub struct EndpointSet {
    name: String,
    state: parking_lot::Mutex<EndpointState>,
}

#[derive(Default)]
struct EndpointState {
    addrs: Vec<SocketAddr>,
    resolved_at: Option<Instant>,
    failed: HashMap<SocketAddr, Instant>,
}

impl EndpointSet {
    pub fn new(name: String) -> Self {
        Self {
            name,
            state: Default::default(),
        }
    }

    /// For tests: a fixed address list that is never resolved again.
    #[cfg(test)]
    pub fn fixed(addrs: Vec<SocketAddr>) -> Self {
        let set = Self::new(String::new());
        {
            let mut s = set.state.lock();
            s.addrs = addrs;
            s.resolved_at = Some(Instant::now() + Duration::from_secs(3600));
        }
        set
    }

    /// The current addresses; resolved again once [`RESOLVE_EVERY`] has passed. A failed or
    /// empty resolution keeps the previous list.
    pub async fn addrs(&self) -> Vec<SocketAddr> {
        {
            let s = self.state.lock();
            if s.resolved_at.is_some_and(|t| t.elapsed() < RESOLVE_EVERY) || self.name.is_empty() {
                return s.addrs.clone();
            }
        }
        let resolved =
            tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host(self.name.as_str()))
                .await;
        let mut s = self.state.lock();
        s.resolved_at = Some(Instant::now());
        match resolved {
            Ok(Ok(found)) => {
                let mut found: Vec<SocketAddr> = found.collect();
                found.sort();
                found.dedup();
                if found.is_empty() {
                    tracing::warn!(name = %self.name, "LWD_ENDPOINTS resolved to no address; keeping the previous list");
                } else {
                    s.failed.retain(|a, _| found.contains(a));
                    s.addrs = found;
                }
            }
            Ok(Err(e)) => {
                tracing::warn!(name = %self.name, error = %e, "LWD_ENDPOINTS did not resolve; keeping the previous list")
            }
            Err(_) => {
                tracing::warn!(name = %self.name, "LWD_ENDPOINTS resolution timed out; keeping the previous list")
            }
        }
        s.addrs.clone()
    }

    /// An address of `addrs` other than `avoid`, at random among those that did not fail in the
    /// last [`EJECT_FOR`] (or among all others when every one did); `avoid` itself when it is the
    /// only one; None for an empty list.
    pub fn pick(
        &self,
        addrs: &[SocketAddr],
        avoid: Option<SocketAddr>,
        now: Instant,
    ) -> Option<SocketAddr> {
        use rand::seq::SliceRandom;
        let others: Vec<SocketAddr> = addrs
            .iter()
            .copied()
            .filter(|a| Some(*a) != avoid)
            .collect();
        if others.is_empty() {
            return avoid.filter(|a| addrs.contains(a));
        }
        let s = self.state.lock();
        let healthy: Vec<SocketAddr> = others
            .iter()
            .copied()
            .filter(|a| {
                s.failed
                    .get(a)
                    .is_none_or(|t| now.saturating_duration_since(*t) >= EJECT_FOR)
            })
            .collect();
        let pool = if healthy.is_empty() {
            &others
        } else {
            &healthy
        };
        pool.choose(&mut rand::thread_rng()).copied()
    }

    pub fn mark_failed(&self, addr: SocketAddr, now: Instant) {
        self.state.lock().failed.insert(addr, now);
    }

    pub fn mark_ok(&self, addr: SocketAddr) {
        self.state.lock().failed.remove(&addr);
    }
}

/// Why a call to lightwalletd got no response head.
#[derive(Debug)]
pub enum RequestError {
    /// No head within the call's head deadline.
    Timeout,
    Http(hyper_util::client::legacy::Error),
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestError::Timeout => write!(f, "deadline has elapsed"),
            RequestError::Http(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RequestError {}

impl RequestError {
    fn is_connect(&self) -> bool {
        matches!(self, RequestError::Http(e) if e.is_connect())
    }
}

/// The call-specific part of [`request`].
#[derive(Clone, Copy, Debug)]
pub struct CallOpts<'a> {
    pub network: &'a str,
    /// Bound on connecting and receiving the response head (both attempts together).
    pub head: Duration,
    /// For `ohttp_lwd_timeouts_total` (None: not counted there).
    pub class: Option<&'static str>,
    /// Use the shared pooled client for the first attempt (`LWD_CONNECTION_POOL`).
    pub pooled: bool,
}

/// Send `req` and return its response head, with the instance choice and the one retry
/// described in the module documentation.
pub async fn request(
    req: Request<Full<Bytes>>,
    opts: CallOpts<'_>,
) -> Result<hyper::Response<hyper::body::Incoming>, RequestError> {
    let (own, endpoints) = match TRANSPORT.get() {
        Some(t) => (
            req.uri()
                .authority()
                .is_some_and(|a| a.as_str() == t.settings.lwd_addr),
            t.endpoints.as_ref(),
        ),
        None => (false, None),
    };
    request_with(req, opts, own, if own { endpoints } else { None }).await
}

/// [`request`] with the transport given: `own` = a call to the gateway's own lightwalletd.
pub async fn request_with(
    req: Request<Full<Bytes>>,
    opts: CallOpts<'_>,
    own: bool,
    endpoints: Option<&EndpointSet>,
) -> Result<hyper::Response<hyper::body::Incoming>, RequestError> {
    let start = Instant::now();
    let path = req.uri().path();
    let retry_reads = own && is_idempotent(path);
    // Only a read whose head normally comes at once is cut at half its head deadline: the mempool
    // long poll sends its head with its first message, and an address query may legitimately
    // take most of its deadline. Both still get the retry after a transport error.
    let retry_on_timeout = retry_reads && !waits_for_its_head(path);
    let addrs = match endpoints {
        Some(set) => set.addrs().await,
        None => Vec::new(),
    };
    let pick = |avoid| endpoints.and_then(|set| set.pick(&addrs, avoid, Instant::now()));

    let first_addr = pick(None);
    let first_budget = if retry_on_timeout {
        opts.head / 2
    } else {
        opts.head
    };
    let client = if opts.pooled {
        crate::lwd::lwd_client()
    } else {
        fresh_client()
    };
    let first = attempt(&client, &req, first_addr, first_budget).await;
    let err = match first {
        Ok(resp) => {
            settle(endpoints, first_addr, true);
            if own {
                crate::health::record_lwd_call(opts.network, true);
            }
            return Ok(resp);
        }
        Err(e) => e,
    };
    settle(endpoints, first_addr, false);
    if matches!(err, RequestError::Timeout) {
        if let Some(class) = opts.class {
            crate::health::record_lwd_timeout(opts.network, class, "head");
        }
        crate::lwd::reset_pool(opts.network);
    }
    let connect = err.is_connect();
    let timed_out = matches!(err, RequestError::Timeout);
    let retry = connect || (retry_reads && (retry_on_timeout || !timed_out));
    let remaining = opts.head.saturating_sub(start.elapsed());
    if !retry || remaining.is_zero() {
        if own {
            crate::health::record_lwd_call(opts.network, false);
        }
        return Err(err);
    }

    let second_addr = pick(first_addr);
    if connect {
        tracing::warn!(error = %err, to = ?second_addr, "lightwalletd connect failed, retrying once");
        crate::health::record_lwd_connect_retry();
        tokio::time::sleep(CONNECT_RETRY_DELAY.min(remaining)).await;
    } else {
        tracing::warn!(error = %err, path = %req.uri().path(), to = ?second_addr, "lightwalletd read failed before its answer, retrying once");
        crate::health::record_lwd_read_retry(
            opts.network,
            if matches!(err, RequestError::Timeout) {
                "timeout"
            } else {
                "error"
            },
        );
    }
    // Always a new connection: a pooled one may be the one that hangs.
    let remaining = opts.head.saturating_sub(start.elapsed());
    let second = attempt(&fresh_client(), &req, second_addr, remaining).await;
    let ok = second.is_ok();
    settle(endpoints, second_addr, ok);
    if own {
        crate::health::record_lwd_call(opts.network, ok);
    }
    if let Err(RequestError::Timeout) = &second {
        if let Some(class) = opts.class {
            crate::health::record_lwd_timeout(opts.network, class, "head");
        }
    }
    second
}

fn settle(endpoints: Option<&EndpointSet>, addr: Option<SocketAddr>, ok: bool) {
    let (Some(set), Some(addr)) = (endpoints, addr) else {
        return;
    };
    if ok {
        set.mark_ok(addr);
    } else {
        tracing::warn!(addr = %addr, eject_secs = EJECT_FOR.as_secs(), "lightwalletd instance failed: skipped while another one answers");
        set.mark_failed(addr, Instant::now());
    }
}

/// One attempt: `req` (sent to `addr` instead of its authority when given) on `client`, bounded
/// by `budget`.
async fn attempt(
    client: &LwdClient,
    req: &Request<Full<Bytes>>,
    addr: Option<SocketAddr>,
    budget: Duration,
) -> Result<hyper::Response<hyper::body::Incoming>, RequestError> {
    let mut copy = Request::new(req.body().clone());
    *copy.method_mut() = req.method().clone();
    *copy.uri_mut() = match addr {
        Some(addr) => with_authority(req.uri(), addr),
        None => req.uri().clone(),
    };
    *copy.version_mut() = req.version();
    *copy.headers_mut() = req.headers().clone();
    match tokio::time::timeout(budget, client.request(copy)).await {
        Ok(Ok(resp)) => Ok(resp),
        Ok(Err(e)) => Err(RequestError::Http(e)),
        Err(_) => Err(RequestError::Timeout),
    }
}

/// `uri` with its authority replaced by `addr` (scheme and path kept).
fn with_authority(uri: &hyper::Uri, addr: SocketAddr) -> hyper::Uri {
    let mut parts = uri.clone().into_parts();
    match hyper::http::uri::Authority::try_from(addr.to_string().as_str()) {
        Ok(a) => parts.authority = Some(a),
        Err(_) => return uri.clone(),
    }
    hyper::Uri::from_parts(parts).unwrap_or_else(|_| uri.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const READ: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock";
    const WRITE: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/SendTransaction";

    fn opts(head_ms: u64) -> CallOpts<'static> {
        CallOpts {
            network: "test-endpoints",
            head: Duration::from_millis(head_ms),
            class: None,
            pooled: false,
        }
    }

    fn req(addr: &str, path: &str) -> Request<Full<Bytes>> {
        Request::builder()
            .method("POST")
            .uri(format!("http://{addr}{path}"))
            .header("content-type", "application/grpc")
            .body(Full::new(Bytes::from_static(&[0, 0, 0, 0, 0])))
            .unwrap()
    }

    /// An h2c server that answers every request with an empty gRPC OK and counts them.
    async fn answering() -> (SocketAddr, Arc<AtomicUsize>) {
        serve(false).await
    }

    /// An h2c server that accepts the connection and never answers (a hung process); counts
    /// the requests it received.
    async fn hanging() -> (SocketAddr, Arc<AtomicUsize>) {
        serve(true).await
    }

    async fn serve(hang: bool) -> (SocketAddr, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let seen = seen.clone();
                let service = hyper::service::service_fn(
                    move |_req: hyper::Request<hyper::body::Incoming>| {
                        let seen = seen.clone();
                        async move {
                            seen.fetch_add(1, Ordering::SeqCst);
                            if hang {
                                tokio::time::sleep(Duration::from_secs(60)).await;
                            }
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
                                    .status(200)
                                    .header("content-type", "application/grpc")
                                    .header("grpc-status", "0")
                                    .body(Full::new(Bytes::new()))
                                    .unwrap(),
                            )
                        }
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
        (addr, count)
    }

    /// An address that refuses connections (a port nothing listens on).
    async fn refusing() -> SocketAddr {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        drop(l);
        a
    }

    #[test]
    fn only_compact_tx_streamer_reads_are_idempotent() {
        assert!(is_idempotent(READ));
        assert!(is_idempotent(
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlockRange"
        ));
        assert!(!is_idempotent(WRITE));
        assert!(!is_idempotent("/cash.z.wallet.sdk.rpc.CompactTxStreamer/"));
        assert!(!is_idempotent("/other.Service/GetLatestBlock"));
        assert!(!is_idempotent("/api/v1/quote"));
    }

    #[test]
    fn settings_parse() {
        let s = Settings::parse("lwd:9067", None, None).unwrap();
        assert_eq!(s.endpoints, None);
        assert_eq!(s.connect_timeout, DEFAULT_CONNECT_TIMEOUT);
        let s = Settings::parse("lwd:9067", Some(" lwd-instances:9067 "), Some("500")).unwrap();
        assert_eq!(s.endpoints.as_deref(), Some("lwd-instances:9067"));
        assert_eq!(s.connect_timeout, Duration::from_millis(500));
        assert!(Settings::parse("lwd:9067", Some("lwd-instances"), None).is_err());
        assert!(Settings::parse("lwd:9067", Some(":9067"), None).is_err());
        assert!(Settings::parse("lwd:9067", Some("http://a:1"), None).is_err());
        assert!(Settings::parse("lwd:9067", None, Some("0")).is_err());
        assert!(Settings::parse("lwd:9067", None, Some("x")).is_err());
    }

    #[test]
    fn pick_skips_failed_and_avoided_addresses() {
        let a: SocketAddr = "192.0.2.1:9067".parse().unwrap();
        let b: SocketAddr = "192.0.2.2:9067".parse().unwrap();
        let c: SocketAddr = "192.0.2.3:9067".parse().unwrap();
        let set = EndpointSet::fixed(vec![a, b, c]);
        let now = Instant::now();
        set.mark_failed(a, now);
        for _ in 0..50 {
            let p = set.pick(&[a, b, c], Some(b), now).unwrap();
            assert_eq!(p, c, "a failed recently, b is avoided");
        }
        // Every other address failed: still one of them (never the avoided one).
        set.mark_failed(c, now);
        for _ in 0..50 {
            let p = set.pick(&[a, b, c], Some(b), now).unwrap();
            assert!(p == a || p == c);
        }
        // After EJECT_FOR a failed address is a candidate again; a success clears it at once.
        set.mark_ok(c);
        let later = now + EJECT_FOR;
        let mut seen_a = false;
        for _ in 0..200 {
            seen_a |= set.pick(&[a, b, c], Some(b), later).unwrap() == a;
        }
        assert!(seen_a);
        // One address: the avoided one is all there is; none at all: None.
        assert_eq!(set.pick(&[a], Some(a), now), Some(a));
        assert_eq!(set.pick(&[], None, now), None);
    }

    #[tokio::test]
    async fn read_moves_to_another_instance_when_the_first_hangs() {
        let (hung, hung_count) = hanging().await;
        let (good, good_count) = answering().await;
        let set = EndpointSet::fixed(vec![hung, good]);
        // Make sure the first pick is the hung instance.
        set.mark_failed(good, Instant::now());
        let start = Instant::now();
        let resp = request_with(req("lwd:9067", READ), opts(2000), true, Some(&set))
            .await
            .expect("the retry on the other instance answers");
        assert_eq!(resp.status(), 200);
        let took = start.elapsed();
        assert!(
            took >= Duration::from_millis(900) && took < Duration::from_millis(1900),
            "first attempt bounded by half the head deadline, took {took:?}"
        );
        assert_eq!(hung_count.load(Ordering::SeqCst), 1);
        assert_eq!(good_count.load(Ordering::SeqCst), 1);
        // The hung instance is now skipped: the next read goes to the answering one directly.
        let start = Instant::now();
        request_with(req("lwd:9067", READ), opts(2000), true, Some(&set))
            .await
            .unwrap();
        assert!(start.elapsed() < Duration::from_millis(500));
        assert_eq!(hung_count.load(Ordering::SeqCst), 1);
        assert_eq!(good_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn send_transaction_is_never_sent_twice() {
        let (hung, hung_count) = hanging().await;
        let (good, good_count) = answering().await;
        let set = EndpointSet::fixed(vec![hung, good]);
        set.mark_failed(good, Instant::now());
        let start = Instant::now();
        let r = request_with(req("lwd:9067", WRITE), opts(1000), true, Some(&set)).await;
        assert!(matches!(r, Err(RequestError::Timeout)));
        assert!(
            start.elapsed() >= Duration::from_millis(900),
            "a WRITE keeps the whole head deadline"
        );
        assert_eq!(hung_count.load(Ordering::SeqCst), 1);
        assert_eq!(good_count.load(Ordering::SeqCst), 0, "no second send");
    }

    #[tokio::test]
    async fn connect_error_moves_any_call_to_another_instance() {
        let dead = refusing().await;
        let (good, good_count) = answering().await;
        let set = EndpointSet::fixed(vec![dead, good]);
        set.mark_failed(good, Instant::now());
        let resp = request_with(req("lwd:9067", WRITE), opts(2000), true, Some(&set))
            .await
            .expect("nothing reached the refusing address: the WRITE may go to the other one");
        assert_eq!(resp.status(), 200);
        assert_eq!(good_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn without_instances_a_read_is_retried_on_a_new_connection() {
        // Only the authority: the retry is a new connection to the same address (here the hung
        // server again), still bounded by the head deadline as a whole.
        let (hung, hung_count) = hanging().await;
        let start = Instant::now();
        let r = request_with(req(&hung.to_string(), READ), opts(1000), true, None).await;
        assert!(matches!(r, Err(RequestError::Timeout)));
        let took = start.elapsed();
        assert!(took < Duration::from_millis(1500), "took {took:?}");
        assert_eq!(hung_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn slow_head_reads_keep_their_whole_deadline() {
        let (hung, hung_count) = hanging().await;
        let (good, good_count) = answering().await;
        let set = EndpointSet::fixed(vec![hung, good]);
        set.mark_failed(good, Instant::now());
        let path = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTaddressBalance";
        let start = Instant::now();
        let r = request_with(req("lwd:9067", path), opts(1000), true, Some(&set)).await;
        assert!(matches!(r, Err(RequestError::Timeout)));
        assert!(start.elapsed() >= Duration::from_millis(900));
        assert_eq!(hung_count.load(Ordering::SeqCst), 1);
        assert_eq!(good_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn other_backends_are_not_retried_after_a_timeout() {
        let (hung, hung_count) = hanging().await;
        let r = request_with(req(&hung.to_string(), READ), opts(500), false, None).await;
        assert!(matches!(r, Err(RequestError::Timeout)));
        assert_eq!(hung_count.load(Ordering::SeqCst), 1);
    }
}

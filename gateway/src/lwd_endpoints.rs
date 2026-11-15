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
//! - **One deadline**: the call's head deadline is fixed before the instance list is resolved and
//!   covers the resolution and every attempt, so a slow resolution never extends it.
//! - **One retry**:
//!   - after a connect error, for every call (no byte of the request reached lightwalletd, so
//!     nothing can run twice, `SendTransaction` included);
//!   - for an idempotent call (every `CompactTxStreamer` RPC except `SendTransaction`) also after
//!     a transport error. A `SendTransaction` is never sent twice by the gateway.
//! - **Hedged reads**: an idempotent read whose response head has not arrived after the hedge
//!   delay (`LWD_HEDGE_DELAY_MS`, default half of the head deadline) is sent a second time to a
//!   *different* instance of `LWD_ENDPOINTS` (none: no hedge), while the first attempt keeps
//!   running. The first head wins and the other attempt is cancelled; both share the call's
//!   whole head deadline, so a read that is merely slow is no longer cut at half of it. The
//!   loser is not a failure (not a timeout, not a failed call, no pool replacement); an
//!   attempt that fails is settled as failed even when the other one then answers. An instance
//!   that loses two hedges in a row, without a response head from it in between, is skipped for
//!   [`EJECT_FOR`] at that and each further loss (`event="loser_skipped"`), so one that accepts
//!   calls and never answers leaves the rotation. Never hedged:
//!   `SendTransaction` and any path that is not a `CompactTxStreamer` read, heavy calls
//!   (`enforcement::is_heavy_lwd_call`: long block ranges, transactions, transparent-address
//!   and subtree queries), `GetMempoolStream` and the transparent-address RPCs, and calls to
//!   other backends. Two bounds: a hedge takes a permit of its own (`LWD_HEDGE_MAX_INFLIGHT`,
//!   default an eighth of `MAX_INFLIGHT_LWD`, at most 16), taken when the hedge is sent and
//!   held until the race ends (also while the first attempt still runs after the hedge
//!   failed; a read that is not hedged holds none), and the rate cap ([`HedgeRate`]): six
//!   hedges a minute are always allowed, above that hedges stay at most one in ten of the
//!   hedgeable reads of the last minute. Hedges are
//!   not counted in `MAX_INFLIGHT_LWD` (the caller's permit covers the first attempt only), so
//!   hedging adds at most `LWD_HEDGE_MAX_INFLIGHT` concurrent lightwalletd calls, and 10 % more
//!   calls plus at most six a minute. Counted in `ohttp_lwd_hedges_total`.
//!
//!   Every attempt cut by the call's deadline counts in `ohttp_lwd_timeouts_total`, also when
//!   another attempt answers.
//!
//!   The retry goes to another instance when `LWD_ENDPOINTS` has one, always on a new connection.
//!   Only the phase up to the response head is retried: a call that fails after its head arrived
//!   is not (part of the answer may already be on its way to the client).
//! - **Outcome** of every call to the own lightwalletd (after the retry) goes to the `/healthz`
//!   error window (`health::record_lwd_call`). For the reads whose head may take long
//!   (`GetMempoolStream`, the transparent-address RPCs) only connect and transport errors count
//!   there and eject an instance: a head that is merely late is not a lightwalletd failure.

use axum::body::Bytes;
use http_body_util::Full;
use hyper::Request;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

type LwdClient = Client<HttpConnector, Full<Bytes>>;

/// How often the instance addresses of `LWD_ENDPOINTS` are resolved again.
pub const RESOLVE_EVERY: Duration = Duration::from_secs(5);
/// How long an address whose attempt failed is skipped while another one is available.
pub const EJECT_FOR: Duration = Duration::from_secs(30);
/// Longest wait of a call for the first resolution of `LWD_ENDPOINTS`.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(1);
/// A resolution still running after this is abandoned (the next one may start).
const REFRESH_TIMEOUT: Duration = Duration::from_secs(30);
/// Pause before the retry after a connect error.
const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(50);

pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_millis(2000);
/// Hedges in flight per process at most (`LWD_HEDGE_MAX_INFLIGHT`).
pub const DEFAULT_HEDGE_MAX_INFLIGHT: usize = 16;

/// When a read is hedged (`LWD_HEDGE_DELAY_MS`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HedgeDelay {
    /// Half of the call's head deadline (the default: the time the first attempt used to be cut).
    Half,
    /// A fixed delay (at most the head deadline).
    Fixed(Duration),
    /// No hedging (`LWD_HEDGE_DELAY_MS=0`).
    Off,
}

impl HedgeDelay {
    /// The delay for a call with head deadline `head`; None = no hedge.
    pub fn for_head(self, head: Duration) -> Option<Duration> {
        match self {
            HedgeDelay::Half => Some(head / 2),
            HedgeDelay::Fixed(d) => Some(d.min(head)),
            HedgeDelay::Off => None,
        }
    }
}

/// `LWD_ADDR`, `LWD_ENDPOINTS`, `LWD_CONNECT_TIMEOUT_MS`, `LWD_HEDGE_DELAY_MS` and
/// `LWD_HEDGE_MAX_INFLIGHT`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// `LWD_ADDR`: requests to this authority are the gateway's own lightwalletd calls.
    pub lwd_addr: String,
    /// `LWD_ENDPOINTS`: `host:port` resolving to one address per instance.
    pub endpoints: Option<String>,
    pub connect_timeout: Duration,
    pub hedge_delay: HedgeDelay,
    pub hedge_max_inflight: usize,
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
            hedge_delay: HedgeDelay::Half,
            hedge_max_inflight: DEFAULT_HEDGE_MAX_INFLIGHT,
        })
    }

    /// `LWD_HEDGE_DELAY_MS` (unset: half of the head deadline; `0`: off) and
    /// `LWD_HEDGE_MAX_INFLIGHT` (unset: [`default_hedge_max_inflight`] of `max_inflight_lwd`,
    /// the `MAX_INFLIGHT_LWD` permits; at least 1, at most `Semaphore::MAX_PERMITS`).
    pub fn with_hedging(
        mut self,
        delay_ms: Option<&str>,
        max_inflight: Option<&str>,
        max_inflight_lwd: usize,
    ) -> anyhow::Result<Self> {
        self.hedge_delay = match delay_ms.map(str::trim).filter(|v| !v.is_empty()) {
            None => HedgeDelay::Half,
            Some(v) => match v.parse::<u64>() {
                Ok(0) => HedgeDelay::Off,
                Ok(n) => HedgeDelay::Fixed(Duration::from_millis(n)),
                Err(_) => {
                    anyhow::bail!("LWD_HEDGE_DELAY_MS must be a non-negative integer, got '{v}'")
                }
            },
        };
        self.hedge_max_inflight = match max_inflight.map(str::trim).filter(|v| !v.is_empty()) {
            None => default_hedge_max_inflight(max_inflight_lwd),
            Some(v) => match v.parse::<usize>() {
                Ok(n) if n > 0 && n <= tokio::sync::Semaphore::MAX_PERMITS => n,
                _ => anyhow::bail!(
                    "LWD_HEDGE_MAX_INFLIGHT must be an integer from 1 to {}, got '{v}'",
                    tokio::sync::Semaphore::MAX_PERMITS
                ),
            },
        };
        Ok(self)
    }

    pub fn from_env(lwd_addr: &str) -> anyhow::Result<Self> {
        // The same value and default as `Config::max_inflight_lwd`.
        let max_inflight_lwd = std::env::var("MAX_INFLIGHT_LWD")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(128);
        Self::parse(
            lwd_addr,
            std::env::var("LWD_ENDPOINTS").ok().as_deref(),
            std::env::var("LWD_CONNECT_TIMEOUT_MS").ok().as_deref(),
        )?
        .with_hedging(
            std::env::var("LWD_HEDGE_DELAY_MS").ok().as_deref(),
            std::env::var("LWD_HEDGE_MAX_INFLIGHT").ok().as_deref(),
            max_inflight_lwd,
        )
    }
}

/// The default of `LWD_HEDGE_MAX_INFLIGHT`: an eighth of the lightwalletd permits
/// (`MAX_INFLIGHT_LWD`), at most [`DEFAULT_HEDGE_MAX_INFLIGHT`], at least 1.
pub fn default_hedge_max_inflight(max_inflight_lwd: usize) -> usize {
    (max_inflight_lwd / 8).clamp(1, DEFAULT_HEDGE_MAX_INFLIGHT)
}

struct Transport {
    settings: Settings,
    endpoints: Option<EndpointSet>,
    hedging: Hedging,
}

static TRANSPORT: OnceLock<Transport> = OnceLock::new();

/// Set once at startup (main); later calls are ignored. Without it (tests) no request counts as
/// a call to the own lightwalletd: no instance choice, no read retry, no `/healthz` outcome.
pub fn init(settings: Settings) {
    let endpoints = settings.endpoints.clone().map(EndpointSet::new);
    let hedging = Hedging::new(settings.hedge_delay, settings.hedge_max_inflight);
    let _ = TRANSPORT.set(Transport {
        settings,
        endpoints,
        hedging,
    });
}

/// Hedges at most this share of the hedgeable reads of the last [`HEDGE_RATE_WINDOW`]
/// (one in ten).
pub const HEDGE_RATE_DIVISOR: u64 = 10;
/// The window of [`HEDGE_RATE_DIVISOR`] and [`HEDGE_RATE_FLOOR`].
pub const HEDGE_RATE_WINDOW: Duration = Duration::from_secs(60);
/// Hedges allowed per [`HEDGE_RATE_WINDOW`] whatever the number of reads: with few reads the
/// one-in-ten rule alone allowed none, and a read on an instance that hangs then failed at its
/// whole deadline. Six a minute also find such an instance again after each time it was
/// skipped (two lost hedges, see [`LOST_HEDGES_TO_SKIP`]).
pub const HEDGE_RATE_FLOOR: u64 = 6;
/// Consecutive hedges an instance must lose (the hedge's head came while its own attempt still
/// had none) before each further loss makes it skipped for [`EJECT_FOR`].
pub const LOST_HEDGES_TO_SKIP: u32 = 2;

/// The rate cap of hedges: hedgeable reads and hedges sent, per second of the last
/// [`HEDGE_RATE_WINDOW`]. Up to [`HEDGE_RATE_FLOOR`] hedges per window are always allowed; above
/// that a hedge is sent only while hedges stay at most one in [`HEDGE_RATE_DIVISOR`] of the
/// reads in the window. A slow lightwalletd (every read past the hedge delay) thus costs at
/// most 10 % more calls, plus at most six a minute.
pub struct HedgeRate {
    epoch: Instant,
    buckets: parking_lot::Mutex<std::collections::VecDeque<(u64, u64, u64)>>,
}

impl Default for HedgeRate {
    fn default() -> Self {
        Self {
            epoch: Instant::now(),
            buckets: Default::default(),
        }
    }
}

impl HedgeRate {
    fn bucket(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.epoch).as_secs()
    }

    fn current<'a>(
        buckets: &'a mut std::collections::VecDeque<(u64, u64, u64)>,
        sec: u64,
    ) -> &'a mut (u64, u64, u64) {
        let window = HEDGE_RATE_WINDOW.as_secs();
        while buckets.front().is_some_and(|(s, _, _)| s + window <= sec) {
            buckets.pop_front();
        }
        if buckets.back().is_none_or(|(s, _, _)| *s != sec) {
            buckets.push_back((sec, 0, 0));
        }
        buckets.back_mut().expect("just pushed")
    }

    /// A hedgeable read started at `now`.
    pub fn record_read(&self, now: Instant) {
        let sec = self.bucket(now);
        Self::current(&mut self.buckets.lock(), sec).1 += 1;
    }

    /// Whether a hedge may be sent at `now`; counts it when it may.
    pub fn try_hedge(&self, now: Instant) -> bool {
        let sec = self.bucket(now);
        let mut buckets = self.buckets.lock();
        Self::current(&mut buckets, sec);
        let (reads, hedges) = buckets
            .iter()
            .fold((0, 0), |(r, h), (_, br, bh)| (r + br, h + bh));
        if hedges >= HEDGE_RATE_FLOOR && (hedges + 1) * HEDGE_RATE_DIVISOR > reads {
            return false;
        }
        Self::current(&mut buckets, sec).2 += 1;
        true
    }
}

/// How [`request_with`] hedges: the delay, the permits of hedges in flight and the rate cap.
#[derive(Clone)]
pub struct Hedging {
    pub delay: HedgeDelay,
    pub permits: Arc<tokio::sync::Semaphore>,
    pub rate: Arc<HedgeRate>,
}

impl Hedging {
    pub fn new(delay: HedgeDelay, max_inflight: usize) -> Self {
        Self {
            delay,
            permits: Arc::new(tokio::sync::Semaphore::new(
                max_inflight.clamp(1, tokio::sync::Semaphore::MAX_PERMITS),
            )),
            rate: Arc::new(HedgeRate::default()),
        }
    }
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
    state: Arc<parking_lot::Mutex<EndpointState>>,
    /// Woken when a resolution ends.
    resolved: Arc<tokio::sync::Notify>,
    /// Resolutions started (for tests).
    resolutions: Arc<std::sync::atomic::AtomicUsize>,
}

#[derive(Default)]
struct EndpointState {
    addrs: Vec<SocketAddr>,
    resolved_at: Option<Instant>,
    failed: HashMap<SocketAddr, Instant>,
    /// Consecutive hedges each address lost (see [`EndpointSet::hedge_lost`]).
    lost_hedges: HashMap<SocketAddr, u32>,
    /// A resolution is running (at most one at a time).
    refreshing: bool,
}

impl EndpointSet {
    pub fn new(name: String) -> Self {
        Self {
            name,
            state: Default::default(),
            resolved: Default::default(),
            resolutions: Default::default(),
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
        self.addrs_until(Instant::now() + RESOLVE_TIMEOUT).await
    }

    /// [`Self::addrs`], waiting until `deadline` at most. One resolution runs at a time, in a
    /// task of its own: once the list is older than [`RESOLVE_EVERY`] the first caller starts
    /// it, and every caller (that one included) gets the previous list at once meanwhile. Only
    /// while there is no list yet (the first resolution) does a caller wait for it, at most
    /// [`RESOLVE_TIMEOUT`] and never past `deadline`; it then gets an empty list (the call goes
    /// to `LWD_ADDR`) if the resolution has not ended.
    pub async fn addrs_until(&self, deadline: Instant) -> Vec<SocketAddr> {
        let resolved = self.resolved.notified();
        {
            let mut s = self.state.lock();
            if s.resolved_at.is_some_and(|t| t.elapsed() < RESOLVE_EVERY) || self.name.is_empty() {
                return s.addrs.clone();
            }
            if !s.refreshing {
                s.refreshing = true;
                self.spawn_refresh();
            }
            if !s.addrs.is_empty() {
                return s.addrs.clone();
            }
        }
        let wait = deadline
            .min(Instant::now() + RESOLVE_TIMEOUT)
            .saturating_duration_since(Instant::now());
        let _ = tokio::time::timeout(wait, resolved).await;
        self.state.lock().addrs.clone()
    }

    /// Resolve the name in a task of its own and store the result. One runs at a time; it is
    /// abandoned after [`REFRESH_TIMEOUT`] (the flag is cleared, the previous list kept), so a
    /// resolver that hangs delays the next resolution by that much at most.
    fn spawn_refresh(&self) {
        let name = self.name.clone();
        let state = self.state.clone();
        let resolved = self.resolved.clone();
        self.resolutions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tokio::spawn(async move {
            let started = Instant::now();
            let found =
                tokio::time::timeout(REFRESH_TIMEOUT, tokio::net::lookup_host(name.as_str())).await;
            if started.elapsed() > RESOLVE_TIMEOUT {
                tracing::debug!(name = %name, "LWD_ENDPOINTS resolution was slow");
                tracing::warn!(
                    took_ms = started.elapsed().as_millis() as u64,
                    "LWD_ENDPOINTS resolution was slow; the previous list was used meanwhile"
                );
            }
            {
                let mut s = state.lock();
                s.resolved_at = Some(Instant::now());
                s.refreshing = false;
                match found {
                    Ok(Ok(found)) => {
                        let mut found: Vec<SocketAddr> = found.collect();
                        found.sort();
                        found.dedup();
                        if found.is_empty() {
                            tracing::debug!(name = %name, "LWD_ENDPOINTS resolved to no address");
                            tracing::warn!(
                                "LWD_ENDPOINTS resolved to no address; keeping the previous list"
                            );
                        } else {
                            s.failed.retain(|a, _| found.contains(a));
                            s.lost_hedges.retain(|a, _| found.contains(a));
                            s.addrs = found;
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::debug!(name = %name, error = %e, "LWD_ENDPOINTS did not resolve");
                        tracing::warn!("LWD_ENDPOINTS did not resolve; keeping the previous list")
                    }
                    Err(_) => {
                        tracing::debug!(name = %name, "LWD_ENDPOINTS resolution abandoned");
                        tracing::warn!(timeout_secs = REFRESH_TIMEOUT.as_secs(), "LWD_ENDPOINTS resolution did not end in time; keeping the previous list")
                    }
                }
            }
            resolved.notify_waiters();
        });
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

    /// An address of `addrs` other than `avoid`, as [`Self::pick`], or None when there is no other
    /// one (a hedge only goes to a different instance).
    pub fn pick_other(
        &self,
        addrs: &[SocketAddr],
        avoid: Option<SocketAddr>,
        now: Instant,
    ) -> Option<SocketAddr> {
        self.pick(addrs, avoid, now).filter(|a| Some(*a) != avoid)
    }

    pub fn mark_failed(&self, addr: SocketAddr, now: Instant) {
        self.state.lock().failed.insert(addr, now);
    }

    /// A response head came from `addr`: it is a candidate again, and its lost hedges are
    /// forgotten.
    pub fn mark_ok(&self, addr: SocketAddr) {
        let mut s = self.state.lock();
        s.failed.remove(&addr);
        s.lost_hedges.remove(&addr);
    }

    /// `addr` lost a hedge: the hedge's head came while its own attempt still had none. One
    /// loss means little (it was only slower once). From the [`LOST_HEDGES_TO_SKIP`]th loss in
    /// a row on, each one makes the address skipped for [`EJECT_FOR`] (as a failed one is: still
    /// used when every other address is skipped too); true then. The count is reset by a head
    /// from the address ([`Self::mark_ok`]), not by the skip, so an instance that accepts calls
    /// and never answers is skipped again at its first loss after each skip ends. Without this
    /// it stayed in rotation and took its share of the reads, of which the rate cap leaves
    /// most without a hedge.
    pub fn hedge_lost(&self, addr: SocketAddr, now: Instant) -> bool {
        let mut s = self.state.lock();
        let lost = s.lost_hedges.entry(addr).or_insert(0);
        *lost = lost.saturating_add(1);
        if *lost < LOST_HEDGES_TO_SKIP {
            return false;
        }
        s.failed.insert(addr, now);
        true
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
    /// The call may be hedged (a read that is not a heavy call, see
    /// `enforcement::is_heavy_lwd_call`; the other conditions are checked here).
    pub may_hedge: bool,
}

/// Send `req` and return its response head, with the instance choice, the hedge and the one
/// retry described in the module documentation.
pub async fn request(
    req: Request<Full<Bytes>>,
    opts: CallOpts<'_>,
) -> Result<hyper::Response<hyper::body::Incoming>, RequestError> {
    let (own, endpoints, hedging) = match TRANSPORT.get() {
        Some(t) => (
            req.uri()
                .authority()
                .is_some_and(|a| a.as_str() == t.settings.lwd_addr),
            t.endpoints.as_ref(),
            Some(t.hedging.clone()),
        ),
        None => (false, None, None),
    };
    request_with(
        req,
        opts,
        own,
        if own { endpoints } else { None },
        hedging.as_ref(),
    )
    .await
}

/// One attempt's result, the instance it went to, whether a hedge was sent (the call's
/// second send: no retry after it), and whether a failure was already settled and counted.
type Attempted = (
    Result<hyper::Response<hyper::body::Incoming>, RequestError>,
    Option<SocketAddr>,
    bool,
    bool,
);

/// [`request`] with the transport given: `own` = a call to the gateway's own lightwalletd;
/// `hedging` None = no hedged reads.
pub async fn request_with(
    req: Request<Full<Bytes>>,
    opts: CallOpts<'_>,
    own: bool,
    endpoints: Option<&EndpointSet>,
    hedging: Option<&Hedging>,
) -> Result<hyper::Response<hyper::body::Incoming>, RequestError> {
    // One absolute deadline, fixed before the instances are resolved: resolution and every
    // attempt share it.
    let start = Instant::now();
    let deadline = start + opts.head;
    let path = req.uri().path().to_string();
    let retry_reads = own && is_idempotent(&path);
    // The mempool long poll sends its head with its first message, and an address query may
    // legitimately take most of its deadline: no hedge, and a late head is not a failure of
    // the instance. Both still get the retry after a transport error.
    let slow_head = waits_for_its_head(&path);
    let addrs = match endpoints {
        Some(set) => set.addrs_until(deadline).await,
        None => Vec::new(),
    };
    let pick = |avoid| endpoints.and_then(|set| set.pick(&addrs, avoid, Instant::now()));

    let first_addr = pick(None);
    let client = if opts.pooled {
        crate::lwd::lwd_client()
    } else {
        fresh_client()
    };
    let first = attempt(&client, &req, first_addr, deadline);
    let hedge = match (hedging, endpoints) {
        (Some(h), Some(set)) if retry_reads && !slow_head && opts.may_hedge => h
            .delay
            .for_head(opts.head)
            .filter(|d| *d < opts.head)
            .map(|d| (start + d, h, set)),
        _ => None,
    };
    let (result, addr, hedge_sent, accounted) = match hedge {
        None => (first.await, first_addr, false, false),
        Some((at, h, set)) => {
            h.rate.record_read(start);
            hedged(first, first_addr, at, h, set, &addrs, &req, deadline, opts).await
        }
    };
    let err = match result {
        Ok(resp) => {
            settle(endpoints, addr, true);
            if own {
                crate::health::record_lwd_call(opts.network, true);
            }
            return Ok(resp);
        }
        Err(e) => e,
    };
    let timed_out = matches!(err, RequestError::Timeout);
    // A late head of a slow-head read is not a failure of the instance (C10).
    let instance_failed = !(timed_out && slow_head);
    if instance_failed && !accounted {
        settle(endpoints, addr, false);
    }
    if timed_out && !accounted {
        if let Some(class) = opts.class {
            crate::health::record_lwd_timeout(opts.network, class, "head");
        }
        if !slow_head {
            crate::lwd::reset_pool(opts.network);
        }
    }
    let connect = err.is_connect();
    let retry = !hedge_sent && (connect || (retry_reads && !timed_out));
    let remaining = deadline.saturating_duration_since(Instant::now());
    if !retry || remaining.is_zero() {
        if own && instance_failed {
            crate::health::record_lwd_call(opts.network, false);
        }
        return Err(err);
    }

    let second_addr = pick(addr);
    if connect {
        tracing::debug!(to = ?second_addr, "lightwalletd connect retry");
        tracing::warn!(error = %err, "lightwalletd connect failed, retrying once");
        crate::health::record_lwd_connect_retry();
        tokio::time::sleep(CONNECT_RETRY_DELAY.min(remaining)).await;
    } else {
        tracing::debug!(to = ?second_addr, "lightwalletd read retry");
        tracing::warn!(error = %err, path = %req.uri().path(), "lightwalletd read failed before its answer, retrying once");
        crate::health::record_lwd_read_retry(opts.network, "error");
    }
    // Always a new connection: a pooled one may be the one that hangs.
    let second = attempt(&fresh_client(), &req, second_addr, deadline).await;
    let ok = second.is_ok();
    let timed_out = matches!(second, Err(RequestError::Timeout));
    let instance_failed = !ok && !(timed_out && slow_head);
    if ok || instance_failed {
        settle(endpoints, second_addr, ok);
        if own {
            crate::health::record_lwd_call(opts.network, ok);
        }
    }
    if timed_out {
        if let Some(class) = opts.class {
            crate::health::record_lwd_timeout(opts.network, class, "head");
        }
    }
    second
}

/// Race `first` against a hedge to a different instance started at `hedge_at` (when the first
/// has no head by then, another instance exists, a hedge permit is free and the rate cap allows
/// one). The first head wins; the other attempt is cancelled (dropped). The loser of the race
/// is not a failure: it is not counted as a timeout or as a failed call, and does not count
/// towards replacing the pool (it was only slower); an instance that loses hedges in a row is
/// skipped for a while ([`EndpointSet::hedge_lost`]). An attempt that fails while the other still runs is
/// settled as failed at once (its instance is skipped), and the other one is awaited; when both
/// fail, the first attempt's error is returned for the caller to settle and count.
#[allow(clippy::too_many_arguments)]
async fn hedged<F>(
    first: F,
    first_addr: Option<SocketAddr>,
    hedge_at: Instant,
    hedging: &Hedging,
    set: &EndpointSet,
    addrs: &[SocketAddr],
    req: &Request<Full<Bytes>>,
    deadline: Instant,
    opts: CallOpts<'_>,
) -> Attempted
where
    F: std::future::Future<Output = Result<hyper::Response<hyper::body::Incoming>, RequestError>>,
{
    let mut first = std::pin::pin!(first);
    tokio::select! {
        r = &mut first => return (r, first_addr, false, false),
        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(hedge_at)) => {}
    }
    let Some(second_addr) = set.pick_other(addrs, first_addr, Instant::now()) else {
        return (first.await, first_addr, false, false);
    };
    let Ok(permit) = hedging.permits.clone().try_acquire_owned() else {
        crate::health::record_lwd_hedge(opts.network, "no_permit");
        return (first.await, first_addr, false, false);
    };
    if !hedging.rate.try_hedge(Instant::now()) {
        crate::health::record_lwd_hedge(opts.network, "rate_limited");
        // Not hedged: the permit goes back before the wait for the first attempt, which may
        // last until the deadline.
        drop(permit);
        return (first.await, first_addr, false, false);
    }
    // Held until the race ends (this function returns), also while the first attempt still
    // runs after the hedge failed.
    let _permit = permit;
    crate::health::record_lwd_hedge(opts.network, "started");
    tracing::debug!(path = %req.uri().path(), to = %second_addr, "lightwalletd read without a head yet: hedged on another instance");
    let client = fresh_client();
    let mut second = std::pin::pin!(attempt(&client, req, Some(second_addr), deadline));
    let mut first_err: Option<RequestError> = None;
    let mut second_failed = false;
    loop {
        tokio::select! {
            r = &mut first, if first_err.is_none() => match r {
                Ok(resp) => return (Ok(resp), first_addr, true, false),
                Err(e) => {
                    if second_failed {
                        return (Err(e), first_addr, true, false);
                    }
                    // Settled now: the hedge may still answer for the call.
                    settle(Some(set), first_addr, false);
                    if matches!(e, RequestError::Timeout) {
                        if let Some(class) = opts.class {
                            crate::health::record_lwd_timeout(opts.network, class, "head");
                        }
                    }
                    first_err = Some(e);
                }
            },
            r = &mut second, if !second_failed => match r {
                Ok(resp) => {
                    crate::health::record_lwd_hedge(opts.network, "won");
                    // The first attempt still has no head: its instance lost this hedge. Not a
                    // failure of lightwalletd (no timeout, no /healthz outcome, no pool
                    // replacement); only an instance that keeps losing is skipped for a while.
                    if let (None, Some(lost)) = (&first_err, first_addr) {
                        if set.hedge_lost(lost, Instant::now()) {
                            crate::health::record_lwd_hedge(opts.network, "loser_skipped");
                            tracing::debug!(addr = %lost, "lightwalletd instance keeps losing hedges: skipped");
                        }
                    }
                    return (Ok(resp), Some(second_addr), true, false);
                }
                Err(e) => {
                    settle(Some(set), Some(second_addr), false);
                    if matches!(e, RequestError::Timeout) {
                        if let Some(class) = opts.class {
                            crate::health::record_lwd_timeout(opts.network, class, "head");
                        }
                    }
                    if let Some(first) = first_err.take() {
                        // Both failed; the first was settled and counted above.
                        return (Err(first), first_addr, true, true);
                    }
                    second_failed = true;
                }
            },
        }
    }
}

fn settle(endpoints: Option<&EndpointSet>, addr: Option<SocketAddr>, ok: bool) {
    let (Some(set), Some(addr)) = (endpoints, addr) else {
        return;
    };
    if ok {
        set.mark_ok(addr);
    } else {
        tracing::debug!(addr = %addr, "lightwalletd instance failed");
        tracing::warn!(
            eject_secs = EJECT_FOR.as_secs(),
            "lightwalletd instance failed: skipped while another one answers"
        );
        set.mark_failed(addr, Instant::now());
    }
}

/// One attempt: `req` (sent to `addr` instead of its authority when given) on `client`, until
/// `deadline`.
async fn attempt(
    client: &LwdClient,
    req: &Request<Full<Bytes>>,
    addr: Option<SocketAddr>,
    deadline: Instant,
) -> Result<hyper::Response<hyper::body::Incoming>, RequestError> {
    let mut copy = Request::new(req.body().clone());
    *copy.method_mut() = req.method().clone();
    *copy.uri_mut() = match addr {
        Some(addr) => with_authority(req.uri(), addr),
        None => req.uri().clone(),
    };
    *copy.version_mut() = req.version();
    *copy.headers_mut() = req.headers().clone();
    let deadline = tokio::time::Instant::from_std(deadline);
    match tokio::time::timeout_at(deadline, client.request(copy)).await {
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
        opts_on("test-endpoints", head_ms)
    }

    fn opts_on(network: &'static str, head_ms: u64) -> CallOpts<'static> {
        CallOpts {
            network,
            head: Duration::from_millis(head_ms),
            class: None,
            pooled: false,
            may_hedge: true,
        }
    }

    /// The default hedging (half of the head deadline), with enough recent reads that the rate
    /// cap allows hedges.
    fn hedging() -> Hedging {
        warm(Hedging::new(HedgeDelay::Half, DEFAULT_HEDGE_MAX_INFLIGHT))
    }

    fn warm(h: Hedging) -> Hedging {
        for _ in 0..100 {
            h.rate.record_read(Instant::now());
        }
        h
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
        serve(None).await
    }

    /// An h2c server that accepts the connection and never answers (a hung process); counts
    /// the requests it received.
    async fn hanging() -> (SocketAddr, Arc<AtomicUsize>) {
        serve(Some(Duration::from_secs(60))).await
    }

    /// An h2c server that answers every request after `delay` (a slow but working instance).
    async fn slow(delay: Duration) -> (SocketAddr, Arc<AtomicUsize>) {
        serve(Some(delay)).await
    }

    async fn serve(delay: Option<Duration>) -> (SocketAddr, Arc<AtomicUsize>) {
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
                            if let Some(delay) = delay {
                                tokio::time::sleep(delay).await;
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
        let resp = request_with(
            req("lwd:9067", READ),
            opts(2000),
            true,
            Some(&set),
            Some(&hedging()),
        )
        .await
        .expect("the retry on the other instance answers");
        assert_eq!(resp.status(), 200);
        let took = start.elapsed();
        assert!(
            took >= Duration::from_millis(900) && took < Duration::from_millis(1900),
            "hedged on the other instance after half the head deadline, took {took:?}"
        );
        assert_eq!(hung_count.load(Ordering::SeqCst), 1);
        assert_eq!(good_count.load(Ordering::SeqCst), 1);
        // The answering instance is no longer skipped; the slower one lost a race, which is not
        // a failure: it is not ejected either.
        assert!(!set.state.lock().failed.contains_key(&good));
        assert!(!set.state.lock().failed.contains_key(&hung));
    }

    #[tokio::test]
    async fn send_transaction_is_never_sent_twice() {
        let (hung, hung_count) = hanging().await;
        let (good, good_count) = answering().await;
        let set = EndpointSet::fixed(vec![hung, good]);
        set.mark_failed(good, Instant::now());
        let start = Instant::now();
        let r = request_with(
            req("lwd:9067", WRITE),
            opts(1000),
            true,
            Some(&set),
            Some(&hedging()),
        )
        .await;
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
        let resp = request_with(
            req("lwd:9067", WRITE),
            opts(2000),
            true,
            Some(&set),
            Some(&hedging()),
        )
        .await
        .expect("nothing reached the refusing address: the WRITE may go to the other one");
        assert_eq!(resp.status(), 200);
        assert_eq!(good_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn without_instances_a_read_is_not_hedged() {
        // Only the authority: there is no other instance to hedge on, so the one attempt keeps
        // the whole head deadline.
        let (hung, hung_count) = hanging().await;
        let start = Instant::now();
        let r = request_with(
            req(&hung.to_string(), READ),
            opts(1000),
            true,
            None,
            Some(&hedging()),
        )
        .await;
        assert!(matches!(r, Err(RequestError::Timeout)));
        let took = start.elapsed();
        assert!(
            took >= Duration::from_millis(900) && took < Duration::from_millis(1500),
            "took {took:?}"
        );
        assert_eq!(hung_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_slow_read_is_not_cut_at_half_its_deadline() {
        // Both instances answer after 1.5 s of a 2 s head deadline. Cutting the first attempt
        // at 1 s and giving the retry the other second failed both; the hedge keeps the first
        // running, and its head wins.
        let (a, a_count) = slow(Duration::from_millis(1500)).await;
        let (b, b_count) = slow(Duration::from_millis(1500)).await;
        let set = EndpointSet::fixed(vec![a, b]);
        let network = "test-hedge-slow";
        let before_won = crate::health::lwd_hedges(network, "won");
        let start = Instant::now();
        let resp = request_with(
            req("lwd:9067", READ),
            opts_on(network, 2000),
            true,
            Some(&set),
            Some(&hedging()),
        )
        .await
        .expect("the first attempt answers within the whole deadline");
        assert_eq!(resp.status(), 200);
        let took = start.elapsed();
        assert!(
            took >= Duration::from_millis(1400) && took < Duration::from_millis(1900),
            "took {took:?}"
        );
        assert_eq!(
            a_count.load(Ordering::SeqCst) + b_count.load(Ordering::SeqCst),
            2,
            "the read and its hedge"
        );
        assert!(crate::health::lwd_hedges(network, "started") >= 1);
        assert_eq!(crate::health::lwd_hedges(network, "won"), before_won);
    }

    #[tokio::test]
    async fn a_hedge_that_wins_is_counted_and_the_loser_not_ejected() {
        let (hung, hung_count) = hanging().await;
        let (good, good_count) = answering().await;
        let set = EndpointSet::fixed(vec![hung, good]);
        set.mark_failed(good, Instant::now());
        let network = "test-hedge-won";
        request_with(
            req("lwd:9067", READ),
            opts_on(network, 1000),
            true,
            Some(&set),
            Some(&hedging()),
        )
        .await
        .unwrap();
        assert_eq!(crate::health::lwd_hedges(network, "started"), 1);
        assert_eq!(crate::health::lwd_hedges(network, "won"), 1);
        assert_eq!(hung_count.load(Ordering::SeqCst), 1);
        assert_eq!(good_count.load(Ordering::SeqCst), 1);
        assert!(
            !set.state.lock().failed.contains_key(&hung),
            "a loser is not a failure"
        );
        assert!(!set.state.lock().failed.contains_key(&good));
    }

    #[tokio::test]
    async fn a_failed_hedge_is_settled_and_the_first_attempt_still_answers() {
        // The first attempt answers after 1.5 s of 2 s; the hedge (after 1 s) goes to an
        // instance that refuses the connection.
        let (slow_one, slow_count) = slow(Duration::from_millis(1500)).await;
        let dead = refusing().await;
        let set = EndpointSet::fixed(vec![slow_one, dead]);
        // Marked failed a moment ago, so that the first pick is the slow instance.
        let marked = Instant::now();
        set.mark_failed(dead, marked);
        let network = "test-hedge-failed";
        let resp = request_with(
            req("lwd:9067", READ),
            opts_on(network, 2000),
            true,
            Some(&set),
            Some(&hedging()),
        )
        .await
        .expect("the first attempt answers");
        assert_eq!(resp.status(), 200);
        assert_eq!(slow_count.load(Ordering::SeqCst), 1);
        assert_eq!(crate::health::lwd_hedges(network, "started"), 1);
        assert!(
            set.state
                .lock()
                .failed
                .get(&dead)
                .is_some_and(|t| *t > marked),
            "the failed hedge is settled"
        );
        assert!(!set.state.lock().failed.contains_key(&slow_one));
    }

    #[tokio::test]
    async fn both_attempts_failing_is_one_failed_call() {
        let (hung, hung_count) = hanging().await;
        let dead = refusing().await;
        let set = EndpointSet::fixed(vec![hung, dead]);
        let marked = Instant::now();
        set.mark_failed(dead, marked);
        let network = "test-hedge-both";
        let r = request_with(
            req("lwd:9067", READ),
            opts_on(network, 1000),
            true,
            Some(&set),
            Some(&hedging()),
        )
        .await;
        assert!(matches!(r, Err(RequestError::Timeout)));
        assert_eq!(hung_count.load(Ordering::SeqCst), 1);
        assert_eq!(crate::health::lwd_hedges(network, "started"), 1);
        let failed = set.state.lock().failed.clone();
        assert!(failed.contains_key(&hung));
        assert!(failed.get(&dead).is_some_and(|t| *t > marked));
    }

    #[tokio::test]
    async fn heavy_calls_and_reads_past_the_rate_cap_are_not_hedged() {
        let (hung, _) = hanging().await;
        let (good, good_count) = answering().await;
        let set = EndpointSet::fixed(vec![hung, good]);
        set.mark_failed(good, Instant::now());
        let heavy = CallOpts {
            may_hedge: false,
            ..opts(600)
        };
        let r = request_with(
            req("lwd:9067", READ),
            heavy,
            true,
            Some(&set),
            Some(&hedging()),
        )
        .await;
        assert!(matches!(r, Err(RequestError::Timeout)));
        assert_eq!(good_count.load(Ordering::SeqCst), 0);
        // The floor of the rate cap is used up and there are fewer than ten reads for each
        // hedge: no hedge.
        let set = EndpointSet::fixed(vec![hung, good]);
        set.mark_failed(good, Instant::now());
        let network = "test-hedge-rate";
        let capped = Hedging::new(HedgeDelay::Half, 16);
        for _ in 0..HEDGE_RATE_FLOOR {
            assert!(capped.rate.try_hedge(Instant::now()));
        }
        let r = request_with(
            req("lwd:9067", READ),
            opts_on(network, 600),
            true,
            Some(&set),
            Some(&capped),
        )
        .await;
        assert!(matches!(r, Err(RequestError::Timeout)));
        assert_eq!(crate::health::lwd_hedges(network, "rate_limited"), 1);
        assert_eq!(good_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn hedges_stay_at_most_one_in_ten_reads_of_the_window() {
        let rate = HedgeRate::default();
        let t0 = Instant::now();
        // The floor first; above it, one hedge per ten reads of the window.
        for _ in 0..HEDGE_RATE_FLOOR {
            assert!(rate.try_hedge(t0));
        }
        for _ in 0..69 {
            rate.record_read(t0);
        }
        assert!(!rate.try_hedge(t0), "69 reads: no seventh hedge");
        rate.record_read(t0);
        assert!(rate.try_hedge(t0));
        assert!(!rate.try_hedge(t0), "one in ten");
        for _ in 0..10 {
            rate.record_read(t0 + Duration::from_secs(1));
        }
        assert!(rate.try_hedge(t0 + Duration::from_secs(1)));
        assert!(!rate.try_hedge(t0 + Duration::from_secs(1)));
        // A window later the old reads and hedges are gone.
        let later = t0 + HEDGE_RATE_WINDOW + Duration::from_secs(2);
        for _ in 0..HEDGE_RATE_FLOOR {
            assert!(rate.try_hedge(later));
        }
        for _ in 0..69 {
            rate.record_read(later);
        }
        assert!(!rate.try_hedge(later));
        rate.record_read(later);
        assert!(rate.try_hedge(later));
    }

    #[test]
    fn the_rate_cap_has_a_floor() {
        let t0 = Instant::now();
        // No read at all in the window, or a few: six hedges, the seventh is refused.
        for reads in [0, 3] {
            let rate = HedgeRate::default();
            for _ in 0..reads {
                rate.record_read(t0);
            }
            for n in 1..=HEDGE_RATE_FLOOR {
                assert!(rate.try_hedge(t0), "hedge {n} with {reads} reads");
            }
            assert!(!rate.try_hedge(t0), "the seventh with {reads} reads");
            // Still refused a little later, allowed again a window later.
            assert!(!rate.try_hedge(t0 + Duration::from_secs(30)));
            assert!(rate.try_hedge(t0 + HEDGE_RATE_WINDOW + Duration::from_secs(1)));
        }
    }

    #[test]
    fn an_instance_is_skipped_from_its_second_lost_hedge_in_a_row() {
        let a: SocketAddr = "192.0.2.1:9067".parse().unwrap();
        let b: SocketAddr = "192.0.2.2:9067".parse().unwrap();
        let set = EndpointSet::fixed(vec![a, b]);
        let now = Instant::now();
        let skipped = |addr: &SocketAddr| set.state.lock().failed.contains_key(addr);
        assert!(!set.hedge_lost(a, now), "one lost hedge means little");
        assert!(!skipped(&a));
        // A head from it in between: the count starts again.
        set.mark_ok(a);
        assert!(!set.hedge_lost(a, now));
        assert!(!skipped(&a));
        assert!(set.hedge_lost(a, now), "the second in a row");
        assert!(skipped(&a));
        // The skip does not reset the count: once it is over, the next loss skips again.
        set.state.lock().failed.remove(&a);
        assert!(set.hedge_lost(a, now));
        assert!(skipped(&a));
        // Per address.
        assert!(!set.hedge_lost(b, now));
        assert!(!skipped(&b));
    }

    #[tokio::test]
    async fn an_instance_that_keeps_losing_hedges_is_skipped_without_a_failure() {
        let (hung, hung_count) = hanging().await;
        let (good, good_count) = answering().await;
        let set = EndpointSet::fixed(vec![hung, good]);
        let network = "test-hedge-loser";
        let call = CallOpts {
            class: Some("unary"),
            ..opts_on(network, 600)
        };
        let h = hedging();
        for round in 1..=2u64 {
            // Make sure the first pick is the hung instance.
            set.mark_failed(good, Instant::now());
            request_with(req("lwd:9067", READ), call, true, Some(&set), Some(&h))
                .await
                .expect("the hedge answers");
            assert_eq!(
                set.state.lock().failed.contains_key(&hung),
                round == 2,
                "round {round}"
            );
            assert_eq!(
                crate::health::lwd_hedges(network, "loser_skipped"),
                round - 1
            );
        }
        assert_eq!(hung_count.load(Ordering::SeqCst), 2);
        assert_eq!(good_count.load(Ordering::SeqCst), 2);
        // Not a failure of lightwalletd: no timeout, no failed call.
        assert_eq!(crate::health::lwd_timeouts(network, "unary", "head"), 0);
        assert_eq!(crate::health::lwd_call_totals(network), (2, 0));
        // The next read goes to the answering instance directly.
        let start = Instant::now();
        request_with(req("lwd:9067", READ), call, true, Some(&set), Some(&h))
            .await
            .unwrap();
        assert!(start.elapsed() < Duration::from_millis(250));
        assert_eq!(hung_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_read_the_rate_cap_leaves_unhedged_holds_no_hedge_permit() {
        let (hung, _) = hanging().await;
        let (good, good_count) = answering().await;
        let set = EndpointSet::fixed(vec![hung, good]);
        set.mark_failed(good, Instant::now());
        // One hedge permit; the rate cap refuses (its floor is used up, no reads).
        let h = Hedging::new(HedgeDelay::Half, 1);
        for _ in 0..HEDGE_RATE_FLOOR {
            assert!(h.rate.try_hedge(Instant::now()));
        }
        let network = "test-hedge-permit-back";
        // The first read waits on the hung instance until its deadline, not hedged.
        let pending = request_with(
            req("lwd:9067", READ),
            opts_on(network, 2000),
            true,
            Some(&set),
            Some(&h),
        );
        let later = async {
            tokio::time::sleep(Duration::from_millis(1400)).await;
            assert_eq!(crate::health::lwd_hedges(network, "rate_limited"), 1);
            assert_eq!(
                h.permits.available_permits(),
                1,
                "a read that is not hedged holds no hedge permit"
            );
            // Enough reads for the cap now: a second read is hedged while the first still waits.
            for _ in 0..200 {
                h.rate.record_read(Instant::now());
            }
            set.mark_failed(good, Instant::now());
            request_with(
                req("lwd:9067", READ),
                opts_on(network, 400),
                true,
                Some(&set),
                Some(&h),
            )
            .await
        };
        let (first, second) = tokio::join!(pending, later);
        assert!(matches!(first, Err(RequestError::Timeout)));
        assert!(second.is_ok(), "hedged on the answering instance");
        assert_eq!(crate::health::lwd_hedges(network, "started"), 1);
        assert_eq!(good_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn no_hedge_without_another_instance_or_a_permit_or_when_off() {
        let (only, only_count) = slow(Duration::from_millis(700)).await;
        let set = EndpointSet::fixed(vec![only]);
        let r = request_with(
            req("lwd:9067", READ),
            opts(1000),
            true,
            Some(&set),
            Some(&hedging()),
        )
        .await;
        assert!(
            r.is_ok(),
            "one instance: the one attempt keeps the whole deadline"
        );
        assert_eq!(only_count.load(Ordering::SeqCst), 1);

        let (hung, hung_count) = hanging().await;
        let (good, good_count) = answering().await;
        let set = EndpointSet::fixed(vec![hung, good]);
        set.mark_failed(good, Instant::now());
        let exhausted = warm(Hedging::new(HedgeDelay::Half, 1));
        let _held = exhausted.permits.clone().try_acquire_owned().unwrap();
        let network = "test-hedge-permit";
        let r = request_with(
            req("lwd:9067", READ),
            opts_on(network, 600),
            true,
            Some(&set),
            Some(&exhausted),
        )
        .await;
        assert!(matches!(r, Err(RequestError::Timeout)));
        assert_eq!(crate::health::lwd_hedges(network, "no_permit"), 1);
        assert_eq!(good_count.load(Ordering::SeqCst), 0);

        let set = EndpointSet::fixed(vec![hung, good]);
        set.mark_failed(good, Instant::now());
        let off = Hedging::new(HedgeDelay::Off, 16);
        let r = request_with(
            req("lwd:9067", READ),
            opts(600),
            true,
            Some(&set),
            Some(&off),
        )
        .await;
        assert!(matches!(r, Err(RequestError::Timeout)));
        assert_eq!(good_count.load(Ordering::SeqCst), 0);
        assert_eq!(hung_count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn hedging_settings_parse() {
        let s = Settings::parse("lwd:9067", None, None).unwrap();
        assert_eq!(s.hedge_delay, HedgeDelay::Half);
        assert_eq!(s.hedge_max_inflight, DEFAULT_HEDGE_MAX_INFLIGHT);
        let s = s.with_hedging(Some("250"), Some("4"), 128).unwrap();
        assert_eq!(s.hedge_delay, HedgeDelay::Fixed(Duration::from_millis(250)));
        assert_eq!(s.hedge_max_inflight, 4);
        let s = s.with_hedging(Some("0"), None, 128).unwrap();
        assert_eq!(s.hedge_delay, HedgeDelay::Off);
        assert_eq!(s.hedge_max_inflight, 16);
        assert_eq!(
            s.clone()
                .with_hedging(None, None, 40)
                .unwrap()
                .hedge_max_inflight,
            5,
            "an eighth of MAX_INFLIGHT_LWD"
        );
        assert_eq!(
            s.clone()
                .with_hedging(None, None, 4)
                .unwrap()
                .hedge_max_inflight,
            1
        );
        assert!(s.clone().with_hedging(Some("x"), None, 128).is_err());
        assert!(s.clone().with_hedging(None, Some("0"), 128).is_err());
        let too_many = (tokio::sync::Semaphore::MAX_PERMITS + 1).to_string();
        assert!(s.with_hedging(None, Some(&too_many), 128).is_err());
        let head = Duration::from_secs(10);
        assert_eq!(
            HedgeDelay::Half.for_head(head),
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            HedgeDelay::Fixed(Duration::from_secs(30)).for_head(head),
            Some(head)
        );
        assert_eq!(HedgeDelay::Off.for_head(head), None);
    }

    #[tokio::test]
    async fn one_resolution_at_a_time_and_the_previous_list_meanwhile() {
        let set = Arc::new(EndpointSet::new("localhost:9067".to_string()));
        // The first resolution: every caller waits for the same one.
        let calls: Vec<_> = (0..32)
            .map(|_| {
                let set = set.clone();
                tokio::spawn(async move { set.addrs().await })
            })
            .collect();
        let mut lists = Vec::new();
        for c in calls {
            lists.push(c.await.unwrap());
        }
        assert_eq!(set.resolutions.load(Ordering::SeqCst), 1);
        assert!(!lists[0].is_empty(), "localhost resolves");
        assert!(lists.iter().all(|l| *l == lists[0]));
        // An old list: callers get it at once while one new resolution runs.
        set.state.lock().resolved_at = Some(Instant::now() - RESOLVE_EVERY * 2);
        let start = Instant::now();
        for _ in 0..32 {
            assert_eq!(set.addrs().await, lists[0]);
        }
        assert!(start.elapsed() < Duration::from_millis(500));
        assert_eq!(set.resolutions.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn slow_head_reads_keep_their_whole_deadline() {
        let (hung, hung_count) = hanging().await;
        let (good, good_count) = answering().await;
        let set = EndpointSet::fixed(vec![hung, good]);
        set.mark_failed(good, Instant::now());
        let path = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTaddressBalance";
        let start = Instant::now();
        let r = request_with(
            req("lwd:9067", path),
            opts(1000),
            true,
            Some(&set),
            Some(&hedging()),
        )
        .await;
        assert!(matches!(r, Err(RequestError::Timeout)));
        assert!(start.elapsed() >= Duration::from_millis(900));
        assert_eq!(hung_count.load(Ordering::SeqCst), 1);
        assert_eq!(good_count.load(Ordering::SeqCst), 0);
        // A late head of such a read is not a failure of the instance: not ejected.
        assert!(!set.state.lock().failed.contains_key(&hung));
    }

    #[tokio::test]
    async fn other_backends_are_not_retried_after_a_timeout() {
        let (hung, hung_count) = hanging().await;
        let r = request_with(
            req(&hung.to_string(), READ),
            opts(500),
            false,
            None,
            Some(&hedging()),
        )
        .await;
        assert!(matches!(r, Err(RequestError::Timeout)));
        assert_eq!(hung_count.load(Ordering::SeqCst), 1);
    }
}

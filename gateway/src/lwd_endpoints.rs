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
//!   - after an error that says the request was not written to the connection
//!     ([`RequestError::not_written`]: the HTTP client got the request back unsent, or the
//!     connection was closed between its handshake and the request), for every call as well;
//!   - for an idempotent call (every `CompactTxStreamer` RPC except `SendTransaction`) also after
//!     any other transport error. A `SendTransaction` that may have been written is never sent
//!     twice by the gateway: every error that does not prove the opposite fails it.
//! - **Hedged reads**: an idempotent read whose response head has not arrived after the hedge
//!   delay (`LWD_HEDGE_DELAY_MS`, default half of the head deadline) is sent a second time to a
//!   *different* instance of `LWD_ENDPOINTS` (none: no hedge), while the first attempt keeps
//!   running. The first head wins; both share the call's
//!   whole head deadline, so a read that is merely slow is no longer cut at half of it. The
//!   other attempt is not cancelled (a cancelled call makes lightwalletd cancel the node RPC
//!   behind it, which can cost the node an RPC slot): it runs to its end in a task of its own
//!   and its answer is discarded ([`detach_loser`]), unless as many detached attempts as
//!   `LWD_HEDGE_MAX_INFLIGHT` are running already (then it is cancelled, as before), or its
//!   request was not given to a connection yet (then it is dropped: nothing was sent). The
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
//!   not counted in `MAX_INFLIGHT_LWD` (the caller's permit covers the attempt whose answer
//!   it gets), nor are detached losers, which hold a permit of a second set of the same size
//!   and none of the caller's: hedging adds at most `LWD_HEDGE_MAX_INFLIGHT` hedges in flight
//!   plus as many detached losers to the concurrent lightwalletd calls, and 10 % more
//!   calls plus at most six a minute. Counted in `ohttp_lwd_hedges_total`.
//!
//!   Every attempt cut by the call's deadline while the call still waits for it counts in
//!   `ohttp_lwd_timeouts_total`, also when another attempt answers afterwards. A detached
//!   loser cut by that deadline does not (the call has its answer): it counts as
//!   `ohttp_lwd_hedges_total{event="loser_expired"}`.
//!
//!   The retry goes to another instance when `LWD_ENDPOINTS` has one, always on a new connection.
//!   Only the phase up to the response head is retried: a call that fails after its head arrived
//!   is not (part of the answer may already be on its way to the client).
//! - **Outcome** of every call to the own lightwalletd (after the retry) goes to the `/healthz`
//!   error window (`health::record_lwd_call`). For the reads whose head may take long
//!   (`GetMempoolStream`, the transparent-address RPCs) only connect and transport errors count
//!   there and eject an instance: a head that is merely late is not a lightwalletd failure.

use axum::body::Bytes;
use futures_util::future::BoxFuture;
use http_body_util::Full;
use hyper::Request;
use hyper_util::client::legacy::{
    connect::{capture_connection, CaptureConnection, Connect, HttpConnector},
    Client,
};
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

/// A detached loser of a hedge ([`detach_loser`]) reads its answer's body for this long at most.
const DETACHED_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
/// A detached loser of a hedge reads this much of its answer's body at most.
const DETACHED_DRAIN_MAX_BYTES: usize = 8 * 1024 * 1024;
/// A detached loser of a hedge lets other tasks run after this many frames of its body.
const DETACHED_DRAIN_YIELD_EVERY: u32 = 64;

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

/// How [`request_with`] hedges: the delay, the permits of hedges in flight, the permits of
/// detached losers and the rate cap.
#[derive(Clone)]
pub struct Hedging {
    pub delay: HedgeDelay,
    pub permits: Arc<tokio::sync::Semaphore>,
    /// One per attempt that lost its race and runs to its end detached ([`detach_loser`]): as
    /// many as `permits`, and apart from them, so that losers on an instance that hangs do not
    /// use up the hedges.
    pub detached: Arc<tokio::sync::Semaphore>,
    pub rate: Arc<HedgeRate>,
}

impl Hedging {
    pub fn new(delay: HedgeDelay, max_inflight: usize) -> Self {
        let max = max_inflight.clamp(1, tokio::sync::Semaphore::MAX_PERMITS);
        Self {
            delay,
            permits: Arc::new(tokio::sync::Semaphore::new(max)),
            detached: Arc::new(tokio::sync::Semaphore::new(max)),
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

    /// The error says that no byte of the request was written to a connection, so the call may
    /// be sent again whatever it is. From the HTTP client's sources (hyper 1.x, HTTP/2), the
    /// error it wraps is one of exactly two kinds then:
    ///
    /// - *canceled*: the connection gave the request back unsent (it was not ready, or its
    ///   task ended with the request still queued and unread). The client itself sends such a
    ///   request again when the connection was a reused pooled one; this is the same error on
    ///   a connection that was new.
    /// - *closed*: the connection was closed between its handshake and the moment the request
    ///   would have been handed to it.
    ///
    /// This is read from the sources of the HTTP client at the versions of the lock file
    /// (hyper 1.12, hyper-util 0.1.21), not promised by their documentation: check it again
    /// when either is updated. There, *canceled* is made only where the request is still in
    /// hand (`client::conn::http2::SendRequest::try_send_request`, and the drop of a queued
    /// request the connection task never took), *closed* only by `SendRequest::poll_ready`,
    /// and every failure after the connection task took the request is an HTTP/2, I/O or
    /// user error. `a_request_the_connection_gave_back_was_not_written` and the tests of a
    /// refused stream and of a connection that shuts down or fails after the request hold
    /// both sides.
    ///
    /// Every other error is ambiguous and false here: the client reports a failed handshake,
    /// a request the connection refused to start and a stream or connection that failed after
    /// the request was written as the same kind. A connect error is not covered either (see
    /// `is_connect`), nor is a deadline.
    pub fn not_written(&self) -> bool {
        match self {
            RequestError::Http(e) => std::error::Error::source(e)
                .and_then(|cause| cause.downcast_ref::<hyper::Error>())
                .is_some_and(hyper_not_written),
            RequestError::Timeout => false,
        }
    }
}

/// See [`RequestError::not_written`].
fn hyper_not_written(e: &hyper::Error) -> bool {
    e.is_canceled() || e.is_closed()
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

/// A response head, or why there is none.
type Head = Result<hyper::Response<hyper::body::Incoming>, RequestError>;

/// One attempt in flight. It owns what it needs, so the loser of a hedge can outlive its call.
struct Attempt {
    head: BoxFuture<'static, Head>,
    /// Tells whether the HTTP client has given the request to a connection yet.
    connection: CaptureConnection,
}

impl Attempt {
    /// The request was given to a connection: it may be at lightwalletd. False while the
    /// attempt was not polled, still connects, or failed before that: dropping it then sends
    /// nothing and cancels nothing. True is not proof that it was sent: it stays true when a
    /// pooled connection gave the request back and the client is connecting again for it.
    /// Such a loser is detached like one that was sent, and its call then runs as any other
    /// (one more read; nothing is cancelled by it).
    fn handed_over(&self) -> bool {
        self.connection.connection_metadata().is_some()
    }
}

/// One attempt's result, the instance it went to, whether a hedge was sent (the call's
/// second send: no retry after it), and whether a failure was already settled and counted.
type Attempted = (Head, Option<SocketAddr>, bool, bool);

/// [`request`] with the transport given: `own` = a call to the gateway's own lightwalletd;
/// `hedging` None = no hedged reads.
pub async fn request_with(
    req: Request<Full<Bytes>>,
    opts: CallOpts<'_>,
    own: bool,
    endpoints: Option<&EndpointSet>,
    hedging: Option<&Hedging>,
) -> Head {
    let client = if opts.pooled {
        crate::lwd::lwd_client()
    } else {
        fresh_client()
    };
    request_on(&client, req, opts, own, endpoints, hedging).await
}

/// [`request_with`] with the client of the first attempt given (the retry and the hedge always
/// use a new connection of their own).
async fn request_on<C>(
    client: &Client<C, Full<Bytes>>,
    req: Request<Full<Bytes>>,
    opts: CallOpts<'_>,
    own: bool,
    endpoints: Option<&EndpointSet>,
    hedging: Option<&Hedging>,
) -> Head
where
    C: Connect + Clone + Send + Sync + 'static,
{
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
    let first = attempt(client, &req, first_addr, deadline);
    let hedge = match (hedging, endpoints) {
        (Some(h), Some(set)) if retry_reads && !slow_head && opts.may_hedge => h
            .delay
            .for_head(opts.head)
            .filter(|d| *d < opts.head)
            .map(|d| (start + d, h, set)),
        _ => None,
    };
    let (result, addr, hedge_sent, accounted) = match hedge {
        None => (first.head.await, first_addr, false, false),
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
    // Not written to the connection: as safe to send again as after a connect error, for
    // every call. A read gets its retry after any transport error anyway.
    let unsent = !connect && err.not_written();
    let retry = !hedge_sent && (connect || unsent || (retry_reads && !timed_out));
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
    } else if unsent && !retry_reads {
        tracing::warn!(error = %err, "lightwalletd connection ended before the request was written to it, sending it once on a new connection");
        let call = if path.ends_with("/SendTransaction") {
            "send"
        } else {
            "other"
        };
        crate::health::record_lwd_unsent_retry(opts.network, call);
    } else {
        tracing::debug!(to = ?second_addr, "lightwalletd read retry");
        tracing::warn!(error = %err, path = %req.uri().path(), "lightwalletd read failed before its answer, retrying once");
        crate::health::record_lwd_read_retry(opts.network, "error");
    }
    // Always a new connection: a pooled one may be the one that hangs.
    let second = attempt(&fresh_client(), &req, second_addr, deadline)
        .head
        .await;
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
/// one). The first head wins; the other attempt, when it is still running, goes on in a task
/// of its own ([`detach_loser`]). The loser of the race
/// is not a failure: it is not counted as a timeout or as a failed call, and does not count
/// towards replacing the pool (it was only slower); an instance that loses hedges in a row is
/// skipped for a while ([`EndpointSet::hedge_lost`]). An attempt that fails while the other still runs is
/// settled as failed at once (its instance is skipped), and the other one is awaited; when both
/// fail, the first attempt's error is returned for the caller to settle and count.
#[allow(clippy::too_many_arguments)]
async fn hedged(
    mut first: Attempt,
    first_addr: Option<SocketAddr>,
    hedge_at: Instant,
    hedging: &Hedging,
    set: &EndpointSet,
    addrs: &[SocketAddr],
    req: &Request<Full<Bytes>>,
    deadline: Instant,
    opts: CallOpts<'_>,
) -> Attempted {
    tokio::select! {
        r = &mut first.head => return (r, first_addr, false, false),
        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(hedge_at)) => {}
    }
    let Some(second_addr) = set.pick_other(addrs, first_addr, Instant::now()) else {
        return (first.head.await, first_addr, false, false);
    };
    let Ok(permit) = hedging.permits.clone().try_acquire_owned() else {
        crate::health::record_lwd_hedge(opts.network, "no_permit");
        return (first.head.await, first_addr, false, false);
    };
    if !hedging.rate.try_hedge(Instant::now()) {
        crate::health::record_lwd_hedge(opts.network, "rate_limited");
        // Not hedged: the permit goes back before the wait for the first attempt, which may
        // last until the deadline.
        drop(permit);
        return (first.head.await, first_addr, false, false);
    }
    // Held until the race ends (this function returns), also while the first attempt still
    // runs after the hedge failed.
    let _permit = permit;
    crate::health::record_lwd_hedge(opts.network, "started");
    tracing::debug!(path = %req.uri().path(), to = %second_addr, "lightwalletd read without a head yet: hedged on another instance");
    let mut second = attempt(&fresh_client(), req, Some(second_addr), deadline);
    let mut first_err: Option<RequestError> = None;
    let mut second_failed = false;
    loop {
        tokio::select! {
            r = &mut first.head, if first_err.is_none() => match r {
                Ok(resp) => {
                    if !second_failed {
                        // The hedge is still running: it lost.
                        detach_loser(hedging, opts.network, second);
                    }
                    return (Ok(resp), first_addr, true, false);
                }
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
            r = &mut second.head, if !second_failed => match r {
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
                    if first_err.is_none() {
                        detach_loser(hedging, opts.network, first);
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

/// The attempt that lost a hedge race, still without a head: instead of being cancelled it runs
/// to its end in a task of its own, and its answer is discarded. A cancelled call makes
/// lightwalletd cancel the node RPC behind it, which can cost the node an RPC slot.
///
/// - **Bounds**: the head by the call's own head deadline (inside the attempt), the body by
///   [`DETACHED_DRAIN_TIMEOUT`] and [`DETACHED_DRAIN_MAX_BYTES`]. The body is read because a
///   server stream sends its head with its first message while the call still runs: dropping
///   it there would cancel the call all the same. A loser cut by one of the bounds is
///   cancelled then, as every call that runs into its deadline (`event="loser_expired"`).
/// - **Permits**: one of [`Hedging::detached`] (as many as `LWD_HEDGE_MAX_INFLIGHT`), held
///   until the task is gone. None free: the loser is cancelled as before
///   (`event="loser_cancelled"`). It holds no hedge permit (that one goes back when the race
///   ends, so losers on an instance that hangs do not use up the hedges) and no permit of the
///   caller (`MAX_INFLIGHT_LWD` covers the attempt whose answer the caller reads), so it never
///   keeps a request waiting; it is one more call at lightwalletd, at most
///   `LWD_HEDGE_MAX_INFLIGHT` of them at a time.
/// - **No outcome**: whatever the loser ends with settles nothing (no `/healthz` outcome, no
///   timeout counted, the instance neither skipped nor cleared: a late head does not reset its
///   lost hedges), exactly as when it was cancelled.
///
/// A loser whose request was not given to a connection yet (never polled, or still
/// connecting) is dropped instead, without an event: nothing of it is at lightwalletd, and
/// detaching it would send a call after the answer is there.
///
/// When the caller itself goes away during the race, both attempts are dropped as before.
fn detach_loser(hedging: &Hedging, network: &str, loser: Attempt) {
    if !loser.handed_over() {
        return;
    }
    let Ok(permit) = hedging.detached.clone().try_acquire_owned() else {
        crate::health::record_lwd_hedge(network, "loser_cancelled");
        // Dropped here: cancelled.
        return;
    };
    crate::health::record_lwd_hedge(network, "loser_detached");
    let network = network.to_string();
    tokio::spawn(async move {
        let _permit = permit;
        let ended = match loser.head.await {
            Ok(resp) => {
                // For the tests: the loser has its head and reads its body from here on.
                #[cfg(test)]
                crate::health::record_lwd_hedge(&network, tests::LOSER_HAS_ITS_HEAD);
                drained(
                    resp.into_body(),
                    DETACHED_DRAIN_TIMEOUT,
                    DETACHED_DRAIN_MAX_BYTES,
                )
                .await
            }
            // Cut by the head deadline: the attempt dropped its request.
            Err(RequestError::Timeout) => false,
            Err(RequestError::Http(_)) => true,
        };
        if !ended {
            crate::health::record_lwd_hedge(&network, "loser_expired");
        }
    });
}

/// Read `body` to its end and discard it; false when `timeout` passed or more than
/// `max_bytes` came first (the caller drops it, which cancels the call): the data of its
/// frames, a frame without data counted as one byte. A body that ends with an error has
/// ended.
async fn drained<B>(mut body: B, timeout: Duration, max_bytes: usize) -> bool
where
    B: hyper::body::Body + Unpin,
{
    use bytes::Buf;
    use http_body_util::BodyExt;
    let end = tokio::time::Instant::now() + timeout;
    let mut left = max_bytes;
    let mut frames = 0u32;
    loop {
        // Checked here as well: a timeout polls its future first, so frames that are always
        // ready would never let it fire.
        if tokio::time::Instant::now() >= end {
            return false;
        }
        // Frames that are always ready never let this task wait: it gives way to the others
        // now and then.
        frames = frames.wrapping_add(1);
        if frames % DETACHED_DRAIN_YIELD_EVERY == 0 {
            tokio::task::yield_now().await;
        }
        match tokio::time::timeout_at(end, body.frame()).await {
            Err(_) => return false,
            Ok(None) | Ok(Some(Err(_))) => return true,
            Ok(Some(Ok(frame))) => {
                // Every frame costs at least one byte of the bound: frames without data
                // (empty ones, trailers) cannot go on for ever either.
                let n = frame.data_ref().map_or(0, |data| data.remaining()).max(1);
                if n > left {
                    return false;
                }
                left -= n;
            }
        }
    }
}

/// One attempt: `req` (sent to `addr` instead of its authority when given) on `client`, until
/// `deadline`. The future owns the request and its handle on the client; nothing is sent
/// before it is polled.
fn attempt<C>(
    client: &Client<C, Full<Bytes>>,
    req: &Request<Full<Bytes>>,
    addr: Option<SocketAddr>,
    deadline: Instant,
) -> Attempt
where
    C: Connect + Clone + Send + Sync + 'static,
{
    let mut copy = Request::new(req.body().clone());
    *copy.method_mut() = req.method().clone();
    *copy.uri_mut() = match addr {
        Some(addr) => with_authority(req.uri(), addr),
        None => req.uri().clone(),
    };
    *copy.version_mut() = req.version();
    *copy.headers_mut() = req.headers().clone();
    let deadline = tokio::time::Instant::from_std(deadline);
    let connection = capture_connection(&mut copy);
    let sent = client.request(copy);
    Attempt {
        head: Box::pin(async move {
            match tokio::time::timeout_at(deadline, sent).await {
                Ok(Ok(resp)) => Ok(resp),
                Ok(Err(e)) => Err(RequestError::Http(e)),
                Err(_) => Err(RequestError::Timeout),
            }
        }),
        connection,
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

    /// Counted in test builds, as an `event` of the hedge counter, when a detached loser has
    /// its response head and starts to read its body (`detach_loser`).
    pub(super) const LOSER_HAS_ITS_HEAD: &str = "test_loser_has_its_head";

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

    /// What a [`gated`] upstream saw.
    struct Gated {
        addr: SocketAddr,
        /// Requests received.
        received: Arc<AtomicUsize>,
        /// Handlers that ran to their end (the answer's head was handed to the server).
        finished: Arc<AtomicUsize>,
        /// Handlers that are gone, finished or dropped (the handler of a request the client
        /// cancels is dropped before its end).
        ended: Arc<AtomicUsize>,
        /// Answer bodies whose one message was produced.
        produced: Arc<AtomicUsize>,
        /// One permit lets one handler answer.
        head: Arc<tokio::sync::Semaphore>,
        /// One permit lets one answer's body produce its message (only with `streamed`).
        body: Arc<tokio::sync::Semaphore>,
    }

    /// Counts a handler that is gone, however it ended.
    struct Ended(Arc<AtomicUsize>);

    impl Drop for Ended {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// An h2c server whose handlers wait for the test: each request is answered once a permit
    /// is added to `head`. The answer's body is one message: with `streamed` it is produced
    /// once a permit is added to `body` (the head goes out before it), without, at once. No
    /// timing: the test decides what happens when.
    async fn gated(streamed: bool) -> Gated {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let state = Gated {
            addr: listener.local_addr().unwrap(),
            received: Default::default(),
            finished: Default::default(),
            ended: Default::default(),
            produced: Default::default(),
            head: Arc::new(tokio::sync::Semaphore::new(0)),
            body: Arc::new(tokio::sync::Semaphore::new(0)),
        };
        let handles = (
            state.received.clone(),
            state.finished.clone(),
            state.ended.clone(),
            state.produced.clone(),
            state.head.clone(),
            state.body.clone(),
        );
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let handles = handles.clone();
                let service = hyper::service::service_fn(
                    move |_req: hyper::Request<hyper::body::Incoming>| {
                        let (received, finished, ended, produced, head, body) = handles.clone();
                        async move {
                            let _ended = Ended(ended);
                            received.fetch_add(1, Ordering::SeqCst);
                            head.acquire().await.unwrap().forget();
                            let message = futures_util::stream::once(Box::pin(async move {
                                if streamed {
                                    body.acquire().await.unwrap().forget();
                                    produced.fetch_add(1, Ordering::SeqCst);
                                }
                                Ok::<_, std::convert::Infallible>(hyper::body::Frame::data(
                                    Bytes::from_static(&[0, 0, 0, 0, 0]),
                                ))
                            }));
                            finished.fetch_add(1, Ordering::SeqCst);
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
                                    .status(200)
                                    .header("content-type", "application/grpc")
                                    .body(http_body_util::StreamBody::new(message))
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
        state
    }

    /// Wait until `done` holds, for at most 10 s (a bound for a broken test, not a margin:
    /// nothing here depends on how long it takes).
    async fn eventually(what: &str, done: impl Fn() -> bool) {
        let start = Instant::now();
        while !done() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "never happened: {what}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The head deadline of the detached-loser tests: the hedge goes out after half of it,
    /// and the other half is the room a loser has before its deadline.
    const DETACH_HEAD_MS: u64 = 6000;

    #[tokio::test]
    async fn the_loser_of_a_hedge_runs_to_its_end() {
        // The first attempt goes to an instance that answers only when the test lets it;
        // the hedge is answered at once and wins. The first attempt is not cancelled.
        let slow_one = gated(false).await;
        let (good, good_count) = answering().await;
        let set = EndpointSet::fixed(vec![slow_one.addr, good]);
        set.mark_failed(good, Instant::now());
        let h = hedging();
        let network = "test-hedge-detached";
        request_with(
            req("lwd:9067", READ),
            opts_on(network, DETACH_HEAD_MS),
            true,
            Some(&set),
            Some(&h),
        )
        .await
        .expect("the hedge answers");
        assert_eq!(crate::health::lwd_hedges(network, "won"), 1);
        assert_eq!(crate::health::lwd_hedges(network, "loser_detached"), 1);
        assert_eq!(good_count.load(Ordering::SeqCst), 1);
        assert_eq!(slow_one.received.load(Ordering::SeqCst), 1);
        assert_eq!(slow_one.ended.load(Ordering::SeqCst), 0, "still running");
        assert_eq!(
            h.detached.available_permits(),
            DEFAULT_HEDGE_MAX_INFLIGHT - 1,
            "the detached loser holds a permit of its own"
        );
        assert_eq!(
            h.permits.available_permits(),
            DEFAULT_HEDGE_MAX_INFLIGHT,
            "the hedge permit went back when the race ended"
        );
        slow_one.head.add_permits(1);
        eventually("the loser ran to its end and gave its permit back", || {
            slow_one.finished.load(Ordering::SeqCst) == 1
                && h.detached.available_permits() == DEFAULT_HEDGE_MAX_INFLIGHT
        })
        .await;
        assert_eq!(crate::health::lwd_hedges(network, "loser_cancelled"), 0);
        assert_eq!(crate::health::lwd_hedges(network, "loser_expired"), 0);
        // Its late answer settles nothing: neither skipped nor cleared.
        assert!(!set.state.lock().failed.contains_key(&slow_one.addr));
        assert_eq!(set.state.lock().lost_hedges.get(&slow_one.addr), Some(&1));
        assert_eq!(crate::health::lwd_call_totals(network), (1, 0));
    }

    #[tokio::test]
    async fn a_hedge_that_loses_runs_to_its_end_too() {
        // Both instances answer only when the test lets them: the first attempt once the
        // hedge has arrived at the other one, the hedge after the call has its answer.
        let first = gated(false).await;
        let second = gated(false).await;
        let set = Arc::new(EndpointSet::fixed(vec![first.addr, second.addr]));
        set.mark_failed(second.addr, Instant::now());
        let h = hedging();
        let network = "test-hedge-detached-second";
        let call = {
            let (set, h) = (set.clone(), h.clone());
            tokio::spawn(async move {
                request_with(
                    req("lwd:9067", READ),
                    opts_on(network, DETACH_HEAD_MS),
                    true,
                    Some(&*set),
                    Some(&h),
                )
                .await
                .map(|resp| resp.status())
            })
        };
        eventually("the hedge arrived", || {
            second.received.load(Ordering::SeqCst) == 1
        })
        .await;
        first.head.add_permits(1);
        let status = call.await.unwrap().expect("the first attempt answers");
        assert_eq!(status, 200);
        assert_eq!(first.received.load(Ordering::SeqCst), 1);
        assert_eq!(crate::health::lwd_hedges(network, "won"), 0);
        assert_eq!(crate::health::lwd_hedges(network, "loser_detached"), 1);
        assert_eq!(second.ended.load(Ordering::SeqCst), 0, "still running");
        second.head.add_permits(1);
        eventually("the hedge ran to its end and gave its permit back", || {
            second.finished.load(Ordering::SeqCst) == 1
                && h.detached.available_permits() == DEFAULT_HEDGE_MAX_INFLIGHT
        })
        .await;
        assert_eq!(crate::health::lwd_hedges(network, "loser_expired"), 0);
    }

    #[tokio::test]
    async fn without_a_free_permit_the_loser_is_cancelled_and_counted() {
        let slow_one = gated(false).await;
        let (good, _) = answering().await;
        let set = EndpointSet::fixed(vec![slow_one.addr, good]);
        set.mark_failed(good, Instant::now());
        let h = warm(Hedging::new(HedgeDelay::Half, 1));
        let held = h.detached.clone().try_acquire_owned().unwrap();
        let network = "test-hedge-detached-full";
        request_with(
            req("lwd:9067", READ),
            opts_on(network, DETACH_HEAD_MS),
            true,
            Some(&set),
            Some(&h),
        )
        .await
        .expect("the hedge answers");
        assert_eq!(crate::health::lwd_hedges(network, "loser_cancelled"), 1);
        assert_eq!(crate::health::lwd_hedges(network, "loser_detached"), 0);
        assert_eq!(slow_one.received.load(Ordering::SeqCst), 1);
        // The instance sees the cancellation: its handler is dropped, never let through.
        eventually("the loser's handler was dropped", || {
            slow_one.ended.load(Ordering::SeqCst) == 1
        })
        .await;
        assert_eq!(
            slow_one.finished.load(Ordering::SeqCst),
            0,
            "cancelled, as before"
        );
        drop(held);
        assert_eq!(h.detached.available_permits(), 1);
    }

    #[tokio::test]
    async fn a_detached_loser_that_never_answers_ends_at_its_deadline() {
        // Never let through: the loser has no head at the call's head deadline.
        let hung = gated(false).await;
        let (good, _) = answering().await;
        let set = EndpointSet::fixed(vec![hung.addr, good]);
        set.mark_failed(good, Instant::now());
        let h = warm(Hedging::new(HedgeDelay::Half, 2));
        let network = "test-hedge-detached-expired";
        let call = CallOpts {
            class: Some("unary"),
            ..opts_on(network, 1000)
        };
        request_with(req("lwd:9067", READ), call, true, Some(&set), Some(&h))
            .await
            .expect("the hedge answers");
        assert_eq!(crate::health::lwd_hedges(network, "loser_detached"), 1);
        eventually("the loser was cut by the head deadline", || {
            crate::health::lwd_hedges(network, "loser_expired") == 1
                && h.detached.available_permits() == 2
        })
        .await;
        // Cut means cancelled: the instance's handler is dropped.
        eventually("the loser's handler was dropped", || {
            hung.ended.load(Ordering::SeqCst) == 1
        })
        .await;
        assert_eq!(hung.received.load(Ordering::SeqCst), 1);
        assert_eq!(hung.finished.load(Ordering::SeqCst), 0);
        // Not a failure of lightwalletd, as when the loser was cancelled.
        assert_eq!(crate::health::lwd_timeouts(network, "unary", "head"), 0);
        assert_eq!(crate::health::lwd_call_totals(network), (1, 0));
        assert!(!set.state.lock().failed.contains_key(&hung.addr));
    }

    #[tokio::test]
    async fn a_detached_loser_reads_its_streamed_answer_to_the_end() {
        // The loser's head goes out when the test lets it, the one message of its body only
        // after that: dropping the answer at its head would cancel the stream before the
        // message is produced.
        let streaming = gated(true).await;
        let (good, _) = answering().await;
        let set = EndpointSet::fixed(vec![streaming.addr, good]);
        set.mark_failed(good, Instant::now());
        let h = hedging();
        let network = "test-hedge-detached-stream";
        request_with(
            req("lwd:9067", READ),
            opts_on(network, DETACH_HEAD_MS),
            true,
            Some(&set),
            Some(&h),
        )
        .await
        .expect("the hedge answers");
        assert_eq!(crate::health::lwd_hedges(network, "loser_detached"), 1);
        streaming.head.add_permits(1);
        eventually("the loser has its head and reads its body", || {
            crate::health::lwd_hedges(network, LOSER_HAS_ITS_HEAD) == 1
        })
        .await;
        // The head is with the loser, its body still open (the message waits for the test):
        // the loser goes on, and holds its permit. One that dropped the answer at its head
        // would have given the permit back with it.
        assert_eq!(
            h.detached.available_permits(),
            DEFAULT_HEDGE_MAX_INFLIGHT - 1,
            "held while the body is read"
        );
        assert_eq!(streaming.produced.load(Ordering::SeqCst), 0);
        streaming.body.add_permits(1);
        eventually("the body was read to its end", || {
            streaming.produced.load(Ordering::SeqCst) == 1
                && h.detached.available_permits() == DEFAULT_HEDGE_MAX_INFLIGHT
        })
        .await;
        assert_eq!(crate::health::lwd_hedges(network, "loser_expired"), 0);
    }

    /// The two errors of the HTTP client that say a request was not written, made the way the
    /// client meets them: a connection whose task is gone.
    #[tokio::test]
    async fn a_request_the_connection_gave_back_was_not_written() {
        let (io, _peer) = tokio::io::duplex(64 * 1024);
        let (mut sender, conn) = hyper::client::conn::http2::handshake::<_, _, Full<Bytes>>(
            hyper_util::rt::TokioExecutor::new(),
            hyper_util::rt::TokioIo::new(io),
        )
        .await
        .expect("the handshake only writes");
        drop(conn);
        let Err(closed) = sender.ready().await else {
            panic!("the connection is gone");
        };
        assert!(closed.is_closed(), "{closed:?}");
        assert!(hyper_not_written(&closed));
        let Err(unsent) = sender.try_send_request(req("lwd:9067", WRITE)).await else {
            panic!("the connection is gone");
        };
        assert!(unsent.message().is_some(), "the request came back");
        let unsent = unsent.into_error();
        assert!(unsent.is_canceled(), "{unsent:?}");
        assert!(hyper_not_written(&unsent));
        assert!(!RequestError::Timeout.not_written());
    }

    /// A connection that takes everything written to it (and keeps it for the test) and reads
    /// as closed at once: its HTTP/2 handshake (which only writes) succeeds, and the
    /// connection ends before the request is written to it.
    struct ClosedAfterHandshake {
        written: Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl hyper::rt::Read for ClosedAfterHandshake {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: hyper::rt::ReadBufCursor<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            // Nothing read: the end of the stream.
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl hyper::rt::Write for ClosedAfterHandshake {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<Result<usize, std::io::Error>> {
            self.written.lock().unwrap().extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl hyper_util::client::legacy::connect::Connection for ClosedAfterHandshake {
        fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
            hyper_util::client::legacy::connect::Connected::new()
        }
    }

    /// Gives out [`ClosedAfterHandshake`] connections; `written` is everything the client
    /// wrote to any of them.
    #[derive(Clone, Default)]
    struct ClosedConnector {
        written: Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl tower::Service<hyper::Uri> for ClosedConnector {
        type Response = ClosedAfterHandshake;
        type Error = std::io::Error;
        type Future = std::future::Ready<Result<ClosedAfterHandshake, std::io::Error>>;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, _dst: hyper::Uri) -> Self::Future {
            std::future::ready(Ok(ClosedAfterHandshake {
                written: self.written.clone(),
            }))
        }
    }

    /// The length of the HTTP/2 client connection preface.
    const H2_PREFACE_LEN: usize = 24;

    /// The (type, stream id) of every HTTP/2 frame in `bytes`, which must be a client
    /// connection preface followed by whole frames and nothing else.
    fn h2_frames(bytes: &[u8]) -> Vec<(u8, u32)> {
        assert!(
            bytes.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
            "no connection preface"
        );
        let mut bytes = &bytes[H2_PREFACE_LEN..];
        let mut frames = Vec::new();
        while !bytes.is_empty() {
            assert!(bytes.len() >= 9, "a truncated frame header");
            let len = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) as usize;
            let stream = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) & 0x7fff_ffff;
            assert!(bytes.len() >= 9 + len, "a truncated frame");
            frames.push((bytes[3], stream));
            bytes = &bytes[9 + len..];
        }
        frames
    }

    #[test]
    fn h2_frames_reads_whole_frames_only() {
        let mut bytes = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        assert_eq!(bytes.len(), H2_PREFACE_LEN);
        assert!(h2_frames(&bytes).is_empty());
        // SETTINGS on stream 0, then HEADERS on stream 1 with a payload of two bytes.
        bytes.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
        bytes.extend_from_slice(&[0, 0, 2, 1, 4, 0, 0, 0, 1, 0x82, 0x86]);
        assert_eq!(h2_frames(&bytes), vec![(4, 0), (1, 1)]);
        for truncated in [&bytes[..bytes.len() - 1], &bytes[..H2_PREFACE_LEN + 4]] {
            let truncated = truncated.to_vec();
            assert!(std::panic::catch_unwind(move || h2_frames(&truncated)).is_err());
        }
    }

    #[tokio::test]
    async fn a_send_that_was_not_written_is_sent_once_on_a_new_connection() {
        // The first attempt's connection ends between its handshake and the request; the
        // other instance answers.
        let connector = ClosedConnector::default();
        let client: Client<ClosedConnector, Full<Bytes>> =
            Client::builder(hyper_util::rt::TokioExecutor::new())
                .http2_only(true)
                .build(connector.clone());
        let (good, good_count) = answering().await;
        let closed: SocketAddr = "192.0.2.1:9067".parse().unwrap();
        let set = EndpointSet::fixed(vec![closed, good]);
        set.mark_failed(good, Instant::now());
        let network = "test-unsent-send";
        let resp = request_on(
            &client,
            req("lwd:9067", WRITE),
            opts_on(network, 2000),
            true,
            Some(&set),
            Some(&hedging()),
        )
        .await
        .expect("not written the first time: sent once on a new connection");
        assert_eq!(resp.status(), 200);
        assert_eq!(good_count.load(Ordering::SeqCst), 1, "sent exactly once");
        assert_eq!(crate::health::lwd_unsent_retries(network, "send"), 1);
        assert!(set.state.lock().failed.contains_key(&closed));
        assert_eq!(crate::health::lwd_call_totals(network), (1, 0));
        // Every byte the first connection was given: the preface and whole connection-level
        // frames (stream 0), no frame of a request.
        let written = connector.written.lock().unwrap().clone();
        let frames = h2_frames(&written);
        assert!(
            frames.iter().all(|(_, stream)| *stream == 0),
            "nothing of the request was written: {frames:?}"
        );
        // One retry only: when the retry fails too (here: nothing listens), the call fails
        // with the retry's error and nothing is sent a third time.
        let dead = refusing().await;
        let set = EndpointSet::fixed(vec![dead]);
        let network = "test-unsent-once";
        let err = request_on(
            &client,
            req("lwd:9067", WRITE),
            opts_on(network, 2000),
            true,
            Some(&set),
            None,
        )
        .await
        .expect_err("the retry is refused");
        assert!(!err.not_written(), "{err:?}");
        assert_eq!(crate::health::lwd_unsent_retries(network, "send"), 1);
        assert_eq!(crate::health::lwd_call_totals(network), (0, 1));
    }

    /// A raw HTTP/2 server that lets the client open its first stream and then either
    /// refuses it (`RST_STREAM` with `REFUSED_STREAM`) or announces a shutdown that leaves it
    /// out (`GOAWAY` with last stream 0), without ever answering; counts the request HEADERS
    /// frames it received.
    async fn turning_the_request_away(goaway: bool) -> (SocketAddr, Arc<AtomicUsize>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let seen = seen.clone();
                tokio::spawn(async move {
                    let mut preface = [0u8; H2_PREFACE_LEN];
                    if stream.read_exact(&mut preface).await.is_err() {
                        return;
                    }
                    // The server's (empty) SETTINGS.
                    if stream
                        .write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0])
                        .await
                        .is_err()
                    {
                        return;
                    }
                    loop {
                        let mut header = [0u8; 9];
                        if stream.read_exact(&mut header).await.is_err() {
                            return;
                        }
                        let len = u32::from_be_bytes([0, header[0], header[1], header[2]]);
                        let mut payload = vec![0u8; len as usize];
                        if stream.read_exact(&mut payload).await.is_err() {
                            return;
                        }
                        // HEADERS: the request.
                        if header[3] != 1 {
                            continue;
                        }
                        seen.fetch_add(1, Ordering::SeqCst);
                        let id = [header[5], header[6], header[7], header[8]];
                        let frame: Vec<u8> = if goaway {
                            // GOAWAY, last stream 0, NO_ERROR.
                            vec![0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                        } else {
                            // RST_STREAM on the request's stream, REFUSED_STREAM (7).
                            vec![0, 0, 4, 3, 0, id[0], id[1], id[2], id[3], 0, 0, 0, 7]
                        };
                        if stream.write_all(&frame).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (addr, count)
    }

    /// A stream the peer refused and a shutdown that leaves the request out: the peer says
    /// it did not process the request, but the request was written. Not "not written": a
    /// `SendTransaction` is not sent again.
    #[tokio::test]
    async fn a_send_the_peer_turned_away_after_it_was_written_is_not_sent_again() {
        for goaway in [false, true] {
            let (turning_away, received) = turning_the_request_away(goaway).await;
            let (good, good_count) = answering().await;
            let set = EndpointSet::fixed(vec![turning_away, good]);
            set.mark_failed(good, Instant::now());
            let network = if goaway {
                "test-unsent-goaway"
            } else {
                "test-unsent-refused"
            };
            let err = request_with(
                req("lwd:9067", WRITE),
                opts_on(network, 2000),
                true,
                Some(&set),
                Some(&hedging()),
            )
            .await
            .expect_err("written: never sent a second time");
            assert!(
                matches!(err, RequestError::Http(_)),
                "goaway {goaway}: {err:?}"
            );
            assert!(!err.not_written(), "goaway {goaway}: {err:?}");
            assert_eq!(received.load(Ordering::SeqCst), 1);
            assert_eq!(good_count.load(Ordering::SeqCst), 0, "no second send");
            assert_eq!(crate::health::lwd_unsent_retries(network, "send"), 0);
        }
    }

    /// The bounds of reading a detached loser's body.
    #[tokio::test(start_paused = true)]
    async fn the_body_of_a_detached_loser_is_read_within_its_bounds() {
        use http_body_util::StreamBody;
        use hyper::body::Frame;
        type Item = Result<Frame<Bytes>, std::convert::Infallible>;
        let chunk = || -> Item { Ok(Frame::data(Bytes::from_static(&[0u8; 1024]))) };
        let limit = Duration::from_secs(10);
        // Exactly the byte bound, then the end: read to the end.
        let exact = StreamBody::new(futures_util::stream::iter((0..4).map(|_| chunk())));
        assert!(drained(exact, limit, 4096).await);
        // One byte more than the bound: given up.
        let over = StreamBody::new(futures_util::stream::iter(vec![
            chunk(),
            Ok(Frame::data(Bytes::from_static(&[0u8; 1]))),
        ]));
        assert!(!drained(over, limit, 1024).await);
        // A body that never ends: given up at the byte bound.
        let endless = StreamBody::new(futures_util::stream::repeat_with(chunk));
        assert!(!drained(endless, limit, 64 * 1024).await);
        // A body that stalls: given up at the time bound, not before.
        let stalled = StreamBody::new(futures_util::stream::pending::<Item>());
        let start = tokio::time::Instant::now();
        assert!(!drained(stalled, limit, 4096).await);
        assert_eq!(start.elapsed(), limit);
        // An empty body has ended.
        assert!(drained(Full::new(Bytes::new()), limit, 0).await);
        // Frames without data, for ever: each costs one byte of the bound.
        let empty = || -> Item { Ok(Frame::data(Bytes::new())) };
        let hollow = StreamBody::new(futures_util::stream::repeat_with(empty));
        assert!(!drained(hollow, limit, 4096).await);
        // A few of them and the end: read to the end.
        let few = StreamBody::new(futures_util::stream::iter((0..3).map(|_| empty())));
        assert!(drained(few, limit, 4096).await);
    }

    /// Frames that are always ready do not outlast the time bound (a timeout alone polls
    /// its future first and would never fire). On the real clock: nothing waits here, so a
    /// paused one would not move.
    #[tokio::test]
    async fn the_time_bound_of_a_detached_loser_holds_for_frames_that_are_always_ready() {
        use http_body_util::StreamBody;
        use hyper::body::Frame;
        type Item = Result<Frame<Bytes>, std::convert::Infallible>;
        let ready = StreamBody::new(futures_util::stream::repeat_with(|| -> Item {
            Ok(Frame::data(Bytes::new()))
        }));
        let limit = Duration::from_millis(50);
        // Another task of this (single-threaded) runtime: it runs only when the reader
        // gives way.
        let beats = Arc::new(AtomicUsize::new(0));
        let heartbeat = {
            let beats = beats.clone();
            tokio::spawn(async move {
                loop {
                    beats.fetch_add(1, Ordering::SeqCst);
                    tokio::task::yield_now().await;
                }
            })
        };
        let start = Instant::now();
        assert!(!drained(ready, limit, usize::MAX).await);
        assert!(start.elapsed() >= limit);
        assert!(
            beats.load(Ordering::SeqCst) > 1,
            "other tasks ran while the body was read"
        );
        heartbeat.abort();
    }

    /// A connector whose connections are never established: counts the attempts it was asked
    /// for and the ones that were abandoned (their future dropped).
    #[derive(Clone, Default)]
    struct PendingConnector {
        calls: Arc<AtomicUsize>,
        abandoned: Arc<AtomicUsize>,
    }

    impl tower::Service<hyper::Uri> for PendingConnector {
        type Response = ClosedAfterHandshake;
        type Error = std::io::Error;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<ClosedAfterHandshake, std::io::Error>>
                    + Send,
            >,
        >;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, _dst: hyper::Uri) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let abandoned = Ended(self.abandoned.clone());
            Box::pin(async move {
                let _abandoned = abandoned;
                std::future::pending::<Result<ClosedAfterHandshake, std::io::Error>>().await
            })
        }
    }

    /// A loser whose request was not given to a connection is dropped, not detached:
    /// detaching it would send the call after the answer is there. Both cases: an attempt
    /// that was never polled, and one that is still connecting.
    #[tokio::test]
    async fn a_loser_that_was_not_sent_yet_is_dropped_without_sending() {
        let h = hedging();
        let network = "test-hedge-detached-unsent";
        let connector = PendingConnector::default();
        let client: Client<PendingConnector, Full<Bytes>> =
            Client::builder(hyper_util::rt::TokioExecutor::new())
                .http2_only(true)
                .build(connector.clone());
        let deadline = Instant::now() + Duration::from_secs(30);
        // Never polled: not even a connection was asked for, and none is after the drop.
        let unsent = attempt(&client, &req("lwd:9067", READ), None, deadline);
        assert!(!unsent.handed_over());
        detach_loser(&h, network, unsent);
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0, "nothing started");
        // Still connecting: polled until the client asked for its connection, which is never
        // established.
        let mut connecting = attempt(&client, &req("lwd:9067", READ), None, deadline);
        let start = Instant::now();
        while connector.calls.load(Ordering::SeqCst) == 0 {
            assert!(futures_util::poll!(&mut connecting.head).is_pending());
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "the client never asked for a connection"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(futures_util::poll!(&mut connecting.head).is_pending());
        assert!(!connecting.handed_over());
        assert_eq!(connector.abandoned.load(Ordering::SeqCst), 0);
        detach_loser(&h, network, connecting);
        // Dropped: the connection attempt is abandoned, so no request can follow it.
        eventually("the connection attempt was abandoned", || {
            connector.abandoned.load(Ordering::SeqCst) == 1
        })
        .await;
        assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
        assert_eq!(crate::health::lwd_hedges(network, "loser_detached"), 0);
        assert_eq!(crate::health::lwd_hedges(network, "loser_cancelled"), 0);
        assert_eq!(h.detached.available_permits(), DEFAULT_HEDGE_MAX_INFLIGHT);
        // One that got its answer was given to a connection.
        let (other, _) = answering().await;
        let mut sent = attempt(
            &fresh_client(),
            &req(&other.to_string(), READ),
            None,
            Instant::now() + Duration::from_secs(10),
        );
        (&mut sent.head).await.expect("answered");
        assert!(sent.handed_over());
    }

    /// An h2c server that takes a request and then drops its connection without an answer;
    /// counts the requests it received.
    async fn dropping_after_the_request() -> (SocketAddr, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let seen = seen.clone();
                let got = Arc::new(tokio::sync::Notify::new());
                let notify = got.clone();
                let service = hyper::service::service_fn(
                    move |_req: hyper::Request<hyper::body::Incoming>| {
                        let (seen, notify) = (seen.clone(), notify.clone());
                        async move {
                            seen.fetch_add(1, Ordering::SeqCst);
                            notify.notify_one();
                            std::future::pending::<()>().await;
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                                Bytes::new(),
                            )))
                        }
                    },
                );
                tokio::spawn(async move {
                    let builder = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    );
                    let conn =
                        builder.serve_connection(hyper_util::rt::TokioIo::new(stream), service);
                    tokio::select! {
                        _ = conn => {}
                        _ = got.notified() => {}
                    }
                });
            }
        });
        (addr, count)
    }

    #[tokio::test]
    async fn a_send_whose_connection_fails_after_the_request_is_not_sent_again() {
        let (dropping, received) = dropping_after_the_request().await;
        let (good, good_count) = answering().await;
        let set = EndpointSet::fixed(vec![dropping, good]);
        set.mark_failed(good, Instant::now());
        let network = "test-unsent-ambiguous";
        let err = request_with(
            req("lwd:9067", WRITE),
            opts_on(network, 2000),
            true,
            Some(&set),
            Some(&hedging()),
        )
        .await
        .expect_err("the request reached the instance: never sent a second time");
        assert!(matches!(err, RequestError::Http(_)), "{err:?}");
        assert!(!err.not_written(), "{err:?}");
        assert_eq!(received.load(Ordering::SeqCst), 1);
        assert_eq!(good_count.load(Ordering::SeqCst), 0, "no second send");
        assert_eq!(crate::health::lwd_unsent_retries(network, "send"), 0);
        assert_eq!(crate::health::lwd_call_totals(network), (0, 1));
    }

    /// An h2c server that answers the first request of every connection and then closes that
    /// connection; counts connections and requests.
    async fn one_request_per_connection() -> (SocketAddr, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let (accepted, seen) = (connections.clone(), requests.clone());
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                accepted.fetch_add(1, Ordering::SeqCst);
                let seen = seen.clone();
                let got = Arc::new(tokio::sync::Notify::new());
                let notify = got.clone();
                let service = hyper::service::service_fn(
                    move |_req: hyper::Request<hyper::body::Incoming>| {
                        let (seen, notify) = (seen.clone(), notify.clone());
                        async move {
                            seen.fetch_add(1, Ordering::SeqCst);
                            notify.notify_one();
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
                    let builder = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    );
                    let conn =
                        builder.serve_connection(hyper_util::rt::TokioIo::new(stream), service);
                    tokio::pin!(conn);
                    tokio::select! {
                        _ = conn.as_mut() => {}
                        _ = got.notified() => {
                            // The answer in flight is completed, then the connection closed.
                            conn.as_mut().graceful_shutdown();
                            let _ = conn.await;
                        }
                    }
                });
            }
        });
        (addr, connections, requests)
    }

    /// A TCP connection that counts when the client is done with it (dropped).
    struct Watched {
        io: hyper_util::rt::TokioIo<tokio::net::TcpStream>,
        _closed: Ended,
    }

    impl hyper::rt::Read for Watched {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: hyper::rt::ReadBufCursor<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            hyper::rt::Read::poll_read(std::pin::Pin::new(&mut self.io), cx, buf)
        }
    }

    impl hyper::rt::Write for Watched {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<Result<usize, std::io::Error>> {
            hyper::rt::Write::poll_write(std::pin::Pin::new(&mut self.io), cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            hyper::rt::Write::poll_flush(std::pin::Pin::new(&mut self.io), cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            hyper::rt::Write::poll_shutdown(std::pin::Pin::new(&mut self.io), cx)
        }
    }

    impl hyper_util::client::legacy::connect::Connection for Watched {
        fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
            hyper_util::client::legacy::connect::Connected::new()
        }
    }

    /// Connects over TCP and counts the connections it opened and the ones the client is
    /// done with.
    #[derive(Clone, Default)]
    struct WatchedConnector {
        opened: Arc<AtomicUsize>,
        closed: Arc<AtomicUsize>,
    }

    impl tower::Service<hyper::Uri> for WatchedConnector {
        type Response = Watched;
        type Error = std::io::Error;
        type Future = std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Watched, std::io::Error>> + Send>,
        >;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, dst: hyper::Uri) -> Self::Future {
            let (opened, closed) = (self.opened.clone(), self.closed.clone());
            Box::pin(async move {
                let host = dst.host().unwrap_or("127.0.0.1").to_string();
                let port = dst.port_u16().unwrap_or(80);
                let stream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
                opened.fetch_add(1, Ordering::SeqCst);
                Ok(Watched {
                    io: hyper_util::rt::TokioIo::new(stream),
                    _closed: Ended(closed),
                })
            })
        }
    }

    /// A send after the upstream closed the connection the client had pooled arrives exactly
    /// once, on a new connection. The test waits until the client itself is done with the
    /// first connection (no timing); from there the client opens a new one for the send,
    /// which is the client library's handling, kept visible here.
    #[tokio::test]
    async fn a_send_after_the_upstream_closed_the_pooled_connection_is_received_once() {
        let (upstream, connections, requests) = one_request_per_connection().await;
        // One client for both calls: the second would find the first one's connection in
        // its pool.
        let connector = WatchedConnector::default();
        let client: Client<WatchedConnector, Full<Bytes>> =
            Client::builder(hyper_util::rt::TokioExecutor::new())
                .http2_only(true)
                .build(connector.clone());
        let authority = upstream.to_string();
        let network = "test-unsent-pooled";
        request_on(
            &client,
            req(&authority, READ),
            opts_on(network, 5000),
            true,
            None,
            None,
        )
        .await
        .expect("the read answers");
        assert_eq!(connector.opened.load(Ordering::SeqCst), 1);
        // The upstream closes the connection after its answer; the client ends its side.
        eventually("the client is done with the first connection", || {
            connector.closed.load(Ordering::SeqCst) == 1
        })
        .await;
        let resp = request_on(
            &client,
            req(&authority, WRITE),
            opts_on(network, 5000),
            true,
            None,
            None,
        )
        .await
        .expect("sent on a new connection");
        assert_eq!(resp.status(), 200);
        assert_eq!(
            connector.opened.load(Ordering::SeqCst),
            2,
            "a new connection for the send"
        );
        assert_eq!(connections.load(Ordering::SeqCst), 2);
        assert_eq!(requests.load(Ordering::SeqCst), 2, "the send arrived once");
    }
}

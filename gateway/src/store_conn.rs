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

//! A store connection that follows a failover of a managed Redis.
//!
//! redis-rs' `ConnectionManager` replaces its connection only when the socket breaks (reset,
//! EOF, broken pipe). A managed Redis with automatic failover (one endpoint name that is moved
//! to the promoted replica) usually keeps the demoted primary running as a replica for a while:
//! its open connections stay up, every write is answered `READONLY` and `WAIT` is refused, and
//! nothing breaks the socket until that node restarts, which can take minutes. A connection that
//! hangs without an RST has the same effect.
//!
//! `StoreConn` wraps one `ConnectionManager` and replaces it with a freshly opened one when a
//! command reports such a signal: `READONLY`, `MOVED`, `MASTERDOWN`, `LOADING`, `UNBLOCKED`, a
//! refused `WAIT` on a replica, an I/O error, or consecutive timeouts. Every new connection
//! resolves the endpoint name again (redis-rs resolves on each connect, and the container's
//! resolver keeps no cache), so it reaches the node the name points at now. For a store that
//! must be a primary ([`Role::Primary`], the replay stores) the new connection is accepted only
//! once that node reports `ROLE master`; until then the old connection stays in place and keeps
//! failing, so callers stay fail-closed. One reconnect runs at a time, with a bounded backoff.
//!
//! Callers report every outcome (`observe_*`); nothing here retries a command.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use redis::aio::ConnectionManager;
use redis::{ErrorKind, RedisError, Value};
use tokio::sync::watch;
use tokio::time::timeout;
use tracing::{info, warn};

/// Budget of one connection attempt (TCP, TLS, AUTH), also used per attempt inside
/// `ConnectionManager`, so an address that no longer answers costs at most this long.
pub const STORE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// First and last delay between reconnect attempts.
const RECONNECT_MIN_BACKOFF: Duration = Duration::from_millis(100);
const RECONNECT_MAX_BACKOFF: Duration = Duration::from_secs(2);
/// After a connection was replaced, signals are ignored for this long: they come from commands
/// that were still running on the old connection.
const SIGNAL_HOLDOFF: Duration = Duration::from_millis(500);
/// A replacement that has been running this long counts the store as down (`usable`).
const RECONNECT_GRACE: Duration = Duration::from_secs(2);
/// At most one `ROLE` check per this interval (after a short `WAIT`, and in housekeeping).
const ROLE_CHECK_INTERVAL: Duration = Duration::from_secs(1);
/// Budget of one `ROLE` check of an open connection. `ROLE` answers at once; housekeeping checks
/// several connections, and a hung one must not hold the others up for a connect timeout.
pub const ROLE_CHECK_TIMEOUT: Duration = Duration::from_secs(1);
/// A node that answers `LOADING` (it restarted and reads its data set) is reached again by every
/// new connection. Each reconnect for `LOADING` doubles the hold-off before the next one, from
/// `SIGNAL_HOLDOFF` up to `SIGNAL_HOLDOFF * 2^LOADING_BACKOFF_STEPS` (8 s), until a command
/// succeeds.
const LOADING_BACKOFF_STEPS: u32 = 4;
/// `ConnectionManager`'s own retries of a refused connection (100 ms base, factor 2).
const MANAGER_RETRIES: usize = 3;

/// How long after a replacement a signal `reason` is ignored, after `loading_streak`
/// reconnects for `LOADING` in a row.
fn signal_holdoff(reason: &str, loading_streak: u32) -> Duration {
    if reason == "LOADING" {
        SIGNAL_HOLDOFF * (1u32 << loading_streak.min(LOADING_BACKOFF_STEPS))
    } else {
        SIGNAL_HOLDOFF
    }
}

/// The hold-off for a signal `reason`. Any signal other than `LOADING` (a role change,
/// `READONLY`, a broken connection) ends a `LOADING` streak first: its reconnect must not wait
/// for the `LOADING` backoff.
fn holdoff_after(reason: &str, loading_streak: &AtomicU32) -> Duration {
    if reason != "LOADING" {
        loading_streak.store(0, Ordering::Relaxed);
    }
    signal_holdoff(reason, loading_streak.load(Ordering::Relaxed))
}

/// Whether a failed reopen met a node that answers `LOADING`.
fn is_loading(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<RedisError>()
            .is_some_and(|r| r.kind() == redis::ErrorKind::BusyLoadingError)
    }) || format!("{e:#}").contains("LOADING")
}

/// The pause before the next reopen attempt: `backoff`, or for a node that answers `LOADING`
/// the `LOADING` backoff after `streak` such answers (`signal_holdoff`), whichever is longer.
fn reopen_backoff(backoff: Duration, loading: bool, streak: u32) -> Duration {
    if loading {
        backoff.max(signal_holdoff("LOADING", streak))
    } else {
        backoff
    }
}

/// The pause before the next attempt to open a store connection after the failed attempt `e`:
/// `backoff`, or for a node that answers `LOADING` (`streak` such answers, counted here) at
/// least the `LOADING` backoff (`signal_holdoff`). The one rule of every reopen loop: a
/// `StoreConn` reconnect, and a replay peer's main, `WAIT` and retry connections.
pub fn reopen_pause(e: &anyhow::Error, backoff: Duration, streak: &mut u32) -> Duration {
    if is_loading(e) {
        *streak = streak.saturating_add(1);
        reopen_backoff(backoff, true, *streak)
    } else {
        // Another error in a LOADING period (a refused connection while the node restarts)
        // keeps the step reached: only a success ends the period.
        backoff
    }
}

/// What the store must be for a connection to it to be usable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Writes must succeed (replay nonces, `WAIT`): a replica is a failover signal.
    Primary,
    /// Fail-open stores, some of which are read replicas on purpose: only a broken or hung
    /// connection is replaced.
    Any,
}

/// Whether `e` means that the connection no longer reaches a usable store.
pub fn is_failover_signal(e: &RedisError, role: Role) -> bool {
    if e.is_io_error() || e.is_connection_dropped() || e.is_unrecoverable_error() {
        return true;
    }
    // A blocked WAIT/WAITAOF answered when its primary was demoted.
    if e.code() == Some("UNBLOCKED") {
        return true;
    }
    if role != Role::Primary {
        return false;
    }
    match e.kind() {
        ErrorKind::ReadOnly
        | ErrorKind::Moved
        | ErrorKind::MasterDown
        | ErrorKind::BusyLoadingError => true,
        // "WAIT cannot be used with replica instances", the same for WAITAOF.
        ErrorKind::ResponseError => e.detail().is_some_and(|d| d.contains("replica")),
        _ => false,
    }
}

/// `e` as text without network addresses: a URL, an IP address (with or without a port) or a
/// `host:port` becomes `<addr>`. For log lines of store errors, which can name the endpoint.
pub fn redact_addrs(e: &impl std::fmt::Display) -> String {
    let text = e.to_string();
    let mut out = String::with_capacity(text.len());
    let mut token = String::new();
    let flush = |token: &mut String, out: &mut String| {
        if token.is_empty() {
            return;
        }
        let lead: &[char] = &['(', '{', '<', '\'', '"'];
        let trail: &[char] = &[')', ']', '}', '>', ',', ';', '\'', '"', '.', ':'];
        let core = token.trim_start_matches(lead).trim_end_matches(trail);
        if !core.is_empty()
            && (looks_like_addr(core) || looks_like_addr(core.trim_matches(['[', ']'])))
        {
            out.push_str(&token.replacen(core, "<addr>", 1));
        } else {
            out.push_str(token);
        }
        token.clear();
    };
    for c in text.chars() {
        if c.is_whitespace() {
            flush(&mut token, &mut out);
            out.push(c);
        } else {
            token.push(c);
        }
    }
    flush(&mut token, &mut out);
    out
}

/// Server error codes a log line may carry (`store_error`); any other code is logged as
/// `server error`. Never the detail after the code: a server can put anything there (an
/// address, a key, a value).
const LOGGED_CODES: &[&str] = &[
    "ERR",
    "READONLY",
    "MOVED",
    "ASK",
    "LOADING",
    "MASTERDOWN",
    "NOREPLICAS",
    "UNBLOCKED",
    "NOAUTH",
    "WRONGPASS",
    "NOPERM",
    "OOM",
    "BUSY",
    "BUSYKEY",
    "CLUSTERDOWN",
    "TRYAGAIN",
    "CROSSSLOT",
    "EXECABORT",
    "NOSCRIPT",
    "WRONGTYPE",
    "MISCONF",
    "NOPROTO",
];

/// A store error for a log line: its I/O kind (never its text, which can name the endpoint),
/// or its server code if listed in `LOGGED_CODES`, or the client's error category; never any
/// detail. The one function every store error goes through before it is logged.
pub fn store_error(e: &RedisError) -> String {
    if e.is_io_error() {
        return if e.is_timeout() {
            "I/O error: timed out".to_string()
        } else if e.is_connection_refusal() {
            "I/O error: connection refused".to_string()
        } else if e.is_connection_dropped() {
            "I/O error: connection dropped".to_string()
        } else {
            "I/O error".to_string()
        };
    }
    match e.code() {
        Some(code) if LOGGED_CODES.contains(&code) => code.to_string(),
        Some(_) => "server error".to_string(),
        None => format!("{:?}", e.kind()),
    }
}

/// Messages of this module's own connection checks that a log line may carry (`error_summary`).
const LOGGED_MESSAGES: &[&str] = &["ROLE timed out", "the endpoint still reaches a replica"];

/// `store_error` for an error from opening a store connection: the store error in it, an I/O
/// error's kind, a timeout, or one of `LOGGED_MESSAGES`; anything else is `connection failed`.
pub fn error_summary(e: &anyhow::Error) -> String {
    for cause in e.chain() {
        if let Some(r) = cause.downcast_ref::<RedisError>() {
            return store_error(r);
        }
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            return format!("I/O error: {:?}", io.kind());
        }
        if cause
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some()
        {
            return "timed out".to_string();
        }
    }
    let root = e.root_cause().to_string();
    if LOGGED_MESSAGES.contains(&root.as_str()) || root.starts_with("connect timed out after ") {
        root
    } else {
        "connection failed".to_string()
    }
}

fn looks_like_addr(s: &str) -> bool {
    // `endpoint=host:port`, `addr:192.0.2.1:6379` and the like: the part after the separator.
    if let Some((_, value)) = s.rsplit_once('=') {
        if !value.is_empty() && looks_like_addr(value) {
            return true;
        }
    }
    if s.contains("://") || s.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if looks_like_hostname(s) {
        return true;
    }
    if s.parse::<std::net::SocketAddr>().is_ok() {
        return true;
    }
    if let Some((host, port)) = s.rsplit_once(':') {
        let host_ok = !host.is_empty()
            && host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
        if host_ok && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            return true;
        }
    }
    false
}

/// A bare host name: dot-separated labels of letters, digits and `-`, at least two, the last of
/// two or more letters (`store.example.com`, `node-1.cache.internal`). Version numbers and
/// decimals have a numeric last label.
fn looks_like_hostname(s: &str) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    labels.len() >= 2
        && labels
            .iter()
            .all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        && labels
            .last()
            .is_some_and(|l| l.len() >= 2 && l.chars().all(|c| c.is_ascii_alphabetic()))
}

/// Whether `e` says something about the node rather than about one connection: it is no longer
/// the primary (`READONLY`, `MOVED`, `MASTERDOWN`, an unblocked `WAIT`, `WAIT` refused on a
/// replica). Every connection to that endpoint is then affected; an I/O error or a timeout on one
/// connection says nothing about the others.
pub fn is_role_signal(e: &RedisError) -> bool {
    if e.code() == Some("UNBLOCKED") {
        return true;
    }
    match e.kind() {
        ErrorKind::ReadOnly | ErrorKind::Moved | ErrorKind::MasterDown => true,
        ErrorKind::ResponseError => e.detail().is_some_and(|d| d.contains("replica")),
        _ => false,
    }
}

/// The metric label of a failover signal.
pub fn signal_reason(e: &RedisError) -> &'static str {
    match e.kind() {
        ErrorKind::ReadOnly => "READONLY",
        ErrorKind::Moved => "MOVED",
        ErrorKind::MasterDown => "MASTERDOWN",
        ErrorKind::BusyLoadingError => "LOADING",
        ErrorKind::ResponseError => "ERR",
        _ if e.code() == Some("UNBLOCKED") => "UNBLOCKED",
        _ => "error",
    }
}

/// Whether `ROLE` was refused because the store cannot or may not answer it: an unknown command
/// (`ERR ...`) or an ACL that does not allow it (`NOPERM ...`). The role is then unknown and the
/// connection is accepted, as for a store without `ROLE`: a write on a replica still fails with
/// `READONLY` (a failover signal), so the replay checks stay fail-closed; only the early check
/// against a demoted node is lost. Rejecting such a connection instead would never accept one:
/// every reconnect after a failover signal, and every peer connection, would keep failing.
pub fn role_not_available(e: &RedisError) -> bool {
    e.kind() == ErrorKind::ResponseError || e.code() == Some("NOPERM")
}

/// `ROLE`'s first element: Some(true) for a primary, Some(false) for anything else, None when
/// the store does not answer `ROLE` (treated as "unknown", accepted).
pub(crate) fn parse_role(v: &Value) -> Option<bool> {
    let Value::Bulk(items) = v else {
        return None;
    };
    match items.first()? {
        Value::Data(d) => Some(d.as_slice() == b"master"),
        Value::Status(s) => Some(s == "master"),
        _ => None,
    }
}

pub struct StoreConn {
    store: &'static str,
    network: String,
    client: redis::Client,
    role: Role,
    timeout_threshold: u32,
    conn: ArcSwap<ConnectionManager>,
    /// Incremented on every replacement; `wait_for_reconnect` watches it.
    generation: watch::Sender<u64>,
    /// The running replacement and its cause, in one value so that starting one and saying why
    /// are a single step: `IDLE`, `RECONNECT_FAILOVER` (a failover signal: counted in
    /// `failover_generation`), `RECONNECT_QUIET` (one stuck connection, `retire_quietly`).
    reconnecting: AtomicU8,
    consecutive_timeouts: AtomicU32,
    epoch: Instant,
    /// Milliseconds since `epoch` of the last replacement / `ROLE` check (0 = never).
    last_swap_ms: AtomicU64,
    last_role_check_ms: AtomicU64,
    /// Whether the last `ROLE` answer on the current connection said primary (true until one
    /// says otherwise, and again once a new connection is accepted).
    role_primary: AtomicBool,
    /// Reconnects for `LOADING` since the last successful command (`LOADING_BACKOFF_STEPS`).
    loading_streak: AtomicU32,
    /// Milliseconds since `epoch` when the running reconnect started (0 = none).
    reconnect_since_ms: AtomicU64,
    /// Replacements caused by a failover signal (not by `retire_quietly`): what a change of the
    /// store means for the WRITE fallback's window.
    failover_generation: AtomicU64,
    /// Woken once a replacement is in place (a `WAIT` pool waiting for an open connection).
    replaced: std::sync::OnceLock<Arc<tokio::sync::Notify>>,
}

const IDLE: u8 = 0;
const RECONNECT_FAILOVER: u8 = 1;
const RECONNECT_QUIET: u8 = 2;

impl StoreConn {
    /// Open the first connection; an error fails, like `ConnectionManager::new`.
    pub async fn connect(
        url: &str,
        store: &'static str,
        network: String,
        role: Role,
    ) -> anyhow::Result<Arc<Self>> {
        let client = redis::Client::open(url)?;
        let conn = open(&client).await?;
        Ok(Self::from_parts(client, conn, store, network, role))
    }

    /// Wrap an open connection to the store `client` points at.
    pub fn from_parts(
        client: redis::Client,
        conn: ConnectionManager,
        store: &'static str,
        network: String,
        role: Role,
    ) -> Arc<Self> {
        let (generation, _) = watch::channel(0u64);
        Arc::new(Self {
            store,
            network,
            client,
            role,
            timeout_threshold: match role {
                Role::Primary => 2,
                Role::Any => 3,
            },
            conn: ArcSwap::from_pointee(conn),
            generation,
            reconnecting: AtomicU8::new(IDLE),
            consecutive_timeouts: AtomicU32::new(0),
            epoch: Instant::now(),
            last_swap_ms: AtomicU64::new(0),
            last_role_check_ms: AtomicU64::new(0),
            role_primary: AtomicBool::new(true),
            loading_streak: AtomicU32::new(0),
            reconnect_since_ms: AtomicU64::new(0),
            failover_generation: AtomicU64::new(0),
            replaced: std::sync::OnceLock::new(),
        })
    }

    /// The current connection (a cheap clone of the multiplexed handle).
    pub fn get(&self) -> ConnectionManager {
        (**self.conn.load()).clone()
    }

    /// How many times the connection was replaced.
    pub fn generation(&self) -> u64 {
        *self.generation.borrow()
    }

    /// How many times the connection was replaced after a failover signal (not counting
    /// `retire_quietly`).
    pub fn failover_generation(&self) -> u64 {
        self.failover_generation.load(Ordering::Relaxed)
    }

    pub fn observe_ok(&self) {
        if self.consecutive_timeouts.load(Ordering::Relaxed) != 0 {
            self.consecutive_timeouts.store(0, Ordering::Relaxed);
        }
        if self.loading_streak.load(Ordering::Relaxed) != 0 {
            self.loading_streak.store(0, Ordering::Relaxed);
        }
    }

    /// Whether the connection can be trusted to reach the primary right now: no replacement is
    /// running and the last `ROLE` answer said primary (choosing a connection for a command).
    pub fn usable_now(&self) -> bool {
        self.role != Role::Primary
            || (self.reconnecting.load(Ordering::Acquire) == IDLE
                && self.role_primary.load(Ordering::Relaxed))
    }

    /// `usable_now` for health (`/healthz`): a `PING` still succeeds on a demoted primary, so a
    /// store whose last `ROLE` said replica counts as down, and so does one whose replacement
    /// has been running for longer than `RECONNECT_GRACE` (a failover signal was seen and the
    /// endpoint does not yet reach a node that says `ROLE master`). A replacement that is done
    /// within the grace (most take milliseconds) does not count.
    pub fn usable(&self) -> bool {
        if self.role != Role::Primary {
            return true;
        }
        if !self.role_primary.load(Ordering::Relaxed) {
            return false;
        }
        if self.reconnecting.load(Ordering::Acquire) == IDLE {
            return true;
        }
        let since = self.reconnect_since_ms.load(Ordering::Relaxed);
        since == 0 || self.now_ms().saturating_sub(since) <= RECONNECT_GRACE.as_millis() as u64
    }

    pub fn observe_error(self: &Arc<Self>, e: &RedisError) {
        if is_failover_signal(e, self.role) {
            self.trigger(signal_reason(e));
        }
    }

    pub fn observe_timeout(self: &Arc<Self>) {
        let n = self.consecutive_timeouts.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= self.timeout_threshold {
            self.consecutive_timeouts.store(0, Ordering::Relaxed);
            self.trigger("timeout");
        }
    }

    /// Report a `RedisResult` (no outer timeout).
    pub fn observe<T>(self: &Arc<Self>, r: &redis::RedisResult<T>) {
        match r {
            Ok(_) => self.observe_ok(),
            Err(e) => self.observe_error(e),
        }
    }

    /// Report a command bounded by `tokio::time::timeout`.
    pub fn observe_timed<T>(
        self: &Arc<Self>,
        r: &Result<redis::RedisResult<T>, tokio::time::error::Elapsed>,
    ) {
        match r {
            Ok(r) => self.observe(r),
            Err(_) => self.observe_timeout(),
        }
    }

    /// Fewer replica acknowledgements than required: on a primary that is normal (a replica is
    /// lagging or resynchronising), on a demoted node it is not, so ask the node (rate-limited).
    pub fn observe_short_ack(self: &Arc<Self>) {
        if self.role != Role::Primary || !self.role_check_due() {
            return;
        }
        let this = self.clone();
        tokio::spawn(async move { this.check_role().await });
    }

    /// Housekeeping: for a primary store, replace the connection if its node is no longer one
    /// (an idle gateway sees no `READONLY` to react to).
    pub async fn verify_primary(self: &Arc<Self>) {
        if self.role == Role::Primary && self.role_check_due() {
            self.check_role().await;
        }
    }

    /// `verify_primary` without its own timeout, for a caller that bounds the command itself
    /// and holds the connection until it is answered (a `WAIT` pool's housekeeping check:
    /// dropping the `ROLE` at a timeout of its own would hand the connection back with the
    /// command still on it).
    pub async fn verify_primary_unbounded(self: &Arc<Self>) {
        if self.role == Role::Primary && self.role_check_due() {
            let mut conn = self.get();
            let answer = redis::cmd("ROLE").query_async::<_, Value>(&mut conn).await;
            self.apply_role(answer);
        }
    }

    /// Wait until the connection was replaced after `since` (a `generation()`), at most `max`.
    pub async fn wait_for_reconnect(&self, since: u64, max: Duration) -> bool {
        let mut rx = self.generation.subscribe();
        let changed = timeout(max, rx.wait_for(|g| *g != since)).await;
        matches!(changed, Ok(Ok(_)))
    }

    fn now_ms(&self) -> u64 {
        // +1 so that 0 stays "never".
        self.epoch.elapsed().as_millis() as u64 + 1
    }

    fn role_check_due(&self) -> bool {
        let now = self.now_ms();
        let last = self.last_role_check_ms.load(Ordering::Relaxed);
        if last != 0 && now.saturating_sub(last) < ROLE_CHECK_INTERVAL.as_millis() as u64 {
            return false;
        }
        self.last_role_check_ms
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    async fn check_role(self: &Arc<Self>) {
        let mut conn = self.get();
        let answer = timeout(
            ROLE_CHECK_TIMEOUT,
            redis::cmd("ROLE").query_async::<_, Value>(&mut conn),
        )
        .await;
        if let Ok(answer) = answer {
            self.apply_role(answer);
        }
    }

    /// What a `ROLE` answer means for the connection.
    fn apply_role(self: &Arc<Self>, answer: redis::RedisResult<Value>) {
        match answer {
            Ok(v) => match parse_role(&v) {
                Some(false) => {
                    self.role_primary.store(false, Ordering::Relaxed);
                    self.trigger("role");
                }
                Some(true) => self.role_primary.store(true, Ordering::Relaxed),
                None => {}
            },
            Err(e) => self.observe_error(&e),
        }
    }

    /// Replace the connection (new name resolution, primary only) although no command reported a
    /// failover signal: for a node that still says `ROLE master` but has stopped acknowledging
    /// writes on any replica for a long time (a primary the endpoint may have left behind).
    pub fn force_reconnect(self: &Arc<Self>, reason: &'static str) {
        self.trigger(reason);
    }

    /// Woken once a replacement of this connection is in place (set once).
    pub fn set_replaced_notify(&self, notify: Arc<tokio::sync::Notify>) {
        let _ = self.replaced.set(notify);
    }

    /// Replace this connection only (it timed out; a `WAIT` connection of a pool), and only if
    /// it is still the one of `generation` (never its replacement): unlike a failover signal,
    /// `failover_generation` does not change, so nothing treats it as a change of the store.
    /// Whether a replacement was started.
    pub fn retire_quietly(self: &Arc<Self>, reason: &'static str, generation: u64) -> bool {
        self.start_reconnect(reason, RECONNECT_QUIET, Some(generation))
    }

    /// Start a reconnect for a failover signal unless one is running or the connection was just
    /// replaced. Whether one was started. A quiet one that is running is turned into a
    /// failover one (its replacement then counts as a change of the store).
    fn trigger(self: &Arc<Self>, reason: &'static str) -> bool {
        self.start_reconnect(reason, RECONNECT_FAILOVER, None)
    }

    /// Give up a quiet replacement just claimed (its connection was replaced meanwhile): back to
    /// idle, unless a failover signal turned it into a failover one meanwhile, whose reconnect
    /// must then run (false).
    fn abandon_quiet(&self) -> bool {
        self.reconnecting
            .compare_exchange(RECONNECT_QUIET, IDLE, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn start_reconnect(
        self: &Arc<Self>,
        reason: &'static str,
        cause: u8,
        only_generation: Option<u64>,
    ) -> bool {
        let last = self.last_swap_ms.load(Ordering::Relaxed);
        let holdoff = holdoff_after(reason, &self.loading_streak);
        if last != 0 && self.now_ms().saturating_sub(last) < holdoff.as_millis() as u64 {
            return false;
        }
        if let Err(running) =
            self.reconnecting
                .compare_exchange(IDLE, cause, Ordering::AcqRel, Ordering::Acquire)
        {
            if cause == RECONNECT_FAILOVER
                && running == RECONNECT_QUIET
                && self
                    .reconnecting
                    .compare_exchange(
                        RECONNECT_QUIET,
                        RECONNECT_FAILOVER,
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    )
                    .is_ok()
            {
                // The running replacement now stands for this failover signal: counted under
                // its reason (the quiet one was counted as a timeout).
                crate::health::record_store_reconnect(&self.network, self.store, reason);
            }
            return false;
        }
        // The generation only changes while a replacement runs, and none ran from here on: if
        // it is still `only_generation`, the connection to replace is the current one.
        if only_generation.is_some_and(|g| g != self.generation()) && self.abandon_quiet() {
            return false;
        }
        self.reconnect_since_ms
            .store(self.now_ms(), Ordering::Relaxed);
        if reason == "LOADING" {
            self.loading_streak.fetch_add(1, Ordering::Relaxed);
        }
        if crate::health::warn_due(&self.network, "store_reconnect") {
            warn!(network = %self.network, store = self.store, reason, "Store connection failover signal: reconnecting");
        }
        crate::health::record_store_reconnect(&self.network, self.store, reason);
        let this = self.clone();
        tokio::spawn(async move {
            let started = Instant::now();
            let mut backoff = RECONNECT_MIN_BACKOFF;
            let mut attempts = 0u32;
            loop {
                attempts += 1;
                match this.open_usable().await {
                    Ok(conn) => {
                        this.conn.store(Arc::new(conn));
                        // open_usable accepted it on a node that says ROLE master (or knows no
                        // ROLE).
                        this.role_primary.store(true, Ordering::Relaxed);
                        this.consecutive_timeouts.store(0, Ordering::Relaxed);
                        this.last_swap_ms.store(this.now_ms(), Ordering::Relaxed);
                        // Counted before the generation moves (its watchers read it then).
                        let cause = this.reconnecting.load(Ordering::Acquire);
                        if cause != RECONNECT_QUIET {
                            this.failover_generation.fetch_add(1, Ordering::Relaxed);
                        }
                        this.generation.send_modify(|g| *g += 1);
                        this.reconnect_since_ms.store(0, Ordering::Relaxed);
                        // A failover signal that turned this quiet replacement into a failover
                        // one meanwhile is counted too.
                        let ended = this.reconnecting.swap(IDLE, Ordering::AcqRel);
                        if cause == RECONNECT_QUIET && ended != RECONNECT_QUIET {
                            this.failover_generation.fetch_add(1, Ordering::Relaxed);
                        }
                        if let Some(n) = this.replaced.get() {
                            n.notify_waiters();
                        }
                        crate::health::record_store_reconnect(
                            &this.network,
                            this.store,
                            "replaced",
                        );
                        info!(
                            network = %this.network,
                            store = this.store,
                            attempts,
                            elapsed_ms = started.elapsed().as_millis() as u64,
                            "Store connection replaced"
                        );
                        return;
                    }
                    Err(e) => {
                        if crate::health::warn_due(&this.network, "store_reconnect_attempt") {
                            warn!(network = %this.network, store = this.store, attempts, error = %error_summary(&e), "Store reconnect attempt failed");
                        }
                        // A node that answers LOADING (restarted, reading its data set) is
                        // asked again after the LOADING backoff, not every RECONNECT_MIN_BACKOFF.
                        let mut streak = this.loading_streak.load(Ordering::Relaxed);
                        let pause = reopen_pause(&e, backoff, &mut streak);
                        this.loading_streak.store(streak, Ordering::Relaxed);
                        tokio::time::sleep(pause).await;
                        backoff = (backoff * 2).min(RECONNECT_MAX_BACKOFF);
                    }
                }
            }
        });
        true
    }

    /// A new connection (new name resolution), accepted for a primary store only once its node
    /// reports `ROLE master` (or does not know `ROLE`).
    async fn open_usable(&self) -> anyhow::Result<ConnectionManager> {
        open_checked(&self.client, self.role).await
    }
}

/// The warning of `role_not_available` is logged once per process.
static ROLE_UNAVAILABLE_WARNED: AtomicBool = AtomicBool::new(false);

/// `open`, and for `Role::Primary` accept the connection only if its node reports `ROLE master`
/// (or does not know `ROLE`, or its ACL does not allow it: `role_not_available`): right after a
/// failover the endpoint name can still reach the demoted node for a few seconds.
pub async fn open_checked(client: &redis::Client, role: Role) -> anyhow::Result<ConnectionManager> {
    let mut conn = open(client).await?;
    if role == Role::Primary {
        let answer = timeout(
            STORE_CONNECT_TIMEOUT,
            redis::cmd("ROLE").query_async::<_, Value>(&mut conn),
        )
        .await
        .map_err(|_| anyhow::anyhow!("ROLE timed out"))?;
        match answer {
            Ok(v) if parse_role(&v) == Some(false) => {
                anyhow::bail!("the endpoint still reaches a replica")
            }
            Ok(_) => {}
            // A store without ROLE, or an ACL without it: accepted, its writes still report
            // READONLY.
            Err(e) if role_not_available(&e) => {
                if !ROLE_UNAVAILABLE_WARNED.swap(true, Ordering::Relaxed) {
                    warn!(error = %store_error(&e), "Store does not answer ROLE (unknown command or not allowed by its ACL): connections are accepted without the primary check; writes on a replica still fail with READONLY");
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(conn)
}

/// Open a `ConnectionManager` within `STORE_CONNECT_TIMEOUT` (also its per-attempt timeout).
pub async fn open(client: &redis::Client) -> anyhow::Result<ConnectionManager> {
    let manager = ConnectionManager::new_with_backoff_and_timeouts(
        client.clone(),
        2,
        100,
        MANAGER_RETRIES,
        Duration::MAX,
        STORE_CONNECT_TIMEOUT,
    );
    match timeout(STORE_CONNECT_TIMEOUT * 2, manager).await {
        Ok(conn) => Ok(conn?),
        Err(_) => anyhow::bail!(
            "connect timed out after {}s",
            (STORE_CONNECT_TIMEOUT * 2).as_secs()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_loading_node_is_reopened_after_the_loading_backoff() {
        let b = Duration::from_millis(100);
        assert_eq!(reopen_backoff(b, false, 3), b);
        assert_eq!(reopen_backoff(b, true, 1), SIGNAL_HOLDOFF * 2);
        assert_eq!(
            reopen_backoff(b, true, 10),
            SIGNAL_HOLDOFF * (1 << LOADING_BACKOFF_STEPS)
        );
        let e = anyhow::Error::from(server_error(
            "LOADING Redis is loading the dataset in memory",
        ));
        assert!(is_loading(&e));
        assert!(!is_loading(&anyhow::anyhow!("connection refused")));
        // The same rule for every reopen loop.
        let mut streak = 0;
        assert_eq!(reopen_pause(&e, b, &mut streak), SIGNAL_HOLDOFF * 2);
        assert_eq!(reopen_pause(&e, b, &mut streak), SIGNAL_HOLDOFF * 4);
        assert_eq!(
            reopen_pause(&anyhow::anyhow!("connection refused"), b, &mut streak),
            b
        );
        assert_eq!(streak, 2, "another error keeps the LOADING step");
        assert_eq!(reopen_pause(&e, b, &mut streak), SIGNAL_HOLDOFF * 8);
    }

    /// A quiet retirement replaces only the connection of the generation it names (never a
    /// replacement), and is not counted as a change of the store.
    #[tokio::test]
    async fn a_quiet_retirement_replaces_only_the_named_generation() {
        use crate::store::test_support::{store_missing, STORE_CONNECT_TIMEOUT, TEST_STORE};
        let url = format!("redis://{TEST_STORE}");
        let connected = tokio::time::timeout(
            STORE_CONNECT_TIMEOUT,
            StoreConn::connect(&url, "test", "testnet-retire".to_string(), Role::Primary),
        )
        .await;
        let c = match connected {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => return store_missing(&format!("the test store {url}"), &e),
            Err(_) => {
                return store_missing(
                    &format!("the test store {url}"),
                    &format!("no connection within {STORE_CONNECT_TIMEOUT:?}"),
                )
            }
        };
        let g = c.generation();
        assert!(
            !c.retire_quietly("timeout", g + 1),
            "not the current connection"
        );
        assert!(c.usable_now(), "nothing started");
        assert!(c.retire_quietly("timeout", g));
        assert!(c.wait_for_reconnect(g, Duration::from_secs(5)).await);
        assert_eq!(
            c.failover_generation(),
            0,
            "quiet: not a change of the store"
        );
        assert!(c.usable_now());
        // A quiet replacement given up for a stale generation goes back to idle, unless a
        // failover signal upgraded it meanwhile: then it stays claimed and runs.
        c.reconnecting.store(RECONNECT_QUIET, Ordering::Release);
        assert!(c.abandon_quiet());
        assert_eq!(c.reconnecting.load(Ordering::Acquire), IDLE);
        c.reconnecting.store(RECONNECT_FAILOVER, Ordering::Release);
        assert!(!c.abandon_quiet());
        assert_eq!(c.reconnecting.load(Ordering::Acquire), RECONNECT_FAILOVER);
        c.reconnecting.store(IDLE, Ordering::Release);
        // A failover signal that upgrades a running quiet replacement is counted under its own
        // reason.
        crate::health::init_metrics();
        let upgraded = || -> f64 {
            crate::health::REGISTRY
                .gather()
                .iter()
                .filter(|f| f.get_name() == "ohttp_store_reconnect_total")
                .flat_map(|f| f.get_metric().iter())
                .filter(|m| {
                    let l = m.get_label();
                    let has = |k: &str, v: &str| {
                        l.iter().any(|p| p.get_name() == k && p.get_value() == v)
                    };
                    has("network", "testnet-retire")
                        && has("store", "test")
                        && has("reason", "READONLY")
                })
                .map(|m| m.get_counter().get_value())
                .sum()
        };
        let before = upgraded();
        c.reconnecting.store(RECONNECT_QUIET, Ordering::Release);
        c.last_swap_ms.store(0, Ordering::Relaxed);
        assert!(!c.trigger("READONLY"), "a replacement is running already");
        assert_eq!(c.reconnecting.load(Ordering::Acquire), RECONNECT_FAILOVER);
        assert_eq!(upgraded(), before + 1.0);
        c.reconnecting.store(IDLE, Ordering::Release);
    }

    fn server_error(line: &str) -> RedisError {
        // Parse a RESP error line the way the client does.
        let mut parser = redis::Parser::new();
        match parser.parse_value(format!("-{line}\r\n").as_bytes()) {
            Err(e) => e,
            Ok(v) => panic!("not an error: {v:?}"),
        }
    }

    #[test]
    fn test_failover_signals() {
        let readonly = server_error("READONLY You can't write against a read only replica.");
        assert!(is_failover_signal(&readonly, Role::Primary));
        assert!(!is_failover_signal(&readonly, Role::Any));
        let moved = server_error("MOVED 3999 127.0.0.1:6381");
        assert!(is_failover_signal(&moved, Role::Primary));
        let wait = server_error("ERR WAIT cannot be used with replica instances. Please also note that writes to replicas are just local and are not propagated.");
        assert!(is_failover_signal(&wait, Role::Primary));
        assert!(!is_failover_signal(&wait, Role::Any));
        let unblocked = server_error(
            "UNBLOCKED force unblock from blocking operation, instance state changed (master -> replica?)",
        );
        assert!(is_failover_signal(&unblocked, Role::Primary));
        assert!(is_failover_signal(&unblocked, Role::Any));
        assert!(is_failover_signal(
            &server_error("LOADING Redis is loading the dataset in memory"),
            Role::Primary
        ));
        assert!(is_failover_signal(
            &server_error(
                "MASTERDOWN Link with MASTER is down and replica-serve-stale-data is set to 'no'."
            ),
            Role::Primary
        ));
        let io: RedisError =
            std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset").into();
        assert!(is_failover_signal(&io, Role::Any));
        // Only signals about the node are role signals; a broken connection is not.
        assert!(is_role_signal(&readonly));
        assert!(is_role_signal(&moved));
        assert!(is_role_signal(&wait));
        assert!(is_role_signal(&unblocked));
        assert!(!is_role_signal(&io));
        assert!(!is_role_signal(&server_error(
            "LOADING Redis is loading the dataset in memory"
        )));
        // Ordinary command errors are not.
        let wrongtype =
            server_error("WRONGTYPE Operation against a key holding the wrong kind of value");
        assert!(!is_failover_signal(&wrongtype, Role::Primary));
        assert!(!is_failover_signal(
            &server_error("ERR unknown command 'ROLE'"),
            Role::Primary
        ));
        let noperm =
            server_error("NOPERM User default has no permissions to run the 'role' command");
        assert!(!is_failover_signal(&noperm, Role::Primary));
        // Both mean "the role cannot be asked": accepted like a store without ROLE.
        assert!(role_not_available(&noperm));
        assert!(role_not_available(&server_error(
            "ERR unknown command 'ROLE'"
        )));
        assert!(!role_not_available(&readonly));
        assert!(!role_not_available(&io));
    }

    #[test]
    fn store_errors_are_logged_without_addresses() {
        for (raw, want) in [
            (
                "Connection refused (os error 111) to 192.0.2.7:6379",
                "Connection refused (os error 111) to <addr>",
            ),
            (
                "failed to connect to [2001:db8::1]:6380.",
                "failed to connect to <addr>.",
            ),
            ("peer [::1] refused", "peer <addr>] refused"),
            (
                "dns error for store.example.com:6379: no record",
                "dns error for <addr>: no record",
            ),
            (
                "bad url redis://user:pw@store.example.com/2",
                "bad url <addr>",
            ),
            (
                "READONLY You can't write against a read only replica.",
                "READONLY You can't write against a read only replica.",
            ),
            ("timed out after 250ms", "timed out after 250ms"),
            ("MOVED 3999 192.0.2.5:6381", "MOVED 3999 <addr>"),
            ("ASK 12 node-2.cache.internal:6379", "ASK 12 <addr>"),
            ("no route to store.example.com", "no route to <addr>"),
            (
                "failed (endpoint=store.example.com:6380)",
                "failed (<addr>)",
            ),
            ("addr=192.0.2.9:6379 lost", "<addr> lost"),
            ("needs Redis 7.0 or later", "needs Redis 7.0 or later"),
        ] {
            assert_eq!(redact_addrs(&raw), want, "{raw}");
        }
        // Store errors: only a listed code (never its detail), an I/O error without its text.
        for (line, want) in [
            ("MOVED 3999 192.0.2.5:6381", "MOVED"),
            ("ASK 12 [2001:db8::7]:6379", "ASK"),
            (
                "READONLY You can't write against a read only replica.",
                "READONLY",
            ),
            ("ERR connect to 'cachehost:6379' failed", "ERR"),
            ("ERR endpoint=\"store-1.internal:6380\",retry", "ERR"),
            ("NOAUTH node=192.0.2.9:6379 wants a password", "NOAUTH"),
            ("CUSTOMCODE leaked store.example.com secret", "server error"),
        ] {
            assert_eq!(store_error(&server_error(line)), want, "{line}");
        }
        let io: RedisError = std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "connect to store.example.com:6379 refused",
        )
        .into();
        assert_eq!(store_error(&io), "I/O error: connection refused");
        // Errors of opening a connection: the store or I/O error in them, our own messages,
        // nothing else.
        let refused = anyhow::Error::from(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "connect to [2001:db8::1]:6379 refused",
        ));
        assert_eq!(error_summary(&refused), "I/O error: ConnectionRefused");
        let server = anyhow::Error::from(server_error("ERR dial 'cachehost:6379'"))
            .context("opening store.example.com:6379");
        assert_eq!(error_summary(&server), "ERR");
        assert_eq!(
            error_summary(&anyhow::anyhow!("the endpoint still reaches a replica")),
            "the endpoint still reaches a replica"
        );
        assert_eq!(
            error_summary(&anyhow::anyhow!("dial cachehost:6379 (192.0.2.3) failed")),
            "connection failed"
        );
    }

    #[test]
    fn loading_backs_off_and_other_signals_do_not() {
        assert_eq!(signal_holdoff("READONLY", 7), SIGNAL_HOLDOFF);
        assert_eq!(signal_holdoff("LOADING", 0), SIGNAL_HOLDOFF);
        assert_eq!(signal_holdoff("LOADING", 1), SIGNAL_HOLDOFF * 2);
        assert_eq!(signal_holdoff("LOADING", 3), SIGNAL_HOLDOFF * 8);
        assert_eq!(signal_holdoff("LOADING", 4), Duration::from_secs(8));
        assert_eq!(signal_holdoff("LOADING", 40), Duration::from_secs(8));
        // A failover signal after a LOADING streak is not delayed, and ends the streak.
        let streak = AtomicU32::new(4);
        assert_eq!(holdoff_after("LOADING", &streak), Duration::from_secs(8));
        assert_eq!(holdoff_after("READONLY", &streak), SIGNAL_HOLDOFF);
        assert_eq!(streak.load(Ordering::Relaxed), 0);
        assert_eq!(holdoff_after("LOADING", &streak), SIGNAL_HOLDOFF);
    }

    #[test]
    fn test_parse_role() {
        let master = Value::Bulk(vec![
            Value::Data(b"master".to_vec()),
            Value::Int(0),
            Value::Bulk(vec![]),
        ]);
        assert_eq!(parse_role(&master), Some(true));
        let replica = Value::Bulk(vec![
            Value::Data(b"slave".to_vec()),
            Value::Data(b"192.0.2.1".to_vec()),
            Value::Int(6379),
            Value::Data(b"connected".to_vec()),
            Value::Int(0),
        ]);
        assert_eq!(parse_role(&replica), Some(false));
        assert_eq!(parse_role(&Value::Okay), None);
    }
}

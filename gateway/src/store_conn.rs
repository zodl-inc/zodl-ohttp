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

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
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
/// At most one `ROLE` check per this interval (after a short `WAIT`, and in housekeeping).
const ROLE_CHECK_INTERVAL: Duration = Duration::from_secs(1);
/// `ConnectionManager`'s own retries of a refused connection (100 ms base, factor 2).
const MANAGER_RETRIES: usize = 3;

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

/// `ROLE`'s first element: Some(true) for a primary, Some(false) for anything else, None when
/// the store does not answer `ROLE` (treated as "unknown", accepted).
fn parse_role(v: &Value) -> Option<bool> {
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
    reconnecting: AtomicBool,
    consecutive_timeouts: AtomicU32,
    epoch: Instant,
    /// Milliseconds since `epoch` of the last replacement / `ROLE` check (0 = never).
    last_swap_ms: AtomicU64,
    last_role_check_ms: AtomicU64,
}

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
            reconnecting: AtomicBool::new(false),
            consecutive_timeouts: AtomicU32::new(0),
            epoch: Instant::now(),
            last_swap_ms: AtomicU64::new(0),
            last_role_check_ms: AtomicU64::new(0),
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

    pub fn observe_ok(&self) {
        if self.consecutive_timeouts.load(Ordering::Relaxed) != 0 {
            self.consecutive_timeouts.store(0, Ordering::Relaxed);
        }
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
            STORE_CONNECT_TIMEOUT,
            redis::cmd("ROLE").query_async::<_, Value>(&mut conn),
        )
        .await;
        match answer {
            Ok(Ok(v)) if parse_role(&v) == Some(false) => self.trigger("role"),
            Ok(Err(e)) => self.observe_error(&e),
            _ => {}
        }
    }

    /// Replace the connection (new name resolution, primary only) although no command reported a
    /// failover signal: for a node that still says `ROLE master` but has stopped acknowledging
    /// writes on any replica for a long time (a primary the endpoint may have left behind).
    pub fn force_reconnect(self: &Arc<Self>, reason: &'static str) {
        self.trigger(reason);
    }

    /// Start a reconnect unless one is running or the connection was just replaced.
    fn trigger(self: &Arc<Self>, reason: &'static str) {
        let last = self.last_swap_ms.load(Ordering::Relaxed);
        if last != 0 && self.now_ms().saturating_sub(last) < SIGNAL_HOLDOFF.as_millis() as u64 {
            return;
        }
        if self
            .reconnecting
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        warn!(network = %self.network, store = self.store, reason, "Store connection failover signal: reconnecting");
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
                        this.consecutive_timeouts.store(0, Ordering::Relaxed);
                        this.last_swap_ms.store(this.now_ms(), Ordering::Relaxed);
                        this.generation.send_modify(|g| *g += 1);
                        this.reconnecting.store(false, Ordering::Release);
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
                        warn!(network = %this.network, store = this.store, attempts, error = %e, "Store reconnect attempt failed");
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(RECONNECT_MAX_BACKOFF);
                    }
                }
            }
        });
    }

    /// A new connection (new name resolution), accepted for a primary store only once its node
    /// reports `ROLE master` (or does not know `ROLE`).
    async fn open_usable(&self) -> anyhow::Result<ConnectionManager> {
        open_checked(&self.client, self.role).await
    }
}

/// `open`, and for `Role::Primary` accept the connection only if its node reports `ROLE master`
/// (or does not know `ROLE`): right after a failover the endpoint name can still reach the
/// demoted node for a few seconds.
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
            // A store without ROLE: accepted, its writes still report READONLY.
            Err(e) if e.kind() == ErrorKind::ResponseError => {}
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
        // Ordinary command errors are not.
        let wrongtype =
            server_error("WRONGTYPE Operation against a key holding the wrong kind of value");
        assert!(!is_failover_signal(&wrongtype, Role::Primary));
        assert!(!is_failover_signal(
            &server_error("ERR unknown command 'ROLE'"),
            Role::Primary
        ));
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

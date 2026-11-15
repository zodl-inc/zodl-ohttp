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

//! The peer fallback of the WRITE replica wait (`REPLAY_WRITE_WAIT_REPLICAS`).
//!
//! A managed Redis that promotes a replica resynchronises every other replica from the new
//! primary at once, so for a while (minutes on a managed Redis) the new primary has no replica and
//! every `WAIT 1` of a WRITE nonce comes back short. Before this, every WRITE failed closed for
//! that whole time although READs were back after the endpoint switch.
//!
//! When the local `SET NX` succeeded (the nonce is new and held by the local primary) and only
//! the replica acknowledgement is short, the WRITE is confirmed at the peer origins' stores
//! instead (`REPLAY_PEER_URLS`, the cross-region store): `SET NX` there, then the peer's own
//! `WAIT` (`REPLAY_PEER_WAIT_REPLICAS`, which must be >= 1). The WRITE runs only if every peer
//! stored the nonce as new and acknowledged it on its replicas; a peer that already holds it
//! makes the request a replay; anything else (a peer unreachable, slow, without replica) fails
//! closed as before. In `async-reads` the peers were already written and acknowledged
//! synchronously before the local wait (`PeerCheck::durable_at_peers`), so nothing more is
//! asked of them. Without peers (or with `REPLAY_PEER_WAIT_REPLICAS=0`) nothing changes.
//!
//! Two follow-ups keep a nonce admitted this way from being forgotten by the local store, whose
//! copy is on one node only:
//!
//! - **Write-back**: the nonce is queued and rewritten to the local store (`SET ... EX <rest of
//!   the TTL>` + `WAIT`, on a connection of its own, so request `WAIT`s never queue behind it)
//!   until the local replicas acknowledge it, or until its TTL is over. When the local `SET NX`
//!   landed on a node the endpoint no longer points at, the rewrite reaches the new primary once
//!   that connection is replaced: by a failover signal, or, for a node that keeps saying
//!   `ROLE master` without acknowledging anything, after `WRITE_BACK_SHORT_RECONNECT` short
//!   acknowledgements in a row (a reconnect resolves the endpoint again). The queue is in memory:
//!   a gateway that stops before it is written back leaves the nonce at the peers only, which is
//!   what the window below covers for the gateways that consult the peers.
//! - **Window** (`failover` mode only): for `REPLAY_TTL_SECS` after this gateway process started,
//!   saw a short acknowledgement, or had a security-store connection replaced (watched in the
//!   background, not only on WRITEs). Since the check below runs on every WRITE, the window
//!   only labels those checks (`path="window"` instead of `"check"`).
//!
//! **Check at the fallback store.** Every WRITE whose local wait succeeded is also `SET NX` at
//! the fallback store synchronously (the peers in `failover` mode, the confirming standby stores
//! of a read origin), and a store that holds the nonce refuses it. An unreachable fallback store
//! there fails the WRITE closed, unless its route is on `REPLAY_ONE_SIDED_WRITE_ROUTES` ("Partition
//! tolerance" below): such a WRITE keeps the first verdict and its nonce reaches the fallback
//! store asynchronously. A replay of a WRITE admitted through the fallback store (here, at
//! another gateway of the same store, or at an origin that could not reach the primary store)
//! is then refused even if the primary store never got or lost its copy. This used to happen
//! only inside the window; it runs on every WRITE because an origin may admit WRITEs at the
//! fallback store alone while the others still reach the primary store (below, and an origin
//! with `REPLAY_PEER_FAIL_CLOSED_WRITES=0`), and nothing tells the others when that starts.
//!
//! **Unavailable store** (`REPLAY_UNAVAILABLE_FALLBACK`, off by default). When the store that
//! decides gives no verdict at all (no connection, a timeout, an error), the request is decided
//! at the fallback store instead of failing closed, with the rules above: new and acknowledged
//! there = runs, held there = replay, anything else = fail-closed; the nonce is written back to
//! the store that gave no verdict once it answers. Only one store decides then, so this applies
//! to READs and to WRITEs on `REPLAY_ONE_SIDED_WRITE_ROUTES`; every other WRITE fails closed
//! ("Partition tolerance" below), except where the deciding store took the nonce and only its
//! `WAIT` got no answer (`local_unavailable` after a local `SET NX`, like a short acknowledgement).
//!
//! - `failover` mode, the local store: the outer check cannot tell READ from WRITE, so the
//!   request is decapsulated and classified first (`LocalReplayCheck::Unavailable`), then
//!   decided at the peers alone (`ResponseCache::admit_without_local`): a READ by `SET NX`, a
//!   WRITE by `SET NX` + the peers' `WAIT`. A WRITE whose local `SET NX` succeeded but whose
//!   local `WAIT` got no answer takes the short-acknowledgement path (`path="local_unavailable"`).
//! - `async-reads`, the hub: a WRITE confirmed at the standby stores, or by the local replicas
//!   where the local store is the fallback store (`path="hub_unavailable"`).
//! - `async-reads`, the local store, where it is the fallback store (no standby stores, the local
//!   replica wait: `ResponseCache::decides_at_peers_without_local`): as in `failover` mode, the
//!   request is classified and decided at the hub alone (`admit_without_local`: a READ by `SET
//!   NX`, a WRITE by `SET NX` + the hub's `WAIT`, written back to the local store). Also with
//!   `REPLAY_PEER_FAIL_CLOSED_WRITES=0`: an unreachable hub is tolerated there, an unreachable
//!   local store is not.
//! - Health: a gateway whose local store does not answer and whose peers decide in its place
//!   (`failover` mode, or the `async-reads` case above) keeps `/healthz`
//!   healthy while every peer answered its last housekeeping PING
//!   (`ResponseCache::serves_without_local_store`, gauge `ohttp_replay_serving_via_fallback`),
//!   so a load balancer keeps sending it the requests the peers can decide. With no peer
//!   answering it fails, as before.
//!
//! **Partition tolerance** (`REPLAY_ONE_SIDED_WRITE_ROUTES`, `cache::WritePolicy`). `SET NX` on
//! one store admits a key once, so two gateways that asked the same store cannot both find one
//! nonce new there: two admissions of one WRITE need two gateways that each ran it on the
//! verdict of a store the other did not ask. That takes no second failure. One network partition
//! between the primary store's region and the fallback store's region is enough: a `failover`-mode
//! gateway next to the primary store gets no answer from its peer and would keep its local verdict
//! (the check above), while an `async-reads` origin next to the fallback store gets none from the
//! hub and would decide on its own store (`REPLAY_PEER_FAIL_CLOSED_WRITES=0`, or the unavailable
//! fallback with its own replicas). The same sealed bytes delivered to both sides (a relay that
//! sends them twice) would run at both.
//!
//! So a WRITE runs only once both stores took its nonce as new: the store that decides (the local
//! store in `sync` and `failover` mode, the hub in `async-reads`) and the second store this
//! gateway consults synchronously (the peers in `sync` mode and in `failover` mode with this
//! fallback, the confirming standby stores of a read origin, the own store of an `async-reads`
//! origin with its own replica wait). Every path that would let it run on one of them alone fails
//! it closed instead (`result="one_sided_refused"`): a peer that gave no verdict and was tolerated
//! (`REPLAY_PEER_FAIL_CLOSED=0` in `sync` mode, `REPLAY_PEER_FAIL_CLOSED_WRITES=0`:
//! `path="peer_tolerated"`), a fallback store that did not answer the check of every WRITE
//! (`check`, `window`, `hub_check`, `hub_window`), and the unavailable fallback (`local_unavailable`
//! when the local `SET NX` gave no verdict, `hub_unavailable`). Two admissions under this rule
//! both asked both stores, so at least one of them found the nonce held. The
//! short-acknowledgement paths stay open (`short_ack`, `hub_short_ack`, and `local_unavailable`
//! after a local `SET NX` that took the nonce): both stores took it as new there, and the one
//! whose replicas acknowledged it keeps it through a failover of the other, which gets it back
//! by the write-back.
//!
//! A route on `REPLAY_ONE_SIDED_WRITE_ROUTES` keeps every one-sided path above, for its
//! availability while one store or the link to it fails. Only routes whose upstream refuses a
//! second copy of the same request belong there (lightwalletd `SendTransaction`: the chain never
//! takes one transaction twice): for them one partition between the two stores can run the
//! request once at each side, and nothing worse. The default list is empty. A `failover`-mode
//! origin without this fallback (no `REPLAY_PEER_WAIT_REPLICAS` or no `REPLAY_WRITE_WAIT_REPLICAS`)
//! consults no second store synchronously and is unchanged: its peers are only replicated to,
//! for an active/passive pair whose load balancer never sends one request to both.
//!
//! A nonce admitted while one store did not answer (a one-sided route, or a short acknowledgement)
//! is copied to it (write-back, asynchronous hand-off) as soon as it is reachable. The check of
//! every WRITE must run on every gateway that asks the primary store
//! (`ResponseCache::checks_writes_at_fallback_store`, gauge `ohttp_replay_fallback_check`): turn the
//! unavailable fallback on only once all of them report it. READ nonces decided at the fallback
//! store are not written back (a replayed READ changes nothing). A nonce stored by a request
//! that then failed closed stays held for those exact bytes; clients seal every attempt afresh.
//!
//! **Hub path** (`async-reads`, the WRITE check at another origin's store, the hub): when the
//! hub took the nonce as new but its replica acknowledgement is short (the hub resyncs after a
//! failover), the WRITE is confirmed at a second store instead. A read origin uses its standby
//! stores (`REPLAY_STANDBY_URLS`, with `REPLAY_PEER_WAIT_REPLICAS`): `SET NX` + `WAIT` there,
//! with the same rules (new + acknowledged = runs, held = replay, anything else fails closed),
//! and a window after startup or a hub disruption in which every WRITE is also `SET NX` at the
//! standby stores. A read origin with a confirming standby store sends that `SET NX` at the
//! same time as the hub's `SET NX` and replica wait, and every path that can let the WRITE run
//! uses its answer (the check, both fallbacks) instead of asking again: the standby `SET NX` no
//! longer adds a round trip after the hub's (the fallbacks' `WAIT` there still does). A nonce it
//! stored for a request the hub then refuses stays held for those exact bytes, as for any
//! request that fails closed; two copies of one request at two origins within a round trip may
//! both be refused, never both run. An origin with its own replica wait
//! (`REPLAY_WRITE_WAIT_REPLICAS`, the
//! standby origin and its spoke) uses its own store: the WRITE runs only once the local replicas
//! acknowledge it (no window: these origins always check both stores). Either way the nonce is
//! written back to the hub until the hub's replicas have it.
//!
//! Metrics: `ohttp_replay_write_fallback_total{network,path,result}` (path `short_ack` |
//! `local_unavailable` | `window` | `check` | `hub_short_ack` | `hub_unavailable` | `hub_window` |
//! `hub_check` | `peer_tolerated`; result `accepted` | `replay` | `unavailable` | `unacknowledged` |
//! `overflow` | `one_sided_refused`),
//! `ohttp_replay_read_fallback_total{network,result}`,
//! `ohttp_replay_write_back_total{network,result}` (`written` | `expired`) and
//! `ohttp_replay_unavailable_fallback{network,target}`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio::time::{timeout, Instant};
use tracing::{debug, warn};

use crate::cache::{WriteWaitConfig, REPLAY_TTL_SECS};
use crate::store_conn::StoreConn;

/// Nonces admitted through the peers that are not yet acknowledged by the local replicas.
/// Beyond this the fallback refuses (fail-closed, `result="overflow"`).
pub const WRITE_BACK_CAPACITY: usize = 10_000;
/// Largest rewrite batch (one pipeline + one `WAIT`).
const WRITE_BACK_BATCH_MAX: usize = 256;
/// Pause between write-back attempts while nonces are pending.
const WRITE_BACK_INTERVAL: Duration = Duration::from_millis(500);
/// Short acknowledgements in a row (one per attempt) after which the write-back connection is
/// replaced: ~10 s, longer than a resync never is not a goal, but a node that answers `ROLE
/// master` and never acknowledges is either resyncing (a reconnect reaches it again, harmless)
/// or one the endpoint has left behind (a reconnect reaches the real primary).
pub const WRITE_BACK_SHORT_RECONNECT: u32 = 20;
/// Failed attempts in a row between two warnings.
const WRITE_BACK_WARN_EVERY: u32 = 20;

/// Per-gateway state of the fallback (one per network, next to the `WAIT` connection).
pub struct WriteFallback {
    network: String,
    base: Instant,
    /// The window is open while `now_ms() < window_until_ms` (0 = never opened).
    window_until_ms: AtomicU64,
    window: Duration,
    /// Last seen sum of the security and `WAIT` connection generations.
    seen_generation: AtomicU64,
    /// (key, end of its TTL), oldest first; pushes all carry the same TTL, so the deadlines
    /// are in order.
    pending: Mutex<VecDeque<(String, Instant)>>,
    capacity: usize,
    notify: Notify,
}

impl WriteFallback {
    pub fn new(network: &str, generation: u64) -> Self {
        Self::with_limits(
            network,
            generation,
            Duration::from_secs(REPLAY_TTL_SECS),
            WRITE_BACK_CAPACITY,
        )
    }

    /// The window starts open: a gateway that just started cannot know whether the local store
    /// lost a nonce that another gateway admitted through the peers shortly before.
    pub fn with_limits(network: &str, generation: u64, window: Duration, capacity: usize) -> Self {
        Self {
            network: network.to_string(),
            base: Instant::now(),
            window_until_ms: AtomicU64::new(window.as_millis() as u64 + 1),
            window,
            seen_generation: AtomicU64::new(generation),
            pending: Mutex::new(VecDeque::new()),
            capacity,
            notify: Notify::new(),
        }
    }

    fn now_ms(&self) -> u64 {
        self.base.elapsed().as_millis() as u64 + 1
    }

    /// Open (or extend) the window: the local store just showed a failover.
    pub fn open_window(&self) {
        let until = self.now_ms() + self.window.as_millis() as u64;
        self.window_until_ms.fetch_max(until, Ordering::Relaxed);
    }

    /// Open the window when a store connection was replaced since the last call.
    pub fn note_generation(&self, generation: u64) {
        if self.seen_generation.swap(generation, Ordering::Relaxed) != generation {
            self.open_window();
        }
    }

    /// Close the window now (tests).
    pub fn close_window(&self) {
        self.window_until_ms.store(0, Ordering::Relaxed);
    }

    pub fn window_open(&self) -> bool {
        self.now_ms() < self.window_until_ms.load(Ordering::Relaxed)
    }

    pub fn has_room(&self) -> bool {
        self.pending.lock().len() < self.capacity
    }

    /// Queue `key` for the write-back. False when the queue is full (the caller fails closed).
    pub fn push_write_back(&self, key: String) -> bool {
        let mut p = self.pending.lock();
        if p.len() >= self.capacity {
            return false;
        }
        p.push_back((key, Instant::now() + Duration::from_secs(REPLAY_TTL_SECS)));
        drop(p);
        crate::health::record_replay_write_back_pending(&self.network, self.pending_len());
        self.notify.notify_one();
        true
    }

    pub fn pending_len(&self) -> usize {
        self.pending.lock().len()
    }

    /// Drop the expired entries (counted) and return a copy of the oldest batch.
    fn batch(&self) -> Vec<(String, Instant)> {
        let now = Instant::now();
        let mut p = self.pending.lock();
        let mut expired = 0;
        while p.front().is_some_and(|(_, d)| *d <= now) {
            p.pop_front();
            expired += 1;
        }
        let batch: Vec<_> = p.iter().take(WRITE_BACK_BATCH_MAX).cloned().collect();
        drop(p);
        if expired > 0 {
            warn!(network = %self.network, expired, "Replay nonces admitted through the peers expired before the local replicas acknowledged them");
            crate::health::record_replay_write_back(&self.network, "expired", expired);
        }
        batch
    }

    /// The first `n` entries were written back and acknowledged. Only the write-back task
    /// removes entries, and pushes go to the back, so they are still the first `n` (minus any
    /// that `batch` dropped as expired meanwhile, which only this task does).
    fn done(&self, n: usize) {
        let mut p = self.pending.lock();
        let n = n.min(p.len());
        p.drain(..n);
        let left = p.len();
        drop(p);
        crate::health::record_replay_write_back(&self.network, "written", n as u64);
        crate::health::record_replay_write_back_pending(&self.network, left);
    }
}

/// Open the window whenever `conn` is replaced (a failover of the local store), also on a
/// gateway that serves no WRITE meanwhile.
pub fn spawn_window_watch(fb: Arc<WriteFallback>, conn: Arc<StoreConn>) {
    tokio::spawn(async move {
        loop {
            let g = conn.generation();
            let failovers = conn.failover_generation();
            // A replacement of one stuck `WAIT` connection (`StoreConn::retire_quietly`) is not
            // a change of the store.
            if conn.wait_for_reconnect(g, Duration::from_secs(3600)).await
                && conn.failover_generation() != failovers
            {
                fb.open_window();
            }
        }
    });
}

/// The outcome of one write-back attempt (a pipelined `SET ... EX` per nonce + `WAIT`).
pub enum WriteBackResult {
    Acked,
    /// Fewer replicas than required acknowledged.
    Short(String),
    Failed(String),
}

/// Where a write-back goes: the local store (`LocalWriteBack`) or the replay peers
/// (`cache::ReplayPeers`, for the hub of a read origin).
pub trait WriteBackSink: Send + Sync + 'static {
    /// `SET key 1 EX ttl` for every (key, ttl), then `WAIT`.
    fn write(&self, batch: Vec<(String, u64)>) -> BoxFuture<'static, WriteBackResult>;
    /// Replace the connection (re-resolve the endpoint): after many short acknowledgements.
    fn reconnect(&self);
}

/// The local store, on a connection of its own.
pub struct LocalWriteBack {
    pub conn: Arc<StoreConn>,
    pub wait: WriteWaitConfig,
    pub redis_timeout: Duration,
}

impl WriteBackSink for LocalWriteBack {
    fn write(&self, batch: Vec<(String, u64)>) -> BoxFuture<'static, WriteBackResult> {
        let conn = self.conn.clone();
        let wait = self.wait;
        let budget = Duration::from_millis(wait.timeout_ms) + self.redis_timeout * 4;
        Box::pin(async move {
            let mut pipe = redis::pipe();
            for (key, ttl) in &batch {
                pipe.cmd("SET")
                    .arg(key)
                    .arg("1")
                    .arg("EX")
                    .arg(*ttl)
                    .ignore();
            }
            pipe.cmd("WAIT").arg(wait.replicas).arg(wait.timeout_ms);
            let mut c = conn.get();
            let r = timeout(budget, pipe.query_async::<_, (i64,)>(&mut c)).await;
            conn.observe_timed(&r);
            match r {
                Ok(Ok((acked,))) if acked >= wait.replicas as i64 => WriteBackResult::Acked,
                Ok(Ok((acked,))) => {
                    conn.observe_short_ack();
                    WriteBackResult::Short(format!(
                        "acknowledged by {acked} of {} replica(s)",
                        wait.replicas
                    ))
                }
                Ok(Err(e)) => WriteBackResult::Failed(crate::store_conn::store_error(&e)),
                Err(_) => {
                    WriteBackResult::Failed(format!("timed out after {}ms", budget.as_millis()))
                }
            }
        })
    }

    fn reconnect(&self) {
        self.conn.force_reconnect("short_ack");
    }
}

/// The write-back task: rewrite pending nonces to `sink` until its replicas have them.
pub fn spawn_write_back(fb: Arc<WriteFallback>, sink: Arc<dyn WriteBackSink>) {
    tokio::spawn(async move {
        let mut short_in_a_row = 0u32;
        let mut failed_in_a_row = 0u32;
        loop {
            if fb.pending_len() == 0 {
                short_in_a_row = 0;
                failed_in_a_row = 0;
                // A push notifies; the timeout is only a safety net.
                let _ = timeout(Duration::from_secs(5), fb.notify.notified()).await;
                continue;
            }
            tokio::time::sleep(WRITE_BACK_INTERVAL).await;
            let batch = fb.batch();
            if batch.is_empty() {
                continue;
            }
            let now = Instant::now();
            let items: Vec<(String, u64)> = batch
                .iter()
                .map(|(k, d)| (k.clone(), d.saturating_duration_since(now).as_secs().max(1)))
                .collect();
            let failure = match sink.write(items).await {
                WriteBackResult::Acked => {
                    debug!(network = %fb.network, n = batch.len(), "Replay nonces admitted through another store written back");
                    fb.done(batch.len());
                    short_in_a_row = 0;
                    failed_in_a_row = 0;
                    continue;
                }
                WriteBackResult::Short(m) => {
                    short_in_a_row += 1;
                    if short_in_a_row >= WRITE_BACK_SHORT_RECONNECT {
                        short_in_a_row = 0;
                        sink.reconnect();
                    }
                    m
                }
                WriteBackResult::Failed(m) => m,
            };
            failed_in_a_row += 1;
            if failed_in_a_row % WRITE_BACK_WARN_EVERY == 0 {
                warn!(network = %fb.network, attempts = failed_in_a_row, pending = fb.pending_len(), error = %failure, "Write-back of replay nonces admitted through another store still failing");
            } else {
                debug!(network = %fb.network, pending = fb.pending_len(), error = %failure, "Write-back not done, retrying");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_starts_open_and_reopens_on_a_new_generation_only() {
        let fb = WriteFallback::new("testnet-wfb-unit", 3);
        assert!(fb.window_open(), "open after startup");
        fb.close_window();
        assert!(!fb.window_open());
        fb.note_generation(3);
        assert!(!fb.window_open(), "same generation");
        fb.note_generation(4);
        assert!(fb.window_open(), "a replaced connection opens it");
    }

    #[tokio::test]
    async fn window_closes_after_its_duration() {
        let fb = WriteFallback::with_limits("testnet-wfb-unit", 0, Duration::from_millis(50), 10);
        assert!(fb.window_open());
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(!fb.window_open(), "the startup window ends");
        fb.open_window();
        assert!(fb.window_open());
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(!fb.window_open());
    }

    #[test]
    fn write_back_queue_is_bounded() {
        let fb = WriteFallback::with_limits("testnet-wfb-unit", 0, Duration::from_secs(1), 2);
        assert!(fb.has_room());
        assert!(fb.push_write_back("a".into()));
        assert!(fb.push_write_back("b".into()));
        assert!(!fb.has_room());
        assert!(!fb.push_write_back("c".into()));
        assert_eq!(fb.batch().len(), 2);
        fb.done(1);
        assert_eq!(fb.pending_len(), 1);
        assert!(fb.push_write_back("c".into()));
    }
}

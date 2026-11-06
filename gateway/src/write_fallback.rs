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
//! primary at once, so for a while (minutes on ElastiCache) the new primary has no replica and
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
//! - **Window** (`failover` mode only, where WRITEs are otherwise never checked at the peers):
//!   for `REPLAY_TTL_SECS` after this gateway process started, saw a short acknowledgement, or
//!   had a security-store connection replaced (watched in the background, not only on WRITEs),
//!   every WRITE whose local wait succeeded is also `SET NX` at the peers synchronously, and a
//!   peer that holds the nonce refuses it. A replay of a WRITE admitted through the peers (here
//!   or at another gateway of the same store) is then refused even if the local store lost its
//!   copy before the write-back. An unreachable peer there keeps the local verdict, as outside
//!   the window (the window never fails a request closed). The window is per process, in
//!   memory; a gateway that only checks at another origin's store (a read origin) has none.
//!
//! Metrics: `ohttp_replay_write_fallback_total{network,path,result}` (path `short_ack` |
//! `window`; result `accepted` | `replay` | `unavailable` | `unacknowledged` | `overflow`) and
//! `ohttp_replay_write_back_total{network,result}` (`written` | `expired`).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

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
            if conn.wait_for_reconnect(g, Duration::from_secs(3600)).await {
                fb.open_window();
            }
        }
    });
}

/// The write-back task: rewrite pending nonces to the local store until its replicas have them.
/// `conn` is its own connection to the local store.
pub fn spawn_write_back(
    fb: Arc<WriteFallback>,
    conn: Arc<StoreConn>,
    wait: WriteWaitConfig,
    redis_timeout: Duration,
) {
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
            let mut pipe = redis::pipe();
            for (key, deadline) in &batch {
                let ttl = deadline.saturating_duration_since(now).as_secs().max(1);
                pipe.cmd("SET")
                    .arg(key)
                    .arg("1")
                    .arg("EX")
                    .arg(ttl)
                    .ignore();
            }
            pipe.cmd("WAIT").arg(wait.replicas).arg(wait.timeout_ms);
            let mut c = conn.get();
            let budget = Duration::from_millis(wait.timeout_ms) + redis_timeout * 4;
            let r = timeout(budget, pipe.query_async::<_, (i64,)>(&mut c)).await;
            conn.observe_timed(&r);
            let failure = match r {
                Ok(Ok((acked,))) if acked >= wait.replicas as i64 => {
                    debug!(network = %fb.network, n = batch.len(), "Replay nonces admitted through the peers written back to the local store");
                    fb.done(batch.len());
                    short_in_a_row = 0;
                    failed_in_a_row = 0;
                    continue;
                }
                Ok(Ok((acked,))) => {
                    conn.observe_short_ack();
                    short_in_a_row += 1;
                    if short_in_a_row >= WRITE_BACK_SHORT_RECONNECT {
                        short_in_a_row = 0;
                        conn.force_reconnect("short_ack");
                    }
                    format!("acknowledged by {acked} of {} replica(s)", wait.replicas)
                }
                Ok(Err(e)) => e.to_string(),
                Err(_) => format!("timed out after {}ms", budget.as_millis()),
            };
            failed_in_a_row += 1;
            if failed_in_a_row % WRITE_BACK_WARN_EVERY == 0 {
                warn!(network = %fb.network, attempts = failed_in_a_row, pending = fb.pending_len(), error = %failure, "Write-back of replay nonces admitted through the peers still failing");
            } else {
                debug!(network = %fb.network, pending = fb.pending_len(), error = %failure, "Write-back to the local store not done, retrying");
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

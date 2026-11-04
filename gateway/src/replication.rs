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

//! Asynchronous replication of replay nonces to the peer origins
//! (`REPLAY_PEER_MODE=async-reads|failover`, see `origin.rs`).
//!
//! A request classified READ writes its nonce to the local security store synchronously (as
//! always, fail-closed) and hands the key to `AsyncReplicator::enqueue`, which never blocks: one
//! bounded queue per peer, one worker task per peer that drains the queue in batches (every
//! `BATCH_INTERVAL` or `BATCH_MAX` nonces) and sends them as one pipelined `SET NX EX` per peer.
//! A peer that already holds a nonce means the request was most likely also served by that peer
//! inside the replication window (or an earlier attempt of the same batch landed before its reply
//! was lost); it is counted (`ohttp_replay_peer_total{result="replay_async"}`), the request cannot
//! be refused any more.
//!
//! `ReplicationHealth` decides whether the asynchronous path is trustworthy right now. It is
//! strict (READs take the synchronous path) when:
//! - the p99 of the lag samples over the last `LAG_WINDOW` (enqueue-to-ack lags and probe round
//!   trips, at most `LAG_WINDOW_MAX_SAMPLES`) exceeds the configured maximum
//!   (`REPLAY_ASYNC_MAX_LAG_MS`),
//! - a queue overflowed (a nonce could not be enqueued: it is counted as dropped and the
//!   protection for it is only the local store, so the mode must not stay relaxed),
//! - batches or probes failed, timed out or found the peer not connected
//!   `REPLAY_ASYNC_FAILURES_BEFORE_STRICT` times in a row at a peer,
//! - and at startup, until the peers have proven healthy.
//!
//! It relaxes again when every peer has acknowledged (a batch or a probe PING) after the last
//! bad event and `REPLAY_ASYNC_RECOVERY_SECS` have passed since it (hysteresis). In `failover`
//! mode the same health is tracked and exported but never changes the request path: that mode
//! has no synchronous peer call by definition.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::time::{timeout, Instant};
use tracing::{debug, info, warn};

use crate::origin::ReplayPeerMode;

/// Nonces waiting per peer; beyond this `enqueue` drops (counted) and degrades to strict.
pub const ASYNC_QUEUE_CAPACITY: usize = 10_000;
/// Largest pipelined batch per peer round trip.
pub const BATCH_MAX: usize = 256;
/// How long a batch waits for more nonces before it is sent.
pub const BATCH_INTERVAL: Duration = Duration::from_millis(20);
/// Idle probe (PING) interval: keeps the health evidence fresh when no READ is replicated, and
/// is the recovery signal while strict (strict READs are synchronous, so nothing is enqueued).
pub const PROBE_INTERVAL: Duration = Duration::from_secs(1);
/// Pause after a failed batch before it is retried.
const RETRY_BACKOFF: Duration = Duration::from_millis(200);
/// Sliding window of lag samples for the p99.
const LAG_WINDOW: Duration = Duration::from_secs(10);
const LAG_WINDOW_MAX_SAMPLES: usize = 4096;

/// The peer side as the worker sees it: a pipelined `SET NX EX` and a `PING`.
/// `cache::ReplayPeers` implements it; tests use a fake.
pub trait PeerSink: Send + Sync + 'static {
    /// `SET key 1 NX EX ttl` for every key, pipelined. `Some(_)` = stored, `None` = the peer
    /// already had it. `Err` = not connected or a Redis error (the whole batch is retried).
    fn set_nx_batch(
        &self,
        peer: usize,
        keys: Vec<String>,
        ttl_secs: u64,
    ) -> BoxFuture<'static, Result<Vec<Option<String>>, String>>;
    fn ping(&self, peer: usize) -> BoxFuture<'static, Result<(), String>>;
    fn peers(&self) -> usize;
}

/// Tunables (the env defaults live in `origin.rs`; tests shorten them).
#[derive(Clone, Debug)]
pub struct ReplicationConfig {
    pub network: String,
    pub mode: ReplayPeerMode,
    pub max_lag: Duration,
    pub recovery: Duration,
    /// Budget for one pipelined batch / probe.
    pub op_timeout: Duration,
    pub nonce_ttl_secs: u64,
    pub queue_capacity: usize,
    pub batch_max: usize,
    pub batch_interval: Duration,
    pub probe_interval: Duration,
    /// Number of consecutive failures before degrading to strict.
    pub failures_before_strict: usize,
}

impl ReplicationConfig {
    pub fn new(
        network: &str,
        mode: ReplayPeerMode,
        max_lag_ms: u64,
        recovery_secs: u64,
        peer_timeout_ms: u64,
        nonce_ttl_secs: u64,
        failures_before_strict: usize,
    ) -> Self {
        Self {
            network: network.to_string(),
            mode,
            max_lag: Duration::from_millis(max_lag_ms),
            recovery: Duration::from_secs(recovery_secs),
            // A batch of BATCH_MAX SETs over a long-distance link needs more than one request's
            // budget; the lag limit is the natural bound.
            op_timeout: Duration::from_millis(max_lag_ms.max(peer_timeout_ms)),
            nonce_ttl_secs,
            queue_capacity: ASYNC_QUEUE_CAPACITY,
            batch_max: BATCH_MAX,
            batch_interval: BATCH_INTERVAL,
            probe_interval: PROBE_INTERVAL,
            failures_before_strict,
        }
    }
}

/// Whether READs may use the asynchronous path right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effective {
    /// Replication is healthy: READs local + async.
    Relaxed,
    /// READs take the synchronous peer path.
    Strict,
}

/// Why the health degraded (metric label).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DegradeReason {
    Startup,
    Lag,
    Overflow,
    PeerDown,
}

impl DegradeReason {
    pub fn as_str(self) -> &'static str {
        match self {
            DegradeReason::Startup => "startup",
            DegradeReason::Lag => "lag",
            DegradeReason::Overflow => "overflow",
            DegradeReason::PeerDown => "peer_down",
        }
    }
}

struct HealthInner {
    /// Last bad event (startup counts as one).
    last_bad: Instant,
    /// Last successful ack or probe per peer.
    last_ok: Vec<Option<Instant>>,
    /// (sample time, lag) of the last `LAG_WINDOW`.
    lags: VecDeque<(Instant, Duration)>,
    /// Per peer: healthy = acknowledged since that peer last reached the failure threshold.
    peer_ok: Vec<bool>,
    /// Per peer: consecutive failures since the last success.
    consecutive_failures: Vec<usize>,
}

pub struct ReplicationHealth {
    network: String,
    mode: ReplayPeerMode,
    max_lag: Duration,
    recovery: Duration,
    failures_before_strict: usize,
    strict: AtomicBool,
    inner: Mutex<HealthInner>,
}

impl ReplicationHealth {
    /// Starts strict: the peers have not proven anything yet.
    pub fn new(
        network: &str,
        mode: ReplayPeerMode,
        peers: usize,
        max_lag: Duration,
        recovery: Duration,
        failures_before_strict: usize,
    ) -> Self {
        let now = Instant::now();
        let h = Self {
            network: network.to_string(),
            mode,
            max_lag,
            recovery,
            failures_before_strict,
            strict: AtomicBool::new(true),
            inner: Mutex::new(HealthInner {
                last_bad: now,
                last_ok: vec![None; peers],
                lags: VecDeque::new(),
                peer_ok: vec![false; peers],
                consecutive_failures: vec![0; peers],
            }),
        };
        crate::health::record_replay_mode_switch(
            network,
            "strict",
            DegradeReason::Startup.as_str(),
        );
        for p in 0..peers {
            crate::health::record_replay_replication_healthy(network, p, false);
            crate::health::record_replay_peer_consecutive_failures(network, p, 0);
        }
        h.publish_effective();
        h
    }

    pub fn mode(&self) -> ReplayPeerMode {
        self.mode
    }

    /// The current verdict, recovering if the hysteresis has elapsed.
    pub fn effective(&self) -> Effective {
        if self.strict.load(Ordering::Acquire) {
            self.maybe_recover();
        }
        if self.strict.load(Ordering::Acquire) {
            Effective::Strict
        } else {
            Effective::Relaxed
        }
    }

    pub fn is_strict(&self) -> bool {
        self.effective() == Effective::Strict
    }

    /// The `mode` label of `ohttp_replay_mode_effective`.
    pub fn effective_label(&self) -> &'static str {
        match (self.mode, self.strict.load(Ordering::Acquire)) {
            (ReplayPeerMode::Sync, _) => "sync",
            (ReplayPeerMode::Failover, _) => "failover",
            (ReplayPeerMode::AsyncReads, false) => "async-reads",
            (ReplayPeerMode::AsyncReads, true) => "async-reads-strict",
        }
    }

    fn publish_effective(&self) {
        crate::health::record_replay_mode_effective(&self.network, self.effective_label());
    }

    /// A nonce (or probe) acknowledged by `peer` after `lag`.
    pub fn record_ack(&self, peer: usize, lag: Duration) {
        crate::health::observe_replay_replication_lag(&self.network, peer, lag.as_secs_f64());
        let now = Instant::now();
        let p99 = {
            let mut g = self.inner.lock();
            if let Some(slot) = g.last_ok.get_mut(peer) {
                *slot = Some(now);
            }
            if let Some(ok) = g.peer_ok.get_mut(peer) {
                if !*ok {
                    *ok = true;
                    crate::health::record_replay_replication_healthy(&self.network, peer, true);
                }
            }
            // Reset consecutive failures on success.
            if let Some(count) = g.consecutive_failures.get_mut(peer) {
                if *count > 0 {
                    *count = 0;
                    crate::health::record_replay_peer_consecutive_failures(&self.network, peer, 0);
                }
            }
            g.lags.push_back((now, lag));
            while g.lags.len() > LAG_WINDOW_MAX_SAMPLES
                || g.lags
                    .front()
                    .is_some_and(|(t, _)| now.duration_since(*t) > LAG_WINDOW)
            {
                g.lags.pop_front();
            }
            p99_of(g.lags.iter().map(|(_, l)| *l))
        };
        if p99 > self.max_lag {
            self.degrade(DegradeReason::Lag, Some(peer), Some(p99));
        } else {
            self.maybe_recover();
        }
    }

    /// A batch or probe failed at `peer`.
    pub fn record_failure(&self, peer: usize, what: &str) {
        let consecutive = {
            let mut g = self.inner.lock();
            if let Some(count) = g.consecutive_failures.get_mut(peer) {
                *count += 1;
                crate::health::record_replay_peer_consecutive_failures(&self.network, peer, *count);
                *count
            } else {
                0
            }
        };

        if consecutive >= self.failures_before_strict {
            {
                let mut g = self.inner.lock();
                if let Some(ok) = g.peer_ok.get_mut(peer) {
                    if *ok {
                        *ok = false;
                        crate::health::record_replay_replication_healthy(
                            &self.network,
                            peer,
                            false,
                        );
                    }
                }
            }
            debug!(
                network = %self.network,
                peer,
                what,
                consecutive,
                threshold = self.failures_before_strict,
                "Replay replication failure threshold reached"
            );
            self.degrade(DegradeReason::PeerDown, Some(peer), None);
        } else {
            debug!(
                network = %self.network,
                peer,
                what,
                consecutive,
                threshold = self.failures_before_strict,
                "Replay replication failure (not degrading yet)"
            );
        }
    }

    /// A nonce could not be enqueued for `peer`.
    pub fn record_overflow(&self, peer: usize) {
        crate::health::record_replay_async_dropped(&self.network, peer, "overflow");
        self.degrade(DegradeReason::Overflow, Some(peer), None);
    }

    fn degrade(&self, reason: DegradeReason, peer: Option<usize>, p99: Option<Duration>) {
        {
            let mut g = self.inner.lock();
            g.last_bad = Instant::now();
        }
        if !self.strict.swap(true, Ordering::AcqRel) {
            warn!(
                network = %self.network,
                mode = %self.mode,
                reason = reason.as_str(),
                peer = ?peer,
                lag_p99_ms = ?p99.map(|d| d.as_millis()),
                max_lag_ms = self.max_lag.as_millis(),
                recovery_secs = self.recovery.as_secs(),
                "Replay replication degraded; READs use the synchronous peer path until the peers are healthy again"
            );
            crate::health::record_replay_mode_switch(&self.network, "strict", reason.as_str());
            self.publish_effective();
        }
    }

    fn maybe_recover(&self) {
        if !self.strict.load(Ordering::Acquire) {
            return;
        }
        let recovered = {
            let g = self.inner.lock();
            let now = Instant::now();
            now.duration_since(g.last_bad) >= self.recovery
                && g.last_ok
                    .iter()
                    .all(|ok| ok.is_some_and(|t| t > g.last_bad))
                && g.peer_ok.iter().all(|ok| *ok)
        };
        if recovered && self.strict.swap(false, Ordering::AcqRel) {
            info!(
                network = %self.network,
                mode = %self.mode,
                recovery_secs = self.recovery.as_secs(),
                "Replay replication healthy again; READs back on the asynchronous path"
            );
            crate::health::record_replay_mode_switch(&self.network, "relaxed", "-");
            self.publish_effective();
        }
    }

    /// p99 of the lag samples held (pruned to the window on each ack; for tests and logs).
    pub fn lag_p99(&self) -> Option<Duration> {
        let g = self.inner.lock();
        if g.lags.is_empty() {
            None
        } else {
            Some(p99_of(g.lags.iter().map(|(_, l)| *l)))
        }
    }
}

fn p99_of(lags: impl Iterator<Item = Duration>) -> Duration {
    let mut v: Vec<Duration> = lags.collect();
    if v.is_empty() {
        return Duration::ZERO;
    }
    v.sort_unstable();
    let idx = ((v.len() as f64) * 0.99).ceil() as usize;
    v[idx.clamp(1, v.len()) - 1]
}

struct Pending {
    key: String,
    enqueued_at: Instant,
}

/// One bounded queue + worker per peer. `enqueue` never blocks and never fails loudly: a full
/// queue is counted and degrades the health to strict.
pub struct AsyncReplicator {
    network: String,
    queues: Vec<mpsc::Sender<Pending>>,
    backlogs: Vec<Arc<AtomicUsize>>,
    health: Arc<ReplicationHealth>,
    capacity: usize,
}

impl AsyncReplicator {
    pub fn start(sink: Arc<dyn PeerSink>, cfg: ReplicationConfig) -> Self {
        let peers = sink.peers();
        let health = Arc::new(ReplicationHealth::new(
            &cfg.network,
            cfg.mode,
            peers,
            cfg.max_lag,
            cfg.recovery,
            cfg.failures_before_strict,
        ));
        let mut queues = Vec::with_capacity(peers);
        let mut backlogs = Vec::with_capacity(peers);
        for peer in 0..peers {
            let (tx, rx) = mpsc::channel::<Pending>(cfg.queue_capacity);
            let backlog = Arc::new(AtomicUsize::new(0));
            tokio::spawn(worker(
                peer,
                rx,
                sink.clone(),
                health.clone(),
                cfg.clone(),
                backlog.clone(),
            ));
            queues.push(tx);
            backlogs.push(backlog);
        }
        info!(
            network = %cfg.network,
            mode = %cfg.mode,
            peers,
            max_lag_ms = cfg.max_lag.as_millis(),
            recovery_secs = cfg.recovery.as_secs(),
            queue_capacity = cfg.queue_capacity,
            batch_max = cfg.batch_max,
            batch_interval_ms = cfg.batch_interval.as_millis(),
            "Asynchronous replay nonce replication started (strict until the peers prove healthy)"
        );
        Self {
            network: cfg.network,
            queues,
            backlogs,
            health,
            capacity: cfg.queue_capacity,
        }
    }

    pub fn health(&self) -> &Arc<ReplicationHealth> {
        &self.health
    }

    /// Hand a locally stored nonce key to every peer's queue.
    pub fn enqueue(&self, key: &str) {
        let now = Instant::now();
        for (peer, tx) in self.queues.iter().enumerate() {
            match tx.try_send(Pending {
                key: key.to_string(),
                enqueued_at: now,
            }) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => self.health.record_overflow(peer),
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.health.record_failure(peer, "worker gone")
                }
            }
            crate::health::record_replay_async_queue_depth(
                &self.network,
                peer,
                self.queue_depth(peer),
            );
        }
    }

    /// Nonces waiting for `peer` (queue + the worker's retry backlog).
    pub fn queue_depth(&self, peer: usize) -> usize {
        let queued = self
            .queues
            .get(peer)
            .map(|tx| self.capacity.saturating_sub(tx.capacity()))
            .unwrap_or(0);
        queued
            + self
                .backlogs
                .get(peer)
                .map(|b| b.load(Ordering::Relaxed))
                .unwrap_or(0)
    }
}

async fn worker(
    peer: usize,
    mut rx: mpsc::Receiver<Pending>,
    sink: Arc<dyn PeerSink>,
    health: Arc<ReplicationHealth>,
    cfg: ReplicationConfig,
    backlog_gauge: Arc<AtomicUsize>,
) {
    let network = cfg.network.clone();
    let mut backlog: VecDeque<Pending> = VecDeque::new();
    let ttl = Duration::from_secs(cfg.nonce_ttl_secs);
    loop {
        if backlog.is_empty() {
            // Idle: wait for a nonce, probing the peer meanwhile.
            match timeout(cfg.probe_interval, rx.recv()).await {
                Ok(Some(p)) => backlog.push_back(p),
                Ok(None) => return,
                Err(_) => {
                    probe(peer, &*sink, &health, &cfg).await;
                    continue;
                }
            }
            backlog_gauge.store(backlog.len(), Ordering::Relaxed);
            // Batch window: collect what arrives within BATCH_INTERVAL, up to BATCH_MAX.
            let deadline = Instant::now() + cfg.batch_interval;
            while backlog.len() < cfg.batch_max {
                match tokio::time::timeout_at(deadline, rx.recv()).await {
                    Ok(Some(p)) => {
                        backlog.push_back(p);
                        backlog_gauge.store(backlog.len(), Ordering::Relaxed);
                    }
                    Ok(None) | Err(_) => break,
                }
            }
        } else {
            // Retrying or draining a burst: take what is already there, no waiting.
            while backlog.len() < cfg.batch_max {
                match rx.try_recv() {
                    Ok(p) => backlog.push_back(p),
                    Err(_) => break,
                }
            }
            backlog_gauge.store(backlog.len(), Ordering::Relaxed);
        }

        // Nonces older than the TTL would have expired locally anyway.
        let now = Instant::now();
        let before = backlog.len();
        backlog.retain(|p| now.duration_since(p.enqueued_at) < ttl);
        for _ in backlog.len()..before {
            crate::health::record_replay_async_dropped(&network, peer, "expired");
        }
        backlog_gauge.store(backlog.len(), Ordering::Relaxed);
        if backlog.is_empty() {
            continue;
        }

        let n = backlog.len().min(cfg.batch_max);
        let batch: Vec<Pending> = backlog.drain(..n).collect();
        let keys: Vec<String> = batch.iter().map(|p| p.key.clone()).collect();
        let sent = timeout(
            cfg.op_timeout,
            sink.set_nx_batch(peer, keys, cfg.nonce_ttl_secs),
        )
        .await;
        match sent {
            Ok(Ok(results)) if results.len() == batch.len() => {
                let now = Instant::now();
                let mut max_lag = Duration::ZERO;
                for (p, r) in batch.iter().zip(results.iter()) {
                    let lag = now.duration_since(p.enqueued_at);
                    max_lag = max_lag.max(lag);
                    crate::health::record_replay_peer(
                        &network,
                        peer,
                        if r.is_some() { "fresh" } else { "replay_async" },
                    );
                    health.record_ack(peer, lag);
                }
                debug!(network = %network, peer, batch = batch.len(), max_lag_ms = max_lag.as_millis(), "Replay nonces replicated");
                backlog_gauge.store(backlog.len(), Ordering::Relaxed);
            }
            other => {
                let what = match &other {
                    Ok(Ok(_)) => "short reply".to_string(),
                    Ok(Err(e)) => e.clone(),
                    Err(_) => "timeout".to_string(),
                };
                let result = match &other {
                    Ok(Err(e)) if e == "disconnected" => "disconnected",
                    Ok(_) => "error",
                    Err(_) => "timeout",
                };
                crate::health::record_replay_peer(&network, peer, result);
                warn!(network = %network, peer, batch = batch.len(), error = %what, "Replay nonce batch failed at peer; will retry");
                health.record_failure(peer, result);
                // Back to the front, oldest first; bounded.
                for p in batch.into_iter().rev() {
                    backlog.push_front(p);
                }
                trim_backlog(&mut backlog, cfg.queue_capacity, &health, peer);
                backlog_gauge.store(backlog.len(), Ordering::Relaxed);
                tokio::time::sleep(RETRY_BACKOFF).await;
            }
        }
    }
}

/// Drops the newest entries of a retry backlog beyond `capacity`. Each dropped nonce is counted
/// once in `ohttp_replay_async_dropped_total{reason="overflow"}` (by
/// [`ReplicationHealth::record_overflow`], which also degrades to strict).
fn trim_backlog<T>(
    backlog: &mut VecDeque<T>,
    capacity: usize,
    health: &ReplicationHealth,
    peer: usize,
) {
    while backlog.len() > capacity {
        backlog.pop_back();
        health.record_overflow(peer);
    }
}

async fn probe(
    peer: usize,
    sink: &dyn PeerSink,
    health: &ReplicationHealth,
    cfg: &ReplicationConfig,
) {
    let t = Instant::now();
    match timeout(cfg.op_timeout, sink.ping(peer)).await {
        Ok(Ok(())) => health.record_ack(peer, t.elapsed()),
        Ok(Err(e)) => health.record_failure(peer, &e),
        Err(_) => health.record_failure(peer, "probe timeout"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    /// A peer that records what it was asked to store, with a settable delay / failure.
    struct FakePeer {
        stored: Mutex<Vec<Vec<String>>>,
        delay_ms: AtomicU64,
        fail: AtomicBool,
        pings: AtomicUsize,
        n: usize,
    }

    impl FakePeer {
        fn new(n: usize) -> Arc<Self> {
            Arc::new(Self {
                stored: Mutex::new(vec![Vec::new(); n]),
                delay_ms: AtomicU64::new(0),
                fail: AtomicBool::new(false),
                pings: AtomicUsize::new(0),
                n,
            })
        }
        fn keys(&self, peer: usize) -> Vec<String> {
            self.stored.lock()[peer].clone()
        }
    }

    impl PeerSink for Arc<FakePeer> {
        fn set_nx_batch(
            &self,
            peer: usize,
            keys: Vec<String>,
            _ttl: u64,
        ) -> BoxFuture<'static, Result<Vec<Option<String>>, String>> {
            let me = self.clone();
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(me.delay_ms.load(Ordering::Relaxed)))
                    .await;
                if me.fail.load(Ordering::Relaxed) {
                    return Err("disconnected".to_string());
                }
                let mut g = me.stored.lock();
                let out = keys
                    .into_iter()
                    .map(|k| {
                        if g[peer].contains(&k) {
                            None
                        } else {
                            g[peer].push(k);
                            Some("OK".to_string())
                        }
                    })
                    .collect();
                Ok(out)
            })
        }
        fn ping(&self, _peer: usize) -> BoxFuture<'static, Result<(), String>> {
            let me = self.clone();
            Box::pin(async move {
                me.pings.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(me.delay_ms.load(Ordering::Relaxed)))
                    .await;
                if me.fail.load(Ordering::Relaxed) {
                    Err("disconnected".to_string())
                } else {
                    Ok(())
                }
            })
        }
        fn peers(&self) -> usize {
            self.n
        }
    }

    fn cfg(mode: ReplayPeerMode) -> ReplicationConfig {
        ReplicationConfig {
            network: "repl-test".into(),
            mode,
            // A nonce retried after a peer outage legitimately shows a few hundred ms of lag
            // (RETRY_BACKOFF); the limit here is above that so only the "slow peer" step trips it.
            max_lag: Duration::from_millis(1000),
            recovery: Duration::from_secs(2),
            op_timeout: Duration::from_millis(2000),
            nonce_ttl_secs: 600,
            queue_capacity: 8,
            batch_max: 4,
            batch_interval: Duration::from_millis(20),
            probe_interval: Duration::from_millis(100),
            failures_before_strict: 3,
        }
    }

    #[test]
    fn p99_picks_the_tail() {
        let ms = |v: &[u64]| p99_of(v.iter().map(|m| Duration::from_millis(*m)));
        assert_eq!(ms(&[]), Duration::ZERO);
        assert_eq!(ms(&[7]), Duration::from_millis(7));
        assert_eq!(ms(&[1, 2, 3]), Duration::from_millis(3));
        let mut many: Vec<u64> = (1..=100).collect();
        many.push(5000);
        assert_eq!(
            ms(&many),
            Duration::from_millis(100),
            "1 outlier in 101 is above the p99"
        );
        let two_hundred: Vec<u64> = (1..=200).collect();
        assert_eq!(ms(&two_hundred), Duration::from_millis(198));
    }

    #[tokio::test(start_paused = true)]
    async fn health_starts_strict_and_recovers_after_hysteresis() {
        crate::health::init_metrics();
        let h = ReplicationHealth::new(
            "h1",
            ReplayPeerMode::AsyncReads,
            2,
            Duration::from_millis(500),
            Duration::from_secs(30),
            3,
        );
        assert_eq!(h.effective(), Effective::Strict);
        assert_eq!(h.effective_label(), "async-reads-strict");
        // (Paused clock: an ack must be strictly after the bad event, as on a real clock.)
        tokio::time::advance(Duration::from_millis(1)).await;
        // One peer healthy is not enough.
        h.record_ack(0, Duration::from_millis(60));
        tokio::time::advance(Duration::from_secs(31)).await;
        assert_eq!(h.effective(), Effective::Strict);
        h.record_ack(1, Duration::from_millis(60));
        assert_eq!(
            h.effective(),
            Effective::Relaxed,
            "both peers acked after the last bad event and 30 s passed"
        );
        assert_eq!(h.effective_label(), "async-reads");

        // Lag p99 above the limit: strict again, and it stays strict during the hysteresis
        // even with good samples.
        h.record_ack(0, Duration::from_millis(900));
        assert_eq!(h.effective(), Effective::Strict);
        tokio::time::advance(Duration::from_secs(29)).await;
        tokio::time::advance(Duration::from_millis(1)).await;
        h.record_ack(0, Duration::from_millis(50));
        h.record_ack(1, Duration::from_millis(50));
        assert_eq!(h.effective(), Effective::Strict, "hysteresis not elapsed");
        tokio::time::advance(Duration::from_secs(2)).await;
        h.record_ack(0, Duration::from_millis(50));
        h.record_ack(1, Duration::from_millis(50));
        // The 900 ms sample has left the 10 s window by now, so the p99 is fine.
        assert_eq!(h.effective(), Effective::Relaxed);

        // Overflow degrades immediately; peer failure requires 3 consecutive failures.
        tokio::time::advance(Duration::from_millis(1)).await;
        h.record_overflow(1);
        assert_eq!(h.effective(), Effective::Strict);
        tokio::time::advance(Duration::from_secs(31)).await;
        h.record_ack(0, Duration::from_millis(50));
        assert_eq!(
            h.effective(),
            Effective::Strict,
            "peer 1 has not acked since the overflow"
        );
        h.record_ack(1, Duration::from_millis(50));
        assert_eq!(h.effective(), Effective::Relaxed);
        tokio::time::advance(Duration::from_millis(1)).await;
        // Now test consecutive failures: 1-2 failures should not degrade.
        h.record_failure(0, "disconnected");
        assert_eq!(
            h.effective(),
            Effective::Relaxed,
            "1 failure: still relaxed"
        );
        h.record_failure(0, "disconnected");
        assert_eq!(
            h.effective(),
            Effective::Relaxed,
            "2 failures: still relaxed"
        );
        h.record_failure(0, "disconnected");
        assert_eq!(
            h.effective(),
            Effective::Strict,
            "3 consecutive failures → strict"
        );
        tokio::time::advance(Duration::from_secs(60)).await;
        assert_eq!(
            h.effective(),
            Effective::Strict,
            "time alone never recovers: needs a fresh ack"
        );
        h.record_ack(0, Duration::from_millis(50));
        h.record_ack(1, Duration::from_millis(50));
        assert_eq!(h.effective(), Effective::Relaxed);
    }

    #[tokio::test(start_paused = true)]
    async fn failover_health_label_never_changes() {
        crate::health::init_metrics();
        let h = ReplicationHealth::new(
            "h2",
            ReplayPeerMode::Failover,
            1,
            Duration::from_millis(500),
            Duration::from_secs(1),
            3,
        );
        assert_eq!(h.effective_label(), "failover");
        h.record_failure(0, "x");
        assert_eq!(h.effective_label(), "failover");
        assert_eq!(
            h.effective(),
            Effective::Strict,
            "the health itself is still tracked"
        );
    }

    #[tokio::test]
    async fn replicator_delivers_in_batches_and_recovers() {
        crate::health::init_metrics();
        let fake = FakePeer::new(1);
        let r = AsyncReplicator::start(Arc::new(fake.clone()), cfg(ReplayPeerMode::AsyncReads));
        assert_eq!(
            r.health().effective(),
            Effective::Strict,
            "strict at startup"
        );

        for i in 0..6 {
            r.enqueue(&format!("replay:t:{i}"));
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
        let keys = fake.keys(0);
        assert_eq!(keys.len(), 6, "{keys:?}");
        assert_eq!(r.queue_depth(0), 0);
        // Recovery needs the hysteresis (2 s here) and acks (probes every 100 ms keep coming).
        assert_eq!(r.health().effective(), Effective::Strict);
        tokio::time::sleep(Duration::from_millis(2200)).await;
        assert_eq!(r.health().effective(), Effective::Relaxed);
        assert!(fake.pings.load(Ordering::Relaxed) > 0, "idle probes ran");
        assert!(r.health().lag_p99().unwrap() < Duration::from_millis(200));

        // A replayed nonce (already at the peer) is counted, not refused: still delivered.
        r.enqueue("replay:t:0");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(fake.keys(0).len(), 6);

        // Peer down: after 3 consecutive failures => strict, nonces are kept and delivered once it is back.
        fake.fail.store(true, Ordering::Relaxed);
        r.enqueue("replay:t:down-1");
        // Wait for 3 consecutive failures of the batch (retried after a 200ms backoff each) to
        // trigger strict mode: batch interval (20ms) + 2 backoffs (400ms), with margin.
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(r.health().effective(), Effective::Strict);
        assert!(r.queue_depth(0) >= 1, "kept for retry");
        fake.fail.store(false, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(
            fake.keys(0).contains(&"replay:t:down-1".to_string()),
            "{:?}",
            fake.keys(0)
        );
        assert_eq!(r.queue_depth(0), 0);
        tokio::time::sleep(Duration::from_millis(2200)).await;
        assert_eq!(
            r.health().effective(),
            Effective::Relaxed,
            "recovered after the hysteresis"
        );

        // Slow peer (1300 ms ack, within the op timeout but above max_lag 1000 ms): strict.
        fake.delay_ms.store(1300, Ordering::Relaxed);
        r.enqueue("replay:t:slow");
        tokio::time::sleep(Duration::from_millis(1600)).await;
        assert_eq!(r.health().effective(), Effective::Strict);
        assert!(
            fake.keys(0).contains(&"replay:t:slow".to_string()),
            "delivered, just late"
        );
        assert!(r.health().lag_p99().unwrap() >= Duration::from_millis(1000));
        fake.delay_ms.store(0, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn backlog_overflow_drop_counted_once() {
        crate::health::init_metrics();
        let net = "repl-overflow-once";
        let h = ReplicationHealth::new(
            net,
            ReplayPeerMode::AsyncReads,
            1,
            Duration::from_millis(500),
            Duration::from_secs(1),
            3,
        );
        let before = crate::health::replay_async_dropped_count(net, 0, "overflow");
        let mut backlog: VecDeque<u32> = (0..9).collect();
        trim_backlog(&mut backlog, 8, &h, 0);
        assert_eq!(backlog.len(), 8);
        assert_eq!(backlog.back(), Some(&7), "the newest entry is dropped");
        assert_eq!(
            crate::health::replay_async_dropped_count(net, 0, "overflow") - before,
            1,
            "one dropped nonce = one count"
        );
        assert_eq!(h.effective(), Effective::Strict);
    }

    #[tokio::test]
    async fn replicator_overflow_degrades_and_counts() {
        crate::health::init_metrics();
        let fake = FakePeer::new(1);
        fake.fail.store(true, Ordering::Relaxed);
        let mut c = cfg(ReplayPeerMode::AsyncReads);
        c.recovery = Duration::from_millis(300);
        let r = AsyncReplicator::start(Arc::new(fake.clone()), c);
        // Queue capacity 8 (+ the worker takes up to 4 into its backlog): flood it.
        for i in 0..40 {
            r.enqueue(&format!("replay:t:flood-{i}"));
        }
        assert_eq!(r.health().effective(), Effective::Strict);
        assert!(r.queue_depth(0) <= 8 + 8, "bounded: {}", r.queue_depth(0));
        fake.fail.store(false, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let delivered = fake.keys(0).len();
        assert!(
            (8..40).contains(&delivered),
            "the overflow was dropped, the rest delivered: {delivered}"
        );
        assert_eq!(r.queue_depth(0), 0);
    }

    #[tokio::test]
    async fn consecutive_failures_threshold() {
        crate::health::init_metrics();
        let fake = FakePeer::new(1);
        let mut c = cfg(ReplayPeerMode::AsyncReads);
        c.failures_before_strict = 3;
        c.probe_interval = Duration::from_millis(50);
        c.recovery = Duration::from_millis(200);
        let r = AsyncReplicator::start(Arc::new(fake.clone()), c);

        // Wait for startup to recover.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            r.health().effective(),
            Effective::Relaxed,
            "recovered from startup"
        );

        // Fail the peer: 1-2 failures should not degrade.
        fake.fail.store(true, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(90)).await; // At most 2 probe failures at t=0 and t=50
        assert_eq!(
            r.health().effective(),
            Effective::Relaxed,
            "1-2 failures: still relaxed"
        );

        // 3rd failure → strict (wait for t=100 probe).
        tokio::time::sleep(Duration::from_millis(70)).await;
        assert_eq!(
            r.health().effective(),
            Effective::Strict,
            "3 consecutive failures → strict"
        );

        // Recover the peer.
        fake.fail.store(false, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            r.health().effective(),
            Effective::Relaxed,
            "peer back: relaxed"
        );

        // Success resets: fail once, succeed, fail twice → still relaxed.
        fake.fail.store(true, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(60)).await; // 1 failure
        fake.fail.store(false, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(60)).await; // 1 success
        fake.fail.store(true, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(90)).await; // 2 failures
        assert_eq!(
            r.health().effective(),
            Effective::Relaxed,
            "counter reset by success"
        );

        // 3rd failure → strict again.
        tokio::time::sleep(Duration::from_millis(70)).await;
        assert_eq!(
            r.health().effective(),
            Effective::Strict,
            "3 consecutive → strict again"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn startup_transition_fast() {
        crate::health::init_metrics();
        let fake = FakePeer::new(1);
        let mut c = cfg(ReplayPeerMode::AsyncReads);
        c.failures_before_strict = 3;
        c.probe_interval = Duration::from_millis(100);
        c.recovery = Duration::from_secs(30);
        let r = AsyncReplicator::start(Arc::new(fake.clone()), c);
        assert_eq!(
            r.health().effective(),
            Effective::Strict,
            "strict at startup"
        );

        // After the first successful probe and hysteresis, should recover.
        tokio::time::advance(Duration::from_millis(1)).await; // past startup instant
        tokio::time::advance(Duration::from_millis(150)).await; // first probe initiated
        tokio::task::yield_now().await; // give the probe task a chance to run
        assert_eq!(
            r.health().effective(),
            Effective::Strict,
            "hysteresis not elapsed"
        );
        tokio::time::advance(Duration::from_secs(30)).await;
        tokio::task::yield_now().await; // yield to let maybe_recover check run
        assert_eq!(
            r.health().effective(),
            Effective::Relaxed,
            "healthy after one good probe + hysteresis"
        );
    }
}

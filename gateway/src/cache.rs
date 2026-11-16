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

// Response cache: the Redis plumbing behind the chain-validated cache.
//
// Two Redis roles:
//   - cache Redis (allkeys-lru, fail-open): every cached answer, the per-block cache and the
//     chain follower's index/tip/lock (`store::CacheStore` is implemented here);
//   - security Redis (noeviction, fail-closed): replay nonces and the shared cache epoch.
//
// Key layout: cached entries live under
//   ohttp:{network}:{backend_host}:{epoch}:v{KEY_VERSION}:{policy_hash}:
// so an epoch bump (operator INCR of `epoch:{network}`) or a policy change flushes them; the
// chain state lives under ohttp:{network}:{backend_host}:chain:v1: and the pinned tree-state
// tier under pinned:{network}:{backend_host}:treestate:v1:, and both survive either.
//
// What is cached and for how long is decided by `rpc_cache` (validated, immutable and
// tip-scoped entries; no TTLs) and `block_cache` (per-block entries validated against the
// index). The tip comes from the chain follower (`chain::ChainFollower`) through `TipCell`.
//
// The pinned tier (REDIS_PINNED_URL + PINNED_TREESTATE_RANGE) is a third Redis (noeviction,
// persistent) holding GetTreeState answers for a fixed finalized height range; it is served
// first and written through (to REDIS_PINNED_WRITE_URL when the pinned store is a read replica;
// a read replica alone is never written to).
//
// The permanent block tier (PERMANENT_REDIS_URL, `PermanentRedis` below) is a fourth store,
// a disk-backed Redis-protocol store: every final CompactBlock (depth >= 100,
// height >= Sapling activation), no TTL, never evicted. `block_cache` routes by height.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use bytes::Bytes;
use futures_util::future::BoxFuture;
use redis::{aio::ConnectionManager, AsyncCommands};
use sha2::{Digest, Sha256};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::origin::{ReplayPeerMode, RouteClass};
use crate::replication::{AsyncReplicator, Effective, PeerSink, ReplicationConfig};
use crate::rpc_cache::{self, grpc_message, BlockId, TreeStateHead};
use crate::store::{CacheStore, PermanentStore, TipCell};
use crate::store_conn::{
    error_summary, is_failover_signal, is_role_signal, redact_addrs, reopen_pause, store_error,
    Role, StoreConn, ROLE_CHECK_TIMEOUT,
};
use crate::write_fallback::{LocalWriteBack, WriteBackResult, WriteBackSink, WriteFallback};

pub use crate::rpc_cache::{grpc_block_id, height_key, CacheLookup, CacheMiss, MAX_CACHEABLE_SIZE};

/// Finalized depth: pinned tree states are written only this far below the tip.
pub const FINALIZED_DEPTH: u64 = 100;
/// How often a caught-up pinned backfill worker checks for newly final heights.
pub const PINNED_FOLLOW_INTERVAL: Duration = Duration::from_secs(60);
/// How often a gateway re-checks the pinned heights the backfill cursor already passed
/// (`pinned_sweep_pass`): a claim whose `INCR` reply was lost, or a height a worker gave up on,
/// is filled then.
pub const PINNED_SWEEP_INTERVAL: Duration = Duration::from_secs(600);
/// Heights per `EXISTS` pipeline of the sweep.
const PINNED_SWEEP_BATCH: u64 = 500;
/// Pause between two sweep batches, so a sweep never keeps the store busy.
const PINNED_SWEEP_PAUSE: Duration = Duration::from_millis(50);
/// Holes (heights a pass could not fill) retried per pass.
const PINNED_SWEEP_HOLES_PER_PASS: u64 = 100;
/// How long one process's claim of a sweep batch holds without a renewal (released when the
/// batch is done; renewed before and during every fill). Shorter than PINNED_SWEEP_INTERVAL, so
/// the claim of a process that died is free by the next pass.
const PINNED_SWEEP_CLAIM_TTL: Duration = Duration::from_secs(120);
/// Bound of one height's fill by the sweep (three fetch attempts and their pauses).
const PINNED_SWEEP_FILL_TIMEOUT: Duration = Duration::from_secs(60);
/// Upstream calls the pinned sweep of one cache may have alive at a time, awaited or abandoned
/// (a fill that is abandoned stops waiting for its call and lets it run to its own end, see
/// `pinned_fill`, `FillMode::Detached`). A fill waits for a permit, within its fill timeout,
/// only while all of them are alive.
const PINNED_SWEEP_FETCH_PERMITS: usize = 3;
/// The unit of the pauses between the attempts of one fill (1, 3 and 5 units after the first,
/// second and third failed attempt). Shorter in tests, which wait for them in real time.
const PINNED_FILL_PAUSE: Duration = if cfg!(test) {
    Duration::from_millis(20)
} else {
    Duration::from_secs(1)
};
/// How often a sweep fill in flight checks whether its store is still the one chosen (it is
/// abandoned, and its claim released, once it is not).
const PINNED_SWEEP_SUPERSEDED_CHECK: Duration = Duration::from_secs(1);
/// Retries of one hole with an upstream answer before the sweep drops it (logged,
/// `result="pinned_sweep_dropped"`): a height that keeps failing is left to the write-through
/// path. A retry without any answer (an upstream outage) does not count.
const PINNED_SWEEP_HOLE_ATTEMPTS: u64 = 10;
/// Heights just below the cursor that the sweep leaves to the workers that may still hold them
/// (plus one per worker).
const PINNED_SWEEP_MARGIN: u64 = 64;
/// After the store pinned entries are written to answers as a read replica, writes are skipped
/// for this long; then its `ROLE` is asked again before the next write.
pub const PINNED_READ_ONLY_RECHECK: Duration = Duration::from_secs(300);
/// A pinned store that did not answer its `ROLE` (timeout, connection error) is asked again
/// after this; pinned writes and the backfill wait meanwhile.
const PINNED_PROBE_RETRY: Duration = Duration::from_secs(30);
/// How often paused pinned backfill workers check whether the store takes writes again (the
/// store itself is asked only every PINNED_READ_ONLY_RECHECK).
const PINNED_BACKFILL_RESUME_CHECK: Duration = if cfg!(test) {
    Duration::from_millis(100)
} else {
    Duration::from_secs(30)
};
/// Lower bound of the operation timeout on the separate pinned write store
/// (REDIS_PINNED_WRITE_URL), which can be far away; the write is off the request path.
const PINNED_REMOTE_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
/// Cache key version: bump to orphan old entries on a format change.
const KEY_VERSION: u32 = 4;
/// Epoch refresh interval for per-request sync (seconds).
const EPOCH_REFRESH_SECS: u64 = 2;
/// How often the housekeeping task syncs the epoch and pings Redis.
const HOUSEKEEPING_SECS: u64 = 10;
/// Housekeeping rounds in a row the local store must answer before an epoch switched for a
/// bump seen at a peer gives way to its own value again (`ResponseCache::sync_epoch`).
const EPOCH_STEADY_ROUNDS: u32 = 3;
/// Bound of one housekeeping round's peer and standby checks, which run concurrently: a peer
/// that has not answered by then counts as not answering.
const HOUSEKEEPING_DEADLINE: Duration = Duration::from_secs(5);
/// Replay nonce lifetime (ZIP "Replay protection": reference implementation 600 s).
pub const REPLAY_TTL_SECS: u64 = 600;
/// Consecutive failed housekeeping PINGs after which a replay peer connection is dropped and
/// reopened. redis-rs' ConnectionManager reconnects on I/O errors only: after a managed Redis
/// failover the old TCP connection can hang (no RST) and every command just times out until the
/// kernel gives up, which can take minutes. 2 x HOUSEKEEPING_SECS = 20 s.
const PEER_PING_FAILURES_RECONNECT: u32 = 2;
/// Upper bound of the peer reconnect backoff: a connect attempt is cheap, and the peer should be
/// back as soon as its DNS name points at the new primary.
const PEER_RECONNECT_MAX_BACKOFF_SECS: u64 = 5;
/// Budget for opening a replay peer connection (TCP, TLS, AUTH). Without it, a connect to an
/// address that no longer answers (the old primary right after a failover, before its DNS name
/// moves) waits for the kernel's SYN retries, which can take minutes; the next attempt resolves
/// the name again. Above the ~6.3 s of ConnectionManager's own retries on a
/// refused connection, so those still end with their own error.
const PEER_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Consecutive failed housekeeping PINGs after which the cache Redis connection is dropped and
/// reopened (a hung connection never errors, so ConnectionManager would keep it). The cache is
/// fail-open: meanwhile requests are cache misses.
const CACHE_PING_FAILURES_RECONNECT: u32 = 2;

#[derive(Clone)]
pub struct ResponseCache {
    /// Cache Redis (allkeys-lru, fail-open). ArcSwapOption allows lock-free swaps on reconnect.
    cache_conn: Arc<ArcSwapOption<ConnectionManager>>,
    /// Consecutive failed housekeeping PINGs of the cache Redis (see CACHE_PING_FAILURES_RECONNECT).
    cache_ping_failures: Arc<AtomicU32>,
    /// Security Redis (noeviction, fail-closed): replay nonces and the shared epoch. Follows a
    /// failover of the store (`StoreConn`, `Role::Primary`).
    security_conn: Option<Arc<StoreConn>>,
    /// The chain tip, written by the follower.
    tip: Arc<TipCell>,
    /// Cache epoch, mirrored from Redis.
    epoch: Arc<AtomicU64>,
    network: String,
    backend_host: String,
    last_epoch_sync: Arc<AtomicU64>,
    redis_timeout: Duration,
    /// Policy/limits hash for cache namespace isolation (MAX_BLOCK_RANGE + BACKENDS_POLICY).
    policy_hash: String,
    pinned_conn: Option<Arc<StoreConn>>,
    /// Where pinned entries are written when `pinned_conn` is a read replica
    /// (REDIS_PINNED_WRITE_URL, normally its primary); None: they are written to `pinned_conn`.
    /// Swappable: a write store unreachable at startup is connected in the background.
    pinned_write_conn: Arc<ArcSwapOption<StoreConn>>,
    /// Pinned writes are skipped until this time (ms since the UNIX epoch, 0 = not skipped):
    /// the store they go to is a read replica (see `pinned_writer`).
    pinned_read_only_until: Arc<AtomicU64>,
    /// Bumped whenever the store pinned entries go to changes (the write store connected, the
    /// store found read-only or writable again): backfill workers bound to an older value go
    /// back to choosing their store.
    pinned_writer_gen: Arc<AtomicU64>,
    /// Serializes the transitions of the pinned writer's state (the write connection, the
    /// read-only pause and the generation, see `pinned_writer_bound`). Never held across an
    /// await.
    pinned_writer_lock: Arc<parking_lot::Mutex<()>>,
    /// Inclusive height range served from the pinned tier.
    pinned_range: Option<(u64, u64)>,
    /// The lowest height the pinned backfill and sweep fill (`with_pinned`: the network's
    /// Sapling activation; 0 = the range start). Below it the light wallet server has no tree
    /// state to answer with, so those heights are never fetched, and holes there are dropped.
    pinned_fill_from: u64,
    cache_redis_url: String,
    /// The other origins' security Redis (REPLAY_PEER_URLS); None in a single-origin deployment.
    replay_peers: Option<Arc<ReplayPeers>>,
    /// Asynchronous nonce replication (REPLAY_PEER_MODE=async-reads|failover); None otherwise.
    replicator: Option<Arc<AsyncReplicator>>,
    /// The standby origins' security stores (REPLAY_STANDBY_URLS) and the replication of every
    /// admitted WRITE nonce to them; None without standby stores.
    standby_peers: Option<Arc<ReplayPeers>>,
    standby_replicator: Option<Arc<AsyncReplicator>>,
    /// Replica acknowledgement of WRITE nonces (REPLAY_WRITE_WAIT_REPLICAS); None when off.
    write_wait: Option<Arc<WriteWait>>,
    /// Local AOF fsync of WRITE nonces no peer took (REPLAY_LOCAL_WAITAOF_MS); None when off.
    local_aof: Option<Arc<LocalAof>>,
    /// The peer fallback of the WRITE replica wait (write_fallback.rs); with `write_wait`.
    write_fallback: Option<Arc<WriteFallback>>,
    /// The hub path of the fallback (write_fallback.rs): async-reads with peers that wait;
    /// its queue writes back to the peers.
    hub_fallback: Option<Arc<WriteFallback>>,
    /// REPLAY_UNAVAILABLE_FALLBACK: confirm at the fallback store when the store that normally
    /// decides gives no verdict at all (write_fallback.rs, "Unavailable store").
    unavailable_fallback: bool,
    /// Consecutive WRITEs the peers could not confirm while the local store gave no verdict
    /// (`REPLAY_FALLBACK_HEALTH_FAILURES`): `/healthz` stops counting on the fallback then.
    fallback_health: Arc<FallbackHealth>,
    /// The epoch's state machine (`EpochState`). `epoch` is only written while this lock is
    /// held, so a refresh from the local store and a switch for a bump seen at a peer never
    /// overwrite each other.
    epoch_state: Arc<parking_lot::Mutex<EpochState>>,
    /// The permits of the upstream calls the pinned sweep starts (PINNED_SWEEP_FETCH_PERMITS,
    /// shared by the clones): each call holds one from before it is spawned until its task is
    /// gone (`pinned_fill`, `FillMode::Detached`).
    pinned_sweep_fetch_permits: Arc<tokio::sync::Semaphore>,
}

/// The shared epoch's state besides its value (`ResponseCache::epoch`, written under the same
/// lock).
#[derive(Default)]
struct EpochState {
    /// Each replay peer's shared epoch as last read by housekeeping, by store identity (its
    /// position and a hash of its URL), to notice an epoch bump while the local store gives no
    /// answer (`sync_epoch`).
    baselines: std::collections::HashMap<String, u64>,
    /// While Some: the epoch was moved to a fresh value for a bump seen at a peer, and the
    /// housekeeping rounds since in which the local store answered (`EPOCH_STEADY_ROUNDS`).
    switch: Option<u32>,
}

/// `REPLAY_FALLBACK_HEALTH_FAILURES` default: consecutive WRITEs decided at the peer stores for an
/// unreachable local store that failed closed (`path="local_unavailable"`, result
/// `unacknowledged`, `unavailable` or `overflow`) after which `/healthz` fails although every peer
/// answers its PING.
pub const DEFAULT_REPLAY_FALLBACK_HEALTH_FAILURES: u32 = 20;
/// `REPLAY_FALLBACK_HEALTH_WINDOW_SECS` default: such failures count as consecutive while the
/// last one is at most this old; the next accepted WRITE or a quiet window clears them.
pub const DEFAULT_REPLAY_FALLBACK_HEALTH_WINDOW_SECS: u64 = 60;

/// Whether serving through the peer stores still works for WRITEs (`serves_without_local_store`).
/// The peers answering their PINGs says nothing about a peer that is short of replicas (every
/// WRITE unacknowledged), a full write-back queue (every WRITE overflows) or a broken `WAIT`
/// connection: `/healthz` stayed 200 while every WRITE failed closed.
///
/// `threshold` failures in a row (the last within `window` of the one before) withdraw the
/// gateway (`failing`), and it stays withdrawn until the local store answers again
/// (`local_answered`) or a WRITE decided through the fallback runs (`accepted`): a load balancer
/// that took it out of rotation sends it nothing that could tell, so returning on a timer alone
/// would only send traffic back to fail again. The state is one mutex-guarded value, so
/// concurrent requests never see half an update.
pub struct FallbackHealth {
    /// 0 = off.
    threshold: u32,
    window: Duration,
    base: std::time::Instant,
    state: parking_lot::Mutex<FallbackHealthState>,
}

#[derive(Default)]
struct FallbackHealthState {
    failures: u32,
    /// Milliseconds since `base` of the last counted failure (0 = none).
    last_failure_ms: u64,
    withdrawn: bool,
}

impl FallbackHealth {
    pub fn new(threshold: u32, window: Duration) -> Self {
        Self {
            threshold,
            window,
            base: std::time::Instant::now(),
            state: parking_lot::Mutex::new(FallbackHealthState::default()),
        }
    }

    fn now_ms(&self) -> u64 {
        self.base.elapsed().as_millis() as u64 + 1
    }

    /// `REPLAY_FALLBACK_HEALTH_FAILURES` / `REPLAY_FALLBACK_HEALTH_WINDOW_SECS`.
    pub fn from_env() -> anyhow::Result<Self> {
        Self::parse(
            std::env::var("REPLAY_FALLBACK_HEALTH_FAILURES")
                .ok()
                .as_deref(),
            std::env::var("REPLAY_FALLBACK_HEALTH_WINDOW_SECS")
                .ok()
                .as_deref(),
        )
    }

    pub fn parse(failures: Option<&str>, window_secs: Option<&str>) -> anyhow::Result<Self> {
        let threshold = match failures.map(str::trim).filter(|s| !s.is_empty()) {
            None => DEFAULT_REPLAY_FALLBACK_HEALTH_FAILURES,
            Some(v) => v.parse::<u32>().map_err(|_| {
                anyhow::anyhow!(
                    "REPLAY_FALLBACK_HEALTH_FAILURES must be a non-negative integer, got '{v}'"
                )
            })?,
        };
        let window = match window_secs.map(str::trim).filter(|s| !s.is_empty()) {
            None => DEFAULT_REPLAY_FALLBACK_HEALTH_WINDOW_SECS,
            Some(v) => match v.parse::<u64>() {
                Ok(n) if n > 0 => n,
                _ => anyhow::bail!(
                    "REPLAY_FALLBACK_HEALTH_WINDOW_SECS must be a positive integer, got '{v}'"
                ),
            },
        };
        Ok(Self::new(threshold, Duration::from_secs(window)))
    }

    /// A WRITE that only the fallback could decide (the local store gave no verdict) failed
    /// closed.
    pub fn failed(&self) {
        let now = self.now_ms();
        let mut st = self.state.lock();
        if st.last_failure_ms == 0
            || now.saturating_sub(st.last_failure_ms) > self.window.as_millis() as u64
        {
            st.failures = 1;
        } else {
            st.failures = st.failures.saturating_add(1);
        }
        st.last_failure_ms = now;
        if self.threshold > 0 && st.failures >= self.threshold {
            st.withdrawn = true;
        }
    }

    /// Such a WRITE ran: the fallback works.
    pub fn accepted(&self) {
        *self.state.lock() = FallbackHealthState::default();
    }

    /// The local store answers again: the fallback is not needed. Whether the gateway was
    /// withdrawn until now.
    pub fn local_answered(&self) -> bool {
        let mut st = self.state.lock();
        let was_withdrawn = st.withdrawn;
        if st.withdrawn || st.failures != 0 {
            *st = FallbackHealthState::default();
        }
        was_withdrawn
    }

    /// Whether the gateway is withdrawn (`threshold` failures in a row, no recovery since).
    pub fn failing(&self) -> bool {
        self.state.lock().withdrawn
    }

    /// The failures in a row so far (diagnostics, tests).
    pub fn consecutive_failures(&self) -> u32 {
        self.state.lock().failures
    }
}

/// What the peer stage said about one request's nonce (`replicate_nonce_checked`,
/// `admit_without_local`), for the steps that follow (`confirm_write_nonce`,
/// `replicate_write_to_standby`). Only those admission steps build one, bound to the nonce of
/// the request they checked: it has no public constructor, no public fields and is not `Clone`,
/// and a step given the `PeerCheck` of another request refuses it.
#[derive(Debug, PartialEq, Eq)]
pub struct PeerCheck {
    /// The nonce key of the request it was built for.
    key: String,
    /// A peer already held the nonce: a cross-origin replay.
    replay: bool,
    /// Every peer (at least one) stored the nonce as new and acknowledged it on its own
    /// replicas (`REPLAY_PEER_WAIT_REPLICAS` >= 1), synchronously, before the local wait.
    durable_at_peers: bool,
    /// `failover` mode, a WRITE with `REPLAY_WRITE_WAIT_REPLICAS`: the asynchronous replication
    /// to the peers is left to `confirm_write_nonce`, after the local verdict, so that a
    /// synchronous check at the peers there never meets this request's own nonce.
    deferred: bool,
    /// The WRITE was also confirmed at the standby stores synchronously (the hub fallback or
    /// window): no asynchronous hand-off to them is needed.
    at_standby: bool,
    /// The hub took the nonce but its replicas did not acknowledge it: the WRITE runs only if
    /// the local replicas do (`confirm_write_nonce`).
    hub_needs_local_ack: bool,
    /// With `hub_needs_local_ack`: the hub gave no verdict at all (unreachable), rather than a
    /// short acknowledgement. Only the metric label differs.
    hub_unavailable: bool,
    /// The local store gave no verdict and the request was decided at the peer stores instead
    /// (`admit_without_local`): the local replica wait does not apply.
    local_bypassed: bool,
    /// The WRITE's route may run on one store's verdict (`WritePolicy::OneSided`); the replica
    /// wait that follows (`confirm_write_nonce`) applies the same policy.
    one_sided: bool,
    /// The peers (bit `i` = peer `i`) that did not take the nonce (tolerated) and get it
    /// asynchronously once the WRITE is finally admitted: `confirm_write_nonce` hands it over
    /// only if the local replica wait lets the WRITE run.
    replicate_to_after: Vec<usize>,
}

impl PeerCheck {
    /// Nothing decided yet; the step that returns it sets the key (`bound_to`).
    fn blank() -> Self {
        Self {
            key: String::new(),
            replay: false,
            durable_at_peers: false,
            deferred: false,
            at_standby: false,
            hub_needs_local_ack: false,
            hub_unavailable: false,
            local_bypassed: false,
            one_sided: false,
            replicate_to_after: Vec::new(),
        }
    }

    fn bound_to(mut self, local: &LocalCheck) -> Self {
        self.key = local.key.clone();
        self
    }

    /// Whether it belongs to the request whose local check is `local`.
    fn belongs_to(&self, local: &LocalCheck) -> bool {
        !self.key.is_empty() && self.key == local.key
    }

    /// A peer (or the fallback store) already held the nonce: a cross-origin replay.
    pub fn replay(&self) -> bool {
        self.replay
    }

    /// The WRITE was confirmed at the standby stores synchronously already.
    pub fn at_standby(&self) -> bool {
        self.at_standby
    }

    /// Decided at the peer stores without the local store (`admit_without_local`): the local
    /// replica wait does not apply.
    pub fn local_bypassed(&self) -> bool {
        self.local_bypassed
    }
}

/// Whether a WRITE may run on the verdict of one store alone (`REPLAY_ONE_SIDED_WRITE_ROUTES`,
/// write_fallback.rs "Partition tolerance").
///
/// Every admission path asks the store that decides (the local store in `sync` and `failover`
/// mode, the hub in `async-reads`) and, where one is configured, a second store synchronously
/// (the peers in `sync` mode and in `failover` mode with the peer fallback, the confirming standby
/// stores of a read origin, the own store of an `async-reads` origin with its own replica wait).
/// A WRITE under `BothStores` runs only once both took its nonce as new; a path that would let it
/// run on one of them alone (the other unreachable, slow or not asked) fails it closed instead,
/// counted as `ohttp_replay_write_fallback_total{result="one_sided_refused"}`. `OneSided` keeps
/// those paths: for routes whose upstream refuses a second copy of the same request by itself.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WritePolicy {
    one_sided: bool,
}

impl WritePolicy {
    /// Not on `REPLAY_ONE_SIDED_WRITE_ROUTES` (the default): both stores must take the nonce.
    pub const BOTH_STORES: Self = Self { one_sided: false };
    /// On `REPLAY_ONE_SIDED_WRITE_ROUTES`: one store's verdict may admit it.
    pub const ONE_SIDED: Self = Self { one_sided: true };

    pub fn for_route(one_sided: bool) -> Self {
        if one_sided {
            Self::ONE_SIDED
        } else {
            Self::BOTH_STORES
        }
    }

    pub fn one_sided(self) -> bool {
        self.one_sided
    }
}

/// The local replay check of one request (`check_replay_detailed`), required by every later
/// admission step (`replicate_nonce_checked`, `admit_without_local`, `confirm_write_nonce`,
/// `replicate_write_to_standby`). It has no public constructor and is not `Clone`, so a caller
/// can neither forge a verdict nor drop what the check saw: notably a `sync`-mode peer that gave
/// no verdict (`LocalReplayCheck::NewPeersUnconfirmed`), which only the peer stage, once the
/// request is classified, may retry or accept.
#[derive(Debug)]
pub struct LocalCheck {
    key: String,
    verdict: LocalReplayCheck,
    /// `sync` mode: the value the nonce was written to the peers with, and the peers (by
    /// position) whose `SET NX` timed out: retried once (`SET ... NX GET`) after classification.
    sync_value: String,
    sync_timed_out: Vec<usize>,
    /// `sync` mode: the peers that gave no verdict at all (timed out, an error, not connected).
    sync_unanswered: usize,
    /// `sync` mode with REPLAY_PEER_FAIL_CLOSED: the only peers without a verdict timed out,
    /// and the request fails closed unless they take the nonce on the retry after
    /// classification (READs included).
    sync_strict: bool,
}

impl LocalCheck {
    pub fn verdict(&self) -> LocalReplayCheck {
        self.verdict
    }

    /// A check that found the nonce new locally, for unit tests of the later steps.
    #[cfg(test)]
    fn assume_new(key: String) -> Self {
        Self {
            key,
            verdict: LocalReplayCheck::New,
            sync_value: String::new(),
            sync_timed_out: Vec::new(),
            sync_unanswered: 0,
            sync_strict: false,
        }
    }
}

/// The local verdict of `check_replay_detailed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalReplayCheck {
    /// The local store took the nonce as new.
    New,
    /// `sync` mode: the local store took the nonce as new, every peer that answered too, but a
    /// peer gave no verdict and `REPLAY_PEER_FAIL_CLOSED=0` tolerated it. New for a READ and for
    /// a WRITE on `REPLAY_ONE_SIDED_WRITE_ROUTES`; any other WRITE fails closed once classified,
    /// unless the retry of the peers whose `SET NX` timed out finds the nonce new there. With
    /// `REPLAY_PEER_FAIL_CLOSED=1` it means peers whose `SET NX` timed out: every request (READ
    /// or WRITE) fails closed once classified unless the retry finds the nonce new there.
    NewPeersUnconfirmed,
    /// The local store already held the nonce.
    Replay,
    /// The local store gave no verdict (unreachable, a timeout or an error) and the unavailable
    /// fallback can decide instead, once the request is classified (`admit_without_local`).
    Unavailable,
}

/// The retry of a `sync`-mode gap (`ResponseCache::retry_sync_gap`).
enum SyncRetry {
    /// A peer holds the nonce for another request.
    Replay,
    /// Every peer that gave no verdict took the nonce now.
    Taken,
    /// Still not every peer took it.
    Gap,
}

/// The decision of `confirm_write_nonce` for a WRITE whose nonce is new locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteAdmission {
    Run,
    /// A peer store already held the nonce.
    Replay,
}

/// What the hub path of the fallback decided (`hub_short_ack_fallback`).
enum HubFallback {
    Replay,
    AtStandby,
    NeedsLocalAck,
}

/// The outcome of the local replica wait of a WRITE nonce.
enum LocalWait {
    Acked,
    /// The nonce is on the local primary (`SET XX` succeeded) but fewer replicas acknowledged
    /// it than required: the case the peer fallback covers.
    Short(anyhow::Error),
    /// The store gave no answer (a timeout, a broken connection or a failover signal): covered
    /// by the peer fallback only with REPLAY_UNAVAILABLE_FALLBACK.
    Unavailable(anyhow::Error),
    /// Any other outcome, notably a nonce that is not on the node reached: never covered.
    Failed(anyhow::Error),
}

/// `REPLAY_WRITE_WAIT_REPLICAS` / `REPLAY_WRITE_WAIT_MS`: before a WRITE (anything not on
/// `REPLAY_READ_ROUTES`) is executed, its replay nonce must be acknowledged by this many
/// replicas of the security Redis (`WAIT`). An asynchronously replicated store (a managed Redis
/// with automatic failover) otherwise loses the newest nonces when a replica is promoted, and a
/// WRITE accepted just before the failover could be replayed once after it. READs are not
/// delayed: replaying one yields the replayer nothing (the response is sealed to the original
/// Client) and changes no state. 0 (default) disables the check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteWaitConfig {
    pub replicas: u32,
    pub timeout_ms: u64,
}

pub const DEFAULT_REPLAY_WRITE_WAIT_MS: u64 = 100;

/// `REPLAY_PEER_WAIT_REPLICAS` default: a WRITE checked at a peer (a peer origin's synchronous
/// check at a shared store) waits for one replica of that store. `0` disables it,
/// for a peer store without replicas.
pub const DEFAULT_REPLAY_PEER_WAIT_REPLICAS: u32 = 1;

/// Opening a peer's `WAIT` connection (normally done at startup by `ReplayPeers::with_wait`).
const PEER_WAIT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const PEER_WAIT_ATTEMPTS: usize = 2;

/// `REPLAY_WAIT_CONNS` default: dedicated `WAIT` connections per store (the local security
/// store, each peer, each standby store).
pub const DEFAULT_REPLAY_WAIT_CONNS: usize = 8;
/// Upper bound of `REPLAY_WAIT_CONNS`.
pub const MAX_REPLAY_WAIT_CONNS: usize = 32;

/// `REPLAY_WAIT_CONNS` (default `DEFAULT_REPLAY_WAIT_CONNS`, 1 to `MAX_REPLAY_WAIT_CONNS`).
pub fn wait_conns_from_env() -> anyhow::Result<usize> {
    parse_wait_conns(std::env::var("REPLAY_WAIT_CONNS").ok().as_deref())
}

pub fn parse_wait_conns(raw: Option<&str>) -> anyhow::Result<usize> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(DEFAULT_REPLAY_WAIT_CONNS),
        Some(v) => match v.parse::<usize>() {
            Ok(n) if (1..=MAX_REPLAY_WAIT_CONNS).contains(&n) => Ok(n),
            _ => anyhow::bail!(
                "REPLAY_WAIT_CONNS must be an integer from 1 to {MAX_REPLAY_WAIT_CONNS}, got '{v}'"
            ),
        },
    }
}

/// While a `WAIT` of a store took longer than its round trip plus half its timeout, came back
/// short or timed out within this long, its pool hands out connections exclusively.
const WAIT_EXCLUSIVE_HOLD: Duration = Duration::from_secs(10);
/// How long a leased `WAIT` may run past its caller's budget before its connection is replaced
/// (its reply would never be read) and the lease returned.
const WAIT_DRAIN_EXTRA: Duration = Duration::from_secs(5);
/// The round-trip floor of a pool (the fastest recent `WAIT`) is forgotten after this long, so a
/// store that moved further away is measured again.
const WAIT_FLOOR_RESET: Duration = Duration::from_secs(60);

/// The dedicated `WAIT` connections of one store (`REPLAY_WAIT_CONNS`), used in two modes.
///
/// - **Shared** (the normal case): `WAIT`s that the replicas acknowledge at once return at once,
///   so many of them can be in flight on one connection, as with a single connection before;
///   the pool spreads them over its connections round robin. This puts no cap on the WRITE rate.
/// - **Exclusive**: `WAIT` blocks the connection it runs on until the replicas acknowledge or its
///   timeout, so while the replicas resync every `WAIT` takes its whole timeout and the ones
///   behind it on the same connection queue up, until the later ones run out of time. While a
///   `WAIT` of this store recently took longer than the fastest recent one plus half its timeout,
///   came back short or timed out (`WAIT_EXCLUSIVE_HOLD`), each connection is handed to one
///   request at a time (`Lease`), and a WRITE that finds every connection busy waits in the
///   process, where the time it waited is known. The pool then admits at most
///   `REPLAY_WAIT_CONNS / (round trip + WAIT time)` WRITEs per second to this store's `WAIT`;
///   the others take the saturated path (a short acknowledgement after a `SET XX`).
///
/// A lease is returned only once its command is done: a request that gave up (its budget, or the
/// caller went away) leaves the command running in a task of its own that still holds the lease
/// (`run_leased`), so the next request never queues behind it.
struct LeasePool {
    /// Per connection: (leased exclusively, shared commands in flight). One lock, so a
    /// connection is never leased while shared work is on it, nor shared while leased.
    state: parking_lot::Mutex<Vec<(bool, u32)>>,
    /// Woken whenever a connection is released or (re)opened (`wake`).
    changed: Arc<tokio::sync::Notify>,
    n: usize,
    next: AtomicU64,
    /// The turn of the housekeeping checks (`take_idle_for_check`).
    next_check: AtomicU64,
    base: std::time::Instant,
    /// Shared mode while `now_ms() >= exclusive_until_ms`.
    exclusive_until_ms: AtomicU64,
    /// The round-trip floor (`WaitFloor`), one lock for all of it.
    floor: parking_lot::Mutex<WaitFloor>,
    /// Half the `WAIT` timeout: a `WAIT` that took this much longer than the floor waited for
    /// replicas.
    slow_margin_ms: u64,
    /// `WAIT_FLOOR_RESET` in ms.
    floor_reset_ms: u64,
}

/// One connection of a `LeasePool`, held until dropped: shared with other requests (counted in
/// flight), or leased to this one alone.
struct WaitSlot {
    pool: Arc<LeasePool>,
    index: usize,
    leased: bool,
}

impl WaitSlot {
    fn index(&self) -> usize {
        self.index
    }

    /// Whether the connection is this request's alone (exclusive mode).
    fn leased(&self) -> bool {
        self.leased
    }
}

impl Drop for WaitSlot {
    fn drop(&mut self) {
        {
            let mut st = self.pool.state.lock();
            let (leased, inflight) = &mut st[self.index];
            if self.leased {
                *leased = false;
            } else {
                *inflight = inflight.saturating_sub(1);
            }
        }
        self.pool.changed.notify_waiters();
    }
}

/// What `LeasePool::acquire` got.
enum Acquired {
    Slot(WaitSlot),
    /// Every eligible connection stayed taken until the deadline.
    Busy,
    /// No connection was eligible (open, reaching the primary) by the deadline.
    NoneOpen,
}

impl Acquired {
    fn into_slot(self) -> Option<WaitSlot> {
        match self {
            Acquired::Slot(s) => Some(s),
            _ => None,
        }
    }

    #[cfg(test)]
    fn slot(self) -> Option<WaitSlot> {
        match self {
            Acquired::Slot(s) => Some(s),
            _ => None,
        }
    }
}

/// How one `WAIT` went, for the mode of its pool (`LeasePool::observe`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum WaitOutcome {
    Acked,
    /// Fewer replicas than required, a timeout or an error.
    Slow,
}

/// The fastest recent acknowledged `WAIT` of a pool (ms; u64::MAX = none yet) and when that
/// floor was set; while it is measured again (`samples_left` of `WAIT_FLOOR_SAMPLES` left), the
/// smallest of those samples so far.
struct WaitFloor {
    floor_ms: u64,
    since_ms: u64,
    samples_left: u32,
    candidate_ms: u64,
}

/// Samples the round-trip floor of a pool is measured again from (`WAIT_FLOOR_RESET`).
const WAIT_FLOOR_SAMPLES: u32 = 8;

impl LeasePool {
    fn new(n: usize, wait_timeout_ms: u64) -> Arc<Self> {
        Self::with_changed(n, wait_timeout_ms, Arc::new(tokio::sync::Notify::new()))
    }

    /// `new` waking its waiters through `changed` (shared with whatever else makes one of its
    /// connections usable, e.g. a peer's main connection coming back).
    fn with_changed(
        n: usize,
        wait_timeout_ms: u64,
        changed: Arc<tokio::sync::Notify>,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: parking_lot::Mutex::new(vec![(false, 0); n]),
            changed,
            n,
            next: AtomicU64::new(0),
            next_check: AtomicU64::new(0),
            base: std::time::Instant::now(),
            exclusive_until_ms: AtomicU64::new(0),
            floor: parking_lot::Mutex::new(WaitFloor {
                floor_ms: u64::MAX,
                since_ms: 0,
                samples_left: 0,
                candidate_ms: u64::MAX,
            }),
            slow_margin_ms: wait_timeout_ms / 2,
            floor_reset_ms: WAIT_FLOOR_RESET.as_millis() as u64,
        })
    }

    /// `new` with another floor reset period (tests).
    #[cfg(test)]
    fn with_floor_reset(n: usize, wait_timeout_ms: u64, reset: Duration) -> Arc<Self> {
        let mut pool = Arc::try_unwrap(Self::new(n, wait_timeout_ms)).ok().unwrap();
        pool.floor_reset_ms = reset.as_millis() as u64;
        Arc::new(pool)
    }

    fn now_ms(&self) -> u64 {
        self.base.elapsed().as_millis() as u64 + 1
    }

    /// Whether connections are handed out exclusively right now.
    fn exclusive(&self) -> bool {
        self.now_ms() < self.exclusive_until_ms.load(Ordering::Relaxed)
    }

    /// Record how a `WAIT` on this store went and how long it took (`elapsed`, its round trip
    /// included). The floor is the fastest recent acknowledged `WAIT`; every `WAIT_FLOOR_RESET`
    /// it is measured again as the fastest of the next `WAIT_FLOOR_SAMPLES` (the old floor
    /// stays in force meanwhile), so one slow sample never becomes the floor.
    fn observe(&self, outcome: WaitOutcome, elapsed: Duration) {
        let now = self.now_ms();
        let took = elapsed.as_millis() as u64;
        let slow = match outcome {
            WaitOutcome::Slow => true,
            WaitOutcome::Acked => {
                let mut f = self.floor.lock();
                if f.since_ms == 0 {
                    f.since_ms = now;
                } else if now.saturating_sub(f.since_ms) > self.floor_reset_ms
                    && f.samples_left == 0
                {
                    f.candidate_ms = u64::MAX;
                    f.samples_left = WAIT_FLOOR_SAMPLES;
                    f.since_ms = now;
                }
                if f.samples_left > 0 {
                    f.candidate_ms = f.candidate_ms.min(took);
                    f.samples_left -= 1;
                    if f.samples_left == 0 {
                        f.floor_ms = f.candidate_ms;
                    }
                } else {
                    f.floor_ms = f.floor_ms.min(took);
                }
                took > f.floor_ms.saturating_add(self.slow_margin_ms)
            }
        };
        if slow {
            self.exclusive_until_ms.fetch_max(
                now + WAIT_EXCLUSIVE_HOLD.as_millis() as u64,
                Ordering::Relaxed,
            );
        }
    }

    /// The current floor (tests).
    #[cfg(test)]
    fn floor(&self) -> u64 {
        self.floor.lock().floor_ms
    }

    /// A connection was (re)opened: requests waiting in `acquire` look again (the stores wake
    /// `changed` directly; tests).
    #[cfg(test)]
    fn wake(&self) {
        self.changed.notify_waiters();
    }

    /// A connection for one `WAIT`, waiting at most until `deadline` for one to be released or
    /// opened. Only a connection that `eligible` accepts (open, reaching the primary) is ever
    /// handed out. Shared mode: the next one round robin that is not leased. Exclusive mode: one
    /// that is neither leased nor running shared work (drained). A connection whose exclusive
    /// mode ended while leased stays out of shared use until its lease is returned.
    ///
    /// None by `deadline`: `Busy` if an eligible connection exists but all of them are taken
    /// (the `WAIT`s ahead ran into their timeout: the saturated path), `NoneOpen` if none is
    /// eligible.
    async fn acquire(
        self: &Arc<Self>,
        deadline: tokio::time::Instant,
        eligible: impl Fn(usize) -> bool,
    ) -> Acquired {
        if self.n == 0 {
            return Acquired::NoneOpen;
        }
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let exclusive = self.exclusive();
            let start = self.next.fetch_add(1, Ordering::Relaxed) as usize;
            let picked = {
                let mut st = self.state.lock();
                let pick = (0..self.n).map(|k| (start + k) % self.n).find(|i| {
                    let (leased, inflight) = st[*i];
                    !leased && (!exclusive || inflight == 0) && eligible(*i)
                });
                if let Some(i) = pick {
                    if exclusive {
                        st[i].0 = true;
                    } else {
                        st[i].1 += 1;
                    }
                }
                pick
            };
            if let Some(index) = picked {
                return Acquired::Slot(WaitSlot {
                    pool: self.clone(),
                    index,
                    leased: exclusive,
                });
            }
            if tokio::time::Instant::now() >= deadline
                || tokio::time::timeout_at(deadline, notified).await.is_err()
            {
                return if (0..self.n).any(&eligible) {
                    Acquired::Busy
                } else {
                    Acquired::NoneOpen
                };
            }
        }
    }

    /// One connection no request holds, leased to a housekeeping check (a busy one is never
    /// taken, and the checked one goes to no request until the check is answered). Staggered:
    /// one per call, in turn, leased only while another connection of the pool stays idle too,
    /// so a WRITE never waits behind a check; the last idle connection (also of a pool of one)
    /// is checked as shared work, in shared mode only.
    ///
    /// Only an `eligible` connection (open and usable now) counts as idle: a closed one is
    /// neither checked nor counted as the one left free.
    fn take_idle_for_check(self: &Arc<Self>, eligible: impl Fn(usize) -> bool) -> Option<WaitSlot> {
        let mut st = self.state.lock();
        let idle: Vec<usize> = (0..self.n)
            .filter(|i| st[*i] == (false, 0) && eligible(*i))
            .collect();
        if idle.is_empty() {
            return None;
        }
        // The last idle connection (or the only one of a pool of one) is checked as shared
        // work, which a WRITE in shared mode still uses meanwhile, and not while the pool hands
        // its connections out exclusively (a lease would wait for the check).
        let leased = idle.len() >= 2;
        if !leased && self.exclusive() {
            return None;
        }
        let turn = self.next_check.fetch_add(1, Ordering::Relaxed) as usize;
        let i = idle[turn % idle.len()];
        if leased {
            st[i].0 = true;
        } else {
            st[i].1 += 1;
        }
        Some(WaitSlot {
            pool: self.clone(),
            index: i,
            leased,
        })
    }

    /// The connections no request holds right now, leased or shared (housekeeping).
    fn idle(&self) -> Vec<usize> {
        let st = self.state.lock();
        (0..self.n).filter(|i| st[*i] == (false, 0)).collect()
    }
}

/// What the task that owns a command does when it ends (`run_on_slot_with`). The hooks run in
/// that task, so they also run for a caller that gave up or went away.
struct SlotHooks<T> {
    /// The command was answered within the caller's deadline: its result and round trip.
    answered: Box<dyn FnOnce(&redis::RedisResult<T>, Duration) + Send>,
    /// No answer within the caller's deadline: a timeout of this connection.
    timed_out: Box<dyn FnOnce() + Send>,
    /// Still no answer after the drain period: the connection is stuck (its reply will never
    /// be read) and must be replaced.
    stuck: Box<dyn FnOnce() + Send>,
}

impl<T> SlotHooks<T> {
    /// Only `stuck` does something.
    fn on_stuck(stuck: impl FnOnce() + Send + 'static) -> Self {
        Self {
            answered: Box::new(|_, _| {}),
            timed_out: Box::new(|| {}),
            stuck: Box::new(stuck),
        }
    }
}

/// The hooks of a `WAIT` command for the mode of its pool: an acknowledged answer
/// (`acked`) is a round-trip sample, anything else, and a timeout, switches the pool to
/// exclusive (`LeasePool::observe`); `on_timeout` and `on_stuck` handle the connection.
fn wait_hooks<T: 'static>(
    pool: Arc<LeasePool>,
    acked: impl FnOnce(&redis::RedisResult<T>) -> bool + Send + 'static,
    on_timeout: impl FnOnce() + Send + 'static,
    on_stuck: impl FnOnce() + Send + 'static,
) -> SlotHooks<T> {
    let timeout_pool = pool.clone();
    SlotHooks {
        answered: Box::new(move |r, took| {
            let outcome = if acked(r) {
                WaitOutcome::Acked
            } else {
                WaitOutcome::Slow
            };
            pool.observe(outcome, took);
        }),
        timed_out: Box::new(move || {
            timeout_pool.observe(WaitOutcome::Slow, Duration::ZERO);
            on_timeout();
        }),
        stuck: Box::new(on_stuck),
    }
}

/// The `stuck` hook of a running command: fired when the command never answers, and also when
/// its task ends without disarming it (a panic), so the connection is never handed back with a
/// reply still owed on it.
struct StuckGuard(Option<Box<dyn FnOnce() + Send>>);

impl StuckGuard {
    fn fire(&mut self) {
        if let Some(stuck) = self.0.take() {
            stuck();
        }
    }

    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for StuckGuard {
    fn drop(&mut self) {
        self.fire();
    }
}

/// An `Elapsed` for a command that was not sent (its deadline had passed).
async fn elapsed() -> tokio::time::error::Elapsed {
    match timeout(Duration::ZERO, std::future::pending::<()>()).await {
        Err(e) => e,
        Ok(()) => unreachable!("a pending future never completes"),
    }
}

/// `run_on_slot_with` where only a stuck command does something (`retire`).
async fn run_on_slot<T: Send + 'static>(
    slot: WaitSlot,
    deadline: tokio::time::Instant,
    drain: Duration,
    command: impl std::future::Future<Output = redis::RedisResult<T>> + Send + 'static,
    retire: impl FnOnce() + Send + 'static,
) -> Result<redis::RedisResult<T>, tokio::time::error::Elapsed> {
    run_on_slot_with(slot, deadline, drain, command, SlotHooks::on_stuck(retire)).await
}

/// Run `command` (one round trip on the connection of `slot`), bounded by the caller's
/// absolute `deadline`. The command runs in a task of its own that holds the slot until the
/// command is done, also when the caller stops waiting or goes away, so a connection is never
/// counted free (or handed to a lease) while a command is still on it. In that task:
///
/// - the deadline is checked right before the command goes out: one whose deadline passed
///   (while the task waited to be scheduled) is never sent;
/// - the outcome is recorded (`hooks`): an answer within the deadline, or a timeout once it
///   passed, whether the caller is still there or not;
/// - after a timeout the slot stays held until the answer arrives or `drain` more has passed;
///   then the connection is stuck (`hooks.stuck`, which replaces that one connection) and the
///   slot is released.
async fn run_on_slot_with<T: Send + 'static>(
    slot: WaitSlot,
    deadline: tokio::time::Instant,
    drain: Duration,
    command: impl std::future::Future<Output = redis::RedisResult<T>> + Send + 'static,
    hooks: SlotHooks<T>,
) -> Result<redis::RedisResult<T>, tokio::time::error::Elapsed> {
    let task = tokio::spawn(async move {
        if tokio::time::Instant::now() >= deadline {
            drop(slot);
            return None;
        }
        let SlotHooks {
            answered,
            timed_out,
            stuck,
        } = hooks;
        // Declared after `slot`, so dropped before it: if the task panics (the command or a
        // hook), the connection is replaced (its reply may still be owed) before the slot goes
        // back to the pool.
        let mut stuck = StuckGuard(Some(stuck));
        let sent = std::time::Instant::now();
        tokio::pin!(command);
        let answer = match tokio::time::timeout_at(deadline, &mut command).await {
            Ok(r) => {
                answered(&r, sent.elapsed());
                stuck.disarm();
                Some(r)
            }
            Err(_) => {
                timed_out();
                if timeout(drain, &mut command).await.is_err() {
                    stuck.fire();
                } else {
                    stuck.disarm();
                }
                None
            }
        };
        drop(stuck);
        drop(slot);
        answer
    });
    match tokio::time::timeout_at(deadline, task).await {
        Ok(Ok(Some(r))) => Ok(r),
        Ok(Ok(None)) => Err(elapsed().await),
        Ok(Err(_)) => Ok(Err(redis::RedisError::from((
            redis::ErrorKind::IoError,
            "WAIT command did not complete",
        )))),
        Err(e) => Err(e),
    }
}

/// Two different connections of one store's `WAIT` pool timing out within this long mean the
/// path to the store, not one connection, is stuck: all of them are replaced.
const WAIT_TIMEOUTS_WINDOW: Duration = Duration::from_secs(5);

/// The timeout history of one store's `WAIT` pool (`note_timeout`).
#[derive(Default)]
struct RecentTimeout {
    /// The last connection that timed out, and when.
    last: parking_lot::Mutex<Option<(usize, std::time::Instant)>>,
    /// Replacements of the whole pool so far: a command captures it when it is sent
    /// (`round`), and its late timeout after a replacement is stale.
    round: AtomicU64,
}

/// What a timeout means for its pool (`RecentTimeout::note_timeout`).
#[derive(Debug, PartialEq, Eq)]
enum TimeoutVerdict {
    /// The connection or the pool was replaced since the command was sent: nothing to do.
    Stale,
    /// Replace that one connection.
    One,
    /// A second connection within `WAIT_TIMEOUTS_WINDOW`: the path is stuck, replace them all.
    All,
}

impl RecentTimeout {
    /// The pool round a command is sent in.
    fn round(&self) -> u64 {
        self.round.load(Ordering::Acquire)
    }

    /// Connection `index` timed out on a command sent in `round`; `current` is whether that
    /// connection is still the one the command went out on. Checked before the history is
    /// touched, so a late completion of a replaced connection (or of a pool replaced since)
    /// neither counts nor replaces the healthy replacements.
    ///
    /// Only a command that had its connection to itself (`leased`, exclusive mode) counts
    /// toward replacing the whole pool: a `WAIT` queued behind others on a shared connection
    /// may time out without anything being stuck, so it replaces at most that connection.
    fn note_timeout(
        &self,
        index: usize,
        round: u64,
        current: bool,
        leased: bool,
    ) -> TimeoutVerdict {
        if !current {
            return TimeoutVerdict::Stale;
        }
        let now = std::time::Instant::now();
        let mut last = self.last.lock();
        // Checked under the lock the round only moves under.
        if round != self.round() {
            return TimeoutVerdict::Stale;
        }
        if !leased {
            return TimeoutVerdict::One;
        }
        let second = matches!(*last, Some((i, at)) if i != index && now.duration_since(at) <= WAIT_TIMEOUTS_WINDOW);
        if second {
            *last = None;
            self.round.fetch_add(1, Ordering::AcqRel);
            TimeoutVerdict::All
        } else {
            *last = Some((index, now));
            TimeoutVerdict::One
        }
    }
}

impl WriteWaitConfig {
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        Self::parse(
            std::env::var("REPLAY_WRITE_WAIT_REPLICAS").ok().as_deref(),
            std::env::var("REPLAY_WRITE_WAIT_MS").ok().as_deref(),
        )
    }

    /// `REPLAY_PEER_WAIT_REPLICAS` / `REPLAY_PEER_WAIT_MS`: the same acknowledgement for the
    /// nonce of a WRITE written synchronously to a peer origin's store (`ReplayPeers`).
    pub fn peer_from_env() -> anyhow::Result<Option<Self>> {
        Self::parse_named(
            std::env::var("REPLAY_PEER_WAIT_REPLICAS").ok().as_deref(),
            std::env::var("REPLAY_PEER_WAIT_MS").ok().as_deref(),
            DEFAULT_REPLAY_PEER_WAIT_REPLICAS,
            "REPLAY_PEER_WAIT",
        )
    }

    pub fn parse(replicas: Option<&str>, timeout_ms: Option<&str>) -> anyhow::Result<Option<Self>> {
        Self::parse_named(replicas, timeout_ms, 0, "REPLAY_WRITE_WAIT")
    }

    pub fn parse_named(
        replicas: Option<&str>,
        timeout_ms: Option<&str>,
        default_replicas: u32,
        prefix: &str,
    ) -> anyhow::Result<Option<Self>> {
        let replicas = match replicas.map(str::trim).filter(|s| !s.is_empty()) {
            None => default_replicas,
            Some(r) => r.parse::<u32>().map_err(|_| {
                anyhow::anyhow!("{prefix}_REPLICAS must be a non-negative integer, got '{r}'")
            })?,
        };
        let timeout_ms = match timeout_ms.map(str::trim).filter(|s| !s.is_empty()) {
            None => DEFAULT_REPLAY_WRITE_WAIT_MS,
            Some(t) => match t.parse::<u64>() {
                Ok(v) if v > 0 => v,
                _ => anyhow::bail!("{prefix}_MS must be a positive integer, got '{t}'"),
            },
        };
        Ok((replicas > 0).then_some(Self {
            replicas,
            timeout_ms,
        }))
    }
}

/// `REPLAY_LOCAL_WAITAOF_MS`: a WRITE whose nonce only the local security Redis holds (an
/// origin with `REPLAY_PEER_FAIL_CLOSED_WRITES=0` while its peers are unreachable) runs
/// only once that nonce is fsynced to the local AOF (`WAITAOF 1 0`, Redis >= 7.2 with
/// `appendonly yes`). Without it a crash of the host loses up to the last second of nonces
/// (`appendfsync everysec`) and such a WRITE could be replayed once after the restart. With
/// `everysec` the wait is up to about one second (the next background fsync); with
/// `appendfsync always` it ends with the write itself.
/// Unset: on when the store supports it (probed at startup), off otherwise. `0`: off. A
/// positive value: required (startup fails if the store cannot `WAITAOF`), with that timeout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalAofConfig {
    Off,
    Auto(u64),
    Required(u64),
}

pub const DEFAULT_REPLAY_LOCAL_WAITAOF_MS: u64 = 2000;

impl LocalAofConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::parse(std::env::var("REPLAY_LOCAL_WAITAOF_MS").ok().as_deref())
    }

    pub fn parse(value: Option<&str>) -> anyhow::Result<Self> {
        match value.map(str::trim).filter(|s| !s.is_empty()) {
            None => Ok(Self::Auto(DEFAULT_REPLAY_LOCAL_WAITAOF_MS)),
            Some("0") => Ok(Self::Off),
            Some(t) => match t.parse::<u64>() {
                Ok(v) if v > 0 => Ok(Self::Required(v)),
                _ => anyhow::bail!(
                    "REPLAY_LOCAL_WAITAOF_MS must be a non-negative integer, got '{t}'"
                ),
            },
        }
    }
}

/// The dedicated security-Redis connection for `WAITAOF` (blocks its connection, like `WAIT`).
struct LocalAof {
    conn: Arc<StoreConn>,
    timeout_ms: u64,
}

/// The dedicated security-Redis connections for `WAIT` (`REPLAY_WAIT_CONNS`, a `LeasePool`).
/// `WAIT` blocks the connection it runs on until the replicas acknowledge, so it must not share
/// the multiplexed connection every request's `SET NX` goes through: a slow replica would stall
/// READs too.
struct WriteWait {
    conns: Vec<Arc<StoreConn>>,
    pool: Arc<LeasePool>,
    config: WriteWaitConfig,
    timeouts: Arc<RecentTimeout>,
}

impl WriteWait {
    /// Sum of the generations of every `WAIT` connection: it changes whenever one was replaced.
    /// Sum of the failover generations of every `WAIT` connection: it changes whenever one was
    /// replaced after a failover signal (not when one stuck connection was retired).
    fn generation(&self) -> u64 {
        self.conns.iter().map(|c| c.failover_generation()).sum()
    }
}

/// One entry of REPLAY_PEER_URLS (or REPLAY_STANDBY_URLS): the security Redis of another origin.
struct ReplayPeer {
    /// The `peer` metric label: the position in REPLAY_PEER_URLS, or for a standby store the
    /// number of peers plus its position in REPLAY_STANDBY_URLS.
    index: usize,
    url: String,
    /// None until the first successful connection (a background task retries); afterwards the
    /// ConnectionManager reconnects by itself.
    conn: Arc<ArcSwapOption<ConnectionManager>>,
    /// The dedicated connections for `WAIT` (see `WriteWait`), opened and reopened in the
    /// background (`with_wait`, housekeeping, a failed `WAIT`).
    wait: PeerWaitPool,
    /// One connection of its own for `retry_timed_out` when `wait` has none
    /// (REPLAY_PEER_WAIT_REPLICAS=0).
    retry: PeerWaitPool,
    /// Woken when one of its connections becomes usable: a `WAIT` or retry connection opened,
    /// or the main connection back (which makes the others usable again: `primary_usable`).
    changed: Arc<tokio::sync::Notify>,
    /// The write-back's own connection (`rewrite_replicated`): its `WAIT`s must not delay the
    /// requests' on `wait`. Opened on first use.
    write_back_conn: Arc<ArcSwapOption<ConnectionManager>>,
    /// Consecutive failed housekeeping PINGs (see PEER_PING_FAILURES_RECONNECT).
    ping_failures: AtomicU32,
    /// Whether the last housekeeping PING was answered (false until the first one).
    answered: AtomicBool,
    /// A standby store (REPLAY_STANDBY_URLS): its connectivity is `ohttp_replay_standby_connected`,
    /// never `ohttp_replay_peer_connected` (which watchdogs read as "the peers are reachable").
    standby: bool,
}

/// One dedicated `WAIT` connection of a replay peer.
struct PeerWaitSlot {
    conn: ArcSwapOption<ConnectionManager>,
    /// A background task is opening `conn`.
    reopening: AtomicBool,
    /// Woken when a background task stored a new `conn` in any slot of the pool (shared by
    /// the slots of one peer).
    opened: Arc<tokio::sync::Notify>,
}

/// The dedicated `WAIT` connections of one replay peer (`REPLAY_WAIT_CONNS`): a `LeasePool`
/// whose connections are opened in the background, never inside a request's budget.
struct PeerWaitPool {
    slots: Vec<Arc<PeerWaitSlot>>,
    pool: Arc<LeasePool>,
    timeouts: Arc<RecentTimeout>,
}

impl PeerWaitSlot {
    /// The reopen task stored the new connection: clear the flag. A reset of the connection
    /// before that found a reopen running and started none, so when the slot is empty again
    /// the task keeps the flag and opens it once more (true).
    fn reopen_done(&self) -> bool {
        // SeqCst on both sides (here and `spawn_wait_reopen`'s claim of the flag): either the
        // reset sees the flag cleared and starts a reopen itself, or this sees the slot empty.
        self.reopening.store(false, Ordering::SeqCst);
        self.conn.load().is_none() && !self.reopening.swap(true, Ordering::SeqCst)
    }
}

impl PeerWaitPool {
    /// `changed`: the peer's wake-up (`ReplayPeer::changed`), shared by its pools and its main
    /// connection.
    fn new(n: usize, wait_timeout_ms: u64, changed: Arc<tokio::sync::Notify>) -> Self {
        let pool = LeasePool::with_changed(n, wait_timeout_ms, changed);
        Self {
            slots: (0..n)
                .map(|_| {
                    Arc::new(PeerWaitSlot {
                        conn: ArcSwapOption::empty(),
                        reopening: AtomicBool::new(false),
                        // An opened connection wakes the requests waiting in `acquire`.
                        opened: pool.changed.clone(),
                    })
                })
                .collect(),
            pool,
            timeouts: Arc::default(),
        }
    }

    /// Have every closed connection reopened in the background (`spawn_wait_reopen`).
    fn reopen_closed(&self, network: &str, index: usize, url: &str) {
        for s in &self.slots {
            if s.conn.load().is_none() {
                spawn_wait_reopen(network.to_string(), index, url.to_string(), s.clone());
            }
        }
    }

    /// What to do when a command sent now on `used` (slot `slot_index`) times out, for the
    /// task that owns the command: nothing if that connection or the pool was replaced since
    /// (`RecentTimeout::note_timeout`), else replace that one connection, or every one on a
    /// second within `WAIT_TIMEOUTS_WINDOW` (the path is stuck).
    fn on_timeout(
        &self,
        network: &str,
        index: usize,
        url: &str,
        slot_index: usize,
        used: &Arc<ConnectionManager>,
        leased: bool,
    ) -> impl FnOnce() + Send + 'static {
        let (slots, timeouts, round) = (
            self.slots.clone(),
            self.timeouts.clone(),
            self.timeouts.round(),
        );
        let (network, url, used) = (network.to_string(), url.to_string(), used.clone());
        move || {
            let Some(slot) = slots.get(slot_index) else {
                return;
            };
            let current = slot
                .conn
                .load()
                .as_ref()
                .is_some_and(|c| Arc::ptr_eq(c, &used));
            match timeouts.note_timeout(slot_index, round, current, leased) {
                TimeoutVerdict::Stale => {}
                TimeoutVerdict::One => {
                    drop_wait_conn(&network, index, &url, slot, &used);
                }
                TimeoutVerdict::All => {
                    for s in &slots {
                        if let Some(c) = s.conn.load_full() {
                            drop_wait_conn(&network, index, &url, s, &c);
                        }
                    }
                }
            }
        }
    }

    fn connected(&self, i: usize) -> bool {
        self.slots.get(i).is_some_and(|s| s.conn.load().is_some())
    }

    /// Whether at least one `WAIT` connection is open.
    fn any_connected(&self) -> bool {
        self.slots.iter().any(|s| s.conn.load().is_some())
    }
}

/// Open `slot`'s connection in the background, unless that is already running; retried with a
/// jittered backoff (about 200 ms to PEER_RECONNECT_MAX_BACKOFF_SECS) until it succeeds, so the
/// slots of many gateways that lost their connections at once do not reconnect in step.
fn spawn_wait_reopen(network: String, index: usize, url: String, slot: Arc<PeerWaitSlot>) {
    if tokio::runtime::Handle::try_current().is_err() || slot.reopening.swap(true, Ordering::SeqCst)
    {
        return;
    }
    tokio::spawn(async move {
        let mut backoff = Duration::from_millis(200);
        let mut loading = 0u32;
        loop {
            match ReplayPeer::open(&url).await {
                Ok(c) => {
                    // Stored before the flag is cleared, so no second reopen of this slot
                    // starts meanwhile.
                    slot.conn.store(Some(Arc::new(c)));
                    slot.opened.notify_waiters();
                    if slot.reopen_done() {
                        // A new reopen after a success: its backoff starts over.
                        backoff = Duration::from_millis(200);
                        loading = 0;
                        continue;
                    }
                    return;
                }
                Err(e) => {
                    debug!(network = %network, peer = index, error = %error_summary(&e), "Replay peer WAIT connection attempt failed");
                    tokio::time::sleep(reopen_pause(&e, jittered(backoff), &mut loading)).await;
                    backoff =
                        (backoff * 2).min(Duration::from_secs(PEER_RECONNECT_MAX_BACKOFF_SECS));
                }
            }
        }
    });
}

/// `d` scaled by a random factor from 0.5 to 1.5.
fn jittered(d: Duration) -> Duration {
    d.mul_f64(0.5 + rand::random::<f64>())
}

/// Replace `used` in `slot` by None and reopen it in the background, once per connection.
fn drop_wait_conn(
    network: &str,
    index: usize,
    url: &str,
    slot: &Arc<PeerWaitSlot>,
    used: &Arc<ConnectionManager>,
) -> bool {
    let prev = slot
        .conn
        .compare_and_swap(&Some(used.clone()), None::<Arc<ConnectionManager>>);
    let swapped = (*prev).as_ref().is_some_and(|p| Arc::ptr_eq(p, used));
    if swapped {
        spawn_wait_reopen(network.to_string(), index, url.to_string(), slot.clone());
    }
    swapped
}

/// Replay nonces are written to every peer as well as to the local security Redis, and a nonce
/// any store already holds is a replay ("write to all, replay if any"). See `origin.rs`.
pub struct ReplayPeers {
    peers: Vec<ReplayPeer>,
    network: String,
    /// Budget for the concurrent peer round trips of one request.
    timeout: Duration,
    /// Whether an unavailable peer refuses the request (sync mode, and READs on the strict path).
    fail_closed: bool,
    /// REPLAY_PEER_MODE.
    mode: ReplayPeerMode,
    /// async-reads: whether an unavailable peer refuses a WRITE.
    fail_closed_writes: bool,
    /// REPLAY_PEER_WAIT_REPLICAS: replica acknowledgement of a WRITE nonce at each peer that took it.
    wait: Option<WriteWaitConfig>,
    /// Peer errors, timeouts, disconnects and failed PINGs so far: a change opens the hub
    /// window of a read origin (write_fallback.rs).
    disruptions: AtomicU64,
}

/// The outcome of one nonce write at one peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerOutcome {
    /// Stored: the peer had not seen the nonce.
    Fresh,
    /// The peer already held the nonce: another origin recorded it first.
    Replay,
    /// Redis error.
    Error,
    /// No answer within the budget.
    Timeout,
    /// Not connected (not reached since startup, or reconnecting).
    Disconnected,
}

impl PeerOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            PeerOutcome::Fresh => "fresh",
            PeerOutcome::Replay => "replay",
            PeerOutcome::Error => "error",
            PeerOutcome::Timeout => "timeout",
            PeerOutcome::Disconnected => "disconnected",
        }
    }
}

/// The joint verdict of all peers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerVerdict {
    /// No peer had the nonce and every peer answered.
    Fresh,
    /// At least one peer had the nonce: a cross-origin replay.
    Replay,
    /// No peer had the nonce but at least one did not answer; the policy decides.
    Unavailable,
}

/// A replay anywhere wins, even over errors elsewhere: a peer's "already seen" is a positive
/// fact, while an unavailable peer only means that we do not know.
pub fn combine_peer_outcomes(outcomes: &[PeerOutcome]) -> PeerVerdict {
    if outcomes.contains(&PeerOutcome::Replay) {
        PeerVerdict::Replay
    } else if outcomes.iter().all(|o| *o == PeerOutcome::Fresh) {
        PeerVerdict::Fresh
    } else {
        PeerVerdict::Unavailable
    }
}

impl ReplayPeers {
    /// Connect to every peer. A peer that is unreachable now is retried in the background
    /// (and counted as `disconnected` meanwhile), so an outage of the link between origins never stops a gateway
    /// from starting.
    pub async fn connect(
        urls: &[String],
        network: String,
        timeout_ms: u64,
        fail_closed: bool,
    ) -> Self {
        Self::connect_labeled(urls, network, timeout_ms, fail_closed, 0, false).await
    }

    /// The standby stores (REPLAY_STANDBY_URLS): labelled from `first_label` on (the number of
    /// REPLAY_PEER_URLS), so their metrics never share a `peer` value with a peer. The
    /// asynchronous replicator uses them, and, with `with_wait`, the hub path of the WRITE
    /// fallback (write_fallback.rs) on the request path.
    pub async fn connect_standby(
        urls: &[String],
        network: String,
        timeout_ms: u64,
        first_label: usize,
    ) -> Self {
        Self::connect_labeled(urls, network, timeout_ms, false, first_label, true)
            .await
            .with_mode(ReplayPeerMode::Failover, false)
    }

    async fn connect_labeled(
        urls: &[String],
        network: String,
        timeout_ms: u64,
        fail_closed: bool,
        first_label: usize,
        standby: bool,
    ) -> Self {
        let mut peers = Vec::with_capacity(urls.len());
        for (index, url) in urls.iter().enumerate() {
            let index = first_label + index;
            let conn = Arc::new(ArcSwapOption::empty());
            // A standby store is only replicated to, so startup never waits for it (an
            // unreachable one would delay readiness by PEER_CONNECT_TIMEOUT): the background
            // task below connects it, and nonces queue meanwhile.
            if standby {
                record_peer_connected(&network, index, true, false);
            } else {
                match ReplayPeer::open(url).await {
                    Ok(c) => {
                        info!(network = %network, peer = index, "Replay peer connected");
                        conn.store(Some(Arc::new(c)));
                        record_peer_connected(&network, index, false, true);
                    }
                    Err(e) => {
                        warn!(network = %network, peer = index, error = %error_summary(&e), "Replay peer unreachable at startup, retrying in background");
                        record_peer_connected(&network, index, false, false);
                    }
                }
            }
            // The retry connection is set up with the WAIT pool (`with_wait_conns`).
            let changed = Arc::new(tokio::sync::Notify::new());
            peers.push(ReplayPeer {
                index,
                url: url.clone(),
                conn,
                wait: PeerWaitPool::new(0, 0, changed.clone()),
                retry: PeerWaitPool::new(0, 0, changed.clone()),
                changed,
                write_back_conn: Arc::new(ArcSwapOption::empty()),
                ping_failures: AtomicU32::new(0),
                answered: AtomicBool::new(false),
                standby,
            });
        }
        let this = Self {
            peers,
            network,
            timeout: Duration::from_millis(timeout_ms),
            fail_closed,
            mode: ReplayPeerMode::Sync,
            fail_closed_writes: true,
            wait: None,
            disruptions: AtomicU64::new(0),
        };
        for p in &this.peers {
            if p.conn.load().is_none() {
                spawn_peer_reconnect_task(this.network.clone(), p.links());
            }
        }
        this
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// The `peer` label of the first store (0, or the first standby label).
    pub fn first_label(&self) -> usize {
        self.peers.first().map_or(0, |p| p.index)
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub fn fail_closed(&self) -> bool {
        self.fail_closed
    }

    /// REPLAY_PEER_MODE and REPLAY_PEER_FAIL_CLOSED_WRITES (defaults: `sync`, true).
    pub fn with_mode(mut self, mode: ReplayPeerMode, fail_closed_writes: bool) -> Self {
        self.mode = mode;
        self.fail_closed_writes = fail_closed_writes;
        self
    }

    pub fn mode(&self) -> ReplayPeerMode {
        self.mode
    }

    pub fn fail_closed_writes(&self) -> bool {
        self.fail_closed_writes
    }

    /// REPLAY_PEER_WAIT_REPLICAS / REPLAY_PEER_WAIT_MS (None = no acknowledgement), with
    /// `DEFAULT_REPLAY_WAIT_CONNS` dedicated `WAIT` connections per peer.
    pub fn with_wait(self, wait: Option<WriteWaitConfig>) -> Self {
        self.with_wait_conns(wait, DEFAULT_REPLAY_WAIT_CONNS)
    }

    /// `with_wait` with `conns` dedicated `WAIT` connections per peer (`REPLAY_WAIT_CONNS`). They
    /// are opened now, in the background, so that the first WRITE does not pay the connection
    /// setup (TCP, TLS, AUTH: several round trips); one that breaks later is reopened in the
    /// background as well.
    ///
    /// Without a peer `WAIT` (`wait` None) each store gets one connection of its own instead,
    /// for the retry of a `SET NX` that timed out (`retry_timed_out`); with a `WAIT` pool the
    /// retry uses that pool and no extra connection is opened.
    pub fn with_wait_conns(mut self, wait: Option<WriteWaitConfig>, conns: usize) -> Self {
        self.wait = wait;
        for p in &mut self.peers {
            if wait.is_some() {
                p.wait = PeerWaitPool::new(
                    conns.max(1),
                    wait.map_or(0, |w| w.timeout_ms),
                    p.changed.clone(),
                );
                p.retry = PeerWaitPool::new(0, 0, p.changed.clone());
                for slot in &p.wait.slots {
                    spawn_wait_reopen(self.network.clone(), p.index, p.url.clone(), slot.clone());
                }
            } else {
                p.wait = PeerWaitPool::new(0, 0, p.changed.clone());
                p.retry = PeerWaitPool::new(1, 0, p.changed.clone());
                p.retry.reopen_closed(&self.network, p.index, &p.url);
            }
        }
        self
    }

    pub fn wait(&self) -> Option<WriteWaitConfig> {
        self.wait
    }

    /// For a WRITE whose nonce `key` was just stored at the peers `confirm(index)` selects:
    /// rewrite it on the peer's dedicated connection (`SET XX`) and `WAIT` for the configured
    /// replicas of that store, so that a failover of the shared store cannot forget it.
    /// Each attempt is bounded by REPLAY_PEER_TIMEOUT_MS (the round trip) + REPLAY_PEER_WAIT_MS
    /// (the server-side `WAIT`); opening the connection is not part of it. One failed attempt
    /// (fewer acknowledgements, an error, a timeout) is retried once: `SET XX` and `WAIT` are
    /// idempotent. Fail-closed: the nonce gone, or both attempts failing, is an `Err` (outer 503)
    /// even where an unreachable peer would be tolerated, because that peer was reachable a
    /// moment ago. No-op when peer acknowledgement is off (REPLAY_PEER_WAIT_REPLICAS=0).
    pub async fn confirm_replicated(
        &self,
        key: &str,
        confirm: impl Fn(usize) -> bool,
    ) -> anyhow::Result<()> {
        self.confirm_replicated_kind(key, confirm)
            .await
            .map_err(|f| anyhow::anyhow!(f.message))
    }

    /// Times a peer failed (error, timeout, disconnected, failed PING).
    pub fn disruptions(&self) -> u64 {
        self.disruptions.load(Ordering::Relaxed)
    }

    /// `confirm_replicated`, telling apart the case where every failing peer still held the
    /// nonce and only its replica acknowledgement was short (`ConfirmFailure::only_short`).
    pub async fn confirm_replicated_kind(
        &self,
        key: &str,
        confirm: impl Fn(usize) -> bool,
    ) -> Result<(), ConfirmFailure> {
        let Some(WriteWaitConfig {
            replicas,
            timeout_ms,
        }) = self.wait
        else {
            return Ok(());
        };
        // One attempt: its round trip and the server-side WAIT. The whole confirmation (both
        // attempts, and the wait for a WAIT connection when none is open) ends at one deadline.
        let budget = self.timeout + Duration::from_millis(timeout_ms);
        let deadline = tokio::time::Instant::now()
            + PEER_WAIT_CONNECT_TIMEOUT
            + budget * PEER_WAIT_ATTEMPTS as u32;
        let futures = self.peers.iter().filter(|p| confirm(p.index)).map(|p| async move {
            let verdict = async {
                let mut last = String::new();
                let mut short = false;
                let mut attempt = 0;
                while attempt < PEER_WAIT_ATTEMPTS {
                    // An attempt starts only while its whole budget still fits.
                    let Some(attempt_deadline) = deadline.checked_sub(budget) else {
                        break;
                    };
                    if tokio::time::Instant::now() > attempt_deadline {
                        break;
                    }
                    if attempt > 0 {
                        if crate::health::warn_due(&self.network, "peer_wait_retry") {
                            warn!(network = %self.network, peer = p.index, error = %last, "Replay peer WAIT failed, retrying once");
                        }
                        crate::health::record_replay_peer(&self.network, p.index, "wait_retry");
                    }
                    // A WAIT connection of the pool (`LeasePool`): only an open one, waiting for
                    // one to be released or opened (closed ones reopen in the background). In
                    // exclusive mode the wait for a free connection is bounded like one attempt
                    // (and leaves the attempt its whole budget before the deadline). Every open
                    // one taken until then: the WAITs ahead all ran into their timeout (the
                    // saturated path); none open: no attempt.
                    p.wait.reopen_closed(&self.network, p.index, &p.url);
                    let lease_deadline =
                        attempt_deadline.min(tokio::time::Instant::now() + budget);
                    let held = match p
                        .wait
                        .pool
                        .acquire(lease_deadline, |i| p.wait.connected(i) && p.primary_usable())
                        .await
                    {
                        Acquired::Slot(h) => h,
                        Acquired::Busy => {
                            return self.peer_wait_saturated(p, key, timeout_ms, deadline).await
                        }
                        Acquired::NoneOpen => {
                            last = "no WAIT connection open in time (reopening in the background)"
                                .to_string();
                            short = false;
                            break;
                        }
                    };
                    let slot_index = held.index();
                    let slot = p.wait.slots[slot_index].clone();
                    // Closed since it was picked: take another one.
                    let Some(conn) = slot.conn.load_full() else {
                        drop(held);
                        continue;
                    };
                    // Checked again right before the command goes out: never after the cutoff.
                    if tokio::time::Instant::now() > attempt_deadline {
                        drop(held);
                        break;
                    }
                    attempt += 1;
                    let mut c = (*conn).clone();
                    let owned_key = key.to_string();
                    let command = async move {
                        redis::pipe()
                            .cmd("SET")
                            .arg(&owned_key)
                            .arg("1")
                            .arg("XX")
                            .arg("EX")
                            .arg(REPLAY_TTL_SECS)
                            .cmd("WAIT")
                            .arg(replicas)
                            .arg(timeout_ms)
                            .query_async::<_, (Option<String>, i64)>(&mut c)
                            .await
                    };
                    let retire = {
                        let (network, index, url, slot, used) = (
                            self.network.clone(),
                            p.index,
                            p.url.clone(),
                            slot.clone(),
                            conn.clone(),
                        );
                        move || {
                            drop_wait_conn(&network, index, &url, &slot, &used);
                        }
                    };
                    // The pool's mode and the connection's timeout are recorded by the task
                    // that owns the command, also if this request goes away meanwhile.
                    // An error is handled there too (`PeerLinks::command_failed`): this
                    // connection is dropped, and on a signal about the node the peer's other
                    // connections as well, if this one was still installed.
                    let failed = {
                        let (links, network, slot, conn) =
                            (p.links(), self.network.clone(), slot.clone(), conn.clone());
                        move |e: &redis::RedisError| {
                            links.command_failed(&network, FailedOn::Extra(&slot, &conn), e)
                        }
                    };
                    let hooks = wait_hooks(
                        p.wait.pool.clone(),
                        move |r: &redis::RedisResult<(Option<String>, i64)>| {
                            if let Err(e) = r {
                                failed(e);
                            }
                            matches!(r, Ok((Some(_), acked)) if *acked >= replicas as i64)
                        },
                        p.wait.on_timeout(
                            &self.network,
                            p.index,
                            &p.url,
                            slot_index,
                            &conn,
                            held.leased(),
                        ),
                        retire,
                    );
                    let result = run_on_slot_with(
                        held,
                        (tokio::time::Instant::now() + budget).min(deadline),
                        budget + WAIT_DRAIN_EXTRA,
                        command,
                        hooks,
                    )
                    .await;
                    short = matches!(result, Ok(Ok((Some(_), _))));
                    last = match result {
                        Ok(Ok((Some(_), acked))) if acked >= replicas as i64 => return Ok(()),
                        Ok(Ok((Some(_), acked))) => format!(
                            "acknowledged by {acked} of {replicas} replica(s) within {timeout_ms}ms"
                        ),
                        Ok(Ok((None, _))) => {
                            return Err((false, "nonce no longer at the peer".to_string()))
                        }
                        // A broken or stuck connection: replaced in the background, and the
                        // retry takes another one. Only a signal about the node (it is no
                        // longer the primary) also replaces the peer's main connection; an
                        // I/O error on this connection says nothing about that one.
                        // Handled by the command's task (`PeerLinks::command_failed` above).
                        Ok(Err(e)) => store_error(&e),
                        // No answer although a WAIT ends after its timeout: this connection is
                        // stuck and replaced, and a second one of this peer stuck within a few
                        // seconds means the path is and all of them are (the command's task,
                        // `PeerWaitPool::on_timeout`).
                        Err(_) => format!("timed out after {}ms", budget.as_millis()),
                    };
                }
                if last.is_empty() {
                    last = "no time left for an attempt".to_string();
                }
                Err((short, last))
            }
            .await;
            crate::health::record_replay_peer(
                &self.network,
                p.index,
                if verdict.is_ok() { "acknowledged" } else { "unacknowledged" },
            );
            verdict.map_err(|(short, e)| (short, format!("peer {}: {e}", p.index)))
        });
        let failures: Vec<(bool, String)> = futures_util::future::join_all(futures)
            .await
            .into_iter()
            .filter_map(Result::err)
            .collect();
        if failures.is_empty() {
            Ok(())
        } else {
            Err(ConfirmFailure {
                only_short: failures.iter().all(|(short, _)| *short),
                message: format!(
                    "WRITE replay nonce not acknowledged by the peer replicas (fail-closed): {}",
                    failures
                        .iter()
                        .map(|(_, m)| m.as_str())
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            })
        }
    }

    /// Write-back to every peer: `SET key 1 EX ttl` per entry on the `WAIT` connection, then
    /// `WAIT`; acknowledged only when every peer acknowledged.
    async fn rewrite_replicated(&self, batch: &[(String, u64)]) -> WriteBackResult {
        let Some(WriteWaitConfig {
            replicas,
            timeout_ms,
        }) = self.wait
        else {
            return WriteBackResult::Acked;
        };
        let budget = self.timeout + Duration::from_millis(timeout_ms);
        let futures = self.peers.iter().map(|p| async move {
            let conn = match p.write_back_conn.load_full() {
                Some(c) => c,
                None => match timeout(PEER_WAIT_CONNECT_TIMEOUT, ReplayPeer::open(&p.url)).await {
                    Ok(Ok(c)) => {
                        let c = Arc::new(c);
                        p.write_back_conn.store(Some(c.clone()));
                        c
                    }
                    Ok(Err(e)) => {
                        return WriteBackResult::Failed(format!("connect: {}", error_summary(&e)))
                    }
                    Err(_) => return WriteBackResult::Failed("connect timed out".to_string()),
                },
            };
            let mut conn = (*conn).clone();
            let mut pipe = redis::pipe();
            for (key, ttl) in batch {
                pipe.cmd("SET")
                    .arg(key)
                    .arg("1")
                    .arg("EX")
                    .arg(*ttl)
                    .ignore();
            }
            pipe.cmd("WAIT").arg(replicas).arg(timeout_ms);
            match timeout(budget, pipe.query_async::<_, (i64,)>(&mut conn)).await {
                Ok(Ok((acked,))) if acked >= replicas as i64 => WriteBackResult::Acked,
                Ok(Ok((acked,))) => WriteBackResult::Short(format!(
                    "peer {}: acknowledged by {acked} of {replicas} replica(s)",
                    p.index
                )),
                Ok(Err(e)) => {
                    p.write_back_conn.store(None);
                    WriteBackResult::Failed(format!("peer {}: {}", p.index, store_error(&e)))
                }
                Err(_) => {
                    p.write_back_conn.store(None);
                    WriteBackResult::Failed(format!("peer {}: timed out", p.index))
                }
            }
        });
        let mut short = None;
        for r in futures_util::future::join_all(futures).await {
            match r {
                WriteBackResult::Acked => {}
                WriteBackResult::Failed(m) => return WriteBackResult::Failed(m),
                WriteBackResult::Short(m) => short = Some(m),
            }
        }
        match short {
            Some(m) => WriteBackResult::Short(m),
            None => WriteBackResult::Acked,
        }
    }

    /// Drop the write-back connections, so the next attempt resolves the endpoints again.
    fn reset_write_back_conns(&self) {
        for p in &self.peers {
            p.write_back_conn.store(None);
        }
    }
}

/// `ReplayPeers` as a write-back target (the hub of a read origin).
struct PeerWriteBack(Arc<ReplayPeers>);

impl WriteBackSink for PeerWriteBack {
    fn write(&self, batch: Vec<(String, u64)>) -> BoxFuture<'static, WriteBackResult> {
        let peers = self.0.clone();
        Box::pin(async move { peers.rewrite_replicated(&batch).await })
    }

    fn reconnect(&self) {
        self.0.reset_write_back_conns();
    }
}

/// Why `confirm_replicated_kind` failed.
#[derive(Debug)]
pub struct ConfirmFailure {
    /// Every failing peer still held the nonce; only its replicas did not acknowledge in time.
    pub only_short: bool,
    pub message: String,
}

impl ReplayPeers {
    /// `confirm_replicated_kind` found every `WAIT` connection of `p` busy for the whole
    /// budget (`LocalWait`'s saturated case, at the peer): the nonce is looked up on the main
    /// connection. Held = short (`ConfirmFailure::only_short`: the hub fallback may confirm the
    /// WRITE elsewhere), gone or no answer = not short.
    async fn peer_wait_saturated(
        &self,
        p: &ReplayPeer,
        key: &str,
        timeout_ms: u64,
        deadline: tokio::time::Instant,
    ) -> Result<(), (bool, String)> {
        crate::health::record_replay_wait_saturated(&self.network, "peer");
        // `timeout_at` alone is no dispatch fence: nothing goes out once the deadline passed.
        if tokio::time::Instant::now() >= deadline {
            return Err((
                false,
                "every WAIT connection busy, and no time left".to_string(),
            ));
        }
        let Some(used) = p.conn.load_full() else {
            return Err((
                false,
                "every WAIT connection busy, and disconnected".to_string(),
            ));
        };
        let mut conn = (*used).clone();
        // Within the confirmation's own deadline (no fresh budget).
        let r = tokio::time::timeout_at(
            deadline,
            redis::cmd("SET")
                .arg(key)
                .arg("1")
                .arg("XX")
                .arg("EX")
                .arg(REPLAY_TTL_SECS)
                .query_async::<_, Option<String>>(&mut conn),
        )
        .await;
        match r {
            Ok(Ok(Some(_))) => Err((
                true,
                format!(
                    "not acknowledged: every WAIT connection busy with WAITs of {timeout_ms}ms"
                ),
            )),
            Ok(Ok(None)) => Err((false, "nonce no longer at the peer".to_string())),
            Ok(Err(e)) => {
                p.on_error(&self.network, &used, &e);
                Err((false, store_error(&e)))
            }
            Err(_) => Err((
                false,
                "every WAIT connection busy, and SET XX timed out".to_string(),
            )),
        }
    }

    /// Whether at least one peer has a connection right now.
    pub fn any_connected(&self) -> bool {
        self.peers.iter().any(|p| p.conn.load().is_some())
    }

    /// Whether every peer has a connection right now (at least one peer).
    pub fn all_connected(&self) -> bool {
        !self.peers.is_empty() && self.peers.iter().all(|p| p.conn.load().is_some())
    }

    /// `all_connected`, and where their replica acknowledgement is required
    /// (`REPLAY_PEER_WAIT_REPLICAS`), every peer with at least one open `WAIT` connection.
    pub fn all_ready(&self) -> bool {
        self.all_connected()
            && (self.wait.is_none() || self.peers.iter().all(|p| p.wait.any_connected()))
    }

    /// Whether at least one peer answered its last housekeeping PING.
    pub fn any_answering(&self) -> bool {
        self.peers
            .iter()
            .any(|p| p.answered.load(Ordering::Relaxed))
    }

    /// Whether every peer answered its last housekeeping PING: a request that the local store
    /// cannot decide needs all of them (`admit_without_local`).
    pub fn all_answering(&self) -> bool {
        !self.peers.is_empty()
            && self
                .peers
                .iter()
                .all(|p| p.answered.load(Ordering::Relaxed))
    }

    /// Whether peer `index` has a connection (it may still fail a command).
    fn connected(&self, index: usize) -> bool {
        self.peers
            .get(index)
            .is_some_and(|p| p.conn.load().is_some())
    }

    /// `SET key 1 NX EX ttl` at every peer concurrently, within one budget.
    pub async fn write_nonce(&self, key: &str, ttl_secs: u64) -> Vec<PeerOutcome> {
        self.write_nonce_value(key, ttl_secs, "1").await
    }

    /// `write_nonce` for a WRITE that both stores must take (`WritePolicy::BOTH_STORES`), where a
    /// peer that did not answer would fail it closed: the nonce is written with a value of this
    /// request's own, and a peer whose `SET NX` timed out is asked once more at once, within one
    /// more budget, with `SET key value NX GET`. Its answer tells the cases apart: nil (it was not
    /// there: stored now) or this request's value (the first `SET NX` landed) = new; any other
    /// value = held by another request (a replay). A peer whose store does not know `SET ... NX
    /// GET` (before Redis 7.0) answers an error, which fails the WRITE closed as before.
    pub async fn write_nonce_retrying(&self, key: &str, ttl_secs: u64) -> Vec<PeerOutcome> {
        let value = format!("{:016x}", rand::random::<u64>());
        let mut outcomes = self.write_nonce_value(key, ttl_secs, &value).await;
        self.retry_timed_out(key, ttl_secs, &value, &mut outcomes)
            .await;
        outcomes
    }

    /// Ask every peer whose outcome is `Timeout` once more, at once, whether `key` is new:
    /// `SET key value NX GET` with the value the first `SET NX` carried. nil (it was not there:
    /// stored now) or `value` (the first `SET NX` landed) = `Fresh`, another value = `Replay`.
    /// The retry goes over another connection to the peer, one of its `WAIT` connections (or,
    /// without a `WAIT` pool, a retry connection of its own): the main connection still owes
    /// the answer to the timed-out command, so a retry queued behind it would wait for that
    /// answer, or be matched with it if it was lost. Without another open connection within
    /// the retry's budget the outcome stays `Timeout`. Needs Redis >= 7.0 at the peer (`NX` with
    /// `GET`); an older store answers an error (`Error`: fail-closed, as without the retry).
    pub async fn retry_timed_out(
        &self,
        key: &str,
        ttl_secs: u64,
        value: &str,
        outcomes: &mut [PeerOutcome],
    ) {
        let retries = self
            .peers
            .iter()
            .enumerate()
            .filter(|(i, _)| outcomes.get(*i) == Some(&PeerOutcome::Timeout))
            .map(|(i, p)| async move {
                crate::health::record_replay_peer(&self.network, p.index, "timeout_retry");
                let deadline = tokio::time::Instant::now() + self.timeout;
                // A WAIT connection of the peer, or its own retry connection without a WAIT
                // pool: an open one only, within the retry's budget.
                let pool = if p.wait.slots.is_empty() {
                    &p.retry
                } else {
                    &p.wait
                };
                pool.reopen_closed(&self.network, p.index, &p.url);
                let outcome = match pool
                    .pool
                    .acquire(deadline, |j| pool.connected(j) && p.primary_usable())
                    .await
                {
                    Acquired::Busy | Acquired::NoneOpen => PeerOutcome::Timeout,
                    Acquired::Slot(held) => {
                        let slot_index = held.index();
                        let slot = pool.slots[slot_index].clone();
                        match slot.conn.load_full() {
                            None => PeerOutcome::Timeout,
                            // Checked again right before the command goes out.
                            Some(_) if tokio::time::Instant::now() >= deadline => {
                                PeerOutcome::Timeout
                            }
                            Some(used) => {
                                self.retry_on(
                                    p, pool, held, slot, &used, key, ttl_secs, value, deadline,
                                )
                                .await
                            }
                        }
                    }
                };
                crate::health::record_replay_peer(&self.network, p.index, outcome.as_str());
                (i, outcome)
            });
        for (i, outcome) in futures_util::future::join_all(retries).await {
            if let Some(o) = outcomes.get_mut(i) {
                *o = outcome;
            }
        }
    }

    /// One `SET key value NX GET` of `retry_timed_out` on the connection `used` of `held`. It
    /// is treated like a `WAIT` on that connection: an error drops this connection (a signal
    /// about the node also the peer's main one), and no answer replaces it (all of the pool's
    /// on a second one within `WAIT_TIMEOUTS_WINDOW`), also when the reply never comes after
    /// the caller gave up (`run_on_slot`'s retire, for this very connection only).
    #[allow(clippy::too_many_arguments)]
    async fn retry_on(
        &self,
        p: &ReplayPeer,
        pool: &PeerWaitPool,
        held: WaitSlot,
        slot: Arc<PeerWaitSlot>,
        used: &Arc<ConnectionManager>,
        key: &str,
        ttl_secs: u64,
        value: &str,
        deadline: tokio::time::Instant,
    ) -> PeerOutcome {
        let slot_index = held.index();
        let mut conn = (**used).clone();
        let (owned_key, value_owned) = (key.to_string(), value.to_string());
        let command = async move {
            redis::cmd("SET")
                .arg(&owned_key)
                .arg(&value_owned)
                .arg("NX")
                .arg("GET")
                .arg("EX")
                .arg(ttl_secs)
                .query_async::<_, Option<String>>(&mut conn)
                .await
        };
        let retire = {
            let (network, index, url, slot, used) = (
                self.network.clone(),
                p.index,
                p.url.clone(),
                slot.clone(),
                used.clone(),
            );
            move || {
                drop_wait_conn(&network, index, &url, &slot, &used);
            }
        };
        // An error or no answer switches the pool to exclusive like a WAIT would (recorded by
        // the command's task); an answer is no round-trip sample (not a WAIT).
        let errors_pool = pool.pool.clone();
        let timeout_pool = pool.pool.clone();
        let on_timeout = pool.on_timeout(
            &self.network,
            p.index,
            &p.url,
            slot_index,
            used,
            held.leased(),
        );
        let (links, network, failed_slot, failed_conn) =
            (p.links(), self.network.clone(), slot.clone(), used.clone());
        let hooks = SlotHooks {
            answered: Box::new(move |r: &redis::RedisResult<Option<String>>, _| {
                if let Err(e) = r {
                    errors_pool.observe(WaitOutcome::Slow, Duration::ZERO);
                    links.command_failed(&network, FailedOn::Extra(&failed_slot, &failed_conn), e);
                }
            }),
            timed_out: Box::new(move || {
                timeout_pool.observe(WaitOutcome::Slow, Duration::ZERO);
                on_timeout();
            }),
            stuck: Box::new(retire),
        };
        match run_on_slot_with(
            held,
            deadline,
            self.timeout + WAIT_DRAIN_EXTRA,
            command,
            hooks,
        )
        .await
        {
            Ok(Ok(None)) => PeerOutcome::Fresh,
            Ok(Ok(Some(v))) if v == value => PeerOutcome::Fresh,
            Ok(Ok(Some(_))) => PeerOutcome::Replay,
            // Handled by the command's task (`PeerLinks::command_failed`).
            Ok(Err(_)) => PeerOutcome::Error,
            // Handled by the command's task (`PeerWaitPool::on_timeout`).
            Err(_) => PeerOutcome::Timeout,
        }
    }

    async fn write_nonce_value(&self, key: &str, ttl_secs: u64, value: &str) -> Vec<PeerOutcome> {
        let futures = self.peers.iter().map(|p| async move {
            let outcome = match p.conn.load_full() {
                None => PeerOutcome::Disconnected,
                Some(used) => {
                    let mut conn = (*used).clone();
                    match timeout(self.timeout, async {
                        redis::cmd("SET")
                            .arg(key)
                            .arg(value)
                            .arg("NX")
                            .arg("EX")
                            .arg(ttl_secs)
                            .query_async::<_, Option<String>>(&mut conn)
                            .await
                    })
                    .await
                    {
                        Ok(Ok(Some(_))) => PeerOutcome::Fresh,
                        Ok(Ok(None)) => PeerOutcome::Replay,
                        Ok(Err(e)) => {
                            if crate::health::warn_due(&self.network, "peer_write") {
                                warn!(network = %self.network, peer = p.index, error = %store_error(&e), "Replay peer write failed");
                            }
                            p.on_error(&self.network, &used, &e);
                            PeerOutcome::Error
                        }
                        Err(_) => PeerOutcome::Timeout,
                    }
                }
            };
            crate::health::record_replay_peer(&self.network, p.index, outcome.as_str());
            if !matches!(outcome, PeerOutcome::Fresh | PeerOutcome::Replay) {
                self.disruptions.fetch_add(1, Ordering::Relaxed);
            }
            outcome
        });
        futures_util::future::join_all(futures).await
    }

    /// PING every peer for the `ohttp_replay_peer_connected` gauge (housekeeping). A connection
    /// that fails PEER_PING_FAILURES_RECONNECT PINGs in a row is dropped and reopened in the
    /// background (a hung connection never errors, so ConnectionManager would keep it). A peer
    /// that answers is also asked its `ROLE`: a PING succeeds on a demoted primary, and an idle
    /// gateway sends nothing that would be refused with `READONLY`. The idle `WAIT` connections
    /// are PINGed too, so that one a middlebox reset while idle is reopened here, in the
    /// background, rather than found by the next WRITE.
    pub async fn ping_all(&self) {
        self.ping_all_until(tokio::time::Instant::now() + HOUSEKEEPING_DEADLINE)
            .await
    }

    /// `ping_all`, every peer at once; a peer whose checks are not done by `deadline` counts as
    /// not answering this round.
    pub async fn ping_all_until(&self, deadline: tokio::time::Instant) {
        let checks = self.peers.iter().map(|p| async move {
            // Whether the peer answers is its main connection's verdict, recorded as soon as it
            // is known: a slow check of its WAIT connections after it does not change it.
            // Its WAIT (or retry) connections are checked at the same time.
            let main = async {
                let ok = tokio::time::timeout_at(deadline, self.ping_main(p))
                    .await
                    .unwrap_or(false);
                if !ok {
                    self.disruptions.fetch_add(1, Ordering::Relaxed);
                }
                p.answered.store(ok, Ordering::Relaxed);
                record_peer_connected(&self.network, p.index, p.standby, ok);
            };
            let extra = async {
                let _ = tokio::time::timeout_at(deadline, self.ping_wait_conns(p)).await;
            };
            tokio::join!(main, extra);
        });
        futures_util::future::join_all(checks).await;
    }

    /// PING (and ROLE) of a peer's main connection: whether it answered and reaches a primary.
    async fn ping_main(&self, p: &ReplayPeer) -> bool {
        let ok = match p.conn.load_full() {
            // A reconnect task is running.
            None => false,
            Some(used) => {
                let mut conn = (*used).clone();
                let ok = matches!(
                    timeout(
                        self.timeout,
                        redis::cmd("PING").query_async::<_, String>(&mut conn)
                    )
                    .await,
                    Ok(Ok(pong)) if pong == "PONG"
                );
                if ok {
                    p.ping_failures.store(0, Ordering::Relaxed);
                    // A replica there: the connection was dropped, the peer is not usable this
                    // round.
                    if !self.check_peer_role(p, &used).await {
                        return false;
                    }
                } else if p.ping_failures.fetch_add(1, Ordering::Relaxed) + 1
                    >= PEER_PING_FAILURES_RECONNECT
                {
                    p.ping_failures.store(0, Ordering::Relaxed);
                    if crate::health::warn_due(&self.network, "peer_ping_failures") {
                        warn!(network = %self.network, peer = p.index, "Replay peer failed {PEER_PING_FAILURES_RECONNECT} PINGs in a row: reopening the connection");
                    }
                    p.links()
                        .drop_all(&self.network, &used, "timeout", "PING failures");
                }
                ok
            }
        };
        ok
    }

    /// `ROLE` of a peer whose main connection answered a PING: a replica there (the endpoint
    /// still reaches a demoted primary) drops the connection and reconnects (false). No answer,
    /// or a store that does not allow `ROLE`, changes nothing (true).
    async fn check_peer_role(&self, p: &ReplayPeer, used: &Arc<ConnectionManager>) -> bool {
        let mut conn = (**used).clone();
        let answer = timeout(
            self.timeout,
            redis::cmd("ROLE").query_async::<_, redis::Value>(&mut conn),
        )
        .await;
        if let Ok(Ok(v)) = answer {
            if crate::store_conn::parse_role(&v) == Some(false) {
                self.disruptions.fetch_add(1, Ordering::Relaxed);
                p.links()
                    .drop_all(&self.network, used, "role", "ROLE is not master");
                return false;
            }
        }
        true
    }

    /// Housekeeping of the extra connections of `p`: its `WAIT` pool, or its retry connection
    /// without one. A closed connection is reopened in the background; one connection that no
    /// request holds is PINGed (`take_idle_for_check`), and replaced if it does not answer.
    async fn ping_wait_conns(&self, p: &ReplayPeer) {
        let (pool, budget) = match self.wait {
            // A request may lease the connection meanwhile: its WAIT can delay the PING's answer.
            Some(WriteWaitConfig { timeout_ms, .. }) => {
                (&p.wait, self.timeout + Duration::from_millis(timeout_ms))
            }
            None => (&p.retry, self.timeout),
        };
        pool.reopen_closed(&self.network, p.index, &p.url);
        let Some(held) = pool.pool.take_idle_for_check(|i| pool.connected(i)) else {
            return;
        };
        let slot = pool.slots[held.index()].clone();
        let Some(used) = slot.conn.load_full() else {
            return;
        };
        let mut conn = (*used).clone();
        let command = async move { redis::cmd("PING").query_async::<_, String>(&mut conn).await };
        let retire = {
            let (network, index, url, slot, used) = (
                self.network.clone(),
                p.index,
                p.url.clone(),
                slot.clone(),
                used.clone(),
            );
            move || {
                drop_wait_conn(&network, index, &url, &slot, &used);
            }
        };
        // No answer in time: replaced by the command's task (only if still the slot's).
        let on_timeout = {
            let (network, index, url, slot, used) = (
                self.network.clone(),
                p.index,
                p.url.clone(),
                slot.clone(),
                used.clone(),
            );
            move || {
                drop_wait_conn(&network, index, &url, &slot, &used);
            }
        };
        let hooks = SlotHooks {
            answered: Box::new(|_, _| {}),
            timed_out: Box::new(on_timeout),
            stuck: Box::new(retire),
        };
        let r = run_on_slot_with(
            held,
            tokio::time::Instant::now() + budget,
            budget + WAIT_DRAIN_EXTRA,
            command,
            hooks,
        )
        .await;
        if matches!(r, Ok(Ok(ref pong)) if pong != "PONG") || matches!(r, Ok(Err(_))) {
            debug!(network = %self.network, peer = p.index, "Replay peer WAIT connection failed its PING: reopening it in the background");
            drop_wait_conn(&self.network, p.index, &p.url, &slot, &used);
        }
    }

    /// How many `WAIT` connections of each peer are open (tests, diagnostics).
    pub fn wait_conns_open(&self) -> Vec<usize> {
        self.peers
            .iter()
            .map(|p| {
                p.wait
                    .slots
                    .iter()
                    .filter(|s| s.conn.load().is_some())
                    .count()
            })
            .collect()
    }
}

impl ReplayPeer {
    /// A new connection (the name is resolved again), accepted only on a primary: right after
    /// a failover of the peer's store its endpoint name can still reach the demoted node.
    async fn open(url: &str) -> anyhow::Result<ConnectionManager> {
        let client = redis::Client::open(url)?;
        match timeout(
            PEER_CONNECT_TIMEOUT,
            crate::store_conn::open_checked(&client, Role::Primary),
        )
        .await
        {
            Ok(conn) => conn,
            Err(_) => anyhow::bail!(
                "connect timed out after {}s",
                PEER_CONNECT_TIMEOUT.as_secs()
            ),
        }
    }

    /// Whether the peer's endpoint is known to reach its primary right now: its main
    /// connection is open (it is dropped on every signal that the node is not the primary, and
    /// a new one is accepted only on a primary). A `WAIT` or retry connection is used only then.
    fn primary_usable(&self) -> bool {
        self.conn.load().is_some()
    }

    /// What a `'static` task needs to act on this peer's connections (`PeerLinks`).
    fn links(&self) -> PeerLinks {
        PeerLinks {
            index: self.index,
            url: self.url.clone(),
            standby: self.standby,
            main: self.conn.clone(),
            extras: self
                .wait
                .slots
                .iter()
                .chain(self.retry.slots.iter())
                .cloned()
                .collect(),
            changed: self.changed.clone(),
        }
    }

    /// A command on the main connection `used` failed with `e` (`PeerLinks::command_failed`).
    fn on_error(&self, network: &str, used: &Arc<ConnectionManager>, e: &redis::RedisError) {
        self.links()
            .command_failed(network, FailedOn::Main(used), e);
    }
}

/// What a failed command ran on (`PeerLinks::command_failed`).
enum FailedOn<'a> {
    /// The peer's main connection.
    Main(&'a Arc<ConnectionManager>),
    /// One of its `WAIT` or retry connections, in that slot.
    Extra(&'a Arc<PeerWaitSlot>, &'a Arc<ConnectionManager>),
}

/// A replay peer's connections, for code that may outlive a borrow of it (the task of a
/// command, the replicator).
#[derive(Clone)]
struct PeerLinks {
    index: usize,
    url: String,
    standby: bool,
    main: Arc<ArcSwapOption<ConnectionManager>>,
    /// Its `WAIT` and retry connection slots.
    extras: Vec<Arc<PeerWaitSlot>>,
    changed: Arc<tokio::sync::Notify>,
}

impl PeerLinks {
    /// Drop every `WAIT` and retry connection (each reopens in the background).
    fn drop_extras(&self, network: &str) {
        for slot in &self.extras {
            if let Some(c) = slot.conn.load_full() {
                drop_wait_conn(network, self.index, &self.url, slot, &c);
            }
        }
    }

    /// Replace the main connection `used` by None and start the reconnect task, only if
    /// `used` is still the installed one (once per connection).
    fn drop_main(
        &self,
        network: &str,
        used: &Arc<ConnectionManager>,
        reason: &'static str,
        detail: &str,
    ) -> bool {
        let current = Some(used.clone());
        let prev = self
            .main
            .compare_and_swap(&current, None::<Arc<ConnectionManager>>);
        let swapped = (*prev).as_ref().is_some_and(|p| Arc::ptr_eq(p, used));
        if swapped {
            if crate::health::warn_due(network, "peer_lost_primary") {
                warn!(network = %network, peer = self.index, error = %detail, "Replay peer connection lost the primary: reconnecting");
            }
            crate::health::record_store_reconnect(network, "replay_peer", reason);
            spawn_peer_reconnect_task(network.to_string(), self.clone());
        }
        swapped
    }

    /// The main connection `used` (and with it every `WAIT` and retry connection) is to be
    /// replaced, only if `used` is still the installed one: a stale check changes nothing.
    fn drop_all(
        &self,
        network: &str,
        used: &Arc<ConnectionManager>,
        reason: &'static str,
        detail: &str,
    ) {
        // The extras only once this check's connection was swapped out: a stale check (or one
        // that lost the race to another) changes nothing.
        if self.drop_main(network, used, reason, detail) {
            self.drop_extras(network);
        }
    }

    /// The one handling of a failed command on one of the peer's connections. A `WAIT` or
    /// retry connection is dropped (only if still in its slot). If the connection was still
    /// the installed one and `e` says the node is no longer the primary (`is_role_signal`),
    /// the other `WAIT` and retry connections go too, and so does the main connection; a
    /// failover signal on the main connection drops it. A stale connection (already
    /// replaced) changes nothing else.
    fn command_failed(&self, network: &str, on: FailedOn<'_>, e: &redis::RedisError) {
        let installed = match on {
            FailedOn::Main(used) => self
                .main
                .load()
                .as_ref()
                .is_some_and(|c| Arc::ptr_eq(c, used)),
            // Installed = this call swapped it out of its slot (compare-and-swap).
            FailedOn::Extra(slot, used) => {
                drop_wait_conn(network, self.index, &self.url, slot, used)
            }
        };
        if !installed || !is_failover_signal(e, Role::Primary) {
            return;
        }
        let reason = crate::store_conn::signal_reason(e);
        if is_role_signal(e) {
            self.drop_extras(network);
            if let FailedOn::Extra(..) = on {
                if let Some(main) = self.main.load_full() {
                    self.drop_main(network, &main, reason, &store_error(e));
                }
            }
        }
        if let FailedOn::Main(used) = on {
            self.drop_main(network, used, reason, &store_error(e));
        }
    }
}

/// The asynchronous replicator's view of the peers: one pipelined `SET NX EX` per batch.
impl PeerSink for ReplayPeers {
    fn set_nx_batch(
        &self,
        peer: usize,
        keys: Vec<String>,
        ttl_secs: u64,
    ) -> BoxFuture<'static, Result<Vec<Option<String>>, String>> {
        let p = self.peers.get(peer);
        let conn = p.and_then(|p| p.conn.load_full());
        let links = p.map(ReplayPeer::links);
        let network = self.network.clone();
        Box::pin(async move {
            let (Some(used), Some(links)) = (conn, links) else {
                return Err("disconnected".to_string());
            };
            let mut conn = (*used).clone();
            let mut pipe = redis::pipe();
            for key in &keys {
                pipe.cmd("SET")
                    .arg(key)
                    .arg("1")
                    .arg("NX")
                    .arg("EX")
                    .arg(ttl_secs);
            }
            pipe.query_async::<_, Vec<Option<String>>>(&mut conn)
                .await
                .map_err(|e| {
                    links.command_failed(&network, FailedOn::Main(&used), &e);
                    store_error(&e)
                })
        })
    }

    fn ping(&self, peer: usize) -> BoxFuture<'static, Result<(), String>> {
        let conn = self.peers.get(peer).and_then(|p| p.conn.load_full());
        Box::pin(async move {
            let Some(conn) = conn else {
                return Err("disconnected".to_string());
            };
            let mut conn = (*conn).clone();
            match redis::cmd("PING").query_async::<_, String>(&mut conn).await {
                Ok(pong) if pong == "PONG" => Ok(()),
                Ok(other) => Err(format!("unexpected PING reply {other}")),
                Err(e) => Err(store_error(&e)),
            }
        })
    }

    fn peers(&self) -> usize {
        self.peers.len()
    }
}

/// The connectivity gauge of a peer: `ohttp_replay_peer_connected` for REPLAY_PEER_URLS,
/// `ohttp_replay_standby_connected` for REPLAY_STANDBY_URLS.
fn record_peer_connected(network: &str, index: usize, standby: bool, connected: bool) {
    if standby {
        crate::health::record_replay_standby_connected(network, index, connected);
    } else {
        crate::health::record_replay_peer_connected(network, index, connected);
    }
}

/// Retry a peer connection with exponential backoff (200 ms to PEER_RECONNECT_MAX_BACKOFF_SECS)
/// until it succeeds. The first attempt is quick: after a failover the peer's endpoint name
/// usually points at the promoted replica within seconds.
fn spawn_peer_reconnect_task(network: String, links: PeerLinks) {
    let PeerLinks {
        index,
        url,
        standby,
        main: conn,
        changed,
        ..
    } = links;
    tokio::spawn(async move {
        let mut backoff = Duration::from_millis(200);
        let mut pause = jittered(backoff);
        let mut loading = 0u32;
        loop {
            tokio::time::sleep(pause).await;
            match ReplayPeer::open(&url).await {
                Ok(c) => {
                    conn.store(Some(Arc::new(c)));
                    // Its WAIT and retry connections are usable again (`primary_usable`).
                    changed.notify_waiters();
                    record_peer_connected(&network, index, standby, true);
                    info!(network = %network, peer = index, standby, "Replay peer connected");
                    return;
                }
                Err(e) => {
                    if crate::health::warn_due(&network, "peer_reconnect") {
                        warn!(network = %network, peer = index, error = %error_summary(&e), "Replay peer reconnection attempt failed");
                    }
                    backoff =
                        (backoff * 2).min(Duration::from_secs(PEER_RECONNECT_MAX_BACKOFF_SECS));
                    pause = reopen_pause(&e, jittered(backoff), &mut loading);
                }
            }
        }
    });
}

const GET_TREE_STATE_PATH: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTreeState";

/// Parse a PINNED_TREESTATE_RANGE value: "START-END" or "START-" (open-ended).
pub fn parse_pinned_range(s: &str) -> Option<(u64, u64)> {
    let (a, b) = s.trim().split_once('-')?;
    let start: u64 = a.trim().parse().ok()?;
    let end: u64 = if b.trim().is_empty() {
        u64::MAX
    } else {
        b.trim().parse().ok()?
    };
    if start == 0 || end < start {
        return None;
    }
    Some((start, end))
}

/// gRPC-framed GetTreeState request body (BlockId { height }).
pub fn grpc_tree_state_request(height: u64) -> Vec<u8> {
    grpc_block_id(height, &[])
}

pub fn tree_state_path() -> &'static str {
    GET_TREE_STATE_PATH
}

impl ResponseCache {
    pub async fn connect(
        redis_url: &str,
        redis_security_url: Option<&str>,
        network: String,
        backend_host: String,
        redis_op_timeout_ms: u64,
        max_block_range: u32,
        backends_policy: &std::collections::HashMap<String, Vec<(String, String)>>,
    ) -> anyhow::Result<Self> {
        // Try to connect to cache Redis; if it fails, log and continue with None (fail-open).
        // A background retry task will attempt reconnection.
        let cache_conn = match redis::Client::open(redis_url) {
            Ok(client) => match ConnectionManager::new(client).await {
                Ok(conn) => {
                    info!(network = %network, "Redis cache connected");
                    Some(conn)
                }
                Err(e) => {
                    warn!(
                        "Failed to connect to Redis cache, continuing without cache (will retry in background): {}",
                        e
                    );
                    None
                }
            },
            Err(e) => {
                warn!(
                    "Invalid Redis cache URL, continuing without cache (will retry in background): {}",
                    e
                );
                None
            }
        };

        // Separate security connection if configured. Its failure still fails startup
        // (fail-closed for replay protection).
        let security_conn = if let Some(sec_url) = redis_security_url {
            if !sec_url.is_empty() && sec_url != redis_url {
                Some(StoreConn::connect(sec_url, "security", network.clone(), Role::Primary).await?)
            } else {
                None
            }
        } else {
            None
        };

        // Policy hash from MAX_BLOCK_RANGE + serialized BACKENDS_POLICY (sorted by authority).
        let policy_hash = {
            let mut hasher = Sha256::new();
            hasher.update(max_block_range.to_be_bytes());
            let mut sorted_policies: Vec<_> = backends_policy.iter().collect();
            sorted_policies.sort_by_key(|(k, _)| *k);
            for (authority, policies) in sorted_policies {
                hasher.update(authority.as_bytes());
                for (method, path) in policies {
                    hasher.update(method.as_bytes());
                    hasher.update(path.as_bytes());
                }
            }
            let hash = hasher.finalize();
            format!(
                "{:016x}",
                u64::from_be_bytes([
                    hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
                ])
            )
        };

        let cache = Self {
            cache_conn: Arc::new(ArcSwapOption::from(cache_conn.map(Arc::new))),
            cache_ping_failures: Arc::new(AtomicU32::new(0)),
            security_conn,
            tip: Arc::new(TipCell::new()),
            epoch: Arc::new(AtomicU64::new(0)),
            network,
            backend_host,
            last_epoch_sync: Arc::new(AtomicU64::new(0)),
            redis_timeout: Duration::from_millis(redis_op_timeout_ms),
            policy_hash,
            pinned_conn: None,
            pinned_write_conn: Default::default(),
            pinned_read_only_until: Arc::new(AtomicU64::new(0)),
            pinned_writer_gen: Default::default(),
            pinned_writer_lock: Default::default(),
            pinned_range: None,
            pinned_fill_from: 0,
            cache_redis_url: redis_url.to_string(),
            replay_peers: None,
            replicator: None,
            standby_peers: None,
            standby_replicator: None,
            write_wait: None,
            local_aof: None,
            write_fallback: None,
            hub_fallback: None,
            unavailable_fallback: false,
            fallback_health: Arc::new(FallbackHealth::new(
                DEFAULT_REPLAY_FALLBACK_HEALTH_FAILURES,
                Duration::from_secs(DEFAULT_REPLAY_FALLBACK_HEALTH_WINDOW_SECS),
            )),
            epoch_state: Arc::default(),
            pinned_sweep_fetch_permits: Arc::new(tokio::sync::Semaphore::new(
                PINNED_SWEEP_FETCH_PERMITS,
            )),
        };

        if cache.cache_conn.load().is_none() {
            spawn_cache_reconnect_task(cache.clone());
        }

        Ok(cache)
    }

    /// Attempt to (re)connect to the cache Redis. Returns true if successful.
    async fn try_reconnect_cache(&self) -> bool {
        match redis::Client::open(self.cache_redis_url.as_str()) {
            Ok(client) => match ConnectionManager::new(client).await {
                Ok(conn) => {
                    self.cache_conn.store(Some(Arc::new(conn)));
                    info!(network = %self.network, "Redis cache reconnected successfully");
                    true
                }
                Err(e) => {
                    debug!(network = %self.network, error = %store_error(&e), "Redis cache reconnection attempt failed");
                    false
                }
            },
            Err(e) => {
                warn!(network = %self.network, error = %store_error(&e), "Invalid Redis cache URL during reconnect");
                false
            }
        }
    }

    /// Attach the pinned tier (REDIS_PINNED_URL + PINNED_TREESTATE_RANGE), and optionally a
    /// separate store its entries are written to (REDIS_PINNED_WRITE_URL), for a pinned store
    /// that is a read replica. An unreachable write store is not fatal: the entries are then
    /// written to the pinned store, or not at all when it is a read replica, until a background
    /// task has connected it (retried with a backoff of 1 s up to 60 s).
    pub async fn with_pinned(
        mut self,
        url: &str,
        write_url: Option<&str>,
        range: (u64, u64),
    ) -> anyhow::Result<Self> {
        self.pinned_conn =
            Some(StoreConn::connect(url, "pinned", self.network.clone(), Role::Any).await?);
        self.pinned_range = Some(range);
        // No tree state exists below the Sapling activation (the light wallet server refuses
        // those heights, and wallets never ask for them).
        self.pinned_fill_from = crate::store::sapling_activation(&self.network);
        if let Some(write_url) = write_url {
            match StoreConn::connect(write_url, "pinned_write", self.network.clone(), Role::Any)
                .await
            {
                Ok(c) => self.pinned_write_conn.store(Some(c)),
                Err(e) => {
                    warn!(network = %self.network, error = %error_summary(&e), "pinned write store unreachable at startup, writing pinned entries to the pinned store until it is reachable");
                    self.spawn_pinned_write_reconnect(write_url.to_string());
                }
            }
        }
        if let Some(writer) = self
            .pinned_write_conn
            .load_full()
            .or_else(|| self.pinned_conn.clone())
        {
            let generation = self.pinned_writer_gen.load(Ordering::SeqCst);
            if !self.probe_pinned_writer(&writer, generation).await {
                info!(network = %self.network, "pinned store is a read replica, pinned entries are not written");
            }
        }
        Ok(self)
    }

    pub fn pinned_range(&self) -> Option<(u64, u64)> {
        self.pinned_range
    }

    /// Enable replica acknowledgement of WRITE nonces on dedicated connections to `security_url`
    /// (`DEFAULT_REPLAY_WAIT_CONNS` of them).
    pub async fn with_write_wait(
        self,
        security_url: &str,
        config: WriteWaitConfig,
    ) -> anyhow::Result<Self> {
        self.with_write_wait_conns(security_url, config, DEFAULT_REPLAY_WAIT_CONNS)
            .await
    }

    /// `with_write_wait` with `conns` dedicated `WAIT` connections (`REPLAY_WAIT_CONNS`).
    pub async fn with_write_wait_conns(
        mut self,
        security_url: &str,
        config: WriteWaitConfig,
        conns: usize,
    ) -> anyhow::Result<Self> {
        if security_url.is_empty() {
            anyhow::bail!("REPLAY_WRITE_WAIT_REPLICAS needs REDIS_SECURITY_URL");
        }
        let mut pool = Vec::with_capacity(conns.max(1));
        for _ in 0..conns.max(1) {
            pool.push(
                StoreConn::connect(
                    security_url,
                    "write_wait",
                    self.network.clone(),
                    Role::Primary,
                )
                .await?,
            );
        }
        let lease_pool = LeasePool::new(pool.len(), config.timeout_ms);
        // A replaced connection wakes the requests waiting for one (`LeasePool::acquire`).
        for c in &pool {
            c.set_replaced_notify(lease_pool.changed.clone());
        }
        let ww = WriteWait {
            pool: lease_pool,
            conns: pool,
            config,
            timeouts: Arc::default(),
        };
        // The peer fallback needs peers that acknowledge on their replicas (the replay peers
        // are attached before this, see main.rs); without them nothing changes.
        if self
            .replay_peers
            .as_ref()
            .is_some_and(|p| p.wait().is_some())
        {
            let fb = Arc::new(WriteFallback::new(
                &self.network,
                self.store_generation_of(&ww),
            ));
            // Its own connection: its WAITs must not delay the requests' WAITs.
            let write_back = StoreConn::connect(
                security_url,
                "write_back",
                self.network.clone(),
                Role::Primary,
            )
            .await?;
            crate::write_fallback::spawn_write_back(
                fb.clone(),
                Arc::new(LocalWriteBack {
                    conn: write_back,
                    wait: config,
                    redis_timeout: self.redis_timeout,
                }),
            );
            for conn in &ww.conns {
                crate::write_fallback::spawn_window_watch(fb.clone(), conn.clone());
            }
            if let Some(sec) = &self.security_conn {
                crate::write_fallback::spawn_window_watch(fb.clone(), sec.clone());
            }
            self.write_fallback = Some(fb);
        }
        self.write_wait = Some(Arc::new(ww));
        Ok(self)
    }

    /// Sum of the security and `WAIT` connection generations: it changes whenever one of them
    /// was replaced (a failover of the local store, or a hung connection).
    fn store_generation_of(&self, ww: &WriteWait) -> u64 {
        ww.generation()
            + self
                .security_conn
                .as_ref()
                .map_or(0, |c| c.failover_generation())
    }

    /// Diagnostics of the local `WAIT` pool (`LeasePool`): whether it hands out connections
    /// exclusively right now.
    pub fn local_wait_exclusive(&self) -> bool {
        self.write_wait.as_ref().is_some_and(|w| w.pool.exclusive())
    }

    /// Diagnostics of the local `WAIT` pool: its connections that no request holds exclusively.
    pub fn local_wait_idle(&self) -> usize {
        self.write_wait.as_ref().map_or(0, |w| w.pool.idle().len())
    }

    pub fn write_wait(&self) -> Option<WriteWaitConfig> {
        self.write_wait.as_ref().map(|w| w.config)
    }

    /// For a WRITE: rewrite its nonce (`SET XX`, keeps it a write on this connection) and `WAIT`
    /// until `replicas` replicas have it. Fail-closed: fewer acknowledgements, an error or a
    /// timeout is an `Err` (outer 503), like an unavailable replay store. No-op when disabled.
    #[cfg(test)]
    pub async fn confirm_nonce_replicated(&self, body_hash: &[u8]) -> anyhow::Result<()> {
        let Some(ww) = self.write_wait.as_ref() else {
            return Ok(());
        };
        let key = self.nonce_key(body_hash);
        match self.wait_local(ww, &key).await {
            LocalWait::Acked => Ok(()),
            LocalWait::Short(e) | LocalWait::Unavailable(e) | LocalWait::Failed(e) => Err(e),
        }
    }

    async fn wait_local(&self, ww: &WriteWait, key: &str) -> LocalWait {
        let WriteWaitConfig {
            replicas,
            timeout_ms,
        } = ww.config;
        // WAIT returns after at most timeout_ms; the budget adds the round trips (and the
        // retry's, including the wait for a replaced connection).
        let budget = Duration::from_millis(timeout_ms) + self.redis_timeout * 4;
        let deadline = tokio::time::Instant::now() + budget;
        let timed_out = || {
            anyhow::anyhow!(
                "Replay nonce WAIT timed out after {}ms (fail-closed)",
                budget.as_millis()
            )
        };
        // One `WAIT` connection of the pool (`LeasePool`), only while the whole `WAIT` (its
        // timeout and the round trips) still fits in the budget, and checked again once it is
        // held. Exclusive mode: every connection busy until then means that the `WAIT`s ahead
        // all ran into their timeout: decided without a `WAIT`, which would only come back
        // short too (`wait_saturated`). Only a connection that reaches the primary right now is
        // handed out (one being replaced never is).
        let required = Duration::from_millis(timeout_ms) + self.redis_timeout * 2;
        let lease_deadline = deadline.checked_sub(required).unwrap_or(deadline);
        // A connection that no longer reaches the primary (a failover: the old primary answers
        // READONLY / refuses WAIT, or the socket broke) fails the first command and is replaced
        // (a new name resolution, accepted only on a primary); one retry runs within the same
        // budget, on that connection's replacement if it comes within one command timeout,
        // else on any usable connection of the pool. SET XX and WAIT are idempotent, and SET XX only
        // succeeds where the nonce is: on a promoted replica that never received it, the WRITE
        // is refused instead of confirmed. Both go out as one pipeline on one connection, so the
        // WAIT counts the replicas of the very session that rewrote the nonce: sent as two
        // commands, a reconnect of the connection between them would have the WAIT measure a
        // new session on another node, where the nonce may never have been.
        let mut retried = false;
        // The connection that reported the failover signal, with its generation then: the
        // retry waits up to one command timeout for its replacement and then prefers that one
        // (the others may share its broken path) for up to one more command timeout; without a
        // replacement, or with it busy, any usable connection of the pool.
        let mut failed: Option<(usize, u64)> = None;
        let mut pinned: Option<usize> = None;
        loop {
            if let Some((i, generation)) = failed.take() {
                let left = lease_deadline
                    .saturating_duration_since(tokio::time::Instant::now())
                    .min(self.redis_timeout);
                if ww.conns[i].wait_for_reconnect(generation, left).await {
                    pinned = Some(i);
                }
            }
            // The replacement of the failed connection, if it came in time, for up to one
            // command timeout; after that (it is busy) any usable connection.
            let pinned_slot = match pinned.take() {
                Some(p) => {
                    let until =
                        lease_deadline.min(tokio::time::Instant::now() + self.redis_timeout);
                    ww.pool
                        .acquire(until, |i| i == p && ww.conns[i].usable_now())
                        .await
                        .into_slot()
                }
                None => None,
            };
            // Only a connection that reaches the primary right now is eligible; a request waits
            // for one to be released or replaced until `lease_deadline`. Every eligible one
            // taken until then: the saturated path; none eligible: unavailable.
            let acquired = match pinned_slot {
                Some(h) => Acquired::Slot(h),
                None => {
                    ww.pool
                        .acquire(lease_deadline, |i| ww.conns[i].usable_now())
                        .await
                }
            };
            let held = match acquired {
                Acquired::Slot(h) => h,
                Acquired::Busy => return self.wait_saturated(key, timeout_ms, deadline).await,
                Acquired::NoneOpen => return LocalWait::Unavailable(timed_out()),
            };
            let index = held.index();
            let wait_conn = ww.conns[index].clone();
            // Checked again right before the command goes out: never after the cutoff.
            if tokio::time::Instant::now() > lease_deadline {
                drop(held);
                return self.wait_saturated(key, timeout_ms, deadline).await;
            }
            if !wait_conn.usable_now() {
                // Replaced since it was picked: take another one.
                drop(held);
                continue;
            }
            let generation = wait_conn.generation();
            let mut conn = wait_conn.get();
            let owned_key = key.to_string();
            let command = async move {
                redis::pipe()
                    .cmd("SET")
                    .arg(&owned_key)
                    .arg("1")
                    .arg("XX")
                    .arg("EX")
                    .arg(REPLAY_TTL_SECS)
                    .cmd("WAIT")
                    .arg(replicas)
                    .arg(timeout_ms)
                    .query_async::<_, (Option<String>, i64)>(&mut conn)
                    .await
            };
            let retire = {
                let c = wait_conn.clone();
                move || {
                    c.retire_quietly("timeout", generation);
                }
            };
            // Recorded by the task that owns the command, also if this request goes away: the
            // answer (the connection's failover signals, the pool's mode), and a timeout. A
            // WAIT ends after its timeout on the server, so no answer within the budget means
            // this connection is stuck: it is replaced, quietly (no change of the store), unless
            // it or the pool was replaced since the command went out (a stale completion); a
            // second connection of the pool stuck within a few seconds means the path to the
            // store is: then all of them are replaced.
            let on_timeout = {
                let (c, conns, timeouts) =
                    (wait_conn.clone(), ww.conns.clone(), ww.timeouts.clone());
                let (round, leased) = (timeouts.round(), held.leased());
                move || {
                    let current = c.generation() == generation;
                    match timeouts.note_timeout(index, round, current, leased) {
                        TimeoutVerdict::Stale => {}
                        TimeoutVerdict::One => {
                            c.retire_quietly("timeout", generation);
                        }
                        TimeoutVerdict::All => {
                            for c in &conns {
                                c.force_reconnect("timeout");
                            }
                        }
                    }
                }
            };
            let observed = wait_conn.clone();
            let hooks = wait_hooks(
                ww.pool.clone(),
                move |r: &redis::RedisResult<(Option<String>, i64)>| {
                    observed.observe(r);
                    matches!(r, Ok((Some(_), acked)) if *acked >= replicas as i64)
                },
                on_timeout,
                retire,
            );
            let r =
                run_on_slot_with(held, deadline, budget + WAIT_DRAIN_EXTRA, command, hooks).await;
            let e = match r {
                Ok(Ok((Some(_), acked))) if acked >= replicas as i64 => return LocalWait::Acked,
                Ok(Ok((Some(_), acked))) => {
                    wait_conn.observe_short_ack();
                    return LocalWait::Short(anyhow::anyhow!(
                        "Replay nonce acknowledged by {acked} of {replicas} replica(s) within {timeout_ms}ms (fail-closed)"
                    ));
                }
                Ok(Ok((None, _))) => {
                    return LocalWait::Failed(anyhow::anyhow!(
                        "Replay nonce no longer in the security store (fail-closed)"
                    ))
                }
                Ok(Err(e)) if !retried && is_failover_signal(&e, Role::Primary) => e,
                Ok(Err(e)) if is_failover_signal(&e, Role::Primary) => {
                    return LocalWait::Unavailable(anyhow::anyhow!(
                        "Replay nonce WAIT failed (fail-closed): {}",
                        store_error(&e)
                    ))
                }
                Ok(Err(e)) => {
                    return LocalWait::Failed(anyhow::anyhow!(
                        "Replay nonce WAIT failed (fail-closed): {}",
                        store_error(&e)
                    ))
                }
                // Handled by the command's task (above).
                Err(_) => return LocalWait::Unavailable(timed_out()),
            };
            retried = true;
            failed = Some((index, generation));
            if crate::health::warn_due(&self.network, "local_wait_retry") {
                warn!(network = %self.network, error = %store_error(&e), "Replay nonce WAIT connection lost the primary, retrying once on a new connection");
            }
        }
    }

    /// Every `WAIT` connection stayed busy for the wait budget: the `WAIT`s ahead all took their
    /// timeout, so this one would have come back short as well. The nonce is looked up on the
    /// security connection (`SET XX`, primary-checked like every connection to this store): held
    /// = a short acknowledgement (the peer fallback may confirm it; without one it fails closed,
    /// as a short acknowledgement always did), gone = refused, no answer = unavailable.
    async fn wait_saturated(
        &self,
        key: &str,
        timeout_ms: u64,
        deadline: tokio::time::Instant,
    ) -> LocalWait {
        crate::health::record_replay_wait_saturated(&self.network, "local");
        // `timeout_at` alone is no dispatch fence: nothing goes out once the deadline passed.
        if tokio::time::Instant::now() >= deadline {
            return LocalWait::Unavailable(anyhow::anyhow!(
                "Replay nonce WAIT timed out: every WAIT connection busy (fail-closed)"
            ));
        }
        let Some(sec) = self.security_conn.as_ref() else {
            return LocalWait::Unavailable(anyhow::anyhow!(
                "Replay protection unavailable: REDIS_SECURITY_URL not configured"
            ));
        };
        let r = tokio::time::timeout_at(
            deadline,
            redis::cmd("SET")
                .arg(key)
                .arg("1")
                .arg("XX")
                .arg("EX")
                .arg(REPLAY_TTL_SECS)
                .query_async::<_, Option<String>>(&mut sec.get()),
        )
        .await;
        sec.observe_timed(&r);
        match r {
            Ok(Ok(Some(_))) => LocalWait::Short(anyhow::anyhow!(
                "Replay nonce not acknowledged: every WAIT connection was busy with WAITs of {timeout_ms}ms (fail-closed)"
            )),
            Ok(Ok(None)) => LocalWait::Failed(anyhow::anyhow!(
                "Replay nonce no longer in the security store (fail-closed)"
            )),
            Ok(Err(e)) => LocalWait::Unavailable(anyhow::anyhow!(
                "Replay nonce WAIT failed (fail-closed): {}", store_error(&e)
            )),
            Err(_) => LocalWait::Unavailable(anyhow::anyhow!(
                "Replay nonce WAIT timed out: every WAIT connection busy (fail-closed)"
            )),
        }
    }

    pub fn write_fallback(&self) -> Option<&WriteFallback> {
        self.write_fallback.as_deref()
    }

    /// For a WRITE whose nonce is new everywhere it was checked so far (`check_replay`, then
    /// `replicate_nonce_checked` gave `check`): the local replica wait
    /// (`REPLAY_WRITE_WAIT_REPLICAS`), with the peer fallback of `write_fallback.rs` when only
    /// the acknowledgement is short. `Err` = fail-closed (outer 503 / grpc-status 14), as an
    /// unacknowledged nonce always was. `Run` when the wait is off.
    pub async fn confirm_write_nonce(
        &self,
        local: &LocalCheck,
        check: &PeerCheck,
    ) -> anyhow::Result<WriteAdmission> {
        if !matches!(
            local.verdict,
            LocalReplayCheck::New | LocalReplayCheck::NewPeersUnconfirmed
        ) {
            anyhow::bail!("Replay check: the local store did not take the nonce (fail-closed)");
        }
        if !check.belongs_to(local) {
            anyhow::bail!("Replay check: the peer check belongs to another request (fail-closed)");
        }
        // The peer stage found the nonce held elsewhere: never run, whatever the caller did
        // with that verdict.
        if check.replay {
            anyhow::bail!("Replay check: the peer stage found a replay (fail-closed)");
        }
        let key = local.key.clone();
        let admission = self.confirm_write_nonce_key(&key, check).await;
        // The tolerated peers get the nonce of a WRITE that runs, and only of one that runs.
        if !check.replicate_to_after.is_empty() && matches!(admission, Ok(WriteAdmission::Run)) {
            if let Some(r) = &self.replicator {
                r.enqueue_to(&key, |i| check.replicate_to_after.contains(&i));
            }
        }
        admission
    }

    async fn confirm_write_nonce_key(
        &self,
        key: &str,
        check: &PeerCheck,
    ) -> anyhow::Result<WriteAdmission> {
        let key = key.to_string();
        let Some(ww) = self.write_wait.as_ref() else {
            // `deferred` is only ever set with the wait on; keep the replication anyway.
            if check.deferred {
                if let Some(r) = &self.replicator {
                    r.enqueue(&key);
                }
            }
            return Ok(WriteAdmission::Run);
        };
        let started = std::time::Instant::now();
        let local = self.wait_local(ww, &key).await;
        crate::health::observe_replay_write_wait(
            &self.network,
            matches!(local, LocalWait::Acked),
            started.elapsed(),
        );
        if let Some(fb) = &self.write_fallback {
            fb.note_generation(self.store_generation_of(ww));
        }
        if check.hub_needs_local_ack {
            let path = if check.hub_unavailable {
                "hub_unavailable"
            } else {
                "hub_short_ack"
            };
            // Without any hub verdict only the local store decides (refused earlier, in
            // hub_unavailable_fallback; kept here so that no caller can skip it).
            if check.hub_unavailable && !check.one_sided {
                return Err(self.refuse_one_sided(path, "the hub gave no verdict"));
            }
            let record = |result: &str| {
                crate::health::record_replay_write_fallback(&self.network, path, result)
            };
            return match local {
                LocalWait::Acked => match self.hub_fallback.as_ref() {
                    Some(fb) if fb.push_write_back(key.clone()) => {
                        record("accepted");
                        if crate::health::warn_due(&self.network, "hub_local_ack") {
                            warn!(network = %self.network, path, "WRITE replay nonce confirmed by the local replicas (no acknowledged verdict from the hub); written back to the hub later");
                        }
                        self.after_local_ack(&key, check).await
                    }
                    Some(_) => {
                        record("overflow");
                        anyhow::bail!("WRITE replay nonce not acknowledged by the hub replicas, write-back queue full (fail-closed)")
                    }
                    None => anyhow::bail!(
                        "WRITE replay nonce not acknowledged by the hub replicas (fail-closed)"
                    ),
                },
                LocalWait::Short(e) | LocalWait::Unavailable(e) | LocalWait::Failed(e) => {
                    if let Some(fb) = &self.write_fallback {
                        fb.open_window();
                    }
                    record("unacknowledged");
                    Err(e.context(
                        "the hub gave no acknowledged verdict, the local replicas neither",
                    ))
                }
            };
        }
        match local {
            LocalWait::Acked => self.after_local_ack(&key, check).await,
            LocalWait::Failed(e) => Err(e),
            LocalWait::Unavailable(e) if !self.unavailable_fallback => Err(e),
            LocalWait::Unavailable(e) => {
                if let Some(fb) = &self.write_fallback {
                    fb.open_window();
                }
                self.short_ack_fallback(key, check, e, "local_unavailable")
                    .await
            }
            LocalWait::Short(e) => {
                if let Some(fb) = &self.write_fallback {
                    fb.open_window();
                }
                self.short_ack_fallback(key, check, e, "short_ack").await
            }
        }
    }

    /// The local replicas have the nonce. In `failover` mode the deferred replication to the
    /// peers happens now: with a peer fallback (peers that acknowledge on their replicas)
    /// synchronously, with the peers' verdict, on every WRITE (write_fallback.rs, "Check at
    /// the fallback store"); without one asynchronously. A peer that does not answer leaves the
    /// local verdict alone: that runs a WRITE only under `WritePolicy::ONE_SIDED`.
    async fn after_local_ack(
        &self,
        key: &str,
        check: &PeerCheck,
    ) -> anyhow::Result<WriteAdmission> {
        if !check.deferred {
            return Ok(WriteAdmission::Run);
        }
        let peers = self.replay_peers.as_ref();
        let (Some(peers), Some(fb)) = (peers, self.write_fallback.as_ref()) else {
            if let Some(r) = &self.replicator {
                r.enqueue(key);
            }
            return Ok(WriteAdmission::Run);
        };
        // The label tells a check inside the window (after startup or a local store failover)
        // from the steady state; both are decided the same way.
        let path = if fb.window_open() { "window" } else { "check" };
        let outcomes = if check.one_sided {
            peers.write_nonce(key, REPLAY_TTL_SECS).await
        } else {
            peers.write_nonce_retrying(key, REPLAY_TTL_SECS).await
        };
        let verdict = combine_peer_outcomes(&outcomes);
        if verdict == PeerVerdict::Unavailable && !check.one_sided {
            return Err(
                self.refuse_one_sided(path, format!("a peer store gave no verdict: {outcomes:?}"))
            );
        }
        let result = match verdict {
            PeerVerdict::Fresh => "accepted",
            PeerVerdict::Replay => "replay",
            PeerVerdict::Unavailable => "unavailable",
        };
        crate::health::record_replay_write_fallback(&self.network, path, result);
        Ok(match verdict {
            PeerVerdict::Replay => WriteAdmission::Replay,
            PeerVerdict::Fresh => WriteAdmission::Run,
            PeerVerdict::Unavailable => {
                // The local verdict stands (a one-sided route); the peers that did not take
                // the nonce get it asynchronously.
                if let Some(r) = &self.replicator {
                    r.enqueue_to(key, |i| outcomes.get(i) != Some(&PeerOutcome::Fresh));
                }
                WriteAdmission::Run
            }
        })
    }

    /// The local replica acknowledgement was short (the nonce is on the local primary only), or
    /// with REPLAY_UNAVAILABLE_FALLBACK the local store did not answer the wait (`path`
    /// `local_unavailable`): confirm the WRITE at the peer stores instead, or fail closed with
    /// `e`.
    async fn short_ack_fallback(
        &self,
        key: String,
        check: &PeerCheck,
        e: anyhow::Error,
        path: &'static str,
    ) -> anyhow::Result<WriteAdmission> {
        // No peer store that can acknowledge on its replicas: as without the fallback.
        let (Some(peers), Some(fb)) = (
            self.replay_peers.as_ref().filter(|p| p.wait().is_some()),
            self.write_fallback.as_ref(),
        ) else {
            return Err(e);
        };
        // sync mode: check_replay asked the peers but its outcomes are not kept; unchanged.
        if peers.mode() == ReplayPeerMode::Sync {
            return Err(e);
        }
        let record = |result: &str| {
            if path == "local_unavailable" {
                self.note_local_unavailable(result);
            }
            crate::health::record_replay_write_fallback(&self.network, path, result)
        };
        if !fb.has_room() {
            record("overflow");
            return Err(e.context("write-back queue full, no peer fallback"));
        }
        if !check.durable_at_peers {
            if !check.deferred {
                // async-reads / sync: the peers were asked already and did not all take and
                // acknowledge the nonce (unreachable, tolerated by the policy).
                record("unavailable");
                return Err(e.context("not every peer store took and acknowledged the nonce"));
            }
            let outcomes = peers.write_nonce_retrying(&key, REPLAY_TTL_SECS).await;
            match combine_peer_outcomes(&outcomes) {
                PeerVerdict::Replay => {
                    record("replay");
                    return Ok(WriteAdmission::Replay);
                }
                PeerVerdict::Unavailable => {
                    record("unavailable");
                    return Err(e.context(format!("peer fallback unavailable: {outcomes:?}")));
                }
                PeerVerdict::Fresh => {}
            }
            if let Err(pe) = peers.confirm_replicated(&key, |_| true).await {
                record("unacknowledged");
                return Err(e.context(format!("peer fallback: {pe}")));
            }
        }
        if !fb.push_write_back(key) {
            record("overflow");
            return Err(e.context("write-back queue full, no peer fallback"));
        }
        record("accepted");
        if crate::health::warn_due(&self.network, "short_ack_fallback") {
            warn!(
                network = %self.network,
                path,
                reason = %redact_addrs(&e),
                "WRITE replay nonce confirmed at the peer stores (no acknowledged local verdict); written back locally later"
            );
        }
        Ok(WriteAdmission::Run)
    }

    /// REPLAY_UNAVAILABLE_FALLBACK (write_fallback.rs, "Unavailable store"). Off by default:
    /// every gateway that checks at the same stores must run a version that checks every WRITE
    /// at the fallback store before any of them turns this on.
    pub fn with_unavailable_fallback(mut self, on: bool) -> Self {
        self.unavailable_fallback = on;
        self
    }

    /// `REPLAY_FALLBACK_HEALTH_FAILURES` / `REPLAY_FALLBACK_HEALTH_WINDOW_SECS` (`FallbackHealth`).
    pub fn with_fallback_health(mut self, health: FallbackHealth) -> Self {
        self.fallback_health = Arc::new(health);
        self
    }

    /// Whether WRITEs decided at the peers for an unreachable local store keep failing closed
    /// (`FallbackHealth::failing`): `/healthz` no longer counts on the fallback then.
    pub fn fallback_writes_failing(&self) -> bool {
        self.fallback_health.failing()
    }

    /// Count the outcome of a WRITE decided at the peers because the local store gave no
    /// verdict (`path="local_unavailable"`) for `FallbackHealth`.
    fn note_local_unavailable(&self, result: &str) {
        match result {
            "accepted" => self.fallback_health.accepted(),
            "unacknowledged" | "unavailable" | "overflow" => self.fallback_health.failed(),
            _ => {}
        }
    }

    /// Where the unavailable fallback confirms a WRITE on this origin, for the startup log and
    /// `ohttp_replay_unavailable_fallback`: `local` (the local store is the one that decides; a
    /// `failover`-mode origin with peers that acknowledge), `standby` (a read origin's hub:
    /// confirmed at its standby stores), `local_replicas` (the hub of an origin with its own
    /// replica wait), or None (off, or nothing to confirm at).
    pub fn unavailable_fallback_target(&self) -> Option<&'static str> {
        if !self.unavailable_fallback {
            return None;
        }
        let peers = self.replay_peers.as_ref()?;
        match peers.mode() {
            ReplayPeerMode::Failover if peers.wait().is_some() && self.write_fallback.is_some() => {
                Some("local")
            }
            ReplayPeerMode::AsyncReads
                if peers.fail_closed_writes() && self.hub_fallback.is_some() =>
            {
                if self.confirming_standby().is_some() {
                    Some("standby")
                } else if self.write_wait.is_some() {
                    Some("local_replicas")
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Whether every WRITE this gateway admits is also `SET NX` synchronously at a fallback store
    /// (write_fallback.rs, "Check at the fallback store"): `failover` mode with the peer fallback
    /// (peers that acknowledge, `REPLAY_WRITE_WAIT_REPLICAS`), or `async-reads` with standby
    /// stores that acknowledge; an `async-reads` origin with its own replica wait and no standby
    /// stores counts its own store as the fallback store (it is asked first, on every request).
    /// `ohttp_replay_fallback_check`: the unavailable fallback is safe only once this is true on
    /// every gateway of the network that has peers.
    pub fn checks_writes_at_fallback_store(&self) -> bool {
        let Some(peers) = self.replay_peers.as_ref() else {
            return false;
        };
        match peers.mode() {
            ReplayPeerMode::Failover => self.write_fallback.is_some(),
            ReplayPeerMode::AsyncReads => {
                self.hub_fallback.is_some()
                    && (self.confirming_standby().is_some()
                        || (self.write_wait.is_some() && self.standby_peers.is_none()))
            }
            ReplayPeerMode::Sync => false,
        }
    }

    /// Whether the peer stores can decide a request the local store gives no verdict on
    /// (`admit_without_local`), with REPLAY_UNAVAILABLE_FALLBACK, peers that acknowledge on their
    /// replicas and the local write-back queue (`REPLAY_WRITE_WAIT_REPLICAS`):
    ///
    /// - `failover` (the fallback target `local`): the peers are the fallback store.
    /// - `async-reads` without standby stores (the standby origin and its spoke): the local store
    ///   is the fallback store and the peer is the hub, which already decides every WRITE here.
    ///   With standby stores (a read origin) the local store is neither, and nothing changes.
    pub fn decides_at_peers_without_local(&self) -> bool {
        if !self.unavailable_fallback || self.write_fallback.is_none() {
            return false;
        }
        let Some(peers) = self.replay_peers.as_ref().filter(|p| p.wait().is_some()) else {
            return false;
        };
        match peers.mode() {
            ReplayPeerMode::Failover => true,
            ReplayPeerMode::AsyncReads => {
                self.standby_peers.is_none() && self.hub_fallback.is_some()
            }
            ReplayPeerMode::Sync => false,
        }
    }

    /// Whether a request whose local `SET NX` gave no verdict can still be decided at the peer
    /// stores (`admit_without_local`): `decides_at_peers_without_local` and a peer is connected
    /// right now (else the request fails closed at once, as before).
    fn local_unavailable_fallback_ready(&self) -> bool {
        self.decides_at_peers_without_local()
            && self
                .replay_peers
                .as_ref()
                .is_some_and(|p| p.any_connected())
    }

    /// Whether this origin can serve while its local store does not answer: the peer stores
    /// decide in its place (`decides_at_peers_without_local`), every WRITE is also checked at
    /// the fallback store while the local store answers, and every peer answered its last
    /// housekeeping PING. `/healthz` stays healthy on this alone
    /// (`ohttp_replay_serving_via_fallback`); with no peer answering it fails, as before.
    ///
    /// Also not while the WRITEs decided that way keep failing closed although the peers answer
    /// their PINGs (`FallbackHealth`: a peer short of replicas, a full write-back queue, a broken
    /// peer `WAIT` connection): a load balancer then sends the requests elsewhere. READs that
    /// still reach this gateway are decided at the peers as before.
    pub fn serves_without_local_store(&self) -> bool {
        self.decides_at_peers_without_local()
            && self.checks_writes_at_fallback_store()
            && self
                .replay_peers
                .as_ref()
                .is_some_and(|p| p.all_answering())
            && !self.fallback_health.failing()
    }

    /// The local store gave no verdict on this request's nonce (`LocalReplayCheck::Unavailable`):
    /// decide it at the peer stores alone, which then are the single point of confirmation. In
    /// `failover` mode these are the fallback store; in `async-reads` (an origin whose own store
    /// is the fallback store) the hub, the store every WRITE here is decided at anyway.
    ///
    /// - READ: `SET NX` at every peer; new everywhere = runs, held anywhere = replay, a peer that
    ///   does not answer = fail-closed.
    /// - WRITE: the same, then the peers' own replica wait (`REPLAY_PEER_WAIT_REPLICAS`); only a
    ///   nonce that every peer took as new and acknowledged runs, and it is written back to the
    ///   local store until the local replicas have it.
    ///
    /// `Err` = fail-closed (inner 503 / grpc-status 14). Only the peer stores decide here, so a
    /// WRITE under `WritePolicy::BOTH_STORES` always fails closed (`path="local_unavailable"`,
    /// `result="one_sided_refused"`); READs are decided as above whatever `policy` says.
    pub async fn admit_without_local(
        &self,
        local: &LocalCheck,
        class: RouteClass,
        policy: WritePolicy,
    ) -> anyhow::Result<PeerCheck> {
        let check = match self.admit_without_local_inner(local, class, policy).await? {
            WriteAdmission::Run => PeerCheck {
                local_bypassed: true,
                ..PeerCheck::blank()
            },
            WriteAdmission::Replay => PeerCheck {
                replay: true,
                ..PeerCheck::blank()
            },
        };
        Ok(check.bound_to(local))
    }

    async fn admit_without_local_inner(
        &self,
        local: &LocalCheck,
        class: RouteClass,
        policy: WritePolicy,
    ) -> anyhow::Result<WriteAdmission> {
        if local.verdict != LocalReplayCheck::Unavailable {
            anyhow::bail!("Replay check: the local store gave a verdict, nothing to decide without it (fail-closed)");
        }
        let key = local.key.clone();
        let (Some(peers), Some(fb), true) = (
            self.replay_peers.as_ref().filter(|p| p.wait().is_some()),
            self.write_fallback.as_ref(),
            self.decides_at_peers_without_local(),
        ) else {
            anyhow::bail!("Replay protection unavailable: no verdict from the local store and no peer store to decide at (fail-closed)");
        };
        fb.open_window();
        if class == RouteClass::Read {
            let outcomes = peers.write_nonce_retrying(&key, REPLAY_TTL_SECS).await;
            let verdict = combine_peer_outcomes(&outcomes);
            crate::health::record_replay_read_fallback(
                &self.network,
                match verdict {
                    PeerVerdict::Fresh => "accepted",
                    PeerVerdict::Replay => "replay",
                    PeerVerdict::Unavailable => "unavailable",
                },
            );
            return match verdict {
                PeerVerdict::Fresh => Ok(WriteAdmission::Run),
                PeerVerdict::Replay => Ok(WriteAdmission::Replay),
                PeerVerdict::Unavailable => anyhow::bail!(
                    "Replay protection unavailable: no verdict from the local store or the peer stores (fail-closed): {outcomes:?}"
                ),
            };
        }
        if !policy.one_sided {
            // The local store gave no verdict: the fallback cannot serve this WRITE, which
            // counts toward withdrawing the gateway (`FallbackHealth`).
            self.fallback_health.failed();
            return Err(
                self.refuse_one_sided("local_unavailable", "no verdict from the local store")
            );
        }
        let record = |result: &str| {
            self.note_local_unavailable(result);
            crate::health::record_replay_write_fallback(&self.network, "local_unavailable", result)
        };
        if !fb.has_room() {
            record("overflow");
            anyhow::bail!("Replay protection unavailable: no verdict from the local store, write-back queue full (fail-closed)");
        }
        let outcomes = peers.write_nonce_retrying(&key, REPLAY_TTL_SECS).await;
        match combine_peer_outcomes(&outcomes) {
            PeerVerdict::Replay => {
                record("replay");
                return Ok(WriteAdmission::Replay);
            }
            PeerVerdict::Unavailable => {
                record("unavailable");
                anyhow::bail!("Replay protection unavailable: no verdict from the local store or the peer stores (fail-closed): {outcomes:?}");
            }
            PeerVerdict::Fresh => {}
        }
        if let Err(e) = peers.confirm_replicated(&key, |_| true).await {
            record("unacknowledged");
            return Err(e.context("no verdict from the local store"));
        }
        if !fb.push_write_back(key) {
            record("overflow");
            anyhow::bail!("Replay protection unavailable: no verdict from the local store, write-back queue full (fail-closed)");
        }
        record("accepted");
        if crate::health::warn_due(&self.network, "local_unavailable_fallback") {
            warn!(network = %self.network, "WRITE replay nonce confirmed at the peer stores (no verdict from the local store); written back locally later");
        }
        Ok(WriteAdmission::Run)
    }

    /// REPLAY_LOCAL_WAITAOF_MS (`LocalAofConfig`) on a dedicated connection to `security_url`.
    /// The store is probed with `WAITAOF 1 0 1`: its refusal (AOF off, Redis < 7.2) leaves it
    /// off in `Auto` and fails startup in `Required`; a timeout or a connection error fails
    /// startup in both.
    pub async fn with_local_waitaof(
        mut self,
        security_url: &str,
        config: LocalAofConfig,
    ) -> anyhow::Result<Self> {
        let (timeout_ms, required) = match config {
            LocalAofConfig::Off => return Ok(self),
            LocalAofConfig::Auto(t) => (t, false),
            LocalAofConfig::Required(t) => (t, true),
        };
        let probe_timeout = self.redis_timeout * 4;
        let probe = async {
            if security_url.is_empty() {
                anyhow::bail!("REDIS_SECURITY_URL not configured");
            }
            let conn = StoreConn::connect(
                security_url,
                "local_aof",
                self.network.clone(),
                Role::Primary,
            )
            .await?;
            let answer = timeout(
                probe_timeout,
                redis::cmd("WAITAOF")
                    .arg(1)
                    .arg(0)
                    .arg(1)
                    .query_async::<_, (i64, i64)>(&mut conn.get()),
            )
            .await
            .map_err(|_| anyhow::anyhow!("WAITAOF probe timed out"))?;
            anyhow::Ok((conn, answer))
        };
        // Only the store's own refusal (AOF off, unknown command) means "unsupported"; a
        // timeout or a connection error fails startup like the security connection itself.
        let probe = match probe.await {
            Ok((conn, Ok(_))) => Ok(conn),
            Ok((_, Err(e)))
                if matches!(
                    e.kind(),
                    redis::ErrorKind::ResponseError | redis::ErrorKind::ExtensionError
                ) =>
            {
                Err(anyhow::Error::from(e))
            }
            Ok((_, Err(e))) => anyhow::bail!(
                "REPLAY_LOCAL_WAITAOF_MS: WAITAOF probe failed: {}",
                store_error(&e)
            ),
            Err(e) => anyhow::bail!(
                "REPLAY_LOCAL_WAITAOF_MS: WAITAOF probe failed: {}",
                error_summary(&e)
            ),
        };
        match probe {
            Ok(conn) => {
                self.local_aof = Some(Arc::new(LocalAof { conn, timeout_ms }));
                Ok(self)
            }
            Err(e) if required => anyhow::bail!(
                "REPLAY_LOCAL_WAITAOF_MS={timeout_ms} but the security Redis cannot WAITAOF (needs Redis >= 7.2 with appendonly yes): {}",
                error_summary(&e)
            ),
            Err(e) => {
                warn!(
                    network = %self.network,
                    error = %error_summary(&e),
                    "Security Redis cannot WAITAOF: WRITE nonces held only locally are not fsync-confirmed"
                );
                Ok(self)
            }
        }
    }

    pub fn local_waitaof_ms(&self) -> Option<u64> {
        self.local_aof.as_ref().map(|l| l.timeout_ms)
    }

    /// For a WRITE whose nonce only the local store holds: rewrite it on the dedicated
    /// connection (`SET XX`) and `WAITAOF 1 0` until the local AOF has fsynced it. Fail-closed:
    /// not fsynced in time, the nonce gone, an error or a timeout is an `Err` (outer 503).
    /// No-op when off.
    pub async fn confirm_nonce_local_aof(&self, key: &str) -> anyhow::Result<()> {
        let Some(la) = self.local_aof.as_ref() else {
            return Ok(());
        };
        let started = std::time::Instant::now();
        let mut conn = la.conn.get();
        let budget = Duration::from_millis(la.timeout_ms) + self.redis_timeout * 2;
        let result = timeout(budget, async {
            redis::pipe()
                .cmd("SET")
                .arg(key)
                .arg("1")
                .arg("XX")
                .arg("EX")
                .arg(REPLAY_TTL_SECS)
                .cmd("WAITAOF")
                .arg(1)
                .arg(0)
                .arg(la.timeout_ms)
                .query_async::<_, (Option<String>, (i64, i64))>(&mut conn)
                .await
        })
        .await;
        la.conn.observe_timed(&result);
        let verdict = match result {
            Ok(Ok((Some(_), (local, _)))) if local >= 1 => Ok(()),
            Ok(Ok((Some(_), _))) => {
                la.conn.observe_short_ack();
                Err(format!("not fsynced within {}ms", la.timeout_ms))
            }
            Ok(Ok((None, _))) => Err("nonce no longer in the local store".to_string()),
            Ok(Err(e)) => Err(store_error(&e)),
            Err(_) => Err(format!("timed out after {}ms", budget.as_millis())),
        };
        crate::health::observe_replay_local_aof(&self.network, verdict.is_ok(), started.elapsed());
        verdict.map_err(|e| {
            anyhow::anyhow!("WRITE replay nonce not fsynced to the local AOF (fail-closed): {e}")
        })
    }

    pub fn with_replay_peers(mut self, peers: ReplayPeers) -> Self {
        let peers = Arc::new(peers);
        if peers.mode() == ReplayPeerMode::AsyncReads
            && peers.wait().is_some()
            && tokio::runtime::Handle::try_current().is_ok()
        {
            let fb = Arc::new(WriteFallback::new(&self.network, peers.disruptions()));
            crate::write_fallback::spawn_write_back(
                fb.clone(),
                Arc::new(PeerWriteBack(peers.clone())),
            );
            self.hub_fallback = Some(fb);
        }
        self.replay_peers = Some(peers);
        self
    }

    pub fn hub_fallback(&self) -> Option<&WriteFallback> {
        self.hub_fallback.as_deref()
    }

    /// Start the asynchronous nonce replication for REPLAY_PEER_MODE=async-reads|failover (a
    /// no-op without peers or in `sync` mode). Must run inside the Tokio runtime.
    pub fn with_async_replication(mut self, cfg: ReplicationConfig) -> Self {
        let Some(peers) = self.replay_peers.clone() else {
            return self;
        };
        if peers.mode() == ReplayPeerMode::Sync {
            return self;
        }
        let cfg = ReplicationConfig {
            mode: peers.mode(),
            network: self.network.clone(),
            ..cfg
        };
        let sink: Arc<dyn PeerSink> = peers;
        self.replicator = Some(Arc::new(AsyncReplicator::start(sink, cfg)));
        self
    }

    pub fn replay_peers(&self) -> Option<&ReplayPeers> {
        self.replay_peers.as_deref()
    }

    pub fn replicator(&self) -> Option<&AsyncReplicator> {
        self.replicator.as_deref()
    }

    /// REPLAY_STANDBY_URLS: replicate every admitted WRITE nonce to the standby stores
    /// (`replicate_write_to_standby`), with the `failover` mechanism (queue per store,
    /// pipelined batches, retried until the nonce TTL, never on the request path). A no-op
    /// without stores. Must run inside the Tokio runtime.
    pub fn with_standby_replication(mut self, peers: ReplayPeers, cfg: ReplicationConfig) -> Self {
        if peers.is_empty() {
            return self;
        }
        let cfg = ReplicationConfig {
            network: self.network.clone(),
            ..cfg
        }
        .for_standby(peers.first_label());
        let peers = Arc::new(peers);
        let sink: Arc<dyn PeerSink> = peers.clone();
        self.standby_replicator = Some(Arc::new(AsyncReplicator::start(sink, cfg)));
        self.standby_peers = Some(peers);
        self
    }

    pub fn standby_replicator(&self) -> Option<&AsyncReplicator> {
        self.standby_replicator.as_deref()
    }

    /// A WRITE that passed every replay check and is about to run: hand its nonce to the
    /// standby stores (REPLAY_STANDBY_URLS). Never blocks, never fails the request: a standby
    /// store that is unreachable gets the nonce when it is back, until the nonce TTL.
    ///
    /// This is what keeps a standby origin, which admits WRITEs on its own store while the
    /// shared store is unreachable, from admitting a WRITE that this origin already ran: this
    /// origin's WRITE check went to the shared store, whose owner replicates only its own
    /// requests to the standby.
    ///
    /// `check` is the request's peer stage: a WRITE it already confirmed at the standby stores
    /// is not handed over again. A `check` of another request is ignored (the nonce of `local`
    /// is handed over).
    pub fn replicate_write_to_standby(&self, local: &LocalCheck, check: PeerCheck) {
        if check.belongs_to(local) && check.at_standby {
            return;
        }
        if let Some(r) = &self.standby_replicator {
            r.enqueue(&local.key);
        }
    }

    /// The replay peer mode in force (`sync` without peers).
    pub fn replay_peer_mode(&self) -> ReplayPeerMode {
        self.replay_peers
            .as_ref()
            .map(|p| p.mode())
            .unwrap_or(ReplayPeerMode::Sync)
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    fn pinned_key(&self, height: u64) -> String {
        format!(
            "pinned:{}:{}:treestate:v1:{}",
            self.network, self.backend_host, height
        )
    }

    fn pinned_cursor_key(&self) -> String {
        format!(
            "pinned:{}:{}:treestate:v1:backfill_cursor",
            self.network, self.backend_host
        )
    }

    /// The next height the sweep checks (`pinned_sweep_pass`), shared by every gateway like
    /// the cursor.
    fn pinned_verified_key(&self) -> String {
        format!(
            "pinned:{}:{}:treestate:v1:backfill_verified",
            self.network, self.backend_host
        )
    }

    /// The heights the sweep could not fill (a set), retried by later passes.
    fn pinned_holes_key(&self) -> String {
        format!(
            "pinned:{}:{}:treestate:v1:backfill_holes",
            self.network, self.backend_host
        )
    }

    /// One process's claim of the retries of the holes.
    fn pinned_sweep_claim_key_holes(&self) -> String {
        format!(
            "pinned:{}:{}:treestate:v1:backfill_sweep:holes",
            self.network, self.backend_host
        )
    }

    /// The failed retries per hole (a hash), for PINNED_SWEEP_HOLE_ATTEMPTS.
    fn pinned_hole_attempts_key(&self) -> String {
        format!(
            "pinned:{}:{}:treestate:v1:backfill_hole_attempts",
            self.network, self.backend_host
        )
    }

    /// One process's claim of the sweep batch that starts at `from` (`sweep_batch_of`).
    fn pinned_sweep_claim_key(&self, from: u64) -> String {
        format!(
            "pinned:{}:{}:treestate:v1:backfill_sweep:{from}",
            self.network, self.backend_host
        )
    }

    /// Height of a height-only GetTreeState request inside the pinned range, if any. Heights
    /// within FINALIZED_DEPTH of a fresh tip are left out: `pinned_put` never writes them, so
    /// a lookup could only miss (they are answered by the chain-validated cache). Without a
    /// fresh tip every height in the range is looked up.
    fn pinned_height(&self, method: &str, path: &str, body: &[u8]) -> Option<u64> {
        let (start, end) = self.pinned_range?;
        self.pinned_conn.as_ref()?;
        if method != "POST" || path != GET_TREE_STATE_PATH {
            return None;
        }
        let id: BlockId = prost::Message::decode(grpc_message(body)?).ok()?;
        if !id.hash.is_empty() || id.height < start || id.height > end {
            return None;
        }
        if let Some(tip) = self.tip.get() {
            if tip.height.saturating_sub(id.height) <= FINALIZED_DEPTH {
                return None;
            }
        }
        Some(id.height)
    }

    fn unix_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Connect REDIS_PINNED_WRITE_URL in the background (it was unreachable at startup); once
    /// connected, pinned writes and the pinned backfill use it. The read-only pause, which was
    /// about the pinned store, is lifted: the new store is asked (`ROLE`) on its next use, as
    /// after a pause.
    fn spawn_pinned_write_reconnect(&self, url: String) {
        let cache = self.clone();
        let network = self.network.clone();
        tokio::spawn(async move {
            let mut backoff = Duration::from_secs(1);
            loop {
                tokio::time::sleep(backoff).await;
                match StoreConn::connect(&url, "pinned_write", network.clone(), Role::Any).await {
                    Ok(c) => {
                        cache.publish_pinned_write_conn(c);
                        info!(network = %network, "pinned write store connected");
                        return;
                    }
                    Err(e) => {
                        debug!(network = %network, error = %error_summary(&e), "pinned write store still unreachable");
                        backoff = (backoff * 2).min(Duration::from_secs(60));
                    }
                }
            }
        });
    }

    /// Make `conn` the store pinned entries are written to, asked (`ROLE`) on its next use
    /// (`pinned_writer_bound` probes a store whose pause is over): the pause, the connection
    /// and the generation change in one step (`pinned_writer_lock`), so no caller can use the
    /// new store unasked, and a probe of the previous store that was in flight neither lifts
    /// nor replaces the new store's pause.
    fn publish_pinned_write_conn(&self, conn: Arc<StoreConn>) {
        let _state = self.pinned_writer_lock.lock();
        self.pinned_read_only_until.store(1, Ordering::SeqCst);
        self.pinned_write_conn.store(Some(conn));
        self.pinned_writer_gen.fetch_add(1, Ordering::SeqCst);
    }

    /// The store pinned entries are written to now, whatever its pause.
    fn pinned_write_target(&self) -> Option<Arc<StoreConn>> {
        self.pinned_write_conn
            .load_full()
            .or_else(|| self.pinned_conn.clone())
    }

    /// Whether `conn`, chosen in `generation`, is still the store pinned entries go to. Only
    /// meaningful under `pinned_writer_lock`.
    fn pinned_selection_is(&self, conn: &Arc<StoreConn>, generation: u64) -> bool {
        self.pinned_writer_gen.load(Ordering::SeqCst) == generation
            && self
                .pinned_write_target()
                .is_some_and(|now| Arc::ptr_eq(&now, conn))
    }

    /// Skip pinned writes for PINNED_READ_ONLY_RECHECK. Returns true when they were not skipped
    /// before (the caller logs the change once).
    #[cfg(test)]
    fn mark_pinned_read_only(&self) -> bool {
        self.mark_pinned_read_only_for(PINNED_READ_ONLY_RECHECK)
    }

    /// Skip pinned writes for `pause`, then ask the store again.
    #[cfg(test)]
    fn mark_pinned_read_only_for(&self, pause: Duration) -> bool {
        let _state = self.pinned_writer_lock.lock();
        self.pause_pinned_writes(pause)
    }

    /// `mark_pinned_read_only_for` on behalf of `conn`, chosen in `generation` (a
    /// `ROLE` probe of it, or a read-only answer to a write through it): only while it is still
    /// the store pinned entries go to. An answer of a store that was replaced meanwhile says
    /// nothing about the one chosen now, whose pause stays as it is.
    fn mark_pinned_read_only_of(
        &self,
        conn: &Arc<StoreConn>,
        generation: u64,
        pause: Duration,
    ) -> bool {
        let _state = self.pinned_writer_lock.lock();
        self.pinned_selection_is(conn, generation) && self.pause_pinned_writes(pause)
    }

    /// Under `pinned_writer_lock`: set the pause; the generation moves when writes were on.
    fn pause_pinned_writes(&self, pause: Duration) -> bool {
        let until = Self::unix_ms() + pause.as_millis() as u64;
        let changed = self.pinned_read_only_until.swap(until, Ordering::SeqCst) == 0;
        if changed {
            self.pinned_writer_gen.fetch_add(1, Ordering::SeqCst);
        }
        changed
    }

    /// Ask `conn`, chosen in `generation`, for its `ROLE`. A primary, or a store without `ROLE`
    /// (an error answer), is writable: true. A replica turns pinned writes off for
    /// PINNED_READ_ONLY_RECHECK; no answer in time or a connection error for PINNED_PROBE_RETRY
    /// (asked again then): false. The pause is set only while `conn` is still the store chosen
    /// (`mark_pinned_read_only_of`).
    async fn probe_pinned_writer(&self, conn: &Arc<StoreConn>, generation: u64) -> bool {
        let answer = timeout(
            self.pinned_write_timeout(),
            redis::cmd("ROLE").query_async::<_, redis::Value>(&mut conn.get()),
        )
        .await;
        conn.observe_timed(&answer);
        #[cfg(test)]
        test_hooks::probe_answered(&self.network).await;
        match answer {
            Ok(Ok(v)) if crate::store_conn::parse_role(&v) == Some(false) => {
                self.mark_pinned_read_only_of(conn, generation, PINNED_READ_ONLY_RECHECK);
                false
            }
            Ok(Ok(_)) => true,
            Ok(Err(e)) if e.kind() == redis::ErrorKind::ResponseError => true,
            Ok(Err(e)) => {
                debug!(network = %self.network, error = %store_error(&e), "pinned store ROLE failed");
                self.mark_pinned_read_only_of(conn, generation, PINNED_PROBE_RETRY);
                false
            }
            Err(_) => {
                self.mark_pinned_read_only_of(conn, generation, PINNED_PROBE_RETRY);
                false
            }
        }
    }

    /// The store pinned entries are written to: REDIS_PINNED_WRITE_URL's when set, else the
    /// pinned store. None while that store is known to be a read replica (or did not answer its
    /// `ROLE`): its writes would only fail. After the pause the store is asked again (`ROLE`),
    /// so a replica that was promoted is written to again.
    #[cfg(test)]
    async fn pinned_writer(&self) -> Option<Arc<StoreConn>> {
        self.pinned_writer_bound().await.map(|w| w.conn)
    }

    /// The store pinned entries are written to (REDIS_PINNED_WRITE_URL's when set, else the
    /// pinned store), bound to the generation it was chosen in (`pinned_writer_gen`). None
    /// while that store is known to be a read replica (or did not answer its `ROLE`): its
    /// writes would only fail. After the pause the store is asked again (`ROLE`), so a replica
    /// that was promoted is written to again.
    ///
    /// A `ROLE` probe acts only on the selection it was made for: its answer lifts the pause
    /// (or sets one, see `probe_pinned_writer`) in one step with the check that the generation,
    /// the store chosen and the pause are still those the probe started with
    /// (`pinned_writer_lock`). The pause of a store connected meanwhile is neither lifted nor
    /// replaced by a probe of the previous one. Callers that asked the same store at the same
    /// time all get it: the first answer lifts the pause, and the others find the store they
    /// asked chosen and writable.
    async fn pinned_writer_bound(&self) -> Option<PinnedWriter> {
        let (before, conn, until) = {
            let _state = self.pinned_writer_lock.lock();
            (
                self.pinned_writer_gen.load(Ordering::SeqCst),
                self.pinned_write_target()?,
                self.pinned_read_only_until.load(Ordering::SeqCst),
            )
        };
        if until != 0 && (Self::unix_ms() < until || !self.probe_pinned_writer(&conn, before).await)
        {
            return None;
        }
        let _state = self.pinned_writer_lock.lock();
        if !self.pinned_selection_is(&conn, before) {
            // The generation moved meanwhile. The store asked is still the one chosen and
            // takes writes (another caller's probe of it lifted the pause): use it, in the
            // generation of now. Another store, or a pause in place: not this time.
            let still_chosen = self
                .pinned_write_target()
                .is_some_and(|now| Arc::ptr_eq(&now, &conn));
            if !still_chosen || self.pinned_read_only_until.load(Ordering::SeqCst) != 0 {
                return None;
            }
            let generation = self.pinned_writer_gen.load(Ordering::SeqCst);
            return Some(PinnedWriter { conn, generation });
        }
        if until != 0 {
            if self.pinned_read_only_until.load(Ordering::SeqCst) != until {
                return None;
            }
            // Between the checks above and the lift, under the lock (tests only).
            #[cfg(test)]
            test_hooks::pause_lift(&self.network);
            self.pinned_read_only_until.store(0, Ordering::SeqCst);
            self.pinned_writer_gen.fetch_add(1, Ordering::SeqCst);
            info!(network = %self.network, "pinned store accepts writes again");
        }
        let generation = self.pinned_writer_gen.load(Ordering::SeqCst);
        Some(PinnedWriter { conn, generation })
    }

    /// Whether `writer` is still the store pinned entries go to (its generation is current).
    fn pinned_writer_current(&self, writer: &PinnedWriter) -> bool {
        self.pinned_writer_gen.load(Ordering::SeqCst) == writer.generation
    }

    /// Operation timeout of pinned writes: at least PINNED_REMOTE_WRITE_TIMEOUT on a separate
    /// write store.
    fn pinned_write_timeout(&self) -> Duration {
        if self.pinned_write_conn.load().is_some() {
            self.redis_timeout.max(PINNED_REMOTE_WRITE_TIMEOUT)
        } else {
            self.redis_timeout
        }
    }

    /// Operation timeout of the backfill cursor and the sweep's commands, on the store the
    /// entries are written to: four store timeouts, and at least the write timeout
    /// (`pinned_write_timeout`) of a separate write store.
    fn pinned_cursor_timeout(&self) -> Duration {
        (self.redis_timeout * 4).max(self.pinned_write_timeout())
    }

    /// `INCR` or `DECR` of the backfill cursor on `conn`, bounded by `pinned_cursor_timeout`.
    async fn pinned_cursor_step(
        &self,
        conn: &Arc<StoreConn>,
        cmd: &'static str,
    ) -> Result<redis::RedisResult<i64>, tokio::time::error::Elapsed> {
        let r = timeout(
            self.pinned_cursor_timeout(),
            redis::cmd(cmd)
                .arg(self.pinned_cursor_key())
                .query_async::<_, i64>(&mut conn.get()),
        )
        .await;
        conn.observe_timed(&r);
        r
    }

    /// Move the backfill cursor up to `to` (never down) on `conn`: heights below
    /// `pinned_fill_from` are skipped in one step instead of being claimed one by one. False
    /// when the store did not confirm it: the worker then skips them one by one and tries the
    /// step again before its next claim.
    async fn pinned_cursor_skip_to(&self, conn: &Arc<StoreConn>, to: u64) -> bool {
        let script = redis::Script::new(
            r"local cur = tonumber(redis.call('GET', KEYS[1]) or '0')
              if cur < tonumber(ARGV[1]) then redis.call('SET', KEYS[1], ARGV[1]) end
              return 1",
        );
        let r = timeout(
            self.pinned_cursor_timeout(),
            script
                .key(self.pinned_cursor_key())
                .arg(to)
                .invoke_async::<_, i64>(&mut conn.get()),
        )
        .await;
        conn.observe_timed(&r);
        matches!(r, Ok(Ok(_)))
    }

    async fn pinned_get(&self, height: u64) -> Option<Vec<u8>> {
        let pinned = self.pinned_conn.as_ref()?;
        let r = timeout(
            self.redis_timeout,
            pinned.get().get::<_, Vec<u8>>(self.pinned_key(height)),
        )
        .await;
        pinned.observe_timed(&r);
        match r {
            Ok(Ok(v)) if !v.is_empty() => Some(v),
            Ok(Ok(_)) => None,
            Ok(Err(e)) => {
                if crate::health::warn_due(&self.network, "pinned_get") {
                    warn!(network = %self.network, height, error = %store_error(&e), "pinned get error");
                }
                crate::health::record_cache_redis_timeout(&self.network, "pinned_get_error");
                None
            }
            Err(_) => {
                crate::health::record_cache_redis_timeout(&self.network, "pinned_get_timeout");
                None
            }
        }
    }

    /// `pinned_exists` on `conn` (the store the entries are written to), bounded like the
    /// write it guards (`pinned_write_timeout`): a slow answer of a remote write store is not
    /// taken for a missing entry.
    async fn pinned_exists_at(&self, conn: &Arc<StoreConn>, height: u64) -> bool {
        let r = timeout(
            self.pinned_write_timeout(),
            conn.get().exists::<_, bool>(self.pinned_key(height)),
        )
        .await;
        conn.observe_timed(&r);
        matches!(r, Ok(Ok(true)))
    }

    #[cfg(test)]
    async fn pinned_exists(&self, height: u64) -> bool {
        let Some(pinned) = self.pinned_conn.as_ref() else {
            return false;
        };
        let r = timeout(
            self.redis_timeout,
            pinned.get().exists::<_, bool>(self.pinned_key(height)),
        )
        .await;
        pinned.observe_timed(&r);
        matches!(r, Ok(Ok(true)))
    }

    /// True if `response` is a successful GetTreeState answer for exactly `height`.
    fn is_tree_state_for(response: &[u8], height: u64) -> bool {
        if !rpc_cache::should_admit(response, true) {
            return false;
        }
        let Ok(resp) = bincode::deserialize::<crate::ohttp::InnerResponse>(response) else {
            return false;
        };
        let Some(msg) = grpc_message(&resp.body) else {
            return false;
        };
        match prost::Message::decode(msg) {
            Ok(ts) => {
                let ts: TreeStateHead = ts;
                ts.height == height
            }
            Err(_) => false,
        }
    }

    /// Whether `response` may be stored as the pinned entry of `height`: only finalized heights
    /// (depth > FINALIZED_DEPTH against a fresh tip) and only responses that decode to a
    /// TreeState for the same height.
    fn pinned_admissible(&self, height: u64, response: &[u8]) -> bool {
        if self.pinned_conn.is_none() {
            return false;
        }
        let tip = self.tip_height();
        if tip == 0 || tip.saturating_sub(height) <= FINALIZED_DEPTH {
            return false;
        }
        Self::is_tree_state_for(response, height)
    }

    /// Store a pinned entry (see [`Self::pinned_admissible`]). SET NX, no TTL. Written to
    /// `pinned_writer`; nothing while that is a read replica.
    async fn pinned_put(&self, height: u64, response: &[u8]) -> bool {
        if !self.pinned_admissible(height, response) {
            return false;
        }
        let Some(writer) = self.pinned_writer_bound().await else {
            return false;
        };
        self.pinned_set(&writer, height, response).await == Some(true)
    }

    /// [`Self::pinned_put`] through `writer`, the store the caller chose (the backfill and the
    /// sweep, whose cursor and checks are on it): None, and nothing sent, once another store
    /// was chosen since (its generation moved on).
    async fn pinned_put_bound(
        &self,
        writer: &PinnedWriter,
        height: u64,
        response: &[u8],
    ) -> Option<bool> {
        if !self.pinned_admissible(height, response) {
            return Some(false);
        }
        self.pinned_set(writer, height, response).await
    }

    /// The `SET NX` of a pinned entry on `writer`, only while its generation is current (None
    /// otherwise, nothing sent); whether it is stored.
    async fn pinned_set(
        &self,
        writer: &PinnedWriter,
        height: u64,
        response: &[u8],
    ) -> Option<bool> {
        if !self.pinned_writer_current(writer) {
            return None;
        }
        let pinned = &writer.conn;
        let res = timeout(
            self.pinned_write_timeout(),
            redis::cmd("SET")
                .arg(self.pinned_key(height))
                .arg(response)
                .arg("NX")
                .query_async::<_, Option<String>>(&mut pinned.get()),
        )
        .await;
        pinned.observe_timed(&res);
        Some(match res {
            Ok(Ok(_)) => true,
            Ok(Err(e)) if e.kind() == redis::ErrorKind::ReadOnly => {
                if self.mark_pinned_read_only_of(
                    &writer.conn,
                    writer.generation,
                    PINNED_READ_ONLY_RECHECK,
                ) {
                    info!(network = %self.network, "pinned store is a read replica, pinned entries are not written");
                }
                false
            }
            Ok(Err(e)) => {
                if crate::health::warn_due(&self.network, "pinned_set") {
                    warn!(network = %self.network, height, error = %store_error(&e), "pinned set error");
                }
                crate::health::record_cache_redis_timeout(&self.network, "pinned_set_error");
                false
            }
            Err(_) => {
                crate::health::record_cache_redis_timeout(&self.network, "pinned_set_timeout");
                false
            }
        })
    }

    /// The follower's tip height, 0 when unknown or stale.
    pub fn tip_height(&self) -> u64 {
        self.tip.get().map(|t| t.height).unwrap_or(0)
    }

    /// Whether a fresh tip is known.
    pub fn is_tip_fresh(&self) -> bool {
        self.tip.get().is_some()
    }

    /// Actual Redis PING check (cache, and security when configured). Updates
    /// `ohttp_cache_redis_connected`, the store and peer connectivity gauges and
    /// `ohttp_replay_serving_via_fallback`. Run by the housekeeping task every
    /// `HOUSEKEEPING_SECS`; public so tests can run one round.
    pub async fn ping_redis(&self) -> bool {
        self.ping_redis_until(tokio::time::Instant::now() + HOUSEKEEPING_DEADLINE)
            .await
    }

    /// One housekeeping round (`spawn_redis_housekeeping`): the epoch sync and every check of
    /// `ping_redis`, all at once, under one deadline (`HOUSEKEEPING_DEADLINE`).
    pub async fn housekeeping_round(&self) -> bool {
        let deadline = tokio::time::Instant::now() + HOUSEKEEPING_DEADLINE;
        let epoch = async {
            self.sync_epoch_until(deadline).await;
            if tokio::time::Instant::now() >= deadline
                && crate::health::warn_due(&self.network, "epoch_sync")
            {
                warn!(network = %self.network, "Shared epoch sync did not finish within the housekeeping deadline");
            }
        };
        let ((), ok) = tokio::join!(epoch, self.ping_redis_until(deadline));
        ok
    }

    /// `ping_redis` under `deadline`: a check not done by then counts as failed.
    async fn ping_redis_until(&self, deadline: tokio::time::Instant) -> bool {
        // Started together with every other check of the round (below).
        let cache = async {
            let Some(cache_conn) = self.cache_conn.load_full() else {
                return false;
            };
            let mut cache_conn = (*cache_conn).clone();
            let bound = deadline.min(tokio::time::Instant::now() + self.redis_timeout);
            match tokio::time::timeout_at(
                bound,
                redis::cmd("PING").query_async::<_, String>(&mut cache_conn),
            )
            .await
            {
                Ok(Ok(resp)) if resp == "PONG" => true,
                Ok(Ok(_)) => {
                    if crate::health::warn_due(&self.network, "cache_ping") {
                        warn!(network = %self.network, "Redis PING returned unexpected response");
                    }
                    false
                }
                Ok(Err(e)) => {
                    if crate::health::warn_due(&self.network, "cache_ping") {
                        warn!(network = %self.network, error = %store_error(&e), "Redis PING failed");
                    }
                    false
                }
                Err(_) => {
                    if crate::health::warn_due(&self.network, "cache_ping") {
                        warn!(network = %self.network, "Redis PING timeout");
                    }
                    false
                }
            }
        };
        // Keep the WRITE-wait connections warm: a PING after a failover takes the broken
        // connection's error here instead of in the next user's WRITE. A PING also succeeds on
        // a demoted primary, so these connections (and the security one) also check that their
        // node is still the primary (`ROLE`): an idle gateway sees no READONLY to react to.
        // A WAIT connection is checked only while no request holds it, one per round in turn
        // while another stays idle, and it stays out of the requests' use until its checks are
        // answered (`LeasePool::take_idle_for_check`).
        let write_wait = self.write_wait.iter().flat_map(|w| {
            w.pool
                .take_idle_for_check(|i| w.conns[i].usable_now())
                .into_iter()
                .filter_map(move |held| {
                let conn = w.conns[held.index()].clone();
                let generation = conn.generation();
                let budget = self.redis_timeout + ROLE_CHECK_TIMEOUT;
                Some(async move {
                    // PING and ROLE without timeouts of their own: the slot is held until both
                    // are answered (or the connection is replaced after the drain period), so
                    // it never goes back to the requests with a command still on it.
                    let c = conn.clone();
                    let command = async move {
                        let r = redis::cmd("PING")
                            .query_async::<_, String>(&mut c.get())
                            .await;
                        c.observe(&r);
                        if r.is_ok() {
                            c.verify_primary_unbounded().await;
                        }
                        r
                    };
                    let retire = {
                        let c = conn.clone();
                        move || {
                            c.retire_quietly("timeout", generation);
                        }
                    };
                    // Only while the connection checked is still the installed one: a late
                    // timeout of a replaced connection says nothing about its replacement.
                    let on_timeout = {
                        let c = conn.clone();
                        move || {
                            if c.generation() == generation {
                                c.observe_timeout();
                            }
                        }
                    };
                    let hooks = SlotHooks {
                        answered: Box::new(|_, _| {}),
                        timed_out: Box::new(on_timeout),
                        stuck: Box::new(retire),
                    };
                    let r = run_on_slot_with(
                        held,
                        deadline.min(tokio::time::Instant::now() + budget),
                        budget + WAIT_DRAIN_EXTRA,
                        command,
                        hooks,
                    )
                    .await;
                    if let Ok(Err(e)) = &r {
                        if crate::health::warn_due(&self.network, "wait_conn_ping") {
                            warn!(network = %self.network, error = %store_error(e), "Replay nonce WAIT connection PING failed (reconnecting)");
                        }
                    }
                })
            })
        });
        let cache = async {
            let cache_ok = cache.await;
            crate::health::record_cache_redis_connected(&self.network, cache_ok);
            if cache_ok {
                self.cache_ping_failures.store(0, Ordering::Relaxed);
            } else if self.cache_conn.load().is_some()
                && self.cache_ping_failures.fetch_add(1, Ordering::Relaxed) + 1
                    >= CACHE_PING_FAILURES_RECONNECT
            {
                self.cache_ping_failures.store(0, Ordering::Relaxed);
                warn!(network = %self.network, "Cache Redis failed {CACHE_PING_FAILURES_RECONNECT} PINGs in a row: reopening the connection");
                crate::health::record_store_reconnect(&self.network, "cache", "timeout");
                self.cache_conn.store(None);
                spawn_cache_reconnect_task(self.clone());
            }
            cache_ok
        };

        // The same for the WAITAOF connection.
        // Every check runs at once (the cache store, the dedicated connections, the security
        // store, each peer and standby store) under one deadline: one hung connection or peer
        // costs its own budgets once instead of delaying every check after it.
        let aof = self
            .local_aof
            .as_ref()
            .map(|l| &l.conn)
            .into_iter()
            .map(|conn| async move {
                let r = timeout(
                    self.redis_timeout,
                    redis::cmd("PING").query_async::<_, String>(&mut conn.get()),
                )
                .await;
                conn.observe_timed(&r);
                if let Ok(Err(e)) = &r {
                    if crate::health::warn_due(&self.network, "wait_conn_ping") {
                        warn!(network = %self.network, error = %store_error(e), "Replay nonce WAIT connection PING failed (reconnecting)");
                    }
                }
                conn.verify_primary().await;
            });
        let peers = async {
            if let Some(peers) = &self.replay_peers {
                peers.ping_all_until(deadline).await;
            }
        };
        let standby = async {
            if let Some(peers) = &self.standby_peers {
                peers.ping_all_until(deadline).await;
            }
        };
        let dedicated = async {
            let _ = tokio::time::timeout_at(
                deadline,
                futures_util::future::join(
                    futures_util::future::join_all(write_wait),
                    futures_util::future::join_all(aof),
                ),
            )
            .await;
        };
        let cache = async {
            match tokio::time::timeout_at(deadline, cache).await {
                Ok(ok) => ok,
                Err(_) => {
                    crate::health::record_cache_redis_connected(&self.network, false);
                    false
                }
            }
        };
        // A security store whose check is not done by the deadline counts as down this round.
        let probe = async {
            match tokio::time::timeout_at(deadline, self.probe_security()).await {
                Ok(p) => p,
                Err(_) => self.security_conn.as_ref().map(|_| false),
            }
        };
        let (cache_ok, (), (), probe, ()) = tokio::join!(cache, dedicated, peers, probe, standby);
        // Evaluated once the peers' answers of this round are in.
        self.evaluate_security(cache_ok, probe)
    }

    /// The security store's housekeeping PING and `ROLE` check: whether it answered and reaches
    /// a primary (None: no security store).
    async fn probe_security(&self) -> Option<bool> {
        let sec = self.security_conn.as_ref()?;
        let ping = timeout(
            self.redis_timeout,
            redis::cmd("PING").query_async::<_, String>(&mut sec.get()),
        )
        .await;
        sec.observe_timed(&ping);
        sec.verify_primary().await;
        let ping_ok = match ping {
            Ok(Ok(resp)) if resp == "PONG" => true,
            Ok(Ok(_)) => {
                if crate::health::warn_due(&self.network, "security_ping") {
                    warn!(network = %self.network, "Security Redis PING returned unexpected response");
                }
                false
            }
            Ok(Err(e)) => {
                if crate::health::warn_due(&self.network, "security_ping") {
                    warn!(network = %self.network, error = %store_error(&e), "Security Redis PING failed");
                }
                false
            }
            Err(_) => {
                if crate::health::warn_due(&self.network, "security_ping") {
                    warn!(network = %self.network, "Security Redis PING timeout");
                }
                false
            }
        };
        // A PING also succeeds on a demoted primary: while the connection waits for a node
        // that says ROLE master (a reconnect is pending) or its last ROLE was not master,
        // the store counts as down, so /healthz does not stay 200 on a store whose every
        // replay write is refused.
        let sec_ok = ping_ok && sec.usable();
        if ping_ok && !sec_ok && crate::health::warn_due(&self.network, "security_not_primary") {
            warn!(network = %self.network, "Security Redis answers PING but does not reach a primary (reconnecting): counted as down");
        }
        Some(sec_ok)
    }

    fn evaluate_security(&self, cache_ok: bool, probe: Option<bool>) -> bool {
        let Some(sec_ok) = probe else {
            // No dedicated security Redis: replay checks fail closed, so the origin cannot serve.
            crate::health::record_security_redis_connected(&self.network, false);
            return cache_ok;
        };
        crate::health::record_security_redis_connected(&self.network, sec_ok);
        if sec_ok {
            // Not needed any more: a later outage starts with the fallback trusted again.
            self.fallback_health.local_answered();
        }
        let via_fallback = !sec_ok && self.serves_without_local_store();
        if via_fallback != crate::health::is_replay_serving_via_fallback(&self.network) {
            if via_fallback {
                warn!(network = %self.network, "Security Redis unreachable: serving through the peer stores (REPLAY_UNAVAILABLE_FALLBACK)");
            } else if !sec_ok && self.fallback_health.failing() {
                warn!(network = %self.network, "Security Redis unreachable and the WRITEs decided at the peer stores keep failing closed (REPLAY_FALLBACK_HEALTH_FAILURES): not serving");
            } else if !sec_ok {
                warn!(network = %self.network, "Security Redis unreachable and the peer stores cannot decide: not serving");
            } else {
                info!(network = %self.network, "Security Redis answers again: requests decided locally");
            }
        }
        crate::health::record_replay_serving_via_fallback(&self.network, via_fallback);
        crate::health::record_replay_fallback_writes_failing(
            &self.network,
            self.fallback_health.failing(),
        );
        cache_ok && sec_ok
    }

    /// Check if a request is a replay (body hash already seen). Returns Ok(true) if replay detected.
    /// Sets the hash in Redis with 600s TTL if not seen before.
    /// Uses security_conn (noeviction) to prevent eviction of replay nonces.
    /// Fails CLOSED if security_conn unavailable (replay protection is security-critical).
    ///
    /// Multi-origin (REPLAY_PEER_URLS) in `sync` mode: the nonce is written to every peer
    /// origin's store at the same time as to the local one (so the peers add no latency beyond
    /// their own round trip); a peer that already holds it makes the request a replay (recorded
    /// first by that origin). Other modes consult the peers later, in `replicate_nonce`.
    /// The local verdict is evaluated first and is fail-closed as before. A peer that does not
    /// answer within REPLAY_PEER_TIMEOUT_MS is an error only with REPLAY_PEER_FAIL_CLOSED;
    /// otherwise the local verdict stands and the outcome is counted (`ohttp_replay_peer_total`):
    /// `check_replay_detailed` then says `NewPeersUnconfirmed`, which admits a READ and a WRITE
    /// on `REPLAY_ONE_SIDED_WRITE_ROUTES` only (`WritePolicy`). Unit tests only: it drops what
    /// the later admission steps need (`LocalCheck`).
    #[cfg(test)]
    pub async fn check_replay(&self, body_hash: &[u8]) -> anyhow::Result<bool> {
        let local = self.check_replay_detailed(body_hash).await?;
        if local.sync_strict {
            anyhow::bail!(
                "Replay check failed at a peer origin (REPLAY_PEER_FAIL_CLOSED): a peer timed out"
            );
        }
        match local.verdict() {
            LocalReplayCheck::New | LocalReplayCheck::NewPeersUnconfirmed => Ok(false),
            LocalReplayCheck::Replay => Ok(true),
            LocalReplayCheck::Unavailable => {
                anyhow::bail!("Replay check: no verdict from the security store (fail-closed)")
            }
        }
    }

    /// The local replay check (see `check_replay` for the rules): `LocalCheck`, which every later
    /// admission step requires. A local store that gives no verdict is
    /// `LocalReplayCheck::Unavailable` instead of an error when the unavailable fallback can
    /// decide the request at the peer stores (`admit_without_local`, after the inner request
    /// is classified); any other failure is an error (fail-closed).
    pub async fn check_replay_detailed(&self, body_hash: &[u8]) -> anyhow::Result<LocalCheck> {
        let key = self.nonce_key(body_hash);

        let Some(sec) = self.security_conn.as_ref() else {
            anyhow::bail!("Replay protection unavailable: REDIS_SECURITY_URL not configured");
        };
        let mut conn = sec.get();

        let local = timeout(self.redis_timeout, async {
            redis::cmd("SET")
                .arg(&key)
                .arg("1")
                .arg("NX")
                .arg("EX")
                .arg(REPLAY_TTL_SECS)
                .query_async::<_, Option<String>>(&mut conn)
                .await
        });
        // Peers are consulted here, concurrently with the local store, in `sync` mode only. In
        // `async-reads` and `failover` the inner request must be decapsulated and classified
        // first (`replicate_nonce`), so this is the local verdict alone.
        let sync_peers = self
            .replay_peers
            .as_ref()
            .filter(|p| p.mode() == ReplayPeerMode::Sync);
        // A value of this request's own: a peer whose SET NX timed out can be asked again after
        // classification (`SET ... NX GET`, `replicate_nonce_checked`).
        let sync_value = format!("{:016x}", rand::random::<u64>());
        let peers = async {
            match sync_peers {
                Some(p) => Some(
                    p.write_nonce_value(&key, REPLAY_TTL_SECS, &sync_value)
                        .await,
                ),
                None => None,
            }
        };
        let (local, peer_outcomes) = tokio::join!(local, peers);
        // A failover signal (READONLY on a demoted primary, a hung or broken connection) replaces
        // the connection in the background; this request still fails closed below.
        sec.observe_timed(&local);
        // The local store gave a verdict (new or replay): the fallback is trusted again at once,
        // not only from the next housekeeping round on (`FallbackHealth`).
        if matches!(local, Ok(Ok(_))) && self.fallback_health.local_answered() {
            crate::health::record_replay_fallback_writes_failing(&self.network, false);
        }

        let checked =
            |verdict: LocalReplayCheck, timed_out: Vec<usize>, unanswered: usize| LocalCheck {
                key: key.clone(),
                verdict,
                sync_value: sync_value.clone(),
                sync_timed_out: timed_out,
                sync_unanswered: unanswered,
                sync_strict: false,
            };
        match local {
            Ok(Ok(Some(_))) => {}
            Ok(Ok(None)) => return Ok(checked(LocalReplayCheck::Replay, Vec::new(), 0)),
            Ok(Err(e)) => {
                if self.local_unavailable_fallback_ready() {
                    debug!(network = %self.network, error = %store_error(&e), "Replay check: no verdict from the security store, deciding at the peer stores");
                    return Ok(checked(LocalReplayCheck::Unavailable, Vec::new(), 0));
                }
                anyhow::bail!(
                    "Replay check failed on security connection (fail-closed): {}",
                    store_error(&e)
                );
            }
            Err(_) => {
                if self.local_unavailable_fallback_ready() {
                    debug!(network = %self.network, "Replay check: security store timed out, deciding at the peer stores");
                    return Ok(checked(LocalReplayCheck::Unavailable, Vec::new(), 0));
                }
                anyhow::bail!(
                    "Replay check timeout on security connection (fail-closed): {}ms",
                    self.redis_timeout.as_millis()
                );
            }
        }

        let (Some(peers), Some(outcomes)) = (sync_peers, peer_outcomes) else {
            return Ok(checked(LocalReplayCheck::New, Vec::new(), 0));
        };
        let gap = combine_peer_outcomes(&outcomes) == PeerVerdict::Unavailable;
        let timed_out = (0..outcomes.len())
            .filter(|i| outcomes[*i] == PeerOutcome::Timeout)
            .collect();
        let unanswered = outcomes
            .iter()
            .filter(|o| !matches!(o, PeerOutcome::Fresh | PeerOutcome::Replay))
            .count();
        // REPLAY_PEER_FAIL_CLOSED: peers whose SET NX only timed out are asked again once the
        // request is classified (`replicate_nonce_checked`), before it fails closed; any other
        // gap (an error, a peer not connected) fails it closed now.
        if peers.fail_closed()
            && gap
            && outcomes
                .iter()
                .all(|o| matches!(o, PeerOutcome::Fresh | PeerOutcome::Timeout))
        {
            let mut c = checked(LocalReplayCheck::NewPeersUnconfirmed, timed_out, unanswered);
            c.sync_strict = true;
            return Ok(c);
        }
        Ok(
            match self.peer_verdict(&outcomes, peers.fail_closed(), "REPLAY_PEER_FAIL_CLOSED")? {
                true => checked(LocalReplayCheck::Replay, Vec::new(), 0),
                // Tolerated (REPLAY_PEER_FAIL_CLOSED=0): only a READ or a one-sided WRITE runs,
                // or a WRITE whose timed-out peers take the nonce on the retry.
                false if gap => {
                    checked(LocalReplayCheck::NewPeersUnconfirmed, timed_out, unanswered)
                }
                false => checked(LocalReplayCheck::New, Vec::new(), 0),
            },
        )
    }

    fn peer_verdict(
        &self,
        outcomes: &[PeerOutcome],
        fail_closed: bool,
        policy: &str,
    ) -> anyhow::Result<bool> {
        match combine_peer_outcomes(outcomes) {
            PeerVerdict::Fresh => Ok(false),
            PeerVerdict::Replay => Ok(true),
            PeerVerdict::Unavailable if fail_closed => {
                anyhow::bail!(
                    "Replay check failed at a peer origin ({policy}): {:?}",
                    outcomes
                )
            }
            PeerVerdict::Unavailable => {
                if crate::health::warn_due(&self.network, "peer_tolerated") {
                    warn!(
                        network = %self.network,
                        outcomes = ?outcomes,
                        "Replay peer unavailable; proceeding on the local verdict"
                    );
                }
                Ok(false)
            }
        }
    }

    /// Cross-origin replay protection after the inner request is classified
    /// (REPLAY_PEER_MODE=async-reads|failover). In `sync` mode `check_replay` already consulted
    /// the peers: a READ is a no-op and a WRITE only waits for the peers' replica acknowledgement
    /// (`confirm_replicated`). The nonce is already in the local store.
    ///
    /// - `failover`: enqueue for every peer, never wait. `Ok(false)`.
    /// - `async-reads`, READ with healthy replication: enqueue. `Ok(false)`.
    /// - `async-reads`, READ while replication is degraded (strict): synchronous `SET NX` at
    ///   every peer; a peer that holds the nonce => `Ok(true)` (409); unavailable peers follow
    ///   `REPLAY_PEER_FAIL_CLOSED`.
    /// - `async-reads`, WRITE: synchronous, unavailable peers follow
    ///   `REPLAY_PEER_FAIL_CLOSED_WRITES` (default fail-closed), and tolerating them admits only a
    ///   WRITE under `WritePolicy::ONE_SIDED`.
    ///
    /// `policy` is the WRITE's (`WritePolicy`, from `REPLAY_ONE_SIDED_WRITE_ROUTES`); it has no
    /// default: with `BOTH_STORES` a WRITE that only one store took as new fails closed.
    /// Unit tests only (the nonce assumed new locally): see `replicate_nonce_checked`.
    #[cfg(test)]
    pub async fn replicate_nonce(
        &self,
        body_hash: &[u8],
        class: RouteClass,
        policy: WritePolicy,
    ) -> anyhow::Result<bool> {
        let local = LocalCheck::assume_new(self.nonce_key(body_hash));
        Ok(self
            .replicate_nonce_checked(&local, class, policy)
            .await?
            .replay)
    }

    /// The peer stage of a request whose local check (`local`) took the nonce as new: what the
    /// replica wait that follows needs to know (`PeerCheck`). `Err` = fail-closed.
    pub async fn replicate_nonce_checked(
        &self,
        local: &LocalCheck,
        class: RouteClass,
        policy: WritePolicy,
    ) -> anyhow::Result<PeerCheck> {
        if !matches!(
            local.verdict,
            LocalReplayCheck::New | LocalReplayCheck::NewPeersUnconfirmed
        ) {
            anyhow::bail!("Replay check: the local store did not take the nonce (fail-closed)");
        }
        let mut check = self.replicate_nonce_inner(local, class, policy).await?;
        check.one_sided = policy.one_sided();
        Ok(check.bound_to(local))
    }

    /// `sync` mode, a peer gave no verdict on the check (`LocalReplayCheck::NewPeersUnconfirmed`):
    /// the peers whose `SET NX` timed out are asked once more (`retry_timed_out`). `Taken` only
    /// if every peer that gave no verdict took the nonce now.
    async fn retry_sync_gap(
        &self,
        peers: &ReplayPeers,
        local: &LocalCheck,
        key: &str,
    ) -> SyncRetry {
        let mut outcomes = vec![PeerOutcome::Error; peers.len()];
        for i in &local.sync_timed_out {
            outcomes[*i] = PeerOutcome::Timeout;
        }
        let retried = local.sync_timed_out.len();
        if retried > 0 {
            peers
                .retry_timed_out(key, REPLAY_TTL_SECS, &local.sync_value, &mut outcomes)
                .await;
        }
        if outcomes.contains(&PeerOutcome::Replay) {
            return SyncRetry::Replay;
        }
        let fresh = local
            .sync_timed_out
            .iter()
            .all(|i| outcomes[*i] == PeerOutcome::Fresh);
        if retried > 0 && fresh && retried == local.sync_unanswered {
            SyncRetry::Taken
        } else {
            SyncRetry::Gap
        }
    }

    fn nonce_key(&self, body_hash: &[u8]) -> String {
        format!("replay:{}:{}", self.network, hex::encode(body_hash))
    }

    /// A WRITE under `WritePolicy::BOTH_STORES` reached a path that would admit it on one
    /// store's verdict (`path`): counted, and failed closed with `why`.
    fn refuse_one_sided(&self, path: &str, why: impl std::fmt::Display) -> anyhow::Error {
        crate::health::record_replay_write_fallback(&self.network, path, "one_sided_refused");
        anyhow::anyhow!(
            "WRITE replay nonce taken by one store only, the route is not on REPLAY_ONE_SIDED_WRITE_ROUTES (fail-closed): {why}"
        )
    }

    async fn replicate_nonce_inner(
        &self,
        local: &LocalCheck,
        class: RouteClass,
        policy: WritePolicy,
    ) -> anyhow::Result<PeerCheck> {
        let replay = |replay: bool| PeerCheck {
            replay,
            ..PeerCheck::blank()
        };
        let Some(peers) = &self.replay_peers else {
            return Ok(replay(false));
        };
        let key = local.key.clone();
        match (peers.mode(), class) {
            // check_replay already wrote the nonce to every peer; a WRITE waits for their
            // replicas at the peers that are connected (a disconnected one was tolerated there).
            (ReplayPeerMode::Sync, class) if local.sync_strict => {
                // REPLAY_PEER_FAIL_CLOSED and peers whose SET NX timed out: the request runs
                // only once they took the nonce on the retry (READs too: fail-closed covers
                // every request there).
                match self.retry_sync_gap(peers, local, &key).await {
                    SyncRetry::Replay => return Ok(replay(true)),
                    SyncRetry::Gap => anyhow::bail!(
                        "Replay check failed at a peer origin (REPLAY_PEER_FAIL_CLOSED): a peer gave no verdict"
                    ),
                    SyncRetry::Taken => {}
                }
                if class == RouteClass::Write {
                    peers
                        .confirm_replicated(&key, |i| peers.connected(i))
                        .await?;
                }
                Ok(replay(false))
            }
            (ReplayPeerMode::Sync, RouteClass::Write) => {
                // A peer gave no verdict and REPLAY_PEER_FAIL_CLOSED=0 tolerated it.
                if local.verdict == LocalReplayCheck::NewPeersUnconfirmed {
                    if policy.one_sided {
                        crate::health::record_replay_write_fallback(
                            &self.network,
                            "peer_tolerated",
                            "accepted",
                        );
                    } else {
                        // Both stores must take it: the peers whose SET NX timed out are asked
                        // once more (the others gave an error or were not connected).
                        match self.retry_sync_gap(peers, local, &key).await {
                            SyncRetry::Replay => return Ok(replay(true)),
                            SyncRetry::Gap => {
                                return Err(self.refuse_one_sided(
                                    "peer_tolerated",
                                    "a peer store gave no verdict",
                                ))
                            }
                            SyncRetry::Taken => {}
                        }
                    }
                }
                peers
                    .confirm_replicated(&key, |i| peers.connected(i))
                    .await?;
                Ok(replay(false))
            }
            (ReplayPeerMode::Sync, RouteClass::Read) => Ok(replay(false)),
            (ReplayPeerMode::Failover, class) => {
                // A WRITE with the local replica wait: replicated after it (confirm_write_nonce).
                let deferred = class == RouteClass::Write && self.write_wait.is_some();
                if !deferred {
                    if let Some(r) = &self.replicator {
                        r.enqueue(&key);
                    }
                }
                Ok(PeerCheck {
                    deferred,
                    ..PeerCheck::blank()
                })
            }
            (ReplayPeerMode::AsyncReads, RouteClass::Read) => {
                let strict = match &self.replicator {
                    Some(r) if r.health().effective() == Effective::Relaxed => {
                        r.enqueue(&key);
                        return Ok(replay(false));
                    }
                    Some(_) => true,
                    // No replicator (cannot happen in main; tests): synchronous.
                    None => true,
                };
                debug_assert!(strict);
                let outcomes = peers.write_nonce(&key, REPLAY_TTL_SECS).await;
                self.peer_verdict(&outcomes, peers.fail_closed(), "REPLAY_PEER_FAIL_CLOSED")
                    .map(replay)
            }
            (ReplayPeerMode::AsyncReads, RouteClass::Write) => {
                // With a confirming standby store, every path below that can let the WRITE run
                // asks it (`SET NX`): the check at the fallback store, the short-acknowledgement
                // and the unavailable-hub fallbacks. Its `SET NX` runs concurrently with the hub's
                // `SET NX` and replica wait instead of after them, which saves the round trip to
                // the standby store on every WRITE. A replay at either store refuses the request,
                // as before. A nonce left at the standby store by a request that is then refused
                // or fails closed stays held for those exact bytes, which clients never send
                // again. Two copies of one request arriving at two origins within a round trip
                // may now both be refused (one wins the hub, the other the standby store); both
                // running remains impossible while both answer (and for a WRITE that is not on
                // REPLAY_ONE_SIDED_WRITE_ROUTES at all: `WritePolicy`).
                let early_standby = self.hub_fallback.as_ref().and(self.confirming_standby());
                let hub = async {
                    // A WRITE that both stores must take: a SET NX that timed out is asked once
                    // more instead of failing the WRITE closed at once.
                    let outcomes = if policy.one_sided {
                        peers.write_nonce(&key, REPLAY_TTL_SECS).await
                    } else {
                        peers.write_nonce_retrying(&key, REPLAY_TTL_SECS).await
                    };
                    let disruptions = peers.disruptions();
                    // The replica wait of the peers that stored the nonce, in exactly the cases
                    // the verdict below lets through: every peer took it, or a peer did not
                    // answer and REPLAY_PEER_FAIL_CLOSED_WRITES=0 tolerates that. Not on a
                    // replay, and not where an unavailable peer fails the WRITE closed or sends
                    // it to the unavailable-hub fallback.
                    let fresh = |i: usize| outcomes.get(i) == Some(&PeerOutcome::Fresh);
                    let verdict = combine_peer_outcomes(&outcomes);
                    let confirmed = if outcomes.contains(&PeerOutcome::Fresh)
                        && (verdict == PeerVerdict::Fresh
                            || (verdict == PeerVerdict::Unavailable
                                && !peers.fail_closed_writes()
                                && policy.one_sided))
                    {
                        Some(peers.confirm_replicated_kind(&key, fresh).await)
                    } else {
                        None
                    };
                    (outcomes, disruptions, confirmed)
                };
                let standby = async {
                    match early_standby {
                        Some(s) if policy.one_sided => {
                            Some(s.write_nonce(&key, REPLAY_TTL_SECS).await)
                        }
                        Some(s) => Some(s.write_nonce_retrying(&key, REPLAY_TTL_SECS).await),
                        None => None,
                    }
                };
                let ((outcomes, disruptions, confirmed), at_standby_outcomes) =
                    tokio::join!(hub, standby);
                // The hub gave no verdict (unreachable, a timeout or an error) where it would fail
                // the WRITE closed: confirm at the fallback store instead
                // (REPLAY_UNAVAILABLE_FALLBACK).
                if peers.fail_closed_writes()
                    && combine_peer_outcomes(&outcomes) == PeerVerdict::Unavailable
                    && matches!(
                        self.unavailable_fallback_target(),
                        Some("standby" | "local_replicas")
                    )
                {
                    return self
                        .hub_unavailable_fallback(&key, &outcomes, at_standby_outcomes, policy)
                        .await;
                }
                let replay = self.peer_verdict(
                    &outcomes,
                    peers.fail_closed_writes(),
                    "REPLAY_PEER_FAIL_CLOSED_WRITES",
                )?;
                // An unavailable hub tolerated above (REPLAY_PEER_FAIL_CLOSED_WRITES=0): the
                // WRITE would run without the hub's verdict.
                if !replay && combine_peer_outcomes(&outcomes) == PeerVerdict::Unavailable {
                    if !policy.one_sided {
                        return Err(self.refuse_one_sided(
                            "peer_tolerated",
                            format!("the hub gave no verdict: {outcomes:?}"),
                        ));
                    }
                    crate::health::record_replay_write_fallback(
                        &self.network,
                        "peer_tolerated",
                        "accepted",
                    );
                }
                // The peers that stored the nonce (the shared store, while reachable) must have
                // it on their replicas before the WRITE runs. A peer that did not answer was
                // tolerated by the verdict above (REPLAY_PEER_FAIL_CLOSED_WRITES=0 while the peers
                // are down).
                let mut at_standby = false;
                let mut hub_needs_local_ack = false;
                let mut replicate_to_after = Vec::new();
                if !replay {
                    let fresh = |i: usize| outcomes.get(i) == Some(&PeerOutcome::Fresh);
                    let all_fresh =
                        !outcomes.is_empty() && outcomes.iter().all(|o| *o == PeerOutcome::Fresh);
                    if let Some(fb) = &self.hub_fallback {
                        fb.note_generation(disruptions);
                    }
                    // No peer stored the nonce (tolerated): nothing to wait for.
                    match confirmed.unwrap_or(Ok(())) {
                        Ok(()) => {
                            // Also when a peer did not answer and the policy tolerated it
                            // (REPLAY_PEER_FAIL_CLOSED_WRITES=0, a one-sided route): the WRITE
                            // then runs on the local verdict, and the fallback store must still
                            // be asked. A standby store that does not answer fails any other
                            // WRITE closed there.
                            match self
                                .hub_window_check(&key, at_standby_outcomes, policy)
                                .await?
                            {
                                Some(true) => {
                                    return Ok(PeerCheck {
                                        replay: true,
                                        ..PeerCheck::blank()
                                    })
                                }
                                // Stored there synchronously: no asynchronous hand-off.
                                Some(false) => at_standby = true,
                                None => {}
                            }
                        }
                        Err(f) if f.only_short && all_fresh => {
                            match self
                                .hub_short_ack_fallback(&key, f, at_standby_outcomes)
                                .await?
                            {
                                HubFallback::Replay => {
                                    return Ok(PeerCheck {
                                        replay: true,
                                        ..PeerCheck::blank()
                                    })
                                }
                                HubFallback::AtStandby => at_standby = true,
                                HubFallback::NeedsLocalAck => hub_needs_local_ack = true,
                            }
                        }
                        Err(f) => anyhow::bail!(f.message),
                    }
                    // No peer took it (tolerated): only the local store holds the nonce, so it
                    // must survive a crash of this host (REPLAY_LOCAL_WAITAOF_MS).
                    if !outcomes.contains(&PeerOutcome::Fresh) {
                        self.confirm_nonce_local_aof(&key).await?;
                    }
                    // A peer that did not take it (tolerated: REPLAY_PEER_FAIL_CLOSED_WRITES=0)
                    // gets it asynchronously once it is reachable again, until the nonce TTL:
                    // after the switch back, the origins that check there must refuse a replay
                    // of a WRITE that ran here meanwhile.
                    // Only once the WRITE is admitted: with the local replica wait still to come
                    // (`confirm_write_nonce`) the hand-off waits for its verdict, so a WRITE that
                    // then fails closed leaves no nonce at a peer for bytes that never ran here.
                    if !outcomes.iter().all(|o| *o == PeerOutcome::Fresh) {
                        if self.write_wait.is_some() {
                            replicate_to_after =
                                (0..outcomes.len()).filter(|i| !fresh(*i)).collect();
                        } else if let Some(r) = &self.replicator {
                            r.enqueue_to(&key, |i| !fresh(i));
                        }
                    }
                }
                // Every peer took the nonce and (confirm_replicated above, with a wait) has it
                // on its replicas: the local replica wait may fall back on that.
                let durable_at_peers = !replay
                    && !hub_needs_local_ack
                    && peers.wait().is_some()
                    && !outcomes.is_empty()
                    && outcomes.iter().all(|o| *o == PeerOutcome::Fresh);
                Ok(PeerCheck {
                    replay,
                    durable_at_peers,
                    at_standby,
                    hub_needs_local_ack,
                    replicate_to_after,
                    ..PeerCheck::blank()
                })
            }
        }
    }

    /// The standby stores that can confirm a WRITE synchronously (REPLAY_STANDBY_URLS with
    /// REPLAY_PEER_WAIT_REPLICAS >= 1).
    fn confirming_standby(&self) -> Option<&ReplayPeers> {
        self.standby_peers
            .as_deref()
            .filter(|s| s.wait().is_some() && !s.is_empty())
    }

    /// Every WRITE of a read origin with a confirming standby store, concurrently with the hub's
    /// check: `SET NX` at the standby stores (write_fallback.rs, "Check at the fallback store").
    /// Some(true) = a standby store held the nonce (replay), Some(false) = every one took it,
    /// None = no standby store that confirms, or one did not answer (the hub's verdict stands,
    /// the asynchronous hand-off follows as usual). `asked`: the outcomes of that `SET NX` when
    /// it already ran (concurrently with the hub's check); else it runs now.
    ///
    /// A standby store that did not answer fails a WRITE under `WritePolicy::BOTH_STORES` closed
    /// (`Err`, `result="one_sided_refused"`): the hub's verdict alone would admit it.
    async fn hub_window_check(
        &self,
        key: &str,
        asked: Option<Vec<PeerOutcome>>,
        policy: WritePolicy,
    ) -> anyhow::Result<Option<bool>> {
        let (Some(fb), Some(standby)) = (self.hub_fallback.as_ref(), self.confirming_standby())
        else {
            return Ok(None);
        };
        // The label tells a check inside the window (after startup or a hub disruption) from
        // the steady state; both are decided the same way.
        let path = if fb.window_open() {
            "hub_window"
        } else {
            "hub_check"
        };
        debug_assert!(
            asked.is_some(),
            "the standby store was not asked concurrently"
        );
        let outcomes = match asked {
            Some(o) => o,
            None => standby.write_nonce(key, REPLAY_TTL_SECS).await,
        };
        let verdict = combine_peer_outcomes(&outcomes);
        if verdict == PeerVerdict::Unavailable && !policy.one_sided {
            return Err(self.refuse_one_sided(
                path,
                format!("the standby store gave no verdict: {outcomes:?}"),
            ));
        }
        let result = match verdict {
            PeerVerdict::Fresh => "accepted",
            PeerVerdict::Replay => "replay",
            PeerVerdict::Unavailable => "unavailable",
        };
        crate::health::record_replay_write_fallback(&self.network, path, result);
        Ok(match verdict {
            PeerVerdict::Replay => Some(true),
            PeerVerdict::Fresh => Some(false),
            PeerVerdict::Unavailable => None,
        })
    }

    /// The hub took the nonce as new but its replicas did not acknowledge it (`f`). With
    /// standby stores: confirm there (`SET NX` + `WAIT`). With the local replica wait: leave it
    /// to the local replicas. Otherwise, or on any other outcome: fail closed with `f`.
    /// `asked`: the outcomes of the standby `SET NX` when it already ran (see
    /// `hub_window_check`).
    async fn hub_short_ack_fallback(
        &self,
        key: &str,
        f: ConfirmFailure,
        asked: Option<Vec<PeerOutcome>>,
    ) -> anyhow::Result<HubFallback> {
        let Some(fb) = self.hub_fallback.as_ref() else {
            anyhow::bail!(f.message);
        };
        if self.confirming_standby().is_none() && self.write_wait.is_none() {
            anyhow::bail!(f.message);
        }
        fb.open_window();
        let record = |result: &str| {
            crate::health::record_replay_write_fallback(&self.network, "hub_short_ack", result)
        };
        if !fb.has_room() {
            record("overflow");
            anyhow::bail!("{} (write-back queue full, no fallback)", f.message);
        }
        if let Some(standby) = self.confirming_standby() {
            debug_assert!(
                asked.is_some(),
                "the standby store was not asked concurrently"
            );
            let outcomes = match asked {
                Some(o) => o,
                None => standby.write_nonce(key, REPLAY_TTL_SECS).await,
            };
            match combine_peer_outcomes(&outcomes) {
                PeerVerdict::Replay => {
                    record("replay");
                    return Ok(HubFallback::Replay);
                }
                PeerVerdict::Unavailable => {
                    record("unavailable");
                    anyhow::bail!("{} (standby fallback unavailable: {outcomes:?})", f.message);
                }
                PeerVerdict::Fresh => {}
            }
            if let Err(e) = standby.confirm_replicated(key, |_| true).await {
                record("unacknowledged");
                anyhow::bail!("{} (standby fallback: {e})", f.message);
            }
            if !fb.push_write_back(key.to_string()) {
                record("overflow");
                anyhow::bail!("{} (write-back queue full, no fallback)", f.message);
            }
            record("accepted");
            if crate::health::warn_due(&self.network, "hub_short_standby") {
                warn!(network = %self.network, reason = %f.message, "WRITE replay nonce confirmed at the standby stores (hub replica acknowledgement short); written back to the hub later");
            }
            return Ok(HubFallback::AtStandby);
        }
        if self.write_wait.is_some() {
            // Decided by the local replica wait (confirm_write_nonce).
            return Ok(HubFallback::NeedsLocalAck);
        }
        anyhow::bail!(f.message)
    }

    /// The hub gave no verdict on a WRITE nonce (`outcomes`: none held it, at least one did not
    /// answer) and REPLAY_UNAVAILABLE_FALLBACK is on: decide at the fallback store, with the
    /// rules of the short-acknowledgement path. With standby stores: `SET NX` + `WAIT` there
    /// (new and acknowledged = runs, held = replay, anything else = fail-closed). With the
    /// local replica wait (the local store is the fallback store): the local replicas decide
    /// (`confirm_write_nonce`). Either way the nonce is written back to the hub until the hub's
    /// replicas have it. `asked`: the outcomes of the standby `SET NX` when it already ran (see
    /// `hub_window_check`).
    ///
    /// Under `WritePolicy::BOTH_STORES` this always fails closed (`result="one_sided_refused"`):
    /// without the hub's verdict only one store decides.
    async fn hub_unavailable_fallback(
        &self,
        key: &str,
        outcomes: &[PeerOutcome],
        asked: Option<Vec<PeerOutcome>>,
        policy: WritePolicy,
    ) -> anyhow::Result<PeerCheck> {
        let Some(fb) = self.hub_fallback.as_ref() else {
            anyhow::bail!("Replay check failed at a peer origin (REPLAY_PEER_FAIL_CLOSED_WRITES): {outcomes:?}");
        };
        fb.open_window();
        if !policy.one_sided {
            return Err(self.refuse_one_sided(
                "hub_unavailable",
                format!("the hub gave no verdict: {outcomes:?}"),
            ));
        }
        let record = |result: &str| {
            crate::health::record_replay_write_fallback(&self.network, "hub_unavailable", result)
        };
        if !fb.has_room() {
            record("overflow");
            anyhow::bail!("Replay check failed at a peer origin: {outcomes:?} (write-back queue full, no fallback)");
        }
        let Some(standby) = self.confirming_standby() else {
            // The local replica wait decides (confirm_write_nonce, which also queues the
            // write-back to the hub).
            return Ok(PeerCheck {
                hub_needs_local_ack: true,
                hub_unavailable: true,
                ..PeerCheck::blank()
            });
        };
        debug_assert!(
            asked.is_some(),
            "the standby store was not asked concurrently"
        );
        let at_standby = match asked {
            Some(o) => o,
            None => standby.write_nonce(key, REPLAY_TTL_SECS).await,
        };
        match combine_peer_outcomes(&at_standby) {
            PeerVerdict::Replay => {
                record("replay");
                return Ok(PeerCheck {
                    replay: true,
                    ..PeerCheck::blank()
                });
            }
            PeerVerdict::Unavailable => {
                record("unavailable");
                anyhow::bail!("Replay check failed at a peer origin: {outcomes:?} (standby fallback unavailable: {at_standby:?})");
            }
            PeerVerdict::Fresh => {}
        }
        if let Err(e) = standby.confirm_replicated(key, |_| true).await {
            record("unacknowledged");
            anyhow::bail!(
                "Replay check failed at a peer origin: {outcomes:?} (standby fallback: {e})"
            );
        }
        if !fb.push_write_back(key.to_string()) {
            record("overflow");
            anyhow::bail!("Replay check failed at a peer origin: {outcomes:?} (write-back queue full, no fallback)");
        }
        record("accepted");
        if crate::health::warn_due(&self.network, "hub_unavailable_standby") {
            warn!(network = %self.network, outcomes = ?outcomes, "WRITE replay nonce confirmed at the standby stores (no verdict from the hub); written back to the hub later");
        }
        Ok(PeerCheck {
            at_standby: true,
            ..PeerCheck::blank()
        })
    }

    /// The shared epoch from Redis, initialised atomically (SET NX) to the current Unix time
    /// when missing (an existing epoch is kept). Returns the local value on error.
    pub async fn get_shared_epoch(&self) -> u64 {
        match self.fetch_shared_epoch().await {
            Some(e) => self.commit_local_epoch(e),
            None => self.epoch.load(Ordering::Relaxed),
        }
    }

    /// Take the local store's epoch `e` (read before, without side effects), unless an epoch
    /// switched for a bump seen at a peer is in force: decided and written under the epoch's
    /// lock, so a refresh that read the store before a switch never overwrites it. The epoch
    /// in force afterwards.
    fn commit_local_epoch(&self, e: u64) -> u64 {
        let state = self.epoch_state.lock();
        if state.switch.is_none() {
            self.epoch.store(e, Ordering::Relaxed);
        }
        // The store answered: the refresh is done either way, so a switched epoch does not
        // send every request to the store again (`refresh_epoch_if_stale`).
        self.last_epoch_sync.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Ordering::Relaxed,
        );
        self.epoch.load(Ordering::Relaxed)
    }

    /// Housekeeping's epoch sync: `get_shared_epoch`, and the replay peers' epochs next to it.
    /// Each store keeps its own epoch value (initialised when it was first used), so a peer's
    /// value is never taken over; but while the local store gives no answer (the peer stores
    /// decide in its place, `REPLAY_UNAVAILABLE_FALLBACK`) an operator bump there could not be
    /// seen at all.
    ///
    /// While the local store answers, every peer's epoch is recorded as its baseline, by store
    /// identity (`EpochState::baselines`). While it does not, the first peer in `REPLAY_PEER_URLS` order
    /// that answers is compared with its own baseline: a different value is taken as an
    /// operator bump, and so is a peer without a baseline yet (nothing tells whether it was
    /// bumped meanwhile). Either moves the epoch here to a fresh random 64-bit value, under
    /// which nothing was cached, so cached answers are missed rather than served stale; the peer's
    /// value becomes its baseline. The switched epoch stays in force until the local store has
    /// answered `EPOCH_STEADY_ROUNDS` housekeeping rounds in a row (a single answer during a
    /// flapping outage does not bring the old entries back); then the peers' baselines are taken
    /// again and the local store's own value applies again: a bump meant to outlast the outage
    /// must also be applied to every store once it answers.
    pub async fn sync_epoch(&self) -> u64 {
        self.sync_epoch_until(tokio::time::Instant::now() + HOUSEKEEPING_DEADLINE)
            .await
    }

    /// `sync_epoch` with the local and the peer reads concurrently, both bounded by `deadline`:
    /// a local read not done by then counts as no answer (a round that does not count toward
    /// `EPOCH_STEADY_ROUNDS`), a peer read not done as that peer giving none.
    pub async fn sync_epoch_until(&self, deadline: tokio::time::Instant) -> u64 {
        let (local, peers) = tokio::join!(
            async {
                tokio::time::timeout_at(deadline, self.fetch_shared_epoch())
                    .await
                    .ok()
                    .flatten()
            },
            async {
                tokio::time::timeout_at(deadline, self.peer_epochs_now())
                    .await
                    .unwrap_or_default()
            },
        );
        // Everything below is decided and written under the epoch's lock.
        let mut state = self.epoch_state.lock();
        let current = self.epoch.load(Ordering::Relaxed);
        if let Some(e) = local {
            if let Some(rounds) = state.switch.as_mut() {
                *rounds += 1;
                if *rounds < EPOCH_STEADY_ROUNDS {
                    // Still watching the peers meanwhile.
                    return self.compare_peer_epochs(&mut state, peers, current);
                }
                state.switch = None;
                info!(network = %self.network, "Security store answered steadily again: its shared epoch applies again");
            }
            self.epoch.store(e, Ordering::Relaxed);
            self.last_epoch_sync.store(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                Ordering::Relaxed,
            );
            for (id, v) in peers.into_iter().flatten() {
                state.baselines.insert(id, v);
            }
            return e;
        }
        if let Some(rounds) = state.switch.as_mut() {
            *rounds = 0;
        }
        self.compare_peer_epochs(&mut state, peers, current)
    }

    /// The local store gives no verdict (or not steadily yet): compare the first answering peer
    /// with its baseline, and move to a fresh epoch on a change or without a baseline (under
    /// the epoch's lock, `state`).
    fn compare_peer_epochs(
        &self,
        state: &mut EpochState,
        peers: Vec<Option<(String, u64)>>,
        current: u64,
    ) -> u64 {
        let Some((id, value)) = peers.into_iter().flatten().next() else {
            return current;
        };
        let previous = state.baselines.insert(id, value);
        if previous == Some(value) {
            return current;
        }
        let mut fresh = rand::random::<u64>();
        while fresh == current || fresh == 0 {
            fresh = rand::random::<u64>();
        }
        self.epoch.store(fresh, Ordering::Relaxed);
        state.switch = Some(0);
        if previous.is_some() {
            if crate::health::warn_due(&self.network, "epoch_switch") {
                warn!(network = %self.network, "Shared cache epoch changed at a peer store while the security store gives no answer: cache entries of the old epoch are no longer served");
            }
        } else {
            if crate::health::warn_due(&self.network, "epoch_switch_unknown") {
                warn!(network = %self.network, "Security store gives no answer and its epoch was never compared with this peer store's: cache entries of the old epoch are no longer served");
            }
        }
        crate::health::record_epoch_bump_seen_at_peer(&self.network);
        fresh
    }

    /// `GET epoch:{network}` at every replay peer at once, within the peer timeout, in
    /// `REPLAY_PEER_URLS` order: (store identity, epoch) of each that answered with one.
    async fn peer_epochs_now(&self) -> Vec<Option<(String, u64)>> {
        let Some(peers) = self.replay_peers.as_ref() else {
            return Vec::new();
        };
        let key = format!("epoch:{}", self.network);
        let reads = peers.peers.iter().map(|p| {
            let key = key.as_str();
            async move {
                let conn = p.conn.load_full()?;
                let mut conn = (*conn).clone();
                let v = timeout(peers.timeout, conn.get::<_, Option<u64>>(key))
                    .await
                    .ok()?
                    .ok()??;
                let id = format!(
                    "{}:{}",
                    p.index,
                    hex::encode(&Sha256::digest(p.url.as_bytes())[..8])
                );
                Some((id, v))
            }
        });
        futures_util::future::join_all(reads).await
    }

    /// The shared epoch from the local store (`get_shared_epoch`); None when it gave no answer.
    async fn fetch_shared_epoch(&self) -> Option<u64> {
        let key = format!("epoch:{}", self.network);

        let sec = self.security_conn.as_ref();
        let mut conn = if let Some(sec) = sec {
            sec.get()
        } else if let Some(cache) = self.cache_conn.load_full().map(|c| (*c).clone()) {
            cache
        } else {
            return None;
        };

        let initial_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let init = timeout(self.redis_timeout, async {
            redis::cmd("SET")
                .arg(&key)
                .arg(initial_epoch)
                .arg("NX")
                .query_async::<_, Option<String>>(&mut conn)
                .await
        })
        .await;
        if let Some(sec) = sec {
            sec.observe_timed(&init);
        }

        match timeout(self.redis_timeout, conn.get::<_, Option<u64>>(&key)).await {
            // Taken by the caller under the epoch's lock (`commit_local_epoch`, `sync_epoch`).
            Ok(Ok(Some(epoch))) => Some(epoch),
            Ok(Ok(None)) => {
                let fallback_epoch = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if crate::health::warn_due(&self.network, "epoch_vanished") {
                    warn!(
                        fallback_epoch,
                        "Epoch key vanished after SET NX, using timestamp"
                    );
                }
                Some(fallback_epoch)
            }
            Ok(Err(e)) => {
                if crate::health::warn_due(&self.network, "epoch_read") {
                    warn!(network = %self.network, error = %store_error(&e), "Failed to read shared epoch from Redis");
                }
                crate::health::record_cache_redis_timeout(&self.network, "epoch_error");
                None
            }
            Err(_) => {
                if crate::health::warn_due(&self.network, "epoch_get_timeout") {
                    warn!(network = %self.network, timeout_ms = self.redis_timeout.as_millis(), "Epoch GET timeout");
                }
                crate::health::record_cache_redis_timeout(&self.network, "epoch_timeout");
                None
            }
        }
    }

    /// Refresh epoch from Redis if stale (> EPOCH_REFRESH_SECS since last sync).
    async fn refresh_epoch_if_stale(&self) -> u64 {
        let last_sync = self.last_epoch_sync.load(Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now.saturating_sub(last_sync) > EPOCH_REFRESH_SECS {
            self.get_shared_epoch().await
        } else {
            self.epoch.load(Ordering::Relaxed)
        }
    }

    /// Prefix of every cached entry of this epoch.
    pub fn key_prefix_for_epoch(&self, epoch: u64) -> String {
        format!(
            "ohttp:{}:{}:{}:v{}:{}:",
            self.network, self.backend_host, epoch, KEY_VERSION, self.policy_hash
        )
    }

    /// Prefix of the chain state (index, tip, leader lock).
    pub fn chain_key_prefix(&self) -> String {
        format!("ohttp:{}:{}:chain:v1:", self.network, self.backend_host)
    }

    /// Writes `value` under `cache_key` only if the shared epoch still equals `epoch_at_read`.
    /// Returns whether the entry was written.
    ///
    /// The epoch lives in the security Redis while entries live in the cache Redis, so the
    /// check reads the epoch from the security connection; no single-server script can span
    /// both servers. A reorg or operator bump landing between the epoch read and the write is
    /// harmless because the key embeds `epoch_at_read` and readers use the new epoch's keys.
    /// Without a security connection (single Redis) the check stays one atomic script.
    async fn write_if_epoch_current(
        &self,
        cache_key: &str,
        epoch_at_read: u64,
        value: &[u8],
        ttl: Option<u64>,
    ) -> redis::RedisResult<bool> {
        let epoch_key = format!("epoch:{}", self.network);
        let mut cache_conn = match self.cache_conn.load_full().map(|c| (*c).clone()) {
            Some(c) => c,
            None => return Ok(false),
        };

        if let Some(sec) = self.security_conn.as_ref() {
            let current: redis::RedisResult<Option<u64>> = redis::cmd("GET")
                .arg(&epoch_key)
                .query_async(&mut sec.get())
                .await;
            sec.observe(&current);
            let current = current?;
            if current != Some(epoch_at_read) {
                return Ok(false);
            }
            let mut cmd = redis::cmd("SET");
            cmd.arg(cache_key).arg(value);
            if let Some(t) = ttl {
                cmd.arg("EX").arg(t);
            }
            cmd.query_async::<_, ()>(&mut cache_conn).await?;
            return Ok(true);
        }

        let lua_script = r#"
            local epoch_key = KEYS[1]
            local cache_key = KEYS[2]
            local expected_epoch = tonumber(ARGV[1])
            local value = ARGV[2]
            local ttl = tonumber(ARGV[3])

            local current_epoch = tonumber(redis.call('GET', epoch_key) or '0')
            if current_epoch == expected_epoch then
                if ttl > 0 then
                    redis.call('SET', cache_key, value, 'EX', ttl)
                else
                    redis.call('SET', cache_key, value)
                end
                return 1
            else
                return 0
            end
        "#;
        let written: i32 = redis::Script::new(lua_script)
            .key(&epoch_key)
            .key(cache_key)
            .arg(epoch_at_read)
            .arg(value)
            .arg(ttl.unwrap_or(0))
            .invoke_async(&mut cache_conn)
            .await?;
        Ok(written == 1)
    }

    /// Serve from cache, or call `fetch`, store and return (the collecting proxy path).
    /// `fetch` returns a bincode `InnerResponse`.
    #[allow(clippy::too_many_arguments)]
    pub async fn get_or_fetch<F, Fut>(
        &self,
        method: &str,
        content_type: &str,
        path: &str,
        headers: &[(String, String)],
        body: &[u8],
        cache_get_semaphore: &tokio::sync::Semaphore,
        fetch: F,
    ) -> anyhow::Result<Vec<u8>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<Vec<u8>>>,
    {
        match self
            .lookup(
                method,
                content_type,
                path,
                headers,
                body,
                cache_get_semaphore,
            )
            .await
        {
            CacheLookup::Hit(bytes) => Ok(bytes),
            CacheLookup::Bypass => fetch().await,
            CacheLookup::Miss(ticket) => {
                let response = fetch().await?;
                self.store(ticket, &response).await;
                Ok(response)
            }
        }
    }

    /// The read half: Authorization bypass, the pinned tier first, then the chain-validated
    /// policy of `rpc_cache`. Records the cache metrics.
    pub async fn lookup(
        &self,
        method: &str,
        content_type: &str,
        path: &str,
        headers: &[(String, String)],
        body: &[u8],
        cache_get_semaphore: &tokio::sync::Semaphore,
    ) -> CacheLookup {
        let rpc = crate::health::normalize_rpc_name(path, method);
        if headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        {
            debug!(path, network = %self.network, "cache bypass (authorization header)");
            crate::health::record_cache_request(&self.network, &rpc, "bypass");
            return CacheLookup::Bypass;
        }
        if self.cache_conn.load().is_none() {
            debug!(network = %self.network, "Cache not connected, bypassing");
            crate::health::record_cache_request(&self.network, &rpc, "bypass");
            return CacheLookup::Bypass;
        }
        let Ok(_permit) = cache_get_semaphore.try_acquire() else {
            debug!("Cache-get semaphore exhausted, bypassing cache");
            crate::health::record_cache_request(&self.network, &rpc, "semaphore_full");
            return CacheLookup::Bypass;
        };

        let pinned_height = self.pinned_height(method, path, body);
        if let Some(height) = pinned_height {
            if let Some(bytes) = self.pinned_get(height).await {
                debug!(height, network = %self.network, "pinned hit");
                crate::health::record_cache_request(&self.network, &rpc, "pinned_hit");
                return CacheLookup::Hit(bytes);
            }
            crate::health::record_cache_request(&self.network, &rpc, "pinned_miss");
        }

        match rpc_cache::lookup(self, &self.network, method, content_type, path, body).await {
            CacheLookup::Miss(mut miss) => {
                miss.pinned_height = pinned_height;
                CacheLookup::Miss(miss)
            }
            other => other,
        }
    }

    /// The write half: admit `response` (a bincode `InnerResponse`) under the miss ticket and
    /// write it through to the pinned tier when the request was pinned.
    pub async fn store(&self, miss: CacheMiss, response: &[u8]) {
        let pinned_height = miss.pinned_height;
        rpc_cache::store(self, &self.network, miss, response).await;
        if let Some(height) = pinned_height {
            self.pinned_put(height, response).await;
        }
    }

    /// The current cache epoch: third-party answer keys include it, so an epoch bump flushes
    /// them with the other epoch-scoped entries.
    pub fn current_epoch(&self) -> u64 {
        self.epoch.load(Ordering::Relaxed)
    }

    /// Read a third-party answer (`third_party_cache`). Fail-open: a Redis error or timeout is
    /// a miss.
    pub async fn get_third_party(&self, key: &str) -> Option<Vec<u8>> {
        let conn = self.cache_conn.load_full()?;
        let mut conn = (*conn).clone();
        match timeout(self.redis_timeout, conn.get::<_, Option<Vec<u8>>>(key)).await {
            Ok(Ok(data)) => data,
            Ok(Err(e)) => {
                if crate::health::warn_due(&self.network, "third_party_get") {
                    warn!(network = %self.network, error = %store_error(&e), "third-party cache get error");
                }
                None
            }
            Err(_) => {
                crate::health::record_cache_redis_timeout(&self.network, "third_party_get");
                None
            }
        }
    }

    /// Store a third-party answer for `ttl_secs`. Fail-open: an error only logs.
    pub async fn put_third_party(&self, key: &str, data: &[u8], ttl_secs: u64) {
        let Some(conn) = self.cache_conn.load_full() else {
            return;
        };
        let mut conn = (*conn).clone();
        match timeout(
            self.redis_timeout,
            conn.set_ex::<_, _, ()>(key, data, ttl_secs),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                if crate::health::warn_due(&self.network, "third_party_put") {
                    warn!(network = %self.network, error = %store_error(&e), "third-party cache put error");
                }
            }
            Err(_) => crate::health::record_cache_redis_timeout(&self.network, "third_party_put"),
        }
    }
}

/// The chain-validated cache's store, on the cache Redis (allkeys-lru, fail-open).
impl CacheStore for ResponseCache {
    fn epoch(&self) -> BoxFuture<'_, u64> {
        Box::pin(self.refresh_epoch_if_stale())
    }

    fn key_prefix(&self, epoch: u64) -> String {
        self.key_prefix_for_epoch(epoch)
    }

    fn chain_prefix(&self) -> String {
        self.chain_key_prefix()
    }

    fn tip_cell(&self) -> &TipCell {
        &self.tip
    }

    fn mget(&self, keys: Vec<String>) -> BoxFuture<'_, Vec<Option<Bytes>>> {
        Box::pin(async move {
            let n = keys.len();
            if n == 0 {
                return Vec::new();
            }
            let Some(conn) = self.cache_conn.load_full() else {
                return vec![None; n];
            };
            let mut conn = (*conn).clone();
            let mut cmd = redis::cmd("MGET");
            cmd.arg(&keys);
            let fut = cmd.query_async::<_, Vec<Option<Vec<u8>>>>(&mut conn);
            match timeout(self.redis_timeout, fut).await {
                Ok(Ok(values)) if values.len() == n => {
                    values.into_iter().map(|v| v.map(Bytes::from)).collect()
                }
                Ok(Ok(_)) => vec![None; n],
                Ok(Err(e)) => {
                    if crate::health::warn_due(&self.network, "cache_mget") {
                        warn!(network = %self.network, error = %store_error(&e), "cache mget error");
                    }
                    crate::health::record_cache_redis_timeout(&self.network, "mget_error");
                    vec![None; n]
                }
                Err(_) => {
                    if crate::health::warn_due(&self.network, "cache_mget_timeout") {
                        warn!(network = %self.network, timeout_ms = self.redis_timeout.as_millis(), "cache mget timeout");
                    }
                    crate::health::record_cache_redis_timeout(&self.network, "mget_timeout");
                    vec![None; n]
                }
            }
        })
    }

    fn set(
        &self,
        key: String,
        value: Bytes,
        ttl_secs: Option<u64>,
        epoch: Option<u64>,
    ) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let result = match epoch {
                Some(e) => {
                    timeout(
                        self.redis_timeout,
                        self.write_if_epoch_current(&key, e, &value, ttl_secs),
                    )
                    .await
                }
                None => {
                    let Some(conn) = self.cache_conn.load_full() else {
                        return;
                    };
                    let mut conn = (*conn).clone();
                    let mut cmd = redis::cmd("SET");
                    cmd.arg(&key).arg(&value[..]);
                    if let Some(t) = ttl_secs {
                        cmd.arg("EX").arg(t);
                    }
                    timeout(self.redis_timeout, async move {
                        cmd.query_async::<_, ()>(&mut conn).await.map(|_| true)
                    })
                    .await
                }
            };
            match result {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    if crate::health::warn_due(&self.network, "cache_set") {
                        warn!(network = %self.network, error = %store_error(&e), "cache set error");
                    }
                    crate::health::record_cache_redis_timeout(&self.network, "set_error");
                }
                Err(_) => {
                    crate::health::record_cache_redis_timeout(&self.network, "set_timeout");
                }
            }
        })
    }

    fn del(&self, keys: Vec<String>) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if keys.is_empty() {
                return;
            }
            let Some(conn) = self.cache_conn.load_full() else {
                return;
            };
            let mut conn = (*conn).clone();
            let mut cmd = redis::cmd("DEL");
            cmd.arg(&keys);
            let fut = cmd.query_async::<_, i64>(&mut conn);
            match timeout(self.redis_timeout, fut).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    if crate::health::warn_due(&self.network, "cache_del") {
                        warn!(network = %self.network, error = %store_error(&e), "cache del error");
                    }
                    crate::health::record_cache_redis_timeout(&self.network, "del_error");
                }
                Err(_) => {
                    crate::health::record_cache_redis_timeout(&self.network, "del_timeout");
                }
            }
        })
    }

    fn set_nx_px(&self, key: String, value: String, ttl_ms: u64) -> BoxFuture<'_, Option<bool>> {
        Box::pin(async move {
            let conn = self.cache_conn.load_full()?;
            let mut conn = (*conn).clone();
            let mut cmd = redis::cmd("SET");
            cmd.arg(&key).arg(&value).arg("NX").arg("PX").arg(ttl_ms);
            let fut = cmd.query_async::<_, Option<String>>(&mut conn);
            match timeout(self.redis_timeout, fut).await {
                Ok(Ok(v)) => Some(v.is_some()),
                Ok(Err(e)) => {
                    warn!(network = %self.network, error = %store_error(&e), "leader lock set error");
                    crate::health::record_cache_redis_timeout(&self.network, "lock_error");
                    None
                }
                Err(_) => {
                    crate::health::record_cache_redis_timeout(&self.network, "lock_timeout");
                    None
                }
            }
        })
    }

    fn pexpire_if_equal(
        &self,
        key: String,
        value: String,
        ttl_ms: u64,
    ) -> BoxFuture<'_, Option<bool>> {
        Box::pin(async move {
            let conn = self.cache_conn.load_full()?;
            let mut conn = (*conn).clone();
            let script = r#"
                if redis.call('GET', KEYS[1]) == ARGV[1] then
                    return redis.call('PEXPIRE', KEYS[1], ARGV[2])
                else
                    return 0
                end
            "#;
            let script = redis::Script::new(script);
            let mut invocation = script.key(&key);
            invocation.arg(&value).arg(ttl_ms);
            let fut = invocation.invoke_async::<_, i64>(&mut conn);
            match timeout(self.redis_timeout, fut).await {
                Ok(Ok(v)) => Some(v == 1),
                Ok(Err(e)) => {
                    warn!(network = %self.network, error = %store_error(&e), "leader lock renew error");
                    crate::health::record_cache_redis_timeout(&self.network, "lock_error");
                    None
                }
                Err(_) => {
                    crate::health::record_cache_redis_timeout(&self.network, "lock_timeout");
                    None
                }
            }
        })
    }

    fn take_lock_if(
        &self,
        key: String,
        value: String,
        ttl_ms: u64,
        guard_key: String,
        guard: Bytes,
        holder: Option<String>,
    ) -> BoxFuture<'_, Option<bool>> {
        Box::pin(async move {
            let conn = self.cache_conn.load_full()?;
            let mut conn = (*conn).clone();
            // ARGV[4] = the holder the caller observed, '' = none (a holder is never empty).
            let script = r#"
                if redis.call('GET', KEYS[2]) ~= ARGV[3] then
                    return 0
                end
                local holder = redis.call('GET', KEYS[1])
                if ARGV[4] == '' then
                    if holder then
                        return 0
                    end
                elseif holder ~= ARGV[4] then
                    return 0
                end
                redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
                return 1
            "#;
            let script = redis::Script::new(script);
            let mut invocation = script.key(&key);
            invocation
                .key(&guard_key)
                .arg(&value)
                .arg(ttl_ms)
                .arg(&guard[..])
                .arg(holder.as_deref().unwrap_or(""));
            let fut = invocation.invoke_async::<_, i64>(&mut conn);
            match timeout(self.redis_timeout, fut).await {
                Ok(Ok(v)) => Some(v == 1),
                Ok(Err(e)) => {
                    warn!(network = %self.network, error = %store_error(&e), "leader lock takeover error");
                    crate::health::record_cache_redis_timeout(&self.network, "lock_error");
                    None
                }
                Err(_) => {
                    crate::health::record_cache_redis_timeout(&self.network, "lock_timeout");
                    None
                }
            }
        })
    }

    fn set_if_lock_held(
        &self,
        lock: String,
        value: String,
        ttl_ms: u64,
        entries: Vec<(String, Bytes, u64)>,
    ) -> BoxFuture<'_, Option<bool>> {
        Box::pin(async move {
            let conn = self.cache_conn.load_full()?;
            let mut conn = (*conn).clone();
            // KEYS[1] = the lock, KEYS[2..] the entries; ARGV[1] = the holder, ARGV[2] = the lock
            // TTL (ms), then value + TTL (s, 0 = none) per entry: KEYS[i] -> ARGV[2i-1], ARGV[2i].
            // Only the exact holder writes: an absent lock (lapsed, or released by a process
            // that took over meanwhile) refuses too.
            let script = r#"
                if redis.call('GET', KEYS[1]) ~= ARGV[1] then
                    return 0
                end
                redis.call('PEXPIRE', KEYS[1], ARGV[2])
                for i = 2, #KEYS do
                    if tonumber(ARGV[2 * i]) > 0 then
                        redis.call('SET', KEYS[i], ARGV[2 * i - 1], 'EX', ARGV[2 * i])
                    else
                        redis.call('SET', KEYS[i], ARGV[2 * i - 1])
                    end
                end
                return 1
            "#;
            let script = redis::Script::new(script);
            let mut invocation = script.key(&lock);
            invocation.arg(&value).arg(ttl_ms);
            for (k, v, ttl) in &entries {
                invocation.key(k).arg(&v[..]).arg(*ttl);
            }
            let fut = invocation.invoke_async::<_, i64>(&mut conn);
            match timeout(self.redis_timeout, fut).await {
                Ok(Ok(v)) => Some(v == 1),
                Ok(Err(e)) => {
                    warn!(network = %self.network, error = %store_error(&e), "fenced chain write error");
                    crate::health::record_cache_redis_timeout(&self.network, "lock_error");
                    None
                }
                Err(_) => {
                    crate::health::record_cache_redis_timeout(&self.network, "lock_timeout");
                    None
                }
            }
        })
    }

    fn del_if_lock_held(
        &self,
        lock: String,
        value: String,
        keys: Vec<String>,
    ) -> BoxFuture<'_, Option<bool>> {
        Box::pin(async move {
            let conn = self.cache_conn.load_full()?;
            let mut conn = (*conn).clone();
            let script = r#"
                if redis.call('GET', KEYS[1]) ~= ARGV[1] then
                    return 0
                end
                for i = 2, #KEYS do
                    redis.call('DEL', KEYS[i])
                end
                return 1
            "#;
            let script = redis::Script::new(script);
            let mut invocation = script.key(&lock);
            invocation.arg(&value);
            for k in &keys {
                invocation.key(k);
            }
            let fut = invocation.invoke_async::<_, i64>(&mut conn);
            match timeout(self.redis_timeout, fut).await {
                Ok(Ok(v)) => Some(v == 1),
                Ok(Err(e)) => {
                    warn!(network = %self.network, error = %store_error(&e), "fenced index delete error");
                    crate::health::record_cache_redis_timeout(&self.network, "lock_error");
                    None
                }
                Err(_) => {
                    crate::health::record_cache_redis_timeout(&self.network, "lock_timeout");
                    None
                }
            }
        })
    }

    fn set_max_u32(
        &self,
        key: String,
        value: u32,
        ttl_secs: u64,
        epoch: u64,
    ) -> BoxFuture<'_, Option<bool>> {
        Box::pin(async move {
            if !self.epoch_current(epoch).await? {
                return Some(false);
            }
            let conn = self.cache_conn.load_full()?;
            let mut conn = (*conn).clone();
            // The stored value as a big-endian u32 (4 bytes; anything else is replaced).
            let script = r#"
                local cur = redis.call('GET', KEYS[1])
                if cur and string.len(cur) == 4 then
                    local a, b, c, d = string.byte(cur, 1, 4)
                    if ((a * 256 + b) * 256 + c) * 256 + d >= tonumber(ARGV[2]) then
                        return 0
                    end
                end
                redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[3])
                return 1
            "#;
            let script = redis::Script::new(script);
            let mut invocation = script.key(&key);
            invocation
                .arg(&value.to_be_bytes()[..])
                .arg(value)
                .arg(ttl_secs);
            let fut = invocation.invoke_async::<_, i64>(&mut conn);
            match timeout(self.redis_timeout, fut).await {
                Ok(Ok(v)) => Some(v == 1),
                Ok(Err(e)) => {
                    warn!(network = %self.network, error = %store_error(&e), "cache max write error");
                    crate::health::record_cache_redis_timeout(&self.network, "set_error");
                    None
                }
                Err(_) => {
                    crate::health::record_cache_redis_timeout(&self.network, "set_timeout");
                    None
                }
            }
        })
    }

    fn epoch_current(&self, epoch: u64) -> BoxFuture<'_, Option<bool>> {
        Box::pin(async move {
            // Where the epoch lives, as in `write_if_epoch_current`: the security Redis, or the
            // cache Redis without one (absent = 0).
            let current: Option<u64> = match self.security_conn.as_ref() {
                Some(sec) => {
                    let r = timeout(
                        self.redis_timeout,
                        redis::cmd("GET")
                            .arg(format!("epoch:{}", self.network))
                            .query_async::<_, Option<u64>>(&mut sec.get()),
                    )
                    .await;
                    sec.observe_timed(&r);
                    match r {
                        Ok(Ok(v)) => v,
                        _ => return None,
                    }
                }
                None => {
                    let conn = self.cache_conn.load_full()?;
                    let mut conn = (*conn).clone();
                    let r = timeout(
                        self.redis_timeout,
                        redis::cmd("GET")
                            .arg(format!("epoch:{}", self.network))
                            .query_async::<_, Option<u64>>(&mut conn),
                    )
                    .await;
                    match r {
                        Ok(Ok(v)) => Some(v.unwrap_or(0)),
                        _ => return None,
                    }
                }
            };
            Some(current == Some(epoch))
        })
    }

    fn lock_holder(&self, key: String) -> BoxFuture<'_, Option<Option<String>>> {
        Box::pin(async move {
            let conn = self.cache_conn.load_full()?;
            let mut conn = (*conn).clone();
            let fut = conn.get::<_, Option<String>>(&key);
            match timeout(self.redis_timeout, fut).await {
                Ok(Ok(v)) => Some(v),
                Ok(Err(e)) => {
                    warn!(network = %self.network, error = %store_error(&e), "leader lock read error");
                    crate::health::record_cache_redis_timeout(&self.network, "lock_error");
                    None
                }
                Err(_) => {
                    crate::health::record_cache_redis_timeout(&self.network, "lock_timeout");
                    None
                }
            }
        })
    }

    fn release_lock(&self, key: String, value: String) -> BoxFuture<'_, Option<bool>> {
        Box::pin(async move {
            let conn = self.cache_conn.load_full()?;
            let mut conn = (*conn).clone();
            let script = r#"
                if redis.call('GET', KEYS[1]) == ARGV[1] then
                    return redis.call('DEL', KEYS[1])
                else
                    return 0
                end
            "#;
            let script = redis::Script::new(script);
            let mut invocation = script.key(&key);
            invocation.arg(&value);
            let fut = invocation.invoke_async::<_, i64>(&mut conn);
            match timeout(self.redis_timeout, fut).await {
                Ok(Ok(v)) => Some(v == 1),
                Ok(Err(e)) => {
                    warn!(network = %self.network, error = %store_error(&e), "leader lock release error");
                    crate::health::record_cache_redis_timeout(&self.network, "lock_error");
                    None
                }
                Err(_) => {
                    crate::health::record_cache_redis_timeout(&self.network, "lock_timeout");
                    None
                }
            }
        })
    }
}

/// The permanent block tier on a disk-backed Redis-protocol store. Plain PING/GET/MGET/SET/MSET/DEL
/// only: no TTL, no epoch check, no Lua, so it works on any store that implements those.
/// Fail-open with the same operation timeout as the cache; errors are counted under
/// `ohttp_redis_op_timeout_total` with `perm_*` operations.
#[derive(Clone)]
pub struct PermanentRedis {
    /// `Role::Any`: some origins read a replica of this store on purpose, so only a broken or
    /// hung connection is replaced.
    conn: Arc<StoreConn>,
    timeout: Duration,
    network: String,
    /// The store is a read-only replica (`INFO replication` says so, or a write was refused with
    /// `READONLY`): writes are skipped, and the callers keep final data in the cache tier.
    replica: Arc<AtomicBool>,
}

/// `role:` of an `INFO replication` answer: Some(true) for a replica (`slave`), Some(false) for
/// a primary, None when absent.
pub fn info_replication_is_replica(info: &str) -> Option<bool> {
    info.lines().find_map(|l| {
        let role = l.trim().strip_prefix("role:")?;
        Some(matches!(role.trim(), "slave" | "replica"))
    })
}

impl PermanentRedis {
    pub async fn connect(url: &str, op_timeout_ms: u64, network: String) -> anyhow::Result<Self> {
        let conn = StoreConn::connect(url, "permanent", network.clone(), Role::Any).await?;
        let this = Self {
            conn,
            timeout: Duration::from_millis(op_timeout_ms),
            network,
            replica: Arc::new(AtomicBool::new(false)),
        };
        // Fail startup on an unreachable store so a misconfiguration is visible; the request
        // paths stay fail-open afterwards.
        let mut c = this.conn.get();
        let pong: String = timeout(this.timeout, redis::cmd("PING").query_async(&mut c)).await??;
        anyhow::ensure!(pong == "PONG", "permanent store PING answered {pong}");
        this.refresh_role().await;
        Ok(this)
    }

    /// Ask the store for its role (`INFO replication`) and remember it; an unanswered or
    /// unparsable probe keeps the last known role.
    pub async fn refresh_role(&self) {
        let r = timeout(
            self.timeout,
            redis::cmd("INFO")
                .arg("replication")
                .query_async::<_, String>(&mut self.conn.get()),
        )
        .await;
        if let Ok(Ok(info)) = r {
            if let Some(replica) = info_replication_is_replica(&info) {
                self.set_replica(replica);
            }
        }
    }

    fn set_replica(&self, replica: bool) {
        if self.replica.swap(replica, Ordering::Relaxed) != replica {
            if replica {
                info!(network = %self.network, "permanent store is a read-only replica: its writes are skipped");
            } else {
                info!(network = %self.network, "permanent store is a primary: writes resume");
            }
        }
        crate::health::record_permanent_replica(&self.network, replica);
    }

    /// Skip a write while the store is a replica (counted).
    fn skip_write(&self, op: &str) -> bool {
        let skip = self.replica.load(Ordering::Relaxed);
        if skip {
            crate::health::record_permanent_write_skipped(&self.network, op);
        }
        skip
    }

    /// `PING`, for the housekeeping gauge.
    pub async fn ping(&self) -> bool {
        let r = timeout(
            self.timeout,
            redis::cmd("PING").query_async::<_, String>(&mut self.conn.get()),
        )
        .await;
        self.conn.observe_timed(&r);
        matches!(r, Ok(Ok(p)) if p == "PONG")
    }

    /// Run `cmd`, mapping errors and timeouts to `None` and counting them.
    async fn run<T: redis::FromRedisValue + Send>(&self, op: &str, cmd: redis::Cmd) -> Option<T> {
        let mut c = self.conn.get();
        let r = timeout(self.timeout, cmd.query_async::<_, T>(&mut c)).await;
        self.conn.observe_timed(&r);
        match r {
            Ok(Ok(v)) => Some(v),
            Ok(Err(e)) if e.kind() == redis::ErrorKind::ReadOnly => {
                // A replica (the role probe has not seen it yet): stop writing at once.
                self.set_replica(true);
                crate::health::record_permanent_write_skipped(&self.network, op);
                None
            }
            Ok(Err(e)) => {
                if crate::health::warn_due(&self.network, "permanent_store") {
                    warn!(network = %self.network, op, error = %store_error(&e), "permanent store error");
                }
                crate::health::record_cache_redis_timeout(
                    &self.network,
                    &format!("perm_{op}_error"),
                );
                None
            }
            Err(_) => {
                crate::health::record_cache_redis_timeout(
                    &self.network,
                    &format!("perm_{op}_timeout"),
                );
                None
            }
        }
    }
}

impl PermanentStore for PermanentRedis {
    fn mget(&self, keys: Vec<String>) -> BoxFuture<'_, Vec<Option<Bytes>>> {
        Box::pin(async move {
            let n = keys.len();
            if n == 0 {
                return Vec::new();
            }
            let mut cmd = redis::cmd("MGET");
            cmd.arg(&keys);
            match self.run::<Vec<Option<Vec<u8>>>>("mget", cmd).await {
                Some(values) if values.len() == n => {
                    values.into_iter().map(|v| v.map(Bytes::from)).collect()
                }
                _ => vec![None; n],
            }
        })
    }

    fn set(&self, key: String, value: Bytes) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            if self.skip_write("set") {
                return false;
            }
            let mut cmd = redis::cmd("SET");
            cmd.arg(&key).arg(&value[..]);
            self.run::<()>("set", cmd).await.is_some()
        })
    }

    /// `MSET` in chunks, flushed at 64 entries or once ~8 MiB is reached.
    fn set_many(&self, entries: Vec<(String, Bytes)>) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            if self.skip_write("mset") {
                return false;
            }
            let mut ok = true;
            let mut chunk: Vec<&(String, Bytes)> = Vec::new();
            let mut bytes = 0usize;
            let flush = |chunk: &mut Vec<&(String, Bytes)>, bytes: &mut usize| {
                let mut cmd = redis::cmd("MSET");
                for (k, v) in chunk.iter() {
                    cmd.arg(k).arg(&v[..]);
                }
                chunk.clear();
                *bytes = 0;
                cmd
            };
            for e in &entries {
                chunk.push(e);
                bytes += e.1.len();
                if chunk.len() >= 64 || bytes >= 8 * 1024 * 1024 {
                    let cmd = flush(&mut chunk, &mut bytes);
                    ok &= self.run::<()>("mset", cmd).await.is_some();
                }
            }
            if !chunk.is_empty() {
                let cmd = flush(&mut chunk, &mut bytes);
                ok &= self.run::<()>("mset", cmd).await.is_some();
            }
            ok
        })
    }

    fn del(&self, keys: Vec<String>) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if keys.is_empty() || self.skip_write("del") {
                return;
            }
            let mut cmd = redis::cmd("DEL");
            cmd.arg(&keys);
            self.run::<i64>("del", cmd).await;
        })
    }

    fn writable(&self) -> bool {
        !self.replica.load(Ordering::Relaxed)
    }
}

/// Ping the permanent store every `HOUSEKEEPING_SECS` for `ohttp_permanent_store_connected`,
/// and check its role (a replica takes no writes; a promoted one takes them again).
pub fn spawn_permanent_housekeeping(store: PermanentRedis) {
    tokio::spawn(async move {
        loop {
            let ok = store.ping().await;
            crate::health::record_permanent_connected(&store.network, ok);
            if ok {
                store.refresh_role().await;
            } else {
                warn!(network = %store.network, "permanent store PING failed");
            }
            tokio::time::sleep(Duration::from_secs(HOUSEKEEPING_SECS)).await;
        }
    });
}

/// `REPLAY_STARTUP_STORES_WAIT_SECS` default.
pub const DEFAULT_REPLAY_STARTUP_STORES_WAIT_SECS: u64 = 10;

/// `REPLAY_STARTUP_STORES_WAIT_SECS` (default 10; 0 = do not wait).
pub fn startup_stores_wait_from_env() -> anyhow::Result<Duration> {
    match std::env::var("REPLAY_STARTUP_STORES_WAIT_SECS") {
        Ok(v) if !v.trim().is_empty() => match v.trim().parse::<u64>() {
            Ok(n) => Ok(Duration::from_secs(n)),
            Err(_) => anyhow::bail!(
                "REPLAY_STARTUP_STORES_WAIT_SECS must be a non-negative integer, got '{v}'"
            ),
        },
        _ => Ok(Duration::from_secs(DEFAULT_REPLAY_STARTUP_STORES_WAIT_SECS)),
    }
}

impl ResponseCache {
    /// Whether every store a WRITE needs for both-store admission has a connection: every
    /// replay peer (REPLAY_PEER_URLS) and every standby store (REPLAY_STANDBY_URLS), each with at
    /// least one open `WAIT` connection where their replica acknowledgement is required, and the
    /// local `WAIT` pool a usable connection. All are connected in the background at startup.
    pub fn replay_stores_connected(&self) -> bool {
        self.replay_peers.as_ref().is_none_or(|p| p.all_ready())
            && self.standby_peers.as_ref().is_none_or(|p| p.all_ready())
            && self
                .write_wait
                .as_ref()
                .is_none_or(|w| w.conns.iter().any(|c| c.usable_now()))
    }
}

/// Startup gate (`REPLAY_STARTUP_STORES_WAIT_SECS`): until every replay peer and standby store
/// is connected, or `bound` has passed, `/healthz` answers 503 (`ohttp_replay_stores_pending`
/// 1), so a load balancer does not send a pod WRITEs it would refuse because a second store is
/// not connected yet. After `bound` the pod reports ready anyway, with a warning: a store that
/// stays unreachable is an outage the WRITE policies handle, not a reason never to start.
/// Returns whether every store connected in time.
pub fn spawn_replay_stores_gate(
    cache: ResponseCache,
    bound: Duration,
) -> tokio::task::JoinHandle<bool> {
    let network = cache.network.clone();
    let pending = !cache.replay_stores_connected();
    crate::health::record_replay_stores_pending(&network, pending);
    tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + bound;
        while !cache.replay_stores_connected() {
            if tokio::time::Instant::now() >= deadline {
                warn!(network = %network, bound_secs = bound.as_secs(), "Not every replay peer / standby store connected at startup within REPLAY_STARTUP_STORES_WAIT_SECS: reporting ready; WRITEs that need a store that is not connected fail closed");
                crate::health::record_replay_stores_pending(&network, false);
                return false;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        crate::health::record_replay_stores_pending(&network, false);
        true
    })
}

/// Spawn the Redis housekeeping task: sync the shared epoch and PING both Redis roles every
/// `HOUSEKEEPING_SECS`, updating `ohttp_redis_connected`. (The tip is the chain follower's.)
pub fn spawn_redis_housekeeping(cache: ResponseCache) {
    tokio::spawn(async move {
        let redis_ok = cache.housekeeping_round().await;
        crate::health::record_redis_connected(&cache.network, redis_ok);
        if redis_ok {
            info!(network = %cache.network, "Redis PING successful on startup");
        } else {
            warn!(network = %cache.network, "Redis PING failed on startup, will retry");
        }
        loop {
            tokio::time::sleep(Duration::from_secs(HOUSEKEEPING_SECS)).await;
            let redis_ok = cache.housekeeping_round().await;
            debug!(network = %cache.network, epoch = cache.current_epoch(), "Housekeeping round done");
            crate::health::record_redis_connected(&cache.network, redis_ok);
            if !redis_ok {
                if crate::health::warn_due(&cache.network, "housekeeping_failed") {
                    warn!(network = %cache.network, "Redis connectivity check failed, will retry");
                }
            }
        }
    });
}

/// Spawn a background task that retries cache Redis connection with exponential backoff.
/// Backs off from 1s to 60s max. Stops once connection succeeds.
fn spawn_cache_reconnect_task(cache: ResponseCache) {
    tokio::spawn(async move {
        let mut backoff_secs = 1u64;
        const MAX_BACKOFF: u64 = 60;

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(backoff_secs)).await;

            info!(
                network = %cache.network,
                backoff_secs,
                "Attempting to reconnect to Redis cache..."
            );

            if cache.try_reconnect_cache().await {
                crate::health::record_cache_redis_connected(&cache.network, true);
                info!(network = %cache.network, "Redis cache connection established, stopping retry task");
                return;
            }

            backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF);
            crate::health::record_cache_redis_connected(&cache.network, false);
        }
    });
}

/// The store pinned entries are written to, bound to the generation of the choice
/// (`pinned_writer_gen`, see `ResponseCache::pinned_writer_bound`). The backfill workers and
/// the sweep claim, check and write through one such handle: a height claimed on one store's
/// cursor is never written to another. The generation is checked in this process before a
/// command is sent, not by the store: no entry, hole or mark is sent once another store was
/// chosen, while a command already sent completes on the store it was bound to (for an entry
/// an idempotent `SET NX` of a finalized height).
#[derive(Clone)]
struct PinnedWriter {
    conn: Arc<StoreConn>,
    generation: u64,
}

/// How a `pinned_fill` went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fill {
    Stored,
    /// The upstream answered, but no answer could be stored (a height that fails by itself).
    Answered,
    /// The upstream never answered (an outage: says nothing about the height).
    NoAnswer,
    /// Another store was chosen meanwhile (the writer's generation moved on): nothing was
    /// written; the caller chooses its store again.
    Superseded,
}

/// How `pinned_fill` runs its upstream calls.
#[derive(Clone, Copy)]
enum FillMode<'a> {
    /// Awaited in the fill (the backfill workers, which never abandon a fill).
    Inline,
    /// In a task of their own under one of these permits (the sweep, whose fills are abandoned
    /// on a change of store, a lost claim and the fill timeout): abandoning the fill drops only
    /// the wait, the call runs to its own end and its answer is dropped. Cancelling a call in
    /// flight can cost the node behind lightwalletd a slot.
    Detached(&'a Arc<tokio::sync::Semaphore>),
}

/// Fetch and store the pinned entry of `height` through `writer`: three attempts, with a pause
/// after each failed one. Stops at once, without a write, when `writer` is superseded. An
/// error status of the upstream says nothing about the height (lightwalletd answers every
/// failure of this call with the same status, an unreachable node included), so every failed
/// height is retried the same way. `mode`: how the upstream calls run (see [`FillMode`]); a
/// detached call that panicked is a failed attempt.
async fn pinned_fill<F, Fut>(
    cache: &ResponseCache,
    fetch: &F,
    height: u64,
    writer: &PinnedWriter,
    mode: FillMode<'_>,
) -> Fill
where
    F: Fn(u64) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<Vec<u8>>> + Send + 'static,
{
    let mut answered = false;
    for attempt in 0..3u64 {
        if !cache.pinned_writer_current(writer) {
            return Fill::Superseded;
        }
        let answer = match mode {
            FillMode::Inline => fetch(height).await,
            FillMode::Detached(permits) => {
                match detached_fetch(cache, fetch, height, writer, permits).await {
                    Some(answer) => answer,
                    None => return Fill::Superseded,
                }
            }
        };
        match answer {
            Ok(resp) => {
                answered = true;
                match cache.pinned_put_bound(writer, height, &resp).await {
                    Some(true) => return Fill::Stored,
                    Some(false) => {}
                    None => return Fill::Superseded,
                }
            }
            Err(e) => {
                debug!(network = %cache.network, height, error = %e, "pinned backfill fetch error");
            }
        }
        tokio::time::sleep(PINNED_FILL_PAUSE * (1 + attempt as u32 * 2)).await;
    }
    if answered {
        Fill::Answered
    } else {
        Fill::NoAnswer
    }
}

/// One detached attempt of `pinned_fill` (`FillMode::Detached`): wait for a permit, checking
/// `writer` every PINNED_FILL_PAUSE (the wait is not an attempt), check it again, then run the
/// call in a task of its own that holds the permit, and wait for it. None when `writer` was
/// superseded before the call started. When the caller stops waiting (the fill is abandoned)
/// the call goes on to its own end and nothing uses its answer; that is counted
/// (`result="pinned_fetch_detached"`).
async fn detached_fetch<F, Fut>(
    cache: &ResponseCache,
    fetch: &F,
    height: u64,
    writer: &PinnedWriter,
    permits: &Arc<tokio::sync::Semaphore>,
) -> Option<anyhow::Result<Vec<u8>>>
where
    F: Fn(u64) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<Vec<u8>>> + Send + 'static,
{
    let permit = loop {
        if !cache.pinned_writer_current(writer) {
            return None;
        }
        match timeout(PINNED_FILL_PAUSE, permits.clone().acquire_owned()).await {
            Ok(Ok(permit)) => break permit,
            Ok(Err(_)) => return Some(Err(anyhow::anyhow!("pinned sweep: no call permits"))),
            Err(_) => {
                #[cfg(test)]
                test_hooks::permit_waited(&cache.network);
            }
        }
    };
    if !cache.pinned_writer_current(writer) {
        return None;
    }
    let mut waiter = DetachedWaiter {
        network: &cache.network,
        call: spawn_with_permit(permit, fetch(height)),
        armed: true,
    };
    let joined = (&mut waiter.call).await;
    waiter.armed = false;
    Some(joined.unwrap_or_else(|e| Err(anyhow::anyhow!("pinned sweep: upstream call task: {e}"))))
}

/// Spawn `fut` holding `permit` until its task is gone: the permit is moved into the future
/// before the spawn, so it is released exactly once, whether the task completes, panics or is
/// dropped without ever running (a runtime that shuts down).
fn spawn_with_permit<T: Send + 'static>(
    permit: tokio::sync::OwnedSemaphorePermit,
    fut: impl std::future::Future<Output = T> + Send + 'static,
) -> tokio::task::JoinHandle<T> {
    tokio::spawn(async move {
        let _permit = permit;
        fut.await
    })
}

/// The wait for a detached upstream call: counts the call when the waiter is dropped before
/// its result arrived while the call is still running (`result="pinned_fetch_detached"`); not
/// once the result arrived, nor for a call that already ended in the same poll.
struct DetachedWaiter<'a, T> {
    network: &'a str,
    call: tokio::task::JoinHandle<T>,
    armed: bool,
}

impl<T> Drop for DetachedWaiter<'_, T> {
    fn drop(&mut self) {
        if self.armed && !self.call.is_finished() {
            crate::health::record_cache_request(
                self.network,
                "GetTreeState",
                "pinned_fetch_detached",
            );
        }
    }
}

/// How a fill under a sweep claim ended (`SweepClaim::fill`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SweepFill {
    /// The fill ran to its end (never `Fill::Superseded`).
    Done(Fill),
    /// The claim expired and was taken over: abandoned, the other holder decides.
    ClaimLost,
    /// Another store was chosen meanwhile: abandoned, nothing written.
    Superseded,
}

/// One process's claim of a part of the sweep (a batch, or the hole retries): `SET NX` with a
/// random token of its own and `PINNED_SWEEP_CLAIM_TTL`, renewed before every fill, released by
/// compare-and-delete, so a claim that expired and was taken over by another process is never
/// renewed or released by the first one.
struct SweepClaim<'a> {
    conn: &'a Arc<StoreConn>,
    key: String,
    token: String,
    budget: Duration,
}

impl<'a> SweepClaim<'a> {
    /// The claim, None when another process holds it (or the answer was lost: it expires).
    async fn take(
        conn: &'a Arc<StoreConn>,
        key: String,
        budget: Duration,
    ) -> anyhow::Result<Option<SweepClaim<'a>>> {
        let token = format!("{:016x}", rand::random::<u64>());
        let r = timeout(
            budget,
            redis::cmd("SET")
                .arg(&key)
                .arg(&token)
                .arg("NX")
                .arg("PX")
                .arg(PINNED_SWEEP_CLAIM_TTL.as_millis() as u64)
                .query_async::<_, Option<String>>(&mut conn.get()),
        )
        .await;
        conn.observe_timed(&r);
        match r {
            Ok(Ok(Some(_))) => Ok(Some(Self {
                conn,
                key,
                token,
                budget,
            })),
            Ok(Ok(None)) | Err(_) => Ok(None),
            Ok(Err(e)) => anyhow::bail!("pinned sweep: claim failed: {}", store_error(&e)),
        }
    }

    /// Extend the claim; false when it is no longer ours.
    async fn renew(&self) -> bool {
        #[cfg(test)]
        test_hooks::sweep_renewal(&self.key).await;
        let script = redis::Script::new(
            r"if redis.call('GET', KEYS[1]) == ARGV[1] then
                return redis.call('PEXPIRE', KEYS[1], ARGV[2])
              end
              return 0",
        );
        let r = timeout(
            self.budget,
            script
                .key(&self.key)
                .arg(&self.token)
                .arg(PINNED_SWEEP_CLAIM_TTL.as_millis() as u64)
                .invoke_async::<_, i64>(&mut self.conn.get()),
        )
        .await;
        self.conn.observe_timed(&r);
        matches!(r, Ok(Ok(1)))
    }

    /// `pinned_fill` of `height` through `writer` while the claim is held: bounded by
    /// PINNED_SWEEP_FILL_TIMEOUT and renewed during the fill. Abandoned when the claim was lost
    /// meanwhile (the other holder decides about the height), and when
    /// `writer` was superseded (nothing written; the next pass chooses its store again): that
    /// is checked every PINNED_SWEEP_SUPERSEDED_CHECK while the fill runs, so a fill whose
    /// upstream fetch hangs is abandoned (not renewed until the fill timeout) and the caller
    /// releases the claim. The check does not run while a renewal of the claim waits for the
    /// store, so the fill ends within PINNED_SWEEP_SUPERSEDED_CHECK plus the bound of one claim
    /// command (`pinned_cursor_timeout`: four store timeouts, at least the write timeout on a
    /// separate write store) of the change; the release of the claim that follows is one more
    /// such command, checked by its token. A renewal that fails once the store was replaced
    /// counts as superseded, not as a lost claim. The two reasons are told apart (`SweepFill`): only a superseded fill is
    /// counted as one.
    ///
    /// The upstream calls run detached (`FillMode::Detached`, under the cache's
    /// PINNED_SWEEP_FETCH_PERMITS): an abandoned fill (superseded, claim lost, fill timeout)
    /// stops waiting for its call in flight without cancelling it, and writes nothing of its
    /// answer. A fill that waits for a permit meanwhile is superseded, loses its claim or
    /// times out (`Fill::NoAnswer`) the same way.
    async fn fill<F, Fut>(
        &self,
        cache: &ResponseCache,
        fetch: &F,
        height: u64,
        writer: &PinnedWriter,
    ) -> SweepFill
    where
        F: Fn(u64) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<Vec<u8>>> + Send + 'static,
    {
        #[cfg(test)]
        let (fill_timeout, renew_every) = test_hooks::sweep_timings(&cache.network)
            .unwrap_or((PINNED_SWEEP_FILL_TIMEOUT, PINNED_SWEEP_CLAIM_TTL / 4));
        #[cfg(not(test))]
        let (fill_timeout, renew_every) = (PINNED_SWEEP_FILL_TIMEOUT, PINNED_SWEEP_CLAIM_TTL / 4);
        if !self.renew().await {
            return self.not_renewed(cache, writer);
        }
        let fill = timeout(
            fill_timeout,
            pinned_fill(
                cache,
                fetch,
                height,
                writer,
                FillMode::Detached(&cache.pinned_sweep_fetch_permits),
            ),
        );
        tokio::pin!(fill);
        let mut renewal = tokio::time::interval(renew_every);
        renewal.tick().await;
        let mut superseded = tokio::time::interval(PINNED_SWEEP_SUPERSEDED_CHECK);
        superseded.tick().await;
        loop {
            tokio::select! {
                outcome = &mut fill => {
                    return match outcome.unwrap_or(Fill::NoAnswer) {
                        Fill::Superseded => SweepFill::Superseded,
                        outcome => SweepFill::Done(outcome),
                    };
                }
                _ = superseded.tick() => {
                    if !cache.pinned_writer_current(writer) {
                        return SweepFill::Superseded;
                    }
                }
                _ = renewal.tick() => {
                    if !cache.pinned_writer_current(writer) {
                        return SweepFill::Superseded;
                    }
                    if !self.renew().await {
                        return self.not_renewed(cache, writer);
                    }
                }
            }
        }
    }

    /// Why a fill ends when the claim could not be renewed: the store was replaced meanwhile
    /// (its answer, or silence, says nothing about the claim), or the claim was lost.
    fn not_renewed(&self, cache: &ResponseCache, writer: &PinnedWriter) -> SweepFill {
        if cache.pinned_writer_current(writer) {
            SweepFill::ClaimLost
        } else {
            SweepFill::Superseded
        }
    }

    /// Move the shared mark `backfill_verified` forward to `to` (never back), only while the
    /// claim is ours: `Ok(Ok(false))` when it is not (nothing moved).
    async fn advance_mark(
        &self,
        cache: &ResponseCache,
        to: u64,
    ) -> Result<redis::RedisResult<bool>, tokio::time::error::Elapsed> {
        let script = redis::Script::new(
            r"if redis.call('GET', KEYS[2]) ~= ARGV[2] then return 0 end
              local cur = tonumber(redis.call('GET', KEYS[1]) or '0')
              if cur < tonumber(ARGV[1]) then redis.call('SET', KEYS[1], ARGV[1]) end
              return 1",
        );
        let r = timeout(
            self.budget,
            script
                .key(cache.pinned_verified_key())
                .key(&self.key)
                .arg(to)
                .arg(&self.token)
                .invoke_async::<_, i64>(&mut self.conn.get()),
        )
        .await;
        self.conn.observe_timed(&r);
        r.map(|r| r.map(|moved| moved == 1))
    }

    /// Delete the claim if it is still ours.
    async fn release(self) {
        let script = redis::Script::new(
            r"if redis.call('GET', KEYS[1]) == ARGV[1] then
                return redis.call('DEL', KEYS[1])
              end
              return 0",
        );
        let r = timeout(
            self.budget,
            script
                .key(&self.key)
                .arg(&self.token)
                .invoke_async::<_, i64>(&mut self.conn.get()),
        )
        .await;
        self.conn.observe_timed(&r);
        if let Ok(Err(e)) = &r {
            warn!(error = %store_error(e), "pinned sweep: claim release script failed");
        }
    }
}

/// The first height of the sweep batch `height` belongs to (batches are aligned to
/// PINNED_SWEEP_BATCH, so every process means the same heights by one batch).
fn sweep_batch_of(height: u64) -> u64 {
    height - height % PINNED_SWEEP_BATCH
}

/// What one sweep pass did (`pinned_sweep_pass`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SweepPass {
    /// Heights filled (holes and newly found gaps).
    filled: u64,
    /// The next height to check (the shared mark after the pass).
    next: u64,
    /// Heights that still could not be filled (`backfill_holes`), retried by later passes
    /// (None: the count could not be read).
    holes: Option<u64>,
}

/// One pass of the sweep behind the backfill cursor. The workers claim heights with `INCR`; a
/// claim whose reply is lost (a timeout) advanced the cursor without any worker knowing the
/// height, which used to be skipped for good, and so is a height a worker gave up on.
///
/// - First the holes earlier passes could not fill (the set `backfill_holes`, at most
///   PINNED_SWEEP_HOLES_PER_PASS of them) are tried again; one found present or filled leaves
///   the set. A hole below the lowest height that is filled (`pinned_fill_from`, recorded by a
///   version that asked for those heights, or left below the range start after the range was
///   raised) is dropped without asking the upstream; it is counted (`pinned_sweep_dropped`)
///   and logged (one line with their number at most once a minute) once the store has
///   removed it. That means the removal command as a whole was acknowledged (the removal from
///   the set together with the clean-up of its attempt count): if the store takes the first
///   and rejects the second, the hole is gone and not counted.
/// - Then every height from the shared mark `backfill_verified` (at least `pinned_fill_from`:
///   no height below it is checked or fetched) up to `margin` below the last
///   claimed one (no margin once a worker has claimed past the range end, i.e. the range is
///   done; never above the last final height) is checked with pipelined `EXISTS` on the store
///   the entries are written to, PINNED_SWEEP_BATCH at a time with a short pause between
///   batches. Batches are aligned to PINNED_SWEEP_BATCH, and each is first claimed for every
///   process (`SweepClaim`: a token of its own, renewed during every fill, released when done):
///   a batch another process sweeps ends this pass. The mark is read again once the batch is
///   claimed, and only the claim's holder moves it (a fenced script). A hole that failed
///   PINNED_SWEEP_HOLE_ATTEMPTS retries is dropped (`pinned_sweep_dropped`). A missing height is filled
///   (`result="pinned_sweep"`); one that cannot be is added to the holes
///   (`pinned_sweep_failed`). The mark moves past a batch only once every height of it is
///   present or a hole, so it covers a contiguous, fully handled prefix.
///
/// Everything goes through `writer` (the store the backfill uses, bound to the generation of
/// that choice): once another store is chosen, the pass writes nothing more there (no claim,
/// fill, hole or mark) and ends; the next pass chooses its store again. A fill in flight then
/// is abandoned within a second plus the bound of one claim command (see `SweepClaim::fill`), counted
/// (`pinned_sweep_superseded`; a fill whose claim was lost is not), and its claim released. The
/// upstream call of an abandoned fill is not cancelled: it runs to its own end and its answer is
/// not used (`pinned_fetch_detached`, see `FillMode::Detached`).
///
/// `Err` on a store error: the next pass resumes from the mark.
async fn pinned_sweep_pass<F, Fut>(
    cache: &ResponseCache,
    writer: &PinnedWriter,
    (start, end): (u64, u64),
    margin: u64,
    fetch: &F,
) -> anyhow::Result<SweepPass>
where
    F: Fn(u64) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<Vec<u8>>> + Send + 'static,
{
    let conn = &writer.conn;
    let current = || cache.pinned_writer_current(writer);
    // Every command of the pass goes to the store the entries are written to: bounded at
    // least like its writes.
    let budget = cache.pinned_cursor_timeout();
    let store_err = |what: &str, e: &redis::RedisError| {
        anyhow::anyhow!("pinned sweep: {what} failed: {}", store_error(e))
    };
    // Heights below it are never filled (no tree state exists there).
    let floor = start.max(cache.pinned_fill_from);
    let mut filled = 0u64;
    let mut record = |stored: bool| {
        filled += u64::from(stored);
        crate::health::record_cache_request(
            &cache.network,
            "GetTreeState",
            if stored {
                "pinned_sweep"
            } else {
                "pinned_sweep_failed"
            },
        );
    };
    // A fill abandoned because another store was chosen (not one whose claim was lost).
    let record_superseded = || {
        crate::health::record_cache_request(
            &cache.network,
            "GetTreeState",
            "pinned_sweep_superseded",
        )
    };
    // Holes below `floor` this pass removed (acknowledged by the store).
    let mut below_floor = 0u64;

    // The holes of earlier passes, retried by one process at a time.
    let holes_key = cache.pinned_holes_key();
    let attempts_key = cache.pinned_hole_attempts_key();
    let holes_claim = if current() {
        SweepClaim::take(conn, cache.pinned_sweep_claim_key_holes(), budget).await?
    } else {
        None
    };
    if let Some(claim) = holes_claim {
        let retried: anyhow::Result<()> = async {
            let holes = timeout(
                budget,
                redis::cmd("SRANDMEMBER")
                    .arg(&holes_key)
                    .arg(PINNED_SWEEP_HOLES_PER_PASS)
                    .query_async::<_, Vec<u64>>(&mut conn.get()),
            )
            .await;
            conn.observe_timed(&holes);
            let holes = holes
                .map_err(|_| anyhow::anyhow!("pinned sweep: hole read timed out"))?
                .map_err(|e| store_err("hole read", &e))?;
            for h in holes {
                // A hole below the heights that are filled (recorded by a version that asked
                // for them): dropped without asking the upstream.
                if h < floor {
                    if !current() {
                        break;
                    }
                    // Counted (and logged) only once the store has removed it: a store that
                    // refuses the removal keeps the hole, and a later pass drops it.
                    let r = timeout(
                        budget,
                        redis::pipe()
                            .cmd("SREM")
                            .arg(&holes_key)
                            .arg(h)
                            .cmd("HDEL")
                            .arg(&attempts_key)
                            .arg(h)
                            .ignore()
                            .query_async::<_, (u64,)>(&mut conn.get()),
                    )
                    .await;
                    conn.observe_timed(&r);
                    if matches!(r, Ok(Ok((removed,))) if removed > 0) {
                        below_floor += 1;
                        crate::health::record_cache_request(
                            &cache.network,
                            "GetTreeState",
                            "pinned_sweep_dropped",
                        );
                    }
                    continue;
                }
                let outcome = if cache.pinned_exists_at(conn, h).await {
                    Some(Fill::Stored)
                } else {
                    match claim.fill(cache, fetch, h, writer).await {
                        SweepFill::Done(outcome) => {
                            record(outcome == Fill::Stored);
                            Some(outcome)
                        }
                        SweepFill::Superseded => {
                            record_superseded();
                            break;
                        }
                        SweepFill::ClaimLost => break,
                    }
                };
                // Filled (or there): out of the holes. Failed with an upstream answer: one more attempt counted, and after
                // PINNED_SWEEP_HOLE_ATTEMPTS the hole is dropped. A pass during an upstream
                // outage (no answer) counts nothing. Nothing is recorded once another store was
                // chosen.
                if !current() {
                    break;
                }
                let drop_hole = if outcome == Some(Fill::Stored) {
                    true
                } else if outcome == Some(Fill::NoAnswer) {
                    false
                } else {
                    let r = timeout(
                        budget,
                        redis::cmd("HINCRBY")
                            .arg(&attempts_key)
                            .arg(h)
                            .arg(1)
                            .query_async::<_, u64>(&mut conn.get()),
                    )
                    .await;
                    conn.observe_timed(&r);
                    let dropped = matches!(r, Ok(Ok(n)) if n >= PINNED_SWEEP_HOLE_ATTEMPTS);
                    if dropped {
                        crate::health::record_cache_request(
                            &cache.network,
                            "GetTreeState",
                            "pinned_sweep_dropped",
                        );
                        if crate::health::warn_due(&cache.network, "pinned_hole_dropped") {
                            warn!(network = %cache.network, height = h, "pinned sweep: a height kept failing and is left to the write-through path");
                        }
                    }
                    dropped
                };
                if drop_hole {
                    let r = timeout(
                        budget,
                        redis::pipe()
                            .cmd("SREM")
                            .arg(&holes_key)
                            .arg(h)
                            .ignore()
                            .cmd("HDEL")
                            .arg(&attempts_key)
                            .arg(h)
                            .ignore()
                            .query_async::<_, ()>(&mut conn.get()),
                    )
                    .await;
                    conn.observe_timed(&r);
                }
            }
            Ok(())
        }
        .await;
        claim.release().await;
        if below_floor > 0 && crate::health::warn_due(&cache.network, "pinned_holes_below_floor") {
            info!(network = %cache.network, dropped = below_floor, floor, "pinned sweep: dropped holes below the lowest height that is filled");
        }
        retried?;
    }

    let marks = timeout(
        budget,
        redis::cmd("MGET")
            .arg(cache.pinned_cursor_key())
            .arg(cache.pinned_verified_key())
            .query_async::<_, (Option<u64>, Option<u64>)>(&mut conn.get()),
    )
    .await;
    conn.observe_timed(&marks);
    let (cursor, verified) = marks
        .map_err(|_| anyhow::anyhow!("pinned sweep: cursor read timed out"))?
        .map_err(|e| store_err("cursor read", &e))?;
    let mut next = verified.unwrap_or(floor).max(floor);
    let claimed = cursor.unwrap_or(0);
    let hi = if claimed == 0 {
        None
    } else {
        let last_claimed = start.saturating_add(claimed - 1);
        // A worker claimed past the end: the range is done and no claim is in flight any more.
        let margin = if last_claimed > end { 0 } else { margin };
        let last_final = cache.tip_height().saturating_sub(FINALIZED_DEPTH + 1);
        last_claimed
            .min(end)
            .checked_sub(margin)
            .map(|h| h.min(last_final))
    };
    while let Some(hi) = hi.filter(|hi| next <= *hi) {
        if !current() {
            break;
        }
        // Batches have fixed identities (aligned to PINNED_SWEEP_BATCH): every process claims
        // the same heights under the same key, whatever its own reading of the mark was.
        let batch_lo = sweep_batch_of(next);
        let batch_hi = hi.min(batch_lo.saturating_add(PINNED_SWEEP_BATCH - 1));
        // One process per batch: swept by another process now (or the claim's reply was lost:
        // it expires) ends this pass.
        let Some(claim) =
            SweepClaim::take(conn, cache.pinned_sweep_claim_key(batch_lo), budget).await?
        else {
            break;
        };
        // The mark again, now that the batch is ours: another process may have swept it since
        // it was read.
        let mark = timeout(
            budget,
            redis::cmd("GET")
                .arg(cache.pinned_verified_key())
                .query_async::<_, Option<u64>>(&mut conn.get()),
        )
        .await;
        conn.observe_timed(&mark);
        let mark = match mark {
            Ok(Ok(m)) => m,
            Ok(Err(e)) => {
                claim.release().await;
                return Err(store_err("mark read", &e));
            }
            Err(_) => {
                claim.release().await;
                anyhow::bail!("pinned sweep: mark read timed out");
            }
        };
        next = next.max(mark.unwrap_or(0));
        if next > batch_hi {
            claim.release().await;
            continue;
        }
        let swept: anyhow::Result<bool> = async {
            let mut pipe = redis::pipe();
            for h in next..=batch_hi {
                pipe.cmd("EXISTS").arg(cache.pinned_key(h));
            }
            let present = timeout(budget, pipe.query_async::<_, Vec<bool>>(&mut conn.get())).await;
            conn.observe_timed(&present);
            let present = present
                .map_err(|_| anyhow::anyhow!("pinned sweep: EXISTS timed out"))?
                .map_err(|e| store_err("EXISTS", &e))?;
            for (h, there) in (next..=batch_hi).zip(present) {
                if there {
                    continue;
                }
                // Still missing (a worker or the write-through path may have filled it
                // meanwhile), then filled while the claim is held (renewed during the fill).
                if cache.pinned_exists_at(conn, h).await {
                    continue;
                }
                let outcome = match claim.fill(cache, fetch, h, writer).await {
                    SweepFill::Done(outcome) => outcome,
                    SweepFill::Superseded => {
                        record_superseded();
                        return Ok(false);
                    }
                    SweepFill::ClaimLost => return Ok(false),
                };
                let stored = outcome == Fill::Stored;
                record(stored);
                if !stored {
                    if !current() {
                        return Ok(false);
                    }
                    let r = timeout(
                        budget,
                        redis::cmd("SADD")
                            .arg(&holes_key)
                            .arg(h)
                            .query_async::<_, i64>(&mut conn.get()),
                    )
                    .await;
                    conn.observe_timed(&r);
                    match r {
                        Ok(Ok(_)) => {}
                        // Not recorded: the batch is checked again, the mark does not move past it.
                        Ok(Err(e)) => return Err(store_err("hole record", &e)),
                        Err(_) => anyhow::bail!("pinned sweep: hole record timed out"),
                    }
                }
            }
            Ok(true)
        }
        .await;
        let done = match swept {
            Ok(done) => done,
            Err(e) => {
                claim.release().await;
                return Err(e);
            }
        };
        if !done {
            // The claim was lost (expired and taken over): the batch is the other process's.
            // Released anyway (compare-and-delete: only a claim still ours goes).
            claim.release().await;
            break;
        }
        if !current() {
            // Another store was chosen: this one's mark stays (its batch is checked again).
            claim.release().await;
            break;
        }
        let r = claim.advance_mark(cache, batch_hi + 1).await;
        let held = match &r {
            Ok(Ok(true)) => true,
            // The claim was lost before the mark moved: the other holder moves it.
            Ok(Ok(false)) => false,
            // A lost reply only means that a later pass checks this batch again.
            Ok(Err(e)) => {
                warn!(network = %cache.network, error = %store_error(e), "pinned sweep: mark update script failed");
                true
            }
            Err(_) => {
                warn!(network = %cache.network, "pinned sweep: mark update timed out");
                true
            }
        };
        claim.release().await;
        if !held {
            break;
        }
        next = batch_hi + 1;
        tokio::time::sleep(PINNED_SWEEP_PAUSE).await;
    }
    // Only a successful count of 0 says there is no hole left.
    let holes = timeout(
        budget,
        redis::cmd("SCARD")
            .arg(&holes_key)
            .query_async::<_, u64>(&mut conn.get()),
    )
    .await;
    conn.observe_timed(&holes);
    let holes = holes.ok().and_then(Result::ok);
    Ok(SweepPass {
        filled,
        next,
        holes,
    })
}

/// Spawn `workers` tasks that fill the pinned tier for every height in PINNED_TREESTATE_RANGE.
/// Heights are claimed with INCR on a cursor in the pinned Redis, so all gateway processes share
/// one pass and a restart resumes where it stopped. Stops at the range end; at tip -
/// FINALIZED_DEPTH it gives the height back to the cursor and waits, then follows the tip as
/// blocks become final, so the tier keeps up with the tip (origins that read it from a replica of
/// that Redis stay current too). A height whose claim was lost (an `INCR` that timed out after
/// the store counted it) or that kept failing is found by a sweep behind the cursor every
/// PINNED_SWEEP_INTERVAL (`pinned_sweep_pass`) and filled then; one that still fails is left to
/// the write-through path.
///
/// Heights below `pinned_fill_from` (the network's Sapling activation: no tree state exists
/// below it) are not filled: the workers move the cursor past them in one step and the sweep
/// starts its mark there. Lookups in the range are unchanged.
///
/// While the store the entries go to does not take writes (a read replica, no `ROLE` answer,
/// or REDIS_PINNED_WRITE_URL not connected yet with a replica as pinned store), the workers wait
/// and check again every [`PINNED_BACKFILL_RESUME_CHECK`] and the sweep skips its pass; they
/// start once it takes writes, so a promoted replica or a write store that became reachable gets
/// its backfill without a restart. The workers and the sweep use the store `pinned_writer_bound`
/// chooses, for the cursor, the existence checks and the writes alike; when that changes (its
/// generation), or a cursor command fails, they choose again, and a fill in flight writes
/// nothing to the store it no longer belongs to (the worker counts the height it had claimed,
/// `pinned_backfill_superseded`).
///
/// `fetch` must end by itself within a bound: the sweep does not cancel an upstream call when
/// it abandons the fill that started it (`FillMode::Detached`), so a call that never ended would
/// keep one of the cache's PINNED_SWEEP_FETCH_PERMITS for good (with all of them held, the
/// sweep's fills wait for one and time out as `NoAnswer`; the workers are not affected). The
/// gateway's fetch (`proxy::forward_to_backend`) is bounded as a whole, connection, response
/// head and body, by the upstream request timeout (`LWD_TIMEOUT_SECS`).
///
/// Returns the handles of the tasks it spawned (the sweep, then the workers).
pub fn spawn_pinned_backfill<F, Fut>(
    cache: ResponseCache,
    workers: usize,
    fetch: F,
) -> Vec<tokio::task::JoinHandle<()>>
where
    F: Fn(u64) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = anyhow::Result<Vec<u8>>> + Send + 'static,
{
    let mut tasks = Vec::new();
    let Some((start, end)) = cache.pinned_range else {
        return tasks;
    };
    if cache.pinned_conn.is_none() && cache.pinned_write_conn.load().is_none() {
        return tasks;
    }
    if cache.pinned_read_only_until.load(Ordering::Relaxed) != 0 {
        warn!(network = %cache.network, "pinned backfill paused: the pinned store is a read replica; it starts once the store takes writes");
    }
    {
        let cache = cache.clone();
        let fetch = fetch.clone();
        let margin = PINNED_SWEEP_MARGIN + workers as u64;
        tasks.push(tokio::spawn(async move {
            loop {
                // Jittered (+-10 %), so processes started together do not sweep in step.
                tokio::time::sleep(
                    PINNED_SWEEP_INTERVAL.mul_f64(0.9 + rand::random::<f64>() * 0.2),
                )
                .await;
                if !cache.is_tip_fresh() {
                    continue;
                }
                // The store the backfill uses now; none while it does not take writes.
                let Some(writer) = cache.pinned_writer_bound().await else {
                    continue;
                };
                match pinned_sweep_pass(&cache, &writer, (start, end), margin, &fetch).await {
                    Ok(pass) => {
                        if pass.filled > 0 {
                            info!(network = %cache.network, filled = pass.filled, holes = ?pass.holes, "pinned sweep filled heights the backfill had skipped");
                        }
                        if pass.next > end && pass.holes == Some(0) {
                            info!(network = %cache.network, "pinned sweep done");
                            return;
                        }
                    }
                    Err(e) => {
                        warn!(network = %cache.network, error = %e, "pinned sweep failed, retrying at the next interval")
                    }
                }
            }
        }));
    }
    for worker in 0..workers {
        let cache = cache.clone();
        let fetch = fetch.clone();
        tasks.push(tokio::spawn(async move {
            'resolve: loop {
                // The cursor lives in the store the entries are written to: the one that takes
                // writes, bound to its generation. Every worker chooses the same store, and all
                // of them choose again when it changes.
                let writer = loop {
                    if let Some(writer) = cache.pinned_writer_bound().await {
                        break writer;
                    }
                    tokio::time::sleep(PINNED_BACKFILL_RESUME_CHECK).await;
                };
                let conn = writer.conn.clone();
                #[cfg(test)]
                test_hooks::backfill_resolved(&cache.network);
                // Wait for a fresh tip so pinned_put's finality check can pass.
                while !cache.is_tip_fresh() {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                info!(network = %cache.network, worker, start, end, "pinned backfill worker started");
                // Heights below `pinned_fill_from` are not filled: the cursor moves past them
                // in one step (the cursor value n claims height start + n - 1), tried again
                // before every claim until the store confirmed it or a claim is past them.
                let mut skipped = cache.pinned_fill_from <= start;
                loop {
                    if !cache.pinned_writer_current(&writer) {
                        info!(network = %cache.network, worker, "pinned store changed: the backfill chooses its store again");
                        continue 'resolve;
                    }
                    if !skipped {
                        skipped = cache
                            .pinned_cursor_skip_to(&conn, cache.pinned_fill_from - start)
                            .await;
                        if !skipped && crate::health::warn_due(&cache.network, "pinned_cursor_skip")
                        {
                            warn!(network = %cache.network, "pinned backfill: the cursor could not be moved past the heights that are not filled; they are skipped one by one meanwhile");
                        }
                    }
                    // Bounded, so that a hung connection is reported (and replaced) instead of
                    // stopping the worker (at least like the writes on a separate write store).
                    let incr = cache.pinned_cursor_step(&conn, "INCR").await;
                    // A cursor error: back to choosing the store (and waiting while none takes
                    // writes); a read-only answer pauses every worker.
                    let n: u64 = match incr {
                        Ok(Ok(n)) if n > 0 => n as u64,
                        Ok(Ok(n)) => {
                            warn!(network = %cache.network, value = n, "pinned backfill cursor out of range");
                            tokio::time::sleep(Duration::from_secs(10)).await;
                            continue 'resolve;
                        }
                        Err(_) => {
                            warn!(network = %cache.network, "pinned backfill cursor timeout");
                            tokio::time::sleep(Duration::from_secs(10)).await;
                            continue 'resolve;
                        }
                        Ok(Err(e)) => {
                            warn!(network = %cache.network, error = %store_error(&e), "pinned backfill cursor error");
                            if e.kind() == redis::ErrorKind::ReadOnly {
                                cache.mark_pinned_read_only_of(
                                    &conn,
                                    writer.generation,
                                    PINNED_READ_ONLY_RECHECK,
                                );
                            }
                            tokio::time::sleep(Duration::from_secs(10)).await;
                            continue 'resolve;
                        }
                    };
                    let height = start.saturating_add(n - 1);
                    if height >= cache.pinned_fill_from {
                        // The cursor is past the lower heights: nothing left to skip.
                        skipped = true;
                    }
                    let limit = end.min(cache.tip_height().saturating_sub(FINALIZED_DEPTH + 1));
                    if height > end {
                        info!(network = %cache.network, worker, height, "pinned backfill done");
                        return;
                    }
                    if height > limit {
                        // Caught up: hand the height back and wait for the next final block.
                        let _ = cache.pinned_cursor_step(&conn, "DECR").await;
                        tokio::time::sleep(PINNED_FOLLOW_INTERVAL).await;
                        continue;
                    }
                    if height < cache.pinned_fill_from {
                        // Below the heights that are filled (the skip above failed).
                        continue;
                    }
                    // Checked and written on the store the height was claimed on.
                    if cache.pinned_exists_at(&conn, height).await {
                        continue;
                    }
                    let stored = match pinned_fill(&cache, &fetch, height, &writer, FillMode::Inline)
                        .await
                    {
                        Fill::Superseded => {
                            // The height was claimed on the store it no longer writes to:
                            // counted (that store's sweep finds it if it is chosen again).
                            crate::health::record_cache_request(
                                &cache.network,
                                "GetTreeState",
                                "pinned_backfill_superseded",
                            );
                            info!(network = %cache.network, worker, "pinned store changed during a fill: the backfill chooses its store again");
                            continue 'resolve;
                        }
                        fill => fill == Fill::Stored,
                    };
                    let result = if stored {
                        "pinned_backfill"
                    } else {
                        "pinned_backfill_failed"
                    };
                    crate::health::record_cache_request(&cache.network, "GetTreeState", result);
                    if height.is_multiple_of(1000) {
                        info!(network = %cache.network, worker, height, "pinned backfill progress");
                    }
                }
            }
        }));
    }
    tasks
}

#[cfg(test)]
mod lease_tests {
    use super::*;

    #[test]
    fn wait_conns_parse() {
        assert_eq!(parse_wait_conns(None).unwrap(), DEFAULT_REPLAY_WAIT_CONNS);
        assert_eq!(
            parse_wait_conns(Some(" ")).unwrap(),
            DEFAULT_REPLAY_WAIT_CONNS
        );
        assert_eq!(parse_wait_conns(Some("1")).unwrap(), 1);
        assert_eq!(parse_wait_conns(Some("32")).unwrap(), 32);
        for bad in ["0", "33", "-1", "four"] {
            assert!(parse_wait_conns(Some(bad)).is_err(), "{bad}");
        }
    }

    fn soon(ms: u64) -> tokio::time::Instant {
        tokio::time::Instant::now() + Duration::from_millis(ms)
    }

    #[tokio::test]
    async fn a_lease_pool_shares_while_waits_are_fast_and_leases_once_one_is_slow() {
        let pool = LeasePool::new(2, 100);
        // Fast WAITs (a 100 ms round trip): shared, round robin.
        for _ in 0..3 {
            pool.observe(WaitOutcome::Acked, Duration::from_millis(100));
        }
        assert!(!pool.exclusive());
        let a = pool.acquire(soon(50), |_| true).await.slot().unwrap();
        let b = pool.acquire(soon(50), |_| true).await.slot().unwrap();
        assert!(!a.leased && !b.leased);
        assert_ne!(a.index(), b.index(), "round robin");
        // Within the round trip plus half the WAIT timeout: still shared.
        pool.observe(WaitOutcome::Acked, Duration::from_millis(140));
        assert!(!pool.exclusive());
        // Longer: the replicas made it wait.
        pool.observe(WaitOutcome::Acked, Duration::from_millis(160));
        assert!(pool.exclusive());
        let pool = LeasePool::new(2, 100);
        pool.observe(WaitOutcome::Slow, Duration::from_millis(1));
        assert!(pool.exclusive(), "a short acknowledgement switches at once");
    }

    #[tokio::test]
    async fn a_lease_pool_hands_out_each_connection_once_and_bounds_the_wait() {
        let pool = LeasePool::new(2, 100);
        pool.observe(WaitOutcome::Slow, Duration::ZERO);
        let a = pool.acquire(soon(50), |_| true).await.slot().unwrap();
        assert!(a.leased);
        // The preferred connection is taken when it is free.
        let b = pool
            .acquire(soon(50), |i| i != a.index())
            .await
            .slot()
            .unwrap();
        assert_ne!(a.index(), b.index());
        // Both busy: the wait ends at its deadline, on the saturated path.
        let started = std::time::Instant::now();
        assert!(matches!(
            pool.acquire(soon(50), |_| true).await,
            Acquired::Busy
        ));
        assert!(started.elapsed() >= Duration::from_millis(40));
        assert!(pool.idle().is_empty());
        let freed = a.index();
        drop(a);
        assert_eq!(pool.idle(), vec![freed]);
        // A free connection that is not eligible (not open) is never handed out.
        assert!(matches!(
            pool.acquire(soon(50), |_| false).await,
            Acquired::NoneOpen
        ));
        let c = pool.acquire(soon(50), |i| i == freed).await.slot().unwrap();
        assert_eq!(c.index(), freed);
        drop((b, c));
        assert_eq!(pool.idle().len(), 2);
    }

    /// The switch to exclusive leasing with shared work still on the connections (callers that
    /// gave up included): a lease is taken only on a drained connection, and a leased connection
    /// is never used for shared work, also after the exclusive mode ended.
    #[tokio::test]
    async fn exclusive_leases_wait_for_shared_work_to_drain() {
        let pool = LeasePool::new(2, 100);
        // Shared commands in flight on both connections; their callers give up.
        let mut done = Vec::new();
        for _ in 0..2 {
            let slot = pool.acquire(soon(50), |_| true).await.slot().unwrap();
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            done.push(tx);
            let out = run_on_slot(
                slot,
                soon(10),
                Duration::from_secs(5),
                async move {
                    let _ = rx.await;
                    redis::RedisResult::Ok(1i64)
                },
                || {},
            )
            .await;
            assert!(out.is_err(), "the caller gave up");
        }
        assert!(
            pool.idle().is_empty(),
            "still busy with the shared commands"
        );
        pool.observe(WaitOutcome::Slow, Duration::ZERO);
        assert!(pool.exclusive());
        assert!(
            pool.acquire(soon(50), |_| true).await.slot().is_none(),
            "no connection is drained"
        );
        // One shared command ends: that connection can be leased, the other still cannot.
        done.remove(0).send(()).unwrap();
        let lease = pool.acquire(soon(500), |_| true).await.slot().unwrap();
        assert!(lease.leased);
        assert!(pool.acquire(soon(50), |_| true).await.slot().is_none());
        // The exclusive mode ends while the lease is held: shared work never gets that one.
        pool.exclusive_until_ms.store(0, Ordering::Relaxed);
        let shared = pool.acquire(soon(50), |_| true).await.slot().unwrap();
        assert!(!shared.leased);
        assert_ne!(shared.index(), lease.index());
        drop((lease, shared, done));
    }

    /// A caller that stops waiting (its budget, or it went away) does not give the connection
    /// back while its command is still on it.
    #[tokio::test]
    async fn a_leased_connection_stays_busy_until_its_command_is_done() {
        let pool = LeasePool::new(1, 100);
        pool.observe(WaitOutcome::Slow, Duration::ZERO);
        let slot = pool.acquire(soon(50), |_| true).await.slot().unwrap();
        let (done, rx) = tokio::sync::oneshot::channel::<()>();
        let command = async move {
            let _ = rx.await;
            redis::RedisResult::Ok(1i64)
        };
        let retired = Arc::new(AtomicBool::new(false));
        let r = retired.clone();
        let out = run_on_slot(slot, soon(30), Duration::from_secs(5), command, move || {
            r.store(true, Ordering::SeqCst)
        })
        .await;
        assert!(out.is_err(), "the caller gave up");
        assert!(pool.idle().is_empty(), "still busy with the command");
        assert!(pool.acquire(soon(30), |_| true).await.slot().is_none());
        done.send(()).unwrap();
        for _ in 0..50 {
            if !pool.idle().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(pool.idle(), vec![0], "returned once the command is done");
        assert!(!retired.load(Ordering::SeqCst));

        // A command that never ends: the connection is replaced and the lease returned.
        let slot = pool.acquire(soon(50), |_| true).await.slot().unwrap();
        let r = retired.clone();
        let out = run_on_slot(
            slot,
            soon(10),
            Duration::from_millis(50),
            std::future::pending::<redis::RedisResult<i64>>(),
            move || r.store(true, Ordering::SeqCst),
        )
        .await;
        assert!(out.is_err());
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(retired.load(Ordering::SeqCst));
        assert_eq!(pool.idle(), vec![0]);
    }

    /// A request waiting for an eligible connection takes one as soon as it opens (`wake`), not
    /// only when another request releases one.
    #[tokio::test]
    async fn a_waiting_request_takes_a_connection_once_it_opens() {
        let pool = LeasePool::new(2, 100);
        let open = Arc::new(AtomicBool::new(false));
        let waiter = {
            let (pool, open) = (pool.clone(), open.clone());
            tokio::spawn(async move {
                let started = std::time::Instant::now();
                let got = pool
                    .acquire(soon(2000), |i| i == 1 && open.load(Ordering::SeqCst))
                    .await
                    .slot()
                    .map(|s| s.index());
                (got, started.elapsed())
            })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        open.store(true, Ordering::SeqCst);
        pool.wake();
        let (got, took) = waiter.await.unwrap();
        assert_eq!(got, Some(1));
        assert!(took < Duration::from_millis(1000), "{took:?}");
    }

    /// Exclusive mode with every open connection leased: the saturated path (`Busy`), although
    /// a closed connection is free; with no open connection at all: `NoneOpen`. A deadline that
    /// has passed is not waited for.
    #[tokio::test]
    async fn a_partial_pool_outage_never_hands_out_a_closed_connection() {
        let pool = LeasePool::new(3, 100);
        pool.observe(WaitOutcome::Slow, Duration::ZERO);
        let open = |i: usize| i != 2;
        let a = pool.acquire(soon(50), open).await.slot().unwrap();
        let b = pool.acquire(soon(50), open).await.slot().unwrap();
        assert!(a.index() != 2 && b.index() != 2);
        let started = std::time::Instant::now();
        assert!(matches!(pool.acquire(soon(50), open).await, Acquired::Busy));
        assert!(started.elapsed() >= Duration::from_millis(40));
        assert!(matches!(
            pool.acquire(soon(50), |_| false).await,
            Acquired::NoneOpen
        ));
        // The deadline has passed: decided at once.
        let started = std::time::Instant::now();
        assert!(matches!(
            pool.acquire(tokio::time::Instant::now(), open).await,
            Acquired::Busy
        ));
        assert!(started.elapsed() < Duration::from_millis(20));
        drop(a);
        assert!(
            pool.acquire(tokio::time::Instant::now(), open)
                .await
                .slot()
                .is_some(),
            "a free open connection is taken even at the deadline"
        );
        drop(b);
    }

    /// A shared caller that gave up (or went away) while its WAIT was slow still switches the
    /// pool to exclusive: the outcome is recorded by the task that owns the command.
    #[tokio::test]
    async fn a_cancelled_caller_still_records_its_slow_wait() {
        let pool = LeasePool::new(2, 100);
        assert!(!pool.exclusive());
        let slot = pool.acquire(soon(50), |_| true).await.slot().unwrap();
        let hooks = wait_hooks(
            pool.clone(),
            |_: &redis::RedisResult<i64>| true,
            || {},
            || {},
        );
        let caller = tokio::spawn(run_on_slot_with(
            slot,
            soon(30),
            Duration::from_secs(5),
            std::future::pending::<redis::RedisResult<i64>>(),
            hooks,
        ));
        // The caller goes away after the command went out, before its deadline.
        tokio::time::sleep(Duration::from_millis(10)).await;
        caller.abort();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            pool.exclusive(),
            "the timeout was recorded without its caller"
        );
    }

    /// A command task that panics still replaces its connection, then returns the slot.
    #[tokio::test]
    async fn a_panicking_command_still_replaces_its_connection() {
        let pool = LeasePool::new(1, 100);
        let slot = pool.acquire(soon(50), |_| true).await.slot().unwrap();
        let retired = Arc::new(AtomicBool::new(false));
        let r = retired.clone();
        let command = async move {
            if true {
                panic!("a command that panics");
            }
            redis::RedisResult::Ok(1i64)
        };
        let out = run_on_slot(
            slot,
            soon(500),
            Duration::from_secs(5),
            command,
            move || r.store(true, Ordering::SeqCst),
        )
        .await;
        assert!(matches!(out, Ok(Err(_))), "{out:?}");
        assert!(retired.load(Ordering::SeqCst), "the connection is replaced");
        assert_eq!(pool.idle(), vec![0], "and the slot is back");
    }

    /// A command whose deadline passed before it could be sent is never sent.
    #[tokio::test]
    async fn an_expired_command_is_never_sent() {
        let pool = LeasePool::new(1, 100);
        let slot = pool.acquire(soon(50), |_| true).await.slot().unwrap();
        let sent = Arc::new(AtomicBool::new(false));
        let s = sent.clone();
        let command = async move {
            s.store(true, Ordering::SeqCst);
            redis::RedisResult::Ok(1i64)
        };
        let out = run_on_slot(
            slot,
            tokio::time::Instant::now(),
            Duration::from_secs(5),
            command,
            || {},
        )
        .await;
        assert!(out.is_err());
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !sent.load(Ordering::SeqCst),
            "nothing went out after the deadline"
        );
        assert_eq!(pool.idle(), vec![0]);
    }

    /// Timeouts are checked against the connection and the pool round they were sent on
    /// before they count: a late one of a replaced connection, or one sent before the pool
    /// was replaced, changes nothing.
    #[test]
    fn stale_timeouts_neither_count_nor_replace_the_pool() {
        let t = RecentTimeout::default();
        let round = t.round();
        assert_eq!(t.note_timeout(0, round, true, true), TimeoutVerdict::One);
        // Connection 1 was replaced meanwhile: its late timeout is not a second one.
        assert_eq!(t.note_timeout(1, round, false, true), TimeoutVerdict::Stale);
        assert_eq!(t.note_timeout(1, round, true, true), TimeoutVerdict::All);
        // Sent before that replacement of the pool: stale.
        assert_eq!(t.note_timeout(0, round, true, true), TimeoutVerdict::Stale);
        assert_eq!(
            t.note_timeout(0, t.round(), true, true),
            TimeoutVerdict::One
        );
        // Queued behind others on a shared connection: that connection at most, never all.
        assert_eq!(
            t.note_timeout(1, t.round(), true, false),
            TimeoutVerdict::One
        );
        assert_eq!(
            t.note_timeout(2, t.round(), true, false),
            TimeoutVerdict::One
        );
    }

    /// A reopened slot that was reset before its reopen flag was cleared is opened again.
    #[test]
    fn a_slot_reset_during_its_reopen_is_opened_again() {
        let slot = PeerWaitSlot {
            conn: ArcSwapOption::empty(),
            reopening: AtomicBool::new(true),
            opened: Arc::new(tokio::sync::Notify::new()),
        };
        // Empty again when the task finishes: it keeps the flag and reopens.
        assert!(slot.reopen_done());
        assert!(slot.reopening.load(Ordering::Acquire));
    }

    /// Housekeeping checks one idle connection at a time and always leaves another one idle;
    /// a pool of one is checked as shared work.
    #[tokio::test]
    async fn housekeeping_checks_leave_a_connection_free() {
        let pool = LeasePool::new(3, 100);
        let a = pool.take_idle_for_check(|_| true).unwrap();
        assert!(a.leased);
        let b = pool.take_idle_for_check(|_| true).unwrap();
        assert_ne!(a.index(), b.index());
        // The last idle one is still checked, as shared work: a WRITE still gets it.
        let c = pool.take_idle_for_check(|_| true).unwrap();
        assert!(!c.leased);
        assert_eq!(
            pool.acquire(soon(50), |_| true)
                .await
                .slot()
                .map(|s| s.index()),
            Some(c.index()),
            "the last one stays usable"
        );
        drop(c);
        // Not while the pool hands out its connections exclusively.
        pool.observe(WaitOutcome::Slow, Duration::ZERO);
        assert!(pool.take_idle_for_check(|_| true).is_none());
        drop((a, b));
        let one = LeasePool::new(1, 100);
        let check = one.take_idle_for_check(|_| true).unwrap();
        assert!(!check.leased);
        assert!(
            one.acquire(soon(50), |_| true).await.slot().is_some(),
            "still usable shared"
        );
        drop(check);
        // A closed connection is neither checked nor counted as the one left free.
        let pool = LeasePool::new(3, 100);
        let open = |i: usize| i != 2;
        let a = pool.take_idle_for_check(open).unwrap();
        assert_ne!(a.index(), 2);
        assert!(a.leased, "another open one is idle");
        let b = pool.take_idle_for_check(open).unwrap();
        assert!(!b.leased && b.index() != 2, "the last open one, shared");
        drop((a, b));
    }

    /// Samples from many threads, across resets of the floor (every sample is past the reset
    /// period here): the sampling state stays consistent (no lost or wrapped count).
    #[test]
    fn the_floor_stays_consistent_under_concurrent_samples_and_resets() {
        let pool = LeasePool::with_floor_reset(1, 100, Duration::ZERO);
        std::thread::scope(|sc| {
            for t in 0..8u64 {
                let pool = &pool;
                sc.spawn(move || {
                    for k in 0..2000u64 {
                        pool.observe(WaitOutcome::Acked, Duration::from_millis(5 + (t + k) % 7));
                    }
                });
            }
        });
        let f = pool.floor.lock();
        assert!(f.samples_left <= WAIT_FLOOR_SAMPLES, "{}", f.samples_left);
        assert!((5..=11).contains(&f.floor_ms), "{}", f.floor_ms);
    }

    /// The round-trip floor is measured again as the fastest of the next samples, not taken
    /// from the first one after the reset period.
    #[tokio::test]
    async fn the_round_trip_floor_is_measured_again_from_several_samples() {
        let pool = LeasePool::with_floor_reset(1, 100, Duration::from_millis(50));
        pool.observe(WaitOutcome::Acked, Duration::from_millis(20));
        assert_eq!(pool.floor(), 20);
        tokio::time::sleep(Duration::from_millis(80)).await;
        // The store moved further away: the first sample after the period is a slow one.
        pool.observe(WaitOutcome::Acked, Duration::from_millis(400));
        assert_eq!(pool.floor(), 20, "kept until the samples are in");
        for _ in 1..WAIT_FLOOR_SAMPLES - 1 {
            pool.observe(WaitOutcome::Acked, Duration::from_millis(120));
        }
        pool.observe(WaitOutcome::Acked, Duration::from_millis(130));
        assert_eq!(pool.floor(), 120, "the fastest of the samples");
    }
}

#[cfg(test)]
mod test_hooks {
    use std::collections::HashMap;
    use std::sync::Mutex;

    static RESOLVED: Mutex<Option<HashMap<String, usize>>> = Mutex::new(None);

    /// A pinned backfill worker of `network` chose its store.
    pub fn backfill_resolved(network: &str) {
        *RESOLVED
            .lock()
            .unwrap()
            .get_or_insert_with(HashMap::new)
            .entry(network.to_string())
            .or_default() += 1;
    }

    /// A stop for the `ROLE` probes of one network: between the store's answer and what the
    /// probe does with it.
    pub struct ProbeGate {
        pub reached: tokio::sync::Notify,
        /// Probes stopped at the gate so far.
        pub stopped: std::sync::atomic::AtomicUsize,
        /// One permit lets one stopped probe go on.
        pub release: tokio::sync::Semaphore,
    }

    impl Default for ProbeGate {
        fn default() -> Self {
            Self {
                reached: tokio::sync::Notify::new(),
                stopped: Default::default(),
                release: tokio::sync::Semaphore::new(0),
            }
        }
    }

    static PROBE_GATES: Mutex<Option<HashMap<String, std::sync::Arc<ProbeGate>>>> =
        Mutex::new(None);

    /// Stop the next `ROLE` probes of `network` at their answer until released.
    pub fn gate_probes(network: &str) -> std::sync::Arc<ProbeGate> {
        let gate = std::sync::Arc::new(ProbeGate::default());
        PROBE_GATES
            .lock()
            .unwrap()
            .get_or_insert_with(HashMap::new)
            .insert(network.to_string(), gate.clone());
        gate
    }

    pub fn ungate_probes(network: &str) {
        if let Some(gates) = PROBE_GATES.lock().unwrap().as_mut() {
            gates.remove(network);
        }
    }

    /// A `ROLE` probe of `network` got its answer (or none in time).
    pub async fn probe_answered(network: &str) {
        let gate = PROBE_GATES
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|gates| gates.get(network).cloned());
        if let Some(gate) = gate {
            gate.stopped
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            gate.reached.notify_one();
            if let Ok(permit) = gate.release.acquire().await {
                permit.forget();
            }
        }
    }

    type PauseLiftHook = Box<dyn FnOnce() + Send>;
    static PAUSE_LIFT_HOOKS: Mutex<Option<HashMap<String, PauseLiftHook>>> = Mutex::new(None);

    /// Run `hook` once, at the next lift of the pinned pause of `network`: after the checks of
    /// the generation, the store and the pause, before the pause is lifted, with the writer
    /// state lock held.
    pub fn on_pause_lift(network: &str, hook: impl FnOnce() + Send + 'static) {
        PAUSE_LIFT_HOOKS
            .lock()
            .unwrap()
            .get_or_insert_with(HashMap::new)
            .insert(network.to_string(), Box::new(hook));
    }

    /// The pinned pause of `network` is about to be lifted (see `on_pause_lift`).
    pub fn pause_lift(network: &str) {
        let hook = PAUSE_LIFT_HOOKS
            .lock()
            .unwrap()
            .as_mut()
            .and_then(|hooks| hooks.remove(network));
        if let Some(hook) = hook {
            hook();
        }
    }

    type RenewalHook =
        Box<dyn FnMut() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send>;
    static RENEWAL_HOOKS: Mutex<Option<HashMap<String, RenewalHook>>> = Mutex::new(None);

    /// Run `hook` at the start of every renewal of the sweep claim `key`, before the store is
    /// asked, and wait for what it returns.
    pub fn on_sweep_renewal(
        key: &str,
        hook: impl FnMut() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
            + Send
            + 'static,
    ) {
        RENEWAL_HOOKS
            .lock()
            .unwrap()
            .get_or_insert_with(HashMap::new)
            .insert(key.to_string(), Box::new(hook));
    }

    pub fn clear_sweep_renewal(key: &str) {
        if let Some(hooks) = RENEWAL_HOOKS.lock().unwrap().as_mut() {
            hooks.remove(key);
        }
    }

    /// The sweep claim `key` is about to be renewed (see `on_sweep_renewal`).
    pub async fn sweep_renewal(key: &str) {
        let pending = RENEWAL_HOOKS
            .lock()
            .unwrap()
            .as_mut()
            .and_then(|hooks| hooks.get_mut(key).map(|hook| hook()));
        if let Some(pending) = pending {
            pending.await;
        }
    }

    type SweepTimings = (std::time::Duration, std::time::Duration);
    static SWEEP_TIMINGS: Mutex<Option<HashMap<String, SweepTimings>>> = Mutex::new(None);

    /// The sweep fills of `network` use `fill_timeout` instead of PINNED_SWEEP_FILL_TIMEOUT and
    /// renew their claim every `renew_every` (None: the defaults again).
    pub fn set_sweep_timings(network: &str, timings: Option<SweepTimings>) {
        let mut all = SWEEP_TIMINGS.lock().unwrap();
        let all = all.get_or_insert_with(HashMap::new);
        match timings {
            Some(t) => {
                all.insert(network.to_string(), t);
            }
            None => {
                all.remove(network);
            }
        }
    }

    pub fn sweep_timings(network: &str) -> Option<SweepTimings> {
        SWEEP_TIMINGS
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|m| m.get(network).copied())
    }

    static PERMIT_WAITS: Mutex<Option<HashMap<String, usize>>> = Mutex::new(None);

    /// A sweep fill of `network` waited one pause for a call permit (none was free).
    pub fn permit_waited(network: &str) {
        *PERMIT_WAITS
            .lock()
            .unwrap()
            .get_or_insert_with(HashMap::new)
            .entry(network.to_string())
            .or_default() += 1;
    }

    pub fn permit_waits(network: &str) -> usize {
        PERMIT_WAITS
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|m| m.get(network).copied())
            .unwrap_or(0)
    }

    pub fn backfill_resolutions(network: &str) -> usize {
        RESOLVED
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|m| m.get(network).copied())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod pinned_tests {
    use super::*;

    #[test]
    fn test_parse_pinned_range() {
        assert_eq!(
            parse_pinned_range("1710000-2050000"),
            Some((1_710_000, 2_050_000))
        );
        assert_eq!(parse_pinned_range("1-"), Some((1, u64::MAX)));
        assert_eq!(parse_pinned_range("0-10"), None);
        assert_eq!(parse_pinned_range("10-5"), None);
        assert_eq!(parse_pinned_range("abc"), None);
    }

    #[test]
    fn test_tree_state_request_roundtrip() {
        let body = grpc_tree_state_request(1_775_116);
        let id: BlockId = prost::Message::decode(&body[5..]).unwrap();
        assert_eq!(id.height, 1_775_116);
        assert!(id.hash.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Operation budget of the local test Redis in `test_cache`, and of the peers that are
    /// databases of that Redis. It is shared by every test running in parallel, and some of
    /// them make it slow on purpose for a moment (`appendfsync always`), so a production-sized
    /// timeout (250 ms) turned correct verdicts into fail-closed errors at random. Tests of a
    /// store that does not answer in time set their own short timeout.
    const LOCAL_TEST_OP_TIMEOUT: Duration = Duration::from_secs(5);

    /// A cache on `conn` (and optionally a security connection) for the Redis-gated tests.
    fn test_cache(
        conn: ConnectionManager,
        security: Option<ConnectionManager>,
        network: &str,
    ) -> ResponseCache {
        ResponseCache {
            cache_conn: Arc::new(ArcSwapOption::from(Some(Arc::new(conn)))),
            // The client is only used to reconnect after a failover signal, which these tests
            // do not produce (store_failover.rs does).
            security_conn: security.map(|c| {
                StoreConn::from_parts(
                    redis::Client::open("redis://127.0.0.1:6379").unwrap(),
                    c,
                    "security",
                    network.to_string(),
                    Role::Primary,
                )
            }),
            cache_ping_failures: Arc::new(AtomicU32::new(0)),
            tip: Arc::new(TipCell::new()),
            epoch: Arc::new(AtomicU64::new(0)),
            network: network.to_string(),
            backend_host: "lwd.example.com:9067".to_string(),
            last_epoch_sync: Arc::new(AtomicU64::new(0)),
            redis_timeout: LOCAL_TEST_OP_TIMEOUT,
            policy_hash: "test".to_string(),
            pinned_conn: None,
            pinned_write_conn: Default::default(),
            pinned_read_only_until: Arc::new(AtomicU64::new(0)),
            pinned_writer_gen: Default::default(),
            pinned_writer_lock: Default::default(),
            pinned_range: None,
            pinned_fill_from: 0,
            cache_redis_url: "redis://127.0.0.1:6379".to_string(),
            replay_peers: None,
            replicator: None,
            standby_peers: None,
            standby_replicator: None,
            write_wait: None,
            local_aof: None,
            write_fallback: None,
            hub_fallback: None,
            unavailable_fallback: false,
            fallback_health: Arc::new(FallbackHealth::new(
                DEFAULT_REPLAY_FALLBACK_HEALTH_FAILURES,
                Duration::from_secs(DEFAULT_REPLAY_FALLBACK_HEALTH_WINDOW_SECS),
            )),
            epoch_state: Arc::default(),
            pinned_sweep_fetch_permits: Arc::new(tokio::sync::Semaphore::new(
                PINNED_SWEEP_FETCH_PERMITS,
            )),
        }
    }

    /// The test store (`store::test_support::TEST_STORE`), or None when the test is to be
    /// skipped: its absence fails the test unless `OHTTP_TEST_ALLOW_NO_STORE=1` outside CI
    /// (`store::test_support::store_policy`). The check is this first connection (bounded);
    /// a store lost later fails the test.
    async fn local_redis() -> Option<ConnectionManager> {
        use crate::store::test_support::{store_missing, STORE_CONNECT_TIMEOUT, TEST_STORE};
        let url = format!("redis://{TEST_STORE}");
        let connect = async {
            let client = redis::Client::open(url.as_str())?;
            ConnectionManager::new(client).await
        };
        let what = format!("the test store {url}");
        match timeout(STORE_CONNECT_TIMEOUT, connect).await {
            Ok(Ok(conn)) => Some(conn),
            Ok(Err(e)) => {
                store_missing(&what, &e);
                None
            }
            Err(_) => {
                store_missing(
                    &what,
                    &format!("no connection within {STORE_CONNECT_TIMEOUT:?}"),
                );
                None
            }
        }
    }

    /// Whether `e` is the store's own answer refusing a command (an error reply), not a lost
    /// connection, an I/O error or a timeout.
    fn refused_by_the_store(e: &redis::RedisError) -> bool {
        e.code().is_some() && !e.is_io_error() && !e.is_timeout() && !e.is_connection_dropped()
    }

    #[test]
    fn a_refusal_by_the_store_is_told_from_a_lost_store() {
        let refused = redis::RedisError::from((
            redis::ErrorKind::ResponseError,
            "ERR unknown command 'CONFIG'",
        ));
        assert!(refused_by_the_store(&refused));
        for lost in [
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::BrokenPipe,
            std::io::ErrorKind::TimedOut,
            std::io::ErrorKind::ConnectionRefused,
        ] {
            let e = redis::RedisError::from(std::io::Error::from(lost));
            assert!(!refused_by_the_store(&e), "{lost:?}");
        }
        let client = redis::RedisError::from((redis::ErrorKind::ClientError, "client side"));
        assert!(!refused_by_the_store(&client));
    }

    /// `cargo test` runs these tests twice (lib and bin targets) against the same Redis, and
    /// replay nonces live 600 s: hash inputs must differ per process.
    fn unique(s: &str) -> Vec<u8> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{s} {nanos} {}", std::process::id()).into_bytes()
    }

    /// A peer whose node said it is no longer the primary (READONLY) lends neither a WAIT nor
    /// a retry connection until its main connection is accepted on a primary again.
    #[tokio::test]
    async fn a_demoted_peer_lends_no_wait_or_retry_connection() {
        if local_redis().await.is_none() {
            return;
        }
        let network = "testnet-demoted-peer";
        let peers = ReplayPeers::connect(
            &["redis://127.0.0.1:6379/11".to_string()],
            network.to_string(),
            100,
            true,
        )
        .await
        .with_mode(ReplayPeerMode::Sync, true)
        .with_wait_conns(
            Some(WriteWaitConfig {
                replicas: 1,
                timeout_ms: 50,
            }),
            2,
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while peers.wait_conns_open() != vec![2] {
            assert!(
                std::time::Instant::now() < deadline,
                "WAIT connections not open"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let p = &peers.peers[0];
        let main = p.conn.load_full().unwrap();
        let readonly = redis::RedisError::from((
            redis::ErrorKind::ReadOnly,
            "READONLY",
            "You can't write against a read only replica.".to_string(),
        ));
        p.on_error(network, &main, &readonly);
        assert!(!p.primary_usable());
        // The retry of a timed-out SET NX gets no connection (within its 100 ms; the main
        // connection is reopened only after 200 ms) and writes nothing.
        let key = format!("replay:{network}:{}", hex::encode(unique("demoted retry")));
        let mut outcomes = vec![PeerOutcome::Timeout];
        peers.retry_timed_out(&key, 60, "v", &mut outcomes).await;
        assert_eq!(outcomes, vec![PeerOutcome::Timeout]);
        let mut c = redis::Client::open("redis://127.0.0.1:6379/11")
            .unwrap()
            .get_multiplexed_async_connection()
            .await
            .unwrap();
        let exists: bool = redis::cmd("EXISTS")
            .arg(&key)
            .query_async(&mut c)
            .await
            .unwrap();
        assert!(!exists);
    }

    /// A failed command on a connection that was already replaced changes nothing; on the
    /// installed one a signal about the node drops the peer's main and other connections too.
    #[tokio::test]
    async fn only_an_installed_connection_drops_the_others() {
        if local_redis().await.is_none() {
            return;
        }
        let network = "testnet-failed-on-stale";
        let peers = ReplayPeers::connect(
            &["redis://127.0.0.1:6379/12".to_string()],
            network.to_string(),
            250,
            true,
        )
        .await
        .with_wait_conns(
            Some(WriteWaitConfig {
                replicas: 1,
                timeout_ms: 50,
            }),
            2,
        );
        let open = |peers: &ReplayPeers| peers.wait_conns_open() == vec![2];
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !open(&peers) {
            assert!(
                std::time::Instant::now() < deadline,
                "WAIT connections not open"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let p = &peers.peers[0];
        let slot = p.wait.slots[0].clone();
        let stale = slot.conn.load_full().unwrap();
        // Replaced meanwhile.
        drop_wait_conn(network, p.index, &p.url, &slot, &stale);
        while !open(&peers) {
            assert!(std::time::Instant::now() < deadline, "not reopened");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let readonly = redis::RedisError::from((
            redis::ErrorKind::ReadOnly,
            "READONLY",
            "You can't write against a read only replica.".to_string(),
        ));
        p.links()
            .command_failed(network, FailedOn::Extra(&slot, &stale), &readonly);
        assert!(p.primary_usable(), "a stale connection drops nothing else");
        assert!(open(&peers));
        // A check of a main connection that is no longer installed replaces nothing either.
        let stale_main = Arc::new((*p.conn.load_full().unwrap()).clone());
        p.links()
            .drop_all(network, &stale_main, "role", "ROLE is not master");
        assert!(p.primary_usable());
        assert!(open(&peers));
        let installed = slot.conn.load_full().unwrap();
        p.links()
            .command_failed(network, FailedOn::Extra(&slot, &installed), &readonly);
        assert!(
            !p.primary_usable(),
            "the installed one: the node is not the primary"
        );
    }

    /// A refresh from the local store that read its epoch before a switch for a bump seen at a
    /// peer commits after it: the switched epoch stays (one lock for the epoch's state).
    #[tokio::test]
    async fn a_local_refresh_never_overwrites_a_switched_epoch() {
        let Some(conn) = local_redis().await else {
            return;
        };
        let c = Arc::new(test_cache(
            conn.clone(),
            Some(conn),
            &format!("testnet-epoch-race-{}", std::process::id()),
        ));
        let (read, switched) = (
            Arc::new(tokio::sync::Barrier::new(2)),
            Arc::new(tokio::sync::Barrier::new(2)),
        );
        let refresh = {
            let (c, read, switched) = (c.clone(), read.clone(), switched.clone());
            tokio::spawn(async move {
                let local = c.fetch_shared_epoch().await.unwrap();
                read.wait().await;
                switched.wait().await;
                c.commit_local_epoch(local)
            })
        };
        read.wait().await;
        let fresh = {
            let mut state = c.epoch_state.lock();
            let current = c.epoch.load(Ordering::Relaxed);
            c.compare_peer_epochs(&mut state, vec![Some(("peer".to_string(), 7))], current)
        };
        c.last_epoch_sync.store(0, Ordering::Relaxed);
        switched.wait().await;
        assert_eq!(
            refresh.await.unwrap(),
            fresh,
            "the refresh did not take over"
        );
        assert_ne!(
            c.last_epoch_sync.load(Ordering::Relaxed),
            0,
            "the refresh counts as done while the switch is in force"
        );
        assert_eq!(c.current_epoch(), fresh);
    }

    /// A `PeerCheck` is bound to the request it was built for: another request's, or one that
    /// never went through the peer stage, is refused.
    #[tokio::test]
    async fn a_peer_check_of_another_request_is_refused() {
        let Some(conn) = local_redis().await else {
            return;
        };
        let c = test_cache(conn.clone(), Some(conn), "testnet-peercheck-bound");
        let a = c.check_replay_detailed(&unique("bound a")).await.unwrap();
        let b = c.check_replay_detailed(&unique("bound b")).await.unwrap();
        let check_b = c
            .replicate_nonce_checked(&b, RouteClass::Write, WritePolicy::BOTH_STORES)
            .await
            .unwrap();
        let err = c
            .confirm_write_nonce(&a, &check_b)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("another request"), "{err}");
        let err = c
            .confirm_write_nonce(&a, &PeerCheck::blank())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("another request"), "{err}");
        let check_a = c
            .replicate_nonce_checked(&a, RouteClass::Write, WritePolicy::BOTH_STORES)
            .await
            .unwrap();
        assert_eq!(
            c.confirm_write_nonce(&a, &check_a).await.unwrap(),
            WriteAdmission::Run
        );
        assert_eq!(
            c.confirm_write_nonce(&b, &check_b).await.unwrap(),
            WriteAdmission::Run
        );
        // A PeerCheck that says replay is refused, also when handed on anyway.
        let replayed = PeerCheck {
            replay: true,
            ..PeerCheck::blank()
        }
        .bound_to(&a);
        let err = c
            .confirm_write_nonce(&a, &replayed)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("found a replay"), "{err}");
    }

    #[test]
    fn test_write_wait_config_parse() {
        assert_eq!(
            WriteWaitConfig::parse(None, None).unwrap(),
            None,
            "off by default"
        );
        assert_eq!(
            WriteWaitConfig::parse(Some("0"), Some("50")).unwrap(),
            None,
            "0 = off"
        );
        assert_eq!(WriteWaitConfig::parse(Some(" "), None).unwrap(), None);
        assert_eq!(
            WriteWaitConfig::parse(Some("1"), None).unwrap(),
            Some(WriteWaitConfig {
                replicas: 1,
                timeout_ms: DEFAULT_REPLAY_WRITE_WAIT_MS
            })
        );
        assert_eq!(
            WriteWaitConfig::parse(Some("2"), Some("250")).unwrap(),
            Some(WriteWaitConfig {
                replicas: 2,
                timeout_ms: 250
            })
        );
        assert!(WriteWaitConfig::parse(Some("-1"), None).is_err());
        assert!(WriteWaitConfig::parse(Some("one"), None).is_err());
        assert!(WriteWaitConfig::parse(Some("1"), Some("0")).is_err());
        assert!(WriteWaitConfig::parse(Some("1"), Some("fast")).is_err());
    }

    #[tokio::test]
    async fn test_confirm_nonce_replicated_is_a_noop_when_off() {
        let Some(conn) = local_redis().await else {
            return;
        };
        let c = test_cache(conn.clone(), Some(conn), "testnet-writewait-off");
        assert_eq!(c.write_wait(), None);
        assert!(c.confirm_nonce_replicated(b"anything").await.is_ok());
    }

    #[tokio::test]
    async fn test_confirm_nonce_replicated_fails_closed_without_replicas() {
        let Some(conn) = local_redis().await else {
            return;
        };
        // A standalone test Redis has no replica, so WAIT 1 returns 0 after the timeout.
        let c = test_cache(conn.clone(), Some(conn), "testnet-writewait")
            .with_write_wait(
                "redis://127.0.0.1:6379",
                WriteWaitConfig {
                    replicas: 1,
                    timeout_ms: 30,
                },
            )
            .await
            .unwrap();
        let h = sha2::Sha256::digest(unique("write wait"));
        assert!(!c.check_replay(&h).await.unwrap(), "first sight");
        let t = std::time::Instant::now();
        let err = c
            .confirm_nonce_replicated(&h)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("0 of 1 replica"), "{err}");
        assert!(
            t.elapsed() >= Duration::from_millis(25),
            "WAIT honoured its timeout: {:?}",
            t.elapsed()
        );
        assert!(
            c.check_replay(&h).await.unwrap(),
            "the nonce is still held (SET XX kept it)"
        );
    }

    #[test]
    fn test_authorization_bypass() {
        let headers_with_auth = [
            ("content-type".to_string(), "application/grpc".to_string()),
            ("Authorization".to_string(), "Bearer token".to_string()),
        ];
        let headers_without_auth = [("content-type".to_string(), "application/grpc".to_string())];

        assert!(headers_with_auth
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("authorization")));
        assert!(!headers_without_auth
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("authorization")));
    }

    #[tokio::test]
    async fn test_key_prefixes() {
        let Some(conn) = local_redis().await else {
            return;
        };
        let cache = test_cache(conn, None, "testnet");
        assert_eq!(
            cache.key_prefix_for_epoch(7),
            "ohttp:testnet:lwd.example.com:9067:7:v4:test:"
        );
        assert_eq!(
            cache.chain_key_prefix(),
            "ohttp:testnet:lwd.example.com:9067:chain:v1:"
        );
        assert_ne!(cache.key_prefix_for_epoch(7), cache.key_prefix_for_epoch(8));
    }

    #[tokio::test]
    async fn test_replay_cache() {
        let Some(conn) = local_redis().await else {
            return;
        };
        let cache = test_cache(conn.clone(), Some(conn), "testnet");

        let body1 = &unique("unique request body 1");
        let body2 = &unique("unique request body 2");

        let is_replay = cache.check_replay(body1).await.unwrap();
        assert!(!is_replay, "First request should not be replay");
        let is_replay = cache.check_replay(body1).await.unwrap();
        assert!(is_replay, "Second request with same body should be replay");
        let is_replay = cache.check_replay(body2).await.unwrap();
        assert!(!is_replay, "Different body should not be replay");
        let is_replay = cache.check_replay(body2).await.unwrap();
        assert!(is_replay, "Second request with body2 should be replay");
    }

    #[tokio::test]
    async fn test_epoch_nx_init_no_overwrite() {
        let Some(mut conn) = local_redis().await else {
            return;
        };
        let key = "epoch:testnet-nx-test";
        let _: () = conn.set(key, 5u64).await.unwrap();
        let cache = test_cache(conn.clone(), None, "testnet-nx-test");
        let epoch = cache.get_shared_epoch().await;
        assert_eq!(epoch, 5, "Should return existing epoch, not overwrite");
        let redis_value: u64 = conn.get(key).await.unwrap();
        assert_eq!(redis_value, 5);
        let _: () = conn.del(key).await.unwrap();
    }

    #[tokio::test]
    async fn test_per_request_epoch_refresh() {
        let Some(conn) = local_redis().await else {
            return;
        };
        let cache = test_cache(conn, None, "testnet-refresh-test");

        let epoch1 = cache.refresh_epoch_if_stale().await;
        let sync_time1 = cache.last_epoch_sync.load(Ordering::Relaxed);
        assert!(sync_time1 > 0, "Sync timestamp should be set");

        let epoch2 = cache.refresh_epoch_if_stale().await;
        let sync_time2 = cache.last_epoch_sync.load(Ordering::Relaxed);
        assert_eq!(
            sync_time1, sync_time2,
            "Should reuse cached epoch within 2s"
        );
        assert_eq!(epoch1, epoch2);

        cache
            .last_epoch_sync
            .store(sync_time1 - 10, Ordering::Relaxed);
        let _epoch3 = cache.refresh_epoch_if_stale().await;
        let sync_time3 = cache.last_epoch_sync.load(Ordering::Relaxed);
        // The timestamp is in whole seconds, so "refreshed" means it moved back from the stale
        // value to now (>= sync_time1), not strictly past sync_time2.
        assert!(
            sync_time3 >= sync_time1,
            "Should refresh from Redis after staleness"
        );
    }

    #[test]
    fn test_combine_peer_outcomes() {
        use PeerOutcome::*;
        assert_eq!(combine_peer_outcomes(&[]), PeerVerdict::Fresh);
        assert_eq!(combine_peer_outcomes(&[Fresh, Fresh]), PeerVerdict::Fresh);
        // A replay anywhere wins, whatever the other peers did.
        assert_eq!(combine_peer_outcomes(&[Fresh, Replay]), PeerVerdict::Replay);
        assert_eq!(
            combine_peer_outcomes(&[Timeout, Replay, Error]),
            PeerVerdict::Replay
        );
        // Otherwise one silent peer makes the verdict unknown.
        assert_eq!(
            combine_peer_outcomes(&[Fresh, Timeout]),
            PeerVerdict::Unavailable
        );
        assert_eq!(combine_peer_outcomes(&[Error]), PeerVerdict::Unavailable);
        assert_eq!(
            combine_peer_outcomes(&[Disconnected, Fresh]),
            PeerVerdict::Unavailable
        );
    }

    #[tokio::test]
    async fn test_replay_peer_check_any_write_all() {
        // Two origins, each with its own security Redis (DB 12 and DB 13 here), each listing the
        // other as a peer. A nonce seen by origin A is a replay at origin B.
        let Some(_) = local_redis().await else {
            return;
        };
        let open = |db: u8| async move {
            ConnectionManager::new(
                redis::Client::open(format!("redis://127.0.0.1:6379/{db}")).unwrap(),
            )
            .await
            .unwrap()
        };
        let (mut a_sec, mut b_sec) = (open(12).await, open(13).await);
        let _: () = redis::cmd("FLUSHDB").query_async(&mut a_sec).await.unwrap();
        let _: () = redis::cmd("FLUSHDB").query_async(&mut b_sec).await.unwrap();

        let net = "testnet-peer-test";
        let peers_of_a = ReplayPeers::connect(
            &["redis://127.0.0.1:6379/13".to_string()],
            net.to_string(),
            LOCAL_TEST_OP_TIMEOUT.as_millis() as u64,
            false,
        )
        .await;
        let peers_of_b = ReplayPeers::connect(
            &["redis://127.0.0.1:6379/12".to_string()],
            net.to_string(),
            LOCAL_TEST_OP_TIMEOUT.as_millis() as u64,
            false,
        )
        .await;
        let a = test_cache(a_sec.clone(), Some(a_sec.clone()), net).with_replay_peers(peers_of_a);
        let b = test_cache(b_sec.clone(), Some(b_sec.clone()), net).with_replay_peers(peers_of_b);

        let h1 = sha2::Sha256::digest(b"request one");
        let h2 = sha2::Sha256::digest(b"request two");
        assert!(!a.check_replay(&h1).await.unwrap(), "first sight at A");
        assert!(b.check_replay(&h1).await.unwrap(), "replayed to B: refused");
        assert!(
            a.check_replay(&h1).await.unwrap(),
            "replayed to A: refused locally"
        );
        assert!(!b.check_replay(&h2).await.unwrap(), "another request at B");
        assert!(
            a.check_replay(&h2).await.unwrap(),
            "replayed to A: refused via B's store"
        );

        // The nonce was written to both stores with a TTL.
        let key = format!("replay:{net}:{}", hex::encode(h1));
        let ttl_a: i64 = redis::cmd("TTL")
            .arg(&key)
            .query_async(&mut a_sec)
            .await
            .unwrap();
        let ttl_b: i64 = redis::cmd("TTL")
            .arg(&key)
            .query_async(&mut b_sec)
            .await
            .unwrap();
        assert!(ttl_a > 0 && ttl_a <= REPLAY_TTL_SECS as i64);
        assert!(ttl_b > 0 && ttl_b <= REPLAY_TTL_SECS as i64);
        let _: () = redis::cmd("FLUSHDB").query_async(&mut a_sec).await.unwrap();
        let _: () = redis::cmd("FLUSHDB").query_async(&mut b_sec).await.unwrap();
    }

    #[tokio::test]
    async fn test_replay_peer_unreachable_policy() {
        // An unreachable peer: the local verdict stands by default, refuses with fail-closed.
        let Some(conn) = local_redis().await else {
            return;
        };
        let net = "testnet-peer-down";
        let dead = "redis://127.0.0.1:1".to_string();
        let open_peers = |fail_closed: bool| {
            let dead = dead.clone();
            async move { ReplayPeers::connect(&[dead], net.to_string(), 100, fail_closed).await }
        };
        let cache_open = test_cache(conn.clone(), Some(conn.clone()), net)
            .with_replay_peers(open_peers(false).await);
        let h = sha2::Sha256::digest(unique("peer down request"));
        assert!(!cache_open.check_replay(&h).await.unwrap());
        assert!(
            cache_open.check_replay(&h).await.unwrap(),
            "local store still works"
        );

        let cache_closed = test_cache(conn.clone(), Some(conn.clone()), net)
            .with_replay_peers(open_peers(true).await);
        let h2 = sha2::Sha256::digest(unique("peer down request 2"));
        assert!(
            cache_closed.check_replay(&h2).await.is_err(),
            "fail-closed refuses"
        );
    }

    /// Two origins A (DB `a`) and B (DB `b`), each listing the other as a peer, in `mode`.
    /// Replication tunables are short so the tests stay fast; `batch_interval` is the
    /// replication window the "before/after" tests rely on.
    async fn two_origins(
        net: &str,
        a: u8,
        b: u8,
        mode: ReplayPeerMode,
        fail_closed_writes: bool,
        batch_interval_ms: u64,
    ) -> (
        ResponseCache,
        ResponseCache,
        ConnectionManager,
        ConnectionManager,
    ) {
        let open = |db: u8| async move {
            ConnectionManager::new(
                redis::Client::open(format!("redis://127.0.0.1:6379/{db}")).unwrap(),
            )
            .await
            .unwrap()
        };
        let (mut a_sec, mut b_sec) = (open(a).await, open(b).await);
        let _: () = redis::cmd("FLUSHDB").query_async(&mut a_sec).await.unwrap();
        let _: () = redis::cmd("FLUSHDB").query_async(&mut b_sec).await.unwrap();
        let cfg = |network: &str| {
            // max_lag above the longest batch window used here (400 ms), recovery 1 s.
            let mut c = ReplicationConfig::new(network, mode, 1000, 1, 250, REPLAY_TTL_SECS, 3);
            c.batch_interval = Duration::from_millis(batch_interval_ms);
            c.probe_interval = Duration::from_millis(100);
            c
        };
        let peers_of_a = ReplayPeers::connect(
            &[format!("redis://127.0.0.1:6379/{b}")],
            net.to_string(),
            LOCAL_TEST_OP_TIMEOUT.as_millis() as u64,
            false,
        )
        .await
        .with_mode(mode, fail_closed_writes);
        let peers_of_b = ReplayPeers::connect(
            &[format!("redis://127.0.0.1:6379/{a}")],
            net.to_string(),
            LOCAL_TEST_OP_TIMEOUT.as_millis() as u64,
            false,
        )
        .await
        .with_mode(mode, fail_closed_writes);
        let ca = test_cache(a_sec.clone(), Some(a_sec.clone()), net)
            .with_replay_peers(peers_of_a)
            .with_async_replication(cfg(net));
        let cb = test_cache(b_sec.clone(), Some(b_sec.clone()), net)
            .with_replay_peers(peers_of_b)
            .with_async_replication(cfg(net));
        (ca, cb, a_sec, b_sec)
    }

    /// Wait until the replicator has left its startup strict phase (recovery 1 s here).
    async fn wait_relaxed(c: &ResponseCache) {
        for _ in 0..60 {
            if c.replicator().unwrap().health().effective() == Effective::Relaxed {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("replication never became healthy");
    }

    const READ: RouteClass = RouteClass::Read;
    /// The existing tests check the one-sided paths (a route on REPLAY_ONE_SIDED_WRITE_ROUTES).
    const ONE_SIDED: WritePolicy = WritePolicy::ONE_SIDED;
    const WRITE: RouteClass = RouteClass::Write;

    #[tokio::test]
    async fn test_async_reads_mode_replicates_reads_and_keeps_writes_synchronous() {
        let Some(_) = local_redis().await else {
            return;
        };
        let net = "testnet-async-reads";
        let (a, b, mut a_sec, mut b_sec) =
            two_origins(net, 8, 9, ReplayPeerMode::AsyncReads, true, 20).await;
        assert_eq!(a.replay_peer_mode(), ReplayPeerMode::AsyncReads);
        wait_relaxed(&a).await;
        wait_relaxed(&b).await;

        // READ at A: the local check is synchronous, the peer write asynchronous.
        let h1 = sha2::Sha256::digest(b"read one");
        assert!(!a.check_replay(&h1).await.unwrap());
        // Timed: the peer step alone (the local check runs on the shared test Redis).
        let t = std::time::Instant::now();
        assert!(!a.replicate_nonce(&h1, READ, ONE_SIDED).await.unwrap());
        assert!(t.elapsed() < Duration::from_millis(200));
        // check_replay did NOT touch the peer store in this mode (only sync mode does).
        let key1 = format!("replay:{net}:{}", hex::encode(h1));
        let at_b_now: Option<String> = redis::cmd("GET")
            .arg(&key1)
            .query_async(&mut b_sec)
            .await
            .unwrap();
        // ... but it arrives within the batch window.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let at_b_later: Option<String> = redis::cmd("GET")
            .arg(&key1)
            .query_async(&mut b_sec)
            .await
            .unwrap();
        assert!(at_b_later.is_some(), "replicated asynchronously");
        let ttl_b: i64 = redis::cmd("TTL")
            .arg(&key1)
            .query_async(&mut b_sec)
            .await
            .unwrap();
        assert!(ttl_b > 0 && ttl_b <= REPLAY_TTL_SECS as i64);
        let _ = at_b_now; // may or may not have landed yet: timing, not a contract
                          // Replay to B after replication: refused by B's local check.
        assert!(
            b.check_replay(&h1).await.unwrap(),
            "replayed to B after replication: 409"
        );

        // WRITE at A: synchronous at the peer, so an immediate replay at B is refused.
        let h2 = sha2::Sha256::digest(b"write one");
        assert!(!a.check_replay(&h2).await.unwrap());
        assert!(!a.replicate_nonce(&h2, WRITE, ONE_SIDED).await.unwrap());
        let key2 = format!("replay:{net}:{}", hex::encode(h2));
        let at_b: Option<String> = redis::cmd("GET")
            .arg(&key2)
            .query_async(&mut b_sec)
            .await
            .unwrap();
        assert!(
            at_b.is_some(),
            "WRITE nonce is at the peer before the request proceeds"
        );
        assert!(
            b.check_replay(&h2).await.unwrap(),
            "immediate replay of a WRITE at B: 409"
        );
        // A WRITE at B lands in A's store synchronously, so A refuses it locally.
        let h3 = sha2::Sha256::digest(b"write seen at b first");
        assert!(!b.check_replay(&h3).await.unwrap());
        assert!(!b.replicate_nonce(&h3, WRITE, ONE_SIDED).await.unwrap());
        assert!(
            a.check_replay(&h3).await.unwrap(),
            "B's synchronous write is in A's store"
        );
        // A nonce only the peer holds (e.g. written there by a third origin): A's local store is
        // fresh, the synchronous WRITE check at the peer refuses it (check-any).
        let h4 = sha2::Sha256::digest(b"write known to b only");
        let key4 = format!("replay:{net}:{}", hex::encode(h4));
        let _: () = redis::cmd("SET")
            .arg(&key4)
            .arg("1")
            .arg("EX")
            .arg(600)
            .query_async(&mut b_sec)
            .await
            .unwrap();
        assert!(
            !a.check_replay(&h4).await.unwrap(),
            "A's local store is fresh..."
        );
        assert!(
            a.replicate_nonce(&h4, WRITE, ONE_SIDED).await.unwrap(),
            "...but the peer check refuses it"
        );

        let _: () = redis::cmd("FLUSHDB").query_async(&mut a_sec).await.unwrap();
        let _: () = redis::cmd("FLUSHDB").query_async(&mut b_sec).await.unwrap();
    }

    /// A WRITE checked at a peer waits for that peer's replicas: the CI Redis has none, so a
    /// required acknowledgement fails closed, `0` replicas passes, and an unreachable peer the
    /// policy tolerates (`REPLAY_PEER_FAIL_CLOSED_WRITES=0`, peer down) is not waited for.
    #[tokio::test]
    async fn test_peer_write_nonce_waits_for_the_peer_replicas() {
        let Some(_) = local_redis().await else {
            return;
        };
        let net = "testnet-peer-wait";
        let open = |db: u8| async move {
            ConnectionManager::new(
                redis::Client::open(format!("redis://127.0.0.1:6379/{db}")).unwrap(),
            )
            .await
            .unwrap()
        };
        let (mut a_sec, mut peer_store) = (open(2).await, open(3).await);
        let _: () = redis::cmd("FLUSHDB").query_async(&mut a_sec).await.unwrap();
        let _: () = redis::cmd("FLUSHDB")
            .query_async(&mut peer_store)
            .await
            .unwrap();
        let read_origin = |wait: WriteWaitConfig| {
            let a_sec = a_sec.clone();
            async move {
                let peers = ReplayPeers::connect(
                    &["redis://127.0.0.1:6379/3".to_string()],
                    net.to_string(),
                    LOCAL_TEST_OP_TIMEOUT.as_millis() as u64,
                    false,
                )
                .await
                .with_mode(ReplayPeerMode::AsyncReads, true)
                .with_wait(Some(wait));
                test_cache(a_sec.clone(), Some(a_sec), net).with_replay_peers(peers)
            }
        };

        let strict = read_origin(WriteWaitConfig {
            replicas: 1,
            timeout_ms: 50,
        })
        .await;
        // The WAIT connection is opened at startup, not inside the first WRITE's budget.
        let peers = strict.replay_peers.clone().unwrap();
        for _ in 0..40 {
            if peers.peers[0].wait.any_connected() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            peers.peers[0].wait.any_connected(),
            "WAIT connection opened in the background"
        );
        let h1 = sha2::Sha256::digest(unique("write without a replica"));
        assert!(!strict.check_replay(&h1).await.unwrap());
        let started = std::time::Instant::now();
        let err = strict
            .replicate_nonce(&h1, WRITE, ONE_SIDED)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not acknowledged"), "{err}");
        // Retried once: two full server-side WAITs.
        assert!(
            started.elapsed() >= Duration::from_millis(100),
            "{:?}",
            started.elapsed()
        );
        // READs are not delayed.
        let h2 = sha2::Sha256::digest(unique("read without a replica"));
        assert!(!strict.check_replay(&h2).await.unwrap());
        assert!(!strict.replicate_nonce(&h2, READ, ONE_SIDED).await.unwrap());

        let none_needed = read_origin(WriteWaitConfig {
            replicas: 0,
            timeout_ms: 50,
        })
        .await;
        let h3 = sha2::Sha256::digest(unique("write, zero replicas"));
        assert!(!none_needed.check_replay(&h3).await.unwrap());
        assert!(!none_needed
            .replicate_nonce(&h3, WRITE, ONE_SIDED)
            .await
            .unwrap());
        let key3 = format!("replay:{net}:{}", hex::encode(h3));
        let ttl: i64 = redis::cmd("TTL")
            .arg(&key3)
            .query_async(&mut peer_store)
            .await
            .unwrap();
        assert!(
            ttl > 0 && ttl <= REPLAY_TTL_SECS as i64,
            "the nonce keeps its TTL at the peer store"
        );

        // Peer unreachable, WRITEs tolerated on the local check, nothing to wait for.
        let peers = ReplayPeers::connect(
            &["redis://127.0.0.1:1".to_string()],
            net.to_string(),
            100,
            false,
        )
        .await
        .with_mode(ReplayPeerMode::AsyncReads, false)
        .with_wait(Some(WriteWaitConfig {
            replicas: 1,
            timeout_ms: 50,
        }));
        let peer_origin =
            test_cache(a_sec.clone(), Some(a_sec.clone()), net).with_replay_peers(peers);
        let h4 = sha2::Sha256::digest(unique("local write, shared store down"));
        assert!(!peer_origin.check_replay(&h4).await.unwrap());
        assert!(!peer_origin
            .replicate_nonce(&h4, WRITE, ONE_SIDED)
            .await
            .unwrap());

        let _: () = redis::cmd("FLUSHDB").query_async(&mut a_sec).await.unwrap();
        let _: () = redis::cmd("FLUSHDB")
            .query_async(&mut peer_store)
            .await
            .unwrap();
    }

    #[test]
    fn test_local_waitaof_config_parse() {
        assert_eq!(
            LocalAofConfig::parse(None).unwrap(),
            LocalAofConfig::Auto(DEFAULT_REPLAY_LOCAL_WAITAOF_MS)
        );
        assert_eq!(
            LocalAofConfig::parse(Some(" ")).unwrap(),
            LocalAofConfig::Auto(DEFAULT_REPLAY_LOCAL_WAITAOF_MS)
        );
        assert_eq!(
            LocalAofConfig::parse(Some("0")).unwrap(),
            LocalAofConfig::Off
        );
        assert_eq!(
            LocalAofConfig::parse(Some("250")).unwrap(),
            LocalAofConfig::Required(250)
        );
        assert!(LocalAofConfig::parse(Some("-1")).is_err());
        assert!(LocalAofConfig::parse(Some("x")).is_err());
    }

    /// An origin whose peer store is down: a WRITE on the local check alone waits for the
    /// local AOF fsync. Without AOF the probe leaves it off (auto) or fails startup (required).
    #[tokio::test]
    async fn test_peer_down_local_write_waits_for_the_aof_fsync() {
        let Some(admin) = local_redis().await else {
            return;
        };
        let net = "testnet-local-waitaof";
        let url = "redis://127.0.0.1:6379/4";
        let sec = ConnectionManager::new(redis::Client::open(url).unwrap())
            .await
            .unwrap();
        let peer_origin = || {
            let sec = sec.clone();
            async move {
                let peers = ReplayPeers::connect(
                    &["redis://127.0.0.1:1".to_string()],
                    net.to_string(),
                    100,
                    false,
                )
                .await
                .with_mode(ReplayPeerMode::AsyncReads, false);
                test_cache(sec.clone(), Some(sec), net).with_replay_peers(peers)
            }
        };
        let set_aof = |on: bool| {
            let mut admin = admin.clone();
            async move {
                redis::cmd("CONFIG")
                    .arg("SET")
                    .arg("appendonly")
                    .arg(if on { "yes" } else { "no" })
                    .arg("appendfsync")
                    .arg(if on { "always" } else { "everysec" })
                    .query_async::<_, ()>(&mut admin)
                    .await
            }
        };
        if let Err(e) = set_aof(false).await {
            // The test needs `CONFIG SET` on the test store: a refusal by the store follows the
            // store policy, a store lost meanwhile fails the test.
            assert!(
                refused_by_the_store(&e),
                "the test store was lost during the test: {e}"
            );
            return crate::store::test_support::store_unusable(&format!(
                "the test store {} refused CONFIG SET appendonly: {e}",
                crate::store::test_support::TEST_STORE
            ));
        }

        let auto = peer_origin()
            .await
            .with_local_waitaof(url, LocalAofConfig::Auto(500))
            .await
            .unwrap();
        assert_eq!(auto.local_waitaof_ms(), None, "no AOF: auto leaves it off");
        let h0 = sha2::Sha256::digest(unique("local write, no aof"));
        assert!(!auto.check_replay(&h0).await.unwrap());
        assert!(!auto.replicate_nonce(&h0, WRITE, ONE_SIDED).await.unwrap());
        let err = peer_origin()
            .await
            .with_local_waitaof(url, LocalAofConfig::Required(500))
            .await
            .err()
            .expect("required without AOF fails");
        assert!(err.to_string().contains("REPLAY_LOCAL_WAITAOF_MS"), "{err}");

        set_aof(true).await.unwrap();
        let mut on = None;
        for _ in 0..100 {
            if let Ok(c) = peer_origin()
                .await
                .with_local_waitaof(url, LocalAofConfig::Required(500))
                .await
            {
                on = Some(c);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let on = on.expect("WAITAOF available once the AOF rewrite is done");
        assert_eq!(on.local_waitaof_ms(), Some(500));
        let h1 = sha2::Sha256::digest(unique("local write, aof"));
        assert!(!on.check_replay(&h1).await.unwrap());
        assert!(!on.replicate_nonce(&h1, WRITE, ONE_SIDED).await.unwrap());
        // READs are not delayed, and a nonce gone from the store fails closed.
        let h2 = sha2::Sha256::digest(unique("local read, aof"));
        assert!(!on.check_replay(&h2).await.unwrap());
        assert!(!on.replicate_nonce(&h2, READ, ONE_SIDED).await.unwrap());
        let h3 = sha2::Sha256::digest(unique("local write, nonce gone"));
        assert!(!on.check_replay(&h3).await.unwrap());
        let mut sec_conn = sec.clone();
        let _: () = redis::cmd("DEL")
            .arg(format!("replay:{net}:{}", hex::encode(h3)))
            .query_async(&mut sec_conn)
            .await
            .unwrap();
        let err = on.replicate_nonce(&h3, WRITE, ONE_SIDED).await.unwrap_err();
        assert!(err.to_string().contains("local AOF"), "{err}");

        // One peer took the nonce, another is down: the nonce is not only local, no WAITAOF
        // (the local copy is gone here, so a WAITAOF would fail). The peer that takes it is the
        // shared test Redis with `appendfsync always` on (the local test budget); the other one
        // refuses at once.
        let mixed_peers = ReplayPeers::connect(
            &[
                "redis://127.0.0.1:6379/5".to_string(),
                "redis://127.0.0.1:1".to_string(),
            ],
            net.to_string(),
            LOCAL_TEST_OP_TIMEOUT.as_millis() as u64,
            false,
        )
        .await
        .with_mode(ReplayPeerMode::AsyncReads, false);
        let mixed = test_cache(sec.clone(), Some(sec.clone()), net)
            .with_replay_peers(mixed_peers)
            .with_local_waitaof(url, LocalAofConfig::Required(500))
            .await
            .unwrap();
        let h4 = sha2::Sha256::digest(unique("write, one peer took it"));
        assert!(!mixed.check_replay(&h4).await.unwrap());
        let _: () = redis::cmd("DEL")
            .arg(format!("replay:{net}:{}", hex::encode(h4)))
            .query_async(&mut sec_conn)
            .await
            .unwrap();
        assert!(!mixed.replicate_nonce(&h4, WRITE, ONE_SIDED).await.unwrap());

        set_aof(false).await.unwrap();
        let _: () = redis::cmd("FLUSHDB")
            .query_async(&mut sec_conn)
            .await
            .unwrap();
        let mut peer5 =
            ConnectionManager::new(redis::Client::open("redis://127.0.0.1:6379/5").unwrap())
                .await
                .unwrap();
        let _: () = redis::cmd("FLUSHDB").query_async(&mut peer5).await.unwrap();
    }

    #[test]
    fn test_peer_wait_config_defaults_to_one_replica() {
        let parse = |replicas: Option<&str>| {
            WriteWaitConfig::parse_named(
                replicas,
                None,
                DEFAULT_REPLAY_PEER_WAIT_REPLICAS,
                "REPLAY_PEER_WAIT",
            )
            .unwrap()
        };
        assert_eq!(
            parse(None),
            Some(WriteWaitConfig {
                replicas: 1,
                timeout_ms: DEFAULT_REPLAY_WRITE_WAIT_MS
            })
        );
        assert_eq!(parse(Some("0")), None, "0 turns it off");
        let err = WriteWaitConfig::parse_named(Some("x"), None, 1, "REPLAY_PEER_WAIT").unwrap_err();
        assert!(err.to_string().contains("REPLAY_PEER_WAIT_REPLICAS"));
    }

    #[tokio::test]
    async fn test_async_reads_window_before_and_after_replication() {
        // Documents the bounded window: a READ replayed to the other origin BEFORE replication
        // lands is accepted there (and nothing else), the same replay later is refused.
        let Some(_) = local_redis().await else {
            return;
        };
        let net = "testnet-async-window";
        // A 400 ms batch window makes "before" deterministic.
        let (a, b, mut a_sec, mut b_sec) =
            two_origins(net, 10, 11, ReplayPeerMode::AsyncReads, true, 400).await;
        wait_relaxed(&a).await;
        wait_relaxed(&b).await;

        let h = sha2::Sha256::digest(b"read replayed fast");
        assert!(!a.check_replay(&h).await.unwrap());
        assert!(!a.replicate_nonce(&h, READ, ONE_SIDED).await.unwrap());
        // Inside the window: B accepts (its store does not have it yet) and enqueues its own
        // replication, which will find the nonce already at A.
        assert!(
            !b.check_replay(&h).await.unwrap(),
            "inside the replication window: accepted at B"
        );
        assert!(!b.replicate_nonce(&h, READ, ONE_SIDED).await.unwrap());
        tokio::time::sleep(Duration::from_millis(600)).await;
        // After the window: both stores hold it, both refuse.
        assert!(a.check_replay(&h).await.unwrap());
        assert!(b.check_replay(&h).await.unwrap());
        // The late detection is counted at the peer that replicated second.
        let key = format!("replay:{net}:{}", hex::encode(h));
        let ttl_a: i64 = redis::cmd("TTL")
            .arg(&key)
            .query_async(&mut a_sec)
            .await
            .unwrap();
        let ttl_b: i64 = redis::cmd("TTL")
            .arg(&key)
            .query_async(&mut b_sec)
            .await
            .unwrap();
        assert!(ttl_a > 0 && ttl_b > 0);

        let _: () = redis::cmd("FLUSHDB").query_async(&mut a_sec).await.unwrap();
        let _: () = redis::cmd("FLUSHDB").query_async(&mut b_sec).await.unwrap();
    }

    #[tokio::test]
    async fn test_async_reads_peer_down_is_strict_and_writes_fail_closed() {
        let Some(conn) = local_redis().await else {
            return;
        };
        let net = "testnet-async-peer-down";
        let dead = "redis://127.0.0.1:1".to_string();
        let mk = |fail_closed_writes: bool| {
            let dead = dead.clone();
            let conn = conn.clone();
            async move {
                let peers = ReplayPeers::connect(&[dead], net.to_string(), 100, false)
                    .await
                    .with_mode(ReplayPeerMode::AsyncReads, fail_closed_writes);
                test_cache(conn.clone(), Some(conn.clone()), net)
                    .with_replay_peers(peers)
                    .with_async_replication(ReplicationConfig::new(
                        net,
                        ReplayPeerMode::AsyncReads,
                        300,
                        1,
                        100,
                        REPLAY_TTL_SECS,
                        3,
                    ))
            }
        };
        let c = mk(true).await;
        tokio::time::sleep(Duration::from_millis(1300)).await;
        // Never healthy: the peer is unreachable, so the probes fail and the mode stays strict.
        assert_eq!(
            c.replicator().unwrap().health().effective(),
            Effective::Strict
        );
        assert_eq!(
            c.replicator().unwrap().health().effective_label(),
            "async-reads-strict"
        );

        // READ on the strict path: synchronous peer attempt, local verdict stands
        // (REPLAY_PEER_FAIL_CLOSED=0) and nothing is enqueued.
        let h = sha2::Sha256::digest(unique("read with peer down"));
        assert!(!c.check_replay(&h).await.unwrap());
        assert!(!c.replicate_nonce(&h, READ, ONE_SIDED).await.unwrap());
        assert_eq!(
            c.replicator().unwrap().queue_depth(0),
            0,
            "strict READs are not enqueued"
        );
        assert!(
            c.check_replay(&h).await.unwrap(),
            "local store still refuses the replay"
        );

        // WRITE: fail-closed by default.
        let h2 = sha2::Sha256::digest(unique("write with peer down"));
        assert!(!c.check_replay(&h2).await.unwrap());
        let err = c.replicate_nonce(&h2, WRITE, ONE_SIDED).await.unwrap_err();
        assert!(
            err.to_string().contains("REPLAY_PEER_FAIL_CLOSED_WRITES"),
            "{err}"
        );

        // WRITE with REPLAY_PEER_FAIL_CLOSED_WRITES=0: local verdict.
        let c_open = mk(false).await;
        let h3 = sha2::Sha256::digest(unique("write with peer down, open"));
        assert!(!c_open.check_replay(&h3).await.unwrap());
        assert!(!c_open.replicate_nonce(&h3, WRITE, ONE_SIDED).await.unwrap());
    }

    #[tokio::test]
    async fn test_failover_mode_never_waits_for_peers() {
        let Some(conn) = local_redis().await else {
            return;
        };
        let net = "testnet-failover-dead";
        // A peer that accepts TCP but never answers would be the worst case; an unreachable one
        // shows the same property: no synchronous peer call, whatever the class or the flags.
        let peers = ReplayPeers::connect(
            &["redis://127.0.0.1:1".to_string()],
            net.to_string(),
            2000,
            true,
        )
        .await
        .with_mode(ReplayPeerMode::Failover, true);
        let c = test_cache(conn.clone(), Some(conn.clone()), net)
            .with_replay_peers(peers)
            .with_async_replication(ReplicationConfig::new(
                net,
                ReplayPeerMode::Failover,
                300,
                1,
                2000,
                REPLAY_TTL_SECS,
                3,
            ));
        for (i, class) in [READ, WRITE, READ, WRITE].into_iter().enumerate() {
            let h = sha2::Sha256::digest(unique(&format!("failover {i}")));
            assert!(!c.check_replay(&h).await.unwrap());
            // Timed: the peer step alone (the local check above runs on the shared test Redis,
            // whose latency is not what this test is about).
            let t = std::time::Instant::now();
            assert!(
                !c.replicate_nonce(&h, class, ONE_SIDED).await.unwrap(),
                "{class:?}"
            );
            assert!(
                t.elapsed() < Duration::from_millis(100),
                "{class:?} waited {:?}",
                t.elapsed()
            );
            assert!(
                c.check_replay(&h).await.unwrap(),
                "local replay still refused"
            );
        }
        assert_eq!(
            c.replicator().unwrap().health().effective_label(),
            "failover"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            c.replicator().unwrap().queue_depth(0) >= 1,
            "nonces wait for the peer to come back"
        );
    }

    #[tokio::test]
    async fn test_failover_mode_replicates_everything() {
        let Some(_) = local_redis().await else {
            return;
        };
        let net = "testnet-failover-live";
        let (a, b, mut a_sec, mut b_sec) =
            two_origins(net, 4, 5, ReplayPeerMode::Failover, true, 20).await;
        let hr = sha2::Sha256::digest(b"failover read");
        let hw = sha2::Sha256::digest(b"failover write");
        // No strict phase matters here: everything is local + async from the first request.
        for (h, class) in [(hr, READ), (hw, WRITE)] {
            assert!(!a.check_replay(&h).await.unwrap());
            assert!(!a.replicate_nonce(&h, class, ONE_SIDED).await.unwrap());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            b.check_replay(&hr).await.unwrap(),
            "READ nonce replicated to the passive origin"
        );
        assert!(
            b.check_replay(&hw).await.unwrap(),
            "WRITE nonce replicated to the passive origin"
        );
        let _: () = redis::cmd("FLUSHDB").query_async(&mut a_sec).await.unwrap();
        let _: () = redis::cmd("FLUSHDB").query_async(&mut b_sec).await.unwrap();
    }

    #[tokio::test]
    async fn test_sync_mode_is_unchanged_by_replicate_nonce() {
        let Some(_) = local_redis().await else {
            return;
        };
        let net = "testnet-sync-noop";
        let (a, b, mut a_sec, mut b_sec) =
            two_origins(net, 6, 7, ReplayPeerMode::Sync, true, 20).await;
        assert!(a.replicator().is_none(), "no replicator in sync mode");
        let h = sha2::Sha256::digest(b"sync request");
        assert!(
            !a.check_replay(&h).await.unwrap(),
            "check_replay wrote local + peer"
        );
        assert!(
            !a.replicate_nonce(&h, READ, ONE_SIDED).await.unwrap(),
            "no-op"
        );
        assert!(
            !a.replicate_nonce(&h, WRITE, ONE_SIDED).await.unwrap(),
            "no-op"
        );
        assert!(
            b.check_replay(&h).await.unwrap(),
            "already at B through the synchronous write"
        );
        let _: () = redis::cmd("FLUSHDB").query_async(&mut a_sec).await.unwrap();
        let _: () = redis::cmd("FLUSHDB").query_async(&mut b_sec).await.unwrap();
    }

    /// A Redis-protocol store for the permanent tier role tests: answers PING, `INFO
    /// replication` with `role`, and refuses writes with READONLY while `refuse` is set.
    async fn fake_permanent(
        role: &'static str,
        refuse: Arc<AtomicBool>,
        writes: Arc<AtomicU32>,
    ) -> String {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let (refuse, writes) = (refuse.clone(), writes.clone());
                tokio::spawn(async move {
                    let (r, mut w) = sock.into_split();
                    let mut r = BufReader::new(r);
                    loop {
                        let mut line = String::new();
                        if r.read_line(&mut line).await.unwrap_or(0) == 0 {
                            return;
                        }
                        let Some(n) = line
                            .trim_end()
                            .strip_prefix('*')
                            .and_then(|n| n.parse::<usize>().ok())
                        else {
                            return;
                        };
                        let mut args = Vec::new();
                        for _ in 0..n {
                            line.clear();
                            r.read_line(&mut line).await.unwrap();
                            let len: usize = line.trim_end()[1..].parse().unwrap();
                            let mut data = vec![0u8; len + 2];
                            r.read_exact(&mut data).await.unwrap();
                            data.truncate(len);
                            args.push(String::from_utf8_lossy(&data).to_uppercase());
                        }
                        let answer = match args[0].as_str() {
                            "PING" => "+PONG\r\n".to_string(),
                            "INFO" => {
                                let body = format!("# Replication\r\nrole:{role}\r\n");
                                format!("${}\r\n{body}\r\n", body.len())
                            }
                            "SET" | "MSET" | "DEL" => {
                                writes.fetch_add(1, Ordering::SeqCst);
                                if refuse.load(Ordering::SeqCst) {
                                    "-READONLY You can't write against a read only replica.\r\n"
                                        .to_string()
                                } else if args[0] == "DEL" {
                                    ":1\r\n".to_string()
                                } else {
                                    "+OK\r\n".to_string()
                                }
                            }
                            _ => "+OK\r\n".to_string(),
                        };
                        if w.write_all(answer.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        format!("redis://{addr}")
    }

    #[test]
    fn test_info_replication_role() {
        assert_eq!(
            info_replication_is_replica("# Replication\r\nrole:slave\r\nmaster_host:x\r\n"),
            Some(true)
        );
        assert_eq!(
            info_replication_is_replica("# Replication\r\nrole:master\r\nconnected_slaves:1\r\n"),
            Some(false)
        );
        assert_eq!(
            info_replication_is_replica("# Server\r\nredis_version:7\r\n"),
            None
        );
    }

    #[tokio::test]
    async fn test_permanent_tier_skips_writes_on_a_replica() {
        let refuse = Arc::new(AtomicBool::new(true));
        let writes = Arc::new(AtomicU32::new(0));
        let url = fake_permanent("slave", refuse.clone(), writes.clone()).await;
        let p = PermanentRedis::connect(&url, 500, "testnet-perm-replica".to_string())
            .await
            .unwrap();
        assert!(!p.writable(), "INFO replication says replica");
        assert!(!p.set("k".to_string(), Bytes::from_static(b"v")).await);
        assert!(
            !p.set_many(vec![("k".to_string(), Bytes::from_static(b"v"))])
                .await
        );
        p.del(vec!["k".to_string()]).await;
        assert_eq!(
            writes.load(Ordering::SeqCst),
            0,
            "nothing sent to a replica"
        );
    }

    #[tokio::test]
    async fn test_permanent_tier_stops_writing_on_readonly() {
        // The role probe says primary, but the node refuses writes (a demotion the probe has not
        // seen yet): the first refusal stops further writes.
        let refuse = Arc::new(AtomicBool::new(true));
        let writes = Arc::new(AtomicU32::new(0));
        let url = fake_permanent("master", refuse.clone(), writes.clone()).await;
        let p = PermanentRedis::connect(&url, 500, "testnet-perm-readonly".to_string())
            .await
            .unwrap();
        assert!(p.writable());
        assert!(!p.set("k".to_string(), Bytes::from_static(b"v")).await);
        assert!(!p.writable());
        assert!(!p.set("k2".to_string(), Bytes::from_static(b"v")).await);
        assert_eq!(writes.load(Ordering::SeqCst), 1);
        // The next role probe (housekeeping) finds a primary: writes resume.
        refuse.store(false, Ordering::SeqCst);
        p.refresh_role().await;
        assert!(p.writable());
        assert!(p.set("k3".to_string(), Bytes::from_static(b"v")).await);
    }

    #[tokio::test]
    async fn test_replay_failclosed_on_unreachable_security_redis() {
        // When the security Redis is unavailable, check_replay fails closed (Err).
        let Some(cache_conn) = local_redis().await else {
            return;
        };
        // ConnectionManager::new connects eagerly, so the "security Redis" is a TCP listener that
        // accepts and then never answers (a black-holed store): the connect succeeds, the SET
        // times out. Should construction itself need a reply, fall back to "not configured",
        // which is the other fail-closed path, rather than hang the test.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                held.push(sock);
            }
        });
        let security_client = redis::Client::open(format!("redis://127.0.0.1:{port}")).unwrap();
        let security_conn = timeout(
            Duration::from_secs(5),
            ConnectionManager::new(security_client),
        )
        .await
        .ok()
        .and_then(|r| r.ok());
        let mut cache = test_cache(cache_conn, security_conn, "testnet-failclosed");
        // The store never answers: the production-sized timeout keeps the test short.
        cache.redis_timeout = Duration::from_millis(250);

        let body_hash = {
            let mut h = sha2::Sha256::new();
            h.update(b"test-request-body");
            h.finalize()
        };
        let result = cache.check_replay(&body_hash).await;
        assert!(
            result.is_err(),
            "check_replay should return Err when security Redis is unreachable (fail closed)"
        );
    }

    #[tokio::test]
    #[ignore] // Only run with local Redis: cargo test test_cache_write_with_split_redis -- --ignored
    async fn test_cache_write_with_split_redis() {
        // With separate cache and security Redis the epoch lives only in the security Redis;
        // the write check must read it there. DB 14 is the cache Redis, DB 15 the security one.
        let cache_conn =
            ConnectionManager::new(redis::Client::open("redis://127.0.0.1:6379/14").unwrap())
                .await
                .unwrap();
        let security_conn =
            ConnectionManager::new(redis::Client::open("redis://127.0.0.1:6379/15").unwrap())
                .await
                .unwrap();
        let cache = test_cache(
            cache_conn.clone(),
            Some(security_conn.clone()),
            "split-redis-test",
        );
        cache.tip.set(crate::store::Tip {
            height: 100,
            hash: vec![1u8; 32],
        });
        let epoch_key = format!("epoch:{}", cache.network);
        let mut sec = security_conn.clone();
        let mut cc = cache_conn.clone();
        let _: () = redis::cmd("FLUSHDB").query_async(&mut cc).await.unwrap();
        let _: () = redis::cmd("DEL")
            .arg(&epoch_key)
            .query_async(&mut sec)
            .await
            .unwrap();

        let path = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLightdInfo";
        let response = bincode::serialize(&crate::ohttp::InnerResponse {
            status: 200,
            headers: vec![("grpc-status".to_string(), "0".to_string())],
            // LightdInfo { blockHeight: 100 }: an answer at the tip (tip-scoped answers must match it).
            body: vec![0, 0, 0, 0, 2, 0x38, 100],
        })
        .unwrap();
        let sem = tokio::sync::Semaphore::new(4);
        let fetches = std::sync::atomic::AtomicUsize::new(0);
        let fetch = || async {
            fetches.fetch_add(1, Ordering::SeqCst);
            Ok::<_, anyhow::Error>(response.clone())
        };

        let first = cache
            .get_or_fetch("POST", "application/grpc", path, &[], b"", &sem, fetch)
            .await
            .unwrap();
        assert_eq!(first, response);

        let cache_epoch: Option<u64> = redis::cmd("GET")
            .arg(&epoch_key)
            .query_async(&mut cc)
            .await
            .unwrap();
        assert_eq!(cache_epoch, None, "epoch must not live in the cache Redis");
        let dbsize: u64 = redis::cmd("DBSIZE").query_async(&mut cc).await.unwrap();
        assert_eq!(dbsize, 1, "response must be written to the cache Redis");

        let second = cache
            .get_or_fetch("POST", "application/grpc", path, &[], b"", &sem, fetch)
            .await
            .unwrap();
        assert_eq!(second, response);
        assert_eq!(
            fetches.load(Ordering::SeqCst),
            1,
            "second request must be a cache hit"
        );

        let epoch_at_read = cache.epoch.load(Ordering::Relaxed);
        let _: u64 = redis::cmd("INCR")
            .arg(&epoch_key)
            .query_async(&mut sec)
            .await
            .unwrap();
        let written = cache
            .write_if_epoch_current("stale-key", epoch_at_read, b"stale", Some(10))
            .await
            .unwrap();
        assert!(!written, "write with a superseded epoch must be skipped");

        let _: () = redis::cmd("FLUSHDB").query_async(&mut cc).await.unwrap();
        let _: () = redis::cmd("DEL")
            .arg(&epoch_key)
            .query_async(&mut sec)
            .await
            .unwrap();
    }

    /// A GetTreeState answer for `height`, as the gateway stores it.
    fn tree_state_answer(height: u64) -> Vec<u8> {
        let msg = prost::Message::encode_to_vec(&rpc_cache::TreeStateHead {
            height,
            hash: "ab".repeat(32),
        });
        let mut body = vec![0u8];
        body.extend_from_slice(&(msg.len() as u32).to_be_bytes());
        body.extend_from_slice(&msg);
        bincode::serialize(&crate::ohttp::InnerResponse {
            status: 200,
            headers: vec![("grpc-status".to_string(), "0".to_string())],
            body,
        })
        .unwrap()
    }

    /// A gRPC error answer with status `code` (HTTP 200, no message).
    fn grpc_error_answer(code: u32) -> Vec<u8> {
        bincode::serialize(&crate::ohttp::InnerResponse {
            status: 200,
            headers: vec![("grpc-status".to_string(), code.to_string())],
            body: vec![],
        })
        .unwrap()
    }

    fn unique_network(s: &str) -> String {
        String::from_utf8(unique(s)).unwrap().replace(' ', "-")
    }

    fn tip_at(cache: &ResponseCache, height: u64) {
        cache.tip.set(crate::store::Tip {
            height,
            hash: vec![1u8; 32],
        });
    }

    /// A pinned tier on the local test Redis for `pinned_sweep_pass`, heights `present`
    /// stored, the cursor at `cursor`.
    async fn sweep_fixture(
        network: &str,
        range: (u64, u64),
        present: impl Iterator<Item = u64>,
        cursor: u64,
    ) -> Option<(ResponseCache, Arc<StoreConn>, ConnectionManager)> {
        let conn = required_redis().await?;
        let mut cache = test_cache(conn.clone(), None, network);
        let pinned = StoreConn::from_parts(
            redis::Client::open("redis://127.0.0.1:6379").unwrap(),
            conn.clone(),
            "pinned",
            network.to_string(),
            Role::Any,
        );
        cache.pinned_conn = Some(pinned.clone());
        cache.pinned_range = Some(range);
        tip_at(&cache, 1000);
        let mut c = conn.clone();
        for h in present {
            let _: () = redis::cmd("SET")
                .arg(cache.pinned_key(h))
                .arg(tree_state_answer(h))
                .query_async(&mut c)
                .await
                .unwrap();
        }
        let _: () = redis::cmd("SET")
            .arg(cache.pinned_cursor_key())
            .arg(cursor)
            .query_async(&mut c)
            .await
            .unwrap();
        Some((cache, pinned, c))
    }

    /// `conn` as the store pinned writes go to, in the current writer generation.
    fn bound(cache: &ResponseCache, conn: &Arc<StoreConn>) -> PinnedWriter {
        PinnedWriter {
            conn: conn.clone(),
            generation: cache.pinned_writer_gen.load(Ordering::SeqCst),
        }
    }

    /// A fetch that records the heights asked and fails for those in `failing`.
    fn sweep_fetch(
        failing: Arc<parking_lot::Mutex<Vec<u64>>>,
    ) -> (
        Arc<parking_lot::Mutex<Vec<u64>>>,
        impl Fn(
            u64,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Vec<u8>>> + Send>>,
    ) {
        let fetched = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let f = fetched.clone();
        let fetch = move |h: u64| {
            let (f, failing) = (f.clone(), failing.clone());
            Box::pin(async move {
                f.lock().push(h);
                if failing.lock().contains(&h) {
                    anyhow::bail!("upstream down");
                }
                anyhow::Ok(tree_state_answer(h))
            })
                as std::pin::Pin<
                    Box<dyn std::future::Future<Output = anyhow::Result<Vec<u8>>> + Send>,
                >
        };
        (fetched, fetch)
    }

    #[tokio::test]
    async fn pinned_sweep_fills_a_height_whose_claim_was_lost() {
        let network = unique_network("pinned-sweep");
        // The workers claimed 1..=50; the INCR that claimed 17 timed out after the store
        // counted it, so nobody filled it.
        let Some((cache, pinned, mut c)) =
            sweep_fixture(&network, (1, 200), (1..=50u64).filter(|h| *h != 17), 50).await
        else {
            return;
        };
        let (fetched, fetch) = sweep_fetch(Arc::default());
        let pass = pinned_sweep_pass(&cache, &bound(&cache, &pinned), (1, 200), 0, &fetch)
            .await
            .unwrap();
        assert_eq!((pass.filled, pass.next, pass.holes), (1, 51, Some(0)));
        assert_eq!(*fetched.lock(), vec![17]);
        assert!(cache.pinned_exists(17).await);
        // The mark is shared and moves on: nothing to fill again.
        let pass = pinned_sweep_pass(&cache, &bound(&cache, &pinned), (1, 200), 0, &fetch)
            .await
            .unwrap();
        assert_eq!((pass.filled, pass.next), (0, 51));
        assert_eq!(fetched.lock().len(), 1);
        // Heights within the margin below the cursor are left to the workers.
        let _: () = redis::cmd("SET")
            .arg(cache.pinned_cursor_key())
            .arg(60)
            .query_async(&mut c)
            .await
            .unwrap();
        let pass = pinned_sweep_pass(&cache, &bound(&cache, &pinned), (1, 200), 5, &fetch)
            .await
            .unwrap();
        assert_eq!(
            pass.filled, 5,
            "51..=55 are missing and claimed long enough"
        );
        assert_eq!(pass.next, 56);
        assert_eq!(*fetched.lock(), vec![17, 51, 52, 53, 54, 55]);
    }

    /// A height whose fill fails is kept as a hole and retried by the next pass (also by
    /// another process: a new cache on the same store), while the mark moves on.
    #[tokio::test]
    async fn pinned_sweep_retries_a_failed_fill_and_survives_a_restart() {
        let network = unique_network("pinned-sweep-hole");
        let Some((cache, pinned, _c)) =
            sweep_fixture(&network, (1, 200), (1..=40u64).filter(|h| *h != 9), 40).await
        else {
            return;
        };
        let failing = Arc::new(parking_lot::Mutex::new(vec![9]));
        let (fetched, fetch) = sweep_fetch(failing.clone());
        let pass = pinned_sweep_pass(&cache, &bound(&cache, &pinned), (1, 200), 0, &fetch)
            .await
            .unwrap();
        assert_eq!((pass.filled, pass.next, pass.holes), (0, 41, Some(1)));
        assert!(!cache.pinned_exists(9).await);
        // The upstream is back; a restarted process (its own cache) retries the hole.
        failing.lock().clear();
        let Some((restarted, pinned2, _)) =
            sweep_fixture(&network, (1, 200), std::iter::empty(), 40).await
        else {
            return;
        };
        let pass = pinned_sweep_pass(
            &restarted,
            &bound(&restarted, &pinned2),
            (1, 200),
            0,
            &fetch,
        )
        .await
        .unwrap();
        assert_eq!((pass.filled, pass.next, pass.holes), (1, 41, Some(0)));
        assert!(cache.pinned_exists(9).await);
        // 1..=40 checked once: only the hole was fetched, twice.
        assert_eq!(*fetched.lock(), vec![9, 9, 9, 9]);
    }

    /// The range is done (a worker claimed past its end): the margin no longer hides its last
    /// heights, so a lost claim of the final height is found.
    #[tokio::test]
    async fn pinned_sweep_finds_a_lost_claim_of_the_final_height() {
        let network = unique_network("pinned-sweep-tail");
        let Some((cache, pinned, _c)) = sweep_fixture(&network, (1, 50), 1..=49u64, 51).await
        else {
            return;
        };
        let (fetched, fetch) = sweep_fetch(Arc::default());
        let pass = pinned_sweep_pass(&cache, &bound(&cache, &pinned), (1, 50), 64, &fetch)
            .await
            .unwrap();
        assert_eq!((pass.filled, pass.next), (1, 51));
        assert_eq!(*fetched.lock(), vec![50]);
    }

    /// A batch another process is sweeping is left to it.
    #[tokio::test]
    async fn pinned_sweep_batches_are_swept_by_one_process() {
        let network = unique_network("pinned-sweep-claim");
        let Some((cache, pinned, mut c)) = sweep_fixture(&network, (1, 200), 2..=30u64, 30).await
        else {
            return;
        };
        let _: () = redis::cmd("SET")
            .arg(cache.pinned_sweep_claim_key(sweep_batch_of(1)))
            .arg("another process")
            .arg("EX")
            .arg(60)
            .query_async(&mut c)
            .await
            .unwrap();
        let (fetched, fetch) = sweep_fetch(Arc::default());
        let pass = pinned_sweep_pass(&cache, &bound(&cache, &pinned), (1, 200), 0, &fetch)
            .await
            .unwrap();
        assert_eq!((pass.filled, pass.next), (0, 1));
        assert!(fetched.lock().is_empty());
        let _: () = redis::cmd("DEL")
            .arg(cache.pinned_sweep_claim_key(sweep_batch_of(1)))
            .query_async(&mut c)
            .await
            .unwrap();
        let pass = pinned_sweep_pass(&cache, &bound(&cache, &pinned), (1, 200), 0, &fetch)
            .await
            .unwrap();
        assert_eq!((pass.filled, pass.next), (1, 31));
        assert_eq!(*fetched.lock(), vec![1]);
    }

    /// A hole that keeps failing is dropped after PINNED_SWEEP_HOLE_ATTEMPTS retries.
    #[tokio::test]
    async fn pinned_sweep_drops_a_hole_that_keeps_failing() {
        let network = unique_network("pinned-sweep-drop");
        let Some((cache, pinned, mut c)) =
            sweep_fixture(&network, (1, 200), (1..=40u64).filter(|h| *h != 9), 40).await
        else {
            return;
        };
        let _: () = redis::pipe()
            .cmd("SADD")
            .arg(cache.pinned_holes_key())
            .arg(9)
            .ignore()
            .cmd("HSET")
            .arg(cache.pinned_hole_attempts_key())
            .arg(9)
            .arg(PINNED_SWEEP_HOLE_ATTEMPTS - 1)
            .ignore()
            .cmd("SET")
            .arg(cache.pinned_verified_key())
            .arg(41)
            .ignore()
            .query_async(&mut c)
            .await
            .unwrap();
        // The upstream is down: a pass counts no attempt.
        let (fetched, fetch) = sweep_fetch(Arc::new(parking_lot::Mutex::new(vec![9])));
        let pass = pinned_sweep_pass(&cache, &bound(&cache, &pinned), (1, 200), 0, &fetch)
            .await
            .unwrap();
        assert_eq!(
            pass.holes,
            Some(1),
            "kept: no answer says nothing about the height"
        );
        assert_eq!(*fetched.lock(), vec![9, 9, 9]);
        // The upstream answers, but never with an entry for the height: the last attempt.
        let wrong = |h: u64| {
            Box::pin(async move { anyhow::Ok(tree_state_answer(h + 1)) })
                as std::pin::Pin<
                    Box<dyn std::future::Future<Output = anyhow::Result<Vec<u8>>> + Send>,
                >
        };
        let pass = pinned_sweep_pass(&cache, &bound(&cache, &pinned), (1, 200), 0, &wrong)
            .await
            .unwrap();
        assert_eq!(pass.holes, Some(0), "dropped after its last attempt");
        let attempts: Option<u64> = redis::cmd("HGET")
            .arg(cache.pinned_hole_attempts_key())
            .arg(9)
            .query_async(&mut c)
            .await
            .unwrap();
        assert_eq!(attempts, None);
    }

    /// Only the holder of a batch's claim moves the shared mark, and only forward.
    #[tokio::test]
    async fn pinned_sweep_mark_moves_only_for_the_claim_holder() {
        let network = unique_network("pinned-sweep-fence");
        let Some((cache, pinned, mut c)) = sweep_fixture(&network, (1, 200), 1..=30u64, 30).await
        else {
            return;
        };
        let key = cache.pinned_sweep_claim_key(sweep_batch_of(1));
        let claim = SweepClaim::take(&pinned, key.clone(), Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(claim.advance_mark(&cache, 20).await, Ok(Ok(true))));
        assert!(matches!(claim.advance_mark(&cache, 10).await, Ok(Ok(true))));
        let reader = c.clone();
        let mark = || {
            let mut c = reader.clone();
            let key = cache.pinned_verified_key();
            async move {
                redis::cmd("GET")
                    .arg(key)
                    .query_async::<_, Option<u64>>(&mut c)
                    .await
                    .unwrap()
            }
        };
        assert_eq!(mark().await, Some(20), "never back");
        // Taken over by another process: the first holder moves nothing.
        let _: () = redis::cmd("SET")
            .arg(&key)
            .arg("another process")
            .query_async(&mut c)
            .await
            .unwrap();
        assert!(matches!(
            claim.advance_mark(&cache, 30).await,
            Ok(Ok(false))
        ));
        assert_eq!(mark().await, Some(20));
        claim.release().await;
        let _: () = redis::cmd("DEL")
            .arg(&key)
            .query_async(&mut c)
            .await
            .unwrap();
    }

    /// A claim that expired is taken over; the first holder can then neither renew nor release
    /// it, and the new holder releases it when its batch is done.
    #[tokio::test]
    async fn pinned_sweep_claims_are_taken_over_and_released_by_their_holder() {
        let network = unique_network("pinned-sweep-takeover");
        let Some((cache, pinned, mut c)) = sweep_fixture(&network, (1, 200), 2..=30u64, 30).await
        else {
            return;
        };
        let key = cache.pinned_sweep_claim_key(sweep_batch_of(1));
        // Another process's claim, expiring now.
        let _: () = redis::cmd("SET")
            .arg(&key)
            .arg("another process")
            .arg("PX")
            .arg(50)
            .query_async(&mut c)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        let (fetched, fetch) = sweep_fetch(Arc::default());
        let pass = pinned_sweep_pass(&cache, &bound(&cache, &pinned), (1, 200), 0, &fetch)
            .await
            .unwrap();
        assert_eq!((pass.filled, pass.next), (1, 31));
        assert_eq!(*fetched.lock(), vec![1]);
        let left: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut c)
            .await
            .unwrap();
        assert_eq!(left, None, "released when the batch was done");

        // A holder whose claim expired and was taken over neither renews nor releases it.
        let first = SweepClaim::take(&pinned, key.clone(), Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();
        let _: () = redis::cmd("SET")
            .arg(&key)
            .arg("the next holder")
            .query_async(&mut c)
            .await
            .unwrap();
        assert!(!first.renew().await);
        first.release().await;
        let left: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut c)
            .await
            .unwrap();
        assert_eq!(left.as_deref(), Some("the next holder"));
        let _: () = redis::cmd("DEL")
            .arg(&key)
            .query_async(&mut c)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn pinned_lookup_leaves_out_heights_that_are_not_final() {
        let Some(conn) = local_redis().await else {
            return;
        };
        let network = unique_network("pinned-depth");
        let mut cache = test_cache(conn.clone(), None, &network);
        cache.pinned_conn = Some(StoreConn::from_parts(
            redis::Client::open("redis://127.0.0.1:6379").unwrap(),
            conn,
            "pinned",
            network.clone(),
            Role::Any,
        ));
        cache.pinned_range = Some((1, u64::MAX));
        let at =
            |h: u64| cache.pinned_height("POST", GET_TREE_STATE_PATH, &grpc_tree_state_request(h));

        // Without a fresh tip every height of the range is looked up.
        assert_eq!(at(950), Some(950));
        assert_eq!(at(1005), Some(1005));

        // With one, only heights pinned_put can have written (deeper than FINALIZED_DEPTH).
        tip_at(&cache, 1000);
        assert_eq!(at(899), Some(899));
        assert_eq!(at(900), None);
        assert_eq!(at(1000), None);
        assert_eq!(at(1005), None);
    }

    /// The end marker's compare-and-set on a real store: concurrent writers keep the highest.
    #[tokio::test]
    async fn concurrent_max_writes_keep_the_highest_value() {
        let Some(conn) = required_redis().await else {
            return;
        };
        let network = unique_network("max-u32");
        let cache = test_cache(conn.clone(), None, &network);
        let epoch = cache.current_epoch();
        let key = format!("{network}:end-marker");
        let writes: Vec<_> = (1..=40u32)
            .rev()
            .chain(1..=40)
            .map(|v| {
                let cache = cache.clone();
                let key = key.clone();
                tokio::spawn(async move { cache.set_max_u32(key, v, 60, epoch).await })
            })
            .collect();
        for w in writes {
            assert!(w.await.unwrap().is_some());
        }
        let mut c = conn;
        let stored: Vec<u8> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut c)
            .await
            .unwrap();
        assert_eq!(stored, 40u32.to_be_bytes().to_vec());
        assert_eq!(
            cache.set_max_u32(key.clone(), 39, 60, epoch).await,
            Some(false)
        );
        assert_eq!(
            cache.set_max_u32(key.clone(), 41, 60, epoch).await,
            Some(true)
        );
        let _: () = redis::cmd("DEL")
            .arg(&key)
            .query_async(&mut c)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn pinned_writes_pause_while_the_store_is_read_only() {
        let Some(conn) = local_redis().await else {
            return;
        };
        let network = unique_network("pinned-read-only");
        let mut cache = test_cache(conn.clone(), None, &network);
        cache.pinned_conn = Some(StoreConn::from_parts(
            redis::Client::open("redis://127.0.0.1:6379").unwrap(),
            conn.clone(),
            "pinned",
            network.clone(),
            Role::Any,
        ));
        cache.pinned_range = Some((1, u64::MAX));
        tip_at(&cache, 1000);
        let answer = tree_state_answer(500);

        // Known to be read-only: nothing is sent.
        assert!(cache.mark_pinned_read_only());
        assert!(!cache.mark_pinned_read_only(), "logged once per change");
        assert!(!cache.pinned_put(500, &answer).await);
        assert_eq!(cache.pinned_get(500).await, None);

        // Once the pause is over the store is asked again; a primary is written to again.
        cache.pinned_read_only_until.store(1, Ordering::Relaxed);
        assert!(cache.pinned_put(500, &answer).await);
        assert_eq!(cache.pinned_read_only_until.load(Ordering::Relaxed), 0);
        assert_eq!(cache.pinned_get(500).await, Some(answer));

        let mut c = conn;
        let _: () = redis::cmd("DEL")
            .arg(cache.pinned_key(500))
            .query_async(&mut c)
            .await
            .unwrap();
    }

    /// A pinned backfill started while its store is read-only waits, and starts once the store
    /// takes writes (a promoted replica), without a restart.
    #[tokio::test]
    async fn pinned_backfill_starts_once_the_store_takes_writes() {
        let Some(conn) = required_redis().await else {
            return;
        };
        let network = unique_network("pinned-backfill-resume");
        let mut cache = test_cache(conn.clone(), None, &network);
        cache.pinned_conn = Some(StoreConn::from_parts(
            redis::Client::open("redis://127.0.0.1:6379").unwrap(),
            conn.clone(),
            "pinned",
            network.clone(),
            Role::Any,
        ));
        cache.pinned_range = Some((1, u64::MAX));
        tip_at(&cache, 1000);
        assert!(cache.mark_pinned_read_only());
        let fetches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = fetches.clone();
        let tasks = spawn_pinned_backfill(cache.clone(), 1, move |_height| {
            let counted = counted.clone();
            async move {
                counted.fetch_add(1, Ordering::SeqCst);
                Err::<Vec<u8>, _>(anyhow::anyhow!("not needed by the test"))
            }
        });
        tokio::time::sleep(PINNED_BACKFILL_RESUME_CHECK * 5).await;
        assert_eq!(fetches.load(Ordering::SeqCst), 0, "paused while read-only");
        // The pause is over and the store answers ROLE as a primary: the worker starts.
        cache.pinned_read_only_until.store(1, Ordering::Relaxed);
        let mut started = false;
        for _ in 0..100 {
            if fetches.load(Ordering::SeqCst) > 0 {
                started = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
        assert!(started, "the backfill resumed once the store took writes");
        let mut c = conn;
        let _: () = redis::cmd("DEL")
            .arg(cache.pinned_cursor_key())
            .query_async(&mut c)
            .await
            .unwrap();
    }

    /// A Redis-protocol server that answers `+OK` to every command except `ROLE`, which it
    /// never answers (a store that hangs on it).
    async fn role_hanging_store() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let Ok(n) = stream.read(&mut chunk).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        // Answer every complete command (RESP arrays of bulk strings).
                        while let Some((len, is_role)) = resp_command(&buf) {
                            buf.drain(..len);
                            if !is_role && stream.write_all(b"+OK\r\n").await.is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        });
        format!("redis://{addr}")
    }

    /// The length of the first complete RESP command in `buf` and whether it is `ROLE`.
    fn resp_command(buf: &[u8]) -> Option<(usize, bool)> {
        resp_command_name(buf).map(|(len, name)| (len, name == b"ROLE"))
    }

    /// The length of the first complete RESP command in `buf` and its name in upper case.
    fn resp_command_name(buf: &[u8]) -> Option<(usize, Vec<u8>)> {
        fn line(buf: &[u8], at: usize) -> Option<(&[u8], usize)> {
            let end = buf[at..].windows(2).position(|w| w == b"\r\n")? + at;
            Some((&buf[at..end], end + 2))
        }
        let (head, mut at) = line(buf, 0)?;
        let n: usize = std::str::from_utf8(head.strip_prefix(b"*")?)
            .ok()?
            .parse()
            .ok()?;
        let mut first = None;
        for _ in 0..n {
            let (len, next) = line(buf, at)?;
            let len: usize = std::str::from_utf8(len.strip_prefix(b"$")?)
                .ok()?
                .parse()
                .ok()?;
            if buf.len() < next + len + 2 {
                return None;
            }
            first.get_or_insert_with(|| buf[next..next + len].to_ascii_uppercase());
            at = next + len + 2;
        }
        Some((at, first.unwrap_or_default()))
    }

    /// A pinned store that does not answer its ROLE is not written to (asked again later).
    #[tokio::test]
    async fn a_pinned_store_without_a_role_answer_is_not_writable() {
        let Some(conn) = required_redis().await else {
            return;
        };
        let network = unique_network("pinned-role-timeout");
        let mut cache = test_cache(conn, None, &network);
        cache.redis_timeout = Duration::from_millis(300);
        let url = role_hanging_store().await;
        let store = StoreConn::connect(&url, "pinned", network.clone(), Role::Any)
            .await
            .unwrap();
        cache.pinned_conn = Some(store.clone());
        let generation = cache.pinned_writer_gen.load(Ordering::Relaxed);
        assert!(!cache.probe_pinned_writer(&store, generation).await);
        assert_ne!(cache.pinned_read_only_until.load(Ordering::Relaxed), 0);
        assert_ne!(cache.pinned_writer_gen.load(Ordering::Relaxed), generation);
        assert!(cache.pinned_writer().await.is_none(), "paused");
    }

    /// Backfill workers choose their store again when it changes.
    #[tokio::test]
    async fn pinned_backfill_workers_follow_a_change_of_store() {
        let Some(conn) = required_redis().await else {
            return;
        };
        let network = unique_network("pinned-backfill-switch");
        let mut cache = test_cache(conn.clone(), None, &network);
        let pinned = |name| {
            StoreConn::from_parts(
                redis::Client::open("redis://127.0.0.1:6379").unwrap(),
                conn.clone(),
                name,
                network.clone(),
                Role::Any,
            )
        };
        cache.pinned_conn = Some(pinned("pinned"));
        cache.pinned_range = Some((1, u64::MAX));
        tip_at(&cache, 1000);
        let tasks = spawn_pinned_backfill(cache.clone(), 2, move |_height| async move {
            Err::<Vec<u8>, _>(anyhow::anyhow!("not needed by the test"))
        });
        let wait_for = |n: usize| {
            let network = network.clone();
            async move {
                for _ in 0..400 {
                    if test_hooks::backfill_resolutions(&network) >= n {
                        return true;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                false
            }
        };
        assert!(wait_for(2).await, "both workers chose the pinned store");
        // The write store becomes available: every worker chooses again.
        cache.pinned_write_conn.store(Some(pinned("pinned_write")));
        cache.pinned_writer_gen.fetch_add(1, Ordering::Relaxed);
        let chose_again = wait_for(4).await;
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
        assert!(chose_again, "both workers chose the new store");
        let mut c = conn;
        let _: () = redis::cmd("DEL")
            .arg(cache.pinned_cursor_key())
            .query_async(&mut c)
            .await
            .unwrap();
    }

    /// A second pinned store: another database of the local test Redis (a keyspace of its own).
    async fn second_pinned_store(network: &str) -> (Arc<StoreConn>, ConnectionManager) {
        let client = redis::Client::open("redis://127.0.0.1:6379/13").unwrap();
        let conn = ConnectionManager::new(client.clone()).await.unwrap();
        let store = StoreConn::from_parts(
            client,
            conn.clone(),
            "pinned_write",
            network.to_string(),
            Role::Any,
        );
        (store, conn)
    }

    async fn key_exists(conn: &ConnectionManager, key: &str) -> bool {
        let mut c = conn.clone();
        redis::cmd("EXISTS")
            .arg(key)
            .query_async::<_, bool>(&mut c)
            .await
            .unwrap()
    }

    /// A fetch that records the heights asked, makes `store` the write store (a change of the
    /// store chosen while the fetch is in flight) and answers.
    fn switching_fetch(
        cache: &ResponseCache,
        store: &Arc<StoreConn>,
    ) -> (
        Arc<parking_lot::Mutex<Vec<u64>>>,
        impl Fn(
            u64,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Vec<u8>>> + Send>>,
    ) {
        let fetched = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let (f, cache, store) = (fetched.clone(), cache.clone(), store.clone());
        let fetch = move |h: u64| {
            let (f, cache, store) = (f.clone(), cache.clone(), store.clone());
            Box::pin(async move {
                f.lock().push(h);
                cache.pinned_write_conn.store(Some(store));
                cache.pinned_writer_gen.fetch_add(1, Ordering::SeqCst);
                anyhow::Ok(tree_state_answer(h))
            })
                as std::pin::Pin<
                    Box<dyn std::future::Future<Output = anyhow::Result<Vec<u8>>> + Send>,
                >
        };
        (fetched, fetch)
    }

    /// A backfill fill whose store is replaced while its upstream fetch is in flight writes
    /// nothing, to neither store; through the store chosen now it writes there only.
    #[tokio::test]
    async fn a_pinned_fill_writes_nothing_once_another_store_was_chosen() {
        let Some(conn) = required_redis().await else {
            return;
        };
        let network = unique_network("pinned-fill-switch");
        let mut cache = test_cache(conn.clone(), None, &network);
        let first = StoreConn::from_parts(
            redis::Client::open("redis://127.0.0.1:6379").unwrap(),
            conn.clone(),
            "pinned",
            network.clone(),
            Role::Any,
        );
        cache.pinned_conn = Some(first.clone());
        cache.pinned_range = Some((1, u64::MAX));
        tip_at(&cache, 1000);
        let (second, second_conn) = second_pinned_store(&network).await;
        let writer = cache.pinned_writer_bound().await.unwrap();
        assert!(Arc::ptr_eq(&writer.conn, &first));
        let (fetched, switching) = switching_fetch(&cache, &second);
        assert_eq!(
            pinned_fill(&cache, &switching, 500, &writer, FillMode::Inline).await,
            Fill::Superseded
        );
        assert_eq!(*fetched.lock(), vec![500], "no further attempt");
        let key = cache.pinned_key(500);
        assert!(!key_exists(&conn, &key).await);
        assert!(!key_exists(&second_conn, &key).await);
        // Nor through the write-through path's bound write with the old choice.
        assert_eq!(
            cache
                .pinned_put_bound(&writer, 500, &tree_state_answer(500))
                .await,
            None
        );
        assert!(!key_exists(&second_conn, &key).await);

        let now = cache.pinned_writer_bound().await.unwrap();
        assert!(Arc::ptr_eq(&now.conn, &second));
        let fetch = |h: u64| async move { anyhow::Ok(tree_state_answer(h)) };
        assert_eq!(
            pinned_fill(&cache, &fetch, 500, &now, FillMode::Inline).await,
            Fill::Stored
        );
        assert!(key_exists(&second_conn, &key).await);
        assert!(!key_exists(&conn, &key).await);
        let mut c = second_conn;
        let _: () = redis::cmd("DEL")
            .arg(&key)
            .query_async(&mut c)
            .await
            .unwrap();
    }

    /// A sweep whose store is replaced during a fill writes nothing more: no entry (on either
    /// store), no hole and no mark.
    #[tokio::test]
    async fn a_pinned_sweep_writes_nothing_once_another_store_was_chosen() {
        let network = unique_network("pinned-sweep-switch");
        let Some((cache, pinned, c)) =
            sweep_fixture(&network, (1, 200), (1..=50u64).filter(|h| *h != 17), 50).await
        else {
            return;
        };
        let (second, second_conn) = second_pinned_store(&network).await;
        let writer = bound(&cache, &pinned);
        let (fetched, switching) = switching_fetch(&cache, &second);
        let pass = pinned_sweep_pass(&cache, &writer, (1, 200), 0, &switching)
            .await
            .unwrap();
        assert_eq!(pass.filled, 0);
        assert_eq!(*fetched.lock(), vec![17]);
        let key = cache.pinned_key(17);
        assert!(!key_exists(&c, &key).await);
        assert!(!key_exists(&second_conn, &key).await);
        assert!(!key_exists(&c, &cache.pinned_holes_key()).await, "no hole");
        assert!(
            !key_exists(&c, &cache.pinned_verified_key()).await,
            "the mark did not move"
        );
        // A later pass through the old choice does nothing at all.
        let (fetched, fetch) = sweep_fetch(Arc::default());
        let pass = pinned_sweep_pass(&cache, &writer, (1, 200), 0, &fetch)
            .await
            .unwrap();
        assert_eq!((pass.filled, pass.next), (0, 1));
        assert!(fetched.lock().is_empty());
        assert!(!key_exists(&c, &cache.pinned_verified_key()).await);
    }

    const ROLE_PRIMARY: &[u8] = b"*3\r\n$6\r\nmaster\r\n:0\r\n*0\r\n";
    const ROLE_REPLICA: &[u8] =
        b"*5\r\n$5\r\nslave\r\n$9\r\n127.0.0.1\r\n:6379\r\n$9\r\nconnected\r\n:0\r\n";

    /// A Redis-protocol server that answers `ROLE` with `role`, `EXISTS`, `INCR` and `DECR`
    /// with 1 after `exists_delay`, and `+OK` to every other command.
    async fn scripted_store(role: &'static [u8], exists_delay: Duration) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let Ok(n) = stream.read(&mut chunk).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        while let Some((len, name)) = resp_command_name(&buf) {
                            buf.drain(..len);
                            let answer: &[u8] = match name.as_slice() {
                                b"ROLE" => role,
                                b"EXISTS" | b"INCR" | b"DECR" => {
                                    tokio::time::sleep(exists_delay).await;
                                    b":1\r\n"
                                }
                                _ => b"+OK\r\n",
                            };
                            if stream.write_all(answer).await.is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        });
        format!("redis://{addr}")
    }

    /// A cache whose pinned store is the one at `url`, its pause over (asked on its next use),
    /// and a write store on the local test Redis that is not published yet.
    async fn probe_race_fixture(name: &str, url: &str) -> Option<(ResponseCache, Arc<StoreConn>)> {
        let conn = required_redis().await?;
        let network = unique_network(name);
        let mut cache = test_cache(conn.clone(), None, &network);
        cache.redis_timeout = Duration::from_millis(300);
        cache.pinned_conn = Some(
            StoreConn::connect(url, "pinned", network.clone(), Role::Any)
                .await
                .unwrap(),
        );
        cache.pinned_range = Some((1, u64::MAX));
        cache.pinned_read_only_until.store(1, Ordering::SeqCst);
        let write = StoreConn::from_parts(
            redis::Client::open("redis://127.0.0.1:6379").unwrap(),
            conn,
            "pinned_write",
            network,
            Role::Any,
        );
        Some((cache, write))
    }

    /// A `ROLE` probe of the pinned store is stopped at its answer; the write store is
    /// published; the probe goes on. What the probe returned.
    async fn publish_during_a_probe(cache: &ResponseCache, write: &Arc<StoreConn>) -> Option<u64> {
        let gate = test_hooks::gate_probes(&cache.network);
        let probing = {
            let cache = cache.clone();
            tokio::spawn(async move { cache.pinned_writer_bound().await.map(|w| w.generation) })
        };
        timeout(Duration::from_secs(30), gate.reached.notified())
            .await
            .expect("the probe got its answer");
        cache.publish_pinned_write_conn(write.clone());
        test_hooks::ungate_probes(&cache.network);
        gate.release.add_permits(1);
        probing.await.unwrap()
    }

    /// Callers that ask the same store at the same time after a pause all get it.
    #[tokio::test]
    async fn concurrent_callers_after_a_pause_all_get_the_writer() {
        let url = scripted_store(ROLE_PRIMARY, Duration::ZERO).await;
        let Some((cache, _)) = probe_race_fixture("pinned-probe-concurrent", &url).await else {
            return;
        };
        let gate = test_hooks::gate_probes(&cache.network);
        let callers: Vec<_> = (0..2)
            .map(|_| {
                let cache = cache.clone();
                tokio::spawn(async move { cache.pinned_writer_bound().await })
            })
            .collect();
        // Both asked the store and have its answer; neither has acted on it yet.
        for _ in 0..600 {
            if gate.stopped.load(Ordering::SeqCst) == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(gate.stopped.load(Ordering::SeqCst), 2);
        test_hooks::ungate_probes(&cache.network);
        gate.release.add_permits(2);
        let pinned = cache.pinned_conn.clone().unwrap();
        for caller in callers {
            let writer = caller.await.unwrap().expect("the store takes writes");
            assert!(Arc::ptr_eq(&writer.conn, &pinned));
            assert!(cache.pinned_writer_current(&writer));
        }
        assert_eq!(cache.pinned_read_only_until.load(Ordering::SeqCst), 0);
    }

    /// A `ROLE` probe that succeeds after the write store connected does not lift the new
    /// store's pause: the new store is asked itself before its first use.
    #[tokio::test]
    async fn a_successful_probe_does_not_lift_the_pause_of_a_store_connected_meanwhile() {
        let url = scripted_store(ROLE_PRIMARY, Duration::ZERO).await;
        let Some((cache, write)) = probe_race_fixture("pinned-probe-race", &url).await else {
            return;
        };
        assert_eq!(publish_during_a_probe(&cache, &write).await, None);
        assert_eq!(
            cache.pinned_read_only_until.load(Ordering::SeqCst),
            1,
            "the new store is still to be asked"
        );
        // Its own probe (a primary) lifts its pause.
        let now = cache.pinned_writer_bound().await.unwrap();
        assert!(Arc::ptr_eq(&now.conn, &write));
        assert_eq!(cache.pinned_read_only_until.load(Ordering::SeqCst), 0);
    }

    /// A `ROLE` probe of the previous store that answers "replica", or does not answer, after
    /// the write store connected does not pause the new store: it is asked on its next use.
    #[tokio::test]
    async fn a_failed_probe_does_not_pause_a_store_connected_meanwhile() {
        let replica = scripted_store(ROLE_REPLICA, Duration::ZERO).await;
        let hanging = role_hanging_store().await;
        for (name, url) in [
            ("pinned-probe-replica", replica),
            ("pinned-probe-timeout", hanging),
        ] {
            let Some((cache, write)) = probe_race_fixture(name, &url).await else {
                return;
            };
            assert_eq!(publish_during_a_probe(&cache, &write).await, None, "{name}");
            assert_eq!(
                cache.pinned_read_only_until.load(Ordering::SeqCst),
                1,
                "{name}: asked on its next use, not paused"
            );
            let now = cache.pinned_writer_bound().await.unwrap();
            assert!(Arc::ptr_eq(&now.conn, &write), "{name}");
        }
        // Without a change of store the same answers pause the store that gave them.
        let replica = scripted_store(ROLE_REPLICA, Duration::ZERO).await;
        let Some((cache, _)) = probe_race_fixture("pinned-probe-replica-kept", &replica).await
        else {
            return;
        };
        assert!(cache.pinned_writer_bound().await.is_none());
        assert!(cache.pinned_read_only_until.load(Ordering::SeqCst) > ResponseCache::unix_ms());
    }

    /// The existence check of a height goes to the store the entries are written to and is
    /// bounded like its writes: a slow answer of a separate write store is not a missing entry.
    #[tokio::test]
    async fn the_existence_check_on_a_write_store_uses_the_write_timeout() {
        let Some(conn) = required_redis().await else {
            return;
        };
        let network = unique_network("pinned-exists-timeout");
        let mut cache = test_cache(conn, None, &network);
        cache.redis_timeout = Duration::from_millis(100);
        let slow = Duration::from_millis(600);
        assert!(slow > cache.redis_timeout && slow < PINNED_REMOTE_WRITE_TIMEOUT);
        let url = scripted_store(ROLE_PRIMARY, slow).await;
        let store = StoreConn::connect(&url, "pinned_write", network.clone(), Role::Any)
            .await
            .unwrap();
        // A separate write store: bounded by the write timeout, so the entry is found there
        // and not fetched and written again.
        cache.pinned_write_conn.store(Some(store.clone()));
        assert!(cache.pinned_exists_at(&store, 500).await);
        // No separate write store: bounded by the store timeout (a timeout reads as missing).
        cache.pinned_write_conn.store(None);
        assert!(!cache.pinned_exists_at(&store, 500).await);
    }

    /// The backfill cursor on a separate write store is bounded like its writes: a slow
    /// answer is a claim, not a cursor timeout.
    #[tokio::test]
    async fn the_backfill_cursor_on_a_write_store_uses_the_write_timeout() {
        let Some(conn) = required_redis().await else {
            return;
        };
        let network = unique_network("pinned-cursor-timeout");
        let mut cache = test_cache(conn, None, &network);
        cache.redis_timeout = Duration::from_millis(100);
        let slow = Duration::from_millis(600);
        assert!(slow > cache.redis_timeout * 4 && slow < PINNED_REMOTE_WRITE_TIMEOUT);
        let url = scripted_store(ROLE_PRIMARY, slow).await;
        let store = StoreConn::connect(&url, "pinned_write", network.clone(), Role::Any)
            .await
            .unwrap();
        cache.pinned_write_conn.store(Some(store.clone()));
        assert_eq!(cache.pinned_cursor_timeout(), PINNED_REMOTE_WRITE_TIMEOUT);
        for cmd in ["INCR", "DECR"] {
            assert!(
                matches!(cache.pinned_cursor_step(&store, cmd).await, Ok(Ok(1))),
                "{cmd}"
            );
        }
        // No separate write store: four store timeouts, as before.
        cache.pinned_write_conn.store(None);
        assert_eq!(cache.pinned_cursor_timeout(), cache.redis_timeout * 4);
        assert!(cache.pinned_cursor_step(&store, "INCR").await.is_err());
    }

    /// A sweep fill whose store is replaced while its upstream fetch hangs is abandoned within
    /// the check interval, counted, and its claim released (it held the batch until the fill
    /// timeout).
    #[tokio::test]
    async fn a_sweep_fill_whose_store_is_replaced_releases_its_claim_at_once() {
        let network = unique_network("pinned-sweep-switch-hang");
        let Some((cache, pinned, c)) =
            sweep_fixture(&network, (1, 200), (1..=50u64).filter(|h| *h != 17), 50).await
        else {
            return;
        };
        let (second, second_conn) = second_pinned_store(&network).await;
        let writer = bound(&cache, &pinned);
        let hanging = {
            let (cache, second) = (cache.clone(), second.clone());
            move |_h: u64| {
                let (cache, second) = (cache.clone(), second.clone());
                Box::pin(async move {
                    cache.pinned_write_conn.store(Some(second));
                    cache.pinned_writer_gen.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    anyhow::Ok(Vec::new())
                })
                    as std::pin::Pin<
                        Box<dyn std::future::Future<Output = anyhow::Result<Vec<u8>>> + Send>,
                    >
            }
        };
        let pass = timeout(
            PINNED_SWEEP_FILL_TIMEOUT / 4,
            pinned_sweep_pass(&cache, &writer, (1, 200), 0, &hanging),
        )
        .await
        .expect("abandoned well before the fill timeout")
        .unwrap();
        assert_eq!(pass.filled, 0);
        let count = |result| crate::health::cache_request_count(&network, "GetTreeState", result);
        assert_eq!(count("pinned_sweep_superseded"), 1, "counted once");
        assert_eq!(count("pinned_sweep_failed"), 0);
        assert!(
            !key_exists(&c, &cache.pinned_sweep_claim_key(sweep_batch_of(17))).await,
            "the claim of the batch is released"
        );
        assert!(!key_exists(&c, &cache.pinned_key(17)).await);
        assert!(!key_exists(&second_conn, &cache.pinned_key(17)).await);
        assert!(!key_exists(&c, &cache.pinned_holes_key()).await, "no hole");
        assert!(!key_exists(&c, &cache.pinned_verified_key()).await);
    }

    /// A backfill worker whose store is replaced during a fill counts the height it claimed.
    #[tokio::test]
    async fn a_backfill_worker_counts_a_height_whose_store_was_replaced() {
        let Some(conn) = required_redis().await else {
            return;
        };
        let network = unique_network("pinned-backfill-superseded");
        let mut cache = test_cache(conn.clone(), None, &network);
        cache.pinned_conn = Some(StoreConn::from_parts(
            redis::Client::open("redis://127.0.0.1:6379").unwrap(),
            conn.clone(),
            "pinned",
            network.clone(),
            Role::Any,
        ));
        cache.pinned_range = Some((1, u64::MAX));
        tip_at(&cache, 1000);
        let (second, second_conn) = second_pinned_store(&network).await;
        let (_, switching) = switching_fetch(&cache, &second);
        let switching = Arc::new(switching);
        let tasks = spawn_pinned_backfill(cache.clone(), 1, move |h| {
            let switching = switching.clone();
            async move { (*switching)(h).await }
        });
        let count = || {
            crate::health::cache_request_count(
                &network,
                "GetTreeState",
                "pinned_backfill_superseded",
            )
        };
        let mut counted = false;
        for _ in 0..400 {
            if count() >= 1 {
                counted = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
        assert!(counted, "the superseded height is counted");
        for c in [conn, second_conn] {
            let mut c = c;
            let _: () = redis::cmd("DEL")
                .arg(cache.pinned_cursor_key())
                .query_async(&mut c)
                .await
                .unwrap();
        }
    }

    /// A store connected while a lift of the pause is between its checks and the lift waits
    /// for the lift (the writer state lock is held): the lift does not clear the new store's
    /// pause, and the writer it returns is no longer current once the new store is published.
    #[tokio::test]
    async fn a_store_published_during_a_pause_lift_keeps_its_own_pause() {
        let url = scripted_store(ROLE_PRIMARY, Duration::ZERO).await;
        let Some((cache, write)) = probe_race_fixture("pinned-lift-window", &url).await else {
            return;
        };
        let publisher = Arc::new(parking_lot::Mutex::new(None));
        {
            let (cache, write, publisher) = (cache.clone(), write.clone(), publisher.clone());
            test_hooks::on_pause_lift(&cache.network.clone(), move || {
                // In the window: the state lock is held, so a publication waits for the lift.
                assert!(cache.pinned_writer_lock.try_lock().is_none());
                let started = Arc::new(std::sync::Barrier::new(2));
                let handle = {
                    let started = started.clone();
                    std::thread::spawn(move || {
                        started.wait();
                        cache.publish_pinned_write_conn(write);
                    })
                };
                started.wait();
                // Give the publication time to reach the lock.
                std::thread::sleep(Duration::from_millis(100));
                *publisher.lock() = Some(handle);
            });
        }
        let writer = cache.pinned_writer_bound().await.expect("lifted");
        let handle = publisher.lock().take().expect("the hook ran");
        handle.join().unwrap();
        assert!(Arc::ptr_eq(
            &writer.conn,
            cache.pinned_conn.as_ref().unwrap()
        ));
        assert!(
            !cache.pinned_writer_current(&writer),
            "the publication after the lift supersedes it"
        );
        assert_eq!(
            cache.pinned_read_only_until.load(Ordering::SeqCst),
            1,
            "the new store is still to be asked"
        );
        assert!(Arc::ptr_eq(&cache.pinned_write_target().unwrap(), &write));
    }

    /// A fetch whose every answer is the next gRPC error status of `codes` (HTTP 200, no
    /// message). Records the heights asked.
    fn erroring_fetch(
        codes: &'static [u32],
    ) -> (
        Arc<parking_lot::Mutex<Vec<u64>>>,
        impl Fn(
            u64,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Vec<u8>>> + Send>>,
    ) {
        let fetched = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let f = fetched.clone();
        let fetch = move |h: u64| {
            let f = f.clone();
            Box::pin(async move {
                let mut asked = f.lock();
                let code = codes[asked.len() % codes.len()];
                asked.push(h);
                anyhow::Ok(grpc_error_answer(code))
            })
                as std::pin::Pin<
                    Box<dyn std::future::Future<Output = anyhow::Result<Vec<u8>>> + Send>,
                >
        };
        (fetched, fetch)
    }

    /// An error status of the upstream is no verdict about the height (lightwalletd answers
    /// every failure of the call with `INVALID_ARGUMENT`, an unreachable node included): a
    /// finalized height answered with `INVALID_ARGUMENT` and `NOT_FOUND` is tried three times,
    /// becomes a hole, is not dropped before its attempts are used up, and is filled once the
    /// upstream answers.
    #[tokio::test]
    async fn an_error_status_of_the_upstream_is_retried_like_any_failure() {
        let network = unique_network("pinned-sweep-status");
        let Some((mut cache, pinned, mut c)) =
            sweep_fixture(&network, (1, 200), (1..=50u64).filter(|h| *h != 30), 50).await
        else {
            return;
        };
        // The height is above the lowest one that is filled.
        cache.pinned_fill_from = 20;
        let count = |result| crate::health::cache_request_count(&network, "GetTreeState", result);
        let (fetched, fetch) = erroring_fetch(&[3, 5]);
        let pass = pinned_sweep_pass(&cache, &bound(&cache, &pinned), (1, 200), 0, &fetch)
            .await
            .unwrap();
        assert_eq!((pass.filled, pass.next, pass.holes), (0, 51, Some(1)));
        assert_eq!(*fetched.lock(), vec![30, 30, 30], "three attempts");
        // The hole's retry fails the same way: one attempt counted, the hole stays.
        let pass = pinned_sweep_pass(&cache, &bound(&cache, &pinned), (1, 200), 0, &fetch)
            .await
            .unwrap();
        assert_eq!(pass.holes, Some(1));
        assert_eq!(fetched.lock().len(), 6);
        let attempts: Option<u64> = redis::cmd("HGET")
            .arg(cache.pinned_hole_attempts_key())
            .arg(30)
            .query_async(&mut c)
            .await
            .unwrap();
        assert_eq!(attempts, Some(1));
        assert!(PINNED_SWEEP_HOLE_ATTEMPTS > 1);
        assert_eq!(count("pinned_sweep_dropped"), 0);
        assert_eq!(count("pinned_sweep_failed"), 2);
        // The upstream answers again: filled, out of the holes.
        let (_, fetch) = sweep_fetch(Arc::default());
        let pass = pinned_sweep_pass(&cache, &bound(&cache, &pinned), (1, 200), 0, &fetch)
            .await
            .unwrap();
        assert_eq!((pass.filled, pass.holes), (1, Some(0)));
        assert!(cache.pinned_exists(30).await);
        assert_eq!(count("pinned_sweep_dropped"), 0);
    }

    /// A sweep whose claim of a batch is taken over by another process during a fill leaves
    /// the batch to it and counts nothing as superseded.
    #[tokio::test]
    async fn a_lost_sweep_claim_is_not_counted_as_superseded() {
        let network = unique_network("pinned-sweep-claim-lost");
        let missing = [17u64, 18];
        let Some((cache, pinned, c)) = sweep_fixture(
            &network,
            (1, 200),
            (1..=50u64).filter(|h| !missing.contains(h)),
            50,
        )
        .await
        else {
            return;
        };
        let key = cache.pinned_sweep_claim_key(sweep_batch_of(17));
        let fetched = Arc::new(parking_lot::Mutex::new(Vec::new()));
        // The fetch of the first height finds the claim taken over by another process.
        let stealing = {
            let (fetched, key, c) = (fetched.clone(), key.clone(), c.clone());
            move |h: u64| {
                let (fetched, key, mut c) = (fetched.clone(), key.clone(), c.clone());
                Box::pin(async move {
                    fetched.lock().push(h);
                    let _: () = redis::cmd("SET")
                        .arg(&key)
                        .arg("another-process")
                        .arg("PX")
                        .arg(60_000)
                        .query_async(&mut c)
                        .await?;
                    anyhow::Ok(tree_state_answer(h))
                })
                    as std::pin::Pin<
                        Box<dyn std::future::Future<Output = anyhow::Result<Vec<u8>>> + Send>,
                    >
            }
        };
        let pass = pinned_sweep_pass(&cache, &bound(&cache, &pinned), (1, 200), 0, &stealing)
            .await
            .unwrap();
        assert_eq!(pass.filled, 1);
        assert_eq!(
            *fetched.lock(),
            vec![17],
            "the batch is the other process's"
        );
        assert_eq!(
            crate::health::cache_request_count(&network, "GetTreeState", "pinned_sweep_superseded"),
            0
        );
        assert!(key_exists(&c, &key).await, "the other holder's claim stays");
        assert!(!key_exists(&c, &cache.pinned_verified_key()).await);
        let mut c = c;
        let _: () = redis::cmd("DEL")
            .arg(&key)
            .query_async(&mut c)
            .await
            .unwrap();
    }

    /// A fill under a sweep claim tells a lost claim from a change of store.
    #[tokio::test]
    async fn a_sweep_fill_tells_a_lost_claim_from_a_change_of_store() {
        let network = unique_network("pinned-sweep-fill-ends");
        let Some((cache, pinned, mut c)) = sweep_fixture(&network, (1, 200), 1..=1u64, 50).await
        else {
            return;
        };
        let (fetched, fetch) = sweep_fetch(Arc::default());
        let writer = bound(&cache, &pinned);
        let key = cache.pinned_sweep_claim_key(sweep_batch_of(1));
        let take = || SweepClaim::take(&pinned, key.clone(), Duration::from_secs(5));
        // Taken over by another process while the store is still the one chosen: lost.
        let claim = take().await.unwrap().unwrap();
        let _: () = redis::cmd("SET")
            .arg(&key)
            .arg("another-process")
            .query_async(&mut c)
            .await
            .unwrap();
        assert_eq!(
            claim.fill(&cache, &fetch, 7, &writer).await,
            SweepFill::ClaimLost
        );
        let _: () = redis::cmd("DEL")
            .arg(&key)
            .query_async(&mut c)
            .await
            .unwrap();
        // Held, with a current writer: the fill runs.
        let claim = take().await.unwrap().unwrap();
        assert_eq!(
            claim.fill(&cache, &fetch, 7, &writer).await,
            SweepFill::Done(Fill::Stored)
        );
        // Held, another store chosen: superseded, nothing fetched.
        cache.pinned_writer_gen.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            claim.fill(&cache, &fetch, 8, &writer).await,
            SweepFill::Superseded
        );
        assert_eq!(*fetched.lock(), vec![7]);
        // Taken over as well, with another store chosen: what the renewal says is about the
        // store that was replaced, so the fill counts as superseded, not as a lost claim.
        let _: () = redis::cmd("SET")
            .arg(&key)
            .arg("another-process")
            .query_async(&mut c)
            .await
            .unwrap();
        assert_eq!(
            claim.fill(&cache, &fetch, 9, &writer).await,
            SweepFill::Superseded
        );
        assert_eq!(*fetched.lock(), vec![7]);
        claim.release().await;
        let _: () = redis::cmd("DEL")
            .arg(&key)
            .query_async(&mut c)
            .await
            .unwrap();
    }

    /// A pass whose claim renewal fails after another store was chosen (the claim is taken over
    /// and the store replaced right before the renewal for its second height) counts that
    /// fill as superseded, once.
    #[tokio::test]
    async fn a_failed_renewal_after_a_change_of_store_is_counted_as_superseded() {
        let network = unique_network("pinned-sweep-renew-switch");
        let missing = [17u64, 18];
        let Some((cache, pinned, c)) = sweep_fixture(
            &network,
            (1, 200),
            (1..=50u64).filter(|h| !missing.contains(h)),
            50,
        )
        .await
        else {
            return;
        };
        let key = cache.pinned_sweep_claim_key(sweep_batch_of(17));
        // The renewal before the first fill goes through; at the start of the second one
        // another process takes the claim over and another store is chosen.
        {
            let (key, c, cache) = (key.clone(), c.clone(), cache.clone());
            let mut renewals = 0u32;
            test_hooks::on_sweep_renewal(&key.clone(), move || {
                renewals += 1;
                let second = renewals == 2;
                let (key, mut c, cache) = (key.clone(), c.clone(), cache.clone());
                Box::pin(async move {
                    if !second {
                        return;
                    }
                    let _: () = redis::cmd("SET")
                        .arg(&key)
                        .arg("another-process")
                        .arg("PX")
                        .arg(60_000)
                        .query_async(&mut c)
                        .await
                        .unwrap();
                    cache.pinned_writer_gen.fetch_add(1, Ordering::SeqCst);
                })
            });
        }
        let (fetched, fetch) = sweep_fetch(Arc::default());
        let pass = pinned_sweep_pass(&cache, &bound(&cache, &pinned), (1, 200), 0, &fetch)
            .await
            .unwrap();
        test_hooks::clear_sweep_renewal(&key);
        let count = |result| crate::health::cache_request_count(&network, "GetTreeState", result);
        assert_eq!(*fetched.lock(), vec![17], "the second height is not asked");
        assert_eq!(pass.filled, 1);
        assert_eq!(count("pinned_sweep_superseded"), 1, "exactly once");
        assert_eq!(count("pinned_sweep_failed"), 0);
        let mut c = c;
        let _: () = redis::cmd("DEL")
            .arg(&key)
            .query_async(&mut c)
            .await
            .unwrap();
    }

    type BoxedFetch =
        std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Vec<u8>>> + Send>>;

    /// A fetch whose calls wait at `gate` (one permit lets one call through) and then answer.
    /// Counts the calls started and the calls that ended.
    struct Gated {
        gate: Arc<tokio::sync::Semaphore>,
        started: Arc<std::sync::atomic::AtomicUsize>,
        ended: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Gated {
        fn new() -> Self {
            Self {
                gate: Arc::new(tokio::sync::Semaphore::new(0)),
                started: Arc::default(),
                ended: Arc::default(),
            }
        }

        fn fetch(&self) -> impl Fn(u64) -> BoxedFetch {
            let (gate, started, ended) =
                (self.gate.clone(), self.started.clone(), self.ended.clone());
            move |h: u64| {
                let (gate, started, ended) = (gate.clone(), started.clone(), ended.clone());
                Box::pin(async move {
                    started.fetch_add(1, Ordering::SeqCst);
                    gate.acquire().await.unwrap().forget();
                    ended.fetch_add(1, Ordering::SeqCst);
                    anyhow::Ok(tree_state_answer(h))
                }) as BoxedFetch
            }
        }

        fn started(&self) -> usize {
            self.started.load(Ordering::SeqCst)
        }

        fn ended(&self) -> usize {
            self.ended.load(Ordering::SeqCst)
        }
    }

    /// Wait (real time, at most 10 s) until `done`.
    async fn wait_until(what: &str, done: impl Fn() -> bool) {
        for _ in 0..500 {
            if done() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("timed out waiting: {what}");
    }

    /// A sweep fill abandoned because another store was chosen while its upstream call is in
    /// flight: superseded, claim released, counted as detached; the call goes on to its end,
    /// and nothing of its answer is written to either store.
    #[tokio::test]
    async fn a_superseded_sweep_fill_lets_its_upstream_call_end_and_writes_nothing() {
        let network = unique_network("pinned-sweep-detached-switch");
        let Some((cache, pinned, c)) =
            sweep_fixture(&network, (1, 200), (1..=50u64).filter(|h| *h != 17), 50).await
        else {
            return;
        };
        let (second, second_conn) = second_pinned_store(&network).await;
        let gated = Gated::new();
        let fetch = gated.fetch();
        let writer = bound(&cache, &pinned);
        let count = |result| crate::health::cache_request_count(&network, "GetTreeState", result);
        let (pass, ()) = tokio::join!(
            timeout(
                PINNED_SWEEP_FILL_TIMEOUT / 4,
                pinned_sweep_pass(&cache, &writer, (1, 200), 0, &fetch),
            ),
            async {
                wait_until("the call started", || gated.started() == 1).await;
                cache.pinned_write_conn.store(Some(second.clone()));
                cache.pinned_writer_gen.fetch_add(1, Ordering::SeqCst);
            }
        );
        let pass = pass
            .expect("abandoned well before the fill timeout")
            .unwrap();
        assert_eq!(pass.filled, 0);
        assert_eq!(count("pinned_sweep_superseded"), 1);
        assert_eq!(count("pinned_fetch_detached"), 1);
        assert!(!key_exists(&c, &cache.pinned_sweep_claim_key(sweep_batch_of(17))).await);
        assert_eq!((gated.started(), gated.ended()), (1, 0), "still in flight");
        gated.gate.add_permits(1);
        wait_until("the call ended", || gated.ended() == 1).await;
        wait_until("its permit is back", || {
            cache.pinned_sweep_fetch_permits.available_permits() == PINNED_SWEEP_FETCH_PERMITS
        })
        .await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!key_exists(&c, &cache.pinned_key(17)).await);
        assert!(!key_exists(&second_conn, &cache.pinned_key(17)).await);
        assert!(!key_exists(&c, &cache.pinned_holes_key()).await, "no hole");
        assert!(!key_exists(&c, &cache.pinned_verified_key()).await);
        assert_eq!(count("pinned_fetch_detached"), 1);
    }

    /// A sweep fill whose claim is taken over while its upstream call is in flight: the claim
    /// is lost (not counted as superseded), the fill counted as detached; the call goes on to
    /// its end and nothing of its answer is written.
    #[tokio::test]
    async fn a_sweep_fill_that_loses_its_claim_lets_its_upstream_call_end() {
        let network = unique_network("pinned-sweep-detached-claim");
        let Some((cache, pinned, c)) =
            sweep_fixture(&network, (1, 200), (1..=50u64).filter(|h| *h != 17), 50).await
        else {
            return;
        };
        // Renewals every 200 ms, so that the loss is seen while the call is in flight.
        test_hooks::set_sweep_timings(
            &network,
            Some((PINNED_SWEEP_FILL_TIMEOUT, Duration::from_millis(200))),
        );
        let key = cache.pinned_sweep_claim_key(sweep_batch_of(17));
        let gated = Gated::new();
        let fetch = gated.fetch();
        let count = |result| crate::health::cache_request_count(&network, "GetTreeState", result);
        let writer = bound(&cache, &pinned);
        let (pass, ()) = tokio::join!(
            pinned_sweep_pass(&cache, &writer, (1, 200), 0, &fetch),
            async {
                wait_until("the call started", || gated.started() == 1).await;
                let mut c = c.clone();
                let _: () = redis::cmd("SET")
                    .arg(&key)
                    .arg("another-process")
                    .arg("PX")
                    .arg(60_000)
                    .query_async(&mut c)
                    .await
                    .unwrap();
            }
        );
        test_hooks::set_sweep_timings(&network, None);
        assert_eq!(pass.unwrap().filled, 0);
        assert_eq!(count("pinned_sweep_superseded"), 0);
        assert_eq!(count("pinned_sweep_failed"), 0);
        assert_eq!(count("pinned_fetch_detached"), 1);
        assert_eq!((gated.started(), gated.ended()), (1, 0), "still in flight");
        gated.gate.add_permits(1);
        wait_until("the call ended", || gated.ended() == 1).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!key_exists(&c, &cache.pinned_key(17)).await);
        assert!(!key_exists(&c, &cache.pinned_holes_key()).await, "no hole");
        assert!(!key_exists(&c, &cache.pinned_verified_key()).await);
        assert!(key_exists(&c, &key).await, "the other holder's claim stays");
        let mut c = c;
        let _: () = redis::cmd("DEL")
            .arg(&key)
            .query_async(&mut c)
            .await
            .unwrap();
    }

    /// A sweep fill that times out while its upstream call is in flight ends as `NoAnswer`,
    /// counted as detached; the call goes on to its end and nothing of its answer is written.
    #[tokio::test]
    async fn a_sweep_fill_that_times_out_lets_its_upstream_call_end() {
        let network = unique_network("pinned-sweep-detached-timeout");
        let Some((cache, pinned, c)) = sweep_fixture(&network, (1, 200), 1..=1u64, 50).await else {
            return;
        };
        test_hooks::set_sweep_timings(
            &network,
            Some((Duration::from_millis(300), PINNED_SWEEP_CLAIM_TTL / 4)),
        );
        let key = cache.pinned_sweep_claim_key(sweep_batch_of(17));
        let claim = SweepClaim::take(&pinned, key, Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();
        let gated = Gated::new();
        let fetch = gated.fetch();
        let started = std::time::Instant::now();
        assert_eq!(
            claim
                .fill(&cache, &fetch, 17, &bound(&cache, &pinned))
                .await,
            SweepFill::Done(Fill::NoAnswer)
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        test_hooks::set_sweep_timings(&network, None);
        assert_eq!(
            crate::health::cache_request_count(&network, "GetTreeState", "pinned_fetch_detached"),
            1
        );
        assert_eq!((gated.started(), gated.ended()), (1, 0), "still in flight");
        gated.gate.add_permits(1);
        wait_until("the call ended", || gated.ended() == 1).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!key_exists(&c, &cache.pinned_key(17)).await);
        claim.release().await;
    }

    /// At most PINNED_SWEEP_FETCH_PERMITS sweep calls are alive: with two abandoned calls still
    /// running a fill starts the third; with three a fill starts none, leaves when another
    /// store is chosen, and goes on once a call ended. A worker's fill does not use the permits.
    #[tokio::test]
    async fn sweep_calls_are_bounded_by_their_permits() {
        let network = unique_network("pinned-sweep-detached-permits");
        let Some((cache, pinned, mut c)) = sweep_fixture(&network, (1, 200), 1..=1u64, 50).await
        else {
            return;
        };
        assert_eq!(PINNED_SWEEP_FETCH_PERMITS, 3);
        let key = cache.pinned_sweep_claim_key(sweep_batch_of(101));
        let claim = SweepClaim::take(&pinned, key, Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();
        let permits = || cache.pinned_sweep_fetch_permits.available_permits();
        let waits = || test_hooks::permit_waits(&network);
        let gated = Gated::new();
        let fetch = gated.fetch();
        // Three fills abandoned at a short fill timeout, each with its call still in flight
        // (gated: the timeout is the expected end of each).
        test_hooks::set_sweep_timings(
            &network,
            Some((Duration::from_millis(300), PINNED_SWEEP_CLAIM_TTL / 4)),
        );
        for n in 1..=3usize {
            let writer = bound(&cache, &pinned);
            assert_eq!(
                claim.fill(&cache, &fetch, 100 + n as u64, &writer).await,
                SweepFill::Done(Fill::NoAnswer)
            );
            assert_eq!(gated.started(), n, "one call per fill");
            assert_eq!(permits(), PINNED_SWEEP_FETCH_PERMITS - n);
        }
        // From here the default fill timeout: every step below waits for an event, not a timer.
        test_hooks::set_sweep_timings(&network, None);
        let watchdog = Duration::from_secs(30);
        // No permit left: the fill waits without starting a call, and leaves once another
        // store is chosen.
        let writer = bound(&cache, &pinned);
        let before = waits();
        let (outcome, ()) = timeout(watchdog, async {
            tokio::join!(claim.fill(&cache, &fetch, 104, &writer), async {
                wait_until("the fill waits for a permit", || waits() > before).await;
                cache.pinned_writer_gen.fetch_add(1, Ordering::SeqCst);
            })
        })
        .await
        .expect("watchdog");
        assert_eq!(outcome, SweepFill::Superseded);
        assert_eq!(gated.started(), 3, "no call started");
        // A worker's fill meanwhile: not bound by the sweep's permits.
        let writer = bound(&cache, &pinned);
        let answering = |h: u64| async move { anyhow::Ok(tree_state_answer(h)) };
        assert_eq!(permits(), 0);
        assert_eq!(
            pinned_fill(&cache, &answering, 106, &writer, FillMode::Inline).await,
            Fill::Stored
        );
        // Once a call ends, a waiting sweep fill goes on.
        let before = waits();
        let (outcome, ()) = timeout(watchdog, async {
            tokio::join!(claim.fill(&cache, &answering, 105, &writer), async {
                wait_until("the fill waits for a permit", || waits() > before).await;
                assert_eq!(gated.ended(), 0);
                gated.gate.add_permits(1);
            })
        })
        .await
        .expect("watchdog");
        assert_eq!(outcome, SweepFill::Done(Fill::Stored));
        assert_eq!(gated.ended(), 1);
        assert_eq!(
            crate::health::cache_request_count(&network, "GetTreeState", "pinned_fetch_detached"),
            3
        );
        gated.gate.add_permits(2);
        wait_until("every call ended", || gated.ended() == 3).await;
        wait_until("every permit is back", || {
            permits() == PINNED_SWEEP_FETCH_PERMITS
        })
        .await;
        claim.release().await;
        let _: () = redis::cmd("DEL")
            .arg(cache.pinned_key(105))
            .arg(cache.pinned_key(106))
            .query_async(&mut c)
            .await
            .unwrap();
    }

    /// A waiter dropped before taking its result counts the call only while it still runs: not
    /// once its task finished (nothing is left running), and once while it runs.
    #[tokio::test]
    async fn a_dropped_waiter_counts_only_a_call_still_running() {
        let network = unique_network("pinned-detached-waiter");
        let count = || {
            crate::health::cache_request_count(&network, "GetTreeState", "pinned_fetch_detached")
        };
        let permits = Arc::new(tokio::sync::Semaphore::new(2));
        // Finished, its result not taken.
        let waiter = DetachedWaiter {
            network: &network,
            call: spawn_with_permit(permits.clone().try_acquire_owned().unwrap(), async { 1u8 }),
            armed: true,
        };
        timeout(Duration::from_secs(10), async {
            while !waiter.call.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("watchdog");
        drop(waiter);
        assert_eq!(count(), 0, "finished: not counted");
        // Still running.
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let started = Arc::new(tokio::sync::Notify::new());
        let (g, s) = (gate.clone(), started.clone());
        let waiter = DetachedWaiter {
            network: &network,
            call: spawn_with_permit(permits.clone().try_acquire_owned().unwrap(), async move {
                s.notify_one();
                g.acquire().await.unwrap().forget();
                2u8
            }),
            armed: true,
        };
        timeout(Duration::from_secs(10), started.notified())
            .await
            .expect("watchdog");
        assert!(!waiter.call.is_finished());
        drop(waiter);
        assert_eq!(count(), 1, "running: counted once");
        gate.add_permits(1);
    }

    /// The permit of a sweep call is released when its task completes, panics, or is dropped
    /// without ever running (its runtime shut down).
    #[test]
    fn a_sweep_call_returns_its_permit_however_its_task_ends() {
        let permits = Arc::new(tokio::sync::Semaphore::new(PINNED_SWEEP_FETCH_PERMITS));
        let runtime = || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
        };
        // Dropped unpolled.
        let rt = runtime();
        {
            let _entered = rt.enter();
            let permit = permits.clone().try_acquire_owned().unwrap();
            drop(spawn_with_permit(permit, async { 1u8 }));
        }
        assert_eq!(permits.available_permits(), PINNED_SWEEP_FETCH_PERMITS - 1);
        drop(rt);
        assert_eq!(permits.available_permits(), PINNED_SWEEP_FETCH_PERMITS);
        // Panicked, and completed.
        runtime().block_on(async {
            let permit = permits.clone().try_acquire_owned().unwrap();
            let panics = true;
            let panicked = spawn_with_permit(permit, async move {
                if panics {
                    panic!("the upstream client panicked");
                }
            });
            assert!(panicked.await.unwrap_err().is_panic());
            assert_eq!(permits.available_permits(), PINNED_SWEEP_FETCH_PERMITS);
            let permit = permits.clone().try_acquire_owned().unwrap();
            assert_eq!(spawn_with_permit(permit, async { 7u8 }).await.unwrap(), 7);
            assert_eq!(permits.available_permits(), PINNED_SWEEP_FETCH_PERMITS);
        });
    }

    /// A sweep call that panics is a failed attempt of its fill (three, then `NoAnswer`), and
    /// its permit comes back.
    #[tokio::test]
    async fn a_panicking_sweep_call_is_a_failed_attempt() {
        let network = unique_network("pinned-sweep-detached-panic");
        let Some((cache, pinned, _c)) = sweep_fixture(&network, (1, 200), 1..=1u64, 50).await
        else {
            return;
        };
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let panicking = {
            let calls = calls.clone();
            move |h: u64| {
                let calls = calls.clone();
                Box::pin(async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(h, u64::MAX, "the upstream client panicked");
                    anyhow::Ok(Vec::new())
                }) as BoxedFetch
            }
        };
        assert_eq!(
            pinned_fill(
                &cache,
                &panicking,
                17,
                &bound(&cache, &pinned),
                FillMode::Detached(&cache.pinned_sweep_fetch_permits),
            )
            .await,
            Fill::NoAnswer
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(
            cache.pinned_sweep_fetch_permits.available_permits(),
            PINNED_SWEEP_FETCH_PERMITS
        );
        assert_eq!(
            crate::health::cache_request_count(&network, "GetTreeState", "pinned_fetch_detached"),
            0,
            "waited for to the end: not detached"
        );
    }

    /// Holes below the lowest height that is filled are counted as dropped only once the
    /// store has removed them: a store that refuses the removal keeps them, uncounted, and
    /// the next pass on a store that takes it drops them.
    #[tokio::test]
    async fn holes_below_the_floor_are_counted_only_once_the_store_removed_them() {
        let network = unique_network("pinned-sweep-floor-refused");
        let Some((mut cache, pinned, mut c)) =
            sweep_fixture(&network, (1, 2000), 600..=700u64, 700).await
        else {
            return;
        };
        cache.pinned_fill_from = 600;
        let _: () = redis::cmd("SADD")
            .arg(cache.pinned_holes_key())
            .arg(62)
            .arg(113)
            .query_async(&mut c)
            .await
            .unwrap();
        // A user of the test store that may not remove from the holes.
        let user = format!("u-{network}");
        let _: () = redis::cmd("ACL")
            .arg("SETUSER")
            .arg(&user)
            .arg("on")
            .arg(">test-only")
            .arg("~*")
            .arg("&*")
            .arg("+@all")
            .arg("-srem")
            .arg("-hdel")
            .query_async(&mut c)
            .await
            .unwrap();
        let refusing = StoreConn::connect(
            &format!("redis://{user}:test-only@127.0.0.1:6379"),
            "pinned",
            network.clone(),
            Role::Any,
        )
        .await
        .unwrap();
        let count =
            || crate::health::cache_request_count(&network, "GetTreeState", "pinned_sweep_dropped");
        let (fetched, fetch) = sweep_fetch(Arc::default());
        let pass = pinned_sweep_pass(&cache, &bound(&cache, &refusing), (1, 2000), 0, &fetch)
            .await
            .unwrap();
        assert_eq!(pass.holes, Some(2), "the holes are still there");
        assert_eq!(count(), 0, "nothing was dropped");
        // The store takes the removal: dropped and counted, without an upstream call.
        let pass = pinned_sweep_pass(&cache, &bound(&cache, &pinned), (1, 2000), 0, &fetch)
            .await
            .unwrap();
        assert_eq!(pass.holes, Some(0));
        assert_eq!(count(), 2);
        assert!(fetched.lock().is_empty(), "{:?}", fetched.lock());
        let _: () = redis::cmd("ACL")
            .arg("DELUSER")
            .arg(&user)
            .query_async(&mut c)
            .await
            .unwrap();
    }

    /// What `cursor_store` saw.
    #[derive(Default)]
    struct CursorStore {
        /// The cursor's value.
        cursor: AtomicU64,
        /// `INCR`s answered.
        incrs: AtomicU64,
        /// Scripts (the cursor step past the lower heights) received.
        evals: AtomicU64,
    }

    /// A Redis-protocol server that keeps a backfill cursor: `INCR`/`DECR` move it, a script
    /// (`EVALSHA`) is refused with an error the first `refused` times and then moves the cursor
    /// up to `jump_to`; `ROLE` answers as a primary, `EXISTS` 0, every other command `+OK`.
    async fn cursor_store(refused: u64, jump_to: u64) -> (String, Arc<CursorStore>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(CursorStore::default());
        let state = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let state = state.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let Ok(n) = stream.read(&mut chunk).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        while let Some((len, name)) = resp_command_name(&buf) {
                            buf.drain(..len);
                            let answer: Vec<u8> = match name.as_slice() {
                                b"ROLE" => ROLE_PRIMARY.to_vec(),
                                b"INCR" => {
                                    state.incrs.fetch_add(1, Ordering::SeqCst);
                                    let n = state.cursor.fetch_add(1, Ordering::SeqCst) + 1;
                                    format!(":{n}\r\n").into_bytes()
                                }
                                b"DECR" => {
                                    let n = state.cursor.fetch_sub(1, Ordering::SeqCst) - 1;
                                    format!(":{n}\r\n").into_bytes()
                                }
                                b"EVALSHA" | b"EVAL" => {
                                    if state.evals.fetch_add(1, Ordering::SeqCst) < refused {
                                        b"-ERR refused\r\n".to_vec()
                                    } else {
                                        state.cursor.fetch_max(jump_to, Ordering::SeqCst);
                                        b":1\r\n".to_vec()
                                    }
                                }
                                b"EXISTS" => b":0\r\n".to_vec(),
                                _ => b"+OK\r\n".to_vec(),
                            };
                            if stream.write_all(&answer).await.is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        });
        (format!("redis://{addr}"), seen)
    }

    /// A worker on `cursor_store(refused, floor - 1)` with the lowest fillable height `floor`,
    /// run until it asked for at least three heights: the heights asked and what the store saw.
    async fn backfill_on_a_cursor_store(
        name: &str,
        refused: u64,
        floor: u64,
    ) -> Option<(Vec<u64>, Arc<CursorStore>)> {
        assert!(floor > 1);
        let conn = required_redis().await?;
        let network = unique_network(name);
        let (url, seen) = cursor_store(refused, floor - 1).await;
        let mut cache = test_cache(conn, None, &network);
        cache.pinned_conn = Some(
            StoreConn::connect(&url, "pinned", network.clone(), Role::Any)
                .await
                .unwrap(),
        );
        cache.pinned_range = Some((1, u64::MAX));
        cache.pinned_fill_from = floor;
        tip_at(&cache, 100_000);
        let fetched = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let tasks = {
            let fetched = fetched.clone();
            spawn_pinned_backfill(cache.clone(), 1, move |h| {
                let fetched = fetched.clone();
                async move {
                    fetched.lock().push(h);
                    anyhow::Ok(tree_state_answer(h))
                }
            })
        };
        for _ in 0..600 {
            if fetched.lock().len() >= 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
        let fetched = fetched.lock().clone();
        Some((fetched, seen))
    }

    /// A cursor step past the lower heights that the store refuses is tried again before the
    /// next claim: the worker walks only the few heights claimed meanwhile, asks the upstream
    /// for none of them, and goes on at the lowest fillable height.
    #[tokio::test]
    async fn a_refused_cursor_step_is_tried_again_before_the_next_claim() {
        let Some((fetched, seen)) = backfill_on_a_cursor_store("pinned-skip-retry", 3, 500).await
        else {
            return;
        };
        assert_eq!(fetched.get(..3), Some(&[500, 501, 502][..]), "{fetched:?}");
        assert!(fetched.iter().all(|h| *h >= 500), "nothing below is asked");
        assert_eq!(
            seen.evals.load(Ordering::SeqCst),
            4,
            "three refused, one taken"
        );
        assert!(seen.cursor.load(Ordering::SeqCst) >= 500);
        // 1, 2 and 3 were claimed while the step was refused; every later claim is a height
        // that is asked for (the last one may have been claimed when the worker was stopped).
        let claims = seen.incrs.load(Ordering::SeqCst);
        let asked = fetched.len() as u64;
        assert!(
            claims == 3 + asked || claims == 4 + asked,
            "{claims} claims for {asked} heights asked"
        );
    }

    /// On a store that never takes the cursor step the worker walks the lower heights one by
    /// one, asks the upstream for none of them, and stops trying the step once a claim is
    /// past them.
    #[tokio::test]
    async fn a_cursor_step_that_never_succeeds_is_given_up_past_the_lower_heights() {
        let Some((fetched, seen)) =
            backfill_on_a_cursor_store("pinned-skip-never", u64::MAX, 30).await
        else {
            return;
        };
        assert_eq!(fetched.get(..3), Some(&[30, 31, 32][..]), "{fetched:?}");
        assert!(fetched.iter().all(|h| *h >= 30), "nothing below is asked");
        assert!(seen.cursor.load(Ordering::SeqCst) >= 30);
        assert_eq!(
            seen.evals.load(Ordering::SeqCst),
            30,
            "once before each of the claims 1..=30, none after"
        );
    }

    /// A batch whose every height in the range is a hole is done all the same: the mark moves
    /// past it.
    #[tokio::test]
    async fn the_sweep_mark_moves_past_a_batch_of_holes() {
        let network = unique_network("pinned-sweep-all-holes");
        // Height 499 is the only one of its batch in the range; 500 and 501 are present.
        let Some((cache, pinned, _c)) = sweep_fixture(&network, (499, 501), 500..=501u64, 3).await
        else {
            return;
        };
        let (fetched, fetch) = erroring_fetch(&[14]);
        let pass = pinned_sweep_pass(&cache, &bound(&cache, &pinned), (499, 501), 0, &fetch)
            .await
            .unwrap();
        assert_eq!((pass.filled, pass.next, pass.holes), (0, 502, Some(1)));
        assert_eq!(*fetched.lock(), vec![499, 499, 499]);
    }

    /// Below the lowest height the backfill fills (the Sapling activation in production) the
    /// sweep asks nothing: holes there (recorded by an earlier version) are dropped without a
    /// fetch, and the mark starts at that height.
    #[tokio::test]
    async fn the_sweep_starts_at_the_lowest_fillable_height() {
        let network = unique_network("pinned-sweep-floor");
        let Some((mut cache, pinned, mut c)) =
            sweep_fixture(&network, (1, 2000), 600..=700u64, 700).await
        else {
            return;
        };
        cache.pinned_fill_from = 600;
        let _: () = redis::pipe()
            .cmd("SADD")
            .arg(cache.pinned_holes_key())
            .arg(62)
            .arg(113)
            .arg(388)
            .ignore()
            .cmd("HSET")
            .arg(cache.pinned_hole_attempts_key())
            .arg(62)
            .arg(3)
            .ignore()
            .cmd("SET")
            .arg(cache.pinned_verified_key())
            .arg(500)
            .ignore()
            .query_async(&mut c)
            .await
            .unwrap();
        let (fetched, fetch) = sweep_fetch(Arc::default());
        let pass = pinned_sweep_pass(&cache, &bound(&cache, &pinned), (1, 2000), 0, &fetch)
            .await
            .unwrap();
        assert!(fetched.lock().is_empty(), "{:?}", fetched.lock());
        assert_eq!((pass.filled, pass.next, pass.holes), (0, 701, Some(0)));
        assert!(!key_exists(&c, &cache.pinned_hole_attempts_key()).await);
        assert_eq!(
            crate::health::cache_request_count(&network, "GetTreeState", "pinned_sweep_dropped"),
            3
        );
    }

    /// Backfill workers skip the heights below the lowest fillable one in one step of the
    /// cursor, without asking the upstream.
    #[tokio::test]
    async fn backfill_workers_skip_the_heights_below_the_lowest_fillable_one() {
        let Some(conn) = required_redis().await else {
            return;
        };
        let network = unique_network("pinned-backfill-floor");
        let mut cache = test_cache(conn.clone(), None, &network);
        cache.pinned_conn = Some(StoreConn::from_parts(
            redis::Client::open("redis://127.0.0.1:6379").unwrap(),
            conn.clone(),
            "pinned",
            network.clone(),
            Role::Any,
        ));
        cache.pinned_range = Some((1, u64::MAX));
        cache.pinned_fill_from = 300;
        tip_at(&cache, 1000);
        let fetched = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let tasks = {
            let fetched = fetched.clone();
            spawn_pinned_backfill(cache.clone(), 1, move |h| {
                let fetched = fetched.clone();
                async move {
                    fetched.lock().push(h);
                    anyhow::Ok(tree_state_answer(h))
                }
            })
        };
        for _ in 0..400 {
            if fetched.lock().len() >= 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
        let first: Vec<u64> = fetched.lock().iter().take(3).copied().collect();
        assert_eq!(first, vec![300, 301, 302], "the first heights asked");
        let mut c = conn;
        let _: () = redis::cmd("DEL")
            .arg(cache.pinned_cursor_key())
            .query_async(&mut c)
            .await
            .unwrap();
    }

    /// The lowest height filled comes from the network through `with_pinned`: the Sapling
    /// activation of mainnet, the testnet one for testnet and for any other network label. A
    /// range that starts above it keeps its start; one that ends below it fills nothing.
    #[tokio::test]
    async fn the_lowest_fillable_height_is_the_networks_sapling_activation() {
        let Some(conn) = required_redis().await else {
            return;
        };
        let url = "redis://127.0.0.1:6379";
        for (label, floor) in [
            ("mainnet".to_string(), 419_200),
            ("testnet".to_string(), 280_000),
            (unique_network("pinned-floor-other"), 280_000),
        ] {
            let cache = test_cache(conn.clone(), None, &label)
                .with_pinned(url, None, (1, u64::MAX))
                .await
                .unwrap();
            assert_eq!(cache.pinned_fill_from, floor, "{label}");
            assert_eq!(crate::store::sapling_activation(&label), floor, "{label}");
        }

        // A range that starts above the activation: swept from its own start.
        let network = unique_network("pinned-floor-above");
        let range = (300_000, 300_010);
        let cache = test_cache(conn.clone(), None, &network)
            .with_pinned(url, None, range)
            .await
            .unwrap();
        tip_at(&cache, 400_000);
        let mut c = conn.clone();
        let _: () = redis::cmd("SET")
            .arg(cache.pinned_cursor_key())
            .arg(5)
            .query_async(&mut c)
            .await
            .unwrap();
        let writer = cache.pinned_writer_bound().await.unwrap();
        let (fetched, fetch) = sweep_fetch(Arc::default());
        let pass = pinned_sweep_pass(&cache, &writer, range, 0, &fetch)
            .await
            .unwrap();
        assert_eq!((pass.filled, pass.next), (5, 300_005));
        assert_eq!(fetched.lock().first(), Some(&300_000));

        // A range that ends below the activation: nothing is asked, by the sweep or a worker.
        let network = unique_network("pinned-floor-below");
        let range = (1, 1_000);
        let cache = test_cache(conn.clone(), None, &network)
            .with_pinned(url, None, range)
            .await
            .unwrap();
        tip_at(&cache, 400_000);
        let _: () = redis::cmd("SET")
            .arg(cache.pinned_cursor_key())
            .arg(900)
            .query_async(&mut c)
            .await
            .unwrap();
        let writer = cache.pinned_writer_bound().await.unwrap();
        let (fetched, fetch) = sweep_fetch(Arc::default());
        let pass = pinned_sweep_pass(&cache, &writer, range, 0, &fetch)
            .await
            .unwrap();
        assert_eq!((pass.filled, pass.holes), (0, Some(0)));
        assert!(pass.next > range.1, "the range counts as swept");
        let asked = fetched.clone();
        let mut tasks = spawn_pinned_backfill(cache.clone(), 1, move |h| {
            let asked = asked.clone();
            async move {
                asked.lock().push(h);
                anyhow::Ok(tree_state_answer(h))
            }
        });
        // The worker (the last task) finds the range done and ends.
        let worker = tasks.pop().expect("a worker was spawned");
        timeout(Duration::from_secs(30), worker)
            .await
            .expect("the worker ends")
            .unwrap();
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
        assert!(fetched.lock().is_empty(), "{:?}", fetched.lock());
        let _: () = redis::cmd("DEL")
            .arg(cache.pinned_cursor_key())
            .query_async(&mut c)
            .await
            .unwrap();
    }

    /// A REDIS_PINNED_WRITE_URL that is unreachable at startup is connected in the background.
    #[tokio::test]
    async fn an_unreachable_pinned_write_store_is_connected_later() {
        let Some(conn) = required_redis().await else {
            return;
        };
        // A port nothing listens on yet; later a forwarder to the local Redis.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let network = unique_network("pinned-write-later");
        let cache = test_cache(conn, None, &network)
            .with_pinned(
                "redis://127.0.0.1:6379",
                Some(&format!("redis://127.0.0.1:{port}")),
                (1, u64::MAX),
            )
            .await
            .unwrap();
        assert!(cache.pinned_write_conn.load().is_none());
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .unwrap();
        tokio::spawn(async move {
            while let Ok((mut inbound, _)) = listener.accept().await {
                tokio::spawn(async move {
                    if let Ok(mut outbound) = tokio::net::TcpStream::connect("127.0.0.1:6379").await
                    {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                });
            }
        });
        let mut connected = false;
        for _ in 0..100 {
            if cache.pinned_write_conn.load().is_some() {
                connected = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(connected, "the write store was connected in the background");
    }

    /// `Some(true)` when the Redis at `url` is a replica, `Some(false)` for a primary.
    async fn is_replica(url: &str) -> Option<bool> {
        let client = redis::Client::open(url).ok()?;
        let mut c = timeout(Duration::from_secs(5), ConnectionManager::new(client))
            .await
            .ok()?
            .ok()?;
        let v: redis::Value = redis::cmd("ROLE").query_async(&mut c).await.ok()?;
        crate::store_conn::parse_role(&v).map(|primary| !primary)
    }

    /// The local Redis these tests need: `local_redis`, whose policy covers every test of the
    /// store (kept as a name for the tests that use it).
    async fn required_redis() -> Option<ConnectionManager> {
        local_redis().await
    }

    /// The chain follower's fence scripts against a real store (the Lua is the fence): keys of
    /// their own, the lock absent, held by another process and held by the caller.
    #[tokio::test]
    async fn the_fence_scripts_write_only_for_the_exact_lock_holder() {
        let Some(conn) = required_redis().await else {
            return;
        };
        let network = unique_network("fence-scripts");
        let cache = test_cache(conn.clone(), None, &network);
        let mut c = conn;
        let key = |name: &str| format!("{network}:fence:{name}");
        let (lock, index, block, tip) = (key("lock"), key("index"), key("block"), key("tip"));
        let entries = || {
            vec![
                (index.clone(), Bytes::from_static(b"hash"), 600u64),
                (block.clone(), Bytes::from_static(b"\x00block\xff"), 0u64),
            ]
        };
        let me = || "me".to_string();
        macro_rules! get {
            ($k:expr) => {
                redis::cmd("GET")
                    .arg($k)
                    .query_async::<_, Option<Vec<u8>>>(&mut c)
                    .await
                    .unwrap()
            };
        }
        macro_rules! ttl {
            ($cmd:expr, $k:expr) => {
                redis::cmd($cmd)
                    .arg($k)
                    .query_async::<_, i64>(&mut c)
                    .await
                    .unwrap()
            };
        }

        // set_if_lock_held. The lock absent: refused, nothing written, no lock created.
        assert_eq!(cache.lock_holder(lock.clone()).await, Some(None));
        assert_eq!(
            cache
                .set_if_lock_held(lock.clone(), me(), 10_000, entries())
                .await,
            Some(false)
        );
        assert_eq!(get!(&index), None);
        assert_eq!(get!(&block), None);
        assert_eq!(get!(&lock), None);
        // Held by another process: refused, nothing written, the lock and its TTL untouched.
        let _: () = redis::cmd("SET")
            .arg(&lock)
            .arg("other")
            .arg("PX")
            .arg(1_500)
            .query_async(&mut c)
            .await
            .unwrap();
        assert_eq!(
            cache.lock_holder(lock.clone()).await,
            Some(Some("other".to_string()))
        );
        assert_eq!(
            cache
                .set_if_lock_held(lock.clone(), me(), 10_000, entries())
                .await,
            Some(false)
        );
        assert_eq!(get!(&index), None);
        assert_eq!(get!(&block), None);
        assert_eq!(get!(&lock), Some(b"other".to_vec()));
        assert!(ttl!("PTTL", &lock) <= 1_500);
        // Held by the caller: every entry at its key with its value, the index entry with its
        // TTL, the entry with TTL 0 without one, the lock extended.
        let _: () = redis::cmd("SET")
            .arg(&lock)
            .arg("me")
            .arg("PX")
            .arg(1_500)
            .query_async(&mut c)
            .await
            .unwrap();
        assert_eq!(
            cache
                .set_if_lock_held(lock.clone(), me(), 10_000, entries())
                .await,
            Some(true)
        );
        assert_eq!(get!(&index), Some(b"hash".to_vec()));
        assert_eq!(get!(&block), Some(b"\x00block\xff".to_vec()));
        let index_ttl = ttl!("TTL", &index);
        assert!((590..=600).contains(&index_ttl), "{index_ttl}");
        assert_eq!(ttl!("TTL", &block), -1, "no expiry");
        let lock_ttl = ttl!("PTTL", &lock);
        assert!((5_000..=10_000).contains(&lock_ttl), "{lock_ttl}");
        assert_eq!(get!(&lock), Some(b"me".to_vec()));

        // del_if_lock_held. Another holder, then no holder: refused, nothing deleted.
        let keys = || vec![index.clone(), block.clone()];
        let _: () = redis::cmd("SET")
            .arg(&lock)
            .arg("other")
            .query_async(&mut c)
            .await
            .unwrap();
        assert_eq!(
            cache.del_if_lock_held(lock.clone(), me(), keys()).await,
            Some(false)
        );
        let _: () = redis::cmd("DEL")
            .arg(&lock)
            .query_async(&mut c)
            .await
            .unwrap();
        assert_eq!(
            cache.del_if_lock_held(lock.clone(), me(), keys()).await,
            Some(false)
        );
        assert!(get!(&index).is_some() && get!(&block).is_some());
        assert_eq!(get!(&lock), None, "a refused delete creates no lock");
        // The caller holds it: deleted.
        let _: () = redis::cmd("SET")
            .arg(&lock)
            .arg("me")
            .query_async(&mut c)
            .await
            .unwrap();
        assert_eq!(
            cache.del_if_lock_held(lock.clone(), me(), keys()).await,
            Some(true)
        );
        assert_eq!(get!(&index), None);
        assert_eq!(get!(&block), None);
        assert_eq!(get!(&lock), Some(b"me".to_vec()));

        // take_lock_if: the guard (the stored tip) and the observed holder must both match.
        let _: () = redis::cmd("SET")
            .arg(&tip)
            .arg("tip-1")
            .query_async(&mut c)
            .await
            .unwrap();
        let _: () = redis::cmd("SET")
            .arg(&lock)
            .arg("stale-leader")
            .query_async(&mut c)
            .await
            .unwrap();
        let take = |guard: &'static [u8], holder: Option<&str>| {
            cache.take_lock_if(
                lock.clone(),
                me(),
                10_000,
                tip.clone(),
                Bytes::from_static(guard),
                holder.map(str::to_string),
            )
        };
        // The guard changed (the leader moved the tip).
        assert_eq!(take(b"tip-0", Some("stale-leader")).await, Some(false));
        // Another holder than the one observed.
        assert_eq!(take(b"tip-1", Some("someone-else")).await, Some(false));
        // Observed as not held, but it is held.
        assert_eq!(take(b"tip-1", None).await, Some(false));
        assert_eq!(get!(&lock), Some(b"stale-leader".to_vec()));
        assert_eq!(ttl!("PTTL", &lock), -1, "refusals leave the lock as it was");
        // The observed holder: taken, with the TTL.
        assert_eq!(take(b"tip-1", Some("stale-leader")).await, Some(true));
        assert_eq!(cache.lock_holder(lock.clone()).await, Some(Some(me())));
        let lock_ttl = ttl!("PTTL", &lock);
        assert!((5_000..=10_000).contains(&lock_ttl), "{lock_ttl}");
        // Observed as not held while a holder is expected, and while it is absent.
        let _: () = redis::cmd("DEL")
            .arg(&lock)
            .query_async(&mut c)
            .await
            .unwrap();
        assert_eq!(take(b"tip-1", Some("stale-leader")).await, Some(false));
        assert_eq!(cache.lock_holder(lock.clone()).await, Some(None));
        assert_eq!(take(b"tip-1", None).await, Some(true));
        assert_eq!(cache.lock_holder(lock.clone()).await, Some(Some(me())));

        let _: () = redis::cmd("DEL")
            .arg(&lock)
            .arg(&index)
            .arg(&block)
            .arg(&tip)
            .query_async(&mut c)
            .await
            .unwrap();
    }

    /// The chain follower's tip write against a real store: the tip, `tip_at`, `tip_seen` and
    /// the stamp binding `tip_at` to the tip are written by one fenced script (all four there,
    /// the stamp naming the tip and `tip_at` written with it), and refused together while the
    /// lock is held by another process or by none.
    #[tokio::test]
    async fn the_tip_and_its_stamp_are_written_and_refused_together() {
        use crate::store::{
            decode_tip_stamp, decode_unix_ms, encode_tip, lock_key, tip_at_key, tip_key,
            tip_seen_key, tip_stamp_key,
        };
        let Some(conn) = required_redis().await else {
            return;
        };
        let network = unique_network("tip-stamp");
        let cache = Arc::new(test_cache(conn.clone(), None, &network));
        let lwd = Arc::new(crate::block_cache::test_support::FakeChain::new(500));
        let f = crate::chain::ChainFollower::new(
            cache.clone(),
            Arc::new(crate::chain::test_support::FakeChainSource(lwd)),
            None,
            Arc::new(crate::block_cache::PoolKeys::default()),
            network.clone(),
        );
        let prefix = cache.chain_prefix();
        let keys = [
            tip_key(&prefix),
            tip_at_key(&prefix),
            tip_seen_key(&prefix),
            tip_stamp_key(&prefix),
        ];
        let lock = lock_key(&prefix);
        let mut c = conn;
        macro_rules! values {
            () => {{
                let mut v = Vec::new();
                for k in &keys {
                    v.push(
                        redis::cmd("GET")
                            .arg(k)
                            .query_async::<_, Option<Vec<u8>>>(&mut c)
                            .await
                            .unwrap(),
                    );
                }
                v
            }};
        }
        assert_eq!(f.tick().await, crate::chain::Outcome::Cold { tip: 500 });
        let written = values!();
        assert!(written.iter().all(Option::is_some), "{written:?}");
        let stamp = decode_tip_stamp(written[3].as_ref().unwrap()).unwrap();
        assert_eq!(&stamp.tip, written[0].as_ref().unwrap());
        assert_eq!(
            Some(stamp.tip_at_ms),
            decode_unix_ms(written[1].as_ref().unwrap())
        );
        let next = crate::store::Tip {
            height: 501,
            hash: vec![5; 32],
        };
        assert_ne!(encode_tip(&next).to_vec(), stamp.tip);
        // Held by another process, then by none: refused, none of the four changed.
        let _: () = redis::cmd("SET")
            .arg(&lock)
            .arg("another-process")
            .arg("PX")
            .arg(60_000)
            .query_async(&mut c)
            .await
            .unwrap();
        assert!(!crate::chain::test_support::write_tip(&f, &next)
            .await
            .unwrap());
        assert_eq!(values!(), written);
        let _: () = redis::cmd("DEL")
            .arg(&lock)
            .query_async(&mut c)
            .await
            .unwrap();
        assert!(!crate::chain::test_support::write_tip(&f, &next)
            .await
            .unwrap());
        assert_eq!(values!(), written);
        let mut del = redis::cmd("DEL");
        for k in &keys {
            del.arg(k);
        }
        let _: () = del.arg(&lock).query_async(&mut c).await.unwrap();
    }

    /// With the primary and replica of tests/failover (OHTTP_FAILOVER_REDIS=1): a pinned store
    /// that is a replica is detected at startup and never written to; with the primary as
    /// write store the entry is written there and read back through the replica.
    #[tokio::test]
    async fn pinned_entries_of_a_read_replica_go_to_the_write_store() {
        if std::env::var("OHTTP_FAILOVER_REDIS").is_err() {
            return;
        }
        let Some(local) = local_redis().await else {
            return;
        };
        let a = "redis://127.0.0.1:6391";
        let b = "redis://127.0.0.1:6392";
        // tests/store_failover.rs swaps the two, so ask them.
        let (primary, replica) = match (is_replica(a).await, is_replica(b).await) {
            (Some(false), Some(true)) => (a, b),
            (Some(true), Some(false)) => (b, a),
            other => panic!("expected one primary and one replica, got {other:?}"),
        };
        let network = unique_network("pinned-replica");
        let range = (1, u64::MAX);
        let answer = tree_state_answer(500);

        let cache = test_cache(local.clone(), None, &network)
            .with_pinned(replica, None, range)
            .await
            .unwrap();
        assert_ne!(cache.pinned_read_only_until.load(Ordering::Relaxed), 0);
        tip_at(&cache, 1000);
        assert!(!cache.pinned_put(500, &answer).await);

        let cache = test_cache(local, None, &network)
            .with_pinned(replica, Some(primary), range)
            .await
            .unwrap();
        assert_eq!(cache.pinned_read_only_until.load(Ordering::Relaxed), 0);
        tip_at(&cache, 1000);
        assert!(cache.pinned_put(500, &answer).await);
        let mut replicated = None;
        for _ in 0..50 {
            replicated = cache.pinned_get(500).await;
            if replicated.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(replicated, Some(answer));

        let mut p = cache.pinned_write_conn.load_full().unwrap().get();
        let _: () = redis::cmd("DEL")
            .arg(cache.pinned_key(500))
            .query_async(&mut p)
            .await
            .unwrap();
    }
}

#[path = "cache_retry_test.rs"]
#[cfg(test)]
mod cache_retry_test;

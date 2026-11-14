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
use crate::store_conn::{is_failover_signal, Role, StoreConn};
use crate::write_fallback::{LocalWriteBack, WriteBackResult, WriteBackSink, WriteFallback};

pub use crate::rpc_cache::{grpc_block_id, height_key, CacheLookup, CacheMiss, MAX_CACHEABLE_SIZE};

/// Finalized depth: pinned tree states are written only this far below the tip.
pub const FINALIZED_DEPTH: u64 = 100;
/// How often a caught-up pinned backfill worker checks for newly final heights.
pub const PINNED_FOLLOW_INTERVAL: Duration = Duration::from_secs(60);
/// After the store pinned entries are written to answers as a read replica, writes are skipped
/// for this long; then its `ROLE` is asked again before the next write.
pub const PINNED_READ_ONLY_RECHECK: Duration = Duration::from_secs(300);
/// Lower bound of the operation timeout on the separate pinned write store
/// (REDIS_PINNED_WRITE_URL), which can be far away; the write is off the request path.
const PINNED_REMOTE_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
/// Cache key version: bump to orphan old entries on a format change.
const KEY_VERSION: u32 = 4;
/// Epoch refresh interval for per-request sync (seconds).
const EPOCH_REFRESH_SECS: u64 = 2;
/// How often the housekeeping task syncs the epoch and pings Redis.
const HOUSEKEEPING_SECS: u64 = 10;
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
    pinned_write_conn: Option<Arc<StoreConn>>,
    /// Pinned writes are skipped until this time (ms since the UNIX epoch, 0 = not skipped):
    /// the store they go to is a read replica (see `pinned_writer`).
    pinned_read_only_until: Arc<AtomicU64>,
    /// Inclusive height range served from the pinned tier.
    pinned_range: Option<(u64, u64)>,
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
}

/// What the peers said about a WRITE nonce in `replicate_nonce_checked`, for the replica wait
/// that follows (`confirm_write_nonce`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerCheck {
    /// A peer already held the nonce: a cross-origin replay.
    pub replay: bool,
    /// Every peer (at least one) stored the nonce as new and acknowledged it on its own
    /// replicas (`REPLAY_PEER_WAIT_REPLICAS` >= 1), synchronously, before the local wait.
    pub durable_at_peers: bool,
    /// `failover` mode, a WRITE with `REPLAY_WRITE_WAIT_REPLICAS`: the asynchronous replication
    /// to the peers is left to `confirm_write_nonce`, after the local verdict, so that a
    /// synchronous check at the peers there never meets this request's own nonce.
    pub deferred: bool,
    /// The WRITE was also confirmed at the standby stores synchronously (the hub fallback or
    /// window): no asynchronous hand-off to them is needed.
    pub at_standby: bool,
    /// The hub took the nonce but its replicas did not acknowledge it: the WRITE runs only if
    /// the local replicas do (`confirm_write_nonce`).
    pub hub_needs_local_ack: bool,
    /// With `hub_needs_local_ack`: the hub gave no verdict at all (unreachable), rather than a
    /// short acknowledgement. Only the metric label differs.
    pub hub_unavailable: bool,
    /// The local store gave no verdict and the request was decided at the peer stores instead
    /// (`admit_without_local`): the local replica wait does not apply.
    pub local_bypassed: bool,
}

/// The local verdict of `check_replay_detailed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalReplayCheck {
    /// The local store took the nonce as new.
    New,
    /// The local store already held the nonce.
    Replay,
    /// The local store gave no verdict (unreachable, a timeout or an error) and the unavailable
    /// fallback can decide instead, once the request is classified (`admit_without_local`).
    Unavailable,
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

/// The dedicated security-Redis connection for `WAIT`. `WAIT` blocks the connection it runs on
/// until the replicas acknowledge, so it must not share the multiplexed connection every
/// request's `SET NX` goes through: a slow replica would stall READs too.
struct WriteWait {
    conn: Arc<StoreConn>,
    config: WriteWaitConfig,
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
    /// The dedicated connection for `WAIT` (see `WriteWait`), opened in the background by
    /// `with_wait`, else on first use.
    wait_conn: Arc<ArcSwapOption<ConnectionManager>>,
    /// The write-back's own connection (`rewrite_replicated`): its `WAIT`s must not delay the
    /// requests' on `wait_conn`. Opened on first use.
    write_back_conn: Arc<ArcSwapOption<ConnectionManager>>,
    /// Consecutive failed housekeeping PINGs (see PEER_PING_FAILURES_RECONNECT).
    ping_failures: AtomicU32,
    /// Whether the last housekeeping PING was answered (false until the first one).
    answered: AtomicBool,
    /// A standby store (REPLAY_STANDBY_URLS): its connectivity is `ohttp_replay_standby_connected`,
    /// never `ohttp_replay_peer_connected` (which watchdogs read as "the peers are reachable").
    standby: bool,
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
                        warn!(network = %network, peer = index, error = %e, "Replay peer unreachable at startup, retrying in background");
                        record_peer_connected(&network, index, false, false);
                    }
                }
            }
            peers.push(ReplayPeer {
                index,
                url: url.clone(),
                conn,
                wait_conn: Arc::new(ArcSwapOption::empty()),
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
                spawn_peer_reconnect_task(
                    this.network.clone(),
                    p.index,
                    p.url.clone(),
                    p.conn.clone(),
                    p.standby,
                );
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

    /// REPLAY_PEER_WAIT_REPLICAS / REPLAY_PEER_WAIT_MS (None = no acknowledgement). The
    /// dedicated `WAIT` connections are opened now, in the background, so that the first WRITE
    /// does not pay the connection setup (TCP, TLS, AUTH: several round trips).
    pub fn with_wait(mut self, wait: Option<WriteWaitConfig>) -> Self {
        self.wait = wait;
        if wait.is_some() && tokio::runtime::Handle::try_current().is_ok() {
            for p in &self.peers {
                let (network, index, url, slot) = (
                    self.network.clone(),
                    p.index,
                    p.url.clone(),
                    p.wait_conn.clone(),
                );
                tokio::spawn(async move {
                    let mut backoff_secs = 1u64;
                    while slot.load().is_none() {
                        match ReplayPeer::open(&url).await {
                            Ok(c) => {
                                slot.store(Some(Arc::new(c)));
                            }
                            Err(e) => {
                                debug!(network = %network, peer = index, error = %e, "Replay peer WAIT connection attempt failed");
                                tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                                backoff_secs = (backoff_secs * 2).min(60);
                            }
                        }
                    }
                });
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
        let budget = self.timeout + Duration::from_millis(timeout_ms);
        let futures = self.peers.iter().filter(|p| confirm(p.index)).map(|p| async move {
            let verdict = async {
                let mut last = String::new();
                let mut short = false;
                for attempt in 0..PEER_WAIT_ATTEMPTS {
                    if attempt > 0 {
                        warn!(network = %self.network, peer = p.index, error = %last, "Replay peer WAIT failed, retrying once");
                        crate::health::record_replay_peer(&self.network, p.index, "wait_retry");
                    }
                    // Opening the connection is not part of the budget.
                    let conn = match p.wait_conn.load_full() {
                        Some(c) => c,
                        None => match timeout(PEER_WAIT_CONNECT_TIMEOUT, ReplayPeer::open(&p.url)).await {
                            Ok(Ok(c)) => {
                                let c = Arc::new(c);
                                p.wait_conn.store(Some(c.clone()));
                                c
                            }
                            Ok(Err(e)) => {
                                last = format!("connect: {e}");
                                short = false;
                                continue;
                            }
                            Err(_) => {
                                last = format!(
                                    "connect timed out after {}ms",
                                    PEER_WAIT_CONNECT_TIMEOUT.as_millis()
                                );
                                short = false;
                                continue;
                            }
                        },
                    };
                    let mut conn = (*conn).clone();
                    let result = timeout(budget, async {
                        redis::pipe()
                            .cmd("SET")
                            .arg(key)
                            .arg("1")
                            .arg("XX")
                            .arg("EX")
                            .arg(REPLAY_TTL_SECS)
                            .cmd("WAIT")
                            .arg(replicas)
                            .arg(timeout_ms)
                            .query_async::<_, (Option<String>, i64)>(&mut conn)
                            .await
                    })
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
                        // A broken or stuck connection: the retry opens a fresh one (on the
                        // primary). A failover signal also replaces the peer's main connection.
                        Ok(Err(e)) => {
                            p.wait_conn.store(None);
                            if let Some(main) = p.conn.load_full() {
                                p.on_error(&self.network, &main, &e);
                            }
                            e.to_string()
                        }
                        Err(_) => {
                            p.wait_conn.store(None);
                            format!("timed out after {}ms", budget.as_millis())
                        }
                    };
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
                    Ok(Err(e)) => return WriteBackResult::Failed(format!("connect: {e}")),
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
                    WriteBackResult::Failed(format!("peer {}: {e}", p.index))
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
    /// Whether at least one peer has a connection right now.
    pub fn any_connected(&self) -> bool {
        self.peers.iter().any(|p| p.conn.load().is_some())
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
        let futures = self.peers.iter().map(|p| async move {
            let outcome = match p.conn.load_full() {
                None => PeerOutcome::Disconnected,
                Some(used) => {
                    let mut conn = (*used).clone();
                    match timeout(self.timeout, async {
                        redis::cmd("SET")
                            .arg(key)
                            .arg("1")
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
                            warn!(network = %self.network, peer = p.index, error = %e, "Replay peer write failed");
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
    /// background (a hung connection never errors, so ConnectionManager would keep it).
    pub async fn ping_all(&self) {
        for p in &self.peers {
            let ok = match p.conn.load_full() {
                // A reconnect task is running.
                None => false,
                Some(conn) => {
                    let mut conn = (*conn).clone();
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
                    } else if p.ping_failures.fetch_add(1, Ordering::Relaxed) + 1
                        >= PEER_PING_FAILURES_RECONNECT
                    {
                        p.ping_failures.store(0, Ordering::Relaxed);
                        warn!(network = %self.network, peer = p.index, "Replay peer failed {PEER_PING_FAILURES_RECONNECT} PINGs in a row: reopening the connection");
                        p.conn.store(None);
                        p.wait_conn.store(None);
                        spawn_peer_reconnect_task(
                            self.network.clone(),
                            p.index,
                            p.url.clone(),
                            p.conn.clone(),
                            p.standby,
                        );
                    }
                    ok
                }
            };
            if !ok {
                self.disruptions.fetch_add(1, Ordering::Relaxed);
            }
            p.answered.store(ok, Ordering::Relaxed);
            record_peer_connected(&self.network, p.index, p.standby, ok);
        }
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

    /// A command on `used` reported that the connection no longer reaches the peer's primary
    /// (READONLY on a demoted primary, a broken connection): drop it and reconnect in the
    /// background, unless that already happened. Meanwhile the peer counts as disconnected,
    /// which every policy treats like an error.
    fn on_error(&self, network: &str, used: &Arc<ConnectionManager>, e: &redis::RedisError) {
        if !is_failover_signal(e, Role::Primary) {
            return;
        }
        drop_peer_conn(
            network,
            self.index,
            &self.url,
            &self.conn,
            used,
            e,
            self.standby,
        );
    }
}

/// Replace `used` in `slot` by None and start the reconnect task, once per connection.
fn drop_peer_conn(
    network: &str,
    index: usize,
    url: &str,
    slot: &Arc<ArcSwapOption<ConnectionManager>>,
    used: &Arc<ConnectionManager>,
    e: &redis::RedisError,
    standby: bool,
) {
    let current = Some(used.clone());
    let prev = slot.compare_and_swap(&current, None::<Arc<ConnectionManager>>);
    let swapped = (*prev).as_ref().is_some_and(|p| Arc::ptr_eq(p, used));
    if swapped {
        warn!(network = %network, peer = index, error = %e, "Replay peer connection lost the primary: reconnecting");
        crate::health::record_store_reconnect(
            network,
            "replay_peer",
            crate::store_conn::signal_reason(e),
        );
        spawn_peer_reconnect_task(
            network.to_string(),
            index,
            url.to_string(),
            slot.clone(),
            standby,
        );
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
        let slot = p.map(|p| (p.conn.clone(), p.url.clone(), p.index, p.standby));
        let network = self.network.clone();
        Box::pin(async move {
            let (Some(used), Some((slot, url, label, standby))) = (conn, slot) else {
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
                    if is_failover_signal(&e, Role::Primary) {
                        drop_peer_conn(&network, label, &url, &slot, &used, &e, standby);
                    }
                    e.to_string()
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
                Err(e) => Err(e.to_string()),
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
fn spawn_peer_reconnect_task(
    network: String,
    index: usize,
    url: String,
    conn: Arc<ArcSwapOption<ConnectionManager>>,
    standby: bool,
) {
    tokio::spawn(async move {
        let mut backoff = Duration::from_millis(200);
        loop {
            tokio::time::sleep(backoff).await;
            match ReplayPeer::open(&url).await {
                Ok(c) => {
                    conn.store(Some(Arc::new(c)));
                    record_peer_connected(&network, index, standby, true);
                    info!(network = %network, peer = index, standby, "Replay peer connected");
                    return;
                }
                Err(e) => {
                    warn!(network = %network, peer = index, error = %e, "Replay peer reconnection attempt failed");
                    backoff =
                        (backoff * 2).min(Duration::from_secs(PEER_RECONNECT_MAX_BACKOFF_SECS));
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
            pinned_write_conn: None,
            pinned_read_only_until: Arc::new(AtomicU64::new(0)),
            pinned_range: None,
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
                    debug!(network = %self.network, error = %e, "Redis cache reconnection attempt failed");
                    false
                }
            },
            Err(e) => {
                warn!(network = %self.network, error = %e, "Invalid Redis cache URL during reconnect");
                false
            }
        }
    }

    /// Attach the pinned tier (REDIS_PINNED_URL + PINNED_TREESTATE_RANGE), and optionally a
    /// separate store its entries are written to (REDIS_PINNED_WRITE_URL), for a pinned store
    /// that is a read replica. An unreachable write store is not fatal: the entries are then
    /// written to the pinned store, or not at all when it is a read replica.
    pub async fn with_pinned(
        mut self,
        url: &str,
        write_url: Option<&str>,
        range: (u64, u64),
    ) -> anyhow::Result<Self> {
        self.pinned_conn =
            Some(StoreConn::connect(url, "pinned", self.network.clone(), Role::Any).await?);
        self.pinned_range = Some(range);
        if let Some(write_url) = write_url {
            match StoreConn::connect(write_url, "pinned_write", self.network.clone(), Role::Any)
                .await
            {
                Ok(c) => self.pinned_write_conn = Some(c),
                Err(e) => {
                    warn!(network = %self.network, error = %e, "pinned write store unreachable at startup, writing pinned entries to the pinned store")
                }
            }
        }
        if let Some(writer) = self
            .pinned_write_conn
            .as_ref()
            .or(self.pinned_conn.as_ref())
        {
            if !self.probe_pinned_writer(writer).await {
                info!(network = %self.network, "pinned store is a read replica, pinned entries are not written");
            }
        }
        Ok(self)
    }

    pub fn pinned_range(&self) -> Option<(u64, u64)> {
        self.pinned_range
    }

    /// Enable replica acknowledgement of WRITE nonces on a dedicated connection to `security_url`.
    pub async fn with_write_wait(
        mut self,
        security_url: &str,
        config: WriteWaitConfig,
    ) -> anyhow::Result<Self> {
        if security_url.is_empty() {
            anyhow::bail!("REPLAY_WRITE_WAIT_REPLICAS needs REDIS_SECURITY_URL");
        }
        let conn = StoreConn::connect(
            security_url,
            "write_wait",
            self.network.clone(),
            Role::Primary,
        )
        .await?;
        // The peer fallback needs peers that acknowledge on their replicas (the replay peers
        // are attached before this, see main.rs); without them nothing changes.
        if self
            .replay_peers
            .as_ref()
            .is_some_and(|p| p.wait().is_some())
        {
            let fb = Arc::new(WriteFallback::new(
                &self.network,
                self.store_generation_of(&conn),
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
            crate::write_fallback::spawn_window_watch(fb.clone(), conn.clone());
            if let Some(sec) = &self.security_conn {
                crate::write_fallback::spawn_window_watch(fb.clone(), sec.clone());
            }
            self.write_fallback = Some(fb);
        }
        self.write_wait = Some(Arc::new(WriteWait { conn, config }));
        Ok(self)
    }

    /// Sum of the security and `WAIT` connection generations: it changes whenever one of them
    /// was replaced (a failover of the local store, or a hung connection).
    fn store_generation_of(&self, wait_conn: &StoreConn) -> u64 {
        wait_conn.generation() + self.security_conn.as_ref().map_or(0, |c| c.generation())
    }

    pub fn write_wait(&self) -> Option<WriteWaitConfig> {
        self.write_wait.as_ref().map(|w| w.config)
    }

    /// For a WRITE: rewrite its nonce (`SET XX`, keeps it a write on this connection) and `WAIT`
    /// until `replicas` replicas have it. Fail-closed: fewer acknowledgements, an error or a
    /// timeout is an `Err` (outer 503), like an unavailable replay store. No-op when disabled.
    pub async fn confirm_nonce_replicated(&self, body_hash: &[u8]) -> anyhow::Result<()> {
        let Some(ww) = self.write_wait.as_ref() else {
            return Ok(());
        };
        let key = format!("replay:{}:{}", self.network, hex::encode(body_hash));
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
        // A connection that no longer reaches the primary (a failover: the old primary answers
        // READONLY / refuses WAIT, or the socket broke) fails the first command. The connection
        // is then replaced (a new name resolution, accepted only on a primary), and one retry
        // runs on the new one within the same budget. SET XX and WAIT are idempotent, and SET XX
        // only succeeds where the nonce is: on a promoted replica that never received it, the
        // WRITE is refused instead of confirmed.
        let mut retried = false;
        loop {
            let generation = ww.conn.generation();
            let mut conn = ww.conn.get();
            let round_trip = async {
                let set = redis::cmd("SET")
                    .arg(&key)
                    .arg("1")
                    .arg("XX")
                    .arg("EX")
                    .arg(REPLAY_TTL_SECS)
                    .query_async::<_, Option<String>>(&mut conn)
                    .await?;
                if set.is_none() {
                    return Ok(None);
                }
                redis::cmd("WAIT")
                    .arg(replicas)
                    .arg(timeout_ms)
                    .query_async::<_, i64>(&mut conn)
                    .await
                    .map(Some)
            };
            let r = tokio::time::timeout_at(deadline, round_trip).await;
            ww.conn.observe_timed(&r);
            let e = match r {
                Ok(Ok(Some(acked))) if acked >= replicas as i64 => return LocalWait::Acked,
                Ok(Ok(Some(acked))) => {
                    ww.conn.observe_short_ack();
                    return LocalWait::Short(anyhow::anyhow!(
                        "Replay nonce acknowledged by {acked} of {replicas} replica(s) within {timeout_ms}ms (fail-closed)"
                    ));
                }
                Ok(Ok(None)) => {
                    return LocalWait::Failed(anyhow::anyhow!(
                        "Replay nonce no longer in the security store (fail-closed)"
                    ))
                }
                Ok(Err(e)) if !retried && is_failover_signal(&e, Role::Primary) => e,
                Ok(Err(e)) if is_failover_signal(&e, Role::Primary) => {
                    return LocalWait::Unavailable(anyhow::anyhow!(
                        "Replay nonce WAIT failed (fail-closed): {e}"
                    ))
                }
                Ok(Err(e)) => {
                    return LocalWait::Failed(anyhow::anyhow!(
                        "Replay nonce WAIT failed (fail-closed): {e}"
                    ))
                }
                Err(_) => return LocalWait::Unavailable(timed_out()),
            };
            retried = true;
            warn!(network = %self.network, error = %e, "Replay nonce WAIT connection lost the primary, retrying once on a new connection");
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            // An I/O error is also repaired by ConnectionManager itself; a READONLY connection
            // only by the replacement.
            if !ww.conn.wait_for_reconnect(generation, left).await && !e.is_io_error() {
                return LocalWait::Unavailable(anyhow::anyhow!(
                    "Replay nonce WAIT failed (fail-closed): {e}"
                ));
            }
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
        body_hash: &[u8],
        check: PeerCheck,
    ) -> anyhow::Result<WriteAdmission> {
        let key = format!("replay:{}:{}", self.network, hex::encode(body_hash));
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
            fb.note_generation(self.store_generation_of(&ww.conn));
        }
        if check.hub_needs_local_ack {
            let path = if check.hub_unavailable {
                "hub_unavailable"
            } else {
                "hub_short_ack"
            };
            let record = |result: &str| {
                crate::health::record_replay_write_fallback(&self.network, path, result)
            };
            return match local {
                LocalWait::Acked => match self.hub_fallback.as_ref() {
                    Some(fb) if fb.push_write_back(key.clone()) => {
                        record("accepted");
                        warn!(network = %self.network, path, "WRITE replay nonce confirmed by the local replicas (no acknowledged verdict from the hub); written back to the hub later");
                        Ok(self.after_local_ack(&key, check).await)
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
            LocalWait::Acked => Ok(self.after_local_ack(&key, check).await),
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
    /// the fallback store"); without one asynchronously.
    async fn after_local_ack(&self, key: &str, check: PeerCheck) -> WriteAdmission {
        if !check.deferred {
            return WriteAdmission::Run;
        }
        let peers = self.replay_peers.as_ref();
        let (Some(peers), Some(fb)) = (peers, self.write_fallback.as_ref()) else {
            if let Some(r) = &self.replicator {
                r.enqueue(key);
            }
            return WriteAdmission::Run;
        };
        // The label tells a check inside the window (after startup or a local store failover)
        // from the steady state; both are decided the same way.
        let path = if fb.window_open() { "window" } else { "check" };
        let outcomes = peers.write_nonce(key, REPLAY_TTL_SECS).await;
        let verdict = combine_peer_outcomes(&outcomes);
        let result = match verdict {
            PeerVerdict::Fresh => "accepted",
            PeerVerdict::Replay => "replay",
            PeerVerdict::Unavailable => "unavailable",
        };
        crate::health::record_replay_write_fallback(&self.network, path, result);
        match verdict {
            PeerVerdict::Replay => WriteAdmission::Replay,
            PeerVerdict::Fresh => WriteAdmission::Run,
            PeerVerdict::Unavailable => {
                // The local verdict stands, as outside the window; the peers that did not take
                // the nonce get it asynchronously.
                if let Some(r) = &self.replicator {
                    r.enqueue_to(key, |i| outcomes.get(i) != Some(&PeerOutcome::Fresh));
                }
                WriteAdmission::Run
            }
        }
    }

    /// The local replica acknowledgement was short (the nonce is on the local primary only), or
    /// with REPLAY_UNAVAILABLE_FALLBACK the local store did not answer the wait (`path`
    /// `local_unavailable`): confirm the WRITE at the peer stores instead, or fail closed with
    /// `e`.
    async fn short_ack_fallback(
        &self,
        key: String,
        check: PeerCheck,
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
        let record =
            |result: &str| crate::health::record_replay_write_fallback(&self.network, path, result);
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
            let outcomes = peers.write_nonce(&key, REPLAY_TTL_SECS).await;
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
        warn!(
            network = %self.network,
            path,
            reason = %e,
            "WRITE replay nonce confirmed at the peer stores (no acknowledged local verdict); written back locally later"
        );
        Ok(WriteAdmission::Run)
    }

    /// REPLAY_UNAVAILABLE_FALLBACK (write_fallback.rs, "Unavailable store"). Off by default:
    /// every gateway that checks at the same stores must run a version that checks every WRITE
    /// at the fallback store before any of them turns this on.
    pub fn with_unavailable_fallback(mut self, on: bool) -> Self {
        self.unavailable_fallback = on;
        self
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
    pub fn serves_without_local_store(&self) -> bool {
        self.decides_at_peers_without_local()
            && self.checks_writes_at_fallback_store()
            && self
                .replay_peers
                .as_ref()
                .is_some_and(|p| p.all_answering())
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
    /// `Err` = fail-closed (inner 503 / grpc-status 14).
    pub async fn admit_without_local(
        &self,
        body_hash: &[u8],
        class: RouteClass,
    ) -> anyhow::Result<WriteAdmission> {
        let key = format!("replay:{}:{}", self.network, hex::encode(body_hash));
        let (Some(peers), Some(fb), true) = (
            self.replay_peers.as_ref().filter(|p| p.wait().is_some()),
            self.write_fallback.as_ref(),
            self.decides_at_peers_without_local(),
        ) else {
            anyhow::bail!("Replay protection unavailable: no verdict from the local store and no peer store to decide at (fail-closed)");
        };
        fb.open_window();
        if class == RouteClass::Read {
            let outcomes = peers.write_nonce(&key, REPLAY_TTL_SECS).await;
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
        let record = |result: &str| {
            crate::health::record_replay_write_fallback(&self.network, "local_unavailable", result)
        };
        if !fb.has_room() {
            record("overflow");
            anyhow::bail!("Replay protection unavailable: no verdict from the local store, write-back queue full (fail-closed)");
        }
        let outcomes = peers.write_nonce(&key, REPLAY_TTL_SECS).await;
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
        warn!(network = %self.network, "WRITE replay nonce confirmed at the peer stores (no verdict from the local store); written back locally later");
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
            Ok((_, Err(e))) => anyhow::bail!("REPLAY_LOCAL_WAITAOF_MS: WAITAOF probe failed: {e}"),
            Err(e) => anyhow::bail!("REPLAY_LOCAL_WAITAOF_MS: WAITAOF probe failed: {e}"),
        };
        match probe {
            Ok(conn) => {
                self.local_aof = Some(Arc::new(LocalAof { conn, timeout_ms }));
                Ok(self)
            }
            Err(e) if required => anyhow::bail!(
                "REPLAY_LOCAL_WAITAOF_MS={timeout_ms} but the security Redis cannot WAITAOF (needs Redis >= 7.2 with appendonly yes): {e}"
            ),
            Err(e) => {
                warn!(
                    network = %self.network,
                    error = %e,
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
            Ok(Err(e)) => Err(e.to_string()),
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
    pub fn replicate_write_to_standby(&self, body_hash: &[u8]) {
        if let Some(r) = &self.standby_replicator {
            r.enqueue(&format!(
                "replay:{}:{}",
                self.network,
                hex::encode(body_hash)
            ));
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

    /// Skip pinned writes for PINNED_READ_ONLY_RECHECK. Returns true when they were not skipped
    /// before (the caller logs the change once).
    fn mark_pinned_read_only(&self) -> bool {
        let until = Self::unix_ms() + PINNED_READ_ONLY_RECHECK.as_millis() as u64;
        self.pinned_read_only_until.swap(until, Ordering::Relaxed) == 0
    }

    /// Ask `conn` for its `ROLE`. A replica turns pinned writes off for
    /// PINNED_READ_ONLY_RECHECK and returns false; a primary, a store without `ROLE` or no
    /// answer in time return true.
    async fn probe_pinned_writer(&self, conn: &Arc<StoreConn>) -> bool {
        let answer = timeout(
            self.pinned_write_timeout(),
            redis::cmd("ROLE").query_async::<_, redis::Value>(&mut conn.get()),
        )
        .await;
        match answer {
            Ok(Ok(v)) if crate::store_conn::parse_role(&v) == Some(false) => {
                self.mark_pinned_read_only();
                false
            }
            _ => true,
        }
    }

    /// The store pinned entries are written to: REDIS_PINNED_WRITE_URL's when set, else the
    /// pinned store. None while that store is known to be a read replica: its writes would only
    /// fail. After PINNED_READ_ONLY_RECHECK the store is asked again (`ROLE`), so a replica
    /// that was promoted is written to again.
    async fn pinned_writer(&self) -> Option<&Arc<StoreConn>> {
        let conn = self
            .pinned_write_conn
            .as_ref()
            .or(self.pinned_conn.as_ref())?;
        let until = self.pinned_read_only_until.load(Ordering::Relaxed);
        if until == 0 {
            return Some(conn);
        }
        if Self::unix_ms() < until || !self.probe_pinned_writer(conn).await {
            return None;
        }
        if self.pinned_read_only_until.swap(0, Ordering::Relaxed) != 0 {
            info!(network = %self.network, "pinned store accepts writes again");
        }
        Some(conn)
    }

    /// Operation timeout of pinned writes: at least PINNED_REMOTE_WRITE_TIMEOUT on a separate
    /// write store.
    fn pinned_write_timeout(&self) -> Duration {
        if self.pinned_write_conn.is_some() {
            self.redis_timeout.max(PINNED_REMOTE_WRITE_TIMEOUT)
        } else {
            self.redis_timeout
        }
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
                warn!(network = %self.network, height, error = %e, "pinned get error");
                crate::health::record_cache_redis_timeout(&self.network, "pinned_get_error");
                None
            }
            Err(_) => {
                crate::health::record_cache_redis_timeout(&self.network, "pinned_get_timeout");
                None
            }
        }
    }

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

    /// Store a pinned entry. Only finalized heights (depth > FINALIZED_DEPTH against a fresh
    /// tip) and only responses that decode to a TreeState for the same height. SET NX, no TTL.
    /// Written to `pinned_writer`; nothing while that is a read replica.
    async fn pinned_put(&self, height: u64, response: &[u8]) -> bool {
        if self.pinned_conn.is_none() {
            return false;
        }
        let tip = self.tip_height();
        if tip == 0 || tip.saturating_sub(height) <= FINALIZED_DEPTH {
            return false;
        }
        if !Self::is_tree_state_for(response, height) {
            return false;
        }
        let Some(pinned) = self.pinned_writer().await else {
            return false;
        };
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
        match res {
            Ok(Ok(_)) => true,
            Ok(Err(e)) if e.kind() == redis::ErrorKind::ReadOnly => {
                if self.mark_pinned_read_only() {
                    info!(network = %self.network, "pinned store is a read replica, pinned entries are not written");
                }
                false
            }
            Ok(Err(e)) => {
                warn!(network = %self.network, height, error = %e, "pinned set error");
                crate::health::record_cache_redis_timeout(&self.network, "pinned_set_error");
                false
            }
            Err(_) => {
                crate::health::record_cache_redis_timeout(&self.network, "pinned_set_timeout");
                false
            }
        }
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
        let cache_ok = if let Some(cache_conn) = self.cache_conn.load_full() {
            let mut cache_conn = (*cache_conn).clone();
            match timeout(
                self.redis_timeout,
                redis::cmd("PING").query_async::<_, String>(&mut cache_conn),
            )
            .await
            {
                Ok(Ok(resp)) if resp == "PONG" => true,
                Ok(Ok(_)) => {
                    warn!("Redis PING returned unexpected response");
                    false
                }
                Ok(Err(e)) => {
                    warn!("Redis PING failed: {}", e);
                    false
                }
                Err(_) => {
                    warn!("Redis PING timeout");
                    false
                }
            }
        } else {
            false
        };
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

        // Keep the WRITE-wait connection warm: a PING after a failover takes the broken
        // connection's error here instead of in the next user's WRITE.
        // The same for the WAITAOF connection. A PING also succeeds on a demoted primary, so
        // these connections (and the security one) also check that their node is still the
        // primary (`ROLE`): an idle gateway sees no READONLY to react to.
        let dedicated = [
            self.write_wait.as_ref().map(|w| &w.conn),
            self.local_aof.as_ref().map(|l| &l.conn),
        ];
        for conn in dedicated.into_iter().flatten() {
            let r = timeout(
                self.redis_timeout,
                redis::cmd("PING").query_async::<_, String>(&mut conn.get()),
            )
            .await;
            conn.observe_timed(&r);
            if let Ok(Err(e)) = &r {
                warn!(network = %self.network, error = %e, "Replay nonce WAIT connection PING failed (reconnecting)");
            }
            conn.verify_primary().await;
        }

        if let Some(peers) = &self.replay_peers {
            peers.ping_all().await;
        }

        let ok = self.ping_security(cache_ok).await;
        // Standby stores last: an unreachable one (up to REPLAY_PEER_TIMEOUT_MS each) must not
        // delay the security store's check above.
        if let Some(peers) = &self.standby_peers {
            peers.ping_all().await;
        }
        ok
    }

    async fn ping_security(&self, cache_ok: bool) -> bool {
        if let Some(sec) = self.security_conn.as_ref() {
            let ping = timeout(
                self.redis_timeout,
                redis::cmd("PING").query_async::<_, String>(&mut sec.get()),
            )
            .await;
            sec.observe_timed(&ping);
            sec.verify_primary().await;
            let sec_ok = match ping {
                Ok(Ok(resp)) if resp == "PONG" => true,
                Ok(Ok(_)) => {
                    warn!("Security Redis PING returned unexpected response");
                    false
                }
                Ok(Err(e)) => {
                    warn!("Security Redis PING failed: {}", e);
                    false
                }
                Err(_) => {
                    warn!("Security Redis PING timeout");
                    false
                }
            };
            crate::health::record_security_redis_connected(&self.network, sec_ok);
            // The peers were PINGed just before (ping_redis), so their state is current.
            let via_fallback = !sec_ok && self.serves_without_local_store();
            if via_fallback != crate::health::is_replay_serving_via_fallback(&self.network) {
                if via_fallback {
                    warn!(network = %self.network, "Security Redis unreachable: serving through the peer stores (REPLAY_UNAVAILABLE_FALLBACK)");
                } else if !sec_ok {
                    warn!(network = %self.network, "Security Redis unreachable and the peer stores cannot decide: not serving");
                } else {
                    info!(network = %self.network, "Security Redis answers again: requests decided locally");
                }
            }
            crate::health::record_replay_serving_via_fallback(&self.network, via_fallback);
            cache_ok && sec_ok
        } else {
            // No dedicated security Redis: replay checks fail closed, so the origin cannot serve.
            crate::health::record_security_redis_connected(&self.network, false);
            cache_ok
        }
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
    /// otherwise the local verdict stands and the outcome is counted (`ohttp_replay_peer_total`).
    pub async fn check_replay(&self, body_hash: &[u8]) -> anyhow::Result<bool> {
        match self.check_replay_detailed(body_hash).await? {
            LocalReplayCheck::New => Ok(false),
            LocalReplayCheck::Replay => Ok(true),
            LocalReplayCheck::Unavailable => {
                anyhow::bail!("Replay check: no verdict from the security store (fail-closed)")
            }
        }
    }

    /// `check_replay`, except that a local store that gives no verdict is
    /// `LocalReplayCheck::Unavailable` instead of an error when the unavailable fallback can
    /// decide the request at the peer stores (`admit_without_local`, after the inner request
    /// is classified). Errors otherwise as `check_replay`.
    pub async fn check_replay_detailed(
        &self,
        body_hash: &[u8],
    ) -> anyhow::Result<LocalReplayCheck> {
        let key = format!("replay:{}:{}", self.network, hex::encode(body_hash));

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
        let peers = async {
            match sync_peers {
                Some(p) => Some(p.write_nonce(&key, REPLAY_TTL_SECS).await),
                None => None,
            }
        };
        let (local, peer_outcomes) = tokio::join!(local, peers);
        // A failover signal (READONLY on a demoted primary, a hung or broken connection) replaces
        // the connection in the background; this request still fails closed below.
        sec.observe_timed(&local);

        match local {
            Ok(Ok(Some(_))) => {}
            Ok(Ok(None)) => return Ok(LocalReplayCheck::Replay),
            Ok(Err(e)) => {
                if self.local_unavailable_fallback_ready() {
                    debug!(network = %self.network, error = %e, "Replay check: no verdict from the security store, deciding at the peer stores");
                    return Ok(LocalReplayCheck::Unavailable);
                }
                anyhow::bail!(
                    "Replay check failed on security connection (fail-closed): {}",
                    e
                );
            }
            Err(_) => {
                if self.local_unavailable_fallback_ready() {
                    debug!(network = %self.network, "Replay check: security store timed out, deciding at the peer stores");
                    return Ok(LocalReplayCheck::Unavailable);
                }
                anyhow::bail!(
                    "Replay check timeout on security connection (fail-closed): {}ms",
                    self.redis_timeout.as_millis()
                );
            }
        }

        let (Some(peers), Some(outcomes)) = (sync_peers, peer_outcomes) else {
            return Ok(LocalReplayCheck::New);
        };
        Ok(
            match self.peer_verdict(&outcomes, peers.fail_closed(), "REPLAY_PEER_FAIL_CLOSED")? {
                true => LocalReplayCheck::Replay,
                false => LocalReplayCheck::New,
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
                warn!(
                    network = %self.network,
                    outcomes = ?outcomes,
                    "Replay peer unavailable; proceeding on the local verdict"
                );
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
    ///   `REPLAY_PEER_FAIL_CLOSED_WRITES` (default fail-closed).
    pub async fn replicate_nonce(
        &self,
        body_hash: &[u8],
        class: RouteClass,
    ) -> anyhow::Result<bool> {
        Ok(self.replicate_nonce_checked(body_hash, class).await?.replay)
    }

    /// `replicate_nonce` with what the replica wait that follows needs to know (`PeerCheck`).
    pub async fn replicate_nonce_checked(
        &self,
        body_hash: &[u8],
        class: RouteClass,
    ) -> anyhow::Result<PeerCheck> {
        let replay = |replay: bool| PeerCheck {
            replay,
            ..PeerCheck::default()
        };
        let Some(peers) = &self.replay_peers else {
            return Ok(replay(false));
        };
        let key = format!("replay:{}:{}", self.network, hex::encode(body_hash));
        match (peers.mode(), class) {
            // check_replay already wrote the nonce to every peer; a WRITE waits for their
            // replicas at the peers that are connected (a disconnected one was tolerated there).
            (ReplayPeerMode::Sync, RouteClass::Write) => {
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
                    ..PeerCheck::default()
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
                let outcomes = peers.write_nonce(&key, REPLAY_TTL_SECS).await;
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
                    return self.hub_unavailable_fallback(&key, &outcomes).await;
                }
                let replay = self.peer_verdict(
                    &outcomes,
                    peers.fail_closed_writes(),
                    "REPLAY_PEER_FAIL_CLOSED_WRITES",
                )?;
                // The peers that stored the nonce (the shared store, while reachable) must have
                // it on their replicas before the WRITE runs. A peer that did not answer was
                // tolerated by the verdict above (REPLAY_PEER_FAIL_CLOSED_WRITES=0 while the peers
                // are down).
                let mut at_standby = false;
                let mut hub_needs_local_ack = false;
                if !replay {
                    let fresh = |i: usize| outcomes.get(i) == Some(&PeerOutcome::Fresh);
                    let all_fresh =
                        !outcomes.is_empty() && outcomes.iter().all(|o| *o == PeerOutcome::Fresh);
                    if let Some(fb) = &self.hub_fallback {
                        fb.note_generation(peers.disruptions());
                    }
                    match peers.confirm_replicated_kind(&key, fresh).await {
                        Ok(()) => {
                            // Also when a peer did not answer and the policy tolerated it
                            // (REPLAY_PEER_FAIL_CLOSED_WRITES=0): the WRITE then runs on the
                            // local verdict, and the fallback store must still be asked.
                            match self.hub_window_check(&key).await {
                                Some(true) => {
                                    return Ok(PeerCheck {
                                        replay: true,
                                        ..PeerCheck::default()
                                    })
                                }
                                // Stored there synchronously: no asynchronous hand-off.
                                Some(false) => at_standby = true,
                                None => {}
                            }
                        }
                        Err(f) if f.only_short && all_fresh => {
                            match self.hub_short_ack_fallback(&key, f).await? {
                                HubFallback::Replay => {
                                    return Ok(PeerCheck {
                                        replay: true,
                                        ..PeerCheck::default()
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
                    if let Some(r) = &self.replicator {
                        if !outcomes.iter().all(|o| *o == PeerOutcome::Fresh) {
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
                    ..PeerCheck::default()
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

    /// Every WRITE of a read origin with a confirming standby store, after the hub's verdict:
    /// `SET NX` at the standby stores (write_fallback.rs, "Check at the fallback store").
    /// Some(true) = a standby store held the nonce (replay), Some(false) = every one took it,
    /// None = no standby store that confirms, or one did not answer (the hub's verdict stands,
    /// the asynchronous hand-off follows as usual).
    async fn hub_window_check(&self, key: &str) -> Option<bool> {
        let fb = self.hub_fallback.as_ref()?;
        let standby = self.confirming_standby()?;
        // The label tells a check inside the window (after startup or a hub disruption) from
        // the steady state; both are decided the same way.
        let path = if fb.window_open() {
            "hub_window"
        } else {
            "hub_check"
        };
        let outcomes = standby.write_nonce(key, REPLAY_TTL_SECS).await;
        let verdict = combine_peer_outcomes(&outcomes);
        let result = match verdict {
            PeerVerdict::Fresh => "accepted",
            PeerVerdict::Replay => "replay",
            PeerVerdict::Unavailable => "unavailable",
        };
        crate::health::record_replay_write_fallback(&self.network, path, result);
        match verdict {
            PeerVerdict::Replay => Some(true),
            PeerVerdict::Fresh => Some(false),
            PeerVerdict::Unavailable => None,
        }
    }

    /// The hub took the nonce as new but its replicas did not acknowledge it (`f`). With
    /// standby stores: confirm there (`SET NX` + `WAIT`). With the local replica wait: leave it
    /// to the local replicas. Otherwise, or on any other outcome: fail closed with `f`.
    async fn hub_short_ack_fallback(
        &self,
        key: &str,
        f: ConfirmFailure,
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
            let outcomes = standby.write_nonce(key, REPLAY_TTL_SECS).await;
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
            warn!(network = %self.network, reason = %f.message, "WRITE replay nonce confirmed at the standby stores (hub replica acknowledgement short); written back to the hub later");
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
    /// replicas have it.
    async fn hub_unavailable_fallback(
        &self,
        key: &str,
        outcomes: &[PeerOutcome],
    ) -> anyhow::Result<PeerCheck> {
        let Some(fb) = self.hub_fallback.as_ref() else {
            anyhow::bail!("Replay check failed at a peer origin (REPLAY_PEER_FAIL_CLOSED_WRITES): {outcomes:?}");
        };
        fb.open_window();
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
                ..PeerCheck::default()
            });
        };
        let at_standby = standby.write_nonce(key, REPLAY_TTL_SECS).await;
        match combine_peer_outcomes(&at_standby) {
            PeerVerdict::Replay => {
                record("replay");
                return Ok(PeerCheck {
                    replay: true,
                    ..PeerCheck::default()
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
        warn!(network = %self.network, outcomes = ?outcomes, "WRITE replay nonce confirmed at the standby stores (no verdict from the hub); written back to the hub later");
        Ok(PeerCheck {
            at_standby: true,
            ..PeerCheck::default()
        })
    }

    /// The shared epoch from Redis, initialised atomically (SET NX) to the current Unix time
    /// when missing (an existing epoch is kept). Returns the local value on error.
    pub async fn get_shared_epoch(&self) -> u64 {
        let key = format!("epoch:{}", self.network);

        let sec = self.security_conn.as_ref();
        let mut conn = if let Some(sec) = sec {
            sec.get()
        } else if let Some(cache) = self.cache_conn.load_full().map(|c| (*c).clone()) {
            cache
        } else {
            return self.epoch.load(Ordering::Relaxed);
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
            Ok(Ok(Some(epoch))) => {
                self.epoch.store(epoch, Ordering::Relaxed);
                self.last_epoch_sync.store(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    Ordering::Relaxed,
                );
                epoch
            }
            Ok(Ok(None)) => {
                let fallback_epoch = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                warn!(
                    fallback_epoch,
                    "Epoch key vanished after SET NX, using timestamp"
                );
                fallback_epoch
            }
            Ok(Err(e)) => {
                warn!(network = %self.network, error = %e, "Failed to read shared epoch from Redis");
                crate::health::record_cache_redis_timeout(&self.network, "epoch_error");
                self.epoch.load(Ordering::Relaxed)
            }
            Err(_) => {
                warn!(network = %self.network, timeout_ms = self.redis_timeout.as_millis(), "Epoch GET timeout");
                crate::health::record_cache_redis_timeout(&self.network, "epoch_timeout");
                self.epoch.load(Ordering::Relaxed)
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
                warn!(error = %e, "third-party cache get error");
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
            Ok(Err(e)) => warn!(error = %e, "third-party cache put error"),
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
                    warn!(network = %self.network, error = %e, "cache mget error");
                    crate::health::record_cache_redis_timeout(&self.network, "mget_error");
                    vec![None; n]
                }
                Err(_) => {
                    warn!(network = %self.network, timeout_ms = self.redis_timeout.as_millis(), "cache mget timeout");
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
                    warn!(network = %self.network, error = %e, "cache set error");
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
                    warn!(network = %self.network, error = %e, "cache del error");
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
                    warn!(network = %self.network, error = %e, "leader lock set error");
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
                    warn!(network = %self.network, error = %e, "leader lock renew error");
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
    ) -> BoxFuture<'_, Option<bool>> {
        Box::pin(async move {
            let conn = self.cache_conn.load_full()?;
            let mut conn = (*conn).clone();
            let script = r#"
                if redis.call('GET', KEYS[2]) == ARGV[3] then
                    redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
                    return 1
                else
                    return 0
                end
            "#;
            let script = redis::Script::new(script);
            let mut invocation = script.key(&key);
            invocation
                .key(&guard_key)
                .arg(&value)
                .arg(ttl_ms)
                .arg(&guard[..]);
            let fut = invocation.invoke_async::<_, i64>(&mut conn);
            match timeout(self.redis_timeout, fut).await {
                Ok(Ok(v)) => Some(v == 1),
                Ok(Err(e)) => {
                    warn!(network = %self.network, error = %e, "leader lock takeover error");
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
            // TTL (ms), then value + TTL (s) per entry: KEYS[i] -> ARGV[2i-1], ARGV[2i].
            let script = r#"
                local holder = redis.call('GET', KEYS[1])
                if holder and holder ~= ARGV[1] then
                    return 0
                end
                redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
                for i = 2, #KEYS do
                    redis.call('SET', KEYS[i], ARGV[2 * i - 1], 'EX', ARGV[2 * i])
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
                    warn!(network = %self.network, error = %e, "fenced tip write error");
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
                    warn!(network = %self.network, error = %e, "leader lock release error");
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
                warn!(network = %self.network, op, error = %e, "permanent store error");
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

/// Spawn the Redis housekeeping task: sync the shared epoch and PING both Redis roles every
/// `HOUSEKEEPING_SECS`, updating `ohttp_redis_connected`. (The tip is the chain follower's.)
pub fn spawn_redis_housekeeping(cache: ResponseCache) {
    tokio::spawn(async move {
        cache.get_shared_epoch().await;
        let redis_ok = cache.ping_redis().await;
        crate::health::record_redis_connected(&cache.network, redis_ok);
        if redis_ok {
            info!(network = %cache.network, "Redis PING successful on startup");
        } else {
            warn!(network = %cache.network, "Redis PING failed on startup, will retry");
        }
        loop {
            tokio::time::sleep(Duration::from_secs(HOUSEKEEPING_SECS)).await;
            let epoch = cache.get_shared_epoch().await;
            debug!(network = %cache.network, epoch, "Synced shared cache epoch from Redis");
            let redis_ok = cache.ping_redis().await;
            crate::health::record_redis_connected(&cache.network, redis_ok);
            if !redis_ok {
                warn!(network = %cache.network, "Redis connectivity check failed, will retry");
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

/// Spawn `workers` tasks that fill the pinned tier for every height in PINNED_TREESTATE_RANGE.
/// Heights are claimed with INCR on a cursor in the pinned Redis, so all gateway processes share
/// one pass and a restart resumes where it stopped. A height that keeps failing is skipped (the
/// write-through path fills it later). Stops at the range end; at tip - FINALIZED_DEPTH it gives
/// the height back to the cursor and waits, then follows the tip as blocks become final, so the
/// tier keeps up with the tip (origins that read it from a replica of that Redis stay current too).
pub fn spawn_pinned_backfill<F, Fut>(cache: ResponseCache, workers: usize, fetch: F)
where
    F: Fn(u64) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = anyhow::Result<Vec<u8>>> + Send + 'static,
{
    // The cursor lives in the store the entries are written to.
    let writer = cache
        .pinned_write_conn
        .clone()
        .or_else(|| cache.pinned_conn.clone());
    let (Some((start, end)), Some(conn)) = (cache.pinned_range, writer) else {
        return;
    };
    if cache.pinned_read_only_until.load(Ordering::Relaxed) != 0 {
        warn!(network = %cache.network, "pinned backfill not started: the pinned store is a read replica");
        return;
    }
    for worker in 0..workers {
        let cache = cache.clone();
        let fetch = fetch.clone();
        let conn = conn.clone();
        tokio::spawn(async move {
            // Wait for a fresh tip so pinned_put's finality check can pass.
            while !cache.is_tip_fresh() {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            info!(network = %cache.network, worker, start, end, "pinned backfill worker started");
            loop {
                // Bounded, so that a hung connection is reported (and replaced) instead of
                // stopping the worker.
                let incr = timeout(
                    cache.redis_timeout * 4,
                    redis::cmd("INCR")
                        .arg(cache.pinned_cursor_key())
                        .query_async::<_, u64>(&mut conn.get()),
                )
                .await;
                conn.observe_timed(&incr);
                let n: u64 = match incr {
                    Ok(Ok(n)) => n,
                    Err(_) => {
                        warn!(network = %cache.network, "pinned backfill cursor timeout");
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        continue;
                    }
                    Ok(Err(e)) => {
                        warn!(network = %cache.network, error = %e, "pinned backfill cursor error");
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        continue;
                    }
                };
                let height = start.saturating_add(n - 1);
                let limit = end.min(cache.tip_height().saturating_sub(FINALIZED_DEPTH + 1));
                if height > end {
                    info!(network = %cache.network, worker, height, "pinned backfill done");
                    return;
                }
                if height > limit {
                    // Caught up: hand the height back and wait for the next final block.
                    let _ = timeout(
                        cache.redis_timeout * 4,
                        redis::cmd("DECR")
                            .arg(cache.pinned_cursor_key())
                            .query_async::<_, i64>(&mut conn.get()),
                    )
                    .await;
                    tokio::time::sleep(PINNED_FOLLOW_INTERVAL).await;
                    continue;
                }
                if cache.pinned_exists(height).await {
                    continue;
                }
                let mut stored = false;
                for attempt in 0..3u64 {
                    match fetch(height).await {
                        Ok(resp) => {
                            if cache.pinned_put(height, &resp).await {
                                stored = true;
                                break;
                            }
                        }
                        Err(e) => {
                            debug!(network = %cache.network, height, error = %e, "pinned backfill fetch error");
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(1 + attempt * 2)).await;
                }
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
        });
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
            pinned_write_conn: None,
            pinned_read_only_until: Arc::new(AtomicU64::new(0)),
            pinned_range: None,
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
        }
    }

    async fn local_redis() -> Option<ConnectionManager> {
        let client = redis::Client::open("redis://127.0.0.1:6379").ok()?;
        ConnectionManager::new(client).await.ok()
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
        // Skip without a local Redis.
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
        assert!(!a.replicate_nonce(&h1, READ).await.unwrap());
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
        assert!(!a.replicate_nonce(&h2, WRITE).await.unwrap());
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
        assert!(!b.replicate_nonce(&h3, WRITE).await.unwrap());
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
            a.replicate_nonce(&h4, WRITE).await.unwrap(),
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
            if peers.peers[0].wait_conn.load().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            peers.peers[0].wait_conn.load().is_some(),
            "WAIT connection opened in the background"
        );
        let h1 = sha2::Sha256::digest(unique("write without a replica"));
        assert!(!strict.check_replay(&h1).await.unwrap());
        let started = std::time::Instant::now();
        let err = strict.replicate_nonce(&h1, WRITE).await.unwrap_err();
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
        assert!(!strict.replicate_nonce(&h2, READ).await.unwrap());

        let none_needed = read_origin(WriteWaitConfig {
            replicas: 0,
            timeout_ms: 50,
        })
        .await;
        let h3 = sha2::Sha256::digest(unique("write, zero replicas"));
        assert!(!none_needed.check_replay(&h3).await.unwrap());
        assert!(!none_needed.replicate_nonce(&h3, WRITE).await.unwrap());
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
        assert!(!peer_origin.replicate_nonce(&h4, WRITE).await.unwrap());

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
        if set_aof(false).await.is_err() {
            return;
        }

        let auto = peer_origin()
            .await
            .with_local_waitaof(url, LocalAofConfig::Auto(500))
            .await
            .unwrap();
        assert_eq!(auto.local_waitaof_ms(), None, "no AOF: auto leaves it off");
        let h0 = sha2::Sha256::digest(unique("local write, no aof"));
        assert!(!auto.check_replay(&h0).await.unwrap());
        assert!(!auto.replicate_nonce(&h0, WRITE).await.unwrap());
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
        assert!(!on.replicate_nonce(&h1, WRITE).await.unwrap());
        // READs are not delayed, and a nonce gone from the store fails closed.
        let h2 = sha2::Sha256::digest(unique("local read, aof"));
        assert!(!on.check_replay(&h2).await.unwrap());
        assert!(!on.replicate_nonce(&h2, READ).await.unwrap());
        let h3 = sha2::Sha256::digest(unique("local write, nonce gone"));
        assert!(!on.check_replay(&h3).await.unwrap());
        let mut sec_conn = sec.clone();
        let _: () = redis::cmd("DEL")
            .arg(format!("replay:{net}:{}", hex::encode(h3)))
            .query_async(&mut sec_conn)
            .await
            .unwrap();
        let err = on.replicate_nonce(&h3, WRITE).await.unwrap_err();
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
        assert!(!mixed.replicate_nonce(&h4, WRITE).await.unwrap());

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
        assert!(!a.replicate_nonce(&h, READ).await.unwrap());
        // Inside the window: B accepts (its store does not have it yet) and enqueues its own
        // replication, which will find the nonce already at A.
        assert!(
            !b.check_replay(&h).await.unwrap(),
            "inside the replication window: accepted at B"
        );
        assert!(!b.replicate_nonce(&h, READ).await.unwrap());
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
        assert!(!c.replicate_nonce(&h, READ).await.unwrap());
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
        let err = c.replicate_nonce(&h2, WRITE).await.unwrap_err();
        assert!(
            err.to_string().contains("REPLAY_PEER_FAIL_CLOSED_WRITES"),
            "{err}"
        );

        // WRITE with REPLAY_PEER_FAIL_CLOSED_WRITES=0: local verdict.
        let c_open = mk(false).await;
        let h3 = sha2::Sha256::digest(unique("write with peer down, open"));
        assert!(!c_open.check_replay(&h3).await.unwrap());
        assert!(!c_open.replicate_nonce(&h3, WRITE).await.unwrap());
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
            assert!(!c.replicate_nonce(&h, class).await.unwrap(), "{class:?}");
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
            assert!(!a.replicate_nonce(&h, class).await.unwrap());
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
        assert!(!a.replicate_nonce(&h, READ).await.unwrap(), "no-op");
        assert!(!a.replicate_nonce(&h, WRITE).await.unwrap(), "no-op");
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
            body: b"lightd-info".to_vec(),
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

    fn unique_network(s: &str) -> String {
        String::from_utf8(unique(s)).unwrap().replace(' ', "-")
    }

    fn tip_at(cache: &ResponseCache, height: u64) {
        cache.tip.set(crate::store::Tip {
            height,
            hash: vec![1u8; 32],
        });
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

        let mut p = cache.pinned_write_conn.as_ref().unwrap().get();
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

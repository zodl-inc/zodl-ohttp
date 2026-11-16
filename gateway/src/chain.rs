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

//! Chain follower: one leader per network keeps the `height -> hash` index that validates
//! every cached block, tree state and transaction; the other gateway processes follow its index.
//!
//! - **Leader lock**: `SET {chain}leader {token} NX PX 10000`, renewed every tick with an
//!   atomic "extend if still mine" script, and every third of the TTL while leader work runs
//!   (a cold start or a catch-up can take longer than the TTL). Work whose renewal finds the lock
//!   held by another process, or that could not renew it for a whole TTL, is cancelled. A
//!   process that loses Redis stops leading; another takes over once the TTL lapses.
//!   Non-leaders read the tip from Redis every tick.
//! - **Confirmation**: on every tick its lightwalletd answers with the indexed tip (or moves
//!   it), the leader rewrites `{chain}tip_seen` under the lock. Followers refresh their tip only
//!   when that value changed since their last read (no clock comparison between processes), so a
//!   tip the leader stops confirming goes stale everywhere after `store::TIP_STALE_AFTER`. The
//!   leader stops confirming after [`MAX_IDLE_TICKS`] ticks with the same tip (a lightwalletd
//!   stuck at the tip height) and after [`MAX_BEHIND_TICKS`] ticks behind it. A leader that
//!   does not write `tip_seen` (an older version) is followed as before, every read refreshing
//!   the tip: that is the case when the key is absent, and when its value stays the same while
//!   the stored tip changes (the key outlives the leader that wrote it), until the value changes
//!   again.
//! - **Stale leader**: a leader can keep its lock and still stop moving the tip (its
//!   lightwalletd answers with an old tip, or keeps failing the block fetch). With every tip it
//!   writes, the leader also stores when it moved it (`{chain}tip_at`). A follower that finds
//!   the stored tip unmoved for longer than [`DEFAULT_TIP_STALE_AFTER`]
//!   (`CHAIN_TIP_STALE_SECS`) asks its own lightwalletd every [`STALE_PROBE_EVERY`] ticks.
//!   If that is ahead, it serves its own tip at once, and if it is still ahead on the next
//!   probe, with the same stored tip (height and hash) and the same lock holder, it takes the
//!   lock over (one script that checks both) and continues the index from there in the same
//!   tick. So two followers that saw the same stale tip cannot take it from each other; a
//!   refused takeover, or another holder, starts the observation again. What a follower serves
//!   meanwhile follows one rule (`ChainFollower::follow_stored`): the highest tip its own
//!   lightwalletd answered, for at most [`HELD_TIP_MAX_AGE`] after it last did, while the stored
//!   tip stays below it on the same chain; a lower or failed probe never makes it step back;
//!   the stored tip again once it ages out, catches up, or changes at or below the observed
//!   height. A chain that really has no new block leaves every lightwalletd at the stored tip,
//!   so nothing happens. The age is wall-clock time between processes: clock skew beyond the
//!   bound makes followers probe more often, never take over from a leader whose tip moves. A
//!   leader that does not store the time (an older version) is never treated as stale.
//!   Metrics `ohttp_chain_tip_age_seconds`, `ohttp_chain_stale_leader_total`.
//! - **Fencing**: the tip, every index entry with its block (one script per batch of at most
//!   [`BLOCK_WRITE_BATCH`] blocks and [`BLOCK_WRITE_BATCH_BYTES`] of payload), the confirmation and every deletion of a reorg are written
//!   only while the writer holds the lock with its own token (an absent lock refuses too). A
//!   leader that was replaced while a tick was in flight (a slow block fetch, a pause) thus
//!   cannot write the index or blocks of another fork, delete what its successor wrote, or move
//!   the stored tip back; it stops leading. A store error in one of these writes stops the tick
//!   (and hands the lock over).
//! - **Lagging backend**: a leader whose lightwalletd answers with a lower tip that is on the
//!   indexed chain (the index has that block) treats it as behind, not as a reorg: the tip and
//!   the index stay. After [`MAX_BEHIND_TICKS`] such ticks in a row it gives the lock up and
//!   does not try to take it again for [`BEHIND_COOLDOWN_TICKS`], so a process with another
//!   lightwalletd leads.
//! - **Polling**: the leader calls `GetLatestBlock` once per tick, with a 2 s pause after each
//!   tick. On a new tip it fetches the new blocks once (`GetBlockRange`, at most
//!   [`MAX_CATCHUP`] per tick when advancing), checks `prevHash`
//!   continuity against the index, stores the blocks in the block cache and writes
//!   `index:{height} -> hash` for each, then the tip.
//! - **Reorg**: when the fetched blocks do not chain to the index (or the tip hash changed at the
//!   same or a lower height) it walks back in batches of eight until a canonical block matches
//!   the index or an index entry is missing (the fork point), deletes the index entries, cached blocks (every pool filter
//!   seen), nullifiers and tree states above it, refetches the canonical blocks and rewrites
//!   the index. Cached transactions above the fork are caught by validation (their stored block
//!   hash no longer matches the index) and refetched on demand.
//! - **Cold index**: after indexing its first tip, the leader fills the gaps of its window
//!   (`tip - INDEX_WINDOW ..= tip`) in batches of 100 heights per idle tick, so cached blocks
//!   inside the window become servable. A leader that takes over an existing index does not
//!   rescan it.
//! - **Permanent tier** (optional): blocks the leader fetches that are already final (depth >=
//!   `PERMANENT_DEPTH` below the tip, at or above the tier's floor) are written there instead
//!   of the cache Redis, and on every advance the heights that just became final are moved
//!   from the cache Redis (every pool filter seen, index-matched) to the permanent tier.
//!
//! Everything is fail-open: a Redis error demotes the leader (or stops its tick) and leaves the
//! tip unknown, and the request paths then answer from upstream.

use crate::block_cache::{block_key, grpc_frame, FetchedBlock, PoolKeys};
use crate::local::LocalCache;
use crate::store::{
    decode_tip, decode_unix_ms, encode_tip, encode_unix_ms, index_key, lock_key,
    permanent_block_key, tip_at_key, tip_key, tip_seen_key, unix_ms_now, CacheStore,
    PermanentStore, Tip, INDEX_WINDOW, PERMANENT_DEPTH,
};
use anyhow::Result;
use bytes::Bytes;
use futures_util::future::BoxFuture;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Poll interval.
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Leader lock TTL; a dead leader is replaced after this.
pub const LOCK_TTL_MS: u64 = 10_000;
/// While a leader tick runs, its lock is renewed this often, so a tick that takes longer than
/// the TTL (a slow catch-up) keeps it. A tick that fails hands the lock over at once.
const LOCK_RENEW_EVERY: Duration = Duration::from_millis(LOCK_TTL_MS / 3);
/// New blocks fetched per tick at most.
pub const MAX_CATCHUP: u64 = 100;
/// Deepest walk-back before giving up and invalidating the whole span.
const MAX_WALK_BACK: u64 = 200;
/// Heights compared per walk-back step.
const WALK_BATCH: u64 = 8;
/// Index entries expire after this (they leave the window long before).
const INDEX_TTL_SECS: u64 = 7 * 86_400;
/// Heights checked per backfill tick.
const BACKFILL_BATCH: u64 = 100;
/// Non-leaders probe lightwalletd for the reachability gauge every this many ticks.
const HEALTH_PROBE_EVERY: u64 = 15;
/// A stored tip unmoved for this long makes followers compare it with their own lightwalletd:
/// two block intervals. A chain without new blocks costs only those probes.
pub const DEFAULT_TIP_STALE_AFTER: Duration = Duration::from_secs(150);
/// While the stored tip is older than the bound, followers ask their own lightwalletd every this
/// many ticks; a takeover needs two such probes in a row that are ahead.
pub const STALE_PROBE_EVERY: u64 = 5;
/// A follower that found its own lightwalletd ahead of an unmoved stored tip serves that tip for
/// at most this long after a probe last confirmed it (three probe intervals). Meanwhile it never
/// falls back to the lower stored tip (a failed probe or a lagging answer does not count), so the
/// tip it serves does not go back and forth; once the bound passes without a confirmation it
/// serves the stored tip again.
pub const HELD_TIP_MAX_AGE: Duration = Duration::from_secs(30);
/// A leader whose lightwalletd answers below the indexed tip (on the indexed chain) keeps
/// serving and confirming the indexed tip for at most this many ticks in a row (about 30 s at
/// the poll interval). On the next one it stops confirming it, releases the lock and does not
/// try to take it again for [`BEHIND_COOLDOWN_TICKS`], so that a process with another
/// lightwalletd leads; the unconfirmed tip goes stale everywhere after `store::TIP_STALE_AFTER`
/// and the request paths answer from upstream meanwhile. Any other outcome resets the count.
pub const MAX_BEHIND_TICKS: u64 = 15;
/// Ticks a leader that gave the lock up after [`MAX_BEHIND_TICKS`] waits before it tries to
/// take it again.
pub const BEHIND_COOLDOWN_TICKS: u64 = 5;
/// A leader whose lightwalletd keeps answering with the indexed tip confirms it for at most
/// this many ticks in a row (at least 10 minutes at the poll interval), then stops: a
/// lightwalletd stuck at the tip height cannot keep an old tip fresh either. A gap of 10
/// minutes between blocks is rare (well below 0.1 % of blocks at a 75 s target spacing), and
/// during one the request paths only answer from upstream. A new tip resets the count.
pub const MAX_IDLE_TICKS: u64 = 300;
/// Blocks written per fenced script at most (two entries each: index and block).
const BLOCK_WRITE_BATCH: usize = 32;
/// Block payload bytes per fenced script at most: a script ends before the block that would
/// take it past this, so one script stays well inside the store's operation timeout whatever
/// the block sizes. A single block above it is written alone.
const BLOCK_WRITE_BATCH_BYTES: usize = 1 << 20;
/// Keys deleted per fenced script.
const DELETE_BATCH: usize = 256;

/// Where the follower reads the chain: lightwalletd, or a fake in tests.
pub trait ChainSource: Send + Sync {
    /// `GetLatestBlock`.
    fn latest(&self) -> BoxFuture<'static, Result<Tip>>;
    /// `GetBlockRange(start, end)` ascending, each block decoded.
    fn blocks(&self, start: u64, end: u64) -> BoxFuture<'static, Result<Vec<FetchedBlock>>>;
}

/// Told whenever this process, as leader, writes a new tip (the mempool fan-out ends its
/// session). Followers update their tip without telling listeners.
pub trait BlockListener: Send + Sync {
    fn on_new_block(&self, tip: &Tip);
}

/// What one tick did (for tests and logs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Not the leader this tick.
    Follower,
    /// Leader, no change.
    Idle,
    /// Leader, first tip indexed.
    Cold {
        tip: u64,
    },
    Advanced {
        from: u64,
        to: u64,
    },
    Reorg {
        fork: u64,
        depth: u64,
        tip: u64,
    },
    /// Leader, its lightwalletd answered with a lower tip on the indexed chain: kept `tip`.
    Behind {
        backend: u64,
        tip: u64,
    },
    /// Follower, the stored tip had not moved and its own lightwalletd was ahead: it serves
    /// its own tip (`to`). `took_over` (it holds the lock now) is internal: `tick` then goes on
    /// as the leader and returns the leader's outcome.
    StaleLeader {
        from: u64,
        to: u64,
        took_over: bool,
    },
    Error(String),
}

pub struct ChainFollower {
    store: Arc<dyn CacheStore>,
    source: Arc<dyn ChainSource>,
    local: Option<Arc<LocalCache>>,
    pools: Arc<PoolKeys>,
    listeners: parking_lot::Mutex<Vec<Arc<dyn BlockListener>>>,
    network: String,
    token: String,
    leader: AtomicBool,
    ticks: AtomicU64,
    /// The leader's indexed tip (what the index covers up to).
    last: parking_lot::Mutex<Option<Tip>>,
    /// Next height (downward) the cold backfill checks, `None` when done or not started.
    backfill_cursor: parking_lot::Mutex<Option<u64>>,
    permanent: Option<Arc<dyn PermanentStore>>,
    permanent_min_height: u64,
    /// See [`DEFAULT_TIP_STALE_AFTER`].
    stale_after: Duration,
    /// Follower: what the last probes of its own lightwalletd found (see [`HeldTip`]).
    stale: parking_lot::Mutex<Option<HeldTip>>,
    /// Unix milliseconds of the last tip this process wrote as leader (0 = none).
    moved_at_ms: AtomicU64,
    /// Consecutive leader ticks whose lightwalletd was behind the indexed tip.
    behind_ticks: AtomicU64,
    /// Consecutive leader ticks whose lightwalletd answered with the indexed tip.
    idle_ticks: AtomicU64,
    /// No attempt to take the lock before this tick (after giving it up, see
    /// [`MAX_BEHIND_TICKS`]).
    cooldown_until: AtomicU64,
    /// Follower: the last `tip_seen` value read and the stored tip read with it (see
    /// [`SeenTip`]); the tip is refreshed only when the value changes.
    last_seen: parking_lot::Mutex<Option<SeenTip>>,
}

/// A follower's last read of the leader's confirmation.
#[derive(Clone, Debug)]
struct SeenTip {
    /// The `tip_seen` value.
    seen: Bytes,
    /// The stored tip read with it.
    tip: Tip,
    /// The stored tip changed while `seen` did not: the leader does not write `tip_seen` (a
    /// leader of this version writes both in one script), and `seen` is a leftover of an
    /// earlier one. The confirmation is treated as absent (every read refreshes) until `seen`
    /// changes again.
    unconfirming_leader: bool,
}

/// A follower's view of a leader whose tip stopped moving (see [`ChainFollower::follow_stored`]
/// for the exact rule of what it serves).
#[derive(Clone, Debug)]
struct HeldTip {
    /// The stored tip (height and hash) the observation is bound to.
    stored: Tip,
    /// The tip it serves meanwhile: the highest its own lightwalletd answered since the
    /// observation began (a lower answer does not replace it).
    own: Tip,
    /// When a probe last answered `own` (or higher): the held tip is served for at most
    /// [`HELD_TIP_MAX_AGE`] after it.
    confirmed_at: tokio::time::Instant,
    /// The last probe found its own lightwalletd ahead of `stored` with the lock held by
    /// `holder`: the next such probe is a second one in a row. A probe that failed changes
    /// nothing; one that was not ahead, a refused takeover or another holder clears it.
    ahead: bool,
    /// The lock holder when the observation was made (`""` = not held; None = it could not be
    /// read, no takeover): a takeover requires the lock to still be held by it, so that two
    /// followers that saw the same stale tip do not take the lock from each other.
    holder: Option<String>,
}

impl HeldTip {
    /// Whether the observation still applies to `stored`: the same stored tip, or one higher
    /// on the leader's chain (it moves again, below `own`). A stored tip at the same height with
    /// another hash, or a lower one, is a reorg of the stored chain: the observation is dropped.
    fn applies_to(&self, stored: &Tip) -> bool {
        stored == &self.stored || stored.height > self.stored.height
    }

    fn fresh(&self) -> bool {
        self.confirmed_at.elapsed() <= HELD_TIP_MAX_AGE
    }
}

impl ChainFollower {
    pub fn new(
        store: Arc<dyn CacheStore>,
        source: Arc<dyn ChainSource>,
        local: Option<Arc<LocalCache>>,
        pools: Arc<PoolKeys>,
        network: String,
    ) -> Self {
        Self {
            store,
            source,
            local,
            pools,
            listeners: parking_lot::Mutex::new(Vec::new()),
            network,
            token: uuid::Uuid::new_v4().to_string(),
            leader: AtomicBool::new(false),
            ticks: AtomicU64::new(0),
            last: parking_lot::Mutex::new(None),
            backfill_cursor: parking_lot::Mutex::new(None),
            permanent: None,
            permanent_min_height: 0,
            stale_after: DEFAULT_TIP_STALE_AFTER,
            stale: parking_lot::Mutex::new(None),
            moved_at_ms: AtomicU64::new(0),
            behind_ticks: AtomicU64::new(0),
            idle_ticks: AtomicU64::new(0),
            cooldown_until: AtomicU64::new(0),
            last_seen: parking_lot::Mutex::new(None),
        }
    }

    /// The bound after which an unmoved stored tip makes followers check their own lightwalletd.
    pub fn with_stale_after(mut self, stale_after: Duration) -> Self {
        self.stale_after = stale_after;
        self
    }

    /// Attach the permanent tier for heights `>= min_height`.
    pub fn with_permanent(mut self, permanent: Arc<dyn PermanentStore>, min_height: u64) -> Self {
        self.permanent = Some(permanent);
        self.permanent_min_height = min_height;
        self
    }

    /// Whether a block at `height` is final against a tip at `tip_height` and goes to the
    /// permanent tier (not while that is a read-only replica: the block then stays in the cache
    /// tier, and the move of newly final blocks is skipped; they reach the tier on a later read
    /// once it takes writes).
    fn permanent_height(&self, height: u64, tip_height: u64) -> bool {
        self.permanent.as_ref().is_some_and(|p| p.writable())
            && height >= self.permanent_min_height
            && height.saturating_add(PERMANENT_DEPTH) <= tip_height
    }

    pub fn add_listener(&self, l: Arc<dyn BlockListener>) {
        self.listeners.lock().push(l);
    }

    pub fn is_leader(&self) -> bool {
        self.leader.load(Ordering::Relaxed)
    }

    /// The tip for answering requests (`None` when unknown or stale).
    pub fn tip(&self) -> Option<Tip> {
        self.store.tip_cell().get()
    }

    /// Run forever: one tick, then a pause of [`POLL_INTERVAL`].
    pub async fn run(self: Arc<Self>) {
        loop {
            let outcome = self.tick().await;
            match &outcome {
                Outcome::Error(e) => {
                    warn!(network = %self.network, error = %e, "chain follower tick failed")
                }
                Outcome::Follower
                | Outcome::Idle
                | Outcome::Behind { .. }
                | Outcome::StaleLeader {
                    took_over: false, ..
                } => {}
                other => info!(network = %self.network, outcome = ?other, "chain follower"),
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    fn set_leader(&self, is: bool) {
        let was = self.leader.swap(is, Ordering::Relaxed);
        if was != is {
            info!(network = %self.network, leader = is, "chain follower role changed");
            if !is {
                *self.last.lock() = None;
                *self.backfill_cursor.lock() = None;
            }
        }
        crate::health::record_chain_leader(&self.network, is);
    }

    fn notify_new_block(&self, tip: &Tip) {
        self.store.tip_cell().set(tip.clone());
        crate::health::record_cache_tip_height(&self.network, tip.height);
        for l in self.listeners.lock().iter() {
            l.on_new_block(tip);
        }
    }

    async fn read_stored_tip(&self) -> Option<Tip> {
        self.read_stored().await.0
    }

    /// The stored tip, how long ago the leader moved it (None: not stored, e.g. by a leader
    /// that does not write it) and the leader's last confirmation (`tip_seen`, None: not stored).
    async fn read_stored(&self) -> (Option<Tip>, Option<Duration>, Option<Bytes>) {
        let chain = self.store.chain_prefix();
        let mut values = self
            .store
            .mget(vec![
                tip_key(&chain),
                tip_at_key(&chain),
                tip_seen_key(&chain),
            ])
            .await
            .into_iter();
        let tip = values.next().flatten().and_then(|b| decode_tip(&b));
        let age = values
            .next()
            .flatten()
            .and_then(|b| decode_unix_ms(&b))
            .map(|ms| Duration::from_millis(unix_ms_now().saturating_sub(ms)));
        let seen = values.next().flatten();
        (tip, age, seen)
    }

    /// Follower tick with a stored tip that has not moved for `age`: compare it with this
    /// process's own lightwalletd (every [`STALE_PROBE_EVERY`] ticks). None = nothing to do
    /// (the caller serves the stored tip, or the tip held from an earlier probe, see
    /// [`Self::follow_stored`]). See the module docs, "Stale leader".
    async fn check_stale_leader(
        &self,
        n: u64,
        stored: &Tip,
        age: Option<Duration>,
    ) -> Option<Outcome> {
        if age.is_none_or(|a| a <= self.stale_after) || !n.is_multiple_of(STALE_PROBE_EVERY) {
            return None;
        }
        let own = match self.source.latest().await {
            Ok(t) => {
                crate::health::record_lwd_reachable(&self.network, true);
                t
            }
            Err(e) => {
                crate::health::record_lwd_reachable(&self.network, false);
                debug!(network = %self.network, error = %e, "stale tip check: own lightwalletd unavailable");
                return None;
            }
        };
        if own.height <= stored.height || own.hash.is_empty() {
            // Not ahead (now): no takeover on the next probe. A tip held from an earlier probe
            // is kept until it ages out (see `follow_stored`).
            if let Some(held) = self.stale.lock().as_mut() {
                held.ahead = false;
            }
            return None;
        }
        // Bind the observation to the current holder of the lock.
        let chain = self.store.chain_prefix();
        let holder = self
            .store
            .lock_holder(lock_key(&chain))
            .await
            .map(|h| h.unwrap_or_default());
        let now = tokio::time::Instant::now();
        let (served, seen_before) = {
            let mut held = self.stale.lock();
            let previous = held.take().filter(|h| h.applies_to(stored) && h.fresh());
            // Never lower than a held tip that is still fresh: a lower answer (another instance
            // behind the same name, a lagging one) does not replace it, nor reset its age.
            let (served, confirmed_at) = match &previous {
                Some(p) if p.own.height > own.height => (p.own.clone(), p.confirmed_at),
                _ => (own.clone(), now),
            };
            let seen_before = previous.as_ref().is_some_and(|p| {
                p.ahead && p.stored == *stored && p.holder.is_some() && p.holder == holder
            });
            *held = Some(HeldTip {
                stored: stored.clone(),
                own: served.clone(),
                confirmed_at,
                ahead: holder.is_some(),
                holder: holder.clone(),
            });
            (served, seen_before)
        };
        self.store.tip_cell().set(served.clone());
        crate::health::record_cache_tip_height(&self.network, served.height);
        let age_secs = age.map_or(0, |a| a.as_secs());
        let Some(holder) = holder.filter(|_| seen_before) else {
            warn!(network = %self.network, stored = stored.height, own = own.height, age_secs, "chain tip has not moved and this process's lightwalletd is ahead: serving its tip");
            crate::health::record_chain_stale_leader(&self.network, "local_tip");
            return Some(Outcome::StaleLeader {
                from: stored.height,
                to: served.height,
                took_over: false,
            });
        };
        let took_over = self
            .store
            .take_lock_if(
                lock_key(&chain),
                self.token.clone(),
                LOCK_TTL_MS,
                tip_key(&chain),
                encode_tip(stored),
                (!holder.is_empty()).then_some(holder),
            )
            .await
            == Some(true);
        if took_over {
            warn!(network = %self.network, stored = stored.height, own = own.height, age_secs, "chain follower took over from a leader whose tip stopped moving");
            crate::health::record_chain_stale_leader(&self.network, "takeover");
            self.set_leader(true);
            *self.last.lock() = Some(stored.clone());
            *self.backfill_cursor.lock() = None;
            *self.stale.lock() = None;
        } else if let Some(held) = self.stale.lock().as_mut() {
            // Refused (the tip or the holder changed meanwhile): start the observation again.
            held.ahead = false;
        }
        Some(Outcome::StaleLeader {
            from: stored.height,
            to: served.height,
            took_over,
        })
    }

    /// Follower: what to serve for the stored tip `stored`. The rule:
    ///
    /// - A held tip (its own lightwalletd ahead, see [`HeldTip`]) is served while it is fresh
    ///   (confirmed less than [`HELD_TIP_MAX_AGE`] ago), still above `stored`, and the
    ///   observation applies to `stored` (the same stored tip, or a higher one: the leader moves
    ///   again but is still below). It never steps back meanwhile, whatever probes answer.
    /// - Otherwise the held tip is dropped (aged out, caught up, or the stored chain changed at
    ///   or below its height) and the stored tip is served: one step back at most, after the age
    ///   bound.
    /// - The stored tip is refreshed only when the leader confirmed it since the last read
    ///   (`seen` changed), so a tip the leader stopped confirming goes stale here too. A leader
    ///   that does not write `seen` is followed as before, every read refreshing the tip: that
    ///   is the case without `seen`, and with a `seen` that stays the same while the stored tip
    ///   changes (the key left by an earlier leader; see [`SeenTip`]), until `seen` changes
    ///   again.
    fn follow_stored(&self, stored: &Tip, seen: Option<Bytes>) {
        let held = {
            let mut held = self.stale.lock();
            let keep = held
                .as_ref()
                .filter(|h| h.applies_to(stored) && h.own.height > stored.height && h.fresh())
                .map(|h| h.own.clone());
            if keep.is_none() {
                *held = None;
            }
            keep
        };
        let confirmed = match seen {
            None => {
                *self.last_seen.lock() = None;
                true
            }
            Some(seen) => {
                let mut last = self.last_seen.lock();
                let (confirmed, unconfirming_leader) = match last.as_ref() {
                    Some(prev) if prev.seen == seen => {
                        let unconfirming = prev.unconfirming_leader || prev.tip != *stored;
                        (unconfirming, unconfirming)
                    }
                    // First read, or a new confirmation: the strict rule applies (again).
                    _ => (true, false),
                };
                *last = Some(SeenTip {
                    seen,
                    tip: stored.clone(),
                    unconfirming_leader,
                });
                confirmed
            }
        };
        let tip = match held {
            Some(own) => own,
            None if confirmed => stored.clone(),
            None => return,
        };
        crate::health::record_cache_tip_height(&self.network, tip.height);
        self.store.tip_cell().set(tip);
    }

    /// One poll. Public so tests drive the follower deterministically.
    pub async fn tick(&self) -> Outcome {
        let n = self.ticks.fetch_add(1, Ordering::Relaxed);
        let lock = lock_key(&self.store.chain_prefix());
        let held = if self.is_leader() {
            self.store
                .pexpire_if_equal(lock, self.token.clone(), LOCK_TTL_MS)
                .await
        } else if n < self.cooldown_until.load(Ordering::Relaxed) {
            // Gave the lock up a moment ago (its lightwalletd stays behind): let another lead.
            Some(false)
        } else {
            self.store
                .set_nx_px(lock, self.token.clone(), LOCK_TTL_MS)
                .await
        };
        let became_leader = held == Some(true) && !self.is_leader();
        self.set_leader(held == Some(true));

        if !self.is_leader() {
            // Follow the leader's tip unless it stopped moving while this process's own
            // lightwalletd moved on; probe lightwalletd now and then for the health gauge.
            let (stored, age, seen) = self.read_stored().await;
            crate::health::record_chain_tip_age(&self.network, age);
            let mut took_over = false;
            if let Some(tip) = stored {
                match self.check_stale_leader(n, &tip, age).await {
                    // Leader now: this tick continues as one (below), so the stored tip moves
                    // before another process could take it over too.
                    Some(Outcome::StaleLeader {
                        took_over: true, ..
                    }) => took_over = true,
                    Some(outcome) => return outcome,
                    None => self.follow_stored(&tip, seen),
                }
            }
            if !took_over {
                if n.is_multiple_of(HEALTH_PROBE_EVERY) {
                    crate::health::record_lwd_reachable(
                        &self.network,
                        self.source.latest().await.is_ok(),
                    );
                }
                return Outcome::Follower;
            }
        }

        // The lock is renewed (exact token) while the tick runs, so leader work longer than the
        // TTL (a cold start, a catch-up) keeps it. When a renewal finds the lock held by another
        // process, or renewals fail for a whole TTL (the lease may have lapsed), the work is
        // cancelled at once: it could only be refused at its next fenced write. A tick that
        // fails (lightwalletd unreachable, an answer that does not chain) releases the lock,
        // so another process, maybe with another lightwalletd, can lead from its next tick
        // instead of after the TTL.
        let renew = async {
            let mut renewed_at = tokio::time::Instant::now();
            loop {
                tokio::time::sleep(LOCK_RENEW_EVERY).await;
                match self
                    .store
                    .pexpire_if_equal(
                        lock_key(&self.store.chain_prefix()),
                        self.token.clone(),
                        LOCK_TTL_MS,
                    )
                    .await
                {
                    Some(true) => renewed_at = tokio::time::Instant::now(),
                    Some(false) => return "the lock is held by another process",
                    None if renewed_at.elapsed() >= Duration::from_millis(LOCK_TTL_MS) => {
                        return "the lock could not be renewed for its whole TTL"
                    }
                    None => {}
                }
            }
        };
        let outcome = tokio::select! {
            o = self.lead(n, became_leader) => o,
            why = renew => {
                info!(network = %self.network, why, "chain follower: leader work cancelled");
                self.set_leader(false);
                Outcome::Follower
            }
        };
        if let Outcome::Error(e) = &outcome {
            if self.is_leader() {
                debug!(network = %self.network, error = %e, "chain follower: handing the lock over after a failed tick");
                self.store
                    .release_lock(lock_key(&self.store.chain_prefix()), self.token.clone())
                    .await;
                self.set_leader(false);
            }
        }
        outcome
    }

    /// Confirm the indexed tip `tip` (the lightwalletd answered with it, or the leader keeps it
    /// while its lightwalletd is behind): rewrite `tip_seen` under the lock, then refresh the
    /// tip here. False when the lock is held by another process (the caller stops leading). A
    /// store error only skips this confirmation.
    async fn confirm(&self, tip: &Tip) -> bool {
        let chain = self.store.chain_prefix();
        match self
            .store
            .set_if_lock_held(
                lock_key(&chain),
                self.token.clone(),
                LOCK_TTL_MS,
                vec![(
                    tip_seen_key(&chain),
                    encode_unix_ms(unix_ms_now()),
                    INDEX_TTL_SECS,
                )],
            )
            .await
        {
            Some(true) => {
                self.store.tip_cell().set(tip.clone());
                true
            }
            Some(false) => {
                self.lost_lock("tip confirmation");
                false
            }
            None => true,
        }
    }

    /// The leader's part of tick `n`.
    async fn lead(&self, n: u64, became_leader: bool) -> Outcome {
        if became_leader {
            // Continue from the previous leader's index.
            *self.last.lock() = self.read_stored_tip().await;
            *self.backfill_cursor.lock() = None;
            *self.stale.lock() = None;
            self.idle_ticks.store(0, Ordering::Relaxed);
            self.behind_ticks.store(0, Ordering::Relaxed);
        }

        let latest = match self.source.latest().await {
            Ok(t) => t,
            Err(e) => {
                crate::health::record_lwd_reachable(&self.network, false);
                return Outcome::Error(format!("GetLatestBlock: {e}"));
            }
        };
        crate::health::record_lwd_reachable(&self.network, true);
        if latest.height == 0 || latest.hash.is_empty() {
            return Outcome::Error("GetLatestBlock returned an empty tip".to_string());
        }

        let moved_at = self.moved_at_ms.load(Ordering::Relaxed);
        crate::health::record_chain_tip_age(
            &self.network,
            (moved_at > 0).then(|| Duration::from_millis(unix_ms_now().saturating_sub(moved_at))),
        );
        let last = self.last.lock().clone();
        let outcome = match last {
            None => self.index_cold(&latest).await,
            Some(last) if last == latest => {
                let idle = self.idle_ticks.fetch_add(1, Ordering::Relaxed) + 1;
                if idle <= MAX_IDLE_TICKS {
                    if !self.confirm(&last).await {
                        return Outcome::Follower;
                    }
                } else if idle == MAX_IDLE_TICKS + 1 {
                    warn!(network = %self.network, tip = last.height, ticks = idle, "chain follower: lightwalletd keeps answering with the same tip; it is no longer confirmed");
                }
                Ok(Outcome::Idle)
            }
            Some(last) if latest.height > last.height => self.advance(&last, &latest).await,
            Some(last) if latest.height < last.height && self.on_index(&latest).await => {
                // A lightwalletd that is behind (e.g. one of several behind a load-balanced
                // address), not a reorg: keep the tip and the index.
                debug!(network = %self.network, backend = latest.height, tip = last.height, "chain follower: lightwalletd behind the indexed tip");
                let behind = self.behind_ticks.fetch_add(1, Ordering::Relaxed) + 1;
                if behind <= MAX_BEHIND_TICKS {
                    if !self.confirm(&last).await {
                        return Outcome::Follower;
                    }
                } else {
                    warn!(network = %self.network, backend = latest.height, tip = last.height, ticks = behind, "chain follower: lightwalletd stays behind the indexed tip; giving the lock up");
                    self.store
                        .release_lock(lock_key(&self.store.chain_prefix()), self.token.clone())
                        .await;
                    self.set_leader(false);
                    self.cooldown_until
                        .store(n + 1 + BEHIND_COOLDOWN_TICKS, Ordering::Relaxed);
                }
                Ok(Outcome::Behind {
                    backend: latest.height,
                    tip: last.height,
                })
            }
            Some(last) => self.reorg(&last, &latest, latest.height).await,
        };
        if !matches!(outcome, Ok(Outcome::Behind { .. })) {
            self.behind_ticks.store(0, Ordering::Relaxed);
        }
        if !matches!(outcome, Ok(Outcome::Idle)) {
            self.idle_ticks.store(0, Ordering::Relaxed);
        }
        match outcome {
            Ok(o) => {
                if matches!(o, Outcome::Idle) && self.is_leader() {
                    self.backfill_step().await;
                }
                o
            }
            Err(e) => Outcome::Error(e.to_string()),
        }
    }

    /// First tip ever indexed: fetch the tip block, write index and tip, start the backfill.
    async fn index_cold(&self, latest: &Tip) -> Result<Outcome> {
        let blocks = self.source.blocks(latest.height, latest.height).await?;
        let tip = match blocks.last() {
            Some(b) if b.height == Some(latest.height) && !b.hash.is_empty() => Tip {
                height: latest.height,
                hash: b.hash.clone(),
            },
            _ => latest.clone(),
        };
        if !self.store_blocks(&blocks, tip.height).await? {
            return Ok(Outcome::Follower);
        }
        if !self.write_tip(&tip).await? {
            return Ok(Outcome::Follower);
        }
        *self.backfill_cursor.lock() = Some(tip.height.saturating_sub(1));
        Ok(Outcome::Cold { tip: tip.height })
    }

    /// New blocks above the indexed tip.
    async fn advance(&self, last: &Tip, latest: &Tip) -> Result<Outcome> {
        let from = last.height + 1;
        let to = latest.height.min(from + MAX_CATCHUP - 1);
        let blocks = self.source.blocks(from, to).await?;
        if blocks.is_empty() {
            return Ok(Outcome::Idle);
        }
        let first = &blocks[0];
        if first.height != Some(from) {
            anyhow::bail!("GetBlockRange({from},{to}) started at {:?}", first.height);
        }
        if !first.prev_hash.is_empty() && first.prev_hash != last.hash {
            return self.reorg(last, latest, last.height).await;
        }
        if !chained(&blocks) {
            anyhow::bail!("GetBlockRange({from},{to}) is not a chain");
        }
        let new_tip = tip_of(&blocks).unwrap_or_else(|| latest.clone());
        if !self.store_blocks(&blocks, new_tip.height).await? {
            return Ok(Outcome::Follower);
        }
        if !self.write_tip(&new_tip).await? {
            return Ok(Outcome::Follower);
        }
        self.promote_final(last.height, &new_tip).await;
        Ok(Outcome::Advanced {
            from,
            to: new_tip.height,
        })
    }

    /// The chain moved under the index: find the fork point below `from`, invalidate above
    /// it, refetch and rewrite up to `latest`.
    async fn reorg(&self, last: &Tip, latest: &Tip, from: u64) -> Result<Outcome> {
        let chain = self.store.chain_prefix();
        let mut top = from.min(last.height);
        let floor = top.saturating_sub(MAX_WALK_BACK).max(1);
        let mut fork: Option<u64> = None;
        while fork.is_none() && top >= floor {
            let start = top.saturating_sub(WALK_BATCH - 1).max(floor);
            let canonical = self.source.blocks(start, top).await?;
            let heights: Vec<u64> = (start..=top).collect();
            let keys: Vec<String> = heights.iter().map(|h| index_key(&chain, *h)).collect();
            let index = self.store.mget(keys).await;
            for (i, h) in heights.iter().copied().enumerate().rev() {
                let canon = canonical.iter().find(|b| b.height == Some(h));
                match (canon, index.get(i).cloned().flatten()) {
                    // No index entry: nothing cached is validated here; stop.
                    (_, None) => {
                        fork = Some(h);
                        break;
                    }
                    (Some(b), Some(idx)) if b.hash.as_slice() == idx.as_ref() => {
                        fork = Some(h);
                        break;
                    }
                    _ => {}
                }
            }
            if start <= floor {
                break;
            }
            top = start - 1;
        }
        let fork = fork.unwrap_or(floor.saturating_sub(1));
        let depth = last.height.saturating_sub(fork);
        warn!(
            network = %self.network,
            fork,
            depth,
            old_tip = last.height,
            new_tip = latest.height,
            "chain reorg: invalidating above the fork point"
        );
        crate::health::record_chain_reorg(&self.network, depth);

        // Invalidate fork+1 ..= old tip (and anything above, up to the new tip): the index
        // entries and the payload (cached blocks of every pool filter seen, nullifiers, tree
        // states, non-final subtree roots), only while this process still holds the lock: a
        // leader replaced while this tick was in flight must not delete what the one that
        // replaced it wrote. A refusal or a store error stops the tick.
        let upper = last.height.max(latest.height);
        let epoch = self.store.epoch().await;
        let prefix = self.store.key_prefix(epoch);
        let pools = self.pools.all();
        let mut keys = Vec::new();
        for h in fork + 1..=upper {
            keys.push(index_key(&chain, h));
            for p in &pools {
                keys.push(block_key(&prefix, p, h));
            }
            keys.push(crate::cache::height_key(&prefix, "nullifiers", h));
            keys.push(crate::cache::height_key(&prefix, "treestate", h));
        }
        // Non-final subtree roots completing above the fork (and their height pointers).
        keys.extend(crate::subtree_cache::reorg_keys(&*self.store, &prefix, fork + 1, upper).await);
        for chunk in keys.chunks(DELETE_BATCH) {
            match self
                .store
                .del_if_lock_held(lock_key(&chain), self.token.clone(), chunk.to_vec())
                .await
            {
                Some(true) => {}
                Some(false) => {
                    self.lost_lock("reorg invalidation");
                    return Ok(Outcome::Follower);
                }
                None => anyhow::bail!(
                    "reorg invalidation: store error or timeout (after a timeout the outcome is unknown)"
                ),
            }
            if let Some(local) = &self.local {
                for k in chunk {
                    local.invalidate(k);
                }
            }
        }

        // Refetch the canonical chain above the fork and rewrite the index.
        let to = latest.height.min(fork + MAX_CATCHUP + MAX_WALK_BACK);
        let blocks = self.source.blocks(fork + 1, to).await?;
        if !chained(&blocks) {
            anyhow::bail!("GetBlockRange({},{to}) is not a chain", fork + 1);
        }
        let new_tip = tip_of(&blocks).unwrap_or_else(|| latest.clone());
        if !self.store_blocks(&blocks, new_tip.height).await? {
            return Ok(Outcome::Follower);
        }
        if !self.write_tip(&new_tip).await? {
            return Ok(Outcome::Follower);
        }
        self.promote_final(last.height, &new_tip).await;
        Ok(Outcome::Reorg {
            fork,
            depth,
            tip: new_tip.height,
        })
    }

    /// Store `blocks` (pool filter none) and their index entries: final blocks against
    /// `tip_height` go to the permanent tier, the rest to the block cache.
    ///
    /// The index entry and the cache-tier block of every block are written together, in
    /// scripts that write only while this process holds the lock with its own token (the same
    /// fence as the tip, [`Self::write_tip`]), at most [`BLOCK_WRITE_BATCH`] blocks and
    /// [`BLOCK_WRITE_BATCH_BYTES`] of block payload per script (see [`write_batches`]). The
    /// epoch is checked once before (as an epoch-checked write does); while it is not current
    /// only the index is written. Ok(false) when the lock is held by another process (or by
    /// none): this one was replaced while its tick was in flight, so the batch and every later
    /// one are not written and it stops leading; a fetch of another fork that was in flight
    /// cannot overwrite the new leader's index or blocks. Err on a store error or timeout
    /// (after a timeout the script may or may not have run): the tick stops (and hands the lock
    /// over). Final blocks go to the permanent tier after the
    /// fenced batches (they are below any reorg depth).
    async fn store_blocks(&self, blocks: &[FetchedBlock], tip_height: u64) -> Result<bool> {
        let chain = self.store.chain_prefix();
        let epoch = self.store.epoch().await;
        let prefix = self.store.key_prefix(epoch);
        let blocks_current = self.store.epoch_current(epoch).await == Some(true);
        let mut permanent: Vec<(String, Bytes)> = Vec::new();
        let usable: Vec<&FetchedBlock> = blocks
            .iter()
            .filter(|b| b.height.is_some() && !b.hash.is_empty())
            .collect();
        // The payload a block adds to its script: nothing when it goes to the permanent tier
        // or is not written (only its index entry is).
        let payload = |b: &&FetchedBlock| match b.height {
            Some(h) if blocks_current && !self.permanent_height(h, tip_height) => b.message().len(),
            _ => 0,
        };
        let sizes: Vec<usize> = usable.iter().map(payload).collect();
        for range in write_batches(&sizes, BLOCK_WRITE_BATCH, BLOCK_WRITE_BATCH_BYTES) {
            let batch = &usable[range];
            let mut entries: Vec<(String, Bytes, u64)> = Vec::with_capacity(batch.len() * 2);
            let mut cached: Vec<(String, Bytes)> = Vec::new();
            for b in batch {
                let Some(h) = b.height else { continue };
                entries.push((
                    index_key(&chain, h),
                    Bytes::from(b.hash.clone()),
                    INDEX_TTL_SECS,
                ));
                if self.permanent_height(h, tip_height) {
                    permanent.push((permanent_block_key(&self.network, "", h), b.message()));
                } else if blocks_current {
                    let bk = block_key(&prefix, "", h);
                    entries.push((bk.clone(), b.message(), 0));
                    cached.push((bk, b.message()));
                }
            }
            match self
                .store
                .set_if_lock_held(lock_key(&chain), self.token.clone(), LOCK_TTL_MS, entries)
                .await
            {
                Some(true) => {}
                Some(false) => {
                    self.lost_lock("block write");
                    return Ok(false);
                }
                None => anyhow::bail!(
                    "fenced block write: store error or timeout (after a timeout the outcome is unknown)"
                ),
            }
            if let Some(local) = &self.local {
                for (k, v) in cached {
                    local.insert(k, v);
                }
            }
        }
        if let (Some(perm), false) = (&self.permanent, permanent.is_empty()) {
            if let Some(local) = &self.local {
                for (k, v) in &permanent {
                    local.insert(k.clone(), v.clone());
                }
            }
            let n = permanent.len() as u64;
            if perm.set_many(permanent).await {
                crate::health::record_block_permanent(&self.network, "stored", n);
            }
        }
        crate::health::record_upstream_blocks(&self.network, blocks.len() as u64);
        Ok(true)
    }

    /// A fenced write found the lock held by another process (or by none): stop leading.
    fn lost_lock(&self, what: &str) {
        info!(network = %self.network, what, "chain follower: the lock is no longer held, write refused");
        self.set_leader(false);
    }

    /// Move the blocks that became final with the advance from `old_tip` to `new_tip` from the
    /// cache Redis to the permanent tier: every pool filter seen, only entries whose hash
    /// matches the index. Missing entries are left to write-through.
    async fn promote_final(&self, old_tip: u64, new_tip: &Tip) {
        let Some(perm) = self.permanent.as_ref().filter(|p| p.writable()) else {
            return;
        };
        let Some(hi) = new_tip.height.checked_sub(PERMANENT_DEPTH) else {
            return;
        };
        let lo = (old_tip + 1)
            .saturating_sub(PERMANENT_DEPTH)
            .max(self.permanent_min_height)
            .max(1);
        if lo > hi {
            return;
        }
        let heights: Vec<u64> = (lo..=hi).collect();
        let epoch = self.store.epoch().await;
        let prefix = self.store.key_prefix(epoch);
        let chain = self.store.chain_prefix();
        let index = self
            .store
            .mget(heights.iter().map(|h| index_key(&chain, *h)).collect())
            .await;
        let mut moved = 0u64;
        for pool in self.pools.all() {
            let keys: Vec<String> = heights
                .iter()
                .map(|h| block_key(&prefix, &pool, *h))
                .collect();
            let values = self.store.mget(keys.clone()).await;
            let mut entries = Vec::new();
            let mut drop = Vec::new();
            for (i, h) in heights.iter().copied().enumerate() {
                let (Some(bytes), Some(canonical)) = (
                    values.get(i).cloned().flatten(),
                    index.get(i).cloned().flatten(),
                ) else {
                    continue;
                };
                let block = FetchedBlock::from_frame(grpc_frame(&bytes));
                if block.height != Some(h) || block.hash.as_slice() != canonical.as_ref() {
                    continue;
                }
                entries.push((permanent_block_key(&self.network, &pool, h), bytes));
                drop.push(keys[i].clone());
            }
            if entries.is_empty() {
                continue;
            }
            let n = entries.len() as u64;
            if perm.set_many(entries).await {
                moved += n;
                if let Some(local) = &self.local {
                    for k in &drop {
                        local.invalidate(k);
                    }
                }
                self.store.del(drop).await;
            }
        }
        if moved > 0 {
            crate::health::record_block_permanent(&self.network, "promoted", moved);
            debug!(network = %self.network, lo, hi, moved, "final blocks moved to the permanent tier");
        }
    }

    /// Whether `tip` (a lower height than the indexed tip) is a block of the indexed chain.
    async fn on_index(&self, tip: &Tip) -> bool {
        if tip.hash.is_empty() {
            return false;
        }
        let key = index_key(&self.store.chain_prefix(), tip.height);
        self.store
            .mget(vec![key])
            .await
            .into_iter()
            .next()
            .flatten()
            .is_some_and(|h| h.as_ref() == tip.hash.as_slice())
    }

    /// Store `tip`, when it moved and that it is confirmed, only while this process holds the
    /// lock. Ok(false) when it does not any more (replaced by another process during this
    /// tick): it stops leading and leaves the stored tip alone. Err when the store did not
    /// answer: the tick stops (the tip is not taken over in memory either).
    async fn write_tip(&self, tip: &Tip) -> Result<bool> {
        let chain = self.store.chain_prefix();
        let now = unix_ms_now();
        let written = self
            .store
            .set_if_lock_held(
                lock_key(&chain),
                self.token.clone(),
                LOCK_TTL_MS,
                vec![
                    (tip_key(&chain), encode_tip(tip), INDEX_TTL_SECS),
                    (tip_at_key(&chain), encode_unix_ms(now), INDEX_TTL_SECS),
                    (tip_seen_key(&chain), encode_unix_ms(now), INDEX_TTL_SECS),
                ],
            )
            .await;
        match written {
            Some(true) => {}
            Some(false) => {
                warn!(network = %self.network, height = tip.height, "chain follower lost the leader lock during this tick: tip not written");
                self.set_leader(false);
                return Ok(false);
            }
            None => anyhow::bail!(
                "tip write: store error or timeout (after a timeout the outcome is unknown)"
            ),
        }
        self.moved_at_ms.store(now, Ordering::Relaxed);
        *self.last.lock() = Some(tip.clone());
        self.notify_new_block(tip);
        Ok(true)
    }

    /// Fill index gaps inside the window, one batch per idle tick.
    async fn backfill_step(&self) {
        let (cursor, tip) = {
            let c = *self.backfill_cursor.lock();
            let Some(c) = c else { return };
            let Some(t) = self.last.lock().clone() else {
                return;
            };
            (c, t.height)
        };
        let low_bound = tip.saturating_sub(INDEX_WINDOW).max(1);
        if cursor < low_bound {
            *self.backfill_cursor.lock() = None;
            info!(network = %self.network, "chain index backfill done");
            return;
        }
        let start = cursor.saturating_sub(BACKFILL_BATCH - 1).max(low_bound);
        let chain = self.store.chain_prefix();
        let keys: Vec<String> = (start..=cursor).map(|h| index_key(&chain, h)).collect();
        let present = self.store.mget(keys).await;
        // Missing heights, grouped into maximal contiguous runs.
        let mut runs: Vec<(u64, u64)> = Vec::new();
        for (i, h) in (start..=cursor).enumerate() {
            if present.get(i).map(|v| v.is_some()).unwrap_or(false) {
                continue;
            }
            match runs.last_mut() {
                Some((_, e)) if *e + 1 == h => *e = h,
                _ => runs.push((h, h)),
            }
        }
        for (s, e) in runs {
            match self.source.blocks(s, e).await {
                Ok(blocks) => {
                    debug!(network = %self.network, start = s, end = e, n = blocks.len(), "chain index backfill");
                    match self.store_blocks(&blocks, tip).await {
                        Ok(true) => {}
                        Ok(false) => return,
                        Err(err) => {
                            warn!(network = %self.network, error = %err, "chain index backfill write failed");
                            return;
                        }
                    }
                }
                Err(err) => {
                    warn!(network = %self.network, start = s, end = e, error = %err, "chain index backfill fetch failed");
                    return;
                }
            }
        }
        *self.backfill_cursor.lock() = Some(start.saturating_sub(1));
    }
}

/// Split items of `sizes` bytes into consecutive batches of at most `max_items` items and
/// `max_bytes` bytes each; an item larger than `max_bytes` is a batch of its own.
fn write_batches(
    sizes: &[usize],
    max_items: usize,
    max_bytes: usize,
) -> Vec<std::ops::Range<usize>> {
    let mut batches = Vec::new();
    let (mut start, mut bytes) = (0, 0usize);
    for (i, size) in sizes.iter().enumerate() {
        if i > start && (i - start >= max_items || bytes.saturating_add(*size) > max_bytes) {
            batches.push(start..i);
            start = i;
            bytes = 0;
        }
        bytes = bytes.saturating_add(*size);
    }
    if start < sizes.len() {
        batches.push(start..sizes.len());
    }
    batches
}

/// Whether consecutive blocks chain (`prev_hash` of each equals the hash of the previous and the
/// heights are consecutive). A pair where either hash is empty is not checked.
pub fn chained(blocks: &[FetchedBlock]) -> bool {
    blocks.windows(2).all(|w| {
        w[0].hash.is_empty()
            || w[1].prev_hash.is_empty()
            || (w[1].prev_hash == w[0].hash && w[1].height == w[0].height.map(|h| h + 1))
    })
}

fn tip_of(blocks: &[FetchedBlock]) -> Option<Tip> {
    let b = blocks.last()?;
    Some(Tip {
        height: b.height?,
        hash: b.hash.clone(),
    })
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::block_cache::test_support::FakeChain;
    use crate::block_cache::{grpc_frame, FetchedBlock};

    /// The fake lightwalletd's chain view as a `ChainSource`.
    pub struct FakeChainSource(pub Arc<FakeChain>);

    impl ChainSource for FakeChainSource {
        fn latest(&self) -> BoxFuture<'static, Result<Tip>> {
            let c = self.0.clone();
            Box::pin(async move {
                c.latest_calls.fetch_add(1, Ordering::SeqCst);
                if c.down.load(Ordering::SeqCst) {
                    anyhow::bail!("lwd down");
                }
                let tip = c.tip();
                Ok(Tip {
                    height: tip,
                    hash: c.hash_at(tip),
                })
            })
        }
        fn blocks(&self, start: u64, end: u64) -> BoxFuture<'static, Result<Vec<FetchedBlock>>> {
            let c = self.0.clone();
            Box::pin(async move {
                c.range_calls.lock().unwrap().push((start, end));
                let delay = c.blocks_delay_ms.load(Ordering::SeqCst);
                if delay > 0 {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                if c.down.load(Ordering::SeqCst) {
                    anyhow::bail!("lwd down");
                }
                let tip = c.tip();
                Ok((start..=end.min(tip))
                    .map(|h| FetchedBlock::from_frame(grpc_frame(&c.msg(h))))
                    .collect())
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::block_cache::test_support::{hash_at, FakeChain};
    use crate::store::test_support::{MemPermanent, MemStore};

    fn follower(
        store: Arc<MemStore>,
        chain: Arc<FakeChain>,
        local: Option<Arc<LocalCache>>,
    ) -> Arc<ChainFollower> {
        Arc::new(ChainFollower::new(
            store,
            Arc::new(FakeChainSource(chain)),
            local,
            Arc::new(PoolKeys::default()),
            "testnet".to_string(),
        ))
    }

    #[tokio::test]
    async fn leader_writes_final_blocks_permanently_and_promotes_on_advance() {
        let store = Arc::new(MemStore::default());
        let perm = Arc::new(MemPermanent::default());
        let chain = Arc::new(FakeChain::new(1000));
        let local = Arc::new(LocalCache::new(1 << 20, "testnet".to_string()));
        let f = Arc::new(
            ChainFollower::new(
                store.clone(),
                Arc::new(FakeChainSource(chain.clone())),
                Some(local.clone()),
                Arc::new(PoolKeys::default()),
                "testnet".to_string(),
            )
            .with_permanent(perm.clone(), 500),
        );
        let prefix = store.key_prefix(42);
        assert_eq!(f.tick().await, Outcome::Cold { tip: 1000 });
        // The idle tick backfills 900..=999: 900 is final (depth 100) -> permanent, 901.. cache.
        assert_eq!(f.tick().await, Outcome::Idle);
        assert_eq!(
            perm.get(&permanent_block_key("testnet", "", 900)),
            Some(Bytes::from(chain.msg(900)))
        );
        assert_eq!(store.get(&block_key(&prefix, "", 900)), None);
        assert_eq!(perm.get(&permanent_block_key("testnet", "", 901)), None);
        assert!(store.get(&block_key(&prefix, "", 901)).is_some());
        assert!(local
            .get(&permanent_block_key("testnet", "", 900))
            .is_some());
        // Advance by one: 901 becomes final and is moved.
        chain.set_tip(1001);
        assert_eq!(
            f.tick().await,
            Outcome::Advanced {
                from: 1001,
                to: 1001
            }
        );
        assert_eq!(
            perm.get(&permanent_block_key("testnet", "", 901)),
            Some(Bytes::from(chain.msg(901)))
        );
        assert_eq!(
            store.get(&block_key(&prefix, "", 901)),
            None,
            "moved, not copied"
        );
        assert_eq!(local.get(&block_key(&prefix, "", 901)), None);
        assert!(
            store.get(&block_key(&prefix, "", 902)).is_some(),
            "902 not final yet"
        );
        // Advance by several: 902..=905 move; the second idle backfill tick (800..=899, all
        // final) goes straight to the permanent tier.
        chain.set_tip(1005);
        assert!(matches!(f.tick().await, Outcome::Advanced { to: 1005, .. }));
        for h in 902..=905 {
            assert!(
                perm.get(&permanent_block_key("testnet", "", h)).is_some(),
                "{h}"
            );
            assert_eq!(store.get(&block_key(&prefix, "", h)), None, "{h}");
        }
        assert!(perm.get(&permanent_block_key("testnet", "", 906)).is_none());
        assert_eq!(f.tick().await, Outcome::Idle);
        assert!(perm.get(&permanent_block_key("testnet", "", 850)).is_some());
        assert_eq!(store.get(&block_key(&prefix, "", 850)), None);
        // Below the floor: cache tier (idle ticks reach 400..=499 eventually).
        for _ in 0..4 {
            assert_eq!(f.tick().await, Outcome::Idle);
        }
        assert!(perm.get(&permanent_block_key("testnet", "", 450)).is_none());
        assert!(store.get(&block_key(&prefix, "", 450)).is_some());
        // Index entries exist for everything, whichever tier.
        assert_eq!(index_of(&store, 900), Some(hash_at(900, 0)));
        assert_eq!(index_of(&store, 450), Some(hash_at(450, 0)));
    }

    fn index_of(store: &MemStore, h: u64) -> Option<Vec<u8>> {
        store
            .get(&index_key(&store.chain_prefix(), h))
            .map(|b| b.to_vec())
    }

    #[tokio::test]
    async fn cold_start_indexes_tip_then_backfills_the_window() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(1500));
        let f = follower(store.clone(), chain.clone(), None);
        assert_eq!(f.tick().await, Outcome::Cold { tip: 1500 });
        assert!(f.is_leader());
        assert_eq!(index_of(&store, 1500), Some(hash_at(1500, 0)));
        assert_eq!(f.tip().unwrap().height, 1500);
        assert_eq!(store.tip.get().unwrap().hash, hash_at(1500, 0));
        // The tip block is in the block cache.
        assert_eq!(
            store.get(&block_key(&store.key_prefix(42), "", 1500)),
            Some(Bytes::from(chain.msg(1500)))
        );
        // Idle ticks backfill 100 heights each until tip - INDEX_WINDOW.
        for _ in 0..12 {
            assert_eq!(f.tick().await, Outcome::Idle);
        }
        assert_eq!(index_of(&store, 1499), Some(hash_at(1499, 0)));
        assert_eq!(index_of(&store, 500), Some(hash_at(500, 0)));
        assert_eq!(index_of(&store, 499), None, "below the window");
        // Backfill fetched each missing height once, as whole batches.
        let calls = chain.range_calls.lock().unwrap().clone();
        assert!(calls.contains(&(1400, 1499)), "{calls:?}");
        assert!(calls.contains(&(500, 599)), "{calls:?}");
        assert_eq!(calls.len(), 11, "{calls:?}");
        // Backfill does not refetch what is present.
        assert_eq!(f.tick().await, Outcome::Idle);
        assert_eq!(chain.range_calls.lock().unwrap().len(), 11);
    }

    #[tokio::test]
    async fn advance_fetches_new_blocks_once_and_notifies() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(1000));
        let f = follower(store.clone(), chain.clone(), None);
        struct Seen(std::sync::Mutex<Vec<u64>>);
        impl BlockListener for Seen {
            fn on_new_block(&self, tip: &Tip) {
                self.0.lock().unwrap().push(tip.height);
            }
        }
        let seen = Arc::new(Seen(std::sync::Mutex::new(vec![])));
        f.add_listener(seen.clone());
        assert_eq!(f.tick().await, Outcome::Cold { tip: 1000 });
        chain.set_tip(1003);
        assert_eq!(
            f.tick().await,
            Outcome::Advanced {
                from: 1001,
                to: 1003
            }
        );
        assert_eq!(f.tick().await, Outcome::Idle);
        for h in 1001..=1003 {
            assert_eq!(index_of(&store, h), Some(hash_at(h, 0)));
            assert!(store
                .get(&block_key(&store.key_prefix(42), "", h))
                .is_some());
        }
        assert_eq!(*seen.0.lock().unwrap(), vec![1000, 1003]);
        let calls = chain.range_calls.lock().unwrap().clone();
        assert_eq!(&calls[..2], &[(1000, 1000), (1001, 1003)]);
    }

    #[tokio::test]
    async fn reorg_of_depth_three_rewrites_the_index_and_drops_cached_entries() {
        let store = Arc::new(MemStore::default());
        let local = Arc::new(LocalCache::new(1 << 20, "testnet".to_string()));
        let chain = Arc::new(FakeChain::new(2000));
        let f = follower(store.clone(), chain.clone(), Some(local.clone()));
        assert_eq!(f.tick().await, Outcome::Cold { tip: 2000 });
        chain.set_tip(2010);
        assert_eq!(
            f.tick().await,
            Outcome::Advanced {
                from: 2001,
                to: 2010
            }
        );
        let prefix = store.key_prefix(42);
        // Cached answers at the heights about to be replaced.
        store.put(
            &crate::cache::height_key(&prefix, "treestate", 2009),
            b"ts".to_vec(),
        );
        store.put(
            &crate::cache::height_key(&prefix, "nullifiers", 2008),
            b"nf".to_vec(),
        );
        local.insert(block_key(&prefix, "", 2010), Bytes::from_static(b"x"));
        assert!(local.get(&block_key(&prefix, "", 2010)).is_some());
        // A non-final subtree root completing at 2009 (entry + height pointer) and one at 2005.
        store.put(
            &crate::subtree_cache::subtree_key(&prefix, 1, 7),
            b"root".to_vec(),
        );
        store.put(
            &crate::subtree_cache::subtree_at_key(&prefix, 1, 2009),
            7u32.to_be_bytes().to_vec(),
        );
        store.put(
            &crate::subtree_cache::subtree_key(&prefix, 0, 3),
            b"root".to_vec(),
        );
        store.put(
            &crate::subtree_cache::subtree_at_key(&prefix, 0, 2005),
            3u32.to_be_bytes().to_vec(),
        );

        // Fork: heights 2008..=2010 replaced, same tip height.
        chain.reorg_from(2008, 1);
        assert_eq!(
            f.tick().await,
            Outcome::Reorg {
                fork: 2007,
                depth: 3,
                tip: 2010
            }
        );
        for h in 2008..=2010 {
            assert_eq!(index_of(&store, h), Some(hash_at(h, 1)), "{h}");
            assert_eq!(
                store.get(&block_key(&prefix, "", h)),
                Some(Bytes::from(chain.msg(h))),
                "{h}"
            );
        }
        assert_eq!(index_of(&store, 2007), Some(hash_at(2007, 0)));
        assert!(store
            .get(&crate::cache::height_key(&prefix, "treestate", 2009))
            .is_none());
        assert!(store
            .get(&crate::cache::height_key(&prefix, "nullifiers", 2008))
            .is_none());
        assert!(store
            .get(&crate::subtree_cache::subtree_key(&prefix, 1, 7))
            .is_none());
        assert!(store
            .get(&crate::subtree_cache::subtree_at_key(&prefix, 1, 2009))
            .is_none());
        assert!(
            store
                .get(&crate::subtree_cache::subtree_key(&prefix, 0, 3))
                .is_some(),
            "a root completing below the fork stays"
        );
        assert_eq!(
            local.get(&block_key(&prefix, "", 2010)),
            Some(Bytes::from(chain.msg(2010))),
            "local copy replaced by the canonical block"
        );
        assert_eq!(store.tip.get().unwrap().hash, hash_at(2010, 1));
        assert_eq!(f.tick().await, Outcome::Idle);
    }

    #[tokio::test]
    async fn reorg_to_a_lower_tip_and_then_forward() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(3000));
        let f = follower(store.clone(), chain.clone(), None);
        f.tick().await;
        chain.set_tip(3005);
        f.tick().await;
        // The new chain is one block shorter: 3004..=3005 replaced by 3004'.
        chain.reorg_from(3004, 2);
        chain.set_tip(3004);
        assert_eq!(
            f.tick().await,
            Outcome::Reorg {
                fork: 3003,
                depth: 2,
                tip: 3004
            }
        );
        assert_eq!(index_of(&store, 3004), Some(hash_at(3004, 2)));
        assert_eq!(index_of(&store, 3005), None);
        chain.set_tip(3006);
        assert_eq!(
            f.tick().await,
            Outcome::Advanced {
                from: 3005,
                to: 3006
            }
        );
        assert_eq!(index_of(&store, 3005), Some(hash_at(3005, 2)));
    }

    #[tokio::test]
    async fn upstream_failure_keeps_the_index_and_marks_the_error() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(100));
        let f = follower(store.clone(), chain.clone(), None);
        f.tick().await;
        chain.down.store(true, Ordering::SeqCst);
        assert!(matches!(f.tick().await, Outcome::Error(_)));
        assert_eq!(index_of(&store, 100), Some(hash_at(100, 0)));
        chain.down.store(false, Ordering::SeqCst);
        assert_eq!(f.tick().await, Outcome::Idle);
    }

    #[tokio::test(start_paused = true)]
    async fn second_follower_takes_over_after_the_lock_ttl() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(500));
        let a = follower(store.clone(), chain.clone(), None);
        let b = follower(store.clone(), chain.clone(), None);
        assert_eq!(a.tick().await, Outcome::Cold { tip: 500 });
        assert_eq!(b.tick().await, Outcome::Follower);
        assert!(!b.is_leader());
        // b follows a's tip from the store.
        assert_eq!(b.tip().unwrap().height, 500);
        // a keeps renewing: b never gets the lock.
        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(4)).await;
            assert_eq!(a.tick().await, Outcome::Idle);
            assert_eq!(b.tick().await, Outcome::Follower);
        }
        // a dies (stops ticking); after the TTL b acquires the lock and continues the index.
        tokio::time::advance(Duration::from_millis(LOCK_TTL_MS + 100)).await;
        chain.set_tip(502);
        assert_eq!(b.tick().await, Outcome::Advanced { from: 501, to: 502 });
        assert!(b.is_leader());
        assert_eq!(index_of(&store, 502), Some(hash_at(502, 0)));
        // a comes back: it is a follower now and reads b's tip.
        assert_eq!(a.tick().await, Outcome::Follower);
        assert!(!a.is_leader());
        assert_eq!(a.tip().unwrap().height, 502);
    }

    #[tokio::test(start_paused = true)]
    async fn redis_outage_demotes_the_leader_and_recovers() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(700));
        let f = follower(store.clone(), chain.clone(), None);
        f.tick().await;
        assert!(f.is_leader());
        store.down.store(true, Ordering::SeqCst);
        assert_eq!(f.tick().await, Outcome::Follower);
        assert!(!f.is_leader());
        store.down.store(false, Ordering::SeqCst);
        chain.set_tip(701);
        // Its own old lock still stands: a follower until it lapses.
        assert_eq!(f.tick().await, Outcome::Follower);
        tokio::time::advance(Duration::from_millis(LOCK_TTL_MS + 100)).await;
        // Back as leader, continuing from the stored tip.
        assert_eq!(f.tick().await, Outcome::Advanced { from: 701, to: 701 });
    }

    /// Two processes on one store, each with its own lightwalletd view.
    fn pair(
        store: &Arc<MemStore>,
        leader_chain: &Arc<FakeChain>,
        follower_chain: &Arc<FakeChain>,
    ) -> (Arc<ChainFollower>, Arc<ChainFollower>) {
        let make = |chain: &Arc<FakeChain>| {
            Arc::new(
                ChainFollower::new(
                    store.clone(),
                    Arc::new(FakeChainSource(chain.clone())),
                    None,
                    Arc::new(PoolKeys::default()),
                    "testnet".to_string(),
                )
                .with_stale_after(Duration::from_millis(1)),
            )
        };
        (make(leader_chain), make(follower_chain))
    }

    /// Let the stored tip age past the 1 ms bound (wall clock, not the paused tokio clock).
    fn age_the_tip() {
        std::thread::sleep(Duration::from_millis(5));
    }

    #[tokio::test(start_paused = true)]
    async fn a_follower_takes_over_a_leader_whose_tip_stopped_moving() {
        let store = Arc::new(MemStore::default());
        // The leader's lightwalletd is stuck at 1000; the follower's moves on.
        let stuck = Arc::new(FakeChain::new(1000));
        let live = Arc::new(FakeChain::new(1000));
        let (leader, follower) = pair(&store, &stuck, &live);
        assert_eq!(leader.tick().await, Outcome::Cold { tip: 1000 });
        live.set_tip(1006);
        age_the_tip();

        // First probe: its own tip is served at once, no takeover yet.
        assert_eq!(
            follower.tick().await,
            Outcome::StaleLeader {
                from: 1000,
                to: 1006,
                took_over: false
            }
        );
        assert_eq!(follower.tip().unwrap().height, 1006);
        // Between probes it keeps serving that tip, never the older stored one.
        for _ in 1..STALE_PROBE_EVERY {
            assert_eq!(follower.tick().await, Outcome::Follower);
            assert_eq!(follower.tip().unwrap().height, 1006);
            assert_eq!(leader.tick().await, Outcome::Idle);
        }
        // Second probe, still ahead: it takes the lock over and continues the index in the
        // same tick.
        assert_eq!(
            follower.tick().await,
            Outcome::Advanced {
                from: 1001,
                to: 1006
            }
        );
        assert!(follower.is_leader());
        assert_eq!(index_of(&store, 1006), Some(hash_at(1006, 0)));
        // A tick of the old leader that was in flight during the takeover cannot move the
        // stored tip back: its write is refused and it stops leading.
        let stale_tip = Tip {
            height: 1000,
            hash: hash_at(1000, 0),
        };
        assert!(!leader.write_tip(&stale_tip).await.unwrap());
        assert!(!leader.is_leader());
        assert_eq!(
            store
                .get(&tip_key(&store.chain_prefix()))
                .and_then(|b| decode_tip(&b))
                .map(|t| t.height),
            Some(1006)
        );
        // The old leader follows and does not take the lock back: its own lightwalletd is
        // behind the stored tip.
        assert_eq!(leader.tick().await, Outcome::Follower);
        assert!(!leader.is_leader());
        assert_eq!(leader.tip().unwrap().height, 1006);
        age_the_tip();
        for _ in 0..(2 * STALE_PROBE_EVERY) {
            assert_eq!(leader.tick().await, Outcome::Follower);
        }
        assert!(follower.is_leader());
    }

    #[tokio::test(start_paused = true)]
    async fn an_unmoved_tip_is_kept_when_no_lightwalletd_is_ahead() {
        let store = Arc::new(MemStore::default());
        let a = Arc::new(FakeChain::new(2000));
        let b = Arc::new(FakeChain::new(2000));
        let (leader, follower) = pair(&store, &a, &b);
        assert_eq!(leader.tick().await, Outcome::Cold { tip: 2000 });
        age_the_tip();
        // No new block anywhere (a slow block): nothing to take over, the stored tip is served.
        for _ in 0..(2 * STALE_PROBE_EVERY + 1) {
            assert_eq!(follower.tick().await, Outcome::Follower);
            assert_eq!(follower.tip().unwrap().height, 2000);
        }
        assert!(leader.tick().await == Outcome::Idle && leader.is_leader());
        // The leader moves the tip again before a second probe: no takeover either.
        b.set_tip(2003);
        assert!(matches!(
            follower.tick().await,
            Outcome::Follower
                | Outcome::StaleLeader {
                    took_over: false,
                    ..
                }
        ));
        a.set_tip(2003);
        assert_eq!(
            leader.tick().await,
            Outcome::Advanced {
                from: 2001,
                to: 2003
            }
        );
        for _ in 0..(2 * STALE_PROBE_EVERY) {
            assert_eq!(follower.tick().await, Outcome::Follower);
        }
        assert!(leader.is_leader());
        assert_eq!(follower.tip().unwrap().height, 2003);
    }

    #[tokio::test(start_paused = true)]
    async fn a_takeover_needs_the_same_unmoved_tip_on_both_probes() {
        let store = Arc::new(MemStore::default());
        let slow = Arc::new(FakeChain::new(3000));
        let fast = Arc::new(FakeChain::new(3000));
        let (leader, follower) = pair(&store, &slow, &fast);
        leader.tick().await;
        fast.set_tip(3004);
        age_the_tip();
        assert!(matches!(
            follower.tick().await,
            Outcome::StaleLeader {
                took_over: false,
                ..
            }
        ));
        // The leader moves a little (its lightwalletd is slow, not stuck).
        slow.set_tip(3001);
        assert_eq!(
            leader.tick().await,
            Outcome::Advanced {
                from: 3001,
                to: 3001
            }
        );
        age_the_tip();
        for _ in 1..STALE_PROBE_EVERY {
            follower.tick().await;
        }
        // A new stored tip: a first sighting again, not a takeover.
        assert_eq!(
            follower.tick().await,
            Outcome::StaleLeader {
                from: 3001,
                to: 3004,
                took_over: false
            }
        );
        assert!(leader.is_leader() && !follower.is_leader());
    }

    #[tokio::test(start_paused = true)]
    async fn a_lagging_lightwalletd_is_not_a_reorg() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(4000));
        let f = follower(store.clone(), chain.clone(), None);
        assert_eq!(f.tick().await, Outcome::Cold { tip: 4000 });
        // Fill the index window below the tip.
        assert_eq!(f.tick().await, Outcome::Idle);
        // A lightwalletd behind on the same chain answers.
        chain.set_tip(3995);
        assert_eq!(
            f.tick().await,
            Outcome::Behind {
                backend: 3995,
                tip: 4000
            }
        );
        assert_eq!(f.tip().unwrap().height, 4000);
        assert_eq!(index_of(&store, 4000), Some(hash_at(4000, 0)));
        // A lower tip off the indexed chain is still a reorg.
        chain.reorg_from(3990, 1);
        assert!(matches!(f.tick().await, Outcome::Reorg { .. }));
    }

    #[tokio::test(start_paused = true)]
    async fn the_leader_stores_when_it_moved_the_tip() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(5000));
        let f = follower(store.clone(), chain.clone(), None);
        let before = unix_ms_now();
        f.tick().await;
        let at = store
            .get(&tip_at_key(&store.chain_prefix()))
            .and_then(|b| decode_unix_ms(&b))
            .unwrap();
        assert!(at >= before && at <= unix_ms_now());
        // Unchanged while idle.
        f.tick().await;
        assert_eq!(
            store
                .get(&tip_at_key(&store.chain_prefix()))
                .and_then(|b| decode_unix_ms(&b)),
            Some(at)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn final_blocks_stay_in_the_cache_tier_while_the_permanent_tier_is_a_replica() {
        let store = Arc::new(MemStore::default());
        let perm = Arc::new(MemPermanent::default());
        perm.replica.store(true, Ordering::SeqCst);
        let chain = Arc::new(FakeChain::new(1000));
        let f = Arc::new(
            ChainFollower::new(
                store.clone(),
                Arc::new(FakeChainSource(chain.clone())),
                None,
                Arc::new(PoolKeys::default()),
                "testnet".to_string(),
            )
            .with_permanent(perm.clone(), 500),
        );
        let prefix = store.key_prefix(42);
        assert_eq!(f.tick().await, Outcome::Cold { tip: 1000 });
        assert_eq!(f.tick().await, Outcome::Idle);
        chain.set_tip(1001);
        assert!(matches!(f.tick().await, Outcome::Advanced { .. }));
        assert_eq!(
            perm.writes.load(Ordering::SeqCst),
            0,
            "no write to a replica"
        );
        // The final block 900 is in the cache tier instead, and still there after the advance.
        assert!(store.get(&block_key(&prefix, "", 900)).is_some());
        assert!(store.get(&block_key(&prefix, "", 901)).is_some());
        // Promoted to a primary: final blocks go to the permanent tier again.
        perm.replica.store(false, Ordering::SeqCst);
        chain.set_tip(1002);
        assert!(matches!(f.tick().await, Outcome::Advanced { .. }));
        assert!(perm.get(&permanent_block_key("testnet", "", 902)).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn a_leader_tick_longer_than_the_lock_ttl_keeps_the_lock_and_writes() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(6000));
        let a = follower(store.clone(), chain.clone(), None);
        let b = follower(store.clone(), chain.clone(), None);
        assert_eq!(a.tick().await, Outcome::Cold { tip: 6000 });
        // A slow catch-up: the block fetch takes three lock TTLs; the other process ticks
        // meanwhile.
        chain.set_tip(6010);
        chain
            .blocks_delay_ms
            .store(3 * LOCK_TTL_MS, Ordering::SeqCst);
        let other = async {
            let mut outcomes = Vec::new();
            for _ in 0..12 {
                tokio::time::sleep(POLL_INTERVAL).await;
                outcomes.push(b.tick().await);
            }
            outcomes
        };
        let (outcome, others) = tokio::join!(a.tick(), other);
        assert_eq!(
            outcome,
            Outcome::Advanced {
                from: 6001,
                to: 6010
            }
        );
        assert!(a.is_leader() && !b.is_leader());
        assert!(others.iter().all(|o| *o == Outcome::Follower), "{others:?}");
        assert_eq!(
            store
                .get(&tip_key(&store.chain_prefix()))
                .and_then(|b| decode_tip(&b))
                .map(|t| t.height),
            Some(6010)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_leader_tick_hands_the_lock_over() {
        let store = Arc::new(MemStore::default());
        let broken = Arc::new(FakeChain::new(7000));
        let fine = Arc::new(FakeChain::new(7000));
        let (a, b) = pair(&store, &broken, &fine);
        assert_eq!(a.tick().await, Outcome::Cold { tip: 7000 });
        broken.down.store(true, Ordering::SeqCst);
        assert!(matches!(a.tick().await, Outcome::Error(_)));
        assert!(!a.is_leader());
        // The other process leads from its next tick, not after the TTL.
        fine.set_tip(7002);
        assert_eq!(
            b.tick().await,
            Outcome::Advanced {
                from: 7001,
                to: 7002
            }
        );
        assert!(b.is_leader());
    }

    fn stored_tip(store: &MemStore) -> Option<u64> {
        store
            .get(&tip_key(&store.chain_prefix()))
            .and_then(|b| decode_tip(&b))
            .map(|t| t.height)
    }

    #[tokio::test(start_paused = true)]
    async fn a_displaced_leader_with_a_fetch_in_flight_writes_no_index() {
        let store = Arc::new(MemStore::default());
        // The leader's lightwalletd is stuck at 1000 and then answers with another fork above
        // it, slowly; the follower's is ahead on the canonical chain.
        let stuck = Arc::new(FakeChain::new(1000));
        let live = Arc::new(FakeChain::new(1000));
        let (leader, follower) = pair(&store, &stuck, &live);
        assert_eq!(leader.tick().await, Outcome::Cold { tip: 1000 });
        live.set_tip(1006);
        age_the_tip();
        assert!(matches!(
            follower.tick().await,
            Outcome::StaleLeader {
                took_over: false,
                ..
            }
        ));
        // The leader's next tick fetches fork-1 blocks 1001..=1003 for 20 s; meanwhile the
        // follower's second probe takes the lock over and indexes the canonical chain.
        stuck.reorg_from(1001, 1);
        stuck.set_tip(1003);
        stuck.blocks_delay_ms.store(20_000, Ordering::SeqCst);
        let other = async {
            let mut outcomes = Vec::new();
            for _ in 1..=STALE_PROBE_EVERY {
                tokio::time::sleep(POLL_INTERVAL).await;
                outcomes.push(follower.tick().await);
            }
            outcomes
        };
        let (displaced, outcomes) = tokio::join!(leader.tick(), other);
        assert_eq!(
            outcomes.last(),
            Some(&Outcome::Advanced {
                from: 1001,
                to: 1006
            }),
            "{outcomes:?}"
        );
        assert_eq!(displaced, Outcome::Follower);
        assert!(!leader.is_leader() && follower.is_leader());
        for h in 1001..=1006 {
            assert_eq!(index_of(&store, h), Some(hash_at(h, 0)), "height {h}");
        }
        assert_eq!(stored_tip(&store), Some(1006));
    }

    #[tokio::test(start_paused = true)]
    async fn a_released_lock_does_not_let_a_paused_leader_write() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(800));
        let f = follower(store.clone(), chain.clone(), None);
        assert_eq!(f.tick().await, Outcome::Cold { tip: 800 });
        // Another process took the lock over, wrote a newer tip and released the lock again.
        store.locks.lock().unwrap().clear();
        let newer = Tip {
            height: 805,
            hash: hash_at(805, 0),
        };
        store.put(&tip_key(&store.chain_prefix()), encode_tip(&newer));
        let older = Tip {
            height: 801,
            hash: hash_at(801, 0),
        };
        assert!(
            !f.write_tip(&older).await.unwrap(),
            "an absent lock refuses the write"
        );
        assert!(!f.is_leader());
        assert_eq!(stored_tip(&store), Some(805));
        let block = FetchedBlock::from_frame(grpc_frame(&chain.msg(801)));
        assert!(!f.store_blocks(&[block], 801).await.unwrap());
        assert_eq!(index_of(&store, 801), None);
    }

    #[tokio::test(start_paused = true)]
    async fn two_followers_do_not_take_the_lock_from_each_other() {
        let store = Arc::new(MemStore::default());
        let stuck = Arc::new(FakeChain::new(1000));
        let live_b = Arc::new(FakeChain::new(1000));
        let live_c = Arc::new(FakeChain::new(1000));
        let (leader, b) = pair(&store, &stuck, &live_b);
        let (_, c) = pair(&store, &stuck, &live_c);
        assert_eq!(leader.tick().await, Outcome::Cold { tip: 1000 });
        live_b.set_tip(1006);
        live_c.set_tip(1006);
        age_the_tip();
        // Both see the stale tip on their first probe.
        for f in [&b, &c] {
            assert!(matches!(
                f.tick().await,
                Outcome::StaleLeader {
                    took_over: false,
                    ..
                }
            ));
        }
        for _ in 1..STALE_PROBE_EVERY {
            assert_eq!(b.tick().await, Outcome::Follower);
            assert_eq!(c.tick().await, Outcome::Follower);
            assert_eq!(leader.tick().await, Outcome::Idle);
        }
        // b takes over and is still fetching its blocks when c probes the same stale tip.
        live_b.blocks_delay_ms.store(5_000, Ordering::SeqCst);
        let (outcome_b, outcome_c) = tokio::join!(b.tick(), c.tick());
        assert_eq!(
            outcome_b,
            Outcome::Advanced {
                from: 1001,
                to: 1006
            }
        );
        assert_eq!(
            outcome_c,
            Outcome::StaleLeader {
                from: 1000,
                to: 1006,
                took_over: false
            }
        );
        assert!(b.is_leader() && !c.is_leader());
        assert_eq!(stored_tip(&store), Some(1006));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_probe_does_not_send_the_served_tip_back() {
        let store = Arc::new(MemStore::default());
        let stuck = Arc::new(FakeChain::new(1000));
        let live = Arc::new(FakeChain::new(1000));
        let (leader, follower) = pair(&store, &stuck, &live);
        assert_eq!(leader.tick().await, Outcome::Cold { tip: 1000 });
        live.set_tip(1006);
        age_the_tip();
        assert!(matches!(
            follower.tick().await,
            Outcome::StaleLeader {
                took_over: false,
                ..
            }
        ));
        assert_eq!(follower.tip().unwrap().height, 1006);
        // Its own lightwalletd fails from now on: every tick, the probes included, keeps 1006.
        live.down.store(true, Ordering::SeqCst);
        for _ in 0..(2 * STALE_PROBE_EVERY) {
            assert_eq!(follower.tick().await, Outcome::Follower);
            assert_eq!(follower.tip().unwrap().height, 1006);
            assert_eq!(leader.tick().await, Outcome::Idle);
        }
        // Bounded: without a confirmation for HELD_TIP_MAX_AGE it serves the stored tip again.
        let mut waited = Duration::ZERO;
        while waited <= HELD_TIP_MAX_AGE {
            tokio::time::advance(Duration::from_secs(3)).await;
            waited += Duration::from_secs(3);
            assert_eq!(leader.tick().await, Outcome::Idle);
            follower.tick().await;
        }
        assert_eq!(follower.tip().unwrap().height, 1000);
        assert!(leader.is_leader() && !follower.is_leader());
    }

    #[tokio::test(start_paused = true)]
    async fn a_lightwalletd_stuck_behind_gives_the_lock_up() {
        let store = Arc::new(MemStore::default());
        let stuck = Arc::new(FakeChain::new(4000));
        let fine = Arc::new(FakeChain::new(4000));
        let f = follower(store.clone(), stuck.clone(), None);
        let other = follower(store.clone(), fine.clone(), None);
        assert_eq!(f.tick().await, Outcome::Cold { tip: 4000 });
        assert_eq!(f.tick().await, Outcome::Idle);
        assert_eq!(other.tick().await, Outcome::Follower);
        stuck.set_tip(3995);
        for _ in 0..MAX_BEHIND_TICKS {
            assert!(matches!(f.tick().await, Outcome::Behind { .. }));
            assert!(f.is_leader());
        }
        assert_eq!(f.tip().unwrap().height, 4000);
        // One more: it gives the lock up and stays away from it for the cooldown.
        assert!(matches!(f.tick().await, Outcome::Behind { .. }));
        assert!(!f.is_leader());
        for _ in 0..BEHIND_COOLDOWN_TICKS {
            assert_eq!(f.tick().await, Outcome::Follower);
        }
        // Nobody confirms the tip any more: it goes stale on both.
        tokio::time::advance(crate::store::TIP_STALE_AFTER + Duration::from_secs(1)).await;
        assert_eq!(f.tip(), None);
        assert_eq!(other.tip(), None);
        // The other process leads from its next tick and moves on.
        fine.set_tip(4001);
        assert_eq!(
            other.tick().await,
            Outcome::Advanced {
                from: 4001,
                to: 4001
            }
        );
        assert_eq!(f.tick().await, Outcome::Follower);
        assert_eq!(f.tip().unwrap().height, 4001);
    }

    #[tokio::test(start_paused = true)]
    async fn followers_keep_the_tip_fresh_only_while_the_leader_confirms_it() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(9000));
        let leader = follower(store.clone(), chain.clone(), None);
        let f = follower(store.clone(), chain.clone(), None);
        assert_eq!(leader.tick().await, Outcome::Cold { tip: 9000 });
        // Normal operation: a chain without a new block for a while, every tick confirmed.
        for _ in 0..12 {
            tokio::time::advance(Duration::from_secs(5)).await;
            assert_eq!(leader.tick().await, Outcome::Idle);
            assert_eq!(f.tick().await, Outcome::Follower);
            assert_eq!(f.tip().unwrap().height, 9000);
        }
        // The lightwalletd is stuck at the tip height: after MAX_IDLE_TICKS the leader stops
        // confirming, and the followers' tip ages out although they still read it every tick.
        for _ in 0..MAX_IDLE_TICKS {
            leader.tick().await;
        }
        assert_eq!(leader.tick().await, Outcome::Idle);
        f.tick().await;
        for _ in 0..7 {
            tokio::time::advance(Duration::from_secs(5)).await;
            assert_eq!(leader.tick().await, Outcome::Idle);
            assert_eq!(f.tick().await, Outcome::Follower);
        }
        assert_eq!(f.tip(), None);
        assert_eq!(leader.tip(), None);
        // A new block: confirmed and fresh again.
        chain.set_tip(9001);
        assert!(matches!(leader.tick().await, Outcome::Advanced { .. }));
        f.tick().await;
        assert_eq!(f.tip().unwrap().height, 9001);
    }

    #[tokio::test(start_paused = true)]
    async fn leader_work_longer_than_the_lease_keeps_it_without_another_process() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(6500));
        let f = follower(store.clone(), chain.clone(), None);
        // A cold start whose block fetch takes three lock TTLs.
        chain
            .blocks_delay_ms
            .store(3 * LOCK_TTL_MS, Ordering::SeqCst);
        assert_eq!(f.tick().await, Outcome::Cold { tip: 6500 });
        assert!(f.is_leader());
        assert_eq!(stored_tip(&store), Some(6500));
    }

    #[tokio::test(start_paused = true)]
    async fn leader_work_is_cancelled_when_its_lease_is_taken() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(6600));
        let f = follower(store.clone(), chain.clone(), None);
        assert_eq!(f.tick().await, Outcome::Cold { tip: 6600 });
        chain.set_tip(6610);
        chain
            .blocks_delay_ms
            .store(10 * LOCK_TTL_MS, Ordering::SeqCst);
        let lock = lock_key(&store.chain_prefix());
        let thief = async {
            tokio::time::sleep(Duration::from_millis(LOCK_TTL_MS / 2)).await;
            store.locks.lock().unwrap().insert(
                lock.clone(),
                (
                    "other".to_string(),
                    tokio::time::Instant::now() + Duration::from_secs(3600),
                ),
            );
        };
        let start = tokio::time::Instant::now();
        let (outcome, _) = tokio::join!(f.tick(), thief);
        assert_eq!(outcome, Outcome::Follower);
        assert!(!f.is_leader());
        assert!(
            start.elapsed() < Duration::from_millis(2 * LOCK_TTL_MS),
            "cancelled at the next renewal, not after the fetch"
        );
        assert_eq!(stored_tip(&store), Some(6600));
        assert_eq!(index_of(&store, 6601), None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_displacement_between_two_batches_stops_the_rest() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(1000));
        let f = follower(store.clone(), chain.clone(), None);
        assert_eq!(f.tick().await, Outcome::Cold { tip: 1000 });
        chain.set_tip(1100);
        // The first block batch of the next tick is accepted, then another process takes the
        // lock before the second batch.
        *store.steal_lock_after.lock().unwrap() = Some((1, "other".to_string()));
        assert_eq!(f.tick().await, Outcome::Follower);
        assert!(!f.is_leader());
        let prefix = store.key_prefix(store.epoch);
        let last_written = 1000 + BLOCK_WRITE_BATCH as u64;
        for h in 1001..=last_written {
            assert_eq!(index_of(&store, h), Some(hash_at(h, 0)), "height {h}");
            assert!(store.get(&block_key(&prefix, "", h)).is_some(), "block {h}");
        }
        for h in last_written + 1..=1100 {
            assert_eq!(index_of(&store, h), None, "height {h}");
            assert!(store.get(&block_key(&prefix, "", h)).is_none(), "block {h}");
        }
        assert_eq!(stored_tip(&store), Some(1000));
    }

    #[test]
    fn write_batches_end_at_the_item_or_the_byte_bound() {
        assert!(write_batches(&[], 4, 100).is_empty());
        assert_eq!(
            write_batches(&[1, 1, 1, 1, 1], 2, 100),
            vec![0..2, 2..4, 4..5]
        );
        // 40 + 40 fit, the third would pass 100; an item above the bound goes alone.
        assert_eq!(
            write_batches(&[40, 40, 40, 250, 10, 10], 32, 100),
            vec![0..2, 2..3, 3..4, 4..6]
        );
        assert_eq!(write_batches(&[60, 40, 1], 32, 100), vec![0..2, 2..3]);
        assert_eq!(write_batches(&[0, 0, 0], 32, 0), vec![0..3]);
    }

    /// A block at `height` whose message is `size` bytes (the follower stores it as it is).
    fn sized_block(height: u64, size: usize) -> FetchedBlock {
        FetchedBlock {
            height: Some(height),
            hash: hash_at(height, 0),
            prev_hash: Vec::new(),
            frame: Bytes::from(vec![0u8; 5 + size]),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn large_blocks_are_written_in_scripts_bounded_by_bytes() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(1000));
        let f = follower(store.clone(), chain.clone(), None);
        assert_eq!(f.tick().await, Outcome::Cold { tip: 1000 });
        let third = BLOCK_WRITE_BATCH_BYTES * 2 / 5;
        let sizes = [third, third, third, 2 * BLOCK_WRITE_BATCH_BYTES, 10, 10];
        let blocks: Vec<FetchedBlock> = sizes
            .iter()
            .enumerate()
            .map(|(i, size)| sized_block(1001 + i as u64, *size))
            .collect();
        store.fenced_writes.lock().unwrap().clear();
        assert!(f.store_blocks(&blocks, 1006).await.unwrap());
        // Two blocks fit, the third would pass the bound, the large one goes alone, then the
        // rest: the index entry and the block of a height always in the same script.
        let chain_prefix = store.chain_prefix();
        let prefix = store.key_prefix(store.epoch);
        let script = |heights: std::ops::RangeInclusive<u64>| -> Vec<String> {
            heights
                .flat_map(|h| [index_key(&chain_prefix, h), block_key(&prefix, "", h)])
                .collect()
        };
        assert_eq!(
            *store.fenced_writes.lock().unwrap(),
            vec![
                script(1001..=1002),
                script(1003..=1003),
                script(1004..=1004),
                script(1005..=1006)
            ]
        );
        for (i, size) in sizes.iter().enumerate() {
            let h = 1001 + i as u64;
            assert_eq!(store.get(&block_key(&prefix, "", h)).unwrap().len(), *size);
        }

        // Displaced between two such scripts: the rest is not written.
        let blocks: Vec<FetchedBlock> = sizes
            .iter()
            .enumerate()
            .map(|(i, size)| sized_block(2001 + i as u64, *size))
            .collect();
        *store.steal_lock_after.lock().unwrap() = Some((1, "other".to_string()));
        assert!(!f.store_blocks(&blocks, 2006).await.unwrap());
        assert!(!f.is_leader());
        for h in 2001..=2002 {
            assert!(index_of(&store, h).is_some(), "height {h}");
            assert!(store.get(&block_key(&prefix, "", h)).is_some(), "block {h}");
        }
        for h in 2003..=2006 {
            assert_eq!(index_of(&store, h), None, "height {h}");
            assert!(store.get(&block_key(&prefix, "", h)).is_none(), "block {h}");
        }
    }

    /// A leader simulated by its keys only: it holds the lock and writes the stored tip, so
    /// the follower's tip cell is written by the follower alone.
    struct KeysOnlyLeader {
        store: Arc<MemStore>,
    }

    impl KeysOnlyLeader {
        fn new(store: &Arc<MemStore>) -> Self {
            store.locks.lock().unwrap().insert(
                lock_key(&store.chain_prefix()),
                (
                    "another-process".to_string(),
                    tokio::time::Instant::now() + Duration::from_secs(86_400),
                ),
            );
            Self {
                store: store.clone(),
            }
        }

        /// Move the stored tip to `height`, as every version does.
        fn move_tip(&self, height: u64) {
            let chain = self.store.chain_prefix();
            let tip = Tip {
                height,
                hash: hash_at(height, 0),
            };
            self.store.put(&tip_key(&chain), encode_tip(&tip));
            self.store
                .put(&tip_at_key(&chain), encode_unix_ms(unix_ms_now()));
        }

        /// Confirm the stored tip (`tip_seen`), as this version does; `n` makes the value new.
        fn confirm(&self, n: u64) {
            self.store
                .put(&tip_seen_key(&self.store.chain_prefix()), encode_unix_ms(n));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_leader_that_does_not_confirm_is_followed_as_before() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(100));
        let f = follower(store.clone(), chain, None);
        let leader = KeysOnlyLeader::new(&store);
        // A leader of this version: it moves the tip and confirms it.
        leader.move_tip(100);
        leader.confirm(1);
        assert_eq!(f.tick().await, Outcome::Follower);
        assert_eq!(f.tip().unwrap().height, 100);
        // Then one that does not write the confirmation leads: the key stays as it was while
        // the tip moves. The follower follows it ...
        for height in [101, 102] {
            leader.move_tip(height);
            tokio::time::advance(Duration::from_secs(5)).await;
            assert_eq!(f.tick().await, Outcome::Follower);
            assert_eq!(f.tip().unwrap().height, height);
        }
        // ... and keeps the tip fresh while that leader idles, as with no key at all.
        let mut idle = Duration::ZERO;
        while idle <= crate::store::TIP_STALE_AFTER * 2 {
            tokio::time::advance(Duration::from_secs(5)).await;
            idle += Duration::from_secs(5);
            assert_eq!(f.tick().await, Outcome::Follower);
            assert_eq!(f.tip().unwrap().height, 102);
        }

        // A leader that confirms again: the strict rule applies again.
        leader.move_tip(103);
        leader.confirm(2);
        assert_eq!(f.tick().await, Outcome::Follower);
        assert_eq!(f.tip().unwrap().height, 103);
        // It stops confirming (and moving): the tip goes stale although it is read every tick.
        let mut idle = Duration::ZERO;
        while idle <= crate::store::TIP_STALE_AFTER {
            assert_eq!(f.tip().unwrap().height, 103);
            tokio::time::advance(Duration::from_secs(5)).await;
            idle += Duration::from_secs(5);
            assert_eq!(f.tick().await, Outcome::Follower);
        }
        assert_eq!(f.tip(), None);
        // The next confirmation makes it fresh again.
        leader.confirm(3);
        assert_eq!(f.tick().await, Outcome::Follower);
        assert_eq!(f.tip().unwrap().height, 103);
    }

    #[tokio::test(start_paused = true)]
    async fn a_store_error_in_a_fenced_write_stops_the_tick() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(2000));
        let f = follower(store.clone(), chain.clone(), None);
        let block = FetchedBlock::from_frame(grpc_frame(&chain.msg(2000)));
        assert_eq!(f.tick().await, Outcome::Cold { tip: 2000 });
        store.down.store(true, Ordering::SeqCst);
        assert!(f.store_blocks(&[block], 2000).await.is_err());
        assert!(f
            .write_tip(&Tip {
                height: 2001,
                hash: hash_at(2001, 0)
            })
            .await
            .is_err());
        store.down.store(false, Ordering::SeqCst);
        assert_eq!(stored_tip(&store), Some(2000));
    }

    #[tokio::test(start_paused = true)]
    async fn a_lower_probe_does_not_replace_a_higher_held_tip() {
        let store = Arc::new(MemStore::default());
        let stuck = Arc::new(FakeChain::new(1000));
        let live = Arc::new(FakeChain::new(1000));
        let (leader, follower) = pair(&store, &stuck, &live);
        assert_eq!(leader.tick().await, Outcome::Cold { tip: 1000 });
        live.set_tip(1006);
        age_the_tip();
        assert!(matches!(
            follower.tick().await,
            Outcome::StaleLeader { to: 1006, .. }
        ));
        // Another instance behind the same name answers lower, still ahead of the stored tip
        // (and another holder, so that this probe is a new observation, not a takeover).
        live.set_tip(1003);
        store.locks.lock().unwrap().insert(
            lock_key(&store.chain_prefix()),
            (
                "third".to_string(),
                tokio::time::Instant::now() + Duration::from_secs(3600),
            ),
        );
        for _ in 1..STALE_PROBE_EVERY {
            follower.tick().await;
            assert_eq!(follower.tip().unwrap().height, 1006);
        }
        assert_eq!(
            follower.tick().await,
            Outcome::StaleLeader {
                from: 1000,
                to: 1006,
                took_over: false
            }
        );
        assert_eq!(follower.tip().unwrap().height, 1006);
    }

    #[tokio::test(start_paused = true)]
    async fn the_held_tip_rule() {
        let store = Arc::new(MemStore::default());
        let stuck = Arc::new(FakeChain::new(1000));
        let live = Arc::new(FakeChain::new(1000));
        let (_leader, follower) = pair(&store, &stuck, &live);
        let chain = store.chain_prefix();
        let tip = |h: u64, f: u8| Tip {
            height: h,
            hash: hash_at(h, f),
        };
        let put_stored = |t: &Tip| store.put(&tip_key(&chain), encode_tip(t));
        // A leader that holds the lock and does not move (it never ticks here).
        store.locks.lock().unwrap().insert(
            lock_key(&chain),
            (
                "stuck-leader".to_string(),
                tokio::time::Instant::now() + Duration::from_secs(3600),
            ),
        );
        put_stored(&tip(1000, 0));
        store.put(&tip_at_key(&chain), encode_unix_ms(1));
        live.set_tip(1006);
        assert!(matches!(
            follower.tick().await,
            Outcome::StaleLeader { to: 1006, .. }
        ));
        // The stored tip moves but stays below: the held tip is kept (no step back).
        put_stored(&tip(1002, 0));
        follower.tick().await;
        assert_eq!(follower.tip().unwrap().height, 1006);
        // The stored chain changes at the held observation's height (a reorg of the stored
        // chain): the held tip is dropped and the stored tip served.
        put_stored(&tip(1000, 7));
        follower.tick().await;
        assert_eq!(follower.tip(), Some(tip(1000, 7)));
        // A fresh observation; then it ages out without a confirmation: one step back to the
        // stored tip, not before.
        put_stored(&tip(1000, 0));
        for _ in 0..STALE_PROBE_EVERY {
            follower.tick().await;
        }
        assert_eq!(follower.tip().unwrap().height, 1006);
        live.down.store(true, Ordering::SeqCst);
        tokio::time::advance(HELD_TIP_MAX_AGE - Duration::from_secs(1)).await;
        follower.tick().await;
        assert_eq!(follower.tip().unwrap().height, 1006);
        tokio::time::advance(Duration::from_secs(2)).await;
        follower.tick().await;
        assert_eq!(follower.tip(), Some(tip(1000, 0)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_holder_change_between_probes_starts_a_new_observation() {
        let store = Arc::new(MemStore::default());
        let stuck = Arc::new(FakeChain::new(1000));
        let live = Arc::new(FakeChain::new(1000));
        let (leader, follower) = pair(&store, &stuck, &live);
        assert_eq!(leader.tick().await, Outcome::Cold { tip: 1000 });
        live.set_tip(1006);
        age_the_tip();
        assert!(matches!(
            follower.tick().await,
            Outcome::StaleLeader {
                took_over: false,
                ..
            }
        ));
        // Another process holds the lock now (the stale leader's lapsed, a third one took it,
        // and it is stuck too).
        let lock = lock_key(&store.chain_prefix());
        store.locks.lock().unwrap().insert(
            lock.clone(),
            (
                "third".to_string(),
                tokio::time::Instant::now() + Duration::from_secs(3600),
            ),
        );
        for _ in 1..STALE_PROBE_EVERY {
            follower.tick().await;
        }
        // Second probe: another holder than observed, no takeover yet (a new observation).
        assert!(matches!(
            follower.tick().await,
            Outcome::StaleLeader {
                took_over: false,
                ..
            }
        ));
        assert!(!follower.is_leader());
        for _ in 1..STALE_PROBE_EVERY {
            follower.tick().await;
        }
        // Third probe, the same holder twice in a row: it takes over.
        assert_eq!(
            follower.tick().await,
            Outcome::Advanced {
                from: 1001,
                to: 1006
            }
        );
        assert!(follower.is_leader());
    }
}

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
//!   atomic "extend if still mine" script. A process that loses Redis stops leading; another
//!   takes over once the TTL lapses. Non-leaders read the tip from Redis every tick.
//! - **Stale leader**: a leader can keep its lock and still stop moving the tip (its
//!   lightwalletd answers with an old tip, or keeps failing the block fetch). With every tip it
//!   writes, the leader also stores when it moved it (`{chain}tip_at`). A follower that finds
//!   the stored tip unmoved for longer than [`DEFAULT_TIP_STALE_AFTER`]
//!   (`CHAIN_TIP_STALE_SECS`) asks its own lightwalletd every [`STALE_PROBE_EVERY`] ticks.
//!   If that is ahead, it serves its own tip at once, and if it is still ahead on the next
//!   probe it takes the lock over (only while the stored tip is still the unmoved one) and
//!   continues the index from there in the same tick. A chain that really has no new block
//!   leaves every lightwalletd at the stored tip, so nothing happens. The tip is written only
//!   while the writer holds the lock (one script), so a leader that was replaced while a tick
//!   was in flight cannot move the stored tip back. The age is wall-clock time between
//!   processes: clock skew beyond the bound makes followers probe more often, never take over
//!   from a leader whose tip moves. A leader that does not store the time (an older version)
//!   is never treated as stale. Metrics `ohttp_chain_tip_age_seconds`,
//!   `ohttp_chain_stale_leader_total`.
//! - **Lagging backend**: a leader whose lightwalletd answers with a lower tip that is on the
//!   indexed chain (the index has that block) treats it as behind, not as a reorg: the tip and
//!   the index stay.
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
//! Everything is fail-open: a Redis error demotes the leader and leaves the tip unknown, and
//! the request paths then answer from upstream.

use crate::block_cache::{block_key, grpc_frame, FetchedBlock, PoolKeys};
use crate::local::LocalCache;
use crate::store::{
    decode_tip, decode_unix_ms, encode_tip, encode_unix_ms, index_key, lock_key,
    permanent_block_key, tip_at_key, tip_key, unix_ms_now, CacheStore, PermanentStore, Tip,
    INDEX_WINDOW, PERMANENT_DEPTH,
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
    /// Follower: the stored tip height that its own lightwalletd was last found ahead of, and
    /// the tip it serves meanwhile.
    stale: parking_lot::Mutex<Option<(u64, Tip)>>,
    /// Unix milliseconds of the last tip this process wrote as leader (0 = none).
    moved_at_ms: AtomicU64,
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
        self.read_stored_tip_and_age().await.0
    }

    /// The stored tip and how long ago the leader moved it (None: not stored, e.g. by a leader
    /// that does not write it).
    async fn read_stored_tip_and_age(&self) -> (Option<Tip>, Option<Duration>) {
        let chain = self.store.chain_prefix();
        let mut values = self
            .store
            .mget(vec![tip_key(&chain), tip_at_key(&chain)])
            .await
            .into_iter();
        let tip = values.next().flatten().and_then(|b| decode_tip(&b));
        let age = values
            .next()
            .flatten()
            .and_then(|b| decode_unix_ms(&b))
            .map(|ms| Duration::from_millis(unix_ms_now().saturating_sub(ms)));
        (tip, age)
    }

    /// Follower tick with a stored tip that has not moved for `age`: compare it with this
    /// process's own lightwalletd (every [`STALE_PROBE_EVERY`] ticks). None = nothing to do
    /// (serve the stored tip). See the module docs, "Stale leader".
    async fn check_stale_leader(
        &self,
        n: u64,
        stored: &Tip,
        age: Option<Duration>,
    ) -> Option<Outcome> {
        if age.is_none_or(|a| a <= self.stale_after) {
            *self.stale.lock() = None;
            return None;
        }
        if !n.is_multiple_of(STALE_PROBE_EVERY) {
            // Between probes keep serving the tip the last probe found, never an older one.
            let held = self.stale.lock().clone();
            return match held {
                Some((height, own)) if height == stored.height && own.height > stored.height => {
                    self.store.tip_cell().set(own.clone());
                    crate::health::record_cache_tip_height(&self.network, own.height);
                    Some(Outcome::Follower)
                }
                _ => None,
            };
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
            *self.stale.lock() = None;
            return None;
        }
        let seen_before = self
            .stale
            .lock()
            .replace((stored.height, own.clone()))
            .is_some_and(|(height, _)| height == stored.height);
        self.store.tip_cell().set(own.clone());
        crate::health::record_cache_tip_height(&self.network, own.height);
        let age_secs = age.map_or(0, |a| a.as_secs());
        if !seen_before {
            warn!(network = %self.network, stored = stored.height, own = own.height, age_secs, "chain tip has not moved and this process's lightwalletd is ahead: serving its tip");
            crate::health::record_chain_stale_leader(&self.network, "local_tip");
            return Some(Outcome::StaleLeader {
                from: stored.height,
                to: own.height,
                took_over: false,
            });
        }
        let chain = self.store.chain_prefix();
        let took_over = self
            .store
            .take_lock_if(
                lock_key(&chain),
                self.token.clone(),
                LOCK_TTL_MS,
                tip_key(&chain),
                encode_tip(stored),
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
        }
        Some(Outcome::StaleLeader {
            from: stored.height,
            to: own.height,
            took_over,
        })
    }

    /// One poll. Public so tests drive the follower deterministically.
    pub async fn tick(&self) -> Outcome {
        let n = self.ticks.fetch_add(1, Ordering::Relaxed);
        let lock = lock_key(&self.store.chain_prefix());
        let held = if self.is_leader() {
            self.store
                .pexpire_if_equal(lock, self.token.clone(), LOCK_TTL_MS)
                .await
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
            let (stored, age) = self.read_stored_tip_and_age().await;
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
                    None => {
                        self.store.tip_cell().set(tip.clone());
                        crate::health::record_cache_tip_height(&self.network, tip.height);
                    }
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

        // The lock is renewed while the tick runs; a tick that fails (lightwalletd unreachable,
        // an answer that does not chain) releases it, so another process, maybe with another
        // lightwalletd, can lead from its next tick instead of after the TTL.
        let renew = async {
            loop {
                tokio::time::sleep(LOCK_RENEW_EVERY).await;
                if self
                    .store
                    .pexpire_if_equal(
                        lock_key(&self.store.chain_prefix()),
                        self.token.clone(),
                        LOCK_TTL_MS,
                    )
                    .await
                    == Some(false)
                {
                    break;
                }
            }
            std::future::pending::<()>().await
        };
        let outcome = tokio::select! {
            o = self.lead(became_leader) => o,
            _ = renew => unreachable!("the renewal never ends"),
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

    /// The leader's part of a tick.
    async fn lead(&self, became_leader: bool) -> Outcome {
        if became_leader {
            // Continue from the previous leader's index.
            *self.last.lock() = self.read_stored_tip().await;
            *self.backfill_cursor.lock() = None;
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
                self.store.tip_cell().set(latest.clone());
                Ok(Outcome::Idle)
            }
            Some(last) if latest.height > last.height => self.advance(&last, &latest).await,
            Some(last) if latest.height < last.height && self.on_index(&latest).await => {
                // A lightwalletd that is behind (e.g. one of several behind a load-balanced
                // address), not a reorg: keep the tip and the index.
                debug!(network = %self.network, backend = latest.height, tip = last.height, "chain follower: lightwalletd behind the indexed tip");
                self.store.tip_cell().set(last.clone());
                Ok(Outcome::Behind {
                    backend: latest.height,
                    tip: last.height,
                })
            }
            Some(last) => self.reorg(&last, &latest, latest.height).await,
        };
        match outcome {
            Ok(o) => {
                if matches!(o, Outcome::Idle) {
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
        self.store_blocks(&blocks, tip.height).await;
        if !self.write_tip(&tip).await {
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
        self.store_blocks(&blocks, new_tip.height).await;
        if !self.write_tip(&new_tip).await {
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

        // Invalidate fork+1 ..= old tip (and anything above, up to the new tip).
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
        if let Some(local) = &self.local {
            for k in &keys {
                local.invalidate(k);
            }
        }
        for chunk in keys.chunks(256) {
            self.store.del(chunk.to_vec()).await;
        }

        // Refetch the canonical chain above the fork and rewrite the index.
        let to = latest.height.min(fork + MAX_CATCHUP + MAX_WALK_BACK);
        let blocks = self.source.blocks(fork + 1, to).await?;
        if !chained(&blocks) {
            anyhow::bail!("GetBlockRange({},{to}) is not a chain", fork + 1);
        }
        let new_tip = tip_of(&blocks).unwrap_or_else(|| latest.clone());
        self.store_blocks(&blocks, new_tip.height).await;
        if !self.write_tip(&new_tip).await {
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
    async fn store_blocks(&self, blocks: &[FetchedBlock], tip_height: u64) {
        let epoch = self.store.epoch().await;
        let prefix = self.store.key_prefix(epoch);
        let chain = self.store.chain_prefix();
        let mut writes = Vec::with_capacity(blocks.len() * 2);
        let mut permanent: Vec<(String, Bytes)> = Vec::new();
        for b in blocks {
            let Some(h) = b.height else { continue };
            if b.hash.is_empty() {
                continue;
            }
            writes.push(self.store.set(
                index_key(&chain, h),
                Bytes::from(b.hash.clone()),
                Some(INDEX_TTL_SECS),
                None,
            ));
            if self.permanent_height(h, tip_height) {
                let pk = permanent_block_key(&self.network, "", h);
                if let Some(local) = &self.local {
                    local.insert(pk.clone(), b.message());
                }
                permanent.push((pk, b.message()));
                continue;
            }
            let bk = block_key(&prefix, "", h);
            if let Some(local) = &self.local {
                local.insert(bk.clone(), b.message());
            }
            writes.push(self.store.set(bk, b.message(), None, Some(epoch)));
        }
        for chunk in writes.chunks_mut(64) {
            futures_util::future::join_all(chunk.iter_mut()).await;
        }
        if let (Some(perm), false) = (&self.permanent, permanent.is_empty()) {
            let n = permanent.len() as u64;
            if perm.set_many(permanent).await {
                crate::health::record_block_permanent(&self.network, "stored", n);
            }
        }
        crate::health::record_upstream_blocks(&self.network, blocks.len() as u64);
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

    /// Store `tip` and when it moved, only while this process holds the lock. False when it
    /// does not any more (replaced by another process during this tick): it stops leading and
    /// leaves the stored tip alone. A store error keeps the tip in memory (fail-open, as before).
    async fn write_tip(&self, tip: &Tip) -> bool {
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
                ],
            )
            .await;
        if written == Some(false) {
            warn!(network = %self.network, height = tip.height, "chain follower lost the leader lock during this tick: tip not written");
            self.set_leader(false);
            return false;
        }
        self.moved_at_ms.store(now, Ordering::Relaxed);
        *self.last.lock() = Some(tip.clone());
        self.notify_new_block(tip);
        true
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
                    self.store_blocks(&blocks, tip).await;
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
        assert!(!leader.write_tip(&stale_tip).await);
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
}

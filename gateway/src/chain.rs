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
    decode_tip, encode_tip, index_key, lock_key, permanent_block_key, tip_key, CacheStore,
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
        }
    }

    /// Attach the permanent tier for heights `>= min_height`.
    pub fn with_permanent(mut self, permanent: Arc<dyn PermanentStore>, min_height: u64) -> Self {
        self.permanent = Some(permanent);
        self.permanent_min_height = min_height;
        self
    }

    /// Whether a block at `height` is final against a tip at `tip_height` and belongs to the
    /// permanent tier.
    fn permanent_height(&self, height: u64, tip_height: u64) -> bool {
        self.permanent.is_some()
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
                Outcome::Follower | Outcome::Idle => {}
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
        let key = tip_key(&self.store.chain_prefix());
        self.store
            .mget(vec![key])
            .await
            .into_iter()
            .next()
            .flatten()
            .and_then(|b| decode_tip(&b))
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
            // Follow the leader's tip; probe lightwalletd now and then for the health gauge.
            if let Some(tip) = self.read_stored_tip().await {
                self.store.tip_cell().set(tip.clone());
                crate::health::record_cache_tip_height(&self.network, tip.height);
            }
            if n.is_multiple_of(HEALTH_PROBE_EVERY) {
                crate::health::record_lwd_reachable(
                    &self.network,
                    self.source.latest().await.is_ok(),
                );
            }
            return Outcome::Follower;
        }

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

        let last = self.last.lock().clone();
        let outcome = match last {
            None => self.index_cold(&latest).await,
            Some(last) if last == latest => {
                self.store.tip_cell().set(latest.clone());
                Ok(Outcome::Idle)
            }
            Some(last) if latest.height > last.height => self.advance(&last, &latest).await,
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
        self.write_tip(&tip).await;
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
        self.write_tip(&new_tip).await;
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
        self.write_tip(&new_tip).await;
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
        let Some(perm) = &self.permanent else { return };
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

    async fn write_tip(&self, tip: &Tip) {
        self.store
            .set(
                tip_key(&self.store.chain_prefix()),
                encode_tip(tip),
                Some(INDEX_TTL_SECS),
                None,
            )
            .await;
        *self.last.lock() = Some(tip.clone());
        self.notify_new_block(tip);
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
}

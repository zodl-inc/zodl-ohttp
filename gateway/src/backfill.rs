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

//! `ohttp-gateway backfill`: fill the permanent block tier from lightwalletd.
//!
//! Walks `[start, end]` (default Sapling activation .. tip - `PERMANENT_DEPTH`) in batches,
//! each batch one `MGET` on the permanent tier to find the heights still missing, grouped into
//! maximal contiguous runs fetched with one `GetBlockRange` each (directly from lightwalletd,
//! never through the gateway) and written with the exact key and value the gateway reads
//! (`store::permanent_block_key`, the CompactBlock message without the gRPC prefix). Every run
//! is checked to be a chain (`prev_hash` links, sequential heights) before anything is written.
//!
//! Throttled: `concurrency` batches in flight at most, `pause` between runs. Resumable: present
//! heights are skipped, and a checkpoint (`perm:{network}:block:v1:backfill:cursor:{pool}`, the
//! last height of the newest batch completed in order) is written to the tier so a restart
//! begins after it. Delete the key to rescan from `start`.

use crate::block_cache::FetchedBlock;
use crate::chain::{chained, ChainSource};
use crate::store::{permanent_block_key, PermanentStore, PERMANENT_DEPTH};
use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use futures_util::StreamExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

#[derive(Clone, Debug)]
pub struct BackfillConfig {
    pub network: String,
    /// Inclusive range; `end` must already be final.
    pub start: u64,
    pub end: u64,
    /// Heights per batch (one MGET, at most one GetBlockRange when nothing is present).
    pub batch: u64,
    /// Batches in flight.
    pub concurrency: usize,
    /// Pause after every run fetched and written.
    pub pause: Duration,
    /// Pool filter variant to fill (the empty filter is what wallets send).
    pub pool: String,
}

#[derive(Debug, Default)]
pub struct BackfillStats {
    pub written: AtomicU64,
    pub bytes: AtomicU64,
    pub skipped: AtomicU64,
    pub upstream_calls: AtomicU64,
    pub batches: AtomicU64,
}

impl BackfillStats {
    pub fn written(&self) -> u64 {
        self.written.load(Ordering::Relaxed)
    }
    pub fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }
    pub fn skipped(&self) -> u64 {
        self.skipped.load(Ordering::Relaxed)
    }
    pub fn upstream_calls(&self) -> u64 {
        self.upstream_calls.load(Ordering::Relaxed)
    }
}

/// The checkpoint key: last height of the newest batch completed in order.
pub fn checkpoint_key(network: &str, pool: &str) -> String {
    format!("perm:{network}:block:v1:backfill:cursor:{pool}")
}

async fn read_checkpoint(perm: &dyn PermanentStore, key: &str) -> Option<u64> {
    let v = perm
        .mget(vec![key.to_string()])
        .await
        .into_iter()
        .next()??;
    std::str::from_utf8(&v).ok()?.trim().parse().ok()
}

/// Fetch `[s, e]` with up to three attempts.
async fn fetch_run(source: &dyn ChainSource, s: u64, e: u64) -> Result<Vec<FetchedBlock>> {
    let mut last = None;
    for attempt in 0..3u64 {
        match source.blocks(s, e).await {
            Ok(b) => return Ok(b),
            Err(err) => {
                warn!(start = s, end = e, attempt, error = %err, "backfill fetch failed");
                last = Some(err);
                tokio::time::sleep(Duration::from_secs(2 + attempt * 3)).await;
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("fetch failed")))
}

/// Verify `blocks` is exactly the chain `[s, e]`.
fn verify_run(blocks: &[FetchedBlock], s: u64, e: u64) -> Result<()> {
    let want = (e - s + 1) as usize;
    anyhow::ensure!(
        blocks.len() == want,
        "GetBlockRange({s},{e}) returned {} blocks, expected {want}",
        blocks.len()
    );
    for (i, b) in blocks.iter().enumerate() {
        anyhow::ensure!(
            b.height == Some(s + i as u64) && !b.hash.is_empty(),
            "GetBlockRange({s},{e}) block {i} has height {:?}",
            b.height
        );
    }
    anyhow::ensure!(chained(blocks), "GetBlockRange({s},{e}) is not a chain");
    Ok(())
}

async fn process_batch(
    cfg: &BackfillConfig,
    source: &dyn ChainSource,
    perm: &dyn PermanentStore,
    stats: &BackfillStats,
    s: u64,
    e: u64,
) -> Result<()> {
    let heights: Vec<u64> = (s..=e).collect();
    let keys: Vec<String> = heights
        .iter()
        .map(|h| permanent_block_key(&cfg.network, &cfg.pool, *h))
        .collect();
    let present = perm.mget(keys).await;
    let mut runs: Vec<(u64, u64)> = Vec::new();
    for (i, h) in heights.iter().copied().enumerate() {
        if present.get(i).is_some_and(|v| v.is_some()) {
            stats.skipped.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        match runs.last_mut() {
            Some((_, end)) if *end + 1 == h => *end = h,
            _ => runs.push((h, h)),
        }
    }
    for (rs, re) in runs {
        let blocks = fetch_run(source, rs, re).await?;
        stats.upstream_calls.fetch_add(1, Ordering::Relaxed);
        verify_run(&blocks, rs, re)?;
        let mut bytes = 0u64;
        let entries: Vec<(String, Bytes)> = blocks
            .iter()
            .map(|b| {
                let m = b.message();
                bytes += m.len() as u64;
                (
                    permanent_block_key(&cfg.network, &cfg.pool, b.height.unwrap_or(0)),
                    m,
                )
            })
            .collect();
        let n = entries.len() as u64;
        // Writes retry too: a compaction stall on the store must not end the run (without the
        // retry it would, and the next run would resume from the checkpoint).
        let mut written = false;
        for attempt in 0..3u64 {
            if perm.set_many(entries.clone()).await {
                written = true;
                break;
            }
            warn!(
                start = rs,
                end = re,
                attempt,
                "permanent store write failed, retrying"
            );
            tokio::time::sleep(Duration::from_secs(2 + attempt * 3)).await;
        }
        if !written {
            return Err(anyhow!("permanent store write failed for {rs}..={re}"));
        }
        stats.written.fetch_add(n, Ordering::Relaxed);
        stats.bytes.fetch_add(bytes, Ordering::Relaxed);
        crate::health::record_block_permanent(&cfg.network, "backfilled", n);
        if !cfg.pause.is_zero() {
            tokio::time::sleep(cfg.pause).await;
        }
    }
    stats.batches.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// Run the backfill. Returns the stats; `Err` when a batch failed after retries (the
/// checkpoint covers everything completed in order before it).
pub async fn run(
    cfg: BackfillConfig,
    source: Arc<dyn ChainSource>,
    perm: Arc<dyn PermanentStore>,
) -> Result<Arc<BackfillStats>> {
    anyhow::ensure!(cfg.batch > 0, "batch must be > 0");
    anyhow::ensure!(cfg.concurrency > 0, "concurrency must be > 0");
    let stats = Arc::new(BackfillStats::default());
    let ck = checkpoint_key(&cfg.network, &cfg.pool);
    let mut from = cfg.start.max(1);
    if let Some(c) = read_checkpoint(perm.as_ref(), &ck).await {
        if c >= from {
            info!(network = %cfg.network, checkpoint = c, "backfill resuming after checkpoint");
            from = c + 1;
        }
    }
    if from > cfg.end {
        info!(network = %cfg.network, start = cfg.start, end = cfg.end, "backfill: nothing to do");
        return Ok(stats);
    }
    let started = Instant::now();
    let total = cfg.end - from + 1;
    let mut batches = Vec::new();
    let mut s = from;
    while s <= cfg.end {
        let e = (s + cfg.batch - 1).min(cfg.end);
        batches.push((s, e));
        s = e + 1;
    }
    info!(
        network = %cfg.network,
        from,
        end = cfg.end,
        heights = total,
        batches = batches.len(),
        batch = cfg.batch,
        concurrency = cfg.concurrency,
        "backfill started"
    );
    let cfg = Arc::new(cfg);
    let (cfg_b, source_b, perm_b, stats_b) =
        (cfg.clone(), source.clone(), perm.clone(), stats.clone());
    let mut stream = std::pin::pin!(futures_util::stream::iter(batches)
        .map(move |(s, e)| {
            let cfg = cfg_b.clone();
            let source = source_b.clone();
            let perm = perm_b.clone();
            let stats = stats_b.clone();
            async move {
                let r = process_batch(&cfg, source.as_ref(), perm.as_ref(), &stats, s, e).await;
                (s, e, r)
            }
        })
        .buffered(cfg.concurrency));
    let mut done = 0u64;
    let mut last_log = Instant::now();
    while let Some((s, e, r)) = stream.next().await {
        r.with_context(|| format!("batch {s}..={e}"))?;
        perm.set(ck.clone(), Bytes::from(e.to_string())).await;
        done += e - s + 1;
        if last_log.elapsed() >= Duration::from_secs(30) {
            last_log = Instant::now();
            let el = started.elapsed().as_secs_f64();
            info!(
                network = %cfg.network,
                height = e,
                done,
                total,
                pct = format!("{:.1}", done as f64 * 100.0 / total as f64),
                written = stats.written(),
                skipped = stats.skipped(),
                mib = stats.bytes() / (1024 * 1024),
                upstream_calls = stats.upstream_calls(),
                heights_per_s = format!("{:.0}", done as f64 / el),
                "backfill progress"
            );
        }
    }
    info!(
        network = %cfg.network,
        from,
        end = cfg.end,
        written = stats.written(),
        skipped = stats.skipped(),
        bytes = stats.bytes(),
        upstream_calls = stats.upstream_calls(),
        secs = started.elapsed().as_secs(),
        "backfill done"
    );
    Ok(stats)
}

/// Entry point of `ohttp-gateway backfill`. Environment: `NETWORK`, `LWD_ADDR`,
/// `PERMANENT_REDIS_URL` (required); `BACKFILL_START` (default Sapling activation),
/// `BACKFILL_END` (default and cap: tip - PERMANENT_DEPTH), `BACKFILL_BATCH` (500),
/// `BACKFILL_CONCURRENCY` (2), `BACKFILL_PAUSE_MS` (200), `PERMANENT_OP_TIMEOUT_MS` (5000),
/// `LWD_TIMEOUT_SECS`.
pub async fn main() -> Result<()> {
    let config = crate::config::Config::from_env()?;
    let env_u64 = |k: &str, d: u64| -> u64 {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    let url = std::env::var("PERMANENT_REDIS_URL").unwrap_or_default();
    anyhow::ensure!(!url.is_empty(), "PERMANENT_REDIS_URL is required");
    // Bulk writes: a longer operation timeout than the request path (default 5 s).
    let op_timeout = env_u64("PERMANENT_OP_TIMEOUT_MS", 5_000);
    let perm = crate::cache::PermanentRedis::connect(&url, op_timeout, config.network.clone())
        .await
        .context("permanent store")?;
    let sources = Arc::new(crate::lwd::LwdSources::new_unclassed(
        config.clone(),
        Arc::new(tokio::sync::Semaphore::new(config.max_inflight_lwd)),
    ));
    let tip = sources.latest().await.context("GetLatestBlock")?;
    let cap = tip
        .height
        .checked_sub(PERMANENT_DEPTH)
        .ok_or_else(|| anyhow!("tip {} too low", tip.height))?;
    let cfg = BackfillConfig {
        network: config.network.clone(),
        start: env_u64(
            "BACKFILL_START",
            env_u64(
                "PERMANENT_MIN_HEIGHT",
                crate::store::sapling_activation(&config.network),
            ),
        ),
        end: env_u64("BACKFILL_END", cap).min(cap),
        batch: env_u64("BACKFILL_BATCH", 500),
        concurrency: env_u64("BACKFILL_CONCURRENCY", 2) as usize,
        pause: Duration::from_millis(env_u64("BACKFILL_PAUSE_MS", 200)),
        pool: std::env::var("BACKFILL_POOL").unwrap_or_default(),
    };
    info!(network = %cfg.network, tip = tip.height, lwd = %config.lwd_addr, ?cfg, "permanent tier backfill");
    let stats = run(cfg, sources, Arc::new(perm)).await?;
    info!(
        written = stats.written(),
        skipped = stats.skipped(),
        bytes = stats.bytes(),
        upstream_calls = stats.upstream_calls(),
        "backfill finished"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_cache::test_support::FakeChain;
    use crate::chain::test_support::FakeChainSource;
    use crate::store::test_support::MemPermanent;

    fn cfg(start: u64, end: u64, batch: u64) -> BackfillConfig {
        BackfillConfig {
            network: "testnet".to_string(),
            start,
            end,
            batch,
            concurrency: 2,
            pause: Duration::ZERO,
            pool: String::new(),
        }
    }

    #[tokio::test]
    async fn fills_the_range_skips_present_heights_and_resumes_from_the_checkpoint() {
        let chain = Arc::new(FakeChain::new(5000));
        let source = Arc::new(FakeChainSource(chain.clone()));
        let perm = Arc::new(MemPermanent::default());
        // 1100..=1149 already present; checkpoint says batches up to 1099 are done (so
        // 1000..=1099, though absent, are not refetched by this run).
        for h in 1100..=1149 {
            perm.put(&permanent_block_key("testnet", "", h), chain.msg(h));
        }
        perm.put(&checkpoint_key("testnet", ""), "1099");

        let stats = run(cfg(1000, 1399, 100), source.clone(), perm.clone())
            .await
            .unwrap();
        // 1150..=1199 (the rest of the first batch) plus two full batches.
        assert_eq!(stats.written(), 50 + 200);
        assert_eq!(stats.skipped(), 50);
        let calls = chain.range_calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 3, "{calls:?}");
        assert!(calls.contains(&(1150, 1199)), "{calls:?}");
        assert!(calls.contains(&(1200, 1299)), "{calls:?}");
        assert!(calls.contains(&(1300, 1399)), "{calls:?}");
        assert_eq!(stats.upstream_calls(), 3);
        for h in 1100..=1399 {
            assert_eq!(
                perm.get(&permanent_block_key("testnet", "", h)),
                Some(Bytes::from(chain.msg(h))),
                "{h}"
            );
        }
        assert_eq!(perm.get(&permanent_block_key("testnet", "", 1050)), None);
        assert_eq!(perm.get(&permanent_block_key("testnet", "", 1400)), None);
        assert_eq!(
            perm.get(&checkpoint_key("testnet", "")),
            Some(Bytes::from("1399"))
        );
        let bytes: usize = (1150..=1399).map(|h| chain.msg(h).len()).sum();
        assert_eq!(stats.bytes(), bytes as u64);

        // A second run is a no-op.
        let stats = run(cfg(1000, 1399, 100), source.clone(), perm.clone())
            .await
            .unwrap();
        assert_eq!(stats.written(), 0);
        assert_eq!(chain.range_calls.lock().unwrap().len(), 3);

        // Without the checkpoint, present heights are skipped and gaps become minimal runs.
        perm.del(vec![checkpoint_key("testnet", "")]).await;
        perm.del(vec![permanent_block_key("testnet", "", 1234)])
            .await;
        let stats = run(cfg(1000, 1399, 100), source.clone(), perm.clone())
            .await
            .unwrap();
        assert_eq!(stats.written(), 100 + 1);
        assert_eq!(stats.skipped(), 299);
        let calls = chain.range_calls.lock().unwrap().clone();
        assert_eq!(&calls[3..], &[(1000, 1099), (1234, 1234)], "{calls:?}");
    }

    /// A source that serves `inner` but swaps the block at `tamper` for one of another fork
    /// (breaking the `prev_hash` link) and fails every fetch starting at or above `fail_from`.
    struct Faulty {
        inner: FakeChainSource,
        tamper: Option<u64>,
        fail_from: Option<u64>,
    }

    impl ChainSource for Faulty {
        fn latest(&self) -> futures_util::future::BoxFuture<'static, Result<crate::store::Tip>> {
            self.inner.latest()
        }
        fn blocks(
            &self,
            start: u64,
            end: u64,
        ) -> futures_util::future::BoxFuture<'static, Result<Vec<FetchedBlock>>> {
            let fut = self.inner.blocks(start, end);
            let tamper = self.tamper;
            let fail = self.fail_from.is_some_and(|f| start >= f);
            Box::pin(async move {
                let mut blocks = fut.await?;
                if fail {
                    anyhow::bail!("lwd down");
                }
                if let Some(t) = tamper {
                    for b in blocks.iter_mut() {
                        if b.height == Some(t) {
                            *b = FetchedBlock::from_frame(crate::block_cache::grpc_frame(
                                &crate::block_cache::test_support::block_msg(t, 1),
                            ));
                        }
                    }
                }
                Ok(blocks)
            })
        }
    }

    #[tokio::test]
    async fn a_range_that_is_not_a_chain_is_not_written() {
        let chain = Arc::new(FakeChain::new(5000));
        let source = Arc::new(Faulty {
            inner: FakeChainSource(chain.clone()),
            tamper: Some(2050),
            fail_from: None,
        });
        let perm = Arc::new(MemPermanent::default());
        let err = run(cfg(2000, 2099, 100), source, perm.clone())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("batch 2000..=2099"), "{err}");
        assert!(format!("{err:#}").contains("not a chain"), "{err:#}");
        assert_eq!(perm.len(), 0, "nothing written, no checkpoint");
    }

    #[tokio::test(start_paused = true)]
    async fn upstream_failure_stops_after_retries_and_keeps_the_checkpoint() {
        let chain = Arc::new(FakeChain::new(5000));
        let source = Arc::new(Faulty {
            inner: FakeChainSource(chain.clone()),
            tamper: None,
            fail_from: Some(3100),
        });
        let perm = Arc::new(MemPermanent::default());
        let mut c = cfg(3000, 3299, 100);
        c.concurrency = 1;
        let err = run(c, source, perm.clone()).await.unwrap_err();
        assert!(format!("{err:#}").contains("lwd down"), "{err:#}");
        assert_eq!(
            perm.get(&checkpoint_key("testnet", "")),
            Some(Bytes::from("3099"))
        );
        assert_eq!(perm.len(), 101, "first batch plus the checkpoint");
        // Three attempts were made on the failing batch.
        assert_eq!(chain.range_calls.lock().unwrap().len(), 1 + 3);
    }
}

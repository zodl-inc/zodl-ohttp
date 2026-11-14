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

//! Work the chain follower's leader does once per new tip, so the first requests after a block
//! are cache hits instead of upstream round trips.
//!
//! - **Tip-scoped answers** (`PREFETCH_TIP`, on by default): `GetLightdInfo` and
//!   `GetLatestTreeState` are keyed by the tip hash ([`crate::rpc_cache`]), so without this the
//!   first request after every block misses. The leader asks lightwalletd once per tip and
//!   stores the answer under the key a Client's request has (same method, content type, path
//!   and the empty message body), through the same admission rules as a Client's miss.
//! - **Subtree end markers** (with `PREFETCH_TIP`): the number of completed note commitment
//!   subtrees of a pool at a tip is `floor(tree size / 2^16)`, and the tip block carries both
//!   tree sizes (`ChainMetadata`). The leader writes that count as the tip's end marker
//!   ([`crate::subtree_cache::subtree_end_key`]), so a `GetSubtreeRoots` whose cached prefix
//!   reaches it needs no upstream call. The count is an upper bound of what the node lists
//!   (it cannot list a subtree that is not complete), so the marker never hides a root: a
//!   request below it still fetches what is missing. The markers come from the stored tip
//!   block, so they are written first, before any upstream call of the tip.
//! - **Tree states** (`PREFETCH_TREE_STATE=1`, off by default): `GetTreeState` of each new tip
//!   height (and of the tips since the last run, at most [`MAX_BLOCKS_PER_TIP`]), stored as the
//!   validated entry a Client's height-only request has. A wallet that synced to a tip asks for
//!   the tree state at that height when it next scans; heights this close to the tip are not
//!   final, so they are never in the pinned tier, and without this each one is fetched from
//!   lightwalletd on its first request. One upstream call per block.
//! - **Block transactions** (`PREFETCH_BLOCK_TXS=1`, off by default): the transactions of each
//!   new block (the `CompactTx` hashes of the follower's own block fetch) are fetched once with
//!   `GetTransaction` and stored as validated entries, so wallets syncing to the tip find their
//!   recent transactions cached. At most `PREFETCH_BLOCK_TXS_MAX` transactions per block
//!   (default 100; a larger block is skipped) and at most [`MAX_BLOCKS_PER_TIP`] blocks per tip.
//!
//! Everything is fail-open and off the request path: a failed or slow upstream call only means
//! the entry is not prefetched, and the request path behaves as before. Only the leader
//! prefetches (it is the process that writes the tip). Each prefetched entry is counted in
//! `ohttp_cache_requests_total{result="prefetched"}`.

use crate::block_cache::block_key;
use crate::chain::BlockListener;
use crate::rpc_cache::{self, CacheMiss, HashSource, Policy, MAX_CACHEABLE_SIZE};
use crate::singleflight::RpcFlights;
use crate::store::{CacheStore, Tip};
use futures_util::StreamExt;
use prost::Message;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, info};

const RPC_PREFIX: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/";
const CT: &str = "application/grpc";
/// The tip-scoped answers prefetched per tip.
const TIP_RPCS: [&str; 2] = ["GetLightdInfo", "GetLatestTreeState"];
/// Blocks whose transactions are prefetched per tip at most (a catch-up only does the newest).
pub const MAX_BLOCKS_PER_TIP: u64 = 10;
/// Transactions fetched in parallel.
const TX_PARALLEL: usize = 4;
/// Note commitment subtree size (2^16 leaves).
const SUBTREE_LEAVES: u32 = 1 << 16;

/// What [`TipPrefetch`] does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefetchConfig {
    /// Tip-scoped answers and subtree end markers.
    pub tip: bool,
    /// Block transactions: the largest block (in transactions) that is prefetched; `None` = off.
    pub block_txs: Option<usize>,
    /// `GetTreeState` of each new tip height.
    pub tree_state: bool,
}

impl PrefetchConfig {
    /// From `PREFETCH_TIP` (default on; `0` turns it off), `PREFETCH_BLOCK_TXS` (default off;
    /// `1` turns it on), `PREFETCH_BLOCK_TXS_MAX` (default 100) and `PREFETCH_TREE_STATE`
    /// (default off; `1` turns it on).
    pub fn from_env() -> anyhow::Result<Self> {
        let flag = |name: &str, default: bool| -> anyhow::Result<bool> {
            match std::env::var(name) {
                Ok(v) if !v.trim().is_empty() => match v.trim() {
                    "1" | "true" => Ok(true),
                    "0" | "false" => Ok(false),
                    _ => anyhow::bail!("{name} must be 0 or 1, got '{v}'"),
                },
                _ => Ok(default),
            }
        };
        let max = match std::env::var("PREFETCH_BLOCK_TXS_MAX") {
            Ok(v) if !v.trim().is_empty() => match v.trim().parse::<usize>() {
                Ok(n) if n > 0 => n,
                _ => anyhow::bail!("PREFETCH_BLOCK_TXS_MAX must be a positive integer, got '{v}'"),
            },
            _ => 100,
        };
        Ok(Self {
            tip: flag("PREFETCH_TIP", true)?,
            block_txs: flag("PREFETCH_BLOCK_TXS", false)?.then_some(max),
            tree_state: flag("PREFETCH_TREE_STATE", false)?,
        })
    }

    pub fn is_off(&self) -> bool {
        !self.tip && self.block_txs.is_none() && !self.tree_state
    }
}

/// The parts of a `CompactBlock` the prefetch needs: the transaction hashes (field 7) and the
/// commitment tree sizes after the block (field 8).
#[derive(Clone, PartialEq, prost::Message)]
struct BlockTail {
    #[prost(message, repeated, tag = "7")]
    vtx: Vec<TxHead>,
    #[prost(message, optional, tag = "8")]
    chain_metadata: Option<ChainMetadata>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct TxHead {
    #[prost(bytes, tag = "2")]
    hash: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ChainMetadata {
    #[prost(uint32, tag = "1")]
    sapling_commitment_tree_size: u32,
    #[prost(uint32, tag = "2")]
    orchard_commitment_tree_size: u32,
    #[prost(uint32, tag = "3")]
    ironwood_commitment_tree_size: u32,
}

/// `TxFilter { hash }`, as a Client sends it for `GetTransaction`.
#[derive(Clone, PartialEq, prost::Message)]
struct TxFilter {
    #[prost(bytes, tag = "3")]
    hash: Vec<u8>,
}

fn grpc_frame(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + msg.len());
    out.push(0);
    out.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    out.extend_from_slice(msg);
    out
}

/// The gRPC body of `GetTransaction(TxFilter { hash })`.
pub fn get_transaction_body(txid: &[u8]) -> Vec<u8> {
    grpc_frame(
        &TxFilter {
            hash: txid.to_vec(),
        }
        .encode_to_vec(),
    )
}

/// Completed subtrees of each pool (sapling 0, orchard 1, ironwood 2) after a block with these tree sizes.
pub fn completed_subtrees(
    sapling_size: u32,
    orchard_size: u32,
    ironwood_size: u32,
) -> [(u32, u32); 3] {
    [
        (0, sapling_size / SUBTREE_LEAVES),
        (1, orchard_size / SUBTREE_LEAVES),
        (2, ironwood_size / SUBTREE_LEAVES),
    ]
}

/// The heights a tip at `tip` covers when `done` was the last one done (0 = none): the tip
/// alone on the first run or after a reorg to a lower or equal height, else the heights since
/// `done`, at most [`MAX_BLOCKS_PER_TIP`] (a catch-up only does the newest).
fn since_last(done: u64, tip: u64) -> std::ops::RangeInclusive<u64> {
    let from = if done == 0 || done >= tip {
        tip
    } else {
        (done + 1).max(tip.saturating_sub(MAX_BLOCKS_PER_TIP - 1))
    };
    from..=tip
}

/// The prefetch, registered as a listener of the chain follower.
pub struct TipPrefetch {
    inner: Arc<Inner>,
}

struct Inner {
    store: Arc<dyn CacheStore>,
    flights: Arc<RpcFlights>,
    network: String,
    config: PrefetchConfig,
    /// Highest block whose transactions were prefetched (0 = none yet).
    tx_height: AtomicU64,
    /// Highest height whose tree state was prefetched (0 = none yet).
    tree_height: AtomicU64,
    /// One prefetch at a time: a tip that arrives while one runs is skipped (the next covers
    /// its blocks).
    running: AtomicBool,
}

impl TipPrefetch {
    pub fn new(
        store: Arc<dyn CacheStore>,
        flights: Arc<RpcFlights>,
        network: String,
        config: PrefetchConfig,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                store,
                flights,
                network,
                config,
                tx_height: AtomicU64::new(0),
                tree_height: AtomicU64::new(0),
                running: AtomicBool::new(false),
            }),
        }
    }

    /// Prefetch for `tip` and wait (the listener spawns this).
    pub async fn run(&self, tip: &Tip) {
        let inner = &self.inner;
        if inner.running.swap(true, Ordering::AcqRel) {
            debug!(network = %inner.network, height = tip.height, "prefetch still running, tip skipped");
            return;
        }
        inner.run(tip).await;
        inner.running.store(false, Ordering::Release);
    }
}

impl BlockListener for TipPrefetch {
    fn on_new_block(&self, tip: &Tip) {
        let this = TipPrefetch {
            inner: self.inner.clone(),
        };
        let tip = tip.clone();
        tokio::spawn(async move { this.run(&tip).await });
    }
}

impl Inner {
    async fn run(&self, tip: &Tip) {
        let epoch = self.store.epoch().await;
        let prefix = self.store.key_prefix(epoch);
        // The follower stores the tip block before it announces the tip, so the end markers need
        // no upstream call: write them first. Subtree requests that wallets send right after a
        // new block then find them, instead of waiting for the tip RPCs below, which take one
        // lightwalletd round trip each.
        let blocks = self.blocks(&prefix, tip).await;
        if self.config.tip {
            if let Some((_, tail)) = blocks.iter().find(|(h, _)| *h == tip.height) {
                self.write_end_markers(&prefix, epoch, tip, tail).await;
            }
            for rpc in TIP_RPCS {
                self.prefetch(&prefix, epoch, tip, rpc, grpc_frame(&[]))
                    .await;
            }
        }
        if self.config.tree_state {
            let done = self.tree_height.load(Ordering::Acquire);
            for height in since_last(done, tip.height) {
                self.prefetch(
                    &prefix,
                    epoch,
                    tip,
                    "GetTreeState",
                    rpc_cache::grpc_block_id(height, &[]),
                )
                .await;
                self.tree_height.fetch_max(height, Ordering::AcqRel);
            }
        }
        if let Some(max_txs) = self.config.block_txs {
            for (height, tail) in &blocks {
                self.prefetch_block_txs(&prefix, epoch, tip, *height, tail, max_txs)
                    .await;
                self.tx_height.fetch_max(*height, Ordering::AcqRel);
            }
        }
    }

    /// The decoded blocks this tip needs: the tip block for the end markers, plus the blocks
    /// since the last transaction prefetch (at most [`MAX_BLOCKS_PER_TIP`]) when that is on.
    async fn blocks(&self, prefix: &str, tip: &Tip) -> Vec<(u64, BlockTail)> {
        let mut heights: Vec<u64> = Vec::new();
        if self.config.block_txs.is_some() {
            heights.extend(since_last(
                self.tx_height.load(Ordering::Acquire),
                tip.height,
            ));
        } else if self.config.tip {
            heights.push(tip.height);
        }
        if heights.is_empty() {
            return Vec::new();
        }
        let keys: Vec<String> = heights.iter().map(|h| block_key(prefix, "", *h)).collect();
        let values = self.store.mget(keys).await;
        heights
            .into_iter()
            .zip(values)
            .filter_map(|(h, v)| Some((h, BlockTail::decode(v?.as_ref()).ok()?)))
            .collect()
    }

    /// `floor(tree size / 2^16)` per pool as the end marker of `tip`; only when the block
    /// carries its tree sizes.
    async fn write_end_markers(&self, prefix: &str, epoch: u64, tip: &Tip, tail: &BlockTail) {
        let Some(meta) = &tail.chain_metadata else {
            return;
        };
        for (protocol, count) in completed_subtrees(
            meta.sapling_commitment_tree_size,
            meta.orchard_commitment_tree_size,
            meta.ironwood_commitment_tree_size,
        ) {
            if count == 0 {
                continue;
            }
            self.store
                .set(
                    crate::subtree_cache::subtree_end_key(prefix, protocol, &tip.hash),
                    bytes::Bytes::copy_from_slice(&count.to_be_bytes()),
                    Some(rpc_cache::TIP_SCOPED_TTL_SECS),
                    Some(epoch),
                )
                .await;
        }
    }

    async fn prefetch_block_txs(
        &self,
        prefix: &str,
        epoch: u64,
        tip: &Tip,
        height: u64,
        tail: &BlockTail,
        max_txs: usize,
    ) {
        let n = tail.vtx.len();
        if n == 0 {
            return;
        }
        if n > max_txs {
            info!(network = %self.network, height, txs = n, max_txs, "block transactions not prefetched: block too large");
            return;
        }
        let bodies: Vec<Vec<u8>> = tail
            .vtx
            .iter()
            .filter(|t| !t.hash.is_empty())
            .map(|t| get_transaction_body(&t.hash))
            .collect();
        let results: Vec<Option<usize>> = futures_util::stream::iter(bodies)
            .map(|body| self.prefetch(prefix, epoch, tip, "GetTransaction", body))
            .buffer_unordered(TX_PARALLEL)
            .collect()
            .await;
        let fetched = results.iter().flatten().count();
        let bytes: usize = results.iter().flatten().sum();
        info!(
            network = %self.network,
            height,
            txs = n,
            fetched,
            bytes,
            "block transactions prefetched"
        );
    }

    /// Fetch `rpc` once and store it under the key a Client's identical request has, unless it
    /// is cached already. Returns the response size when an upstream call completed.
    async fn prefetch(
        &self,
        prefix: &str,
        epoch: u64,
        tip: &Tip,
        rpc: &str,
        body: Vec<u8>,
    ) -> Option<usize> {
        let path = format!("{RPC_PREFIX}{rpc}");
        let (key, ttl, validate): (String, Option<u64>, Option<HashSource>) =
            match rpc_cache::policy(prefix, "POST", CT, &path, &body, Some(&tip.hash)) {
                Policy::TipScoped { key } => (key, Some(rpc_cache::TIP_SCOPED_TTL_SECS), None),
                Policy::Validated { key, source } => (key, None, Some(source)),
                _ => return None,
            };
        if self
            .store
            .mget(vec![key.clone()])
            .await
            .into_iter()
            .next()
            .flatten()
            .is_some()
        {
            return None;
        }
        let miss = CacheMiss {
            key,
            epoch,
            ttl,
            validate,
            is_grpc: true,
            path: path.clone(),
            rpc: rpc.to_string(),
            pinned_height: None,
        };
        let store = self.store.clone();
        let network = self.network.clone();
        let (tx, rx) = tokio::sync::oneshot::channel::<usize>();
        let on_complete: crate::singleflight::OnComplete =
            Box::new(move |resp: crate::ohttp::InnerResponse| {
                tokio::spawn(async move {
                    let size = resp.body.len();
                    if let Ok(bytes) = bincode::serialize(&resp) {
                        let rpc = miss.rpc.clone();
                        if rpc_cache::should_admit(&bytes, true) {
                            rpc_cache::store(&*store, &network, miss, &bytes).await;
                            crate::health::record_cache_request(&network, &rpc, "prefetched");
                        }
                    }
                    let _ = tx.send(size);
                });
            });
        let resp = match self
            .flights
            .call(
                rpc,
                &path,
                body,
                None,
                MAX_CACHEABLE_SIZE,
                Some(on_complete),
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                debug!(network = %self.network, rpc, error = %e, "prefetch upstream call failed");
                return None;
            }
        };
        // Drain the stream: the flight completes (and stores) when the body ends.
        let mut s = resp.body;
        while let Some(item) = s.next().await {
            if item.is_err() {
                return None;
            }
        }
        rx.await.ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunked_stream::UpFrame;
    use crate::rpc_cache::{lookup, CacheLookup};
    use crate::singleflight::{RpcResponse, RpcSource};
    use crate::store::index_key;
    use crate::store::test_support::MemStore;
    use futures_util::future::BoxFuture;
    use std::sync::Mutex;

    /// Answers `GetLightdInfo`/`GetLatestTreeState` with a fixed body and `GetTransaction` with a
    /// RawTransaction at `tx_height`; records every call.
    struct FakeLwd {
        calls: Mutex<Vec<(String, Vec<u8>)>>,
        tx_height: u64,
        fail: bool,
        /// When set, every call waits for a permit before it answers (a slow lightwalletd).
        gate: Option<Arc<tokio::sync::Semaphore>>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    struct RawTx {
        #[prost(bytes, tag = "1")]
        data: Vec<u8>,
        #[prost(uint64, tag = "2")]
        height: u64,
    }

    impl RpcSource for FakeLwd {
        fn call(
            &self,
            path: String,
            body: Vec<u8>,
            _request_id: Option<uuid::Uuid>,
        ) -> BoxFuture<'static, anyhow::Result<RpcResponse>> {
            self.calls
                .lock()
                .unwrap()
                .push((path.clone(), body.clone()));
            let fail = self.fail;
            let gate = self.gate.clone();
            let msg = if path.ends_with("GetTransaction") {
                RawTx {
                    data: body.clone(),
                    height: self.tx_height,
                }
                .encode_to_vec()
            } else if path.ends_with("GetTreeState") {
                // The TreeState of the requested height, on the chain of every block 0xab..
                rpc_cache::TreeStateHead {
                    height: rpc_cache::BlockId::decode(&body[5..]).unwrap().height,
                    hash: hex::encode([0xab; 32]),
                }
                .encode_to_vec()
            } else {
                path.as_bytes().to_vec()
            };
            Box::pin(async move {
                if let Some(gate) = gate {
                    gate.acquire().await.expect("gate open").forget();
                }
                if fail {
                    anyhow::bail!("upstream down");
                }
                let frame = grpc_frame(&msg);
                let stream = async_stream::stream! {
                    yield Ok(UpFrame::Data(bytes::Bytes::from(frame)));
                    yield Ok(UpFrame::Trailers(vec![("grpc-status".to_string(), "0".to_string())]));
                };
                Ok(RpcResponse {
                    status: 200,
                    headers: vec![("content-type".to_string(), CT.to_string())],
                    body: Box::pin(stream),
                })
            })
        }
    }

    fn block(txids: &[[u8; 32]], sapling: u32, orchard: u32, ironwood: u32) -> Vec<u8> {
        BlockTail {
            vtx: txids.iter().map(|h| TxHead { hash: h.to_vec() }).collect(),
            chain_metadata: Some(ChainMetadata {
                sapling_commitment_tree_size: sapling,
                orchard_commitment_tree_size: orchard,
                ironwood_commitment_tree_size: ironwood,
            }),
        }
        .encode_to_vec()
    }

    struct Rig {
        store: Arc<MemStore>,
        lwd: Arc<FakeLwd>,
        prefetch: TipPrefetch,
        tip: Tip,
    }

    async fn rig(config: PrefetchConfig, fail: bool) -> Rig {
        rig_with_gate(config, fail, None).await
    }

    async fn rig_with_gate(
        config: PrefetchConfig,
        fail: bool,
        gate: Option<Arc<tokio::sync::Semaphore>>,
    ) -> Rig {
        let store = Arc::new(MemStore::default());
        let tip = Tip {
            height: 1000,
            hash: vec![0xab; 32],
        };
        store.tip.set(tip.clone());
        store.put(&index_key(&store.chain_prefix(), 1000), tip.hash.clone());
        let prefix = store.key_prefix(store.epoch);
        store.put(
            &block_key(&prefix, "", 1000),
            block(
                &[[1; 32], [2; 32]],
                3 * SUBTREE_LEAVES + 5,
                SUBTREE_LEAVES - 1,
                0,
            ),
        );
        let lwd = Arc::new(FakeLwd {
            calls: Mutex::new(Vec::new()),
            tx_height: 1000,
            fail,
            gate,
        });
        let flights = Arc::new(RpcFlights::new(lwd.clone(), "testnet".to_string()));
        let prefetch = TipPrefetch::new(store.clone(), flights, "testnet".to_string(), config);
        Rig {
            store,
            lwd,
            prefetch,
            tip,
        }
    }

    fn path(rpc: &str) -> String {
        format!("{RPC_PREFIX}{rpc}")
    }

    async fn is_hit(store: &MemStore, rpc: &str, body: &[u8]) -> bool {
        // Give the spawned store a moment.
        for _ in 0..50 {
            if let CacheLookup::Hit(_) =
                lookup(store, "testnet", "POST", CT, &path(rpc), body).await
            {
                return true;
            }
            tokio::task::yield_now().await;
        }
        false
    }

    #[tokio::test]
    async fn tip_answers_are_cached_under_a_clients_key() {
        let r = rig(
            PrefetchConfig {
                tip: true,
                block_txs: None,
                tree_state: false,
            },
            false,
        )
        .await;
        r.prefetch.run(&r.tip).await;
        assert!(is_hit(&r.store, "GetLightdInfo", &grpc_frame(&[])).await);
        assert!(is_hit(&r.store, "GetLatestTreeState", &grpc_frame(&[])).await);
        // A second tip run finds them cached: no new upstream calls.
        let n = r.lwd.calls.lock().unwrap().len();
        r.prefetch.run(&r.tip).await;
        assert_eq!(r.lwd.calls.lock().unwrap().len(), n);
        // Transactions are off.
        assert!(!r
            .lwd
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|(p, _)| p.ends_with("GetTransaction")));
    }

    #[tokio::test]
    async fn tip_answers_change_with_the_tip() {
        let r = rig(
            PrefetchConfig {
                tip: true,
                block_txs: None,
                tree_state: false,
            },
            false,
        )
        .await;
        r.prefetch.run(&r.tip).await;
        assert!(is_hit(&r.store, "GetLightdInfo", &grpc_frame(&[])).await);
        // A new tip (or a reorg to another hash): the old entry is not served.
        r.store.tip.set(Tip {
            height: 1001,
            hash: vec![0xcd; 32],
        });
        assert!(matches!(
            lookup(
                &*r.store,
                "testnet",
                "POST",
                CT,
                &path("GetLightdInfo"),
                &grpc_frame(&[])
            )
            .await,
            CacheLookup::Miss(_)
        ));
    }

    #[tokio::test]
    async fn end_markers_are_the_completed_subtree_counts() {
        let r = rig(
            PrefetchConfig {
                tip: true,
                block_txs: None,
                tree_state: false,
            },
            false,
        )
        .await;
        r.prefetch.run(&r.tip).await;
        let prefix = r.store.key_prefix(r.store.epoch);
        let sapling = r
            .store
            .get(&crate::subtree_cache::subtree_end_key(
                &prefix,
                0,
                &r.tip.hash,
            ))
            .unwrap();
        assert_eq!(u32::from_be_bytes(sapling[..].try_into().unwrap()), 3);
        // Orchard has no completed subtree yet: no marker.
        assert_eq!(
            r.store.get(&crate::subtree_cache::subtree_end_key(
                &prefix,
                1,
                &r.tip.hash
            )),
            None
        );
        // Ironwood has no completed subtree yet: no marker.
        assert_eq!(
            r.store.get(&crate::subtree_cache::subtree_end_key(
                &prefix,
                2,
                &r.tip.hash
            )),
            None
        );
        // Tip-scoped: it carries the tip-scoped expiry.
        assert_eq!(
            r.store.ttl(&crate::subtree_cache::subtree_end_key(
                &prefix,
                0,
                &r.tip.hash
            )),
            Some(Some(rpc_cache::TIP_SCOPED_TTL_SECS))
        );
    }

    #[tokio::test]
    async fn end_markers_do_not_wait_for_the_tip_rpcs() {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let r = rig_with_gate(
            PrefetchConfig {
                tip: true,
                block_txs: None,
                tree_state: false,
            },
            false,
            Some(gate.clone()),
        )
        .await;
        let prefetch = TipPrefetch {
            inner: r.prefetch.inner.clone(),
        };
        let tip = r.tip.clone();
        let run = tokio::spawn(async move { prefetch.run(&tip).await });
        let prefix = r.store.key_prefix(r.store.epoch);
        let key = crate::subtree_cache::subtree_end_key(&prefix, 0, &r.tip.hash);
        // lightwalletd has not answered any tip RPC yet, and the marker is already there.
        let mut found = false;
        for _ in 0..200 {
            if r.store.get(&key).is_some() {
                found = true;
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(found, "end marker written before the tip RPCs answered");
        assert!(!run.is_finished());
        // Let the tip RPCs answer: the run completes and caches them as before.
        gate.add_permits(TIP_RPCS.len());
        tokio::time::timeout(std::time::Duration::from_secs(5), run)
            .await
            .expect("prefetch finishes once lightwalletd answers")
            .unwrap();
        assert!(is_hit(&r.store, "GetLightdInfo", &grpc_frame(&[])).await);
    }

    #[test]
    fn completed_subtrees_round_down() {
        assert_eq!(completed_subtrees(0, 0, 0), [(0, 0), (1, 0), (2, 0)]);
        assert_eq!(
            completed_subtrees(SUBTREE_LEAVES - 1, SUBTREE_LEAVES, 2 * SUBTREE_LEAVES),
            [(0, 0), (1, 1), (2, 2)]
        );
        assert_eq!(
            completed_subtrees(5 * SUBTREE_LEAVES + 1, 0, SUBTREE_LEAVES - 1),
            [(0, 5), (1, 0), (2, 0)]
        );
    }

    #[tokio::test]
    async fn block_transactions_are_cached_and_validated() {
        let r = rig(
            PrefetchConfig {
                tip: false,
                block_txs: Some(100),
                tree_state: false,
            },
            false,
        )
        .await;
        r.prefetch.run(&r.tip).await;
        assert!(is_hit(&r.store, "GetTransaction", &get_transaction_body(&[1; 32])).await);
        assert!(is_hit(&r.store, "GetTransaction", &get_transaction_body(&[2; 32])).await);
        // A reorg replaces the block hash in the index: the prefetched entries are not served.
        r.store
            .put(&index_key(&r.store.chain_prefix(), 1000), vec![0xee; 32]);
        assert!(!matches!(
            lookup(
                &*r.store,
                "testnet",
                "POST",
                CT,
                &path("GetTransaction"),
                &get_transaction_body(&[1; 32])
            )
            .await,
            CacheLookup::Hit(_)
        ));
    }

    #[tokio::test]
    async fn large_blocks_are_skipped() {
        let r = rig(
            PrefetchConfig {
                tip: false,
                block_txs: Some(1),
                tree_state: false,
            },
            false,
        )
        .await;
        r.prefetch.run(&r.tip).await;
        assert!(r.lwd.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn off_by_default_does_nothing_and_upstream_failure_is_fail_open() {
        let r = rig(
            PrefetchConfig {
                tip: false,
                block_txs: None,
                tree_state: false,
            },
            false,
        )
        .await;
        r.prefetch.run(&r.tip).await;
        assert!(r.lwd.calls.lock().unwrap().is_empty());
        assert!(r.store.keys_with(":subtree_end:").is_empty());

        let r = rig(
            PrefetchConfig {
                tip: true,
                block_txs: Some(100),
                tree_state: false,
            },
            true,
        )
        .await;
        r.prefetch.run(&r.tip).await;
        assert!(matches!(
            lookup(
                &*r.store,
                "testnet",
                "POST",
                CT,
                &path("GetLightdInfo"),
                &grpc_frame(&[])
            )
            .await,
            CacheLookup::Miss(_)
        ));
    }

    fn tree_state_calls(lwd: &FakeLwd) -> Vec<u64> {
        lwd.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(p, _)| p.ends_with("GetTreeState"))
            .map(|(_, b)| rpc_cache::BlockId::decode(&b[5..]).unwrap().height)
            .collect()
    }

    #[tokio::test]
    async fn tree_state_of_new_tips_is_cached_under_a_clients_key() {
        let r = rig(
            PrefetchConfig {
                tip: false,
                block_txs: None,
                tree_state: true,
            },
            false,
        )
        .await;
        let body = |h: u64| rpc_cache::grpc_block_id(h, &[]);
        r.prefetch.run(&r.tip).await;
        assert!(is_hit(&r.store, "GetTreeState", &body(1000)).await);
        assert_eq!(tree_state_calls(&r.lwd), vec![1000]);

        // The same tip again: cached, no upstream call.
        r.prefetch.run(&r.tip).await;
        assert_eq!(tree_state_calls(&r.lwd), vec![1000]);

        // Tips the follower moved past while a run was busy are filled in.
        for h in 1001..=1003 {
            r.store
                .put(&index_key(&r.store.chain_prefix(), h), vec![0xab; 32]);
        }
        let tip = Tip {
            height: 1003,
            hash: vec![0xab; 32],
        };
        r.store.tip.set(tip.clone());
        r.prefetch.run(&tip).await;
        for h in 1001..=1003 {
            assert!(is_hit(&r.store, "GetTreeState", &body(h)).await, "{h}");
        }
        assert_eq!(tree_state_calls(&r.lwd), vec![1000, 1001, 1002, 1003]);
        // Nothing else was asked for.
        assert!(r
            .lwd
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|(p, _)| p.ends_with("GetTreeState")));
    }

    #[test]
    fn heights_since_the_last_run() {
        assert_eq!(since_last(0, 1000), 1000..=1000);
        assert_eq!(since_last(1000, 1000), 1000..=1000);
        assert_eq!(since_last(1005, 1000), 1000..=1000);
        assert_eq!(since_last(997, 1000), 998..=1000);
        assert_eq!(since_last(500, 1000), (1001 - MAX_BLOCKS_PER_TIP)..=1000);
    }

    #[tokio::test]
    async fn tree_state_is_not_prefetched_when_off() {
        let r = rig(
            PrefetchConfig {
                tip: true,
                block_txs: Some(100),
                tree_state: false,
            },
            false,
        )
        .await;
        r.prefetch.run(&r.tip).await;
        assert!(tree_state_calls(&r.lwd).is_empty());
    }
}

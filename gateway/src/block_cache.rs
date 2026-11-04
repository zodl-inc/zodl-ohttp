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

//! Per-block cache for `GetBlockRange`, validated against the chain follower's index.
//!
//! Every CompactBlock is one entry:
//!
//! - **Key** `{prefix}block:{pool_types}:{height}` where `prefix` is the per-request cache's
//!   `ohttp:{network}:{backend}:{epoch}:v{KEY_VERSION}:{policy_hash}:` and `pool_types` is the
//!   request's pool filter, canonicalised (sorted, deduplicated, comma-joined; empty when
//!   absent). The value is the serialized CompactBlock message (no 5-byte gRPC prefix).
//! - **No TTL.** A cached block is served only if its hash equals the follower's index hash at
//!   that height (`{chain}index:{height}`, fetched in the same MGET). Below the index window
//!   (depth > [`INDEX_WINDOW`]) cached blocks are trusted. Eviction is Redis `allkeys-lru`.
//!   The tip zone is cached like everything else, since validation replaces the old
//!   "never cache the tip" rule.
//! - **Permanent tier** (optional, `PermanentStore` on a disk-backed Redis-protocol store): a block whose height is at
//!   least `PERMANENT_DEPTH` (100) below a fresh tip and at or above the network's Sapling
//!   activation is final, so it is stored under `perm:{network}:block:v1:{pool}:{height}` with
//!   no TTL and no further index validation; it is read before the cache Redis for such heights
//!   (or, at or above the floor, for every height when the tip is unknown: an entry there is
//!   final by construction). Blocks
//!   above the finality depth stay in the cache Redis under index validation; a final block
//!   found in the cache Redis is copied to the permanent tier. Keys are per pool filter, like
//!   the cache tier: lightwalletd's filtering is never re-implemented here.
//! - **Three levels**: a per-process in-memory LRU (`local::LocalCache`, values up to its admission
//!   cap) is consulted before either store for block bytes; index entries always come from the
//!   cache Redis.
//! - **Serving** walks the heights in request order (ascending or descending, as lightwalletd
//!   does), streams every valid cached block at once, groups the missing heights into maximal
//!   contiguous gaps and fetches each gap from lightwalletd as one `GetBlockRange`, streaming
//!   and storing each block as it arrives.
//! - **Continuity**: at every boundary the next block must chain to the previous one
//!   (`prevHash`/`hash`). The last block is held back until its successor confirms it; on a
//!   mismatch the cached entries involved are deleted and the rest of the range is fetched from
//!   lightwalletd without consulting the cache again. Blocks with unknown hashes are not a
//!   mismatch, and two upstream blocks that do not chain are passed through as lightwalletd sent
//!   them.
//! - **Singleflight**: identical gap fetches share one upstream call (`singleflight::Flights`).

use crate::chunked_stream::UpFrame;
use crate::local::LocalCache;
use crate::singleflight::{Flights, Reader};
use crate::store::{
    hash_is_current, index_key, is_final, permanent_block_key, CacheStore, PermanentStore, Tip,
    Validity,
};
use anyhow::Result;
use bytes::{Bytes, BytesMut};
use futures_util::future::BoxFuture;
use futures_util::stream::BoxStream;
use futures_util::{Stream, StreamExt};
use prost::Message;
use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// The one RPC this cache serves (exact path; `GetBlockRangeNullifiers` is a different RPC).
pub const GET_BLOCK_RANGE_PATH: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlockRange";

/// Heights looked up per MGET while walking a range (block keys plus index keys).
const MGET_BATCH: usize = 64;
/// Blocks queued for storing per upstream fetch; one writer task drains the queue behind the
/// response. Writes are best-effort: a block that finds the queue full is served but not stored.
const STORE_QUEUE: usize = 4096;

#[derive(Clone, PartialEq, prost::Message)]
struct BlockId {
    #[prost(uint64, tag = "1")]
    height: u64,
    #[prost(bytes, tag = "2")]
    hash: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct BlockRange {
    #[prost(message, optional, tag = "1")]
    start: Option<BlockId>,
    #[prost(message, optional, tag = "2")]
    end: Option<BlockId>,
}

/// The chain-linking fields of a CompactBlock (compact_formats.proto: height 2, hash 3,
/// prevHash 4). Other fields are skipped by prost.
#[derive(Clone, PartialEq, prost::Message)]
pub struct CompactBlockHead {
    #[prost(uint64, tag = "2")]
    pub height: u64,
    #[prost(bytes, tag = "3")]
    pub hash: Vec<u8>,
    #[prost(bytes, tag = "4")]
    pub prev_hash: Vec<u8>,
}

/// A parsed `GetBlockRange` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRangeRequest {
    pub start: u64,
    pub end: u64,
    /// Pool filter values (field 3), as sent.
    pub pool_types: Vec<u64>,
    /// The raw bytes of every field other than start and end, appended verbatim to the gap
    /// requests sent upstream so lightwalletd applies the same filter.
    extra: Vec<u8>,
}

pub(crate) fn read_pb_varint(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let b = *bytes.get(*pos)?;
        *pos += 1;
        value |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}

impl BlockRangeRequest {
    /// Parse one uncompressed gRPC frame holding a `BlockRange`. Returns `None` for anything the
    /// cache cannot key: compressed or multi-frame bodies, missing or zero heights, unknown
    /// fields. Such requests are streamed from lightwalletd without the block cache.
    pub fn parse(body: &[u8]) -> Option<Self> {
        if body.len() < 5 || body[0] != 0 {
            return None;
        }
        let len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
        if body.len() != 5 + len {
            return None;
        }
        let msg = &body[5..];
        let mut pos = 0usize;
        let mut start = None;
        let mut end = None;
        let mut pool_types = Vec::new();
        let mut extra = Vec::new();
        while pos < msg.len() {
            let field_start = pos;
            let tag = read_pb_varint(msg, &mut pos)?;
            let field = tag >> 3;
            let wire_type = tag & 7;
            match (field, wire_type) {
                (1, 2) | (2, 2) => {
                    let l = usize::try_from(read_pb_varint(msg, &mut pos)?).ok()?;
                    let bytes = msg.get(pos..pos.checked_add(l)?)?;
                    pos += l;
                    let id = BlockId::decode(bytes).ok()?;
                    if field == 1 {
                        start = Some(id.height);
                    } else {
                        end = Some(id.height);
                    }
                }
                (3, 0) => {
                    pool_types.push(read_pb_varint(msg, &mut pos)?);
                    extra.extend_from_slice(&msg[field_start..pos]);
                }
                (3, 2) => {
                    let l = usize::try_from(read_pb_varint(msg, &mut pos)?).ok()?;
                    let packed = msg.get(pos..pos.checked_add(l)?)?;
                    let mut p = 0usize;
                    while p < packed.len() {
                        pool_types.push(read_pb_varint(packed, &mut p)?);
                    }
                    pos += l;
                    extra.extend_from_slice(&msg[field_start..pos]);
                }
                _ => return None,
            }
        }
        let (start, end) = (start?, end?);
        if start == 0 || end == 0 {
            return None;
        }
        Some(Self {
            start,
            end,
            pool_types,
            extra,
        })
    }

    pub fn ascending(&self) -> bool {
        self.start <= self.end
    }

    /// The heights in the order lightwalletd sends them.
    pub fn heights(&self) -> Vec<u64> {
        if self.ascending() {
            (self.start..=self.end).collect()
        } else {
            (self.end..=self.start).rev().collect()
        }
    }

    /// The canonical pool filter for the cache key: sorted, deduplicated, comma-joined.
    pub fn pool_key(&self) -> String {
        let mut pools = self.pool_types.clone();
        pools.sort_unstable();
        pools.dedup();
        pools
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    /// A gRPC request body for `GetBlockRange(start, end)` with this request's extra fields.
    pub fn grpc_body(start: u64, end: u64, extra: &[u8]) -> Vec<u8> {
        let mut msg = BlockRange {
            start: Some(BlockId {
                height: start,
                hash: vec![],
            }),
            end: Some(BlockId {
                height: end,
                hash: vec![],
            }),
        }
        .encode_to_vec();
        msg.extend_from_slice(extra);
        grpc_frame_vec(&msg)
    }
}

fn grpc_frame_vec(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + msg.len());
    out.push(0);
    out.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    out.extend_from_slice(msg);
    out
}

/// `0x00 || be32(len) || msg`.
pub fn grpc_frame(msg: &[u8]) -> Bytes {
    Bytes::from(grpc_frame_vec(msg))
}

/// Reassembles gRPC length-prefixed messages from arbitrary byte chunks.
#[derive(Default)]
pub struct GrpcSplitter {
    buf: BytesMut,
}

impl GrpcSplitter {
    /// Push bytes; returns every complete frame (5-byte prefix included).
    pub fn push(&mut self, data: &[u8]) -> Vec<Bytes> {
        self.buf.extend_from_slice(data);
        let mut frames = Vec::new();
        while self.buf.len() >= 5 {
            let len =
                u32::from_be_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]]) as usize;
            if self.buf.len() < 5 + len {
                break;
            }
            frames.push(self.buf.split_to(5 + len).freeze());
        }
        frames
    }

    /// Bytes left over that never formed a frame.
    pub fn remainder(&self) -> usize {
        self.buf.len()
    }
}

/// The block key of `height` under `prefix` for pool filter `pool`.
pub fn block_key(prefix: &str, pool: &str, height: u64) -> String {
    format!("{prefix}block:{pool}:{height}")
}

/// Pool filters seen by this process, so a reorg can delete every block key variant.
#[derive(Default)]
pub struct PoolKeys(parking_lot::Mutex<BTreeSet<String>>);

impl PoolKeys {
    pub fn note(&self, pool: &str) {
        self.0.lock().insert(pool.to_string());
    }

    /// Every pool key seen, always including the empty filter.
    pub fn all(&self) -> Vec<String> {
        let mut v: Vec<String> = self.0.lock().iter().cloned().collect();
        if !v.iter().any(|p| p.is_empty()) {
            v.insert(0, String::new());
        }
        v
    }
}

/// An upstream `GetBlockRange` answer.
pub struct UpstreamResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: BoxStream<'static, Result<UpFrame>>,
}

/// Where blocks are fetched from: lightwalletd, or a fake in tests.
pub trait BlockSource: Send + Sync {
    /// Send a `GetBlockRange` gRPC request body.
    fn fetch(&self, body: Vec<u8>) -> BoxFuture<'static, Result<UpstreamResponse>>;
}

/// One block as fetched or cached.
pub struct FetchedBlock {
    /// The decoded height, `None` when the message did not decode (then its hashes are empty, so
    /// it is never a continuity mismatch, and it is not stored).
    pub height: Option<u64>,
    pub hash: Vec<u8>,
    pub prev_hash: Vec<u8>,
    /// The full gRPC frame to forward.
    pub frame: Bytes,
}

impl FetchedBlock {
    pub fn from_frame(frame: Bytes) -> Self {
        let decoded = if frame.len() >= 5 && frame[0] == 0 {
            CompactBlockHead::decode(&frame[5..]).ok()
        } else {
            None
        };
        match decoded {
            Some(h) if h.height > 0 => Self {
                height: Some(h.height),
                hash: h.hash,
                prev_hash: h.prev_hash,
                frame,
            },
            _ => Self {
                height: None,
                hash: vec![],
                prev_hash: vec![],
                frame,
            },
        }
    }

    /// The cache value: the message without the gRPC prefix.
    pub fn message(&self) -> Bytes {
        self.frame.slice(5..)
    }
}

/// Whether `next` chains to `prev` in the given direction. Unknown hashes are not a mismatch.
fn chains(prev: &FetchedBlock, next: &FetchedBlock, ascending: bool) -> bool {
    if prev.hash.is_empty()
        || prev.prev_hash.is_empty()
        || next.hash.is_empty()
        || next.prev_hash.is_empty()
    {
        return true;
    }
    if ascending {
        next.prev_hash == prev.hash
    } else {
        prev.prev_hash == next.hash
    }
}

#[derive(Clone)]
enum FetchItem {
    Block(Arc<FetchedBlock>),
    /// The end of the upstream call: its trailers, or a synthesized `grpc-status` (14 when the
    /// call could not be made, 13 when it broke off) so the client sees a well-formed failure
    /// instead of a reset.
    Trailers(Vec<(String, String)>),
}

fn grpc_failure(code: &str, message: String) -> FetchItem {
    FetchItem::Trailers(vec![
        ("grpc-status".to_string(), code.to_string()),
        ("grpc-message".to_string(), message),
    ])
}

fn grpc_status_of(fields: &[(String, String)]) -> Option<&str> {
    fields
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("grpc-status"))
        .map(|(_, v)| v.as_str())
}

/// The per-block cache engine. One per gateway process.
pub struct BlockRangeCache {
    store: Arc<dyn CacheStore>,
    source: Arc<dyn BlockSource>,
    local: Option<Arc<LocalCache>>,
    pools: Arc<PoolKeys>,
    flights: Arc<Flights<FetchItem>>,
    network: String,
    /// The permanent tier and its lowest height.
    permanent: Option<Arc<dyn PermanentStore>>,
    permanent_min_height: u64,
}

/// Which store a block entry lives in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tier {
    Permanent,
    Cache,
}

/// A block found in a tier.
struct Found {
    block: Arc<FetchedBlock>,
    key: String,
    tier: Tier,
}

/// A block in the assembly, with where it came from.
struct Blk {
    block: Arc<FetchedBlock>,
    from_cache: bool,
    /// Position in the request's height list.
    idx: usize,
    key: String,
    tier: Tier,
}

enum Segment {
    Cached(Blk),
    Fetch { from: usize, to: usize },
}

impl BlockRangeCache {
    pub fn new(
        store: Arc<dyn CacheStore>,
        source: Arc<dyn BlockSource>,
        local: Option<Arc<LocalCache>>,
        pools: Arc<PoolKeys>,
        network: String,
    ) -> Self {
        Self {
            store,
            source,
            local,
            pools,
            flights: Arc::new(Flights::new()),
            network,
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

    pub fn pools(&self) -> Arc<PoolKeys> {
        self.pools.clone()
    }

    /// Whether `height` is read from the permanent tier: configured, at or above its floor and
    /// final against the tip, or the tip unknown (anything stored there is final).
    fn permanent_read(&self, height: u64, tip: Option<&Tip>) -> bool {
        self.permanent.is_some()
            && height >= self.permanent_min_height
            && tip.is_none_or(|t| is_final(height, t))
    }

    /// Whether `height` is written to the permanent tier: as above, but only against a fresh
    /// tip (never guess finality).
    fn permanent_write(&self, height: u64, tip: Option<&Tip>) -> bool {
        self.permanent.is_some()
            && height >= self.permanent_min_height
            && tip.is_some_and(|t| is_final(height, t))
    }

    /// Decode a stored entry, checking it is the block of `height`.
    fn decode_entry(bytes: &Bytes, height: u64) -> Option<FetchedBlock> {
        let block = FetchedBlock::from_frame(grpc_frame(bytes));
        (block.height == Some(height) && !block.hash.is_empty()).then_some(block)
    }

    /// Copy final blocks found in the cache tier to the permanent tier, off the request path.
    fn promote(&self, entries: Vec<(String, Bytes)>) {
        let Some(perm) = self.permanent.clone() else {
            return;
        };
        if entries.is_empty() {
            return;
        }
        let network = self.network.clone();
        tokio::spawn(async move {
            let mut n = 0u64;
            for (key, value) in entries {
                if perm.set(key, value).await {
                    n += 1;
                }
            }
            crate::health::record_block_permanent(&network, "promoted", n);
        });
    }

    /// Look `heights` up: the local LRU first for block bytes, then the permanent tier for the
    /// heights it covers, then one MGET on the cache Redis for the index entries of every
    /// remaining height plus the blocks the LRU did not have. A block is returned only when it
    /// is final (permanent tier) or current (index match, or below the window).
    async fn lookup(
        &self,
        prefix: &str,
        chain: &str,
        pool: &str,
        heights: &[u64],
    ) -> Vec<Option<Found>> {
        let n = heights.len();
        let tip = self.store.tip_cell().get();
        let mut out: Vec<Option<Found>> = (0..n).map(|_| None).collect();

        // 1. Permanent tier.
        if let Some(perm) = &self.permanent {
            let mut pending: Vec<usize> = Vec::new();
            for i in 0..n {
                if !self.permanent_read(heights[i], tip.as_ref()) {
                    continue;
                }
                let key = permanent_block_key(&self.network, pool, heights[i]);
                match self.local.as_ref().and_then(|l| l.get(&key)) {
                    Some(bytes) => match Self::decode_entry(&bytes, heights[i]) {
                        Some(block) => {
                            out[i] = Some(Found {
                                block: Arc::new(block),
                                key,
                                tier: Tier::Permanent,
                            })
                        }
                        None => {
                            if let Some(l) = &self.local {
                                l.invalidate(&key);
                            }
                            pending.push(i);
                        }
                    },
                    None => pending.push(i),
                }
            }
            if !pending.is_empty() {
                let keys: Vec<String> = pending
                    .iter()
                    .map(|i| permanent_block_key(&self.network, pool, heights[*i]))
                    .collect();
                let values = perm.mget(keys.clone()).await;
                let mut hits = 0u64;
                let mut bad = Vec::new();
                for (j, i) in pending.iter().copied().enumerate() {
                    let Some(bytes) = values.get(j).cloned().flatten() else {
                        continue;
                    };
                    match Self::decode_entry(&bytes, heights[i]) {
                        Some(block) => {
                            hits += 1;
                            if let Some(l) = &self.local {
                                l.insert(keys[j].clone(), bytes);
                            }
                            out[i] = Some(Found {
                                block: Arc::new(block),
                                key: keys[j].clone(),
                                tier: Tier::Permanent,
                            });
                        }
                        None => bad.push(keys[j].clone()),
                    }
                }
                crate::health::record_block_permanent(&self.network, "hit", hits);
                crate::health::record_block_permanent(
                    &self.network,
                    "miss",
                    pending.len() as u64 - hits,
                );
                if !bad.is_empty() {
                    warn!(network = %self.network, n = bad.len(), "undecodable permanent entries dropped");
                    perm.del(bad).await;
                }
            }
        }

        // 2. Cache tier for everything still missing.
        let rest: Vec<usize> = (0..n).filter(|i| out[*i].is_none()).collect();
        if rest.is_empty() {
            return out;
        }
        let m = rest.len();
        let block_keys: Vec<String> = rest
            .iter()
            .map(|i| block_key(prefix, pool, heights[*i]))
            .collect();
        let local: Vec<Option<Bytes>> = match &self.local {
            Some(l) => block_keys.iter().map(|k| l.get(k)).collect(),
            None => vec![None; m],
        };
        let mut keys: Vec<String> = rest.iter().map(|i| index_key(chain, heights[*i])).collect();
        let redis_slots: Vec<usize> = (0..m).filter(|j| local[*j].is_none()).collect();
        keys.extend(redis_slots.iter().map(|j| block_keys[*j].clone()));
        let values = self.store.mget(keys).await;

        let mut redis_pos = m;
        let mut stale_keys = Vec::new();
        let mut promote = Vec::new();
        for (j, i) in rest.iter().copied().enumerate() {
            let index_hash = values.get(j).cloned().flatten();
            let (bytes, from_local) = match &local[j] {
                Some(b) => (Some(b.clone()), true),
                None => {
                    let v = values.get(redis_pos).cloned().flatten();
                    redis_pos += 1;
                    (v, false)
                }
            };
            let Some(bytes) = bytes else {
                continue;
            };
            let Some(block) = Self::decode_entry(&bytes, heights[i]) else {
                // Undecodable or mislabelled entry: drop it and treat as a miss.
                stale_keys.push(block_keys[j].clone());
                continue;
            };
            match hash_is_current(&block.hash, heights[i], index_hash.as_deref(), tip.as_ref()) {
                Validity::Current => {
                    if !from_local {
                        if let Some(l) = &self.local {
                            l.insert(block_keys[j].clone(), bytes.clone());
                        }
                    }
                    if self.permanent_write(heights[i], tip.as_ref()) {
                        promote.push((
                            permanent_block_key(&self.network, pool, heights[i]),
                            bytes.clone(),
                        ));
                    }
                    out[i] = Some(Found {
                        block: Arc::new(block),
                        key: block_keys[j].clone(),
                        tier: Tier::Cache,
                    });
                }
                Validity::Stale => {
                    crate::health::record_block_cache_stale(&self.network);
                    stale_keys.push(block_keys[j].clone());
                }
                Validity::Unknown => {
                    crate::health::record_block_cache_unvalidated(&self.network);
                    if from_local {
                        // Cannot validate the local copy: fall back to Redis next time.
                        if let Some(l) = &self.local {
                            l.invalidate(&block_keys[j]);
                        }
                    }
                }
            }
        }
        if !stale_keys.is_empty() {
            if let Some(l) = &self.local {
                for k in &stale_keys {
                    l.invalidate(k);
                }
            }
            self.store.del(stale_keys).await;
        }
        self.promote(promote);
        out
    }

    /// Start or join the upstream fetch of `[start, end]` (request order) with `extra` fields.
    fn fetch_blocks(
        self: &Arc<Self>,
        start: u64,
        end: u64,
        extra: &[u8],
        prefix: &str,
        pool: &str,
        epoch: u64,
    ) -> Reader<FetchItem> {
        let flight_key = format!("{start}-{end}:{pool}:{}", hex::encode(extra));
        let this = self.clone();
        let body = BlockRangeRequest::grpc_body(start, end, extra);
        let prefix = prefix.to_string();
        let pool = pool.to_string();
        let (reader, joined) =
            self.flights
                .join_or_start(flight_key, move |shared| -> BoxFuture<'static, ()> {
                    Box::pin(async move {
                        this.run_fetch(&shared, body, &prefix, &pool, epoch).await;
                    })
                });
        if joined {
            crate::health::record_singleflight_join(&self.network, "GetBlockRange");
            debug!(network = %self.network, start, end, "singleflight join");
        }
        reader
    }

    /// The upstream call behind one singleflight entry: forwards every frame to the replay
    /// buffer and stores each decoded block.
    async fn run_fetch(
        self: &Arc<Self>,
        shared: &Arc<crate::singleflight::Shared<FetchItem>>,
        body: Vec<u8>,
        prefix: &str,
        pool: &str,
        epoch: u64,
    ) {
        crate::health::record_upstream_call(&self.network, "GetBlockRange");
        let resp = match self.source.fetch(body).await {
            Ok(r) => r,
            Err(e) => {
                warn!(network = %self.network, error = %e, "block range upstream call failed");
                shared.push(grpc_failure("14", format!("upstream unavailable: {e}")));
                return;
            }
        };
        if resp.status != 200 {
            shared.push(grpc_failure(
                "14",
                format!("upstream answered HTTP {}", resp.status),
            ));
            return;
        }
        // Trailers-only response: the status came in the headers.
        if grpc_status_of(&resp.headers).is_some() {
            let trailers: Vec<(String, String)> = resp
                .headers
                .into_iter()
                .filter(|(k, _)| k.to_ascii_lowercase().starts_with("grpc-"))
                .collect();
            shared.push(FetchItem::Trailers(trailers));
            return;
        }

        // One writer per fetch stores the blocks in order behind the response; the fetch never
        // waits on Redis. Final blocks go to the permanent tier, the rest to the cache Redis.
        let (store_tx, mut store_rx) = mpsc::channel::<(Tier, String, Bytes)>(STORE_QUEUE);
        let store = self.store.clone();
        let permanent = self.permanent.clone();
        let network = self.network.clone();
        tokio::spawn(async move {
            while let Some((tier, key, value)) = store_rx.recv().await {
                match (tier, &permanent) {
                    (Tier::Permanent, Some(p)) => {
                        if p.set(key, value).await {
                            crate::health::record_block_permanent(&network, "stored", 1);
                        }
                    }
                    _ => store.set(key, value, None, Some(epoch)).await,
                }
            }
        });
        let tip = self.store.tip_cell().get();

        let mut splitter = GrpcSplitter::default();
        let mut trailers: Vec<(String, String)> = Vec::new();
        let mut blocks = 0u64;
        let mut body = resp.body;
        while let Some(frame) = body.next().await {
            match frame {
                Ok(UpFrame::Data(data)) => {
                    for frame in splitter.push(&data) {
                        let block = Arc::new(FetchedBlock::from_frame(frame));
                        blocks += 1;
                        self.maybe_store(&store_tx, &block, prefix, pool, tip.as_ref());
                        shared.push(FetchItem::Block(block));
                    }
                }
                Ok(UpFrame::Trailers(t)) => trailers.extend(t),
                Err(e) => {
                    warn!(network = %self.network, error = %e, "block range upstream stream failed");
                    crate::health::record_upstream_blocks(&self.network, blocks);
                    shared.push(grpc_failure("13", format!("upstream stream failed: {e}")));
                    return;
                }
            }
        }
        crate::health::record_upstream_blocks(&self.network, blocks);
        if splitter.remainder() > 0 {
            shared.push(grpc_failure(
                "13",
                "upstream ended inside a gRPC frame".to_string(),
            ));
            return;
        }
        if grpc_status_of(&trailers).is_none() {
            trailers.push(("grpc-status".to_string(), "13".to_string()));
            trailers.push((
                "grpc-message".to_string(),
                "lightwalletd closed stream without grpc-status".to_string(),
            ));
        }
        shared.push(FetchItem::Trailers(trailers));
    }

    /// Queue `block` for the fetch's writer (permanent tier when final against `tip`, else the
    /// cache Redis) and put it in the local LRU under that tier's key.
    fn maybe_store(
        &self,
        store_tx: &mpsc::Sender<(Tier, String, Bytes)>,
        block: &Arc<FetchedBlock>,
        prefix: &str,
        pool: &str,
        tip: Option<&Tip>,
    ) {
        let Some(height) = block.height else { return };
        if block.hash.is_empty() {
            return;
        }
        let (tier, key) = if self.permanent_write(height, tip) {
            (
                Tier::Permanent,
                permanent_block_key(&self.network, pool, height),
            )
        } else {
            (Tier::Cache, block_key(prefix, pool, height))
        };
        if let Some(l) = &self.local {
            l.insert(key.clone(), block.message());
        }
        if store_tx.try_send((tier, key, block.message())).is_err() {
            debug!(network = %self.network, height, "block cache write skipped (store queue full)");
        }
    }

    /// Serve a `GetBlockRange`: the body frames and the final trailers of the inner response
    /// (status 200, `content-type: application/grpc`). The trailers are an upstream error's when
    /// a gap fetch fails, otherwise a synthesized `grpc-status: 0`.
    pub fn serve(
        self: &Arc<Self>,
        req: BlockRangeRequest,
    ) -> impl Stream<Item = Result<UpFrame>> + Send + 'static {
        let this = self.clone();
        async_stream::stream! {
            let heights = req.heights();
            let ascending = req.ascending();
            let pool = req.pool_key();
            this.pools.note(&pool);
            let extra = req.extra.clone();
            let n = heights.len();
            let epoch = this.store.epoch().await;
            let prefix = this.store.key_prefix(epoch);
            let chain = this.store.chain_prefix();

            let mut idx = 0usize;
            let mut use_cache = true;
            let mut held: Option<Blk> = None;
            let mut lookahead: VecDeque<(usize, Option<Found>)> = VecDeque::new();
            let mut hits = 0u64;
            let mut misses = 0u64;
            let mut final_trailers: Option<Vec<(String, String)>> = None;

            'outer: while idx < n {
                // 1. Decide the next segment.
                let segment = if !use_cache {
                    Segment::Fetch { from: idx, to: n - 1 }
                } else {
                    if lookahead.is_empty() {
                        let to = (idx + MGET_BATCH).min(n);
                        let found = this.lookup(&prefix, &chain, &pool, &heights[idx..to]).await;
                        lookahead.extend((idx..to).zip(found));
                    }
                    let (i, cached) = lookahead.pop_front().expect("lookahead filled");
                    debug_assert_eq!(i, idx);
                    match cached {
                        Some(found) => {
                            hits += 1;
                            Segment::Cached(Blk {
                                block: found.block,
                                from_cache: true,
                                idx,
                                key: found.key,
                                tier: found.tier,
                            })
                        }
                        None => {
                            misses += 1;
                            // Extend the gap over every following miss (maximal contiguous gap).
                            let mut to = idx;
                            loop {
                                if lookahead.is_empty() {
                                    if to + 1 >= n {
                                        break;
                                    }
                                    let batch_end = (to + 1 + MGET_BATCH).min(n);
                                    let found = this.lookup(&prefix, &chain, &pool, &heights[to + 1..batch_end]).await;
                                    lookahead.extend((to + 1..batch_end).zip(found));
                                }
                                match lookahead.front() {
                                    Some((_, None)) => {
                                        lookahead.pop_front();
                                        to += 1;
                                        misses += 1;
                                    }
                                    _ => break,
                                }
                            }
                            Segment::Fetch { from: idx, to }
                        }
                    }
                };

                // 2. Run it, holding back one block until its successor confirms the chain.
                match segment {
                    Segment::Cached(blk) => {
                        match held.take() {
                            None => held = Some(blk),
                            Some(prev) if chains(&prev.block, &blk.block, ascending) => {
                                yield Ok(UpFrame::Data(prev.block.frame.clone()));
                                held = Some(blk);
                            }
                            Some(prev) => {
                                crate::health::record_block_cache_continuity_mismatch(&this.network);
                                warn!(
                                    network = %this.network,
                                    prev_height = ?prev.block.height,
                                    next_height = ?blk.block.height,
                                    "block cache continuity mismatch; refetching the rest of the range"
                                );
                                let mut stale = vec![(blk.key.clone(), blk.tier)];
                                if prev.from_cache {
                                    stale.push((prev.key.clone(), prev.tier));
                                }
                                this.drop_entries(stale).await;
                                use_cache = false;
                                lookahead.clear();
                                if prev.from_cache {
                                    idx = prev.idx;
                                } else {
                                    yield Ok(UpFrame::Data(prev.block.frame.clone()));
                                    idx = blk.idx;
                                }
                                continue 'outer;
                            }
                        }
                        idx += 1;
                    }
                    Segment::Fetch { from, to } => {
                        let mut reader = this.fetch_blocks(heights[from], heights[to], &extra, &prefix, &pool, epoch);
                        let mut restart: Option<usize> = None;
                        let mut pos = from;
                        while let Some(item) = reader.next().await {
                            match item {
                                FetchItem::Block(block) => {
                                    let blk = Blk {
                                        block,
                                        from_cache: false,
                                        idx: pos.min(to),
                                        key: String::new(),
                                        tier: Tier::Cache,
                                    };
                                    pos += 1;
                                    match held.take() {
                                        None => held = Some(blk),
                                        Some(prev) if chains(&prev.block, &blk.block, ascending) => {
                                            yield Ok(UpFrame::Data(prev.block.frame.clone()));
                                            held = Some(blk);
                                        }
                                        Some(prev) if prev.from_cache => {
                                            // The cached block we were holding is stale: drop it,
                                            // refetch from its height without the cache.
                                            crate::health::record_block_cache_continuity_mismatch(&this.network);
                                            warn!(
                                                network = %this.network,
                                                prev_height = ?prev.block.height,
                                                next_height = ?blk.block.height,
                                                "cached block does not chain to upstream; refetching"
                                            );
                                            this.drop_entries(vec![(prev.key.clone(), prev.tier)]).await;
                                            use_cache = false;
                                            lookahead.clear();
                                            restart = Some(prev.idx);
                                            break;
                                        }
                                        Some(prev) => {
                                            // Two upstream blocks that do not chain: lightwalletd's
                                            // word is final, pass them through.
                                            yield Ok(UpFrame::Data(prev.block.frame.clone()));
                                            held = Some(blk);
                                        }
                                    }
                                }
                                FetchItem::Trailers(t) => {
                                    if grpc_status_of(&t) != Some("0") {
                                        final_trailers = Some(t);
                                        break 'outer;
                                    }
                                }
                            }
                        }
                        idx = match restart {
                            Some(r) => r,
                            None => to + 1,
                        };
                    }
                }
            }

            if let Some(prev) = held.take() {
                yield Ok(UpFrame::Data(prev.block.frame.clone()));
            }
            crate::health::record_block_cache_hits(&this.network, hits);
            crate::health::record_block_cache_misses(&this.network, misses);
            debug!(network = %this.network, start = req.start, end = req.end, hits, misses, "block range served");
            yield Ok(UpFrame::Trailers(
                final_trailers.unwrap_or_else(|| vec![("grpc-status".to_string(), "0".to_string())]),
            ));
        }
    }

    /// Delete entries from the local LRU and from the tier each lives in.
    async fn drop_entries(&self, keys: Vec<(String, Tier)>) {
        if let Some(l) = &self.local {
            for (k, _) in &keys {
                l.invalidate(k);
            }
        }
        let (perm, cache): (Vec<_>, Vec<_>) =
            keys.into_iter().partition(|(_, t)| *t == Tier::Permanent);
        if !cache.is_empty() {
            self.store
                .del(cache.into_iter().map(|(k, _)| k).collect())
                .await;
        }
        if let (Some(p), false) = (&self.permanent, perm.is_empty()) {
            p.del(perm.into_iter().map(|(k, _)| k).collect()).await;
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// A full CompactBlock as lightwalletd encodes it (fields 1..=6; vtx omitted).
    #[derive(Clone, PartialEq, prost::Message)]
    struct FullBlock {
        #[prost(uint32, tag = "1")]
        proto_version: u32,
        #[prost(uint64, tag = "2")]
        height: u64,
        #[prost(bytes, tag = "3")]
        hash: Vec<u8>,
        #[prost(bytes, tag = "4")]
        prev_hash: Vec<u8>,
        #[prost(uint32, tag = "5")]
        time: u32,
        #[prost(bytes, tag = "6")]
        header: Vec<u8>,
    }

    pub fn hash_at(height: u64, fork: u8) -> Vec<u8> {
        Sha256::digest([&height.to_be_bytes()[..], &[fork]].concat()).to_vec()
    }

    fn full_block(height: u64, hash: Vec<u8>, prev_hash: Vec<u8>) -> Vec<u8> {
        FullBlock {
            proto_version: 4,
            height,
            hash,
            prev_hash,
            time: 1_700_000_000 + height as u32,
            header: vec![0xab; 40 + (height % 7) as usize],
        }
        .encode_to_vec()
    }

    /// A block of `fork` whose parent is also of `fork` (a stale entry for tests).
    pub fn block_msg(height: u64, fork: u8) -> Vec<u8> {
        full_block(height, hash_at(height, fork), hash_at(height - 1, fork))
    }

    /// The fake lightwalletd's chain: a tip and fork segments (`reorg_from(h, f)` makes every
    /// height >= h belong to fork `f`). Shared by the block cache and chain follower fakes.
    pub struct FakeChain {
        tip: AtomicU64,
        forks: Mutex<Vec<(u64, u8)>>,
        pub latest_calls: AtomicUsize,
        pub range_calls: Mutex<Vec<(u64, u64)>>,
        pub down: AtomicBool,
    }

    impl FakeChain {
        pub fn new(tip: u64) -> Self {
            Self {
                tip: AtomicU64::new(tip),
                forks: Mutex::new(vec![]),
                latest_calls: AtomicUsize::new(0),
                range_calls: Mutex::new(vec![]),
                down: AtomicBool::new(false),
            }
        }
        pub fn tip(&self) -> u64 {
            self.tip.load(Ordering::SeqCst)
        }
        pub fn set_tip(&self, tip: u64) {
            self.tip.store(tip, Ordering::SeqCst);
        }
        pub fn reorg_from(&self, height: u64, fork: u8) {
            self.forks.lock().unwrap().push((height, fork));
        }
        pub fn fork_at(&self, height: u64) -> u8 {
            self.forks
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|(from, _)| height >= *from)
                .map(|(_, f)| *f)
                .unwrap_or(0)
        }
        pub fn hash_at(&self, height: u64) -> Vec<u8> {
            hash_at(height, self.fork_at(height))
        }
        /// The canonical CompactBlock at `height`, chained to the canonical parent.
        pub fn msg(&self, height: u64) -> Vec<u8> {
            full_block(height, self.hash_at(height), self.hash_at(height - 1))
        }
        pub fn frames_for(&self, start: u64, end: u64) -> Vec<Bytes> {
            let heights: Vec<u64> = if start <= end {
                (start..=end).collect()
            } else {
                (end..=start).rev().collect()
            };
            heights
                .into_iter()
                .filter(|h| *h <= self.tip())
                .map(|h| grpc_frame(&self.msg(h)))
                .collect()
        }
    }

    /// A fake lightwalletd `GetBlockRange`, splitting its output at odd byte offsets.
    pub struct FakeLwd {
        pub chain: Arc<FakeChain>,
        pub calls: Mutex<Vec<(u64, u64, Vec<u8>)>>,
        pub delay: Option<std::time::Duration>,
    }

    impl FakeLwd {
        pub fn new(chain: Arc<FakeChain>) -> Self {
            Self {
                chain,
                calls: Mutex::new(vec![]),
                delay: None,
            }
        }
    }

    impl BlockSource for FakeLwd {
        fn fetch(&self, body: Vec<u8>) -> BoxFuture<'static, Result<UpstreamResponse>> {
            let req = BlockRangeRequest::parse(&body).expect("gap request parses");
            self.calls
                .lock()
                .unwrap()
                .push((req.start, req.end, req.extra.clone()));
            let delay = self.delay;
            let chain = self.chain.clone();
            Box::pin(async move {
                let mut all = Vec::new();
                for f in chain.frames_for(req.start, req.end) {
                    all.extend_from_slice(&f);
                }
                let body = async_stream::stream! {
                    if let Some(d) = delay {
                        tokio::time::sleep(d).await;
                    }
                    // 37-byte pieces so frames straddle Data boundaries.
                    for piece in all.chunks(37) {
                        yield Ok(UpFrame::Data(Bytes::copy_from_slice(piece)));
                    }
                    yield Ok(UpFrame::Trailers(vec![("grpc-status".to_string(), "0".to_string())]));
                };
                Ok(UpstreamResponse {
                    status: 200,
                    headers: vec![("content-type".to_string(), "application/grpc".to_string())],
                    body: Box::pin(body),
                })
            })
        }
    }

    pub fn concat(frames: &[Bytes]) -> Vec<u8> {
        frames.iter().flat_map(|b| b.to_vec()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::store::test_support::{MemPermanent, MemStore};
    use crate::store::Tip;

    fn request(start: u64, end: u64) -> BlockRangeRequest {
        BlockRangeRequest::parse(&BlockRangeRequest::grpc_body(start, end, &[])).unwrap()
    }

    async fn collect(
        cache: &Arc<BlockRangeCache>,
        req: BlockRangeRequest,
    ) -> (Vec<u8>, Vec<(String, String)>) {
        let frames: Vec<UpFrame> = cache
            .serve(req)
            .map(|f| f.expect("no stream error"))
            .collect()
            .await;
        let mut body = Vec::new();
        let mut trailers = Vec::new();
        for f in frames {
            match f {
                UpFrame::Data(d) => body.extend_from_slice(&d),
                UpFrame::Trailers(t) => trailers.extend(t),
            }
        }
        (body, trailers)
    }

    struct Rig {
        store: Arc<MemStore>,
        chain: Arc<FakeChain>,
        lwd: Arc<FakeLwd>,
        cache: Arc<BlockRangeCache>,
        local: Option<Arc<LocalCache>>,
        permanent: Option<Arc<MemPermanent>>,
    }

    impl Rig {
        fn new(chain_tip: u64, known_tip: Option<u64>, local: bool) -> Self {
            Self::build(chain_tip, known_tip, local, None)
        }

        /// A rig with the permanent tier for heights `>= min_height`.
        fn with_permanent(
            chain_tip: u64,
            known_tip: Option<u64>,
            local: bool,
            min_height: u64,
        ) -> Self {
            Self::build(chain_tip, known_tip, local, Some(min_height))
        }

        fn build(
            chain_tip: u64,
            known_tip: Option<u64>,
            local: bool,
            permanent_min: Option<u64>,
        ) -> Self {
            let store = Arc::new(MemStore::default());
            let chain = Arc::new(FakeChain::new(chain_tip));
            if let Some(t) = known_tip {
                store.tip.set(Tip {
                    height: t,
                    hash: chain.hash_at(t),
                });
            }
            let lwd = Arc::new(FakeLwd::new(chain.clone()));
            let local = local.then(|| Arc::new(LocalCache::new(1 << 24, "testnet".to_string())));
            let cache = BlockRangeCache::new(
                store.clone(),
                lwd.clone(),
                local.clone(),
                Arc::new(PoolKeys::default()),
                "testnet".to_string(),
            );
            let (cache, permanent) = match permanent_min {
                Some(min) => {
                    let p = Arc::new(MemPermanent::default());
                    (cache.with_permanent(p.clone(), min), Some(p))
                }
                None => (cache, None),
            };
            Self {
                store,
                chain,
                lwd,
                cache: Arc::new(cache),
                local,
                permanent,
            }
        }

        fn key(&self, height: u64) -> String {
            block_key(&self.store.key_prefix(42), "", height)
        }

        fn perm_key(&self, height: u64) -> String {
            permanent_block_key("testnet", "", height)
        }

        fn perm(&self) -> &Arc<MemPermanent> {
            self.permanent.as_ref().expect("permanent tier")
        }

        /// Put the canonical block at `height` in the store (and the index when `indexed`).
        fn cache_block(&self, height: u64, indexed: bool) {
            self.store.put(&self.key(height), self.chain.msg(height));
            if indexed {
                self.index(height, self.chain.hash_at(height));
            }
        }

        fn index(&self, height: u64, hash: Vec<u8>) {
            self.store
                .put(&index_key(&self.store.chain_prefix(), height), hash);
        }

        fn calls(&self) -> Vec<(u64, u64)> {
            self.lwd
                .calls
                .lock()
                .unwrap()
                .iter()
                .map(|(s, e, _)| (*s, *e))
                .collect()
        }
    }

    /// Wait for the spawned store writes.
    async fn settle() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn parses_pool_types_and_rejects_unknown_fields() {
        let mut body = BlockRangeRequest::grpc_body(10, 20, &[]);
        assert_eq!(
            BlockRangeRequest::parse(&body),
            Some(BlockRangeRequest {
                start: 10,
                end: 20,
                pool_types: vec![],
                extra: vec![],
            })
        );
        // Field 3, unpacked varints 2 then 1: canonical key "1,2", extra bytes preserved.
        let extra = vec![0x18, 2, 0x18, 1];
        body = BlockRangeRequest::grpc_body(10, 20, &extra);
        let req = BlockRangeRequest::parse(&body).unwrap();
        assert_eq!(req.pool_types, vec![2, 1]);
        assert_eq!(req.pool_key(), "1,2");
        assert_eq!(req.extra, extra);
        // Packed form gives the same key.
        let packed =
            BlockRangeRequest::parse(&BlockRangeRequest::grpc_body(10, 20, &[0x1a, 2, 2, 1]))
                .unwrap();
        assert_eq!(packed.pool_key(), "1,2");
        // Unknown field 9 and height 0 are not cacheable.
        assert!(
            BlockRangeRequest::parse(&BlockRangeRequest::grpc_body(10, 20, &[0x48, 1])).is_none()
        );
        assert!(BlockRangeRequest::parse(&BlockRangeRequest::grpc_body(0, 20, &[])).is_none());
        // Compressed frame.
        let mut compressed = BlockRangeRequest::grpc_body(10, 20, &[]);
        compressed[0] = 1;
        assert!(BlockRangeRequest::parse(&compressed).is_none());
        // A field length near 2^64 (the offset plus it would overflow) is refused, not a panic.
        for tag in [0x0a, 0x12, 0x1a] {
            let mut msg = vec![tag];
            msg.extend_from_slice(&[0xff; 9]);
            msg.push(0x01);
            assert!(BlockRangeRequest::parse(&grpc_frame_vec(&msg)).is_none());
        }
    }

    #[tokio::test]
    async fn interleaved_hits_and_gaps_equal_upstream_byte_for_byte() {
        // Tip far above: the range is below the index window, cached blocks are trusted.
        let rig = Rig::new(10_000, Some(10_000), false);
        for h in (1000..=1004).chain(1010..=1011) {
            rig.cache_block(h, false);
        }
        let (body, trailers) = collect(&rig.cache, request(1000, 1020)).await;
        assert_eq!(body, concat(&rig.chain.frames_for(1000, 1020)));
        assert_eq!(trailers, vec![("grpc-status".to_string(), "0".to_string())]);
        // Two maximal gaps, nothing else, went upstream.
        assert_eq!(rig.calls(), vec![(1005, 1009), (1012, 1020)]);
        settle().await;
        // Every fetched block is now stored, without a TTL.
        for h in 1000..=1020 {
            assert_eq!(
                rig.store.get(&rig.key(h)),
                Some(Bytes::from(rig.chain.msg(h))),
                "height {h}"
            );
            assert_eq!(rig.store.ttl(&rig.key(h)), Some(None), "no TTL at {h}");
        }
    }

    #[tokio::test]
    async fn descending_ranges_walk_in_request_order() {
        let rig = Rig::new(10_000, Some(10_000), false);
        for h in 1003..=1005 {
            rig.cache_block(h, false);
        }
        let (body, _) = collect(&rig.cache, request(1008, 1000)).await;
        assert_eq!(body, concat(&rig.chain.frames_for(1008, 1000)));
        assert_eq!(rig.calls(), vec![(1008, 1006), (1002, 1000)]);
    }

    #[tokio::test]
    async fn pool_types_key_and_upstream_filter() {
        let rig = Rig::new(10_000, Some(10_000), false);
        let extra = vec![0x18, 2];
        let req =
            BlockRangeRequest::parse(&BlockRangeRequest::grpc_body(500, 503, &extra)).unwrap();
        let (body, _) = collect(&rig.cache, req).await;
        assert_eq!(body, concat(&rig.chain.frames_for(500, 503)));
        assert_eq!(
            rig.lwd.calls.lock().unwrap().clone(),
            vec![(500, 503, extra)]
        );
        settle().await;
        let prefix = rig.store.key_prefix(42);
        assert!(rig.store.get(&block_key(&prefix, "2", 500)).is_some());
        assert!(rig.store.get(&rig.key(500)).is_none());
        assert_eq!(
            rig.cache.pools().all(),
            vec!["".to_string(), "2".to_string()]
        );
    }

    #[tokio::test]
    async fn validated_stale_block_is_dropped_and_refetched() {
        // Inside the window: 2000..=2010 indexed; the cached 2005 is from another fork.
        let rig = Rig::new(2100, Some(2100), false);
        for h in 2000..=2010 {
            if h == 2005 {
                rig.store.put(&rig.key(h), block_msg(h, 1));
                rig.index(h, rig.chain.hash_at(h));
            } else {
                rig.cache_block(h, true);
            }
        }
        let (body, trailers) = collect(&rig.cache, request(2000, 2010)).await;
        assert_eq!(body, concat(&rig.chain.frames_for(2000, 2010)));
        assert_eq!(trailers, vec![("grpc-status".to_string(), "0".to_string())]);
        // Only the stale height was a miss (validation, not continuity, caught it).
        assert_eq!(rig.calls(), vec![(2005, 2005)]);
        settle().await;
        assert_eq!(
            rig.store.get(&rig.key(2005)),
            Some(Bytes::from(rig.chain.msg(2005))),
            "stale entry replaced by the upstream block"
        );
    }

    #[tokio::test]
    async fn unindexed_blocks_inside_the_window_are_not_served() {
        let rig = Rig::new(2100, Some(2100), false);
        for h in 2000..=2010 {
            rig.cache_block(h, false);
        }
        let (body, _) = collect(&rig.cache, request(2000, 2010)).await;
        assert_eq!(body, concat(&rig.chain.frames_for(2000, 2010)));
        assert_eq!(rig.calls(), vec![(2000, 2010)], "all misses, one gap");
        // The entries are kept: the index may still arrive.
        assert!(rig.store.get(&rig.key(2000)).is_some());
        // Once indexed, they are served without any upstream call.
        for h in 2000..=2010 {
            rig.index(h, rig.chain.hash_at(h));
        }
        let (body, _) = collect(&rig.cache, request(2000, 2010)).await;
        assert_eq!(body, concat(&rig.chain.frames_for(2000, 2010)));
        assert_eq!(rig.calls().len(), 1);
    }

    #[tokio::test]
    async fn unknown_tip_serves_only_indexed_blocks() {
        let rig = Rig::new(10_000, None, false);
        rig.cache_block(10, true);
        rig.cache_block(11, false);
        let (body, _) = collect(&rig.cache, request(10, 12)).await;
        assert_eq!(body, concat(&rig.chain.frames_for(10, 12)));
        assert_eq!(rig.calls(), vec![(11, 12)]);
    }

    #[tokio::test]
    async fn tip_zone_blocks_are_stored() {
        let rig = Rig::new(1000, Some(1000), false);
        let (body, _) = collect(&rig.cache, request(990, 1000)).await;
        assert_eq!(body, concat(&rig.chain.frames_for(990, 1000)));
        settle().await;
        for h in 990..=1000 {
            assert_eq!(
                rig.store.get(&rig.key(h)),
                Some(Bytes::from(rig.chain.msg(h))),
                "{h}"
            );
        }
    }

    #[tokio::test]
    async fn continuity_catches_a_stale_trusted_block() {
        // Below the window (no index): 2005 is from another fork, caught by prevHash/hash.
        let rig = Rig::new(10_000, Some(10_000), false);
        for h in 2000..=2010 {
            if h == 2005 {
                rig.store.put(&rig.key(h), block_msg(h, 1));
            } else {
                rig.cache_block(h, false);
            }
        }
        let (body, trailers) = collect(&rig.cache, request(2000, 2010)).await;
        assert_eq!(body, concat(&rig.chain.frames_for(2000, 2010)));
        assert_eq!(trailers, vec![("grpc-status".to_string(), "0".to_string())]);
        // The mismatch was found at 2004 -> 2005 (2004 held, 2005 cached): both keys dropped and
        // the rest refetched from 2004 without the cache.
        assert_eq!(rig.calls(), vec![(2004, 2010)]);
        settle().await;
        assert_eq!(
            rig.store.get(&rig.key(2005)),
            Some(Bytes::from(rig.chain.msg(2005)))
        );
    }

    #[tokio::test]
    async fn cached_block_that_does_not_chain_to_upstream_is_replaced() {
        let rig = Rig::new(10_000, Some(10_000), false);
        // 3000 cached from the wrong fork, 3001.. missing: the held cached block fails against
        // the first upstream block and is refetched.
        rig.store.put(&rig.key(3000), block_msg(3000, 1));
        let (body, _) = collect(&rig.cache, request(3000, 3003)).await;
        assert_eq!(body, concat(&rig.chain.frames_for(3000, 3003)));
        assert_eq!(rig.calls(), vec![(3001, 3003), (3000, 3003)]);
    }

    #[tokio::test]
    async fn local_lru_serves_blocks_without_reading_them_from_redis() {
        let rig = Rig::new(2100, Some(2100), true);
        let local = rig.local.clone().unwrap();
        let (body, _) = collect(&rig.cache, request(2000, 2010)).await;
        assert_eq!(body, concat(&rig.chain.frames_for(2000, 2010)));
        assert_eq!(rig.calls(), vec![(2000, 2010)]);
        settle().await;
        // Fetched blocks are in the local LRU and in Redis.
        assert!(local.get(&rig.key(2000)).is_some());
        assert!(rig.store.get(&rig.key(2000)).is_some());
        for h in 2000..=2010 {
            rig.index(h, rig.chain.hash_at(h));
        }
        rig.store.mgets.lock().unwrap().clear();
        let (body, _) = collect(&rig.cache, request(2000, 2010)).await;
        assert_eq!(body, concat(&rig.chain.frames_for(2000, 2010)));
        assert_eq!(rig.calls().len(), 1, "served from cache");
        // The MGET asked Redis for the index only.
        let mgets = rig.store.mgets.lock().unwrap().clone();
        assert_eq!(mgets.len(), 1);
        assert!(
            mgets[0].iter().all(|k| k.contains(":chain:v1:index:")),
            "{:?}",
            mgets[0]
        );
        assert_eq!(mgets[0].len(), 11);
        // A reorg under a local copy is caught by the index: the stale local entry is dropped.
        rig.chain.reorg_from(2010, 1);
        rig.index(2010, rig.chain.hash_at(2010));
        let (body, _) = collect(&rig.cache, request(2009, 2010)).await;
        assert_eq!(body, concat(&rig.chain.frames_for(2009, 2010)));
        assert_eq!(rig.calls().last(), Some(&(2010, 2010)));
        settle().await;
        assert_eq!(
            local.get(&rig.key(2010)),
            Some(Bytes::from(rig.chain.msg(2010)))
        );
    }

    #[tokio::test]
    async fn identical_gaps_share_one_upstream_call() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(10_000));
        store.tip.set(Tip {
            height: 10_000,
            hash: chain.hash_at(10_000),
        });
        let lwd = Arc::new(FakeLwd {
            chain: chain.clone(),
            calls: std::sync::Mutex::new(vec![]),
            delay: Some(std::time::Duration::from_millis(50)),
        });
        let cache = Arc::new(BlockRangeCache::new(
            store.clone(),
            lwd.clone(),
            None,
            Arc::new(PoolKeys::default()),
            "testnet".to_string(),
        ));
        let (a, b, c) = tokio::join!(
            collect(&cache, request(100, 160)),
            collect(&cache, request(100, 160)),
            collect(&cache, request(100, 160)),
        );
        let want = concat(&chain.frames_for(100, 160));
        assert_eq!(a.0, want);
        assert_eq!(b.0, want);
        assert_eq!(c.0, want);
        assert_eq!(lwd.calls.lock().unwrap().len(), 1, "singleflight");
        assert_eq!(cache.flights.in_flight(), 0);
    }

    #[tokio::test]
    async fn upstream_grpc_error_is_forwarded_as_trailers() {
        struct Failing;
        impl BlockSource for Failing {
            fn fetch(&self, _body: Vec<u8>) -> BoxFuture<'static, Result<UpstreamResponse>> {
                Box::pin(async {
                    Ok(UpstreamResponse {
                        status: 200,
                        headers: vec![
                            ("content-type".to_string(), "application/grpc".to_string()),
                            ("grpc-status".to_string(), "14".to_string()),
                            ("grpc-message".to_string(), "unavailable".to_string()),
                        ],
                        body: Box::pin(futures_util::stream::empty()),
                    })
                })
            }
        }
        let store = Arc::new(MemStore::default());
        let cache = Arc::new(BlockRangeCache::new(
            store,
            Arc::new(Failing),
            None,
            Arc::new(PoolKeys::default()),
            "testnet".to_string(),
        ));
        let (body, trailers) = collect(&cache, request(1, 3)).await;
        assert!(body.is_empty());
        assert_eq!(
            trailers,
            vec![
                ("grpc-status".to_string(), "14".to_string()),
                ("grpc-message".to_string(), "unavailable".to_string()),
            ]
        );
    }

    #[tokio::test]
    async fn upstream_short_range_ends_cleanly() {
        // lightwalletd only has blocks up to 505: the client gets 500..=505 and grpc-status 0,
        // as it would directly.
        let rig = Rig::new(505, Some(505), false);
        let (body, trailers) = collect(&rig.cache, request(500, 510)).await;
        assert_eq!(body, concat(&rig.chain.frames_for(500, 505)));
        assert_eq!(trailers, vec![("grpc-status".to_string(), "0".to_string())]);
    }

    #[tokio::test]
    async fn fetched_blocks_are_routed_by_height_between_tiers() {
        // Tip 10_000: heights <= 9_900 are final (permanent), above stay in the cache Redis.
        let rig = Rig::with_permanent(10_000, Some(10_000), false, 1000);
        let (body, _) = collect(&rig.cache, request(9_890, 9_910)).await;
        assert_eq!(body, concat(&rig.chain.frames_for(9_890, 9_910)));
        settle().await;
        for h in 9_890..=9_900 {
            assert_eq!(
                rig.perm().get(&rig.perm_key(h)),
                Some(Bytes::from(rig.chain.msg(h))),
                "final height {h} in the permanent tier"
            );
            assert_eq!(
                rig.store.get(&rig.key(h)),
                None,
                "{h} not in the cache tier"
            );
        }
        for h in 9_901..=9_910 {
            assert_eq!(rig.perm().get(&rig.perm_key(h)), None, "{h} not permanent");
            assert_eq!(
                rig.store.get(&rig.key(h)),
                Some(Bytes::from(rig.chain.msg(h))),
                "{h} in the cache tier"
            );
        }
        // Below the permanent floor: cache tier even though final.
        let (_, _) = collect(&rig.cache, request(500, 502)).await;
        settle().await;
        assert_eq!(rig.perm().get(&rig.perm_key(500)), None);
        assert!(rig.store.get(&rig.key(500)).is_some());
    }

    #[tokio::test]
    async fn permanent_hits_never_call_upstream_nor_the_cache_redis() {
        // No tip known at all: permanent entries are still served (final by construction).
        let rig = Rig::with_permanent(10_000, None, false, 1000);
        for h in 2000..=2020 {
            rig.perm().put(&rig.perm_key(h), rig.chain.msg(h));
        }
        let (body, trailers) = collect(&rig.cache, request(2000, 2020)).await;
        assert_eq!(body, concat(&rig.chain.frames_for(2000, 2020)));
        assert_eq!(trailers, vec![("grpc-status".to_string(), "0".to_string())]);
        assert!(rig.calls().is_empty(), "no upstream call");
        assert!(
            rig.store.mgets.lock().unwrap().is_empty(),
            "no cache Redis round trip when every height is permanent"
        );
        // Descending order too.
        let (body, _) = collect(&rig.cache, request(2020, 2000)).await;
        assert_eq!(body, concat(&rig.chain.frames_for(2020, 2000)));
        assert!(rig.calls().is_empty());
    }

    #[tokio::test]
    async fn permanent_misses_fall_through_to_cache_then_upstream() {
        let rig = Rig::with_permanent(10_000, Some(10_000), false, 1000);
        // 3000..=3002 permanent, 3003 in the cache tier (trusted below the window), 3004 nowhere.
        for h in 3000..=3002 {
            rig.perm().put(&rig.perm_key(h), rig.chain.msg(h));
        }
        rig.cache_block(3003, false);
        let (body, _) = collect(&rig.cache, request(3000, 3004)).await;
        assert_eq!(body, concat(&rig.chain.frames_for(3000, 3004)));
        assert_eq!(rig.calls(), vec![(3004, 3004)]);
        settle().await;
        // The final block found in the cache tier was copied to the permanent tier, and the
        // fetched one was stored there directly.
        assert_eq!(
            rig.perm().get(&rig.perm_key(3003)),
            Some(Bytes::from(rig.chain.msg(3003)))
        );
        assert_eq!(
            rig.perm().get(&rig.perm_key(3004)),
            Some(Bytes::from(rig.chain.msg(3004)))
        );
        assert_eq!(rig.store.get(&rig.key(3004)), None);
    }

    #[tokio::test]
    async fn permanent_tier_down_is_fail_open() {
        let rig = Rig::with_permanent(10_000, Some(10_000), false, 1000);
        rig.perm()
            .down
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let (body, trailers) = collect(&rig.cache, request(4000, 4005)).await;
        assert_eq!(body, concat(&rig.chain.frames_for(4000, 4005)));
        assert_eq!(trailers, vec![("grpc-status".to_string(), "0".to_string())]);
        assert_eq!(rig.calls(), vec![(4000, 4005)]);
    }

    #[tokio::test]
    async fn permanent_keys_are_per_pool_filter() {
        let rig = Rig::with_permanent(10_000, Some(10_000), false, 1000);
        let extra = vec![0x18, 2];
        let req =
            BlockRangeRequest::parse(&BlockRangeRequest::grpc_body(5000, 5002, &extra)).unwrap();
        let (body, _) = collect(&rig.cache, req.clone()).await;
        assert_eq!(body, concat(&rig.chain.frames_for(5000, 5002)));
        settle().await;
        assert!(rig
            .perm()
            .get(&permanent_block_key("testnet", "2", 5000))
            .is_some());
        assert_eq!(
            rig.perm().get(&rig.perm_key(5000)),
            None,
            "unfiltered variant untouched"
        );
        // The unfiltered request is a miss and goes upstream with no filter: lightwalletd's
        // filtering is never re-implemented in the gateway.
        let (body, _) = collect(&rig.cache, request(5000, 5002)).await;
        assert_eq!(body, concat(&rig.chain.frames_for(5000, 5002)));
        assert_eq!(
            rig.lwd.calls.lock().unwrap().clone(),
            vec![(5000, 5002, extra), (5000, 5002, vec![])]
        );
        // The filtered request is now a permanent hit.
        let before = rig.calls().len();
        let (_, _) = collect(&rig.cache, req).await;
        assert_eq!(rig.calls().len(), before);
    }

    #[tokio::test]
    async fn oversized_blocks_bypass_the_local_lru_but_are_stored() {
        let rig = Rig::with_permanent(10_000, Some(10_000), true, 1000);
        let local = rig.local.clone().unwrap();
        // A 100 KiB block at 6000, a normal one at 6001.
        let big = {
            let mut m = rig.chain.msg(6000);
            // Field 7 (vtx) as one length-delimited blob of 100 KiB.
            m.push(0x3a);
            let len = 100 * 1024u64;
            let mut l = len;
            while l >= 0x80 {
                m.push((l as u8 & 0x7f) | 0x80);
                l >>= 7;
            }
            m.push(l as u8);
            m.extend(std::iter::repeat_n(0u8, len as usize));
            m
        };
        rig.perm().put(&rig.perm_key(6000), big.clone());
        rig.perm().put(&rig.perm_key(6001), rig.chain.msg(6001));
        let (body, _) = collect(&rig.cache, request(6000, 6001)).await;
        let mut want = grpc_frame(&big).to_vec();
        want.extend_from_slice(&grpc_frame(&rig.chain.msg(6001)));
        assert_eq!(body, want);
        assert!(rig.calls().is_empty());
        assert_eq!(
            local.get(&rig.perm_key(6000)),
            None,
            "over the cap: not in the LRU"
        );
        assert!(local.get(&rig.perm_key(6001)).is_some());
        // A small fetched block: stored in the tier and admitted to the LRU.
        let (_, _) = collect(&rig.cache, request(6002, 6002)).await;
        settle().await;
        assert!(rig.perm().get(&rig.perm_key(6002)).is_some());
        assert!(
            local.get(&rig.perm_key(6002)).is_some(),
            "small fetched block is admitted"
        );
    }

    #[test]
    fn splitter_reassembles_frames_across_pushes() {
        let chain = FakeChain::new(10);
        let frames = chain.frames_for(1, 3);
        let all = concat(&frames);
        let mut splitter = GrpcSplitter::default();
        let mut out = Vec::new();
        for piece in all.chunks(11) {
            out.extend(splitter.push(piece));
        }
        assert_eq!(out, frames);
        assert_eq!(splitter.remainder(), 0);
    }
}

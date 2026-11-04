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

//! Per-entry cache for `GetSubtreeRoots`, validated against the chain follower's index.
//!
//! `GetSubtreeRoots(startIndex, shieldedProtocol, maxEntries)` streams the roots of the completed
//! note commitment subtrees from `startIndex` on, in order, at most `maxEntries` of them
//! (`0` = all, as lightwalletd passes the limit to the node only when it is positive). A root
//! never changes once its completing block is final, so the answer is assembled per entry:
//!
//! - **Key** `(network, protocol, index)`. Final entries (completing block at depth >=
//!   [`PERMANENT_DEPTH`](crate::store::PERMANENT_DEPTH) below a fresh tip) live in the permanent
//!   tier under `perm:{network}:subtree:v1:{protocol}:{index}` with no TTL and are never
//!   validated again. Non-final entries live in the cache Redis under
//!   `{prefix}subtree:{protocol}:{index}` and are served only while their
//!   `completingBlockHash` is the follower's index hash at `completingBlockHeight` (stale ones
//!   are dropped and refetched; ones with no index entry are served only below the index
//!   window). The value is the serialized
//!   `SubtreeRoot` message without the 5-byte gRPC prefix.
//! - **Reorg**: a non-final entry also writes a pointer `{prefix}subtree_at:{protocol}:{height}`
//!   -> index, so the follower's walk-back deletes every entry completing above the fork
//!   ([`reorg_keys`]); the index check above is the second line of defence.
//! - **End marker**: the set of completed subtrees is a function of the tip, so when an upstream
//!   answer ends the list (no limit, or fewer entries than asked) under an unchanged tip, the
//!   end index is stored under `{prefix}subtree_end:{protocol}:{tip hash}` (tip-scoped, TTL
//!   [`TIP_SCOPED_TTL_SECS`](crate::rpc_cache::TIP_SCOPED_TTL_SECS)). A request whose cached
//!   prefix reaches that index is complete without any upstream call.
//! - **Serving** streams the cached entries from `startIndex` as long as they are consecutive,
//!   then, unless the end marker says the list is over, fetches the rest from lightwalletd once
//!   (`startIndex` = first missing index, `maxEntries` = what is left of the client's limit),
//!   streaming and storing each root as it arrives. Identical fetches in flight share one
//!   upstream call. The bytes equal what lightwalletd sends for the same request: same messages,
//!   same order, same framing, and its trailers (or `grpc-status 0` when nothing was fetched).
//!
//! Requests the parser cannot key (compressed, several frames, unknown fields, unknown protocol)
//! take the generic per-request path instead.

use crate::block_cache::{grpc_frame, read_pb_varint, GrpcSplitter};
use crate::chunked_stream::UpFrame;
use crate::singleflight::{Flights, Reader, RpcSource};
use crate::store::{
    hash_is_current, index_key, is_final, CacheStore, PermanentStore, Tip, Validity,
};
use anyhow::Result;
use bytes::Bytes;
use futures_util::future::BoxFuture;
use futures_util::{Stream, StreamExt};
use prost::Message;
use std::sync::Arc;
use tracing::{debug, warn};

/// The one RPC this cache serves.
pub const GET_SUBTREE_ROOTS_PATH: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetSubtreeRoots";

/// `ShieldedProtocol` values lightwalletd knows: sapling 0, orchard 1.
pub const PROTOCOLS: [u32; 2] = [0, 1];

/// Indices looked up per round trip while walking the cached prefix.
const MGET_BATCH: usize = 64;

const RPC: &str = "GetSubtreeRoots";

/// service.proto `GetSubtreeRootsArg`: startIndex 1, shieldedProtocol 2 (enum, varint),
/// maxEntries 3. Zero fields are omitted, as any proto3 encoder does.
#[derive(Clone, PartialEq, prost::Message)]
struct GetSubtreeRootsArg {
    #[prost(uint32, tag = "1")]
    start_index: u32,
    #[prost(uint32, tag = "2")]
    shielded_protocol: u32,
    #[prost(uint32, tag = "3")]
    max_entries: u32,
}

/// The chain position of a `SubtreeRoot` (rootHash 2, completingBlockHash 3,
/// completingBlockHeight 4); the root itself is skipped by prost.
#[derive(Clone, PartialEq, prost::Message)]
pub struct SubtreeRootHead {
    #[prost(bytes, tag = "3")]
    pub completing_block_hash: Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub completing_block_height: u64,
}

/// A parsed `GetSubtreeRoots` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubtreeRootsRequest {
    pub start_index: u32,
    pub protocol: u32,
    /// `0` = every entry from `start_index`.
    pub max_entries: u32,
}

impl SubtreeRootsRequest {
    /// Parse one uncompressed gRPC frame holding a `GetSubtreeRootsArg`. `None` for anything the
    /// cache cannot key (compressed or multi-frame bodies, unknown fields or wire types, a
    /// protocol lightwalletd does not know): such requests go the generic way.
    pub fn parse(body: &[u8]) -> Option<Self> {
        let msg = crate::rpc_cache::grpc_message(body)?;
        let mut pos = 0usize;
        let mut req = Self {
            start_index: 0,
            protocol: 0,
            max_entries: 0,
        };
        while pos < msg.len() {
            let tag = read_pb_varint(msg, &mut pos)?;
            if tag & 7 != 0 {
                return None;
            }
            let value = u32::try_from(read_pb_varint(msg, &mut pos)?).ok()?;
            match tag >> 3 {
                1 => req.start_index = value,
                2 => req.protocol = value,
                3 => req.max_entries = value,
                _ => return None,
            }
        }
        if !PROTOCOLS.contains(&req.protocol) {
            return None;
        }
        Some(req)
    }

    /// The gRPC request body for `GetSubtreeRoots(start_index, protocol, max_entries)`.
    pub fn grpc_body(start_index: u32, protocol: u32, max_entries: u32) -> Vec<u8> {
        grpc_frame(
            &GetSubtreeRootsArg {
                start_index,
                shielded_protocol: protocol,
                max_entries,
            }
            .encode_to_vec(),
        )
        .to_vec()
    }
}

/// The cache-tier key of entry `index` of `protocol`.
pub fn subtree_key(prefix: &str, protocol: u32, index: u32) -> String {
    format!("{prefix}subtree:{protocol}:{index}")
}

/// The pointer from the completing `height` of a non-final entry to its index (big-endian u32).
pub fn subtree_at_key(prefix: &str, protocol: u32, height: u64) -> String {
    format!("{prefix}subtree_at:{protocol}:{height}")
}

/// The permanent-tier key of entry `index` of `protocol`. No backend host, epoch or policy
/// hash: a final root is the same whichever lightwalletd served it.
pub fn permanent_subtree_key(network: &str, protocol: u32, index: u32) -> String {
    format!("perm:{network}:subtree:v1:{protocol}:{index}")
}

/// The tip-scoped end marker of `protocol`: the index past the last completed subtree at the
/// tip with `tip_hash` (big-endian u32).
pub fn subtree_end_key(prefix: &str, protocol: u32, tip_hash: &[u8]) -> String {
    format!("{prefix}subtree_end:{protocol}:{}", hex::encode(tip_hash))
}

fn decode_index(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

/// The keys the follower deletes when heights `from..=to` leave the chain: every pointer in the
/// span and the non-final entry each one points to.
pub async fn reorg_keys(store: &dyn CacheStore, prefix: &str, from: u64, to: u64) -> Vec<String> {
    let mut out = Vec::new();
    if from > to {
        return out;
    }
    let pointers: Vec<(u32, String)> = (from..=to)
        .flat_map(|h| {
            PROTOCOLS
                .iter()
                .map(move |p| (*p, subtree_at_key(prefix, *p, h)))
        })
        .collect();
    for chunk in pointers.chunks(256) {
        let values = store
            .mget(chunk.iter().map(|(_, k)| k.clone()).collect())
            .await;
        for ((protocol, key), value) in chunk.iter().zip(values) {
            if let Some(index) = value.as_deref().and_then(decode_index) {
                out.push(subtree_key(prefix, *protocol, index));
            }
            out.push(key.clone());
        }
    }
    out
}

/// One root as fetched or cached.
#[derive(Clone)]
pub struct FetchedRoot {
    /// `(completingBlockHeight, completingBlockHash)` when the message decoded with both.
    pub position: Option<(u64, Vec<u8>)>,
    /// The full gRPC frame to forward.
    pub frame: Bytes,
}

impl FetchedRoot {
    pub fn from_frame(frame: Bytes) -> Self {
        let position = if frame.len() >= 5 && frame[0] == 0 {
            SubtreeRootHead::decode(&frame[5..]).ok().and_then(|h| {
                (h.completing_block_height > 0 && !h.completing_block_hash.is_empty())
                    .then_some((h.completing_block_height, h.completing_block_hash))
            })
        } else {
            None
        };
        Self { position, frame }
    }

    /// A stored entry (the message without the gRPC prefix), if it decodes with a position.
    fn decode_entry(bytes: &Bytes) -> Option<Self> {
        let root = Self::from_frame(grpc_frame(bytes));
        root.position.is_some().then_some(root)
    }

    /// The cache value: the message without the gRPC prefix.
    pub fn message(&self) -> Bytes {
        self.frame.slice(5..)
    }
}

#[derive(Clone)]
enum FetchItem {
    Root(Arc<FetchedRoot>),
    /// The end of the upstream call: its trailers, or a synthesized `grpc-status` (14 when the
    /// call could not be made, 13 when it broke off).
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

/// Where a fetched or found entry is written.
enum Tier {
    Permanent,
    Cache,
}

/// The per-entry cache engine. One per gateway process.
pub struct SubtreeRootsCache {
    store: Arc<dyn CacheStore>,
    source: Arc<dyn RpcSource>,
    flights: Arc<Flights<FetchItem>>,
    network: String,
    permanent: Option<Arc<dyn PermanentStore>>,
}

impl SubtreeRootsCache {
    pub fn new(store: Arc<dyn CacheStore>, source: Arc<dyn RpcSource>, network: String) -> Self {
        Self {
            store,
            source,
            flights: Arc::new(Flights::new()),
            network,
            permanent: None,
        }
    }

    /// Attach the permanent tier.
    pub fn with_permanent(mut self, permanent: Arc<dyn PermanentStore>) -> Self {
        self.permanent = Some(permanent);
        self
    }

    pub fn in_flight(&self) -> usize {
        self.flights.in_flight()
    }

    /// The tier an entry completing at `height` is written to: permanent only when final
    /// against a fresh tip (never guess finality).
    fn tier_for(&self, height: u64, tip: Option<&Tip>) -> Tier {
        if self.permanent.is_some() && tip.is_some_and(|t| is_final(height, t)) {
            Tier::Permanent
        } else {
            Tier::Cache
        }
    }

    /// Look `indices` of `protocol` up: the permanent tier first (anything there is final by
    /// construction), then the cache Redis, each entry validated against the index at its
    /// completing height (with no index entry, trusted only below the index window). Returns
    /// the frames to forward.
    async fn lookup(
        &self,
        prefix: &str,
        chain: &str,
        protocol: u32,
        indices: &[u32],
    ) -> Vec<Option<Bytes>> {
        let n = indices.len();
        let tip = self.store.tip_cell().get();
        let mut out: Vec<Option<Bytes>> = vec![None; n];

        if let Some(perm) = &self.permanent {
            let keys: Vec<String> = indices
                .iter()
                .map(|i| permanent_subtree_key(&self.network, protocol, *i))
                .collect();
            let values = perm.mget(keys.clone()).await;
            let mut bad = Vec::new();
            for (j, value) in values.into_iter().enumerate().take(n) {
                let Some(bytes) = value else { continue };
                match FetchedRoot::decode_entry(&bytes) {
                    Some(root) => out[j] = Some(root.frame),
                    None => bad.push(keys[j].clone()),
                }
            }
            if !bad.is_empty() {
                warn!(network = %self.network, n = bad.len(), "undecodable permanent subtree entries dropped");
                perm.del(bad).await;
            }
        }

        let rest: Vec<usize> = (0..n).filter(|j| out[*j].is_none()).collect();
        if rest.is_empty() {
            return out;
        }
        let keys: Vec<String> = rest
            .iter()
            .map(|j| subtree_key(prefix, protocol, indices[*j]))
            .collect();
        let values = self.store.mget(keys.clone()).await;
        let mut decoded: Vec<(usize, FetchedRoot, Bytes)> = Vec::new();
        let mut stale: Vec<String> = Vec::new();
        for (k, value) in values.into_iter().enumerate().take(rest.len()) {
            let Some(bytes) = value else { continue };
            match FetchedRoot::decode_entry(&bytes) {
                Some(root) => decoded.push((k, root, bytes)),
                None => stale.push(keys[k].clone()),
            }
        }
        if !decoded.is_empty() {
            let index = self
                .store
                .mget(
                    decoded
                        .iter()
                        .map(|(_, r, _)| index_key(chain, r.position.as_ref().map_or(0, |p| p.0)))
                        .collect(),
                )
                .await;
            let mut promote: Vec<(u32, u64, Bytes)> = Vec::new();
            for (m, (k, root, bytes)) in decoded.into_iter().enumerate() {
                let Some((height, hash)) = root.position.as_ref() else {
                    continue;
                };
                let index_hash = index.get(m).cloned().flatten();
                match hash_is_current(hash, *height, index_hash.as_deref(), tip.as_ref()) {
                    Validity::Current => {
                        if matches!(self.tier_for(*height, tip.as_ref()), Tier::Permanent) {
                            promote.push((indices[rest[k]], *height, bytes));
                        }
                        out[rest[k]] = Some(root.frame);
                    }
                    Validity::Stale => {
                        crate::health::record_cache_request(&self.network, RPC, "validated_stale");
                        stale.push(keys[k].clone());
                        stale.push(subtree_at_key(prefix, protocol, *height));
                    }
                    Validity::Unknown => {
                        crate::health::record_cache_request(&self.network, RPC, "unvalidated");
                    }
                }
            }
            self.promote(prefix, protocol, promote);
        }
        if !stale.is_empty() {
            self.store.del(stale).await;
        }
        out
    }

    /// Move entries that became final from the cache tier to the permanent tier, off the
    /// request path.
    fn promote(&self, prefix: &str, protocol: u32, entries: Vec<(u32, u64, Bytes)>) {
        let Some(perm) = self.permanent.clone() else {
            return;
        };
        if entries.is_empty() {
            return;
        }
        let store = self.store.clone();
        let network = self.network.clone();
        let prefix = prefix.to_string();
        tokio::spawn(async move {
            for (index, height, bytes) in entries {
                if perm
                    .set(permanent_subtree_key(&network, protocol, index), bytes)
                    .await
                {
                    store
                        .del(vec![
                            subtree_key(&prefix, protocol, index),
                            subtree_at_key(&prefix, protocol, height),
                        ])
                        .await;
                }
            }
        });
    }

    /// Start or join the upstream fetch of `max_entries` (0 = all) entries of `protocol` from
    /// `start`.
    fn fetch(
        self: &Arc<Self>,
        protocol: u32,
        start: u32,
        max_entries: u32,
        prefix: &str,
        epoch: u64,
        request_id: Option<uuid::Uuid>,
    ) -> Reader<FetchItem> {
        let flight_key = format!("{protocol}:{start}:{max_entries}");
        let this = self.clone();
        let prefix = prefix.to_string();
        let (reader, joined) =
            self.flights
                .join_or_start(flight_key, move |shared| -> BoxFuture<'static, ()> {
                    Box::pin(async move {
                        this.run_fetch(
                            &shared,
                            protocol,
                            start,
                            max_entries,
                            &prefix,
                            epoch,
                            request_id,
                        )
                        .await;
                    })
                });
        if joined {
            crate::health::record_singleflight_join(&self.network, RPC);
            debug!(network = %self.network, protocol, start, max_entries, "singleflight join");
        }
        reader
    }

    /// The upstream call behind one singleflight entry: forwards every frame to the replay
    /// buffer and stores each root under its (positional) index.
    #[allow(clippy::too_many_arguments)]
    async fn run_fetch(
        self: &Arc<Self>,
        shared: &Arc<crate::singleflight::Shared<FetchItem>>,
        protocol: u32,
        start: u32,
        max_entries: u32,
        prefix: &str,
        epoch: u64,
        request_id: Option<uuid::Uuid>,
    ) {
        crate::health::record_upstream_call(&self.network, RPC);
        let body = SubtreeRootsRequest::grpc_body(start, protocol, max_entries);
        let resp = match self
            .source
            .call(GET_SUBTREE_ROOTS_PATH.to_string(), body, request_id)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(network = %self.network, error = %e, "subtree roots upstream call failed");
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
        if grpc_status_of(&resp.headers).is_some() {
            let trailers: Vec<(String, String)> = resp
                .headers
                .into_iter()
                .filter(|(k, _)| k.to_ascii_lowercase().starts_with("grpc-"))
                .collect();
            shared.push(FetchItem::Trailers(trailers));
            return;
        }

        let tip = self.store.tip_cell().get();
        let mut writes: Vec<(Tier, u32, u64, Bytes)> = Vec::new();
        let mut count = 0u32;
        let mut splitter = GrpcSplitter::default();
        let mut trailers: Vec<(String, String)> = Vec::new();
        let mut index = Some(start);
        let mut body = resp.body;
        let mut outcome: Option<FetchItem> = None;
        while let Some(frame) = body.next().await {
            match frame {
                Ok(UpFrame::Data(data)) => {
                    for frame in splitter.push(&data) {
                        let root = Arc::new(FetchedRoot::from_frame(frame));
                        if let (Some(i), Some((height, _))) = (index, root.position.as_ref()) {
                            writes.push((
                                self.tier_for(*height, tip.as_ref()),
                                i,
                                *height,
                                root.message(),
                            ));
                        }
                        index = index.and_then(|i| i.checked_add(1));
                        count = count.saturating_add(1);
                        shared.push(FetchItem::Root(root));
                    }
                }
                Ok(UpFrame::Trailers(t)) => trailers.extend(t),
                Err(e) => {
                    warn!(network = %self.network, error = %e, "subtree roots upstream stream failed");
                    outcome = Some(grpc_failure("13", format!("upstream stream failed: {e}")));
                    break;
                }
            }
        }
        if let Some(failure) = outcome {
            self.store_roots(protocol, prefix, epoch, writes, None);
            shared.push(failure);
            return;
        }
        if splitter.remainder() > 0 {
            self.store_roots(protocol, prefix, epoch, writes, None);
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
        // The list ended here (no limit, or fewer than asked) under a tip that did not move
        // during the call: remember where, for this tip.
        let ended =
            grpc_status_of(&trailers) == Some("0") && (max_entries == 0 || count < max_entries);
        let end = match (ended, index, &tip, self.store.tip_cell().get()) {
            (true, Some(end), Some(before), Some(after)) if before.hash == after.hash => {
                Some((subtree_end_key(prefix, protocol, &before.hash), end))
            }
            _ => None,
        };
        self.store_roots(protocol, prefix, epoch, writes, end);
        shared.push(FetchItem::Trailers(trailers));
    }

    /// Write fetched roots behind the response: final ones to the permanent tier, the rest to
    /// the cache Redis with their height pointer; then the end marker, if the list ended. Roots
    /// that arrived before an upstream failure are still right for their index, so they are
    /// written too.
    fn store_roots(
        &self,
        protocol: u32,
        prefix: &str,
        epoch: u64,
        writes: Vec<(Tier, u32, u64, Bytes)>,
        end: Option<(String, u32)>,
    ) {
        if writes.is_empty() && end.is_none() {
            return;
        }
        let store = self.store.clone();
        let permanent = self.permanent.clone();
        let network = self.network.clone();
        let prefix = prefix.to_string();
        tokio::spawn(async move {
            for (tier, index, height, value) in writes {
                match (tier, &permanent) {
                    (Tier::Permanent, Some(p)) => {
                        p.set(permanent_subtree_key(&network, protocol, index), value)
                            .await;
                    }
                    _ => {
                        store
                            .set(
                                subtree_key(&prefix, protocol, index),
                                value,
                                None,
                                Some(epoch),
                            )
                            .await;
                        store
                            .set(
                                subtree_at_key(&prefix, protocol, height),
                                Bytes::copy_from_slice(&index.to_be_bytes()),
                                None,
                                Some(epoch),
                            )
                            .await;
                    }
                }
            }
            if let Some((key, end)) = end {
                store
                    .set(
                        key,
                        Bytes::copy_from_slice(&end.to_be_bytes()),
                        Some(crate::rpc_cache::TIP_SCOPED_TTL_SECS),
                        Some(epoch),
                    )
                    .await;
            }
        });
    }

    /// Serve a `GetSubtreeRoots`: the body frames and the final trailers of the inner response
    /// (status 200, `content-type: application/grpc`).
    pub fn serve(
        self: &Arc<Self>,
        req: SubtreeRootsRequest,
        request_id: Option<uuid::Uuid>,
    ) -> impl Stream<Item = Result<UpFrame>> + Send + 'static {
        let this = self.clone();
        async_stream::stream! {
            let epoch = this.store.epoch().await;
            let prefix = this.store.key_prefix(epoch);
            let chain = this.store.chain_prefix();
            let limit: Option<u32> = (req.max_entries > 0).then_some(req.max_entries);
            // Where the list ends at the current tip, when a previous fetch found out.
            let end: Option<u32> = match this.store.tip_cell().get() {
                Some(tip) => this
                    .store
                    .mget(vec![subtree_end_key(&prefix, req.protocol, &tip.hash)])
                    .await
                    .into_iter()
                    .next()
                    .flatten()
                    .as_deref()
                    .and_then(decode_index),
                None => None,
            };
            // The next index to produce; `None` once past u32::MAX.
            let mut next: Option<u32> = Some(req.start_index);
            let mut served: u32 = 0;

            // 1. The cached prefix: consecutive entries from start_index.
            'cached: while let Some(from) = next {
                let want = limit
                    .map_or(usize::MAX, |l| (l - served) as usize)
                    .min(MGET_BATCH);
                if want == 0 {
                    break;
                }
                let indices: Vec<u32> = (0..want)
                    .map_while(|i| from.checked_add(i as u32))
                    .collect();
                let found = this.lookup(&prefix, &chain, req.protocol, &indices).await;
                for (i, frame) in indices.iter().zip(found) {
                    let Some(frame) = frame else {
                        break 'cached;
                    };
                    served += 1;
                    next = i.checked_add(1);
                    yield Ok(UpFrame::Data(frame));
                }
                if indices.len() < want {
                    break;
                }
            }

            // 2. The rest from lightwalletd, once, unless the end marker says there is none.
            let mut trailers = vec![("grpc-status".to_string(), "0".to_string())];
            let remaining = limit.map_or(0, |l| l - served);
            let fetched = match next {
                Some(from) if limit.is_none_or(|l| served < l) && end.is_none_or(|e| from < e) => {
                    let mut reader = this.fetch(req.protocol, from, remaining, &prefix, epoch, request_id);
                    let mut n = 0u32;
                    while let Some(item) = reader.next().await {
                        match item {
                            FetchItem::Root(root) => {
                                n += 1;
                                yield Ok(UpFrame::Data(root.frame.clone()));
                            }
                            FetchItem::Trailers(t) => trailers = t,
                        }
                    }
                    Some(n)
                }
                _ => None,
            };
            crate::health::record_cache_request(
                &this.network,
                RPC,
                if fetched.is_some() { "miss" } else { "hit" },
            );
            debug!(
                network = %this.network,
                protocol = req.protocol,
                start_index = req.start_index,
                max_entries = req.max_entries,
                cached = served,
                fetched = ?fetched,
                end = ?end,
                "subtree roots served"
            );
            yield Ok(UpFrame::Trailers(trailers));
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::singleflight::RpcResponse;
    use sha2::{Digest, Sha256};
    use std::sync::Mutex;

    /// A full `SubtreeRoot` as lightwalletd encodes it.
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct SubtreeRoot {
        #[prost(bytes, tag = "2")]
        pub root_hash: Vec<u8>,
        #[prost(bytes, tag = "3")]
        pub completing_block_hash: Vec<u8>,
        #[prost(uint64, tag = "4")]
        pub completing_block_height: u64,
    }

    pub fn root_hash(protocol: u32, index: u32) -> Vec<u8> {
        Sha256::digest(format!("root:{protocol}:{index}")).to_vec()
    }

    pub fn root_msg(protocol: u32, index: u32, height: u64, block_hash: Vec<u8>) -> Vec<u8> {
        SubtreeRoot {
            root_hash: root_hash(protocol, index),
            completing_block_hash: block_hash,
            completing_block_height: height,
        }
        .encode_to_vec()
    }

    /// One fake subtree root: `(completing height, completing hash)`.
    pub type RootEntry = (u64, Vec<u8>);

    /// A fake lightwalletd answering `GetSubtreeRoots` from a per-protocol list of
    /// `(completing height, completing hash)`, split at odd byte offsets.
    pub struct FakeRoots {
        pub roots: Mutex<Vec<Vec<RootEntry>>>,
        pub calls: Mutex<Vec<(u32, u32, u32)>>,
        pub delay: Option<std::time::Duration>,
    }

    impl FakeRoots {
        pub fn new(roots: Vec<Vec<(u64, Vec<u8>)>>) -> Self {
            Self {
                roots: Mutex::new(roots),
                calls: Mutex::new(vec![]),
                delay: None,
            }
        }

        pub fn set(&self, protocol: u32, index: u32, height: u64, hash: Vec<u8>) {
            self.roots.lock().unwrap()[protocol as usize][index as usize] = (height, hash);
        }

        pub fn frames_for(&self, protocol: u32, start: u32, max: u32) -> Vec<Bytes> {
            let roots = self.roots.lock().unwrap();
            let list = &roots[protocol as usize];
            let end = if max == 0 {
                list.len()
            } else {
                (start as usize + max as usize).min(list.len())
            };
            (start as usize..end.max(start as usize))
                .map(|i| {
                    let (h, hash) = &list[i];
                    grpc_frame(&root_msg(protocol, i as u32, *h, hash.clone()))
                })
                .collect()
        }

        pub fn calls(&self) -> Vec<(u32, u32, u32)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl RpcSource for FakeRoots {
        fn call(
            &self,
            path: String,
            body: Vec<u8>,
            _request_id: Option<uuid::Uuid>,
        ) -> BoxFuture<'static, Result<RpcResponse>> {
            assert_eq!(path, GET_SUBTREE_ROOTS_PATH);
            let req = SubtreeRootsRequest::parse(&body).expect("gap request parses");
            self.calls
                .lock()
                .unwrap()
                .push((req.start_index, req.protocol, req.max_entries));
            let all: Vec<u8> = self
                .frames_for(req.protocol, req.start_index, req.max_entries)
                .iter()
                .flat_map(|f| f.to_vec())
                .collect();
            let delay = self.delay;
            Box::pin(async move {
                let body = async_stream::stream! {
                    if let Some(d) = delay {
                        tokio::time::sleep(d).await;
                    }
                    for piece in all.chunks(37) {
                        yield Ok(UpFrame::Data(Bytes::copy_from_slice(piece)));
                    }
                    yield Ok(UpFrame::Trailers(vec![("grpc-status".to_string(), "0".to_string())]));
                };
                Ok(RpcResponse {
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

    fn ok_trailers() -> Vec<(String, String)> {
        vec![("grpc-status".to_string(), "0".to_string())]
    }

    fn request(start: u32, protocol: u32, max: u32) -> SubtreeRootsRequest {
        SubtreeRootsRequest::parse(&SubtreeRootsRequest::grpc_body(start, protocol, max)).unwrap()
    }

    async fn collect(
        cache: &Arc<SubtreeRootsCache>,
        req: SubtreeRootsRequest,
    ) -> (Vec<u8>, Vec<(String, String)>) {
        let frames: Vec<UpFrame> = cache
            .serve(req, None)
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

    /// Wait for the spawned store writes.
    async fn settle() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    fn block_hash(height: u64, fork: u8) -> Vec<u8> {
        crate::block_cache::test_support::hash_at(height, fork)
    }

    struct Rig {
        store: Arc<MemStore>,
        lwd: Arc<FakeRoots>,
        cache: Arc<SubtreeRootsCache>,
        permanent: Option<Arc<MemPermanent>>,
    }

    impl Rig {
        /// Ten sapling roots completing every 500 blocks from 1000 (all final against tip
        /// 10_000) and three orchard roots, the last one completing at 9_950 (non-final).
        fn new(tip: Option<u64>, permanent: bool) -> Self {
            let sapling: Vec<(u64, Vec<u8>)> = (0..10u64)
                .map(|i| (1000 + 500 * i, block_hash(1000 + 500 * i, 0)))
                .collect();
            let orchard: Vec<(u64, Vec<u8>)> = vec![
                (5000, block_hash(5000, 0)),
                (8000, block_hash(8000, 0)),
                (9950, block_hash(9950, 0)),
            ];
            let store = Arc::new(MemStore::default());
            if let Some(t) = tip {
                store.tip.set(Tip {
                    height: t,
                    hash: block_hash(t, 0),
                });
            }
            let lwd = Arc::new(FakeRoots::new(vec![sapling, orchard]));
            let cache = SubtreeRootsCache::new(store.clone(), lwd.clone(), "testnet".to_string());
            let (cache, permanent) = if permanent {
                let p = Arc::new(MemPermanent::default());
                (cache.with_permanent(p.clone()), Some(p))
            } else {
                (cache, None)
            };
            Self {
                store,
                lwd,
                cache: Arc::new(cache),
                permanent,
            }
        }

        fn prefix(&self) -> String {
            self.store.key_prefix(42)
        }

        fn perm(&self) -> &Arc<MemPermanent> {
            self.permanent.as_ref().expect("permanent tier")
        }

        fn index(&self, height: u64, hash: Vec<u8>) {
            self.store
                .put(&index_key(&self.store.chain_prefix(), height), hash);
        }

        fn set_tip(&self, height: u64, fork: u8) {
            self.store.tip.set(Tip {
                height,
                hash: block_hash(height, fork),
            });
        }

        fn end_key(&self, protocol: u32) -> String {
            let tip = self.store.tip.get().expect("tip");
            subtree_end_key(&self.prefix(), protocol, &tip.hash)
        }

        fn want(&self, protocol: u32, start: u32, max: u32) -> Vec<u8> {
            concat(&self.lwd.frames_for(protocol, start, max))
        }
    }

    #[test]
    fn parses_requests_and_rejects_what_it_cannot_key() {
        assert_eq!(
            SubtreeRootsRequest::parse(&SubtreeRootsRequest::grpc_body(0, 0, 0)),
            Some(SubtreeRootsRequest {
                start_index: 0,
                protocol: 0,
                max_entries: 0
            })
        );
        // All zero fields encode to an empty message: the default request.
        assert_eq!(SubtreeRootsRequest::grpc_body(0, 0, 0), vec![0, 0, 0, 0, 0]);
        assert_eq!(
            SubtreeRootsRequest::parse(&SubtreeRootsRequest::grpc_body(7, 1, 3)),
            Some(SubtreeRootsRequest {
                start_index: 7,
                protocol: 1,
                max_entries: 3
            })
        );
        // Unknown protocol, unknown field, wrong wire type, compressed, two frames.
        assert_eq!(
            SubtreeRootsRequest::parse(&SubtreeRootsRequest::grpc_body(0, 2, 0)),
            None
        );
        assert_eq!(SubtreeRootsRequest::parse(&grpc_frame(&[0x20, 1])), None);
        assert_eq!(SubtreeRootsRequest::parse(&grpc_frame(&[0x0a, 1, 1])), None);
        let mut compressed = SubtreeRootsRequest::grpc_body(1, 0, 0);
        compressed[0] = 1;
        assert_eq!(SubtreeRootsRequest::parse(&compressed), None);
        let mut two = SubtreeRootsRequest::grpc_body(1, 0, 0);
        two.extend_from_slice(&SubtreeRootsRequest::grpc_body(1, 0, 0));
        assert_eq!(SubtreeRootsRequest::parse(&two), None);
        assert_eq!(subtree_key("p:", 1, 5), "p:subtree:1:5");
        assert_eq!(subtree_at_key("p:", 0, 900), "p:subtree_at:0:900");
        assert_eq!(
            subtree_end_key("p:", 1, &[0xab, 0xcd]),
            "p:subtree_end:1:abcd"
        );
        assert_eq!(
            permanent_subtree_key("mainnet", 1, 5),
            "perm:mainnet:subtree:v1:1:5"
        );
    }

    #[tokio::test]
    async fn cached_prefix_and_fetched_suffix_equal_upstream_byte_for_byte() {
        let rig = Rig::new(Some(10_000), true);
        // Indices 0..=3 already in the permanent tier.
        for i in 0..=3u32 {
            let (h, hash) = rig.lwd.roots.lock().unwrap()[0][i as usize].clone();
            rig.perm().put(
                &permanent_subtree_key("testnet", 0, i),
                root_msg(0, i, h, hash),
            );
        }
        let (body, trailers) = collect(&rig.cache, request(0, 0, 0)).await;
        assert_eq!(body, rig.want(0, 0, 0));
        assert_eq!(trailers, ok_trailers());
        // One upstream call, from the first missing index, for the rest.
        assert_eq!(rig.lwd.calls(), vec![(4, 0, 0)]);
        settle().await;
        // Every fetched root (all final) is now permanent; nothing in the cache tier but the
        // end marker for this tip (10 entries), which expires with the tip.
        for i in 4..10u32 {
            let (h, hash) = rig.lwd.roots.lock().unwrap()[0][i as usize].clone();
            assert_eq!(
                rig.perm().get(&permanent_subtree_key("testnet", 0, i)),
                Some(Bytes::from(root_msg(0, i, h, hash))),
                "index {i}"
            );
        }
        assert!(rig.store.keys_with(":subtree:").is_empty());
        assert_eq!(
            rig.store.get(&rig.end_key(0)),
            Some(Bytes::copy_from_slice(&10u32.to_be_bytes()))
        );
        assert_eq!(
            rig.store.ttl(&rig.end_key(0)),
            Some(Some(crate::rpc_cache::TIP_SCOPED_TTL_SECS))
        );
        // Second run: entirely from the permanent tier, no upstream call at all.
        let (body, trailers) = collect(&rig.cache, request(0, 0, 0)).await;
        assert_eq!(body, rig.want(0, 0, 0));
        assert_eq!(trailers, ok_trailers());
        assert_eq!(
            rig.lwd.calls().len(),
            1,
            "final entries are never refetched"
        );
        // A later start index is a sub-slice of the same bytes.
        let (body, _) = collect(&rig.cache, request(6, 0, 0)).await;
        assert_eq!(body, rig.want(0, 6, 0));
        assert_eq!(rig.lwd.calls().len(), 1);
        // Past the end: empty with grpc-status 0, as lightwalletd answers, without asking it.
        let (body, trailers) = collect(&rig.cache, request(20, 0, 0)).await;
        assert!(body.is_empty());
        assert_eq!(trailers, ok_trailers());
        assert_eq!(rig.lwd.calls().len(), 1);
    }

    #[tokio::test]
    async fn end_marker_is_tip_scoped() {
        let rig = Rig::new(Some(10_000), true);
        collect(&rig.cache, request(0, 0, 0)).await;
        settle().await;
        assert_eq!(rig.lwd.calls(), vec![(0, 0, 0)]);
        // A new block: the list may have grown, so the tail is asked for once more.
        rig.set_tip(10_001, 0);
        let (body, trailers) = collect(&rig.cache, request(0, 0, 0)).await;
        assert_eq!(body, rig.want(0, 0, 0));
        assert_eq!(trailers, ok_trailers());
        assert_eq!(rig.lwd.calls(), vec![(0, 0, 0), (10, 0, 0)]);
        settle().await;
        // ... and then not again at this tip.
        collect(&rig.cache, request(0, 0, 0)).await;
        assert_eq!(rig.lwd.calls().len(), 2);
        // A limited request that ends early also ends the list.
        rig.set_tip(10_002, 0);
        let (body, _) = collect(&rig.cache, request(8, 0, 5)).await;
        assert_eq!(body, rig.want(0, 8, 5));
        assert_eq!(rig.lwd.calls().last(), Some(&(10, 0, 3)));
        settle().await;
        assert_eq!(
            rig.store.get(&rig.end_key(0)),
            Some(Bytes::copy_from_slice(&10u32.to_be_bytes()))
        );
        collect(&rig.cache, request(0, 0, 0)).await;
        assert_eq!(rig.lwd.calls().len(), 3);
        // A limited request that fills its limit says nothing about the end.
        rig.set_tip(10_003, 0);
        collect(&rig.cache, request(9, 0, 1)).await;
        assert_eq!(
            rig.lwd.calls().last(),
            Some(&(10, 0, 3)),
            "served from cache"
        );
        collect(&rig.cache, request(5, 0, 5)).await;
        assert_eq!(rig.lwd.calls().len(), 3, "5..=9 cached, limit filled");
        assert_eq!(rig.store.get(&rig.end_key(0)), None);
    }

    #[tokio::test]
    async fn a_tip_moving_during_the_fetch_leaves_no_marker() {
        let store = Arc::new(MemStore::default());
        store.tip.set(Tip {
            height: 10_000,
            hash: block_hash(10_000, 0),
        });
        let lwd = Arc::new(FakeRoots {
            roots: std::sync::Mutex::new(vec![vec![(1000, block_hash(1000, 0))], vec![]]),
            calls: std::sync::Mutex::new(vec![]),
            delay: Some(std::time::Duration::from_millis(50)),
        });
        let cache = Arc::new(SubtreeRootsCache::new(
            store.clone(),
            lwd.clone(),
            "testnet".to_string(),
        ));
        let (served, _) = tokio::join!(collect(&cache, request(0, 0, 0)), async {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            store.tip.set(Tip {
                height: 10_001,
                hash: block_hash(10_001, 0),
            });
        });
        assert_eq!(served.0, concat(&lwd.frames_for(0, 0, 0)));
        settle().await;
        assert!(store.keys_with(":subtree_end:").is_empty());
        // At the new tip the end is learnt again.
        collect(&cache, request(0, 0, 0)).await;
        settle().await;
        assert_eq!(lwd.calls(), vec![(0, 0, 0), (1, 0, 0)]);
        assert_eq!(store.keys_with(":subtree_end:").len(), 1);
    }

    #[tokio::test]
    async fn max_entries_limits_the_cached_prefix_and_the_upstream_call() {
        let rig = Rig::new(Some(10_000), true);
        // maxEntries 3 from 2: upstream gets exactly that.
        let (body, trailers) = collect(&rig.cache, request(2, 0, 3)).await;
        assert_eq!(body, rig.want(0, 2, 3));
        assert_eq!(trailers, ok_trailers());
        assert_eq!(rig.lwd.calls(), vec![(2, 0, 3)]);
        settle().await;
        // 2..=4 cached: a request for 5 from 2 streams them and fetches the two left.
        let (body, _) = collect(&rig.cache, request(2, 0, 5)).await;
        assert_eq!(body, rig.want(0, 2, 5));
        assert_eq!(rig.lwd.calls(), vec![(2, 0, 3), (5, 0, 2)]);
        settle().await;
        // Fully cached limit: no upstream call.
        let (body, trailers) = collect(&rig.cache, request(3, 0, 2)).await;
        assert_eq!(body, rig.want(0, 3, 2));
        assert_eq!(trailers, ok_trailers());
        assert_eq!(rig.lwd.calls().len(), 2);
        // A limit larger than what exists ends where lightwalletd ends.
        let (body, _) = collect(&rig.cache, request(8, 0, 50)).await;
        assert_eq!(body, rig.want(0, 8, 50));
        assert_eq!(rig.lwd.calls().last(), Some(&(8, 0, 50)));
        settle().await;
        // maxEntries 0 from 0 with 2..=6 and 8..=9 cached: the hole at 0 sends the whole
        // request upstream (one call, never two).
        let (body, _) = collect(&rig.cache, request(0, 0, 0)).await;
        assert_eq!(body, rig.want(0, 0, 0));
        assert_eq!(rig.lwd.calls().len(), 4);
        assert_eq!(rig.lwd.calls().last(), Some(&(0, 0, 0)));
        settle().await;
        // Everything cached and the end known: nothing goes upstream any more.
        for (start, max) in [(0, 0), (7, 0), (7, 3), (9, 10), (10, 0)] {
            let (body, trailers) = collect(&rig.cache, request(start, 0, max)).await;
            assert_eq!(body, rig.want(0, start, max), "{start}/{max}");
            assert_eq!(trailers, ok_trailers());
        }
        assert_eq!(rig.lwd.calls().len(), 4);
    }

    #[tokio::test]
    async fn non_final_entries_are_validated_against_the_index() {
        let rig = Rig::new(Some(10_000), true);
        let prefix = rig.prefix();
        let (body, _) = collect(&rig.cache, request(0, 1, 0)).await;
        assert_eq!(body, rig.want(1, 0, 0));
        settle().await;
        // 0 and 1 are final (permanent); 2 completes at 9_950, non-final: cache tier + pointer.
        assert!(rig
            .perm()
            .get(&permanent_subtree_key("testnet", 1, 1))
            .is_some());
        assert_eq!(
            rig.perm().get(&permanent_subtree_key("testnet", 1, 2)),
            None
        );
        assert!(rig.store.get(&subtree_key(&prefix, 1, 2)).is_some());
        assert_eq!(
            rig.store.get(&subtree_at_key(&prefix, 1, 9950)),
            Some(Bytes::copy_from_slice(&2u32.to_be_bytes()))
        );
        // No index entry at 9_950 yet: not served, kept, refetched from there.
        let (body, _) = collect(&rig.cache, request(0, 1, 0)).await;
        assert_eq!(body, rig.want(1, 0, 0));
        assert_eq!(rig.lwd.calls(), vec![(0, 1, 0), (2, 1, 0)]);
        assert!(rig.store.get(&subtree_key(&prefix, 1, 2)).is_some());
        settle().await;
        // Indexed with the same hash: served from the cache tier, no call.
        rig.index(9950, block_hash(9950, 0));
        let (body, _) = collect(&rig.cache, request(0, 1, 0)).await;
        assert_eq!(body, rig.want(1, 0, 0));
        assert_eq!(rig.lwd.calls().len(), 2);
        // A reorg replaces blocks 9_950..: the index and the tip change, lightwalletd reports
        // the new completing hash; the cached entry is stale, dropped and refetched.
        rig.index(9950, block_hash(9950, 1));
        rig.set_tip(10_000, 1);
        rig.lwd.set(1, 2, 9950, block_hash(9950, 1));
        let (body, trailers) = collect(&rig.cache, request(0, 1, 0)).await;
        assert_eq!(body, rig.want(1, 0, 0));
        assert_eq!(trailers, ok_trailers());
        assert_eq!(rig.lwd.calls(), vec![(0, 1, 0), (2, 1, 0), (2, 1, 0)]);
        settle().await;
        assert_eq!(
            rig.store.get(&subtree_key(&prefix, 1, 2)),
            Some(Bytes::from(root_msg(1, 2, 9950, block_hash(9950, 1)))),
            "replaced by the canonical root"
        );
        // Once final, the entry found in the cache tier moves to the permanent tier.
        rig.set_tip(10_100, 1);
        let (body, _) = collect(&rig.cache, request(2, 1, 0)).await;
        assert_eq!(body, rig.want(1, 2, 0));
        assert_eq!(
            rig.lwd.calls().last(),
            Some(&(3, 1, 0)),
            "tail asked at the new tip"
        );
        settle().await;
        assert!(rig
            .perm()
            .get(&permanent_subtree_key("testnet", 1, 2))
            .is_some());
        assert_eq!(rig.store.get(&subtree_key(&prefix, 1, 2)), None);
        assert_eq!(rig.store.get(&subtree_at_key(&prefix, 1, 9950)), None);
    }

    #[tokio::test]
    async fn reorg_keys_cover_the_pointers_in_the_span() {
        let rig = Rig::new(Some(10_000), true);
        let prefix = rig.prefix();
        collect(&rig.cache, request(0, 1, 0)).await;
        settle().await;
        // 9_950 is above a fork at 9_940: the entry and its pointer are deleted.
        let keys = reorg_keys(&*rig.store, &prefix, 9941, 10_000).await;
        assert!(keys.contains(&subtree_key(&prefix, 1, 2)));
        assert!(keys.contains(&subtree_at_key(&prefix, 1, 9950)));
        assert!(!keys.contains(&subtree_key(&prefix, 1, 1)));
        rig.store.del(keys).await;
        assert_eq!(rig.store.get(&subtree_key(&prefix, 1, 2)), None);
        // Below the fork: untouched.
        let keys = reorg_keys(&*rig.store, &prefix, 9951, 10_000).await;
        assert!(!keys.iter().any(|k| k.contains(":subtree:1:")));
        assert!(reorg_keys(&*rig.store, &prefix, 5, 4).await.is_empty());
    }

    #[tokio::test]
    async fn without_a_permanent_tier_final_entries_are_trusted_below_the_window() {
        let rig = Rig::new(Some(10_000), false);
        let prefix = rig.prefix();
        let (body, _) = collect(&rig.cache, request(0, 0, 0)).await;
        assert_eq!(body, rig.want(0, 0, 0));
        settle().await;
        for i in 0..10u32 {
            assert!(rig.store.get(&subtree_key(&prefix, 0, i)).is_some(), "{i}");
            assert_eq!(
                rig.store.ttl(&subtree_key(&prefix, 0, i)),
                Some(None),
                "no TTL"
            );
        }
        let (body, _) = collect(&rig.cache, request(0, 0, 0)).await;
        assert_eq!(body, rig.want(0, 0, 0));
        assert_eq!(rig.lwd.calls().len(), 1);
        // Tip unknown: nothing in the cache tier can be validated; everything is refetched.
        let rig2 = Rig::new(None, false);
        let (body, _) = collect(&rig2.cache, request(0, 0, 0)).await;
        assert_eq!(body, rig2.want(0, 0, 0));
        settle().await;
        collect(&rig2.cache, request(0, 0, 0)).await;
        assert_eq!(rig2.lwd.calls().len(), 2);
        assert!(rig2.store.keys_with(":subtree_end:").is_empty());
    }

    #[tokio::test]
    async fn permanent_entries_are_served_without_a_tip() {
        let rig = Rig::new(Some(10_000), true);
        collect(&rig.cache, request(0, 0, 0)).await;
        settle().await;
        let fresh = Rig::new(None, true);
        for (k, v) in rig.perm().data.lock().unwrap().iter() {
            fresh.perm().put(k, v.clone());
        }
        let (body, trailers) = collect(&fresh.cache, request(0, 0, 0)).await;
        assert_eq!(body, fresh.want(0, 0, 0));
        assert_eq!(trailers, ok_trailers());
        // The permanent tier covers 0..=9; without a tip there is no end marker, so the tail
        // is asked for once.
        assert_eq!(fresh.lwd.calls(), vec![(10, 0, 0)]);
        let (body, _) = collect(&fresh.cache, request(3, 0, 4)).await;
        assert_eq!(body, fresh.want(0, 3, 4));
        assert_eq!(
            fresh.lwd.calls().len(),
            1,
            "a bounded request inside the tier never calls upstream"
        );
    }

    #[tokio::test]
    async fn identical_gaps_share_one_upstream_call() {
        let store = Arc::new(MemStore::default());
        store.tip.set(Tip {
            height: 10_000,
            hash: block_hash(10_000, 0),
        });
        let lwd = Arc::new(FakeRoots {
            roots: std::sync::Mutex::new(vec![
                (0..10u64)
                    .map(|i| (1000 + 500 * i, block_hash(1000 + 500 * i, 0)))
                    .collect(),
                vec![],
            ]),
            calls: std::sync::Mutex::new(vec![]),
            delay: Some(std::time::Duration::from_millis(50)),
        });
        let cache = Arc::new(SubtreeRootsCache::new(
            store.clone(),
            lwd.clone(),
            "testnet".to_string(),
        ));
        let (a, b, c) = tokio::join!(
            collect(&cache, request(0, 0, 0)),
            collect(&cache, request(0, 0, 0)),
            collect(&cache, request(0, 0, 0)),
        );
        let want = concat(&lwd.frames_for(0, 0, 0));
        assert_eq!(a.0, want);
        assert_eq!(b.0, want);
        assert_eq!(c.0, want);
        assert_eq!(a.1, ok_trailers());
        assert_eq!(lwd.calls().len(), 1, "singleflight");
        assert_eq!(cache.in_flight(), 0);
        settle().await;
        collect(&cache, request(0, 0, 3)).await;
        assert_eq!(lwd.calls().len(), 1, "0..=2 are cached by now");
    }

    #[tokio::test]
    async fn upstream_failure_is_forwarded_after_the_cached_prefix() {
        struct Failing;
        impl RpcSource for Failing {
            fn call(
                &self,
                _: String,
                _: Vec<u8>,
                _: Option<uuid::Uuid>,
            ) -> BoxFuture<'static, Result<crate::singleflight::RpcResponse>> {
                Box::pin(async { Err(anyhow::anyhow!("down")) })
            }
        }
        let store = Arc::new(MemStore::default());
        let perm = Arc::new(MemPermanent::default());
        perm.put(
            &permanent_subtree_key("testnet", 0, 0),
            root_msg(0, 0, 1000, block_hash(1000, 0)),
        );
        let cache = Arc::new(
            SubtreeRootsCache::new(store, Arc::new(Failing), "testnet".to_string())
                .with_permanent(perm),
        );
        let (body, trailers) = collect(&cache, request(0, 0, 0)).await;
        assert_eq!(
            body,
            grpc_frame(&root_msg(0, 0, 1000, block_hash(1000, 0))).to_vec()
        );
        assert_eq!(trailers[0], ("grpc-status".to_string(), "14".to_string()));
    }
}

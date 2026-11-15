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

//! Chain-validated per-request cache for the lightwalletd RPCs other than `GetBlockRange`.
//!
//! What reaches the node behind lightwalletd is `GetTreeState`, `GetTransaction`, `GetSubtreeRoots`, `GetAddressUtxos`
//! and the mempool; lightwalletd serves block ranges from its own store. So these are the
//! entries that matter, and none of them relies on a TTL for correctness: each is tied to chain
//! state and served only while that state is current (tip-scoped entries also carry a safety
//! expiry, [`TIP_SCOPED_TTL_SECS`]).
//!
//! - **Validated** entries carry the block height and hash they belong to and are served only
//!   if that hash is the follower's index hash at that height (with no index entry, they are
//!   trusted only below the index window). `GetTreeState(height)` takes the hash from the
//!   `TreeState.hash` field,
//!   `GetBlock`/`GetBlockNullifiers` from the CompactBlock, `GetTransaction` from the index at
//!   the transaction's height. Mempool transactions (height 0 or -1) are not cached.
//! - **Immutable** entries (`GetTreeState` by block hash) never change for that hash.
//! - **Tip-scoped** entries (`GetLightdInfo`, `GetLatestTreeState`, `GetAddressUtxos(Stream)`,
//!   and `GetSubtreeRoots` requests `subtree_cache` cannot key) are keyed by the current tip
//!   hash, so they are valid exactly until the next block, including after a reorg. Without a
//!   known tip they bypass the cache. Keyable `GetSubtreeRoots` requests are assembled per
//!   entry by `subtree_cache` instead. An answer that names its own chain position is stored
//!   and served only when it is at the tip of its key ([`matches_tip`]): a `GetLatestTreeState`
//!   whose height and hash are the tip's, a `GetLightdInfo` whose `blockHeight` is at least the
//!   tip height (it carries no hash, so this catches an instance that is behind, not one on
//!   another fork at the same height). An entry that does not match (written by an older
//!   gateway) is deleted on read and fetched again.
//!
//! Values are bincode `InnerResponse`s (validated ones behind a small header). The keys sit
//! under the epoch/version/policy prefix, so an epoch bump or a policy change still flushes.
//! The Redis plumbing (connections, pinned tier, replay, epoch) is `cache::ResponseCache`,
//! which implements the [`CacheStore`] this module works against.

use crate::block_cache::CompactBlockHead;
use crate::ohttp::InnerResponse;
use crate::store::{hash_is_current, index_key, CacheStore, Tip, Validity, INDEX_WINDOW};
use bytes::Bytes;
use prost::Message;
use sha2::{Digest, Sha256};
use tracing::debug;

/// Largest serialized response admitted to the per-request cache (8 MiB).
pub const MAX_CACHEABLE_SIZE: usize = 8 * 1024 * 1024;
/// Safety expiry of tip-scoped entries; they are dead after the next block anyway.
pub const TIP_SCOPED_TTL_SECS: u64 = 600;

const RPC_PREFIX: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/";

#[derive(Clone, PartialEq, prost::Message)]
pub struct BlockId {
    #[prost(uint64, tag = "1")]
    pub height: u64,
    #[prost(bytes, tag = "2")]
    pub hash: Vec<u8>,
}

/// TreeState: network 1, height 2, hash 3 (RPC display-order hex), time 4, trees 5/6.
#[derive(Clone, PartialEq, prost::Message)]
pub struct TreeStateHead {
    #[prost(uint64, tag = "2")]
    pub height: u64,
    #[prost(string, tag = "3")]
    pub hash: String,
}

/// LightdInfo (service.proto): blockHeight 7, the node's best chain height.
#[derive(Clone, PartialEq, prost::Message)]
struct LightdInfoHead {
    #[prost(uint64, tag = "7")]
    block_height: u64,
}

/// RawTransaction: data 1, height 2 (0 or u64::MAX for mempool transactions).
#[derive(Clone, PartialEq, prost::Message)]
struct RawTransactionHead {
    #[prost(uint64, tag = "2")]
    height: u64,
}

/// Where a validated entry's (height, hash) comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashSource {
    /// The response is a CompactBlock: height 2, hash 3.
    CompactBlock,
    /// The response is a TreeState: height 2, hash 3 as hex.
    TreeState,
    /// The response carries a height only (RawTransaction): the hash is the index's.
    Index,
}

/// How a request is cached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Policy {
    Bypass,
    /// Key fixed by the request; the entry carries the chain state it belongs to.
    Validated {
        key: String,
        source: HashSource,
    },
    /// Key fixed by the request; never changes.
    Immutable {
        key: String,
    },
    /// Keyed by the current tip hash.
    TipScoped {
        key: String,
    },
}

/// A miss ticket: what [`store`] needs once the response has been collected.
pub struct CacheMiss {
    pub key: String,
    pub epoch: u64,
    pub ttl: Option<u64>,
    pub validate: Option<HashSource>,
    pub is_grpc: bool,
    pub path: String,
    pub rpc: String,
    /// Set by `cache::ResponseCache` when the request is inside the pinned tier's range.
    pub pinned_height: Option<u64>,
    /// The tip a tip-scoped key belongs to: the answer must match it ([`matches_tip`]).
    pub tip: Option<Tip>,
}

pub enum CacheLookup {
    Bypass,
    /// A bincode-serialized `InnerResponse`.
    Hit(Vec<u8>),
    Miss(CacheMiss),
}

/// `{prefix}{kind}:{height}`: the key of a height-keyed entry (used by the follower's reorg
/// invalidation too).
pub fn height_key(prefix: &str, kind: &str, height: u64) -> String {
    format!("{prefix}{kind}:{height}")
}

/// SHA-256 over length-framed (method, content-type without parameters, path, body).
fn framed_hash(method: &str, content_type: &str, path: &str, body: &[u8]) -> String {
    let normalized_ct = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let mut h = Sha256::new();
    h.update(b"zodl-cache-v4");
    for field in [
        method.as_bytes(),
        normalized_ct.as_bytes(),
        path.as_bytes(),
        body,
    ] {
        h.update((field.len() as u32).to_be_bytes());
        h.update(field);
    }
    hex::encode(h.finalize())
}

/// The protobuf message of a single uncompressed gRPC frame, if `body` is exactly one.
pub fn grpc_message(body: &[u8]) -> Option<&[u8]> {
    if body.len() < 5 || body[0] != 0 {
        return None;
    }
    let len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    if body.len() != 5 + len {
        return None;
    }
    Some(&body[5..])
}

/// gRPC-framed `BlockId { height, hash }`.
pub fn grpc_block_id(height: u64, hash: &[u8]) -> Vec<u8> {
    let msg = BlockId {
        height,
        hash: hash.to_vec(),
    }
    .encode_to_vec();
    let mut out = Vec::with_capacity(5 + msg.len());
    out.push(0);
    out.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    out.extend_from_slice(&msg);
    out
}

/// Decide how `method path body` is cached. `tip_hash` is the follower's current tip hash.
pub fn policy(
    prefix: &str,
    method: &str,
    content_type: &str,
    path: &str,
    body: &[u8],
    tip_hash: Option<&[u8]>,
) -> Policy {
    let Some(rpc) = path.strip_prefix(RPC_PREFIX) else {
        return Policy::Bypass;
    };
    let framed = || framed_hash(method, content_type, path, body);
    match rpc {
        "GetTreeState" | "GetBlock" | "GetBlockNullifiers" => {
            let Some(id) = grpc_message(body).and_then(|m| BlockId::decode(m).ok()) else {
                return Policy::Bypass;
            };
            let (kind, source) = match rpc {
                "GetTreeState" => ("treestate", HashSource::TreeState),
                "GetBlock" => ("cblock", HashSource::CompactBlock),
                _ => ("nullifiers", HashSource::CompactBlock),
            };
            if id.height > 0 {
                Policy::Validated {
                    key: height_key(prefix, kind, id.height),
                    source,
                }
            } else if !id.hash.is_empty() {
                Policy::Immutable {
                    key: format!("{prefix}{kind}:h:{}", hex::encode(&id.hash)),
                }
            } else {
                Policy::Bypass
            }
        }
        "GetTransaction" => {
            if grpc_message(body).is_none() {
                return Policy::Bypass;
            }
            Policy::Validated {
                key: format!("{prefix}tx:{}", framed()),
                source: HashSource::Index,
            }
        }
        "GetSubtreeRoots"
        | "GetLightdInfo"
        | "GetLatestTreeState"
        | "GetAddressUtxos"
        | "GetAddressUtxosStream" => match tip_hash {
            Some(h) if !h.is_empty() => Policy::TipScoped {
                key: format!("{prefix}tip:{}:{}", hex::encode(h), framed()),
            },
            _ => Policy::Bypass,
        },
        _ => Policy::Bypass,
    }
}

const VALIDATED_TAG: u8 = 1;

/// `0x01 || height(8) || hash_len(1) || hash || payload`.
pub fn encode_validated(height: u64, hash: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + hash.len() + payload.len());
    out.push(VALIDATED_TAG);
    out.extend_from_slice(&height.to_be_bytes());
    out.push(hash.len().min(255) as u8);
    out.extend_from_slice(&hash[..hash.len().min(255)]);
    out.extend_from_slice(payload);
    out
}

/// `(height, hash, payload)` of a validated entry.
pub fn decode_validated(value: &[u8]) -> Option<(u64, &[u8], &[u8])> {
    if value.len() < 10 || value[0] != VALIDATED_TAG {
        return None;
    }
    let height = u64::from_be_bytes(value[1..9].try_into().ok()?);
    let n = value[9] as usize;
    let hash = value.get(10..10 + n)?;
    let payload = value.get(10 + n..)?;
    Some((height, hash, payload))
}

/// Whether `response` (bincode `InnerResponse`) is a success worth caching: status 200,
/// `grpc-status 0` for gRPC, at most [`MAX_CACHEABLE_SIZE`] bytes.
pub fn should_admit(response_bytes: &[u8], is_grpc: bool) -> bool {
    if response_bytes.len() > MAX_CACHEABLE_SIZE {
        return false;
    }
    match bincode::deserialize::<InnerResponse>(response_bytes) {
        Ok(resp) => {
            if resp.status != 200 {
                return false;
            }
            if is_grpc && resp.header("grpc-status").unwrap_or("-") != "0" {
                return false;
            }
            true
        }
        Err(_) => false,
    }
}

/// The (height, hash) a response belongs to, per `source`; the hash is empty for `Index`.
/// `None` when the response does not decode or is a mempool transaction.
pub fn chain_position(source: HashSource, response: &InnerResponse) -> Option<(u64, Vec<u8>)> {
    let msg = grpc_message(&response.body)?;
    match source {
        HashSource::CompactBlock => {
            let b = CompactBlockHead::decode(msg).ok()?;
            (b.height > 0 && !b.hash.is_empty()).then_some((b.height, b.hash))
        }
        HashSource::TreeState => {
            let t = TreeStateHead::decode(msg).ok()?;
            let hash = hex::decode(t.hash.trim()).ok()?;
            (t.height > 0 && !hash.is_empty()).then_some((t.height, hash))
        }
        HashSource::Index => {
            let t = RawTransactionHead::decode(msg).ok()?;
            (t.height > 0 && t.height != u64::MAX).then_some((t.height, vec![]))
        }
    }
}

/// Whether the tip-scoped answer `response` to `rpc` belongs to `tip`: `GetLightdInfo` when its
/// `blockHeight` is at least the tip height (the node may be a block ahead of lightwalletd's
/// own tip; a lower one is an instance behind), `GetLatestTreeState` when its height and hash
/// are the tip's (either byte order). Other tip-scoped answers carry no chain position: true.
/// An answer that does not decode: false.
pub fn matches_tip(rpc: &str, response: &InnerResponse, tip: &Tip) -> bool {
    match rpc {
        "GetLightdInfo" => grpc_message(&response.body)
            .and_then(|m| LightdInfoHead::decode(m).ok())
            .is_some_and(|i| i.block_height >= tip.height),
        "GetLatestTreeState" => {
            let Some(t) = grpc_message(&response.body).and_then(|m| TreeStateHead::decode(m).ok())
            else {
                return false;
            };
            let Ok(hash) = hex::decode(t.hash.trim()) else {
                return false;
            };
            let reversed: Vec<u8> = hash.iter().rev().copied().collect();
            t.height == tip.height && (hash == tip.hash || reversed == tip.hash)
        }
        _ => true,
    }
}

/// The RPCs whose tip-scoped answers [`matches_tip`] checks.
fn checks_tip(rpc: &str) -> bool {
    matches!(rpc, "GetLightdInfo" | "GetLatestTreeState")
}

/// Whether a stored tip-scoped entry `value` (bincode `InnerResponse`) of the RPC at `path` may
/// be served for `tip`: always for answers without a chain position, else [`matches_tip`].
pub fn tip_scoped_entry_matches(path: &str, value: &[u8], tip: &Tip) -> bool {
    let rpc = path.rsplit('/').next().unwrap_or("");
    !checks_tip(rpc)
        || bincode::deserialize::<InnerResponse>(value).is_ok_and(|r| matches_tip(rpc, &r, tip))
}

/// How a stored validated entry (`encode_validated`) stands against the index and `tip`; None
/// when it does not decode.
pub async fn validated_entry_validity(
    store: &dyn CacheStore,
    value: &[u8],
    tip: Option<&Tip>,
) -> Option<Validity> {
    let (height, hash, _) = decode_validated(value)?;
    if hash.is_empty() {
        // Stored as trusted (below the window at write time): still trusted below the window.
        return Some(match tip {
            Some(t) if height.saturating_add(INDEX_WINDOW) < t.height => Validity::Current,
            _ => Validity::Unknown,
        });
    }
    let index_hash = store
        .mget(vec![index_key(&store.chain_prefix(), height)])
        .await
        .into_iter()
        .next()
        .flatten();
    Some(hash_is_current(hash, height, index_hash.as_deref(), tip))
}

/// Look `method path body` up in `store`. Records `ohttp_cache_requests_total`.
pub async fn lookup(
    store: &dyn CacheStore,
    network: &str,
    method: &str,
    content_type: &str,
    path: &str,
    body: &[u8],
) -> CacheLookup {
    let rpc = crate::health::normalize_rpc_name(path, method);
    let tip = store.tip_cell().get();
    let epoch = store.epoch().await;
    let prefix = store.key_prefix(epoch);
    let pol = policy(
        &prefix,
        method,
        content_type,
        path,
        body,
        tip.as_ref().map(|t| t.hash.as_slice()),
    );
    let (key, ttl, validate, key_tip) = match pol {
        Policy::Bypass => {
            crate::health::record_cache_request(network, &rpc, "bypass");
            return CacheLookup::Bypass;
        }
        Policy::Validated { key, source } => (key, None, Some(source), None),
        Policy::Immutable { key } => (key, None, None, None),
        Policy::TipScoped { key } => (key, Some(TIP_SCOPED_TTL_SECS), None, tip.clone()),
    };
    let is_grpc = path.starts_with(RPC_PREFIX);
    let miss = |result: &str| {
        crate::health::record_cache_request(network, &rpc, result);
        CacheLookup::Miss(CacheMiss {
            key: key.clone(),
            epoch,
            ttl,
            validate,
            is_grpc,
            path: path.to_string(),
            rpc: rpc.clone(),
            pinned_height: None,
            tip: key_tip.clone(),
        })
    };

    let Some(value) = store
        .mget(vec![key.clone()])
        .await
        .into_iter()
        .next()
        .flatten()
    else {
        debug!(path, epoch, network, "cache miss");
        return miss("miss");
    };
    let Some(source) = validate else {
        if let Some(t) = &key_tip {
            if !tip_scoped_entry_matches(path, &value, t) {
                // Not at the tip of its key (left by an older gateway): fetched again.
                store.del(vec![key.clone()]).await;
                crate::health::record_cache_tip_mismatch(network, &rpc, "lookup");
                return miss("miss");
            }
        }
        crate::health::record_cache_request(network, &rpc, "hit");
        return CacheLookup::Hit(value.to_vec());
    };
    let Some(validity) = validated_entry_validity(store, &value, tip.as_ref()).await else {
        store.del(vec![key.clone()]).await;
        return miss("miss");
    };
    let Some((height, _, payload)) = decode_validated(&value) else {
        return miss("miss");
    };
    match validity {
        Validity::Current => {
            debug!(path, height, source = ?source, network, "validated cache hit");
            crate::health::record_cache_request(network, &rpc, "hit");
            CacheLookup::Hit(payload.to_vec())
        }
        Validity::Stale => {
            store.del(vec![key.clone()]).await;
            miss("validated_stale")
        }
        Validity::Unknown => miss("unvalidated"),
    }
}

/// Store `response` (bincode `InnerResponse`) under the miss ticket.
pub async fn store(store: &dyn CacheStore, network: &str, miss: CacheMiss, response: &[u8]) {
    let path = miss.path.as_str();
    if !should_admit(response, miss.is_grpc) {
        debug!(
            path,
            network, "response not admitted to cache (non-success)"
        );
        return;
    }
    if let Some(tip) = &miss.tip {
        if !tip_scoped_entry_matches(path, response, tip) {
            debug!(
                path,
                network, "not cached: the answer is not at the tip of its key"
            );
            crate::health::record_cache_tip_mismatch(network, &miss.rpc, "store");
            return;
        }
    }
    let value: Vec<u8> = match miss.validate {
        None => response.to_vec(),
        Some(source) => {
            let Ok(resp) = bincode::deserialize::<InnerResponse>(response) else {
                return;
            };
            let Some((height, mut hash)) = chain_position(source, &resp) else {
                debug!(
                    path,
                    network, "not cached: no chain position (mempool or undecodable)"
                );
                crate::health::record_cache_request(network, &miss.rpc, "not_positioned");
                return;
            };
            if hash.is_empty() {
                let index_hash = store
                    .mget(vec![index_key(&store.chain_prefix(), height)])
                    .await
                    .into_iter()
                    .next()
                    .flatten();
                match index_hash {
                    Some(h) => hash = h.to_vec(),
                    None => {
                        let trusted = store
                            .tip_cell()
                            .get()
                            .is_some_and(|t| height.saturating_add(INDEX_WINDOW) < t.height);
                        if !trusted {
                            debug!(
                                path,
                                height, network, "not cached: no index entry inside the window"
                            );
                            crate::health::record_cache_request(network, &miss.rpc, "not_indexed");
                            return;
                        }
                    }
                }
            }
            encode_validated(height, &hash, response)
        }
    };
    store
        .set(miss.key, Bytes::from(value), miss.ttl, Some(miss.epoch))
        .await;
    debug!(path, epoch = miss.epoch, network, "cache write");
}

/// The vendored lightwalletd protocol files (`proto/lightwalletd`, see its README) and a
/// textual lookup of field numbers, for tests that pin the hand-written messages to them.
#[cfg(test)]
pub(crate) mod vendored_proto {
    pub const COMPACT_FORMATS: &str = include_str!("../proto/lightwalletd/compact_formats.proto");
    pub const SERVICE: &str = include_str!("../proto/lightwalletd/service.proto");

    /// The field number of `field` in `message` of `proto`.
    pub fn field_number(proto: &str, message: &str, field: &str) -> Option<u32> {
        let start = proto.find(&format!("message {message} {{"))?;
        let body = &proto[start..];
        let body = &body[..body.find("\n}")?];
        body.lines().find_map(|line| {
            let line = line.split("//").next()?.trim();
            let (decl, number) = line.split_once('=')?;
            if decl.split_whitespace().last()? != field {
                return None;
            }
            number.trim().trim_end_matches(';').trim().parse().ok()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::test_support::MemStore;
    use crate::store::Tip;
    use std::sync::Arc;

    const CT: &str = "application/grpc";

    fn frame(msg: &[u8]) -> Vec<u8> {
        crate::block_cache::grpc_frame(msg).to_vec()
    }

    fn ok_response(body: Vec<u8>) -> Vec<u8> {
        bincode::serialize(&InnerResponse {
            status: 200,
            headers: vec![
                ("content-type".to_string(), CT.to_string()),
                ("grpc-status".to_string(), "0".to_string()),
            ],
            body,
        })
        .unwrap()
    }

    #[derive(Clone, PartialEq, prost::Message)]
    struct RawTransaction {
        #[prost(bytes, tag = "1")]
        data: Vec<u8>,
        #[prost(uint64, tag = "2")]
        height: u64,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    struct TreeState {
        #[prost(string, tag = "1")]
        network: String,
        #[prost(uint64, tag = "2")]
        height: u64,
        #[prost(string, tag = "3")]
        hash: String,
        #[prost(uint32, tag = "4")]
        time: u32,
        #[prost(string, tag = "5")]
        sapling_tree: String,
    }

    fn path(rpc: &str) -> String {
        format!("{RPC_PREFIX}{rpc}")
    }

    fn store_with_tip(height: u64) -> Arc<MemStore> {
        let s = Arc::new(MemStore::default());
        s.tip.set(Tip {
            height,
            hash: vec![0xaa; 32],
        });
        s
    }

    fn set_index(s: &MemStore, height: u64, hash: &[u8]) {
        s.put(&index_key(&s.chain_prefix(), height), hash.to_vec());
    }

    async fn lookup_miss(s: &MemStore, p: &str, body: &[u8]) -> CacheMiss {
        match lookup(s, "testnet", "POST", CT, p, body).await {
            CacheLookup::Miss(m) => m,
            CacheLookup::Hit(_) => panic!("unexpected hit"),
            CacheLookup::Bypass => panic!("unexpected bypass"),
        }
    }

    async fn lookup_hit(s: &MemStore, p: &str, body: &[u8]) -> Vec<u8> {
        match lookup(s, "testnet", "POST", CT, p, body).await {
            CacheLookup::Hit(v) => v,
            CacheLookup::Miss(_) => panic!("unexpected miss"),
            CacheLookup::Bypass => panic!("unexpected bypass"),
        }
    }

    #[test]
    fn policies_by_rpc() {
        let prefix = "p:";
        let tip = [7u8; 32];
        // GetTreeState by height: validated; by hash: immutable; empty: bypass.
        assert_eq!(
            policy(
                prefix,
                "POST",
                CT,
                &path("GetTreeState"),
                &grpc_block_id(500, &[]),
                Some(&tip)
            ),
            Policy::Validated {
                key: "p:treestate:500".to_string(),
                source: HashSource::TreeState
            }
        );
        assert_eq!(
            policy(
                prefix,
                "POST",
                CT,
                &path("GetTreeState"),
                &grpc_block_id(0, &[1, 2]),
                Some(&tip)
            ),
            Policy::Immutable {
                key: "p:treestate:h:0102".to_string()
            }
        );
        assert_eq!(
            policy(
                prefix,
                "POST",
                CT,
                &path("GetTreeState"),
                &grpc_block_id(0, &[]),
                Some(&tip)
            ),
            Policy::Bypass
        );
        assert!(matches!(
            policy(prefix, "POST", CT, &path("GetBlock"), &grpc_block_id(9, &[]), None),
            Policy::Validated { key, source: HashSource::CompactBlock } if key == "p:cblock:9"
        ));
        assert!(matches!(
            policy(prefix, "POST", CT, &path("GetTransaction"), &frame(&[0x1a, 1, 9]), None),
            Policy::Validated { key, source: HashSource::Index } if key.starts_with("p:tx:")
        ));
        // Tip-scoped: the tip hash is in the key; no tip: bypass.
        let k1 = policy(
            prefix,
            "POST",
            CT,
            &path("GetSubtreeRoots"),
            &frame(&[8, 1]),
            Some(&tip),
        );
        assert!(
            matches!(&k1, Policy::TipScoped { key } if key.starts_with(&format!("p:tip:{}:", hex::encode(tip))))
        );
        let k2 = policy(
            prefix,
            "POST",
            CT,
            &path("GetSubtreeRoots"),
            &frame(&[8, 1]),
            Some(&[8u8; 32]),
        );
        assert_ne!(k1, k2);
        assert_eq!(
            policy(
                prefix,
                "POST",
                CT,
                &path("GetLightdInfo"),
                &frame(&[]),
                None
            ),
            Policy::Bypass
        );
        for rpc in [
            "GetLightdInfo",
            "GetLatestTreeState",
            "GetAddressUtxos",
            "GetAddressUtxosStream",
        ] {
            assert!(
                matches!(
                    policy(prefix, "POST", CT, &path(rpc), &frame(&[]), Some(&tip)),
                    Policy::TipScoped { .. }
                ),
                "{rpc}"
            );
        }
        // Never cached.
        for rpc in [
            "SendTransaction",
            "GetMempoolStream",
            "GetMempoolTx",
            "GetLatestBlock",
            "GetTaddressTxids",
            "Ping",
        ] {
            assert_eq!(
                policy(prefix, "POST", CT, &path(rpc), &frame(&[]), Some(&tip)),
                Policy::Bypass,
                "{rpc}"
            );
        }
        assert_eq!(
            policy(prefix, "GET", "", "/v1/other", b"", Some(&tip)),
            Policy::Bypass
        );
    }

    #[test]
    fn validated_entry_roundtrip() {
        let v = encode_validated(123, &[1, 2, 3], b"payload");
        assert_eq!(
            decode_validated(&v),
            Some((123, &[1u8, 2, 3][..], &b"payload"[..]))
        );
        assert_eq!(decode_validated(b"garbage"), None);
        assert_eq!(
            decode_validated(&ok_response(vec![])),
            None,
            "a plain entry is not validated"
        );
    }

    #[tokio::test]
    async fn mempool_transaction_is_not_cached_mined_one_is_and_a_reorg_invalidates_it() {
        let s = store_with_tip(1000);
        let p = path("GetTransaction");
        let req = frame(&[0x1a, 2, 0xab, 0xcd]);
        // Mempool: height 0, and height -1 (u64::MAX) as the node RPC reports it.
        for h in [0u64, u64::MAX] {
            let miss = lookup_miss(&s, &p, &req).await;
            let resp = ok_response(frame(
                &RawTransaction {
                    data: vec![1, 2, 3],
                    height: h,
                }
                .encode_to_vec(),
            ));
            store(&*s, "testnet", miss, &resp).await;
            assert!(
                s.keys_with(":tx:").is_empty(),
                "height {h} must not be cached"
            );
        }
        // Mined at 950, inside the window, index known: cached with the index hash.
        set_index(&s, 950, &[5u8; 32]);
        let miss = lookup_miss(&s, &p, &req).await;
        let resp = ok_response(frame(
            &RawTransaction {
                data: vec![1, 2, 3],
                height: 950,
            }
            .encode_to_vec(),
        ));
        store(&*s, "testnet", miss, &resp).await;
        assert_eq!(s.keys_with(":tx:").len(), 1);
        assert_eq!(lookup_hit(&s, &p, &req).await, resp);
        // Reorg at 950: the index changes, the entry is stale, dropped, a miss again.
        set_index(&s, 950, &[6u8; 32]);
        let miss = lookup_miss(&s, &p, &req).await;
        assert!(s.keys_with(":tx:").is_empty(), "stale entry deleted");
        // Refetched and stored under the new hash.
        store(&*s, "testnet", miss, &resp).await;
        assert_eq!(lookup_hit(&s, &p, &req).await, resp);
        // Inside the window with no index entry: not cached.
        let s2 = store_with_tip(1000);
        let miss = lookup_miss(&s2, &p, &req).await;
        store(&*s2, "testnet", miss, &resp).await;
        assert!(s2.keys_with(":tx:").is_empty());
        // Below the window: trusted without an index entry.
        let s3 = store_with_tip(5000);
        let miss = lookup_miss(&s3, &p, &req).await;
        store(&*s3, "testnet", miss, &resp).await;
        assert_eq!(lookup_hit(&s3, &p, &req).await, resp);
    }

    #[tokio::test]
    async fn tree_state_by_height_is_validated_in_either_byte_order() {
        let s = store_with_tip(1000);
        let p = path("GetTreeState");
        let req = grpc_block_id(900, &[]);
        let internal: Vec<u8> = (0u8..32).collect();
        let mut display = internal.clone();
        display.reverse();
        set_index(&s, 900, &internal);
        let miss = lookup_miss(&s, &p, &req).await;
        assert_eq!(miss.key, format!("{}treestate:900", s.key_prefix(42)));
        let resp = ok_response(frame(
            &TreeState {
                network: "test".to_string(),
                height: 900,
                hash: hex::encode(&display),
                time: 1,
                sapling_tree: "00".to_string(),
            }
            .encode_to_vec(),
        ));
        store(&*s, "testnet", miss, &resp).await;
        assert_eq!(lookup_hit(&s, &p, &req).await, resp);
        assert_eq!(
            s.ttl(&format!("{}treestate:900", s.key_prefix(42))),
            Some(None),
            "no TTL"
        );
        // The chain moves under it.
        set_index(&s, 900, &[1u8; 32]);
        lookup_miss(&s, &p, &req).await;
        assert!(s
            .get(&format!("{}treestate:900", s.key_prefix(42)))
            .is_none());
        // By hash: immutable, served without any index.
        let req_h = grpc_block_id(0, &internal);
        let miss = lookup_miss(&s, &p, &req_h).await;
        store(&*s, "testnet", miss, &resp).await;
        assert_eq!(lookup_hit(&s, &p, &req_h).await, resp);
        // A failed response is never stored.
        let miss = lookup_miss(&s, &p, &grpc_block_id(901, &[])).await;
        let failed = bincode::serialize(&InnerResponse {
            status: 200,
            headers: vec![("grpc-status".to_string(), "5".to_string())],
            body: vec![],
        })
        .unwrap();
        store(&*s, "testnet", miss, &failed).await;
        assert!(s
            .get(&format!("{}treestate:901", s.key_prefix(42)))
            .is_none());
    }

    #[tokio::test]
    async fn tip_scoped_entries_change_with_the_tip() {
        let s = Arc::new(MemStore::default());
        let p = path("GetSubtreeRoots");
        let req = frame(&[8, 1, 16, 2]);
        // No tip yet: bypass.
        assert!(matches!(
            lookup(&*s, "testnet", "POST", CT, &p, &req).await,
            CacheLookup::Bypass
        ));
        let tip_a = Tip {
            height: 100,
            hash: vec![0xa; 32],
        };
        let tip_b = Tip {
            height: 101,
            hash: vec![0xb; 32],
        };
        s.tip.set(tip_a.clone());
        let miss = lookup_miss(&s, &p, &req).await;
        assert_eq!(miss.ttl, Some(TIP_SCOPED_TTL_SECS));
        let resp_a = ok_response(b"roots-at-a".to_vec());
        store(&*s, "testnet", miss, &resp_a).await;
        assert_eq!(lookup_hit(&s, &p, &req).await, resp_a);
        // New block: a different key, so a miss; the answer at B is stored separately.
        s.tip.set(tip_b.clone());
        let miss = lookup_miss(&s, &p, &req).await;
        let resp_b = ok_response(b"roots-at-b".to_vec());
        store(&*s, "testnet", miss, &resp_b).await;
        assert_eq!(lookup_hit(&s, &p, &req).await, resp_b);
        assert_eq!(s.keys_with(":tip:").len(), 2);
        // Back at A (a reorg to the old tip): the old answer is still right and still there.
        s.tip.set(tip_a);
        assert_eq!(lookup_hit(&s, &p, &req).await, resp_a);
        // GetLightdInfo shares the mechanism.
        let info = ok_response(frame(&LightdInfoHead { block_height: 100 }.encode_to_vec()));
        let miss = lookup_miss(&s, &path("GetLightdInfo"), &frame(&[])).await;
        store(&*s, "testnet", miss, &info).await;
        assert_eq!(
            lookup_hit(&s, &path("GetLightdInfo"), &frame(&[])).await,
            info
        );
    }

    #[test]
    fn decoded_fields_match_the_vendored_service_proto() {
        use super::vendored_proto::{field_number, SERVICE};
        assert_eq!(field_number(SERVICE, "LightdInfo", "blockHeight"), Some(7));
        assert_eq!(
            LightdInfoHead { block_height: 1 }.encode_to_vec(),
            vec![7 << 3, 1]
        );
        assert_eq!(field_number(SERVICE, "TreeState", "height"), Some(2));
        assert_eq!(field_number(SERVICE, "TreeState", "hash"), Some(3));
        let t = TreeStateHead {
            height: 1,
            hash: "a".to_string(),
        }
        .encode_to_vec();
        assert_eq!(t, vec![2 << 3, 1, (3 << 3) | 2, 1, b'a']);
    }

    #[tokio::test]
    async fn a_stored_tip_scoped_entry_of_another_tip_is_not_served() {
        let s = Arc::new(MemStore::default());
        s.tip.set(Tip {
            height: 700,
            hash: vec![0x11; 32],
        });
        let p = path("GetLightdInfo");
        // An entry under the tip's key with the answer of an instance behind, as an older
        // gateway (without the store check) wrote it.
        let miss = lookup_miss(&s, &p, &frame(&[])).await;
        let poisoned = ok_response(frame(&LightdInfoHead { block_height: 699 }.encode_to_vec()));
        s.put(&miss.key, poisoned);
        let before = crate::health::cache_tip_mismatches("testnet-read", "GetLightdInfo", "lookup");
        match lookup(&*s, "testnet-read", "POST", CT, &p, &frame(&[])).await {
            CacheLookup::Miss(m) => assert_eq!(m.key, miss.key),
            _ => panic!("a mismatching entry is a miss"),
        }
        assert_eq!(s.get(&miss.key), None, "deleted");
        assert_eq!(
            crate::health::cache_tip_mismatches("testnet-read", "GetLightdInfo", "lookup"),
            before + 1
        );
        // The right answer is stored and served again.
        let miss = lookup_miss(&s, &p, &frame(&[])).await;
        let info = ok_response(frame(&LightdInfoHead { block_height: 700 }.encode_to_vec()));
        store(&*s, "testnet", miss, &info).await;
        assert_eq!(lookup_hit(&s, &p, &frame(&[])).await, info);
    }

    #[tokio::test]
    async fn a_tip_scoped_answer_of_another_tip_is_not_cached() {
        let s = Arc::new(MemStore::default());
        // A hash that differs from its reverse, to check both byte orders.
        let hash: Vec<u8> = (0u8..32).collect();
        s.tip.set(Tip {
            height: 500,
            hash: hash.clone(),
        });
        let info = |h: u64| ok_response(frame(&LightdInfoHead { block_height: h }.encode_to_vec()));
        // An instance one block behind answers: not cached, the next request misses again.
        let miss = lookup_miss(&s, &path("GetLightdInfo"), &frame(&[])).await;
        assert_eq!(miss.tip.as_ref().map(|t| t.height), Some(500));
        store(&*s, "testnet", miss, &info(499)).await;
        let miss = lookup_miss(&s, &path("GetLightdInfo"), &frame(&[])).await;
        store(
            &*s,
            "testnet",
            miss,
            &ok_response(b"not a LightdInfo".to_vec()),
        )
        .await;
        let miss = lookup_miss(&s, &path("GetLightdInfo"), &frame(&[])).await;
        store(&*s, "testnet", miss, &info(500)).await;
        assert_eq!(
            lookup_hit(&s, &path("GetLightdInfo"), &frame(&[])).await,
            info(500)
        );
        // A node a block ahead of lightwalletd's tip: still the answer at this tip.
        s.del(s.keys_with(":tip:")).await;
        let miss = lookup_miss(&s, &path("GetLightdInfo"), &frame(&[])).await;
        store(&*s, "testnet", miss, &info(501)).await;
        assert_eq!(
            lookup_hit(&s, &path("GetLightdInfo"), &frame(&[])).await,
            info(501)
        );

        let tree = |h: u64, hash: &[u8]| {
            ok_response(frame(
                &TreeState {
                    network: "test".to_string(),
                    height: h,
                    hash: hex::encode(hash),
                    time: 0,
                    sapling_tree: String::new(),
                }
                .encode_to_vec(),
            ))
        };
        let p = path("GetLatestTreeState");
        // Same height, another fork.
        let miss = lookup_miss(&s, &p, &frame(&[])).await;
        store(&*s, "testnet", miss, &tree(500, &[0xee; 32])).await;
        // The tip's block one height lower.
        let miss = lookup_miss(&s, &p, &frame(&[])).await;
        store(&*s, "testnet", miss, &tree(499, &hash)).await;
        let miss = lookup_miss(&s, &p, &frame(&[])).await;
        // The tip, in RPC display order (reversed).
        let display: Vec<u8> = hash.iter().rev().copied().collect();
        store(&*s, "testnet", miss, &tree(500, &display)).await;
        assert_eq!(lookup_hit(&s, &p, &frame(&[])).await, tree(500, &display));
    }

    #[tokio::test]
    async fn get_block_is_validated_by_its_own_hash() {
        let s = store_with_tip(1000);
        let chain = crate::block_cache::test_support::FakeChain::new(1000);
        let p = path("GetBlock");
        let req = grpc_block_id(990, &[]);
        set_index(&s, 990, &chain.hash_at(990));
        let miss = lookup_miss(&s, &p, &req).await;
        let resp = ok_response(frame(&chain.msg(990)));
        store(&*s, "testnet", miss, &resp).await;
        assert_eq!(lookup_hit(&s, &p, &req).await, resp);
        chain.reorg_from(990, 3);
        set_index(&s, 990, &chain.hash_at(990));
        lookup_miss(&s, &p, &req).await;
    }

    #[tokio::test]
    async fn store_outage_is_a_miss_and_a_dropped_write() {
        let s = store_with_tip(5000);
        s.down.store(true, std::sync::atomic::Ordering::SeqCst);
        let p = path("GetSubtreeRoots");
        let miss = lookup_miss(&s, &p, &frame(&[])).await;
        store(&*s, "testnet", miss, &ok_response(b"x".to_vec())).await;
        lookup_miss(&s, &p, &frame(&[])).await;
        assert!(s.data.lock().unwrap().is_empty());
    }
}

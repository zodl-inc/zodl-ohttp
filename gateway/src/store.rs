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

//! The key-value store behind the chain-validated cache, as a trait.
//!
//! `cache::ResponseCache` implements it on Redis (fail-open: every error reads as "not
//! there" and writes are dropped); tests use [`test_support::MemStore`]. Two key families
//! live in it:
//!
//! - **Cached entries** under `key_prefix(epoch)` =
//!   `ohttp:{network}:{backend}:{epoch}:v{KEY_VERSION}:{policy_hash}:` (blocks, tree states,
//!   transactions, tip-scoped answers). Writes are epoch-checked.
//! - **Chain state** under `chain_prefix()` = `ohttp:{network}:{backend}:chain:v1:`: the
//!   `height -> hash` index, the tip and the leader lock. It is chain truth, not a cached
//!   answer, so neither the epoch nor the policy hash is part of it; bumping the epoch flushes
//!   every epoch-prefixed answer and keeps the index (the permanent tier has its own keys and
//!   survives it).

use bytes::Bytes;
use futures_util::future::BoxFuture;
use std::sync::Arc;
use std::time::Duration;

/// The chain tip as the follower knows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tip {
    pub height: u64,
    pub hash: Vec<u8>,
}

/// A tip older than this is treated as unknown: tip-scoped answers then go upstream, and
/// validated entries are served only on a matching index entry.
pub const TIP_STALE_AFTER: Duration = Duration::from_secs(30);

/// The in-memory tip shared by the follower (writer) and the request paths (readers).
#[derive(Default)]
pub struct TipCell {
    inner: arc_swap::ArcSwapOption<(Tip, tokio::time::Instant)>,
}

impl TipCell {
    pub fn new() -> Self {
        Self::default()
    }

    /// The tip, unless none was seen or the last one is older than [`TIP_STALE_AFTER`].
    pub fn get(&self) -> Option<Tip> {
        let v = self.inner.load_full()?;
        if v.1.elapsed() > TIP_STALE_AFTER {
            return None;
        }
        Some(v.0.clone())
    }

    /// The last tip seen, however old.
    pub fn get_any(&self) -> Option<Tip> {
        self.inner.load_full().map(|v| v.0.clone())
    }

    pub fn set(&self, tip: Tip) {
        self.inner
            .store(Some(Arc::new((tip, tokio::time::Instant::now()))));
    }
}

/// A cached entry is always checked against the index when the index has its height; with no
/// index entry it is trusted only at depth > this below the tip (Zebra cannot reorg more than
/// 99 blocks).
pub const INDEX_WINDOW: u64 = 1000;

/// Blocks at depth >= this below a fresh tip are final (Zebra cannot reorg more than 99
/// blocks) and belong to the permanent tier.
pub const PERMANENT_DEPTH: u64 = 100;

/// Whether `height` is final against `tip`: at least [`PERMANENT_DEPTH`] below it.
pub fn is_final(height: u64, tip: &Tip) -> bool {
    height.saturating_add(PERMANENT_DEPTH) <= tip.height
}

/// Sapling activation height of `network`: the default lower bound of the permanent tier
/// (wallets never scan below it).
pub fn sapling_activation(network: &str) -> u64 {
    match network {
        "mainnet" => 419_200,
        _ => 280_000,
    }
}

/// The permanent tier key of the block at `height` for pool filter `pool`:
/// `perm:{network}:block:v1:{pool}:{height}`. No backend host, epoch or policy hash: a final
/// CompactBlock is the same whichever lightwalletd served it, so the data outlives backend
/// swaps and epoch bumps. `v1` is bumped only on a value format change.
pub fn permanent_block_key(network: &str, pool: &str, height: u64) -> String {
    format!("perm:{network}:block:v1:{pool}:{height}")
}

/// The permanent tier (a disk-backed Redis-protocol store): final blocks, no TTL, never evicted.
/// Fail-open like the cache: errors read as misses and dropped writes.
pub trait PermanentStore: Send + Sync {
    /// Values for `keys`, in order.
    fn mget(&self, keys: Vec<String>) -> BoxFuture<'_, Vec<Option<Bytes>>>;
    /// Store `value` under `key` with no expiry; true when written.
    fn set(&self, key: String, value: Bytes) -> BoxFuture<'_, bool>;
    /// Store every entry (the backfill's bulk path); true when all were written.
    fn set_many(&self, entries: Vec<(String, Bytes)>) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            for (k, v) in entries {
                if !self.set(k, v).await {
                    return false;
                }
            }
            true
        })
    }
    fn del(&self, keys: Vec<String>) -> BoxFuture<'_, ()>;
}

/// Key-value operations the cache needs. Every method is fail-open: an error reads as a miss
/// (`None` values) and a dropped write.
pub trait CacheStore: Send + Sync {
    /// The current cache epoch (operator-bumpable to flush every epoch-prefixed cached answer;
    /// the permanent tier is not affected).
    fn epoch(&self) -> BoxFuture<'_, u64>;
    /// Prefix of every cached entry of `epoch`.
    fn key_prefix(&self, epoch: u64) -> String;
    /// Prefix of the chain state (index, tip, lock).
    fn chain_prefix(&self) -> String;
    /// The in-memory tip.
    fn tip_cell(&self) -> &TipCell;
    /// Values for `keys`, in order.
    fn mget(&self, keys: Vec<String>) -> BoxFuture<'_, Vec<Option<Bytes>>>;
    /// Store `value`; `ttl_secs` None = no expiry (LRU only); `epoch` Some = write only while
    /// the shared epoch still equals it.
    fn set(
        &self,
        key: String,
        value: Bytes,
        ttl_secs: Option<u64>,
        epoch: Option<u64>,
    ) -> BoxFuture<'_, ()>;
    fn del(&self, keys: Vec<String>) -> BoxFuture<'_, ()>;
    /// `SET key value NX PX ttl_ms`: Some(true) when acquired, Some(false) when held by
    /// another value, None on error.
    fn set_nx_px(&self, key: String, value: String, ttl_ms: u64) -> BoxFuture<'_, Option<bool>>;
    /// Extend `key` by `ttl_ms` only if it still holds `value` (one atomic script).
    fn pexpire_if_equal(
        &self,
        key: String,
        value: String,
        ttl_ms: u64,
    ) -> BoxFuture<'_, Option<bool>>;
}

/// The index key of `height`.
pub fn index_key(chain_prefix: &str, height: u64) -> String {
    format!("{chain_prefix}index:{height}")
}

/// The stored tip: `height || hash`.
pub fn tip_key(chain_prefix: &str) -> String {
    format!("{chain_prefix}tip")
}

pub fn lock_key(chain_prefix: &str) -> String {
    format!("{chain_prefix}leader")
}

pub fn encode_tip(tip: &Tip) -> Bytes {
    let mut v = Vec::with_capacity(8 + tip.hash.len());
    v.extend_from_slice(&tip.height.to_be_bytes());
    v.extend_from_slice(&tip.hash);
    Bytes::from(v)
}

pub fn decode_tip(bytes: &[u8]) -> Option<Tip> {
    if bytes.len() < 8 {
        return None;
    }
    let height = u64::from_be_bytes(bytes[..8].try_into().ok()?);
    if height == 0 {
        return None;
    }
    Some(Tip {
        height,
        hash: bytes[8..].to_vec(),
    })
}

/// Whether a cached entry carrying `hash` is current given the index's `index_hash` and the
/// tip. `None` index: trusted only below the window. Both byte orders of a hash are accepted:
/// CompactBlock hashes are in internal order, the node RPC's strings (TreeState.hash)
/// in display order.
pub fn hash_is_current(
    hash: &[u8],
    height: u64,
    index_hash: Option<&[u8]>,
    tip: Option<&Tip>,
) -> Validity {
    match index_hash {
        Some(canonical) => {
            if hash == canonical {
                return Validity::Current;
            }
            let mut rev = hash.to_vec();
            rev.reverse();
            if rev == canonical {
                Validity::Current
            } else {
                Validity::Stale
            }
        }
        None => match tip {
            Some(t) if height.saturating_add(INDEX_WINDOW) < t.height => Validity::Current,
            _ => Validity::Unknown,
        },
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Validity {
    /// Serve it.
    Current,
    /// The chain moved under it: do not serve, drop it.
    Stale,
    /// Inside the window with no index entry (cold index, evicted key): do not serve, keep it.
    Unknown,
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// A fake store: a HashMap with lock expiry on the tokio clock. Shared between the chain
    /// follower, block cache and response cache tests.
    pub struct MemStore {
        pub data: Mutex<HashMap<String, (Bytes, Option<u64>)>>,
        pub locks: Mutex<HashMap<String, (String, tokio::time::Instant)>>,
        pub mgets: Mutex<Vec<Vec<String>>>,
        pub tip: TipCell,
        pub epoch: u64,
        /// When set, every read answers "nothing" and every write is dropped (Redis down).
        pub down: std::sync::atomic::AtomicBool,
    }

    impl Default for MemStore {
        fn default() -> Self {
            Self {
                data: Mutex::new(HashMap::new()),
                locks: Mutex::new(HashMap::new()),
                mgets: Mutex::new(Vec::new()),
                tip: TipCell::new(),
                epoch: 42,
                down: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    impl MemStore {
        pub fn is_down(&self) -> bool {
            self.down.load(std::sync::atomic::Ordering::SeqCst)
        }
        pub fn get(&self, key: &str) -> Option<Bytes> {
            self.data.lock().unwrap().get(key).map(|(v, _)| v.clone())
        }
        pub fn ttl(&self, key: &str) -> Option<Option<u64>> {
            self.data.lock().unwrap().get(key).map(|(_, t)| *t)
        }
        pub fn put(&self, key: &str, value: impl Into<Bytes>) {
            self.data
                .lock()
                .unwrap()
                .insert(key.to_string(), (value.into(), None));
        }
        pub fn keys_with(&self, part: &str) -> Vec<String> {
            let mut v: Vec<String> = self
                .data
                .lock()
                .unwrap()
                .keys()
                .filter(|k| k.contains(part))
                .cloned()
                .collect();
            v.sort();
            v
        }
    }

    impl CacheStore for MemStore {
        fn epoch(&self) -> BoxFuture<'_, u64> {
            Box::pin(async move { self.epoch })
        }
        fn key_prefix(&self, epoch: u64) -> String {
            format!("ohttp:testnet:lwd:{epoch}:v3:deadbeef:")
        }
        fn chain_prefix(&self) -> String {
            "ohttp:testnet:lwd:chain:v1:".to_string()
        }
        fn tip_cell(&self) -> &TipCell {
            &self.tip
        }
        fn mget(&self, keys: Vec<String>) -> BoxFuture<'_, Vec<Option<Bytes>>> {
            Box::pin(async move {
                self.mgets.lock().unwrap().push(keys.clone());
                if self.is_down() {
                    return vec![None; keys.len()];
                }
                let data = self.data.lock().unwrap();
                keys.iter()
                    .map(|k| data.get(k).map(|(v, _)| v.clone()))
                    .collect()
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
                if self.is_down() {
                    return;
                }
                if let Some(e) = epoch {
                    assert_eq!(e, self.epoch, "epoch-checked write with a stale epoch");
                }
                self.data.lock().unwrap().insert(key, (value, ttl_secs));
            })
        }
        fn del(&self, keys: Vec<String>) -> BoxFuture<'_, ()> {
            Box::pin(async move {
                if self.is_down() {
                    return;
                }
                let mut data = self.data.lock().unwrap();
                for k in keys {
                    data.remove(&k);
                }
            })
        }
        fn set_nx_px(
            &self,
            key: String,
            value: String,
            ttl_ms: u64,
        ) -> BoxFuture<'_, Option<bool>> {
            Box::pin(async move {
                if self.is_down() {
                    return None;
                }
                let now = tokio::time::Instant::now();
                let mut locks = self.locks.lock().unwrap();
                if let Some((_, exp)) = locks.get(&key) {
                    if *exp > now {
                        return Some(false);
                    }
                }
                locks.insert(key, (value, now + Duration::from_millis(ttl_ms)));
                Some(true)
            })
        }
        fn pexpire_if_equal(
            &self,
            key: String,
            value: String,
            ttl_ms: u64,
        ) -> BoxFuture<'_, Option<bool>> {
            Box::pin(async move {
                if self.is_down() {
                    return None;
                }
                let now = tokio::time::Instant::now();
                let mut locks = self.locks.lock().unwrap();
                match locks.get_mut(&key) {
                    Some((held, exp)) if *held == value && *exp > now => {
                        *exp = now + Duration::from_millis(ttl_ms);
                        Some(true)
                    }
                    _ => Some(false),
                }
            })
        }
    }

    /// A fake permanent tier.
    #[derive(Default)]
    pub struct MemPermanent {
        pub data: Mutex<HashMap<String, Bytes>>,
        pub mgets: Mutex<Vec<Vec<String>>>,
        pub down: std::sync::atomic::AtomicBool,
    }

    impl MemPermanent {
        pub fn is_down(&self) -> bool {
            self.down.load(std::sync::atomic::Ordering::SeqCst)
        }
        pub fn get(&self, key: &str) -> Option<Bytes> {
            self.data.lock().unwrap().get(key).cloned()
        }
        pub fn put(&self, key: &str, value: impl Into<Bytes>) {
            self.data
                .lock()
                .unwrap()
                .insert(key.to_string(), value.into());
        }
        pub fn len(&self) -> usize {
            self.data.lock().unwrap().len()
        }
    }

    impl PermanentStore for MemPermanent {
        fn mget(&self, keys: Vec<String>) -> BoxFuture<'_, Vec<Option<Bytes>>> {
            Box::pin(async move {
                self.mgets.lock().unwrap().push(keys.clone());
                if self.is_down() {
                    return vec![None; keys.len()];
                }
                let data = self.data.lock().unwrap();
                keys.iter().map(|k| data.get(k).cloned()).collect()
            })
        }
        fn set(&self, key: String, value: Bytes) -> BoxFuture<'_, bool> {
            Box::pin(async move {
                if self.is_down() {
                    return false;
                }
                self.data.lock().unwrap().insert(key, value);
                true
            })
        }
        fn del(&self, keys: Vec<String>) -> BoxFuture<'_, ()> {
            Box::pin(async move {
                if self.is_down() {
                    return;
                }
                let mut data = self.data.lock().unwrap();
                for k in keys {
                    data.remove(&k);
                }
            })
        }
    }

    #[test]
    fn permanent_depth_and_key() {
        let tip = Tip {
            height: 1000,
            hash: vec![],
        };
        assert!(is_final(900, &tip));
        assert!(!is_final(901, &tip));
        assert_eq!(sapling_activation("mainnet"), 419_200);
        assert_eq!(sapling_activation("testnet"), 280_000);
        assert_eq!(
            permanent_block_key("mainnet", "", 5),
            "perm:mainnet:block:v1::5"
        );
        assert_eq!(
            permanent_block_key("testnet", "1,2", 5),
            "perm:testnet:block:v1:1,2:5"
        );
    }

    #[test]
    fn tip_roundtrip_and_validity() {
        let tip = Tip {
            height: 77,
            hash: vec![1, 2, 3],
        };
        assert_eq!(decode_tip(&encode_tip(&tip)), Some(tip.clone()));
        assert_eq!(decode_tip(&[0u8; 8]), None);
        let canonical = [9u8, 8, 7];
        assert_eq!(
            hash_is_current(&[9, 8, 7], 10, Some(&canonical), Some(&tip)),
            Validity::Current
        );
        assert_eq!(
            hash_is_current(&[7, 8, 9], 10, Some(&canonical), Some(&tip)),
            Validity::Current,
            "display order accepted"
        );
        assert_eq!(
            hash_is_current(&[1, 1, 1], 10, Some(&canonical), Some(&tip)),
            Validity::Stale
        );
        let far = Tip {
            height: 5000,
            hash: vec![],
        };
        assert_eq!(
            hash_is_current(&[1], 10, None, Some(&far)),
            Validity::Current,
            "below the window, trusted"
        );
        assert_eq!(
            hash_is_current(&[1], 4500, None, Some(&far)),
            Validity::Unknown
        );
        assert_eq!(hash_is_current(&[1], 10, None, None), Validity::Unknown);
    }
}

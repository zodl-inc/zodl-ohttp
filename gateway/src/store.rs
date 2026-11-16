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
        self.set_at(tip, tokio::time::Instant::now());
    }

    /// Set `tip` as seen at `at` (not now): it goes stale [`TIP_STALE_AFTER`] after `at`.
    pub fn set_at(&self, tip: Tip, at: tokio::time::Instant) {
        self.inner.store(Some(Arc::new((tip, at))));
    }

    /// Forget the tip (unknown until the next `set`).
    pub fn clear(&self) {
        self.inner.store(None);
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
    /// Whether writes can go to this store now (false while it is a read-only replica: the
    /// callers keep such data in the cache tier instead).
    fn writable(&self) -> bool {
        true
    }
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
    /// `SET key value PX ttl_ms` only while `guard_key` still holds `guard` and `key` is still
    /// held by `holder` (`None`: not held at all), in one atomic script: Some(true) when taken,
    /// Some(false) when the guard or the holder changed, None on error. The chain follower takes
    /// over a leader whose tip stopped moving this way: it never takes over from a leader that
    /// has just moved it, nor from another follower that took over from the same stale leader
    /// a moment before.
    fn take_lock_if(
        &self,
        key: String,
        value: String,
        ttl_ms: u64,
        guard_key: String,
        guard: Bytes,
        holder: Option<String>,
    ) -> BoxFuture<'_, Option<bool>>;
    /// Write `entries` (key, value, TTL in seconds; 0 = no expiry) only while `lock` holds exactly `value`
    /// (one atomic script), and hold `lock` for `ttl_ms` again: Some(true) when written,
    /// Some(false) when the lock is held by another value or by nobody, None on error. A leader
    /// replaced while a tick was in flight cannot overwrite the index or the tip of the process
    /// that replaced it, also not after that one released the lock again; one whose lock lapsed
    /// stops leading and acquires it again on its next tick.
    fn set_if_lock_held(
        &self,
        lock: String,
        value: String,
        ttl_ms: u64,
        entries: Vec<(String, Bytes, u64)>,
    ) -> BoxFuture<'_, Option<bool>>;
    /// Delete `keys` only while `lock` holds exactly `value` (one atomic script): Some(true)
    /// when deleted, Some(false) when the lock is not held by `value`, None on error.
    fn del_if_lock_held(
        &self,
        lock: String,
        value: String,
        keys: Vec<String>,
    ) -> BoxFuture<'_, Option<bool>>;
    /// The value `key` (a lock) holds: Some(None) when it is not held, None on error.
    fn lock_holder(&self, key: String) -> BoxFuture<'_, Option<Option<String>>>;
    /// Whether the shared epoch still equals `epoch` (the check an epoch-checked `set` makes
    /// before its write): None on error.
    fn epoch_current(&self, epoch: u64) -> BoxFuture<'_, Option<bool>>;
    /// Store the big-endian `value` under `key` with `ttl_secs`, only if the stored value is
    /// lower (or absent, or not a 4-byte value), in one atomic step; the epoch is checked
    /// before (as an epoch-checked `set`). Some(true) when written, Some(false) when the stored
    /// value is as high or the epoch changed, None on error (nothing written).
    fn set_max_u32(
        &self,
        key: String,
        value: u32,
        ttl_secs: u64,
        epoch: u64,
    ) -> BoxFuture<'_, Option<bool>>;
    /// Delete `key` only if it still holds `value` (one atomic script).
    fn release_lock(&self, key: String, value: String) -> BoxFuture<'_, Option<bool>>;
}

/// The index key of `height`.
pub fn index_key(chain_prefix: &str, height: u64) -> String {
    format!("{chain_prefix}index:{height}")
}

/// The stored tip: `height || hash`.
pub fn tip_key(chain_prefix: &str) -> String {
    format!("{chain_prefix}tip")
}

/// When the leader last moved the stored tip: Unix milliseconds, decimal. A separate key, so
/// that a gateway that does not know it still reads the tip as before.
pub fn tip_at_key(chain_prefix: &str) -> String {
    format!("{chain_prefix}tip_at")
}

/// When the leader last confirmed the stored tip (its lightwalletd answered with it, or it
/// moved it): Unix milliseconds, decimal, rewritten on every such leader tick. Followers keep
/// the tip fresh only while this value changes, so a leader that stops confirming (a stuck
/// lightwalletd) lets the tip go stale everywhere. Absent (an older leader): followers refresh
/// on every read, as before.
pub fn tip_seen_key(chain_prefix: &str) -> String {
    format!("{chain_prefix}tip_seen")
}

/// What binds the stored `tip_at` to the tip it was written with:
/// `1:<tip_at, Unix ms, decimal>:<nonce, 16 lowercase hex digits>:<lowercase hex of the tip
/// value as stored, encode_tip>`. A leader writes it only together with `tip_at`, in the same
/// fenced script, with a new random nonce on every write, and never stamps a `tip_at` it only
/// read. Followers use it as positive evidence only, under the rules of `chain::TipAtRead`
/// (when a stamp vouches for a read, and when it says nothing). A separate key, so that a
/// gateway that does not know it reads the other keys as before.
pub fn tip_stamp_key(chain_prefix: &str) -> String {
    format!("{chain_prefix}tip_stamp")
}

/// A parsed `{chain}tip_stamp` value (see [`tip_stamp_key`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TipStamp {
    /// The `tip_at` value written with it.
    pub tip_at_ms: u64,
    /// The write's random nonce.
    pub nonce: u64,
    /// The exact bytes of the tip value written with it (`encode_tip`).
    pub tip: Vec<u8>,
}

pub fn encode_tip_stamp(tip_at_ms: u64, nonce: u64, tip: &Tip) -> Bytes {
    Bytes::from(format!(
        "1:{tip_at_ms}:{nonce:016x}:{}",
        hex::encode(encode_tip(tip))
    ))
}

/// A `{chain}tip_stamp` value; None for anything that is not exactly the format
/// [`encode_tip_stamp`] writes (another version, missing or extra fields, a decimal with a
/// sign, spaces or leading zeros, hex that is not lowercase or has an odd length, a tip value
/// `encode_tip` cannot write: fewer than 8 bytes, or height 0).
pub fn decode_tip_stamp(bytes: &[u8]) -> Option<TipStamp> {
    let lower_hex = |s: &str| s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    let mut fields = std::str::from_utf8(bytes).ok()?.split(':');
    let (version, ms, nonce, tip) = (
        fields.next()?,
        fields.next()?,
        fields.next()?,
        fields.next()?,
    );
    if fields.next().is_some() || version != "1" {
        return None;
    }
    if ms.is_empty() || !ms.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let tip_at_ms: u64 = ms.parse().ok()?;
    if tip_at_ms.to_string() != ms || nonce.len() != 16 || !lower_hex(nonce) {
        return None;
    }
    if tip.len() % 2 != 0 || !lower_hex(tip) {
        return None;
    }
    let tip = hex::decode(tip).ok()?;
    // Only a tip value `encode_tip` writes (a height above 0, then the hash).
    decode_tip(&tip)?;
    Some(TipStamp {
        tip_at_ms,
        nonce: u64::from_str_radix(nonce, 16).ok()?,
        tip,
    })
}

pub fn encode_unix_ms(ms: u64) -> Bytes {
    Bytes::from(ms.to_string())
}

pub fn decode_unix_ms(bytes: &[u8]) -> Option<u64> {
    std::str::from_utf8(bytes).ok()?.trim().parse().ok()
}

/// The wall clock in Unix milliseconds (shared between processes, unlike `Instant`).
pub fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
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
        /// `Some((n, holder))`: the n-th fenced write from now succeeds, then `holder` takes the
        /// lock (a process replaced between two batches of one tick).
        pub steal_lock_after: Mutex<Option<(usize, String)>>,
        /// The keys of every accepted fenced write (`set_if_lock_held`), one list per script.
        pub fenced_writes: Mutex<Vec<Vec<String>>>,
        pub tip: TipCell,
        pub epoch: u64,
        /// When set, every read answers "nothing" and every write is dropped (Redis down).
        pub down: std::sync::atomic::AtomicBool,
        /// `Some((part, delay))`: an `mget` of a key containing `part` takes `delay`.
        pub slow_mget: Mutex<Option<(String, Duration)>>,
    }

    impl Default for MemStore {
        fn default() -> Self {
            Self {
                data: Mutex::new(HashMap::new()),
                locks: Mutex::new(HashMap::new()),
                mgets: Mutex::new(Vec::new()),
                steal_lock_after: Mutex::new(None),
                fenced_writes: Mutex::new(Vec::new()),
                tip: TipCell::new(),
                epoch: 42,
                down: std::sync::atomic::AtomicBool::new(false),
                slow_mget: Mutex::new(None),
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
                let slow = self
                    .slow_mget
                    .lock()
                    .unwrap()
                    .clone()
                    .filter(|(part, _)| keys.iter().any(|k| k.contains(part.as_str())));
                if let Some((_, delay)) = slow {
                    tokio::time::sleep(delay).await;
                }
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
        fn take_lock_if(
            &self,
            key: String,
            value: String,
            ttl_ms: u64,
            guard_key: String,
            guard: Bytes,
            holder: Option<String>,
        ) -> BoxFuture<'_, Option<bool>> {
            Box::pin(async move {
                if self.is_down() {
                    return None;
                }
                let data = self.data.lock().unwrap();
                if data.get(&guard_key).map(|(v, _)| v) != Some(&guard) {
                    return Some(false);
                }
                let now = tokio::time::Instant::now();
                let mut locks = self.locks.lock().unwrap();
                let current = locks
                    .get(&key)
                    .filter(|(_, exp)| *exp > now)
                    .map(|(v, _)| v.clone());
                if current != holder {
                    return Some(false);
                }
                locks.insert(key, (value, now + Duration::from_millis(ttl_ms)));
                Some(true)
            })
        }
        fn del_if_lock_held(
            &self,
            lock: String,
            value: String,
            keys: Vec<String>,
        ) -> BoxFuture<'_, Option<bool>> {
            Box::pin(async move {
                if self.is_down() {
                    return None;
                }
                let now = tokio::time::Instant::now();
                let held = self
                    .locks
                    .lock()
                    .unwrap()
                    .get(&lock)
                    .is_some_and(|(v, exp)| *v == value && *exp > now);
                if !held {
                    return Some(false);
                }
                let mut data = self.data.lock().unwrap();
                for k in keys {
                    data.remove(&k);
                }
                Some(true)
            })
        }
        fn set_max_u32(
            &self,
            key: String,
            value: u32,
            ttl_secs: u64,
            epoch: u64,
        ) -> BoxFuture<'_, Option<bool>> {
            Box::pin(async move {
                if self.is_down() {
                    return None;
                }
                if epoch != self.epoch {
                    return Some(false);
                }
                let mut data = self.data.lock().unwrap();
                let current = data
                    .get(&key)
                    .and_then(|(v, _)| <[u8; 4]>::try_from(&v[..]).ok())
                    .map(u32::from_be_bytes);
                if current.is_some_and(|c| c >= value) {
                    return Some(false);
                }
                data.insert(
                    key,
                    (Bytes::copy_from_slice(&value.to_be_bytes()), Some(ttl_secs)),
                );
                Some(true)
            })
        }
        fn epoch_current(&self, epoch: u64) -> BoxFuture<'_, Option<bool>> {
            Box::pin(async move {
                if self.is_down() {
                    return None;
                }
                Some(epoch == self.epoch)
            })
        }
        fn lock_holder(&self, key: String) -> BoxFuture<'_, Option<Option<String>>> {
            Box::pin(async move {
                if self.is_down() {
                    return None;
                }
                let now = tokio::time::Instant::now();
                Some(
                    self.locks
                        .lock()
                        .unwrap()
                        .get(&key)
                        .filter(|(_, exp)| *exp > now)
                        .map(|(v, _)| v.clone()),
                )
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
                if self.is_down() {
                    return None;
                }
                let now = tokio::time::Instant::now();
                let mut locks = self.locks.lock().unwrap();
                let held = locks
                    .get(&lock)
                    .is_some_and(|(v, exp)| *v == value && *exp > now);
                if !held {
                    return Some(false);
                }
                locks.insert(lock.clone(), (value, now + Duration::from_millis(ttl_ms)));
                self.fenced_writes
                    .lock()
                    .unwrap()
                    .push(entries.iter().map(|(k, _, _)| k.clone()).collect());
                let mut data = self.data.lock().unwrap();
                for (k, v, ttl) in entries {
                    data.insert(k, (v, (ttl > 0).then_some(ttl)));
                }
                // Test hook: another process takes the lock right after this write.
                let mut steal = self.steal_lock_after.lock().unwrap();
                if let Some((n, thief)) = steal.as_mut() {
                    if *n <= 1 {
                        locks.insert(lock, (thief.clone(), now + Duration::from_secs(3600)));
                        *steal = None;
                    } else {
                        *n -= 1;
                    }
                }
                Some(true)
            })
        }
        fn release_lock(&self, key: String, value: String) -> BoxFuture<'_, Option<bool>> {
            Box::pin(async move {
                if self.is_down() {
                    return None;
                }
                let mut locks = self.locks.lock().unwrap();
                if locks.get(&key).is_some_and(|(v, _)| *v == value) {
                    locks.remove(&key);
                    return Some(true);
                }
                Some(false)
            })
        }
    }

    /// A fake permanent tier.
    #[derive(Default)]
    pub struct MemPermanent {
        pub data: Mutex<HashMap<String, Bytes>>,
        pub mgets: Mutex<Vec<Vec<String>>>,
        pub down: std::sync::atomic::AtomicBool,
        /// A read-only replica: `writable()` is false and writes are refused.
        pub replica: std::sync::atomic::AtomicBool,
        /// Writes attempted (refused ones included).
        pub writes: std::sync::atomic::AtomicUsize,
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
                self.writes
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if self.is_down() || !self.writable() {
                    return false;
                }
                self.data.lock().unwrap().insert(key, value);
                true
            })
        }
        fn del(&self, keys: Vec<String>) -> BoxFuture<'_, ()> {
            Box::pin(async move {
                self.writes
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if self.is_down() || !self.writable() {
                    return;
                }
                let mut data = self.data.lock().unwrap();
                for k in keys {
                    data.remove(&k);
                }
            })
        }
        fn writable(&self) -> bool {
            !self.replica.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    /// The test store of every store-backed test of the crate.
    pub const TEST_STORE: &str = "127.0.0.1:6379";
    /// Set to exactly `1`, outside CI, to let the store-backed tests pass without a test store.
    pub const ALLOW_NO_STORE: &str = "OHTTP_TEST_ALLOW_NO_STORE";
    /// Bound of the first connection of a store-backed test.
    pub const STORE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

    /// What a store-backed test does after its first connection to the test store.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum StorePolicy {
        Run,
        /// Returns early (passes), with one line on stderr.
        Skip,
        Fail,
    }

    /// The policy for the test store: run when it is reachable; otherwise fail, unless `CI` is
    /// not set and the opt-out (`OHTTP_TEST_ALLOW_NO_STORE=1`) is (it is ignored in CI).
    pub fn store_policy(reachable: bool, ci: bool, allow_no_store: bool) -> StorePolicy {
        match (reachable, ci, allow_no_store) {
            (true, _, _) => StorePolicy::Run,
            (false, false, true) => StorePolicy::Skip,
            (false, _, _) => StorePolicy::Fail,
        }
    }

    /// A store-backed test could not make its first connection to `what` (`error`: why):
    /// fails the test, or returns after one line on stderr when the policy says skip (the
    /// caller then returns).
    #[track_caller]
    pub fn store_missing(what: &str, error: &dyn std::fmt::Display) {
        store_unusable(&format!("{what} is not reachable: {error}"));
    }

    /// A store-backed test cannot use the test store (`problem`: what failed, e.g. a command
    /// the store refused that the test needs): the same policy as [`store_missing`].
    #[track_caller]
    pub fn store_unusable(problem: &str) {
        let ci = std::env::var_os("CI").is_some();
        let allowed = std::env::var(ALLOW_NO_STORE).is_ok_and(|v| v == "1");
        if store_policy(false, ci, allowed) == StorePolicy::Skip {
            eprintln!("test skipped: {problem} ({ALLOW_NO_STORE}=1)");
            return;
        }
        panic!(
            "{problem}. Run a Redis on {TEST_STORE} (CI has one as a service), or set \
             {ALLOW_NO_STORE}=1 outside CI to skip the tests that need it"
        );
    }

    #[test]
    fn the_test_store_policy() {
        use StorePolicy::*;
        // (reachable, CI set, opt-out set) -> policy
        for (reachable, ci, allowed, policy) in [
            (true, false, false, Run),
            (true, true, false, Run),
            (true, false, true, Run),
            (true, true, true, Run),
            (false, false, false, Fail),
            (false, true, false, Fail),
            (false, true, true, Fail),
            (false, false, true, Skip),
        ] {
            assert_eq!(
                store_policy(reachable, ci, allowed),
                policy,
                "reachable {reachable}, CI {ci}, opt-out {allowed}"
            );
        }
    }

    #[test]
    fn tip_stamp_codec() {
        let tip = Tip {
            height: 1_000_001,
            hash: vec![0xab, 0x01, 0xff],
        };
        let raw = encode_tip_stamp(1_700_000_000_123, 0x0123_4567_89ab_cdef, &tip);
        assert_eq!(
            &raw[..],
            b"1:1700000000123:0123456789abcdef:00000000000f4241ab01ff"
        );
        assert_eq!(
            decode_tip_stamp(&raw),
            Some(TipStamp {
                tip_at_ms: 1_700_000_000_123,
                nonce: 0x0123_4567_89ab_cdef,
                tip: encode_tip(&tip).to_vec(),
            })
        );
        // A tip with an empty hash; the smallest values.
        let bare = Tip {
            height: 7,
            hash: vec![],
        };
        let raw = encode_tip_stamp(0, 0, &bare);
        assert_eq!(&raw[..], b"1:0:0000000000000000:0000000000000007");
        let stamp = decode_tip_stamp(&raw).unwrap();
        assert_eq!(decode_tip(&stamp.tip), Some(bare));
        assert_eq!((stamp.tip_at_ms, stamp.nonce), (0, 0));
        for bad in [
            &b""[..],
            b"2:5:0123456789abcdef:0000000000000007",
            b"01:5:0123456789abcdef:0000000000000007",
            b"1:5:0123456789abcdef",
            b"1:5:0123456789abcdef:0000000000000007:",
            b"1:5:0123456789abcdef:0000000000000007:00",
            b"1::0123456789abcdef:0000000000000007",
            b"1:+5:0123456789abcdef:0000000000000007",
            b"1:05:0123456789abcdef:0000000000000007",
            b"1: 5:0123456789abcdef:0000000000000007",
            b"1:18446744073709551616:0123456789abcdef:0000000000000007",
            b"1:5:0123456789abcde:0000000000000007",
            b"1:5:0123456789abcdef0:0000000000000007",
            b"1:5:0123456789ABCDEF:0000000000000007",
            b"1:5:0123456789abcdeg:0000000000000007",
            b"1:5:0123456789abcdef:000000000000000",
            b"1:5:0123456789abcdef:000000000000000G",
            b"1:5:0123456789abcdef:00000000000000AB",
            b"1:5:0123456789abcdef:0000000000000007\n",
            b"1:5:0123456789abcdef:0000000000000007 ",
            b"\xff:5:0123456789abcdef:0000000000000007",
            // Not a tip value: empty, shorter than a height, height 0.
            b"1:5:0123456789abcdef:",
            b"1:5:0123456789abcdef:00000000000007",
            b"1:5:0123456789abcdef:0000000000000000",
            b"1:5:0123456789abcdef:0000000000000000ab",
        ] {
            assert_eq!(
                decode_tip_stamp(bad),
                None,
                "{:?}",
                String::from_utf8_lossy(bad)
            );
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

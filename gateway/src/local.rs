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

//! Per-process in-memory LRU in front of Redis for blocks and tree states.
//!
//! Entries are weighed by key plus value bytes and the cache is bounded by `LOCAL_CACHE_BYTES`
//! (default 256 MiB). Only cached answers live here, never the chain index: the index is
//! read from Redis on every request so a stale local entry is always caught by validation.
//!
//! Values larger than `LOCAL_CACHE_MAX_ENTRY_BYTES` (default 64 KiB) are not admitted, so a
//! scan of unusually large historical blocks cannot churn the hot recent blocks out of the
//! LRU.

use bytes::Bytes;
use moka::sync::Cache;

/// Default capacity in bytes.
pub const DEFAULT_LOCAL_CACHE_BYTES: u64 = 256 * 1024 * 1024;
/// Default largest value admitted.
pub const DEFAULT_LOCAL_CACHE_MAX_ENTRY_BYTES: usize = 64 * 1024;

pub struct LocalCache {
    cache: Cache<String, Bytes>,
    max_entry_bytes: usize,
    network: String,
}

impl LocalCache {
    pub fn new(max_bytes: u64, network: String) -> Self {
        Self::with_max_entry(max_bytes, DEFAULT_LOCAL_CACHE_MAX_ENTRY_BYTES, network)
    }

    /// A cache admitting values of at most `max_entry_bytes` (0 = no limit).
    pub fn with_max_entry(max_bytes: u64, max_entry_bytes: usize, network: String) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_bytes)
            .weigher(|k: &String, v: &Bytes| (k.len() + v.len()).min(u32::MAX as usize) as u32)
            .build();
        Self {
            cache,
            max_entry_bytes,
            network,
        }
    }

    pub fn max_entry_bytes(&self) -> usize {
        self.max_entry_bytes
    }

    pub fn get(&self, key: &str) -> Option<Bytes> {
        let v = self.cache.get(key);
        crate::health::record_local_cache(&self.network, v.is_some());
        v
    }

    /// Insert unless the value is over the admission cap.
    pub fn insert(&self, key: String, value: Bytes) {
        if self.max_entry_bytes > 0 && value.len() > self.max_entry_bytes {
            crate::health::record_local_cache_oversized(&self.network);
            return;
        }
        self.cache.insert(key, value);
    }

    pub fn invalidate(&self, key: &str) {
        self.cache.invalidate(key);
    }

    /// Entries held (after pending maintenance).
    pub fn entry_count(&self) -> u64 {
        self.cache.run_pending_tasks();
        self.cache.entry_count()
    }

    pub fn weighted_size(&self) -> u64 {
        self.cache.run_pending_tasks();
        self.cache.weighted_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_by_bytes_and_invalidates() {
        let c = LocalCache::new(10_000, "testnet".to_string());
        for i in 0..100u32 {
            c.insert(format!("k{i}"), Bytes::from(vec![0u8; 500]));
        }
        // Bounded (one entry of slack for moka's approximate accounting).
        assert!(c.weighted_size() <= 10_600, "{}", c.weighted_size());
        assert!(c.entry_count() < 100);
        c.insert("keep".to_string(), Bytes::from_static(b"v"));
        assert_eq!(c.get("keep"), Some(Bytes::from_static(b"v")));
        c.invalidate("keep");
        assert_eq!(c.get("keep"), None);
    }

    #[test]
    fn oversized_values_are_not_admitted() {
        let c = LocalCache::with_max_entry(1 << 24, 64 * 1024, "testnet".to_string());
        c.insert("big".to_string(), Bytes::from(vec![0u8; 64 * 1024 + 1]));
        assert_eq!(c.get("big"), None, "above the cap: bypassed");
        c.insert("edge".to_string(), Bytes::from(vec![0u8; 64 * 1024]));
        assert!(c.get("edge").is_some(), "at the cap: admitted");
        c.insert("small".to_string(), Bytes::from(vec![0u8; 2048]));
        assert!(c.get("small").is_some());
        assert_eq!(c.entry_count(), 2);
        // 0 = unlimited.
        let u = LocalCache::with_max_entry(1 << 24, 0, "testnet".to_string());
        u.insert("big".to_string(), Bytes::from(vec![0u8; 1 << 20]));
        assert!(u.get("big").is_some());
    }
}

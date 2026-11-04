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

// Tests for startup and degraded behaviour when Redis is unreachable.
//
// Verifies that:
// 1. ResponseCache::connect succeeds even when cache Redis is unavailable
// 2. The epoch falls back and replay checks fail closed when connections are None
// 3. ping_redis correctly reports disconnected state
// 4. An unreachable security Redis still fails startup

#[cfg(test)]
mod tests {
    use super::super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_cache_connect_with_invalid_redis_url() {
        // Invalid Redis URL should not fail ResponseCache::connect
        let result = ResponseCache::connect(
            "redis://invalid-host:9999", // Non-existent Redis
            None,
            "testnet".to_string(),
            "test-backend".to_string(),
            250,
            10000,
            &HashMap::new(),
        )
        .await;

        assert!(
            result.is_ok(),
            "connect() should succeed even with invalid cache Redis"
        );
        let cache = result.unwrap();

        // Cache connection should be None
        assert!(
            cache.cache_conn.load().is_none(),
            "cache_conn should be None when connection failed"
        );

        // ping_redis should return false (cache not connected)
        let redis_ok = cache.ping_redis().await;
        assert!(
            !redis_ok,
            "ping_redis should return false when cache disconnected"
        );

        // Tip height should be 0 initially
        assert_eq!(cache.tip_height(), 0);
    }

    #[tokio::test]
    async fn test_cache_operations_bypass_when_disconnected() {
        let cache = ResponseCache::connect(
            "redis://invalid-host:9999",
            None,
            "testnet".to_string(),
            "test-backend".to_string(),
            250,
            10000,
            &HashMap::new(),
        )
        .await
        .unwrap();

        // get_shared_epoch should return 0 (default) without crashing
        let epoch = cache.get_shared_epoch().await;
        assert_eq!(epoch, 0, "epoch should be 0 when no Redis connection");

        // check_replay should now fail closed (return Err when security_conn is None)
        let is_replay = cache.check_replay(b"test_body_hash").await;
        assert!(
            is_replay.is_err(),
            "check_replay should error when security_conn is None (fail-closed)"
        );
        assert!(
            is_replay.unwrap_err().to_string().contains("unavailable"),
            "error should mention replay protection unavailable"
        );
    }

    #[tokio::test]
    async fn test_security_redis_failure_still_fails_startup() {
        // Security Redis failure should still return Err (fail-closed behavior)
        let result = ResponseCache::connect(
            "redis://127.0.0.1:6379",              // Assume cache Redis might exist
            Some("redis://invalid-security:9999"), // Invalid security Redis
            "testnet".to_string(),
            "test-backend".to_string(),
            250,
            10000,
            &HashMap::new(),
        )
        .await;

        // This should fail because security Redis is critical
        assert!(
            result.is_err(),
            "connect() should fail when security Redis is unavailable (fail-closed)"
        );
    }
}

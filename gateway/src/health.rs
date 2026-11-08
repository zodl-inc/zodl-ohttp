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

// Health checks and metrics

use prometheus::Histogram;
use prometheus::{HistogramVec, IntCounter, IntCounterVec, IntGaugeVec, Opts, Registry};

lazy_static::lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();

    static ref OHTTP_REQUESTS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_requests_total", "Total OHTTP requests by status and labels"),
        &["status", "mode", "network", "hop", "method", "http_status", "grpc_status", "backend", "route_class"]
    )
    .unwrap();

    static ref OHTTP_REQUEST_DURATION_SECONDS: HistogramVec = HistogramVec::new(
        prometheus::HistogramOpts::new("ohttp_request_duration_seconds", "OHTTP request duration in seconds")
            .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]),
        &["network", "hop", "backend"]
    )
    .unwrap();

    static ref OHTTP_REQUESTS_IN_FLIGHT: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_requests_in_flight", "Current OHTTP requests in flight by network"),
        &["network"]
    )
    .unwrap();

    static ref OHTTP_UPSTREAM_ERRORS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_upstream_errors_total", "Total upstream errors by network and backend"),
        &["network", "backend", "error_type"]
    )
    .unwrap();

    static ref OHTTP_UPSTREAM_REQUESTS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_upstream_requests_total", "Total upstream requests by RPC method"),
        &["network", "backend", "rpc", "http_status", "grpc_status"]
    )
    .unwrap();

    static ref OHTTP_UPSTREAM_REQUEST_DURATION_SECONDS: HistogramVec = HistogramVec::new(
        prometheus::HistogramOpts::new("ohttp_upstream_request_duration_seconds", "Upstream request duration in seconds")
            .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]),
        &["network", "backend", "rpc"]
    )
    .unwrap();

    static ref OHTTP_RELAY_REQUESTS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new(
            "ohttp_relay_requests_total",
            "Authenticated requests to /gateway by relay (the RELAY_SECRETS entry that matched; - when relay authentication is off) and edge location (the relay edge location from the edge's request-id header; - without one)"
        ),
        &["network", "relay", "edge"]
    )
    .unwrap();

    static ref OHTTP_RELAY_REQUEST_ID_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_relay_request_id_total", "Relay-supplied correlation id per request: present, missing or invalid"),
        &["network", "state"]
    )
    .unwrap();

    static ref OHTTP_DECRYPT_ERRORS: IntCounter = IntCounter::new(
        "ohttp_decrypt_errors_total",
        "Total HPKE decryption errors"
    )
    .unwrap();

    static ref OHTTP_LWD_ERRORS: IntCounter = IntCounter::new(
        "ohttp_lwd_errors_total",
        "Total lightwalletd forwarding errors"
    )
    .unwrap();

    static ref OHTTP_LWD_CONNECT_RETRIES: IntCounter = IntCounter::new(
        "ohttp_lwd_connect_retries_total",
        "lightwalletd requests sent a second time because the first connection attempt failed"
    )
    .unwrap();

    // Kept registered (existing queries may select it) although nothing
    // increments it any more: the chunked encoder reports a sealing failure as a stream error.
    static ref OHTTP_ENCRYPT_ERRORS: IntCounter = IntCounter::new(
        "ohttp_encrypt_errors_total",
        "Total HPKE encryption errors"
    )
    .unwrap();

    static ref OHTTP_LWD_SHED_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_lwd_shed_total", "lightwalletd calls refused with UNAVAILABLE because their class is at its cap (class=heavy: MAX_INFLIGHT_LWD_HEAVY)"),
        &["network", "class"]
    )
    .unwrap();

    static ref OHTTP_LWD_PERMIT_WAITED_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_lwd_permit_waited_total", "lightwalletd calls that waited for a permit before proceeding"),
        &["network", "class"]
    )
    .unwrap();

    static ref OHTTP_LWD_PERMIT_WAIT_SECONDS: HistogramVec = HistogramVec::new(
        prometheus::HistogramOpts::new("ohttp_lwd_permit_wait_seconds", "Time lightwalletd calls spent waiting for a permit")
            .buckets(vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0]),
        &["network", "class"]
    )
    .unwrap();
    static ref OHTTP_POLICY_DENIED_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_policy_denied_total", "Policy-denied requests by alias"),
        &["alias"]
    )
    .unwrap();
    static ref OHTTP_CACHE_REQUESTS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_cache_requests_total", "Total cache requests by result"),
        &["network", "rpc", "result"]
    )
    .unwrap();

    static ref OHTTP_CACHE_TIP_HEIGHT: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_cache_tip_height", "Current tip height known to the cache"),
        &["network"]
    )
    .unwrap();

    pub static ref OHTTP_REPLAY_REJECTED: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_replay_rejected_total", "Total requests rejected as replays"),
        &["network"]
    )
    .unwrap();

    // Dependency health gauges for readiness checks
    static ref OHTTP_REDIS_CONNECTED: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_redis_connected", "Overall Redis connection status (cache AND security, 1=both connected, 0=either disconnected) per network"),
        &["network"]
    )
    .unwrap();

    static ref OHTTP_CACHE_REDIS_CONNECTED: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_cache_redis_connected", "Cache Redis connection status (1=connected, 0=disconnected) per network"),
        &["network"]
    )
    .unwrap();

    static ref OHTTP_LWD_REACHABLE: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_lwd_reachable", "LWD reachability status (1=reachable, 0=unreachable) per network"),
        &["network"]
    )
    .unwrap();

    static ref OHTTP_REDIS_OP_TIMEOUT_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_redis_op_timeout_total", "Total Redis operation timeouts by network and operation"),
        &["network", "operation"]
    )
    .unwrap();

    static ref OHTTP_RESPONSE_TRUNCATED_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_response_truncated_total", "Total upstream responses truncated at gateway size cap"),
        &["network"]
    )
    .unwrap();

    // Chunked streaming and the per-block cache.
    static ref OHTTP_CHUNKS_SENT_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_chunks_sent_total", "Sealed response chunks sent, by kind (full, flush = short chunk after a stall, final)"),
        &["network", "kind"]
    )
    .unwrap();

    static ref OHTTP_BLOCK_CACHE_HITS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_block_cache_hits_total", "GetBlockRange blocks served from the per-block cache"),
        &["network"]
    )
    .unwrap();

    static ref OHTTP_BLOCK_CACHE_MISSES_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_block_cache_misses_total", "GetBlockRange blocks not found in the per-block cache"),
        &["network"]
    )
    .unwrap();

    static ref OHTTP_UPSTREAM_BLOCKS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_upstream_blocks_total", "Blocks fetched from lightwalletd for GetBlockRange (after singleflight)"),
        &["network"]
    )
    .unwrap();

    static ref OHTTP_SINGLEFLIGHT_JOINS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_singleflight_joins_total", "Upstream calls that joined an identical call already in flight, by RPC"),
        &["network", "rpc"]
    )
    .unwrap();

    static ref OHTTP_UPSTREAM_CALLS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_upstream_calls_total", "Calls actually sent to lightwalletd (after caches and singleflight), by RPC"),
        &["network", "rpc"]
    )
    .unwrap();

    static ref OHTTP_BLOCK_CACHE_STALE_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_block_cache_stale_total", "Cached blocks whose hash no longer matched the chain index (dropped, refetched)"),
        &["network"]
    )
    .unwrap();

    static ref OHTTP_BLOCK_CACHE_UNVALIDATED_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_block_cache_unvalidated_total", "Cached blocks inside the index window with no index entry (not served)"),
        &["network"]
    )
    .unwrap();

    static ref OHTTP_LOCAL_CACHE_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_local_cache_total", "Per-process in-memory LRU lookups by result (hit, miss, oversized = value over the admission cap, not inserted)"),
        &["network", "result"]
    )
    .unwrap();

    static ref OHTTP_PERMANENT_STORE_CONNECTED: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_permanent_store_connected", "Permanent block tier PING status (1=connected, 0=down) per network"),
        &["network"]
    )
    .unwrap();

    static ref OHTTP_BLOCK_PERMANENT_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_block_permanent_total", "Permanent block tier (final blocks) events: hit/miss = lookups of eligible heights, stored = written on fetch, promoted = moved from the cache Redis once final, backfilled = written by the backfill job"),
        &["network", "result"]
    )
    .unwrap();

    static ref OHTTP_CHAIN_LEADER: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_chain_leader", "1 when this gateway instance holds the chain follower leader lock"),
        &["network"]
    )
    .unwrap();

    static ref OHTTP_CHAIN_REORGS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_chain_reorgs_total", "Reorgs detected by the chain follower"),
        &["network"]
    )
    .unwrap();

    static ref OHTTP_CHAIN_REORG_DEPTH: Histogram = Histogram::with_opts(
        prometheus::HistogramOpts::new("ohttp_chain_reorg_depth", "Fork depth (blocks invalidated) per reorg")
            .buckets(vec![1.0, 2.0, 3.0, 5.0, 10.0, 20.0, 50.0, 100.0])
    )
    .unwrap();

    static ref OHTTP_MEMPOOL_SUBSCRIBERS: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_mempool_subscribers", "Clients currently subscribed to the mempool fan-out"),
        &["network"]
    )
    .unwrap();

    static ref OHTTP_MEMPOOL_UPSTREAM_STREAMS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_mempool_upstream_streams_total", "Upstream GetMempoolStream sessions ended, by reason"),
        &["network", "reason"]
    )
    .unwrap();

    static ref OHTTP_BLOCK_CACHE_CONTINUITY_MISMATCH_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_block_cache_continuity_mismatch_total", "Cached blocks dropped because prevHash/hash did not chain to their neighbour"),
        &["network"]
    )
    .unwrap();

    // Multi-origin: which origin this is, what key material it publishes, and the replay peers.
    static ref OHTTP_ORIGIN_INFO: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_origin_info", "Always 1; origin = ORIGIN_ID of this gateway (\"-\" when unset)"),
        &["network", "origin"]
    )
    .unwrap();

    static ref OHTTP_KEY_CONFIG_INFO: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_key_config_info", "Always 1; fingerprint = first 16 hex of SHA-256 of the /ohttp-configs document, signing_key_id = key_id of the /ohttp-configs/signed signer (\"-\" when unsigned). Compare across origins."),
        &["network", "fingerprint", "signing_key_id"]
    )
    .unwrap();

    static ref OHTTP_SECURITY_REDIS_CONNECTED: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_security_redis_connected", "Security Redis (replay nonces) PING status (1=connected, 0=down or not configured) per network"),
        &["network"]
    )
    .unwrap();

    static ref OHTTP_REPLAY_PEERS_CONFIGURED: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_replay_peers_configured", "Number of REPLAY_PEER_URLS (other origins' security Redis) this gateway writes nonces to"),
        &["network"]
    )
    .unwrap();

    static ref OHTTP_REPLAY_PEER_CONNECTED: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_replay_peer_connected", "Replay peer (another origin's security Redis) PING status (1=connected, 0=down) per peer index"),
        &["network", "peer"]
    )
    .unwrap();

    static ref OHTTP_REPLAY_PEER_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_replay_peer_total", "Replay nonce writes to peer origins by outcome: fresh (stored), replay (nonce already there: cross-origin replay refused), replay_async (already there when replicated asynchronously: served by both origins inside the replication window), error, timeout, disconnected"),
        &["network", "peer", "result"]
    )
    .unwrap();

    static ref OHTTP_REPLAY_MODE_EFFECTIVE: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_replay_mode_effective", "1 for the replay peer mode in effect: sync, async-reads, async-reads-strict (replication degraded: READs synchronous), failover"),
        &["network", "mode"]
    )
    .unwrap();

    static ref OHTTP_REPLAY_MODE_SWITCHES_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_replay_mode_switches_total", "Effective replay mode switches: to=strict (reason: startup, lag, overflow, peer_down) or to=relaxed"),
        &["network", "to", "reason"]
    )
    .unwrap();

    static ref OHTTP_REPLAY_REPLICATION_LAG_SECONDS: HistogramVec = HistogramVec::new(
        prometheus::HistogramOpts::new("ohttp_replay_replication_lag_seconds", "Asynchronous replay nonce replication lag (enqueue to peer ack; idle probes count too) per peer index")
            .buckets(vec![0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.15, 0.2, 0.3, 0.5, 0.75, 1.0, 2.0, 5.0]),
        &["network", "peer"]
    )
    .unwrap();

    static ref OHTTP_REPLAY_ASYNC_QUEUE_DEPTH: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_replay_async_queue_depth", "Replay nonces waiting for asynchronous replication per peer index (queue + retry backlog)"),
        &["network", "peer"]
    )
    .unwrap();

    static ref OHTTP_REPLAY_ASYNC_DROPPED_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_replay_async_dropped_total", "Replay nonces not replicated to a peer: overflow (queue full; degrades to strict) or expired (older than the nonce TTL while retrying)"),
        &["network", "peer", "reason"]
    )
    .unwrap();

    static ref OHTTP_REPLAY_REPLICATION_HEALTHY: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_replay_replication_healthy", "1 when the peer acknowledged asynchronous replication since its last failure, per peer index"),
        &["network", "peer"]
    )
    .unwrap();

    static ref OHTTP_REPLAY_PEER_CONSECUTIVE_FAILURES: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_replay_peer_consecutive_failures", "Consecutive failures since the last success for each replay peer, per peer index"),
        &["network", "peer"]
    )
    .unwrap();

    static ref OHTTP_FRESHNESS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_freshness_total", "Inner requests by freshness verdict (REPLAY_FRESHNESS): fresh, missing, malformed or stale"),
        &["network", "result"]
    )
    .unwrap();

    static ref OHTTP_REPLAY_WRITE_WAIT_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_replay_write_wait_total", "WRITE replay nonces checked for replica acknowledgement (REPLAY_WRITE_WAIT_REPLICAS): result ok or failed (answered with an encrypted UNAVAILABLE)"),
        &["network", "result"]
    )
    .unwrap();

    static ref OHTTP_REPLAY_LOCAL_AOF_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_replay_local_aof_total", "WRITE replay nonces held only by the local store, checked for an AOF fsync (REPLAY_LOCAL_WAITAOF_MS): result ok or failed (answered with an encrypted UNAVAILABLE)"),
        &["network", "result"]
    )
    .unwrap();

    static ref OHTTP_REPLAY_LOCAL_AOF_SECONDS: HistogramVec = HistogramVec::new(
        prometheus::HistogramOpts::new("ohttp_replay_local_aof_seconds", "Time to get a WRITE replay nonce fsynced to the local security Redis AOF")
            .buckets(vec![0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]),
        &["network"]
    )
    .unwrap();

    static ref OHTTP_REPLAY_WRITE_WAIT_SECONDS: HistogramVec = HistogramVec::new(
        prometheus::HistogramOpts::new("ohttp_replay_write_wait_seconds", "Time to get a WRITE replay nonce acknowledged by the security Redis replicas")
            .buckets(vec![0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25]),
        &["network"]
    )
    .unwrap();

    static ref OHTTP_REPLAY_CLASS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_replay_class_total", "Inner requests by replay-protection class (REPLAY_READ_ROUTES): read or write; only counted when replay peers are configured"),
        &["network", "class"]
    )
    .unwrap();


    static ref OHTTP_THIRD_PARTY_CACHE_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_third_party_cache_total", "Third-party answer cache lookups (THIRD_PARTY_CACHE_ROUTES) by authority and result (hit, miss)"),
        &["network", "authority", "result"]
    )
    .unwrap();

    static ref OHTTP_THIRD_PARTY_LIMITED_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_third_party_limited_total", "Third-party upstream calls refused by the per-backend cap (THIRD_PARTY_RATE_LIMITS, inner 429)"),
        &["network", "authority"]
    )
    .unwrap();
}

// A second block: one more static in the first exceeds the macro recursion limit.
lazy_static::lazy_static! {
    static ref OHTTP_REPLAY_STANDBY_CONNECTED: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_replay_standby_connected", "Standby store (REPLAY_STANDBY_URLS) PING, per peer label; kept apart from ohttp_replay_peer_connected, which means the peers"),
        &["network", "peer"]
    )
    .unwrap();

    static ref OHTTP_REPLAY_STANDBY_STORES_CONFIGURED: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_replay_standby_stores_configured", "Number of REPLAY_STANDBY_URLS (standby origins' security Redis) this gateway replicates WRITE nonces to; their peer labels follow the REPLAY_PEER_URLS ones"),
        &["network"]
    )
    .unwrap();
}

pub fn init_metrics() {
    REGISTRY
        .register(Box::new(OHTTP_REQUESTS_TOTAL.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_REQUEST_DURATION_SECONDS.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_REQUESTS_IN_FLIGHT.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_UPSTREAM_ERRORS_TOTAL.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_UPSTREAM_REQUESTS_TOTAL.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_UPSTREAM_REQUEST_DURATION_SECONDS.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_DECRYPT_ERRORS.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_RELAY_REQUEST_ID_TOTAL.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_RELAY_REQUESTS_TOTAL.clone()))
        .ok();
    REGISTRY.register(Box::new(OHTTP_LWD_ERRORS.clone())).ok();
    REGISTRY
        .register(Box::new(OHTTP_LWD_CONNECT_RETRIES.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_ENCRYPT_ERRORS.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_POLICY_DENIED_TOTAL.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_LWD_SHED_TOTAL.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_LWD_PERMIT_WAITED_TOTAL.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_LWD_PERMIT_WAIT_SECONDS.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_CHUNKS_SENT_TOTAL.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_BLOCK_CACHE_HITS_TOTAL.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_BLOCK_CACHE_MISSES_TOTAL.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_UPSTREAM_BLOCKS_TOTAL.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_SINGLEFLIGHT_JOINS_TOTAL.clone()))
        .ok();
    REGISTRY
        .register(Box::new(
            OHTTP_BLOCK_CACHE_CONTINUITY_MISMATCH_TOTAL.clone(),
        ))
        .ok();
    for c in [
        &*OHTTP_UPSTREAM_CALLS_TOTAL,
        &*OHTTP_BLOCK_CACHE_STALE_TOTAL,
        &*OHTTP_BLOCK_CACHE_UNVALIDATED_TOTAL,
        &*OHTTP_LOCAL_CACHE_TOTAL,
        &*OHTTP_BLOCK_PERMANENT_TOTAL,
        &*OHTTP_CHAIN_REORGS_TOTAL,
        &*OHTTP_STORE_RECONNECT_TOTAL,
        &*OHTTP_REPLAY_WRITE_FALLBACK_TOTAL,
        &*OHTTP_REPLAY_WRITE_BACK_TOTAL,
        &*OHTTP_REPLAY_READ_FALLBACK_TOTAL,
        &*OHTTP_CHAIN_STALE_LEADER_TOTAL,
        &*OHTTP_PERMANENT_WRITES_SKIPPED_TOTAL,
        &*OHTTP_LWD_TIMEOUTS_TOTAL,
        &*OHTTP_LWD_POOL_RESETS_TOTAL,
        &*OHTTP_LWD_READ_RETRIES_TOTAL,
    ] {
        REGISTRY.register(Box::new(c.clone())).ok();
    }
    for g in [
        &*OHTTP_REPLAY_UNAVAILABLE_FALLBACK,
        &*OHTTP_REPLAY_FALLBACK_CHECK,
        &*OHTTP_REPLAY_SERVING_VIA_FALLBACK,
        &*OHTTP_REPLAY_LOCAL_FALLBACK,
        &*OHTTP_CHAIN_TIP_AGE_SECONDS,
        &*OHTTP_PERMANENT_STORE_REPLICA,
    ] {
        REGISTRY.register(Box::new(g.clone())).ok();
    }
    REGISTRY
        .register(Box::new(OHTTP_HEALTHZ_LWD_ERROR_RATIO.clone()))
        .ok();
    for g in [
        &*OHTTP_PERMANENT_STORE_CONNECTED,
        &*OHTTP_ORIGIN_INFO,
        &*OHTTP_KEY_CONFIG_INFO,
        &*OHTTP_SECURITY_REDIS_CONNECTED,
        &*OHTTP_REPLAY_PEERS_CONFIGURED,
        &*OHTTP_REPLAY_STANDBY_STORES_CONFIGURED,
        &*OHTTP_REPLAY_STANDBY_CONNECTED,
        &*OHTTP_REPLAY_PEER_CONNECTED,
        &*OHTTP_REPLAY_WRITE_BACK_PENDING,
    ] {
        REGISTRY.register(Box::new(g.clone())).ok();
    }
    REGISTRY
        .register(Box::new(OHTTP_REPLAY_PEER_TOTAL.clone()))
        .ok();
    for c in [
        &*OHTTP_REPLAY_MODE_SWITCHES_TOTAL,
        &*OHTTP_REPLAY_ASYNC_DROPPED_TOTAL,
        &*OHTTP_REPLAY_CLASS_TOTAL,
    ] {
        REGISTRY.register(Box::new(c.clone())).ok();
    }
    for g in [
        &*OHTTP_REPLAY_MODE_EFFECTIVE,
        &*OHTTP_REPLAY_ASYNC_QUEUE_DEPTH,
        &*OHTTP_REPLAY_REPLICATION_HEALTHY,
        &*OHTTP_REPLAY_PEER_CONSECUTIVE_FAILURES,
    ] {
        REGISTRY.register(Box::new(g.clone())).ok();
    }
    REGISTRY
        .register(Box::new(OHTTP_REPLAY_REPLICATION_LAG_SECONDS.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_MEMPOOL_UPSTREAM_STREAMS_TOTAL.clone()))
        .ok();
    REGISTRY.register(Box::new(OHTTP_CHAIN_LEADER.clone())).ok();
    REGISTRY
        .register(Box::new(OHTTP_MEMPOOL_SUBSCRIBERS.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_CHAIN_REORG_DEPTH.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_RESPONSE_TRUNCATED_TOTAL.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_CACHE_REQUESTS_TOTAL.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_CACHE_TIP_HEIGHT.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_THIRD_PARTY_CACHE_TOTAL.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_THIRD_PARTY_LIMITED_TOTAL.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_REPLAY_REJECTED.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_REPLAY_WRITE_WAIT_TOTAL.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_FRESHNESS_TOTAL.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_REPLAY_WRITE_WAIT_SECONDS.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_REPLAY_LOCAL_AOF_TOTAL.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_REPLAY_LOCAL_AOF_SECONDS.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_REDIS_CONNECTED.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_CACHE_REDIS_CONNECTED.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_LWD_REACHABLE.clone()))
        .ok();
    REGISTRY
        .register(Box::new(OHTTP_REDIS_OP_TIMEOUT_TOTAL.clone()))
        .ok();
}

/// Normalize HTTP method to bounded set for metrics.
/// Maps to: GET, POST, PUT, DELETE, HEAD, OPTIONS, or "other".
pub fn normalize_method(method: &str) -> &'static str {
    match method.to_ascii_uppercase().as_str() {
        "GET" => "GET",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "HEAD" => "HEAD",
        "OPTIONS" => "OPTIONS",
        _ => "other",
    }
}

/// Normalize backend label to bounded set for metrics.
/// Uses GATEWAY_HOSTS config to map authority to:
/// - "lwd" if authority is empty or matches gateway_hosts
/// - The authority itself if it's a known alias (in backends map)
/// - "other" for unknown authorities
///
/// NEVER use raw path or query string in labels.
pub fn normalize_backend(
    authority: &str,
    gateway_hosts: &[String],
    backends: &std::collections::HashMap<String, String>,
) -> String {
    if authority.is_empty() {
        return "lwd".to_string();
    }

    // Normalize authority: lowercase, strip port
    let authority_lower = authority
        .to_ascii_lowercase()
        .split(':')
        .next()
        .unwrap_or("")
        .to_string();

    // Check if it's a gateway host (own LWD)
    if gateway_hosts.iter().any(|h| h == &authority_lower) {
        return "lwd".to_string();
    }

    // Check if it's a known alias
    if backends.contains_key(&authority_lower) {
        return authority_lower;
    }

    // Unknown authority
    "other".to_string()
}

// Legacy API for backward compatibility
pub fn record_request(status: &str, mode: &str) {
    OHTTP_REQUESTS_TOTAL
        .with_label_values(&[status, mode, "unknown", "-", "-", "-", "-", "-", "-"])
        .inc();
}

// New API with full observability
#[allow(clippy::too_many_arguments)]
pub fn record_request_detailed(
    status: &str,
    mode: &str,
    network: &str,
    hop: &str,
    method: &str,
    http_status: u16,
    grpc_status: &str,
    backend: &str,
    route_class: &str,
) {
    OHTTP_REQUESTS_TOTAL
        .with_label_values(&[
            status,
            mode,
            network,
            hop,
            method,
            &http_status.to_string(),
            grpc_status,
            backend,
            route_class,
        ])
        .inc();
}

pub fn record_duration(network: &str, hop: &str, backend: &str, duration_secs: f64) {
    OHTTP_REQUEST_DURATION_SECONDS
        .with_label_values(&[network, hop, backend])
        .observe(duration_secs);
}

pub fn record_in_flight_inc(network: &str) {
    OHTTP_REQUESTS_IN_FLIGHT.with_label_values(&[network]).inc();
}

pub fn record_in_flight_dec(network: &str) {
    OHTTP_REQUESTS_IN_FLIGHT.with_label_values(&[network]).dec();
}

pub fn record_upstream_error(network: &str, backend: &str, error_type: &str) {
    OHTTP_UPSTREAM_ERRORS_TOTAL
        .with_label_values(&[network, backend, error_type])
        .inc();
}

/// Count an authenticated `/gateway` request by relay (the name of the `RELAY_SECRETS` entry that
/// matched, `-` with relay authentication off) and edge location (`CF-Ray` data centre, or `-`).
pub fn record_relay_request(network: &str, relay: &str, edge: &str) {
    OHTTP_RELAY_REQUESTS_TOTAL
        .with_label_values(&[network, relay, edge])
        .inc();
}

/// Count whether the relay sent a usable correlation id (`present` | `missing` | `invalid`).
pub fn record_relay_request_id(network: &str, state: &str) {
    OHTTP_RELAY_REQUEST_ID_TOTAL
        .with_label_values(&[network, state])
        .inc();
}

pub fn record_decrypt_error() {
    OHTTP_DECRYPT_ERRORS.inc();
}

/// A response chunk could not be sealed (`ohttp_encrypt_errors_total`; should stay 0).
pub fn record_encrypt_error() {
    OHTTP_ENCRYPT_ERRORS.inc();
}

pub fn record_lwd_error() {
    OHTTP_LWD_ERRORS.inc();
}

pub fn record_lwd_connect_retry() {
    OHTTP_LWD_CONNECT_RETRIES.inc();
}

/// Normalize RPC name for metrics (bounded label set to prevent cardinality explosion).
/// For LWD (gRPC) paths: only known CompactTxStreamer method names, else "other".
/// For HTTP backends: "other" (the backend is the separate `backend` label), never the raw path.
/// Rejected requests: "other".
pub fn normalize_rpc_name(path: &str, _method: &str) -> String {
    // LWD gRPC paths
    if path.contains("/cash.z.wallet.sdk.rpc.CompactTxStreamer/") || path.starts_with("/cash.z.") {
        let method_name = path.rsplit('/').next().unwrap_or("");
        match method_name {
            "GetLatestBlock"
            | "GetBlock"
            | "GetBlockNullifiers"
            | "GetBlockRange"
            | "GetBlockRangeNullifiers"
            | "GetTransaction"
            | "SendTransaction"
            | "GetTaddressTxids"
            | "GetTaddressBalance"
            | "GetTaddressBalanceStream"
            | "GetMempoolTx"
            | "GetMempoolStream"
            | "GetTreeState"
            | "GetLatestTreeState"
            | "GetSubtreeRoots"
            | "GetAddressUtxos"
            | "GetAddressUtxosStream"
            | "GetLightdInfo"
            | "Ping" => method_name.to_string(),
            _ => "other".to_string(),
        }
    } else {
        // HTTP backend paths: "other" (backend identity is recorded in the `backend` dimension)
        // Do NOT include the path itself to keep labels bounded
        "other".to_string()
    }
}

pub fn record_upstream_request(
    network: &str,
    backend: &str,
    rpc: &str,
    http_status: u16,
    grpc_status: &str,
    duration_secs: f64,
) {
    OHTTP_UPSTREAM_REQUESTS_TOTAL
        .with_label_values(&[network, backend, rpc, &http_status.to_string(), grpc_status])
        .inc();

    OHTTP_UPSTREAM_REQUEST_DURATION_SECONDS
        .with_label_values(&[network, backend, rpc])
        .observe(duration_secs);
}

pub fn record_cache_request(network: &str, rpc: &str, result: &str) {
    OHTTP_CACHE_REQUESTS_TOTAL
        .with_label_values(&[network, rpc, result])
        .inc();
}

pub fn record_cache_tip_height(network: &str, height: u64) {
    OHTTP_CACHE_TIP_HEIGHT
        .with_label_values(&[network])
        .set(height as i64);
}

pub fn record_lwd_shed(network: &str, class: &str) {
    OHTTP_LWD_SHED_TOTAL
        .with_label_values(&[network, class])
        .inc();
}

pub fn record_lwd_permit_wait(network: &str, class: &str, wait_seconds: f64) {
    OHTTP_LWD_PERMIT_WAITED_TOTAL
        .with_label_values(&[network, class])
        .inc();
    OHTTP_LWD_PERMIT_WAIT_SECONDS
        .with_label_values(&[network, class])
        .observe(wait_seconds);
}

pub fn record_policy_denied(alias: &str) {
    OHTTP_POLICY_DENIED_TOTAL.with_label_values(&[alias]).inc();
}

pub fn record_redis_connected(network: &str, connected: bool) {
    OHTTP_REDIS_CONNECTED
        .with_label_values(&[network])
        .set(if connected { 1 } else { 0 });
}

pub fn record_cache_redis_connected(network: &str, connected: bool) {
    OHTTP_CACHE_REDIS_CONNECTED
        .with_label_values(&[network])
        .set(if connected { 1 } else { 0 });
}

pub fn record_lwd_reachable(network: &str, reachable: bool) {
    OHTTP_LWD_REACHABLE
        .with_label_values(&[network])
        .set(if reachable { 1 } else { 0 });
    let mut since = LWD_UNREACHABLE_SINCE.lock();
    if reachable {
        since.remove(network);
    } else {
        since
            .entry(network.to_string())
            .or_insert_with(std::time::Instant::now);
    }
}

/// How long lightwalletd may be unreachable before `/health/ready` answers 503 (ZIP "Health
/// endpoints").
pub const LWD_READY_GRACE: std::time::Duration = std::time::Duration::from_secs(60);

static LWD_UNREACHABLE_SINCE: std::sync::LazyLock<
    parking_lot::Mutex<std::collections::HashMap<String, std::time::Instant>>,
> = std::sync::LazyLock::new(Default::default);

/// Readiness: lightwalletd answered the last check, or has been failing for less than
/// [`LWD_READY_GRACE`]. Before the first check it is not ready.
pub fn is_lwd_ready(network: &str) -> bool {
    let since = LWD_UNREACHABLE_SINCE.lock().get(network).copied();
    lwd_ready(is_lwd_healthy(network), since, std::time::Instant::now())
}

fn lwd_ready(
    reachable: bool,
    unreachable_since: Option<std::time::Instant>,
    now: std::time::Instant,
) -> bool {
    reachable || unreachable_since.is_some_and(|t| now.duration_since(t) < LWD_READY_GRACE)
}

/// Whether lightwalletd was reachable at its last reported probe (`ohttp_lwd_reachable`).
pub fn is_lwd_healthy(network: &str) -> bool {
    OHTTP_LWD_REACHABLE.with_label_values(&[network]).get() == 1
}

pub fn record_security_redis_connected(network: &str, connected: bool) {
    OHTTP_SECURITY_REDIS_CONNECTED
        .with_label_values(&[network])
        .set(if connected { 1 } else { 0 });
}

/// Whether the last security Redis PING succeeded. Without it every OHTTP request is refused
/// (replay protection fails closed), so a load balancer must not send traffic here.
pub fn is_security_redis_connected(network: &str) -> bool {
    OHTTP_SECURITY_REDIS_CONNECTED
        .with_label_values(&[network])
        .get()
        == 1
}

/// `ohttp_origin_info{origin}` = 1. `origin` is ORIGIN_ID, or "-" for a single-origin deployment.
pub fn record_origin_info(network: &str, origin_id: &str) {
    let origin = if origin_id.is_empty() { "-" } else { origin_id };
    OHTTP_ORIGIN_INFO
        .with_label_values(&[network, origin])
        .set(1);
}

/// `ohttp_key_config_info{fingerprint, signing_key_id}` = 1, so that operators can compare the
/// key material two origins publish with one PromQL query.
pub fn record_key_config_info(network: &str, fingerprint: &str, signing_key_id: Option<&str>) {
    OHTTP_KEY_CONFIG_INFO
        .with_label_values(&[network, fingerprint, signing_key_id.unwrap_or("-")])
        .set(1);
}

pub fn record_replay_peers_configured(network: &str, n: usize) {
    OHTTP_REPLAY_PEERS_CONFIGURED
        .with_label_values(&[network])
        .set(n as i64);
}

pub fn record_replay_standby_stores_configured(network: &str, n: usize) {
    OHTTP_REPLAY_STANDBY_STORES_CONFIGURED
        .with_label_values(&[network])
        .set(n as i64);
}

pub fn record_replay_standby_connected(network: &str, peer: usize, connected: bool) {
    OHTTP_REPLAY_STANDBY_CONNECTED
        .with_label_values(&[network, &peer.to_string()])
        .set(if connected { 1 } else { 0 });
}

pub fn record_replay_peer_connected(network: &str, peer: usize, connected: bool) {
    OHTTP_REPLAY_PEER_CONNECTED
        .with_label_values(&[network, &peer.to_string()])
        .set(if connected { 1 } else { 0 });
}

/// `peer` is the position in REPLAY_PEER_URLS (URLs carry credentials, so they are never a
/// label); `result`: fresh | replay | replay_async | error | timeout | disconnected.
pub fn record_replay_peer(network: &str, peer: usize, result: &str) {
    OHTTP_REPLAY_PEER_TOTAL
        .with_label_values(&[network, &peer.to_string(), result])
        .inc();
}

pub const REPLAY_MODE_LABELS: &[&str] = &["sync", "async-reads", "async-reads-strict", "failover"];

/// `ohttp_replay_mode_effective{mode}`: 1 for `label`, 0 for every other mode label.
pub fn record_replay_mode_effective(network: &str, label: &str) {
    for m in REPLAY_MODE_LABELS {
        OHTTP_REPLAY_MODE_EFFECTIVE
            .with_label_values(&[network, m])
            .set(if *m == label { 1 } else { 0 });
    }
}

pub fn record_replay_mode_switch(network: &str, to: &str, reason: &str) {
    OHTTP_REPLAY_MODE_SWITCHES_TOTAL
        .with_label_values(&[network, to, reason])
        .inc();
}

pub fn observe_replay_replication_lag(network: &str, peer: usize, secs: f64) {
    OHTTP_REPLAY_REPLICATION_LAG_SECONDS
        .with_label_values(&[network, &peer.to_string()])
        .observe(secs);
}

pub fn record_replay_async_queue_depth(network: &str, peer: usize, depth: usize) {
    OHTTP_REPLAY_ASYNC_QUEUE_DEPTH
        .with_label_values(&[network, &peer.to_string()])
        .set(depth as i64);
}

/// `reason`: overflow | expired.
pub fn record_replay_async_dropped(network: &str, peer: usize, reason: &str) {
    OHTTP_REPLAY_ASYNC_DROPPED_TOTAL
        .with_label_values(&[network, &peer.to_string(), reason])
        .inc();
}

/// Current value of `ohttp_replay_async_dropped_total` for one series (tests).
#[cfg(test)]
pub(crate) fn replay_async_dropped_count(network: &str, peer: usize, reason: &str) -> u64 {
    OHTTP_REPLAY_ASYNC_DROPPED_TOTAL
        .with_label_values(&[network, &peer.to_string(), reason])
        .get()
}

pub fn record_replay_replication_healthy(network: &str, peer: usize, healthy: bool) {
    OHTTP_REPLAY_REPLICATION_HEALTHY
        .with_label_values(&[network, &peer.to_string()])
        .set(if healthy { 1 } else { 0 });
}

pub fn record_replay_peer_consecutive_failures(network: &str, peer: usize, count: usize) {
    OHTTP_REPLAY_PEER_CONSECUTIVE_FAILURES
        .with_label_values(&[network, &peer.to_string()])
        .set(count as i64);
}

/// `result`: fresh | missing | malformed | stale.
pub fn record_freshness(network: &str, result: &str) {
    OHTTP_FRESHNESS_TOTAL
        .with_label_values(&[network, result])
        .inc();
}

pub fn observe_replay_local_aof(network: &str, ok: bool, elapsed: std::time::Duration) {
    OHTTP_REPLAY_LOCAL_AOF_TOTAL
        .with_label_values(&[network, if ok { "ok" } else { "failed" }])
        .inc();
    OHTTP_REPLAY_LOCAL_AOF_SECONDS
        .with_label_values(&[network])
        .observe(elapsed.as_secs_f64());
}

pub fn observe_replay_write_wait(network: &str, ok: bool, elapsed: std::time::Duration) {
    OHTTP_REPLAY_WRITE_WAIT_TOTAL
        .with_label_values(&[network, if ok { "ok" } else { "failed" }])
        .inc();
    OHTTP_REPLAY_WRITE_WAIT_SECONDS
        .with_label_values(&[network])
        .observe(elapsed.as_secs_f64());
}

/// `class`: read | write.
pub fn record_replay_class(network: &str, class: &str) {
    OHTTP_REPLAY_CLASS_TOTAL
        .with_label_values(&[network, class])
        .inc();
}

/// The verdict of the public `/healthz` route for a load-balancer monitor: 200 only while this
/// origin can actually answer OHTTP requests, which needs replay protection (else every request
/// is a 503) and lightwalletd (else every uncached RPC is a 502). Replay protection is the
/// security Redis, or, while that does not answer, the peer stores that decide in its place
/// (`via_fallback`, `ohttp_replay_serving_via_fallback`). Pure so that it is testable.
pub fn healthz_ok(
    security_redis_ok: bool,
    via_fallback: bool,
    lwd_ok: bool,
    lwd_errors_ok: bool,
) -> bool {
    (security_redis_ok || via_fallback) && lwd_ok && lwd_errors_ok
}

/// When the outcome of recent lightwalletd calls fails `/healthz` (`HEALTHZ_LWD_ERROR_RATIO`,
/// `HEALTHZ_LWD_ERROR_WINDOW_SECS`, `HEALTHZ_LWD_MIN_ERRORS`): over the last `window`, at least
/// `min_errors` calls failed and failed calls are at least `ratio` of all calls. A call failed
/// when it got no response head after its retry (connect error, transport error, deadline);
/// gRPC errors that lightwalletd answers do not count.
///
/// `ohttp_lwd_reachable` only follows the chain follower's probe, so a lightwalletd that answers
/// some connections and not others (one of several instances unreachable from here) kept
/// `/healthz` up while a share of the calls failed; this sends a load balancer to another origin
/// in that case. `ratio` 0 turns it off.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LwdErrorPolicy {
    pub ratio: f64,
    pub window: std::time::Duration,
    pub min_errors: u64,
}

pub const DEFAULT_HEALTHZ_LWD_ERROR_RATIO: f64 = 0.2;
pub const DEFAULT_HEALTHZ_LWD_ERROR_WINDOW_SECS: u64 = 30;
pub const DEFAULT_HEALTHZ_LWD_MIN_ERRORS: u64 = 5;

impl Default for LwdErrorPolicy {
    fn default() -> Self {
        Self {
            ratio: DEFAULT_HEALTHZ_LWD_ERROR_RATIO,
            window: std::time::Duration::from_secs(DEFAULT_HEALTHZ_LWD_ERROR_WINDOW_SECS),
            min_errors: DEFAULT_HEALTHZ_LWD_MIN_ERRORS,
        }
    }
}

impl LwdErrorPolicy {
    pub fn parse(
        ratio: Option<&str>,
        window_secs: Option<&str>,
        min_errors: Option<&str>,
    ) -> anyhow::Result<Self> {
        fn set(v: Option<&str>) -> Option<&str> {
            v.map(str::trim).filter(|v| !v.is_empty())
        }
        let ratio = match set(ratio) {
            None => DEFAULT_HEALTHZ_LWD_ERROR_RATIO,
            Some(v) => match v.parse::<f64>() {
                Ok(r) if (0.0..=1.0).contains(&r) => r,
                _ => anyhow::bail!("HEALTHZ_LWD_ERROR_RATIO must be between 0 and 1, got '{v}'"),
            },
        };
        let window = match set(window_secs) {
            None => DEFAULT_HEALTHZ_LWD_ERROR_WINDOW_SECS,
            Some(v) => match v.parse::<u64>() {
                Ok(n) if (1..=600).contains(&n) => n,
                _ => anyhow::bail!(
                    "HEALTHZ_LWD_ERROR_WINDOW_SECS must be an integer from 1 to 600, got '{v}'"
                ),
            },
        };
        let min_errors = match set(min_errors) {
            None => DEFAULT_HEALTHZ_LWD_MIN_ERRORS,
            Some(v) => match v.parse::<u64>() {
                Ok(n) if n > 0 => n,
                _ => anyhow::bail!("HEALTHZ_LWD_MIN_ERRORS must be a positive integer, got '{v}'"),
            },
        };
        Ok(Self {
            ratio,
            window: std::time::Duration::from_secs(window),
            min_errors,
        })
    }

    pub fn from_env() -> anyhow::Result<Self> {
        Self::parse(
            std::env::var("HEALTHZ_LWD_ERROR_RATIO").ok().as_deref(),
            std::env::var("HEALTHZ_LWD_ERROR_WINDOW_SECS")
                .ok()
                .as_deref(),
            std::env::var("HEALTHZ_LWD_MIN_ERRORS").ok().as_deref(),
        )
    }

    /// The verdict for `ok` and `failed` calls in the window (pure, for tests).
    pub fn healthy(&self, ok: u64, failed: u64) -> bool {
        if self.ratio <= 0.0 || failed < self.min_errors {
            return true;
        }
        (failed as f64) / ((ok + failed) as f64) < self.ratio
    }
}

static LWD_ERROR_POLICY: std::sync::OnceLock<LwdErrorPolicy> = std::sync::OnceLock::new();

/// Set once at startup (main); later calls are ignored (the defaults apply without it).
pub fn init_lwd_error_policy(p: LwdErrorPolicy) {
    let _ = LWD_ERROR_POLICY.set(p);
}

fn lwd_error_policy() -> LwdErrorPolicy {
    LWD_ERROR_POLICY.get().copied().unwrap_or_default()
}

/// Per-second counts of lightwalletd call outcomes, the last 600 s at most.
#[derive(Default)]
pub struct CallWindow {
    /// (second, ok, failed), oldest first.
    buckets: std::collections::VecDeque<(u64, u64, u64)>,
}

impl CallWindow {
    pub fn record(&mut self, now_sec: u64, ok: bool) {
        match self.buckets.back_mut() {
            Some((sec, o, f)) if *sec == now_sec => {
                if ok {
                    *o += 1
                } else {
                    *f += 1
                }
            }
            _ => self
                .buckets
                .push_back((now_sec, u64::from(ok), u64::from(!ok))),
        }
        while self
            .buckets
            .front()
            .is_some_and(|(sec, _, _)| now_sec.saturating_sub(*sec) >= 600)
        {
            self.buckets.pop_front();
        }
    }

    /// (ok, failed) over the `window_secs` seconds up to `now_sec`.
    pub fn totals(&self, now_sec: u64, window_secs: u64) -> (u64, u64) {
        self.buckets
            .iter()
            .filter(|(sec, _, _)| now_sec.saturating_sub(*sec) < window_secs)
            .fold((0, 0), |(o, f), (_, bo, bf)| (o + bo, f + bf))
    }
}

static LWD_CALLS: std::sync::LazyLock<
    parking_lot::Mutex<std::collections::HashMap<String, CallWindow>>,
> = std::sync::LazyLock::new(Default::default);
static LWD_CALLS_EPOCH: std::sync::LazyLock<std::time::Instant> =
    std::sync::LazyLock::new(std::time::Instant::now);

fn lwd_calls_now() -> u64 {
    LWD_CALLS_EPOCH.elapsed().as_secs()
}

/// The outcome of one call to the own lightwalletd, after its retry (lwd_endpoints::request).
pub fn record_lwd_call(network: &str, ok: bool) {
    let now = lwd_calls_now();
    LWD_CALLS
        .lock()
        .entry(network.to_string())
        .or_default()
        .record(now, ok);
}

/// Whether recent lightwalletd calls allow `/healthz` to be healthy ([`LwdErrorPolicy`]);
/// sets `ohttp_healthz_lwd_error_ratio`.
pub fn lwd_errors_ok(network: &str) -> bool {
    let policy = lwd_error_policy();
    let (ok, failed) = LWD_CALLS.lock().get(network).map_or((0, 0), |w| {
        w.totals(lwd_calls_now(), policy.window.as_secs())
    });
    let ratio = if failed < policy.min_errors {
        -1.0
    } else {
        failed as f64 / (ok + failed) as f64
    };
    OHTTP_HEALTHZ_LWD_ERROR_RATIO
        .with_label_values(&[network])
        .set(ratio);
    policy.healthy(ok, failed)
}

/// `reason`: timeout | error.
pub fn record_lwd_read_retry(network: &str, reason: &str) {
    OHTTP_LWD_READ_RETRIES_TOTAL
        .with_label_values(&[network, reason])
        .inc();
}

lazy_static::lazy_static! {
    // Its own block: the main one is at the macro recursion limit.
    static ref OHTTP_STORE_RECONNECT_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_store_reconnect_total", "Store connection failover signals and replacements, by store and reason: READONLY, MOVED, UNBLOCKED, LOADING, MASTERDOWN, ERR (WAIT refused on a replica), role (ROLE is not master), timeout, error (broken connection), short_ack (write-back: no replica acknowledgement for ~10 s); replaced = a new connection is in use"),
        &["network", "store", "reason"]
    )
    .unwrap();
    static ref OHTTP_REPLAY_WRITE_FALLBACK_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_replay_write_fallback_total", "WRITE replay nonces decided at a second store (write_fallback.rs). path: short_ack (the local replica acknowledgement was short, e.g. a resync after a failover of the local store), local_unavailable (the local store gave no verdict, REPLAY_UNAVAILABLE_FALLBACK), hub_short_ack / hub_unavailable (the same for the hub of an async-reads origin), window / hub_window (the check of every WRITE at the fallback store, inside the window after startup or a disruption), check / hub_check (the same check outside the window). result: accepted (the WRITE runs), replay (a store held the nonce: refused), unavailable (a store did not answer: the fallbacks fail closed, the checks keep the first verdict), unacknowledged (the store's own replicas did not confirm: fail-closed), overflow (write-back queue full: fail-closed)"),
        &["network", "path", "result"]
    )
    .unwrap();
    static ref OHTTP_REPLAY_WRITE_BACK_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_replay_write_back_total", "Nonces of WRITEs admitted through the peer stores, rewritten to the local security store: written (acknowledged by its replicas) or expired (TTL over before that)"),
        &["network", "result"]
    )
    .unwrap();
    static ref OHTTP_REPLAY_WRITE_BACK_PENDING: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_replay_write_back_pending", "Nonces of WRITEs admitted through the peer stores still waiting for the local replicas"),
        &["network"]
    )
    .unwrap();
}

lazy_static::lazy_static! {
    static ref OHTTP_REPLAY_READ_FALLBACK_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_replay_read_fallback_total", "READ replay nonces decided at the peer stores because the local store gave no verdict (REPLAY_UNAVAILABLE_FALLBACK). result: accepted | replay | unavailable (fail-closed)"),
        &["network", "result"]
    )
    .unwrap();
    static ref OHTTP_REPLAY_UNAVAILABLE_FALLBACK: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_replay_unavailable_fallback", "1 when REPLAY_UNAVAILABLE_FALLBACK is in effect on this gateway; target: local (the local store's verdict), standby (the hub's verdict, confirmed at the standby stores) or local_replicas (the hub's verdict, confirmed by the local replicas)"),
        &["network", "target"]
    )
    .unwrap();
    static ref OHTTP_REPLAY_FALLBACK_CHECK: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_replay_fallback_check", "1 when every WRITE this gateway admits is also checked at a fallback store synchronously (write_fallback.rs); REPLAY_UNAVAILABLE_FALLBACK is safe only while every gateway of the network with peers reports 1"),
        &["network"]
    )
    .unwrap();
    static ref OHTTP_REPLAY_SERVING_VIA_FALLBACK: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_replay_serving_via_fallback", "1 while the security Redis does not answer and this gateway keeps serving (and /healthz healthy) because its requests are decided at the peer stores (REPLAY_UNAVAILABLE_FALLBACK, every peer answering)"),
        &["network"]
    )
    .unwrap();
    static ref OHTTP_REPLAY_LOCAL_FALLBACK: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_replay_local_fallback", "1 when a request the security Redis gives no verdict on is decided at the peer stores instead of failing closed (REPLAY_UNAVAILABLE_FALLBACK; failover mode, or async-reads whose own store is the fallback store)"),
        &["network"]
    )
    .unwrap();
    static ref OHTTP_CHAIN_TIP_AGE_SECONDS: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_chain_tip_age_seconds", "Seconds since the chain follower's leader last moved the stored tip, as this process sees it (-1 = unknown)"),
        &["network"]
    )
    .unwrap();
    static ref OHTTP_CHAIN_STALE_LEADER_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_chain_stale_leader_total", "Times this process found the stored tip older than CHAIN_TIP_STALE_SECS while its own lightwalletd was ahead. action: local_tip (served its own lightwalletd's tip), takeover (took the leader lock)"),
        &["network", "action"]
    )
    .unwrap();
    static ref OHTTP_PERMANENT_STORE_REPLICA: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ohttp_permanent_store_replica", "1 while the permanent tier store is a read-only replica: its writes are skipped"),
        &["network"]
    )
    .unwrap();
    static ref OHTTP_PERMANENT_WRITES_SKIPPED_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_permanent_writes_skipped_total", "Permanent tier writes not sent because the store is a read-only replica"),
        &["network", "op"]
    )
    .unwrap();
    static ref OHTTP_LWD_TIMEOUTS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_lwd_timeouts_total", "lightwalletd call attempts ended by a per-class deadline (a read retried on another attempt counts each attempt). class: unary | stream; phase: head (no response head in time), body (unary: the whole call), gap (stream: no frame in time)"),
        &["network", "class", "phase"]
    )
    .unwrap();
    static ref OHTTP_LWD_READ_RETRIES_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_lwd_read_retries_total", "Idempotent lightwalletd calls sent a second time (to another instance when LWD_ENDPOINTS has one) because the first attempt got no response head. reason: timeout (half of the head deadline passed) | error (transport error)"),
        &["network", "reason"]
    )
    .unwrap();
    static ref OHTTP_HEALTHZ_LWD_ERROR_RATIO: prometheus::GaugeVec = prometheus::GaugeVec::new(
        Opts::new("ohttp_healthz_lwd_error_ratio", "Share of calls to lightwalletd that failed (no answer after the retry) in the /healthz error window, at the last /healthz; -1 below HEALTHZ_LWD_MIN_ERRORS failures"),
        &["network"]
    )
    .unwrap();
    static ref OHTTP_LWD_POOL_RESETS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("ohttp_lwd_pool_resets_total", "Times the pooled lightwalletd client (LWD_CONNECTION_POOL=1) was replaced after a call ran into its deadline, so that new calls open new connections"),
        &["network"]
    )
    .unwrap();
}

/// `result`: accepted | replay | unavailable.
pub fn record_replay_read_fallback(network: &str, result: &str) {
    OHTTP_REPLAY_READ_FALLBACK_TOTAL
        .with_label_values(&[network, result])
        .inc();
}

/// The unavailable fallback's target on this gateway (None = off).
pub fn record_replay_unavailable_fallback(network: &str, target: Option<&str>) {
    for t in ["local", "standby", "local_replicas"] {
        OHTTP_REPLAY_UNAVAILABLE_FALLBACK
            .with_label_values(&[network, t])
            .set(i64::from(target == Some(t)));
    }
}

pub fn record_replay_local_fallback(network: &str, on: bool) {
    OHTTP_REPLAY_LOCAL_FALLBACK
        .with_label_values(&[network])
        .set(i64::from(on));
}

pub fn record_replay_serving_via_fallback(network: &str, on: bool) {
    OHTTP_REPLAY_SERVING_VIA_FALLBACK
        .with_label_values(&[network])
        .set(i64::from(on));
}

/// Whether the last housekeeping round found the security Redis unreachable and the peer
/// stores able to decide this gateway's requests (`ResponseCache::serves_without_local_store`).
pub fn is_replay_serving_via_fallback(network: &str) -> bool {
    OHTTP_REPLAY_SERVING_VIA_FALLBACK
        .with_label_values(&[network])
        .get()
        == 1
}

pub fn record_replay_fallback_check(network: &str, on: bool) {
    OHTTP_REPLAY_FALLBACK_CHECK
        .with_label_values(&[network])
        .set(i64::from(on));
}

/// `age`: None = no advance time stored (an older leader, or no tip yet).
pub fn record_chain_tip_age(network: &str, age: Option<std::time::Duration>) {
    OHTTP_CHAIN_TIP_AGE_SECONDS
        .with_label_values(&[network])
        .set(age.map_or(-1, |a| a.as_secs() as i64));
}

/// `action`: local_tip | takeover.
pub fn record_chain_stale_leader(network: &str, action: &str) {
    OHTTP_CHAIN_STALE_LEADER_TOTAL
        .with_label_values(&[network, action])
        .inc();
}

pub fn record_permanent_replica(network: &str, replica: bool) {
    OHTTP_PERMANENT_STORE_REPLICA
        .with_label_values(&[network])
        .set(i64::from(replica));
}

/// `op`: set | mset | del.
pub fn record_permanent_write_skipped(network: &str, op: &str) {
    OHTTP_PERMANENT_WRITES_SKIPPED_TOTAL
        .with_label_values(&[network, op])
        .inc();
}

/// `class`: unary | stream; `phase`: head | body | gap.
pub fn record_lwd_timeout(network: &str, class: &str, phase: &str) {
    OHTTP_LWD_TIMEOUTS_TOTAL
        .with_label_values(&[network, class, phase])
        .inc();
}

pub fn record_lwd_pool_reset(network: &str) {
    OHTTP_LWD_POOL_RESETS_TOTAL
        .with_label_values(&[network])
        .inc();
}

/// `path`: short_ack | local_unavailable | hub_short_ack | hub_unavailable | window | check |
/// hub_window | hub_check; `result`: accepted | replay | unavailable | unacknowledged | overflow.
pub fn record_replay_write_fallback(network: &str, path: &str, result: &str) {
    OHTTP_REPLAY_WRITE_FALLBACK_TOTAL
        .with_label_values(&[network, path, result])
        .inc();
}

/// `result`: written | expired.
pub fn record_replay_write_back(network: &str, result: &str, n: u64) {
    OHTTP_REPLAY_WRITE_BACK_TOTAL
        .with_label_values(&[network, result])
        .inc_by(n);
}

pub fn record_replay_write_back_pending(network: &str, n: usize) {
    OHTTP_REPLAY_WRITE_BACK_PENDING
        .with_label_values(&[network])
        .set(n as i64);
}

/// `store`: security | write_wait | write_back | local_aof | pinned | permanent (no URLs: they carry
/// credentials).
pub fn record_store_reconnect(network: &str, store: &str, reason: &str) {
    OHTTP_STORE_RECONNECT_TOTAL
        .with_label_values(&[network, store, reason])
        .inc();
}

pub fn record_cache_redis_timeout(network: &str, operation: &str) {
    OHTTP_REDIS_OP_TIMEOUT_TOTAL
        .with_label_values(&[network, operation])
        .inc();
}

pub fn record_response_truncated(network: &str) {
    OHTTP_RESPONSE_TRUNCATED_TOTAL
        .with_label_values(&[network])
        .inc();
}

pub fn record_chunk_sent(network: &str, kind: &str) {
    OHTTP_CHUNKS_SENT_TOTAL
        .with_label_values(&[network, kind])
        .inc();
}

pub fn record_block_cache_hits(network: &str, n: u64) {
    OHTTP_BLOCK_CACHE_HITS_TOTAL
        .with_label_values(&[network])
        .inc_by(n);
}

pub fn record_block_cache_misses(network: &str, n: u64) {
    OHTTP_BLOCK_CACHE_MISSES_TOTAL
        .with_label_values(&[network])
        .inc_by(n);
}

pub fn record_upstream_blocks(network: &str, n: u64) {
    OHTTP_UPSTREAM_BLOCKS_TOTAL
        .with_label_values(&[network])
        .inc_by(n);
}

pub fn record_singleflight_join(network: &str, rpc: &str) {
    OHTTP_SINGLEFLIGHT_JOINS_TOTAL
        .with_label_values(&[network, rpc])
        .inc();
}

pub fn record_upstream_call(network: &str, rpc: &str) {
    OHTTP_UPSTREAM_CALLS_TOTAL
        .with_label_values(&[network, rpc])
        .inc();
}

pub fn record_block_cache_stale(network: &str) {
    OHTTP_BLOCK_CACHE_STALE_TOTAL
        .with_label_values(&[network])
        .inc();
}

pub fn record_block_cache_unvalidated(network: &str) {
    OHTTP_BLOCK_CACHE_UNVALIDATED_TOTAL
        .with_label_values(&[network])
        .inc();
}

pub fn record_local_cache(network: &str, hit: bool) {
    OHTTP_LOCAL_CACHE_TOTAL
        .with_label_values(&[network, if hit { "hit" } else { "miss" }])
        .inc();
}

pub fn record_local_cache_oversized(network: &str) {
    OHTTP_LOCAL_CACHE_TOTAL
        .with_label_values(&[network, "oversized"])
        .inc();
}

pub fn record_permanent_connected(network: &str, connected: bool) {
    OHTTP_PERMANENT_STORE_CONNECTED
        .with_label_values(&[network])
        .set(if connected { 1 } else { 0 });
}

/// `result`: hit | miss | stored | promoted | backfilled.
pub fn record_block_permanent(network: &str, result: &str, n: u64) {
    OHTTP_BLOCK_PERMANENT_TOTAL
        .with_label_values(&[network, result])
        .inc_by(n);
}

pub fn record_chain_leader(network: &str, leader: bool) {
    OHTTP_CHAIN_LEADER
        .with_label_values(&[network])
        .set(if leader { 1 } else { 0 });
}

pub fn record_chain_reorg(network: &str, depth: u64) {
    OHTTP_CHAIN_REORGS_TOTAL.with_label_values(&[network]).inc();
    OHTTP_CHAIN_REORG_DEPTH.observe(depth as f64);
}

pub fn record_mempool_subscribers(network: &str, delta: i64) {
    OHTTP_MEMPOOL_SUBSCRIBERS
        .with_label_values(&[network])
        .add(delta);
}

pub fn record_mempool_upstream_ended(network: &str, reason: &str) {
    OHTTP_MEMPOOL_UPSTREAM_STREAMS_TOTAL
        .with_label_values(&[network, reason])
        .inc();
}

pub fn record_block_cache_continuity_mismatch(network: &str) {
    OHTTP_BLOCK_CACHE_CONTINUITY_MISMATCH_TOTAL
        .with_label_values(&[network])
        .inc();
}

pub fn record_third_party_cache(network: &str, authority: &str, result: &str) {
    OHTTP_THIRD_PARTY_CACHE_TOTAL
        .with_label_values(&[network, authority, result])
        .inc();
}

pub fn record_third_party_limited(network: &str, authority: &str) {
    OHTTP_THIRD_PARTY_LIMITED_TOTAL
        .with_label_values(&[network, authority])
        .inc();
}

#[cfg(test)]
mod tests {
    #[test]
    fn readiness_waits_60_seconds_of_lwd_failures() {
        use std::time::{Duration, Instant};
        let t0 = Instant::now();
        assert!(super::lwd_ready(true, None, t0));
        assert!(
            !super::lwd_ready(false, None, t0),
            "never reached: not ready"
        );
        assert!(super::lwd_ready(
            false,
            Some(t0),
            t0 + Duration::from_secs(59)
        ));
        assert!(!super::lwd_ready(
            false,
            Some(t0),
            t0 + Duration::from_secs(60)
        ));

        let net = "readiness-test";
        super::record_lwd_reachable(net, true);
        super::record_lwd_reachable(net, false);
        assert!(
            super::is_lwd_ready(net),
            "one failed check is not an outage"
        );
        super::record_lwd_reachable(net, false);
        assert!(
            super::is_lwd_ready(net),
            "the outage starts at the first failure"
        );
        super::record_lwd_reachable(net, true);
        assert!(super::is_lwd_ready(net));
    }

    use super::*;

    #[test]
    fn test_normalize_rpc_name_grpc_known() {
        assert_eq!(
            normalize_rpc_name(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlockRange",
                "POST"
            ),
            "GetBlockRange"
        );
        assert_eq!(
            normalize_rpc_name(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock",
                "POST"
            ),
            "GetLatestBlock"
        );
        assert_eq!(
            normalize_rpc_name(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTreeState",
                "POST"
            ),
            "GetTreeState"
        );
        assert_eq!(
            normalize_rpc_name(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/SendTransaction",
                "POST"
            ),
            "SendTransaction"
        );
    }

    #[test]
    fn test_normalize_rpc_name_grpc_unknown() {
        // Unknown method → "other"
        assert_eq!(
            normalize_rpc_name(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/UnknownMethod",
                "POST"
            ),
            "other"
        );
        assert_eq!(
            normalize_rpc_name("/cash.z.wallet.sdk.rpc.CompactTxStreamer/", "POST"),
            "other"
        );
    }

    #[test]
    fn test_normalize_rpc_name_http() {
        // HTTP paths → "other" (backend dimension has the actual backend label)
        assert_eq!(normalize_rpc_name("/v0/blocks/123", "GET"), "other");
        assert_eq!(normalize_rpc_name("/v1/transactions", "POST"), "other");
        assert_eq!(normalize_rpc_name("/any/path/here", "GET"), "other");
    }

    #[test]
    fn test_normalize_rpc_name_bounded_set() {
        // Verify that 1000 unique paths produce a small bounded set of labels
        let mut labels = std::collections::HashSet::new();

        // Add all known LWD methods
        let known_methods = vec![
            "GetLatestBlock",
            "GetBlock",
            "GetBlockNullifiers",
            "GetBlockRange",
            "GetBlockRangeNullifiers",
            "GetTransaction",
            "SendTransaction",
            "GetTaddressTxids",
            "GetTaddressBalance",
            "GetTaddressBalanceStream",
            "GetMempoolTx",
            "GetMempoolStream",
            "GetTreeState",
            "GetLatestTreeState",
            "GetSubtreeRoots",
            "GetAddressUtxos",
            "GetAddressUtxosStream",
            "GetLightdInfo",
            "Ping",
        ];

        for method in &known_methods {
            let path = format!("/cash.z.wallet.sdk.rpc.CompactTxStreamer/{}", method);
            labels.insert(normalize_rpc_name(&path, "POST"));
        }

        // Add 1000 unknown paths (all should map to "other")
        for i in 0..1000 {
            let path = format!("/some/random/path/{}", i);
            labels.insert(normalize_rpc_name(&path, "GET"));
        }

        // Should have: 19 known methods + 1 "other" = 20 labels max
        assert!(labels.len() <= 25, "Label count: {}", labels.len());
        assert!(labels.contains("GetLatestBlock"));
        assert!(labels.contains("other"));
    }

    // Regression tests: bounded metric labels
    #[test]
    fn test_normalize_method_bounded() {
        // Standard methods
        assert_eq!(normalize_method("GET"), "GET");
        assert_eq!(normalize_method("POST"), "POST");
        assert_eq!(normalize_method("PUT"), "PUT");
        assert_eq!(normalize_method("DELETE"), "DELETE");
        assert_eq!(normalize_method("HEAD"), "HEAD");
        assert_eq!(normalize_method("OPTIONS"), "OPTIONS");

        // Case insensitive
        assert_eq!(normalize_method("get"), "GET");
        assert_eq!(normalize_method("Post"), "POST");

        // Unknown methods map to "other"
        assert_eq!(normalize_method("CUSTOM"), "other");
        assert_eq!(normalize_method("TRACE"), "other");
        assert_eq!(normalize_method("CONNECT"), "other");
        assert_eq!(normalize_method("/some/path"), "other");
    }

    #[test]
    fn test_normalize_method_cardinality() {
        // Verify 1000 unique methods produce bounded set
        let mut labels = std::collections::HashSet::new();

        // Add standard methods
        for method in &["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"] {
            labels.insert(normalize_method(method));
        }

        // Add 1000 random methods (all should map to "other")
        for i in 0..1000 {
            labels.insert(normalize_method(&format!("METHOD{}", i)));
        }

        // Should have at most 7 labels: 6 standard + "other"
        assert!(labels.len() <= 7, "Label count: {}", labels.len());
    }

    #[test]
    fn test_normalize_backend_empty_authority() {
        let gateway_hosts = vec![];
        let backends = std::collections::HashMap::new();
        assert_eq!(normalize_backend("", &gateway_hosts, &backends), "lwd");
    }

    #[test]
    fn test_normalize_backend_gateway_host() {
        let gateway_hosts = vec!["ohttp-gateway.example".to_string()];
        let backends = std::collections::HashMap::new();

        // Exact match
        assert_eq!(
            normalize_backend("ohttp-gateway.example", &gateway_hosts, &backends),
            "lwd"
        );

        // Case insensitive
        assert_eq!(
            normalize_backend("OHTTP-GATEWAY.EXAMPLE", &gateway_hosts, &backends),
            "lwd"
        );

        // With port
        assert_eq!(
            normalize_backend("ohttp-gateway.example:443", &gateway_hosts, &backends),
            "lwd"
        );
    }

    #[test]
    fn test_normalize_backend_known_alias() {
        let gateway_hosts = vec!["ohttp-gateway.example".to_string()];
        let mut backends = std::collections::HashMap::new();
        backends.insert(
            "api1.example.com".to_string(),
            "https://prices-upstream.example".to_string(),
        );
        backends.insert(
            "api2.example.com".to_string(),
            "https://1click.backend-api.example".to_string(),
        );

        assert_eq!(
            normalize_backend("api1.example.com", &gateway_hosts, &backends),
            "api1.example.com"
        );
        assert_eq!(
            normalize_backend("api2.example.com", &gateway_hosts, &backends),
            "api2.example.com"
        );

        // Case insensitive
        assert_eq!(
            normalize_backend("API1.EXAMPLE.COM", &gateway_hosts, &backends),
            "api1.example.com"
        );

        // With port
        assert_eq!(
            normalize_backend("api1.example.com:443", &gateway_hosts, &backends),
            "api1.example.com"
        );
    }

    #[test]
    fn test_normalize_backend_unknown_authority() {
        let gateway_hosts = vec!["ohttp-gateway.example".to_string()];
        let backends = std::collections::HashMap::new();

        // Unknown authority maps to "other"
        assert_eq!(
            normalize_backend("random.example.com", &gateway_hosts, &backends),
            "other"
        );
        assert_eq!(
            normalize_backend("malicious.attacker.example", &gateway_hosts, &backends),
            "other"
        );

        // Attackers trying to create unbounded labels
        for i in 0..1000 {
            assert_eq!(
                normalize_backend(&format!("r{}.x", i), &gateway_hosts, &backends),
                "other"
            );
        }
    }

    #[test]
    fn test_normalize_backend_cardinality() {
        let gateway_hosts = vec!["ohttp-gateway.example".to_string()];
        let mut backends = std::collections::HashMap::new();
        backends.insert(
            "api1.example.com".to_string(),
            "https://prices-upstream.example".to_string(),
        );
        backends.insert(
            "api2.example.com".to_string(),
            "https://1click.backend-api.example".to_string(),
        );

        let mut labels = std::collections::HashSet::new();

        // LWD variants
        labels.insert(normalize_backend("", &gateway_hosts, &backends));
        labels.insert(normalize_backend(
            "ohttp-gateway.example",
            &gateway_hosts,
            &backends,
        ));
        labels.insert(normalize_backend(
            "ohttp-gateway.example:443",
            &gateway_hosts,
            &backends,
        ));

        // Known aliases
        labels.insert(normalize_backend(
            "api1.example.com",
            &gateway_hosts,
            &backends,
        ));
        labels.insert(normalize_backend(
            "api2.example.com",
            &gateway_hosts,
            &backends,
        ));

        // 10000 unknown authorities (all map to "other")
        for i in 0..10000 {
            labels.insert(normalize_backend(
                &format!("attacker{}.evil.example", i),
                &gateway_hosts,
                &backends,
            ));
        }

        // Should have at most: "lwd" + 2 aliases + "other" = 4 labels
        assert!(labels.len() <= 4, "Label count: {}", labels.len());
        assert!(labels.contains("lwd"));
        assert!(labels.contains("api1.example.com"));
        assert!(labels.contains("api2.example.com"));
        assert!(labels.contains("other"));
    }
}

#[cfg(test)]
mod multi_origin_tests {
    use super::*;

    #[test]
    fn healthz_needs_replay_store_and_lightwalletd() {
        assert!(healthz_ok(true, false, true, true));
        assert!(
            !healthz_ok(false, false, true, true),
            "no replay store: every request is a 503"
        );
        assert!(
            !healthz_ok(true, false, false, true),
            "no lightwalletd: every uncached RPC is a 502"
        );
        assert!(!healthz_ok(false, false, false, true));
        assert!(
            healthz_ok(false, true, true, true),
            "replay store down, peer stores decide: still serving"
        );
        assert!(
            !healthz_ok(false, true, false, true),
            "the fallback does not replace lightwalletd"
        );
        assert!(
            !healthz_ok(false, true, true, false),
            "too many failed lightwalletd calls fail it also while the fallback works"
        );
        assert!(!healthz_ok(true, false, true, false));
    }

    #[test]
    fn lwd_error_policy_parse_and_verdict() {
        let d = LwdErrorPolicy::parse(None, None, None).unwrap();
        assert_eq!(d, LwdErrorPolicy::default());
        let p = LwdErrorPolicy::parse(Some("0.5"), Some("10"), Some("3")).unwrap();
        assert_eq!(p.window, std::time::Duration::from_secs(10));
        assert_eq!(p.min_errors, 3);
        assert!(LwdErrorPolicy::parse(Some("1.5"), None, None).is_err());
        assert!(LwdErrorPolicy::parse(Some("x"), None, None).is_err());
        assert!(LwdErrorPolicy::parse(None, Some("0"), None).is_err());
        assert!(LwdErrorPolicy::parse(None, Some("601"), None).is_err());
        assert!(LwdErrorPolicy::parse(None, None, Some("0")).is_err());

        // Default: 20 % of the calls, at least 5 failures.
        assert!(d.healthy(0, 0));
        assert!(d.healthy(0, 4), "below the minimum number of failures");
        assert!(!d.healthy(0, 5));
        assert!(!d.healthy(20, 5), "5 of 25 = 20 %");
        assert!(d.healthy(21, 5));
        // Ratio 0: off.
        let off = LwdErrorPolicy::parse(Some("0"), None, None).unwrap();
        assert!(off.healthy(0, 1000));
    }

    #[test]
    fn call_window_counts_only_the_window() {
        let mut w = CallWindow::default();
        for sec in 0..10 {
            w.record(sec, true);
            w.record(sec, sec % 2 == 0);
        }
        assert_eq!(w.totals(9, 30), (15, 5));
        assert_eq!(w.totals(9, 2), (3, 1), "seconds 8 and 9");
        assert_eq!(w.totals(100, 30), (0, 0), "all older than the window");
        // Old buckets are dropped after 600 s.
        w.record(700, false);
        assert_eq!(w.totals(700, 600), (0, 1));
    }

    #[test]
    fn failed_calls_fail_healthz_until_they_age_out() {
        let net = "test-lwd-errors";
        assert!(lwd_errors_ok(net));
        for _ in 0..5 {
            record_lwd_call(net, false);
        }
        record_lwd_call(net, true);
        assert!(!lwd_errors_ok(net), "5 of 6 calls failed");
        for _ in 0..30 {
            record_lwd_call(net, true);
        }
        assert!(lwd_errors_ok(net), "5 of 36 is below 20 %");
    }

    #[test]
    fn security_redis_gauge_drives_healthz() {
        let net = "healthz-gauge-test";
        assert!(
            !is_security_redis_connected(net),
            "unset gauge reads as down"
        );
        record_security_redis_connected(net, true);
        assert!(is_security_redis_connected(net));
        record_security_redis_connected(net, false);
        assert!(!is_security_redis_connected(net));
    }

    #[test]
    fn origin_and_key_config_info_labels() {
        init_metrics();
        record_origin_info("info-test", "");
        record_origin_info("info-test", "origin-b");
        record_key_config_info("info-test", "0123456789abcdef", None);
        record_key_config_info("info-test", "0123456789abcdef", Some("ba8a2dbd"));
        record_replay_peers_configured("info-test", 2);
        record_replay_peer("info-test", 1, "replay");
        record_replay_peer_connected("info-test", 1, true);
        let families = REGISTRY.gather();
        let find = |name: &str| {
            families
                .iter()
                .find(|f| f.get_name() == name)
                .unwrap_or_else(|| panic!("{name} not registered"))
                .get_metric()
                .iter()
                .filter(|m| m.get_label().iter().any(|l| l.get_value() == "info-test"))
                .map(|m| {
                    let mut labels: Vec<(String, String)> = m
                        .get_label()
                        .iter()
                        .map(|l| (l.get_name().to_string(), l.get_value().to_string()))
                        .collect();
                    labels.sort();
                    (
                        labels,
                        m.get_gauge().get_value() as i64 + m.get_counter().get_value() as i64,
                    )
                })
                .collect::<Vec<_>>()
        };
        let origins = find("ohttp_origin_info");
        assert!(origins
            .iter()
            .any(|(l, v)| *v == 1 && l.contains(&("origin".to_string(), "-".to_string()))));
        assert!(origins
            .iter()
            .any(|(l, v)| *v == 1 && l.contains(&("origin".to_string(), "origin-b".to_string()))));
        let keys = find("ohttp_key_config_info");
        assert!(keys
            .iter()
            .any(|(l, _)| l.contains(&("signing_key_id".to_string(), "-".to_string()))));
        assert!(keys.iter().any(|(l, _)| l
            .contains(&("signing_key_id".to_string(), "ba8a2dbd".to_string()))
            && l.contains(&("fingerprint".to_string(), "0123456789abcdef".to_string()))));
        assert_eq!(find("ohttp_replay_peers_configured")[0].1, 2);
        let peer = find("ohttp_replay_peer_total");
        assert!(peer.iter().any(|(l, v)| *v == 1
            && l.contains(&("peer".to_string(), "1".to_string()))
            && l.contains(&("result".to_string(), "replay".to_string()))));
        assert_eq!(find("ohttp_replay_peer_connected")[0].1, 1);

        // Replication mode metrics.
        record_replay_mode_effective("info-test", "async-reads-strict");
        record_replay_mode_switch("info-test", "strict", "lag");
        observe_replay_replication_lag("info-test", 0, 0.061);
        record_replay_async_queue_depth("info-test", 0, 7);
        record_replay_async_dropped("info-test", 0, "overflow");
        record_replay_replication_healthy("info-test", 0, true);
        record_replay_class("info-test", "read");
        let families = REGISTRY.gather();
        let find = |name: &str| {
            families
                .iter()
                .find(|f| f.get_name() == name)
                .unwrap_or_else(|| panic!("{name} not registered"))
                .get_metric()
                .iter()
                .filter(|m| m.get_label().iter().any(|l| l.get_value() == "info-test"))
                .map(|m| {
                    let labels: Vec<(String, String)> = m
                        .get_label()
                        .iter()
                        .map(|l| (l.get_name().to_string(), l.get_value().to_string()))
                        .collect();
                    (
                        labels,
                        m.get_gauge().get_value() as i64
                            + m.get_counter().get_value() as i64
                            + m.get_histogram().get_sample_count() as i64,
                    )
                })
                .collect::<Vec<_>>()
        };
        let modes = find("ohttp_replay_mode_effective");
        assert_eq!(
            modes.len(),
            REPLAY_MODE_LABELS.len(),
            "one series per mode label"
        );
        for (labels, v) in &modes {
            let mode = &labels.iter().find(|(k, _)| k == "mode").unwrap().1;
            assert_eq!(*v == 1, mode == "async-reads-strict", "{mode}");
        }
        assert!(find("ohttp_replay_mode_switches_total")
            .iter()
            .any(|(l, v)| *v == 1
                && l.contains(&("to".to_string(), "strict".to_string()))
                && l.contains(&("reason".to_string(), "lag".to_string()))));
        assert_eq!(find("ohttp_replay_replication_lag_seconds")[0].1, 1);
        assert_eq!(find("ohttp_replay_async_queue_depth")[0].1, 7);
        assert!(find("ohttp_replay_async_dropped_total")
            .iter()
            .any(|(l, v)| *v == 1 && l.contains(&("reason".to_string(), "overflow".to_string()))));
        assert_eq!(find("ohttp_replay_replication_healthy")[0].1, 1);
        assert!(find("ohttp_replay_class_total")
            .iter()
            .any(|(l, v)| *v == 1 && l.contains(&("class".to_string(), "read".to_string()))));
    }
}

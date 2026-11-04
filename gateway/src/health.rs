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
    ] {
        REGISTRY.register(Box::new(c.clone())).ok();
    }
    for g in [
        &*OHTTP_PERMANENT_STORE_CONNECTED,
        &*OHTTP_ORIGIN_INFO,
        &*OHTTP_KEY_CONFIG_INFO,
        &*OHTTP_SECURITY_REDIS_CONNECTED,
        &*OHTTP_REPLAY_PEERS_CONFIGURED,
        &*OHTTP_REPLAY_PEER_CONNECTED,
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
/// origin can actually answer OHTTP requests, which needs the replay store (else every request
/// is a 503) and lightwalletd (else every uncached RPC is a 502). Pure so that it is testable.
pub fn healthz_ok(security_redis_ok: bool, lwd_ok: bool) -> bool {
    security_redis_ok && lwd_ok
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
        assert!(healthz_ok(true, true));
        assert!(
            !healthz_ok(false, true),
            "no replay store: every request is a 503"
        );
        assert!(
            !healthz_ok(true, false),
            "no lightwalletd: every uncached RPC is a 502"
        );
        assert!(!healthz_ok(false, false));
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

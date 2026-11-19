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

// OHTTP Gateway — RFC 9458 Oblivious HTTP for Zcash Lightwalletd
//
// Two modes via GATEWAY_MODE env:
//
//   proxy  - Accepts plain gRPC from app, forwards to LWD. LWD only sees
//            gateway IP, not app IP. No HPKE encryption (basic IP hiding).
//
//   ohttp  - Accepts OHTTP-encapsulated requests from a relay.
//            The relay sees the client IP (not content), the gateway sees content
//            (not the IP); linking them needs relay and gateway to collude.

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use futures_util::Stream;
use parking_lot::RwLock;
use sha2::Digest;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};
use uuid::Uuid;

mod backfill;
mod block_cache;
mod cache;
mod chain;
mod chunked_stream;
mod config;
mod dynamic_hosts;
mod enforcement;
mod flexa;
mod freshness;
mod health;
mod host_list;
mod hpke;
mod local;
mod lwd;
mod lwd_endpoints;
mod mempool;
mod ohttp;
mod ohttp_chunked;
mod origin;
mod padding;
mod prefetch;
mod proxy;
mod query_rules;
mod query_value_sources;
mod replication;
mod request_id;
mod rpc_cache;
mod server;
mod singleflight;
mod store;
mod store_conn;
mod subtree_cache;
mod third_party_cache;
mod write_fallback;

mod signing;
use config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    health::init_metrics();

    // `ohttp-gateway backfill`: fill the permanent block tier and exit.
    if std::env::args().nth(1).as_deref() == Some("backfill") {
        return backfill::main().await;
    }

    let config = Config::from_env()?;
    // Multi-origin settings (ORIGIN_ID, REPLAY_PEER_URLS, ...): all inert when unset.
    let origin = origin::OriginSettings::from_env()?;
    let freshness_settings = freshness::Settings::from_env(cache::REPLAY_TTL_SECS)?;
    freshness::init(freshness_settings);
    let padding_mode = padding::Mode::from_env()?;
    padding::init(padding_mode);
    info!(mode = %padding_mode, "Response padding");
    let lwd_deadlines = lwd::LwdDeadlines::from_env()?;
    lwd::init_deadlines(lwd_deadlines);
    let lwd_transport = lwd_endpoints::Settings::from_env(&config.lwd_addr)?;
    debug!(
        endpoints = lwd_transport.endpoints.as_deref().unwrap_or("-"),
        "lightwalletd instances name (LWD_ENDPOINTS)"
    );
    info!(
        endpoints = lwd_transport.endpoints.is_some(),
        connect_timeout_ms = lwd_transport.connect_timeout.as_millis() as u64,
        hedge_delay = ?lwd_transport.hedge_delay,
        hedge_max_inflight = lwd_transport.hedge_max_inflight,
        "lightwalletd instances (LWD_ENDPOINTS, LWD_CONNECT_TIMEOUT_MS, LWD_HEDGE_DELAY_MS, LWD_HEDGE_MAX_INFLIGHT)"
    );
    lwd_endpoints::init(lwd_transport);
    let lwd_error_policy = health::LwdErrorPolicy::from_env()?;
    info!(
        ratio = lwd_error_policy.ratio,
        window_secs = lwd_error_policy.window.as_secs(),
        min_errors = lwd_error_policy.min_errors,
        "/healthz lightwalletd error window (HEALTHZ_LWD_ERROR_RATIO, HEALTHZ_LWD_ERROR_WINDOW_SECS, HEALTHZ_LWD_MIN_ERRORS)"
    );
    health::init_lwd_error_policy(lwd_error_policy);
    info!(
        unary_secs = lwd_deadlines.unary.as_secs(),
        stream_idle_secs = lwd_deadlines.stream_idle.as_secs(),
        "lightwalletd call deadlines (LWD_UNARY_TIMEOUT_SECS, LWD_STREAM_IDLE_SECS; LWD_TIMEOUT_SECS bounds both)"
    );
    info!(
        mode = %freshness_settings.mode,
        window_secs = freshness_settings.window_secs,
        "Request freshness (REPLAY_FRESHNESS)"
    );

    // Fail-closed: require relay auth unless explicitly disabled
    if config.mode == "ohttp"
        && config.relay_secrets.is_empty()
        && !config.allow_unauthenticated_relay
    {
        anyhow::bail!(
            "RELAY_SECRET (or RELAY_SECRETS) is required in OHTTP mode unless ALLOW_UNAUTHENTICATED_RELAY=1. \
             Configure a high-entropy secret to authenticate the relay."
        );
    }
    if config.relay_secret_on_key_config == config::RelaySecretOnKeyConfig::Require
        && config.relay_secrets.is_empty()
    {
        anyhow::bail!(
            "RELAY_SECRET_ON_KEY_CONFIG=require needs RELAY_SECRET (or RELAY_SECRETS): without a relay \
             secret no request could fetch the key configuration."
        );
    }
    info!(
        mode = ?config.relay_secret_on_key_config,
        "Relay secret on key configuration GETs (RELAY_SECRET_ON_KEY_CONFIG)"
    );
    if config.mode == "ohttp" && config.relay_secrets.is_empty() {
        warn!(
            "ALLOW_UNAUTHENTICATED_RELAY: /gateway accepts any sender. Only for local testing, or behind an \
             edge that admits authorised relays alone (source-address allowlist or mutual TLS, ZIP \
             \"Relay authorisation\")"
        );
    }

    let sanitized_redis = if !config.redis_url.is_empty() {
        config
            .redis_url
            .split('@')
            .next_back()
            .map(|s| format!("redis://***@{}", s))
            .unwrap_or_else(|| "redis://***".to_string())
    } else {
        String::new()
    };

    // Fingerprints (never the values) of the relay secrets, so that operators can check that
    // every origin behind a load balancer accepts the same relays.
    let relay_secret_fingerprints: Vec<String> = config
        .relay_secrets
        .iter()
        .map(|s| origin::secret_fingerprint("relay-secret", s.secret.as_bytes()))
        .collect();
    info!(
        mode = %config.mode,
        network = %config.network,
        origin = origin.label(),
        port = config.port,
        lwd_timeout_secs = config.lwd_timeout_secs,
        relay_auth_enabled = !config.relay_secrets.is_empty(),
        relay_secrets_count = config.relay_secrets.len(),
        relay_secret_fingerprints = %relay_secret_fingerprints.join(","),
        replay_peers = origin.replay_peer_urls.len(),
        replay_standby_stores = origin.replay_standby_urls.len(),
        replay_peer_timeout_ms = origin.replay_peer_timeout_ms,
        replay_peer_fail_closed = origin.replay_peer_fail_closed,
        replay_peer_mode = %origin.replay_peer_mode,
        replay_peer_fail_closed_writes = origin.replay_peer_fail_closed_writes,
        replay_async_max_lag_ms = origin.replay_async_max_lag_ms,
        replay_async_recovery_secs = origin.replay_async_recovery_secs,
        replay_unavailable_fallback = origin.replay_unavailable_fallback,
        redis = %sanitized_redis,
        "Starting OHTTP Gateway"
    );
    for authority in config.backends_policy.keys() {
        if !config.backends.contains_key(authority) && !config.gateway_hosts.contains(authority) {
            warn!(
                authority = %authority,
                "BACKENDS_POLICY entry for an authority in neither BACKENDS nor GATEWAY_HOSTS: never applied"
            );
        }
    }
    health::record_origin_info(&config.network, &origin.origin_id);
    health::record_replay_peers_configured(&config.network, origin.replay_peer_urls.len());
    health::record_replay_standby_stores_configured(
        &config.network,
        origin.replay_standby_urls.len(),
    );
    if origin.replay_peer_urls.is_empty() {
        health::record_replay_mode_effective(&config.network, "sync");
    } else {
        // The effective-mode gauge is owned by the replicator in the asynchronous modes.
        if origin.replay_peer_mode == origin::ReplayPeerMode::Sync {
            health::record_replay_mode_effective(&config.network, "sync");
        }
        info!(
            network = %config.network,
            mode = %origin.replay_peer_mode,
            read_routes = origin.replay_read_routes.len(),
            routes = %origin.replay_read_routes,
            "Replay READ routes (REPLAY_READ_ROUTES): these inner routes replicate their nonce asynchronously in async-reads mode; everything else is a WRITE (synchronous)"
        );
        info!(
            network = %config.network,
            one_sided_routes = origin.replay_one_sided_write_routes.len(),
            routes = %origin.replay_one_sided_write_routes,
            "WRITE routes that may run on one replay store's verdict (REPLAY_ONE_SIDED_WRITE_ROUTES); every other WRITE fails closed unless both stores take its nonce"
        );
    }

    // An OHTTP gateway answers only for its own host names (ZIP "Gateway behaviour" rule 5).
    // Without GATEWAY_HOSTS every unknown authority would reach lightwalletd, so refuse to start.
    config::require_gateway_hosts(&config.mode, &config.gateway_hosts)?;

    // Dynamic third-party hosts (DYNAMIC_HOST_SOURCES): one refresh per source before serving
    // (its network waits end with the fetch timeout; checking and applying a document comes on
    // top), so a starting process knows the hosts its peers serve. A
    // source that does not answer leaves its hosts out until it does; it never stops the start.
    if config.dynamic_hosts.enabled() {
        info!(
            sources = %config.dynamic_hosts.source_names().join(","),
            network = %config.network,
            "Dynamic host sources configured (DYNAMIC_HOST_SOURCES)"
        );
        config.dynamic_hosts.refresh_all().await;
        config.dynamic_hosts.spawn_refresh_tasks();
    }
    match config.host_list.mode {
        host_list::PublishMode::Off => {}
        mode => info!(
            mode = ?mode,
            max_age_secs = config.host_list.max_age_secs,
            path = host_list::HOST_LIST_PATH,
            network = %config.network,
            "Third-party host list published to wallets (THIRD_PARTY_HOSTS_PUBLISH)"
        ),
    }

    match config.flexa_alias.as_deref() {
        Some(alias) if !config.backends.contains_key(alias) => warn!(
            "FLEXA_ALIAS {} has no BACKENDS entry: the Flexa handling never applies",
            alias
        ),
        Some(alias) if config.flexa_publishable_key.is_none() => warn!(
            "FLEXA_PUBLISHABLE_KEY not set: {} requests carrying the placeholder key go upstream without Authorization",
            alias
        ),
        _ => {}
    }
    if config.flexa_publishable_key.is_some() && config.flexa_alias.is_none() {
        warn!("FLEXA_PUBLISHABLE_KEY set without FLEXA_ALIAS: the key is never used");
    }

    // Log backends policy status
    if !config.backends_policy.is_empty() {
        info!(
            backends_with_policy = config.backends_policy.len(),
            "Per-alias operation policies configured"
        );
        if !config.third_party_query_rules.is_empty() {
            info!(
                query_rules = config.third_party_query_rules.len(),
                "Per-route query allowlists configured (THIRD_PARTY_QUERY_RULES)"
            );
        }
    } else if !config.backends.is_empty() && !config.backends_policy_default_allow {
        warn!(
            "BACKENDS configured without BACKENDS_POLICY; all requests to aliases will be denied. \
             Set BACKENDS_POLICY or BACKENDS_POLICY_DEFAULT=allow."
        );
    }

    let hpke_state = if config.mode == "ohttp" {
        // Error if no HPKE key configured in OHTTP mode, instead of just warning and continuing
        if config.hpke_keys.is_empty() && config.hpke_private_key.is_none() {
            anyhow::bail!(
                "HPKE_KEYS (or HPKE_PRIVATE_KEY) is required in OHTTP mode. \
                 Generate a key: openssl rand -hex 32"
            );
        }
        let ks = hpke::KeyState::new(&config)?;
        info!(
            network = %config.network,
            origin = origin.label(),
            key_config_fingerprint = %ks.fingerprint(),
            key_ids = ?ks.key_ids(),
            accept_only_key_ids = ?ks.accept_only_key_ids(),
            "HPKE key configuration loaded (fingerprint = sha256(/ohttp-configs)[..8]; must match on every origin)"
        );
        Some(ks)
    } else {
        None
    };

    // OHTTP mode requires both Redis URLs: replay protection (the security Redis) lives in the
    // response cache module, and without it every request would be refused with 503 for good.
    if config.mode == "ohttp"
        && (config.redis_security_url.is_empty() || config.redis_url.is_empty())
    {
        anyhow::bail!(
            "REDIS_URL and REDIS_SECURITY_URL are required in OHTTP mode (replay protection fails \
             closed without them). REDIS_SECURITY_URL: a Redis with maxmemory-policy noeviction."
        );
    }

    let cache_state = if config.redis_url.is_empty() {
        info!("Response cache disabled (REDIS_URL not set)");
        None
    } else {
        info!("Connecting to Redis cache at {}", sanitized_redis);
        let network = config.network.clone();
        // CACHE_KEY_BACKEND overrides the backend name in cache keys. Set it on a backfill-only
        // instance that fetches from its own lwd but must write the pinned keys the serving
        // gateways read (e.g. "lwd.example:9067").
        let backend_host = std::env::var("CACHE_KEY_BACKEND")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| config.lwd_addr.clone());

        // Pass security URL for separate noeviction connection to prevent replay nonces from being evicted
        let security_url = if !config.redis_security_url.is_empty() {
            info!("Security Redis connection configured (noeviction)");
            Some(config.redis_security_url.as_str())
        } else {
            warn!("REDIS_SECURITY_URL not set");
            None
        };

        // Without the security Redis no OHTTP request can be served (replay protection fails
        // closed), and the cache is never retried once startup gave up on it: wait for it.
        let connected = loop {
            match cache::ResponseCache::connect(
                &config.redis_url,
                security_url,
                network.clone(),
                backend_host.clone(),
                config.redis_op_timeout_ms,
                config.max_block_range,
                &config.backends_policy,
            )
            .await
            {
                Err(e) if config.mode == "ohttp" && security_url.is_some() => {
                    warn!(
                        "Security Redis unreachable at startup, retrying in 5 s (every OHTTP request would be refused without it): {}",
                        e
                    );
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                other => break other,
            }
        };
        match connected {
            Ok(c) => {
                debug!(network = %network, backend = %backend_host, "cache key backend");
                info!(network = %network, "Redis cache connected, starting tip poller");

                // Pinned tier (optional): REDIS_PINNED_URL + PINNED_TREESTATE_RANGE.
                let pinned_url = std::env::var("REDIS_PINNED_URL").unwrap_or_default();
                let pinned_range = std::env::var("PINNED_TREESTATE_RANGE").unwrap_or_default();
                // REDIS_PINNED_WRITE_URL (optional): where pinned entries are written when
                // REDIS_PINNED_URL is a read replica (its primary).
                let pinned_write_url = std::env::var("REDIS_PINNED_WRITE_URL")
                    .ok()
                    .filter(|u| !u.trim().is_empty());
                let c = if pinned_url.is_empty() || pinned_range.is_empty() {
                    c
                } else {
                    match cache::parse_pinned_range(&pinned_range) {
                        None => anyhow::bail!("Malformed PINNED_TREESTATE_RANGE: {pinned_range}"),
                        Some(range) => match c
                            .clone()
                            .with_pinned(&pinned_url, pinned_write_url.as_deref(), range)
                            .await
                        {
                            Ok(p) => {
                                info!(network = %network, start = range.0, end = range.1, "Pinned GetTreeState tier enabled");
                                p
                            }
                            Err(e) => {
                                warn!("Failed to connect to pinned Redis, continuing without pinned tier: {}", e);
                                c
                            }
                        },
                    }
                };

                // Replay peers (REPLAY_PEER_URLS): the other origins' security Redis.
                let c = if origin.replay_peer_urls.is_empty() {
                    c
                } else {
                    let peers = cache::ReplayPeers::connect(
                        &origin.replay_peer_urls,
                        network.clone(),
                        origin.replay_peer_timeout_ms,
                        origin.replay_peer_fail_closed,
                    )
                    .await
                    .with_mode(
                        origin.replay_peer_mode,
                        origin.replay_peer_fail_closed_writes,
                    )
                    .with_wait_conns(
                        cache::WriteWaitConfig::peer_from_env()?,
                        cache::wait_conns_from_env()?,
                    );
                    info!(
                        network = %network,
                        peers = peers.len(),
                        mode = %origin.replay_peer_mode,
                        timeout_ms = origin.replay_peer_timeout_ms,
                        fail_closed = origin.replay_peer_fail_closed,
                        fail_closed_writes = origin.replay_peer_fail_closed_writes,
                        wait_replicas = peers.wait().map_or(0, |w| w.replicas),
                        wait_ms = peers.wait().map_or(0, |w| w.timeout_ms),
                        "Replay nonces are written to every peer origin; a nonce any peer holds is a replay"
                    );
                    c.with_replay_peers(peers).with_async_replication(
                        replication::ReplicationConfig::new(
                            &network,
                            origin.replay_peer_mode,
                            origin.replay_async_max_lag_ms,
                            origin.replay_async_recovery_secs,
                            origin.replay_peer_timeout_ms,
                            cache::REPLAY_TTL_SECS,
                            origin.replay_async_failures_before_strict,
                        ),
                    )
                };

                // Standby stores (REPLAY_STANDBY_URLS): every admitted WRITE nonce is replicated
                // there asynchronously; never on the request path.
                let c = if origin.replay_standby_urls.is_empty() {
                    c
                } else {
                    // REPLAY_PEER_WAIT_REPLICAS also applies to the standby stores: the hub
                    // fallback (write_fallback.rs) confirms a WRITE there synchronously.
                    let standby = cache::ReplayPeers::connect_standby(
                        &origin.replay_standby_urls,
                        network.clone(),
                        origin.replay_peer_timeout_ms,
                        origin.replay_peer_urls.len(),
                    )
                    .await
                    .with_wait_conns(
                        cache::WriteWaitConfig::peer_from_env()?,
                        cache::wait_conns_from_env()?,
                    );
                    info!(
                        network = %network,
                        stores = standby.len(),
                        first_peer_label = standby.first_label(),
                        "WRITE replay nonces are also replicated to the standby stores (asynchronously; synchronously in the hub path of the WRITE fallback)"
                    );
                    c.with_standby_replication(
                        standby,
                        replication::ReplicationConfig::new(
                            &network,
                            origin::ReplayPeerMode::Failover,
                            origin.replay_async_max_lag_ms,
                            origin.replay_async_recovery_secs,
                            origin.replay_peer_timeout_ms,
                            cache::REPLAY_TTL_SECS,
                            origin.replay_async_failures_before_strict,
                        ),
                    )
                };

                // REPLAY_WRITE_WAIT_REPLICAS: WRITE nonces must reach the security Redis
                // replicas before the request runs (cache::WriteWaitConfig). A connection
                // failure here fails startup, like the security connection itself.
                let c = match cache::WriteWaitConfig::from_env()? {
                    None => c,
                    Some(ww) => {
                        let conns = cache::wait_conns_from_env()?;
                        let c = c
                            .with_write_wait_conns(&config.redis_security_url, ww, conns)
                            .await?;
                        info!(
                            network = %network,
                            replicas = ww.replicas,
                            timeout_ms = ww.timeout_ms,
                            wait_conns = conns,
                            "WRITE replay nonces wait for replica acknowledgement (fail-closed)"
                        );
                        c
                    }
                };

                // REPLAY_LOCAL_WAITAOF_MS: only where a WRITE can run on the local check alone
                // (async-reads with REPLAY_PEER_FAIL_CLOSED_WRITES=0).
                let c = if !origin.replay_peer_urls.is_empty()
                    && origin.replay_peer_mode == origin::ReplayPeerMode::AsyncReads
                    && !origin.replay_peer_fail_closed_writes
                {
                    let c = c
                        .with_local_waitaof(
                            &config.redis_security_url,
                            cache::LocalAofConfig::from_env()?,
                        )
                        .await?;
                    info!(
                        network = %network,
                        waitaof_ms = c.local_waitaof_ms().unwrap_or(0),
                        "WRITE replay nonces held only locally wait for the AOF fsync (0 = off)"
                    );
                    c
                } else {
                    c
                };

                // REPLAY_UNAVAILABLE_FALLBACK: decide at the fallback store when the deciding
                // store gives no verdict (write_fallback.rs, "Unavailable store").
                let c = c
                    .with_unavailable_fallback(origin.replay_unavailable_fallback)
                    .with_fallback_health(cache::FallbackHealth::from_env()?);
                let target = c.unavailable_fallback_target();
                health::record_replay_unavailable_fallback(&network, target);
                let checks = c.checks_writes_at_fallback_store();
                health::record_replay_fallback_check(&network, checks);
                if c.replay_peers().is_some() && !checks {
                    warn!(
                        network = %network,
                        "WRITEs admitted here reach the fallback store only asynchronously: REPLAY_UNAVAILABLE_FALLBACK on another origin of these stores could admit one of them again"
                    );
                }
                // failover mode without the peer fallback: no second store is consulted on the
                // request path, so the both-stores rule has nothing to apply to here.
                if c.replay_peer_mode() == origin::ReplayPeerMode::Failover && !checks {
                    warn!(
                        network = %network,
                        "failover mode without the peer fallback (REPLAY_WRITE_WAIT_REPLICAS and REPLAY_PEER_WAIT_REPLICAS >= 1 needed): every WRITE is decided by the local store alone and its nonce only replicated to the peers afterwards; REPLAY_ONE_SIDED_WRITE_ROUTES does not apply, and a request sent to this origin and to a peer at once can run at both (active/passive only)"
                    );
                }
                let local_fallback = c.decides_at_peers_without_local();
                health::record_replay_local_fallback(&network, local_fallback);
                match (origin.replay_unavailable_fallback, target) {
                    (true, Some(target)) => info!(
                        network = %network,
                        target,
                        "A store that gives no replay verdict is replaced by the fallback store (REPLAY_UNAVAILABLE_FALLBACK)"
                    ),
                    // An origin that tolerates an unreachable hub has no deciding store to replace,
                    // but its own store still is (below).
                    (true, None) if !local_fallback => warn!(
                        network = %network,
                        "REPLAY_UNAVAILABLE_FALLBACK has no effect here: no fallback store that acknowledges on its replicas"
                    ),
                    _ => {}
                }
                if local_fallback {
                    info!(
                        network = %network,
                        mode = c.replay_peer_mode().as_str(),
                        "A security store that gives no replay verdict is replaced by the peer stores (REPLAY_UNAVAILABLE_FALLBACK); WRITE nonces are written back once it answers"
                    );
                }

                Some(c)
            }
            Err(e) => {
                warn!(
                    "Failed to connect to Redis cache, continuing without cache: {}",
                    e
                );
                None
            }
        }
    };

    // Signing state for /ohttp-configs/signed
    // Error on signing state initialization failure in OHTTP mode, instead of just warning
    let signing_state = if let Some(ref seed) = config.configs_signing_seed {
        match signing::SigningState::new(seed, config.network.clone()) {
            Ok(s) => {
                info!(
                    "Ed25519 signing enabled for /ohttp-configs/signed, key_id={} (envelopes issued per {} s slot, valid {} s)",
                    s.key_id(),
                    signing::ISSUANCE_SLOT_SECS,
                    signing::MAX_ISSUED_VALIDITY_SECS
                );
                Some(s)
            }
            Err(e) => {
                if config.mode == "ohttp" {
                    anyhow::bail!("Failed to initialize signing key in OHTTP mode: {}", e);
                } else {
                    warn!("Failed to initialize signing key: {}", e);
                    None
                }
            }
        }
    } else {
        if config.mode == "ohttp" {
            warn!("/ohttp-configs/signed will return 503 (CONFIGS_SIGNING_SEED_HEX not set)");
        }
        None
    };
    if let Some(ks) = &hpke_state {
        health::record_key_config_info(
            &config.network,
            &ks.fingerprint(),
            signing_state.as_ref().map(|s| s.key_id()).as_deref(),
        );
    }
    let lwd_semaphore = Arc::new(Semaphore::new(config.max_inflight_lwd));

    // Third-party answer cache and per-backend upstream cap (both off when unset).
    let third_party = third_party_cache::ThirdParty::from_env(
        config.flexa_alias.as_deref(),
        config.near_alias.as_deref(),
    )?;
    let (third_party_routes, third_party_capped) = third_party.summary();
    if third_party_routes + third_party_capped > 0 {
        info!(
            routes = third_party_routes,
            capped_backends = third_party_capped,
            "Third-party cache routes / upstream caps configured"
        );
    }

    // Every upstream the caches use: the gateway's own lightwalletd under the lwd concurrency limit.
    let sources = Arc::new(lwd::LwdSources::new(config.clone(), lwd_semaphore.clone()));

    // Singleflight for every RPC except SendTransaction, and the mempool fan-out (one upstream stream per process).
    let flights = Arc::new(singleflight::RpcFlights::new(
        sources.clone(),
        config.network.clone(),
    ));
    let mempool_fanout = Arc::new(
        mempool::MempoolFanout::new(sources.clone(), config.network.clone()).with_limits(
            Duration::from_secs(config.long_poll_max_initial_silence_secs),
            Duration::from_secs(config.long_poll_idle_secs),
            Duration::from_secs(config.lwd_timeout_secs),
        ),
    );

    // Per-process in-memory LRU in front of Redis (LOCAL_CACHE_BYTES, default 256 MiB, 0 = off;
    // values over LOCAL_CACHE_MAX_ENTRY_BYTES, default 64 KiB, are not admitted).
    let local_cache_bytes: u64 = std::env::var("LOCAL_CACHE_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(local::DEFAULT_LOCAL_CACHE_BYTES);
    let local_cache_max_entry: usize = std::env::var("LOCAL_CACHE_MAX_ENTRY_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(local::DEFAULT_LOCAL_CACHE_MAX_ENTRY_BYTES);
    let local_cache = match (&cache_state, local_cache_bytes) {
        (Some(_), n) if n > 0 => {
            info!(
                bytes = n,
                max_entry_bytes = local_cache_max_entry,
                "Local in-memory cache enabled"
            );
            Some(Arc::new(local::LocalCache::with_max_entry(
                n,
                local_cache_max_entry,
                config.network.clone(),
            )))
        }
        _ => None,
    };

    // Permanent block tier (PERMANENT_REDIS_URL, disk-backed Redis protocol): final blocks from
    // PERMANENT_MIN_HEIGHT (default Sapling activation) up to tip - 100, no TTL. Fail-open:
    // unreachable at startup = disabled until the next restart (logged).
    // PERMANENT_OP_TIMEOUT_MS (default 2000) is separate from REDIS_OP_TIMEOUT_MS: one MGET of
    // a batch of large blocks can be several MB read from disk, which the 250 ms cache budget
    // would turn into fail-open misses that go to lightwalletd instead.
    let permanent_min_height: u64 = std::env::var("PERMANENT_MIN_HEIGHT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| store::sapling_activation(&config.network));
    let permanent_op_timeout_ms: u64 = std::env::var("PERMANENT_OP_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2_000);
    let permanent_store: Option<Arc<cache::PermanentRedis>> = match (
        &cache_state,
        std::env::var("PERMANENT_REDIS_URL").unwrap_or_default(),
    ) {
        (Some(_), url) if !url.is_empty() => {
            match cache::PermanentRedis::connect(
                &url,
                permanent_op_timeout_ms,
                config.network.clone(),
            )
            .await
            {
                Ok(p) => {
                    info!(network = %config.network, min_height = permanent_min_height, op_timeout_ms = permanent_op_timeout_ms, "Permanent block tier enabled");
                    health::record_permanent_connected(&config.network, true);
                    cache::spawn_permanent_housekeeping(p.clone());
                    Some(Arc::new(p))
                }
                Err(e) => {
                    warn!(error = %e, "Permanent block tier unreachable, continuing without it");
                    health::record_permanent_connected(&config.network, false);
                    None
                }
            }
        }
        _ => None,
    };

    // Per-block cache for GetBlockRange and the chain follower that validates it, both on the
    // same Redis; the follower tells the mempool fan-out about new blocks.
    let pools = Arc::new(block_cache::PoolKeys::default());
    let block_cache_state = cache_state.as_ref().map(|c| {
        let mut bc = block_cache::BlockRangeCache::new(
            Arc::new(c.clone()),
            sources.clone(),
            local_cache.clone(),
            pools.clone(),
            config.network.clone(),
        );
        if let Some(p) = &permanent_store {
            bc = bc.with_permanent(p.clone(), permanent_min_height);
        }
        Arc::new(bc)
    });
    // Per-entry cache for GetSubtreeRoots: final roots in the permanent tier, the rest
    // validated against the follower's index.
    let subtree_cache_state = cache_state.as_ref().map(|c| {
        let mut sc = subtree_cache::SubtreeRootsCache::new(
            Arc::new(c.clone()),
            sources.clone(),
            config.network.clone(),
        );
        if let Some(p) = &permanent_store {
            sc = sc.with_permanent(p.clone());
        }
        Arc::new(sc)
    });
    // CHAIN_TIP_STALE_SECS: a stored tip unmoved for longer makes the followers compare it with
    // their own lightwalletd (chain.rs, "Stale leader").
    let chain_tip_stale_after = match std::env::var("CHAIN_TIP_STALE_SECS") {
        Ok(v) if !v.trim().is_empty() => match v.trim().parse::<u64>() {
            Ok(n) if n > 0 => Duration::from_secs(n),
            _ => anyhow::bail!("CHAIN_TIP_STALE_SECS must be a positive integer, got '{v}'"),
        },
        _ => chain::DEFAULT_TIP_STALE_AFTER,
    };
    // PREFETCH_TIP / PREFETCH_BLOCK_TXS / PREFETCH_BLOCK_TXS_MAX (prefetch.rs).
    let prefetch_config = prefetch::PrefetchConfig::from_env()?;
    let follower = cache_state.as_ref().map(|c| {
        let mut f = chain::ChainFollower::new(
            Arc::new(c.clone()),
            sources.clone(),
            local_cache.clone(),
            pools.clone(),
            config.network.clone(),
        );
        if let Some(p) = &permanent_store {
            f = f.with_permanent(p.clone(), permanent_min_height);
        }
        f = f.with_stale_after(chain_tip_stale_after);
        let f = Arc::new(f);
        f.add_listener(mempool_fanout.clone());
        if !prefetch_config.is_off() {
            f.add_listener(Arc::new(prefetch::TipPrefetch::new(
                Arc::new(c.clone()),
                flights.clone(),
                config.network.clone(),
                prefetch_config.clone(),
            )));
            info!(network = %config.network, prefetch = ?prefetch_config, "Tip prefetch enabled");
        }
        tokio::spawn(f.clone().run());
        cache::spawn_redis_housekeeping(c.clone());
        info!(network = %config.network, "Chain follower started");
        f
    });

    // Global in-flight limit on OHTTP requests, held until each response body ends.
    let max_inflight_requests = match std::env::var("MAX_INFLIGHT_REQUESTS") {
        Ok(v) if !v.trim().is_empty() => match v.trim().parse::<usize>() {
            Ok(n) if n > 0 => n,
            _ => anyhow::bail!("MAX_INFLIGHT_REQUESTS must be a positive integer, got '{v}'"),
        },
        _ => DEFAULT_MAX_INFLIGHT_REQUESTS,
    };
    info!(
        max_inflight_requests,
        "Global in-flight OHTTP request limit"
    );

    // REPLAY_STARTUP_STORES_WAIT_SECS: /healthz stays 503 until the replay peers and standby
    // stores are connected (connected in the background), or the bound has passed.
    if let Some(c) = &cache_state {
        let bound = cache::startup_stores_wait_from_env()?;
        if !c.replay_stores_connected() {
            info!(network = %config.network, bound_secs = bound.as_secs(), "Waiting for the replay peers and standby stores before reporting ready");
        }
        cache::spawn_replay_stores_gate(c.clone(), bound);
    }

    let app_state = Arc::new(AppState {
        config: config.clone(),
        origin: origin.clone(),
        hpke: hpke_state,
        cache: cache_state,
        block_cache: block_cache_state,
        subtree_cache: subtree_cache_state,
        follower,
        mempool: mempool_fanout,
        flights,
        sources,
        signing: signing_state,
        global_semaphore: Arc::new(Semaphore::new(config.max_inflight_upstream)),
        per_backend_semaphores: Arc::new(RwLock::new(HashMap::new())),
        lwd_semaphore,
        cache_get_semaphore: Arc::new(Semaphore::new(config.max_cache_get_concurrency)),
        large_response_semaphore: Arc::new(Semaphore::new(config.max_large_response_concurrency)),
        third_party,
        request_semaphore: Arc::new(Semaphore::new(max_inflight_requests)),
    });

    // THIRD_PARTY_QUERY_VALUE_SOURCES: each list is fetched in the background (first after a
    // random 0..5 s);
    // until a fetch is accepted, `{from:name}` admits the source's fallback, or nothing.
    let value_sources = app_state.config.third_party_query_rules.sources().clone();
    if !value_sources.is_empty() {
        info!(
            sources = value_sources.len(),
            "Query value sources configured (THIRD_PARTY_QUERY_VALUE_SOURCES)"
        );
        value_sources.spawn_refresh_tasks(app_state.clone());
    }

    // Pinned tier backfill: PINNED_BACKFILL_WORKERS per process (0/unset = write-through only).
    let backfill_workers: usize = std::env::var("PINNED_BACKFILL_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if let Some(c) = app_state.cache.clone() {
        if backfill_workers > 0 && c.pinned_range().is_some() {
            let st = app_state.clone();
            let authority = config.gateway_hosts.first().cloned().unwrap_or_default();
            cache::spawn_pinned_backfill(c, backfill_workers, move |height| {
                let st = st.clone();
                let req = ohttp::InnerRequest {
                    method: "POST".to_string(),
                    path: cache::tree_state_path().to_string(),
                    authority: authority.clone(),
                    headers: vec![
                        ("content-type".to_string(), "application/grpc".to_string()),
                        ("te".to_string(), "trailers".to_string()),
                    ],
                    body: cache::grpc_tree_state_request(height),
                };
                async move {
                    let resp = proxy::forward_to_backend(&st, &req).await?;
                    Ok(bincode::serialize(&resp)?)
                }
            });
        }
    }

    // Health and metrics handlers
    /// /health/live — process liveness (always returns 200 OK if the server is running)
    /// M4: Does NOT check LWD reachability; that's a gauge (ohttp_lwd_reachable).
    /// This endpoint checks process health only.
    async fn health_live_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
        let lwd_reachable = health::is_lwd_healthy(&state.config.network);
        let status = format!(
            "ok mode={} backend_reachable={}",
            state.config.mode, lwd_reachable
        );
        (StatusCode::OK, status)
    }

    /// /health/ready — dependency readiness check (M4: updated documentation)
    ///
    /// This endpoint checks process health and core dependency status:
    /// - Returns 503 if LWD has been unreachable for > 60s (core dependency for uncached requests)
    /// - Redis is not checked here (in OHTTP mode the replay check fails closed per request)
    ///
    /// Note: The LWD check uses the `ohttp_lwd_reachable` gauge (updated on each upstream attempt),
    /// not a live probe. This means:
    /// - Readiness reflects recent request history, not live backend status
    /// - First requests after startup may fail even if ready=200
    /// - Cached requests succeed regardless of LWD reachability
    ///
    /// Recorded upstream observations are on the `/metrics` endpoint (internal port 9090).
    async fn health_ready_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
        // 503 only once lightwalletd has been unreachable for more than 60 s.
        let lwd_healthy = health::is_lwd_ready(&state.config.network);

        if lwd_healthy {
            let status = format!(
                "ready mode={} network={}",
                state.config.mode, state.config.network
            );
            (StatusCode::OK, status).into_response()
        } else {
            let status = format!(
                "not ready: LWD unreachable network={}",
                state.config.network
            );
            (StatusCode::SERVICE_UNAVAILABLE, status).into_response()
        }
    }

    /// GET /healthz — the public, unauthenticated probe for a load balancer in front of several
    /// origins (load balancer health monitor). 200 "ok" while this origin can answer OHTTP requests:
    /// replay protection works (the security Redis answered the last PING and its connection
    /// reaches a primary: its last ROLE said master and no reconnect after a failover signal has
    /// been pending for more than 2 s; or it did not and the peer stores decide in its place:
    /// `ohttp_replay_serving_via_fallback`), lightwalletd is
    /// reachable and recent lightwalletd calls did not fail too often (`health::LwdErrorPolicy`),
    /// and the startup wait for the replay peers and standby stores (and their WAIT channels) is
    /// over (`REPLAY_STARTUP_STORES_WAIT_SECS`);
    /// else 503 "unavailable". Reads gauges, no I/O, no mode/network/origin in the body.
    async fn healthz_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
        let ok = health::healthz_ok(
            health::is_security_redis_connected(&state.config.network),
            health::is_replay_serving_via_fallback(&state.config.network),
            health::is_lwd_healthy(&state.config.network),
            health::lwd_errors_ok(&state.config.network),
        ) && health::is_replay_stores_ready(&state.config.network);
        let status = if ok {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        (
            status,
            [
                ("Content-Type", "text/plain"),
                ("Cache-Control", "no-store"),
            ],
            if ok { "ok" } else { "unavailable" },
        )
            .into_response()
    }

    /// Process-level startup readiness (NO LWD dependency).
    /// Returns 200 once the gateway process is configured and listening and the startup gate
    /// of the replay stores is open (503 `starting` while it waits for the replay peers and
    /// standby stores and their WAIT channels, at most REPLAY_STARTUP_STORES_WAIT_SECS).
    /// This is for readiness probes: an LWD outage should NOT mark the process unready,
    /// since the gateway still serves mapped backend aliases and cached LWD requests.
    /// LWD reachability is tracked by the `ohttp_lwd_reachable` gauge.
    async fn health_startup_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
        // Not ready while the startup gate waits for the replay stores
        // (REPLAY_STARTUP_STORES_WAIT_SECS, bounded).
        if !health::is_replay_stores_ready(&state.config.network) {
            return (StatusCode::SERVICE_UNAVAILABLE, "starting".to_string()).into_response();
        }
        let status = format!("ready mode={}", state.config.mode);
        (StatusCode::OK, status).into_response()
    }

    async fn metrics_handler_impl() -> impl IntoResponse {
        use prometheus::{Encoder, TextEncoder};
        let encoder = TextEncoder::new();
        let metric_families = health::REGISTRY.gather();
        let mut buffer = Vec::new();

        if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
            warn!("Failed to encode metrics: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to encode metrics",
            )
                .into_response();
        }

        let output = String::from_utf8(buffer).unwrap_or_else(|_| {
            "# Encoding error
"
            .to_string()
        });
        (StatusCode::OK, output).into_response()
    }

    // Split into two servers:
    // - Public server (PORT): /gateway, /ohttp-configs, /ohttp-configs/signed, /health/startup
    //   (process up and the replay-store startup gate open), /healthz (replay protection and
    //   lightwalletd; a security-store reconnect counts only after a 2 s grace)
    // - Internal server (9090): /metrics, /health/live, /health/ready (observability only)
    let public_app = Router::new()
        .route(
            "/health/startup",
            get(health_startup_handler).fallback(ohttp_required_handler),
        )
        .route(
            "/healthz",
            get(healthz_handler).fallback(ohttp_required_handler),
        )
        // Any other method on these paths is not an Encapsulated Request: 426 (ZIP rule 4).
        .route(
            "/ohttp-configs",
            get(ohttp_configs_handler).fallback(ohttp_required_handler),
        )
        .route(
            "/ohttp-configs/signed",
            get(ohttp_configs_signed_handler).fallback(ohttp_required_handler),
        )
        .route(
            "/gateway",
            post(gateway_handler).fallback(ohttp_required_handler),
        )
        .layer(DefaultBodyLimit::max(MAX_ENCAPSULATED_REQUEST_BYTES));
    // Plain gRPC passthrough is ONLY available in proxy mode. In ohttp mode every request must
    // arrive encapsulated via /gateway, so a client that bypasses OHTTP fails loudly instead of
    // silently degrading to IP-hiding-only.
    let public_app = if config.mode == "proxy" {
        public_app.fallback(proxy::proxy_handler)
    } else {
        public_app.fallback(ohttp_required_handler)
    };
    let public_app = public_app.with_state(app_state.clone());

    // Internal observability server
    let internal_app = Router::new()
        .route("/health", get(health_live_handler)) // Backward compat alias
        .route("/health/live", get(health_live_handler))
        .route("/health/ready", get(health_ready_handler)) // LWD-gated, observability only
        .route("/metrics", get(metrics_handler_impl))
        .with_state(app_state);

    let public_addr = format!("0.0.0.0:{}", config.port);
    // INTERNAL_BIND_ADDR (default 0.0.0.0:9090): health + metrics, never the public port.
    let internal_addr = server::internal_bind_addr_from_env()?;
    info!("Public server listening on {}", public_addr);
    info!(
        "Internal observability server listening on {}",
        internal_addr
    );

    let public_listener = tokio::net::TcpListener::bind(&public_addr).await?;
    let internal_listener = tokio::net::TcpListener::bind(internal_addr).await?;

    // Request header read timeout (HEADER_READ_TIMEOUT_SECS): hyper's `header_read_timeout`
    // with a timer, which `axum::serve` does not set. It also bounds the idle time of a
    // keep-alive connection, so it must stay above the proxies' idle timeouts (server.rs).
    let header_read_timeout = server::header_read_timeout_from_env()?;
    match header_read_timeout {
        Some(timeout) => info!(
            timeout_secs = timeout.as_secs(),
            "Request header read timeout (also the keep-alive idle bound)"
        ),
        None => warn!(
            "Request header read timeout disabled ({}=0)",
            server::HEADER_READ_TIMEOUT_ENV
        ),
    }

    // Run both servers concurrently
    tokio::try_join!(
        server::serve(
            public_listener,
            public_app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            header_read_timeout,
        ),
        server::serve(
            internal_listener,
            internal_app.into_make_service(),
            header_read_timeout,
        ),
    )?;

    Ok(())
}

pub struct AppState {
    pub config: Config,
    /// Multi-origin settings; `origin.label()` is the `origin` log field.
    pub origin: origin::OriginSettings,
    pub hpke: Option<hpke::KeyState>,
    pub cache: Option<cache::ResponseCache>,
    /// Per-block cache for GetBlockRange (present whenever the response cache is).
    pub block_cache: Option<Arc<block_cache::BlockRangeCache>>,
    /// Per-entry cache for GetSubtreeRoots (present whenever the response cache is).
    pub subtree_cache: Option<Arc<subtree_cache::SubtreeRootsCache>>,
    /// Chain follower: the tip and the height -> hash index (present whenever the cache is).
    pub follower: Option<Arc<chain::ChainFollower>>,
    /// Mempool fan-out: one upstream GetMempoolStream per process.
    pub mempool: Arc<mempool::MempoolFanout>,
    /// Singleflight for every other lightwalletd RPC.
    pub flights: Arc<singleflight::RpcFlights>,
    /// Direct upstream (SendTransaction, which is never coalesced).
    pub sources: Arc<lwd::LwdSources>,
    pub signing: Option<signing::SigningState>,
    /// Global upstream request limit
    pub global_semaphore: Arc<Semaphore>,
    /// Per-backend request limits
    pub per_backend_semaphores: Arc<RwLock<HashMap<String, Arc<Semaphore>>>>,
    /// LWD-specific concurrency limit to prevent resource exhaustion
    pub lwd_semaphore: Arc<Semaphore>,
    /// Cache GET concurrency limit to prevent excessive Redis load
    pub cache_get_semaphore: Arc<Semaphore>,
    /// Large response concurrency limit to bound memory usage
    pub large_response_semaphore: Arc<Semaphore>,
    /// Third-party answer cache and per-backend upstream cap (THIRD_PARTY_CACHE_ROUTES,
    /// THIRD_PARTY_RATE_LIMITS; both off when unset).
    pub third_party: third_party_cache::ThirdParty,
    /// MAX_INFLIGHT_REQUESTS: OHTTP requests in flight, a permit per request until its body ends.
    pub request_semaphore: Arc<Semaphore>,
}

/// Largest Encapsulated Request the gateway reads (ZIP: Gateways and Relays accept at least 10 MiB).
const MAX_ENCAPSULATED_REQUEST_BYTES: usize = 10 * 1024 * 1024;

/// MAX_INFLIGHT_REQUESTS default. Above the ZIP's reference (256) because every mempool long
/// poll and block range stream holds a permit for its whole duration.
const DEFAULT_MAX_INFLIGHT_REQUESTS: usize = 1024;

/// Builds the one kind of answer the gateway gives once a request has been opened: a chunked
/// OHTTP response (`message/ohttp-chunked-res`) sealed under the request's context, streamed
/// in fixed-size chunks by `chunked_stream::encode_response_stream`.
struct ChunkedResponder {
    ctx: hpke::ResponseContext,
    chunk_size: usize,
    flush: Duration,
    network: String,
    /// Whether the final chunk is padded (padding.rs); set again once the inner path is known.
    pad: bool,
    /// The request's MAX_INFLIGHT_REQUESTS permit, released when the response body ends.
    permit: tokio::sync::OwnedSemaphorePermit,
}

impl ChunkedResponder {
    fn new(
        ctx: hpke::ResponseContext,
        config: &Config,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Self {
        Self {
            ctx,
            chunk_size: config.chunk_size,
            flush: Duration::from_millis(config.chunk_flush_ms),
            network: config.network.clone(),
            pad: padding::mode().pads(None),
            permit,
        }
    }

    /// The padding of the answer to a request for `path`, under `RESPONSE_PADDING`.
    fn for_path(mut self, path: &str) -> Self {
        self.pad = padding::mode().pads(Some(path));
        self
    }

    /// Stream `upstream` as the inner response body and trailers.
    fn stream<S>(
        self,
        status: u16,
        mut headers: Vec<(String, String)>,
        upstream: S,
    ) -> axum::response::Response
    where
        S: Stream<Item = anyhow::Result<chunked_stream::UpFrame>> + Send + 'static,
    {
        use futures_util::StreamExt;
        // The Gateway clock, sealed to the Client, on every inner response (freshness.rs). An
        // upstream (a third-party backend) must not be able to set it: drop any copy first.
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case(freshness::SERVER_TIME_HEADER));
        headers.push((
            freshness::SERVER_TIME_HEADER.to_string(),
            freshness::now_unix().to_string(),
        ));
        let body = chunked_stream::encode_response_stream_padded(
            self.ctx,
            status,
            headers,
            upstream,
            self.chunk_size,
            self.flush,
            self.network,
            self.pad,
        );
        let permit = self.permit;
        let body = async_stream::stream! {
            let _permit = permit;
            let mut body = Box::pin(body);
            while let Some(item) = body.next().await {
                yield item;
            }
        };
        (
            StatusCode::OK,
            [
                ("Content-Type", ohttp_chunked::CONTENT_TYPE_CHUNKED_RES),
                ("Cache-Control", "no-store"),
            ],
            Body::from_stream(body),
        )
            .into_response()
    }

    /// A response collected in memory (a third-party backend, a cache hit, an error). Its
    /// `headers` already hold any gRPC trailers, as the collecting proxy writes them. With a
    /// body, the `grpc-*` fields go back into the trailer section: gRPC puts the status in the
    /// headers only for a Trailers-Only response, one without a body.
    fn collected(self, resp: ohttp::InnerResponse) -> axum::response::Response {
        let (headers, trailers) = if resp.body.is_empty() {
            (resp.headers, vec![])
        } else {
            chunked_stream::split_grpc_trailers(resp.headers)
        };
        self.stream(
            resp.status,
            headers,
            chunked_stream::collected_upstream(resp.body, trailers),
        )
    }

    fn text(self, status: u16, body: &str) -> axum::response::Response {
        self.collected(ohttp::InnerResponse {
            status,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body: body.as_bytes().to_vec(),
        })
    }

    /// An inner 200 with a gRPC error status and no body.
    fn grpc_error(self, code: &str, message: &str) -> axum::response::Response {
        self.collected(ohttp::InnerResponse {
            status: 200,
            headers: vec![
                ("content-type".to_string(), "application/grpc".to_string()),
                ("grpc-status".to_string(), code.to_string()),
                ("grpc-message".to_string(), message.to_string()),
            ],
            body: vec![],
        })
    }
}

/// The per-request log lines of the lightwalletd routes. They bypass `proxy.rs`, whose
/// "Forwarding to backend" line used to be the one place a request showed up with its
/// `client_trace_id`; operators correlate a device trace with the gateway on exactly that.
/// One line when the answer is dispatched (route, gRPC status when already known), one when
/// a streamed body ends (bytes, duration, outcome).
struct RequestLog {
    request_id: Uuid,
    client_trace_id: Option<String>,
    network: String,
    /// ORIGIN_ID, or "-".
    origin: String,
    method: String,
    path: String,
    start: Instant,
}

impl RequestLog {
    fn trace(&self) -> &str {
        self.client_trace_id.as_deref().unwrap_or("-")
    }

    /// A complete answer (a cache hit, a follower tip, an error) is being sent.
    fn served(&self, route: &str, grpc_status: &str, bytes_out: usize) {
        info!(
            request_id = %self.request_id,
            client_trace_id = self.trace(),
            method = %self.method,
            path = %self.path,
            route,
            grpc_status,
            bytes_out,
            duration_ms = self.start.elapsed().as_millis() as u64,
            network = %self.network,
            origin = %self.origin,
            hop = "lwd",
            "Serving lightwalletd request"
        );
    }

    /// An answer of the gateway itself (the third-party host list) is being sent.
    fn served_gateway(&self, route: &str, status: u16, bytes_out: usize) {
        info!(
            request_id = %self.request_id,
            client_trace_id = self.trace(),
            method = %self.method,
            path = %self.path,
            route,
            status,
            bytes_out,
            duration_ms = self.start.elapsed().as_millis() as u64,
            network = %self.network,
            origin = %self.origin,
            hop = "gateway",
            "Serving gateway request"
        );
    }

    /// A complete third-party answer (`third_party_cache`: a cache hit, the per-backend cap's
    /// 429, or one upstream call) is being sent.
    fn served_third_party(&self, status: u16, bytes_out: usize) {
        info!(
            request_id = %self.request_id,
            client_trace_id = self.trace(),
            method = %self.method,
            path = %self.path,
            route = "third_party",
            status,
            bytes_out,
            duration_ms = self.start.elapsed().as_millis() as u64,
            network = %self.network,
            origin = %self.origin,
            hop = "upstream",
            "Serving third-party request"
        );
    }

    /// A streamed answer is being sent; the end of `upstream` is logged with its byte count.
    fn stream<S>(
        &self,
        route: &'static str,
        grpc_status: &str,
        upstream: S,
    ) -> impl Stream<Item = anyhow::Result<chunked_stream::UpFrame>> + Send + 'static
    where
        S: Stream<Item = anyhow::Result<chunked_stream::UpFrame>> + Send + 'static,
    {
        info!(
            request_id = %self.request_id,
            client_trace_id = self.trace(),
            method = %self.method,
            path = %self.path,
            route,
            grpc_status,
            network = %self.network,
            origin = %self.origin,
            hop = "lwd",
            "Streaming lightwalletd request"
        );
        let request_id = self.request_id;
        let client_trace_id = self.client_trace_id.clone();
        let network = self.network.clone();
        let origin = self.origin.clone();
        let path = self.path.clone();
        let start = self.start;
        chunked_stream::on_end(upstream, move |end| {
            info!(
                request_id = %request_id,
                client_trace_id = client_trace_id.as_deref().unwrap_or("-"),
                path = %path,
                route,
                outcome = %end.outcome,
                grpc_status = end.grpc_status.as_deref().unwrap_or("-"),
                bytes_out = end.bytes,
                duration_ms = start.elapsed().as_millis() as u64,
                network = %network,
                origin = %origin,
                hop = "lwd",
                "Lightwalletd response ended"
            );
        })
    }
}

// Fallback in ohttp mode: refuse plain gRPC so nothing can bypass encapsulation.
async fn ohttp_required_handler(req: axum::http::Request<axum::body::Body>) -> impl IntoResponse {
    warn!(
        "Rejected non-OHTTP request {} {} (ohttp mode)",
        req.method(),
        req.uri().path()
    );
    health::record_request("rejected_plain", "ohttp");
    (
        StatusCode::UPGRADE_REQUIRED,
        [("Content-Type", "text/plain")],
        "OHTTP required: POST an encapsulated request to /gateway via a relay (RFC 9458)",
    )
        .into_response()
}

/// With `RELAY_SECRET_ON_KEY_CONFIG=require`, the 401 for a key configuration GET whose
/// `X-Relay-Secret` is missing, duplicated or wrong; `None` when the request may be answered.
fn key_config_unauthorized(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Option<axum::response::Response> {
    if state.config.relay_secret_on_key_config == config::RelaySecretOnKeyConfig::Off
        || config::authenticated_relay(&state.config.relay_secrets, headers).is_some()
    {
        return None;
    }
    warn!(
        network = %state.config.network,
        "Unauthorized key configuration request (X-Relay-Secret missing, duplicated or invalid)"
    );
    Some((StatusCode::UNAUTHORIZED, "Unauthorized").into_response())
}

// GET /ohttp-configs — Returns the HPKE key configuration (application/ohttp-keys)
async fn ohttp_configs_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Some(response) = key_config_unauthorized(&state, &headers) {
        return response;
    }
    match &state.hpke {
        Some(hpke_state) => (
            StatusCode::OK,
            [
                ("Content-Type", "application/ohttp-keys"),
                ("Cache-Control", "max-age=300"),
            ],
            hpke_state.public_config(),
        )
            .into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            [("Content-Type", "text/plain")],
            b"OHTTP mode disabled".to_vec(),
        )
            .into_response(),
    }
}

// GET /ohttp-configs/signed — Returns signed HPKE key configuration (application/json)
async fn ohttp_configs_signed_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Some(response) = key_config_unauthorized(&state, &headers) {
        return response;
    }
    match (&state.hpke, &state.signing) {
        (Some(hpke_state), Some(signing_state)) => {
            let configs_bytes = hpke_state.public_config();
            let signed_config = signing_state.get_signed_config(&configs_bytes);

            match serde_json::to_vec(&signed_config) {
                Ok(json_bytes) => (
                    StatusCode::OK,
                    [
                        ("Content-Type", "application/json"),
                        ("Cache-Control", "max-age=300"),
                    ],
                    json_bytes,
                )
                    .into_response(),
                Err(e) => {
                    warn!("Failed to serialize signed config: {}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        [("Content-Type", "text/plain")],
                        b"Serialization error".to_vec(),
                    )
                        .into_response()
                }
            }
        }
        (None, _) => (
            StatusCode::SERVICE_UNAVAILABLE,
            [("Content-Type", "text/plain")],
            b"OHTTP mode disabled".to_vec(),
        )
            .into_response(),
        (_, None) => (
            StatusCode::SERVICE_UNAVAILABLE,
            [("Content-Type", "text/plain")],
            b"Signing not configured".to_vec(),
        )
            .into_response(),
    }
}

// POST /gateway — OHTTP request handler
async fn gateway_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(_peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    body: Body,
) -> impl IntoResponse {
    let start = Instant::now();
    let network = state.config.network.clone();

    // Track in-flight requests
    health::record_in_flight_inc(&network);
    let _guard = scopeguard::guard((), |_| {
        health::record_in_flight_dec(&network);
    });

    // Correlation ids, one per checkpoint:
    // - `request_id`: ALWAYS minted here (UUIDv4). It is the only id forwarded upstream
    //   (X-Request-Id / grpc-request-id) and the key of the gateway's log lines.
    // - `relay_request_id`: whatever the relay sent (X-Request-Id, else a relay's trace header), kept as an
    //   opaque validated token and logged only as a per-process HMAC (below). Untrusted input:
    //   strict charset/length, never forwarded, never echoed, only a structured log field.
    let request_id = Uuid::new_v4();
    let (relay_request_id_raw, relay_request_id_source, relay_id_state) =
        request_id::extract_relay_request_id(&headers);
    health::record_relay_request_id(&network, relay_id_state.as_str());
    // Truncate relay_request_id with HMAC for privacy
    let relay_request_id = relay_request_id_raw
        .as_deref()
        .map(enforcement::truncate_relay_id)
        .unwrap_or_else(|| "-".to_string());

    // Extract optional client_trace_id for debugging.
    // Privacy note: This is OPT-IN. A client_trace_id links the relay's view (client IP) with
    // the gateway's view (request content) for debugging. Do not use in regular traffic.
    let client_trace_id = request_id::extract_client_trace_id(&headers);

    // Privacy evidence: the gateway only ever sees the relay. `_peer` is the relay's address and no
    // client-identifying forwarding header should be present.
    let _forwarded_for = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-");

    // Validate relay secret (required unless explicitly disabled); the name of the relay whose
    // secret matched goes to the metrics and logs.
    let mut relay_name = "-";
    if !state.config.relay_secrets.is_empty() {
        // Reject duplicate X-Relay-Secret headers
        let secret_headers: Vec<_> = headers.get_all("X-Relay-Secret").iter().collect();
        if secret_headers.len() > 1 {
            warn!(
                request_id = %request_id,
                network = %network,
                count = secret_headers.len(),
                "Multiple X-Relay-Secret headers"
            );
            health::record_request_detailed(
                "unauthorized",
                "ohttp",
                &network,
                "ohttp",
                "-",
                401,
                "-",
                "-",
                "other",
            );
            return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
        }

        // A header that is present but not visible ASCII is an invalid secret, not a missing one
        // (`HeaderValue::to_str` fails on it); the two are told apart in the log only, both 401.
        match headers.get("X-Relay-Secret").map(|v| v.to_str().ok()) {
            Some(header_secret) => {
                let matched = header_secret.and_then(|secret| {
                    config::match_relay_secret(&state.config.relay_secrets, secret.as_bytes())
                });
                if let Some(i) = matched {
                    relay_name = &state.config.relay_secrets[i].name;
                }
                let authenticated = matched.is_some();
                if !authenticated {
                    warn!(
                        request_id = %request_id,
                        network = %network,
                        visible_ascii = header_secret.is_some(),
                        "Unauthorized gateway request (invalid X-Relay-Secret)"
                    );
                    health::record_request_detailed(
                        "unauthorized",
                        "ohttp",
                        &network,
                        "ohttp",
                        "-",
                        401,
                        "-",
                        "-",
                        "other",
                    );
                    return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
                }
            }
            None => {
                warn!(
                    request_id = %request_id,
                    network = %network,
                    "Missing X-Relay-Secret"
                );
                health::record_request_detailed(
                    "unauthorized",
                    "ohttp",
                    &network,
                    "ohttp",
                    "-",
                    401,
                    "-",
                    "-",
                    "other",
                );
                return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
            }
        }
    } else if !state.config.allow_unauthenticated_relay {
        // This should not happen due to startup check, but defend in depth
        warn!(
            request_id = %request_id,
            network = %network,
            "Configuration error: no relay secrets configured"
        );
        health::record_request_detailed(
            "config_error",
            "ohttp",
            &network,
            "ohttp",
            "-",
            503,
            "-",
            "-",
            "other",
        );
        return (StatusCode::SERVICE_UNAVAILABLE, "Service misconfigured").into_response();
    }

    health::record_relay_request(&network, relay_name, request_id::edge_location(&headers));

    // Validate Content-Type for chunked OHTTP
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Not an Encapsulated Request: 426 like any other plaintext request (ZIP rule 4; 415 is not
    // an outer status of the ZIP's outer response contract).
    if content_type != ohttp_chunked::CONTENT_TYPE_CHUNKED_REQ {
        warn!(
            request_id = %request_id,
            network = %network,
            content_type = content_type,
            "Invalid Content-Type for chunked OHTTP request"
        );
        health::record_request_detailed(
            "invalid_content_type",
            "ohttp",
            &network,
            "ohttp",
            "-",
            426,
            "-",
            "-",
            "other",
        );
        return (
            StatusCode::UPGRADE_REQUIRED,
            [("Content-Type", "text/plain")],
            "Expected Content-Type: message/ohttp-chunked-req",
        )
            .into_response();
    }

    // Global in-flight limit: shed load before any work, reading the body included (up to
    // 10 MiB each), as an outer 503 (no inner answer exists yet). The permit is held until the
    // response body ends; the body read below has a deadline so that a sender which trickles
    // bytes cannot hold a permit indefinitely.
    let inflight_permit = match state.request_semaphore.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            warn!(
                request_id = %request_id,
                network = %network,
                "Global in-flight request limit reached (MAX_INFLIGHT_REQUESTS)"
            );
            health::record_request_detailed(
                "gateway_busy",
                "ohttp",
                &network,
                "ohttp",
                "-",
                503,
                "-",
                "-",
                "other",
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [("Content-Type", "text/plain"), ("Retry-After", "1")],
                "Gateway busy",
            )
                .into_response();
        }
    };

    // The body is read only now, after relay authentication: 413 for more than 10 MiB (ZIP
    // "Outer response contract"), never to a sender that did not authenticate (unless
    // ALLOW_UNAUTHENTICATED_RELAY=1). The whole body must
    // arrive within BODY_READ_DEADLINE (30 s), else 400 like any other unreadable body: the permit
    // taken above is released with the early return.
    let body = match enforcement::read_body(
        body,
        MAX_ENCAPSULATED_REQUEST_BYTES,
        enforcement::BODY_READ_DEADLINE,
    )
    .await
    {
        Ok(b) => b,
        Err(enforcement::BodyReadError::TooLarge(e)) => {
            warn!(
                request_id = %request_id,
                network = %network,
                error = %e,
                "Encapsulated request too large"
            );
            health::record_request_detailed(
                "request_too_large",
                "ohttp",
                &network,
                "ohttp",
                "-",
                413,
                "-",
                "-",
                "other",
            );
            return (StatusCode::PAYLOAD_TOO_LARGE, "Request entity too large").into_response();
        }
        Err(e) => {
            // A body that could not be read (the sender went away, or did not finish within the
            // deadline) is not a size violation.
            warn!(request_id = %request_id, network = %network, error = %e, "Encapsulated request unreadable");
            health::record_request_detailed(
                "body_unreadable",
                "ohttp",
                &network,
                "ohttp",
                "-",
                400,
                "-",
                "-",
                "other",
            );
            return (StatusCode::BAD_REQUEST, "Request body unreadable").into_response();
        }
    };

    // Privacy audit (LOG_OUTER_HEADER_NAMES=1): which outer headers does the relay let through?
    // Names only, sorted, lowercase; values are never logged.
    if state.config.log_outer_header_names {
        let mut names: Vec<&str> = headers.keys().map(|k| k.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        info!(
            request_id = %request_id,
            network = %network,
            outer_header_names = %names.join(","),
            "Outer request headers received from relay"
        );
    }

    if let Some(ref trace_id) = client_trace_id {
        info!(
            request_id = %request_id,
            relay_request_id = relay_request_id,
            relay_request_id_source = relay_request_id_source,
            relay = relay_name,
            client_trace_id = %trace_id,
            bytes_in = body.len(),
            network = %network,
            origin = state.origin.label(),
            hop = "ohttp",
            "Gateway received OHTTP request"
        );
    } else {
        info!(
            request_id = %request_id,
            relay_request_id = relay_request_id,
            relay_request_id_source = relay_request_id_source,
            relay = relay_name,
            bytes_in = body.len(),
            network = %network,
            origin = state.origin.label(),
            hop = "ohttp",
            "Gateway received OHTTP request"
        );
    }

    // Replay protection: check if this exact request body has been seen before.
    // Compute sha256(body) and check against Redis replay cache.
    let body_hash = {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&body);
        hasher.finalize()
    };
    // The local store gave no verdict and the unavailable fallback decides at the peer stores
    // once the inner request is classified (GW-REPLAY-INNER below).
    let mut local_unavailable = false;
    // What the local check saw; every later admission step needs it (`cache::LocalCheck`).
    let mut local_check: Option<cache::LocalCheck> = None;
    // The local check's duration: a stage of a WRITE (`ohttp_write_stage_duration_seconds`),
    // recorded once the inner request is classified.
    let local_started = Instant::now();
    let mut local_elapsed = Duration::ZERO;
    if let Some(ref cache) = state.cache {
        let checked = cache.check_replay_detailed(&body_hash).await;
        local_elapsed = local_started.elapsed();
        let verdict = checked
            .as_ref()
            .map(|c| c.verdict())
            .map_err(|e| e.to_string());
        if let Ok(c) = checked {
            local_check = Some(c);
        }
        match verdict {
            Ok(cache::LocalReplayCheck::Replay) => {
                warn!(
                    request_id = %request_id,
                    network = %network,
                    origin = state.origin.label(),
                    "Replay detected"
                );
                health::record_request_detailed(
                    "replay", "ohttp", &network, "ohttp", "-", 409, "-", "-", "other",
                );
                crate::health::OHTTP_REPLAY_REJECTED
                    .with_label_values(&[&network])
                    .inc();
                return (
                    StatusCode::CONFLICT,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    r#"{"error":"replay"}"#,
                )
                    .into_response();
            }
            Ok(cache::LocalReplayCheck::New | cache::LocalReplayCheck::NewPeersUnconfirmed) => {
                // Not a replay, continue
            }
            Ok(cache::LocalReplayCheck::Unavailable) => local_unavailable = true,
            Err(e) => {
                warn!(
                    request_id = %request_id,
                    network = %network,
                    error = %e,
                    "Replay protection unavailable (security Redis failure)"
                );
                health::record_request_detailed(
                    "replay_unavailable",
                    "ohttp",
                    &network,
                    "ohttp",
                    "-",
                    503,
                    "-",
                    "-",
                    "other",
                );
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Replay protection unavailable",
                )
                    .into_response();
            }
        }
    } else {
        // No Redis at all: replay protection cannot run, so fail closed.
        warn!(
            request_id = %request_id,
            network = %network,
            "Replay protection unavailable (no Redis configured)"
        );
        health::record_request_detailed(
            "replay_unavailable",
            "ohttp",
            &network,
            "ohttp",
            "-",
            503,
            "-",
            "-",
            "other",
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Replay protection unavailable",
        )
            .into_response();
    }

    let hpke_state = match &state.hpke {
        Some(hs) => hs,
        None => {
            warn!(
                request_id = %request_id,
                network = %network,
                "OHTTP mode not enabled"
            );
            health::record_request_detailed(
                "disabled", "ohttp", &network, "ohttp", "-", 503, "-", "-", "other",
            );
            return (StatusCode::SERVICE_UNAVAILABLE, "OHTTP mode disabled").into_response();
        }
    };

    // Stage 1: Chunked OHTTP decapsulation (failures here cannot be encrypted)
    let (plaintext, response_ctx) = match ohttp_chunked::decapsulate_chunked_request(
        std::io::Cursor::new(body.to_vec()),
        hpke_state,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!(
                request_id = %request_id,
                network = %network,
                error = %e,
                "OHTTP decapsulation failed"
            );
            health::record_decrypt_error();
            health::record_request_detailed(
                "decrypt_error",
                "ohttp",
                &network,
                "ohttp",
                "-",
                400,
                "-",
                "-",
                "other",
            );
            health::record_upstream_error(&network, "-", "decrypt");
            return (
                StatusCode::BAD_REQUEST,
                [("Content-Type", "text/plain")],
                "Bad Request",
            )
                .into_response();
        }
    };

    // Every answer from here on is sealed under this request's context.
    let responder = ChunkedResponder::new(response_ctx, &state.config, inflight_permit);

    // Stage 2: BHTTP parse (failures here can be encrypted)
    let inner_request = match ohttp::parse_inner_request(&plaintext) {
        Ok(v) => v,
        Err(e) => {
            warn!(
                request_id = %request_id,
                network = %network,
                error = %e,
                "BHTTP parse failed"
            );
            health::record_request_detailed(
                "parse_error",
                "ohttp",
                &network,
                "ohttp",
                "-",
                400,
                "-",
                "-",
                "other",
            );
            return responder.text(400, "Bad Request");
        }
    };
    let responder = responder.for_path(&inner_request.path);

    // Freshness (freshness.rs): refuse a request whose timestamp is outside the window before
    // anything is executed or served. When on, with the replay nonce (kept twice the window) this makes
    // every encapsulated request single-use for good, not only for REPLAY_TTL_SECS.
    let fresh_settings = freshness::settings();
    if fresh_settings.mode != freshness::Mode::Off {
        let verdict = freshness::check(
            &inner_request.headers,
            freshness::now_unix(),
            fresh_settings.window_secs,
        );
        health::record_freshness(&network, verdict.label());
        if freshness::refuses(fresh_settings.mode, verdict) {
            warn!(
                request_id = %request_id,
                network = %network,
                verdict = ?verdict,
                "Request outside the freshness window (refused)"
            );
            health::record_request_detailed(
                "freshness",
                "ohttp",
                &network,
                "ohttp",
                "-",
                400,
                "-",
                "-",
                "other",
            );
            return responder.collected(ohttp::InnerResponse {
                status: 400,
                headers: vec![
                    ("content-type".to_string(), "text/plain".to_string()),
                    (
                        freshness::REQUEST_HEADER.to_string(),
                        freshness::REJECTED.to_string(),
                    ),
                ],
                body: b"Request timestamp outside the freshness window".to_vec(),
            });
        }
    }

    // The dynamic-host view of this request, read once: the replay class, policy, labels, logged
    // route and the forward all use it, whatever a refresh does to the served set meanwhile.
    // The THIRD_PARTY_QUERY_RULES verdict is taken here once too, for the precheck and both
    // forwards.
    let route = proxy::RouteContext::resolve(&state.config, &inner_request)
        .with_query_verdict(&state.config, &inner_request);

    // Third-party paths are logged as their policy pattern at every level, debug included.
    let log = RequestLog {
        request_id,
        client_trace_id: client_trace_id.clone(),
        network: network.clone(),
        origin: state.origin.label().to_string(),
        method: inner_request.method.clone(),
        path: proxy::loggable_route_in(&state.config, &inner_request, &route),
        start,
    };
    debug!(
        request_id = %request_id,
        method = %inner_request.method,
        path = %log.path,
        authority = %inner_request.authority,
        network = %network,
        hop = "ohttp",
        "Decapsulated inner request"
    );

    // Resolve the backend from the inner :authority BEFORE touching the cache. The cache key is
    // path + body only, so a cached lightwalletd answer must never be returned to a request whose
    // authority is unknown (must get 403) or maps to a third-party upstream.
    let cache_allowed = proxy::resolve_backend_in(&state.config, &inner_request, &route).is_lwd();

    // The gateway's own host list (THIRD_PARTY_HOSTS_PUBLISH): answered below, after the replay
    // stages every inner request passes. Not a lightwalletd route, so the gateway host's
    // BACKENDS_POLICY entry does not apply to it.
    let host_list_request = cache_allowed && host_list::is_request(&state.config, &inner_request);
    // The replay class, decided once for all replay stages. READ: the host list; for a dynamic
    // host, what its lists call a READ (REPLAY_READ_ROUTES is not consulted for it); for
    // anything else, a route on REPLAY_READ_ROUTES. Everything else is a WRITE.
    let route_class = if host_list_request {
        origin::RouteClass::Read
    } else {
        route.replay_class(
            &state.origin.replay_read_routes,
            cache_allowed,
            &inner_request,
        )
    };

    if route_class == origin::RouteClass::Write && local_check.is_some() {
        health::observe_write_stage(
            &network,
            "local",
            if local_unavailable {
                "unavailable"
            } else {
                "new"
            },
            local_elapsed,
        );
    }

    // The light client server's own operation policy (BACKENDS_POLICY entry of a GATEWAY_HOSTS
    // authority): inner 403 before the cache and before anything is forwarded.
    if cache_allowed
        && !host_list_request
        && proxy::gateway_host_policy_denies(&state.config, &inner_request)
    {
        warn!(
            policy = "deny",
            request_id = %request_id,
            authority = %inner_request.authority,
            method = %inner_request.method,
            path = %inner_request.path,
            network = %network,
            "Operation denied by policy"
        );
        health::record_policy_denied("lwd");
        health::record_request_detailed(
            "policy_denied",
            "ohttp",
            &network,
            "ohttp",
            "-",
            403,
            "-",
            "lwd",
            "other",
        );
        return responder.collected(ohttp::InnerResponse {
            status: 403,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body: b"policy denied".to_vec(),
        });
    }

    // GW-REPLAY-INNER: Cross-origin replay protection by request class (REPLAY_PEER_MODE=async-reads|failover;
    // a no-op in sync mode, where check_replay above already consulted the peers). Decided
    // before anything is executed or served from the cache. The nonce is already in the local
    // store; a WRITE (anything not on REPLAY_READ_ROUTES) is checked at the peers synchronously
    // and a nonce a peer holds is refused like a local replay.
    // Returns inner responses so the relay learns nothing about side effects.
    // With `local_unavailable` the peer stores decide alone (admit_without_local).
    // REPLAY_ONE_SIDED_WRITE_ROUTES: whether this WRITE may run on one store's verdict
    // (write_fallback.rs, "Partition tolerance"). Not on the list: both stores must take it.
    let write_policy = cache::WritePolicy::for_route(route.one_sided_write(
        &state.origin.replay_one_sided_write_routes,
        cache_allowed,
        &inner_request,
    ));
    // The peer stage runs for every request the local check admitted (without peers it decides
    // nothing): its result, bound to this request's nonce, is what the later steps require.
    let mut peer_check: Option<cache::PeerCheck> = None;
    if let (Some(cache), Some(local)) = (state.cache.as_ref(), local_check.as_ref()) {
        let class = route_class;
        if local_unavailable || cache.replay_peers().is_some() {
            health::record_replay_class(&network, class.as_str());
        }
        let verdict = if local_unavailable {
            cache.admit_without_local(local, class, write_policy).await
        } else {
            cache
                .replicate_nonce_checked(local, class, write_policy)
                .await
        };
        match verdict {
            Ok(check) if !check.replay() => peer_check = Some(check),
            Ok(_) => {
                warn!(
                    request_id = %request_id,
                    network = %network,
                    origin = state.origin.label(),
                    class = class.as_str(),
                    "Replay detected at a peer origin"
                );
                crate::health::OHTTP_REPLAY_REJECTED
                    .with_label_values(&[&network])
                    .inc();
                // GW-REPLAY-INNER: gRPC requests get grpc-status, third-party HTTP gets HTTP 409
                if inner_request.is_grpc() {
                    health::record_request_detailed(
                        "replay", "ohttp", &network, "ohttp", "-", 200, "10", "-", "other",
                    );
                    log.served("replay", "10", 0);
                    return responder
                        .grpc_error("10", "Request aborted: replay detected at peer origin");
                } else {
                    health::record_request_detailed(
                        "replay", "ohttp", &network, "ohttp", "-", 409, "-", "-", "other",
                    );
                    log.served("replay", "-", 0);
                    return responder.collected(ohttp::InnerResponse {
                        status: 409,
                        headers: vec![("content-type".to_string(), "text/plain".to_string())],
                        body: b"Conflict: replay detected".to_vec(),
                    });
                }
            }
            Err(e) => {
                warn!(
                    request_id = %request_id,
                    network = %network,
                    error = %e,
                    class = class.as_str(),
                    "Replay protection unavailable (peer origin failure, fail-closed)"
                );
                // GW-REPLAY-INNER: gRPC requests get grpc-status, third-party HTTP gets HTTP 503
                if inner_request.is_grpc() {
                    health::record_request_detailed(
                        "replay_unavailable",
                        "ohttp",
                        &network,
                        "ohttp",
                        "-",
                        200,
                        "14",
                        "-",
                        "other",
                    );
                    log.served("replay_unavailable", "14", 0);
                    return responder.grpc_error(
                        "14",
                        "Service unavailable: replay protection unavailable (peer origin failure)",
                    );
                } else {
                    health::record_request_detailed(
                        "replay_unavailable",
                        "ohttp",
                        &network,
                        "ohttp",
                        "-",
                        503,
                        "-",
                        "-",
                        "other",
                    );
                    log.served("replay_unavailable", "-", 0);
                    return responder.collected(ohttp::InnerResponse {
                        status: 503,
                        headers: vec![("content-type".to_string(), "text/plain".to_string())],
                        body: b"Service unavailable: replay protection unavailable".to_vec(),
                    });
                }
            }
        }
    }

    // GW-REPLAY-INNER: Same-store failover window (REPLAY_WRITE_WAIT_REPLICAS): a WRITE runs only once its
    // replay nonce is on the security Redis replicas, so promoting a replica cannot forget it.
    // While the local replicas cannot acknowledge (a resync after a failover) the WRITE is
    // confirmed at the peer stores instead, when there are any (write_fallback.rs).
    // READs skip this: a replayed READ changes no state. Decided before
    // anything is executed or served from the cache; fail-closed like the replay check.
    // Returns inner responses so the relay learns nothing about side effects.
    if let (Some(cache), Some(local), Some(check)) = (
        state.cache.as_ref().filter(|c| c.write_wait().is_some()),
        local_check.as_ref(),
        peer_check.as_ref().filter(|c| !c.local_bypassed()),
    ) {
        let class = route_class;
        if class == origin::RouteClass::Write {
            let result = cache.confirm_write_nonce(local, check).await;
            if let Ok(cache::WriteAdmission::Replay) = result {
                warn!(
                    request_id = %request_id,
                    network = %network,
                    origin = state.origin.label(),
                    "Replay detected at a peer origin (WRITE confirmed at the peer stores)"
                );
                crate::health::OHTTP_REPLAY_REJECTED
                    .with_label_values(&[&network])
                    .inc();
                // GW-REPLAY-INNER: gRPC requests get grpc-status, third-party HTTP gets HTTP 409
                if inner_request.is_grpc() {
                    health::record_request_detailed(
                        "replay", "ohttp", &network, "ohttp", "-", 200, "10", "-", "other",
                    );
                    log.served("replay", "10", 0);
                    return responder
                        .grpc_error("10", "Request aborted: replay detected at peer origin");
                } else {
                    health::record_request_detailed(
                        "replay", "ohttp", &network, "ohttp", "-", 409, "-", "-", "other",
                    );
                    log.served("replay", "-", 0);
                    return responder.collected(ohttp::InnerResponse {
                        status: 409,
                        headers: vec![("content-type".to_string(), "text/plain".to_string())],
                        body: b"Conflict: replay detected".to_vec(),
                    });
                }
            }
            if let Err(e) = result {
                warn!(
                    request_id = %request_id,
                    network = %network,
                    error = %e,
                    "Replay protection unavailable (WRITE nonce not acknowledged by replicas, fail-closed)"
                );
                // GW-REPLAY-INNER: gRPC requests get grpc-status, third-party HTTP gets HTTP 503
                if inner_request.is_grpc() {
                    health::record_request_detailed(
                        "replay_unavailable",
                        "ohttp",
                        &network,
                        "ohttp",
                        "-",
                        200,
                        "14",
                        "-",
                        "other",
                    );
                    log.served("replay_unavailable", "14", 0);
                    return responder.grpc_error(
                        "14",
                        "Service unavailable: WRITE nonce not acknowledged by replicas",
                    );
                } else {
                    health::record_request_detailed(
                        "replay_unavailable",
                        "ohttp",
                        &network,
                        "ohttp",
                        "-",
                        503,
                        "-",
                        "-",
                        "other",
                    );
                    log.served("replay_unavailable", "-", 0);
                    return responder.collected(ohttp::InnerResponse {
                        status: 503,
                        headers: vec![("content-type".to_string(), "text/plain".to_string())],
                        body: b"Service unavailable: WRITE nonce not acknowledged".to_vec(),
                    });
                }
            }
        }
    }

    // GW-REPLAY-STANDBY: The WRITE passed every replay check and is about to run: its nonce goes
    // to the standby origins' stores too (REPLAY_STANDBY_URLS), asynchronously. A standby that
    // later takes over the WRITEs (shared store unreachable) then refuses a replay of it.
    if let (Some(cache), Some(local), Some(check)) = (
        state
            .cache
            .as_ref()
            .filter(|c| c.standby_replicator().is_some()),
        local_check.as_ref(),
        peer_check.take(),
    ) {
        let class = route_class;
        // Already confirmed there synchronously (the hub fallback or window).
        if class == origin::RouteClass::Write {
            cache.replicate_write_to_standby(local, check);
        }
    }

    // The host list: built from the configuration and the current dynamic hosts, no upstream.
    if host_list_request {
        let resp = host_list::answer(&state.config, &inner_request);
        let status = resp.status;
        health::record_request_detailed(
            if status == 503 {
                "unavailable"
            } else {
                "success"
            },
            "ohttp",
            &network,
            "ohttp",
            "GET",
            status,
            "-",
            "gateway",
            "other",
        );
        health::record_duration(
            &network,
            "ohttp",
            "gateway",
            "third_party_hosts",
            start.elapsed().as_secs_f64(),
            client_trace_id.is_some(),
        );
        log.served_gateway("host_list", status, resp.body.len());
        return responder.collected(resp);
    }

    // GW-GRPC-COMPRESSED: Reject compressed gRPC messages on all lightwalletd RPCs (ZIP L602-604).
    // This check runs before cache lookup and before the block range check.
    if cache_allowed {
        if let Err(e) = enforcement::check_grpc_compression(&inner_request.body) {
            let error_msg = e.to_string();
            let label = if error_msg.contains("Malformed") {
                "framing_error"
            } else {
                "compression_error"
            };
            warn!(
                request_id = %request_id,
                path = %inner_request.path,
                error = %error_msg,
                "gRPC message rejected"
            );
            health::record_request_detailed(
                label,
                "ohttp",
                &network,
                "ohttp",
                health::normalize_method(&inner_request.method),
                200,
                "3",
                "lwd",
                "other",
            );
            log.served(label, "3", 0);
            return responder.grpc_error("3", &error_msg);
        }
    }

    // Block range enforcement BEFORE any cache lookup (applies to hits and misses).
    // GW-BLOCKRANGE-MSG: Error messages distinguish span violations from other rejections.
    if let Err(e) = enforcement::check_block_range(
        &inner_request.path,
        &inner_request.body,
        state.config.max_block_range,
    ) {
        use enforcement::BlockRangeError;
        let message = match &e {
            BlockRangeError::SpanExceeded { span, max } => {
                format!(
                    "Block range of {} blocks exceeds the maximum of {}",
                    span, max
                )
            }
            BlockRangeError::Compression => {
                "Compressed gRPC messages are not supported".to_string()
            }
            BlockRangeError::MultiFrame => "Multi-frame or truncated gRPC request".to_string(),
            BlockRangeError::HeightlessBlockId => {
                "BlockID with height=0 not allowed (hash-only requests not supported)".to_string()
            }
            BlockRangeError::Other(msg) => msg.clone(),
        };
        warn!(
            request_id = %request_id,
            path = %inner_request.path,
            max_range = state.config.max_block_range,
            error = %e,
            "GetBlockRange validation failed"
        );
        health::record_request_detailed(
            "range_error",
            "ohttp",
            &network,
            "ohttp",
            health::normalize_method(&inner_request.method),
            200,
            "3",
            "lwd",
            "other",
        );
        log.served("range_error", "3", 0);
        return responder.grpc_error("3", &message);
    }

    let method_label = health::normalize_method(&inner_request.method);
    let backend = route.backend_label(&state.config, &inner_request.authority);
    let rpc = health::normalize_rpc_name(&inner_request.path, &inner_request.method);
    // Third-party requests: the policy entry that admits them (proxy::rpc_label).
    let backend_rpc = proxy::rpc_label_in(&state.config, &inner_request, &route);

    // Third-party backends: an answer from THIRD_PARTY_CACHE_ROUTES, or the per-backend cap's
    // inner 429 (THIRD_PARTY_RATE_LIMITS), before the usual streamed forward. The gateway cannot
    // see clients, so a backend's quota is protected per backend. A request the backend's policy
    // refuses (BACKENDS_POLICY, or a THIRD_PARTY_QUERY_RULES query shape) skips both: it gets the
    // inner 403 below and uses up no quota.
    // A dynamic host has neither: THIRD_PARTY_CACHE_ROUTES and THIRD_PARTY_RATE_LIMITS belong to
    // BACKENDS aliases; its cap is its source's `rate_limit`, counted in the forwarder.
    let is_dynamic_host = route.dynamic().is_some();
    if !cache_allowed
        && !is_dynamic_host
        && !proxy::policy_denies_in(&state.config, &inner_request, &route)
    {
        // The upstream call itself, when the cache and the cap let one through: the WRITE stage.
        let fetch = || async {
            let started = Instant::now();
            let fetched = proxy::forward_to_backend_in(&state, &inner_request, &route).await;
            if route_class == origin::RouteClass::Write {
                health::observe_write_stage(
                    &network,
                    "upstream_third_party",
                    match &fetched {
                        Ok(resp) if resp.status < 500 => "ok",
                        _ => "error",
                    },
                    started.elapsed(),
                );
            }
            fetched
        };
        if let Some(resp) = state
            .third_party
            .answer(
                state.cache.as_ref(),
                &network,
                &inner_request.authority,
                &inner_request.method,
                &inner_request.path,
                fetch,
            )
            .await
        {
            let status = resp.status;
            health::record_request_detailed(
                if status == 429 {
                    "third_party_limited"
                } else {
                    "success"
                },
                "ohttp",
                &network,
                "ohttp",
                method_label,
                status,
                "-",
                &backend,
                "mapped",
            );
            health::record_duration(
                &network,
                "ohttp",
                &backend,
                &backend_rpc,
                start.elapsed().as_secs_f64(),
                client_trace_id.is_some(),
            );
            log.served_third_party(status, resp.body.len());
            return responder.collected(resp);
        }
    }

    // Third-party backends, and authorities proxy.rs rejects (403/400): now streamed like lightwalletd.
    if !cache_allowed {
        let started = Instant::now();
        let forwarded = proxy::forward_to_backend_stream_in(
            &state,
            &inner_request,
            request_id,
            client_trace_id.clone(),
            &route,
        )
        .await;
        if route_class == origin::RouteClass::Write {
            health::observe_write_stage(
                &network,
                "upstream_third_party",
                match &forwarded {
                    Ok((status, _, _)) if *status < 500 => "ok",
                    _ => "error",
                },
                started.elapsed(),
            );
        }
        let (status, headers, stream) = match forwarded {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    request_id = %request_id,
                    path = %log.path,
                    error = %e,
                    network = %network,
                    "Backend error"
                );
                health::record_request_detailed(
                    "upstream_error",
                    "ohttp",
                    &network,
                    "upstream",
                    method_label,
                    502,
                    "-",
                    &backend,
                    "other",
                );
                health::record_upstream_error(&network, &backend, "request_failed");
                return responder.text(502, "Bad Gateway");
            }
        };
        health::record_request_detailed(
            "success",
            "ohttp",
            &network,
            "ohttp",
            method_label,
            status,
            "-",
            &backend,
            "mapped",
        );
        health::record_duration(
            &network,
            "ohttp",
            &backend,
            &backend_rpc,
            start.elapsed().as_secs_f64(),
            client_trace_id.is_some(),
        );
        return responder.stream(status, headers, log.stream("backend_stream", "-", stream));
    }

    // The gateway's own lightwalletd: streamed. GetBlockRange is assembled from the per-block cache,
    // GetLatestBlock is answered from the chain follower, GetMempoolStream joins the fan-out,
    // and every other RPC goes through the chain-validated per-request cache (hit: stream the
    // stored response; miss: one shared upstream call, stored behind the client).
    let grpc_headers = vec![("content-type".to_string(), "application/grpc".to_string())];
    let served = |status: u16, grpc_status: &str, route: &str| {
        health::record_request_detailed(
            "success",
            "ohttp",
            &network,
            "ohttp",
            method_label,
            status,
            grpc_status,
            &backend,
            route,
        );
        health::record_duration(
            &network,
            "ohttp",
            &backend,
            &rpc,
            start.elapsed().as_secs_f64(),
            client_trace_id.is_some(),
        );
    };

    if inner_request.path == block_cache::GET_BLOCK_RANGE_PATH {
        if let (Some(block_cache), Some(range)) = (
            state.block_cache.as_ref(),
            block_cache::BlockRangeRequest::parse(&inner_request.body),
        ) {
            debug!(
                request_id = %request_id,
                start_height = range.start,
                end_height = range.end,
                network = %network,
                hop = "ohttp",
                "GetBlockRange via per-block cache"
            );
            served(200, "-", "lwd");
            return responder.stream(
                200,
                grpc_headers,
                log.stream("block_cache", "-", block_cache.serve(range)),
            );
        }
    }

    if inner_request.path == subtree_cache::GET_SUBTREE_ROOTS_PATH {
        if let (Some(subtree_cache), Some(req)) = (
            state.subtree_cache.as_ref(),
            subtree_cache::SubtreeRootsRequest::parse(&inner_request.body),
        ) {
            debug!(
                request_id = %request_id,
                protocol = req.protocol,
                start_index = req.start_index,
                max_entries = req.max_entries,
                network = %network,
                hop = "ohttp",
                "GetSubtreeRoots via per-entry cache"
            );
            served(200, "-", "lwd");
            return responder.stream(
                200,
                grpc_headers,
                log.stream(
                    "subtree_cache",
                    "-",
                    subtree_cache.serve(req, Some(request_id)),
                ),
            );
        }
    }

    if rpc == "GetLatestBlock" {
        if let Some(tip) = state.follower.as_ref().and_then(|f| f.tip()) {
            debug!(
                request_id = %request_id,
                height = tip.height,
                network = %network,
                hop = "ohttp",
                "GetLatestBlock answered from the chain follower"
            );
            health::record_cache_request(&network, "GetLatestBlock", "follower_tip");
            served(200, "0", "lwd");
            let body = cache::grpc_block_id(tip.height, &tip.hash);
            log.served("follower_tip", "0", body.len());
            return responder.stream(
                200,
                grpc_headers,
                chunked_stream::collected_upstream(
                    body,
                    vec![("grpc-status".to_string(), "0".to_string())],
                ),
            );
        }
        // No tip yet (cold start, Redis down): upstream, below.
        health::record_cache_request(&network, "GetLatestBlock", "bypass");
    }

    if rpc == "GetMempoolStream" {
        debug!(
            request_id = %request_id,
            network = %network,
            hop = "ohttp",
            "GetMempoolStream joined the mempool fan-out"
        );
        served(200, "-", "lwd");
        return responder.stream(
            200,
            grpc_headers,
            log.stream("mempool", "-", state.mempool.subscribe()),
        );
    }

    let mut cache_miss = None;
    if let Some(cache) = state.cache.as_ref() {
        let content_type = inner_request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        match cache
            .lookup(
                &inner_request.method,
                content_type,
                &inner_request.path,
                &inner_request.headers,
                &inner_request.body,
                &state.cache_get_semaphore,
            )
            .await
        {
            cache::CacheLookup::Hit(bytes) => {
                match bincode::deserialize::<ohttp::InnerResponse>(&bytes) {
                    Ok(resp) => {
                        let grpc_status = resp.header("grpc-status").unwrap_or("-");
                        debug!(
                            request_id = %request_id,
                            path = %inner_request.path,
                            bytes_out = resp.body.len(),
                            network = %network,
                            hop = "ohttp",
                            "OHTTP request served from cache"
                        );
                        served(resp.status, grpc_status, "lwd");
                        log.served("cache_hit", grpc_status, resp.body.len());
                        return responder.collected(resp);
                    }
                    Err(e) => {
                        // A corrupt entry: answer from lightwalletd instead.
                        warn!(
                            request_id = %request_id,
                            path = %inner_request.path,
                            error = %e,
                            network = %network,
                            "Cache deserialization error"
                        );
                        health::record_upstream_error(&network, "cache", "deserialization");
                    }
                }
            }
            cache::CacheLookup::Miss(ticket) => cache_miss = Some(ticket),
            cache::CacheLookup::Bypass => {}
        }
    }

    // The cache's write path, run by the shared upstream call when the response ends cleanly.
    let on_complete: Option<singleflight::OnComplete> = match (state.cache.clone(), cache_miss) {
        (Some(cache), Some(ticket)) => {
            let path = inner_request.path.clone();
            Some(Box::new(move |resp: ohttp::InnerResponse| {
                tokio::spawn(async move {
                    match bincode::serialize(&resp) {
                        Ok(bytes) => cache.store(ticket, &bytes).await,
                        Err(e) => warn!(path, error = %e, "cache serialization error"),
                    }
                });
            }))
        }
        _ => None,
    };

    // SendTransaction is never coalesced; everything else shares identical calls in flight.
    let client_headers = lwd::client_grpc_headers(&inner_request.headers);
    let upstream = if rpc == "SendTransaction" {
        use singleflight::RpcSource;
        health::record_upstream_call(&network, &rpc);
        let started = Instant::now();
        let sent = state
            .sources
            .call_with_headers(
                inner_request.path.clone(),
                inner_request.body.clone(),
                Some(request_id),
                client_headers,
            )
            .await;
        if route_class == origin::RouteClass::Write {
            health::observe_write_stage(
                &network,
                "upstream_lwd",
                if sent.is_ok() { "ok" } else { "error" },
                started.elapsed(),
            );
        }
        sent
    } else {
        state
            .flights
            .call_with_headers(
                &rpc,
                &inner_request.path,
                inner_request.body.clone(),
                Some(request_id),
                client_headers,
                cache::MAX_CACHEABLE_SIZE,
                on_complete,
            )
            .await
    };
    let resp = match upstream {
        Ok(r) => r,
        Err(e) if e.to_string().contains(lwd::BUSY) => {
            warn!(request_id = %request_id, "lightwalletd concurrency limit reached");
            health::record_request_detailed(
                "lwd_busy",
                "ohttp",
                &network,
                "lwd",
                method_label,
                200,
                "14",
                "lwd",
                "lwd",
            );
            log.served("lwd_busy", "14", 0);
            return responder.grpc_error("14", "Service unavailable: too many concurrent requests");
        }
        Err(e) => {
            warn!(
                request_id = %request_id,
                path = %inner_request.path,
                error = %e,
                network = %network,
                "Lightwalletd error"
            );
            health::record_lwd_error();
            health::record_request_detailed(
                "lwd_error",
                "ohttp",
                &network,
                "lwd",
                method_label,
                200,
                "14",
                "lwd",
                "upstream",
            );
            health::record_upstream_error(&network, "lwd", "request_failed");
            log.served("lwd_error", "14", 0);
            return responder.grpc_error("14", "Service unavailable: lightwalletd call failed");
        }
    };

    let grpc_status = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("grpc-status"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("-")
        .to_string();
    debug!(
        request_id = %request_id,
        method = %inner_request.method,
        path = %log.path,
        authority = %inner_request.authority,
        http_status = resp.status,
        grpc_status = %grpc_status,
        duration_ms = start.elapsed().as_millis() as u64,
        network = %network,
        backend = &backend,
        hop = "ohttp",
        "OHTTP request streaming from lightwalletd"
    );
    served(resp.status, &grpc_status, "lwd");
    let body = chunked_stream::ensure_grpc_status(grpc_status != "-", resp.body);
    let body = log.stream("lwd_stream", &grpc_status, body);
    responder.stream(resp.status, resp.headers, body)
}

/// The replay admission of `gateway_handler` end to end: a sealed request in, the decrypted inner
/// response out, the upstream calls counted at mocks. In each mode one replay peer never answers,
/// so every WRITE could only run on one store's verdict: with `SendTransaction` on
/// `REPLAY_ONE_SIDED_WRITE_ROUTES`, a third-party WRITE is refused before anything goes upstream
/// and `SendTransaction` passes the replay checks to its upstream.
#[cfg(test)]
mod handler_tests {
    use super::*;
    use ::hpke::{
        aead::AesGcm128, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem, OpModeS,
        Serializable,
    };
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use rand_core::TryRngCore;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const SEND_TX: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/SendTransaction";
    /// A port nothing listens on: the replay peer never connects.
    const NO_PEER: &str = "redis://127.0.0.1:1";

    /// Whether the store at `url` answers (a bounded first connection). A missing store fails
    /// the test, unless `OHTTP_TEST_ALLOW_NO_STORE=1` outside CI (`store_policy`); with the
    /// failover topology on (`OHTTP_FAILOVER_REDIS`) always.
    async fn store_up(url: &str, what: &str) -> bool {
        use crate::store::test_support::{store_missing, STORE_CONNECT_TIMEOUT};
        let connect = async {
            let client = redis::Client::open(url)?;
            redis::aio::ConnectionManager::new(client).await
        };
        let error = match tokio::time::timeout(STORE_CONNECT_TIMEOUT, connect).await {
            Ok(Ok(_)) => return true,
            Ok(Err(e)) => e.to_string(),
            Err(_) => format!("no connection within {STORE_CONNECT_TIMEOUT:?}"),
        };
        if std::env::var("OHTTP_FAILOVER_REDIS").is_ok() {
            panic!("{what} ({url}) not reachable with OHTTP_FAILOVER_REDIS set: {error}");
        }
        store_missing(&format!("{what} ({url})"), &error);
        false
    }

    /// An upstream mock: the third-party one counts the requests it gets and answers `200 ok`,
    /// the lightwalletd one counts the connections and closes them.
    async fn upstream(answer: bool) -> (String, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        // BACKENDS takes a URL, LWD_ADDR a bare `host:port`.
        let addr = listener.local_addr().unwrap();
        let url = if answer {
            format!("http://{addr}")
        } else {
            addr.to_string()
        };
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                if !answer {
                    // lightwalletd: counted per connection, closed at once.
                    h.fetch_add(1, Ordering::SeqCst);
                    continue;
                }
                // The third-party backend (h2c or HTTP/1.1): counted per request, `200 ok`.
                let h = h.clone();
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(
                        move |_req: hyper::Request<hyper::body::Incoming>| {
                            h.fetch_add(1, Ordering::SeqCst);
                            async move {
                                Ok::<_, std::convert::Infallible>(hyper::Response::new(
                                    http_body_util::Full::new(bytes::Bytes::from_static(b"ok")),
                                ))
                            }
                        },
                    );
                    let _ = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(hyper_util::rt::TokioIo::new(sock), service)
                    .await;
                });
            }
        });
        (url, hits)
    }

    fn config(network: &str, security: &str, lwd: &str, third_party: &str) -> Config {
        let mut backends = HashMap::new();
        backends.insert("api.example.com".to_string(), third_party.to_string());
        Config {
            port: 0,
            lwd_addr: lwd.to_string(),
            mode: "ohttp".to_string(),
            relay_secrets: vec![],
            hpke_private_key: None,
            hpke_key_id: 1,
            hpke_keys: vec![(1, format!("{:064x}", 0xa1u64))],
            lwd_timeout_secs: 2,
            long_poll_max_initial_silence_secs: 25,
            long_poll_idle_secs: 3,
            sse_keepalive_secs: 20,
            redis_url: "redis://127.0.0.1:6379/0".to_string(),
            redis_security_url: security.to_string(),
            backends,
            backend_headers: HashMap::new(),
            backends_policy: HashMap::new(),
            backends_policy_default_allow: true,
            max_upstream_response_bytes: 64 * 1024 * 1024,
            max_inflight_upstream: 256,
            max_inflight_per_backend: 64,
            max_inflight_lwd: 128,
            max_inflight_lwd_heavy: 32,
            lwd_heavy_block_range: 100,
            max_block_range: 1000,
            lwd_permit_wait_ms: 2000,
            lwd_permit_max_waiters: 0,
            redis_op_timeout_ms: 1000,
            max_cache_get_concurrency: 64,
            max_large_response_concurrency: 2,
            large_response_threshold: 8 * 1024 * 1024,
            allow_unauthenticated_relay: true,
            proxy_allow_suffixes: vec![],
            network: network.to_string(),
            log_outer_header_names: false,
            gateway_hosts: vec!["lwd.example.com".to_string()],
            configs_signing_seed: None,
            chunk_size: 16384,
            chunk_flush_ms: 50,
            flexa_publishable_key: None,
            flexa_alias: None,
            near_alias: None,
            dynamic_hosts: Default::default(),
            host_list: Default::default(),
            third_party_query_rules: Default::default(),
            relay_secret_on_key_config: config::RelaySecretOnKeyConfig::Off,
        }
    }

    fn varint(n: usize, out: &mut Vec<u8>) {
        if n < 64 {
            out.push(n as u8);
        } else {
            out.extend_from_slice(&[0x40 | (n >> 8) as u8, n as u8]);
        }
    }

    fn read_varint(bytes: &[u8]) -> (u64, &[u8]) {
        let first = bytes[0];
        let len = 1usize << (first >> 6);
        let mut value = u64::from(first & 0x3f);
        for b in &bytes[1..len] {
            value = (value << 8) | u64::from(*b);
        }
        (value, &bytes[len..])
    }

    /// A known-length Binary HTTP request (RFC 9292 §3.1).
    fn bhttp(method: &str, authority: &str, path: &str, ct: &str, body: &[u8]) -> Vec<u8> {
        let mut m = vec![0];
        for field in [method, "https", authority, path] {
            varint(field.len(), &mut m);
            m.extend_from_slice(field.as_bytes());
        }
        let mut header = Vec::new();
        varint("content-type".len(), &mut header);
        header.extend_from_slice(b"content-type");
        varint(ct.len(), &mut header);
        header.extend_from_slice(ct.as_bytes());
        varint(header.len(), &mut m);
        m.extend_from_slice(&header);
        varint(body.len(), &mut m);
        m.extend_from_slice(body);
        m.push(0);
        m
    }

    /// The client half of a chunked OHTTP request (one chunk, then the final one), and what
    /// opening the response needs (`enc`, the exported secret).
    fn seal(key_config: &[u8], request: &[u8]) -> (Vec<u8>, Vec<u8>, [u8; hpke::N_K]) {
        let key_id = key_config[2];
        let mut hdr = vec![key_id];
        hdr.extend_from_slice(&0x0020u16.to_be_bytes());
        hdr.extend_from_slice(&0x0001u16.to_be_bytes());
        hdr.extend_from_slice(&0x0001u16.to_be_bytes());
        let mut info = b"message/bhttp chunked request".to_vec();
        info.push(0);
        info.extend_from_slice(&hdr);
        let pk = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&key_config[5..37]).unwrap();
        let mut rng = rand_core::OsRng.unwrap_err();
        let (enc, mut ctx) = ::hpke::setup_sender::<AesGcm128, HkdfSha256, X25519HkdfSha256, _>(
            &OpModeS::Base,
            &pk,
            &info,
            &mut rng,
        )
        .unwrap();
        let sealed = ctx.seal(request, b"").unwrap();
        let fin = ctx.seal(&[], b"final").unwrap();
        let mut out = hdr;
        out.extend_from_slice(&enc.to_bytes());
        varint(sealed.len(), &mut out);
        out.extend_from_slice(&sealed);
        out.push(0);
        out.extend_from_slice(&fin);
        let mut secret = [0u8; hpke::N_K];
        ctx.export(b"message/bhttp chunked response", &mut secret)
            .unwrap();
        (out, enc.to_bytes().to_vec(), secret)
    }

    /// The inner response: (status, every header and trailer as `name: value`, body).
    fn open(enc: &[u8], secret: &[u8], wire: &[u8]) -> (u64, String, Vec<u8>) {
        let (response_nonce, mut rest) = wire.split_at(hpke::N_N.max(hpke::N_K));
        let mut salt = enc.to_vec();
        salt.extend_from_slice(response_nonce);
        let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), secret);
        let mut key = [0u8; hpke::N_K];
        hkdf.expand(b"key", &mut key).unwrap();
        let mut base_nonce = [0u8; hpke::N_N];
        hkdf.expand(b"nonce", &mut base_nonce).unwrap();
        let cipher = aes_gcm::Aes128Gcm::new_from_slice(&key).unwrap();
        let mut plain = Vec::new();
        let mut counter = 0u64;
        loop {
            let (len, tail) = read_varint(rest);
            let (sealed, aad, tail) = if len == 0 {
                (tail, &b"final"[..], &[][..])
            } else {
                let (s, t) = tail.split_at(len as usize);
                (s, &b""[..], t)
            };
            let chunk = cipher
                .decrypt(
                    aes_gcm::Nonce::from_slice(&chunked_stream::chunk_nonce(&base_nonce, counter)),
                    Payload { msg: sealed, aad },
                )
                .expect("the response opens under the client's keys");
            counter += 1;
            plain.extend_from_slice(&chunk);
            rest = tail;
            if len == 0 {
                break;
            }
        }
        // Binary HTTP response, known-length (1) or indeterminate-length (3) framing.
        let (framing, rest) = read_varint(&plain);
        let (status, mut rest) = read_varint(rest);
        let mut fields = String::new();
        let mut body = Vec::new();
        fn field_section(rest: &mut &[u8], sized: bool, out: &mut String) {
            let all: &[u8] = *rest;
            let mut section: &[u8] = if sized {
                let (n, tail) = read_varint(all);
                let (sec, tail) = tail.split_at(n as usize);
                *rest = tail;
                sec
            } else {
                all
            };
            loop {
                if section.is_empty() {
                    break;
                }
                let (n, tail) = read_varint(section);
                if n == 0 {
                    section = tail;
                    break;
                }
                let (name, tail) = tail.split_at(n as usize);
                let (v, tail) = read_varint(tail);
                let (value, tail) = tail.split_at(v as usize);
                out.push_str(&format!(
                    "{}: {}\n",
                    String::from_utf8_lossy(name),
                    String::from_utf8_lossy(value)
                ));
                section = tail;
            }
            if !sized {
                *rest = section;
            }
        }
        if framing == 1 {
            field_section(&mut rest, true, &mut fields);
            let (n, tail) = read_varint(rest);
            body.extend_from_slice(&tail[..n as usize]);
            rest = &tail[n as usize..];
            if !rest.is_empty() {
                field_section(&mut rest, true, &mut fields);
            }
        } else {
            field_section(&mut rest, false, &mut fields);
            loop {
                let (n, tail) = read_varint(rest);
                rest = tail;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&rest[..n as usize]);
                rest = &rest[n as usize..];
            }
            field_section(&mut rest, false, &mut fields);
        }
        (status, fields, body)
    }

    fn counter(name: &str, labels: &[(&str, &str)]) -> f64 {
        health::REGISTRY
            .gather()
            .iter()
            .filter(|f| f.get_name() == name)
            .flat_map(|f| f.get_metric().iter())
            .filter(|m| {
                labels.iter().all(|(n, v)| {
                    m.get_label()
                        .iter()
                        .any(|l| l.get_name() == *n && l.get_value() == *v)
                })
            })
            .map(|m| m.get_counter().get_value())
            .sum()
    }

    /// Send `inner` through `gateway_handler`; the decrypted inner response.
    async fn post(state: &Arc<AppState>, inner: Vec<u8>) -> (u64, String, Vec<u8>) {
        let key_config = state.hpke.as_ref().unwrap().public_config();
        let (sealed, enc, secret) = seal(&key_config, &inner);
        let (status, wire) = post_sealed(state, sealed).await;
        assert_eq!(status, StatusCode::OK, "an encapsulated answer");
        open(&enc, &secret, &wire)
    }

    /// Send one encapsulated request as it is (the same bytes twice = a replay).
    async fn post_sealed(state: &Arc<AppState>, sealed: Vec<u8>) -> (StatusCode, Vec<u8>) {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "content-type",
            ohttp_chunked::CONTENT_TYPE_CHUNKED_REQ.parse().unwrap(),
        );
        let response = gateway_handler(
            State(state.clone()),
            axum::extract::ConnectInfo("127.0.0.1:9".parse().unwrap()),
            headers,
            Body::from(sealed),
        )
        .await
        .into_response();
        let status = response.status();
        let wire = axum::body::to_bytes(response.into_body(), 1 << 24)
            .await
            .unwrap();
        (status, wire.to_vec())
    }

    fn app_state(
        config: Config,
        origin: origin::OriginSettings,
        cache: cache::ResponseCache,
    ) -> Arc<AppState> {
        let lwd_semaphore = Arc::new(Semaphore::new(config.max_inflight_lwd));
        let sources = Arc::new(lwd::LwdSources::new(config.clone(), lwd_semaphore.clone()));
        let network = config.network.clone();
        Arc::new(AppState {
            hpke: Some(hpke::KeyState::new(&config).unwrap()),
            origin,
            cache: Some(cache),
            block_cache: None,
            subtree_cache: None,
            follower: None,
            mempool: Arc::new(mempool::MempoolFanout::new(
                sources.clone(),
                network.clone(),
            )),
            flights: Arc::new(singleflight::RpcFlights::new(sources.clone(), network)),
            sources,
            signing: None,
            global_semaphore: Arc::new(Semaphore::new(config.max_inflight_upstream)),
            per_backend_semaphores: Arc::new(RwLock::new(HashMap::new())),
            lwd_semaphore,
            cache_get_semaphore: Arc::new(Semaphore::new(config.max_cache_get_concurrency)),
            large_response_semaphore: Arc::new(Semaphore::new(
                config.max_large_response_concurrency,
            )),
            third_party: third_party_cache::ThirdParty::from_env(None, None).unwrap(),
            request_semaphore: Arc::new(Semaphore::new(16)),
            config,
        })
    }

    /// The two requests of every case: the third-party WRITE refused (path `refused_path`,
    /// nothing upstream), `SendTransaction` admitted to its upstream.
    async fn check_case(
        state: Arc<AppState>,
        refused_path: &[&str],
        third_party: Arc<AtomicUsize>,
        lwd: Arc<AtomicUsize>,
    ) {
        let network = state.config.network.clone();
        let refused = |paths: &[&str]| -> f64 {
            paths
                .iter()
                .map(|p| {
                    counter(
                        "ohttp_replay_write_fallback_total",
                        &[
                            ("network", &network),
                            ("path", p),
                            ("result", "one_sided_refused"),
                        ],
                    )
                })
                .sum()
        };
        let nonce = Uuid::new_v4().to_string();
        let (status, _, body) = post(
            &state,
            bhttp(
                "POST",
                "api.example.com",
                "/v1/send",
                "application/json",
                format!("{{\"n\":\"{nonce}\"}}").as_bytes(),
            ),
        )
        .await;
        // Refused in the peer stage ("replay protection unavailable") or, in failover mode, by
        // the check of every WRITE after the local replica wait ("not acknowledged").
        let text = String::from_utf8_lossy(&body);
        assert_eq!(status, 503, "{text}");
        assert!(text.starts_with("Service unavailable"), "{text}");
        assert_eq!(refused(refused_path), 1.0);
        assert_eq!(
            third_party.load(Ordering::SeqCst),
            0,
            "nothing sent upstream"
        );

        // RawTransaction { data: <bytes> } in one gRPC frame.
        let mut raw = vec![0x0a, nonce.len() as u8];
        raw.extend_from_slice(nonce.as_bytes());
        let mut grpc = vec![0u8, 0, 0, 0, raw.len() as u8];
        grpc.extend_from_slice(&raw);
        let (_, fields, body) = post(
            &state,
            bhttp(
                "POST",
                "lwd.example.com",
                SEND_TX,
                "application/grpc",
                &grpc,
            ),
        )
        .await;
        let answer = format!("{fields}{}", String::from_utf8_lossy(&body));
        assert!(
            !answer.contains("replay protection unavailable"),
            "SendTransaction passed the replay checks: {answer}"
        );
        assert_eq!(refused(refused_path), 1.0);
        assert!(
            lwd.load(Ordering::SeqCst) >= 1,
            "SendTransaction went upstream: {answer}"
        );
    }

    fn origin_env(mode: &str, fail_closed: bool) -> origin::OriginSettings {
        let routes = format!("lwd=POST {SEND_TX}");
        origin::OriginSettings::parse_env(origin::RawOriginEnv {
            peer_urls: Some(NO_PEER),
            peer_mode: Some(mode),
            peer_fail_closed: Some("0"),
            peer_fail_closed_writes: Some(if fail_closed { "1" } else { "0" }),
            one_sided_write_routes: Some(&routes),
            ..origin::RawOriginEnv::default()
        })
        .unwrap()
    }

    /// The peer replica wait of the handler tests that need one (REPLAY_PEER_WAIT_REPLICAS=1,
    /// the default), set here instead of read from the process environment.
    const PEER_WAIT: Option<cache::WriteWaitConfig> = Some(cache::WriteWaitConfig {
        replicas: 1,
        timeout_ms: 100,
    });

    async fn base_cache(
        config: &Config,
        origin: &origin::OriginSettings,
        peer_wait: Option<cache::WriteWaitConfig>,
    ) -> cache::ResponseCache {
        let peers = cache::ReplayPeers::connect(
            &origin.replay_peer_urls,
            config.network.clone(),
            origin.replay_peer_timeout_ms,
            origin.replay_peer_fail_closed,
        )
        .await
        .with_mode(
            origin.replay_peer_mode,
            origin.replay_peer_fail_closed_writes,
        )
        .with_wait(peer_wait);
        cache::ResponseCache::connect(
            &config.redis_url,
            Some(&config.redis_security_url),
            config.network.clone(),
            "lwd.example.com".to_string(),
            config.redis_op_timeout_ms,
            config.max_block_range,
            &config.backends_policy,
        )
        .await
        .unwrap()
        .with_replay_peers(peers)
    }

    /// `sync` mode, `REPLAY_PEER_FAIL_CLOSED=0`.
    #[tokio::test]
    async fn sync_mode_refuses_an_unlisted_one_sided_write_and_admits_a_listed_one() {
        if !store_up("redis://127.0.0.1:6379", "the test Redis").await {
            return;
        }
        health::init_metrics();
        let (tp, tp_hits) = upstream(true).await;
        let (lwd, lwd_hits) = upstream(false).await;
        let config = config(
            "testnet-handler-sync",
            "redis://127.0.0.1:6379/1",
            &lwd,
            &tp,
        );
        let origin = origin_env("sync", true);
        let cache = base_cache(&config, &origin, PEER_WAIT).await;
        check_case(
            app_state(config, origin, cache),
            &["peer_tolerated"],
            tp_hits,
            lwd_hits,
        )
        .await;
    }

    /// The third-party host list (THIRD_PARTY_HOSTS_PUBLISH) through the OHTTP handler: answered
    /// by the gateway itself after the replay check, not subject to the gateway host's own
    /// policy, never forwarded; any other method on the path, and the path while publishing is
    /// off, is an ordinary request to the gateway host.
    #[tokio::test]
    async fn the_host_list_is_answered_inside_ohttp_after_the_replay_check() {
        if !store_up("redis://127.0.0.1:6379", "the test Redis").await {
            return;
        }
        health::init_metrics();
        let (tp, tp_hits) = upstream(true).await;
        let (lwd, lwd_hits) = upstream(false).await;
        let mut config = config(
            "testnet-handler-hostlist",
            "redis://127.0.0.1:6379/1",
            &lwd,
            &tp,
        );
        config.host_list = host_list::HostListSettings {
            mode: host_list::PublishMode::All,
            max_age_secs: 300,
        };
        // The gateway host admits lightwalletd RPCs only: as a lightwalletd route the list's
        // path would be refused.
        config.backends_policy.insert(
            "lwd.example.com".to_string(),
            vec![(
                "POST".to_string(),
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/*".to_string(),
            )],
        );
        let origin = origin_env("sync", true);
        let cache = base_cache(&config, &origin, PEER_WAIT).await;
        let state = app_state(config.clone(), origin.clone(), cache);
        let list = |method: &str| {
            bhttp(
                method,
                "lwd.example.com",
                host_list::HOST_LIST_PATH,
                "application/json",
                b"",
            )
        };

        let key_config = state.hpke.as_ref().unwrap().public_config();
        let (sealed, enc, secret) = seal(&key_config, &list("GET"));
        let (status, wire) = post_sealed(&state, sealed.clone()).await;
        assert_eq!(status, StatusCode::OK);
        let (inner_status, fields, body) = open(&enc, &secret, &wire);
        assert_eq!(inner_status, 200, "{}", String::from_utf8_lossy(&body));
        let json: serde_json::Value = serde_json::from_slice(&body).expect("the host list");
        assert_eq!(json["version"], 1);
        assert_eq!(json["scope"], "all");
        assert_eq!(json["hosts"][0]["host"], "api.example.com");
        assert_eq!(json["hosts"][0]["routes"][0], "* /*");
        assert!(fields.to_ascii_lowercase().contains("etag"), "{fields}");
        assert!(
            !String::from_utf8_lossy(&body).contains("127.0.0.1"),
            "no alias target in the list"
        );
        // It passed the replay check like any inner request: the same bytes again are refused.
        let (status, _) = post_sealed(&state, sealed).await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "the same request again is a replay"
        );

        // Another method on the path is not the list: the gateway host's policy refuses it.
        let (inner_status, _, body) = post(&state, list("POST")).await;
        assert_eq!(inner_status, 403, "{}", String::from_utf8_lossy(&body));
        assert_eq!(body, b"policy denied");

        // Publishing off (the default): the path is an ordinary path of the gateway host.
        let mut off = config;
        off.network = "testnet-handler-hostlist-off".to_string();
        off.host_list = host_list::HostListSettings::default();
        let cache = base_cache(&off, &origin, PEER_WAIT).await;
        let state = app_state(off, origin, cache);
        let (inner_status, _, body) = post(&state, list("GET")).await;
        assert_eq!(inner_status, 403, "{}", String::from_utf8_lossy(&body));
        assert_eq!(body, b"policy denied");

        assert_eq!(tp_hits.load(Ordering::SeqCst), 0, "nothing forwarded");
        assert_eq!(lwd_hits.load(Ordering::SeqCst), 0, "nothing forwarded");
    }

    /// A recording third-party backend: the path and query of every request it gets; it
    /// answers `/v1/fiat/map` with a list document (`USD`, `EUR`) and anything else `200 ok`.
    async fn quotes_backend() -> (String, Arc<parking_lot::Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(parking_lot::Mutex::new(Vec::<String>::new()));
        let recorded = seen.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let recorded = recorded.clone();
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(
                        move |req: hyper::Request<hyper::body::Incoming>| {
                            let path = req
                                .uri()
                                .path_and_query()
                                .map(|pq| pq.as_str().to_string())
                                .unwrap_or_default();
                            let body: &'static [u8] = if path == "/v1/fiat/map" {
                                br#"{"data":[{"symbol":"USD"},{"symbol":"EUR"}]}"#
                            } else {
                                b"ok"
                            };
                            recorded.lock().push(path);
                            async move {
                                Ok::<_, std::convert::Infallible>(hyper::Response::new(
                                    http_body_util::Full::new(bytes::Bytes::from_static(body)),
                                ))
                            }
                        },
                    );
                    let _ = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(hyper_util::rt::TokioIo::new(sock), service)
                    .await;
                });
            }
        });
        (backend, seen)
    }

    /// A handler state whose alias `quotes.example` (to `backend`) allows `GET` on `paths`,
    /// with `rules`, `THIRD_PARTY_CACHE_ROUTES` on `GET /v1/quotes` and a cap of one upstream
    /// call per hour.
    async fn quotes_state(
        network: &str,
        backend: &str,
        paths: &[&str],
        rules: query_rules::QueryRules,
    ) -> Arc<AppState> {
        let (lwd, _) = upstream(false).await;
        let mut config = config(network, "redis://127.0.0.1:6379/3", &lwd, backend);
        // An alias no other handler test uses: the variables set below are process-wide.
        config
            .backends
            .insert("quotes.example".to_string(), backend.to_string());
        config.backends_policy_default_allow = false;
        config.backends_policy.insert(
            "quotes.example".to_string(),
            paths
                .iter()
                .map(|p| ("GET".to_string(), p.to_string()))
                .collect(),
        );
        config.third_party_query_rules = rules;
        config
            .third_party_query_rules
            .validate(&config.backends, &config.backends_policy)
            .unwrap();
        let origin = origin::OriginSettings::default();
        let cache = base_cache(&config, &origin, None).await;
        // ThirdParty::from_env (in app_state) reads both variables; nothing awaits here.
        let _env = config::test_env_lock();
        std::env::set_var(
            "THIRD_PARTY_CACHE_ROUTES",
            "quotes.example=GET /v1/quotes@300",
        );
        std::env::set_var("THIRD_PARTY_RATE_LIMITS", "quotes.example=1/3600s");
        let state = app_state(config, origin, cache);
        std::env::remove_var("THIRD_PARTY_CACHE_ROUTES");
        std::env::remove_var("THIRD_PARTY_RATE_LIMITS");
        state
    }

    /// `ohttp_third_party_cache_total` (hits + misses) and `ohttp_third_party_limited_total` of
    /// `quotes.example` on `network`.
    fn quotes_counters(network: &str) -> (f64, f64, f64) {
        let lookups = |result: &str| {
            counter(
                "ohttp_third_party_cache_total",
                &[
                    ("network", network),
                    ("authority", "quotes.example"),
                    ("result", result),
                ],
            )
        };
        let limited = counter(
            "ohttp_third_party_limited_total",
            &[("network", network), ("authority", "quotes.example")],
        );
        (lookups("hit"), lookups("miss"), limited)
    }

    /// `{from:}` through the OHTTP handler with the cache and a cap of one call: before the first
    /// fetch (no fallback) nothing is admitted; the list fetch itself neither uses the cache nor
    /// spends the cap; a value not in the list is refused before both; a value in it reaches the
    /// upstream and spends the cap.
    #[tokio::test]
    async fn a_value_source_list_is_checked_before_the_cache_and_the_cap() {
        if !store_up("redis://127.0.0.1:6379", "the test Redis").await {
            return;
        }
        health::init_metrics();
        let (backend, seen) = quotes_backend().await;
        let network = format!("testnet-handler-qsources-{}", Uuid::new_v4().simple());
        let sources = query_value_sources::QueryValueSources::parse(
            "fiat=quotes.example GET /v1/fiat/map#/data/*/symbol@300",
        )
        .unwrap();
        let rules = query_rules::QueryRules::parse_with_sources(
            "quotes.example=GET /v1/quotes?convert={from:fiat}",
            sources.clone(),
        )
        .unwrap();
        let state = quotes_state(&network, &backend, &["/v1/quotes", "/v1/fiat/map"], rules).await;
        let get = |path: &str| bhttp("GET", "quotes.example", path, "application/json", b"");
        let denied =
            |(status, _, body): (u64, String, Vec<u8>)| status == 403 && body == b"policy denied";

        // Fail closed until the first accepted fetch.
        assert!(denied(post(&state, get("/v1/quotes?convert=USD")).await));
        assert!(seen.lock().is_empty());

        assert_eq!(
            sources.refresh(&state, "fiat").await,
            query_value_sources::Outcome::Ok
        );
        assert_eq!(*seen.lock(), vec!["/v1/fiat/map".to_string()]);
        assert_eq!(quotes_counters(&network), (0.0, 0.0, 0.0));

        for refused in ["JPY", "usd", "USD&x=1"] {
            let path = format!("/v1/quotes?convert={refused}");
            assert!(denied(post(&state, get(&path)).await), "{path}");
        }
        assert_eq!(quotes_counters(&network), (0.0, 0.0, 0.0));
        assert_eq!(seen.lock().len(), 1);

        // In the list: upstream once (a miss, the cap's one call), then the cache.
        let (status, _, body) = post(&state, get("/v1/quotes?convert=USD")).await;
        assert_eq!((status, body.as_slice()), (200, &b"ok"[..]));
        let (status, _, _) = post(&state, get("/v1/quotes?convert=USD")).await;
        assert_eq!(status, 200);
        assert_eq!(quotes_counters(&network), (1.0, 1.0, 0.0));
        // The other listed value is its own key; the cap is spent.
        let (status, _, _) = post(&state, get("/v1/quotes?convert=EUR")).await;
        assert_eq!(status, 429);
        assert_eq!(
            *seen.lock(),
            vec![
                "/v1/fiat/map".to_string(),
                "/v1/quotes?convert=USD".to_string()
            ]
        );
    }

    /// THIRD_PARTY_QUERY_RULES through the OHTTP handler, with a cached route and an upstream cap
    /// of one call: a refused query gets the inner 403 without reading or filling the cache and
    /// without spending the cap, so the allowed query after it still gets the upstream's 200 (a
    /// spent cap would answer 429), and the one after that is a cache hit.
    #[tokio::test]
    async fn a_refused_query_costs_no_cache_lookup_and_no_upstream_call() {
        if !store_up("redis://127.0.0.1:6379", "the test Redis").await {
            return;
        }
        health::init_metrics();
        let (backend, seen) = quotes_backend().await;
        // A network of its own: fresh cache keys and metric series on every run.
        let network = format!("testnet-handler-qrules-{}", Uuid::new_v4().simple());
        let rules =
            query_rules::QueryRules::parse("quotes.example=GET /v1/quotes?symbol={in:ZEC|BTC}")
                .unwrap();
        let state = quotes_state(&network, &backend, &["/v1/quotes"], rules).await;
        assert_eq!(state.third_party.summary(), (1, 1));
        let get = |path: &str| bhttp("GET", "quotes.example", path, "application/json", b"");
        let cache_lookups = |result: &str| {
            counter(
                "ohttp_third_party_cache_total",
                &[
                    ("network", &network),
                    ("authority", "quotes.example"),
                    ("result", result),
                ],
            )
        };
        let limited = || {
            counter(
                "ohttp_third_party_limited_total",
                &[("network", &network), ("authority", "quotes.example")],
            )
        };

        for path in [
            "/v1/quotes?symbol=ETH",
            "/v1/quotes?symbol=ZEC&x=1",
            "/v1/quotes?symbol=zec",
            "/v1/quotes",
            "/v1/quotes?symbol=ETH",
        ] {
            let (status, _, body) = post(&state, get(path)).await;
            assert_eq!(
                (status, body.as_slice()),
                (403, &b"policy denied"[..]),
                "{path}"
            );
        }
        assert_eq!(
            cache_lookups("hit") + cache_lookups("miss"),
            0.0,
            "no cache lookup"
        );
        assert_eq!(limited(), 0.0);
        assert!(seen.lock().is_empty(), "{:?}", seen.lock());

        // The cap's one call is still there: the allowed query goes upstream (a miss), then is
        // served from the cache.
        let (status, _, body) = post(&state, get("/v1/quotes?symbol=ZEC")).await;
        assert_eq!((status, body.as_slice()), (200, &b"ok"[..]));
        assert_eq!((cache_lookups("hit"), cache_lookups("miss")), (0.0, 1.0));
        let (status, _, body) = post(&state, get("/v1/quotes?symbol=ZEC")).await;
        assert_eq!((status, body.as_slice()), (200, &b"ok"[..]));
        assert_eq!((cache_lookups("hit"), cache_lookups("miss")), (1.0, 1.0));
        assert_eq!(*seen.lock(), vec!["/v1/quotes?symbol=ZEC".to_string()]);

        // Refused queries stay refused, with the cap now spent and an entry in the cache.
        let (status, _, body) = post(&state, get("/v1/quotes?symbol=ETH")).await;
        assert_eq!((status, body.as_slice()), (403, &b"policy denied"[..]));
        // The other admitted value is its own cache key; the spent cap answers it.
        let (status, _, _) = post(&state, get("/v1/quotes?symbol=BTC")).await;
        assert_eq!(status, 429);
        assert_eq!(limited(), 1.0);
        assert_eq!(seen.lock().len(), 1);
    }

    /// `async-reads`, `REPLAY_PEER_FAIL_CLOSED_WRITES=0` (an unreachable hub tolerated).
    #[tokio::test]
    async fn async_reads_refuses_an_unlisted_one_sided_write_and_admits_a_listed_one() {
        if !store_up("redis://127.0.0.1:6379", "the test Redis").await {
            return;
        }
        health::init_metrics();
        let (tp, tp_hits) = upstream(true).await;
        let (lwd, lwd_hits) = upstream(false).await;
        let config = config(
            "testnet-handler-async",
            "redis://127.0.0.1:6379/2",
            &lwd,
            &tp,
        );
        let origin = origin_env("async-reads", false);
        let cache = base_cache(&config, &origin, PEER_WAIT).await;
        check_case(
            app_state(config, origin, cache),
            &["peer_tolerated"],
            tp_hits,
            lwd_hits,
        )
        .await;
    }

    /// A fake peer store: `SET ... NX` / `XX` on a set of keys, `WAIT` acknowledged by one
    /// replica, anything else `+OK` (`PING`: `+PONG`). Whole RESP commands, pipelines included.
    async fn acking_store() -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let keys = Arc::new(std::sync::Mutex::new(
            std::collections::HashSet::<String>::new(),
        ));
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let keys = keys.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = vec![0u8; 8192];
                    loop {
                        let Ok(n) = sock.read(&mut chunk).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        while let Some((args, used)) = resp_command(&buf) {
                            buf.drain(..used);
                            let name = args.first().map(|a| a.to_ascii_uppercase());
                            let has =
                                |w: &str| args.iter().skip(3).any(|a| a.eq_ignore_ascii_case(w));
                            let reply: Vec<u8> = match name.as_deref() {
                                Some("PING") => b"+PONG\r\n".to_vec(),
                                Some("WAIT") => b":1\r\n".to_vec(),
                                Some("ROLE") => b"*3\r\n$6\r\nmaster\r\n:0\r\n*0\r\n".to_vec(),
                                Some("SET") if args.len() > 1 => {
                                    let mut k = keys.lock().unwrap();
                                    let key = args[1].clone();
                                    if has("NX") {
                                        if k.insert(key) {
                                            b"+OK\r\n".to_vec()
                                        } else {
                                            b"$-1\r\n".to_vec()
                                        }
                                    } else if has("XX") && !k.contains(&key) {
                                        b"$-1\r\n".to_vec()
                                    } else {
                                        k.insert(key);
                                        b"+OK\r\n".to_vec()
                                    }
                                }
                                Some("GET") => b"$-1\r\n".to_vec(),
                                _ => b"+OK\r\n".to_vec(),
                            };
                            if sock.write_all(&reply).await.is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        });
        format!("redis://{addr}")
    }

    /// One whole RESP command (an array of bulk strings) at the start of `buf`, and its length.
    fn resp_command(buf: &[u8]) -> Option<(Vec<String>, usize)> {
        let line = |at: usize| -> Option<(&[u8], usize)> {
            let p = buf.get(at..)?.windows(2).position(|w| w == b"\r\n")?;
            Some((&buf[at..at + p], at + p + 2))
        };
        let (head, mut at) = line(0)?;
        let count: usize = std::str::from_utf8(head.get(1..)?).ok()?.parse().ok()?;
        let mut args = Vec::with_capacity(count);
        for _ in 0..count {
            let (len, next) = line(at)?;
            let len: usize = std::str::from_utf8(len.get(1..)?).ok()?.parse().ok()?;
            let end = next + len;
            if buf.len() < end + 2 {
                return None;
            }
            args.push(String::from_utf8_lossy(&buf[next..end]).into_owned());
            at = end + 2;
        }
        Some((args, at))
    }

    /// `sync` mode with a reachable peer and REPLAY_PEER_FAIL_CLOSED=1: a WRITE that is not on
    /// REPLAY_ONE_SIDED_WRITE_ROUTES runs once both stores took its nonce (and, with the peer
    /// replica wait, the peer acknowledged it), and reaches its upstream exactly once (the same
    /// encapsulated request again is a replay).
    async fn strict_write_runs_once(
        network: &str,
        security: &str,
        peer: &str,
        peer_wait: Option<cache::WriteWaitConfig>,
    ) {
        health::init_metrics();
        let (tp, tp_hits) = upstream(true).await;
        let (lwd, _) = upstream(false).await;
        let config = config(network, security, &lwd, &tp);
        let origin = origin::OriginSettings::parse_env(origin::RawOriginEnv {
            peer_urls: Some(peer),
            // The test Redis is shared with tests that slow it down on purpose.
            peer_timeout_ms: Some("5000"),
            peer_mode: Some("sync"),
            peer_fail_closed: Some("1"),
            peer_fail_closed_writes: Some("1"),
            ..origin::RawOriginEnv::default()
        })
        .unwrap();
        let cache = base_cache(&config, &origin, peer_wait).await;
        if peer_wait.is_some() {
            // The peer WAIT connections open in the background.
            let peers = cache.replay_peers().unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while peers.wait_conns_open().iter().any(|n| *n == 0) {
                assert!(
                    std::time::Instant::now() < deadline,
                    "peer WAIT connections"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        let state = app_state(config, origin, cache);
        let nonce = Uuid::new_v4().to_string();
        let inner = bhttp(
            "POST",
            "api.example.com",
            "/v1/send",
            "application/json",
            format!("{{\"n\":\"{nonce}\"}}").as_bytes(),
        );
        let key_config = state.hpke.as_ref().unwrap().public_config();
        let (sealed, enc, secret) = seal(&key_config, &inner);
        let (status, wire) = post_sealed(&state, sealed.clone()).await;
        assert_eq!(status, StatusCode::OK);
        let (inner_status, _, body) = open(&enc, &secret, &wire);
        assert_eq!(inner_status, 200, "{}", String::from_utf8_lossy(&body));
        assert_eq!(body, b"ok");
        assert_eq!(tp_hits.load(Ordering::SeqCst), 1);
        let (status, _) = post_sealed(&state, sealed).await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "the same request again is a replay"
        );
        assert_eq!(
            tp_hits.load(Ordering::SeqCst),
            1,
            "upstream reached exactly once"
        );
    }

    /// Without the peer replica wait (the test Redis has no replica).
    #[tokio::test]
    async fn a_strict_write_with_both_stores_up_runs_once() {
        if !store_up("redis://127.0.0.1:6379", "the test Redis").await {
            return;
        }
        strict_write_runs_once(
            "testnet-handler-strict",
            "redis://127.0.0.1:6379/4",
            "redis://127.0.0.1:6379/5",
            None,
        )
        .await;
    }

    /// With the peer replica wait on, against a peer store that acknowledges.
    #[tokio::test]
    async fn a_strict_write_acknowledged_at_the_peer_runs_once() {
        if !store_up("redis://127.0.0.1:6379", "the test Redis").await {
            return;
        }
        let peer = acking_store().await;
        strict_write_runs_once(
            "testnet-handler-strict-wait",
            "redis://127.0.0.1:6379/6",
            &peer,
            PEER_WAIT,
        )
        .await;
    }

    /// `failover` mode with the peer fallback (the local replica wait on a primary with a
    /// replica: tests/failover/docker-compose.yml, `OHTTP_FAILOVER_REDIS=1`): the check of every
    /// WRITE at the peer gets no answer.
    #[tokio::test]
    async fn failover_mode_refuses_an_unlisted_one_sided_write_and_admits_a_listed_one() {
        if std::env::var("OHTTP_FAILOVER_REDIS").is_err() {
            eprintln!(
                "skipped: set OHTTP_FAILOVER_REDIS=1 with tests/failover/docker-compose.yml up"
            );
            return;
        }
        let security = "redis://127.0.0.1:6391/3";
        assert!(store_up(security, "the failover test primary").await);
        assert!(store_up("redis://127.0.0.1:6379", "the test Redis").await);
        health::init_metrics();
        let (tp, tp_hits) = upstream(true).await;
        let (lwd, lwd_hits) = upstream(false).await;
        let config = config("testnet-handler-failover", security, &lwd, &tp);
        let origin = origin_env("failover", true);
        let wait = cache::WriteWaitConfig {
            replicas: 1,
            timeout_ms: 500,
        };
        let cache = base_cache(&config, &origin, PEER_WAIT)
            .await
            .with_write_wait(security, wait)
            .await
            .unwrap();
        check_case(
            app_state(config, origin, cache),
            &["check", "window"],
            tp_hits,
            lwd_hits,
        )
        .await;
    }
}

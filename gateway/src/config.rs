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

// Configuration — Environment variables

use std::collections::HashMap;

/// One accepted `X-Relay-Secret` and the relay it belongs to.
///
/// Grammar of a `RELAY_SECRETS` (or `RELAY_SECRET`) entry, comma-separated list:
///
/// - `name=secret`: `name` is 1-32 bytes of `a-z0-9-` and names the relay in the metric
///   `ohttp_relay_requests_total{relay}` and the log field `relay`; `secret` is everything after
///   the first `=` and must contain a byte other than `=`.
/// - anything else is a bare secret (base64 padding such as `ag==` or `abcd=` is not a name, nor is
///   an upper-case or over-long prefix), named `relay-<position>` (1-based).
///
/// Names and secrets are both unique within the list; a duplicate is a configuration error, so
/// that a presented secret always attributes to exactly one relay.
#[derive(Clone)]
pub struct RelaySecret {
    pub name: String,
    pub secret: String,
    /// SHA-256 of `secret`, computed once at load; requests compare digests only.
    pub digest: [u8; 32],
}

/// The index of the entry of `secrets` equal to `presented`. The presented value is hashed once
/// and its SHA-256 digest is compared with every entry's precomputed digest (fixed length, no
/// early exit), so the time taken does not depend on which entry matched, on how far the presented
/// value agrees with any secret, or on the lengths of the configured secrets.
pub fn match_relay_secret(secrets: &[RelaySecret], presented: &[u8]) -> Option<usize> {
    use sha2::{Digest, Sha256};
    use subtle::{ConditionallySelectable, ConstantTimeEq};
    let presented = Sha256::digest(presented);
    let mut matched = subtle::Choice::from(0u8);
    let mut index = 0u32;
    for (i, expected) in secrets.iter().enumerate() {
        let eq = presented.as_slice().ct_eq(&expected.digest);
        index.conditional_assign(&(i as u32), eq);
        matched |= eq;
    }
    bool::from(matched).then_some(index as usize)
}

/// `RELAY_SECRET_ON_KEY_CONFIG`: whether `GET /ohttp-configs` and `GET /ohttp-configs/signed` need
/// a valid `X-Relay-Secret` like `POST /gateway`. The ZIP ("Relay authorisation") lets an operator
/// restrict the whole origin to authorised Relays; with `require` the Relays are the only way to
/// obtain the Key Configuration, so every Relay must forward both GETs with its secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelaySecretOnKeyConfig {
    /// Default: the Key Configuration is a public document, no credential needed.
    Off,
    /// One `X-Relay-Secret` matching a configured relay secret, otherwise 401.
    Require,
}

impl RelaySecretOnKeyConfig {
    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        match raw.trim() {
            "" | "off" => Ok(Self::Off),
            "require" => Ok(Self::Require),
            other => anyhow::bail!(
                "Invalid RELAY_SECRET_ON_KEY_CONFIG value '{}': must be 'off' or 'require'",
                other
            ),
        }
    }
}

/// The relay whose secret a request carries: exactly one `X-Relay-Secret` header, visible ASCII,
/// equal to one of `secrets` ([`match_relay_secret`]). `None` for a missing, duplicated, invalid or
/// unknown secret.
pub fn authenticated_relay(
    secrets: &[RelaySecret],
    headers: &axum::http::HeaderMap,
) -> Option<usize> {
    let mut values = headers.get_all("X-Relay-Secret").iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    match_relay_secret(secrets, value.to_str().ok()?.as_bytes())
}

/// `RELAY_SECRETS` as a list: every entry parsed with [`RelaySecret::parse`], no empty entries, no
/// duplicate names and no duplicate secrets. Errors name positions and relay names, never values.
pub fn parse_relay_secrets(raw: &str) -> anyhow::Result<Vec<RelaySecret>> {
    let mut secrets: Vec<RelaySecret> = Vec::new();
    for (i, entry) in raw.split(',').enumerate() {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            anyhow::bail!(
                "Malformed RELAY_SECRETS: empty secret at position {} (check for trailing commas)",
                i
            );
        }
        let parsed = RelaySecret::parse(i, trimmed);
        if let Some((j, previous)) = secrets
            .iter()
            .enumerate()
            .find(|(_, s)| s.name == parsed.name)
        {
            anyhow::bail!(
                "Malformed RELAY_SECRETS: relay name {:?} is used twice (entries {} and {}); every relay needs its own name",
                previous.name,
                j + 1,
                i + 1
            );
        }
        // Load time, not a request: plain equality of the digests is fine here.
        if let Some((j, previous)) = secrets
            .iter()
            .enumerate()
            .find(|(_, s)| s.digest == parsed.digest)
        {
            anyhow::bail!(
                "Malformed RELAY_SECRETS: entries {} ({:?}) and {} ({:?}) carry the same secret; a secret can belong to one relay only",
                j + 1,
                previous.name,
                i + 1,
                parsed.name
            );
        }
        secrets.push(parsed);
    }
    if secrets.is_empty() {
        anyhow::bail!("RELAY_SECRETS set but contains no valid secrets");
    }
    Ok(secrets)
}

impl RelaySecret {
    fn parse(index: usize, entry: &str) -> Self {
        match entry.split_once('=') {
            // A remainder made only of '=' is base64 padding of a bare secret (`ag==`), not a name.
            Some((name, secret))
                if secret.bytes().any(|b| b != b'=')
                    && (1..=32).contains(&name.len())
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') =>
            {
                Self::new(name.to_string(), secret.to_string())
            }
            _ => Self::new(format!("relay-{}", index + 1), entry.to_string()),
        }
    }

    fn new(name: String, secret: String) -> Self {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(secret.as_bytes()).into();
        RelaySecret {
            name,
            secret,
            digest,
        }
    }
}

#[derive(Clone)]
pub struct Config {
    pub port: u16,
    pub lwd_addr: String,
    pub mode: String,
    pub relay_secrets: Vec<RelaySecret>,
    /// Single HPKE key (legacy compat). Ignored when hpke_keys is set.
    pub hpke_private_key: Option<String>,
    pub hpke_key_id: u8,
    /// Multi-key HPKE configuration: Vec<(key_id, hex_private_key)>. Format: "0:hex1,1:hex2".
    /// If set, takes precedence over hpke_private_key.
    pub hpke_keys: Vec<(u8, String)>,
    /// Maximum wall-clock time for one forwarded lightwalletd call.
    pub lwd_timeout_secs: u64,
    /// Maximum silence before first message on long-poll streams (GetMempoolStream).
    /// Stream ends cleanly (grpc-status 0) if no message arrives within this time.
    /// GW-SILENCE: Default 25s to avoid relay between-bytes timeouts (30s at a typical relay).
    /// Validated at startup: values >25s are clamped to 25s with a warning.
    pub long_poll_max_initial_silence_secs: u64,
    /// Idle time after the first message on long-poll streams (GetMempoolStream).
    /// Stream ends cleanly (grpc-status 0) after this silence following a message.
    /// Default 3s keeps polls responsive while avoiding relay timeouts.
    pub long_poll_idle_secs: u64,
    /// SSE keep-alive interval: when a text/event-stream response is silent for this duration,
    /// the gateway emits a comment line (`: keep-alive\n\n`) to prevent relay timeouts.
    /// GW-SILENCE: Default 20s to stay under relay between-bytes timeouts (30s at a typical relay).
    /// Validated at startup: values >25s are clamped to 25s with a warning.
    pub sse_keepalive_secs: u64,
    /// Redis URL for response caching. If empty, caching is disabled.
    pub redis_url: String,
    /// Redis URL for security-critical operations (replay nonces, epoch state).
    /// Uses noeviction policy. Required in OHTTP mode together with redis_url (main.rs).
    pub redis_security_url: String,
    /// Multi-backend map: authority → backend base URL.
    /// Format: "api1.example.com=https://api-backend1.example,api2.example.com=https://api-backend2.example"
    /// Unknown authorities go to LWD only while GATEWAY_HOSTS is empty (see gateway_hosts).
    pub backends: HashMap<String, String>,
    /// Per-backend extra request headers to inject (e.g. API keys).
    /// Format: "api1.example.com=X-API-KEY:secret123,api3.example.com=Authorization:Bearer token"
    pub backend_headers: HashMap<String, Vec<(String, String)>>,
    /// Per-backend operation allowlist. Format: "api1.example.com=GET /v1/cryptocurrency/quotes/latest,GET /v1/key/info"
    /// If an alias has no policy and BACKENDS_POLICY_DEFAULT != "allow", all requests are denied.
    pub backends_policy: HashMap<String, Vec<(String, String)>>,
    pub backends_policy_default_allow: bool,
    /// Maximum upstream response size in bytes (default 64 MiB)
    pub max_upstream_response_bytes: usize,
    /// Maximum inflight upstream requests globally (default 256)
    pub max_inflight_upstream: usize,
    /// Maximum inflight upstream requests per backend (default 64)
    pub max_inflight_per_backend: usize,
    /// Maximum inflight upstream requests to own-LWD (default 128)
    pub max_inflight_lwd: usize,
    /// Of those, at most this many "heavy" calls at once (MAX_INFLIGHT_LWD_HEAVY, default a quarter
    /// of max_inflight_lwd): long GetBlockRange, GetTransaction, transparent-address and subtree
    /// queries. The rest of the permits stay free for SendTransaction, GetLatestBlock, GetTreeState
    /// and short ranges, so a flood of history scans gets UNAVAILABLE without starving them.
    pub max_inflight_lwd_heavy: usize,
    /// GetBlockRange spans above this many blocks count as heavy (LWD_HEAVY_BLOCK_RANGE, default 100).
    pub lwd_heavy_block_range: u32,
    /// Maximum GetBlockRange span (default 10000)
    pub max_block_range: u32,
    /// How long a lightwalletd call waits for a permit before rejection (LWD_PERMIT_WAIT_MS, default 2000). 0 = immediate rejection
    pub lwd_permit_wait_ms: u64,
    /// Maximum calls waiting for a lightwalletd permit at once (LWD_PERMIT_MAX_WAITERS, default 0 = 4x the permit count of each semaphore). Above it, calls are rejected immediately. An explicit value overrides the per-class default for both classes
    pub lwd_permit_max_waiters: usize,
    /// Redis operation timeout in milliseconds (default 250)
    pub redis_op_timeout_ms: u64,
    /// Maximum concurrent cache GET operations (default 64)
    pub max_cache_get_concurrency: usize,
    /// Maximum concurrent large responses (> large_response_threshold, default 1)
    pub max_large_response_concurrency: usize,
    /// Large response threshold in bytes (default 8 MiB)
    pub large_response_threshold: usize,
    /// Allow unauthenticated relay connections (INSECURE, default false)
    pub allow_unauthenticated_relay: bool,
    /// `PROXY_ALLOW_SUFFIXES` (comma-separated, lowercase), parsed but not used for routing:
    /// `proxy::resolve_backend` forwards only exact `BACKENDS` aliases and `GATEWAY_HOSTS`
    /// (suffix routing was removed as an SSRF surface; `matches_allowed_suffix` is test-only).
    #[allow(dead_code)]
    pub proxy_allow_suffixes: Vec<String>,
    /// Network identifier for observability (mainnet or testnet)
    pub network: String,
    /// Privacy audit aid: when true, the gateway logs the NAMES (never values) of the outer HTTP
    /// headers it receives from the relay on every request. Off by default.
    pub log_outer_header_names: bool,
    /// Gateway's own host names (e.g., "ohttp-gateway.example,ohttp-gateway-testnet.example").
    /// Requests whose authority matches one of these hosts are forwarded to LWD (an empty
    /// authority is refused).
    /// Required in ohttp mode: the gateway refuses to start without it. Routing still treats an
    /// empty list as permissive (any unknown authority goes to LWD), which only a `Config` built
    /// in code (tests, proxy mode) can reach.
    pub gateway_hosts: Vec<String>,
    /// Ed25519 seed for signing /ohttp-configs/signed (32-byte hex, 64 chars)
    pub configs_signing_seed: Option<String>,
    /// Chunked OHTTP response chunk size in bytes (default 16384, 1024..=65536)
    pub chunk_size: usize,
    /// Chunked OHTTP response flush interval in milliseconds (default 50)
    pub chunk_flush_ms: u64,
    /// Flexa publishable key swapped in for the apps' placeholder credential
    /// (`zodl_ohttp_integrations::flexa`).
    pub flexa_publishable_key: Option<String>,
    /// `FLEXA_ALIAS`: the `BACKENDS` alias (inner authority) of the Flexa API, lowercase. Requests
    /// to it get the Flexa header handling of `zodl_ohttp_integrations::flexa` and are never
    /// cached. `None` (unset or empty) = no alias is treated as Flexa.
    pub flexa_alias: Option<String>,
    /// `NEAR_ALIAS`: the `BACKENDS` alias of the NEAR Intents 1Click API, lowercase
    /// (`zodl_ohttp_integrations::near`). Only its public `GET /v0/tokens` may be listed in
    /// `THIRD_PARTY_CACHE_ROUTES` (its other routes carry per-deposit state). `None` (unset or
    /// empty) = no such restriction.
    pub near_alias: Option<String>,
    /// `RELAY_SECRET_ON_KEY_CONFIG` (default `off`).
    pub relay_secret_on_key_config: RelaySecretOnKeyConfig,
    /// `DYNAMIC_HOST_SOURCES`: third-party hosts read from published documents and refreshed
    /// while the gateway runs (`dynamic_hosts.rs`). A handle: clones of the configuration share
    /// one served set. Default: no source, no host.
    pub dynamic_hosts: crate::dynamic_hosts::DynamicHosts,
    /// `THIRD_PARTY_HOSTS_PUBLISH` / `THIRD_PARTY_HOSTS_MAX_AGE_SECS`: the host list published
    /// to wallets (`host_list.rs`). Default: off.
    pub host_list: crate::host_list::HostListSettings,
    /// `THIRD_PARTY_QUERY_RULES`: per-route query string allowlists of `BACKENDS` aliases
    /// (`query_rules.rs`), checked with `BACKENDS_POLICY`. Default: no rule.
    pub third_party_query_rules: crate::query_rules::QueryRules,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let mode =
            crate::config_source::var("GATEWAY_MODE").unwrap_or_else(|_| "ohttp".to_string());
        // Network detection: use NETWORK env var if set, otherwise derive from mode if it's
        // "mainnet" or "testnet", otherwise default to "mainnet"
        let network = crate::config_source::var("NETWORK")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                if mode == "mainnet" || mode == "testnet" {
                    Some(mode.clone())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "mainnet".to_string());

        let gateway_hosts: Vec<String> = crate::config_source::var("GATEWAY_HOSTS")
            .unwrap_or_default()
            .split(',')
            .map(|s| {
                // Normalize: lowercase, strip port
                s.trim()
                    .to_ascii_lowercase()
                    .split(':')
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
            .filter(|s| !s.is_empty())
            .collect();

        // Parse relay secrets (comma-separated for rotation support)
        // Error if both RELAY_SECRET and RELAY_SECRETS are set, instead of letting one silently shadow the other.
        let relay_secret_set = crate::config_source::var("RELAY_SECRET").is_ok();
        let relay_secrets_set = crate::config_source::var("RELAY_SECRETS").is_ok();

        if relay_secret_set && relay_secrets_set {
            anyhow::bail!(
                "Both RELAY_SECRET and RELAY_SECRETS are set. Use only one. \
                 For rotation, use comma-separated values: RELAY_SECRET=old,new"
            );
        }

        let relay_secrets_raw = crate::config_source::var("RELAY_SECRET")
            .or_else(|_| crate::config_source::var("RELAY_SECRETS"))
            .ok()
            .filter(|s| !s.is_empty());

        let relay_secrets: Vec<RelaySecret> = match relay_secrets_raw {
            Some(raw) => parse_relay_secrets(&raw)?,
            None => Vec::new(),
        };

        let allow_unauthenticated = crate::config_source::var("ALLOW_UNAUTHENTICATED_RELAY")
            .map(|v| flag_on(&v))
            .unwrap_or(false);

        // Parse HPKE_KEYS: "key_id:hex_private_key,key_id:hex_private_key,..."
        // Strict parsing: reject malformed entries with a clear error instead of silently ignoring them.
        let hpke_keys: Vec<(u8, String)> = match crate::config_source::var("HPKE_KEYS")
            .ok()
            .filter(|s| !s.is_empty())
        {
            Some(raw) => parse_hpke_keys("HPKE_KEYS", &raw)?,
            None => Vec::new(),
        };

        // Parse backends policy with strict validation
        let backends_policy = zodl_ohttp_integrations::core::policy::parse_backends_policy(
            &crate::config_source::var("BACKENDS_POLICY").unwrap_or_default(),
        )?;

        let backends_policy_default_allow = crate::config_source::var("BACKENDS_POLICY_DEFAULT")
            .map(|v| v.eq_ignore_ascii_case("allow"))
            .unwrap_or(false);

        let config = Self {
            port: crate::config_source::var("PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()?,
            lwd_addr: crate::config_source::var("LWD_ADDR")
                .unwrap_or_else(|_| "localhost:9067".to_string()),
            mode,
            relay_secrets,
            allow_unauthenticated_relay: allow_unauthenticated,
            hpke_private_key: crate::config_source::var("HPKE_PRIVATE_KEY")
                .ok()
                .filter(|s| !s.is_empty()),
            hpke_key_id: crate::config_source::var("HPKE_KEY_ID")
                .unwrap_or_else(|_| "1".to_string())
                .parse()?,
            hpke_keys,
            lwd_timeout_secs: crate::config_source::var("LWD_TIMEOUT_SECS")
                .unwrap_or_else(|_| "80".to_string())
                .parse()?,
            long_poll_max_initial_silence_secs: {
                let raw: u64 = crate::config_source::var("LONG_POLL_MAX_INITIAL_SILENCE_SECS")
                    .unwrap_or_else(|_| "25".to_string())
                    .parse()?;
                if raw > 25 {
                    eprintln!(
                        "WARNING: LONG_POLL_MAX_INITIAL_SILENCE_SECS={} exceeds safe relay timeout (25s); clamping to 25",
                        raw
                    );
                    25
                } else {
                    raw
                }
            },
            long_poll_idle_secs: {
                let raw: u64 = crate::config_source::var("LONG_POLL_IDLE_SECS")
                    .unwrap_or_else(|_| "3".to_string())
                    .parse()?;
                if raw > 25 {
                    eprintln!(
                        "WARNING: LONG_POLL_IDLE_SECS={} exceeds safe relay timeout (25s); clamping to 25",
                        raw
                    );
                    25
                } else {
                    raw
                }
            },
            sse_keepalive_secs: {
                let raw: u64 = crate::config_source::var("SSE_KEEPALIVE_SECS")
                    .unwrap_or_else(|_| "20".to_string())
                    .parse()?;
                if raw == 0 {
                    eprintln!(
                        "WARNING: SSE_KEEPALIVE_SECS=0 disables keep-alives; using default 20"
                    );
                    20
                } else if raw > 25 {
                    eprintln!(
                        "WARNING: SSE_KEEPALIVE_SECS={} exceeds safe relay timeout (25s); clamping to 25",
                        raw
                    );
                    25
                } else {
                    raw
                }
            },
            redis_url: crate::config_source::var("REDIS_URL").unwrap_or_default(),
            redis_security_url: crate::config_source::var("REDIS_SECURITY_URL").unwrap_or_default(),
            // Strict parsing: a malformed entry is an error, never skipped.
            backends: zodl_ohttp_integrations::core::policy::parse_backends(
                &crate::config_source::var("BACKENDS").unwrap_or_default(),
            )?,
            backend_headers: zodl_ohttp_integrations::core::policy::parse_backend_headers(
                &crate::config_source::var("BACKEND_HEADERS").unwrap_or_default(),
            )?,
            proxy_allow_suffixes: crate::config_source::var("PROXY_ALLOW_SUFFIXES")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            network,
            log_outer_header_names: crate::config_source::var("LOG_OUTER_HEADER_NAMES")
                .map(|v| flag_on(&v))
                .unwrap_or(false),
            gateway_hosts,
            backends_policy,
            backends_policy_default_allow,
            max_upstream_response_bytes: crate::config_source::var("MAX_UPSTREAM_RESPONSE_BYTES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(64 * 1024 * 1024),
            max_inflight_upstream: crate::config_source::var("MAX_INFLIGHT_UPSTREAM")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(256),
            max_inflight_per_backend: crate::config_source::var("MAX_INFLIGHT_PER_BACKEND")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(64),
            max_inflight_lwd: crate::config_source::var("MAX_INFLIGHT_LWD")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(128),
            max_inflight_lwd_heavy: crate::config_source::var("MAX_INFLIGHT_LWD_HEAVY")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| {
                    (crate::config_source::var("MAX_INFLIGHT_LWD")
                        .ok()
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(128)
                        / 4)
                    .max(1)
                }),
            lwd_heavy_block_range: crate::config_source::var("LWD_HEAVY_BLOCK_RANGE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100),
            // At least 10 000: the ZIP requires that floor unless coordinated with Clients.
            max_block_range: crate::config_source::var("MAX_BLOCK_RANGE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10_000),
            lwd_permit_wait_ms: crate::config_source::var("LWD_PERMIT_WAIT_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(2000),
            lwd_permit_max_waiters: crate::config_source::var("LWD_PERMIT_MAX_WAITERS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            redis_op_timeout_ms: crate::config_source::var("REDIS_OP_TIMEOUT_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(250),
            max_cache_get_concurrency: crate::config_source::var("MAX_CACHE_GET_CONCURRENCY")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(64),
            max_large_response_concurrency: crate::config_source::var(
                "MAX_LARGE_RESPONSE_CONCURRENCY",
            )
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1),
            large_response_threshold: crate::config_source::var("LARGE_RESPONSE_THRESHOLD")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8 * 1024 * 1024),
            configs_signing_seed: crate::config_source::var("CONFIGS_SIGNING_SEED_HEX")
                .ok()
                .filter(|s| !s.is_empty()),
            chunk_size: parse_chunk_size(crate::config_source::var("CHUNK_SIZE").ok().as_deref())?,
            chunk_flush_ms: crate::config_source::var("CHUNK_FLUSH_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(50),
            flexa_publishable_key: crate::config_source::var("FLEXA_PUBLISHABLE_KEY")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            flexa_alias: alias_env("FLEXA_ALIAS"),
            near_alias: alias_env("NEAR_ALIAS"),
            relay_secret_on_key_config: RelaySecretOnKeyConfig::parse(
                &crate::config_source::var("RELAY_SECRET_ON_KEY_CONFIG").unwrap_or_default(),
            )?,
            dynamic_hosts: crate::dynamic_hosts::DynamicHosts::default(),
            host_list: crate::host_list::HostListSettings::from_env()?,
            third_party_query_rules: crate::query_rules::QueryRules::from_env()?,
        };
        config
            .third_party_query_rules
            .validate(&config.backends, &config.backends_policy)?;
        // The dynamic sources need the static names they must never take.
        let dynamic_hosts = crate::dynamic_hosts::DynamicHosts::from_env(
            crate::dynamic_hosts::Reserved {
                aliases: config.backends.keys().cloned().collect(),
                gateway_hosts: config.gateway_hosts.iter().cloned().collect(),
                targets: crate::dynamic_hosts::static_target_hosts(
                    config.backends.values(),
                    &config.lwd_addr,
                ),
            },
            &config.network,
            config.max_inflight_per_backend,
        )?;
        Ok(Self {
            dynamic_hosts,
            ..config
        })
    }
}

/// `ALLOW_UNAUTHENTICATED_RELAY`, `LOG_OUTER_HEADER_NAMES`: `1` or `true` (any case, not
/// trimmed) is on, anything else off.
pub fn flag_on(v: &str) -> bool {
    v == "1" || v.eq_ignore_ascii_case("true")
}

/// An alias host from `var` (trimmed, lowercase), `None` when unset or empty.
fn alias_env(var: &str) -> Option<String> {
    crate::config_source::var(var)
        .ok()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
}

/// Smallest accepted `CHUNK_SIZE`.
pub const MIN_CHUNK_SIZE: usize = 1024;
/// Largest accepted `CHUNK_SIZE`: the client refuses a response chunk whose plaintext exceeds
/// 65536 bytes (`zodl_ohttp_client::chunked::MAX_RESPONSE_CHUNK_PLAINTEXT_BYTES`), so a larger
/// value would break every response of more than one chunk (and every padded one).
pub const MAX_CHUNK_SIZE: usize = 64 * 1024;
/// Default `CHUNK_SIZE`.
pub const DEFAULT_CHUNK_SIZE: usize = 16384;

/// Parses `CHUNK_SIZE` (unset or unparsable = [`DEFAULT_CHUNK_SIZE`]) and refuses values outside
/// [`MIN_CHUNK_SIZE`]..=[`MAX_CHUNK_SIZE`].
pub fn parse_chunk_size(raw: Option<&str>) -> anyhow::Result<usize> {
    let size = raw
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(DEFAULT_CHUNK_SIZE);
    if size < MIN_CHUNK_SIZE {
        anyhow::bail!(
            "CHUNK_SIZE must be at least {} bytes, got {}",
            MIN_CHUNK_SIZE,
            size
        );
    }
    if size > MAX_CHUNK_SIZE {
        anyhow::bail!(
            "CHUNK_SIZE must be at most {} bytes (clients refuse larger response chunks), got {}",
            MAX_CHUNK_SIZE,
            size
        );
    }
    Ok(size)
}

/// `id:hex,id:hex,...` (HPKE_KEYS, HPKE_ACCEPT_ONLY_KEYS): key ids and hex X25519 private keys,
/// strictly parsed structurally (a malformed entry is an error, never skipped); the hex key
/// material itself is checked when the keys are loaded (`hpke.rs`).
pub fn parse_hpke_keys(var: &str, raw: &str) -> anyhow::Result<Vec<(u8, String)>> {
    let mut keys = Vec::new();
    for (i, pair) in raw.split(',').enumerate() {
        let trimmed = pair.trim();
        if trimmed.is_empty() {
            anyhow::bail!(
                "Malformed {}: empty entry at position {} (check for trailing commas)",
                var,
                i
            );
        }
        let mut parts = trimmed.splitn(2, ':');
        let key_id_str = parts.next().ok_or_else(|| {
            anyhow::anyhow!("Malformed {} entry at position {}: missing key_id", var, i)
        })?;
        let key_id = key_id_str.parse::<u8>().map_err(|e| {
            anyhow::anyhow!(
                "Malformed {} entry at position {}: invalid key_id '{}': {}",
                var,
                i,
                key_id_str,
                e
            )
        })?;
        let hex_key = parts
            .next()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Malformed {} entry at position {}: missing hex key (format: 'id:hex')",
                    var,
                    i
                )
            })?
            .trim();
        if hex_key.is_empty() {
            anyhow::bail!("Malformed {} entry at position {}: empty hex key", var, i);
        }
        keys.push((key_id, hex_key.to_string()));
    }
    if keys.is_empty() {
        anyhow::bail!("{} set but contains no valid keys", var);
    }
    Ok(keys)
}

/// `HPKE_ACCEPT_ONLY_KEYS`: private keys the gateway decapsulates with but does not publish in
/// `/ohttp-configs` (key rotation: a key is accepted before it is advertised and after it is no
/// longer advertised). Unset or empty: none.
pub fn hpke_accept_only_keys_from_env() -> anyhow::Result<Vec<(u8, String)>> {
    match crate::config_source::var("HPKE_ACCEPT_ONLY_KEYS")
        .ok()
        .filter(|s| !s.trim().is_empty())
    {
        Some(raw) => parse_hpke_keys("HPKE_ACCEPT_ONLY_KEYS", &raw),
        None => Ok(Vec::new()),
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Ensure all secret fields are redacted in debug output to prevent accidental logging
        f.debug_struct("Config")
            .field("port", &self.port)
            .field("lwd_addr", &self.lwd_addr)
            .field("mode", &self.mode)
            .field("relay_secrets", &"<REDACTED>")
            .field("hpke_private_key", &"<REDACTED>")
            .field("hpke_keys", &"<REDACTED>")
            .field("backend_headers", &"<REDACTED>")
            .field("backends", &self.backends)
            .field("gateway_hosts", &self.gateway_hosts)
            .field("network", &self.network)
            .field("redis_url", &"<REDACTED>")
            .field("redis_security_url", &"<REDACTED>")
            .field("configs_signing_seed", &"<REDACTED>")
            .field("flexa_publishable_key", &"<REDACTED>")
            .field("flexa_alias", &self.flexa_alias)
            .field("near_alias", &self.near_alias)
            .field("dynamic_hosts", &self.dynamic_hosts)
            .field("host_list", &self.host_list)
            .field("third_party_query_rules", &self.third_party_query_rules)
            .finish()
    }
}

/// An OHTTP gateway answers only for its own host names, so `GATEWAY_HOSTS` is required in
/// `ohttp` mode: without it every unknown authority would reach lightwalletd.
pub fn require_gateway_hosts(mode: &str, gateway_hosts: &[String]) -> anyhow::Result<()> {
    if mode == "ohttp" && gateway_hosts.is_empty() {
        anyhow::bail!(
            "GATEWAY_HOSTS is required in ohttp mode: set it to the gateway's own host names \
             (comma-separated); any other authority that is not a BACKENDS alias gets an inner 403"
        );
    }
    Ok(())
}

/// A configuration for unit tests: `ohttp` mode on `testnet`, the gateway host
/// `ohttp-gateway.example`, no backend, no policy (default deny), no dynamic source.
#[cfg(test)]
pub(crate) fn test_config() -> Config {
    Config {
        port: 8080,
        lwd_addr: "lwd:9067".to_string(),
        mode: "ohttp".to_string(),
        relay_secrets: vec![],
        allow_unauthenticated_relay: true,
        hpke_private_key: None,
        hpke_key_id: 1,
        hpke_keys: vec![],
        lwd_timeout_secs: 5,
        long_poll_max_initial_silence_secs: 25,
        long_poll_idle_secs: 3,
        sse_keepalive_secs: 20,
        redis_url: String::new(),
        redis_security_url: String::new(),
        backends: HashMap::new(),
        backend_headers: HashMap::new(),
        backends_policy: HashMap::new(),
        backends_policy_default_allow: false,
        max_inflight_lwd: 128,
        max_inflight_lwd_heavy: 32,
        lwd_heavy_block_range: 100,
        lwd_permit_wait_ms: 2000,
        lwd_permit_max_waiters: 0,
        redis_op_timeout_ms: 250,
        max_cache_get_concurrency: 64,
        max_large_response_concurrency: 2,
        large_response_threshold: 8 * 1024 * 1024,
        proxy_allow_suffixes: vec![],
        network: "testnet".to_string(),
        log_outer_header_names: false,
        gateway_hosts: vec!["ohttp-gateway.example".to_string()],
        configs_signing_seed: None,
        max_upstream_response_bytes: 1024 * 1024,
        max_inflight_upstream: 256,
        max_inflight_per_backend: 64,
        max_block_range: 1000,
        chunk_size: 16384,
        chunk_flush_ms: 50,
        flexa_publishable_key: None,
        flexa_alias: None,
        near_alias: None,
        relay_secret_on_key_config: RelaySecretOnKeyConfig::Off,
        dynamic_hosts: Default::default(),
        host_list: Default::default(),
        third_party_query_rules: Default::default(),
    }
}

/// Serialises the tests that set or read the process environment (`Config::from_env`): the
/// test harness runs them on parallel threads and the environment is process-wide.
#[cfg(test)]
pub(crate) fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

// Config tests
#[path = "config_tests.rs"]
mod tests;

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn the_matching_relay_secret_is_found_at_any_position() {
        let secrets: Vec<RelaySecret> = ["edge=aaaa", "internal=bbbbbbbb", "cccc"]
            .iter()
            .enumerate()
            .map(|(i, e)| RelaySecret::parse(i, e))
            .collect();
        assert_eq!(match_relay_secret(&secrets, b"aaaa"), Some(0));
        assert_eq!(match_relay_secret(&secrets, b"bbbbbbbb"), Some(1));
        assert_eq!(match_relay_secret(&secrets, b"cccc"), Some(2));
        assert_eq!(match_relay_secret(&secrets, b"edge=aaaa"), None);
        assert_eq!(match_relay_secret(&secrets, b""), None);
        assert_eq!(match_relay_secret(&[], b"aaaa"), None);
    }

    #[test]
    fn duplicate_relay_secrets_or_names_are_a_configuration_error() {
        let parsed = parse_relay_secrets("edge=aaaa, internal=bbbb ,cccc").unwrap();
        assert_eq!(
            parsed.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
            ["edge", "internal", "relay-3"]
        );
        // The digest is computed at load and is the one the request path compares.
        assert_eq!(match_relay_secret(&parsed, b"bbbb"), Some(1));

        let same_secret = parse_relay_secrets("edge=aaaa,internal=aaaa")
            .err()
            .unwrap();
        let text = same_secret.to_string();
        assert!(
            text.contains("same secret")
                && text.contains("\"edge\"")
                && text.contains("\"internal\"")
        );
        assert!(
            !text.contains("aaaa"),
            "error must not carry the secret: {text}"
        );

        let same_name = parse_relay_secrets("edge=aaaa,edge=bbbb").err().unwrap();
        assert!(same_name.to_string().contains("used twice"));

        // A bare secret at position 2 is named `relay-2`; an explicit `relay-2` elsewhere collides.
        let bare_collision = parse_relay_secrets("relay-2=aaaa,bbbb").err().unwrap();
        assert!(bare_collision.to_string().contains("used twice"));

        assert!(parse_relay_secrets("aaaa,").is_err());
        assert!(parse_relay_secrets("").is_err());
    }

    #[test]
    fn relay_secret_entries_carry_an_optional_name() {
        let named = RelaySecret::parse(0, "edge=abc123");
        assert_eq!(
            (named.name.as_str(), named.secret.as_str()),
            ("edge", "abc123")
        );
        // A base64 secret ends with '=': it is a bare secret, not a name.
        let bare = RelaySecret::parse(1, "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0NTY3ODk=");
        assert_eq!(bare.name, "relay-2");
        assert_eq!(bare.secret, "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0NTY3ODk=");
        for padded in ["ag==", "abcd=", "YWJj"] {
            let bare = RelaySecret::parse(0, padded);
            assert_eq!(
                (bare.name.as_str(), bare.secret.as_str()),
                ("relay-1", padded)
            );
        }
        let upper = RelaySecret::parse(2, "Edge=abc");
        assert_eq!(
            (upper.name.as_str(), upper.secret.as_str()),
            ("relay-3", "Edge=abc")
        );
    }

    #[test]
    fn chunk_size_is_bounded_to_what_clients_accept() {
        assert_eq!(parse_chunk_size(None).unwrap(), 16384);
        assert_eq!(parse_chunk_size(Some("not a number")).unwrap(), 16384);
        assert_eq!(parse_chunk_size(Some("1024")).unwrap(), 1024);
        assert_eq!(parse_chunk_size(Some("65536")).unwrap(), 65536);
        let low = parse_chunk_size(Some("1023")).unwrap_err().to_string();
        assert!(low.contains("at least 1024"), "{low}");
        let high = parse_chunk_size(Some("65537")).unwrap_err().to_string();
        assert!(high.contains("at most 65536"), "{high}");
    }

    #[test]
    fn test_multiple_relay_secrets_parsed() {
        let _env = crate::config::test_env_lock();
        std::env::set_var("RELAY_SECRETS", "secret1,secret2,secret3");
        let config = Config::from_env().unwrap();
        assert_eq!(config.relay_secrets.len(), 3);
        std::env::remove_var("RELAY_SECRETS");
    }

    #[test]
    fn test_backends_policy_parsed() {
        let _env = crate::config::test_env_lock();
        std::env::set_var(
            "BACKENDS_POLICY",
            "api1.example.com=GET /v1/info,POST /v1/data",
        );
        let config = Config::from_env().unwrap();
        assert!(config.backends_policy.contains_key("api1.example.com"));
        assert_eq!(config.backends_policy["api1.example.com"].len(), 2);
        std::env::remove_var("BACKENDS_POLICY");
    }

    #[test]
    fn third_party_query_rules_are_parsed_and_checked_at_startup() {
        // Every result is collected and the variables removed before any assertion, so that a
        // failing one cannot leave them set for other tests.
        let (valid, blank, errors, with_source, not_utf8, unset) = {
            let _env = crate::config::test_env_lock();
            std::env::set_var("BACKENDS", "api1.example.com=https://api.example.org");
            std::env::set_var(
                "BACKENDS_POLICY",
                "api1.example.com=GET /v1/info,GET /v1/list,GET /v2/*",
            );
            let attempt = |rules: &str| {
                std::env::set_var("THIRD_PARTY_QUERY_RULES", rules);
                Config::from_env()
            };
            let valid = attempt("api1.example.com=GET /v1/info?id={in:ABC|XYZ},GET /v1/list?");
            let blank = attempt("  ");
            let errors = [
                attempt("api1.example.com=GET /v1/info?id={lower:1-4}"),
                attempt("api2.example.com=GET /v1/info?"),
                attempt("api1.example.com=POST /v1/info?"),
                attempt("api1.example.com=GET /v3/info?"),
                attempt("api1.example.com=GET /v2/info?"),
            ];
            std::env::set_var(
                "THIRD_PARTY_QUERY_VALUE_SOURCES",
                "ids=api1.example.com GET /v1/list#/data/*@300@fallback=ABC",
            );
            let with_source = attempt("api1.example.com=GET /v1/info?id={from:ids}");
            #[cfg(unix)]
            let not_utf8 = {
                use std::os::unix::ffi::OsStrExt;
                let bad = std::ffi::OsStr::from_bytes(b"api1.example.com=GET /v1/info?id=\xff");
                std::env::set_var("THIRD_PARTY_QUERY_VALUE_SOURCES", bad);
                let sources = Config::from_env();
                std::env::remove_var("THIRD_PARTY_QUERY_VALUE_SOURCES");
                std::env::set_var("THIRD_PARTY_QUERY_RULES", bad);
                vec![Config::from_env(), sources]
            };
            #[cfg(not(unix))]
            let not_utf8: Vec<anyhow::Result<Config>> = Vec::new();
            std::env::remove_var("THIRD_PARTY_QUERY_VALUE_SOURCES");
            std::env::remove_var("THIRD_PARTY_QUERY_RULES");
            let unset = Config::from_env();
            std::env::remove_var("BACKENDS_POLICY");
            std::env::remove_var("BACKENDS");
            (valid, blank, errors, with_source, not_utf8, unset)
        };

        let rules = valid.unwrap().third_party_query_rules;
        assert_eq!(rules.len(), 2);
        assert!(rules.admits("api1.example.com", "GET", "/v1/info?id=ABC"));
        assert!(!rules.admits("api1.example.com", "GET", "/v1/info?id=ABC&x=1"));
        assert!(!rules.admits("api1.example.com", "GET", "/v1/info?id=ABD"));
        assert!(blank.unwrap().third_party_query_rules.is_empty());
        for result in errors {
            let text = result.unwrap_err().to_string();
            assert!(text.contains("THIRD_PARTY_QUERY_RULES"), "{text}");
        }
        let rules = with_source.unwrap().third_party_query_rules;
        assert_eq!(rules.sources().len(), 1);
        assert!(rules.admits("api1.example.com", "GET", "/v1/info?id=ABC"));
        assert!(!rules.admits("api1.example.com", "GET", "/v1/info?id=XYZ"));
        for (result, var) in not_utf8
            .into_iter()
            .zip(["THIRD_PARTY_QUERY_RULES", "THIRD_PARTY_QUERY_VALUE_SOURCES"])
        {
            let text = result.unwrap_err().to_string();
            assert!(
                text.contains("not valid UTF-8") && text.contains(var),
                "{text}"
            );
        }
        assert!(unset.unwrap().third_party_query_rules.is_empty());
    }
}

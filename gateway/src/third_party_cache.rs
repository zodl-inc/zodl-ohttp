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

//! Third-party backend caching and rate limiting.
//!
//! Problem: without caching, every exchange-rate request hits the upstream price or swap API with the
//! operator's API key.
//! A distributed attacker (many client IPs, each under the relay's per-IP rate limit) can burn the
//! daily API quota and break prices for everyone. The gateway cannot see client IPs (OHTTP), so the
//! protection must be per backend, not per client.
//!
//! Two features, both off by default (behaviour unchanged when env vars are unset):
//!
//! 1. `THIRD_PARTY_CACHE_ROUTES` — cache third-party responses (e.g., exchange rates, public market
//!    data) with per-route TTLs. Only GET requests with status 200 are cached. The cache key includes
//!    authority, method, full path WITH query string, and the existing cache epoch/namespace, so it
//!    never collides with lightwalletd entries or other backends. Concurrent cache misses for the
//!    same key are serialized: waiters read the first call's stored answer (an answer that is
//!    not cached, such as an error, is fetched again by the next waiter). These responses are
//!    expected to carry no per-client data (public market
//!    data), so sharing them across clients is safe.
//!
//!    Syntax: `authority=METHOD /path@TTL_SECS,...;authority2=...`
//!    Example: `prices.example=GET /v1/cryptocurrency/quotes/latest@60,GET /v1/fiat/map@3600;swap.example=GET /v0/tokens@60`
//!
//!    **`NEAR_ALIAS` constraint:** for the alias of the NEAR Intents 1Click API (`NEAR_ALIAS`), only
//!    `GET /v0/tokens` (public token list) may be cached. Routes `POST /v0/quote`, `GET /v0/status`,
//!    `POST /v0/deposit/submit`, and any non-GET are explicitly denied. Parsing a configuration
//!    that lists them fails at startup. The Flexa alias (`FLEXA_ALIAS`) is never cacheable.
//!
//! 2. `THIRD_PARTY_RATE_LIMITS` — per-backend cap on UPSTREAM requests (cache hits do not count).
//!    When exceeded, answer the inner request with inner status 429 and a `retry-after` header
//!    (seconds until the window frees), without contacting the upstream. Enforced per gateway
//!    process (simple fixed window, in memory). Prometheus counters for visibility.
//!
//!    Syntax: `authority=REQUESTS/WINDOW,...`
//!    Example: `prices.example=120/60s,swap.example=600/60s`
//!
//! The inner 429 is NOT counted as a replay/freshness error and does not affect lightwalletd paths.

use anyhow::{anyhow, Result};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::warn;

use crate::cache::ResponseCache;
use crate::ohttp::InnerResponse;
use crate::origin::path_matches;

/// Cache route: method, path pattern, TTL in seconds.
#[derive(Clone, Debug)]
struct CacheRoute {
    method: String,
    path: String,
    ttl_secs: u64,
}

/// The aliases whose cache routes are restricted (`FLEXA_ALIAS`, `NEAR_ALIAS`), lowercase.
#[derive(Clone, Copy, Debug, Default)]
pub struct Aliases<'a> {
    /// Never cacheable (per-user answers).
    pub flexa: Option<&'a str>,
    /// Only `GET /v0/tokens` is cacheable.
    pub near: Option<&'a str>,
}

/// Per-backend cache routes.
#[derive(Clone, Debug)]
pub struct CacheRoutes {
    routes: HashMap<String, Vec<CacheRoute>>,
}

impl CacheRoutes {
    /// Parse `THIRD_PARTY_CACHE_ROUTES` from env, with the constraints of the Flexa and NEAR
    /// aliases (`FLEXA_ALIAS`, `NEAR_ALIAS`, lowercase).
    /// Format: `authority=METHOD /path@TTL,...;authority2=...`
    pub fn from_env(aliases: Aliases<'_>) -> Result<Option<Self>> {
        let s = match std::env::var("THIRD_PARTY_CACHE_ROUTES")
            .ok()
            .filter(|s| !s.trim().is_empty())
        {
            Some(s) => s,
            None => return Ok(None),
        };
        Self::parse(&s, aliases).map(Some)
    }

    fn parse(s: &str, aliases: Aliases<'_>) -> Result<Self> {
        let mut routes = HashMap::new();
        for entry in s.split(';') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let Some((authority, policies)) = entry.split_once('=') else {
                anyhow::bail!(
                    "Malformed THIRD_PARTY_CACHE_ROUTES: '{entry}' must be 'authority=METHOD /path@TTL,...'"
                );
            };
            let authority = authority.trim().to_ascii_lowercase();
            if authority.is_empty() {
                anyhow::bail!("Malformed THIRD_PARTY_CACHE_ROUTES: missing authority in '{entry}'");
            }
            let mut list = Vec::new();
            for policy in policies.split(',') {
                let policy = policy.trim();
                if policy.is_empty() {
                    continue;
                }
                // Parse "METHOD /path@TTL"
                let Some((method_path, ttl_str)) = policy.split_once('@') else {
                    anyhow::bail!(
                        "Malformed THIRD_PARTY_CACHE_ROUTES: '{policy}' must be 'METHOD /path@TTL' (entry: '{entry}')"
                    );
                };
                let Some((method, path)) = method_path.trim().split_once(' ') else {
                    anyhow::bail!(
                        "Malformed THIRD_PARTY_CACHE_ROUTES: '{method_path}' must be 'METHOD /path' (entry: '{entry}')"
                    );
                };
                let method = method.trim().to_ascii_uppercase();
                if method != "GET" {
                    anyhow::bail!(
                        "Invalid THIRD_PARTY_CACHE_ROUTES method '{method}' in '{policy}': only GET is allowed"
                    );
                }
                let path = path.trim().to_string();
                if !path.starts_with('/') {
                    anyhow::bail!(
                        "Invalid THIRD_PARTY_CACHE_ROUTES path '{path}' in '{policy}': must start with /"
                    );
                }

                // Flexa answers are per user (the cache key has no Authorization): never cached.
                if aliases.flexa == Some(authority.as_str()) {
                    anyhow::bail!(
                        "Invalid THIRD_PARTY_CACHE_ROUTES: {} (FLEXA_ALIAS) answers are per user and never cacheable",
                        authority
                    );
                }

                // NEAR_ALIAS constraint: only GET /v0/tokens is allowed to be cached.
                // Deny: POST /v0/quote (creates quote+address), GET /v0/status (per-deposit state),
                // POST /v0/deposit/submit, and any non-GET.
                if aliases.near == Some(authority.as_str()) {
                    if method != "GET" {
                        anyhow::bail!(
                            "Invalid THIRD_PARTY_CACHE_ROUTES: {} (NEAR_ALIAS) non-GET '{}' is not cacheable (only GET /v0/tokens allowed)",
                            authority,
                            method
                        );
                    }
                    // Only /v0/tokens is allowed
                    if path != "/v0/tokens" {
                        anyhow::bail!(
                            "Invalid THIRD_PARTY_CACHE_ROUTES: {} (NEAR_ALIAS) '{}' is not cacheable \
                             (only GET /v0/tokens allowed; POST /v0/quote, GET /v0/status, POST /v0/deposit/submit are denied)",
                            authority,
                            path
                        );
                    }
                }

                let ttl_str = ttl_str.trim();
                let ttl_secs = ttl_str.parse::<u64>().map_err(|_| {
                    anyhow!(
                        "Invalid THIRD_PARTY_CACHE_ROUTES TTL '{ttl_str}' in '{policy}': must be a positive integer"
                    )
                })?;
                if ttl_secs == 0 {
                    anyhow::bail!(
                        "Invalid THIRD_PARTY_CACHE_ROUTES TTL '{ttl_secs}' in '{policy}': must be > 0"
                    );
                }
                list.push(CacheRoute {
                    method,
                    path,
                    ttl_secs,
                });
            }
            if list.is_empty() {
                anyhow::bail!(
                    "Malformed THIRD_PARTY_CACHE_ROUTES: no routes for authority '{authority}'"
                );
            }
            routes.insert(authority, list);
        }
        if routes.is_empty() {
            anyhow::bail!("Malformed THIRD_PARTY_CACHE_ROUTES: no entries");
        }
        Ok(Self { routes })
    }

    /// Find a matching route for (authority, method, path). Returns the TTL if found.
    pub fn find_ttl(&self, authority: &str, method: &str, path: &str) -> Option<u64> {
        let authority = authority.to_ascii_lowercase();
        let routes = self.routes.get(&authority)?;
        for route in routes {
            if method.eq_ignore_ascii_case(&route.method) && path_matches(&route.path, path) {
                return Some(route.ttl_secs);
            }
        }
        None
    }

    /// Total number of configured routes across all authorities.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.routes.values().map(Vec::len).sum()
    }
}

/// Rate limit window: fixed window per backend.
#[derive(Debug)]
struct RateWindow {
    /// Window start time.
    window_start: Instant,
    /// Window duration.
    window_duration: Duration,
    /// Request count in the current window.
    count: u64,
    /// Max requests per window.
    limit: u64,
}

impl RateWindow {
    fn new(limit: u64, window_duration: Duration) -> Self {
        Self {
            window_start: Instant::now(),
            window_duration,
            count: 0,
            limit,
        }
    }

    /// Check and increment. Returns Ok(()) if allowed, Err(retry_after_secs) if limited.
    fn check_and_increment(&mut self) -> Result<(), u64> {
        let now = Instant::now();
        let elapsed = now.duration_since(self.window_start);

        // Reset window if expired
        if elapsed >= self.window_duration {
            self.window_start = now;
            self.count = 0;
        }

        if self.count >= self.limit {
            // Calculate seconds until window expires
            let remaining = self.window_duration.saturating_sub(elapsed);
            let retry_after_secs = remaining.as_secs().max(1);
            return Err(retry_after_secs);
        }

        self.count += 1;
        Ok(())
    }
}

/// Per-backend rate limiters.
#[derive(Clone)]
pub struct RateLimiters {
    limits: Arc<Mutex<HashMap<String, RateWindow>>>,
    pub configs: HashMap<String, (u64, Duration)>,
}

impl RateLimiters {
    /// Parse `THIRD_PARTY_RATE_LIMITS` from env.
    /// Format: `authority=REQUESTS/WINDOW,...`
    /// Example: `prices.example=120/60s,swap.example=600/60s`
    pub fn from_env() -> Result<Option<Self>> {
        let s = match std::env::var("THIRD_PARTY_RATE_LIMITS")
            .ok()
            .filter(|s| !s.trim().is_empty())
        {
            Some(s) => s,
            None => return Ok(None),
        };
        Self::parse(&s).map(Some)
    }

    fn parse(s: &str) -> Result<Self> {
        let mut configs = HashMap::new();
        for entry in s.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let Some((authority, limit_window)) = entry.split_once('=') else {
                anyhow::bail!(
                    "Malformed THIRD_PARTY_RATE_LIMITS: '{entry}' must be 'authority=REQUESTS/WINDOW'"
                );
            };
            let authority = authority.trim().to_ascii_lowercase();
            if authority.is_empty() {
                anyhow::bail!("Malformed THIRD_PARTY_RATE_LIMITS: missing authority in '{entry}'");
            }
            let Some((requests, window)) = limit_window.split_once('/') else {
                anyhow::bail!(
                    "Malformed THIRD_PARTY_RATE_LIMITS: '{limit_window}' must be 'REQUESTS/WINDOW' (entry: '{entry}')"
                );
            };
            let requests = requests.trim().parse::<u64>().map_err(|_| {
                anyhow!(
                    "Invalid THIRD_PARTY_RATE_LIMITS requests '{requests}' in '{entry}': must be a positive integer"
                )
            })?;
            if requests == 0 {
                anyhow::bail!(
                    "Invalid THIRD_PARTY_RATE_LIMITS requests '{requests}' in '{entry}': must be > 0"
                );
            }
            let window = window.trim();
            let duration = if let Some(secs) = window.strip_suffix('s') {
                let secs = secs.parse::<u64>().map_err(|_| {
                    anyhow!(
                        "Invalid THIRD_PARTY_RATE_LIMITS window '{window}' in '{entry}': must be a positive integer followed by 's'"
                    )
                })?;
                Duration::from_secs(secs)
            } else {
                anyhow::bail!(
                    "Invalid THIRD_PARTY_RATE_LIMITS window '{window}' in '{entry}': must end with 's' (e.g., '60s')"
                );
            };
            if duration.as_secs() == 0 {
                anyhow::bail!(
                    "Invalid THIRD_PARTY_RATE_LIMITS window '{window}' in '{entry}': must be > 0"
                );
            }
            configs.insert(authority, (requests, duration));
        }
        if configs.is_empty() {
            anyhow::bail!("Malformed THIRD_PARTY_RATE_LIMITS: no entries");
        }
        Ok(Self {
            limits: Arc::new(Mutex::new(HashMap::new())),
            configs,
        })
    }

    /// Check rate limit for a backend. Returns Ok(()) if allowed, Err(retry_after_secs) if limited.
    pub fn check(&self, authority: &str) -> Result<(), u64> {
        let authority = authority.to_ascii_lowercase();
        let Some(&(limit, duration)) = self.configs.get(&authority) else {
            // No limit configured for this authority
            return Ok(());
        };

        let mut limits = self.limits.lock();
        let window = limits
            .entry(authority.clone())
            .or_insert_with(|| RateWindow::new(limit, duration));
        window.check_and_increment()
    }
}

/// Cache key of a third-party answer: its own namespace (never a lightwalletd key), the
/// authority, the method, the full path WITH query (hashed to bound the key length) and the
/// cache epoch. No client header is part of it: the answers cached here do not vary by client
/// (the gateway injects the credential).
pub fn cache_key(network: &str, authority: &str, method: &str, path: &str, epoch: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.as_bytes());
    format!(
        "ohttp:{}:third_party:{}:{}:{}:{:x}",
        network,
        authority.to_ascii_lowercase(),
        epoch,
        method.to_ascii_uppercase(),
        hasher.finalize()
    )
}

/// The inner answer when the per-backend cap is reached: 429 with `retry-after`, the upstream is
/// not contacted.
pub fn create_rate_limited_response(retry_after_secs: u64) -> InnerResponse {
    InnerResponse {
        status: 429,
        headers: vec![
            ("content-type".to_string(), "text/plain".to_string()),
            ("retry-after".to_string(), retry_after_secs.to_string()),
        ],
        body: b"rate limited".to_vec(),
    }
}

/// One lock per cache key: concurrent misses for the same key wait for the first upstream call
/// and then read its stored answer, instead of each calling the upstream. Entries are removed
/// when the last holder that completes leaves (a cancelled caller can leave its entry until the
/// key is used again), so finished query strings do not accumulate in the map.
#[derive(Default)]
struct KeyedLock {
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl KeyedLock {
    async fn run<T, Fut: std::future::Future<Output = T>>(&self, key: &str, f: Fut) -> T {
        let lock = self
            .locks
            .lock()
            .entry(key.to_string())
            .or_default()
            .clone();
        let out = {
            let _held = lock.lock().await;
            f.await
        };
        let mut locks = self.locks.lock();
        // The map's copy and ours: nobody else is waiting for this key.
        if Arc::strong_count(&lock) == 2 {
            locks.remove(key);
        }
        out
    }
}

/// `THIRD_PARTY_CACHE_ROUTES` + `THIRD_PARTY_RATE_LIMITS`, consulted on the third-party path of
/// the OHTTP handler before it forwards.
#[derive(Default)]
pub struct ThirdParty {
    routes: Option<CacheRoutes>,
    limits: Option<RateLimiters>,
    flights: KeyedLock,
}

impl ThirdParty {
    /// `THIRD_PARTY_CACHE_ROUTES` and `THIRD_PARTY_RATE_LIMITS` from env; `flexa_alias` and
    /// `near_alias` are `Config::flexa_alias` / `Config::near_alias`.
    pub fn from_env(flexa_alias: Option<&str>, near_alias: Option<&str>) -> Result<Self> {
        let aliases = Aliases {
            flexa: flexa_alias,
            near: near_alias,
        };
        Ok(Self {
            routes: CacheRoutes::from_env(aliases)?,
            limits: RateLimiters::from_env()?,
            flights: KeyedLock::default(),
        })
    }

    #[cfg(test)]
    fn new(routes: Option<CacheRoutes>, limits: Option<RateLimiters>) -> Self {
        Self {
            routes,
            limits,
            flights: KeyedLock::default(),
        }
    }

    /// Number of cache routes and capped backends, for the startup log.
    pub fn summary(&self) -> (usize, usize) {
        (
            self.routes.as_ref().map_or(0, CacheRoutes::len),
            self.limits.as_ref().map_or(0, |l| l.configs.len()),
        )
    }

    /// Consumes one upstream call of `authority`'s budget: `Some(429 answer)` when it is spent.
    fn limited(&self, network: &str, authority: &str) -> Option<InnerResponse> {
        let retry_after = self.limits.as_ref()?.check(authority).err()?;
        warn!(
            authority,
            retry_after, network, "third-party upstream cap reached (inner 429)"
        );
        crate::health::record_third_party_limited(network, authority);
        Some(create_rate_limited_response(retry_after))
    }

    async fn cached(&self, cache: &ResponseCache, key: &str) -> Option<InnerResponse> {
        let bytes = cache.get_third_party(key).await?;
        match bincode::deserialize::<InnerResponse>(&bytes) {
            Ok(r) => Some(r),
            Err(e) => {
                warn!(error = %e, "third-party cache entry unreadable, treated as a miss");
                None
            }
        }
    }

    /// What the third-party path answers before (or instead of) its usual streamed forward:
    /// - a route on `THIRD_PARTY_CACHE_ROUTES` (and a cache): the stored answer, or one upstream
    ///   call through `fetch` (counted against the cap, stored when it is a 200), or the cap's
    ///   429; always `Some`;
    /// - any other route: `Some(429)` when the backend's cap is spent, else `None` (the call
    ///   is counted and the caller forwards as before).
    ///
    /// Cache hits never count against the cap.
    pub async fn answer<F, Fut>(
        &self,
        cache: Option<&ResponseCache>,
        network: &str,
        authority: &str,
        method: &str,
        path: &str,
        fetch: F,
    ) -> Option<InnerResponse>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<InnerResponse>>,
    {
        let ttl = self
            .routes
            .as_ref()
            .and_then(|r| r.find_ttl(authority, method, path));
        let (Some(cache), Some(ttl)) = (cache, ttl) else {
            return self.limited(network, authority);
        };
        let key = cache_key(network, authority, method, path, cache.current_epoch());
        if let Some(hit) = self.cached(cache, &key).await {
            crate::health::record_third_party_cache(network, authority, "hit");
            return Some(hit);
        }
        let answer = self
            .flights
            .run(&key, async {
                // A concurrent miss may have stored it while we waited for the lock.
                if let Some(hit) = self.cached(cache, &key).await {
                    crate::health::record_third_party_cache(network, authority, "hit");
                    return hit;
                }
                crate::health::record_third_party_cache(network, authority, "miss");
                if let Some(limited) = self.limited(network, authority) {
                    return limited;
                }
                match fetch().await {
                    Ok(resp) => {
                        if resp.status == 200 && method.eq_ignore_ascii_case("GET") {
                            match bincode::serialize(&resp) {
                                Ok(bytes) => cache.put_third_party(&key, &bytes, ttl).await,
                                Err(e) => warn!(error = %e, "third-party answer not serialisable"),
                            }
                        }
                        resp
                    }
                    Err(e) => {
                        warn!(authority, error = %e, network, "third-party upstream error");
                        InnerResponse {
                            status: 502,
                            headers: vec![("content-type".to_string(), "text/plain".to_string())],
                            body: b"Bad Gateway".to_vec(),
                        }
                    }
                }
            })
            .await;
        Some(answer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Flexa and NEAR aliases of these tests (`FLEXA_ALIAS`, `NEAR_ALIAS`).
    const TEST_ALIASES: Aliases<'static> = Aliases {
        flexa: Some("pay.example"),
        near: Some("swap.example"),
    };

    #[test]
    fn test_cache_routes_parse_valid() {
        let routes = CacheRoutes::parse(
            "prices.example=GET /v1/cryptocurrency/quotes/latest@60,GET /v1/fiat/map@3600;\
             swap.example=GET /v0/tokens@60",
            TEST_ALIASES,
        )
        .unwrap();

        assert_eq!(
            routes.find_ttl("prices.example", "GET", "/v1/cryptocurrency/quotes/latest"),
            Some(60)
        );
        assert_eq!(
            routes.find_ttl("prices.example", "GET", "/v1/fiat/map"),
            Some(3600)
        );
        assert_eq!(
            routes.find_ttl("swap.example", "GET", "/v0/tokens"),
            Some(60)
        );

        // Case insensitive authority
        assert_eq!(
            routes.find_ttl("PRICES.EXAMPLE", "GET", "/v1/cryptocurrency/quotes/latest"),
            Some(60)
        );

        // With query string (exact match)
        assert_eq!(
            routes.find_ttl(
                "prices.example",
                "GET",
                "/v1/cryptocurrency/quotes/latest?symbol=ZEC"
            ),
            Some(60)
        );

        // Wrong method
        assert_eq!(
            routes.find_ttl("prices.example", "POST", "/v1/cryptocurrency/quotes/latest"),
            None
        );

        // Unknown authority
        assert_eq!(routes.find_ttl("other.example", "GET", "/v0/tokens"), None);
    }

    #[test]
    fn test_cache_routes_parse_prefix() {
        let routes = CacheRoutes::parse("api.example.com=GET /*@60", TEST_ALIASES).unwrap();
        assert_eq!(routes.find_ttl("api.example.com", "GET", "/"), Some(60));
        assert_eq!(routes.find_ttl("api.example.com", "GET", "/foo"), Some(60));
        assert_eq!(
            routes.find_ttl("api.example.com", "GET", "/foo/bar"),
            Some(60)
        );
    }

    #[test]
    fn test_cache_routes_parse_segment_bounded() {
        let routes = CacheRoutes::parse("api.example.com=GET /v1/*@60", TEST_ALIASES).unwrap();
        assert_eq!(
            routes.find_ttl("api.example.com", "GET", "/v1/foo"),
            Some(60)
        );
        assert_eq!(
            routes.find_ttl("api.example.com", "GET", "/v1/foo/bar"),
            Some(60)
        );
        assert_eq!(routes.find_ttl("api.example.com", "GET", "/v1"), Some(60));
        // Does not match /v1x (segment-bounded)
        assert_eq!(routes.find_ttl("api.example.com", "GET", "/v1x"), None);
    }

    #[test]
    fn test_cache_routes_parse_invalid() {
        // Missing TTL
        assert!(CacheRoutes::parse("prices.example=GET /path", TEST_ALIASES).is_err());

        // Invalid TTL
        assert!(CacheRoutes::parse("prices.example=GET /path@abc", TEST_ALIASES).is_err());

        // Zero TTL
        assert!(CacheRoutes::parse("prices.example=GET /path@0", TEST_ALIASES).is_err());

        // Non-GET method
        assert!(CacheRoutes::parse("prices.example=POST /path@60", TEST_ALIASES).is_err());

        // Missing authority
        assert!(CacheRoutes::parse("=GET /path@60", TEST_ALIASES).is_err());

        // Missing path
        assert!(CacheRoutes::parse("prices.example=GET@60", TEST_ALIASES).is_err());

        // No slash in path
        assert!(CacheRoutes::parse("prices.example=GET path@60", TEST_ALIASES).is_err());
    }

    #[test]
    fn test_flexa_never_cacheable() {
        assert!(CacheRoutes::parse("pay.example=GET /brands@60", TEST_ALIASES).is_err());
        assert!(CacheRoutes::parse(
            "prices.example=GET /v1/fiat/map@60;PAY.example=GET /assets@60",
            TEST_ALIASES
        )
        .is_err());
    }

    #[test]
    fn test_alias_constraints_need_the_aliases() {
        // Without FLEXA_ALIAS / NEAR_ALIAS no authority is restricted beyond the general rules.
        let none = Aliases::default();
        assert!(CacheRoutes::parse("pay.example=GET /brands@60", none).is_ok());
        assert!(CacheRoutes::parse("swap.example=GET /v0/other@60", none).is_ok());
        // The constraints follow the configured names, not fixed hosts.
        let other = Aliases {
            flexa: Some("flexa-alias.example"),
            near: Some("near-alias.example"),
        };
        assert!(CacheRoutes::parse("flexa-alias.example=GET /brands@60", other).is_err());
        assert!(CacheRoutes::parse("near-alias.example=GET /v0/status@60", other).is_err());
        assert!(CacheRoutes::parse("pay.example=GET /brands@60", other).is_ok());
    }

    #[test]
    fn test_near_alias_constraint_allows_tokens() {
        // swap.example GET /v0/tokens is allowed
        let routes = CacheRoutes::parse("swap.example=GET /v0/tokens@60", TEST_ALIASES).unwrap();
        assert_eq!(
            routes.find_ttl("swap.example", "GET", "/v0/tokens"),
            Some(60)
        );
    }

    #[test]
    fn test_near_alias_constraint_denies_quote() {
        // swap.example POST /v0/quote is denied
        let result = CacheRoutes::parse("swap.example=POST /v0/quote@60", TEST_ALIASES);
        assert!(result.is_err());
    }

    #[test]
    fn test_near_alias_constraint_denies_status() {
        // swap.example GET /v0/status is denied
        let result = CacheRoutes::parse("swap.example=GET /v0/status@60", TEST_ALIASES);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("/v0/status"));
        assert!(err.contains("not cacheable"));
    }

    #[test]
    fn test_near_alias_constraint_denies_submit() {
        // swap.example POST /v0/deposit/submit is denied
        let result = CacheRoutes::parse("swap.example=POST /v0/deposit/submit@60", TEST_ALIASES);
        assert!(result.is_err());
    }

    #[test]
    fn test_near_alias_constraint_denies_other_paths() {
        // swap.example GET /v0/other is denied (not /v0/tokens)
        let result = CacheRoutes::parse("swap.example=GET /v0/other@60", TEST_ALIASES);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("/v0/other"));
        assert!(err.contains("only GET /v0/tokens allowed"));
    }

    #[test]
    fn test_rate_limiters_parse_valid() {
        let limiters = RateLimiters::parse("prices.example=120/60s,swap.example=600/60s").unwrap();

        assert!(limiters.configs.contains_key("prices.example"));
        assert_eq!(
            limiters.configs["prices.example"],
            (120, Duration::from_secs(60))
        );
        assert_eq!(
            limiters.configs["swap.example"],
            (600, Duration::from_secs(60))
        );
    }

    #[test]
    fn test_rate_limiters_check() {
        let limiters = RateLimiters::parse("test.example.com=5/10s").unwrap();

        // First 5 requests should succeed
        for _ in 0..5 {
            assert!(limiters.check("test.example.com").is_ok());
        }

        // 6th request should fail
        let result = limiters.check("test.example.com");
        assert!(result.is_err());
        let retry_after = result.unwrap_err();
        assert!(retry_after > 0 && retry_after <= 10);

        // Unknown authority should succeed (no limit)
        assert!(limiters.check("other.example.com").is_ok());
    }

    #[test]
    fn test_rate_limiters_window_reset() {
        let limiters = RateLimiters {
            limits: Arc::new(Mutex::new(HashMap::new())),
            configs: [(
                "test.example.com".to_string(),
                (2, Duration::from_millis(100)),
            )]
            .into_iter()
            .collect(),
        };

        // Use up the limit
        assert!(limiters.check("test.example.com").is_ok());
        assert!(limiters.check("test.example.com").is_ok());
        assert!(limiters.check("test.example.com").is_err());

        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(150));

        // Should be allowed again
        assert!(limiters.check("test.example.com").is_ok());
    }

    #[test]
    fn test_rate_limiters_parse_invalid() {
        // Missing window
        assert!(RateLimiters::parse("prices.example=120").is_err());

        // Invalid requests
        assert!(RateLimiters::parse("prices.example=abc/60s").is_err());

        // Zero requests
        assert!(RateLimiters::parse("prices.example=0/60s").is_err());

        // Missing 's' suffix
        assert!(RateLimiters::parse("prices.example=120/60").is_err());

        // Invalid window
        assert!(RateLimiters::parse("prices.example=120/abc").is_err());

        // Zero window
        assert!(RateLimiters::parse("prices.example=120/0s").is_err());
    }

    #[test]
    fn test_cache_key_includes_query() {
        let key1 = cache_key("mainnet", "api.example.com", "GET", "/v1/data", 1);
        let key2 = cache_key("mainnet", "api.example.com", "GET", "/v1/data?foo=bar", 1);

        // Different query strings should produce different keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cache_key_includes_authority() {
        let key1 = cache_key("mainnet", "api1.example.com", "GET", "/v1/data", 1);
        let key2 = cache_key("mainnet", "api2.example.com", "GET", "/v1/data", 1);

        // Different authorities should produce different keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cache_key_includes_epoch() {
        let key1 = cache_key("mainnet", "api.example.com", "GET", "/v1/data", 1);
        let key2 = cache_key("mainnet", "api.example.com", "GET", "/v1/data", 2);

        // Different epochs should produce different keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_rate_limited_response() {
        let response = create_rate_limited_response(30);
        assert_eq!(response.status, 429);
        assert_eq!(response.body, b"rate limited");
        assert_eq!(response.header("retry-after"), Some("30"));
    }

    #[tokio::test]
    async fn uncached_routes_only_consume_the_cap() {
        let limits = RateLimiters::parse("prices.example=2/60s").unwrap();
        let tp = ThirdParty::new(None, Some(limits));
        let fetch = || async {
            Err::<InnerResponse, _>(anyhow!("uncached routes are forwarded by the caller"))
        };
        for _ in 0..2 {
            assert!(tp
                .answer(None, "mainnet", "prices.example", "GET", "/v1/x", fetch)
                .await
                .is_none());
        }
        let limited = tp
            .answer(None, "mainnet", "prices.example", "GET", "/v1/x", fetch)
            .await
            .expect("cap reached");
        assert_eq!(limited.status, 429);
        assert!(limited.headers.iter().any(|(k, _)| k == "retry-after"));
        // Another backend has its own budget (none configured: never limited).
        assert!(tp
            .answer(None, "mainnet", "swap.example", "GET", "/v0/tokens", fetch)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn unconfigured_changes_nothing() {
        let tp = ThirdParty::default();
        assert_eq!(tp.summary(), (0, 0));
        let fetch = || async { Err::<InnerResponse, _>(anyhow!("not called")) };
        assert!(tp
            .answer(None, "mainnet", "prices.example", "GET", "/v1/x", fetch)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn keyed_lock_serialises_one_key_and_forgets_it() {
        let lock = std::sync::Arc::new(KeyedLock::default());
        let running = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..4 {
            let (lock, running) = (lock.clone(), running.clone());
            tasks.push(tokio::spawn(async move {
                lock.run("k", async {
                    let now = running.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    assert_eq!(now, 0, "one holder at a time");
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    running.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                })
                .await
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert!(
            lock.locks.lock().is_empty(),
            "entry removed after the last holder"
        );
    }
}

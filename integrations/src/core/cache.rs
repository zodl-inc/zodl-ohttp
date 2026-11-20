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

//! `THIRD_PARTY_CACHE_ROUTES`: the third-party routes whose `200` answers the gateway caches,
//! and for how long (`authority=METHOD /path@TTL_SECS,...;authority2=...`, `GET` only, the path
//! in the route grammar of [`crate::core::route`]). The cache store and its single flight stay
//! in the gateway.

use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};

/// Cache route: method, path pattern, TTL in seconds.
#[derive(Clone, Debug)]
struct CacheRoute {
    method: String,
    path: String,
    ttl_secs: u64,
}

/// Per-backend cache routes.
#[derive(Clone, Debug)]
pub struct CacheRoutes {
    routes: HashMap<String, Vec<CacheRoute>>,
}

impl CacheRoutes {
    /// Parse `THIRD_PARTY_CACHE_ROUTES` (`authority=METHOD /path@TTL,...;authority2=...`).
    /// `restriction` is asked about every route (authority lowercase, method, path) after its
    /// method and path and before its TTL are checked; its error is the parse error (the
    /// restrictions of a provider kind, [`crate::registry::Aliases::check_cache_route`]).
    pub fn parse(s: &str, restriction: impl Fn(&str, &str, &str) -> Result<()>) -> Result<Self> {
        let mut routes = HashMap::new();
        for entry in s.split(';') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let Some((authority, policies)) = entry.split_once('=') else {
                bail!(
                    "Malformed THIRD_PARTY_CACHE_ROUTES: '{entry}' must be 'authority=METHOD /path@TTL,...'"
                );
            };
            let authority = authority.trim().to_ascii_lowercase();
            if authority.is_empty() {
                bail!("Malformed THIRD_PARTY_CACHE_ROUTES: missing authority in '{entry}'");
            }
            let mut list = Vec::new();
            for policy in policies.split(',') {
                let policy = policy.trim();
                if policy.is_empty() {
                    continue;
                }
                // Parse "METHOD /path@TTL"
                let Some((method_path, ttl_str)) = policy.split_once('@') else {
                    bail!(
                        "Malformed THIRD_PARTY_CACHE_ROUTES: '{policy}' must be 'METHOD /path@TTL' (entry: '{entry}')"
                    );
                };
                let Some((method, path)) = method_path.trim().split_once(' ') else {
                    bail!(
                        "Malformed THIRD_PARTY_CACHE_ROUTES: '{method_path}' must be 'METHOD /path' (entry: '{entry}')"
                    );
                };
                let method = method.trim().to_ascii_uppercase();
                if method != "GET" {
                    bail!(
                        "Invalid THIRD_PARTY_CACHE_ROUTES method '{method}' in '{policy}': only GET is allowed"
                    );
                }
                let path = path.trim().to_string();
                if !path.starts_with('/') {
                    bail!(
                        "Invalid THIRD_PARTY_CACHE_ROUTES path '{path}' in '{policy}': must start with /"
                    );
                }

                // The restrictions of the authority's provider kind (Flexa: never; NEAR: only
                // GET /v0/tokens).
                restriction(&authority, &method, &path)?;

                let ttl_str = ttl_str.trim();
                let ttl_secs = ttl_str.parse::<u64>().map_err(|_| {
                    anyhow!(
                        "Invalid THIRD_PARTY_CACHE_ROUTES TTL '{ttl_str}' in '{policy}': must be a positive integer"
                    )
                })?;
                if ttl_secs == 0 {
                    bail!(
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
                bail!("Malformed THIRD_PARTY_CACHE_ROUTES: no routes for authority '{authority}'");
            }
            routes.insert(authority, list);
        }
        if routes.is_empty() {
            bail!("Malformed THIRD_PARTY_CACHE_ROUTES: no entries");
        }
        Ok(Self { routes })
    }

    /// Find a matching route for (authority, method, path). Returns the TTL if found.
    pub fn find_ttl(&self, authority: &str, method: &str, path: &str) -> Option<u64> {
        let authority = authority.to_ascii_lowercase();
        let routes = self.routes.get(&authority)?;
        for route in routes {
            if method.eq_ignore_ascii_case(&route.method)
                && crate::core::route::path_matches(&route.path, path)
            {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn none(_: &str, _: &str, _: &str) -> Result<()> {
        Ok(())
    }

    #[test]
    fn routes_and_ttls() {
        let routes = CacheRoutes::parse(
            " A.example = get /v1/x@60 , GET /v2/*@5 ;b.example=GET /*@1;",
            none,
        )
        .unwrap();
        assert_eq!(routes.len(), 3);
        assert_eq!(routes.find_ttl("a.EXAMPLE", "get", "/v1/x?q=1"), Some(60));
        assert_eq!(routes.find_ttl("a.example", "GET", "/v1/x/y"), None);
        assert_eq!(routes.find_ttl("a.example", "GET", "/v2"), Some(5));
        assert_eq!(routes.find_ttl("a.example", "POST", "/v1/x"), None);
        assert_eq!(routes.find_ttl("b.example", "GET", "/z"), Some(1));
        assert_eq!(routes.find_ttl("c.example", "GET", "/z"), None);
        for (raw, expected) in [
            (";", "no entries"),
            ("a.example", "must be 'authority=METHOD /path@TTL,...'"),
            ("=GET /x@1", "missing authority"),
            ("a.example=GET /x", "must be 'METHOD /path@TTL'"),
            ("a.example=GET@1", "must be 'METHOD /path'"),
            ("a.example=POST /x@1", "only GET is allowed"),
            ("a.example=GET x@1", "must start with /"),
            ("a.example=GET /x@a", "must be a positive integer"),
            ("a.example=GET /x@0", "must be > 0"),
            ("a.example=,", "no routes for authority 'a.example'"),
        ] {
            let text = CacheRoutes::parse(raw, none).unwrap_err().to_string();
            assert!(text.contains(expected), "{raw}: {text}");
        }
    }

    #[test]
    fn the_restriction_runs_between_the_path_and_the_ttl() {
        let refuse = |authority: &str, method: &str, path: &str| -> Result<()> {
            bail!("refused {authority} {method} {path}")
        };
        let text = CacheRoutes::parse("A.example=get /x@abc", refuse)
            .unwrap_err()
            .to_string();
        assert_eq!(text, "refused a.example GET /x");
        // The method and path checks come first.
        let text = CacheRoutes::parse("a.example=POST /x@1", refuse)
            .unwrap_err()
            .to_string();
        assert!(text.contains("only GET"), "{text}");
    }
}

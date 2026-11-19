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

//! Parsers of the static alias tables, strict: a malformed entry is an error (it would otherwise
//! silently deny or open traffic), never skipped. Aliases are lowercased.
//!
//! - `BACKENDS`: `alias=url,...` (alias -> upstream base URL, `http://` or `https://`; the alias
//!   `lwd` is reserved).
//! - `BACKENDS_POLICY`: `alias=METHOD /path,METHOD /path;alias=...` (the operations an alias may
//!   forward, in the grammar of [`crate::core::route`]).
//! - `BACKEND_HEADERS`: `alias=Name:value,...` (headers set on every upstream request of the
//!   alias; an alias may be named more than once).

use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};

/// The reserved pseudo-alias of the gateway's own lightwalletd.
pub const LWD_LABEL: &str = "lwd";

/// Parse `BACKENDS` (empty: no alias).
pub fn parse_backends(raw: &str) -> Result<HashMap<String, String>> {
    let mut backends = HashMap::new();
    if raw.is_empty() {
        return Ok(backends);
    }
    for (i, pair) in raw.split(',').enumerate() {
        let trimmed = pair.trim();
        if trimmed.is_empty() {
            continue; // Allow trailing commas
        }
        if !trimmed.contains('=') {
            bail!(
                "Malformed BACKENDS entry at position {}: missing '=' in '{}' (format: 'alias=url')",
                i,
                trimmed
            );
        }
        let mut parts = trimmed.splitn(2, '=');
        let authority = parts.next().unwrap_or_default().trim();
        let url = parts.next().unwrap_or_default().trim();
        if authority.is_empty() {
            bail!(
                "Malformed BACKENDS entry at position {}: empty authority in '{}'",
                i,
                trimmed
            );
        }
        if url.is_empty() {
            bail!(
                "Malformed BACKENDS entry at position {}: empty URL in '{}'",
                i,
                trimmed
            );
        }
        // Lowercase authority for consistent matching (case-insensitive hostnames per RFC 3986)
        let authority_lower = authority.to_ascii_lowercase();
        // ZIP conformance: "lwd" is reserved for own-LWD, cannot be a backend alias
        if authority_lower == LWD_LABEL {
            bail!(
                "Malformed BACKENDS entry at position {}: '{}' is reserved (own-LWD label)",
                i,
                authority
            );
        }
        // Scheme check: require http:// or https:// (http:// is accepted, e.g. for testing)
        if !url.starts_with("https://") && !url.starts_with("http://") {
            bail!(
                "Malformed BACKENDS entry at position {}: URL must start with http:// or https:// in '{}'",
                i,
                trimmed
            );
        }
        backends.insert(authority_lower, url.to_string());
    }
    Ok(backends)
}

/// Parse `BACKENDS_POLICY` (empty: no policy). An authority named twice keeps its last entry.
pub fn parse_backends_policy(raw: &str) -> Result<HashMap<String, Vec<(String, String)>>> {
    let mut backends_policy: HashMap<String, Vec<(String, String)>> = HashMap::new();
    if raw.is_empty() {
        return Ok(backends_policy);
    }
    for entry in raw.split(';') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        if !entry.contains('=') {
            bail!("Malformed BACKENDS_POLICY entry (missing '='): {}", entry);
        }
        let mut parts = entry.splitn(2, '=');
        let authority = parts
            .next()
            .ok_or_else(|| {
                anyhow!(
                    "Malformed BACKENDS_POLICY: missing authority in '{}'",
                    entry
                )
            })?
            .trim()
            .to_ascii_lowercase();
        let policies = parts
            .next()
            .ok_or_else(|| anyhow!("Malformed BACKENDS_POLICY: missing policies in '{}'", entry))?
            .trim();

        let mut policy_list = Vec::new();
        for policy in policies.split(',') {
            let mut p = policy.trim().splitn(2, ' ');
            let method = p
                .next()
                .ok_or_else(|| {
                    anyhow!(
                        "Malformed BACKENDS_POLICY: missing method in '{}' (entry: '{}')",
                        policy,
                        entry
                    )
                })?
                .to_string();
            let path = p
                .next()
                .ok_or_else(|| {
                    anyhow!(
                        "Malformed BACKENDS_POLICY: missing path in '{}' (entry: '{}')",
                        policy,
                        entry
                    )
                })?
                .to_string();

            // A typo in the method would silently deny traffic.
            if !crate::core::route::is_policy_method(&method) {
                bail!(
                    "Invalid BACKENDS_POLICY method '{}' in '{}': must be GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH/* (typos silently deny traffic)",
                    method,
                    policy
                );
            }
            policy_list.push((method, path));
        }

        if policy_list.is_empty() {
            bail!(
                "Malformed BACKENDS_POLICY: no valid policies for authority '{}'",
                authority
            );
        }
        backends_policy.insert(authority, policy_list);
    }
    Ok(backends_policy)
}

/// Parse `BACKEND_HEADERS` (empty: no header).
pub fn parse_backend_headers(raw: &str) -> Result<HashMap<String, Vec<(String, String)>>> {
    let mut headers_map: HashMap<String, Vec<(String, String)>> = HashMap::new();
    if raw.is_empty() {
        return Ok(headers_map);
    }
    for (i, pair) in raw.split(',').enumerate() {
        let trimmed = pair.trim();
        if trimmed.is_empty() {
            continue; // Allow trailing commas
        }
        if !trimmed.contains('=') {
            bail!(
                "Malformed BACKEND_HEADERS entry at position {}: missing '=' in '{}' (format: 'alias=HeaderName:value')",
                i,
                trimmed
            );
        }
        let mut parts = trimmed.splitn(2, '=');
        let authority = parts.next().unwrap_or_default().trim();
        let header_pair = parts.next().unwrap_or_default().trim();
        if authority.is_empty() {
            bail!(
                "Malformed BACKEND_HEADERS entry at position {}: empty authority in '{}'",
                i,
                trimmed
            );
        }
        if !header_pair.contains(':') {
            bail!(
                "Malformed BACKEND_HEADERS entry at position {}: missing ':' in header '{}' (format: 'HeaderName:value')",
                i,
                header_pair
            );
        }
        let mut hp = header_pair.splitn(2, ':');
        let name = hp.next().unwrap_or_default().trim();
        let value = hp.next().unwrap_or_default().trim();
        if name.is_empty() {
            bail!(
                "Malformed BACKEND_HEADERS entry at position {}: empty header name in '{}'",
                i,
                trimmed
            );
        }
        headers_map
            .entry(authority.to_ascii_lowercase())
            .or_default()
            .push((name.to_string(), value.to_string()));
    }
    Ok(headers_map)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(r: Result<impl std::fmt::Debug>) -> String {
        r.expect_err("must fail").to_string()
    }

    #[test]
    fn backends() {
        let b = parse_backends(" A.example=https://a-api.example ,b.example=http://b:1,").unwrap();
        assert_eq!(b.len(), 2);
        assert_eq!(b["a.example"], "https://a-api.example");
        assert_eq!(b["b.example"], "http://b:1");
        assert!(parse_backends("").unwrap().is_empty());
        assert!(err(parse_backends("a.example")).contains("missing '='"));
        assert!(err(parse_backends("=https://x")).contains("empty authority"));
        assert!(err(parse_backends("a.example=")).contains("empty URL"));
        assert!(err(parse_backends("LWD=https://x")).contains("reserved"));
        assert!(err(parse_backends("a.example=ftp://x")).contains("must start with http"));
    }

    #[test]
    fn backends_policy() {
        let p = parse_backends_policy("A.example=GET /v1/x, post /y/*;b.example=* /*;").unwrap();
        assert_eq!(
            p["a.example"],
            vec![
                ("GET".to_string(), "/v1/x".to_string()),
                ("post".to_string(), "/y/*".to_string())
            ]
        );
        assert_eq!(p["b.example"], vec![("*".to_string(), "/*".to_string())]);
        // The last entry of an authority wins.
        let p = parse_backends_policy("a.example=GET /1;a.example=GET /2").unwrap();
        assert_eq!(p["a.example"], vec![("GET".to_string(), "/2".to_string())]);
        assert!(err(parse_backends_policy("a.example")).contains("missing '='"));
        assert!(err(parse_backends_policy("a.example=GET")).contains("missing path"));
        assert!(err(parse_backends_policy("a.example=GETS /x"))
            .contains("Invalid BACKENDS_POLICY method"));
        assert!(parse_backends_policy("").unwrap().is_empty());
    }

    #[test]
    fn backend_headers() {
        let h = parse_backend_headers("A.example=X-Key: v:1 ,a.example=Authorization:Bearer t")
            .unwrap();
        assert_eq!(
            h["a.example"],
            vec![
                ("X-Key".to_string(), "v:1".to_string()),
                ("Authorization".to_string(), "Bearer t".to_string())
            ]
        );
        assert!(err(parse_backend_headers("a.example")).contains("missing '='"));
        assert!(err(parse_backend_headers("=X:1")).contains("empty authority"));
        assert!(err(parse_backend_headers("a.example=X")).contains("missing ':'"));
        assert!(err(parse_backend_headers("a.example=:v")).contains("empty header name"));
    }
}

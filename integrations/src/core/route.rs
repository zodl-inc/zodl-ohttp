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

//! The route grammar of every `METHOD /path` list: the per-alias operation policy, the routes
//! of a dynamic host and the replay classes.
//!
//! - The method is `GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `PATCH` or `*` (any),
//!   compared without case.
//! - A path pattern is exact, a query string allowed (`/v0/tokens` matches `/v0/tokens` and
//!   `/v0/tokens?x=1`, not `/v0/tokens/x` or `/v0/tokensx`), unless it ends in `/*`, which is a
//!   segment-bounded prefix (`/rounds/*` matches `/rounds` and `/rounds/1`, not `/roundsx`);
//!   `/*` matches every path.
//! - The matchers are syntactic: they do not refuse a traversal or an encoded dot, or a double
//!   slash after the first byte. A caller checks [`path_trick`] first (the alias policy and the
//!   dynamic hosts do).

/// The methods a policy entry may name (upper case), besides `*`.
pub const METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"];

/// Whether `method` is a method token a policy entry may name: one of [`METHODS`] in any case,
/// or `*`.
pub fn is_policy_method(method: &str) -> bool {
    method == "*" || METHODS.iter().any(|m| method.eq_ignore_ascii_case(m))
}

/// Whether the entry method `allowed` (`*` or a method, any case) admits the request method.
pub fn method_matches(allowed: &str, method: &str) -> bool {
    allowed == "*" || method.eq_ignore_ascii_case(allowed)
}

/// Whether the path pattern `pattern` admits the request path `path` (see the module
/// documentation).
pub fn path_matches(pattern: &str, path: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/*") {
        prefix.is_empty() || path == prefix || path.starts_with(&format!("{prefix}/"))
    } else {
        path == pattern || path.starts_with(&format!("{pattern}?"))
    }
}

/// The first entry of `rules` (method, path pattern) that admits `method` and `path`.
pub fn matching_rule<'a>(
    rules: &'a [(String, String)],
    method: &str,
    path: &str,
) -> Option<&'a (String, String)> {
    rules.iter().find(|(allowed_method, pattern)| {
        method_matches(allowed_method, method) && path_matches(pattern, path)
    })
}

/// Why no pattern admits `path`, if a pattern never may: a directory traversal or an encoded dot,
/// or a double slash after the first byte.
pub fn path_trick(path: &str) -> Option<&'static str> {
    if path.contains("..") || path.contains("%2e") || path.contains("%2E") {
        return Some("path contains directory traversal");
    }
    // Bytes, since the path is not validated yet and may start with a multi-byte character.
    if path
        .as_bytes()
        .get(1..)
        .is_some_and(|rest| rest.windows(2).any(|w| w == b"//"))
    {
        return Some("path contains double slashes");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(m, p)| (m.to_string(), p.to_string()))
            .collect()
    }

    #[test]
    fn exact_pattern_allows_a_query_but_no_extension() {
        assert!(path_matches("/v0/tokens", "/v0/tokens"));
        assert!(path_matches("/v0/tokens", "/v0/tokens?a=1"));
        assert!(!path_matches("/v0/tokens", "/v0/tokens/x"));
        assert!(!path_matches("/v0/tokens", "/v0/tokensx"));
        assert!(!path_matches("/v0/tokens", "/v0"));
    }

    #[test]
    fn wildcard_pattern_is_segment_bounded() {
        assert!(path_matches("/rounds/*", "/rounds"));
        assert!(path_matches("/rounds/*", "/rounds/1"));
        assert!(path_matches("/rounds/*", "/rounds/1/2"));
        assert!(!path_matches("/rounds/*", "/roundsx"));
        assert!(!path_matches("/rounds/*", "/rounds?x"));
        assert!(path_matches("/*", "/anything"));
        assert!(path_matches("/*", ""));
    }

    #[test]
    fn method_wildcard_and_case() {
        assert!(method_matches("*", "PATCH"));
        assert!(method_matches("get", "GET"));
        assert!(method_matches("GET", "get"));
        assert!(!method_matches("GET", "POST"));
        assert!(is_policy_method("patch"));
        assert!(is_policy_method("*"));
        assert!(!is_policy_method("GETS"));
        assert!(!is_policy_method("TRACE"));
        assert!(!is_policy_method(""));
    }

    #[test]
    fn first_matching_entry_wins() {
        let r = rules(&[("GET", "/a/*"), ("*", "/*")]);
        assert_eq!(matching_rule(&r, "GET", "/a/b"), Some(&r[0]));
        assert_eq!(matching_rule(&r, "POST", "/a/b"), Some(&r[1]));
        assert_eq!(matching_rule(&rules(&[("GET", "/a")]), "GET", "/b"), None);
    }

    #[test]
    fn path_tricks() {
        assert!(path_trick("/a/../b").is_some());
        assert!(path_trick("/a/%2e%2e/b").is_some());
        assert!(path_trick("/a/%2E/b").is_some());
        assert!(path_trick("/a//b").is_some());
        // The first byte is not checked: a leading "//" is left to the path validation.
        assert_eq!(path_trick("//a"), None);
        assert!(path_trick("///a").is_some());
        assert_eq!(path_trick("/a/b?c=d"), None);
        assert_eq!(path_trick("/"), None);
        assert_eq!(path_trick("é//"), Some("path contains double slashes"));
    }
}

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

//! The provider of an alias, looked up in the static alias tables.

use std::collections::HashMap;

use crate::generic::Generic;

/// A view of the static alias tables (`BACKENDS`, `BACKENDS_POLICY`, `BACKENDS_POLICY_DEFAULT`,
/// `BACKEND_HEADERS`), borrowed from the gateway's configuration: it owns nothing, so the tables
/// stay the one source of truth.
#[derive(Clone, Copy, Debug)]
pub struct Registry<'a> {
    pub backends: &'a HashMap<String, String>,
    pub policy: &'a HashMap<String, Vec<(String, String)>>,
    pub default_allow: bool,
    pub headers: &'a HashMap<String, Vec<(String, String)>>,
}

impl<'a> Registry<'a> {
    /// The provider of `alias` (lowercase), `None` when it is not a `BACKENDS` alias.
    pub fn provider(&self, alias: &str) -> Option<Generic<'a>> {
        self.backends.contains_key(alias).then(|| Generic {
            policy: self.policy.get(alias).map(Vec::as_slice),
            default_allow: self.default_allow,
            headers: self.headers.get(alias).map(Vec::as_slice).unwrap_or(&[]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::policy::{parse_backend_headers, parse_backends, parse_backends_policy};
    use crate::core::provider::{Denial, Provider, RequestView};

    #[test]
    fn aliases_resolve_to_their_tables() {
        let backends = parse_backends("a.example=https://a,b.example=https://b").unwrap();
        let policy = parse_backends_policy("a.example=GET /x;gw.example=POST /*").unwrap();
        let headers = parse_backend_headers("a.example=X-Key:k").unwrap();
        let registry = Registry {
            backends: &backends,
            policy: &policy,
            default_allow: false,
            headers: &headers,
        };
        let req = |method, path| RequestView {
            method,
            path,
            headers: &[],
            body: &[],
        };
        let a = registry.provider("a.example").unwrap();
        assert!(a.admit(&req("GET", "/x")).is_ok());
        assert_eq!(a.headers, headers["a.example"].as_slice());
        let b = registry.provider("b.example").unwrap();
        assert_eq!(b.admit(&req("GET", "/x")), Err(Denial::NoPolicy));
        assert!(b.headers.is_empty());
        // A policy entry alone (a gateway host) is no alias.
        assert!(registry.provider("gw.example").is_none());
        assert!(registry.provider("A.example").is_none());
    }
}

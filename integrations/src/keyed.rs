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

//! Keyed providers: a generic provider whose alias authenticates with a header the gateway adds
//! (a key that spends a quota) and whose every route has a `THIRD_PARTY_QUERY_RULES` rule, so the
//! key never answers a query of the client's choosing (each distinct query is also a new cache
//! key). A [`Keyed`] provider only exists with both invariants met ([`Keyed::new`]); the kinds
//! `cmc` and `swapkit` are keyed providers.
//!
//! The query rules themselves are evaluated by the gateway with every alias's
//! ([`crate::core::query`]).

use std::time::SystemTime;

use crate::core::provider::{Admitted, Denial, Provider, RequestView, ResponseAction};
use crate::core::query::QueryRules;
use crate::generic::Generic;

/// Startup invariant of a provider kind whose credential spends a quota: every entry of the
/// alias's operation policy has a query rule for its method on its exact path, so no admitted
/// operation reaches the upstream with a query of the client's choosing (an entry with a `*`
/// method or a `/*` prefix can have none). `kind` names the provider in the error.
fn require_query_rule_per_route(
    kind: &str,
    alias: &str,
    policy: Option<&[(String, String)]>,
    rules: &crate::core::query::QueryRules,
) -> anyhow::Result<()> {
    let Some(policy) = policy.filter(|p| !p.is_empty()) else {
        anyhow::bail!(
            "Invalid {kind} integration '{alias}': it needs an operation policy whose every route has a query rule"
        );
    };
    for (method, path) in policy {
        if !rules.has_rule(alias, method, path) {
            anyhow::bail!(
                "Invalid {kind} integration '{alias}': route '{} {path}' has no query rule (every route of a {kind} integration needs one)",
                method.to_ascii_uppercase()
            );
        }
    }
    Ok(())
}

/// Startup invariant of a provider kind that authenticates with a header: the alias has at
/// least one upstream header. `kind` names the provider in the error.
fn require_header_credential(
    kind: &str,
    alias: &str,
    headers: &[(String, String)],
) -> anyhow::Result<()> {
    if headers.is_empty() {
        anyhow::bail!("Invalid {kind} integration '{alias}': it needs a header credential");
    }
    Ok(())
}

/// A keyed provider of kind `kind`: the generic provider of its alias, its invariants checked.
#[derive(Clone, Copy, Debug)]
pub struct Keyed<'a> {
    kind: &'static str,
    generic: Generic<'a>,
}

impl<'a> Keyed<'a> {
    /// The `kind` provider of `alias` over `generic`, refused unless the alias carries a header
    /// credential and every route of its policy has a query rule in `rules`.
    pub fn new(
        kind: &'static str,
        alias: &str,
        generic: Generic<'a>,
        rules: &QueryRules,
    ) -> anyhow::Result<Self> {
        require_header_credential(kind, alias, generic.headers)?;
        require_query_rule_per_route(kind, alias, generic.policy, rules)?;
        Ok(Self { kind, generic })
    }

    /// The generic provider underneath.
    pub fn generic(&self) -> &Generic<'a> {
        &self.generic
    }
}

impl Provider for Keyed<'_> {
    fn kind(&self) -> &'static str {
        self.kind
    }

    fn admit(&self, req: &RequestView<'_>) -> Result<Admitted, Denial> {
        self.generic.admit(req)
    }

    fn upstream_headers(
        &self,
        req: &RequestView<'_>,
        admitted: &Admitted,
        now: SystemTime,
    ) -> Result<Vec<(String, String)>, Denial> {
        self.generic.upstream_headers(req, admitted, now)
    }

    fn response(&self, admitted: &Admitted, status: u16) -> ResponseAction {
        self.generic.response(admitted, status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::policy::{parse_backend_headers, parse_backends_policy};

    fn check_with(policy: &str, rules: &str, headers: &str) -> Result<(), String> {
        let policy = parse_backends_policy(policy).unwrap();
        let headers = parse_backend_headers(headers).unwrap();
        let rules = if rules.is_empty() {
            QueryRules::default()
        } else {
            QueryRules::parse(rules).unwrap()
        };
        let generic = Generic {
            policy: policy.get("api.example").map(Vec::as_slice),
            default_allow: false,
            headers: headers.get("api.example").map(Vec::as_slice).unwrap_or(&[]),
        };
        Keyed::new("cmc", "api.example", generic, &rules)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    const POLICY: &str = "api.example=GET /v1/a,post /v1/b";
    const RULES: &str = "api.example=GET /v1/a?id={in:X|Y},POST /v1/b?";
    const KEY: &str = "api.example=X-Api-Key:k";

    #[test]
    fn every_route_needs_a_query_rule() {
        check_with(POLICY, RULES, KEY).unwrap();
        // A second rule for a route is fine; a route without one is not.
        check_with(
            POLICY,
            "api.example=GET /v1/a?id=X,GET /v1/a?,POST /v1/b?",
            KEY,
        )
        .unwrap();
        let text = check_with(POLICY, "api.example=GET /v1/a?id=X", KEY).unwrap_err();
        assert!(
            text.contains("route 'POST /v1/b' has no query rule") && text.contains("cmc"),
            "{text}"
        );
        // A rule of another method or alias does not count.
        let text = check_with(POLICY, "api.example=GET /v1/a?,GET /v1/b?", KEY).unwrap_err();
        assert!(text.contains("'POST /v1/b'"), "{text}");
        let text = check_with(POLICY, "other.example=GET /v1/a?,POST /v1/b?", KEY).unwrap_err();
        assert!(text.contains("'GET /v1/a'"), "{text}");
        // Entries no exact rule can cover.
        let text = check_with("api.example=GET /v1/*", "api.example=GET /v1/x?", KEY).unwrap_err();
        assert!(text.contains("'GET /v1/*'"), "{text}");
        let text = check_with("api.example=* /v1/a", "api.example=GET /v1/a?", KEY).unwrap_err();
        assert!(text.contains("'* /v1/a'"), "{text}");
        // No policy at all.
        let text = check_with("", RULES, KEY).unwrap_err();
        assert!(text.contains("needs an operation policy"), "{text}");
    }

    #[test]
    fn a_header_credential_is_required() {
        let text = check_with(POLICY, RULES, "").unwrap_err();
        assert!(
            text.contains("needs a header credential") && text.contains("'api.example'"),
            "{text}"
        );
        let text = check_with(POLICY, RULES, "other.example=X-Api-Key:k").unwrap_err();
        assert!(text.contains("needs a header credential"), "{text}");
    }

    #[test]
    fn behaves_as_the_generic_provider() {
        let policy = parse_backends_policy(POLICY).unwrap();
        let headers = parse_backend_headers(KEY).unwrap();
        let generic = Generic {
            policy: policy.get("api.example").map(Vec::as_slice),
            default_allow: false,
            headers: &headers["api.example"],
        };
        let rules = QueryRules::parse(RULES).unwrap();
        let provider = Keyed::new("swapkit", "api.example", generic, &rules).unwrap();
        assert_eq!(provider.kind(), "swapkit");
        assert_eq!(provider.generic().headers, generic.headers);
        for (method, path) in [
            ("GET", "/v1/a?id=Z"),
            ("POST", "/v1/b"),
            ("GET", "/v1/b"),
            ("GET", "/v1/a/../b"),
        ] {
            let req = RequestView {
                method,
                path,
                headers: &[],
                body: &[],
            };
            let admitted = provider.admit(&req);
            assert_eq!(admitted, generic.admit(&req), "{method} {path}");
            if let Ok(admitted) = admitted {
                assert_eq!(
                    provider.upstream_headers(&req, &admitted, SystemTime::UNIX_EPOCH),
                    Ok(headers["api.example"].clone())
                );
                assert_eq!(provider.response(&admitted, 502), ResponseAction::Pass);
            }
        }
    }

    #[cfg(all(feature = "cmc", feature = "swapkit"))]
    #[test]
    fn the_kinds_are_keyed_providers() {
        let policy = parse_backends_policy(POLICY).unwrap();
        let headers = parse_backend_headers(KEY).unwrap();
        let generic = Generic {
            policy: policy.get("api.example").map(Vec::as_slice),
            default_allow: false,
            headers: &headers["api.example"],
        };
        let rules = QueryRules::parse(RULES).unwrap();
        assert_eq!(
            crate::cmc::new("api.example", generic, &rules)
                .unwrap()
                .kind(),
            "cmc"
        );
        assert_eq!(
            crate::swapkit::new("api.example", generic, &rules)
                .unwrap()
                .kind(),
            "swapkit"
        );
        let partial = QueryRules::parse("api.example=GET /v1/a?").unwrap();
        for text in [
            crate::cmc::new("api.example", generic, &partial)
                .unwrap_err()
                .to_string(),
            crate::swapkit::new("api.example", generic, &partial)
                .unwrap_err()
                .to_string(),
        ] {
            assert!(
                text.contains("route 'POST /v1/b' has no query rule"),
                "{text}"
            );
        }
    }
}

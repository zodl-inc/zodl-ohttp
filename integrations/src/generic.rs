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

//! The declarative provider: an alias with an operation policy and fixed upstream headers, no
//! credential logic of its own.

use std::time::SystemTime;

use crate::core::provider::{Admitted, Denial, Provider, RequestView, ResponseAction};
use crate::core::route;

/// The operation policy of one authority: `policy` is its entry list, `None` when it has none,
/// in which case `default_allow` decides.
///
/// Also the check of a gateway host that has a policy entry; there `known` is `false` and an
/// authority without entries is never refused.
pub fn check_policy<'a>(
    policy: Option<&'a [(String, String)]>,
    known: bool,
    default_allow: bool,
    method: &str,
    path: &str,
) -> Result<Option<&'a (String, String)>, Denial> {
    if let Some(reason) = route::path_trick(path) {
        return Err(Denial::PathTrick(reason));
    }
    match policy {
        Some(rules) => route::matching_rule(rules, method, path)
            .map(Some)
            .ok_or(Denial::NotInPolicy),
        None if known && !default_allow => Err(Denial::NoPolicy),
        None => Ok(None),
    }
}

/// A generic provider, borrowing its tables from the gateway's configuration.
#[derive(Clone, Copy, Debug)]
pub struct Generic<'a> {
    /// The operation policy of the alias (`BACKENDS_POLICY`), `None` when it has none.
    pub policy: Option<&'a [(String, String)]>,
    /// `BACKENDS_POLICY_DEFAULT=allow`: an alias without a policy admits every operation.
    pub default_allow: bool,
    /// The fixed upstream headers of the alias (`BACKEND_HEADERS`).
    pub headers: &'a [(String, String)],
}

impl Provider for Generic<'_> {
    fn kind(&self) -> &'static str {
        "generic"
    }

    fn admit(&self, req: &RequestView<'_>) -> Result<Admitted, Denial> {
        check_policy(self.policy, true, self.default_allow, req.method, req.path).map(|rule| {
            Admitted {
                rule: rule.cloned(),
            }
        })
    }

    fn upstream_headers(
        &self,
        _req: &RequestView<'_>,
        _admitted: &Admitted,
        _now: SystemTime,
    ) -> Result<Vec<(String, String)>, Denial> {
        Ok(self.headers.to_vec())
    }

    fn response(&self, _admitted: &Admitted, _status: u16) -> ResponseAction {
        ResponseAction::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(m, p)| (m.to_string(), p.to_string()))
            .collect()
    }

    fn req<'a>(method: &'a str, path: &'a str) -> RequestView<'a> {
        RequestView {
            method,
            path,
            headers: &[],
            body: &[],
        }
    }

    #[test]
    fn policy_admits_listed_operations_only() {
        let policy = rules(&[("GET", "/v0/tokens"), ("POST", "/v0/quote")]);
        let p = Generic {
            policy: Some(&policy),
            default_allow: true,
            headers: &[],
        };
        let admitted = p.admit(&req("GET", "/v0/tokens?x=1")).unwrap();
        assert_eq!(admitted.rule, Some(policy[0].clone()));
        assert_eq!(
            p.admit(&req("POST", "/v0/tokens")),
            Err(Denial::NotInPolicy)
        );
        assert_eq!(
            p.admit(&req("GET", "/v0/../v0/tokens")),
            Err(Denial::PathTrick("path contains directory traversal"))
        );
    }

    #[test]
    fn no_policy_follows_the_default() {
        let deny = Generic {
            policy: None,
            default_allow: false,
            headers: &[],
        };
        assert_eq!(deny.admit(&req("GET", "/x")), Err(Denial::NoPolicy));
        let allow = Generic {
            default_allow: true,
            ..deny
        };
        assert_eq!(allow.admit(&req("GET", "/x")).unwrap().rule, None);
        // A path trick is refused even then.
        assert!(matches!(
            allow.admit(&req("GET", "/a//b")),
            Err(Denial::PathTrick(_))
        ));
    }

    #[test]
    fn unknown_authority_without_policy_is_not_refused() {
        assert_eq!(check_policy(None, false, false, "GET", "/x"), Ok(None));
    }

    #[test]
    fn headers_are_the_configured_ones() {
        let headers = rules(&[("X-Key", "k")]);
        let p = Generic {
            policy: None,
            default_allow: true,
            headers: &headers,
        };
        let r = req("GET", "/");
        let admitted = p.admit(&r).unwrap();
        assert_eq!(
            p.upstream_headers(&r, &admitted, SystemTime::UNIX_EPOCH),
            Ok(headers.clone())
        );
        assert_eq!(p.response(&admitted, 500), ResponseAction::Pass);
        assert_eq!(p.kind(), "generic");
        assert_eq!(
            Denial::NotInPolicy.reason(),
            "operation not in alias policy"
        );
        assert_eq!(Denial::NoPolicy.reason(), "alias has no operation policy");
    }
}

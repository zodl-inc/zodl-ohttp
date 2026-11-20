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
//!
//! An alias named by `FLEXA_ALIAS` is a [`crate::flexa`] provider, one named by `NEAR_ALIAS` a
//! [`crate::near`] provider, any other `BACKENDS` alias a generic one.

use std::collections::HashMap;
use std::time::SystemTime;

use crate::core::provider::{Admitted, Denial, Provider, RequestView, ResponseAction};
use crate::generic::Generic;

/// The aliases the environment gives a provider kind (`FLEXA_ALIAS`, `NEAR_ALIAS`), lowercase.
#[derive(Clone, Copy, Debug, Default)]
pub struct Aliases<'a> {
    /// Never cacheable (per-user answers).
    pub flexa: Option<&'a str>,
    /// Only `GET /v0/tokens` is cacheable.
    pub near: Option<&'a str>,
}

impl Aliases<'_> {
    /// The cache restriction of the kind of `authority` (lowercase) for its
    /// `THIRD_PARTY_CACHE_ROUTES` route `method path` ([`crate::core::cache::CacheRoutes::parse`]):
    /// none for the Flexa alias, only `GET /v0/tokens` for the NEAR alias. Applied whether or
    /// not the provider of the kind is built.
    pub fn check_cache_route(
        &self,
        authority: &str,
        method: &str,
        path: &str,
    ) -> anyhow::Result<()> {
        if self.flexa == Some(authority) {
            crate::flexa::check_cache_route(authority)?;
        }
        if self.near == Some(authority) {
            crate::near::check_cache_route(authority, method, path)?;
        }
        Ok(())
    }

    /// An error when an alias is named for a kind whose provider this build lacks (cargo
    /// feature `flexa` or `near` off): such an alias would lose its handling, so the gateway
    /// refuses to start.
    pub fn check_built(&self) -> anyhow::Result<()> {
        #[cfg(not(feature = "flexa"))]
        if let Some(alias) = self.flexa {
            anyhow::bail!(
                "FLEXA_ALIAS is set ({alias}) but this build has no Flexa provider (cargo feature 'flexa')"
            );
        }
        #[cfg(not(feature = "near"))]
        if let Some(alias) = self.near {
            anyhow::bail!(
                "NEAR_ALIAS is set ({alias}) but this build has no NEAR provider (cargo feature 'near')"
            );
        }
        Ok(())
    }
}

/// A view of the static alias tables (`BACKENDS`, `BACKENDS_POLICY`, `BACKENDS_POLICY_DEFAULT`,
/// `BACKEND_HEADERS`, `FLEXA_ALIAS`, `NEAR_ALIAS`, `FLEXA_PUBLISHABLE_KEY`), borrowed from the
/// gateway's configuration: it owns nothing, so the tables stay the one source of truth.
#[derive(Clone, Copy, Debug)]
pub struct Registry<'a> {
    pub backends: &'a HashMap<String, String>,
    pub policy: &'a HashMap<String, Vec<(String, String)>>,
    pub default_allow: bool,
    pub headers: &'a HashMap<String, Vec<(String, String)>>,
    /// The aliases of the provider kinds.
    pub aliases: Aliases<'a>,
    /// The Flexa publishable key.
    pub flexa_key: Option<&'a str>,
}

impl<'a> Registry<'a> {
    /// The generic view of `alias` (lowercase): its route policy and fixed headers, whatever its
    /// kind ([`Self::integration`]); `None` when it is not a `BACKENDS` alias.
    pub fn provider(&self, alias: &str) -> Option<Generic<'a>> {
        self.backends.contains_key(alias).then(|| Generic {
            policy: self.policy.get(alias).map(Vec::as_slice),
            default_allow: self.default_allow,
            headers: self.headers.get(alias).map(Vec::as_slice).unwrap_or(&[]),
        })
    }

    /// The provider of `alias` (lowercase), `None` when it is not a `BACKENDS` alias. An alias
    /// named for a kind whose provider is not built gets the generic provider (its policy, no
    /// forwarded header); [`Aliases::check_built`] refuses that configuration at startup.
    pub fn integration(&self, alias: &str) -> Option<Integration<'a>> {
        let generic = self.provider(alias)?;
        #[cfg(feature = "flexa")]
        if self.aliases.flexa == Some(alias) {
            return Some(Integration::Flexa(crate::flexa::Flexa {
                generic,
                publishable_key: self.flexa_key,
            }));
        }
        #[cfg(feature = "near")]
        if self.aliases.near == Some(alias) {
            return Some(Integration::Near(crate::near::Near { generic }));
        }
        Some(Integration::Generic(generic))
    }

    /// The headers forwarded besides the gateway's allowlist on a request to `authority`
    /// (lowercase; not a dynamic host): those of its provider. An authority that is no
    /// `BACKENDS` alias gets the Flexa headers when `FLEXA_ALIAS` names it (a configuration the
    /// gateway warns about at startup), as it always has.
    pub fn forwarded_headers(
        &self,
        authority: &str,
        req: &RequestView<'_>,
    ) -> Vec<(String, String)> {
        match self.integration(authority) {
            Some(provider) => provider.forwarded_headers(req),
            #[cfg(feature = "flexa")]
            None if crate::flexa::is_alias(self.aliases.flexa, authority) => {
                crate::flexa::upstream_headers(req.headers, self.flexa_key)
            }
            None => Vec::new(),
        }
    }
}

/// The provider of an alias, of one of the kinds the registry assigns.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum Integration<'a> {
    Generic(Generic<'a>),
    #[cfg(feature = "flexa")]
    Flexa(crate::flexa::Flexa<'a>),
    #[cfg(feature = "near")]
    Near(crate::near::Near<'a>),
}

impl Integration<'_> {
    fn get(&self) -> &dyn Provider {
        match self {
            Integration::Generic(p) => p,
            #[cfg(feature = "flexa")]
            Integration::Flexa(p) => p,
            #[cfg(feature = "near")]
            Integration::Near(p) => p,
        }
    }
}

impl Provider for Integration<'_> {
    fn kind(&self) -> &'static str {
        self.get().kind()
    }

    fn admit(&self, req: &RequestView<'_>) -> Result<Admitted, Denial> {
        self.get().admit(req)
    }

    fn forwarded_headers(&self, req: &RequestView<'_>) -> Vec<(String, String)> {
        self.get().forwarded_headers(req)
    }

    fn upstream_headers(
        &self,
        req: &RequestView<'_>,
        admitted: &Admitted,
        now: SystemTime,
    ) -> Result<Vec<(String, String)>, Denial> {
        self.get().upstream_headers(req, admitted, now)
    }

    fn response(&self, admitted: &Admitted, status: u16) -> ResponseAction {
        self.get().response(admitted, status)
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
            aliases: Aliases::default(),
            flexa_key: None,
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

    #[cfg(all(feature = "flexa", feature = "near"))]
    #[test]
    fn the_kind_aliases_get_their_providers() {
        let backends =
            parse_backends("pay.example=https://p,swap.example=https://s,a.example=https://a")
                .unwrap();
        let policy =
            parse_backends_policy("pay.example=POST /tokens;swap.example=GET /v0/tokens").unwrap();
        let headers =
            parse_backend_headers("swap.example=Authorization:Bearer t,pay.example=X-P:1").unwrap();
        let registry = Registry {
            backends: &backends,
            policy: &policy,
            default_allow: true,
            headers: &headers,
            aliases: Aliases {
                flexa: Some("pay.example"),
                near: Some("swap.example"),
            },
            flexa_key: Some("real"),
        };
        let kind = |alias: &str| registry.integration(alias).map(|p| p.kind());
        assert_eq!(kind("pay.example"), Some("flexa"));
        assert_eq!(kind("swap.example"), Some("near"));
        assert_eq!(kind("a.example"), Some("generic"));
        assert_eq!(kind("gw.example"), None);
        let client = vec![
            (
                "Authorization".to_string(),
                crate::flexa::basic_authorization(crate::flexa::PLACEHOLDER_PUBLISHABLE_KEY),
            ),
            ("Accept".to_string(), "text/event-stream".to_string()),
        ];
        let req = |method, path| RequestView {
            method,
            path,
            headers: &client,
            body: &[],
        };
        let flexa_headers = vec![
            ("accept".to_string(), "text/event-stream".to_string()),
            (
                "authorization".to_string(),
                crate::flexa::basic_authorization("real"),
            ),
        ];
        assert_eq!(
            registry.forwarded_headers("pay.example", &req("POST", "/tokens")),
            flexa_headers
        );
        assert!(registry
            .forwarded_headers("swap.example", &req("GET", "/v0/tokens"))
            .is_empty());
        assert!(registry
            .forwarded_headers("a.example", &req("GET", "/"))
            .is_empty());
        // The generic behaviour and headers whatever the kind.
        let near = registry.integration("swap.example").unwrap();
        let admitted = near.admit(&req("GET", "/v0/tokens")).unwrap();
        assert_eq!(
            near.upstream_headers(&req("GET", "/v0/tokens"), &admitted, SystemTime::UNIX_EPOCH),
            Ok(headers["swap.example"].clone())
        );
        assert_eq!(
            near.admit(&req("POST", "/v0/quote")),
            Err(Denial::NotInPolicy)
        );
        assert_eq!(near.response(&admitted, 500), ResponseAction::Pass);
        // FLEXA_ALIAS naming an authority outside BACKENDS: its Flexa headers as before.
        let unlisted = Registry {
            aliases: Aliases {
                flexa: Some("gw.example"),
                near: None,
            },
            ..registry
        };
        assert!(unlisted.integration("gw.example").is_none());
        assert_eq!(
            unlisted.forwarded_headers("gw.example", &req("POST", "/x")),
            flexa_headers
        );
    }

    #[test]
    fn cache_restrictions_of_the_kinds() {
        let aliases = Aliases {
            flexa: Some("pay.example"),
            near: Some("swap.example"),
        };
        assert!(aliases
            .check_cache_route("pay.example", "GET", "/brands")
            .unwrap_err()
            .to_string()
            .contains("(FLEXA_ALIAS) answers are per user"));
        aliases
            .check_cache_route("swap.example", "GET", "/v0/tokens")
            .unwrap();
        assert!(aliases
            .check_cache_route("swap.example", "GET", "/v0/status")
            .unwrap_err()
            .to_string()
            .contains("(NEAR_ALIAS) '/v0/status' is not cacheable"));
        aliases
            .check_cache_route("other.example", "GET", "/v0/status")
            .unwrap();
        Aliases::default()
            .check_cache_route("pay.example", "GET", "/brands")
            .unwrap();
    }

    #[cfg(not(feature = "flexa"))]
    #[test]
    fn without_the_flexa_feature_its_alias_is_refused_and_never_cacheable() {
        let aliases = Aliases {
            flexa: Some("pay.example"),
            near: None,
        };
        let text = aliases.check_built().unwrap_err().to_string();
        assert!(text.contains("FLEXA_ALIAS is set (pay.example)"), "{text}");
        assert!(aliases
            .check_cache_route("pay.example", "GET", "/brands")
            .unwrap_err()
            .to_string()
            .contains("(FLEXA_ALIAS) answers are per user"));
        // The policy still applies, nothing is forwarded.
        let backends = parse_backends("pay.example=https://p").unwrap();
        let policy = parse_backends_policy("pay.example=POST /tokens").unwrap();
        let headers = parse_backend_headers("").unwrap();
        let registry = Registry {
            backends: &backends,
            policy: &policy,
            default_allow: true,
            headers: &headers,
            aliases,
            flexa_key: Some("real"),
        };
        let client = vec![("Authorization".to_string(), "Basic x".to_string())];
        let req = |method, path| RequestView {
            method,
            path,
            headers: &client,
            body: &[],
        };
        let provider = registry.integration("pay.example").unwrap();
        assert_eq!(provider.kind(), "generic");
        assert_eq!(
            provider.admit(&req("GET", "/tokens")),
            Err(Denial::NotInPolicy)
        );
        assert!(registry
            .forwarded_headers("pay.example", &req("POST", "/tokens"))
            .is_empty());
    }

    #[cfg(not(feature = "near"))]
    #[test]
    fn without_the_near_feature_its_alias_is_refused_and_restricted() {
        let aliases = Aliases {
            flexa: None,
            near: Some("swap.example"),
        };
        let text = aliases.check_built().unwrap_err().to_string();
        assert!(text.contains("NEAR_ALIAS is set (swap.example)"), "{text}");
        aliases
            .check_cache_route("swap.example", "GET", "/v0/tokens")
            .unwrap();
        assert!(aliases
            .check_cache_route("swap.example", "GET", "/v0/status")
            .unwrap_err()
            .to_string()
            .contains("(NEAR_ALIAS) '/v0/status' is not cacheable"));
    }

    #[cfg(all(feature = "flexa", feature = "near"))]
    #[test]
    fn with_both_features_every_alias_is_built() {
        Aliases {
            flexa: Some("pay.example"),
            near: Some("swap.example"),
        }
        .check_built()
        .unwrap();
    }
}

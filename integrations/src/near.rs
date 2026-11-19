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

//! NEAR Intents 1Click API alias: the `BACKENDS` entry named by `NEAR_ALIAS`. Its credential is a
//! bearer header (`Authorization: Bearer {secret}`, a `BACKEND_HEADERS` entry with the
//! environment variables). Only `GET /v0/tokens` (the public token list) may be cached:
//! `POST /v0/quote` creates a quote and a deposit address, `GET /v0/status` is per deposit,
//! `POST /v0/deposit/submit` writes ([`check_cache_route`]). Without `NEAR_ALIAS` no alias gets
//! this restriction.

#[cfg(feature = "near")]
use std::time::SystemTime;

use crate::core::auth::Header;
#[cfg(feature = "near")]
use crate::core::provider::{Admitted, Denial, Provider, RequestView, ResponseAction};
#[cfg(feature = "near")]
use crate::generic::Generic;

/// The provider kind.
pub const KIND: &str = "near";

/// The one cacheable route.
pub const CACHEABLE: (&str, &str) = ("GET", "/v0/tokens");

/// The bearer credential of the alias: `Authorization: Bearer {secret}`.
pub fn bearer(secret: &str) -> Header<'_> {
    Header {
        name: "Authorization",
        value: "Bearer {secret}",
        secret: Some(secret),
    }
}

/// The startup restriction of the NEAR alias's `THIRD_PARTY_CACHE_ROUTES` (`method` uppercase):
/// only [`CACHEABLE`].
pub fn check_cache_route(authority: &str, method: &str, path: &str) -> anyhow::Result<()> {
    // Deny: POST /v0/quote (creates quote+address), GET /v0/status (per-deposit state),
    // POST /v0/deposit/submit, and any non-GET.
    if method != CACHEABLE.0 {
        anyhow::bail!(
            "Invalid THIRD_PARTY_CACHE_ROUTES: {} (NEAR_ALIAS) non-GET '{}' is not cacheable (only GET /v0/tokens allowed)",
            authority,
            method
        );
    }
    // Only /v0/tokens is allowed
    if path != CACHEABLE.1 {
        anyhow::bail!(
            "Invalid THIRD_PARTY_CACHE_ROUTES: {} (NEAR_ALIAS) '{}' is not cacheable \
             (only GET /v0/tokens allowed; POST /v0/quote, GET /v0/status, POST /v0/deposit/submit are denied)",
            authority,
            path
        );
    }
    Ok(())
}

#[cfg(feature = "near")]
/// The NEAR provider: the generic provider of the alias (its bearer header among the alias's
/// headers).
#[derive(Clone, Copy, Debug)]
pub struct Near<'a> {
    pub generic: Generic<'a>,
}

#[cfg(feature = "near")]
impl Provider for Near<'_> {
    fn kind(&self) -> &'static str {
        KIND
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

    #[test]
    fn only_the_token_list_is_cacheable() {
        check_cache_route("swap.example", "GET", "/v0/tokens").unwrap();
        let text = check_cache_route("swap.example", "GET", "/v0/status")
            .unwrap_err()
            .to_string();
        assert_eq!(
            text,
            "Invalid THIRD_PARTY_CACHE_ROUTES: swap.example (NEAR_ALIAS) '/v0/status' is not cacheable \
             (only GET /v0/tokens allowed; POST /v0/quote, GET /v0/status, POST /v0/deposit/submit are denied)"
        );
        for path in [
            "/v0/quote",
            "/v0/deposit/submit",
            "/v0/tokens/x",
            "/v0/tokens?x=1",
        ] {
            assert!(
                check_cache_route("swap.example", "GET", path).is_err(),
                "{path}"
            );
        }
        let text = check_cache_route("swap.example", "POST", "/v0/tokens")
            .unwrap_err()
            .to_string();
        assert!(text.contains("(NEAR_ALIAS) non-GET 'POST'"), "{text}");
    }

    #[cfg(feature = "near")]
    #[test]
    fn the_bearer_header_and_the_generic_behaviour() {
        assert_eq!(
            bearer("jwt.a.b").header(),
            ("Authorization".to_string(), "Bearer jwt.a.b".to_string())
        );
        let policy = vec![("GET".to_string(), "/v0/tokens".to_string())];
        let headers = vec![bearer("jwt.a.b").header()];
        let provider = Near {
            generic: Generic {
                policy: Some(&policy),
                default_allow: false,
                headers: &headers,
            },
        };
        let req = RequestView {
            method: "GET",
            path: "/v0/tokens",
            headers: &[],
            body: &[],
        };
        let admitted = provider.admit(&req).unwrap();
        assert_eq!(provider.kind(), "near");
        assert_eq!(
            provider.upstream_headers(&req, &admitted, SystemTime::UNIX_EPOCH),
            Ok(headers.clone())
        );
        assert!(provider.forwarded_headers(&req).is_empty());
        assert_eq!(provider.response(&admitted, 401), ResponseAction::Pass);
    }
}

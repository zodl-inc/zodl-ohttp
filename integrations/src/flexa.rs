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

//! Flexa API alias: the `BACKENDS` entry named by `FLEXA_ALIAS`, whose upstream is the Flexa API.
//! Without `FLEXA_ALIAS` no alias gets this handling.
//!
//! The Flexa SDKs (Android and iOS) authenticate every call with
//! `Authorization: Basic base64(":" + secret)`, where the secret is the app's publishable key
//! (`POST /tokens`, `PATCH /tokens/{id}`, `POST /accounts`, iOS `GET /assets` before login) or
//! the user's access token. The apps configure the SDK with [`PLACEHOLDER_PUBLISHABLE_KEY`]; the
//! gateway swaps exactly that credential for the real publishable key (`FLEXA_PUBLISHABLE_KEY`)
//! and passes any other `Authorization` through untouched ([`PlaceholderSwap`]).
//!
//! The provider ([`Flexa`]) is the generic provider of the alias plus these forwarded headers.
//! Its answers are per user, so no route of it is ever cacheable ([`check_cache_route`]).

#[cfg(feature = "flexa")]
use std::time::SystemTime;

use crate::core::auth::PlaceholderSwap;
#[cfg(feature = "flexa")]
use crate::core::provider::{Admitted, Denial, Provider, RequestView, ResponseAction};
#[cfg(feature = "flexa")]
use crate::generic::Generic;

pub use crate::core::auth::basic_authorization;

/// The provider kind.
pub const KIND: &str = "flexa";

/// Whether `authority` (lowercase) is the configured Flexa alias (`FLEXA_ALIAS`, lowercase).
pub fn is_alias(alias: Option<&str>, authority: &str) -> bool {
    alias == Some(authority)
}

/// The publishable key the apps hand to the Flexa SDK instead of the real one.
pub const PLACEHOLDER_PUBLISHABLE_KEY: &str = "publishable_live_zodl_gateway_placeholder";

/// Inner request headers forwarded to Flexa besides the ones every backend gets
/// (`content-type`): the API version and app the SDK speaks for, its per-request random trace
/// id, the SSE `Accept` and resume point. `user-agent` stays the gateway's own (the SDK's carries
/// OS and app versions).
const FORWARDED: &[&str] = &[
    "accept",
    "flexa-app",
    "flexa-version",
    "client-trace-id",
    "last-event-id",
];

/// The headers of an inner request to the Flexa alias that go upstream (first value of each name).
/// The placeholder credential becomes the real publishable key, or is dropped when none is
/// configured; it is never sent to Flexa.
pub fn upstream_headers(
    headers: &[(String, String)],
    publishable_key: Option<&str>,
) -> Vec<(String, String)> {
    let first = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };
    let mut out: Vec<(String, String)> = FORWARDED
        .iter()
        .filter_map(|name| first(name).map(|v| (name.to_string(), v)))
        .collect();
    let swap = PlaceholderSwap {
        placeholder: PLACEHOLDER_PUBLISHABLE_KEY,
        secret: publishable_key,
    };
    if let Some(v) = swap.authorization(first("authorization").as_deref()) {
        out.push(("authorization".to_string(), v));
    }
    out
}

/// The startup restriction of the Flexa alias's `THIRD_PARTY_CACHE_ROUTES`: none (its answers
/// are per user and the cache key has no `Authorization`).
pub fn check_cache_route(authority: &str) -> anyhow::Result<()> {
    anyhow::bail!(
        "Invalid THIRD_PARTY_CACHE_ROUTES: {} (FLEXA_ALIAS) answers are per user and never cacheable",
        authority
    )
}

#[cfg(feature = "flexa")]
/// The Flexa provider: the generic provider of the alias and the publishable key.
#[derive(Clone, Copy, Debug)]
pub struct Flexa<'a> {
    pub generic: Generic<'a>,
    /// `FLEXA_PUBLISHABLE_KEY`; `None`: the placeholder is dropped.
    pub publishable_key: Option<&'a str>,
}

#[cfg(feature = "flexa")]
impl Provider for Flexa<'_> {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn admit(&self, req: &RequestView<'_>) -> Result<Admitted, Denial> {
        self.generic.admit(req)
    }

    fn forwarded_headers(&self, req: &RequestView<'_>) -> Vec<(String, String)> {
        upstream_headers(req.headers, self.publishable_key)
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

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    fn authorization(out: &[(String, String)]) -> Option<&str> {
        out.iter()
            .find(|(n, _)| n == "authorization")
            .map(|(_, v)| v.as_str())
    }

    // What both SDKs send for the placeholder (Android Base64.NO_WRAP, iOS base64EncodedString).
    const SDK_PLACEHOLDER: &str = "Basic OnB1Ymxpc2hhYmxlX2xpdmVfem9kbF9nYXRld2F5X3BsYWNlaG9sZGVy";

    #[test]
    fn placeholder_encoding_matches_the_sdks() {
        assert_eq!(
            basic_authorization(PLACEHOLDER_PUBLISHABLE_KEY),
            SDK_PLACEHOLDER
        );
    }

    #[test]
    fn placeholder_replaced_by_the_real_key() {
        let out = upstream_headers(
            &h(&[("Authorization", SDK_PLACEHOLDER)]),
            Some("publishable_live_real"),
        );
        assert_eq!(
            authorization(&out),
            Some(basic_authorization("publishable_live_real").as_str())
        );
        let out = upstream_headers(
            &h(&[("authorization", &SDK_PLACEHOLDER.replace("Basic", "basic"))]),
            Some("publishable_live_real"),
        );
        assert_eq!(
            authorization(&out),
            Some(basic_authorization("publishable_live_real").as_str())
        );
    }

    #[test]
    fn placeholder_dropped_without_a_key() {
        let out = upstream_headers(&h(&[("Authorization", SDK_PLACEHOLDER)]), None);
        assert_eq!(authorization(&out), None);
    }

    #[test]
    fn user_token_passes_untouched() {
        let token = basic_authorization("eyJhbGciOiJIUzI1NiJ9.user.token");
        for value in [
            token.as_str(),
            "Bearer publishable_live_zodl_gateway_placeholder",
            "Basic cHVibGlzaGFibGVfbGl2ZV96b2RsX2dhdGV3YXlfcGxhY2Vob2xkZXI6",
            "Basic not-base64!",
        ] {
            let out = upstream_headers(&h(&[("Authorization", value)]), Some("real"));
            assert_eq!(authorization(&out), Some(value));
        }
    }

    #[test]
    fn only_the_listed_headers_are_forwarded() {
        let out = upstream_headers(
            &h(&[
                ("Accept", "text/event-stream"),
                ("Last-Event-ID", "evt_1"),
                ("Last-Event-ID", "evt_2"),
                ("Flexa-Version", "2025-11-04"),
                ("Flexa-App", "Zodl"),
                ("Client-Trace-Id", "6f1c"),
                ("User-Agent", "iOS/18.1 Flexa/1.1.4 co.zodl/3.0"),
                ("Cookie", "a=b"),
                ("X-Forwarded-For", "10.0.0.1"),
            ]),
            None,
        );
        assert_eq!(
            out,
            h(&[
                ("accept", "text/event-stream"),
                ("flexa-app", "Zodl"),
                ("flexa-version", "2025-11-04"),
                ("client-trace-id", "6f1c"),
                ("last-event-id", "evt_1"),
            ])
        );
    }

    #[test]
    fn only_the_configured_alias_is_flexa() {
        assert!(is_alias(Some("pay.example"), "pay.example"));
        assert!(!is_alias(Some("pay.example"), "other.example"));
        assert!(!is_alias(None, "pay.example"));
        assert!(!is_alias(None, ""));
    }

    #[cfg(feature = "flexa")]
    #[test]
    fn the_provider_forwards_the_flexa_headers_and_adds_the_alias_headers() {
        let policy = h(&[("POST", "/tokens")]);
        let fixed = h(&[("X-Fixed", "1")]);
        let provider = Flexa {
            generic: Generic {
                policy: Some(&policy),
                default_allow: false,
                headers: &fixed,
            },
            publishable_key: Some("publishable_live_real"),
        };
        let headers = h(&[
            ("Authorization", SDK_PLACEHOLDER),
            ("Flexa-Version", "2025-11-04"),
        ]);
        let req = RequestView {
            method: "POST",
            path: "/tokens",
            headers: &headers,
            body: &[],
        };
        assert_eq!(provider.kind(), "flexa");
        assert_eq!(
            provider.forwarded_headers(&req),
            upstream_headers(&headers, Some("publishable_live_real"))
        );
        let admitted = provider.admit(&req).unwrap();
        assert_eq!(
            provider.upstream_headers(&req, &admitted, SystemTime::UNIX_EPOCH),
            Ok(fixed.clone())
        );
        assert_eq!(
            provider.admit(&RequestView {
                method: "GET",
                ..req
            }),
            Err(Denial::NotInPolicy)
        );
    }

    #[test]
    fn no_route_is_cacheable() {
        let text = check_cache_route("pay.example").unwrap_err().to_string();
        assert_eq!(
            text,
            "Invalid THIRD_PARTY_CACHE_ROUTES: pay.example (FLEXA_ALIAS) answers are per user and never cacheable"
        );
    }
}

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

//! The interface between the gateway and a third-party provider.
//!
//! The gateway resolves the inner authority to a provider and asks it whether the request is
//! admitted ([`Provider::admit`]) before any cache, cap or upstream call, and again when it
//! forwards the request, together with the upstream headers that carry its credential
//! ([`Provider::upstream_headers`]); a refusal at either point is the inner `403`. The gateway's
//! own forwarded header allowlist, the `User-Agent` and the transport stay in the gateway.

use std::time::SystemTime;

/// The parts of an inner request a provider may look at.
#[derive(Clone, Copy, Debug)]
pub struct RequestView<'a> {
    /// The request method as received.
    pub method: &'a str,
    /// The request target as received: the path with its query string, if any. The route
    /// grammar matches on it whole ([`crate::core::route`]).
    pub path: &'a str,
    /// The inner request headers, in order.
    pub headers: &'a [(String, String)],
    /// The inner request body.
    pub body: &'a [u8],
}

/// An admitted request: what the gateway needs to log, label and forward it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Admitted {
    /// The policy entry that admitted the request: its method token as configured and its path
    /// pattern. `None` when the provider admits without an entry (no policy and the default is
    /// to allow).
    pub rule: Option<(String, String)>,
}

/// Why a provider refuses a request. The gateway answers each with its existing inner response
/// (`403` and the reason in its log line).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Denial {
    /// A path no pattern may admit ([`crate::core::route::path_trick`]).
    PathTrick(&'static str),
    /// No entry of the alias's policy admits the operation.
    NotInPolicy,
    /// The alias has no policy and the default is to deny.
    NoPolicy,
    /// The body fails the route's body schema ([`crate::core::body`]).
    InvalidBody(crate::core::body::BodyError),
}

impl Denial {
    /// The reason as logged.
    pub fn reason(&self) -> &'static str {
        match self {
            Denial::PathTrick(reason) => reason,
            Denial::NotInPolicy => "operation not in alias policy",
            Denial::NoPolicy => "alias has no operation policy",
            Denial::InvalidBody(error) => error.reason(),
        }
    }
}

/// What the gateway does with an upstream answer.
///
/// The gateway's generic forward (every alias of the registry) does not consult
/// [`Provider::response`]: each provider it uses answers [`ResponseAction::Pass`] for every
/// status (a test of the registry pins it). `Replace` and `Rewrite` are for providers that
/// answer outside it (the `coinbase` kind), which apply them themselves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResponseAction {
    /// Return it as received (through the gateway's response header filter).
    Pass,
    /// Answer `status` with the fixed JSON `body` instead: the upstream body is never
    /// forwarded (it may echo the request, e.g. an address) and never logged (error
    /// scrubbing).
    Replace { status: u16, body: &'static [u8] },
    /// The provider builds the answer from the upstream body itself (a success it turns into
    /// its own shape); the upstream body is never passed as received.
    Rewrite,
}

/// A third-party provider: one alias and its rules.
pub trait Provider: Send + Sync {
    /// The kind of the provider (`generic`, ...), for logs and metrics.
    fn kind(&self) -> &'static str;

    /// Whether the request is admitted. Runs before the third-party cache and the upstream cap.
    fn admit(&self, req: &RequestView<'_>) -> Result<Admitted, Denial>;

    /// Inner request headers the provider forwards besides the gateway's allowlist (`Flexa`:
    /// its protocol headers and the client's `Authorization`, the placeholder swapped). The
    /// gateway adds them after its allowlist and before its `User-Agent`. None by default.
    fn forwarded_headers(&self, _req: &RequestView<'_>) -> Vec<(String, String)> {
        Vec::new()
    }

    /// The headers the provider adds to the upstream request of an admitted request: its
    /// credential. The gateway never forwards the client's own credential headers, and adds these
    /// after its own. `now` is the time a signed credential is issued at.
    fn upstream_headers(
        &self,
        req: &RequestView<'_>,
        admitted: &Admitted,
        now: SystemTime,
    ) -> Result<Vec<(String, String)>, Denial>;

    /// What to do with an upstream answer of `status`.
    fn response(&self, admitted: &Admitted, status: u16) -> ResponseAction;
}

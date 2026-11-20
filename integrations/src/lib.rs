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

//! Third-party integrations of the OHTTP gateway: what an inner request to a third-party alias
//! may do and what goes upstream, without any I/O.
//!
//! The gateway keeps every connection, cache, cap store, replay check and stream; this crate
//! decides and transforms. It opens no socket, reads no clock (a time is an argument) and reads
//! no environment, so every provider can be tested and fuzzed without a network.
//!
//! - [`core::route`]: the route grammar shared by every list of `METHOD /path` entries (the
//!   per-alias policy, the dynamic hosts, the replay classes).
//! - [`core::policy`]: the parsers of the static alias tables (`BACKENDS`, `BACKENDS_POLICY`,
//!   `BACKEND_HEADERS`).
//! - [`core::provider`]: the [`core::provider::Provider`] interface and its verdict types.
//! - [`core::auth`]: the credentials a provider adds (a header, a placeholder swap, a signed
//!   JWT per request).
//! - [`core::body`]: the validation of a JSON request body against a fixed schema.
//! - [`core::caps`]: the upstream caps (`THIRD_PARTY_RATE_LIMITS`) and their fixed window.
//! - [`core::cache`]: the cacheable routes (`THIRD_PARTY_CACHE_ROUTES`).
//! - [`core::query`]: the per-route query rules (`THIRD_PARTY_QUERY_RULES`).
//! - [`core::value_source`]: the lists of allowed query values read from an upstream
//!   (`THIRD_PARTY_QUERY_VALUE_SOURCES`): grammar, extraction, acceptance; the gateway fetches.
//! - [`generic`]: the declarative provider (route policy and fixed upstream headers).
//! - [`flexa`], [`near`]: the aliases named by `FLEXA_ALIAS` and `NEAR_ALIAS`: their cache
//!   restrictions, always built, and their providers (cargo features `flexa`, `near`, on by
//!   default; without the feature the registry refuses the alias).
//! - [`keyed`]: generic providers with a key header and a query rule on every route, refused at
//!   construction otherwise; `cmc`, `swapkit` (cargo features of the same names, on by default)
//!   are its kinds, assigned by the configuration file only.
//! - [`registry`]: the provider of an alias.

#[cfg(feature = "cmc")]
pub mod cmc;
pub mod core;
pub mod flexa;
pub mod generic;
pub mod keyed;
pub mod near;
pub mod registry;
#[cfg(feature = "swapkit")]
pub mod swapkit;

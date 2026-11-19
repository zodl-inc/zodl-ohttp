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
//! - [`generic`]: the declarative provider (route policy and fixed upstream headers).
//! - [`registry`]: the provider of an alias.

pub mod core;
pub mod generic;
pub mod registry;

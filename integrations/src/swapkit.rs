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

//! The `swapkit` provider kind: a swap aggregator API that authenticates with a key header.
//! Every listed route must have a `THIRD_PARTY_QUERY_RULES` rule (a route that takes no query
//! has the rule `METHOD /path?`), so the gateway's key never answers a query of the client's
//! choosing.
//!
//! A [`crate::keyed`] provider. Assigned by the configuration file only: with the environment
//! variables an alias is always generic.

use crate::core::query::QueryRules;
use crate::generic::Generic;
use crate::keyed::Keyed;

/// The provider kind.
pub const KIND: &str = "swapkit";

/// A `swapkit` provider: a [`Keyed`] provider of kind [`KIND`].
pub type Swapkit<'a> = Keyed<'a>;

/// The `swapkit` provider of `alias` over `generic`, refused unless its invariants hold
/// ([`Keyed::new`]).
pub fn new<'a>(
    alias: &str,
    generic: Generic<'a>,
    rules: &QueryRules,
) -> anyhow::Result<Swapkit<'a>> {
    Keyed::new(KIND, alias, generic, rules)
}

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

//! Flexa API alias: the `BACKENDS` entry named by `FLEXA_ALIAS`, whose upstream is the Flexa API
//! ([`zodl_ohttp_integrations::flexa`], the provider the registry gives that alias). Without
//! `FLEXA_ALIAS` no alias gets this handling.

//!
//! Part of the library only (the binary does not use it): the names its users had.

pub use zodl_ohttp_integrations::flexa::{is_alias, upstream_headers};

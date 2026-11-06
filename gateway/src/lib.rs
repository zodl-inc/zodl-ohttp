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

// Re-export for tests and binary
pub mod block_cache;
pub mod cache;
pub mod config;
pub mod enforcement;
pub mod flexa;
pub mod freshness;
pub mod health;
pub mod hpke;
pub mod lwd;
pub mod ohttp;
pub mod padding;
pub mod proxy;
pub mod request_id;
pub mod signing;

// Re-export AppState for use in other modules
pub use crate::main_module::AppState;

// AppState for the library target, defined in main_appstate.rs (avoids a dependency on main.rs)
#[path = "main_appstate.rs"]
mod main_module;

// Audit fix regression tests
#[cfg(test)]
#[path = "audit_fixes_tests.rs"]
mod audit_fixes_tests;
pub mod backfill;
pub mod chain;
pub mod chunked_stream;
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing;
pub mod local;
pub mod mempool;
pub mod ohttp_chunked;
pub mod origin;
pub mod replication;
pub mod rpc_cache;
pub mod server;
pub mod singleflight;
pub mod store;
pub mod store_conn;
pub mod subtree_cache;
pub mod third_party_cache;

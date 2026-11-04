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

// AppState for the library target (lib.rs `main_module`), used by the proxy module and tests
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Semaphore;

pub struct AppState {
    pub config: crate::config::Config,
    pub origin: crate::origin::OriginSettings,
    pub hpke: Option<crate::hpke::KeyState>,
    pub cache: Option<crate::cache::ResponseCache>,
    pub block_cache: Option<Arc<crate::block_cache::BlockRangeCache>>,
    pub subtree_cache: Option<Arc<crate::subtree_cache::SubtreeRootsCache>>,
    pub follower: Option<Arc<crate::chain::ChainFollower>>,
    pub mempool: Arc<crate::mempool::MempoolFanout>,
    pub flights: Arc<crate::singleflight::RpcFlights>,
    pub sources: Arc<crate::lwd::LwdSources>,
    pub signing: Option<crate::signing::SigningState>,
    pub global_semaphore: Arc<Semaphore>,
    pub per_backend_semaphores: Arc<RwLock<HashMap<String, Arc<Semaphore>>>>,
    pub lwd_semaphore: Arc<Semaphore>,
    pub cache_get_semaphore: Arc<Semaphore>,
    pub large_response_semaphore: Arc<Semaphore>,
    pub third_party: crate::third_party_cache::ThirdParty,
    pub request_semaphore: Arc<Semaphore>,
}

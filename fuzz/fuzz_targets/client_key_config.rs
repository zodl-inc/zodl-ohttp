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

//! `application/ohttp-keys` documents under every client's selection rules.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zodl_ohttp_client::{KeyConfig, KeySelection};

fuzz_target!(|data: &[u8]| {
    let library = KeyConfig::select_with(data, &KeySelection::LIBRARY);
    for selection in [
        KeySelection::ANDROID,
        KeySelection::IOS,
        KeySelection::SLIPSTREAM,
    ] {
        let lenient = KeyConfig::select_with(data, &selection);
        if let Ok(config) = &library {
            assert_eq!(lenient.as_ref().ok(), Some(config), "{selection:?}");
        }
        if let Ok(config) = lenient {
            assert_eq!(KeyConfig::from_bytes(&config.to_bytes()), Some(config));
        }
    }
    let _ = KeyConfig::from_bytes(data);
});

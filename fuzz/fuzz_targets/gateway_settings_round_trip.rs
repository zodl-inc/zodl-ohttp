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

//! The `[settings]` export of an arbitrary environment (`KEY=value` lines, a key that is not a
//! setting picks one by its first byte): whenever the export takes the environment, the files
//! it writes, parsed back and rendered, are exactly the values the gateway reads from that
//! environment. That the gateway's parsers read the same settings from the files as from the
//! environment is checked by `gateway/tests/config_settings.rs`.

#![no_main]

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use zodl_ohttp_gateway::settings::{check_round_trip, SETTINGS};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut env = BTreeMap::new();
    for line in text.lines().take(32) {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = match SETTINGS.iter().find(|s| s.env == key) {
            Some(s) => s.env,
            None => match key.bytes().next() {
                Some(b) => SETTINGS[usize::from(b) % SETTINGS.len()].env,
                None => continue,
            },
        };
        env.insert(key.to_string(), value.to_string());
    }
    if let Err(e) = check_round_trip(&env) {
        panic!("{e}");
    }
});

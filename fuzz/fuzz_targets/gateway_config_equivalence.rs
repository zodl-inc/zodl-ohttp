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

//! The configuration file export of an arbitrary policy environment (`KEY=value` lines, a key
//! that is not a policy variable picks one by its first byte): whenever the export reads the
//! environment and the exported file parses, the file is the same policy (header values
//! included), and the variables it renders read back to that policy again. This is the
//! self-consistency of export and parse; that the gateway's parsers read the same tables from
//! a file as from its environment is checked by `gateway/tests/config_file.rs`.

#![no_main]

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use zodl_ohttp_integrations::core::config::{check_round_trip, POLICY_ENV_KEYS};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut env = BTreeMap::new();
    for line in text.lines().take(32) {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = if POLICY_ENV_KEYS.contains(&key) {
            key
        } else {
            match key.bytes().next() {
                Some(b) => POLICY_ENV_KEYS[usize::from(b) % POLICY_ENV_KEYS.len()],
                None => continue,
            }
        };
        env.insert(key.to_string(), value.to_string());
    }
    if let Err(e) = check_round_trip(&env) {
        panic!("{e}");
    }
});

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

//! A dynamic host source document (`DYNAMIC_HOST_SOURCES`): untrusted JSON fetched from a
//! publisher. Parsing and host extraction never panic, and every accepted host is a plain
//! `https://host[:port]` that validates again to itself.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ohttp_gateway::dynamic_hosts;

fuzz_target!(|data: &[u8]| {
    dynamic_hosts::fuzz_extract(data);
    // A listed URL on its own, and an address literal's verdict.
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(target) = dynamic_hosts::parse_host_url(text, &[8443], &[]) {
            assert!(target.base_url.starts_with("https://"));
            assert!(!target.authority.contains(['/', '@', '?', '#', '[', ' ']));
            if let Ok(ip) = target.authority.parse::<std::net::IpAddr>() {
                assert!(dynamic_hosts::is_public_ip(ip));
            }
        }
    }
});

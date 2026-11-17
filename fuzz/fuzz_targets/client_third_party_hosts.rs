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

//! The gateway's third-party host list as a wallet reads it: bytes from a peer. Reading never
//! panics; a list that is read holds only hosts that are carried under their own name, and a
//! holder fed with it never allows a host of neither list.

#![no_main]

use std::time::Instant;

use libfuzzer_sys::fuzz_target;
use zodl_ohttp_client::{
    read_third_party_hosts, HostListAnswer, HostListScope, RefreshOutcome, Response,
    ThirdPartyHosts,
};

fuzz_target!(|data: &[u8]| {
    let (status, body) = match data.split_first() {
        // Mostly 200, sometimes another status.
        Some((selector, body)) if selector % 8 == 0 => (304, body),
        Some((selector, body)) if selector % 8 == 1 => (503, body),
        Some((_, body)) => (200, body),
        None => (200, data),
    };
    let response = Response {
        status,
        headers: Vec::new(),
        body: body.to_vec(),
    };
    let answer = read_third_party_hosts(&response);
    let hosts = ThirdPartyHosts::new(["compiled.example.org"]);
    let now = Instant::now();
    let Some(refresh) = hosts.begin_refresh_at(now) else {
        panic!("the first refresh is due");
    };
    let outcome = hosts.finish_refresh_at(refresh, Some(&response), now);
    match answer {
        Ok(HostListAnswer::List(list)) => {
            assert_eq!(outcome, RefreshOutcome::Updated);
            for host in &list.hosts {
                // Every host of the list is carried, as itself.
                assert_eq!(
                    hosts.carried_authority(&host.host).as_deref(),
                    Some(host.host.as_str())
                );
            }
            let listed = list.hosts.iter().any(|h| h.host == "compiled.example.org");
            assert_eq!(
                hosts.is_carried("compiled.example.org"),
                listed || list.scope != HostListScope::All
            );
            assert!(
                !hosts.is_carried("neither.example.net")
                    || list.hosts.iter().any(|h| h.host == "neither.example.net")
            );
        }
        // No list was held, so a 304 confirms nothing; anything else is no list either.
        _ => {
            assert!(matches!(outcome, RefreshOutcome::Kept(_)));
            assert!(hosts.held().is_none());
            assert!(hosts.is_carried("compiled.example.org"));
        }
    }
});

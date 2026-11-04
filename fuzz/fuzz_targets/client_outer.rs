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

//! What the client reads from the relay's outer answer: `Retry-After`, `Cache-Control`,
//! status, media type and error body, the signed-configuration URL rules, and the freshness
//! fields of an inner answer.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zodl_ohttp_client::{
    classify_outer_response, freshness, retry_after_delay, signed_config_url, unsigned_cache_secs,
    OuterPolicy, OuterResponse, SignedConfigUrlRule, MAX_RETRY_AFTER,
};

fuzz_target!(|data: &[u8]| {
    let [hi, lo, rest @ ..] = data else {
        return;
    };
    let status = u16::from_be_bytes([*hi, *lo]);
    let text: &str = &String::from_utf8_lossy(rest);

    if let Some(delay) = retry_after_delay(Some(text)) {
        assert!(delay <= MAX_RETRY_AFTER);
    }
    let _ = unsigned_cache_secs(Some(text));
    for rule in [
        SignedConfigUrlRule::TrimThenReplaceRelaySuffix,
        SignedConfigUrlRule::ReplaceRelaySuffix,
        SignedConfigUrlRule::RelayHostRoot,
    ] {
        if let Ok(url) = signed_config_url(text, rule) {
            assert!(url.ends_with("/ohttp-configs/signed"));
            if rule == SignedConfigUrlRule::RelayHostRoot {
                assert!(url.starts_with("https://"));
            }
        }
    }
    for policy in [
        OuterPolicy::LIBRARY,
        OuterPolicy::ANDROID,
        OuterPolicy::IOS,
        OuterPolicy::SLIPSTREAM,
    ] {
        for attempt in [0, 1] {
            let _ = classify_outer_response(
                &policy,
                &OuterResponse {
                    status,
                    content_type: Some(text),
                    body: rest,
                },
                attempt,
            );
        }
    }
    let fields = [
        (freshness::SERVER_TIME_HEADER.as_bytes(), rest),
        (freshness::REQUEST_HEADER.as_bytes(), rest),
    ];
    let _ = freshness::observe_response_headers(&fields);
    let _ = freshness::is_rejection(status, &fields);
});

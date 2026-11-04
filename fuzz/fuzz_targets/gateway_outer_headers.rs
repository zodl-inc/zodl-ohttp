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

//! The outer request headers the relay hop controls, read before the request is opened:
//! the relay's correlation id and the client trace id. Input: `name: value` lines.

#![no_main]

use http::{HeaderMap, HeaderName, HeaderValue};
use libfuzzer_sys::fuzz_target;
use ohttp_gateway::{enforcement, freshness, request_id};

fuzz_target!(|data: &[u8]| {
    let mut headers = HeaderMap::new();
    for line in data.split(|b| *b == b'\n') {
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            continue;
        };
        let value = line[colon + 1..]
            .strip_prefix(b" ")
            .unwrap_or(&line[colon + 1..]);
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(&line[..colon]),
            HeaderValue::from_bytes(value),
        ) {
            headers.append(name, value);
        }
    }
    let (relay_id, _, _) = request_id::extract_relay_request_id(&headers);
    if let Some(id) = relay_id {
        assert!(request_id::is_valid_client_trace_id(&id));
        assert_eq!(enforcement::truncate_relay_id(&id).len(), 16);
    }
    if let Some(id) = request_id::extract_client_trace_id(&headers) {
        assert!(id.len() <= 64 && request_id::is_valid_client_trace_id(&id));
    }
    let text = String::from_utf8_lossy(data).into_owned();
    let _ = request_id::is_valid_client_trace_id(&text);
    let fields = vec![(freshness::REQUEST_HEADER.to_string(), text)];
    let _ = freshness::check(&fields, ohttp_fuzz::NOW, freshness::DEFAULT_WINDOW_SECS);
});

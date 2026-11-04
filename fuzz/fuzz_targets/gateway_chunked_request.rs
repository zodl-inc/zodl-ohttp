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

//! The gateway's chunked request decapsulation (header, key id, suite, varint chunk lengths,
//! chunk bounds) on raw bytes (first byte even), or on a valid sealing of the rest (odd), and
//! then whatever the gateway does with the opened inner request.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ohttp_fuzz::{decapsulate, inner_request, seal_request};

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode & 1 == 0 {
        if let Ok((plaintext, _)) = decapsulate(rest) {
            inner_request(&plaintext);
        }
    } else {
        let (sealed, _) = seal_request(rest);
        let (plaintext, _) = decapsulate(&sealed).expect("a valid sealing opens");
        assert_eq!(plaintext, rest);
        inner_request(&plaintext);
    }
});

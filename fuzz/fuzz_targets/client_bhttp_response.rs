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

//! The client's Binary HTTP response decoder (known and indeterminate length, interim
//! responses, padding) and the packed field list of the foreign-function boundary.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zodl_ohttp_client::{
    decode_bhttp_response, decode_response, pack_fields, unpack_fields, DecodeOptions,
};

fuzz_target!(|data: &[u8]| {
    let any = decode_bhttp_response(data, &DecodeOptions::ANY_STATUS);
    let http = decode_bhttp_response(data, &DecodeOptions::HTTP_STATUS);
    if let Ok(response) = &http {
        assert!((100..=599).contains(&response.status));
        assert_eq!(any.as_ref().ok(), Some(response));
        let _ = response.headers_latin1();
        let _ = response.trailers_latin1();
        let _ = response.field("grpc-status");
    }
    assert_eq!(decode_response(data).is_ok(), http.is_ok());
    if let Ok(fields) = unpack_fields(data) {
        assert_eq!(pack_fields(&fields).expect("unpacked fields pack"), data);
    }
});

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

//! The client's chunked response opener: `ChunkedResponseDecoder` fed in pieces against the
//! whole-response `open_response` and `open`. First byte even: the rest after a split byte is
//! the raw wire. Odd: the rest after a split byte and a chunk count is a plaintext the
//! gateway's sealer seals into at most that many chunks (1 to 8), the last one final, so the
//! inner Binary HTTP parser is reached; with bit 1 of the first byte set and a non-final chunk
//! present, a bit of the first non-final chunk is flipped and every opener must answer
//! `Error::Open`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ohttp_fuzz::{exchange, seal_response, RESPONSE_NONCE};
use zodl_ohttp_client::{
    collect_response, decode_bhttp_response, ChunkedResponseDecoder, DecodeOptions, Error, Response,
};

fn streamed(wire: &[u8], step: usize) -> Result<Response, Error> {
    let mut decoder = ChunkedResponseDecoder::from_opener(&exchange().1);
    let mut events = Vec::new();
    for piece in wire.chunks(step) {
        events.extend(decoder.push(piece)?);
    }
    events.extend(decoder.finish()?);
    collect_response(events)
}

fuzz_target!(|data: &[u8]| {
    let [mode, step, rest @ ..] = data else {
        return;
    };
    let step = usize::from(*step % 64) + 1;
    let opener = &exchange().1;
    let (wire, plaintext, non_final) = if mode & 1 == 0 {
        (rest.to_vec(), None, false)
    } else {
        let [count, plaintext @ ..] = rest else {
            return;
        };
        let count = usize::from(*count % 8) + 1;
        let size = plaintext.len().div_ceil(count).max(1);
        let parts: Vec<&[u8]> = plaintext.chunks(size).collect();
        (seal_response(&parts), Some(plaintext), parts.len() > 1)
    };

    if mode & 2 != 0 && non_final {
        let mut tampered = wire.clone();
        let nonce = RESPONSE_NONCE.len();
        let at = nonce + (1usize << (tampered[nonce] >> 6));
        tampered[at] ^= 1;
        assert!(matches!(opener.open_response(&tampered), Err(Error::Open)));
        assert!(matches!(streamed(&tampered, step), Err(Error::Open)));
        assert!(matches!(opener.open(&tampered), Err(Error::Open)));
    }

    let whole = opener.open_response(&wire);
    let pieces = streamed(&wire, step);
    match (&whole, &pieces) {
        (Ok(a), Ok(b)) => assert_eq!(a, b),
        (Err(a), Err(b)) => assert_eq!(std::mem::discriminant(a), std::mem::discriminant(b)),
        _ => panic!("split feed {pieces:?} differs from the whole response {whole:?}"),
    }
    if whole.is_ok() {
        assert!(opener.open(&wire).is_ok());
    }
    if let (Ok(response), Some(plaintext)) = (&whole, plaintext) {
        if let Ok(decoded) = decode_bhttp_response(plaintext, &DecodeOptions::HTTP_STATUS) {
            assert_eq!(decoded.status, response.status);
            assert_eq!(decoded.body, response.body);
        }
    }
});

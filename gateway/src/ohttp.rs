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

// OHTTP (Oblivious HTTP, RFC 9458) inner messages: the Binary HTTP request (RFC 9292) a chunked
// request carries once `ohttp_chunked::decapsulate_chunked_request` has opened it, and the inner
// response `chunked_stream::encode_response_stream` seals.

use anyhow::{anyhow, Result};
use bhttp::Message;
use std::io::Cursor;

#[derive(Clone)]
pub struct InnerRequest {
    pub method: String,
    pub path: String,
    /// RFC 9292 :authority — the host the client intended to reach.
    /// The gateway uses this to select the correct backend.
    pub authority: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl InnerRequest {
    /// A gRPC call (`content-type: application/grpc...`).
    pub fn is_grpc(&self) -> bool {
        self.headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("content-type")
                && v.to_ascii_lowercase().starts_with("application/grpc")
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct InnerResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl InnerResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Parse Binary HTTP request (RFC 9292) from plaintext.
///
/// The message may be followed by zero padding (RFC 9292 §3.8), which clients add to hide the
/// request size; any non-zero byte after the trailer section refuses the request.
pub fn parse_inner_request(plaintext: &[u8]) -> Result<InnerRequest> {
    let mut cursor = Cursor::new(plaintext);
    let msg = Message::read_bhttp(&mut cursor)
        .map_err(|e| anyhow!("Binary HTTP parse error: {:?}", e))?;
    let end = usize::try_from(cursor.position())?;
    if plaintext[end..].iter().any(|&b| b != 0) {
        return Err(anyhow!(
            "Binary HTTP parse error: non-zero bytes after the message"
        ));
    }

    let control = msg.control();
    let method_bytes = control.method().ok_or_else(|| anyhow!("Missing method"))?;
    let path_bytes = control.path().ok_or_else(|| anyhow!("Missing path"))?;

    // Strict UTF-8 validation (reject invalid, don't repair)
    let method = std::str::from_utf8(method_bytes)
        .map_err(|_| anyhow!("Method contains invalid UTF-8"))?
        .to_string();
    let path = std::str::from_utf8(path_bytes)
        .map_err(|_| anyhow!("Path contains invalid UTF-8"))?
        .to_string();

    let authority = if let Some(auth_bytes) = control.authority() {
        std::str::from_utf8(auth_bytes)
            .map_err(|_| anyhow!("Authority contains invalid UTF-8"))?
            .to_string()
    } else {
        String::new()
    };

    let headers = msg
        .header()
        .iter()
        .map(|field| {
            let name = std::str::from_utf8(field.name())
                .map_err(|_| anyhow!("Header name contains invalid UTF-8"))?
                .to_string();
            let value = std::str::from_utf8(field.value())
                .map_err(|_| anyhow!("Header value contains invalid UTF-8"))?
                .to_string();
            Ok((name, value))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(InnerRequest {
        method,
        path,
        authority,
        headers,
        body: msg.content().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A known-length Binary HTTP request (RFC 9292 §3.1): `POST https://gw.example/p`, one
    /// header field, a body, an empty trailer section.
    fn message() -> Vec<u8> {
        let mut m = vec![0];
        for field in [&b"POST"[..], b"https", b"gw.example", b"/p"] {
            m.push(field.len() as u8);
            m.extend_from_slice(field);
        }
        let header = [&[2u8][..], b"te", &[8], b"trailers"].concat();
        m.push(header.len() as u8);
        m.extend_from_slice(&header);
        m.extend_from_slice(&[3, 1, 2, 3]);
        m.push(0);
        m
    }

    fn summary(r: &InnerRequest) -> (String, String, String, Vec<(String, String)>, Vec<u8>) {
        (
            r.method.clone(),
            r.authority.clone(),
            r.path.clone(),
            r.headers.clone(),
            r.body.clone(),
        )
    }

    #[test]
    fn zero_padding_after_the_message_is_accepted_and_changes_nothing() {
        let plain = parse_inner_request(&message()).unwrap();
        assert_eq!(plain.method, "POST");
        assert_eq!(plain.authority, "gw.example");
        assert_eq!(plain.body, [1, 2, 3]);
        for pad in [1, 100, 4096 - message().len(), 32 << 10] {
            let mut padded = message();
            padded.resize(padded.len() + pad, 0);
            let parsed = parse_inner_request(&padded).unwrap();
            assert_eq!(summary(&parsed), summary(&plain), "{pad}");
        }
    }

    #[test]
    fn non_zero_bytes_after_the_message_are_refused() {
        for junk in [&[1u8][..], &[0, 0, 0x80], &[0xff; 16]] {
            let mut bytes = message();
            bytes.extend_from_slice(junk);
            assert!(parse_inner_request(&bytes).is_err(), "{junk:?}");
        }
    }
}

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
pub fn parse_inner_request(plaintext: &[u8]) -> Result<InnerRequest> {
    let mut cursor = Cursor::new(plaintext.to_vec());
    let msg = Message::read_bhttp(&mut cursor)
        .map_err(|e| anyhow!("Binary HTTP parse error: {:?}", e))?;

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

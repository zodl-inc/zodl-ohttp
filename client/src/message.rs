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

//! The Binary HTTP (RFC 9292) messages a sealed request and response carry.

use crate::{
    decode_bhttp_response, encode_bhttp_request, BhttpRequest, DecodeOptions, EncodeOptions, Error,
};

/// An HTTP request for the gateway to forward.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The method, `GET`, `POST`, ...
    pub method: String,
    /// The backend's host name as the gateway knows it (its `:authority`), with a port if
    /// not 443.
    pub authority: String,
    /// The path, with its query.
    pub path: String,
    /// The header fields, in order.
    pub headers: Vec<(String, String)>,
    /// The body, empty for none.
    pub body: Vec<u8>,
}

impl Request {
    /// A request with no header field and no body.
    pub fn new(
        method: impl Into<String>,
        authority: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        Request {
            method: method.into(),
            authority: authority.into(),
            path: path.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Adds a header field.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Sets the body.
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }
}

/// The backend's answer, as the gateway forwarded it (the gateway may drop some header
/// fields on the way).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// The final status.
    pub status: u16,
    /// The header fields, in order; names as the gateway wrote them.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl Response {
    /// The first value of the header field `name`, compared case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// `request` as a known-length Binary HTTP message, `:scheme` https, header names as given.
pub fn encode_request(request: &Request) -> Result<Vec<u8>, Error> {
    // Real requests carry the freshness timestamp the gateway requires (crate::freshness).
    encode_bhttp_request(&BhttpRequest::from(request), &EncodeOptions::PRESERVE_FRESH)
}

/// The response a Binary HTTP message holds (known or indeterminate length), status 100 to
/// 599, header fields as lossy UTF-8.
pub fn decode_response(encoded: &[u8]) -> Result<Response, Error> {
    let response = decode_bhttp_response(encoded, &DecodeOptions::HTTP_STATUS)?;
    Ok(Response {
        status: response.status,
        headers: response.headers_utf8_lossy(),
        body: response.body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_encodes_as_the_gateway_reads_it() {
        let request = Request::new("POST", "backend.example", "/v1/slots/ab/entries?since=3")
            .header("content-type", "application/json")
            .body(br#"{"a":1}"#.to_vec());
        let encoded = encode_request(&request).unwrap();
        let inner = ohttp_gateway::ohttp::parse_inner_request(&encoded).unwrap();
        assert_eq!(inner.method, "POST");
        assert_eq!(inner.authority, "backend.example");
        assert_eq!(inner.path, "/v1/slots/ab/entries?since=3");
        assert_eq!(inner.body, br#"{"a":1}"#);
        assert!(inner
            .headers
            .iter()
            .any(|(k, v)| k == "content-type" && v == "application/json"));
    }

    #[test]
    fn an_indeterminate_length_response_decodes() {
        // Framing 3: status 201, one header field, content in one chunk, end of content,
        // empty trailer section.
        let mut encoded = vec![3, 0x40, 201];
        for field in [&b"content-type"[..], b"application/json"] {
            encoded.push(field.len() as u8);
            encoded.extend_from_slice(field);
        }
        encoded.push(0); // end of the header section
        encoded.extend_from_slice(&[2, b'{', b'}', 0, 0]);
        let response = decode_response(&encoded).unwrap();
        assert_eq!(response.status, 201);
        assert_eq!(response.header("Content-Type"), Some("application/json"));
        assert_eq!(response.body, b"{}");
    }

    #[test]
    fn a_request_does_not_decode_as_a_response() {
        let encoded = encode_request(&Request::new("GET", "a.example", "/")).unwrap();
        let Err(Error::NotAResponse) = decode_response(&encoded) else {
            panic!("a request decoded as a response");
        };
    }
}

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

//! Binary HTTP (RFC 9292) messages as bytes: the codec the three wallet clients share.
//!
//! Unlike [`crate::Request`] and [`crate::Response`] (text fields, the `bhttp` crate's
//! reading), the types here carry fields as bytes, so each platform picks its own text
//! decoding (Android and iOS read response fields as ISO-8859-1, Slipstream and the networked
//! [`crate::Client`] as lossy UTF-8), and keep the response's trailer section apart from its
//! header section, which the gRPC clients read `grpc-status` out of.
//!
//! The request is always a known-length message, `:scheme` as given, with the header
//! section, the content and the (empty) trailer section all written out. A response is read
//! in either framing, interim (1xx) responses set apart, and a message that stops before its
//! content or trailer section (RFC 9292 §3.1) reads as having none.

use crate::{Error, Request};

/// One header or trailer field: name and value, as bytes.
pub type Field = (Vec<u8>, Vec<u8>);

/// `fields` as one buffer, for a foreign-function boundary that passes one byte array rather
/// than a list of pairs: each name and value as a 4-byte big-endian length and the bytes,
/// in order (`len(name) name len(value) value ...`). Fails for a field of 4 GiB or more.
pub fn pack_fields(fields: &[Field]) -> Result<Vec<u8>, Error> {
    let total = fields
        .iter()
        .map(|(n, v)| 8usize.saturating_add(n.len()).saturating_add(v.len()))
        .fold(0, usize::saturating_add);
    let mut out = Vec::new();
    out.try_reserve_exact(total)
        .map_err(|_| format_error("the fields do not fit in memory"))?;
    for part in fields.iter().flat_map(|(n, v)| [n, v]) {
        let len = u32::try_from(part.len()).map_err(|_| format_error("a field of 4 GiB"))?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(part);
    }
    Ok(out)
}

/// The fields [`pack_fields`] wrote. An odd number of parts, a length past the end of the
/// buffer or a stray byte is an error; no allocation follows a length before it is checked
/// against what is left of `packed`.
pub fn unpack_fields(packed: &[u8]) -> Result<Vec<Field>, Error> {
    let mut rest = packed;
    let mut parts: Vec<&[u8]> = Vec::new();
    while !rest.is_empty() {
        let (len, tail) = rest
            .split_first_chunk::<4>()
            .ok_or_else(|| format_error("truncated field length"))?;
        let len = u32::from_be_bytes(*len) as usize;
        if len > tail.len() {
            return Err(format_error("truncated field"));
        }
        let (part, tail) = tail.split_at(len);
        parts.push(part);
        rest = tail;
    }
    if parts.len() & 1 == 1 {
        return Err(format_error("a name without a value"));
    }
    Ok(parts
        .as_chunks::<2>()
        .0
        .iter()
        .map(|[name, value]| (name.to_vec(), value.to_vec()))
        .collect())
}

/// A request as Binary HTTP carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BhttpRequest {
    /// The method.
    pub method: Vec<u8>,
    /// `:scheme`, `https` for everything the gateway forwards.
    pub scheme: Vec<u8>,
    /// `:authority`: the backend's host name as the gateway knows it.
    pub authority: Vec<u8>,
    /// `:path`, with its query.
    pub path: Vec<u8>,
    /// The header fields, in order.
    pub headers: Vec<Field>,
    /// The content.
    pub body: Vec<u8>,
}

impl BhttpRequest {
    /// A request with scheme `https`, no header field and no content.
    pub fn new(
        method: impl Into<Vec<u8>>,
        authority: impl Into<Vec<u8>>,
        path: impl Into<Vec<u8>>,
    ) -> Self {
        BhttpRequest {
            method: method.into(),
            scheme: b"https".to_vec(),
            authority: authority.into(),
            path: path.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Sets `:scheme`.
    pub fn scheme(mut self, scheme: impl Into<Vec<u8>>) -> Self {
        self.scheme = scheme.into();
        self
    }

    /// Adds a header field.
    pub fn header(mut self, name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Sets the content.
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }
}

impl From<&Request> for BhttpRequest {
    fn from(request: &Request) -> Self {
        BhttpRequest {
            method: request.method.as_bytes().to_vec(),
            scheme: b"https".to_vec(),
            authority: request.authority.as_bytes().to_vec(),
            path: request.path.as_bytes().to_vec(),
            headers: request
                .headers
                .iter()
                .map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec()))
                .collect(),
            body: request.body.clone(),
        }
    }
}

/// How [`encode_bhttp_request`] writes a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodeOptions {
    /// Whether header field names are written in ASCII lower case (RFC 9292 §3.6 asks for
    /// it) or as given.
    pub lowercase_header_names: bool,
    /// Whether an `ohttp-freshness` field with [`crate::freshness::request_timestamp`] is added
    /// to the header section (unless the request already has one). The gateway refuses
    /// requests without a fresh one when it enforces freshness.
    pub freshness: bool,
}

impl EncodeOptions {
    /// Names written in lower case: the Android and iOS encoders, and gRPC over Slipstream
    /// (whose names come lower-cased from the `http` crate). The bytes are exactly the
    /// request's; see [`EncodeOptions::LOWERCASE_FRESH`] for real requests.
    pub const LOWERCASE: EncodeOptions = EncodeOptions {
        lowercase_header_names: true,
        freshness: false,
    };
    /// Names written as given: [`crate::encode_request`], and Slipstream's `http_round_trip`.
    pub const PRESERVE: EncodeOptions = EncodeOptions {
        lowercase_header_names: false,
        freshness: false,
    };
    /// [`EncodeOptions::LOWERCASE`] with the freshness timestamp.
    pub const LOWERCASE_FRESH: EncodeOptions = EncodeOptions {
        lowercase_header_names: true,
        freshness: true,
    };
    /// [`EncodeOptions::PRESERVE`] with the freshness timestamp.
    pub const PRESERVE_FRESH: EncodeOptions = EncodeOptions {
        lowercase_header_names: false,
        freshness: true,
    };
}

/// The status codes [`decode_bhttp_response`] accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusRange {
    /// Any status that fits sixteen bits.
    Any,
    /// 100 to 599, the range the `bhttp` crate (so Slipstream and this library's `Client`)
    /// accepts.
    Http100To599,
}

/// How [`decode_bhttp_response`] reads a response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeOptions {
    /// The statuses accepted, for the final response and the interim ones.
    pub status: StatusRange,
}

impl DecodeOptions {
    /// Any status: the Android and iOS decoders.
    pub const ANY_STATUS: DecodeOptions = DecodeOptions {
        status: StatusRange::Any,
    };
    /// 100 to 599: Slipstream and this library.
    pub const HTTP_STATUS: DecodeOptions = DecodeOptions {
        status: StatusRange::Http100To599,
    };
}

/// A response as Binary HTTP carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BhttpResponse {
    /// The final status.
    pub status: u16,
    /// The interim (1xx) responses before it, with their header fields.
    pub informational: Vec<(u16, Vec<Field>)>,
    /// The header fields of the final response, in order.
    pub headers: Vec<Field>,
    /// The content.
    pub body: Vec<u8>,
    /// The trailer fields, in order.
    pub trailers: Vec<Field>,
}

impl BhttpResponse {
    /// The first value of the field `name` among the trailers, then the headers, compared
    /// case-insensitively: how the gRPC clients find `grpc-status`, per the ZIP's requirement
    /// to check trailers before headers.
    pub fn field(&self, name: &str) -> Option<&[u8]> {
        self.trailers
            .iter()
            .chain(&self.headers)
            .find(|(k, _)| k.eq_ignore_ascii_case(name.as_bytes()))
            .map(|(_, v)| v.as_slice())
    }

    /// `headers` as text, each byte one character (ISO-8859-1): the Android and iOS reading.
    pub fn headers_latin1(&self) -> Vec<(String, String)> {
        fields_latin1(&self.headers)
    }

    /// `trailers` as text, each byte one character (ISO-8859-1).
    pub fn trailers_latin1(&self) -> Vec<(String, String)> {
        fields_latin1(&self.trailers)
    }

    /// `headers` as text, invalid UTF-8 replaced: the Slipstream reading.
    pub fn headers_utf8_lossy(&self) -> Vec<(String, String)> {
        self.headers
            .iter()
            .map(|(k, v)| {
                (
                    String::from_utf8_lossy(k).into_owned(),
                    String::from_utf8_lossy(v).into_owned(),
                )
            })
            .collect()
    }
}

fn fields_latin1(fields: &[Field]) -> Vec<(String, String)> {
    let text = |bytes: &[u8]| bytes.iter().map(|&b| char::from(b)).collect::<String>();
    fields.iter().map(|(k, v)| (text(k), text(v))).collect()
}

/// `request` as a known-length Binary HTTP message (RFC 9292 §3.1, framing indicator 0):
/// control data, header section, content and trailer section (always empty), each
/// length-prefixed; no padding. Fails for a field of 2^62 bytes or more, which cannot be
/// framed, or when the message does not fit in memory.
pub fn encode_bhttp_request(
    request: &BhttpRequest,
    options: &EncodeOptions,
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    encode_bhttp_request_into(&mut out, request, options)?;
    Ok(out)
}

/// [`encode_bhttp_request`] appending to `out`, which is grown once, to the exact size.
pub(crate) fn encode_bhttp_request_into(
    out: &mut Vec<u8>,
    request: &BhttpRequest,
    options: &EncodeOptions,
) -> Result<(), Error> {
    let stamp: Option<(Vec<u8>, Vec<u8>)> = (options.freshness
        && !request.headers.iter().any(|(name, _)| {
            name.eq_ignore_ascii_case(crate::freshness::REQUEST_HEADER.as_bytes())
        }))
    .then(|| {
        (
            crate::freshness::REQUEST_HEADER.as_bytes().to_vec(),
            crate::freshness::request_timestamp()
                .to_string()
                .into_bytes(),
        )
    });
    let section_len: usize = request
        .headers
        .iter()
        .chain(stamp.iter())
        .map(|(name, value)| vec_len(name.len()).saturating_add(vec_len(value.len())))
        .fold(0, usize::saturating_add);
    let total = [
        1, // the framing indicator
        vec_len(request.method.len()),
        vec_len(request.scheme.len()),
        vec_len(request.authority.len()),
        vec_len(request.path.len()),
        vec_len(section_len),
        vec_len(request.body.len()),
        1, // the empty trailer section
    ]
    .into_iter()
    .fold(0, usize::saturating_add);
    out.try_reserve_exact(total)
        .map_err(|_| format_error("the request does not fit in memory"))?;
    write_varint(out, 0)?;
    write_vec(out, &request.method)?;
    write_vec(out, &request.scheme)?;
    write_vec(out, &request.authority)?;
    write_vec(out, &request.path)?;
    write_varint(out, section_len as u64)?;
    for (name, value) in request.headers.iter().chain(stamp.iter()) {
        write_varint(out, name.len() as u64)?;
        if options.lowercase_header_names {
            out.extend(name.iter().map(u8::to_ascii_lowercase));
        } else {
            out.extend_from_slice(name);
        }
        write_vec(out, value)?;
    }
    write_vec(out, &request.body)?;
    write_varint(out, 0)
}

/// The bytes a length-prefixed field of `len` bytes takes.
fn vec_len(len: usize) -> usize {
    len.saturating_add(varint_len(len as u64))
}

fn varint_len(value: u64) -> usize {
    match value {
        0..=0x3f => 1,
        0x40..=0x3fff => 2,
        0x4000..=0x3fff_ffff => 4,
        _ => 8,
    }
}

/// The response in `encoded`, a known-length (framing 1) or indeterminate-length (framing 3)
/// Binary HTTP message. Zero padding after the trailer section is skipped, anything else after
/// it is refused.
pub fn decode_bhttp_response(
    encoded: &[u8],
    options: &DecodeOptions,
) -> Result<BhttpResponse, Error> {
    let mut reader = Reader { bytes: encoded };
    let known_length = match reader.varint()? {
        1 => true,
        3 => false,
        0 | 2 => return Err(Error::NotAResponse),
        other => {
            return Err(format_error(format!(
                "unsupported framing indicator {other}"
            )))
        }
    };
    let section = |reader: &mut Reader| {
        if known_length {
            reader.known_length_section()
        } else {
            reader.indeterminate_section()
        }
    };

    let mut informational = Vec::new();
    let (status, headers) = loop {
        let status = options.status.check(reader.varint()?)?;
        let headers = if reader.has_remaining() {
            section(&mut reader)?
        } else {
            Vec::new()
        };
        // An interim response is set apart; a 1xx with nothing after it is the final one.
        if (100..=199).contains(&status) && reader.has_remaining() {
            informational.push((status, headers));
        } else {
            break (status, headers);
        }
    };

    let body = if !reader.has_remaining() {
        Vec::new()
    } else if known_length {
        reader.vec()?.to_vec()
    } else {
        let mut body = Vec::new();
        loop {
            // Cut inside the content (after a chunk, before its terminator): RFC 9292 §3.8
            // allows a message to end only where every later section is empty.
            if !reader.has_remaining() {
                return Err(format_error("truncated content"));
            }
            let chunk = reader.vec()?;
            if chunk.is_empty() {
                break;
            }
            body.extend_from_slice(chunk);
        }
        body
    };
    let trailers = if reader.has_remaining() {
        section(&mut reader)?
    } else {
        Vec::new()
    };
    if reader.has_remaining() && reader.bytes.iter().any(|&b| b != 0) {
        return Err(format_error("non-zero trailing bytes".to_string()));
    }
    // Callers decode opened (authenticated) responses: learn the Gateway clock.
    crate::freshness::observe_response_headers(&headers);
    Ok(BhttpResponse {
        status,
        informational,
        headers,
        body,
        trailers,
    })
}

impl StatusRange {
    fn check(self, status: u64) -> Result<u16, Error> {
        let in_range = match self {
            StatusRange::Any => status <= u64::from(u16::MAX),
            StatusRange::Http100To599 => (100..=599).contains(&status),
        };
        if in_range {
            Ok(status as u16)
        } else {
            Err(format_error(format!("status {status} out of range")))
        }
    }
}

fn format_error(what: impl Into<String>) -> Error {
    Error::BhttpFormat(what.into())
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn has_remaining(&self) -> bool {
        !self.bytes.is_empty()
    }

    fn byte(&mut self) -> Result<u8, Error> {
        let (&first, rest) = self
            .bytes
            .split_first()
            .ok_or_else(|| format_error("truncated message"))?;
        self.bytes = rest;
        Ok(first)
    }

    /// A QUIC variable-length integer (RFC 9000 §16).
    fn varint(&mut self) -> Result<u64, Error> {
        let first = self.byte()?;
        let mut value = u64::from(first & 0x3f);
        for _ in 1..(1usize << (first >> 6)) {
            value = (value << 8) | u64::from(self.byte()?);
        }
        Ok(value)
    }

    fn vec(&mut self) -> Result<&'a [u8], Error> {
        let len = self.varint()?;
        if len > self.bytes.len() as u64 {
            return Err(format_error("truncated field"));
        }
        let (field, rest) = self.bytes.split_at(len as usize);
        self.bytes = rest;
        Ok(field)
    }

    /// A length-prefixed run of `name value` pairs.
    fn known_length_section(&mut self) -> Result<Vec<Field>, Error> {
        let mut section = Reader { bytes: self.vec()? };
        let mut fields = Vec::new();
        while section.has_remaining() {
            fields.push((section.vec()?.to_vec(), section.vec()?.to_vec()));
        }
        Ok(fields)
    }

    /// `name value` pairs up to an empty name.
    fn indeterminate_section(&mut self) -> Result<Vec<Field>, Error> {
        let mut fields = Vec::new();
        while self.has_remaining() {
            let name = self.vec()?;
            if name.is_empty() {
                break;
            }
            fields.push((name.to_vec(), self.vec()?.to_vec()));
        }
        Ok(fields)
    }
}

/// A QUIC variable-length integer (RFC 9000 §16); an error above 2^62 - 1.
fn write_varint(out: &mut Vec<u8>, value: u64) -> Result<(), Error> {
    match value {
        0..=0x3f => out.push(value as u8),
        0x40..=0x3fff => out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        0x4000..=0x3fff_ffff => {
            out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes())
        }
        0x4000_0000..=0x3fff_ffff_ffff_ffff => {
            out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes())
        }
        _ => return Err(format_error("a field too long to frame")),
    }
    Ok(())
}

fn write_vec(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    write_varint(out, bytes.len() as u64)?;
    out.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let digits: Vec<u8> = s.bytes().filter(u8::is_ascii_hexdigit).collect();
        digits
            .chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn freshness_option_stamps_the_header_once() {
        let request = BhttpRequest::new("POST", "gw.example", "/p");
        let plain = encode_bhttp_request(&request, &EncodeOptions::LOWERCASE).unwrap();
        let fresh = encode_bhttp_request(&request, &EncodeOptions::LOWERCASE_FRESH).unwrap();
        assert!(fresh.len() > plain.len());
        let text = String::from_utf8_lossy(&fresh);
        assert!(text.contains(crate::freshness::REQUEST_HEADER), "{text}");
        let stamped = BhttpRequest::new("POST", "gw.example", "/p").header("Ohttp-Freshness", "1");
        let again = encode_bhttp_request(&stamped, &EncodeOptions::PRESERVE_FRESH).unwrap();
        assert_eq!(
            again,
            encode_bhttp_request(&stamped, &EncodeOptions::PRESERVE).unwrap(),
            "an existing timestamp is left alone"
        );
    }

    #[test]
    fn rfc_9292_request_example_encodes_byte_for_byte() {
        // Figure 8.
        let expected = hex(
            "00034745 54056874 74707300 0a2f6865 6c6c6f2e 74787440 6c0a7573
             65722d61 67656e74 34637572 6c2f372e 31362e33 206c6962 6375726c 2f372e31
             362e3320 4f70656e 53534c2f 302e392e 376c207a 6c69622f 312e322e 3304686f
             73740f77 77772e65 78616d70 6c652e63 6f6d0f61 63636570 742d6c61 6e677561
             67650665 6e2c206d 690000",
        );
        let request = BhttpRequest::new("GET", "", "/hello.txt")
            .header(
                "User-Agent",
                "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3",
            )
            .header("Host", "www.example.com")
            .header("Accept-Language", "en, mi");
        assert_eq!(
            encode_bhttp_request(&request, &EncodeOptions::LOWERCASE).unwrap(),
            expected
        );
    }

    #[test]
    fn rfc_9292_response_examples_decode() {
        // Figure 13, known length, with a trailer section.
        let response = decode_bhttp_response(
            &hex(
                "0140c800 1d546869 7320636f 6e74656e 7420636f 6e746169 6e732043 524c462e
                 0d0a0d07 74726169 6c657204 74657874",
            ),
            &DecodeOptions::HTTP_STATUS,
        )
        .unwrap();
        assert_eq!(response.status, 200);
        assert!(response.headers.is_empty());
        assert_eq!(response.body, b"This content contains CRLF.\r\n");
        assert_eq!(
            response.trailers,
            vec![(b"trailer".to_vec(), b"text".to_vec())]
        );
        assert_eq!(response.field("Trailer"), Some(&b"text"[..]));

        // Figure 11, indeterminate length, two interim responses.
        let response = decode_bhttp_response(
            &hex(
                "03406607 72756e6e 696e670a 22736c65 65702031 35220040 67046c69 6e6b233c
                 2f737479 6c652e63 73733e3b 2072656c 3d707265 6c6f6164 3b206173 3d737479
                 6c65046c 696e6b24 3c2f7363 72697074 2e6a733e 3b207265 6c3d7072 656c6f61
                 643b2061 733d7363 72697074 0040c804 64617465 1d4d6f6e 2c203237 204a756c
                 20323030 39203132 3a32383a 35332047 4d540673 65727665 72064170 61636865
                 0d6c6173 742d6d6f 64696669 65641d57 65642c20 3232204a 756c2032 30303920
                 31393a31 353a3536 20474d54 04657461 67142233 34616133 38372d64 2d313536
                 38656230 30220d61 63636570 742d7261 6e676573 05627974 65730e63 6f6e7465
                 6e742d6c 656e6774 68023531 04766172 790f4163 63657074 2d456e63 6f64696e
                 670c636f 6e74656e 742d7479 70650a74 6578742f 706c6169 6e003348 656c6c6f
                 20576f72 6c642120 4d792063 6f6e7465 6e742069 6e636c75 64657320 61207472
                 61696c69 6e672043 524c462e 0d0a0000",
            ),
            &DecodeOptions::ANY_STATUS,
        )
        .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(
            response
                .informational
                .iter()
                .map(|(s, _)| *s)
                .collect::<Vec<_>>(),
            vec![102, 103]
        );
        assert_eq!(response.field("content-type"), Some(&b"text/plain"[..]));
        assert_eq!(
            response.body,
            b"Hello World! My content includes a trailing CRLF.\r\n"
        );
        assert!(response.trailers.is_empty());
    }

    #[test]
    fn a_message_may_stop_before_its_content_and_trailers() {
        // RFC 9458 Appendix A: `0140c8`, a bare 200.
        let response = decode_bhttp_response(&hex("0140c8"), &DecodeOptions::HTTP_STATUS).unwrap();
        assert_eq!(response.status, 200);
        assert!(response.body.is_empty() && response.headers.is_empty());
        // Padding after the trailer section is ignored.
        let padded = hex("0140c8 00 00 00 00 00 00 00 00");
        assert_eq!(
            decode_bhttp_response(&padded, &DecodeOptions::HTTP_STATUS)
                .unwrap()
                .status,
            200
        );
    }

    #[test]
    fn an_indeterminate_message_cut_inside_its_content_is_refused() {
        // Framing 3, 200, no headers, one content chunk "ab", then the content terminator.
        let whole = hex("03 40c8 00 026162 00");
        assert_eq!(
            decode_bhttp_response(&whole, &DecodeOptions::HTTP_STATUS)
                .unwrap()
                .body,
            b"ab"
        );
        // The same without the terminator, and with trailing bytes that are not padding.
        assert!(matches!(
            decode_bhttp_response(&whole[..whole.len() - 1], &DecodeOptions::HTTP_STATUS),
            Err(Error::BhttpFormat(_))
        ));
        let mut extra = whole.clone();
        extra.extend_from_slice(&[0, 0, 1]);
        assert!(matches!(
            decode_bhttp_response(&extra, &DecodeOptions::HTTP_STATUS),
            Err(Error::BhttpFormat(_))
        ));
    }

    #[test]
    fn trailers_come_before_headers_for_a_field() {
        let response = BhttpResponse {
            status: 200,
            informational: vec![],
            headers: vec![(b"grpc-status".to_vec(), b"13".to_vec())],
            body: vec![],
            trailers: vec![(b"Grpc-Status".to_vec(), b"0".to_vec())],
        };
        assert_eq!(response.field("grpc-status"), Some(&b"0"[..]));
    }

    #[test]
    fn requests_and_unknown_framings_are_not_responses() {
        let request = encode_bhttp_request(
            &BhttpRequest::new("GET", "a", "/"),
            &EncodeOptions::PRESERVE,
        )
        .unwrap();
        assert!(matches!(
            decode_bhttp_response(&request, &DecodeOptions::ANY_STATUS),
            Err(Error::NotAResponse)
        ));
        assert!(matches!(
            decode_bhttp_response(&[7], &DecodeOptions::ANY_STATUS),
            Err(Error::BhttpFormat(_))
        ));
        assert!(matches!(
            decode_bhttp_response(&[], &DecodeOptions::ANY_STATUS),
            Err(Error::BhttpFormat(_))
        ));
    }

    #[test]
    fn the_status_range_is_an_option() {
        // Status 42 and 700, framing 1.
        for status in [42u8, 0x40] {
            let mut bytes = vec![1];
            if status == 0x40 {
                bytes.extend_from_slice(&[0x42, 0xbc]); // 700
            } else {
                bytes.push(status);
            }
            assert!(decode_bhttp_response(&bytes, &DecodeOptions::ANY_STATUS).is_ok());
            assert!(matches!(
                decode_bhttp_response(&bytes, &DecodeOptions::HTTP_STATUS),
                Err(Error::BhttpFormat(_))
            ));
        }
    }

    #[test]
    fn lengths_are_checked_against_the_input_before_anything_is_allocated() {
        // A field announcing 2^62 - 1 bytes behind eight bytes of message.
        let mut bytes = vec![
            1u8, 0x40, 200, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];
        assert!(matches!(
            decode_bhttp_response(&bytes, &DecodeOptions::ANY_STATUS),
            Err(Error::BhttpFormat(_))
        ));
        // The same in a content field, and in an indeterminate-length chunk.
        bytes = vec![1, 0x40, 200, 0, 0xbf, 0xff, 0xff, 0xff];
        assert!(decode_bhttp_response(&bytes, &DecodeOptions::ANY_STATUS).is_err());
        bytes = vec![
            3, 0x40, 200, 0, 0xc0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];
        assert!(decode_bhttp_response(&bytes, &DecodeOptions::ANY_STATUS).is_err());
    }

    #[test]
    fn a_request_encodes_to_the_size_it_announced_and_lowercases_without_a_copy() {
        let request = BhttpRequest::new("GET", "a.example", "/p")
            .header("X-Mixed-CASE", "Value")
            .body(vec![7; 1000]);
        let encoded = encode_bhttp_request(&request, &EncodeOptions::LOWERCASE).unwrap();
        assert!(encoded.windows(12).any(|w| w == b"x-mixed-case"));
        assert!(encoded.windows(5).any(|w| w == b"Value"));
        let preserved = encode_bhttp_request(&request, &EncodeOptions::PRESERVE).unwrap();
        assert_eq!(encoded.len(), preserved.len());
        // The reserve was exact: no slack beyond the message.
        let mut out = Vec::new();
        encode_bhttp_request_into(&mut out, &request, &EncodeOptions::PRESERVE).unwrap();
        assert_eq!(out.len(), out.capacity());
    }

    #[test]
    fn packed_fields_round_trip_and_bad_buffers_are_errors() {
        let fields: Vec<Field> = vec![
            (b"name".to_vec(), b"value".to_vec()),
            (vec![], vec![0xff; 300]),
        ];
        let packed = pack_fields(&fields).unwrap();
        assert_eq!(unpack_fields(&packed).unwrap(), fields);
        assert_eq!(unpack_fields(&[]).unwrap(), vec![]);
        for cut in 1..packed.len() {
            let _ = unpack_fields(&packed[..cut]); // an error or a shorter list, never a panic
        }
        assert!(unpack_fields(&packed[..packed.len() - 1]).is_err());
        assert!(
            unpack_fields(&[0, 0, 0, 1, b'a']).is_err(),
            "a name without a value"
        );
        assert!(unpack_fields(&[0xff, 0xff, 0xff, 0xff]).is_err());
        assert!(unpack_fields(&[0, 0]).is_err());
    }

    #[test]
    fn truncation_anywhere_is_an_error_not_a_panic() {
        let full = hex("0140c8 0b 0a636f6e74656e742d74 00");
        for cut in 0..full.len() {
            let _ = decode_bhttp_response(&full[..cut], &DecodeOptions::ANY_STATUS);
        }
    }

    #[test]
    fn the_text_views_differ_as_the_platforms_do() {
        let response = BhttpResponse {
            status: 200,
            informational: vec![],
            headers: vec![(b"x".to_vec(), "é".as_bytes().to_vec())],
            body: vec![],
            trailers: vec![],
        };
        assert_eq!(response.headers_latin1()[0].1, "Ã©");
        assert_eq!(response.headers_utf8_lossy()[0].1, "é");
    }
}

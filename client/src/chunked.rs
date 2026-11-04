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

//! Chunked OHTTP (draft-ietf-ohai-chunked-ohttp-08) — client-side encapsulation and decapsulation.
//!
//! Requests are sent as chunked messages (single chunk + final chunk). Responses are opened
//! chunk by chunk as the bytes arrive ([`ChunkedResponseDecoder`]): the inner message is an
//! indeterminate-length Binary HTTP response (RFC 9292 §3.2), so its status and headers, then
//! every body chunk, then the trailers come out as [`ResponseEvent`]s before the response has
//! ended. The gateway pads the final chunk with zero bytes (RFC 9292 §3.8); the decoder
//! accepts any number of them after the trailers and refuses anything else.

use crate::encapsulation::{
    KeyConfig, AEAD_AES_128_GCM, KDF_HKDF_SHA256, KEM_X25519, N_K, N_N, N_PK, N_T,
};
use crate::{Error, Response};
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use hpke::aead::AesGcm128;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, OpModeS, Serializable};
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

/// AAD for the final chunk.
const AAD_FINAL: &[u8] = b"final";

/// Request header length: `key_id(8) kem_id(16) kdf_id(16) aead_id(16)`.
const REQUEST_HEADER_LEN: usize = 7;

/// The length of `hdr || enc` prefix in a sealed chunked request.
const SEAL_PREFIX_LEN: usize = REQUEST_HEADER_LEN + N_PK;

/// The largest plaintext a response chunk (final or not) may carry, 64 KiB.
///
/// The gateway seals every non-final chunk with exactly `CHUNK_SIZE` bytes of plaintext (fewer
/// only on a stall flush) and the final chunk with at most `CHUNK_SIZE` (padded up to it unless
/// the response is unpadded); `CHUNK_SIZE` defaults to 16384 and is what every deployment runs.
/// The cap is four times that, so a gateway may raise `CHUNK_SIZE` up to 65536 without breaking
/// clients; a larger `CHUNK_SIZE` is refused by every client.
pub const MAX_RESPONSE_CHUNK_PLAINTEXT_BYTES: usize = 64 * 1024;

/// The largest sealed response chunk accepted: [`MAX_RESPONSE_CHUNK_PLAINTEXT_BYTES`] plus the
/// 16-byte AEAD tag, 65552 bytes (the varint length prefix, at most 8 bytes, is not counted).
///
/// A chunk's length comes from the relay's unauthenticated bytes and the chunk is opened only
/// once all of it has arrived, so without this cap a hostile relay could make the decoder
/// buffer up to the whole-response limit ([`crate::GATEWAY_MAX_SEALED_RESPONSE_BYTES`], about
/// 257 MiB) before the tag check fails. A declared length above it fails with
/// [`Error::BhttpFormat`] as soon as the length prefix is read, without waiting for the rest
/// of the chunk, and so does a final chunk growing past it. The cap bounds what the decoder
/// keeps across [`ChunkedResponseDecoder::push`] calls, not one call's input: the bytes of the
/// call that carries an oversized length prefix are already in its buffer when the prefix is
/// read.
pub const MAX_SEALED_RESPONSE_CHUNK_BYTES: usize = MAX_RESPONSE_CHUNK_PLAINTEXT_BYTES + N_T;

/// The error for a sealed chunk above [`MAX_SEALED_RESPONSE_CHUNK_BYTES`].
fn chunk_too_long(len: u64) -> Error {
    Error::BhttpFormat(format!(
        "sealed chunk of {len} bytes exceeds the {MAX_SEALED_RESPONSE_CHUNK_BYTES}-byte limit"
    ))
}

/// Content type for chunked OHTTP requests.
pub const CONTENT_TYPE_CHUNKED_REQ: &str = "message/ohttp-chunked-req";

/// Content type for chunked OHTTP responses.
pub const CONTENT_TYPE_CHUNKED_RES: &str = "message/ohttp-chunked-res";

/// Encapsulate a request as a chunked OHTTP message (draft-ietf-ohai-chunked-ohttp-08 §6.1).
///
/// The request is sent as a single chunk followed by a final chunk (zero-length prefix); an
/// empty request as the final chunk alone, since a non-final chunk must not be empty.
/// Returns the sealed request and a response opener.
pub fn encapsulate_chunked_request(
    config: &KeyConfig,
    request: &[u8],
) -> Result<(Vec<u8>, ChunkedResponseOpener), Error> {
    let mut rng = OsEntropy { failed: false };
    let result = encapsulate_chunked_request_with_rng(config, request, &mut rng)?;
    if rng.failed {
        return Err(Error::Seal("the random source failed".into()));
    }
    Ok(result)
}

/// Encapsulate a chunked request with a specific RNG (for testing).
pub fn encapsulate_chunked_request_with_rng<R: CryptoRng + RngCore>(
    config: &KeyConfig,
    request: &[u8],
    rng: &mut R,
) -> Result<(Vec<u8>, ChunkedResponseOpener), Error> {
    let seal_error = |e: hpke::HpkeError| Error::Seal(e.to_string());

    // Build header
    let mut header = [0u8; REQUEST_HEADER_LEN];
    header[0] = config.key_id();
    header[1..3].copy_from_slice(&KEM_X25519.to_be_bytes());
    header[3..5].copy_from_slice(&KDF_HKDF_SHA256.to_be_bytes());
    header[5..7].copy_from_slice(&AEAD_AES_128_GCM.to_be_bytes());

    let mut info = Vec::with_capacity(36); // "message/bhttp chunked request" + 0 + 7
    info.extend_from_slice(b"message/bhttp chunked request");
    info.push(0);
    info.extend_from_slice(&header);

    let public_key = <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(config.public_key())
        .map_err(seal_error)?;
    let (enc, mut context) = hpke::setup_sender::<AesGcm128, HkdfSha256, X25519HkdfSha256, _>(
        &OpModeS::Base,
        &public_key,
        &info,
        rng,
    )
    .map_err(seal_error)?;

    // Seal the single chunk (non-final)
    let sealed_chunk = if request.is_empty() {
        Vec::new()
    } else {
        context
            .seal(request, b"")
            .map_err(|e| Error::Seal(e.to_string()))?
    };

    // Seal the final chunk (empty, with "final" AAD)
    let sealed_final = context
        .seal(&[], AAD_FINAL)
        .map_err(|e| Error::Seal(e.to_string()))?;

    // Build the complete request: hdr || enc || varint(len) || sealed_chunk || varint(0) || sealed_final
    let mut out =
        Vec::with_capacity(SEAL_PREFIX_LEN + 8 + sealed_chunk.len() + 1 + sealed_final.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&enc.to_bytes());
    if !sealed_chunk.is_empty() {
        write_varint(&mut out, sealed_chunk.len() as u64)?;
        out.extend_from_slice(&sealed_chunk);
    }
    write_varint(&mut out, 0)?; // Final chunk marker
    out.extend_from_slice(&sealed_final);

    // Export secret for response decryption
    let response_label = b"message/bhttp chunked response";
    let mut secret = Zeroizing::new([0u8; N_K]);
    context
        .export(response_label, secret.as_mut())
        .map_err(seal_error)?;

    let opener = ChunkedResponseOpener {
        enc: enc.to_bytes().to_vec(),
        secret,
    };

    Ok((out, opener))
}

/// Opens chunked OHTTP responses.
pub struct ChunkedResponseOpener {
    enc: Vec<u8>,
    secret: Zeroizing<[u8; N_K]>,
}

impl ChunkedResponseOpener {
    /// Decrypt a chunked response (draft-ietf-ohai-chunked-ohttp-08 §6.2).
    ///
    /// The response format is:
    /// - Response nonce: `random(max(Nn, Nk))`
    /// - Non-final chunks: `varint(len) || sealed_chunk`
    /// - Final chunk: `varint(0) || sealed_final_chunk` (AAD = "final")
    ///
    /// A response that ends before its final chunk is [`Error::Truncated`] (a chunk length that
    /// is itself cut short is [`Error::BhttpFormat`], as is a chunk longer than
    /// [`MAX_SEALED_RESPONSE_CHUNK_BYTES`], or a non-final chunk whose plaintext is empty); a
    /// chunk that does not open, final or not, is [`Error::Open`].
    pub fn open(&self, response: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce_len = N_N.max(N_K);
        if response.len() < nonce_len {
            return Err(Error::Truncated);
        }

        let (response_nonce, mut rest) = response.split_at(nonce_len);

        // Derive AEAD key and nonce
        let (aead_key, aead_nonce) = self.derive_keys(response_nonce)?;

        let mut plaintext = Vec::new();
        let mut counter: u64 = 0;

        loop {
            if rest.is_empty() {
                return Err(Error::Truncated);
            }
            let (chunk_len, tail) = read_varint(rest)?;
            rest = tail;

            if chunk_len == 0 {
                // Final chunk
                let sealed_final = rest;
                if sealed_final.len() > MAX_SEALED_RESPONSE_CHUNK_BYTES {
                    return Err(chunk_too_long(sealed_final.len() as u64));
                }
                let final_chunk =
                    open_chunk(&aead_key, &aead_nonce, counter, sealed_final, AAD_FINAL)?;
                plaintext.extend_from_slice(&final_chunk);
                break;
            }

            // Non-final chunk
            if chunk_len > MAX_SEALED_RESPONSE_CHUNK_BYTES as u64 {
                return Err(chunk_too_long(chunk_len));
            }
            let Some(chunk_len) = usize::try_from(chunk_len)
                .ok()
                .filter(|len| *len <= rest.len())
            else {
                return Err(Error::Truncated);
            };
            let (sealed_chunk, tail) = rest.split_at(chunk_len);
            rest = tail;

            let chunk = open_chunk(&aead_key, &aead_nonce, counter, sealed_chunk, b"")?;
            if chunk.is_empty() {
                return Err(Error::BhttpFormat(
                    "non-final chunk with empty plaintext".into(),
                ));
            }
            plaintext.extend_from_slice(&chunk);
            counter += 1;
        }

        Ok(plaintext)
    }

    /// An incremental decoder for the response to this request.
    pub fn decoder(&self) -> ChunkedResponseDecoder {
        ChunkedResponseDecoder::from_opener(self)
    }

    /// Open a complete chunked response and decode the inner message.
    pub fn open_response(&self, response: &[u8]) -> Result<Response, Error> {
        let mut decoder = self.decoder();
        let mut events = decoder.push(response)?;
        events.extend(decoder.finish()?);
        collect_response(events)
    }

    /// Derive AEAD key and nonce for response decryption.
    fn derive_keys(&self, response_nonce: &[u8]) -> Result<([u8; N_K], [u8; N_N]), Error> {
        derive_response_keys(&self.enc, &self.secret[..], response_nonce)
    }
}

/// §6.2: `prk = Extract(enc || response_nonce, secret)`, key and nonce expanded from it.
fn derive_response_keys(
    enc: &[u8],
    secret: &[u8],
    response_nonce: &[u8],
) -> Result<([u8; N_K], [u8; N_N]), Error> {
    let mut salt = enc.to_vec();
    salt.extend_from_slice(response_nonce);

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), secret);
    let mut aead_key = [0u8; N_K];
    hkdf.expand(b"key", &mut aead_key)
        .map_err(|_| Error::Seal("HKDF expand (key) failed".into()))?;
    let mut aead_nonce = [0u8; N_N];
    hkdf.expand(b"nonce", &mut aead_nonce)
        .map_err(|_| Error::Seal("HKDF expand (nonce) failed".into()))?;

    Ok((aead_key, aead_nonce))
}

/// One step of an inner response as it is decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResponseEvent {
    /// The final status and the header fields (interim 1xx responses are skipped).
    Head {
        /// The status code.
        status: u16,
        /// The header fields, names as the gateway wrote them, values as lossy UTF-8.
        headers: Vec<(String, String)>,
    },
    /// Body bytes as they arrive; one Binary HTTP content chunk may span several events.
    Data(Vec<u8>),
    /// The trailer fields (empty when the response has none).
    Trailers(Vec<(String, String)>),
    /// The response is complete and authenticated: the final chunk opened and the message
    /// ended inside it. Emitted by [`ChunkedResponseDecoder::finish`] only.
    End,
}

/// The events of one response as a [`Response`]: the trailers are appended to the headers,
/// as the gateway's collecting proxy wrote them (so `response.header("grpc-status")` works).
pub fn collect_response(events: Vec<ResponseEvent>) -> Result<Response, Error> {
    let mut status = None;
    let mut headers = Vec::new();
    let mut body = Vec::new();
    for event in events {
        match event {
            ResponseEvent::Head {
                status: s,
                headers: h,
            } => {
                status = Some(s);
                headers = h;
            }
            ResponseEvent::Data(d) => body.extend_from_slice(&d),
            ResponseEvent::Trailers(t) => headers.extend(t),
            ResponseEvent::End => {}
        }
    }
    Ok(Response {
        status: status.ok_or(Error::NotAResponse)?,
        headers,
        body,
    })
}

/// Learn the Gateway clock from a response head (crate::freshness). Every chunk is
/// authenticated on its own, so a head event is already the Gateway's.
fn observe_head(events: &[ResponseEvent]) {
    for event in events {
        if let ResponseEvent::Head { headers, .. } = event {
            crate::freshness::observe_response_headers(headers);
        }
    }
}

/// Opens a chunked response incrementally: feed the relay's bytes to [`push`](Self::push) as
/// they arrive, then call [`finish`](Self::finish) when the HTTP body ends.
///
/// Every non-final chunk is opened as soon as it is complete and its plaintext parsed as far
/// as it goes, so the first [`ResponseEvent::Data`] comes out long before the response ends.
/// The final chunk runs to the end of the body, so it is opened by `finish`, which also checks
/// that the message ended (trailer section seen) and that only zero padding followed.
pub struct ChunkedResponseDecoder {
    enc: Vec<u8>,
    secret: Zeroizing<[u8; N_K]>,
    keys: Option<([u8; N_K], [u8; N_N])>,
    counter: u64,
    /// Undecrypted bytes: the nonce, then a chunk being assembled, then the final chunk.
    wire: Vec<u8>,
    in_final: bool,
    finished: bool,
    parser: BhttpParser,
}

impl ChunkedResponseDecoder {
    /// A decoder for the response the opener's request gets.
    pub fn from_opener(opener: &ChunkedResponseOpener) -> Self {
        Self {
            enc: opener.enc.clone(),
            secret: opener.secret.clone(),
            keys: None,
            counter: 0,
            wire: Vec::new(),
            in_final: false,
            finished: false,
            parser: BhttpParser::default(),
        }
    }

    /// Feed more bytes of the sealed response. Returns the events they completed. Fails with
    /// [`Error::Open`] when a chunk does not open (as [`finish`](Self::finish) does for the
    /// final chunk), and with [`Error::BhttpFormat`] when a non-final chunk opens to an empty
    /// plaintext, as soon as a chunk length above [`MAX_SEALED_RESPONSE_CHUNK_BYTES`] is read
    /// (without waiting for the rest of the chunk), or when the final chunk would grow past it
    /// (checked before `bytes` is appended). The slice is appended to the internal buffer before
    /// the length prefixes in it are read, so a single call that carries an oversized length
    /// prefix has its whole slice buffered before it fails.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<ResponseEvent>, Error> {
        if self.finished {
            return Err(Error::BhttpFormat("decoder already finished".into()));
        }
        if self.in_final {
            let total = self.wire.len().saturating_add(bytes.len());
            if total > MAX_SEALED_RESPONSE_CHUNK_BYTES {
                return Err(chunk_too_long(total as u64));
            }
        }
        self.wire.extend_from_slice(bytes);
        let mut events = Vec::new();
        loop {
            if self.in_final {
                // The final chunk runs to the end of the body: opened by `finish`.
                if self.wire.len() > MAX_SEALED_RESPONSE_CHUNK_BYTES {
                    return Err(chunk_too_long(self.wire.len() as u64));
                }
                break;
            }
            let (aead_key, aead_nonce) = match self.keys {
                Some(k) => k,
                None => {
                    let nonce_len = N_N.max(N_K);
                    if self.wire.len() < nonce_len {
                        break;
                    }
                    let keys =
                        derive_response_keys(&self.enc, &self.secret[..], &self.wire[..nonce_len])?;
                    self.wire.drain(..nonce_len);
                    self.keys = Some(keys);
                    keys
                }
            };
            let Some((len, prefix)) = try_varint(&self.wire)? else {
                break;
            };
            if len == 0 {
                self.wire.drain(..prefix);
                self.in_final = true;
                continue;
            }
            // Bounded before waiting for the chunk: the length is unauthenticated.
            if len > MAX_SEALED_RESPONSE_CHUNK_BYTES as u64 {
                return Err(chunk_too_long(len));
            }
            // Checked: on a 32-bit target `prefix + len` can overflow before any byte arrives.
            let end = usize::try_from(len)
                .ok()
                .and_then(|len| len.checked_add(prefix))
                .ok_or_else(|| Error::BhttpFormat("chunk too long".into()))?;
            if self.wire.len() < end {
                break;
            }
            let sealed: Vec<u8> = self.wire.drain(..end).skip(prefix).collect();
            let plaintext = open_chunk(&aead_key, &aead_nonce, self.counter, &sealed, b"")?;
            if plaintext.is_empty() {
                return Err(Error::BhttpFormat(
                    "non-final chunk with empty plaintext".into(),
                ));
            }
            self.counter += 1;
            events.extend(self.parser.feed(&plaintext)?);
        }
        observe_head(&events);
        Ok(events)
    }

    /// The body has ended: open the final chunk and check the message is complete. Fails with
    /// [`Error::Truncated`] when the body ended before the final chunk began (the exchange
    /// broke off), with [`Error::Open`] when the final chunk does not open, and with
    /// [`Error::BhttpFormat`] when the message is cut short or followed by anything but zero
    /// padding.
    pub fn finish(&mut self) -> Result<Vec<ResponseEvent>, Error> {
        if self.finished {
            return Err(Error::BhttpFormat("decoder already finished".into()));
        }
        self.finished = true;
        if !self.in_final {
            return Err(Error::Truncated);
        }
        let (aead_key, aead_nonce) = self.keys.ok_or(Error::Truncated)?;
        let sealed = std::mem::take(&mut self.wire);
        let plaintext = open_chunk(&aead_key, &aead_nonce, self.counter, &sealed, AAD_FINAL)?;
        let mut events = self.parser.feed(&plaintext)?;
        self.parser.finish()?;
        observe_head(&events);
        events.push(ResponseEvent::End);
        Ok(events)
    }
}

/// A QUIC varint at the start of `bytes`: `(value, length)`, or `None` when incomplete.
fn try_varint(bytes: &[u8]) -> Result<Option<(u64, usize)>, Error> {
    let Some(&first) = bytes.first() else {
        return Ok(None);
    };
    let len = 1usize << (first >> 6);
    if bytes.len() < len {
        return Ok(None);
    }
    let mut value = u64::from(first & 0x3f);
    for b in &bytes[1..len] {
        value = (value << 8) | u64::from(*b);
    }
    Ok(Some((value, len)))
}

#[derive(Default)]
enum ParseState {
    #[default]
    Framing,
    Status,
    /// The field section of an interim (1xx) response, discarded.
    InterimHeaders,
    Headers {
        status: u16,
        fields: Vec<(String, String)>,
    },
    ContentLength,
    Content {
        remaining: u64,
    },
    Trailers {
        fields: Vec<(String, String)>,
    },
    Padding,
}

/// An incremental parser of an indeterminate-length Binary HTTP response (RFC 9292 §3.2).
#[derive(Default)]
struct BhttpParser {
    buf: Vec<u8>,
    state: ParseState,
}

impl BhttpParser {
    fn feed(&mut self, bytes: &[u8]) -> Result<Vec<ResponseEvent>, Error> {
        self.buf.extend_from_slice(bytes);
        let mut events = Vec::new();
        loop {
            match std::mem::take(&mut self.state) {
                ParseState::Framing => {
                    let Some((framing, n)) = try_varint(&self.buf)? else {
                        self.state = ParseState::Framing;
                        break;
                    };
                    self.buf.drain(..n);
                    match framing {
                        3 => self.state = ParseState::Status,
                        0 | 2 => return Err(Error::NotAResponse),
                        other => {
                            return Err(Error::BhttpFormat(format!(
                                "unsupported framing indicator {other}"
                            )))
                        }
                    }
                }
                ParseState::Status => {
                    let Some((status, n)) = try_varint(&self.buf)? else {
                        self.state = ParseState::Status;
                        break;
                    };
                    self.buf.drain(..n);
                    if !(100..=599).contains(&status) {
                        return Err(Error::BhttpFormat(format!("status {status} out of range")));
                    }
                    self.state = if (100..=199).contains(&status) {
                        ParseState::InterimHeaders
                    } else {
                        ParseState::Headers {
                            status: status as u16,
                            fields: Vec::new(),
                        }
                    };
                }
                ParseState::InterimHeaders => match self.try_field()? {
                    FieldStep::Incomplete => {
                        self.state = ParseState::InterimHeaders;
                        break;
                    }
                    FieldStep::Field(_) => self.state = ParseState::InterimHeaders,
                    FieldStep::End => self.state = ParseState::Status,
                },
                ParseState::Headers { status, mut fields } => match self.try_field()? {
                    FieldStep::Incomplete => {
                        self.state = ParseState::Headers { status, fields };
                        break;
                    }
                    FieldStep::Field(f) => {
                        fields.push(f);
                        self.state = ParseState::Headers { status, fields };
                    }
                    FieldStep::End => {
                        events.push(ResponseEvent::Head {
                            status,
                            headers: fields,
                        });
                        self.state = ParseState::ContentLength;
                    }
                },
                ParseState::ContentLength => {
                    let Some((len, n)) = try_varint(&self.buf)? else {
                        self.state = ParseState::ContentLength;
                        break;
                    };
                    self.buf.drain(..n);
                    self.state = if len == 0 {
                        ParseState::Trailers { fields: Vec::new() }
                    } else {
                        ParseState::Content { remaining: len }
                    };
                }
                ParseState::Content { remaining } => {
                    if self.buf.is_empty() {
                        self.state = ParseState::Content { remaining };
                        break;
                    }
                    let take = usize::try_from(remaining)
                        .unwrap_or(usize::MAX)
                        .min(self.buf.len());
                    let data: Vec<u8> = self.buf.drain(..take).collect();
                    events.push(ResponseEvent::Data(data));
                    let remaining = remaining - take as u64;
                    self.state = if remaining == 0 {
                        ParseState::ContentLength
                    } else {
                        ParseState::Content { remaining }
                    };
                }
                ParseState::Trailers { mut fields } => match self.try_field()? {
                    FieldStep::Incomplete => {
                        self.state = ParseState::Trailers { fields };
                        break;
                    }
                    FieldStep::Field(f) => {
                        fields.push(f);
                        self.state = ParseState::Trailers { fields };
                    }
                    FieldStep::End => {
                        events.push(ResponseEvent::Trailers(fields));
                        self.state = ParseState::Padding;
                    }
                },
                ParseState::Padding => {
                    // RFC 9292 §3.8: any number of zero bytes; anything else is invalid.
                    if self.buf.iter().any(|b| *b != 0) {
                        return Err(Error::BhttpFormat("non-zero padding".into()));
                    }
                    self.buf.clear();
                    self.state = ParseState::Padding;
                    break;
                }
            }
        }
        Ok(events)
    }

    /// One field line, or the section terminator (a zero-length name).
    fn try_field(&mut self) -> Result<FieldStep, Error> {
        let Some((name_len, n1)) = try_varint(&self.buf)? else {
            return Ok(FieldStep::Incomplete);
        };
        if name_len == 0 {
            self.buf.drain(..n1);
            return Ok(FieldStep::End);
        }
        // Checked sums: on a 32-bit target the lengths alone can overflow `usize`.
        let too_long = || Error::BhttpFormat("field too long".into());
        let name_end = usize::try_from(name_len)
            .ok()
            .and_then(|len| len.checked_add(n1))
            .ok_or_else(too_long)?;
        let Some(rest) = self.buf.get(name_end..) else {
            return Ok(FieldStep::Incomplete);
        };
        let Some((value_len, n2)) = try_varint(rest)? else {
            return Ok(FieldStep::Incomplete);
        };
        let value_start = name_end + n2;
        let total = usize::try_from(value_len)
            .ok()
            .and_then(|len| len.checked_add(value_start))
            .ok_or_else(too_long)?;
        if self.buf.len() < total {
            return Ok(FieldStep::Incomplete);
        }
        let name = String::from_utf8_lossy(&self.buf[n1..name_end]).into_owned();
        let value = String::from_utf8_lossy(&self.buf[value_start..total]).into_owned();
        self.buf.drain(..total);
        Ok(FieldStep::Field((name, value)))
    }

    /// The message must have reached its trailer terminator.
    fn finish(&self) -> Result<(), Error> {
        match self.state {
            ParseState::Padding => Ok(()),
            _ => Err(Error::BhttpFormat("response cut short".into())),
        }
    }
}

enum FieldStep {
    Incomplete,
    Field((String, String)),
    End,
}

/// Open a single chunk with the derived AEAD key and counter-based nonce.
fn open_chunk(
    aead_key: &[u8; N_K],
    aead_nonce: &[u8; N_N],
    counter: u64,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    // XOR nonce with counter
    let mut chunk_nonce = *aead_nonce;
    let counter_bytes = counter.to_be_bytes();
    let offset = N_N.saturating_sub(8);
    for (i, &b) in counter_bytes.iter().enumerate() {
        if offset + i < N_N {
            chunk_nonce[offset + i] ^= b;
        }
    }

    // Too short to hold a tag: it cannot authenticate either.
    if ciphertext.len() < N_T {
        return Err(Error::Open);
    }

    let mut buffer = ciphertext.to_vec();
    let cipher =
        Aes128Gcm::new_from_slice(aead_key).map_err(|_| Error::Seal("Invalid AEAD key".into()))?;

    let tag_pos = buffer.len() - N_T;
    let tag = aes_gcm::Tag::clone_from_slice(&buffer[tag_pos..]);
    buffer.truncate(tag_pos);

    cipher
        .decrypt_in_place_detached(Nonce::from_slice(&chunk_nonce), aad, &mut buffer, &tag)
        .map_err(|_| Error::Open)?;

    Ok(buffer)
}

/// Read a QUIC variable-length integer.
fn read_varint(bytes: &[u8]) -> Result<(u64, &[u8]), Error> {
    let format_error = || Error::BhttpFormat("truncated varint".into());
    let (&first, rest) = bytes.split_first().ok_or_else(format_error)?;
    let mut value = u64::from(first & 0x3f);
    let len = 1usize << (first >> 6);
    if rest.len() < len - 1 {
        return Err(format_error());
    }
    for i in 1..len {
        value = (value << 8) | u64::from(rest[i - 1]);
    }
    Ok((value, &rest[len - 1..]))
}

/// Write a QUIC variable-length integer.
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
        _ => return Err(Error::Seal("Varint value too large".into())),
    }
    Ok(())
}

/// The operating system's random source as the infallible generator `hpke` takes.
struct OsEntropy {
    failed: bool,
}

impl RngCore for OsEntropy {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        use rand_core::TryRngCore;
        if OsRng.try_fill_bytes(dest).is_err() {
            self.failed = true;
            dest.fill(0);
        }
    }
}

impl CryptoRng for OsEntropy {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an indeterminate-length response: framing 3, status, headers, body in `chunks`,
    /// trailers, then `padding` zero bytes.
    fn indeterminate(
        status: u64,
        headers: &[(&str, &str)],
        chunks: &[&[u8]],
        trailers: &[(&str, &str)],
        padding: usize,
    ) -> Vec<u8> {
        let mut out = vec![3u8];
        write_varint(&mut out, status).unwrap();
        for (n, v) in headers {
            write_varint(&mut out, n.len() as u64).unwrap();
            out.extend_from_slice(n.as_bytes());
            write_varint(&mut out, v.len() as u64).unwrap();
            out.extend_from_slice(v.as_bytes());
        }
        out.push(0);
        for c in chunks {
            write_varint(&mut out, c.len() as u64).unwrap();
            out.extend_from_slice(c);
        }
        out.push(0);
        for (n, v) in trailers {
            write_varint(&mut out, n.len() as u64).unwrap();
            out.extend_from_slice(n.as_bytes());
            write_varint(&mut out, v.len() as u64).unwrap();
            out.extend_from_slice(v.as_bytes());
        }
        out.push(0);
        out.extend(std::iter::repeat_n(0u8, padding));
        out
    }

    #[test]
    fn parser_emits_the_same_events_for_every_split() {
        let message = indeterminate(
            200,
            &[
                ("content-type", "application/grpc"),
                ("x-long", &"v".repeat(70)),
            ],
            &[b"hello ", b"world", &[7u8; 300]],
            &[("grpc-status", "0")],
            37,
        );
        let mut whole = BhttpParser::default();
        let mut expected = whole.feed(&message).unwrap();
        whole.finish().unwrap();
        // Data events merge: compare the collected view.
        let want = collect_response(expected.clone()).unwrap();
        assert_eq!(want.status, 200);
        assert_eq!(want.header("x-long").unwrap().len(), 70);
        assert_eq!(want.header("grpc-status"), Some("0"));
        assert_eq!(want.body.len(), 6 + 5 + 300);
        expected.retain(|e| !matches!(e, ResponseEvent::Data(_)));
        for step in [1usize, 2, 3, 5, 64] {
            let mut parser = BhttpParser::default();
            let mut events = Vec::new();
            for piece in message.chunks(step) {
                events.extend(parser.feed(piece).unwrap());
            }
            parser.finish().unwrap();
            assert_eq!(
                collect_response(events.clone()).unwrap(),
                want,
                "step {step}"
            );
            events.retain(|e| !matches!(e, ResponseEvent::Data(_)));
            assert_eq!(events, expected, "step {step}");
        }
    }

    #[test]
    fn parser_rejects_non_zero_padding_and_short_messages() {
        let mut message = indeterminate(200, &[], &[b"x"], &[], 4);
        let mut parser = BhttpParser::default();
        parser.feed(&message).unwrap();
        parser.finish().unwrap();
        let last = message.len() - 1;
        message[last] = 1;
        let mut parser = BhttpParser::default();
        assert!(matches!(parser.feed(&message), Err(Error::BhttpFormat(_))));
        // Cut inside the trailer section.
        let cut = indeterminate(200, &[], &[b"x"], &[("grpc-status", "0")], 0);
        let mut parser = BhttpParser::default();
        parser.feed(&cut[..cut.len() - 3]).unwrap();
        assert!(matches!(parser.finish(), Err(Error::BhttpFormat(_))));
    }

    #[test]
    fn parser_skips_interim_responses_and_refuses_requests() {
        // 103 with one field, then the final 200.
        let mut message = vec![3u8, 0x40, 103, 4];
        message.extend_from_slice(b"link");
        message.extend_from_slice(&[1, b'x', 0]);
        message.extend_from_slice(&indeterminate(200, &[], &[b"ok"], &[], 0)[1..]);
        let mut parser = BhttpParser::default();
        let events = parser.feed(&message).unwrap();
        parser.finish().unwrap();
        let response = collect_response(events).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
        let mut parser = BhttpParser::default();
        assert!(matches!(parser.feed(&[0, 3]), Err(Error::NotAResponse)));
    }

    #[test]
    fn parser_survives_lengths_at_the_varint_maximum() {
        // Waits for the bytes on a 64-bit target, refuses on a 32-bit one; never overflows.
        let max = [0xffu8; 8];
        let name = [&[3u8, 0x40, 200][..], &max].concat();
        let value = [&[3u8, 0x40, 200, 1, b'a'][..], &max].concat();
        for message in [name, value] {
            let mut parser = BhttpParser::default();
            if let Ok(events) = parser.feed(&message) {
                assert!(events.is_empty());
            }
            assert!(parser.finish().is_err());
        }
    }

    #[test]
    fn test_varint_roundtrip() {
        let test_values = vec![0u64, 63, 64, 16383, 16384, 0x3fff_ffff, 0x4000_0000];
        for value in test_values {
            let mut buf = Vec::new();
            write_varint(&mut buf, value).unwrap();
            let (decoded, rest) = read_varint(&buf).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(rest.len(), 0);
        }
    }
}

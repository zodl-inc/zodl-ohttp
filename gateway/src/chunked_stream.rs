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

//! Streaming chunked OHTTP response encoding (draft-ietf-ohai-chunked-ohttp-08 §6.2).
//!
//! The plaintext is an indeterminate-length Binary HTTP response (RFC 9292 §3.2): framing
//! indicator 3, status, header section, content chunks, trailer section, then padding. It is
//! re-sliced into fixed-size AEAD chunks so chunk boundaries do not follow message boundaries:
//!
//! - Every non-final chunk carries exactly `chunk_size` bytes of plaintext, except a stall
//!   flush (next item).
//! - A shorter non-final chunk is emitted only when the upstream stalls: no frame arrives for
//!   `flush` while plaintext is waiting. That trades a little privacy for latency, and it is
//!   the one place where timing and sizes say something about the upstream (a slow
//!   lightwalletd, or a cache miss between two cache hits). `CHUNK_FLUSH_MS` controls it.
//! - The final chunk is padded with zero bytes after the trailer section (RFC 9292 §3.8) up
//!   to `chunk_size`, so without stall flushes the relay sees `N x chunk_size` plus the AEAD
//!   and framing overhead, unless the response is unpadded (`RESPONSE_PADDING`, see
//!   `padding.rs`): then it ends with the trailers.

use crate::hpke::{ResponseContext, N_K, N_N};
use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use futures_util::{Stream, StreamExt};
use rand::RngCore;
use std::time::Duration;

const AAD_FINAL: &[u8] = b"final";

/// One frame of an upstream (inner) response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpFrame {
    /// Body bytes. Empty frames are ignored by the encoder.
    Data(Bytes),
    /// Trailer fields, written after the content terminator. Several frames accumulate.
    Trailers(Vec<(String, String)>),
}

/// Seals successive chunks under the chunked-response AEAD key (§6.2).
pub struct ChunkSealer {
    aead_key: [u8; N_K],
    base_nonce: [u8; N_N],
    counter: u64,
}

impl ChunkSealer {
    pub fn new(response_ctx: &ResponseContext, response_nonce: &[u8]) -> Result<Self> {
        let (aead_key, base_nonce) = response_ctx.derive_chunked_keys(response_nonce)?;
        Ok(Self {
            aead_key,
            base_nonce,
            counter: 0,
        })
    }

    /// `varint(len) || Seal(chunk)` for a non-final chunk, `varint(0) || Seal(chunk)` with
    /// AAD "final" for the final one. The nonce is `base_nonce XOR counter`.
    pub fn seal(&mut self, plaintext: &[u8], final_chunk: bool) -> Result<Bytes> {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::{Aes128Gcm, Nonce};

        if !final_chunk && plaintext.is_empty() {
            return Err(anyhow!("non-final chunk must not be empty"));
        }
        if self.counter == u64::MAX {
            return Err(anyhow!("chunk counter overflow"));
        }

        let chunk_nonce = chunk_nonce(&self.base_nonce, self.counter);
        let aad = if final_chunk { AAD_FINAL } else { b"" };
        let cipher =
            Aes128Gcm::new_from_slice(&self.aead_key).map_err(|_| anyhow!("Invalid AEAD key"))?;
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&chunk_nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| anyhow!("AEAD seal failed"))?;
        self.counter += 1;

        let mut out = BytesMut::with_capacity(8 + sealed.len());
        write_varint(&mut out, if final_chunk { 0 } else { sealed.len() as u64 });
        out.extend_from_slice(&sealed);
        Ok(out.freeze())
    }
}

/// `aead_nonce XOR encode(Nn, counter)`: the counter in the low-order bytes.
pub fn chunk_nonce(base_nonce: &[u8; N_N], counter: u64) -> [u8; N_N] {
    let mut nonce = *base_nonce;
    let counter_bytes = counter.to_be_bytes();
    let offset = N_N - counter_bytes.len();
    for (i, b) in counter_bytes.iter().enumerate() {
        nonce[offset + i] ^= b;
    }
    nonce
}

/// A QUIC variable-length integer (RFC 9000 §16).
pub fn write_varint(out: &mut BytesMut, value: u64) {
    match value {
        0..=0x3f => out.extend_from_slice(&[value as u8]),
        0x40..=0x3fff => out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        0x4000..=0x3fff_ffff => {
            out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes())
        }
        _ => out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

fn write_field_section(buf: &mut BytesMut, fields: &[(String, String)]) {
    for (name, value) in fields {
        write_varint(buf, name.len() as u64);
        buf.extend_from_slice(name.as_bytes());
        write_varint(buf, value.len() as u64);
        buf.extend_from_slice(value.as_bytes());
    }
    write_varint(buf, 0);
}

fn io_err(e: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// Seal an inner response as a chunked OHTTP response body.
///
/// The stream yields the wire bytes: the response nonce, then every sealed chunk (length
/// prefix included), the final one last. `status` and `headers` are written before the
/// first upstream frame; `upstream` supplies the body and the trailers. An upstream error
/// ends the stream with an error, which hyper turns into a reset: the client never gets a
/// final chunk, so it knows the response is truncated.
// Library API and tests; the binary seals through `encode_response_stream_padded`.
#[allow(dead_code)]
pub fn encode_response_stream<S>(
    ctx: ResponseContext,
    status: u16,
    headers: Vec<(String, String)>,
    upstream: S,
    chunk_size: usize,
    flush: Duration,
    network: String,
) -> impl Stream<Item = Result<Bytes, std::io::Error>> + Send
where
    S: Stream<Item = Result<UpFrame>> + Send + 'static,
{
    encode_response_stream_padded(
        ctx, status, headers, upstream, chunk_size, flush, network, true,
    )
}

/// [`encode_response_stream`], with the final chunk padded to `chunk_size` only when `pad`.
#[allow(clippy::too_many_arguments)]
pub fn encode_response_stream_padded<S>(
    ctx: ResponseContext,
    status: u16,
    headers: Vec<(String, String)>,
    upstream: S,
    chunk_size: usize,
    flush: Duration,
    network: String,
    pad: bool,
) -> impl Stream<Item = Result<Bytes, std::io::Error>> + Send
where
    S: Stream<Item = Result<UpFrame>> + Send + 'static,
{
    let chunk_size = chunk_size.max(1);
    async_stream::stream! {
        let nonce_len = N_N.max(N_K);
        let mut response_nonce = vec![0u8; nonce_len];
        rand::rngs::OsRng.fill_bytes(&mut response_nonce);
        let mut sealer = match ChunkSealer::new(&ctx, &response_nonce) {
            Ok(s) => s,
            Err(e) => {
                crate::health::record_encrypt_error();
                yield Err(io_err(e));
                return;
            }
        };
        yield Ok(Bytes::from(response_nonce));

        let mut buf = BytesMut::with_capacity(chunk_size * 2);
        write_varint(&mut buf, 3);
        write_varint(&mut buf, status as u64);
        write_field_section(&mut buf, &headers);

        let mut upstream = Box::pin(upstream);
        let mut trailers: Vec<(String, String)> = Vec::new();
        let mut upstream_done = false;

        while !upstream_done {
            // Fast path: full chunks only.
            while buf.len() >= chunk_size {
                let plaintext = buf.split_to(chunk_size);
                match sealer.seal(&plaintext, false) {
                    Ok(sealed) => {
                        crate::health::record_chunk_sent(&network, "full");
                        yield Ok(sealed);
                    }
                    Err(e) => {
                        crate::health::record_encrypt_error();
                        yield Err(io_err(e));
                        return;
                    }
                }
            }

            // Wait for the next frame; with plaintext waiting, give up after `flush` and
            // emit a short chunk (the stall leak documented above).
            let next = if buf.is_empty() {
                upstream.next().await
            } else {
                tokio::select! {
                    frame = upstream.next() => frame,
                    _ = tokio::time::sleep(flush) => {
                        let plaintext = buf.split();
                        match sealer.seal(&plaintext, false) {
                            Ok(sealed) => {
                                crate::health::record_chunk_sent(&network, "flush");
                                yield Ok(sealed);
                            }
                            Err(e) => {
                                crate::health::record_encrypt_error();
                                yield Err(io_err(e));
                                return;
                            }
                        }
                        continue;
                    }
                }
            };

            match next {
                Some(Ok(UpFrame::Data(data))) => {
                    // A zero-length chunk would be the content terminator.
                    if !data.is_empty() {
                        write_varint(&mut buf, data.len() as u64);
                        buf.extend_from_slice(&data);
                    }
                }
                Some(Ok(UpFrame::Trailers(t))) => trailers.extend(t),
                Some(Err(e)) => {
                    yield Err(io_err(e));
                    return;
                }
                None => upstream_done = true,
            }
        }

        // Content terminator, trailer section, then the final chunk (padded to chunk_size
        // unless the response is unpadded).
        write_varint(&mut buf, 0);
        write_field_section(&mut buf, &trailers);
        while buf.len() > chunk_size {
            let plaintext = buf.split_to(chunk_size);
            match sealer.seal(&plaintext, false) {
                Ok(sealed) => {
                    crate::health::record_chunk_sent(&network, "full");
                    yield Ok(sealed);
                }
                Err(e) => {
                    crate::health::record_encrypt_error();
                    yield Err(io_err(e));
                    return;
                }
            }
        }
        if pad {
            buf.resize(chunk_size, 0);
        }
        match sealer.seal(&buf, true) {
            Ok(sealed) => {
                crate::health::record_chunk_sent(&network, if pad { "final" } else { "final_unpadded" });
                yield Ok(sealed);
            }
            Err(e) => {
                crate::health::record_encrypt_error();
                yield Err(io_err(e));
            }
        }
    }
}

/// A collected inner response as an upstream: the body frame (if any), then the trailers (if any).
pub fn collected_upstream(
    body: Vec<u8>,
    trailers: Vec<(String, String)>,
) -> impl Stream<Item = Result<UpFrame>> + Send {
    let mut frames = Vec::with_capacity(2);
    if !body.is_empty() {
        frames.push(Ok(UpFrame::Data(Bytes::from(body))));
    }
    if !trailers.is_empty() {
        frames.push(Ok(UpFrame::Trailers(trailers)));
    }
    futures_util::stream::iter(frames)
}

/// Forward `upstream` while holding `permit` until it ends (or is dropped).
pub fn hold_permit<S>(
    upstream: S,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> impl Stream<Item = Result<UpFrame>> + Send + 'static
where
    S: Stream<Item = Result<UpFrame>> + Send + 'static,
{
    async_stream::stream! {
        let _permit = permit;
        let mut upstream = Box::pin(upstream);
        while let Some(item) = upstream.next().await {
            yield item;
        }
    }
}

/// A header or trailer section: `(name, value)` fields in order.
pub type Fields = Vec<(String, String)>;

/// Split the `grpc-*` fields off a collected response's headers, as the collecting proxy
/// folded them in: `(headers, trailers)`. The order within each part is kept.
pub fn split_grpc_trailers(headers: Fields) -> (Fields, Fields) {
    headers
        .into_iter()
        .partition(|(name, _)| !name.to_ascii_lowercase().starts_with("grpc-"))
}

/// How an upstream stream ended, for the per-request log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndOutcome {
    /// The stream ended cleanly.
    Complete,
    /// The stream yielded an error (the client gets a truncated response).
    Failed(String),
    /// The consumer dropped the stream before it ended (the client went away).
    Dropped,
}

impl std::fmt::Display for EndOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EndOutcome::Complete => f.write_str("complete"),
            EndOutcome::Failed(e) => write!(f, "failed: {e}"),
            EndOutcome::Dropped => f.write_str("dropped"),
        }
    }
}

/// The tally of one upstream stream at its end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamEnd {
    pub bytes: usize,
    pub frames: usize,
    /// The `grpc-status` trailer, when the stream carried one.
    pub grpc_status: Option<String>,
    pub outcome: EndOutcome,
}

/// Forward `upstream` unchanged and, once the returned stream has been polled, call `on_end`
/// exactly once when it ends: cleanly, with an error, or because the consumer dropped it.
/// Dropping it before the first poll does not call `on_end`.
pub fn on_end<S, F>(upstream: S, on_end: F) -> impl Stream<Item = Result<UpFrame>> + Send + 'static
where
    S: Stream<Item = Result<UpFrame>> + Send + 'static,
    F: FnOnce(StreamEnd) + Send + 'static,
{
    struct Guard<F: FnOnce(StreamEnd)> {
        end: StreamEnd,
        on_end: Option<F>,
    }
    impl<F: FnOnce(StreamEnd)> Guard<F> {
        fn finish(&mut self, outcome: EndOutcome) {
            if let Some(f) = self.on_end.take() {
                let mut end = self.end.clone();
                end.outcome = outcome;
                f(end);
            }
        }
    }
    impl<F: FnOnce(StreamEnd)> Drop for Guard<F> {
        fn drop(&mut self) {
            self.finish(EndOutcome::Dropped);
        }
    }

    async_stream::stream! {
        let mut guard = Guard {
            end: StreamEnd {
                bytes: 0,
                frames: 0,
                grpc_status: None,
                outcome: EndOutcome::Dropped,
            },
            on_end: Some(on_end),
        };
        let mut upstream = Box::pin(upstream);
        while let Some(item) = upstream.next().await {
            match &item {
                Ok(UpFrame::Data(d)) => {
                    guard.end.bytes += d.len();
                    guard.end.frames += 1;
                }
                Ok(UpFrame::Trailers(t)) => {
                    if let Some((_, v)) = t.iter().find(|(k, _)| k.eq_ignore_ascii_case("grpc-status")) {
                        guard.end.grpc_status = Some(v.clone());
                    }
                }
                Err(e) => {
                    guard.finish(EndOutcome::Failed(e.to_string()));
                }
            }
            yield item;
        }
        guard.finish(EndOutcome::Complete);
    }
}

fn grpc_status_trailers(code: &str, message: String) -> Vec<(String, String)> {
    vec![
        ("grpc-status".to_string(), code.to_string()),
        ("grpc-message".to_string(), message),
    ]
}

/// A lightwalletd response stream as the Client must receive it (ZIP "Gateway behaviour"
/// rule 7): when the stream ends without a `grpc-status`, `grpc-status: 13` is appended, and an
/// upstream error before any `grpc-status` ends it with `grpc-status: 13` trailers instead of a
/// reset (after one, the stream just ends). `head_has_status`:
/// the response head already carried one (trailers-only response).
pub fn ensure_grpc_status<S>(
    head_has_status: bool,
    upstream: S,
) -> impl Stream<Item = Result<UpFrame>> + Send + 'static
where
    S: Stream<Item = Result<UpFrame>> + Send + 'static,
{
    async_stream::stream! {
        let mut has_status = head_has_status;
        let mut upstream = Box::pin(upstream);
        while let Some(item) = upstream.next().await {
            match item {
                Ok(UpFrame::Trailers(t)) => {
                    if t.iter().any(|(k, _)| k.eq_ignore_ascii_case("grpc-status")) {
                        has_status = true;
                    }
                    yield Ok(UpFrame::Trailers(t));
                }
                Ok(frame) => yield Ok(frame),
                Err(e) => {
                    if !has_status {
                        yield Ok(UpFrame::Trailers(grpc_status_trailers(
                            "13",
                            format!("upstream stream failed: {e}"),
                        )));
                    }
                    return;
                }
            }
        }
        if !has_status {
            yield Ok(UpFrame::Trailers(grpc_status_trailers(
                "13",
                "lightwalletd closed the stream without grpc-status".to_string(),
            )));
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! A client-side opener for tests: the inverse of [`ChunkSealer`].
    use super::*;
    use crate::hpke::N_N;

    /// Open the wire bytes of one response (nonce, chunks, final chunk). Returns the
    /// plaintext of every chunk and the plaintext lengths per chunk in order.
    pub fn open_wire(ctx: &ResponseContext, wire: &[u8]) -> (Vec<u8>, Vec<usize>) {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::{Aes128Gcm, Nonce};

        let nonce_len = N_N.max(N_K);
        let (response_nonce, mut rest) = wire.split_at(nonce_len);
        let (key, base_nonce) = ctx.derive_chunked_keys(response_nonce).unwrap();
        let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
        let mut plaintext = Vec::new();
        let mut lengths = Vec::new();
        let mut counter = 0u64;
        loop {
            let (len, tail) = read_varint(rest);
            rest = tail;
            let (sealed, aad, tail) = if len == 0 {
                (rest, &b"final"[..], &[][..])
            } else {
                let (s, t) = rest.split_at(len as usize);
                (s, &b""[..], t)
            };
            let chunk = cipher
                .decrypt(
                    Nonce::from_slice(&chunk_nonce(&base_nonce, counter)),
                    Payload { msg: sealed, aad },
                )
                .expect("chunk opens");
            counter += 1;
            lengths.push(chunk.len());
            plaintext.extend_from_slice(&chunk);
            rest = tail;
            if len == 0 {
                break;
            }
        }
        (plaintext, lengths)
    }

    pub fn read_varint(bytes: &[u8]) -> (u64, &[u8]) {
        let first = bytes[0];
        let len = 1usize << (first >> 6);
        let mut value = u64::from(first & 0x3f);
        for b in &bytes[1..len] {
            value = (value << 8) | u64::from(*b);
        }
        (value, &bytes[len..])
    }

    /// Parse an indeterminate-length BHTTP response: (status, headers, body, trailers).
    /// Trailing zero padding is accepted; anything else after the trailers fails.
    #[allow(clippy::type_complexity)]
    pub fn parse_indeterminate(
        plaintext: &[u8],
    ) -> (u16, Vec<(String, String)>, Vec<u8>, Vec<(String, String)>) {
        let (framing, mut rest) = read_varint(plaintext);
        assert_eq!(framing, 3);
        let (status, tail) = read_varint(rest);
        rest = tail;
        let section = |rest: &mut &[u8]| {
            let mut fields = Vec::new();
            loop {
                let (n, tail) = read_varint(rest);
                *rest = tail;
                if n == 0 {
                    break;
                }
                let (name, tail) = rest.split_at(n as usize);
                let (v, tail) = read_varint(tail);
                let (value, tail) = tail.split_at(v as usize);
                *rest = tail;
                fields.push((
                    String::from_utf8(name.to_vec()).unwrap(),
                    String::from_utf8(value.to_vec()).unwrap(),
                ));
            }
            fields
        };
        let headers = section(&mut rest);
        let mut body = Vec::new();
        loop {
            let (n, tail) = read_varint(rest);
            rest = tail;
            if n == 0 {
                break;
            }
            let (chunk, tail) = rest.split_at(n as usize);
            body.extend_from_slice(chunk);
            rest = tail;
        }
        let trailers = section(&mut rest);
        assert!(rest.iter().all(|b| *b == 0), "non-zero padding");
        (status as u16, headers, body, trailers)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    /// AES-GCM tag length.
    const N_T: usize = 16;

    fn ctx() -> ResponseContext {
        ResponseContext {
            enc: vec![7u8; 32],
            secret: vec![9u8; N_K],
        }
    }

    fn trailers() -> Vec<(String, String)> {
        vec![
            ("grpc-status".to_string(), "0".to_string()),
            ("grpc-message".to_string(), "".to_string()),
        ]
    }

    /// A slow upstream: `frames` each after `gap`, then the trailers, then end.
    fn slow_upstream(
        frames: Vec<Bytes>,
        gap: Duration,
    ) -> impl Stream<Item = Result<UpFrame>> + Send {
        async_stream::stream! {
            for f in frames {
                tokio::time::sleep(gap).await;
                yield Ok(UpFrame::Data(f));
            }
            yield Ok(UpFrame::Trailers(trailers()));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn fixed_size_chunks_and_padding() {
        let chunk_size = 1024;
        let body: Vec<Bytes> = (0..10u8).map(|i| Bytes::from(vec![i; 700])).collect();
        let expected_body: Vec<u8> = body.iter().flat_map(|b| b.to_vec()).collect();
        // Frames arrive every 5 ms, well inside the 50 ms flush: no stall flush happens.
        let upstream = slow_upstream(body, Duration::from_millis(5));
        let headers = vec![("content-type".to_string(), "application/grpc".to_string())];
        let wire: Vec<Bytes> = encode_response_stream(
            ctx(),
            200,
            headers.clone(),
            upstream,
            chunk_size,
            Duration::from_millis(50),
            "test".to_string(),
        )
        .map(|r| r.unwrap())
        .collect()
        .await;

        // Item 0 is the nonce; every non-final sealed chunk on the wire has the same length.
        assert_eq!(wire[0].len(), N_N.max(N_K));
        let sealed_lens: Vec<usize> = wire[1..].iter().map(|b| b.len()).collect();
        assert!(sealed_lens.len() >= 7, "{sealed_lens:?}");
        let non_final = &sealed_lens[..sealed_lens.len() - 1];
        assert!(
            non_final.iter().all(|l| *l == non_final[0]),
            "{sealed_lens:?}"
        );
        // The final chunk has a 1-byte length prefix (0) instead of 2 bytes for 1040.
        assert_eq!(*sealed_lens.last().unwrap(), 1 + chunk_size + N_T);

        let flat: Vec<u8> = wire.iter().flat_map(|b| b.to_vec()).collect();
        let (plaintext, lengths) = open_wire(&ctx(), &flat);
        assert!(lengths.iter().all(|l| *l == chunk_size), "{lengths:?}");
        let (status, got_headers, got_body, got_trailers) = parse_indeterminate(&plaintext);
        assert_eq!(status, 200);
        assert_eq!(got_headers, headers);
        assert_eq!(got_body, expected_body);
        assert_eq!(got_trailers, trailers());
    }

    #[tokio::test(start_paused = true)]
    async fn first_chunk_leaves_before_upstream_ends() {
        let chunk_size = 512;
        // Two 2000-byte frames 10 s apart: the first frame alone fills three full chunks.
        let upstream = slow_upstream(
            vec![Bytes::from(vec![1u8; 2000]), Bytes::from(vec![2u8; 2000])],
            Duration::from_secs(10),
        );
        let mut stream = Box::pin(encode_response_stream(
            ctx(),
            200,
            vec![],
            upstream,
            chunk_size,
            Duration::from_millis(50),
            "test".to_string(),
        ));
        let started = tokio::time::Instant::now();
        let _nonce = stream.next().await.unwrap().unwrap();
        // The header bytes stall for 50 ms and leave as a short chunk (the documented leak).
        let first = stream.next().await.unwrap().unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(first.len() < 2 + chunk_size + N_T);
        // The first full chunk leaves with the first frame, at 10 s, not with the end at 20 s.
        let second = stream.next().await.unwrap().unwrap();
        assert_eq!(second.len(), 2 + chunk_size + N_T);
        assert!(started.elapsed() >= Duration::from_secs(10));
        assert!(started.elapsed() < Duration::from_secs(11));
        let rest: Vec<Bytes> = stream.map(|r| r.unwrap()).collect().await;
        assert!(started.elapsed() >= Duration::from_secs(20));
        assert!(!rest.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn stall_flushes_a_short_chunk_and_the_rest_stays_fixed() {
        let chunk_size = 1024;
        // One small frame, then a 1 s stall, then a big one.
        let upstream = slow_upstream(
            vec![Bytes::from(vec![1u8; 100]), Bytes::from(vec![2u8; 3000])],
            Duration::from_secs(1),
        );
        let wire: Vec<Bytes> = encode_response_stream(
            ctx(),
            200,
            vec![],
            upstream,
            chunk_size,
            Duration::from_millis(50),
            "test".to_string(),
        )
        .map(|r| r.unwrap())
        .collect()
        .await;
        let flat: Vec<u8> = wire.iter().flat_map(|b| b.to_vec()).collect();
        let (plaintext, lengths) = open_wire(&ctx(), &flat);
        // Two short chunks (headers alone, then the 100-byte frame), full chunks after.
        assert!(lengths[0] < chunk_size);
        assert!(lengths[1] < chunk_size);
        assert!(lengths[2..].iter().all(|l| *l == chunk_size), "{lengths:?}");
        let (_, _, body, _) = parse_indeterminate(&plaintext);
        assert_eq!(body.len(), 3100);
    }

    #[tokio::test]
    async fn small_body_is_one_padded_final_chunk() {
        let wire: Vec<Bytes> = encode_response_stream(
            ctx(),
            403,
            vec![("content-type".to_string(), "text/plain".to_string())],
            collected_upstream(b"policy denied".to_vec(), vec![]),
            2048,
            Duration::from_millis(50),
            "test".to_string(),
        )
        .map(|r| r.unwrap())
        .collect()
        .await;
        assert_eq!(wire.len(), 2);
        let flat: Vec<u8> = wire.iter().flat_map(|b| b.to_vec()).collect();
        let (plaintext, lengths) = open_wire(&ctx(), &flat);
        assert_eq!(lengths, vec![2048]);
        let (status, _, body, trailers) = parse_indeterminate(&plaintext);
        assert_eq!(status, 403);
        assert_eq!(body, b"policy denied");
        assert!(trailers.is_empty());
    }

    #[tokio::test]
    async fn unpadded_final_chunk_ends_with_the_trailers() {
        let wire: Vec<Bytes> = encode_response_stream_padded(
            ctx(),
            200,
            vec![("content-type".to_string(), "application/grpc".to_string())],
            collected_upstream(
                b"tip".to_vec(),
                vec![("grpc-status".to_string(), "0".to_string())],
            ),
            2048,
            Duration::from_millis(50),
            "test".to_string(),
            false,
        )
        .map(|r| r.unwrap())
        .collect()
        .await;
        assert_eq!(wire.len(), 2);
        let flat: Vec<u8> = wire.iter().flat_map(|b| b.to_vec()).collect();
        let (plaintext, lengths) = open_wire(&ctx(), &flat);
        assert_eq!(lengths, vec![plaintext.len()]);
        assert!(plaintext.len() < 100, "unpadded: {} bytes", plaintext.len());
        let (status, _, body, trailers) = parse_indeterminate(&plaintext);
        assert_eq!(status, 200);
        assert_eq!(body, b"tip");
        assert_eq!(trailers, vec![("grpc-status".to_string(), "0".to_string())]);
    }

    #[tokio::test]
    async fn unpadded_keeps_full_non_final_chunks() {
        let wire: Vec<Bytes> = encode_response_stream_padded(
            ctx(),
            200,
            vec![],
            collected_upstream(vec![7u8; 5000], vec![]),
            2048,
            Duration::from_millis(50),
            "test".to_string(),
            false,
        )
        .map(|r| r.unwrap())
        .collect()
        .await;
        let flat: Vec<u8> = wire.iter().flat_map(|b| b.to_vec()).collect();
        let (plaintext, lengths) = open_wire(&ctx(), &flat);
        assert_eq!(&lengths[..2], &[2048, 2048]);
        assert!(lengths[2] < 2048);
        let (_, _, body, _) = parse_indeterminate(&plaintext);
        assert_eq!(body, vec![7u8; 5000]);
    }

    #[tokio::test]
    async fn trailers_longer_than_a_chunk_are_not_duplicated() {
        let big = "x".repeat(3000);
        let upstream = collected_upstream(
            b"abc".to_vec(),
            vec![("grpc-message".to_string(), big.clone())],
        );
        let wire: Vec<Bytes> = encode_response_stream(
            ctx(),
            200,
            vec![],
            upstream,
            1024,
            Duration::from_millis(50),
            "test".to_string(),
        )
        .map(|r| r.unwrap())
        .collect()
        .await;
        let flat: Vec<u8> = wire.iter().flat_map(|b| b.to_vec()).collect();
        let (plaintext, lengths) = open_wire(&ctx(), &flat);
        assert!(lengths.iter().all(|l| *l == 1024), "{lengths:?}");
        let (_, _, body, trailers) = parse_indeterminate(&plaintext);
        assert_eq!(body, b"abc");
        assert_eq!(trailers, vec![("grpc-message".to_string(), big)]);
    }

    #[tokio::test]
    async fn upstream_error_ends_the_stream_without_a_final_chunk() {
        let upstream = async_stream::stream! {
            yield Ok(UpFrame::Data(Bytes::from(vec![1u8; 10])));
            yield Err(anyhow!("boom"));
        };
        let items: Vec<Result<Bytes, std::io::Error>> = encode_response_stream(
            ctx(),
            200,
            vec![],
            upstream,
            1024,
            Duration::from_millis(50),
            "test".to_string(),
        )
        .collect()
        .await;
        assert!(items.last().unwrap().is_err());
        // Only the nonce was emitted before the error.
        assert_eq!(items.len(), 2);
    }

    async fn frames(s: impl Stream<Item = Result<UpFrame>> + Send + 'static) -> Vec<UpFrame> {
        s.map(|r| r.unwrap()).collect().await
    }

    #[tokio::test]
    async fn ensure_grpc_status_appends_13_when_the_stream_ends_without_one() {
        let upstream =
            futures_util::stream::iter(vec![Ok(UpFrame::Data(Bytes::from_static(b"x")))]);
        let out = frames(ensure_grpc_status(false, upstream)).await;
        assert_eq!(out[0], UpFrame::Data(Bytes::from_static(b"x")));
        let UpFrame::Trailers(t) = &out[1] else {
            panic!("{out:?}")
        };
        assert_eq!(t[0], ("grpc-status".to_string(), "13".to_string()));
        assert_eq!(t[1].0, "grpc-message");
        assert_eq!(out.len(), 2);
    }

    #[tokio::test]
    async fn ensure_grpc_status_turns_an_upstream_error_into_13_trailers() {
        let upstream = async_stream::stream! {
            yield Ok(UpFrame::Data(Bytes::from(vec![1u8; 10])));
            yield Err(anyhow!("cut"));
            yield Ok(UpFrame::Data(Bytes::from(vec![2u8; 10])));
        };
        let out = frames(ensure_grpc_status(false, upstream)).await;
        assert_eq!(out.len(), 2, "nothing after the error: {out:?}");
        let UpFrame::Trailers(t) = &out[1] else {
            panic!("{out:?}")
        };
        assert_eq!(t[0], ("grpc-status".to_string(), "13".to_string()));
        assert!(t[1].1.contains("cut"));
    }

    #[tokio::test]
    async fn ensure_grpc_status_keeps_an_upstream_status() {
        let ok = vec![("grpc-status".to_string(), "0".to_string())];
        let upstream = futures_util::stream::iter(vec![
            Ok(UpFrame::Data(Bytes::from_static(b"x"))),
            Ok(UpFrame::Trailers(ok.clone())),
        ]);
        let out = frames(ensure_grpc_status(false, upstream)).await;
        assert_eq!(
            out,
            vec![
                UpFrame::Data(Bytes::from_static(b"x")),
                UpFrame::Trailers(ok)
            ]
        );
        // Trailers-only: the head carried the status, nothing is appended.
        let empty = futures_util::stream::iter(Vec::<Result<UpFrame>>::new());
        let out = frames(ensure_grpc_status(true, empty)).await;
        assert!(out.is_empty());
    }

    #[test]
    fn split_grpc_trailers_keeps_order_within_each_part() {
        let headers = vec![
            ("content-type".to_string(), "application/grpc".to_string()),
            ("grpc-status".to_string(), "0".to_string()),
            ("date".to_string(), "x".to_string()),
            ("Grpc-Message".to_string(), "ok".to_string()),
        ];
        let (headers, trailers) = split_grpc_trailers(headers);
        assert_eq!(
            headers,
            vec![
                ("content-type".to_string(), "application/grpc".to_string()),
                ("date".to_string(), "x".to_string()),
            ]
        );
        assert_eq!(
            trailers,
            vec![
                ("grpc-status".to_string(), "0".to_string()),
                ("Grpc-Message".to_string(), "ok".to_string()),
            ]
        );
    }

    /// A collected response with a body carries its status in the trailer section on the
    /// wire, where a client that streams the response expects it (gRPC Trailers-Only is for
    /// empty bodies). Regression: cache hits used to answer with a header-carried status.
    #[tokio::test]
    async fn a_collected_body_puts_grpc_status_in_the_trailer_section() {
        let (headers, trailers) = split_grpc_trailers(vec![
            ("content-type".to_string(), "application/grpc".to_string()),
            ("grpc-status".to_string(), "0".to_string()),
        ]);
        let wire: Vec<Bytes> = encode_response_stream(
            ctx(),
            200,
            headers,
            collected_upstream(b"body".to_vec(), trailers),
            64,
            Duration::from_millis(10),
            "test".into(),
        )
        .map(|r| r.expect("chunk"))
        .collect()
        .await;
        let wire: Vec<u8> = wire.concat();
        let (plaintext, _) = open_wire(&ctx(), &wire);
        // After the body: content terminator (0), then the trailer section with grpc-status.
        let body_end = plaintext
            .windows(4)
            .position(|w| w == b"body")
            .expect("body")
            + 4;
        let tail = &plaintext[body_end..];
        assert_eq!(tail[0], 0, "content terminator");
        assert_eq!(
            &tail[1..1 + 1 + 11],
            &[11, b'g', b'r', b'p', b'c', b'-', b's', b't', b'a', b't', b'u', b's'][..]
        );
        // And the header section does not carry it.
        let head = &plaintext[..body_end];
        assert!(!head.windows(11).any(|w| w == b"grpc-status"));
    }

    #[tokio::test]
    async fn on_end_reports_bytes_frames_status_and_outcome() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<StreamEnd>::new()));

        let s = seen.clone();
        let items: Vec<Result<UpFrame>> = on_end(
            futures_util::stream::iter(vec![
                Ok(UpFrame::Data(Bytes::from_static(b"abc"))),
                Ok(UpFrame::Data(Bytes::from_static(b"de"))),
                Ok(UpFrame::Trailers(vec![("grpc-status".into(), "0".into())])),
            ]),
            move |end| s.lock().unwrap().push(end),
        )
        .collect()
        .await;
        assert_eq!(items.len(), 3);
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            &[StreamEnd {
                bytes: 5,
                frames: 2,
                grpc_status: Some("0".into()),
                outcome: EndOutcome::Complete,
            }]
        );

        let s = seen.clone();
        let failing = async_stream::stream! {
            yield Ok(UpFrame::Data(Bytes::from_static(b"x")));
            yield Err(anyhow!("cut"));
        };
        let _: Vec<Result<UpFrame>> = on_end(failing, move |end| s.lock().unwrap().push(end))
            .collect()
            .await;
        assert_eq!(seen.lock().unwrap().len(), 2, "reported once");
        assert_eq!(
            seen.lock().unwrap()[1].outcome,
            EndOutcome::Failed("cut".into())
        );

        let s = seen.clone();
        let mut dropped = Box::pin(on_end(
            futures_util::stream::iter(vec![
                Ok(UpFrame::Data(Bytes::from_static(b"1"))),
                Ok(UpFrame::Data(Bytes::from_static(b"2"))),
            ]),
            move |end| s.lock().unwrap().push(end),
        ));
        let _ = dropped.next().await;
        drop(dropped);
        assert_eq!(seen.lock().unwrap().len(), 3);
        assert_eq!(seen.lock().unwrap()[2].outcome, EndOutcome::Dropped);
        assert_eq!(seen.lock().unwrap()[2].bytes, 1);
    }

    #[test]
    fn varint_encoding() {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 0);
        assert_eq!(&buf[..], &[0x00]);
        buf.clear();
        write_varint(&mut buf, 63);
        assert_eq!(&buf[..], &[0x3f]);
        buf.clear();
        write_varint(&mut buf, 64);
        assert_eq!(&buf[..], &[0x40, 0x40]);
        buf.clear();
        write_varint(&mut buf, 16384);
        assert_eq!(&buf[..], &[0x80, 0x00, 0x40, 0x00]);
    }
}

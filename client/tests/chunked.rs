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

//! Chunked OHTTP (draft-ietf-ohai-chunked-ohttp-08) round trips against the gateway's own
//! code: the client seals a chunked request the gateway opens, and the gateway's streaming
//! encoder (`chunked_stream::encode_response_stream`, the one the handler uses) produces what
//! `ChunkedResponseDecoder` opens, chunk by chunk, before the upstream has ended.

use std::collections::HashMap;
use std::time::Duration;

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use zodl_ohttp_client::{
    collect_response, encapsulate_chunked_request, ChunkedResponseDecoder, ChunkedResponseOpener,
    Error, KeyConfig, ResponseEvent,
};

use ohttp_gateway::{
    chunked_stream::{encode_response_stream, encode_response_stream_padded, UpFrame},
    config::Config,
    hpke::{KeyState, ResponseContext},
    ohttp_chunked::decapsulate_chunked_request,
};

/// The gateway's configuration with only its HPKE keys set.
fn gateway_config(key_id: u8, private_key_hex: &str) -> Config {
    Config {
        port: 0,
        lwd_addr: String::new(),
        mode: "ohttp".to_string(),
        relay_secrets: vec![],
        hpke_private_key: None,
        hpke_key_id: key_id,
        hpke_keys: vec![(key_id, private_key_hex.to_string())],
        lwd_timeout_secs: 80,
        long_poll_max_initial_silence_secs: 25,
        long_poll_idle_secs: 3,
        sse_keepalive_secs: 20,
        redis_url: String::new(),
        redis_security_url: String::new(),
        backends: HashMap::new(),
        backend_headers: HashMap::new(),
        backends_policy: HashMap::new(),
        backends_policy_default_allow: false,
        max_inflight_lwd: 128,
        max_inflight_lwd_heavy: 32,
        lwd_heavy_block_range: 100,
        redis_op_timeout_ms: 250,
        max_cache_get_concurrency: 64,
        max_large_response_concurrency: 2,
        large_response_threshold: 8 * 1024 * 1024,
        max_upstream_response_bytes: 64 * 1024 * 1024,
        max_inflight_upstream: 256,
        max_inflight_per_backend: 64,
        max_block_range: 1000,
        allow_unauthenticated_relay: false,
        proxy_allow_suffixes: vec![],
        network: "testnet".to_string(),
        log_outer_header_names: false,
        gateway_hosts: vec![],
        configs_signing_seed: None,
        chunk_size: 16384,
        chunk_flush_ms: 50,
        flexa_publishable_key: None,
        flexa_alias: None,
        near_alias: None,
        relay_secret_on_key_config: ohttp_gateway::config::RelaySecretOnKeyConfig::Off,
        lwd_permit_wait_ms: 2000,
        lwd_permit_max_waiters: 0,
    }
}

fn private_key(key_id: u8) -> String {
    format!("{:064x}", u64::from(key_id) + 0xa0)
}

fn key_state(key_id: u8) -> KeyState {
    KeyState::new(&gateway_config(key_id, &private_key(key_id))).unwrap()
}

/// A client request sealed to the gateway and opened there: the gateway's response context
/// and the client's opener for it.
async fn exchange(gateway: &KeyState) -> (ResponseContext, ChunkedResponseOpener) {
    let key_config = KeyConfig::select(&gateway.public_config()).unwrap();
    let request_plaintext = b"GET /test HTTP/1.1\r\nHost: backend.example\r\n\r\n";
    let (sealed_request, opener) =
        encapsulate_chunked_request(&key_config, request_plaintext).unwrap();
    let (decrypted_request, response_ctx) =
        decapsulate_chunked_request(&sealed_request[..], gateway)
            .await
            .unwrap();
    assert_eq!(decrypted_request, request_plaintext);
    (response_ctx, opener)
}

fn grpc_trailers() -> Vec<(String, String)> {
    vec![
        ("grpc-status".to_string(), "0".to_string()),
        ("grpc-message".to_string(), String::new()),
    ]
}

/// An upstream that yields `frames` `gap` apart, then the gRPC trailers.
fn slow_upstream(
    frames: Vec<Vec<u8>>,
    gap: Duration,
) -> impl Stream<Item = anyhow::Result<UpFrame>> + Send + 'static {
    futures_util::stream::unfold(
        (frames.into_iter(), false),
        move |(mut it, done)| async move {
            if done {
                return None;
            }
            match it.next() {
                Some(f) => {
                    tokio::time::sleep(gap).await;
                    Some((Ok(UpFrame::Data(Bytes::from(f))), (it, false)))
                }
                None => Some((Ok(UpFrame::Trailers(grpc_trailers())), (it, true))),
            }
        },
    )
}

fn headers() -> Vec<(String, String)> {
    vec![("content-type".to_string(), "application/grpc".to_string())]
}

/// Sealed chunk lengths on the wire: everything after the response nonce, each item one chunk.
fn sealed_lengths(wire: &[Bytes]) -> Vec<usize> {
    wire[1..].iter().map(|b| b.len()).collect()
}

#[tokio::test(start_paused = true)]
async fn first_data_is_decoded_before_the_upstream_ends() {
    let gateway = key_state(1);
    let (ctx, opener) = exchange(&gateway).await;
    let chunk_size = 1024;
    // Three 3000-byte frames, 10 ms apart (inside the 50 ms stall flush, so every chunk is a
    // fast-path chunk): the first frame alone fills two full chunks.
    let frames: Vec<Vec<u8>> = (1..=3u8).map(|i| vec![i; 3000]).collect();
    let body: Vec<u8> = frames.iter().flatten().copied().collect();
    let mut wire = Box::pin(encode_response_stream(
        ctx,
        200,
        headers(),
        slow_upstream(frames, Duration::from_millis(10)),
        chunk_size,
        Duration::from_millis(50),
        "test".to_string(),
    ));

    let started = tokio::time::Instant::now();
    let mut decoder = ChunkedResponseDecoder::from_opener(&opener);
    let mut events = Vec::new();
    let mut first_data_at = None;
    let mut sealed = Vec::new();
    while let Some(item) = wire.next().await {
        let bytes = item.unwrap();
        sealed.push(bytes.clone());
        for event in decoder.push(&bytes).unwrap() {
            if first_data_at.is_none() && matches!(event, ResponseEvent::Data(_)) {
                first_data_at = Some(started.elapsed());
            }
            events.push(event);
        }
    }
    let end = decoder.finish().unwrap();
    assert!(end.contains(&ResponseEvent::End));
    events.extend(end);

    // The first Data event came with the first frame (10 ms), not with the end (30 ms).
    let first_data_at = first_data_at.expect("data decoded");
    assert!(
        first_data_at >= Duration::from_millis(10),
        "{first_data_at:?}"
    );
    assert!(
        first_data_at < Duration::from_millis(20),
        "{first_data_at:?}"
    );
    assert!(started.elapsed() >= Duration::from_millis(30));

    // Every wire chunk carries chunk_size bytes of plaintext: the non-final ones are all the
    // same length, and the final one differs only by its 1-byte (zero) length prefix.
    let lens = sealed_lengths(&sealed);
    assert!(lens.len() >= 9, "{lens:?}");
    let (last, non_final) = lens.split_last().unwrap();
    assert!(
        non_final.iter().all(|l| *l == 2 + chunk_size + 16),
        "{lens:?}"
    );
    assert_eq!(*last, 1 + chunk_size + 16, "{lens:?}");

    let response = collect_response(events.clone()).unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-type"), Some("application/grpc"));
    assert_eq!(response.header("grpc-status"), Some("0"));
    assert_eq!(response.body, body);
    assert!(events
        .iter()
        .any(|e| matches!(e, ResponseEvent::Trailers(t) if *t == grpc_trailers())));
}

#[tokio::test]
async fn the_decoder_gives_the_same_message_for_every_byte_split() {
    let gateway = key_state(2);
    let (ctx, opener) = exchange(&gateway).await;
    let body = vec![0x5au8; 5000];
    let wire: Vec<Bytes> = encode_response_stream(
        ctx,
        200,
        headers(),
        slow_upstream(vec![body.clone()], Duration::ZERO),
        512,
        Duration::from_millis(50),
        "test".to_string(),
    )
    .map(|r| r.unwrap())
    .collect()
    .await;
    let flat: Vec<u8> = wire.iter().flat_map(|b| b.to_vec()).collect();

    for step in [1usize, 7, 100, flat.len()] {
        let mut decoder = ChunkedResponseDecoder::from_opener(&opener);
        let mut events = Vec::new();
        for piece in flat.chunks(step) {
            events.extend(decoder.push(piece).unwrap());
        }
        events.extend(decoder.finish().unwrap());
        let response = collect_response(events).unwrap();
        assert_eq!(response.status, 200, "step {step}");
        assert_eq!(response.body, body, "step {step}");
        assert_eq!(response.header("grpc-status"), Some("0"), "step {step}");
    }
    // The whole-response opener agrees.
    let response = opener.open_response(&flat).unwrap();
    assert_eq!(response.body, body);
}

/// RESPONSE_PADDING=off or sensitive: a final chunk that ends with the trailers, no zero bytes
/// after them, decodes like a padded one, streamed or whole.
#[tokio::test]
async fn an_unpadded_response_decodes() {
    let gateway = key_state(4);
    let (ctx, opener) = exchange(&gateway).await;
    let body = vec![0x42u8; 1500];
    let wire: Vec<Bytes> = encode_response_stream_padded(
        ctx,
        200,
        headers(),
        slow_upstream(vec![body.clone()], Duration::ZERO),
        1024,
        Duration::from_millis(50),
        "test".to_string(),
        false,
    )
    .map(|r| r.unwrap())
    .collect()
    .await;
    let flat: Vec<u8> = wire.iter().flat_map(|b| b.to_vec()).collect();

    let mut decoder = ChunkedResponseDecoder::from_opener(&opener);
    let mut events = decoder.push(&flat).unwrap();
    events.extend(decoder.finish().unwrap());
    let response = collect_response(events).unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, body);
    assert_eq!(response.header("grpc-status"), Some("0"));

    let response = opener.open_response(&flat).unwrap();
    assert_eq!(response.body, body);
}

#[tokio::test]
async fn truncation_tampering_and_padding() {
    let gateway = key_state(3);
    let (ctx, opener) = exchange(&gateway).await;
    let wire: Vec<Bytes> = encode_response_stream(
        ctx,
        403,
        vec![("content-type".to_string(), "text/plain".to_string())],
        slow_upstream(vec![b"policy denied".to_vec()], Duration::ZERO),
        2048,
        Duration::from_millis(50),
        "test".to_string(),
    )
    .map(|r| r.unwrap())
    .collect()
    .await;
    let flat: Vec<u8> = wire.iter().flat_map(|b| b.to_vec()).collect();

    // The final chunk is padded to 2048 bytes of plaintext, and the decoder accepts that.
    assert_eq!(flat.len(), 16 + 1 + 2048 + 16);
    let response = opener.open_response(&flat).unwrap();
    assert_eq!(response.status, 403);
    assert_eq!(response.body, b"policy denied");

    // Cut before the final chunk ends: finish() refuses (no final chunk opened).
    let mut decoder = ChunkedResponseDecoder::from_opener(&opener);
    decoder.push(&flat[..flat.len() / 2]).unwrap();
    assert!(matches!(decoder.finish(), Err(Error::Open)));

    // Cut before the final chunk began (inside the nonce, or before the final-chunk marker):
    // the exchange broke off, which is not a malformed answer.
    for cut in [0, 8, 16] {
        let mut decoder = ChunkedResponseDecoder::from_opener(&opener);
        decoder.push(&flat[..cut]).unwrap();
        assert!(
            matches!(decoder.finish(), Err(Error::Truncated)),
            "cut at {cut}"
        );
    }

    // A flipped bit anywhere fails authentication.
    let mut tampered = flat.clone();
    tampered[flat.len() / 2] ^= 1;
    assert!(opener.open_response(&tampered).is_err());

    // Bytes after the final chunk's tag are not padding: they break the AEAD tag check.
    let mut extended = flat.clone();
    extended.extend_from_slice(&[0, 0, 0, 0]);
    assert!(opener.open_response(&extended).is_err());
}

#[tokio::test]
async fn non_zero_padding_inside_the_final_chunk_is_rejected() {
    // Build the plaintext by hand: a complete message followed by a non-zero byte, sealed as
    // the one final chunk, must be refused as invalid padding (RFC 9292 §3.8).
    let gateway = key_state(4);
    let (ctx, opener) = exchange(&gateway).await;
    let mut plaintext = vec![3u8, 0x40, 200, 0, 0, 0]; // framing, 200, no headers/body/trailers
    plaintext.push(0); // zero padding is fine
    let good = seal_single_final_chunk(&ctx, &plaintext);
    opener.open_response(&good).unwrap();
    plaintext.push(1);
    let bad = seal_single_final_chunk(&ctx, &plaintext);
    assert!(matches!(
        opener.open_response(&bad),
        Err(zodl_ohttp_client::Error::BhttpFormat(_))
    ));
}

/// `nonce || varint(0) || Seal(final chunk)` with the gateway's own sealer.
fn seal_single_final_chunk(ctx: &ResponseContext, plaintext: &[u8]) -> Vec<u8> {
    use ohttp_gateway::chunked_stream::ChunkSealer;
    let nonce = [0x42u8; 16];
    let mut sealer = ChunkSealer::new(ctx, &nonce).unwrap();
    let mut out = nonce.to_vec();
    out.extend_from_slice(&sealer.seal(plaintext, true).unwrap());
    out
}

/// A non-final chunk that does not authenticate fails like a final one (`Error::Open`, which
/// the wallets map to INTERNAL), on the streaming and the whole-response paths alike; a cut
/// before the final chunk stays `Error::Truncated`.
#[tokio::test]
async fn a_non_final_chunk_that_does_not_open_is_an_open_error() {
    use ohttp_gateway::chunked_stream::ChunkSealer;
    let gateway = key_state(5);
    let (ctx, opener) = exchange(&gateway).await;
    let nonce = [0x24u8; 16];
    let mut sealer = ChunkSealer::new(&ctx, &nonce).unwrap();
    let mut message = vec![3u8, 0x40, 200, 0, 5];
    message.extend_from_slice(b"hello");
    let first = sealer.seal(&message, false).unwrap();
    let last = sealer.seal(&[0, 0, 0], true).unwrap();
    let mut wire = nonce.to_vec();
    wire.extend_from_slice(&first);
    wire.extend_from_slice(&last);
    assert_eq!(opener.open_response(&wire).unwrap().body, b"hello");

    // A flipped bit in the non-final chunk's ciphertext.
    let mut tampered = wire.clone();
    tampered[nonce.len() + 4] ^= 1;
    let mut decoder = ChunkedResponseDecoder::from_opener(&opener);
    assert!(matches!(decoder.push(&tampered), Err(Error::Open)));
    assert!(matches!(opener.open(&tampered), Err(Error::Open)));
    assert!(matches!(opener.open_response(&tampered), Err(Error::Open)));

    // A non-final chunk too short to hold its tag.
    let mut short = nonce.to_vec();
    short.extend_from_slice(&[4, 1, 2, 3, 4]);
    let mut decoder = ChunkedResponseDecoder::from_opener(&opener);
    assert!(matches!(decoder.push(&short), Err(Error::Open)));
    assert!(matches!(opener.open(&short), Err(Error::Open)));

    // Cut inside the non-final chunk: nothing failed to open, the exchange broke off.
    let cut = &wire[..nonce.len() + first.len() - 1];
    let mut decoder = ChunkedResponseDecoder::from_opener(&opener);
    assert!(decoder.push(cut).unwrap().is_empty());
    assert!(matches!(decoder.finish(), Err(Error::Truncated)));
    assert!(matches!(opener.open(cut), Err(Error::Truncated)));
}

/// A non-final chunk that authenticates but carries no plaintext breaks the draft's rule that
/// non-final chunks are not empty: refused with `Error::BhttpFormat` on the streaming and the
/// whole-response paths alike. (The gateway's sealer refuses to make one, so it is sealed here
/// by hand.)
#[tokio::test]
async fn an_empty_non_final_chunk_is_refused() {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes128Gcm, Nonce};
    use ohttp_gateway::chunked_stream::chunk_nonce;
    let gateway = key_state(9);
    let (ctx, opener) = exchange(&gateway).await;
    let nonce = [0x5au8; 16];
    let (aead_key, base_nonce) = ctx.derive_chunked_keys(&nonce).unwrap();
    let cipher = Aes128Gcm::new_from_slice(&aead_key).unwrap();
    let seal = |counter: u64, msg: &[u8], aad: &[u8]| {
        cipher
            .encrypt(
                Nonce::from_slice(&chunk_nonce(&base_nonce, counter)),
                Payload { msg, aad },
            )
            .unwrap()
    };
    let empty = seal(0, b"", b"");
    assert_eq!(empty.len(), 16);
    let mut message = vec![3u8, 0x40, 200, 0, 2];
    message.extend_from_slice(b"ok");
    message.extend_from_slice(&[0, 0]);
    let last = seal(1, &message, b"final");
    let mut wire = nonce.to_vec();
    wire.push(empty.len() as u8);
    wire.extend_from_slice(&empty);
    wire.push(0);
    wire.extend_from_slice(&last);

    let mut decoder = ChunkedResponseDecoder::from_opener(&opener);
    assert!(matches!(decoder.push(&wire), Err(Error::BhttpFormat(_))));
    assert!(matches!(opener.open(&wire), Err(Error::BhttpFormat(_))));
    assert!(matches!(
        opener.open_response(&wire),
        Err(Error::BhttpFormat(_))
    ));

    // The same body without the empty chunk (the final chunk at counter 0) opens.
    let mut good = nonce.to_vec();
    good.push(0);
    good.extend_from_slice(&seal(0, &message, b"final"));
    assert_eq!(opener.open_response(&good).unwrap().body, b"ok");
}

/// An empty request is sealed as the final chunk alone (a non-final chunk must not be empty),
/// which the gateway opens.
#[tokio::test]
async fn an_empty_request_is_the_final_chunk_alone() {
    let gateway = key_state(6);
    let key_config = KeyConfig::select(&gateway.public_config()).unwrap();
    let (sealed, _) = encapsulate_chunked_request(&key_config, &[]).unwrap();
    // hdr (7) || enc (32) || varint(0) || Seal("", aad "final") (16)
    assert_eq!(sealed.len(), 7 + 32 + 1 + 16);
    assert_eq!(sealed[39], 0);
    let (opened, _) = decapsulate_chunked_request(&sealed[..], &gateway)
        .await
        .unwrap();
    assert!(opened.is_empty());
}

/// The largest chunks a conforming gateway can emit (`CHUNK_SIZE` at the client's 64 KiB cap,
/// non-final chunks and a padded final chunk of `MAX_SEALED_RESPONSE_CHUNK_BYTES` each) decode,
/// streamed and whole; one byte more per chunk is refused.
#[tokio::test]
async fn a_chunk_at_the_cap_decodes_and_one_byte_more_is_refused() {
    use zodl_ohttp_client::chunked::{
        MAX_RESPONSE_CHUNK_PLAINTEXT_BYTES, MAX_SEALED_RESPONSE_CHUNK_BYTES,
    };
    assert_eq!(MAX_SEALED_RESPONSE_CHUNK_BYTES, 65536 + 16);

    let gateway = key_state(7);
    let body = vec![0x5au8; 3 * MAX_RESPONSE_CHUNK_PLAINTEXT_BYTES];
    let encode = |ctx, chunk_size| {
        encode_response_stream(
            ctx,
            200,
            headers(),
            slow_upstream(vec![body.clone()], Duration::ZERO),
            chunk_size,
            Duration::from_millis(50),
            "test".to_string(),
        )
        .map(|r| r.unwrap())
        .collect::<Vec<Bytes>>()
    };

    let (ctx, opener) = exchange(&gateway).await;
    let wire = encode(ctx, MAX_RESPONSE_CHUNK_PLAINTEXT_BYTES).await;
    let lengths = sealed_lengths(&wire);
    // Non-final: 4-byte varint prefix + sealed chunk; final: 1-byte prefix + sealed chunk.
    assert!(lengths.len() >= 2, "{lengths:?}");
    assert!(lengths[..lengths.len() - 1]
        .iter()
        .all(|l| *l == 4 + MAX_SEALED_RESPONSE_CHUNK_BYTES));
    assert_eq!(
        *lengths.last().unwrap(),
        1 + MAX_SEALED_RESPONSE_CHUNK_BYTES
    );
    let mut decoder = ChunkedResponseDecoder::from_opener(&opener);
    let mut events = Vec::new();
    for piece in &wire {
        events.extend(decoder.push(piece).unwrap());
    }
    events.extend(decoder.finish().unwrap());
    assert_eq!(collect_response(events).unwrap().body, body);
    let flat: Vec<u8> = wire.iter().flat_map(|b| b.to_vec()).collect();
    assert_eq!(opener.open_response(&flat).unwrap().body, body);
    assert!(opener.open(&flat).is_ok());

    let (ctx, opener) = exchange(&gateway).await;
    let wire = encode(ctx, MAX_RESPONSE_CHUNK_PLAINTEXT_BYTES + 1).await;
    let mut decoder = ChunkedResponseDecoder::from_opener(&opener);
    assert!(matches!(decoder.push(&wire[0]), Ok(events) if events.is_empty()));
    assert!(matches!(decoder.push(&wire[1]), Err(Error::BhttpFormat(_))));
    let flat: Vec<u8> = wire.iter().flat_map(|b| b.to_vec()).collect();
    assert!(matches!(opener.open(&flat), Err(Error::BhttpFormat(_))));
    assert!(matches!(
        opener.open_response(&flat),
        Err(Error::BhttpFormat(_))
    ));
}

/// A declared chunk length above the cap is refused as soon as the length prefix is read,
/// before any of the chunk arrives (it was buffered up to the whole-response limit before the
/// tag check could fail), and so is a final chunk that grows past the cap.
#[tokio::test]
async fn a_declared_chunk_length_above_the_cap_is_refused_before_buffering() {
    use zodl_ohttp_client::chunked::MAX_SEALED_RESPONSE_CHUNK_BYTES;
    let gateway = key_state(8);
    let (_, opener) = exchange(&gateway).await;
    let nonce = [0x33u8; 16];

    // varint prefixes: cap + 1 (4 bytes), 256 MiB (4 bytes), and the 8-byte varint maximum.
    let mut declared: Vec<Vec<u8>> = Vec::new();
    for len in [
        MAX_SEALED_RESPONSE_CHUNK_BYTES as u64 + 1,
        256 * 1024 * 1024,
    ] {
        declared.push(((len as u32) | 0x8000_0000).to_be_bytes().to_vec());
    }
    declared.push(u64::MAX.to_be_bytes().to_vec());
    for prefix in &declared {
        let mut wire = nonce.to_vec();
        wire.extend_from_slice(prefix);
        // Streaming: the prefix alone fails, nothing of the chunk is waited for.
        let mut decoder = ChunkedResponseDecoder::from_opener(&opener);
        assert!(
            matches!(decoder.push(&wire), Err(Error::BhttpFormat(_))),
            "{prefix:?}"
        );
        // Byte by byte, the failure comes with the prefix's last byte.
        let mut decoder = ChunkedResponseDecoder::from_opener(&opener);
        for b in &wire[..wire.len() - 1] {
            assert!(decoder.push(&[*b]).unwrap().is_empty());
        }
        assert!(matches!(
            decoder.push(&wire[wire.len() - 1..]),
            Err(Error::BhttpFormat(_))
        ));
        // Whole: a length above the cap is malformed, not a cut-short answer.
        assert!(matches!(opener.open(&wire), Err(Error::BhttpFormat(_))));
    }

    // A chunk at the cap is still waited for (it fails to open only once complete).
    let mut wire = nonce.to_vec();
    wire.extend_from_slice(&((MAX_SEALED_RESPONSE_CHUNK_BYTES as u32) | 0x8000_0000).to_be_bytes());
    let mut decoder = ChunkedResponseDecoder::from_opener(&opener);
    assert!(decoder.push(&wire).unwrap().is_empty());
    assert!(decoder
        .push(&vec![0u8; MAX_SEALED_RESPONSE_CHUNK_BYTES - 1])
        .unwrap()
        .is_empty());
    assert!(matches!(decoder.push(&[0]), Err(Error::Open)));

    // The final chunk runs to the end of the body: refused once it passes the cap, in one
    // push or across several.
    let mut wire = nonce.to_vec();
    wire.push(0);
    let mut decoder = ChunkedResponseDecoder::from_opener(&opener);
    assert!(decoder.push(&wire).unwrap().is_empty());
    assert!(decoder
        .push(&vec![0u8; MAX_SEALED_RESPONSE_CHUNK_BYTES])
        .unwrap()
        .is_empty());
    assert!(matches!(decoder.push(&[0]), Err(Error::BhttpFormat(_))));

    wire.extend_from_slice(&vec![0u8; MAX_SEALED_RESPONSE_CHUNK_BYTES + 1]);
    let mut decoder = ChunkedResponseDecoder::from_opener(&opener);
    assert!(matches!(decoder.push(&wire), Err(Error::BhttpFormat(_))));
    assert!(matches!(opener.open(&wire), Err(Error::BhttpFormat(_))));
}

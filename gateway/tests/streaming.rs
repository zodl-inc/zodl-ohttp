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

//! Streaming integration test: a chunked OHTTP request sealed with the `hpke` crate the way a
//! client does, opened by the gateway, answered through `encode_response_stream` from a slow
//! upstream, and opened again on the client side from the exported secret. Checks that the
//! first sealed chunk leaves before the upstream ends, that every chunk on the wire carries
//! `chunk_size` bytes of plaintext (the final one padded), and that the inner message, its
//! trailers included, is what the upstream sent.

use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use hkdf::Hkdf;
use hpke::{
    aead::AesGcm128, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem, OpModeS,
    Serializable,
};
use ohttp_gateway::chunked_stream::{chunk_nonce, encode_response_stream, UpFrame};
use ohttp_gateway::config::Config;
use ohttp_gateway::hpke::{KeyState, ResponseContext, N_K, N_N};
use ohttp_gateway::ohttp_chunked::decapsulate_chunked_request;
use rand_core::TryRngCore;
use sha2::Sha256;
use std::collections::HashMap;

const TAG: usize = 16;

fn gateway_config() -> Config {
    Config {
        port: 0,
        lwd_addr: String::new(),
        mode: "ohttp".to_string(),
        relay_secrets: vec![],
        hpke_private_key: None,
        hpke_key_id: 1,
        hpke_keys: vec![(1, format!("{:064x}", 0xa1u64))],
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

/// The client half of §6.1: `hdr || enc || varint(len) || seal(request) || varint(0) ||
/// seal("", "final")`, and the response secret exported from the same context.
fn seal_chunked_request(key_config: &[u8], request: &[u8]) -> (Vec<u8>, Vec<u8>, [u8; N_K]) {
    // application/ohttp-keys: len(2) key_id(1) kem_id(2) pk(32) suites_len(2) suites...
    let key_id = key_config[2];
    let pk_bytes = &key_config[5..37];
    let mut hdr = vec![key_id];
    hdr.extend_from_slice(&0x0020u16.to_be_bytes());
    hdr.extend_from_slice(&0x0001u16.to_be_bytes());
    hdr.extend_from_slice(&0x0001u16.to_be_bytes());
    let mut info = b"message/bhttp chunked request".to_vec();
    info.push(0);
    info.extend_from_slice(&hdr);
    let pk = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(pk_bytes).unwrap();
    let mut rng = rand_core::OsRng.unwrap_err();
    let (enc, mut ctx) = hpke::setup_sender::<AesGcm128, HkdfSha256, X25519HkdfSha256, _>(
        &OpModeS::Base,
        &pk,
        &info,
        &mut rng,
    )
    .unwrap();
    let sealed = ctx.seal(request, b"").unwrap();
    let fin = ctx.seal(&[], b"final").unwrap();
    let mut out = hdr;
    out.extend_from_slice(&enc.to_bytes());
    out.extend_from_slice(&[0x40 | (sealed.len() >> 8) as u8, sealed.len() as u8]);
    out.extend_from_slice(&sealed);
    out.push(0);
    out.extend_from_slice(&fin);
    let mut secret = [0u8; N_K];
    ctx.export(b"message/bhttp chunked response", &mut secret)
        .unwrap();
    (out, enc.to_bytes().to_vec(), secret)
}

fn read_varint(bytes: &[u8]) -> (u64, &[u8]) {
    let first = bytes[0];
    let len = 1usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for b in &bytes[1..len] {
        value = (value << 8) | u64::from(*b);
    }
    (value, &bytes[len..])
}

/// The client half of §6.2 from the exported secret: plaintext and per-chunk lengths.
fn open_wire(enc: &[u8], secret: &[u8], wire: &[u8]) -> (Vec<u8>, Vec<usize>) {
    let (response_nonce, mut rest) = wire.split_at(N_N.max(N_K));
    let mut salt = enc.to_vec();
    salt.extend_from_slice(response_nonce);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), secret);
    let mut key = [0u8; N_K];
    hkdf.expand(b"key", &mut key).unwrap();
    let mut base_nonce = [0u8; N_N];
    hkdf.expand(b"nonce", &mut base_nonce).unwrap();
    let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
    let mut plaintext = Vec::new();
    let mut lengths = Vec::new();
    let mut counter = 0u64;
    loop {
        let (len, tail) = read_varint(rest);
        let (sealed, aad, tail) = if len == 0 {
            (tail, &b"final"[..], &[][..])
        } else {
            let (s, t) = tail.split_at(len as usize);
            (s, &b""[..], t)
        };
        let chunk = cipher
            .decrypt(
                Nonce::from_slice(&chunk_nonce(&base_nonce, counter)),
                Payload { msg: sealed, aad },
            )
            .expect("chunk opens under the client's keys");
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

type Fields = Vec<(String, String)>;

fn section(rest: &mut &[u8]) -> Fields {
    let mut fields = Vec::new();
    loop {
        let (n, tail) = read_varint(rest);
        *rest = tail;
        if n == 0 {
            return fields;
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
}

/// An indeterminate-length BHTTP response (RFC 9292 §3.2) with trailing zero padding.
fn parse_response(plaintext: &[u8]) -> (u16, Fields, Vec<u8>, Fields) {
    let (framing, rest) = read_varint(plaintext);
    assert_eq!(framing, 3, "indeterminate-length framing");
    let (status, mut rest) = read_varint(rest);
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
    assert!(rest.iter().all(|b| *b == 0), "only zero padding may follow");
    (status as u16, headers, body, trailers)
}

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
                None => Some((
                    Ok(UpFrame::Trailers(vec![(
                        "grpc-status".to_string(),
                        "0".to_string(),
                    )])),
                    (it, true),
                )),
            }
        },
    )
}

async fn open_request(gateway: &KeyState) -> (ResponseContext, Vec<u8>, [u8; N_K]) {
    let request = b"POST /cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlockRange";
    let (sealed, enc, secret) = seal_chunked_request(&gateway.public_config(), request);
    let (plaintext, ctx) = decapsulate_chunked_request(&sealed[..], gateway)
        .await
        .unwrap();
    assert_eq!(plaintext, request);
    // The gateway derives the same chunk keys the client will.
    let nonce = [9u8; 16];
    let (gw_key, gw_nonce) = ctx.derive_chunked_keys(&nonce).unwrap();
    let mut salt = enc.clone();
    salt.extend_from_slice(&nonce);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &secret);
    let mut key = [0u8; N_K];
    hkdf.expand(b"key", &mut key).unwrap();
    let mut base_nonce = [0u8; N_N];
    hkdf.expand(b"nonce", &mut base_nonce).unwrap();
    assert_eq!((gw_key, gw_nonce), (key, base_nonce));
    (ctx, enc, secret)
}

#[tokio::test(start_paused = true)]
async fn streams_fixed_size_chunks_before_the_upstream_ends() {
    let gateway = KeyState::new(&gateway_config()).unwrap();
    let (ctx, enc, secret) = open_request(&gateway).await;

    let chunk_size = 2048;
    // Twenty 1500-byte "blocks", 20 ms apart: well inside the 50 ms stall flush.
    let frames: Vec<Vec<u8>> = (0..20u8).map(|i| vec![i; 1500]).collect();
    let body: Vec<u8> = frames.iter().flatten().copied().collect();
    let headers = vec![("content-type".to_string(), "application/grpc".to_string())];
    let mut wire = Box::pin(encode_response_stream(
        ctx,
        200,
        headers.clone(),
        slow_upstream(frames, Duration::from_millis(20)),
        chunk_size,
        Duration::from_millis(50),
        "test".to_string(),
    ));

    let started = tokio::time::Instant::now();
    let nonce = wire.next().await.unwrap().unwrap();
    assert_eq!(nonce.len(), N_N.max(N_K));
    let first = wire.next().await.unwrap().unwrap();
    // One full chunk needs two frames (3000 B > 2048 B): it leaves at 40 ms, not at 400 ms.
    assert_eq!(first.len(), 2 + chunk_size + TAG);
    assert!(started.elapsed() < Duration::from_millis(100));
    let mut items = vec![nonce, first];
    items.extend(wire.map(|r| r.unwrap()).collect::<Vec<Bytes>>().await);
    assert!(started.elapsed() >= Duration::from_millis(400));

    // Every sealed chunk on the wire is the same size (the final one has a 1-byte prefix).
    let lens: Vec<usize> = items[1..].iter().map(|b| b.len()).collect();
    let (last, non_final) = lens.split_last().unwrap();
    assert!(
        non_final.iter().all(|l| *l == 2 + chunk_size + TAG),
        "{lens:?}"
    );
    assert_eq!(*last, 1 + chunk_size + TAG, "{lens:?}");

    let flat: Vec<u8> = items.iter().flat_map(|b| b.to_vec()).collect();
    let (plaintext, plain_lens) = open_wire(&enc, &secret, &flat);
    assert!(
        plain_lens.iter().all(|l| *l == chunk_size),
        "{plain_lens:?}"
    );
    let (status, got_headers, got_body, trailers) = parse_response(&plaintext);
    assert_eq!(status, 200);
    assert_eq!(got_headers, headers);
    assert_eq!(got_body, body);
    assert_eq!(trailers, vec![("grpc-status".to_string(), "0".to_string())]);
}

#[tokio::test]
async fn a_small_response_is_one_padded_final_chunk() {
    let gateway = KeyState::new(&gateway_config()).unwrap();
    let (ctx, enc, secret) = open_request(&gateway).await;
    let items: Vec<Bytes> = encode_response_stream(
        ctx,
        200,
        vec![("content-type".to_string(), "application/grpc".to_string())],
        slow_upstream(
            vec![b"\x00\x00\x00\x00\x02\x08\x01".to_vec()],
            Duration::ZERO,
        ),
        4096,
        Duration::from_millis(50),
        "test".to_string(),
    )
    .map(|r| r.unwrap())
    .collect()
    .await;
    assert_eq!(items.len(), 2, "nonce and one final chunk");
    assert_eq!(items[1].len(), 1 + 4096 + TAG);
    let flat: Vec<u8> = items.iter().flat_map(|b| b.to_vec()).collect();
    let (plaintext, lens) = open_wire(&enc, &secret, &flat);
    assert_eq!(lens, vec![4096]);
    let (status, _, body, trailers) = parse_response(&plaintext);
    assert_eq!(status, 200);
    assert_eq!(body, b"\x00\x00\x00\x00\x02\x08\x01");
    assert_eq!(trailers[0], ("grpc-status".to_string(), "0".to_string()));
}

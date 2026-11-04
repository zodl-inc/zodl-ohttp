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

//! Seed corpora for the fuzz targets, from the encodings the tests use and the gateway's and
//! the client's own encoders: `cargo run --release --example gen_corpus -- corpus`.

use std::path::Path;

use ohttp_fuzz::{
    key_state, seal_request, seal_response, signed_envelope, ALIASES, GATEWAY_HOST, VECTOR_NOW,
};
use ohttp_gateway::{
    block_cache::BlockRangeRequest, rpc_cache, signing::SigningState,
    subtree_cache::SubtreeRootsRequest,
};
use zodl_ohttp_client::{encode_bhttp_request, BhttpRequest, EncodeOptions};

const LWD: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/";

fn write(dir: &Path, target: &str, seeds: &[Vec<u8>]) {
    let dir = dir.join(target);
    std::fs::create_dir_all(&dir).expect("corpus directory");
    for (i, seed) in seeds.iter().enumerate() {
        std::fs::write(dir.join(format!("seed-{i:03}")), seed).expect("seed file");
    }
}

fn prefixed(prefix: &[u8], seeds: &[Vec<u8>]) -> Vec<Vec<u8>> {
    seeds.iter().map(|s| cat(prefix, s)).collect()
}

fn cat(a: &[u8], b: &[u8]) -> Vec<u8> {
    [a, b].concat()
}

fn grpc(rpc: &str, body: Vec<u8>) -> BhttpRequest {
    BhttpRequest::new("POST", GATEWAY_HOST, format!("{LWD}{rpc}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("grpc-timeout", "30S")
        .header("ohttp-freshness", "1760000000")
        .body(body)
}

fn requests() -> Vec<Vec<u8>> {
    let requests = [
        grpc("GetLatestBlock", vec![0, 0, 0, 0, 0]),
        grpc(
            "GetBlockRange",
            BlockRangeRequest::grpc_body(3_000_000, 3_000_099, &[]),
        ),
        grpc(
            "GetBlockRange",
            BlockRangeRequest::grpc_body(3_000_099, 3_000_000, &[0x18, 1]),
        ),
        grpc(
            "GetBlockRange",
            BlockRangeRequest::grpc_body(1, 2_000_000, &[0x1a, 2, 1, 2]),
        ),
        grpc("GetBlock", rpc_cache::grpc_block_id(2_500_000, &[])),
        grpc("GetTreeState", rpc_cache::grpc_block_id(0, &[0xab; 32])),
        grpc("GetTransaction", rpc_cache::grpc_block_id(0, &[0xcd; 32])),
        grpc("GetSubtreeRoots", SubtreeRootsRequest::grpc_body(0, 1, 0)),
        grpc("GetLightdInfo", vec![0, 0, 0, 0, 0]),
        BhttpRequest::new(
            "GET",
            ALIASES[0],
            "/v1/cryptocurrency/quotes/latest?id=1437",
        )
        .header("accept", "application/json")
        .header("ohttp-freshness", "1760000000"),
        BhttpRequest::new("GET", ALIASES[0], "/v2/tools/price-conversion?amount=1"),
        BhttpRequest::new("POST", ALIASES[1], "/")
            .header("content-type", "application/json")
            .body(br#"{"jsonrpc":"2.0","id":1,"method":"status","params":[]}"#.to_vec()),
        BhttpRequest::new("GET", format!("{}:8080", ALIASES[2]), "/rounds/1"),
        BhttpRequest::new("GET", "evil.example", "/"),
        BhttpRequest::new("GET", "", "/"),
    ];
    let mut out: Vec<Vec<u8>> = requests
        .iter()
        .flat_map(|r| {
            [
                encode_bhttp_request(r, &EncodeOptions::LOWERCASE).unwrap(),
                encode_bhttp_request(r, &EncodeOptions::PRESERVE_FRESH).unwrap(),
            ]
        })
        .collect();
    // Indeterminate length (framing 2), as the bhttp crate also reads it.
    out.push(b"\x02\x03GET\x05https\x0fgateway.example\x01/\x00\x00\x00".to_vec());
    out
}

/// An indeterminate-length response: framing 3, status, headers, content chunks, trailers,
/// then zero padding (the client tests' `indeterminate`).
fn response(
    status: u16,
    headers: &[(&str, &str)],
    chunks: &[&[u8]],
    trailers: &[(&str, &str)],
    padding: usize,
) -> Vec<u8> {
    fn varint(out: &mut Vec<u8>, v: usize) {
        match v {
            0..=0x3f => out.push(v as u8),
            0x40..=0x3fff => out.extend_from_slice(&(v as u16 | 0x4000).to_be_bytes()),
            _ => out.extend_from_slice(&(v as u32 | 0x8000_0000).to_be_bytes()),
        }
    }
    let field = |out: &mut Vec<u8>, (n, v): &(&str, &str)| {
        varint(out, n.len());
        out.extend_from_slice(n.as_bytes());
        varint(out, v.len());
        out.extend_from_slice(v.as_bytes());
    };
    let mut out = vec![3u8];
    varint(&mut out, usize::from(status));
    headers.iter().for_each(|f| field(&mut out, f));
    out.push(0);
    for chunk in chunks {
        varint(&mut out, chunk.len());
        out.extend_from_slice(chunk);
    }
    out.push(0);
    trailers.iter().for_each(|f| field(&mut out, f));
    out.push(0);
    out.extend(std::iter::repeat_n(0u8, padding));
    out
}

fn responses() -> Vec<Vec<u8>> {
    let grpc = [
        ("content-type", "application/grpc"),
        ("ohttp-server-time", "1760000000"),
    ];
    let ok = [("grpc-status", "0"), ("grpc-message", "")];
    let block = rpc_cache::grpc_block_id(3_000_000, &[0x11; 32]);
    let mut interim = vec![3u8, 0x40, 103, 4];
    interim.extend_from_slice(b"link");
    interim.extend_from_slice(&[1, b'x', 0]);
    interim.extend_from_slice(&response(200, &[], &[b"ok"], &[], 0)[1..]);
    vec![
        response(200, &grpc, &[&block, &block], &ok, 0),
        response(200, &grpc, &[&[0x5a; 300]], &ok, 37),
        response(
            403,
            &[("content-type", "text/plain")],
            &[b"policy denied"],
            &[],
            64,
        ),
        response(400, &[("ohttp-freshness", "rejected")], &[], &[], 0),
        response(
            200,
            &grpc,
            &[],
            &[("grpc-status", "14"), ("grpc-message", "unavailable")],
            0,
        ),
        interim,
        // Known length (framing 1), as the no_panics sweep uses.
        vec![1, 0x40, 200, 4, 1, b'a', 1, b'b', 3, 1, 2, 3, 0, 0, 0, 0, 0],
    ]
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "corpus".into());
    let dir = Path::new(&dir);

    let requests = requests();
    write(dir, "gateway_inner_request", &requests);
    let mut sealed: Vec<Vec<u8>> = requests
        .iter()
        .map(|r| cat(&[0], &seal_request(r).0))
        .collect();
    sealed.extend(prefixed(&[1], &requests));
    write(dir, "gateway_chunked_request", &sealed);

    let frames = [
        rpc_cache::grpc_block_id(3_000_000, &[0x11; 32]),
        BlockRangeRequest::grpc_body(10, 20, &[]),
        SubtreeRootsRequest::grpc_body(7, 1, 3),
        rpc_cache::encode_validated(3_000_000, &[0x22; 32], &rpc_cache::grpc_block_id(1, &[2])),
    ];
    let mut grpc: Vec<Vec<u8>> = frames.iter().map(|f| cat(&[7], f)).collect();
    grpc.push(cat(&[0], &frames.concat()));
    grpc.push(cat(&[3], &frames[0][..frames[0].len() - 1]));
    write(dir, "gateway_grpc_frames", &grpc);

    write(
        dir,
        "gateway_outer_headers",
        &[
            b"x-request-id: 5f0c2a1e-relay\nx-client-trace-id: example-phone-test-1\n".to_vec(),
            b"fastly-trace-id: abc.123:def\ncontent-type: message/ohttp-chunked-req\n".to_vec(),
            b"x-request-id: \x80bad\n".to_vec(),
            b"1760000000".to_vec(),
        ],
    );

    let responses = responses();
    let mut wires: Vec<Vec<u8>> = responses
        .iter()
        .map(|r| {
            let (head, tail) = r.split_at(r.len() / 2);
            cat(&[0, 7], &seal_response(&[head, tail]))
        })
        .collect();
    wires.extend(
        responses
            .iter()
            .map(|r| cat(&[0, 63], &seal_response(&[r]))),
    );
    wires.extend(prefixed(&[1, 5, 2], &responses));
    wires.extend(prefixed(&[3, 9, 3], &responses));
    write(dir, "client_chunked_response", &wires);
    write(dir, "client_bhttp_response", &responses);

    let document = key_state().public_config();
    let mut no_panics = vec![4u8, 0x00, 0x20];
    no_panics.extend_from_slice(&[9; 32]);
    no_panics.extend_from_slice(&[0, 4, 0, 1, 0, 1]);
    let mut two = vec![0, 8, 1, 0, 0x10, 0, 0, 0, 0, 0];
    two.extend_from_slice(&[0, no_panics.len() as u8]);
    two.extend_from_slice(&no_panics);
    let mut one = vec![0, no_panics.len() as u8];
    one.extend_from_slice(&no_panics);
    write(dir, "client_key_config", &[document.clone(), one, two]);

    let vector_configs: Vec<u8> = (0u8..=42).collect();
    let gateway = SigningState::new(&"22".repeat(32), "testnet".into()).expect("signing seed");
    let issued = serde_json::to_vec(&gateway.get_signed_config_at(&document, VECTOR_NOW)).unwrap();
    let mut structured = vec![1u8, 0];
    structured.extend_from_slice(&1_700_000_000u64.to_be_bytes());
    structured.extend_from_slice(&1_700_021_600u64.to_be_bytes());
    structured.extend_from_slice(&document);
    write(
        dir,
        "client_signed_config",
        &[
            cat(
                &[0],
                &signed_envelope("testnet", 1_700_000_000, 1_700_021_600, &vector_configs),
            ),
            cat(&[0], &issued),
            structured,
        ],
    );

    write(
        dir,
        "client_outer",
        &[
            cat(&[1, 0xad], b"30"),
            cat(&[0, 200], b"message/ohttp-chunked-res; charset=binary"),
            cat(
                &[1, 0xa6],
                br#"{"type":"https://iana.org/assignments/http-problem-types#ohttp-key","status":422}"#,
            ),
            cat(&[0, 200], b"https://relay-mainnet.example/relay"),
            cat(&[0, 200], b"max-age=600, no-cache"),
            cat(&[1, 0x90], b"1760000000"),
        ],
    );
}

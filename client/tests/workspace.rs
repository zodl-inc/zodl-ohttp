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

//! Checks that need the rest of the repository: the gateway's request parser
//! (`zodl-ohttp-gateway`'s library) and the documented test vector. Like `gateway.rs`,
//! `gateway_core.rs` and `chunked.rs`, this file is left out of the published crate
//! (`exclude` in `Cargo.toml`), whose dev-dependencies do not include the gateway.

use zodl_ohttp_client::{encode_request, Request};
use zodl_ohttp_gateway::ohttp::parse_inner_request;

const SEND_TRANSACTION: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/SendTransaction";

#[test]
fn the_crates_test_vector_is_the_documented_one() {
    assert_eq!(
        include_str!("../testdata/signed-configs-test-vector.json"),
        include_str!("../../docs/signed-configs-test-vector.json")
    );
}

#[test]
fn the_crates_relay_weights_vector_is_the_documented_one() {
    assert_eq!(
        include_str!("../testdata/relay-weights-test-vector.json"),
        include_str!("../../docs/relay-weights-test-vector.json")
    );
}

#[test]
fn the_crates_relay_url_vectors_are_the_documented_ones() {
    assert_eq!(
        include_str!("../testdata/relay-url-vectors.json"),
        include_str!("../../docs/relay-url-vectors.json")
    );
}

#[test]
fn a_request_encodes_as_the_gateway_reads_it() {
    let request = Request::new("POST", "backend.example", "/v1/slots/ab/entries?since=3")
        .header("content-type", "application/json")
        .body(br#"{"a":1}"#.to_vec());
    let encoded = encode_request(&request).unwrap();
    let inner = parse_inner_request(&encoded).unwrap();
    assert_eq!(inner.method, "POST");
    assert_eq!(inner.authority, "backend.example");
    assert_eq!(inner.path, "/v1/slots/ab/entries?since=3");
    assert_eq!(inner.body, br#"{"a":1}"#);
    assert!(inner
        .headers
        .iter()
        .any(|(k, v)| k == "content-type" && v == "application/json"));
}

/// The padding after the message (`src/message.rs` checks it is zeros) is skipped: the gateway
/// reads exactly the request's method, authority, path, headers (and the freshness stamp) and
/// body, and refuses a non-zero byte there.
#[test]
fn the_gateway_reads_a_padded_request_as_the_request() {
    for (path, body) in [
        (
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock",
            vec![0; 5],
        ),
        (SEND_TRANSACTION, vec![7; 20_000]),
    ] {
        let request = Request::new("POST", "gw.example", path)
            .header("content-type", "application/grpc")
            .body(body.clone());
        let padded = encode_request(&request).unwrap();
        let inner = parse_inner_request(&padded).unwrap();
        assert_eq!(
            (
                inner.method.as_str(),
                inner.authority.as_str(),
                inner.path.as_str()
            ),
            ("POST", "gw.example", path)
        );
        assert_eq!(inner.body, body);
        let (stamps, others): (Vec<_>, Vec<_>) = inner
            .headers
            .iter()
            .partition(|(k, _)| k == "ohttp-freshness");
        assert_eq!(stamps.len(), 1);
        assert!(stamps[0].1.bytes().all(|b| b.is_ascii_digit()));
        assert_eq!(
            others
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect::<Vec<_>>(),
            [("content-type", "application/grpc")]
        );
        // Non-zero bytes after the message are refused.
        let mut junk = padded.clone();
        *junk.last_mut().unwrap() = 1;
        assert!(parse_inner_request(&junk).is_err());
    }
}

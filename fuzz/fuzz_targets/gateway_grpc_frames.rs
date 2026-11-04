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

//! Upstream (lightwalletd) response bodies: gRPC framing as the streaming proxy and the caches
//! split it, and the messages the caches decode from it. The first byte sets the size of the
//! pieces the splitter is fed.

#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use ohttp_gateway::{
    block_cache::GrpcSplitter,
    fuzzing::{count_grpc_messages, last_complete_grpc_message_offset},
    ohttp::InnerResponse,
    rpc_cache::{self, HashSource},
    subtree_cache::FetchedRoot,
};

fuzz_target!(|data: &[u8]| {
    let Some((&step, body)) = data.split_first() else {
        return;
    };
    let end = last_complete_grpc_message_offset(body);
    assert!(end <= body.len());
    let count = count_grpc_messages(body, end);

    let mut splitter = GrpcSplitter::default();
    let mut frames = Vec::new();
    for piece in body.chunks(usize::from(step % 64) + 1) {
        frames.extend(splitter.push(piece));
    }
    assert_eq!(frames.len(), count);
    let joined: Vec<u8> = frames.iter().flat_map(|f| f.to_vec()).collect();
    assert_eq!(&joined[..], &body[..end]);
    assert_eq!(splitter.remainder(), body.len() - end);

    for frame in &frames {
        let _ = rpc_cache::grpc_message(frame);
        let root = FetchedRoot::from_frame(frame.clone());
        let _ = root.message();
    }
    let _ = FetchedRoot::from_frame(Bytes::copy_from_slice(body));

    let response = InnerResponse {
        status: 200,
        headers: vec![],
        body: body.to_vec(),
    };
    for source in [
        HashSource::CompactBlock,
        HashSource::TreeState,
        HashSource::Index,
    ] {
        let _ = rpc_cache::chain_position(source, &response);
    }
    if let Some((height, hash, payload)) = rpc_cache::decode_validated(body) {
        assert_eq!(rpc_cache::encode_validated(height, hash, payload), body);
    }
    let _ = rpc_cache::should_admit(body, true);
});

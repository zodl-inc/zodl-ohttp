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

//! The parsers of bytes from the network do not panic on malformed bytes. A deterministic
//! pseudo-random sweep (no extra dependency; the seed is fixed so a failure reproduces) over
//! the byte parsers and the chunked decapsulation path: random bytes, and valid inputs with bytes
//! flipped, cut and extended.

use zodl_ohttp_client::{
    classify_outer_response, decode_bhttp_response, decode_response, encapsulate_chunked_request,
    encode_bhttp_request, signed_config_url, verify_signed_config, verify_signed_config_with,
    BhttpRequest, ChunkedResponseDecoder, ClientProfile, DecodeOptions, EncodeOptions, KeyConfig,
    KeySelection, Network, OuterResponse, SignedConfigPolicy, SignedConfigUrlRule,
};

/// xorshift64*: good enough to make bytes, and the same on every machine.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn bytes(&mut self, max_len: usize) -> Vec<u8> {
        let len = self.below(max_len + 1);
        (0..len).map(|_| self.next() as u8).collect()
    }
    /// `base` with a few bytes flipped, then possibly cut or extended.
    fn mutate(&mut self, base: &[u8]) -> Vec<u8> {
        let mut out = base.to_vec();
        for _ in 0..self.below(4) {
            if !out.is_empty() {
                let at = self.below(out.len());
                out[at] = self.next() as u8;
            }
        }
        match self.below(4) {
            0 => out.truncate(self.below(out.len() + 1)),
            1 => out.extend(self.bytes(16)),
            _ => {}
        }
        out
    }
}

const ROUNDS: usize = 4000;
const SELECTIONS: [KeySelection; 4] = [
    KeySelection::LIBRARY,
    KeySelection::ANDROID,
    KeySelection::IOS,
    KeySelection::SLIPSTREAM,
];
const PROFILES: [ClientProfile; 4] = [
    ClientProfile::LIBRARY,
    ClientProfile::ANDROID,
    ClientProfile::IOS,
    ClientProfile::SLIPSTREAM,
];

fn valid_document() -> Vec<u8> {
    let mut config = vec![4u8, 0x00, 0x20];
    config.extend_from_slice(&[9; 32]);
    config.extend_from_slice(&[0, 4, 0, 1, 0, 1]);
    let mut document = (config.len() as u16).to_be_bytes().to_vec();
    document.extend(config);
    document
}

#[test]
fn key_configurations_never_panic() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    let base = valid_document();
    for i in 0..ROUNDS {
        let input = if i % 2 == 0 {
            rng.bytes(200)
        } else {
            rng.mutate(&base)
        };
        for selection in &SELECTIONS {
            let _ = KeyConfig::select_with(&input, selection);
        }
    }
}

#[test]
fn binary_http_never_panics() {
    let mut rng = Rng(0x0bad_cafe_f00d_0001);
    let response = {
        let mut r = vec![1u8, 0x40, 200, 4, 1, b'a', 1, b'b', 3, 1, 2, 3, 0];
        r.extend_from_slice(&[0; 4]);
        r
    };
    let indeterminate = vec![3u8, 0x40, 200, 1, b'a', 1, b'b', 0, 2, 1, 2, 0, 0, 0];
    let request = encode_bhttp_request(
        &BhttpRequest::new("POST", "a.example", "/p")
            .header("k", "v")
            .body(vec![1, 2, 3]),
        &EncodeOptions::LOWERCASE,
    )
    .unwrap();
    for i in 0..ROUNDS * 2 {
        let input = match i % 4 {
            0 => rng.bytes(120),
            1 => rng.mutate(&response),
            2 => rng.mutate(&indeterminate),
            _ => rng.mutate(&request),
        };
        for decode in [DecodeOptions::ANY_STATUS, DecodeOptions::HTTP_STATUS] {
            let _ = decode_bhttp_response(&input, &decode);
        }
        let _ = decode_response(&input);
    }
    // Lengths that claim more than the input holds, at several varint widths, are refused.
    for prefix in [
        vec![
            1u8, 0x40, 200, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ],
        vec![1u8, 0x40, 200, 0x3f, 0xff],
        vec![1u8, 0x40, 200, 0, 0xbf, 0xff, 0xff, 0xff],
        vec![
            3u8, 0x40, 200, 0xc0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ],
    ] {
        assert!(decode_bhttp_response(&prefix, &DecodeOptions::ANY_STATUS).is_err());
    }
}

#[test]
fn signed_envelopes_never_panic() {
    let mut rng = Rng(0x5eed_5eed_5eed_5eed);
    let base = br#"{"v":1,"network":"testnet","configs":"AAAA","not_before":10,"not_after":20,"key_id":"abcd1234","sig":"AAAA"}"#;
    let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]).verifying_key();
    for i in 0..ROUNDS {
        let input = if i % 3 == 0 {
            rng.bytes(300)
        } else {
            rng.mutate(base)
        };
        for policy in [
            SignedConfigPolicy::LIBRARY,
            SignedConfigPolicy::ANDROID,
            SignedConfigPolicy::IOS,
            SignedConfigPolicy::SLIPSTREAM,
        ] {
            let _ = verify_signed_config(&input, Network::Testnet, 15, &policy);
            let _ = verify_signed_config_with(&input, "testnet", &key, 15, &policy);
        }
    }
}

#[test]
fn sealed_responses_never_panic() {
    let mut rng = Rng(0xfeed_face_dead_beef);
    let doc = valid_document();
    let key = KeyConfig::select(&doc).unwrap();
    // One real sealing gives the opener; every answer below is fed to it whole and in pieces.
    let (_, opener) = encapsulate_chunked_request(&key, b"").unwrap();
    for i in 0..ROUNDS {
        let input = rng.bytes(if i % 10 == 0 { 2000 } else { 80 });
        let _ = opener.open(&input);
        let _ = opener.open_response(&input);
        let mut decoder = ChunkedResponseDecoder::from_opener(&opener);
        let step = 1 + rng.below(16);
        let mut failed = false;
        for piece in input.chunks(step) {
            if decoder.push(piece).is_err() {
                failed = true;
                break;
            }
        }
        if !failed {
            let _ = decoder.finish();
        }
    }
    // Requests of odd shapes seal and the lengths stay consistent: hdr(7) || enc(32) ||
    // varint(len) || ct(len = plain + 16) || varint(0) || final chunk (16).
    for _ in 0..200 {
        let request = BhttpRequest::new(rng.bytes(8), rng.bytes(40), rng.bytes(60))
            .header(rng.bytes(10), rng.bytes(10))
            .body(rng.bytes(300));
        let plain = encode_bhttp_request(&request, &EncodeOptions::LOWERCASE).unwrap();
        let (sealed, _) = encapsulate_chunked_request(&key, &plain).unwrap();
        let chunk = plain.len() + 16;
        let varint = if chunk < 64 { 1 } else { 2 };
        assert_eq!(sealed.len(), 7 + 32 + varint + chunk + 1 + 16);
    }
}

#[test]
fn outer_answers_and_urls_never_panic() {
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    for _ in 0..ROUNDS {
        let body = rng.bytes(400);
        let content_type = String::from_utf8_lossy(&rng.bytes(30)).into_owned();
        let status = rng.next() as u16;
        for profile in &PROFILES {
            for attempt in [0, 1, u32::MAX] {
                let _ = classify_outer_response(
                    &profile.outer,
                    &OuterResponse {
                        status,
                        content_type: Some(&content_type),
                        body: &body,
                    },
                    attempt,
                );
            }
            let url = String::from_utf8_lossy(&rng.bytes(60)).into_owned();
            for rule in [
                SignedConfigUrlRule::TrimThenReplaceRelaySuffix,
                SignedConfigUrlRule::ReplaceRelaySuffix,
                SignedConfigUrlRule::RelayHostRoot,
            ] {
                let _ = signed_config_url(&url, rule);
            }
            let host = String::from_utf8_lossy(&rng.bytes(30)).into_owned();
            let _ = profile.network_rule.network_for(&host);
        }
    }
}

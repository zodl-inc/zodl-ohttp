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

//! The sans-IO core against published vectors (RFC 9180 Appendix A.1.1, RFC 9458 Appendix A's
//! key configuration) and against an independent chunked-OHTTP receiver
//! (draft-ietf-ohai-chunked-ohttp-08) built from the `hpke` crate.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use hpke::aead::AesGcm128;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::rand_core::{CryptoRng, RngCore};
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use sha2::Sha256;
use zodl_ohttp_client::{
    check_size, classify_outer_response, encapsulate_chunked_request, encode_bhttp_request,
    encode_request, BhttpRequest, ChunkedResponseDecoder, ChunkedResponseOpener, ClientProfile,
    EncodeOptions, Error, KeyConfig, KeySelection, Limits, Network, OuterOutcome, OuterResponse,
    Request, ResponseEvent, UnsupportedKem, CONTENT_TYPE_CHUNKED_RES,
};

fn hex(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s.bytes().filter(u8::is_ascii_hexdigit).collect();
    digits
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

/// An RNG that yields `bytes` and then fails: what hpke's `gen_keypair` reads as `ikmE`.
struct Fixed(Vec<u8>);

impl RngCore for Fixed {
    fn next_u32(&mut self) -> u32 {
        unimplemented!("hpke reads bytes")
    }
    fn next_u64(&mut self) -> u64 {
        unimplemented!("hpke reads bytes")
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        assert!(dest.len() <= self.0.len(), "the fixed RNG ran dry");
        let rest = self.0.split_off(dest.len());
        dest.copy_from_slice(&self.0);
        self.0 = rest;
    }
}
impl CryptoRng for Fixed {}

/// RFC 9180 Appendix A.1.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, base mode.
/// The dependency that does the HPKE under `encapsulate_chunked_request` reproduces the
/// published values.
#[test]
fn rfc_9180_a_1_1_known_answers() {
    let info = hex("4f6465206f6e2061204772656369616e2055726e");
    let ikm_e = hex("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");
    let pk_em = hex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
    let pk_rm = hex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
    let sk_rm = hex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
    let pt = hex("4265617574792069732074727574682c20747275746820626561757479");

    let pk_r = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&pk_rm).unwrap();
    let (enc, mut sender) = hpke::setup_sender::<AesGcm128, HkdfSha256, X25519HkdfSha256, _>(
        &OpModeS::Base,
        &pk_r,
        &info,
        &mut Fixed(ikm_e),
    )
    .unwrap();
    assert_eq!(enc.to_bytes().as_slice(), pk_em);

    let sk_r = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&sk_rm).unwrap();
    let mut receiver = hpke::setup_receiver::<AesGcm128, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &sk_r,
        &enc,
        &info,
    )
    .unwrap();

    // Sequence numbers 0, 1 and 2.
    for (aad, ct) in [
        (
            "436f756e742d30",
            "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
        ),
        (
            "436f756e742d31",
            "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84",
        ),
        (
            "436f756e742d32",
            "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180",
        ),
    ] {
        let sealed = sender.seal(&pt, &hex(aad)).unwrap();
        assert_eq!(sealed, hex(ct));
        assert_eq!(receiver.open(&sealed, &hex(aad)).unwrap(), pt);
    }

    // Exported values.
    for (context, want) in [
        (
            "",
            "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee",
        ),
        (
            "00",
            "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5",
        ),
        (
            "54657374436f6e74657874",
            "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931",
        ),
    ] {
        let mut out = [0u8; 32];
        sender.export(&hex(context), &mut out).unwrap();
        assert_eq!(out.as_slice(), hex(want));
    }
}

// ---- RFC 9458 Appendix A: the key configuration and the Binary HTTP request ---------------

const RFC9458_SECRET_KEY: &str = "3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a";
const RFC9458_KEY_CONFIG: &str =
    "01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e79815500080001000100010003";
const RFC9458_BHTTP_REQUEST: &str = "00034745540568747470730b6578616d706c652e636f6d012f";

fn receiver_key() -> <X25519HkdfSha256 as Kem>::PrivateKey {
    <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&hex(RFC9458_SECRET_KEY)).unwrap()
}

#[test]
fn rfc_9458_key_configuration_is_selected_under_every_profile() {
    let document = {
        // The document is the configuration behind its two-byte length.
        let config = hex(RFC9458_KEY_CONFIG);
        let mut d = (config.len() as u16).to_be_bytes().to_vec();
        d.extend(config);
        d
    };
    for selection in [
        KeySelection::LIBRARY,
        KeySelection::ANDROID,
        KeySelection::IOS,
        KeySelection::SLIPSTREAM,
    ] {
        let config = KeyConfig::select_with(&document, &selection).unwrap();
        assert_eq!(config.key_id(), 1);
        assert_eq!(
            config.public_key().as_slice(),
            hex("31e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155")
        );
    }
}

#[test]
fn rfc_9458_bhttp_request_is_ours_up_to_the_sections_it_leaves_out() {
    // RFC 9292 §3.1 lets a message stop before its empty header section, content and trailer
    // section; the clients write all three.
    let request = BhttpRequest::new("GET", "example.com", "/");
    let ours = encode_bhttp_request(&request, &EncodeOptions::LOWERCASE).unwrap();
    let mut expected = hex(RFC9458_BHTTP_REQUEST);
    expected.extend_from_slice(&[0, 0, 0]);
    assert_eq!(ours, expected);
    // The library's `Request` maps to the same bytes; `encode_request` itself also appends the
    // freshness field real requests need.
    let request = Request::new("GET", "example.com", "/");
    assert_eq!(
        encode_bhttp_request(&BhttpRequest::from(&request), &EncodeOptions::PRESERVE).unwrap(),
        expected
    );
    let stamped = encode_request(&request).unwrap();
    assert!(stamped.len() > expected.len());
    assert!(stamped
        .windows(b"ohttp-freshness".len())
        .any(|w| w == b"ohttp-freshness"));
}

// ---- An independent chunked-OHTTP receiver (draft-ietf-ohai-chunked-ohttp-08) --------------

fn read_varint(bytes: &[u8]) -> (u64, &[u8]) {
    let first = bytes[0];
    let len = 1usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for b in &bytes[1..len] {
        value = (value << 8) | u64::from(*b);
    }
    (value, &bytes[len..])
}

fn write_varint(out: &mut Vec<u8>, value: u64) {
    match value {
        0..=0x3f => out.push(value as u8),
        0x40..=0x3fff => out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        0x4000..=0x3fff_ffff => {
            out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes())
        }
        _ => out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

/// What a gateway does with a sealed chunked request (§6.1): the Binary HTTP request inside
/// it and the secret it exports for the response, plus `enc`.
fn gateway_opens(sealed: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (header, rest) = sealed.split_at(7);
    let (enc, mut rest) = rest.split_at(32);
    let mut info = b"message/bhttp chunked request".to_vec();
    info.push(0);
    info.extend_from_slice(header);
    let enc_key = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(enc).unwrap();
    let mut context = hpke::setup_receiver::<AesGcm128, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &receiver_key(),
        &enc_key,
        &info,
    )
    .unwrap();
    let mut plain = Vec::new();
    loop {
        let (len, tail) = read_varint(rest);
        if len == 0 {
            plain.extend(context.open(tail, b"final").unwrap());
            break;
        }
        let (chunk, tail) = tail.split_at(len as usize);
        plain.extend(context.open(chunk, b"").unwrap());
        rest = tail;
    }
    let mut secret = [0u8; 16];
    context
        .export(b"message/bhttp chunked response", &mut secret)
        .unwrap();
    (plain, secret.to_vec(), enc.to_vec())
}

/// What a gateway does to seal a response (§6.2): `response_nonce || varint(len) ||
/// Seal(chunk) ... || varint(0) || Seal(last chunk, aad "final")`, one sealed chunk per item of
/// `chunks`, the chunk nonce being the derived nonce XOR the chunk counter.
fn gateway_seals(chunks: &[&[u8]], enc: &[u8], secret: &[u8], nonce: [u8; 16]) -> Vec<u8> {
    let mut salt = enc.to_vec();
    salt.extend_from_slice(&nonce);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), secret);
    let mut key = [0u8; 16];
    let mut base_nonce = [0u8; 12];
    hkdf.expand(b"key", &mut key).unwrap();
    hkdf.expand(b"nonce", &mut base_nonce).unwrap();
    let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
    let mut out = nonce.to_vec();
    for (counter, chunk) in chunks.iter().enumerate() {
        let last = counter + 1 == chunks.len();
        let mut chunk_nonce = base_nonce;
        for (i, b) in (counter as u64).to_be_bytes().iter().enumerate() {
            chunk_nonce[4 + i] ^= *b;
        }
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&chunk_nonce),
                Payload {
                    msg: chunk,
                    aad: if last { b"final" } else { b"" },
                },
            )
            .unwrap();
        write_varint(&mut out, if last { 0 } else { ct.len() as u64 });
        out.extend_from_slice(&ct);
    }
    out
}

/// An indeterminate-length Binary HTTP response (RFC 9292 §3.2): the inner message of a
/// chunked response. `fields` are raw bytes so that non-UTF-8 header text can be written.
fn indeterminate(
    status: u16,
    headers: &[(&[u8], &[u8])],
    body: &[u8],
    trailers: &[(&[u8], &[u8])],
) -> Vec<u8> {
    let mut out = vec![3u8];
    write_varint(&mut out, u64::from(status));
    for (name, value) in headers {
        write_varint(&mut out, name.len() as u64);
        out.extend_from_slice(name);
        write_varint(&mut out, value.len() as u64);
        out.extend_from_slice(value);
    }
    out.push(0);
    if !body.is_empty() {
        write_varint(&mut out, body.len() as u64);
        out.extend_from_slice(body);
    }
    out.push(0);
    for (name, value) in trailers {
        write_varint(&mut out, name.len() as u64);
        out.extend_from_slice(name);
        write_varint(&mut out, value.len() as u64);
        out.extend_from_slice(value);
    }
    out.push(0);
    out
}

/// A 200 with no fields and no body: the smallest inner response.
fn empty_200() -> Vec<u8> {
    indeterminate(200, &[], &[], &[])
}

fn key_config() -> KeyConfig {
    let mut config = vec![1u8, 0x00, 0x20];
    config.extend_from_slice(&receiver_key_public());
    config.extend_from_slice(&[0, 4, 0, 1, 0, 1]);
    let mut document = (config.len() as u16).to_be_bytes().to_vec();
    document.extend(config);
    KeyConfig::select(&document).unwrap()
}

fn receiver_key_public() -> Vec<u8> {
    let sk = receiver_key();
    <X25519HkdfSha256 as Kem>::sk_to_pk(&sk).to_bytes().to_vec()
}

/// The request as a client seals it: encoded under the profile's options, sealed as one
/// chunked request.
fn seal(profile: &ClientProfile, request: &BhttpRequest) -> (Vec<u8>, ChunkedResponseOpener) {
    let plain = encode_bhttp_request(request, &profile.encode).unwrap();
    encapsulate_chunked_request(&key_config(), &plain).unwrap()
}

/// The whole answer through the incremental decoder, one byte at a time.
fn decode_bytewise(
    opener: &ChunkedResponseOpener,
    answer: &[u8],
) -> Result<Vec<ResponseEvent>, Error> {
    let mut decoder = ChunkedResponseDecoder::from_opener(opener);
    let mut events = Vec::new();
    for byte in answer {
        events.extend(decoder.push(std::slice::from_ref(byte))?);
    }
    events.extend(decoder.finish()?);
    Ok(events)
}

#[test]
fn a_sealed_request_opens_at_an_independent_receiver_and_its_answer_decapsulates() {
    for profile in [
        ClientProfile::LIBRARY,
        ClientProfile::ANDROID,
        ClientProfile::IOS,
        ClientProfile::SLIPSTREAM,
    ] {
        let request = BhttpRequest::new(
            "POST",
            "lwd.example",
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLightdInfo",
        )
        .header("Content-Type", "application/grpc")
        .header("te", "trailers")
        .body(vec![0, 0, 0, 0, 0]);
        let (sealed, opener) = seal(&profile, &request);
        assert_eq!(&sealed[..7], [1, 0, 0x20, 0, 1, 0, 1]);

        let (plain, secret, enc) = gateway_opens(&sealed);
        let lowercase = profile.encode.lowercase_header_names;
        let mut headers = if lowercase {
            vec![
                (b"content-type".to_vec(), b"application/grpc".to_vec()),
                (b"te".to_vec(), b"trailers".to_vec()),
            ]
        } else {
            request.headers.clone()
        };
        if profile.encode.freshness {
            // Appended last, the value is the encoder's timestamp: read it back.
            let name = b"ohttp-freshness";
            let at = plain
                .windows(name.len())
                .position(|w| w == name)
                .expect("freshness field written")
                + name.len();
            let len = plain[at] as usize;
            let value = plain[at + 1..at + 1 + len].to_vec();
            let ts: i64 = std::str::from_utf8(&value).unwrap().parse().unwrap();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            assert!((ts - now).abs() <= 5, "timestamp {ts} vs now {now}");
            headers.push((name.to_vec(), value));
        }
        let expected = BhttpRequest {
            headers,
            ..request.clone()
        };
        assert_eq!(
            plain,
            encode_bhttp_request(&expected, &EncodeOptions::PRESERVE).unwrap()
        );

        // The gateway answers 200 with a gRPC trailer, in two chunks cut mid-message.
        let message = indeterminate(
            200,
            &[(&b"content-type"[..], &b"application/grpc"[..])],
            &[1, 2, 3],
            &[(&b"grpc-status"[..], &b"0"[..])],
        );
        let cut = message.len() / 2;
        let answer = gateway_seals(&[&message[..cut], &message[cut..]], &enc, &secret, [9; 16]);
        let events = decode_bytewise(&opener, &answer).unwrap();
        assert!(events.contains(&ResponseEvent::End));
        assert!(events.contains(&ResponseEvent::Trailers(vec![(
            "grpc-status".to_string(),
            "0".to_string()
        )])));
        let opened = zodl_ohttp_client::collect_response(events).unwrap();
        assert_eq!(opened.status, 200);
        assert_eq!(opened.header("content-type"), Some("application/grpc"));
        assert_eq!(opened.header("GRPC-STATUS"), Some("0"));
        assert_eq!(opened.body, [1, 2, 3]);
        // The one-call opener agrees with the incremental decoder.
        let whole = opener.open_response(&answer).unwrap();
        assert_eq!(whole, opened);
    }
}

#[test]
fn a_tampered_or_oversized_or_foreign_answer_is_refused() {
    let request = BhttpRequest::new("GET", "a.example", "/");
    let limits = Limits {
        max_sealed_response_bytes: Some(80),
        ..Limits::UNLIMITED
    };
    let (sealed, opener) = seal(&ClientProfile::LIBRARY, &request);
    let (_, secret, enc) = gateway_opens(&sealed);
    let answer = gateway_seals(&[&empty_200()], &enc, &secret, [1; 16]);
    assert!(answer.len() <= 80);

    check_size(answer.len(), limits.max_sealed_response_bytes).unwrap();
    assert_eq!(opener.open_response(&answer).unwrap().status, 200);

    // A flipped bit anywhere fails authentication.
    let mut tampered = answer.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(opener.open_response(&tampered).is_err());

    // Over the cap: refused by the size check, before anything is decrypted, whether the body
    // is known whole or read in chunks.
    let mut long = answer.clone();
    long.resize(81, 0);
    assert!(matches!(
        check_size(long.len(), limits.max_sealed_response_bytes),
        Err(Error::TooLarge { max: 80 })
    ));
    let mut guard = limits.response_guard();
    guard.push(40).unwrap();
    guard.push(40).unwrap();
    assert!(matches!(guard.push(1), Err(Error::TooLarge { max: 80 })));

    // An answer to another request does not open.
    let (_, other) = seal(&ClientProfile::LIBRARY, &request);
    assert!(other.open_response(&answer).is_err());

    // The request-size limit, checked on the sealed body before it is posted.
    let tiny = Limits {
        max_sealed_request_bytes: Some(10),
        ..Limits::UNLIMITED
    };
    assert!(matches!(
        check_size(sealed.len(), tiny.max_sealed_request_bytes),
        Err(Error::TooLarge { max: 10 })
    ));
}

/// Each request is sealed afresh: the ephemeral key, hence the whole ciphertext, differs, so a
/// retry never repeats a nonce to the gateway.
#[test]
fn every_attempt_is_sealed_afresh() {
    let request = BhttpRequest::new("GET", "a.example", "/");
    let bodies: Vec<Vec<u8>> = (0..8)
        .map(|_| seal(&ClientProfile::LIBRARY, &request).0)
        .collect();
    for (i, a) in bodies.iter().enumerate() {
        for b in &bodies[i + 1..] {
            assert_ne!(a[7..39], b[7..39], "the same ephemeral key twice");
            assert_ne!(a, b);
        }
    }
}

// ---- Key-configuration selection --------------------------------------------------------

fn entry(key_id: u8, kem: u16, key_len: usize, suites: &[(u16, u16)], trailing: &[u8]) -> Vec<u8> {
    let mut config = vec![key_id];
    config.extend_from_slice(&kem.to_be_bytes());
    config.extend(std::iter::repeat_n(key_id, key_len));
    config.extend_from_slice(&((suites.len() * 4) as u16).to_be_bytes());
    for (kdf, aead) in suites {
        config.extend_from_slice(&kdf.to_be_bytes());
        config.extend_from_slice(&aead.to_be_bytes());
    }
    config.extend_from_slice(trailing);
    let mut prefixed = (config.len() as u16).to_be_bytes().to_vec();
    prefixed.extend(config);
    prefixed
}

#[test]
fn a_non_x25519_configuration_is_skipped_by_every_profile() {
    // A P-256 configuration (65-byte key) ahead of the X25519 one.
    let mut document = entry(1, 0x0010, 65, &[(1, 1)], &[]);
    document.extend(entry(2, 0x0020, 32, &[(1, 1)], &[]));
    for selection in [
        KeySelection::LIBRARY,
        KeySelection::ANDROID,
        KeySelection::IOS,
        KeySelection::SLIPSTREAM,
    ] {
        assert_eq!(
            KeyConfig::select_with(&document, &selection)
                .unwrap()
                .key_id(),
            2
        );
    }
    // Refusing stays available to a caller that asks for it.
    let strict = KeySelection {
        unsupported_kem: UnsupportedKem::Reject,
        ..KeySelection::ANDROID
    };
    assert!(matches!(
        KeyConfig::select_with(&document, &strict),
        Err(Error::KeyConfig(_))
    ));
}

#[test]
fn bytes_after_the_suite_list_are_tolerated_or_refused_as_the_profile_says() {
    let document = entry(5, 0x0020, 32, &[(1, 1)], &[0xff, 0xff, 0xff]);
    assert_eq!(
        KeyConfig::select_with(&document, &KeySelection::ANDROID)
            .unwrap()
            .key_id(),
        5
    );
    assert_eq!(
        KeyConfig::select_with(&document, &KeySelection::IOS)
            .unwrap()
            .key_id(),
        5
    );
    // The library's exact-length reading fails the entry.
    assert!(matches!(
        KeyConfig::select(&document),
        Err(Error::KeyConfig(_))
    ));
}

// ---- Signed envelopes --------------------------------------------------------------------

#[test]
fn the_pinned_keys_are_the_configured_ones() {
    use sha2::Digest;
    use zodl_ohttp_client::{OhttpConfig, OhttpConfigParams, OhttpNetworks};
    let key_hex = |seed: u8| {
        hex_of(
            ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .as_bytes(),
        )
    };
    let config = |host: &str, seed: u8| {
        OhttpConfig::new(OhttpConfigParams {
            gateway_host: host,
            relay_url: &format!("https://{host}/relay"),
            keys_dns_name: &format!("keys.{host}"),
            signing_pubkey: &key_hex(seed).to_ascii_uppercase(),
        })
        .unwrap()
    };
    let networks = OhttpNetworks::new(
        Some(config("ohttp-gateway.example", 4)),
        Some(config("ohttp-gateway-testnet.example", 5)),
    )
    .unwrap();
    for (network, seed) in [(Network::Mainnet, 4), (Network::Testnet, 5)] {
        let key = networks.get(network).unwrap().signing_pubkey();
        assert_eq!(hex_of(key.as_bytes()), key_hex(seed));
        assert_eq!(hex_of(&Sha256::digest(key.as_bytes())[..4]).len(), 8);
    }
    assert_eq!(Network::from_name("mainnet"), Some(Network::Mainnet));
    assert_eq!(Network::from_name("regtest"), None);
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A request-shaped answer is a typed error, never a successful response.
#[test]
fn a_request_shaped_answer_is_an_error_not_a_200() {
    // An answer that is a request must not read as status 200.
    let request = BhttpRequest::new("GET", "a.example", "/");
    let (sealed, opener) = seal(&ClientProfile::SLIPSTREAM, &request);
    let (plain, secret, enc) = gateway_opens(&sealed);
    // The gateway (here: a hostile one) answers with the request itself.
    let answer = gateway_seals(&[&plain], &enc, &secret, [2; 16]);
    assert!(matches!(
        opener.open_response(&answer),
        Err(Error::NotAResponse)
    ));
    assert!(matches!(
        decode_bytewise(&opener, &answer),
        Err(Error::NotAResponse)
    ));
}

#[test]
fn non_utf8_text_fields_are_bytes_not_a_panic() {
    // Non-ASCII method, authority, path, header name and value encode (the wrapper decides
    // what it sends); a response with Latin-1 and invalid UTF-8 in its fields decodes, and
    // the text view is total (lossy).
    let request = BhttpRequest::new("GÉT", "ü.example", "/päth")
        .header("x-ñ", b"\xff\xfe".to_vec())
        .body(vec![0xff; 3]);
    let (sealed, opener) = seal(&ClientProfile::IOS, &request);
    let (plain, secret, enc) = gateway_opens(&sealed);
    let path = "/päth".as_bytes();
    assert!(plain.windows(path.len()).any(|w| w == path));

    let message = indeterminate(200, &[(&b"x-\xe9"[..], &b"\xff\xfe\x80"[..])], &[], &[]);
    let answer = gateway_seals(&[&message], &enc, &secret, [8; 16]);
    let opened = opener.open_response(&answer).unwrap();
    assert_eq!(opened.status, 200);
    assert_eq!(opened.headers.len(), 1);
    assert_eq!(opened.headers[0].0, "x-\u{fffd}");
    assert_eq!(opened.headers[0].1, "\u{fffd}\u{fffd}\u{fffd}");
}

/// The step after the post: the outer answer is classified under the profile, and only a
/// sealed one is opened, under the profile's size cap.
#[test]
fn the_outer_answer_is_classified_then_a_sealed_one_opened() {
    let request = BhttpRequest::new("GET", "a.example", "/");
    let profile = ClientProfile::ANDROID;
    let (sealed, opener) = seal(&profile, &request);
    let (_, secret, enc) = gateway_opens(&sealed);
    let answer = gateway_seals(&[&empty_200()], &enc, &secret, [5; 16]);
    let outer = |status, body: &'static [u8]| OuterResponse {
        status,
        content_type: Some(CONTENT_TYPE_CHUNKED_RES),
        body,
    };
    // A sealed answer: classified, size-checked, opened.
    let sealed_answer = OuterResponse {
        status: 200,
        content_type: None,
        body: &answer,
    };
    assert_eq!(
        classify_outer_response(&profile.outer, &sealed_answer, 0),
        OuterOutcome::Sealed
    );
    check_size(answer.len(), profile.limits.max_sealed_response_bytes).unwrap();
    assert_eq!(opener.open_response(&answer).unwrap().status, 200);
    // A refusal and a key rotation (once).
    assert_eq!(
        classify_outer_response(&profile.outer, &outer(503, b"down"), 0),
        OuterOutcome::Refused {
            status: 503,
            detail: "down".into()
        }
    );
    assert_eq!(
        classify_outer_response(&profile.outer, &outer(400, b""), 0),
        OuterOutcome::RefetchKeyConfig
    );
    assert!(matches!(
        classify_outer_response(&profile.outer, &outer(400, b""), 1),
        OuterOutcome::Refused { status: 400, .. }
    ));
    // Every preset accepts a 200 whatever its content-type (the networked `Client` checks it).
    let wrong = OuterResponse {
        status: 200,
        content_type: Some("text/html"),
        body: b"<html>",
    };
    assert_eq!(
        classify_outer_response(&ClientProfile::LIBRARY.outer, &wrong, 0),
        OuterOutcome::Sealed
    );
    // A 200 that does not open is an error.
    let (_, fresh) = seal(&profile, &request);
    assert!(fresh.open_response(b"not sealed at all, no").is_err());
    // A 200 over the cap is refused before anything is decrypted.
    let capped = ClientProfile {
        limits: Limits {
            max_sealed_response_bytes: Some(8),
            ..Limits::UNLIMITED
        },
        ..profile
    };
    assert!(matches!(
        check_size(9, capped.limits.max_sealed_response_bytes),
        Err(Error::TooLarge { max: 8 })
    ));
}

/// Sealed requests are capped at the gateway's 10 MiB, refused before anything is sent.
#[test]
fn the_sealed_request_cap_is_exact_for_every_preset() {
    const CAP: usize = 10_485_760;
    assert_eq!(
        zodl_ohttp_client::GATEWAY_MAX_ENCAPSULATED_REQUEST_BYTES,
        CAP
    );
    let request =
        |len: usize| BhttpRequest::new("POST", "a.example", "/upload").body(vec![0u8; len]);
    // The sealed size is 39 (hdr || enc) + varint + the Binary HTTP message + 16 (tag) + the
    // final chunk (1 + 16); find the body length that makes it exactly CAP.
    // Every preset adds the same `ohttp-freshness` field (a 10-digit timestamp), so measure with
    // a preset's own options.
    let profile = ClientProfile::IOS;
    let sealed_len = |len: usize| seal(&profile, &request(len)).0.len();
    let probe = CAP - 1000;
    let exact = probe + (CAP - sealed_len(probe));
    for profile in [
        ClientProfile::LIBRARY,
        ClientProfile::ANDROID,
        ClientProfile::IOS,
        ClientProfile::SLIPSTREAM,
        ClientProfile::SLIPSTREAM_HTTP,
    ] {
        assert_eq!(profile.limits.max_sealed_request_bytes, Some(CAP));
    }
    let at_cap = sealed_len(exact);
    assert_eq!(at_cap, CAP);
    check_size(at_cap, profile.limits.max_sealed_request_bytes).unwrap();
    // One byte more is refused, for every preset, as a typed error.
    let over = sealed_len(exact + 1);
    assert_eq!(over, CAP + 1);
    for profile in [
        ClientProfile::LIBRARY,
        ClientProfile::ANDROID,
        ClientProfile::IOS,
        ClientProfile::SLIPSTREAM,
    ] {
        assert!(matches!(
            check_size(over, profile.limits.max_sealed_request_bytes),
            Err(Error::TooLarge { max: CAP })
        ));
    }
}

/// ZIP, "Outer response contract": an outer 400 or 422 refetches the key configuration and
/// retries exactly once, whatever the body says, in every preset; the second one is permanent.
/// Every retry re-seals (a new ciphertext), and nothing else is retried.
#[test]
fn every_preset_refetches_once_on_an_outer_400_or_422_whatever_the_body() {
    let request = BhttpRequest::new("GET", "a.example", "/");
    let bodies: [&'static [u8]; 5] = [
        b"",
        b"nope",
        b"the HPKE key is unknown",
        br#"{"type":"https://iana.org/assignments/http-problem-types#ohttp-key"}"#,
        &[0xff, 0xfe, 0x00],
    ];
    for profile in [
        ClientProfile::ANDROID,
        ClientProfile::IOS,
        ClientProfile::SLIPSTREAM,
        ClientProfile::SLIPSTREAM_HTTP,
        ClientProfile::LIBRARY,
    ] {
        let first = seal(&profile, &request).0;
        let second = seal(&profile, &request).0;
        assert_ne!(first, second, "a retry is sealed afresh");
        for status in [400u16, 422] {
            for body in bodies {
                let outer = OuterResponse {
                    status,
                    content_type: Some("application/problem+json"),
                    body,
                };
                assert_eq!(
                    classify_outer_response(&profile.outer, &outer, 0),
                    OuterOutcome::RefetchKeyConfig,
                    "{status} {body:?}"
                );
                assert!(
                    matches!(
                        classify_outer_response(&profile.outer, &outer, 1),
                        OuterOutcome::Refused { status: s, .. } if s == status
                    ),
                    "{status} {body:?} twice"
                );
            }
        }
        // 409 and 413 are never retried, nor is any status but 400 and 422.
        for status in [401u16, 403, 409, 413, 426, 500, 502, 503] {
            let outer = OuterResponse {
                status,
                content_type: None,
                body: b"ohttp-key",
            };
            assert!(
                matches!(
                    classify_outer_response(&profile.outer, &outer, 0),
                    OuterOutcome::Refused { status: s, .. } if s == status
                ),
                "{status}"
            );
        }
    }
}

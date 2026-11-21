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

//! The wallet's signature of a session request: a Zcash signed message (the convention of
//! `signmessage`/`verifymessage`) by the key of the session's transparent P2PKH address, over
//! the address and a timestamp.
//!
//! - The message is the UTF-8 text [`message`]: `zodl-onramp-session-v1`, a line feed, the
//!   address exactly as sent, a line feed, the timestamp in decimal Unix seconds (no sign, no
//!   leading zero), with no trailing line feed.
//! - Its hash is the double SHA-256 of the compact-size length of [`MAGIC`], `MAGIC`, the
//!   compact-size length of the message and the message ([`message_hash`]).
//! - The signature is 65 bytes, base64 (standard alphabet, padded: 88 characters): a header
//!   byte `27 + recovery id` (0 to 3) for an uncompressed key, `31 + recovery id` for a
//!   compressed one, then `r` and `s` (32 bytes each, big endian).
//!
//! [`verify`] recovers the public key from the signature and the hash, encodes it as the
//! header says (33 bytes compressed, 65 uncompressed) and compares its HASH160 (RIPEMD-160 of
//! the SHA-256) with the hash of the address. It refuses an `s` in the upper half of the
//! order (a malleated copy of a valid signature): signers produce the low form.

use base64::Engine;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::core::body::{base58check, TRANSPARENT_HASH_BYTES, ZCASH_MAINNET_P2PKH};

/// The magic prefix of a Zcash signed message.
pub const MAGIC: &str = "Zcash Signed Message:\n";
/// The first line of the message: the purpose and its version.
pub const PURPOSE: &str = "zodl-onramp-session-v1";
/// The most a session request's timestamp may differ from the gateway's clock, either way.
pub const MAX_SKEW_SECS: u64 = 300;
/// The length of a signature, decoded.
pub const SIGNATURE_BYTES: usize = 65;

/// Why a signature is refused (never part of an answer: every one is `invalid_signature`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureError {
    /// Not base64 of [`SIGNATURE_BYTES`] bytes.
    Encoding,
    /// A header byte outside 27..=34.
    Header,
    /// `r` or `s` zero or not below the order.
    Scalars,
    /// `s` in the upper half of the order.
    HighS,
    /// No public key recovers, or the recovered one does not verify.
    Recovery,
    /// Not a transparent P2PKH address.
    Address,
    /// The recovered key (as the header encodes it) is not the address's.
    Mismatch,
}

/// The message signed for `address` at `timestamp`.
pub fn message(address: &str, timestamp: u64) -> String {
    format!("{PURPOSE}\n{address}\n{timestamp}")
}

/// `len` as a compact size (the length prefix of Zcash's serialisation).
fn compact_size(len: usize, out: &mut Vec<u8>) {
    match len {
        0..=0xfc => out.push(len as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(len as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(len as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&(len as u64).to_le_bytes());
        }
    }
}

/// The bytes hashed for `message`: the length-prefixed magic, then the length-prefixed message.
pub fn message_preimage(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAGIC.len() + message.len() + 10);
    compact_size(MAGIC.len(), &mut out);
    out.extend_from_slice(MAGIC.as_bytes());
    compact_size(message.len(), &mut out);
    out.extend_from_slice(message);
    out
}

/// The hash signed for `message`: the double SHA-256 of its [`message_preimage`].
pub fn message_hash(message: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(message_preimage(message))).into()
}

/// Whether `timestamp` is within [`MAX_SKEW_SECS`] of `now` (both Unix seconds).
pub fn is_fresh(timestamp: u64, now: u64) -> bool {
    timestamp.abs_diff(now) <= MAX_SKEW_SECS
}

/// The HASH160 of `bytes`: RIPEMD-160 of the SHA-256.
pub fn hash160(bytes: &[u8]) -> [u8; TRANSPARENT_HASH_BYTES] {
    Ripemd160::digest(Sha256::digest(bytes)).into()
}

/// Whether `signature` (base64) is a signature of [`message`]`(address, timestamp)` by the key
/// of `address`, a Zcash mainnet transparent P2PKH address.
pub fn verify(address: &str, timestamp: u64, signature: &str) -> Result<(), SignatureError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(signature)
        .map_err(|_| SignatureError::Encoding)?;
    let bytes: [u8; SIGNATURE_BYTES] = bytes.try_into().map_err(|_| SignatureError::Encoding)?;
    let header = bytes[0];
    if !(27..=34).contains(&header) {
        return Err(SignatureError::Header);
    }
    let compressed = header >= 31;
    let recovery = RecoveryId::from_byte((header - 27) & 3).ok_or(SignatureError::Header)?;
    let sig = Signature::from_slice(&bytes[1..]).map_err(|_| SignatureError::Scalars)?;
    // `normalize_s` gives the low form of a high `s` only.
    if sig.normalize_s().is_some() {
        return Err(SignatureError::HighS);
    }
    let payload = base58check(address).ok_or(SignatureError::Address)?;
    let hash = match payload.strip_prefix(ZCASH_MAINNET_P2PKH) {
        Some(hash) if hash.len() == TRANSPARENT_HASH_BYTES => hash,
        _ => return Err(SignatureError::Address),
    };
    let digest = message_hash(message(address, timestamp).as_bytes());
    let key = VerifyingKey::recover_from_prehash(&digest, &sig, recovery)
        .map_err(|_| SignatureError::Recovery)?;
    let encoded = key.to_encoded_point(compressed);
    if hash160(encoded.as_bytes()) == *hash {
        Ok(())
    } else {
        Err(SignatureError::Mismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use k256::elliptic_curve::scalar::IsHigh;

    /// The published test vector (a key made for it; see CONFIG.md).
    pub(crate) const VECTOR_KEY: &str =
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    pub(crate) const VECTOR_ADDRESS: &str = "t1RwUkDxFKCydymAzBtTwHtVyH9Tvf6CiiL";
    pub(crate) const VECTOR_TIMESTAMP: u64 = 1_700_000_000;
    pub(crate) const VECTOR_SIGNATURE: &str =
        "IJdQ6f64QRlbvvFp2dTb33IU8GeRNmRVE1/re+l6yGVkeTv0Lvbid7DGQ3JxOVXZZ4GpXl24i75ZzDQe1Z5jZAs=";
    const VECTOR_PUBLIC_KEY: &str =
        "0284bf7562262bbd6940085748f3be6afa52ae317155181ece31b66351ccffa4b0";
    const VECTOR_MESSAGE: &str = "7a6f646c2d6f6e72616d702d73657373696f6e2d76310a74315277556b4478464b437964796d417a42745477487456794839547666364369694c0a31373030303030303030";
    const VECTOR_PREIMAGE: &str = "165a63617368205369676e6564204d6573736167653a0a457a6f646c2d6f6e72616d702d73657373696f6e2d76310a74315277556b4478464b437964796d417a42745477487456794839547666364369694c0a31373030303030303030";
    const VECTOR_HASH: &str = "3e0f90d09a41b6cc3a720cf740dbfc68abe90013111494f05aa170cd4143c7fa";
    /// The address of the vector key's uncompressed encoding, and its signature at the same
    /// timestamp (header 28).
    const VECTOR_UNCOMPRESSED_ADDRESS: &str = "t1cJfqUTpZiKZ2r7vLUgQFhuj1yAmtcoDhE";
    const VECTOR_UNCOMPRESSED_SIGNATURE: &str =
        "HFuzIoquD5CClZMiyd9iWfEJvtBXDyfjy0Wd6TYDz7wqX6MwseZHt1iAQy5YWb0zv4+vgYAZNUqe9u36L7jPuMs=";
    /// The compressed address of the key `22..22` (another key).
    const OTHER_ADDRESS: &str = "t1RSr79xfHYE8LALif4h9Puuft9pGgydJv3";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn key(hex_key: &str) -> SigningKey {
        SigningKey::from_slice(&hex(hex_key)).unwrap()
    }

    /// The base58check P2PKH address of `key` in the encoding `compressed` says.
    fn address(key: &SigningKey, compressed: bool) -> String {
        let point = key.verifying_key().to_encoded_point(compressed);
        let mut data = [ZCASH_MAINNET_P2PKH, &hash160(point.as_bytes())].concat();
        let check = Sha256::digest(Sha256::digest(&data));
        data.extend_from_slice(&check[..4]);
        const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let mut digits: Vec<u8> = Vec::new();
        for &byte in &data {
            let mut carry = u32::from(byte);
            for d in digits.iter_mut() {
                carry += u32::from(*d) << 8;
                *d = (carry % 58) as u8;
                carry /= 58;
            }
            while carry > 0 {
                digits.push((carry % 58) as u8);
                carry /= 58;
            }
        }
        let zeros = data.iter().take_while(|&&b| b == 0).count();
        let mut out = "1".repeat(zeros);
        out.extend(
            digits
                .iter()
                .rev()
                .map(|&d| char::from(ALPHABET[usize::from(d)])),
        );
        out
    }

    /// The 65 signature bytes of `key` for `address` at `timestamp`, the header for
    /// `compressed`.
    fn sign_bytes(key: &SigningKey, address: &str, timestamp: u64, compressed: bool) -> [u8; 65] {
        let digest = message_hash(message(address, timestamp).as_bytes());
        let (sig, recovery) = key.sign_prehash_recoverable(&digest).unwrap();
        let mut out = [0u8; 65];
        out[0] = 27 + recovery.to_byte() + if compressed { 4 } else { 0 };
        out[1..].copy_from_slice(&sig.to_bytes());
        out
    }

    /// `header` with the other y parity of its recovery id, the key encoding (compressed or
    /// not) and the x-reduced bit kept: `27 + ((header - 27) ^ 1)`.
    fn other_parity(header: u8) -> u8 {
        27 + ((header - 27) ^ 1)
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn the_published_vector() {
        let k = key(VECTOR_KEY);
        assert_eq!(
            k.verifying_key().to_encoded_point(true).as_bytes(),
            hex(VECTOR_PUBLIC_KEY).as_slice()
        );
        assert_eq!(address(&k, true), VECTOR_ADDRESS);
        let text = message(VECTOR_ADDRESS, VECTOR_TIMESTAMP);
        assert_eq!(text.as_bytes(), hex(VECTOR_MESSAGE).as_slice());
        assert_eq!(
            text,
            "zodl-onramp-session-v1\nt1RwUkDxFKCydymAzBtTwHtVyH9Tvf6CiiL\n1700000000"
        );
        assert_eq!(message_preimage(text.as_bytes()), hex(VECTOR_PREIMAGE));
        assert_eq!(message_hash(text.as_bytes()).to_vec(), hex(VECTOR_HASH));
        // RFC 6979 signing is deterministic: the vector is what k256 signs, byte for byte.
        assert_eq!(
            b64(&sign_bytes(&k, VECTOR_ADDRESS, VECTOR_TIMESTAMP, true)),
            VECTOR_SIGNATURE
        );
        assert_eq!(
            verify(VECTOR_ADDRESS, VECTOR_TIMESTAMP, VECTOR_SIGNATURE),
            Ok(())
        );
        // The uncompressed encoding of the same key: its own address and header.
        assert_eq!(address(&k, false), VECTOR_UNCOMPRESSED_ADDRESS);
        assert_eq!(
            b64(&sign_bytes(
                &k,
                VECTOR_UNCOMPRESSED_ADDRESS,
                VECTOR_TIMESTAMP,
                false
            )),
            VECTOR_UNCOMPRESSED_SIGNATURE
        );
        assert_eq!(
            verify(
                VECTOR_UNCOMPRESSED_ADDRESS,
                VECTOR_TIMESTAMP,
                VECTOR_UNCOMPRESSED_SIGNATURE
            ),
            Ok(())
        );
        assert_eq!(address(&key(&"22".repeat(32)), true), OTHER_ADDRESS);
    }

    /// The independent Python reference (`scripts/coinbase-signature-vector.py`, standard
    /// library only) reproduces the same vectors. Without `python3` the test is skipped,
    /// except under `CI`, where that is a failure.
    #[test]
    fn the_python_reference_reproduces_the_vectors() {
        let script = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../scripts/coinbase-signature-vector.py"
        );
        let run = |args: &[&str]| {
            std::process::Command::new("python3")
                .arg("-I")
                .arg(script)
                .args(args)
                .output()
        };
        let output = match run(&["check"]) {
            Ok(output) => output,
            Err(e) if std::env::var_os("CI").is_none() => {
                eprintln!("python3 not run ({e}): the reference check is skipped");
                return;
            }
            Err(e) => panic!("python3 is required under CI: {e}"),
        };
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let ts = VECTOR_TIMESTAMP.to_string();
        let verify = |address: &str, signature: &str| {
            run(&["verify", address, &ts, signature])
                .unwrap()
                .status
                .success()
        };
        assert!(verify(VECTOR_ADDRESS, VECTOR_SIGNATURE));
        assert!(verify(
            VECTOR_UNCOMPRESSED_ADDRESS,
            VECTOR_UNCOMPRESSED_SIGNATURE
        ));
        assert!(!verify(OTHER_ADDRESS, VECTOR_SIGNATURE));
        // A signature of another key, made here, agrees with the reference both ways.
        let other = key(&"22".repeat(32));
        let own = b64(&sign_bytes(&other, OTHER_ADDRESS, VECTOR_TIMESTAMP, true));
        assert!(verify(OTHER_ADDRESS, &own));
        assert!(!verify(VECTOR_ADDRESS, &own));
    }

    #[test]
    fn the_signature_binds_the_address_and_the_timestamp() {
        // Another address, another timestamp: another message, another key recovered.
        assert_eq!(
            verify(OTHER_ADDRESS, VECTOR_TIMESTAMP, VECTOR_SIGNATURE),
            Err(SignatureError::Mismatch)
        );
        for timestamp in [
            VECTOR_TIMESTAMP - 1,
            VECTOR_TIMESTAMP + 1,
            0,
            17_000_000_000,
        ] {
            assert_eq!(
                verify(VECTOR_ADDRESS, timestamp, VECTOR_SIGNATURE),
                Err(SignatureError::Mismatch),
                "{timestamp}"
            );
        }
        // A valid signature by another key, for this address.
        let other = key(&"22".repeat(32));
        let forged = b64(&sign_bytes(&other, VECTOR_ADDRESS, VECTOR_TIMESTAMP, true));
        assert_eq!(
            verify(VECTOR_ADDRESS, VECTOR_TIMESTAMP, &forged),
            Err(SignatureError::Mismatch)
        );
        // The other key's own signature for its own address verifies.
        let own = b64(&sign_bytes(&other, OTHER_ADDRESS, VECTOR_TIMESTAMP, true));
        assert_eq!(verify(OTHER_ADDRESS, VECTOR_TIMESTAMP, &own), Ok(()));
        // Any changed byte of r or s.
        let mut bytes = sign_bytes(&key(VECTOR_KEY), VECTOR_ADDRESS, VECTOR_TIMESTAMP, true);
        for i in [1, 32, 33, 64] {
            bytes[i] ^= 1;
            assert!(verify(VECTOR_ADDRESS, VECTOR_TIMESTAMP, &b64(&bytes)).is_err());
            bytes[i] ^= 1;
        }
        // The other y parity recovers another key (the same encoding, so not the address's).
        assert_eq!(other_parity(32), 31);
        bytes[0] = other_parity(bytes[0]);
        assert_eq!(
            verify(VECTOR_ADDRESS, VECTOR_TIMESTAMP, &b64(&bytes)),
            Err(SignatureError::Mismatch)
        );
    }

    #[test]
    fn the_header_says_which_encoding_the_address_hashes() {
        let k = key(VECTOR_KEY);
        let compressed = sign_bytes(&k, VECTOR_ADDRESS, VECTOR_TIMESTAMP, true);
        // The compressed key's address with an uncompressed header: the same key recovers,
        // but its uncompressed encoding hashes to another address.
        let mut flipped = compressed;
        flipped[0] -= 4;
        assert_eq!(
            verify(VECTOR_ADDRESS, VECTOR_TIMESTAMP, &b64(&flipped)),
            Err(SignatureError::Mismatch)
        );
        // And the reverse: the uncompressed key's address with a compressed header.
        let mut reverse = sign_bytes(&k, VECTOR_UNCOMPRESSED_ADDRESS, VECTOR_TIMESTAMP, false);
        assert_eq!(
            verify(
                VECTOR_UNCOMPRESSED_ADDRESS,
                VECTOR_TIMESTAMP,
                &b64(&reverse)
            ),
            Ok(())
        );
        reverse[0] += 4;
        assert_eq!(
            verify(
                VECTOR_UNCOMPRESSED_ADDRESS,
                VECTOR_TIMESTAMP,
                &b64(&reverse)
            ),
            Err(SignatureError::Mismatch)
        );
    }

    #[test]
    fn a_high_s_is_malleable_and_refused() {
        let bytes = sign_bytes(&key(VECTOR_KEY), VECTOR_ADDRESS, VECTOR_TIMESTAMP, true);
        let sig = Signature::from_slice(&bytes[1..]).unwrap();
        assert!(!bool::from(sig.s().is_high()));
        // (r, n - s) with the other y parity is the same signature, malleated: its low form is
        // exactly the original, whose own header recovers the vector key.
        let s: k256::Scalar = *sig.s().as_ref();
        let mut malleated = bytes;
        malleated[0] = other_parity(bytes[0]);
        malleated[33..].copy_from_slice(&(-s).to_bytes());
        let high = Signature::from_slice(&malleated[1..]).unwrap();
        assert!(bool::from(high.s().is_high()));
        assert_eq!(high.normalize_s(), Some(sig));
        let digest = message_hash(message(VECTOR_ADDRESS, VECTOR_TIMESTAMP).as_bytes());
        let recovered = VerifyingKey::recover_from_prehash(
            &digest,
            &sig,
            RecoveryId::from_byte((bytes[0] - 27) & 3).unwrap(),
        )
        .unwrap();
        assert_eq!(&recovered, key(VECTOR_KEY).verifying_key());
        // The explicit low-S check is defence in depth: whatever the curve library's own
        // verification does with a high s, the answer is this stable error, before recovery.
        assert_eq!(
            verify(VECTOR_ADDRESS, VECTOR_TIMESTAMP, &b64(&malleated)),
            Err(SignatureError::HighS)
        );
    }

    #[test]
    fn malformed_signatures() {
        let good = sign_bytes(&key(VECTOR_KEY), VECTOR_ADDRESS, VECTOR_TIMESTAMP, true);
        let check = |s: &str| verify(VECTOR_ADDRESS, VECTOR_TIMESTAMP, s);
        // Not base64, or not padded, or of another length.
        let unpadded = VECTOR_SIGNATURE.trim_end_matches('=');
        for bad in [
            "",
            "!",
            unpadded,
            &VECTOR_SIGNATURE[1..],
            &format!("{VECTOR_SIGNATURE}AAAA"),
            &format!("A{}", &VECTOR_SIGNATURE[1..VECTOR_SIGNATURE.len() - 1]),
            &b64(&good[..64]),
            &b64(&[good.as_slice(), &[0]].concat()),
            // URL-safe alphabet.
            &VECTOR_SIGNATURE.replace('+', "-").replace('/', "_"),
        ] {
            assert_eq!(check(bad), Err(SignatureError::Encoding), "{bad}");
        }
        // The vector with recovery ids 2 and 3 (x reduced; either encoding): its r + n is no
        // field element, so no key recovers. Refused, no panic.
        for header in [29u8, 30, 33, 34] {
            let mut bytes = good;
            bytes[0] = header;
            assert_eq!(
                check(&b64(&bytes)),
                Err(SignatureError::Recovery),
                "{header}"
            );
        }
        // Header bytes outside 27..=34.
        for header in [0u8, 26, 35, 36, 0xff] {
            let mut bytes = good;
            bytes[0] = header;
            assert_eq!(check(&b64(&bytes)), Err(SignatureError::Header), "{header}");
        }
        // r or s zero, or not below the order.
        let order = hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        for (at, value) in [
            (1, [0u8; 32].to_vec()),
            (33, [0u8; 32].to_vec()),
            (1, order.clone()),
            (33, order),
            (1, [0xff; 32].to_vec()),
        ] {
            let mut bytes = good;
            bytes[at..at + 32].copy_from_slice(&value);
            assert_eq!(check(&b64(&bytes)), Err(SignatureError::Scalars));
        }
        // A P2SH or a testnet address, or not an address.
        for address in [
            "t3JZcvsuaXE6ygokL4XUiZSTrQBUoPYFnXJ",
            "tm9iMLAuYMzJ6jtFLcA7rzUmfreGuKvr7Ma",
            "t1",
        ] {
            assert_eq!(
                verify(address, VECTOR_TIMESTAMP, VECTOR_SIGNATURE),
                Err(SignatureError::Address)
            );
        }
    }

    #[test]
    fn the_time_window() {
        let now = 1_700_000_000;
        for (timestamp, fresh) in [
            (now, true),
            (now - 300, true),
            (now + 300, true),
            (now - 301, false),
            (now + 301, false),
            (0, false),
            (u64::MAX, false),
        ] {
            assert_eq!(is_fresh(timestamp, now), fresh, "{timestamp}");
        }
        assert!(is_fresh(0, 300) && !is_fresh(0, 301));
    }

    #[test]
    fn compact_sizes() {
        let size = |len| {
            let mut out = Vec::new();
            compact_size(len, &mut out);
            out
        };
        assert_eq!(size(0), [0]);
        assert_eq!(size(0xfc), [0xfc]);
        assert_eq!(size(0xfd), [0xfd, 0xfd, 0]);
        assert_eq!(size(0xffff), [0xfd, 0xff, 0xff]);
        assert_eq!(size(0x1_0000), [0xfe, 0, 0, 1, 0]);
        // The magic's length is 22.
        assert_eq!(message_preimage(b"")[..2], [22, b'Z']);
    }
}

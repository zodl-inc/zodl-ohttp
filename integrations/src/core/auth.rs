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

//! Credentials a provider adds to its upstream requests.
//!
//! - [`Header`]: one header, its value a template in which `{secret}` stands for a secret
//!   (`X-Api-Key: {secret}`, `Authorization: Bearer {secret}`); without a secret the value is
//!   taken as it is (a fixed `BACKEND_HEADERS` entry).
//! - [`PlaceholderSwap`]: the client sends an agreed placeholder in `Authorization` (HTTP Basic
//!   with an empty user name and the placeholder as password); the gateway puts the real secret
//!   in its place and passes any other `Authorization` through untouched.
//! - [`JwtEdDsa`]: a JSON Web Token per upstream request, signed with an Ed25519 key (the
//!   Coinbase Developer Platform's API keys), sent as `Authorization: Bearer <jwt>`.

use base64::Engine;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

/// A credential of a provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Signer<'a> {
    Header(Header<'a>),
    PlaceholderSwap(PlaceholderSwap<'a>),
    JwtEdDsa(&'a JwtEdDsa),
}

/// What a credential may look at: the inner request's headers and the upstream request it is
/// for (a signed credential covers its method, host and path), the time and a source of
/// randomness (the crate has neither of its own).
#[derive(Clone, Copy)]
pub struct SignInput<'a> {
    /// The inner request headers, in order.
    pub headers: &'a [(String, String)],
    /// The upstream request: its method, its host (`host[:port]`, as in the upstream URL) and
    /// its path.
    pub method: &'a str,
    pub host: &'a str,
    pub path: &'a str,
    /// Seconds since the Unix epoch.
    pub now: u64,
    pub nonces: &'a dyn NonceSource,
}

impl Signer<'_> {
    /// The headers this credential adds to the upstream request `input` describes.
    pub fn headers(&self, input: &SignInput<'_>) -> Result<Vec<(String, String)>, SignError> {
        match self {
            Signer::Header(header) => Ok(vec![header.header()]),
            Signer::PlaceholderSwap(swap) => {
                let client = input
                    .headers
                    .iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case("authorization"))
                    .map(|(_, v)| v.as_str());
                Ok(swap
                    .authorization(client)
                    .map(|v| ("authorization".to_string(), v))
                    .into_iter()
                    .collect())
            }
            Signer::JwtEdDsa(jwt) => {
                let mut nonce = [0u8; NONCE_BYTES];
                input.nonces.fill(&mut nonce);
                let token = jwt.token(input.method, input.host, input.path, input.now, &nonce)?;
                Ok(vec![(
                    "authorization".to_string(),
                    format!("Bearer {token}"),
                )])
            }
        }
    }
}

/// One header: `name` and a `value` template; with a `secret`, every `{secret}` in the template
/// is replaced by it, without one the template is the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header<'a> {
    pub name: &'a str,
    pub value: &'a str,
    pub secret: Option<&'a str>,
}

impl<'a> Header<'a> {
    /// A fixed header (no secret).
    pub fn literal(name: &'a str, value: &'a str) -> Self {
        Self {
            name,
            value,
            secret: None,
        }
    }

    /// The header as sent: its name and value, unchanged otherwise.
    pub fn header(&self) -> (String, String) {
        let value = match self.secret {
            Some(secret) => self.value.replace("{secret}", secret),
            None => self.value.to_string(),
        };
        (self.name.to_string(), value)
    }
}

/// `Basic base64(":" + secret)`: HTTP Basic with an empty user name.
pub fn basic_authorization(secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!(":{secret}"))
    )
}

/// The swap of a placeholder credential for the real secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlaceholderSwap<'a> {
    /// What the client sends as the password of `Basic base64(":" + placeholder)`.
    pub placeholder: &'a str,
    /// The real secret; `None`: not configured, the placeholder is dropped.
    pub secret: Option<&'a str>,
}

impl PlaceholderSwap<'_> {
    /// Whether `value` is the placeholder credential: scheme `Basic` (any case), and a
    /// credential that decodes to exactly `":" + placeholder`.
    pub fn is_placeholder(&self, value: &str) -> bool {
        let Some((scheme, credential)) = value.trim().split_once(' ') else {
            return false;
        };
        scheme.eq_ignore_ascii_case("basic")
            && base64::engine::general_purpose::STANDARD
                .decode(credential.trim())
                .is_ok_and(|decoded| decoded == format!(":{}", self.placeholder).as_bytes())
    }

    /// The `Authorization` value that goes upstream for the client's `client` (the first one it
    /// sent): the real secret for the placeholder (none when no secret is configured: the
    /// placeholder is never sent), any other value untouched, none for none.
    pub fn authorization(&self, client: Option<&str>) -> Option<String> {
        match client {
            Some(v) if self.is_placeholder(v) => self.secret.map(basic_authorization),
            Some(v) => Some(v.to_string()),
            None => None,
        }
    }
}

/// The random bytes of a JWT's `nonce` (hex in the header).
pub const NONCE_BYTES: usize = 16;

/// A source of random bytes (the gateway's operating system generator; a fixed one in tests).
pub trait NonceSource: Send + Sync {
    /// Fill `out` with random bytes.
    fn fill(&self, out: &mut [u8]);
}

/// Why a credential could not be made. Never carries a key or a token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignError {
    /// The upstream request a token would cover is not one it may name (an unknown method, a
    /// host or path with a character outside visible ASCII, a space or a `"`, a path without a
    /// leading `/`).
    Request(&'static str),
}

impl SignError {
    /// The reason, as logged.
    pub fn reason(&self) -> &'static str {
        match self {
            SignError::Request(reason) => reason,
        }
    }
}

/// Why a key was refused. Never carries the key or a part of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyError {
    /// The key document is not JSON with the expected fields.
    Document(&'static str),
    /// The key id is empty, too long, or holds a character outside `A-Z a-z 0-9 - _ . / :`.
    KeyId,
    /// The private key is not base64 of a 32-byte seed or a 64-byte key pair.
    PrivateKey,
    /// A 64-byte key pair whose public half is not the public key of its seed.
    PublicKeyMismatch,
    /// The token lifetime is outside 1..=[`JwtEdDsa::MAX_TTL_SECS`].
    Ttl,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::Document(what) => write!(f, "the key is not a key document ({what})"),
            KeyError::KeyId => write!(
                f,
                "the key id is empty, too long or holds a character outside A-Z a-z 0-9 - _ . / :"
            ),
            KeyError::PrivateKey => write!(
                f,
                "the private key is not base64 of a 32-byte Ed25519 seed or a 64-byte key pair"
            ),
            KeyError::PublicKeyMismatch => write!(
                f,
                "the public half of the 64-byte key pair is not the public key of its seed"
            ),
            KeyError::Ttl => write!(
                f,
                "the token lifetime is outside 1..={} seconds",
                JwtEdDsa::MAX_TTL_SECS
            ),
        }
    }
}

impl std::error::Error for KeyError {}

/// A JWT per upstream request, signed with an Ed25519 key: the API key authentication of the
/// Coinbase Developer Platform (CDP).
///
/// The token is `base64url(header) "." base64url(claims) "." base64url(signature)`, without
/// padding, the signature an Ed25519 signature over the first two parts:
///
/// - header `{"alg":"EdDSA","kid":<key id>,"nonce":<hex of 16 random bytes>,"typ":"JWT"}`;
/// - claims `{"exp":<nbf + ttl>,"iss":"cdp","nbf":<now - leeway>,"sub":<key id>,"uri":"<METHOD> <host><path>"}`,
///   times in seconds since the Unix epoch.
///
/// Field names as in CDP's JWT authentication documentation: `kid` and `sub` are the API key
/// id, `iss` is the constant `cdp`, `uri` binds the token to one request (`POST
/// api.example/onramp/v1/token`: method, a space, host and path, no scheme and no query), and
/// a token lives 120 seconds at most (`exp`). The `nonce` makes every token distinct. Keys are
/// written in sorted order, so a token is fully determined by the key, the request, the time
/// and the nonce.
#[derive(Clone)]
pub struct JwtEdDsa {
    key_id: String,
    key: SigningKey,
    ttl_secs: u64,
    nbf_leeway_secs: u64,
}

impl PartialEq for JwtEdDsa {
    fn eq(&self, other: &Self) -> bool {
        self.key_id == other.key_id
            && self.ttl_secs == other.ttl_secs
            && self.nbf_leeway_secs == other.nbf_leeway_secs
            && self.key.verifying_key() == other.key.verifying_key()
    }
}

impl Eq for JwtEdDsa {}

impl std::fmt::Debug for JwtEdDsa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the key; the id is no secret but stays out of logs too.
        f.debug_struct("JwtEdDsa")
            .field("ttl_secs", &self.ttl_secs)
            .finish_non_exhaustive()
    }
}

/// The longest key id taken.
const MAX_KEY_ID_LEN: usize = 256;

fn is_key_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_KEY_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/' | b':'))
}

/// A path of the `uri` claim: visible ASCII without a space, `"`, `\`, `?` or `#` (the claim
/// covers the path alone, never a query or a fragment).
fn is_uri_path(s: &str) -> bool {
    s.starts_with('/')
        && s.bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && !matches!(b, b'"' | b'\\' | b'?' | b'#'))
}

/// A host of the `uri` claim: a lower-case name (`a-z 0-9 . -`) or a bracketed IPv6 literal
/// (hex digits and `:` in `[]`), then optionally `:` and a port ([`parse_port`]).
pub fn is_uri_host(host: &str) -> bool {
    let (name_ok, port) = if let Some(rest) = host.strip_prefix('[') {
        let Some((literal, after)) = rest.split_once(']') else {
            return false;
        };
        let literal_ok = !literal.is_empty()
            && literal
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b':');
        let port = match after {
            "" => None,
            _ => match after.strip_prefix(':') {
                Some(port) => Some(port),
                None => return false,
            },
        };
        (literal_ok, port)
    } else {
        let (name, port) = match host.split_once(':') {
            Some((name, port)) => (name, Some(port)),
            None => (host, None),
        };
        let name_ok = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
        (name_ok, port)
    };
    name_ok && port.is_none_or(|p| parse_port(p).is_some())
}

/// A port: decimal digits without a leading zero, 1 to 65535.
pub fn parse_port(port: &str) -> Option<u16> {
    if port.is_empty() || port.starts_with('0') || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    port.parse::<u16>().ok()
}

impl JwtEdDsa {
    /// The lifetime of a token unless configured.
    pub const DEFAULT_TTL_SECS: u64 = 120;
    /// The longest lifetime CDP accepts.
    pub const MAX_TTL_SECS: u64 = 120;
    /// The largest `nbf` leeway taken ([`Self::with_nbf_leeway`]).
    pub const MAX_NBF_LEEWAY_SECS: u64 = 30;

    /// A signer for the key `key_id` with the private key `private_key`: base64 (standard
    /// alphabet, padding optional) of a 32-byte Ed25519 seed, or of the 64-byte key pair (seed
    /// then public key) as CDP issues it, whose public half must match the seed.
    pub fn new(key_id: &str, private_key: &str, ttl_secs: u64) -> Result<Self, KeyError> {
        if !is_key_id(key_id) {
            return Err(KeyError::KeyId);
        }
        if !(1..=Self::MAX_TTL_SECS).contains(&ttl_secs) {
            return Err(KeyError::Ttl);
        }
        // Decoded into a fixed buffer, wiped when dropped on every path (the key itself is in
        // `SigningKey`, which wipes itself). More than 64 bytes does not fit: no key.
        let mut buffer = Zeroizing::new([0u8; 64]);
        let input = private_key.trim();
        let len = base64::engine::general_purpose::STANDARD
            .decode_slice(input, &mut buffer[..])
            .or_else(|_| {
                base64::engine::general_purpose::STANDARD_NO_PAD
                    .decode_slice(input, &mut buffer[..])
            })
            .map_err(|_| KeyError::PrivateKey)?;
        let bytes = &buffer[..len];
        let (seed_part, public_part) = match bytes.len() {
            32 => (bytes, None),
            64 => (&bytes[..32], Some(&bytes[32..])),
            _ => return Err(KeyError::PrivateKey),
        };
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(seed_part);
        let key = SigningKey::from_bytes(&seed);
        if public_part.is_some_and(|public| key.verifying_key().as_bytes()[..] != *public) {
            return Err(KeyError::PublicKeyMismatch);
        }
        Ok(Self {
            key_id: key_id.to_string(),
            key,
            ttl_secs,
            nbf_leeway_secs: 0,
        })
    }

    /// The signer with `nbf` set `secs` before the time of signing, for an upstream whose clock
    /// is slightly behind (at most [`Self::MAX_NBF_LEEWAY_SECS`]; default 0). The lifetime stays
    /// the configured one: `exp` = `nbf` + ttl.
    pub fn with_nbf_leeway(mut self, secs: u64) -> Self {
        self.nbf_leeway_secs = secs.min(Self::MAX_NBF_LEEWAY_SECS);
        self
    }

    /// A signer from CDP's key document, JSON `{"id": <key id>, "privateKey": <base64>}` (other
    /// fields are refused), see [`Self::new`].
    pub fn from_cdp_json(document: &str, ttl_secs: u64) -> Result<Self, KeyError> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Document {
            id: String,
            #[serde(rename = "privateKey")]
            private_key: String,
        }
        // serde_json's error could quote a part of the document: never shown.
        let doc: Document = serde_json::from_str(document)
            .map_err(|_| KeyError::Document("JSON {\"id\": ..., \"privateKey\": ...}"))?;
        let private_key = Zeroizing::new(doc.private_key);
        Self::new(&doc.id, &private_key, ttl_secs)
    }

    /// The public key, to verify a token (tests, a fingerprint).
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// The lifetime of a token.
    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    /// The token for `method host path` at `now` (seconds since the Unix epoch) with `nonce`.
    pub fn token(
        &self,
        method: &str,
        host: &str,
        path: &str,
        now: u64,
        nonce: &[u8; NONCE_BYTES],
    ) -> Result<String, SignError> {
        if !crate::core::route::METHODS.contains(&method) {
            return Err(SignError::Request(
                "method is not an upper-case HTTP method",
            ));
        }
        if !is_uri_host(host) {
            return Err(SignError::Request("host is not a lower-case host[:port]"));
        }
        if !is_uri_path(path) {
            return Err(SignError::Request("path is not a path without a query"));
        }
        let nbf = now.saturating_sub(self.nbf_leeway_secs);
        let json = |s: &str| serde_json::Value::String(s.to_string()).to_string();
        let nonce_hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let header = format!(
            "{{\"alg\":\"EdDSA\",\"kid\":{},\"nonce\":{},\"typ\":\"JWT\"}}",
            json(&self.key_id),
            json(&nonce_hex)
        );
        let claims = format!(
            "{{\"exp\":{},\"iss\":\"cdp\",\"nbf\":{nbf},\"sub\":{},\"uri\":{}}}",
            nbf.saturating_add(self.ttl_secs),
            json(&self.key_id),
            json(&format!("{method} {host}{path}"))
        );
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let signing_input = format!("{}.{}", b64(header.as_bytes()), b64(claims.as_bytes()));
        let signature = self.key.sign(signing_input.as_bytes());
        Ok(format!("{signing_input}.{}", b64(&signature.to_bytes())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    /// Bytes 0, 1, 2, ...: a fixed nonce.
    struct Counting;

    impl NonceSource for Counting {
        fn fill(&self, out: &mut [u8]) {
            for (i, b) in out.iter_mut().enumerate() {
                *b = i as u8;
            }
        }
    }

    fn input<'a>(headers: &'a [(String, String)]) -> SignInput<'a> {
        SignInput {
            headers,
            method: "POST",
            host: "api.example",
            path: "/onramp/v1/token",
            now: 1_700_000_000,
            nonces: &Counting,
        }
    }

    fn signed(signer: Signer<'_>, headers: &[(String, String)]) -> Vec<(String, String)> {
        signer.headers(&input(headers)).unwrap()
    }

    // RFC 8032 section 7.1 test 1: the seed and its public key.
    const SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const PUBLIC_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const SEED_B64: &str = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=";
    const PAIR_B64: &str =
        "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2DXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGg==";
    const KEY_ID: &str = "00000000-0000-4000-8000-000000000001";
    // Computed independently (Python `cryptography`, Ed25519 of the RFC 8032 seed) over the
    // header and claims of `JwtEdDsa::token` for KEY_ID, `POST api.example/onramp/v1/token`,
    // now 1700000000, ttl 120 and the nonce 000102..0f.
    const KAT: &str = "eyJhbGciOiJFZERTQSIsImtpZCI6IjAwMDAwMDAwLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDAwMSIsIm5vbmNlIjoiMDAwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE3MDAwMDAxMjAsImlzcyI6ImNkcCIsIm5iZiI6MTcwMDAwMDAwMCwic3ViIjoiMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAxIiwidXJpIjoiUE9TVCBhcGkuZXhhbXBsZS9vbnJhbXAvdjEvdG9rZW4ifQ.1syspj5RVK654r44IiFfahS4NQEFCeGmfvrUkNu0nHhGx-2bDfDJrH1xV25Tv7Y64n2kz1eiMENi4uCnz42fAA";

    fn b64url(part: &str) -> Vec<u8> {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(part)
            .unwrap()
    }

    #[test]
    fn jwt_known_answer() {
        let nonce: [u8; NONCE_BYTES] = std::array::from_fn(|i| i as u8);
        for key in [SEED_B64, PAIR_B64, SEED_B64.trim_end_matches('=')] {
            let jwt = JwtEdDsa::new(KEY_ID, key, 120).unwrap();
            assert_eq!(hex(jwt.verifying_key().as_bytes()), PUBLIC_HEX);
            let token = jwt
                .token(
                    "POST",
                    "api.example",
                    "/onramp/v1/token",
                    1_700_000_000,
                    &nonce,
                )
                .unwrap();
            assert_eq!(token, KAT);
        }
        // The parts as CDP reads them.
        let parts: Vec<&str> = KAT.split('.').collect();
        let header: serde_json::Value = serde_json::from_slice(&b64url(parts[0])).unwrap();
        assert_eq!(
            header,
            serde_json::json!({"alg": "EdDSA", "kid": KEY_ID, "typ": "JWT",
                "nonce": "000102030405060708090a0b0c0d0e0f"})
        );
        let claims: serde_json::Value = serde_json::from_slice(&b64url(parts[1])).unwrap();
        assert_eq!(
            claims,
            serde_json::json!({"iss": "cdp", "sub": KEY_ID, "nbf": 1_700_000_000u64,
                "exp": 1_700_000_120u64, "uri": "POST api.example/onramp/v1/token"})
        );
        // The signer of the enum: a bearer header with the counting nonce.
        let jwt = JwtEdDsa::new(KEY_ID, SEED_B64, 120).unwrap();
        assert_eq!(
            signed(
                Signer::JwtEdDsa(&jwt),
                &h(&[("Authorization", "Bearer client")])
            ),
            h(&[("authorization", &format!("Bearer {KAT}"))])
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn jwt_verifies_with_the_public_key_and_binds_the_request() {
        use ed25519_dalek::Verifier;
        let jwt = JwtEdDsa::from_cdp_json(
            &format!("{{\"id\":\"{KEY_ID}\",\"privateKey\":\"{PAIR_B64}\"}}"),
            JwtEdDsa::DEFAULT_TTL_SECS,
        )
        .unwrap();
        let mut public = [0u8; 32];
        for (i, b) in public.iter_mut().enumerate() {
            *b = u8::from_str_radix(&PUBLIC_HEX[2 * i..2 * i + 2], 16).unwrap();
        }
        let public = VerifyingKey::from_bytes(&public).unwrap();
        let nonce = [7u8; NONCE_BYTES];
        let token = jwt
            .token(
                "GET",
                "api.example:8443",
                "/onramp/v1/sell/user/abc/transactions",
                5,
                &nonce,
            )
            .unwrap();
        let (input, sig) = token.rsplit_once('.').unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&b64url(sig)).unwrap();
        public.verify(input.as_bytes(), &sig).unwrap();
        let claims: serde_json::Value =
            serde_json::from_slice(&b64url(input.split('.').nth(1).unwrap())).unwrap();
        assert_eq!(
            claims["uri"],
            "GET api.example:8443/onramp/v1/sell/user/abc/transactions"
        );
        assert_eq!(
            (claims["nbf"].as_u64(), claims["exp"].as_u64()),
            (Some(5), Some(125))
        );
        // Another nonce, another token.
        assert_ne!(
            token,
            jwt.token(
                "GET",
                "api.example:8443",
                "/onramp/v1/sell/user/abc/transactions",
                5,
                &[8u8; NONCE_BYTES]
            )
            .unwrap()
        );
        // A tampered token does not verify.
        let mut forged = input.to_string();
        forged.push('x');
        assert!(public.verify(forged.as_bytes(), &sig).is_err());
    }

    #[test]
    fn jwt_nbf_leeway() {
        let jwt = JwtEdDsa::new(KEY_ID, SEED_B64, 120)
            .unwrap()
            .with_nbf_leeway(5);
        let claims = |jwt: &JwtEdDsa, now| -> serde_json::Value {
            let token = jwt
                .token("POST", "api.example", "/a", now, &[0; NONCE_BYTES])
                .unwrap();
            serde_json::from_slice(&b64url(token.split('.').nth(1).unwrap())).unwrap()
        };
        let c = claims(&jwt, 1000);
        assert_eq!(
            (c["nbf"].as_u64(), c["exp"].as_u64()),
            (Some(995), Some(1115))
        );
        // Bounded, and never before the epoch.
        let jwt = jwt.with_nbf_leeway(3600);
        assert_eq!(claims(&jwt, 100)["nbf"].as_u64(), Some(70));
        assert_eq!(claims(&jwt, 10)["nbf"].as_u64(), Some(0));
    }

    #[test]
    fn jwt_refuses_bad_keys_and_requests() {
        assert_eq!(JwtEdDsa::new("", SEED_B64, 120), Err(KeyError::KeyId));
        assert_eq!(JwtEdDsa::new("a b", SEED_B64, 120), Err(KeyError::KeyId));
        assert_eq!(JwtEdDsa::new("a\"b", SEED_B64, 120), Err(KeyError::KeyId));
        assert_eq!(
            JwtEdDsa::new(&"a".repeat(257), SEED_B64, 120),
            Err(KeyError::KeyId)
        );
        assert_eq!(JwtEdDsa::new(KEY_ID, SEED_B64, 0), Err(KeyError::Ttl));
        assert_eq!(JwtEdDsa::new(KEY_ID, SEED_B64, 121), Err(KeyError::Ttl));
        let short = &SEED_B64[4..];
        for bad in ["", "!!!!", "AAAA", short, "-----BEGIN EC PRIVATE KEY-----"] {
            assert_eq!(
                JwtEdDsa::new(KEY_ID, bad, 120),
                Err(KeyError::PrivateKey),
                "{bad}"
            );
        }
        // A key pair whose public half is another key.
        let bad_pair =
            "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2DXWpgBgrEKt9RL/tPJZAc6DuFy89qmIyWvAhpo9wdRGg==";
        assert_eq!(
            JwtEdDsa::new(KEY_ID, bad_pair, 120),
            Err(KeyError::PublicKeyMismatch)
        );
        let docs = [
            String::new(),
            "{}".to_string(),
            "[]".to_string(),
            format!("{{\"id\":\"{KEY_ID}\"}}"),
            format!("{{\"id\":\"{KEY_ID}\",\"privateKey\":\"{SEED_B64}\",\"x\":1}}"),
            format!("{{\"name\":\"{KEY_ID}\",\"privateKey\":\"{SEED_B64}\"}}"),
        ];
        for doc in &docs {
            assert!(
                matches!(
                    JwtEdDsa::from_cdp_json(doc, 120),
                    Err(KeyError::Document(_))
                ),
                "{doc}"
            );
        }
        // No error or debug output shows the key.
        let jwt = JwtEdDsa::new(KEY_ID, SEED_B64, 120).unwrap();
        let debug = format!("{jwt:?}");
        assert!(
            !debug.contains(KEY_ID) && !debug.contains("nWGx"),
            "{debug}"
        );
        for e in [
            KeyError::PrivateKey,
            KeyError::PublicKeyMismatch,
            KeyError::Document("x"),
        ] {
            assert!(!e.to_string().contains("nWGx"));
        }
        let nonce = [0u8; NONCE_BYTES];
        for (method, host, path) in [
            ("post", "api.example", "/a"),
            ("TRACE", "api.example", "/a"),
            ("POST", "", "/a"),
            ("POST", "api.example/x", "/a"),
            ("POST", "api example", "/a"),
            ("POST", "api.example", "a"),
            ("POST", "api.example", "/a b"),
            ("POST", "api.example", "/a\"b"),
            ("POST", "api.example", "/\u{e9}"),
            ("POST", "api.example", "/a?b=1"),
            ("POST", "api.example", "/a#f"),
            ("POST", "API.example", "/a"),
            ("POST", "api_example", "/a"),
            ("POST", "api.example:", "/a"),
            ("POST", "api.example:x1", "/a"),
            ("POST", "api.example:123456", "/a"),
            ("POST", "[::1", "/a"),
            ("POST", "[::g]", "/a"),
            ("POST", "user@api.example", "/a"),
        ] {
            assert!(
                matches!(
                    jwt.token(method, host, path, 0, &nonce),
                    Err(SignError::Request(_))
                ),
                "{method} {host} {path}"
            );
        }
        assert_eq!(
            JwtEdDsa::new(KEY_ID, SEED_B64, 120),
            JwtEdDsa::new(KEY_ID, PAIR_B64, 120)
        );
        for host in [
            "api.example",
            "api.example:8443",
            "127.0.0.1:80",
            "[::1]",
            "[::1]:8080",
        ] {
            assert!(is_uri_host(host), "{host}");
        }
        for host in [
            "api.example:0",
            "api.example:0443",
            "api.example:65536",
            "[::1]:08080",
        ] {
            assert!(!is_uri_host(host), "{host}");
        }
        assert_eq!(parse_port("65535"), Some(65535));
        assert_eq!(parse_port("+1"), None);
        // More than a key pair: no key.
        let long = base64::engine::general_purpose::STANDARD.encode([1u8; 65]);
        assert_eq!(JwtEdDsa::new(KEY_ID, &long, 120), Err(KeyError::PrivateKey));
        assert_eq!(
            hex(&base64::engine::general_purpose::STANDARD
                .decode(SEED_B64)
                .unwrap()),
            SEED_HEX
        );
    }

    #[test]
    fn header_templates() {
        let literal = Header::literal("X-Fixed", "a {secret} b");
        assert_eq!(literal.header(), ("X-Fixed".into(), "a {secret} b".into()));
        let bearer = Header {
            name: "Authorization",
            value: "Bearer {secret}",
            secret: Some("jwt-1"),
        };
        assert_eq!(
            signed(
                Signer::Header(bearer),
                &h(&[("Authorization", "Bearer client")])
            ),
            h(&[("Authorization", "Bearer jwt-1")])
        );
        let key = Header {
            name: "x-api-key",
            value: "{secret}",
            secret: Some("k"),
        };
        assert_eq!(key.header(), ("x-api-key".into(), "k".into()));
    }

    #[test]
    fn placeholder_swap() {
        let swap = PlaceholderSwap {
            placeholder: "placeholder-1",
            secret: Some("real-1"),
        };
        let placeholder = basic_authorization("placeholder-1");
        assert_eq!(placeholder, "Basic OnBsYWNlaG9sZGVyLTE=");
        assert_eq!(
            swap.authorization(Some(&placeholder)),
            Some(basic_authorization("real-1"))
        );
        assert_eq!(
            swap.authorization(Some(&placeholder.replace("Basic", "bAsIc"))),
            Some(basic_authorization("real-1"))
        );
        for other in [
            "Bearer placeholder-1",
            "Basic cGxhY2Vob2xkZXItMTo=",
            "Basic !",
        ] {
            assert_eq!(swap.authorization(Some(other)), Some(other.to_string()));
        }
        assert_eq!(swap.authorization(None), None);
        let unset = PlaceholderSwap {
            secret: None,
            ..swap
        };
        assert_eq!(unset.authorization(Some(&placeholder)), None);
        // The first Authorization of the request counts.
        assert_eq!(
            signed(
                Signer::PlaceholderSwap(swap),
                &h(&[
                    ("authorization", &placeholder),
                    ("Authorization", "Basic other"),
                ])
            ),
            h(&[("authorization", &basic_authorization("real-1"))])
        );
        assert!(signed(Signer::PlaceholderSwap(swap), &[]).is_empty());
    }
}

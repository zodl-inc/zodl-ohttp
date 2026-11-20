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

//! Validation of a JSON request body against a fixed schema: a size cap, one JSON object whose
//! members are exactly the listed fields (an unknown or repeated member is refused), every
//! value a string checked by its field's [`Check`]. No regular expressions: each check is a
//! small, total function of the string.
//!
//! - [`Check::OneOf`]: one of a list of values, exactly;
//! - [`Check::Chars`]: characters of a set, a length range;
//! - [`Check::Decimal`]: a plain decimal number (no sign, exponent or leading zero) with a
//!   bounded number of fraction digits, within a range;
//! - [`Check::Base58Check`]: a base58check string (Bitcoin alphabet, double SHA-256 checksum)
//!   whose payload is one of the given version prefixes and a fixed number of bytes, such as
//!   a Zcash transparent address ([`ZCASH_MAINNET_P2PKH`]).
//!
//! An error names the field (when it is a listed one) and the kind of the problem, never a
//! value.

use sha2::{Digest, Sha256};

/// The version bytes of a Zcash mainnet transparent P2PKH address (`t1...`).
pub const ZCASH_MAINNET_P2PKH: &[u8] = &[0x1c, 0xb8];
/// The version bytes of a Zcash mainnet transparent P2SH address (`t3...`).
pub const ZCASH_MAINNET_P2SH: &[u8] = &[0x1c, 0xbd];
/// The payload of a transparent address after its version: a 20-byte hash.
pub const TRANSPARENT_HASH_BYTES: usize = 20;

/// RFC 4648 base32, both cases.
pub const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz234567";

/// The Bitcoin base58 alphabet.
const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The longest base58check string decoded.
const MAX_BASE58_LEN: usize = 128;

/// The most integer digits a [`Check::Decimal`] takes.
const MAX_INTEGER_DIGITS: usize = 20;

/// The check of one field's value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    /// Exactly one of these values.
    OneOf(&'static [&'static str]),
    /// Bytes of `charset` only (ASCII), `min..=max` of them.
    Chars {
        charset: &'static [u8],
        min: usize,
        max: usize,
    },
    /// Digits, optionally a `.` and 1 to `max_fraction` digits; no sign, exponent, leading `+`
    /// or leading zero (`0.5` is fine, `05` is not); `min <= value <= max`, both written the
    /// same way.
    Decimal {
        max_fraction: usize,
        min: &'static str,
        max: &'static str,
    },
    /// A base58check string: decoded, its last 4 bytes are the first 4 of the double SHA-256
    /// of the rest, which is one of `versions` followed by `payload_len` bytes.
    Base58Check {
        versions: &'static [&'static [u8]],
        payload_len: usize,
    },
}

impl Check {
    /// Whether `value` passes.
    pub fn accepts(&self, value: &str) -> bool {
        match *self {
            Check::OneOf(values) => values.contains(&value),
            Check::Chars { charset, min, max } => {
                (min..=max).contains(&value.len()) && value.bytes().all(|b| charset.contains(&b))
            }
            Check::Decimal {
                max_fraction,
                min,
                max,
            } => match (
                scaled(value, max_fraction),
                scaled(min, max_fraction),
                scaled(max, max_fraction),
            ) {
                (Some(v), Some(lo), Some(hi)) => lo <= v && v <= hi,
                _ => false,
            },
            Check::Base58Check {
                versions,
                payload_len,
            } => base58check(value).is_some_and(|payload| {
                versions.iter().any(|version| {
                    payload.len() == version.len() + payload_len && payload.starts_with(version)
                })
            }),
        }
    }
}

/// `value` as an integer in units of `10^-fraction`, if it is a decimal of the grammar of
/// [`Check::Decimal`] with at most `fraction` fraction digits.
fn scaled(value: &str, fraction: usize) -> Option<u128> {
    let (int, frac) = match value.split_once('.') {
        Some((int, frac)) => (int, Some(frac)),
        None => (value, None),
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(int) || int.len() > MAX_INTEGER_DIGITS || (int.len() > 1 && int.starts_with('0')) {
        return None;
    }
    if let Some(frac) = frac {
        if !digits(frac) || frac.len() > fraction {
            return None;
        }
    }
    let frac = frac.unwrap_or("");
    let mut n: u128 = 0;
    for b in int
        .bytes()
        .chain(frac.bytes())
        .chain(std::iter::repeat_n(b'0', fraction - frac.len()))
    {
        n = n.checked_mul(10)?.checked_add(u128::from(b - b'0'))?;
    }
    Some(n)
}

/// The payload of a base58check string (version and data, the checksum removed), if it is
/// one.
pub fn base58check(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || value.len() > MAX_BASE58_LEN {
        return None;
    }
    // Big-endian base-256 digits of the number, built one base-58 digit at a time.
    let mut bytes: Vec<u8> = Vec::with_capacity(value.len());
    for c in value.bytes() {
        let mut carry = BASE58.iter().position(|&a| a == c)? as u32;
        for b in bytes.iter_mut().rev() {
            carry += u32::from(*b) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // Each leading '1' is a leading zero byte.
    let zeros = value.bytes().take_while(|&c| c == b'1').count();
    let mut decoded = vec![0u8; zeros];
    decoded.extend_from_slice(&bytes);
    if decoded.len() < 5 {
        return None;
    }
    let (payload, checksum) = decoded.split_at(decoded.len() - 4);
    let hash = Sha256::digest(Sha256::digest(payload));
    (hash[..4] == *checksum).then(|| payload.to_vec())
}

/// One member of a body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field {
    pub name: &'static str,
    pub required: bool,
    pub check: Check,
}

/// A body: at most `max_bytes`, a JSON object with exactly `fields` (the required ones present,
/// no other member).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schema {
    pub max_bytes: usize,
    pub fields: &'static [Field],
}

/// What is wrong with a body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyErrorKind {
    /// More than the schema's `max_bytes`.
    TooLarge,
    /// Not JSON (or not UTF-8).
    NotJson,
    /// JSON, but not an object.
    NotObject,
    /// A member that is not a field of the schema.
    UnknownField,
    /// A field given twice.
    DuplicateField,
    /// A required field missing.
    Missing,
    /// A field whose value is not a string.
    NotString,
    /// A field whose value fails its check.
    Invalid,
}

/// A refused body: the kind of the problem and the field it concerns (a field of the schema;
/// `None` for the body as a whole or a member that is no field).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyError {
    pub field: Option<&'static str>,
    pub kind: BodyErrorKind,
}

impl BodyError {
    /// The reason, as logged (no value, no member name that is not a field).
    pub fn reason(&self) -> &'static str {
        match self.kind {
            BodyErrorKind::TooLarge => "body too large",
            BodyErrorKind::NotJson => "body is not JSON",
            BodyErrorKind::NotObject => "body is not a JSON object",
            BodyErrorKind::UnknownField => "body has an unknown member",
            BodyErrorKind::DuplicateField => "body has a member twice",
            BodyErrorKind::Missing => "body lacks a required member",
            BodyErrorKind::NotString => "body member is not a string",
            BodyErrorKind::Invalid => "body member is not valid",
        }
    }
}

/// The values of a valid body, by field.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Values(Vec<(&'static str, String)>);

impl std::fmt::Debug for Values {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Values are user data (addresses, amounts): their names only.
        f.debug_list()
            .entries(self.0.iter().map(|(name, _)| name))
            .finish()
    }
}

impl Values {
    /// The value of `field`, if the body has it.
    pub fn get(&self, field: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(name, _)| *name == field)
            .map(|(_, v)| v.as_str())
    }
}

/// The members of a JSON object in order, repeated ones kept (serde_json's own map keeps the
/// last).
struct Members(Vec<(String, serde_json::Value)>);

impl<'de> serde::Deserialize<'de> for Members {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Members;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Members, A::Error> {
                let mut out = Vec::new();
                while let Some(entry) = map.next_entry::<String, serde_json::Value>()? {
                    out.push(entry);
                }
                Ok(Members(out))
            }
        }
        d.deserialize_map(Visitor)
    }
}

/// `body` checked against `schema`: its values, or the first problem found.
pub fn validate(schema: &Schema, body: &[u8]) -> Result<Values, BodyError> {
    let whole = |kind| BodyError { field: None, kind };
    if body.len() > schema.max_bytes {
        return Err(whole(BodyErrorKind::TooLarge));
    }
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| whole(BodyErrorKind::NotJson))?;
    if !value.is_object() {
        return Err(whole(BodyErrorKind::NotObject));
    }
    // Parsed again with its members in order: a repeated member must not hide behind the last.
    let members: Members =
        serde_json::from_slice(body).map_err(|_| whole(BodyErrorKind::NotJson))?;
    let mut values = Values::default();
    for (name, value) in members.0 {
        let Some(field) = schema.fields.iter().find(|f| f.name == name) else {
            return Err(whole(BodyErrorKind::UnknownField));
        };
        let error = |kind| BodyError {
            field: Some(field.name),
            kind,
        };
        if values.get(field.name).is_some() {
            return Err(error(BodyErrorKind::DuplicateField));
        }
        let serde_json::Value::String(value) = value else {
            return Err(error(BodyErrorKind::NotString));
        };
        if !field.check.accepts(&value) {
            return Err(error(BodyErrorKind::Invalid));
        }
        values.0.push((field.name, value));
    }
    if let Some(missing) = schema
        .fields
        .iter()
        .find(|f| f.required && values.get(f.name).is_none())
    {
        return Err(BodyError {
            field: Some(missing.name),
            kind: BodyErrorKind::Missing,
        });
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A base58check string of `version` + `payload`.
    fn encode(version: &[u8], payload: &[u8]) -> String {
        let mut data = [version, payload].concat();
        let hash = Sha256::digest(Sha256::digest(&data));
        data.extend_from_slice(&hash[..4]);
        let zeros = data.iter().take_while(|&&b| b == 0).count();
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
        let mut out: String = std::iter::repeat_n('1', zeros).collect();
        out.extend(digits.iter().rev().map(|&d| BASE58[usize::from(d)] as char));
        out
    }

    const T_ADDRESS: Check = Check::Base58Check {
        versions: &[ZCASH_MAINNET_P2PKH],
        payload_len: TRANSPARENT_HASH_BYTES,
    };

    // Synthetic addresses (made-up hashes), computed independently with Python.
    const T1_ZERO: &str = "t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs";
    const T1_SAMPLE: &str = "t1Hxw6JqWMnhDK5jRCieg5bFHM2qt7UtQvu";
    const T3_ZERO: &str = "t3JZcvsuaXE6ygokL4XUiZSTrQBUoPYFnXJ";

    #[test]
    fn base58check_known_answers() {
        assert_eq!(encode(ZCASH_MAINNET_P2PKH, &[0; 20]), T1_ZERO);
        assert_eq!(encode(ZCASH_MAINNET_P2SH, &[0; 20]), T3_ZERO);
        let sample: Vec<u8> = (1..=20).collect();
        assert_eq!(encode(ZCASH_MAINNET_P2PKH, &sample), T1_SAMPLE);
        assert_eq!(
            base58check(T1_SAMPLE),
            Some([ZCASH_MAINNET_P2PKH, &sample].concat())
        );
        assert!(T_ADDRESS.accepts(T1_ZERO));
        assert!(T_ADDRESS.accepts(T1_SAMPLE));
        // Leading zero bytes are leading '1's.
        assert_eq!(
            encode(&[0, 0], &[1, 2]).chars().take(2).collect::<String>(),
            "11"
        );
        assert_eq!(
            base58check(&encode(&[0, 0], &[1, 2])),
            Some(vec![0, 0, 1, 2])
        );
        // Round trips of every length and leading zeros.
        for len in 0..40usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 % 256) as u8).collect();
            for prefix in [&[][..], &[0], &[0, 0, 0]] {
                let payload = [prefix, &data].concat();
                if payload.is_empty() {
                    continue;
                }
                assert_eq!(base58check(&encode(&[], &payload)), Some(payload.clone()));
            }
        }
    }

    #[test]
    fn base58check_refusals() {
        // P2SH, a testnet or a shielded encoding, a wrong checksum, a typo, a bad character.
        assert!(!T_ADDRESS.accepts(T3_ZERO));
        let testnet = encode(&[0x1d, 0x25], &[0; 20]);
        assert!(testnet.starts_with("tm"));
        assert!(!T_ADDRESS.accepts(&testnet));
        let mut typo = T1_SAMPLE.to_string();
        let other = if &typo[10..11] == "a" { "b" } else { "a" };
        typo.replace_range(10..11, other);
        assert!(!T_ADDRESS.accepts(&typo));
        let bad = [
            String::new(),
            "t1".to_string(),
            "0OIl".to_string(),
            T1_SAMPLE[..34].to_string(),
            format!("{T1_SAMPLE}1"),
            format!(" {T1_SAMPLE}"),
            "u1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".to_string(),
            "zs1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".to_string(),
            "t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbt".to_string(),
            "1".repeat(129),
        ];
        for bad in &bad {
            assert!(!T_ADDRESS.accepts(bad), "{bad}");
        }
        // A payload of the wrong length under the right version.
        assert!(!T_ADDRESS.accepts(&encode(ZCASH_MAINNET_P2PKH, &[0; 19])));
        assert!(!T_ADDRESS.accepts(&encode(ZCASH_MAINNET_P2PKH, &[0; 21])));
        assert_eq!(base58check("1111"), None);
        let both = Check::Base58Check {
            versions: &[ZCASH_MAINNET_P2PKH, ZCASH_MAINNET_P2SH],
            payload_len: TRANSPARENT_HASH_BYTES,
        };
        assert!(both.accepts(T3_ZERO) && both.accepts(T1_ZERO));
    }

    #[test]
    fn decimals() {
        let amount = Check::Decimal {
            max_fraction: 2,
            min: "1",
            max: "10000",
        };
        for ok in [
            "1", "1.0", "1.00", "50", "50.5", "9999.99", "10000", "10000.00",
        ] {
            assert!(amount.accepts(ok), "{ok}");
        }
        for bad in [
            "",
            "0",
            "0.99",
            "10000.01",
            "10001",
            "1.001",
            "01",
            "+1",
            "-1",
            "1e3",
            "1.",
            ".5",
            " 1",
            "1 ",
            "1,5",
            "١",
            "1.5.0",
            "NaN",
            "Infinity",
            "0x10",
            "100000000000000000000000",
        ] {
            assert!(!amount.accepts(bad), "{bad}");
        }
        let fine = Check::Decimal {
            max_fraction: 8,
            min: "0.00000001",
            max: "21000000",
        };
        assert!(fine.accepts("0.00000001") && fine.accepts("0.5") && fine.accepts("21000000"));
        assert!(!fine.accepts("0") && !fine.accepts("0.000000001") && !fine.accepts("21000000.1"));
        assert_eq!(scaled("0", 0), Some(0));
        assert_eq!(scaled("12.5", 3), Some(12_500));
        // 20 integer digits at most; the largest scaled value fits.
        assert_eq!(scaled(&"9".repeat(21), 0), None);
        assert!(scaled(&"9".repeat(20), 18).is_some());
        // A malformed bound admits nothing.
        let broken = Check::Decimal {
            max_fraction: 2,
            min: "1",
            max: "x",
        };
        assert!(!broken.accepts("5"));
    }

    #[test]
    fn chars_and_one_of() {
        let reference = Check::Chars {
            charset: BASE32,
            min: 26,
            max: 40,
        };
        assert!(reference.accepts(&"A".repeat(26)));
        assert!(reference.accepts("abcdefghijklmnopqrstuvwxyz234567ABCDEFGH"));
        for bad in [
            "A".repeat(25),
            "A".repeat(41),
            format!("{}1", "A".repeat(26)),
            format!("{}=", "A".repeat(26)),
            format!("{}é", "A".repeat(26)),
        ] {
            assert!(!reference.accepts(&bad), "{bad}");
        }
        let flow = Check::OneOf(&["buy", "sell"]);
        assert!(flow.accepts("buy") && flow.accepts("sell"));
        assert!(!flow.accepts("Buy") && !flow.accepts("") && !flow.accepts("buy "));
    }

    const SCHEMA: Schema = Schema {
        max_bytes: 128,
        fields: &[
            Field {
                name: "flow",
                required: true,
                check: Check::OneOf(&["buy", "sell"]),
            },
            Field {
                name: "address",
                required: true,
                check: T_ADDRESS,
            },
            Field {
                name: "fiat",
                required: false,
                check: Check::OneOf(&["USD", "EUR"]),
            },
        ],
    };

    fn err(body: &str) -> BodyError {
        validate(&SCHEMA, body.as_bytes()).unwrap_err()
    }

    #[test]
    fn bodies() {
        let ok = format!(r#"{{"flow":"buy","address":"{T1_ZERO}"}}"#);
        let values = validate(&SCHEMA, ok.as_bytes()).unwrap();
        assert_eq!(values.get("flow"), Some("buy"));
        assert_eq!(values.get("address"), Some(T1_ZERO));
        assert_eq!(values.get("fiat"), None);
        // The debug form names the fields only.
        assert_eq!(format!("{values:?}"), r#"["flow", "address"]"#);
        let with_fiat = format!(r#" {{ "fiat" : "EUR", "address":"{T1_ZERO}", "flow":"sell" }} "#);
        assert_eq!(
            validate(&SCHEMA, with_fiat.as_bytes()).unwrap().get("fiat"),
            Some("EUR")
        );
        let whole = |kind| BodyError { field: None, kind };
        let field = |name, kind| BodyError {
            field: Some(name),
            kind,
        };
        assert_eq!(err(&" ".repeat(129)), whole(BodyErrorKind::TooLarge));
        assert_eq!(err(""), whole(BodyErrorKind::NotJson));
        assert_eq!(err("{"), whole(BodyErrorKind::NotJson));
        assert_eq!(err(r#"{"flow":"buy"} x"#), whole(BodyErrorKind::NotJson));
        assert_eq!(err("[]"), whole(BodyErrorKind::NotObject));
        assert_eq!(err(r#""buy""#), whole(BodyErrorKind::NotObject));
        assert_eq!(err("null"), whole(BodyErrorKind::NotObject));
        assert_eq!(
            err(r#"{"flow":"buy","clientIp":"192.0.2.1"}"#),
            whole(BodyErrorKind::UnknownField)
        );
        assert_eq!(
            err(r#"{"flow":"buy","flow":"sell"}"#),
            field("flow", BodyErrorKind::DuplicateField)
        );
        assert_eq!(
            err(r#"{"flow":"buy"}"#),
            field("address", BodyErrorKind::Missing)
        );
        assert_eq!(err("{}"), field("flow", BodyErrorKind::Missing));
        assert_eq!(
            err(r#"{"flow":1}"#),
            field("flow", BodyErrorKind::NotString)
        );
        assert_eq!(
            err(r#"{"flow":["buy"]}"#),
            field("flow", BodyErrorKind::NotString)
        );
        assert_eq!(
            err(r#"{"flow":null}"#),
            field("flow", BodyErrorKind::NotString)
        );
        assert_eq!(
            err(r#"{"flow":"rent"}"#),
            field("flow", BodyErrorKind::Invalid)
        );
        assert_eq!(
            err(&format!(r#"{{"flow":"buy","address":"{T3_ZERO}"}}"#)),
            field("address", BodyErrorKind::Invalid)
        );
        // An escaped value is compared decoded.
        assert_eq!(
            validate(
                &SCHEMA,
                format!(r#"{{"flow":"b\u0075y","address":"{T1_ZERO}"}}"#).as_bytes()
            )
            .unwrap()
            .get("flow"),
            Some("buy")
        );
        assert_eq!(err("\u{feff}{}"), whole(BodyErrorKind::NotJson));
        assert_eq!(
            validate(&SCHEMA, b"{\"flow\":\"\xff\"}").unwrap_err(),
            whole(BodyErrorKind::NotJson)
        );
        // Every reason is fixed text.
        for kind in [
            BodyErrorKind::TooLarge,
            BodyErrorKind::NotJson,
            BodyErrorKind::NotObject,
            BodyErrorKind::UnknownField,
            BodyErrorKind::DuplicateField,
            BodyErrorKind::Missing,
            BodyErrorKind::NotString,
            BodyErrorKind::Invalid,
        ] {
            assert!(!whole(kind).reason().is_empty());
        }
    }
}

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

//! DNS-over-HTTPS as a last-resort source for the signed Key Configuration.
//!
//! The TXT record names are build-time configuration (`ZODL_OHTTP_KEYS_DNS_NAME_MAINNET`,
//! `ZODL_OHTTP_KEYS_DNS_NAME_TESTNET`, see `relays.rs`). When the build did not set the
//! name of a network, the DNS source is off for it: [`key_config_dns_name`] and
//! [`doh_query_url`] return `None` and [`envelope_from_doh_json`] refuses every response.

use crate::{Error, MAX_KEY_CONFIG_BYTES};
use base64::Engine as _;

/// Public DNS-over-HTTPS resolvers (JSON API), tried in order.
pub const DOH_RESOLVERS: &[&str] = &[
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
];

/// The DNS name of the signed Key Configuration TXT record for `network`, as the build set it
/// (`ZODL_OHTTP_KEYS_DNS_NAME_*`); `None` when unset (no DNS source for that network).
pub fn key_config_dns_name(network: crate::signed::Network) -> Option<&'static str> {
    crate::relays::Endpoints::BUILT_IN
        .network(network)
        .keys_dns_name
}

/// The DoH query URL for `resolver` and `network` (JSON API, TXT record); `None` when the build
/// did not set the network's DNS name.
pub fn doh_query_url(resolver: &str, network: crate::signed::Network) -> Option<String> {
    key_config_dns_name(network).map(|name| doh_query_url_for(resolver, name))
}

/// The DoH query URL for `resolver` and the TXT record `name`.
fn doh_query_url_for(resolver: &str, name: &str) -> String {
    if resolver.contains("dns.google") {
        format!(
            "{}?name={}&type=TXT&edns_client_subnet=0.0.0.0/0",
            resolver, name
        )
    } else {
        format!("{}?name={}&type=TXT", resolver, name)
    }
}

/// The signed Key Configuration envelope from a DoH JSON response `body` for `network`. The
/// response must have `Status` 0, one or more TXT answers for the queried name (`type` 16), whose
/// presentation-format `data` fields (one or more quoted strings, `\"` / `\\` / `\DDD` escapes)
/// are concatenated and base64-decoded. Enforces the 64 KiB envelope limit. Errors on 0 or >1
/// distinct TXT values, and always when the build did not set the network's DNS name.
pub fn envelope_from_doh_json(
    body: &[u8],
    network: crate::signed::Network,
) -> Result<Vec<u8>, Error> {
    let name = key_config_dns_name(network).ok_or_else(|| {
        Error::KeyConfig(format!(
            "DoH response: no key-configuration DNS name configured for {}",
            network.as_str()
        ))
    })?;
    envelope_from_doh_json_for(body, name)
}

/// [`envelope_from_doh_json`] for the TXT record `expected_name`.
fn envelope_from_doh_json_for(body: &[u8], expected_name: &str) -> Result<Vec<u8>, Error> {
    let refused = |why: String| Error::KeyConfig(format!("DoH response: {why}"));

    let response: DohResponse = serde_json::from_slice(body)
        .map_err(|e| refused(format!("not a DoH JSON response: {e}")))?;

    if response.status != 0 {
        return Err(refused(format!("Status {}, not 0", response.status)));
    }

    let answers = response
        .answer
        .as_ref()
        .ok_or_else(|| refused("no Answer section".into()))?;

    if answers.is_empty() {
        return Err(refused("no TXT answers".into()));
    }

    let mut txt_values = Vec::new();

    for answer in answers {
        if answer.typ != 16 {
            continue;
        }

        let name_matches = answer.name == expected_name
            || (answer.name.ends_with('.') && answer.name.trim_end_matches('.') == expected_name);

        if !name_matches {
            continue;
        }

        let txt =
            parse_txt_presentation(&answer.data).map_err(|e| refused(format!("TXT data: {e}")))?;
        txt_values.push(txt);
    }

    if txt_values.is_empty() {
        return Err(refused("no TXT answers of type 16".into()));
    }

    let distinct: std::collections::HashSet<_> = txt_values.iter().collect();
    if distinct.len() > 1 {
        return Err(refused(format!(
            "{} distinct TXT values, expected 1",
            distinct.len()
        )));
    }

    let concatenated = txt_values[0].as_str();

    if concatenated.len() > MAX_KEY_CONFIG_BYTES.div_ceil(3).saturating_mul(4) {
        return Err(refused(format!(
            "base64 text longer than {} bytes",
            MAX_KEY_CONFIG_BYTES.div_ceil(3).saturating_mul(4)
        )));
    }

    let envelope = base64::engine::general_purpose::STANDARD
        .decode(concatenated)
        .map_err(|e| refused(format!("base64: {e}")))?;

    if envelope.is_empty() {
        return Err(refused("empty envelope after base64 decode".into()));
    }

    if envelope.len() > MAX_KEY_CONFIG_BYTES {
        return Err(refused(format!(
            "envelope of {} bytes, more than {MAX_KEY_CONFIG_BYTES}",
            envelope.len()
        )));
    }

    Ok(envelope)
}

/// Parse a TXT record's presentation format: one or more double-quoted strings separated by spaces,
/// with `\"`, `\\`, and `\DDD` (decimal) escapes, all concatenated. Google's JSON API may also return
/// unquoted text when it's a single string.
fn parse_txt_presentation(data: &str) -> Result<String, String> {
    let trimmed = data.trim();

    // Google DNS may return unquoted text for single-string TXT records
    if !trimmed.starts_with('"') {
        return Ok(trimmed.to_string());
    }

    let mut result = String::new();
    let mut chars = data.chars().peekable();
    let mut in_string = false;

    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' if !in_string => continue,
            '"' if !in_string => {
                in_string = true;
            }
            '"' if in_string => {
                in_string = false;
            }
            '\\' if in_string => match chars.next() {
                Some('"') => result.push('"'),
                Some('\\') => result.push('\\'),
                Some(d1 @ '0'..='9') => {
                    let d2 = chars.next().ok_or("incomplete \\DDD escape")?;
                    let d3 = chars.next().ok_or("incomplete \\DDD escape")?;
                    if !d2.is_ascii_digit() || !d3.is_ascii_digit() {
                        return Err(format!("invalid \\DDD escape: \\{d1}{d2}{d3}"));
                    }
                    let decimal = format!("{d1}{d2}{d3}");
                    let byte: u8 = decimal
                        .parse()
                        .map_err(|_| format!("invalid decimal escape: \\{decimal}"))?;
                    result.push(byte as char);
                }
                Some(other) => return Err(format!("invalid escape: \\{other}")),
                None => return Err("trailing backslash".into()),
            },
            _ if in_string => result.push(c),
            _ => return Err(format!("unexpected character outside quoted string: {c}")),
        }
    }

    if in_string {
        return Err("unterminated quoted string".into());
    }

    Ok(result)
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DohResponse {
    status: i32,
    answer: Option<Vec<DohAnswer>>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "lowercase")]
struct DohAnswer {
    name: String,
    #[serde(rename = "type")]
    typ: u16,
    data: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signed::Network;

    /// The example DNS names of the tests (RFC 2606).
    const MAINNET_NAME: &str = "mainnet.ohttp-keys.example";
    const TESTNET_NAME: &str = "testnet.ohttp-keys.example";

    #[test]
    fn dns_names_are_what_the_build_set() {
        for network in [Network::Mainnet, Network::Testnet] {
            let name = crate::relays::Endpoints::BUILT_IN
                .network(network)
                .keys_dns_name;
            assert_eq!(key_config_dns_name(network), name);
            assert_eq!(
                doh_query_url(DOH_RESOLVERS[0], network).is_some(),
                name.is_some()
            );
            if name.is_none() {
                // No DNS name: the DNS source is off and refuses every response.
                let json = format!(
                    r#"{{"Status":0,"Answer":[{{"name":"{MAINNET_NAME}","type":16,"data":"aGVsbG8gd29ybGQ="}}]}}"#
                );
                assert!(envelope_from_doh_json(json.as_bytes(), network).is_err());
            }
        }
    }

    #[test]
    fn doh_urls_are_correct() {
        assert_eq!(
            doh_query_url_for(DOH_RESOLVERS[0], MAINNET_NAME),
            "https://cloudflare-dns.com/dns-query?name=mainnet.ohttp-keys.example&type=TXT"
        );
        assert_eq!(
            doh_query_url_for(DOH_RESOLVERS[1], TESTNET_NAME),
            "https://dns.google/resolve?name=testnet.ohttp-keys.example&type=TXT&edns_client_subnet=0.0.0.0/0"
        );
    }

    #[test]
    fn unquoted_txt_is_parsed() {
        let json = r#"{
            "Status": 0,
            "Answer": [{
                "name": "mainnet.ohttp-keys.example",
                "type": 16,
                "data": "aGVsbG8gd29ybGQ="
            }]
        }"#;
        let envelope = envelope_from_doh_json_for(json.as_bytes(), MAINNET_NAME).unwrap();
        assert_eq!(envelope, b"hello world");
    }

    #[test]
    fn single_string_txt_record_is_parsed() {
        let json = r#"{
            "Status": 0,
            "Answer": [{
                "name": "mainnet.ohttp-keys.example",
                "type": 16,
                "data": "\"aGVsbG8gd29ybGQ=\""
            }]
        }"#;
        let envelope = envelope_from_doh_json_for(json.as_bytes(), MAINNET_NAME).unwrap();
        assert_eq!(envelope, b"hello world");
    }

    #[test]
    fn split_strings_are_concatenated() {
        let json = r#"{
            "Status": 0,
            "Answer": [{
                "name": "mainnet.ohttp-keys.example",
                "type": 16,
                "data": "\"aGVsbG8g\" \"d29ybGQ=\""
            }]
        }"#;
        let envelope = envelope_from_doh_json_for(json.as_bytes(), MAINNET_NAME).unwrap();
        assert_eq!(envelope, b"hello world");
    }

    #[test]
    fn escapes_are_handled() {
        let json = r#"{
            "Status": 0,
            "Answer": [{
                "name": "mainnet.ohttp-keys.example",
                "type": 16,
                "data": "\"aGVs\" \"bG8g\" \"d29y\" \"bGQ=\""
            }]
        }"#;
        let envelope = envelope_from_doh_json_for(json.as_bytes(), MAINNET_NAME).unwrap();
        assert_eq!(envelope, b"hello world");
    }

    #[test]
    fn multiple_answers_with_same_value_are_accepted() {
        let json = r#"{
            "Status": 0,
            "Answer": [
                {
                    "name": "mainnet.ohttp-keys.example",
                    "type": 16,
                    "data": "\"aGVsbG8gd29ybGQ=\""
                },
                {
                    "name": "mainnet.ohttp-keys.example",
                    "type": 16,
                    "data": "\"aGVsbG8gd29ybGQ=\""
                }
            ]
        }"#;
        let envelope = envelope_from_doh_json_for(json.as_bytes(), MAINNET_NAME).unwrap();
        assert_eq!(envelope, b"hello world");
    }

    #[test]
    fn wrong_type_is_ignored() {
        let json = r#"{
            "Status": 0,
            "Answer": [
                {
                    "name": "mainnet.ohttp-keys.example",
                    "type": 1,
                    "data": "1.2.3.4"
                },
                {
                    "name": "mainnet.ohttp-keys.example",
                    "type": 16,
                    "data": "\"aGVsbG8gd29ybGQ=\""
                }
            ]
        }"#;
        let envelope = envelope_from_doh_json_for(json.as_bytes(), MAINNET_NAME).unwrap();
        assert_eq!(envelope, b"hello world");
    }

    #[test]
    fn status_not_zero_is_refused() {
        let json = r#"{
            "Status": 3,
            "Answer": [{
                "name": "mainnet.ohttp-keys.example",
                "type": 16,
                "data": "\"aGVsbG8gd29ybGQ=\""
            }]
        }"#;
        let Err(Error::KeyConfig(msg)) = envelope_from_doh_json_for(json.as_bytes(), MAINNET_NAME)
        else {
            panic!("expected KeyConfig error");
        };
        assert!(msg.contains("Status 3"));
    }

    #[test]
    fn bad_base64_is_refused() {
        let json = r#"{
            "Status": 0,
            "Answer": [{
                "name": "mainnet.ohttp-keys.example",
                "type": 16,
                "data": "\"not-base64!!!\""
            }]
        }"#;
        let Err(Error::KeyConfig(msg)) = envelope_from_doh_json_for(json.as_bytes(), MAINNET_NAME)
        else {
            panic!("expected KeyConfig error");
        };
        assert!(msg.contains("base64"));
    }

    #[test]
    fn oversize_envelope_is_refused() {
        let huge_base64 = "AAAA".repeat(MAX_KEY_CONFIG_BYTES / 3 + 1);
        let json = format!(
            r#"{{
            "Status": 0,
            "Answer": [{{
                "name": "mainnet.ohttp-keys.example",
                "type": 16,
                "data": "{}"
            }}]
        }}"#,
            huge_base64
        );
        let Err(Error::KeyConfig(msg)) = envelope_from_doh_json_for(json.as_bytes(), MAINNET_NAME)
        else {
            panic!("expected KeyConfig error");
        };
        assert!(msg.contains("more than"));
    }

    #[test]
    fn wrong_network_name_is_refused() {
        let json = r#"{
            "Status": 0,
            "Answer": [{
                "name": "testnet.ohttp-keys.example",
                "type": 16,
                "data": "\"aGVsbG8gd29ybGQ=\""
            }]
        }"#;
        let Err(Error::KeyConfig(msg)) = envelope_from_doh_json_for(json.as_bytes(), MAINNET_NAME)
        else {
            panic!("expected KeyConfig error");
        };
        assert!(msg.contains("no TXT answers"));
    }

    #[test]
    fn multiple_distinct_txt_values_are_refused() {
        let json = r#"{
            "Status": 0,
            "Answer": [
                {
                    "name": "mainnet.ohttp-keys.example",
                    "type": 16,
                    "data": "\"aGVsbG8=\""
                },
                {
                    "name": "mainnet.ohttp-keys.example",
                    "type": 16,
                    "data": "\"d29ybGQ=\""
                }
            ]
        }"#;
        let Err(Error::KeyConfig(msg)) = envelope_from_doh_json_for(json.as_bytes(), MAINNET_NAME)
        else {
            panic!("expected KeyConfig error");
        };
        assert!(msg.contains("distinct"));
    }

    #[test]
    fn decimal_escapes_are_handled() {
        // DNS TXT uses decimal \DDD escapes (RFC 1035).
        // Test by encoding valid base64 characters using decimal notation:
        // \097 = 'a', \071 = 'G', \086 = 'V', \115 = 's'. The backslashes are JSON-escaped (`\\`),
        // as a resolver sends them.
        let json = r#"{
            "Status": 0,
            "Answer": [{
                "name": "mainnet.ohttp-keys.example",
                "type": 16,
                "data": "\"\\097\\071\\086\\115bG8gd29ybGQ=\""
            }]
        }"#;
        let envelope = envelope_from_doh_json_for(json.as_bytes(), MAINNET_NAME).unwrap();
        // "aGVsbG8gd29ybGQ=" base64-decodes to "hello world"
        assert_eq!(envelope, b"hello world");
    }

    #[test]
    fn unrelated_txt_records_are_filtered() {
        let json = r#"{
            "Status": 0,
            "Answer": [
                {
                    "name": "evil.example.com",
                    "type": 16,
                    "data": "\"evildata\""
                },
                {
                    "name": "mainnet.ohttp-keys.example",
                    "type": 16,
                    "data": "\"aGVsbG8gd29ybGQ=\""
                }
            ]
        }"#;
        let envelope = envelope_from_doh_json_for(json.as_bytes(), MAINNET_NAME).unwrap();
        assert_eq!(envelope, b"hello world");
    }

    #[test]
    fn trailing_dot_in_name_is_accepted() {
        let json = r#"{
            "Status": 0,
            "Answer": [{
                "name": "mainnet.ohttp-keys.example.",
                "type": 16,
                "data": "\"aGVsbG8gd29ybGQ=\""
            }]
        }"#;
        let envelope = envelope_from_doh_json_for(json.as_bytes(), MAINNET_NAME).unwrap();
        assert_eq!(envelope, b"hello world");
    }

    /// A signed envelope (the test vector of `docs/signed-configs-test-vector.json`) as DoH
    /// resolvers answer it: split into quoted strings of at most 255 characters, the way one
    /// resolver presents a long TXT record, and as one unquoted string, the way another does.
    #[test]
    fn a_signed_envelope_round_trips_through_both_answer_styles() {
        use base64::Engine as _;
        #[derive(serde::Deserialize)]
        struct Vector {
            public_key_hex: String,
            key_id: String,
            network: String,
            configs_bytes_base64: String,
            not_before: u64,
            not_after: u64,
            signature_base64: String,
        }
        let v: Vector =
            serde_json::from_str(include_str!("../../docs/signed-configs-test-vector.json"))
                .unwrap();
        let envelope = serde_json::json!({
            "v": 1,
            "network": v.network,
            "configs": v.configs_bytes_base64,
            "not_before": v.not_before,
            "not_after": v.not_after,
            "key_id": v.key_id,
            "sig": v.signature_base64,
        })
        .to_string();
        let text = base64::engine::general_purpose::STANDARD.encode(&envelope);
        assert!(text.len() > 255, "the record needs more than one string");
        let quoted = text
            .as_bytes()
            .chunks(255)
            .map(|chunk| format!("\\\"{}\\\"", std::str::from_utf8(chunk).unwrap()))
            .collect::<Vec<_>>()
            .join(" ");
        let signer: [u8; 32] = hex::decode(v.public_key_hex.as_str())
            .unwrap()
            .try_into()
            .unwrap();
        let signer = ed25519_dalek::VerifyingKey::from_bytes(&signer).unwrap();
        for (name, data) in [
            (TESTNET_NAME.to_string(), quoted),
            (format!("{TESTNET_NAME}."), text),
        ] {
            let json = format!(
                r#"{{
  "Status": 0,
  "TC": false,
  "RD": true,
  "RA": true,
  "AD": false,
  "CD": false,
  "Question": [{{ "name": "{name}", "type": 16 }}],
  "Answer": [{{ "name": "{name}", "type": 16, "TTL": 300, "data": "{data}" }}]
}}"#
            );
            let opened = envelope_from_doh_json_for(json.as_bytes(), TESTNET_NAME).unwrap();
            assert_eq!(opened, envelope.as_bytes(), "{name}");
            let keys =
                crate::open_signed_config(&opened, &v.network, &signer, v.not_before + 60).unwrap();
            assert_eq!(keys.not_after, v.not_after);
            // The record of the other network is not this one.
            assert!(envelope_from_doh_json_for(json.as_bytes(), MAINNET_NAME).is_err());
        }
    }
}

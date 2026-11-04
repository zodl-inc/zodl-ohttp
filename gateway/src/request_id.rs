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

//! Custom client trace ID validation
//!
//! Clients can supply custom trace IDs for debugging via X-Client-Trace-Id header.
//! The ID must match:
//! - Start with alphanumeric
//! - Contain only: letters, digits, . _ : -
//! - Max 64 characters
//!
//! Examples: "example-phone-test-1", "abc-123", "debug.test:001"
//!
//! Privacy note: Custom trace IDs are opt-in and for debugging only. A custom trace ID
//! links the relay's view (client IP) with the gateway's view (request content)
//! for THAT request. Do not use custom trace IDs for regular traffic.

/// Validate a client-supplied trace ID.
/// Returns true if the ID matches: ^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$
pub fn is_valid_client_trace_id(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 {
        return false;
    }

    let mut chars = s.chars();

    // First char must be alphanumeric
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }

    // Rest can be alphanumeric or . _ : -
    for c in chars {
        if !c.is_ascii_alphanumeric() && c != '.' && c != '_' && c != ':' && c != '-' {
            return false;
        }
    }

    true
}

/// Extract and validate client trace ID from X-Client-Trace-Id header.
/// Returns Some(id) if valid, None if missing or invalid.
pub fn extract_client_trace_id(headers: &axum::http::HeaderMap) -> Option<String> {
    let candidate = headers
        .get("x-client-trace-id")
        .or_else(|| headers.get("X-Client-Trace-Id"))
        .and_then(|v| v.to_str().ok())?;

    if is_valid_client_trace_id(candidate) {
        Some(candidate.to_string())
    } else {
        None
    }
}

/// Outcome of looking for a relay-supplied correlation id (metrics label).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayIdState {
    Present,
    Missing,
    Invalid,
}

impl RelayIdState {
    pub fn as_str(&self) -> &'static str {
        match self {
            RelayIdState::Present => "present",
            RelayIdState::Missing => "missing",
            RelayIdState::Invalid => "invalid",
        }
    }
}

/// Relay-supplied correlation id (`X-Request-Id`, else a relay's trace header, `Fastly-Trace-Id`).
///
/// Security: the value is untrusted input from the relay hop. It is treated as an OPAQUE token and
/// accepted only if it matches `^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$` (same rule as client trace ids,
/// so no CR/LF, quotes, braces, spaces or non-ASCII can reach a log line or header). It is never
/// forwarded upstream, never echoed to the client and only ever written as a structured log field;
/// the gateway always mints its own `request_id` for the hops it controls.
///
/// Returns `(id, source, state)` where `source` is `x-request-id`, `fastly-trace-id` or `none`.
pub fn extract_relay_request_id(
    headers: &axum::http::HeaderMap,
) -> (Option<String>, &'static str, RelayIdState) {
    for name in ["x-request-id", "fastly-trace-id"] {
        if let Some(v) = headers.get(name) {
            // Non-UTF-8 / non-visible-ASCII header bytes are rejected by `to_str`.
            return match v.to_str() {
                Ok(s) if is_valid_client_trace_id(s) => {
                    (Some(s.to_string()), name, RelayIdState::Present)
                }
                _ => (None, name, RelayIdState::Invalid),
            };
        }
    }
    (None, "none", RelayIdState::Missing)
}

/// The edge location label of a request: the three upper-case letters after the last `-` of the
/// `CF-Ray` header (e.g. `8d2f...-XYZ`), or `-`. The header is untrusted relay-hop input, so this
/// is a syntactically filtered label, not a verified location. It names a site of the relay's
/// network, never a client: metrics only (ZIP "Metrics and logs").
pub fn edge_location(headers: &axum::http::HeaderMap) -> &str {
    headers
        .get("cf-ray")
        .and_then(|v| v.to_str().ok())
        .and_then(|ray| ray.rsplit_once('-'))
        .map(|(_, colo)| colo)
        .filter(|c| c.len() == 3 && c.bytes().all(|b| b.is_ascii_uppercase()))
        .unwrap_or("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edge_location_is_the_cf_ray_colo() {
        let mut h = axum::http::HeaderMap::new();
        assert_eq!(edge_location(&h), "-");
        h.insert("cf-ray", "8d2f1a2b3c4d5e6f-XYZ".parse().unwrap());
        assert_eq!(edge_location(&h), "XYZ");
        h.insert("cf-ray", "8d2f1a2b3c4d5e6f-xyz1".parse().unwrap());
        assert_eq!(edge_location(&h), "-");
    }

    fn hm(pairs: &[(&str, &[u8])]) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_bytes(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn relay_id_uuid_from_x_request_id() {
        let (id, src, st) = extract_relay_request_id(&hm(&[(
            "x-request-id",
            b"550e8400-e29b-41d4-a716-446655440000",
        )]));
        assert_eq!(id.as_deref(), Some("550e8400-e29b-41d4-a716-446655440000"));
        assert_eq!(src, "x-request-id");
        assert_eq!(st, RelayIdState::Present);
    }

    #[test]
    fn relay_id_accepts_a_non_uuid_relay_trace_id() {
        // Relay trace ids are not UUIDs; any opaque token in the allowed charset is fine.
        let (id, src, st) = extract_relay_request_id(&hm(&[(
            "fastly-trace-id",
            b"b0e3e6b1-7f1a-4a8c-9c6f-2a1b:edge-01",
        )]));
        assert!(id.is_some());
        assert_eq!(src, "fastly-trace-id");
        assert_eq!(st, RelayIdState::Present);
    }

    #[test]
    fn relay_id_x_request_id_wins_over_the_trace_header() {
        let (id, src, _) = extract_relay_request_id(&hm(&[
            ("fastly-trace-id", b"trace-1"),
            ("x-request-id", b"relay-1"),
        ]));
        assert_eq!(id.as_deref(), Some("relay-1"));
        assert_eq!(src, "x-request-id");
    }

    #[test]
    fn relay_id_missing() {
        let (id, src, st) = extract_relay_request_id(&hm(&[]));
        assert!(id.is_none());
        assert_eq!(src, "none");
        assert_eq!(st, RelayIdState::Missing);
    }

    #[test]
    fn relay_id_rejects_injection_attempts() {
        let bad: &[&[u8]] = &[
            b"abc\tdef",                  // control char (tab is a legal header byte)
            b"{\"json\":1}",              // JSON/braces
            b"id\" level=\"ERROR",        // quote / log-field injection
            b"<script>alert(1)</script>", // markup
            b"a b",                       // space
            b"$(reboot)",                 // shell-ish
            b"-leading-dash",             // must start alphanumeric
            b"",                          // empty
            b"a12345678901234567890123456789012345678901234567890123456789012345", // 65 chars
            b"caf\xc3\xa9",               // non-ASCII (valid UTF-8)
        ];
        for b in bad {
            let (id, _, st) = extract_relay_request_id(&hm(&[("x-request-id", b)]));
            assert!(id.is_none(), "accepted {:?}", String::from_utf8_lossy(b));
            assert_eq!(
                st,
                RelayIdState::Invalid,
                "state for {:?}",
                String::from_utf8_lossy(b)
            );
        }
        // Invalid X-Request-Id does not fall through to the trace header (state stays Invalid).
        let (id, src, st) = extract_relay_request_id(&hm(&[
            ("x-request-id", b"a b"),
            ("fastly-trace-id", b"ok-1"),
        ]));
        assert!(id.is_none());
        assert_eq!(src, "x-request-id");
        assert_eq!(st, RelayIdState::Invalid);
    }

    #[test]
    fn test_valid_client_trace_ids() {
        assert!(is_valid_client_trace_id("abc-123"));
        assert!(is_valid_client_trace_id("example.test:1"));
        assert!(is_valid_client_trace_id("debug_001"));
        assert!(is_valid_client_trace_id("a"));
        assert!(is_valid_client_trace_id("A1B2C3"));
        assert!(is_valid_client_trace_id("test-id.v2:final"));
        // UUID format is valid (all allowed chars)
        assert!(is_valid_client_trace_id(
            "550e8400-e29b-41d4-a716-446655440000"
        ));
    }

    #[test]
    fn test_invalid_client_trace_ids() {
        // Empty
        assert!(!is_valid_client_trace_id(""));

        // Too long (65 chars)
        assert!(!is_valid_client_trace_id(
            "a12345678901234567890123456789012345678901234567890123456789012345"
        ));

        // Starts with non-alphanumeric
        assert!(!is_valid_client_trace_id("-starts-with-dash"));
        assert!(!is_valid_client_trace_id(".starts.with.dot"));
        assert!(!is_valid_client_trace_id(":colon"));

        // Contains invalid characters
        assert!(!is_valid_client_trace_id("has spaces"));
        assert!(!is_valid_client_trace_id("has/slash"));
        assert!(!is_valid_client_trace_id("<script>"));
        assert!(!is_valid_client_trace_id("unicode→arrow"));
        assert!(!is_valid_client_trace_id("emoji😀"));
        assert!(!is_valid_client_trace_id("semi;colon"));
        assert!(!is_valid_client_trace_id("at@sign"));
    }

    #[test]
    fn test_extract_valid() {
        use axum::http::HeaderMap;

        let mut headers = HeaderMap::new();
        headers.insert("x-client-trace-id", "example-debug-001".parse().unwrap());

        let id = extract_client_trace_id(&headers);
        assert_eq!(id, Some("example-debug-001".to_string()));
    }

    #[test]
    fn test_extract_invalid() {
        use axum::http::HeaderMap;

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-client-trace-id",
            "invalid id with spaces".parse().unwrap(),
        );

        let id = extract_client_trace_id(&headers);
        assert_eq!(id, None);
    }

    #[test]
    fn test_extract_missing() {
        use axum::http::HeaderMap;

        let headers = HeaderMap::new();
        let id = extract_client_trace_id(&headers);
        assert_eq!(id, None);
    }

    #[test]
    fn test_extract_case_insensitive() {
        use axum::http::HeaderMap;

        let mut headers = HeaderMap::new();
        headers.insert("X-Client-Trace-Id", "test-123".parse().unwrap());

        let id = extract_client_trace_id(&headers);
        assert_eq!(id, Some("test-123".to_string()));
    }
}

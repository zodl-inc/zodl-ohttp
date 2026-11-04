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
//! for every request that carries it (reusing one ID links all of them). Do not use custom
//! trace IDs for regular traffic.

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

#[cfg(test)]
mod tests {
    use super::*;

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

        // Too long (66 chars)
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

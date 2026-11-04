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

// Regression tests for the security audit fixes.
// Most tests fail without their fix; the ones that print a FIXME only document the expected
// behaviour.

#[cfg(test)]
mod bounded_labels {
    use crate::health::{normalize_backend, normalize_method};
    use std::collections::HashMap;

    #[test]
    fn test_unbounded_methods_fail_before_fix() {
        // Before fix: raw methods would be used directly in metrics
        // After fix: they map to bounded set
        let unbounded = vec!["CUSTOM", "TRACE", "CONNECT", "/some/path"];

        for method in unbounded {
            assert_eq!(normalize_method(method), "other");
        }
    }

    #[test]
    fn test_unbounded_authorities_fail_before_fix() {
        // Before fix: raw authority would create unbounded metric series
        // After fix: unknown authorities map to "other"
        let gateway_hosts = vec!["ohttp-gateway.example".to_string()];
        let backends = HashMap::new();

        // Simulate attacker creating 1000 unique authorities
        for i in 0..1000 {
            assert_eq!(
                normalize_backend(&format!("r{}.x", i), &gateway_hosts, &backends),
                "other"
            );
        }
    }

    #[test]
    fn test_cardinality_bounded_after_fix() {
        let gateway_hosts = vec!["ohttp-gateway.example".to_string()];
        let mut backends = HashMap::new();
        backends.insert(
            "api1.example.com".to_string(),
            "https://prices-upstream.example".to_string(),
        );

        let mut labels = std::collections::HashSet::new();

        // Add 10000 unknown authorities (of the 3 possible labels lwd, api1.example.com and other,
        // they can only produce other)
        for i in 0..10000 {
            labels.insert(normalize_backend(
                &format!("attack{}.example", i),
                &gateway_hosts,
                &backends,
            ));
        }

        assert!(
            labels.len() <= 3,
            "Expected ≤3 labels, got {}",
            labels.len()
        );
    }
}

#[cfg(test)]
mod compactblock_proto_tags {
    use prost::Message;

    #[derive(Clone, PartialEq, prost::Message)]
    struct CompactBlockBroken {
        #[prost(uint64, tag = "1")]
        height: u64,
        #[prost(bytes, tag = "12")]
        hash: Vec<u8>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    struct CompactBlockFixed {
        #[prost(uint64, tag = "2")]
        height: u64,
        #[prost(bytes, tag = "3")]
        hash: Vec<u8>,
    }

    #[test]
    fn test_wrong_tags_decode_to_zero_before_fix() {
        // Real CompactBlock from lightwalletd compact_formats.proto
        // Height at tag 2, hash at tag 3
        let mut real_compact_block = vec![
            0x10, // tag=2, varint (Field 2: height)
            0xB9, // 12345 in varint encoding
            0x60, 0x1A, // tag=3, length-delimited (Field 3: hash)
            32,   // length
        ];
        real_compact_block.extend_from_slice(&[0xAA; 32]); // 32 bytes of 0xAA

        // Broken struct with wrong tags decodes to (0, [])
        let broken = CompactBlockBroken::decode(&real_compact_block[..]).unwrap();
        assert_eq!(broken.height, 0, "Broken tags decode height to 0");
        assert_eq!(broken.hash.len(), 0, "Broken tags decode hash to empty");

        // Fixed struct with correct tags decodes properly
        let fixed = CompactBlockFixed::decode(&real_compact_block[..]).unwrap();
        assert_eq!(fixed.height, 12345, "Fixed tags decode height correctly");
        assert_eq!(fixed.hash.len(), 32, "Fixed tags decode hash correctly");
        assert_eq!(fixed.hash[0], 0xAA);
    }
}

#[cfg(test)]
mod cache_storage {
    #[test]
    fn test_json_vec_u8_inflation() {
        // Before fix: Vec<u8> serialized as JSON array of decimal numbers
        // This inflates the body (about 2x for these zero bytes, more for larger values)
        let body = vec![0u8; 1_000_000]; // 1 MB
        let json_bytes = serde_json::to_vec(&body).unwrap();

        // JSON array format: "[0,0,0,...]" is about 2 bytes per element (number + comma)
        // So 1M elements = ~2MB+ (actually more due to brackets and formatting)
        assert!(
            json_bytes.len() > body.len() * 2,
            "JSON inflation: {} bytes -> {} bytes ({}x)",
            body.len(),
            json_bytes.len(),
            json_bytes.len() as f64 / body.len() as f64
        );

        // After fix: use bincode or raw bytes (no inflation)
        let bincode_bytes = bincode::serialize(&body).unwrap();
        assert!(
            bincode_bytes.len() < ((body.len() as f64 * 1.1) as usize),
            "Bincode should be close to original size: {} bytes -> {} bytes",
            body.len(),
            bincode_bytes.len()
        );
    }
}

#[cfg(test)]
mod startup_validation {
    use crate::config::Config;
    use std::env;

    #[test]
    fn test_both_relay_secret_vars_error_before_fix() {
        let _env = crate::config::test_env_lock();
        // Setting both RELAY_SECRET and RELAY_SECRETS should ERROR at startup,
        // instead of one silently shadowing the other.

        env::set_var("RELAY_SECRET", "secret1");
        env::set_var("RELAY_SECRETS", "secret2,secret3");

        // This should error after the fix
        let result = Config::from_env();

        env::remove_var("RELAY_SECRET");
        env::remove_var("RELAY_SECRETS");

        // Before fix: this would succeed (shadowing)
        // After fix: this should error
        // Uncomment after implementing the fix:
        // assert!(result.is_err(), "Both RELAY_SECRET and RELAY_SECRETS should cause error");

        // For now, document expected behavior:
        println!(
            "FIXME: Config should reject both RELAY_SECRET and RELAY_SECRETS set simultaneously"
        );
        let _ = result;
    }

    #[test]
    fn test_missing_hpke_key_production_error() {
        // Missing HPKE key in production mode should ERROR at startup instead of just warning.
        // This test documents expected behavior.
        println!("FIXME: Missing HPKE_KEYS in ohttp mode should cause startup ERROR");
    }
}
#[cfg(test)]
mod metrics_cardinality {
    use crate::health;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn test_unknown_paths_collapse_to_other() {
        // Unknown gRPC paths should normalize to "other", not create unbounded labels
        let unknown_paths = vec![
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/UnknownMethod",
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/AttackPath1",
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/AttackPath2",
            "/completely/different/path",
            "/another/random/path",
        ];

        let mut labels = HashSet::new();
        for path in &unknown_paths {
            labels.insert(health::normalize_rpc_name(path, "POST"));
        }

        // All unknown paths should collapse to "other"
        assert_eq!(labels.len(), 1, "All unknown paths should map to 'other'");
        assert_eq!(labels.iter().next().unwrap(), "other");
    }

    #[test]
    fn test_known_paths_preserved() {
        // Known gRPC methods should be preserved
        let known_paths = [
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock",
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlockRange",
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTreeState",
        ];

        let results: Vec<String> = known_paths
            .iter()
            .map(|p| health::normalize_rpc_name(p, "POST"))
            .collect();

        assert_eq!(results[0], "GetLatestBlock");
        assert_eq!(results[1], "GetBlockRange");
        assert_eq!(results[2], "GetTreeState");
    }

    #[test]
    fn test_authority_with_port_normalized() {
        // Authority with port should be normalized (strip port, unknown -> "other")
        let gateway_hosts = vec!["ohttp-gateway.example".to_string()];
        let backends = HashMap::new();

        // Authority with different ports should all map to the same label
        let mut labels = HashSet::new();
        for port in 1..65536 {
            labels.insert(health::normalize_backend(
                &format!("attack.example:{}", port),
                &gateway_hosts,
                &backends,
            ));
        }

        // All should collapse to "other"
        assert_eq!(
            labels.len(),
            1,
            "All unknown authorities should map to 'other'"
        );
        assert_eq!(labels.iter().next().unwrap(), "other");
    }

    #[test]
    fn test_known_backend_preserved() {
        // Known backend aliases should be preserved
        let gateway_hosts = vec!["ohttp-gateway.example".to_string()];
        let mut backends = HashMap::new();
        backends.insert(
            "api1.example.com".to_string(),
            "https://backend".to_string(),
        );
        backends.insert(
            "api2.example.com".to_string(),
            "https://backend".to_string(),
        );

        let result1 = health::normalize_backend("api1.example.com", &gateway_hosts, &backends);
        let result2 = health::normalize_backend("api2.example.com", &gateway_hosts, &backends);

        assert_eq!(result1, "api1.example.com");
        assert_eq!(result2, "api2.example.com");
    }
}

#[cfg(test)]
mod rejection_cardinality {
    use crate::health;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn test_rejection_paths_bounded_cardinality() {
        // Send 10k hostile authorities/paths through rejection code paths
        // and verify metric label cardinality stays bounded (prevents cardinality explosion).

        let gateway_hosts = vec!["ohttp-gateway.example".to_string()];
        let backends = HashMap::new();

        let mut backend_labels = HashSet::new();
        let mut rpc_labels = HashSet::new();
        let mut method_labels = HashSet::new();

        // Simulate 10k requests with unique hostile authorities and paths
        for i in 0..10_000 {
            // Authority normalization (the label the 426 plain-gRPC rejection records)
            let hostile_authority = format!("attack{}.malicious.example", i);
            backend_labels.insert(health::normalize_backend(
                &hostile_authority,
                &gateway_hosts,
                &backends,
            ));

            // Path normalization (the label a 403 policy denial records)
            let hostile_path = format!("/cash.z.wallet.sdk.rpc.CompactTxStreamer/Attack{}", i);
            rpc_labels.insert(health::normalize_rpc_name(&hostile_path, "POST"));

            // Method normalization (the label the 400/413/422/409 paths record)
            let hostile_method = format!("CUSTOM{}", i);
            method_labels.insert(health::normalize_method(&hostile_method));
        }

        // Cardinality bounds:
        // - backends: lwd + configured aliases + "other" = at most ~10
        // - RPCs: known gRPC methods + "other" = at most ~20
        // - methods: GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS + "other" = 8
        assert!(
            backend_labels.len() <= 10,
            "Backend labels unbounded: {} unique labels (expected ≤10)",
            backend_labels.len()
        );
        assert!(
            rpc_labels.len() <= 20,
            "RPC labels unbounded: {} unique labels (expected ≤20)",
            rpc_labels.len()
        );
        assert!(
            method_labels.len() <= 8,
            "Method labels unbounded: {} unique labels (expected ≤8)",
            method_labels.len()
        );

        // Verify "other" is the dominant label for hostile inputs
        assert!(backend_labels.contains("other"));
        assert!(rpc_labels.contains("other"));
        assert!(method_labels.contains("other"));
    }

    #[test]
    fn test_path_traversal_normalized() {
        // Path traversal attempts should normalize to "other" to prevent cardinality explosion
        let hostile_paths = vec![
            "/../../../etc/passwd",
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/../../../secret",
            "/cash.z.wallet.sdk.rpc.%2e%2e%2fsecret",
        ];

        for path in &hostile_paths {
            let label = health::normalize_rpc_name(path, "POST");
            assert_eq!(label, "other", "Path traversal should normalize to 'other'");
        }
    }

    #[test]
    fn test_port_scanning_normalized() {
        // Port scanning via authority should collapse to "other" to prevent cardinality explosion
        let gateway_hosts = vec!["ohttp-gateway.example".to_string()];
        let backends = HashMap::new();

        let mut labels = HashSet::new();
        for port in 1..1000 {
            labels.insert(health::normalize_backend(
                &format!("internal-service.local:{}", port),
                &gateway_hosts,
                &backends,
            ));
        }

        assert_eq!(
            labels.len(),
            1,
            "Port scanning should produce single 'other' label"
        );
        assert_eq!(labels.iter().next().unwrap(), "other");
    }
}

#[cfg(test)]
mod gw_framing_msg {
    use crate::enforcement::check_grpc_compression;

    #[test]
    fn test_framing_errors_have_distinct_message() {
        // Frame too short
        let too_short = vec![0x00, 0x00, 0x00];
        let err = check_grpc_compression(&too_short).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Malformed gRPC framing"),
            "Expected framing error message, got: {}",
            msg
        );
        assert!(
            msg.contains("too short"),
            "Expected 'too short' in message, got: {}",
            msg
        );

        // Frame extends beyond body
        let extends_beyond = vec![
            0x00, // not compressed
            0x00, 0x00, 0x00, 0x10, // length = 16
            0x01, 0x02, 0x03, // only 3 bytes follow, not 16
        ];
        let err = check_grpc_compression(&extends_beyond).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Malformed gRPC framing"),
            "Expected framing error message, got: {}",
            msg
        );
        assert!(
            msg.contains("extends beyond"),
            "Expected 'extends beyond' in message, got: {}",
            msg
        );

        // Compression error has distinct message
        let compressed = vec![
            0x01, // compressed flag = 1
            0x00, 0x00, 0x00, 0x05, // length = 5
            0x01, 0x02, 0x03, 0x04, 0x05,
        ];
        let err = check_grpc_compression(&compressed).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Compressed gRPC messages are not supported"),
            "Expected compression error message, got: {}",
            msg
        );
        assert!(
            !msg.contains("Malformed"),
            "Compression error should not mention framing, got: {}",
            msg
        );
    }

    #[test]
    fn test_valid_frame_passes() {
        let valid = vec![
            0x00, // not compressed
            0x00, 0x00, 0x00, 0x05, // length = 5
            0x01, 0x02, 0x03, 0x04, 0x05,
        ];
        assert!(check_grpc_compression(&valid).is_ok());
    }
}

#[cfg(test)]
mod grpc_error_responses {
    use crate::ohttp::InnerRequest;

    fn make_request(content_type: Option<&str>) -> InnerRequest {
        let mut headers = vec![];
        if let Some(ct) = content_type {
            headers.push(("content-type".to_string(), ct.to_string()));
        }
        InnerRequest {
            method: "POST".to_string(),
            path: "/test".to_string(),
            authority: "example.com".to_string(),
            headers,
            body: vec![],
        }
    }

    #[test]
    fn test_is_grpc_detects_application_grpc() {
        let req = make_request(Some("application/grpc"));
        assert!(req.is_grpc(), "application/grpc should be detected as gRPC");

        let req = make_request(Some("application/grpc+proto"));
        assert!(
            req.is_grpc(),
            "application/grpc+proto should be detected as gRPC"
        );

        let req = make_request(Some("Application/GRPC"));
        assert!(req.is_grpc(), "content-type is case-insensitive");
    }

    #[test]
    fn test_is_grpc_rejects_non_grpc() {
        let req = make_request(Some("application/json"));
        assert!(!req.is_grpc(), "application/json is not gRPC");

        let req = make_request(Some("text/plain"));
        assert!(!req.is_grpc(), "text/plain is not gRPC");

        let req = make_request(None);
        assert!(!req.is_grpc(), "missing content-type is not gRPC");
    }

    #[test]
    fn test_error_response_format_depends_on_content_type() {
        // Before fix: error responses used cache_allowed (is_lwd) to decide format
        // After fix: they check the actual content-type header
        //
        // This ensures that a gRPC request to a third-party backend (not lwd)
        // gets grpc-status format, not HTTP status codes.

        let grpc_req = make_request(Some("application/grpc"));
        let http_req = make_request(Some("application/json"));

        // The actual response format is tested in integration tests, but we verify
        // that the helper correctly identifies gRPC requests
        assert!(
            grpc_req.is_grpc(),
            "gRPC request should be identified correctly"
        );
        assert!(
            !http_req.is_grpc(),
            "HTTP request should not be identified as gRPC"
        );
    }

    #[test]
    fn test_third_party_grpc_backend_format() {
        // ZIP rule 9 says "for a gRPC request" not "for light client server calls"
        // A gRPC request to a third-party backend should get grpc-status, not HTTP status.

        // Simulate a third-party gRPC backend (e.g., voting service)
        let voting_req = InnerRequest {
            method: "POST".to_string(),
            path: "/zodl.vote.v1.VoteService/GetRates".to_string(),
            authority: "api-vote.example".to_string(),
            headers: vec![("content-type".to_string(), "application/grpc".to_string())],
            body: vec![],
        };

        assert!(
            voting_req.is_grpc(),
            "Third-party gRPC backend should be detected as gRPC"
        );
    }
}

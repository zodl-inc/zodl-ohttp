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

//! Resource limits and enforcement

use anyhow::{anyhow, Result};
use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Semaphore;

// Minimal protobuf for GetBlockRange validation
#[derive(Clone, PartialEq, prost::Message)]
struct BlockId {
    #[prost(uint64, tag = "1")]
    height: u64,
    #[prost(bytes, tag = "2")]
    hash: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct BlockRange {
    #[prost(message, optional, tag = "1")]
    start: Option<BlockId>,
    #[prost(message, optional, tag = "2")]
    end: Option<BlockId>,
}

/// Error types for GetBlockRange enforcement
#[derive(Debug, Clone)]
pub enum BlockRangeError {
    Compression,
    MultiFrame,
    HeightlessBlockId,
    SpanExceeded { span: u64, max: u32 },
    Other(String),
}

impl std::fmt::Display for BlockRangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Compression => write!(f, "Compressed gRPC frames not supported"),
            Self::MultiFrame => write!(f, "Multi-frame or truncated gRPC request"),
            Self::HeightlessBlockId => {
                write!(
                    f,
                    "BlockID with height=0 not allowed (hash-only requests not supported)"
                )
            }
            Self::SpanExceeded { span, max } => {
                write!(
                    f,
                    "Block range of {} blocks exceeds maximum of {}",
                    span, max
                )
            }
            Self::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for BlockRangeError {}

/// Check gRPC compression for all lightwalletd RPCs. Gateways MUST reject compressed messages (ZIP L602-604).
/// Validates every frame in the body, not just the first one.
pub fn check_grpc_compression(body: &[u8]) -> Result<()> {
    let mut pos = 0;

    // Check every frame in the body
    while pos < body.len() {
        if body.len() - pos < 5 {
            return Err(anyhow!(
                "Malformed gRPC framing: frame too short at offset {}",
                pos
            ));
        }

        let compressed = body[pos];
        if compressed != 0 {
            return Err(anyhow!(
                "Compressed gRPC messages are not supported (compressed flag = {} at offset {})",
                compressed,
                pos
            ));
        }

        let length =
            u32::from_be_bytes([body[pos + 1], body[pos + 2], body[pos + 3], body[pos + 4]])
                as usize;

        // Move to next frame
        pos += 5 + length;

        if pos > body.len() {
            return Err(anyhow!(
                "Malformed gRPC framing: frame extends beyond body end"
            ));
        }
    }

    Ok(())
}

/// Check GetBlockRange span and reject if > max_block_range
pub fn check_block_range(path: &str, body: &[u8], max_range: u32) -> Result<(), BlockRangeError> {
    if !path.contains("GetBlockRange") {
        return Ok(());
    }

    if body.len() < 5 {
        return Err(BlockRangeError::Other("gRPC frame too short".to_string()));
    }

    let compressed = body[0];
    if compressed != 0 {
        return Err(BlockRangeError::Compression);
    }

    let length = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;

    // Require exactly one complete gRPC frame
    if body.len() != 5 + length {
        return Err(BlockRangeError::MultiFrame);
    }

    let protobuf_data = &body[5..5 + length];
    let range: BlockRange = match Message::decode(protobuf_data) {
        Ok(r) => r,
        Err(e) => {
            return Err(BlockRangeError::Other(format!(
                "Invalid BlockRange protobuf: {:?}",
                e
            )))
        }
    };

    let start_height = range.start.as_ref().map(|b| b.height).unwrap_or(0);
    let end_height = range.end.as_ref().map(|b| b.height).unwrap_or(0);

    // Reject BlockIDs with height 0 (hash-only forms not supported)
    if start_height == 0 || end_height == 0 {
        return Err(BlockRangeError::HeightlessBlockId);
    }

    // Use abs_diff to handle descending ranges correctly
    let span = start_height.abs_diff(end_height).saturating_add(1);
    if span > max_range as u64 {
        return Err(BlockRangeError::SpanExceeded {
            span,
            max: max_range,
        });
    }

    Ok(())
}

/// lightwalletd calls that can make it scan or serve a lot (MAX_INFLIGHT_LWD_HEAVY): history and
/// address queries, and GetBlockRange spans above `heavy_range` blocks (by span only, wherever
/// the range lies). Short ranges such as a wallet's normal sync, SendTransaction, GetLatestBlock,
/// GetTreeState, GetLightdInfo and the mempool are never heavy.
pub fn is_heavy_lwd_call(path: &str, body: &[u8], heavy_range: u32) -> bool {
    let method = path.rsplit('/').next().unwrap_or("");
    match method {
        "GetTransaction"
        | "GetTaddressTxids"
        | "GetTaddressTransactions"
        | "GetTaddressBalance"
        | "GetTaddressBalanceStream"
        | "GetAddressUtxos"
        | "GetAddressUtxosStream"
        | "GetSubtreeRoots"
        | "GetBlockRangeNullifiers" => true,
        "GetBlockRange" => {
            if body.len() < 5 || body[0] != 0 {
                return false;
            }
            let length = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
            let Some(data) = body.get(5..5 + length) else {
                return false;
            };
            match <BlockRange as Message>::decode(data) {
                Ok(r) => {
                    let s = r.start.as_ref().map(|b| b.height).unwrap_or(0);
                    let e = r.end.as_ref().map(|b| b.height).unwrap_or(0);
                    // `abs_diff + 1` overflows for a span of the whole u64 range (wrapping to 0
                    // in release builds, i.e. "light"). An overflow is the heaviest case: heavy.
                    match s.abs_diff(e).checked_add(1) {
                        Some(span) => span > heavy_range as u64,
                        None => true,
                    }
                }
                Err(_) => false,
            }
        }
        _ => false,
    }
}

/// Get or create per-backend semaphore
pub fn get_backend_semaphore(
    backend_label: &str,
    per_backend_limit: usize,
    semaphores: &Arc<parking_lot::RwLock<HashMap<String, Arc<Semaphore>>>>,
) -> Arc<Semaphore> {
    {
        let read = semaphores.read();
        if let Some(sem) = read.get(backend_label) {
            return sem.clone();
        }
    }

    let mut write = semaphores.write();
    write
        .entry(backend_label.to_string())
        .or_insert_with(|| Arc::new(Semaphore::new(per_backend_limit)))
        .clone()
}

/// Key for [`truncate_relay_id`]: random per process, held only in memory and never configured or
/// persisted. While the process runs, the same relay ID always maps to the same log value, so logs
/// can still be correlated for debugging; once the process exits nobody (including the gateway operator) can recompute
/// the mapping, so a relay's own `X-Request-Id` logs can never be joined with these logs afterwards.
fn relay_id_log_key() -> &'static [u8; 32] {
    static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        key
    })
}

/// The relay-supplied request ID as logged: HMAC-SHA256 under [`relay_id_log_key`], truncated to
/// 16 hex characters (8 bytes).
pub fn truncate_relay_id(relay_id: &str) -> String {
    let key = relay_id_log_key();

    // HMAC-SHA256(key, relay_id)
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..32 {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(relay_id.as_bytes());
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let result = outer.finalize();

    format!(
        "{:016x}",
        u64::from_be_bytes([
            result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
        ])
    )
}

/// Whether a body read error of `axum::body::to_bytes` is the size limit, not a broken stream.
pub fn body_too_large(error: &axum::Error) -> bool {
    std::iter::successors(std::error::Error::source(error), |s| s.source())
        .any(|s| s.is::<http_body_util::LengthLimitError>())
}

/// How long the whole request body may take to arrive (`read_body`). The handler holds an
/// in-flight permit while it reads, so a sender that trickles bytes must not be able to keep a
/// permit for longer than this. One deadline for the body, not per byte: even the 10 MiB cap fits
/// at ~2.8 Mbit/s, and a real Encapsulated Request is a few KiB (the relay forwards it at line
/// rate), so only a sender that stalls or trickles is refused.
pub const BODY_READ_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// Why `read_body` returned no body.
#[derive(Debug)]
pub enum BodyReadError {
    /// More than the limit: outer 413.
    TooLarge(axum::Error),
    /// The stream broke before the end: outer 400 `body_unreadable`.
    Unreadable(axum::Error),
    /// The end did not arrive within the deadline: outer 400 `body_unreadable`.
    TimedOut,
}

impl std::fmt::Display for BodyReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyReadError::TooLarge(e) | BodyReadError::Unreadable(e) => write!(f, "{e}"),
            BodyReadError::TimedOut => write!(
                f,
                "request body not received within {} s",
                BODY_READ_DEADLINE.as_secs()
            ),
        }
    }
}

/// The whole request body, at most `limit` bytes, complete within `deadline` (one deadline for the
/// body, not per frame). On expiry the body is dropped, which closes the request stream.
pub async fn read_body(
    body: axum::body::Body,
    limit: usize,
    deadline: std::time::Duration,
) -> Result<bytes::Bytes, BodyReadError> {
    match tokio::time::timeout(deadline, axum::body::to_bytes(body, limit)).await {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(e)) if body_too_large(&e) => Err(BodyReadError::TooLarge(e)),
        Ok(Err(e)) => Err(BodyReadError::Unreadable(e)),
        Err(_elapsed) => Err(BodyReadError::TimedOut),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_stalled_body_is_refused_at_the_deadline_not_before() {
        use futures_util::StreamExt;
        // One frame now, then nothing: the sender holds the connection open without finishing.
        let stalled = axum::body::Body::from_stream(
            futures_util::stream::once(async {
                Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"abc"))
            })
            .chain(futures_util::stream::pending()),
        );
        let read = tokio::spawn(read_body(stalled, 1024, BODY_READ_DEADLINE));
        // Just inside the deadline the read is still waiting for the rest of the body.
        tokio::time::sleep(BODY_READ_DEADLINE - std::time::Duration::from_millis(1)).await;
        assert!(!read.is_finished());
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        assert!(matches!(read.await.unwrap(), Err(BodyReadError::TimedOut)));

        // A complete body is returned whole, well before the deadline.
        let complete = axum::body::Body::from(vec![7u8; 20]);
        let bytes = read_body(complete, 1024, BODY_READ_DEADLINE).await.unwrap();
        assert_eq!(bytes.len(), 20);

        // The two other failures keep their own classes.
        let big = axum::body::Body::from(vec![0u8; 20]);
        assert!(matches!(
            read_body(big, 10, BODY_READ_DEADLINE).await,
            Err(BodyReadError::TooLarge(_))
        ));
        let broken = axum::body::Body::from_stream(futures_util::stream::iter(vec![Err::<
            bytes::Bytes,
            std::io::Error,
        >(
            std::io::Error::other("connection reset"),
        )]));
        assert!(matches!(
            read_body(broken, 10, BODY_READ_DEADLINE).await,
            Err(BodyReadError::Unreadable(_))
        ));
    }

    #[tokio::test]
    async fn only_the_size_limit_is_a_body_too_large() {
        let big = axum::body::Body::from(vec![0u8; 20]);
        let err = axum::body::to_bytes(big, 10).await.unwrap_err();
        assert!(body_too_large(&err));

        let broken = axum::body::Body::from_stream(futures_util::stream::iter(vec![Err::<
            bytes::Bytes,
            std::io::Error,
        >(
            std::io::Error::other("connection reset"),
        )]));
        let err = axum::body::to_bytes(broken, 10).await.unwrap_err();
        assert!(!body_too_large(&err));
    }

    #[test]
    fn test_check_block_range_allows_small_span() {
        let range = BlockRange {
            start: Some(BlockId {
                height: 100,
                hash: vec![],
            }),
            end: Some(BlockId {
                height: 200,
                hash: vec![],
            }),
        };
        let mut body = vec![0u8]; // uncompressed
        let proto_bytes = range.encode_to_vec();
        body.extend_from_slice(&(proto_bytes.len() as u32).to_be_bytes());
        body.extend_from_slice(&proto_bytes);

        assert!(check_block_range("/GetBlockRange", &body, 1000).is_ok());
    }

    #[test]
    fn test_check_block_range_rejects_large_span() {
        let range = BlockRange {
            start: Some(BlockId {
                height: 100,
                hash: vec![],
            }),
            end: Some(BlockId {
                height: 1200,
                hash: vec![],
            }),
        };
        let mut body = vec![0u8];
        let proto_bytes = range.encode_to_vec();
        body.extend_from_slice(&(proto_bytes.len() as u32).to_be_bytes());
        body.extend_from_slice(&proto_bytes);

        assert!(check_block_range("/GetBlockRange", &body, 1000).is_err());
    }

    #[test]
    fn test_truncate_relay_id_is_stable_within_the_process() {
        assert_eq!(
            truncate_relay_id("test-relay-id-1"),
            truncate_relay_id("test-relay-id-1")
        );
        assert_ne!(
            truncate_relay_id("test-relay-id-1"),
            truncate_relay_id("test-relay-id-2")
        );
    }

    #[test]
    fn test_check_grpc_compression_accepts_uncompressed_single_frame() {
        // Single uncompressed frame: flag=0, length=10, data=10 bytes
        let body = vec![
            0, 0, 0, 0, 10, // flag=0, length=10
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // data
        ];
        assert!(check_grpc_compression(&body).is_ok());
    }

    #[test]
    fn test_check_grpc_compression_rejects_compressed_single_frame() {
        // Single compressed frame: flag=1, length=10, data=10 bytes
        let body = vec![
            1, 0, 0, 0, 10, // flag=1 (compressed)
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        ];
        assert!(check_grpc_compression(&body).is_err());
    }

    #[test]
    fn test_check_grpc_compression_accepts_multiple_uncompressed_frames() {
        // Two uncompressed frames
        let mut body = vec![
            0, 0, 0, 0, 5, // frame 1: flag=0, length=5
            1, 2, 3, 4, 5,
        ];
        body.extend_from_slice(&[
            0, 0, 0, 0, 3, // frame 2: flag=0, length=3
            6, 7, 8,
        ]);
        assert!(check_grpc_compression(&body).is_ok());
    }

    #[test]
    fn test_check_grpc_compression_rejects_second_frame_compressed() {
        // First frame uncompressed, second frame compressed
        let mut body = vec![
            0, 0, 0, 0, 5, // frame 1: flag=0, length=5
            1, 2, 3, 4, 5,
        ];
        body.extend_from_slice(&[
            1, 0, 0, 0, 3, // frame 2: flag=1 (compressed)
            6, 7, 8,
        ]);
        let result = check_grpc_compression(&body);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Compressed gRPC messages are not supported"));
    }

    #[test]
    fn test_check_grpc_compression_rejects_short_body() {
        let body = vec![0, 0, 0]; // Too short for a frame header
        assert!(check_grpc_compression(&body).is_err());
    }

    #[test]
    fn test_check_grpc_compression_rejects_incomplete_frame() {
        // Frame header says length=100 but body only has 5 data bytes
        let body = vec![0, 0, 0, 0, 100, 1, 2, 3, 4, 5];
        assert!(check_grpc_compression(&body).is_err());
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn test_semaphore_acquisition() {
        let semaphores: Arc<parking_lot::RwLock<HashMap<String, Arc<Semaphore>>>> =
            Arc::new(parking_lot::RwLock::new(HashMap::new()));

        let sem1 = get_backend_semaphore("backend1", 2, &semaphores);
        let _permit1 = sem1.try_acquire().unwrap();
        let _permit2 = sem1.try_acquire().unwrap();
        assert!(
            sem1.try_acquire().is_err(),
            "Should fail after exhausting permits"
        );

        // Different backend should have its own semaphore
        let sem2 = get_backend_semaphore("backend2", 2, &semaphores);
        assert!(
            sem2.try_acquire().is_ok(),
            "Different backend should succeed"
        );
    }

    #[test]
    fn test_truncate_relay_id_is_keyed_not_a_plain_hash() {
        let id = truncate_relay_id("test-relay-id-abc123");
        assert_eq!(id.len(), 16, "Should be 16 hex chars");
        // Unkeyed SHA-256 of the ID, truncated the same way: anyone holding the relay's logs could
        // compute it. The logged value must differ (it depends on the per-process key).
        let plain = Sha256::digest(b"test-relay-id-abc123");
        let plain = format!(
            "{:016x}",
            u64::from_be_bytes(plain[..8].try_into().unwrap())
        );
        assert_ne!(id, plain);
    }
}

#[test]
fn test_descending_range_within_limit() {
    let range = BlockRange {
        start: Some(BlockId {
            height: 200,
            hash: vec![],
        }),
        end: Some(BlockId {
            height: 100,
            hash: vec![],
        }),
    };
    let mut body = vec![0u8]; // uncompressed
    let proto_bytes = range.encode_to_vec();
    body.extend_from_slice(&(proto_bytes.len() as u32).to_be_bytes());
    body.extend_from_slice(&proto_bytes);

    // Descending range 200..100 = 101 blocks (abs_diff + 1)
    assert!(check_block_range("/GetBlockRange", &body, 1000).is_ok());
}

#[test]
fn test_descending_range_over_limit() {
    let range = BlockRange {
        start: Some(BlockId {
            height: 1200,
            hash: vec![],
        }),
        end: Some(BlockId {
            height: 100,
            hash: vec![],
        }),
    };
    let mut body = vec![0u8];
    let proto_bytes = range.encode_to_vec();
    body.extend_from_slice(&(proto_bytes.len() as u32).to_be_bytes());
    body.extend_from_slice(&proto_bytes);

    // 1200..100 = 1101 blocks, limit 1000
    assert!(check_block_range("/GetBlockRange", &body, 1000).is_err());
}

#[test]
fn test_compressed_frame_rejected() {
    let range = BlockRange {
        start: Some(BlockId {
            height: 100,
            hash: vec![],
        }),
        end: Some(BlockId {
            height: 110,
            hash: vec![],
        }),
    };
    let mut body = vec![1u8]; // compressed flag = 1
    let proto_bytes = range.encode_to_vec();
    body.extend_from_slice(&(proto_bytes.len() as u32).to_be_bytes());
    body.extend_from_slice(&proto_bytes);

    let result = check_block_range("/GetBlockRange", &body, 1000);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Compressed"));
}

#[test]
fn test_multi_frame_rejected() {
    let range = BlockRange {
        start: Some(BlockId {
            height: 100,
            hash: vec![],
        }),
        end: Some(BlockId {
            height: 110,
            hash: vec![],
        }),
    };
    let mut body = vec![0u8];
    let proto_bytes = range.encode_to_vec();
    body.extend_from_slice(&(proto_bytes.len() as u32).to_be_bytes());
    body.extend_from_slice(&proto_bytes);
    body.extend_from_slice(b"extra data"); // Multi-frame

    let result = check_block_range("/GetBlockRange", &body, 1000);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Multi-frame"));
}

#[test]
fn test_height_zero_rejected() {
    // Any BlockID with height=0 is rejected (hash-only forms not supported)
    let range = BlockRange {
        start: Some(BlockId {
            height: 0,
            hash: vec![1, 2, 3],
        }),
        end: Some(BlockId {
            height: 100,
            hash: vec![],
        }),
    };
    let mut body = vec![0u8];
    let proto_bytes = range.encode_to_vec();
    body.extend_from_slice(&(proto_bytes.len() as u32).to_be_bytes());
    body.extend_from_slice(&proto_bytes);

    let result = check_block_range("/GetBlockRange", &body, 1000);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("height=0"));
}

#[test]
fn test_hash_only_rejected() {
    // Both heights=0 (hash-only BlockIDs) are now rejected
    let range = BlockRange {
        start: Some(BlockId {
            height: 0,
            hash: vec![1, 2, 3],
        }),
        end: Some(BlockId {
            height: 0,
            hash: vec![4, 5, 6],
        }),
    };
    let mut body = vec![0u8];
    let proto_bytes = range.encode_to_vec();
    body.extend_from_slice(&(proto_bytes.len() as u32).to_be_bytes());
    body.extend_from_slice(&proto_bytes);

    let result = check_block_range("/GetBlockRange", &body, 1000);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("height=0"));
}

#[test]
fn test_span_exactly_at_limit() {
    let range = BlockRange {
        start: Some(BlockId {
            height: 100,
            hash: vec![],
        }),
        end: Some(BlockId {
            height: 1099,
            hash: vec![],
        }),
    };
    let mut body = vec![0u8];
    let proto_bytes = range.encode_to_vec();
    body.extend_from_slice(&(proto_bytes.len() as u32).to_be_bytes());
    body.extend_from_slice(&proto_bytes);

    // 100..1099 = 1000 blocks exactly
    assert!(check_block_range("/GetBlockRange", &body, 1000).is_ok());
}

#[cfg(test)]
mod heavy_lwd_call_tests {
    use super::*;

    fn range_body(start: u64, end: u64) -> Vec<u8> {
        let r = BlockRange {
            start: Some(BlockId {
                height: start,
                ..Default::default()
            }),
            end: Some(BlockId {
                height: end,
                ..Default::default()
            }),
        };
        let msg = r.encode_to_vec();
        let mut b = vec![0u8];
        b.extend_from_slice(&(msg.len() as u32).to_be_bytes());
        b.extend_from_slice(&msg);
        b
    }

    const P: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/";

    #[test]
    fn short_and_long_ranges() {
        let path = format!("{P}GetBlockRange");
        assert!(!is_heavy_lwd_call(
            &path,
            &range_body(3_527_000, 3_527_099),
            100
        ));
        assert!(is_heavy_lwd_call(
            &path,
            &range_body(3_527_000, 3_527_100),
            100
        ));
        assert!(
            is_heavy_lwd_call(&path, &range_body(3_527_100, 3_527_000), 100),
            "descending"
        );
        assert!(
            !is_heavy_lwd_call(&path, &[0, 0, 0], 100),
            "malformed is left to check_block_range"
        );
    }

    #[test]
    fn heavy_range_overflow_is_heavy() {
        // abs_diff(0, u64::MAX) + 1 overflows: must be heavy (fail closed), not panic or wrap
        // to a span of 0.
        let path = format!("{P}GetBlockRange");
        assert!(is_heavy_lwd_call(&path, &range_body(0, u64::MAX), 100));
        assert!(is_heavy_lwd_call(&path, &range_body(u64::MAX, 0), 100));
        assert!(is_heavy_lwd_call(
            &path,
            &range_body(u64::MAX, u64::MAX - 1),
            1
        ));
        assert!(!is_heavy_lwd_call(
            &path,
            &range_body(u64::MAX, u64::MAX),
            1
        ));
    }

    #[test]
    fn methods() {
        for m in [
            "GetTransaction",
            "GetTaddressTxids",
            "GetAddressUtxosStream",
            "GetSubtreeRoots",
        ] {
            assert!(is_heavy_lwd_call(&format!("{P}{m}"), &[], 100), "{m}");
        }
        for m in [
            "SendTransaction",
            "GetLatestBlock",
            "GetTreeState",
            "GetLightdInfo",
            "GetMempoolStream",
            "GetBlock",
        ] {
            assert!(!is_heavy_lwd_call(&format!("{P}{m}"), &[], 100), "{m}");
        }
    }
}

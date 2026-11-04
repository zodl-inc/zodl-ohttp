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

//! Chunked OHTTP (draft-ietf-ohai-chunked-ohttp-08) — request decapsulation.
//!
//! Responses are sealed by `chunked_stream::encode_response_stream`.

use crate::hpke::{self, KeyState, ResponseContext};
use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Content type for chunked OHTTP requests.
pub const CONTENT_TYPE_CHUNKED_REQ: &str = "message/ohttp-chunked-req";

/// Content type for chunked OHTTP responses.
pub const CONTENT_TYPE_CHUNKED_RES: &str = "message/ohttp-chunked-res";

/// AAD for the final chunk.
const AAD_FINAL: &[u8] = b"final";

/// `key_id(1) || kem_id(2) || kdf_id(2) || aead_id(2)`
const HDR_LEN: usize = 7;

/// Decapsulate a chunked OHTTP request (RFC draft-ietf-ohai-chunked-ohttp-08 §6.1).
///
/// The request format is:
/// - Header: `key_id || kem_id || kdf_id || aead_id || enc`
/// - Non-final chunks: `varint(len) || sealed_chunk`
/// - Final chunk: `varint(0) || sealed_final_chunk` (AAD = "final")
///
/// Returns the plaintext (a Binary HTTP request, known-length per the ZIP; either framing is
/// accepted) and response context.
pub async fn decapsulate_chunked_request<R: AsyncRead + Unpin>(
    mut reader: R,
    key_state: &KeyState,
) -> Result<(Vec<u8>, ResponseContext)> {
    // Read and validate the header
    let mut header = [0u8; HDR_LEN + hpke::N_ENC];
    reader
        .read_exact(&mut header)
        .await
        .context("Failed to read chunked request header")?;

    let hdr = &header[..HDR_LEN];
    let kem_id = u16::from_be_bytes([hdr[1], hdr[2]]);
    let kdf_id = u16::from_be_bytes([hdr[3], hdr[4]]);
    let aead_id = u16::from_be_bytes([hdr[5], hdr[6]]);

    if kem_id != hpke::KEM_ID || kdf_id != hpke::KDF_ID || aead_id != hpke::AEAD_ID {
        return Err(anyhow!(
            "Unsupported HPKE suite kem=0x{:04x} kdf=0x{:04x} aead=0x{:04x}",
            kem_id,
            kdf_id,
            aead_id
        ));
    }

    let enc = &header[HDR_LEN..];
    let key_id = hdr[0];

    // Set up HPKE decapsulation context
    let (mut open_chunk, secret) = key_state.setup_chunked_decapsulation(key_id, hdr, enc)?;

    // Decrypt chunks
    let mut plaintext = Vec::new();
    loop {
        let chunk_len = read_varint(&mut reader).await?;

        if chunk_len == 0 {
            // Final chunk
            let sealed_final = read_remaining(&mut reader).await?;
            let final_chunk = open_chunk(&sealed_final, AAD_FINAL)?;
            plaintext.extend_from_slice(&final_chunk);
            break;
        }

        // Non-final chunk. The length comes from the (unauthenticated) request: bound it before
        // allocating, or one small request declaring a huge chunk aborts the process.
        if chunk_len > MAX_SEALED_CHUNK_BYTES {
            return Err(anyhow!(
                "Sealed chunk length {chunk_len} exceeds the request limit"
            ));
        }
        let mut sealed_chunk = vec![0u8; chunk_len as usize];
        reader
            .read_exact(&mut sealed_chunk)
            .await
            .context("Failed to read sealed chunk")?;

        let chunk = open_chunk(&sealed_chunk, b"")?;

        if chunk.is_empty() {
            return Err(anyhow!("Non-final chunk must not be empty"));
        }

        plaintext.extend_from_slice(&chunk);
    }

    // Create response context
    let response_ctx = ResponseContext {
        enc: enc.to_vec(),
        secret,
    };

    Ok((plaintext, response_ctx))
}

/// Largest sealed chunk a request can carry: the whole encapsulated request is at most 10 MiB
/// (`MAX_ENCAPSULATED_REQUEST_BYTES` in main.rs), so no chunk can be longer.
const MAX_SEALED_CHUNK_BYTES: u64 = 10 * 1024 * 1024;

/// Read a QUIC variable-length integer from an async reader.
async fn read_varint<R: AsyncRead + Unpin>(reader: &mut R) -> Result<u64> {
    let first = reader.read_u8().await?;
    let mut value = u64::from(first & 0x3f);
    for _ in 1..(1usize << (first >> 6)) {
        value = (value << 8) | u64::from(reader.read_u8().await?);
    }
    Ok(value)
}

/// Read all remaining bytes from an async reader.
async fn read_remaining<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).await?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_read_varint() {
        for (bytes, want) in [
            (vec![0x00u8], 0u64),
            (vec![0x3f], 63),
            (vec![0x40, 0x40], 64),
            (vec![0x7f, 0xff], 16383),
            (vec![0x80, 0x00, 0x40, 0x00], 16384),
        ] {
            let mut cursor = std::io::Cursor::new(bytes);
            assert_eq!(read_varint(&mut cursor).await.unwrap(), want);
        }
    }
}

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

//! Oblivious HTTP (RFC 9458) client for the ZODL gateway.
//!
//! A request is encoded as Binary HTTP (RFC 9292), sealed with HPKE to the gateway's key and
//! posted to an oblivious relay. The relay sees the client's address and an opaque blob; the
//! gateway opens it, forwards it to the backend its `:authority` names, and seals the answer
//! back, seeing the request but never the address.
//!
//! Two layers:
//!
//! - The encapsulation, with no I/O: [`KeyConfig::select`] picks the gateway's key out of
//!   its `application/ohttp-keys` document (or [`open_signed_config`] out of its signed
//!   envelope first), [`encode_request`] frames a [`Request`], [`encapsulate_chunked_request`]
//!   seals it, and [`ChunkedResponseDecoder`] (or [`ChunkedResponseOpener::open_response`])
//!   turns the relay's answer back into a [`Response`].
//! - `Client` (feature `client`): one relay and one gateway, the key configuration
//!   fetched on first use and again after a key rotation, and one call per request.
//!
//! Underneath both is a sans-IO core for clients that do their own I/O (the Android and iOS
//! SDKs over Tor-capable transports, Slipstream over hyper): [`KeyConfig::select_with`],
//! [`verify_signed_config`], [`encode_bhttp_request`], [`encapsulate_chunked_request`],
//! [`classify_outer_response`], [`ChunkedResponseDecoder`] and the byte-level Binary HTTP
//! codec, each taking the options in which the clients differ. A [`ClientProfile`] bundles
//! those options as one client passes them. `client/INTEGRATION.md` describes how to use
//! either layer.
//!
//! The gateway speaks chunked OHTTP (draft-ietf-ohai-chunked-ohttp-08) only, and so does this
//! crate: a request is posted as `message/ohttp-chunked-req` ([`encapsulate_chunked_request`])
//! and the `message/ohttp-chunked-res` answer is opened as it streams
//! ([`ChunkedResponseDecoder`], [`Client::send_stream`]). The RFC 9458 single-shot framing
//! (`message/ohttp-req` / `message/ohttp-res`) is not spoken by the gateway and is not
//! implemented here.
//!
//! The one suite spoken is the gateway's: KEM DHKEM(X25519, HKDF-SHA256), KDF HKDF-SHA256,
//! AEAD AES-128-GCM.
//!
//! ```no_run
//! # #[cfg(feature = "client")]
//! # async fn demo() -> Result<(), zodl_ohttp_client::Error> {
//! use std::time::Duration;
//! use zodl_ohttp_client::{Client, KeyConfigSource, Request};
//!
//! let client = Client::new(
//!     "https://relay.example/relay",
//!     KeyConfigSource::Plain {
//!         url: "https://relay.example/ohttp-configs".into(),
//!     },
//! );
//! let response = client
//!     .send(
//!         &Request::new("GET", "backend.example", "/v1/info"),
//!         Duration::from_secs(30),
//!     )
//!     .await?;
//! println!("{} {:?}", response.status, response.header("content-type"));
//! # Ok(()) }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod bhttp_codec;
pub mod chunked;
#[cfg(feature = "client")]
mod client;
mod dns;
pub mod encapsulation;
pub mod freshness;
mod message;
mod outer;
mod profile;
mod relays;
mod signed;
mod trace;

pub use bhttp_codec::{
    decode_bhttp_response, encode_bhttp_request, pack_fields, unpack_fields, BhttpRequest,
    BhttpResponse, DecodeOptions, EncodeOptions, Field, StatusRange,
};
pub use chunked::{
    collect_response, encapsulate_chunked_request, encapsulate_chunked_request_with_rng,
    ChunkedResponseDecoder, ChunkedResponseOpener, ResponseEvent, CONTENT_TYPE_CHUNKED_REQ,
    CONTENT_TYPE_CHUNKED_RES,
};
#[cfg(feature = "client")]
pub use client::{Client, KeyConfigSource, ResponseStream};
pub use dns::{doh_query_url, envelope_from_doh_json, key_config_dns_name, DOH_RESOLVERS};
/// The key type of [`open_signed_config`]'s signer, so callers need not pin `ed25519-dalek`.
pub use ed25519_dalek::VerifyingKey;
pub use encapsulation::{EntryLayout, KeyConfig, KeySelection, UnsupportedKem, KEY_BYTES};
pub use message::{decode_response, encode_request, Request, Response};
pub use outer::{
    check_size, classify_outer_response, retry_after_delay, signed_config_url, unsigned_cache_secs,
    CachePolicy, Limits, OuterHeaders, OuterOutcome, OuterPolicy, OuterResponse, RelayBackoff,
    SignedConfigUrlRule, SizeGuard, SuccessStatus, GATEWAY_MAX_ENCAPSULATED_REQUEST_BYTES,
    GATEWAY_MAX_SEALED_RESPONSE_BYTES, GATEWAY_MAX_UPSTREAM_RESPONSE_BYTES, MAX_KEY_CONFIG_BYTES,
    MAX_RETRY_AFTER, UNSIGNED_DEFAULT_CACHE_SECS,
};
pub use profile::ClientProfile;
pub use relays::{relay_for, GATEWAY_HOST_MAINNET, GATEWAY_HOST_TESTNET};
pub use signed::{
    open_signed_config, verify_signed_config, verify_signed_config_with, Base64Decoding,
    DuplicateKeys, Network, NetworkRule, SignatureCheck, SignedConfigPolicy, SignedKeys,
    UnknownFields, CLOCK_SKEW_SECS, MAINNET_SIGNING_KEY_HEX, TESTNET_SIGNING_KEY_HEX,
};
pub use trace::{ClientTrace, PrefixSanitization, TraceIdFormat, TracePolicy};

/// The media type of a sealed request, which the relay is posted.
pub const REQUEST_MEDIA_TYPE: &str = "message/ohttp-chunked-req";
/// The media type of a sealed response, which the relay answers.
pub const RESPONSE_MEDIA_TYPE: &str = "message/ohttp-chunked-res";

/// What can go wrong. (`Refused`, `MediaType` and `TooLarge` are raised by `Client` and by the
/// sans-IO checks alike.)
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The relay or the key-configuration URL could not be reached, the exchange broke off or
    /// timed out, or the key-configuration URL answered an error status.
    #[cfg(feature = "client")]
    #[error("HTTP: {0}")]
    Http(#[from] reqwest::Error),
    /// The relay or the gateway refused the sealed request (an HTTP error status on the outer
    /// response). The backend's own answers, errors included, are [`Response`]s.
    #[error("the relay or the gateway answered {status}")]
    Refused {
        /// The outer HTTP status.
        status: u16,
    },
    /// The relay answered something other than a sealed response.
    #[error("the relay answered {0:?}, not {RESPONSE_MEDIA_TYPE}")]
    MediaType(String),
    /// A key configuration or a sealed response was larger than `max` bytes.
    #[error("an answer larger than {max} bytes")]
    TooLarge {
        /// The limit.
        max: usize,
    },
    /// The gateway's key configuration is malformed, offers no suite spoken here or no usable
    /// key, or its signed envelope does not check out.
    #[error("key configuration: {0}")]
    KeyConfig(String),
    /// HPKE failed to seal (a malformed gateway key).
    #[error("sealing failed: {0}")]
    Seal(String),
    /// A chunk of the sealed response, final or not, does not open under the request's secret.
    #[error("the gateway's answer does not open")]
    Open,
    /// The sealed response ended before its final chunk: the exchange broke off, which is a
    /// transport failure rather than a malformed answer.
    #[error("the gateway's answer ended before its final chunk")]
    Truncated,
    /// Not sent: the relay asked for a pause (a `Retry-After` on an outer `429`) that has not
    /// passed yet, see [`RelayBackoff`].
    #[error("the relay asked to wait {wait:?} more before the next request")]
    Backoff {
        /// What is left of the pause.
        wait: std::time::Duration,
    },
    /// The decoded message is a request, or a response without a final status.
    #[error("the gateway's answer is not a response")]
    NotAResponse,
    /// A Binary HTTP message is truncated, has a framing or status this crate does not read,
    /// or a field too long to frame.
    #[error("binary HTTP: {0}")]
    BhttpFormat(String),
}

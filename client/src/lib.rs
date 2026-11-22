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
//! Beside them, with no I/O of its own: [`ThirdPartyHosts`], the third-party hosts a gateway
//! carries as the gateway publishes them (which hosts may be sent through it, which servers
//! of a service to use), fetched through either layer.
//!
//! Underneath both is a sans-IO core for clients that do their own I/O (the Android and iOS
//! SDKs over Tor-capable transports, Slipstream over hyper): [`KeyConfig::select_with`],
//! [`verify_signed_config`], [`encode_bhttp_request`], [`encapsulate_chunked_request`],
//! [`classify_outer_response`], [`ChunkedResponseDecoder`] and the byte-level Binary HTTP
//! codec, each taking the options in which the clients differ. A [`ClientProfile`] bundles
//! those options as one client passes them. `client/INTEGRATION.md` describes how to use
//! either layer.
//!
//! The crate carries no endpoint, host name or key. The application passes the configuration
//! of each network in at runtime: an [`OhttpConfig`] (gateway host, relay URL, keys DNS name,
//! signing key) per network, both held by an [`OhttpNetworks`]. A network without one has
//! OHTTP off.
//!
//! A network may list several relays. Each request goes to one of them, chosen at random by
//! share ([`OhttpConfig::choose_relay`]): equal shares, unless a relay weights block, signed
//! with a key of its own ([`OhttpConfig::with_relay_weights_key`]) and carried in the gateway's
//! signed key-configuration envelope, sets others for its validity (at most 30 days). The block
//! names no relay (one share per position of the application's list, and the list's
//! fingerprint, [`relay_set`]); a block that does not check out is ignored and never affects
//! the key configuration. `docs/relay-weights.md` describes the format.
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
//! # async fn demo(signing_pubkey_hex: &str) -> Result<(), Box<dyn std::error::Error>> {
//! use std::time::Duration;
//! use zodl_ohttp_client::{
//!     Client, Network, OhttpConfig, OhttpConfigParams, OhttpNetworks, Request,
//!     SignedConfigUrlRule,
//! };
//!
//! // The application's configuration of the network (placeholder values).
//! let config = OhttpConfig::new(OhttpConfigParams {
//!     gateway_host: "ohttp-gateway.example",
//!     relay_url: "https://relay.example/relay",
//!     keys_dns_name: "ohttp-keys.example",
//!     signing_pubkey: signing_pubkey_hex,
//! })?;
//! let networks = OhttpNetworks::new(Some(config), None)?;
//! // Seals to the key of the gateway's signed envelope, fetched through the relay
//! // (`.../relay` becomes `.../ohttp-configs/signed`) and used only once it checks out
//! // against the configured signing key.
//! let client = Client::for_network(
//!     &networks,
//!     Network::Mainnet,
//!     SignedConfigUrlRule::ReplaceRelaySuffix,
//! )?;
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
mod config;
mod dns;
pub mod encapsulation;
pub mod freshness;
#[cfg(feature = "client")]
mod http_error;
mod message;
mod outer;
mod profile;
mod relays;
mod signed;
mod third_party_hosts;
mod trace;
mod weights;

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
pub use client::{Client, KeyConfigSource, ResponseStream, DEFAULT_LIST_CONNECT_TIMEOUT};
pub use config::{
    canonical_relay_url, ConfigError, ConfigField, OhttpConfig, OhttpConfigParams, OhttpNetworks,
    RelayWeightsKeyError,
};
pub use dns::{doh_query_url, envelope_from_doh_json, DOH_RESOLVERS};
/// The key type of [`open_signed_config`]'s signer, so callers need not pin `ed25519-dalek`.
pub use ed25519_dalek::VerifyingKey;
pub use encapsulation::{EntryLayout, KeyConfig, KeySelection, UnsupportedKem, KEY_BYTES};
#[cfg(feature = "client")]
pub use http_error::{HttpError, HttpErrorKind};
pub use message::{decode_response, encode_request, Request, Response};
pub use outer::{
    check_size, classify_outer_response, retry_after_delay, signed_config_url, unsigned_cache_secs,
    CachePolicy, Limits, OuterHeaders, OuterOutcome, OuterPolicy, OuterResponse, RelayBackoff,
    SignedConfigUrlRule, SizeGuard, SuccessStatus, GATEWAY_MAX_ENCAPSULATED_REQUEST_BYTES,
    GATEWAY_MAX_SEALED_RESPONSE_BYTES, GATEWAY_MAX_UPSTREAM_RESPONSE_BYTES, KEY_CONFIG_MEDIA_TYPE,
    MAX_KEY_CONFIG_BYTES, MAX_MEDIA_TYPE_CHARS, MAX_REFUSED_DETAIL_CHARS, MAX_RETRY_AFTER,
    RELAY_ACCEPT_LANGUAGE, RELAY_USER_AGENT, SIGNED_CONFIG_MEDIA_TYPE, UNSIGNED_DEFAULT_CACHE_SECS,
};
pub use profile::ClientProfile;
pub use relays::{
    relay_status_answered, relay_status_fails_over, Relay, RelayProbe, RelaySelector,
    MASKED_FAILURES_TO_HOLD, MASKED_FAILURE_WINDOW, MAX_HELD_RELAYS, MAX_RELAYS,
    MAX_RELAY_FAILOVER_HOLD, RELAY_FAILOVER_HOLD, RELAY_PROBE_WINDOW,
};
pub use signed::{
    open_signed_config, verify_signed_config, verify_signed_config_with, Base64Decoding,
    DuplicateKeys, Network, NetworkRule, SignatureCheck, SignedConfigPolicy, SignedKeys,
    UnknownFields, CLOCK_SKEW_SECS,
};
pub use third_party_hosts::{
    is_unknown_authority, read_third_party_hosts, third_party_hosts_request, CarriedHost,
    CarriedServer, CarriedServers, HostList, HostListAnswer, HostListRefresh, HostListScope,
    NoHostList, RefreshOutcome, ThirdPartyHosts, FIRST_REFRESH_BACKOFF, MAX_HOST_LIST_AGE,
    MAX_REFRESH_BACKOFF, MAX_THIRD_PARTY_HOSTS_BYTES, MIN_HOST_LIST_AGE, REFRESH_ABANDONED_AFTER,
    REFUSAL_REFRESH_MIN_AGE, THIRD_PARTY_HOSTS_PATH, THIRD_PARTY_HOSTS_VERSION,
    UNKNOWN_AUTHORITY_REFRESH_INTERVAL,
};
pub use trace::{ClientTrace, PrefixSanitization, TraceIdFormat, TracePolicy};
pub use weights::{
    relay_set, RelayWeights, RelayWeightsStatus, MAX_RELAY_WEIGHTS_BLOCK_BYTES,
    MAX_RELAY_WEIGHTS_VALIDITY_SECS, RELAY_WEIGHTS_DOMAIN, RELAY_WEIGHTS_FIELD,
    RELAY_WEIGHTS_TOTAL,
};

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
    /// timed out, or the key-configuration URL answered an error status or a redirect. Shows
    /// only the kind of failure ([`HttpError`]): never a URL, host, address, port or the HTTP
    /// stack's own message.
    #[cfg(feature = "client")]
    #[error("HTTP: {0}")]
    Http(HttpError),
    /// The relay or the gateway refused the sealed request (an HTTP error status on the outer
    /// response). The backend's own answers, errors included, are [`Response`]s.
    #[error("the relay or the gateway answered {status}")]
    Refused {
        /// The outer HTTP status.
        status: u16,
    },
    /// A `Client` constructor refused its arguments or could not set itself up: the `what`
    /// (`relay URL`, `key-configuration URL`, `key configuration source`, or `TLS backend` when
    /// the HTTP stack cannot be initialized) breaks the `rule`. Names neither value.
    #[error("client setup: the {what} {rule}")]
    Setup {
        /// What was refused.
        what: &'static str,
        /// The rule it breaks.
        rule: &'static str,
    },
    /// The relay answered something other than a sealed response. The media type of the
    /// `Content-Type` received: a registered top-level type and a common subtype (else `*`),
    /// lower case, parameters dropped; or [`NOT_A_MEDIA_TYPE`]. No free text of the relay's.
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
    /// The gateway's answer to a host list request is no list ([`NoHostList`]): keep the list
    /// held. Shows a status or a fixed text only.
    #[error("no third-party host list: {0}")]
    NoHostList(NoHostList),
}

/// A transport error of `Client`, reduced to its kind ([`HttpError`]).
#[cfg(feature = "client")]
impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        Error::Http(HttpError::from_reqwest(error))
    }
}

/// What an error shows of a peer's `Content-Type`: a registered top-level type and, when it is
/// one of a few common ones, its subtype (`text/html`, `message/ohttp-res`, ...), else `*`
/// (`text/*`); in lower case, parameters dropped. A value that is no media type of a registered
/// top-level type is [`NOT_A_MEDIA_TYPE`]. So no free text of the peer's (a URL, a host, a
/// parameter) can reach an error or a log line through it.
pub(crate) fn shown_media_type(value: &str) -> String {
    const TYPES: [&str; 10] = [
        "application",
        "audio",
        "font",
        "haptics",
        "image",
        "message",
        "model",
        "multipart",
        "text",
        "video",
    ];
    const SUBTYPES: [&str; 13] = [
        "html",
        "plain",
        "json",
        "xml",
        "octet-stream",
        "problem+json",
        "grpc",
        "ohttp-keys",
        "ohttp-req",
        "ohttp-res",
        "ohttp-chunked-req",
        "ohttp-chunked-res",
        "http",
    ];
    let essence = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    // RFC 9110 `token "/" token` first: anything else is no media type at all.
    let token = |part: &str| {
        !part.is_empty()
            && part.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(
                        b,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    )
            })
    };
    let Some((kind, sub)) = essence
        .split_once('/')
        .filter(|(kind, sub)| token(kind) && token(sub))
    else {
        return NOT_A_MEDIA_TYPE.to_owned();
    };
    let Some(kind) = TYPES.iter().find(|&&t| t == kind) else {
        return NOT_A_MEDIA_TYPE.to_owned();
    };
    match SUBTYPES.iter().find(|&&t| t == sub) {
        Some(sub) => format!("{kind}/{sub}"),
        None => format!("{kind}/*"),
    }
}

/// What an error shows for a `Content-Type` that is no media type (absent, malformed, or
/// carrying anything else).
pub const NOT_A_MEDIA_TYPE: &str = "<not a media type>";

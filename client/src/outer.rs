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

//! The outer HTTP exchange with the relay, without the I/O: what to send, what an answer
//! means, and how large it may be.
//!
//! Everything here except the [`RelayBackoff`] table is a pure function of its arguments, so a
//! client that does its own I/O (`HttpURLConnection` or a Tor stream on Android, `URLSession`
//! on iOS, hyper in Slipstream) makes the same decisions as any other given the same policy.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::{Error, RESPONSE_MEDIA_TYPE};

/// The largest encapsulated request the gateway reads; it answers 413 to a larger one.
pub const GATEWAY_MAX_ENCAPSULATED_REQUEST_BYTES: usize = 10 * 1024 * 1024;
/// The largest backend body a client accepts from the gateway, 256 MiB. A gateway relays bodies
/// up to its `MAX_UPSTREAM_RESPONSE_BYTES` (which must not exceed this) and answers a larger
/// upstream body with an error instead.
pub const GATEWAY_MAX_UPSTREAM_RESPONSE_BYTES: usize = 268_435_456;
/// The room the sealed form of a maximal answer takes beyond its body: the header fields
/// (the gateway passes an allowlist of them), the Binary HTTP framing, the per-chunk AEAD tags
/// and length prefixes. For a 256 MiB response in 16 KiB chunks, this is about 320 KiB.
const SEALED_RESPONSE_OVERHEAD_BYTES: usize = 1024 * 1024;
/// The largest sealed response a client reads, for every client: the gateway's largest body
/// plus 1 MiB for the chunking overhead. The cap applies to the sealed bytes, before
/// decryption; enforce it as they arrive with [`SizeGuard`].
pub const GATEWAY_MAX_SEALED_RESPONSE_BYTES: usize =
    GATEWAY_MAX_UPSTREAM_RESPONSE_BYTES + SEALED_RESPONSE_OVERHEAD_BYTES;

/// The most bytes of a key-configuration document or signed envelope read: a few keys take a
/// few hundred bytes, an envelope under 10 KiB.
pub const MAX_KEY_CONFIG_BYTES: usize = 64 * 1024;

/// Which outer statuses mean the relay forwarded a sealed answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuccessStatus {
    /// Exactly 200.
    Exactly200,
    /// Any 2xx.
    Any2xx,
}

impl SuccessStatus {
    /// Whether `status` is a success under this rule; also the test a key-configuration
    /// fetch's status is held to.
    pub fn accepts(self, status: u16) -> bool {
        match self {
            SuccessStatus::Exactly200 => status == 200,
            SuccessStatus::Any2xx => (200..300).contains(&status),
        }
    }
}

/// How an outer answer is classified by [`classify_outer_response`]. Where the three wallet
/// clients differed when this was written, each has a preset ([`crate::ClientProfile`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OuterPolicy {
    /// Which statuses are success.
    pub success: SuccessStatus,
    /// How many bytes of a non-success answer's body are quoted in
    /// [`OuterOutcome::Refused`]; `None` for all of it. (An outer `400` or `422` is retried
    /// whatever its body says: see [`classify_outer_response`].)
    pub body_window: Option<usize>,
    /// Whether a success answer must be labelled `message/ohttp-chunked-res`.
    pub require_response_media_type: bool,
}

impl OuterPolicy {
    /// The preset of this library's [`crate::ClientProfile::LIBRARY`]: 200 only, no media type
    /// check. (The networked `Client` applies its own checks: any 2xx, and the
    /// `message/ohttp-chunked-res` label is required.)
    pub const LIBRARY: OuterPolicy = OuterPolicy {
        success: SuccessStatus::Exactly200,
        body_window: None,
        require_response_media_type: false,
    };
    /// The Android SDK (`OhttpTransport.roundTrip`): 200 only, the first 200 bytes of an
    /// error body quoted.
    pub const ANDROID: OuterPolicy = OuterPolicy {
        success: SuccessStatus::Exactly200,
        body_window: Some(200),
        require_response_media_type: false,
    };
    /// The Swift SDK (`OHTTPTransport.roundTrip`): 200 only, the first 200 bytes of an error
    /// body quoted.
    pub const IOS: OuterPolicy = OuterPolicy {
        success: SuccessStatus::Exactly200,
        body_window: Some(200),
        require_response_media_type: false,
    };
    /// Slipstream (`OhttpClient::round_trip`): 200 only, the whole error body quoted.
    pub const SLIPSTREAM: OuterPolicy = OuterPolicy {
        success: SuccessStatus::Exactly200,
        body_window: None,
        require_response_media_type: false,
    };
}

/// An outer answer, as far as [`classify_outer_response`] needs it.
#[derive(Clone, Copy, Debug)]
pub struct OuterResponse<'a> {
    /// The outer HTTP status.
    pub status: u16,
    /// The `Content-Type` header, if any.
    pub content_type: Option<&'a str>,
    /// The body of a non-success answer, the first [`OuterPolicy::body_window`] bytes of it at
    /// least. [`classify_outer_response`] does not read it for a success answer, so a caller
    /// that classifies first need not buffer one: a sealed answer is fed to a
    /// [`crate::ChunkedResponseDecoder`] as it streams.
    pub body: &'a [u8],
}

/// What an outer answer means.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OuterOutcome {
    /// The body is a sealed response: open it with the request's
    /// [`crate::ChunkedResponseOpener`] (or its [`crate::ChunkedResponseDecoder`]).
    Sealed,
    /// The gateway does not know the key configuration: fetch it again (dropping the kept
    /// one), encapsulate the request afresh, and post once more. Never returned on a retry.
    RefetchKeyConfig,
    /// The relay or the gateway refused the request.
    Refused {
        /// The outer status.
        status: u16,
        /// The body, up to the policy's window, invalid UTF-8 replaced.
        detail: String,
    },
    /// A success status, but not labelled `message/ohttp-chunked-res`.
    WrongMediaType {
        /// The `Content-Type` received.
        content_type: String,
    },
}

/// What the outer answer `response` means, under `policy`. `attempt` is 0 for the first post
/// of a request and 1 for the post after a [`OuterOutcome::RefetchKeyConfig`]; a request is
/// retried once at most.
///
/// An outer `400` (the gateway could not open the request) or `422` (key configuration
/// problem) on the first attempt is [`OuterOutcome::RefetchKeyConfig`] for every client,
/// whatever the body says; on the second it is refused for good (ZIP, "Outer response
/// contract and decapsulation failure handling"). A `409` is never a refetch: the sealing is
/// fresh on every attempt, so a repeat of the same ciphertext cannot happen here. `413`,
/// `401`, `426`, `500`, `502`, `503` are refused, and the wrapper surfaces them as transient.
pub fn classify_outer_response(
    policy: &OuterPolicy,
    response: &OuterResponse<'_>,
    attempt: u32,
) -> OuterOutcome {
    let window = policy.body_window.map_or(response.body, |n| {
        &response.body[..n.min(response.body.len())]
    });
    if attempt == 0 && matches!(response.status, 400 | 422) {
        return OuterOutcome::RefetchKeyConfig;
    }
    if !policy.success.accepts(response.status) {
        return OuterOutcome::Refused {
            status: response.status,
            detail: String::from_utf8_lossy(window).into_owned(),
        };
    }
    if policy.require_response_media_type {
        let content_type = response.content_type.unwrap_or_default();
        let essence = content_type.split(';').next().unwrap_or_default().trim();
        if !essence.eq_ignore_ascii_case(RESPONSE_MEDIA_TYPE) {
            return OuterOutcome::WrongMediaType {
                content_type: content_type.to_string(),
            };
        }
    }
    OuterOutcome::Sealed
}

/// The `User-Agent` every [`OuterHeaders`] preset sends to the relay, on the post and on the
/// key-configuration fetch. The relay sees the client address, so one fixed value keeps it from
/// telling the clients apart by their HTTP stack or application. It is part of this crate's
/// public surface: changing it is a breaking change.
pub const RELAY_USER_AGENT: &str = "zodl-ohttp/1";

/// The headers the client sets on its own requests to the relay (those the HTTP stack adds
/// by itself, `Host` and `Content-Length`, are not listed). Every preset sets the fixed
/// [`RELAY_USER_AGENT`], so the stack's default `User-Agent` is never sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OuterHeaders {
    /// `Accept: message/ohttp-chunked-res` on the post.
    pub post_accept: bool,
    /// `Accept-Encoding: identity` on the post.
    pub post_accept_encoding_identity: bool,
    /// A fixed `User-Agent` on every request ([`RELAY_USER_AGENT`] in every preset).
    pub user_agent: Option<&'static str>,
    /// The `Accept` of the key-configuration fetch, if set.
    pub key_fetch_accept: Option<&'static str>,
    /// `Accept-Encoding: identity` on the key-configuration fetch.
    pub key_fetch_accept_encoding_identity: bool,
    /// Whether the key-configuration fetch carries `X-Client-Trace-Id` as the post does.
    pub trace_on_key_fetch: bool,
}

impl OuterHeaders {
    /// This library's `Client`: the post's content type, `Accept` and identity encoding.
    pub const LIBRARY: OuterHeaders = OuterHeaders {
        post_accept: true,
        post_accept_encoding_identity: true,
        user_agent: Some(RELAY_USER_AGENT),
        key_fetch_accept: None,
        key_fetch_accept_encoding_identity: false,
        trace_on_key_fetch: false,
    };
    /// The Android SDK: `Accept` and identity encoding on the post, `Accept:
    /// application/json` on the fetch.
    pub const ANDROID: OuterHeaders = OuterHeaders {
        post_accept: true,
        post_accept_encoding_identity: true,
        user_agent: Some(RELAY_USER_AGENT),
        key_fetch_accept: Some("application/json"),
        key_fetch_accept_encoding_identity: false,
        trace_on_key_fetch: false,
    };
    /// The Swift SDK: as Android, but the fetch asks for `application/ohttp-keys` (though it
    /// gets JSON) and carries the trace id.
    pub const IOS: OuterHeaders = OuterHeaders {
        post_accept: true,
        post_accept_encoding_identity: true,
        user_agent: Some(RELAY_USER_AGENT),
        key_fetch_accept: Some("application/ohttp-keys"),
        key_fetch_accept_encoding_identity: false,
        trace_on_key_fetch: true,
    };
    /// Slipstream: identity encoding on the fetch too.
    pub const SLIPSTREAM: OuterHeaders = OuterHeaders {
        post_accept: true,
        post_accept_encoding_identity: true,
        user_agent: Some(RELAY_USER_AGENT),
        key_fetch_accept: Some("application/json"),
        key_fetch_accept_encoding_identity: true,
        trace_on_key_fetch: false,
    };

    /// The headers of the post of a sealed request; `trace` is the `X-Client-Trace-Id` value,
    /// if one is being sent.
    pub fn relay_post(&self, trace: Option<&str>) -> Vec<(&'static str, String)> {
        let mut headers = vec![("Content-Type", crate::REQUEST_MEDIA_TYPE.to_string())];
        if self.post_accept {
            headers.push(("Accept", RESPONSE_MEDIA_TYPE.to_string()));
        }
        if self.post_accept_encoding_identity {
            headers.push(("Accept-Encoding", "identity".to_string()));
        }
        if let Some(agent) = self.user_agent {
            headers.push(("User-Agent", agent.to_string()));
        }
        if let Some(trace) = trace {
            headers.push(("X-Client-Trace-Id", trace.to_string()));
        }
        headers
    }

    /// The headers of the fetch of the signed key configuration.
    pub fn key_fetch(&self, trace: Option<&str>) -> Vec<(&'static str, String)> {
        let mut headers = Vec::new();
        if let Some(accept) = self.key_fetch_accept {
            headers.push(("Accept", accept.to_string()));
        }
        if self.key_fetch_accept_encoding_identity {
            headers.push(("Accept-Encoding", "identity".to_string()));
        }
        if let Some(agent) = self.user_agent {
            headers.push(("User-Agent", agent.to_string()));
        }
        if let (true, Some(trace)) = (self.trace_on_key_fetch, trace) {
            headers.push(("X-Client-Trace-Id", trace.to_string()));
        }
        headers
    }
}

/// Byte limits on what is read from the relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The most bytes of a sealed response read, if capped.
    pub max_sealed_response_bytes: Option<usize>,
    /// The most bytes of a key-configuration document or envelope read, if capped.
    pub max_key_config_bytes: Option<usize>,
    /// The most bytes of a sealed request sent, if capped.
    pub max_sealed_request_bytes: Option<usize>,
}

impl Limits {
    /// Nothing capped.
    pub const UNLIMITED: Limits = Limits {
        max_sealed_response_bytes: None,
        max_key_config_bytes: None,
        max_sealed_request_bytes: None,
    };
    /// This library's `Client`: the limits every preset shares ([`Limits::WALLET`]).
    pub const LIBRARY: Limits = Limits::WALLET;
    /// The Android SDK: as [`Limits::WALLET`] (it was 64 MiB for a response and for a
    /// key-configuration fetch, and had no request cap).
    pub const ANDROID: Limits = Limits::WALLET;
    /// The Swift SDK: as [`Limits::WALLET`] (nothing was capped before this crate).
    pub const IOS: Limits = Limits::WALLET;
    /// Slipstream: as [`Limits::WALLET`] (nothing was capped before this crate).
    pub const SLIPSTREAM: Limits = Limits::WALLET;

    /// The limits of every preset: a sealed response of [`GATEWAY_MAX_SEALED_RESPONSE_BYTES`],
    /// a key-configuration document or envelope of [`MAX_KEY_CONFIG_BYTES`] (64 KiB, enforced
    /// on the bytes as they are read and again by [`crate::verify_signed_config`] before it
    /// parses anything), and a sealed request of [`GATEWAY_MAX_ENCAPSULATED_REQUEST_BYTES`]
    /// (10 MiB, which the gateway and the relay answer with 413 above; a client checks
    /// the sealed body against it with [`check_size`] before anything is sent).
    pub const WALLET: Limits = Limits {
        max_sealed_response_bytes: Some(GATEWAY_MAX_SEALED_RESPONSE_BYTES),
        max_key_config_bytes: Some(MAX_KEY_CONFIG_BYTES),
        max_sealed_request_bytes: Some(GATEWAY_MAX_ENCAPSULATED_REQUEST_BYTES),
    };

    /// A guard for the sealed response being read: feed it every chunk and stop reading at its
    /// first error, rather than buffering what will be refused.
    pub fn response_guard(&self) -> SizeGuard {
        SizeGuard::new(self.max_sealed_response_bytes)
    }

    /// A guard for the key-configuration document or envelope being read.
    pub fn key_config_guard(&self) -> SizeGuard {
        SizeGuard::new(self.max_key_config_bytes)
    }
}

/// A running count of the bytes read against a limit, for a body read in chunks: [`push`]
/// fails once the total passes the limit, as [`check_size`] does for a whole body.
///
/// [`push`]: SizeGuard::push
#[derive(Clone, Copy, Debug)]
pub struct SizeGuard {
    max: Option<usize>,
    seen: usize,
}

impl SizeGuard {
    /// A guard that lets `max` bytes through, or any number for `None`.
    pub fn new(max: Option<usize>) -> Self {
        SizeGuard { max, seen: 0 }
    }

    /// Counts `chunk_len` more bytes. Once it has failed every later call fails too, and
    /// nothing more should be read.
    pub fn push(&mut self, chunk_len: usize) -> Result<(), Error> {
        self.seen = self.seen.saturating_add(chunk_len);
        check_size(self.seen, self.max)
    }

    /// Checks a length the peer announced (`Content-Length`) before reading any of the body:
    /// an error if it alone is more than the limit allows, counting nothing.
    pub fn check_declared(&self, declared: u64) -> Result<(), Error> {
        match self.max {
            Some(max) if declared > max as u64 => Err(Error::TooLarge { max }),
            _ => Ok(()),
        }
    }

    /// The bytes counted so far.
    pub fn seen(&self) -> usize {
        self.seen
    }
}

/// `len` bytes against `max`: an error once it is more.
pub fn check_size(len: usize, max: Option<usize>) -> Result<(), Error> {
    match max {
        Some(max) if len > max => Err(Error::TooLarge { max }),
        _ => Ok(()),
    }
}

/// The longest `Retry-After` honoured: a relay asking for more is capped at this.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(120);

/// The delay of an outer `429`'s `Retry-After` header, in the delay-seconds form, capped at
/// [`MAX_RETRY_AFTER`]. The HTTP-date form is not supported and gives `None`.
pub fn retry_after_delay(value: Option<&str>) -> Option<Duration> {
    let secs: u64 = value?.trim().parse().ok()?;
    Some(Duration::from_secs(secs).min(MAX_RETRY_AFTER))
}

/// The pause each relay asked for with `Retry-After`, kept per relay URL so that every request
/// through that relay waits for it, not only the one that was answered `429`.
///
/// [`note`](Self::note) records a pause when a `429` arrives; [`remaining`](Self::remaining)
/// is checked before every post, and a request is not sent while a pause is running.
/// [`RelayBackoff::global`] is the one table a process shares.
#[derive(Debug, Default)]
pub struct RelayBackoff {
    not_before: Mutex<HashMap<String, Instant>>,
}

impl RelayBackoff {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// The process-wide table.
    pub fn global() -> &'static RelayBackoff {
        static GLOBAL: OnceLock<RelayBackoff> = OnceLock::new();
        GLOBAL.get_or_init(RelayBackoff::new)
    }

    /// The relay at `relay_url` asked for `delay` (capped at [`MAX_RETRY_AFTER`]) before the
    /// next request. A shorter pause never cuts a running one short.
    pub fn note(&self, relay_url: &str, delay: Duration) {
        self.note_at(relay_url, delay, Instant::now());
    }

    /// [`note`](Self::note) at `now`.
    pub fn note_at(&self, relay_url: &str, delay: Duration, now: Instant) {
        let until = now + delay.min(MAX_RETRY_AFTER);
        let mut map = self.not_before.lock().unwrap_or_else(|p| p.into_inner());
        map.retain(|_, t| *t > now);
        let entry = map.entry(relay_url.to_string()).or_insert(until);
        if *entry < until {
            *entry = until;
        }
    }

    /// What is left of the pause the relay at `relay_url` asked for, or `None` when a request
    /// may be sent now.
    pub fn remaining(&self, relay_url: &str) -> Option<Duration> {
        self.remaining_at(relay_url, Instant::now())
    }

    /// [`remaining`](Self::remaining) at `now`.
    pub fn remaining_at(&self, relay_url: &str, now: Instant) -> Option<Duration> {
        let map = self.not_before.lock().unwrap_or_else(|p| p.into_inner());
        map.get(relay_url)
            .and_then(|until| until.checked_duration_since(now))
            .filter(|left| !left.is_zero())
    }
}

/// The key-configuration cache rules of a client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CachePolicy {
    /// Seconds before a signed configuration's `not_after` it is no longer used.
    pub refresh_margin_secs: u64,
    /// Whether the kept configuration is dropped before the fetch that replaces it, so that
    /// a failed fetch leaves none (rather than the stale one) to be used next.
    pub drop_before_refetch: bool,
}

impl CachePolicy {
    /// This library's `Client`, and every preset: a signed configuration is used until its
    /// `not_after` (ZIP, "Retrieval, caching and rotation") and the kept one is discarded
    /// before the fetch that replaces it after an outer `400` or `422`, so that a failed fetch
    /// leaves none to be used next.
    pub const LIBRARY: CachePolicy = CachePolicy {
        refresh_margin_secs: 0,
        drop_before_refetch: true,
    };
    /// The Android SDK: as the library (it kept the refused one; now discarded, per the ZIP).
    pub const ANDROID: CachePolicy = CachePolicy::LIBRARY;
    /// The Swift SDK: as the library.
    pub const IOS: CachePolicy = CachePolicy::LIBRARY;
    /// Slipstream: as the library (it refetched 60 s early and kept the refused one).
    pub const SLIPSTREAM: CachePolicy = CachePolicy::LIBRARY;

    /// Whether a configuration valid until `not_after` (Unix seconds; `None` for one that
    /// does not expire) may still be sealed to at `now`.
    pub fn is_fresh(&self, not_after: Option<u64>, now: u64) -> bool {
        not_after.is_none_or(|end| now.saturating_add(self.refresh_margin_secs) < end)
    }
}

/// How long the key configuration the unsigned endpoint (`/ohttp-configs`) serves may be
/// cached, in seconds: the `max-age` of its `Cache-Control` header, or
/// [`UNSIGNED_DEFAULT_CACHE_SECS`] (5 minutes) when there is none (ZIP, "Retrieval, caching and
/// rotation": "at most the `max-age` advertised"). `max-age=0` and `no-store` / `no-cache` give
/// 0: fetch again for the next request. A signed envelope is cached until its `not_after`
/// instead ([`CachePolicy::is_fresh`]).
pub fn unsigned_cache_secs(cache_control: Option<&str>) -> u64 {
    let Some(header) = cache_control else {
        return UNSIGNED_DEFAULT_CACHE_SECS;
    };
    let mut max_age = None;
    let mut no_cache = false;
    for directive in header.split(',') {
        let directive = directive.trim();
        let (name, value) = directive.split_once('=').unwrap_or((directive, ""));
        let name = name.trim();
        if name.eq_ignore_ascii_case("no-store") || name.eq_ignore_ascii_case("no-cache") {
            no_cache = true;
        } else if name.eq_ignore_ascii_case("max-age") && max_age.is_none() {
            // An unparsable value is as good as none; a huge one saturates.
            let digits = value.trim().trim_matches('"');
            max_age = Some(
                if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                    digits.parse::<u64>().unwrap_or(u64::MAX)
                } else {
                    UNSIGNED_DEFAULT_CACHE_SECS
                },
            );
        }
    }
    if no_cache {
        0
    } else {
        max_age.unwrap_or(UNSIGNED_DEFAULT_CACHE_SECS)
    }
}

/// The cache lifetime of an unsigned key configuration that carries no `max-age`.
pub const UNSIGNED_DEFAULT_CACHE_SECS: u64 = 300;

/// How the URL of the signed key configuration is derived from the relay's URL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignedConfigUrlRule {
    /// Trailing slashes trimmed, then a final `/relay` replaced by `/ohttp-configs/signed`,
    /// or that appended if the URL does not end in `/relay` (Android).
    TrimThenReplaceRelaySuffix,
    /// A final `/relay` replaced by `/ohttp-configs/signed`, or that appended (iOS).
    ReplaceRelaySuffix,
    /// `/ohttp-configs/signed` on the relay's host and port, whatever the relay's path
    /// (Slipstream).
    RelayHostRoot,
}

/// The URL of the signed key configuration of the relay at `relay_url`, under `rule`.
pub fn signed_config_url(relay_url: &str, rule: SignedConfigUrlRule) -> Result<String, Error> {
    const SIGNED: &str = "/ohttp-configs/signed";
    let replace = |base: &str| match base.strip_suffix("/relay") {
        Some(root) => format!("{root}{SIGNED}"),
        None => format!("{base}{SIGNED}"),
    };
    match rule {
        SignedConfigUrlRule::TrimThenReplaceRelaySuffix => {
            Ok(replace(relay_url.trim_end_matches('/')))
        }
        SignedConfigUrlRule::ReplaceRelaySuffix => Ok(replace(relay_url)),
        SignedConfigUrlRule::RelayHostRoot => {
            let rest = relay_url
                .strip_prefix("https://")
                .ok_or_else(|| Error::KeyConfig("relay URL must be https".into()))?;
            let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
            if authority.is_empty() {
                return Err(Error::KeyConfig("relay URL without host".into()));
            }
            Ok(format!("https://{authority}{SIGNED}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outer<'a>(status: u16, content_type: Option<&'a str>, body: &'a [u8]) -> OuterResponse<'a> {
        OuterResponse {
            status,
            content_type,
            body,
        }
    }

    const PROBLEM: &[u8] =
        br#"{"type":"https://iana.org/assignments/http-problem-types#ohttp-key","status":422}"#;

    const ALL: [OuterPolicy; 4] = [
        OuterPolicy::LIBRARY,
        OuterPolicy::ANDROID,
        OuterPolicy::IOS,
        OuterPolicy::SLIPSTREAM,
    ];

    /// ZIP, "Outer response contract": outer 400 and 422 refetch the key configuration and
    /// retry exactly once, for every client, whatever the body says.
    #[test]
    fn a_400_or_422_is_retried_once_by_every_client_whatever_the_body() {
        let bodies: [&[u8]; 6] = [
            PROBLEM,
            b"",
            b"nope",
            b"the HPKE key is unknown",
            b"OHTTP-KEY",
            &[0xff, 0xfe],
        ];
        for policy in ALL {
            for status in [400u16, 422] {
                for body in bodies {
                    assert_eq!(
                        classify_outer_response(&policy, &outer(status, None, body), 0),
                        OuterOutcome::RefetchKeyConfig,
                        "{status} {body:?}"
                    );
                    // The second one is permanent.
                    assert!(matches!(
                        classify_outer_response(&policy, &outer(status, None, body), 1),
                        OuterOutcome::Refused { status: s, .. } if s == status
                    ));
                }
            }
        }
    }

    #[test]
    fn no_other_status_is_a_refetch() {
        for policy in ALL {
            for status in [401u16, 403, 404, 409, 413, 426, 429, 500, 502, 503, 504] {
                for attempt in [0, 1] {
                    assert!(
                        matches!(
                            classify_outer_response(&policy, &outer(status, None, PROBLEM), attempt),
                            OuterOutcome::Refused { status: s, .. } if s == status
                        ),
                        "{status} attempt {attempt}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_body_window_bounds_what_is_quoted() {
        let body = vec![b'x'; 300];
        for (policy, window) in [
            (OuterPolicy::ANDROID, 200),
            (OuterPolicy::IOS, 200),
            (OuterPolicy::SLIPSTREAM, 300),
        ] {
            let OuterOutcome::Refused { detail, .. } =
                classify_outer_response(&policy, &outer(503, None, &body), 0)
            else {
                panic!("a 503 was not refused");
            };
            assert_eq!(detail.len(), window);
        }
    }

    #[test]
    fn an_unsigned_configuration_is_cached_for_its_max_age_or_five_minutes() {
        assert_eq!(unsigned_cache_secs(None), 300);
        assert_eq!(unsigned_cache_secs(Some("")), 300);
        assert_eq!(unsigned_cache_secs(Some("public")), 300);
        assert_eq!(unsigned_cache_secs(Some("max-age=300")), 300);
        assert_eq!(unsigned_cache_secs(Some("public, max-age=60")), 60);
        assert_eq!(unsigned_cache_secs(Some("Max-Age=\"90\", public")), 90);
        assert_eq!(unsigned_cache_secs(Some("max-age=0")), 0);
        assert_eq!(unsigned_cache_secs(Some("no-store")), 0);
        assert_eq!(unsigned_cache_secs(Some("no-cache, max-age=600")), 0);
        assert_eq!(unsigned_cache_secs(Some("max-age=abc")), 300);
        assert_eq!(unsigned_cache_secs(Some("max-age=-5")), 300);
        assert_eq!(
            unsigned_cache_secs(Some("max-age=99999999999999999999999")),
            u64::MAX
        );
    }

    /// Slipstream sliced its error body as `&body_str[..160]`, which panics inside a multi-byte
    /// character; the window here is bytes, and the text replaces what it cuts.
    #[test]
    fn a_body_cut_inside_a_multi_byte_character_is_text_not_a_panic() {
        for policy in [
            OuterPolicy::LIBRARY,
            OuterPolicy::ANDROID,
            OuterPolicy::IOS,
            OuterPolicy::SLIPSTREAM,
        ] {
            for prefix in [198usize, 199, 200, 201] {
                let mut body = vec![b'a'; prefix];
                body.extend_from_slice("é€😀".repeat(50).as_bytes());
                for status in [400u16, 422, 500, 503] {
                    let outcome = classify_outer_response(&policy, &outer(status, None, &body), 1);
                    let OuterOutcome::Refused { detail, .. } = outcome else {
                        panic!("not refused");
                    };
                    if let Some(window) = policy.body_window {
                        assert!(detail.len() <= window + 3 * 2, "{}", detail.len());
                    }
                    assert!(std::str::from_utf8(detail.as_bytes()).is_ok());
                    // And on the first attempt, where a 400 or 422 is decided by its status alone.
                    let _ = classify_outer_response(&policy, &outer(status, None, &body), 0);
                }
            }
        }
        // A relay URL with multi-byte characters is an error or a URL, never a panic.
        for rule in [
            SignedConfigUrlRule::TrimThenReplaceRelaySuffix,
            SignedConfigUrlRule::ReplaceRelaySuffix,
            SignedConfigUrlRule::RelayHostRoot,
        ] {
            let _ = signed_config_url("https://ré.example/é/relay/", rule);
            let _ = signed_config_url("https://", rule);
            let _ = signed_config_url("", rule);
        }
    }

    #[test]
    fn success_and_the_media_type_are_options() {
        let sealed = outer(200, Some("message/ohttp-chunked-res"), &[]);
        for policy in [
            OuterPolicy::LIBRARY,
            OuterPolicy::ANDROID,
            OuterPolicy::IOS,
            OuterPolicy::SLIPSTREAM,
        ] {
            assert_eq!(
                classify_outer_response(&policy, &sealed, 0),
                OuterOutcome::Sealed
            );
        }
        // Any other 2xx is refused by every preset.
        let no_content = outer(204, Some("message/ohttp-chunked-res"), &[]);
        for policy in [
            OuterPolicy::LIBRARY,
            OuterPolicy::ANDROID,
            OuterPolicy::IOS,
            OuterPolicy::SLIPSTREAM,
        ] {
            assert!(matches!(
                classify_outer_response(&policy, &no_content, 0),
                OuterOutcome::Refused { status: 204, .. }
            ));
        }
        // A wrong label is accepted by every preset.
        let wrong = outer(200, Some("text/html; charset=utf-8"), &[]);
        for policy in [
            OuterPolicy::LIBRARY,
            OuterPolicy::ANDROID,
            OuterPolicy::IOS,
            OuterPolicy::SLIPSTREAM,
        ] {
            assert_eq!(
                classify_outer_response(&policy, &wrong, 0),
                OuterOutcome::Sealed
            );
        }
        let parameters = outer(200, Some("Message/OHTTP-Chunked-Res; x=y"), &[]);
        assert_eq!(
            classify_outer_response(&OuterPolicy::LIBRARY, &parameters, 0),
            OuterOutcome::Sealed
        );
    }

    #[test]
    fn size_limits_count_the_total() {
        assert!(check_size(10, Some(10)).is_ok());
        assert!(matches!(
            check_size(11, Some(10)),
            Err(Error::TooLarge { max: 10 })
        ));
        assert!(check_size(usize::MAX, None).is_ok());
        let mut guard = SizeGuard::new(Some(10));
        guard.push(6).unwrap();
        guard.push(4).unwrap();
        assert_eq!(guard.seen(), 10);
        assert!(guard.push(1).is_err());
        assert!(guard.push(0).is_err(), "a failed guard stays failed");
    }

    #[test]
    fn the_key_configuration_cap_is_64_kib_for_every_preset_and_exact() {
        for limits in [
            Limits::LIBRARY,
            Limits::ANDROID,
            Limits::IOS,
            Limits::SLIPSTREAM,
        ] {
            assert_eq!(limits.max_key_config_bytes, Some(65_536));
            let mut guard = limits.key_config_guard();
            guard.push(65_536).unwrap();
            assert!(matches!(
                guard.push(1),
                Err(Error::TooLarge { max: 65_536 })
            ));
            // A declared length is refused before any byte is read.
            let guard = limits.key_config_guard();
            assert!(guard.check_declared(65_536).is_ok());
            assert!(guard.check_declared(65_537).is_err());
            assert_eq!(limits.max_sealed_request_bytes, Some(10 * 1024 * 1024));
        }
    }

    #[test]
    fn a_stream_is_aborted_as_soon_as_it_passes_the_cap() {
        // The limit is the same for every client.
        for limits in [
            Limits::LIBRARY,
            Limits::ANDROID,
            Limits::IOS,
            Limits::SLIPSTREAM,
        ] {
            assert_eq!(
                limits.max_sealed_response_bytes,
                Some(GATEWAY_MAX_SEALED_RESPONSE_BYTES)
            );
            let mut guard = limits.response_guard();
            let chunk = 1 << 20;
            let mut chunks = 0usize;
            // Feed 1 MiB chunks of an endless stream: the cap is 257 MiB, so 257 chunks pass
            // and the 258th is refused; the guard was told of at most one chunk past the cap.
            while guard.push(chunk).is_ok() {
                chunks += 1;
                assert!(chunks < 10_000, "the guard never fired");
            }
            assert_eq!(chunks, 257);
            assert!(guard.seen() <= GATEWAY_MAX_SEALED_RESPONSE_BYTES + chunk);
        }
        assert_eq!(GATEWAY_MAX_UPSTREAM_RESPONSE_BYTES, 268_435_456);
        // A declared length over the cap is refused with nothing read.
        let guard = Limits::IOS.response_guard();
        assert!(guard
            .check_declared(GATEWAY_MAX_SEALED_RESPONSE_BYTES as u64)
            .is_ok());
        assert!(matches!(
            guard.check_declared(GATEWAY_MAX_SEALED_RESPONSE_BYTES as u64 + 1),
            Err(Error::TooLarge { .. })
        ));
        assert!(SizeGuard::new(None).check_declared(u64::MAX).is_ok());
        // Saturating, not wrapping.
        let mut guard = SizeGuard::new(Some(10));
        assert!(guard.push(usize::MAX).is_err());
        assert!(guard.push(usize::MAX).is_err());
    }

    #[test]
    fn maximal_response_with_gateway_chunk_size_fits() {
        // A response of exactly 256 MiB of plaintext, sealed with the gateway's default 16 KiB
        // chunks, must fit within GATEWAY_MAX_SEALED_RESPONSE_BYTES.
        const GATEWAY_CHUNK_SIZE: usize = 16384;
        const CHUNK_OVERHEAD: usize = 4 + 16; // length prefix + AEAD tag
        let plaintext_size = GATEWAY_MAX_UPSTREAM_RESPONSE_BYTES;
        let num_chunks = plaintext_size.div_ceil(GATEWAY_CHUNK_SIZE);
        let sealed_size = plaintext_size + num_chunks * CHUNK_OVERHEAD;
        assert!(
            sealed_size <= GATEWAY_MAX_SEALED_RESPONSE_BYTES,
            "A maximal 256 MiB response in {}-byte chunks needs {} bytes sealed, \
             but the limit is {}",
            GATEWAY_CHUNK_SIZE,
            sealed_size,
            GATEWAY_MAX_SEALED_RESPONSE_BYTES
        );
        // The overhead is about 320 KiB for a maximal response.
        let overhead = sealed_size - plaintext_size;
        assert!((320 * 1024..330 * 1024).contains(&overhead));
    }

    #[test]
    fn the_cache_margin_and_the_urls() {
        assert!(CachePolicy::ANDROID.is_fresh(Some(1000), 999));
        assert!(!CachePolicy::ANDROID.is_fresh(Some(1000), 1000));
        // Every client uses a signed configuration until `not_after`, no earlier.
        assert!(CachePolicy::SLIPSTREAM.is_fresh(Some(1000), 999));
        assert!(!CachePolicy::SLIPSTREAM.is_fresh(Some(1000), 1000));
        assert!(CachePolicy::IOS.is_fresh(None, u64::MAX));

        let url = |relay, rule| signed_config_url(relay, rule).unwrap();
        for rule in [
            SignedConfigUrlRule::TrimThenReplaceRelaySuffix,
            SignedConfigUrlRule::ReplaceRelaySuffix,
            SignedConfigUrlRule::RelayHostRoot,
        ] {
            assert_eq!(
                url("https://relay.example/relay", rule),
                "https://relay.example/ohttp-configs/signed"
            );
        }
        assert_eq!(
            url(
                "https://relay.example/relay/",
                SignedConfigUrlRule::TrimThenReplaceRelaySuffix
            ),
            "https://relay.example/ohttp-configs/signed"
        );
        assert_eq!(
            url(
                "https://relay.example/relay/",
                SignedConfigUrlRule::ReplaceRelaySuffix
            ),
            "https://relay.example/relay//ohttp-configs/signed"
        );
        assert_eq!(
            url(
                "https://relay.example:8443/a/b?c",
                SignedConfigUrlRule::RelayHostRoot
            ),
            "https://relay.example:8443/ohttp-configs/signed"
        );
        assert!(signed_config_url(
            "http://relay.example/relay",
            SignedConfigUrlRule::RelayHostRoot
        )
        .is_err());
    }

    #[test]
    fn retry_after_is_delay_seconds_capped() {
        assert_eq!(retry_after_delay(None), None);
        assert_eq!(retry_after_delay(Some(" 7 ")), Some(Duration::from_secs(7)));
        assert_eq!(retry_after_delay(Some("86400")), Some(MAX_RETRY_AFTER));
        assert_eq!(
            retry_after_delay(Some("Wed, 21 Oct 2026 07:28:00 GMT")),
            None
        );
        assert_eq!(retry_after_delay(Some("-1")), None);
    }

    #[test]
    fn a_relay_pause_holds_every_request_through_that_relay() {
        let backoff = RelayBackoff::new();
        let t0 = Instant::now();
        assert_eq!(backoff.remaining_at("https://a/relay", t0), None);
        backoff.note_at("https://a/relay", Duration::from_secs(10), t0);
        let t3 = t0 + Duration::from_secs(3);
        assert_eq!(
            backoff.remaining_at("https://a/relay", t3),
            Some(Duration::from_secs(7))
        );
        // Another relay is not held.
        assert_eq!(backoff.remaining_at("https://b/relay", t3), None);
        // A shorter pause does not cut the running one short; a longer one extends it.
        backoff.note_at("https://a/relay", Duration::from_secs(1), t3);
        assert_eq!(
            backoff.remaining_at("https://a/relay", t3),
            Some(Duration::from_secs(7))
        );
        backoff.note_at("https://a/relay", Duration::from_secs(20), t3);
        assert_eq!(
            backoff.remaining_at("https://a/relay", t3),
            Some(Duration::from_secs(20))
        );
        // Capped, and over once it has run.
        backoff.note_at("https://c/relay", Duration::from_secs(10_000), t0);
        assert_eq!(
            backoff.remaining_at("https://c/relay", t0),
            Some(MAX_RETRY_AFTER)
        );
        assert_eq!(
            backoff.remaining_at("https://a/relay", t3 + Duration::from_secs(20)),
            None
        );
    }

    #[test]
    fn the_headers_differ_per_client() {
        fn names(h: Vec<(&'static str, String)>) -> Vec<&'static str> {
            h.into_iter().map(|(k, _)| k).collect()
        }
        assert_eq!(
            names(OuterHeaders::LIBRARY.relay_post(None)),
            ["Content-Type", "Accept", "Accept-Encoding", "User-Agent"]
        );
        assert_eq!(
            names(OuterHeaders::ANDROID.relay_post(Some("t"))),
            [
                "Content-Type",
                "Accept",
                "Accept-Encoding",
                "User-Agent",
                "X-Client-Trace-Id"
            ]
        );
        assert_eq!(
            names(OuterHeaders::ANDROID.key_fetch(Some("t"))),
            ["Accept", "User-Agent"]
        );
        assert_eq!(
            names(OuterHeaders::IOS.key_fetch(Some("t"))),
            ["Accept", "User-Agent", "X-Client-Trace-Id"]
        );
        assert_eq!(
            names(OuterHeaders::SLIPSTREAM.key_fetch(Some("t"))),
            ["Accept", "Accept-Encoding", "User-Agent"]
        );
        assert_eq!(
            names(OuterHeaders::LIBRARY.key_fetch(Some("t"))),
            ["User-Agent"]
        );
    }

    #[test]
    fn every_preset_sends_the_one_fixed_user_agent() {
        fn agents(h: Vec<(&'static str, String)>) -> Vec<String> {
            h.into_iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
                .map(|(_, v)| v)
                .collect()
        }
        assert_eq!(RELAY_USER_AGENT, "zodl-ohttp/1");
        for preset in [
            OuterHeaders::LIBRARY,
            OuterHeaders::ANDROID,
            OuterHeaders::IOS,
            OuterHeaders::SLIPSTREAM,
        ] {
            assert_eq!(preset.user_agent, Some(RELAY_USER_AGENT));
            for trace in [None, Some("t")] {
                assert_eq!(agents(preset.relay_post(trace)), ["zodl-ohttp/1"]);
                assert_eq!(agents(preset.key_fetch(trace)), ["zodl-ohttp/1"]);
            }
        }
    }
}

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

//! `Client`: requests through one relay to one gateway.

use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use reqwest::header::{CONTENT_TYPE, RETRY_AFTER};
use reqwest::{redirect, StatusCode};

use crate::chunked::{
    collect_response, encapsulate_chunked_request, ChunkedResponseDecoder, ResponseEvent,
    CONTENT_TYPE_CHUNKED_RES,
};
use crate::{
    check_size, encode_request, open_signed_config, retry_after_delay, signed_config_url, Error,
    HostListAnswer, HttpError, HttpErrorKind, KeyConfig, Limits, Network, NoHostList,
    OhttpNetworks, OuterHeaders, RelayBackoff, Request, Response, SignedConfigUrlRule, SizeGuard,
    GATEWAY_MAX_ENCAPSULATED_REQUEST_BYTES, MAX_THIRD_PARTY_HOSTS_BYTES,
};

/// Where a gateway's key configuration is fetched, and how it is authenticated.
///
/// The fetch is a plain HTTPS `GET` of the URL, not sealed: whoever serves the URL sees the
/// client's address fetch it, once per configuration rather than per request.
///
/// A wallet uses [`KeyConfigSource::Signed`] ([`Client::for_network`] builds it from the
/// application's [`crate::OhttpConfig`]). The unsigned source exists only with the cargo
/// feature `insecure-plain-key-config` and only for `Client::insecure_for_local_testing`:
/// whoever serves an unsigned document, the relay when it is fetched through the relay, can
/// hand out a key of its own and read every request sealed to it.
// A `VerifyingKey` keeps its decompressed point, so `Signed` is the larger variant; a source is
// built once per client.
///
/// Its `Debug` output names the variant and the network only, never the URL or the key.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
#[non_exhaustive]
pub enum KeyConfigSource {
    /// An `application/ohttp-keys` document (RFC 9458 §3), authenticated by the HTTPS
    /// connection alone (no redirect is followed): the server of the URL is trusted with every
    /// request. Only with the feature `insecure-plain-key-config`, and refused by
    /// [`Client::new`]: for tests against a local gateway.
    #[cfg(feature = "insecure-plain-key-config")]
    Plain {
        /// The document's URL.
        url: String,
    },
    /// The gateway's signed envelope, checked against a pinned key
    /// ([`crate::open_signed_config`]) and fetched again once it expires.
    Signed {
        /// The envelope's URL.
        url: String,
        /// The network the envelope must name.
        network: Network,
        /// The gateway's configuration-signing key.
        signer: VerifyingKey,
    },
}

impl std::fmt::Debug for KeyConfigSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "insecure-plain-key-config")]
            KeyConfigSource::Plain { .. } => f
                .debug_struct("Plain")
                .field("url", &format_args!("<set>"))
                .finish(),
            KeyConfigSource::Signed { network, .. } => f
                .debug_struct("Signed")
                .field("url", &format_args!("<set>"))
                .field("network", network)
                .field("signer", &format_args!("<set>"))
                .finish(),
        }
    }
}

impl KeyConfigSource {
    fn url(&self) -> &str {
        match self {
            #[cfg(feature = "insecure-plain-key-config")]
            KeyConfigSource::Plain { url } => url,
            KeyConfigSource::Signed { url, .. } => url,
        }
    }
}

/// The longest timeout [`Client::send`] and [`Client::send_stream`] apply: a longer one (such
/// as `Duration::MAX` for "no timeout") is this long, so that the deadline and the timeouts
/// handed to the HTTP stack stay finite.
const MAX_TIMEOUT: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// Requests through one oblivious relay to the gateway behind it.
///
/// The gateway's key configuration is fetched on first use and kept: until a signed one
/// expires (an unsigned one after its `Cache-Control: max-age`, or 5 minutes), or until the
/// gateway refuses it (outer `400` or `422`, whatever the body says, as after a key rotation),
/// when it is discarded and the request is sent once more under a fresh one. No redirect is
/// followed, and only `https://` is spoken.
pub struct Client {
    relay_url: String,
    keys: KeyConfigSource,
    http: reqwest::Client,
    config: Mutex<Option<Fetched>>,
}

#[derive(Clone, Copy)]
struct Fetched {
    config: KeyConfig,
    /// The end of the configuration's cache life, in Unix seconds: a signed one's `not_after`,
    /// an unsigned one's fetch time plus its `max-age` (or 5 minutes).
    not_after: Option<u64>,
}

impl Fetched {
    /// Whether the configuration may still be sealed to at `now` (Unix seconds).
    fn usable(&self, now: u64) -> bool {
        self.not_after.is_none_or(|end| now < end)
    }
}

impl Client {
    /// A client posting to the relay at `relay_url`, sealing to the key of the signed envelope
    /// at the `KeyConfigSource::Signed` URL.
    ///
    /// Refused with [`Error::Setup`]:
    ///
    /// - a relay URL that breaks the syntax rules of
    ///   [`crate::OhttpConfigParams::relay_url`] (the client posts to its canonical form, as
    ///   [`crate::OhttpConfig::relay_url`] describes it);
    /// - an envelope URL that is not `https://` with a non-empty host, or that has userinfo
    ///   (an empty one included), a backslash, whitespace or a control character;
    /// - the unsigned source.
    ///
    /// The client also speaks `https://` only on the wire, so no redirect or later change of
    /// scheme can reach a plain-HTTP server. This constructor does not know the gateway host,
    /// so it does not apply the gateway-host rule: a relay on the gateway's own host is refused
    /// only by [`crate::OhttpConfig::new`], and so through [`Client::for_network`].
    ///
    /// Use it for a relay that serves the signed envelope at a URL none of the
    /// [`SignedConfigUrlRule`]s derives; otherwise use [`Client::for_network`].
    ///
    /// Also [`Error::Setup`] if the TLS backend cannot be initialized; nothing here panics.
    pub fn new(relay_url: impl Into<String>, keys: KeyConfigSource) -> Result<Self, Error> {
        Self::checked(relay_url.into(), keys, reqwest::Client::builder())
    }

    /// The client of `network` under the application's configuration of it in `networks`:
    /// posting to the configured relay URL, sealing to the key of the gateway's signed envelope,
    /// checked against the signing key configured for `network`.
    ///
    /// The envelope must be served where `url_rule` derives it from the relay URL
    /// ([`signed_config_url`]): with [`SignedConfigUrlRule::ReplaceRelaySuffix`] (what
    /// [`crate::ClientProfile::LIBRARY`] uses) `https://relay.example/relay` gives
    /// `https://relay.example/ohttp-configs/signed`. For a relay that serves it elsewhere, use
    /// [`Client::new`] with [`KeyConfigSource::Signed`] and its URL.
    ///
    /// The network and its configuration come from the same place, so they cannot disagree.
    /// [`Error::KeyConfig`] when OHTTP is off for `network`; otherwise as [`Client::new`].
    pub fn for_network(
        networks: &OhttpNetworks,
        network: Network,
        url_rule: SignedConfigUrlRule,
    ) -> Result<Self, Error> {
        let config = networks.require(network)?;
        let url = signed_config_url(config.relay_url(), url_rule)?;
        Self::new(
            config.relay_url(),
            KeyConfigSource::Signed {
                url,
                network,
                signer: *config.signing_pubkey(),
            },
        )
    }

    /// A client without the checks of [`Client::new`]: `http://` URLs and the unsigned source
    /// are used as given. Only with the feature `insecure-plain-key-config`, for tests against a
    /// gateway on the local machine. A plain-HTTP relay exposes the client's requests to anyone
    /// on the path, and an unsigned source lets its server read them; never use this in a
    /// wallet. [`Error::Setup`] if the TLS backend cannot be initialized.
    #[cfg(feature = "insecure-plain-key-config")]
    pub fn insecure_for_local_testing(
        relay_url: impl Into<String>,
        keys: KeyConfigSource,
    ) -> Result<Self, Error> {
        Self::assemble(relay_url.into(), keys, reqwest::Client::builder(), false)
    }

    /// [`Client::new`] with the HTTP stack `builder` (tests add their own root certificate).
    fn checked(
        relay_url: String,
        keys: KeyConfigSource,
        builder: reqwest::ClientBuilder,
    ) -> Result<Self, Error> {
        // The relay URL under the rules of `OhttpConfig::new`, in its canonical form.
        let relay_url = crate::config::parse_relay_url(&relay_url)
            .map_err(|rule| Error::Setup {
                what: "relay URL",
                rule,
            })?
            .url;
        match &keys {
            #[cfg(feature = "insecure-plain-key-config")]
            KeyConfigSource::Plain { .. } => {
                return Err(Error::Setup {
                    what: "key configuration source",
                    rule: "must be signed (the unsigned one is for tests only)",
                })
            }
            KeyConfigSource::Signed { url, .. } => {
                check_https_url(url, "key-configuration URL")?;
            }
        }
        Self::assemble(relay_url, keys, builder, true)
    }

    fn assemble(
        relay_url: String,
        keys: KeyConfigSource,
        builder: reqwest::ClientBuilder,
        https_only: bool,
    ) -> Result<Self, Error> {
        let http = builder
            .redirect(redirect::Policy::none())
            .https_only(https_only)
            .build()
            .map_err(|_| Error::Setup {
                what: "TLS backend",
                rule: "could not be initialized",
            })?;
        Ok(Client {
            relay_url,
            keys,
            http,
            config: Mutex::new(None),
        })
    }

    /// Sends `request` through the relay and returns the backend's answer, whatever its
    /// status, all within `timeout` (a key-configuration fetch and a resend after a rotation
    /// included). Fails when the relay, the gateway or the key-configuration URL cannot be
    /// reached or refuses ([`Error::Http`], [`Error::Refused`]), or when the answer is not a
    /// sealed response that opens. The inner trailers are appended to the headers.
    ///
    /// A `timeout` of more than a year (`Duration::MAX` for "no timeout") is a year; no
    /// timeout panics.
    ///
    /// A sealed request over 10 MiB is not sent: it fails as an outer `413` would. Nothing is
    /// sent through a relay whose `Retry-After` pause is still running ([`Error::Backoff`]).
    pub async fn send(&self, request: &Request, timeout: Duration) -> Result<Response, Error> {
        let mut stream = self.send_stream(request, timeout).await?;
        let mut events = Vec::new();
        while let Some(event) = stream.next().await {
            events.push(event?);
        }
        collect_response(events)
    }

    /// Fetches the list of third-party hosts the gateway `gateway_host` carries (the
    /// gateway's own host name, as for lightwalletd calls), through the relay like any other
    /// request, within `timeout`. `revision`: the revision of the list held, sent as
    /// `if-none-match`; the answer is then [`HostListAnswer::NotModified`] while that list is
    /// still the gateway's.
    ///
    /// [`Error::NoHostList`] when the gateway's answer is no list (it does not publish one, has
    /// no complete list at the moment, or sent a document this crate does not read or one
    /// over 256 KiB, which is not read to its end): keep what is held. Any other error is
    /// that of [`send`](Self::send).
    /// [`ThirdPartyHosts`](crate::ThirdPartyHosts) holds the list and decides when to fetch
    /// it again.
    pub async fn third_party_hosts(
        &self,
        gateway_host: &str,
        revision: Option<&str>,
        timeout: Duration,
    ) -> Result<HostListAnswer, Error> {
        let request = crate::third_party_hosts_request(gateway_host, revision);
        let sent_revision = request
            .headers
            .iter()
            .any(|(name, _)| name == "if-none-match");
        let response = match self.host_list_exchange(&request, timeout).await {
            Err(Error::TooLarge { .. }) => return Err(Error::NoHostList(NoHostList::TooLarge)),
            other => other?,
        };
        match crate::read_third_party_hosts(&response) {
            Ok(HostListAnswer::NotModified) if !sent_revision => {
                Err(Error::NoHostList(NoHostList::UnexpectedNotModified))
            }
            Ok(answer) => Ok(answer),
            Err(reason) => Err(Error::NoHostList(reason)),
        }
    }

    /// [`send`](Self::send) for a host list request: the answer's body is read up to
    /// [`MAX_THIRD_PARTY_HOSTS_BYTES`] and no further ([`Error::TooLarge`] beyond it).
    pub(crate) async fn host_list_exchange(
        &self,
        request: &Request,
        timeout: Duration,
    ) -> Result<Response, Error> {
        let mut stream = self.send_stream(request, timeout).await?;
        let mut events = Vec::new();
        let mut body_bytes = 0usize;
        while let Some(event) = stream.next().await {
            let event = event?;
            if let ResponseEvent::Data(data) = &event {
                body_bytes = body_bytes.saturating_add(data.len());
                if body_bytes > MAX_THIRD_PARTY_HOSTS_BYTES {
                    return Err(Error::TooLarge {
                        max: MAX_THIRD_PARTY_HOSTS_BYTES,
                    });
                }
            }
            events.push(event);
        }
        collect_response(events)
    }

    /// Like [`send`](Self::send), but returns the inner response as it streams: the head, then
    /// every body chunk as the gateway sends it (a `GetBlockRange` block arrives before the
    /// next is fetched), then the trailers and [`ResponseEvent::End`]. The outer exchange
    /// (key configuration, resend after a rotation, outer status and media type) is complete
    /// when this returns; `timeout` then also bounds the whole body.
    ///
    /// A request the gateway refuses as stale (an inner `400` with `ohttp-freshness: rejected`,
    /// see [`crate::freshness`]) is sealed afresh and sent once more: the refusal carried the
    /// gateway clock, so the second attempt is stamped right. Never more than one such retry.
    pub async fn send_stream(
        &self,
        request: &Request,
        timeout: Duration,
    ) -> Result<ResponseStream, Error> {
        // Never `Instant + Duration`, which panics on overflow (a binding may pass
        // `Duration::MAX` for "no timeout"): the timeout is capped, and the sum is checked.
        let now = Instant::now();
        let deadline = now.checked_add(timeout.min(MAX_TIMEOUT)).unwrap_or(now);
        let mut stream = self.send_stream_once(request, deadline).await?;
        match stream.next().await {
            Some(Ok(ResponseEvent::Head { status, headers }))
                if crate::freshness::is_rejection(status, &headers) =>
            {
                drop(stream);
                self.send_stream_once(request, deadline).await
            }
            Some(Ok(event)) => {
                stream.pending.push_front(event);
                Ok(stream)
            }
            Some(Err(e)) => Err(e),
            None => Ok(stream),
        }
    }

    /// One exchange: the outer loop (key configuration, resend after a rotation, outer status
    /// and media type), within `deadline`. Encoded here, so that every call carries a current
    /// `ohttp-freshness` stamp.
    async fn send_stream_once(
        &self,
        request: &Request,
        deadline: Instant,
    ) -> Result<ResponseStream, Error> {
        let remaining = || deadline.saturating_duration_since(Instant::now());
        let encoded = encode_request(request)?;
        let mut stale = false;
        loop {
            if let Some(wait) = RelayBackoff::global().remaining(&self.relay_url) {
                return Err(Error::Backoff { wait });
            }
            let config = self.key_config(stale, remaining()).await?;
            // Sealed afresh on every attempt: the gateway answers a repeated nonce with 409.
            let (sealed, opener) = encapsulate_chunked_request(&config, &encoded)?;
            // Refused here as the relay would refuse it, before anything is uploaded.
            if check_size(sealed.len(), Some(GATEWAY_MAX_ENCAPSULATED_REQUEST_BYTES)).is_err() {
                return Err(Error::Refused { status: 413 });
            }
            // Checked again here: another request may have been answered 429 while this one
            // fetched the key configuration.
            if let Some(wait) = RelayBackoff::global().remaining(&self.relay_url) {
                return Err(Error::Backoff { wait });
            }
            let mut post = self.http.post(&self.relay_url);
            for (name, value) in OuterHeaders::LIBRARY.relay_post(None) {
                post = post.header(name, value);
            }
            let resp = post.body(sealed).timeout(remaining()).send().await?;
            let status = resp.status();
            if status == StatusCode::TOO_MANY_REQUESTS {
                let delay = retry_after_delay(
                    resp.headers()
                        .get(RETRY_AFTER)
                        .and_then(|v| v.to_str().ok()),
                );
                if let Some(delay) = delay {
                    RelayBackoff::global().note(&self.relay_url, delay);
                }
            }
            if matches!(
                status,
                StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
            ) && !stale
            {
                stale = true;
                continue;
            }
            if !status.is_success() {
                return Err(Error::Refused {
                    status: status.as_u16(),
                });
            }
            let media_type = resp
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            let essence = media_type.split(';').next().unwrap_or_default().trim();
            if !essence.eq_ignore_ascii_case(CONTENT_TYPE_CHUNKED_RES) {
                return Err(Error::MediaType(crate::sanitized(
                    media_type,
                    crate::MAX_MEDIA_TYPE_CHARS,
                )));
            }
            let guard = Limits::LIBRARY.response_guard();
            if let Some(declared) = resp.content_length() {
                guard.check_declared(declared)?;
            }
            return Ok(ResponseStream {
                resp: Some(resp),
                decoder: opener.decoder(),
                guard,
                pending: std::collections::VecDeque::new(),
            });
        }
    }

    /// The key configuration to seal to: the one kept, or a fresh one when none is kept, it
    /// expired, or it is `stale`.
    async fn key_config(&self, stale: bool, timeout: Duration) -> Result<KeyConfig, Error> {
        if stale {
            // Discarded before the fetch that replaces it: a failed fetch leaves none.
            *self.config.lock().expect("never poisoned") = None;
        }
        let kept = *self.config.lock().expect("never poisoned");
        if let Some(fetched) = kept.filter(|f| f.usable(unix_now())) {
            return Ok(fetched.config);
        }
        let fetched = self.fetch(timeout).await?;
        *self.config.lock().expect("never poisoned") = Some(fetched);
        Ok(fetched.config)
    }

    async fn fetch(&self, timeout: Duration) -> Result<Fetched, Error> {
        let headers = match &self.keys {
            #[cfg(feature = "insecure-plain-key-config")]
            KeyConfigSource::Plain { .. } => OuterHeaders::LIBRARY.key_fetch_plain(None),
            KeyConfigSource::Signed { .. } => OuterHeaders::LIBRARY.key_fetch_signed(None),
        };
        let mut get = self.http.get(self.keys.url());
        for (name, value) in headers {
            get = get.header(name, value);
        }
        let resp = get.timeout(timeout).send().await?;
        // Never followed (the stack's policy is none); reported as what it is.
        if resp.status().is_redirection() {
            return Err(Error::Http(HttpError::new(HttpErrorKind::RedirectRefused)));
        }
        let resp = resp.error_for_status()?;
        // How long an unsigned document may be kept; a signed one is kept until its `not_after`.
        #[cfg(feature = "insecure-plain-key-config")]
        let max_age = crate::unsigned_cache_secs(
            resp.headers()
                .get(reqwest::header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
        );
        let body = read_limited(resp, Limits::LIBRARY.key_config_guard()).await?;
        match &self.keys {
            #[cfg(feature = "insecure-plain-key-config")]
            KeyConfigSource::Plain { .. } => Ok(Fetched {
                config: KeyConfig::select(&body)?,
                not_after: Some(unix_now().saturating_add(max_age)),
            }),
            KeyConfigSource::Signed {
                network, signer, ..
            } => {
                let keys = open_signed_config(&body, network.as_str(), signer, unix_now())?;
                Ok(Fetched {
                    config: KeyConfig::select(&keys.document)?,
                    not_after: Some(keys.not_after),
                })
            }
        }
    }
}

/// The inner response of [`Client::send_stream`], one [`ResponseEvent`] at a time.
///
/// The sealed body is read from the relay as it arrives and opened chunk by chunk; the
/// response is refused as soon as it passes the size limit. After [`ResponseEvent::End`]
/// (or an error) `next` returns `None`.
pub struct ResponseStream {
    resp: Option<reqwest::Response>,
    decoder: ChunkedResponseDecoder,
    guard: SizeGuard,
    pending: std::collections::VecDeque<ResponseEvent>,
}

impl ResponseStream {
    /// The next event, or `None` once the response has ended.
    #[allow(clippy::should_implement_trait)]
    pub async fn next(&mut self) -> Option<Result<ResponseEvent, Error>> {
        loop {
            if let Some(event) = self.pending.pop_front() {
                return Some(Ok(event));
            }
            let resp = self.resp.as_mut()?;
            let step = match resp.chunk().await {
                Ok(Some(chunk)) => self
                    .guard
                    .push(chunk.len())
                    .and_then(|()| self.decoder.push(&chunk)),
                Ok(None) => {
                    self.resp = None;
                    self.decoder.finish()
                }
                Err(e) => Err(Error::from(e)),
            };
            match step {
                Ok(events) => self.pending.extend(events),
                Err(e) => {
                    self.resp = None;
                    return Some(Err(e));
                }
            }
        }
    }
}

/// `resp`'s body, refused as soon as the length it announces, or the bytes read so far, pass
/// the guard's limit: an oversized answer is never buffered.
async fn read_limited(mut resp: reqwest::Response, mut guard: SizeGuard) -> Result<Vec<u8>, Error> {
    if let Some(declared) = resp.content_length() {
        guard.check_declared(declared)?;
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        guard.push(chunk.len())?;
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Checks that `value`, the `what` of a client, is an `https://` URL (the scheme written in
/// lower case) with a host and without userinfo (not even an empty one, `https://@host/`, which
/// the URL parser drops).
fn check_https_url(value: &str, what: &'static str) -> Result<(), Error> {
    let refused = |rule| Err(Error::Setup { what, rule });
    let Some(after_scheme) = value.strip_prefix("https://") else {
        return refused("must be an https:// URL");
    };
    // First of all: the URL parser drops tab, CR and LF wherever they are, so the checks on
    // the text as written below would otherwise see another URL than the one it reads.
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return refused("must not contain whitespace or control characters");
    }
    // A backslash is read as a path separator by some URL parsers and not by others, so the
    // host would depend on who reads the URL.
    if value.contains('\\') {
        return refused("must not contain a backslash");
    }
    // The authority as written: the URL parser would skip extra slashes (`https:////@host/`)
    // and so recover a host, dropping an empty userinfo on the way.
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if authority.is_empty() {
        return refused("must have a host");
    }
    if authority.contains('@') {
        return refused("must not contain userinfo");
    }
    let Ok(url) = url::Url::parse(value) else {
        return refused("must be a valid URL");
    };
    if url.host_str().is_none_or(str::is_empty) {
        return refused("must have a host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return refused("must not contain userinfo");
    }
    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_configuration_source_debug_shows_no_value() {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[3; 32]).verifying_key();
        let source = KeyConfigSource::Signed {
            url: "https://keys.example/ohttp-configs/signed".into(),
            network: Network::Testnet,
            signer,
        };
        let shown = format!("{source:?}");
        assert_eq!(
            shown,
            "Signed { url: <set>, network: Testnet, signer: <set> }"
        );
        let key_hex = hex::encode(signer.as_bytes());
        for part in ["keys.example", "ohttp-configs", key_hex.as_str()] {
            assert!(!shown.contains(part), "{shown}");
        }
        assert!(!format!("{source:#?}").contains("keys.example"));
    }

    #[cfg(feature = "insecure-plain-key-config")]
    #[test]
    fn an_unsigned_source_debug_shows_no_url() {
        let source = KeyConfigSource::Plain {
            url: "https://keys.example/ohttp-configs".into(),
        };
        let shown = format!("{source:?}");
        assert_eq!(shown, "Plain { url: <set> }");
        for shown in [shown, format!("{source:#?}")] {
            assert!(!shown.contains("keys.example") && !shown.contains("ohttp-configs"));
        }
    }

    #[test]
    fn a_signed_configuration_is_used_until_it_expires() {
        let config = KeyConfig::select(&crate::encapsulation::tests::usable_document()).unwrap();
        let signed = Fetched {
            config,
            not_after: Some(1_000),
        };
        assert!(signed.usable(999));
        assert!(!signed.usable(1_000));
        let plain = Fetched {
            config,
            not_after: None,
        };
        assert!(plain.usable(u64::MAX));
    }

    #[test]
    fn a_client_for_a_network_uses_the_signed_envelope_where_the_rule_puts_it() {
        let networks = crate::config::tests::example();
        for network in [Network::Mainnet, Network::Testnet] {
            let config = networks.get(network).unwrap();
            let relay = config.relay_url();
            for rule in [
                SignedConfigUrlRule::ReplaceRelaySuffix,
                SignedConfigUrlRule::TrimThenReplaceRelaySuffix,
                SignedConfigUrlRule::RelayHostRoot,
            ] {
                let client = Client::for_network(&networks, network, rule).unwrap();
                assert_eq!(client.relay_url, relay);
                // Irrefutable without the feature `insecure-plain-key-config`.
                #[allow(irrefutable_let_patterns)]
                let KeyConfigSource::Signed {
                    url,
                    network: named,
                    signer,
                } = &client.keys
                else {
                    panic!("a client for a network trusts an unsigned key");
                };
                assert_eq!(url, &signed_config_url(relay, rule).unwrap());
                assert_eq!(*named, network);
                assert_eq!(signer, config.signing_pubkey());
            }
        }
        let off = OhttpNetworks::default();
        assert!(matches!(
            Client::for_network(
                &off,
                Network::Mainnet,
                SignedConfigUrlRule::ReplaceRelaySuffix
            ),
            Err(Error::KeyConfig(_))
        ));
    }

    #[test]
    fn a_client_refuses_anything_but_https_urls() {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[3; 32]).verifying_key();
        let signed = |url: &str| KeyConfigSource::Signed {
            url: url.to_string(),
            network: Network::Testnet,
            signer,
        };
        let good_keys = "https://relay.example/ohttp-configs/signed";
        let refused = |relay: &str, keys: &str| match Client::new(relay, signed(keys)) {
            Err(Error::Setup { what, rule }) => (what, rule),
            Err(e) => panic!("{relay} {keys}: {e}"),
            Ok(_) => panic!("{relay} {keys} accepted"),
        };
        for relay in [
            "http://relay.example/relay",
            "HTTPS://relay.example/relay",
            "relay.example/relay",
            "https://",
            "https://user@relay.example/relay",
            "https://@relay.example/relay",
            "https://:@relay.example/relay",
            "https://relay.example/relay?x=1",
            "https://relay.example/relay#x",
        ] {
            assert_eq!(refused(relay, good_keys).0, "relay URL", "{relay}");
        }
        for keys in [
            "http://relay.example/ohttp-configs/signed",
            "https://user:pw@relay.example/ohttp-configs/signed",
            "https://@relay.example/ohttp-configs/signed",
            "https://:@relay.example/ohttp-configs/signed",
            "https:////@relay.example/k",
            "https://\\@relay.example/k",
            "https:///relay.example/k",
            "https://\t/@relay.example/k",
            "https://\n/relay.example/k",
            "https://relay.example/k\r\n",
            "https:// relay.example/k",
            "ftp://relay.example/ohttp-configs/signed",
        ] {
            assert_eq!(
                refused("https://relay.example/relay", keys).0,
                "key-configuration URL",
                "{keys}"
            );
        }
        assert_eq!(
            refused("http://relay.example/relay", good_keys).1,
            "must be an https:// URL"
        );
        // An empty authority, which the URL parser would skip to recover a host (dropping an
        // empty userinfo), and a backslash, which parsers read differently.
        assert_eq!(
            refused("https://relay.example/relay", "https:////@relay.example/k").1,
            "must have a host"
        );
        assert_eq!(
            refused("https://relay.example/relay", "https:///relay.example/k").1,
            "must have a host"
        );
        assert_eq!(
            refused("https://relay.example/relay", "https://\\@relay.example/k").1,
            "must not contain a backslash"
        );
        // Whitespace and control characters, which the URL parser would drop (tab, CR, LF)
        // before reading the host, so that the checks above would see another URL.
        for keys in [
            "https://\t/@relay.example/k",
            "https://\n/relay.example/k",
            "https://relay.example/k\r\n",
            "https:// relay.example/k",
        ] {
            assert_eq!(
                refused("https://relay.example/relay", keys).1,
                "must not contain whitespace or control characters",
                "{keys:?}"
            );
        }
        // An empty userinfo, which the URL parser would drop, is userinfo too.
        assert_eq!(
            refused("https://relay.example/relay", "https://@relay.example/k").1,
            "must not contain userinfo"
        );
        Client::new("https://relay.example/relay", signed(good_keys)).unwrap();
        Client::new("https://[2001:db8::1]:8443/relay", signed(good_keys)).unwrap();
        // The relay URL is used in its canonical form.
        let client =
            Client::new("https://Relay.Example:443/a/../relay/", signed(good_keys)).unwrap();
        assert_eq!(client.relay_url, "https://relay.example/relay");
    }

    #[cfg(feature = "insecure-plain-key-config")]
    #[test]
    fn the_unsigned_source_is_for_the_testing_constructor_only() {
        let plain = || KeyConfigSource::Plain {
            url: "https://relay.example/ohttp-configs".to_string(),
        };
        let Err(Error::Setup { what, .. }) = Client::new("https://relay.example/relay", plain())
        else {
            panic!("Client::new took an unsigned source");
        };
        assert_eq!(what, "key configuration source");
        Client::insecure_for_local_testing("http://127.0.0.1:1/relay", plain()).unwrap();
    }

    /// The test TLS server: a root and a leaf for `localhost` only, generated once per test
    /// process (nothing is shipped), so these tests exercise the production checks and an
    /// `https://`-only client against a real handshake.
    pub(crate) mod tls {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, OnceLock};

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        /// The root (DER), the leaf (DER) and the leaf's key (PKCS #8 DER).
        struct Material {
            root: Vec<u8>,
            leaf: Vec<u8>,
            key: Vec<u8>,
        }

        fn material() -> &'static Material {
            static MATERIAL: OnceLock<Material> = OnceLock::new();
            MATERIAL.get_or_init(|| {
                let mut root = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
                root.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
                root.key_usages = vec![
                    rcgen::KeyUsagePurpose::KeyCertSign,
                    rcgen::KeyUsagePurpose::DigitalSignature,
                ];
                root.distinguished_name = rcgen::DistinguishedName::new();
                root.distinguished_name
                    .push(rcgen::DnType::CommonName, "test root");
                let root_key = rcgen::KeyPair::generate().unwrap();
                let root_cert = root.self_signed(&root_key).unwrap();
                let issuer = rcgen::Issuer::new(root, root_key);
                let mut leaf =
                    rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
                leaf.distinguished_name = rcgen::DistinguishedName::new();
                leaf.distinguished_name
                    .push(rcgen::DnType::CommonName, "localhost");
                leaf.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
                let leaf_key = rcgen::KeyPair::generate().unwrap();
                let leaf_cert = leaf.signed_by(&leaf_key, &issuer).unwrap();
                Material {
                    root: root_cert.der().to_vec(),
                    leaf: leaf_cert.der().to_vec(),
                    key: leaf_key.serialize_der(),
                }
            })
        }

        /// An HTTP stack that trusts the test root (and the public ones).
        pub(crate) fn builder() -> reqwest::ClientBuilder {
            reqwest::Client::builder()
                .add_root_certificate(reqwest::Certificate::from_der(&material().root).unwrap())
        }

        /// What a server answers a request for `path` with: the raw HTTP/1.1 response, or
        /// `None` to keep the connection open without answering.
        pub(crate) type Answer = Arc<dyn Fn(&str) -> Option<Vec<u8>> + Send + Sync>;

        /// A raw HTTP/1.1 response.
        pub(crate) fn response(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
            let mut out = format!("HTTP/1.1 {status}\r\ncontent-length: {}\r\n", body.len());
            for (name, value) in headers {
                out.push_str(&format!("{name}: {value}\r\n"));
            }
            out.push_str("connection: close\r\n\r\n");
            let mut out = out.into_bytes();
            out.extend_from_slice(body);
            out
        }

        /// A listener on 127.0.0.1, its port and the number of connections it accepted. With
        /// `tls`, it speaks TLS with the test leaf; otherwise plain TCP.
        pub(crate) async fn serve(tls: bool, answer: Answer) -> (u16, Arc<AtomicUsize>) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let accepted = Arc::new(AtomicUsize::new(0));
            let count = accepted.clone();
            let acceptor = tls.then(|| {
                let material = material();
                let certs = vec![rustls::pki_types::CertificateDer::from(
                    material.leaf.clone(),
                )];
                let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(material.key.clone()),
                );
                let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap();
                tokio_rustls::TlsAcceptor::from(Arc::new(config))
            });
            tokio::spawn(async move {
                loop {
                    let Ok((tcp, _)) = listener.accept().await else {
                        return;
                    };
                    count.fetch_add(1, Ordering::SeqCst);
                    let answer = answer.clone();
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        match acceptor {
                            Some(acceptor) => {
                                if let Ok(stream) = acceptor.accept(tcp).await {
                                    exchange(stream, answer).await;
                                }
                            }
                            None => exchange(tcp, answer).await,
                        }
                    });
                }
            });
            (port, accepted)
        }

        async fn exchange<S: AsyncReadExt + AsyncWriteExt + Unpin>(mut stream: S, answer: Answer) {
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                match stream.read(&mut byte).await {
                    Ok(1) => head.push(byte[0]),
                    _ => return,
                }
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            let path = head.split(' ').nth(1).unwrap_or_default().to_string();
            match answer(&path) {
                Some(bytes) => {
                    let _ = stream.write_all(&bytes).await;
                    let _ = stream.shutdown().await;
                }
                // Hold the connection until the client gives up.
                None => tokio::time::sleep(std::time::Duration::from_secs(60)).await,
            }
        }

        pub(crate) fn count(accepted: &AtomicUsize) -> usize {
            accepted.load(Ordering::SeqCst)
        }
    }

    /// An envelope of `usable_document()` for `testnet`, signed with the seed `[5; 32]`, valid
    /// around now.
    fn signed_envelope() -> (Vec<u8>, VerifyingKey) {
        use base64::Engine as _;
        use ed25519_dalek::Signer as _;
        use sha2::Digest as _;
        let key = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
        let document = crate::encapsulation::tests::usable_document();
        let (not_before, not_after) = (unix_now() - 60, unix_now() + 3_600);
        let mut message = b"zodl-ohttp-configs-v1\0testnet\0".to_vec();
        message.extend_from_slice(&not_before.to_be_bytes());
        message.extend_from_slice(&not_after.to_be_bytes());
        message.extend_from_slice(&document);
        let b64 = base64::engine::general_purpose::STANDARD;
        let envelope = serde_json::json!({
            "v": 1,
            "network": "testnet",
            "configs": b64.encode(&document),
            "not_before": not_before,
            "not_after": not_after,
            "key_id": hex::encode(&sha2::Sha256::digest(key.verifying_key().as_bytes())[..4]),
            "sig": b64.encode(key.sign(&message).to_bytes()),
        });
        (envelope.to_string().into_bytes(), key.verifying_key())
    }

    fn signed_at(url: String, signer: VerifyingKey) -> KeyConfigSource {
        KeyConfigSource::Signed {
            url,
            network: Network::Testnet,
            signer,
        }
    }

    /// The production checks over a real TLS handshake: the envelope is fetched and opened,
    /// then the request is posted to the relay (which refuses it here).
    #[tokio::test]
    async fn the_production_client_fetches_and_posts_over_https() {
        let (envelope, signer) = signed_envelope();
        let (port, accepted) = tls::serve(
            true,
            std::sync::Arc::new(move |path: &str| {
                Some(match path {
                    "/ohttp-configs/signed" => {
                        tls::response("200 OK", &[("content-type", "application/json")], &envelope)
                    }
                    _ => tls::response("503 Service Unavailable", &[], b""),
                })
            }),
        )
        .await;
        let base = format!("https://localhost:{port}");
        let client = Client::checked(
            format!("{base}/relay"),
            signed_at(format!("{base}/ohttp-configs/signed"), signer),
            tls::builder(),
        )
        .unwrap();
        let request = Request::new("GET", "backend.example", "/v1/info");
        let Err(Error::Refused { status: 503 }) =
            client.send(&request, Duration::from_secs(10)).await
        else {
            panic!("the relay's refusal was not reported");
        };
        assert_eq!(tls::count(&accepted), 2, "one fetch, one post");
    }

    /// An `http://` relay with an `https://` envelope: refused at construction, and a client
    /// that skipped the checks still never reaches the relay, its HTTP stack being https-only.
    #[tokio::test]
    async fn a_plain_http_relay_is_never_contacted() {
        let (envelope, signer) = signed_envelope();
        let (keys_port, keys_accepted) = tls::serve(
            true,
            std::sync::Arc::new(move |_: &str| {
                Some(tls::response(
                    "200 OK",
                    &[("content-type", "application/json")],
                    &envelope,
                ))
            }),
        )
        .await;
        let (relay_port, relay_accepted) = tls::serve(
            false,
            std::sync::Arc::new(|_: &str| Some(tls::response("200 OK", &[], b""))),
        )
        .await;
        let relay = format!("http://127.0.0.1:{relay_port}/relay");
        let keys = format!("https://localhost:{keys_port}/ohttp-configs/signed");
        let Err(Error::Setup { what, .. }) = Client::checked(
            relay.clone(),
            signed_at(keys.clone(), signer),
            tls::builder(),
        ) else {
            panic!("a plain-HTTP relay was accepted");
        };
        assert_eq!(what, "relay URL");
        let bypassed =
            Client::assemble(relay, signed_at(keys, signer), tls::builder(), true).unwrap();
        let request = Request::new("GET", "backend.example", "/v1/info");
        let Err(Error::Http(_)) = bypassed.send(&request, Duration::from_secs(10)).await else {
            panic!("a plain-HTTP relay was posted to");
        };
        assert_eq!(tls::count(&keys_accepted), 1, "the envelope was fetched");
        assert_eq!(
            tls::count(&relay_accepted),
            0,
            "the relay was never contacted"
        );
    }

    /// A redirect from the `https://` envelope URL to an `http://` one is not followed.
    #[tokio::test]
    async fn a_redirect_to_plain_http_is_not_followed() {
        let (target_port, target_accepted) = tls::serve(
            false,
            std::sync::Arc::new(|_: &str| Some(tls::response("200 OK", &[], b"{}"))),
        )
        .await;
        let location = format!("http://127.0.0.1:{target_port}/ohttp-configs/signed");
        let (port, accepted) = tls::serve(
            true,
            std::sync::Arc::new(move |_: &str| {
                Some(tls::response(
                    "302 Found",
                    &[("location", location.as_str())],
                    b"",
                ))
            }),
        )
        .await;
        let (_, signer) = signed_envelope();
        let base = format!("https://localhost:{port}");
        let client = Client::checked(
            format!("{base}/relay"),
            signed_at(format!("{base}/ohttp-configs/signed"), signer),
            tls::builder(),
        )
        .unwrap();
        let request = Request::new("GET", "backend.example", "/v1/info");
        let Err(Error::Http(error)) = client.send(&request, Duration::from_secs(10)).await else {
            panic!("a redirect was followed or ignored");
        };
        assert_eq!(error.kind(), HttpErrorKind::RedirectRefused);
        assert_eq!(tls::count(&accepted), 1);
        assert_eq!(tls::count(&target_accepted), 0, "the redirect was followed");
    }

    /// A timeout too long to add to the clock (what a binding may pass for "no timeout") is
    /// capped, not a panic: the request fails as any other against a port nothing listens on.
    #[tokio::test]
    async fn an_unbounded_timeout_does_not_panic() {
        // Reserved for this test (bound, never listening): refused, and not taken meanwhile.
        let reserved = tokio::net::TcpSocket::new_v4().unwrap();
        reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let base = format!(
            "https://127.0.0.1:{}",
            reserved.local_addr().unwrap().port()
        );
        let (_, signer) = signed_envelope();
        let client = Client::checked(
            format!("{base}/relay"),
            signed_at(format!("{base}/ohttp-configs/signed"), signer),
            tls::builder(),
        )
        .unwrap();
        let request = Request::new("GET", "backend.example", "/v1/info");
        assert!(matches!(
            client.send(&request, Duration::MAX).await,
            Err(Error::Http(_))
        ));
        assert!(matches!(
            client.send_stream(&request, Duration::MAX).await,
            Err(Error::Http(_))
        ));
    }

    /// Neither output of a transport error names the host, the address, the port or the path.
    fn assert_shows_no_peer(error: &Error, port: u16) {
        let shown = format!("{error} | {error:?}");
        for part in [
            "127.0.0.1".to_string(),
            "localhost".to_string(),
            port.to_string(),
            "/ohttp-configs".to_string(),
            "/relay".to_string(),
            "https".to_string(),
        ] {
            assert!(!shown.contains(&part), "{shown} shows {part}");
        }
    }

    async fn transport_error(base: &str) -> Error {
        let (_, signer) = signed_envelope();
        let client = Client::checked(
            format!("{base}/relay"),
            signed_at(format!("{base}/ohttp-configs/signed"), signer),
            tls::builder(),
        )
        .unwrap();
        let request = Request::new("GET", "backend.example", "/v1/info");
        match client.send(&request, Duration::from_millis(1_500)).await {
            Err(error) => error,
            Ok(_) => panic!("{base} answered"),
        }
    }

    #[tokio::test]
    async fn a_refused_connection_is_a_kind_only() {
        // Reserved for this test (bound, never listening): refused, and not taken meanwhile.
        let reserved = tokio::net::TcpSocket::new_v4().unwrap();
        reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let port = reserved.local_addr().unwrap().port();
        let error = transport_error(&format!("https://127.0.0.1:{port}")).await;
        let Error::Http(http) = &error else {
            panic!("{error}");
        };
        assert_eq!(http.kind(), HttpErrorKind::Connect);
        assert_shows_no_peer(&error, port);
    }

    #[tokio::test]
    async fn a_certificate_for_another_name_is_a_kind_only() {
        // The test leaf is for `localhost`; asked for by address, it does not match.
        let (port, _) = tls::serve(
            true,
            std::sync::Arc::new(|_: &str| Some(tls::response("200 OK", &[], b""))),
        )
        .await;
        let error = transport_error(&format!("https://127.0.0.1:{port}")).await;
        let Error::Http(http) = &error else {
            panic!("{error}");
        };
        assert!(http.transport_error_not_log_safe().is_some());
        assert_eq!(
            http.kind(),
            HttpErrorKind::Tls,
            "{:?}",
            http.transport_error_not_log_safe()
        );
        assert_shows_no_peer(&error, port);
    }

    #[tokio::test]
    async fn a_timeout_is_a_kind_only() {
        // Accepts and completes the handshake, then never answers.
        let (port, _) = tls::serve(true, std::sync::Arc::new(|_: &str| None)).await;
        let error = transport_error(&format!("https://localhost:{port}")).await;
        let Error::Http(http) = &error else {
            panic!("{error}");
        };
        assert_eq!(http.kind(), HttpErrorKind::Timeout);
        assert_shows_no_peer(&error, port);
    }

    #[tokio::test]
    async fn an_error_status_is_a_kind_only() {
        let (port, _) = tls::serve(
            true,
            std::sync::Arc::new(|_: &str| Some(tls::response("404 Not Found", &[], b"/relay"))),
        )
        .await;
        let error = transport_error(&format!("https://localhost:{port}")).await;
        let Error::Http(http) = &error else {
            panic!("{error}");
        };
        assert_eq!(http.kind(), HttpErrorKind::Status(404));
        assert_shows_no_peer(&error, port);
    }
}

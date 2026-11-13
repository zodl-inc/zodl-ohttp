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
use reqwest::header::{CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER};
use reqwest::{redirect, StatusCode};

use crate::chunked::{
    collect_response, encapsulate_chunked_request, ChunkedResponseDecoder, ResponseEvent,
    CONTENT_TYPE_CHUNKED_RES,
};
use crate::{
    check_size, encode_request, open_signed_config, retry_after_delay, unsigned_cache_secs, Error,
    KeyConfig, Limits, OuterHeaders, RelayBackoff, Request, Response, SizeGuard,
    GATEWAY_MAX_ENCAPSULATED_REQUEST_BYTES,
};

/// Where a gateway's key configuration is fetched, and how it is authenticated.
///
/// The fetch is a plain HTTPS `GET` of the URL, not sealed: whoever serves the URL sees the
/// client's address fetch it, once per configuration rather than per request.
// A `VerifyingKey` keeps its decompressed point, so `Signed` is the larger variant; a source is
// built once per client.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum KeyConfigSource {
    /// An `application/ohttp-keys` document (RFC 9458 §3), authenticated by the HTTPS
    /// connection alone (no redirect is followed).
    Plain {
        /// The document's URL.
        url: String,
    },
    /// The gateway's signed envelope, checked against a pinned key
    /// ([`crate::open_signed_config`]) and fetched again once it expires.
    Signed {
        /// The envelope's URL.
        url: String,
        /// The network the envelope must name: `mainnet` or `testnet`.
        network: String,
        /// The gateway's configuration-signing key.
        signer: VerifyingKey,
    },
}

impl KeyConfigSource {
    fn url(&self) -> &str {
        match self {
            KeyConfigSource::Plain { url } | KeyConfigSource::Signed { url, .. } => url,
        }
    }
}

/// Requests through one oblivious relay to the gateway behind it.
///
/// The gateway's key configuration is fetched on first use and kept: until a signed one
/// expires (an unsigned one after its `Cache-Control: max-age`, or 5 minutes), or until the
/// gateway refuses it (outer `400` or `422`, whatever the body says, as after a key rotation),
/// when it is discarded and the request is sent once more under a fresh one. No redirect is followed.
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
    /// A client posting to the relay at `relay_url`, sealing to the key `keys` gives.
    ///
    /// Panics if the TLS backend cannot be initialized, as `reqwest::Client::new` does.
    pub fn new(relay_url: impl Into<String>, keys: KeyConfigSource) -> Self {
        Client {
            relay_url: relay_url.into(),
            keys,
            http: reqwest::Client::builder()
                .redirect(redirect::Policy::none())
                .build()
                .expect("the TLS backend initializes"),
            config: Mutex::new(None),
        }
    }

    /// Sends `request` through the relay and returns the backend's answer, whatever its
    /// status, all within `timeout` (a key-configuration fetch and a resend after a rotation
    /// included). Fails when the relay, the gateway or the key-configuration URL cannot be
    /// reached or refuses ([`Error::Http`], [`Error::Refused`]), or when the answer is not a
    /// sealed response that opens. The inner trailers are appended to the headers.
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
        let deadline = Instant::now() + timeout;
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
                return Err(Error::MediaType(media_type.to_string()));
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
        let mut get = self.http.get(self.keys.url());
        for (name, value) in OuterHeaders::LIBRARY.key_fetch(None) {
            get = get.header(name, value);
        }
        let resp = get.timeout(timeout).send().await?.error_for_status()?;
        let max_age = unsigned_cache_secs(
            resp.headers()
                .get(CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
        );
        let body = read_limited(resp, Limits::LIBRARY.key_config_guard()).await?;
        match &self.keys {
            KeyConfigSource::Plain { .. } => Ok(Fetched {
                config: KeyConfig::select(&body)?,
                not_after: Some(unix_now().saturating_add(max_age)),
            }),
            KeyConfigSource::Signed {
                network, signer, ..
            } => {
                let keys = open_signed_config(&body, network, signer, unix_now())?;
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
                Err(e) => Err(Error::Http(e)),
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

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

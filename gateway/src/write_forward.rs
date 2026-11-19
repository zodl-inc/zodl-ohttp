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

//! WRITE forwarding: a read origin hands its WRITEs to the gateway next to the hub store.
//!
//! A read origin (`REPLAY_PEER_MODE=async-reads`) decides each WRITE at the hub store, a long
//! round trip away, and then calls an upstream that is usually just as far. With
//! `REPLAY_WRITE_FORWARD_URL` it instead sends the Encapsulated Request of a WRITE, exactly the
//! bytes the relay sent, to a gateway that runs next to the hub store and accepts forwarded
//! WRITEs on a listener of its own (`WRITE_FORWARD_BIND_ADDR`, never the public port). That
//! gateway handles it as it handles a request from a relay: it computes the nonce from those
//! bytes, takes it at its own security store (the hub store) with its replica wait and its check
//! of every WRITE at its fallback store, decrypts it with the same keys, applies its own route
//! policy, freshness check and third-party rules, calls the upstream and seals the answer to the
//! client. The read origin streams that sealed answer back unchanged. Its own replay checks were
//! made before (the local `SET NX` on the same bytes); nothing about the request is decided on
//! its word, and no plaintext leaves it.
//!
//! What the read origin does with the answer (`Forwarded`):
//!
//! - an answer (`200`, `message/ohttp-chunked-res`): streamed back as it is;
//! - `409` (the hub store already held the nonce): the replay answer of a peer replay;
//! - any other answer of the receiving gateway (its secret check, busy, not ready, its replay
//!   store without a verdict, a request it could not open), or no connection at all: that
//!   gateway did not run the WRITE and will not, so the read origin decides it itself, exactly
//!   as without forwarding (`declined`, `declined_once`, `connect`), and after a lasting reason
//!   (no connection, the secret, readiness, a requirement, not a receiving gateway at that URL),
//!   after an unclear answer of its store, or after three one-off declines in a row, for
//!   `REPLAY_WRITE_FORWARD_BACKOFF_MS` does so at once (`skipped`);
//! - no answer in time, a connection that broke after the request was sent, or an answer saying
//!   its replay store gave no verdict after the nonce may have been stored (`DECLINE_UNCLEAR`):
//!   the receiving gateway may have taken the nonce (and in the first two cases run the WRITE),
//!   so it fails closed (inner `503` / grpc-status 14) rather than finding the request's own
//!   nonce and calling it a replay. The client retries with a new Encapsulated Request.
//!
//! Deciding locally after an answer is safe in any case: a WRITE runs only once the stores that
//! decide it took its nonce as new, and both paths ask the same stores for the same nonce; a
//! nonce the receiving gateway took before it declined makes the local decision a replay. The
//! path between the two gateways must not answer on the receiving gateway's behalf (no proxy
//! of its own between them): such an answer, after the receiving gateway ran the WRITE, would
//! give the client a replay answer instead of the result.
//!
//! The read origin states what its own decision of a WRITE requires (`REQUIRES_HEADER`: a check
//! at a second store, a replica acknowledgement of the nonce); a receiving gateway that cannot
//! meet a requirement declines, so forwarding never drops a check the read origin would make.
//! What the two cannot check against each other is configuration and must hold: the receiving
//! gateway's own store is the read origins' hub store, its second store (peers or fallback
//! store) is their standby stores, both list the same one-sided routes and fail-closed settings,
//! and its second store is never a forwarding origin's own store (an origin with its own
//! replica wait and no standby stores, a fallback store itself, is refused as a forwarder at
//! startup). The
//! receiving gateway takes every forwarded request for a WRITE, whatever its own read routes
//! say, and opens it before it asks its replay store, so a request it cannot open costs no
//! nonce.
//!
//! The link carries the Encapsulated Request, the sealed answer and the forwarding secret in
//! clear (cleartext HTTP/2): use it on a private network only. A holder of the secret can submit
//! Encapsulated Requests like a relay; replay protection, freshness and the route policy still
//! apply to them.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context;
use bytes::Bytes;
use http_body_util::Full;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioTimer};

use crate::config::RelaySecret;

/// The path forwarded WRITEs are posted to on the receiving gateway's listener.
pub const FORWARD_PATH: &str = "/ohttp-gateway/internal/v1/write";
/// The header carrying the forwarding secret.
pub const SECRET_HEADER: &str = "x-write-forward-secret";
/// Set by the receiving gateway on some of its non-sealed answers (`classify`).
pub const DECLINE_HEADER: &str = "ohttp-write-forward-decline";
/// Its replay store gave no verdict after the nonce may have been stored there: the read
/// origin fails the WRITE closed instead of deciding it (it would find the request's own nonce).
pub const DECLINE_UNCLEAR: &str = "store-unclear";
/// Declined for a reason that lasts (the secret, readiness, a requirement): the read origin
/// decides it itself and stops forwarding for its backoff.
pub const DECLINE_LASTING: &str = "lasting";

/// What the read origin's own decision of a WRITE requires, as a comma-separated list
/// (`Requirement`): a receiving gateway that cannot meet one of them, or does not know it,
/// answers 503 without asking any store, so the read origin decides the WRITE with its own
/// checks (`declined`).
pub const REQUIRES_HEADER: &str = "ohttp-write-forward-requires";

/// One entry of `REQUIRES_HEADER`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Requirement {
    /// Every WRITE is also checked synchronously at a second store (the read origin's
    /// confirming standby stores).
    SecondStore,
    /// The deciding store must acknowledge the nonce on at least this many replicas before the
    /// WRITE runs (`replica-ack=N`: the read origin's hub check with `REPLAY_PEER_WAIT_REPLICAS`,
    /// or its own `REPLAY_WRITE_WAIT_REPLICAS`, the larger one).
    ReplicaAck(u32),
}

impl Requirement {
    pub fn render(self) -> String {
        match self {
            Requirement::SecondStore => "second-store".to_string(),
            Requirement::ReplicaAck(n) => format!("replica-ack={n}"),
        }
    }

    /// The entries of a `REQUIRES_HEADER` value; `Err` names the first one that is not known.
    pub fn parse_list(raw: &str) -> Result<Vec<Self>, String> {
        raw.split(',')
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(|t| match t.split_once('=') {
                None if t == "second-store" => Ok(Requirement::SecondStore),
                Some(("replica-ack", n)) => n
                    .parse::<u32>()
                    .ok()
                    .filter(|n| *n > 0)
                    .map(Requirement::ReplicaAck)
                    .ok_or_else(|| t.chars().take(32).collect()),
                _ => Err(t.chars().take(32).collect()),
            })
            .collect()
    }
}

/// `REPLAY_WRITE_FORWARD_CONNECT_TIMEOUT_MS` default.
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 1000;
/// `REPLAY_WRITE_FORWARD_TIMEOUT_SECS` default: above the receiving gateway's own upstream
/// timeouts (its answer starts once its upstream answered).
pub const DEFAULT_TIMEOUT_SECS: u64 = 90;
/// `REPLAY_WRITE_FORWARD_BACKOFF_MS` default.
pub const DEFAULT_BACKOFF_MS: u64 = 5000;
/// HTTP/2 PINGs of the forwarding connection, idle or not, and how long one may go unanswered:
/// a receiving gateway that vanished without closing the connection is noticed within a few
/// seconds; the WRITEs sent on it meanwhile fail closed, the next ones open a new connection or
/// are decided here.
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(2);
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(5);
/// One-off declines in a row after which forwarding pauses for the backoff as well.
const ONE_OFF_DECLINES_BEFORE_PAUSE: u64 = 3;

/// The forwarding side (`REPLAY_WRITE_FORWARD_*`).
#[derive(Clone, Debug)]
pub struct ForwardConfig {
    /// `http://host:port`, the path set to `FORWARD_PATH`.
    pub url: hyper::Uri,
    pub secret: String,
    pub connect_timeout: Duration,
    pub timeout: Duration,
    pub backoff: Duration,
}

impl ForwardConfig {
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let get = |k: &str| std::env::var(k).ok();
        Self::parse(
            get("REPLAY_WRITE_FORWARD_URL").as_deref(),
            get("REPLAY_WRITE_FORWARD_SECRET").as_deref(),
            get("REPLAY_WRITE_FORWARD_CONNECT_TIMEOUT_MS").as_deref(),
            get("REPLAY_WRITE_FORWARD_TIMEOUT_SECS").as_deref(),
            get("REPLAY_WRITE_FORWARD_BACKOFF_MS").as_deref(),
        )
    }

    /// None when `url` is unset or empty. Errors never contain the secret.
    pub fn parse(
        url: Option<&str>,
        secret: Option<&str>,
        connect_timeout_ms: Option<&str>,
        timeout_secs: Option<&str>,
        backoff_ms: Option<&str>,
    ) -> anyhow::Result<Option<Self>> {
        let Some(url) = url.map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(None);
        };
        let parsed: hyper::Uri = url
            .parse()
            .context("REPLAY_WRITE_FORWARD_URL is not a URL")?;
        if parsed.scheme_str() != Some("http") {
            anyhow::bail!(
                "REPLAY_WRITE_FORWARD_URL must be an http:// URL (cleartext HTTP/2 on a private network)"
            );
        }
        let Some(authority) = parsed.authority() else {
            anyhow::bail!("REPLAY_WRITE_FORWARD_URL has no host");
        };
        if authority.port_u16().is_none() {
            anyhow::bail!("REPLAY_WRITE_FORWARD_URL must name a port");
        }
        if authority.as_str().contains('@') {
            anyhow::bail!("REPLAY_WRITE_FORWARD_URL must not carry credentials");
        }
        if !matches!(parsed.path(), "" | "/") || parsed.query().is_some() {
            anyhow::bail!(
                "REPLAY_WRITE_FORWARD_URL takes no path or query (the path is {FORWARD_PATH})"
            );
        }
        let url: hyper::Uri = format!("http://{authority}{FORWARD_PATH}")
            .parse()
            .context("REPLAY_WRITE_FORWARD_URL")?;
        let secret = secret.unwrap_or("");
        if secret.is_empty() {
            anyhow::bail!("REPLAY_WRITE_FORWARD_URL is set but REPLAY_WRITE_FORWARD_SECRET is not");
        }
        if !secret.bytes().all(|b| b.is_ascii_graphic()) {
            anyhow::bail!("REPLAY_WRITE_FORWARD_SECRET must be visible ASCII without spaces");
        }
        let millis = |name: &str, raw: Option<&str>, default: u64| -> anyhow::Result<u64> {
            match raw.map(str::trim).filter(|s| !s.is_empty()) {
                None => Ok(default),
                Some(v) => match v.parse::<u64>() {
                    Ok(n) if n > 0 => Ok(n),
                    _ => anyhow::bail!("{name} must be a positive integer, got '{v}'"),
                },
            }
        };
        Ok(Some(Self {
            url,
            secret: secret.to_string(),
            connect_timeout: Duration::from_millis(millis(
                "REPLAY_WRITE_FORWARD_CONNECT_TIMEOUT_MS",
                connect_timeout_ms,
                DEFAULT_CONNECT_TIMEOUT_MS,
            )?),
            timeout: Duration::from_secs(millis(
                "REPLAY_WRITE_FORWARD_TIMEOUT_SECS",
                timeout_secs,
                DEFAULT_TIMEOUT_SECS,
            )?),
            backoff: Duration::from_millis(millis(
                "REPLAY_WRITE_FORWARD_BACKOFF_MS",
                backoff_ms,
                DEFAULT_BACKOFF_MS,
            )?),
        }))
    }
}

/// What forwarding one WRITE gave (`Forwarder::forward`).
#[derive(Debug)]
pub enum Forwarded {
    /// The receiving gateway's sealed answer, to be streamed back as it is.
    Answer(hyper::Response<hyper::body::Incoming>),
    /// The hub store already held the nonce.
    Replay,
    /// The receiving gateway did not run it (an answer other than a sealed one or a replay, or
    /// no connection): decide the WRITE here, as without forwarding.
    Declined(&'static str),
    /// The receiving gateway may have taken the nonce: fail closed.
    Failed(&'static str),
}

impl Forwarded {
    /// The `result` label of `ohttp_write_forward_total`.
    pub fn label(&self) -> &'static str {
        match self {
            Forwarded::Answer(_) => "answered",
            Forwarded::Replay => "replay",
            Forwarded::Declined(why) => why,
            Forwarded::Failed(why) => why,
        }
    }

    /// The `result` label of `ohttp_write_stage_duration_seconds{stage="forward"}`.
    fn stage_result(&self) -> &'static str {
        match self {
            Forwarded::Answer(_) => "answered",
            Forwarded::Replay => "replay",
            Forwarded::Declined(_) => "declined",
            Forwarded::Failed(_) => "failed",
        }
    }
}

/// The forwarding client of a read origin: one pooled cleartext HTTP/2 client, with a pause
/// after a declined WRITE or a failed connection attempt.
pub struct Forwarder {
    config: ForwardConfig,
    client: Client<HttpConnector, Full<Bytes>>,
    network: String,
    base: Instant,
    /// Forwarding is skipped (`Declined("skipped")`) until this many ms after `base`.
    skip_until_ms: AtomicU64,
    /// One-off declines in a row (`ONE_OFF_DECLINES_BEFORE_PAUSE`).
    one_off_declines: AtomicU64,
}

impl Forwarder {
    pub fn new(config: ForwardConfig, network: String) -> Self {
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(config.connect_timeout));
        connector.set_nodelay(true);
        let client = Client::builder(TokioExecutor::new())
            .http2_only(true)
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(Duration::from_secs(60))
            .timer(TokioTimer::new())
            .http2_keep_alive_interval(KEEP_ALIVE_INTERVAL)
            .http2_keep_alive_timeout(KEEP_ALIVE_TIMEOUT)
            .http2_keep_alive_while_idle(true)
            .build(connector);
        Self {
            config,
            client,
            network,
            base: Instant::now(),
            skip_until_ms: AtomicU64::new(0),
            one_off_declines: AtomicU64::new(0),
        }
    }

    pub fn config(&self) -> &ForwardConfig {
        &self.config
    }

    fn now_ms(&self) -> u64 {
        self.base.elapsed().as_millis() as u64 + 1
    }

    /// Forward the Encapsulated Request `body` of a WRITE (`ohttp_write_forward_total`,
    /// `ohttp_write_stage_duration_seconds{stage="forward"}`, until the answer's head);
    /// `requires`: what this origin's own decision of a WRITE requires (`REQUIRES_HEADER`).
    pub async fn forward(&self, body: Bytes, requires: &[Requirement]) -> Forwarded {
        let started = Instant::now();
        let outcome = self.send(body, requires).await;
        crate::health::record_write_forward(&self.network, outcome.label());
        crate::health::observe_write_stage(
            &self.network,
            "forward",
            outcome.stage_result(),
            started.elapsed(),
        );
        outcome
    }

    async fn send(&self, body: Bytes, requires: &[Requirement]) -> Forwarded {
        if self.now_ms() < self.skip_until_ms.load(Ordering::Relaxed) {
            return Forwarded::Declined("skipped");
        }
        let mut request = hyper::Request::post(self.config.url.clone())
            .header(
                hyper::header::CONTENT_TYPE,
                crate::ohttp_chunked::CONTENT_TYPE_CHUNKED_REQ,
            )
            .header(SECRET_HEADER, self.config.secret.as_str());
        if !requires.is_empty() {
            let list: Vec<String> = requires.iter().map(|r| r.render()).collect();
            request = request.header(REQUIRES_HEADER, list.join(","));
        }
        let request = match request.body(Full::new(body)) {
            Ok(r) => r,
            // A secret that is not a header value is refused at startup; never sent.
            Err(_) => return Forwarded::Declined("declined"),
        };
        let answer =
            match tokio::time::timeout(self.config.timeout, self.client.request(request)).await {
                Err(_) => Forwarded::Failed("timeout"),
                Ok(Err(e)) if e.is_connect() => Forwarded::Declined("connect"),
                Ok(Err(_)) => Forwarded::Failed("transport"),
                Ok(Ok(r)) => classify(r),
            };
        // Pause after a lasting decline, after an unclear store answer there (the next WRITEs
        // carry other nonces: deciding them here is as safe as after any decline), and after
        // ONE_OFF_DECLINES_BEFORE_PAUSE one-off declines in a row (busy, a request it could not
        // open: alone, the next WRITE may well be run there). Any other outcome ends a run of
        // them; counted across concurrent WRITEs, so "in a row" is approximate under load.
        let pause = match &answer {
            Forwarded::Declined("declined_once") => {
                self.one_off_declines.fetch_add(1, Ordering::Relaxed) + 1
                    >= ONE_OFF_DECLINES_BEFORE_PAUSE
            }
            Forwarded::Declined(_) | Forwarded::Failed("unclear") => true,
            _ => {
                self.one_off_declines.store(0, Ordering::Relaxed);
                false
            }
        };
        if pause {
            self.one_off_declines.store(0, Ordering::Relaxed);
            self.skip_until_ms.store(
                self.now_ms() + self.config.backoff.as_millis() as u64,
                Ordering::Relaxed,
            );
        }
        answer
    }
}

/// The verdict on the receiving gateway's answer head: a sealed answer, a replay, an unclear
/// answer of its replay store (fail closed), or any other answer, which that gateway gives only
/// for a request it did not run (`lasting`: one whose reason will hold for the next ones too).
pub fn classify(answer: hyper::Response<hyper::body::Incoming>) -> Forwarded {
    let header = |name: &str| {
        answer
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let sealed =
        header("content-type").as_deref() == Some(crate::ohttp_chunked::CONTENT_TYPE_CHUNKED_RES);
    let decline = header(DECLINE_HEADER);
    match answer.status().as_u16() {
        200 if sealed => Forwarded::Answer(answer),
        409 => Forwarded::Replay,
        _ if decline.as_deref() == Some(DECLINE_UNCLEAR) => Forwarded::Failed("unclear"),
        _ if decline.as_deref() == Some(DECLINE_LASTING) => Forwarded::Declined("declined"),
        // Not a receiving gateway at that URL (no such route, method or protocol): lasting.
        404 | 405 | 426 => Forwarded::Declined("declined"),
        _ => Forwarded::Declined("declined_once"),
    }
}

/// The receiving side (`WRITE_FORWARD_*`): its own listener and the accepted secrets.
#[derive(Clone)]
pub struct ReceiverConfig {
    pub bind: std::net::SocketAddr,
    pub secrets: Vec<RelaySecret>,
}

impl std::fmt::Debug for ReceiverConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.secrets.iter().map(|s| s.name.as_str()).collect();
        f.debug_struct("ReceiverConfig")
            .field("bind", &self.bind)
            .field("secrets", &names)
            .finish()
    }
}

impl ReceiverConfig {
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        Self::parse(
            std::env::var("WRITE_FORWARD_BIND_ADDR").ok().as_deref(),
            std::env::var("WRITE_FORWARD_SECRETS").ok().as_deref(),
        )
    }

    /// None when `bind` is unset or empty. `secrets`: `RELAY_SECRETS` syntax (`name=secret`,
    /// comma-separated); the names label the metrics like relay names.
    pub fn parse(bind: Option<&str>, secrets: Option<&str>) -> anyhow::Result<Option<Self>> {
        let Some(bind) = bind.map(str::trim).filter(|s| !s.is_empty()) else {
            if secrets.map(str::trim).is_some_and(|s| !s.is_empty()) {
                anyhow::bail!("WRITE_FORWARD_SECRETS is set but WRITE_FORWARD_BIND_ADDR is not");
            }
            return Ok(None);
        };
        let bind: std::net::SocketAddr = bind.parse().map_err(|_| {
            anyhow::anyhow!("WRITE_FORWARD_BIND_ADDR must be IP:port, got '{bind}'")
        })?;
        let raw = secrets.map(str::trim).unwrap_or("");
        if raw.is_empty() {
            anyhow::bail!("WRITE_FORWARD_BIND_ADDR is set but WRITE_FORWARD_SECRETS is not");
        }
        let secrets = crate::config::parse_relay_secrets(raw)
            .map_err(|e| anyhow::anyhow!("WRITE_FORWARD_SECRETS: {e}"))?;
        Ok(Some(Self { bind, secrets }))
    }
}

/// The entry of `secrets` whose secret a forwarded request carries: exactly one
/// `SECRET_HEADER`, visible ASCII, compared like a relay secret (`match_relay_secret`).
pub fn authenticated(secrets: &[RelaySecret], headers: &axum::http::HeaderMap) -> Option<usize> {
    let mut values = headers.get_all(SECRET_HEADER).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    crate::config::match_relay_secret(secrets, value.to_str().ok()?.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(url: Option<&str>, secret: Option<&str>) -> anyhow::Result<Option<ForwardConfig>> {
        ForwardConfig::parse(url, secret, None, None, None)
    }

    #[test]
    fn the_forward_url_is_an_http_origin_with_a_port() {
        assert!(parse(None, None).unwrap().is_none());
        assert!(parse(Some(" "), Some("s")).unwrap().is_none());
        let c = parse(Some("http://10.0.0.1:8081"), Some("a-secret"))
            .unwrap()
            .unwrap();
        assert_eq!(
            c.url.to_string(),
            format!("http://10.0.0.1:8081{FORWARD_PATH}")
        );
        assert_eq!(
            c.connect_timeout,
            Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS)
        );
        assert_eq!(c.timeout, Duration::from_secs(DEFAULT_TIMEOUT_SECS));
        assert_eq!(c.backoff, Duration::from_millis(DEFAULT_BACKOFF_MS));
        assert!(parse(Some("http://gw.example.com:8081/"), Some("s")).is_ok());
        for bad in [
            "https://gw.example.com:8081",
            "http://gw.example.com",
            "http://gw.example.com:8081/other",
            "http://gw.example.com:8081/?a=b",
            "http://user:pw@gw.example.com:8081",
            "gw.example.com:8081",
        ] {
            assert!(parse(Some(bad), Some("s")).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_forward_secret_is_required_and_never_in_an_error() {
        let err = parse(Some("http://gw.example.com:8081"), None).unwrap_err();
        assert!(err.to_string().contains("REPLAY_WRITE_FORWARD_SECRET"));
        let err = parse(Some("http://gw.example.com:8081"), Some("has space secret")).unwrap_err();
        assert!(!err.to_string().contains("has space"), "{err}");
        let err = ForwardConfig::parse(
            Some("http://gw.example.com:8081"),
            Some("s"),
            Some("0"),
            None,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("CONNECT_TIMEOUT_MS"));
    }

    #[test]
    fn requirements_round_trip_and_unknown_ones_are_refused() {
        assert_eq!(
            Requirement::parse_list("second-store, replica-ack=2").unwrap(),
            vec![Requirement::SecondStore, Requirement::ReplicaAck(2)]
        );
        assert_eq!(Requirement::ReplicaAck(1).render(), "replica-ack=1");
        assert!(Requirement::parse_list("replica-ack").is_err());
        assert!(Requirement::parse_list("replica-ack=0").is_err());
        assert_eq!(Requirement::parse_list("").unwrap(), vec![]);
        assert_eq!(
            Requirement::parse_list("replica-ack=1,new-thing"),
            Err("new-thing".to_string())
        );
    }

    #[test]
    fn the_receiver_needs_an_address_and_secrets() {
        assert!(ReceiverConfig::parse(None, None).unwrap().is_none());
        assert!(ReceiverConfig::parse(None, Some("a=b")).is_err());
        assert!(ReceiverConfig::parse(Some("0.0.0.0:8081"), None).is_err());
        assert!(ReceiverConfig::parse(Some("localhost:8081"), Some("a=b")).is_err());
        let r = ReceiverConfig::parse(Some("0.0.0.0:8081"), Some("origin-a=s1,origin-b=s2"))
            .unwrap()
            .unwrap();
        assert_eq!(r.secrets.len(), 2);
        assert!(
            !format!("{r:?}").contains("s1"),
            "the secrets are not printed"
        );
        let mut headers = axum::http::HeaderMap::new();
        assert_eq!(authenticated(&r.secrets, &headers), None);
        headers.insert(SECRET_HEADER, "s2".parse().unwrap());
        assert_eq!(authenticated(&r.secrets, &headers), Some(1));
        headers.append(SECRET_HEADER, "s2".parse().unwrap());
        assert_eq!(authenticated(&r.secrets, &headers), None, "two headers");
        headers.remove(SECRET_HEADER);
        headers.insert(SECRET_HEADER, "s3".parse().unwrap());
        assert_eq!(authenticated(&r.secrets, &headers), None);
    }
}

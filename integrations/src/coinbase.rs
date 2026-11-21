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

//! The Coinbase Onramp provider (kind `coinbase`, configuration file only): hosted buy and sell
//! sessions of the Coinbase Developer Platform (CDP) for ZEC, minted by the gateway with its own
//! CDP key. The wallet never holds the key, and the gateway's API calls to Coinbase carry no
//! client IP and nothing of the client's request but the validated values. (The browser or app
//! that then opens the hosted page talks to Coinbase directly.)
//!
//! The alias answers three routes (its whole policy, [`ROUTES`]); the module validates every
//! body, builds the upstream request itself and scrubs every upstream answer:
//!
//! - `POST /v1/session` `{"flow": "buy"|"sell", "address": "t1...", "ref": "<base32>", "fiat"?:
//!   "USD"|"CAD"|"GBP"|"EUR", "amount"?: "50", "timestamp": "<unix seconds>", "signature":
//!   "<base64>"}` (`amount` needs `fiat`): `POST /onramp/v1/token` with the address for the
//!   `zcash` network and the asset `ZEC` (constants, never inputs; no client IP is ever sent),
//!   then `{"url": <hosted page URL>, "expires_at": <unix seconds>}` ([`buy_url`],
//!   [`sell_url`]). The address must be a Zcash mainnet transparent P2PKH address
//!   (base58check), the timestamp within [`signature::MAX_SKEW_SECS`] of the gateway's clock,
//!   and the signature the wallet's, by that address's key, over the address and the timestamp
//!   ([`signature`]). A sell needs the configured `redirect_url`.
//! - `POST /v1/sell/status` `{"ref": ...}`: `GET /onramp/v1/sell/user/<ref>/transactions`, then
//!   `{"status": "started"|"success"|"failed"|"unknown"|"not_found", "asset": "ZEC", "network":
//!   "zcash", "to_address"?: "t1...|t3...", "sell_amount"?: "<ZEC>"}` from the newest
//!   transaction of the ref ([`sell_status_answer`]).
//! - `GET /v1/availability`: the configured document `{"enabled": true, "countries": {"US":
//!   {"buy": true, "sell": true}, ...}}`, without an upstream call.
//!
//! Every upstream call carries a fresh JWT ([`crate::core::auth::JwtEdDsa`]). Errors are fixed
//! JSON answers `{"error": <code>}`: `400 invalid_address`, `400 invalid_request` (any other
//! body problem), `401 invalid_signature` (a session request whose timestamp is out of the
//! window or whose signature is not the address's), `503 unavailable` (switched off with
//! `enabled = false`, a sell without a redirect, no usable key), `429 rate_limited` (the
//! upstream's 429, or a cap), `502 upstream` (any other upstream answer, an answer that is not
//! the expected shape, or no answer). With
//! `enabled = false` the availability document is `{"enabled": false, "countries": {}}`, so the
//! wallets hide the feature. An upstream body is never forwarded and never logged: CDP's errors
//! echo the address.
//!
//! The provider answers outside the gateway's generic forward and implements no
//! [`crate::core::provider::Provider`]: nothing can forward a request to its alias as received.

#[cfg(feature = "coinbase")]
pub mod signature;

#[cfg(feature = "coinbase")]
use std::collections::BTreeMap;
#[cfg(feature = "coinbase")]
use std::sync::Arc;
#[cfg(feature = "coinbase")]
use std::time::Duration;

#[cfg(feature = "coinbase")]
use serde_json::{json, Map, Value};

#[cfg(feature = "coinbase")]
use crate::core::auth::{JwtEdDsa, NonceSource, NONCE_BYTES};
#[cfg(feature = "coinbase")]
use crate::core::body::{
    self, BodyError, BodyErrorKind, Check, Field, Schema, BASE32, TRANSPARENT_HASH_BYTES,
    ZCASH_MAINNET_P2PKH, ZCASH_MAINNET_P2SH,
};
#[cfg(feature = "coinbase")]
use crate::core::provider::{Denial, RequestView, ResponseAction};

/// The provider kind.
pub const KIND: &str = "coinbase";

/// The routes of the alias, its whole operation policy.
pub const ROUTES: [(&str, &str); 3] = [
    ("POST", "/v1/session"),
    ("POST", "/v1/sell/status"),
    ("GET", "/v1/availability"),
];

/// The longest `redirect_url`.
pub const MAX_REDIRECT_URL_LEN: usize = 512;

/// Schemes a `redirect_url` may not have (compared without case): plain HTTP and the schemes
/// that run or embed content.
const DENIED_REDIRECT_SCHEMES: &[&str] = &["http", "javascript", "data", "file", "vbscript"];

/// Whether `url` may be the `redirect_url`: visible ASCII, at most [`MAX_REDIRECT_URL_LEN`]
/// bytes, a scheme (`[a-z][a-z0-9+.-]*:`) and something after it: `https`, or a custom app
/// scheme (an app's return link), never one of `http`, `javascript`, `data`, `file`,
/// `vbscript`. Coinbase ignores one that is not on the project's allowlist.
pub fn is_redirect_url(url: &str) -> bool {
    let Some((scheme, rest)) = url.split_once(':') else {
        return false;
    };
    !DENIED_REDIRECT_SCHEMES
        .iter()
        .any(|d| scheme.eq_ignore_ascii_case(d))
        && url.len() <= MAX_REDIRECT_URL_LEN
        && url.bytes().all(|b| (0x21..=0x7e).contains(&b))
        && !rest.is_empty()
        && scheme
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase())
        && scheme.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'+' | b'.' | b'-')
        })
}

/// The upstream of a coinbase integration, normalised: `base` = `scheme://host[:port]`, `host`
/// = `host[:port]` (as the JWT's `uri` names it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    pub base: String,
    pub host: String,
}

/// The hosts an `http://` upstream may name (a local stub); anything else must be `https://`.
const LOOPBACK: &[&str] = &["127.0.0.1", "localhost", "[::1]"];

/// `upstream` as an [`Origin`]: `https://host[:port]` (or `http://` with a loopback host),
/// at most a trailing `/` after it (no path, query, fragment or credentials), the host in
/// lower case, a port that is not the scheme's default. `None` otherwise.
pub fn upstream_origin(upstream: &str) -> Option<Origin> {
    let (scheme, rest) = match upstream.strip_prefix("https://") {
        Some(rest) => ("https", rest),
        None => ("http", upstream.strip_prefix("http://")?),
    };
    let host = rest.strip_suffix('/').unwrap_or(rest).to_ascii_lowercase();
    if !crate::core::auth::is_uri_host(&host) {
        return None;
    }
    let (name, port) = match host.rsplit_once(':') {
        Some((name, port)) if !name.ends_with(':') && port.bytes().all(|b| b.is_ascii_digit()) => {
            (name, Some(port))
        }
        _ => (host.as_str(), None),
    };
    let default: u16 = if scheme == "https" { 443 } else { 80 };
    // The port as a number (no leading zero: `is_uri_host`), never the scheme's default.
    if port.and_then(crate::core::auth::parse_port) == Some(default)
        || (scheme == "http" && !LOOPBACK.contains(&name))
    {
        return None;
    }
    Some(Origin {
        base: format!("{scheme}://{host}"),
        host,
    })
}

/// The asset of every session.
#[cfg(feature = "coinbase")]
pub const ASSET: &str = "ZEC";
/// The network of every session.
#[cfg(feature = "coinbase")]
pub const NETWORK: &str = "zcash";
/// The hosted buy (Onramp) page.
#[cfg(feature = "coinbase")]
pub const HOSTED_BUY: &str = "https://pay.coinbase.com/buy/select-asset";
/// The hosted sell (Offramp) page.
#[cfg(feature = "coinbase")]
pub const HOSTED_SELL: &str = "https://pay.coinbase.com/v3/sell/input";
/// The session token API.
#[cfg(feature = "coinbase")]
pub const TOKEN_PATH: &str = "/onramp/v1/token";
/// A session token is single use and lives 5 minutes.
#[cfg(feature = "coinbase")]
pub const SESSION_TTL_SECS: u64 = 300;
/// The `nbf` leeway of every token: a few seconds for an upstream clock slightly behind.
#[cfg(feature = "coinbase")]
pub const NBF_LEEWAY_SECS: u64 = 5;
/// The largest request body taken.
#[cfg(feature = "coinbase")]
pub const MAX_BODY_BYTES: usize = 1024;
/// The largest upstream body read.
#[cfg(feature = "coinbase")]
pub const MAX_UPSTREAM_BODY_BYTES: usize = 64 * 1024;
/// The fiat currencies a preset amount may be in.
#[cfg(feature = "coinbase")]
pub const FIATS: &[&str] = &["USD", "CAD", "GBP", "EUR"];
/// The `retry-after` of a `rate_limited` answer to an upstream 429: the upstream's own seconds
/// within these bounds, else the default.
#[cfg(feature = "coinbase")]
pub const RETRY_AFTER_BOUNDS: (u64, u64) = (1, 300);
#[cfg(feature = "coinbase")]
pub const RETRY_AFTER_DEFAULT: u64 = 60;

/// The fixed answers.
#[cfg(feature = "coinbase")]
pub mod answers {
    pub const INVALID_REQUEST: &[u8] = br#"{"error":"invalid_request"}"#;
    pub const INVALID_ADDRESS: &[u8] = br#"{"error":"invalid_address"}"#;
    pub const INVALID_SIGNATURE: &[u8] = br#"{"error":"invalid_signature"}"#;
    pub const UNAVAILABLE: &[u8] = br#"{"error":"unavailable"}"#;
    pub const RATE_LIMITED: &[u8] = br#"{"error":"rate_limited"}"#;
    pub const UPSTREAM: &[u8] = br#"{"error":"upstream"}"#;
}

#[cfg(feature = "coinbase")]
const ADDRESS: Check = Check::Base58Check {
    versions: &[ZCASH_MAINNET_P2PKH],
    payload_len: TRANSPARENT_HASH_BYTES,
};
/// A deposit address Coinbase gives for a sell: transparent, P2PKH or P2SH.
#[cfg(feature = "coinbase")]
const DEPOSIT_ADDRESS: Check = Check::Base58Check {
    versions: &[ZCASH_MAINNET_P2PKH, ZCASH_MAINNET_P2SH],
    payload_len: TRANSPARENT_HASH_BYTES,
};
/// `partnerUserRef`: 128 random bits or more in base32 (26 characters), under CDP's 50.
#[cfg(feature = "coinbase")]
const REF: Check = Check::Chars {
    charset: BASE32,
    min: 26,
    max: 40,
};
#[cfg(feature = "coinbase")]
const AMOUNT: Check = Check::Decimal {
    max_fraction: 2,
    min: "1",
    max: "10000",
};
#[cfg(feature = "coinbase")]
const ZEC_AMOUNT: Check = Check::Decimal {
    max_fraction: 8,
    min: "0",
    max: "21000000",
};
#[cfg(feature = "coinbase")]
const TOKEN: Check = Check::Chars {
    charset: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=+/.",
    min: 1,
    max: 2048,
};

/// The wallet's timestamp of a session request: decimal Unix seconds, no sign, no leading zero.
#[cfg(feature = "coinbase")]
const TIMESTAMP: Check = Check::Decimal {
    max_fraction: 0,
    min: "0",
    max: "9999999999",
};
/// The wallet's signature of a session request: base64 characters, bounded (decoded and
/// verified after the body is valid: [`signature::verify`]).
#[cfg(feature = "coinbase")]
const SIGNATURE: Check = Check::Chars {
    charset: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
    min: 1,
    max: 128,
};

#[cfg(feature = "coinbase")]
const SESSION: Schema = Schema {
    max_bytes: MAX_BODY_BYTES,
    fields: &[
        Field {
            name: "flow",
            required: true,
            check: Check::OneOf(&["buy", "sell"]),
        },
        Field {
            name: "address",
            required: true,
            check: ADDRESS,
        },
        Field {
            name: "ref",
            required: true,
            check: REF,
        },
        Field {
            name: "fiat",
            required: false,
            check: Check::OneOf(FIATS),
        },
        Field {
            name: "amount",
            required: false,
            check: AMOUNT,
        },
        Field {
            name: "timestamp",
            required: true,
            check: TIMESTAMP,
        },
        Field {
            name: "signature",
            required: true,
            check: SIGNATURE,
        },
    ],
};

#[cfg(feature = "coinbase")]
const SELL_STATUS: Schema = Schema {
    max_bytes: MAX_BODY_BYTES,
    fields: &[Field {
        name: "ref",
        required: true,
        check: REF,
    }],
};

/// One route of the alias.
#[cfg(feature = "coinbase")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Session,
    SellStatus,
    Availability,
}

#[cfg(feature = "coinbase")]
impl Route {
    /// The route as logged and labelled: its policy entry.
    pub fn label(self) -> &'static str {
        match self {
            Route::Session => "POST /v1/session",
            Route::SellStatus => "POST /v1/sell/status",
            Route::Availability => "GET /v1/availability",
        }
    }

    /// The route of `method path`: the method exactly (upper case), the path exactly (no
    /// query string).
    fn of(method: &str, path: &str) -> Option<Self> {
        [Route::Session, Route::SellStatus, Route::Availability]
            .into_iter()
            .find(|r| ROUTES[*r as usize] == (method, path))
    }
}

/// Where the key document of an integration is read from: its `[secrets]` entry.
#[cfg(feature = "coinbase")]
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretSource {
    /// The `[secrets]` name (logged, never the value).
    pub name: String,
    pub env: Option<String>,
    pub file: Option<String>,
}

/// The settings of one integration, as the configuration file renders them
/// ([`crate::core::config::COINBASE_RENDERED`]). They name the key's secret, never hold it.
#[cfg(feature = "coinbase")]
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub label: String,
    pub alias: String,
    pub upstream: String,
    pub secret: SecretSource,
    /// `false` when the file was loaded without its secrets (`--secrets=skip`): the key is not
    /// read.
    pub read_key: bool,
    pub ttl_secs: u64,
    pub enabled: bool,
    pub redirect_url: Option<String>,
    pub countries: BTreeMap<String, Country>,
    /// The cap of `POST /v1/session` (`REQUESTS/WINDOWs`).
    pub rate_limit: String,
    /// The cap of `POST /v1/sell/status`.
    pub status_rate_limit: String,
}

/// One country of the availability document.
#[cfg(feature = "coinbase")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Country {
    pub buy: bool,
    pub sell: bool,
}

#[cfg(feature = "coinbase")]
impl Settings {
    /// The settings of every integration in `rendered` (the JSON array the file renders).
    pub fn parse_rendered(rendered: &str) -> anyhow::Result<Vec<Settings>> {
        serde_json::from_str(rendered).map_err(|e| {
            anyhow::anyhow!("the coinbase integrations of the file do not read back: {e}")
        })
    }

    /// Whether any country offers sell.
    pub fn sells(&self) -> bool {
        self.countries.values().any(|c| c.sell)
    }
}

/// An answer of the provider: always JSON. Its debug form shows the status and length only.
#[cfg(feature = "coinbase")]
#[derive(Clone, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    pub body: Vec<u8>,
}

#[cfg(feature = "coinbase")]
impl std::fmt::Debug for Answer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Answer")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish()
    }
}

#[cfg(feature = "coinbase")]
impl Answer {
    fn fixed(status: u16, body: &[u8]) -> Self {
        Self {
            status,
            body: body.to_vec(),
        }
    }

    /// `503 unavailable`.
    pub fn unavailable() -> Self {
        Self::fixed(503, answers::UNAVAILABLE)
    }

    /// `429 rate_limited`.
    pub fn rate_limited() -> Self {
        Self::fixed(429, answers::RATE_LIMITED)
    }

    /// `502 upstream`.
    pub fn upstream() -> Self {
        Self::fixed(502, answers::UPSTREAM)
    }

    /// The content type of every answer.
    pub const CONTENT_TYPE: &'static str = "application/json";
}

/// What the gateway does with a request to the alias.
#[cfg(feature = "coinbase")]
pub enum Plan {
    /// Not one of the routes (or a path trick): the gateway's own policy answer (inner 403).
    Denied(Denial),
    /// Answered here, without an upstream call: `refusal` is the bounded reason of a refusal
    /// (`disabled`, `invalid_request`, `invalid_address`, `unexpected_body`,
    /// `stale_timestamp`, `invalid_signature`, `sell_unavailable`), `None` for the
    /// availability document.
    Local {
        answer: Answer,
        refusal: Option<&'static str>,
    },
    /// The upstream call to make (after the key, the concurrency permits and the cap).
    Upstream(Call),
}

#[cfg(feature = "coinbase")]
impl std::fmt::Debug for Plan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Plan::Denied(denial) => f.debug_tuple("Denied").field(denial).finish(),
            Plan::Local { answer, refusal } => f
                .debug_struct("Local")
                .field("answer", answer)
                .field("refusal", refusal)
                .finish(),
            Plan::Upstream(call) => f.debug_tuple("Upstream").field(call).finish(),
        }
    }
}

/// An upstream call: the request the module built from the validated body. Its debug form
/// shows the route only (the path and body hold the address or the ref).
#[cfg(feature = "coinbase")]
#[derive(Clone, PartialEq, Eq)]
pub struct Call {
    pub route: Route,
    pub method: &'static str,
    /// The upstream path.
    pub path: String,
    /// The JSON body, if any.
    pub body: Option<Vec<u8>>,
    reference: String,
    session: Option<SessionParams>,
}

#[cfg(feature = "coinbase")]
#[derive(Clone, PartialEq, Eq)]
struct SessionParams {
    sell: bool,
    fiat: Option<String>,
    amount: Option<String>,
}

#[cfg(feature = "coinbase")]
impl std::fmt::Debug for Call {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Call")
            .field("route", &self.route)
            .finish_non_exhaustive()
    }
}

/// The answer to an upstream response, and how it ended for the logs and metrics: `ok`,
/// `rate_limited` (an upstream 429, with the `retry-after` to send), `upstream_status` (any
/// other status but 2xx) or `upstream_shape` (a 2xx whose body is not what the route expects).
#[cfg(feature = "coinbase")]
#[derive(Clone, PartialEq, Eq)]
pub struct Finished {
    pub answer: Answer,
    pub outcome: &'static str,
    pub retry_after: Option<u64>,
}

#[cfg(feature = "coinbase")]
impl std::fmt::Debug for Finished {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Finished")
            .field("answer", &self.answer)
            .field("outcome", &self.outcome)
            .field("retry_after", &self.retry_after)
            .finish()
    }
}

/// The provider of one alias.
#[cfg(feature = "coinbase")]
#[derive(Clone)]
pub struct Coinbase {
    label: String,
    alias: String,
    origin: Origin,
    signer: Option<JwtEdDsa>,
    enabled: bool,
    redirect_url: Option<String>,
    availability: Vec<u8>,
    session_cap: (u64, Duration),
    status_cap: (u64, Duration),
    nonces: Arc<dyn NonceSource>,
}

#[cfg(feature = "coinbase")]
impl std::fmt::Debug for Coinbase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Coinbase")
            .field("label", &self.label)
            .field("alias", &self.alias)
            .field("enabled", &self.enabled)
            .field("signer", &self.signer.is_some())
            .finish_non_exhaustive()
    }
}

/// Percent-encoding of a query parameter value: every byte but `A-Z a-z 0-9 - . _ ~`.
#[cfg(feature = "coinbase")]
fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A URL of `base` with the query `params` (values percent-encoded), in order.
#[cfg(feature = "coinbase")]
fn with_query(base: &str, params: &[(&str, &str)]) -> String {
    let query: Vec<String> = params
        .iter()
        .map(|(name, value)| format!("{name}={}", encode(value)))
        .collect();
    format!("{base}?{}", query.join("&"))
}

/// The hosted buy (Onramp) page of a session: `sessionToken`, `defaultAsset`, `defaultNetwork`,
/// `partnerUserRef`, then `redirectUrl`, `fiatCurrency` and `presetFiatAmount` when given.
/// Parameter names per CDP's Onramp URL reference (see CONFIG.md for the list to verify
/// against the live project).
#[cfg(feature = "coinbase")]
pub fn buy_url(
    token: &str,
    reference: &str,
    redirect: Option<&str>,
    fiat: Option<&str>,
    amount: Option<&str>,
) -> String {
    let mut params = vec![
        ("sessionToken", token),
        ("defaultAsset", ASSET),
        ("defaultNetwork", NETWORK),
        ("partnerUserRef", reference),
    ];
    params.extend(redirect.map(|r| ("redirectUrl", r)));
    params.extend(fiat.map(|f| ("fiatCurrency", f)));
    params.extend(amount.map(|a| ("presetFiatAmount", a)));
    with_query(HOSTED_BUY, &params)
}

/// The hosted sell (Offramp) page of a session: `sessionToken`, `partnerUserRef`,
/// `redirectUrl` (required: the wallet resumes the sell from it), `defaultAsset`,
/// `defaultNetwork`, then `fiatCurrency` and `presetFiatAmount` when given. Parameter names
/// per CDP's Offramp URL reference (see CONFIG.md for the list to verify).
#[cfg(feature = "coinbase")]
pub fn sell_url(
    token: &str,
    reference: &str,
    redirect: &str,
    fiat: Option<&str>,
    amount: Option<&str>,
) -> String {
    let mut params = vec![
        ("sessionToken", token),
        ("partnerUserRef", reference),
        ("redirectUrl", redirect),
        ("defaultAsset", ASSET),
        ("defaultNetwork", NETWORK),
    ];
    params.extend(fiat.map(|f| ("fiatCurrency", f)));
    params.extend(amount.map(|a| ("presetFiatAmount", a)));
    with_query(HOSTED_SELL, &params)
}

/// The refusal code of a body error: the address, or anything else.
#[cfg(feature = "coinbase")]
fn refusal(error: &BodyError) -> (&'static str, &'static [u8]) {
    match (error.field, error.kind) {
        (Some("address"), BodyErrorKind::Invalid | BodyErrorKind::NotString) => {
            ("invalid_address", answers::INVALID_ADDRESS)
        }
        _ => ("invalid_request", answers::INVALID_REQUEST),
    }
}

/// The `retry-after` seconds of a `rate_limited` answer to an upstream 429 whose own
/// `retry-after` is `upstream` (seconds; a date or anything else is the default).
#[cfg(feature = "coinbase")]
pub fn retry_after(upstream: Option<&str>) -> u64 {
    upstream
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map_or(RETRY_AFTER_DEFAULT, |secs| {
            secs.clamp(RETRY_AFTER_BOUNDS.0, RETRY_AFTER_BOUNDS.1)
        })
}

#[cfg(feature = "coinbase")]
impl Coinbase {
    /// The provider of `settings` with `signer` (`None`: no usable key; every upstream route
    /// then answers `unavailable`) and the randomness of the JWT nonces. Refused: an upstream
    /// that is no [`upstream_origin`], a `redirect_url` that is not valid or missing while a
    /// country offers sell, a cap that is no `REQUESTS/WINDOWs`.
    pub fn new(
        settings: &Settings,
        signer: Option<JwtEdDsa>,
        nonces: Arc<dyn NonceSource>,
    ) -> anyhow::Result<Self> {
        let alias = &settings.alias;
        let Some(origin) = upstream_origin(&settings.upstream) else {
            anyhow::bail!(
                "coinbase integration '{alias}': the upstream must be https://host[:port] (http:// only for a loopback host), lower case, without a path or the default port"
            );
        };
        match &settings.redirect_url {
            Some(url) if !is_redirect_url(url) => {
                anyhow::bail!("coinbase integration '{alias}': the redirect_url is not a valid URL")
            }
            None if settings.sells() => anyhow::bail!(
                "coinbase integration '{alias}': a country offers sell, which needs a redirect_url"
            ),
            _ => {}
        }
        let cap = |key: &str, spec: &str| {
            crate::core::caps::parse_rate_spec(&format!("{key} of '{alias}'"), spec)
        };
        let session_cap = cap("rate_limit", &settings.rate_limit)?;
        let status_cap = cap("status_rate_limit", &settings.status_rate_limit)?;
        let countries: Map<String, Value> = settings
            .countries
            .iter()
            .map(|(code, c)| (code.clone(), json!({"buy": c.buy, "sell": c.sell})))
            .collect();
        let availability = if settings.enabled {
            json!({"enabled": true, "countries": countries})
        } else {
            json!({"enabled": false, "countries": {}})
        };
        Ok(Self {
            label: settings.label.clone(),
            alias: settings.alias.to_ascii_lowercase(),
            origin,
            signer: signer.map(|s| s.with_nbf_leeway(NBF_LEEWAY_SECS)),
            enabled: settings.enabled,
            redirect_url: settings.redirect_url.clone(),
            availability: availability.to_string().into_bytes(),
            session_cap,
            status_cap,
            nonces,
        })
    }

    /// The table label of the integration (the `integration` metric label).
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The alias (lowercase).
    pub fn alias(&self) -> &str {
        &self.alias
    }

    /// The upstream base URL (`scheme://host[:port]`).
    pub fn upstream(&self) -> &str {
        &self.origin.base
    }

    /// The upstream `host[:port]`.
    pub fn upstream_host(&self) -> &str {
        &self.origin.host
    }

    /// Whether it is switched on.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Whether it has a usable key.
    pub fn has_signer(&self) -> bool {
        self.signer.is_some()
    }

    /// The cap of the upstream calls of `route` (`requests`, `window`); none for the
    /// availability document, which calls nothing.
    pub fn cap(&self, route: Route) -> Option<(u64, Duration)> {
        match route {
            Route::Session => Some(self.session_cap),
            Route::SellStatus => Some(self.status_cap),
            Route::Availability => None,
        }
    }

    /// What to do with `req` at `now` (seconds since the Unix epoch, the gateway's clock): the
    /// policy refusal, a local answer (switched off, an invalid body, a session request whose
    /// timestamp or signature is refused, the availability document), or the upstream call.
    pub fn plan(&self, req: &RequestView<'_>, now: u64) -> Plan {
        // The route first: anything else is the gateway's policy refusal, whatever the switch.
        if let Some(reason) = crate::core::route::path_trick(req.path) {
            return Plan::Denied(Denial::PathTrick(reason));
        }
        let Some(route) = Route::of(req.method, req.path) else {
            return Plan::Denied(Denial::NotInPolicy);
        };
        let local = |status, body: &[u8], refusal| Plan::Local {
            answer: Answer::fixed(status, body),
            refusal,
        };
        if !self.enabled {
            return match route {
                Route::Availability => local(200, &self.availability[..], None),
                _ => local(503, answers::UNAVAILABLE, Some("disabled")),
            };
        }
        let schema = match route {
            Route::Availability if req.body.is_empty() => {
                return local(200, &self.availability[..], None)
            }
            Route::Availability => {
                return local(400, answers::INVALID_REQUEST, Some("unexpected_body"))
            }
            Route::Session => &SESSION,
            Route::SellStatus => &SELL_STATUS,
        };
        let values = match body::validate(schema, req.body) {
            Ok(values) => values,
            Err(error) => {
                let (code, body) = refusal(&error);
                return local(400, body, Some(code));
            }
        };
        let get = |name: &str| values.get(name).map(str::to_string);
        let reference = get("ref").unwrap_or_default();
        match route {
            Route::Session => {
                if values.get("amount").is_some() && values.get("fiat").is_none() {
                    return local(400, answers::INVALID_REQUEST, Some("invalid_request"));
                }
                // The wallet's signature, before anything is signed or called: a fresh
                // timestamp, then the key of exactly this address. Both refusals are the
                // same answer; neither echoes anything of the request.
                let address = values.get("address").unwrap_or_default();
                let timestamp = values.get("timestamp").and_then(|t| t.parse::<u64>().ok());
                let Some(timestamp) = timestamp.filter(|&t| signature::is_fresh(t, now)) else {
                    return local(401, answers::INVALID_SIGNATURE, Some("stale_timestamp"));
                };
                let signed = values.get("signature").unwrap_or_default();
                if signature::verify(address, timestamp, signed).is_err() {
                    return local(401, answers::INVALID_SIGNATURE, Some("invalid_signature"));
                }
                let sell = values.get("flow") == Some("sell");
                if sell && self.redirect_url.is_none() {
                    return local(503, answers::UNAVAILABLE, Some("sell_unavailable"));
                }
                // Asset and network are constants; the address is the only input, and no
                // client IP is ever part of the request.
                let body = json!({
                    "addresses": [{"address": get("address").unwrap_or_default(), "blockchains": [NETWORK]}],
                    "assets": [ASSET],
                });
                Plan::Upstream(Call {
                    route,
                    method: "POST",
                    path: TOKEN_PATH.to_string(),
                    body: Some(body.to_string().into_bytes()),
                    reference,
                    session: Some(SessionParams {
                        sell,
                        fiat: get("fiat"),
                        amount: get("amount"),
                    }),
                })
            }
            Route::SellStatus => Plan::Upstream(Call {
                route,
                method: "GET",
                // `ref` is base32: nothing in it needs encoding.
                path: format!("/onramp/v1/sell/user/{reference}/transactions"),
                body: None,
                reference,
                session: None,
            }),
            Route::Availability => unreachable!("answered above"),
        }
    }

    /// The `Authorization` value of `call` at `now` (seconds since the Unix epoch): a fresh
    /// JWT. `None` without a usable key.
    pub fn authorization(&self, call: &Call, now: u64) -> Option<String> {
        let signer = self.signer.as_ref()?;
        let mut nonce = [0u8; NONCE_BYTES];
        self.nonces.fill(&mut nonce);
        signer
            .token(call.method, &self.origin.host, &call.path, now, &nonce)
            .ok()
            .map(|token| format!("Bearer {token}"))
    }

    /// The upstream request headers of `call` besides `authorization`, in order: nothing of
    /// the client's.
    pub fn headers(call: &Call) -> Vec<(&'static str, &'static str)> {
        let mut out = vec![("accept", "application/json")];
        if call.body.is_some() {
            out.push(("content-type", "application/json"));
        }
        out
    }

    /// What an upstream status means before any body is read: a 2xx is rewritten from its
    /// body ([`Self::finish`]); a 429 is `rate_limited`, any other status `upstream`, both
    /// without reading the body.
    pub fn response_action(status: u16) -> ResponseAction {
        match status {
            200..=299 => ResponseAction::Rewrite,
            429 => ResponseAction::Replace {
                status: 429,
                body: answers::RATE_LIMITED,
            },
            _ => ResponseAction::Replace {
                status: 502,
                body: answers::UPSTREAM,
            },
        }
    }

    /// The answer to the upstream's `status` for `call` at `now`: `body` is the upstream body
    /// of a 2xx (not read otherwise), `retry_after` the upstream's `retry-after` header.
    pub fn finish(
        &self,
        call: &Call,
        status: u16,
        body: &[u8],
        retry_after_header: Option<&str>,
        now: u64,
    ) -> Finished {
        let fail = |outcome| Finished {
            answer: Answer::upstream(),
            outcome,
            retry_after: None,
        };
        match Self::response_action(status) {
            ResponseAction::Replace { status: 429, body } => {
                return Finished {
                    answer: Answer::fixed(429, body),
                    outcome: "rate_limited",
                    retry_after: Some(retry_after(retry_after_header)),
                }
            }
            ResponseAction::Rewrite => {}
            _ => return fail("upstream_status"),
        }
        if body.len() > MAX_UPSTREAM_BODY_BYTES {
            return fail("upstream_shape");
        }
        let Ok(doc) = serde_json::from_slice::<Value>(body) else {
            return fail("upstream_shape");
        };
        let answer = match (call.route, &call.session) {
            (Route::Session, Some(session)) => self.session_answer(&doc, call, session, now),
            (Route::SellStatus, _) => sell_status_answer(&doc, &call.reference),
            _ => None,
        };
        match answer {
            Some(body) => Finished {
                answer: Answer { status: 200, body },
                outcome: "ok",
                retry_after: None,
            },
            None => fail("upstream_shape"),
        }
    }

    /// `{"url", "expires_at"}` from the token API's `{"token": ...}`.
    fn session_answer(
        &self,
        doc: &Value,
        call: &Call,
        session: &SessionParams,
        now: u64,
    ) -> Option<Vec<u8>> {
        let token = doc.as_object()?.get("token")?.as_str()?;
        if !TOKEN.accepts(token) {
            return None;
        }
        let (fiat, amount) = (session.fiat.as_deref(), session.amount.as_deref());
        let url = if session.sell {
            // A sell never builds a URL without its redirect (refused in `plan`).
            sell_url(
                token,
                &call.reference,
                self.redirect_url.as_deref()?,
                fiat,
                amount,
            )
        } else {
            buy_url(
                token,
                &call.reference,
                self.redirect_url.as_deref(),
                fiat,
                amount,
            )
        };
        Some(
            json!({"url": url, "expires_at": now.saturating_add(SESSION_TTL_SECS)})
                .to_string()
                .into_bytes(),
        )
    }
}

/// A string member of `object`: `Some(None)` when absent, null or empty, `None` when it is not
/// a string.
#[cfg(feature = "coinbase")]
fn text_member<'a>(object: &'a Map<String, Value>, name: &str) -> Option<Option<&'a str>> {
    match object.get(name) {
        None | Some(Value::Null) => Some(None),
        Some(Value::String(s)) if s.is_empty() => Some(None),
        Some(Value::String(s)) => Some(Some(s.as_str())),
        Some(_) => None,
    }
}

/// An RFC 3339 date-time (`YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)`) as UTC: seconds since the
/// Unix epoch and nanoseconds. `None` when it is not one.
#[cfg(feature = "coinbase")]
pub fn rfc3339_utc(text: &str) -> Option<(i64, u32)> {
    let b = text.as_bytes();
    let num = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = b.get(range)?;
        if part.is_empty() || !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        Some(part.iter().fold(0i64, |n, d| n * 10 + i64::from(d - b'0')))
    };
    let at = |i: usize, c: u8| b.get(i) == Some(&c);
    if !(at(4, b'-')
        && at(7, b'-')
        && matches!(b.get(10), Some(b'T' | b't' | b' '))
        && at(13, b':')
        && at(16, b':'))
    {
        return None;
    }
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_month = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month[(month - 1) as usize]
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let mut i = 19;
    let mut nanos = 0u32;
    if at(i, b'.') {
        let start = i + 1;
        let mut end = start;
        while b.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
        }
        if end == start || end - start > 9 {
            return None;
        }
        let frac = num(start..end)? as u32;
        nanos = frac * 10u32.pow(9 - (end - start) as u32);
        i = end;
    }
    let offset = match b.get(i) {
        Some(b'Z' | b'z') if b.len() == i + 1 => 0,
        Some(sign @ (b'+' | b'-')) if b.len() == i + 6 && at(i + 3, b':') => {
            let (h, m) = (num(i + 1..i + 3)?, num(i + 4..i + 6)?);
            if h > 23 || m > 59 {
                return None;
            }
            let secs = h * 3600 + m * 60;
            if *sign == b'+' {
                secs
            } else {
                -secs
            }
        }
        _ => return None,
    };
    // Days from the civil date (proleptic Gregorian), H. Hinnant's algorithm.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some((
        days * 86_400 + hour * 3600 + minute * 60 + second - offset,
        nanos,
    ))
}

/// The status answer from the transaction status API's `{"transactions": [...]}`: an empty
/// list is `not_found`; otherwise the newest transaction (by `created_at`, RFC 3339, compared
/// in UTC; a candidate without one is refused) among those of
/// `reference` (`partner_user_ref`), or among all when none names a ref. `None` (an `upstream`
/// answer) when the document is not that shape, every named ref is another one, or the chosen
/// transaction lacks its status, asset (`ZEC`) or network (`zcash`), names an amount without
/// its currency (`ZEC`), or a deposit address or amount that is not valid.
#[cfg(feature = "coinbase")]
pub fn sell_status_answer(doc: &Value, reference: &str) -> Option<Vec<u8>> {
    let transactions = doc.as_object()?.get("transactions")?.as_array()?;
    let mut out = Map::new();
    out.insert("asset".into(), Value::String(ASSET.into()));
    out.insert("network".into(), Value::String(NETWORK.into()));
    if transactions.is_empty() {
        out.insert("status".into(), Value::String("not_found".into()));
        return Some(Value::Object(out).to_string().into_bytes());
    }
    let mut all = Vec::with_capacity(transactions.len());
    for tx in transactions {
        all.push(tx.as_object()?);
    }
    let mut mine = Vec::new();
    let mut named = false;
    for tx in &all {
        if let Some(r) = text_member(tx, "partner_user_ref")? {
            named = true;
            if r == reference {
                mine.push(*tx);
            }
        }
    }
    let candidates = match (named, mine.is_empty()) {
        (false, _) => all,
        (true, false) => mine,
        (true, true) => return None,
    };
    // Every candidate has a valid `created_at`, compared as UTC instants.
    let mut dated = Vec::with_capacity(candidates.len());
    for tx in candidates {
        dated.push((rfc3339_utc(text_member(tx, "created_at")??)?, tx));
    }
    let (_, tx) = dated.into_iter().max_by(|a, b| a.0.cmp(&b.0))?;
    let status = match text_member(tx, "status")? {
        Some("TRANSACTION_STATUS_STARTED") => "started",
        Some("TRANSACTION_STATUS_SUCCESS") => "success",
        Some("TRANSACTION_STATUS_FAILED") => "failed",
        Some(_) => "unknown",
        None => return None,
    };
    if text_member(tx, "asset")? != Some(ASSET) || text_member(tx, "network")? != Some(NETWORK) {
        return None;
    }
    out.insert("status".into(), Value::String(status.into()));
    if let Some(address) = text_member(tx, "to_address")? {
        if !DEPOSIT_ADDRESS.accepts(address) {
            return None;
        }
        out.insert("to_address".into(), Value::String(address.into()));
    }
    match tx.get("sell_amount") {
        None | Some(Value::Null) => {}
        Some(Value::Object(amount)) => {
            if let Some(value) = text_member(amount, "value")? {
                if text_member(amount, "currency")? != Some(ASSET) || !ZEC_AMOUNT.accepts(value) {
                    return None;
                }
                out.insert("sell_amount".into(), Value::String(value.into()));
            }
        }
        Some(_) => return None,
    }
    Some(Value::Object(out).to_string().into_bytes())
}

#[cfg(all(test, feature = "coinbase"))]
mod tests;

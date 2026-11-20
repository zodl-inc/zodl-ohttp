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

//! The `coinbase` integrations ([`zodl_ohttp_integrations::coinbase`]): their providers, read
//! from the configuration file in force, and the answer to a request to one of their aliases.
//!
//! Only a configuration file sets them (`[integrations.<label>] kind = "coinbase"`), and only
//! on a mainnet gateway (`NETWORK=mainnet`): no environment variable can (the export of an
//! environment has none). The alias is a `BACKENDS` alias like any
//! other (routing, replay class: every route a WRITE, labels), but its requests never take the
//! generic forward: the provider validates the body, builds the upstream request, signs it,
//! and scrubs the answer, all here, with a cap per route. Nothing of the client's request but
//! the validated values reaches the upstream; no body, address, amount, ref, token or upstream
//! path is logged.
//!
//! The key document is read once with every other secret of the files
//! ([`crate::config_source::secret_value`]; it is never part of the rendered policy); the
//! provider's copy is wiped after the signer is made. A key that does not read as
//! a key leaves the provider without a signer: its two POST routes answer `503 unavailable`,
//! the availability document is still served, the process starts (one error at startup names
//! the secret); `--check-config` refuses it.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{anyhow, bail, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use tracing::{info, warn};
use zodl_ohttp_integrations::coinbase::{
    Answer, Call, Coinbase, Finished, Plan, Route, Settings, MAX_UPSTREAM_BODY_BYTES,
};
use zodl_ohttp_integrations::core::auth::{JwtEdDsa, NonceSource};
use zodl_ohttp_integrations::core::caps::RateWindow;
use zodl_ohttp_integrations::core::config::COINBASE_RENDERED;
use zodl_ohttp_integrations::core::provider::RequestView;

use crate::ohttp::{InnerRequest, InnerResponse};
use crate::AppState;

/// The network a coinbase integration may run on (Coinbase has no ZEC testnet).
pub const NETWORK: &str = "mainnet";

/// What became of the key of an integration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyState {
    /// Read and usable.
    Loaded,
    /// Not read: the file was loaded without its secrets (`--secrets=skip`).
    Skipped,
    /// Read, but no usable key: why (never a part of the value).
    Invalid(String),
}

/// One coinbase integration: its provider, what became of its key, and the caps of its two
/// upstream routes.
pub struct Entry {
    pub provider: Coinbase,
    pub key: KeyState,
    /// The `[secrets]` name of the key (logged, never the value).
    pub secret: String,
    session_cap: parking_lot::Mutex<RateWindow>,
    status_cap: parking_lot::Mutex<RateWindow>,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("provider", &self.provider)
            .field("key", &self.key)
            .field("secret", &self.secret)
            .finish_non_exhaustive()
    }
}

impl Entry {
    /// An entry of `provider` with its key state and secret name.
    pub fn new(provider: Coinbase, key: KeyState, secret: &str) -> Self {
        let now = Instant::now();
        let window = |route| {
            let (limit, window) = provider.cap(route).unwrap_or((1, Duration::from_secs(1)));
            parking_lot::Mutex::new(RateWindow::new(limit, window, now))
        };
        let session_cap = window(Route::Session);
        let status_cap = window(Route::SellStatus);
        Self {
            provider,
            key,
            secret: secret.to_string(),
            session_cap,
            status_cap,
        }
    }

    /// Why the key is not usable, if it was read and is not (for `--check-config` and the
    /// startup log): names the integration and the secret, never the value.
    pub fn key_problem(&self) -> Option<String> {
        match &self.key {
            KeyState::Invalid(why) => Some(format!(
                "coinbase integration '{}': the key of secret '{}' is not usable: {why}",
                self.provider.alias(),
                self.secret
            )),
            _ => None,
        }
    }

    /// Count one upstream call of `route` against its cap: `Err(retry_after_secs)` when spent.
    fn spend(&self, route: Route) -> Result<(), u64> {
        let cap = match route {
            Route::Session => &self.session_cap,
            Route::SellStatus => &self.status_cap,
            Route::Availability => return Ok(()),
        };
        cap.lock().check_and_increment(Instant::now())
    }
}

/// The coinbase integrations of the policy in force, by alias (lowercase). Clones share them.
#[derive(Clone, Default)]
pub struct Integrations(Arc<BTreeMap<String, Arc<Entry>>>);

impl std::fmt::Debug for Integrations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.0.values()).finish()
    }
}

/// The operating system's random generator, for the JWT nonces.
struct OsNonces;

impl NonceSource for OsNonces {
    fn fill(&self, out: &mut [u8]) {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(out);
    }
}

/// The upstream of `settings` parsed as a URI once more: `scheme://authority` with no path
/// beyond `/`, no query, the authority the provider's.
fn check_upstream_uri(provider: &Coinbase) -> Result<()> {
    let uri: hyper::Uri = provider
        .upstream()
        .parse()
        .map_err(|_| anyhow!("the upstream is not a URI"))?;
    let path_ok = matches!(uri.path(), "" | "/") && uri.query().is_none();
    let authority_ok = uri
        .authority()
        .is_some_and(|a| a.as_str() == provider.upstream_host());
    if !(path_ok && authority_ok && matches!(uri.scheme_str(), Some("https" | "http"))) {
        bail!("the upstream is not scheme://host[:port]");
    }
    Ok(())
}

/// The key of `settings`: the value its secret was read as by the files (a copy, wiped after
/// use), made a signer.
fn read_key(settings: &Settings) -> (Option<JwtEdDsa>, KeyState) {
    if !settings.read_key {
        return (None, KeyState::Skipped);
    }
    // Read once, with every other secret of the files (`config_source::load_files`).
    let Some(document) = crate::config_source::secret_value(&settings.secret.name) else {
        return (
            None,
            KeyState::Invalid("the files did not read it".to_string()),
        );
    };
    match JwtEdDsa::from_cdp_json(&document, settings.ttl_secs) {
        Ok(signer) => (Some(signer), KeyState::Loaded),
        Err(e) => (None, KeyState::Invalid(e.to_string())),
    }
}

impl Integrations {
    /// The providers of the configuration file in force ([`crate::config_source::file_value`])
    /// on a gateway of `network`; none without one. A table on another network than mainnet, or
    /// whose settings are not valid, is an error; a key that is not usable is not (see the
    /// module documentation).
    pub fn from_policy(network: &str) -> Result<Self> {
        let Some(rendered) = crate::config_source::file_value(COINBASE_RENDERED) else {
            return Ok(Self::default());
        };
        let mut entries = Vec::new();
        for settings in Settings::parse_rendered(&rendered)? {
            if network != NETWORK {
                bail!(
                    "Invalid coinbase integration '{}': kind coinbase runs on a mainnet gateway only (NETWORK is '{network}')",
                    settings.alias
                );
            }
            let (signer, key) = read_key(&settings);
            let provider = Coinbase::new(&settings, signer, Arc::new(OsNonces))?;
            check_upstream_uri(&provider)
                .map_err(|e| anyhow!("Invalid coinbase integration '{}': {e}", settings.alias))?;
            entries.push(Entry::new(provider, key, &settings.secret.name));
        }
        Ok(Self::from_entries(entries))
    }

    /// A set of entries (by their aliases).
    pub fn from_entries(entries: Vec<Entry>) -> Self {
        Self(Arc::new(
            entries
                .into_iter()
                .map(|e| (e.provider.alias().to_ascii_lowercase(), Arc::new(e)))
                .collect(),
        ))
    }

    /// The entry of `authority` (any case), if it is a coinbase alias.
    pub fn get(&self, authority: &str) -> Option<Arc<Entry>> {
        self.0.get(&authority.to_ascii_lowercase()).cloned()
    }

    /// Whether `authority_lower` is a coinbase alias.
    pub fn contains(&self, authority_lower: &str) -> bool {
        self.0.contains_key(authority_lower)
    }

    /// Whether there is none.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The entries.
    pub fn iter(&self) -> impl Iterator<Item = &Arc<Entry>> {
        self.0.values()
    }
}

/// `answer` as an inner response (always JSON), with `extra` headers.
fn json(answer: Answer, extra: Vec<(String, String)>) -> InnerResponse {
    let mut headers = vec![("content-type".to_string(), Answer::CONTENT_TYPE.to_string())];
    headers.extend(extra);
    InnerResponse {
        status: answer.status,
        headers,
        body: answer.body,
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The label of an answer of the provider for `ohttp_requests_total`'s status label.
pub fn outcome_label(status: u16) -> &'static str {
    match status {
        200..=299 => "success",
        400 => "invalid_request",
        403 => "policy_denied",
        429 => "third_party_limited",
        502 => "upstream_error",
        503 => "unavailable",
        _ => "other",
    }
}

/// The answer to `inner_request` for the alias of `entry`: the policy refusal (the gateway's
/// inner 403), an answer of the provider without an upstream call (switched off, an invalid
/// body, the availability document), `unavailable` without a key or a concurrency permit, the
/// route's cap (`rate_limited`), or the upstream call (signed, built by the provider) and its
/// scrubbed answer. Never an error: every failure is one of the provider's fixed answers.
pub async fn answer(
    state: &Arc<AppState>,
    inner_request: &InnerRequest,
    entry: &Entry,
) -> InnerResponse {
    let provider = &entry.provider;
    let config = &state.config;
    let network = config.network.as_str();
    let label = provider.label();
    let view = RequestView {
        method: &inner_request.method,
        path: &inner_request.path,
        headers: &inner_request.headers,
        body: &inner_request.body,
    };
    let call = match provider.plan(&view) {
        Plan::Denied(denial) => {
            warn!(
                policy = "deny",
                integration = label,
                authority = %inner_request.authority,
                method = %inner_request.method,
                reason = denial.reason(),
                network,
                "Operation denied by policy"
            );
            crate::health::record_upstream_request(
                network,
                "policy_denied",
                "other",
                403,
                "-",
                0.0,
            );
            crate::health::record_policy_denied(&inner_request.authority);
            crate::health::record_integration_denied(label, "policy");
            return InnerResponse {
                status: 403,
                headers: vec![("content-type".to_string(), "text/plain".to_string())],
                body: b"policy denied".to_vec(),
            };
        }
        Plan::Local { answer, refusal } => {
            if let Some(reason) = refusal {
                info!(
                    integration = label,
                    reason, network, "Integration request refused without an upstream call"
                );
                crate::health::record_integration_denied(label, reason);
            }
            return json(answer, Vec::new());
        }
        Plan::Upstream(call) => call,
    };
    let route = call.route.label();

    // A signer first: without one nothing is spent.
    let now = unix_now();
    let Some(authorization) = provider.authorization(&call, now) else {
        crate::health::record_integration_sign_failure(label);
        return json(Answer::unavailable(), Vec::new());
    };

    // Then the concurrency permits, then the route's cap: a 503 spends no budget.
    let backend = crate::health::normalize_backend(
        &inner_request.authority,
        &config.gateway_hosts,
        &config.backends,
    );
    let _global = match state.global_semaphore.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            warn!(backend, "Global upstream limit reached");
            crate::health::record_upstream_request(network, &backend, "other", 503, "-", 0.0);
            return json(Answer::unavailable(), Vec::new());
        }
    };
    let semaphore = crate::enforcement::get_backend_semaphore(
        &backend,
        config.max_inflight_per_backend,
        &state.per_backend_semaphores,
    );
    let _permit = match semaphore.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            warn!(backend, "Per-backend upstream limit reached");
            crate::health::record_upstream_request(network, &backend, "other", 503, "-", 0.0);
            return json(Answer::unavailable(), Vec::new());
        }
    };
    if let Err(retry_after) = entry.spend(call.route) {
        warn!(
            integration = label,
            route, retry_after, network, "Integration upstream cap reached (inner 429)"
        );
        crate::health::record_third_party_limited(network, provider.alias());
        crate::health::record_integration_denied(label, "rate_limited");
        return json(
            Answer::rate_limited(),
            vec![("retry-after".to_string(), retry_after.to_string())],
        );
    }

    let started = Instant::now();
    let deadline = Duration::from_secs(config.lwd_timeout_secs);
    let result = tokio::time::timeout(deadline, call_upstream(provider, &call, &authorization))
        .await
        .unwrap_or_else(|_| Err(anyhow!("no answer within {deadline:?}")));
    let (upstream_status, finished) = match result {
        Ok(upstream) => (
            upstream.status,
            provider.finish(
                &call,
                upstream.status,
                &upstream.body,
                upstream.retry_after.as_deref(),
                now,
            ),
        ),
        Err(e) => {
            // The error names the transport failure only (no URL: its path may hold the ref).
            warn!(
                integration = label,
                route,
                network,
                error = %e,
                "Integration upstream call failed (answered 502)"
            );
            crate::health::record_upstream_error(network, &backend, "request_failed");
            (
                0,
                Finished {
                    answer: Answer::upstream(),
                    outcome: "upstream_unreachable",
                    retry_after: None,
                },
            )
        }
    };
    crate::health::record_upstream_request(
        network,
        &backend,
        route,
        upstream_status,
        "-",
        started.elapsed().as_secs_f64(),
    );
    if finished.outcome != "ok" {
        warn!(
            integration = label,
            route,
            upstream_status,
            outcome = finished.outcome,
            status = finished.answer.status,
            network,
            "Integration upstream answer replaced by a fixed answer"
        );
    }
    let extra = finished
        .retry_after
        .map(|secs| ("retry-after".to_string(), secs.to_string()))
        .into_iter()
        .collect();
    json(finished.answer, extra)
}

/// What the upstream answered: its status, its body when it is a 2xx (at most
/// [`MAX_UPSTREAM_BODY_BYTES`] + 1 bytes read; no other body is read), its `retry-after`.
struct Upstream {
    status: u16,
    body: Vec<u8>,
    retry_after: Option<String>,
}

/// The upstream request of `call`: method, the provider's upstream and the call's path, the
/// provider's headers, a fixed `User-Agent` and `authorization`.
async fn call_upstream(provider: &Coinbase, call: &Call, authorization: &str) -> Result<Upstream> {
    let host = provider.upstream_host();
    let expected = match host.rsplit_once(':') {
        Some((h, port)) if !h.ends_with(':') && port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host,
    };
    let uri = crate::proxy::build_validated_uri(provider.upstream(), &call.path, expected)
        .map_err(|_| anyhow!("the upstream URL could not be built"))?;
    let mut builder = hyper::Request::builder().method(call.method).uri(uri);
    for (name, value) in Coinbase::headers(call) {
        builder = builder.header(name, value);
    }
    builder = builder
        .header("user-agent", "ohttp-gateway/1.0")
        .header("authorization", authorization);
    let request = builder
        .body(Full::new(Bytes::from(
            call.body.clone().unwrap_or_default(),
        )))
        .map_err(|_| anyhow!("the upstream request could not be built"))?;
    let response = crate::proxy::https_backend_client()
        .request(request)
        .await
        .map_err(|e| anyhow!("request failed: {}", error_kind(&e)))?;
    let status = response.status().as_u16();
    let retry_after = response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    if !(200..=299).contains(&status) {
        // Neither read nor kept: dropping it closes the connection.
        return Ok(Upstream {
            status,
            body: Vec::new(),
            retry_after,
        });
    }
    let limited = http_body_util::Limited::new(response.into_body(), MAX_UPSTREAM_BODY_BYTES + 1);
    let body = match limited.collect().await {
        Ok(collected) => collected.to_bytes().to_vec(),
        // Too large (or cut): a body the provider refuses.
        Err(_) => vec![0; MAX_UPSTREAM_BODY_BYTES + 1],
    };
    Ok(Upstream {
        status,
        body,
        retry_after,
    })
}

/// The kind of a client error, without the URI it may carry.
fn error_kind(e: &hyper_util::client::legacy::Error) -> &'static str {
    if e.is_connect() {
        "connect"
    } else {
        "other"
    }
}

#[cfg(test)]
#[path = "coinbase_tests.rs"]
pub(crate) mod tests;

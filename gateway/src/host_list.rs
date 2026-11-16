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

//! The third-party host list a gateway publishes to wallets (`THIRD_PARTY_HOSTS_PUBLISH`).
//!
//! Wallets refuse to send a third-party request through the gateway unless they know the
//! gateway carries its host. Without this document that knowledge is a list compiled into the
//! wallet, which goes stale as soon as the gateway's set changes (a new `BACKENDS` alias, a
//! host a dynamic source added). The gateway answers the question itself:
//!
//! inner `GET /ohttp-gateway/v1/third-party-hosts` with `:authority` = a `GATEWAY_HOSTS` name,
//! through OHTTP only (the path does not exist on the outer HTTP router):
//!
//! ```json
//! { "version": 1,
//!   "revision": "5b0c1d9e7a3f2c44",
//!   "scope": "all",
//!   "max_age_secs": 300,
//!   "hosts": [ { "host": "vote.example.org", "routes": ["GET /*", "POST /*"] } ] }
//! ```
//!
//! - `host` is what a wallet puts in `:authority`. Nothing else about a backend is published:
//!   no alias target, no injected header, no source URL.
//! - `routes` are the operations the gateway forwards, in the `BACKENDS_POLICY` grammar.
//! - `scope` says what the list covers: `all` = every third-party host the gateway carries;
//!   `dynamic` = only the hosts of the dynamic sources (the `BACKENDS` aliases are not listed).
//! - `hosts` is sorted; `revision` is derived from `version`, `scope`, `max_age_secs` and `hosts`, so it
//!   changes exactly when the document does and replicas with the same configuration and the
//!   same hosts publish the same value. It is also the `etag`; a request whose `if-none-match`
//!   names it gets a 304 without a body.
//!
//! Modes: `off` (default; the path is an ordinary lightwalletd path), `dynamic` (hosts of
//! `DYNAMIC_HOST_SOURCES` only), `all` (the `BACKENDS` aliases too: one with a `BACKENDS_POLICY`
//! entry with its rules, one without only under `BACKENDS_POLICY_DEFAULT=allow`, as `* /*`).

use crate::config::Config;
use crate::ohttp::{InnerRequest, InnerResponse};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};

/// The oversize error was logged for the current episode (cleared when a list is published).
static OVERSIZE_LOGGED: AtomicBool = AtomicBool::new(false);

/// The inner path of the host list.
pub const HOST_LIST_PATH: &str = "/ohttp-gateway/v1/third-party-hosts";
/// The `version` of the document.
pub const HOST_LIST_VERSION: u32 = 1;
/// The largest document published; wallets refuse a larger one. Far above what the configured
/// bounds produce in practice (a host with its routes is on the order of 100 bytes).
pub const MAX_HOST_LIST_BYTES: usize = 256 * 1024;
/// `THIRD_PARTY_HOSTS_MAX_AGE_SECS`: default and bounds.
const DEFAULT_MAX_AGE_SECS: u64 = 300;
const MIN_MAX_AGE_SECS: u64 = 30;
const MAX_MAX_AGE_SECS: u64 = 86_400;

/// `THIRD_PARTY_HOSTS_PUBLISH`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PublishMode {
    /// The host list is not published.
    #[default]
    Off,
    /// The hosts of the dynamic sources.
    Dynamic,
    /// Those and the `BACKENDS` aliases.
    All,
}

/// The host list settings of a gateway. `Default`: off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostListSettings {
    pub mode: PublishMode,
    /// How long a wallet may use the list before asking again (`max_age_secs`, `cache-control`).
    pub max_age_secs: u64,
}

impl Default for HostListSettings {
    fn default() -> Self {
        Self {
            mode: PublishMode::Off,
            max_age_secs: DEFAULT_MAX_AGE_SECS,
        }
    }
}

impl HostListSettings {
    /// `THIRD_PARTY_HOSTS_PUBLISH` and `THIRD_PARTY_HOSTS_MAX_AGE_SECS` from the environment.
    pub fn from_env() -> anyhow::Result<Self> {
        Self::parse(
            std::env::var("THIRD_PARTY_HOSTS_PUBLISH").ok().as_deref(),
            std::env::var("THIRD_PARTY_HOSTS_MAX_AGE_SECS")
                .ok()
                .as_deref(),
        )
    }

    /// Parse the two values (`None` or empty = default). An unknown mode or a `max_age_secs`
    /// that is not a number in range is an error (a typo must not silently publish nothing).
    pub fn parse(mode: Option<&str>, max_age_secs: Option<&str>) -> anyhow::Result<Self> {
        let mode = match mode.unwrap_or("").trim().to_ascii_lowercase().as_str() {
            "" | "off" => PublishMode::Off,
            "dynamic" => PublishMode::Dynamic,
            "all" => PublishMode::All,
            other => {
                anyhow::bail!(
                    "Invalid THIRD_PARTY_HOSTS_PUBLISH '{other}': must be off, dynamic or all"
                )
            }
        };
        let max_age_secs = match max_age_secs.map(str::trim).filter(|v| !v.is_empty()) {
            None => DEFAULT_MAX_AGE_SECS,
            Some(raw) => raw
                .parse::<u64>()
                .ok()
                .filter(|v| (MIN_MAX_AGE_SECS..=MAX_MAX_AGE_SECS).contains(v))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Invalid THIRD_PARTY_HOSTS_MAX_AGE_SECS '{raw}': must be {MIN_MAX_AGE_SECS}..={MAX_MAX_AGE_SECS}"
                    )
                })?,
        };
        Ok(Self { mode, max_age_secs })
    }
}

/// Whether `inner_request` asks for the host list: publishing is on, the method is `GET`, the
/// path is exactly [`HOST_LIST_PATH`] (a query is not accepted) and the authority is one of the
/// gateway's own names (`GATEWAY_HOSTS`; an explicit port is ignored, as for lightwalletd).
pub fn is_request(config: &Config, inner_request: &InnerRequest) -> bool {
    if config.host_list.mode == PublishMode::Off
        || inner_request.method != "GET"
        || inner_request.path != HOST_LIST_PATH
    {
        return false;
    }
    let authority = inner_request.authority.to_ascii_lowercase();
    let host = authority.split(':').next().unwrap_or("");
    !host.is_empty() && config.gateway_hosts.iter().any(|h| h == host)
}

/// The hosts published now, sorted by name, each with its routes as `METHOD /pattern`.
fn published_hosts(config: &Config) -> Vec<(String, Vec<String>)> {
    let format_rules = |rules: &[(String, String)]| -> Vec<String> {
        rules
            .iter()
            .map(|(method, pattern)| format!("{} {pattern}", method.to_ascii_uppercase()))
            .collect()
    };
    let mut hosts: Vec<(String, Vec<String>)> = Vec::new();
    if config.host_list.mode == PublishMode::All {
        for alias in config.backends.keys() {
            match config.backends_policy.get(alias) {
                Some(rules) => hosts.push((alias.clone(), format_rules(rules))),
                None if config.backends_policy_default_allow => {
                    hosts.push((alias.clone(), vec!["* /*".to_string()]))
                }
                // No rule admits anything: the gateway refuses every request to it.
                None => {}
            }
        }
    }
    if config.host_list.mode != PublishMode::Off {
        for (authority, rules) in config.dynamic_hosts.served() {
            // Static wins at routing; the same here should a snapshot ever hold such a name.
            if !config.backends.contains_key(&authority) {
                hosts.push((authority, format_rules(&rules)));
            }
        }
    }
    hosts.sort();
    hosts.dedup_by(|a, b| a.0 == b.0);
    hosts
}

/// `scope` of the document: what the list covers.
fn scope(mode: PublishMode) -> &'static str {
    match mode {
        PublishMode::All => "all",
        // `Off` publishes nothing; the list of a gateway without `all` is never complete.
        PublishMode::Dynamic | PublishMode::Off => "dynamic",
    }
}

/// The document and its revision: the first 16 hex characters of the SHA-256 over everything
/// else in the document (`version`, `scope`, `max_age_secs` and the sorted `hosts`), so the
/// revision, which is also the `etag`, names exactly one document body.
fn document(config: &Config) -> (Vec<u8>, String) {
    let hosts: Vec<serde_json::Value> = published_hosts(config)
        .into_iter()
        .map(|(host, routes)| serde_json::json!({ "host": host, "routes": routes }))
        .collect();
    let scope = scope(config.host_list.mode);
    let content = serde_json::json!([
        HOST_LIST_VERSION,
        scope,
        config.host_list.max_age_secs,
        hosts
    ]);
    let revision = hex::encode(&Sha256::digest(content.to_string().as_bytes())[..8]);
    let body = serde_json::json!({
        "version": HOST_LIST_VERSION,
        "revision": revision,
        "scope": scope,
        "max_age_secs": config.host_list.max_age_secs,
        "hosts": hosts,
    });
    (body.to_string().into_bytes(), revision)
}

/// The inner 503 of a gateway that has no complete list to give: wallets keep what they hold.
fn unavailable(reason: &'static str) -> InnerResponse {
    InnerResponse {
        status: 503,
        headers: vec![
            ("content-type".to_string(), "text/plain".to_string()),
            ("cache-control".to_string(), "no-store".to_string()),
        ],
        body: reason.as_bytes().to_vec(),
    }
}

/// Whether an `if-none-match` value names `etag` (a strong or weak tag in a list, or `*`).
fn none_match(value: &str, etag: &str) -> bool {
    value.split(',').any(|candidate| {
        let candidate = candidate.trim();
        let candidate = candidate.strip_prefix("W/").unwrap_or(candidate);
        candidate == "*" || candidate == etag
    })
}

/// The answer to a host list request ([`is_request`] must hold): 200 with the document, 304
/// when the request's `if-none-match` names the current revision, or 503 when this process
/// has no complete list: the document of a source has not been read since the start (the
/// list would lack hosts other replicas serve; a source that cannot be fetched, parsed or
/// verified keeps it so), or the document would exceed [`MAX_HOST_LIST_BYTES`].
pub fn answer(config: &Config, inner_request: &InnerRequest) -> InnerResponse {
    if !config.dynamic_hosts.all_loaded() {
        return unavailable("host list not ready");
    }
    let (body, revision) = document(config);
    if body.len() > MAX_HOST_LIST_BYTES {
        // Once each time the list becomes too large, not per request: every wallet asks, and
        // asks again. The requests are counted with status `unavailable`.
        if !OVERSIZE_LOGGED.swap(true, Ordering::Relaxed) {
            tracing::error!(
                bytes = body.len(),
                max = MAX_HOST_LIST_BYTES,
                "The third-party host list is larger than wallets accept and is not published"
            );
        }
        return unavailable("host list too large");
    }
    OVERSIZE_LOGGED.store(false, Ordering::Relaxed);
    let etag = format!("\"{revision}\"");
    let mut headers = vec![
        (
            "cache-control".to_string(),
            format!("max-age={}", config.host_list.max_age_secs),
        ),
        ("etag".to_string(), etag.clone()),
    ];
    let not_modified = inner_request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("if-none-match"))
        .any(|(_, value)| none_match(value, &etag));
    if not_modified {
        return InnerResponse {
            status: 304,
            headers,
            body: Vec::new(),
        };
    }
    headers.insert(
        0,
        ("content-type".to_string(), "application/json".to_string()),
    );
    InnerResponse {
        status: 200,
        headers,
        body,
    }
}

#[cfg(test)]
#[path = "host_list_tests.rs"]
mod tests;

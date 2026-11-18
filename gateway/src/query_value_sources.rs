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

//! `THIRD_PARTY_QUERY_VALUE_SOURCES`: allowed-value lists for `{from:name}` in
//! `THIRD_PARTY_QUERY_RULES`, read from the upstream itself.
//!
//! ```text
//! THIRD_PARTY_QUERY_VALUE_SOURCES=fiat=prices.example GET /v1/fiat/map#/data/*/symbol@21600@fallback=USD|EUR
//! ```
//!
//! Each process fetches every source on its own, in the background: first after a random
//! 0..5 s, then every `REFRESH_SECS`; after a failure again in 60 s, doubling up to
//! `REFRESH_SECS`; every wait +-10 %. The fetch is a `GET` of the alias through the forwarder,
//! sent like any request to it (its `BACKENDS` base URL and `BACKEND_HEADERS`), outside the
//! third-party cache and the upstream cap, with its own deadline and body cap. The JSON pointer
//! (RFC 6901, a segment `*` iterates an array) selects the values. A refresh that fails in any
//! way changes nothing: the last accepted list stays. A document with fewer valid values than
//! half the admitted list (rounded up, at least one) is a failure too, so a refresh never
//! accepts a list that small: it is held until a restart or a configuration change. Before the
//! first accepted list the `fallback` list is used (the first accepted list replaces it);
//! without one `{from:name}` admits nothing (fail closed). A list never becomes empty through a
//! refresh.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail};
use parking_lot::RwLock;
use tracing::{info, warn};

/// The environment variable.
pub const ENV: &str = "THIRD_PARTY_QUERY_VALUE_SOURCES";
/// Shortest and longest `REFRESH_SECS`.
pub const MIN_REFRESH_SECS: u64 = 300;
pub const MAX_REFRESH_SECS: u64 = 604_800;
/// Deadline of one fetch (head and body).
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest document; reading stops beyond it.
pub const MAX_BODY_BYTES: usize = 256 * 1024;
/// Most values of one list; a document with more is rejected.
pub const MAX_VALUES: usize = 2048;
/// Longest value.
pub const MAX_VALUE_LEN: usize = 64;
/// Most `*` segments of a pointer.
pub const MAX_WILDCARDS: usize = 2;
/// First retry after a failed refresh; it doubles up to `REFRESH_SECS`.
pub const FIRST_RETRY: Duration = Duration::from_secs(60);

/// Whether `value` may be in a list: 1..=64 characters of `[A-Za-z0-9._~-]` (the unreserved
/// characters of RFC 3986, so a value is the same encoded and decoded).
pub fn valid_value(value: &str) -> bool {
    (1..=MAX_VALUE_LEN).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'))
}

/// The value rule in error messages.
pub const VALUE_RULE: &str = "1 to 64 characters of [A-Za-z0-9._~-]";

/// Whether `name` is a valid source name: `[a-z0-9_-]{1,32}`.
pub fn valid_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// One JSON pointer segment.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Segment {
    /// An object member, or an array index.
    Key(String),
    /// `*`: every element of an array.
    Each,
}

/// Why a refresh did not change the list (the `result` label), or `Ok`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Transport,
    Status,
    Oversize,
    Json,
    Pointer,
    Empty,
    TooMany,
    TooFew,
}

impl Outcome {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Transport => "transport",
            Self::Status => "status",
            Self::Oversize => "oversize",
            Self::Json => "json",
            Self::Pointer => "pointer",
            Self::Empty => "empty",
            Self::TooMany => "too_many",
            Self::TooFew => "too_few",
        }
    }
}

/// A failed fetch: its outcome, the HTTP status if there was one, and the error text (never
/// the body).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub outcome: Outcome,
    pub status: Option<u16>,
    pub error: String,
}

impl From<Outcome> for Failure {
    fn from(outcome: Outcome) -> Self {
        Self {
            outcome,
            status: None,
            error: outcome.label().to_string(),
        }
    }
}

/// One configured source.
#[derive(Clone, Debug)]
pub struct SourceSpec {
    pub name: String,
    /// The `BACKENDS` alias (lowercase).
    pub alias: String,
    /// Path of the `GET`, with its query if any.
    pub path: String,
    pointer: Vec<Segment>,
    pub refresh: Duration,
    fallback: Option<Arc<HashSet<String>>>,
}

impl SourceSpec {
    /// The path without its query.
    pub fn route(&self) -> &str {
        self.path.split_once('?').map_or(&self.path, |(r, _)| r)
    }
}

struct Source {
    spec: SourceSpec,
    /// The last accepted list; `None` before the first success.
    accepted: RwLock<Option<Arc<HashSet<String>>>>,
    /// Reads of the current list ([`QueryValueSources::list`]).
    #[cfg(test)]
    reads: std::sync::atomic::AtomicUsize,
}

/// The configured sources and their current lists. A handle: clones share the lists.
#[derive(Clone, Default)]
pub struct QueryValueSources {
    sources: Arc<Vec<Source>>,
}

impl std::fmt::Debug for QueryValueSources {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Names and sizes only.
        let mut list = f.debug_list();
        for s in self.sources.iter() {
            list.entry(&(
                s.spec.name.as_str(),
                Self::current_of(s).map_or(0, |l| l.len()),
            ));
        }
        list.finish()
    }
}

impl QueryValueSources {
    /// `THIRD_PARTY_QUERY_VALUE_SOURCES` from the environment. Unset or blank: no source; a
    /// value that is not UTF-8 is an error.
    pub fn from_env() -> anyhow::Result<Self> {
        match std::env::var(ENV) {
            Ok(raw) if raw.trim().is_empty() => Ok(Self::default()),
            Ok(raw) => Self::parse(&raw),
            Err(std::env::VarError::NotPresent) => Ok(Self::default()),
            Err(std::env::VarError::NotUnicode(_)) => bail!("Invalid {ENV}: not valid UTF-8"),
        }
    }

    /// Parse `name=alias GET /path#/json/pointer@REFRESH_SECS[@fallback=A|B|C];name2=...`.
    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        let mut sources: Vec<Source> = Vec::new();
        for entry in raw.split(';') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let spec = parse_source(entry)?;
            if sources.iter().any(|s| s.spec.name == spec.name) {
                bail!("Malformed {ENV}: source '{}' listed twice", spec.name);
            }
            sources.push(Source {
                spec,
                accepted: RwLock::new(None),
                #[cfg(test)]
                reads: Default::default(),
            });
        }
        if sources.is_empty() {
            bail!("Malformed {ENV}: no entries");
        }
        Ok(Self {
            sources: Arc::new(sources),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    pub fn len(&self) -> usize {
        self.sources.len()
    }

    pub fn specs(&self) -> impl Iterator<Item = &SourceSpec> {
        self.sources.iter().map(|s| &s.spec)
    }

    pub fn spec(&self, name: &str) -> Option<&SourceSpec> {
        self.source(name).map(|s| &s.spec)
    }

    fn source(&self, name: &str) -> Option<&Source> {
        self.sources.iter().find(|s| s.spec.name == name)
    }

    /// The list `{from:name}` admits now: the last accepted one, else the fallback, else none.
    fn current_of(source: &Source) -> Option<Arc<HashSet<String>>> {
        source
            .accepted
            .read()
            .clone()
            .or_else(|| source.spec.fallback.clone())
    }

    /// The current list of source `name` (`None`: unknown source, or no list yet), one read;
    /// a query evaluation takes it once per source and keeps it.
    pub fn list(&self, name: &str) -> Option<Arc<HashSet<String>>> {
        let source = self.source(name)?;
        #[cfg(test)]
        source
            .reads
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self::current_of(source)
    }

    /// Whether `value` is in the current list of source `name` (byte equality).
    #[cfg(test)]
    pub fn admits(&self, name: &str, value: &str) -> bool {
        self.list(name).is_some_and(|l| l.contains(value))
    }

    /// Reads of the list of `name` so far.
    #[cfg(test)]
    pub fn reads(&self, name: &str) -> usize {
        self.source(name)
            .map_or(0, |s| s.reads.load(std::sync::atomic::Ordering::SeqCst))
    }

    /// Size of the current list of `name` (0 without one).
    #[cfg(test)]
    pub fn current_len(&self, name: &str) -> usize {
        self.source(name)
            .and_then(Self::current_of)
            .map_or(0, |l| l.len())
    }

    /// Apply the result of one fetch of `name` (`Ok(body)` or the failure) and record it. Only
    /// an accepted document changes the list: one with at least
    /// `max(1, ceil(current / 2))` valid values, `current` being the size of the list admitted
    /// now (the fallback before the first success), so a list never shrinks to less than half
    /// in one refresh.
    pub fn apply(&self, network: &str, name: &str, fetched: Result<Vec<u8>, Failure>) -> Outcome {
        // Callers only pass configured names; an unknown one changes nothing.
        let Some(source) = self.source(name) else {
            return Outcome::Pointer;
        };
        let before = Self::current_of(source);
        let before_len = before.as_ref().map_or(0, |l| l.len());
        let result = fetched.and_then(|body| {
            // A body is only read from a 200.
            let (result, skipped) = extract(&source.spec.pointer, &body);
            if skipped > 0 {
                crate::health::add_query_value_source_skipped(network, name, skipped as u64);
            }
            let values = result.map_err(|f| Failure {
                status: Some(200),
                ..f
            })?;
            let floor = before_len.div_ceil(2).max(1);
            if values.len() < floor {
                return Err(Failure {
                    outcome: Outcome::TooFew,
                    status: Some(200),
                    error: format!("{} valid values, at least {floor} needed", values.len()),
                });
            }
            Ok(values)
        });
        let outcome = match result {
            Ok(values) => {
                self.accept(network, source, before, values);
                Outcome::Ok
            }
            Err(failure) => {
                warn!(
                    network,
                    source = name,
                    result = failure.outcome.label(),
                    status = ?failure.status,
                    error = %failure.error,
                    values = before_len,
                    "Query value source refresh failed; the current list stays"
                );
                failure.outcome
            }
        };
        crate::health::record_query_value_source_refresh(network, name, outcome.label());
        outcome
    }

    /// Store an accepted list; the comparison and the log line happen outside the lock.
    fn accept(
        &self,
        network: &str,
        source: &Source,
        before: Option<Arc<HashSet<String>>>,
        values: HashSet<String>,
    ) {
        let name = source.spec.name.as_str();
        let len = values.len();
        let first = source.accepted.read().is_none();
        let unchanged = before.as_deref() == Some(&values);
        if first && unchanged {
            // The fallback, now confirmed by the upstream.
            *source.accepted.write() = Some(Arc::new(values));
            info!(
                network,
                source = name,
                values = len,
                "Query value source list accepted, unchanged from fallback"
            );
        } else if !unchanged {
            let values = Arc::new(values);
            *source.accepted.write() = Some(values.clone());
            let before = before.unwrap_or_default();
            let added = values.difference(&before).count();
            let removed = before.difference(&values).count();
            info!(
                network,
                source = name,
                values = len,
                added,
                removed,
                "Query value source list changed"
            );
        }
        crate::health::set_query_value_source_values(network, name, len);
        crate::health::record_query_value_source_success(network, name);
    }

    /// Fetch `name` now through `state` and apply the result.
    pub async fn refresh(&self, state: &Arc<crate::AppState>, name: &str) -> Outcome {
        let Some(source) = self.source(name) else {
            return Outcome::Pointer;
        };
        let fetched = fetch(state, &source.spec).await;
        self.apply(&state.config.network, name, fetched)
    }

    /// One refresh task per source: a first fetch after a random 0..5 s, then [`next_delay`]
    /// after each.
    pub fn spawn_refresh_tasks(&self, state: Arc<crate::AppState>) {
        for source in self.sources.iter() {
            let name = source.spec.name.clone();
            let refresh = source.spec.refresh;
            let network = state.config.network.clone();
            crate::health::init_query_value_source(
                &network,
                &name,
                Self::current_of(source).map_or(0, |l| l.len()),
            );
            let sources = self.clone();
            let state = state.clone();
            tokio::spawn(async move {
                let first = {
                    use rand::Rng;
                    Duration::from_millis(rand::thread_rng().gen_range(0..5000))
                };
                tokio::time::sleep(first).await;
                let mut failures = 0u32;
                loop {
                    if sources.refresh(&state, &name).await == Outcome::Ok {
                        failures = 0;
                    } else {
                        failures = failures.saturating_add(1);
                    }
                    tokio::time::sleep(next_delay(refresh, failures)).await;
                }
            });
        }
    }
}

/// The wait before the next fetch, +-10 %: `refresh` after a success, else [`retry_delay`].
pub fn next_delay(refresh: Duration, consecutive_failures: u32) -> Duration {
    use rand::Rng;
    let base = if consecutive_failures == 0 {
        refresh
    } else {
        retry_delay(refresh, consecutive_failures)
    };
    base.mul_f64(rand::thread_rng().gen_range(0.9..1.1))
}

/// After `failures` (>= 1) failed refreshes in a row: 60 s, doubling, at most `refresh`.
pub fn retry_delay(refresh: Duration, failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(20);
    FIRST_RETRY.saturating_mul(1u32 << doublings).min(refresh)
}

/// One `GET` of the source through the gateway's forwarder (the alias's base URL and headers),
/// at most [`MAX_BODY_BYTES`] read, within [`FETCH_TIMEOUT`].
async fn fetch(state: &Arc<crate::AppState>, spec: &SourceSpec) -> Result<Vec<u8>, Failure> {
    use crate::chunked_stream::UpFrame;
    use futures_util::StreamExt;
    let request = crate::ohttp::InnerRequest {
        method: "GET".to_string(),
        path: spec.path.clone(),
        authority: spec.alias.clone(),
        headers: vec![],
        body: vec![],
    };
    let failure = |outcome, status, error: String| Failure {
        outcome,
        status,
        error,
    };
    // The status of a received head, kept for a body that then times out (0: none yet).
    let head_status = std::sync::atomic::AtomicU16::new(0);
    let run = async {
        let (status, _headers, mut stream) =
            crate::proxy::forward_to_backend_stream(state, &request, uuid::Uuid::new_v4(), None)
                .await
                .map_err(|e| failure(Outcome::Transport, None, e.to_string()))?;
        head_status.store(status, std::sync::atomic::Ordering::Relaxed);
        if status != 200 {
            return Err(failure(
                Outcome::Status,
                Some(status),
                format!("HTTP status {status}"),
            ));
        }
        let mut body = Vec::new();
        while let Some(frame) = stream.next().await {
            match frame {
                Ok(UpFrame::Data(data)) => {
                    if body.len() + data.len() > MAX_BODY_BYTES {
                        return Err(failure(
                            Outcome::Oversize,
                            Some(status),
                            format!("body over {MAX_BODY_BYTES} bytes"),
                        ));
                    }
                    body.extend_from_slice(&data);
                }
                Ok(UpFrame::Trailers(_)) => {}
                Err(e) => return Err(failure(Outcome::Transport, Some(status), e.to_string())),
            }
        }
        Ok(body)
    };
    let result = tokio::time::timeout(FETCH_TIMEOUT, run).await;
    result.unwrap_or_else(|_| {
        let status = head_status.load(std::sync::atomic::Ordering::Relaxed);
        Err(failure(
            Outcome::Transport,
            (status != 0).then_some(status),
            format!("no complete answer within {FETCH_TIMEOUT:?}"),
        ))
    })
}

/// What a walk collected: the valid values and the number of skipped items.
#[derive(Default)]
struct Collected {
    values: HashSet<String>,
    skipped: usize,
}

/// The values `pointer` selects in `body`, and how many selected items were skipped (missing
/// below a `*`, not a string, or not a valid value). The walk stops as soon as there are more
/// than [`MAX_VALUES`] values.
fn extract(pointer: &[Segment], body: &[u8]) -> (Result<HashSet<String>, Failure>, usize) {
    let doc = match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(doc) => doc,
        Err(e) => {
            return (
                Err(Failure {
                    outcome: Outcome::Json,
                    status: None,
                    error: e.to_string(),
                }),
                0,
            )
        }
    };
    let mut collected = Collected::default();
    if let Err(outcome) = select(&doc, pointer, false, &mut collected) {
        let error = match outcome {
            Outcome::Pointer => "pointer not found".to_string(),
            _ => format!("more than {MAX_VALUES} values"),
        };
        return (
            Err(Failure {
                outcome,
                status: None,
                error,
            }),
            collected.skipped,
        );
    }
    let result = if collected.values.is_empty() {
        Err(Failure {
            outcome: Outcome::Empty,
            status: None,
            error: "no valid value".to_string(),
        })
    } else {
        Ok(collected.values)
    };
    (result, collected.skipped)
}

/// Walk `segments` from `value`. Above the first `*` a missing step is a pointer error; below
/// one it skips that item. More than [`MAX_VALUES`] values: `TooMany`, at once.
fn select(
    value: &serde_json::Value,
    segments: &[Segment],
    below_each: bool,
    out: &mut Collected,
) -> Result<(), Outcome> {
    let Some((first, rest)) = segments.split_first() else {
        match value.as_str() {
            Some(s) if valid_value(s) => {
                out.values.insert(s.to_string());
                if out.values.len() > MAX_VALUES {
                    return Err(Outcome::TooMany);
                }
            }
            _ => out.skipped += 1,
        }
        return Ok(());
    };
    let missing = |out: &mut Collected| {
        if below_each {
            out.skipped += 1;
            Ok(())
        } else {
            Err(Outcome::Pointer)
        }
    };
    match first {
        Segment::Each => match value.as_array() {
            Some(items) => {
                for item in items {
                    select(item, rest, true, out)?;
                }
                Ok(())
            }
            None => missing(out),
        },
        Segment::Key(key) => {
            let next = match value {
                serde_json::Value::Object(map) => map.get(key),
                serde_json::Value::Array(items) => array_index(key).and_then(|i| items.get(i)),
                _ => None,
            };
            match next {
                Some(next) => select(next, rest, below_each, out),
                None => missing(out),
            }
        }
    }
}

/// An RFC 6901 array index: `0` or digits without a leading zero.
fn array_index(key: &str) -> Option<usize> {
    if key.is_empty()
        || !key.bytes().all(|b| b.is_ascii_digit())
        || (key.len() > 1 && key.starts_with('0'))
    {
        return None;
    }
    key.parse().ok()
}

fn parse_pointer(raw: &str, entry: &str) -> anyhow::Result<Vec<Segment>> {
    let Some(rest) = raw.strip_prefix('/') else {
        bail!("Invalid {ENV} pointer '{raw}' in '{entry}': must start with /");
    };
    let mut segments = Vec::new();
    for part in rest.split('/') {
        if part == "*" {
            segments.push(Segment::Each);
            continue;
        }
        let mut key = String::new();
        let mut chars = part.chars();
        while let Some(c) = chars.next() {
            if c == '~' {
                match chars.next() {
                    Some('0') => key.push('~'),
                    Some('1') => key.push('/'),
                    _ => bail!(
                        "Invalid {ENV} pointer '{raw}' in '{entry}': '~' must be followed by 0 or 1"
                    ),
                }
            } else {
                key.push(c);
            }
        }
        segments.push(Segment::Key(key));
    }
    let wildcards = segments.iter().filter(|s| **s == Segment::Each).count();
    if wildcards > MAX_WILDCARDS {
        bail!("Invalid {ENV} pointer '{raw}' in '{entry}': at most {MAX_WILDCARDS} '*' segments");
    }
    Ok(segments)
}

fn parse_source(entry: &str) -> anyhow::Result<SourceSpec> {
    let format = "must be 'name=alias GET /path#/json/pointer@REFRESH_SECS[@fallback=A|B|C]'";
    let (name, rest) = entry
        .split_once('=')
        .ok_or_else(|| anyhow!("Malformed {ENV} entry '{entry}': {format}"))?;
    let name = name.trim();
    if !valid_name(name) {
        bail!("Invalid {ENV} source name '{name}' in '{entry}': must be [a-z0-9_-]{{1,32}}");
    }
    let parts: Vec<&str> = rest.split('@').collect();
    if !(2..=3).contains(&parts.len()) {
        bail!("Malformed {ENV} entry '{entry}': {format}");
    }
    let mut words = parts[0].trim().splitn(3, ' ');
    let (Some(alias), Some(method), Some(target)) = (words.next(), words.next(), words.next())
    else {
        bail!("Malformed {ENV} entry '{entry}': {format}");
    };
    let alias = alias.trim().to_ascii_lowercase();
    if alias.is_empty() {
        bail!("Malformed {ENV} entry '{entry}': missing alias");
    }
    if !method.eq_ignore_ascii_case("GET") {
        bail!("Invalid {ENV} method '{method}' in '{entry}': only GET");
    }
    let (path, pointer) = target
        .trim()
        .split_once('#')
        .ok_or_else(|| anyhow!("Malformed {ENV} entry '{entry}': missing '#/json/pointer'"))?;
    let route = path.split_once('?').map_or(path, |(r, _)| r);
    if let Some(reason) = crate::proxy::rule_path_rejection(path) {
        bail!("Invalid {ENV} path '{path}' in '{entry}': {reason}");
    }
    if route.contains('*') {
        bail!("Invalid {ENV} path '{path}' in '{entry}': must be an exact path");
    }
    let pointer = parse_pointer(pointer, entry)?;
    let refresh_raw = parts[1].trim();
    let refresh: u64 = refresh_raw
        .parse()
        .ok()
        .filter(|_| refresh_raw.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(|| {
            anyhow!("Invalid {ENV} REFRESH_SECS '{refresh_raw}' in '{entry}': must be a number")
        })?;
    if !(MIN_REFRESH_SECS..=MAX_REFRESH_SECS).contains(&refresh) {
        bail!(
            "Invalid {ENV} REFRESH_SECS {refresh} in '{entry}': must be {MIN_REFRESH_SECS}..={MAX_REFRESH_SECS}"
        );
    }
    let fallback = match parts.get(2) {
        None => None,
        Some(raw) => {
            let list = raw.trim().strip_prefix("fallback=").ok_or_else(|| {
                anyhow!("Malformed {ENV} entry '{entry}': the third part must be 'fallback=A|B|C'")
            })?;
            let mut values = HashSet::new();
            for value in list.split('|') {
                if !valid_value(value) {
                    bail!("Invalid {ENV} fallback value '{value}' in '{entry}': {VALUE_RULE}");
                }
                if !values.insert(value.to_string()) {
                    bail!("Invalid {ENV} fallback value '{value}' in '{entry}': listed twice");
                }
            }
            if values.len() > MAX_VALUES {
                bail!("Invalid {ENV} fallback in '{entry}': at most {MAX_VALUES} values");
            }
            Some(Arc::new(values))
        }
    };
    Ok(SourceSpec {
        name: name.to_string(),
        alias,
        path: path.to_string(),
        pointer,
        refresh: Duration::from_secs(refresh),
        fallback,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET: &str = "testnet-value-sources";
    const FIAT: &str = "fiat=Prices.Example GET /v1/fiat/map#/data/*/symbol@21600@fallback=USD|EUR";

    fn err(raw: &str) -> String {
        QueryValueSources::parse(raw).unwrap_err().to_string()
    }

    fn set(values: &[&str]) -> HashSet<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    #[test]
    fn sources_parse() {
        let sources = QueryValueSources::parse(&format!(
            " {FIAT} ; codes=other.example get /v2/list?all=1#/@300;"
        ))
        .unwrap();
        assert_eq!(sources.len(), 2);
        let specs: Vec<&SourceSpec> = sources.specs().collect();
        assert_eq!(specs[0].name, "fiat");
        assert_eq!(specs[0].alias, "prices.example");
        assert_eq!(specs[0].path, "/v1/fiat/map");
        assert_eq!(
            specs[0].pointer,
            vec![
                Segment::Key("data".into()),
                Segment::Each,
                Segment::Key("symbol".into())
            ]
        );
        assert_eq!(specs[0].refresh, Duration::from_secs(21600));
        assert_eq!(specs[0].fallback.as_deref(), Some(&set(&["USD", "EUR"])));
        assert_eq!(specs[1].path, "/v2/list?all=1");
        assert_eq!(specs[1].route(), "/v2/list");
        assert_eq!(specs[1].pointer, vec![Segment::Key(String::new())]);
        assert!(specs[1].fallback.is_none());
        let escaped = QueryValueSources::parse("e=a.example GET /x#/a~1b/~0c/*/*@604800").unwrap();
        assert_eq!(
            escaped.specs().next().unwrap().pointer,
            vec![
                Segment::Key("a/b".into()),
                Segment::Key("~c".into()),
                Segment::Each,
                Segment::Each
            ]
        );
    }

    #[test]
    fn source_grammar_errors() {
        for (raw, expected) in [
            (";", "no entries"),
            ("fiat", "must be 'name=alias GET"),
            ("Fiat=a.example GET /x#/a@300", "source name"),
            ("=a.example GET /x#/a@300", "source name"),
            (
                "abcdefghijklmnopqrstuvwxyz0123456=a.example GET /x#/a@300",
                "source name",
            ),
            ("f=a.example GET /x#/a", "must be 'name=alias GET"),
            (
                "f=a.example GET /x#/a@300@fallback=A@1",
                "must be 'name=alias GET",
            ),
            ("f=a.example GET@300", "must be 'name=alias GET"),
            ("f=a.example POST /x#/a@300", "only GET"),
            ("f=a.example GET /x@300", "missing '#/json/pointer'"),
            ("f=a.example GET x#/a@300", "does not start with /"),
            ("f=a.example GET /x/../y#/a@300", "traversal"),
            ("f=a.example GET /x//y#/a@300", "double slashes"),
            ("f=a.example GET /x/*#/a@300", "exact path"),
            ("f=a.example GET /x#a@300", "must start with /"),
            ("f=a.example GET /x#/a~2@300", "followed by 0 or 1"),
            ("f=a.example GET /x#/*/*/*@300", "at most 2"),
            ("f=a.example GET /x#/a@299", "300..=604800"),
            ("f=a.example GET /x#/a@604801", "300..=604800"),
            ("f=a.example GET /x#/a@+300", "must be a number"),
            ("f=a.example GET /x#/a@5m", "must be a number"),
            ("f=a.example GET /x#/a@300@USD", "fallback=A|B|C"),
            ("f=a.example GET /x#/a@300@fallback=", "fallback value"),
            ("f=a.example GET /x#/a@300@fallback=A||B", "fallback value"),
            ("f=a.example GET /x#/a@300@fallback=A%20B", "fallback value"),
            ("f=a.example GET /x#/a@300@fallback=A+B", "fallback value"),
            ("f=a.example GET /x#/a@300@fallback=A}", "fallback value"),
            ("f=a.example GET /x#/a@300@fallback=A|A", "listed twice"),
            (
                "f=a.example GET /x#/a@300;f=b.example GET /y#/a@300",
                "listed twice",
            ),
        ] {
            let text = err(raw);
            assert!(text.contains(expected), "{raw}: {text}");
            assert!(text.contains(ENV), "{raw}: {text}");
        }
        let long = format!("f=a.example GET /x#/a@300@fallback={}", "A".repeat(65));
        assert!(err(&long).contains("fallback value"));
    }

    fn pointer(raw: &str) -> Vec<Segment> {
        parse_pointer(raw, "test").unwrap()
    }

    fn values(p: &str, body: &str) -> (Result<HashSet<String>, Outcome>, usize) {
        let (result, skipped) = extract(&pointer(p), body.as_bytes());
        (result.map_err(|f| f.outcome), skipped)
    }

    #[test]
    fn pointer_extraction() {
        let doc = r#"{"data":[{"symbol":"USD"},{"symbol":"EUR"},{"symbol":"USD"},
            {"name":"no symbol"},{"symbol":7},{"symbol":"has space"},{"symbol":"a%2B"},
            {"symbol":""},{"symbol":"X|Y"},{"symbol":"JPY"}],"one":"ZEC",
            "nested":[["A","B"],["C",1],"D"],"list":["P","Q"]}"#;
        // `*` over an array; missing members, wrong types and invalid values are skipped and
        // counted; duplicates are merged.
        assert_eq!(
            values("/data/*/symbol", doc),
            (Ok(set(&["USD", "EUR", "JPY"])), 6)
        );
        // No `*`: one string.
        assert_eq!(values("/one", doc), (Ok(set(&["ZEC"])), 0));
        // Array index segments.
        assert_eq!(values("/data/1/symbol", doc), (Ok(set(&["EUR"])), 0));
        assert_eq!(values("/list/*", doc), (Ok(set(&["P", "Q"])), 0));
        // Two `*`: a non-array element below the first is skipped, so is the number.
        assert_eq!(values("/nested/*/*", doc), (Ok(set(&["A", "B", "C"])), 2));
        // Above the first `*` a missing step is a pointer error; a selected non-string or an
        // array without `*` is skipped, leaving nothing.
        assert_eq!(values("/missing/*/symbol", doc).0, Err(Outcome::Pointer));
        assert_eq!(values("/one/*", doc).0, Err(Outcome::Pointer));
        assert_eq!(values("/data/01/symbol", doc).0, Err(Outcome::Pointer));
        assert_eq!(values("/data/99/symbol", doc).0, Err(Outcome::Pointer));
        assert_eq!(values("/list", doc), (Err(Outcome::Empty), 1));
        assert_eq!(values("/data/*/name", doc).0, Err(Outcome::Empty));
        assert_eq!(values("/data/*/symbol", "[]").0, Err(Outcome::Pointer));
        assert_eq!(values("/*", "[]").0, Err(Outcome::Empty));
        assert_eq!(values("/*", "not json").0, Err(Outcome::Json));
        // Caps: 2048 distinct values pass, 2049 do not (duplicates count once).
        let list = |n: usize| {
            let items: Vec<String> = (0..n).map(|i| format!("\"V{i}\"")).collect();
            format!("[{},\"V0\"]", items.join(","))
        };
        assert_eq!(
            values("/*", &list(MAX_VALUES)).0.map(|v| v.len()),
            Ok(MAX_VALUES)
        );
        assert_eq!(values("/*", &list(MAX_VALUES + 1)).0, Err(Outcome::TooMany));
        // Value rules.
        assert!(valid_value(&"A".repeat(64)));
        assert!(valid_value("Az09._~-"));
        assert!(!valid_value(&"A".repeat(65)));
        for bad in [
            "", "a b", "a|b", "a}b", "a,b", "a;b", "a&b", "a=b", "a%b", "a+b", "a?b", "a#b", "a!b",
            "a:b", "a/b", "a@b", "a'b", "a*b", "\u{e9}",
        ] {
            assert!(!valid_value(bad), "{bad}");
        }
    }

    fn fiat(fallback: bool) -> QueryValueSources {
        let raw = if fallback {
            FIAT.to_string()
        } else {
            FIAT.split("@fallback").next().unwrap().to_string()
        };
        QueryValueSources::parse(&raw).unwrap()
    }

    fn doc(symbols: &[&str]) -> Vec<u8> {
        let items: Vec<String> = symbols
            .iter()
            .map(|s| format!("{{\"symbol\":\"{s}\"}}"))
            .collect();
        format!("{{\"data\":[{}]}}", items.join(",")).into_bytes()
    }

    #[test]
    fn fallback_before_the_first_success_and_last_known_good_after() {
        crate::health::init_metrics();
        let sources = fiat(true);
        assert!(sources.admits("fiat", "USD"));
        assert!(sources.admits("fiat", "EUR"));
        assert!(!sources.admits("fiat", "JPY"));
        assert!(!sources.admits("other", "USD"));
        // A failure before the first success keeps the fallback.
        assert_eq!(
            sources.apply(NET, "fiat", Err(Outcome::Transport.into())),
            Outcome::Transport
        );
        assert!(sources.admits("fiat", "USD"));
        // The first accepted list replaces the fallback.
        assert_eq!(
            sources.apply(NET, "fiat", Ok(doc(&["JPY", "GBP"]))),
            Outcome::Ok
        );
        assert!(sources.admits("fiat", "JPY") && sources.admits("fiat", "GBP"));
        assert!(!sources.admits("fiat", "USD"));
        assert_eq!(sources.current_len("fiat"), 2);
        // Every failure class keeps the last accepted list.
        let mut too_many = Vec::new();
        for i in 0..=MAX_VALUES {
            too_many.push(format!("V{i}"));
        }
        let too_many: Vec<&str> = too_many.iter().map(String::as_str).collect();
        for (fetched, expected) in [
            (Err(Outcome::Transport.into()), Outcome::Transport),
            (Err(Outcome::Status.into()), Outcome::Status),
            (Err(Outcome::Oversize.into()), Outcome::Oversize),
            (Ok(b"<html>".to_vec()), Outcome::Json),
            (Ok(b"{\"other\":[]}".to_vec()), Outcome::Pointer),
            (Ok(b"{\"data\":[]}".to_vec()), Outcome::Empty),
            (Ok(doc(&["bad value", "x|y"])), Outcome::Empty),
            (Ok(doc(&too_many)), Outcome::TooMany),
        ] {
            assert_eq!(sources.apply(NET, "fiat", fetched), expected);
            assert!(sources.admits("fiat", "JPY"), "{expected:?}");
            assert!(!sources.admits("fiat", "USD"), "{expected:?}");
            assert_eq!(sources.current_len("fiat"), 2, "{expected:?}");
        }
        // A later success replaces it; clones share the list.
        let clone = sources.clone();
        assert_eq!(clone.apply(NET, "fiat", Ok(doc(&["CHF"]))), Outcome::Ok);
        assert!(sources.admits("fiat", "CHF") && !sources.admits("fiat", "JPY"));
    }

    #[test]
    fn without_a_fallback_nothing_is_admitted_until_the_first_success() {
        crate::health::init_metrics();
        let sources = fiat(false);
        assert!(!sources.admits("fiat", "USD"));
        assert_eq!(sources.current_len("fiat"), 0);
        for failure in [Outcome::Transport, Outcome::Status, Outcome::Json] {
            sources.apply(NET, "fiat", Err(failure.into()));
            assert!(!sources.admits("fiat", "USD"));
        }
        assert_eq!(sources.apply(NET, "fiat", Ok(doc(&[]))), Outcome::Empty);
        assert!(!sources.admits("fiat", "USD"));
        assert_eq!(sources.apply(NET, "fiat", Ok(doc(&["USD"]))), Outcome::Ok);
        assert!(sources.admits("fiat", "USD"));
        assert!(!sources.admits("fiat", "usd"));
    }

    #[test]
    fn retries_back_off_from_60_seconds_up_to_the_refresh_interval() {
        let refresh = Duration::from_secs(21600);
        let waits: Vec<u64> = (1..=10)
            .map(|f| retry_delay(refresh, f).as_secs())
            .collect();
        assert_eq!(
            waits,
            [60, 120, 240, 480, 960, 1920, 3840, 7680, 15360, 21600]
        );
        assert_eq!(retry_delay(refresh, u32::MAX), refresh);
        assert_eq!(
            retry_delay(Duration::from_secs(300), 4),
            Duration::from_secs(300)
        );
        for _ in 0..100 {
            let wait = next_delay(refresh, 3).as_secs_f64();
            assert!((216.0..=264.0).contains(&wait), "{wait}");
        }
        for _ in 0..100 {
            let wait = next_delay(refresh, 0).as_secs_f64();
            assert!((19440.0..=23760.0).contains(&wait), "{wait}");
        }
    }

    #[test]
    fn a_list_never_shrinks_below_half_in_one_refresh() {
        crate::health::init_metrics();
        // The fallback (3 values) is the list to compare with before the first success.
        let sources = QueryValueSources::parse(
            "fiat=prices.example GET /v1/fiat/map#/data/*/symbol@300@fallback=USD|EUR|GBP",
        )
        .unwrap();
        assert_eq!(
            sources.apply(NET, "fiat", Ok(doc(&["JPY"]))),
            Outcome::TooFew
        );
        assert!(sources.admits("fiat", "USD") && !sources.admits("fiat", "JPY"));
        // The first accepted list replaces the fallback; it is not merged into it.
        assert_eq!(
            sources.apply(NET, "fiat", Ok(doc(&["JPY", "CHF"]))),
            Outcome::Ok
        );
        assert!(sources.admits("fiat", "JPY") && !sources.admits("fiat", "USD"));
        let ten: Vec<String> = (0..10).map(|i| format!("C{i}")).collect();
        let ten: Vec<&str> = ten.iter().map(String::as_str).collect();
        assert_eq!(sources.apply(NET, "fiat", Ok(doc(&ten))), Outcome::Ok);
        // From 10: 4 is too few, 5 is enough; invalid items do not count.
        assert_eq!(
            sources.apply(NET, "fiat", Ok(doc(&["C1", "C2", "C3", "C4", "bad value"]))),
            Outcome::TooFew
        );
        assert_eq!(sources.current_len("fiat"), 10);
        assert_eq!(
            sources.apply(NET, "fiat", Ok(doc(&["C1", "C2", "C3", "C4", "C5"]))),
            Outcome::Ok
        );
        assert_eq!(sources.current_len("fiat"), 5);
        // From 5 at least 3, from 3 at least 2, from 2 and from 1 at least 1.
        assert_eq!(
            sources.apply(NET, "fiat", Ok(doc(&["C1", "C2"]))),
            Outcome::TooFew
        );
        assert_eq!(
            sources.apply(NET, "fiat", Ok(doc(&["C1", "C2", "C3"]))),
            Outcome::Ok
        );
        assert_eq!(
            sources.apply(NET, "fiat", Ok(doc(&["C1"]))),
            Outcome::TooFew
        );
        assert_eq!(
            sources.apply(NET, "fiat", Ok(doc(&["C1", "C2"]))),
            Outcome::Ok
        );
        assert_eq!(sources.apply(NET, "fiat", Ok(doc(&["C1"]))), Outcome::Ok);
        assert_eq!(sources.apply(NET, "fiat", Ok(doc(&["C9"]))), Outcome::Ok);
        assert!(sources.admits("fiat", "C9"));
    }

    #[test]
    fn the_walk_stops_as_soon_as_there_are_too_many_values() {
        // MAX_VALUES + 1 valid values, then invalid items: the walk ends before them.
        let mut items: Vec<String> = (0..=MAX_VALUES).map(|i| format!("\"V{i}\"")).collect();
        items.extend((0..10).map(|_| "7".to_string()));
        let body = format!("[{}]", items.join(","));
        assert_eq!(values("/*", &body), (Err(Outcome::TooMany), 0));
        // With MAX_VALUES the invalid ones are walked (and counted).
        let mut items: Vec<String> = (0..MAX_VALUES).map(|i| format!("\"V{i}\"")).collect();
        items.extend((0..10).map(|_| "7".to_string()));
        let body = format!("[{}]", items.join(","));
        let (result, skipped) = values("/*", &body);
        assert_eq!((result.map(|v| v.len()), skipped), (Ok(MAX_VALUES), 10));
    }
}

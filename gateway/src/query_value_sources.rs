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
//! The grammar, the lists and the acceptance rules are
//! [`zodl_ohttp_integrations::core::value_source`]; this module reads the variable, runs the
//! refreshes and logs and records each one. Each process fetches every source on its own, in the
//! background: first after a random 0..5 s, then every `REFRESH_SECS`; after a failure again in
//! 60 s, doubling up to `REFRESH_SECS`; every wait +-10 %. The fetch is a `GET` of the alias
//! through the forwarder, sent like any request to it (its `BACKENDS` base URL and
//! `BACKEND_HEADERS`), outside the third-party cache and the upstream cap, with its own deadline
//! and body cap. A refresh that fails in any way changes nothing: the last accepted list stays.
//! A document with fewer valid values than half the admitted list (rounded up, at least one) is
//! a failure too, so a refresh never accepts a list that small: it is held until a restart or a
//! configuration change. Before the first accepted list the `fallback` list is used (the first
//! accepted list replaces it); without one `{from:name}` admits nothing (fail closed). A list
//! never becomes empty through a refresh.

use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use tracing::{info, warn};
use zodl_ohttp_integrations::core::value_source::{self as core, Change};

pub use zodl_ohttp_integrations::core::value_source::{
    retry_delay, Failure, Outcome, SourceSpec, ENV, MAX_BODY_BYTES,
};

/// Deadline of one fetch (head and body).
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// The configured sources and their current lists
/// ([`zodl_ohttp_integrations::core::value_source::QueryValueSources`], whose reads it offers),
/// with the refreshes. A handle: clones share the lists.
#[derive(Clone, Default)]
pub struct QueryValueSources(core::QueryValueSources);

impl std::fmt::Debug for QueryValueSources {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::ops::Deref for QueryValueSources {
    type Target = core::QueryValueSources;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl QueryValueSources {
    /// `THIRD_PARTY_QUERY_VALUE_SOURCES` from the environment. Unset or blank: no source; a
    /// value that is not UTF-8 is an error.
    pub fn from_env() -> anyhow::Result<Self> {
        match crate::config_source::var(ENV) {
            Ok(raw) if raw.trim().is_empty() => Ok(Self::default()),
            Ok(raw) => Self::parse(&raw),
            Err(std::env::VarError::NotPresent) => Ok(Self::default()),
            Err(std::env::VarError::NotUnicode(_)) => bail!("Invalid {ENV}: not valid UTF-8"),
        }
    }

    /// Parse `name=alias GET /path#/json/pointer@REFRESH_SECS[@fallback=A|B|C];name2=...`.
    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        core::QueryValueSources::parse(raw).map(Self)
    }

    /// The sources and lists without the refreshes.
    pub fn core(&self) -> &core::QueryValueSources {
        &self.0
    }

    /// Apply the result of one fetch of `name` (`Ok(body)` or the failure), log and record it
    /// ([`core::QueryValueSources::update`]).
    pub fn apply(&self, network: &str, name: &str, fetched: Result<Vec<u8>, Failure>) -> Outcome {
        // Callers only pass configured names; an unknown one changes nothing.
        let Some(update) = self.0.update(name, fetched) else {
            return Outcome::Pointer;
        };
        if update.skipped > 0 {
            crate::health::add_query_value_source_skipped(network, name, update.skipped as u64);
        }
        match &update.change {
            Change::Failed(failure) => warn!(
                network,
                source = name,
                result = failure.outcome.label(),
                status = ?failure.status,
                error = %failure.error,
                values = update.before,
                "Query value source refresh failed; the current list stays"
            ),
            Change::ConfirmedFallback => info!(
                network,
                source = name,
                values = update.values,
                "Query value source list accepted, unchanged from fallback"
            ),
            Change::Replaced { added, removed } => info!(
                network,
                source = name,
                values = update.values,
                added,
                removed,
                "Query value source list changed"
            ),
            Change::Unchanged => {}
        }
        if update.outcome == Outcome::Ok {
            crate::health::set_query_value_source_values(network, name, update.values);
            crate::health::record_query_value_source_success(network, name);
        }
        crate::health::record_query_value_source_refresh(network, name, update.outcome.label());
        update.outcome
    }

    /// Fetch `name` now through `state` and apply the result.
    pub async fn refresh(&self, state: &Arc<crate::AppState>, name: &str) -> Outcome {
        let Some(spec) = self.spec(name) else {
            return Outcome::Pointer;
        };
        let fetched = fetch(state, spec).await;
        self.apply(&state.config.network, name, fetched)
    }

    /// One refresh task per source: a first fetch after a random 0..5 s, then [`next_delay`]
    /// after each.
    pub fn spawn_refresh_tasks(&self, state: Arc<crate::AppState>) {
        for spec in self.specs() {
            let name = spec.name.clone();
            let refresh = spec.refresh;
            let network = state.config.network.clone();
            crate::health::init_query_value_source(&network, &name, self.current_len(&name));
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

#[cfg(test)]
mod tests {
    use super::*;
    use zodl_ohttp_integrations::core::value_source::MAX_VALUES;

    const NET: &str = "testnet-value-sources";
    const FIAT: &str = "fiat=Prices.Example GET /v1/fiat/map#/data/*/symbol@21600@fallback=USD|EUR";

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

    /// The value of the series of metric `name` with `labels` (a counter or a gauge; 0 when
    /// there is none).
    fn metric(name: &str, labels: &[(&str, &str)]) -> f64 {
        crate::health::REGISTRY
            .gather()
            .iter()
            .filter(|f| f.get_name() == name)
            .flat_map(|f| f.get_metric().iter())
            .filter(|m| {
                labels.iter().all(|(n, v)| {
                    m.get_label()
                        .iter()
                        .any(|l| l.get_name() == *n && l.get_value() == *v)
                })
            })
            .map(|m| m.get_counter().get_value() + m.get_gauge().get_value())
            .sum()
    }

    #[test]
    fn each_refresh_records_its_metrics() {
        crate::health::init_metrics();
        let net = "testnet-value-sources-metrics";
        let sources = fiat(true);
        let series = [("network", net), ("source", "fiat")];
        let refreshes = |result: &str| {
            metric(
                "ohttp_query_value_source_refresh_total",
                &[("network", net), ("source", "fiat"), ("result", result)],
            )
        };
        let values = || metric("ohttp_query_value_source_values", &series);
        let skipped = || metric("ohttp_query_value_source_skipped_total", &series);
        let last_success = || {
            metric(
                "ohttp_query_value_source_last_success_timestamp_seconds",
                &series,
            )
        };
        // A failure with skipped items: counted by result, nothing else recorded.
        assert_eq!(
            sources.apply(net, "fiat", Ok(doc(&["bad value"]))),
            Outcome::Empty
        );
        assert_eq!(
            (refreshes("empty"), refreshes("ok"), skipped()),
            (1.0, 0.0, 1.0)
        );
        assert_eq!((values(), last_success()), (0.0, 0.0));
        // The fallback confirmed: its size and the time of the success.
        assert_eq!(
            sources.apply(net, "fiat", Ok(doc(&["USD", "EUR", "x y"]))),
            Outcome::Ok
        );
        assert_eq!((refreshes("ok"), values(), skipped()), (1.0, 2.0, 2.0));
        assert!(last_success() > 0.0);
        // Unchanged: recorded like any success.
        assert_eq!(
            sources.apply(net, "fiat", Ok(doc(&["EUR", "USD"]))),
            Outcome::Ok
        );
        assert_eq!((refreshes("ok"), values(), skipped()), (2.0, 2.0, 2.0));
        // Replaced: the new size.
        assert_eq!(
            sources.apply(net, "fiat", Ok(doc(&["JPY", "CHF", "GBP"]))),
            Outcome::Ok
        );
        assert_eq!((refreshes("ok"), values()), (3.0, 3.0));
        // A transport failure: its result only, the size stays.
        assert_eq!(
            sources.apply(net, "fiat", Err(Outcome::Transport.into())),
            Outcome::Transport
        );
        assert_eq!((refreshes("transport"), values()), (1.0, 3.0));
        // An unknown source records nothing.
        assert_eq!(
            sources.apply(net, "other", Ok(doc(&["USD"]))),
            Outcome::Pointer
        );
        assert_eq!(
            metric(
                "ohttp_query_value_source_refresh_total",
                &[("network", net), ("source", "other")]
            ),
            0.0
        );
    }
}

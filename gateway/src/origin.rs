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

//! Multi-origin settings: several gateways behind one load balancer.
//!
//! Every setting here is inert by default. Without `ORIGIN_ID` and `REPLAY_PEER_URLS` the
//! gateway behaves exactly as a single origin: the origin label is `-`, replay nonces live in the
//! local security Redis only.
//!
//! - `ORIGIN_ID`: operator label of this origin (`origin-a`, `origin-b`), at most 32 characters
//!   of `[A-Za-z0-9._-]`. It is a log field and the `origin` label of `ohttp_origin_info`. It is
//!   never put in a response: a client must not be able to tell which origin answered.
//! - `REPLAY_PEER_URLS`: the security Redis of each other origin, comma-separated
//!   (`redis://` or `rediss://`, credentials in the URL). A replay nonce is written to every peer
//!   as well as to the local store, and a nonce that any store already holds is a replay. So an
//!   encapsulated request captured at one origin and replayed to another is refused as long as
//!   the peers are reachable (`cache::ResponseCache::check_replay`; synchronous in `sync` mode and
//!   for WRITEs in `async-reads`, see `REPLAY_PEER_MODE`).
//! - `REPLAY_PEER_TIMEOUT_MS` (default 150): the budget for all peer round trips of one request,
//!   run concurrently. Peers can be far away, so this is separate from `REDIS_OP_TIMEOUT_MS`.
//! - `REPLAY_PEER_FAIL_CLOSED` (default false): whether a peer error or timeout refuses the
//!   request (outer 503, like a local security Redis failure). The default keeps the origin
//!   serving on its local verdict when the link between origins is down, accepting a cross-origin
//!   replay window bounded by the outage; every such outcome is counted in
//!   `ohttp_replay_peer_total{result="error"|"timeout"|"disconnected"}`.
//! - `REPLAY_PEER_MODE` (default `sync`; only meaningful with `REPLAY_PEER_URLS`): how the peers
//!   are consulted.
//!   - `sync`: every request writes the nonce to the local store and to every peer
//!     synchronously (check-any). One round trip to the peers per request.
//!   - `async-reads`: a request whose inner route is on the READ allowlist
//!     (`REPLAY_READ_ROUTES`) is checked in the local store synchronously (fail-closed as
//!     always) and its nonce is then replicated to the peers asynchronously, in pipelined
//!     batches, off the request path. Everything else is a WRITE and takes the `sync` path; for
//!     WRITEs an unavailable peer refuses the request when `REPLAY_PEER_FAIL_CLOSED_WRITES`
//!     (default true). Replication health is watched (`replication.rs`): when the enqueue-to-ack
//!     lag p99 exceeds `REPLAY_ASYNC_MAX_LAG_MS` (default 500), the queue overflows or a peer is
//!     unreachable, READs fall back to the synchronous path until the peers have been healthy
//!     for `REPLAY_ASYNC_RECOVERY_SECS` (default 30).
//!   - `failover`: active-passive. Every request is checked locally only and its nonce
//!     replicated asynchronously to the peers (a WRITE's after its local verdict). For a load
//!     balancer that sends all traffic to one origin: the passive origin's store is kept warm so
//!     that a switch-over opens a replay window only for nonces still being replicated. With
//!     `REPLAY_WRITE_WAIT_REPLICAS` and `REPLAY_PEER_WAIT_REPLICAS` >= 1 a WRITE also has a
//!     synchronous peer round trip when the local replica acknowledgement is short, and for one
//!     nonce TTL after startup or a local store failover (`write_fallback.rs`).
//! - `REPLAY_STANDBY_URLS`: the security store of each standby origin, comma-separated (same
//!   syntax as `REPLAY_PEER_URLS`, no entry may also be a peer). A standby origin is one that
//!   takes WRITEs only while the shared store of the peers is unreachable (it checks its own
//!   store then). Every WRITE this gateway admits is also replicated there, asynchronously, off
//!   the request path (the `failover` mechanism: per-store queue, pipelined batches, retried
//!   until the nonce TTL). That hand-off never refuses or delays a request; it keeps the
//!   standby from admitting the same WRITE once more after a switch-over. With
//!   `REPLAY_PEER_WAIT_REPLICAS` >= 1 the standby stores also take part in the request path of
//!   an `async-reads` WRITE, in the hub path of the WRITE fallback (`write_fallback.rs`): while
//!   the peers' store cannot acknowledge on its replicas, or for one nonce TTL after startup or a
//!   disruption of it, a WRITE is also `SET NX` there synchronously and a nonce held there is a
//!   replay. Needed where the
//!   WRITE check goes to a shared store whose owner replicates only its own requests to the
//!   standby (a read origin in `async-reads` checking WRITEs at the primary origin's store):
//!   without it, a WRITE admitted there within the nonce TTL before the primary origin is lost
//!   is unknown to the standby.
//! - `REPLAY_UNAVAILABLE_FALLBACK` (default false): when the store that normally decides a
//!   request gives no verdict at all (unreachable, a timeout, an error), decide it at the
//!   fallback store instead of failing closed (`write_fallback.rs`, "Unavailable store"): a
//!   `failover`-mode origin whose own store is down decides at its peers (READs `SET NX`,
//!   WRITEs `SET NX` + the peers' `WAIT`); an `async-reads` origin whose hub is down confirms
//!   WRITEs at its standby stores, or by its own replicas when its own store is the fallback
//!   store. Every gateway that checks at the same stores must run a version that checks every
//!   WRITE at the fallback store (`write_fallback.rs`, "Check at the fallback store") before
//!   any of them turns this on.
//! - `REPLAY_READ_ROUTES`: the READ allowlist for `async-reads`, in the `BACKENDS_POLICY`
//!   syntax (`authority=METHOD /path,...;authority2=...`; `/*` suffix = segment-bounded prefix,
//!   `*` method = any). The pseudo-authority `lwd` stands for the gateway's own lightwalletd (any
//!   `GATEWAY_HOSTS` entry). Anything not listed is a WRITE (fail-safe). The default is every
//!   read-only lightwalletd RPC (`default_read_routes_spec`) and no third-party route: a
//!   deployment whose `BACKENDS` aliases have read-only routes lists them itself, together with
//!   the `lwd=` entry (a set value replaces the default). The effective list is logged at
//!   startup.

use std::collections::BTreeMap;
use std::env;
use std::fmt;

pub const DEFAULT_REPLAY_PEER_TIMEOUT_MS: u64 = 150;
pub const DEFAULT_REPLAY_ASYNC_MAX_LAG_MS: u64 = 500;
pub const DEFAULT_REPLAY_ASYNC_RECOVERY_SECS: u64 = 30;
pub const DEFAULT_REPLAY_ASYNC_FAILURES_BEFORE_STRICT: usize = 3;
const MAX_ORIGIN_ID_LEN: usize = 32;

/// Pseudo-authority in `REPLAY_READ_ROUTES` for the gateway's own lightwalletd (any `GATEWAY_HOSTS`
/// entry), so the default list does not depend on the deployment's hostnames.
pub const LWD_PSEUDO_AUTHORITY: &str = "lwd";

const LWD_RPC_PREFIX: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/";

/// Every read-only RPC of lightwalletd's `CompactTxStreamer` (service.proto). `SendTransaction`
/// is the only RPC with a side effect and is deliberately absent.
pub const LWD_READ_RPCS: &[&str] = &[
    "GetLatestBlock",
    "GetBlock",
    "GetBlockNullifiers",
    "GetBlockRange",
    "GetBlockRangeNullifiers",
    "GetTransaction",
    "GetTaddressTxids",
    "GetTaddressBalance",
    "GetTaddressBalanceStream",
    "GetMempoolTx",
    "GetMempoolStream",
    "GetTreeState",
    "GetLatestTreeState",
    "GetSubtreeRoots",
    "GetAddressUtxos",
    "GetAddressUtxosStream",
    "GetLightdInfo",
    "Ping",
];

/// The default `REPLAY_READ_ROUTES` document: every read-only lightwalletd RPC, no third-party
/// route (those depend on the deployment's `BACKENDS` aliases).
pub fn default_read_routes_spec() -> String {
    let lwd: Vec<String> = LWD_READ_RPCS
        .iter()
        .map(|rpc| format!("POST {LWD_RPC_PREFIX}{rpc}"))
        .collect();
    format!("{LWD_PSEUDO_AUTHORITY}={}", lwd.join(","))
}

/// How the replay peers are consulted (`REPLAY_PEER_MODE`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ReplayPeerMode {
    /// Local + every peer synchronously, for every request (today's behaviour).
    #[default]
    Sync,
    /// READs: local synchronously, peers asynchronously; WRITEs: as `Sync`.
    AsyncReads,
    /// Everything local synchronously, peers asynchronously; never a synchronous peer call.
    Failover,
}

impl ReplayPeerMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ReplayPeerMode::Sync => "sync",
            ReplayPeerMode::AsyncReads => "async-reads",
            ReplayPeerMode::Failover => "failover",
        }
    }

    fn parse(raw: &str) -> anyhow::Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "sync" => Ok(ReplayPeerMode::Sync),
            "async-reads" | "async_reads" | "asyncreads" => Ok(ReplayPeerMode::AsyncReads),
            "failover" => Ok(ReplayPeerMode::Failover),
            other => anyhow::bail!(
                "Malformed REPLAY_PEER_MODE '{other}': must be sync, async-reads or failover"
            ),
        }
    }
}

impl fmt::Display for ReplayPeerMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The replay-protection class of an inner request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteClass {
    /// On the READ allowlist: no side effect at the upstream, so a second execution at another
    /// origin inside the replication window is harmless.
    Read,
    /// Everything else (fail-safe): cross-origin replay protection is synchronous (`sync` and
    /// `async-reads` modes; `failover` replicates every nonce asynchronously).
    Write,
}

impl RouteClass {
    pub fn as_str(self) -> &'static str {
        match self {
            RouteClass::Read => "read",
            RouteClass::Write => "write",
        }
    }
}

/// The READ allowlist (`REPLAY_READ_ROUTES`), `authority -> [(METHOD, path pattern)]`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReadRoutes {
    rules: BTreeMap<String, Vec<(String, String)>>,
}

impl ReadRoutes {
    /// Parse a `BACKENDS_POLICY`-style document. Empty = the default list.
    pub fn parse(spec: &str) -> anyhow::Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Self::parse(&default_read_routes_spec());
        }
        let mut rules: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
        for entry in spec.split(';') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let Some((authority, policies)) = entry.split_once('=') else {
                anyhow::bail!("Malformed REPLAY_READ_ROUTES entry (missing '='): {entry}");
            };
            let authority = authority.trim().to_ascii_lowercase();
            if authority.is_empty() {
                anyhow::bail!("Malformed REPLAY_READ_ROUTES: missing authority in '{entry}'");
            }
            let mut list = Vec::new();
            for policy in policies.split(',') {
                let policy = policy.trim();
                if policy.is_empty() {
                    continue;
                }
                let Some((method, path)) = policy.split_once(' ') else {
                    anyhow::bail!(
                        "Malformed REPLAY_READ_ROUTES: '{policy}' must be 'METHOD /path' (entry: '{entry}')"
                    );
                };
                let method = method.trim().to_ascii_uppercase();
                let path = path.trim().to_string();
                if !matches!(
                    method.as_str(),
                    "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "*"
                ) {
                    anyhow::bail!(
                        "Invalid REPLAY_READ_ROUTES method '{method}' in '{policy}': must be GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH/*"
                    );
                }
                if !path.starts_with('/') {
                    anyhow::bail!(
                        "Invalid REPLAY_READ_ROUTES path '{path}' in '{policy}': must start with /"
                    );
                }
                list.push((method, path));
            }
            if list.is_empty() {
                anyhow::bail!(
                    "Malformed REPLAY_READ_ROUTES: no routes for authority '{authority}'"
                );
            }
            rules.entry(authority).or_default().extend(list);
        }
        if rules.is_empty() {
            anyhow::bail!("Malformed REPLAY_READ_ROUTES: no entries");
        }
        Ok(Self { rules })
    }

    /// The default allowlist.
    pub fn default_list() -> Self {
        Self::parse(&default_read_routes_spec()).expect("default REPLAY_READ_ROUTES parses")
    }

    /// Classify an inner request. `is_lwd`: the authority resolved to the gateway's own lightwalletd
    /// (`proxy::resolve_backend(..).is_lwd()`), which the pseudo-authority `lwd` matches.
    /// Unknown authority, method or path => `Write` (fail-safe).
    pub fn classify(&self, is_lwd: bool, authority: &str, method: &str, path: &str) -> RouteClass {
        if path.is_empty() || !path.starts_with('/') {
            return RouteClass::Write;
        }
        let host = authority
            .to_ascii_lowercase()
            .split(':')
            .next()
            .unwrap_or("")
            .to_string();
        let candidates = [
            is_lwd.then_some(LWD_PSEUDO_AUTHORITY),
            (!host.is_empty()).then_some(host.as_str()),
        ];
        for authority in candidates.into_iter().flatten() {
            let Some(rules) = self.rules.get(authority) else {
                continue;
            };
            for (allowed_method, pattern) in rules {
                if allowed_method != "*" && !method.eq_ignore_ascii_case(allowed_method) {
                    continue;
                }
                if path_matches(pattern, path) {
                    return RouteClass::Read;
                }
            }
        }
        RouteClass::Write
    }

    pub fn len(&self) -> usize {
        self.rules.values().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// `BACKENDS_POLICY` path semantics: exact (query allowed) unless the pattern ends in `/*`,
/// which is a segment-bounded prefix (`/foo/*` matches `/foo` and `/foo/bar`, not `/foobar`);
/// `/*` matches everything.
pub(crate) fn path_matches(pattern: &str, path: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/*") {
        prefix.is_empty() || path == prefix || path.starts_with(&format!("{prefix}/"))
    } else {
        path == pattern || path.starts_with(&format!("{pattern}?"))
    }
}

impl fmt::Display for ReadRoutes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (authority, rules) in &self.rules {
            if !first {
                f.write_str(";")?;
            }
            first = false;
            let list: Vec<String> = rules.iter().map(|(m, p)| format!("{m} {p}")).collect();
            write!(f, "{authority}={}", list.join(","))?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OriginSettings {
    pub origin_id: String,
    pub replay_peer_urls: Vec<String>,
    /// `REPLAY_STANDBY_URLS`.
    pub replay_standby_urls: Vec<String>,
    pub replay_peer_timeout_ms: u64,
    pub replay_peer_fail_closed: bool,
    /// `REPLAY_PEER_MODE`.
    pub replay_peer_mode: ReplayPeerMode,
    /// `REPLAY_PEER_FAIL_CLOSED_WRITES` (async-reads: an unavailable peer refuses a WRITE).
    pub replay_peer_fail_closed_writes: bool,
    /// `REPLAY_ASYNC_MAX_LAG_MS`.
    pub replay_async_max_lag_ms: u64,
    /// `REPLAY_ASYNC_RECOVERY_SECS`.
    pub replay_async_recovery_secs: u64,
    /// `REPLAY_ASYNC_FAILURES_BEFORE_STRICT`.
    pub replay_async_failures_before_strict: usize,
    /// `REPLAY_READ_ROUTES` (parsed; the default list when unset).
    pub replay_read_routes: ReadRoutes,
    /// `REPLAY_UNAVAILABLE_FALLBACK` (default false).
    pub replay_unavailable_fallback: bool,
}

/// The raw environment of `OriginSettings::parse_env`, so tests can build it without `set_var`.
#[derive(Clone, Debug, Default)]
pub struct RawOriginEnv<'a> {
    pub origin_id: Option<&'a str>,
    pub peer_urls: Option<&'a str>,
    pub standby_urls: Option<&'a str>,
    pub peer_timeout_ms: Option<&'a str>,
    pub peer_fail_closed: Option<&'a str>,
    pub peer_mode: Option<&'a str>,
    pub peer_fail_closed_writes: Option<&'a str>,
    pub async_max_lag_ms: Option<&'a str>,
    pub async_recovery_secs: Option<&'a str>,
    pub async_failures_before_strict: Option<&'a str>,
    pub read_routes: Option<&'a str>,
    pub unavailable_fallback: Option<&'a str>,
}

impl OriginSettings {
    pub fn from_env() -> anyhow::Result<Self> {
        let get = |k: &str| env::var(k).ok();
        let (
            origin_id,
            peer_urls,
            standby_urls,
            peer_timeout_ms,
            peer_fail_closed,
            peer_mode,
            peer_fail_closed_writes,
            async_max_lag_ms,
            async_recovery_secs,
            async_failures_before_strict,
            read_routes,
            unavailable_fallback,
        ) = (
            get("ORIGIN_ID"),
            get("REPLAY_PEER_URLS"),
            get("REPLAY_STANDBY_URLS"),
            get("REPLAY_PEER_TIMEOUT_MS"),
            get("REPLAY_PEER_FAIL_CLOSED"),
            get("REPLAY_PEER_MODE"),
            get("REPLAY_PEER_FAIL_CLOSED_WRITES"),
            get("REPLAY_ASYNC_MAX_LAG_MS"),
            get("REPLAY_ASYNC_RECOVERY_SECS"),
            get("REPLAY_ASYNC_FAILURES_BEFORE_STRICT"),
            get("REPLAY_READ_ROUTES"),
            get("REPLAY_UNAVAILABLE_FALLBACK"),
        );
        Self::parse_env(RawOriginEnv {
            origin_id: origin_id.as_deref(),
            peer_urls: peer_urls.as_deref(),
            standby_urls: standby_urls.as_deref(),
            peer_timeout_ms: peer_timeout_ms.as_deref(),
            peer_fail_closed: peer_fail_closed.as_deref(),
            peer_mode: peer_mode.as_deref(),
            peer_fail_closed_writes: peer_fail_closed_writes.as_deref(),
            async_max_lag_ms: async_max_lag_ms.as_deref(),
            async_recovery_secs: async_recovery_secs.as_deref(),
            async_failures_before_strict: async_failures_before_strict.as_deref(),
            read_routes: read_routes.as_deref(),
            unavailable_fallback: unavailable_fallback.as_deref(),
        })
    }

    /// The pre-mode settings only (mode `sync`, default allowlist).
    pub fn parse(
        origin_id: Option<&str>,
        peer_urls: Option<&str>,
        peer_timeout_ms: Option<&str>,
        peer_fail_closed: Option<&str>,
    ) -> anyhow::Result<Self> {
        Self::parse_env(RawOriginEnv {
            origin_id,
            peer_urls,
            peer_timeout_ms,
            peer_fail_closed,
            ..RawOriginEnv::default()
        })
    }

    pub fn parse_env(raw: RawOriginEnv<'_>) -> anyhow::Result<Self> {
        let origin_id = raw.origin_id.unwrap_or_default().trim().to_string();
        if origin_id.len() > MAX_ORIGIN_ID_LEN
            || !origin_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            anyhow::bail!(
                "ORIGIN_ID must be at most {MAX_ORIGIN_ID_LEN} characters of [A-Za-z0-9._-], got '{origin_id}'"
            );
        }

        let replay_peer_urls = parse_store_urls("REPLAY_PEER_URLS", raw.peer_urls)?;
        let replay_standby_urls = parse_store_urls("REPLAY_STANDBY_URLS", raw.standby_urls)?;
        if let Some(i) = replay_standby_urls
            .iter()
            .position(|u| replay_peer_urls.contains(u))
        {
            anyhow::bail!(
                "Malformed REPLAY_STANDBY_URLS: entry at position {i} is also in REPLAY_PEER_URLS"
            );
        }

        let replay_peer_timeout_ms = parse_positive_u64(
            "REPLAY_PEER_TIMEOUT_MS",
            raw.peer_timeout_ms,
            DEFAULT_REPLAY_PEER_TIMEOUT_MS,
        )?;
        let replay_async_max_lag_ms = parse_positive_u64(
            "REPLAY_ASYNC_MAX_LAG_MS",
            raw.async_max_lag_ms,
            DEFAULT_REPLAY_ASYNC_MAX_LAG_MS,
        )?;
        let replay_async_recovery_secs = parse_positive_u64(
            "REPLAY_ASYNC_RECOVERY_SECS",
            raw.async_recovery_secs,
            DEFAULT_REPLAY_ASYNC_RECOVERY_SECS,
        )?;
        let replay_async_failures_before_strict = parse_positive_usize(
            "REPLAY_ASYNC_FAILURES_BEFORE_STRICT",
            raw.async_failures_before_strict,
            DEFAULT_REPLAY_ASYNC_FAILURES_BEFORE_STRICT,
        )?;

        let replay_peer_fail_closed = parse_flag(raw.peer_fail_closed, false);
        let replay_peer_fail_closed_writes = parse_flag(raw.peer_fail_closed_writes, true);
        let replay_peer_mode = ReplayPeerMode::parse(raw.peer_mode.unwrap_or_default())?;
        let replay_read_routes = ReadRoutes::parse(raw.read_routes.unwrap_or_default())?;
        let replay_unavailable_fallback = parse_flag(raw.unavailable_fallback, false);

        Ok(Self {
            origin_id,
            replay_peer_urls,
            replay_standby_urls,
            replay_peer_timeout_ms,
            replay_peer_fail_closed,
            replay_peer_mode,
            replay_peer_fail_closed_writes,
            replay_async_max_lag_ms,
            replay_async_recovery_secs,
            replay_async_failures_before_strict,
            replay_read_routes,
            replay_unavailable_fallback,
        })
    }

    /// The origin as a log field / metric label: ORIGIN_ID, or `-` when unset.
    pub fn label(&self) -> &str {
        if self.origin_id.is_empty() {
            "-"
        } else {
            &self.origin_id
        }
    }

    /// Whether any peer is consulted asynchronously (modes other than `sync`, with peers).
    pub fn uses_async_replication(&self) -> bool {
        !self.replay_peer_urls.is_empty() && self.replay_peer_mode != ReplayPeerMode::Sync
    }
}

/// A comma-separated list of `redis://` / `rediss://` URLs (credentials in the URL): no empty
/// entries, no duplicates. Errors name the position only, never the URL.
fn parse_store_urls(name: &str, raw: Option<&str>) -> anyhow::Result<Vec<String>> {
    let mut urls: Vec<String> = Vec::new();
    let raw = raw.unwrap_or_default();
    if raw.trim().is_empty() {
        return Ok(urls);
    }
    for (i, url) in raw.split(',').enumerate() {
        let url = url.trim();
        if url.is_empty() {
            anyhow::bail!(
                "Malformed {name}: empty entry at position {i} (check for trailing commas)"
            );
        }
        if !url.starts_with("redis://") && !url.starts_with("rediss://") {
            anyhow::bail!(
                "Malformed {name} entry at position {i}: must start with redis:// or rediss://"
            );
        }
        if urls.iter().any(|u| u == url) {
            anyhow::bail!("Malformed {name}: entry at position {i} is a duplicate");
        }
        urls.push(url.to_string());
    }
    Ok(urls)
}

fn parse_positive_u64(name: &str, raw: Option<&str>, default: u64) -> anyhow::Result<u64> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(default),
        Some(s) => {
            let v: u64 = s
                .parse()
                .map_err(|e| anyhow::anyhow!("Malformed {name} '{s}': {e}"))?;
            if v == 0 {
                anyhow::bail!("{name} must be positive");
            }
            Ok(v)
        }
    }
}

fn parse_positive_usize(name: &str, raw: Option<&str>, default: usize) -> anyhow::Result<usize> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(default),
        Some(s) => {
            let v: usize = s
                .parse()
                .map_err(|e| anyhow::anyhow!("Malformed {name} '{s}': {e}"))?;
            if v == 0 {
                anyhow::bail!("{name} must be positive");
            }
            Ok(v)
        }
    }
}

/// `1`/`true` => true, `0`/`false` => false (case-insensitive); anything else, or unset, is the
/// default. Unknown strings therefore never silently flip a safety default.
fn parse_flag(raw: Option<&str>, default: bool) -> bool {
    match raw.map(str::trim) {
        Some(v) if v == "1" || v.eq_ignore_ascii_case("true") => true,
        Some(v) if v == "0" || v.eq_ignore_ascii_case("false") => false,
        _ => default,
    }
}

/// Short fingerprint of a shared secret for the startup log, so that two origins can be
/// compared without printing the secret: first 8 hex of SHA-256 over a fixed domain separator
/// and the secret. 32 bits of a hash of a high-entropy secret reveal nothing useful.
pub fn secret_fingerprint(domain: &str, secret: &[u8]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(b"zodl-ohttp-fingerprint-v1");
    h.update([0u8]);
    h.update(domain.as_bytes());
    h.update([0u8]);
    h.update(secret);
    hex::encode(&h.finalize()[..4])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lwd(rpc: &str) -> String {
        format!("{LWD_RPC_PREFIX}{rpc}")
    }

    #[test]
    fn unset_is_single_origin() {
        let s = OriginSettings::parse(None, None, None, None).unwrap();
        assert_eq!(s, OriginSettings::default_single_origin());
        assert_eq!(s.label(), "-");
        assert!(s.replay_peer_urls.is_empty());
        assert!(!s.replay_peer_fail_closed);
        assert_eq!(s.replay_peer_timeout_ms, DEFAULT_REPLAY_PEER_TIMEOUT_MS);
        assert_eq!(s.replay_peer_mode, ReplayPeerMode::Sync);
        assert!(s.replay_peer_fail_closed_writes);
        assert_eq!(s.replay_async_max_lag_ms, DEFAULT_REPLAY_ASYNC_MAX_LAG_MS);
        assert_eq!(
            s.replay_async_recovery_secs,
            DEFAULT_REPLAY_ASYNC_RECOVERY_SECS
        );
        assert!(!s.uses_async_replication());
    }

    #[test]
    fn empty_strings_are_unset() {
        let s = OriginSettings::parse(Some(""), Some(" "), Some(""), Some("")).unwrap();
        assert_eq!(s, OriginSettings::default_single_origin());
        let s = OriginSettings::parse_env(RawOriginEnv {
            peer_mode: Some(""),
            peer_fail_closed_writes: Some(""),
            async_max_lag_ms: Some(" "),
            async_recovery_secs: Some(""),
            read_routes: Some(""),
            ..RawOriginEnv::default()
        })
        .unwrap();
        assert_eq!(s, OriginSettings::default_single_origin());
    }

    #[test]
    fn origin_id_is_validated() {
        let s = OriginSettings::parse(Some(" origin-a "), None, None, None).unwrap();
        assert_eq!(s.origin_id, "origin-a");
        assert_eq!(s.label(), "origin-a");
        assert!(OriginSettings::parse(Some("origin a"), None, None, None).is_err());
        assert!(OriginSettings::parse(Some("origin\"a"), None, None, None).is_err());
        assert!(OriginSettings::parse(Some(&"a".repeat(33)), None, None, None).is_err());
        assert!(OriginSettings::parse(Some(&"a".repeat(32)), None, None, None).is_ok());
    }

    #[test]
    fn peers_are_parsed_strictly() {
        let s = OriginSettings::parse(
            None,
            Some("rediss://:pw@peer-a:6380, redis://peer-b:6379"),
            Some("200"),
            Some("1"),
        )
        .unwrap();
        assert_eq!(
            s.replay_peer_urls,
            vec!["rediss://:pw@peer-a:6380", "redis://peer-b:6379"]
        );
        assert_eq!(s.replay_peer_timeout_ms, 200);
        assert!(s.replay_peer_fail_closed);

        let err = OriginSettings::parse(None, Some("redis://a,"), None, None).unwrap_err();
        assert!(err.to_string().contains("empty entry"), "{err}");
        let err = OriginSettings::parse(None, Some("http://a"), None, None).unwrap_err();
        assert!(err.to_string().contains("redis://"), "{err}");
        let err = OriginSettings::parse(None, Some("redis://a,redis://a"), None, None).unwrap_err();
        assert!(err.to_string().contains("duplicate"), "{err}");
        assert!(OriginSettings::parse(None, None, Some("0"), None).is_err());
        assert!(OriginSettings::parse(None, None, Some("fast"), None).is_err());
    }

    #[test]
    fn standby_stores_are_parsed_strictly() {
        let s = OriginSettings::parse_env(RawOriginEnv {
            peer_urls: Some("rediss://:pw@hub:6379"),
            standby_urls: Some(" rediss://:pw@standby:6379 "),
            peer_mode: Some("async-reads"),
            ..RawOriginEnv::default()
        })
        .unwrap();
        assert_eq!(s.replay_peer_urls, vec!["rediss://:pw@hub:6379"]);
        assert_eq!(s.replay_standby_urls, vec!["rediss://:pw@standby:6379"]);

        // Unset or blank: none, whatever the peers.
        let s = OriginSettings::parse_env(RawOriginEnv {
            standby_urls: Some("  "),
            ..RawOriginEnv::default()
        })
        .unwrap();
        assert!(s.replay_standby_urls.is_empty());

        let parse = |peers: Option<&'static str>, standby: &'static str| {
            OriginSettings::parse_env(RawOriginEnv {
                peer_urls: peers,
                standby_urls: Some(standby),
                ..RawOriginEnv::default()
            })
        };
        let err = parse(None, "redis://a,").unwrap_err();
        assert!(
            err.to_string().contains("REPLAY_STANDBY_URLS: empty entry"),
            "{err}"
        );
        let err = parse(None, "http://a").unwrap_err();
        assert!(
            err.to_string().contains("REPLAY_STANDBY_URLS entry"),
            "{err}"
        );
        let err = parse(None, "redis://a, redis://a").unwrap_err();
        assert!(err.to_string().contains("duplicate"), "{err}");
        // A store is either a peer (checked) or a standby (replicated to), never both.
        let err = parse(Some("redis://hub,redis://b"), "redis://c,redis://b").unwrap_err();
        assert!(
            err.to_string()
                .contains("position 1 is also in REPLAY_PEER_URLS"),
            "{err}"
        );
        // The URL (credentials) is never part of an error.
        let err = parse(None, "http://:secret@a").unwrap_err();
        assert!(!err.to_string().contains("secret"), "{err}");
    }

    #[test]
    fn fail_closed_flag_forms() {
        for v in ["1", "true", "TRUE"] {
            assert!(
                OriginSettings::parse(None, None, None, Some(v))
                    .unwrap()
                    .replay_peer_fail_closed
            );
        }
        for v in ["0", "false", "yes", ""] {
            assert!(
                !OriginSettings::parse(None, None, None, Some(v))
                    .unwrap()
                    .replay_peer_fail_closed
            );
        }
        // The WRITE flag defaults to true and only an explicit 0/false clears it.
        for v in [None, Some(""), Some("yes"), Some("1"), Some("true")] {
            let s = OriginSettings::parse_env(RawOriginEnv {
                peer_fail_closed_writes: v,
                ..RawOriginEnv::default()
            })
            .unwrap();
            assert!(s.replay_peer_fail_closed_writes, "{v:?}");
        }
        for v in ["0", "false", "FALSE"] {
            let s = OriginSettings::parse_env(RawOriginEnv {
                peer_fail_closed_writes: Some(v),
                ..RawOriginEnv::default()
            })
            .unwrap();
            assert!(!s.replay_peer_fail_closed_writes, "{v}");
        }
    }

    #[test]
    fn mode_is_parsed() {
        for (raw, mode) in [
            ("sync", ReplayPeerMode::Sync),
            ("SYNC", ReplayPeerMode::Sync),
            ("async-reads", ReplayPeerMode::AsyncReads),
            ("async_reads", ReplayPeerMode::AsyncReads),
            (" failover ", ReplayPeerMode::Failover),
        ] {
            let s = OriginSettings::parse_env(RawOriginEnv {
                peer_mode: Some(raw),
                ..RawOriginEnv::default()
            })
            .unwrap();
            assert_eq!(s.replay_peer_mode, mode, "{raw}");
            assert_eq!(mode.to_string(), mode.as_str());
            // Without peers no mode replicates anything.
            assert!(!s.uses_async_replication());
        }
        let err = OriginSettings::parse_env(RawOriginEnv {
            peer_mode: Some("async"),
            ..RawOriginEnv::default()
        })
        .unwrap_err();
        assert!(err.to_string().contains("REPLAY_PEER_MODE"), "{err}");

        let s = OriginSettings::parse_env(RawOriginEnv {
            peer_urls: Some("redis://peer:6379"),
            peer_mode: Some("async-reads"),
            async_max_lag_ms: Some("250"),
            async_recovery_secs: Some("5"),
            ..RawOriginEnv::default()
        })
        .unwrap();
        assert!(s.uses_async_replication());
        assert_eq!(s.replay_async_max_lag_ms, 250);
        assert_eq!(s.replay_async_recovery_secs, 5);
        assert!(OriginSettings::parse_env(RawOriginEnv {
            async_max_lag_ms: Some("0"),
            ..RawOriginEnv::default()
        })
        .is_err());
        assert!(OriginSettings::parse_env(RawOriginEnv {
            async_recovery_secs: Some("soon"),
            ..RawOriginEnv::default()
        })
        .is_err());
    }

    #[test]
    fn default_read_routes_cover_every_read_only_lwd_rpc_and_nothing_else() {
        let r = ReadRoutes::default_list();
        for rpc in LWD_READ_RPCS {
            assert_eq!(
                r.classify(true, "ohttp-gateway.example", "POST", &lwd(rpc)),
                RouteClass::Read,
                "{rpc}"
            );
        }
        // The only RPC with a side effect.
        assert_eq!(
            r.classify(
                true,
                "ohttp-gateway.example",
                "POST",
                &lwd("SendTransaction")
            ),
            RouteClass::Write
        );
        // Unknown RPCs and a gateway authority without is_lwd: WRITE (fail-safe). A literal `lwd`
        // authority matches the lwd rules.
        assert_eq!(
            r.classify(
                true,
                "ohttp-gateway.example",
                "POST",
                &lwd("GetSomethingNew")
            ),
            RouteClass::Write
        );
        assert_eq!(
            r.classify(false, "lwd", "POST", &lwd("GetLatestBlock")),
            RouteClass::Read,
            "a literal authority 'lwd' matches the lwd rules too (harmless: resolve_backend rejects it later)"
        );
        assert_eq!(
            r.classify(
                false,
                "ohttp-gateway.example",
                "POST",
                &lwd("GetLatestBlock")
            ),
            RouteClass::Write,
            "an authority that does not resolve to lightwalletd is not lwd"
        );
        // The gateway's own host with a non-RPC path.
        assert_eq!(
            r.classify(true, "ohttp-gateway.example", "GET", "/"),
            RouteClass::Write
        );
        // The default list has one lwd rule per read RPC and nothing else.
        assert_eq!(r.len(), LWD_READ_RPCS.len());
        assert_eq!(
            r.classify(false, "prices.example", "GET", "/"),
            RouteClass::Write
        );
        assert_eq!(
            r.to_string(),
            ReadRoutes::parse(&r.to_string()).unwrap().to_string()
        );
    }

    /// A deployment's third-party READ routes, in the `REPLAY_READ_ROUTES` syntax: a price API,
    /// a swap API (only the public token list and the deposit status), a payments API (GETs),
    /// voting servers (GETs), PIR servers (their query is a POST without side effect) and a
    /// slot service.
    const THIRD_PARTY_TEST_ROUTES: &str = "\
prices.example=GET /*;\
swap.example=GET /v0/tokens,GET /v0/status;\
vote.example=GET /*;\
vote-primary.example=GET /*;\
voting.example=GET /*;\
vote-3.example=GET /*;\
vote-4.example=GET /*;\
pir-primary.example=GET /root,GET /tier0,GET /params/tier1,POST /tier1/query;\
pir-backup.example=GET /root,GET /tier0,GET /params/tier1,POST /tier1/query;\
pir-3.example=GET /root,GET /tier0,GET /params/tier1,POST /tier1/query;\
slots.example=GET /v1/info,GET /v1/slots/*;\
pay.example=GET /*";

    #[test]
    fn configured_third_party_read_routes() {
        let r = ReadRoutes::parse(&format!(
            "{};{THIRD_PARTY_TEST_ROUTES}",
            default_read_routes_spec()
        ))
        .unwrap();
        assert!(r.len() > LWD_READ_RPCS.len());
        let read = |a: &str, m: &str, p: &str| {
            assert_eq!(r.classify(false, a, m, p), RouteClass::Read, "{a} {m} {p}")
        };
        let write = |a: &str, m: &str, p: &str| {
            assert_eq!(r.classify(false, a, m, p), RouteClass::Write, "{a} {m} {p}")
        };

        read(
            "prices.example",
            "GET",
            "/v1/cryptocurrency/quotes/latest?symbol=ZEC",
        );
        read("PRICES.example:443", "GET", "/v1/fiat/map");
        write("prices.example", "POST", "/v1/fiat/map");

        read("swap.example", "GET", "/v0/tokens");
        read("swap.example", "GET", "/v0/status?depositAddress=x");
        write("swap.example", "POST", "/v0/quote");
        write("swap.example", "POST", "/v0/deposit/submit");
        write("swap.example", "GET", "/v0/tokens/extra");
        write("swap.example", "GET", "/v0/quote");
        read(
            "pay.example",
            "GET",
            "/events?type=commerce_session.created",
        );
        read("pay.example", "GET", "/accounts/me");
        write("pay.example", "POST", "/tokens");
        write("pay.example", "PATCH", "/commerce_sessions/cs_1");

        for host in [
            "vote.example",
            "vote-primary.example",
            "voting.example",
            "vote-3.example",
            "vote-4.example",
        ] {
            read(host, "GET", "/rounds/abc/tree");
            read(host, "get", "/");
            write(host, "POST", "/rounds/abc/ballots");
            write(host, "PUT", "/rounds/abc");
            write(host, "DELETE", "/rounds/abc");
            write(host, "HEAD", "/rounds");
        }

        for host in ["pir-primary.example", "pir-backup.example", "pir-3.example"] {
            read(host, "GET", "/root");
            read(host, "GET", "/tier0");
            read(host, "GET", "/params/tier1");
            read(host, "POST", "/tier1/query");
            write(host, "POST", "/tier0");
            write(host, "GET", "/root/extra");
        }

        read("slots.example", "GET", "/v1/info");
        read("slots.example", "GET", "/v1/slots/abc");
        write("slots.example", "POST", "/v1/slots");
        write("slots.example", "POST", "/v1/slots/abc");

        // Unknown hosts, malformed paths: WRITE.
        write("evil.example.com", "GET", "/");
        write("prices.example", "GET", "");
        write("prices.example", "GET", "v1/fiat/map");
    }

    #[test]
    fn custom_read_routes_replace_the_default() {
        let r = ReadRoutes::parse("lwd=POST /cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock; Example.COM=* /public/*").unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(
            r.classify(true, "x", "POST", &lwd("GetLatestBlock")),
            RouteClass::Read
        );
        // Everything else from the default list is now a WRITE.
        assert_eq!(
            r.classify(true, "x", "POST", &lwd("GetBlock")),
            RouteClass::Write
        );
        assert_eq!(
            r.classify(false, "prices.example", "GET", "/v1/fiat/map"),
            RouteClass::Write
        );
        assert_eq!(
            r.classify(false, "example.com", "DELETE", "/public/x"),
            RouteClass::Read
        );
        assert_eq!(
            r.classify(false, "example.com", "GET", "/publicx"),
            RouteClass::Write
        );
        assert_eq!(
            r.to_string(),
            "example.com=* /public/*;lwd=POST /cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock"
        );

        for bad in [
            "prices.example",
            "=GET /x",
            "prices.example=GET",
            "prices.example=FETCH /x",
            "prices.example=GET x",
            "prices.example=",
            ";",
        ] {
            assert!(ReadRoutes::parse(bad).is_err(), "{bad}");
        }

        let s = OriginSettings::parse_env(RawOriginEnv {
            read_routes: Some("prices.example=GET /*"),
            ..RawOriginEnv::default()
        })
        .unwrap();
        assert_eq!(s.replay_read_routes.len(), 1);
    }

    #[test]
    fn secret_fingerprint_is_short_and_domain_separated() {
        let a = secret_fingerprint("relay-secret", b"s3cret");
        assert_eq!(a.len(), 8);
        assert_eq!(a, secret_fingerprint("relay-secret", b"s3cret"));
        assert_ne!(a, secret_fingerprint("other", b"s3cret"));
        assert_ne!(a, secret_fingerprint("relay-secret", b"s3cret2"));
    }

    impl OriginSettings {
        fn default_single_origin() -> Self {
            Self {
                origin_id: String::new(),
                replay_peer_urls: vec![],
                replay_standby_urls: vec![],
                replay_peer_timeout_ms: DEFAULT_REPLAY_PEER_TIMEOUT_MS,
                replay_peer_fail_closed: false,
                replay_peer_mode: ReplayPeerMode::Sync,
                replay_peer_fail_closed_writes: true,
                replay_async_max_lag_ms: DEFAULT_REPLAY_ASYNC_MAX_LAG_MS,
                replay_async_recovery_secs: DEFAULT_REPLAY_ASYNC_RECOVERY_SECS,
                replay_async_failures_before_strict: DEFAULT_REPLAY_ASYNC_FAILURES_BEFORE_STRICT,
                replay_read_routes: ReadRoutes::default_list(),
                replay_unavailable_fallback: false,
            }
        }
    }
}

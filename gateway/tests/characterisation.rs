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

//! Characterisation of the routing policy the gateway derives from its environment.
//!
//! `tests/fixtures/characterisation/<network>.vars` holds the policy environment of a mainnet
//! and a testnet deployment with every host name, address and secret replaced by a placeholder
//! (`*.example`, documentation addresses, fake keys). Two baselines are pinned against it:
//!
//! - `<network>.policy.json`: the effective policy (the parsed tables that have a public view,
//!   and the verdicts of every request the configuration itself names: each policy, replay,
//!   cache and query-rule route, instantiated, plus near misses of each);
//! - `shapes/*.json`: hand-written request shapes per third-party alias, the allowed and the
//!   refused ones, with the verdicts of the code that wrote them.
//!
//! Both are equivalence baselines for refactors of the policy code: a change to any verdict is
//! a behaviour change. `CHARACTERISATION_BLESS=1 cargo test --test characterisation` rewrites
//! the expected values from the current code; review the diff before committing it.
//!
//! Each verdict holds the result of every policy function the handler calls for the request
//! (`raw`), and the decision the handler composes from them (`effective`: which stage answers,
//! the replay class, whether the third-party cache and cap are consulted). The policy snapshot
//! also pins the upstream caps through `ThirdParty::answer`, the third-party cache key and a
//! refresh of each query value list.
//!
//! Not covered here (they need crate-internal access): hosts of a loaded dynamic-host document
//! and the published host list built from them (only the configured sources and the
//! not-ready answer are pinned), the client headers forwarded upstream and the response header
//! filter (only the headers the policy code decides: injected credentials and the Flexa
//! headers).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use serde_json::{json, Value};
use zodl_ohttp_gateway::config::Config;
use zodl_ohttp_gateway::dynamic_hosts::parse_deny_cidrs;
use zodl_ohttp_gateway::flexa;
use zodl_ohttp_gateway::host_list;
use zodl_ohttp_gateway::ohttp::InnerRequest;
use zodl_ohttp_gateway::ohttp::InnerResponse;
use zodl_ohttp_gateway::origin::OriginSettings;
use zodl_ohttp_gateway::proxy::{self, BackendTarget, RouteContext};
use zodl_ohttp_gateway::third_party_cache::{self, Aliases, CacheRoutes, RateLimiters, ThirdParty};

/// The process environment is global: every test of this file that sets or reads it (directly
/// or through a gateway `from_env`) must hold this lock.
static ENV_LOCK: Mutex<()> = Mutex::new(());

const NETWORKS: &[&str] = &["mainnet", "testnet"];

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/characterisation")
}

/// `CHARACTERISATION_BLESS=1`, read once before any fixture replaces the environment. Refused
/// when `CI` is set: a CI run always compares.
static BLESS: OnceLock<bool> = OnceLock::new();

fn bless() -> bool {
    *BLESS.get_or_init(|| {
        let bless = std::env::var("CHARACTERISATION_BLESS").is_ok_and(|v| v == "1");
        assert!(
            !(bless && std::env::var_os("CI").is_some()),
            "CHARACTERISATION_BLESS=1 is refused when CI is set"
        );
        bless
    })
}

fn read_env(network: &str) -> Vec<(String, String)> {
    let path = fixtures().join(format!("{network}.vars"));
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
    raw.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (k, v) = l
                .split_once('=')
                .unwrap_or_else(|| panic!("bad line {l:?}"));
            (k.to_string(), v.to_string())
        })
        .collect()
}

/// Everything the policy is built from, read from one fixture.
struct Loaded {
    env: BTreeMap<String, String>,
    config: Config,
    origin: OriginSettings,
    cache: Option<CacheRoutes>,
    limits: Option<RateLimiters>,
}

/// Names a test process may keep: anything else is removed before a fixture is applied, so an
/// ambient variable can never change a verdict.
fn keep_var(name: &str) -> bool {
    matches!(
        name,
        "PATH" | "HOME" | "TMPDIR" | "TMP" | "TEMP" | "USER" | "LANG" | "TERM"
    ) || ["CARGO", "RUST", "LC_", "LD_", "DYLD_"]
        .iter()
        .any(|p| name.starts_with(p))
}

fn load(network: &str) -> Loaded {
    bless(); // before the environment is replaced
    let vars = read_env(network);
    for (name, _) in std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v)))
        .filter(|(k, _)| !keep_var(k))
    {
        std::env::remove_var(name);
    }
    for (k, v) in &vars {
        std::env::set_var(k, v);
    }
    let config = Config::from_env().expect("fixture config parses");
    let origin = OriginSettings::from_env().expect("fixture origin settings parse");
    let cache = CacheRoutes::from_env(Aliases {
        flexa: config.flexa_alias.as_deref(),
        near: config.near_alias.as_deref(),
    })
    .expect("fixture cache routes parse");
    let limits = RateLimiters::from_env().expect("fixture rate limits parse");
    // Every route the fixture names was parsed: a key the gateway no longer reads (renamed,
    // misspelled) would otherwise fall back to a default while the probes still use its text.
    let env: BTreeMap<String, String> = vars.iter().cloned().collect();
    let count = |k: &str| named_routes(env.get(k).map_or("", String::as_str)).len();
    let entries = |k: &str| {
        env.get(k).map_or(0, |v| {
            v.split([',', ';']).filter(|e| !e.trim().is_empty()).count()
        })
    };
    let policy_rules: usize = config.backends_policy.values().map(Vec::len).sum();
    assert_eq!(
        config.backends.len(),
        entries("BACKENDS"),
        "{network}: BACKENDS"
    );
    assert_eq!(
        policy_rules,
        count("BACKENDS_POLICY"),
        "{network}: BACKENDS_POLICY"
    );
    assert_eq!(
        origin.replay_read_routes.len(),
        count("REPLAY_READ_ROUTES"),
        "{network}: REPLAY_READ_ROUTES"
    );
    assert_eq!(
        origin.replay_one_sided_write_routes.len(),
        count("REPLAY_ONE_SIDED_WRITE_ROUTES"),
        "{network}: REPLAY_ONE_SIDED_WRITE_ROUTES"
    );
    assert_eq!(
        cache.as_ref().map_or(0, CacheRoutes::len),
        count("THIRD_PARTY_CACHE_ROUTES"),
        "{network}: THIRD_PARTY_CACHE_ROUTES"
    );
    assert_eq!(
        config.third_party_query_rules.len(),
        count("THIRD_PARTY_QUERY_RULES"),
        "{network}: THIRD_PARTY_QUERY_RULES"
    );
    assert_eq!(
        limits.as_ref().map_or(0, |l| l.configs.len()),
        entries("THIRD_PARTY_RATE_LIMITS"),
        "{network}: THIRD_PARTY_RATE_LIMITS"
    );
    let headers: usize = config.backend_headers.values().map(Vec::len).sum();
    assert_eq!(
        headers,
        entries("BACKEND_HEADERS"),
        "{network}: BACKEND_HEADERS"
    );
    assert_eq!(
        config.third_party_query_rules.sources().len(),
        env.get("THIRD_PARTY_QUERY_VALUE_SOURCES")
            .map_or(0, |v| v.split(';').filter(|e| !e.trim().is_empty()).count()),
        "{network}: THIRD_PARTY_QUERY_VALUE_SOURCES"
    );
    assert_eq!(
        config.flexa_alias.is_some(),
        env.contains_key("FLEXA_ALIAS"),
        "{network}: FLEXA_ALIAS"
    );
    assert_eq!(
        config.near_alias.is_some(),
        env.contains_key("NEAR_ALIAS"),
        "{network}: NEAR_ALIAS"
    );
    assert_eq!(
        config.dynamic_hosts.source_names().len(),
        env.get("DYNAMIC_HOST_SOURCES")
            .map_or(0, |raw| serde_json::from_str::<Vec<Value>>(raw)
                .expect("sources are a JSON array")
                .len()),
        "{network}: DYNAMIC_HOST_SOURCES"
    );
    Loaded {
        env,
        config,
        origin,
        cache,
        limits,
    }
}

fn request(
    method: &str,
    authority: &str,
    path: &str,
    headers: &[(String, String)],
) -> InnerRequest {
    InnerRequest {
        method: method.to_string(),
        path: path.to_string(),
        authority: authority.to_string(),
        headers: headers.to_vec(),
        body: Vec::new(),
    }
}

/// The verdict of one request: `raw`, the result of each policy function the OHTTP handler
/// calls, and `effective`, the decision the handler composes from them (`main.rs`: lightwalletd
/// target -> host list / gateway-host policy; otherwise the third-party path, whose cache and
/// cap are consulted only for a static alias the policy admits).
fn verdict(
    l: &Loaded,
    method: &str,
    authority: &str,
    path: &str,
    headers: &[(String, String)],
) -> Value {
    let c = &l.config;
    let req = request(method, authority, path, headers);
    let route = RouteContext::resolve(c, &req).with_query_verdict(c, &req);
    let target = proxy::resolve_backend_in(c, &req, &route);
    let is_lwd = target.is_lwd();
    let target_json = match &target {
        BackendTarget::Upstream { uri, label } => json!({ "upstream": uri, "label": label }),
        BackendTarget::Rejected => json!("rejected"),
        BackendTarget::MalformedAuthority(r) => json!({ "malformed_authority": r }),
        BackendTarget::MalformedPath(r) => json!({ "malformed_path": r }),
    };
    let lower = authority.to_ascii_lowercase();
    let cap = l
        .limits
        .as_ref()
        .and_then(|r| r.configs.get(&lower))
        .map(|(n, w)| json!({ "requests": n, "window_secs": w.as_secs() }));
    let cache_ttl = l
        .cache
        .as_ref()
        .and_then(|r| r.find_ttl(&req.authority, method, path));
    let upstream_headers = if flexa::is_alias(c.flexa_alias.as_deref(), &lower) {
        let out = flexa::upstream_headers(headers, c.flexa_publishable_key.as_deref());
        json!({ "flexa": out })
    } else {
        json!({ "injected": c.backend_headers.get(&lower).cloned().unwrap_or_default() })
    };
    let policy_denied = proxy::policy_denies_in(c, &req, &route);
    let gateway_host_denied = proxy::gateway_host_policy_denies(c, &req);
    let host_list = host_list::is_request(c, &req);
    let dynamic = route.dynamic().is_some();
    let route_class = route
        .replay_class(&l.origin.replay_read_routes, is_lwd, &req)
        .as_str();
    let one_sided = route.one_sided_write(&l.origin.replay_one_sided_write_routes, is_lwd, &req);

    // The handler's composition (main.rs, OHTTP request path).
    let host_list_request = is_lwd && host_list;
    let stage = if is_lwd && !host_list_request && gateway_host_denied {
        "gateway_host_policy_403"
    } else if host_list_request {
        "host_list"
    } else if is_lwd {
        "lightwalletd"
    } else {
        "third_party_path"
    };
    let third_party_answer = (!is_lwd && !dynamic && !policy_denied)
        .then(|| json!({ "cache_ttl_secs": cache_ttl, "cap": cap }));
    json!({
        "raw": {
            "target": target_json,
            "policy_denied": policy_denied,
            "gateway_host_policy_denied": gateway_host_denied,
            "query_admitted": c.third_party_query_rules.admits(&req.authority, &req.method, &req.path),
            "dynamic_host": dynamic,
            "host_list_request": host_list,
            "route_replay_class": route_class,
            "one_sided_write": one_sided,
            "route_cache_ttl_secs": cache_ttl,
            "route_cap": cap,
            "upstream_headers": upstream_headers,
            "logged_route": proxy::loggable_route_in(c, &req, &route),
            "rpc_label": proxy::rpc_label_in(c, &req, &route),
            "backend_label": route.backend_label(c, authority),
        },
        "effective": {
            "stage": stage,
            "replay_class": if host_list_request { "read" } else { route_class },
            "one_sided_write": one_sided,
            "third_party_answer": third_party_answer,
        },
    })
}

/// Upstream caps as the handler applies them (`ThirdParty::answer` without a response cache):
/// per capped alias and authority spelling, how many calls pass before the inner 429.
fn caps(l: &Loaded) -> Value {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut out = BTreeMap::new();
    let mut configs: Vec<(String, u64)> = l
        .limits
        .as_ref()
        .map(|r| {
            r.configs
                .iter()
                .map(|(a, (n, _))| (a.clone(), *n))
                .collect()
        })
        .unwrap_or_default();
    configs.sort();
    for (alias, n) in configs {
        let mut per = BTreeMap::new();
        for spelling in [
            alias.clone(),
            alias.to_ascii_uppercase(),
            format!("{alias}:443"),
        ] {
            let tp = ThirdParty::from_env(
                l.config.flexa_alias.as_deref(),
                l.config.near_alias.as_deref(),
            )
            .expect("third-party settings parse");
            let mut passed = 0u64;
            let mut status = None;
            for _ in 0..n + 1 {
                let r = rt.block_on(tp.answer(
                    None,
                    &l.config.network,
                    &spelling,
                    "GET",
                    "/",
                    || async {
                        Ok::<InnerResponse, anyhow::Error>(InnerResponse {
                            status: 200,
                            headers: Vec::new(),
                            body: Vec::new(),
                        })
                    },
                ));
                match r {
                    None => passed += 1,
                    Some(resp) => {
                        status = Some(resp.status);
                        break;
                    }
                }
            }
            per.insert(spelling, json!({ "passed": passed, "then_status": status }));
        }
        out.insert(alias, Value::Object(per.into_iter().collect()));
    }
    json!(out)
}

/// A query rule's literal query with every `{..}` value replaced by `value`.
fn fill_query(query: &str, value: &str) -> String {
    query
        .split('&')
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) if v.starts_with('{') => format!("{k}={value}"),
            _ => kv.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// One refresh of each query value list (`QueryValueSources::apply`, as the refresh task does),
/// for the `{"data": [{"symbol": ..}]}` documents of the fixtures: a malformed body, a too short
/// list, an accepted list (the current one minus five values plus one new), and the verdicts of
/// the rules that use the list afterwards.
fn value_source_refresh(l: &Loaded) -> Value {
    let c = &l.config;
    let sources = c.third_party_query_rules.sources();
    let raw_sources = l
        .env
        .get("THIRD_PARTY_QUERY_VALUE_SOURCES")
        .cloned()
        .unwrap_or_default();
    let rules = named_routes(
        l.env
            .get("THIRD_PARTY_QUERY_RULES")
            .map_or("", String::as_str),
    );
    let mut out = BTreeMap::new();
    let names: Vec<String> = sources.specs().map(|s| s.name.clone()).collect();
    for name in names {
        if !raw_sources.contains("#/data/*/symbol") {
            continue;
        }
        let mut current: Vec<String> = sources
            .list(&name)
            .map(|l| l.iter().cloned().collect())
            .unwrap_or_default();
        current.sort();
        let doc = |values: &[String]| {
            serde_json::to_vec(&json!({ "data": values.iter().map(|v| json!({ "symbol": v })).collect::<Vec<_>>() })).unwrap()
        };
        let malformed = sources
            .apply(&c.network, &name, Ok(b"not json".to_vec()))
            .label();
        let too_few = sources
            .apply(&c.network, &name, Ok(doc(&current[..current.len().min(2)])))
            .label();
        let removed: Vec<String> = current.iter().take(5).cloned().collect();
        let mut next: Vec<String> = current.iter().skip(5).cloned().collect();
        next.push("XAU".to_string());
        let accepted = sources.apply(&c.network, &name, Ok(doc(&next))).label();
        let after = sources.list(&name).map_or(0, |l| l.len());
        let mut checks = BTreeMap::new();
        for (alias, method, pattern) in &rules {
            let Some((route, query)) = pattern.split_once('?') else {
                continue;
            };
            if !query.contains(&format!("{{from:{name}}}")) {
                continue;
            }
            for v in ["XAU", removed.first().map_or("", String::as_str), "USD"] {
                let path = format!("{route}?{}", fill_query(query, v));
                checks.insert(
                    format!("{method} {alias} {path}"),
                    c.third_party_query_rules.admits(alias, method, &path),
                );
            }
        }
        out.insert(
            name,
            json!({ "malformed": malformed, "too_few": too_few, "accepted": accepted,
                    "len_before": current.len(), "len_after": after, "removed": removed, "admits_after": checks }),
        );
    }
    json!(out)
}

/// `authority=METHOD /path,...;authority=...` (the grammar of BACKENDS_POLICY,
/// REPLAY_READ_ROUTES, THIRD_PARTY_CACHE_ROUTES and THIRD_PARTY_QUERY_RULES): the routes it
/// names, as text. Only used to choose probe requests; the gateway's parsers decide.
fn named_routes(raw: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for entry in raw.split(';').map(str::trim).filter(|e| !e.is_empty()) {
        let Some((authority, list)) = entry.split_once('=') else {
            continue;
        };
        for item in list.split(',').map(str::trim).filter(|i| !i.is_empty()) {
            let Some((method, path)) = item.split_once(' ') else {
                continue;
            };
            out.push((
                authority.trim().to_string(),
                method.to_string(),
                path.to_string(),
            ));
        }
    }
    out
}

/// Concrete paths for one route pattern: the pattern itself and its near misses.
fn probe_paths(pattern: &str) -> Vec<String> {
    let (route, query) = match pattern.split_once('?') {
        Some((r, q)) => (r, Some(q)),
        None => (pattern, None),
    };
    let route = route.split('@').next().unwrap_or(route);
    let mut out = Vec::new();
    if let Some(base) = route.strip_suffix("/*") {
        out.push(format!("{base}/item"));
        out.push(format!("{base}/item/sub"));
        out.push(if base.is_empty() {
            "/".to_string()
        } else {
            base.to_string()
        });
        if !base.is_empty() {
            out.push(format!("{base}x"));
        }
    } else {
        out.push(route.to_string());
        out.push(format!("{route}?probe=1"));
        out.push(format!("{route}/extra"));
        out.push(format!("{route}x"));
    }
    if let Some(q) = query {
        // A query rule: its literal shape with each `{from:x}` / `{..}` value replaced by a
        // value of the right form, and the empty query.
        for value in ["USD", "XXX"] {
            let filled = fill_query(q, value);
            if !filled.is_empty() {
                out.push(format!("{route}?{filled}"));
            }
        }
        out.push(format!("{route}?"));
    }
    out
}

fn other_method(method: &str) -> &'static str {
    if method.eq_ignore_ascii_case("GET") {
        "POST"
    } else {
        "GET"
    }
}

/// The requests the configuration itself names, each with its near misses, plus path tricks
/// and an unknown authority. Deterministic order, no duplicates.
fn probes(l: &Loaded) -> Vec<(String, String, String)> {
    let mut set = BTreeSet::new();
    let mut add = |m: &str, a: &str, p: &str| {
        set.insert((a.to_string(), m.to_string(), p.to_string()));
    };
    let gateway = l.config.gateway_hosts.first().cloned().unwrap_or_default();
    for var in [
        "BACKENDS_POLICY",
        "REPLAY_READ_ROUTES",
        "REPLAY_ONE_SIDED_WRITE_ROUTES",
        "THIRD_PARTY_CACHE_ROUTES",
        "THIRD_PARTY_QUERY_RULES",
    ] {
        let raw = l.env.get(var).cloned().unwrap_or_default();
        for (authority, method, pattern) in named_routes(&raw) {
            let authority = if authority == "lwd" {
                gateway.clone()
            } else {
                authority
            };
            for path in probe_paths(&pattern) {
                let method = if method == "*" {
                    "GET"
                } else {
                    method.as_str()
                };
                add(method, &authority, &path);
                add(other_method(method), &authority, &path);
            }
        }
    }
    let mut aliases: Vec<String> = l.config.backends.keys().cloned().collect();
    aliases.extend(l.config.gateway_hosts.iter().cloned());
    for a in &aliases {
        for p in ["/", "/../etc/passwd", "/a//b", "/%2e%2e/x", "relative"] {
            add("GET", a, p);
        }
        add("GET", &a.to_ascii_uppercase(), "/");
        add("GET", &format!("{a}:443"), "/");
    }
    add("GET", "unknown.example", "/");
    add("GET", "", "/");
    add("GET", &gateway, host_list::HOST_LIST_PATH);
    set.into_iter().map(|(a, m, p)| (m, a, p)).collect()
}

/// The effective policy: the public views of the parsed configuration, and the probe verdicts.
fn snapshot(l: &Loaded) -> Value {
    let c = &l.config;
    let sorted = |v: &[String]| -> Vec<String> {
        let mut v = v.to_vec();
        v.sort();
        v
    };
    let policy: BTreeMap<&String, Vec<String>> = c
        .backends_policy
        .iter()
        .map(|(a, rules)| (a, rules.iter().map(|(m, p)| format!("{m} {p}")).collect()))
        .collect();
    let headers: BTreeMap<&String, &Vec<(String, String)>> = c.backend_headers.iter().collect();
    let backends: BTreeMap<&String, &String> = c.backends.iter().collect();
    let rate_limits: BTreeMap<String, Value> = l
        .limits
        .as_ref()
        .map(|r| {
            r.configs
                .iter()
                .map(|(a, (n, w))| {
                    (
                        a.clone(),
                        json!({ "requests": n, "window_secs": w.as_secs() }),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let sources: Vec<Value> = c
        .third_party_query_rules
        .sources()
        .specs()
        .map(|s| {
            let list = c.third_party_query_rules.sources().list(&s.name);
            let mut values: Vec<String> = list
                .map(|l| l.iter().cloned().collect())
                .unwrap_or_default();
            values.sort();
            json!({ "name": s.name, "alias": s.alias, "path": s.path, "route": s.route(),
                    "refresh_secs": s.refresh.as_secs(), "current_list": values })
        })
        .collect();
    let host_list = {
        let gateway = c.gateway_hosts.first().cloned().unwrap_or_default();
        let r = host_list::answer(c, &request("GET", &gateway, host_list::HOST_LIST_PATH, &[]));
        json!({ "settings": format!("{:?}", c.host_list), "status": r.status, "headers": r.headers,
                "body": String::from_utf8_lossy(&r.body) })
    };
    // The blocks as parsed from the fixture. The set in force is process-wide (first reader
    // wins), so both fixtures carry the same list.
    let deny_cidrs: Vec<String> = l
        .env
        .get("DYNAMIC_HOSTS_DENY_CIDRS")
        .map(|raw| {
            parse_deny_cidrs(raw)
                .expect("deny cidrs parse")
                .iter()
                .map(|b| format!("{b:?}"))
                .collect()
        })
        .unwrap_or_default();
    let dynamic_sources: Value = l
        .env
        .get("DYNAMIC_HOST_SOURCES")
        .map(|raw| serde_json::from_str(raw).expect("dynamic sources are JSON"))
        .unwrap_or(Value::Null);
    let probes: Vec<Value> = probes(l)
        .into_iter()
        .map(|(m, a, p)| json!({ "request": format!("{m} {a} {p}"), "verdict": verdict(l, &m, &a, &p, &[]) }))
        .collect();
    let caps = caps(l);
    // Cache keys of the cached routes: a format change splits or poisons a shared cache.
    let cache_keys: BTreeMap<String, String> = named_routes(
        l.env
            .get("THIRD_PARTY_CACHE_ROUTES")
            .map_or("", String::as_str),
    )
    .into_iter()
    .map(|(a, m, p)| {
        let p = p.split('@').next().unwrap_or(&p).to_string();
        let key = third_party_cache::cache_key(&c.network, &a, &m, &p, 7);
        (format!("{m} {a} {p}"), key)
    })
    .collect();
    // Last: it replaces the query value lists the probes above were evaluated with.
    let refresh = value_source_refresh(l);
    json!({
        "network": c.network,
        "mode": c.mode,
        "gateway_hosts": sorted(&c.gateway_hosts),
        "backends": backends,
        "backends_policy": policy,
        "backends_policy_default_allow": c.backends_policy_default_allow,
        "backend_headers": headers,
        "flexa_alias": c.flexa_alias,
        "near_alias": c.near_alias,
        "flexa_publishable_key_set": c.flexa_publishable_key.is_some(),
        "proxy_allow_suffixes": c.proxy_allow_suffixes,
        "relay_secret_on_key_config": format!("{:?}", c.relay_secret_on_key_config),
        "limits": {
            "max_block_range": c.max_block_range,
            "max_inflight_lwd": c.max_inflight_lwd,
            "max_inflight_lwd_heavy": c.max_inflight_lwd_heavy,
            "lwd_heavy_block_range": c.lwd_heavy_block_range,
            "max_inflight_upstream": c.max_inflight_upstream,
            "max_inflight_per_backend": c.max_inflight_per_backend,
            "max_upstream_response_bytes": c.max_upstream_response_bytes,
            "max_cache_get_concurrency": c.max_cache_get_concurrency,
            "max_large_response_concurrency": c.max_large_response_concurrency,
            "lwd_timeout_secs": c.lwd_timeout_secs,
        },
        "rate_limits": rate_limits,
        "cache_routes": l.cache.as_ref().map_or(0, CacheRoutes::len),
        "query_rules": c.third_party_query_rules.len(),
        "query_value_sources": sources,
        "replay_read_routes": l.origin.replay_read_routes.len(),
        "replay_one_sided_write_routes": l.origin.replay_one_sided_write_routes.len(),
        "dynamic_hosts": { "sources": c.dynamic_hosts.source_names(), "hosts": c.dynamic_hosts.len(),
                           "configured": dynamic_sources, "deny_cidrs": deny_cidrs },
        "host_list": host_list,
        "caps": caps,
        "third_party_cache_keys": cache_keys,
        "query_value_source_refresh": refresh,
        "probes": probes,
    })
}

/// One line per probe, so that a behaviour change shows as a readable diff.
fn render_snapshot(v: &Value) -> String {
    let mut head = v.clone();
    let probes = head
        .as_object_mut()
        .and_then(|o| o.remove("probes"))
        .and_then(|p| p.as_array().cloned())
        .unwrap_or_default();
    let mut s = serde_json::to_string_pretty(&head).unwrap();
    s.pop(); // the closing brace
    s.push_str(",\n  \"probes\": [\n");
    let lines: Vec<String> = probes
        .iter()
        .map(|p| format!("    {}", serde_json::to_string(p).unwrap()))
        .collect();
    s.push_str(&lines.join(",\n"));
    s.push_str("\n  ]\n}\n");
    s
}

/// Compare with the committed file, or rewrite it under CHARACTERISATION_BLESS=1.
fn assert_golden(path: PathBuf, actual: &Value, rendered: String) {
    if bless() {
        std::fs::write(&path, rendered).unwrap();
        return;
    }
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{path:?}: {e} (CHARACTERISATION_BLESS=1 creates it)"));
    let expected: Value = serde_json::from_str(&raw).unwrap();
    if &expected != actual {
        // Probes by request, the rest by top-level key: an added or removed probe shows as one line.
        let by_key = |v: &Value| -> BTreeMap<String, String> {
            let mut m = BTreeMap::new();
            for (k, x) in v.as_object().into_iter().flatten() {
                if k == "probes" {
                    for p in x.as_array().into_iter().flatten() {
                        m.insert(
                            format!("probe {}", p["request"].as_str().unwrap_or("")),
                            p["verdict"].to_string(),
                        );
                    }
                } else {
                    m.insert(k.clone(), x.to_string());
                }
            }
            m
        };
        let (e, a) = (by_key(&expected), by_key(actual));
        let keys: BTreeSet<&String> = e.keys().chain(a.keys()).collect();
        let diff: Vec<String> = keys
            .into_iter()
            .filter(|k| e.get(*k) != a.get(*k))
            .take(20)
            .map(|k| {
                format!(
                    "{k}\n  - {}\n  + {}",
                    e.get(k).map_or("(absent)", String::as_str),
                    a.get(k).map_or("(absent)", String::as_str)
                )
            })
            .collect();
        panic!(
            "{path:?} differs from the current behaviour (first entries):\n{}",
            diff.join("\n")
        );
    }
}

#[test]
fn effective_policy_matches_the_golden_snapshots() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    for network in NETWORKS {
        let l = load(network);
        assert_eq!(l.config.network, *network);
        let snap = snapshot(&l);
        let probes = snap["probes"].as_array().map_or(0, Vec::len);
        assert!(probes > 100, "{network}: only {probes} probes");
        assert_golden(
            fixtures().join(format!("{network}.policy.json")),
            &snap,
            render_snapshot(&snap),
        );
    }
}

/// A shape corpus file: request shapes for one alias, with their expected verdicts per network.
fn shape_files() -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(fixtures().join("shapes"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    files
}

#[test]
fn request_shapes_keep_their_verdicts() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let loaded: BTreeMap<&str, Loaded> = NETWORKS.iter().map(|n| (*n, load(n))).collect();
    let files = shape_files();
    assert!(files.len() >= 7, "shape corpus incomplete: {files:?}");
    let mut failures = Vec::new();
    for path in files {
        let mut doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap())
            .unwrap_or_else(|e| panic!("{path:?}: {e}"));
        let networks: Vec<String> = doc["networks"]
            .as_array()
            .unwrap_or_else(|| panic!("{path:?}: no networks"))
            .iter()
            .map(|n| n.as_str().unwrap().to_string())
            .collect();
        assert!(
            !networks.is_empty() && networks.iter().all(|n| NETWORKS.contains(&n.as_str())),
            "{path:?}: networks must be a non-empty subset of {NETWORKS:?}"
        );
        let shapes = doc["shapes"]
            .as_array_mut()
            .unwrap_or_else(|| panic!("{path:?}: no shapes"));
        assert!(!shapes.is_empty(), "{path:?}: empty");
        for shape in shapes.iter_mut() {
            let name = shape["name"].as_str().unwrap().to_string();
            let method = shape["method"].as_str().unwrap().to_string();
            let authority = shape["authority"].as_str().unwrap().to_string();
            let path_ = shape["path"].as_str().unwrap().to_string();
            let headers: Vec<(String, String)> = shape
                .get("headers")
                .and_then(Value::as_array)
                .map(|h| {
                    h.iter()
                        .map(|p| {
                            (
                                p[0].as_str().unwrap().to_string(),
                                p[1].as_str().unwrap().to_string(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            let mut expect = serde_json::Map::new();
            for network in &networks {
                let l = &loaded[network.as_str()];
                expect.insert(
                    network.clone(),
                    verdict(l, &method, &authority, &path_, &headers),
                );
            }
            let actual = Value::Object(expect);
            if bless() {
                shape["expect"] = actual;
            } else if shape.get("expect") != Some(&actual) {
                failures.push(format!(
                    "{}: {name}\n  expected {}\n  actual   {}",
                    path.file_name().unwrap().to_string_lossy(),
                    shape
                        .get("expect")
                        .map(Value::to_string)
                        .unwrap_or_default(),
                    actual
                ));
            }
        }
        if bless() {
            std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
        }
    }
    assert!(
        failures.is_empty(),
        "{} shape(s) changed verdict:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The fixtures carry placeholders only.
#[test]
fn fixtures_name_no_real_host() {
    for network in NETWORKS {
        for (k, v) in read_env(network) {
            for word in v.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '.' || ch == '-'))
            {
                let looks_like_host = word.contains('.')
                    && word.rsplit('.').next().is_some_and(|tld| {
                        tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic())
                    });
                if looks_like_host {
                    assert!(
                        word.ends_with(".example")
                            || word.eq_ignore_ascii_case("cash.z.wallet.sdk.rpc.CompactTxStreamer")
                            || word == "dynamic-voting-config.json",
                        "{network}.vars {k}: {word} is not a placeholder host"
                    );
                }
            }
        }
    }
}

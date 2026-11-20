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

//! The gateway's configuration file, stage 1: the routing policy of the environment variables
//! ([`POLICY_ENV_KEYS`]) as TOML, grouped by authority, every list entry in the grammar of its
//! variable. Deployment keys (addresses, stores, identity, sizing, secrets: [`DEPLOYMENT_ENV_KEYS`])
//! stay in the environment.
//!
//! ```toml
//! schema = 1
//! gateway_hosts = ["gateway.example"]
//!
//! [secrets]
//! prices_key = { env = "PRICES_API_KEY" }          # or { file = "/run/secrets/prices_key" }
//!
//! [integrations.prices]
//! alias = "prices.example"                          # BACKENDS
//! upstream = "https://prices-api.example"
//! kind = "generic"                                  # flexa (FLEXA_ALIAS), near (NEAR_ALIAS), cmc, swapkit
//! routes = ["GET /v1/quotes", "GET /v1/fiat/map"]   # BACKENDS_POLICY
//! headers = [{ name = "X-Api-Key", value = "{secret}", secret = "prices_key" }]   # BACKEND_HEADERS
//! cache = ["GET /v1/quotes@120"]                    # THIRD_PARTY_CACHE_ROUTES
//! rate_limit = "10/60s"                             # THIRD_PARTY_RATE_LIMITS
//! query_rules = ["GET /v1/quotes?convert={from:fiat}", "GET /v1/fiat/map?"]   # THIRD_PARTY_QUERY_RULES
//! read_routes = ["GET /*"]                          # REPLAY_READ_ROUTES
//!
//! [hosts."gateway.example"]                         # an authority that is no alias, `lwd` included
//! routes = ["POST /cash.z.wallet.sdk.rpc.CompactTxStreamer/*"]
//!
//! [value_sources.fiat]                              # THIRD_PARTY_QUERY_VALUE_SOURCES
//! alias = "prices.example"
//! route = "GET /v1/fiat/map"
//! pointer = "/data/*/symbol"
//! refresh_secs = 21600
//! fallback = ["EUR", "USD"]
//! ```
//!
//! The file is turned into the values of the environment variables it stands for
//! ([`render`]), which the gateway's own parsers read, so a file and the environment it
//! transliterates are the same policy by construction; [`export`] is the reverse (the
//! export). [`canonical`] is the effective policy as canonical JSON (sorted keys, header values
//! redacted), the same for a file and its environment.
//!
//! This module reads no file and no environment: the caller hands it text, variables and a
//! secret resolver.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use serde_json::{Map, Value};

/// The schema version this binary reads.
pub const SCHEMA: u32 = 1;

/// The policy variables the file stands for. `PROXY_ALLOW_SUFFIXES` is read by no code: the
/// file has no key for it (a `proxy_allow_suffixes` key is accepted with a warning, see
/// [`REMOVED_KEYS`]), and with the file in force the variable is ignored like the others.
pub const POLICY_ENV_KEYS: &[&str] = &[
    "GATEWAY_HOSTS",
    "BACKENDS",
    "BACKENDS_POLICY",
    "BACKENDS_POLICY_DEFAULT",
    "BACKEND_HEADERS",
    "FLEXA_ALIAS",
    "NEAR_ALIAS",
    "THIRD_PARTY_CACHE_ROUTES",
    "THIRD_PARTY_RATE_LIMITS",
    "THIRD_PARTY_QUERY_RULES",
    "THIRD_PARTY_QUERY_VALUE_SOURCES",
    "THIRD_PARTY_HOSTS_PUBLISH",
    "THIRD_PARTY_HOSTS_MAX_AGE_SECS",
    "REPLAY_READ_ROUTES",
    "REPLAY_ONE_SIDED_WRITE_ROUTES",
    "DYNAMIC_HOST_SOURCES",
    "DYNAMIC_HOSTS_DENY_CIDRS",
    "RELAY_SECRET_ON_KEY_CONFIG",
    "PROXY_ALLOW_SUFFIXES",
];

/// The variables each host sets for itself (the deployment's per-host list: stores, addresses,
/// identity, peers, WRITE forwarding), the identity of a process (`NETWORK`, `PORT`) and the
/// secrets (keys, relay secrets, the signing seed, the Flexa key): none of them is policy. The
/// gateway reads them, and every other setting, from its `[settings]` tables when its
/// configuration files are in force (the gateway's `settings.rs` classifies each one); this
/// list is not used by the code.
pub const DEPLOYMENT_ENV_KEYS: &[&str] = &[
    "LWD_CONNECTION_POOL",
    "LWD_ENDPOINTS",
    "PINNED_BACKFILL_WORKERS",
    "LWD_ADDR",
    "REDIS_URL",
    "REDIS_SECURITY_URL",
    "REDIS_PINNED_URL",
    "REDIS_PINNED_WRITE_URL",
    "PINNED_REDIS_PASSWORD",
    "PERMANENT_REDIS_URL",
    "REPLAY_WRITE_WAIT_REPLICAS",
    "REPLAY_WRITE_WAIT_MS",
    "ORIGIN_ID",
    "REPLAY_PEER_URLS",
    "REPLAY_STANDBY_URLS",
    "REPLAY_PEER_MODE",
    "REPLAY_PEER_TIMEOUT_MS",
    "REPLAY_PEER_FAIL_CLOSED",
    "WRITE_FORWARD_BIND_ADDR",
    "WRITE_FORWARD_SECRETS",
    "REPLAY_WRITE_FORWARD_URL",
    "REPLAY_WRITE_FORWARD_SECRET",
    "NETWORK",
    "PORT",
    "HPKE_PRIVATE_KEY",
    "HPKE_KEY_ID",
    "HPKE_KEYS",
    "HPKE_ACCEPT_ONLY_KEYS",
    "RELAY_SECRET",
    "RELAY_SECRETS",
    "CONFIGS_SIGNING_SEED_HEX",
    "FLEXA_PUBLISHABLE_KEY",
];

/// Keys a release removed: still accepted for one release, with a warning, and ignored.
/// (dotted path, why it is ignored)
pub const REMOVED_KEYS: &[(&str, &str)] = &[(
    "proxy_allow_suffixes",
    "PROXY_ALLOW_SUFFIXES is read by no code",
)];

/// What a header value is in [`canonical`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderValues {
    /// `<redacted>`: the form printed and digested.
    Redacted,
    /// The values as given (only for an in-memory comparison; never print it).
    Plain,
}

/// The redacted header value.
pub const REDACTED: &str = "<redacted>";

/// A secret: an environment variable or a file (its content, without the final line break).
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    pub env: Option<String>,
    pub file: Option<String>,
}

/// One upstream header (`BACKEND_HEADERS`): `{secret}` in `value` is replaced by the secret
/// `secret` names; without `secret` the value is sent as written.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HeaderEntry {
    pub name: String,
    pub value: String,
    pub secret: Option<String>,
}

/// The provider kind of an alias.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Generic,
    Flexa,
    Near,
    Cmc,
    Swapkit,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Generic => "generic",
            Kind::Flexa => "flexa",
            Kind::Near => "near",
            Kind::Cmc => "cmc",
            Kind::Swapkit => "swapkit",
        }
    }
}

/// The rules of one authority, each list in the grammar of its variable's entries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rules {
    /// `BACKENDS_POLICY` (`METHOD /path`); `None`: no entry.
    pub routes: Option<Vec<String>>,
    pub headers: Vec<HeaderEntry>,
    /// `THIRD_PARTY_CACHE_ROUTES` (`METHOD /path@TTL`).
    pub cache: Vec<String>,
    /// `THIRD_PARTY_RATE_LIMITS` (`REQUESTS/WINDOWs`).
    pub rate_limit: Option<String>,
    /// `THIRD_PARTY_QUERY_RULES` (`METHOD /path?QUERY`).
    pub query_rules: Vec<String>,
    /// `REPLAY_READ_ROUTES` (`METHOD /path`).
    pub read_routes: Vec<String>,
    /// `REPLAY_ONE_SIDED_WRITE_ROUTES` (`METHOD /path`).
    pub one_sided_write_routes: Vec<String>,
}

/// `[integrations.<label>]`: a `BACKENDS` alias.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Integration {
    pub alias: String,
    pub upstream: String,
    pub kind: Option<Kind>,
    pub routes: Option<Vec<String>>,
    #[serde(default)]
    pub headers: Vec<HeaderEntry>,
    #[serde(default)]
    pub cache: Vec<String>,
    pub rate_limit: Option<String>,
    #[serde(default)]
    pub query_rules: Vec<String>,
    #[serde(default)]
    pub read_routes: Vec<String>,
    #[serde(default)]
    pub one_sided_write_routes: Vec<String>,
}

/// `[hosts."<authority>"]`: an authority that is no alias (a gateway host, the pseudo
/// authority `lwd` of the replay routes); `kind` only `flexa` or `near` (`FLEXA_ALIAS` /
/// `NEAR_ALIAS` naming an authority outside `BACKENDS`).
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub kind: Option<Kind>,
    pub routes: Option<Vec<String>>,
    #[serde(default)]
    pub headers: Vec<HeaderEntry>,
    #[serde(default)]
    pub cache: Vec<String>,
    pub rate_limit: Option<String>,
    #[serde(default)]
    pub query_rules: Vec<String>,
    #[serde(default)]
    pub read_routes: Vec<String>,
    #[serde(default)]
    pub one_sided_write_routes: Vec<String>,
}

/// `[value_sources.<name>]`: one `THIRD_PARTY_QUERY_VALUE_SOURCES` entry.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ValueSource {
    pub alias: String,
    /// `GET /path` (with its query, if any).
    pub route: String,
    pub pointer: String,
    pub refresh_secs: u64,
    pub fallback: Option<Vec<String>>,
}

/// `[dynamic_hosts]`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DynamicHostsSection {
    /// `DYNAMIC_HOSTS_DENY_CIDRS`.
    #[serde(default)]
    pub deny_cidrs: Vec<String>,
    /// `DYNAMIC_HOST_SOURCES`: the sources as tables (the JSON document's objects).
    pub sources: Option<Vec<Value>>,
}

/// `[host_list]`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostListSection {
    /// `THIRD_PARTY_HOSTS_PUBLISH`.
    pub publish: Option<String>,
    /// `THIRD_PARTY_HOSTS_MAX_AGE_SECS`.
    pub max_age_secs: Option<u64>,
}

/// The default of an alias without `routes` (`BACKENDS_POLICY_DEFAULT`).
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyDefault {
    Allow,
    Deny,
}

/// A configuration file.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    pub schema: u32,
    #[serde(default)]
    pub gateway_hosts: Vec<String>,
    pub backends_policy_default: Option<PolicyDefault>,
    pub relay_secret_on_key_config: Option<String>,
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretRef>,
    #[serde(default)]
    pub integrations: BTreeMap<String, Integration>,
    #[serde(default)]
    pub hosts: BTreeMap<String, Host>,
    #[serde(default)]
    pub value_sources: BTreeMap<String, ValueSource>,
    #[serde(default)]
    pub dynamic_hosts: DynamicHostsSection,
    #[serde(default)]
    pub host_list: HostListSection,
    /// `[settings]`: the gateway's settings other than the policy (tuning, deployment, secret
    /// references), read and checked by the gateway, not by this crate; present (even empty),
    /// the files carry every setting. Never part of the policy: not in [`canonical`],
    /// [`render`] or the digest.
    #[serde(default)]
    pub settings: Option<toml::Table>,
}

impl Integration {
    fn rules(&self) -> Rules {
        Rules {
            routes: self.routes.clone(),
            headers: self.headers.clone(),
            cache: self.cache.clone(),
            rate_limit: self.rate_limit.clone(),
            query_rules: self.query_rules.clone(),
            read_routes: self.read_routes.clone(),
            one_sided_write_routes: self.one_sided_write_routes.clone(),
        }
    }
}

impl Host {
    fn rules(&self) -> Rules {
        Rules {
            routes: self.routes.clone(),
            headers: self.headers.clone(),
            cache: self.cache.clone(),
            rate_limit: self.rate_limit.clone(),
            query_rules: self.query_rules.clone(),
            read_routes: self.read_routes.clone(),
            one_sided_write_routes: self.one_sided_write_routes.clone(),
        }
    }

    fn from_rules(kind: Option<Kind>, r: Rules) -> Self {
        Self {
            kind,
            routes: r.routes,
            headers: r.headers,
            cache: r.cache,
            rate_limit: r.rate_limit,
            query_rules: r.query_rules,
            read_routes: r.read_routes,
            one_sided_write_routes: r.one_sided_write_routes,
        }
    }
}

/// One authority of the file: its kind, upstream (`None`: no alias) and rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authority {
    pub kind: Option<Kind>,
    pub upstream: Option<String>,
    pub rules: Rules,
}

/// A parsed file and its warnings (removed keys).
#[derive(Clone, Debug)]
pub struct Loaded {
    pub file: PolicyFile,
    pub warnings: Vec<String>,
}

/// Parse a file: TOML, `schema = 1`, no unknown key (a key of [`REMOVED_KEYS`] is dropped with
/// a warning), the structural checks ([`PolicyFile::authorities`], [`PolicyFile::check`]).
pub fn parse(text: &str) -> Result<Loaded> {
    let te = |e: toml::de::Error| toml_error(text, &e);
    let table: toml::Table = toml::from_str(text).map_err(te)?;
    let mut warnings = Vec::new();
    let file: PolicyFile = if REMOVED_KEYS.iter().any(|(k, _)| table.contains_key(*k)) {
        let mut table = table;
        for (key, why) in REMOVED_KEYS {
            if table.remove(*key).is_some() {
                warnings.push(format!(
                    "config file key '{key}' is no longer used and is ignored ({why}); remove it"
                ));
            }
        }
        // Positions refer to the file without the removed keys: approximate.
        let text = toml::to_string(&table).map_err(|_| anyhow!("Invalid config file"))?;
        toml::from_str(&text).map_err(|e| {
            anyhow!(
                "{} (position approximate: the file was read without its removed keys)",
                toml_error_in(&text, &e)
            )
        })?
    } else {
        toml::from_str(text).map_err(te)?
    };
    if file.schema != SCHEMA {
        bail!(
            "Invalid config file: schema {} (this gateway reads schema {SCHEMA})",
            file.schema
        );
    }
    let file = file.normalized()?;
    file.check()?;
    file.check_kinds()?;
    Ok(Loaded { file, warnings })
}

/// A TOML error without any of the file's content: its position and its kind, quoted values
/// removed (a value may be a secret's neighbour, or one written in the wrong place). Public for
/// the gateway's other configuration file (the host file).
pub fn toml_error(text: &str, e: &toml::de::Error) -> anyhow::Error {
    toml_error_in(text, e)
}

fn toml_error_in(text: &str, e: &toml::de::Error) -> anyhow::Error {
    let position = e
        .span()
        .map(|span| {
            let before = &text[..span.start.min(text.len())];
            let line = before.matches('\n').count() + 1;
            let column = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
            format!(" at line {line}, column {column}")
        })
        .unwrap_or_default();
    anyhow!(
        "Invalid config file{position}: {}",
        redact_quoted(e.message())
    )
}

/// `message` with every quoted part replaced by `…`: double-quoted (a `\\` escapes the next
/// character) and backquoted (serde's quoting of a value: an enum variant, an integer); only
/// the first backquoted part of `unknown field` and `missing field`, a key, is kept. One line:
/// no excerpt of the file.
fn redact_quoted(message: &str) -> String {
    let message = message.lines().next().unwrap_or("");
    // serde quotes an unknown variant with backquotes, unescaped: a backquote inside the value
    // would end the span early. The message is cut to its kind.
    if message.starts_with("unknown variant") {
        return "unknown variant `…`".to_string();
    }
    let keep_first_backquote =
        message.starts_with("unknown field") || message.starts_with("missing field");
    let mut out = String::new();
    let mut chars = message.chars();
    let mut backquotes = 0;
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                // Skip to the closing quote, escapes included.
                while let Some(d) = chars.next() {
                    match d {
                        '\\' => {
                            chars.next();
                        }
                        '"' => break,
                        _ => {}
                    }
                }
                out.push_str("\"…\"");
            }
            '`' => {
                backquotes += 1;
                let span: String = chars.by_ref().take_while(|&d| d != '`').collect();
                if keep_first_backquote && backquotes == 1 {
                    out.push('`');
                    out.push_str(&span);
                    out.push('`');
                } else {
                    out.push_str("`…`");
                }
            }
            c => out.push(c),
        }
    }
    out
}

fn trim_all(list: &[String]) -> Vec<String> {
    list.iter().map(|s| s.trim().to_string()).collect()
}

/// `host[:port]` lowercased without the port, as `GATEWAY_HOSTS` is read.
fn gateway_host(name: &str) -> String {
    name.trim()
        .to_ascii_lowercase()
        .split(':')
        .next()
        .unwrap_or("")
        .to_string()
}

impl PolicyFile {
    /// Entries trimmed, authorities lowercased: the form both the file and an environment
    /// reach.
    fn normalized(&self) -> Result<Self> {
        let norm_rules = |r: Rules| Rules {
            routes: r.routes.map(|v| trim_all(&v)),
            headers: r
                .headers
                .iter()
                .map(|h| HeaderEntry {
                    name: h.name.trim().to_string(),
                    value: h.value.trim().to_string(),
                    secret: h.secret.clone(),
                })
                .collect(),
            cache: trim_all(&r.cache),
            rate_limit: r.rate_limit.map(|s| s.trim().to_string()),
            query_rules: trim_all(&r.query_rules),
            read_routes: trim_all(&r.read_routes),
            one_sided_write_routes: trim_all(&r.one_sided_write_routes),
        };
        let mut out = self.clone();
        out.gateway_hosts = self
            .gateway_hosts
            .iter()
            .map(|h| gateway_host(h))
            .filter(|h| !h.is_empty())
            .collect();
        out.relay_secret_on_key_config = self
            .relay_secret_on_key_config
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        out.integrations = self
            .integrations
            .iter()
            .map(|(label, i)| {
                let r = norm_rules(i.rules());
                (
                    label.clone(),
                    Integration {
                        alias: i.alias.trim().to_ascii_lowercase(),
                        upstream: i.upstream.trim().to_string(),
                        kind: i.kind,
                        routes: r.routes,
                        headers: r.headers,
                        cache: r.cache,
                        rate_limit: r.rate_limit,
                        query_rules: r.query_rules,
                        read_routes: r.read_routes,
                        one_sided_write_routes: r.one_sided_write_routes,
                    },
                )
            })
            .collect();
        out.hosts = BTreeMap::new();
        let mut host_keys: BTreeMap<String, &String> = BTreeMap::new();
        for (name, h) in &self.hosts {
            let key = name.trim().to_ascii_lowercase();
            if let Some(other) = host_keys.insert(key.clone(), name) {
                bail!("Invalid config file: hosts \"{other}\" and \"{name}\" are the same authority '{key}' (listed twice)");
            }
            out.hosts
                .insert(key, Host::from_rules(h.kind, norm_rules(h.rules())));
        }
        let mut source_keys: BTreeMap<String, &String> = BTreeMap::new();
        for name in self.value_sources.keys() {
            if let Some(other) = source_keys.insert(name.trim().to_string(), name) {
                bail!("Invalid config file: value_sources \"{other}\" and \"{name}\" are the same source (listed twice)");
            }
        }
        out.value_sources = self
            .value_sources
            .iter()
            .map(|(name, s)| {
                (
                    name.trim().to_string(),
                    ValueSource {
                        alias: s.alias.trim().to_ascii_lowercase(),
                        route: s.route.trim().to_string(),
                        pointer: s.pointer.trim().to_string(),
                        refresh_secs: s.refresh_secs,
                        fallback: s.fallback.as_ref().map(|v| trim_all(v)),
                    },
                )
            })
            .collect();
        out.dynamic_hosts.deny_cidrs = trim_all(&self.dynamic_hosts.deny_cidrs)
            .into_iter()
            .filter(|c| !c.is_empty())
            .collect();
        out.host_list.publish = self
            .host_list
            .publish
            .as_ref()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        Ok(out)
    }

    /// Every authority of the file (lowercase): duplicate aliases, an alias also listed as a
    /// host, a host with the kind of an alias are errors.
    pub fn authorities(&self) -> Result<BTreeMap<String, Authority>> {
        let mut out: BTreeMap<String, Authority> = BTreeMap::new();
        for (label, i) in &self.integrations {
            if out.contains_key(&i.alias) {
                bail!(
                    "Invalid config file: alias '{}' is listed twice (integrations.{label})",
                    i.alias
                );
            }
            out.insert(
                i.alias.clone(),
                Authority {
                    kind: Some(i.kind.unwrap_or(Kind::Generic)),
                    upstream: Some(i.upstream.clone()),
                    rules: i.rules(),
                },
            );
        }
        for (name, h) in &self.hosts {
            if out.contains_key(name) {
                bail!(
                    "Invalid config file: '{name}' is both an integration alias and a hosts entry"
                );
            }
            if let Some(kind) = h.kind.filter(|k| !matches!(k, Kind::Flexa | Kind::Near)) {
                bail!(
                    "Invalid config file: hosts.\"{name}\" has kind '{}'; a host can only be named by FLEXA_ALIAS or NEAR_ALIAS (kind flexa or near), other kinds need an integration with an upstream",
                    kind.as_str()
                );
            }
            out.insert(
                name.clone(),
                Authority {
                    kind: h.kind,
                    upstream: None,
                    rules: h.rules(),
                },
            );
        }
        Ok(out)
    }

    /// The structural checks: what the environment variables could not express (a separator
    /// inside an entry), the cross-checks of the file (an alias that is a gateway host, a secret
    /// without a mapping, a cache route outside the routes, kinds), not yet the grammar of the
    /// entries (that is the gateway's parsers', on [`render`]).
    pub fn check(&self) -> Result<()> {
        let authorities = self.authorities()?;
        for host in &self.gateway_hosts {
            no_sep("a gateway_hosts entry", host, &[','])?;
        }
        for cidr in &self.dynamic_hosts.deny_cidrs {
            no_sep("a dynamic_hosts.deny_cidrs entry", cidr, &[','])?;
        }
        let mut flexa = None;
        let mut near = None;
        for (authority, a) in &authorities {
            if authority.is_empty() {
                bail!("Invalid config file: an empty alias or host name");
            }
            no_sep(
                "an alias or host name",
                authority,
                &['=', ',', ';', ' ', '\t'],
            )?;
            if self.gateway_hosts.contains(authority) && a.upstream.is_some() {
                bail!("Invalid config file: alias '{authority}' is also a gateway host (GATEWAY_HOSTS)");
            }
            if let Some(up) = &a.upstream {
                no_sep(&format!("the upstream of '{authority}'"), up, &[','])?;
            }
            let r = &a.rules;
            if let Some(routes) = &r.routes {
                if routes.is_empty() {
                    bail!("Invalid config file: '{authority}' has an empty routes list (leave the key out for no policy entry)");
                }
                for (i, e) in routes.iter().enumerate() {
                    no_sep(&format!("routes[{i}] of '{authority}'"), e, &[',', ';'])?;
                }
            }
            for h in &r.headers {
                if h.name.is_empty() {
                    bail!("Invalid config file: a header of '{authority}' has an empty name");
                }
                no_sep(
                    &format!("a header name of '{authority}'"),
                    &h.name,
                    &[',', ':'],
                )?;
                no_sep(
                    &format!("the value of header '{}' of '{authority}'", h.name),
                    &h.value,
                    &[','],
                )?;
                match &h.secret {
                    Some(name) => {
                        if !self.secrets.contains_key(name) {
                            bail!("Invalid config file: header '{}' of '{authority}' names the secret '{name}', which [secrets] does not map", h.name);
                        }
                        if !h.value.contains("{secret}") {
                            bail!("Invalid config file: header '{}' of '{authority}' names a secret but its value has no {{secret}}", h.name);
                        }
                    }
                    None if h.value.contains("{secret}") => bail!(
                        "Invalid config file: header '{}' of '{authority}' has {{secret}} in its value but names no secret",
                        h.name
                    ),
                    None => {}
                }
            }
            for (key, list) in [
                ("cache", &r.cache),
                ("query_rules", &r.query_rules),
                ("read_routes", &r.read_routes),
                ("one_sided_write_routes", &r.one_sided_write_routes),
            ] {
                for (i, e) in list.iter().enumerate() {
                    no_sep(&format!("{key}[{i}] of '{authority}'"), e, &[',', ';'])?;
                }
            }
            if let Some(rl) = &r.rate_limit {
                no_sep(&format!("the rate_limit of '{authority}'"), rl, &[','])?;
            }
            // A cache route must be a route the alias admits.
            for entry in &r.cache {
                let route = entry.split('@').next().unwrap_or(entry).trim();
                let (method, path) = route.split_once(' ').unwrap_or((route, ""));
                let admitted = match &r.routes {
                    Some(routes) => {
                        let rules = route_pairs(routes);
                        crate::core::route::matching_rule(&rules, method, path.trim()).is_some()
                    }
                    None => {
                        a.upstream.is_none()
                            || self.backends_policy_default == Some(PolicyDefault::Allow)
                    }
                };
                if !admitted {
                    bail!("Invalid config file: cache route '{entry}' of '{authority}' is outside its routes");
                }
            }
            match a.kind {
                Some(Kind::Flexa) => {
                    if let Some(other) = flexa.replace(authority.clone()) {
                        bail!("Invalid config file: two authorities of kind flexa ('{other}', '{authority}')");
                    }
                }
                Some(Kind::Near) => {
                    if let Some(other) = near.replace(authority.clone()) {
                        bail!("Invalid config file: two authorities of kind near ('{other}', '{authority}')");
                    }
                }
                _ => {}
            }
        }
        for (name, s) in &self.secrets {
            match (&s.env, &s.file) {
                (Some(_), None) | (None, Some(_)) => {}
                _ => bail!("Invalid config file: secret '{name}' needs exactly one of env or file"),
            }
        }
        for (name, s) in &self.value_sources {
            no_sep(
                &format!("the value source name '{name}'"),
                name,
                &['=', ';', ' '],
            )?;
            no_sep(
                &format!("the alias of value source '{name}'"),
                &s.alias,
                &[' ', '@', '#', ';'],
            )?;
            no_sep(
                &format!("the route of value source '{name}'"),
                &s.route,
                &['@', '#', ';'],
            )?;
            match s.route.split_once(' ') {
                Some((method, path))
                    if method.eq_ignore_ascii_case("GET") && !path.trim().is_empty() => {}
                _ => bail!(
                    "Invalid config file: value source '{name}' route '{}' must be 'GET /path'",
                    s.route
                ),
            }
            no_sep(
                &format!("the pointer of value source '{name}'"),
                &s.pointer,
                &['@', ';'],
            )?;
            for (i, v) in s.fallback.iter().flatten().enumerate() {
                no_sep(
                    &format!("fallback[{i}] of value source '{name}'"),
                    v,
                    &['|', '@', ';'],
                )?;
            }
        }
        Ok(())
    }
}

impl PolicyFile {
    /// The startup invariants of the keyed kinds (`cmc`, `swapkit`): a header credential and a
    /// query rule on every route ([`crate::keyed::Keyed::new`]); a kind whose provider this
    /// build lacks is refused.
    pub fn check_kinds(&self) -> Result<()> {
        let keyed: Vec<&Integration> = self
            .integrations
            .values()
            .filter(|i| matches!(i.kind, Some(Kind::Cmc | Kind::Swapkit)))
            .collect();
        if keyed.is_empty() {
            return Ok(());
        }
        // The query rules as the gateway reads them (no secret is needed for them).
        let rendered = render(self, &|_: &str| Ok(String::new()))?;
        let rules = match rendered.get("THIRD_PARTY_QUERY_RULES") {
            Some(raw) => crate::core::query::QueryRules::parse(raw)?,
            None => crate::core::query::QueryRules::default(),
        };
        for i in keyed {
            let kind = i.kind.unwrap_or(Kind::Generic);
            #[cfg(not(feature = "cmc"))]
            if kind == Kind::Cmc {
                bail!("Invalid config file: '{}' has kind cmc but this build has no cmc provider (cargo feature 'cmc')", i.alias);
            }
            #[cfg(not(feature = "swapkit"))]
            if kind == Kind::Swapkit {
                bail!("Invalid config file: '{}' has kind swapkit but this build has no swapkit provider (cargo feature 'swapkit')", i.alias);
            }
            let policy = i.routes.as_ref().map(|r| route_pairs(r));
            let headers: Vec<(String, String)> = i
                .headers
                .iter()
                .map(|h| (h.name.clone(), h.value.clone()))
                .collect();
            let generic = crate::generic::Generic {
                policy: policy.as_deref(),
                default_allow: self.backends_policy_default == Some(PolicyDefault::Allow),
                headers: &headers,
            };
            crate::keyed::Keyed::new(kind.as_str(), &i.alias, generic, &rules)
                .map_err(|e| anyhow!("Invalid config file: {e}"))?;
        }
        Ok(())
    }
}

/// `value` holds none of `seps`; the error names the place (`what`), never the value.
fn no_sep(what: &str, value: &str, seps: &[char]) -> Result<()> {
    if let Some(c) = value.chars().find(|c| seps.contains(c)) {
        bail!(
            "Invalid config file: {what} contains {c:?}, which its variable's grammar cannot hold"
        );
    }
    Ok(())
}

/// `METHOD /path` entries as (method, path).
fn route_pairs(routes: &[String]) -> Vec<(String, String)> {
    routes
        .iter()
        .map(|r| {
            let (m, p) = r.split_once(' ').unwrap_or((r.as_str(), ""));
            (m.to_string(), p.trim().to_string())
        })
        .collect()
}

/// The environment variables `file` stands for (only those it sets). `resolve` gives the value
/// of a secret by name (a missing one is its error).
pub fn render(
    file: &PolicyFile,
    resolve: &dyn Fn(&str) -> Result<String>,
) -> Result<BTreeMap<&'static str, String>> {
    let authorities = file.authorities()?;
    let mut out: BTreeMap<&'static str, String> = BTreeMap::new();
    if !file.gateway_hosts.is_empty() {
        out.insert("GATEWAY_HOSTS", file.gateway_hosts.join(","));
    }
    if let Some(d) = file.backends_policy_default {
        out.insert(
            "BACKENDS_POLICY_DEFAULT",
            match d {
                PolicyDefault::Allow => "allow",
                PolicyDefault::Deny => "deny",
            }
            .to_string(),
        );
    }
    if let Some(r) = &file.relay_secret_on_key_config {
        out.insert("RELAY_SECRET_ON_KEY_CONFIG", r.clone());
    }
    let mut backends = Vec::new();
    let mut policy = Vec::new();
    let mut headers = Vec::new();
    let mut cache = Vec::new();
    let mut limits = Vec::new();
    let mut query = Vec::new();
    let mut read = Vec::new();
    let mut one_sided = Vec::new();
    for (authority, a) in &authorities {
        if let Some(up) = &a.upstream {
            backends.push(format!("{authority}={up}"));
        }
        match a.kind {
            Some(Kind::Flexa) => {
                out.insert("FLEXA_ALIAS", authority.clone());
            }
            Some(Kind::Near) => {
                out.insert("NEAR_ALIAS", authority.clone());
            }
            _ => {}
        }
        let r = &a.rules;
        if let Some(routes) = &r.routes {
            policy.push(format!("{authority}={}", routes.join(",")));
        }
        for h in &r.headers {
            let value = match &h.secret {
                Some(name) => {
                    let secret = resolve(name).with_context(|| {
                        format!("secret '{name}' (header '{}' of '{authority}')", h.name)
                    })?;
                    if secret.contains(',') {
                        bail!("secret '{name}' contains ',', which BACKEND_HEADERS cannot hold");
                    }
                    h.value.replace("{secret}", &secret)
                }
                None => h.value.clone(),
            };
            headers.push(format!("{authority}={}:{value}", h.name));
        }
        if !r.cache.is_empty() {
            cache.push(format!("{authority}={}", r.cache.join(",")));
        }
        if let Some(rl) = &r.rate_limit {
            limits.push(format!("{authority}={rl}"));
        }
        if !r.query_rules.is_empty() {
            query.push(format!("{authority}={}", r.query_rules.join(",")));
        }
        if !r.read_routes.is_empty() {
            read.push(format!("{authority}={}", r.read_routes.join(",")));
        }
        if !r.one_sided_write_routes.is_empty() {
            one_sided.push(format!(
                "{authority}={}",
                r.one_sided_write_routes.join(",")
            ));
        }
    }
    for (key, list, sep) in [
        ("BACKENDS", backends, ","),
        ("BACKENDS_POLICY", policy, ";"),
        ("BACKEND_HEADERS", headers, ","),
        ("THIRD_PARTY_CACHE_ROUTES", cache, ";"),
        ("THIRD_PARTY_RATE_LIMITS", limits, ","),
        ("THIRD_PARTY_QUERY_RULES", query, ";"),
        ("REPLAY_READ_ROUTES", read, ";"),
        ("REPLAY_ONE_SIDED_WRITE_ROUTES", one_sided, ";"),
    ] {
        if !list.is_empty() {
            out.insert(key, list.join(sep));
        }
    }
    if !file.value_sources.is_empty() {
        let entries: Vec<String> = file
            .value_sources
            .iter()
            .map(|(name, s)| {
                let mut e = format!(
                    "{name}={} {}#{}@{}",
                    s.alias, s.route, s.pointer, s.refresh_secs
                );
                if let Some(f) = &s.fallback {
                    e.push_str(&format!("@fallback={}", f.join("|")));
                }
                e
            })
            .collect();
        out.insert("THIRD_PARTY_QUERY_VALUE_SOURCES", entries.join(";"));
    }
    if let Some(p) = &file.host_list.publish {
        out.insert("THIRD_PARTY_HOSTS_PUBLISH", p.clone());
    }
    if let Some(m) = file.host_list.max_age_secs {
        out.insert("THIRD_PARTY_HOSTS_MAX_AGE_SECS", m.to_string());
    }
    if let Some(sources) = &file.dynamic_hosts.sources {
        out.insert(
            "DYNAMIC_HOST_SOURCES",
            Value::Array(sources.clone()).to_string(),
        );
    }
    if !file.dynamic_hosts.deny_cidrs.is_empty() {
        out.insert(
            "DYNAMIC_HOSTS_DENY_CIDRS",
            file.dynamic_hosts.deny_cidrs.join(","),
        );
    }
    Ok(out)
}

/// The variable `key` of `env`, trimmed, `None` when unset or blank.
fn get<'a>(env: &'a BTreeMap<String, String>, key: &str) -> Option<&'a str> {
    env.get(key).map(|v| v.trim()).filter(|v| !v.is_empty())
}

/// `authority=item,item;authority=...` (the authority lowercased, items trimmed, empty items
/// skipped): authority -> items, a later entry of an authority replacing (`replace`) or
/// extending the earlier one.
fn split_lists(
    name: &str,
    raw: &str,
    entry_sep: char,
    replace: bool,
) -> Result<BTreeMap<String, Vec<String>>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in raw
        .split(entry_sep)
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        let (authority, items) = entry
            .split_once('=')
            .ok_or_else(|| anyhow!("Malformed {name} entry '{entry}' (missing '=')"))?;
        let authority = authority.trim().to_ascii_lowercase();
        if authority.is_empty() {
            bail!("Malformed {name}: missing authority in '{entry}'");
        }
        let items: Vec<String> = items
            .split(',')
            .map(str::trim)
            .filter(|i| !i.is_empty())
            .map(str::to_string)
            .collect();
        if replace {
            out.insert(authority, items);
        } else {
            out.entry(authority).or_default().extend(items);
        }
    }
    Ok(out)
}

/// The secret a header value of the environment was assembled from, for the export.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportedSecret {
    /// The `[secrets]` name.
    pub name: String,
    /// The environment variable it maps to.
    pub env: String,
    /// Whether `env` was found holding the value (else it is a new name the operator sets).
    pub found: bool,
}

/// An export: the file, its secrets, and their values (in memory only, for a comparison).
#[derive(Clone)]
pub struct Export {
    pub file: PolicyFile,
    pub secrets: Vec<ExportedSecret>,
    values: BTreeMap<String, String>,
}

impl Export {
    /// The value a secret of the export stands for.
    pub fn secret_value(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    /// [`Self::secret_value`] as a resolver for [`render`] and [`canonical`].
    pub fn resolve(&self, name: &str) -> Result<String> {
        self.secret_value(name)
            .map(str::to_string)
            .ok_or_else(|| anyhow!("no value for secret '{name}'"))
    }
}

impl std::fmt::Debug for Export {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the values.
        f.debug_struct("Export")
            .field("file", &self.file)
            .field("secrets", &self.secrets)
            .finish_non_exhaustive()
    }
}

/// The file an environment stands for (the reverse of [`render`]): every policy variable of
/// `env` read like the gateway reads it, each list entry kept as written (trimmed). A header
/// value becomes a secret reference: to the variable of `env` it equals, or equals after a
/// scheme (`Bearer `, `Basic `), else to a new variable for the whole value, named after the
/// alias and the header (`_2`, `_3`, ... for another value under the same name). The secret is
/// named after its variable. An empty value stays a literal.
pub fn export(env: &BTreeMap<String, String>) -> Result<Export> {
    use crate::core::policy::{parse_backend_headers, parse_backends, parse_backends_policy};
    let backends = parse_backends(env.get("BACKENDS").map_or("", |s| s.as_str()))?;
    let policy = parse_backends_policy(env.get("BACKENDS_POLICY").map_or("", |s| s.as_str()))?;
    // Its entries hold credentials: never in an error.
    let headers = parse_backend_headers(env.get("BACKEND_HEADERS").map_or("", |s| s.as_str()))
        .map_err(|_| anyhow!("BACKEND_HEADERS is not valid (its entries are not shown)"))?;
    let default = env.get("BACKENDS_POLICY_DEFAULT").map(|v| {
        if v.eq_ignore_ascii_case("allow") {
            PolicyDefault::Allow
        } else {
            PolicyDefault::Deny
        }
    });
    let alias = |k: &str| get(env, k).map(|v| v.to_ascii_lowercase());
    let flexa = alias("FLEXA_ALIAS");
    let near = alias("NEAR_ALIAS");
    if flexa.is_some() && flexa == near {
        bail!("FLEXA_ALIAS and NEAR_ALIAS name the same authority, which a file cannot express");
    }
    let cache = split_lists(
        "THIRD_PARTY_CACHE_ROUTES",
        get(env, "THIRD_PARTY_CACHE_ROUTES").unwrap_or(""),
        ';',
        true,
    )?;
    let mut limits: BTreeMap<String, String> = BTreeMap::new();
    for entry in get(env, "THIRD_PARTY_RATE_LIMITS")
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        let (a, spec) = entry
            .split_once('=')
            .ok_or_else(|| anyhow!("Malformed THIRD_PARTY_RATE_LIMITS entry '{entry}'"))?;
        limits.insert(a.trim().to_ascii_lowercase(), spec.trim().to_string());
    }
    let mut query: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in get(env, "THIRD_PARTY_QUERY_RULES")
        .unwrap_or("")
        .split(';')
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        let (a, routes) = entry
            .split_once('=')
            .ok_or_else(|| anyhow!("Malformed THIRD_PARTY_QUERY_RULES entry '{entry}'"))?;
        let a = a.trim().to_ascii_lowercase();
        if query.contains_key(&a) {
            bail!("Malformed THIRD_PARTY_QUERY_RULES: alias '{a}' listed twice");
        }
        let routes: Vec<String> = routes.split(',').map(|r| r.trim().to_string()).collect();
        if routes.iter().any(String::is_empty) {
            bail!("Malformed THIRD_PARTY_QUERY_RULES: empty route in '{entry}'");
        }
        query.insert(a, routes);
    }
    let read = split_lists(
        "REPLAY_READ_ROUTES",
        get(env, "REPLAY_READ_ROUTES").unwrap_or(""),
        ';',
        false,
    )?;
    let one_sided = split_lists(
        "REPLAY_ONE_SIDED_WRITE_ROUTES",
        get(env, "REPLAY_ONE_SIDED_WRITE_ROUTES").unwrap_or(""),
        ';',
        false,
    )?;

    let mut names: BTreeSet<String> = BTreeSet::new();
    names.extend(backends.keys().cloned());
    names.extend(policy.keys().cloned());
    names.extend(headers.keys().cloned());
    names.extend(cache.keys().cloned());
    names.extend(limits.keys().cloned());
    names.extend(query.keys().cloned());
    names.extend(read.keys().cloned());
    names.extend(one_sided.keys().cloned());
    names.extend(flexa.clone());
    names.extend(near.clone());

    let mut secrets: BTreeMap<String, SecretRef> = BTreeMap::new();
    let mut exported: Vec<ExportedSecret> = Vec::new();
    let mut values: BTreeMap<String, String> = BTreeMap::new();
    let mut file = PolicyFile {
        schema: SCHEMA,
        gateway_hosts: get(env, "GATEWAY_HOSTS")
            .unwrap_or("")
            .split(',')
            .map(gateway_host)
            .filter(|h| !h.is_empty())
            .collect(),
        backends_policy_default: default,
        relay_secret_on_key_config: get(env, "RELAY_SECRET_ON_KEY_CONFIG").map(str::to_string),
        secrets: BTreeMap::new(),
        integrations: BTreeMap::new(),
        hosts: BTreeMap::new(),
        value_sources: BTreeMap::new(),
        dynamic_hosts: DynamicHostsSection::default(),
        settings: None,
        host_list: HostListSection {
            publish: get(env, "THIRD_PARTY_HOSTS_PUBLISH").map(|v| v.to_ascii_lowercase()),
            max_age_secs: get(env, "THIRD_PARTY_HOSTS_MAX_AGE_SECS")
                .map(|v| {
                    v.parse::<u64>()
                        .map_err(|_| anyhow!("Invalid THIRD_PARTY_HOSTS_MAX_AGE_SECS '{v}'"))
                })
                .transpose()?,
        },
    };
    for authority in &names {
        let kind = if flexa.as_deref() == Some(authority) {
            Some(Kind::Flexa)
        } else if near.as_deref() == Some(authority) {
            Some(Kind::Near)
        } else {
            None
        };
        let mut header_entries = Vec::new();
        for (name, value) in headers.get(authority).into_iter().flatten() {
            if value.is_empty() {
                // An empty value is no secret.
                header_entries.push(HeaderEntry {
                    name: name.clone(),
                    value: String::new(),
                    secret: None,
                });
                continue;
            }
            let (template, var, found, secret_value) = match secret_var(env, value) {
                Some((var, template, v)) => (template, var.to_string(), true, v),
                None => {
                    let base = generated_secret_var(authority, name);
                    let mut var = base.clone();
                    let mut n = 1;
                    // Never a variable the environment has, never a name bound to another value.
                    while env.contains_key(&var) || values.get(&var).is_some_and(|v| v != value) {
                        n += 1;
                        var = format!("{base}_{n}");
                    }
                    ("{secret}".to_string(), var, false, value.as_str())
                }
            };
            // The secret is named after its variable, case kept (TOKEN and token are two).
            let secret_name = var.clone();
            if values.get(&secret_name).is_some_and(|v| v != secret_value) {
                bail!("the export would bind secret '{secret_name}' to two values");
            }
            values.insert(secret_name.clone(), secret_value.to_string());
            if !secrets.contains_key(&secret_name) {
                secrets.insert(
                    secret_name.clone(),
                    SecretRef {
                        env: Some(var.clone()),
                        file: None,
                    },
                );
                exported.push(ExportedSecret {
                    name: secret_name.clone(),
                    env: var,
                    found,
                });
            }
            header_entries.push(HeaderEntry {
                name: name.clone(),
                value: template,
                secret: Some(secret_name),
            });
        }
        let rules = Rules {
            routes: policy
                .get(authority)
                .map(|rules| rules.iter().map(|(m, p)| format!("{m} {p}")).collect()),
            headers: header_entries,
            cache: cache.get(authority).cloned().unwrap_or_default(),
            rate_limit: limits.get(authority).cloned(),
            query_rules: query.get(authority).cloned().unwrap_or_default(),
            read_routes: read.get(authority).cloned().unwrap_or_default(),
            one_sided_write_routes: one_sided.get(authority).cloned().unwrap_or_default(),
        };
        match backends.get(authority) {
            Some(upstream) => {
                file.integrations.insert(
                    label_of(authority),
                    Integration {
                        alias: authority.clone(),
                        upstream: upstream.clone(),
                        kind,
                        routes: rules.routes,
                        headers: rules.headers,
                        cache: rules.cache,
                        rate_limit: rules.rate_limit,
                        query_rules: rules.query_rules,
                        read_routes: rules.read_routes,
                        one_sided_write_routes: rules.one_sided_write_routes,
                    },
                );
            }
            None => {
                file.hosts
                    .insert(authority.clone(), Host::from_rules(kind, rules));
            }
        }
    }
    file.secrets = secrets;
    for entry in get(env, "THIRD_PARTY_QUERY_VALUE_SOURCES")
        .unwrap_or("")
        .split(';')
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        let (name, source) = parse_value_source(entry)?;
        if file.value_sources.insert(name.clone(), source).is_some() {
            bail!("Malformed THIRD_PARTY_QUERY_VALUE_SOURCES: source '{name}' listed twice");
        }
    }
    if let Some(raw) = get(env, "DYNAMIC_HOST_SOURCES") {
        let doc: Value = serde_json::from_str(raw).map_err(|e| {
            anyhow!("Malformed DYNAMIC_HOST_SOURCES (a JSON array of sources): {e}")
        })?;
        let Value::Array(sources) = doc else {
            bail!("Malformed DYNAMIC_HOST_SOURCES: not a JSON array");
        };
        fn exact(v: &Value) -> bool {
            match v {
                // A fraction whose shortest form reads back to another number cannot be kept.
                Value::Number(n) if n.is_f64() => {
                    serde_json::from_str::<Value>(&n.to_string()).is_ok_and(|back| &back == v)
                }
                Value::Array(a) => a.iter().all(exact),
                Value::Object(m) => m.values().all(exact),
                _ => true,
            }
        }
        if !sources.iter().all(exact) {
            bail!("DYNAMIC_HOST_SOURCES holds a fractional number that does not keep its value when written again");
        }
        file.dynamic_hosts.sources = Some(sources);
    }
    if let Some(raw) = get(env, "DYNAMIC_HOSTS_DENY_CIDRS") {
        file.dynamic_hosts.deny_cidrs = raw
            .split(',')
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .map(str::to_string)
            .collect();
    }
    Ok(Export {
        file: file.normalized()?,
        secrets: exported,
        values,
    })
}

/// The table label of an exported alias: the alias itself.
fn label_of(alias: &str) -> String {
    alias.to_string()
}

/// The schemes a header value may put before a secret.
const SCHEMES: &[&str] = &["Bearer ", "Basic "];

/// The variable of `env` (not a policy variable, at least 8 bytes) that `value` is made of: equal to
/// it, or to a scheme ([`SCHEMES`]) followed by it; the variable, the template and the secret.
/// The first by name when several are.
fn secret_var<'a>(
    env: &'a BTreeMap<String, String>,
    value: &str,
) -> Option<(&'a str, String, &'a str)> {
    let candidates = || {
        env.iter()
            .filter(|(k, v)| v.len() >= 8 && !POLICY_ENV_KEYS.contains(&k.as_str()))
    };
    if let Some((k, v)) = candidates().find(|(_, v)| v.as_str() == value) {
        return Some((k.as_str(), "{secret}".to_string(), v.as_str()));
    }
    for scheme in SCHEMES {
        if let Some(rest) = value.strip_prefix(scheme) {
            if let Some((k, v)) = candidates().find(|(_, v)| v.as_str() == rest) {
                return Some((k.as_str(), format!("{scheme}{{secret}}"), v.as_str()));
            }
        }
    }
    None
}

/// The variable a header's secret gets when no variable holds it: `<ALIAS>_<HEADER>`, upper
/// case, `[A-Z0-9_]`.
fn generated_secret_var(authority: &str, header: &str) -> String {
    format!("{authority}_{header}")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// `name=alias GET /path#/pointer@REFRESH_SECS[@fallback=A|B]`, split as the gateway splits it.
fn parse_value_source(entry: &str) -> Result<(String, ValueSource)> {
    let malformed = || anyhow!("Malformed THIRD_PARTY_QUERY_VALUE_SOURCES entry '{entry}'");
    let (name, rest) = entry.split_once('=').ok_or_else(malformed)?;
    let parts: Vec<&str> = rest.split('@').collect();
    if !(2..=3).contains(&parts.len()) {
        return Err(malformed());
    }
    let mut words = parts[0].trim().splitn(3, ' ');
    let (Some(alias), Some(method), Some(target)) = (words.next(), words.next(), words.next())
    else {
        return Err(malformed());
    };
    // The gateway takes GET only.
    if !method.eq_ignore_ascii_case("GET") {
        return Err(malformed());
    }
    let (path, pointer) = target.trim().split_once('#').ok_or_else(malformed)?;
    let refresh_raw = parts[1].trim();
    let refresh_secs = refresh_raw
        .parse::<u64>()
        .ok()
        .filter(|_| refresh_raw.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(malformed)?;
    let fallback = match parts.get(2) {
        None => None,
        Some(raw) => Some(
            raw.trim()
                .strip_prefix("fallback=")
                .ok_or_else(malformed)?
                .split('|')
                .map(str::to_string)
                .collect(),
        ),
    };
    Ok((
        name.trim().to_string(),
        ValueSource {
            alias: alias.trim().to_ascii_lowercase(),
            route: format!("{method} {}", path.trim()),
            pointer: pointer.to_string(),
            refresh_secs,
            fallback,
        },
    ))
}

/// The default of `THIRD_PARTY_HOSTS_MAX_AGE_SECS`.
pub const HOST_LIST_DEFAULT_MAX_AGE_SECS: u64 = 300;

/// `entry` (`METHOD rest`) with its method token in upper case.
fn upper_method(entry: &str) -> String {
    match entry.split_once(' ') {
        Some((method, rest)) => format!("{} {rest}", method.to_ascii_uppercase()),
        None => entry.to_ascii_uppercase(),
    }
}

/// The effective policy of `file` as JSON, keyed by authority (labels and secret names are
/// not part of it), header values per `headers`. `resolve` is only used with
/// [`HeaderValues::Plain`]. `same_behaviour` gives the behaviour form, the same for every way
/// of writing one policy: keyed kinds (`cmc`, `swapkit`, generic providers with startup checks)
/// as `generic`, method tokens in upper case, gateway hosts and deny CIDRs as sorted sets, no
/// dynamic sources as an empty list, the defaults of unset keys written out; without it the
/// policy as declared.
pub fn canonical(
    file: &PolicyFile,
    headers: HeaderValues,
    same_behaviour: bool,
    resolve: &dyn Fn(&str) -> Result<String>,
) -> Result<Value> {
    let strings = |v: &[String]| Value::Array(v.iter().cloned().map(Value::String).collect());
    // The behaviour form: method tokens as the parsers compare them.
    let routes_of = |v: &[String]| {
        if same_behaviour {
            Value::Array(v.iter().map(|e| Value::String(upper_method(e))).collect())
        } else {
            strings(v)
        }
    };
    let mut auths = Map::new();
    for (authority, a) in file.authorities()? {
        let mut o = Map::new();
        if let Some(kind) = a.kind {
            let kind = match kind {
                Kind::Cmc | Kind::Swapkit if same_behaviour => Kind::Generic,
                k => k,
            };
            o.insert("kind".into(), Value::String(kind.as_str().into()));
        }
        if let Some(up) = &a.upstream {
            o.insert("upstream".into(), Value::String(up.clone()));
        }
        let r = &a.rules;
        if let Some(routes) = &r.routes {
            o.insert("routes".into(), routes_of(routes));
        }
        if !r.headers.is_empty() {
            let mut list = Vec::new();
            for h in &r.headers {
                let value = match headers {
                    HeaderValues::Redacted => REDACTED.to_string(),
                    HeaderValues::Plain => match &h.secret {
                        // Trimmed, as BACKEND_HEADERS is read.
                        Some(name) => h
                            .value
                            .replace("{secret}", &resolve(name)?)
                            .trim()
                            .to_string(),
                        None => h.value.clone(),
                    },
                };
                let mut e = Map::new();
                e.insert("name".into(), Value::String(h.name.clone()));
                e.insert("value".into(), Value::String(value));
                list.push(Value::Object(e));
            }
            o.insert("headers".into(), Value::Array(list));
        }
        for (key, list) in [
            ("cache", &r.cache),
            ("query_rules", &r.query_rules),
            ("read_routes", &r.read_routes),
            ("one_sided_write_routes", &r.one_sided_write_routes),
        ] {
            if !list.is_empty() {
                o.insert(key.into(), routes_of(list));
            }
        }
        if let Some(rl) = &r.rate_limit {
            o.insert("rate_limit".into(), Value::String(rl.clone()));
        }
        // An authority with nothing configured is no part of the policy.
        if !o.is_empty() {
            auths.insert(authority, Value::Object(o));
        }
    }
    let mut sources = Map::new();
    for (name, s) in &file.value_sources {
        let mut o = Map::new();
        o.insert("alias".into(), Value::String(s.alias.clone()));
        let route = if same_behaviour {
            upper_method(&s.route)
        } else {
            s.route.clone()
        };
        o.insert("route".into(), Value::String(route));
        o.insert("pointer".into(), Value::String(s.pointer.clone()));
        o.insert("refresh_secs".into(), Value::from(s.refresh_secs));
        if let Some(f) = &s.fallback {
            o.insert("fallback".into(), strings(f));
        }
        sources.insert(name.clone(), Value::Object(o));
    }
    let mut root = Map::new();
    root.insert("schema".into(), Value::from(SCHEMA));
    if same_behaviour {
        let set: BTreeSet<&String> = file.gateway_hosts.iter().collect();
        root.insert(
            "gateway_hosts".into(),
            Value::Array(set.into_iter().cloned().map(Value::String).collect()),
        );
    } else {
        root.insert("gateway_hosts".into(), strings(&file.gateway_hosts));
    }
    root.insert(
        "backends_policy_default".into(),
        Value::String(
            match file.backends_policy_default {
                Some(PolicyDefault::Allow) => "allow",
                _ => "deny",
            }
            .into(),
        ),
    );
    root.insert(
        "relay_secret_on_key_config".into(),
        match (&file.relay_secret_on_key_config, same_behaviour) {
            (None, true) => Value::String("off".into()),
            (r, _) => r.clone().map_or(Value::Null, Value::String),
        },
    );
    root.insert("authorities".into(), Value::Object(auths));
    root.insert("value_sources".into(), Value::Object(sources));
    let mut dynamic = Map::new();
    if same_behaviour {
        // A set, as the deny list is read; no sources is an empty list.
        let set: BTreeSet<&String> = file.dynamic_hosts.deny_cidrs.iter().collect();
        dynamic.insert(
            "deny_cidrs".into(),
            Value::Array(set.into_iter().cloned().map(Value::String).collect()),
        );
        dynamic.insert(
            "sources".into(),
            Value::Array(file.dynamic_hosts.sources.clone().unwrap_or_default()),
        );
    } else {
        dynamic.insert("deny_cidrs".into(), strings(&file.dynamic_hosts.deny_cidrs));
        dynamic.insert(
            "sources".into(),
            file.dynamic_hosts
                .sources
                .clone()
                .map_or(Value::Null, Value::Array),
        );
    }
    root.insert("dynamic_hosts".into(), Value::Object(dynamic));
    let mut host_list = Map::new();
    host_list.insert(
        "publish".into(),
        match (&file.host_list.publish, same_behaviour) {
            (None, true) => Value::String("off".into()),
            (p, _) => p.clone().map_or(Value::Null, Value::String),
        },
    );
    host_list.insert(
        "max_age_secs".into(),
        match (file.host_list.max_age_secs, same_behaviour) {
            (None, true) => Value::from(HOST_LIST_DEFAULT_MAX_AGE_SECS),
            (m, _) => m.map_or(Value::Null, Value::from),
        },
    );
    root.insert("host_list".into(), Value::Object(host_list));
    Ok(Value::Object(root))
}

/// `value` as compact JSON with the keys of every object sorted.
pub fn canonical_json(value: &Value) -> String {
    fn sorted(v: &Value) -> Value {
        match v {
            Value::Object(m) => {
                let sorted_map: BTreeMap<&String, Value> =
                    m.iter().map(|(k, v)| (k, sorted(v))).collect();
                let mut out = Map::new();
                for (k, v) in sorted_map {
                    out.insert(k.clone(), v);
                }
                Value::Object(out)
            }
            Value::Array(a) => Value::Array(a.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    sorted(value).to_string()
}

/// The keys at which two canonical policies differ: a top-level key, or for `authorities` and
/// `value_sources` the entry and its field (`authorities.<authority>.<field>`). Names only.
pub fn differing_keys(a: &Value, b: &Value) -> Vec<String> {
    fn keys(v: &Value) -> BTreeSet<String> {
        v.as_object()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }
    let mut out = Vec::new();
    let top: BTreeSet<String> = keys(a).union(&keys(b)).cloned().collect();
    for k in top {
        let (x, y) = (&a[&k], &b[&k]);
        if x == y {
            continue;
        }
        if k == "authorities" || k == "value_sources" {
            for e in keys(x).union(&keys(y)) {
                let (ex, ey) = (&x[e], &y[e]);
                if ex == ey {
                    continue;
                }
                if ex.is_null() || ey.is_null() {
                    out.push(format!("{k}.{e}"));
                    continue;
                }
                for f in keys(ex).union(&keys(ey)) {
                    if ex[f] != ey[f] {
                        out.push(format!("{k}.{e}.{f}"));
                    }
                }
            }
        } else {
            out.push(k);
        }
    }
    out
}

/// TOML text of `file` (the export): one table per integration, host and value source, lists
/// one entry per line. `secrets` notes which secret variables are new names.
pub fn to_toml(file: &PolicyFile, secrets: &[ExportedSecret]) -> Result<String> {
    let mut s = String::new();
    s.push_str("schema = 1\n");
    if !file.gateway_hosts.is_empty() {
        s.push_str(&format!(
            "gateway_hosts = {}\n",
            toml_strings(&file.gateway_hosts)
        ));
    }
    if let Some(d) = file.backends_policy_default {
        s.push_str(&format!(
            "backends_policy_default = \"{}\"\n",
            match d {
                PolicyDefault::Allow => "allow",
                PolicyDefault::Deny => "deny",
            }
        ));
    }
    if let Some(r) = &file.relay_secret_on_key_config {
        s.push_str(&format!("relay_secret_on_key_config = {}\n", toml_str(r)));
    }
    if !file.secrets.is_empty() {
        s.push_str("\n[secrets]\n");
        for (name, r) in &file.secrets {
            let new = secrets.iter().any(|e| &e.name == name && !e.found);
            if new {
                s.push_str(
                    "# A new variable: set it to the header value this secret stands for.\n",
                );
            }
            match (&r.env, &r.file) {
                (Some(env), _) => s.push_str(&format!(
                    "{} = {{ env = {} }}\n",
                    toml_key(name),
                    toml_str(env)
                )),
                (None, Some(path)) => s.push_str(&format!(
                    "{} = {{ file = {} }}\n",
                    toml_key(name),
                    toml_str(path)
                )),
                (None, None) => {}
            }
        }
    }
    let rules_toml = |s: &mut String, kind: Option<Kind>, r: &Rules| {
        if let Some(k) = kind {
            s.push_str(&format!("kind = \"{}\"\n", k.as_str()));
        }
        if let Some(routes) = &r.routes {
            s.push_str(&format!("routes = {}\n", toml_list(routes)));
        }
        if !r.headers.is_empty() {
            let items: Vec<String> = r
                .headers
                .iter()
                .map(|h| {
                    let mut e = format!(
                        "{{ name = {}, value = {}",
                        toml_str(&h.name),
                        toml_str(&h.value)
                    );
                    if let Some(sec) = &h.secret {
                        e.push_str(&format!(", secret = {}", toml_str(sec)));
                    }
                    e.push_str(" }");
                    e
                })
                .collect();
            s.push_str(&format!("headers = [\n  {},\n]\n", items.join(",\n  ")));
        }
        for (key, list) in [
            ("cache", &r.cache),
            ("query_rules", &r.query_rules),
            ("read_routes", &r.read_routes),
            ("one_sided_write_routes", &r.one_sided_write_routes),
        ] {
            if !list.is_empty() {
                s.push_str(&format!("{key} = {}\n", toml_list(list)));
            }
        }
        if let Some(rl) = &r.rate_limit {
            s.push_str(&format!("rate_limit = {}\n", toml_str(rl)));
        }
    };
    for (label, i) in &file.integrations {
        s.push_str(&format!("\n[integrations.{}]\n", toml_key(label)));
        s.push_str(&format!("alias = {}\n", toml_str(&i.alias)));
        s.push_str(&format!("upstream = {}\n", toml_str(&i.upstream)));
        rules_toml(&mut s, i.kind, &i.rules());
    }
    for (name, h) in &file.hosts {
        s.push_str(&format!("\n[hosts.{}]\n", toml_key(name)));
        rules_toml(&mut s, h.kind, &h.rules());
    }
    for (name, v) in &file.value_sources {
        s.push_str(&format!("\n[value_sources.{}]\n", toml_key(name)));
        s.push_str(&format!("alias = {}\n", toml_str(&v.alias)));
        s.push_str(&format!("route = {}\n", toml_str(&v.route)));
        s.push_str(&format!("pointer = {}\n", toml_str(&v.pointer)));
        s.push_str(&format!("refresh_secs = {}\n", v.refresh_secs));
        if let Some(f) = &v.fallback {
            s.push_str(&format!("fallback = {}\n", toml_strings(f)));
        }
    }
    let d = &file.dynamic_hosts;
    if !d.deny_cidrs.is_empty() || d.sources.is_some() {
        s.push_str("\n[dynamic_hosts]\n");
        if !d.deny_cidrs.is_empty() {
            s.push_str(&format!("deny_cidrs = {}\n", toml_list(&d.deny_cidrs)));
        }
        if let Some(sources) = &d.sources {
            let items: Result<Vec<String>> = sources.iter().map(toml_inline).collect();
            let items = items?;
            if items.is_empty() {
                s.push_str("sources = []\n");
            } else {
                s.push_str(&format!("sources = [\n  {},\n]\n", items.join(",\n  ")));
            }
        }
    }
    let h = &file.host_list;
    if h.publish.is_some() || h.max_age_secs.is_some() {
        s.push_str("\n[host_list]\n");
        if let Some(p) = &h.publish {
            s.push_str(&format!("publish = {}\n", toml_str(p)));
        }
        if let Some(m) = h.max_age_secs {
            s.push_str(&format!("max_age_secs = {m}\n"));
        }
    }
    Ok(s)
}

/// A TOML basic string.
fn toml_str(v: &str) -> String {
    let mut s = String::with_capacity(v.len() + 2);
    s.push('"');
    for c in v.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                s.push_str(&format!("\\u{:04X}", c as u32))
            }
            c => s.push(c),
        }
    }
    s.push('"');
    s
}

/// A TOML key: bare when it can be, else quoted.
fn toml_key(k: &str) -> String {
    if !k.is_empty()
        && k.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        k.to_string()
    } else {
        toml_str(k)
    }
}

/// An inline array of strings.
fn toml_strings(v: &[String]) -> String {
    let items: Vec<String> = v.iter().map(|x| toml_str(x)).collect();
    format!("[{}]", items.join(", "))
}

/// An array of strings, one per line.
fn toml_list(v: &[String]) -> String {
    let items: Vec<String> = v.iter().map(|x| format!("  {},", toml_str(x))).collect();
    format!("[\n{}\n]", items.join("\n"))
}

/// A JSON value as an inline TOML value (no `null` in TOML).
fn toml_inline(v: &Value) -> Result<String> {
    Ok(match v {
        Value::Null => bail!("DYNAMIC_HOST_SOURCES holds a null, which TOML cannot hold"),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => toml_str(s),
        Value::Array(a) => {
            let items: Result<Vec<String>> = a.iter().map(toml_inline).collect();
            format!("[{}]", items?.join(", "))
        }
        Value::Object(m) => {
            let items: Result<Vec<String>> = m
                .iter()
                .map(|(k, v)| Ok(format!("{} = {}", toml_key(k), toml_inline(v)?)))
                .collect();
            if m.is_empty() {
                "{}".to_string()
            } else {
                format!("{{ {} }}", items?.join(", "))
            }
        }
    })
}

/// The export round trip on `env`: [`export`], [`to_toml`], [`parse`], [`render`] and
/// [`export`] again reach the same canonical policy with the same header values. `Ok(false)`:
/// `env` is not a policy [`export`] reads.
pub fn check_round_trip(env: &BTreeMap<String, String>) -> std::result::Result<bool, String> {
    let Ok(exported) = export(env) else {
        return Ok(false);
    };
    let Ok(text) = to_toml(&exported.file, &exported.secrets) else {
        return Ok(false);
    };
    let resolve = |name: &str| exported.resolve(name);
    let loaded = match parse(&text) {
        Ok(l) => l,
        // A policy the file checks refuse (an entry no file can hold).
        Err(_) => return Ok(false),
    };
    let a = canonical(&exported.file, HeaderValues::Plain, false, &resolve)
        .map_err(|e| e.to_string())?;
    let b = canonical(&loaded.file, HeaderValues::Plain, false, &resolve)
        .map_err(|e| format!("canonical of the parsed export: {e}"))?;
    if a != b {
        return Err(format!(
            "export and parse differ at {:?}\n{text}",
            differing_keys(&a, &b)
        ));
    }
    let rendered = render(&loaded.file, &resolve).map_err(|e| format!("render: {e}"))?;
    let env2: BTreeMap<String, String> = rendered
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    let again = export(&env2).map_err(|e| format!("export of the render: {e}"))?;
    let c = canonical(&again.file, HeaderValues::Plain, false, &|n| {
        again.resolve(n)
    })
    .map_err(|e| e.to_string())?;
    if c != a {
        return Err(format!(
            "render and export differ at {:?}\n{text}",
            differing_keys(&c, &a)
        ));
    }
    Ok(true)
}

#[cfg(test)]
mod tests;

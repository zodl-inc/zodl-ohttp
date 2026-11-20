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

//! The gateway's settings other than the routing policy, as keys of the `[settings]` table of
//! its configuration files ([`crate::config_source`]).
//!
//! Every variable the gateway reads at startup is either policy
//! ([`zodl_ohttp_integrations::core::config::POLICY_ENV_KEYS`]) or one of [`SETTINGS`]: a
//! `tuning` setting (non-secret, the same on every origin of a network: the common file), a
//! `deployment` setting (addresses, stores, identity, per-host sizing: the host file) or a
//! `secret` (written in a file only as a reference to a `[secrets]` entry). The key of a
//! setting is its variable in lower case (`LWD_TIMEOUT_SECS` = `lwd_timeout_secs`).
//!
//! A value in a file is typed (integer, number, boolean, string, array of strings) and stands
//! for exactly one value of the variable, which the gateway's parser then reads through
//! [`crate::config_source::var`], so a file and the environment it stands for are read by the
//! same code: integers as their decimal digits, booleans as `1` / `0`, arrays joined with `,`.
//! A key left out is the variable unset: the defaults are the parsers' own.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Result};
use sha2::{Digest, Sha256};
use toml::Value;
use zodl_ohttp_integrations::core::config::POLICY_ENV_KEYS;

/// Which file a setting belongs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    /// The common file (one per network, non-secret).
    Common,
    /// The host file (one per host or per network on a cluster).
    Host,
}

/// How a boolean variable is read today (each is its parser's own rule).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flag {
    /// `1` or `true` (any case) is true, anything else false ([`crate::config::flag_on`]).
    OneOrTrue,
    /// `1`, `true` or `on` (trimmed, any case) is true, anything else false
    /// ([`crate::lwd::connection_pool_on`]).
    OneTrueOn,
    /// `1`/`true` true, `0`/`false` false, anything else the default
    /// ([`crate::origin::parse_flag`]).
    Lenient,
    /// `1`/`true` true, `0`/`false` false, blank the default, anything else an error
    /// ([`crate::prefetch::parse_flag`]).
    Strict,
}

/// The type of a setting's value in a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A non-negative integer.
    Int,
    /// A number.
    Float,
    /// A string, as is.
    Str,
    /// An array of strings, joined with `,` (no entry may hold one).
    List,
    /// A boolean.
    Bool(Flag),
}

/// Whether a setting's value may or must be a secret reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretUse {
    /// A literal only.
    Never,
    /// A literal, or a secret reference (a store URL carrying a password: a literal with
    /// credentials is refused).
    Allowed,
    /// A secret reference only.
    Required,
}

/// One setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Setting {
    /// The variable.
    pub env: &'static str,
    pub place: Place,
    pub kind: Kind,
    pub secret: SecretUse,
}

impl Setting {
    /// The key in a file: the variable in lower case.
    pub fn key(&self) -> String {
        self.env.to_ascii_lowercase()
    }

    /// `tuning`, `deployment` or `secret`.
    pub fn class(&self) -> &'static str {
        match (self.secret, self.place) {
            (SecretUse::Required, _) => "secret",
            (_, Place::Common) => "tuning",
            (_, Place::Host) => "deployment",
        }
    }
}

const fn tuning(env: &'static str, kind: Kind) -> Setting {
    Setting {
        env,
        place: Place::Common,
        kind,
        secret: SecretUse::Never,
    }
}

const fn deployment(env: &'static str, kind: Kind) -> Setting {
    Setting {
        env,
        place: Place::Host,
        kind,
        secret: SecretUse::Never,
    }
}

const fn store(env: &'static str, kind: Kind) -> Setting {
    Setting {
        env,
        place: Place::Host,
        kind,
        secret: SecretUse::Allowed,
    }
}

const fn secret(env: &'static str, place: Place) -> Setting {
    Setting {
        env,
        place,
        kind: Kind::Str,
        secret: SecretUse::Required,
    }
}

use Kind::{Bool, Float, Int, List, Str};

/// Every setting of the gateway that is not policy. The serving process reads exactly these and
/// the policy variables, from its configuration files only (from the environment it reads no
/// more than the transition's [`BOOTSTRAP_ENV_KEYS`]); the `backfill` subcommand reads these and
/// its own variables from the environment ([`BACKFILL_ENV_KEYS`]).
pub const SETTINGS: &[Setting] = &[
    // Mode, listener, logs.
    tuning("GATEWAY_MODE", Str),
    tuning("HEADER_READ_TIMEOUT_SECS", Int),
    tuning("LOG_OUTER_HEADER_NAMES", Bool(Flag::OneOrTrue)),
    // Relay authentication and keys.
    tuning("ALLOW_UNAUTHENTICATED_RELAY", Bool(Flag::OneOrTrue)),
    tuning("HPKE_KEY_ID", Int),
    // Limits and timeouts.
    tuning("MAX_INFLIGHT_REQUESTS", Int),
    tuning("MAX_UPSTREAM_RESPONSE_BYTES", Int),
    tuning("MAX_INFLIGHT_UPSTREAM", Int),
    tuning("MAX_INFLIGHT_PER_BACKEND", Int),
    tuning("LWD_HEAVY_BLOCK_RANGE", Int),
    tuning("LWD_PERMIT_WAIT_MS", Int),
    tuning("LWD_PERMIT_MAX_WAITERS", Int),
    tuning("MAX_BLOCK_RANGE", Int),
    tuning("LWD_TIMEOUT_SECS", Int),
    tuning("LWD_UNARY_TIMEOUT_SECS", Int),
    tuning("LWD_SEND_TIMEOUT_SECS", Int),
    tuning("LWD_STREAM_IDLE_SECS", Int),
    tuning("LWD_CONNECT_TIMEOUT_MS", Int),
    tuning("LWD_HEDGE_DELAY_MS", Int),
    tuning("LWD_HEDGE_MAX_INFLIGHT", Int),
    tuning("LONG_POLL_MAX_INITIAL_SILENCE_SECS", Int),
    tuning("LONG_POLL_IDLE_SECS", Int),
    tuning("SSE_KEEPALIVE_SECS", Int),
    tuning("MAX_CACHE_GET_CONCURRENCY", Int),
    tuning("MAX_LARGE_RESPONSE_CONCURRENCY", Int),
    tuning("LARGE_RESPONSE_THRESHOLD", Int),
    tuning("HEALTHZ_LWD_ERROR_RATIO", Float),
    tuning("HEALTHZ_LWD_ERROR_WINDOW_SECS", Int),
    tuning("HEALTHZ_LWD_MIN_ERRORS", Int),
    tuning("REDIS_OP_TIMEOUT_MS", Int),
    // Responses.
    tuning("CHUNK_SIZE", Int),
    tuning("CHUNK_FLUSH_MS", Int),
    tuning("RESPONSE_PADDING", Str),
    // Replay protection.
    tuning("REPLAY_FRESHNESS", Str),
    tuning("REPLAY_FRESHNESS_WINDOW_SECS", Int),
    tuning("REPLAY_WAIT_CONNS", Int),
    tuning("REPLAY_FALLBACK_HEALTH_FAILURES", Int),
    tuning("REPLAY_FALLBACK_HEALTH_WINDOW_SECS", Int),
    tuning("REPLAY_STARTUP_STORES_WAIT_SECS", Int),
    // Dynamic hosts.
    tuning("DYNAMIC_HOSTS_MAX_DOCUMENT_BYTES", Int),
    tuning("DYNAMIC_HOSTS_FETCH_TIMEOUT_SECS", Int),
    // Caches.
    tuning("LOCAL_CACHE_BYTES", Int),
    tuning("LOCAL_CACHE_MAX_ENTRY_BYTES", Int),
    tuning("PERMANENT_MIN_HEIGHT", Int),
    tuning("PERMANENT_OP_TIMEOUT_MS", Int),
    tuning("CHAIN_TIP_STALE_SECS", Int),
    tuning("PREFETCH_TIP", Bool(Flag::Strict)),
    tuning("PREFETCH_BLOCK_TXS_MAX", Int),
    tuning("PREFETCH_TREE_STATE", Bool(Flag::Strict)),
    tuning("PINNED_TREESTATE_RANGE", Str),
    // Secrets the same on every origin.
    secret("HPKE_KEYS", Place::Common),
    secret("HPKE_PRIVATE_KEY", Place::Common),
    secret("HPKE_ACCEPT_ONLY_KEYS", Place::Common),
    secret("RELAY_SECRET", Place::Common),
    secret("RELAY_SECRETS", Place::Common),
    secret("CONFIGS_SIGNING_SEED_HEX", Place::Common),
    secret("FLEXA_PUBLISHABLE_KEY", Place::Common),
    // Identity and addresses (and the log filter, raised per host for debugging).
    deployment("RUST_LOG", Str),
    deployment("NETWORK", Str),
    deployment("PORT", Int),
    deployment("INTERNAL_BIND_ADDR", Str),
    deployment("ORIGIN_ID", Str),
    deployment("LWD_ADDR", Str),
    deployment("LWD_ENDPOINTS", Str),
    deployment("LWD_CONNECTION_POOL", Bool(Flag::OneTrueOn)),
    deployment("CACHE_KEY_BACKEND", Str),
    // Per-host sizing.
    deployment("MAX_INFLIGHT_LWD", Int),
    deployment("MAX_INFLIGHT_LWD_HEAVY", Int),
    deployment("PINNED_BACKFILL_WORKERS", Int),
    deployment("PREFETCH_BLOCK_TXS", Bool(Flag::Strict)),
    // Stores (a password in the URL: a secret reference).
    store("REDIS_URL", Str),
    store("REDIS_SECURITY_URL", Str),
    store("REDIS_PINNED_URL", Str),
    store("REDIS_PINNED_WRITE_URL", Str),
    store("PERMANENT_REDIS_URL", Str),
    store("REPLAY_PEER_URLS", List),
    store("REPLAY_STANDBY_URLS", List),
    // Multiple origins.
    deployment("REPLAY_PEER_MODE", Str),
    deployment("REPLAY_PEER_TIMEOUT_MS", Int),
    deployment("REPLAY_PEER_FAIL_CLOSED", Bool(Flag::Lenient)),
    deployment("REPLAY_PEER_FAIL_CLOSED_WRITES", Bool(Flag::Lenient)),
    deployment("REPLAY_PEER_WAIT_REPLICAS", Int),
    deployment("REPLAY_PEER_WAIT_MS", Int),
    deployment("REPLAY_ASYNC_MAX_LAG_MS", Int),
    deployment("REPLAY_ASYNC_RECOVERY_SECS", Int),
    deployment("REPLAY_ASYNC_FAILURES_BEFORE_STRICT", Int),
    deployment("REPLAY_WRITE_WAIT_REPLICAS", Int),
    deployment("REPLAY_WRITE_WAIT_MS", Int),
    deployment("REPLAY_UNAVAILABLE_FALLBACK", Bool(Flag::Lenient)),
    deployment("REPLAY_LOCAL_WAITAOF_MS", Int),
    // WRITE forwarding.
    deployment("REPLAY_WRITE_FORWARD_URL", Str),
    deployment("REPLAY_WRITE_FORWARD_CONNECT_TIMEOUT_MS", Int),
    deployment("REPLAY_WRITE_FORWARD_TIMEOUT_SECS", Int),
    deployment("REPLAY_WRITE_FORWARD_BACKOFF_MS", Int),
    deployment("WRITE_FORWARD_BIND_ADDR", Str),
    secret("REPLAY_WRITE_FORWARD_SECRET", Place::Host),
    secret("WRITE_FORWARD_SECRETS", Place::Host),
];

/// The variables of the transition the environment may still hold: the two file paths (read when
/// `--config` / `--host-config` are not given and `CONFIG_SOURCE=file` is set, with a warning,
/// for one release; refused without it) and `CONFIG_SOURCE` (refused unless it is `file`).
#[allow(dead_code)] // documentation and tests
pub const BOOTSTRAP_ENV_KEYS: &[&str] = &[
    crate::config_source::SOURCE_ENV,
    crate::config_source::FILE_ENV,
    crate::config_source::HOST_FILE_ENV,
];

/// The variables only the `backfill` subcommand reads (it reads its configuration from the
/// environment).
#[allow(dead_code)] // documentation and tests
pub const BACKFILL_ENV_KEYS: &[&str] = &[
    "BACKFILL_START",
    "BACKFILL_END",
    "BACKFILL_BATCH",
    "BACKFILL_CONCURRENCY",
    "BACKFILL_PAUSE_MS",
    "BACKFILL_POOL",
];

/// MAX_INFLIGHT_REQUESTS default. Above the ZIP's reference (256) because every mempool long
/// poll and block range stream holds a permit for its whole duration.
pub const DEFAULT_MAX_INFLIGHT_REQUESTS: usize = 1024;

/// `MAX_INFLIGHT_REQUESTS`: OHTTP requests in flight per process (a positive integer).
pub fn max_inflight_requests() -> Result<usize> {
    Ok(match crate::config_source::var("MAX_INFLIGHT_REQUESTS") {
        Ok(v) if !v.trim().is_empty() => match v.trim().parse::<usize>() {
            Ok(n) if n > 0 => n,
            _ => anyhow::bail!("MAX_INFLIGHT_REQUESTS must be a positive integer, got '{v}'"),
        },
        _ => DEFAULT_MAX_INFLIGHT_REQUESTS,
    })
}

/// `CHAIN_TIP_STALE_SECS`: a stored tip unmoved for longer makes the followers compare it with
/// their own lightwalletd (chain.rs, "Stale leader").
pub fn chain_tip_stale_after() -> Result<std::time::Duration> {
    Ok(match crate::config_source::var("CHAIN_TIP_STALE_SECS") {
        Ok(v) if !v.trim().is_empty() => match v.trim().parse::<u64>() {
            Ok(n) if n > 0 => std::time::Duration::from_secs(n),
            _ => anyhow::bail!("CHAIN_TIP_STALE_SECS must be a positive integer, got '{v}'"),
        },
        _ => crate::chain::DEFAULT_TIP_STALE_AFTER,
    })
}

/// The check of `PINNED_TREESTATE_RANGE` the serving process makes once its cache is connected:
/// with `REDIS_PINNED_URL` set, a range that does not parse is a startup error.
pub fn check_pinned_range() -> Result<()> {
    let url = crate::config_source::var("REDIS_PINNED_URL").unwrap_or_default();
    let range = crate::config_source::var("PINNED_TREESTATE_RANGE").unwrap_or_default();
    if !url.is_empty() && !range.is_empty() && crate::cache::parse_pinned_range(&range).is_none() {
        bail!("Malformed PINNED_TREESTATE_RANGE: {range}");
    }
    Ok(())
}

/// The setting of variable `env`.
pub fn setting(env: &str) -> Option<&'static Setting> {
    SETTINGS.iter().find(|s| s.env == env)
}

/// The setting of file key `key`.
pub fn by_key(key: &str) -> Option<&'static Setting> {
    SETTINGS
        .iter()
        .find(|s| s.env.eq_ignore_ascii_case(key) && s.key() == key)
}

/// A setting's value in a file.
#[derive(Clone, PartialEq, Eq)]
pub enum FileValue {
    /// A literal, as the variable's value.
    Plain(String),
    /// A secret: its value (`template` `None`), or `template` with `{secret}` replaced by it.
    Secret {
        name: String,
        template: Option<String>,
    },
}

impl std::fmt::Debug for FileValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // A literal is never a secret (one with credentials is refused).
            Self::Plain(v) => f.debug_tuple("Plain").field(v).finish(),
            Self::Secret { name, template } => f
                .debug_struct("Secret")
                .field("name", name)
                .field("template", &template.is_some())
                .finish(),
        }
    }
}

/// The placeholder of a secret in a template.
pub const SECRET_PLACEHOLDER: &str = "{secret}";

/// `value` as a URL parser reads it: ASCII whitespace (tabs, line breaks) removed.
fn url_form(value: &str) -> String {
    value.chars().filter(|c| !c.is_ascii_whitespace()).collect()
}

/// The userinfo of one URL entry: after the scheme (`scheme:` and any `/`), up to the last `@`
/// anywhere after it (a `/`, `?` or `#` in a password does not end it here: conservative).
fn userinfo(entry: &str) -> Option<&str> {
    let (_, rest) = entry.split_once(':')?;
    let rest = rest.trim_start_matches('/');
    rest.rfind('@').map(|at| &rest[..at])
}

/// Whether `value` (a store setting: one URL, or comma-separated URLs for a `list`) holds a
/// password: a URL with a userinfo that has a `:` (`scheme://user:password@host`,
/// `scheme://:password@host`). A user name without a password (`scheme://user@host`) is no
/// credential. One URL is read whole (a `,` may be part of its password).
fn has_credentials(value: &str, list: bool) -> bool {
    let value = url_form(value);
    let has = |entry: &str| userinfo(entry).is_some_and(|u| u.contains(':'));
    if list {
        value.split(',').any(has)
    } else {
        has(&value)
    }
}

/// A store URL template: `{secret}` is the whole password of its single URL
/// (`scheme://[user]:{secret}@host...`), nowhere else, and the user holds no `:`.
fn template_ok(template: &str) -> bool {
    let t = url_form(template);
    if t.contains(',') || t.matches(SECRET_PLACEHOLDER).count() != 1 {
        return false;
    }
    match userinfo(&t).and_then(|u| u.split_once(':')) {
        Some((user, password)) => {
            password == SECRET_PLACEHOLDER && !user.contains(SECRET_PLACEHOLDER)
        }
        None => false,
    }
}

/// `secret` percent-encoded for the password of a URL: every byte but the unreserved
/// characters (`A-Z a-z 0-9 - . _ ~`) as `%XX`, so a secret file holds the password itself.
pub fn encode_password(secret: &str) -> String {
    let mut out = String::with_capacity(secret.len());
    for b in secret.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The variable's value a typed literal stands for (errors name the key, never a value).
fn literal(s: &Setting, v: &Value) -> Result<String> {
    let key = s.key();
    Ok(match (s.kind, v) {
        (Int, Value::Integer(n)) if *n >= 0 => n.to_string(),
        (Int, _) => bail!("settings.{key} must be a non-negative integer"),
        (Float, Value::Float(f)) if f.is_finite() => f.to_string(),
        (Float, Value::Integer(n)) => (*n as f64).to_string(),
        (Float, _) => bail!("settings.{key} must be a number"),
        (Bool(_), Value::Boolean(b)) => if *b { "1" } else { "0" }.to_string(),
        (Bool(_), _) => bail!("settings.{key} must be true or false"),
        (Str, Value::String(v)) => v.clone(),
        (Str, _) => bail!("settings.{key} must be a string"),
        (List, Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::String(i) if !i.contains(',') => out.push(i.as_str()),
                    Value::String(_) => {
                        bail!("settings.{key}: an entry holds a ',' (one entry per array item)")
                    }
                    _ => bail!("settings.{key} must be an array of strings"),
                }
            }
            out.join(",")
        }
        (List, _) => bail!("settings.{key} must be an array of strings"),
    })
}

/// Parse the `[settings]` table of a file: every key known, every value of its type, a secret
/// only as a reference (`{ secret = "<name>" }`, or `{ secret = "<name>", value = "...{secret}..." }`
/// for a string setting). Errors name keys, never values.
pub fn parse_table(table: &toml::Table) -> Result<BTreeMap<&'static str, FileValue>> {
    let mut out = BTreeMap::new();
    for (key, v) in table {
        let Some(s) = by_key(key) else {
            if POLICY_ENV_KEYS.iter().any(|p| p.eq_ignore_ascii_case(key)) {
                bail!("settings.{key} is a policy variable: write it in the policy part of the common file");
            }
            bail!("settings: unknown setting `{key}`");
        };
        let value = match v {
            Value::Table(t) => {
                if s.secret == SecretUse::Never {
                    bail!("settings.{key} cannot be a secret reference");
                }
                if let Some(other) = t.keys().find(|k| *k != "secret" && *k != "value") {
                    bail!("settings.{key}: unknown field `{other}` (a secret reference has `secret` and an optional `value`)");
                }
                let name = match t.get("secret") {
                    Some(Value::String(n)) if !n.trim().is_empty() => n.clone(),
                    _ => bail!("settings.{key}: a secret reference needs `secret`, the name of a [secrets] entry"),
                };
                let template = match t.get("value") {
                    None => None,
                    Some(Value::String(t)) => {
                        if s.kind != Str || s.secret != SecretUse::Allowed {
                            bail!(
                                "settings.{key}: only a store URL setting takes a `value` template"
                            );
                        }
                        if !template_ok(t) {
                            bail!("settings.{key}: `value` must be one URL whose whole password is {SECRET_PLACEHOLDER} (scheme://[user]:{SECRET_PLACEHOLDER}@host...), {SECRET_PLACEHOLDER} nowhere else");
                        }
                        Some(t.clone())
                    }
                    Some(_) => bail!("settings.{key}: `value` must be a string"),
                };
                FileValue::Secret { name, template }
            }
            _ if s.secret == SecretUse::Required => {
                bail!("settings.{key} is a secret: write {{ secret = \"<name>\" }} and the value in the [secrets] entry's file (never in this file)")
            }
            _ => {
                let rendered = literal(s, v)?;
                if s.secret == SecretUse::Allowed && has_credentials(&rendered, s.kind == List) {
                    bail!("settings.{key} holds credentials: write {{ secret = \"<name>\" }} (the whole URL) or {{ secret = \"<name>\", value = \"redis://:{SECRET_PLACEHOLDER}@host:port\" }}");
                }
                FileValue::Plain(rendered)
            }
        };
        out.insert(s.env, value);
    }
    Ok(out)
}

/// A secret's value by its `[secrets]` name.
pub type Resolve<'a> = &'a dyn Fn(&str) -> Result<String>;

/// The `[settings]` lines of an export and the secrets they name (`[secrets]` name, variable).
pub type ExportLines = (Vec<String>, Vec<(String, String)>);

/// What a setting that is a whole secret stands for when the secrets are not read
/// (`--check-config --secrets=skip`): a value of the variable's form for the secrets other
/// settings require (the relay and forwarding secrets, the Flexa key), else nothing (the
/// variable unset: keys, the signing seed, store URLs).
pub fn skipped_value(env: &str) -> Option<&'static str> {
    match env {
        "RELAY_SECRET" | "RELAY_SECRETS" | "WRITE_FORWARD_SECRETS" => {
            Some("skipped=secret-not-read")
        }
        "REPLAY_WRITE_FORWARD_SECRET" | "FLEXA_PUBLISHABLE_KEY" => Some("secret-not-read"),
        _ => None,
    }
}

/// The variables `values` stand for. `resolve` gives a secret's value; `None` (the secrets are
/// not read): a setting that is a whole secret is [`skipped_value`] (or left out) and a
/// template gets `placeholder`. A template's secret is the password itself, percent-encoded
/// into the URL ([`encode_password`]).
pub fn render(
    values: &BTreeMap<&'static str, FileValue>,
    resolve: Option<Resolve<'_>>,
    placeholder: &str,
) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for (env, v) in values {
        let rendered = match v {
            FileValue::Plain(p) => p.clone(),
            FileValue::Secret { name, template } => {
                let secret = match resolve {
                    Some(resolve) => resolve(name)?,
                    None if template.is_none() => match skipped_value(env) {
                        Some(v) => v.to_string(),
                        None => continue,
                    },
                    None => placeholder.to_string(),
                };
                match template {
                    None => secret,
                    Some(t) => t.replace(SECRET_PLACEHOLDER, &encode_password(&secret)),
                }
            }
        };
        out.insert(env.to_string(), rendered);
    }
    Ok(out)
}

/// What the export makes of a variable's value.
#[derive(Clone, PartialEq)]
pub enum Exported {
    /// Left out: the value means the default (blank, or a boolean value its parser ignores).
    Omit,
    /// A typed literal.
    Literal(Value),
    /// A secret reference to the variable itself.
    Secret,
}

impl std::fmt::Debug for Exported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Omit => f.write_str("Omit"),
            Self::Literal(_) => f.write_str("Literal"),
            Self::Secret => f.write_str("Secret"),
        }
    }
}

/// How the parser of a variable reads a blank value (empty or white space only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Blank {
    /// As unset, whatever the white space.
    Unset,
    /// Empty as unset; white space is a value (an error or another meaning).
    EmptyOnly,
    /// Not as unset (an error, or a different meaning: `RELAY_SECRET` set at all).
    Value,
}

fn blank(env: &str) -> Blank {
    match env {
        // `.parse()?` untrimmed, or trimmed without a default for a blank value.
        "PORT"
        | "HPKE_KEY_ID"
        | "LWD_TIMEOUT_SECS"
        | "LONG_POLL_MAX_INITIAL_SILENCE_SECS"
        | "LONG_POLL_IDLE_SECS"
        | "SSE_KEEPALIVE_SECS"
        | "HEADER_READ_TIMEOUT_SECS" => Blank::Value,
        // Set at all counts: both set is an error.
        "RELAY_SECRET" | "RELAY_SECRETS" => Blank::Value,
        // Empty filtered out, white space kept (and refused when decoded).
        "HPKE_KEYS" | "HPKE_PRIVATE_KEY" | "CONFIGS_SIGNING_SEED_HEX" => Blank::EmptyOnly,
        _ => Blank::Unset,
    }
}

/// The file value of the variable of `s` set to `raw`, read exactly as the gateway reads `raw`:
/// a value the file cannot stand for exactly is an error naming the variable (never the value).
/// A blank value: a string or a list keeps it as written; another setting is left out where
/// its parser takes it as unset, else the export refuses it.
pub fn export_value(s: &Setting, raw: &str) -> Result<Exported> {
    let env = s.env;
    let is_blank = raw.trim().is_empty();
    if is_blank && (s.secret == SecretUse::Required || !matches!(s.kind, Str | List)) {
        return match (blank(env), raw.is_empty()) {
            (Blank::Unset, _) | (Blank::EmptyOnly, true) => Ok(Exported::Omit),
            _ => bail!("{env} is set but blank, which the gateway does not read as unset: unset it or give it a value before exporting"),
        };
    }
    if s.secret == SecretUse::Required {
        return Ok(Exported::Secret);
    }
    if s.secret == SecretUse::Allowed && has_credentials(raw, s.kind == List) {
        return Ok(Exported::Secret);
    }
    Ok(match s.kind {
        Str => Exported::Literal(Value::String(raw.to_string())),
        List => Exported::Literal(Value::Array(
            raw.split(',')
                .map(|e| Value::String(e.to_string()))
                .collect(),
        )),
        Int => match raw.parse::<i64>() {
            Ok(n) if n >= 0 && n.to_string() == raw => Exported::Literal(Value::Integer(n)),
            _ => bail!("{env} is not written as a plain non-negative integer: fix the variable before exporting it"),
        },
        Float => match raw.parse::<f64>() {
            Ok(f) if f.is_finite() => Exported::Literal(Value::Float(f)),
            _ => bail!("{env} is not a finite number: fix the variable before exporting it"),
        },
        Bool(flag) => {
            let b = match flag {
                Flag::OneOrTrue => Some(crate::config::flag_on(raw)),
                Flag::OneTrueOn => Some(crate::lwd::connection_pool_on(raw)),
                Flag::Lenient => {
                    let (t, f) = (
                        crate::origin::parse_flag(Some(raw), true),
                        crate::origin::parse_flag(Some(raw), false),
                    );
                    (t == f).then_some(t)
                }
                Flag::Strict => Some(
                    crate::prefetch::parse_flag(env, Some(raw), false)
                        .map_err(|_| anyhow!("{env} must be 0 or 1: fix the variable before exporting it"))?,
                ),
            };
            match b {
                Some(b) => Exported::Literal(Value::Boolean(b)),
                None => Exported::Omit,
            }
        }
    })
}

/// The value of the variable of `s` the gateway reads when the environment holds `raw`, written
/// as the file renders it (`None`: the default): the form compared and digested.
pub fn normalized(s: &Setting, raw: &str) -> Result<Option<String>> {
    Ok(match export_value(s, raw)? {
        Exported::Omit => None,
        Exported::Secret => Some(raw.to_string()),
        Exported::Literal(v) => Some(literal(s, &v)?),
    })
}

/// The settings of the environment `env` (set ones only, normalized; a value that cannot be is
/// kept as given, so it differs from every file).
pub fn env_settings(env: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    SETTINGS
        .iter()
        .filter_map(|s| {
            let raw = env.get(s.env)?;
            match normalized(s, raw) {
                Ok(v) => v.map(|v| (s.env.to_string(), v)),
                Err(_) => Some((s.env.to_string(), format!("\u{0}{raw}"))),
            }
        })
        .collect()
}

/// The first 16 hex digits of the SHA-256 of the tuning settings of `values` (variable ->
/// value as rendered): the same for a file and the environment it stands for. Secrets and
/// deployment settings are not part of it.
pub fn tuning_digest(values: &BTreeMap<String, String>) -> String {
    let tuning: BTreeMap<&str, &str> = values
        .iter()
        .filter(|(k, _)| setting(k).is_some_and(|s| s.class() == "tuning"))
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let json = serde_json::to_string(&tuning).unwrap_or_default();
    hex::encode(Sha256::digest(json.as_bytes()))[..16].to_string()
}

/// The keys at which two settings maps (variable -> value) differ, as file keys.
pub fn differing(a: &BTreeMap<String, String>, b: &BTreeMap<String, String>) -> Vec<String> {
    let mut keys: Vec<String> = a
        .keys()
        .chain(b.keys())
        .filter(|k| a.get(*k) != b.get(*k))
        .map(|k| format!("settings.{}", k.to_ascii_lowercase()))
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// A TOML basic string.
pub fn toml_str(v: &str) -> String {
    let mut s = String::with_capacity(v.len() + 2);
    s.push('"');
    for c in v.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                s.push_str(&format!("\\u{:04X}", c as u32))
            }
            c => s.push(c),
        }
    }
    s.push('"');
    s
}

/// A literal of the export as TOML (integers, numbers, booleans, strings, arrays of strings).
fn toml_value(v: &Value) -> String {
    match v {
        Value::Integer(n) => n.to_string(),
        // Debug keeps a fraction or an exponent, so the value stays a TOML float.
        Value::Float(f) => format!("{f:?}"),
        Value::Boolean(b) => b.to_string(),
        Value::String(s) => toml_str(s),
        Value::Array(items) => {
            let items: Vec<String> = items.iter().map(toml_value).collect();
            format!("[{}]", items.join(", "))
        }
        other => toml_str(&format!("{other:?}")),
    }
}

/// The `[settings]` lines of the variables of `env` that belong in `place` (in table order),
/// and the secrets they reference (`[secrets]` name, variable).
pub fn export_lines(env: &BTreeMap<String, String>, place: Place) -> Result<ExportLines> {
    let mut lines = Vec::new();
    let mut secrets = Vec::new();
    for s in SETTINGS.iter().filter(|s| s.place == place) {
        let Some(raw) = env.get(s.env) else {
            continue;
        };
        match export_value(s, raw)? {
            Exported::Omit => {}
            Exported::Literal(v) => lines.push(format!("{} = {}", s.key(), toml_value(&v))),
            Exported::Secret => {
                lines.push(format!(
                    "{} = {{ secret = {} }}",
                    s.key(),
                    toml_str(&s.key())
                ));
                secrets.push((s.key(), s.env.to_string()));
            }
        }
    }
    Ok((lines, secrets))
}

/// Every parsed setting of the variables in force, comparable: the `Config` fields and the
/// settings each module parses at startup (`ERR` for a parser that refuses). Holds secret
/// values in memory: for comparisons only, never print it.
#[allow(dead_code)] // the fuzz target and the tests
pub fn parsed_view() -> BTreeMap<String, String> {
    fn put<T: std::fmt::Debug>(out: &mut BTreeMap<String, String>, name: &str, r: Result<T>) {
        out.insert(
            name.to_string(),
            match r {
                Ok(v) => format!("{v:?}"),
                Err(_) => "ERR".to_string(),
            },
        );
    }
    let mut out = BTreeMap::new();
    let config = crate::config::Config::from_env();
    let lwd_addr = config
        .as_ref()
        .map(|c| c.lwd_addr.clone())
        .unwrap_or_else(|_| "localhost:9067".to_string());
    put(
        &mut out,
        "config",
        config.map(|c| {
            let relay: Vec<(String, String)> = c
                .relay_secrets
                .iter()
                .map(|r| (r.name.clone(), hex::encode(r.digest)))
                .collect();
            vec![
                format!("port={}", c.port),
                format!("lwd_addr={}", c.lwd_addr),
                format!("mode={}", c.mode),
                format!("relay_secrets={relay:?}"),
                format!(
                    "allow_unauthenticated_relay={}",
                    c.allow_unauthenticated_relay
                ),
                format!("hpke_private_key={:?}", c.hpke_private_key),
                format!("hpke_key_id={}", c.hpke_key_id),
                format!("hpke_keys={:?}", c.hpke_keys),
                format!("lwd_timeout_secs={}", c.lwd_timeout_secs),
                format!(
                    "long_poll={} {}",
                    c.long_poll_max_initial_silence_secs, c.long_poll_idle_secs
                ),
                format!("sse_keepalive_secs={}", c.sse_keepalive_secs),
                format!("redis_url={}", c.redis_url),
                format!("redis_security_url={}", c.redis_security_url),
                format!(
                    "max_upstream_response_bytes={}",
                    c.max_upstream_response_bytes
                ),
                format!("max_inflight_upstream={}", c.max_inflight_upstream),
                format!("max_inflight_per_backend={}", c.max_inflight_per_backend),
                format!(
                    "max_inflight_lwd={} {}",
                    c.max_inflight_lwd, c.max_inflight_lwd_heavy
                ),
                format!("lwd_heavy_block_range={}", c.lwd_heavy_block_range),
                format!("max_block_range={}", c.max_block_range),
                format!(
                    "lwd_permit={} {}",
                    c.lwd_permit_wait_ms, c.lwd_permit_max_waiters
                ),
                format!("redis_op_timeout_ms={}", c.redis_op_timeout_ms),
                format!("max_cache_get_concurrency={}", c.max_cache_get_concurrency),
                format!(
                    "large_response={} {}",
                    c.max_large_response_concurrency, c.large_response_threshold
                ),
                format!("network={}", c.network),
                format!("log_outer_header_names={}", c.log_outer_header_names),
                format!("gateway_hosts={:?}", c.gateway_hosts),
                format!("configs_signing_seed={:?}", c.configs_signing_seed),
                format!("chunk={} {}", c.chunk_size, c.chunk_flush_ms),
                format!("flexa_publishable_key={:?}", c.flexa_publishable_key),
                format!(
                    "backends={:?}",
                    c.backends.iter().collect::<BTreeMap<_, _>>()
                ),
                format!("host_list={:?}", c.host_list),
                format!(
                    "relay_secret_on_key_config={:?}",
                    c.relay_secret_on_key_config
                ),
            ]
        }),
    );
    put(
        &mut out,
        "origin",
        crate::origin::OriginSettings::from_env(),
    );
    put(
        &mut out,
        "hpke_accept_only",
        crate::config::hpke_accept_only_keys_from_env(),
    );
    put(&mut out, "padding", crate::padding::Mode::from_env());
    put(
        &mut out,
        "lwd_deadlines",
        crate::lwd::LwdDeadlines::from_env(),
    );
    put(
        &mut out,
        "freshness",
        crate::freshness::Settings::from_env(crate::cache::REPLAY_TTL_SECS),
    );
    put(
        &mut out,
        "lwd_endpoints",
        crate::lwd_endpoints::Settings::from_env(&lwd_addr),
    );
    put(
        &mut out,
        "healthz_lwd",
        crate::health::LwdErrorPolicy::from_env(),
    );
    put(
        &mut out,
        "write_wait",
        crate::cache::WriteWaitConfig::from_env(),
    );
    put(
        &mut out,
        "peer_wait",
        crate::cache::WriteWaitConfig::peer_from_env(),
    );
    put(&mut out, "wait_conns", crate::cache::wait_conns_from_env());
    put(
        &mut out,
        "local_aof",
        crate::cache::LocalAofConfig::from_env(),
    );
    put(
        &mut out,
        "startup_stores_wait",
        crate::cache::startup_stores_wait_from_env(),
    );
    put(
        &mut out,
        "prefetch",
        crate::prefetch::PrefetchConfig::from_env(),
    );
    put(
        &mut out,
        "write_forward",
        crate::write_forward::ForwardConfig::from_env(),
    );
    put(
        &mut out,
        "write_forward_receiver",
        crate::write_forward::ReceiverConfig::from_env().map(|r| r.map(|r| format!("{r:?}"))),
    );
    put(
        &mut out,
        "internal_bind_addr",
        crate::server::internal_bind_addr_from_env(),
    );
    put(
        &mut out,
        "header_read_timeout",
        crate::server::header_read_timeout_from_env(),
    );
    put(&mut out, "max_inflight_requests", max_inflight_requests());
    put(&mut out, "chain_tip_stale_after", chain_tip_stale_after());
    put(&mut out, "pinned_range", check_pinned_range());
    // The variables the serving process reads in place (main), as its parsers read them.
    for env in [
        "CACHE_KEY_BACKEND",
        "REDIS_PINNED_URL",
        "PINNED_TREESTATE_RANGE",
        "REDIS_PINNED_WRITE_URL",
        "PERMANENT_REDIS_URL",
        "RUST_LOG",
    ] {
        out.insert(
            format!("var.{env}"),
            format!("{:?}", crate::config_source::var(env).ok()),
        );
    }
    for env in [
        "LOCAL_CACHE_BYTES",
        "LOCAL_CACHE_MAX_ENTRY_BYTES",
        "PERMANENT_MIN_HEIGHT",
        "PERMANENT_OP_TIMEOUT_MS",
        "PINNED_BACKFILL_WORKERS",
    ] {
        let v = crate::config_source::var(env)
            .ok()
            .and_then(|v| v.parse::<u64>().ok());
        out.insert(format!("var.{env}"), format!("{v:?}"));
    }
    out
}

/// The export round trip of the settings of `env` (variable -> value): [`export_lines`] of both
/// places, parsed back as TOML ([`parse_table`]) and rendered with the secrets read from `env`,
/// is read by the gateway's own parsers ([`parsed_view`]) exactly as `env` itself. `Ok(false)`:
/// `env` holds a value the files cannot stand for (the export refuses it).
#[allow(dead_code)] // the fuzz target and the tests
pub fn check_round_trip(env: &BTreeMap<String, String>) -> std::result::Result<bool, String> {
    let mut text = String::new();
    let mut secrets: BTreeMap<String, String> = BTreeMap::new();
    for place in [Place::Common, Place::Host] {
        let Ok((lines, refs)) = export_lines(env, place) else {
            return Ok(false);
        };
        for l in lines {
            text.push_str(&l);
            text.push('\n');
        }
        secrets.extend(refs);
    }
    let table: toml::Table = toml::from_str(&text).map_err(|e| format!("{e}\n{text}"))?;
    let values = parse_table(&table).map_err(|e| format!("{e:#}\n{text}"))?;
    let resolve = |name: &str| -> Result<String> {
        secrets
            .get(name)
            .and_then(|var| env.get(var))
            .cloned()
            .ok_or_else(|| anyhow!("no value for secret '{name}'"))
    };
    let rendered = render(&values, Some(&resolve), "").map_err(|e| format!("{e:#}"))?;
    let raw: BTreeMap<String, String> = env
        .iter()
        .filter(|(k, _)| setting(k).is_some())
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let from_env = crate::config_source::with_config(BTreeMap::new(), raw, parsed_view);
    let from_files = crate::config_source::with_config(BTreeMap::new(), rendered, parsed_view);
    if from_env != from_files {
        let keys: Vec<&String> = from_env
            .keys()
            .filter(|k| from_env.get(*k) != from_files.get(*k))
            .collect();
        return Err(format!(
            "the files are read differently at {keys:?}\n{text}"
        ));
    }
    Ok(true)
}

/// The startup checks of a serving process beyond the parsers: relay secrets, keys, stores and
/// the signing seed in `ohttp` mode. `omitted`: whole-secret settings left out
/// (`--check-config --secrets=skip`), whose checks are skipped. `keys`: also decode the HPKE
/// keys and the signing seed (the serving process does that itself when it loads them).
pub fn startup_checks(config: &crate::config::Config, omitted: &[&str], keys: bool) -> Result<()> {
    let known = |envs: &[&str]| envs.iter().all(|e| !omitted.contains(e));
    let ohttp = config.mode == "ohttp";
    if known(&["RELAY_SECRET", "RELAY_SECRETS"]) {
        // Fail-closed: require relay auth unless explicitly disabled
        if ohttp && config.relay_secrets.is_empty() && !config.allow_unauthenticated_relay {
            bail!(
                "RELAY_SECRET (or RELAY_SECRETS) is required in OHTTP mode unless ALLOW_UNAUTHENTICATED_RELAY=1. \
                 Configure a high-entropy secret to authenticate the relay."
            );
        }
        if config.relay_secret_on_key_config == crate::config::RelaySecretOnKeyConfig::Require
            && config.relay_secrets.is_empty()
        {
            bail!(
                "RELAY_SECRET_ON_KEY_CONFIG=require needs RELAY_SECRET (or RELAY_SECRETS): without a relay \
                 secret no request could fetch the key configuration."
            );
        }
    }
    if !ohttp {
        return Ok(());
    }
    if known(&["HPKE_KEYS", "HPKE_PRIVATE_KEY", "HPKE_ACCEPT_ONLY_KEYS"]) {
        // Error if no HPKE key configured in OHTTP mode, instead of just warning and continuing
        if config.hpke_keys.is_empty() && config.hpke_private_key.is_none() {
            bail!(
                "HPKE_KEYS (or HPKE_PRIVATE_KEY) is required in OHTTP mode. \
                 Generate a key: openssl rand -hex 32"
            );
        }
        if keys {
            crate::hpke::KeyState::new(config)?;
        }
    }
    // OHTTP mode requires both Redis URLs: replay protection (the security Redis) lives in the
    // response cache module, and without it every request would be refused with 503 for good.
    if known(&["REDIS_URL", "REDIS_SECURITY_URL"])
        && (config.redis_security_url.is_empty() || config.redis_url.is_empty())
    {
        bail!(
            "REDIS_URL and REDIS_SECURITY_URL are required in OHTTP mode (replay protection fails \
             closed without them). REDIS_SECURITY_URL: a Redis with maxmemory-policy noeviction."
        );
    }
    if keys && known(&["CONFIGS_SIGNING_SEED_HEX"]) {
        if let Some(seed) = &config.configs_signing_seed {
            crate::signing::SigningState::new(seed, config.network.clone())
                .map_err(|e| anyhow!("Failed to initialize signing key in OHTTP mode: {e}"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_consistent() {
        let mut seen = std::collections::BTreeSet::new();
        for s in SETTINGS {
            assert!(seen.insert(s.env), "{} twice", s.env);
            assert!(!POLICY_ENV_KEYS.contains(&s.env), "{} is policy", s.env);
            assert_eq!(by_key(&s.key()), Some(s));
            if s.secret == SecretUse::Required {
                assert_eq!(s.kind, Str, "{}", s.env);
            }
        }
        for k in BOOTSTRAP_ENV_KEYS.iter().chain(BACKFILL_ENV_KEYS) {
            assert!(setting(k).is_none() && !POLICY_ENV_KEYS.contains(k), "{k}");
        }
        assert!(by_key("LWD_ADDR").is_none());
    }

    fn table(text: &str) -> toml::Table {
        toml::from_str(text).unwrap()
    }

    #[test]
    fn values_are_typed_and_rendered_as_the_variable() {
        let t = table(
            r#"
            lwd_timeout_secs = 80
            healthz_lwd_error_ratio = 0.25
            lwd_connection_pool = true
            prefetch_tip = false
            lwd_addr = "lwd.example:9067"
            replay_peer_urls = ["redis://a.example:6379", "rediss://b.example:6380"]
            redis_url = { secret = "cache", value = "redis://:{secret}@cache.example:6379" }
            hpke_keys = { secret = "hpke" }
            "#,
        );
        let values = parse_table(&t).unwrap();
        let resolve = |n: &str| Ok(format!("<{n}>"));
        let r = render(&values, Some(&resolve), "x").unwrap();
        assert_eq!(r["LWD_TIMEOUT_SECS"], "80");
        assert_eq!(r["HEALTHZ_LWD_ERROR_RATIO"], "0.25");
        assert_eq!(r["LWD_CONNECTION_POOL"], "1");
        assert_eq!(r["PREFETCH_TIP"], "0");
        assert_eq!(r["LWD_ADDR"], "lwd.example:9067");
        assert_eq!(
            r["REPLAY_PEER_URLS"],
            "redis://a.example:6379,rediss://b.example:6380"
        );
        assert_eq!(r["REDIS_URL"], "redis://:%3Ccache%3E@cache.example:6379");
        assert_eq!(r["HPKE_KEYS"], "<hpke>");
        // Not read: a whole secret is left out, a template gets the placeholder.
        let r = render(&values, None, "not-read").unwrap();
        assert!(!r.contains_key("HPKE_KEYS"));
        assert_eq!(r["REDIS_URL"], "redis://:not-read@cache.example:6379");
    }

    #[test]
    fn a_file_refuses_what_the_variable_cannot_be() {
        for (text, expected) in [
            ("color = 1", "unknown setting `color`"),
            ("backends = \"a\"", "is a policy variable"),
            (
                "lwd_timeout_secs = \"80\"",
                "must be a non-negative integer",
            ),
            ("lwd_timeout_secs = -1", "must be a non-negative integer"),
            ("prefetch_tip = 1", "must be true or false"),
            (
                "lwd_addr = { secret = \"a\" }",
                "cannot be a secret reference",
            ),
            ("hpke_keys = \"1:00\"", "is a secret"),
            (
                "redis_url = \"redis://:pw@cache.example:6379\"",
                "holds credentials",
            ),
            (
                "replay_peer_urls = [\"redis://u:pw@a.example\"]",
                "holds credentials",
            ),
            ("replay_peer_urls = [\"a,b\"]", "holds a ','"),
            (
                "redis_url = { secret = \"a\", value = \"redis://x\" }",
                "whole password",
            ),
            (
                "redis_url = { secret = \"a\", value = \"redis://u:pw@x/{secret}\" }",
                "whole password",
            ),
            (
                "redis_url = { secret = \"a\", value = \"redis://:{secret}x@cache.example\" }",
                "whole password",
            ),
            (
                "redis_url = { secret = \"a\", value = \"redis://{secret}@cache.example\" }",
                "whole password",
            ),
            (
                "redis_url = { secret = \"a\", value = \"redis://:{secret}@a,redis://:pw@b\" }",
                "whole password",
            ),
            (
                "redis_url = { secret = \"a\", other = 1 }",
                "unknown field `other`",
            ),
            (
                "replay_peer_urls = { secret = \"a\", value = \"{secret}\" }",
                "only a store URL",
            ),
            (
                "relay_secrets = { secret = \"a\", value = \"edge={secret}\" }",
                "only a store URL",
            ),
            // A password the store client would read, whatever hides it.
            (
                "redis_url = \"redis://:p\\tw@cache.example\"",
                "holds credentials",
            ),
            (
                "redis_url = \"redis://:pa/ss@cache.example\"",
                "holds credentials",
            ),
            (
                "redis_url = \"redis://:pa?ss@cache.example\"",
                "holds credentials",
            ),
            (
                "redis_url = \"redis://:pa#ss@cache.example\"",
                "holds credentials",
            ),
            (
                "redis_url = \"redis://u\\t:pw@cache.example\"",
                "holds credentials",
            ),
            (
                "redis_url = \"redis:/:pw@cache.example\"",
                "holds credentials",
            ),
            ("LWD_TIMEOUT_SECS = 1", "unknown setting"),
        ] {
            let e = format!("{:#}", parse_table(&table(text)).unwrap_err());
            assert!(e.contains(expected), "{text}: {e}");
            assert!(!e.contains("pw"), "{text}: {e}");
        }
    }

    #[test]
    fn one_url_is_read_whole_and_a_list_per_entry() {
        for text in [
            "redis_url = \"redis://:pa,ss@cache.example\"",
            "redis_url = \"redis://cache.example,redis://:pw@b.example\"",
            "replay_peer_urls = [\"redis://a.example\", \"redis://:pw@b.example\"]",
        ] {
            let e = format!("{:#}", parse_table(&table(text)).unwrap_err());
            assert!(e.contains("holds credentials"), "{text}: {e}");
        }
        assert_eq!(
            export_value(
                setting("REDIS_URL").unwrap(),
                "redis://:pa,ss@cache.example"
            )
            .unwrap(),
            Exported::Secret
        );
    }

    #[test]
    fn a_user_without_a_password_is_no_credential_and_templates_encode() {
        let values = parse_table(&table(
            "redis_url = \"redis://user@cache.example:6379\"\nredis_security_url = { secret = \"p\", value = \"rediss://user:{secret}@security.example:6380/0\" }",
        ))
        .unwrap();
        let resolve = |_: &str| Ok("p@s:/?#% w".to_string());
        let r = render(&values, Some(&resolve), "x").unwrap();
        assert_eq!(r["REDIS_URL"], "redis://user@cache.example:6379");
        assert_eq!(
            r["REDIS_SECURITY_URL"],
            "rediss://user:p%40s%3A%2F%3F%23%25%20w@security.example:6380/0"
        );
        assert_eq!(encode_password("Ab-._~9"), "Ab-._~9");
    }

    #[test]
    fn the_export_reads_each_value_as_its_parser_does() {
        let s = |env| setting(env).unwrap();
        let cases: &[(&str, &str, Option<&str>)] = &[
            ("LWD_TIMEOUT_SECS", "80", Some("80")),
            ("MAX_BLOCK_RANGE", "", None),
            ("HPKE_PRIVATE_KEY", "", None),
            ("HEALTHZ_LWD_ERROR_RATIO", "0.20", Some("0.2")),
            ("ALLOW_UNAUTHENTICATED_RELAY", "TRUE", Some("1")),
            ("ALLOW_UNAUTHENTICATED_RELAY", " 1", Some("0")),
            ("LWD_CONNECTION_POOL", " On ", Some("1")),
            ("LWD_CONNECTION_POOL", "yes", Some("0")),
            ("REPLAY_PEER_FAIL_CLOSED", "False", Some("0")),
            ("REPLAY_PEER_FAIL_CLOSED", "maybe", None),
            ("PREFETCH_TIP", "true", Some("1")),
            ("LWD_ADDR", "", Some("")),
            ("REPLAY_PEER_URLS", "", Some("")),
            (
                "REDIS_URL",
                "redis://:pw@cache.example:6379",
                Some("redis://:pw@cache.example:6379"),
            ),
            ("HPKE_KEYS", "1:00", Some("1:00")),
            ("HPKE_ACCEPT_ONLY_KEYS", " ", None),
        ];
        for (env, raw, expected) in cases {
            assert_eq!(
                normalized(s(env), raw).unwrap().as_deref(),
                *expected,
                "{env}={raw:?}"
            );
        }
        for (env, raw) in [
            ("LWD_TIMEOUT_SECS", "+80"),
            ("LWD_TIMEOUT_SECS", "080"),
            ("LWD_TIMEOUT_SECS", " 80"),
            ("LWD_TIMEOUT_SECS", "-1"),
            ("HEALTHZ_LWD_ERROR_RATIO", "NaN"),
            ("PREFETCH_TIP", "yes"),
            // Blank where the parser does not read it as unset.
            ("LWD_TIMEOUT_SECS", ""),
            ("PORT", " "),
            ("RELAY_SECRET", ""),
            ("HPKE_PRIVATE_KEY", " "),
            ("CONFIGS_SIGNING_SEED_HEX", "\t"),
        ] {
            let e = format!("{:#}", normalized(s(env), raw).unwrap_err());
            assert!(e.contains(env), "{e}");
        }
        assert_eq!(
            export_value(s("REDIS_URL"), "redis://cache.example:6379").unwrap(),
            Exported::Literal(Value::String("redis://cache.example:6379".into()))
        );
        assert_eq!(
            export_value(s("REDIS_URL"), "redis://:pw@cache.example:6379").unwrap(),
            Exported::Secret
        );
    }

    #[test]
    fn the_export_round_trips() {
        let env: BTreeMap<String, String> = [
            ("LWD_TIMEOUT_SECS", "80"),
            ("HEALTHZ_LWD_ERROR_RATIO", "0.3"),
            ("LWD_CONNECTION_POOL", "On"),
            ("REPLAY_PEER_FAIL_CLOSED", "maybe"),
            ("RUST_LOG", "info,a=\"b\"\u{1}"),
            (
                "REPLAY_PEER_URLS",
                "redis://a.example, rediss://:pw@b.example,",
            ),
            ("REDIS_URL", "redis://cache.example:6379"),
            ("HPKE_KEYS", "1:00"),
            ("PATH", "/bin"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        assert_eq!(check_round_trip(&env), Ok(true));
        let mut bad = env.clone();
        bad.insert("LWD_TIMEOUT_SECS".into(), "080".into());
        assert_eq!(check_round_trip(&bad), Ok(false));
    }

    #[test]
    fn the_tuning_digest_covers_tuning_only() {
        let a: BTreeMap<String, String> = [
            ("LWD_TIMEOUT_SECS".to_string(), "80".to_string()),
            ("LWD_ADDR".to_string(), "a:1".to_string()),
            ("HPKE_KEYS".to_string(), "1:00".to_string()),
        ]
        .into();
        let mut b = a.clone();
        b.insert("LWD_ADDR".into(), "b:1".into());
        b.insert("HPKE_KEYS".into(), "2:00".into());
        assert_eq!(tuning_digest(&a), tuning_digest(&b));
        b.insert("LWD_TIMEOUT_SECS".into(), "81".into());
        assert_ne!(tuning_digest(&a), tuning_digest(&b));
        assert_eq!(tuning_digest(&a).len(), 16);
    }
}

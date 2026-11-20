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

//! The settings in the configuration files (`[settings]` of the common file and the host file)
//! against the environment they stand for:
//!
//! - every parsed setting (the `Config` struct and the module-level settings) reads the same
//!   from the two files `--export-config --host` writes as from the environment, on both
//!   characterisation fixtures and on `fixtures/settings/full.vars` (every setting set);
//! - every boolean variable is read the same in each spelling;
//! - every variable is read through `config_source::var` and classified;
//! - the binary: `CONFIG_SOURCE=file` with an empty environment except the source and the two
//!   paths, `compare` of the settings, `--check-config` of both files, `--export-config --host`;
//!   no secret value in any output.
//!
//! Every subprocess runs with a deadline and its output in files (no pipe can fill).

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use zodl_ohttp_gateway::config::Config;
use zodl_ohttp_gateway::config_source::{self, Secrets};
use zodl_ohttp_gateway::settings::{self, Kind, SETTINGS};
use zodl_ohttp_integrations::core::config::POLICY_ENV_KEYS;

/// The process environment is global: every test of this file holds this lock.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_vars(path: PathBuf) -> Vec<(String, String)> {
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

/// The three environments: both characterisation fixtures and every setting set.
fn fixtures() -> Vec<(&'static str, Vec<(String, String)>)> {
    let c = manifest().join("tests/fixtures/characterisation");
    // The policy fixtures with what an ohttp-mode gateway needs besides (fake key, test stores).
    let serving = |mut vars: Vec<(String, String)>| {
        for (k, v) in [
            ("RELAY_SECRETS", "edge=relay-fixture-secret".to_string()),
            ("HPKE_KEYS", format!("1:{}", "5a".repeat(32))),
            ("REDIS_URL", "redis://cache.example:6379".to_string()),
            (
                "REDIS_SECURITY_URL",
                "redis://security.example:6379".to_string(),
            ),
        ] {
            vars.push((k.to_string(), v));
        }
        vars
    };
    vec![
        ("mainnet", serving(read_vars(c.join("mainnet.vars")))),
        ("testnet", serving(read_vars(c.join("testnet.vars")))),
        (
            "full",
            read_vars(manifest().join("tests/fixtures/settings/full.vars")),
        ),
    ]
}

/// Process variables kept by [`apply_env`]: none is a policy variable or a setting.
fn keep_var(name: &str) -> bool {
    if settings::setting(name).is_some() || POLICY_ENV_KEYS.contains(&name) {
        return false;
    }
    matches!(
        name,
        "PATH" | "HOME" | "TMPDIR" | "TMP" | "TEMP" | "USER" | "LANG" | "TERM" | "CI"
    ) || ["CARGO", "RUST", "LC_", "LD_", "DYLD_"]
        .iter()
        .any(|p| name.starts_with(p))
}

/// Replace the environment by `vars` (and the few process variables).
fn apply_env(vars: &[(String, String)]) {
    for (name, _) in std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v)))
        .filter(|(k, _)| !keep_var(k))
    {
        std::env::remove_var(name);
    }
    for (k, v) in vars {
        std::env::set_var(k, v);
    }
}

fn process_env() -> BTreeMap<String, String> {
    std::env::vars().collect()
}

/// Every parsed setting of the variables in force, comparable (`ERR` for a parser that refuses).
fn parsed() -> BTreeMap<String, String> {
    fn put<T: std::fmt::Debug>(
        out: &mut BTreeMap<String, String>,
        name: &str,
        r: anyhow::Result<T>,
    ) {
        out.insert(
            name.to_string(),
            match r {
                Ok(v) => format!("{v:?}"),
                Err(e) => format!("ERR {e:#}"),
            },
        );
    }
    let mut out = BTreeMap::new();
    let config = Config::from_env().map(|c| {
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
                "long_poll_max_initial_silence_secs={}",
                c.long_poll_max_initial_silence_secs
            ),
            format!("long_poll_idle_secs={}", c.long_poll_idle_secs),
            format!("sse_keepalive_secs={}", c.sse_keepalive_secs),
            format!("redis_url={}", c.redis_url),
            format!("redis_security_url={}", c.redis_security_url),
            format!(
                "max_upstream_response_bytes={}",
                c.max_upstream_response_bytes
            ),
            format!("max_inflight_upstream={}", c.max_inflight_upstream),
            format!("max_inflight_per_backend={}", c.max_inflight_per_backend),
            format!("max_inflight_lwd={}", c.max_inflight_lwd),
            format!("max_inflight_lwd_heavy={}", c.max_inflight_lwd_heavy),
            format!("lwd_heavy_block_range={}", c.lwd_heavy_block_range),
            format!("max_block_range={}", c.max_block_range),
            format!("lwd_permit_wait_ms={}", c.lwd_permit_wait_ms),
            format!("lwd_permit_max_waiters={}", c.lwd_permit_max_waiters),
            format!("redis_op_timeout_ms={}", c.redis_op_timeout_ms),
            format!("max_cache_get_concurrency={}", c.max_cache_get_concurrency),
            format!(
                "max_large_response_concurrency={}",
                c.max_large_response_concurrency
            ),
            format!("large_response_threshold={}", c.large_response_threshold),
            format!("network={}", c.network),
            format!("log_outer_header_names={}", c.log_outer_header_names),
            format!("gateway_hosts={:?}", c.gateway_hosts),
            format!("configs_signing_seed={:?}", c.configs_signing_seed),
            format!("chunk_size={}", c.chunk_size),
            format!("chunk_flush_ms={}", c.chunk_flush_ms),
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
    });
    let lwd_addr = config
        .as_ref()
        .ok()
        .and_then(|c| c.iter().find_map(|l| l.strip_prefix("lwd_addr=")))
        .unwrap_or("localhost:9067")
        .to_string();
    put(&mut out, "config", config);
    put(
        &mut out,
        "origin",
        zodl_ohttp_gateway::origin::OriginSettings::from_env(),
    );
    put(
        &mut out,
        "hpke_accept_only",
        zodl_ohttp_gateway::config::hpke_accept_only_keys_from_env(),
    );
    put(
        &mut out,
        "padding",
        zodl_ohttp_gateway::padding::Mode::from_env(),
    );
    put(
        &mut out,
        "lwd_deadlines",
        zodl_ohttp_gateway::lwd::LwdDeadlines::from_env(),
    );
    put(
        &mut out,
        "freshness",
        zodl_ohttp_gateway::freshness::Settings::from_env(
            zodl_ohttp_gateway::cache::REPLAY_TTL_SECS,
        ),
    );
    put(
        &mut out,
        "lwd_endpoints",
        zodl_ohttp_gateway::lwd_endpoints::Settings::from_env(&lwd_addr),
    );
    put(
        &mut out,
        "healthz_lwd",
        zodl_ohttp_gateway::health::LwdErrorPolicy::from_env(),
    );
    put(
        &mut out,
        "write_wait",
        zodl_ohttp_gateway::cache::WriteWaitConfig::from_env(),
    );
    put(
        &mut out,
        "peer_wait",
        zodl_ohttp_gateway::cache::WriteWaitConfig::peer_from_env(),
    );
    put(
        &mut out,
        "wait_conns",
        zodl_ohttp_gateway::cache::wait_conns_from_env(),
    );
    put(
        &mut out,
        "local_aof",
        zodl_ohttp_gateway::cache::LocalAofConfig::from_env(),
    );
    put(
        &mut out,
        "startup_stores_wait",
        zodl_ohttp_gateway::cache::startup_stores_wait_from_env(),
    );
    put(
        &mut out,
        "prefetch",
        zodl_ohttp_gateway::prefetch::PrefetchConfig::from_env(),
    );
    put(
        &mut out,
        "write_forward",
        zodl_ohttp_gateway::write_forward::ForwardConfig::from_env(),
    );
    put(
        &mut out,
        "write_forward_receiver",
        zodl_ohttp_gateway::write_forward::ReceiverConfig::from_env()
            .map(|r| r.map(|r| format!("{r:?}"))),
    );
    put(
        &mut out,
        "internal_bind_addr",
        zodl_ohttp_gateway::server::internal_bind_addr_from_env(),
    );
    put(
        &mut out,
        "header_read_timeout",
        zodl_ohttp_gateway::server::header_read_timeout_from_env(),
    );
    put(
        &mut out,
        "max_inflight_requests",
        settings::max_inflight_requests(),
    );
    put(
        &mut out,
        "chain_tip_stale_after",
        settings::chain_tip_stale_after(),
    );
    put(&mut out, "pinned_range", settings::check_pinned_range());
    out
}

/// [`parsed`] and every setting variable as its parser reads it (`var.<NAME>`, normalized: the
/// main-function parsers read these strings).
fn view() -> BTreeMap<String, String> {
    let mut out = parsed();
    for (k, v) in settings::parsed_view() {
        out.insert(format!("lib.{k}"), v);
    }
    out
}

/// A file in the temporary directory, removed on drop.
struct TempFile(PathBuf);

impl TempFile {
    fn new(name: &str, content: &str) -> Self {
        let path = Self::path_for(name);
        std::fs::write(&path, content).unwrap();
        Self(path)
    }

    fn path_for(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("config-settings-{}-{name}", std::process::id()))
    }

    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The two files of the environment in force (`--export-config --host`), and the values of the
/// secrets the policy maps to new variables (set in the environment: the files read them).
fn export_files(name: &str) -> (TempFile, TempFile, String, String) {
    let env = process_env();
    let (text, export) = config_source::export_checked(&env).unwrap();
    for s in export.secrets.iter().filter(|s| !s.found) {
        std::env::set_var(&s.env, export.secret_value(&s.name).unwrap());
    }
    let (common, host) = config_source::export_files(&env, &text, &export).unwrap();
    (
        TempFile::new(&format!("{name}-common.toml"), &common),
        TempFile::new(&format!("{name}-host.toml"), &host),
        common,
        host,
    )
}

/// The secret values of an environment (whole secrets, and the passwords of store URLs).
fn secret_values(vars: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for (k, v) in vars {
        match settings::setting(k) {
            Some(s) if s.secret == settings::SecretUse::Required => {
                for entry in v.split(',') {
                    let secret = entry.split_once(['=', ':']).map_or(entry, |(_, s)| s);
                    out.push(secret.to_string());
                }
            }
            Some(s) if s.secret == settings::SecretUse::Allowed => {
                for entry in v.split(',') {
                    if let Some((userinfo, _)) = entry
                        .split_once("://")
                        .and_then(|(_, rest)| rest.split_once('@'))
                    {
                        out.push(userinfo.trim_start_matches(':').to_string());
                    }
                }
            }
            _ if k == "BACKEND_HEADERS" => {
                for entry in v.split(',') {
                    if let Some((_, value)) =
                        entry.split_once('=').and_then(|(_, h)| h.split_once(':'))
                    {
                        out.push(value.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    out.retain(|s| s.len() >= 8);
    out
}

#[test]
fn every_setting_reads_the_same_from_the_files_as_from_the_environment() {
    let _guard = lock();
    for (name, vars) in fixtures() {
        apply_env(&vars);
        let (common, host, common_text, host_text) = export_files(name);
        let from_env = view();
        let loaded = config_source::load_files(common.path(), Some(host.path()), Secrets::Require)
            .unwrap_or_else(|e| panic!("{name}: {e:#}"));
        assert!(loaded.carries_settings);
        // The files stand for every setting of the environment, and nothing more.
        assert_eq!(
            settings::differing(&settings::env_settings(&process_env()), &loaded.settings),
            Vec::<String>::new(),
            "{name}"
        );
        let from_files =
            config_source::with_config(loaded.policy.clone(), loaded.settings.clone(), view);
        assert_eq!(from_files, from_env, "{name}");
        assert!(
            from_env.values().all(|v| !v.starts_with("ERR")),
            "{name}: {from_env:#?}"
        );
        // Each setting is in the file of its class.
        for s in SETTINGS {
            let line = format!("\n{} = ", s.key());
            if vars.iter().any(|(k, v)| k == s.env && !v.trim().is_empty()) {
                let (inside, other) = match s.place {
                    settings::Place::Common => (&common_text, &host_text),
                    settings::Place::Host => (&host_text, &common_text),
                };
                assert!(inside.contains(&line), "{name}: {} missing", s.env);
                assert!(
                    !other.contains(&line),
                    "{name}: {} in the wrong file",
                    s.env
                );
            }
        }
        // No secret value in either file.
        for secret in secret_values(&vars) {
            assert!(
                !common_text.contains(&secret) && !host_text.contains(&secret),
                "{name}: a secret value is in a file"
            );
        }
        // The tuning digest is the same from either side.
        assert_eq!(
            settings::tuning_digest(&settings::env_settings(&process_env())),
            settings::tuning_digest(&loaded.settings)
        );
        // The policy digest is the policy's only: the same as for the stage-1 file.
        assert_eq!(
            config_source::policy_digest(&loaded.file).unwrap(),
            config_source::env_digest(&config_source::env_policy()).unwrap()
        );
    }
}

#[test]
fn the_full_fixture_sets_every_setting() {
    let vars = read_vars(manifest().join("tests/fixtures/settings/full.vars"));
    for s in SETTINGS {
        // RELAY_SECRET and RELAY_SECRETS cannot both be set.
        if s.env == "RELAY_SECRET" {
            continue;
        }
        assert!(vars.iter().any(|(k, _)| k == s.env), "{} not set", s.env);
    }
}

#[test]
fn every_boolean_spelling_reads_the_same_from_a_file() {
    let _guard = lock();
    let base: Vec<(String, String)> = fixtures().remove(0).1;
    for s in SETTINGS.iter().filter(|s| matches!(s.kind, Kind::Bool(_))) {
        for raw in [
            "1", "0", "true", "false", "TRUE", "False", "on", "off", "yes", "", " 1", "maybe",
        ] {
            let mut env: BTreeMap<String, String> = base.iter().cloned().collect();
            env.insert(s.env.to_string(), raw.to_string());
            // The oracle is the gateway's own parsers on the original value.
            match settings::check_round_trip(&env) {
                Ok(true) => {}
                Ok(false) => {
                    assert!(settings::export_value(s, raw).is_err(), "{}={raw:?}", s.env);
                    let raw_env: BTreeMap<String, String> = env
                        .iter()
                        .filter(|(k, _)| settings::setting(k).is_some())
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();
                    let parsed =
                        config_source::with_config(BTreeMap::new(), raw_env, settings::parsed_view);
                    assert!(
                        parsed.values().any(|v| v == "ERR"),
                        "{}={raw:?}: the export refuses what the gateway reads",
                        s.env
                    );
                }
                Err(e) => panic!("{}={raw:?}: {e}", s.env),
            }
        }
    }
}

/// A blank value of every setting: left out only where its parser reads it as unset, kept
/// where it is a string, refused otherwise; the files are read as the environment.
#[test]
fn a_blank_value_of_every_setting_round_trips_or_is_refused() {
    let base: Vec<(String, String)> =
        read_vars(manifest().join("tests/fixtures/settings/full.vars"));
    for s in SETTINGS {
        for raw in ["", " ", "\t"] {
            let mut env: BTreeMap<String, String> = base.iter().cloned().collect();
            if s.env == "RELAY_SECRET" {
                env.remove("RELAY_SECRETS");
            }
            env.insert(s.env.to_string(), raw.to_string());
            if let Err(e) = settings::check_round_trip(&env) {
                panic!("{}={raw:?}: {e}", s.env);
            }
        }
    }
}

#[test]
fn a_key_in_both_files_and_a_policy_key_in_the_host_file_are_errors() {
    let _guard = lock();
    apply_env(&[]);
    let common = TempFile::new(
        "both-common.toml",
        "schema = 1\ngateway_hosts = [\"gw.example\"]\n[settings]\nlwd_timeout_secs = 70\ngateway_mode = \"proxy\"\n",
    );
    for (name, body, expected) in [
        (
            "both",
            "schema = 1\n[settings]\nlwd_timeout_secs = 60\n",
            "settings.lwd_timeout_secs is set in both",
        ),
        (
            "policy",
            "schema = 1\n[integrations.a]\nalias = \"a.example\"\nupstream = \"https://a\"\n",
            "unknown field `integrations`",
        ),
        ("schema", "schema = 2\n", "schema 2"),
        (
            "noschema",
            "[settings]\nport = 1\n",
            "missing field `schema`",
        ),
        (
            "policy-setting",
            "schema = 1\n[settings]\nbackends = \"a\"\n",
            "is a policy variable",
        ),
        (
            "secret",
            "schema = 1\n[settings]\nrelay_secrets = { secret = \"relay\" }\n",
            "has no [secrets] entry",
        ),
        (
            "both-secrets",
            "schema = 1\n[secrets]\nk = { env = \"X\" }\n",
            "",
        ),
    ] {
        let host = TempFile::new(&format!("both-{name}.toml"), body);
        let r = config_source::load_files(common.path(), Some(host.path()), Secrets::Skip);
        if expected.is_empty() {
            r.unwrap();
            continue;
        }
        let e = format!("{:#}", r.unwrap_err());
        assert!(e.contains(expected), "{name}: {e}");
    }
    // A secret declared in both files.
    let common = TempFile::new(
        "both-secret-common.toml",
        "schema = 1\ngateway_hosts = [\"gw.example\"]\n[secrets]\nk = { env = \"X\" }\n",
    );
    let host = TempFile::new(
        "both-secret-host.toml",
        "schema = 1\n[secrets]\nk = { env = \"Y\" }\n",
    );
    let e = format!(
        "{:#}",
        config_source::load_files(common.path(), Some(host.path()), Secrets::Skip).unwrap_err()
    );
    assert!(e.contains("secret 'k' is declared in both"), "{e}");
}

#[test]
fn a_policy_only_file_leaves_the_settings_to_the_environment() {
    let _guard = lock();
    apply_env(&[("LWD_ADDR".to_string(), "env-lwd.example:9067".to_string())]);
    let common = TempFile::new(
        "stage1.toml",
        "schema = 1\ngateway_hosts = [\"gw.example\"]\n",
    );
    let loaded = config_source::load_file(common.path(), Secrets::Require).unwrap();
    assert!(!loaded.carries_settings && loaded.settings.is_empty());
    let config = config_source::with_policy(loaded.policy.clone(), || Config::from_env().unwrap());
    assert_eq!(config.lwd_addr, "env-lwd.example:9067");
    // A [settings] table: the files carry the settings, every one left out at its default.
    let common = TempFile::new(
        "stage2-empty.toml",
        "schema = 1\ngateway_hosts = [\"gw.example\"]\n[settings]\ngateway_mode = \"proxy\"\n",
    );
    let loaded = config_source::load_file(common.path(), Secrets::Require).unwrap();
    assert!(loaded.carries_settings);
    let config = config_source::with_config(loaded.policy.clone(), loaded.settings.clone(), || {
        Config::from_env().unwrap()
    });
    assert_eq!(config.lwd_addr, "localhost:9067");
}

/// Every variable the gateway reads goes through `config_source::var` (or is a test switch),
/// and every name read is a policy variable or a setting; every setting is read somewhere.
#[test]
fn every_variable_is_read_through_the_configuration_source_and_classified() {
    // Test switches, read only by tests.
    const TEST_ONLY: &[&str] = &[
        "\"OHTTP_FAILOVER_REDIS\"",
        "\"OHTTP_FORWARD_RTT_PORT\"",
        "\"OHTTP_FORWARD_RTT_MAX_MS\"",
        "\"CI\"",
        "ALLOW_NO_STORE",
    ];
    let src = manifest().join("src");
    let mut all = String::new();
    let mut indirect: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_string();
        if !name.ends_with(".rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        all.push_str(&text);
        // The configuration source itself, and backfill (the environment only).
        if name == "config_source.rs" || name == "backfill.rs" || name.ends_with("_tests.rs") {
            continue;
        }
        for (n, line) in text.lines().enumerate() {
            for pat in ["env::var(", "env::var_os("] {
                let mut rest = line;
                while let Some(i) = rest.find(pat) {
                    let before = &rest[..i];
                    let arg = &rest[i + pat.len()..];
                    rest = arg;
                    if before.ends_with("config_source::") {
                        continue;
                    }
                    let arg = arg.split(')').next().unwrap_or("");
                    assert!(
                        TEST_ONLY.contains(&arg),
                        "{name}:{}: reads {arg} from the environment, not through config_source::var",
                        n + 1
                    );
                }
            }
            let mut rest = line;
            while let Some(i) = rest.find("config_source::var(\"") {
                rest = &rest[i + "config_source::var(\"".len()..];
                let var = rest.split('"').next().unwrap_or("");
                assert!(
                    POLICY_ENV_KEYS.contains(&var) || settings::setting(var).is_some(),
                    "{name}:{}: {var} is neither policy nor a setting",
                    n + 1
                );
            }
        }
        // The calls whose variable is not a literal: each is a known helper.
        let mut rest = text.as_str();
        while let Some(i) = rest.find("config_source::var(") {
            rest = &rest[i + "config_source::var(".len()..];
            let arg = rest.trim_start();
            if !arg.starts_with('"') {
                let token: String = arg
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                indirect.push(format!("{name}:{token}"));
            }
        }
    }
    indirect.sort();
    assert_eq!(
        indirect,
        [
            "config.rs:var",
            "dynamic_hosts.rs:var",
            "origin.rs:k",
            "prefetch.rs:name",
            "query_rules.rs:ENV",
            "query_value_sources.rs:ENV",
            "server.rs:HEADER_READ_TIMEOUT_ENV",
            "server.rs:INTERNAL_BIND_ADDR_ENV",
            "settings.rs:env",
            "settings.rs:env",
            "write_forward.rs:k",
        ],
        "a new indirect read: list it here once its variables are in SETTINGS or the policy"
    );
    for s in SETTINGS {
        // RUST_LOG: read by tracing_subscriber's EnvFilter (and as `rust_log` from the files).
        if s.env == "RUST_LOG" {
            continue;
        }
        assert!(
            all.matches(&format!("\"{}\"", s.env)).count() >= 2,
            "{} is not read by the code",
            s.env
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The binary.

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_zodl-ohttp-gateway")
}

/// Run the binary with exactly `env` (nothing inherited) and wait at most 60 s.
fn run(args: &[&str], env: &[(&str, &str)]) -> (Option<i32>, String, String) {
    let out = TempFile::new(&format!("run-out-{}", unique()), "");
    let err = TempFile::new(&format!("run-err-{}", unique()), "");
    let mut child = Command::new(bin())
        .env_clear()
        .envs(env.iter().copied())
        .args(args)
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(&out.0).unwrap())
        .stderr(std::fs::File::create(&err.0).unwrap())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{args:?} did not exit within 60 s");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    (
        status.code(),
        std::fs::read_to_string(&out.0).unwrap(),
        std::fs::read_to_string(&err.0).unwrap(),
    )
}

fn unique() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::Relaxed)
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// `GET path` on `addr` (HTTP/1.1, the whole answer): `(status, text)`.
fn http_get(addr: &str, path: &str) -> Option<(u16, String)> {
    let mut s =
        std::net::TcpStream::connect_timeout(&addr.parse().ok()?, Duration::from_millis(500))
            .ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    s.set_write_timeout(Some(Duration::from_secs(5))).ok()?;
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text.split(' ').nth(1)?.parse().ok()?;
    Some((status, text))
}

/// A serving gateway, killed on drop; its output in files.
struct Server {
    child: Child,
    out: TempFile,
    err: TempFile,
}

impl Server {
    fn start(env: &[(&str, &str)]) -> Self {
        let out = TempFile::new(&format!("serve-out-{}", unique()), "");
        let err = TempFile::new(&format!("serve-err-{}", unique()), "");
        let child = Command::new(bin())
            .env_clear()
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&out.0).unwrap())
            .stderr(std::fs::File::create(&err.0).unwrap())
            .spawn()
            .unwrap();
        Self { child, out, err }
    }

    /// `GET path` on `addr` until it answers 200, at most 30 s (the process must not exit).
    fn wait_for(&mut self, addr: &str, path: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!(
                    "the gateway exited ({status}) before {path} answered:\n{}\n{}",
                    self.logs(),
                    std::fs::read_to_string(&self.err.0).unwrap_or_default()
                );
            }
            if let Some((200, text)) = http_get(addr, path) {
                return text;
            }
            assert!(
                Instant::now() < deadline,
                "{path} on {addr} did not answer 200 within 30 s:\n{}",
                self.logs()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn logs(&self) -> String {
        std::fs::read_to_string(&self.out.0).unwrap_or_default()
            + &std::fs::read_to_string(&self.err.0).unwrap_or_default()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const SENTINEL: &str = "sentinel-secret-value-3f9a";

/// A common file and a host file for a gateway in proxy mode on two free ports, with a relay
/// secret in a secret file.
struct ProxyFiles {
    common: TempFile,
    host: TempFile,
    _secret: TempFile,
    internal: String,
}

fn proxy_files(name: &str, origin: &str) -> ProxyFiles {
    let secret = TempFile::new(
        &format!("{name}-relay-secret"),
        &format!("edge={SENTINEL}\n"),
    );
    let common = TempFile::new(
        &format!("{name}-common.toml"),
        &format!(
            "schema = 1\ngateway_hosts = [\"gateway.example\"]\n\n[secrets]\nrelay = {{ file = {:?} }}\n\n[settings]\ngateway_mode = \"proxy\"\nrust_log = \"info\"\nlwd_timeout_secs = 30\nrelay_secrets = {{ secret = \"relay\" }}\n",
            secret.path()
        ),
    );
    let internal = format!("127.0.0.1:{}", free_port());
    let host = TempFile::new(
        &format!("{name}-host.toml"),
        &format!(
            "schema = 1\n\n[settings]\nport = {}\ninternal_bind_addr = \"{internal}\"\nnetwork = \"testnet\"\nlwd_addr = \"127.0.0.1:1\"\norigin_id = \"{origin}\"\n",
            free_port()
        ),
    );
    ProxyFiles {
        common,
        host,
        _secret: secret,
        internal,
    }
}

#[test]
fn file_mode_serves_with_an_empty_environment() {
    let files = proxy_files("empty-env", "origin-files");
    let env = [
        ("CONFIG_SOURCE", "file"),
        ("GATEWAY_CONFIG_FILE", files.common.path()),
        ("GATEWAY_HOST_CONFIG_FILE", files.host.path()),
    ];
    // --check-config with the same environment: both files, the secret file read.
    let (code, stdout, stderr) = run(&["--check-config"], &env);
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    assert!(stdout.contains("settings OK: 9 settings from"), "{stdout}");
    assert!(!stdout.contains(SENTINEL) && !stderr.contains(SENTINEL));
    let tuning = stdout
        .split("tuning digest ")
        .nth(1)
        .and_then(|s| s.get(..16))
        .unwrap()
        .to_string();

    let mut server = Server::start(&env);
    let metrics = server.wait_for(&files.internal, "/metrics");
    assert!(metrics.contains("source=\"file\""), "{metrics}");
    assert!(
        metrics.contains(&format!("tuning_digest=\"{tuning}\"")),
        "{metrics}"
    );
    // The host file's ORIGIN_ID.
    assert!(metrics.contains("origin=\"origin-files\""), "{metrics}");
    let logs = server.logs();
    drop(server);
    assert!(
        logs.contains("Routing policy from the configuration file"),
        "{logs}"
    );
    assert!(!logs.contains("are ignored"), "{logs}");
    assert!(!logs.contains(SENTINEL) && !metrics.contains(SENTINEL));
}

#[test]
fn file_mode_ignores_the_settings_of_the_environment() {
    let files = proxy_files("ignored", "origin-files");
    let other = format!("127.0.0.1:{}", free_port());
    let env = [
        ("CONFIG_SOURCE", "file"),
        ("GATEWAY_CONFIG_FILE", files.common.path()),
        ("GATEWAY_HOST_CONFIG_FILE", files.host.path()),
        ("INTERNAL_BIND_ADDR", other.as_str()),
        ("ORIGIN_ID", "origin-env"),
        ("RUST_LOG", "error"),
    ];
    let mut server = Server::start(&env);
    let metrics = server.wait_for(&files.internal, "/metrics");
    assert!(metrics.contains("origin=\"origin-files\""), "{metrics}");
    assert!(http_get(&other, "/metrics").is_none());
    let logs = server.logs();
    drop(server);
    // RUST_LOG=error of the environment is ignored too: the info lines are there.
    assert!(
        logs.contains("Routing policy from the configuration file"),
        "{logs}"
    );
    assert!(
        logs.contains("these setting variables of the environment are ignored")
            && logs.contains("INTERNAL_BIND_ADDR,ORIGIN_ID,RUST_LOG"),
        "{logs}"
    );
}

#[test]
fn a_policy_only_file_in_file_mode_keeps_the_settings_of_the_environment() {
    let common = TempFile::new(
        "stage1-serve.toml",
        "schema = 1\ngateway_hosts = [\"gateway.example\"]\n",
    );
    let internal = format!("127.0.0.1:{}", free_port());
    let port = free_port().to_string();
    let env = [
        ("CONFIG_SOURCE", "file"),
        ("GATEWAY_CONFIG_FILE", common.path()),
        ("GATEWAY_MODE", "proxy"),
        ("PORT", port.as_str()),
        ("INTERNAL_BIND_ADDR", internal.as_str()),
        ("LWD_ADDR", "127.0.0.1:1"),
        ("ORIGIN_ID", "origin-env"),
    ];
    let mut server = Server::start(&env);
    let metrics = server.wait_for(&internal, "/metrics");
    assert!(metrics.contains("origin=\"origin-env\""), "{metrics}");
}

#[test]
fn compare_mode_compares_the_settings() {
    for (lwd_timeout, expected) in [("30", "1"), ("31", "0")] {
        let files = proxy_files(&format!("compare-{lwd_timeout}"), "origin-a");
        let host = std::fs::read_to_string(&files.host.0).unwrap();
        let value = |key: &str| {
            host.lines()
                .find_map(|l| l.strip_prefix(&format!("{key} = ")))
                .unwrap()
                .trim_matches('"')
                .to_string()
        };
        let (port, internal) = (value("port"), value("internal_bind_addr"));
        let relay = format!("edge={SENTINEL}");
        let env = [
            ("CONFIG_SOURCE", "compare"),
            ("GATEWAY_CONFIG_FILE", files.common.path()),
            ("GATEWAY_HOST_CONFIG_FILE", files.host.path()),
            ("GATEWAY_HOSTS", "gateway.example"),
            ("GATEWAY_MODE", "proxy"),
            ("RUST_LOG", "info"),
            ("LWD_TIMEOUT_SECS", lwd_timeout),
            ("RELAY_SECRETS", relay.as_str()),
            ("PORT", port.as_str()),
            ("INTERNAL_BIND_ADDR", internal.as_str()),
            ("NETWORK", "testnet"),
            ("LWD_ADDR", "127.0.0.1:1"),
            ("ORIGIN_ID", "origin-a"),
        ];
        let mut server = Server::start(&env);
        let metrics = server.wait_for(&files.internal, "/metrics");
        assert!(
            metrics.contains(&format!("ohttp_config_settings_compare_match {expected}")),
            "{lwd_timeout}: {metrics}"
        );
        assert!(
            metrics.contains("ohttp_config_compare_match 1"),
            "{metrics}"
        );
        let logs = server.logs();
        drop(server);
        if expected == "0" {
            assert!(logs.contains("settings.lwd_timeout_secs"), "{logs}");
        }
        assert!(!logs.contains(SENTINEL) && !metrics.contains(SENTINEL));
    }
}

/// `CONFIG_SOURCE=file` in `ohttp` mode with an empty environment: the keys, the relay secret
/// and the signing seed from secret files, the stores from the host file (the test Redis, a
/// database of its own); the key configuration is served.
#[test]
fn file_mode_serves_ohttp_with_secret_files() {
    let reachable = std::net::TcpStream::connect_timeout(
        &"127.0.0.1:6379".parse().unwrap(),
        Duration::from_secs(1),
    )
    .is_ok();
    if !reachable {
        assert!(
            std::env::var_os("CI").is_none(),
            "the test Redis on 127.0.0.1:6379 is needed in CI"
        );
        eprintln!("test skipped: no test Redis on 127.0.0.1:6379");
        return;
    }
    let key = TempFile::new("ohttp-hpke", &format!("1:{}\n", "5a".repeat(32)));
    let relay = TempFile::new("ohttp-relay", &format!("edge={SENTINEL}"));
    let seed = TempFile::new("ohttp-seed", &"6b".repeat(32));
    let common = TempFile::new(
        "ohttp-common.toml",
        &format!(
            "schema = 1\ngateway_hosts = [\"gateway.example\"]\n\n[secrets]\nhpke_keys = {{ file = {:?} }}\nrelay_secrets = {{ file = {:?} }}\nseed = {{ file = {:?} }}\n\n[settings]\nhpke_keys = {{ secret = \"hpke_keys\" }}\nrelay_secrets = {{ secret = \"relay_secrets\" }}\nconfigs_signing_seed_hex = {{ secret = \"seed\" }}\nreplay_startup_stores_wait_secs = 0\n",
            key.path(),
            relay.path(),
            seed.path()
        ),
    );
    let public = format!("127.0.0.1:{}", free_port());
    let internal = format!("127.0.0.1:{}", free_port());
    let host = TempFile::new(
        "ohttp-host.toml",
        &format!(
            "schema = 1\n\n[settings]\nport = {}\ninternal_bind_addr = \"{internal}\"\nnetwork = \"testnet\"\nlwd_addr = \"127.0.0.1:1\"\nredis_url = \"redis://127.0.0.1:6379/13\"\nredis_security_url = \"redis://127.0.0.1:6379/13\"\n",
            public.rsplit(':').next().unwrap()
        ),
    );
    let env = [
        ("CONFIG_SOURCE", "file"),
        ("GATEWAY_CONFIG_FILE", common.path()),
        ("GATEWAY_HOST_CONFIG_FILE", host.path()),
    ];
    let (code, stdout, stderr) = run(&["--check-config", "--secrets=require"], &env);
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    let mut server = Server::start(&env);
    let configs = server.wait_for(&public, "/ohttp-configs");
    assert!(configs.contains("application/ohttp-keys"), "{configs}");
    let metrics = server.wait_for(&internal, "/metrics");
    assert!(metrics.contains("source=\"file\""), "{metrics}");
    let logs = server.logs();
    drop(server);
    for secret in [SENTINEL, &"5a".repeat(32), &"6b".repeat(32)] {
        assert!(!logs.contains(secret) && !metrics.contains(secret) && !stdout.contains(secret));
    }
}

#[test]
fn check_config_of_both_files_and_its_refusals_never_show_a_secret() {
    let files = proxy_files("check", "origin-a");
    let env = |extra: &[(&'static str, String)]| {
        let mut v: Vec<(&str, String)> = vec![
            ("GATEWAY_CONFIG_FILE", files.common.path().to_string()),
            ("GATEWAY_HOST_CONFIG_FILE", files.host.path().to_string()),
        ];
        v.extend(extra.iter().cloned());
        v
    };
    let as_refs = |v: &[(&str, String)]| -> Vec<(String, String)> {
        v.iter().map(|(k, s)| (k.to_string(), s.clone())).collect()
    };
    let run_env = |args: &[&str], v: Vec<(&str, String)>| {
        let owned = as_refs(&v);
        let refs: Vec<(&str, &str)> = owned
            .iter()
            .map(|(k, s)| (k.as_str(), s.as_str()))
            .collect();
        run(args, &refs)
    };
    let (code, stdout, _) = run_env(&["--check-config"], env(&[]));
    assert_eq!(code, Some(0), "{stdout}");
    // --host-config on the command line wins over the variable.
    let bad = TempFile::new(
        "check-bad-host.toml",
        "schema = 1\n[settings]\nport = \"x\"\n",
    );
    let (code, _, stderr) = run_env(&["--check-config", "--host-config", bad.path()], env(&[]));
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("config INVALID")
            && stderr.contains("settings.port must be a non-negative integer"),
        "{stderr}"
    );
    // A parser of a setting refuses: the gateway's own startup error.
    let bad = TempFile::new(
        "check-bad-value.toml",
        "schema = 1\n[settings]\nchunk_size = 10\n",
    );
    let (code, _, stderr) = run_env(&["--check-config", "--host-config", bad.path()], env(&[]));
    assert_eq!(code, Some(1));
    assert!(stderr.contains("CHUNK_SIZE must be at least"), "{stderr}");
    // A secret file that is missing: refused with require, passes with skip.
    let missing = TempFile::new(
        "check-missing.toml",
        "schema = 1\n[secrets]\nfwd = { file = \"/nonexistent/forward-secret\" }\n[settings]\nreplay_write_forward_secret = { secret = \"fwd\" }\n",
    );
    let (code, _, stderr) = run_env(
        &["--check-config", "--host-config", missing.path()],
        env(&[]),
    );
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("secret 'fwd': file /nonexistent/forward-secret"),
        "{stderr}"
    );
    let (code, stdout, _) = run_env(
        &[
            "--check-config",
            "--secrets=skip",
            "--host-config",
            missing.path(),
        ],
        env(&[]),
    );
    assert_eq!(code, Some(0), "{stdout}");
    // A secret value in a malformed setting is never echoed.
    let leak = TempFile::new(
        "check-leak.toml",
        &format!("schema = 1\n[settings]\nhpke_keys = \"{SENTINEL}\"\nredis_url = \"redis://:{SENTINEL}@cache.example\"\n"),
    );
    let (code, stdout, stderr) =
        run_env(&["--check-config", "--host-config", leak.path()], env(&[]));
    assert_eq!(code, Some(1));
    assert!(
        !stdout.contains(SENTINEL) && !stderr.contains(SENTINEL),
        "{stderr}"
    );
    // --host only with --export-config.
    let (code, _, stderr) = run_env(&["--check-config", "--host", "/tmp/x"], env(&[]));
    assert_eq!(code, Some(2), "{stderr}");
}

#[test]
fn export_config_with_host_writes_the_two_files() {
    let vars = read_vars(manifest().join("tests/fixtures/settings/full.vars"));
    let refs: Vec<(&str, &str)> = vars.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let host_out = TempFile::path_for(&format!("export-host-{}.toml", unique()));
    let _cleanup = TempFile(host_out.clone());
    let host_arg = host_out.to_str().unwrap();
    let (code, common, stderr) = run(&["--export-config", "--host", host_arg], &refs);
    assert_eq!(code, Some(0), "{stderr}");
    let host = std::fs::read_to_string(&host_out).unwrap();
    for secret in secret_values(&vars) {
        assert!(!common.contains(&secret) && !host.contains(&secret) && !stderr.contains(&secret));
    }
    assert!(common.contains("\n[settings]\n") && host.starts_with("schema = 1\n"));
    // Without --host the export is the policy alone, as before.
    let (code, policy_only, _) = run(&["--export-config"], &refs);
    assert_eq!(code, Some(0));
    assert!(!policy_only.contains("[settings]"));
    // The files pass --check-config with the environment's secrets (and of the new variable
    // the policy export names).
    let common_file = TempFile::new("export-common.toml", &common);
    let mut env = refs.clone();
    let generated: Vec<(String, String)> = stderr
        .lines()
        .filter_map(|l| l.strip_prefix("note: secret '"))
        .filter_map(|l| l.split_once("maps to a new variable "))
        .filter_map(|(_, rest)| rest.split(';').next())
        .map(|var| (var.to_string(), "prices-key-fake-1".to_string()))
        .collect();
    env.extend(generated.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    env.push(("GATEWAY_CONFIG_FILE", common_file.path()));
    env.push(("GATEWAY_HOST_CONFIG_FILE", host_arg));
    let (code, stdout, stderr) = run(&["--check-config"], &env);
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    assert!(stdout.contains("settings OK"), "{stdout}");
    // Never over an existing file.
    let (code, _, stderr) = run(&["--export-config", "--host", host_arg], &refs);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("AlreadyExists") || stderr.contains("already exists"),
        "{stderr}"
    );
}

#[test]
fn the_example_files_are_valid_together() {
    let _guard = lock();
    apply_env(&[]);
    let common = manifest().join("config.example.toml");
    let host = manifest().join("host.example.toml");
    let loaded = config_source::load_files(
        common.to_str().unwrap(),
        Some(host.to_str().unwrap()),
        Secrets::Skip,
    )
    .unwrap();
    assert!(loaded.carries_settings && loaded.warnings.is_empty());
    assert_eq!(loaded.settings["LWD_ADDR"], "lwd.example:9067");
    assert_eq!(loaded.settings["LWD_TIMEOUT_SECS"], "80");
    assert_eq!(loaded.settings["LWD_CONNECTION_POOL"], "1");
    assert_eq!(
        loaded.settings["REDIS_URL"],
        "redis://:secret-not-read@cache.example:6379"
    );
    assert!(!loaded.settings.contains_key("HPKE_KEYS"));
}

/// `--check-config` runs the mandatory startup checks of the serving process; a malformed
/// secret fails with the setting's name only.
#[test]
fn check_config_runs_the_startup_checks_and_never_shows_a_malformed_secret() {
    let bad_key = TempFile::new("startup-hpke", &format!("zz:{SENTINEL}"));
    let seed = TempFile::new("startup-seed", &format!("{SENTINEL}{SENTINEL}"));
    let common = |body: &str| {
        format!(
            "schema = 1\ngateway_hosts = [\"gateway.example\"]\n\n[secrets]\nhpke = {{ file = {:?} }}\nseed = {{ file = {:?} }}\n\n[settings]\nallow_unauthenticated_relay = true\n{body}",
            bad_key.path(),
            seed.path()
        )
    };
    let host = TempFile::new(
        "startup-host.toml",
        "schema = 1\n[settings]\nredis_url = \"redis://cache.example:6379\"\nredis_security_url = \"redis://security.example:6379\"\n",
    );
    for (name, body, expected) in [
        ("hpke", "hpke_keys = { secret = \"hpke\" }\n", "settings.hpke_keys"),
        (
            "seed",
            "hpke_private_key = { secret = \"hpke\" }\nconfigs_signing_seed_hex = { secret = \"seed\" }\n",
            "settings.",
        ),
        ("nokey", "", "HPKE_KEYS (or HPKE_PRIVATE_KEY) is required"),
        ("log", "rust_log = \"info,[\"\n", "RUST_LOG is not a valid tracing filter"),
    ] {
        let file = TempFile::new(&format!("startup-{name}.toml"), &common(body));
        let env = [
            ("GATEWAY_CONFIG_FILE", file.path()),
            ("GATEWAY_HOST_CONFIG_FILE", host.path()),
        ];
        let (code, stdout, stderr) = run(&["--check-config"], &env);
        assert_eq!(code, Some(1), "{name}: {stdout}{stderr}");
        assert!(stderr.contains(expected), "{name}: {stderr}");
        assert!(!stderr.contains(SENTINEL) && !stdout.contains(SENTINEL), "{name}: {stderr}");
        // Without the secrets: a whole secret left out skips the checks that need it.
        if name == "hpke" {
            let (code, stdout, stderr) = run(&["--check-config", "--secrets=skip"], &env);
            assert_eq!(code, Some(0), "{stdout}{stderr}");
        }
    }
    // The stores are required in ohttp mode.
    let file = TempFile::new(
        "startup-stores.toml",
        &common("hpke_keys = { secret = \"hpke\" }\n"),
    );
    let empty_host = TempFile::new("startup-empty-host.toml", "schema = 1\n");
    let (code, _, stderr) = run(
        &["--check-config", "--secrets=skip"],
        &[
            ("GATEWAY_CONFIG_FILE", file.path()),
            ("GATEWAY_HOST_CONFIG_FILE", empty_host.path()),
        ],
    );
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("REDIS_URL and REDIS_SECURITY_URL are required"),
        "{stderr}"
    );
}

#[test]
fn check_config_names_the_settings_the_files_leave_out_and_strict_refuses_them() {
    let files = proxy_files("strict", "origin-a");
    let env = [
        ("GATEWAY_CONFIG_FILE", files.common.path()),
        ("GATEWAY_HOST_CONFIG_FILE", files.host.path()),
        ("MAX_BLOCK_RANGE", "12000"),
        ("LWD_TIMEOUT_SECS", "30"),
    ];
    let (code, stdout, stderr) = run(&["--check-config"], &env);
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    assert!(
        stderr.contains("warning: settings of the environment that the files leave out")
            && stderr.contains("MAX_BLOCK_RANGE")
            && !stderr.contains("LWD_TIMEOUT_SECS"),
        "{stderr}"
    );
    let (code, _, stderr) = run(&["--check-config", "--strict"], &env);
    assert_eq!(code, Some(1), "{stderr}");
    assert!(stderr.contains("--strict"), "{stderr}");
    let (code, _, stderr) = run(&["--export-config", "--strict"], &env);
    assert_eq!(code, Some(2), "{stderr}");
}

#[test]
fn print_effective_config_shows_the_settings_with_secret_names_only() {
    let files = proxy_files("print", "origin-a");
    let env = [
        ("CONFIG_SOURCE", "file"),
        ("GATEWAY_CONFIG_FILE", files.common.path()),
        ("GATEWAY_HOST_CONFIG_FILE", files.host.path()),
    ];
    let (code, stdout, stderr) = run(&["--print-effective-config"], &env);
    assert_eq!(code, Some(0), "{stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["settings"]["RELAY_SECRETS"], "<secret:relay>");
    assert_eq!(v["settings"]["ORIGIN_ID"], "origin-a");
    assert!(!stdout.contains(SENTINEL));
}

#[test]
fn a_host_secret_needs_exactly_one_source_even_when_secrets_are_skipped() {
    let _guard = lock();
    apply_env(&[]);
    let common = TempFile::new(
        "secret-shape-common.toml",
        "schema = 1\ngateway_hosts = [\"gw.example\"]\n",
    );
    for body in [
        "schema = 1\n[secrets]\nk = { env = \"X\", file = \"/x\" }\n",
        "schema = 1\n[secrets]\nk = {}\n",
    ] {
        let host = TempFile::new("secret-shape-host.toml", body);
        let e = format!(
            "{:#}",
            config_source::load_files(common.path(), Some(host.path()), Secrets::Skip).unwrap_err()
        );
        assert!(e.contains("needs exactly one of env or file"), "{e}");
    }
}

#[test]
fn compare_mode_reports_a_settings_mismatch_when_a_settings_file_does_not_load() {
    let internal = format!("127.0.0.1:{}", free_port());
    let port = free_port().to_string();
    // A [settings] table and no host file; a value no parser takes.
    let common = TempFile::new(
        "compare-broken.toml",
        "schema = 1\ngateway_hosts = [\"gateway.example\"]\n[settings]\nchunk_size = 10\n",
    );
    let env = [
        ("CONFIG_SOURCE", "compare"),
        ("GATEWAY_CONFIG_FILE", common.path()),
        ("GATEWAY_HOSTS", "gateway.example"),
        ("GATEWAY_MODE", "proxy"),
        ("PORT", port.as_str()),
        ("INTERNAL_BIND_ADDR", internal.as_str()),
        ("LWD_ADDR", "127.0.0.1:1"),
    ];
    let mut server = Server::start(&env);
    let metrics = server.wait_for(&internal, "/metrics");
    assert!(
        metrics.contains("ohttp_config_settings_compare_match 0"),
        "{metrics}"
    );
    assert!(
        metrics.contains("ohttp_config_compare_match 0"),
        "{metrics}"
    );
}

/// The export reads each secret as the serving process would: a value it refuses (a control
/// character, a blank one) fails the export, by name only.
#[test]
fn the_export_refuses_a_secret_the_gateway_would_refuse() {
    let vars = read_vars(manifest().join("tests/fixtures/settings/full.vars"));
    let mut env: BTreeMap<String, String> = vars.into_iter().collect();
    env.insert(
        "REPLAY_WRITE_FORWARD_SECRET".to_string(),
        format!("{SENTINEL}\u{1}"),
    );
    let (text, export) = config_source::export_checked(&env).unwrap();
    let e = format!(
        "{:#}",
        config_source::export_files(&env, &text, &export).unwrap_err()
    );
    assert!(
        e.contains("secret 'replay_write_forward_secret'") && e.contains("control character"),
        "{e}"
    );
    assert!(!e.contains(SENTINEL), "{e}");
}

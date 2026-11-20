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

//! The configuration file against the environment it stands for, on the characterisation
//! fixtures (`tests/fixtures/characterisation/<network>.vars`):
//!
//! - `<network>.toml` is the export (`--export-config`) of the fixture environment and
//!   `<network>.effective.json` its canonical effective policy (`--print-effective-config`);
//!   the environment, the file and the committed snapshot are the same policy;
//! - the gateway's parsers read the same tables from the file as from the environment;
//! - `--check-config` refusals, `CONFIG_SOURCE=compare` and `file`.
//!
//! `CONFIG_FILE_BLESS=1 cargo test --test config_file` rewrites the two files per network from
//! the current code (refused when `CI` is set); review the diff before committing it.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use serde_json::{json, Value};
use zodl_ohttp_gateway::config::Config;
use zodl_ohttp_gateway::config_source::{self, Secrets};
use zodl_ohttp_gateway::origin::OriginSettings;
use zodl_ohttp_gateway::third_party_cache::{Aliases, CacheRoutes, RateLimiters};
use zodl_ohttp_integrations::core::config as policy_file;

/// The process environment is global: every test of this file holds this lock.
static ENV_LOCK: Mutex<()> = Mutex::new(());

const NETWORKS: &[&str] = &["mainnet", "testnet"];

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/characterisation")
}

fn bless() -> bool {
    let bless = std::env::var("CONFIG_FILE_BLESS").is_ok_and(|v| v == "1");
    assert!(
        !(bless && std::env::var_os("CI").is_some()),
        "CONFIG_FILE_BLESS=1 is refused when CI is set"
    );
    bless
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

fn keep_var(name: &str) -> bool {
    matches!(
        name,
        "PATH" | "HOME" | "TMPDIR" | "TMP" | "TEMP" | "USER" | "LANG" | "TERM" | "CI"
    ) || ["CARGO", "RUST", "LC_", "LD_", "DYLD_", "CONFIG_FILE_BLESS"]
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

/// Compare with the committed file, or rewrite it under CONFIG_FILE_BLESS=1.
fn golden(name: &str, actual: &str) {
    let path = fixtures().join(name);
    if bless() {
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{path:?}: {e} (CONFIG_FILE_BLESS=1 creates it)"));
    assert_eq!(expected, actual, "{path:?} differs from the current code");
}

/// The routes named in a `authority=METHOD /path,...;...` value.
fn routes(raw: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for entry in raw.split(';').map(str::trim).filter(|e| !e.is_empty()) {
        let Some((authority, list)) = entry.split_once('=') else {
            continue;
        };
        for item in list.split(',').map(str::trim).filter(|i| !i.is_empty()) {
            if let Some((method, path)) = item.split_once(' ') {
                out.push((
                    authority.trim().to_string(),
                    method.to_string(),
                    path.to_string(),
                ));
            }
        }
    }
    out
}

/// What the gateway's parsers read from the policy in force, as comparable values. `probe` is
/// the environment whose routes are probed (the same for both sides).
fn views(probe: &BTreeMap<String, String>) -> Value {
    let c = Config::from_env().expect("config");
    let o = OriginSettings::from_env().expect("origin settings");
    let cache = CacheRoutes::from_env(Aliases {
        flexa: c.flexa_alias.as_deref(),
        near: c.near_alias.as_deref(),
    })
    .expect("cache routes");
    let limits = RateLimiters::from_env().expect("rate limits");
    let get = |k: &str| probe.get(k).cloned().unwrap_or_default();
    let ttls: BTreeMap<String, Option<u64>> = routes(&get("THIRD_PARTY_CACHE_ROUTES"))
        .into_iter()
        .map(|(a, m, p)| {
            let p = p.split('@').next().unwrap_or(&p).to_string();
            let ttl = cache.as_ref().and_then(|r| r.find_ttl(&a, &m, &p));
            (format!("{m} {a} {p}"), ttl)
        })
        .collect();
    let rules = &c.third_party_query_rules;
    let admits: BTreeMap<String, (bool, bool)> = routes(&get("THIRD_PARTY_QUERY_RULES"))
        .into_iter()
        .map(|(a, m, p)| {
            let bare = p.split('?').next().unwrap_or(&p).to_string();
            let key = format!("{m} {a} {p}");
            (key, (rules.admits(&a, &m, &p), rules.admits(&a, &m, &bare)))
        })
        .collect();
    let sorted = |m: &std::collections::HashMap<String, Vec<(String, String)>>| {
        m.iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    let sources: Vec<Value> = rules
        .sources()
        .specs()
        .map(|s| {
            json!([
                s.name,
                s.alias,
                s.path,
                s.refresh.as_secs(),
                rules.sources().current_len(&s.name)
            ])
        })
        .collect();
    json!({
        "gateway_hosts": c.gateway_hosts,
        "backends": c.backends.iter().collect::<BTreeMap<_, _>>(),
        "backends_policy": sorted(&c.backends_policy),
        "backends_policy_default_allow": c.backends_policy_default_allow,
        "backend_headers": sorted(&c.backend_headers),
        "flexa_alias": c.flexa_alias,
        "near_alias": c.near_alias,
        "relay_secret_on_key_config": format!("{:?}", c.relay_secret_on_key_config),
        "host_list": format!("{:?}", c.host_list),
        "query_rules": rules.len(),
        "query_admits": admits,
        "value_sources": sources,
        "replay_read_routes": o.replay_read_routes.to_string(),
        "replay_one_sided_write_routes": o.replay_one_sided_write_routes.to_string(),
        "cache_routes": cache.as_ref().map_or(0, CacheRoutes::len),
        "cache_ttls": ttls,
        "rate_limits": limits.map(|l| l.configs.into_iter().map(|(a, (n, w))| (a, (n, w.as_secs()))).collect::<BTreeMap<_, _>>()),
        "dynamic_sources": c.dynamic_hosts.source_names(),
    })
}

/// The export of a fixture environment (only its variables: an ambient one can never become
/// a secret reference).
fn export_of(vars: &[(String, String)]) -> policy_file::Export {
    let env: BTreeMap<String, String> = vars.iter().cloned().collect();
    policy_file::export(&env).expect("the fixture environment exports")
}

#[test]
fn the_fixture_files_are_the_export_and_the_effective_policy_of_the_environment() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    for network in NETWORKS {
        let vars = read_env(network);
        apply_env(&vars);
        let export = export_of(&vars);
        let toml = policy_file::to_toml(&export.file, &export.secrets).unwrap();
        // Placeholders only: no header value of the fixture is in the file.
        for (authority, headers) in zodl_ohttp_integrations::core::policy::parse_backend_headers(
            &std::env::var("BACKEND_HEADERS").unwrap_or_default(),
        )
        .unwrap()
        {
            for (name, value) in headers {
                assert!(
                    !toml.contains(&value),
                    "{authority} {name}: value in the file"
                );
            }
        }
        golden(&format!("{network}.toml"), &toml);
        let canonical = config_source::env_canonical(&config_source::env_policy()).unwrap();
        let pretty = serde_json::to_string_pretty(&canonical).unwrap() + "\n";
        golden(&format!("{network}.effective.json"), &pretty);
        // The committed file is that policy.
        let path = fixtures().join(format!("{network}.toml"));
        let committed = std::fs::read_to_string(&path).unwrap();
        let loaded = policy_file::parse(&committed).unwrap();
        assert!(loaded.warnings.is_empty());
        assert_eq!(
            config_source::file_canonical(&loaded.file).unwrap(),
            canonical
        );
        assert_eq!(
            config_source::env_digest(&config_source::env_policy()).unwrap(),
            config_source::policy_digest(&loaded.file).unwrap()
        );
        let snapshot: Value = serde_json::from_str(
            &std::fs::read_to_string(fixtures().join(format!("{network}.effective.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(snapshot, canonical);
        let env: BTreeMap<String, String> = vars.iter().cloned().collect();
        assert!(policy_file::check_round_trip(&env).unwrap());
    }
}

#[test]
fn the_parsers_read_the_same_policy_from_the_file_as_from_the_environment() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    for network in NETWORKS {
        let vars = read_env(network);
        apply_env(&vars);
        let env = process_env();
        let from_env = views(&env);
        let export = export_of(&vars);
        let path = fixtures().join(format!("{network}.toml"));
        let file = policy_file::parse(&std::fs::read_to_string(&path).unwrap())
            .unwrap()
            .file;
        let rendered: BTreeMap<String, String> =
            policy_file::render(&file, &|n: &str| export.resolve(n))
                .unwrap()
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect();
        // Everything the file stands for is set in the environment, and nothing more.
        let env_set = config_source::env_policy();
        let set: Vec<&String> = env_set.keys().collect();
        let rendered_keys: Vec<&String> = rendered.keys().collect();
        assert_eq!(rendered_keys, set, "{network}");
        let from_file = config_source::with_policy(rendered.clone(), || views(&env));
        assert_eq!(from_file, from_env, "{network}");
        // The comparison of CONFIG_SOURCE=compare agrees.
        let c = config_source::compare(&config_source::env_policy(), &file, &|n: &str| {
            export.resolve(n)
        })
        .unwrap();
        assert!(c.matches, "{network}: {:?}", c.keys);
        // --check-config passes, without the secrets and with them.
        let path = path.to_str().unwrap();
        config_source::load_file(path, Secrets::Skip).unwrap();
        for s in &export.secrets {
            std::env::set_var(&s.env, export.secret_value(&s.name).unwrap());
        }
        let loaded = config_source::load_file(path, Secrets::Require).unwrap();
        assert_eq!(loaded.policy, rendered, "{network}");
    }
}

/// A file in the temporary directory, removed on drop.
struct TempFile(PathBuf);

impl TempFile {
    fn new(name: &str, content: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("config-file-test-{}-{name}", std::process::id()));
        std::fs::write(&path, content).unwrap();
        Self(path)
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

const BASE: &str = "schema = 1\ngateway_hosts = [\"gw.example\"]\n";

#[test]
fn check_config_refuses_what_the_policy_cannot_be() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    apply_env(&[]);
    let a = "[integrations.a]\nalias = \"a.example\"\nupstream = \"https://a-api.example\"\n";
    for (name, body, expected) in [
        ("unknown", format!("{BASE}color = \"red\""), "unknown field `color`"),
        (
            "duplicate",
            format!("{BASE}{a}[integrations.b]\nalias = \"a.example\"\nupstream = \"https://b\"\n"),
            "listed twice",
        ),
        (
            "gateway",
            format!("{BASE}[integrations.g]\nalias = \"gw.example\"\nupstream = \"https://g\"\n"),
            "is also a gateway host",
        ),
        (
            "secret",
            format!("{BASE}{a}headers = [{{ name = \"X-Key\", value = \"{{secret}}\", secret = \"k\" }}]\n"),
            "does not map",
        ),
        (
            "cache",
            format!("{BASE}{a}routes = [\"GET /v1/a\"]\ncache = [\"GET /v1/b@60\"]\n"),
            "outside its routes",
        ),
        // The gateway's own startup checks.
        (
            "grammar",
            format!("{BASE}{a}routes = [\"FETCH /v1/a\"]\n"),
            "Invalid BACKENDS_POLICY method",
        ),
        (
            "query",
            format!("{BASE}{a}routes = [\"GET /v1/a\"]\nquery_rules = [\"GET /v1/b?\"]\n"),
            "THIRD_PARTY_QUERY_RULES",
        ),
        (
            "near-cache",
            format!("{BASE}{a}kind = \"near\"\nroutes = [\"GET /v0/status\"]\ncache = [\"GET /v0/status@60\"]\n"),
            "(NEAR_ALIAS) '/v0/status' is not cacheable",
        ),
        (
            "missing-secret",
            format!("{BASE}[secrets]\nk = {{ env = \"CONFIG_TEST_UNSET_SECRET\" }}\n{a}headers = [{{ name = \"X-Key\", value = \"{{secret}}\", secret = \"k\" }}]\n"),
            "variable CONFIG_TEST_UNSET_SECRET is not set",
        ),
    ] {
        let file = TempFile::new(name, &body);
        let text = format!(
            "{:#}",
            config_source::load_file(file.path(), Secrets::Require).unwrap_err()
        );
        assert!(text.contains(expected), "{name}: {text}");
        assert!(text.contains(file.path()), "{name}: {text}");
    }
    // A missing secret passes with --secrets=skip; a missing file never does.
    let file = TempFile::new(
        "skip",
        &format!("{BASE}[secrets]\nk = {{ env = \"CONFIG_TEST_UNSET_SECRET\" }}\n{a}headers = [{{ name = \"X-Key\", value = \"{{secret}}\", secret = \"k\" }}]\n"),
    );
    config_source::load_file(file.path(), Secrets::Skip).unwrap();
    assert!(config_source::load_file("/nonexistent/gateway.toml", Secrets::Skip).is_err());
}

#[test]
fn secrets_come_from_variables_and_files_and_are_never_printed() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    apply_env(&[("CONFIG_TEST_KEY".to_string(), "key-from-env".to_string())]);
    let secret = TempFile::new("secret", "key-from-file\n");
    let body = format!(
        "{BASE}[secrets]\ne = {{ env = \"CONFIG_TEST_KEY\" }}\nf = {{ file = {:?} }}\n[integrations.a]\nalias = \"a.example\"\nupstream = \"https://a-api.example\"\nroutes = [\"GET /v1/a\"]\nheaders = [{{ name = \"X-Key\", value = \"{{secret}}\", secret = \"e\" }}, {{ name = \"Authorization\", value = \"Bearer {{secret}}\", secret = \"f\" }}]\n",
        secret.path()
    );
    let file = TempFile::new("secrets", &body);
    let loaded = config_source::load_file(file.path(), Secrets::Require).unwrap();
    assert_eq!(
        loaded.policy["BACKEND_HEADERS"],
        "a.example=X-Key:key-from-env,a.example=Authorization:Bearer key-from-file"
    );
    let printed =
        policy_file::canonical_json(&config_source::file_canonical(&loaded.file).unwrap());
    assert!(!printed.contains("key-from"), "{printed}");
    // A changed secret value is a difference for compare, named by its key only.
    let mut env = loaded.policy.clone();
    env.insert(
        "BACKEND_HEADERS".to_string(),
        "a.example=X-Key:other-value,a.example=Authorization:Bearer key-from-file".to_string(),
    );
    let resolve = |n: &str| config_source::resolve_secret(&loaded.file, n, Secrets::Require);
    let c = config_source::compare(&env, &loaded.file, &resolve).unwrap();
    assert!(!c.matches);
    assert_eq!(c.keys, vec!["authorities.a.example.headers".to_string()]);
    assert!(!format!("{c:?}").contains("other-value") && !format!("{c:?}").contains("key-from"));
    assert!(
        config_source::compare(&loaded.policy, &loaded.file, &resolve)
            .unwrap()
            .matches
    );
}

#[test]
fn compare_names_the_differing_keys() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let vars = read_env("mainnet");
    apply_env(&vars);
    let export = export_of(&vars);
    let mut file = export.file.clone();
    let first = file.integrations.keys().next().unwrap().clone();
    file.integrations.get_mut(&first).unwrap().rate_limit = Some("1/60s".to_string());
    file.host_list.max_age_secs = Some(7);
    let c = config_source::compare(&config_source::env_policy(), &file, &|n: &str| {
        export.resolve(n)
    })
    .unwrap();
    assert!(!c.matches);
    let alias = &file.integrations[&first].alias;
    assert_eq!(
        c.keys,
        vec![
            format!("authorities.{alias}.rate_limit"),
            "host_list".to_string()
        ]
    );
}

#[test]
fn with_the_file_in_force_the_policy_variables_of_the_environment_are_ignored() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let vars: Vec<(String, String)> = [
        ("BACKENDS", "env.example=https://env-api.example"),
        ("GATEWAY_HOSTS", "env-gw.example"),
        ("LWD_ADDR", "lwd.example:9067"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    apply_env(&vars);
    let file = TempFile::new(
        "inforce",
        &format!(
            "{BASE}[integrations.a]\nalias = \"a.example\"\nupstream = \"https://a-api.example\"\n"
        ),
    );
    let loaded = config_source::load_file(file.path(), Secrets::Require).unwrap();
    let config = config_source::with_policy(loaded.policy.clone(), || Config::from_env().unwrap());
    assert_eq!(
        config.backends.keys().collect::<Vec<_>>(),
        vec!["a.example"]
    );
    assert_eq!(config.gateway_hosts, vec!["gw.example".to_string()]);
    // A deployment variable still comes from the environment.
    assert_eq!(config.lwd_addr, "lwd.example:9067");
    assert_eq!(
        config_source::ignored_env_keys(&config_source::env_policy()),
        vec!["BACKENDS".to_string(), "GATEWAY_HOSTS".to_string()]
    );
    // Outside the scope the environment is in force again.
    let config = Config::from_env().unwrap();
    assert_eq!(
        config.backends.keys().collect::<Vec<_>>(),
        vec!["env.example"]
    );
}

/// The binary's command line on the fixtures: the actions print what the library computes and
/// exit 0, 1 or 2.
#[test]
fn the_command_line_actions() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let bin = env!("CARGO_BIN_EXE_zodl-ohttp-gateway");
    let vars = read_env("mainnet");
    let toml_path = fixtures().join("mainnet.toml");
    let toml_path = toml_path.to_str().unwrap();
    let run = |args: &[&str], extra: &[(&str, &str)]| {
        let mut cmd = std::process::Command::new(bin);
        cmd.env_clear().args(args);
        for (k, v) in &vars {
            cmd.env(k, v);
        }
        for (k, v) in extra {
            cmd.env(k, v);
        }
        let out = cmd.output().unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let committed = std::fs::read_to_string(toml_path).unwrap();
    let (code, stdout, _) = run(&["--export-config"], &[]);
    assert_eq!((code, stdout.as_str()), (Some(0), committed.as_str()));
    let snapshot: Value = serde_json::from_str(
        &std::fs::read_to_string(fixtures().join("mainnet.effective.json")).unwrap(),
    )
    .unwrap();
    let canonical = policy_file::canonical_json(&snapshot) + "\n";
    let (code, stdout, _) = run(&["--print-effective-config"], &[]);
    assert_eq!((code, stdout.as_str()), (Some(0), canonical.as_str()));
    let (code, stdout, _) = run(
        &["--config", toml_path, "--print-effective-config"],
        &[("CONFIG_SOURCE", "file")],
    );
    assert_eq!((code, stdout.as_str()), (Some(0), canonical.as_str()));
    let env: BTreeMap<String, String> = vars.iter().cloned().collect();
    let digest = config_source::env_digest(&env).unwrap();
    let (code, stdout, _) = run(
        &["--check-config", "--secrets=skip"],
        &[("GATEWAY_CONFIG_FILE", toml_path)],
    );
    assert_eq!(code, Some(0), "{stdout}");
    assert!(
        stdout.starts_with(&format!("config OK: {toml_path}")) && stdout.contains(&digest),
        "{stdout}"
    );
    // Without the secrets' variables the default (require) refuses, naming the variable.
    let (code, _, stderr) = run(&["--config", toml_path, "--check-config"], &[]);
    assert_eq!(code, Some(1), "{stderr}");
    assert!(
        stderr.contains("config INVALID") && stderr.contains("is not set"),
        "{stderr}"
    );
    let bad = TempFile::new("cli-bad", "schema = 1\ncolor = 1\n");
    let (code, _, stderr) = run(
        &["--config", bad.path(), "--check-config", "--secrets=skip"],
        &[],
    );
    assert_eq!(code, Some(1), "{stderr}");
    for args in [
        &["--unknown"][..],
        &["--check-config", "--export-config"],
        &["--secrets=skip"],
    ] {
        let (code, _, stderr) = run(args, &[]);
        assert_eq!(code, Some(2), "{args:?}: {stderr}");
        assert!(stderr.contains("usage:"), "{stderr}");
    }
    let (code, stdout, _) = run(&["--help"], &[]);
    assert_eq!(code, Some(0));
    assert!(stdout.starts_with("usage:"));
}

#[test]
fn the_example_file_is_valid() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    apply_env(&[]);
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config.example.toml");
    let loaded = config_source::load_file(path.to_str().unwrap(), Secrets::Skip).unwrap();
    assert!(loaded.warnings.is_empty());
    assert_eq!(
        loaded.policy.get("NEAR_ALIAS").map(String::as_str),
        Some("swap.example")
    );
}

/// The digest of `ohttp_config_info` is the same for a file and the environment it stands for,
/// whatever the declared kind of a keyed alias or the case of a method token.
#[test]
fn the_digest_is_the_behaviour_of_the_policy() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    apply_env(&[("QUOTES_KEY".to_string(), "quotes-key-1".to_string())]);
    let body = format!(
        "{BASE}[secrets]\nk = {{ env = \"QUOTES_KEY\" }}\n[integrations.q]\nalias = \"q.example\"\nupstream = \"https://q-api.example\"\nkind = \"swapkit\"\nroutes = [\"get /tokens\", \"POST /v1/quote\"]\nheaders = [{{ name = \"x-api-key\", value = \"{{secret}}\", secret = \"k\" }}]\nquery_rules = [\"GET /tokens?provider=EXAMPLE\", \"POST /v1/quote?\"]\n"
    );
    let file = TempFile::new("digest", &body);
    let loaded = config_source::load_file(file.path(), Secrets::Require).unwrap();
    let file_digest = config_source::policy_digest(&loaded.file).unwrap();
    // The environment the file stands for.
    assert_eq!(
        config_source::env_digest(&loaded.policy).unwrap(),
        file_digest
    );
    // The same policy written as cmc, or generic, with an upper-case method.
    for (from, to) in [
        ("swapkit", "cmc"),
        ("kind = \"swapkit\"\n", ""),
        ("get /tokens", "GET /tokens"),
    ] {
        let other = TempFile::new("digest-other", &body.replace(from, to));
        let other = config_source::load_file(other.path(), Secrets::Require).unwrap();
        assert_eq!(
            config_source::policy_digest(&other.file).unwrap(),
            file_digest,
            "{to}"
        );
    }
    // A different policy, a different digest.
    let other = TempFile::new(
        "digest-differs",
        &body
            .replace("POST /v1/quote\"]", "POST /v1/quote\", \"GET /v1/x\"]")
            .replace(
                "\"POST /v1/quote?\"]",
                "\"POST /v1/quote?\", \"GET /v1/x?\"]",
            ),
    );
    let other = config_source::load_file(other.path(), Secrets::Require).unwrap();
    assert_ne!(
        config_source::policy_digest(&other.file).unwrap(),
        file_digest
    );
}

#[test]
fn a_secret_must_be_a_usable_value() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    apply_env(&[
        ("BLANK".to_string(), "  ".to_string()),
        ("BREAK".to_string(), "a\nb".to_string()),
        ("GOOD".to_string(), "good-value".to_string()),
    ]);
    let header = "[integrations.a]\nalias = \"a.example\"\nupstream = \"https://a-api.example\"\nheaders = [{ name = \"X-Key\", value = \"{secret}\", secret = \"used\" }]\n";
    let two_lines = TempFile::new("secret-two-lines", "a\nb\n");
    let crlf = TempFile::new("secret-crlf", "crlf-value\r\n");
    let dir = std::env::temp_dir();
    for (name, source, expected) in [
        ("blank", "{ env = \"BLANK\" }".to_string(), "is empty"),
        (
            "break",
            "{ env = \"BREAK\" }".to_string(),
            "control character",
        ),
        (
            "unset",
            "{ env = \"CONFIG_TEST_UNSET\" }".to_string(),
            "is not set",
        ),
        (
            "lines",
            format!("{{ file = {:?} }}", two_lines.path()),
            "control character",
        ),
        (
            "dir",
            format!("{{ file = {:?} }}", dir.to_str().unwrap()),
            "not a regular file",
        ),
        (
            "missing",
            "{ file = \"/nonexistent/secret\" }".to_string(),
            "not found",
        ),
    ] {
        let body = format!("{BASE}[secrets]\nused = {source}\n{header}");
        let file = TempFile::new(&format!("secret-{name}"), &body);
        let text = format!(
            "{:#}",
            config_source::load_file(file.path(), Secrets::Require).unwrap_err()
        );
        assert!(
            text.contains(expected) && text.contains("secret 'used'"),
            "{name}: {text}"
        );
        assert!(!text.contains("a\nb"), "{name}: {text}");
    }
    // Exactly one final CRLF is removed.
    let body = format!(
        "{BASE}[secrets]\nused = {{ file = {:?} }}\n{header}",
        crlf.path()
    );
    let file = TempFile::new("secret-crlf-ok", &body);
    let loaded = config_source::load_file(file.path(), Secrets::Require).unwrap();
    assert_eq!(
        loaded.policy["BACKEND_HEADERS"],
        "a.example=X-Key:crlf-value"
    );
    // Every declared secret must resolve, used or not; --secrets=skip reads none.
    let body = format!("{BASE}[secrets]\nused = {{ env = \"GOOD\" }}\nspare = {{ env = \"CONFIG_TEST_UNSET\" }}\n{header}");
    let file = TempFile::new("secret-spare", &body);
    let text = format!(
        "{:#}",
        config_source::load_file(file.path(), Secrets::Require).unwrap_err()
    );
    assert!(text.contains("secret 'spare'"), "{text}");
    config_source::load_file(file.path(), Secrets::Skip).unwrap();
}

#[test]
fn check_config_validates_the_dynamic_hosts_with_the_production_parser() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    apply_env(&[]);
    for (name, section, expected) in [
        ("nested", "[dynamic_hosts]\nsources = [{ name = \"v\", url = \"https://v.example/h.json\", lists = [{ pointer = \"/h\", routes = \"GET /*\", colour = \"red\" }] }]\n", "DYNAMIC_HOST_SOURCES"),
        ("cidr", "[dynamic_hosts]\ndeny_cidrs = [\"not-a-cidr\"]\n", "not-a-cidr"),
    ] {
        let file = TempFile::new(name, &format!("{BASE}{section}"));
        let text = format!("{:#}", config_source::load_file(file.path(), Secrets::Skip).unwrap_err());
        assert!(text.contains(expected) || text.to_lowercase().contains("cidr"), "{name}: {text}");
    }
}

/// No value of a malformed file reaches stdout or stderr.
#[test]
fn a_malformed_file_never_shows_its_values() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let bin = env!("CARGO_BIN_EXE_zodl-ohttp-gateway");
    const SENTINEL: &str = "sentinel-secret-41c9";
    for (name, body) in [
        ("type", format!("{BASE}[value_sources.f]\nalias = \"a\"\nroute = \"GET /x\"\npointer = \"/p\"\nrefresh_secs = \"{SENTINEL}\"\n")),
        ("syntax", format!("{BASE}relay_secret_on_key_config = \"{SENTINEL}\n")),
        ("separator", format!("{BASE}[integrations.a]\nalias = \"a.example\"\nupstream = \"https://a\"\nheaders = [{{ name = \"X\", value = \"{SENTINEL},x\" }}]\n")),
        ("schema", format!("schema = \"{SENTINEL}\"\n")),
    ] {
        let file = TempFile::new(&format!("sentinel-{name}"), &body);
        for args in [&["--check-config", "--secrets=skip"][..], &["--print-effective-config"][..]] {
            let out = std::process::Command::new(bin)
                .env_clear()
                .env("CONFIG_SOURCE", "file")
                .args(["--config", file.path()])
                .args(args)
                .output()
                .unwrap();
            assert_eq!(out.status.code(), Some(1), "{name} {args:?}");
            let all = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(!all.contains(SENTINEL), "{name} {args:?}: {all}");
            assert!(all.contains("config INVALID"), "{name} {args:?}: {all}");
        }
    }
}

/// Small generated environments: the parsers read the same tables from their file.
#[test]
fn generated_environments_read_the_same_from_their_file() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let methods = ["GET", "get", "POST", "Patch"];
    for n in 0..24usize {
        let m = methods[n % methods.len()];
        let mut vars: Vec<(String, String)> = vec![
            ("BACKENDS".into(), format!("a{n}.example=https://a-api.example,b.example=https://b-api.example")),
            ("BACKENDS_POLICY".into(), format!("a{n}.example={m} /v{n}/x,GET /v{n}/y;gw.example=POST /*")),
            ("GATEWAY_HOSTS".into(), "gw.example,GW2.example:443".into()),
            ("BACKEND_HEADERS".into(), format!("a{n}.example=X-K:k{n},a{n}.example=X-K:k{},b.example=Authorization:Bearer t{n}", n + 1)),
            ("THIRD_PARTY_RATE_LIMITS".into(), format!("a{n}.example={}/60s", n + 1)),
            ("REPLAY_READ_ROUTES".into(), format!("lwd=POST /r{n};a{n}.example=GET /v{n}/y")),
        ];
        if n % 2 == 0 {
            vars.push((
                "THIRD_PARTY_CACHE_ROUTES".into(),
                format!("a{n}.example=GET /v{n}/y@{}", n + 10),
            ));
            vars.push(("BACKENDS_POLICY_DEFAULT".into(), "allow".into()));
        }
        if n % 3 == 0 {
            vars.push(("FLEXA_ALIAS".into(), "b.example".into()));
            vars.push(("THIRD_PARTY_HOSTS_PUBLISH".into(), "Dynamic".into()));
        }
        if n % 4 == 1 {
            vars.push(("NEAR_ALIAS".into(), format!("a{n}.example")));
            vars.push(("RELAY_SECRET_ON_KEY_CONFIG".into(), "require".into()));
        }
        apply_env(&vars);
        let env = process_env();
        let from_env = views(&env);
        let (text, export) = config_source::export_checked(&config_source::env_policy()).unwrap();
        let file = policy_file::parse(&text).unwrap().file;
        let rendered: BTreeMap<String, String> =
            policy_file::render(&file, &|s: &str| export.resolve(s))
                .unwrap()
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect();
        let from_file = config_source::with_policy(rendered, || views(&env));
        assert_eq!(from_file, from_env, "{n}");
        assert_eq!(
            config_source::env_digest(&config_source::env_policy()).unwrap(),
            config_source::policy_digest(&file).unwrap(),
            "{n}"
        );
    }
}

/// A secret file that is a FIFO without a writer is refused at once, never waited on.
#[cfg(unix)]
#[test]
fn a_fifo_secret_is_refused_without_waiting() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Not a TempFile name: writing the configuration must not open the FIFO.
    let fifo = std::env::temp_dir().join(format!("config-file-secret-fifo-{}", std::process::id()));
    let _ = std::fs::remove_file(&fifo);
    assert!(std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let body = format!(
        "{BASE}[secrets]\nk = {{ file = {:?} }}\n[integrations.a]\nalias = \"a.example\"\nupstream = \"https://a-api.example\"\nheaders = [{{ name = \"X\", value = \"{{secret}}\", secret = \"k\" }}]\n",
        fifo.to_str().unwrap()
    );
    let file = TempFile::new("fifo-config", &body);
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_zodl-ohttp-gateway"))
        .env_clear()
        .args(["--config", file.path(), "--check-config"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > std::time::Duration::from_secs(20) {
            let _ = child.kill();
            let _ = std::fs::remove_file(&fifo);
            panic!("--check-config waited on the FIFO");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let out = child.wait_with_output().unwrap();
    let _ = std::fs::remove_file(&fifo);
    assert_eq!(status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not a regular file"), "{stderr}");
}

/// Equivalent spellings of the dynamic hosts: one digest, and compare matches.
#[test]
fn equivalent_deny_lists_and_empty_sources_are_one_policy() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    apply_env(&[]);
    let a = TempFile::new(
        "spelling-a",
        &format!("{BASE}[dynamic_hosts]\ndeny_cidrs = [\"2001:db8::/32\", \"192.0.2.0/28\", \"192.0.2.0/28\"]\nsources = []\n"),
    );
    let b = TempFile::new(
        "spelling-b",
        &format!("{BASE}[dynamic_hosts]\ndeny_cidrs = [\"192.0.2.0/28\", \"2001:db8::/32\"]\n"),
    );
    let a = config_source::load_file(a.path(), Secrets::Require).unwrap();
    let b = config_source::load_file(b.path(), Secrets::Require).unwrap();
    assert_eq!(
        config_source::policy_digest(&a.file).unwrap(),
        config_source::policy_digest(&b.file).unwrap()
    );
    let none = |_: &str| -> anyhow::Result<String> { anyhow::bail!("no secret") };
    assert!(
        config_source::compare(&b.policy, &a.file, &none)
            .unwrap()
            .matches
    );
    assert!(
        config_source::compare(&a.policy, &b.file, &none)
            .unwrap()
            .matches
    );
}

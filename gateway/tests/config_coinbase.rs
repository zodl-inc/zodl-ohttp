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

//! A `coinbase` integration in the configuration file: its key document read from a secret
//! file (a key generated here), the policy the file stands for, `--check-config`, and how the
//! comparison with an environment (the export's check) reports a table no environment can
//! express.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine;
use ed25519_dalek::SigningKey;
use zodl_ohttp_gateway::config::Config;
use zodl_ohttp_gateway::config_source::{self, Secrets};
use zodl_ohttp_gateway::origin::{OriginSettings, RouteClass};
use zodl_ohttp_integrations::core::config as policy_file;

/// The process environment is global: every test of this file holds this lock.
static ENV_LOCK: Mutex<()> = Mutex::new(());

const ALIAS: &str = "onramp.example";

/// A file in the temporary directory, removed on drop.
struct TempFile(PathBuf);

impl TempFile {
    fn new(name: &str, content: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "config-coinbase-test-{}-{name}",
            std::process::id()
        ));
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

/// A fresh key and its CDP key document (`{"id", "privateKey"}`, the 64-byte key pair).
fn generated_key() -> (SigningKey, String) {
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let mut pair = key.to_bytes().to_vec();
    pair.extend_from_slice(key.verifying_key().as_bytes());
    let document = format!(
        "{{\"id\":\"11111111-2222-4333-8444-555555555555\",\"privateKey\":\"{}\"}}",
        base64::engine::general_purpose::STANDARD.encode(&pair)
    );
    (key, document)
}

fn table(secret_path: &str) -> String {
    format!(
        r#"schema = 1
gateway_hosts = ["gw.example"]

[secrets]
cdp_key = {{ file = {secret_path:?} }}

[integrations.onramp]
kind = "coinbase"
alias = "{ALIAS}"
upstream = "https://cdp-api.example"
auth = {{ type = "jwt_eddsa", secret = "cdp_key", ttl_secs = 120 }}
redirect_url = "wallet://onramp/return"
enabled = true
rate_limit = "30/60s"
status_rate_limit = "120/60s"

[integrations.onramp.availability]
countries = {{ US = {{ buy = true, sell = true }} }}
"#
    )
}

/// A host file that makes the gateway a testnet one.
const TESTNET_HOST: &str = "schema = 1\n[settings]\nnetwork = \"testnet\"\n";

/// Every policy and secret variable of the process removed (this test's process only).
fn clear_policy_env() {
    for k in policy_file::POLICY_ENV_KEYS {
        std::env::remove_var(k);
    }
    std::env::remove_var("CONFIG_SOURCE");
    std::env::remove_var("GATEWAY_CONFIG_FILE");
}

#[test]
fn a_coinbase_table_loads_with_its_key_from_a_secret_file() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_policy_env();
    let (key, document) = generated_key();
    let secret = TempFile::new("key", &format!("{document}\n"));
    let file = TempFile::new("table.toml", &table(secret.path()));
    let loaded = config_source::load_file(file.path(), Secrets::Require).unwrap();
    assert_eq!(
        loaded.policy.get("BACKENDS").map(String::as_str),
        Some("onramp.example=https://cdp-api.example")
    );
    assert!(!loaded.policy.contains_key("THIRD_PARTY_RATE_LIMITS"));
    assert!(!loaded.policy.contains_key("REPLAY_READ_ROUTES"));
    // The key document is not part of the rendered policy.
    assert!(!loaded.policy.values().any(|v| v.contains("privateKey")));
    // The debug form names the entries, never a value.
    let debug = format!("{loaded:?}");
    assert!(!debug.contains("privateKey"), "{debug}");

    // The policy in force: the provider with its key; every route a WRITE.
    let (config, origin) = loaded.run_in(|| {
        (
            Config::from_env().unwrap(),
            OriginSettings::from_env().unwrap(),
        )
    });
    let entry = config.coinbase.get(ALIAS).expect("the coinbase provider");
    assert!(entry.provider.has_signer() && entry.provider.enabled());
    assert!(entry.key_problem().is_none());
    assert_eq!(entry.provider.upstream_host(), "cdp-api.example");
    assert!(config.backends.contains_key(ALIAS));
    for (method, path) in zodl_ohttp_integrations::coinbase::ROUTES {
        assert_eq!(
            origin
                .replay_read_routes
                .classify(false, ALIAS, method, path),
            RouteClass::Write
        );
    }
    let _ = key;

    // Outside the file's scope (nothing installed, the environment never read): no provider.
    let config = Config::from_env().unwrap();
    assert!(config.coinbase.is_empty());

    // --secrets=skip: the table checks, without a key.
    let skipped = config_source::load_file(file.path(), Secrets::Skip).unwrap();
    let config = skipped.run_in(|| Config::from_env().unwrap());
    assert!(!config.coinbase.get(ALIAS).unwrap().provider.has_signer());

    // Mainnet only: the network of the files (the environment's is not read).
    std::env::set_var("NETWORK", "testnet");
    config_source::load_file(file.path(), Secrets::Require).unwrap();
    std::env::remove_var("NETWORK");
    let testnet = TempFile::new("testnet-host.toml", TESTNET_HOST);
    let text = format!(
        "{:#}",
        config_source::load_files(file.path(), Some(testnet.path()), Secrets::Require).unwrap_err()
    );
    assert!(text.contains("mainnet gateway only"), "{text}");

    // A key in a variable is refused (files only), by the secret's name, never its value.
    std::env::set_var("CONFIG_TEST_CDP_KEY", &document);
    let env_file = TempFile::new(
        "env.toml",
        &table(secret.path()).replace(
            &format!("cdp_key = {{ file = {:?} }}", secret.path()),
            "cdp_key = { env = \"CONFIG_TEST_CDP_KEY\" }",
        ),
    );
    for mode in [Secrets::Require, Secrets::Skip] {
        let text = format!(
            "{:#}",
            config_source::load_file(env_file.path(), mode).unwrap_err()
        );
        assert!(
            text.contains("secret 'cdp_key'") && text.contains("files only"),
            "{text}"
        );
        assert!(!text.contains("privateKey"), "{text}");
    }
    std::env::remove_var("CONFIG_TEST_CDP_KEY");

    // The 32-byte seed form of the key works too.
    let seed = format!(
        "{{\"id\":\"k-1\",\"privateKey\":\"{}\"}}",
        base64::engine::general_purpose::STANDARD.encode(key.to_bytes())
    );
    let seed_secret = TempFile::new("seed", &seed);
    let seed_file = TempFile::new("seed.toml", &table(seed_secret.path()));
    config_source::load_file(seed_file.path(), Secrets::Require).unwrap();
}

#[test]
fn a_bad_key_or_a_missing_secret_is_refused_without_showing_it() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_policy_env();
    let (key, _) = generated_key();
    let mut pair = key.to_bytes().to_vec();
    pair.extend_from_slice(key.verifying_key().as_bytes());
    pair[40] ^= 1;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&pair);
    for (name, content, expected) in [
        (
            "mismatch",
            format!("{{\"id\":\"k\",\"privateKey\":\"{encoded}\"}}"),
            "public half",
        ),
        (
            "short",
            "{\"id\":\"k\",\"privateKey\":\"AAAA\"}".to_string(),
            "private key",
        ),
        (
            "pem",
            "{\"name\":\"k\",\"privateKey\":\"-----BEGIN EC PRIVATE KEY-----\"}".to_string(),
            "key document",
        ),
    ] {
        // The serving process starts: the provider has no signer, the problem names the secret.
        let secret = TempFile::new(name, &content);
        let file = TempFile::new(&format!("{name}.toml"), &table(secret.path()));
        let loaded = config_source::load_file(file.path(), Secrets::Require).unwrap();
        let config = loaded.run_in(|| Config::from_env().unwrap());
        let entry = config.coinbase.get(ALIAS).unwrap();
        assert!(!entry.provider.has_signer());
        let text = entry.key_problem().unwrap();
        assert!(
            text.contains(expected) && text.contains("secret 'cdp_key'"),
            "{name}: {text}"
        );
        assert!(
            !text.contains(&encoded) && !text.contains("BEGIN"),
            "{text}"
        );
    }
    // A multi-line document is no single-line secret.
    let secret = TempFile::new("multiline", "{\n\"id\": \"k\"\n}\n");
    let file = TempFile::new("multiline.toml", &table(secret.path()));
    let text = format!(
        "{:#}",
        config_source::load_file(file.path(), Secrets::Require).unwrap_err()
    );
    assert!(text.contains("line break"), "{text}");
    let file = TempFile::new("missing.toml", &table("/nonexistent/cdp_key"));
    let text = format!(
        "{:#}",
        config_source::load_file(file.path(), Secrets::Require).unwrap_err()
    );
    assert!(text.contains("secret 'cdp_key'"), "{text}");
}

#[test]
fn the_key_is_a_secret_of_the_common_file() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_policy_env();
    let (_, document) = generated_key();
    let secret = TempFile::new("host-key", &document);
    // The key declared in the host file only: refused, the common file names an unmapped secret.
    let common = TempFile::new(
        "host-common.toml",
        &table(secret.path()).replace(&format!("cdp_key = {{ file = {:?} }}\n", secret.path()), ""),
    );
    let host = TempFile::new(
        "host.toml",
        &format!(
            "schema = 1\n[secrets]\ncdp_key = {{ file = {:?} }}\n",
            secret.path()
        ),
    );
    let text = format!(
        "{:#}",
        config_source::load_files(common.path(), Some(host.path()), Secrets::Require).unwrap_err()
    );
    assert!(
        text.contains("names the secret 'cdp_key', which [secrets] does not map"),
        "{text}"
    );
}

#[test]
fn an_environment_cannot_stand_for_a_coinbase_table() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_policy_env();
    let (_, document) = generated_key();
    let secret = TempFile::new("compare-key", &document);
    let file = TempFile::new("compare.toml", &table(secret.path()));
    let loaded = config_source::load_file(file.path(), Secrets::Require).unwrap();
    let resolve = |n: &str| config_source::resolve_secret(&loaded.file, n, Secrets::Require);
    // Not even the environment the rest of the file renders to: no variable assigns the kind.
    let env: BTreeMap<String, String> = loaded
        .policy
        .iter()
        .filter(|(k, _)| policy_file::POLICY_ENV_KEYS.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let c = config_source::compare(&env, &loaded.file, &resolve).unwrap();
    assert!(!c.matches);
    assert_eq!(
        c.keys,
        vec![
            format!("authorities.{ALIAS}.coinbase"),
            format!("authorities.{ALIAS}.kind")
        ]
    );
    // The digest covers the switch.
    let off = TempFile::new(
        "compare-off.toml",
        &table(secret.path()).replace("enabled = true", "enabled = false"),
    );
    let off = config_source::load_file(off.path(), Secrets::Require).unwrap();
    assert_ne!(
        config_source::policy_digest(&loaded.file).unwrap(),
        config_source::policy_digest(&off.file).unwrap()
    );
    let printed =
        policy_file::canonical_json(&config_source::file_canonical(&loaded.file).unwrap());
    assert!(printed.contains("\"kind\":\"coinbase\""), "{printed}");
    assert!(
        !printed.contains("privateKey") && !printed.contains("cdp_key"),
        "{printed}"
    );
}

/// Run the binary with `args` and `env` only; its exit code, stdout and stderr. Killed after
/// 60 seconds.
fn run(args: &[&str], env: &[(&str, &str)]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_zodl-ohttp-gateway"));
    cmd.env_clear()
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("{args:?} did not exit within 60 s");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = child.wait_with_output().unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn check_config_of_a_coinbase_table() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (_, document) = generated_key();
    let secret = TempFile::new("cli-key", &document);
    let file = TempFile::new("cli.toml", &table(secret.path()));
    let (code, stdout, stderr) = run(&["--config", file.path(), "--check-config"], &[]);
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    assert!(stdout.starts_with("config OK:"), "{stdout}");
    let (code, stdout, _) = run(
        &["--config", file.path(), "--check-config", "--secrets=skip"],
        &[],
    );
    assert_eq!(code, Some(0), "{stdout}");
    // The printed policy has the table, never the key.
    let (code, stdout, _) = run(
        &["--config", file.path(), "--print-effective-config"],
        &[("CONFIG_SOURCE", "file")],
    );
    assert_eq!(code, Some(0));
    assert!(stdout.contains("\"kind\":\"coinbase\"") && !stdout.contains("privateKey"));
    // Without the secrets the table is still checked like a serving process builds it:
    // mainnet only (the network of the files), its upstream.
    let testnet = TempFile::new("cli-testnet-host.toml", TESTNET_HOST);
    let (code, _, stderr) = run(
        &[
            "--config",
            file.path(),
            "--host-config",
            testnet.path(),
            "--check-config",
            "--secrets=skip",
        ],
        &[],
    );
    assert_eq!(code, Some(1));
    assert!(stderr.contains("mainnet gateway only"), "{stderr}");
    // A key that is not a key: refused, the key not shown.
    let bad = TempFile::new(
        "cli-bad-key",
        "{\"id\":\"k\",\"privateKey\":\"c2VjcmV0LXZhbHVl\"}",
    );
    let bad_file = TempFile::new("cli-bad.toml", &table(bad.path()));
    let (code, stdout, stderr) = run(&["--config", bad_file.path(), "--check-config"], &[]);
    assert_eq!(code, Some(1), "{stdout}");
    assert!(
        stderr.contains("config INVALID") && stderr.contains("private key"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("c2VjcmV0") && !stdout.contains("c2VjcmV0"),
        "{stderr}"
    );
    // A table that is not valid: refused at the file check.
    let invalid = TempFile::new(
        "cli-invalid.toml",
        &table(secret.path()).replace("rate_limit = \"30/60s\"\n", ""),
    );
    let (code, _, stderr) = run(
        &[
            "--config",
            invalid.path(),
            "--check-config",
            "--secrets=skip",
        ],
        &[],
    );
    assert_eq!(code, Some(1));
    assert!(stderr.contains("needs 'rate_limit'"), "{stderr}");
}

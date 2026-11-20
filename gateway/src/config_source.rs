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

//! Where the routing policy comes from: the environment variables, or the configuration file
//! ([`zodl_ohttp_integrations::core::config`]).
//!
//! `CONFIG_SOURCE` (default `env`):
//! - `env`: the environment, as before; no file is read.
//! - `compare`: the environment is in force; the file (`--config <path>` or
//!   `GATEWAY_CONFIG_FILE`) is loaded and checked as well and both policies are compared:
//!   `ohttp_config_compare_match` 1 or 0, and one log line naming the differing keys (never a
//!   value). A file that does not load is logged and counts as a mismatch; it never stops the
//!   gateway.
//! - `file`: the file is in force; the policy variables ([`POLICY_ENV_KEYS`]) of the
//!   environment are ignored, with one warning naming those that are set.
//!
//! The settings other than the policy ([`crate::settings::SETTINGS`]: tuning, deployment,
//! secrets) come from the environment as well, unless the files carry them: a `[settings]`
//! table in the common file, or a host file (`--host-config <path>` or
//! `GATEWAY_HOST_CONFIG_FILE`, `[settings]` and `[secrets]` only, merged after the common file;
//! a key in both is an error). Then `file` takes every setting from the files too (the
//! environment's are ignored, with one warning naming those that are set; a secret is read
//! where its `[secrets]` entry points), and `compare` compares them as well
//! (`ohttp_config_settings_compare_match`). A process in `file` mode then needs no variable but
//! `CONFIG_SOURCE` and the two paths ([`crate::settings::BOOTSTRAP_ENV_KEYS`]).
//!
//! The files are turned into the values of the variables they stand for, which every parser
//! reads through [`var`]; the parsers are the same in all three modes.
//! `ohttp_config_info{source, digest, tuning_digest}` names the policy and the tuning in force.
//!
//! The command line (`zodl-ohttp-gateway [--config <path>] [--host-config <path>]
//! [--check-config [--secrets=require|skip] | --print-effective-config | --export-config
//! [--host <path>]]`, or `backfill`): see [`Command`].

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use zodl_ohttp_integrations::core::config::{
    self as policy_file, HeaderValues, PolicyFile, SecretRef, POLICY_ENV_KEYS,
};

use crate::settings::{self, FileValue};

/// The variable naming the policy source.
pub const SOURCE_ENV: &str = "CONFIG_SOURCE";
/// The variable naming the configuration file (`--config` wins).
pub const FILE_ENV: &str = "GATEWAY_CONFIG_FILE";
/// The variable naming the host file (`--host-config` wins).
pub const HOST_FILE_ENV: &str = "GATEWAY_HOST_CONFIG_FILE";

/// The policy in force for the whole process when the file is (`CONFIG_SOURCE=file`).
static FILE_POLICY: OnceLock<BTreeMap<String, String>> = OnceLock::new();
/// The settings in force for the whole process when the files carry them and are in force.
static FILE_SETTINGS: OnceLock<BTreeMap<String, String>> = OnceLock::new();

/// The variables of a [`with_policy`] / [`with_config`] scope.
struct Scope {
    policy: BTreeMap<String, String>,
    /// `None`: the settings of the process (the environment, or the files in force).
    settings: Option<BTreeMap<String, String>>,
}

thread_local! {
    /// The scope on this thread.
    static SCOPED: RefCell<Option<Arc<Scope>>> = const { RefCell::new(None) };
}

/// A variable as the gateway's parsers read it: a policy variable from the policy in force
/// (the file's, when it is), a setting from the settings in force (the files', when they carry
/// them and are in force), anything else from the environment.
pub fn var(key: &str) -> Result<String, std::env::VarError> {
    let from = |map: &BTreeMap<String, String>| {
        map.get(key).cloned().ok_or(std::env::VarError::NotPresent)
    };
    if POLICY_ENV_KEYS.contains(&key) {
        let scoped = SCOPED.with(|s| s.borrow().clone());
        let policy = scoped
            .as_deref()
            .map(|s| &s.policy)
            .or_else(|| FILE_POLICY.get());
        if let Some(policy) = policy {
            return from(policy);
        }
    } else if crate::settings::setting(key).is_some() {
        let scoped = SCOPED.with(|s| s.borrow().clone());
        let settings = scoped
            .as_deref()
            .and_then(|s| s.settings.as_ref())
            .or_else(|| FILE_SETTINGS.get());
        if let Some(settings) = settings {
            return from(settings);
        }
    }
    std::env::var(key)
}

/// An entry of the policy in force that is no environment variable (the settings of the
/// `coinbase` integrations, [`policy_file::COINBASE_RENDERED`]): only a configuration file in
/// force (the process's, or a [`with_policy`] scope) has it, never the environment.
pub fn file_value(key: &str) -> Option<String> {
    let scoped = SCOPED.with(|s| s.borrow().clone());
    scoped
        .as_deref()
        .map(|s| &s.policy)
        .or_else(|| FILE_POLICY.get())
        .and_then(|policy| policy.get(key).cloned())
}

/// The secret values a provider reads itself (the keys the `coinbase` integrations name), out
/// of those the files read once; wiped when dropped.
pub(crate) type ProviderSecrets = Arc<BTreeMap<String, zeroize::Zeroizing<String>>>;

/// The [`ProviderSecrets`] of the files in force (`CONFIG_SOURCE=file`).
static FILE_SECRETS: OnceLock<ProviderSecrets> = OnceLock::new();

thread_local! {
    /// The provider secrets of a [`with_secret_values`] scope on this thread.
    static SCOPED_SECRETS: RefCell<Option<ProviderSecrets>> = const { RefCell::new(None) };
}

/// The secrets of `values` (all those the files read) that the coinbase integrations of
/// `policy` name: only these are kept for a provider.
fn provider_secrets(
    policy: &BTreeMap<String, String>,
    values: &BTreeMap<String, String>,
) -> ProviderSecrets {
    let names: Vec<String> = policy
        .get(policy_file::COINBASE_RENDERED)
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|e| e["secret"]["name"].as_str().map(str::to_string))
        .collect();
    Arc::new(
        names
            .into_iter()
            .filter_map(|n| {
                let v = values.get(&n)?.clone();
                Some((n, zeroize::Zeroizing::new(v)))
            })
            .collect(),
    )
}

/// Run `f` with `values` as the provider secrets of this thread ([`secret_value`]): the checks
/// of loaded files see the secrets they read, without making them the process's.
pub(crate) fn with_secret_values<T>(values: ProviderSecrets, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<ProviderSecrets>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.0.take();
            SCOPED_SECRETS.with(|s| *s.borrow_mut() = previous);
        }
    }
    let previous = SCOPED_SECRETS.with(|s| s.borrow_mut().replace(values));
    let _restore = Restore(previous);
    f()
}

/// The value of the secret `name` as the files read it ([`with_secret_values`], else the files
/// in force), a copy wiped when dropped; `None` when no file read it for a provider.
pub(crate) fn secret_value(name: &str) -> Option<zeroize::Zeroizing<String>> {
    let scoped = SCOPED_SECRETS.with(|s| s.borrow().clone());
    let from = |m: &ProviderSecrets| m.get(name).cloned();
    match scoped {
        Some(values) => from(&values),
        None => FILE_SECRETS.get().and_then(from),
    }
}

fn with_scope<T>(scope: Scope, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<Arc<Scope>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.0.take();
            SCOPED.with(|s| *s.borrow_mut() = previous);
        }
    }
    let previous = SCOPED.with(|s| s.borrow_mut().replace(Arc::new(scope)));
    let _restore = Restore(previous);
    f()
}

/// Run `f` with `policy` (variable -> value) as the policy variables of this thread: what
/// `--check-config` and `compare` use to run the parsers on a file without making it the
/// process's policy. Parsers that set process-wide state (the dynamic hosts' deny list) only
/// validate inside such a scope ([`in_scope`]). The settings stay those of the process.
pub fn with_policy<T>(policy: BTreeMap<String, String>, f: impl FnOnce() -> T) -> T {
    with_scope(
        Scope {
            policy,
            settings: None,
        },
        f,
    )
}

/// [`with_policy`], with `settings` (variable -> value) as the settings of this thread too.
pub fn with_config<T>(
    policy: BTreeMap<String, String>,
    settings: BTreeMap<String, String>,
    f: impl FnOnce() -> T,
) -> T {
    with_scope(
        Scope {
            policy,
            settings: Some(settings),
        },
        f,
    )
}

/// Whether this thread runs inside [`with_policy`]: a validation, not the process's startup.
pub fn in_scope() -> bool {
    SCOPED.with(|s| s.borrow().is_some())
}

/// `CONFIG_SOURCE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Env,
    Compare,
    File,
}

impl Source {
    pub fn parse(raw: Option<&str>) -> Result<Self> {
        match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            None | Some("") | Some("env") => Ok(Self::Env),
            Some("compare") => Ok(Self::Compare),
            Some("file") => Ok(Self::File),
            Some(other) => bail!("Invalid {SOURCE_ENV} '{other}': must be env, compare or file"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::Compare => "compare",
            Self::File => "file",
        }
    }
}

/// What `--check-config` does with the secrets the file names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Secrets {
    /// Each must resolve (its variable set, its file readable).
    Require,
    /// None is read (a CI check without the secrets).
    Skip,
}

/// The value a secret gets under [`Secrets::Skip`].
const SKIPPED_SECRET: &str = "secret-not-read";

/// The largest secret file read.
pub const MAX_SECRET_FILE_BYTES: u64 = 64 * 1024;

/// The value of secret `name` of `file`: its variable, or its file (a regular file of at most
/// [`MAX_SECRET_FILE_BYTES`], exactly one final `\n` or `\r\n` removed). Empty, blank, or
/// holding a line break or another control character, it does not resolve. The error names the
/// secret and its source, never a value. No permission of the file is checked.
pub fn resolve_secret(file: &PolicyFile, name: &str, mode: Secrets) -> Result<String> {
    resolve_secret_in(&file.secrets, name, mode)
}

/// [`resolve_secret`] in the `[secrets]` entries `secrets`.
pub fn resolve_secret_in(
    secrets: &BTreeMap<String, SecretRef>,
    name: &str,
    mode: Secrets,
) -> Result<String> {
    if mode == Secrets::Skip {
        return Ok(SKIPPED_SECRET.to_string());
    }
    let r = secrets
        .get(name)
        .ok_or_else(|| anyhow!("secret '{name}' has no [secrets] entry"))?;
    read_secret(name, r.env.as_deref(), r.file.as_deref())
}

/// The value of the secret `name` read from its variable `env` or its file `file` (exactly one),
/// with the rules of [`resolve_secret`]. The buffers it is read into are wiped (on error paths
/// too); the value returned is the one the files keep ([`LoadedFile`]).
fn read_secret(name: &str, env: Option<&str>, file: Option<&str>) -> Result<String> {
    let (value, source) = match (env, file) {
        (Some(var), None) => (
            zeroize::Zeroizing::new(
                std::env::var(var)
                    .map_err(|_| anyhow!("secret '{name}': variable {var} is not set"))?,
            ),
            format!("variable {var}"),
        ),
        (None, Some(path)) => (read_secret_file(name, path)?, format!("file {path}")),
        _ => bail!("secret '{name}' needs exactly one of env or file"),
    };
    usable_secret(name, &source, String::clone(&value))
}

/// A secret's value as read from `source`, refused (by name and source only) when it is empty,
/// blank, or holds a line break or another control character.
fn usable_secret(name: &str, source: &str, value: String) -> Result<String> {
    if value.trim().is_empty() {
        bail!("secret '{name}': {source} is empty");
    }
    if value.chars().any(|c| c.is_control()) {
        bail!("secret '{name}': {source} holds a line break or another control character");
    }
    Ok(value)
}

fn read_secret_file(name: &str, path: &str) -> Result<zeroize::Zeroizing<String>> {
    use std::io::Read;
    // Non-blocking, so that a FIFO without a writer cannot hold the open; the type is checked
    // on the opened handle.
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let f = options
        .open(path)
        .map_err(|e| anyhow!("secret '{name}': file {path}: {}", e.kind()))?;
    let meta = f
        .metadata()
        .map_err(|e| anyhow!("secret '{name}': file {path}: {}", e.kind()))?;
    if !meta.is_file() {
        bail!("secret '{name}': {path} is not a regular file");
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    f.take(MAX_SECRET_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| anyhow!("secret '{name}': file {path}: {}", e.kind()))?;
    if bytes.len() as u64 > MAX_SECRET_FILE_BYTES {
        bail!("secret '{name}': file {path} is larger than {MAX_SECRET_FILE_BYTES} bytes");
    }
    let mut text = match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(text) => zeroize::Zeroizing::new(text),
        Err(e) => {
            drop(zeroize::Zeroizing::new(e.into_bytes()));
            bail!("secret '{name}': file {path} is not UTF-8");
        }
    };
    // In place: no copy of the value is left behind.
    if text.ends_with("\r\n") {
        let len = text.len() - 2;
        text.truncate(len);
    } else if text.ends_with('\n') {
        let len = text.len() - 1;
        text.truncate(len);
    }
    Ok(text)
}

/// A loaded configuration (the common file and, if given, the host file): its content,
/// warnings and the variables it stands for.
#[derive(Clone)]
pub struct LoadedFile {
    pub path: String,
    pub file: PolicyFile,
    pub warnings: Vec<String>,
    /// The policy variables, secrets resolved.
    pub policy: BTreeMap<String, String>,
    /// The host file, when one was given.
    pub host_path: Option<String>,
    /// Whether the files carry the settings (a `[settings]` table in the common file, or a
    /// host file): then they are in force with the policy, else the environment's are.
    pub carries_settings: bool,
    /// The settings of both files, as written (variable -> value).
    pub setting_values: BTreeMap<&'static str, FileValue>,
    /// The `[secrets]` entries of both files.
    pub secrets: BTreeMap<String, SecretRef>,
    /// The settings variables, secrets resolved (with [`Secrets::Skip`]: a whole secret left
    /// out, a template with a placeholder).
    pub settings: BTreeMap<String, String>,
    /// The value of every secret, read once (with [`Secrets::Require`]).
    pub(crate) secret_values: BTreeMap<String, String>,
    /// Of those, the ones the coinbase integrations name ([`secret_value`]).
    pub(crate) provider_secrets: ProviderSecrets,
}

impl std::fmt::Debug for LoadedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The variables carry the secrets: their names only.
        f.debug_struct("LoadedFile")
            .field("path", &self.path)
            .field("host_path", &self.host_path)
            .field("warnings", &self.warnings)
            .field("policy", &self.policy.keys().collect::<Vec<_>>())
            .field("settings", &self.settings.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl LoadedFile {
    /// Run `f` with these files as the configuration of this thread: their policy, their
    /// settings when they carry them, and the secret values they read.
    pub fn run_in<T>(&self, f: impl FnOnce() -> T) -> T {
        with_secret_values(self.provider_secrets.clone(), || {
            if self.carries_settings {
                with_config(self.policy.clone(), self.settings.clone(), f)
            } else {
                with_policy(self.policy.clone(), f)
            }
        })
    }

    /// The variables the `[secrets]` entries of the files read (they stay readable whatever
    /// the source).
    pub fn secret_variables(&self) -> Vec<String> {
        self.secrets
            .values()
            .filter_map(|r| r.env.clone())
            .collect()
    }
}

/// Read, parse, check and render the file at `path`, and run the gateway's own parsers on the
/// result (every startup check of the environment applies to the file too). With
/// [`Secrets::Require`] every declared secret must resolve, used or not. `quiet`: the parsers'
/// warnings are not logged (a serving process logs them on its real pass).
#[allow(dead_code)] // the binary calls load_files
pub fn load_file(path: &str, secrets: Secrets) -> Result<LoadedFile> {
    load_files_with(path, None, secrets, false)
}

/// [`load_file`] for the common file at `path` and the host file at `host`: both parsed, the
/// host file's settings and secrets merged after the common file's (a key in both is an error),
/// and, when they carry settings, every startup parser run on the policy and settings of both.
pub fn load_files(path: &str, host: Option<&str>, secrets: Secrets) -> Result<LoadedFile> {
    load_files_with(path, host, secrets, false)
}

/// A host file: `schema = 1`, `[settings]`, `[secrets]` and nothing else.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostFile {
    schema: u32,
    #[serde(default)]
    settings: toml::Table,
    #[serde(default)]
    secrets: BTreeMap<String, SecretRef>,
}

/// Parse a host file (errors give the position and kind, never a value).
fn parse_host_file(text: &str) -> Result<(toml::Table, BTreeMap<String, SecretRef>)> {
    let file: HostFile = toml::from_str(text).map_err(|e| policy_file::toml_error(text, &e))?;
    if file.schema != policy_file::SCHEMA {
        bail!(
            "Invalid host file: schema {} (this gateway reads schema {})",
            file.schema,
            policy_file::SCHEMA
        );
    }
    // The same structural check as the common file's, whether or not the secrets are read.
    for (name, r) in &file.secrets {
        match (&r.env, &r.file) {
            (Some(_), None) | (None, Some(_)) => {}
            _ => bail!("Invalid host file: secret '{name}' needs exactly one of env or file"),
        }
    }
    Ok((file.settings, file.secrets))
}

fn load_files_with(
    path: &str,
    host: Option<&str>,
    secrets: Secrets,
    quiet: bool,
) -> Result<LoadedFile> {
    let text =
        std::fs::read_to_string(path).map_err(|e| anyhow!("config file {path}: {}", e.kind()))?;
    let loaded = policy_file::parse(&text).with_context(|| format!("config file {path}"))?;
    // Every secret is read once, here; the policy and the settings use these values.
    let mut secret_values: BTreeMap<String, String> = BTreeMap::new();
    if secrets == Secrets::Require {
        for name in loaded.file.secrets.keys() {
            let v = resolve_secret(&loaded.file, name, secrets)
                .with_context(|| format!("config file {path}"))?;
            secret_values.insert(name.clone(), v);
        }
    }
    let lookup = |values: &BTreeMap<String, String>, name: &str| -> Result<String> {
        match secrets {
            Secrets::Skip => Ok(SKIPPED_SECRET.to_string()),
            Secrets::Require => values
                .get(name)
                .cloned()
                .ok_or_else(|| anyhow!("secret '{name}' has no [secrets] entry")),
        }
    };
    let rendered = policy_file::render(&loaded.file, &|name: &str| lookup(&secret_values, name))
        .with_context(|| format!("config file {path}"))?;
    let mut policy: BTreeMap<String, String> = rendered
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    if secrets == Secrets::Skip {
        skip_coinbase_keys(&mut policy)?;
    }

    // The settings: the common file's, then the host file's.
    let mut setting_values = match &loaded.file.settings {
        Some(t) => settings::parse_table(t).with_context(|| format!("config file {path}"))?,
        None => BTreeMap::new(),
    };
    let mut all_secrets = loaded.file.secrets.clone();
    if let Some(host) = host {
        let text = std::fs::read_to_string(host)
            .map_err(|e| anyhow!("host config file {host}: {}", e.kind()))?;
        let (table, host_secrets) =
            parse_host_file(&text).with_context(|| format!("host config file {host}"))?;
        let values =
            settings::parse_table(&table).with_context(|| format!("host config file {host}"))?;
        for (env, v) in values {
            if setting_values.insert(env, v).is_some() {
                bail!(
                    "settings.{} is set in both {path} and {host} (a key belongs in one file)",
                    env.to_ascii_lowercase()
                );
            }
        }
        for (name, r) in host_secrets {
            if all_secrets.contains_key(&name) {
                bail!("secret '{name}' is declared in both {path} and {host}");
            }
            if secrets == Secrets::Require {
                let v =
                    resolve_secret_in(&BTreeMap::from([(name.clone(), r.clone())]), &name, secrets)
                        .with_context(|| format!("host config file {host}"))?;
                secret_values.insert(name.clone(), v);
            }
            all_secrets.insert(name, r);
        }
    }
    let files = match host {
        Some(host) => format!("config files {path} and {host}"),
        None => format!("config file {path}"),
    };
    let mut secret_settings: Vec<&'static str> = Vec::new();
    for (env, v) in &setting_values {
        if let FileValue::Secret { name, .. } = v {
            if !all_secrets.contains_key(name) {
                bail!("{files}: a setting names secret '{name}', which has no [secrets] entry");
            }
            secret_settings.push(env);
        }
    }
    let resolve = |name: &str| lookup(&secret_values, name);
    let rendered_settings = match secrets {
        Secrets::Require => settings::render(&setting_values, Some(&resolve), SKIPPED_SECRET),
        Secrets::Skip => settings::render(&setting_values, None, SKIPPED_SECRET),
    }
    .with_context(|| files.clone())?;
    // Whole secrets left out (--secrets=skip): their checks are skipped.
    let mut omitted: Vec<&'static str> = secret_settings
        .iter()
        .copied()
        .filter(|env| !rendered_settings.contains_key(*env))
        .collect();
    // A common file alone (a CI check of the shared file) names no host's stores: their
    // presence is checked with a host file (and by the serving process itself).
    if host.is_none() {
        omitted.extend(["REDIS_URL", "REDIS_SECURITY_URL"]);
    }
    let carries_settings = loaded.file.settings.is_some() || host.is_some();
    // The checks see the secrets read above (a coinbase provider takes its key from them).
    let provider_secrets = provider_secrets(&policy, &secret_values);
    with_secret_values(provider_secrets.clone(), || -> Result<()> {
        if carries_settings {
            check_config_values(
                &policy,
                &rendered_settings,
                &secret_settings,
                &omitted,
                quiet,
            )
            .with_context(|| files.clone())
        } else {
            check_policy(&policy, quiet).with_context(|| format!("config file {path}"))
        }
    })?;
    Ok(LoadedFile {
        path: path.to_string(),
        file: loaded.file,
        warnings: loaded.warnings,
        policy,
        host_path: host.map(str::to_string),
        carries_settings,
        setting_values,
        secrets: all_secrets,
        settings: rendered_settings,
        secret_values,
        provider_secrets,
    })
}

/// `f`, its warnings logged unless `quiet`.
fn quietly<T>(quiet: bool, f: impl FnOnce() -> T) -> T {
    if quiet {
        tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), f)
    } else {
        f()
    }
}

/// Mark the key of every coinbase integration of `policy` as not to be read (`read_key`
/// false): the file was loaded without its secrets.
fn skip_coinbase_keys(policy: &mut BTreeMap<String, String>) -> Result<()> {
    let Some(raw) = policy.get_mut(policy_file::COINBASE_RENDERED) else {
        return Ok(());
    };
    let mut list: serde_json::Value = serde_json::from_str(raw)?;
    for entry in list.as_array_mut().into_iter().flatten() {
        entry["read_key"] = serde_json::Value::Bool(false);
    }
    *raw = list.to_string();
    Ok(())
}

/// The startup parsers of the policy variables, run on `policy` (the dynamic host sources
/// through their production parser, the deny list validated without being put in force);
/// `quiet`: their warnings are not logged.
fn check_policy(policy: &BTreeMap<String, String>, quiet: bool) -> Result<()> {
    quietly(quiet, || {
        with_policy(policy.clone(), || -> Result<()> {
            let config = crate::config::Config::from_env()?;
            crate::origin::OriginSettings::from_env()?;
            crate::third_party_cache::ThirdParty::from_env(
                config.flexa_alias.as_deref(),
                config.near_alias.as_deref(),
            )?;
            Ok(())
        })
    })
}

/// Every startup parser and check of the serving process, run on `policy` and `settings`
/// (nothing connects, nothing is put in force). `secret_settings`: the settings that hold a
/// secret; `omitted`: those left out (their checks skipped). A failure caused by a secret's
/// value names the setting only: the check is repeated without the secret-holding settings
/// (the error of that run, which holds no secret, is the one shown), then with one at a time.
fn check_config_values(
    policy: &BTreeMap<String, String>,
    settings: &BTreeMap<String, String>,
    secret_settings: &[&'static str],
    omitted: &[&'static str],
    quiet: bool,
) -> Result<()> {
    let run = |values: &BTreeMap<String, String>, omitted: &[&'static str]| {
        quietly(quiet, || {
            with_config(policy.clone(), values.clone(), || {
                check_startup_parsers(omitted)
            })
        })
    };
    if run(settings, omitted).is_ok() {
        return Ok(());
    }
    // Without the secrets.
    let mut bare = settings.clone();
    let mut bare_omitted = omitted.to_vec();
    for env in secret_settings {
        match settings::skipped_value(env) {
            Some(v) if bare.contains_key(*env) => {
                bare.insert(env.to_string(), v.to_string());
            }
            _ => {
                bare.remove(*env);
                bare_omitted.push(env);
            }
        }
    }
    run(&bare, &bare_omitted)?;
    for env in secret_settings.iter().filter(|e| !omitted.contains(e)) {
        let mut one = bare.clone();
        if let Some(v) = settings.get(*env) {
            one.insert(env.to_string(), v.clone());
        }
        let one_omitted: Vec<&'static str> =
            bare_omitted.iter().copied().filter(|e| e != env).collect();
        if run(&one, &one_omitted).is_err() {
            bail!(
                "settings.{}: the value of its secret does not pass the startup checks (the value is not shown)",
                env.to_ascii_lowercase()
            );
        }
    }
    bail!(
        "the settings that hold secrets ({}) do not pass the startup checks together (the values are not shown)",
        secret_settings
            .iter()
            .map(|e| e.to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join(",")
    )
}

/// The startup parsers and checks of the variables in force, in the order the serving process
/// runs them (`omitted`: whole-secret settings not read, see [`settings::startup_checks`]).
pub fn check_startup_parsers(omitted: &[&str]) -> Result<()> {
    // The serving process falls back to `info` on a filter it cannot read; a file must not
    // hold one.
    if let Ok(filter) = var("RUST_LOG") {
        tracing_subscriber::EnvFilter::try_new(&filter)
            .map_err(|_| anyhow!("RUST_LOG is not a valid tracing filter"))?;
    }
    let config = crate::config::Config::from_env()?;
    crate::origin::OriginSettings::from_env()?;
    crate::third_party_cache::ThirdParty::from_env(
        config.flexa_alias.as_deref(),
        config.near_alias.as_deref(),
    )?;
    crate::config::hpke_accept_only_keys_from_env()?;
    crate::padding::Mode::from_env()?;
    crate::lwd::LwdDeadlines::from_env()?;
    crate::freshness::Settings::from_env(crate::cache::REPLAY_TTL_SECS)?;
    crate::lwd_endpoints::Settings::from_env(&config.lwd_addr)?;
    crate::health::LwdErrorPolicy::from_env()?;
    settings::startup_checks(&config, omitted, true)?;
    crate::cache::WriteWaitConfig::from_env()?;
    crate::cache::WriteWaitConfig::peer_from_env()?;
    crate::cache::wait_conns_from_env()?;
    crate::cache::LocalAofConfig::from_env()?;
    crate::cache::FallbackHealth::from_env()?;
    crate::settings::check_pinned_range()?;
    crate::settings::chain_tip_stale_after()?;
    crate::prefetch::PrefetchConfig::from_env()?;
    crate::settings::max_inflight_requests()?;
    crate::cache::startup_stores_wait_from_env()?;
    crate::write_forward::ForwardConfig::from_env()?;
    crate::write_forward::ReceiverConfig::from_env()?;
    crate::server::internal_bind_addr_from_env()?;
    crate::server::header_read_timeout_from_env()?;
    Ok(())
}

/// The policy variables of the process environment (set ones only).
pub fn env_policy() -> BTreeMap<String, String> {
    POLICY_ENV_KEYS
        .iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v)))
        .collect()
}

/// The canonical effective policy of the environment `env`, as declared
/// (`--print-effective-config`).
pub fn env_canonical(env: &BTreeMap<String, String>) -> Result<serde_json::Value> {
    let export = policy_file::export(env)?;
    policy_file::canonical(&export.file, HeaderValues::Redacted, false, &|n: &str| {
        export.resolve(n)
    })
}

/// The canonical effective policy of a file, as declared.
pub fn file_canonical(file: &PolicyFile) -> Result<serde_json::Value> {
    policy_file::canonical(file, HeaderValues::Redacted, false, &|_: &str| {
        Ok(String::new())
    })
}

/// The digest of `ohttp_config_info`: the first 16 hex digits of the SHA-256 of the canonical
/// JSON of the behaviour form of `file` (the same for every way of writing one policy: a file
/// and the environment it stands for, keyed kinds and generic, `get` and `GET`).
pub fn policy_digest(file: &PolicyFile) -> Result<String> {
    let behaviour = policy_file::canonical(file, HeaderValues::Redacted, true, &|_: &str| {
        Ok(String::new())
    })?;
    let hash = Sha256::digest(policy_file::canonical_json(&behaviour).as_bytes());
    Ok(hex::encode(hash)[..16].to_string())
}

/// [`policy_digest`] of the environment `env`.
pub fn env_digest(env: &BTreeMap<String, String>) -> Result<String> {
    policy_digest(&policy_file::export(env)?.file)
}

/// The result of `compare`: whether the two policies are the same, and where they differ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Comparison {
    pub matches: bool,
    /// The differing keys (names only).
    pub keys: Vec<String>,
}

/// Compare the policy of the environment `env` with `file` (its secrets resolved by
/// `resolve`): the same routes, kinds (a keyed kind counts as generic, it behaves as one),
/// header values and everything else.
pub fn compare(
    env: &BTreeMap<String, String>,
    file: &PolicyFile,
    resolve: &dyn Fn(&str) -> Result<String>,
) -> Result<Comparison> {
    let export = policy_file::export(env)?;
    let a = policy_file::canonical(&export.file, HeaderValues::Plain, true, &|n: &str| {
        export.resolve(n)
    })?;
    let b = policy_file::canonical(file, HeaderValues::Plain, true, resolve)?;
    let keys = policy_file::differing_keys(&a, &b);
    Ok(Comparison {
        matches: keys.is_empty(),
        keys,
    })
}

/// The policy variables `env` sets that the file replaces.
pub fn ignored_env_keys(env: &BTreeMap<String, String>) -> Vec<String> {
    env.keys().cloned().collect()
}

/// The policy source of this process, chosen at startup ([`install`]).
#[derive(Clone)]
pub struct Installed {
    pub source: Source,
    /// The file, for `compare` (when it loaded) and `file`.
    pub file: Option<LoadedFile>,
    /// Why the file did not load (`compare`).
    pub file_error: Option<String>,
    /// The host file given (`--host-config` or `GATEWAY_HOST_CONFIG_FILE`).
    pub host_path: Option<String>,
    /// Whether the files carry the settings (a host file, or a `[settings]` table in the
    /// common file), known even when they do not load.
    pub carries_settings: bool,
}

/// The configuration file path: `--config`, else `GATEWAY_CONFIG_FILE`.
fn file_path(cli: &Cli) -> Option<String> {
    cli.config
        .clone()
        .or_else(|| std::env::var(FILE_ENV).ok())
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
}

/// The host file path: `--host-config`, else `GATEWAY_HOST_CONFIG_FILE`.
fn host_path(cmd: &Command) -> Option<String> {
    cmd.host_config
        .clone()
        .or_else(|| std::env::var(HOST_FILE_ENV).ok())
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
}

/// The process environment (variables that are not UTF-8 are no configuration).
fn process_env() -> BTreeMap<String, String> {
    std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        .collect()
}

/// The setting variables `env` sets that the files replace (those a `[secrets]` entry reads,
/// `secret_variables`, are read as secrets, not ignored).
pub fn ignored_env_settings(
    env: &BTreeMap<String, String>,
    secret_variables: &[String],
) -> Vec<String> {
    env.keys()
        .filter(|k| settings::setting(k).is_some() && !secret_variables.contains(k))
        .cloned()
        .collect()
}

/// [`install_command`] for a command line without host file options.
#[allow(dead_code)] // the binary calls install_command
pub fn install(cli: &Cli) -> Result<Installed> {
    install_command(&Command::from(cli.clone()))
}

/// Choose the policy source (`CONFIG_SOURCE`) before any configuration is read; for `file`,
/// make the file the process's policy (and the files' settings the process's settings, when
/// they carry them). A `file` source whose files do not load is a startup error; `compare`
/// only logs it.
pub fn install_command(cmd: &Command) -> Result<Installed> {
    let source = Source::parse(std::env::var(SOURCE_ENV).ok().as_deref())?;
    let path = file_path(&cmd.cli);
    let host = host_path(cmd);
    // Only where the files are read: with CONFIG_SOURCE=env no file is opened.
    let carries_settings = source != Source::Env
        && (host.is_some() || path.as_deref().is_some_and(common_has_settings));
    match source {
        Source::Env => {
            if let Some(path) = path {
                info!(
                    path = %path,
                    "Configuration file given but {SOURCE_ENV} is env: the environment's policy is in force, the file is not read"
                );
            }
            if let Some(host) = &host {
                info!(
                    path = %host,
                    "Host file given but {SOURCE_ENV} is env: the environment's settings are in force, the file is not read"
                );
            }
            Ok(Installed {
                source,
                file: None,
                file_error: None,
                host_path: host,
                carries_settings,
            })
        }
        Source::File => {
            let path = path.ok_or_else(|| {
                anyhow!(
                    "{SOURCE_ENV}=file needs a configuration file (--config <path> or {FILE_ENV})"
                )
            })?;
            let loaded = load_files_with(&path, host.as_deref(), Secrets::Require, true)?;
            for w in &loaded.warnings {
                warn!(path = %path, "{w}");
            }
            let ignored = ignored_env_keys(&env_policy());
            if !ignored.is_empty() {
                warn!(
                    path = %path,
                    ignored = %ignored.join(","),
                    "{SOURCE_ENV}=file: these policy variables of the environment are ignored"
                );
            }
            FILE_POLICY
                .set(loaded.policy.clone())
                .map_err(|_| anyhow!("the policy source was installed twice"))?;
            FILE_SECRETS
                .set(loaded.provider_secrets.clone())
                .map_err(|_| anyhow!("the secrets were installed twice"))?;
            if loaded.carries_settings {
                let ignored = ignored_env_settings(&process_env(), &loaded.secret_variables());
                if !ignored.is_empty() {
                    warn!(
                        path = %path,
                        ignored = %ignored.join(","),
                        "{SOURCE_ENV}=file: the configuration files carry the settings; these setting variables of the environment are ignored"
                    );
                }
                FILE_SETTINGS
                    .set(loaded.settings.clone())
                    .map_err(|_| anyhow!("the settings source was installed twice"))?;
            }
            Ok(Installed {
                source,
                file: Some(loaded),
                file_error: None,
                host_path: host,
                carries_settings,
            })
        }
        Source::Compare => {
            let loaded = match path {
                None => Err(anyhow!(
                    "no configuration file (--config <path> or {FILE_ENV})"
                )),
                Some(path) => load_files_with(&path, host.as_deref(), Secrets::Require, true),
            };
            match loaded {
                Ok(loaded) => {
                    for w in &loaded.warnings {
                        warn!(path = %loaded.path, "{w}");
                    }
                    Ok(Installed {
                        source,
                        file: Some(loaded),
                        file_error: None,
                        host_path: host,
                        carries_settings,
                    })
                }
                Err(e) => Ok(Installed {
                    source,
                    file: None,
                    file_error: Some(format!("{e:#}")),
                    host_path: host,
                    carries_settings,
                }),
            }
        }
    }
}

/// Whether the common file at `path` has a `[settings]` table (read as TOML only; `false` when
/// it cannot be read).
fn common_has_settings(path: &str) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| toml::from_str::<toml::Table>(&t).ok())
        .is_some_and(|t| t.get("settings").is_some_and(toml::Value::is_table))
}

/// The `tracing` filter of a serving process, read before anything else: `None` = the
/// environment's `RUST_LOG` (as before); `Some(value)` = the files are in force and carry the
/// settings, `value` = their `rust_log` (`None`: unset). A file that cannot be read here is
/// `None`: [`install_command`] reports it.
pub fn log_filter(cmd: &Command) -> Option<Option<String>> {
    if Source::parse(std::env::var(SOURCE_ENV).ok().as_deref()).ok()? != Source::File {
        return None;
    }
    let read = |path: &str| -> Option<toml::Table> {
        toml::from_str(&std::fs::read_to_string(path).ok()?).ok()
    };
    let common = read(&file_path(&cmd.cli)?)?;
    let host = match host_path(cmd) {
        Some(p) => Some(read(&p)?),
        None => None,
    };
    let common_settings = common.get("settings").and_then(toml::Value::as_table);
    if common_settings.is_none() && host.is_none() {
        return None;
    }
    let rust_log = |t: Option<&toml::Table>| {
        t.and_then(|t| t.get("rust_log"))
            .and_then(toml::Value::as_str)
            .map(str::to_string)
    };
    let host_settings = host
        .as_ref()
        .and_then(|h| h.get("settings"))
        .and_then(toml::Value::as_table);
    Some(rust_log(common_settings).or_else(|| rust_log(host_settings)))
}

/// After the configuration loaded: `ohttp_config_info`, and for `compare` the comparison.
pub fn report(installed: &Installed) {
    let env = env_policy();
    let digest = match &installed.file {
        Some(f) if installed.source == Source::File => policy_digest(&f.file),
        _ => env_digest(&env),
    };
    let digest = match digest {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %format!("{e:#}"), "The canonical effective policy could not be built; ohttp_config_info has digest 'unavailable'");
            "unavailable".to_string()
        }
    };
    let process = process_env();
    let settings_from_files = matches!(&installed.file, Some(f) if installed.source == Source::File && f.carries_settings);
    let tuning_digest = match &installed.file {
        Some(f) if settings_from_files => settings::tuning_digest(&f.settings),
        _ => settings::tuning_digest(&settings::env_settings(&process)),
    };
    crate::health::set_config_info(installed.source.as_str(), &digest, &tuning_digest);
    match (installed.source, &installed.file) {
        (Source::File, Some(f)) if f.carries_settings => info!(
            path = %f.path,
            digest = %digest,
            host_path = f.host_path.as_deref().unwrap_or("-"),
            tuning_digest = %tuning_digest,
            settings = "files",
            "Routing policy from the configuration file ({SOURCE_ENV}=file)"
        ),
        (Source::File, Some(f)) => info!(
            path = %f.path,
            digest = %digest,
            "Routing policy from the configuration file ({SOURCE_ENV}=file)"
        ),
        (Source::Compare, Some(f)) => {
            let resolve = |name: &str| {
                f.secret_values
                    .get(name)
                    .cloned()
                    .ok_or_else(|| anyhow!("no value for secret '{name}'"))
            };
            match compare(&env, &f.file, &resolve) {
                Ok(c) if c.matches => {
                    crate::health::set_config_compare_match(true);
                    info!(path = %f.path, digest = %digest, "{SOURCE_ENV}=compare: the configuration file's policy equals the environment's");
                }
                Ok(c) => {
                    crate::health::set_config_compare_match(false);
                    warn!(path = %f.path, differing = %c.keys.join(","), "{SOURCE_ENV}=compare: the configuration file's policy differs from the environment's (the environment is in force)");
                }
                Err(e) => {
                    crate::health::set_config_compare_match(false);
                    warn!(path = %f.path, error = %format!("{e:#}"), "{SOURCE_ENV}=compare: the policies could not be compared (the environment is in force)");
                }
            }
            if f.carries_settings {
                let keys = settings::differing(&settings::env_settings(&process), &f.settings);
                crate::health::set_config_settings_compare_match(keys.is_empty());
                if keys.is_empty() {
                    info!(path = %f.path, host_path = f.host_path.as_deref().unwrap_or("-"), tuning_digest = %tuning_digest, "{SOURCE_ENV}=compare: the configuration files' settings equal the environment's");
                } else {
                    warn!(path = %f.path, host_path = f.host_path.as_deref().unwrap_or("-"), differing = %keys.join(","), "{SOURCE_ENV}=compare: the configuration files' settings differ from the environment's (the environment is in force)");
                }
            }
        }
        (Source::Compare, None) => {
            crate::health::set_config_compare_match(false);
            if installed.carries_settings {
                crate::health::set_config_settings_compare_match(false);
            }
            warn!(
                error = installed.file_error.as_deref().unwrap_or(""),
                host_path = installed.host_path.as_deref().unwrap_or("-"),
                "{SOURCE_ENV}=compare: the configuration file did not load (the environment is in force)"
            );
        }
        _ => {}
    }
}

/// What the command line asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// No flag: serve (the default).
    Serve,
    /// `backfill`: fill the permanent block tier and exit.
    Backfill,
    /// `--check-config`.
    CheckConfig,
    /// `--print-effective-config`.
    PrintEffectiveConfig,
    /// `--export-config`.
    ExportConfig,
    /// `--help`.
    Help,
}

/// The command line (without the host file options: [`Command`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cli {
    pub action: Action,
    /// `--config <path>`.
    pub config: Option<String>,
    /// `--secrets=require|skip` (`--check-config`).
    pub secrets: Secrets,
}

/// The whole command line: [`Cli`] and the host file options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    pub cli: Cli,
    /// `--host-config <path>`: the host file (else `GATEWAY_HOST_CONFIG_FILE`).
    pub host_config: Option<String>,
    /// `--host <path>` (`--export-config` only): write the host file there and print the
    /// common file with the settings.
    pub host_out: Option<String>,
    /// `--strict` (`--check-config` only): a setting of the environment the files leave out
    /// is an error.
    pub strict: bool,
}

impl From<Cli> for Command {
    fn from(cli: Cli) -> Self {
        Self {
            cli,
            host_config: None,
            host_out: None,
            strict: false,
        }
    }
}

/// The usage text.
pub const USAGE: &str = "usage: zodl-ohttp-gateway [--config <path>] [--host-config <path>] [--check-config [--secrets=require|skip] [--strict] | --print-effective-config | --export-config [--host <path>]]
       zodl-ohttp-gateway backfill

  (no flag)                 serve; CONFIG_SOURCE=env|compare|file (default env) chooses the policy
                            (and the settings, when the files carry them)
  --config <path>           the configuration file (else GATEWAY_CONFIG_FILE)
  --host-config <path>      the host file: per-host settings and secrets (else GATEWAY_HOST_CONFIG_FILE)
  --check-config            load and check the files, their secrets and the configuration built from them; exit 0 or 1
  --secrets=require|skip    --check-config: resolve every secret (default) or none
  --strict                  --check-config: a setting of the environment the files leave out is an error
  --print-effective-config  print the policy in force as canonical JSON (header values redacted;
                            with CONFIG_SOURCE=file and files that carry settings, the settings too)
  --export-config           print the configuration file equivalent to the environment's policy
  --host <path>             --export-config: also the settings: the common file (policy and common
                            settings) on stdout, the host file written to <path> (a new file)
";

impl Cli {
    /// Parse the arguments (the first is the program): [`Command::parse`] without the host
    /// file options.
    #[allow(dead_code)] // the binary calls Command::parse
    pub fn parse(
        args: impl IntoIterator<Item = std::ffi::OsString>,
    ) -> std::result::Result<Self, String> {
        Command::parse(args).map(|c| c.cli)
    }
}

impl Command {
    /// Parse the arguments (the first is the program). A first argument `backfill` is the
    /// subcommand, and every argument after it is ignored, as before; any other argument that
    /// is no option is ignored too. An argument that is not UTF-8 is no option.
    pub fn parse(
        args: impl IntoIterator<Item = std::ffi::OsString>,
    ) -> std::result::Result<Self, String> {
        let mut cli = Cli {
            action: Action::Serve,
            config: None,
            secrets: Secrets::Require,
        };
        let mut host_config = None;
        let mut host_out = None;
        let mut strict = false;
        let mut args = args.into_iter().skip(1).peekable();
        if args.peek().is_some_and(|a| a == "backfill") {
            cli.action = Action::Backfill;
            return Ok(cli.into());
        }
        let set = |cli: &mut Cli, action: Action| -> std::result::Result<(), String> {
            if cli.action != Action::Serve {
                return Err(format!("only one of --check-config, --print-effective-config, --export-config\n{USAGE}"));
            }
            cli.action = action;
            Ok(())
        };
        let mut secrets_given = false;
        while let Some(arg) = args.next() {
            let Some(arg) = arg.to_str() else {
                continue;
            };
            let mut path_of = |flag: &str| -> std::result::Result<String, String> {
                match args.next().as_deref().map(std::ffi::OsStr::to_str) {
                    Some(Some(path)) if !path.starts_with("--") => Ok(path.to_string()),
                    _ => Err(format!("{flag} needs a path (UTF-8)\n{USAGE}")),
                }
            };
            if let Some(path) = arg.strip_prefix("--host-config=") {
                host_config = Some(path.to_string());
                continue;
            }
            if let Some(path) = arg.strip_prefix("--host=") {
                host_out = Some(path.to_string());
                continue;
            }
            match arg {
                "--check-config" => set(&mut cli, Action::CheckConfig)?,
                "--print-effective-config" => set(&mut cli, Action::PrintEffectiveConfig)?,
                "--export-config" => set(&mut cli, Action::ExportConfig)?,
                "--help" | "-h" => set(&mut cli, Action::Help)?,
                "--config" => cli.config = Some(path_of("--config")?),
                a if a.starts_with("--config=") => {
                    cli.config = Some(a["--config=".len()..].to_string());
                }
                "--host-config" => host_config = Some(path_of("--host-config")?),
                "--host" => host_out = Some(path_of("--host")?),
                "--strict" => strict = true,
                "--secrets=require" => {
                    cli.secrets = Secrets::Require;
                    secrets_given = true;
                }
                "--secrets=skip" => {
                    cli.secrets = Secrets::Skip;
                    secrets_given = true;
                }
                a if a.starts_with("--") || (a.starts_with('-') && a.len() > 1) => {
                    return Err(format!("unknown option '{a}'\n{USAGE}"));
                }
                _ => {}
            }
        }
        if secrets_given && cli.action != Action::CheckConfig {
            return Err(format!("--secrets only goes with --check-config\n{USAGE}"));
        }
        if strict && cli.action != Action::CheckConfig {
            return Err(format!("--strict only goes with --check-config\n{USAGE}"));
        }
        if host_out.is_some() && cli.action != Action::ExportConfig {
            return Err(format!("--host only goes with --export-config\n{USAGE}"));
        }
        if cli.config.as_deref().is_some_and(str::is_empty) {
            return Err(format!("--config needs a path\n{USAGE}"));
        }
        if host_config.as_deref().is_some_and(str::is_empty) {
            return Err(format!("--host-config needs a path\n{USAGE}"));
        }
        if host_out.as_deref().is_some_and(str::is_empty) {
            return Err(format!("--host needs a path\n{USAGE}"));
        }
        Ok(Self {
            cli,
            host_config,
            host_out,
            strict,
        })
    }
}

/// [`run_command`] for a command line without host file options.
#[allow(dead_code)] // the binary calls run_command
pub fn run(cli: &Cli) -> i32 {
    run_command(&Command::from(cli.clone()))
}

/// Run a command-line action that does not serve: its exit code (0 success, 1 failure).
/// Output on stdout, diagnostics on stderr; no secret value is ever written.
pub fn run_command(cmd: &Command) -> i32 {
    let result = match cmd.cli.action {
        Action::Help => {
            print!("{USAGE}");
            Ok(())
        }
        Action::CheckConfig => check_config(cmd),
        Action::PrintEffectiveConfig => print_effective_config(cmd),
        Action::ExportConfig => export_config(cmd),
        Action::Serve | Action::Backfill => Ok(()),
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{e:#}");
            1
        }
    }
}

fn check_config(cmd: &Command) -> Result<()> {
    let cli = &cmd.cli;
    let path = file_path(cli).ok_or_else(|| {
        anyhow!("--check-config needs a configuration file (--config <path> or {FILE_ENV})")
    })?;
    let host = host_path(cmd);
    let loaded = load_files(&path, host.as_deref(), cli.secrets)
        .map_err(|e| anyhow!("config INVALID: {e:#}"))?;
    // Strict where serving is lenient: a coinbase key that does not read as a key is an error
    // here (a serving process answers `unavailable` on its routes instead of not starting).
    if cli.secrets == Secrets::Require {
        let config = loaded
            .run_in(crate::config::Config::from_env)
            .map_err(|e| anyhow!("config INVALID: {e:#}"))?;
        for entry in config.coinbase.iter() {
            if let Some(problem) = entry.key_problem() {
                bail!("config INVALID: {path}: {problem}");
            }
        }
    }
    for w in &loaded.warnings {
        eprintln!("warning: {w}");
    }
    let digest = policy_digest(&loaded.file)?;
    let secrets = match cli.secrets {
        Secrets::Require => "resolved",
        Secrets::Skip => "not read",
    };
    println!(
        "config OK: {path} (schema {}, digest {digest}, secrets {secrets})",
        policy_file::SCHEMA,
    );
    if loaded.carries_settings {
        // The settings the environment sets and the files leave out (names only): with
        // CONFIG_SOURCE=file they would be unset.
        let missing: Vec<String> = ignored_env_settings(&process_env(), &loaded.secret_variables())
            .into_iter()
            .filter(|env| !loaded.setting_values.contains_key(env.as_str()))
            .collect();
        if !missing.is_empty() {
            eprintln!(
                "{}: settings of the environment that the files leave out (unset with {SOURCE_ENV}=file): {}",
                if cmd.strict { "error" } else { "warning" },
                missing.join(",")
            );
            if cmd.strict {
                bail!("config INVALID: --strict: the files leave out settings of the environment");
            }
        }
        println!(
            "settings OK: {} settings from {path}{} (tuning digest {}, secrets {secrets})",
            loaded.setting_values.len(),
            host.as_deref()
                .map(|h| format!(" and {h}"))
                .unwrap_or_default(),
            settings::tuning_digest(&loaded.settings),
        );
    }
    Ok(())
}

fn print_effective_config(cmd: &Command) -> Result<()> {
    let cli = &cmd.cli;
    let source = Source::parse(std::env::var(SOURCE_ENV).ok().as_deref())?;
    let canonical = match source {
        Source::File => {
            let path = file_path(cli).ok_or_else(|| {
                anyhow!(
                    "{SOURCE_ENV}=file needs a configuration file (--config <path> or {FILE_ENV})"
                )
            })?;
            // The checks of --check-config --secrets=skip first.
            let loaded = load_files(&path, host_path(cmd).as_deref(), Secrets::Skip)
                .map_err(|e| anyhow!("config INVALID: {e:#}"))?;
            let mut canonical = file_canonical(&loaded.file)?;
            if loaded.carries_settings {
                // The settings as written: a secret as `<secret:name>`.
                let settings: serde_json::Map<String, serde_json::Value> = loaded
                    .setting_values
                    .iter()
                    .map(|(env, v)| {
                        let shown = match v {
                            FileValue::Plain(p) => p.clone(),
                            FileValue::Secret { name, template } => {
                                let marker = format!("<secret:{name}>");
                                match template {
                                    Some(t) => t.replace(settings::SECRET_PLACEHOLDER, &marker),
                                    None => marker,
                                }
                            }
                        };
                        (env.to_string(), serde_json::Value::String(shown))
                    })
                    .collect();
                if let Some(obj) = canonical.as_object_mut() {
                    obj.insert("settings".to_string(), serde_json::Value::Object(settings));
                }
            }
            canonical
        }
        Source::Env | Source::Compare => {
            if let Some(path) = file_path(cli) {
                eprintln!(
                    "note: {SOURCE_ENV} is {}: the environment's policy is printed, not {path}",
                    source.as_str()
                );
            }
            env_canonical(&env_policy())?
        }
    };
    println!("{}", policy_file::canonical_json(&canonical));
    Ok(())
}

/// The export of the environment, checked before it is printed: the file parses, passes the
/// checks of `--check-config --secrets=skip`, and is the environment's policy (header values
/// included).
pub fn export_checked(env: &BTreeMap<String, String>) -> Result<(String, policy_file::Export)> {
    let export = policy_file::export(env)
        .map_err(|e| anyhow!("the environment's policy cannot be exported: {e:#}"))?;
    let text = policy_file::to_toml(&export.file, &export.secrets)
        .map_err(|e| anyhow!("the environment's policy cannot be exported: {e:#}"))?;
    let parsed = policy_file::parse(&text)
        .map_err(|e| anyhow!("the environment's policy has no file form: {e:#}"))?
        .file;
    let skipped = policy_file::render(&parsed, &|_: &str| Ok(SKIPPED_SECRET.to_string()))?
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    check_policy(&skipped, true)
        .map_err(|e| anyhow!("the exported file does not pass the checks: {e:#}"))?;
    // The header values the file renders are the ones the production parser reads from the
    // environment, in order.
    let rendered = policy_file::render(&parsed, &|n: &str| export.resolve(n))?;
    let original = zodl_ohttp_integrations::core::policy::parse_backend_headers(
        env.get("BACKEND_HEADERS").map_or("", String::as_str),
    )
    .map_err(|_| anyhow!("BACKEND_HEADERS is not valid (its entries are not shown)"))?;
    let exported = zodl_ohttp_integrations::core::policy::parse_backend_headers(
        rendered.get("BACKEND_HEADERS").map_or("", String::as_str),
    )
    .map_err(|_| anyhow!("the exported headers are not valid"))?;
    if original != exported {
        bail!("the exported file does not give the environment's BACKEND_HEADERS");
    }
    let c = compare(env, &parsed, &|n: &str| export.resolve(n))?;
    if !c.matches {
        bail!(
            "the exported file is not the environment's policy at {}",
            c.keys.join(",")
        );
    }
    Ok((text, export))
}

/// The two files equivalent to the environment `env` (`policy_text`, `export`: its checked
/// policy export, [`export_checked`]): the common file (the policy, the common settings and
/// every secret they name) and the host file (the host settings and their secrets). A secret is
/// mapped to the variable that holds it today (`{ env = "VAR" }`). Checked before it is
/// returned: both files parse, stand for exactly the environment's settings and pass the
/// startup checks.
pub fn export_files(
    env: &BTreeMap<String, String>,
    policy_text: &str,
    export: &policy_file::Export,
) -> Result<(String, String)> {
    let (common_lines, common_secrets) = settings::export_lines(env, settings::Place::Common)?;
    let (host_lines, host_secrets) = settings::export_lines(env, settings::Place::Host)?;
    for (name, _) in common_secrets.iter().chain(&host_secrets) {
        if export.file.secrets.contains_key(name) {
            bail!("the secret name '{name}' of a setting is taken by a secret of the policy");
        }
    }
    let secret_lines = |secrets: &[(String, String)]| -> String {
        secrets
            .iter()
            .map(|(name, var)| format!("{name} = {{ env = {} }}\n", settings::toml_str(var)))
            .collect()
    };
    let mut common = policy_text.to_string();
    if !common_secrets.is_empty() {
        let lines = secret_lines(&common_secrets);
        match common.find("\n[secrets]\n") {
            Some(i) => common.insert_str(i + "\n[secrets]\n".len(), &lines),
            None => {
                common.push_str("\n[secrets]\n");
                common.push_str(&lines);
            }
        }
    }
    common.push_str("\n[settings]\n");
    for l in &common_lines {
        common.push_str(l);
        common.push('\n');
    }
    let mut host = String::from("schema = 1\n");
    if !host_secrets.is_empty() {
        host.push_str("\n[secrets]\n");
        host.push_str(&secret_lines(&host_secrets));
    }
    host.push_str("\n[settings]\n");
    for l in &host_lines {
        host.push_str(l);
        host.push('\n');
    }

    // The check: the two files stand for the environment's settings.
    let parsed = policy_file::parse(&common)
        .map_err(|e| anyhow!("the exported common file does not parse: {e:#}"))?
        .file;
    let mut values = settings::parse_table(parsed.settings.as_ref().unwrap_or(&toml::Table::new()))
        .map_err(|e| anyhow!("the exported common file: {e:#}"))?;
    let (host_table, host_secret_refs) =
        parse_host_file(&host).map_err(|e| anyhow!("the exported host file: {e:#}"))?;
    for (k, v) in
        settings::parse_table(&host_table).map_err(|e| anyhow!("the exported host file: {e:#}"))?
    {
        if values.insert(k, v).is_some() {
            bail!("the exported files both set {k}");
        }
    }
    let mut refs = parsed.secrets.clone();
    refs.extend(host_secret_refs);
    // The secrets as the serving process would read them (the variables of `env`), with the
    // same refusals.
    let resolve = |name: &str| -> Result<String> {
        let var = refs
            .get(name)
            .and_then(|r| r.env.as_ref())
            .ok_or_else(|| anyhow!("no value for secret '{name}'"))?;
        let value = env
            .get(var)
            .cloned()
            .ok_or_else(|| anyhow!("secret '{name}': variable {var} is not set"))?;
        usable_secret(name, &format!("variable {var}"), value)
    };
    let rendered = settings::render(&values, Some(&resolve), SKIPPED_SECRET)
        .map_err(|e| anyhow!("the exported files: {e:#}"))?;
    let keys = settings::differing(&settings::env_settings(env), &rendered);
    if !keys.is_empty() {
        bail!(
            "the exported files are not the environment's settings at {}",
            keys.join(",")
        );
    }
    let policy: BTreeMap<String, String> =
        policy_file::render(&parsed, &|n: &str| export.resolve(n))?
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
    let secret_settings: Vec<&'static str> = values
        .iter()
        .filter(|(_, v)| matches!(v, FileValue::Secret { .. }))
        .map(|(k, _)| *k)
        .collect();
    // The files must pass the startup checks wherever the environment itself does.
    let pick = |keep: &dyn Fn(&str) -> bool| -> BTreeMap<String, String> {
        env.iter()
            .filter(|(k, _)| keep(k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    };
    let env_policy = pick(&|k| POLICY_ENV_KEYS.contains(&k));
    let env_settings = pick(&|k| settings::setting(k).is_some());
    let env_passes = quietly(true, || {
        with_config(env_policy, env_settings, || check_startup_parsers(&[]))
    })
    .is_ok();
    if env_passes {
        check_config_values(&policy, &rendered, &secret_settings, &[], true)
            .map_err(|e| anyhow!("the exported files do not pass the checks: {e:#}"))?;
    }
    Ok((common, host))
}

fn export_config(cmd: &Command) -> Result<()> {
    let env = process_env();
    let (text, export) = export_checked(&env)?;
    let text = match &cmd.host_out {
        None => text,
        Some(out) => {
            let (common, host) = export_files(&env, &text, &export)?;
            // A new file: never over a host file in use.
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(out)
                .map_err(|e| anyhow!("--host {out}: {}", e.kind()))?;
            f.write_all(host.as_bytes())
                .map_err(|e| anyhow!("--host {out}: {}", e.kind()))?;
            eprintln!("note: host file written to {out}");
            eprintln!(
                "note: each [secrets] entry of a setting reads the variable that holds it today; for the files-only setup point it at a file instead ({{ file = \"/run/secrets/<name>\" }})"
            );
            common
        }
    };
    print!("{text}");
    for s in export.secrets.iter().filter(|s| !s.found) {
        eprintln!(
            "note: secret '{}' maps to a new variable {}; set it to the header value it stands for",
            s.name, s.env
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli(args: &[&str]) -> std::result::Result<Cli, String> {
        Cli::parse(
            std::iter::once(std::ffi::OsString::from("gw"))
                .chain(args.iter().map(std::ffi::OsString::from)),
        )
    }

    #[test]
    fn command_lines() {
        let serve = cli(&[]).unwrap();
        assert_eq!(
            serve,
            Cli {
                action: Action::Serve,
                config: None,
                secrets: Secrets::Require
            }
        );
        assert_eq!(cli(&["backfill"]).unwrap().action, Action::Backfill);
        // Everything after `backfill` is ignored, as before.
        assert_eq!(
            cli(&["backfill", "--check-config", "--unknown"])
                .unwrap()
                .action,
            Action::Backfill
        );
        // An argument that is not UTF-8 is no option.
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let args = vec![
                std::ffi::OsString::from("gw"),
                std::ffi::OsString::from_vec(vec![0xff, b'-']),
            ];
            assert_eq!(Cli::parse(args).unwrap().action, Action::Serve);
        }
        // Other words are ignored, as before; `backfill` only as the first argument.
        assert_eq!(cli(&["serve", "backfill"]).unwrap().action, Action::Serve);
        let c = cli(&[
            "--config",
            "/etc/g.toml",
            "--check-config",
            "--secrets=skip",
        ])
        .unwrap();
        assert_eq!(c.action, Action::CheckConfig);
        assert_eq!(c.config.as_deref(), Some("/etc/g.toml"));
        assert_eq!(c.secrets, Secrets::Skip);
        assert_eq!(
            cli(&["--config=/x.toml", "--print-effective-config"]).unwrap(),
            Cli {
                action: Action::PrintEffectiveConfig,
                config: Some("/x.toml".into()),
                secrets: Secrets::Require
            }
        );
        assert_eq!(
            cli(&["--export-config"]).unwrap().action,
            Action::ExportConfig
        );
        assert_eq!(cli(&["--config", "/x.toml"]).unwrap().action, Action::Serve);
        for bad in [
            &["--check-config", "--export-config"][..],
            &["--config"],
            &["--config", "--check-config"],
            &["--config="],
            &["--secrets=skip"],
            &["--secrets=maybe", "--check-config"],
            &["--unknown"],
            &["-x"],
        ] {
            assert!(cli(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn sources() {
        assert_eq!(Source::parse(None).unwrap(), Source::Env);
        assert_eq!(Source::parse(Some(" ")).unwrap(), Source::Env);
        assert_eq!(Source::parse(Some("Compare")).unwrap(), Source::Compare);
        assert_eq!(Source::parse(Some("file")).unwrap(), Source::File);
        assert!(Source::parse(Some("files")).is_err());
    }

    #[test]
    fn a_scoped_policy_replaces_the_policy_variables_only() {
        let policy: BTreeMap<String, String> =
            [("BACKENDS".to_string(), "a.example=https://a".to_string())].into();
        with_policy(policy, || {
            assert_eq!(var("BACKENDS").as_deref(), Ok("a.example=https://a"));
            assert_eq!(var("BACKENDS_POLICY"), Err(std::env::VarError::NotPresent));
            // Not a policy variable: the environment.
            assert_eq!(var("PATH").is_ok(), std::env::var("PATH").is_ok());
        });
        // Outside the scope: the environment.
        assert_eq!(var("BACKENDS").ok(), std::env::var("BACKENDS").ok());
    }
}

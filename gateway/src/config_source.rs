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
//!   environment are ignored, with one warning naming those that are set. Deployment
//!   variables and secrets still come from the environment.
//!
//! The file is turned into the values of the variables it stands for, which every parser reads
//! through [`var`]; the parsers are the same in all three modes. `ohttp_config_info{source,
//! digest}` names the policy in force.
//!
//! The command line (`zodl-ohttp-gateway [--config <path>] [--check-config [--secrets=require|skip]
//! | --print-effective-config | --export-config]`, or `backfill`): see [`Cli`].

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use zodl_ohttp_integrations::core::config::{
    self as policy_file, HeaderValues, PolicyFile, POLICY_ENV_KEYS,
};

/// The variable naming the policy source.
pub const SOURCE_ENV: &str = "CONFIG_SOURCE";
/// The variable naming the configuration file (`--config` wins).
pub const FILE_ENV: &str = "GATEWAY_CONFIG_FILE";

/// The policy in force for the whole process when the file is (`CONFIG_SOURCE=file`).
static FILE_POLICY: OnceLock<BTreeMap<String, String>> = OnceLock::new();

thread_local! {
    /// The policy of a [`with_policy`] scope on this thread.
    static SCOPED: RefCell<Option<Arc<BTreeMap<String, String>>>> = const { RefCell::new(None) };
}

/// A variable as the gateway's parsers read it: a policy variable from the policy in force
/// (the file's, when it is), anything else from the environment.
pub fn var(key: &str) -> Result<String, std::env::VarError> {
    if POLICY_ENV_KEYS.contains(&key) {
        let scoped = SCOPED.with(|s| s.borrow().clone());
        let policy = scoped.as_deref().or_else(|| FILE_POLICY.get());
        if let Some(policy) = policy {
            return policy
                .get(key)
                .cloned()
                .ok_or(std::env::VarError::NotPresent);
        }
    }
    std::env::var(key)
}

/// Run `f` with `policy` (variable -> value) as the policy variables of this thread: what
/// `--check-config` and `compare` use to run the parsers on a file without making it the
/// process's policy. Parsers that set process-wide state (the dynamic hosts' deny list) only
/// validate inside such a scope ([`in_scope`]).
pub fn with_policy<T>(policy: BTreeMap<String, String>, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<Arc<BTreeMap<String, String>>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.0.take();
            SCOPED.with(|s| *s.borrow_mut() = previous);
        }
    }
    let previous = SCOPED.with(|s| s.borrow_mut().replace(Arc::new(policy)));
    let _restore = Restore(previous);
    f()
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
    if mode == Secrets::Skip {
        return Ok(SKIPPED_SECRET.to_string());
    }
    let r = file
        .secrets
        .get(name)
        .ok_or_else(|| anyhow!("secret '{name}' has no [secrets] entry"))?;
    let (value, source) = match (&r.env, &r.file) {
        (Some(var), None) => (
            std::env::var(var)
                .map_err(|_| anyhow!("secret '{name}': variable {var} is not set"))?,
            format!("variable {var}"),
        ),
        (None, Some(path)) => (read_secret_file(name, path)?, format!("file {path}")),
        _ => bail!("secret '{name}' needs exactly one of env or file"),
    };
    if value.trim().is_empty() {
        bail!("secret '{name}': {source} is empty");
    }
    if value.chars().any(|c| c.is_control()) {
        bail!("secret '{name}': {source} holds a line break or another control character");
    }
    Ok(value)
}

fn read_secret_file(name: &str, path: &str) -> Result<String> {
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
    let mut bytes = Vec::new();
    f.take(MAX_SECRET_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| anyhow!("secret '{name}': file {path}: {}", e.kind()))?;
    if bytes.len() as u64 > MAX_SECRET_FILE_BYTES {
        bail!("secret '{name}': file {path} is larger than {MAX_SECRET_FILE_BYTES} bytes");
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| anyhow!("secret '{name}': file {path} is not UTF-8"))?;
    let text = match text.strip_suffix("\r\n") {
        Some(t) => t.to_string(),
        None => text.strip_suffix('\n').unwrap_or(&text).to_string(),
    };
    Ok(text)
}

/// A loaded configuration file: its content, warnings and the variables it stands for.
#[derive(Clone)]
pub struct LoadedFile {
    pub path: String,
    pub file: PolicyFile,
    pub warnings: Vec<String>,
    /// The policy variables, secrets resolved.
    pub policy: BTreeMap<String, String>,
}

impl std::fmt::Debug for LoadedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The variables carry the secrets: their names only.
        f.debug_struct("LoadedFile")
            .field("path", &self.path)
            .field("warnings", &self.warnings)
            .field("policy", &self.policy.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// Read, parse, check and render the file at `path`, and run the gateway's own parsers on the
/// result (every startup check of the environment applies to the file too). With
/// [`Secrets::Require`] every declared secret must resolve, used or not. `quiet`: the parsers'
/// warnings are not logged (a serving process logs them on its real pass).
pub fn load_file(path: &str, secrets: Secrets) -> Result<LoadedFile> {
    load_file_with(path, secrets, false)
}

fn load_file_with(path: &str, secrets: Secrets, quiet: bool) -> Result<LoadedFile> {
    let text =
        std::fs::read_to_string(path).map_err(|e| anyhow!("config file {path}: {}", e.kind()))?;
    let loaded = policy_file::parse(&text).with_context(|| format!("config file {path}"))?;
    if secrets == Secrets::Require {
        for name in loaded.file.secrets.keys() {
            resolve_secret(&loaded.file, name, secrets)
                .with_context(|| format!("config file {path}"))?;
        }
    }
    let rendered = policy_file::render(&loaded.file, &|name: &str| {
        resolve_secret(&loaded.file, name, secrets)
    })
    .with_context(|| format!("config file {path}"))?;
    let policy: BTreeMap<String, String> = rendered
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    check_policy(&policy, quiet).with_context(|| format!("config file {path}"))?;
    Ok(LoadedFile {
        path: path.to_string(),
        file: loaded.file,
        warnings: loaded.warnings,
        policy,
    })
}

/// The startup parsers of the policy variables, run on `policy` (the dynamic host sources
/// through their production parser, the deny list validated without being put in force);
/// `quiet`: their warnings are not logged.
fn check_policy(policy: &BTreeMap<String, String>, quiet: bool) -> Result<()> {
    let run = || {
        with_policy(policy.clone(), || -> Result<()> {
            let config = crate::config::Config::from_env()?;
            crate::origin::OriginSettings::from_env()?;
            crate::third_party_cache::ThirdParty::from_env(
                config.flexa_alias.as_deref(),
                config.near_alias.as_deref(),
            )?;
            Ok(())
        })
    };
    if quiet {
        tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), run)
    } else {
        run()
    }
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
}

/// The configuration file path: `--config`, else `GATEWAY_CONFIG_FILE`.
fn file_path(cli: &Cli) -> Option<String> {
    cli.config
        .clone()
        .or_else(|| std::env::var(FILE_ENV).ok())
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
}

/// Choose the policy source (`CONFIG_SOURCE`) before any configuration is read; for `file`,
/// make the file the process's policy. A `file` source whose file does not load is a startup
/// error; `compare` only logs it.
pub fn install(cli: &Cli) -> Result<Installed> {
    let source = Source::parse(std::env::var(SOURCE_ENV).ok().as_deref())?;
    let path = file_path(cli);
    match source {
        Source::Env => {
            if let Some(path) = path {
                info!(
                    path = %path,
                    "Configuration file given but {SOURCE_ENV} is env: the environment's policy is in force, the file is not read"
                );
            }
            Ok(Installed {
                source,
                file: None,
                file_error: None,
            })
        }
        Source::File => {
            let path = path.ok_or_else(|| {
                anyhow!(
                    "{SOURCE_ENV}=file needs a configuration file (--config <path> or {FILE_ENV})"
                )
            })?;
            let loaded = load_file_with(&path, Secrets::Require, true)?;
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
            Ok(Installed {
                source,
                file: Some(loaded),
                file_error: None,
            })
        }
        Source::Compare => {
            let loaded = match path {
                None => Err(anyhow!(
                    "no configuration file (--config <path> or {FILE_ENV})"
                )),
                Some(path) => load_file_with(&path, Secrets::Require, true),
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
                    })
                }
                Err(e) => Ok(Installed {
                    source,
                    file: None,
                    file_error: Some(format!("{e:#}")),
                }),
            }
        }
    }
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
    crate::health::set_config_info(installed.source.as_str(), &digest);
    match (installed.source, &installed.file) {
        (Source::File, Some(f)) => info!(
            path = %f.path,
            digest = %digest,
            "Routing policy from the configuration file ({SOURCE_ENV}=file)"
        ),
        (Source::Compare, Some(f)) => {
            let resolve = |name: &str| resolve_secret(&f.file, name, Secrets::Require);
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
        }
        (Source::Compare, None) => {
            crate::health::set_config_compare_match(false);
            warn!(
                error = installed.file_error.as_deref().unwrap_or(""),
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

/// The command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cli {
    pub action: Action,
    /// `--config <path>`.
    pub config: Option<String>,
    /// `--secrets=require|skip` (`--check-config`).
    pub secrets: Secrets,
}

/// The usage text.
pub const USAGE: &str = "usage: zodl-ohttp-gateway [--config <path>] [--check-config [--secrets=require|skip] | --print-effective-config | --export-config]
       zodl-ohttp-gateway backfill

  (no flag)                 serve; CONFIG_SOURCE=env|compare|file (default env) chooses the policy
  --config <path>           the configuration file (else GATEWAY_CONFIG_FILE)
  --check-config            load and check the file, its secrets and the policy built from it; exit 0 or 1
  --secrets=require|skip    --check-config: resolve every secret (default) or none
  --print-effective-config  print the policy in force as canonical JSON (header values redacted)
  --export-config           print the configuration file equivalent to the environment's policy
";

impl Cli {
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
        let mut args = args.into_iter().skip(1).peekable();
        if args.peek().is_some_and(|a| a == "backfill") {
            cli.action = Action::Backfill;
            return Ok(cli);
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
            match arg {
                "--check-config" => set(&mut cli, Action::CheckConfig)?,
                "--print-effective-config" => set(&mut cli, Action::PrintEffectiveConfig)?,
                "--export-config" => set(&mut cli, Action::ExportConfig)?,
                "--help" | "-h" => set(&mut cli, Action::Help)?,
                "--config" => match args.next().as_deref().map(std::ffi::OsStr::to_str) {
                    Some(Some(path)) if !path.starts_with("--") => {
                        cli.config = Some(path.to_string())
                    }
                    _ => return Err(format!("--config needs a path (UTF-8)\n{USAGE}")),
                },
                a if a.starts_with("--config=") => {
                    cli.config = Some(a["--config=".len()..].to_string());
                }
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
        if cli.config.as_deref().is_some_and(str::is_empty) {
            return Err(format!("--config needs a path\n{USAGE}"));
        }
        Ok(cli)
    }
}

/// Run a command-line action that does not serve: its exit code (0 success, 1 failure).
/// Output on stdout, diagnostics on stderr; no secret value is ever written.
pub fn run(cli: &Cli) -> i32 {
    let result = match cli.action {
        Action::Help => {
            print!("{USAGE}");
            Ok(())
        }
        Action::CheckConfig => check_config(cli),
        Action::PrintEffectiveConfig => print_effective_config(cli),
        Action::ExportConfig => export_config(),
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

fn check_config(cli: &Cli) -> Result<()> {
    let path = file_path(cli).ok_or_else(|| {
        anyhow!("--check-config needs a configuration file (--config <path> or {FILE_ENV})")
    })?;
    let loaded = load_file(&path, cli.secrets).map_err(|e| anyhow!("config INVALID: {e:#}"))?;
    for w in &loaded.warnings {
        eprintln!("warning: {w}");
    }
    let digest = policy_digest(&loaded.file)?;
    println!(
        "config OK: {path} (schema {}, digest {digest}, secrets {})",
        policy_file::SCHEMA,
        match cli.secrets {
            Secrets::Require => "resolved",
            Secrets::Skip => "not read",
        }
    );
    Ok(())
}

fn print_effective_config(cli: &Cli) -> Result<()> {
    let source = Source::parse(std::env::var(SOURCE_ENV).ok().as_deref())?;
    let canonical = match source {
        Source::File => {
            let path = file_path(cli).ok_or_else(|| {
                anyhow!(
                    "{SOURCE_ENV}=file needs a configuration file (--config <path> or {FILE_ENV})"
                )
            })?;
            // The checks of --check-config --secrets=skip first.
            let loaded =
                load_file(&path, Secrets::Skip).map_err(|e| anyhow!("config INVALID: {e:#}"))?;
            file_canonical(&loaded.file)?
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

fn export_config() -> Result<()> {
    // Variables that are not UTF-8 are no policy and no secret.
    let env: BTreeMap<String, String> = std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        .collect();
    let (text, export) = export_checked(&env)?;
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

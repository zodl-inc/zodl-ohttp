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

//! Validates the build-time endpoint configuration of the crate.
//!
//! Each network has four variables: `ZODL_OHTTP_GATEWAY_HOST_<NET>`, `ZODL_OHTTP_RELAY_URL_<NET>`,
//! `ZODL_OHTTP_KEYS_DNS_NAME_<NET>` and `ZODL_OHTTP_SIGNING_PUBKEY_<NET>`, with `<NET>` either
//! `MAINNET` or `TESTNET` (see `src/relays.rs`). The rules:
//!
//! - **Format.** A set value must pass its check: an `https://` URL with a non-empty host, no
//!   userinfo and no whitespace; a bare DNS host name; 64 hex digits.
//! - **All or nothing per network.** A network is configured with all four values or with none.
//!   If one is set and another of the same network is unset or empty, the build fails and names
//!   the network and the missing variables. With none set, OHTTP is off for that network.
//! - **Strict mode.** With `ZODL_OHTTP_REQUIRE=1` the build fails unless all eight values are
//!   set. Unset, empty or `0` leaves it off; any other value fails the build.
//! - **No sharing between networks.** When both networks are configured, mainnet and testnet
//!   must not share a gateway host, relay URL, keys DNS name or signing key (compared ignoring
//!   ASCII case).
//!
//! An unset or empty variable counts as not set, as does a value that is not valid Unicode.
//! With nothing set and strict mode off the build succeeds with OHTTP off for both networks.
//! Error messages name variables and rules, never values. The checks are pure functions over a
//! map of values so that `tests/build_config.rs` can run them without touching the process
//! environment.

use std::collections::BTreeMap;

/// Turns on strict mode: `1` requires all eight values.
pub(crate) const REQUIRE_VAR: &str = "ZODL_OHTTP_REQUIRE";

/// What a variable holds, which decides its format check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A bare DNS host name.
    HostName,
    /// An `https://` relay URL.
    RelayUrl,
    /// A raw Ed25519 public key, hex.
    SigningKey,
}

/// One network's variables.
pub(crate) struct NetworkVars {
    /// The network's name in messages.
    pub(crate) name: &'static str,
    /// The variable name, what it describes in messages, and its kind; in a fixed order shared
    /// by both networks.
    pub(crate) vars: [(&'static str, &'static str, Kind); 4],
}

/// Both networks' variables, mainnet first.
pub(crate) const NETWORKS: [NetworkVars; 2] = [
    NetworkVars {
        name: "mainnet",
        vars: [
            (
                "ZODL_OHTTP_GATEWAY_HOST_MAINNET",
                "a gateway host",
                Kind::HostName,
            ),
            (
                "ZODL_OHTTP_RELAY_URL_MAINNET",
                "a relay URL",
                Kind::RelayUrl,
            ),
            (
                "ZODL_OHTTP_KEYS_DNS_NAME_MAINNET",
                "a keys DNS name",
                Kind::HostName,
            ),
            (
                "ZODL_OHTTP_SIGNING_PUBKEY_MAINNET",
                "a signing key",
                Kind::SigningKey,
            ),
        ],
    },
    NetworkVars {
        name: "testnet",
        vars: [
            (
                "ZODL_OHTTP_GATEWAY_HOST_TESTNET",
                "a gateway host",
                Kind::HostName,
            ),
            (
                "ZODL_OHTTP_RELAY_URL_TESTNET",
                "a relay URL",
                Kind::RelayUrl,
            ),
            (
                "ZODL_OHTTP_KEYS_DNS_NAME_TESTNET",
                "a keys DNS name",
                Kind::HostName,
            ),
            (
                "ZODL_OHTTP_SIGNING_PUBKEY_TESTNET",
                "a signing key",
                Kind::SigningKey,
            ),
        ],
    },
];

/// Every endpoint variable, network by network.
pub(crate) fn endpoint_vars() -> impl Iterator<Item = &'static str> {
    NETWORKS
        .iter()
        .flat_map(|network| network.vars.iter().map(|&(var, _, _)| var))
}

fn main() {
    // Rerun this build script when any of these variables changes, otherwise cached builds
    // keep a stale value.
    for var in endpoint_vars().chain([REQUIRE_VAR]) {
        println!("cargo:rerun-if-env-changed={var}");
    }
    // A value that is not valid Unicode counts as unset.
    let owned: Vec<(&str, String)> = endpoint_vars()
        .filter_map(|var| std::env::var(var).ok().map(|value| (var, value)))
        .collect();
    let values: BTreeMap<&str, &str> = owned
        .iter()
        .map(|(var, value)| (*var, value.as_str()))
        .collect();
    let require = std::env::var(REQUIRE_VAR).ok();
    if let Err(problems) = check_config(&values, require.as_deref()) {
        panic!(
            "invalid OHTTP build configuration:\n  {}",
            problems.join("\n  ")
        );
    }
}

/// Checks the whole configuration: `values` maps variable names to their values (absent or
/// empty = not set), `require` is the value of `ZODL_OHTTP_REQUIRE`. Returns every problem found,
/// each naming variables and rules only, never values.
pub(crate) fn check_config(
    values: &BTreeMap<&str, &str>,
    require: Option<&str>,
) -> Result<(), Vec<String>> {
    let set = |var: &str| values.get(var).copied().filter(|value| !value.is_empty());
    let mut problems = Vec::new();

    let strict = match require.unwrap_or("") {
        "" | "0" => false,
        "1" => true,
        _ => {
            problems.push(format!("{REQUIRE_VAR} must be 1, 0 or unset"));
            false
        }
    };

    // Format of every set value.
    for network in &NETWORKS {
        for &(var, _, kind) in &network.vars {
            if let Some(value) = set(var) {
                if let Err(problem) = check_value(kind, value) {
                    problems.push(format!("{var} {problem}"));
                }
            }
        }
    }

    // All or nothing per network.
    let mut complete = [false; 2];
    for (index, network) in NETWORKS.iter().enumerate() {
        let missing: Vec<&str> = network
            .vars
            .iter()
            .map(|&(var, _, _)| var)
            .filter(|&var| set(var).is_none())
            .collect();
        complete[index] = missing.is_empty();
        if !missing.is_empty() && missing.len() < network.vars.len() {
            problems.push(format!(
                "{} OHTTP configuration is incomplete: set all four of its variables or none; \
                 missing {}",
                network.name,
                missing.join(", ")
            ));
        }
    }

    // Strict mode: everything set.
    if strict {
        let missing: Vec<&str> = endpoint_vars().filter(|&var| set(var).is_none()).collect();
        if !missing.is_empty() {
            problems.push(format!(
                "{REQUIRE_VAR}=1 requires every OHTTP variable; missing {}",
                missing.join(", ")
            ));
        }
    }

    // No value shared between the networks.
    if complete == [true, true] {
        let [mainnet, testnet] = &NETWORKS;
        for (&(main_var, what, _), &(test_var, _, _)) in mainnet.vars.iter().zip(&testnet.vars) {
            if let (Some(main), Some(test)) = (set(main_var), set(test_var)) {
                if main.eq_ignore_ascii_case(test) {
                    problems.push(format!(
                        "{main_var} and {test_var} must differ: mainnet and testnet must not \
                         share {what}"
                    ));
                }
            }
        }
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

/// Checks one set value of `kind`. The error completes "`<variable>` ...".
pub(crate) fn check_value(kind: Kind, value: &str) -> Result<(), String> {
    match kind {
        Kind::HostName => check_host_name(value).map_err(str::to_owned),
        Kind::RelayUrl => check_relay_url(value).map_err(str::to_owned),
        Kind::SigningKey => check_signing_key(value),
    }
}

/// Checks one relay URL: `https://`, a non-empty host, no userinfo, no whitespace or control
/// characters. The error completes "`<variable>` ...".
pub(crate) fn check_relay_url(value: &str) -> Result<(), &'static str> {
    // Must start with https://
    let Some(after_scheme) = value.strip_prefix("https://") else {
        return Err("must be an https:// URL");
    };

    // The authority runs to the first /, ? or # (or the end of the string).
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];

    // No userinfo (`user@`, `user:password@`): a relay URL never carries credentials, and an
    // `@` would make the host something other than what the value seems to name.
    if authority.contains('@') {
        return Err("must not contain userinfo");
    }

    // The host is the authority without its `:port`; a bracketed IPv6 literal keeps its colons.
    let host = if authority.starts_with('[') {
        authority
            .find(']')
            .map_or(authority, |close| &authority[..=close])
    } else {
        authority.split(':').next().unwrap_or("")
    };
    if host.is_empty() || host == "[]" {
        return Err("must have a non-empty host");
    }

    // No whitespace or control characters anywhere in the URL
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("must not contain whitespace or control characters");
    }
    Ok(())
}

/// Checks one host name: dot-separated labels of letters, digits and '-', none empty, no
/// scheme, port, path or trailing dot. The error completes "`<variable>` ...".
pub(crate) fn check_host_name(value: &str) -> Result<(), &'static str> {
    let valid = value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    if valid {
        Ok(())
    } else {
        Err("must be a bare DNS host name (no scheme, port, path or trailing dot)")
    }
}

/// Checks one signing key: 32 bytes of raw Ed25519 public key, as 64 hex digits. The error
/// completes "`<variable>` ..." and gives the length, not the value.
pub(crate) fn check_signing_key(value: &str) -> Result<(), String> {
    if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!(
            "must be a raw Ed25519 public key as 64 hex digits, got {} characters",
            value.len()
        ))
    }
}

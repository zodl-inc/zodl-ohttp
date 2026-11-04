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
//! Every variable is optional. An unset or empty variable turns OHTTP off for its network
//! (see `src/relays.rs`); it never fails the build. A variable that is set but fails the
//! checks below (an `https://` URL with a non-empty host, no userinfo and no whitespace, a
//! bare DNS host name, 64 hex digits) fails the build with a clear message. A value that is
//! not valid Unicode counts as unset.

/// Build-time variables holding an `https://` relay URL.
const RELAY_URL_VARS: [&str; 2] = [
    "ZODL_OHTTP_RELAY_URL_MAINNET",
    "ZODL_OHTTP_RELAY_URL_TESTNET",
];

/// Build-time variables holding a DNS host name.
const HOST_NAME_VARS: [&str; 4] = [
    "ZODL_OHTTP_GATEWAY_HOST_MAINNET",
    "ZODL_OHTTP_GATEWAY_HOST_TESTNET",
    "ZODL_OHTTP_KEYS_DNS_NAME_MAINNET",
    "ZODL_OHTTP_KEYS_DNS_NAME_TESTNET",
];

/// Build-time variables holding a raw Ed25519 public key, hex.
const SIGNING_KEY_VARS: [&str; 2] = [
    "ZODL_OHTTP_SIGNING_PUBKEY_MAINNET",
    "ZODL_OHTTP_SIGNING_PUBKEY_TESTNET",
];

fn main() {
    // Rerun this build script when any of these variables changes, otherwise cached builds
    // keep a stale value.
    for var in RELAY_URL_VARS
        .iter()
        .chain(HOST_NAME_VARS.iter())
        .chain(SIGNING_KEY_VARS.iter())
    {
        println!("cargo:rerun-if-env-changed={var}");
    }
    for var in RELAY_URL_VARS {
        validate_relay_url_env(var);
    }
    for var in HOST_NAME_VARS {
        validate_host_name_env(var);
    }
    for var in SIGNING_KEY_VARS {
        validate_signing_key_env(var);
    }
}

/// The value of `var_name`, or `None` when it is unset, empty or not valid Unicode (OHTTP off
/// for that network).
fn configured(var_name: &str) -> Option<String> {
    std::env::var(var_name)
        .ok()
        .filter(|value| !value.is_empty())
}

fn validate_relay_url_env(var_name: &str) {
    let Some(value) = configured(var_name) else {
        return;
    };
    if let Err(problem) = check_relay_url(&value) {
        panic!("{var_name} {problem}, got {value:?}");
    }
}

/// Checks one relay URL: `https://`, a non-empty host, no userinfo, no whitespace or control
/// characters. The error completes "`<variable>` ...". Also run by `tests/build_config.rs`.
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

fn validate_host_name_env(var_name: &str) {
    let Some(value) = configured(var_name) else {
        return;
    };
    // A bare DNS name: dot-separated labels of letters, digits and '-', none empty, no scheme,
    // port, path or trailing dot.
    let valid = value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    if !valid {
        panic!(
            "{var_name} must be a bare DNS host name (no scheme, port, path or trailing dot), got {value:?}"
        );
    }
}

fn validate_signing_key_env(var_name: &str) {
    let Some(value) = configured(var_name) else {
        return;
    };
    // 32 bytes of raw Ed25519 public key, as 64 hex digits.
    if value.len() != 64 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
        panic!(
            "{var_name} must be a raw Ed25519 public key as 64 hex digits, got {} characters",
            value.len()
        );
    }
}

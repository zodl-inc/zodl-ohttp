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

//! The build script's configuration checks (`build.rs`), run as units: a build script has no
//! test harness of its own, so the same source is compiled here as a module. The checks take a
//! map of values, so these tests never read or change the process environment. Test values are
//! RFC 2606 names and dummy keys.

#[allow(dead_code)]
#[path = "../build.rs"]
mod build_script;

use std::collections::BTreeMap;

use build_script::{check_config, check_relay_url, endpoint_vars, REQUIRE_VAR};

const MAINNET: [(&str, &str); 4] = [
    ("ZODL_OHTTP_GATEWAY_HOST_MAINNET", "ohttp-gateway.example"),
    (
        "ZODL_OHTTP_RELAY_URL_MAINNET",
        "https://relay-mainnet.example/relay",
    ),
    (
        "ZODL_OHTTP_KEYS_DNS_NAME_MAINNET",
        "mainnet.ohttp-keys.example",
    ),
    (
        "ZODL_OHTTP_SIGNING_PUBKEY_MAINNET",
        "1111111111111111111111111111111111111111111111111111111111111111",
    ),
];

const TESTNET: [(&str, &str); 4] = [
    (
        "ZODL_OHTTP_GATEWAY_HOST_TESTNET",
        "ohttp-gateway-testnet.example",
    ),
    (
        "ZODL_OHTTP_RELAY_URL_TESTNET",
        "https://relay-testnet.example/relay",
    ),
    (
        "ZODL_OHTTP_KEYS_DNS_NAME_TESTNET",
        "testnet.ohttp-keys.example",
    ),
    (
        "ZODL_OHTTP_SIGNING_PUBKEY_TESTNET",
        "2222222222222222222222222222222222222222222222222222222222222222",
    ),
];

fn config(sets: &[&[(&'static str, &'static str)]]) -> BTreeMap<&'static str, &'static str> {
    sets.iter().flat_map(|set| set.iter().copied()).collect()
}

fn both() -> BTreeMap<&'static str, &'static str> {
    config(&[&MAINNET, &TESTNET])
}

/// The problems `check_config` reports, after checking that none of them carries a value.
fn problems(values: &BTreeMap<&str, &str>, require: Option<&str>) -> Vec<String> {
    let problems = check_config(values, require).expect_err("configuration should be refused");
    for problem in &problems {
        for value in values.values().filter(|value| !value.is_empty()) {
            assert!(
                !problem
                    .to_ascii_lowercase()
                    .contains(&value.to_ascii_lowercase()),
                "{problem:?} echoes a value"
            );
        }
    }
    problems
}

#[test]
fn relay_urls_with_a_host_and_no_userinfo_are_accepted() {
    for url in [
        "https://relay.example",
        "https://relay.example/",
        "https://relay.example/relay",
        "https://relay.example:443/relay",
        "https://relay.example?x=1",
        "https://[2001:db8::1]:443/relay",
    ] {
        assert_eq!(check_relay_url(url), Ok(()), "{url}");
    }
}

#[test]
fn relay_urls_without_a_host_are_refused() {
    for url in [
        "https://",
        "https:///relay",
        "https://:443/relay",
        "https://:443",
        "https://?x=1",
        "https://#f",
        "https://[]:443/relay",
    ] {
        assert_eq!(
            check_relay_url(url),
            Err("must have a non-empty host"),
            "{url}"
        );
    }
}

#[test]
fn relay_urls_with_userinfo_are_refused() {
    for url in [
        "https://user@/relay",
        "https://user@relay.example/relay",
        "https://user:password@relay.example/relay",
        "https://@relay.example/relay",
        "https://relay.example@other.example/relay",
    ] {
        assert_eq!(
            check_relay_url(url),
            Err("must not contain userinfo"),
            "{url}"
        );
    }
}

#[test]
fn relay_urls_with_another_scheme_or_whitespace_are_refused() {
    for url in [
        "http://relay.example/relay",
        "relay.example",
        "HTTPS://relay.example",
    ] {
        assert_eq!(
            check_relay_url(url),
            Err("must be an https:// URL"),
            "{url}"
        );
    }
    for url in ["https://relay.example/re lay", "https://relay.example/\n"] {
        assert_eq!(
            check_relay_url(url),
            Err("must not contain whitespace or control characters"),
            "{url}"
        );
    }
}

#[test]
fn nothing_set_builds_with_ohttp_off() {
    let empty = BTreeMap::new();
    for require in [None, Some(""), Some("0")] {
        assert_eq!(check_config(&empty, require), Ok(()), "{require:?}");
    }
    let all_empty: BTreeMap<&str, &str> = endpoint_vars().map(|var| (var, "")).collect();
    assert_eq!(check_config(&all_empty, None), Ok(()));
}

#[test]
fn one_or_both_complete_networks_are_accepted() {
    for values in [config(&[&MAINNET]), config(&[&TESTNET]), both()] {
        assert_eq!(check_config(&values, None), Ok(()), "{values:?}");
    }
}

#[test]
fn a_network_missing_one_value_fails_and_names_it() {
    for (network, set, other) in [("mainnet", MAINNET, TESTNET), ("testnet", TESTNET, MAINNET)] {
        for (missing, _) in set {
            for absent in [None, Some("")] {
                let mut values = config(&[&set, &other]);
                match absent {
                    None => values.remove(missing),
                    Some(empty) => values.insert(missing, empty),
                };
                let problems = problems(&values, None);
                assert_eq!(problems.len(), 1, "{problems:?}");
                assert!(
                    problems[0]
                        .starts_with(&format!("{network} OHTTP configuration is incomplete")),
                    "{problems:?}"
                );
                assert!(
                    problems[0].ends_with(&format!("missing {missing}")),
                    "{problems:?}"
                );
            }
        }
    }
}

#[test]
fn a_network_with_one_value_lists_the_other_three() {
    let values = config(&[&MAINNET[..1], &TESTNET]);
    assert_eq!(
        problems(&values, None),
        vec![
            "mainnet OHTTP configuration is incomplete: set all four of its variables or none; \
             missing ZODL_OHTTP_RELAY_URL_MAINNET, ZODL_OHTTP_KEYS_DNS_NAME_MAINNET, \
             ZODL_OHTTP_SIGNING_PUBKEY_MAINNET"
                .to_owned()
        ]
    );
}

#[test]
fn strict_mode_requires_every_value() {
    assert_eq!(check_config(&both(), Some("1")), Ok(()));

    let none = problems(&BTreeMap::new(), Some("1"));
    assert_eq!(none.len(), 1, "{none:?}");
    assert!(none[0].starts_with(&format!("{REQUIRE_VAR}=1 requires every OHTTP variable")));
    for var in endpoint_vars() {
        assert!(none[0].contains(var), "{none:?} {var}");
    }

    let mainnet_only = problems(&config(&[&MAINNET]), Some("1"));
    assert_eq!(
        mainnet_only,
        vec![format!(
            "{REQUIRE_VAR}=1 requires every OHTTP variable; missing \
             ZODL_OHTTP_GATEWAY_HOST_TESTNET, ZODL_OHTTP_RELAY_URL_TESTNET, \
             ZODL_OHTTP_KEYS_DNS_NAME_TESTNET, ZODL_OHTTP_SIGNING_PUBKEY_TESTNET"
        )]
    );
}

#[test]
fn strict_mode_refuses_unknown_values() {
    for require in ["true", "yes", "2", " 1"] {
        assert_eq!(
            check_config(&both(), Some(require)),
            Err(vec![format!("{REQUIRE_VAR} must be 1, 0 or unset")]),
            "{require:?}"
        );
    }
}

#[test]
fn networks_must_not_share_a_value() {
    for ((main_var, main_value), (test_var, _)) in MAINNET.into_iter().zip(TESTNET) {
        // The same value, and the same value in another case (the scheme kept lowercase, as
        // the relay URL check requires).
        let other_case = match main_value.strip_prefix("https://") {
            Some(rest) => format!("https://{}", rest.to_ascii_uppercase()),
            None => main_value.to_ascii_uppercase(),
        };
        for shared in [main_value.to_owned(), other_case] {
            let mut values: BTreeMap<&str, &str> = both();
            values.insert(test_var, &shared);
            let problems = problems(&values, None);
            assert_eq!(problems.len(), 1, "{problems:?}");
            assert!(
                problems[0].starts_with(&format!("{main_var} and {test_var} must differ")),
                "{problems:?}"
            );
        }
    }
}

#[test]
fn shared_values_are_not_checked_when_one_network_is_off() {
    let mut values = config(&[&MAINNET]);
    values.insert("ZODL_OHTTP_GATEWAY_HOST_TESTNET", MAINNET[0].1);
    // Testnet is incomplete, so that is the only problem reported.
    let problems = problems(&values, None);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].starts_with("testnet OHTTP configuration is incomplete"));
}

#[test]
fn malformed_values_fail_without_echoing_them() {
    for (var, bad, rule) in [
        (
            "ZODL_OHTTP_RELAY_URL_MAINNET",
            "http://relay-mainnet.example/relay",
            "must be an https:// URL",
        ),
        (
            "ZODL_OHTTP_RELAY_URL_MAINNET",
            "https://user@relay-mainnet.example/relay",
            "must not contain userinfo",
        ),
        (
            "ZODL_OHTTP_GATEWAY_HOST_MAINNET",
            "https://ohttp-gateway.example",
            "must be a bare DNS host name (no scheme, port, path or trailing dot)",
        ),
        (
            "ZODL_OHTTP_KEYS_DNS_NAME_MAINNET",
            "mainnet.ohttp-keys.example.",
            "must be a bare DNS host name (no scheme, port, path or trailing dot)",
        ),
        (
            "ZODL_OHTTP_SIGNING_PUBKEY_MAINNET",
            "111111111111111111111111111111111111111111111111111111111111111z",
            "must be a raw Ed25519 public key as 64 hex digits, got 64 characters",
        ),
    ] {
        let mut values = both();
        values.insert(var, bad);
        assert_eq!(
            problems(&values, None),
            vec![format!("{var} {rule}")],
            "{var}"
        );
    }
}

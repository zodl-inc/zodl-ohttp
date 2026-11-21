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

//! The runtime OHTTP configuration: what `OhttpConfig::new` and `OhttpNetworks::new` accept and
//! refuse, and that neither an error nor a `Debug` output ever shows a value.

use ed25519_dalek::SigningKey;
use zodl_ohttp_client::{
    signed_config_url, ConfigError, ConfigField, Network, OhttpConfig, OhttpConfigParams,
    OhttpNetworks, SignedConfigUrlRule,
};

/// The four values of one network, in the field order of `OhttpConfigParams`.
type Values = [String; 4];

fn key_hex(seed: u8) -> String {
    hex::encode(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .as_bytes(),
    )
}

fn mainnet() -> Values {
    [
        "ohttp-gateway.example".into(),
        "https://relay-mainnet.example/relay".into(),
        "mainnet.ohttp-keys.example".into(),
        key_hex(1),
    ]
}

fn testnet() -> Values {
    [
        "ohttp-gateway-testnet.example".into(),
        "https://relay-testnet.example/relay".into(),
        "testnet.ohttp-keys.example".into(),
        key_hex(2),
    ]
}

fn build(values: &Values) -> Result<OhttpConfig, ConfigError> {
    OhttpConfig::new(OhttpConfigParams {
        gateway_host: &values[0],
        relay_url: &values[1],
        keys_dns_name: &values[2],
        signing_pubkey: &values[3],
    })
}

/// `values` with field `index` replaced by `value`.
fn with(mut values: Values, index: usize, value: &str) -> Values {
    values[index] = value.into();
    values
}

/// Checks that neither the error's `Display` nor its `Debug` contains any of `values`.
fn assert_no_value(error: &ConfigError, values: &[&str]) {
    let shown = format!("{error} {error:?}");
    for value in values.iter().filter(|value| value.len() > 2) {
        assert!(!shown.contains(value), "{shown:?} shows {value:?}");
    }
}

#[test]
fn a_complete_configuration_is_accepted_as_given() {
    let values = mainnet();
    let config = build(&values).unwrap();
    assert_eq!(config.gateway_host(), values[0]);
    assert_eq!(config.relay_url(), values[1]);
    assert_eq!(config.keys_dns_name(), values[2]);
    assert_eq!(hex::encode(config.signing_pubkey().as_bytes()), values[3]);
    // A port, no path, IP literals and an upper-case host in the relay URL are fine, and so are
    // upper-case hex digits in the signing key.
    for relay in [
        "https://relay.example:8443/relay",
        "https://relay.example",
        "https://Relay.Example/relay",
        "https://192.0.2.1/relay",
        "https://[2001:db8::1]:443/relay",
        "https://[::ffff:192.0.2.1]/relay",
        "https://[::1]/relay",
        "https://[2001:DB8::1]/relay",
        "https://relay.example/a/relay",
    ] {
        build(&with(mainnet(), 1, relay)).unwrap();
    }
    build(&with(mainnet(), 3, &key_hex(1).to_ascii_uppercase())).unwrap();
}

#[test]
fn every_field_must_be_set() {
    for (index, field) in ConfigField::ALL.into_iter().enumerate() {
        let error = build(&with(mainnet(), index, "")).unwrap_err();
        assert_eq!(error, ConfigError::Empty { field });
        assert_eq!(error.field(), field);
        assert_eq!(
            error.to_string(),
            format!("OHTTP configuration: {} is empty", field.as_str())
        );
    }
    // The first empty field in argument order is reported.
    let error = OhttpConfig::new(OhttpConfigParams {
        gateway_host: "",
        relay_url: "",
        keys_dns_name: "",
        signing_pubkey: "",
    })
    .unwrap_err();
    assert_eq!(
        error,
        ConfigError::Empty {
            field: ConfigField::GatewayHost
        }
    );
}

#[test]
fn malformed_values_are_refused_naming_the_field_only() {
    let cases: [(usize, &[&str]); 4] = [
        (
            0,
            &[
                "https://ohttp-gateway.example",
                "ohttp-gateway.example:443",
                "ohttp-gateway.example/path",
                "ohttp-gateway.example.",
                " ohttp-gateway.example",
                "ohttp-gateway.example\n",
                "-gateway.example",
                "gateway-.example",
                "ohttp..example",
                "ohttp_gateway.example",
                "user@ohttp-gateway.example",
                "OHTTP-Gateway.example",
            ],
        ),
        (
            1,
            &[
                "http://relay-mainnet.example/relay",
                "relay-mainnet.example/relay",
                "HTTPS://relay-mainnet.example/relay",
                "https://",
                "https:///relay",
                "https://:443/relay",
                "https://[]/relay",
                "https://user@relay-mainnet.example/relay",
                "https://user:secret-password@relay-mainnet.example/relay",
                "https://relay-mainnet.example/re lay",
                "https://relay-mainnet.example/relay\n",
                "https://relay-mainnet.example/relay\t",
                "https://relay-mainnet.example/relay?x=1",
                "https://relay-mainnet.example/relay#part",
                "https://evil.example\\relay-mainnet.example/relay",
                "https://[::1/relay",
                "https://[relay-mainnet.example]/relay",
                "https://[::1]x/relay",
                "https://relay-mainnet.example:abc/relay",
                "https://relay-mainnet.example:0/relay",
                "https://relay-mainnet.example:65536/relay",
                "https://relay-mainnet.example:/relay",
                "https://relay_mainnet.example/relay",
                "https://relay-mainnet.example%2e/relay",
                "https://relé.example/relay",
                "https://relay-mainnet.example/relay//",
                "https://relay-mainnet.example//relay",
                "https://relay-mainnet.example/a%2Frelay",
                "https://relay-mainnet.example/a/..//relay",
                "https://relay-mainnet.example/%2e%2e/%2F",
                "https://relay-mainnet.example/re%+aay",
                "https://relay-mainnet.example/relay%",
                "https://relay-mainnet.example/relay%4",
                "https://relay-mainnet.example/a%5crelay",
                "https://[:]/relay",
                "https://[:::]/relay",
                "https://[::g]/relay",
                "https://[1:2:3:4:5:6:7:8:9]/relay",
                "https://[::1%25eth0]/relay",
                "https://192.0.2.300/relay",
                "https://1.2.3.4.5/relay",
                "https://0x100000000/relay",
                "https://ohttp-gateway.example/relay",
            ],
        ),
        (
            2,
            &[
                "mainnet.ohttp-keys.example.",
                "https://mainnet.ohttp-keys.example",
                "mainnet ohttp-keys.example",
                "Mainnet.ohttp-keys.example",
            ],
        ),
        (
            3,
            &[
                "11",
                "zz11111111111111111111111111111111111111111111111111111111111111",
                "0x1111111111111111111111111111111111111111111111111111111111111111",
                "1111111111111111111111111111111111111111111111111111111111111111aa",
                // A small-order point (the identity).
                "0100000000000000000000000000000000000000000000000000000000000000",
            ],
        ),
    ];
    let long_label = format!("{}.example", "a".repeat(64));
    let long_name = format!("{}example", "abcdefgh.".repeat(29));
    let host_names = [long_label.as_str(), long_name.as_str()];
    for (index, values) in cases
        .iter()
        .copied()
        .chain([(0, &host_names[..]), (2, &host_names[..])])
    {
        let field = ConfigField::ALL[index];
        for &value in values {
            let error = build(&with(mainnet(), index, value)).unwrap_err();
            let ConfigError::Invalid { field: got, rule } = error else {
                panic!("{value:?}: {error:?}");
            };
            assert_eq!(got, field, "{value:?}");
            assert!(!rule.is_empty());
            assert!(
                error
                    .to_string()
                    .starts_with(&format!("OHTTP configuration: {field} ")),
                "{error}"
            );
            assert_no_value(&error, &[value, value.trim()]);
        }
    }
}

#[test]
fn a_signing_key_off_the_curve_is_refused() {
    // The first encoding `[i, 0, ..., 0]` that is not a point on the curve.
    let bytes = (2..=u8::MAX)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[0] = i;
            bytes
        })
        .find(|bytes| ed25519_dalek::VerifyingKey::from_bytes(bytes).is_err())
        .expect("some encoding is off the curve");
    let error = build(&with(mainnet(), 3, &hex::encode(bytes))).unwrap_err();
    assert_eq!(
        error,
        ConfigError::Invalid {
            field: ConfigField::SigningPubkey,
            rule: "is not a valid Ed25519 public key"
        }
    );
}

#[test]
fn the_relay_url_rules_are_specific() {
    let rule = |relay: &str| match build(&with(mainnet(), 1, relay)) {
        Err(ConfigError::Invalid { rule, .. }) => rule,
        other => panic!("{relay}: {other:?}"),
    };
    assert_eq!(
        rule("http://relay.example/relay"),
        "must be an https:// URL"
    );
    assert_eq!(
        rule("https://user@relay.example/relay"),
        "must not contain userinfo"
    );
    assert_eq!(rule("https://:443/relay"), "must have a non-empty host");
    assert_eq!(
        rule("https://relay.example/re lay"),
        "must not contain whitespace or control characters"
    );
    assert_eq!(
        rule("https://relay.example/relay?x=1"),
        "must not contain a query or fragment"
    );
    assert_eq!(
        rule("https://evil.example\\relay.example/relay"),
        "must not contain a backslash"
    );
    assert_eq!(
        rule("https://relay.example:abc/relay"),
        "must have a numeric port from 1 to 65535"
    );
    assert_eq!(
        rule("https://re_lay.example/relay"),
        "must have a valid host"
    );
    // An empty path segment, or an encoded slash or backslash.
    for relay in [
        "https://relay.example/relay//",
        "https://relay.example//relay",
    ] {
        assert_eq!(
            rule(relay),
            "must not contain an empty path segment ('//')",
            "{relay}"
        );
    }
    for relay in [
        "https://relay.example/a%2Frelay",
        "https://relay.example/a%2frelay",
        "https://relay.example/a%5Crelay",
    ] {
        assert_eq!(
            rule(relay),
            "must not contain an encoded '/' or '\\'",
            "{relay}"
        );
    }
    // IPv6 literals are parsed, not just checked for their characters.
    for relay in [
        "https://[:]/relay",
        "https://[:::]/relay",
        "https://[1:2:3:4:5:6:7:8:9]/relay",
    ] {
        assert_eq!(rule(relay), "must have a valid host", "{relay}");
    }
    // A relay on the gateway's own host would hand the gateway the client's address.
    for relay in [
        "https://ohttp-gateway.example/relay",
        "https://OHTTP-Gateway.example:8443/relay",
        "https://ohttp-gateway.example",
    ] {
        assert_eq!(rule(relay), "must not be on a gateway host", "{relay}");
    }
}

#[test]
fn a_relay_is_compared_by_host_port_and_path() {
    let main = || build(&mainnet()).unwrap();
    let shared = |relay: &str| {
        OhttpNetworks::new(
            Some(main()),
            Some(build(&with(testnet(), 1, relay)).unwrap()),
        )
    };
    // The same relay, spelled differently: the default port, the host's case, the path's case.
    for relay in [
        "https://relay-mainnet.example:443/relay",
        "https://Relay-Mainnet.example/relay",
        "https://relay-mainnet.example/Relay",
    ] {
        assert_eq!(
            shared(relay).unwrap_err(),
            ConfigError::SharedAcrossNetworks {
                field: ConfigField::RelayUrl
            },
            "{relay}"
        );
    }
    // Another port or path is another relay.
    for relay in [
        "https://relay-mainnet.example:8443/relay",
        "https://relay-mainnet.example/relay-testnet",
        "https://relay-mainnet.example",
    ] {
        shared(relay).unwrap();
    }
    // An IPv6 literal in any of its spellings.
    let at = |relay: &str| build(&with(mainnet(), 1, relay)).unwrap();
    let test_at = |relay: &str| build(&with(testnet(), 1, relay)).unwrap();
    assert_eq!(
        OhttpNetworks::new(
            Some(at("https://[2001:db8::1]/relay")),
            Some(test_at("https://[2001:DB8:0:0::1]:443/relay")),
        )
        .unwrap_err(),
        ConfigError::SharedAcrossNetworks {
            field: ConfigField::RelayUrl
        }
    );
    // Nor may one network's relay be on the other network's gateway host.
    for relay in [
        "https://ohttp-gateway.example/relay",
        "https://ohttp-gateway.example:8443/other",
    ] {
        assert_eq!(
            shared(relay).unwrap_err(),
            ConfigError::Invalid {
                field: ConfigField::RelayUrl,
                rule: "must not be on a gateway host"
            },
            "{relay}"
        );
    }
    assert_eq!(
        OhttpNetworks::new(
            Some(at("https://ohttp-gateway-testnet.example/relay")),
            Some(build(&testnet()).unwrap()),
        )
        .unwrap_err(),
        ConfigError::Invalid {
            field: ConfigField::RelayUrl,
            rule: "must not be on a gateway host"
        }
    );
}

#[test]
fn mainnet_and_testnet_must_differ_in_every_field() {
    OhttpNetworks::new(
        Some(build(&mainnet()).unwrap()),
        Some(build(&testnet()).unwrap()),
    )
    .unwrap();
    for (index, field) in ConfigField::ALL.into_iter().enumerate() {
        // The same value, and for the relay URL and the key the same value in another case (host
        // names must be lower-case).
        let shared = mainnet()[index].clone();
        let mut variants = vec![shared.clone()];
        match index {
            1 => variants.push(shared.to_ascii_uppercase().replace("HTTPS://", "https://")),
            3 => variants.push(shared.to_ascii_uppercase()),
            _ => {}
        }
        for value in variants {
            let test = build(&with(testnet(), index, &value)).unwrap();
            let error =
                OhttpNetworks::new(Some(build(&mainnet()).unwrap()), Some(test)).unwrap_err();
            assert_eq!(error, ConfigError::SharedAcrossNetworks { field });
            assert_eq!(
                error.to_string(),
                format!("OHTTP configuration: mainnet and testnet must not share the {field}")
            );
            assert_no_value(&error, &[&value]);
        }
    }
}

#[test]
fn a_single_network_or_none_is_fine() {
    let main = build(&mainnet()).unwrap();
    let only_main = OhttpNetworks::new(Some(main.clone()), None).unwrap();
    assert_eq!(only_main.get(Network::Mainnet), Some(&main));
    assert_eq!(only_main.get(Network::Testnet), None);
    // The testnet slot holding a configuration with mainnet's values is still one network.
    let only_test = OhttpNetworks::new(None, Some(main.clone())).unwrap();
    assert_eq!(only_test.get(Network::Testnet), Some(&main));
    assert_eq!(
        only_test.network_of_host("ohttp-gateway.example"),
        Some(Network::Testnet)
    );
    let off = OhttpNetworks::new(None, None).unwrap();
    assert_eq!(off, OhttpNetworks::default());
}

#[test]
fn ohttp_is_off_without_a_configuration() {
    let off = OhttpNetworks::default();
    for host in ["ohttp-gateway.example", "ohttp-gateway-testnet.example", ""] {
        assert_eq!(off.relay_for(host), None);
        assert_eq!(off.network_of_host(host), None);
    }
    for network in [Network::Mainnet, Network::Testnet] {
        assert!(off.get(network).is_none());
    }
}

#[test]
fn a_configured_network_maps_its_gateway_host_to_its_relay() {
    let networks = OhttpNetworks::new(
        Some(build(&mainnet()).unwrap()),
        Some(build(&testnet()).unwrap()),
    )
    .unwrap();
    assert_eq!(
        networks.relay_for("ohttp-gateway.example"),
        Some("https://relay-mainnet.example/relay")
    );
    assert_eq!(
        networks.relay_for("ohttp-gateway-testnet.example"),
        Some("https://relay-testnet.example/relay")
    );
    assert_eq!(
        networks.network_of_host("ohttp-gateway-testnet.example"),
        Some(Network::Testnet)
    );
    // Exact host matches only.
    for host in [
        "OHTTP-GATEWAY.example",
        "ohttp-gateway.example.evil.example",
        "relay-mainnet.example",
    ] {
        assert_eq!(networks.relay_for(host), None, "{host}");
    }
}

#[test]
fn debug_output_shows_no_value() {
    let main_values = mainnet();
    let test_values = testnet();
    let networks = OhttpNetworks::new(
        Some(build(&main_values).unwrap()),
        Some(build(&test_values).unwrap()),
    )
    .unwrap();
    let config = networks.get(Network::Mainnet).unwrap();
    assert_eq!(
        format!("{config:?}"),
        "OhttpConfig { gateway_host: <set>, relay_url: <set>, keys_dns_name: <set>, \
         signing_pubkey: <set> }"
    );
    let shown = format!("{networks:?} {networks:#?} {config:#?}");
    for value in main_values.iter().chain(&test_values) {
        assert!(!shown.contains(value.as_str()), "{shown}");
    }
    for part in ["example", "https", "://"] {
        assert!(!shown.contains(part), "{shown}");
    }
    assert!(format!("{:?}", OhttpNetworks::default()).contains("None"));
    // The parameters do not show their values either, only whether each is empty.
    let params = OhttpConfigParams {
        gateway_host: &main_values[0],
        relay_url: "",
        keys_dns_name: &main_values[2],
        signing_pubkey: &main_values[3],
    };
    assert_eq!(
        format!("{params:?}"),
        "OhttpConfigParams { gateway_host: <set>, relay_url: <empty>, keys_dns_name: <set>, \
         signing_pubkey: <set> }"
    );
    let shown = format!("{params:#?}");
    for value in &main_values {
        assert!(!shown.contains(value.as_str()), "{shown}");
    }
}

/// The relay URL is kept in its canonical form: what the client posts to, and what the
/// comparison between networks reads.
#[test]
fn a_relay_url_is_kept_canonical() {
    let canonical = |relay: &str| {
        build(&with(mainnet(), 1, relay))
            .unwrap()
            .relay_url()
            .to_string()
    };
    for (given, kept) in [
        // One trailing slash is removed, so configurations that ended in one keep working.
        (
            "https://relay.example/relay/",
            "https://relay.example/relay",
        ),
        ("https://relay.example/", "https://relay.example"),
        ("https://relay.example", "https://relay.example"),
        // Host case and the default port.
        (
            "https://Relay.Example:443/relay",
            "https://relay.example/relay",
        ),
        (
            "https://relay.example:8443/relay",
            "https://relay.example:8443/relay",
        ),
        // Dot segments and percent-encoding.
        (
            "https://relay.example/a/../relay",
            "https://relay.example/relay",
        ),
        (
            "https://relay.example/./relay",
            "https://relay.example/relay",
        ),
        (
            "https://relay.example/%72elay",
            "https://relay.example/relay",
        ),
        (
            "https://relay.example/re%7elay",
            "https://relay.example/re~lay",
        ),
        ("https://relay.example/a%3aB", "https://relay.example/a%3AB"),
        // Every IPv4 form the URL standard reads: hex, octal, a single integer, fewer parts.
        (
            "https://0xc0.0x00.0x02.0x01/relay",
            "https://192.0.2.1/relay",
        ),
        ("https://0300.0.02.01/relay", "https://192.0.2.1/relay"),
        ("https://3221225985/relay", "https://192.0.2.1/relay"),
        ("https://192.0.513/relay", "https://192.0.2.1/relay"),
        // IPv6 in its standard form.
        (
            "https://[2001:DB8:0:0::1]:443/relay",
            "https://[2001:db8::1]/relay",
        ),
    ] {
        assert_eq!(canonical(given), kept, "{given}");
    }
}

/// Two spellings of one relay are one relay: an IPv4 address in any form, an IPv4-mapped IPv6
/// address, dot segments, percent-encoding and a trailing slash.
#[test]
fn equivalent_relay_urls_are_shared() {
    let main = |relay: &str| build(&with(mainnet(), 1, relay)).unwrap();
    let test = |relay: &str| build(&with(testnet(), 1, relay)).unwrap();
    for (a, b) in [
        ("https://192.0.2.1/relay", "https://0xc0000201/relay"),
        ("https://192.0.2.1/relay", "https://0300.0.2.1/relay"),
        ("https://192.0.2.1/relay", "https://3221225985/relay"),
        (
            "https://192.0.2.1/relay",
            "https://[::ffff:192.0.2.1]/relay",
        ),
        (
            "https://192.0.2.1:443/relay",
            "https://[::ffff:c000:201]/relay",
        ),
        (
            "https://relay.example/relay",
            "https://relay.example/a/../relay",
        ),
        (
            "https://relay.example/relay",
            "https://relay.example/%72elay",
        ),
        (
            "https://relay.example/relay",
            "https://relay.example/relay/",
        ),
        (
            "https://relay.example/relay",
            "https://RELAY.example/RELAY/",
        ),
    ] {
        assert_eq!(
            OhttpNetworks::new(Some(main(a)), Some(test(b))).unwrap_err(),
            ConfigError::SharedAcrossNetworks {
                field: ConfigField::RelayUrl
            },
            "{a} {b}"
        );
    }
    // Distinct hosts, ports and paths stay distinct.
    for (a, b) in [
        ("https://192.0.2.1/relay", "https://192.0.2.2/relay"),
        (
            "https://192.0.2.1/relay",
            "https://[::ffff:192.0.2.2]/relay",
        ),
        (
            "https://relay.example/relay",
            "https://relay.example:8443/relay",
        ),
        (
            "https://relay.example/relay",
            "https://relay.example/a/relay",
        ),
    ] {
        OhttpNetworks::new(Some(main(a)), Some(test(b))).unwrap();
    }
}

/// The forbidden path syntax is found as written, before the parser resolves dot segments or
/// decodes anything.
#[test]
fn the_path_is_checked_as_written() {
    let rule = |relay: &str| match build(&with(mainnet(), 1, relay)) {
        Err(ConfigError::Invalid { rule, .. }) => rule,
        other => panic!("{relay}: {other:?}"),
    };
    for relay in [
        "https://relay.example/a/..//relay",
        "https://relay.example//../relay",
        "https://relay.example/a//../relay",
    ] {
        assert_eq!(
            rule(relay),
            "must not contain an empty path segment ('//')",
            "{relay}"
        );
    }
    for relay in [
        "https://relay.example/%2e%2e/%2F",
        "https://relay.example/a/%2f../relay",
        "https://relay.example/%5C/relay",
    ] {
        assert_eq!(
            rule(relay),
            "must not contain an encoded '/' or '\\'",
            "{relay}"
        );
    }
    for relay in [
        "https://relay.example/re%+aay",
        "https://relay.example/re%g1ay",
        "https://relay.example/relay%",
        "https://relay.example/relay%4",
    ] {
        assert_eq!(
            rule(relay),
            "must not contain a '%' not followed by two hex digits",
            "{relay}"
        );
    }
}

/// The shapes shipped configurations use are kept as written, and derive the signed
/// configuration's URL under every rule as before.
#[test]
fn the_shipped_shapes_are_unchanged() {
    use SignedConfigUrlRule::*;
    for (relay, replaced, root) in [
        (
            "https://relay-mainnet.example/relay",
            "https://relay-mainnet.example/ohttp-configs/signed",
            "https://relay-mainnet.example/ohttp-configs/signed",
        ),
        (
            "https://relay-mainnet.example/mainnet",
            "https://relay-mainnet.example/mainnet/ohttp-configs/signed",
            "https://relay-mainnet.example/ohttp-configs/signed",
        ),
        (
            "https://relay.example/mainnet/relay",
            "https://relay.example/mainnet/ohttp-configs/signed",
            "https://relay.example/ohttp-configs/signed",
        ),
    ] {
        let config = build(&with(mainnet(), 1, relay)).unwrap();
        assert_eq!(config.relay_url(), relay);
        for (rule, want) in [
            (TrimThenReplaceRelaySuffix, replaced),
            (ReplaceRelaySuffix, replaced),
            (RelayHostRoot, root),
        ] {
            assert_eq!(
                signed_config_url(config.relay_url(), rule).unwrap(),
                want,
                "{relay} {rule:?}"
            );
        }
    }
}

#[test]
fn a_relay_list_keeps_the_first_relay_as_the_relay_url() {
    let list = "https://relay-a.example/relay,https://relay-b.example/x";
    let config = build(&with(mainnet(), 1, list)).unwrap();
    assert_eq!(config.relay_url(), "https://relay-a.example/relay");
    assert_eq!(config.relays().len(), 2);
    let networks = OhttpNetworks::new(Some(config), None).unwrap();
    // Stable: the first relay, whatever the choice.
    for _ in 0..50 {
        assert_eq!(
            networks.relay_for("ohttp-gateway.example"),
            Some("https://relay-a.example/relay")
        );
    }
    // The envelope URL derives from it, as with one relay.
    assert_eq!(
        signed_config_url(
            networks.relay_for("ohttp-gateway.example").unwrap(),
            SignedConfigUrlRule::ReplaceRelaySuffix
        )
        .unwrap(),
        "https://relay-a.example/ohttp-configs/signed"
    );
    let mut seen = std::collections::HashSet::new();
    for _ in 0..500 {
        seen.insert(networks.choose_relay_for("ohttp-gateway.example").unwrap());
    }
    assert_eq!(seen.len(), 2);
    let twice = "https://relay-a.example/relay,https://RELAY-A.example/relay/";
    let error = build(&with(mainnet(), 1, twice)).unwrap_err();
    assert_eq!(error.field(), ConfigField::RelayUrl);
    assert_no_value(&error, &["relay-a.example", "RELAY-A"]);
}

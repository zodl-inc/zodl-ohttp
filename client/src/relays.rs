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

//! Build-time endpoint configuration: gateway host names and relay URLs per network.
//!
//! The crate carries no endpoint of its own. Every value is read at compile time from the
//! environment of the build:
//!
//! - `ZODL_OHTTP_GATEWAY_HOST_MAINNET`, `ZODL_OHTTP_GATEWAY_HOST_TESTNET`: the gateway host
//!   name (the inner request authority of the light client server) of each network.
//! - `ZODL_OHTTP_RELAY_URL_MAINNET`, `ZODL_OHTTP_RELAY_URL_TESTNET`: the relay URL clients post
//!   sealed requests to, `https://` only.
//! - `ZODL_OHTTP_SIGNING_PUBKEY_MAINNET`, `ZODL_OHTTP_SIGNING_PUBKEY_TESTNET`: the gateway's
//!   key-configuration signing key (see `signed.rs`).
//! - `ZODL_OHTTP_KEYS_DNS_NAME_MAINNET`, `ZODL_OHTTP_KEYS_DNS_NAME_TESTNET`: the DNS TXT name of
//!   the signed key configuration, a last-resort source (see `dns.rs`).
//!
//! The build script (`client/build.rs`) enforces these rules, so a build only ever has a network
//! either fully configured or off:
//!
//! - A network is configured with all four of its variables or with none. Setting some of them
//!   and leaving another unset or empty fails the build, naming the network and the missing
//!   variables.
//! - With none set, OHTTP is off for that network: [`relay_for`] returns `None` and
//!   [`crate::NetworkRule::KnownHosts`] refuses every host of it. With nothing set at all the
//!   build succeeds with OHTTP off for both networks.
//! - `ZODL_OHTTP_REQUIRE=1` (opt-in) fails the build unless all eight variables are set.
//! - When both networks are configured, they must not share a gateway host, relay URL, keys DNS
//!   name or signing key.
//! - A malformed value fails the build. Messages name the variable and the rule, never the value.
//!
//! There is no fallback value and no runtime override; changing a variable triggers a rebuild.

use crate::signed::Network;

/// `value` when it is set and not empty.
const fn configured(value: Option<&'static str>) -> Option<&'static str> {
    match value {
        Some(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

/// The mainnet gateway host name (`ZODL_OHTTP_GATEWAY_HOST_MAINNET`), `None` when the build
/// did not set it.
pub const GATEWAY_HOST_MAINNET: Option<&str> =
    configured(option_env!("ZODL_OHTTP_GATEWAY_HOST_MAINNET"));

/// The testnet gateway host name (`ZODL_OHTTP_GATEWAY_HOST_TESTNET`), `None` when the build
/// did not set it.
pub const GATEWAY_HOST_TESTNET: Option<&str> =
    configured(option_env!("ZODL_OHTTP_GATEWAY_HOST_TESTNET"));

/// The mainnet relay URL (`ZODL_OHTTP_RELAY_URL_MAINNET`).
const RELAY_URL_MAINNET: Option<&str> = configured(option_env!("ZODL_OHTTP_RELAY_URL_MAINNET"));

/// The testnet relay URL (`ZODL_OHTTP_RELAY_URL_TESTNET`).
const RELAY_URL_TESTNET: Option<&str> = configured(option_env!("ZODL_OHTTP_RELAY_URL_TESTNET"));

/// The mainnet signing key (`ZODL_OHTTP_SIGNING_PUBKEY_MAINNET`), hex.
pub(crate) const SIGNING_PUBKEY_MAINNET: Option<&str> =
    configured(option_env!("ZODL_OHTTP_SIGNING_PUBKEY_MAINNET"));

/// The testnet signing key (`ZODL_OHTTP_SIGNING_PUBKEY_TESTNET`), hex.
pub(crate) const SIGNING_PUBKEY_TESTNET: Option<&str> =
    configured(option_env!("ZODL_OHTTP_SIGNING_PUBKEY_TESTNET"));

/// The mainnet DNS TXT name (`ZODL_OHTTP_KEYS_DNS_NAME_MAINNET`).
pub(crate) const KEYS_DNS_NAME_MAINNET: Option<&str> =
    configured(option_env!("ZODL_OHTTP_KEYS_DNS_NAME_MAINNET"));

/// The testnet DNS TXT name (`ZODL_OHTTP_KEYS_DNS_NAME_TESTNET`).
pub(crate) const KEYS_DNS_NAME_TESTNET: Option<&str> =
    configured(option_env!("ZODL_OHTTP_KEYS_DNS_NAME_TESTNET"));

/// The endpoint configuration of one network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NetworkEndpoints {
    pub(crate) gateway_host: Option<&'static str>,
    pub(crate) relay_url: Option<&'static str>,
    pub(crate) signing_key_hex: Option<&'static str>,
    pub(crate) keys_dns_name: Option<&'static str>,
}

impl NetworkEndpoints {
    /// Whether OHTTP is on for this network: gateway host, relay URL and signing key set. The
    /// build script also requires the keys DNS name with them, so a built-in network has all
    /// four or none; test tables may leave the DNS name out.
    fn enabled(&self) -> bool {
        self.gateway_host.is_some() && self.relay_url.is_some() && self.signing_key_hex.is_some()
    }
}

/// The endpoint configuration of both networks. The library uses [`Endpoints::BUILT_IN`];
/// tests build their own with example values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Endpoints {
    pub(crate) mainnet: NetworkEndpoints,
    pub(crate) testnet: NetworkEndpoints,
}

impl Endpoints {
    /// The values the build set.
    pub(crate) const BUILT_IN: Endpoints = Endpoints {
        mainnet: NetworkEndpoints {
            gateway_host: GATEWAY_HOST_MAINNET,
            relay_url: RELAY_URL_MAINNET,
            signing_key_hex: SIGNING_PUBKEY_MAINNET,
            keys_dns_name: KEYS_DNS_NAME_MAINNET,
        },
        testnet: NetworkEndpoints {
            gateway_host: GATEWAY_HOST_TESTNET,
            relay_url: RELAY_URL_TESTNET,
            signing_key_hex: SIGNING_PUBKEY_TESTNET,
            keys_dns_name: KEYS_DNS_NAME_TESTNET,
        },
    };

    /// The configuration of `network`.
    pub(crate) fn network(&self, network: Network) -> &NetworkEndpoints {
        match network {
            Network::Mainnet => &self.mainnet,
            Network::Testnet => &self.testnet,
        }
    }

    /// The network whose gateway host is exactly `gateway_host`, if one is configured.
    pub(crate) fn network_of_host(&self, gateway_host: &str) -> Option<Network> {
        [Network::Mainnet, Network::Testnet]
            .into_iter()
            .find(|&network| self.network(network).gateway_host == Some(gateway_host))
    }

    /// The relay URL for `gateway_host`, when that host is the gateway of a network that is on.
    pub(crate) fn relay_for(&self, gateway_host: &str) -> Option<&'static str> {
        let endpoints = self.network(self.network_of_host(gateway_host)?);
        if endpoints.enabled() {
            endpoints.relay_url
        } else {
            None
        }
    }
}

/// Returns the relay URL for a gateway host, or `None` if the host is not the gateway of a
/// network that this build turned on.
///
/// A network is on when the build configured it: gateway host (`ZODL_OHTTP_GATEWAY_HOST_*`),
/// relay URL (`ZODL_OHTTP_RELAY_URL_*`), signing key (`ZODL_OHTTP_SIGNING_PUBKEY_*`) and keys DNS
/// name (`ZODL_OHTTP_KEYS_DNS_NAME_*`), which the build script requires together. `None` means
/// OHTTP is off for that host.
///
/// Only exact host matches are supported; no prefix/suffix matching.
pub fn relay_for(gateway_host: &str) -> Option<&'static str> {
    Endpoints::BUILT_IN.relay_for(gateway_host)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Both networks on, with example values (RFC 2606).
    pub(crate) const EXAMPLE: Endpoints = Endpoints {
        mainnet: NetworkEndpoints {
            gateway_host: Some("ohttp-gateway.example"),
            relay_url: Some("https://relay-mainnet.example/relay"),
            signing_key_hex: Some(
                "1111111111111111111111111111111111111111111111111111111111111111",
            ),
            keys_dns_name: Some("mainnet.ohttp-keys.example"),
        },
        testnet: NetworkEndpoints {
            gateway_host: Some("ohttp-gateway-testnet.example"),
            relay_url: Some("https://relay-testnet.example/relay"),
            signing_key_hex: Some(
                "2222222222222222222222222222222222222222222222222222222222222222",
            ),
            keys_dns_name: Some("testnet.ohttp-keys.example"),
        },
    };

    #[test]
    fn configured_drops_empty_values() {
        assert_eq!(configured(None), None);
        assert_eq!(configured(Some("")), None);
        assert_eq!(configured(Some("a.example")), Some("a.example"));
    }

    #[test]
    fn relay_for_maps_each_configured_gateway() {
        assert_eq!(
            EXAMPLE.relay_for("ohttp-gateway.example"),
            Some("https://relay-mainnet.example/relay")
        );
        assert_eq!(
            EXAMPLE.relay_for("ohttp-gateway-testnet.example"),
            Some("https://relay-testnet.example/relay")
        );
        assert_eq!(EXAMPLE.relay_for("unknown.example"), None);
        assert_eq!(EXAMPLE.relay_for("ohttp-gateway-staging.example"), None);
    }

    #[test]
    fn relay_for_matches_exact_hosts_only() {
        // Prefix match should not work
        assert_eq!(EXAMPLE.relay_for("ohttp-gateway"), None);
        // Suffix match should not work
        assert_eq!(EXAMPLE.relay_for(".example"), None);
        // Substring match should not work
        assert_eq!(
            EXAMPLE.relay_for("ohttp-gateway.example.evil.example"),
            None
        );
        // Case matters
        assert_eq!(EXAMPLE.relay_for("OHTTP-GATEWAY.example"), None);
    }

    #[test]
    fn a_network_missing_any_value_is_off() {
        for strip in 0..3 {
            let mut endpoints = EXAMPLE;
            match strip {
                0 => endpoints.mainnet.gateway_host = None,
                1 => endpoints.mainnet.relay_url = None,
                _ => endpoints.mainnet.signing_key_hex = None,
            }
            assert_eq!(
                endpoints.relay_for("ohttp-gateway.example"),
                None,
                "{strip}"
            );
            // The other network is unaffected.
            assert_eq!(
                endpoints.relay_for("ohttp-gateway-testnet.example"),
                Some("https://relay-testnet.example/relay")
            );
        }
        let off = Endpoints {
            mainnet: NetworkEndpoints {
                gateway_host: None,
                relay_url: None,
                signing_key_hex: None,
                keys_dns_name: None,
            },
            testnet: NetworkEndpoints {
                gateway_host: None,
                relay_url: None,
                signing_key_hex: None,
                keys_dns_name: None,
            },
        };
        assert_eq!(off.relay_for(""), None);
        assert_eq!(off.network_of_host(""), None);
    }

    #[test]
    fn the_built_in_table_is_what_the_build_set() {
        let built_in = Endpoints::BUILT_IN;
        for network in [Network::Mainnet, Network::Testnet] {
            let endpoints = built_in.network(network);
            if let Some(url) = endpoints.relay_url {
                assert!(url.starts_with("https://"));
            }
            match endpoints.gateway_host {
                Some(host) if endpoints.enabled() => {
                    assert_eq!(relay_for(host), endpoints.relay_url);
                }
                Some(host) => assert_eq!(relay_for(host), None),
                None => {}
            }
        }
        assert_eq!(relay_for("unknown.example"), None);
    }
}

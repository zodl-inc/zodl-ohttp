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

//! The OHTTP configuration of each network, passed in by the application at runtime.
//!
//! The crate carries no endpoint, host name or key. An application that speaks OHTTP on a
//! network builds an [`OhttpConfig`] for it from [`OhttpConfigParams`] (gateway host, relay URL,
//! keys DNS name and signing key), then an [`OhttpNetworks`] holding the configuration of mainnet, testnet, both or neither,
//! and passes that to every function that needs one. A network without a configuration has
//! OHTTP off: [`OhttpNetworks::relay_for`] returns `None` for every host,
//! [`crate::NetworkRule::KnownHosts`] refuses them, and [`crate::verify_signed_config`] and the
//! DNS source refuse that network.
//!
//! Both constructors validate what they are given and fail with a [`ConfigError`] that names the
//! field and the rule, never the value. The `Debug` output of a configuration shows only which
//! fields are set, so a configuration can be logged without exposing it.

use std::fmt;

use ed25519_dalek::VerifyingKey;

use crate::relays::{parse_relay_list, Relay, RelaySelector};
use crate::signed::Network;

/// One value of an [`OhttpConfig`], as a [`ConfigError`] names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConfigField {
    /// [`OhttpConfig::gateway_host`].
    GatewayHost,
    /// [`OhttpConfig::relay_url`].
    RelayUrl,
    /// [`OhttpConfig::keys_dns_name`].
    KeysDnsName,
    /// [`OhttpConfig::signing_pubkey`].
    SigningPubkey,
}

impl ConfigField {
    /// Every field, in the order of [`OhttpConfigParams`]' fields.
    pub const ALL: [ConfigField; 4] = [
        ConfigField::GatewayHost,
        ConfigField::RelayUrl,
        ConfigField::KeysDnsName,
        ConfigField::SigningPubkey,
    ];

    /// The field's name: `gateway_host`, `relay_url`, `keys_dns_name` or `signing_pubkey`.
    pub const fn as_str(self) -> &'static str {
        match self {
            ConfigField::GatewayHost => "gateway_host",
            ConfigField::RelayUrl => "relay_url",
            ConfigField::KeysDnsName => "keys_dns_name",
            ConfigField::SigningPubkey => "signing_pubkey",
        }
    }
}

impl fmt::Display for ConfigField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why an OHTTP configuration was refused. Names the field and the rule, never the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// A field is empty.
    #[error("OHTTP configuration: {field} is empty")]
    Empty {
        /// The empty field.
        field: ConfigField,
    },
    /// A field is set but does not have the form its rule requires.
    #[error("OHTTP configuration: {field} {rule}")]
    Invalid {
        /// The malformed field.
        field: ConfigField,
        /// The rule it breaks, for example `must be an https:// URL`.
        rule: &'static str,
    },
    /// Mainnet and testnet have the same value of a field (host names compared ignoring ASCII
    /// case, relay URLs by host, port and path, see [`OhttpNetworks::new`]).
    #[error("OHTTP configuration: mainnet and testnet must not share the {field}")]
    SharedAcrossNetworks {
        /// The shared field.
        field: ConfigField,
    },
}

impl ConfigError {
    /// The field the error is about.
    pub const fn field(&self) -> ConfigField {
        match *self {
            ConfigError::Empty { field }
            | ConfigError::Invalid { field, .. }
            | ConfigError::SharedAcrossNetworks { field } => field,
        }
    }
}

/// The values of one network's OHTTP configuration, as the application has them, for
/// [`OhttpConfig::new`] to check. Named fields, so that two values of the same form (the gateway
/// host and the keys DNS name) cannot be swapped silently.
///
/// Its `Debug` output names the fields only, never their values.
#[derive(Clone, Copy)]
pub struct OhttpConfigParams<'a> {
    /// The gateway's host name, which is also the inner `:authority` of light client server
    /// requests; a lower-case bare DNS host name (no scheme, port, path or trailing dot).
    pub gateway_host: &'a str,
    /// The URL sealed requests are posted to; `https://`, a host (DNS name or IP address) other
    /// than a gateway host (both compared as the URL parser reads them, so a gateway host
    /// written as a numeric IPv4 alias is the address it names, and an IPv6 literal that embeds
    /// an IPv4 address, `::ffff:a.b.c.d`, `::a.b.c.d` (only when `a` and `b` are not both
    /// zero: `::` to `::ffff` are plain IPv6 addresses) or `64:ff9b::a.b.c.d`, is on that
    /// address), an optional numeric port and an optional path; ASCII, without userinfo, query,
    /// fragment, backslash, whitespace, control characters, encoded `/` or `\` and empty path
    /// segments. Kept in its canonical form ([`OhttpConfig::relay_url`]), one trailing `/`
    /// removed.
    ///
    /// Or several relays: relay URLs under the rules above separated by `,`, each one after the
    /// first starting `https://` (a value is read as a list only where a `,` is followed by
    /// `https://`: any other `,` stays part of a URL's path, as before; an entry other than the last
    /// must not end with `,`), at most 8, no relay twice. Each request then goes to one of them at random, each relay getting an equal
    /// share, and to another while one fails (see [`crate::RelaySelector`]). The order is
    /// significant: the first relay is the network's relay as [`OhttpConfig::relay_url`] gives
    /// it (the signed key configuration is fetched through it first), relays fail over in list
    /// order, and [`OhttpConfig::relays`] keeps it, so that a relay can be referred
    /// to by its position. A client that splits its requests asks
    /// [`OhttpConfig::choose_relay`] for each one.
    pub relay_url: &'a str,
    /// The DNS TXT name of the gateway's signed key configuration, the last-resort source of
    /// it; a lower-case bare DNS host name.
    pub keys_dns_name: &'a str,
    /// The gateway's key-configuration signing key, raw Ed25519 as 64 hex digits (either case).
    pub signing_pubkey: &'a str,
}

impl fmt::Debug for OhttpConfigParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let values = [
            self.gateway_host,
            self.relay_url,
            self.keys_dns_name,
            self.signing_pubkey,
        ];
        let mut s = f.debug_struct("OhttpConfigParams");
        for (field, value) in ConfigField::ALL.into_iter().zip(values) {
            let shown: &dyn fmt::Debug = if value.is_empty() { &Unset } else { &Set };
            s.field(field.as_str(), shown);
        }
        s.finish()
    }
}

/// The OHTTP configuration of one network.
///
/// Built by [`OhttpConfig::new`], which validates every value; once built it is complete and
/// well-formed. Its `Debug` output names the fields only, never their values.
#[derive(Clone, PartialEq, Eq)]
pub struct OhttpConfig {
    gateway_host: String,
    /// The relays, in the order the configuration lists them; never empty.
    relays: Vec<Relay>,
    keys_dns_name: String,
    signing_pubkey: VerifyingKey,
    /// The gateway host as the URL parser reads it, for comparisons with relay hosts.
    gateway_key: String,
}

impl OhttpConfig {
    /// A network's configuration from `params`, each value checked as its field of
    /// [`OhttpConfigParams`] describes.
    ///
    /// Fails on the first empty or malformed value, in field order. Values are taken as given:
    /// surrounding whitespace is an error, not trimmed. The values are copied, the relay URL in
    /// its canonical form; `params` is not kept.
    pub fn new(params: OhttpConfigParams<'_>) -> Result<Self, ConfigError> {
        let OhttpConfigParams {
            gateway_host,
            relay_url,
            keys_dns_name,
            signing_pubkey,
        } = params;
        let values = [gateway_host, relay_url, keys_dns_name, signing_pubkey];
        for (field, value) in ConfigField::ALL.into_iter().zip(values) {
            if value.is_empty() {
                return Err(ConfigError::Empty { field });
            }
        }
        let invalid = |field| move |rule| ConfigError::Invalid { field, rule };
        check_host_name(gateway_host).map_err(invalid(ConfigField::GatewayHost))?;
        let relays = parse_relay_list(relay_url).map_err(invalid(ConfigField::RelayUrl))?;
        // A relay on the gateway's own host would hand the gateway the client's address. Both
        // sides in the URL parser's form, so that a gateway host written as a numeric IPv4
        // alias (`0xc0000201`, `0300.0.2.1`, `192.0.513`) matches a relay on that address, and
        // an IPv6 literal that embeds an IPv4 address matches a gateway on that address.
        let gateway_key = host_key(gateway_host);
        if relays.iter().any(|r| r.target.on_host(&gateway_key)) {
            return Err(invalid(ConfigField::RelayUrl)(RELAY_ON_GATEWAY_HOST));
        }
        check_host_name(keys_dns_name).map_err(invalid(ConfigField::KeysDnsName))?;
        let signing_pubkey =
            parse_signing_pubkey(signing_pubkey).map_err(invalid(ConfigField::SigningPubkey))?;
        Ok(OhttpConfig {
            gateway_host: gateway_host.to_owned(),
            relays,
            keys_dns_name: keys_dns_name.to_owned(),
            signing_pubkey,
            gateway_key,
        })
    }

    /// The gateway host name.
    pub fn gateway_host(&self) -> &str {
        &self.gateway_host
    }

    /// The relay URL, canonical: as given, but for a host in lower case and an IP address in its
    /// standard form, no `:443`, dot segments resolved, percent-encoding normalized and no
    /// trailing `/` (see [`OhttpConfigParams::relay_url`]).
    ///
    /// With a relay list, the first relay listed: the one the signed key configuration is
    /// fetched through ([`crate::signed_config_url`]). Always the same value, so it can key
    /// caches; the relay a request is posted to is [`choose_relay`](Self::choose_relay)'s.
    pub fn relay_url(&self) -> &str {
        self.relays[0].url()
    }

    /// The relay to post the next request to. With one relay, always
    /// [`relay_url`](Self::relay_url). With a list, a fresh random choice on every call (each
    /// relay an equal share), passed on
    /// down the failover order while the relay drawn is held out after a failure or paused by a
    /// `Retry-After` ([`crate::RelaySelector::global`]). Call it for each request, and report
    /// the outcome with [`crate::RelaySelector::note_failure`] /
    /// [`crate::RelaySelector::note_success`].
    pub fn choose_relay(&self) -> &str {
        self.relays[RelaySelector::global().choose(&self.relays)].url()
    }

    /// Gives the relays these shares instead of equal ones, for the tests of `Client`.
    #[cfg(all(test, feature = "client"))]
    pub(crate) fn set_shares_for_test(&mut self, shares: &[u32]) {
        self.relays = self
            .relays
            .iter()
            .zip(shares)
            .map(|(relay, &share)| crate::relays::Relay::weighted(relay.target.clone(), share))
            .collect();
    }

    /// The relays, in the order the configuration lists them.
    pub fn relays(&self) -> &[Relay] {
        &self.relays
    }

    /// The DNS TXT name of the signed key configuration.
    pub fn keys_dns_name(&self) -> &str {
        &self.keys_dns_name
    }

    /// The key-configuration signing key.
    pub fn signing_pubkey(&self) -> &VerifyingKey {
        &self.signing_pubkey
    }
}

impl fmt::Debug for OhttpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Every field of a built configuration is set; the values are never printed.
        let mut s = f.debug_struct("OhttpConfig");
        for field in ConfigField::ALL {
            s.field(field.as_str(), &Set);
        }
        s.finish()
    }
}

/// Stands in for a set value in `Debug` output.
struct Set;

impl fmt::Debug for Set {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<set>")
    }
}

/// Stands in for an empty value in `Debug` output.
struct Unset;

impl fmt::Debug for Unset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<empty>")
    }
}

/// The OHTTP configuration of both networks; a network without one has OHTTP off.
///
/// [`OhttpNetworks::default`] has both networks off. Its `Debug` output shows which networks
/// are configured, never a value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OhttpNetworks {
    mainnet: Option<OhttpConfig>,
    testnet: Option<OhttpConfig>,
}

impl OhttpNetworks {
    /// The configuration of mainnet and testnet, `None` for a network with OHTTP off.
    ///
    /// When both are given they must not share a value: not the gateway host, the relay URL
    /// (the same host, port and path: the host and the path compared ignoring ASCII case, an IPv6
    /// literal in any of its spellings, an IPv6 literal that embeds an IPv4 address the same as
    /// that address, no port the same as port 443), the keys DNS name
    /// (ignoring ASCII case), nor the signing key. The error names the first shared field. Nor
    /// may one network's relay be on the other's gateway host
    /// ([`ConfigError::Invalid`] for [`ConfigField::RelayUrl`]). Gateway hosts are compared,
    /// with each other and with relay hosts, in the form the URL parser reads them in: a gateway
    /// host that is a numeric IPv4 alias (`0xc0000201`, `0300.0.2.1`, `192.0.513`) is the
    /// address it names, and a relay on an IPv6 literal that embeds an IPv4 address
    /// (`::ffff:a.b.c.d`, `64:ff9b::a.b.c.d`, or `::a.b.c.d` when `a` and `b` are not both
    /// zero, so not `::` to `::ffff`) is on that address.
    pub fn new(
        mainnet: Option<OhttpConfig>,
        testnet: Option<OhttpConfig>,
    ) -> Result<Self, ConfigError> {
        if let (Some(main), Some(test)) = (&mainnet, &testnet) {
            let on = |config: &OhttpConfig, gateway_key: &str| {
                config.relays.iter().any(|r| r.target.on_host(gateway_key))
            };
            if on(main, &test.gateway_key) || on(test, &main.gateway_key) {
                return Err(ConfigError::Invalid {
                    field: ConfigField::RelayUrl,
                    rule: RELAY_ON_GATEWAY_HOST,
                });
            }
            let shared = [
                (
                    ConfigField::GatewayHost,
                    main.gateway_key.eq_ignore_ascii_case(&test.gateway_key),
                ),
                (
                    ConfigField::RelayUrl,
                    main.relays
                        .iter()
                        .any(|m| test.relays.iter().any(|t| m.target.same_relay(&t.target))),
                ),
                (
                    ConfigField::KeysDnsName,
                    main.keys_dns_name.eq_ignore_ascii_case(&test.keys_dns_name),
                ),
                (
                    ConfigField::SigningPubkey,
                    main.signing_pubkey == test.signing_pubkey,
                ),
            ];
            if let Some(&(field, _)) = shared.iter().find(|&&(_, same)| same) {
                return Err(ConfigError::SharedAcrossNetworks { field });
            }
        }
        Ok(OhttpNetworks { mainnet, testnet })
    }

    /// The configuration of `network`, `None` when OHTTP is off for it.
    pub fn get(&self, network: Network) -> Option<&OhttpConfig> {
        match network {
            Network::Mainnet => self.mainnet.as_ref(),
            Network::Testnet => self.testnet.as_ref(),
        }
    }

    /// The network whose gateway host is exactly `gateway_host` (no case folding, no prefix or
    /// suffix matching), if one is configured.
    pub fn network_of_host(&self, gateway_host: &str) -> Option<Network> {
        [Network::Mainnet, Network::Testnet]
            .into_iter()
            .find(|&network| {
                self.get(network)
                    .is_some_and(|config| config.gateway_host == gateway_host)
            })
    }

    /// The relay URL for `gateway_host` ([`OhttpConfig::relay_url`]: with a relay list, the
    /// first relay listed), or `None` when it is not exactly the gateway host of a configured
    /// network: `None` means OHTTP is off for that host.
    pub fn relay_for(&self, gateway_host: &str) -> Option<&str> {
        let network = self.network_of_host(gateway_host)?;
        self.get(network).map(OhttpConfig::relay_url)
    }

    /// The relay to post the next request to `gateway_host` through
    /// ([`OhttpConfig::choose_relay`]: with a relay list, a fresh choice on every call), or
    /// `None` as for [`relay_for`](Self::relay_for).
    pub fn choose_relay_for(&self, gateway_host: &str) -> Option<&str> {
        let network = self.network_of_host(gateway_host)?;
        self.get(network).map(OhttpConfig::choose_relay)
    }

    /// The configuration of `network`, or [`crate::Error::KeyConfig`] naming the network when
    /// OHTTP is off for it.
    pub(crate) fn require(&self, network: Network) -> Result<&OhttpConfig, crate::Error> {
        self.get(network).ok_or_else(|| {
            crate::Error::KeyConfig(format!("no OHTTP configuration for {}", network.as_str()))
        })
    }
}

/// `value` in the canonical form [`OhttpConfig::relay_url`] keeps a relay URL in, under the
/// rules of [`OhttpConfigParams::relay_url`] (except the gateway-host rule, which needs the
/// gateway host): for a caller that posts to a relay URL it did not get from an [`OhttpConfig`].
/// The error is [`ConfigError::Invalid`] for [`ConfigField::RelayUrl`], naming the rule only.
pub fn canonical_relay_url(value: &str) -> Result<String, ConfigError> {
    if value.is_empty() {
        return Err(ConfigError::Empty {
            field: ConfigField::RelayUrl,
        });
    }
    parse_relay_url(value)
        .map(|relay| relay.url)
        .map_err(|rule| ConfigError::Invalid {
            field: ConfigField::RelayUrl,
            rule,
        })
}

/// `host` (a checked gateway host name) as the URL parser reads it and as
/// [`RelayTarget::host`] holds a relay host: a name that the URL standard reads as an IPv4
/// address (a numeric alias such as `0xc0000201`, `0300.0.2.1`, `3221225985` or `192.0.513`) as
/// that address in dotted decimal, any other name as the parser gives it (the same name, for
/// every name `check_host_name` accepts). A name the parser refuses (such as `1.2.3.4.5`) is
/// kept as given: no relay URL can name it, so it cannot match one.
fn host_key(host: &str) -> String {
    match url::Url::parse(&format!("https://{host}/")) {
        Ok(url) => match url.host() {
            Some(url::Host::Ipv4(ip)) => ip.to_string(),
            Some(url::Host::Domain(name)) => name.to_owned(),
            // Not reachable for a checked host name (no brackets, never empty).
            Some(url::Host::Ipv6(_)) | None => host.to_owned(),
        },
        Err(_) => host.to_owned(),
    }
}

/// The IPv4 address an IPv6 address `ip` that is not IPv4-mapped (`::ffff:a.b.c.d`, which
/// [`RelayTarget::host`] already holds as its IPv4 address) names in its last 32 bits: an
/// IPv4-compatible address (`::a.b.c.d`, RFC 4291 §2.5.5.1, deprecated), read as one only when
/// the high 16 bits of `a.b.c.d` are not zero (so not `::`, `::1` or `::2` to `::ffff`, which
/// are ordinary IPv6 addresses), or one under the NAT64 well-known prefix (`64:ff9b::a.b.c.d`,
/// RFC 6052 §2.1). A relay on such an address counts as on the gateway host of that IPv4
/// address, and as the same relay as one on it. Deliberately not matched:
/// an IPv4-translated address (`::ffff:0:a.b.c.d`), 6to4, Teredo and a network-specific NAT64
/// prefix, which name another host or cannot be told from the address alone.
fn embedded_ipv4(ip: &std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    let [a, b, c, d, e, f, high, low] = ip.segments();
    let compatible = [a, b, c, d, e, f] == [0; 6] && high != 0;
    let nat64 = [a, b, c, d, e, f] == [0x64, 0xff9b, 0, 0, 0, 0];
    (compatible || nat64).then(|| {
        let [o1, o2] = high.to_be_bytes();
        let [o3, o4] = low.to_be_bytes();
        std::net::Ipv4Addr::new(o1, o2, o3, o4)
    })
}

/// The rule broken by a relay URL on a gateway host.
const RELAY_ON_GATEWAY_HOST: &str = "must not be on a gateway host";

/// A checked relay URL, canonical.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelayTarget {
    /// The URL as the client uses it: `https://`, the host as the URL parser serializes it
    /// (lower case; an IPv4 address in dotted decimal whatever form it was written in; an IPv6
    /// literal bracketed, in its standard form), `:port` unless it is 443, and the path with its
    /// dot segments resolved, its percent-encoding normalized and one trailing `/` removed.
    pub(crate) url: String,
    /// The host for comparisons: as in `url` without brackets, an IPv4-mapped IPv6 address as
    /// its IPv4 address.
    pub(crate) host: String,
    /// The IPv4 address, dotted decimal, that an IPv6 literal host other than an IPv4-mapped
    /// one embeds ([`embedded_ipv4`]), for the gateway-host rule and relay identity.
    pub(crate) embedded_ipv4: Option<String>,
    /// The port, 443 when the URL has none.
    pub(crate) port: u16,
    /// The path as in `url` (empty for the root).
    pub(crate) path: String,
}

impl RelayTarget {
    /// Whether the relay is on the host `gateway_key` (a [`host_key`]): its host, or the IPv4
    /// address its IPv6 literal embeds.
    pub(crate) fn on_host(&self, gateway_key: &str) -> bool {
        self.host == gateway_key || self.embedded_ipv4.as_deref() == Some(gateway_key)
    }

    /// The host as relays are told apart: the IPv4 address an IPv6 literal embeds, else
    /// [`RelayTarget::host`].
    pub(crate) fn identity_host(&self) -> &str {
        self.embedded_ipv4.as_deref().unwrap_or(&self.host)
    }

    /// Whether `self` and `other` are the same relay: the same host (an IPv6 literal that
    /// embeds an IPv4 address as that address) and port and the same path ignoring ASCII case
    /// (conservative: two paths differing in case only count as one).
    pub(crate) fn same_relay(&self, other: &RelayTarget) -> bool {
        self.identity_host() == other.identity_host()
            && self.port == other.port
            && self.path.eq_ignore_ascii_case(&other.path)
    }
}

/// Checks a relay URL and returns its canonical form: `https://` (lower case, as written), then
/// a host (a DNS host name, an IPv4 address in any form the URL standard reads, or a bracketed
/// IPv6 address) with an optional port from 1 to 65535, then an optional path; ASCII only, no
/// userinfo, query, fragment, backslash, whitespace or control characters, no encoded `/` or
/// `\` (`%2F`, `%5C`) and no empty path segment (`//`). One trailing `/` is removed
/// (`https://relay.example/relay/` is `https://relay.example/relay`): the signed
/// key-configuration URL is derived from the relay URL by replacing its path, which a query,
/// a fragment or a trailing slash would break. The error completes "`relay_url` ...".
pub(crate) fn parse_relay_url(value: &str) -> Result<RelayTarget, &'static str> {
    let Some(after_scheme) = value.strip_prefix("https://") else {
        return Err("must be an https:// URL");
    };
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("must not contain whitespace or control characters");
    }
    // A host in Unicode would be read in its punycode form; the value must already be that.
    if !value.is_ascii() {
        return Err("must have a valid host");
    }
    if value.contains(['?', '#']) {
        return Err("must not contain a query or fragment");
    }
    // A backslash is read as a path separator by some URL parsers and not by others, so the
    // host would depend on who reads the URL.
    if value.contains('\\') {
        return Err("must not contain a backslash");
    }
    // The authority as written: the URL parser would skip extra slashes (`https:///relay`
    // naming the host `relay`) and drop an empty port (`host:`).
    let authority = after_scheme.split('/').next().unwrap_or_default();
    // No userinfo (`user@`, `user:password@`): a relay URL never carries credentials, and an
    // `@` would make the host something other than what the value seems to name.
    if authority.contains('@') {
        return Err("must not contain userinfo");
    }
    if authority.is_empty() || authority.starts_with(':') {
        return Err("must have a non-empty host");
    }
    if authority.ends_with(':') {
        return Err("must have a numeric port from 1 to 65535");
    }
    // The path as written, checked before the parser resolves dot segments, which could hide
    // an empty segment (`/a/..//relay`) or join an encoded separator to the path.
    check_raw_path(&after_scheme[authority.len()..])?;
    let url = match url::Url::parse(value) {
        Ok(url) => url,
        Err(url::ParseError::EmptyHost) => return Err("must have a non-empty host"),
        Err(url::ParseError::InvalidPort) => {
            return Err("must have a numeric port from 1 to 65535")
        }
        Err(_) => return Err("must have a valid host"),
    };
    let mut embedded = None;
    let host = match url.host() {
        Some(url::Host::Domain(name)) => {
            if check_host_name(name).is_err() {
                return Err("must have a valid host");
            }
            name.to_owned()
        }
        Some(url::Host::Ipv4(ip)) => ip.to_string(),
        Some(url::Host::Ipv6(ip)) => match ip.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                embedded = embedded_ipv4(&ip).map(|v4| v4.to_string());
                ip.to_string()
            }
        },
        None => return Err("must have a non-empty host"),
    };
    let port = match url.port() {
        Some(0) => return Err("must have a numeric port from 1 to 65535"),
        Some(port) => port,
        None => 443,
    };
    let path = url.path();
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") {
        return Err("must not contain an encoded '/' or '\\'");
    }
    let mut path = normalize_percent_encoding(path);
    // One trailing slash is dropped; the root (`/`) is the empty path.
    if path.ends_with('/') {
        path.pop();
    }
    if path.contains("//") || path.ends_with('/') {
        return Err("must not contain an empty path segment ('//')");
    }
    let host_in_url = url.host_str().unwrap_or_default();
    let canonical = match url.port() {
        Some(port) => format!("https://{host_in_url}:{port}{path}"),
        None => format!("https://{host_in_url}{path}"),
    };
    Ok(RelayTarget {
        url: canonical,
        host,
        embedded_ipv4: embedded,
        port,
        path,
    })
}

/// The rules on the path of a relay URL as written: every `%` followed by exactly two hex
/// digits, no encoded `/` or `\\` (`%2F`, `%5C`, either case), and, one trailing `/` aside, no
/// empty segment (`//`). The error completes "`relay_url` ...".
fn check_raw_path(path: &str) -> Result<(), &'static str> {
    let bytes = path.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        let hex = |j: usize| bytes.get(j).is_some_and(u8::is_ascii_hexdigit);
        if b == b'%' && !(hex(i + 1) && hex(i + 2)) {
            return Err("must not contain a '%' not followed by two hex digits");
        }
    }
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") {
        return Err("must not contain an encoded '/' or '\\'");
    }
    let path = path.strip_suffix('/').unwrap_or(path);
    if path.contains("//") || path.ends_with('/') {
        return Err("must not contain an empty path segment ('//')");
    }
    Ok(())
}

/// `path` with every percent-encoded unreserved character (RFC 3986 §2.3: letters, digits,
/// `-`, `.`, `_`, `~`) decoded and the hex digits of every other one in upper case, so that
/// equivalent spellings of a path compare equal (RFC 3986 §6.2.2.2).
fn normalize_percent_encoding(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut out = String::with_capacity(path.len());
    let mut i = 0;
    while i < bytes.len() {
        // Exactly `%` and two hex digits (`u8::from_str_radix` alone would also take `+a`).
        let encoded = bytes[i] == b'%'
            && bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
            && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit);
        if encoded {
            let hex = &path[i + 1..i + 3];
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                    out.push(byte as char);
                } else {
                    out.push('%');
                    out.push_str(&hex.to_ascii_uppercase());
                }
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Checks a host name: at most 253 characters of dot-separated labels of 1 to 63 lower-case
/// letters, digits and '-', no label starting or ending with '-'; so no scheme, port, path,
/// upper case or trailing dot. Host names are matched exactly (the gateway host is also the
/// inner `:authority`), so only the lower-case form is accepted. The error completes
/// "`<field>` ...".
fn check_host_name(value: &str) -> Result<(), &'static str> {
    let valid = value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        });
    if valid {
        Ok(())
    } else {
        Err("must be a lower-case bare DNS host name (no scheme, port, path or trailing dot)")
    }
}

/// Parses a signing key: 32 bytes of raw Ed25519 public key as 64 hex digits, a point on the
/// curve and not of small order. The error completes "`signing_pubkey` ...".
fn parse_signing_pubkey(value: &str) -> Result<VerifyingKey, &'static str> {
    let malformed = "must be a raw Ed25519 public key as 64 hex digits";
    if value.len() != 64 {
        return Err(malformed);
    }
    let bytes: [u8; 32] = hex::decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(malformed)?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| "is not a valid Ed25519 public key")?;
    if key.is_weak() {
        return Err("is a weak (small-order) Ed25519 public key");
    }
    Ok(key)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A valid signing key, hex: the public key of the seed `[seed; 32]`.
    pub(crate) fn key_hex(seed: u8) -> String {
        hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .as_bytes(),
        )
    }

    /// Both networks on, with example values (RFC 2606).
    pub(crate) fn example() -> OhttpNetworks {
        OhttpNetworks::new(
            Some(
                OhttpConfig::new(OhttpConfigParams {
                    gateway_host: "ohttp-gateway.example",
                    relay_url: "https://relay-mainnet.example/relay",
                    keys_dns_name: "mainnet.ohttp-keys.example",
                    signing_pubkey: &key_hex(1),
                })
                .unwrap(),
            ),
            Some(
                OhttpConfig::new(OhttpConfigParams {
                    gateway_host: "ohttp-gateway-testnet.example",
                    relay_url: "https://relay-testnet.example/relay",
                    keys_dns_name: "testnet.ohttp-keys.example",
                    signing_pubkey: &key_hex(2),
                })
                .unwrap(),
            ),
        )
        .unwrap()
    }

    #[test]
    fn a_relay_url_is_canonicalized_on_its_own() {
        assert_eq!(
            canonical_relay_url("https://Relay.Example:443/a/../relay/").unwrap(),
            "https://relay.example/relay"
        );
        assert_eq!(
            canonical_relay_url(""),
            Err(ConfigError::Empty {
                field: ConfigField::RelayUrl
            })
        );
        assert_eq!(
            canonical_relay_url("http://relay.example/relay"),
            Err(ConfigError::Invalid {
                field: ConfigField::RelayUrl,
                rule: "must be an https:// URL"
            })
        );
    }

    fn config(gateway_host: &str, relay_url: &str, seed: u8) -> Result<OhttpConfig, ConfigError> {
        OhttpConfig::new(OhttpConfigParams {
            gateway_host,
            relay_url,
            keys_dns_name: &format!("keys-{seed}.example"),
            signing_pubkey: &key_hex(seed),
        })
    }

    const ON_GATEWAY: ConfigError = ConfigError::Invalid {
        field: ConfigField::RelayUrl,
        rule: RELAY_ON_GATEWAY_HOST,
    };

    #[test]
    fn a_numeric_ipv4_alias_is_the_address_it_names() {
        for alias in [
            "192.0.2.1",
            "0xc0000201",
            "0300.0.2.1",
            "0xc0.0.2.1",
            "3221225985",
            "192.0.513",
            "192.513",
        ] {
            assert_eq!(host_key(alias), "192.0.2.1", "{alias}");
        }
        for name in [
            "ohttp-gateway.example",
            "xn--bcher-kva.example",
            "1.2.3.4.5",
            "09.0.0.1",
            "a0xc0000201",
        ] {
            assert_eq!(host_key(name), name);
        }
        // A relay on a name in its `xn--` form is on the gateway host of the same name.
        assert_eq!(
            config(
                "xn--bcher-kva.example",
                "https://XN--Bcher-Kva.example/relay",
                1
            ),
            Err(ON_GATEWAY)
        );
    }

    #[test]
    fn a_relay_on_a_numeric_alias_of_the_gateway_host_is_refused() {
        for (gateway, relay) in [
            ("0xc0000201", "https://192.0.2.1/relay"),
            ("0300.0.2.1", "https://192.0.2.1:8443/relay"),
            ("3221225985", "https://[::ffff:192.0.2.1]/relay"),
            ("192.0.513", "https://0xc0000201/relay"),
            ("192.0.2.1", "https://0300.0.2.1/relay"),
        ] {
            assert_eq!(
                config(gateway, relay, 1),
                Err(ON_GATEWAY),
                "{gateway} {relay}"
            );
        }
        // Another address is not the gateway's.
        assert!(config("0xc0000201", "https://192.0.2.2/relay", 1).is_ok());
    }

    #[test]
    fn a_relay_on_an_ipv6_literal_embedding_the_gateway_address_is_refused() {
        for relay in [
            // IPv4-mapped, IPv4-compatible and NAT64 (well-known prefix), in several spellings.
            "https://[::ffff:c000:201]/relay",
            "https://[::192.0.2.1]/relay",
            "https://[::c000:201]:8443/relay",
            "https://[0:0:0:0:0:0:c000:0201]/relay",
            "https://[64:ff9b::192.0.2.1]/relay",
            "https://[64:ff9b::c000:201]/relay",
            "https://[0064:FF9B:0:0:0:0:C000:0201]/relay",
        ] {
            for gateway in ["192.0.2.1", "0xc0000201"] {
                assert_eq!(
                    config(gateway, relay, 1),
                    Err(ON_GATEWAY),
                    "{gateway} {relay}"
                );
            }
            // Another gateway address, or a gateway name: no match.
            assert!(config("192.0.2.2", relay, 1).is_ok(), "{relay}");
            assert!(config("ohttp-gateway.example", relay, 1).is_ok(), "{relay}");
        }
        // The canonical URL keeps the IPv6 literal; only the comparison reads the embedding.
        assert_eq!(
            config("192.0.2.2", "https://[64:ff9b::192.0.2.1]/relay", 1)
                .unwrap()
                .relay_url(),
            "https://[64:ff9b::c000:201]/relay"
        );
        // IPv4-compatible needs the high 16 bits of the IPv4 address set.
        for (gateway, relay) in [
            ("0.1.0.0", "https://[::0.1.0.0]/relay"),
            ("0.1.0.0", "https://[::1:0]/relay"),
            ("198.51.100.7", "https://[::198.51.100.7]/relay"),
            ("255.255.255.255", "https://[::ffff:ffff]/relay"),
        ] {
            assert_eq!(
                config(gateway, relay, 1),
                Err(ON_GATEWAY),
                "{gateway} {relay}"
            );
        }
        for not_embedding in [
            // Loopback, unspecified and the rest of ::/112 are not IPv4-compatible addresses.
            ("0.0.0.1", "https://[::1]/relay"),
            ("0.0.0.0", "https://[::]/relay"),
            ("0.0.0.2", "https://[::2]/relay"),
            ("0.0.255.255", "https://[::ffff]/relay"),
            ("0.0.1.0", "https://[::0.0.1.0]/relay"),
            // Another prefix (6to4, a network-specific NAT64 prefix): another host.
            ("192.0.2.1", "https://[2002:c000:201::1]/relay"),
            ("192.0.2.1", "https://[2001:db8::c000:201]/relay"),
            ("192.0.2.1", "https://[64:ff9b:1::c000:201]/relay"),
            // IPv4-translated (`::ffff:0:a.b.c.d`) is not IPv4-mapped.
            ("192.0.2.1", "https://[::ffff:0:c000:201]/relay"),
        ] {
            let (gateway, relay) = not_embedding;
            assert!(config(gateway, relay, 1).is_ok(), "{gateway} {relay}");
        }
    }

    #[test]
    fn an_embedded_ipv4_relay_is_compared_with_the_other_networks_gateway() {
        let main = config("192.0.2.1", "https://relay-mainnet.example/relay", 1).unwrap();
        for relay in [
            "https://[::192.0.2.1]/relay",
            "https://[64:ff9b::c000:201]/relay",
        ] {
            let test = config("ohttp-gateway-testnet.example", relay, 2).unwrap();
            assert_eq!(
                OhttpNetworks::new(Some(main.clone()), Some(test.clone())),
                Err(ON_GATEWAY),
                "{relay}"
            );
            assert_eq!(
                OhttpNetworks::new(Some(test), Some(main.clone())),
                Err(ON_GATEWAY),
                "{relay}"
            );
        }
    }

    #[test]
    fn an_embedded_ipv4_relay_is_the_relay_on_that_address() {
        let shared = Err(ConfigError::SharedAcrossNetworks {
            field: ConfigField::RelayUrl,
        });
        for (mainnet_relay, testnet_relay) in [
            (
                "https://192.0.2.1/relay",
                "https://[64:ff9b::c000:201]/relay",
            ),
            ("https://192.0.2.1/relay", "https://[::192.0.2.1]:443/Relay"),
            (
                "https://[::ffff:192.0.2.1]/relay",
                "https://[::c000:201]/relay",
            ),
            (
                "https://[64:ff9b::192.0.2.1]/relay",
                "https://[::192.0.2.1]/relay",
            ),
            (
                "https://0xc0000201:8443/relay",
                "https://[64:ff9b::c000:201]:8443/relay",
            ),
        ] {
            let main = config("ohttp-gateway.example", mainnet_relay, 1).unwrap();
            let test = config("ohttp-gateway-testnet.example", testnet_relay, 2).unwrap();
            assert_eq!(
                OhttpNetworks::new(Some(main.clone()), Some(test.clone())),
                shared,
                "{mainnet_relay} {testnet_relay}"
            );
            assert_eq!(
                OhttpNetworks::new(Some(test), Some(main)),
                shared,
                "{testnet_relay} {mainnet_relay}"
            );
        }
        // Another port, path or address, or an IPv6 address that embeds none: two relays.
        for (mainnet_relay, testnet_relay) in [
            (
                "https://192.0.2.1/relay",
                "https://[64:ff9b::c000:201]:8443/relay",
            ),
            (
                "https://192.0.2.1/relay",
                "https://[64:ff9b::c000:201]/other",
            ),
            (
                "https://192.0.2.1/relay",
                "https://[64:ff9b::c000:202]/relay",
            ),
            ("https://0.0.0.2/relay", "https://[::2]/relay"),
            (
                "https://192.0.2.1/relay",
                "https://[::ffff:0:c000:201]/relay",
            ),
        ] {
            let main = config("ohttp-gateway.example", mainnet_relay, 1).unwrap();
            let test = config("ohttp-gateway-testnet.example", testnet_relay, 2).unwrap();
            assert!(
                OhttpNetworks::new(Some(main), Some(test)).is_ok(),
                "{mainnet_relay} {testnet_relay}"
            );
        }
    }

    #[test]
    fn numeric_aliases_are_compared_across_networks() {
        let main = config("0xc0000201", "https://relay-mainnet.example/relay", 1).unwrap();
        let test = config(
            "ohttp-gateway-testnet.example",
            "https://192.0.2.1/relay",
            2,
        )
        .unwrap();
        assert_eq!(
            OhttpNetworks::new(Some(main.clone()), Some(test.clone())),
            Err(ON_GATEWAY)
        );
        assert_eq!(
            OhttpNetworks::new(Some(test), Some(main.clone())),
            Err(ON_GATEWAY)
        );
        let same_gateway = config("192.0.513", "https://relay-testnet.example/relay", 2).unwrap();
        assert_eq!(
            OhttpNetworks::new(Some(main), Some(same_gateway)),
            Err(ConfigError::SharedAcrossNetworks {
                field: ConfigField::GatewayHost
            })
        );
    }

    #[test]
    fn relay_for_maps_each_configured_gateway() {
        let networks = example();
        assert_eq!(
            networks.relay_for("ohttp-gateway.example"),
            Some("https://relay-mainnet.example/relay")
        );
        assert_eq!(
            networks.relay_for("ohttp-gateway-testnet.example"),
            Some("https://relay-testnet.example/relay")
        );
        assert_eq!(networks.relay_for("unknown.example"), None);
        assert_eq!(networks.relay_for("ohttp-gateway-staging.example"), None);
    }

    #[test]
    fn relay_for_matches_exact_hosts_only() {
        let networks = example();
        for host in [
            "ohttp-gateway",
            ".example",
            "ohttp-gateway.example.evil.example",
            "OHTTP-GATEWAY.example",
            "",
        ] {
            assert_eq!(networks.relay_for(host), None, "{host}");
            assert_eq!(networks.network_of_host(host), None, "{host}");
        }
    }

    #[test]
    fn a_network_without_a_configuration_is_off() {
        let networks = example();
        let mainnet_only =
            OhttpNetworks::new(networks.get(Network::Mainnet).cloned(), None).unwrap();
        assert_eq!(
            mainnet_only.relay_for("ohttp-gateway-testnet.example"),
            None
        );
        assert!(mainnet_only.get(Network::Testnet).is_none());
        assert!(mainnet_only.require(Network::Testnet).is_err());
        assert_eq!(
            mainnet_only.relay_for("ohttp-gateway.example"),
            Some("https://relay-mainnet.example/relay")
        );
        let off = OhttpNetworks::default();
        for network in [Network::Mainnet, Network::Testnet] {
            assert!(off.get(network).is_none());
            let Err(crate::Error::KeyConfig(message)) = off.require(network) else {
                panic!("an unconfigured network has a configuration");
            };
            assert_eq!(
                message,
                format!("no OHTTP configuration for {}", network.as_str())
            );
        }
        assert_eq!(off.relay_for("ohttp-gateway.example"), None);
        assert_eq!(off.network_of_host(""), None);
    }

    #[test]
    fn a_relay_list_is_checked_like_a_relay_url() {
        let list = "https://relay-a.example/relay,https://relay-b.example/gateway";
        let main = config("ohttp-gateway.example", list, 1).unwrap();
        assert_eq!(main.relays().len(), 2);
        assert_eq!(main.relay_url(), "https://relay-a.example/relay");
        let chosen = main.choose_relay();
        assert!(main.relays().iter().any(|r| r.url() == chosen));
        // No relay of the list on the gateway host.
        assert_eq!(
            config("relay-b.example", list, 1),
            Err(ConfigError::Invalid {
                field: ConfigField::RelayUrl,
                rule: RELAY_ON_GATEWAY_HOST
            })
        );
        assert!(matches!(
            config(
                "ohttp-gateway.example",
                "https://relay-a.example/relay,https://relay-a.example/relay/",
                1
            ),
            Err(ConfigError::Invalid {
                field: ConfigField::RelayUrl,
                ..
            })
        ));
        // Mainnet and testnet share no relay of either list.
        let test = config(
            "ohttp-gateway-testnet.example",
            "https://relay-c.example/relay,https://Relay-B.example/gateway/",
            2,
        )
        .unwrap();
        assert_eq!(
            OhttpNetworks::new(Some(main.clone()), Some(test)),
            Err(ConfigError::SharedAcrossNetworks {
                field: ConfigField::RelayUrl
            })
        );
        // Nor is one network's relay on the other's gateway host.
        let test = config(
            "ohttp-gateway-testnet.example",
            "https://relay-c.example/relay,https://ohttp-gateway.example/relay",
            2,
        )
        .unwrap();
        assert_eq!(
            OhttpNetworks::new(Some(main.clone()), Some(test)),
            Err(ConfigError::Invalid {
                field: ConfigField::RelayUrl,
                rule: RELAY_ON_GATEWAY_HOST
            })
        );
        let test = config(
            "ohttp-gateway-testnet.example",
            "https://relay-c.example/relay",
            2,
        )
        .unwrap();
        let networks = OhttpNetworks::new(Some(main), Some(test)).unwrap();
        assert_eq!(
            networks.relay_for("ohttp-gateway.example"),
            Some("https://relay-a.example/relay")
        );
        assert_eq!(
            networks.relay_for("ohttp-gateway-testnet.example"),
            Some("https://relay-c.example/relay")
        );
        assert_eq!(networks.choose_relay_for("lightwalletd.example"), None);
        let relay = networks.choose_relay_for("ohttp-gateway.example").unwrap();
        assert!(
            relay.starts_with("https://relay-a.example")
                || relay.starts_with("https://relay-b.example")
        );
        // A list configuration shows no value either.
        assert!(!format!("{networks:?}").contains("example"));
    }
}

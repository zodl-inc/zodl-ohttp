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
    /// than a gateway host, an optional numeric port and an optional path; ASCII, without
    /// userinfo, query, fragment, backslash, whitespace, control characters, encoded `/` or `\`
    /// and empty path segments. Kept in its canonical form ([`OhttpConfig::relay_url`]), one
    /// trailing `/` removed.
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
    relay_url: String,
    keys_dns_name: String,
    signing_pubkey: VerifyingKey,
    /// The relay URL's host, port and path, canonical, for comparisons.
    relay: RelayTarget,
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
        let relay = parse_relay_url(relay_url).map_err(invalid(ConfigField::RelayUrl))?;
        // A relay on the gateway's own host would hand the gateway the client's address.
        if relay.host == gateway_host {
            return Err(invalid(ConfigField::RelayUrl)(RELAY_ON_GATEWAY_HOST));
        }
        check_host_name(keys_dns_name).map_err(invalid(ConfigField::KeysDnsName))?;
        let signing_pubkey =
            parse_signing_pubkey(signing_pubkey).map_err(invalid(ConfigField::SigningPubkey))?;
        Ok(OhttpConfig {
            gateway_host: gateway_host.to_owned(),
            relay_url: relay.url.clone(),
            keys_dns_name: keys_dns_name.to_owned(),
            signing_pubkey,
            relay,
        })
    }

    /// The gateway host name.
    pub fn gateway_host(&self) -> &str {
        &self.gateway_host
    }

    /// The relay URL, canonical: as given, but for a host in lower case and an IP address in its
    /// standard form, no `:443`, dot segments resolved, percent-encoding normalized and no
    /// trailing `/` (see [`OhttpConfigParams::relay_url`]).
    pub fn relay_url(&self) -> &str {
        &self.relay_url
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
    /// literal in any of its spellings, no port the same as port 443), the keys DNS name
    /// (ignoring ASCII case), nor the signing key. The error names the first shared field. Nor
    /// may one network's relay be on the other's gateway host
    /// ([`ConfigError::Invalid`] for [`ConfigField::RelayUrl`]).
    pub fn new(
        mainnet: Option<OhttpConfig>,
        testnet: Option<OhttpConfig>,
    ) -> Result<Self, ConfigError> {
        if let (Some(main), Some(test)) = (&mainnet, &testnet) {
            if main.relay.host == test.gateway_host || test.relay.host == main.gateway_host {
                return Err(ConfigError::Invalid {
                    field: ConfigField::RelayUrl,
                    rule: RELAY_ON_GATEWAY_HOST,
                });
            }
            let shared = [
                (
                    ConfigField::GatewayHost,
                    main.gateway_host.eq_ignore_ascii_case(&test.gateway_host),
                ),
                (ConfigField::RelayUrl, main.relay.same_relay(&test.relay)),
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

    /// The relay URL for `gateway_host`, or `None` when it is not exactly the gateway host of a
    /// configured network: `None` means OHTTP is off for that host.
    pub fn relay_for(&self, gateway_host: &str) -> Option<&str> {
        let network = self.network_of_host(gateway_host)?;
        self.get(network).map(OhttpConfig::relay_url)
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
    /// The port, 443 when the URL has none.
    pub(crate) port: u16,
    /// The path as in `url` (empty for the root).
    pub(crate) path: String,
}

impl RelayTarget {
    /// Whether `self` and `other` are the same relay: the same host and port and the same path
    /// ignoring ASCII case (conservative: two paths differing in case only count as one).
    fn same_relay(&self, other: &RelayTarget) -> bool {
        self.host == other.host
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
            None => ip.to_string(),
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
}

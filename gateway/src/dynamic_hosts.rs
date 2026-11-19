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

//! Dynamic third-party hosts (`DYNAMIC_HOST_SOURCES`).
//!
//! Problem: `BACKENDS` is a static map. A service whose operators publish their server list in a
//! JSON document can add a server at any time; wallets pick it, the gateway answers `403 unknown
//! authority` until it is redeployed with a longer map.
//!
//! A *source* is the URL of such a document plus, per list in it, a JSON pointer to an array of
//! URLs and the routes the listed hosts get. Each source is fetched periodically; the hosts it
//! lists are served like a `BACKENDS` alias whose target is the host itself (`:authority`
//! `vote.example.org` is forwarded to `https://vote.example.org<path>`), restricted to the
//! list's routes.
//!
//! Rules (the gateway must not become an open proxy when a source is wrong or compromised):
//!
//! - **Static wins.** A listed host that is a `BACKENDS` alias or a `GATEWAY_HOSTS` name is never
//!   served from a source; `proxy::resolve_backend` consults the static map first.
//! - A listed URL must be `https://host[:port]` and nothing else: no userinfo, path, query or
//!   fragment; the host is a DNS name (two labels or more, alphabetic last label, no special-use
//!   suffix) or a public dotted-quad IPv4 address; the port is 443 unless the source allows
//!   another. Entries that fail are skipped and counted.
//! - Connections to dynamic hosts resolve through [`PublicResolver`], which hands the connector
//!   only public addresses: a name that resolves to a private, loopback, link-local or otherwise
//!   non-public address is not connected to, whatever it resolved to when it was listed.
//! - Bounded: document size, fetch time, hosts per source, new hosts per refresh.
//! - **Last-known-good.** A failed fetch, an oversized, unparsable, invalid, unsigned (when a
//!   signature is configured) or empty document changes nothing: the hosts of the last accepted
//!   document stay.
//! - The served set is one immutable snapshot behind an atomic pointer; a refresh swaps it.
//!
//! Such documents are usually not signed as a whole (some sign other entries of theirs, not the
//! server list), so a signature is optional: `signature_url` + `signature_keys` verify a
//! detached Ed25519 signature over the document's bytes when the publisher (or a mirror the
//! operator runs) provides one. Without it the controls above bound what a compromised source
//! can add.
//!
//! Each process refreshes on its own; nothing is shared between replicas or kept across restarts.

use anyhow::{anyhow, bail, Result};
use arc_swap::ArcSwap;
use axum::body::Bytes;
use base64::Engine;
use http_body_util::{BodyExt, Full};
use hyper_tls::HttpsConnector;
use hyper_util::client::legacy::connect::dns::Name;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use parking_lot::Mutex;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{info, warn};

use crate::third_party_cache::RateWindow;

/// A route rule, `(METHOD, path pattern)`, in the `BACKENDS_POLICY` grammar.
pub type Rule = (String, String);

/// Sources per gateway.
pub const MAX_SOURCES: usize = 8;
/// Lists per source.
const MAX_LISTS: usize = 8;
/// Hosts per source: default and ceiling of `max_hosts`.
const DEFAULT_MAX_HOSTS: usize = 64;
const MAX_HOSTS_CEILING: usize = 256;
/// New hosts admitted per refresh: default of `max_new_hosts_per_refresh`.
const DEFAULT_MAX_NEW_HOSTS: usize = 8;
/// `refresh_secs`: default and bounds.
const DEFAULT_REFRESH_SECS: u64 = 60;
const MIN_REFRESH_SECS: u64 = 30;
const MAX_REFRESH_SECS: u64 = 86_400;
/// After a failed refresh the next attempt comes after at most this long.
const RETRY_SECS: u64 = 60;
/// `DYNAMIC_HOSTS_MAX_DOCUMENT_BYTES`: default and bounds.
const DEFAULT_MAX_DOCUMENT_BYTES: usize = 256 * 1024;
const MIN_MAX_DOCUMENT_BYTES: usize = 1024;
const MAX_MAX_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;
/// `DYNAMIC_HOSTS_FETCH_TIMEOUT_SECS`: default and bounds.
const DEFAULT_FETCH_TIMEOUT_SECS: u64 = 10;
const MAX_FETCH_TIMEOUT_SECS: u64 = 60;
/// A detached signature document: 64 raw bytes or their base64 text.
const MAX_SIGNATURE_BYTES: usize = 1024;
/// A listed URL longer than this is refused.
const MAX_URL_LEN: usize = 512;
/// Host names named in one refresh log line.
const MAX_LOGGED_HOSTS: usize = 16;

/// Last labels that never name a public host.
const SPECIAL_USE_SUFFIXES: &[&str] = &[
    "localhost",
    "local",
    "internal",
    "arpa",
    "test",
    "invalid",
    "onion",
    "lan",
    "home",
    "corp",
];

/// Whether `ip` is an address a dynamic host may be reached at: globally routable unicast.
///
/// Refused: unspecified, loopback, RFC 1918, shared address space (100.64/10), link-local
/// (169.254/16, which holds the instance metadata address), protocol assignments (192.0.0/24),
/// documentation, 6to4 relay anycast, benchmarking, multicast, reserved and broadcast; for IPv6
/// everything outside `2000::/3` (loopback, unique local, link-local, site-local, multicast,
/// IPv4-compatible), the IETF protocol assignments `2001::/23` (Teredo among them),
/// documentation (`2001:db8::/32`, `3fff::/20`) and 6to4 (`2002::/16`). An IPv4-mapped or NAT64
/// (`64:ff9b::/96`) address is judged by the IPv4 address it carries.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => is_public_v4(a),
        IpAddr::V6(a) => is_public_v6(a),
    }
}

fn is_public_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    !(o[0] == 0
        || o[0] == 10
        || o[0] == 127
        || (o[0] == 100 && (o[1] & 0xc0) == 64)
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 172 && (o[1] & 0xf0) == 16)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 192 && o[1] == 88 && o[2] == 99)
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 198 && (o[1] & 0xfe) == 18)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        || o[0] >= 224)
}

fn is_public_v6(a: Ipv6Addr) -> bool {
    let s = a.segments();
    let embedded_v4 = || {
        Ipv4Addr::new(
            (s[6] >> 8) as u8,
            (s[6] & 0xff) as u8,
            (s[7] >> 8) as u8,
            (s[7] & 0xff) as u8,
        )
    };
    // IPv4-mapped (::ffff:a.b.c.d) and NAT64 (64:ff9b::/96): the IPv4 address decides.
    if s[..5] == [0, 0, 0, 0, 0] && s[5] == 0xffff {
        return is_public_v4(embedded_v4());
    }
    if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        return is_public_v4(embedded_v4());
    }
    // Global unicast only.
    if s[0] & 0xe000 != 0x2000 {
        return false;
    }
    !((s[0] == 0x2001 && s[1] < 0x0200)
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        || s[0] == 0x2002
        || (s[0] == 0x3fff && s[1] & 0xf000 == 0))
}

/// The resolver of the HTTPS client used for dynamic hosts: the system resolver, with every
/// non-public address removed. A name without a public address does not resolve (the request
/// fails before any connection). The connector connects to exactly the addresses returned
/// here, so the check and the connection use one resolution (no rebinding window). The
/// connector does not call a resolver for an address literal: those are checked by
/// [`parse_host_url`] when listed and by `proxy::resolve_backend_in` for every request.
#[derive(Clone, Copy, Debug, Default)]
pub struct PublicResolver;

impl tower::Service<Name> for PublicResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = std::io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let resolved = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let public = public_addresses(resolved);
            if public.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "dynamic host has no public address",
                ));
            }
            Ok(public.into_iter())
        })
    }
}

/// The public addresses among `resolved` that no `DYNAMIC_HOSTS_DENY_CIDRS` block holds, in
/// order.
fn public_addresses(resolved: impl Iterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    resolved.filter(|a| is_connectable(a.ip())).collect()
}

/// An address block (`DYNAMIC_HOSTS_DENY_CIDRS`): `198.51.100.0/24`, `2001:db8::/32`, or a
/// single address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    /// The block's first address (an IPv4 block as its IPv4-mapped form) and its mask.
    network: u128,
    mask: u128,
    v4: bool,
}

impl Cidr {
    /// Parse `address[/prefix]`. The prefix defaults to the whole address.
    pub fn parse(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        let (address, prefix) = match raw.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (raw, None),
        };
        let address: IpAddr = address.parse().map_err(|_| {
            anyhow!("Invalid DYNAMIC_HOSTS_DENY_CIDRS entry '{raw}': not an address")
        })?;
        let (bits, max) = match address {
            IpAddr::V4(a) => (u128::from(a.to_ipv6_mapped()), 32u32),
            IpAddr::V6(a) => (u128::from(a), 128u32),
        };
        let prefix = match prefix {
            None => max,
            Some(p) => p.parse::<u32>().ok().filter(|p| *p <= max).ok_or_else(|| {
                anyhow!("Invalid DYNAMIC_HOSTS_DENY_CIDRS entry '{raw}': prefix must be 0..={max}")
            })?,
        };
        // An IPv4 block lives in the low 32 bits of the mapped form. A block written in the
        // IPv4-mapped IPv6 form (`::ffff:a.b.c.d/120`) is that IPv4 block.
        let length = if address.is_ipv4() {
            prefix + 96
        } else {
            prefix
        };
        let v4 = address.is_ipv4() || (length >= 96 && bits >> 32 == 0xffff);
        let mask = if length == 0 {
            0
        } else {
            u128::MAX << (128 - length)
        };
        Ok(Self {
            network: bits & mask,
            mask,
            v4,
        })
    }

    /// Whether the block holds `ip`. An IPv4 block also holds the IPv4-mapped and NAT64
    /// (`64:ff9b::/96`) forms of its addresses.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let bits = match ip {
            IpAddr::V4(a) => {
                if !self.v4 {
                    return false;
                }
                u128::from(a.to_ipv6_mapped())
            }
            IpAddr::V6(a) => {
                let bits = u128::from(a);
                if self.v4 {
                    let s = a.segments();
                    let nat64 = s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0];
                    let mapped = s[..5] == [0, 0, 0, 0, 0] && s[5] == 0xffff;
                    if !(nat64 || mapped) {
                        return false;
                    }
                    // The carried IPv4 address, in mapped form.
                    0xffff_0000_0000 | (bits & 0xffff_ffff)
                } else {
                    bits
                }
            }
        };
        bits & self.mask == self.network
    }
}

/// Parse `DYNAMIC_HOSTS_DENY_CIDRS` (comma-separated blocks).
pub fn parse_deny_cidrs(raw: &str) -> Result<Vec<Cidr>> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(Cidr::parse)
        .collect()
}

/// `DYNAMIC_HOSTS_DENY_CIDRS` of this process: set once, when the configuration is read.
static DENY_CIDRS: OnceLock<Vec<Cidr>> = OnceLock::new();

/// Whether a dynamic host may be reached at `ip`: a public address ([`is_public_ip`]) outside
/// the blocks of `DYNAMIC_HOSTS_DENY_CIDRS` (the operator's own public ranges, for example).
pub fn is_connectable(ip: IpAddr) -> bool {
    allowed_ip(ip, DENY_CIDRS.get().map(Vec::as_slice).unwrap_or(&[]))
}

fn allowed_ip(ip: IpAddr, deny: &[Cidr]) -> bool {
    is_public_ip(ip) && !deny.iter().any(|block| block.contains(ip))
}

/// A host a listed URL names: what a wallet puts in `:authority` and where it is forwarded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostTarget {
    /// `host`, or `host:port` for a port other than 443 (lowercase).
    pub authority: String,
    /// `https://host[:port]`.
    pub base_url: String,
}

/// The lookup key of an inner `:authority` (already lowercase): an explicit `:443` is dropped.
pub fn authority_key(authority_lower: &str) -> &str {
    authority_lower
        .strip_suffix(":443")
        .unwrap_or(authority_lower)
}

/// Validate one listed URL. `Err` carries the reason (fixed text, safe to log).
///
/// `allow_ports`: ports accepted besides 443. `suffixes`: when not empty, the host must equal
/// one of them or end with `.` + one of them (entries are stored without a leading dot).
pub fn parse_host_url(
    raw: &str,
    allow_ports: &[u16],
    suffixes: &[String],
) -> std::result::Result<HostTarget, &'static str> {
    if raw.len() > MAX_URL_LEN {
        return Err("url too long");
    }
    if !raw.is_ascii() {
        return Err("non-ASCII url");
    }
    if raw.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return Err("whitespace or control character in url");
    }
    const SCHEME: &str = "https://";
    if raw.len() < SCHEME.len() || !raw[..SCHEME.len()].eq_ignore_ascii_case(SCHEME) {
        return Err("scheme is not https");
    }
    let rest = &raw[SCHEME.len()..];
    let end = rest
        .find(|c: char| c == '/' || c == '?' || c == '#' || c == '\\')
        .unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if !(tail.is_empty() || tail == "/") {
        return Err("path, query or fragment not allowed");
    }
    if authority.contains('@') {
        return Err("userinfo not allowed");
    }
    if authority.contains('[') || authority.contains(']') {
        return Err("IPv6 literal not allowed");
    }
    let authority = authority.to_ascii_lowercase();
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => {
            if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
                return Err("invalid port");
            }
            match port.parse::<u16>() {
                Ok(p) if p != 0 => (host, p),
                _ => return Err("invalid port"),
            }
        }
        None => (authority.as_str(), 443),
    };
    if port != 443 && !allow_ports.contains(&port) {
        return Err("port not allowed");
    }
    if host.is_empty() || host.len() > 253 {
        return Err("invalid host length");
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        return Err("invalid character in host");
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels
        .iter()
        .any(|l| l.is_empty() || l.len() > 63 || l.starts_with('-') || l.ends_with('-'))
    {
        return Err("invalid DNS label");
    }
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        if !is_public_v4(ip) {
            return Err("address is not public");
        }
        if !is_connectable(IpAddr::V4(ip)) {
            return Err("address is in a denied block");
        }
    } else {
        if labels.len() < 2 {
            return Err("single-label host");
        }
        let last = labels[labels.len() - 1];
        // An all-letter (or punycode) last label: `127.1`, `0x7f.1` and `2130706433` are not names.
        if !(last.bytes().all(|b| b.is_ascii_lowercase()) || last.starts_with("xn--")) {
            return Err("host is not a DNS name");
        }
        if SPECIAL_USE_SUFFIXES.contains(&last) {
            return Err("special-use host name");
        }
    }
    if !suffixes.is_empty()
        && !suffixes.iter().any(|s| {
            host == s
                || host
                    .strip_suffix(s.as_str())
                    .is_some_and(|p| p.ends_with('.'))
        })
    {
        return Err("host not under an allowed suffix");
    }
    let authority = if port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    Ok(HostTarget {
        base_url: format!("https://{authority}"),
        authority,
    })
}

/// Parse a rule list in the `BACKENDS_POLICY` grammar (`METHOD /path,METHOD /prefix/*`).
pub fn parse_rules(name: &str, spec: &str) -> Result<Vec<Rule>> {
    let mut rules = Vec::new();
    for rule in spec.split(',') {
        let rule = rule.trim();
        if rule.is_empty() {
            continue;
        }
        let Some((method, path)) = rule.split_once(' ') else {
            bail!("Malformed {name}: '{rule}' must be 'METHOD /path'");
        };
        let method = method.trim().to_ascii_uppercase();
        let path = path.trim();
        if !zodl_ohttp_integrations::core::route::is_policy_method(&method) {
            bail!("Invalid {name} method '{method}' in '{rule}': must be GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH/*");
        }
        if !path.starts_with('/') || path.bytes().any(|b| b <= 0x20 || b >= 0x7f) {
            bail!(
                "Invalid {name} path '{path}' in '{rule}': must start with / and be visible ASCII"
            );
        }
        rules.push((method, path.to_string()));
    }
    Ok(rules)
}

/// One list of a source: where the URLs are and what the hosts may do.
#[derive(Clone, Debug)]
struct ListConfig {
    /// RFC 6901 pointer to an array.
    pointer: String,
    /// Field of each array element that holds the URL; `None`: the element is the URL.
    url_field: Option<String>,
    routes: Vec<Rule>,
    read_routes: Vec<Rule>,
}

/// One configured source.
struct SourceConfig {
    name: String,
    /// `dynamic:<name>`: the `backend` metric label of every host of this source.
    label: String,
    url: String,
    refresh: Duration,
    lists: Vec<ListConfig>,
    host_suffixes: Vec<String>,
    allow_ports: Vec<u16>,
    max_hosts: usize,
    max_new_hosts: usize,
    rate_limit: Option<(u64, Duration)>,
    signature: Option<SignatureConfig>,
}

struct SignatureConfig {
    url: String,
    keys: Vec<ed25519_dalek::VerifyingKey>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSource {
    name: String,
    url: String,
    refresh_secs: Option<u64>,
    lists: Vec<RawList>,
    #[serde(default)]
    host_suffixes: Vec<String>,
    #[serde(default)]
    allow_ports: Vec<u16>,
    max_hosts: Option<usize>,
    max_new_hosts_per_refresh: Option<usize>,
    rate_limit: Option<String>,
    signature_url: Option<String>,
    #[serde(default)]
    signature_keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawList {
    pointer: String,
    url_field: Option<String>,
    routes: String,
    read_routes: Option<String>,
}

/// A host of a source's accepted document.
#[derive(Clone, Debug, PartialEq, Eq)]
struct HostSpec {
    target: HostTarget,
    /// One per list that names the host, in configuration order.
    grants: Vec<Grant>,
}

/// What one list gives a host it names: the list's `routes` and `read_routes`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The operations the list allows.
    pub routes: Vec<Rule>,
    /// Of those, the ones the list declares free of side effects.
    pub read_routes: Vec<Rule>,
}

fn rule_matches(rules: &[Rule], method: &str, path: &str) -> bool {
    zodl_ohttp_integrations::core::route::matching_rule(rules, method, path).is_some()
}

/// What a source last accepted.
#[derive(Default)]
struct SourceState {
    /// Hosts of the last accepted document, in document order (last-known-good).
    hosts: Vec<HostSpec>,
    /// SHA-256 of the last accepted document, when all of its hosts were admitted.
    document_hash: Option<[u8; 32]>,
    /// A document was accepted since the process started.
    loaded: bool,
    /// The source's document was read since the process started: accepted, or fetched and
    /// verified but without a valid host (`empty`). Its hosts, if any, are known.
    read: bool,
    /// The limiter state of every host in `hosts`, served or shadowed: it belongs to the
    /// (source, host) pair for as long as the source lists the host.
    limits: HashMap<String, HostLimits>,
}

/// In-flight permits and the rate window of one host of one source.
#[derive(Clone)]
struct HostLimits {
    semaphore: Arc<Semaphore>,
    rate: Option<Arc<Mutex<RateWindow>>>,
}

/// A host served from a source. Immutable; the limiter state (`semaphore`, the rate window) is
/// shared with the entries that replace this one while the same source keeps listing the host
/// (also while an earlier source or the static configuration shadows it), so a refresh that
/// changes its routes or its owner does not hand it fresh permits or a fresh window.
pub struct DynamicHost {
    /// The lookup key: `host` or `host:port`.
    pub authority: String,
    /// `https://host[:port]`.
    pub base_url: String,
    /// The source's name.
    pub source: String,
    /// `dynamic:<source>`: the bounded `backend` metric label.
    pub label: String,
    /// The operations forwarded to this host: the routes of every list that names it.
    pub routes: Vec<Rule>,
    /// Per list that names the host, its routes and READ routes (replay class).
    pub grants: Vec<Grant>,
    /// In-flight upstream calls to this host (`MAX_INFLIGHT_PER_BACKEND`).
    pub semaphore: Arc<Semaphore>,
    rate: Option<Arc<Mutex<RateWindow>>>,
}

impl DynamicHost {
    /// Count one upstream call against the source's per-host `rate_limit`:
    /// `Err(retry_after_secs)` when the window is spent.
    pub fn check_rate(&self) -> std::result::Result<(), u64> {
        match &self.rate {
            Some(window) => window.lock().check_and_increment(),
            None => Ok(()),
        }
    }

    /// Whether `method path` is a READ for the replay check: at least one list allows the
    /// operation, and every list that allows it also declares it a READ. A list's `read_routes`
    /// therefore never reach beyond that list's `routes`, and where two lists that name the
    /// host disagree the operation is a WRITE (fail-safe).
    pub fn is_read_route(&self, method: &str, path: &str) -> bool {
        let mut allowed = false;
        for grant in &self.grants {
            if rule_matches(&grant.routes, method, path) {
                if !rule_matches(&grant.read_routes, method, path) {
                    return false;
                }
                allowed = true;
            }
        }
        allowed
    }
}

impl std::fmt::Debug for DynamicHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicHost")
            .field("authority", &self.authority)
            .field("source", &self.source)
            .field("routes", &self.routes)
            .field("grants", &self.grants)
            .finish()
    }
}

/// The served set: every dynamic host by authority.
#[derive(Default)]
struct Snapshot {
    hosts: HashMap<String, Arc<DynamicHost>>,
}

/// The outcome of one refresh of one source (`result` label of
/// `ohttp_dynamic_hosts_refresh_total`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshResult {
    /// A new document was accepted and all of its hosts are served.
    Ok,
    /// The document is the one already served.
    Unchanged,
    /// Accepted, with new hosts held back by `max_new_hosts_per_refresh`.
    Partial,
    /// The document (or its signature) could not be fetched: transport, timeout, status.
    FetchError,
    /// The document is larger than `DYNAMIC_HOSTS_MAX_DOCUMENT_BYTES`.
    TooLarge,
    /// Not JSON.
    ParseError,
    /// A list is missing or not an array, or the document lists more hosts than `max_hosts`.
    Invalid,
    /// No listed URL passed validation.
    Empty,
    /// The detached signature is missing, malformed or does not verify.
    Signature,
}

impl RefreshResult {
    pub fn as_str(self) -> &'static str {
        match self {
            RefreshResult::Ok => "ok",
            RefreshResult::Unchanged => "unchanged",
            RefreshResult::Partial => "partial",
            RefreshResult::FetchError => "fetch_error",
            RefreshResult::TooLarge => "too_large",
            RefreshResult::ParseError => "parse_error",
            RefreshResult::Invalid => "invalid",
            RefreshResult::Empty => "empty",
            RefreshResult::Signature => "signature",
        }
    }

    /// The source's hosts are those of its current document.
    pub fn is_success(self) -> bool {
        matches!(
            self,
            RefreshResult::Ok | RefreshResult::Unchanged | RefreshResult::Partial
        )
    }
}

/// What the static configuration reserves: a dynamic host never takes one of these names.
#[derive(Clone, Debug, Default)]
pub struct Reserved {
    /// `BACKENDS` aliases (lowercase, as configured).
    pub aliases: HashSet<String>,
    /// `GATEWAY_HOSTS` (lowercase, without port).
    pub gateway_hosts: HashSet<String>,
    /// Hosts (lowercase, without port) the static configuration already forwards to under
    /// another name: the targets of the `BACKENDS` aliases and the lightwalletd host. Served
    /// from a source they would be reachable around the alias' own policy, cache and limits.
    pub targets: HashSet<String>,
}

/// The hosts (lowercase, without port) of the `BACKENDS` targets and of `LWD_ADDR`, for
/// [`Reserved::targets`].
pub fn static_target_hosts<'a>(
    backend_targets: impl Iterator<Item = &'a String>,
    lwd_addr: &str,
) -> HashSet<String> {
    let host_of = |target: &str| -> Option<String> {
        let rest = target.split_once("://").map_or(target, |(_, rest)| rest);
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
        let host = if authority.starts_with('[') {
            authority
                .split(']')
                .next()
                .unwrap_or("")
                .trim_start_matches('[')
        } else {
            authority.split(':').next().unwrap_or("")
        };
        // `host.` and `host` are one name.
        let host = host.trim_end_matches('.');
        (!host.is_empty()).then(|| host.to_ascii_lowercase())
    };
    backend_targets
        .filter_map(|target| host_of(target))
        .chain(host_of(lwd_addr))
        .collect()
}

impl Reserved {
    fn contains(&self, target: &HostTarget) -> bool {
        let host = target
            .authority
            .split(':')
            .next()
            .unwrap_or(&target.authority);
        self.aliases.contains(&target.authority)
            || self.aliases.contains(&format!("{}:443", target.authority))
            || self.gateway_hosts.contains(host)
            || self.targets.contains(host)
            || target.authority == "lwd"
    }
}

/// Process-wide settings of the feature.
#[derive(Clone, Debug)]
pub struct Settings {
    /// `NETWORK`, the metric label.
    pub network: String,
    /// `MAX_INFLIGHT_PER_BACKEND`: in-flight calls per dynamic host.
    pub max_inflight_per_host: usize,
    /// `DYNAMIC_HOSTS_MAX_DOCUMENT_BYTES`.
    pub max_document_bytes: usize,
    /// `DYNAMIC_HOSTS_FETCH_TIMEOUT_SECS`: one refresh in total (document and signature).
    pub fetch_timeout: Duration,
    /// Accept `http://` source URLs. Only the unit tests (a local plain-HTTP source) set it.
    insecure_source_urls: bool,
}

impl Settings {
    pub fn new(network: &str, max_inflight_per_host: usize) -> Self {
        Self {
            network: network.to_string(),
            max_inflight_per_host: max_inflight_per_host.max(1),
            max_document_bytes: DEFAULT_MAX_DOCUMENT_BYTES,
            fetch_timeout: Duration::from_secs(DEFAULT_FETCH_TIMEOUT_SECS),
            insecure_source_urls: false,
        }
    }

    /// `DYNAMIC_HOSTS_MAX_DOCUMENT_BYTES` and `DYNAMIC_HOSTS_FETCH_TIMEOUT_SECS` from the
    /// environment; a value that is not a number in range is a startup error.
    fn from_env(network: &str, max_inflight_per_host: usize) -> Result<Self> {
        let mut settings = Self::new(network, max_inflight_per_host);
        if let Some(raw) = env_value("DYNAMIC_HOSTS_MAX_DOCUMENT_BYTES") {
            settings.max_document_bytes = raw
                .parse::<usize>()
                .ok()
                .filter(|v| (MIN_MAX_DOCUMENT_BYTES..=MAX_MAX_DOCUMENT_BYTES).contains(v))
                .ok_or_else(|| {
                    anyhow!(
                        "Invalid DYNAMIC_HOSTS_MAX_DOCUMENT_BYTES '{raw}': must be {MIN_MAX_DOCUMENT_BYTES}..={MAX_MAX_DOCUMENT_BYTES}"
                    )
                })?;
        }
        if let Some(raw) = env_value("DYNAMIC_HOSTS_FETCH_TIMEOUT_SECS") {
            let secs = raw
                .parse::<u64>()
                .ok()
                .filter(|v| (1..=MAX_FETCH_TIMEOUT_SECS).contains(v))
                .ok_or_else(|| {
                    anyhow!(
                        "Invalid DYNAMIC_HOSTS_FETCH_TIMEOUT_SECS '{raw}': must be 1..={MAX_FETCH_TIMEOUT_SECS}"
                    )
                })?;
            settings.fetch_timeout = Duration::from_secs(secs);
        }
        Ok(settings)
    }

    #[cfg(test)]
    fn for_tests() -> Self {
        let mut settings = Self::new("testnet", 4);
        settings.insecure_source_urls = true;
        settings.fetch_timeout = Duration::from_secs(5);
        settings
    }
}

fn env_value(var: &str) -> Option<String> {
    std::env::var(var)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

struct Inner {
    settings: Settings,
    reserved: Reserved,
    sources: Vec<SourceConfig>,
    /// Per source, what it last accepted. Held only for the swap, never across an await.
    state: Mutex<Vec<SourceState>>,
    snapshot: ArcSwap<Snapshot>,
}

/// The dynamic hosts of a gateway: a cheap handle (clones share one set).
/// `Default`: no source, no host, nothing is ever fetched.
#[derive(Clone)]
pub struct DynamicHosts {
    inner: Arc<Inner>,
}

impl Default for DynamicHosts {
    fn default() -> Self {
        Self::build(Vec::new(), Reserved::default(), Settings::new("", 1))
    }
}

impl std::fmt::Debug for DynamicHosts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicHosts")
            .field("sources", &self.source_names())
            .field("hosts", &self.len())
            .finish()
    }
}

impl DynamicHosts {
    /// `DYNAMIC_HOST_SOURCES` (and the two global bounds) from the environment. Unset or empty:
    /// the feature is off.
    pub fn from_env(
        reserved: Reserved,
        network: &str,
        max_inflight_per_host: usize,
    ) -> Result<Self> {
        let settings = Settings::from_env(network, max_inflight_per_host)?;
        if let Some(raw) = env_value("DYNAMIC_HOSTS_DENY_CIDRS") {
            // Read once per process; the resolver of the dynamic hosts' client consults it.
            let blocks = parse_deny_cidrs(&raw)?;
            let in_force = DENY_CIDRS.get_or_init(|| blocks.clone());
            let same = blocks.iter().all(|b| in_force.contains(b))
                && in_force.iter().all(|b| blocks.contains(b));
            if !same {
                warn!("DYNAMIC_HOSTS_DENY_CIDRS was read before with another value; the first one stays in force");
            }
        }
        match env_value("DYNAMIC_HOST_SOURCES") {
            Some(raw) => Self::parse(&raw, reserved, settings),
            None => Ok(Self::build(Vec::new(), reserved, settings)),
        }
    }

    /// Parse a `DYNAMIC_HOST_SOURCES` document (a JSON array of sources).
    pub fn parse(raw: &str, reserved: Reserved, settings: Settings) -> Result<Self> {
        let raw_sources: Vec<RawSource> = serde_json::from_str(raw).map_err(|e| {
            anyhow!("Malformed DYNAMIC_HOST_SOURCES (a JSON array of sources): {e}")
        })?;
        if raw_sources.len() > MAX_SOURCES {
            bail!("Invalid DYNAMIC_HOST_SOURCES: at most {MAX_SOURCES} sources");
        }
        let mut sources = Vec::with_capacity(raw_sources.len());
        let mut names = HashSet::new();
        for raw in raw_sources {
            let source = parse_source(raw, settings.insecure_source_urls)?;
            if source.host_suffixes.is_empty() && source.signature.is_none() {
                warn!(
                    source = %source.name,
                    "Dynamic host source without host_suffixes and without a signature: whoever controls its document decides which public hosts are forwarded to (bounded by max_hosts and the routes)"
                );
            }
            if !names.insert(source.name.clone()) {
                bail!(
                    "Invalid DYNAMIC_HOST_SOURCES: source name '{}' is used twice",
                    source.name
                );
            }
            sources.push(source);
        }
        Ok(Self::build(sources, reserved, settings))
    }

    fn build(sources: Vec<SourceConfig>, reserved: Reserved, settings: Settings) -> Self {
        let state = sources.iter().map(|_| SourceState::default()).collect();
        Self {
            inner: Arc::new(Inner {
                settings,
                reserved,
                sources,
                state: Mutex::new(state),
                snapshot: ArcSwap::from_pointee(Snapshot::default()),
            }),
        }
    }

    /// Whether any source is configured.
    pub fn enabled(&self) -> bool {
        !self.inner.sources.is_empty()
    }

    /// The configured source names, in order.
    pub fn source_names(&self) -> Vec<&str> {
        self.inner.sources.iter().map(|s| s.name.as_str()).collect()
    }

    /// Hosts currently served.
    pub fn len(&self) -> usize {
        self.inner.snapshot.load().hosts.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The dynamic host an inner `:authority` (lowercase) names, from the current snapshot.
    /// The caller keeps the returned entry for the whole request: target, routes, limits and
    /// labels then come from one snapshot even when a refresh swaps the set meanwhile.
    pub fn lookup(&self, authority_lower: &str) -> Option<Arc<DynamicHost>> {
        let snapshot = self.inner.snapshot.load();
        if snapshot.hosts.is_empty() {
            return None;
        }
        snapshot.hosts.get(authority_key(authority_lower)).cloned()
    }

    /// Whether the document of every configured source has been read since the process
    /// started (accepted, or read and found without a valid host). Until then the served set
    /// may lack hosts that other replicas serve. A source that cannot be fetched, parsed or
    /// verified since the start keeps this false.
    pub fn all_loaded(&self) -> bool {
        self.inner.state.lock().iter().all(|s| s.read)
    }

    /// Note the outcome of a refresh for [`DynamicHosts::all_loaded`].
    fn note_read(&self, index: usize, result: RefreshResult) {
        if result.is_success() || result == RefreshResult::Empty {
            self.inner.state.lock()[index].read = true;
        }
    }

    /// Every served host with its routes, sorted by authority (the published host list).
    pub fn served(&self) -> Vec<(String, Vec<Rule>)> {
        let snapshot = self.inner.snapshot.load();
        let mut hosts: Vec<(String, Vec<Rule>)> = snapshot
            .hosts
            .values()
            .map(|h| (h.authority.clone(), h.routes.clone()))
            .collect();
        hosts.sort();
        hosts
    }

    /// Refresh every source once, concurrently. Used at startup, before the gateway serves:
    /// bounded by the fetch timeout, and a failure only leaves that source without hosts.
    pub async fn refresh_all(&self) {
        let refreshes = (0..self.inner.sources.len()).map(|index| self.refresh_source(index));
        futures_util::future::join_all(refreshes).await;
    }

    /// Start one refresh task per source. Each waits its interval (with +-10 % jitter, so
    /// replicas do not fetch in step; at most `RETRY_SECS` after a failure), then refreshes.
    pub fn spawn_refresh_tasks(&self) {
        for index in 0..self.inner.sources.len() {
            let hosts = self.clone();
            tokio::spawn(async move {
                // The startup refresh already ran; its outcome is not known here, so the
                // first wait is the short one.
                let mut last = RefreshResult::FetchError;
                loop {
                    let wait = next_wait(hosts.inner.sources[index].refresh, last);
                    tokio::time::sleep(jittered(wait)).await;
                    last = hosts.refresh_source(index).await;
                }
            });
        }
    }

    /// Fetch, verify and apply the document of source `index`. Never panics on its content;
    /// on any failure the source's last accepted hosts stay.
    pub async fn refresh_source(&self, index: usize) -> RefreshResult {
        let source = &self.inner.sources[index];
        let settings = &self.inner.settings;
        let result = match self.fetch_and_apply(index).await {
            Ok(result) => result,
            Err((result, reason)) => {
                warn!(
                    source = %source.name,
                    result = result.as_str(),
                    reason = %reason,
                    network = %settings.network,
                    "Dynamic hosts: refresh failed, the last accepted hosts stay"
                );
                result
            }
        };
        crate::health::record_dynamic_hosts_refresh(
            &settings.network,
            &source.name,
            result.as_str(),
        );
        if result.is_success() {
            crate::health::record_dynamic_hosts_success(&settings.network, &source.name);
        }
        self.note_read(index, result);
        result
    }

    async fn fetch_and_apply(
        &self,
        index: usize,
    ) -> std::result::Result<RefreshResult, (RefreshResult, String)> {
        let source = &self.inner.sources[index];
        let settings = &self.inner.settings;

        // One budget for the whole refresh: the document and, when configured, its signature.
        let deadline = tokio::time::Instant::now() + settings.fetch_timeout;
        let document = fetch_bounded(&source.url, settings.max_document_bytes, deadline)
            .await
            .map_err(|e| match e {
                FetchError::TooLarge => (
                    RefreshResult::TooLarge,
                    format!("document over {} bytes", settings.max_document_bytes),
                ),
                FetchError::Other(reason) => (RefreshResult::FetchError, reason),
            })?;
        let hash: [u8; 32] = Sha256::digest(&document).into();

        {
            let state = self.inner.state.lock();
            if state[index].document_hash == Some(hash) {
                return Ok(RefreshResult::Unchanged);
            }
        }

        if let Some(signature) = &source.signature {
            let detached = fetch_bounded(&signature.url, MAX_SIGNATURE_BYTES, deadline)
                .await
                .map_err(|e| match e {
                    FetchError::TooLarge => (
                        RefreshResult::Signature,
                        "signature document too large".to_string(),
                    ),
                    FetchError::Other(reason) => {
                        (RefreshResult::FetchError, format!("signature: {reason}"))
                    }
                })?;
            verify_detached(&document, &detached, &signature.keys)
                .map_err(|reason| (RefreshResult::Signature, reason.to_string()))?;
        }

        let extracted = extract_hosts(source, &document)?;
        Ok(self.apply(index, hash, extracted))
    }

    /// Apply `document` as if source `index` had just served it (no fetch, no signature).
    #[cfg(test)]
    pub(crate) fn load_document(&self, index: usize, document: &[u8]) -> RefreshResult {
        let result = match extract_hosts(&self.inner.sources[index], document) {
            Ok(extracted) => self.apply(index, Sha256::digest(document).into(), extracted),
            Err((result, _)) => result,
        };
        self.note_read(index, result);
        result
    }

    /// One source named `name` with one list at `/hosts` (URL strings) and `routes`, loaded
    /// with `urls`: the dynamic hosts of a unit test that needs no HTTP source.
    #[cfg(test)]
    pub(crate) fn for_tests(name: &str, routes: &str, urls: &[&str], reserved: Reserved) -> Self {
        let config = serde_json::json!([{
            "name": name,
            "url": "https://source.example.com/hosts.json",
            "lists": [{ "pointer": "/hosts", "routes": routes, "read_routes": "GET /*" }],
            "rate_limit": "2/60s",
        }]);
        let hosts = Self::parse(&config.to_string(), reserved, Settings::for_tests())
            .expect("the test source parses");
        let document = serde_json::json!({ "hosts": urls });
        assert!(hosts
            .load_document(0, document.to_string().as_bytes())
            .is_success());
        hosts
    }

    /// Serve `authority` -> `base_url` from source 0 without any validation: for the test that
    /// shows the connect-time check holds even for an entry validation would have refused.
    #[cfg(test)]
    pub(crate) fn insert_unvalidated(&self, authority: &str, base_url: &str) {
        let source = &self.inner.sources[0];
        let mut hosts = self.inner.snapshot.load().hosts.clone();
        hosts.insert(
            authority.to_string(),
            Arc::new(DynamicHost {
                authority: authority.to_string(),
                base_url: base_url.to_string(),
                source: source.name.clone(),
                label: source.label.clone(),
                routes: vec![("GET".to_string(), "/*".to_string())],
                grants: vec![Grant {
                    routes: vec![("GET".to_string(), "/*".to_string())],
                    read_routes: Vec::new(),
                }],
                semaphore: Arc::new(Semaphore::new(4)),
                rate: None,
            }),
        );
        self.inner.snapshot.store(Arc::new(Snapshot { hosts }));
    }

    /// Admit the hosts of an accepted document (growth cap), store them as the source's
    /// last-known-good and swap the served set.
    fn apply(&self, index: usize, hash: [u8; 32], extracted: Extracted) -> RefreshResult {
        let source = &self.inner.sources[index];
        let settings = &self.inner.settings;
        let mut state = self.inner.state.lock();

        let previous: HashSet<&str> = state[index]
            .hosts
            .iter()
            .map(|h| h.target.authority.as_str())
            .collect();
        let first_load = !state[index].loaded;
        let mut admitted = Vec::with_capacity(extracted.hosts.len());
        let mut added = Vec::new();
        let mut held = 0usize;
        for host in extracted.hosts {
            if first_load || previous.contains(host.target.authority.as_str()) {
                admitted.push(host);
            } else if added.len() < source.max_new_hosts {
                added.push(host.target.authority.clone());
                admitted.push(host);
            } else {
                held += 1;
            }
        }
        let now: HashSet<&str> = admitted
            .iter()
            .map(|h| h.target.authority.as_str())
            .collect();
        let removed: Vec<String> = previous
            .iter()
            .filter(|a| !now.contains(*a))
            .map(|a| a.to_string())
            .collect();
        drop(now);
        drop(previous);

        state[index].hosts = admitted;
        state[index].loaded = true;
        // With hosts held back the same document must be read again at the next refresh.
        state[index].document_hash = (held == 0).then_some(hash);

        let (snapshot, served, shadowed) = self.merge(&mut state);
        self.inner.snapshot.store(Arc::new(snapshot));
        // The gauges are written in the order the snapshots are stored (still under the lock),
        // so a slower concurrent refresh of another source cannot leave older counts behind.
        for (i, s) in self.inner.sources.iter().enumerate() {
            crate::health::record_dynamic_hosts(&settings.network, &s.name, served[i], shadowed[i]);
        }
        crate::health::record_dynamic_hosts_document(
            &settings.network,
            &source.name,
            held,
            extracted.rejected,
        );
        drop(state);

        info!(
            source = %source.name,
            hosts = served[index],
            shadowed = shadowed[index],
            added = %loggable_hosts(&added, first_load),
            removed = %loggable_hosts(&removed, false),
            held,
            rejected = extracted.rejected,
            rejected_reasons = %extracted.reasons.join("; "),
            network = %settings.network,
            "Dynamic hosts: document accepted"
        );
        if first_load && served[index] + shadowed[index] > source.max_new_hosts {
            // The growth cap does not bound the first document of a process: make it visible.
            info!(
                source = %source.name,
                hosts = served[index] + shadowed[index],
                max_new_hosts_per_refresh = source.max_new_hosts,
                network = %settings.network,
                "Dynamic hosts: the first document of this process lists more hosts than one later refresh would admit"
            );
        }
        if held > 0 {
            warn!(
                source = %source.name,
                held,
                max_new_hosts_per_refresh = source.max_new_hosts,
                network = %settings.network,
                "Dynamic hosts: more new hosts than one refresh admits, the rest wait for the next refreshes"
            );
            RefreshResult::Partial
        } else {
            RefreshResult::Ok
        }
    }

    /// Build the served set from every source's last-known-good hosts. Returns it with, per
    /// source, the hosts it serves and the hosts it lists that the static configuration or an
    /// earlier source owns. An entry whose source and routes did not change is carried over, so
    /// its in-flight and rate counters survive the swap.
    fn merge(&self, state: &mut [SourceState]) -> (Snapshot, Vec<usize>, Vec<usize>) {
        let settings = &self.inner.settings;
        let current = self.inner.snapshot.load();
        let mut hosts: HashMap<String, Arc<DynamicHost>> = HashMap::new();
        let mut served = vec![0usize; state.len()];
        let mut shadowed = vec![0usize; state.len()];
        for (index, (source, source_state)) in
            self.inner.sources.iter().zip(state.iter_mut()).enumerate()
        {
            // Limits only for the hosts the source lists now; new ones for new hosts.
            let listed: HashSet<&str> = source_state
                .hosts
                .iter()
                .map(|h| h.target.authority.as_str())
                .collect();
            source_state
                .limits
                .retain(|authority, _| listed.contains(authority.as_str()));
            for spec in &source_state.hosts {
                let authority = &spec.target.authority;
                let limits = source_state
                    .limits
                    .entry(authority.clone())
                    .or_insert_with(|| HostLimits {
                        semaphore: Arc::new(Semaphore::new(settings.max_inflight_per_host)),
                        rate: source.rate_limit.map(|(limit, window)| {
                            Arc::new(Mutex::new(RateWindow::new(limit, window)))
                        }),
                    })
                    .clone();
                if self.inner.reserved.contains(&spec.target) || hosts.contains_key(authority) {
                    shadowed[index] += 1;
                    continue;
                }
                // The entry is kept when nothing about it changed.
                let unchanged = current.hosts.get(authority).filter(|existing| {
                    existing.source == source.name && existing.grants == spec.grants
                });
                let entry = match unchanged {
                    Some(existing) => existing.clone(),
                    None => {
                        let mut routes: Vec<Rule> = Vec::new();
                        for rule in spec.grants.iter().flat_map(|g| &g.routes) {
                            if !routes.contains(rule) {
                                routes.push(rule.clone());
                            }
                        }
                        Arc::new(DynamicHost {
                            authority: authority.clone(),
                            base_url: spec.target.base_url.clone(),
                            source: source.name.clone(),
                            label: source.label.clone(),
                            routes,
                            grants: spec.grants.clone(),
                            semaphore: limits.semaphore,
                            rate: limits.rate,
                        })
                    }
                };
                hosts.insert(authority.clone(), entry);
                served[index] += 1;
            }
        }
        (Snapshot { hosts }, served, shadowed)
    }
}

/// Host names for a log line: at most `MAX_LOGGED_HOSTS`, then a count. The first load of a
/// process names none (every host is "added"); its count is in the `hosts` field.
fn loggable_hosts(hosts: &[String], first_load: bool) -> String {
    if first_load || hosts.is_empty() {
        return "-".to_string();
    }
    let mut out = hosts
        .iter()
        .take(MAX_LOGGED_HOSTS)
        .cloned()
        .collect::<Vec<_>>()
        .join(",");
    if hosts.len() > MAX_LOGGED_HOSTS {
        out.push_str(&format!(",+{}", hosts.len() - MAX_LOGGED_HOSTS));
    }
    out
}

/// The wait before the next refresh: the source's interval after an accepted document, at most
/// `RETRY_SECS` after a failure.
fn next_wait(refresh: Duration, last: RefreshResult) -> Duration {
    if last.is_success() {
        refresh
    } else {
        refresh.min(Duration::from_secs(RETRY_SECS))
    }
}

fn jittered(wait: Duration) -> Duration {
    use rand::Rng;
    wait.mul_f64(rand::thread_rng().gen_range(0.9..1.1))
}

fn parse_source(raw: RawSource, insecure_source_urls: bool) -> Result<SourceConfig> {
    let name = raw.name.trim().to_string();
    if name.is_empty()
        || name.len() > 32
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        bail!("Invalid DYNAMIC_HOST_SOURCES name '{name}': 1 to 32 characters of a-z, 0-9, '-' and '_'");
    }
    check_source_url(&name, "url", &raw.url, insecure_source_urls)?;

    let refresh_secs = raw.refresh_secs.unwrap_or(DEFAULT_REFRESH_SECS);
    if !(MIN_REFRESH_SECS..=MAX_REFRESH_SECS).contains(&refresh_secs) {
        bail!(
            "Invalid DYNAMIC_HOST_SOURCES '{name}': refresh_secs must be {MIN_REFRESH_SECS}..={MAX_REFRESH_SECS}"
        );
    }
    let max_hosts = raw.max_hosts.unwrap_or(DEFAULT_MAX_HOSTS);
    if !(1..=MAX_HOSTS_CEILING).contains(&max_hosts) {
        bail!("Invalid DYNAMIC_HOST_SOURCES '{name}': max_hosts must be 1..={MAX_HOSTS_CEILING}");
    }
    let max_new_hosts = raw
        .max_new_hosts_per_refresh
        .unwrap_or(DEFAULT_MAX_NEW_HOSTS.min(max_hosts));
    if !(1..=max_hosts).contains(&max_new_hosts) {
        bail!(
            "Invalid DYNAMIC_HOST_SOURCES '{name}': max_new_hosts_per_refresh must be 1..=max_hosts ({max_hosts})"
        );
    }

    if raw.lists.is_empty() || raw.lists.len() > MAX_LISTS {
        bail!("Invalid DYNAMIC_HOST_SOURCES '{name}': 1 to {MAX_LISTS} lists");
    }
    let mut lists = Vec::with_capacity(raw.lists.len());
    for list in raw.lists {
        if !(list.pointer.is_empty() || list.pointer.starts_with('/')) {
            bail!(
                "Invalid DYNAMIC_HOST_SOURCES '{name}': pointer '{}' must be empty or start with / (RFC 6901)",
                list.pointer
            );
        }
        if list.url_field.as_deref() == Some("") {
            bail!("Invalid DYNAMIC_HOST_SOURCES '{name}': url_field must not be empty");
        }
        let routes = parse_rules("DYNAMIC_HOST_SOURCES routes", &list.routes)?;
        if routes.is_empty() {
            bail!(
                "Invalid DYNAMIC_HOST_SOURCES '{name}': list '{}' has no routes",
                list.pointer
            );
        }
        let read_routes = parse_rules(
            "DYNAMIC_HOST_SOURCES read_routes",
            list.read_routes.as_deref().unwrap_or(""),
        )?;
        lists.push(ListConfig {
            pointer: list.pointer,
            url_field: list.url_field,
            routes,
            read_routes,
        });
    }

    let mut host_suffixes = Vec::with_capacity(raw.host_suffixes.len());
    for suffix in raw.host_suffixes {
        let suffix = suffix.trim().trim_start_matches('.').to_ascii_lowercase();
        if suffix.is_empty()
            || !suffix
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        {
            bail!("Invalid DYNAMIC_HOST_SOURCES '{name}': host_suffixes entry '{suffix}'");
        }
        host_suffixes.push(suffix);
    }
    if raw.allow_ports.contains(&0) {
        bail!("Invalid DYNAMIC_HOST_SOURCES '{name}': allow_ports must not contain 0");
    }

    let rate_limit = match raw.rate_limit.as_deref().map(str::trim) {
        Some(spec) if !spec.is_empty() => Some(crate::third_party_cache::parse_rate_spec(
            "DYNAMIC_HOST_SOURCES rate_limit",
            spec,
        )?),
        _ => None,
    };

    let signature = match (raw.signature_url, raw.signature_keys.is_empty()) {
        (None, true) => None,
        (Some(url), false) => {
            check_source_url(&name, "signature_url", &url, insecure_source_urls)?;
            let mut keys = Vec::with_capacity(raw.signature_keys.len());
            for key in &raw.signature_keys {
                let bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
                    .decode(key.trim())
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| {
                        anyhow!(
                            "Invalid DYNAMIC_HOST_SOURCES '{name}': signature_keys entries are base64 Ed25519 public keys (32 bytes)"
                        )
                    })?;
                keys.push(ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| {
                    anyhow!("Invalid DYNAMIC_HOST_SOURCES '{name}': signature_keys entry is not an Ed25519 public key")
                })?);
            }
            Some(SignatureConfig { url, keys })
        }
        _ => bail!(
            "Invalid DYNAMIC_HOST_SOURCES '{name}': signature_url and signature_keys go together"
        ),
    };

    Ok(SourceConfig {
        label: format!("dynamic:{name}"),
        name,
        url: raw.url,
        refresh: Duration::from_secs(refresh_secs),
        lists,
        host_suffixes,
        allow_ports: raw.allow_ports,
        max_hosts,
        max_new_hosts,
        rate_limit,
        signature,
    })
}

/// A source (or signature) URL: `https://` with a host and no userinfo.
fn check_source_url(name: &str, field: &str, url: &str, insecure: bool) -> Result<()> {
    let uri: hyper::Uri = url
        .parse()
        .map_err(|_| anyhow!("Invalid DYNAMIC_HOST_SOURCES '{name}': {field} is not a URL"))?;
    let https = uri.scheme_str() == Some("https");
    let plain = insecure && uri.scheme_str() == Some("http");
    if !(https || plain) {
        bail!("Invalid DYNAMIC_HOST_SOURCES '{name}': {field} must be an https:// URL");
    }
    match uri.authority() {
        Some(authority) if !authority.as_str().contains('@') && !authority.host().is_empty() => {
            Ok(())
        }
        _ => bail!("Invalid DYNAMIC_HOST_SOURCES '{name}': {field} needs a host and no userinfo"),
    }
}

/// The hosts of a document, validated.
struct Extracted {
    /// Unique hosts in document order (a host of several lists has the union of their routes).
    hosts: Vec<HostSpec>,
    /// Entries skipped: not a string, or refused by [`parse_host_url`].
    rejected: usize,
    /// Up to four distinct reasons for the skipped entries (fixed texts).
    reasons: Vec<&'static str>,
}

/// Parse `document` and collect the hosts of every list of `source`.
fn extract_hosts(
    source: &SourceConfig,
    document: &[u8],
) -> std::result::Result<Extracted, (RefreshResult, String)> {
    let value: serde_json::Value = serde_json::from_slice(document).map_err(|e| {
        (
            RefreshResult::ParseError,
            format!("not JSON: {}", e.classify_text()),
        )
    })?;

    let mut hosts: Vec<HostSpec> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut rejected = 0usize;
    let mut reasons: Vec<&'static str> = Vec::new();
    // Entries looked at, valid or not: bounds the work on a document made of junk entries.
    let mut examined = 0usize;
    let max_examined = source.max_hosts.saturating_mul(4);

    for list in &source.lists {
        let grant = Grant {
            routes: list.routes.clone(),
            read_routes: list.read_routes.clone(),
        };
        let Some(array) = value.pointer(&list.pointer).and_then(|v| v.as_array()) else {
            return Err((
                RefreshResult::Invalid,
                format!("list '{}' is missing or not an array", list.pointer),
            ));
        };
        for element in array {
            examined += 1;
            if examined > max_examined {
                return Err((
                    RefreshResult::Invalid,
                    format!("more than {max_examined} entries"),
                ));
            }
            let url = match &list.url_field {
                Some(field) => element.get(field).and_then(|v| v.as_str()),
                None => element.as_str(),
            };
            let target = url
                .ok_or("entry has no URL string")
                .and_then(|u| parse_host_url(u, &source.allow_ports, &source.host_suffixes));
            let target = match target {
                Ok(target) => target,
                Err(reason) => {
                    rejected += 1;
                    if reasons.len() < 4 && !reasons.contains(&reason) {
                        reasons.push(reason);
                    }
                    continue;
                }
            };
            match index.get(&target.authority) {
                Some(&at) => {
                    // Named again: by another list (one more grant) or twice by this one.
                    if !hosts[at].grants.contains(&grant) {
                        hosts[at].grants.push(grant.clone());
                    }
                }
                None => {
                    if hosts.len() >= source.max_hosts {
                        return Err((
                            RefreshResult::Invalid,
                            format!("more than max_hosts ({}) hosts", source.max_hosts),
                        ));
                    }
                    index.insert(target.authority.clone(), hosts.len());
                    hosts.push(HostSpec {
                        target,
                        grants: vec![grant.clone()],
                    });
                }
            }
        }
    }
    if hosts.is_empty() {
        return Err((
            RefreshResult::Empty,
            format!(
                "no valid host ({rejected} entries refused: {})",
                reasons.join("; ")
            ),
        ));
    }
    Ok(Extracted {
        hosts,
        rejected,
        reasons,
    })
}

/// The hosts `document` would yield for a source with one list at `/hosts` (plain URL strings).
/// For the fuzz target: the document is untrusted input.
#[cfg(feature = "fuzzing")]
pub fn fuzz_extract(document: &[u8]) -> usize {
    let source = SourceConfig {
        name: "fuzz".to_string(),
        label: "dynamic:fuzz".to_string(),
        url: "https://source.example.com/hosts.json".to_string(),
        refresh: Duration::from_secs(DEFAULT_REFRESH_SECS),
        lists: vec![
            ListConfig {
                pointer: "/hosts".to_string(),
                url_field: None,
                routes: vec![("GET".to_string(), "/*".to_string())],
                read_routes: Vec::new(),
            },
            ListConfig {
                pointer: "/servers".to_string(),
                url_field: Some("url".to_string()),
                routes: vec![("POST".to_string(), "/v1/*".to_string())],
                read_routes: Vec::new(),
            },
        ],
        host_suffixes: Vec::new(),
        allow_ports: vec![8443],
        max_hosts: 16,
        max_new_hosts: 4,
        rate_limit: None,
        signature: None,
    };
    match extract_hosts(&source, document) {
        Ok(extracted) => {
            assert!(!extracted.hosts.is_empty() && extracted.hosts.len() <= source.max_hosts);
            for host in &extracted.hosts {
                // What was accepted parses again to itself and is never a non-public literal.
                let again = parse_host_url(&host.target.base_url, &source.allow_ports, &[])
                    .expect("an accepted URL is valid");
                assert_eq!(again, host.target);
                assert!(!host.grants.is_empty());
            }
            extracted.hosts.len()
        }
        Err(_) => 0,
    }
}

trait ClassifyText {
    fn classify_text(&self) -> &'static str;
}

impl ClassifyText for serde_json::Error {
    /// The kind of a JSON error without the document's content.
    fn classify_text(&self) -> &'static str {
        match self.classify() {
            serde_json::error::Category::Io => "io",
            serde_json::error::Category::Syntax => "syntax error",
            serde_json::error::Category::Data => "unexpected data",
            serde_json::error::Category::Eof => "unexpected end",
        }
    }
}

/// Verify the detached Ed25519 signature of `document`: `detached` is the base64 text of the
/// 64-byte signature (surrounding whitespace ignored) or the 64 raw bytes; it must verify
/// (strict) under one of `keys`.
fn verify_detached(
    document: &[u8],
    detached: &[u8],
    keys: &[ed25519_dalek::VerifyingKey],
) -> std::result::Result<(), &'static str> {
    let decoded = std::str::from_utf8(detached)
        .ok()
        .and_then(|text| {
            base64::engine::general_purpose::STANDARD
                .decode(text.trim())
                .ok()
        })
        .filter(|bytes| bytes.len() == 64);
    let bytes: [u8; 64] = match decoded {
        Some(bytes) => bytes.try_into().map_err(|_| "signature is not 64 bytes")?,
        None => detached
            .try_into()
            .map_err(|_| "signature is neither base64 nor 64 raw bytes")?,
    };
    let signature = ed25519_dalek::Signature::from_bytes(&bytes);
    if keys
        .iter()
        .any(|key| key.verify_strict(document, &signature).is_ok())
    {
        Ok(())
    } else {
        Err("signature does not verify under a configured key")
    }
}

enum FetchError {
    TooLarge,
    Other(String),
}

type FetchClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// The client that fetches source documents: no connection is kept between refreshes.
fn fetch_client() -> &'static FetchClient {
    static CLIENT: OnceLock<FetchClient> = OnceLock::new();
    CLIENT.get_or_init(|| {
        Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(0)
            .build(HttpsConnector::new())
    })
}

/// `GET url`: the body of a 200 answer of at most `max_bytes`, complete (connect, head and
/// body) by `deadline`. A redirect is not followed.
async fn fetch_bounded(
    url: &str,
    max_bytes: usize,
    deadline: tokio::time::Instant,
) -> std::result::Result<Vec<u8>, FetchError> {
    let fetch = async {
        let request = hyper::Request::builder()
            .method("GET")
            .uri(url)
            .header("accept", "application/json")
            .header("user-agent", "ohttp-gateway/1.0")
            .body(Full::new(Bytes::new()))
            .map_err(|_| FetchError::Other("request could not be built".to_string()))?;
        let response = fetch_client()
            .request(request)
            .await
            .map_err(|e| FetchError::Other(transport_reason(&e)))?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(FetchError::Other(format!("status {status}")));
        }
        let declared = response
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        if declared.is_some_and(|len| len > max_bytes as u64) {
            return Err(FetchError::TooLarge);
        }
        let mut body = response.into_body();
        let mut bytes: Vec<u8> = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| FetchError::Other("body read failed".to_string()))?;
            if let Some(data) = frame.data_ref() {
                if bytes.len() + data.len() > max_bytes {
                    return Err(FetchError::TooLarge);
                }
                bytes.extend_from_slice(data);
            }
        }
        Ok(bytes)
    };
    match tokio::time::timeout_at(deadline, fetch).await {
        Ok(result) => result,
        Err(_) => Err(FetchError::Other(
            "no complete answer within the fetch timeout".to_string(),
        )),
    }
}

/// A transport error as logged: its kind, never the URL.
fn transport_reason(e: &hyper_util::client::legacy::Error) -> String {
    if e.is_connect() {
        "connect failed".to_string()
    } else {
        "request failed".to_string()
    }
}

#[cfg(test)]
#[path = "dynamic_hosts_tests.rs"]
mod tests;

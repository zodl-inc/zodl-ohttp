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

//! The third-party hosts a gateway carries, as the gateway publishes them.
//!
//! A wallet sends a request for a third-party host through the gateway only when it knows the
//! gateway carries that host; anything else it refuses, and it never falls back to a direct
//! connection. A list compiled into the wallet goes stale whenever the gateway's set changes.
//! A gateway can publish its set: the inner request `GET /ohttp-gateway/v1/third-party-hosts`
//! to the gateway's own host name, through OHTTP like any other request
//! (`gateway/README.md`, "Third-party host list: wallet integration").
//!
//! This module is that note as code, with no I/O of its own:
//!
//! - [`third_party_hosts_request`] builds the inner request, [`read_third_party_hosts`] reads
//!   the answer ([`HostListAnswer`], or [`NoHostList`] with the reason there is none).
//! - [`ThirdPartyHosts`] holds the compiled (bootstrap) list and the list last fetched,
//!   answers [`is_carried`](ThirdPartyHosts::is_carried) and
//!   [`filter_servers`](ThirdPartyHosts::filter_servers) (each with the `:authority` to
//!   send), and says when a refresh is due
//!   ([`begin_refresh`](ThirdPartyHosts::begin_refresh) /
//!   [`finish_refresh`](ThirdPartyHosts::finish_refresh)): one at a time, with a backoff after
//!   a failure, the held list kept until a new one replaces it.
//!
//! With the feature `client`, `Client::third_party_hosts` and `ThirdPartyHosts::refresh` do the
//! exchange. Nothing here starts a task or a timer: a refresh happens when the caller asks.
//!
//! The list says where the gateway forwards. It does not authenticate a host: which servers a
//! wallet uses still comes from the service's own discovery and its checks.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::{Request, Response};

/// The inner path of the host list.
pub const THIRD_PARTY_HOSTS_PATH: &str = "/ohttp-gateway/v1/third-party-hosts";
/// The `version` of the document this crate reads. Any other is treated as no list.
pub const THIRD_PARTY_HOSTS_VERSION: u64 = 1;
/// The largest document accepted (the gateway never sends a larger one).
pub const MAX_THIRD_PARTY_HOSTS_BYTES: usize = 256 * 1024;
/// The shortest and the longest time a fetched list is used before it is fetched again,
/// whatever `max_age_secs` says: the range a gateway can set.
pub const MIN_HOST_LIST_AGE: Duration = Duration::from_secs(30);
/// See [`MIN_HOST_LIST_AGE`].
pub const MAX_HOST_LIST_AGE: Duration = Duration::from_secs(24 * 60 * 60);
/// The pause after the first failed refresh; it doubles with every further failure up to
/// [`MAX_REFRESH_BACKOFF`].
pub const FIRST_REFRESH_BACKOFF: Duration = Duration::from_secs(30);
/// The longest pause between refreshes after failures.
pub const MAX_REFRESH_BACKOFF: Duration = Duration::from_secs(300);
/// A `403 unknown authority` for a listed host asks for a refresh at most this often.
pub const UNKNOWN_AUTHORITY_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
/// Before a host is refused, a list older than this is worth one refresh
/// ([`ThirdPartyHosts::refresh_before_refusing`]).
pub const REFUSAL_REFRESH_MIN_AGE: Duration = Duration::from_secs(5);
/// A refresh that was begun and not finished within this time is taken as failed, so that a
/// caller that dropped it cannot block every later one. An exchange for a refresh must
/// therefore be given up by its sender before this time has passed.
pub const REFRESH_ABANDONED_AFTER: Duration = Duration::from_secs(300);
/// The longest [`ThirdPartyHosts::refresh`] lets its exchange run, whatever timeout it is
/// given: below [`REFRESH_ABANDONED_AFTER`], so that two exchanges never run at once.
#[cfg(feature = "client")]
const MAX_REFRESH_EXCHANGE: Duration = Duration::from_secs(240);

/// The longest revision accepted, and sent back in `if-none-match`.
const MAX_REVISION_CHARS: usize = 128;

/// Tells the holders of one process apart, so that a refresh is finished only at the holder
/// that began it.
static NEXT_HOLDER: AtomicU64 = AtomicU64::new(1);
/// The longest `host[:port]` the gateway takes as an `:authority`.
const MAX_HOST_CHARS: usize = 253;

/// The inner request for the host list of the gateway `gateway_host` (the gateway's own host
/// name, as for lightwalletd calls), with `if-none-match` when `revision` is the revision of
/// the list held. A `revision` that could not stand in a quoted entity tag (empty, longer
/// than 128 characters, or with a character other than visible ASCII without `"`) is left out.
pub fn third_party_hosts_request(gateway_host: &str, revision: Option<&str>) -> Request {
    let request = Request::new("GET", gateway_host, THIRD_PARTY_HOSTS_PATH);
    match revision.filter(|r| valid_revision(r)) {
        Some(revision) => request.header("if-none-match", format!("\"{revision}\"")),
        None => request,
    }
}

/// What a list covers (`scope`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostListScope {
    /// Every third-party host the gateway carries: a host that is not in the list is not
    /// carried, whatever the compiled list says.
    All,
    /// Only the hosts the gateway reads from published server lists: the hosts it carries by
    /// static configuration are not in it, so for those the compiled list stays in force.
    Dynamic,
    /// A scope this crate does not know (or none): treated like [`HostListScope::Dynamic`].
    Unknown,
}

/// A host the gateway carries.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CarriedHost {
    /// What a request puts in `:authority` to reach the host through the gateway, in lower
    /// case: the name, with `:port` where the gateway lists one (it lists none for 443).
    pub host: String,
    /// What the gateway forwards to the host, `METHOD /path` (`*` = any method; a path ending
    /// in `/*` is a prefix on a segment boundary, any other is exact). For information: the
    /// gateway enforces them (inner `403 policy denied`).
    pub routes: Vec<String>,
}

/// A host list as a gateway published it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct HostList {
    /// Names this document; it changes when anything in the document changes.
    pub revision: String,
    /// What the list covers.
    pub scope: HostListScope,
    /// `max_age_secs` as the gateway wrote it. [`ThirdPartyHosts`] uses it clamped to
    /// [`MIN_HOST_LIST_AGE`]..[`MAX_HOST_LIST_AGE`].
    pub max_age_secs: u64,
    /// The hosts, in the gateway's order (sorted by name).
    pub hosts: Vec<CarriedHost>,
}

/// The gateway's answer to a host list request.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostListAnswer {
    /// The list (inner `200`).
    List(HostList),
    /// The list held is still the gateway's (inner `304` to an `if-none-match`): keep it and
    /// restart its lifetime.
    NotModified,
}

/// Why an answer is no host list: keep what is held (the compiled list if nothing was fetched
/// yet). Shows a status or a fixed text only, never anything the gateway or a host sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NoHostList {
    /// The gateway answered another status than `200` or `304`: it does not publish the list
    /// (an inner `403`, `404` or a gRPC error, depending on its configuration) or has no
    /// complete list at the moment (`503`).
    #[error("the gateway answered {0} to the host list request")]
    Status(u16),
    /// The answer is larger than [`MAX_THIRD_PARTY_HOSTS_BYTES`].
    #[error("the host list is larger than {MAX_THIRD_PARTY_HOSTS_BYTES} bytes")]
    TooLarge,
    /// The answer is not the JSON document: not JSON, or a required field is missing or has
    /// another type.
    #[error("the host list is not a well-formed document")]
    Malformed,
    /// The document has another `version` than [`THIRD_PARTY_HOSTS_VERSION`].
    #[error("the host list has a version this client does not read")]
    Version,
    /// A `304` although no revision was sent, or none is held.
    #[error("the gateway answered not modified to a request without a revision")]
    UnexpectedNotModified,
}

#[derive(Deserialize)]
struct RawList {
    revision: String,
    scope: Option<serde_json::Value>,
    max_age_secs: u64,
    hosts: Vec<serde_json::Value>,
}

/// One entry of `hosts`, if it is well-formed.
fn read_entry(entry: &serde_json::Value) -> Option<CarriedHost> {
    let entry = entry.as_object()?;
    let host = host_key(entry.get("host")?.as_str()?)?;
    let routes = entry
        .get("routes")?
        .as_array()?
        .iter()
        .map(|route| route.as_str().map(str::to_owned))
        .collect::<Option<Vec<String>>>()?;
    Some(CarriedHost { host, routes })
}

/// Reads the gateway's answer to a host list request. Unknown fields are ignored; a document
/// of another `version` is [`NoHostList::Version`], whatever else it holds. An entry of
/// `hosts` that is not an object with a string `host` and a `routes` array of strings, or
/// whose `host` no request could carry in `:authority`, is left out (such a host is then
/// simply not carried).
pub fn read_third_party_hosts(response: &Response) -> Result<HostListAnswer, NoHostList> {
    if !matches!(response.status, 200 | 304) {
        return Err(NoHostList::Status(response.status));
    }
    if response.body.len() > MAX_THIRD_PARTY_HOSTS_BYTES {
        return Err(NoHostList::TooLarge);
    }
    if response.status == 304 {
        return Ok(HostListAnswer::NotModified);
    }
    let document: serde_json::Value =
        serde_json::from_slice(&response.body).map_err(|_| NoHostList::Malformed)?;
    // The version first, on its own: a later version may change every other field.
    match document
        .as_object()
        .and_then(|object| object.get("version"))
    {
        Some(version) if version.as_u64() == Some(THIRD_PARTY_HOSTS_VERSION) => {}
        Some(version) if version.is_number() => return Err(NoHostList::Version),
        _ => return Err(NoHostList::Malformed),
    }
    let raw: RawList = serde_json::from_value(document).map_err(|_| NoHostList::Malformed)?;
    if !valid_revision(&raw.revision) {
        return Err(NoHostList::Malformed);
    }
    let scope = match raw.scope.as_ref().and_then(|scope| scope.as_str()) {
        Some("all") => HostListScope::All,
        Some("dynamic") => HostListScope::Dynamic,
        _ => HostListScope::Unknown,
    };
    // Entry by entry: one that is not `{"host": "...", "routes": ["...", ...]}` with a host a
    // request could carry in `:authority` is left out, and the others are read.
    let hosts = raw.hosts.iter().filter_map(read_entry).collect();
    Ok(HostListAnswer::List(HostList {
        revision: raw.revision,
        scope,
        max_age_secs: raw.max_age_secs,
        hosts,
    }))
}

/// Whether `response` is the gateway's refusal of an authority it does not carry: an inner
/// `403` with the body `unknown authority`. For a host the list names it means the replica
/// that answered has not learned the host yet
/// ([`ThirdPartyHosts::report_unknown_authority`]).
pub fn is_unknown_authority(response: &Response) -> bool {
    response.status == 403 && response.body == b"unknown authority"
}

/// Whether `revision` can stand between the quotes of an entity tag: 1 to 128 characters of
/// visible ASCII without `"` (so it cannot end the tag or start another header line).
fn valid_revision(revision: &str) -> bool {
    !revision.is_empty()
        && revision.len() <= MAX_REVISION_CHARS
        && revision
            .bytes()
            .all(|b| b == 0x21 || (0x23..=0x7e).contains(&b))
}

/// `host[:port]` as it is compared and sent: the whole value in lower case. `None` for
/// anything but what the gateway takes as an `:authority`: a host name (or IPv4 address) of
/// at most 253 characters with the port, labels of 1 to 63 letters, digits and hyphens that
/// neither start nor end with a hyphen, and an optional port, here in its plain decimal
/// spelling only (the gateway also takes leading zeros).
/// Nothing is rewritten: `name:443` and `name` are two values, as they are for the gateway.
fn host_key(host: &str) -> Option<String> {
    if host.is_empty() || host.len() > MAX_HOST_CHARS {
        return None;
    }
    let lower = host.to_ascii_lowercase();
    let (name, port) = match lower.rsplit_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (lower.as_str(), None),
    };
    let label_ok = |label: &str| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if !name.split('.').all(label_ok) {
        return None;
    }
    if let Some(port) = port {
        let number: u16 = port.parse().ok().filter(|n| *n != 0)?;
        // The plain spelling only (`8443`, not `08443` or `+8443`).
        if number.to_string() != port {
            return None;
        }
    }
    Some(lower)
}

/// The `:authority` of an `https://` server URL: its host in lower case, with the port unless
/// it is the scheme's (443). `None` for any other scheme, a URL with a userinfo part, an IPv6
/// literal, or one that does not parse.
///
/// The URL is checked as it is written, so that every parser reads the same host in it: it
/// is ASCII, starts with `https://`, holds no whitespace, control character or backslash
/// (which parsers drop or read differently), has no `@` in its authority, and its host is
/// written as it is sent (apart from case): no percent escape and no numeric IPv4 alias.
fn server_key(url: &str) -> Option<String> {
    const SCHEME: &str = "https://";
    let after_scheme = match url.get(..SCHEME.len()) {
        Some(scheme) if scheme.eq_ignore_ascii_case(SCHEME) => &url[SCHEME.len()..],
        _ => return None,
    };
    if !url.is_ascii() || url.bytes().any(|b| b <= 0x20 || b == 0x7f || b == b'\\') {
        return None;
    }
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let parsed = url::Url::parse(url).ok()?;
    if parsed.scheme() != "https" || !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }
    let host = match parsed.host()? {
        url::Host::Domain(name) => name.to_owned(),
        url::Host::Ipv4(address) => address.to_string(),
        // The gateway carries no IPv6 literal.
        url::Host::Ipv6(_) => return None,
    };
    // The host as written is the host that is sent: a spelling the parser rewrites (percent
    // escapes, a numeric IPv4 alias, a non-ASCII name) is another parser's different host.
    let written = match authority.rsplit_once(':') {
        Some((name, port)) if port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => authority,
    };
    if !written.eq_ignore_ascii_case(&host) {
        return None;
    }
    match parsed.port() {
        // `Url::port` is `None` for the scheme's default port, written or not.
        None => host_key(&host),
        Some(port) => host_key(&format!("{host}:{port}")),
    }
}

/// A server [`ThirdPartyHosts::filter_servers`] kept.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CarriedServer<'a> {
    /// The URL as it was given.
    pub url: &'a str,
    /// The `:authority` to send a request for this server with: the value that was checked
    /// against the gateway's hosts. Use it as it is; another spelling of the same host (upper
    /// case, an explicit `:443`, a numeric alias) is not what the gateway knows.
    pub authority: String,
}

/// What [`ThirdPartyHosts::filter_servers`] kept.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CarriedServers<'a> {
    /// The servers the gateway carries, in the order given.
    pub carried: Vec<CarriedServer<'a>>,
    /// How many were dropped: not a plain `https` URL (see
    /// [`ThirdPartyHosts::filter_servers`]), or a host the gateway does not carry.
    pub dropped: usize,
}

impl CarriedServers<'_> {
    /// Whether a server is left to use. When none is, the operation fails: a dropped server
    /// is never reached another way.
    pub fn any(&self) -> bool {
        !self.carried.is_empty()
    }
}

/// The outcome of [`ThirdPartyHosts::finish_refresh`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefreshOutcome {
    /// A list was fetched and replaces the one held (or the compiled list).
    Updated,
    /// The gateway confirmed the list held; its lifetime starts again.
    NotModified,
    /// No list this time: what was held stays, and the next refresh waits for the backoff.
    /// `None`: the exchange itself failed (transport, relay, sealing).
    Kept(Option<NoHostList>),
    /// No refresh was due (`ThirdPartyHosts::refresh` only): the list is fresh, or the
    /// backoff after a failure has not passed.
    NotDue,
    /// Nothing was sent because another refresh is running (`ThirdPartyHosts::refresh` only):
    /// its result is in the holder when it ends. A host that is not allowed at this moment may
    /// be in the list it brings: treat a refusal now as temporary and ask again shortly.
    Running,
    /// The refresh is not the one running at this holder, and nothing was changed: it was
    /// given up after [`REFRESH_ABANDONED_AFTER`] (and counted as a failure then), or it was
    /// begun at another holder.
    Superseded,
}

/// A refresh that was begun ([`ThirdPartyHosts::begin_refresh`]): send
/// [`request`](Self::request) through OHTTP and hand the answer to
/// [`ThirdPartyHosts::finish_refresh`]. Its `Debug` shows the revision it revalidates (a name
/// of the list's content) and two counters.
#[derive(Debug)]
#[must_use = "a refresh that was begun must be finished (finish_refresh or fail_refresh)"]
pub struct HostListRefresh {
    holder: u64,
    id: u64,
    revision: Option<String>,
}

impl HostListRefresh {
    /// The inner request to send to the gateway `gateway_host`: with `if-none-match` when a
    /// list is held.
    pub fn request(&self, gateway_host: &str) -> Request {
        third_party_hosts_request(gateway_host, self.revision.as_deref())
    }

    /// The revision the request revalidates, if a list is held.
    pub fn revision(&self) -> Option<&str> {
        self.revision.as_deref()
    }
}

struct Held {
    list: HostList,
    /// The list's hosts as [`host_key`] writes them.
    keys: HashSet<String>,
    /// When the list was fetched or last confirmed.
    since: Instant,
    /// `max_age_secs`, clamped.
    lifetime: Duration,
}

/// The refresh in flight.
#[derive(Clone, Copy)]
struct Running {
    id: u64,
    began: Instant,
}

#[derive(Default)]
struct State {
    held: Option<Held>,
    refreshing: Option<Running>,
    next_id: u64,
    /// Failed refreshes in a row.
    failures: u32,
    /// The backoff after a failure: when it failed and how long no refresh begins after that.
    backoff: Option<(Instant, Duration)>,
    /// A refresh was asked for although the list is not stale yet. Stays set until a refresh
    /// succeeded, so that a failed one is tried again after the backoff.
    wanted: bool,
    /// ... by [`ThirdPartyHosts::report_unknown_authority`].
    wanted_for_unknown_authority: bool,
    /// When a refresh for an unknown authority was last asked for or, once it began, begun.
    last_unknown_authority: Option<Instant>,
}

/// The third-party hosts a gateway carries: the compiled (bootstrap) list the caller passes
/// in and the list last fetched from the gateway. One per gateway.
///
/// Which hosts are allowed, at any moment:
///
/// - before a list was fetched: the bootstrap list;
/// - while the list held has scope [`All`](HostListScope::All): exactly its hosts;
/// - while it has scope [`Dynamic`](HostListScope::Dynamic) or an unknown one: its hosts and
///   the bootstrap list.
///
/// A fetched list replaces the one before it as a whole. A failed refresh changes nothing.
/// A host that is not allowed is refused; nothing here ever suggests reaching it directly.
///
/// The methods take `&self`: share it behind an `Arc`. The methods ending in `_at` take the
/// current time, for callers with a clock of their own and for tests; the others read
/// [`Instant::now`].
pub struct ThirdPartyHosts {
    id: u64,
    bootstrap: HashSet<String>,
    state: Mutex<State>,
}

impl std::fmt::Debug for ThirdPartyHosts {
    /// Counts only: the hosts are the deployment's.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("ThirdPartyHosts");
        debug.field("bootstrap_hosts", &self.bootstrap.len());
        // Never waits for the lock; a poisoned one is read like any other.
        let state = match self.state.try_lock() {
            Ok(state) => Some(state),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => None,
        };
        match state {
            Some(state) => debug
                .field("held_hosts", &state.held.as_ref().map(|h| h.keys.len()))
                .field("refreshing", &state.refreshing.is_some())
                .field("failures", &state.failures),
            None => debug.field("state", &"<locked>"),
        };
        debug.finish()
    }
}

impl ThirdPartyHosts {
    /// A holder with the compiled list `bootstrap` and no fetched list. The entries are
    /// `host[:port]` as a request puts them in `:authority` (case does not matter): the name
    /// alone for port 443. Entries that are not such values (a URL, for example) are dropped;
    /// [`bootstrap_len`](Self::bootstrap_len) tells how many were kept.
    pub fn new<I, S>(bootstrap: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        ThirdPartyHosts {
            id: NEXT_HOLDER.fetch_add(1, Ordering::Relaxed),
            bootstrap: bootstrap
                .into_iter()
                .filter_map(|host| host_key(host.as_ref()))
                .collect(),
            state: Mutex::new(State::default()),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        // The state is consistent after every statement: a panic elsewhere while it was held
        // leaves nothing half-written.
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// How many hosts the bootstrap list holds (the entries of `new` that are host names,
    /// without repetitions).
    pub fn bootstrap_len(&self) -> usize {
        self.bootstrap.len()
    }

    /// Whether the gateway carries `host`, the `host[:port]` a request would put in
    /// `:authority`: the whole value is compared, case-insensitively. No suffix or wildcard
    /// matching, and no other spelling of the same host: `name:443` is not `name`.
    pub fn is_carried(&self, host: &str) -> bool {
        self.carried_authority(host).is_some()
    }

    /// Like [`is_carried`](Self::is_carried), and when the gateway carries `host`, the value
    /// to send as `:authority`: `host` in lower case.
    pub fn carried_authority(&self, host: &str) -> Option<String> {
        let key = host_key(host)?;
        self.carries(&self.state(), &key).then_some(key)
    }

    fn carries(&self, state: &State, key: &str) -> bool {
        match &state.held {
            None => self.bootstrap.contains(key),
            Some(held) => {
                held.keys.contains(key)
                    || (held.list.scope != HostListScope::All && self.bootstrap.contains(key))
            }
        }
    }

    /// Of the server URLs a service's own discovery offers, those the gateway carries: `https`
    /// URLs whose host (with the port, unless it is 443) [`is_carried`](Self::is_carried),
    /// each with the `:authority` to send ([`CarriedServer::authority`]). A URL must be plain to
    /// be kept: ASCII, starting with `https://`, without userinfo, whitespace or backslash,
    /// its host written as it is sent (no percent escape, no numeric IPv4 alias). The rest are
    /// dropped, not reached another way; when none is left ([`CarriedServers::any`] is false)
    /// the operation fails.
    pub fn filter_servers<'a, I>(&self, urls: I) -> CarriedServers<'a>
    where
        I: IntoIterator<Item = &'a str>,
    {
        // The caller's iterator runs before the lock is taken, never under it.
        let offered: Vec<(&'a str, Option<String>)> =
            urls.into_iter().map(|url| (url, server_key(url))).collect();
        let state = self.state();
        let mut kept = CarriedServers {
            carried: Vec::new(),
            dropped: 0,
        };
        for (url, key) in offered {
            match key {
                Some(authority) if self.carries(&state, &authority) => {
                    kept.carried.push(CarriedServer { url, authority })
                }
                _ => kept.dropped += 1,
            }
        }
        kept
    }

    /// The list held, if one was fetched.
    pub fn held(&self) -> Option<HostList> {
        self.state().held.as_ref().map(|held| held.list.clone())
    }

    /// The revision of the list held.
    pub fn revision(&self) -> Option<String> {
        self.state()
            .held
            .as_ref()
            .map(|held| held.list.revision.clone())
    }

    /// Begins a refresh if one is due at `now`: no list was fetched yet, the list held is
    /// older than its lifetime, or a refresh was asked for
    /// ([`report_unknown_authority`](Self::report_unknown_authority),
    /// [`refresh_before_refusing`](Self::refresh_before_refusing)). `None` while another
    /// refresh is running (one at a time) or the backoff after a failure has not passed.
    ///
    /// The list held stays in use while the refresh runs. Finish it with
    /// [`finish_refresh`](Self::finish_refresh), also when the exchange failed or was given up
    /// ([`fail_refresh`](Self::fail_refresh)). One that is not finished within
    /// [`REFRESH_ABANDONED_AFTER`] counts as failed, and the next may begin: give the
    /// exchange up before that, so that two never run at once.
    #[must_use = "a refresh that was begun must be finished (finish_refresh or fail_refresh)"]
    pub fn begin_refresh_at(&self, now: Instant) -> Option<HostListRefresh> {
        let mut state = self.state();
        if let Some(running) = state.refreshing {
            if now.saturating_duration_since(running.began) < REFRESH_ABANDONED_AFTER {
                return None;
            }
            // Abandoned: a failure like any other.
            Self::failed(&mut state, now);
        }
        if state
            .backoff
            .is_some_and(|(since, pause)| now.saturating_duration_since(since) < pause)
        {
            return None;
        }
        let stale = state
            .held
            .as_ref()
            .is_none_or(|held| now.saturating_duration_since(held.since) >= held.lifetime);
        if !(stale || state.wanted) {
            return None;
        }
        if state.wanted_for_unknown_authority {
            // The interval between two such refreshes runs from when one begins.
            state.last_unknown_authority = Some(now);
        }
        state.next_id = state.next_id.wrapping_add(1);
        let id = state.next_id;
        state.refreshing = Some(Running { id, began: now });
        Some(HostListRefresh {
            holder: self.id,
            id,
            revision: state.held.as_ref().map(|held| held.list.revision.clone()),
        })
    }

    /// Whether a refresh is running at `now` (begun, not finished, not yet given up). While
    /// one runs, a host that is not allowed may be in the list it brings.
    pub fn is_refreshing_at(&self, now: Instant) -> bool {
        self.state().refreshing.is_some_and(|running| {
            now.saturating_duration_since(running.began) < REFRESH_ABANDONED_AFTER
        })
    }

    /// [`is_refreshing_at`](Self::is_refreshing_at) now.
    pub fn is_refreshing(&self) -> bool {
        self.is_refreshing_at(Instant::now())
    }

    /// [`begin_refresh_at`](Self::begin_refresh_at) now.
    #[must_use = "a refresh that was begun must be finished (finish_refresh or fail_refresh)"]
    pub fn begin_refresh(&self) -> Option<HostListRefresh> {
        self.begin_refresh_at(Instant::now())
    }

    /// Finishes `refresh` with the gateway's answer to its request, `None` when the exchange
    /// failed before an inner response (transport, relay, sealing).
    ///
    /// A list replaces the one held; a `304` to the revision held restarts its lifetime;
    /// anything else ([`NoHostList`]) keeps what is held and starts the backoff
    /// ([`FIRST_REFRESH_BACKOFF`], doubling to [`MAX_REFRESH_BACKOFF`]). A refresh that is not
    /// the one running at this holder (begun at another holder, or given up as abandoned), or
    /// that is finished [`REFRESH_ABANDONED_AFTER`] or more after it began, changes the list
    /// in no way ([`RefreshOutcome::Superseded`]).
    pub fn finish_refresh_at(
        &self,
        refresh: HostListRefresh,
        response: Option<&Response>,
        now: Instant,
    ) -> RefreshOutcome {
        match response.map(read_third_party_hosts) {
            Some(Ok(answer)) => self.complete(refresh, Ok(answer), now),
            Some(Err(reason)) => self.complete(refresh, Err(Some(reason)), now),
            None => self.complete(refresh, Err(None), now),
        }
    }

    /// [`finish_refresh_at`](Self::finish_refresh_at) now.
    pub fn finish_refresh(
        &self,
        refresh: HostListRefresh,
        response: Option<&Response>,
    ) -> RefreshOutcome {
        self.finish_refresh_at(refresh, response, Instant::now())
    }

    /// Finishes `refresh` as failed, for a reason the caller found itself (`TooLarge` when it
    /// stopped reading an answer at [`MAX_THIRD_PARTY_HOSTS_BYTES`]) or `None` when the
    /// exchange failed or was given up. Like [`finish_refresh_at`](Self::finish_refresh_at)
    /// with such an answer.
    pub fn fail_refresh_at(
        &self,
        refresh: HostListRefresh,
        reason: Option<NoHostList>,
        now: Instant,
    ) -> RefreshOutcome {
        self.complete(refresh, Err(reason), now)
    }

    /// [`fail_refresh_at`](Self::fail_refresh_at) now.
    pub fn fail_refresh(
        &self,
        refresh: HostListRefresh,
        reason: Option<NoHostList>,
    ) -> RefreshOutcome {
        self.fail_refresh_at(refresh, reason, Instant::now())
    }

    fn complete(
        &self,
        refresh: HostListRefresh,
        answer: Result<HostListAnswer, Option<NoHostList>>,
        now: Instant,
    ) -> RefreshOutcome {
        let mut state = self.state();
        let running = match state.refreshing {
            Some(running) if refresh.holder == self.id && running.id == refresh.id => running,
            _ => return RefreshOutcome::Superseded,
        };
        if now.saturating_duration_since(running.began) >= REFRESH_ABANDONED_AFTER {
            // Too late, whether or not a later refresh has noticed yet: given up, a failure.
            Self::failed(&mut state, now);
            return RefreshOutcome::Superseded;
        }
        match answer {
            Ok(HostListAnswer::List(list)) => {
                let lifetime = Duration::from_secs(list.max_age_secs)
                    .clamp(MIN_HOST_LIST_AGE, MAX_HOST_LIST_AGE);
                state.held = Some(Held {
                    keys: list.hosts.iter().map(|h| h.host.clone()).collect(),
                    list,
                    since: now,
                    lifetime,
                });
                Self::succeeded(&mut state);
                RefreshOutcome::Updated
            }
            Ok(HostListAnswer::NotModified) => {
                // Only for the revision that was sent, which is the one still held (nothing
                // else replaces the list while a refresh is in flight).
                let confirmed = match (&mut state.held, &refresh.revision) {
                    (Some(held), Some(sent)) if held.list.revision == *sent => {
                        held.since = now;
                        true
                    }
                    _ => false,
                };
                if confirmed {
                    Self::succeeded(&mut state);
                    RefreshOutcome::NotModified
                } else {
                    Self::failed(&mut state, now);
                    RefreshOutcome::Kept(Some(NoHostList::UnexpectedNotModified))
                }
            }
            Err(reason) => {
                Self::failed(&mut state, now);
                RefreshOutcome::Kept(reason)
            }
        }
    }

    /// The refresh in flight ended with the gateway's current list (new or confirmed): every
    /// wish for a refresh is met, also one made while it ran.
    fn succeeded(state: &mut State) {
        state.refreshing = None;
        state.failures = 0;
        state.backoff = None;
        state.wanted = false;
        state.wanted_for_unknown_authority = false;
    }

    /// The refresh in flight failed or was given up: the backoff starts. A refresh that was
    /// asked for stays asked for (`wanted` is cleared by a success only), so it is tried
    /// again after the backoff although the list is not stale.
    fn failed(state: &mut State, now: Instant) {
        state.refreshing = None;
        state.failures = state.failures.saturating_add(1);
        // 30 s, 60 s, 120 s, 240 s, then 300 s.
        let doublings = state.failures.saturating_sub(1).min(8);
        let pause = FIRST_REFRESH_BACKOFF
            .saturating_mul(1u32 << doublings)
            .min(MAX_REFRESH_BACKOFF);
        state.backoff = Some((now, pause));
    }

    /// Reports that the gateway answered `403 unknown authority` ([`is_unknown_authority`]) to
    /// a request for `host`. For a host of the list held this means the replica that answered
    /// has not learned the host yet: use another server of the service, and the list is
    /// fetched again at the next [`begin_refresh`](Self::begin_refresh). Returns whether a
    /// refresh was asked for: not while one is running (it brings the current list), and at
    /// most once per [`UNKNOWN_AUTHORITY_REFRESH_INTERVAL`] for this reason, counted from when
    /// the last such refresh began.
    ///
    /// For a host that is allowed only by the bootstrap list nothing is asked: the list held,
    /// if any, does not name it.
    pub fn report_unknown_authority_at(&self, host: &str, now: Instant) -> bool {
        let Some(key) = host_key(host) else {
            return false;
        };
        let mut state = self.state();
        if !state
            .held
            .as_ref()
            .is_some_and(|held| held.keys.contains(&key))
        {
            return false;
        }
        let running = state.refreshing.is_some_and(|running| {
            now.saturating_duration_since(running.began) < REFRESH_ABANDONED_AFTER
        });
        if running || state.wanted_for_unknown_authority {
            return false;
        }
        if state.last_unknown_authority.is_some_and(|last| {
            now.saturating_duration_since(last) < UNKNOWN_AUTHORITY_REFRESH_INTERVAL
        }) {
            return false;
        }
        state.last_unknown_authority = Some(now);
        state.wanted = true;
        state.wanted_for_unknown_authority = true;
        true
    }

    /// [`report_unknown_authority_at`](Self::report_unknown_authority_at) now.
    pub fn report_unknown_authority(&self, host: &str) -> bool {
        self.report_unknown_authority_at(host, Instant::now())
    }

    /// Before refusing a host that is not allowed: whether one refresh is worth it first (a
    /// host added since the list was fetched would be in the new one). True when no list was
    /// fetched yet, and when the list held is older than [`REFUSAL_REFRESH_MIN_AGE`], in which
    /// case a refresh is asked for. When true: run a refresh
    /// ([`begin_refresh`](Self::begin_refresh); it may not be due, during a backoff or while
    /// another runs) and ask [`is_carried`](Self::is_carried) again before refusing.
    pub fn refresh_before_refusing_at(&self, now: Instant) -> bool {
        let mut state = self.state();
        match &state.held {
            None => true,
            Some(held) => {
                let old_enough =
                    now.saturating_duration_since(held.since) >= REFUSAL_REFRESH_MIN_AGE;
                if old_enough {
                    state.wanted = true;
                }
                old_enough
            }
        }
    }

    /// [`refresh_before_refusing_at`](Self::refresh_before_refusing_at) now.
    pub fn refresh_before_refusing(&self) -> bool {
        self.refresh_before_refusing_at(Instant::now())
    }
}

#[cfg(feature = "client")]
impl ThirdPartyHosts {
    /// Refreshes the list through `client` if a refresh is due: the request goes to the
    /// gateway `gateway_host` (the gateway's own host name; always the same one for one
    /// holder) through the client's relay, within `timeout` (at most four minutes). One
    /// refresh at a time; the list held stays in use meanwhile and after a failure. The
    /// answer is read up to [`MAX_THIRD_PARTY_HOSTS_BYTES`] and no further.
    ///
    /// Nothing is sent when the list is fresh or the backoff after a failure has not passed
    /// ([`RefreshOutcome::NotDue`]), or while another refresh is running
    /// ([`RefreshOutcome::Running`]: its result is in the holder when it ends).
    ///
    /// Nothing calls this by itself: call it where the wallet is about to use third-party
    /// hosts, or from a task of the caller's own. It never panics and holds no lock while the
    /// exchange runs.
    pub async fn refresh(
        &self,
        client: &crate::Client,
        gateway_host: &str,
        timeout: Duration,
    ) -> RefreshOutcome {
        let Some(refresh) = self.begin_refresh() else {
            return if self.is_refreshing() {
                RefreshOutcome::Running
            } else {
                RefreshOutcome::NotDue
            };
        };
        // If this future is dropped while the exchange runs, the refresh is given up at once
        // (a failure), instead of blocking the next one for `REFRESH_ABANDONED_AFTER`.
        let mut guard = GiveUpOnDrop {
            hosts: self,
            id: Some(refresh.id),
        };
        let response = client
            .host_list_exchange(
                &refresh.request(gateway_host),
                timeout.min(MAX_REFRESH_EXCHANGE),
            )
            .await;
        guard.id = None;
        match response {
            Ok(response) => self.finish_refresh(refresh, Some(&response)),
            Err(crate::Error::TooLarge { .. }) => {
                self.fail_refresh(refresh, Some(NoHostList::TooLarge))
            }
            Err(_) => self.fail_refresh(refresh, None),
        }
    }
}

/// Gives a refresh up when dropped before it was finished.
#[cfg(feature = "client")]
struct GiveUpOnDrop<'a> {
    hosts: &'a ThirdPartyHosts,
    id: Option<u64>,
}

#[cfg(feature = "client")]
impl Drop for GiveUpOnDrop<'_> {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            let mut state = self.hosts.state();
            if state.refreshing.map(|running| running.id) == Some(id) {
                ThirdPartyHosts::failed(&mut state, Instant::now());
            }
        }
    }
}

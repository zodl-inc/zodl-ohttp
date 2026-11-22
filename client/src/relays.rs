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

//! Several relays in front of one gateway: a random choice per request (equal shares), and a
//! failover to another relay while one fails.
//!
//! A network's `relay_url` may list several relays, separated by `,` (see
//! [`crate::OhttpConfigParams::relay_url`]). Every request draws a fresh random number from the
//! operating system and goes to the relay it falls on, so the relays share the traffic equally. Nothing about the choice is
//! derived from the wallet, and no choice is kept or stored: the only state, in memory, is
//! which relays are held out after a failure (below).
//!
//! [`RelaySelector::note_failure`] takes a relay out of the choice for [`RELAY_FAILOVER_HOLD`]
//! (a transport failure, a success that is no sealed answer, or an outer status
//! [`relay_status_fails_over`]), doubling while it keeps failing right after each hold up to
//! [`MAX_RELAY_FAILOVER_HOLD`], as does a running `Retry-After` pause of
//! [`crate::RelayBackoff::global`]; a request that drew it then goes to another relay of the
//! list (the others in list order), so while a relay is out its share goes to the next one in
//! that order, not spread over the rest. A relay comes back when
//! its hold ends or a request through it succeeds ([`RelaySelector::note_success`]). With every
//! relay out, the first relay in the failover order that is only held (not paused) is used,
//! else the relay drawn; failures while every relay is out (the device offline, the gateway
//! down) do not double a hold, and the first success releases the holds of the relays that
//! failed with it (a hold doubled before, on that relay's own, stays). A list of one relay behaves as a single relay URL always did.
//! Nothing here sends or resends a request: which relay the next request goes to is all it
//! decides.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::config::{parse_relay_url, RelayTarget};
use crate::RelayBackoff;

/// The most relays a list may have.
pub const MAX_RELAYS: usize = 8;
/// How long a relay that failed stays out of the choice when the list has another relay. A
/// relay that fails again soon after its hold ends is held twice as long each time, up to
/// [`MAX_RELAY_FAILOVER_HOLD`]; a success ends the hold and the doubling.
pub const RELAY_FAILOVER_HOLD: Duration = Duration::from_secs(60);
/// The longest hold of a relay that keeps failing.
pub const MAX_RELAY_FAILOVER_HOLD: Duration = Duration::from_secs(16 * 60);

/// Where a relay list's next entry begins: a `,` followed by the next URL's scheme.
pub(crate) const LIST_SEPARATOR: &str = ",https://";

/// Whether an outer refusal with `status` is about the request itself (`400`, `409`, `413`,
/// `415`, `422`, `426`): the relay answered, though the status does not prove it delivered
/// (a front end may write one too). Report it with [`RelaySelector::note_answered_of`], which
/// ends the relay's probe after a hold without counting a success or a failure.
pub const fn relay_status_answered(status: u16) -> bool {
    matches!(status, 400 | 409 | 413 | 415 | 422 | 426)
}

/// Whether an outer answer with `status` holds its relay out of the choice
/// ([`RelaySelector::note_failure`]): `429`, any `5xx`, a redirect (never followed), and the
/// refusals that say the relay cannot deliver to the gateway at all (`401`, `403`, `404`,
/// `405`, `407`, `421`), where
/// another relay may. Not `400`, `409`, `413`, `415` or `422`, which concern the request or its
/// key configuration, the same through any relay.
pub const fn relay_status_fails_over(status: u16) -> bool {
    matches!(status, 300..=399 | 401 | 403 | 404 | 405 | 407 | 421 | 429 | 500..=599)
}

/// One relay of a network's configuration.
///
/// Its `Debug` output never shows the URL.
#[derive(Clone, PartialEq, Eq)]
pub struct Relay {
    pub(crate) target: RelayTarget,
    /// The selector's key for it ([`relay_key`]).
    key: String,
    /// Its share of the requests, against the other relays' (every relay of a configured
    /// list has the same; a relay weights block may set others for a choice).
    weight: u32,
}

impl Relay {
    /// The relay URL, canonical (see [`crate::OhttpConfig::relay_url`]).
    pub fn url(&self) -> &str {
        &self.target.url
    }

    pub(crate) fn weight(&self) -> u32 {
        self.weight
    }

    fn new(target: RelayTarget, weight: u32) -> Self {
        let key = relay_key(&target);
        Relay {
            target,
            key,
            weight,
        }
    }

    /// `target` with the share `weight`.
    #[cfg(test)]
    pub(crate) fn weighted(target: RelayTarget, weight: u32) -> Self {
        Relay::new(target, weight)
    }

    /// This relay with the share `weight` (a relay weights block's).
    pub(crate) fn with_weight(&self, weight: u32) -> Self {
        Relay {
            weight,
            ..self.clone()
        }
    }
}

impl std::fmt::Debug for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relay")
            .field("url", &format_args!("<set>"))
            .finish()
    }
}

/// Reads a `relay_url` value: one relay URL, or a list of relay URLs separated by `,`, each
/// entry after the first beginning `https://` (so a value is a list only where a `,` is followed
/// by `https://`, which no single relay URL holds; any other `,` stays part of a URL's path).
/// Every relay of a list gets the same share. The error completes "`relay_url` ...".
pub(crate) fn parse_relay_list(value: &str) -> Result<Vec<Relay>, &'static str> {
    let mut relays: Vec<Relay> = Vec::new();
    let mut rest = value;
    loop {
        let (entry, next) = match rest.find(LIST_SEPARATOR) {
            Some(at) => (&rest[..at], Some(&rest[at + 1..])),
            None => (rest, None),
        };
        if relays.len() == MAX_RELAYS {
            return Err("must not list more than 8 relays");
        }
        // `URL,,https://...`: a stray comma would otherwise end the first URL's path.
        if next.is_some() && entry.ends_with(',') {
            return Err("must not contain an empty list entry");
        }
        let target = parse_relay_url(entry)?;
        if relays.iter().any(|r| r.target.same_relay(&target)) {
            return Err("must not list the same relay twice");
        }
        relays.push(Relay::new(target, 1));
        match next {
            Some(next) => rest = next,
            None => return Ok(relays),
        }
    }
}

/// The relay `draw` (a uniform 64-bit number) picks under `weights`: the one whose share of
/// the total the draw falls into (each share exact to within one part in 2^64). A relay of
/// weight 0 is never picked; `None` when every weight is 0.
pub(crate) fn pick(weights: &[u32], draw: u64) -> Option<usize> {
    let total: u64 = weights.iter().map(|&w| u64::from(w)).sum();
    if total == 0 {
        return None;
    }
    // `draw / 2^64 * total`, exactly: a point in `0..total`.
    let point = ((u128::from(draw) * u128::from(total)) >> 64) as u64;
    let mut end = 0u64;
    for (i, &w) in weights.iter().enumerate() {
        end += u64::from(w);
        if point < end {
            return Some(i);
        }
    }
    None
}

/// The order relays are tried in: `primary`, then the others by weight (highest first, list
/// order among equals), those of weight 0 last.
fn failover_order(weights: &[u32], primary: usize) -> Vec<usize> {
    let mut rest: Vec<usize> = (0..weights.len()).filter(|&i| i != primary).collect();
    rest.sort_by_key(|&i| std::cmp::Reverse(weights[i]));
    std::iter::once(primary).chain(rest).collect()
}

/// The relays a process holds out of the choice after a failure.
///
/// [`RelaySelector::global`] is the one a process shares, and the one
/// [`crate::OhttpConfig::choose_relay`] and [`crate::OhttpNetworks::choose_relay_for`] ask.
/// Its `Debug` output gives the number of relays held out only, never a relay URL.
#[derive(Default)]
pub struct RelaySelector {
    /// Everything under one lock, so that a failure and a success are each one atomic step.
    state: Mutex<SelectorState>,
}

/// The state of a [`RelaySelector`], by relay key ([`relay_key`]). Each table has at most
/// [`MAX_HELD_RELAYS`] entries.
#[derive(Default)]
struct SelectorState {
    /// Relays held out, and relays whose hold ended no longer ago than it lasted (remembered,
    /// for the doubling and to tell one relay's failure from a failure of them all).
    held: HashMap<String, Hold>,
    /// When the latest request was sent that got its answer through each relay: a failure of a
    /// request sent before it is older news and holds nothing.
    cleared: HashMap<String, Instant>,
    /// The list each relay was last chosen from (a digest of its keys), so that failures and
    /// successes are compared within one list only: the lists of a process's networks share
    /// no relay ([`crate::OhttpNetworks::new`]).
    lists: HashMap<String, u64>,
    /// When the latest failure that counted was reported, kept after its hold is forgotten: a
    /// failure of a request sent before it (a long request reporting late) is older news.
    failed: HashMap<String, Instant>,
    /// Failures set aside because a request sent later had succeeded, by relay: how many, and
    /// since when. A relay that hangs only some requests answers others, so each failure looks
    /// like older news; [`MASKED_FAILURES_TO_HOLD`] of them within [`MASKED_FAILURE_WINDOW`]
    /// count after all.
    masked: HashMap<String, Vec<Instant>>,
    /// The last probe handed out ([`RelayProbe`]); never 0 once one was.
    probes: u64,
}

impl SelectorState {
    /// Records `relays` as the list each of them was chosen from.
    fn remember(&mut self, relays: &[Relay]) {
        use std::hash::{Hash as _, Hasher as _};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        for relay in relays {
            relay.key.hash(&mut hasher);
        }
        let id = hasher.finish();
        let state = self;
        if relays.iter().all(|r| state.lists.get(&r.key) == Some(&id)) {
            return;
        }
        if state.lists.len() + relays.len() > MAX_HELD_RELAYS {
            state.lists.clear();
        }
        for relay in relays {
            state.lists.insert(relay.key.clone(), id);
        }
    }

    /// Whether the relay of key `key` is held out at `now`: during its hold, and after it
    /// while the one probe let through has not reported (for at most [`RELAY_PROBE_WINDOW`]).
    /// When it is not, and its hold has just ended, this request becomes the probe.
    fn admit(&mut self, key: &str, now: Instant) -> Option<RelayProbe> {
        let state = self;
        let Some(h) = state.held.get_mut(key) else {
            return Some(RelayProbe::NONE);
        };
        if h.until > now {
            return None;
        }
        // A probe out keeps the others away, however old the hold.
        if h.probe
            .is_some_and(|(at, _)| now.saturating_duration_since(at) < RELAY_PROBE_WINDOW)
        {
            return None;
        }
        if !h.remembered(now) {
            return Some(RelayProbe::NONE);
        }
        // A counter that never hands out a value twice: once spent (never, in practice), the
        // request goes through as no probe.
        let Some(id) = state.probes.checked_add(1) else {
            return Some(RelayProbe::NONE);
        };
        state.probes = id;
        h.probe = Some((now, id));
        Some(RelayProbe(id))
    }

    /// Whether the relay at index `i` of `relays` may take a request at `now` (letting it
    /// through as the probe after a hold when it is the one).
    fn available(
        &mut self,
        relays: &[Relay],
        i: usize,
        now: Instant,
        pauses: &Pauses<'_>,
    ) -> Option<RelayProbe> {
        if pauses.paused(relays, i, now) {
            return None;
        }
        self.admit(&relays[i].key, now)
    }

    /// Whether the relay at index `i` of `relays` may be sent to at `now` at all: not paused
    /// (a hold is advice, a `Retry-After` pause is the relay's own refusal).
    fn unpaused(&self, relays: &[Relay], i: usize, now: Instant, pauses: &Pauses<'_>) -> bool {
        !pauses.paused(relays, i, now) && !self.probing(&relays[i].key, now)
    }

    /// Whether the relay of key `key` has a probe out (let through after its hold, not yet
    /// reported, within [`RELAY_PROBE_WINDOW`]): the fallback that ignores holds leaves it alone
    /// too, so that one request at a time stays one.
    fn probing(&self, key: &str, now: Instant) -> bool {
        // Whether the hold has ended or not: a probe kept while a later failure holds the relay
        // again is still out.
        self.held.get(key).is_some_and(|h| {
            h.probe
                .is_some_and(|(at, _)| now.saturating_duration_since(at) < RELAY_PROBE_WINDOW)
        })
    }

    /// Whether a report of a request the choice gave `probe` counts: one that was no probe,
    /// or the current probe of the relay of key `key`.
    fn current(&self, key: &str, probe: RelayProbe) -> bool {
        !probe.is_probe()
            || self
                .held
                .get(key)
                .is_some_and(|h| h.probe.is_some_and(|(_, id)| id == probe.0))
    }
}

/// How many failures set aside as older news (a later request had succeeded) hold a relay
/// after all, within [`MASKED_FAILURE_WINDOW`] (a rolling window): a relay that answers some
/// requests and hangs others. Any failure reported to the selector counts (a connect timeout, a
/// broken body, an answer that does not open); a caller's whole-body deadline is not reported,
/// so a relay that stalls bodies only past it is not held this way. A hold only moves load, it
/// never resends anything.
pub const MASKED_FAILURES_TO_HOLD: u32 = 3;
/// The window [`MASKED_FAILURES_TO_HOLD`] is counted in.
pub const MASKED_FAILURE_WINDOW: Duration = Duration::from_secs(5 * 60);
/// After a hold ends, one request at a time is let through to the relay as a probe; others
/// still go elsewhere until it reports or this long has passed.
pub const RELAY_PROBE_WINDOW: Duration = Duration::from_secs(30);

/// Which probe a relay choice let through after the relay's hold, if it let one through: an
/// opaque value the caller keeps with the request and passes back with its report
/// ([`RelaySelector::note_failure_of_probe`], [`RelaySelector::note_success_of_probe`],
/// [`RelaySelector::note_answered_of`]), so that only the report of the relay's current probe
/// ends it. The report of a probe a newer one has replaced (a request chosen as the probe but
/// sent late) never ends the newer probe: its answer changes nothing, its success only makes
/// older failures older news, and its failure counts as any failure.
/// [`RelayProbe::NONE`] for a request that was no probe.
///
/// It carries no relay URL and no time: a counter, for passing through a foreign-function
/// interface as [`to_raw`](Self::to_raw) / [`from_raw`](Self::from_raw) (an unsigned 64-bit
/// value: `ULong` in Kotlin, `UInt64` in Swift).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct RelayProbe(u64);

impl RelayProbe {
    /// A request that was no probe.
    pub const NONE: RelayProbe = RelayProbe(0);

    /// Whether the choice let the request through as a relay's probe.
    pub const fn is_probe(self) -> bool {
        self.0 != 0
    }

    /// The value as a number, for passing it through a foreign-function interface.
    pub const fn to_raw(self) -> u64 {
        self.0
    }

    /// The value [`to_raw`](Self::to_raw) gave, passed back unchanged to the selector and for
    /// the relay it came from (`0` is [`RelayProbe::NONE`]). The value is no secret and no
    /// proof: a number made up by the caller may match a current probe, and each
    /// [`RelaySelector`] counts its own.
    pub const fn from_raw(raw: u64) -> Self {
        RelayProbe(raw)
    }
}

/// A relay held out of the choice.
#[derive(Clone, Copy, Debug)]
struct Hold {
    /// When the hold ends.
    until: Instant,
    /// How long it was last held, for the doubling.
    hold: Duration,
    /// When the hold began: a report of a request sent before it does not change it.
    since: Instant,
    /// When the latest request was sent whose failure counted: an older report (a success or
    /// a failure of a request sent before it) changes nothing.
    last: Instant,
    /// The list the relay was last chosen from, if it was.
    list: Option<u64>,
    /// When the probe after the hold was let through, and which one, if one was.
    probe: Option<(Instant, u64)>,
}

impl Hold {
    /// Whether the entry is still kept at `now`: held, ended no longer ago than it lasted, or
    /// with a probe out.
    fn remembered(&self, now: Instant) -> bool {
        self.until
            .checked_add(self.hold)
            .is_none_or(|end| end > now)
            || self
                .probe
                .is_some_and(|(at, _)| now.saturating_duration_since(at) < RELAY_PROBE_WINDOW)
    }
}

impl std::fmt::Debug for RelaySelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let held = match self.state.try_lock() {
            Ok(state) => Some(state.held.len()),
            Err(std::sync::TryLockError::Poisoned(p)) => Some(p.into_inner().held.len()),
            Err(std::sync::TryLockError::WouldBlock) => None,
        };
        let mut s = f.debug_struct("RelaySelector");
        match held {
            Some(n) => s.field("held", &n),
            None => s.field("held", &format_args!("<locked>")),
        };
        s.finish_non_exhaustive()
    }
}

/// Inserts into `map` and keeps it at [`MAX_HELD_RELAYS`] entries by clearing it first when
/// it is full (a table of advice: losing it only forgets old holds).
fn bounded_insert<V>(map: &mut HashMap<String, V>, key: String, value: V) {
    if !map.contains_key(&key) && map.len() >= MAX_HELD_RELAYS {
        map.clear();
    }
    map.insert(key, value);
}

impl RelaySelector {
    /// An empty selector: no relay held out.
    pub fn new() -> Self {
        Self::default()
    }

    /// The process-wide selector.
    pub fn global() -> &'static RelaySelector {
        static GLOBAL: OnceLock<RelaySelector> = OnceLock::new();
        GLOBAL.get_or_init(RelaySelector::new)
    }

    fn state(&self) -> std::sync::MutexGuard<'_, SelectorState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// A request through the relay at `relay_url` failed in a way another relay may not: no
    /// connection, a TLS failure, a broken exchange, an answer that does not open, a success
    /// that is no sealed answer, or an outer status [`relay_status_fails_over`]. The relay
    /// stays out of the choice for [`RELAY_FAILOVER_HOLD`] where its list has another relay.
    /// When it fails again on a request sent after that hold ended, while no other relay of its
    /// list has failed lately, it is held twice as long, up to [`MAX_RELAY_FAILOVER_HOLD`];
    /// failures of several relays of a list at once (the device offline, the gateway down) are
    /// not doubled. Nothing is resent here.
    ///
    /// `relay_url` is compared as the configuration compares relays (host, port and path as
    /// [`crate::OhttpNetworks::new`] tells relays apart), so any spelling of a configured relay
    /// holds it. At most [`MAX_HELD_RELAYS`] relays are kept at once. This form takes the
    /// request as sent now; [`note_failure_of`](Self::note_failure_of) takes the instant it was
    /// sent.
    pub fn note_failure(&self, relay_url: &str) {
        let now = Instant::now();
        self.note_failure_with(relay_url, now, now);
    }

    /// [`note_failure`](Self::note_failure) for a request sent at `sent_at`: the report of a
    /// request sent before a later request through the relay got its answer, before the
    /// relay's current hold began, or during a hold that has ended since, changes nothing (one
    /// sent during a hold that still runs, when every relay was out, failed anew and extends
    /// it).
    ///
    /// A request a choice let through as a probe reports with
    /// [`note_failure_of_probe`](Self::note_failure_of_probe) instead.
    pub fn note_failure_of(&self, relay_url: &str, sent_at: Instant) {
        self.note_failure_with(relay_url, sent_at, Instant::now());
    }

    /// [`note_failure_of`](Self::note_failure_of) for a request the choice gave `probe`
    /// ([`crate::OhttpConfig::choose_relay_where`]): the failure of the relay's current probe
    /// ends that probe and holds the relay again, twice as long. The failure of a probe no
    /// longer current (replaced by a newer one after [`RELAY_PROBE_WINDOW`], or ended by
    /// another report) counts as any failure of a request sent at `sent_at` (so that a relay
    /// whose every probe hangs past the window is still held), but never ends the newer probe:
    /// that one's own report still counts. With [`RelayProbe::NONE`], exactly
    /// [`note_failure_of`](Self::note_failure_of).
    pub fn note_failure_of_probe(&self, relay_url: &str, sent_at: Instant, probe: RelayProbe) {
        self.note_failure_probe_with(relay_url, sent_at, Instant::now(), probe);
    }

    /// [`note_failure`](Self::note_failure) at `now`, for a request sent then.
    pub fn note_failure_at(&self, relay_url: &str, now: Instant) {
        self.note_failure_with(relay_url, now, now);
    }

    /// [`note_failure_of_probe`](Self::note_failure_of_probe) at `now`, for a request sent
    /// then, for tests.
    #[cfg(test)]
    fn note_failure_probe_at(&self, relay_url: &str, now: Instant, probe: RelayProbe) {
        self.note_failure_probe_with(relay_url, now, now, probe);
    }

    fn note_failure_with(&self, relay_url: &str, sent_at: Instant, now: Instant) {
        self.note_failure_probe_with(relay_url, sent_at, now, RelayProbe::NONE);
    }

    fn note_failure_probe_with(
        &self,
        relay_url: &str,
        sent_at: Instant,
        now: Instant,
        probe: RelayProbe,
    ) {
        let key = held_key(relay_url);
        let mut state = self.state();
        // A probe no longer current failed all the same: the failure counts, but the newer
        // probe stays the relay's, its own report still to come.
        let current = state.current(&key, probe);
        // The probe's own report ends it, whatever the rest of its failure counts for.
        if current && probe.is_probe() {
            if let Some(h) = state.held.get_mut(&key) {
                h.probe = None;
            }
        }
        if state.failed.get(&key).is_some_and(|&last| sent_at < last) {
            return;
        }
        if state.cleared.get(&key).is_some_and(|&ok| sent_at < ok) {
            // Older news, unless the relay keeps failing requests while answering others:
            // the failures set aside within the last MASKED_FAILURE_WINDOW (a rolling window).
            let mut recent: Vec<Instant> = state.masked.get(&key).cloned().unwrap_or_default();
            recent.retain(|&at| now.saturating_duration_since(at) < MASKED_FAILURE_WINDOW);
            recent.push(now);
            if (recent.len() as u32) < MASKED_FAILURES_TO_HOLD {
                bounded_insert(&mut state.masked, key, recent);
                return;
            }
            state.masked.remove(&key);
        }
        let list = state.lists.get(&key).copied();
        state.held.retain(|_, h| h.remembered(now));
        let others_failing =
            list.is_some() && state.held.iter().any(|(k, h)| *k != key && h.list == list);
        let (hold, since) = match state.held.get(&key) {
            // Sent before the latest failure that counted, before the hold began (a late
            // report), or while a hold that has ended since was running: no change.
            Some(h)
                if sent_at < h.last
                    || sent_at < h.since
                    || (h.until <= now && sent_at < h.until) =>
            {
                return
            }
            // Held now and failing again: the hold runs on from now, as long as it is.
            Some(h) if h.until > now => (h.hold, h.since),
            // Failing again after its hold: twice as long, unless others fail too.
            Some(h) if !others_failing => ((h.hold * 2).min(MAX_RELAY_FAILOVER_HOLD), now),
            Some(h) => (h.hold, now),
            None => (RELAY_FAILOVER_HOLD, now),
        };
        let until = now.checked_add(hold).unwrap_or(now);
        if !state.held.contains_key(&key) && state.held.len() >= MAX_HELD_RELAYS {
            if let Some(first) = state
                .held
                .iter()
                .min_by_key(|(_, h)| h.until)
                .map(|(k, _)| k.clone())
            {
                state.held.remove(&first);
            }
        }
        // From now on, a failure of a request sent before this one counted is older news, even
        // once the hold is forgotten.
        bounded_insert(&mut state.failed, key.clone(), now);
        let entry = state.held.entry(key).or_insert(Hold {
            until,
            hold,
            since,
            last: sent_at,
            list,
            probe: None,
        });
        entry.hold = hold;
        entry.since = since;
        entry.last = sent_at;
        entry.list = list;
        // Only the probe's own failure ends it; any other starts a hold longer than the probe
        // window, which keeps the relay out all the same.
        if current && probe.is_probe() {
            entry.probe = None;
        }
        if entry.until < until {
            entry.until = until;
        }
    }

    /// A request through the relay at `relay_url` got its sealed answer, complete: its failure
    /// hold ends at once, and a failure of a request sent before this one is ignored from now
    /// on. If it had failed lately itself, the holds of the other relays of its list that
    /// failed with it end too (the device offline, the gateway down: the way is clear again).
    /// A running `Retry-After` pause of [`RelayBackoff`] is not touched. This form takes the
    /// request as sent now; [`note_success_of`](Self::note_success_of) takes the instant it was
    /// sent.
    pub fn note_success(&self, relay_url: &str) {
        self.note_success_of(relay_url, Instant::now());
    }

    /// [`note_success`](Self::note_success) for a request sent at `sent_at`: a hold that began
    /// after the request was sent (another request failed meanwhile) is left as it is.
    ///
    /// A request a choice let through as a probe reports with
    /// [`note_success_of_probe`](Self::note_success_of_probe) instead.
    pub fn note_success_of(&self, relay_url: &str, sent_at: Instant) {
        self.note_success_of_probe(relay_url, sent_at, RelayProbe::NONE);
    }

    /// [`note_success_of`](Self::note_success_of) for a request the choice gave `probe`
    /// ([`crate::OhttpConfig::choose_relay_where`]): the success of the relay's current probe
    /// ends its hold. That of a probe no longer current (replaced by a newer one after
    /// [`RELAY_PROBE_WINDOW`], or ended by another report) ends neither the hold nor the newer
    /// probe; it only makes the failures of requests sent before it older news. With
    /// [`RelayProbe::NONE`], exactly [`note_success_of`](Self::note_success_of).
    pub fn note_success_of_probe(&self, relay_url: &str, sent_at: Instant, probe: RelayProbe) {
        let key = held_key(relay_url);
        let mut state = self.state();
        if !state.current(&key, probe) {
            // A probe no longer current got its answer: older failures are older news, but
            // the hold and the newer probe are left to that probe's own report.
            let newest = state
                .cleared
                .get(&key)
                .map_or(sent_at, |&ok| ok.max(sent_at));
            bounded_insert(&mut state.cleared, key, newest);
            return;
        }
        // The probe's own report ends it, whatever the rest of its success counts for.
        if probe.is_probe() {
            if let Some(h) = state.held.get_mut(&key) {
                h.probe = None;
            }
        }
        // Recorded for every success (the table is bounded): a request sent earlier may still
        // report a failure, which is older news.
        let newest = state
            .cleared
            .get(&key)
            .map_or(sent_at, |&ok| ok.max(sent_at));
        bounded_insert(&mut state.cleared, key.clone(), newest);
        let Some(mine) = state.held.get(&key).copied() else {
            return;
        };
        // A failure of a request sent after this one is newer news.
        if mine.since > sent_at || mine.last > sent_at {
            return;
        }
        state.held.remove(&key);
        // Others of the list that failed with it (not one held longer, down on its own).
        // One with its probe out is left to that probe's own report.
        if mine.list.is_some() {
            let mut released = Vec::new();
            state.held.retain(|k, h| {
                let keep = h.list != mine.list
                    || h.since > sent_at
                    || h.last > sent_at
                    || h.hold > RELAY_FAILOVER_HOLD
                    // (out when this request was sent: the report's own clock)
                    || h.probe.is_some_and(|(at, _)| {
                        sent_at.saturating_duration_since(at) < RELAY_PROBE_WINDOW
                    });
                if !keep {
                    released.push(k.clone());
                }
                keep
            });
            for other in released {
                let at = state
                    .cleared
                    .get(&other)
                    .map_or(sent_at, |&ok| ok.max(sent_at));
                bounded_insert(&mut state.cleared, other, at);
            }
        }
    }

    /// A request through the relay at `relay_url`, to which the choice gave `probe`, was
    /// refused with an outer status for which [`relay_status_answered`] holds: an answer about
    /// the request itself, which shows the relay answered but not that it delivered (a front end
    /// may write such a status too). Neither a success nor a failure: if `probe` is the relay's
    /// current probe after its hold, the probe ends and the next request may probe the relay, so
    /// that it does not stay at one request per [`RELAY_PROBE_WINDOW`]. The hold and its
    /// doubling are left as they are. A probe no longer current (replaced by a newer one, or
    /// ended by another report), and [`RelayProbe::NONE`], change nothing. Nothing is resent.
    pub fn note_answered_of(&self, relay_url: &str, probe: RelayProbe) {
        let key = held_key(relay_url);
        let mut state = self.state();
        if !probe.is_probe() || !state.current(&key, probe) {
            return;
        }
        if let Some(h) = state.held.get_mut(&key) {
            h.probe = None;
        }
    }

    /// [`SelectorState::unpaused`] under the lock, for tests.
    #[cfg(test)]
    fn unpaused(&self, relays: &[Relay], i: usize, now: Instant, pauses: &Pauses<'_>) -> bool {
        self.state().unpaused(relays, i, now, pauses)
    }

    /// Whether `probe` is the current probe of the relay at `relay_url`, for tests.
    #[cfg(test)]
    fn is_current(&self, relay_url: &str, probe: RelayProbe) -> bool {
        probe.is_probe() && self.state().current(&held_key(relay_url), probe)
    }

    /// [`note_failure_of_probe`](Self::note_failure_of_probe) for a request sent at
    /// `sent_at`, reported at `now`, for tests.
    #[cfg(test)]
    fn note_failure_of_probe_with(
        &self,
        relay_url: &str,
        sent_at: Instant,
        now: Instant,
        probe: RelayProbe,
    ) {
        self.note_failure_probe_with(relay_url, sent_at, now, probe);
    }

    /// [`SelectorState::probing`] under the lock, for tests.
    #[cfg(test)]
    fn probing(&self, key: &str, now: Instant) -> bool {
        self.state().probing(key, now)
    }

    /// The hold of the relay at `relay_url`, for tests.
    #[cfg(test)]
    fn hold_of(&self, relay_url: &str) -> Option<Hold> {
        self.state().held.get(&held_key(relay_url)).copied()
    }

    /// The index of the relay of `relays` a request goes to: a fresh random choice by share,
    /// passed on down the failover order while the relay drawn is held out, paused or has a
    /// probe out. With every relay out, the first one in that order that is only held (not
    /// paused, no probe out); else one that is paused rather than one with a probe out (the
    /// request then fails locally on the pause); the relay drawn only when every relay has a
    /// probe out.
    pub(crate) fn choose(&self, relays: &[Relay]) -> usize {
        if relays.len() < 2 {
            return 0;
        }
        self.choose_with(
            relays,
            random_draw(),
            Instant::now(),
            RelayBackoff::global(),
        )
    }

    /// [`choose`](Self::choose) with the draw `draw`, at `now`, against the pauses of
    /// `backoff`.
    pub(crate) fn choose_with(
        &self,
        relays: &[Relay],
        draw: u64,
        now: Instant,
        backoff: &RelayBackoff,
    ) -> usize {
        if relays.len() < 2 {
            return 0;
        }
        self.choose_among(relays, draw, now, backoff, None)
            .map_or(0, |(i, _)| i)
    }

    /// [`choose`](Self::choose), with the probe the choice let through, if any. With every
    /// relay's probe out, the relay drawn as no probe (the one case where a request that is no
    /// probe goes to a relay while its probe is out; see `Client::for_network`).
    #[cfg_attr(not(feature = "client"), allow(dead_code))]
    pub(crate) fn choose_probe(&self, relays: &[Relay]) -> (usize, RelayProbe) {
        if relays.len() < 2 {
            return (0, RelayProbe::NONE);
        }
        self.choose_among(
            relays,
            random_draw(),
            Instant::now(),
            RelayBackoff::global(),
            None,
        )
        .unwrap_or((0, RelayProbe::NONE))
    }

    /// [`choose_with_where`](Self::choose_with_where) without the probe, for tests.
    #[cfg(test)]
    fn choose_index_where(
        &self,
        relays: &[Relay],
        draw: u64,
        now: Instant,
        backoff: &RelayBackoff,
        eligible: &dyn Fn(&str) -> bool,
    ) -> Option<usize> {
        self.choose_with_where(relays, draw, now, backoff, eligible)
            .map(|(i, _)| i)
    }

    /// [`choose_with`](Self::choose_with), with the probe the choice let through, for tests.
    #[cfg(test)]
    fn choose_probe_with(
        &self,
        relays: &[Relay],
        draw: u64,
        now: Instant,
        backoff: &RelayBackoff,
    ) -> (usize, RelayProbe) {
        self.choose_among(relays, draw, now, backoff, None)
            .unwrap_or((0, RelayProbe::NONE))
    }

    /// The index of the relay a request goes to, as [`choose`](Self::choose), with the
    /// caller's criterion: `eligible` is asked once per relay, before anything else, and a
    /// relay for which it is false is treated as paused (the caller cannot send there, a pause
    /// of its own that the selector does not see, say). Such a relay is passed over, never let
    /// through as the probe after its hold, and never returned. `None` when no relay eligible
    /// can take the request: none is eligible, or every eligible one has a probe out. A relay
    /// eligible but paused by `Retry-After` may be returned (the caller's pause check then
    /// fails the request locally, nothing sent), as [`choose`](Self::choose) does.
    pub(crate) fn choose_where(
        &self,
        relays: &[Relay],
        eligible: &dyn Fn(&str) -> bool,
    ) -> Option<(usize, RelayProbe)> {
        self.choose_with_where(
            relays,
            random_draw(),
            Instant::now(),
            RelayBackoff::global(),
            eligible,
        )
    }

    /// [`choose_where`](Self::choose_where) with the draw `draw`, at `now`, against the pauses
    /// of `backoff`.
    pub(crate) fn choose_with_where(
        &self,
        relays: &[Relay],
        draw: u64,
        now: Instant,
        backoff: &RelayBackoff,
        eligible: &dyn Fn(&str) -> bool,
    ) -> Option<(usize, RelayProbe)> {
        // Asked once per relay, so that the answer cannot change between the choice and the
        // probe it may let through.
        let eligible: Vec<bool> = relays.iter().map(|r| eligible(r.url())).collect();
        if relays.len() < 2 {
            return eligible
                .first()
                .copied()
                .unwrap_or(false)
                .then_some((0, RelayProbe::NONE));
        }
        self.choose_among(relays, draw, now, backoff, Some(&eligible))
    }

    /// The choice of [`choose_with`](Self::choose_with) (`eligible` `None`: every relay) or
    /// [`choose_with_where`](Self::choose_with_where) (only the relays marked eligible).
    fn choose_among(
        &self,
        relays: &[Relay],
        draw: u64,
        now: Instant,
        backoff: &RelayBackoff,
        eligible: Option<&[bool]>,
    ) -> Option<(usize, RelayProbe)> {
        let pauses = Pauses { backoff, eligible };
        let pauses = &pauses;
        // One lock for the whole choice, so that no report changes what it saw half way.
        let mut guard = self.state();
        let state = &mut *guard;
        state.remember(relays);
        let weights: Vec<u32> = relays.iter().map(Relay::weight).collect();
        let drawn = pick(&weights, draw).unwrap_or(0);
        let order = failover_order(&weights, drawn);
        let allowed = |i: usize| eligible.is_none_or(|e| e[i]);
        let first = order.iter().copied().find_map(|i| {
            state
                .available(relays, i, now, pauses)
                .map(|probe| (i, probe))
        });
        first.or_else(|| {
            order
                .iter()
                .copied()
                .find(|&i| state.unpaused(relays, i, now, pauses))
                // Every relay paused or with a probe out: a paused one (the request then fails
                // locally, nothing posted) rather than one whose probe is out. Never one the
                // caller cannot send to.
                .or_else(|| {
                    order
                        .iter()
                        .copied()
                        .find(|&i| allowed(i) && !state.probing(&relays[i].key, now))
                })
                // Every relay with a probe out: the relay drawn, unless the caller has a
                // criterion.
                .or_else(|| eligible.is_none().then_some(drawn))
                .map(|i| (i, RelayProbe::NONE))
        })
    }

    /// The relay of `relays` to take over a request that could not go through the one at
    /// index `failed`: the next one in its failover order that is neither held out nor paused,
    /// else one held but neither paused nor with a probe out, or `None`.
    #[cfg_attr(not(feature = "client"), allow(dead_code))]
    pub(crate) fn alternative(
        &self,
        relays: &[Relay],
        failed: usize,
    ) -> Option<(usize, RelayProbe)> {
        self.alternative_probe_with(relays, failed, Instant::now(), RelayBackoff::global())
    }

    /// [`alternative`](Self::alternative) at `now`, against the pauses of `backoff`, without
    /// the probe, for tests.
    #[cfg(test)]
    pub(crate) fn alternative_with(
        &self,
        relays: &[Relay],
        failed: usize,
        now: Instant,
        backoff: &RelayBackoff,
    ) -> Option<usize> {
        self.alternative_probe_with(relays, failed, now, backoff)
            .map(|(i, _)| i)
    }

    /// [`alternative`](Self::alternative) at `now`, against the pauses of `backoff`.
    #[cfg_attr(not(any(feature = "client", test)), allow(dead_code))]
    fn alternative_probe_with(
        &self,
        relays: &[Relay],
        failed: usize,
        now: Instant,
        backoff: &RelayBackoff,
    ) -> Option<(usize, RelayProbe)> {
        let pauses = Pauses {
            backoff,
            eligible: None,
        };
        let backoff = &pauses;
        let weights: Vec<u32> = relays.iter().map(Relay::weight).collect();
        let order: Vec<usize> = failover_order(&weights, failed)
            .into_iter()
            .skip(1)
            .collect();
        // One that is neither held nor paused; else one only held (a hold is advice, and
        // nothing was sent yet), as for the first choice. One lock for the whole choice.
        let mut guard = self.state();
        let state = &mut *guard;
        let first = order.iter().copied().find_map(|i| {
            state
                .available(relays, i, now, backoff)
                .map(|probe| (i, probe))
        });
        first.or_else(|| {
            order
                .iter()
                .copied()
                .find(|&i| state.unpaused(relays, i, now, backoff))
                .map(|i| (i, RelayProbe::NONE))
        })
    }
}

/// What keeps a request from a relay before anything is sent: a `Retry-After` pause, or the
/// caller's own criterion.
struct Pauses<'a> {
    backoff: &'a RelayBackoff,
    /// Per relay, whether the caller can send there; `None`: every relay.
    eligible: Option<&'a [bool]>,
}

impl Pauses<'_> {
    fn paused(&self, relays: &[Relay], i: usize, now: Instant) -> bool {
        self.eligible.is_some_and(|e| !e[i])
            || self.backoff.remaining_at(relays[i].url(), now).is_some()
    }
}

/// The most relays [`RelaySelector`] holds out at once.
pub const MAX_HELD_RELAYS: usize = 64;

/// The key the selector knows a relay by: host, port and path as
/// [`crate::OhttpNetworks::new`] tells relays apart (an IPv6 literal that embeds an IPv4
/// address as that address, the path in lower case), so that any spelling of one relay is one
/// key.
fn relay_key(target: &RelayTarget) -> String {
    format!(
        "{}:{}{}",
        target.identity_host(),
        target.port,
        target.path.to_ascii_lowercase()
    )
}

/// [`relay_key`] of `relay_url`, or the value as given when it is no relay URL.
fn held_key(relay_url: &str) -> String {
    parse_relay_url(relay_url)
        .map(|target| relay_key(&target))
        .unwrap_or_else(|_| relay_url.to_owned())
}

/// A uniform 64-bit number from the operating system. Should the operating system fail to
/// give one, a number from the standard library's per-process random hash keys and a counter:
/// still spread over the relays, though not of cryptographic quality (the choice
/// guards nothing secret, it only spreads the load).
fn random_draw() -> u64 {
    use rand_core::{OsRng, TryRngCore as _};
    OsRng.try_next_u64().unwrap_or_else(|_| fallback_draw())
}

fn fallback_draw() -> u64 {
    use std::hash::{BuildHasher as _, Hasher as _};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "https://relay-a.example/relay";
    const B: &str = "https://relay-b.example/gateway-path";

    fn list(value: &str) -> Vec<Relay> {
        parse_relay_list(value).unwrap()
    }

    /// Relays with the given shares (a configured list has equal ones).
    fn weighted(relays: &[(&str, u32)]) -> Vec<Relay> {
        relays
            .iter()
            .map(|&(url, w)| Relay::weighted(parse_relay_url(url).unwrap(), w))
            .collect()
    }

    /// SplitMix64: a seeded, reproducible stream of uniform 64-bit numbers.
    struct SplitMix64(u64);

    impl SplitMix64 {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
    }

    #[test]
    fn a_single_url_is_one_relay() {
        let relays = list("https://Relay-A.example/relay/");
        assert_eq!(relays.len(), 1);
        assert_eq!(relays[0].url(), A);
        // A comma not followed by `https://` is part of the path, as in 2.1.0; so is a `|`.
        for single in ["https://relay.example/a,b", "https://relay.example/a|70"] {
            let relays = list(single);
            assert_eq!(relays.len(), 1, "{single}");
            assert_eq!(relays[0].url(), single);
        }
    }

    #[test]
    fn a_list_names_relays_in_order_with_equal_shares() {
        let relays = list(&format!("{A},{B}/,https://relay-c.example/relay"));
        let got: Vec<&str> = relays.iter().map(Relay::url).collect();
        assert_eq!(got, [A, B, "https://relay-c.example/relay"]);
        assert!(relays.iter().all(|r| r.weight() == relays[0].weight()));
    }

    #[test]
    fn a_malformed_list_is_refused_naming_the_rule() {
        for (value, rule) in [
            (
                format!("{A},https://RELAY-A.example:443/relay/"),
                "must not list the same relay twice",
            ),
            (format!(",{A}"), "must be an https:// URL"),
            (format!("{A},https://"), "must have a non-empty host"),
            (
                format!("{A},https://relay-b.example/a b"),
                "must not contain whitespace or control characters",
            ),
            (format!("{A},,{B}"), "must not contain an empty list entry"),
        ] {
            assert_eq!(parse_relay_list(&value).err(), Some(rule), "{value}");
        }
        let nine: Vec<String> = (0..9)
            .map(|i| format!("https://relay-{i}.example/relay"))
            .collect();
        assert_eq!(
            parse_relay_list(&nine.join(",")).err(),
            Some("must not list more than 8 relays")
        );
        assert!(parse_relay_list(&nine[..8].join(",")).is_ok());
    }

    #[test]
    fn the_draw_splits_by_weight() {
        assert_eq!(pick(&[70, 30], 0), Some(0));
        assert_eq!(pick(&[70, 30], u64::MAX), Some(1));
        assert_eq!(pick(&[0, 30], 0), Some(1));
        assert_eq!(pick(&[30, 0], u64::MAX), Some(0));
        assert_eq!(pick(&[0, 0], 7), None);
        // The boundary: 70 % of the range picks the first relay, the rest the second.
        let boundary = ((70u128 << 64) / 100) as u64;
        assert_eq!(pick(&[70, 30], boundary - 1), Some(0));
        assert_eq!(pick(&[70, 30], boundary + 1), Some(1));
    }

    /// Over many draws the relays get their share of the weights.
    #[test]
    fn draws_spread_over_the_relays_in_proportion_to_the_weights() {
        let mut rng = SplitMix64(0x5eed_0001);
        for weights in [[70u32, 30, 0], [50, 50, 0], [10, 60, 30]] {
            let mut counts = [0u32; 3];
            let n = 200_000;
            for _ in 0..n {
                counts[pick(&weights, rng.next()).unwrap()] += 1;
            }
            for (i, &w) in weights.iter().enumerate() {
                let share = f64::from(counts[i]) / f64::from(n);
                let expected = f64::from(w) / 100.0;
                assert!(
                    (share - expected).abs() < 0.005,
                    "{weights:?}: relay {i} got {share}"
                );
            }
        }
    }

    /// Every request draws afresh: over many requests through one selector the relays get
    /// their share of the weights.
    #[test]
    fn requests_spread_over_the_relays_in_proportion_to_the_weights() {
        let relays = weighted(&[(A, 70), (B, 30)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let now = Instant::now();
        let mut rng = SplitMix64(0x5eed_0003);
        let n = 100_000;
        let to_b = (0..n)
            .filter(|_| selector.choose_with(&relays, rng.next(), now, &backoff) == 1)
            .count();
        let share = to_b as f64 / f64::from(n);
        assert!((share - 0.30).abs() < 0.005, "{share}");
        // The operating system's draws too (loose bound: not seeded).
        let to_b = (0..20_000)
            .filter(|_| selector.choose(&relays) == 1)
            .count();
        let share = to_b as f64 / 20_000.0;
        assert!((share - 0.30).abs() < 0.03, "{share}");
    }

    #[test]
    fn a_failed_relay_hands_over_to_the_next_until_its_hold_ends() {
        let relays = weighted(&[(A, 70), (B, 30)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let now = Instant::now();
        // Draw 0 picks the first relay.
        assert_eq!(selector.choose_with(&relays, 0, now, &backoff), 0);
        selector.note_failure_at(A, now);
        assert_eq!(selector.choose_with(&relays, 0, now, &backoff), 1);
        let later = now + RELAY_FAILOVER_HOLD - Duration::from_millis(1);
        assert_eq!(selector.choose_with(&relays, 0, later, &backoff), 1);
        let after = now + RELAY_FAILOVER_HOLD;
        assert_eq!(selector.choose_with(&relays, 0, after, &backoff), 0);
        // A success brings it back at once.
        selector.note_failure_at(A, now);
        selector.note_success(A);
        assert_eq!(selector.choose_with(&relays, 0, now, &backoff), 0);
        // Holding a relay out does not touch requests that drew the other one.
        selector.note_failure_at(A, now);
        assert_eq!(selector.choose_with(&relays, u64::MAX, now, &backoff), 1);
    }

    #[test]
    fn a_relay_pause_hands_over_too() {
        let relays = weighted(&[(A, 70), (B, 30)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let now = Instant::now();
        backoff.note_at(B, Duration::from_secs(10), now);
        assert_eq!(selector.choose_with(&relays, u64::MAX, now, &backoff), 0);
        let after = now + Duration::from_secs(10);
        assert_eq!(selector.choose_with(&relays, u64::MAX, after, &backoff), 1);
    }

    #[test]
    fn with_every_relay_out_the_drawn_relay_is_used() {
        let relays = weighted(&[(A, 70), (B, 30)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let now = Instant::now();
        selector.note_failure_at(A, now);
        selector.note_failure_at(B, now);
        assert_eq!(selector.choose_with(&relays, u64::MAX, now, &backoff), 1);
        assert_eq!(selector.choose_with(&relays, 0, now, &backoff), 0);
    }

    #[test]
    fn a_relay_of_weight_zero_is_only_a_fallback() {
        let relays = weighted(&[(A, 0), (B, 100)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let now = Instant::now();
        for draw in [0, 1 << 63, u64::MAX] {
            assert_eq!(selector.choose_with(&relays, draw, now, &backoff), 1);
        }
        selector.note_failure_at(B, now);
        assert_eq!(selector.choose_with(&relays, 0, now, &backoff), 0);
    }

    #[test]
    fn the_statuses_that_hold_a_relay_out() {
        for status in [
            301, 302, 307, 401, 403, 404, 405, 407, 421, 429, 500, 502, 503, 599,
        ] {
            assert!(relay_status_fails_over(status), "{status}");
        }
        for status in [200, 204, 400, 409, 413, 415, 422, 426] {
            assert!(!relay_status_fails_over(status), "{status}");
        }
    }

    #[test]
    fn the_failover_order_follows_the_weights() {
        assert_eq!(failover_order(&[10, 0, 60, 30], 0), [0, 2, 3, 1]);
        assert_eq!(failover_order(&[10, 0, 60, 30], 1), [1, 2, 3, 0]);
        assert_eq!(failover_order(&[50, 50], 1), [1, 0]);
    }

    #[test]
    fn a_hold_matches_any_spelling_of_the_relay_and_is_never_shortened() {
        let relays = weighted(&[(A, 70), (B, 30)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let now = Instant::now();
        selector.note_failure_at("https://RELAY-A.example:443/relay/", now);
        assert_eq!(selector.choose_with(&relays, 0, now, &backoff), 1);
        let later = now + Duration::from_secs(30);
        selector.note_failure_at(A, later);
        selector.note_failure_at(A, now);
        let end = later + RELAY_FAILOVER_HOLD - Duration::from_millis(1);
        assert_eq!(selector.choose_with(&relays, 0, end, &backoff), 1);
        selector.note_success_of("https://relay-a.EXAMPLE/relay", later);
        assert_eq!(selector.choose_with(&relays, 0, now, &backoff), 0);
    }

    #[test]
    fn the_hold_table_is_bounded() {
        let selector = RelaySelector::new();
        let now = Instant::now();
        for i in 0..(MAX_HELD_RELAYS + 10) {
            let at = now + Duration::from_millis(i as u64);
            selector.note_failure_at(&format!("https://relay-{i}.example/relay"), at);
        }
        assert_eq!(selector.state().held.len(), MAX_HELD_RELAYS);
        // The holds that end first were let go.
        assert!(selector.hold_of("https://relay-0.example/relay").is_none());
        assert!(selector
            .hold_of(&format!(
                "https://relay-{}.example/relay",
                MAX_HELD_RELAYS + 9
            ))
            .is_some());
    }

    #[test]
    fn an_alternative_is_the_next_available_relay_in_failover_order() {
        let relays = weighted(&[(A, 0), (B, 100), ("https://relay-c.example/relay", 50)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let now = Instant::now();
        assert_eq!(
            selector.alternative_with(&relays, 1, now, &backoff),
            Some(2)
        );
        selector.note_failure_at("https://relay-c.example/relay", now);
        assert_eq!(
            selector.alternative_with(&relays, 1, now, &backoff),
            Some(0)
        );
        backoff.note_at(A, Duration::from_secs(5), now);
        // C is only held: still offered, nothing having been sent.
        assert_eq!(
            selector.alternative_with(&relays, 1, now, &backoff),
            Some(2)
        );
        backoff.note_at("https://relay-c.example/relay", Duration::from_secs(5), now);
        assert_eq!(selector.alternative_with(&relays, 1, now, &backoff), None);
        assert_eq!(selector.alternative_with(&list(A), 0, now, &backoff), None);
    }

    #[test]
    fn the_fallback_draws_spread_too() {
        let n = 20_000;
        let high = (0..n).filter(|_| fallback_draw() >= 1 << 63).count();
        let share = high as f64 / f64::from(n);
        assert!((share - 0.5).abs() < 0.03, "{share}");
    }

    #[test]
    fn a_relay_that_keeps_failing_is_held_longer_each_time() {
        let relays = weighted(&[(A, 70), (B, 30)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let mut now = Instant::now();
        let mut hold = RELAY_FAILOVER_HOLD;
        for _ in 0..8 {
            selector.note_failure_at(A, now);
            let just_before = now + hold - Duration::from_millis(1);
            assert_eq!(selector.choose_with(&relays, 0, just_before, &backoff), 1);
            assert_eq!(selector.choose_with(&relays, 0, now + hold, &backoff), 0);
            // It fails again on its first request after the hold.
            now += hold;
            hold = (hold * 2).min(MAX_RELAY_FAILOVER_HOLD);
        }
        assert_eq!(hold, MAX_RELAY_FAILOVER_HOLD);
        // A success ends the doubling.
        selector.note_success_of(A, now);
        selector.note_failure_at(A, now);
        let after = now + RELAY_FAILOVER_HOLD;
        assert_eq!(selector.choose_with(&relays, 0, after, &backoff), 0);
        // So does a long quiet spell.
        let selector = RelaySelector::new();
        selector.note_failure_at(A, now);
        let quiet = now + 2 * RELAY_FAILOVER_HOLD;
        selector.note_failure_at(A, quiet);
        assert_eq!(
            selector.choose_with(&relays, 0, quiet + RELAY_FAILOVER_HOLD, &backoff),
            0
        );
    }

    #[test]
    fn with_every_relay_out_a_held_relay_goes_before_a_paused_one() {
        let relays = weighted(&[(A, 70), (B, 30)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let now = Instant::now();
        backoff.note_at(A, Duration::from_secs(10), now);
        selector.note_failure_at(B, now);
        assert_eq!(selector.choose_with(&relays, 0, now, &backoff), 1);
        // Both paused: the relay drawn.
        backoff.note_at(B, Duration::from_secs(10), now);
        assert_eq!(selector.choose_with(&relays, 0, now, &backoff), 0);
    }

    /// A configured list splits evenly.
    #[test]
    fn a_configured_list_splits_evenly() {
        let relays = list(&format!("{A},{B},https://relay-c.example/relay"));
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let now = Instant::now();
        let mut rng = SplitMix64(0x5eed_0005);
        let mut counts = [0u32; 3];
        let n = 90_000;
        for _ in 0..n {
            counts[selector.choose_with(&relays, rng.next(), now, &backoff)] += 1;
        }
        for count in counts {
            let share = f64::from(count) / f64::from(n);
            assert!((share - 1.0 / 3.0).abs() < 0.005, "{counts:?}");
        }
    }

    /// The client's sequence while the device is offline: each request draws a relay, fails
    /// to connect, moves to the other and fails again, every 90 s.
    #[test]
    fn a_failure_of_every_relay_is_not_held_against_one() {
        let relays = weighted(&[(A, 70), (B, 30)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let mut now = Instant::now();
        let mut rng = SplitMix64(0x5eed_0004);
        for _ in 0..20 {
            let first = selector.choose_with(&relays, rng.next(), now, &backoff);
            selector.note_failure_at(relays[first].url(), now);
            let other = selector.alternative_with(&relays, first, now, &backoff);
            selector.note_failure_at(relays[other.unwrap_or(1 - first)].url(), now);
            now += Duration::from_secs(90);
        }
        {
            for url in [A, B] {
                assert_eq!(
                    selector.hold_of(url).unwrap().hold,
                    RELAY_FAILOVER_HOLD,
                    "{url}"
                );
            }
        }
        // Back online: the first request fails on its relay (held, say A) and succeeds
        // through the other; that success clears every hold of the outage.
        selector.note_failure_at(A, now);
        let sent = now + Duration::from_millis(1);
        selector.note_success_of(B, sent);
        let to_a = (0..100)
            .filter(|i| selector.choose_with(&relays, i * (u64::MAX / 100), sent, &backoff) == 0)
            .count();
        assert!((69..=71).contains(&to_a), "{to_a}");
    }

    #[test]
    fn late_reports_change_nothing() {
        let relays = weighted(&[(A, 70), (B, 30)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let start = Instant::now();
        let failed = start + Duration::from_secs(1);
        selector.note_failure_at(A, failed);
        let until = selector.hold_of(A).unwrap().until;
        // A request sent before the failure succeeds late: the hold stays.
        selector.note_success_of(A, start);
        assert_eq!(selector.choose_with(&relays, 0, failed, &backoff), 1);
        // One sent before the failure fails late, inside the hold: the hold does not grow.
        selector.note_failure_with(A, start, failed + Duration::from_secs(50));
        assert_eq!(selector.hold_of(A).unwrap().until, until);
        // One sent while A was held fails after the hold: no new hold, no doubling.
        let after = until + Duration::from_secs(1);
        selector.note_failure_with(A, failed + Duration::from_secs(2), after);
        assert_eq!(selector.hold_of(A).unwrap().until, until);
        assert_eq!(selector.choose_with(&relays, 0, after, &backoff), 0);
        // A success through B, which never failed, releases nothing else.
        selector.note_failure_at(A, after);
        selector.note_success_of(B, after);
        assert_eq!(selector.choose_with(&relays, 0, after, &backoff), 1);
    }

    #[test]
    fn another_list_neither_releases_nor_shares_a_hold() {
        let main = weighted(&[(A, 70), (B, 30)]);
        let test = list("https://relay-c.example/relay,https://relay-d.example/relay");
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let now = Instant::now();
        selector.choose_with(&main, 0, now, &backoff);
        selector.choose_with(&test, 0, now, &backoff);
        selector.note_failure_at(A, now);
        selector.note_failure_at("https://relay-c.example/relay", now);
        selector.note_success_of("https://relay-c.example/relay", now);
        // A is still held: C belongs to another list.
        assert_eq!(selector.choose_with(&main, 0, now, &backoff), 1);
        // And A doubles when it fails again alone in its list.
        let again = now + RELAY_FAILOVER_HOLD;
        selector.note_failure_at("https://relay-c.example/relay", again);
        selector.note_failure_at(A, again);
        assert_eq!(selector.hold_of(A).unwrap().hold, RELAY_FAILOVER_HOLD * 2);
    }

    /// A failure of a request sent before the success that ended a hold is older news.
    #[test]
    fn a_late_failure_does_not_bring_back_a_hold_a_newer_success_ended() {
        let relays = weighted(&[(A, 70), (B, 30)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let start = Instant::now();
        selector.note_failure_at(A, start);
        let old = start + RELAY_FAILOVER_HOLD + Duration::from_secs(1);
        let newer = old + Duration::from_secs(1);
        selector.note_success_of(A, newer);
        // The request sent at `old` fails only now.
        selector.note_failure_with(A, old, newer + Duration::from_secs(10));
        assert_eq!(
            selector.choose_with(&relays, 0, newer + Duration::from_secs(10), &backoff),
            0
        );
        // A failure of a request sent after the success holds it again.
        let later = newer + Duration::from_secs(20);
        selector.note_failure_at(A, later);
        assert_eq!(selector.choose_with(&relays, 0, later, &backoff), 1);
    }

    /// A success of a request sent before a later failure that extended the hold does not end
    /// it, and an older failure does not extend it again.
    #[test]
    fn reports_older_than_the_latest_failure_change_nothing() {
        let relays = weighted(&[(A, 70), (B, 30)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let t0 = Instant::now();
        let s = |secs| t0 + Duration::from_secs(secs);
        selector.note_failure_at(A, t0);
        // Sent at 20 (every relay out, say), failing at 30: the hold runs from 30.
        selector.note_failure_with(A, s(20), s(30));
        let until = selector.hold_of(A).unwrap().until;
        assert_eq!(until, s(30) + RELAY_FAILOVER_HOLD);
        // A success of a request sent at 10 arrives at 40: older than the failure at 20.
        selector.note_success_of(A, s(10));
        assert_eq!(selector.choose_with(&relays, 0, s(40), &backoff), 1);
        // A failure of a request sent at 15 arrives at 50: older too, no extension.
        selector.note_failure_with(A, s(15), s(50));
        assert_eq!(selector.hold_of(A).unwrap().until, until);
    }

    /// When every relay is held, a request that could not reach the one it drew may still
    /// move to another that is only held (nothing was sent, a hold is advice).
    #[test]
    fn with_every_relay_held_an_alternative_is_still_offered() {
        let relays = weighted(&[(A, 50), (B, 50)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let now = Instant::now();
        selector.note_failure_at(A, now);
        selector.note_failure_at(B, now);
        assert_eq!(
            selector.alternative_with(&relays, 0, now, &backoff),
            Some(1)
        );
        backoff.note_at(B, Duration::from_secs(5), now);
        assert_eq!(selector.alternative_with(&relays, 0, now, &backoff), None);
    }

    /// On a relay that never failed, a success of a newer request makes a late failure of an
    /// older one older news.
    #[test]
    fn a_late_failure_after_a_newer_success_holds_nothing() {
        let relays = weighted(&[(A, 70), (B, 30)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let t0 = Instant::now();
        selector.note_success_of(A, t0 + Duration::from_secs(2));
        selector.note_failure_with(A, t0 + Duration::from_secs(1), t0 + Duration::from_secs(3));
        assert_eq!(
            selector.choose_with(&relays, 0, t0 + Duration::from_secs(3), &backoff),
            0
        );
    }

    /// A request sent before a failure that counted and reporting long after its hold was
    /// forgotten holds nothing.
    #[test]
    fn a_very_late_failure_after_a_forgotten_hold_holds_nothing() {
        let relays = weighted(&[(A, 70), (B, 30)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let t0 = Instant::now();
        selector.note_failure_at(A, t0 + Duration::from_secs(10));
        let much_later = t0 + Duration::from_secs(600);
        selector.note_failure_with(A, t0, much_later);
        assert_eq!(selector.choose_with(&relays, 0, much_later, &backoff), 0);
    }

    /// A request sent before a hold began and reporting after the hold was forgotten holds
    /// nothing either.
    #[test]
    fn a_failure_sent_before_a_forgotten_hold_began_holds_nothing() {
        let relays = weighted(&[(A, 70), (B, 30)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let t0 = Instant::now();
        // Sent at 0, failing at 10: the hold begins at 10.
        selector.note_failure_with(A, t0, t0 + Duration::from_secs(10));
        // Sent at 5, reporting at 200, long after the hold was forgotten.
        let late = t0 + Duration::from_secs(200);
        selector.note_failure_with(A, t0 + Duration::from_secs(5), late);
        assert_eq!(selector.choose_with(&relays, 0, late, &backoff), 0);
    }

    /// After a hold, one request goes to the relay as a probe; the others keep going elsewhere
    /// until it reports (or the probe window passes).
    #[test]
    fn after_a_hold_one_probe_goes_through_at_a_time() {
        let relays = weighted(&[(A, 70), (B, 30)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let t0 = Instant::now();
        selector.note_failure_at(A, t0);
        let after = t0 + RELAY_FAILOVER_HOLD;
        assert_eq!(
            selector.choose_with(&relays, 0, after, &backoff),
            0,
            "the probe"
        );
        assert_eq!(selector.choose_with(&relays, 0, after, &backoff), 1);
        // The probe hangs: after the window another probe goes.
        let later = after + RELAY_PROBE_WINDOW;
        assert_eq!(selector.choose_with(&relays, 0, later, &backoff), 0);
        assert_eq!(selector.choose_with(&relays, 0, later, &backoff), 1);
        // The probe succeeds: the relay is back for everyone.
        selector.note_success_of(A, later);
        assert_eq!(selector.choose_with(&relays, 0, later, &backoff), 0);
        assert_eq!(selector.choose_with(&relays, 0, later, &backoff), 0);
        // A failing probe holds it again, twice as long.
        let selector = RelaySelector::new();
        selector.note_failure_at(A, t0);
        assert_eq!(selector.choose_with(&relays, 0, after, &backoff), 0);
        selector.note_failure_at(A, after);
        assert_eq!(selector.hold_of(A).unwrap().hold, RELAY_FAILOVER_HOLD * 2);
    }

    /// A relay that answers some requests and hangs others: each hung request reports after a
    /// later one succeeded, but enough of them hold the relay after all.
    #[test]
    fn a_relay_that_hangs_some_requests_is_held_after_enough_of_them() {
        let relays = weighted(&[(A, 70), (B, 30)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let t0 = Instant::now();
        let s = |secs| t0 + Duration::from_secs(secs);
        for round in 0..MASKED_FAILURES_TO_HOLD as u64 {
            let sent = s(round * 40);
            // A request sent a little later succeeds quickly...
            selector.note_success_of(A, sent + Duration::from_secs(1));
            // ...and the earlier one fails at its timeout, 30 s on.
            selector.note_failure_with(A, sent, sent + Duration::from_secs(30));
            let at = sent + Duration::from_secs(30);
            let expected = if round + 1 < MASKED_FAILURES_TO_HOLD as u64 {
                0
            } else {
                1
            };
            assert_eq!(
                selector.choose_with(&relays, 0, at, &backoff),
                expected,
                "{round}"
            );
        }
    }

    /// The masked-failure window rolls: three set-aside failures close together count even if
    /// an earlier one began a window that has since run out.
    #[test]
    fn the_masked_failure_window_rolls() {
        let relays = weighted(&[(A, 70), (B, 30)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let t0 = Instant::now();
        let s = |secs| t0 + Duration::from_secs(secs);
        // A success at 1000 makes every failure of an earlier request older news.
        selector.note_success_of(A, s(1_000));
        for at in [0u64, 299, 301] {
            selector.note_failure_with(A, s(10), s(1_000 + at));
            assert_eq!(
                selector.choose_with(&relays, 0, s(1_000 + at), &backoff),
                0,
                "{at}"
            );
        }
        selector.note_failure_with(A, s(10), s(1_302));
        assert_eq!(selector.choose_with(&relays, 0, s(1_302), &backoff), 1);
    }

    /// The fallback that ignores holds (every relay out) leaves a relay with a probe out alone.
    #[test]
    fn the_fallback_does_not_flood_a_relay_with_a_probe_out() {
        let relays = weighted(&[(A, 70), (B, 30)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let t0 = Instant::now();
        selector.note_failure_at(A, t0);
        let after = t0 + RELAY_FAILOVER_HOLD;
        assert_eq!(
            selector.choose_with(&relays, 0, after, &backoff),
            0,
            "the probe"
        );
        backoff.note_at(B, Duration::from_secs(10), after);
        // A has its probe out, B is paused: the choice is B (the request fails locally on its
        // pause, nothing is posted), never A again.
        let pauses = Pauses {
            backoff: &backoff,
            eligible: None,
        };
        assert!(!selector.unpaused(&relays, 0, after, &pauses));
        for draw in [0, u64::MAX] {
            assert_eq!(selector.choose_with(&relays, draw, after, &backoff), 1);
        }
    }

    /// A probe let through just before the hold is forgotten still keeps the others away, and
    /// pruning by another relay's failure does not drop it.
    #[test]
    fn a_probe_outlives_the_memory_of_its_hold() {
        let relays = weighted(&[(A, 70), (B, 30)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let t0 = Instant::now();
        selector.note_failure_at(A, t0);
        // Remembered until t0 + 120 s; the probe goes at 119 s.
        let probe_at = t0 + 2 * RELAY_FAILOVER_HOLD - Duration::from_secs(1);
        assert_eq!(selector.choose_with(&relays, 0, probe_at, &backoff), 0);
        let later = probe_at + Duration::from_secs(5);
        // B fails, pruning old entries; A's probe is still out.
        selector.note_failure_at(B, later);
        assert_eq!(selector.choose_with(&relays, 0, later, &backoff), 1);
        assert!(selector.probing(&held_key(A), later));
    }

    /// A relay the caller cannot send to is passed over, and never let through as a probe.
    #[test]
    fn an_ineligible_relay_is_passed_over_and_never_probed() {
        let relays = weighted(&[(A, 70), (B, 30)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let t0 = Instant::now();
        let not_a = |url: &str| url != A;
        assert_eq!(
            selector.choose_index_where(&relays, 0, t0, &backoff, &not_a),
            Some(1)
        );
        // After A's hold, a draw that would make it the probe passes it over instead...
        selector.note_failure_at(A, t0);
        let after = t0 + RELAY_FAILOVER_HOLD;
        assert_eq!(
            selector.choose_index_where(&relays, 0, after, &backoff, &not_a),
            Some(1)
        );
        // ...so the probe is still there for a request that can go to A.
        assert_eq!(selector.choose_with(&relays, 0, after, &backoff), 0);
    }

    /// A probe answered with a refusal about the request ends, neither success nor failure:
    /// the next request probes again, the hold stays as it was. An answer that is no probe's
    /// ends nothing.
    #[test]
    fn an_answered_probe_ends_and_the_next_request_probes() {
        let relays = weighted(&[(A, 70), (B, 30)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let t0 = Instant::now();
        selector.note_failure_at(A, t0);
        let after = t0 + RELAY_FAILOVER_HOLD;
        let (chosen, probe) = selector.choose_probe_with(&relays, 0, after, &backoff);
        assert_eq!(chosen, 0, "the probe");
        assert!(probe.is_probe());
        assert_eq!(selector.choose_with(&relays, 0, after, &backoff), 1);
        // A request that was no probe does not end it.
        selector.note_answered_of(A, RelayProbe::NONE);
        assert_eq!(selector.choose_with(&relays, 0, after, &backoff), 1);
        // The probe's own answer does (any spelling of the relay).
        selector.note_answered_of("https://RELAY-A.example/relay/", probe);
        let (chosen, again) = selector.choose_probe_with(&relays, 0, after, &backoff);
        assert_eq!(chosen, 0, "probe again");
        assert!(again.is_probe());
        assert_ne!(again, probe);
        assert_eq!(selector.choose_with(&relays, 0, after, &backoff), 1);
        assert_eq!(selector.hold_of(A).unwrap().hold, RELAY_FAILOVER_HOLD);
    }

    /// A request chosen as a probe but sent only after a replacement probe began reports for
    /// a probe that is no longer current: its answer or success never ends the newer probe nor
    /// the hold, its failure counts as a failure (the relay is held again, a probe that hangs
    /// past the window included) without ending the newer probe; the replacement's own report
    /// still counts.
    #[test]
    fn a_late_report_never_ends_a_newer_probe() {
        let relays = weighted(&[(A, 70), (B, 30)]);
        let t0 = Instant::now();
        let after = t0 + RELAY_FAILOVER_HOLD;
        let replaced = after + RELAY_PROBE_WINDOW;
        let late = replaced + Duration::from_secs(1);
        // Each kind of late report, against a fresh selector.
        for kind in ["answered", "success", "failure"] {
            let selector = RelaySelector::new();
            let backoff = RelayBackoff::new();
            selector.note_failure_at(A, t0);
            let (_, first) = selector.choose_probe_with(&relays, 0, after, &backoff);
            let (chosen, second) = selector.choose_probe_with(&relays, 0, replaced, &backoff);
            assert_eq!(chosen, 0, "{kind}: the replacement");
            assert!(first.is_probe() && second.is_probe() && first != second);
            // The first probe reports only now (sent at its choice, or late).
            match kind {
                "answered" => selector.note_answered_of(A, first),
                "success" => selector.note_success_of_probe(A, late, first),
                _ => selector.note_failure_of_probe_with(A, after, late, first),
            }
            // The replacement is still the relay's probe, and no further request goes to A.
            assert!(selector.is_current(A, second), "{kind}");
            assert!(!selector.is_current(A, first), "{kind}");
            assert_eq!(
                selector.choose_with(&relays, 0, late, &backoff),
                1,
                "{kind}"
            );
            let hold = selector.hold_of(A).unwrap().hold;
            if kind == "failure" {
                // The probe that hung past the window failed: held again, twice as long.
                assert_eq!(hold, 2 * RELAY_FAILOVER_HOLD, "{kind}");
            } else {
                assert_eq!(hold, RELAY_FAILOVER_HOLD, "{kind}");
                assert!(selector.probing(&held_key(A), late), "{kind}");
            }
            // The replacement's own report counts.
            match kind {
                "answered" => {
                    selector.note_answered_of(A, second);
                    assert_eq!(
                        selector.choose_with(&relays, 0, late, &backoff),
                        0,
                        "{kind}"
                    );
                }
                "success" => {
                    selector.note_success_of_probe(A, late, second);
                    assert!(selector.hold_of(A).is_none(), "{kind}");
                }
                _ => {
                    selector.note_failure_probe_at(A, late, second);
                    assert!(!selector.is_current(A, second), "{kind}");
                    assert_eq!(
                        selector.hold_of(A).unwrap().hold,
                        2 * RELAY_FAILOVER_HOLD,
                        "{kind}"
                    );
                }
            }
        }
    }

    /// A probe value no relay has, or one of another relay, never ends a probe; nor does a
    /// retired one (its probe ended), after a new hold and a new probe either.
    #[test]
    fn a_stale_probe_value_is_ignored() {
        let relays = weighted(&[(A, 50), (B, 50)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let t0 = Instant::now();
        selector.note_failure_at(A, t0);
        selector.note_failure_at(B, t0 + Duration::from_secs(1));
        // A's hold has ended, B's still runs.
        let after = t0 + RELAY_FAILOVER_HOLD + Duration::from_millis(500);
        let (chosen, a_probe) = selector.choose_probe_with(&relays, 0, after, &backoff);
        assert_eq!(chosen, 0);
        // Unknown values, and B's success with A's probe: A's probe stays, so does its hold.
        for raw in [a_probe.to_raw() + 1, u64::MAX] {
            let stale = RelayProbe::from_raw(raw);
            selector.note_answered_of(A, stale);
            selector.note_success_of_probe(A, after, stale);
        }
        selector.note_success_of_probe(B, after, a_probe);
        assert!(selector.is_current(A, a_probe));
        assert!(selector.probing(&held_key(A), after));
        assert_eq!(selector.hold_of(A).unwrap().hold, RELAY_FAILOVER_HOLD);
        assert!(selector.hold_of(B).is_some());
        // A report without a probe still counts as before: A answers, its hold ends.
        selector.note_success_of(A, after);
        assert!(selector.hold_of(A).is_none());
        assert!(!selector.is_current(A, a_probe));
        // A fails anew, and after that hold a new probe goes: the retired value ends nothing.
        let again = after + Duration::from_secs(1);
        selector.note_failure_at(A, again);
        let next = again + RELAY_FAILOVER_HOLD;
        let (chosen, b_probe) = selector.choose_probe_with(&relays, 0, next, &backoff);
        assert_eq!(chosen, 0);
        assert!(b_probe.is_probe() && b_probe != a_probe);
        selector.note_answered_of(A, a_probe);
        selector.note_success_of_probe(A, next, a_probe);
        assert!(selector.is_current(A, b_probe));
        assert!(selector.probing(&held_key(A), next));
        assert_eq!(RelayProbe::from_raw(0), RelayProbe::NONE);
        assert!(!RelayProbe::default().is_probe());
    }

    /// When a shared outage ends by another relay's success, a relay of the list with its
    /// probe out keeps it: that probe's own report decides.
    #[test]
    fn a_probe_out_outlives_the_end_of_its_outage() {
        let relays = weighted(&[(A, 50), (B, 50)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let t0 = Instant::now();
        selector.choose_with(&relays, 0, t0, &backoff);
        selector.note_failure_at(A, t0);
        selector.note_failure_at(B, t0);
        let after = t0 + RELAY_FAILOVER_HOLD;
        let (chosen, a_probe) = selector.choose_probe_with(&relays, 0, after, &backoff);
        assert_eq!(chosen, 0);
        let (chosen, b_probe) = selector.choose_probe_with(&relays, 0, after, &backoff);
        assert_eq!(chosen, 1);
        // B's probe answers: B's hold ends, A's probe is still out.
        selector.note_success_of_probe(B, after, b_probe);
        assert!(selector.hold_of(B).is_none());
        assert!(selector.is_current(A, a_probe));
        assert!(selector.probing(&held_key(A), after));
        assert_eq!(selector.choose_with(&relays, 0, after, &backoff), 1);
        // A's probe answers: A is back.
        selector.note_success_of_probe(A, after, a_probe);
        assert!(selector.hold_of(A).is_none());
        assert_eq!(selector.choose_with(&relays, 0, after, &backoff), 0);
    }

    /// A probe chosen first but sent after its replacement, failing first: the replacement
    /// is still out (and still keeps fallback requests away while the relay is held again),
    /// and its own report, whatever it is, ends it.
    #[test]
    fn a_late_sent_stale_failure_leaves_the_replacement_to_its_own_report() {
        let relays = weighted(&[(A, 50), (B, 50)]);
        let t0 = Instant::now();
        let s = |secs: u64| t0 + Duration::from_secs(secs);
        for kind in ["answered", "success", "failure"] {
            let selector = RelaySelector::new();
            let backoff = RelayBackoff::new();
            selector.note_failure_at(A, t0);
            // P1 chosen at 60 s, P2 at 90 s and sent at once; P1 sent only at 92 s.
            let (_, p1) = selector.choose_probe_with(&relays, 0, s(60), &backoff);
            let (chosen, p2) = selector.choose_probe_with(&relays, 0, s(90), &backoff);
            assert_eq!(chosen, 0, "{kind}");
            selector.note_failure_of_probe_with(A, s(92), s(95), p1);
            assert!(
                selector.hold_of(A).unwrap().until > s(95),
                "{kind}: held again"
            );
            assert!(selector.is_current(A, p2), "{kind}");
            // B paused, only A eligible: nothing goes to A while P2 is out.
            backoff.note_at(B, Duration::from_secs(60), s(96));
            assert_eq!(
                selector.choose_index_where(&relays, 0, s(96), &backoff, &|url| url == A),
                None,
                "{kind}"
            );
            // P2 reports (sent at 90 s, before the new hold began): it ends all the same.
            match kind {
                "answered" => selector.note_answered_of(A, p2),
                "success" => selector.note_success_of_probe(A, s(90), p2),
                _ => selector.note_failure_of_probe_with(A, s(90), s(97), p2),
            }
            assert!(!selector.is_current(A, p2), "{kind}");
            assert!(!selector.probing(&held_key(A), s(97)), "{kind}");
        }
    }

    /// The one case where a request that is no probe goes to a relay with its probe out: a
    /// choice with no criterion when every relay has one. Its success ends that relay's hold
    /// (the relay answered), and the displaced probe's later report is a stale one.
    #[test]
    fn with_every_relay_probing_a_choice_without_criterion_still_sends() {
        let relays = weighted(&[(A, 50), (B, 50)]);
        let t0 = Instant::now();
        let after = t0 + RELAY_FAILOVER_HOLD;
        for kind in ["success", "failure"] {
            let selector = RelaySelector::new();
            let backoff = RelayBackoff::new();
            selector.choose_with(&relays, 0, t0, &backoff);
            selector.note_failure_at(A, t0);
            selector.note_failure_at(B, t0);
            let (_, a_probe) = selector.choose_probe_with(&relays, 0, after, &backoff);
            let (_, b_probe) = selector.choose_probe_with(&relays, 0, after, &backoff);
            assert!(selector.is_current(A, a_probe) && selector.is_current(B, b_probe));
            // With a criterion: nothing. Without: the relay drawn, as no probe.
            assert_eq!(
                selector.choose_index_where(&relays, 0, after, &backoff, &|_| true),
                None
            );
            let (chosen, none) = selector.choose_probe_with(&relays, 0, after, &backoff);
            assert_eq!((chosen, none), (0, RelayProbe::NONE));
            // Its success ends A's hold, and A's probe with it; B's probe stays out.
            let sent = after + Duration::from_secs(1);
            selector.note_success_of(A, sent);
            assert!(selector.hold_of(A).is_none());
            assert!(!selector.is_current(A, a_probe));
            assert!(selector.is_current(B, b_probe));
            // The displaced probe reports late (sent before that success): older news.
            match kind {
                "success" => selector.note_success_of_probe(A, after, a_probe),
                _ => selector.note_failure_of_probe_with(A, after, sent, a_probe),
            }
            assert!(selector.hold_of(A).is_none(), "{kind}");
            assert_eq!(
                selector.choose_with(&relays, 0, sent, &backoff),
                0,
                "{kind}"
            );
        }
    }

    /// With the caller's criterion: an eligible relay with its probe out is never returned,
    /// nor an ineligible one; an eligible relay paused by `Retry-After` may be.
    #[test]
    fn a_choice_where_returns_only_an_eligible_relay_without_a_probe_out() {
        let relays = weighted(&[(A, 50), (B, 50)]);
        let only_a = |url: &str| url == A;
        let t0 = Instant::now();
        // A has its probe out, B is ineligible: nothing.
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        selector.note_failure_at(A, t0);
        let after = t0 + RELAY_FAILOVER_HOLD;
        assert_eq!(
            selector.choose_with(&relays, 0, after, &backoff),
            0,
            "the probe"
        );
        for draw in [0, u64::MAX / 2, u64::MAX] {
            assert_eq!(
                selector.choose_index_where(&relays, draw, after, &backoff, &only_a),
                None
            );
        }
        // A is paused, B is ineligible: A, whatever the draw (the pause then fails it).
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        backoff.note_at(A, Duration::from_secs(60), t0);
        for draw in [0, u64::MAX / 2, u64::MAX] {
            assert_eq!(
                selector.choose_index_where(&relays, draw, t0, &backoff, &only_a),
                Some(0)
            );
        }
    }

    /// The criterion is asked once per relay and choice, whatever it answers next.
    #[test]
    fn the_criterion_is_asked_once_per_relay() {
        let relays = weighted(&[(A, 50), (B, 50)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let t0 = Instant::now();
        selector.note_failure_at(A, t0);
        let after = t0 + RELAY_FAILOVER_HOLD;
        let asked = std::cell::Cell::new(0u32);
        // True the first time for each relay, false afterwards.
        let flips = |_: &str| {
            asked.set(asked.get() + 1);
            asked.get() <= 2
        };
        let (chosen, probe) = selector
            .choose_with_where(&relays, 0, after, &backoff, &flips)
            .unwrap();
        assert_eq!(chosen, 0);
        assert!(probe.is_probe());
        assert_eq!(asked.get(), 2);
        assert!(selector.probing(&held_key(A), after));
    }

    /// A relay the caller passes over takes no part in its list's outage: being passed over
    /// fails nothing, and a success of the other relay clears the hold it had from the same
    /// outage.
    #[test]
    fn an_ineligible_relay_takes_no_part_in_an_outage() {
        let relays = weighted(&[(A, 50), (B, 50)]);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let t0 = Instant::now();
        let not_a = |url: &str| url != A;
        selector.choose_with(&relays, 0, t0, &backoff);
        // Both fail together (the device was offline).
        selector.note_failure_at(A, t0);
        selector.note_failure_at(B, t0);
        let later = t0 + Duration::from_secs(1);
        for draw in [0, u64::MAX] {
            assert_eq!(
                selector.choose_index_where(&relays, draw, later, &backoff, &not_a),
                Some(1),
                "B, held but eligible"
            );
        }
        assert_eq!(selector.hold_of(A).unwrap().hold, RELAY_FAILOVER_HOLD);
        // B answers: the outage is over for A too.
        selector.note_success_of(B, later);
        assert!(selector.hold_of(A).is_none());
        assert_eq!(selector.choose_with(&relays, 0, later, &backoff), 0);
    }

    #[test]
    fn the_statuses_that_answer_about_the_request() {
        for status in [400, 409, 413, 415, 422, 426] {
            assert!(relay_status_answered(status), "{status}");
            assert!(!relay_status_fails_over(status), "{status}");
        }
        for status in [200, 204, 301, 401, 403, 404, 405, 407, 421, 429, 500, 503] {
            assert!(!relay_status_answered(status), "{status}");
        }
    }

    #[test]
    fn a_single_relay_is_always_chosen() {
        let relays = list(A);
        let selector = RelaySelector::new();
        selector.note_failure(A);
        assert_eq!(selector.choose(&relays), 0);
    }

    #[test]
    fn the_debug_output_shows_no_url() {
        let relays = weighted(&[(A, 70), (B, 30)]);
        let shown = format!("{relays:?}");
        assert!(!shown.contains("example"), "{shown}");
        let selector = RelaySelector::new();
        selector.note_failure(A);
        let shown = format!("{selector:?}");
        assert!(!shown.contains("example"), "{shown}");
    }
}

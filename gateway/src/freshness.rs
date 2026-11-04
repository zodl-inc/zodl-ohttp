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

//! Request freshness: the inner request carries the Client's estimate of the Gateway's clock
//! (`ohttp-freshness: <unix seconds>`), and the Gateway (with `REPLAY_FRESHNESS=enforce`)
//! refuses requests outside
//! `REPLAY_FRESHNESS_WINDOW_SECS` of its own clock. Together with the replay store (nonces kept
//! for `REPLAY_TTL_SECS`, at least twice the window) an encapsulated request can be executed at
//! most once, whenever it is replayed: inside the window the nonce is still held, outside it the
//! timestamp is refused. Without it a ciphertext captured today could be replayed after its
//! nonce expired for as long as the HPKE key stays valid.
//!
//! Every inner response carries `ohttp-server-time: <unix seconds>` (sealed to the Client, so it
//! cannot be forged on the path); the Client keeps its offset to that clock and stamps requests
//! with it, so a device with a wrong clock still produces fresh timestamps after one response.
//!
//! - `REPLAY_FRESHNESS` (default `observe`): `off` ignores the header; `observe` counts
//!   missing/stale requests (`ohttp_freshness_total`) but serves them, for the transition while
//!   older Clients without the header are still in use; `enforce` refuses a missing or stale
//!   timestamp with an inner 400 carrying `ohttp-freshness: rejected` (the Client learns the
//!   offset from that response and retries).
//! - `REPLAY_FRESHNESS_WINDOW_SECS` (default 300): accepted distance from the Gateway clock, in
//!   either direction. Must be at most half of `REPLAY_TTL_SECS`.

use std::fmt;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// Inner request header with the Client's estimate of the Gateway clock (Unix seconds).
pub const REQUEST_HEADER: &str = "ohttp-freshness";
/// Inner response header with the Gateway clock (Unix seconds), on every response.
pub const SERVER_TIME_HEADER: &str = "ohttp-server-time";
/// Value of `REQUEST_HEADER` on the inner 400 of a refused request.
pub const REJECTED: &str = "rejected";

pub const DEFAULT_WINDOW_SECS: u64 = 300;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    Off,
    #[default]
    Observe,
    Enforce,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Mode::Off => "off",
            Mode::Observe => "observe",
            Mode::Enforce => "enforce",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub mode: Mode,
    pub window_secs: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: Mode::Observe,
            window_secs: DEFAULT_WINDOW_SECS,
        }
    }
}

impl Settings {
    pub fn from_env(replay_ttl_secs: u64) -> anyhow::Result<Self> {
        Self::parse(
            std::env::var("REPLAY_FRESHNESS").ok().as_deref(),
            std::env::var("REPLAY_FRESHNESS_WINDOW_SECS")
                .ok()
                .as_deref(),
            replay_ttl_secs,
        )
    }

    pub fn parse(
        mode: Option<&str>,
        window: Option<&str>,
        replay_ttl_secs: u64,
    ) -> anyhow::Result<Self> {
        let mode = match mode.map(|m| m.trim().to_ascii_lowercase()).as_deref() {
            None | Some("") | Some("observe") => Mode::Observe,
            Some("off") => Mode::Off,
            Some("enforce") => Mode::Enforce,
            Some(other) => {
                anyhow::bail!("REPLAY_FRESHNESS must be off, observe or enforce, got '{other}'")
            }
        };
        let window_secs = match window.map(str::trim).filter(|w| !w.is_empty()) {
            None => DEFAULT_WINDOW_SECS,
            Some(w) => match w.parse::<u64>() {
                Ok(v) if v > 0 => v,
                _ => anyhow::bail!(
                    "REPLAY_FRESHNESS_WINDOW_SECS must be a positive integer, got '{w}'"
                ),
            },
        };
        // A ciphertext is accepted within window_secs of its timestamp on either side; its nonce
        // must outlive that whole span, or it could be replayed late in the window.
        if window_secs * 2 > replay_ttl_secs {
            anyhow::bail!(
                "REPLAY_FRESHNESS_WINDOW_SECS ({window_secs}) must be at most half of the replay nonce TTL ({replay_ttl_secs} s)"
            );
        }
        Ok(Self { mode, window_secs })
    }
}

static SETTINGS: OnceLock<Settings> = OnceLock::new();

/// Set once at startup (main). Tests and callers before that see the default.
pub fn init(settings: Settings) {
    let _ = SETTINGS.set(settings);
}

pub fn settings() -> Settings {
    SETTINGS.get().copied().unwrap_or_default()
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Fresh,
    Missing,
    /// Present but unparsable.
    Malformed,
    /// Outside the window; the signed distance in seconds (request minus Gateway clock).
    Stale(i64),
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Fresh => "fresh",
            Verdict::Missing => "missing",
            Verdict::Malformed => "malformed",
            Verdict::Stale(_) => "stale",
        }
    }
}

/// Judge the inner request headers against the Gateway clock `now`.
pub fn check(headers: &[(String, String)], now: i64, window_secs: u64) -> Verdict {
    let Some((_, value)) = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(REQUEST_HEADER))
    else {
        return Verdict::Missing;
    };
    let Ok(ts) = value.trim().parse::<i64>() else {
        return Verdict::Malformed;
    };
    let delta = ts.saturating_sub(now);
    if delta.unsigned_abs() <= window_secs {
        Verdict::Fresh
    } else {
        Verdict::Stale(delta)
    }
}

/// Whether `verdict` refuses the request under `mode`.
pub fn refuses(mode: Mode, verdict: Verdict) -> bool {
    mode == Mode::Enforce && verdict != Verdict::Fresh
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(v: &str) -> Vec<(String, String)> {
        vec![
            ("content-type".into(), "application/grpc".into()),
            ("Ohttp-Freshness".into(), v.into()),
        ]
    }

    #[test]
    fn verdicts() {
        let now = 1_800_000_000;
        assert_eq!(check(&h("1800000000"), now, 300), Verdict::Fresh);
        assert_eq!(
            check(&h("1800000300"), now, 300),
            Verdict::Fresh,
            "edge of the window, future"
        );
        assert_eq!(
            check(&h("1799999700"), now, 300),
            Verdict::Fresh,
            "edge of the window, past"
        );
        assert_eq!(check(&h("1800000301"), now, 300), Verdict::Stale(301));
        assert_eq!(check(&h("1799999000"), now, 300), Verdict::Stale(-1000));
        assert_eq!(
            check(&h(" 1800000010 "), now, 300),
            Verdict::Fresh,
            "whitespace tolerated"
        );
        assert_eq!(check(&h("soon"), now, 300), Verdict::Malformed);
        assert_eq!(check(&h("1.8e9"), now, 300), Verdict::Malformed);
        assert_eq!(check(&[], now, 300), Verdict::Missing);
        assert_eq!(
            check(&h(&i64::MIN.to_string()), now, 300),
            Verdict::Stale(i64::MIN),
            "no overflow"
        );
    }

    #[test]
    fn modes() {
        for v in [Verdict::Missing, Verdict::Malformed, Verdict::Stale(1000)] {
            assert!(refuses(Mode::Enforce, v));
            assert!(!refuses(Mode::Observe, v));
            assert!(!refuses(Mode::Off, v));
        }
        assert!(!refuses(Mode::Enforce, Verdict::Fresh));
    }

    #[test]
    fn settings_parse() {
        assert_eq!(
            Settings::parse(None, None, 600).unwrap(),
            Settings::default()
        );
        assert_eq!(
            Settings::parse(Some("ENFORCE"), Some("120"), 600).unwrap(),
            Settings {
                mode: Mode::Enforce,
                window_secs: 120
            }
        );
        assert_eq!(
            Settings::parse(Some("off"), None, 600).unwrap().mode,
            Mode::Off
        );
        assert!(Settings::parse(Some("strict"), None, 600).is_err());
        assert!(Settings::parse(None, Some("0"), 600).is_err());
        assert!(
            Settings::parse(None, Some("301"), 600).is_err(),
            "window must be at most half the nonce TTL"
        );
        assert!(Settings::parse(None, Some("300"), 600).is_ok());
    }
}

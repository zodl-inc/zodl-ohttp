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

//! Upstream caps: the `REQUESTS/WINDOWs` grammar, `THIRD_PARTY_RATE_LIMITS`
//! (`authority=REQUESTS/WINDOWs,...`) and the fixed window that enforces a cap. The window
//! is told the time (`now`); the gateway keeps one per capped backend.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};

/// Parse one `REQUESTS/WINDOWs` cap (`120/60s`) of the variable `name`: both parts positive.
pub fn parse_rate_spec(name: &str, spec: &str) -> Result<(u64, Duration)> {
    let Some((requests, window)) = spec.split_once('/') else {
        bail!("Malformed {name}: '{spec}' must be 'REQUESTS/WINDOW'");
    };
    let requests = requests
        .trim()
        .parse::<u64>()
        .map_err(|_| anyhow!("Invalid {name} requests in '{spec}': must be a positive integer"))?;
    if requests == 0 {
        bail!("Invalid {name} requests in '{spec}': must be > 0");
    }
    let window = window.trim();
    let Some(secs) = window.strip_suffix('s') else {
        bail!("Invalid {name} window '{window}' in '{spec}': must end with 's' (e.g., '60s')");
    };
    let secs = secs.parse::<u64>().map_err(|_| {
        anyhow!("Invalid {name} window '{window}' in '{spec}': must be a positive integer followed by 's'")
    })?;
    if secs == 0 {
        bail!("Invalid {name} window '{window}' in '{spec}': must be > 0");
    }
    Ok((requests, Duration::from_secs(secs)))
}

/// Parse `THIRD_PARTY_RATE_LIMITS` (`authority=REQUESTS/WINDOW,...`, authorities lowercased; an
/// authority named twice keeps its last entry): authority -> (requests, window).
pub fn parse_rate_limits(s: &str) -> Result<HashMap<String, (u64, Duration)>> {
    let mut configs = HashMap::new();
    for entry in s.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((authority, limit_window)) = entry.split_once('=') else {
            bail!(
                "Malformed THIRD_PARTY_RATE_LIMITS: '{entry}' must be 'authority=REQUESTS/WINDOW'"
            );
        };
        let authority = authority.trim().to_ascii_lowercase();
        if authority.is_empty() {
            bail!("Malformed THIRD_PARTY_RATE_LIMITS: missing authority in '{entry}'");
        }
        let (requests, duration) = parse_rate_spec("THIRD_PARTY_RATE_LIMITS", limit_window)
            .map_err(|e| anyhow!("{e} (entry: '{entry}')"))?;
        configs.insert(authority, (requests, duration));
    }
    if configs.is_empty() {
        bail!("Malformed THIRD_PARTY_RATE_LIMITS: no entries");
    }
    Ok(configs)
}

/// Rate limit window: fixed window per backend.
#[derive(Debug)]
pub struct RateWindow {
    /// Window start time.
    window_start: Instant,
    /// Window duration.
    window_duration: Duration,
    /// Request count in the current window.
    count: u64,
    /// Max requests per window.
    limit: u64,
}

impl RateWindow {
    /// A window of `limit` requests per `window_duration`, starting at `now`.
    pub fn new(limit: u64, window_duration: Duration, now: Instant) -> Self {
        Self {
            window_start: now,
            window_duration,
            count: 0,
            limit,
        }
    }

    /// Check and increment at `now`. Returns Ok(()) if allowed, Err(retry_after_secs) if
    /// limited.
    pub fn check_and_increment(&mut self, now: Instant) -> Result<(), u64> {
        let elapsed = now.duration_since(self.window_start);

        // Reset window if expired
        if elapsed >= self.window_duration {
            self.window_start = now;
            self.count = 0;
        }

        if self.count >= self.limit {
            // Calculate seconds until window expires
            let remaining = self.window_duration.saturating_sub(elapsed);
            let retry_after_secs = remaining.as_secs().max(1);
            return Err(retry_after_secs);
        }

        self.count += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_specs() {
        assert_eq!(
            parse_rate_spec("V", " 120 / 60s ").unwrap(),
            (120, Duration::from_secs(60))
        );
        for (spec, expected) in [
            ("120", "must be 'REQUESTS/WINDOW'"),
            (
                "abc/60s",
                "requests in 'abc/60s': must be a positive integer",
            ),
            ("0/60s", "must be > 0"),
            ("1/60", "must end with 's'"),
            ("1/xs", "positive integer followed by 's'"),
            ("1/0s", "window '0s' in '1/0s': must be > 0"),
        ] {
            let text = parse_rate_spec("V", spec).unwrap_err().to_string();
            assert!(
                text.contains(expected) && text.contains("V"),
                "{spec}: {text}"
            );
        }
    }

    #[test]
    fn rate_limits() {
        let limits =
            parse_rate_limits("A.example=1/1s, b.example=600/60s,a.example=2/2s,").unwrap();
        assert_eq!(limits.len(), 2);
        assert_eq!(limits["a.example"], (2, Duration::from_secs(2)));
        assert_eq!(limits["b.example"], (600, Duration::from_secs(60)));
        for (raw, expected) in [
            ("", "no entries"),
            ("a.example", "must be 'authority=REQUESTS/WINDOW'"),
            ("=1/1s", "missing authority"),
            ("a.example=1/1", "(entry: 'a.example=1/1')"),
        ] {
            let text = parse_rate_limits(raw).unwrap_err().to_string();
            assert!(text.contains(expected), "{raw}: {text}");
        }
    }

    #[test]
    fn fixed_window() {
        let start = Instant::now();
        let at = |secs: u64| start + Duration::from_secs(secs);
        let mut window = RateWindow::new(2, Duration::from_secs(10), start);
        assert_eq!(window.check_and_increment(at(0)), Ok(()));
        assert_eq!(window.check_and_increment(at(1)), Ok(()));
        assert_eq!(window.check_and_increment(at(3)), Err(7));
        // Under a second left: retry after one.
        assert_eq!(
            window.check_and_increment(start + Duration::from_millis(9_500)),
            Err(1)
        );
        // A new window at its end.
        assert_eq!(window.check_and_increment(at(10)), Ok(()));
        assert_eq!(window.check_and_increment(at(11)), Ok(()));
        assert_eq!(window.check_and_increment(at(12)), Err(8));
    }
}

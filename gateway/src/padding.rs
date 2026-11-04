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

//! Response padding: whether the final chunk of a chunked OHTTP response is padded with zero
//! bytes up to `CHUNK_SIZE` (RFC 9292 §3.8). Non-final chunks are always exactly `CHUNK_SIZE`
//! bytes whatever the mode, so chunk boundaries never follow message (block) boundaries.
//!
//! Padding hides exact response sizes (the total is rounded up to a multiple of `CHUNK_SIZE`)
//! from the Relay and from observers of the Client–Relay link:
//! the total size of a `GetBlockRange` stream points at the heights requested (the wallet's
//! sync position), the size of a `GetTransaction` answer at the transaction fetched. Its cost
//! is latency: every response is at least one 16 KiB chunk, more than a TCP initial congestion
//! window, so on an idle long-haul connection a small answer needs a second round trip.
//!
//! - `RESPONSE_PADDING` (default `on`): `on` pads every response; `sensitive` leaves the small
//!   light client server answers in [`UNPADDED_PATHS`] unpadded (their method is already
//!   visible from the request size, and their size says nothing about the wallet) and pads the
//!   rest; `off` pads nothing.

use std::fmt;
use std::sync::OnceLock;

/// Inner paths left unpadded in `sensitive` mode. Anything not listed, including methods added
/// later and every other path, stays padded.
pub const UNPADDED_PATHS: &[&str] = &[
    "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock",
    "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLightdInfo",
    "/cash.z.wallet.sdk.rpc.CompactTxStreamer/SendTransaction",
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    On,
    Sensitive,
    Off,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Mode::On => "on",
            Mode::Sensitive => "sensitive",
            Mode::Off => "off",
        })
    }
}

impl Mode {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::parse(std::env::var("RESPONSE_PADDING").ok().as_deref())
    }

    pub fn parse(value: Option<&str>) -> anyhow::Result<Self> {
        match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
            None | Some("") | Some("on") => Ok(Mode::On),
            Some("sensitive") => Ok(Mode::Sensitive),
            Some("off") => Ok(Mode::Off),
            Some(other) => {
                anyhow::bail!("RESPONSE_PADDING must be on, sensitive or off, got '{other}'")
            }
        }
    }

    /// Whether the response to a request for `path` is padded. `None` is a request not
    /// parsed yet (a Binary HTTP parse failure): padded unless the mode is `off`.
    pub fn pads(self, path: Option<&str>) -> bool {
        match self {
            Mode::On => true,
            Mode::Off => false,
            Mode::Sensitive => !path.is_some_and(|p| UNPADDED_PATHS.contains(&p)),
        }
    }
}

static MODE: OnceLock<Mode> = OnceLock::new();

/// Set once at startup (main). Tests and callers before that see the default (`on`).
pub fn init(mode: Mode) {
    let _ = MODE.set(mode);
}

pub fn mode() -> Mode {
    MODE.get().copied().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_the_three_modes_and_defaults_to_on() {
        assert_eq!(Mode::parse(None).unwrap(), Mode::On);
        assert_eq!(Mode::parse(Some("")).unwrap(), Mode::On);
        assert_eq!(Mode::parse(Some(" ON ")).unwrap(), Mode::On);
        assert_eq!(Mode::parse(Some("sensitive")).unwrap(), Mode::Sensitive);
        assert_eq!(Mode::parse(Some("off")).unwrap(), Mode::Off);
        assert!(Mode::parse(Some("0")).is_err());
    }

    #[test]
    fn sensitive_pads_everything_but_the_listed_paths() {
        let small = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock";
        let range = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlockRange";
        assert!(!Mode::Sensitive.pads(Some(small)));
        assert!(Mode::Sensitive.pads(Some(range)));
        assert!(Mode::Sensitive.pads(Some("/v1/key/info")));
        assert!(Mode::Sensitive.pads(None));
        assert!(Mode::On.pads(Some(small)));
        assert!(!Mode::Off.pads(Some(range)));
        assert!(!Mode::Off.pads(None));
    }
}

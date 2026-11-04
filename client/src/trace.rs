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

//! The `X-Client-Trace-Id` a debug build puts on its posts to the relay, which lets a tester
//! follow one request through relay, gateway and backend logs.
//!
//! **Privacy:** a trace id makes a wallet's requests linkable across those logs. Whether to
//! send one at all (debug builds only) is the caller's decision; this only builds the value.

use std::sync::atomic::{AtomicU64, Ordering};

use rand_core::{OsRng, TryRngCore as _};

/// The longest trace id, in characters.
const MAX_LEN: usize = 64;

/// The shape of a trace id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceIdFormat {
    /// `<prefix>-<session uuid, lower case>-<sequence, six digits>`: one UUID per
    /// [`ClientTrace`], a counter per id (Android and Slipstream).
    SessionSequence,
    /// `<prefix>-<uuid, upper case>`: a fresh UUID per id (iOS).
    PerRequestUuidUpper,
}

/// How the caller's prefix is cleaned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrefixSanitization {
    /// Characters outside `[A-Za-z0-9._:-]` dropped, leading non-alphanumerics dropped, and
    /// `trace` if nothing is left (Android and Slipstream).
    Normalize,
    /// Characters outside `[A-Za-z0-9._:-]` dropped, nothing else: an empty result stays
    /// empty, a leading `.` stays (iOS).
    FilterOnly,
}

/// How trace ids are built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TracePolicy {
    /// The shape of an id.
    pub format: TraceIdFormat,
    /// How the prefix is cleaned.
    pub sanitization: PrefixSanitization,
}

impl TracePolicy {
    /// Android.
    pub const ANDROID: TracePolicy = TracePolicy {
        format: TraceIdFormat::SessionSequence,
        sanitization: PrefixSanitization::Normalize,
    };
    /// iOS.
    pub const IOS: TracePolicy = TracePolicy {
        format: TraceIdFormat::PerRequestUuidUpper,
        sanitization: PrefixSanitization::FilterOnly,
    };
    /// Slipstream.
    pub const SLIPSTREAM: TracePolicy = TracePolicy::ANDROID;
}

/// A trace-id generator.
pub struct ClientTrace {
    prefix: String,
    format: TraceIdFormat,
    session: String,
    counter: AtomicU64,
}

impl ClientTrace {
    /// A generator for `prefix` under `policy`; a `SessionSequence` one draws its UUID now.
    pub fn new(prefix: &str, policy: &TracePolicy) -> Self {
        let cleaned: String = prefix
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'))
            .collect();
        let prefix = match policy.sanitization {
            PrefixSanitization::FilterOnly => cleaned,
            PrefixSanitization::Normalize => {
                let trimmed = cleaned.trim_start_matches(|c: char| !c.is_ascii_alphanumeric());
                if trimmed.is_empty() {
                    "trace".to_string()
                } else {
                    trimmed.to_string()
                }
            }
        };
        ClientTrace {
            prefix,
            format: policy.format,
            session: match policy.format {
                TraceIdFormat::SessionSequence => uuid_v4(),
                TraceIdFormat::PerRequestUuidUpper => String::new(),
            },
            counter: AtomicU64::new(0),
        }
    }

    /// The next id, at most 64 characters.
    pub fn next(&self) -> String {
        let full = match self.format {
            TraceIdFormat::SessionSequence => {
                let seq = self.counter.fetch_add(1, Ordering::Relaxed);
                format!("{}-{}-{seq:06}", self.prefix, self.session)
            }
            TraceIdFormat::PerRequestUuidUpper => {
                format!("{}-{}", self.prefix, uuid_v4().to_uppercase())
            }
        };
        full.chars().take(MAX_LEN).collect()
    }
}

/// A random (version 4) UUID, lower case.
fn uuid_v4() -> String {
    // A trace id is a debug label, not a secret: if the random source fails the id is the
    // fixed UUID 00000000-0000-4000-8000-000000000000 rather than a panic.
    let mut b = [0u8; 16];
    if OsRng.try_fill_bytes(&mut b).is_err() {
        b = [0; 16];
    }
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn android_and_slipstream_ids_count_within_a_session() {
        let trace = ClientTrace::new("test-wallet", &TracePolicy::ANDROID);
        let (a, b) = (trace.next(), trace.next());
        assert!(a.starts_with("test-wallet-") && a.ends_with("-000000"));
        assert!(b.ends_with("-000001"));
        assert_eq!(a[12..a.len() - 7], b[12..b.len() - 7]);
        assert_eq!(a.len(), "test-wallet-".len() + 36 + "-000000".len());
        assert_eq!(a, a.to_lowercase());
    }

    #[test]
    fn ios_ids_are_a_fresh_upper_case_uuid_each() {
        let trace = ClientTrace::new("t", &TracePolicy::IOS);
        let (a, b) = (trace.next(), trace.next());
        assert_ne!(a, b);
        assert_eq!(a.len(), 2 + 36);
        assert_eq!(a, a.to_uppercase().replacen("T-", "t-", 1));
    }

    #[test]
    fn the_prefix_is_cleaned_as_each_client_does() {
        let id = |p: &str, policy: &TracePolicy| ClientTrace::new(p, policy).next();
        assert!(id("test@wallet#123", &TracePolicy::ANDROID).starts_with("testwallet123-"));
        assert!(id("___abc", &TracePolicy::ANDROID).starts_with("abc-"));
        assert!(id("", &TracePolicy::ANDROID).starts_with("trace-"));
        assert!(id("___", &TracePolicy::ANDROID).starts_with("trace-"));
        assert!(id("___abc", &TracePolicy::IOS).starts_with("___abc-"));
        assert!(id("", &TracePolicy::IOS).starts_with('-'));
    }

    #[test]
    fn an_id_is_at_most_64_characters() {
        let long = "a".repeat(60);
        assert_eq!(
            ClientTrace::new(&long, &TracePolicy::ANDROID).next().len(),
            64
        );
        assert_eq!(ClientTrace::new(&long, &TracePolicy::IOS).next().len(), 64);
    }
}

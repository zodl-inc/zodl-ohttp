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

//! Request freshness (the gateway's `REPLAY_FRESHNESS`).
//!
//! Every inner request carries `ohttp-freshness: <unix seconds>`, the Client's estimate of the
//! Gateway clock, and the Gateway refuses requests outside its window, so an encapsulated request
//! captured on the path cannot be replayed once its replay nonce has expired.
//!
//! The estimate is the local clock plus an offset learned from `ohttp-server-time`, which the
//! Gateway puts on every inner response. That header is inside the sealed response, so only the
//! Gateway can set it; a device whose clock is wrong produces fresh timestamps from its second
//! request on (its first one may be refused with `ohttp-freshness: rejected`, which also carries
//! the Gateway time). The offset is process-wide: it assumes every Gateway keeps its clock
//! synchronized (NTP).

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Inner request header: the Client's estimate of the Gateway clock, in Unix seconds.
pub const REQUEST_HEADER: &str = "ohttp-freshness";
/// Inner response header: the Gateway clock, in Unix seconds.
pub const SERVER_TIME_HEADER: &str = "ohttp-server-time";
/// Value of [`REQUEST_HEADER`] on an inner response that refused the request as stale.
pub const REJECTED: &str = "rejected";

/// Gateway clock minus local clock, seconds.
static OFFSET_SECS: AtomicI64 = AtomicI64::new(0);

fn local_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The timestamp to put in the next request.
pub fn request_timestamp() -> i64 {
    local_unix().saturating_add(OFFSET_SECS.load(Ordering::Relaxed))
}

/// The current offset (Gateway minus local clock), seconds.
pub fn clock_offset_secs() -> i64 {
    OFFSET_SECS.load(Ordering::Relaxed)
}

/// Learn the Gateway clock from an inner response's header fields (names compared without
/// case). Returns whether the fields carried it. Call it with authenticated (opened) fields only.
pub fn observe_response_headers<N: AsRef<[u8]>, V: AsRef<[u8]>>(headers: &[(N, V)]) -> bool {
    // The Gateway appends its own value last (and drops upstream copies): take the last one.
    let Some((_, value)) = headers.iter().rev().find(|(n, _)| {
        n.as_ref()
            .eq_ignore_ascii_case(SERVER_TIME_HEADER.as_bytes())
    }) else {
        return false;
    };
    let Some(server) = std::str::from_utf8(value.as_ref())
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
    else {
        return false;
    };
    OFFSET_SECS.store(server.saturating_sub(local_unix()), Ordering::Relaxed);
    true
}

/// Whether an inner response refused the request as stale (retry once: the offset is already
/// corrected from the same response).
pub fn is_rejection<N: AsRef<[u8]>, V: AsRef<[u8]>>(status: u16, headers: &[(N, V)]) -> bool {
    status == 400
        && headers.iter().any(|(n, v)| {
            n.as_ref().eq_ignore_ascii_case(REQUEST_HEADER.as_bytes())
                && v.as_ref().eq_ignore_ascii_case(REJECTED.as_bytes())
        })
}

#[cfg(test)]
pub(crate) fn set_offset_for_test(secs: i64) {
    OFFSET_SECS.store(secs, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    // One test touches the process-wide offset, so the assertions on it live together.
    #[test]
    fn offset_follows_the_gateway_clock() {
        let server = local_unix() + 3600;
        assert!(observe_response_headers(&[(
            "Ohttp-Server-Time",
            server.to_string()
        )]));
        let off = clock_offset_secs();
        assert!((3599..=3601).contains(&off), "offset {off}");
        let ts = request_timestamp();
        assert!((ts - server).abs() <= 1, "stamp {ts} vs gateway {server}");

        let later = local_unix() + 7200;
        assert!(observe_response_headers(&[
            (SERVER_TIME_HEADER, "1".to_string()),
            (SERVER_TIME_HEADER, later.to_string()),
        ]));
        assert!(
            (7199..=7201).contains(&clock_offset_secs()),
            "the last value wins"
        );
        assert!(observe_response_headers(&[(
            SERVER_TIME_HEADER,
            server.to_string()
        )]));

        assert!(!observe_response_headers(&[(
            "content-type",
            "application/grpc"
        )]));
        assert!(!observe_response_headers(&[(SERVER_TIME_HEADER, "noon")]));
        assert_eq!(
            clock_offset_secs(),
            off,
            "unusable headers leave the offset alone"
        );
        set_offset_for_test(0);
    }

    #[test]
    fn rejection_is_recognised() {
        assert!(is_rejection(400, &[("Ohttp-Freshness", "REJECTED")]));
        assert!(!is_rejection(200, &[(REQUEST_HEADER, REJECTED)]));
        assert!(!is_rejection(400, &[("content-type", "text/plain")]));
    }
}

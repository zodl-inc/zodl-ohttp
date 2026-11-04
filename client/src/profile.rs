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

//! One client's choices, in one value.
//!
//! The three wallet clients (Android, iOS, Slipstream) and this library's own `Client` agree
//! on the cryptography and differ in a dozen details around it. Each detail is an explicit
//! option of the function that has it; a [`ClientProfile`] is the bundle one client passes,
//! so that moving a client onto this crate keeps what it does, except where a preset notes a
//! deliberate change (size caps, cache handling, the static network binding).
//! `client/INTEGRATION.md` shows where each option is used.

use crate::bhttp_codec::{DecodeOptions, EncodeOptions};
use crate::encapsulation::KeySelection;
use crate::outer::{CachePolicy, Limits, OuterHeaders, OuterPolicy, SignedConfigUrlRule};
use crate::signed::{NetworkRule, SignedConfigPolicy};
use crate::trace::TracePolicy;

/// Every option of the sans-IO core, for one client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientProfile {
    /// [`crate::KeyConfig::select_with`].
    pub key_selection: KeySelection,
    /// [`crate::verify_signed_config`].
    pub signed_config: SignedConfigPolicy,
    /// How a gateway host picks the network, and so the pinned signing key.
    pub network_rule: NetworkRule,
    /// How the signed-configuration URL follows from the relay URL.
    pub signed_config_url: SignedConfigUrlRule,
    /// [`crate::encode_bhttp_request`] for the client's gRPC calls.
    pub encode: EncodeOptions,
    /// [`crate::decode_bhttp_response`].
    pub decode: DecodeOptions,
    /// [`crate::classify_outer_response`].
    pub outer: OuterPolicy,
    /// The client's own headers on the relay requests.
    pub headers: OuterHeaders,
    /// Byte limits.
    pub limits: Limits,
    /// Key-configuration cache rules.
    pub cache: CachePolicy,
    /// [`crate::ClientTrace`].
    pub trace: TracePolicy,
}

impl ClientProfile {
    /// The profile a foreign-function boundary names by number: 1 Android, 2 iOS,
    /// 3 Slipstream (gRPC), 4 Slipstream (`http_round_trip`), 5 the library's own `Client`.
    pub fn by_id(id: u32) -> Option<ClientProfile> {
        match id {
            1 => Some(Self::ANDROID),
            2 => Some(Self::IOS),
            3 => Some(Self::SLIPSTREAM),
            4 => Some(Self::SLIPSTREAM_HTTP),
            5 => Some(Self::LIBRARY),
            _ => None,
        }
    }

    /// What this crate's `Client` does. (It has no gateway-host rule: its caller names the
    /// network, so the Android rule, the strictest, stands in. Its outer status and media type
    /// checks are its own; see [`OuterPolicy::LIBRARY`].)
    pub const LIBRARY: ClientProfile = ClientProfile {
        key_selection: KeySelection::LIBRARY,
        signed_config: SignedConfigPolicy::LIBRARY,
        network_rule: NetworkRule::KnownHosts,
        signed_config_url: SignedConfigUrlRule::ReplaceRelaySuffix,
        encode: EncodeOptions::PRESERVE_FRESH,
        decode: DecodeOptions::HTTP_STATUS,
        outer: OuterPolicy::LIBRARY,
        headers: OuterHeaders::LIBRARY,
        limits: Limits::LIBRARY,
        cache: CachePolicy::LIBRARY,
        trace: TracePolicy::ANDROID,
    };
    /// What the Android SDK (`lightwallet-client-lib`) does today.
    pub const ANDROID: ClientProfile = ClientProfile {
        key_selection: KeySelection::ANDROID,
        signed_config: SignedConfigPolicy::ANDROID,
        network_rule: NetworkRule::KnownHosts,
        signed_config_url: SignedConfigUrlRule::TrimThenReplaceRelaySuffix,
        encode: EncodeOptions::LOWERCASE_FRESH,
        decode: DecodeOptions::ANY_STATUS,
        outer: OuterPolicy::ANDROID,
        headers: OuterHeaders::ANDROID,
        limits: Limits::ANDROID,
        cache: CachePolicy::ANDROID,
        trace: TracePolicy::ANDROID,
    };
    /// What the Swift SDK (`ZcashLightClientKit`) does today.
    pub const IOS: ClientProfile = ClientProfile {
        key_selection: KeySelection::IOS,
        signed_config: SignedConfigPolicy::IOS,
        network_rule: NetworkRule::KnownHosts,
        signed_config_url: SignedConfigUrlRule::ReplaceRelaySuffix,
        encode: EncodeOptions::LOWERCASE_FRESH,
        decode: DecodeOptions::ANY_STATUS,
        outer: OuterPolicy::IOS,
        headers: OuterHeaders::IOS,
        limits: Limits::IOS,
        cache: CachePolicy::IOS,
        trace: TracePolicy::IOS,
    };
    /// What Slipstream (`core/src/ohttp.rs`) does today, for its gRPC path.
    pub const SLIPSTREAM: ClientProfile = ClientProfile {
        key_selection: KeySelection::SLIPSTREAM,
        signed_config: SignedConfigPolicy::SLIPSTREAM,
        network_rule: NetworkRule::KnownHosts,
        signed_config_url: SignedConfigUrlRule::RelayHostRoot,
        encode: EncodeOptions::LOWERCASE_FRESH,
        decode: DecodeOptions::HTTP_STATUS,
        outer: OuterPolicy::SLIPSTREAM,
        headers: OuterHeaders::SLIPSTREAM,
        limits: Limits::SLIPSTREAM,
        cache: CachePolicy::SLIPSTREAM,
        trace: TracePolicy::SLIPSTREAM,
    };
    /// Slipstream's `http_round_trip` (non-gRPC requests): as [`ClientProfile::SLIPSTREAM`],
    /// header names written as given.
    pub const SLIPSTREAM_HTTP: ClientProfile = ClientProfile {
        encode: EncodeOptions::PRESERVE_FRESH,
        ..ClientProfile::SLIPSTREAM
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_are_named_by_number() {
        assert_eq!(ClientProfile::by_id(1), Some(ClientProfile::ANDROID));
        assert_eq!(ClientProfile::by_id(2), Some(ClientProfile::IOS));
        assert_eq!(ClientProfile::by_id(3), Some(ClientProfile::SLIPSTREAM));
        assert_eq!(
            ClientProfile::by_id(4),
            Some(ClientProfile::SLIPSTREAM_HTTP)
        );
        assert_eq!(ClientProfile::by_id(5), Some(ClientProfile::LIBRARY));
        for id in [0, 6, 255, u32::MAX] {
            assert_eq!(ClientProfile::by_id(id), None);
        }
    }

    #[test]
    fn every_preset_agrees_on_the_decided_rules() {
        for profile in [
            ClientProfile::LIBRARY,
            ClientProfile::ANDROID,
            ClientProfile::IOS,
            ClientProfile::SLIPSTREAM,
            ClientProfile::SLIPSTREAM_HTTP,
        ] {
            // Unknown envelope fields are ignored, every response is capped at the gateway's
            // size, and at most 4096 configurations are read.
            assert_eq!(
                profile.signed_config.unknown_fields,
                crate::UnknownFields::Ignore
            );
            assert_eq!(
                profile.limits.max_sealed_response_bytes,
                Some(crate::GATEWAY_MAX_SEALED_RESPONSE_BYTES)
            );
            assert_eq!(profile.key_selection.max_configs, 4096);
            // The ZIP's envelope and cache rules: 60 s of skew each side, the window ends
            // inclusive, `not_after` within a day, 4096 bytes of configs, any repeated field
            // refused, used until `not_after`, discarded before the refetch.
            let signed = profile.signed_config;
            assert_eq!(signed.skew_tolerance_secs, 60);
            assert!(signed.not_after_inclusive);
            assert_eq!(signed.max_validity_secs, 86_400);
            assert_eq!(signed.max_not_after_ahead_secs, Some(86_400));
            assert_eq!(signed.max_configs_bytes, Some(4096));
            assert_eq!(signed.duplicate_keys, crate::DuplicateKeys::AnyTopLevel);
            assert_eq!(profile.cache.refresh_margin_secs, 0);
            assert!(profile.cache.drop_before_refetch);
            // Request freshness (crate::freshness): every client stamps its requests.
            assert!(profile.encode.freshness, "{profile:?}");
        }
    }
}

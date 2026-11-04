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

//! The build script's relay URL check (`build.rs`), run as a unit: a build script has no test
//! harness of its own, so the same source is compiled here as a module.

#[allow(dead_code)]
#[path = "../build.rs"]
mod build_script;

use build_script::check_relay_url;

#[test]
fn relay_urls_with_a_host_and_no_userinfo_are_accepted() {
    for url in [
        "https://relay.example",
        "https://relay.example/",
        "https://relay.example/relay",
        "https://relay.example:443/relay",
        "https://relay.example?x=1",
        "https://[2001:db8::1]:443/relay",
    ] {
        assert_eq!(check_relay_url(url), Ok(()), "{url}");
    }
}

#[test]
fn relay_urls_without_a_host_are_refused() {
    for url in [
        "https://",
        "https:///relay",
        "https://:443/relay",
        "https://:443",
        "https://?x=1",
        "https://#f",
        "https://[]:443/relay",
    ] {
        assert_eq!(
            check_relay_url(url),
            Err("must have a non-empty host"),
            "{url}"
        );
    }
}

#[test]
fn relay_urls_with_userinfo_are_refused() {
    for url in [
        "https://user@/relay",
        "https://user@relay.example/relay",
        "https://user:password@relay.example/relay",
        "https://@relay.example/relay",
        "https://relay.example@other.example/relay",
    ] {
        assert_eq!(
            check_relay_url(url),
            Err("must not contain userinfo"),
            "{url}"
        );
    }
}

#[test]
fn relay_urls_with_another_scheme_or_whitespace_are_refused() {
    for url in [
        "http://relay.example/relay",
        "relay.example",
        "HTTPS://relay.example",
    ] {
        assert_eq!(
            check_relay_url(url),
            Err("must be an https:// URL"),
            "{url}"
        );
    }
    for url in ["https://relay.example/re lay", "https://relay.example/\n"] {
        assert_eq!(
            check_relay_url(url),
            Err("must not contain whitespace or control characters"),
            "{url}"
        );
    }
}

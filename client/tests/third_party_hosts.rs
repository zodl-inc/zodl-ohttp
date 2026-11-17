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

//! The third-party host list without any I/O: reading a gateway's answer, which hosts are
//! allowed, and when a refresh is due. (`tests/gateway.rs` runs the same against the
//! gateway's own code; it needs the repository.)

use std::time::{Duration, Instant};

use zodl_ohttp_client::{
    is_unknown_authority, read_third_party_hosts, third_party_hosts_request, HostListAnswer,
    HostListScope, NoHostList, RefreshOutcome, Response, ThirdPartyHosts, FIRST_REFRESH_BACKOFF,
    MAX_HOST_LIST_AGE, MAX_REFRESH_BACKOFF, MAX_THIRD_PARTY_HOSTS_BYTES, MIN_HOST_LIST_AGE,
    REFRESH_ABANDONED_AFTER, REFUSAL_REFRESH_MIN_AGE, THIRD_PARTY_HOSTS_PATH,
    UNKNOWN_AUTHORITY_REFRESH_INTERVAL,
};

const GATEWAY: &str = "ohttp-gateway.example";

fn answer(status: u16, body: impl Into<Vec<u8>>) -> Response {
    Response {
        status,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: body.into(),
    }
}

/// A version 1 document.
fn document(revision: &str, scope: &str, max_age_secs: u64, hosts: &[&str]) -> Response {
    let hosts: Vec<serde_json::Value> = hosts
        .iter()
        .map(|host| serde_json::json!({ "host": host, "routes": ["GET /*", "POST /v1/submit"] }))
        .collect();
    answer(
        200,
        serde_json::json!({
            "version": 1,
            "revision": revision,
            "scope": scope,
            "max_age_secs": max_age_secs,
            "hosts": hosts,
        })
        .to_string(),
    )
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// Runs one refresh at `now` with `response` as the gateway's answer.
fn refresh(hosts: &ThirdPartyHosts, response: Option<&Response>, now: Instant) -> RefreshOutcome {
    let refresh = hosts.begin_refresh_at(now).expect("a refresh is due");
    hosts.finish_refresh_at(refresh, response, now)
}

#[test]
fn the_request_is_a_get_to_the_gateway_itself() {
    let request = third_party_hosts_request(GATEWAY, None);
    assert_eq!(request.method, "GET");
    assert_eq!(request.authority, GATEWAY);
    assert_eq!(request.path, THIRD_PARTY_HOSTS_PATH);
    assert_eq!(request.path, "/ohttp-gateway/v1/third-party-hosts");
    assert!(request.headers.is_empty() && request.body.is_empty());

    let request = third_party_hosts_request(GATEWAY, Some("5b0c1d9e7a3f2c44"));
    assert_eq!(
        request.headers,
        [(
            "if-none-match".to_string(),
            "\"5b0c1d9e7a3f2c44\"".to_string()
        )]
    );
    // A revision is opaque: anything that can stand in a quoted entity tag is sent back.
    assert_eq!(
        third_party_hosts_request(GATEWAY, Some("W/r:1+x=y")).headers,
        [("if-none-match".to_string(), "\"W/r:1+x=y\"".to_string())]
    );
    // Nothing else goes into the header.
    let too_long = "r".repeat(129);
    for bad in ["", "a\"b", "a b", "a\r\nx-injected: 1", too_long.as_str()] {
        assert!(
            third_party_hosts_request(GATEWAY, Some(bad))
                .headers
                .is_empty(),
            "{bad:?}"
        );
    }
}

#[test]
fn a_list_is_read_with_unknown_fields_ignored() {
    let response = answer(
        200,
        r#"{"version":1,"revision":"5b0c1d9e7a3f2c44","scope":"all","max_age_secs":300,
            "future_field":{"x":1},
            "hosts":[{"host":"API.example.org","routes":["GET /*","POST /*"],"note":"x"},
                     {"host":"query.example.org:8443","routes":[]},
                     {"host":"plain.example.org:443","routes":["GET /root"]}]}"#,
    );
    let HostListAnswer::List(list) = read_third_party_hosts(&response).unwrap() else {
        panic!("a list");
    };
    assert_eq!(list.revision, "5b0c1d9e7a3f2c44");
    assert_eq!(list.scope, HostListScope::All);
    assert_eq!(list.max_age_secs, 300);
    let names: Vec<&str> = list.hosts.iter().map(|h| h.host.as_str()).collect();
    // As compared and sent: the whole value, in lower case. Nothing else is rewritten.
    assert_eq!(
        names,
        [
            "api.example.org",
            "query.example.org:8443",
            "plain.example.org:443"
        ]
    );
    assert_eq!(list.hosts[0].routes, ["GET /*", "POST /*"]);
    assert!(list.hosts[1].routes.is_empty());

    // The scope: `dynamic`, and anything else (or none) is unknown.
    for (scope, expected) in [
        (r#""scope":"dynamic","#, HostListScope::Dynamic),
        (r#""scope":"regional","#, HostListScope::Unknown),
        (r#""scope":7,"#, HostListScope::Unknown),
        ("", HostListScope::Unknown),
    ] {
        let body =
            format!(r#"{{"version":1,"revision":"r1",{scope}"max_age_secs":60,"hosts":[]}}"#);
        let HostListAnswer::List(list) = read_third_party_hosts(&answer(200, body)).unwrap() else {
            panic!("a list");
        };
        assert_eq!(list.scope, expected, "{scope}");
        assert!(list.hosts.is_empty());
    }
    assert_eq!(
        read_third_party_hosts(&answer(304, "")),
        Ok(HostListAnswer::NotModified)
    );
}

#[test]
fn anything_else_is_no_list() {
    // What a gateway that does not publish the list, or has none to give, answers.
    for status in [403, 404, 500, 503, 204, 301] {
        assert_eq!(
            read_third_party_hosts(&answer(status, "policy denied")),
            Err(NoHostList::Status(status))
        );
    }
    let valid = r#"{"version":1,"revision":"r1","scope":"all","max_age_secs":60,"hosts":[]}"#;
    assert!(read_third_party_hosts(&answer(200, valid)).is_ok());
    for (body, expected) in [
        ("", NoHostList::Malformed),
        ("<html>", NoHostList::Malformed),
        ("[]", NoHostList::Malformed),
        (
            r#"{"revision":"r1","max_age_secs":60,"hosts":[]}"#,
            NoHostList::Malformed,
        ),
        (
            r#"{"version":"1","revision":"r1","max_age_secs":60,"hosts":[]}"#,
            NoHostList::Malformed,
        ),
        // Another version is no list, however well-formed the rest is, and whatever it holds.
        (
            r#"{"version":2,"revision":"r1","scope":"all","max_age_secs":60,"hosts":[]}"#,
            NoHostList::Version,
        ),
        (
            r#"{"version":2,"entirely":"different"}"#,
            NoHostList::Version,
        ),
        (
            r#"{"version":0,"revision":"r1","max_age_secs":60,"hosts":[]}"#,
            NoHostList::Version,
        ),
        // Version 1 with a required field missing or of another type.
        (
            r#"{"version":1,"scope":"all","max_age_secs":60,"hosts":[]}"#,
            NoHostList::Malformed,
        ),
        (
            r#"{"version":1,"revision":"r1","hosts":[]}"#,
            NoHostList::Malformed,
        ),
        (
            r#"{"version":1,"revision":"r1","max_age_secs":60}"#,
            NoHostList::Malformed,
        ),
        (
            r#"{"version":1,"revision":"r1","max_age_secs":-1,"hosts":[]}"#,
            NoHostList::Malformed,
        ),
        (
            r#"{"version":1,"revision":"r1","max_age_secs":60,"hosts":{}}"#,
            NoHostList::Malformed,
        ),
        // A revision that could not go back in a header.
        (
            r#"{"version":1,"revision":"a\"b","max_age_secs":60,"hosts":[]}"#,
            NoHostList::Malformed,
        ),
        (
            r#"{"version":1,"revision":"","max_age_secs":60,"hosts":[]}"#,
            NoHostList::Malformed,
        ),
    ] {
        assert_eq!(
            read_third_party_hosts(&answer(200, body)),
            Err(expected),
            "{body}"
        );
    }

    // Not an object, although its values are in the fields' order.
    assert_eq!(
        read_third_party_hosts(&answer(200, r#"[1,"r1","all",60,[]]"#)),
        Err(NoHostList::Malformed)
    );
    // A version that is a number but not 1, however it is written.
    for version in ["1.5", "-1", "1e3", "18446744073709551616"] {
        let body =
            format!(r#"{{"version":{version},"revision":"r1","max_age_secs":60,"hosts":[]}}"#);
        assert_eq!(
            read_third_party_hosts(&answer(200, body)),
            Err(NoHostList::Version),
            "{version}"
        );
    }
    // An entry whose host no `:authority` can be is left out; the list is read.
    let body = r#"{"version":1,"revision":"r1","scope":"all","max_age_secs":60,"hosts":[
        {"host":"https://api.example.org/","routes":[]},
        {"host":"api.example.org:0","routes":[]},
        {"host":"user@api.example.org","routes":[]},
        {"host":"under_score.example.org","routes":[]},
        {"host":"[2001:db8::1]","routes":[]},
        {"host":"","routes":[]},
        {"host":7,"routes":[]},
        {"host":"no-routes.example.org"},
        {"host":"bad-routes.example.org","routes":[7]},
        {"host":"routes-not-a-list.example.org","routes":"GET /*"},
        "string.example.org",
        ["positional.example.org",["GET /*"]],
        null,
        {"host":"good.example.org","routes":["GET /*"]}]}"#;
    let HostListAnswer::List(list) = read_third_party_hosts(&answer(200, body)).unwrap() else {
        panic!("a list");
    };
    assert_eq!(list.hosts.len(), 1);
    assert_eq!(list.hosts[0].host, "good.example.org");
    // A revision is opaque, within what an entity tag can hold.
    let body = r#"{"version":1,"revision":"W/r:1+x=y","max_age_secs":60,"hosts":[]}"#;
    assert!(read_third_party_hosts(&answer(200, body)).is_ok());

    // The size cap, at its edge: a document of exactly the cap is read, one byte more is not.
    let padding = MAX_THIRD_PARTY_HOSTS_BYTES - valid.len();
    let at_cap = format!("{valid}{}", " ".repeat(padding));
    assert_eq!(at_cap.len(), MAX_THIRD_PARTY_HOSTS_BYTES);
    assert!(read_third_party_hosts(&answer(200, at_cap.clone())).is_ok());
    assert_eq!(
        read_third_party_hosts(&answer(200, format!("{at_cap} "))),
        Err(NoHostList::TooLarge)
    );
    // Also for a 304: an oversized answer confirms nothing.
    assert_eq!(
        read_third_party_hosts(&answer(304, vec![b' '; MAX_THIRD_PARTY_HOSTS_BYTES + 1])),
        Err(NoHostList::TooLarge)
    );
    assert_eq!(MAX_THIRD_PARTY_HOSTS_BYTES, 256 * 1024);
}

#[test]
fn the_reasons_show_nothing_a_peer_sent() {
    for (reason, text) in [
        (
            NoHostList::Status(503),
            "the gateway answered 503 to the host list request",
        ),
        (
            NoHostList::TooLarge,
            "the host list is larger than 262144 bytes",
        ),
        (
            NoHostList::Malformed,
            "the host list is not a well-formed document",
        ),
        (
            NoHostList::Version,
            "the host list has a version this client does not read",
        ),
        (
            NoHostList::UnexpectedNotModified,
            "the gateway answered not modified to a request without a revision",
        ),
    ] {
        assert_eq!(reason.to_string(), text);
    }
    assert_eq!(
        zodl_ohttp_client::Error::NoHostList(NoHostList::Status(403)).to_string(),
        "no third-party host list: the gateway answered 403 to the host list request"
    );
    // The holder's Debug: counts, no host.
    let hosts = ThirdPartyHosts::new(["secret-host.example.org", "other.example.org"]);
    let now = Instant::now();
    assert_eq!(
        refresh(
            &hosts,
            Some(&document("r1", "all", 300, &["listed.example.org"])),
            now
        ),
        RefreshOutcome::Updated
    );
    let debug = format!("{hosts:?}");
    assert!(!debug.contains("example"), "{debug}");
    assert!(
        debug.contains("bootstrap_hosts: 2") && debug.contains("held_hosts: Some(1)"),
        "{debug}"
    );
}

#[test]
fn hosts_are_compared_whole_and_case_insensitively() {
    let hosts = ThirdPartyHosts::new([
        "Vote.Example.org",
        "query.example.org:8443",
        "plain.example.org:443",
        "not a host",
        "",
        "https://url.example.org",
    ]);
    assert_eq!(hosts.bootstrap_len(), 3, "the entries that are host names");
    for (carried, authority) in [
        ("vote.example.org", "vote.example.org"),
        ("VOTE.EXAMPLE.ORG", "vote.example.org"),
        ("query.example.org:8443", "query.example.org:8443"),
        ("Query.Example.Org:8443", "query.example.org:8443"),
        ("plain.example.org:443", "plain.example.org:443"),
    ] {
        assert!(hosts.is_carried(carried), "{carried}");
        // What to send as `:authority`: the value that was checked, in lower case.
        assert_eq!(hosts.carried_authority(carried).as_deref(), Some(authority));
    }
    for refused in [
        // No suffix, prefix or wildcard matching.
        "example.org",
        "a.vote.example.org",
        "xvote.example.org",
        "vote.example.org.evil.example.net",
        "vote.example",
        // The port is part of the value: no other spelling of the same host.
        "vote.example.org:443",
        "plain.example.org",
        "vote.example.org:8443",
        "query.example.org",
        "query.example.org:443",
        "query.example.org:8444",
        "query.example.org:08443",
        // Not hosts (the gateway takes none of these as an `:authority`).
        "vote.example.org.",
        ".vote.example.org",
        "vote..example.org",
        "-vote.example.org",
        "vote-.example.org",
        "",
        "vote.example.org/",
        "vote.example.org:",
        "vote.example.org:0",
        "vote.example.org:99999",
        "user@vote.example.org",
        "https://vote.example.org",
        " vote.example.org",
        "url.example.org",
    ] {
        assert!(!hosts.is_carried(refused), "{refused}");
        assert_eq!(hosts.carried_authority(refused), None, "{refused}");
    }

    // The gateway's own limits on an `:authority`: labels of at most 63 characters, 253 in
    // all with the port.
    let label63 = "a".repeat(63);
    let label64 = "a".repeat(64);
    let long = format!("{}.{}.{}.{}", label63, label63, label63, "b".repeat(56));
    assert_eq!(long.len(), 248);
    let limits = ThirdPartyHosts::new([
        format!("{label63}.example.org"),
        format!("{label64}.example.org"),
        format!("{long}:8443"),
        format!("{long}:18443"),
    ]);
    assert_eq!(limits.bootstrap_len(), 2);
    assert!(limits.is_carried(&format!("{label63}.example.org")));
    assert!(!limits.is_carried(&format!("{label64}.example.org")));
    assert!(limits.is_carried(&format!("{long}:8443")), "253 characters");
    assert!(
        !limits.is_carried(&format!("{long}:18443")),
        "254 characters"
    );
}

#[test]
fn the_scope_decides_what_the_bootstrap_list_still_allows() {
    let hosts = ThirdPartyHosts::new(["compiled.example.org", "both.example.org"]);
    let start = Instant::now();
    // Before any fetch: the bootstrap list.
    assert!(hosts.held().is_none() && hosts.revision().is_none());
    assert!(hosts.is_carried("compiled.example.org"));
    assert!(!hosts.is_carried("listed.example.org"));

    // Scope `all`: exactly the list. The compiled list no longer counts.
    let all = document(
        "r-all",
        "all",
        300,
        &["listed.example.org", "both.example.org"],
    );
    assert_eq!(refresh(&hosts, Some(&all), start), RefreshOutcome::Updated);
    assert_eq!(hosts.revision().as_deref(), Some("r-all"));
    assert_eq!(hosts.held().unwrap().scope, HostListScope::All);
    assert!(hosts.is_carried("listed.example.org") && hosts.is_carried("both.example.org"));
    assert!(!hosts.is_carried("compiled.example.org"));

    // Scope `dynamic`: the list and the compiled list. The list replaces the one before it as
    // a whole, also when the scope differs.
    let later = start + secs(400);
    let dynamic = document("r-dyn", "dynamic", 300, &["other.example.org"]);
    assert_eq!(
        refresh(&hosts, Some(&dynamic), later),
        RefreshOutcome::Updated
    );
    assert!(hosts.is_carried("other.example.org"));
    assert!(hosts.is_carried("compiled.example.org") && hosts.is_carried("both.example.org"));
    assert!(
        !hosts.is_carried("listed.example.org"),
        "of the list that was replaced"
    );

    // A scope this crate does not know: like `dynamic`.
    let unknown = document("r-new", "regional", 300, &["third.example.org"]);
    assert_eq!(
        refresh(&hosts, Some(&unknown), later + secs(400)),
        RefreshOutcome::Updated
    );
    assert!(hosts.is_carried("third.example.org") && hosts.is_carried("compiled.example.org"));
    assert!(!hosts.is_carried("other.example.org"));

    // An empty `all` list: the gateway carries nothing.
    let none = document("r-none", "all", 300, &[]);
    assert_eq!(
        refresh(&hosts, Some(&none), later + secs(800)),
        RefreshOutcome::Updated
    );
    assert!(!hosts.is_carried("compiled.example.org") && !hosts.is_carried("third.example.org"));
}

#[test]
fn servers_the_gateway_does_not_carry_are_dropped_not_fatal() {
    let hosts = ThirdPartyHosts::new(["vote-a.example.org", "pir.example.org:8443"]);
    let offered = [
        "https://vote-a.example.org",
        "https://VOTE-A.example.org/",
        "https://vote-a.example.org:443/base?x=1",
        "https://new-server.example.org",
        "http://vote-a.example.org",
        "https://user:pw@vote-a.example.org",
        "https://pir.example.org:8443",
        "https://pir.example.org",
        "https://[2001:db8::1]",
        "vote-a.example.org",
        "not a url",
        "https://@vote-a.example.org",
        "https:///@vote-a.example.org",
        // Spellings a lenient parser accepts and another reads differently.
        "https:@vote-a.example.org",
        "https:/@vote-a.example.org",
        "https:\\@vote-a.example.org",
        "https:/\t/vote-a.example.org",
        "https://vote-a.example.org\\@other.example.net",
        "https://vote-a.example.org\n",
        " https://vote-a.example.org",
        "https:vote-a.example.org",
        "",
    ];
    let kept = hosts.filter_servers(offered);
    let urls = |kept: &zodl_ohttp_client::CarriedServers<'_>| -> Vec<(String, String)> {
        kept.carried
            .iter()
            .map(|server| (server.url.to_string(), server.authority.clone()))
            .collect()
    };
    let pair = |url: &str, authority: &str| (url.to_string(), authority.to_string());
    // Each with the `:authority` to send: the checked value, not a spelling of the URL.
    assert_eq!(
        urls(&kept),
        [
            pair("https://vote-a.example.org", "vote-a.example.org"),
            pair("https://VOTE-A.example.org/", "vote-a.example.org"),
            pair(
                "https://vote-a.example.org:443/base?x=1",
                "vote-a.example.org"
            ),
            pair("https://pir.example.org:8443", "pir.example.org:8443"),
        ]
    );
    assert_eq!(kept.dropped, 18);
    assert!(kept.any());

    // The host must be written as it is sent: a spelling one parser rewrites into a carried
    // host and another reads differently is dropped.
    let spelled = ThirdPartyHosts::new(["vote-a.example.org", "203.0.113.5", "203.0.113.5:8443"]);
    let kept = spelled.filter_servers([
        "https://vote%2Da.example.org/x",
        "https://0xcb.0.0x71.5",
        "https://3405803781",
        "https://vote-a.example.org.",
        "https://vote\u{ff0d}a.example.org",
        "https://xn--bcher-kva.example.org",
        "https://203.0.113.5:443/x",
        "https://Vote-A.Example.org:443",
        "https://vote-a.example.org:/",
        "https://203.0.113.5:8443",
    ]);
    assert_eq!(
        urls(&kept),
        [
            pair("https://203.0.113.5:443/x", "203.0.113.5"),
            pair("https://Vote-A.Example.org:443", "vote-a.example.org"),
            pair("https://vote-a.example.org:/", "vote-a.example.org"),
            pair("https://203.0.113.5:8443", "203.0.113.5:8443"),
        ]
    );
    assert_eq!(kept.dropped, 6);

    // The iterator runs outside the holder's lock: it may ask the holder itself.
    let reentrant =
        hosts.filter_servers(offered.iter().copied().filter(|url| !hosts.is_carried(url)));
    assert_eq!(reentrant.carried.len(), 4);

    // Nothing carried: the caller fails the operation; nothing is left to try another way.
    let none = hosts.filter_servers([
        "https://new-server.example.org",
        "http://vote-a.example.org",
    ]);
    assert!(none.carried.is_empty() && !none.any());
    assert_eq!(none.dropped, 2);
    let empty = hosts.filter_servers(std::iter::empty::<&str>());
    assert!(!empty.any() && empty.dropped == 0);

    // After a fetch the same call follows the gateway's list.
    let list = document("r1", "all", 300, &["new-server.example.org"]);
    assert_eq!(
        refresh(&hosts, Some(&list), Instant::now()),
        RefreshOutcome::Updated
    );
    let kept = hosts.filter_servers(offered);
    assert_eq!(
        urls(&kept),
        [pair(
            "https://new-server.example.org",
            "new-server.example.org"
        )]
    );
    assert_eq!(kept.dropped, 21);
}

#[test]
fn a_list_is_used_for_its_clamped_lifetime_and_revalidated() {
    let hosts = ThirdPartyHosts::new(["compiled.example.org"]);
    let start = Instant::now();
    // The first fetch is due at once and sends no revision.
    let first = hosts.begin_refresh_at(start).expect("due");
    assert_eq!(first.revision(), None);
    assert!(first.request(GATEWAY).headers.is_empty());
    // One at a time.
    assert!(hosts.begin_refresh_at(start).is_none());
    assert!(hosts.begin_refresh_at(start + secs(60)).is_none());
    let list = document("r1", "all", 300, &["listed.example.org"]);
    assert_eq!(
        hosts.finish_refresh_at(first, Some(&list), start + secs(1)),
        RefreshOutcome::Updated
    );

    // Fresh for max_age_secs from when it was fetched.
    assert!(hosts.begin_refresh_at(start + secs(300)).is_none());
    let second = hosts.begin_refresh_at(start + secs(301)).expect("stale");
    assert_eq!(second.revision(), Some("r1"));
    assert_eq!(
        second.request(GATEWAY).headers,
        [("if-none-match".to_string(), "\"r1\"".to_string())]
    );
    // The held list stays in use while the refresh runs.
    assert!(hosts.is_carried("listed.example.org"));
    // 304: kept, and its lifetime starts again.
    let confirmed = start + secs(302);
    assert_eq!(
        hosts.finish_refresh_at(second, Some(&answer(304, "")), confirmed),
        RefreshOutcome::NotModified
    );
    assert_eq!(hosts.revision().as_deref(), Some("r1"));
    assert!(hosts.begin_refresh_at(confirmed + secs(299)).is_none());
    assert!(hosts.begin_refresh_at(confirmed + secs(300)).is_some());

    // The lifetime is clamped to 30 s..24 h, whatever the gateway writes.
    for (max_age_secs, lifetime) in [
        (0, MIN_HOST_LIST_AGE),
        (5, MIN_HOST_LIST_AGE),
        (30, secs(30)),
        (3600, secs(3600)),
        (86_400, MAX_HOST_LIST_AGE),
        (u64::MAX, MAX_HOST_LIST_AGE),
    ] {
        let hosts = ThirdPartyHosts::new(["compiled.example.org"]);
        let list = document("r1", "all", max_age_secs, &["listed.example.org"]);
        assert_eq!(refresh(&hosts, Some(&list), start), RefreshOutcome::Updated);
        assert_eq!(hosts.held().unwrap().max_age_secs, max_age_secs);
        assert!(
            hosts.begin_refresh_at(start + lifetime - secs(1)).is_none(),
            "{max_age_secs}"
        );
        assert!(
            hosts.begin_refresh_at(start + lifetime).is_some(),
            "{max_age_secs}"
        );
    }
    assert_eq!(
        (MIN_HOST_LIST_AGE, MAX_HOST_LIST_AGE),
        (secs(30), secs(86_400))
    );
}

#[test]
fn a_failed_refresh_keeps_what_is_held_and_backs_off() {
    let hosts = ThirdPartyHosts::new(["compiled.example.org"]);
    let start = Instant::now();
    // Failures before any list: the bootstrap list stays, with a growing pause.
    let mut now = start;
    for (failure, pause) in [
        (None, secs(30)),
        (Some(answer(503, "host list not ready")), secs(60)),
        (Some(answer(403, "policy denied")), secs(120)),
        (Some(answer(200, "<html>")), secs(240)),
        (Some(answer(200, r#"{"version":2}"#)), secs(300)),
        (None, secs(300)),
    ] {
        let outcome = refresh(&hosts, failure.as_ref(), now);
        let expected = failure
            .as_ref()
            .map(|f| read_third_party_hosts(f).unwrap_err());
        assert_eq!(outcome, RefreshOutcome::Kept(expected));
        assert!(hosts.held().is_none());
        assert!(hosts.is_carried("compiled.example.org"));
        assert!(
            hosts.begin_refresh_at(now + pause - secs(1)).is_none(),
            "{pause:?}"
        );
        now += pause;
    }
    assert_eq!(
        (FIRST_REFRESH_BACKOFF, MAX_REFRESH_BACKOFF),
        (secs(30), secs(300))
    );

    // A success ends the backoff.
    let list = document("r1", "all", 60, &["listed.example.org"]);
    assert_eq!(refresh(&hosts, Some(&list), now), RefreshOutcome::Updated);
    let stale = now + secs(60);

    // Failures with a list held: the list stays in force, however old, and the pause starts
    // at 30 s again.
    assert_eq!(refresh(&hosts, None, stale), RefreshOutcome::Kept(None));
    assert!(hosts.is_carried("listed.example.org") && !hosts.is_carried("compiled.example.org"));
    assert!(hosts.begin_refresh_at(stale + secs(29)).is_none());
    assert_eq!(
        refresh(&hosts, Some(&answer(503, "")), stale + secs(30)),
        RefreshOutcome::Kept(Some(NoHostList::Status(503)))
    );
    assert!(hosts.is_carried("listed.example.org"));
    assert_eq!(hosts.revision().as_deref(), Some("r1"));
    assert!(hosts.begin_refresh_at(stale + secs(30 + 59)).is_none());
    // Days later it is still the list held.
    assert!(hosts.is_carried("listed.example.org"));

    // A 304 that confirms nothing is a failure: no revision was sent.
    let fresh = ThirdPartyHosts::new(["compiled.example.org"]);
    assert_eq!(
        refresh(&fresh, Some(&answer(304, "")), start),
        RefreshOutcome::Kept(Some(NoHostList::UnexpectedNotModified))
    );
    assert!(fresh.held().is_none());
    assert!(fresh.begin_refresh_at(start + secs(29)).is_none());
}

#[test]
fn a_refresh_that_is_never_finished_does_not_block_the_next() {
    let hosts = ThirdPartyHosts::new(["compiled.example.org"]);
    let start = Instant::now();
    let dropped = hosts.begin_refresh_at(start).expect("due");
    assert!(hosts
        .begin_refresh_at(start + REFRESH_ABANDONED_AFTER - secs(1))
        .is_none());
    // Given up: a failure, so the backoff runs from then.
    let given_up = start + REFRESH_ABANDONED_AFTER;
    assert!(hosts.begin_refresh_at(given_up).is_none());
    assert!(hosts.begin_refresh_at(given_up + secs(29)).is_none());
    let next = hosts
        .begin_refresh_at(given_up + secs(30))
        .expect("due again");
    // The old one finishing late changes nothing, not even with a list.
    let list = document("late", "all", 300, &["late.example.org"]);
    assert_eq!(
        hosts.finish_refresh_at(dropped, Some(&list), given_up + secs(31)),
        RefreshOutcome::Superseded
    );
    assert!(hosts.held().is_none());
    // The running one is unaffected.
    let list = document("r1", "all", 300, &["listed.example.org"]);
    assert_eq!(
        hosts.finish_refresh_at(next, Some(&list), given_up + secs(32)),
        RefreshOutcome::Updated
    );
    assert_eq!(hosts.revision().as_deref(), Some("r1"));
}

#[test]
fn an_unknown_authority_for_a_listed_host_asks_for_one_refresh_per_interval() {
    let unknown = Response {
        status: 403,
        headers: vec![],
        body: b"unknown authority".to_vec(),
    };
    assert!(is_unknown_authority(&unknown));
    for (status, body) in [
        (403, "policy denied"),
        (404, "unknown authority"),
        (403, ""),
    ] {
        assert!(!is_unknown_authority(&answer(status, body)));
    }

    let hosts = ThirdPartyHosts::new(["compiled.example.org"]);
    let start = Instant::now();
    // Nothing held: nothing to refresh for this reason.
    assert!(!hosts.report_unknown_authority_at("compiled.example.org", start));
    let list = document("r1", "dynamic", 3600, &["listed.example.org"]);
    assert_eq!(refresh(&hosts, Some(&list), start), RefreshOutcome::Updated);
    assert!(hosts.begin_refresh_at(start + secs(10)).is_none(), "fresh");

    // A host the list does not name (allowed by the bootstrap list only, or not at all).
    assert!(!hosts.report_unknown_authority_at("compiled.example.org", start + secs(10)));
    assert!(!hosts.report_unknown_authority_at("nowhere.example.org", start + secs(10)));
    assert!(!hosts.report_unknown_authority_at("not a host", start + secs(10)));
    assert!(hosts.begin_refresh_at(start + secs(10)).is_none());

    // A listed host: one refresh, although the list is fresh.
    assert!(hosts.report_unknown_authority_at("Listed.Example.org", start + secs(10)));
    let asked = hosts.begin_refresh_at(start + secs(11)).expect("asked for");
    assert_eq!(asked.revision(), Some("r1"));
    assert_eq!(
        hosts.finish_refresh_at(asked, Some(&answer(304, "")), start + secs(12)),
        RefreshOutcome::NotModified
    );
    // Not again within the interval, counted from when that refresh began (11 s), however
    // often it is reported.
    for after in [13, 20, 40] {
        assert!(!hosts.report_unknown_authority_at("listed.example.org", start + secs(after)));
    }
    assert!(hosts.begin_refresh_at(start + secs(40)).is_none());
    assert!(hosts.report_unknown_authority_at("listed.example.org", start + secs(41)));
    // Asked for once: a second report before it runs adds nothing.
    assert!(!hosts.report_unknown_authority_at("listed.example.org", start + secs(42)));
    // It runs later than it was asked for: the interval starts when it begins.
    let late = hosts
        .begin_refresh_at(start + secs(100))
        .expect("asked for");
    // While it runs, a report asks for nothing more: it brings the current list.
    assert!(!hosts.report_unknown_authority_at("listed.example.org", start + secs(200)));
    assert_eq!(
        hosts.finish_refresh_at(late, Some(&answer(304, "")), start + secs(201)),
        RefreshOutcome::NotModified
    );
    assert!(
        hosts.begin_refresh_at(start + secs(202)).is_none(),
        "nothing left over"
    );
    assert!(!hosts.report_unknown_authority_at("listed.example.org", start + secs(129)));
    assert!(hosts.report_unknown_authority_at("listed.example.org", start + secs(202)));
    assert_eq!(UNKNOWN_AUTHORITY_REFRESH_INTERVAL, secs(30));
}

#[test]
fn one_refresh_before_refusing_a_host_when_the_list_is_not_brand_new() {
    let hosts = ThirdPartyHosts::new(["compiled.example.org"]);
    let start = Instant::now();
    // Nothing held: the gateway's list was never seen, so it is worth fetching first.
    assert!(hosts.refresh_before_refusing_at(start));
    let list = document("r1", "all", 3600, &["listed.example.org"]);
    assert_eq!(refresh(&hosts, Some(&list), start), RefreshOutcome::Updated);

    assert!(!hosts.is_carried("added-since.example.org"));
    // Just fetched: refuse.
    assert!(!hosts.refresh_before_refusing_at(start + REFUSAL_REFRESH_MIN_AGE - secs(1)));
    assert!(hosts.begin_refresh_at(start + secs(4)).is_none());
    // Older: one refresh, then ask again.
    let now = start + REFUSAL_REFRESH_MIN_AGE;
    assert!(hosts.refresh_before_refusing_at(now));
    let grown = document(
        "r2",
        "all",
        3600,
        &["listed.example.org", "added-since.example.org"],
    );
    assert_eq!(refresh(&hosts, Some(&grown), now), RefreshOutcome::Updated);
    assert!(hosts.is_carried("added-since.example.org"));
    // The new list is brand new again.
    assert!(!hosts.refresh_before_refusing_at(now + secs(1)));

    // During a backoff the wish is kept, not run early.
    assert!(hosts.refresh_before_refusing_at(now + secs(10)));
    assert_eq!(
        refresh(&hosts, None, now + secs(10)),
        RefreshOutcome::Kept(None)
    );
    assert!(hosts.refresh_before_refusing_at(now + secs(20)));
    assert!(hosts.begin_refresh_at(now + secs(39)).is_none());
    assert!(hosts.begin_refresh_at(now + secs(40)).is_some());
}

#[test]
fn it_is_shared_between_threads() {
    let hosts = std::sync::Arc::new(ThirdPartyHosts::new(["compiled.example.org"]));
    let start = Instant::now();
    // Many threads ask at once: exactly one refresh begins.
    let begun: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| hosts.begin_refresh_at(start)))
            .collect();
        handles
            .into_iter()
            .filter_map(|handle| handle.join().unwrap())
            .collect()
    });
    assert_eq!(begun.len(), 1);
    let list = document("r1", "all", 300, &["listed.example.org"]);
    for refresh in begun {
        assert_eq!(
            hosts.finish_refresh_at(refresh, Some(&list), start),
            RefreshOutcome::Updated
        );
    }
    // Readers and a refresh at the same time.
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                for _ in 0..1000 {
                    assert!(hosts.is_carried("listed.example.org"));
                    assert!(hosts.filter_servers(["https://listed.example.org"]).any());
                }
            });
        }
        for round in 1..50u64 {
            let now = start + secs(301 * round);
            if let Some(refresh) = hosts.begin_refresh_at(now) {
                let list = document(&format!("r{round}"), "all", 300, &["listed.example.org"]);
                assert_eq!(
                    hosts.finish_refresh_at(refresh, Some(&list), now),
                    RefreshOutcome::Updated
                );
            }
        }
    });
}

#[test]
fn a_refresh_that_was_asked_for_and_failed_is_tried_again_after_the_backoff() {
    let hosts = ThirdPartyHosts::new(["compiled.example.org"]);
    let start = Instant::now();
    // A list that stays fresh for a day.
    let list = document("r1", "all", 86_400, &["listed.example.org"]);
    assert_eq!(refresh(&hosts, Some(&list), start), RefreshOutcome::Updated);
    // Asked for after ten seconds; the exchange fails.
    assert!(hosts.refresh_before_refusing_at(start + secs(10)));
    assert_eq!(
        refresh(&hosts, None, start + secs(10)),
        RefreshOutcome::Kept(None)
    );
    // The wish is not lost: with nothing but periodic calls it runs once the backoff passed,
    // long before the list goes stale.
    assert!(hosts.begin_refresh_at(start + secs(39)).is_none());
    let again = hosts
        .begin_refresh_at(start + secs(40))
        .expect("tried again");
    assert_eq!(
        hosts.fail_refresh_at(again, Some(NoHostList::TooLarge), start + secs(41)),
        RefreshOutcome::Kept(Some(NoHostList::TooLarge))
    );
    // ... and again (60 s after the second failure), until one succeeds.
    assert!(hosts.begin_refresh_at(start + secs(100)).is_none());
    let third = hosts
        .begin_refresh_at(start + secs(101))
        .expect("tried again");
    assert_eq!(
        hosts.finish_refresh_at(third, Some(&answer(304, "")), start + secs(102)),
        RefreshOutcome::NotModified
    );
    assert!(hosts.begin_refresh_at(start + secs(200)).is_none(), "met");
    // A refresh that was due by age and failed is due again by age after the backoff.
    assert!(hosts.is_carried("listed.example.org"));
}

#[test]
fn a_refresh_is_finished_only_at_the_holder_that_began_it() {
    let mainnet = ThirdPartyHosts::new(["compiled.example.org"]);
    let testnet = ThirdPartyHosts::new(["compiled.example.org"]);
    let start = Instant::now();
    let for_mainnet = mainnet.begin_refresh_at(start).expect("due");
    let for_testnet = testnet.begin_refresh_at(start).expect("due");
    // The answers get mixed up: neither holder takes the other's list or counts a failure.
    let list = document("r1", "all", 300, &["mainnet-only.example.org"]);
    assert_eq!(
        testnet.finish_refresh_at(for_mainnet, Some(&list), start),
        RefreshOutcome::Superseded
    );
    assert!(testnet.held().is_none());
    assert_eq!(
        mainnet.fail_refresh_at(for_testnet, None, start),
        RefreshOutcome::Superseded
    );
    // Both refreshes are still running where they began.
    assert!(mainnet.begin_refresh_at(start + secs(1)).is_none());
    assert!(testnet.begin_refresh_at(start + secs(1)).is_none());
}

#[test]
fn a_refresh_finished_too_late_changes_nothing() {
    let hosts = ThirdPartyHosts::new(["compiled.example.org"]);
    let start = Instant::now();
    let slow = hosts.begin_refresh_at(start).expect("due");
    assert!(hosts.is_refreshing_at(start + REFRESH_ABANDONED_AFTER - secs(1)));
    assert!(!hosts.is_refreshing_at(start + REFRESH_ABANDONED_AFTER));
    // Its answer arrives five minutes after it began, and nothing else happened meanwhile:
    // it is not taken, and counts as the failure it would have been given up as.
    let list = document("late", "all", 300, &["late.example.org"]);
    let late = start + REFRESH_ABANDONED_AFTER;
    assert_eq!(
        hosts.finish_refresh_at(slow, Some(&list), late),
        RefreshOutcome::Superseded
    );
    assert!(hosts.held().is_none() && !hosts.is_refreshing_at(late));
    assert!(hosts.begin_refresh_at(late + secs(29)).is_none());
    assert!(hosts.begin_refresh_at(late + secs(30)).is_some());

    // Just in time it is taken.
    let hosts = ThirdPartyHosts::new(["compiled.example.org"]);
    let in_time = hosts.begin_refresh_at(start).expect("due");
    assert_eq!(
        hosts.finish_refresh_at(in_time, Some(&list), late - secs(1)),
        RefreshOutcome::Updated
    );
    assert!(!hosts.is_refreshing_at(late));
}

#[test]
fn a_refresh_that_was_given_up_does_not_swallow_a_report() {
    let hosts = ThirdPartyHosts::new(["compiled.example.org"]);
    let start = Instant::now();
    let list = document("r1", "all", 60, &["listed.example.org"]);
    assert_eq!(refresh(&hosts, Some(&list), start), RefreshOutcome::Updated);
    // A refresh begins when the list is stale and is never finished.
    let began = start + secs(60);
    let lost = hosts.begin_refresh_at(began).expect("stale");
    // While it counts as running, a report asks for nothing more.
    let almost = began + REFRESH_ABANDONED_AFTER - secs(1);
    assert!(!hosts.report_unknown_authority_at("listed.example.org", almost));
    // Once it is given up (whether or not anything has noticed yet), a report counts again.
    let given_up = began + REFRESH_ABANDONED_AFTER;
    assert!(hosts.report_unknown_authority_at("listed.example.org", given_up));
    assert_eq!(
        hosts.finish_refresh_at(lost, None, given_up),
        RefreshOutcome::Superseded
    );
}

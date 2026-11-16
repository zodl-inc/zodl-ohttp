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

//! Tests of the published third-party host list.

use super::*;
use crate::dynamic_hosts::{DynamicHosts, Reserved};

const TARGET: &str = "https://prices-upstream.example.com";

/// A gateway with two static aliases (one with a policy and a credential, one without a
/// policy) and two dynamic hosts.
fn config(source: &str, mode: PublishMode) -> Config {
    let mut config = crate::config::test_config();
    config
        .backends
        .insert("prices.example.com".to_string(), TARGET.to_string());
    config.backends.insert(
        "nopolicy.example.com".to_string(),
        "https://nopolicy-upstream.example.com".to_string(),
    );
    config.backends_policy.insert(
        "prices.example.com".to_string(),
        vec![
            ("get".to_string(), "/v1/quotes".to_string()),
            ("GET".to_string(), "/v1/fiat/*".to_string()),
        ],
    );
    config.backend_headers.insert(
        "prices.example.com".to_string(),
        vec![("X-Api-Key".to_string(), "secret-api-key".to_string())],
    );
    config.dynamic_hosts = DynamicHosts::for_tests(
        source,
        "GET /shielded-vote/*,POST /shielded-vote/v1/submit",
        &["https://vote-b.example.org", "https://vote-a.example.org"],
        Reserved {
            aliases: config.backends.keys().cloned().collect(),
            gateway_hosts: config.gateway_hosts.iter().cloned().collect(),
            ..Default::default()
        },
    );
    config.host_list = HostListSettings {
        mode,
        max_age_secs: 300,
    };
    config
}

fn list_request(authority: &str) -> InnerRequest {
    InnerRequest {
        method: "GET".to_string(),
        path: HOST_LIST_PATH.to_string(),
        authority: authority.to_string(),
        headers: vec![],
        body: vec![],
    }
}

fn header<'a>(resp: &'a InnerResponse, name: &str) -> Option<&'a str> {
    resp.headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn body(resp: &InnerResponse) -> serde_json::Value {
    serde_json::from_slice(&resp.body).expect("JSON")
}

fn hosts(resp: &InnerResponse) -> Vec<(String, Vec<String>)> {
    body(resp)["hosts"]
        .as_array()
        .expect("hosts")
        .iter()
        .map(|h| {
            (
                h["host"].as_str().unwrap().to_string(),
                h["routes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|r| r.as_str().unwrap().to_string())
                    .collect(),
            )
        })
        .collect()
}

#[test]
fn the_settings_parse_strictly() {
    assert_eq!(
        HostListSettings::parse(None, None).unwrap(),
        HostListSettings::default()
    );
    assert_eq!(HostListSettings::default().mode, PublishMode::Off);
    assert_eq!(
        HostListSettings::parse(Some(""), Some(" ")).unwrap(),
        HostListSettings::default()
    );
    assert_eq!(
        HostListSettings::parse(Some(" Dynamic "), Some("60")).unwrap(),
        HostListSettings {
            mode: PublishMode::Dynamic,
            max_age_secs: 60
        }
    );
    assert_eq!(
        HostListSettings::parse(Some("all"), None).unwrap().mode,
        PublishMode::All
    );
    assert_eq!(
        HostListSettings::parse(Some("off"), None).unwrap().mode,
        PublishMode::Off
    );
    for (mode, age) in [
        (Some("on"), None),
        (Some("true"), None),
        (Some("static"), None),
        (None, Some("5")),
        (None, Some("999999999")),
        (None, Some("five")),
        (None, Some("-1")),
    ] {
        assert!(
            HostListSettings::parse(mode, age).is_err(),
            "{mode:?} {age:?}"
        );
    }
}

#[test]
fn only_a_get_of_the_exact_path_at_a_gateway_host_is_the_list() {
    let on = config("list_request", PublishMode::All);
    assert!(is_request(&on, &list_request("ohttp-gateway.example")));
    assert!(is_request(&on, &list_request("ohttp-gateway.example:443")));
    assert!(is_request(&on, &list_request("OHTTP-Gateway.Example")));
    // Not a gateway host: a third-party alias, a dynamic host, an unknown or an empty name.
    for authority in [
        "prices.example.com",
        "vote-a.example.org",
        "other.example.net",
        "",
    ] {
        assert!(!is_request(&on, &list_request(authority)), "{authority}");
    }
    for (method, path) in [
        ("POST", HOST_LIST_PATH),
        ("HEAD", HOST_LIST_PATH),
        ("get", HOST_LIST_PATH),
        ("GET", "/ohttp-gateway/v1/third-party-hosts/"),
        ("GET", "/ohttp-gateway/v1/third-party-hosts?x=1"),
        ("GET", "/ohttp-gateway/v2/third-party-hosts"),
        ("GET", "/third-party-hosts"),
    ] {
        let mut req = list_request("ohttp-gateway.example");
        req.method = method.to_string();
        req.path = path.to_string();
        assert!(!is_request(&on, &req), "{method} {path}");
    }
    // Off (the default): the path is not special.
    let off = config("list_request_off", PublishMode::Off);
    assert!(!is_request(&off, &list_request("ohttp-gateway.example")));
    assert!(!is_request(
        &crate::config::test_config(),
        &list_request("ohttp-gateway.example")
    ));
}

#[test]
fn the_list_names_hosts_and_routes_and_nothing_else() {
    let all = config("list_all", PublishMode::All);
    let resp = answer(&all, &list_request("ohttp-gateway.example"));
    assert_eq!(resp.status, 200);
    assert_eq!(header(&resp, "content-type"), Some("application/json"));
    assert_eq!(header(&resp, "cache-control"), Some("max-age=300"));
    let json = body(&resp);
    assert_eq!(json["version"], 1);
    assert_eq!(json["scope"], "all");
    assert_eq!(json["max_age_secs"], 300);
    let revision = json["revision"].as_str().unwrap().to_string();
    assert_eq!(revision.len(), 16);
    assert!(revision.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(
        header(&resp, "etag"),
        Some(format!("\"{revision}\"").as_str())
    );
    let rules = |r: &[&str]| r.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let vote = rules(&["GET /shielded-vote/*", "POST /shielded-vote/v1/submit"]);
    // Sorted by host; the alias with rules by its name; the alias without rules is absent
    // (default deny: the gateway forwards nothing to it).
    assert_eq!(
        hosts(&resp),
        vec![
            (
                "prices.example.com".to_string(),
                rules(&["GET /v1/quotes", "GET /v1/fiat/*"])
            ),
            ("vote-a.example.org".to_string(), vote.clone()),
            ("vote-b.example.org".to_string(), vote.clone()),
        ]
    );
    // Nothing about a backend but its name: no target, no credential, no source.
    let text = String::from_utf8(resp.body.clone()).unwrap();
    for secret in [
        "upstream",
        "secret-api-key",
        "X-Api-Key",
        "source.example.com",
        "list_all",
        "dynamic:",
        "ohttp-gateway.example",
        "lwd",
    ] {
        assert!(!text.contains(secret), "{secret} is published");
    }
    assert_eq!(
        json.as_object().unwrap().keys().collect::<Vec<_>>().len(),
        5,
        "version, revision, scope, max_age_secs, hosts"
    );

    // BACKENDS_POLICY_DEFAULT=allow: an alias without rules accepts everything.
    let mut open = all.clone();
    open.backends_policy_default_allow = true;
    let listed = hosts(&answer(&open, &list_request("ohttp-gateway.example")));
    assert_eq!(listed.len(), 4);
    assert_eq!(
        listed[0],
        ("nopolicy.example.com".to_string(), rules(&["* /*"]))
    );

    // `dynamic`: the hosts of the sources only.
    let dynamic = config("list_dynamic", PublishMode::Dynamic);
    assert_eq!(
        hosts(&answer(&dynamic, &list_request("ohttp-gateway.example"))),
        vec![
            ("vote-a.example.org".to_string(), vote.clone()),
            ("vote-b.example.org".to_string(), vote),
        ]
    );

    // No source and no alias: an empty list, still a valid document.
    let mut empty = crate::config::test_config();
    empty.host_list.mode = PublishMode::All;
    let resp = answer(&empty, &list_request("ohttp-gateway.example"));
    assert_eq!(resp.status, 200);
    assert!(hosts(&resp).is_empty());
}

#[test]
fn the_revision_names_the_document() {
    let first = config("list_revision", PublishMode::All);
    let req = list_request("ohttp-gateway.example");
    let revision = |config: &Config| {
        body(&answer(config, &req))["revision"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let initial = revision(&first);
    assert_eq!(revision(&first), initial, "stable");
    // Another replica with the same view (its own handle, another source name) agrees.
    assert_eq!(
        revision(&config("list_revision_peer", PublishMode::All)),
        initial
    );
    // The revision names the whole document: another max_age is another document, so a
    // wallet that revalidates with the old revision gets the new body.
    let mut aged = first.clone();
    aged.host_list.max_age_secs = 60;
    assert_ne!(revision(&aged), initial);
    assert_eq!(body(&answer(&aged, &req))["max_age_secs"], 60);
    let mut revalidate = req.clone();
    revalidate.headers = vec![("if-none-match".to_string(), format!("\"{initial}\""))];
    assert_eq!(answer(&aged, &revalidate).status, 200);
    assert_eq!(answer(&first, &revalidate).status, 304);

    // A refresh adds a host: the revision changes, and changes back when it goes.
    let add = serde_json::json!({ "hosts": [
        "https://vote-a.example.org", "https://vote-b.example.org", "https://vote-c.example.org"
    ] });
    assert!(first
        .dynamic_hosts
        .load_document(0, add.to_string().as_bytes())
        .is_success());
    let grown = revision(&first);
    assert_ne!(grown, initial);
    assert_eq!(hosts(&answer(&first, &req)).len(), 4);
    let back = serde_json::json!({ "hosts": ["https://vote-b.example.org", "https://vote-a.example.org"] });
    assert!(first
        .dynamic_hosts
        .load_document(0, back.to_string().as_bytes())
        .is_success());
    assert_eq!(
        revision(&first),
        initial,
        "the order in the document does not matter"
    );

    // A route change is a list change.
    let mut routes = first.clone();
    routes
        .backends_policy
        .get_mut("prices.example.com")
        .unwrap()
        .push(("GET".to_string(), "/v2/quotes".to_string()));
    assert_ne!(revision(&routes), initial);
    // The mode decides what is listed.
    assert_ne!(
        revision(&config("list_revision_dyn", PublishMode::Dynamic)),
        initial
    );
}

#[test]
fn if_none_match_with_the_current_revision_is_a_304() {
    let config = config("list_etag", PublishMode::All);
    let mut req = list_request("ohttp-gateway.example");
    let fresh = answer(&config, &req);
    let etag = header(&fresh, "etag").unwrap().to_string();

    for value in [
        etag.clone(),
        format!("W/{etag}"),
        format!("\"0000000000000000\", {etag}"),
        "*".to_string(),
    ] {
        req.headers = vec![("If-None-Match".to_string(), value.clone())];
        let resp = answer(&config, &req);
        assert_eq!(resp.status, 304, "{value}");
        assert!(resp.body.is_empty());
        assert_eq!(header(&resp, "etag"), Some(etag.as_str()));
        assert_eq!(header(&resp, "cache-control"), Some("max-age=300"));
        assert_eq!(header(&resp, "content-type"), None);
    }
    for value in ["\"0000000000000000\"", "", etag.trim_matches('"')] {
        req.headers = vec![("if-none-match".to_string(), value.to_string())];
        let resp = answer(&config, &req);
        assert_eq!(resp.status, 200, "{value}");
        assert!(!resp.body.is_empty());
    }
    // After the list changed the old revision gets the new document.
    req.headers = vec![("if-none-match".to_string(), etag.clone())];
    let changed = serde_json::json!({ "hosts": ["https://vote-a.example.org"] });
    assert!(config
        .dynamic_hosts
        .load_document(0, changed.to_string().as_bytes())
        .is_success());
    let resp = answer(&config, &req);
    assert_eq!(resp.status, 200);
    assert_ne!(header(&resp, "etag"), Some(etag.as_str()));
}

#[test]
fn the_scope_says_what_the_list_covers() {
    let req = list_request("ohttp-gateway.example");
    let all = body(&answer(&config("scope_all", PublishMode::All), &req));
    let dynamic = body(&answer(
        &config("scope_dynamic", PublishMode::Dynamic),
        &req,
    ));
    assert_eq!(all["scope"], "all");
    assert_eq!(dynamic["scope"], "dynamic");
    assert_ne!(all["revision"], dynamic["revision"]);
    // Same hosts, another scope: another document, another revision.
    let mut only_dynamic_hosts = config("scope_same_hosts", PublishMode::All);
    only_dynamic_hosts.backends.clear();
    let same_hosts = body(&answer(&only_dynamic_hosts, &req));
    assert_eq!(same_hosts["hosts"], dynamic["hosts"]);
    assert_ne!(same_hosts["revision"], dynamic["revision"]);
}

#[test]
fn a_gateway_without_a_complete_list_says_so() {
    let req = list_request("ohttp-gateway.example");
    // A source that was never read since the start: its hosts would be missing from the list
    // while other replicas serve them. No list, so wallets keep the one they hold.
    let mut starting = crate::config::test_config();
    starting.host_list.mode = PublishMode::All;
    starting.dynamic_hosts = DynamicHosts::parse(
        &serde_json::json!([{
            "name": "not_loaded",
            "url": "https://config.example.com/d.json",
            "lists": [{ "pointer": "/hosts", "routes": "GET /*" }],
        }])
        .to_string(),
        Reserved::default(),
        crate::dynamic_hosts::Settings::new("testnet", 4),
    )
    .unwrap();
    let resp = answer(&starting, &req);
    assert_eq!(resp.status, 503);
    assert_eq!(resp.body, b"host list not ready");
    assert_eq!(header(&resp, "cache-control"), Some("no-store"));
    assert_eq!(header(&resp, "etag"), None);
    // A document that cannot be used (here: not JSON) is not a reading of the source.
    assert!(!starting
        .dynamic_hosts
        .load_document(0, b"<html>")
        .is_success());
    assert_eq!(answer(&starting, &req).status, 503);
    // A document that was read and lists no server is: the source has no hosts now, and the
    // list (here: empty) is complete.
    let none = serde_json::json!({ "hosts": [] });
    assert_eq!(
        starting
            .dynamic_hosts
            .load_document(0, none.to_string().as_bytes()),
        crate::dynamic_hosts::RefreshResult::Empty
    );
    let resp = answer(&starting, &req);
    assert_eq!(resp.status, 200);
    assert!(hosts(&resp).is_empty());
    // Once a document with hosts was accepted, they are in it.
    let doc = serde_json::json!({ "hosts": ["https://vote-a.example.org"] });
    assert!(starting
        .dynamic_hosts
        .load_document(0, doc.to_string().as_bytes())
        .is_success());
    assert_eq!(answer(&starting, &req).status, 200);
    // A later failed refresh keeps the last accepted hosts and the list.
    assert!(!starting.dynamic_hosts.load_document(0, b"{}").is_success());
    assert_eq!(hosts(&answer(&starting, &req)).len(), 1);

    // A document larger than wallets accept is not published (and not truncated).
    let mut large = crate::config::test_config();
    large.host_list.mode = PublishMode::All;
    let long_path = format!("/{}", "p".repeat(200));
    for i in 0..1200 {
        let alias = format!("alias-{i}.example.com");
        large
            .backends
            .insert(alias.clone(), "https://upstream.example.com".to_string());
        large
            .backends_policy
            .insert(alias, vec![("GET".to_string(), format!("{long_path}/{i}"))]);
    }
    let resp = answer(&large, &req);
    assert_eq!(resp.status, 503);
    assert_eq!(resp.body, b"host list too large");
    // Just under the bound it is.
    let mut fits = large.clone();
    let keep: Vec<String> = fits.backends.keys().take(900).cloned().collect();
    fits.backends.retain(|alias, _| keep.contains(alias));
    let resp = answer(&fits, &req);
    assert_eq!(resp.status, 200);
    assert!(resp.body.len() <= MAX_HOST_LIST_BYTES && resp.body.len() > 200 * 1024);
}

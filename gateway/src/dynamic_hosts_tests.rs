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

//! Tests of the dynamic third-party hosts: validation, a fake HTTP source, last-known-good,
//! the growth cap, signatures, routing and the swap under load.

use super::*;
use crate::ohttp::InnerRequest;
use crate::proxy::{self, BackendTarget};
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpListener;

/// What the fake source answers for a path.
#[derive(Clone)]
struct Answer {
    status: u16,
    body: Vec<u8>,
    /// Without `content-length`, in small frames.
    chunked: bool,
    /// Never answer.
    hang: bool,
    /// Answer after this long.
    delay: Duration,
}

/// A plain-HTTP source on a loopback port.
#[derive(Clone, Default)]
struct FakeSource {
    answers: Arc<Mutex<HashMap<String, Answer>>>,
    hits: Arc<AtomicUsize>,
}

impl FakeSource {
    async fn start() -> (Self, String) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let source = Self::default();
        let server = source.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let server = server.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let server = server.clone();
                        async move { Ok::<_, Infallible>(server.respond(req.uri().path()).await) }
                    });
                    let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        (source, format!("http://{addr}"))
    }

    async fn respond(&self, path: &str) -> Response<BoxBody<Bytes, Infallible>> {
        self.hits.fetch_add(1, Ordering::SeqCst);
        let answer = self.answers.lock().get(path).cloned();
        let Some(answer) = answer else {
            return Response::builder()
                .status(404)
                .body(Full::new(Bytes::from_static(b"not found")).boxed())
                .unwrap();
        };
        if answer.hang {
            tokio::time::sleep(Duration::from_secs(600)).await;
        }
        tokio::time::sleep(answer.delay).await;
        let body: BoxBody<Bytes, Infallible> = if answer.chunked {
            let frames: Vec<std::result::Result<hyper::body::Frame<Bytes>, Infallible>> = answer
                .body
                .chunks(512)
                .map(|c| Ok(hyper::body::Frame::data(Bytes::copy_from_slice(c))))
                .collect();
            http_body_util::StreamBody::new(futures_util::stream::iter(frames)).boxed()
        } else {
            Full::new(Bytes::from(answer.body)).boxed()
        };
        Response::builder()
            .status(answer.status)
            .body(body)
            .unwrap()
    }

    fn set(&self, path: &str, status: u16, body: impl Into<Vec<u8>>) {
        self.answers.lock().insert(
            path.to_string(),
            Answer {
                status,
                body: body.into(),
                chunked: false,
                hang: false,
                delay: Duration::ZERO,
            },
        );
    }

    fn set_chunked(&self, path: &str, body: impl Into<Vec<u8>>) {
        self.answers.lock().insert(
            path.to_string(),
            Answer {
                status: 200,
                body: body.into(),
                chunked: true,
                hang: false,
                delay: Duration::ZERO,
            },
        );
    }

    fn set_hanging(&self, path: &str) {
        self.answers.lock().insert(
            path.to_string(),
            Answer {
                status: 200,
                body: Vec::new(),
                chunked: false,
                hang: true,
                delay: Duration::ZERO,
            },
        );
    }

    fn set_delayed(&self, path: &str, body: impl Into<Vec<u8>>, delay: Duration) {
        self.answers.lock().insert(
            path.to_string(),
            Answer {
                status: 200,
                body: body.into(),
                chunked: false,
                hang: false,
                delay,
            },
        );
    }

    fn set_hosts(&self, urls: &[&str]) {
        self.set("/doc.json", 200, document(urls));
    }
}

/// `{"servers":[{"url":..,"label":..}], "other": ...}`.
fn document(urls: &[&str]) -> Vec<u8> {
    let servers: Vec<serde_json::Value> = urls
        .iter()
        .map(|u| serde_json::json!({ "url": u, "label": "a server" }))
        .collect();
    serde_json::json!({ "config_version": 1, "servers": servers, "other": {} })
        .to_string()
        .into_bytes()
}

/// One source `name` reading `/servers[].url` from `base`/doc.json, with `extra` fields merged.
fn one_source(name: &str, base: &str, extra: serde_json::Value) -> String {
    let mut source = serde_json::json!({
        "name": name,
        "url": format!("{base}/doc.json"),
        "lists": [{ "pointer": "/servers", "url_field": "url", "routes": "GET /*,POST /v1/*", "read_routes": "GET /*" }],
    });
    if let (Some(target), Some(extra)) = (source.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            target.insert(key.clone(), value.clone());
        }
    }
    serde_json::Value::Array(vec![source]).to_string()
}

/// Sets the flag when it goes out of scope, also on a panic.
struct StopOnDrop<'a>(&'a std::sync::atomic::AtomicBool);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

fn hosts_of(hosts: &DynamicHosts) -> Vec<String> {
    hosts.served().into_iter().map(|(h, _)| h).collect()
}

fn parse(config: &str) -> DynamicHosts {
    DynamicHosts::parse(config, Reserved::default(), Settings::for_tests()).expect("parses")
}

fn parse_error(config: serde_json::Value) -> String {
    DynamicHosts::parse(
        &config.to_string(),
        Reserved::default(),
        Settings::new("testnet", 4),
    )
    .err()
    .expect("refused")
    .to_string()
}

fn get(authority: &str, path: &str) -> InnerRequest {
    request("GET", authority, path)
}

fn request(method: &str, authority: &str, path: &str) -> InnerRequest {
    InnerRequest {
        method: method.to_string(),
        path: path.to_string(),
        authority: authority.to_string(),
        headers: vec![],
        body: vec![],
    }
}

// ---------------------------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------------------------

#[test]
fn listed_urls_must_be_plain_https_hosts() {
    let ok = |url: &str, authority: &str| {
        let target = parse_host_url(url, &[8443], &[]).unwrap_or_else(|e| panic!("{url}: {e}"));
        assert_eq!(target.authority, authority, "{url}");
        assert_eq!(target.base_url, format!("https://{authority}"), "{url}");
    };
    ok("https://vote.example.org", "vote.example.org");
    ok("https://vote.example.org/", "vote.example.org");
    ok("HTTPS://Vote.Example.ORG", "vote.example.org");
    ok("https://vote.example.org:443", "vote.example.org");
    ok("https://vote.example.org:8443", "vote.example.org:8443");
    ok(
        "https://203-0-113-9.dns.example.com",
        "203-0-113-9.dns.example.com",
    );
    ok(
        "https://xn--bcher-kva.example.xn--p1ai",
        "xn--bcher-kva.example.xn--p1ai",
    );
    ok("https://198.51.101.34", "198.51.101.34");

    for (url, why) in [
        ("http://vote.example.org", "scheme"),
        ("ftp://vote.example.org", "scheme"),
        ("vote.example.org", "scheme"),
        ("//vote.example.org", "scheme"),
        ("https://", "invalid host length"),
        ("https://user@vote.example.org", "userinfo"),
        ("https://user:pw@vote.example.org", "userinfo"),
        ("https://vote.example.org/path", "path"),
        ("https://vote.example.org/?q=1", "path"),
        ("https://vote.example.org?q=1", "path"),
        ("https://vote.example.org#frag", "path"),
        ("https://vote.example.org\\@evil.example.com", "path"),
        ("https://vote.example.org:8444", "port not allowed"),
        ("https://vote.example.org:80", "port not allowed"),
        ("https://vote.example.org:0", "invalid port"),
        ("https://vote.example.org:", "invalid port"),
        ("https://vote.example.org:99999", "invalid port"),
        ("https://vote.example.org:44x", "invalid port"),
        ("https://[::1]", "IPv6"),
        ("https://[2001:db8::1]:443", "IPv6"),
        ("https://localhost", "single-label"),
        ("https://gateway", "single-label"),
        ("https://vote.localhost", "special-use"),
        ("https://db.internal", "special-use"),
        ("https://printer.local", "special-use"),
        ("https://1.0.0.127.in-addr.arpa", "special-use"),
        ("https://hidden.onion", "special-use"),
        ("https://127.0.0.1", "not public"),
        ("https://10.1.2.3", "not public"),
        ("https://169.254.169.254", "not public"),
        ("https://192.168.1.1:8443", "not public"),
        ("https://0.0.0.0", "not public"),
        ("https://127.1", "not a DNS name"),
        ("https://2130706433", "single-label"),
        ("https://0x7f.0.0.1", "not a DNS name"),
        ("https://017700000001.example.1", "not a DNS name"),
        ("https://vote..example.org", "invalid DNS label"),
        ("https://.example.org", "invalid DNS label"),
        ("https://vote.example.org.", "invalid DNS label"),
        ("https://-vote.example.org", "invalid DNS label"),
        ("https://vote_1.example.org", "invalid character"),
        (
            "https://vote.example.org%00.evil.example.com",
            "invalid character",
        ),
        ("https://vote.exämple.org", "non-ASCII"),
        ("https://vote.example.org /", "whitespace"),
        ("https://vote.example.org\n", "whitespace"),
        ("", "scheme"),
    ] {
        let err = parse_host_url(url, &[8443], &[]).expect_err(url);
        assert!(err.contains(why), "{url:?}: {err} (expected {why})");
    }
    let long = format!("https://{}.example.org", "a".repeat(600));
    assert_eq!(parse_host_url(&long, &[], &[]), Err("url too long"));
    // 443 only unless the source allows another port.
    assert_eq!(
        parse_host_url("https://vote.example.org:8443", &[], &[]),
        Err("port not allowed")
    );
}

#[test]
fn host_suffixes_are_an_allowlist_on_label_boundaries() {
    let suffixes = vec!["example.org".to_string(), "sub.example.com".to_string()];
    for url in [
        "https://example.org",
        "https://vote.example.org",
        "https://a.b.example.org",
        "https://sub.example.com",
        "https://one.sub.example.com",
    ] {
        assert!(parse_host_url(url, &[], &suffixes).is_ok(), "{url}");
    }
    for url in [
        "https://badexample.org",
        "https://example.org.evil.example.net",
        "https://example.com",
        "https://xsub.example.com",
    ] {
        assert_eq!(
            parse_host_url(url, &[], &suffixes),
            Err("host not under an allowed suffix"),
            "{url}"
        );
    }
}

#[test]
fn only_public_addresses_are_reachable() {
    for ip in [
        "11.22.33.44",
        "198.51.101.34",
        "100.63.255.255",
        "100.128.0.0",
        "172.15.255.255",
        "172.32.0.0",
        "198.17.255.255",
        "198.20.0.0",
        "223.255.255.255",
        "2400:1234::1",
        "2a00:1234:5678::9",
        "::ffff:198.51.101.34",
        "64:ff9b::c633:6522",
    ] {
        assert!(is_public_ip(ip.parse().unwrap()), "{ip} is public");
    }
    for ip in [
        "0.0.0.0",
        "0.1.2.3",
        "10.0.0.1",
        "10.255.255.255",
        "100.64.0.1",
        "100.127.255.255",
        "127.0.0.1",
        "127.255.255.254",
        "169.254.169.254",
        "169.254.0.1",
        "172.16.0.1",
        "172.31.255.255",
        "192.0.0.1",
        "192.0.2.1",
        "192.88.99.1",
        "192.168.0.1",
        "198.18.0.1",
        "198.19.255.255",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "239.255.255.255",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "::7f00:1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:169.254.169.254",
        "64:ff9b::7f00:1",
        "64:ff9b::a9fe:a9fe",
        "64:ff9b:1::1",
        "100::1",
        "2001::1",
        "2001:db8::1",
        "2002:7f00:1::1",
        "3fff::1",
        "fc00::1",
        "fd12:3456::254",
        "fe80::1",
        "fec0::1",
        "ff02::1",
    ] {
        assert!(!is_public_ip(ip.parse().unwrap()), "{ip} is not public");
    }
}

#[tokio::test]
async fn the_resolver_hands_out_public_addresses_only() {
    let addr = |s: &str| -> SocketAddr { s.parse().unwrap() };
    let mixed = vec![
        addr("127.0.0.1:0"),
        addr("198.51.101.34:0"),
        addr("10.0.0.7:0"),
        addr("[::1]:0"),
        addr("[2400:1234::1]:0"),
        addr("169.254.169.254:0"),
    ];
    assert_eq!(
        public_addresses(mixed.into_iter()),
        vec![addr("198.51.101.34:0"), addr("[2400:1234::1]:0")]
    );
    assert!(public_addresses(vec![addr("127.0.0.1:0"), addr("10.0.0.1:0")].into_iter()).is_empty());

    // A name that resolves to loopback only does not resolve for a dynamic host.
    use std::str::FromStr;
    let mut resolver = PublicResolver;
    let refused = tower::Service::call(&mut resolver, Name::from_str("localhost").unwrap()).await;
    let error = refused.err().expect("localhost has no public address");
    // Where the name resolves at all (to loopback), it is the filter that refused it.
    if tokio::net::lookup_host(("localhost", 0)).await.is_ok() {
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }
}

#[test]
fn the_lookup_key_drops_an_explicit_default_port() {
    assert_eq!(authority_key("vote.example.org:443"), "vote.example.org");
    assert_eq!(authority_key("vote.example.org"), "vote.example.org");
    assert_eq!(
        authority_key("vote.example.org:8443"),
        "vote.example.org:8443"
    );
}

#[test]
fn rules_use_the_backends_policy_grammar() {
    assert_eq!(
        parse_rules("routes", "get /*, POST /v1/submit ,* /open/*").unwrap(),
        vec![
            ("GET".to_string(), "/*".to_string()),
            ("POST".to_string(), "/v1/submit".to_string()),
            ("*".to_string(), "/open/*".to_string()),
        ]
    );
    assert!(parse_rules("routes", "").unwrap().is_empty());
    for bad in ["GET", "FETCH /x", "GET x", "GET /a b", "/x"] {
        assert!(parse_rules("routes", bad).is_err(), "{bad}");
    }
}

// ---------------------------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------------------------

#[test]
fn the_feature_is_off_without_sources() {
    let off = DynamicHosts::default();
    assert!(!off.enabled());
    assert!(off.is_empty());
    assert!(off.lookup("vote.example.org").is_none());
    assert!(off.served().is_empty());
    let empty =
        DynamicHosts::parse("[]", Reserved::default(), Settings::new("testnet", 4)).unwrap();
    assert!(!empty.enabled());
}

#[test]
fn a_full_source_configuration_parses() {
    let key = base64::engine::general_purpose::STANDARD.encode(
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes(),
    );
    let hosts = DynamicHosts::parse(
        &serde_json::json!([{
            "name": "services",
            "url": "https://config.example.org/dynamic.json",
            "refresh_secs": 120,
            "lists": [
                { "pointer": "/api_servers", "url_field": "url", "routes": "GET /*,POST /*", "read_routes": "GET /*" },
                { "pointer": "/query_endpoints", "url_field": "url", "routes": "GET /root,POST /v1/query" }
            ],
            "host_suffixes": [".example.org"],
            "allow_ports": [8443],
            "max_hosts": 32,
            "max_new_hosts_per_refresh": 4,
            "rate_limit": "600/60s",
            "signature_url": "https://config.example.org/dynamic.json.sig",
            "signature_keys": [key],
        }, {
            "name": "other_1",
            "url": "https://lists.example.com/hosts.json",
            "lists": [{ "pointer": "", "routes": "GET /status" }],
        }])
        .to_string(),
        Reserved::default(),
        Settings::new("testnet", 4),
    )
    .unwrap();
    assert!(hosts.enabled());
    assert_eq!(hosts.source_names(), vec!["services", "other_1"]);
    let source = &hosts.inner.sources[0];
    assert_eq!(source.label, "dynamic:services");
    assert_eq!(source.refresh, Duration::from_secs(120));
    assert_eq!(source.host_suffixes, vec!["example.org".to_string()]);
    assert_eq!(source.rate_limit, Some((600, Duration::from_secs(60))));
    assert_eq!((source.max_hosts, source.max_new_hosts), (32, 4));
    assert!(source.signature.is_some());
    let defaults = &hosts.inner.sources[1];
    assert_eq!(defaults.refresh, Duration::from_secs(DEFAULT_REFRESH_SECS));
    assert_eq!(
        (defaults.max_hosts, defaults.max_new_hosts),
        (DEFAULT_MAX_HOSTS, DEFAULT_MAX_NEW_HOSTS)
    );
    assert!(defaults.rate_limit.is_none() && defaults.signature.is_none());
}

#[test]
fn a_wrong_source_configuration_is_a_startup_error() {
    let list = serde_json::json!([{ "pointer": "/hosts", "routes": "GET /*" }]);
    let base = |patch: serde_json::Value| {
        let mut source = serde_json::json!({
            "name": "services",
            "url": "https://config.example.org/dynamic.json",
            "lists": list.clone(),
        });
        for (key, value) in patch.as_object().unwrap() {
            if value.is_null() {
                source.as_object_mut().unwrap().remove(key);
            } else {
                source
                    .as_object_mut()
                    .unwrap()
                    .insert(key.clone(), value.clone());
            }
        }
        serde_json::Value::Array(vec![source])
    };
    let key = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
    for (patch, why) in [
        (serde_json::json!({ "unknown_field": 1 }), "Malformed"),
        (serde_json::json!({ "name": "" }), "name"),
        (serde_json::json!({ "name": "Voting" }), "name"),
        (serde_json::json!({ "name": "a b" }), "name"),
        (
            serde_json::json!({ "url": "http://config.example.org/d.json" }),
            "https://",
        ),
        (
            serde_json::json!({ "url": "config.example.org/d.json" }),
            "url",
        ),
        (
            serde_json::json!({ "url": "https://user@config.example.org/d.json" }),
            "userinfo",
        ),
        (serde_json::json!({ "refresh_secs": 5 }), "refresh_secs"),
        (
            serde_json::json!({ "refresh_secs": 1_000_000 }),
            "refresh_secs",
        ),
        (serde_json::json!({ "max_hosts": 0 }), "max_hosts"),
        (serde_json::json!({ "max_hosts": 100_000 }), "max_hosts"),
        (
            serde_json::json!({ "max_hosts": 4, "max_new_hosts_per_refresh": 5 }),
            "max_new_hosts_per_refresh",
        ),
        (
            serde_json::json!({ "max_new_hosts_per_refresh": 0 }),
            "max_new_hosts_per_refresh",
        ),
        (serde_json::json!({ "lists": [] }), "lists"),
        (
            serde_json::json!({ "lists": [{ "pointer": "hosts", "routes": "GET /*" }] }),
            "pointer",
        ),
        (
            serde_json::json!({ "lists": [{ "pointer": "/hosts", "routes": "" }] }),
            "no routes",
        ),
        (
            serde_json::json!({ "lists": [{ "pointer": "/hosts", "routes": "FETCH /*" }] }),
            "method",
        ),
        (
            serde_json::json!({ "lists": [{ "pointer": "/hosts", "routes": "GET /*", "read_routes": "GET x" }] }),
            "path",
        ),
        (
            serde_json::json!({ "lists": [{ "pointer": "/hosts", "url_field": "", "routes": "GET /*" }] }),
            "url_field",
        ),
        (
            serde_json::json!({ "host_suffixes": ["exa mple.org"] }),
            "host_suffixes",
        ),
        (
            serde_json::json!({ "host_suffixes": ["."] }),
            "host_suffixes",
        ),
        (serde_json::json!({ "allow_ports": [0] }), "allow_ports"),
        (serde_json::json!({ "rate_limit": "fast" }), "rate_limit"),
        (serde_json::json!({ "rate_limit": "0/60s" }), "rate_limit"),
        (
            serde_json::json!({ "signature_url": "https://config.example.org/d.sig" }),
            "go together",
        ),
        (
            serde_json::json!({ "signature_keys": [key] }),
            "go together",
        ),
        (
            serde_json::json!({ "signature_url": "https://config.example.org/d.sig", "signature_keys": ["AAAA"] }),
            "signature_keys",
        ),
        (
            serde_json::json!({ "signature_url": "http://config.example.org/d.sig", "signature_keys": [key] }),
            "https://",
        ),
    ] {
        let err = parse_error(base(patch.clone()));
        assert!(err.contains(why), "{patch}: {err}");
    }
    assert!(parse_error(serde_json::json!({ "name": "x" })).contains("Malformed"));
    let source = base(serde_json::json!({}))[0].clone();
    assert!(parse_error(serde_json::json!([source.clone(), source.clone()])).contains("twice"));
    let many: Vec<serde_json::Value> = (0..MAX_SOURCES + 1)
        .map(|i| {
            let mut s = source.clone();
            s["name"] = serde_json::json!(format!("s{i}"));
            s
        })
        .collect();
    assert!(parse_error(serde_json::Value::Array(many)).contains("at most"));
}

#[test]
fn the_next_refresh_comes_sooner_after_a_failure() {
    let long = Duration::from_secs(600);
    let short = Duration::from_secs(30);
    for ok in [
        RefreshResult::Ok,
        RefreshResult::Unchanged,
        RefreshResult::Partial,
    ] {
        assert!(ok.is_success());
        assert_eq!(next_wait(long, ok), long);
    }
    for failed in [
        RefreshResult::FetchError,
        RefreshResult::TooLarge,
        RefreshResult::ParseError,
        RefreshResult::Invalid,
        RefreshResult::Empty,
        RefreshResult::Signature,
    ] {
        assert!(!failed.is_success());
        assert_eq!(next_wait(long, failed), Duration::from_secs(RETRY_SECS));
        assert_eq!(next_wait(short, failed), short);
    }
    for _ in 0..100 {
        let wait = jittered(long);
        assert!(
            wait >= Duration::from_secs(540) && wait <= Duration::from_secs(660),
            "{wait:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// A fake HTTP source
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_source_is_loaded_and_follows_its_document() {
    let (source, base) = FakeSource::start().await;
    let name = "follows";
    let hosts = parse(&one_source(name, &base, serde_json::json!({})));
    assert!(hosts.is_empty(), "nothing before the first refresh");

    source.set_hosts(&["https://a.example.org", "https://b.example.org/"]);
    hosts.refresh_all().await;
    assert_eq!(hosts_of(&hosts), vec!["a.example.org", "b.example.org"]);
    let a = hosts.lookup("a.example.org").expect("served");
    assert_eq!(a.base_url, "https://a.example.org");
    assert_eq!(a.source, name);
    assert_eq!(a.label, "dynamic:follows");
    assert_eq!(
        a.routes,
        vec![
            ("GET".to_string(), "/*".to_string()),
            ("POST".to_string(), "/v1/*".to_string())
        ]
    );
    assert!(a.is_read_route("GET", "/v1/rounds") && !a.is_read_route("POST", "/v1/submit"));
    assert!(hosts.lookup("a.example.org:443").is_some());
    assert!(hosts.lookup("c.example.org").is_none());

    // The publisher adds a server: served after the next refresh, without a restart.
    source.set_hosts(&[
        "https://a.example.org",
        "https://b.example.org",
        "https://c.example.org",
    ]);
    assert_eq!(hosts.refresh_source(0).await, RefreshResult::Ok);
    assert_eq!(
        hosts_of(&hosts),
        vec!["a.example.org", "b.example.org", "c.example.org"]
    );
    // An entry that stays is the same entry: its counters survive the swap.
    assert!(Arc::ptr_eq(&a, &hosts.lookup("a.example.org").unwrap()));

    // ... and removes one.
    source.set_hosts(&["https://b.example.org", "https://c.example.org"]);
    assert_eq!(hosts.refresh_source(0).await, RefreshResult::Ok);
    assert_eq!(hosts_of(&hosts), vec!["b.example.org", "c.example.org"]);
    assert!(hosts.lookup("a.example.org").is_none());

    // The same document again: nothing is rebuilt.
    let b = hosts.lookup("b.example.org").unwrap();
    assert_eq!(hosts.refresh_source(0).await, RefreshResult::Unchanged);
    assert!(Arc::ptr_eq(&b, &hosts.lookup("b.example.org").unwrap()));

    assert_eq!(
        crate::health::dynamic_hosts_refreshes("testnet", name, "ok"),
        3
    );
    assert_eq!(
        crate::health::dynamic_hosts_refreshes("testnet", name, "unchanged"),
        1
    );
    assert_eq!(
        crate::health::dynamic_hosts_gauges("testnet", name),
        (2, 0, 0, 0)
    );
    assert_eq!(source.hits.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn every_failure_keeps_the_last_known_good_hosts() {
    let (source, base) = FakeSource::start().await;
    let name = "lkg";
    let mut settings = Settings::for_tests();
    settings.max_document_bytes = 4096;
    settings.fetch_timeout = Duration::from_millis(400);
    let hosts = DynamicHosts::parse(
        &one_source(name, &base, serde_json::json!({ "max_hosts": 3 })),
        Reserved::default(),
        settings,
    )
    .unwrap();
    source.set_hosts(&["https://a.example.org", "https://b.example.org"]);
    assert_eq!(hosts.refresh_source(0).await, RefreshResult::Ok);
    let good = vec!["a.example.org".to_string(), "b.example.org".to_string()];

    let oversized = {
        let mut doc = document(&["https://c.example.org"]);
        doc.extend(std::iter::repeat(b' ').take(8192));
        doc
    };
    // After each broken answer: the expected result, and the hosts of the last accepted document.
    let expect_kept = |what: &'static str, expected: RefreshResult| {
        let hosts = hosts.clone();
        let good = good.clone();
        async move {
            assert_eq!(hosts.refresh_source(0).await, expected, "{what}");
            assert_eq!(
                hosts_of(&hosts),
                good,
                "{what}: the last accepted hosts stay"
            );
            assert!(hosts.lookup("a.example.org").is_some(), "{what}");
        }
    };
    source.set("/doc.json", 500, document(&["https://c.example.org"]));
    expect_kept("status 500", RefreshResult::FetchError).await;
    source.answers.lock().remove("/doc.json");
    expect_kept("status 404", RefreshResult::FetchError).await;
    source.set("/doc.json", 302, Vec::new());
    expect_kept("a redirect is not followed", RefreshResult::FetchError).await;
    source.set_hanging("/doc.json");
    expect_kept("no answer in time", RefreshResult::FetchError).await;
    source.set("/doc.json", 200, "<html>maintenance</html>");
    expect_kept("not JSON", RefreshResult::ParseError).await;
    source.set("/doc.json", 200, "{\"servers\":[");
    expect_kept("truncated JSON", RefreshResult::ParseError).await;
    source.set("/doc.json", 200, "{\"config_version\":1}");
    expect_kept("list missing", RefreshResult::Invalid).await;
    source.set(
        "/doc.json",
        200,
        "{\"servers\":{\"url\":\"https://c.example.org\"}}",
    );
    expect_kept("list not an array", RefreshResult::Invalid).await;
    source.set_hosts(&[]);
    expect_kept("empty list", RefreshResult::Empty).await;
    source.set_hosts(&[
        "http://c.example.org",
        "https://127.0.0.1",
        "https://localhost",
    ]);
    expect_kept("no valid entry", RefreshResult::Empty).await;
    source.set_hosts(&[
        "https://a.example.org",
        "https://b.example.org",
        "https://c.example.org",
        "https://d.example.org",
    ]);
    expect_kept("more hosts than the cap", RefreshResult::Invalid).await;
    source.set("/doc.json", 200, oversized.clone());
    expect_kept("declared too large", RefreshResult::TooLarge).await;
    source.set_chunked("/doc.json", oversized);
    expect_kept("too large without a length", RefreshResult::TooLarge).await;
    assert_eq!(
        crate::health::dynamic_hosts_refreshes("testnet", name, "fetch_error"),
        4
    );
    assert_eq!(
        crate::health::dynamic_hosts_refreshes("testnet", name, "parse_error"),
        2
    );
    assert_eq!(
        crate::health::dynamic_hosts_refreshes("testnet", name, "invalid"),
        3
    );
    assert_eq!(
        crate::health::dynamic_hosts_refreshes("testnet", name, "empty"),
        2
    );
    assert_eq!(
        crate::health::dynamic_hosts_refreshes("testnet", name, "too_large"),
        2
    );
    assert_eq!(crate::health::dynamic_hosts_gauges("testnet", name).0, 2);

    // A document without a declared length that fits is read.
    source.set_chunked(
        "/doc.json",
        document(&["https://a.example.org", "https://c.example.org"]),
    );
    assert_eq!(hosts.refresh_source(0).await, RefreshResult::Ok);
    assert_eq!(hosts_of(&hosts), vec!["a.example.org", "c.example.org"]);
}

#[tokio::test]
async fn a_source_that_is_down_changes_nothing() {
    // A port nothing listens on.
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };
    let name = "down";
    let hosts = parse(&one_source(
        name,
        &format!("http://127.0.0.1:{port}"),
        serde_json::json!({}),
    ));
    // Down at startup: no host, and the start is not stopped.
    hosts.refresh_all().await;
    assert!(hosts.is_empty());
    assert_eq!(
        crate::health::dynamic_hosts_refreshes("testnet", name, "fetch_error"),
        1
    );
    // Down after a document was accepted: its hosts stay.
    assert_eq!(
        hosts.load_document(0, &document(&["https://a.example.org"])),
        RefreshResult::Ok
    );
    assert_eq!(hosts.refresh_source(0).await, RefreshResult::FetchError);
    assert_eq!(hosts_of(&hosts), vec!["a.example.org"]);
}

#[tokio::test]
async fn invalid_entries_are_skipped_and_counted() {
    let (source, base) = FakeSource::start().await;
    let name = "skips";
    let hosts = parse(&one_source(name, &base, serde_json::json!({})));
    source.set(
        "/doc.json",
        200,
        serde_json::json!({ "servers": [
            { "url": "https://a.example.org", "label": "ok" },
            { "url": "http://plain.example.org" },
            { "url": "https://169.254.169.254/internal" },
            { "url": "https://user:pw@b.example.org" },
            { "label": "no url" },
            { "url": 7 },
            "https://string-not-object.example.org",
            { "url": "https://b.example.org:8443" },
            { "url": "https://B.example.org/" },
        ] })
        .to_string(),
    );
    assert_eq!(hosts.refresh_source(0).await, RefreshResult::Ok);
    assert_eq!(hosts_of(&hosts), vec!["a.example.org", "b.example.org"]);
    assert_eq!(
        crate::health::dynamic_hosts_gauges("testnet", name),
        (2, 0, 0, 7)
    );
}

#[tokio::test]
async fn growth_is_capped_per_refresh_after_the_first_load() {
    let (source, base) = FakeSource::start().await;
    let name = "growth";
    let hosts = parse(&one_source(
        name,
        &base,
        serde_json::json!({ "max_new_hosts_per_refresh": 2 }),
    ));
    // The first load of a process is bounded by max_hosts only.
    source.set_hosts(&[
        "https://a.example.org",
        "https://b.example.org",
        "https://c.example.org",
    ]);
    assert_eq!(hosts.refresh_source(0).await, RefreshResult::Ok);
    assert_eq!(hosts.len(), 3);

    // Five new hosts at once, one removed: two are admitted per refresh, in document order.
    source.set_hosts(&[
        "https://n1.example.org",
        "https://a.example.org",
        "https://n2.example.org",
        "https://b.example.org",
        "https://n3.example.org",
        "https://n4.example.org",
        "https://n5.example.org",
    ]);
    assert_eq!(hosts.refresh_source(0).await, RefreshResult::Partial);
    assert_eq!(
        hosts_of(&hosts),
        vec![
            "a.example.org",
            "b.example.org",
            "n1.example.org",
            "n2.example.org"
        ]
    );
    assert_eq!(
        crate::health::dynamic_hosts_gauges("testnet", name),
        (4, 0, 3, 0)
    );
    // The same document is read again while hosts are held.
    assert_eq!(hosts.refresh_source(0).await, RefreshResult::Partial);
    assert_eq!(hosts.len(), 6);
    assert_eq!(crate::health::dynamic_hosts_gauges("testnet", name).2, 1);
    assert_eq!(hosts.refresh_source(0).await, RefreshResult::Ok);
    assert_eq!(hosts.len(), 7);
    assert_eq!(
        crate::health::dynamic_hosts_gauges("testnet", name),
        (7, 0, 0, 0)
    );
    assert_eq!(hosts.refresh_source(0).await, RefreshResult::Unchanged);
    assert_eq!(
        crate::health::dynamic_hosts_refreshes("testnet", name, "partial"),
        2
    );
}

#[tokio::test]
async fn a_configured_signature_must_verify() {
    use ed25519_dalek::Signer;
    let (source, base) = FakeSource::start().await;
    let name = "signed";
    let signer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let other = ed25519_dalek::SigningKey::from_bytes(&[10u8; 32]);
    let b64 = base64::engine::general_purpose::STANDARD;
    let hosts = parse(&one_source(
        name,
        &base,
        serde_json::json!({
            "signature_url": format!("{base}/doc.json.sig"),
            "signature_keys": [
                b64.encode(other.verifying_key().to_bytes()),
                b64.encode(signer.verifying_key().to_bytes()),
            ],
        }),
    ));

    // Signed, base64 with a trailing newline.
    let first = document(&["https://a.example.org"]);
    source.set("/doc.json", 200, first.clone());
    source.set(
        "/doc.json.sig",
        200,
        format!("{}\n", b64.encode(signer.sign(&first).to_bytes())),
    );
    assert_eq!(hosts.refresh_source(0).await, RefreshResult::Ok);
    assert_eq!(hosts_of(&hosts), vec!["a.example.org"]);

    // A new document under the old signature: refused, the signed hosts stay.
    let second = document(&["https://a.example.org", "https://evil.example.net"]);
    source.set("/doc.json", 200, second.clone());
    assert_eq!(hosts.refresh_source(0).await, RefreshResult::Signature);
    assert_eq!(hosts_of(&hosts), vec!["a.example.org"]);

    // Signed by a key that is not configured.
    let stranger = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
    source.set(
        "/doc.json.sig",
        200,
        b64.encode(stranger.sign(&second).to_bytes()),
    );
    assert_eq!(hosts.refresh_source(0).await, RefreshResult::Signature);
    // Not a signature at all; too large; missing.
    source.set("/doc.json.sig", 200, "not a signature");
    assert_eq!(hosts.refresh_source(0).await, RefreshResult::Signature);
    source.set("/doc.json.sig", 200, vec![b'A'; 4096]);
    assert_eq!(hosts.refresh_source(0).await, RefreshResult::Signature);
    source.answers.lock().remove("/doc.json.sig");
    assert_eq!(hosts.refresh_source(0).await, RefreshResult::FetchError);
    assert_eq!(hosts_of(&hosts), vec!["a.example.org"]);

    // The raw 64 bytes, by the second configured key.
    let third = document(&["https://b.example.org"]);
    source.set("/doc.json", 200, third.clone());
    source.set("/doc.json.sig", 200, other.sign(&third).to_bytes().to_vec());
    assert_eq!(hosts.refresh_source(0).await, RefreshResult::Ok);
    assert_eq!(hosts_of(&hosts), vec!["b.example.org"]);
    assert_eq!(
        crate::health::dynamic_hosts_refreshes("testnet", name, "signature"),
        4
    );
}

#[tokio::test]
async fn one_refresh_has_one_time_budget_for_document_and_signature() {
    let (source, base) = FakeSource::start().await;
    let name = "budget";
    let key = base64::engine::general_purpose::STANDARD.encode(
        ed25519_dalek::SigningKey::from_bytes(&[12u8; 32])
            .verifying_key()
            .to_bytes(),
    );
    let mut settings = Settings::for_tests();
    settings.fetch_timeout = Duration::from_millis(1000);
    let hosts = DynamicHosts::parse(
        &one_source(
            name,
            &base,
            serde_json::json!({ "signature_url": format!("{base}/doc.json.sig"), "signature_keys": [key] }),
        ),
        Reserved::default(),
        settings,
    )
    .unwrap();
    // The document takes more than half of the budget, the signature never comes: with one
    // budget the refresh ends after 1 s; with one budget per fetch it would take 1.6 s.
    source.set_delayed(
        "/doc.json",
        document(&["https://a.example.org"]),
        Duration::from_millis(600),
    );
    source.set_hanging("/doc.json.sig");
    // What the start of the gateway waits for.
    let started = std::time::Instant::now();
    hosts.refresh_all().await;
    let took = started.elapsed();
    assert!(took >= Duration::from_millis(950), "{took:?}");
    assert!(
        took < Duration::from_millis(1500),
        "{took:?}: not one timeout per fetch"
    );
    assert!(hosts.is_empty());
    assert_eq!(
        crate::health::dynamic_hosts_refreshes("testnet", name, "fetch_error"),
        1
    );
}

// ---------------------------------------------------------------------------------------------
// Composition
// ---------------------------------------------------------------------------------------------

#[test]
fn static_configuration_wins_over_a_source() {
    let name = "shadow";
    let reserved = Reserved {
        aliases: ["a.example.org".to_string(), "p.example.org:443".to_string()]
            .into_iter()
            .collect(),
        gateway_hosts: ["ohttp-gateway.example.com".to_string()]
            .into_iter()
            .collect(),
        targets: ["upstream.example.net".to_string()].into_iter().collect(),
    };
    let hosts = DynamicHosts::for_tests(
        name,
        "GET /*",
        &[
            "https://a.example.org",
            "https://p.example.org",
            "https://ohttp-gateway.example.com",
            "https://ohttp-gateway.example.com:8443",
            "https://upstream.example.net",
            "https://b.example.org",
        ],
        reserved,
    );
    // allow_ports is empty in for_tests: the :8443 entry is refused by validation.
    assert_eq!(hosts_of(&hosts), vec!["b.example.org"]);
    assert!(hosts.lookup("a.example.org").is_none());
    assert!(hosts.lookup("ohttp-gateway.example.com").is_none());
    // ... and so is the target of a static alias, under its own name.
    assert!(hosts.lookup("upstream.example.net").is_none());
    assert_eq!(
        crate::health::dynamic_hosts_gauges("testnet", name),
        (1, 4, 0, 1)
    );
}

#[test]
fn the_first_source_owns_a_host_two_sources_list() {
    let list = |routes: &str| serde_json::json!([{ "pointer": "/hosts", "routes": routes }]);
    let hosts = parse(
        &serde_json::json!([
            { "name": "first_src", "url": "https://one.example.com/h.json", "lists": list("GET /one/*") },
            { "name": "second_src", "url": "https://two.example.com/h.json", "lists": list("GET /two/*") },
        ])
        .to_string(),
    );
    let doc = |urls: &[&str]| {
        serde_json::json!({ "hosts": urls })
            .to_string()
            .into_bytes()
    };
    // The second source loads first, then the first one claims the shared host.
    assert_eq!(
        hosts.load_document(
            1,
            &doc(&["https://shared.example.org", "https://two.example.org"])
        ),
        RefreshResult::Ok
    );
    assert_eq!(
        hosts.lookup("shared.example.org").unwrap().source,
        "second_src"
    );
    assert_eq!(
        hosts.load_document(
            0,
            &doc(&["https://shared.example.org", "https://one.example.org"])
        ),
        RefreshResult::Ok
    );
    let shared = hosts.lookup("shared.example.org").unwrap();
    assert_eq!(shared.source, "first_src");
    assert_eq!(
        shared.routes,
        vec![("GET".to_string(), "/one/*".to_string())]
    );
    assert_eq!(hosts.len(), 3);
    assert_eq!(
        crate::health::dynamic_hosts_gauges("testnet", "first_src"),
        (2, 0, 0, 0)
    );
    assert_eq!(
        crate::health::dynamic_hosts_gauges("testnet", "second_src").0,
        1
    );
    assert_eq!(
        crate::health::dynamic_hosts_gauges("testnet", "second_src").1,
        1
    );
    // A failure of one source leaves the other's hosts alone.
    assert_eq!(
        hosts.load_document(0, b"not json"),
        RefreshResult::ParseError
    );
    assert_eq!(hosts.len(), 3);
    // The first source drops the host: the second serves it again.
    assert_eq!(
        hosts.load_document(0, &doc(&["https://one.example.org"])),
        RefreshResult::Ok
    );
    assert_eq!(
        hosts.lookup("shared.example.org").unwrap().source,
        "second_src"
    );
}

#[test]
fn a_host_in_two_lists_gets_both_route_sets() {
    let hosts = parse(
        &serde_json::json!([{
            "name": "two_lists",
            "url": "https://config.example.com/d.json",
            "lists": [
                { "pointer": "/api_servers", "url_field": "url", "routes": "GET /*,POST /*", "read_routes": "GET /*" },
                { "pointer": "/query/endpoints", "url_field": "url", "routes": "GET /root,POST /v1/query,GET /*", "read_routes": "POST /v1/query" },
            ],
        }])
        .to_string(),
    );
    let doc = serde_json::json!({
        "api_servers": [{ "url": "https://vote.example.org" }, { "url": "https://both.example.org" }],
        "query": { "endpoints": [{ "url": "https://both.example.org/" }, { "url": "https://query.example.org" }] },
    });
    assert_eq!(
        hosts.load_document(0, doc.to_string().as_bytes()),
        RefreshResult::Ok
    );
    let rule = |m: &str, p: &str| (m.to_string(), p.to_string());
    assert_eq!(
        hosts.lookup("vote.example.org").unwrap().routes,
        vec![rule("GET", "/*"), rule("POST", "/*")]
    );
    let query = hosts.lookup("query.example.org").unwrap();
    assert_eq!(
        query.routes,
        vec![
            rule("GET", "/root"),
            rule("POST", "/v1/query"),
            rule("GET", "/*")
        ]
    );
    assert!(query.is_read_route("POST", "/v1/query") && !query.is_read_route("GET", "/root"));
    let both = hosts.lookup("both.example.org").unwrap();
    assert_eq!(
        both.routes,
        vec![
            rule("GET", "/*"),
            rule("POST", "/*"),
            rule("GET", "/root"),
            rule("POST", "/v1/query")
        ]
    );
    // A READ only where every list that allows the operation calls it one: the first list
    // allows POST /v1/query (POST /*) as a WRITE, the other list allows GET /x as a WRITE.
    assert!(!both.is_read_route("POST", "/v1/query"));
    assert!(!both.is_read_route("GET", "/x"));
    assert!(!both.is_read_route("POST", "/submit"));
    assert!(!both.is_read_route("DELETE", "/x"), "not allowed at all");
}

#[test]
fn a_document_of_junk_entries_is_bounded() {
    let hosts = parse(
        &serde_json::json!([{
            "name": "junk",
            "url": "https://config.example.com/d.json",
            "max_hosts": 2,
            "lists": [{ "pointer": "/hosts", "routes": "GET /*" }],
        }])
        .to_string(),
    );
    let junk: Vec<String> = (0..9)
        .map(|i| format!("http://junk{i}.example.org"))
        .collect();
    let doc = serde_json::json!({ "hosts": junk }).to_string();
    assert_eq!(
        hosts.load_document(0, doc.as_bytes()),
        RefreshResult::Invalid
    );
    // Deeply nested input is refused by the parser, not by the stack.
    let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    assert_eq!(
        hosts.load_document(0, deep.as_bytes()),
        RefreshResult::ParseError
    );
    assert!(hosts.is_empty());
}

// ---------------------------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------------------------

fn routed_config(source: &str, urls: &[&str]) -> crate::config::Config {
    let mut config = crate::config::test_config();
    config.backends.insert(
        "prices.example.com".to_string(),
        "https://prices-upstream.example.com".to_string(),
    );
    config.backends_policy.insert(
        "prices.example.com".to_string(),
        vec![("GET".to_string(), "/v1/quotes".to_string())],
    );
    config.dynamic_hosts = DynamicHosts::for_tests(
        source,
        "GET /shielded-vote/*,POST /shielded-vote/v1/submit",
        urls,
        Reserved {
            aliases: config.backends.keys().cloned().collect(),
            gateway_hosts: config.gateway_hosts.iter().cloned().collect(),
            targets: static_target_hosts(config.backends.values(), &config.lwd_addr),
        },
    );
    config
}

fn upstream(target: BackendTarget) -> Option<(String, String)> {
    match target {
        BackendTarget::Upstream { uri, label } => Some((uri, label)),
        _ => None,
    }
}

#[test]
fn a_dynamic_host_is_forwarded_to_itself_on_its_routes_only() {
    let config = routed_config(
        "route",
        &["https://vote.example.org", "https://prices.example.com"],
    );
    let req = get("vote.example.org", "/shielded-vote/v1/rounds?active=1");
    assert_eq!(
        upstream(proxy::resolve_backend(&config, &req)),
        Some((
            "https://vote.example.org/shielded-vote/v1/rounds?active=1".to_string(),
            "dynamic:route".to_string()
        ))
    );
    assert!(
        !proxy::resolve_backend(&config, &req).is_lwd(),
        "never the response cache"
    );
    assert!(!proxy::policy_denies(&config, &req));
    assert_eq!(proxy::rpc_label(&config, &req), "GET /shielded-vote/*");
    assert_eq!(proxy::loggable_route(&config, &req), "/shielded-vote/*");
    assert_eq!(
        proxy::backend_label(&config, "vote.example.org"),
        "dynamic:route"
    );
    assert_eq!(
        proxy::RouteContext::resolve(&config, &req).dynamic_read(&req),
        Some(true)
    );
    // An explicit default port names the same host.
    assert!(upstream(proxy::resolve_backend(
        &config,
        &get("vote.example.org:443", "/shielded-vote/x")
    ))
    .is_some());

    // Outside the list's routes: refused, labelled without the path.
    for denied in [
        request("DELETE", "vote.example.org", "/shielded-vote/v1/rounds"),
        request("POST", "vote.example.org", "/shielded-vote/v1/other"),
        get("vote.example.org", "/admin"),
        get("vote.example.org", "/shielded-votes"),
    ] {
        assert!(
            proxy::policy_denies(&config, &denied),
            "{} {}",
            denied.method,
            denied.path
        );
        assert_eq!(proxy::rpc_label(&config, &denied), "other");
        assert_eq!(proxy::loggable_route(&config, &denied), "(not in policy)");
    }
    // Encoded dots are refused under a matching rule too.
    assert!(proxy::policy_denies(
        &config,
        &get("vote.example.org", "/shielded-vote/%2e%2e/admin")
    ));
    let submit = request("POST", "vote.example.org", "/shielded-vote/v1/submit");
    assert!(!proxy::policy_denies(&config, &submit));
    assert_eq!(
        proxy::RouteContext::resolve(&config, &submit).dynamic_read(&submit),
        Some(false),
        "a WRITE for the replay check"
    );

    // BACKENDS_POLICY_DEFAULT=allow opens nothing for a dynamic host.
    let mut open = config.clone();
    open.backends_policy_default_allow = true;
    assert!(proxy::policy_denies(
        &open,
        &get("vote.example.org", "/admin")
    ));

    // A host no source lists is unknown, as before.
    assert!(matches!(
        proxy::resolve_backend(&config, &get("other.example.org", "/shielded-vote/x")),
        BackendTarget::Rejected
    ));
    assert_eq!(proxy::backend_label(&config, "other.example.org"), "other");
    // The gateway's own name stays lightwalletd.
    assert!(proxy::resolve_backend(&config, &get("ohttp-gateway.example", "/x")).is_lwd());
}

#[test]
fn a_static_alias_wins_at_resolution() {
    // The source lists the alias' name; for_tests reserved it, and a snapshot that held it
    // anyway would still lose to the static map.
    let config = routed_config(
        "static_wins",
        &["https://vote.example.org", "https://prices.example.com"],
    );
    config
        .dynamic_hosts
        .insert_unvalidated("prices.example.com", "https://elsewhere.example.net");
    config
        .dynamic_hosts
        .insert_unvalidated("ohttp-gateway.example", "https://elsewhere.example.net");
    let req = get("prices.example.com", "/v1/quotes");
    assert_eq!(
        upstream(proxy::resolve_backend(&config, &req)),
        Some((
            "https://prices-upstream.example.com/v1/quotes".to_string(),
            "prices.example.com".to_string()
        ))
    );
    assert!(proxy::dynamic_host(&config, "prices.example.com").is_none());
    assert_eq!(
        proxy::backend_label(&config, "prices.example.com"),
        "prices.example.com"
    );
    assert_eq!(proxy::rpc_label(&config, &req), "GET /v1/quotes");
    assert!(proxy::RouteContext::resolve(&config, &req)
        .dynamic()
        .is_none());
    assert_eq!(
        proxy::RouteContext::resolve(&config, &req).dynamic_read(&req),
        None
    );
    assert!(proxy::dynamic_host(&config, "ohttp-gateway.example").is_none());
    assert!(proxy::resolve_backend(&config, &get("ohttp-gateway.example", "/x")).is_lwd());

    // The connector would not resolve an address literal, so a non-public literal that
    // reached the served set anyway is refused when it is resolved as a target.
    for literal in ["127.0.0.1", "10.0.0.7:8443", "169.254.169.254"] {
        config
            .dynamic_hosts
            .insert_unvalidated(literal, &format!("https://{literal}"));
        assert!(
            matches!(
                proxy::resolve_backend(&config, &get(literal, "/x")),
                BackendTarget::Rejected
            ),
            "{literal}"
        );
    }
    config
        .dynamic_hosts
        .insert_unvalidated("198.51.101.34", "https://198.51.101.34");
    assert!(upstream(proxy::resolve_backend(&config, &get("198.51.101.34", "/x"))).is_some());
}

#[test]
fn the_per_host_cap_is_counted_in_the_entry() {
    let hosts = DynamicHosts::for_tests(
        "cap",
        "GET /*",
        &["https://a.example.org", "https://b.example.org"],
        Reserved::default(),
    );
    let a = hosts.lookup("a.example.org").unwrap();
    assert_eq!(a.check_rate(), Ok(()));
    assert_eq!(a.check_rate(), Ok(()));
    let retry_after = a.check_rate().expect_err("2/60s is spent");
    assert!((1..=60).contains(&retry_after));
    // Per host, not per source.
    assert_eq!(hosts.lookup("b.example.org").unwrap().check_rate(), Ok(()));
    assert_eq!(a.semaphore.available_permits(), 4);
    // The cap survives a refresh that keeps the host.
    let doc = serde_json::json!({ "hosts": ["https://a.example.org", "https://c.example.org"] });
    assert_eq!(
        hosts.load_document(0, doc.to_string().as_bytes()),
        RefreshResult::Ok
    );
    assert!(hosts.lookup("a.example.org").unwrap().check_rate().is_err());
}

#[test]
fn the_served_set_is_swapped_whole_under_load() {
    let config = routed_config("swap", &["https://a.example.org", "https://b.example.org"]);
    let doc = |urls: &[&str]| {
        serde_json::json!({ "hosts": urls })
            .to_string()
            .into_bytes()
    };
    let first = doc(&["https://a.example.org", "https://b.example.org"]);
    let second = doc(&[
        "https://b.example.org",
        "https://c.example.org",
        "https://d.example.org",
    ]);
    let set_one = vec!["a.example.org".to_string(), "b.example.org".to_string()];
    let set_two = vec![
        "b.example.org".to_string(),
        "c.example.org".to_string(),
        "d.example.org".to_string(),
    ];
    let stop = std::sync::atomic::AtomicBool::new(false);
    let resolved = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        // Whatever happens to this thread, the workers are told to stop.
        let _stop = StopOnDrop(&stop);
        for _ in 0..6 {
            scope.spawn(|| {
                while !stop.load(Ordering::Relaxed) {
                    // The host in both documents is served at every moment.
                    let b =
                        proxy::resolve_backend(&config, &get("b.example.org", "/shielded-vote/x"));
                    assert_eq!(
                        upstream(b),
                        Some((
                            "https://b.example.org/shielded-vote/x".to_string(),
                            "dynamic:swap".to_string()
                        ))
                    );
                    // A host in one of them is served or unknown, never anything else.
                    for host in ["a.example.org", "c.example.org"] {
                        match proxy::resolve_backend(&config, &get(host, "/shielded-vote/x")) {
                            BackendTarget::Upstream { uri, label } => {
                                assert_eq!(uri, format!("https://{host}/shielded-vote/x"));
                                assert_eq!(label, "dynamic:swap");
                            }
                            BackendTarget::Rejected => {}
                            _ => panic!("{host}: neither served nor unknown"),
                        }
                    }
                    // What is served is one document's hosts, never a mix and never nothing.
                    let served = hosts_of(&config.dynamic_hosts);
                    assert!(served == set_one || served == set_two, "{served:?}");
                    assert!(!proxy::policy_denies(
                        &config,
                        &get("b.example.org", "/shielded-vote/x")
                    ));
                    resolved.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
        for round in 0..400 {
            let document = if round % 2 == 0 { &second } else { &first };
            assert!(config.dynamic_hosts.load_document(0, document).is_success());
            // A failing refresh in between changes nothing.
            assert_eq!(
                config.dynamic_hosts.load_document(0, b"{}"),
                RefreshResult::Invalid
            );
        }
        // Bounded: a worker that failed an assertion stops counting, and its panic is
        // reported when the scope ends.
        let give_up = std::time::Instant::now() + Duration::from_secs(30);
        while resolved.load(Ordering::Relaxed) < 600 && std::time::Instant::now() < give_up {
            std::thread::yield_now();
        }
        stop.store(true, Ordering::Relaxed);
    });
    assert!(resolved.load(Ordering::Relaxed) >= 600, "the workers ran");
    assert_eq!(hosts_of(&config.dynamic_hosts), set_one);
}

#[test]
fn a_request_keeps_the_entry_it_resolved_across_a_refresh() {
    let config = routed_config(
        "pinned",
        &["https://vote.example.org", "https://b.example.org"],
    );
    let req = get("vote.example.org", "/shielded-vote/v1/rounds?id=7");
    // What the handler does first: read the served set once.
    let route = proxy::RouteContext::resolve(&config, &req);
    assert_eq!(route.dynamic_read(&req), Some(true));

    // A refresh removes the host while the request is between its replay check and the forward.
    let doc = serde_json::json!({ "hosts": ["https://b.example.org"] });
    assert_eq!(
        config
            .dynamic_hosts
            .load_document(0, doc.to_string().as_bytes()),
        RefreshResult::Ok
    );
    assert!(
        matches!(
            proxy::resolve_backend(&config, &req),
            BackendTarget::Rejected
        ),
        "new requests: unknown"
    );

    // The request in hand is still the one that was classified: same target, same policy,
    // same labels, and its path is still logged as the route pattern, never raw.
    assert_eq!(
        upstream(proxy::resolve_backend_in(&config, &req, &route)),
        Some((
            "https://vote.example.org/shielded-vote/v1/rounds?id=7".to_string(),
            "dynamic:pinned".to_string()
        ))
    );
    assert!(!proxy::policy_denies_in(&config, &req, &route));
    assert_eq!(
        proxy::loggable_route_in(&config, &req, &route),
        "/shielded-vote/*"
    );
    assert_eq!(
        proxy::rpc_label_in(&config, &req, &route),
        "GET /shielded-vote/*"
    );
    assert_eq!(
        route.backend_label(&config, &req.authority),
        "dynamic:pinned"
    );
    assert_eq!(route.dynamic_read(&req), Some(true));

    // The other way round: a context taken before a host appeared does not pick it up.
    let late = get("c.example.org", "/shielded-vote/x");
    let before = proxy::RouteContext::resolve(&config, &late);
    let doc = serde_json::json!({ "hosts": ["https://b.example.org", "https://c.example.org"] });
    assert!(config
        .dynamic_hosts
        .load_document(0, doc.to_string().as_bytes())
        .is_success());
    assert!(matches!(
        proxy::resolve_backend_in(&config, &late, &before),
        BackendTarget::Rejected
    ));
    assert!(upstream(proxy::resolve_backend(&config, &late)).is_some());
}

#[test]
fn read_routes_never_reach_beyond_their_own_list() {
    // One list allows a query and (too broadly) calls every POST a READ; the other allows a
    // submission and declares no READ. A document that puts one host in both must not turn
    // the submission into a READ.
    let hosts = parse(
        &serde_json::json!([{
            "name": "read_scope",
            "url": "https://config.example.com/d.json",
            "rate_limit": "2/60s",
            "lists": [
                { "pointer": "/query", "routes": "POST /query", "read_routes": "POST /*" },
                { "pointer": "/submit", "routes": "POST /submit,POST /query" },
            ],
        }])
        .to_string(),
    );
    let doc = |query: &[&str], submit: &[&str]| {
        serde_json::json!({ "query": query, "submit": submit })
            .to_string()
            .into_bytes()
    };
    assert_eq!(
        hosts.load_document(
            0,
            &doc(
                &["https://q.example.org", "https://both.example.org"],
                &["https://both.example.org", "https://s.example.org"]
            )
        ),
        RefreshResult::Ok
    );
    let q = hosts.lookup("q.example.org").unwrap();
    assert!(q.is_read_route("POST", "/query"));
    assert!(
        !q.is_read_route("POST", "/submit"),
        "not allowed there, so not a READ either"
    );
    let s = hosts.lookup("s.example.org").unwrap();
    assert!(!s.is_read_route("POST", "/submit") && !s.is_read_route("POST", "/query"));
    let both = hosts.lookup("both.example.org").unwrap();
    assert_eq!(both.routes.len(), 2);
    assert!(
        !both.is_read_route("POST", "/submit"),
        "the submit list's WRITE stays a WRITE"
    );
    assert!(
        !both.is_read_route("POST", "/query"),
        "the lists disagree: a WRITE"
    );

    // The limits are the host's: spend the cap, then let the document move the host from one
    // list to the other. Its routes change, its window and permits do not.
    assert!(q.check_rate().is_ok() && q.check_rate().is_ok() && q.check_rate().is_err());
    let permit = q.semaphore.clone().try_acquire_owned().unwrap();
    assert_eq!(
        hosts.load_document(
            0,
            &doc(
                &["https://both.example.org"],
                &["https://q.example.org", "https://s.example.org"]
            )
        ),
        RefreshResult::Ok
    );
    let moved = hosts.lookup("q.example.org").unwrap();
    assert!(
        !Arc::ptr_eq(&q, &moved),
        "a new entry with the other list's routes"
    );
    assert!(!moved.is_read_route("POST", "/query"));
    assert!(
        moved.check_rate().is_err(),
        "the spent window moved with the host"
    );
    assert_eq!(
        moved.semaphore.available_permits(),
        3,
        "and so did the permit in use"
    );
    drop(permit);
    assert_eq!(moved.semaphore.available_permits(), 4);
    // A host that leaves the source and returns starts anew.
    assert_eq!(
        hosts.load_document(
            0,
            &doc(&["https://both.example.org"], &["https://s.example.org"])
        ),
        RefreshResult::Ok
    );
    assert_eq!(
        hosts.load_document(
            0,
            &doc(&["https://q.example.org"], &["https://s.example.org"])
        ),
        RefreshResult::Ok
    );
    assert!(hosts.lookup("q.example.org").unwrap().check_rate().is_ok());
}

// ---------------------------------------------------------------------------------------------
// The forwarders
// ---------------------------------------------------------------------------------------------

fn state(config: crate::config::Config) -> Arc<crate::AppState> {
    let lwd_semaphore = Arc::new(Semaphore::new(128));
    let sources = Arc::new(crate::lwd::LwdSources::new(
        config.clone(),
        lwd_semaphore.clone(),
    ));
    let flights = Arc::new(crate::singleflight::RpcFlights::new(
        sources.clone(),
        config.network.clone(),
    ));
    let mempool = Arc::new(crate::mempool::MempoolFanout::new(
        sources.clone(),
        config.network.clone(),
    ));
    Arc::new(crate::AppState {
        config,
        origin: crate::origin::OriginSettings::default(),
        cache: None,
        hpke: None,
        block_cache: None,
        subtree_cache: None,
        follower: None,
        mempool,
        flights,
        sources,
        signing: None,
        lwd_semaphore,
        global_semaphore: Arc::new(Semaphore::new(256)),
        cache_get_semaphore: Arc::new(Semaphore::new(64)),
        large_response_semaphore: Arc::new(Semaphore::new(2)),
        third_party: Default::default(),
        per_backend_semaphores: Arc::new(parking_lot::RwLock::new(HashMap::new())),
        request_semaphore: Arc::new(Semaphore::new(1024)),
    })
}

async fn streamed(
    state: &Arc<crate::AppState>,
    req: &InnerRequest,
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    use futures_util::StreamExt;
    let (status, headers, mut stream) =
        proxy::forward_to_backend_stream(state, req, uuid::Uuid::new_v4(), None)
            .await
            .expect("an inner answer");
    let mut body = Vec::new();
    while let Some(frame) = stream.next().await {
        if let Ok(crate::chunked_stream::UpFrame::Data(data)) = frame {
            body.extend_from_slice(&data);
        }
    }
    (status, headers, body)
}

#[tokio::test]
async fn the_forwarders_refuse_what_a_dynamic_host_may_not_do() {
    let mut config = routed_config("forward", &["https://vote.example.org"]);
    // Credentials configured for the same name never reach a dynamic host; the refusals below
    // happen before any request is built, so this only documents the configuration.
    config.backend_headers.insert(
        "vote.example.org".to_string(),
        vec![("Authorization".to_string(), "Bearer secret".to_string())],
    );
    let state = state(config);

    // Outside the routes: inner 403 from both forwarders, nothing is sent.
    let denied = request("DELETE", "vote.example.org", "/shielded-vote/v1/rounds");
    let buffered = proxy::forward_to_backend(&state, &denied).await.unwrap();
    assert_eq!(
        (buffered.status, buffered.body.as_slice()),
        (403, b"policy denied".as_slice())
    );
    let (status, _, body) = streamed(&state, &denied).await;
    assert_eq!(
        (status, body.as_slice()),
        (403, b"policy denied".as_slice())
    );

    // The per-host cap (2/60s in for_tests) spent: inner 429 with retry-after from both.
    let host = state
        .config
        .dynamic_hosts
        .lookup("vote.example.org")
        .unwrap();
    assert!(host.check_rate().is_ok() && host.check_rate().is_ok());
    let allowed = get("vote.example.org", "/shielded-vote/v1/rounds");
    let limited = proxy::forward_to_backend(&state, &allowed).await.unwrap();
    assert_eq!(limited.status, 429);
    assert!(limited.headers.iter().any(|(k, _)| k == "retry-after"));
    let (status, headers, _) = streamed(&state, &allowed).await;
    assert_eq!(status, 429);
    assert!(headers.iter().any(|(k, _)| k == "retry-after"));
    assert_eq!(host.semaphore.available_permits(), 4, "no permit is kept");

    // An unknown host: inner 403 unknown authority, as before the feature.
    let unknown = proxy::forward_to_backend(&state, &get("other.example.org", "/shielded-vote/x"))
        .await
        .unwrap();
    assert_eq!(
        (unknown.status, unknown.body.as_slice()),
        (403, b"unknown authority".as_slice())
    );
}

#[tokio::test]
async fn a_dynamic_host_that_resolves_to_a_private_address_is_not_connected_to() {
    // A local listener, and an entry pointing at it by a name that resolves to loopback.
    // Validation would never admit this entry; the connect-time check must hold on its own
    // (it is what stands when a public name is re-pointed at a private address).
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    tokio::spawn(async move {
        while listener.accept().await.is_ok() {
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });

    let config = routed_config("rebind", &["https://vote.example.org"]);
    let authority = format!("localhost:{port}");
    config
        .dynamic_hosts
        .insert_unvalidated(&authority, &format!("https://{authority}"));
    let state = state(config);
    let req = get(&authority, "/anything");
    assert!(upstream(proxy::resolve_backend(&state.config, &req)).is_some());

    let buffered = proxy::forward_to_backend(&state, &req).await;
    assert!(buffered.is_err(), "no connection, so no answer");
    let streamed = proxy::forward_to_backend_stream(&state, &req, uuid::Uuid::new_v4(), None).await;
    assert!(streamed.is_err());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "the listener saw no connection"
    );
}

#[test]
fn the_targets_of_static_aliases_are_not_served_from_a_source() {
    assert_eq!(
        static_target_hosts(
            [
                "https://Prices-Upstream.example.com/v1".to_string(),
                "http://user@plain.example.com:8080".to_string(),
                "bare.example.com:9000".to_string(),
                "https://[2001:db8::1]:8443/x".to_string(),
                "http://Dotted.example.com.:8080".to_string(),
            ]
            .iter(),
            "lwd.example.com:9067",
        ),
        [
            "prices-upstream.example.com",
            "plain.example.com",
            "bare.example.com",
            "2001:db8::1",
            "dotted.example.com",
            "lwd.example.com"
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<HashSet<_>>()
    );
    // The alias `prices.example.com` forwards to `prices-upstream.example.com` on one route.
    // A document that lists the upstream itself would open it on the list's routes.
    let config = routed_config(
        "targets",
        &[
            "https://vote.example.org",
            "https://prices-upstream.example.com",
        ],
    );
    assert_eq!(hosts_of(&config.dynamic_hosts), vec!["vote.example.org"]);
    assert!(matches!(
        proxy::resolve_backend(
            &config,
            &get("prices-upstream.example.com", "/shielded-vote/x")
        ),
        BackendTarget::Rejected
    ));
    assert_eq!(
        crate::health::dynamic_hosts_gauges("testnet", "targets"),
        (1, 1, 0, 0)
    );
}

#[test]
fn denied_blocks_are_never_connected_to() {
    let deny =
        parse_deny_cidrs("198.51.101.0/24, 2400:1234::/32,203.0.114.7 ,2a00:1234:5678::9/128")
            .unwrap();
    assert_eq!(deny.len(), 4);
    let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
    for denied in [
        "198.51.101.0",
        "198.51.101.34",
        "198.51.101.255",
        "::ffff:198.51.101.34",
        "64:ff9b::c633:6522",
        "2400:1234::1",
        "2400:1234:ffff::1",
        "203.0.114.7",
        "2a00:1234:5678::9",
    ] {
        assert!(!allowed_ip(ip(denied), &deny), "{denied}");
    }
    for allowed in [
        "198.51.102.1",
        "198.51.100.255",
        "203.0.114.8",
        "2400:1235::1",
        "2a00:1234:5678::a",
        "11.22.33.44",
    ] {
        // 198.51.100.0/24 is documentation space: not public, whatever the list says.
        assert_eq!(
            allowed_ip(ip(allowed), &deny),
            is_public_ip(ip(allowed)),
            "{allowed}"
        );
    }
    assert!(allowed_ip(ip("198.51.102.1"), &deny));
    assert!(!allowed_ip(ip("10.0.0.1"), &[]), "private stays refused");
    // Whole families.
    let all_v4 = parse_deny_cidrs("0.0.0.0/0").unwrap();
    assert!(!allowed_ip(ip("11.22.33.44"), &all_v4));
    assert!(allowed_ip(ip("2400:1234::1"), &all_v4));
    let all_v6 = parse_deny_cidrs("::/0").unwrap();
    assert!(!allowed_ip(ip("2400:1234::1"), &all_v6));
    assert!(allowed_ip(ip("11.22.33.44"), &all_v6));
    assert!(parse_deny_cidrs("").unwrap().is_empty());
    for bad in [
        "198.51.101.0/33",
        "2400::/129",
        "example.org/24",
        "198.51.101.0/x",
        "/24",
    ] {
        assert!(parse_deny_cidrs(bad).is_err(), "{bad}");
    }
    // The resolver's filter is the same check.
    let addr = |s: &str| -> SocketAddr { s.parse().unwrap() };
    assert_eq!(
        public_addresses(vec![addr("11.22.33.44:0"), addr("192.168.1.1:0")].into_iter()),
        vec![addr("11.22.33.44:0")]
    );
}

#[test]
fn the_replay_class_of_a_dynamic_host_comes_from_its_lists_alone() {
    use crate::origin::{ReadRoutes, RouteClass};
    // Static lists that name the dynamic host's name: left over from when it was a static
    // alias, or meant for a static alias of that name on the default port.
    let read_routes =
        ReadRoutes::parse("vote.example.org=POST /*,GET /*;prices.example.com=GET /*").unwrap();
    let one_sided = ReadRoutes::parse_list(
        "REPLAY_ONE_SIDED_WRITE_ROUTES",
        "vote.example.org=POST /*;prices.example.com=GET /*",
    )
    .unwrap();
    let config = routed_config("replay_class", &["https://vote.example.org"]);
    let class = |req: &InnerRequest| {
        proxy::RouteContext::resolve(&config, req).replay_class(&read_routes, false, req)
    };
    // The list: GET is a READ, the submission a WRITE, whatever REPLAY_READ_ROUTES says.
    assert_eq!(
        class(&get("vote.example.org", "/shielded-vote/v1/rounds")),
        RouteClass::Read
    );
    let submit = request("POST", "vote.example.org", "/shielded-vote/v1/submit");
    assert_eq!(class(&submit), RouteClass::Write);
    assert_eq!(
        class(&request(
            "POST",
            "vote.example.org:443",
            "/shielded-vote/v1/submit"
        )),
        RouteClass::Write
    );
    // ... and never on one store's verdict.
    assert!(
        !proxy::RouteContext::resolve(&config, &submit).one_sided_write(&one_sided, false, &submit)
    );
    // A static alias is classified by the static lists, as before.
    let quotes = get("prices.example.com", "/v1/quotes");
    assert_eq!(class(&quotes), RouteClass::Read);
    assert!(
        proxy::RouteContext::resolve(&config, &quotes).one_sided_write(&one_sided, false, &quotes)
    );
    assert_eq!(
        class(&request("POST", "prices.example.com", "/v1/quotes")),
        RouteClass::Write
    );
    // A host nobody serves: the static lists decide (it is refused later anyway).
    assert_eq!(
        class(&request("POST", "other.example.org", "/x")),
        RouteClass::Write
    );
}

#[test]
fn a_path_to_an_unknown_authority_is_not_logged() {
    let config = routed_config("unknown_log", &["https://vote.example.org"]);
    // A host this process does not serve (not learned yet, held, removed): no path, no query.
    let req = get("late.example.org", "/shielded-vote/v1/round/abcdef?voter=1");
    assert_eq!(proxy::loggable_route(&config, &req), "(unknown authority)");
    // The gateway's own host: lightwalletd RPC names, as before.
    let rpc = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock";
    assert_eq!(
        proxy::loggable_route(&config, &request("POST", "ohttp-gateway.example", rpc)),
        rpc
    );
    // Without GATEWAY_HOSTS every unknown authority is lightwalletd.
    let mut permissive = config.clone();
    permissive.gateway_hosts.clear();
    assert_eq!(
        proxy::loggable_route(&permissive, &request("POST", "late.example.org", rpc)),
        rpc
    );
}

#[test]
fn a_shadowed_host_keeps_its_limits_for_its_source() {
    let list = serde_json::json!([{ "pointer": "/hosts", "routes": "GET /*" }]);
    let hosts = parse(
        &serde_json::json!([
            { "name": "limits_first", "url": "https://one.example.com/h.json", "lists": list.clone() },
            { "name": "limits_second", "url": "https://two.example.com/h.json", "lists": list.clone(), "rate_limit": "1/600s" },
        ])
        .to_string(),
    );
    let doc = |urls: &[&str]| {
        serde_json::json!({ "hosts": urls })
            .to_string()
            .into_bytes()
    };
    assert_eq!(
        hosts.load_document(1, &doc(&["https://x.example.org"])),
        RefreshResult::Ok
    );
    let second = hosts.lookup("x.example.org").unwrap();
    assert_eq!(second.source, "limits_second");
    assert!(second.check_rate().is_ok() && second.check_rate().is_err());
    let permit = second.semaphore.clone().try_acquire_owned().unwrap();

    // The first source lists the host too and serves it, with limits of its own.
    assert_eq!(
        hosts.load_document(0, &doc(&["https://x.example.org"])),
        RefreshResult::Ok
    );
    let first = hosts.lookup("x.example.org").unwrap();
    assert_eq!(first.source, "limits_first");
    assert!(
        first.check_rate().is_ok(),
        "no rate_limit on the first source"
    );
    assert_eq!(first.semaphore.available_permits(), 4);

    // It drops the host: the second source serves it again, with the window and the permit
    // it had before, not fresh ones.
    assert_eq!(
        hosts.load_document(0, &doc(&["https://y.example.org"])),
        RefreshResult::Ok
    );
    let again = hosts.lookup("x.example.org").unwrap();
    assert_eq!(again.source, "limits_second");
    assert!(
        again.check_rate().is_err(),
        "the spent window is still the host's"
    );
    assert_eq!(again.semaphore.available_permits(), 3);
    drop(permit);
    assert_eq!(again.semaphore.available_permits(), 4);
}

#[test]
fn deny_blocks_come_from_the_environment_once() {
    let _env = crate::config::test_env_lock();
    // Malformed: a startup error.
    std::env::set_var("DYNAMIC_HOSTS_DENY_CIDRS", "203.0.115.0/40");
    let malformed = DynamicHosts::from_env(Reserved::default(), "testnet", 4);
    std::env::remove_var("DYNAMIC_HOSTS_DENY_CIDRS");
    assert!(malformed.is_err());
    // A block used by no other test of this process.
    std::env::set_var(
        "DYNAMIC_HOSTS_DENY_CIDRS",
        "203.0.115.0/24, ::ffff:203.0.116.0/120",
    );
    let hosts = DynamicHosts::from_env(Reserved::default(), "testnet", 4);
    std::env::remove_var("DYNAMIC_HOSTS_DENY_CIDRS");
    assert!(!hosts.unwrap().enabled());
    for denied in ["203.0.115.9", "203.0.116.200", "::ffff:203.0.115.9"] {
        assert!(!is_connectable(denied.parse().unwrap()), "{denied}");
    }
    assert!(is_connectable("203.0.117.9".parse().unwrap()));
    assert!(!is_connectable("127.0.0.1".parse().unwrap()));
    // A literal in a denied block is refused when it is listed, the resolver drops such an
    // address, and a literal that got into the served set is no target.
    assert_eq!(
        parse_host_url("https://203.0.115.9", &[], &[]),
        Err("address is in a denied block")
    );
    assert!(parse_host_url("https://203.0.117.9", &[], &[]).is_ok());
    let addr = |s: &str| -> SocketAddr { s.parse().unwrap() };
    assert_eq!(
        public_addresses(vec![addr("203.0.115.9:0"), addr("203.0.117.9:0")].into_iter()),
        vec![addr("203.0.117.9:0")]
    );
    let config = routed_config("deny_env", &["https://vote.example.org"]);
    config
        .dynamic_hosts
        .insert_unvalidated("203.0.115.9", "https://203.0.115.9");
    assert!(matches!(
        proxy::resolve_backend(&config, &get("203.0.115.9", "/x")),
        BackendTarget::Rejected
    ));
}

#[test]
fn a_context_of_another_authority_is_no_target() {
    let config = routed_config("ctx_other", &["https://vote.example.org"]);
    let route = proxy::RouteContext::resolve(&config, &get("vote.example.org", "/shielded-vote/x"));
    assert!(matches!(
        proxy::resolve_backend_in(
            &config,
            &get("other.example.org", "/shielded-vote/x"),
            &route
        ),
        BackendTarget::Rejected
    ));
    assert!(upstream(proxy::resolve_backend_in(
        &config,
        &get("vote.example.org:443", "/shielded-vote/x"),
        &route
    ))
    .is_some());
    // Not with a static alias or the gateway's own host either: the dynamic entry's routes
    // and limits must never stand in for theirs.
    for authority in ["prices.example.com", "ohttp-gateway.example"] {
        assert!(
            matches!(
                proxy::resolve_backend_in(&config, &get(authority, "/v1/quotes"), &route),
                BackendTarget::Rejected
            ),
            "{authority}"
        );
    }
    // With their own context they resolve as ever.
    assert!(upstream(proxy::resolve_backend(
        &config,
        &get("prices.example.com", "/v1/quotes")
    ))
    .is_some());
}

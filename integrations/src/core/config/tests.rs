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

use super::*;

const FILE: &str = r#"
schema = 1
gateway_hosts = ["Gateway.example:443"]
relay_secret_on_key_config = "require"

[secrets]
prices_key = { env = "PRICES_KEY" }
bearer = { file = "/run/secrets/bearer" }

[integrations.prices]
alias = "Prices.example"
upstream = "https://prices-api.example"
routes = ["GET /v1/quotes", "GET /v1/fiat/map"]
headers = [{ name = "X-Api-Key", value = "{secret}", secret = "prices_key" }]
cache = ["GET /v1/quotes@120"]
rate_limit = "10/60s"
query_rules = ["GET /v1/quotes?convert={from:fiat}", "GET /v1/fiat/map?"]

[integrations.swap]
alias = "swap.example"
upstream = "https://swap-api.example"
kind = "near"
routes = ["GET /v0/tokens"]
headers = [
  { name = "Authorization", value = "Bearer {secret}", secret = "bearer" },
  { name = "X-Fixed", value = "1" },
]
cache = ["GET /v0/tokens@300"]

[hosts."gateway.example"]
routes = ["POST /cash.z.wallet.sdk.rpc.CompactTxStreamer/*"]

[hosts.lwd]
read_routes = ["POST /cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock"]
one_sided_write_routes = ["POST /cash.z.wallet.sdk.rpc.CompactTxStreamer/SendTransaction"]

[value_sources.fiat]
alias = "prices.example"
route = "GET /v1/fiat/map"
pointer = "/data/*/symbol"
refresh_secs = 21600
fallback = ["USD", "EUR"]

[dynamic_hosts]
deny_cidrs = ["192.0.2.0/28"]
sources = [{ name = "voting", url = "https://voting.example/hosts.json", lists = [{ pointer = "/hosts", routes = "GET /*" }], max_hosts = 4 }]

[host_list]
publish = "All"
max_age_secs = 300
"#;

fn secrets(name: &str) -> Result<String> {
    match name {
        "prices_key" => Ok("pk-1".to_string()),
        "bearer" => Ok("jwt-1".to_string()),
        other => bail!("no secret {other}"),
    }
}

fn err(text: &str) -> String {
    parse(text).unwrap_err().to_string()
}

#[test]
fn a_file_renders_to_the_variables_it_stands_for() {
    let loaded = parse(FILE).unwrap();
    assert!(loaded.warnings.is_empty());
    let env = render(&loaded.file, &secrets).unwrap();
    let get = |k: &str| env.get(k).map(String::as_str);
    assert_eq!(get("GATEWAY_HOSTS"), Some("gateway.example"));
    assert_eq!(get("RELAY_SECRET_ON_KEY_CONFIG"), Some("require"));
    assert_eq!(
        get("BACKENDS"),
        Some("prices.example=https://prices-api.example,swap.example=https://swap-api.example")
    );
    assert_eq!(
        get("BACKENDS_POLICY"),
        Some("gateway.example=POST /cash.z.wallet.sdk.rpc.CompactTxStreamer/*;prices.example=GET /v1/quotes,GET /v1/fiat/map;swap.example=GET /v0/tokens")
    );
    assert_eq!(
        get("BACKEND_HEADERS"),
        Some("prices.example=X-Api-Key:pk-1,swap.example=Authorization:Bearer jwt-1,swap.example=X-Fixed:1")
    );
    assert_eq!(get("NEAR_ALIAS"), Some("swap.example"));
    assert_eq!(get("FLEXA_ALIAS"), None);
    assert_eq!(
        get("THIRD_PARTY_CACHE_ROUTES"),
        Some("prices.example=GET /v1/quotes@120;swap.example=GET /v0/tokens@300")
    );
    assert_eq!(
        get("THIRD_PARTY_RATE_LIMITS"),
        Some("prices.example=10/60s")
    );
    assert_eq!(
        get("THIRD_PARTY_QUERY_RULES"),
        Some("prices.example=GET /v1/quotes?convert={from:fiat},GET /v1/fiat/map?")
    );
    assert_eq!(
        get("THIRD_PARTY_QUERY_VALUE_SOURCES"),
        Some("fiat=prices.example GET /v1/fiat/map#/data/*/symbol@21600@fallback=USD|EUR")
    );
    assert_eq!(
        get("REPLAY_READ_ROUTES"),
        Some("lwd=POST /cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock")
    );
    assert_eq!(
        get("REPLAY_ONE_SIDED_WRITE_ROUTES"),
        Some("lwd=POST /cash.z.wallet.sdk.rpc.CompactTxStreamer/SendTransaction")
    );
    assert_eq!(get("THIRD_PARTY_HOSTS_PUBLISH"), Some("all"));
    assert_eq!(get("THIRD_PARTY_HOSTS_MAX_AGE_SECS"), Some("300"));
    assert_eq!(get("DYNAMIC_HOSTS_DENY_CIDRS"), Some("192.0.2.0/28"));
    let sources: Value = serde_json::from_str(get("DYNAMIC_HOST_SOURCES").unwrap()).unwrap();
    assert_eq!(sources[0]["lists"][0]["pointer"], "/hosts");
    assert_eq!(sources[0]["max_hosts"], 4);
    assert_eq!(get("BACKENDS_POLICY_DEFAULT"), None);
    // A missing secret is an error naming it, never a value.
    let text = render(&loaded.file, &|_| bail!("unset"))
        .unwrap_err()
        .to_string();
    assert!(text.contains("secret 'prices_key'"), "{text}");
}

#[test]
fn the_rendered_variables_read_back_to_the_same_policy() {
    let loaded = parse(FILE).unwrap();
    let env: BTreeMap<String, String> = render(&loaded.file, &secrets)
        .unwrap()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    let back = export(&env).unwrap().file;
    let file = |f: &PolicyFile| canonical(f, HeaderValues::Redacted, false, &secrets).unwrap();
    assert_eq!(file(&back), file(&loaded.file));
    assert_eq!(
        canonical_json(&file(&back)),
        canonical_json(&file(&loaded.file))
    );
    assert!(check_round_trip(&env).unwrap());
}

#[test]
fn canonical_policy_redacts_and_sorts() {
    let loaded = parse(FILE).unwrap();
    let c = canonical(&loaded.file, HeaderValues::Redacted, false, &secrets).unwrap();
    let json = canonical_json(&c);
    assert!(!json.contains("pk-1") && !json.contains("jwt-1"), "{json}");
    assert!(
        !json.contains("prices_key"),
        "secret names are not part of it: {json}"
    );
    assert_eq!(
        c["authorities"]["swap.example"]["headers"][0]["value"],
        REDACTED
    );
    assert_eq!(c["authorities"]["swap.example"]["kind"], "near");
    assert_eq!(c["authorities"]["lwd"].get("kind"), None);
    let keys: Vec<&String> = c.as_object().unwrap().keys().collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
    let plain = canonical(&loaded.file, HeaderValues::Plain, false, &secrets).unwrap();
    assert_eq!(
        plain["authorities"]["prices.example"]["headers"][0]["value"],
        "pk-1"
    );
}

#[test]
fn the_export_turns_header_values_into_secret_references() {
    let env: BTreeMap<String, String> = [
        ("BACKENDS", "a.example=https://a,b.example=https://b"),
        (
            "BACKEND_HEADERS",
            "a.example=Authorization:Bearer jwt-abcdefgh,b.example=X-Key:literal-1",
        ),
        ("A_JWT", "jwt-abcdefgh"),
        ("SHORT", "abc"),
        ("FLEXA_ALIAS", " B.example "),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let export = export(&env).unwrap();
    let (file, exported) = (export.file.clone(), export.secrets.clone());
    assert_eq!(export.secret_value("A_JWT"), Some("jwt-abcdefgh"));
    assert_eq!(export.secret_value("B_EXAMPLE_X_KEY"), Some("literal-1"));
    assert!(!format!("{export:?}").contains("literal-1"));
    let a = &file.integrations["a.example"];
    assert_eq!(a.headers[0].value, "Bearer {secret}");
    assert_eq!(a.headers[0].secret.as_deref(), Some("A_JWT"));
    let b = &file.integrations["b.example"];
    assert_eq!(b.headers[0].value, "{secret}");
    assert_eq!(b.headers[0].secret.as_deref(), Some("B_EXAMPLE_X_KEY"));
    assert_eq!(b.kind, Some(Kind::Flexa));
    assert_eq!(
        exported,
        vec![
            ExportedSecret {
                name: "A_JWT".into(),
                env: "A_JWT".into(),
                found: true
            },
            ExportedSecret {
                name: "B_EXAMPLE_X_KEY".into(),
                env: "B_EXAMPLE_X_KEY".into(),
                found: false
            },
        ]
    );
    let text = to_toml(&file, &exported).unwrap();
    assert!(
        !text.contains("jwt-abcdefgh") && !text.contains("literal-1"),
        "{text}"
    );
    assert!(
        text.contains("B_EXAMPLE_X_KEY = { env = \"B_EXAMPLE_X_KEY\" }"),
        "{text}"
    );
    let back = parse(&text).unwrap().file;
    assert_eq!(back, file);
    assert!(check_round_trip(&env).unwrap());
}

#[test]
fn the_structure_is_checked() {
    for (text, expected) in [
        ("schema = 2", "schema 2"),
        ("schema = 1\nunknown = 1", "unknown field"),
        ("gateway_hosts = []", "missing field `schema`"),
        (
            "schema = 1\n[integrations.a]\nalias = \"a.example\"\nupstream = \"https://a\"\nport = 1",
            "unknown field `port`",
        ),
        (
            "schema = 1\n[integrations.a]\nalias = \"a.example\"\nupstream = \"https://a\"\n[integrations.b]\nalias = \"A.example\"\nupstream = \"https://b\"",
            "alias 'a.example' is listed twice",
        ),
        (
            "schema = 1\n[integrations.a]\nalias = \"a.example\"\nupstream = \"https://a\"\n[hosts.\"a.example\"]",
            "both an integration alias and a hosts entry",
        ),
        (
            "schema = 1\ngateway_hosts = [\"a.example\"]\n[integrations.a]\nalias = \"a.example\"\nupstream = \"https://a\"",
            "is also a gateway host",
        ),
        (
            "schema = 1\n[integrations.a]\nalias = \"a.example\"\nupstream = \"https://a\"\nheaders = [{ name = \"X\", value = \"{secret}\", secret = \"k\" }]",
            "which [secrets] does not map",
        ),
        (
            "schema = 1\n[secrets]\nk = { env = \"K\" }\n[integrations.a]\nalias = \"a.example\"\nupstream = \"https://a\"\nheaders = [{ name = \"X\", value = \"v\", secret = \"k\" }]",
            "its value has no {secret}",
        ),
        (
            "schema = 1\n[integrations.a]\nalias = \"a.example\"\nupstream = \"https://a\"\nheaders = [{ name = \"X\", value = \"{secret}\" }]",
            "names no secret",
        ),
        (
            "schema = 1\n[secrets]\nk = { env = \"K\", file = \"/k\" }",
            "secret 'k' needs a file (k = { file = \"/path\" })",
        ),
        (
            "schema = 1\n[secrets]\nk = {}",
            "secret 'k' needs a file (k = { file = \"/path\" })",
        ),
        (
            "schema = 1\n[integrations.a]\nalias = \"a.example\"\nupstream = \"https://a\"\nroutes = [\"GET /x\"]\ncache = [\"GET /y@60\"]",
            "outside its routes",
        ),
        (
            "schema = 1\n[integrations.a]\nalias = \"a.example\"\nupstream = \"https://a\"\ncache = [\"GET /y@60\"]",
            "outside its routes",
        ),
        (
            "schema = 1\n[integrations.a]\nalias = \"a.example\"\nupstream = \"https://a\"\nroutes = []",
            "empty routes list",
        ),
        (
            "schema = 1\n[integrations.a]\nalias = \"a.example\"\nupstream = \"https://a\"\nroutes = [\"GET /x,POST /y\"]",
            "contains ','",
        ),
        (
            "schema = 1\n[hosts.\"gw.example\"]\nkind = \"cmc\"",
            "a host can only be named",
        ),
        (
            "schema = 1\n[integrations.a]\nalias = \"a.example\"\nupstream = \"https://a\"\nkind = \"flexa\"\n[integrations.b]\nalias = \"b.example\"\nupstream = \"https://b\"\nkind = \"flexa\"",
            "two authorities of kind flexa",
        ),
        (
            "schema = 1\n[integrations.a]\nalias = \"a.example\"\nupstream = \"https://a\"\nkind = \"other\"",
            "unknown variant",
        ),
    ] {
        let text = err(text);
        assert!(text.contains(expected), "{expected}: {text}");
    }
    // A cache route under BACKENDS_POLICY_DEFAULT=allow needs no routes; a prefix route admits it.
    parse("schema = 1\nbackends_policy_default = \"allow\"\n[integrations.a]\nalias = \"a.example\"\nupstream = \"https://a\"\ncache = [\"GET /y@60\"]").unwrap();
    parse("schema = 1\n[integrations.a]\nalias = \"a.example\"\nupstream = \"https://a\"\nroutes = [\"GET /v1/*\"]\ncache = [\"GET /v1/x@60\"]").unwrap();
}

#[test]
fn a_removed_key_is_accepted_with_a_warning() {
    let loaded =
        parse("schema = 1\nproxy_allow_suffixes = [\".example\"]\ngateway_hosts = [\"g.example\"]")
            .unwrap();
    assert_eq!(loaded.warnings.len(), 1);
    assert!(
        loaded.warnings[0].contains("proxy_allow_suffixes"),
        "{:?}",
        loaded.warnings
    );
    assert_eq!(loaded.file.gateway_hosts, vec!["g.example".to_string()]);
    // Still no other unknown key.
    assert!(err("schema = 1\nproxy_allow_suffixes = []\nother = 1").contains("unknown field"));
}

#[test]
fn differing_keys_name_the_place_only() {
    let a = parse(FILE).unwrap().file;
    let mut b = a.clone();
    b.integrations.get_mut("prices").unwrap().cache = vec!["GET /v1/quotes@60".into()];
    b.host_list.max_age_secs = Some(60);
    b.value_sources.clear();
    let c = |f: &PolicyFile| canonical(f, HeaderValues::Redacted, false, &secrets).unwrap();
    let keys = differing_keys(&c(&a), &c(&b));
    assert_eq!(
        keys,
        vec![
            "authorities.prices.example.cache".to_string(),
            "host_list".to_string(),
            "value_sources.fiat".to_string()
        ]
    );
    assert!(differing_keys(&c(&a), &c(&a)).is_empty());
    // Keyed kinds behave as generic.
    let mut keyed = a.clone();
    keyed.integrations.get_mut("prices").unwrap().kind = Some(Kind::Cmc);
    let same = |f: &PolicyFile| canonical(f, HeaderValues::Redacted, true, &secrets).unwrap();
    assert_eq!(same(&keyed), same(&a));
    assert_ne!(c(&keyed), c(&a));
}

#[test]
fn round_trips_of_environments() {
    let env = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    };
    for case in [
        env(&[]),
        env(&[
            ("BACKENDS", "a.example=https://a"),
            ("BACKENDS_POLICY_DEFAULT", "ALLOW"),
        ]),
        env(&[
            ("BACKENDS_POLICY", "a.example=GET /x;a.example=GET /y"),
            ("BACKEND_HEADERS", "a.example=X:1,a.example=X:2"),
            ("REPLAY_READ_ROUTES", "lwd=POST /a;lwd=POST /b"),
            ("THIRD_PARTY_RATE_LIMITS", "a.example=1/1s,a.example=2/2s"),
            ("FLEXA_ALIAS", "gw.example"),
        ]),
        env(&[(
            "DYNAMIC_HOST_SOURCES",
            "[{\"name\":\"n\",\"x\":[1,2.5,true]}]",
        )]),
        // Found by the fuzz target: an authority without any route.
        env(&[("THIRD_PARTY_CACHE_ROUTES", "SS=")]),
    ] {
        assert!(check_round_trip(&case).unwrap(), "{case:?}");
    }
    // Found by the fuzz target: a value source without a path is no file entry; a fraction
    // that changes when written again is not exported (or does not change).
    assert_eq!(
        check_round_trip(&env(&[(
            "THIRD_PARTY_QUERY_VALUE_SOURCES",
            "fiat=a.example GET #m//data/*/s@300@fallback=USD|EUR",
        )])),
        Ok(false)
    );
    assert_eq!(
        check_round_trip(&env(&[(
            "THIRD_PARTY_QUERY_VALUE_SOURCES",
            "fiat=a.example  0  GET /m#/d@300",
        )])),
        Ok(false)
    );
    for x in [
        "14.511111111111111111111111111111111",
        "111111111111111111111111",
        "0.1",
    ] {
        let sources = format!("[{{\"name\":\"n\",\"x\":{x}}}]");
        check_round_trip(&env(&[("DYNAMIC_HOST_SOURCES", sources.as_str())])).unwrap();
    }
    // Later entries replace or extend the earlier ones, as the gateway reads them.
    let f = export(&env(&[
        ("BACKENDS_POLICY", "a.example=GET /x;a.example=GET /y"),
        ("REPLAY_READ_ROUTES", "lwd=POST /a;lwd=POST /b"),
        ("THIRD_PARTY_RATE_LIMITS", "a.example=1/1s,a.example=2/2s"),
        ("BACKEND_HEADERS", "a.example=X:1,a.example=X:2"),
    ]))
    .unwrap()
    .file;
    let h = &f.hosts["a.example"];
    assert_eq!(h.routes, Some(vec!["GET /y".to_string()]));
    assert_eq!(h.rate_limit.as_deref(), Some("2/2s"));
    assert_eq!(f.hosts["lwd"].read_routes, vec!["POST /a", "POST /b"]);
    // Two values under one header name: two secrets.
    let secrets: Vec<Option<&str>> = h.headers.iter().map(|h| h.secret.as_deref()).collect();
    assert_eq!(secrets, vec![Some("A_EXAMPLE_X"), Some("A_EXAMPLE_X_2")]);
    // A null cannot be exported.
    let e = export(&env(&[("DYNAMIC_HOST_SOURCES", "[{\"a\":null}]")])).unwrap();
    assert!(to_toml(&e.file, &e.secrets).is_err());
}

#[test]
fn policy_and_deployment_keys_are_disjoint() {
    for k in POLICY_ENV_KEYS {
        assert!(!DEPLOYMENT_ENV_KEYS.contains(k), "{k}");
    }
}

#[cfg(all(feature = "cmc", feature = "swapkit"))]
#[test]
fn keyed_kinds_must_meet_their_invariants() {
    let base = "schema = 1\n[secrets]\nk = { env = \"K\" }\n[integrations.p]\nalias = \"p.example\"\nupstream = \"https://p\"\n";
    let ok = format!("{base}kind = \"cmc\"\nroutes = [\"GET /a\"]\nheaders = [{{ name = \"X\", value = \"{{secret}}\", secret = \"k\" }}]\nquery_rules = [\"GET /a?\"]");
    parse(&ok).unwrap();
    let no_rule = ok.replace("query_rules = [\"GET /a?\"]", "");
    assert!(err(&no_rule).contains("has no query rule"));
    let no_key =
        format!("{base}kind = \"swapkit\"\nroutes = [\"GET /a\"]\nquery_rules = [\"GET /a?\"]");
    assert!(err(&no_key).contains("needs a header credential"));
}

#[test]
fn names_that_meet_after_normalising_are_refused() {
    let text = err("schema = 1\n[hosts.\"A.example\"]\n[hosts.\"a.example\"]");
    assert!(
        text.contains("listed twice") && text.contains("A.example") && text.contains("a.example"),
        "{text}"
    );
    let text = err("schema = 1\n[value_sources.\" f\"]\nalias = \"a\"\nroute = \"GET /x\"\npointer = \"/p\"\nrefresh_secs = 300\n[value_sources.f]\nalias = \"a\"\nroute = \"GET /x\"\npointer = \"/p\"\nrefresh_secs = 300");
    assert!(text.contains("listed twice"), "{text}");
}

#[test]
fn errors_never_show_a_value() {
    const SENTINEL: &str = "sentinel-value-7f3a";
    for text in [
        format!("schema = 1\n[value_sources.f]\nalias = \"a\"\nroute = \"GET /x\"\npointer = \"/p\"\nrefresh_secs = \"{SENTINEL}\""),
        format!("schema = 1\nrelay_secret_on_key_config = \"{SENTINEL}"),
        format!("schema = 1\n[integrations.a]\nalias = \"a.example\"\nupstream = \"https://a\"\nheaders = [{{ name = \"X\", value = \"{SENTINEL},x\" }}]"),
        format!("schema = 1\n[integrations.a]\nalias = \"a.example\"\nupstream = \"https://a\"\nroutes = [\"GET /{SENTINEL},x\"]"),
        format!("schema = 1\n{SENTINEL} = 1"),
    ] {
        let e = err(&text);
        assert!(!e.contains(SENTINEL) || e.contains(&format!("`{SENTINEL}`")), "{e}");
        assert!(!e.contains(&format!("\"{SENTINEL}")), "{e}");
    }
    // A position is given.
    let e = err("schema = 1\nrefresh = \"x");
    assert!(e.contains("line 2"), "{e}");
}

#[test]
fn the_export_maps_whole_values_only() {
    let env: BTreeMap<String, String> = [
        ("BACKEND_HEADERS", "a.example=X:pre-abc12345,a.example=Authorization:Bearer tok-value-1,a.example=Y:Tok-value-1,a.example=E:"),
        ("PART", "abc12345"),
        ("TOKEN", "tok-value-1"),
        ("token", "Tok-value-1"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let e = export(&env).unwrap();
    let h = &e.file.hosts["a.example"].headers;
    let refs: Vec<(&str, Option<&str>)> = h
        .iter()
        .map(|h| (h.value.as_str(), h.secret.as_deref()))
        .collect();
    assert_eq!(
        refs,
        vec![
            ("{secret}", Some("A_EXAMPLE_X")),
            ("Bearer {secret}", Some("TOKEN")),
            ("{secret}", Some("token")),
            ("", None),
        ]
    );
    assert!(check_round_trip(&env).unwrap());
}

#[test]
fn quoted_parts_of_errors_are_redacted() {
    assert_eq!(
        redact_quoted("invalid type: string \"a\\\"b\", expected u64"),
        "invalid type: string \"…\", expected u64"
    );
    assert_eq!(
        redact_quoted("unknown variant `secret`, expected one of `generic`, `flexa`"),
        "unknown variant `…`"
    );
    assert_eq!(
        redact_quoted("unknown field `colour`, expected one of `a`, `b`"),
        "unknown field `colour`, expected one of `…`, `…`"
    );
    for text in [
        "schema = 1\n[integrations.a]\nalias = \"a\"\nupstream = \"https://a\"\nkind = \"sentinel-kind-91\"",
        "schema = 1\n[value_sources.f]\nalias = \"a\"\nroute = \"GET /x\"\npointer = \"/p\"\nrefresh_secs = \"x\\\"sentinel-kind-91\"",
        // A backquote inside an unknown variant (serde does not escape it).
        "schema = 1\n[integrations.a]\nalias = \"a\"\nupstream = \"https://a\"\nkind = \"x`sentinel-kind-91\"",
    ] {
        let e = err(text);
        assert!(!e.contains("sentinel-kind-91"), "{e}");
    }
}

#[test]
fn generated_names_never_take_a_variable_of_the_environment() {
    let env: BTreeMap<String, String> = [
        (
            "BACKEND_HEADERS",
            "a.example=X:value-one,a.example=X:value-two",
        ),
        ("A_EXAMPLE_X", "unrelated-variable"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let e = export(&env).unwrap();
    let names: Vec<Option<&str>> = e.file.hosts["a.example"]
        .headers
        .iter()
        .map(|h| h.secret.as_deref())
        .collect();
    assert_eq!(names, vec![Some("A_EXAMPLE_X_2"), Some("A_EXAMPLE_X_3")]);
    assert_eq!(e.secret_value("A_EXAMPLE_X_2"), Some("value-one"));
    assert_eq!(e.secret_value("A_EXAMPLE_X_3"), Some("value-two"));
    // Two headers made of one variable share its secret.
    let env: BTreeMap<String, String> = [
        (
            "BACKEND_HEADERS",
            "a.example=X:shared-value-1,b.example=Authorization:Bearer shared-value-1",
        ),
        ("SHARED", "shared-value-1"),
        ("SHORT", "short"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let e = export(&env).unwrap();
    assert_eq!(
        e.file.hosts["a.example"].headers[0].secret.as_deref(),
        Some("SHARED")
    );
    assert_eq!(
        e.file.hosts["b.example"].headers[0].secret.as_deref(),
        Some("SHARED")
    );
    assert!(check_round_trip(&env).unwrap());
    // A variable under 8 bytes is never picked.
    let env: BTreeMap<String, String> =
        [("BACKEND_HEADERS", "a.example=X:short"), ("SHORT", "short")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
    assert_eq!(
        export(&env).unwrap().file.hosts["a.example"].headers[0]
            .secret
            .as_deref(),
        Some("A_EXAMPLE_X")
    );
}

#[test]
fn equivalent_spellings_have_one_behaviour_form() {
    let c = |text: &str| {
        canonical(
            &parse(text).unwrap().file,
            HeaderValues::Redacted,
            true,
            &secrets,
        )
        .unwrap()
    };
    assert_eq!(
        c("schema = 1\n[dynamic_hosts]\ndeny_cidrs = [\"192.0.2.0/28\", \"2001:db8::/32\", \"192.0.2.0/28\"]\nsources = []"),
        c("schema = 1\n[dynamic_hosts]\ndeny_cidrs = [\"2001:db8::/32\", \"192.0.2.0/28\"]")
    );
}

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

//! The `coinbase` integration table.

use super::*;

const TABLE: &str = r#"
schema = 1
gateway_hosts = ["gateway.example"]

[secrets]
cdp_key = { file = "/run/secrets/cdp_key" }

[integrations.onramp]
kind = "coinbase"
alias = "Onramp.example"
upstream = "https://cdp-api.example"
auth = { type = "jwt_eddsa", secret = "cdp_key", ttl_secs = 60 }
redirect_url = " wallet://onramp/return "
enabled = true
rate_limit = "30/60s"
status_rate_limit = "120/60s"

[integrations.onramp.availability]
countries = { US = { buy = true, sell = true }, DE = { buy = true, sell = false } }
"#;

#[cfg(feature = "coinbase")]
const KEY: &str = r#"{"id":"k","privateKey":"x"}"#;

#[cfg(feature = "coinbase")]
fn key(name: &str) -> Result<String> {
    match name {
        "cdp_key" => Ok(KEY.to_string()),
        other => bail!("no secret {other}"),
    }
}

fn err(text: &str) -> String {
    parse(text).unwrap_err().to_string()
}

#[cfg(feature = "coinbase")]
#[test]
fn a_coinbase_table_renders_its_alias_and_its_settings() {
    let loaded = parse(TABLE).unwrap();
    let env = render(&loaded.file, &key).unwrap();
    let get = |k: &str| env.get(k).map(String::as_str);
    assert_eq!(
        get("BACKENDS"),
        Some("onramp.example=https://cdp-api.example")
    );
    assert_eq!(
        get("BACKENDS_POLICY"),
        Some("onramp.example=POST /v1/session,POST /v1/sell/status,GET /v1/availability")
    );
    // WRITE class (no read route), never cached, no header; its caps are its own.
    for k in [
        "THIRD_PARTY_RATE_LIMITS",
        "REPLAY_READ_ROUTES",
        "THIRD_PARTY_CACHE_ROUTES",
        "BACKEND_HEADERS",
        "THIRD_PARTY_QUERY_RULES",
    ] {
        assert_eq!(get(k), None, "{k}");
    }
    let rendered: Value = serde_json::from_str(get(COINBASE_RENDERED).unwrap()).unwrap();
    assert_eq!(
        rendered,
        serde_json::json!([{
            "label": "onramp",
            "alias": "onramp.example",
            "upstream": "https://cdp-api.example",
            "secret": {"name": "cdp_key", "env": null, "file": "/run/secrets/cdp_key"},
            "read_key": true,
            "ttl_secs": 60,
            "enabled": true,
            "redirect_url": "wallet://onramp/return",
            "countries": {"US": {"buy": true, "sell": true}, "DE": {"buy": true, "sell": false}},
            "rate_limit": "30/60s",
            "status_rate_limit": "120/60s",
        }])
    );
    // The key document is never part of the rendered policy, whatever the resolver gives.
    assert!(!env.values().any(|v| v.contains("privateKey")));
    // It reads back as the module's settings.
    let settings =
        crate::coinbase::Settings::parse_rendered(get(COINBASE_RENDERED).unwrap()).unwrap();
    assert_eq!(settings[0].ttl_secs, 60);
    // The default lifetime.
    let default_ttl = parse(&TABLE.replace(", ttl_secs = 60", "")).unwrap();
    let env = render(&default_ttl.file, &key).unwrap();
    let rendered: Value = serde_json::from_str(&env[COINBASE_RENDERED]).unwrap();
    assert_eq!(rendered[0]["ttl_secs"], 120);
    // The rendered entry is no environment variable.
    assert!(!POLICY_ENV_KEYS.contains(&COINBASE_RENDERED));
    assert!(!DEPLOYMENT_ENV_KEYS.contains(&COINBASE_RENDERED));
}

#[cfg(feature = "coinbase")]
#[test]
fn the_canonical_policy_has_the_settings_but_no_secret() {
    let loaded = parse(TABLE).unwrap();
    let c = canonical(&loaded.file, HeaderValues::Redacted, false, &key).unwrap();
    let a = &c["authorities"]["onramp.example"];
    assert_eq!(a["kind"], "coinbase");
    assert_eq!(a["rate_limit"], Value::Null);
    assert_eq!(
        a["coinbase"],
        serde_json::json!({
            "auth": {"type": "jwt_eddsa", "ttl_secs": 60},
            "enabled": true,
            "redirect_url": "wallet://onramp/return",
            "availability": {"US": {"buy": true, "sell": true}, "DE": {"buy": true, "sell": false}},
            "rate_limit": "30/60s",
            "status_rate_limit": "120/60s",
        })
    );
    let json = canonical_json(&c);
    assert!(
        !json.contains("cdp_key") && !json.contains("privateKey"),
        "{json}"
    );
    // The switch changes the policy (and so the digest).
    let off = parse(&TABLE.replace("enabled = true", "enabled = false")).unwrap();
    let c_off = canonical(&off.file, HeaderValues::Redacted, true, &key).unwrap();
    let c_on = canonical(&loaded.file, HeaderValues::Redacted, true, &key).unwrap();
    assert_eq!(
        differing_keys(&c_on, &c_off),
        vec!["authorities.onramp.example.coinbase"]
    );
    // No environment can express it: the environment without the table differs at the alias.
    let mut no_table = loaded.file.clone();
    no_table.integrations.clear();
    let c_env = canonical(&no_table, HeaderValues::Redacted, true, &key).unwrap();
    assert_eq!(
        differing_keys(&c_env, &c_on),
        vec!["authorities.onramp.example"]
    );
    // The export form refuses it.
    assert!(to_toml(&loaded.file, &[])
        .unwrap_err()
        .to_string()
        .contains("only a configuration file can express"));
}

#[cfg(feature = "coinbase")]
#[test]
fn a_coinbase_table_is_checked() {
    let without = |line: &str| {
        assert!(TABLE.contains(line), "{line}");
        TABLE.replace(line, "")
    };
    for (text, expected) in [
        (
            without("auth = { type = \"jwt_eddsa\", secret = \"cdp_key\", ttl_secs = 60 }\n"),
            "needs auth",
        ),
        (without("enabled = true\n"), "needs 'enabled'"),
        (without("rate_limit = \"30/60s\"\n"), "needs 'rate_limit'"),
        (
            without("status_rate_limit = \"120/60s\"\n"),
            "needs 'status_rate_limit'",
        ),
        (
            TABLE.replace("\"120/60s\"", "\"many\""),
            "status_rate_limit",
        ),
        (
            TABLE.replace("secret = \"cdp_key\"", "secret = \"other\""),
            "names the secret 'other'",
        ),
        (TABLE.replace("ttl_secs = 60", "ttl_secs = 121"), "ttl_secs"),
        (TABLE.replace("ttl_secs = 60", "ttl_secs = 0"), "ttl_secs"),
        (
            TABLE.replace("type = \"jwt_eddsa\"", "type = \"header\""),
            "unknown variant",
        ),
        (
            TABLE.replace("ttl_secs = 60", "ttl = 60"),
            "unknown field `ttl`",
        ),
        (
            TABLE.replace(
                "redirect_url = \" wallet://onramp/return \"",
                "redirect_url = \"no url\"",
            ),
            "redirect_url",
        ),
        (
            TABLE.replace("https://cdp-api.example", "cdp-api.example"),
            "must be https://",
        ),
        (
            TABLE.replace("https://cdp-api.example", "http://cdp-api.example"),
            "must be https://",
        ),
        (
            TABLE.replace("https://cdp-api.example", "https://cdp-api.example:443"),
            "must be https://",
        ),
        (
            TABLE.replace("https://cdp-api.example", "https://cdp-api.example/v1"),
            "must be https://",
        ),
        (
            without("redirect_url = \" wallet://onramp/return \"\n"),
            "needs a redirect_url",
        ),
        (TABLE.replace("DE =", "de ="), "ISO 3166-1"),
        (TABLE.replace("DE =", "DEU ="), "ISO 3166-1"),
        (
            TABLE.replace("sell = false", "sell = false, limits = 1"),
            "unknown field `limits`",
        ),
        (
            TABLE.replace(", sell = false }", " }"),
            "missing field `sell`",
        ),
        (
            format!("{TABLE}\n[integrations.onramp.extra]\n"),
            "unknown field `extra`",
        ),
    ] {
        let text = err(&text);
        assert!(text.contains(expected), "{expected}: {text}");
    }
    // Its routes and their handling are the module's.
    let with = |line: &str| TABLE.replace("enabled = true\n", &format!("enabled = true\n{line}\n"));
    for key in [
        "routes = [\"GET /*\"]",
        "headers = [{ name = \"X\", value = \"1\" }]",
        "cache = [\"GET /v1/availability@60\"]",
        "query_rules = [\"GET /v1/availability?\"]",
        "read_routes = [\"POST /v1/session\"]",
        "one_sided_write_routes = [\"POST /v1/session\"]",
    ] {
        let name = key.split(' ').next().unwrap();
        let text = err(&with(key));
        assert!(
            text.contains(&format!("has '{name}', which kind coinbase does not take")),
            "{key}: {text}"
        );
    }
    // The settings of the kind on another kind.
    for key in [
        "auth = { type = \"jwt_eddsa\", secret = \"cdp_key\" }",
        "redirect_url = \"wallet://x\"",
        "enabled = true",
        "[integrations.p.availability]",
        "status_rate_limit = \"1/1s\"",
    ] {
        let text = err(&format!("schema = 1\n[secrets]\ncdp_key = {{ env = \"K\" }}\n[integrations.p]\nalias = \"p.example\"\nupstream = \"https://p\"\n{key}\n"));
        assert!(
            text.contains("which only kind coinbase takes"),
            "{key}: {text}"
        );
    }
    // An availability without countries is an empty document.
    let empty = TABLE.replace(
        "countries = { US = { buy = true, sell = true }, DE = { buy = true, sell = false } }",
        "",
    );
    let env = render(&parse(&empty).unwrap().file, &key).unwrap();
    let rendered: Value = serde_json::from_str(&env[COINBASE_RENDERED]).unwrap();
    assert_eq!(rendered[0]["countries"], serde_json::json!({}));
    // Two coinbase aliases are two integrations.
    let two = format!(
        "{TABLE}\n[integrations.second]\nkind = \"coinbase\"\nalias = \"onramp2.example\"\nupstream = \"https://cdp-api.example\"\nauth = {{ type = \"jwt_eddsa\", secret = \"cdp_key\" }}\nenabled = false\nrate_limit = \"1/60s\"\nstatus_rate_limit = \"1/60s\"\n"
    );
    let env = render(&parse(&two).unwrap().file, &key).unwrap();
    let rendered: Value = serde_json::from_str(&env[COINBASE_RENDERED]).unwrap();
    assert_eq!(rendered.as_array().map(Vec::len), Some(2));
}

#[cfg(not(feature = "coinbase"))]
#[test]
fn without_the_feature_the_kind_is_refused() {
    assert!(err(TABLE).contains("this build has no coinbase provider"));
}

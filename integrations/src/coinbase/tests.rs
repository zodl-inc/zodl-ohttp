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
use base64::Engine;
use ed25519_dalek::Verifier;

// RFC 8032 section 7.1 test 1 (a published test key, no real credential).
const SEED_B64: &str = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=";
const KEY_ID: &str = "00000000-0000-4000-8000-000000000001";
// Synthetic addresses (made-up hashes).
const T1: &str = "t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs";
const T1_OTHER: &str = "t1Hxw6JqWMnhDK5jRCieg5bFHM2qt7UtQvu";
const T3: &str = "t3JZcvsuaXE6ygokL4XUiZSTrQBUoPYFnXJ";
const TESTNET: &str = "tm9iMLAuYMzJ6jtFLcA7rzUmfreGuKvr7Ma";
const REF: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

struct Fixed;

impl NonceSource for Fixed {
    fn fill(&self, out: &mut [u8]) {
        out.fill(0x42);
    }
}

fn signer() -> JwtEdDsa {
    JwtEdDsa::from_cdp_json(
        &format!(r#"{{"id":"{KEY_ID}","privateKey":"{SEED_B64}"}}"#),
        120,
    )
    .unwrap()
}

fn settings(enabled: bool) -> Settings {
    Settings {
        label: "onramp".into(),
        alias: "onramp.example".into(),
        upstream: "https://cdp-api.example".into(),
        secret: SecretSource {
            name: "cdp_key".into(),
            env: None,
            file: Some("/run/secrets/cdp_key".into()),
        },
        read_key: true,
        ttl_secs: 120,
        enabled,
        redirect_url: Some("wallet://onramp/return".into()),
        countries: [
            (
                "US".to_string(),
                Country {
                    buy: true,
                    sell: true,
                },
            ),
            (
                "DE".to_string(),
                Country {
                    buy: true,
                    sell: false,
                },
            ),
        ]
        .into(),
        rate_limit: "30/60s".into(),
        status_rate_limit: "120/60s".into(),
    }
}

fn provider(enabled: bool) -> Coinbase {
    Coinbase::new(&settings(enabled), Some(signer()), Arc::new(Fixed)).unwrap()
}

fn req<'a>(method: &'a str, path: &'a str, body: &'a [u8]) -> RequestView<'a> {
    RequestView {
        method,
        path,
        headers: &[],
        body,
    }
}

fn session_body(fields: &str) -> Vec<u8> {
    format!("{{{fields}}}").into_bytes()
}

fn plan(p: &Coinbase, method: &str, path: &str, body: &[u8]) -> Plan {
    p.plan(&req(method, path, body))
}

fn local(plan: Plan) -> (u16, String, Option<&'static str>) {
    match plan {
        Plan::Local { answer, refusal } => (
            answer.status,
            String::from_utf8(answer.body).unwrap(),
            refusal,
        ),
        other => panic!("not local: {other:?}"),
    }
}

fn upstream(plan: Plan) -> Call {
    match plan {
        Plan::Upstream(call) => call,
        other => panic!("not upstream: {other:?}"),
    }
}

fn json_of(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

#[test]
fn only_the_three_routes_are_admitted() {
    for enabled in [true, false] {
        let p = provider(enabled);
        for (method, path) in [
            ("GET", "/v1/session"),
            ("POST", "/v1/availability"),
            ("POST", "/v1/session/x"),
            ("POST", "/v1/session?flow=buy"),
            ("GET", "/v1/availability?x=1"),
            ("POST", "/onramp/v1/token"),
            ("PUT", "/v1/sell/status"),
            ("POST", "/"),
            // The method exactly.
            ("get", "/v1/availability"),
            ("Post", "/v1/session"),
        ] {
            assert!(
                matches!(
                    plan(&p, method, path, b"{}"),
                    Plan::Denied(Denial::NotInPolicy)
                ),
                "{method} {path}"
            );
        }
        assert!(matches!(
            plan(&p, "POST", "/v1/../v1/session", b"{}"),
            Plan::Denied(Denial::PathTrick(_))
        ));
        assert!(matches!(
            plan(&p, "GET", "/v1//availability", b""),
            Plan::Denied(Denial::PathTrick(_))
        ));
    }
}

#[test]
fn switched_off_every_route_answers_without_the_upstream() {
    let p = provider(false);
    let valid = session_body(&format!(r#""flow":"buy","address":"{T1}","ref":"{REF}""#));
    for (path, body) in [
        ("/v1/session", valid.as_slice()),
        ("/v1/session", b"not json".as_slice()),
        (
            "/v1/sell/status",
            br#"{"ref":"ABCDEFGHIJKLMNOPQRSTUVWXYZ"}"#.as_slice(),
        ),
    ] {
        assert_eq!(
            local(plan(&p, "POST", path, body)),
            (
                503,
                r#"{"error":"unavailable"}"#.to_string(),
                Some("disabled")
            ),
            "{path}"
        );
    }
    let (status, body, refusal) = local(plan(&p, "GET", "/v1/availability", b""));
    assert_eq!((status, refusal), (200, None));
    assert_eq!(
        json_of(body.as_bytes()),
        json!({"enabled": false, "countries": {}})
    );
}

#[test]
fn availability_comes_from_the_configuration() {
    let p = provider(true);
    let (status, body, refusal) = local(plan(&p, "GET", "/v1/availability", b""));
    assert_eq!((status, refusal), (200, None));
    assert_eq!(
        json_of(body.as_bytes()),
        json!({"enabled": true, "countries": {
            "US": {"buy": true, "sell": true}, "DE": {"buy": true, "sell": false}}})
    );
    // A GET with a body is refused, with a reason of its own.
    assert_eq!(
        local(plan(&p, "GET", "/v1/availability", b"{}")),
        (
            400,
            r#"{"error":"invalid_request"}"#.to_string(),
            Some("unexpected_body")
        )
    );
    assert_eq!(p.cap(Route::Availability), None);
    assert_eq!(
        p.cap(Route::Session),
        Some((30, std::time::Duration::from_secs(60)))
    );
    assert_eq!(
        p.cap(Route::SellStatus),
        Some((120, std::time::Duration::from_secs(60)))
    );
}

#[test]
fn a_session_is_built_from_the_validated_body_only() {
    let p = provider(true);
    let call = upstream(plan(
        &p,
        "POST",
        "/v1/session",
        &session_body(&format!(r#""flow":"buy","address":"{T1}","ref":"{REF}""#)),
    ));
    assert_eq!(call.route, Route::Session);
    assert_eq!(
        (call.method, call.path.as_str()),
        ("POST", "/onramp/v1/token")
    );
    assert_eq!(
        json_of(call.body.as_deref().unwrap()),
        json!({"addresses": [{"address": T1, "blockchains": ["zcash"]}], "assets": ["ZEC"]})
    );
    // No client IP, ever, and nothing else of the client's.
    let text = String::from_utf8(call.body.clone().unwrap()).unwrap();
    assert!(!text.contains("clientIp") && !text.contains(REF));
    assert_eq!(
        Coinbase::headers(&call),
        vec![
            ("accept", "application/json"),
            ("content-type", "application/json")
        ]
    );
    // The debug forms show the route, the status and lengths only.
    assert_eq!(format!("{call:?}"), "Call { route: Session, .. }");
    let debug = format!("{:?}", Plan::Upstream(call));
    assert!(!debug.contains(T1) && !debug.contains(REF), "{debug}");
    let answer = Answer {
        status: 200,
        body: T1.as_bytes().to_vec(),
    };
    assert_eq!(
        format!("{answer:?}"),
        "Answer { status: 200, body_len: 35 }"
    );
    // A sell with a preset.
    let call = upstream(plan(
        &p,
        "POST",
        "/v1/session",
        &session_body(&format!(
            r#""amount":"50.5","fiat":"EUR","ref":"{REF}","address":"{T1_OTHER}","flow":"sell""#
        )),
    ));
    assert_eq!(
        json_of(call.body.as_deref().unwrap())["addresses"][0]["address"],
        T1_OTHER
    );
}

#[test]
fn the_session_body_matrix() {
    let p = provider(true);
    let ok = |extra: &str| {
        session_body(&format!(
            r#""flow":"buy","address":"{T1}","ref":"{REF}"{extra}"#
        ))
    };
    for extra in [
        "",
        r#","fiat":"USD""#,
        r#","fiat":"CAD","amount":"1""#,
        r#","fiat":"GBP","amount":"10000""#,
        r#","fiat":"EUR","amount":"99.99""#,
    ] {
        assert!(
            matches!(
                plan(&p, "POST", "/v1/session", &ok(extra)),
                Plan::Upstream(_)
            ),
            "{extra}"
        );
    }
    let invalid_address = (
        400,
        r#"{"error":"invalid_address"}"#.to_string(),
        Some("invalid_address"),
    );
    let invalid_request = (
        400,
        r#"{"error":"invalid_request"}"#.to_string(),
        Some("invalid_request"),
    );
    let with_address = |address: &str| {
        session_body(&format!(
            r#""flow":"buy","address":"{address}","ref":"{REF}""#
        ))
    };
    let mut typo = T1.to_string();
    typo.replace_range(5..6, "X");
    for address in [
        T3,
        TESTNET,
        typo.as_str(),
        "u1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
        "",
        "t1",
    ] {
        assert_eq!(
            local(plan(&p, "POST", "/v1/session", &with_address(address))),
            invalid_address,
            "{address}"
        );
    }
    assert_eq!(
        local(plan(
            &p,
            "POST",
            "/v1/session",
            &session_body(&format!(r#""flow":"buy","address":7,"ref":"{REF}""#))
        )),
        invalid_address
    );
    let bodies: Vec<Vec<u8>> = vec![
        session_body(&format!(r#""flow":"buy","ref":"{REF}""#)),
        session_body(&format!(r#""address":"{T1}","ref":"{REF}""#)),
        session_body(&format!(r#""flow":"buy","address":"{T1}""#)),
        ok(r#","clientIp":"192.0.2.1""#),
        ok(r#","asset":"BTC""#),
        ok(r#","network":"ethereum""#),
        ok(r#","redirectUrl":"https://attacker.example""#),
        session_body(&format!(r#""flow":"rent","address":"{T1}","ref":"{REF}""#)),
        session_body(&format!(r#""flow":"buy","address":"{T1}","ref":"short""#)),
        session_body(&format!(r#""flow":"buy","address":"{T1}","ref":"{REF}0""#)),
        session_body(&format!(
            r#""flow":"buy","address":"{T1}","ref":"{}""#,
            "A".repeat(41)
        )),
        ok(r#","amount":"50""#),
        ok(r#","fiat":"JPY""#),
        ok(r#","fiat":"usd""#),
        ok(r#","fiat":"USD","amount":"0.5""#),
        ok(r#","fiat":"USD","amount":"10000.01""#),
        ok(r#","fiat":"USD","amount":"1e3""#),
        ok(r#","fiat":"USD","amount":50"#),
        ok(r#","flow":"sell""#),
        b"[]".to_vec(),
        b"".to_vec(),
        b"null".to_vec(),
        ok(&format!(r#","fiat":"USD"{}"#, " ".repeat(MAX_BODY_BYTES))),
    ];
    for body in &bodies {
        assert_eq!(
            local(plan(&p, "POST", "/v1/session", body)),
            invalid_request,
            "{}",
            String::from_utf8_lossy(body)
        );
    }
}

#[test]
fn a_sell_status_is_asked_by_its_ref() {
    let p = provider(true);
    let call = upstream(plan(
        &p,
        "POST",
        "/v1/sell/status",
        format!(r#"{{"ref":"{REF}"}}"#).as_bytes(),
    ));
    assert_eq!(
        (call.method, call.path.as_str(), call.body.as_ref()),
        (
            "GET",
            "/onramp/v1/sell/user/ABCDEFGHIJKLMNOPQRSTUVWXYZ/transactions",
            None
        )
    );
    assert_eq!(
        Coinbase::headers(&call),
        vec![("accept", "application/json")]
    );
    for body in [
        r#"{}"#.to_string(),
        r#"{"ref":"a/b"}"#.to_string(),
        format!(r#"{{"ref":"{REF}","address":"{T1}"}}"#),
        format!(r#"{{"ref":"{}/../x"}}"#, REF),
    ] {
        assert_eq!(
            local(plan(&p, "POST", "/v1/sell/status", body.as_bytes())).0,
            400,
            "{body}"
        );
    }
}

fn verify(token: &str, uri: &str) -> Value {
    let (input, sig) = token.rsplit_once('.').unwrap();
    let decode = |part: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(part)
            .unwrap()
    };
    let sig = ed25519_dalek::Signature::from_slice(&decode(sig)).unwrap();
    signer()
        .verifying_key()
        .verify(input.as_bytes(), &sig)
        .unwrap();
    let mut parts = input.split('.');
    let header: Value = serde_json::from_slice(&decode(parts.next().unwrap())).unwrap();
    assert_eq!(header["kid"], KEY_ID);
    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(header["nonce"], "42".repeat(16));
    let claims: Value = serde_json::from_slice(&decode(parts.next().unwrap())).unwrap();
    assert_eq!(claims["uri"], uri);
    assert_eq!(claims["iss"], "cdp");
    assert_eq!(claims["sub"], KEY_ID);
    claims
}

#[test]
fn every_call_gets_a_token_for_itself() {
    let p = provider(true);
    let session = upstream(plan(
        &p,
        "POST",
        "/v1/session",
        &session_body(&format!(r#""flow":"buy","address":"{T1}","ref":"{REF}""#)),
    ));
    let auth = p.authorization(&session, 1_700_000_000).unwrap();
    let claims = verify(
        auth.strip_prefix("Bearer ").unwrap(),
        "POST cdp-api.example/onramp/v1/token",
    );
    // The leeway: nbf a few seconds back, the lifetime unchanged.
    assert_eq!(
        (claims["nbf"].as_u64(), claims["exp"].as_u64()),
        (
            Some(1_700_000_000 - NBF_LEEWAY_SECS),
            Some(1_700_000_120 - NBF_LEEWAY_SECS)
        )
    );
    let status = upstream(plan(
        &p,
        "POST",
        "/v1/sell/status",
        format!(r#"{{"ref":"{REF}"}}"#).as_bytes(),
    ));
    let auth = p.authorization(&status, 500).unwrap();
    verify(
        auth.strip_prefix("Bearer ").unwrap(),
        &format!("GET cdp-api.example/onramp/v1/sell/user/{REF}/transactions"),
    );
    // Without a key: no token.
    let keyless = Coinbase::new(&settings(true), None, Arc::new(Fixed)).unwrap();
    assert!(!keyless.has_signer());
    assert_eq!(keyless.authorization(&session, 5), None);
}

fn session_call(p: &Coinbase, extra: &str, flow: &str) -> Call {
    upstream(plan(
        p,
        "POST",
        "/v1/session",
        &session_body(&format!(
            r#""flow":"{flow}","address":"{T1}","ref":"{REF}"{extra}"#
        )),
    ))
}

#[test]
fn a_minted_token_becomes_the_hosted_url() {
    let p = provider(true);
    let call = session_call(&p, "", "buy");
    let done = p.finish(
        &call,
        200,
        br#"{"token":"dG9r+ZW4/=","channel_id":""}"#,
        None,
        1000,
    );
    assert_eq!((done.outcome, done.answer.status), ("ok", 200));
    assert_eq!(
        json_of(&done.answer.body),
        json!({
            "url": format!("https://pay.coinbase.com/buy/select-asset?sessionToken=dG9r%2BZW4%2F%3D&defaultAsset=ZEC&defaultNetwork=zcash&partnerUserRef={REF}&redirectUrl=wallet%3A%2F%2Fonramp%2Freturn"),
            "expires_at": 1300,
        })
    );
    let call = session_call(&p, r#","fiat":"USD","amount":"50""#, "sell");
    let done = p.finish(&call, 201, br#"{"token":"abc"}"#, None, 0);
    assert_eq!(
        json_of(&done.answer.body)["url"],
        format!("https://pay.coinbase.com/v3/sell/input?sessionToken=abc&partnerUserRef={REF}&redirectUrl=wallet%3A%2F%2Fonramp%2Freturn&defaultAsset=ZEC&defaultNetwork=zcash&fiatCurrency=USD&presetFiatAmount=50")
    );
    // No redirect configured (no country sells): a buy has none in its URL, a sell is refused
    // before the upstream.
    let mut s = settings(true);
    s.redirect_url = None;
    s.countries.remove("US");
    let bare = Coinbase::new(&s, None, Arc::new(Fixed)).unwrap();
    let done = bare.finish(
        &session_call(&bare, "", "buy"),
        200,
        br#"{"token":"abc"}"#,
        None,
        0,
    );
    assert!(!json_of(&done.answer.body)["url"]
        .as_str()
        .unwrap()
        .contains("redirectUrl"));
    let sell = session_body(&format!(r#""flow":"sell","address":"{T1}","ref":"{REF}""#));
    assert_eq!(
        local(plan(&bare, "POST", "/v1/session", &sell)),
        (
            503,
            r#"{"error":"unavailable"}"#.to_string(),
            Some("sell_unavailable")
        )
    );
}

#[test]
fn every_upstream_failure_is_a_fixed_answer() {
    let p = provider(true);
    let call = session_call(&p, "", "buy");
    let upstream = (502, r#"{"error":"upstream"}"#.to_string());
    let answer = |status: u16, body: &[u8]| {
        let done = p.finish(&call, status, body, None, 0);
        (
            (
                done.answer.status,
                String::from_utf8(done.answer.body).unwrap(),
            ),
            done.outcome,
        )
    };
    // CDP's 400 echoes the address: never passed on.
    let echo = format!(r#"{{"message":"address [{T1}] is not valid for blockchain [zcash]"}}"#);
    for status in [400, 401, 403, 404, 500, 502, 503, 301, 100] {
        assert_eq!(
            answer(status, echo.as_bytes()),
            (upstream.clone(), "upstream_status"),
            "{status}"
        );
    }
    assert_eq!(
        answer(429, echo.as_bytes()),
        (
            (429, r#"{"error":"rate_limited"}"#.to_string()),
            "rate_limited"
        )
    );
    // The retry-after of an upstream 429: its own seconds, bounded; a default otherwise.
    for (header, secs) in [
        (None, RETRY_AFTER_DEFAULT),
        (Some("7"), 7),
        (Some("0"), 1),
        (Some("86400"), 300),
        (Some("Wed, 21 Oct 2026 07:28:00 GMT"), RETRY_AFTER_DEFAULT),
    ] {
        assert_eq!(
            p.finish(&call, 429, b"", header, 0).retry_after,
            Some(secs),
            "{header:?}"
        );
    }
    assert_eq!(p.finish(&call, 500, b"", Some("7"), 0).retry_after, None);
    for body in [
        b"".to_vec(),
        b"not json".to_vec(),
        b"{}".to_vec(),
        b"[]".to_vec(),
        br#"{"token":7}"#.to_vec(),
        br#"{"token":""}"#.to_vec(),
        br#"{"token":"a b"}"#.to_vec(),
        br#"{"token":"a&b"}"#.to_vec(),
        format!(r#"{{"token":"{}"}}"#, "a".repeat(2049)).into_bytes(),
        format!(
            r#"{{"token":"a","pad":"{}"}}"#,
            "a".repeat(MAX_UPSTREAM_BODY_BYTES)
        )
        .into_bytes(),
    ] {
        assert_eq!(
            answer(200, &body),
            (upstream.clone(), "upstream_shape"),
            "{}",
            String::from_utf8_lossy(&body)
        );
    }
    // What a status means before any body is read.
    assert_eq!(Coinbase::response_action(204), ResponseAction::Rewrite);
    assert_eq!(
        Coinbase::response_action(400),
        ResponseAction::Replace {
            status: 502,
            body: answers::UPSTREAM
        }
    );
    assert_eq!(
        Coinbase::response_action(429),
        ResponseAction::Replace {
            status: 429,
            body: answers::RATE_LIMITED
        }
    );
}

fn tx(fields: &str) -> String {
    let created = if fields.contains("created_at") {
        ""
    } else {
        r#","created_at":"2026-11-01T00:00:00Z""#
    };
    format!(
        r#"{{"status":"TRANSACTION_STATUS_STARTED","asset":"ZEC","network":"zcash"{created}{fields}}}"#
    )
}

#[test]
fn rfc3339_instants() {
    assert_eq!(rfc3339_utc("1970-01-01T00:00:00Z"), Some((0, 0)));
    assert_eq!(
        rfc3339_utc("2026-11-20T12:00:00Z"),
        Some((1_795_176_000, 0))
    );
    assert_eq!(
        rfc3339_utc("2026-11-20T13:30:00+01:30"),
        rfc3339_utc("2026-11-20T12:00:00Z")
    );
    assert_eq!(
        rfc3339_utc("2026-11-20T11:00:00.5-01:00"),
        Some((1_795_176_000, 500_000_000))
    );
    assert_eq!(
        rfc3339_utc("2024-02-29t00:00:00z").map(|t| t.0),
        Some(1_709_164_800)
    );
    assert_eq!(rfc3339_utc("1969-12-31T23:59:59Z"), Some((-1, 0)));
    for bad in [
        "",
        "2026-11-20",
        "2026-11-20T12:00:00",
        "2026-13-01T00:00:00Z",
        "2026-02-29T00:00:00Z",
        "2026-11-20T24:00:00Z",
        "2026-11-20T12:00:00.Z",
        "2026-11-20T12:00:00.1234567890Z",
        "2026-11-20T12:00:00+0100",
        "2026-11-20T12:00:00Zx",
        "+026-11-20T12:00:00Z",
        "1700000000",
    ] {
        assert_eq!(rfc3339_utc(bad), None, "{bad}");
    }
}

#[test]
fn the_sell_status_answer() {
    let p = provider(true);
    let call = upstream(plan(
        &p,
        "POST",
        "/v1/sell/status",
        format!(r#"{{"ref":"{REF}"}}"#).as_bytes(),
    ));
    let status = |body: &str| {
        let done = p.finish(&call, 200, body.as_bytes(), None, 0);
        (done.answer.status, json_of(&done.answer.body), done.outcome)
    };
    let list = |txs: &[String]| format!(r#"{{"transactions":[{}]}}"#, txs.join(","));
    let started = list(&[tx(&format!(
        r#","to_address":"{T3}","sell_amount":{{"value":"0.12345678","currency":"ZEC"}},"partner_user_ref":"{REF}","tx_hash":"""#
    ))]);
    assert_eq!(
        status(&started),
        (
            200,
            json!({"status": "started", "asset": "ZEC", "network": "zcash",
                "to_address": T3, "sell_amount": "0.12345678"}),
            "ok"
        )
    );
    for (cdp, ours) in [
        ("TRANSACTION_STATUS_SUCCESS", "success"),
        ("TRANSACTION_STATUS_FAILED", "failed"),
        ("TRANSACTION_STATUS_SOMETHING_NEW", "unknown"),
    ] {
        assert_eq!(
            status(&list(&[tx("").replace("TRANSACTION_STATUS_STARTED", cdp)])).1,
            json!({"status": ours, "asset": "ZEC", "network": "zcash"})
        );
    }
    // Only the documented empty list is not_found.
    assert_eq!(
        status(r#"{"transactions":[]}"#).1,
        json!({"status": "not_found", "asset": "ZEC", "network": "zcash"})
    );
    // The newest transaction of the ref.
    let older = tx(&format!(
        r#","created_at":"2026-11-01T10:00:00Z","partner_user_ref":"{REF}","sell_amount":{{"value":"1","currency":"ZEC"}}"#
    ));
    let newer = tx(&format!(
        r#","created_at":"2026-11-02T10:00:00Z","partner_user_ref":"{REF}","sell_amount":{{"value":"2","currency":"ZEC"}}"#
    ));
    let other = tx(
        r#","created_at":"2026-11-03T10:00:00Z","partner_user_ref":"ZZZZZZZZZZZZZZZZZZZZZZZZZZ","sell_amount":{"value":"3","currency":"ZEC"}"#,
    );
    assert_eq!(
        status(&list(&[older.clone(), other.clone(), newer.clone()])).1["sell_amount"],
        "2"
    );
    assert_eq!(
        status(&list(&[newer.clone(), older.clone()])).1["sell_amount"],
        "2"
    );
    // Offsets are compared as UTC: 11:00+02:00 is before 10:00Z.
    let early = tx(&format!(
        r#","created_at":"2026-11-02T11:00:00+02:00","partner_user_ref":"{REF}","sell_amount":{{"value":"7","currency":"ZEC"}}"#
    ));
    let late = tx(&format!(
        r#","created_at":"2026-11-02T10:00:00Z","partner_user_ref":"{REF}","sell_amount":{{"value":"8","currency":"ZEC"}}"#
    ));
    assert_eq!(status(&list(&[late, early])).1["sell_amount"], "8");
    // No transaction names a ref: the newest of all.
    let a =
        tx(r#","created_at":"2026-11-01T10:00:00Z","sell_amount":{"value":"1","currency":"ZEC"}"#);
    let b =
        tx(r#","created_at":"2026-11-05T10:00:00Z","sell_amount":{"value":"5","currency":"ZEC"}"#);
    assert_eq!(status(&list(&[b, a])).1["sell_amount"], "5");
    // Empty values are absent.
    assert_eq!(
        status(&list(&[tx(
            r#","to_address":"","sell_amount":{"value":""}"#
        )]))
        .1,
        json!({"status": "started", "asset": "ZEC", "network": "zcash"})
    );
    // Anything the wallet could be misled by fails closed.
    let bad = [
        // Not the documented shape.
        "{}".to_string(),
        "[]".to_string(),
        r#"{"transactions":null}"#.to_string(),
        r#"{"transactions":{}}"#.to_string(),
        r#"{"error":"not found"}"#.to_string(),
        r#"{"transactions":["x"]}"#.to_string(),
        // Only other refs.
        list(&[other]),
        // Missing evidence.
        format!(r#"{{"transactions":[{}]}}"#, tx("").replace(r#","created_at":"2026-11-01T00:00:00Z""#, "")),
        list(&[tx(r#","created_at":"yesterday""#)]),
        r#"{"transactions":[{"status":"TRANSACTION_STATUS_STARTED"}]}"#.to_string(),
        list(&[tx("").replace(r#","network":"zcash""#, "")]),
        list(&[tx("").replace(r#","asset":"ZEC""#, "")]),
        list(&[tx(r#","sell_amount":{"value":"1"}"#)]),
        list(&[tx(r#","sell_amount":"1.5""#)]),
        // Other values.
        list(&[tx("").replace(r#""asset":"ZEC""#, r#""asset":"BTC""#)]),
        list(&[tx("").replace(r#""network":"zcash""#, r#""network":"ethereum""#)]),
        list(&[tx(&format!(r#","to_address":"{TESTNET}""#))]),
        list(&[tx(r#","to_address":"0xabc""#)]),
        list(&[tx(r#","sell_amount":{"value":"1","currency":"BTC"}"#)]),
        list(&[tx(r#","sell_amount":{"value":"-1","currency":"ZEC"}"#)]),
        list(&[tx(
            r#","sell_amount":{"value":"0.123456789","currency":"ZEC"}"#,
        )]),
        list(&[tx(r#","sell_amount":1"#)]),
        r#"{"transactions":[{"status":7,"asset":"ZEC","network":"zcash","created_at":"2026-11-01T00:00:00Z"}]}"#.to_string(),
    ];
    for bad in &bad {
        assert_eq!(
            status(bad),
            (502, json!({"error": "upstream"}), "upstream_shape"),
            "{bad}"
        );
    }
}

#[test]
fn settings_and_urls() {
    let s = settings(true);
    let debug = format!("{s:?} {:?}", provider(true));
    assert!(
        !debug.contains("nWGx") && !debug.contains(KEY_ID),
        "{debug}"
    );
    let rendered = r#"[{"label":"onramp","alias":"onramp.example","upstream":"https://cdp-api.example","secret":{"name":"cdp_key","env":null,"file":"/k"},"read_key":false,"ttl_secs":120,"enabled":true,"redirect_url":null,"countries":{"US":{"buy":true,"sell":false}},"rate_limit":"1/1s","status_rate_limit":"2/1s"}]"#;
    let parsed = Settings::parse_rendered(rendered).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].secret.file.as_deref(), Some("/k"));
    assert!(!parsed[0].read_key && !parsed[0].sells());
    assert!(Settings::parse_rendered(&rendered.replace("\"label\"", "\"labels\"")).is_err());
    for (upstream, ok) in [
        ("https://cdp-api.example", true),
        ("https://cdp-api.example/", true),
        ("https://CDP-api.example", true),
        ("https://cdp-api.example:8443", true),
        ("http://127.0.0.1:8080", true),
        ("http://localhost:8080", true),
        ("http://[::1]:8080", true),
        ("http://cdp-api.example", false),
        ("http://10.0.0.1:8080", false),
        ("https://cdp-api.example:443", false),
        ("https://cdp-api.example:0443", false),
        ("https://cdp-api.example:70000", false),
        ("http://127.0.0.1:80", false),
        ("https://cdp-api.example/base", false),
        ("https://cdp-api.example?x", false),
        ("https://user@cdp-api.example", false),
        ("ftp://cdp-api.example", false),
        ("HTTPS://cdp-api.example", false),
        ("https://", false),
    ] {
        let mut s = settings(true);
        s.upstream = upstream.to_string();
        assert_eq!(
            Coinbase::new(&s, None, Arc::new(Fixed)).is_ok(),
            ok,
            "{upstream}"
        );
    }
    let mut s = settings(true);
    s.upstream = "https://CDP-API.example/".into();
    let p = Coinbase::new(&s, None, Arc::new(Fixed)).unwrap();
    assert_eq!(
        (p.upstream(), p.upstream_host()),
        ("https://cdp-api.example", "cdp-api.example")
    );
    let mut s = settings(true);
    s.redirect_url = Some("not a url".into());
    assert!(Coinbase::new(&s, None, Arc::new(Fixed)).is_err());
    // A country sells: a redirect is required.
    let mut s = settings(true);
    s.redirect_url = None;
    let text = Coinbase::new(&s, None, Arc::new(Fixed))
        .unwrap_err()
        .to_string();
    assert!(text.contains("needs a redirect_url"), "{text}");
    let mut s = settings(true);
    s.status_rate_limit = "many".into();
    assert!(Coinbase::new(&s, None, Arc::new(Fixed)).is_err());
    for (url, ok) in [
        ("wallet://onramp/return", true),
        ("https://wallet.example/return?x=1", true),
        ("a:b", true),
        ("", false),
        ("noscheme", false),
        ("1abc://x", false),
        ("Wallet://x", false),
        ("wallet:", false),
        ("http://wallet.example/return", false),
        ("javascript:alert(1)", false),
        ("JavaScript:alert(1)", false),
        ("data:text/html,x", false),
        ("file:///etc/passwd", false),
        ("vbscript:x", false),
        ("wallet://a b", false),
        ("wallet://\u{e9}", false),
    ] {
        assert_eq!(is_redirect_url(url), ok, "{url}");
    }
    assert!(!is_redirect_url(&format!(
        "a:{}",
        "b".repeat(MAX_REDIRECT_URL_LEN)
    )));
    assert_eq!(encode("a+b/c=d e~._-"), "a%2Bb%2Fc%3Dd%20e~._-");
}

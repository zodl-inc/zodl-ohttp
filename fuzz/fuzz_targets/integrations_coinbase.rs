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

//! The coinbase provider on an arbitrary request body and upstream answer: the first byte picks
//! the route and the upstream status, the rest up to the first `0xff` is the request body, what
//! follows is the upstream body. Nothing panics; a request goes upstream only with a body that
//! passed its schema and, for a session, the wallet's signature at the fuzzer's fixed clock (the
//! session body names exactly one valid mainnet P2PKH address, the constant asset and network,
//! nothing else); every answer is one of the fixed statuses and JSON.

#![no_main]

use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use zodl_ohttp_integrations::coinbase::{
    signature, Coinbase, Country, Plan, Route, SecretSource, Settings,
};
use zodl_ohttp_integrations::core::auth::{JwtEdDsa, NonceSource};
use zodl_ohttp_integrations::core::body::{self, Check};
use zodl_ohttp_integrations::core::provider::RequestView;

struct Fixed;

impl NonceSource for Fixed {
    fn fill(&self, out: &mut [u8]) {
        out.fill(1);
    }
}

fn provider() -> Coinbase {
    let settings = Settings {
        label: "onramp".into(),
        alias: "onramp.example".into(),
        upstream: "https://cdp-api.example".into(),
        secret: SecretSource {
            name: "cdp_key".into(),
            env: None,
            file: None,
        },
        read_key: true,
        ttl_secs: 120,
        enabled: true,
        redirect_url: Some("wallet://return".into()),
        countries: [(
            "US".to_string(),
            Country {
                buy: true,
                sell: true,
            },
        )]
        .into(),
        rate_limit: "1/1s".into(),
        status_rate_limit: "1/1s".into(),
    };
    // RFC 8032 section 7.1 test 1: a published test key.
    let signer = JwtEdDsa::from_cdp_json(
        r#"{"id":"k","privateKey":"nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A="}"#,
        120,
    )
    .expect("the test key");
    Coinbase::new(&settings, Some(signer), Arc::new(Fixed)).expect("the provider")
}

/// The clock of the fuzzer: the published test vector's timestamp (a seed carries its body).
const NOW: u64 = 1_700_000_000;
/// The published test vector's address.
const VECTOR_ADDRESS: &str = "t1RwUkDxFKCydymAzBtTwHtVyH9Tvf6CiiL";

const ADDRESS: Check = Check::Base58Check {
    versions: &[body::ZCASH_MAINNET_P2PKH],
    payload_len: body::TRANSPARENT_HASH_BYTES,
};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let (request_body, upstream_body) = match rest.iter().position(|&b| b == 0xff) {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, &[][..]),
    };
    let (method, path) = match selector % 4 {
        0 => ("POST", "/v1/session"),
        1 => ("POST", "/v1/sell/status"),
        2 => ("GET", "/v1/availability"),
        _ => ("POST", "/v1/other"),
    };
    let status = [200u16, 201, 400, 429, 500][usize::from(selector / 4) % 5];
    let p = provider();
    let req = RequestView {
        method,
        path,
        headers: &[],
        body: request_body,
    };
    match p.plan(&req, NOW) {
        Plan::Denied(_) => assert_eq!(path, "/v1/other"),
        Plan::Local { answer, .. } => {
            assert!(matches!(answer.status, 200 | 400 | 401 | 503));
            serde_json::from_slice::<serde_json::Value>(&answer.body).expect("JSON");
        }
        Plan::Upstream(call) => {
            match call.route {
                Route::Session => {
                    let sent: serde_json::Value =
                        serde_json::from_slice(call.body.as_deref().expect("a body")).unwrap();
                    let addresses = sent["addresses"].as_array().unwrap();
                    assert_eq!(addresses.len(), 1);
                    assert!(ADDRESS.accepts(addresses[0]["address"].as_str().unwrap()));
                    assert_eq!(addresses[0]["blockchains"], serde_json::json!(["zcash"]));
                    assert_eq!(sent["assets"], serde_json::json!(["ZEC"]));
                    assert_eq!(sent.as_object().unwrap().len(), 2);
                    // Only a request the wallet signed, fresh at the fuzzer's clock.
                    let got: serde_json::Value = serde_json::from_slice(request_body).unwrap();
                    let member = |name: &str| got[name].as_str().unwrap();
                    let timestamp: u64 = member("timestamp").parse().unwrap();
                    assert!(signature::is_fresh(timestamp, NOW));
                    assert!(
                        signature::verify(member("address"), timestamp, member("signature"))
                            .is_ok()
                    );
                    assert_eq!(member("address"), addresses[0]["address"].as_str().unwrap());
                }
                Route::SellStatus => {
                    assert!(call.body.is_none());
                    assert!(!call.path.contains(['?', '#', '%', '.']));
                }
                Route::Availability => panic!("the availability document is local"),
            }
            assert!(p.authorization(&call, 1_700_000_000).is_some());
            let done = p.finish(&call, status, upstream_body, Some("5"), 1_700_000_000);
            assert!(matches!(done.answer.status, 200 | 429 | 502));
            serde_json::from_slice::<serde_json::Value>(&done.answer.body).expect("JSON");
        }
    }
    // The validators on their own.
    if let Ok(text) = std::str::from_utf8(request_body) {
        let _ = ADDRESS.accepts(text);
        let _ = body::base58check(text);
        let _ = signature::verify(VECTOR_ADDRESS, NOW, text);
        let _ = signature::verify(text, NOW, "IJdQ6f64QRlbvvFp2dTb33IU8GeRNmRVE1/re+l6yGVkeTv0Lvbid7DGQ3JxOVXZZ4GpXl24i75ZzDQe1Z5jZAs=");
        let _ = Check::Decimal {
            max_fraction: 8,
            min: "0",
            max: "21000000",
        }
        .accepts(text);
    }
});

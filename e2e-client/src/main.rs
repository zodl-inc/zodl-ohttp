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

// One chunked OHTTP exchange (RFC 9458 + draft-ietf-ohai-chunked-ohttp-08) for end-to-end
// checks: key config -> BHTTP -> HPKE encapsulation -> relay -> decapsulate, printing every step. The encapsulation is `zodl-ohttp-client`'s; the outer
// request is sent here, so the relay hardening knobs below can alter it.
use anyhow::{bail, Result};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use zodl_ohttp_client::{
    decode_bhttp_response, doh_query_url, encapsulate_chunked_request, encode_request,
    envelope_from_doh_json, open_signed_config, verify_signed_config, DecodeOptions, KeyConfig,
    Network, OhttpConfig, OhttpConfigParams, OhttpNetworks, Request, SignedConfigPolicy,
    VerifyingKey, CONTENT_TYPE_CHUNKED_REQ, CONTENT_TYPE_CHUNKED_RES, DOH_RESOLVERS,
};

/// The runtime OHTTP configuration of each network, from the environment: the four variables
/// `OHTTP_E2E_GATEWAY_HOST_<NET>`, `OHTTP_E2E_RELAY_URL_<NET>`, `OHTTP_E2E_KEYS_DNS_NAME_<NET>`
/// and `OHTTP_E2E_SIGNING_PUBKEY_<NET>`, `<NET>` being `MAINNET` or `TESTNET`.
const CONFIG_VARS: [&str; 4] = [
    "OHTTP_E2E_GATEWAY_HOST",
    "OHTTP_E2E_RELAY_URL",
    "OHTTP_E2E_KEYS_DNS_NAME",
    "OHTTP_E2E_SIGNING_PUBKEY",
];

/// The OHTTP configuration of both networks, read through `var` (the process environment, or a
/// map in tests). A network is configured with all four of its variables or none (an empty
/// variable counts as unset); none leaves it off. Errors name variables and rules, never values.
fn networks_from(var: impl Fn(&str) -> Option<String>) -> Result<OhttpNetworks> {
    let network = |network: Network| -> Result<Option<OhttpConfig>> {
        let names =
            CONFIG_VARS.map(|prefix| format!("{prefix}_{}", network.as_str().to_ascii_uppercase()));
        let values = names
            .clone()
            .map(|name| var(&name).filter(|value| !value.is_empty()));
        if values.iter().all(Option::is_none) {
            return Ok(None);
        }
        let missing: Vec<&str> = names
            .iter()
            .zip(&values)
            .filter(|(_, value)| value.is_none())
            .map(|(name, _)| name.as_str())
            .collect();
        if !missing.is_empty() {
            bail!(
                "{} OHTTP configuration is incomplete: set all four variables or none; missing {}",
                network.as_str(),
                missing.join(", ")
            );
        }
        let [host, relay, dns, key] = values.map(Option::unwrap_or_default);
        OhttpConfig::new(OhttpConfigParams {
            gateway_host: &host,
            relay_url: &relay,
            keys_dns_name: &dns,
            signing_pubkey: &key,
        })
        .map(Some)
        .map_err(|e| anyhow::anyhow!("{}: {e}", network.as_str()))
    };
    Ok(OhttpNetworks::new(
        network(Network::Mainnet)?,
        network(Network::Testnet)?,
    )?)
}

/// [`networks_from`] the process environment.
fn networks() -> Result<OhttpNetworks> {
    networks_from(|name| std::env::var(name).ok())
}

/// The network named `name`.
fn network_named(name: &str) -> Result<Network> {
    Network::from_name(name).ok_or_else(|| anyhow::anyhow!("network must be mainnet or testnet"))
}

/// The signing key configured for `network`.
fn signer(networks: &OhttpNetworks, network: Network) -> Result<VerifyingKey> {
    match networks.get(network) {
        Some(config) => Ok(*config.signing_pubkey()),
        None => bail!(
            "no OHTTP configuration for {0}: set the OHTTP_E2E_*_{1} variables",
            network.as_str(),
            network.as_str().to_ascii_uppercase()
        ),
    }
}

fn usage() -> ! {
    eprintln!("usage: ohttp-e2e <config_url> <relay_url> <authority> <method> <path> [trace_id] [grpc|http] [body_hex]");
    eprintln!("       ohttp-e2e --key-config-source dns <network>");
    eprintln!("  env: NETWORK=mainnet|testnet (for signed config verification)");
    eprintln!("  env: OHTTP_E2E_{{GATEWAY_HOST,RELAY_URL,KEYS_DNS_NAME,SIGNING_PUBKEY}}_{{MAINNET,TESTNET}}:");
    eprintln!("       the OHTTP configuration of each network, needed for signed configs and DNS");
    eprintln!("  --key-config-source dns: fetch and verify envelope from DNS-over-HTTPS");
    std::process::exit(2)
}

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();

    // DNS key config test mode
    if a.len() == 4 && a[1] == "--key-config-source" && a[2] == "dns" {
        return dns_key_config_test(&a[3]);
    }

    if a.len() < 6 {
        usage()
    }
    let (config_url, relay_url, authority, method, path) = (&a[1], &a[2], &a[3], &a[4], &a[5]);
    let trace_id = a.get(6).cloned().unwrap_or_default();
    let kind = a.get(7).cloned().unwrap_or_else(|| "grpc".into());
    let body: Vec<u8> = match a.get(8) {
        Some(h) => hex::decode(h)?,
        None => {
            if kind == "grpc" {
                vec![0, 0, 0, 0, 0]
            } else {
                vec![]
            }
        }
    };

    let http = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    // 1. key config (application/ohttp-keys, length-prefixed OR signed JSON)
    let t = Instant::now();
    // OHTTP_E2E_EXTRA_HEADERS go on this GET too: an origin checked directly (no relay in front)
    // with RELAY_SECRET_ON_KEY_CONFIG=require wants X-Relay-Secret on the key configuration.
    let mut kb = http.get(config_url);
    for (k, v) in extra_headers() {
        kb = kb.header(k, v)
    }
    let resp = kb.send()?.error_for_status()?;
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let kc_raw = resp.bytes()?;

    // If the config URL contains /signed or the content-type contains application/json, verify
    // the signature
    let kc = if config_url.contains("/signed") || content_type.contains("application/json") {
        let network = std::env::var("NETWORK").unwrap_or_else(|_| "mainnet".to_string());
        println!(
            "[1] signed config {} bytes in {:?} from {} (network={})",
            kc_raw.len(),
            t.elapsed(),
            config_url,
            network
        );
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let signer = signer(&networks()?, network_named(&network)?)?;
        let keys = open_signed_config(&kc_raw, &network, &signer, now)?;
        println!("signed-configs: OK not_after={}", keys.not_after);
        keys.document
    } else {
        println!(
            "[1] key config {} bytes in {:?} from {}",
            kc_raw.len(),
            t.elapsed(),
            config_url
        );
        kc_raw.to_vec()
    };
    let config = KeyConfig::select(&kc)?;
    println!(
        "    key_id={} kem=0x0020 kdf=0x0001 aead=0x0001 pk={}",
        config.key_id(),
        hex::encode(config.public_key())
    );

    // 2. BHTTP known-length request
    let mut request = Request::new(method.as_str(), authority.as_str(), path.as_str());
    if kind == "grpc" {
        request = request
            .header("content-type", "application/grpc")
            .header("te", "trailers");
    } else {
        request = request.header("accept", "application/json");
        if !body.is_empty() {
            request = request.header("content-type", "application/json");
        }
    }
    let plain = encode_request(&request.body(body.clone()))?;

    // 3. HPKE seal as a chunked request (draft-ietf-ohai-chunked-ohttp-08 §6.1)
    let (req, opener) = encapsulate_chunked_request(&config, &plain)?;
    println!("[2] inner {method} https://{authority}{path} ({} B bhttp, {} B body) -> {} B ohttp-chunked-req", plain.len(), body.len(), req.len());

    // 4. POST to relay
    let t = Instant::now();
    let mut rb = http
        .post(relay_url)
        .header("content-type", CONTENT_TYPE_CHUNKED_REQ)
        .body(req.clone());
    if !trace_id.is_empty() {
        rb = rb.header("X-Client-Trace-Id", &trace_id)
    }
    // Optional: send a client-chosen X-Request-Id to check that the relay replaces it (it MUST).
    if let Ok(rid) = std::env::var("OHTTP_E2E_REQUEST_ID") {
        rb = rb.header("X-Request-Id", rid)
    }
    // Optional arbitrary outer headers for relay hardening tests: "Name: value|Name2: value2".
    for (k, v) in extra_headers() {
        rb = rb.header(k, v)
    }

    // Cross-origin replay test: OHTTP_E2E_REPLAY_URLS="urlA,urlB[,urlC...]" sends the SAME sealed
    // bytes to each URL in order (same extra headers), printing the outer status and latency of
    // each. OHTTP_E2E_REPLAY_GAP_MS (default 0) sleeps between sends. The first send is expected 200,
    // every later one 409 when the origins share replay state.
    if let Ok(urls) = std::env::var("OHTTP_E2E_REPLAY_URLS") {
        let gap: u64 = std::env::var("OHTTP_E2E_REPLAY_GAP_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        for (i, url) in urls
            .split(',')
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .enumerate()
        {
            if i > 0 && gap > 0 {
                std::thread::sleep(std::time::Duration::from_millis(gap));
            }
            let mut r = http
                .post(url)
                .header("content-type", CONTENT_TYPE_CHUNKED_REQ)
                .body(req.clone());
            if !trace_id.is_empty() {
                r = r.header("X-Client-Trace-Id", format!("{trace_id}-r{i}"))
            }
            for (k, v) in extra_headers() {
                r = r.header(k, v)
            }
            let t = Instant::now();
            let resp = r.send()?;
            let status = resp.status();
            let body = resp.bytes()?;
            println!(
                "[XREPLAY {i}] {url} -> HTTP {} in {:?} ({} B) {}",
                status,
                t.elapsed(),
                body.len(),
                if status.is_success() {
                    String::new()
                } else {
                    String::from_utf8_lossy(&body).to_string()
                }
            );
        }
        return Ok(());
    }

    // Replay test: send the same request twice if OHTTP_E2E_REPLAY=1
    if std::env::var("OHTTP_E2E_REPLAY").ok().as_deref() == Some("1") {
        println!("[REPLAY TEST] Sending request twice to test replay protection");
        let resp1 = http
            .post(relay_url)
            .header("content-type", CONTENT_TYPE_CHUNKED_REQ)
            .body(req.clone())
            .send()?;
        println!("[REPLAY 1] HTTP {}", resp1.status());
        std::thread::sleep(std::time::Duration::from_millis(100));
        let resp2 = http
            .post(relay_url)
            .header("content-type", CONTENT_TYPE_CHUNKED_REQ)
            .body(req.clone())
            .send()?;
        let status2 = resp2.status();
        println!("[REPLAY 2] HTTP {}", status2);
        if status2.as_u16() == 409 {
            println!("[REPLAY TEST] PASS: Second request rejected with 409");
        } else {
            bail!("REPLAY TEST FAILED: Expected 409, got {}", status2);
        }
        return Ok(());
    }

    let resp = rb.send()?;
    let status = resp.status();
    let hdrs = resp.headers().clone();
    let rbody = resp.bytes()?;
    println!(
        "[3] relay {relay_url} -> HTTP {} in {:?}, {} B, content-type={:?}, x-request-id={:?}",
        status,
        t.elapsed(),
        rbody.len(),
        hdrs.get("content-type").map(|v| v.to_str().unwrap_or("?")),
        hdrs.get("x-request-id").map(|v| v.to_str().unwrap_or("?"))
    );
    if std::env::var("OHTTP_E2E_DUMP_HEADERS").is_ok() {
        println!("    Response headers:");
        for (k, v) in hdrs.iter() {
            println!("      {}: {}", k, v.to_str().unwrap_or("?"));
        }
    }
    if !status.is_success() {
        bail!("relay returned {status}")
    }
    let ct = hdrs
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !ct.contains(CONTENT_TYPE_CHUNKED_RES) {
        bail!("wrong content-type: {ct}")
    }

    // 5. Open the chunked response (§6.2) and parse the indeterminate-length BHTTP inner response
    let t = Instant::now();
    let plaintext = opener.open(&rbody)?;
    // The codec reading (not decode_response): it keeps the trailer section, where a streamed
    // gRPC response carries grpc-status.
    let inner = decode_bhttp_response(&plaintext, &DecodeOptions::HTTP_STATUS)?;
    println!(
        "[4] inner response status={} ({} B plain incl. padding, {} B body) in {:?}",
        inner.status,
        plaintext.len(),
        inner.body.len(),
        t.elapsed()
    );
    for (name, value) in inner.headers_utf8_lossy() {
        println!("    {name}: {value}");
    }
    for (name, value) in inner.trailers_latin1() {
        println!("    (trailer) {name}: {value}");
    }
    if !inner.body.is_empty() {
        if let Ok(s) = std::str::from_utf8(&inner.body) {
            println!("\n{s}");
        } else {
            println!("hex: {}", hex::encode(&inner.body));
        }
    }
    // OHTTP_E2E_EXPECT_OK=1 (periodic checks): fail unless the inner response is a success,
    // i.e. inner 200 and, for gRPC, grpc-status 0.
    if std::env::var("OHTTP_E2E_EXPECT_OK").ok().as_deref() == Some("1") {
        if inner.status != 200 {
            bail!("inner status {}", inner.status)
        }
        if let Some(gs) = inner.field("grpc-status") {
            if gs != b"0" {
                bail!("grpc-status {}", String::from_utf8_lossy(gs))
            }
        } else if kind == "grpc" {
            bail!("no grpc-status in the inner response")
        }
    }
    Ok(())
}

fn dns_key_config_test(network_str: &str) -> Result<()> {
    let network = network_named(network_str)?;
    let networks = networks()?;

    let http = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    println!("DNS key config test for {}", network.as_str());
    // Fails without a configuration for the network.
    signer(&networks, network)?;
    println!("Resolvers: {:?}", DOH_RESOLVERS);

    for (i, resolver) in DOH_RESOLVERS.iter().enumerate() {
        println!("\n[{}] Trying resolver: {}", i + 1, resolver);
        let Some(url) = doh_query_url(&networks, resolver, network) else {
            bail!("no key-configuration DNS name for {}", network.as_str());
        };
        println!("    URL: {}", url);

        let t = Instant::now();
        let resp = match http
            .get(&url)
            .header("accept", "application/dns-json")
            .send()
        {
            Ok(r) => r,
            Err(e) => {
                println!("    ERROR: {}", e);
                continue;
            }
        };

        if !resp.status().is_success() {
            println!("    ERROR: HTTP {}", resp.status());
            continue;
        }

        let body = match resp.bytes() {
            Ok(b) => b,
            Err(e) => {
                println!("    ERROR reading response body: {}", e);
                continue;
            }
        };
        println!("    Response: {} bytes in {:?}", body.len(), t.elapsed());

        match envelope_from_doh_json(&networks, &body, network) {
            Ok(envelope) => {
                println!("    Envelope: {} bytes", envelope.len());

                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                match verify_signed_config(
                    &networks,
                    &envelope,
                    network,
                    now,
                    &SignedConfigPolicy::LIBRARY,
                ) {
                    Ok(keys) => {
                        println!("    Signature: OK");
                        println!("    not_after: {}", keys.not_after);

                        match KeyConfig::select(&keys.document) {
                            Ok(config) => {
                                println!("    key_id: {}", config.key_id());
                                println!("    SUCCESS");
                                return Ok(());
                            }
                            Err(e) => {
                                println!("    ERROR selecting key: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        println!("    ERROR verifying signature: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("    ERROR parsing DoH response: {}", e);
            }
        }
    }

    bail!("All DNS resolvers failed")
}

/// `OHTTP_E2E_EXTRA_HEADERS="Name: value|Name2: value2"` as (name, value) pairs.
fn extra_headers() -> Vec<(String, String)> {
    std::env::var("OHTTP_E2E_EXTRA_HEADERS")
        .unwrap_or_default()
        .split('|')
        .filter_map(|kv| kv.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Valid example signing keys: the Ed25519 base point (`1`) and its double (`2`).
    fn key_hex(which: u8) -> String {
        match which {
            1 => "5866666666666666666666666666666666666666666666666666666666666666".into(),
            _ => "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022".into(),
        }
    }

    fn env(pairs: &[(&str, String)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(name, value)| (name.to_string(), value.clone()))
            .collect();
        move |name| map.get(name).cloned()
    }

    fn testnet() -> Vec<(&'static str, String)> {
        vec![
            (
                "OHTTP_E2E_GATEWAY_HOST_TESTNET",
                "ohttp-gateway-testnet.example".into(),
            ),
            (
                "OHTTP_E2E_RELAY_URL_TESTNET",
                "https://relay-testnet.example/relay".into(),
            ),
            (
                "OHTTP_E2E_KEYS_DNS_NAME_TESTNET",
                "testnet.ohttp-keys.example".into(),
            ),
            ("OHTTP_E2E_SIGNING_PUBKEY_TESTNET", key_hex(1)),
        ]
    }

    #[test]
    fn no_variables_means_ohttp_off() {
        let networks = networks_from(env(&[])).unwrap();
        assert_eq!(networks, OhttpNetworks::default());
        assert!(signer(&networks, Network::Mainnet).is_err());
    }

    #[test]
    fn one_complete_network_is_configured() {
        let networks = networks_from(env(&testnet())).unwrap();
        let config = networks.get(Network::Testnet).unwrap();
        assert_eq!(config.gateway_host(), "ohttp-gateway-testnet.example");
        assert_eq!(
            networks.relay_for("ohttp-gateway-testnet.example"),
            Some("https://relay-testnet.example/relay")
        );
        assert!(networks.get(Network::Mainnet).is_none());
        assert!(signer(&networks, Network::Testnet).is_ok());
    }

    #[test]
    fn a_partial_or_invalid_network_is_an_error_without_values() {
        let mut partial = testnet();
        partial.remove(1);
        let error = networks_from(env(&partial)).unwrap_err().to_string();
        assert!(
            error.contains("missing OHTTP_E2E_RELAY_URL_TESTNET"),
            "{error}"
        );
        assert!(!error.contains("example"), "{error}");

        let mut invalid = testnet();
        invalid[1].1 = "http://relay-testnet.example/relay".into();
        let error = networks_from(env(&invalid)).unwrap_err().to_string();
        assert_eq!(
            error,
            "testnet: OHTTP configuration: relay_url must be an https:// URL"
        );

        // Mainnet with testnet's signing key.
        let mut shared = testnet();
        shared.extend([
            (
                "OHTTP_E2E_GATEWAY_HOST_MAINNET",
                "ohttp-gateway.example".into(),
            ),
            (
                "OHTTP_E2E_RELAY_URL_MAINNET",
                "https://relay-mainnet.example/relay".into(),
            ),
            (
                "OHTTP_E2E_KEYS_DNS_NAME_MAINNET",
                "mainnet.ohttp-keys.example".into(),
            ),
            ("OHTTP_E2E_SIGNING_PUBKEY_MAINNET", key_hex(1)),
        ]);
        let error = networks_from(env(&shared)).unwrap_err().to_string();
        assert!(error.contains("signing_pubkey"), "{error}");
        shared.last_mut().unwrap().1 = key_hex(2);
        let networks = networks_from(env(&shared)).unwrap();
        assert_eq!(
            networks.network_of_host("ohttp-gateway.example"),
            Some(Network::Mainnet)
        );
    }
}

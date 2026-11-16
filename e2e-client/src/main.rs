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
    canonical_relay_url, decode_bhttp_response, doh_query_url, encapsulate_chunked_request,
    encode_request, envelope_from_doh_json, open_signed_config, verify_signed_config, ConfigError,
    DecodeOptions, KeyConfig, Network, OhttpConfig, OhttpConfigParams, OhttpNetworks, OuterHeaders,
    Request, SignedConfigPolicy, VerifyingKey, CONTENT_TYPE_CHUNKED_RES, DOH_RESOLVERS,
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

/// A setting read from the environment, `value` being what `std::env::var(name)` gave: not
/// present or empty is unset (`None`); a value that is not Unicode is an error naming the
/// variable, never the value (it is not silently read as unset).
fn setting(name: &str, value: Result<String, std::env::VarError>) -> Result<Option<String>> {
    match value {
        Ok(value) if value.is_empty() => Ok(None),
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => bail!("{name} is not valid Unicode"),
    }
}

/// [`setting`] of the process environment.
fn env_setting(name: &str) -> Result<Option<String>> {
    setting(name, std::env::var(name))
}

/// The network of a run, from the setting `NETWORK`: mainnet when unset, else the network it
/// names; any other value is an error, which does not repeat it.
fn network_setting(value: Option<&str>) -> Result<Network> {
    match value {
        None => Ok(Network::Mainnet),
        Some(name) => {
            network_named(name).map_err(|_| anyhow::anyhow!("NETWORK must be mainnet or testnet"))
        }
    }
}

/// Whether the setting `OHTTP_E2E_PLAIN_HTTP_RELAY` opts in to `http://` relay URLs: `1` does,
/// unset does not, any other value is an error.
fn plain_http_setting(value: Option<&str>) -> Result<bool> {
    match value {
        None => Ok(false),
        Some("1") => Ok(true),
        Some(_) => bail!("OHTTP_E2E_PLAIN_HTTP_RELAY must be 1 or unset"),
    }
}

/// Where the key configuration of a run comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeySource {
    /// The signed envelope (`application/json`), verified against the network's signing key.
    Signed,
    /// The unsigned `application/ohttp-keys` document, trusted as served.
    Plain,
}

/// The key-configuration source: the setting `OHTTP_E2E_KEY_CONFIG_SOURCE` (`signed` or
/// `plain`) when it is set; otherwise, for compatibility with older invocations, the guess this
/// tool used to make: signed when the config URL contains `/signed`. The flag `guessed` is true
/// for the guess ([`verified_as_signed`] then looks at the answer too).
fn key_source(explicit: Option<&str>, config_url: &str) -> Result<(KeySource, bool)> {
    match explicit {
        Some("signed") => Ok((KeySource::Signed, false)),
        Some("plain") => Ok((KeySource::Plain, false)),
        Some(_) => bail!("OHTTP_E2E_KEY_CONFIG_SOURCE must be signed or plain"),
        None if config_url.contains("/signed") => Ok((KeySource::Signed, true)),
        None => Ok((KeySource::Plain, true)),
    }
}

/// Whether the fetched key configuration is verified as a signed envelope: a signed source
/// always, whatever the answer's `Content-Type`; a guessed source also when the answer is
/// labelled `application/json` (the old guess); an explicit `plain` never.
fn verified_as_signed(source: KeySource, guessed: bool, content_type: &str) -> bool {
    source == KeySource::Signed || (guessed && content_type.contains("application/json"))
}

/// The relay URL `value` in its canonical form (`OhttpConfig::relay_url`), as a wallet posts to
/// it; a URL the configuration rules refuse is an error naming `what` and the rule, never the
/// value. With `plain_http` (`OHTTP_E2E_PLAIN_HTTP_RELAY=1`, for a relay or an origin checked
/// over plain HTTP inside a test network) an `http://` URL is accepted too, under the same rules
/// but the scheme, and canonical the same way (no `:80` instead of no `:443`). Without it an
/// `http://` URL is refused with an error that names the variable.
fn relay_url_arg(what: &str, value: &str, plain_http: bool) -> Result<String> {
    let refused = |e: ConfigError| anyhow::anyhow!("{what}: {e}");
    let Some(rest) = value.strip_prefix("http://") else {
        return canonical_relay_url(value).map_err(refused);
    };
    if !plain_http {
        bail!("{what}: an http:// URL needs OHTTP_E2E_PLAIN_HTTP_RELAY=1");
    }
    let canonical = canonical_relay_url(&format!("https://{rest}")).map_err(refused)?;
    // The https:// form drops a `:443`, which is not the default port of http://.
    let port_443 = url::Url::parse(value).ok().and_then(|url| url.port()) == Some(443);
    let after = &canonical["https://".len()..];
    let (authority, path) = after.split_at(after.find('/').unwrap_or(after.len()));
    let authority = if port_443 {
        format!("{authority}:443")
    } else {
        authority
            .strip_suffix(":80")
            .unwrap_or(authority)
            .to_string()
    };
    Ok(format!("http://{authority}{path}"))
}

/// `OHTTP_E2E_REPLAY_URLS` (comma-separated, blanks around and empty entries ignored), each URL
/// checked and canonical as [`relay_url_arg`] makes it; every entry is checked before anything
/// is sent, and the first one refused fails the run, named by its position. A value without
/// any URL (only commas and blanks) is an error too: the run would send nothing and succeed.
fn replay_urls(value: &str, plain_http: bool) -> Result<Vec<String>> {
    let urls: Vec<String> = value
        .split(',')
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .enumerate()
        .map(|(i, url)| relay_url_arg(&format!("OHTTP_E2E_REPLAY_URLS entry {i}"), url, plain_http))
        .collect::<Result<_>>()?;
    if urls.is_empty() {
        bail!("OHTTP_E2E_REPLAY_URLS names no URL");
    }
    Ok(urls)
}

/// The headers of a DNS-over-HTTPS query: those of the library's signed key-configuration fetch
/// (`Accept-Encoding`, `Accept-Language`, `User-Agent`, all fixed), with `Accept` asking for
/// `application/dns-json`.
fn doh_headers(headers: &OuterHeaders) -> Vec<(&'static str, String)> {
    let mut list: Vec<(&'static str, String)> = headers
        .key_fetch_signed(None)
        .into_iter()
        .filter(|(name, _)| !name.eq_ignore_ascii_case("accept"))
        .collect();
    list.insert(0, ("Accept", "application/dns-json".to_string()));
    list
}

fn usage() -> ! {
    eprintln!("usage: ohttp-e2e <config_url> <relay_url> <authority> <method> <path> [trace_id] [grpc|http] [body_hex]");
    eprintln!("       ohttp-e2e --key-config-source dns <network>");
    eprintln!(
        "  <relay_url>: an https:// relay URL the configuration rules accept (others are refused)"
    );
    eprintln!("  env: OHTTP_E2E_PLAIN_HTTP_RELAY=1: accept http:// relay and replay URLs too");
    eprintln!(
        "  env: OHTTP_E2E_KEY_CONFIG_SOURCE=signed|plain: the key configuration at <config_url>;"
    );
    eprintln!(
        "       unset: signed if <config_url> contains /signed or the answer is application/json"
    );
    eprintln!("  env: NETWORK=mainnet|testnet (for signed config verification, default mainnet)");
    eprintln!("  empty counts as unset for: OHTTP_E2E_KEY_CONFIG_SOURCE, NETWORK,");
    eprintln!("       OHTTP_E2E_PLAIN_HTTP_RELAY, OHTTP_E2E_REPLAY_URLS and OHTTP_E2E_*_<NET>");
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
    let (config_url, relay_arg, authority, method, path) = (&a[1], &a[2], &a[3], &a[4], &a[5]);
    // The settings below are read and checked before anything is sent: an empty variable is
    // unset, a bad or non-Unicode value fails the run.
    // The opt-in to http:// relay and replay URLs.
    let plain_http = plain_http_setting(env_setting("OHTTP_E2E_PLAIN_HTTP_RELAY")?.as_deref())?;
    // Posted to as a wallet would: the relay URL in its canonical form (`OhttpConfig::relay_url`).
    // A URL the configuration rules refuse fails the run.
    let relay_url = &relay_url_arg("relay URL", relay_arg, plain_http)?;
    let replay = match env_setting("OHTTP_E2E_REPLAY_URLS")? {
        Some(urls) => Some(replay_urls(&urls, plain_http)?),
        None => None,
    };
    let (source, guessed) = key_source(
        env_setting("OHTTP_E2E_KEY_CONFIG_SOURCE")?.as_deref(),
        config_url,
    )?;
    if guessed {
        println!(
            "    key configuration source guessed: OHTTP_E2E_KEY_CONFIG_SOURCE is not set \
             (signed|plain)"
        );
    }
    let network = network_setting(env_setting("NETWORK")?.as_deref())?;
    // The exact header sets of `zodl-ohttp-client`, as every wallet preset sends them.
    let headers = OuterHeaders::LIBRARY;
    let trace_id = a.get(6).cloned().unwrap_or_default();
    let trace = (!trace_id.is_empty()).then_some(trace_id.as_str());
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

    let http = http_client(60)?;

    // 1. key config (application/ohttp-keys, length-prefixed OR signed JSON)
    let t = Instant::now();
    // OHTTP_E2E_EXTRA_HEADERS go on this GET too: an origin checked directly (no relay in front)
    // with RELAY_SECRET_ON_KEY_CONFIG=require wants X-Relay-Secret on the key configuration.
    let mut kb = http.get(config_url);
    let fetch_headers = match source {
        KeySource::Signed => headers.key_fetch_signed(None),
        KeySource::Plain => headers.key_fetch_plain(None),
    };
    for (k, v) in fetch_headers {
        kb = kb.header(k, v)
    }
    for (k, v) in extra_headers() {
        kb = kb.header(k, v)
    }
    let resp = net(not_redirected(net(kb.send())?)?.error_for_status())?;
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let kc_raw = net(resp.bytes())?;

    let kc = if verified_as_signed(source, guessed, &content_type) {
        println!(
            "[1] signed config {} bytes in {:?} (network={})",
            kc_raw.len(),
            t.elapsed(),
            network.as_str()
        );
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let signer = signer(&networks()?, network)?;
        let keys = open_signed_config(&kc_raw, network.as_str(), &signer, now)?;
        println!("signed-configs: OK not_after={}", keys.not_after);
        keys.document
    } else {
        println!("[1] key config {} bytes in {:?}", kc_raw.len(), t.elapsed());
        kc_raw.to_vec()
    };
    let config = KeyConfig::select(&kc)?;
    // The suite only: the key id would tell which of the gateway's keys this run used.
    println!("    key selected: kem=0x0020 kdf=0x0001 aead=0x0001");

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
    println!(
        "[2] inner request ({} B bhttp, {} B body) -> {} B ohttp-chunked-req",
        plain.len(),
        body.len(),
        req.len()
    );

    // 4. POST to relay
    let t = Instant::now();
    let post = |url: &str, trace: Option<&str>| {
        let mut rb = http.post(url).body(req.clone());
        for (k, v) in headers.relay_post(trace) {
            rb = rb.header(k, v)
        }
        rb
    };
    let mut rb = post(relay_url, trace);
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
    // Each URL is canonicalized and checked like the relay URL, before the first send.
    if let Some(urls) = replay {
        let gap: u64 = std::env::var("OHTTP_E2E_REPLAY_GAP_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        for (i, url) in urls.iter().enumerate() {
            if i > 0 && gap > 0 {
                std::thread::sleep(std::time::Duration::from_millis(gap));
            }
            let replay_trace = trace.map(|t| format!("{t}-r{i}"));
            let mut r = post(url.as_str(), replay_trace.as_deref());
            for (k, v) in extra_headers() {
                r = r.header(k, v)
            }
            let t = Instant::now();
            let resp = net(r.send())?;
            let status = resp.status();
            let body = net(resp.bytes())?;
            println!(
                "[XREPLAY {i}] -> HTTP {} in {:?} ({} B)",
                status,
                t.elapsed(),
                body.len()
            );
        }
        return Ok(());
    }

    // Replay test: send the same request twice if OHTTP_E2E_REPLAY=1
    if std::env::var("OHTTP_E2E_REPLAY").ok().as_deref() == Some("1") {
        println!("[REPLAY TEST] Sending request twice to test replay protection");
        let resp1 = net(post(relay_url, trace).send())?;
        println!("[REPLAY 1] HTTP {}", resp1.status());
        std::thread::sleep(std::time::Duration::from_millis(100));
        let resp2 = net(post(relay_url, trace).send())?;
        let status2 = resp2.status();
        println!("[REPLAY 2] HTTP {}", status2);
        if status2.as_u16() == 409 {
            println!("[REPLAY TEST] PASS: Second request rejected with 409");
        } else {
            bail!("REPLAY TEST FAILED: Expected 409, got {}", status2);
        }
        return Ok(());
    }

    let resp = net(rb.send())?;
    let status = resp.status();
    let hdrs = resp.headers().clone();
    let rbody = net(resp.bytes())?;
    let sealed_answer = hdrs
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.contains(CONTENT_TYPE_CHUNKED_RES));
    // Kinds and counts only: neither the relay's request id nor any header value.
    println!(
        "[3] relay -> HTTP {} in {:?}, {} B, {}, x-request-id {}",
        status,
        t.elapsed(),
        rbody.len(),
        if sealed_answer {
            "a sealed response"
        } else {
            "not a sealed response"
        },
        if hdrs.contains_key("x-request-id") {
            "present"
        } else {
            "absent"
        }
    );
    if std::env::var("OHTTP_E2E_DUMP_HEADERS").is_ok() {
        println!("    {} response headers", hdrs.len());
    }
    if !status.is_success() {
        bail!("relay returned {status}")
    }
    if !sealed_answer {
        bail!("the relay's answer is not labelled {CONTENT_TYPE_CHUNKED_RES}")
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

    let http = http_client(30)?;

    println!("DNS key config test for {}", network.as_str());
    // Fails without a configuration for the network.
    signer(&networks, network)?;
    // The query URL names the network's keys DNS name, so neither it nor a transport error
    // that would repeat it is printed: a resolver is named by its host, a failure by its kind.
    println!("Resolvers: {}", DOH_RESOLVERS.len());

    for (i, resolver) in DOH_RESOLVERS.iter().enumerate() {
        println!("\n[{}] Trying resolver {}", i + 1, resolver_label(resolver));
        let Some(url) = doh_query_url(&networks, resolver, network) else {
            bail!("no key-configuration DNS name for {}", network.as_str());
        };

        let t = Instant::now();
        let mut query = http.get(&url);
        for (k, v) in doh_headers(&OuterHeaders::LIBRARY) {
            query = query.header(k, v)
        }
        let resp = match query.send() {
            Ok(r) => r,
            Err(e) => {
                println!("    ERROR: {}", transport_failure(&e));
                continue;
            }
        };

        if resp.status().is_redirection() {
            println!("    ERROR: redirected");
            continue;
        }
        if !resp.status().is_success() {
            println!("    ERROR: HTTP {}", resp.status());
            continue;
        }

        let body = match resp.bytes() {
            Ok(b) => b,
            Err(e) => {
                println!("    ERROR reading response body: {}", transport_failure(&e));
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
                            Ok(_) => {
                                println!("    key selected");
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

/// A resolver as printed: the host of its URL only (`https://dns.example:8443/dns-query` is
/// `dns.example`), as the URL parser reads it.
fn resolver_label(resolver: &str) -> String {
    url::Url::parse(resolver)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| "(unparsable resolver URL)".to_string())
}

/// What kind of transport failure `error` is, without its URL (which would name the relay, the
/// key-configuration host or the keys DNS name), host, address, port or message.
fn transport_failure(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "timed out".into()
    } else if error.is_connect() {
        "could not connect".into()
    } else if let Some(status) = error.status() {
        format!("status {}", status.as_u16())
    } else if error.is_body() || error.is_decode() {
        "the response body broke off".into()
    } else if error.is_redirect() {
        "redirected".into()
    } else {
        "request failed".into()
    }
}

/// The HTTP stack of every exchange: as a wallet's, it follows no redirect (a 3xx is an answer,
/// and a failure of the run). Unlike a wallet's it speaks plain HTTP too, for an origin checked
/// directly.
fn http_client(timeout_secs: u64) -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

/// `response`, unless it is a redirect: a wallet follows none, so the run fails, naming the
/// kind only (never the `Location`).
fn not_redirected(response: reqwest::blocking::Response) -> Result<reqwest::blocking::Response> {
    if response.status().is_redirection() {
        bail!("transport: redirected")
    }
    Ok(response)
}

/// `result` with a transport error reduced to its kind ([`transport_failure`]), so that no URL
/// reaches the output through `?`.
fn net<T>(result: reqwest::Result<T>) -> Result<T> {
    result.map_err(|e| anyhow::anyhow!("transport: {}", transport_failure(&e)))
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
    fn a_resolver_is_printed_as_its_host_only() {
        assert_eq!(
            resolver_label("https://dns.example/dns-query?x=1"),
            "dns.example"
        );
        assert_eq!(resolver_label("https://dns.example:8443"), "dns.example");
        assert_eq!(
            resolver_label("https://user:pw@dns.example/resolve"),
            "dns.example"
        );
        assert_eq!(
            resolver_label("dns.example/resolve"),
            "(unparsable resolver URL)"
        );
        for resolver in DOH_RESOLVERS {
            let label = resolver_label(resolver);
            assert!(
                !label.is_empty() && !label.contains(['/', ':', '?']),
                "{label}"
            );
        }
    }

    #[test]
    fn a_transport_failure_is_printed_without_its_url() {
        let http = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        // Port 0, which no server listens on (a connection to it is refused, and no other test
        // can take it), and a query naming a DNS name.
        let error = http
            .get("http://127.0.0.1:0/q?name=keys.example&type=TXT")
            .send()
            .unwrap_err();
        let shown = transport_failure(&error);
        assert_eq!(shown, "could not connect");
        let through_question_mark = net(Err::<(), _>(error)).unwrap_err().to_string();
        assert_eq!(through_question_mark, "transport: could not connect");
        for part in ["keys.example", "127.0.0.1", "/q"] {
            assert!(!through_question_mark.contains(part));
        }
    }

    /// A redirect is not followed and fails the fetch, naming neither status nor `Location`.
    #[test]
    fn a_redirect_is_refused_not_followed() {
        use std::io::{Read, Write};
        let target = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        target.set_nonblocking(true).unwrap();
        let location = format!("http://{}/elsewhere", target.local_addr().unwrap());
        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!(
            "http://{}/ohttp-configs/signed",
            server.local_addr().unwrap()
        );
        let answer = format!(
            "HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
        );
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = server.accept().unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                head.push(byte[0]);
            }
            stream.write_all(answer.as_bytes()).unwrap();
        });
        let response = net(http_client(5).unwrap().get(&url).send()).unwrap();
        handle.join().unwrap();
        let error = not_redirected(response).unwrap_err().to_string();
        assert_eq!(error, "transport: redirected");
        assert!(!error.contains("elsewhere") && !error.contains("127.0.0.1"));
        // The redirect's target was never contacted.
        assert!(target.accept().is_err());
    }

    #[test]
    fn the_key_source_is_explicit_or_guessed_as_documented() {
        let signed_url = "https://keys.example/ohttp-configs/signed";
        let plain_url = "https://keys.example/ohttp-configs";
        assert_eq!(
            key_source(Some("plain"), signed_url).unwrap(),
            (KeySource::Plain, false)
        );
        assert_eq!(
            key_source(Some("signed"), plain_url).unwrap(),
            (KeySource::Signed, false)
        );
        assert_eq!(
            key_source(None, signed_url).unwrap(),
            (KeySource::Signed, true)
        );
        assert_eq!(
            key_source(None, plain_url).unwrap(),
            (KeySource::Plain, true)
        );
        for invalid in ["Signed", "dns", " signed"] {
            let error = key_source(Some(invalid), signed_url)
                .unwrap_err()
                .to_string();
            assert_eq!(error, "OHTTP_E2E_KEY_CONFIG_SOURCE must be signed or plain");
        }
    }

    #[test]
    fn a_setting_is_unset_when_absent_or_empty_and_refused_when_not_unicode() {
        use std::env::VarError;
        assert_eq!(setting("NETWORK", Err(VarError::NotPresent)).unwrap(), None);
        assert_eq!(setting("NETWORK", Ok(String::new())).unwrap(), None);
        assert_eq!(
            setting("NETWORK", Ok("testnet".into())).unwrap().as_deref(),
            Some("testnet")
        );
        for name in [
            "NETWORK",
            "OHTTP_E2E_KEY_CONFIG_SOURCE",
            "OHTTP_E2E_PLAIN_HTTP_RELAY",
            "OHTTP_E2E_REPLAY_URLS",
        ] {
            let error = setting(name, Err(VarError::NotUnicode("not-shown".into())))
                .unwrap_err()
                .to_string();
            assert_eq!(error, format!("{name} is not valid Unicode"));
        }
    }

    /// `NETWORK` and the key source through [`setting`], as `main` reads them.
    #[test]
    fn the_network_and_the_key_source_follow_their_settings() {
        use std::env::VarError;
        let url = "https://keys.example/ohttp-configs/signed";
        let network = |value: Result<String, VarError>| -> Result<Network> {
            network_setting(setting("NETWORK", value)?.as_deref())
        };
        let source = |value: Result<String, VarError>| -> Result<(KeySource, bool)> {
            key_source(
                setting("OHTTP_E2E_KEY_CONFIG_SOURCE", value)?.as_deref(),
                url,
            )
        };
        // Unset and empty: the default network, the guessed source.
        for unset in [Err(VarError::NotPresent), Ok(String::new())] {
            assert_eq!(network(unset.clone()).unwrap(), Network::Mainnet);
            assert_eq!(source(unset).unwrap(), (KeySource::Signed, true));
        }
        // Valid.
        assert_eq!(network(Ok("mainnet".into())).unwrap(), Network::Mainnet);
        assert_eq!(network(Ok("testnet".into())).unwrap(), Network::Testnet);
        assert_eq!(
            source(Ok("plain".into())).unwrap(),
            (KeySource::Plain, false)
        );
        assert_eq!(
            source(Ok("signed".into())).unwrap(),
            (KeySource::Signed, false)
        );
        // Invalid: an error without the value.
        let error = network(Ok("regtest-not-shown".into()))
            .unwrap_err()
            .to_string();
        assert_eq!(error, "NETWORK must be mainnet or testnet");
        let error = source(Ok("not-shown".into())).unwrap_err().to_string();
        assert_eq!(error, "OHTTP_E2E_KEY_CONFIG_SOURCE must be signed or plain");
        // Not Unicode: an error, not the default.
        let error = network(Err(VarError::NotUnicode("not-shown".into())))
            .unwrap_err()
            .to_string();
        assert_eq!(error, "NETWORK is not valid Unicode");
        let error = source(Err(VarError::NotUnicode("not-shown".into())))
            .unwrap_err()
            .to_string();
        assert_eq!(error, "OHTTP_E2E_KEY_CONFIG_SOURCE is not valid Unicode");
    }

    #[test]
    fn plain_http_is_opted_in_with_1_only() {
        assert!(!plain_http_setting(None).unwrap());
        assert!(plain_http_setting(Some("1")).unwrap());
        for invalid in ["0", "true", "yes"] {
            let error = plain_http_setting(Some(invalid)).unwrap_err().to_string();
            assert_eq!(error, "OHTTP_E2E_PLAIN_HTTP_RELAY must be 1 or unset");
        }
    }

    #[test]
    fn only_a_signed_or_guessed_json_answer_is_verified_as_signed() {
        let (json, keys) = ("application/json; charset=utf-8", "application/ohttp-keys");
        // Explicit plain: never, whatever the answer is labelled.
        assert!(!verified_as_signed(KeySource::Plain, false, json));
        assert!(!verified_as_signed(KeySource::Plain, false, keys));
        // Explicit signed: always.
        for content_type in [json, keys, "", "text/html"] {
            assert!(verified_as_signed(KeySource::Signed, false, content_type));
            assert!(verified_as_signed(KeySource::Signed, true, content_type));
        }
        // Guessed plain: by the answer's label.
        assert!(verified_as_signed(KeySource::Plain, true, json));
        assert!(!verified_as_signed(KeySource::Plain, true, keys));
        assert!(!verified_as_signed(KeySource::Plain, true, ""));
    }

    #[test]
    fn relay_urls_are_canonical_or_refused_without_their_value() {
        assert_eq!(
            relay_url_arg("relay URL", "https://Relay.Example:443/relay/", false).unwrap(),
            "https://relay.example/relay"
        );
        let error = relay_url_arg("relay URL", "ftp://relay.example/relay", false)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "relay URL: OHTTP configuration: relay_url must be an https:// URL"
        );
        // Plain HTTP without the opt-in: the error says how to proceed, without the URL.
        let error = relay_url_arg("relay URL", "http://relay.example/relay", false)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "relay URL: an http:// URL needs OHTTP_E2E_PLAIN_HTTP_RELAY=1"
        );
        assert_eq!(
            replay_urls(
                " https://A.example/relay/ ,, https://b.example:443/x/../relay",
                false,
            )
            .unwrap(),
            ["https://a.example/relay", "https://b.example/relay"]
        );
        // Set, but naming no URL: an error, not a run that sends nothing.
        for empty in ["", ",", " , ", ",,"] {
            let error = replay_urls(empty, false).unwrap_err().to_string();
            assert_eq!(error, "OHTTP_E2E_REPLAY_URLS names no URL");
        }
        let error = replay_urls("https://a.example/relay,https://b.example/r?x=1", false)
            .unwrap_err()
            .to_string();
        assert!(
            error.starts_with("OHTTP_E2E_REPLAY_URLS entry 1: "),
            "{error}"
        );
        assert!(!error.contains("b.example"), "{error}");
        let error = replay_urls("https://a.example/relay,http://b.example/relay", false)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "OHTTP_E2E_REPLAY_URLS entry 1: an http:// URL needs OHTTP_E2E_PLAIN_HTTP_RELAY=1"
        );
    }

    #[test]
    fn a_plain_http_relay_url_needs_the_opt_in_and_the_same_rules() {
        for (given, canonical) in [
            ("http://Sim.Example/a/../relay/", "http://sim.example/relay"),
            ("http://sim.example:80/relay", "http://sim.example/relay"),
            (
                "http://sim.example:443/relay",
                "http://sim.example:443/relay",
            ),
            ("http://sim.example:8080", "http://sim.example:8080"),
            ("http://sim.example:443", "http://sim.example:443"),
            ("http://sim.example:443/", "http://sim.example:443"),
            ("http://[::1]:80/relay", "http://[::1]/relay"),
            ("http://[::1]:443", "http://[::1]:443"),
            ("http://[::1]:8080/relay", "http://[::1]:8080/relay"),
            (
                "https://relay.example:443/relay",
                "https://relay.example/relay",
            ),
        ] {
            assert_eq!(relay_url_arg("relay URL", given, true).unwrap(), canonical);
        }
        for refused in [
            "http://sim.example/relay?x=1",
            "http://user@sim.example/relay",
            "http://sim.example//relay",
            "ftp://sim.example/relay",
        ] {
            let error = relay_url_arg("relay URL", refused, true)
                .unwrap_err()
                .to_string();
            assert!(!error.contains("sim.example"), "{error}");
        }
        assert_eq!(
            replay_urls("http://Sim.Example/relay", true).unwrap(),
            ["http://sim.example/relay"]
        );
    }

    #[test]
    fn a_doh_query_sends_the_library_fetch_headers() {
        let headers = OuterHeaders::LIBRARY;
        let doh = doh_headers(&headers);
        assert_eq!(doh[0], ("Accept", "application/dns-json".to_string()));
        let mut expected: Vec<_> = headers
            .key_fetch_signed(None)
            .into_iter()
            .filter(|(name, _)| *name != "Accept")
            .collect();
        expected.insert(0, ("Accept", "application/dns-json".to_string()));
        assert_eq!(doh, expected);
        let names: Vec<&str> = doh.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            ["Accept", "Accept-Encoding", "Accept-Language", "User-Agent"]
        );
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

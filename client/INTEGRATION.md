# Integrating `zodl-ohttp-client`

How a wallet (or any Rust program) uses the crate to send light-client requests through an
oblivious relay to the ZODL OHTTP gateway. The protocol background is in
[../docs/architecture.md](../docs/architecture.md).

The crate has two layers:

- `Client` (default feature `client`, over reqwest): one relay, one gateway, the key
  configuration fetched and cached for you.
- A sans-IO core for callers that do their own I/O (for example over a Tor-capable
  transport): selection and verification of key configurations, Binary HTTP encoding, sealing,
  classification of the relay's answer and streaming decryption. `cargo build
  --no-default-features` builds the core alone, without reqwest or tokio.

## 1. Configuration

The crate carries no endpoint, host name or key. The application passes the OHTTP
configuration of each network in at runtime, and every function that needs one takes it:

```rust
#[derive(Clone, Copy)]
pub struct OhttpConfigParams<'a> {
    pub gateway_host: &'a str,
    pub relay_url: &'a str,
    pub keys_dns_name: &'a str,
    pub signing_pubkey: &'a str,
}

pub struct OhttpConfig { /* private */ }
impl OhttpConfig {
    pub fn new(params: OhttpConfigParams<'_>) -> Result<OhttpConfig, ConfigError>;
    pub fn gateway_host(&self) -> &str;
    pub fn relay_url(&self) -> &str;
    pub fn keys_dns_name(&self) -> &str;
    pub fn signing_pubkey(&self) -> &VerifyingKey;
}

pub struct OhttpNetworks { /* private */ }        // Default: both networks off
impl OhttpNetworks {
    pub fn new(mainnet: Option<OhttpConfig>, testnet: Option<OhttpConfig>)
        -> Result<OhttpNetworks, ConfigError>;
    pub fn get(&self, network: Network) -> Option<&OhttpConfig>;
    pub fn network_of_host(&self, gateway_host: &str) -> Option<Network>;
    pub fn relay_for(&self, gateway_host: &str) -> Option<&str>;
}
```

| Value | Rule |
|---|---|
| `gateway_host` | the gateway host name, which is also the inner `:authority` of light client server requests; a lower-case bare DNS host name (no scheme, port, path or trailing dot) |
| `relay_url` | the relay URL sealed requests are posted to; `https://`, a host (DNS name or IP literal), an optional numeric port and an optional path; no userinfo, query, fragment, backslash, whitespace or control characters |
| `keys_dns_name` | the DNS TXT name of the signed key configuration, a last-resort source (section 2); a lower-case bare DNS host name |
| `signing_pubkey` | the gateway's key-configuration signing key, raw Ed25519 as 64 hex digits, a valid point not of small order |

The values are named fields of `OhttpConfigParams`, so two of the same form (the gateway host
and the keys DNS name) cannot be swapped by position. `OhttpConfig::new` requires all four
values and checks each, copying them; `OhttpNetworks::new` also requires
that mainnet and testnet share no gateway host, relay URL or keys DNS name (compared ignoring
ASCII case) and no signing key. Values are taken as given: surrounding whitespace, such as a
trailing newline from a secret store, is refused, not trimmed. A refusal is a `ConfigError`
(`Empty`, `Invalid` or `SharedAcrossNetworks`) that names the field (`ConfigField`) and the
rule, never the value, and the `Debug` output of a configuration shows only which fields are
set (for `OhttpConfigParams`, which are set and which empty); both can be logged.

A network without a configuration has OHTTP off, and so does every network of
`OhttpNetworks::default()`: `relay_for(host)` returns `None`, `NetworkRule::KnownHosts` refuses
the host, `verify_signed_config` and `envelope_from_doh_json` return `Error::KeyConfig` and
`doh_query_url` returns `None`. The crate keeps no global configuration: build one
`OhttpNetworks` at startup and pass it where it is needed.

`relay_for(gateway_host)` maps exactly the configured gateway host of a network to its relay
URL (no case folding, no prefix or suffix matching); `relay_for(host).is_some()` tells whether a
light client server endpoint is an OHTTP gateway.

```rust
use zodl_ohttp_client::{Network, OhttpConfig, OhttpConfigParams, OhttpNetworks};

let testnet = OhttpConfig::new(OhttpConfigParams {
    gateway_host: "ohttp-gateway-testnet.example",
    relay_url: "https://relay-testnet.example/relay",
    keys_dns_name: "testnet.ohttp-keys.example",
    signing_pubkey: signing_pubkey_hex, // 64 hex digits, from the application's settings or resources
})?;
let networks = OhttpNetworks::new(None, Some(testnet))?; // mainnet: OHTTP off
assert_eq!(
    networks.relay_for("ohttp-gateway-testnet.example"),
    Some("https://relay-testnet.example/relay")
);
assert_eq!(networks.relay_for("lightwalletd.example"), None);
assert!(networks.get(Network::Mainnet).is_none());
```

## 2. Obtaining the key configuration

1. Fetch the signed envelope through the relay: `signed_config_url(relay_url, rule)` derives its
   URL from the relay URL (`.../relay` becomes `.../ohttp-configs/signed` under the default
   rules). Do not follow redirects. Read at most `MAX_KEY_CONFIG_BYTES` (64 KiB, enforce it while
   reading with `Limits::key_config_guard()`).
2. Only if that fails, read the envelope from DNS over HTTPS: for each resolver in
   `DOH_RESOLVERS`, in order, `GET doh_query_url(&networks, resolver, network)` (the network's
   `keys_dns_name`) with `accept: application/dns-json`, and pass the body to
   `envelope_from_doh_json(&networks, body, network)`. It requires `Status` 0 and TXT answers for exactly
   the queried name, concatenates the record's character-strings (presentation format, `\"`,
   `\\` and `\DDD` decimal escapes), requires exactly one distinct TXT value, base64-decodes it
   (standard alphabet, padded) and refuses an envelope over 64 KiB. The TXT value is the base64
   of the exact bytes `GET /ohttp-configs/signed` returns. Use the same transport as for the
   relay (over Tor when the wallet is in Tor mode).
3. Either way, verify the envelope with `verify_signed_config(&networks, json, network, now,
   &profile.signed_config)` (or `open_signed_config(json, network, &key, now)` for the library
   policy). It checks version 1, the network, the key id and Ed25519 signature against the
   network's configured `signing_pubkey`, `not_before < not_after`, a validity of at most 86400 s ending at most
   86400 s from now, `now` inside the window widened by `CLOCK_SKEW_SECS` (60 s) on each side,
   and the size limits. DNS is only a transport: an envelope from DNS gets no other treatment.
4. Pick the key with `KeyConfig::select_with(&keys.document, &profile.key_selection)` (the first
   configuration offering the suite) and cache it until `keys.not_after`
   (`CachePolicy::is_fresh`).

The network of a gateway host comes from the configuration
(`NetworkRule::KnownHosts.network_for(&networks, host)`), never from the host name.

## 3. Using `Client`

```rust
use std::time::Duration;
use zodl_ohttp_client::{signed_config_url, Client, KeyConfigSource, Network, Request, SignedConfigUrlRule};

// `networks` as in section 1; `host` is the light client server host.
let network = zodl_ohttp_client::NetworkRule::KnownHosts.network_for(&networks, host)?;
let config = networks.get(network).expect("a known host has a configuration");
let client = Client::new(
    config.relay_url(),
    KeyConfigSource::Signed {
        url: signed_config_url(config.relay_url(), SignedConfigUrlRule::ReplaceRelaySuffix)?,
        network: network.as_str().into(),
        signer: *config.signing_pubkey(),
    },
);
let request = Request::new("POST", host, "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock")
    .header("content-type", "application/grpc")
    .header("te", "trailers")
    .body(vec![0, 0, 0, 0, 0]);
let response = client.send(&request, Duration::from_secs(30)).await?;
```

`send` returns the backend's answer whatever its status; `send_stream` returns it as it streams
(head, body chunks as the gateway sends them, trailers). Within the one deadline, `Client`:

- fetches the key configuration on first use and keeps it until a signed one expires (an
  unsigned one for its `Cache-Control: max-age`, or 5 minutes);
- on an outer 400 or 422 drops the configuration, fetches it again and sends the request once
  more, sealed afresh; a second refusal is final;
- on an inner 400 marked `ohttp-freshness: rejected` learns the gateway clock from it and sends
  the request once more;
- refuses a sealed request over 10 MiB before sending it and stops reading an answer at the size
  cap;
- holds every request through a relay while a `Retry-After` from an outer 429 runs
  (`Error::Backoff`);
- follows no redirect.

## 4. The sans-IO loop

A caller that owns the transport runs this sequence with its `ClientProfile` (each profile
bundles the options in which existing clients differ; `ClientProfile::LIBRARY` is what `Client`
does):

```
key = cached key if profile.cache.is_fresh(not_after, now), else section 2
attempt = 0
loop {
  plain          = encode_bhttp_request(&request, &profile.encode)   // adds ohttp-freshness
  (body, opener) = encapsulate_chunked_request(&key, &plain)        // fresh on every attempt
  check_size(body.len(), profile.limits.max_sealed_request_bytes)?
  POST body to the relay as message/ohttp-chunked-req with profile.headers.relay_post(trace),
       no redirects, reading the answer through profile.limits.response_guard()
  match classify_outer_response(&profile.outer, &OuterResponse { status, content_type, body }, attempt) {
    Sealed           => feed the body to opener.decoder() as it arrives (or opener.open_response)
    RefetchKeyConfig => drop the cached key, run section 2 again, attempt = 1, continue
    Refused { .. } | WrongMediaType { .. } => error
  }
}
```

Rules that matter for privacy and correctness:

- **Seal every attempt afresh.** Never resend a sealed body: the gateway refuses a repeated
  ciphertext as a replay (409). Each sealing returns its own `ChunkedResponseOpener` (neither
  `Clone` nor `Copy`); keep one sealing per post, the type does not enforce it. A transport error before an answer is just another iteration.
- **Retry once at most** after `RefetchKeyConfig`; 409, 413, 401, 426 and 5xx are not retried by
  the core.
- **Freshness.** Feed every inner response's headers to `freshness::observe_response_headers`
  so later stamps follow the gateway clock; `freshness::is_rejection` recognises a stale-request
  refusal, which may be retried once, sealed afresh.
- **Size caps.** Check `Content-Length` with `SizeGuard::check_declared`, push every chunk length
  to the guard and drop the connection at its first error. Independently, the decoder refuses
  any single sealed chunk above `chunked::MAX_SEALED_RESPONSE_CHUNK_BYTES` (64 KiB of plaintext
  + 16-byte tag) with `BhttpFormat` as soon as its length prefix is read (or, for the final
  chunk, as soon as it grows past it); stop reading the body on that error too. A gateway must
  keep `CHUNK_SIZE` at or below 65536 (default 16384).
- **Trace ids.** `X-Client-Trace-Id` (`ClientTrace`) links the relay's and the gateway's view of a
  request; send it only in debug builds, never by default.

## 5. Errors

`Error` is non-exhaustive. `Refused { status }`, `MediaType`, `TooLarge`, `KeyConfig`, `Seal`,
`BhttpFormat` and `NotAResponse` are permanent for that request; `Truncated` (the answer ended
before its final chunk) and `Http` are transport failures and may be retried with a fresh
sealing; `Open` means a chunk did not authenticate; `Backoff { wait }` means the relay asked for
a pause.

## 6. Testing an integration

The crate's own tests run against the gateway's code (`tests/gateway.rs`,
`tests/gateway_core.rs`) and need no network; they use example configurations (`*.example`
names, RFC 2606) of their own. Against a running deployment, `e2e-client/` and
`scripts/test-e2e.sh` perform real exchanges (`../docs/testing.md`).

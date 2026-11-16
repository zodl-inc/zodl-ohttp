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
| `relay_url` | the relay URL sealed requests are posted to; `https://`, a host (DNS name or IP address, not a gateway host), an optional numeric port and an optional path; ASCII, no userinfo, query, fragment, backslash, whitespace, control characters, encoded `/` or `\\` (`%2F`, `%5C`) or empty path segment (`//`). Kept canonical: one trailing `/` removed, host in lower case, IP addresses in standard form, no `:443`, dot segments resolved, percent-encoding normalized |
| `keys_dns_name` | the DNS TXT name of the signed key configuration, a last-resort source (section 2); a lower-case bare DNS host name |
| `signing_pubkey` | the gateway's key-configuration signing key, raw Ed25519 as 64 hex digits, a valid point not of small order |

The values are named fields of `OhttpConfigParams`, so two of the same form (the gateway host
and the keys DNS name) cannot be swapped by position. `OhttpConfig::new` requires all four
values and checks each, copying them; `OhttpNetworks::new` also requires
that mainnet and testnet share no gateway host or keys DNS name (compared ignoring ASCII case),
no relay (the same canonical host, port and path, the path compared ignoring case:
`https://relay.example/relay`, `https://Relay.example:443/a/../relay/` and
`https://relay.example/%72elay` are one relay, and so are `https://192.0.2.1/relay`,
`https://0xc0000201/relay` and `https://[::ffff:192.0.2.1]/relay`) and no signing key, and that
neither network's relay is on a gateway host. `relay_url()` returns the canonical form, which is
what the client posts to. Other values are taken as given: surrounding whitespace, such as a
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
   rules), with exactly the headers `profile.headers.key_fetch_signed(None)` lists. Do not follow
   redirects. Read at most `MAX_KEY_CONFIG_BYTES` (64 KiB, enforce it while reading with
   `Limits::key_config_guard()`).
2. Only if that fails, read the envelope from DNS over HTTPS: for each resolver in
   `DOH_RESOLVERS`, in order, `GET doh_query_url(&networks, resolver, network)` (the network's
   `keys_dns_name`) with `accept: application/dns-json`, and pass the body to
   `envelope_from_doh_json(&networks, body, network)`. It requires `Status` 0 and TXT answers for exactly
   the queried name, concatenates the record's character-strings (presentation format, `\"`,
   `\\` and `\DDD` decimal escapes), requires exactly one distinct TXT value, base64-decodes it
   (standard alphabet, padded) and refuses an envelope over 64 KiB. The TXT value is the base64
   of the exact bytes `GET /ohttp-configs/signed` returns. Use the same transport as for the
   relay (over Tor when the wallet is in Tor mode). The resolver sees the client's address and
   the name it asks for, which says that the client is looking for this gateway's keys, so send
   it no more than the relay: exactly `Accept: application/dns-json`,
   `Accept-Encoding: identity`, `Accept-Language: en` (`RELAY_ACCEPT_LANGUAGE`) and
   `User-Agent: zodl-ohttp/1` (`RELAY_USER_AGENT`), each set explicitly, no cookies, no other
   header, no redirect followed, and the query URL exactly as `doh_query_url` builds it (it asks
   the resolver not to forward the client's subnet where the resolver supports that).
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
use zodl_ohttp_client::{Client, NetworkRule, Request, SignedConfigUrlRule};

// `networks` as in section 1; `host` is the light client server host.
let network = NetworkRule::KnownHosts.network_for(&networks, host)?;
// The configured relay, and the gateway's signed envelope fetched through it and checked
// against the configured signing key (`.../relay` becomes `.../ohttp-configs/signed`).
let client = Client::for_network(&networks, network, SignedConfigUrlRule::ReplaceRelaySuffix)?;
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
- follows no redirect;
- speaks `https://` only.

The signed envelope must be served where the `SignedConfigUrlRule` derives it from the relay URL
(`ReplaceRelaySuffix`: `https://relay.example/relay` gives
`https://relay.example/ohttp-configs/signed`; `RelayHostRoot`: `/ohttp-configs/signed` on the
relay's host). For a relay that serves it elsewhere, build the client with
`Client::new(relay_url, KeyConfigSource::Signed { url, network, signer })` (`network` a `Network`).

`Client::new` refuses (`Error::Setup`, naming the URL and the rule, never the value) a relay URL
that breaks the rules of `relay_url` above (and uses it in its canonical form) and an envelope
URL that is not `https://` with a host (an empty authority, `https:///host/`, included), or
that has userinfo (an empty one, `https://@host/`, included), a backslash, whitespace or a
control character; it does not know the gateway host, so a relay on the gateway's own host is
refused only through `OhttpConfig::new` (`Client::for_network`). The unsigned `KeyConfigSource::Plain`
exists only with the cargo feature `insecure-plain-key-config` and is accepted only by
`Client::insecure_for_local_testing`, which exists only with that feature too and also allows
`http://`: for tests against a local gateway, never in a wallet. `KeyConfigSource::Signed` names
its network as a `Network`. No constructor panics: a TLS backend that cannot be initialized is
`Error::Setup`.

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

- **Requests are padded to fixed buckets.** `encode_bhttp_request` (and `encode_request`) append
  zero padding after the trailer section (RFC 9292 §3.8): a `SendTransaction` to 16 KiB, 32 KiB
  if larger and then the next multiple of 32 KiB; every other request to the next multiple of
  4 KiB; never past what fits under the 10 MiB sealed-request cap. Seal the encoded bytes as they
  are; do not trim them.
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
- **Send the relay exactly the listed headers.** `relay_post`, `key_fetch_signed` (also
  `key_fetch`) and `key_fetch_plain` return the same names and values, in the same order, for
  every preset: the content type and `Accept` (one per endpoint: `message/ohttp-chunked-res` on
  the post, `application/json` on the signed envelope, `application/ohttp-keys` on the unsigned
  document), `Accept-Encoding: identity`, `Accept-Language: en` (`RELAY_ACCEPT_LANGUAGE`, the
  `accept_language` field) and `User-Agent: zodl-ohttp/1` (`RELAY_USER_AGENT`). Set every one of
  them explicitly, so that the platform HTTP stack does not add its own `User-Agent`,
  `Accept-Language` (the device's language list) or `Accept-Encoding`, and add nothing else (no
  cookies, no cache validators, no application headers). The headers are then identical across
  presets and do not tell the relay which wallet or platform sent a request. What remains
  visible: the TLS and HTTP/2 parameters, header order and compression of the HTTP stack,
  connection reuse and timing, which differ between stacks; a debug build's trace ids (below);
  and the key-configuration URL where the presets' `SignedConfigUrlRule`s derive different ones.
  The rules agree only when the relay URL's path is exactly `/relay` or empty: every rule then
  fetches `/ohttp-configs/signed` at the relay host's root. For any other path, nested ones such
  as `/testnet/relay` included, `ReplaceRelaySuffix` and `TrimThenReplaceRelaySuffix` keep the rest
  of the path (`/testnet/ohttp-configs/signed`) while `RelayHostRoot` (Slipstream) fetches the
  host's root, so the relay can tell those clients apart by the URL they fetch.
- **Trace ids.** `X-Client-Trace-Id` (`ClientTrace`) links the relay's and the gateway's view of a
  request; send it only in debug builds, never by default, and only on the post (no key fetch
  lists it). Its format differs per `TracePolicy`, so a trace id also names the platform.

## 5. Errors

`Error` is non-exhaustive. `Refused { status }`, `MediaType`, `TooLarge`, `KeyConfig`, `Seal`,
`BhttpFormat` and `NotAResponse` are permanent for that request; `Truncated` (the answer ended
before its final chunk) and `Http` are transport failures and may be retried with a fresh
sealing; `Open` means a chunk did not authenticate; `Backoff { wait }` means the relay asked for
a pause; `Setup` means a `Client` constructor refused its arguments.

What may be logged and what may not:

- **Log-safe.** The `Display` and `Debug` of every `Error` and `ConfigError`, and of
  `OhttpConfigParams`, `OhttpConfig` and `OhttpNetworks` (which show only which fields are set).
  The library itself never puts a URL, host name, address, port or key id of the configuration
  or of the transport into an error. `Http` holds an `HttpError` that shows only its
  `HttpErrorKind` (`Connect`, `Tls`, `Timeout`, `Status(n)`, `RedirectRefused`, `Body`,
  `Request`, `Other`) and has no `source()`. What a peer chose appears as numbers (an outer or
  DoH status, a length, a KEM or framing identifier) and in the two quotes below.
- **Format-safe, content the relay's.** Two quotes of relay-chosen text: the relay's
  `Content-Type` in `Error::MediaType` and `OuterOutcome::WrongMediaType { content_type }` (at
  most 64 characters, `MAX_MEDIA_TYPE_CHARS`) and the relay's error body in
  `OuterOutcome::Refused { detail }` (at most 120, `MAX_REFUSED_DETAIL_CHARS`). Each is one
  short line of printable ASCII (anything else `?`), so it cannot inject log lines; but its
  content is whatever the relay sent, and a relay's error body may itself name things (the
  client's own address, a request or node identifier). A privacy-sensitive log records the
  status and drops the quote.
- **Not log-safe.** `HttpError::transport_error_not_log_safe()` (the HTTP stack's own error,
  with URLs, hosts and addresses); the `Debug` of a `KeyConfigSource` (derived: it shows the
  envelope URL and the signing key); the values behind the `OhttpConfig` accessors (relay URL,
  gateway host, keys DNS name, signing key: they identify the deployment); a `Request`, a
  `Response`, `ResponseEvent`s and decoded Binary HTTP messages (the user's request and the
  backend's answer); key configurations, envelopes and `SignedKeys`; and trace ids, which link
  the relay's and the gateway's logs.

## 6. Testing an integration

The crate's own tests run against the gateway's code (`tests/gateway.rs`,
`tests/gateway_core.rs`) and need no network; they use example configurations (`*.example`
names, RFC 2606) of their own. Against a running deployment, `e2e-client/` and
`scripts/test-e2e.sh` perform real exchanges (`../docs/testing.md`).

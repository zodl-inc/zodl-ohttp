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

Beside both, `ThirdPartyHosts` (section 5): which third-party hosts the gateway carries, as the
gateway publishes them, for either layer.

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
    pub fn relay_url(&self) -> &str;          // the (first) relay; stable
    pub fn choose_relay(&self) -> &str;       // the relay for the next request
    pub fn relays(&self) -> &[Relay];         // every relay listed, in order
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
    pub fn choose_relay_for(&self, gateway_host: &str) -> Option<&str>;
}
```

| Value | Rule |
|---|---|
| `gateway_host` | the gateway host name, which is also the inner `:authority` of light client server requests; a lower-case bare DNS host name (no scheme, port, path or trailing dot) |
| `relay_url` | the relay URL sealed requests are posted to; `https://`, a host (DNS name or IP address, not a gateway host), an optional numeric port and an optional path; ASCII, no userinfo, query, fragment, backslash, whitespace, control characters, encoded `/` or `\\` (`%2F`, `%5C`) or empty path segment (`//`). Kept canonical: one trailing `/` removed, host in lower case, IP addresses in standard form, no `:443`, dot segments resolved, percent-encoding normalized. Or a list of relays ("Several relays" below) |
| `keys_dns_name` | the DNS TXT name of the signed key configuration, a last-resort source (section 2); a lower-case bare DNS host name |
| `signing_pubkey` | the gateway's key-configuration signing key, raw Ed25519 as 64 hex digits, a valid point not of small order |

The values are named fields of `OhttpConfigParams`, so two of the same form (the gateway host
and the keys DNS name) cannot be swapped by position. `OhttpConfig::new` requires all four
values and checks each, copying them; `OhttpNetworks::new` also requires
that mainnet and testnet share no gateway host or keys DNS name (compared ignoring ASCII case),
no relay (the same canonical host, port and path, the path compared ignoring case:
`https://relay.example/relay`, `https://Relay.example:443/a/../relay/` and
`https://relay.example/%72elay` are one relay, and so are `https://192.0.2.1/relay`,
`https://0xc0000201/relay`, `https://[::ffff:192.0.2.1]/relay`, `https://[::192.0.2.1]/relay`
and `https://[64:ff9b::c000:201]/relay`) and no signing key, and that
neither network's relay is on a gateway host (a relay on an IPv6 literal that embeds an IPv4
address, `[::ffff:192.0.2.1]`, `[64:ff9b::c000:201]` or `[::192.0.2.1]` (`::a.b.c.d` only when
`a` and `b` are not both zero: `[::]` to `[::ffff]` are plain IPv6 addresses), is on a gateway
host `192.0.2.1`, in any of its numeric spellings). `relay_url()` returns the canonical form,
which is what the client posts to. Other values are taken as given: surrounding whitespace, such as a
trailing newline from a secret store, is refused, not trimmed. A refusal is a `ConfigError`
(`Empty`, `Invalid` or `SharedAcrossNetworks`) that names the field (`ConfigField`) and the
rule, never the value, and the `Debug` output of a configuration shows only which fields are
set (for `OhttpConfigParams`, which are set and which empty); both can be logged.

A network without a configuration has OHTTP off, and so does every network of
`OhttpNetworks::default()`: `relay_for(host)` returns `None`, `NetworkRule::KnownHosts` refuses
the host, `verify_signed_config` and `envelope_from_doh_json` return `Error::KeyConfig` and
`doh_query_url` returns `None`. The crate keeps no global configuration (only the
process-wide relay state of `RelayBackoff::global()` and `RelaySelector::global()`): build one
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

### Several relays

`relay_url` may also list relays: relay URLs separated by `,`, each entry after the first
starting `https://`, for example `https://relay-a.example/relay,https://relay-b.example/gateway`.
A value is a list only where a `,` is followed by `https://`; any other value is one relay URL,
exactly as before. Each URL follows the rules above, a list has at most 8 relays and no relay
twice, every relay gets an equal share of the requests (unless a relay weights block sets
others, below), and the mainnet/testnet and
gateway-host rules apply to every relay.

- **Stable values stay stable.** `relay_url()` and `relay_for(host)` return the first relay
  listed, always: use them for "is this a gateway" checks, cache keys and the signed key
  configuration (`signed_config_url(networks.relay_for(host)?, rule)`), as before; when that
  fetch fails, try the other relays in list order, then the DNS fallback. An integration that
  only bumps the crate keeps posting to that first relay.
- **Per request.** To split the requests, call `choose_relay_for(host)` (or
  `config.choose_relay()`) once per request and use that one string for the post, the
  `RelayBackoff` checks and the report below; never key a cache or connection pool on it (key
  pools on `relays()`, at most 8 stable URLs). Each call is a fresh random choice from
  the operating system's RNG (should it fail, a non-cryptographic draw from the standard
  library's per-process hash keys, still spread evenly: the choice protects nothing secret),
  so the relays share the traffic equally.
  Nothing about the choice depends on the wallet; no choice is kept or stored (in memory, the
  selector keeps only which relays are held out).
- **Failover.** Report a request whose relay failed with
  `RelaySelector::global().note_failure(url)`: no connection, a TLS failure, a broken exchange,
  a timeout that is the relay's (not a short deadline of the caller), a success that is no
  sealed answer (wrong media type), or an outer status for which `relay_status_fails_over(status)`
  holds (`429`, any `5xx`, a redirect, and `401`/`403`/`404`/`405`/`407`/`421`, a relay that
  cannot deliver). Report one whose sealed answer completed with `note_success(url)`. Prefer
  `note_failure_of_probe` / `note_success_of_probe(url, sent_at, probe)` with the instant the
  request was sent and the `RelayProbe` of its choice (below): a report of a request sent
  before the relay's current hold began changes that hold in no way, and only the relay's
  current probe's own report ends that probe. A relay that failed is held out
  of the choice for `RELAY_FAILOVER_HOLD` (60 s, doubling while it keeps failing on requests
  sent after each hold, up to `MAX_RELAY_FAILOVER_HOLD`; not doubled while other relays fail
  too, and released by a success through a relay that failed with it), and one paused by a `Retry-After` (`RelayBackoff::global()`) until the pause ends:
  a request that draws it goes to the next relay in list order, which gets the whole share
  meanwhile. With every relay out, the first relay in that order that
  is only held (not paused) is used, and with every relay paused, the relay drawn. After a
  hold ends one request at a time goes to the relay as a probe (`RELAY_PROBE_WINDOW`), and
  failures set aside as older news (a later request succeeded) hold the relay after all once
  `MASKED_FAILURES_TO_HOLD` of them fall within `MASKED_FAILURE_WINDOW`. Each choice may
  make its request the probe, so choose only for a request you will send, and use
  `choose_relay_for_where(host, eligible)`: it returns the relay and a `RelayProbe`. Keep the
  `RelayProbe` with the request and pass it back with its report (`note_failure_of_probe`,
  `note_success_of_probe`, `note_answered_of`), so that only the relay's current probe ends
  it: the report of a request chosen as a probe but sent late, after a newer probe replaced
  it, never ends the newer probe (its failure still counts as a failure, its success only
  makes older failures older news). Over a foreign-function interface pass it as `to_raw()` /
  `from_raw()` (an unsigned 64-bit value). `choose_relay_for` returns no `RelayProbe`: its
  reports count as in 2.3.0 (a late one may end a newer probe), so use it only where nothing
  reports. A transport that keeps pauses of its own (one per Tor or direct route, say)
  passes `|url| !my_pause(url)` as `eligible`, so that a relay it cannot send to is never
  drawn, nor as a probe (with no such pause, `|_| true`); `None` means no eligible relay can
  take the request: fail it locally, nothing sent (the crate's own `Client`, with no
  criterion, sends to the relay drawn as no probe when every relay has its probe out, and
  that request's success ends the relay's hold). An eligible relay paused by `Retry-After`
  may still come back: keep checking the pause before sending. Report an outer status for
  which `relay_status_answered` holds (400, 409, 413, 415, 422, 426) with
  `note_answered_of(url, probe)`: it ends the relay's current probe, neither a success nor a
  failure; the request itself is still refused and never resent. The selector
  never resends anything. A request may be sent again through another relay only when nothing
  was sent: the connection or TLS handshake failed, or the relay is paused before the post.
  Never after an outer error status (a relay or front end may answer one in place of an answer
  it got), a `5xx` or any later failure (section 4).
- **Order matters.** The first relay is the network's stable relay and the envelope source,
  relays fail over in list order, and the list's order is how its relays are referred to: keep
  it when the list changes otherwise.

### Relay weights

The gateway operator may change the shares (not the relays) with a signed block, `relay_weights`,
inside the signed key-configuration envelope (`docs/relay-weights.md`). To accept it, configure
the network's relay weights key: `OhttpConfig::new(params)?.with_relay_weights_key(hex)?` (64 hex
digits; an empty value means none, and then no block is ever read). Nothing else changes for an
integration that already verifies the envelope with `verify_signed_config(&networks, ...)` (or
uses `Client::for_network`) and asks `choose_relay_for(_where)` per request: a valid block is
taken when the envelope is checked, from a relay or from DNS alike, and every choice uses its
weights while it is valid; once it expires, the shares are equal again without a new fetch. A
relay of weight 0 is never drawn, but requests still fail over to it. A block that does not
check out is ignored and never makes the envelope fail; nor does an envelope without one, or
with an ignored one, drop the block held (only a higher `seq` replaces it, and expiry ends it).
Fetch the envelope through the relays of weight 0 last while a block is held (a relay can withhold
the block; `Client` does this). The block is held in memory only:
persist nothing for it. For a diagnostics screen, `config.relay_weights()` gives
`RelayWeightsStatus::Block(w)` (show `w.id()`, the block id the public log lists) or
`RelayWeightsStatus::AppDefaults` ("app defaults").

## 2. Obtaining the key configuration

1. Fetch the signed envelope through the relay (with a relay list, the first one,
   `relay_for(host)`, and the others in turn when it fails):
   `signed_config_url(relay_url, rule)` derives its
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
    RefetchKeyConfig => drop the cached key (the next request runs section 2 again), error:
                        never resend this one
    Refused { .. } | WrongMediaType { .. } => error
  }
}
```

Rules that matter for privacy and correctness:

- **Requests are padded to fixed buckets.** `encode_bhttp_request` (and `encode_request`) append
  zero padding after the trailer section (RFC 9292 §3.8): a `SendTransaction` to 16 KiB, 32 KiB
  if larger and then the next multiple of 32 KiB; every other request to the next multiple of
  4 KiB; never past what fits under the 10 MiB sealed-request cap. Seal the encoded bytes as they
  are; do not trim them. The classes hide which of the small calls a request is and the exact
  size of a transaction. For typical light-wallet traffic they leave a strong statistical
  fingerprint of a broadcast: a request in the 16 KiB class or above is very likely a `SendTransaction` (calls to
  third-party APIs through the gateway are padded the same way and can land in the same classes
  or others), so the relay learns that the client's address very likely sent a transaction at
  that moment, and by matching the time against transactions arriving in the mempool it can link
  the address to a transaction id with a probability that depends on how many arrive in that
  window (a rejected transaction never arrives). The relay also sees the timing and number of all
  requests and the size of each response to within a chunk. Only a transport that hides the
  address from the relay (Tor) removes that link
  (`../docs/architecture.md`, "Request padding").
- **Seal every attempt afresh.** Never resend a sealed body: the gateway refuses a repeated
  ciphertext as a replay (409). Each sealing returns its own `ChunkedResponseOpener` (neither
  `Clone` nor `Copy`); keep one sealing per post, the type does not enforce it. Only a request
  that was not sent (a failure while connecting, TCP or the TLS handshake) may be sealed again
  and sent. After any later failure (a reset, a timeout, a broken answer, an
  outer error status) the request may have reached the gateway, and a `WRITE`
  (`SendTransaction`) must not be sent again, through the same relay or another.
- **No retry on an outer status.** `RefetchKeyConfig` (an outer `400`/`422`) drops the cached
  key configuration so that the next request fetches it afresh, and the request is reported as
  refused: an outer status, which anything between the client and the gateway can write, does
  not prove that the request did not run. 409, 413, 401, 426 and 5xx are not retried either.
- **Errors show no peer text.** `OuterOutcome::WrongMediaType` and `Error::MediaType` carry
  only a registered type and a common subtype (`text/*` otherwise, or `NOT_A_MEDIA_TYPE`), and
  `OuterOutcome::Refused` only the size of the body; log nothing else of the relay's answer.
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

## 5. The gateway's third-party hosts

A wallet sends a request for a third-party host through the gateway only when it knows the
gateway carries the host. Everything else it refuses, and it never falls back to a direct
connection. The gateway publishes the hosts it carries (`gateway/README.md`, "Third-party host
list: wallet integration"); `ThirdPartyHosts` is that note as code, so an SDK needs no logic of
its own beyond calling it. It does no I/O, starts no task and no timer.

One `ThirdPartyHosts` per gateway (so one per network), created once with the list compiled
into the wallet and shared (`Arc`). It is always refreshed from that one gateway.

```text
hosts = ThirdPartyHosts::new(compiled_hosts)          // "name" or "name:port", as in :authority

// Before a request to a third-party host (host = what the request would put in :authority):
authority = hosts.carried_authority(host)
if authority is none and hosts.refresh_before_refusing():
    refresh(hosts)                                    // below; then ask once more
    authority = hosts.carried_authority(host)
if authority is none and hosts.is_refreshing():       // a refresh, whoever began it, has not
    fail("try again shortly")                         // ended: or wait briefly and ask again
if authority is none:
    fail("the gateway does not carry this host")      // never send it another way
send the request with :authority = authority          // exactly this value

// Choosing among the servers a service's own discovery offers:
servers = hosts.filter_servers(discovered_urls)
if !servers.any() and hosts.refresh_before_refusing():
    refresh(hosts)
    servers = hosts.filter_servers(discovered_urls)
if !servers.any() and hosts.is_refreshing():          // as above: not a final answer yet
    fail("try again shortly")
if !servers.any():
    fail("no server of this service is carried")      // only now
for server in servers.carried:                        // the others are simply not used
    send to server.url with :authority = server.authority

// After an inner response from a third-party host:
if is_unknown_authority(response):                    // 403, body "unknown authority"
    hosts.report_unknown_authority(authority)         // asks for a refresh, at most one per 30 s
    try the next server of the service                // the refresh runs at the next refresh(hosts)

// Whenever convenient (before using third-party hosts, on a timer of the app's own, ...):
refresh(hosts)
```

`refresh` with `Client` is one call, `hosts.refresh(&client, gateway_host, timeout).await`. With
a transport of the SDK's own it is the same three steps:

```text
if let Some(refresh) = hosts.begin_refresh():         // None: fresh, running, or backing off
    request  = refresh.request(gateway_host)          // GET /ohttp-gateway/v1/third-party-hosts
    response = send through OHTTP like any request    // stop reading at 256 KiB, give up
                                                      // well before 5 minutes
    hosts.finish_refresh(refresh, Some(response))     // or fail_refresh(refresh, reason) when
                                                      // the exchange failed: always one of them
```

What it does for the caller:

- **Which hosts are allowed.** Before a list was fetched: the compiled list. While the list held
  has `scope` `all`: exactly that list. While it is `dynamic` or a scope the crate does not
  know: that list plus the compiled list. `host[:port]` is compared whole and
  case-insensitively; there is no suffix matching and no other equivalence (`name:443` is not
  `name`: the gateway lists a host on port 443 by its name alone).
- **What to send.** `carried_authority` and `CarriedServer::authority` return the value that
  was checked: lower case, and for a server URL its host with the port unless it is 443. Put
  exactly this value in `:authority`. Upper and lower case name the same host (the value
  returned is the lower-case one the gateway expects); nothing else is equivalent. As a host
  value (`carried_authority`, `is_carried`) the crate knows a host only in the spelling the
  gateway lists: `name:443`, a port with leading zeros and the like are refused here even
  where a gateway would accept them. In a server URL an explicit `:443` is the default port
  and is left out of the authority. A server URL
  must be plain: it starts with `https://`, has no userinfo, whitespace or backslash, and
  its host is written as it is sent (no percent escape, numeric IPv4 alias or non-ASCII
  name), so that every URL parser reads the same host in it. A server on port 443 is known
  by its name alone: a gateway that lists a host as `name:443` (a static alias configured
  that way) carries it for `carried_authority("name:443")` only, not for a server URL.
- **When to fetch.** At once when nothing is held; then when the list is older than its
  `max_age_secs` (clamped to 30 s..24 h); or when asked (`report_unknown_authority`,
  `refresh_before_refusing`), and then again after the backoff until a refresh succeeded. One
  refresh at a time; the list held stays in use while it runs. A request for an allowed host
  never waits for a refresh. A refresh that finds another one running sends nothing and
  says so (`RefreshOutcome::Running`; `begin_refresh()` returns `None`). Whenever a refresh
  is running (`is_refreshing()`), whoever began it and for whatever reason, a host that is
  not allowed may be in the list it brings: report a temporary failure (or wait a moment and
  ask again), not "the gateway does not carry this host".
- **Failures.** Any answer that is not the version 1 document (or a `304` for the revision
  held), a body over 256 KiB, or a failed exchange keeps what is held, the compiled list if
  nothing was fetched yet, and starts a backoff (30 s, doubling to 5 min). `NoHostList` says
  why, with a status or a fixed text only. A gateway that does not publish the list therefore
  costs one small request per backoff period and changes nothing. An entry of the list that
  is not well-formed, or whose host is no `host[:port]`, is left out; the rest of the list is
  used.
- **Cancellation.** A `HostListRefresh` that is neither finished nor failed is given up after
  5 minutes and counts as a failure, and the next refresh may begin: an SDK transport must
  give its exchange up before that. `ThirdPartyHosts::refresh` limits its exchange to four
  minutes and gives up at once when its future is dropped. A refresh finished at another
  holder than the one that began it, or 5 minutes or more after it began, changes nothing
  (`Superseded`).

Through a foreign-function boundary the holder maps to a handful of calls: carried-authority
(not is-carried alone: the caller needs the value to send), filter-servers (return the kept
URLs with their authorities, or their indices),
report-unknown-authority, refresh-before-refusing and refresh (or begin / finish / fail for an
SDK transport). The methods take `&self` and are safe to call from any thread. The `_at`
variants take the current time as an `Instant`, for tests and for Rust callers that already
hold one.

The list says where the gateway forwards. It does not authenticate a host: which servers a
wallet uses still comes from the service's own discovery and its checks. The hosts of a list
identify the deployment: the `Debug` of `ThirdPartyHosts` shows counts only, but `HostList`,
`HostListAnswer`, `CarriedHost`, `CarriedServer` and `CarriedServers` hold the names and are not
log-safe. The `Debug` of a `HostListRefresh` shows the revision it revalidates and two counters.

## 6. Errors

`Error` is non-exhaustive. `Refused { status }`, `MediaType`, `TooLarge`, `KeyConfig`, `Seal`,
`BhttpFormat` and `NotAResponse` are permanent for that request; `NoHostList` means the
gateway's answer to a host list request is no list (keep what is held, section 5);
`Truncated` (the answer ended before its final chunk) and `Http` are transport failures and
may be retried with a fresh sealing; `Open` means a chunk did not authenticate;
`Backoff { wait }` means the relay asked for a pause; `Setup` means a `Client` constructor
refused its arguments or could not initialize its TLS backend.

What may be logged and what may not:

- **Log-safe.** The `Display` and `Debug` of the errors the library produces (`Error`,
  `ConfigError`, `NoHostList`), the `Debug` of `ThirdPartyHosts` (counts only), and the
  `Debug` of `OhttpConfigParams`, `OhttpConfig` and `OhttpNetworks`
  (which show only which fields are set), `KeyConfigSource` (the variant and the network only)
  and `RelayBackoff` (the number of relays only).
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

## 7. Testing an integration

The crate's own tests need no network and use example configurations (`*.example` names,
RFC 2606) of their own. Those that run against the gateway's code (`tests/gateway.rs`,
`tests/gateway_core.rs`, `tests/chunked.rs`, `tests/workspace.rs`) need the repository and are
not in the published crate; the rest run with `cargo test` on the published crate too. Against a running deployment, `e2e-client/` and
`scripts/test-e2e.sh` perform real exchanges (`../docs/testing.md`).

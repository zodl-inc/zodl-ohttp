# Changelog

[Keep a Changelog](https://keepachangelog.com).

## 2.1.0

No breaking change. `Error` (non-exhaustive) gains the variant `NoHostList`.

### Added

- The third-party host list of a gateway (`gateway/README.md`, "Third-party host list: wallet
  integration"), so that every wallet uses one implementation of it instead of a compiled copy
  of the gateway's hosts. No new dependency; nothing starts a task or a timer.
  - `third_party_hosts_request(gateway_host, revision)` builds the inner request
    (`GET /ohttp-gateway/v1/third-party-hosts`, `if-none-match` for a held revision) and
    `read_third_party_hosts(&Response)` reads the answer: `HostListAnswer::List(HostList)`
    (`revision`, `scope`, `max_age_secs`, `hosts` of `CarriedHost { host, routes }`),
    `HostListAnswer::NotModified`, or `NoHostList` (`Status(n)`, `TooLarge`, `Malformed`,
    `Version`, `UnexpectedNotModified`). Unknown fields are ignored, any `version` other than 1
    is no list, a body over 256 KiB (`MAX_THIRD_PARTY_HOSTS_BYTES`) is refused, an entry of
    `hosts` that is not well-formed or whose `host` is no `host[:port]` is left out.
  - `ThirdPartyHosts::new(bootstrap)` holds the compiled list and the list last fetched.
    `is_carried(host)` / `carried_authority(host)` compare `host[:port]` whole and
    case-insensitively (no suffix matching, no other equivalence: `name:443` is not `name`):
    the bootstrap list before a fetch, exactly the list while its scope is `all`, the list plus
    the bootstrap list while it is `dynamic` or unknown. `filter_servers(urls)` keeps the
    `https` server URLs the gateway carries, each with the `:authority` to send
    (`CarriedServer { url, authority }`), and says whether any is left (`CarriedServers::any`),
    so a caller drops servers the gateway does not carry instead of failing; nothing suggests a
    direct connection. A server URL must be plain: `https://`, no userinfo, whitespace or
    backslash, the host written as it is sent.
  - Refreshing, sans-IO: `begin_refresh()` returns a `HostListRefresh` when one is due (no list
    yet, the list older than `max_age_secs` clamped to 30 s..24 h, or asked for) and none is
    running (`is_refreshing()`); `finish_refresh(refresh, Some(&response) | None)` or
    `fail_refresh(refresh, reason)` ends it (`RefreshOutcome`). A failure keeps what is held
    and starts a backoff (30 s, doubling to 5 min); a refresh that was asked for is tried
    again after it. `report_unknown_authority(host)` (after `is_unknown_authority(&response)`,
    an inner `403 unknown authority`, for a listed host) asks for a refresh at most once per
    30 s; `refresh_before_refusing()` says whether one is worth it before a host is refused
    (no list yet, or one older than 5 s). Every one of these has an `_at(.., now)` form. A
    refresh is finished only at the holder that began it and within 5 minutes of its
    beginning; otherwise it changes nothing (`RefreshOutcome::Superseded`).
  - With the feature `client`: `Client::third_party_hosts(gateway_host, revision, timeout)` and
    `ThirdPartyHosts::refresh(&client, gateway_host, timeout)`; both stop reading the answer at
    256 KiB. `refresh` limits its exchange to four minutes, gives it up when its future is
    dropped, and returns `RefreshOutcome::Running` when another refresh is in flight (a host
    refused at that moment may be in the list that refresh brings).
  - The new public structs and `HostListAnswer` are `#[non_exhaustive]`.
- `Error::NoHostList(NoHostList)`: the gateway's answer to a host list request is no list.
  Like every error of the library it shows a status or a fixed text only.

### Documentation

- `INTEGRATION.md`: section 5, "The gateway's third-party hosts".

## 2.0.2

No API or wire-format change.

### Fixed

- `OhttpConfig::new` and `OhttpNetworks::new` read the IPv4 address an IPv6 relay host names,
  besides the IPv4-mapped form (`::ffff:a.b.c.d`) already compared: an IPv4-compatible address
  (`[::192.0.2.1]`, a deprecated form, read as one only when the high 16 bits of the IPv4
  address are not zero) and one under the NAT64 well-known prefix (`[64:ff9b::c000:201]`)
  count as on the gateway host of that IPv4 address (in any of its numeric spellings), so such
  a relay URL is now refused (`ConfigError::Invalid`, field `relay_url`, rule `must not be on
  a gateway host`). `::`, `::1` to `::ffff`, the IPv4-translated form (`::ffff:0:a.b.c.d`),
  other prefixes (6to4, Teredo, a network-specific NAT64 prefix) and a gateway host that is a
  name are not affected. The relay URL keeps its IPv6 form (`relay_url()` is unchanged).
- `OhttpNetworks::new` tells relays apart the same way: a relay on such an IPv6 literal is the
  relay on the IPv4 address it embeds (`https://192.0.2.1/relay` and
  `https://[64:ff9b::c000:201]/relay` are one relay), so mainnet and testnet relays that differ
  only in this spelling are now `SharedAcrossNetworks` for `relay_url`.
- A configuration that passed only because of such a literal is now refused.

## 2.0.1

No API or wire-format change.

### Fixed

- `OhttpConfig::new` and `OhttpNetworks::new` compare a gateway host with relay hosts (and the
  two gateway hosts with each other) as the URL parser reads it: a gateway host written as a
  numeric IPv4 alias (`0xc0000201`, `0300.0.2.1`, `3221225985`, `192.0.513`) is the address it
  names, so a relay URL on that address is now refused (`ConfigError::Invalid`, field
  `relay_url`), as a relay on the gateway's dotted-decimal address already was, and two such
  spellings of one gateway host are `SharedAcrossNetworks`. A configuration that passed only
  because of the alias is now refused.
- The `Debug` of `KeyConfigSource` shows the variant and the network only (`url` and `signer`
  are `<set>`), and that of `RelayBackoff` the number of relays in the table only, instead of
  URLs, keys and pauses. Formatting a `RelayBackoff` never waits for its table: while the table
  is in use it shows `relays: <locked>`.

### Documentation

- `INTEGRATION.md`: what is log-safe is the output of the errors the library produces (a caller
  can build an `Error` with any text); `Error::Setup` lists `TLS backend` among its `what`
  values; the request-padding fingerprint ("no other lightwalletd call comes near 16 KiB") holds
  for typical traffic only (`docs/architecture.md`).
- `Cargo.toml` no longer sets `homepage` to the repository URL (cargo warns that it is
  redundant).

## 2.0.0

A breaking release: the client refuses configurations and sources that let the relay read
requests or tell clients apart. The migration list comes first; the sections after it describe
each change.

### Breaking changes / migration

- `Client::new(relay_url, keys)` returns `Result<Client, Error>` and refuses (new
  `Error::Setup { what, rule }`) a relay URL that breaks the relay URL syntax rules of
  `OhttpConfig::new` (below; not the gateway-host rule, which needs the gateway host and is
  applied only by `OhttpConfig::new`, and so through `Client::for_network`), an envelope URL that is not `https://` with a host (an empty authority, `https:///host/`,
  included), with userinfo (an empty one, `https://@host/`, included), a backslash, whitespace
  or a control character (the URL parser would drop a tab, CR or LF and read another URL), and
  the unsigned source; a TLS backend that cannot be initialized is `Error::Setup` too (no
  constructor panics, which matters across an FFI boundary). Add `?`. A wallet builds its client
  with the new `Client::for_network(&networks, network, url_rule)` instead.
- `KeyConfigSource::Plain` and `Client::insecure_for_local_testing` (no checks, `http://`
  allowed, returns `Result`) exist only with the new cargo feature `insecure-plain-key-config`;
  `Client::new` refuses `Plain`. `KeyConfigSource` is `#[non_exhaustive]`. Code that used the
  unsigned source in production must switch to `KeyConfigSource::Signed` (or
  `Client::for_network`); tests enable the feature.
- `KeyConfigSource::Signed { network }` is a `Network`, not a `String`.
- `Client` speaks `https://` only on the wire: a relay post or key fetch to any other scheme fails
  before anything is sent, so no redirect or bypass can reach a plain-HTTP server.
- **Wire change at the relay:** every `OuterHeaders` preset is now the same (`ANDROID`, `IOS`
  and `SLIPSTREAM` are `LIBRARY`), so the headers no longer tell the relay which client sent a
  request. The exact lists and what changes per preset are under "Changed".
- `OuterHeaders` has a new field `accept_language: Option<&'static str>` and
  `key_fetch_accept` is a `bool` (the `Accept` value follows from the endpoint); code that
  builds an `OuterHeaders` literal must set them. Use the presets.
- `OuterHeaders::key_fetch` is the fetch of the signed envelope; the new `key_fetch_signed` is
  the same and `key_fetch_plain` is the fetch of the unsigned `/ohttp-configs` document.
- `OhttpConfig::new` refuses a relay on the gateway host (`ConfigError::Invalid`, field
  `relay_url`): it would hand the gateway the client's address; a security fix, so there is no
  opt-out. `Client::new` does not know the gateway host and cannot apply this rule.
- `OhttpConfig::new` refuses more relay URL syntax (`ConfigError::Invalid`, field `relay_url`),
  and `Client::new` applies the same syntax rules to its relay URL: non-ASCII text (write a host
  in its `xn--` form), and hosts the URL standard does not read (`[:]` passed the old character
  check); and, checked on the path as written, before dot segments are resolved: an encoded `/`
  or `\` (`%2F`, `%5C`), an empty path segment (`//`, so `/a/..//relay` too) and a `%` not
  followed by two hex digits. Check the shipped configurations.
- `OhttpNetworks::new` compares the two relay URLs by canonical host, port and path (see
  "Changed") instead of as strings, so two spellings of one relay are now refused as shared, and
  it refuses a network's relay on the other network's gateway host.
- `OhttpConfig::relay_url()` returns the canonical form instead of the value as given: one
  trailing `/` removed (a configuration ending in `/relay/` keeps working and no longer derives
  `.../relay//ohttp-configs/signed`), the host in lower case, an IPv4 address in dotted decimal
  whatever form it was written in, an IPv6 address in its standard form, no `:443`, dot segments
  resolved and percent-encoding normalized. Requests go to that URL.
- `Error::Http` holds an `HttpError` instead of a `reqwest::Error`. Its `Display` and `Debug` give
  only an `HttpErrorKind` (`Connect`, `Tls`, `Timeout`, `Status(n)`, `RedirectRefused`, `Body`,
  `Request`, `Other`): never a URL, host, address, port or the HTTP stack's own message, and it
  has no `source()`, so error-chain printers do not reach the underlying error either. Match on
  `HttpError::kind()`; `HttpError::transport_error_not_log_safe()` returns the underlying error
  for local debugging (not log-safe). A redirect on the key-configuration fetch is now
  `HttpErrorKind::RedirectRefused` (it was read as a body and failed as `Error::KeyConfig`).
- `Error::KeyConfig` and `Error::MediaType` texts changed (they no longer quote peer text or key
  ids, see "Changed"); code matching on the messages must be updated.
- `OuterOutcome::Refused::detail` is at most `MAX_REFUSED_DETAIL_CHARS` (120) characters of
  printable ASCII, anything else replaced by `?` (it was up to the policy's whole window, with
  newlines and any text); `OuterOutcome::WrongMediaType::content_type` and `Error::MediaType` at
  most `MAX_MEDIA_TYPE_CHARS` (64).
- `signed_config_url` rewrites the relay URL's path only: `https://relay` (a single-label host,
  empty path) gives `https://relay/ohttp-configs/signed` under every rule, where the replacing
  rules used to turn the host itself into `https://ohttp-configs/signed`.
- New dependencies: `url` (always, also with `default-features = false`, for the relay URL
  checks; it brings `idna` and its ICU-based normalization tables into builds without the
  `client` feature, which had none of them before) and `rustls` (with the `client` feature, the
  version reqwest already uses, to tell TLS failures apart). Both were already in the dependency
  tree of the `client` feature through reqwest.

### Added

- `Client::for_network(&OhttpNetworks, Network, SignedConfigUrlRule)`: a client posting to the
  configured relay URL and sealing to the key of the gateway's signed envelope, fetched where the
  rule derives it from the relay URL and checked against the signing key configured for that
  network. The network and its configuration come from the same place, so they cannot disagree.
- `Client::insecure_for_local_testing` (feature `insecure-plain-key-config`): no checks,
  `http://` allowed, the unsigned source; for tests against a local gateway.
- `Error::Setup`, naming what a `Client` constructor refused and the rule, never the value.
- `HttpError`, `HttpErrorKind`, `canonical_relay_url` (the canonical form `OhttpConfig` keeps,
  for a caller with a relay URL of its own) and the constants `MAX_REFUSED_DETAIL_CHARS` and
  `MAX_MEDIA_TYPE_CHARS`.

### Changed

- Every preset sends the relay the same headers, in this order.
  Post: `Content-Type: message/ohttp-chunked-req`, `Accept: message/ohttp-chunked-res`,
  `Accept-Encoding: identity`, `Accept-Language: en`, `User-Agent: zodl-ohttp/1`, and
  `X-Client-Trace-Id` when the caller passes one. Signed key-configuration fetch
  (`key_fetch_signed`, `key_fetch`): `Accept: application/json`, `Accept-Encoding: identity`,
  `Accept-Language: en`, `User-Agent: zodl-ohttp/1`, never a trace id. Unsigned document
  (`key_fetch_plain`): the same with `Accept: application/ohttp-keys`. For the presets this
  changes: `LIBRARY` fetch (gains `Accept: application/json` and `Accept-Encoding: identity`),
  `ANDROID` fetch (gains `Accept-Encoding: identity`), `IOS` fetch (`Accept:
  application/ohttp-keys` becomes `application/json`, the type the signed endpoint serves; gains
  `Accept-Encoding: identity`; no longer carries the trace id), and every post and fetch (gains
  `Accept-Language: en`). The gateway reads none of these headers. New constants
  `RELAY_ACCEPT_LANGUAGE`, `SIGNED_CONFIG_MEDIA_TYPE`, `KEY_CONFIG_MEDIA_TYPE`.
- What identical headers do not hide, now documented: the HTTP stack's TLS and HTTP/2 behaviour
  (and header order and compression), connection reuse, timing, the format of a debug build's
  trace ids, and the key-configuration URL itself where the presets' `SignedConfigUrlRule`s
  derive different ones. They agree only when the relay URL's path is exactly `/relay` or empty;
  for any other path, nested ones such as `/testnet/relay` included, the replacing rules keep the
  rest of the path (`/testnet/ohttp-configs/signed`) while Slipstream's `RelayHostRoot` fetches
  `/ohttp-configs/signed` at the host's root. The 1.1.0 note that the fixed `User-Agent` keeps
  the relay from telling clients apart "by their HTTP stack" claimed more than a header can do.
- The e2e client (`e2e-client/`, not part of the crate) sends exactly these header sets, posts to
  the canonical relay URL and follows no redirect, so a run through real relays sends what
  wallets send and fails where a wallet would.
- Relay URLs are parsed with the URL standard's parser and compared by canonical host
  (an IPv4-mapped IPv6 address as its IPv4 address), port (443 when absent) and path (ignoring
  ASCII case, as before): `https://h/relay`, `https://h:443/relay/` and `https://h/a/../relay`
  are one relay, and so are `https://192.0.2.1/relay`, `https://0xc0000201/relay` and
  `https://[::ffff:192.0.2.1]/relay`.
- `Error::KeyConfig` from the signed envelope and the DoH answer no longer quotes the peer's text:
  not the envelope's `network` or `key_id` (the expected network is named; no key id is, the
  pinned one would tell a log reader which deployment the client is configured for), not an
  unknown or duplicated field name (one of the envelope's own fields is still named), not a JSON
  parser message (only its kind, line and column), not a character of a malformed TXT record.
  Before, a relay or resolver could put up to 64 KiB of text, newlines included, into the error
  and so into a wallet's logs. `Error::MediaType` holds at most 64 characters of the
  `Content-Type`, non-printable characters replaced by `?`.
- The published crate's tests pass on their own: the tests that need the gateway's code or the
  repository's `docs/` (`tests/gateway.rs`, `tests/gateway_core.rs`, `tests/chunked.rs`, the new
  `tests/workspace.rs`) are excluded from the package and run in the repository's CI, the unit
  tests no longer use the gateway, and the signed-configuration test vector ships in `testdata/`
  (checked to be the documented one). Before, `cargo test` on the published crate failed to
  build.
- Documentation: `INTEGRATION.md`, `docs/architecture.md` and the rustdoc of
  `encode_bhttp_request` say what request padding hides and what it does not: for typical
  light-wallet traffic the size class is a strong statistical fingerprint of a broadcast (a
  request of 16 KiB or more is very likely a `SendTransaction`, though calls to third-party APIs
  through the gateway can land in the same or other classes), and the time of the post can be
  matched, probabilistically, against the transaction's arrival in the mempool (a rejected
  transaction never arrives). The 1.0.0 entry below no longer claims that the relay sees "a few
  request sizes only". The padding itself is unchanged.
- The crate-level example builds its client with `Client::for_network` (the signed source). It
  used `KeyConfigSource::Plain` on the relay host, which lets the relay substitute its own key.
- `Client::send` and `Client::send_stream` no longer panic on a timeout too long to add to the
  clock (`Duration::MAX`, as a binding may pass for "no timeout"): a timeout of more than a year
  is a year.

## 1.1.0

### Changed

- Every `OuterHeaders` preset (`LIBRARY`, `ANDROID`, `IOS`, `SLIPSTREAM`) now sends the same fixed
  `User-Agent: zodl-ohttp/1` to the relay, on the post and on the key-configuration fetch, and
  the library `Client` sends it on its key-configuration fetch too. The relay sees the client
  address, and a User-Agent that differs per client or HTTP stack lets it tell clients apart.
  The value is the new public constant `RELAY_USER_AGENT`; changing it later is a breaking
  change. Behaviour change for callers that relied on the HTTP stack's default User-Agent
  (`LIBRARY`, `ANDROID`, `IOS`) or on the old slipstream value `zodl-slipstream-ohttp/0.1`.

## 1.0.1

crates.io metadata, no code change: the crate is published on crates.io (repository, homepage,
documentation, readme, keywords and categories in the manifest; the package carries a README and
the license files).

## 1.0.0

The crate carries no OHTTP endpoints or keys any more, not even from its build: the application
passes the configuration of each network in at runtime. A breaking change for every caller.

### Added

- `OhttpConfig`: the configuration of one network (gateway host, relay URL, keys DNS name,
  signing key), built by `OhttpConfig::new(OhttpConfigParams { gateway_host, relay_url,
  keys_dns_name, signing_pubkey })`; the named fields keep two values of the same form from being
  swapped by position. `OhttpConfig::new` requires all four values and checks them: the gateway host
  and the keys DNS name are lower-case bare DNS host names, the relay URL is `https://` with a
  valid host, an optional numeric port and an optional path, and without userinfo, query,
  fragment, backslash, whitespace or control characters, the signing key is a raw Ed25519
  public key as 64 hex digits, a valid point not of small order. Accessors `gateway_host`,
  `relay_url`, `keys_dns_name`, `signing_pubkey`.
- `OhttpNetworks`: the configurations of mainnet and testnet, either or both `None` (OHTTP off
  for that network; `OhttpNetworks::default()` has both off). `OhttpNetworks::new` refuses two
  configurations that share a gateway host, relay URL or keys DNS name (compared ignoring ASCII
  case) or a signing key. `get`, `network_of_host` and `relay_for` (exact host match, as before).
- `ConfigError` (`Empty`, `Invalid`, `SharedAcrossNetworks`) and `ConfigField`: a refused
  configuration names the field and the rule, never the value. The `Debug` output of
  `OhttpConfigParams`, `OhttpConfig` and `OhttpNetworks` shows only which fields and networks are
  set.

### Changed

- Requests are padded to fixed size buckets: `encode_bhttp_request` (and so `encode_request` and
  `Client`) appends zero padding after the trailer section (RFC 9292 §3.8) up to 16 KiB for a
  lightwalletd `SendTransaction` (32 KiB if larger, then the next multiple of 32 KiB) and up to
  the next multiple of 4 KiB for every other request, never past what fits under the 10 MiB
  sealed-request cap. The relay and the network then no longer see which of the small calls a
  request is or the exact size of a transaction; for typical light-wallet traffic a request in the
  `SendTransaction` classes is still very likely a broadcast, and its timing can be matched
  against the mempool (`docs/architecture.md`, "Request padding"). No API change; a gateway
  accepts the padding (this release's gateway also refuses non-zero bytes there).
- `verify_signed_config`, `doh_query_url` and `envelope_from_doh_json` take the
  `&OhttpNetworks` as their first argument, and `NetworkRule::network_for` takes it before the
  host; they read the signing key, the keys DNS name and the gateway hosts from it. For a network
  without a configuration they behave as an unconfigured build did: `Error::KeyConfig`, `None`,
  or no network for the host.
- The `Error::KeyConfig` of `NetworkRule::KnownHosts` for an unknown host no longer contains the
  host, nor does that of `signed_config_url` contain the relay URL.

### Removed

- The build-time configuration: `build.rs`, the `ZODL_OHTTP_*` build variables and
  `ZODL_OHTTP_REQUIRE`. Setting them has no effect.
- `relay_for` (now `OhttpNetworks::relay_for`), `GATEWAY_HOST_MAINNET`, `GATEWAY_HOST_TESTNET`,
  `MAINNET_SIGNING_KEY_HEX`, `TESTNET_SIGNING_KEY_HEX`, `Network::pinned_signing_key` (now
  `OhttpConfig::signing_pubkey`) and `key_config_dns_name` (now `OhttpConfig::keys_dns_name`).

## 0.1.2

### Changed

- The build-time endpoint configuration is all or nothing per network: when any of a network's
  four variables (`ZODL_OHTTP_GATEWAY_HOST_*`, `ZODL_OHTTP_RELAY_URL_*`,
  `ZODL_OHTTP_KEYS_DNS_NAME_*`, `ZODL_OHTTP_SIGNING_PUBKEY_*`) is set while another of the same
  network is unset or empty, the build fails with a message naming the network and the missing
  variables. Before, a partial configuration built and silently left OHTTP off for that
  network. With no variable set the build still succeeds with OHTTP off.
- When both networks are configured, the build fails if mainnet and testnet share a gateway
  host, relay URL, keys DNS name or signing key (compared ignoring ASCII case).
- Build script error messages name the variable and the rule only; they no longer include the
  rejected value.

### Added

- Opt-in strict mode: with `ZODL_OHTTP_REQUIRE=1` the build fails unless all eight endpoint
  variables are set. Unset, empty or `0` leaves it off; any other value fails the build.

## 0.1.1

### Changed

- Response chunks are capped: `ChunkedResponseDecoder::push` and
  `ChunkedResponseOpener::open` fail with `Error::BhttpFormat` when a chunk's declared length
  exceeds `chunked::MAX_SEALED_RESPONSE_CHUNK_BYTES` (65552 = 64 KiB plaintext + 16-byte AEAD
  tag), as soon as the length prefix is read and without waiting for the rest of the chunk, or
  when the final chunk grows past it. The cap bounds what the decoder keeps across `push`
  calls; the bytes of the one `push` call that carries an oversized length prefix are already
  buffered when it fails. The gateway emits chunks of `CHUNK_SIZE` (16384 by default) plus the
  tag, so the cap leaves 4x headroom; before, only the ~257 MiB whole-response limit bounded a
  chunk a hostile relay could make the decoder buffer ahead of the tag check. New constants
  `chunked::MAX_RESPONSE_CHUNK_PLAINTEXT_BYTES` and `chunked::MAX_SEALED_RESPONSE_CHUNK_BYTES`.
- `ChunkedResponseOpener::open` refuses a non-final chunk whose plaintext is empty with
  `Error::BhttpFormat`, as `ChunkedResponseDecoder::push` already did (draft-ietf-ohai-chunked-ohttp:
  a non-final chunk must not be empty).
- The build-time relay URLs (`ZODL_OHTTP_RELAY_URL_*`) must have a non-empty host and no
  userinfo: `https://:443/relay` and `https://user@host/relay` now fail the build.

## 0.1.0 — initial public release

### Added

- Chunked OHTTP (draft-ietf-ohai-chunked-ohttp) request encapsulation
  (`encapsulate_chunked_request`) and streaming response decapsulation
  (`ChunkedResponseDecoder`, `ChunkedResponseOpener`) for the suite DHKEM(X25519, HKDF-SHA256),
  HKDF-SHA256, AES-128-GCM. Every attempt is sealed afresh; the response secret is zeroized and
  never printed.
- Key configuration selection from `application/ohttp-keys` documents (`KeyConfig::select`,
  `KeyConfig::select_with`).
- Signed key configuration verification (`open_signed_config`, `verify_signed_config`,
  `SignedConfigPolicy`): Ed25519 against a pinned per-network key, network binding, validity
  window with 60 s clock skew, size limits.
- Build-time endpoint configuration (`ZODL_OHTTP_GATEWAY_HOST_*`, `ZODL_OHTTP_RELAY_URL_*`,
  `ZODL_OHTTP_SIGNING_PUBKEY_*`, `ZODL_OHTTP_KEYS_DNS_NAME_*`), validated by `build.rs`; a
  network without all required values is off. `relay_for`, `NetworkRule`.
- DNS-over-HTTPS as a last-resort source of the signed key configuration
  (`key_config_dns_name`, `doh_query_url`, `envelope_from_doh_json`, `DOH_RESOLVERS`).
- Binary HTTP (RFC 9292) codec keeping trailers and interim responses (`encode_bhttp_request`,
  `decode_bhttp_response`, `Request`, `Response`).
- Outer response classification without I/O (`classify_outer_response`): a key-configuration
  refetch and one fresh retry after an outer 400 or 422, `Retry-After` handling on 429
  (`RelayBackoff`), size limits enforced while bytes arrive (`Limits`, `SizeGuard`).
- Request freshness (`freshness`): `ohttp-freshness` stamps from the gateway clock offset, one
  retry after a freshness refusal.
- Debug trace ids (`ClientTrace`) and per-client option bundles (`ClientProfile`).
- `Client` (default feature `client`): requests through one relay to one gateway over reqwest,
  key configuration cached and refreshed, no redirects followed. Without the feature the crate
  has no network or runtime dependency.
- No `unsafe`, no panics on malformed input.

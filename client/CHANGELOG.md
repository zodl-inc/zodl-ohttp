# Changelog

[Keep a Changelog](https://keepachangelog.com).

## 1.0.0

The first release published to crates.io. The API and behaviour are those of 0.1.2.

### Changed

- The crate is published: `publish = false` is gone, and the manifest names the repository.
- The package carries the licence texts (`LICENSE`, `LICENSE-EXCEPTIONS.md`,
  `COMMERCIAL-LICENSE.md`) that the source file headers refer to.

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

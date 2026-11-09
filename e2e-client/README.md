# ohttp-e2e — minimal chunked OHTTP client for end-to-end checks

One Oblivious HTTP exchange against a real relay, on the encapsulation of `zodl-ohttp-client`
(`../client`); the outer request is sent here, so the relay hardening knobs below can alter it:

1. `GET <config_url>` → parses the `application/ohttp-keys` document (RFC 9458 §3.1), picks
   DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM.
2. Builds a known-length Binary HTTP request (RFC 9292) with `:scheme https`, the given
   `:authority`, method and path. `grpc` kind adds `content-type: application/grpc`, `te: trailers`
   and an empty gRPC frame (`00 00000000`) as body; `http` kind sends `accept: application/json`.
3. HPKE-seals it as a chunked request (draft-ietf-ohai-chunked-ohttp-08 §6.1: `message/bhttp
   chunked request` info, one chunk plus the final chunk), `POST`s `message/ohttp-chunked-req` to
   the relay with an optional `X-Client-Trace-Id`, and opens the `message/ohttp-chunked-res`
   answer (`response_nonce || sealed chunks`, §6.2) into its indeterminate-length Binary HTTP
   inner response.
4. Prints the inner status, the header and trailer sections (incl. `grpc-status`) and the body
   as text, or as hex when it is not UTF-8.

```
cargo run --release -- <config_url> <relay_url> <authority> <method> <path> [trace_id] [grpc|http] [body_hex]
```

The binary carries no OHTTP configuration; it reads it at runtime from its environment, four
variables per network (`<NET>` is `MAINNET` or `TESTNET`):

| Variable | Value |
|---|---|
| `OHTTP_E2E_GATEWAY_HOST_<NET>` | the gateway host name |
| `OHTTP_E2E_RELAY_URL_<NET>` | the relay URL, `https://` |
| `OHTTP_E2E_KEYS_DNS_NAME_<NET>` | the DNS TXT name of the signed key configuration |
| `OHTTP_E2E_SIGNING_PUBKEY_<NET>` | the key-configuration signing key, 64 hex digits |

A network is configured with all four or none (an empty variable counts as unset); the values
are checked as `zodl_ohttp_client::OhttpConfig::new` checks them, and mainnet and testnet must
not share one. Errors name the variable or field, never the value. Signed key configurations
(`.../ohttp-configs/signed`) are verified against the configured signing key of `NETWORK`, and
`--key-config-source dns <network>` reads the configured keys DNS name; without a configuration
for that network both fail. Unsigned key configurations need none. The URLs and the authority
of an exchange are always the command-line arguments.

```
OHTTP_E2E_GATEWAY_HOST_TESTNET=ohttp-gateway-testnet.example \
OHTTP_E2E_RELAY_URL_TESTNET=https://relay-testnet.example/relay \
OHTTP_E2E_KEYS_DNS_NAME_TESTNET=testnet.ohttp-keys.example \
OHTTP_E2E_SIGNING_PUBKEY_TESTNET=<64 hex digits> \
  ohttp-e2e --key-config-source dns testnet
```

Examples (placeholder hosts, RFC 2606):

```
# testnet: GetLatestBlock via the testnet relay
NETWORK=testnet ohttp-e2e https://relay-testnet.example/ohttp-configs/signed \
  https://relay-testnet.example/relay \
  ohttp-gateway-testnet.example POST /cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock my-trace-1

# mainnet: a third-party API through a gateway alias (credentials injected by the gateway)
ohttp-e2e https://relay-mainnet.example/ohttp-configs \
  https://relay-mainnet.example/relay \
  prices.example GET /v1/key/info my-trace-2 http

# negative: unknown inner authority must yield inner 403 "unknown authority"
ohttp-e2e https://relay-testnet.example/ohttp-configs \
  https://relay-testnet.example/relay \
  evil.example POST /cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock my-trace-3
```

Expected for the gRPC examples: relay HTTP 200 `message/ohttp-chunked-res`, inner status 200, `grpc-status: 0`, and the gateway
log lines for the trace id (`client_trace_id`) carry no client address.

Set `OHTTP_E2E_REQUEST_ID=<uuid>` to send a client-chosen `X-Request-Id`; a conforming relay replaces it with
its own, and the gateway always mints its own `request_id` regardless.

Relay hardening knobs: `OHTTP_E2E_EXTRA_HEADERS="Name: value|Name2: value2"` adds arbitrary outer headers
(spoofed `X-Relay-Secret`, `X-Forwarded-For`, a relay trace header, junk `X-Request-Id`…); `OHTTP_E2E_DUMP_HEADERS=1`
prints every response header the relay returns. Expected for a conforming relay: the gateway logs only the relay's
own ids/egress (nothing you injected), the request still succeeds, and no gateway/CDN-internal headers come back.

Other environment variables: `NETWORK` (`mainnet` default, or `testnet`: the network a signed
key configuration must be bound to), `OHTTP_E2E_REPLAY=1` (post the same sealed request twice;
the second must be refused as a replay), `OHTTP_E2E_EXPECT_OK=1` (exit non-zero unless the inner
status is 200 and, for gRPC, `grpc-status` is 0; for scripted periodic checks).

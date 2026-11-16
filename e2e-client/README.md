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

A network is configured with all four or none (an empty variable counts as unset; one that is
not Unicode fails every run before anything is sent, whatever the key source); the values
are checked as `zodl_ohttp_client::OhttpConfig::new` checks them, and mainnet and testnet must
not share one. Errors name the variable or field, never the value. Signed key configurations
(`OHTTP_E2E_KEY_CONFIG_SOURCE=signed`, below) are verified against the configured signing key
of `NETWORK`, and `--key-config-source dns <network>` reads the configured keys DNS name;
without a configuration for that network both fail. Unsigned key configurations need none. The
URLs and the authority of an exchange are always the command-line arguments.

```
OHTTP_E2E_GATEWAY_HOST_TESTNET=ohttp-gateway-testnet.example \
OHTTP_E2E_RELAY_URL_TESTNET=https://relay-testnet.example/relay \
OHTTP_E2E_KEYS_DNS_NAME_TESTNET=testnet.ohttp-keys.example \
OHTTP_E2E_SIGNING_PUBKEY_TESTNET=<64 hex digits> \
  ohttp-e2e --key-config-source dns testnet
```

Examples (placeholder hosts, RFC 2606):

```
# testnet: GetLatestBlock via the testnet relay, the signed key configuration verified
# (needs the OHTTP_E2E_*_TESTNET variables above)
NETWORK=testnet OHTTP_E2E_KEY_CONFIG_SOURCE=signed \
  ohttp-e2e https://relay-testnet.example/ohttp-configs/signed \
  https://relay-testnet.example/relay \
  ohttp-gateway-testnet.example POST /cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock my-trace-1

# mainnet: a third-party API through a gateway alias (credentials injected by the gateway)
OHTTP_E2E_KEY_CONFIG_SOURCE=plain ohttp-e2e https://relay-mainnet.example/ohttp-configs \
  https://relay-mainnet.example/relay \
  prices.example GET /v1/key/info my-trace-2 http

# negative: unknown inner authority must yield inner 403 "unknown authority"
OHTTP_E2E_KEY_CONFIG_SOURCE=plain ohttp-e2e https://relay-testnet.example/ohttp-configs \
  https://relay-testnet.example/relay \
  evil.example POST /cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock my-trace-3
```

Expected for the gRPC examples: relay HTTP 200 `message/ohttp-chunked-res`, inner status 200, `grpc-status: 0`, and the gateway
log lines for the trace id (`client_trace_id`) carry no client address.

Set `OHTTP_E2E_REQUEST_ID=<uuid>` to send a client-chosen `X-Request-Id`; a conforming relay replaces it with
its own, and the gateway always mints its own `request_id` regardless.

Relay hardening knobs: `OHTTP_E2E_EXTRA_HEADERS="Name: value|Name2: value2"` adds arbitrary outer headers
(spoofed `X-Relay-Secret`, `X-Forwarded-For`, a relay trace header, junk `X-Request-Id`…); `OHTTP_E2E_DUMP_HEADERS=1`
prints the number of response headers the relay returns (names and values are not printed;
empty or unset is off, any other value such as `0` fails the run).
Expected for a conforming relay: the gateway logs only the relay's own ids/egress (nothing you
injected) and the request still succeeds; that no gateway/CDN-internal headers come back is
checked with a tool that shows the headers, the count only tells whether their number changed.

The relay URL must pass the relay URL rules of `zodl_ohttp_client::OhttpConfig::new` (the
gateway-host rule aside); it is posted to in its canonical form, and a URL the rules refuse
fails the run before anything is sent. `OHTTP_E2E_PLAIN_HTTP_RELAY=1` also accepts an `http://`
relay URL (a relay or an origin checked over plain HTTP in a test network), under the same rules
but the scheme; without it an `http://` URL is refused with an error naming the variable. The
scheme must be written in lower case, `http://` as `https://`: `HTTP://` and `HTTPS://` are
refused, with or without the opt-in.

The key configuration at `<config_url>` is read as `OHTTP_E2E_KEY_CONFIG_SOURCE` says: `signed`
(the envelope, verified against the configured signing key of `NETWORK`) or `plain` (the
unsigned `application/ohttp-keys` document). Unset, the tool guesses as older versions did:
signed when `<config_url>` contains `/signed` or the answer is labelled `application/json`,
plain otherwise, and the run prints a line saying that the source was guessed. The guess is
deprecated: such a run also prints a warning on standard error, and a later version will
require `OHTTP_E2E_KEY_CONFIG_SOURCE`. Set it explicitly in scripts.

An exchange run reads its settings before anything is sent (the DNS mode,
`--key-config-source dns`, reads only the `OHTTP_E2E_*_<NET>` variables). What is checked then
depends on the variable; an error names the variable, never the value:

| Variable | Checked before anything is sent |
|---|---|
| `OHTTP_E2E_KEY_CONFIG_SOURCE`, `NETWORK` | one of their values; empty counts as unset |
| `OHTTP_E2E_PLAIN_HTTP_RELAY`, `OHTTP_E2E_DUMP_HEADERS`, `OHTTP_E2E_REPLAY`, `OHTTP_E2E_EXPECT_OK` | `1` only; empty counts as unset (off); any other value, `0` included, fails the run |
| `OHTTP_E2E_REPLAY_URLS` | every URL, as the relay URL; empty counts as unset |
| `OHTTP_E2E_REPLAY_GAP_MS` | decimal digits (milliseconds); empty counts as unset (0) |
| `OHTTP_E2E_EXTRA_HEADERS` | Unicode only; empty counts as unset |
| `OHTTP_E2E_REQUEST_ID` | Unicode only; when it is sent, an empty value is an empty `X-Request-Id` |
| `OHTTP_E2E_*_<NET>` | Unicode only, unless the run uses the configuration (a signed source) |

A value that is not Unicode fails the run for each of them. Not checked then: an
`OHTTP_E2E_EXTRA_HEADERS` entry without a `:` is ignored, and a header name or value HTTP does
not allow is refused only when a request carrying it is built. The extra headers go on the
key-configuration request too, so such an entry fails there, before anything is sent.
`OHTTP_E2E_REQUEST_ID` goes only on the relay request of a run without `OHTTP_E2E_REPLAY=1`
and `OHTTP_E2E_REPLAY_URLS`: there a value HTTP does not allow fails after the key
configuration was fetched, and with either replay setting it is neither sent nor refused. The
warning about a guessed key source comes after these checks: a run that fails on one of them
does not print it.

What the output leaves out: the HPKE key id is never printed, `NETWORK` only once validated,
and a relay or replay URL is never repeated in an error. It does print the `not_after` of a
signed key configuration, the inner response and, with `OHTTP_E2E_DUMP_HEADERS=1`, the number
of outer response headers.

Other environment variables: `NETWORK` (`mainnet` default, or `testnet`: the network a signed
key configuration must be bound to; any other value fails the run), `OHTTP_E2E_REPLAY=1` (post
the same sealed request twice; the second must be refused as a replay),
`OHTTP_E2E_REPLAY_URLS=urlA,urlB,...` (post the same sealed request to each URL in order,
`OHTTP_E2E_REPLAY_GAP_MS` milliseconds apart, 0 by default; each URL is checked and
canonicalized as the relay URL, all before the first send; an error names an entry by its
position as written, from 0, empty entries counted, while the output, `[XREPLAY i]` and the
trace suffix `-r<i>`, numbers the sends in the order sent, so in `a,,b` an error calls `b`
entry 2 and the output calls it 1; a value that names no URL, such as `,`, fails the run),
`OHTTP_E2E_EXPECT_OK=1` (exit non-zero unless the inner status is 200 and, for gRPC,
`grpc-status` is 0; for scripted periodic checks).

# Testing

What exists, per crate, and how to run it. CI (`.github/workflows/ohttp-build.yml` and
`fuzz.yml`) runs all of it except the end-to-end check, which needs a running gateway and relay.

## Unit and integration tests

### Gateway (`gateway/`)

```bash
cd gateway
cargo test --locked
```

Unit tests sit next to the code in `src/` (configuration parsing, relay secret matching, HPKE
key state, chunked decapsulation and response encoding, Binary HTTP parsing, routing and policy,
authority and path validation, caches and the chain follower, freshness, padding, origin
settings, metrics registration). `tests/streaming.rs` seals a chunked request the way a client
does, has the gateway open it and answer from a slow upstream, and checks that sealed chunks
leave before the upstream ends and that every chunk has the configured size.

The tests that need Redis (replay store, replay peers and background replication, response
cache) connect to `redis://127.0.0.1:6379` and are skipped when nothing listens there. CI runs
them against a `redis:7-alpine` service container; locally:

```bash
docker run --rm -d -p 127.0.0.1:6379:6379 redis:7-alpine
cd gateway && cargo test --locked
```

### Client library (`client/`)

```bash
cd client
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --no-default-features --all-targets -- -D warnings
cargo test --locked
```

Besides the unit tests in `src/`:

| File | What it checks |
|---|---|
| `tests/sans_io.rs` | Published vectors (RFC 9180 A.1.1, RFC 9458 Appendix A key configuration) and an independent chunked-OHTTP receiver built from the `hpke` crate. |
| `tests/gateway_core.rs` | The sans-IO core against the gateway's own key configuration, decapsulation, streaming encoder and signed envelope, under the client profiles. |
| `tests/gateway.rs` | `Client` against the gateway's code served in-process (relay and gateway in one) in front of an echo backend; needs the default `client` feature. |
| `tests/chunked.rs` | Chunked round trips: the gateway's streaming encoder produces what `ChunkedResponseDecoder` opens, chunk by chunk. |
| `tests/signed_policy.rs` | Every `SignedConfigPolicy` option, one assertion per difference between the client profiles. |
| `tests/no_panics.rs` | A deterministic pseudo-random sweep over the byte parsers: random bytes and valid inputs flipped, cut and extended may give errors, never panics. |
| `tests/kotlin_parity.rs` | The scenarios of a former platform implementation, kept so the crate covers them. |

The envelope test vector is `docs/signed-configs-test-vector.json`.

The tests build the crate without endpoint configuration; they use example values (RFC 2606
names) of their own and never need `ZODL_OHTTP_*` variables.

### Relay simulator (`relay-simulator/`)

```bash
cd relay-simulator
cargo test --locked
```

Unit tests for client trace id validation, the derived key-configuration URL and the request and
response header allowlists.

### e2e client (`e2e-client/`)

CI builds it (`cargo build --locked`); it has no tests of its own.

## Fuzzing (`fuzz/`)

cargo-fuzz (libFuzzer) targets for every parser of bytes that come from a relay, a client,
lightwalletd or a third-party backend:

| Target | Input |
|---|---|
| `gateway_chunked_request` | chunked Encapsulated Requests |
| `gateway_inner_request` | Binary HTTP inner requests |
| `gateway_grpc_frames` | gRPC frames from upstream |
| `gateway_outer_headers` | outer request headers |
| `client_chunked_response` | chunked sealed responses |
| `client_bhttp_response` | Binary HTTP responses |
| `client_key_config` | `application/ohttp-keys` documents |
| `client_signed_config` | signed envelopes |
| `client_outer` | outer responses |

`fuzz.yml` seeds the corpora (`examples/gen_corpus.rs`, real encodings), builds every target with
debug assertions and runs each for 60 s on pull requests and pushes to `main`, and for 10 min on
the nightly schedule and on a manual run. Crashes are uploaded as the `fuzz-artifacts` artifact.
Locally, with the nightly toolchain pinned in `fuzz.yml`:

```bash
(cd fuzz && cargo run --release --example gen_corpus -- corpus)
cargo fuzz run --fuzz-dir fuzz --debug-assertions client_chunked_response -- -max_total_time=60
cargo fuzz run --fuzz-dir fuzz --debug-assertions client_chunked_response fuzz/artifacts/client_chunked_response/crash-...
```

A crash is fixed together with a unit test next to the code it is in.

## End-to-end check

`scripts/test-e2e.sh` performs real exchanges through a relay with the e2e client
(`e2e-client/`, built on demand):

```bash
NETWORK=testnet GATEWAY_HOST=ohttp-gateway-testnet.example \
  RELAY_URL=https://relay-testnet.example/relay ./scripts/test-e2e.sh [trace_id]
```

It sends `GetLatestBlock` and expects inner status 200 with `grpc-status: 0`, then sends the
same request to an unknown `:authority` and expects inner 403. `GATEWAY_HOST` and `RELAY_URL`
are required; `CONFIGS_URL` overrides where the key configuration is fetched (by default through
the relay when `RELAY_URL` points at a relay simulator, else `https://$GATEWAY_HOST/ohttp-configs`).

The e2e client can also be run directly (`e2e-client/README.md`): signed or unsigned key
configurations, gRPC or plain HTTP inner requests, the DNS key-configuration source
(`--key-config-source dns <network>`), and options that add outer headers or replay a request
to check how a relay and the gateway treat them.

### Locally, with the relay simulator

```bash
# 1. a gateway (gateway/README.md, "Build and run"), e.g. on :8080 with RELAY_SECRET=local=<secret>
# 2. the relay simulator in front of it
cd relay-simulator
GATEWAY_URL=http://localhost:8080/gateway RELAY_SECRET=<secret> NETWORK=testnet cargo run
# 3. one exchange through it
cd ../e2e-client && cargo run --release -- \
  http://localhost:8081/ohttp-configs http://localhost:8081/relay \
  ohttp-gateway.example POST /cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock local-1
```

`ohttp-gateway.example` must be in the gateway's `GATEWAY_HOSTS`.

## License

AGPL-3.0-only with commercial licensing available; see the repository's
[LICENSE](../LICENSE), [LICENSE-EXCEPTIONS.md](../LICENSE-EXCEPTIONS.md) and
[COMMERCIAL-LICENSE.md](../COMMERCIAL-LICENSE.md).

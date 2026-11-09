# ZODL OHTTP — Oblivious HTTP for Zcash light clients

Oblivious HTTP (RFC 9458, chunked variant draft-ietf-ohai-chunked-ohttp) gateway, client library
and test tooling that put a privacy relay between Zcash wallets and lightwalletd.

## Architecture

```
Wallet → Relay (independent operator) → OHTTP Gateway (this repo) → lightwalletd / allowlisted HTTP APIs
```

**Privacy model:**
- The relay sees the client IP but cannot read the request content (HPKE encrypted).
- The gateway sees the content but not the client IP (it only sees the relay's address).
- Both parties would have to collude to deanonymize a user.

See [docs/architecture.md](docs/architecture.md) for the system design and threat analysis.

## Repository Structure

```
ohttp/
├── gateway/              # Rust OHTTP gateway (RFC 9458 HPKE decapsulation, lightwalletd proxy, caches)
├── relay-simulator/      # Test relay for local end-to-end runs
├── client/               # Rust client library (zodl-ohttp-client), shared by the wallet SDKs
├── e2e-client/           # Minimal end-to-end client (one real exchange through a relay)
├── fuzz/                 # cargo-fuzz targets for every parser of untrusted bytes
├── docs/                 # Architecture, observability, testing, signed-config test vector
└── scripts/              # Build, end-to-end test and image verification helpers
```

## Components

### Gateway (`gateway/`)

The OHTTP gateway. Decapsulates chunked OHTTP requests, enforces the request policy,
proxies to lightwalletd (gRPC) or to an allow-listed third-party backend, and encapsulates the
response. Replay protection, response caching, a signed key-configuration endpoint
(`/ohttp-configs/signed`) and Prometheus metrics are built in.

See [gateway/README.md](gateway/README.md) for endpoints, metrics and key rotation, and
[gateway/CONFIG.md](gateway/CONFIG.md) for every environment variable.

### Relay Simulator (`relay-simulator/`)

A test relay: forwards sealed requests and key-configuration GETs to a gateway with a relay
secret and its own request id, and strips client-identifying headers. For tests only.

See [relay-simulator/README.md](relay-simulator/README.md).

### Client (`client/`)

Rust client library, crate `zodl-ohttp-client`:

- Key configuration: `application/ohttp-keys` selection, signed envelope (`/ohttp-configs/signed`)
  verification
- Chunked OHTTP request encapsulation and response decapsulation, Binary HTTP (RFC 9292) framing;
  requests are padded to fixed size buckets (4 KiB steps, `SendTransaction` 16 / 32 KiB), never
  past the 10 MiB sealed-request cap
- `Client` (feature `client`): relay posting, key refetch and one retry after an outer `400`/`422`

The crate carries no endpoint or key: the application passes the configuration of each network
in at runtime (placeholder values):

```rust
use zodl_ohttp_client::{OhttpConfig, OhttpConfigParams, OhttpNetworks};

let testnet = OhttpConfig::new(OhttpConfigParams {
    gateway_host: "ohttp-gateway-testnet.example",
    relay_url: "https://relay-testnet.example/relay",
    keys_dns_name: "testnet.ohttp-keys.example",
    signing_pubkey: signing_pubkey_hex, // 64 hex digits
})?;
let networks = OhttpNetworks::new(None, Some(testnet))?; // mainnet: OHTTP off
let relay = networks.relay_for("ohttp-gateway-testnet.example");
```

Tested against the gateway's own code
(`client/tests/`). `e2e-client/` is built on it. [client/INTEGRATION.md](client/INTEGRATION.md)
explains configuration and use; [client/CHANGELOG.md](client/CHANGELOG.md) lists its changes.

### End-to-end client (`e2e-client/`) and fuzzing (`fuzz/`)

`e2e-client/` performs one real exchange through a relay (used by `scripts/test-e2e.sh`).
`fuzz/` holds the libFuzzer targets that CI runs on every pull request and
nightly.

## Quick Start

### Prerequisites

- Rust 1.88+ (the client crate's `rust-version`)
- Docker 27+ (images)

### Local Development

```bash
# Run the gateway locally (environment: gateway/README.md, "Build and run"), in one terminal
(cd gateway && cargo run)

# Run the relay simulator in front of it, in a second terminal
(cd relay-simulator && GATEWAY_URL=http://localhost:8080/gateway RELAY_SECRET=change-me cargo run)

# One end-to-end exchange through a real relay (GATEWAY_HOST and RELAY_URL required)
NETWORK=testnet GATEWAY_HOST=ohttp-gateway-testnet.example RELAY_URL=https://relay-testnet.example/relay \
  ./scripts/test-e2e.sh my-trace   # see e2e-client/README.md
```

### Build Docker Images

```bash
./scripts/build-all.sh            # all images
./scripts/build-all.sh gateway    # one component
```

Images can be pushed to any OCI registry (`REGISTRY_URL`, see `scripts/deploy.sh`).

## CI

- `.github/workflows/ohttp-build.yml`: `cargo test` for the gateway and the relay simulator,
  `rustfmt` + `clippy` + `cargo test` for the client library and a build of the e2e client, on pull
  requests and pushes to `main`; gateway, relay-simulator and e2e-client images are built on every run and,
  from `main` and `v*` tags only, pushed (tags `sha-<short>`, semver for `v*` tags); every pushed
  image (gateway, relay simulator and e2e client) gets an SPDX SBOM (workflow artifact), a cosign
  signature and a SLSA provenance attestation. The registry, the push role and the region come
  from repository secrets.
- `.github/workflows/fuzz.yml`: every fuzz target for 60 s on pull requests and pushes, 10 min
  nightly.
- `.github/workflows/sign-existing-image.yml` (manual) signs an already pushed image;
  `scripts/verify-image.sh` checks an image's signature and provenance.

## Documentation

- [Architecture](docs/architecture.md) — hops, privacy model, relay authentication, key
  configuration and discovery, replay protection, response framing, multiple origins
- [Gateway](gateway/README.md) and [gateway configuration](gateway/CONFIG.md)
- [Client integration](client/INTEGRATION.md)
- [Observability](docs/observability.md) — request ids, trace ids, logging and metrics
- [Testing](docs/testing.md) — unit tests, fuzzing, end-to-end checks
- [CHANGES.md](CHANGES.md) and [client/CHANGELOG.md](client/CHANGELOG.md)
- [Signed key configuration test vector](docs/signed-configs-test-vector.json)

## Security

**Threat model:**
- Passive relay: cannot read encrypted requests.
- Active gateway: cannot learn the client IP.
- Collusion: relay and gateway cooperating can deanonymize a user.

**Mitigations:**
- Separate relay operator from gateway operator.
- Gateway logs carry no client IP (it never sees one); the relay's request id is logged only as an
  HMAC under a per-process random key, so gateway logs cannot be joined with the relay's after the
  fact. The exception is the opt-in client trace id (`X-Client-Trace-Id`), which a client sends
  only in debug builds precisely to link the two views.
- A relay whose egress addresses rotate further limits gateway-side fingerprinting.
- All first-party code is Rust. (The `e2e-client` runtime image is based on a Python image only so
  that the binary can be wrapped in a scripted loop; no Python ships in this repository.)

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Source files carry the license header described in
[AGENTS.md](AGENTS.md).

## License

Copyright © 2026 Znewco, Inc. (d/b/a Zcash Open Development Lab)

ZODL OHTTP is free software, licensed under the GNU Affero General Public License, version 3 only
(AGPL-3.0-only). See [LICENSE](LICENSE).

In short: you may use, study, modify, and redistribute ZODL OHTTP, but if you incorporate it into
an application, the complete source of that application must be made available under the AGPL to
its users, including users who interact with it over a network.

If those terms don't fit your project, **commercial licenses are available** — see
[COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md). Official ZODL builds distributed through the Apple
App Store are released by Znewco under separate terms; no App Store distribution permission is
granted to AGPL licensees — see [LICENSE-EXCEPTIONS.md](LICENSE-EXCEPTIONS.md).

ZODL OHTTP depends on third-party Rust crates that are separately licensed by their respective
copyright holders (MIT, Apache-2.0, BSD and similar permissive terms) and are not covered by this
notice.

## Links

- [RFC 9458](https://www.rfc-editor.org/rfc/rfc9458.html) — Oblivious HTTP
- [draft-ietf-ohai-chunked-ohttp](https://datatracker.ietf.org/doc/draft-ietf-ohai-chunked-ohttp/) — chunked Oblivious HTTP
- [RFC 9292](https://www.rfc-editor.org/rfc/rfc9292.html) — Binary HTTP messages
- [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) — Hybrid Public Key Encryption (HPKE)

# zodl-ohttp-client

Oblivious HTTP ([RFC 9458](https://www.rfc-editor.org/rfc/rfc9458.html), chunked variant
[draft-ietf-ohai-chunked-ohttp](https://datatracker.ietf.org/doc/draft-ietf-ohai-chunked-ohttp/))
client library for the [ZODL OHTTP](https://github.com/zodl-inc/zodl-ohttp) gateway, shared by the
ZODL wallet SDKs.

A request is encoded as Binary HTTP ([RFC 9292](https://www.rfc-editor.org/rfc/rfc9292.html)),
sealed with HPKE to the gateway's key and posted to an oblivious relay. The relay sees the
client's address and an opaque blob; the gateway opens it, forwards it to the backend its
`:authority` names (lightwalletd or an allowlisted HTTP API) and seals the answer back, seeing the
request but never the address.

```
Wallet → Relay (independent operator) → OHTTP Gateway → lightwalletd / allowlisted HTTP APIs
```

## Features

- Key configuration: `application/ohttp-keys` selection and verification of the gateway's signed
  envelope (`/ohttp-configs/signed`, Ed25519).
- Chunked OHTTP request encapsulation and response decapsulation, Binary HTTP framing. Requests
  are padded to fixed size buckets (4 KiB steps, `SendTransaction` 16 / 32 KiB), never past the
  10 MiB sealed-request cap.
- `Client` (default feature `client`, over reqwest): relay posting, key refetch and one retry
  after an outer `400`/`422`.
- A sans-IO core for callers that do their own I/O (for example over a Tor-capable transport):
  `cargo build --no-default-features` builds it without reqwest or tokio.

HPKE suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM. Minimum supported Rust version:
1.88.

## Usage

The crate carries no endpoint, host name or key: the application passes the OHTTP configuration
of each network in at runtime (placeholder values below). A network without one has OHTTP off.

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

[INTEGRATION.md](https://github.com/zodl-inc/zodl-ohttp/blob/main/client/INTEGRATION.md) explains
configuration, key configuration sources, `Client`, the sans-IO loop, errors and testing an
integration; [CHANGELOG.md](https://github.com/zodl-inc/zodl-ohttp/blob/main/client/CHANGELOG.md)
lists the changes. The protocol background and threat model are in
[docs/architecture.md](https://github.com/zodl-inc/zodl-ohttp/blob/main/docs/architecture.md).

## License

Copyright © 2026 Znewco, Inc. (d/b/a Zcash Open Development Lab)

Licensed under the GNU Affero General Public License, version 3 only (AGPL-3.0-only); see
[LICENSE](LICENSE). If you incorporate this crate into an application, the complete source of
that application must be made available under the AGPL to its users, including users who
interact with it over a network.

Commercial licenses are available, see [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md). No App
Store distribution permission is granted to AGPL licensees, see
[LICENSE-EXCEPTIONS.md](LICENSE-EXCEPTIONS.md).

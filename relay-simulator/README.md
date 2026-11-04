# OHTTP Relay Simulator

A minimal Oblivious Relay Resource (RFC 9458) for local and end-to-end tests of the gateway. It
never decrypts anything: the client seals its request, the simulator forwards the opaque body
to the gateway and streams the sealed answer back. It is a test tool, not a relay to put in
front of real users (no rate limiting, no address rotation, no edge protection).

## What it does

- `POST /relay`: accepts `Content-Type: message/ohttp-chunked-req` only (else 415) and a
  non-empty body (else 400), up to 10 MiB. Forwards the body to `GATEWAY_URL` with
  `X-Relay-Secret`, a fresh `X-Request-Id` of its own (a client-supplied one is dropped), a valid
  `X-Client-Trace-Id` if the client sent one, and a fixed `User-Agent`; no client address or
  other client header is forwarded (an opt-in trace id links the relay's and the gateway's views
  of the requests that carry it). Returns the gateway's answer as `message/ohttp-chunked-res`, streamed,
  with only `Cache-Control` and `Retry-After` from the gateway's headers. A gateway error status
  is passed through with a plain-text body; an unreachable gateway is 502.
- `GET /ohttp-configs`, `GET /ohttp-configs/signed`: forwards the GET to the gateway (with
  `X-Relay-Secret`, so it also works with `RELAY_SECRET_ON_KEY_CONFIG=require`) and returns the
  status and body unchanged, with only `Content-Type`, `Content-Length`, `Cache-Control` and
  `Retry-After`. Nothing is cached.
- Never follows a redirect from the gateway. Waits up to 120 s between bytes from the gateway, so
  long streams are not cut.
- Logs the client address (as a relay operator would) and never forwards it.
- `GET /health`: 200. `GET /metrics`: Prometheus metrics `relay_requests_total{network,
  gateway_status}`, `relay_request_duration_seconds{network}`, `relay_requests_in_flight{network}`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `GATEWAY_URL` | `http://localhost:8080` | URL the sealed requests are posted to: the gateway's `/gateway` endpoint, e.g. `http://localhost:8080/gateway`. |
| `GATEWAY_CONFIGS_URL` | `GATEWAY_URL` with path `/ohttp-configs` | The gateway's key-configuration URL; `/signed` is appended for the signed envelope. |
| `RELAY_SECRET` | required | Value sent as `X-Relay-Secret`: the secret part of one of the gateway's `RELAY_SECRET` entries. The process exits without it. |
| `NETWORK` | `mainnet` | Label of logs and metrics. |
| `PORT` | `8081` | Listen port. |
| `RUST_LOG` | `info` | Log filter (JSON logs). |

## Usage

```bash
# a gateway on :8080 with RELAY_SECRET=local=<secret> (gateway/README.md, "Build and run")
GATEWAY_URL=http://localhost:8080/gateway RELAY_SECRET=<secret> NETWORK=testnet cargo run

# one exchange through it with the e2e client
cd ../e2e-client && cargo run --release -- \
  http://localhost:8081/ohttp-configs http://localhost:8081/relay \
  ohttp-gateway.example POST /cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock local-1
```

Docker:

```bash
docker build -t ohttp-relay-simulator .
docker run -p 8081:8081 -e GATEWAY_URL=http://<gateway>:8080/gateway \
  -e RELAY_SECRET=<secret> ohttp-relay-simulator
```

`cargo test` runs its unit tests (trace id validation, the derived configuration URL, the header
allowlists).

## License

AGPL-3.0-only with commercial licensing available; see the repository's
[LICENSE](../LICENSE), [LICENSE-EXCEPTIONS.md](../LICENSE-EXCEPTIONS.md) and
[COMMERCIAL-LICENSE.md](../COMMERCIAL-LICENSE.md).

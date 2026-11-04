# Observability and request correlation

The gateway writes one JSON log line per event to stdout (`RUST_LOG` filters them) and serves
Prometheus metrics on the internal port 9090 (`/metrics`). The full metric list is in
`gateway/README.md`, "Metrics". Nothing in the logs or metrics identifies a client: the gateway
never receives a client address (the debug-only `X-Client-Trace-Id` below is the one deliberate
exception).

## Correlation ids

Every hop mints its own id; no id is trusted across a hop boundary.

| Log field (gateway) | Origin | Purpose |
|---|---|---|
| `request_id` | the gateway, a fresh UUIDv4 per request | Key of all gateway log lines of a request. The only id the gateway sends upstream (`X-Request-Id`, and `grpc-request-id` metadata on gRPC calls). |
| `relay_request_id` | the relay's `X-Request-Id` (else a relay's trace header the gateway recognises), or `-` | Logged only as HMAC-SHA256 under a random per-process key, truncated to 16 hex characters. |
| `relay_request_id_source` | the gateway | Which header the relay id came from, or `none`. |
| `client_trace_id` | the client, opt-in (`X-Client-Trace-Id`) | Debugging only, see below. |
| `relay` | the gateway | Name of the `RELAY_SECRET` entry that authenticated the request (`relay-<n>` for a bare entry, `-` without relay authentication). |
| `origin` | the gateway | `ORIGIN_ID`, or `-`. |
| `network` | the gateway | `NETWORK`. |
| `hop` | the gateway | `ohttp` (the outer exchange), `lwd` (lightwalletd), `upstream` (a third-party backend). |

The relay id is untrusted input: it is accepted only if it matches
`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`, is never forwarded upstream or echoed to the client, and
only ever appears as that HMAC. A missing or invalid relay id does not reject the request; it is
counted in `ohttp_relay_request_id_total{state="missing"|"invalid"}`.

Because the HMAC key exists only in the memory of the running process, the same relay id maps to
the same value for as long as the process runs, and to nothing anyone can recompute after it
exits. The gateway's logs therefore cannot be joined with a relay's logs (which pair the relay id
with the client address) on the relay id after the fact.

## Per-request log lines

| Message | Fields beyond the ids |
|---|---|
| `Gateway received OHTTP request` | `bytes_in` |
| `Serving lightwalletd request` | `method`, `path`, `route`, `grpc_status`, `bytes_out`, `duration_ms` |
| `Streaming lightwalletd request` / `Lightwalletd response ended` | `route`, `grpc_status`, `outcome`, `bytes_out`, `duration_ms` |
| `Serving third-party request` | `method`, `path` (the policy pattern that admitted it, not the concrete path or query), `status`, `bytes_out`, `duration_ms` |
| `Forwarding to backend (streaming)` | `backend`, `method`, `path` (third-party: the policy pattern) |

Refusals (relay authentication, replay, decapsulation, policy, limits) are logged at `warn` with
`request_id` and a reason. With `LOG_OUTER_HEADER_NAMES=1` the names of the outer headers each
request arrived with are logged as well, never their values.

## Correlating a request with a relay operator

- **Gateway to upstream**: an upstream call made for one request carries that request's
  `request_id`, so an upstream log line can be matched to the gateway's. Calls the caches make
  on their own (coalesced fetches, the chain follower, backfills) carry their own id or none.
- **Gateway to relay, while debugging**: the client sends `X-Client-Trace-Id` (debug builds
  only). A conforming relay validates it and forwards it unchanged; the gateway logs it as
  `client_trace_id`. Both operators can then find the same request in their own logs by that
  value and compare timestamps. The id is chosen by the person debugging, so it links the
  relay's view (client address) with the gateway's view (content) for exactly those requests;
  never enable it by default.
- **Without a client trace id**, the operators can only compare time windows and aggregate
  counts (per relay name, `ohttp_relay_requests_total{relay}`); no shared id links individual
  requests, by design (timing and size correlation remain, see `docs/architecture.md`).

`X-Client-Trace-Id` must match `^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$` (letters, digits, `.`, `_`,
`:`, `-`, at most 64 characters, starting with a letter or digit); the gateway drops an invalid
one. It is never a metric label and is not forwarded upstream.

## What a relay is expected to do

For the ids above to mean anything, a relay in front of the gateway:

1. generates its own `X-Request-Id` for every request and never forwards one from the client;
2. forwards a valid `X-Client-Trace-Id` unchanged and drops an invalid one;
3. forwards no client-identifying header (`X-Forwarded-For`, `X-Real-IP` and similar);
4. forwards `GET /ohttp-configs` and `GET /ohttp-configs/signed` as they are, without caching.

`relay-simulator/` behaves this way and can be used to check a gateway setup locally.

## Health and multi-origin signals

| Signal | Meaning |
|---|---|
| `GET /healthz` (public port) | `200` while `ohttp_security_redis_connected` and `ohttp_lwd_reachable` are both 1, else `503`. |
| `ohttp_key_config_info{fingerprint,signing_key_id}` | `count by (network) (count by (network, fingerprint) (ohttp_key_config_info)) > 1` across origins means two origins publish different keys. |
| `ohttp_origin_info{origin}` | Which origin a scrape came from. |
| `ohttp_replay_peer_total{peer,result}` | Nonce writes to peer origins; `replay` is a cross-origin replay refused, `error`/`timeout`/`disconnected` a peer problem. |
| `ohttp_replay_mode_effective{mode}` | Whether background replication is currently trusted (`async-reads`) or degraded (`async-reads-strict`). |

`edge` in `ohttp_relay_requests_total{relay,edge}` is a three-letter location code taken from an
edge request-id header when the relay's network adds one (else `-`). It names a part of the
relay's network, never a client, and is never logged per request.

## Cardinality

`request_id`, `relay_request_id` and `client_trace_id` are never metric labels. The `rpc` label
is one of the known lightwalletd method names or `other`; third-party paths never become labels.

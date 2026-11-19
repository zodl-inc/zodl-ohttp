# OHTTP Gateway

The Oblivious Gateway Resource (RFC 9458) for Zcash light wallets, in Rust. It accepts chunked
Encapsulated Requests (draft-ietf-ohai-chunked-ohttp) from authorised relays only, opens them
with HPKE (RFC 9180), forwards the Binary HTTP (RFC 9292) inner request to lightwalletd (gRPC)
or to an allowlisted third-party HTTP API, and seals the answer back to the client as it
streams.

Every setting is an environment variable: see [CONFIG.md](CONFIG.md). The design, privacy model
and protocol details are in [../docs/architecture.md](../docs/architecture.md); logs and
metrics in [../docs/observability.md](../docs/observability.md).

## Endpoints

Public listener (`PORT`, default 8080):

| Path | Method | Answer |
|---|---|---|
| `/gateway` | POST | An Encapsulated Request, `Content-Type: message/ohttp-chunked-req`, with `X-Relay-Secret`. Answers `message/ohttp-chunked-res`. |
| `/ohttp-configs` | GET | The key configuration, `application/ohttp-keys` (RFC 9458 §3), `Cache-Control: max-age=300`. |
| `/ohttp-configs/signed` | GET | The signed key configuration envelope (JSON, below), `Cache-Control: max-age=300`. 503 without `CONFIGS_SIGNING_SEED_HEX`. |
| `/healthz` | GET | `200 ok` while replay protection works, lightwalletd is reachable and recent lightwalletd calls did not fail too often (`HEALTHZ_LWD_ERROR_RATIO`), else `503 unavailable`. Replay protection works while the security Redis answers and its connection reaches a primary (not while its last `ROLE` said replica, or a reconnect after a failover signal has been pending for more than 2 s), or, with `REPLAY_UNAVAILABLE_FALLBACK` (`failover` mode, or `async-reads` whose own store is the fallback store: `ohttp_replay_local_fallback` 1), while it does not but every peer store answers and decides in its place (`ohttp_replay_serving_via_fallback`) and the WRITEs decided there do not keep failing (`REPLAY_FALLBACK_HEALTH_FAILURES`). At startup it also waits (`REPLAY_STARTUP_STORES_WAIT_SECS`, default 10 s) until the replay peers and standby stores are connected, each with an open `WAIT` connection where its replica acknowledgement is required, and the local `WAIT` pool has a usable connection. Unauthenticated, no I/O, no details in the body: a monitor path for a load balancer. |
| `/health/startup` | GET | `200` once the process is listening and the startup gate of the replay stores is open (`503 starting` while it waits, as for `/healthz`, at most `REPLAY_STARTUP_STORES_WAIT_SECS`). Does not depend on lightwalletd. |

Inside OHTTP only (an inner request to a `GATEWAY_HOSTS` name; not a path of the public
listener): `GET /ohttp-gateway/v1/third-party-hosts`, the third-party hosts this gateway carries
and their routes, for wallets, when `THIRD_PARTY_HOSTS_PUBLISH` is set (see
[CONFIG.md](CONFIG.md), "The host list for wallets").

Any other method on these paths, and any other path in `ohttp` mode, answers `426`. With
`RELAY_SECRET_ON_KEY_CONFIG=require` the two key-configuration GETs need `X-Relay-Secret` too.

Observability listener (port 9090, bind address `INTERNAL_BIND_ADDR`; keep it internal):

| Path | Answer |
|---|---|
| `/health`, `/health/live` | `200` while the process runs, with lightwalletd reachability in the body. |
| `/health/ready` | `503` once lightwalletd has been unreachable for more than 60 s, else `200`. |
| `/metrics` | Prometheus text format. |

### Outer status codes of `POST /gateway`

Failures before the request is opened cannot be sealed and are plain outer statuses:
`401` (missing, duplicated or wrong `X-Relay-Secret`), `426` (wrong content type), `413`
(body over 10 MiB), `400` (body unreadable, or the request does not decapsulate: unknown key
id, malformed or forged ciphertext), `409` (replay: the same Encapsulated Request was seen
within the nonce TTL; a replay found only at a peer origin is answered inside the sealed
response instead), `503` (in-flight limit reached, with `Retry-After: 1`; or replay
protection unavailable). Everything after decapsulation, errors included, is a sealed inner
response: inner `403` for an unknown or malformed authority or an operation not allowed by the
policy, inner `400` for a malformed path or a stale request, gRPC statuses for lightwalletd
calls.

## Build and run

```bash
cargo build --release            # binary target/release/ohttp-gateway
cargo test                       # store-backed tests need a Redis on 127.0.0.1:6379 and fail without it;
                                 # OHTTP_TEST_ALLOW_NO_STORE=1 skips them instead (ignored when CI is set)
docker build -t ohttp-gateway .  # from this directory
```

A minimal local run (two Redis databases, a lightwalletd on 9067):

```bash
export GATEWAY_MODE=ohttp NETWORK=testnet LWD_ADDR=localhost:9067
export GATEWAY_HOSTS=ohttp-gateway.example
export RELAY_SECRET="local=$(openssl rand -hex 32)"
export HPKE_KEYS="1:$(openssl rand -hex 32)"
export CONFIGS_SIGNING_SEED_HEX="$(openssl rand -hex 32)"
export REDIS_URL=redis://127.0.0.1:6379/0 REDIS_SECURITY_URL=redis://127.0.0.1:6379/1
cargo run --release
```

TLS is terminated in front of the gateway. The relay simulator (`../relay-simulator`) and the
e2e client (`../e2e-client`, `../scripts/test-e2e.sh`) exercise a running gateway end to end.

`ohttp-gateway backfill` fills the permanent block tier from lightwalletd and exits
(CONFIG.md, "`ohttp-gateway backfill`").

## Signed key configuration

`GET /ohttp-configs/signed` returns:

```json
{
  "v": 1,
  "network": "mainnet",
  "configs": "<base64 of the application/ohttp-keys document>",
  "not_before": 1699999700,
  "not_after": 1700021300,
  "key_id": "<first 4 bytes of SHA-256 of the signing public key, hex>",
  "sig": "<base64 Ed25519 signature>"
}
```

The signature covers `"zodl-ohttp-configs-v1" || 0x00 || network || 0x00 || u64be(not_before) ||
u64be(not_after) || configs` (the decoded document). Envelopes are issued per one-hour slot:
`not_before` is the slot start minus 300 s and `not_after` the slot start plus 21300 s, so every
envelope is valid for 21600 s (`MAX_ISSUED_VALIDITY_SECS`) and overlaps the next one by five
hours. Ed25519 is deterministic, so every gateway with the same seed, network and keys serves the
identical envelope within a slot. Clients pin the public key of `CONFIGS_SIGNING_SEED_HEX` in
their OHTTP configuration; `../docs/signed-configs-test-vector.json` is a test vector with a test key.

## HPKE key rotation

A key is accepted before it is advertised and stays accepted after it is no longer advertised,
long enough for every cached configuration to expire. Signed envelopes live 21600 s, so a key
must stay accepted for **21720 s after the last moment it was advertised** (21600 + 120 s of
margin); the unsigned `/ohttp-configs` (`max-age=300`) needs less. When several origins serve one
gateway name, each phase must be running on all of them before the next starts. Rotating from key
A (id 1) to key B (id 2):

| Phase | `HPKE_KEYS` (advertised) | `HPKE_ACCEPT_ONLY_KEYS` | Before the next phase |
|---|---|---|---|
| 0 | `1:A` | - | - |
| 1 accept | `1:A` | `2:B` | every origin runs phase 1 |
| 2 advertise | `2:B,1:A` (B preferred) | - | every origin runs phase 2 |
| 3 stop advertising A | `2:B` | `1:A` | 21720 s after the last origin stopped advertising A |
| 4 retire A | `2:B` | - | - |

Check each phase with the startup log line "HPKE key configuration loaded" (`key_ids`,
`accept_only_key_ids`, `key_config_fingerprint`) and the metric `ohttp_key_config_info`. A
client that still holds a retired key gets an outer 400, refetches the configuration and retries
once, so an emergency revocation can skip the waits at the cost of one extra round trip per
client.

## Caching

The cache is consulted only after the authority has been resolved: only requests for the
gateway's own lightwalletd are served from or stored in the lightwalletd caches, and only
successful answers (HTTP 200, grpc-status 0) are stored. There are no TTLs; entries are tied to
chain state:

- A chain follower (one leader per network, elected through a Redis lock) polls the tip and
  keeps a height-to-hash index of recent blocks. On a reorg it walks back to the fork point and
  deletes the affected index entries and cached blocks, nullifiers and tree states. A
  lightwalletd answering with a lower tip on the indexed chain is behind, not a reorg. A leader
  whose stored tip stops moving while another process's lightwalletd is ahead is replaced by
  that process (`CHAIN_TIP_STALE_SECS`). The tip, every index entry with its block and every
  deletion of a reorg are written only while the writer holds the lock with its own token, so
  a leader replaced during a slow tick cannot write the index of another fork, delete what its
  successor wrote or move the tip back. Followers keep the tip fresh only while the leader
  confirms it (`{chain}tip_seen`); the leader confirms a tip only for 10 minutes after it
  moved (`{chain}tip_at`, whichever process wrote it), so a lightwalletd stuck at or behind the
  tip cannot keep it fresh, and one that stays behind gives the lock up. A tip's age is at
  least as long as a process has read the same stored record on its own clock, so a `tip_at`
  ahead of a process's clock delays neither its stale-leader probe nor, after it takes the
  lock, the end of the confirmations by more than the bound after its first read of that
  record. A process that takes the lock over a tip whose `tip_at` is more than 2 s ahead of
  its clock replaces it, with its first confirmation and in the same script, by the time it
  counts the tip's age from, so followers read that age too; a leader whose own clock stepped
  back does the same for a `tip_at` that is left that far ahead, and counts its confirmation
  bound on its local clock as well. A tip that moves while `tip_at` stays (a leader that writes neither key, after a
  rollback) is followed as one without `tip_at`, unless the stamp the leader writes with
  every `tip_at` (`{chain}tip_stamp`, in the same script) vouches for the read: it names
  exactly that tip and time, the process remembers no leftover verdict for that time, and it
  did not read the same stamp value before next to another stored tip. When only the stamp
  key is lost afterwards (evicted) while that tip and time stay, what it vouched for stands. A tip a
  follower serves from its own lightwalletd ahead of a stale leader is dropped when the stored
  chain forks under it, when the lock is taken while that cannot be checked, and, as leader,
  when it indexes a lower tip of another fork.
- Blocks (`GetBlockRange` per block, `GetBlock`, `GetBlockNullifiers`) are served only while
  their hash matches the index; final blocks can live in the permanent tier
  (`PERMANENT_REDIS_URL`). `GetTreeState`, mined `GetTransaction` and `GetSubtreeRoots` entries
  are validated against the index the same way. Tip-scoped answers (`GetLightdInfo`,
  `GetLatestTreeState`, `GetAddressUtxos*`) are keyed by the tip hash; a `GetLatestTreeState`
  answer is stored and served only when its height and hash are that tip, a `GetLightdInfo`
  answer only when its `blockHeight` is at least the tip height (no hash to compare: an
  instance behind is caught, one on another fork at the same height is not). `GetLatestBlock` is
  answered from the follower's tip.
- `GetMempoolStream` subscribers share one upstream stream per process; identical upstream calls
  in flight are coalesced; `SendTransaction` is never cached or coalesced.
- A shared epoch counter in the security Redis is part of every cache key: incrementing it
  flushes every cached answer at once. Each security store keeps its own counter, so a flush of
  several origins is one increment per store. While the security Redis gives no answer (the peer
  stores decide in its place) a change of a replay peer's counter against the value last seen
  for that store (or a peer never seen) is taken as such a flush and the gateway moves to a
  fresh random epoch (`ohttp_epoch_bump_seen_at_peer_total`); once its own store answers again,
  that store's counter applies again, so increment it too.
- Third-party answers are cached only for the routes in `THIRD_PARTY_CACHE_ROUTES`.

## Timeouts and relays

A relay typically closes a response that stays silent for too long between bytes. The gateway
keeps long answers moving: `GetMempoolStream` ends cleanly after `LONG_POLL_MAX_INITIAL_SILENCE_SECS`
without a first message and `LONG_POLL_IDLE_SECS` after the last one; `text/event-stream`
answers get keep-alive comments every `SSE_KEEPALIVE_SECS`; partial data is flushed as a short
chunk after `CHUNK_FLUSH_MS`. Every upstream call is bounded by `LWD_TIMEOUT_SECS` in total, and
a lightwalletd call by its class: an RPC with one answer by `LWD_UNARY_TIMEOUT_SECS`, a
server-streaming RPC by `LWD_STREAM_IDLE_SECS` of silence (for the head and between frames),
`SendTransaction` by `LWD_SEND_TIMEOUT_SECS` (default `LWD_TIMEOUT_SECS`). An
upstream that sends no response head at all (an unresponsive backend) can still exceed a relay's
silence limit; the client then sees the relay's error.

A lightwalletd connection must be established within `LWD_CONNECT_TIMEOUT_MS`. A call that could
not connect, or whose connection ended before the request was written to it, is sent once more;
a read (every lightwalletd RPC except `SendTransaction`) is also
sent once more when it got a transport error. With `LWD_ENDPOINTS`, a read without a response head
after `LWD_HEDGE_DELAY_MS` (default half of its head deadline) is also sent to another instance
while the first attempt keeps running: the first head wins, and the other attempt is not
counted as a failure. It is not cancelled at that point (a cancelled call can cost the node
behind lightwalletd an RPC slot): it runs to its end in a task of its own and its answer is
discarded. It is still cancelled when `LWD_HEDGE_MAX_INFLIGHT` such attempts are running
already, when it has no response head at the call's head deadline, and when reading its body
takes more than 10 s or 8 MiB (see `LWD_HEDGE_DELAY_MS` and `LWD_HEDGE_MAX_INFLIGHT` in
[CONFIG.md](CONFIG.md)). Heavy calls, `GetMempoolStream` and the transparent-address RPCs
are not hedged; hedges are bounded by `LWD_HEDGE_MAX_INFLIGHT` and to one in ten reads (six a
minute are always allowed). The second attempt goes to another lightwalletd instance, and an
instance that failed, or lost two hedges in a row, is skipped for 30 s. A `SendTransaction` that may have reached lightwalletd is never
sent a second time by the gateway (only a connect error, and an error by which the HTTP client
says the request was not written, are followed by the one retry; every other error fails it), and a call that fails after its response head arrived is not
retried.

## Third-party host list: wallet integration

For wallet SDKs. A wallet sends a third-party request through the gateway only when it knows
the gateway carries the host; anything else it refuses, and it never falls back to a direct
connection. A compiled copy of the gateway's hosts goes stale whenever the gateway's set
changes, so the gateway publishes the set (`THIRD_PARTY_HOSTS_PUBLISH`, see
[CONFIG.md](CONFIG.md)).

**Request.** An ordinary OHTTP request to the gateway that carries the third-party hosts, with
the inner request

```
GET /ohttp-gateway/v1/third-party-hosts
:authority  <the gateway's own host name, as for lightwalletd calls>
if-none-match: "<revision>"        (optional, when a list is held)
```

No body, no query, no credential. The path exists only inside OHTTP; a plain HTTPS request to
it is not answered.

**Answer.** `200`, `content-type: application/json`, `cache-control: max-age=<max_age_secs>`,
`etag: "<revision>"`:

```json
{"version":1,"revision":"5b0c1d9e7a3f2c44","scope":"all","max_age_secs":300,
 "hosts":[{"host":"api.example.org","routes":["GET /*","POST /*"]},
          {"host":"query.example.org:8443","routes":["GET /root","POST /v1/query"]}]}
```

- `host`: exactly what the wallet puts in `:authority` to reach that host through the gateway:
  a lower-case name, with `:port` only for a port other than 443. Compare whole values,
  case-insensitively; no suffix or wildcard matching.
- `routes`: what the gateway forwards to the host, `METHOD /path`: `*` as method means any;
  a path ending in `/*` is a prefix on a segment boundary (`/a/*` matches `/a` and `/a/b`, not
  `/ab`), any other path is exact (a query string may follow). Informational for a wallet: the
  gateway enforces them (inner `403 policy denied`).
- `scope`: `all`: the list is every third-party host this gateway carries; a host that is
  not in it is not carried. `dynamic`: the list holds only the hosts the gateway reads from
  published server lists; hosts the gateway carries by static configuration are not in it,
  so for those the compiled list stays in force. A gateway meant to replace the compiled list
  publishes `all`.
- `revision`: names this document (it changes when anything in it changes). `304` (no body)
  answers an `if-none-match` that carries it: keep the held list and restart its lifetime.
- `max_age_secs`: how long to use the list before asking again.
- `version`: `1`. Unknown top-level or per-host fields must be ignored; a document with another
  `version` must be treated as no list.

**No list.** A gateway that does not publish the list answers this request like any other
unknown lightwalletd path (an inner `403`, a gRPC error or a `404`, depending on its
configuration). A gateway that publishes it but has no complete list answers an inner `503`: until
every published server list it reads has been read once since the process started (one that
keeps failing keeps it at `503`), or if the document would exceed 256 KiB. Treat every answer that is not
a `200` with a parsable `version` 1 document (or a `304` for a held revision), any transport
error, and any body larger than 256 KiB (the gateway never sends a larger one) as "no list":
keep what is held, the bootstrap list if nothing was fetched yet.

**What a wallet should do.**

1. The allowed hosts are, at any moment:
   - before any list was fetched: the compiled (bootstrap) list;
   - while the list held has `scope` `all`: exactly the hosts of that list (a host it lacks
     is not carried by the gateway, whatever the compiled list says);
   - while the list held has `scope` `dynamic`, or a `scope` the wallet does not know: the
     hosts of that list plus the compiled list.

   "The list held" is the last one fetched successfully; it replaces the one before it as a
   whole, also when its `scope` differs. A gateway is expected to keep its `scope`.
2. Fetch the list through OHTTP, from the same relay and gateway pair that carries the
   third-party requests. Never fetch it directly.
3. Hold it in memory for `max_age_secs` (clamp to 30 s..24 h, the range a gateway can set).
   When it is older, refresh in the background (one fetch at a time) and keep using the held
   list meanwhile. After a failed refresh keep the held list and retry with backoff (for
   example 30 s, doubling to 5 min).
4. Allow a third-party request when its `host[:port]` is an allowed host by rule 1. Refuse
   everything else as before. Never send a refused request directly.
5. When choosing among the servers a service's own discovery document offers, drop the ones
   the gateway does not carry and use the rest; fail only when none is left. For a host that
   is not allowed by rule 1, one refresh (if the list is older than a few seconds) before
   refusing picks up a host that was added since.
6. Replicas of a gateway refresh independently, so for a short time one replica can list a host
   another does not serve yet. An inner `403` with the body `unknown authority` for a listed
   host means that: try another server of the service, and refresh the list (at most once per
   30 s for this reason).
7. The list is per gateway. A wallet that talks to more than one gateway (one per network)
   keeps one list per gateway.

The list tells a wallet where the gateway will forward. It does not authenticate the hosts:
which servers a wallet uses still comes from the service's own discovery and its checks.

The client crate implements these rules (`zodl-ohttp-client` from 2.1.0: `ThirdPartyHosts`,
`third_party_hosts_request`, `read_third_party_hosts`; `client/INTEGRATION.md`, section 5), so
a wallet built on it calls the crate instead of implementing them again.

## Metrics

All metrics are registered in `src/health.rs` and served on `:9090/metrics`. Request ids and
trace ids are never labels. `network` is `NETWORK`.

| Metric | Labels | Meaning |
|---|---|---|
| `ohttp_requests_total` | `status, mode, network, hop, method, http_status, grpc_status, backend, route_class` | Requests by outcome. |
| `ohttp_request_duration_seconds` | `network, hop, backend, rpc` | Request duration (histogram). |
| `ohttp_traced_request_duration_seconds` | `network, hop, backend, rpc` | The same histogram (same buckets), observed in addition for requests whose outer request carried a valid `X-Client-Trace-Id`, so it holds only synthetic checks, test tools and debug builds. Real-user latency is `ohttp_request_duration_seconds` minus this one, per bucket, aggregated to the same labels on both sides; a label set without traced traffic has no traced series, so in PromQL write `main - (traced or main * 0)`. Only answered requests are observed (refusals record no duration), and the split relies on relays forwarding `X-Client-Trace-Id`: synthetic traffic through a relay that strips it counts as real users. |
| `ohttp_requests_in_flight` | `network` | Requests in flight. |
| `ohttp_relay_requests_total` | `network, relay, edge` | Authenticated `POST /gateway` by relay name and edge location (below). |
| `ohttp_relay_request_id_total` | `network, state` | Relay correlation id `present`, `missing` or `invalid`. |
| `ohttp_decrypt_errors_total` | - | Requests that did not decapsulate. |
| `ohttp_encrypt_errors_total` | - | Registered for compatibility; no longer incremented. |
| `ohttp_policy_denied_total` | `alias` | Inner requests refused by `BACKENDS_POLICY`, or by the routes of a dynamic host (`alias` is then `dynamic:<source>`). |
| `ohttp_freshness_total` | `network, result` | Freshness verdicts: `fresh`, `missing`, `malformed`, `stale`. |
| `ohttp_chunks_sent_total` | `network, kind` | Sealed response chunks: `full`, `flush`, `final`. |
| `ohttp_response_truncated_total` | `network` | Upstream answers cut at `MAX_UPSTREAM_RESPONSE_BYTES`. |
| `ohttp_upstream_requests_total` | `network, backend, rpc, http_status, grpc_status` | Upstream requests. `rpc` is a known lightwalletd method name; for a third-party (`BACKENDS`) request the `BACKENDS_POLICY` entry that admitted it (`GET /v0/status`); else `other`. |
| `ohttp_upstream_request_duration_seconds` | `network, backend, rpc` | Upstream duration (histogram). |
| `ohttp_upstream_errors_total` | `network, backend, error_type` | Upstream errors. |
| `ohttp_upstream_calls_total` | `network, rpc` | Calls actually sent to lightwalletd, after caches and coalescing. |
| `ohttp_upstream_blocks_total` | `network` | Blocks fetched from lightwalletd for `GetBlockRange`. |
| `ohttp_singleflight_joins_total` | `network, rpc` | Calls that joined an identical call in flight. |
| `ohttp_lwd_errors_total` | - | lightwalletd forwarding errors. |
| `ohttp_lwd_connect_retries_total` | - | lightwalletd calls retried after a failed connection attempt. |
| `ohttp_lwd_read_retries_total` | `network, reason` | lightwalletd reads sent a second time because the first attempt failed before its response head. `reason`: `error` (transport error); `timeout` is no longer produced (see `ohttp_lwd_hedges_total`). |
| `ohttp_lwd_hedges_total` | `network, event` | Hedged lightwalletd reads: `started` (sent to another instance as well after `LWD_HEDGE_DELAY_MS` without a head), `won` (the hedge's head came first), `no_permit` (not hedged: `LWD_HEDGE_MAX_INFLIGHT` in flight), `rate_limited` (not hedged: six or more hedges in the last minute already, and one more would exceed one in ten of its hedgeable reads), `loser_skipped` (an instance lost its second or a later hedge in a row, with no response head from it in between, and is skipped for 30 s; not a lightwalletd failure), `loser_detached` (the attempt that lost the race runs to its end in a task of its own, its answer discarded), `loser_cancelled` (it was cancelled instead: `LWD_HEDGE_MAX_INFLIGHT` detached ones were running), `loser_expired` (a detached one was cut by its head deadline, or by the bound on reading its body: 10 s, 8 MiB). |
| `ohttp_lwd_unsent_retries_total` | `network, call` | Calls sent a second time, on a new connection, because the first connection ended before the request was written to it. `call`: `send` (`SendTransaction`), `other` (any other call that has no read retry). Reads of the gateway's own lightwalletd retried for that reason count in `ohttp_lwd_read_retries_total`. |
| `ohttp_lwd_mempool_no_head_total` | `network` | `GetMempoolStream` calls without a response head within their deadline, ended cleanly (an empty mempool, or an instance that does not answer). |
| `ohttp_healthz_lwd_error_ratio` | `network` | Share of failed lightwalletd calls in the `/healthz` error window at the last `/healthz`; `-1` while fewer than `HEALTHZ_LWD_MIN_ERRORS` failed. |
| `ohttp_lwd_reachable` | `network` | 1 while lightwalletd is reachable. |
| `ohttp_lwd_shed_total` | `network, class` | lightwalletd calls refused because their class was at its cap. |
| `ohttp_lwd_timeouts_total` | `network, class, phase` | lightwalletd call attempts cut by their deadline (the attempt that lost a hedged read is not counted, also when its deadline cuts it after the race: `ohttp_lwd_hedges_total{event="loser_expired"}`). `class`: `unary`, `stream`, `send` (`SendTransaction`); `phase`: `head` (no response head in time), `body` (the call's overall deadline: the unary deadline, or `LWD_TIMEOUT_SECS` for a stream), `gap` (a stream silent too long). |
| `ohttp_lwd_pool_resets_total` | `network` | Pooled lightwalletd clients replaced after a call ran into its deadline (`LWD_CONNECTION_POOL`). |
| `ohttp_lwd_permit_waited_total` | `network, class` | Calls that waited for a permit. |
| `ohttp_lwd_permit_wait_seconds` | `network, class` | Permit wait time (histogram). |
| `ohttp_third_party_cache_total` | `network, authority, result` | Third-party cache `hit` / `miss`. |
| `ohttp_third_party_limited_total` | `network, authority` | Third-party calls refused by `THIRD_PARTY_RATE_LIMITS`, or by the `rate_limit` of a dynamic host source (then `authority` is `dynamic:<source>`). |
| `ohttp_query_value_source_refresh_total` | `network, source, result` | Refreshes of a `THIRD_PARTY_QUERY_VALUE_SOURCES` source: `ok`, `transport`, `status`, `oversize`, `json`, `pointer`, `empty`, `too_many`, `too_few`. After any result but `ok` the current list stays. |
| `ohttp_query_value_source_values` | `network, source` | Values in the current list of a source (its fallback before the first accepted refresh; 0 = `{from:}` admits nothing). |
| `ohttp_query_value_source_last_success_timestamp_seconds` | `network, source` | Unix time of the last accepted refresh of a source; 0 until the first one. |
| `ohttp_query_value_source_skipped_total` | `network, source` | Items a source's pointer selected that were not valid values (missing, not a string, outside `[A-Za-z0-9._~-]` or longer than 64). |
| `ohttp_dynamic_hosts` | `network, source` | Third-party hosts served from a dynamic host source (`DYNAMIC_HOST_SOURCES`). |
| `ohttp_dynamic_hosts_refresh_total` | `network, source, result` | Refreshes of a source: `ok`, `unchanged`, `partial` (new hosts held by `max_new_hosts_per_refresh`), `fetch_error`, `too_large`, `parse_error`, `invalid`, `empty`, `signature`. After any result but the first three the last accepted hosts stay served. |
| `ohttp_dynamic_hosts_last_success_timestamp_seconds` | `network, source` | Unix time of the last refresh whose document was accepted. |
| `ohttp_dynamic_hosts_held` | `network, source` | New hosts of the current document not admitted yet. |
| `ohttp_dynamic_hosts_rejected` | `network, source` | Entries of the last accepted document refused by validation. |
| `ohttp_dynamic_hosts_shadowed` | `network, source` | Listed hosts that the static configuration (`BACKENDS` aliases and targets, `GATEWAY_HOSTS`, `LWD_ADDR`) or an earlier source keeps. |
| `ohttp_redis_connected` | `network` | 1 while both the cache and the security Redis are connected. |
| `ohttp_cache_redis_connected` | `network` | Cache Redis connection. |
| `ohttp_security_redis_connected` | `network` | Security Redis PING (0 also when not configured). |
| `ohttp_redis_op_timeout_total` | `network, operation` | Redis operation timeouts. |
| `ohttp_cache_requests_total` | `network, rpc, result` | Cache lookups by result. Also counts answers not stored: `not_positioned`, `not_indexed`. The pinned backfill and sweep count under `rpc="GetTreeState"` (see `PINNED_BACKFILL_WORKERS` in CONFIG.md), among them `pinned_fetch_detached`: a sweep fill was abandoned while one of its upstream calls was in flight (the call runs to its end, its answer unused). |
| `ohttp_cache_tip_mismatch_total` | `network, rpc, phase` | Tip-scoped answers not at the tip of their key: `store` (not cached), `lookup` (a stored entry deleted and fetched again; the request counts as a miss above). |
| `ohttp_cache_tip_height` | `network` | Tip height known to the cache. |
| `ohttp_local_cache_total` | `network, result` | In-process LRU `hit`, `miss`, `oversized`. |
| `ohttp_block_cache_hits_total`, `ohttp_block_cache_misses_total` | `network` | Per-block cache lookups for `GetBlockRange`. |
| `ohttp_block_cache_stale_total` | `network` | Cached blocks dropped because their hash no longer matched the index. |
| `ohttp_block_cache_unvalidated_total` | `network` | Cached blocks inside the index window without an index entry (not served). |
| `ohttp_block_cache_continuity_mismatch_total` | `network` | Cached blocks dropped because they did not chain to their neighbour. |
| `ohttp_permanent_store_connected` | `network` | Permanent tier PING. |
| `ohttp_permanent_store_replica` | `network` | 1 while the permanent tier store is a read-only replica (`INFO replication`, or a write refused with `READONLY`): its writes are skipped and final blocks stay in the cache tier. |
| `ohttp_permanent_writes_skipped_total` | `network, op` | Permanent tier writes not sent to a replica. |
| `ohttp_block_permanent_total` | `network, result` | Permanent tier `hit`, `miss`, `stored`, `promoted`, `backfilled`. |
| `ohttp_chain_leader` | `network` | 1 while this process leads the chain follower. |
| `ohttp_chain_tip_age_seconds` | `network` | Seconds since the leader last moved the stored tip, as this process sees it (`-1`: unknown); on a follower at least as long as it has read the same stored record (its own clock), so a `tip_at` ahead of its clock does not read as a fresh tip for longer than that. |
| `ohttp_chain_tip_at_rewrites_total` | `network` | Times this process, as leader, replaced a stored `tip_at` more than 2 s ahead of its clock by the tip's time on its clock, with a confirmation (a tip it took over, or its own after its clock stepped back). |
| `ohttp_chain_tip_stamp_lost_total` | `network` | Stored tip records whose `{chain}tip_stamp` key was gone on a read while the tip and `tip_at` it had vouched for were still stored (counted when the loss is first read); the earlier verdict is kept. |
| `ohttp_chain_tip_time_ahead_seconds` | `network` | How far the stored `tip_at` was ahead of this process's clock at its last read as a follower or at a takeover (`0`: not ahead, or no `tip_at`): a discrepancy between the stored time and this clock (a writer clock ahead, this clock behind, or a clock step). |
| `ohttp_chain_stale_leader_total` | `network, action` | Times this process found the stored tip unmoved past `CHAIN_TIP_STALE_SECS` with its own lightwalletd ahead: `local_tip` (served its own tip), `takeover` (took the leader lock). |
| `ohttp_chain_reorgs_total` | `network` | Reorgs detected. |
| `ohttp_chain_reorg_depth` | - | Blocks invalidated per reorg (histogram). |
| `ohttp_mempool_subscribers` | `network` | Clients subscribed to the mempool fan-out. |
| `ohttp_mempool_upstream_streams_total` | `network, reason` | Upstream `GetMempoolStream` sessions ended, by reason. |
| `ohttp_replay_rejected_total` | `network` | Requests refused as replays. |
| `ohttp_replay_write_wait_total` | `network, result` | WRITE nonces checked for replica acknowledgement (`REPLAY_WRITE_WAIT_REPLICAS`). |
| `ohttp_replay_write_wait_seconds` | `network` | Time to that acknowledgement (histogram). |
| `ohttp_write_stage_duration_seconds` | `network, stage, result` | Time of each stage of a WRITE (histogram, 0.5 ms to 10 s). `stage`: `local` (local `SET NX`; `new`, `unavailable`), `hub` (an `async-reads` origin's hub `SET NX` with its pipelined `WAIT`; `acknowledged`, `short`, `failed`, `fresh`, `replay`, `unavailable`), `standby` (its concurrent standby `SET NX`; `fresh`, `replay`, `unavailable`), `replica_wait` (the local replica wait; `acknowledged`, `failed`), `upstream_lwd` (the lightwalletd call of a WRITE such as `SendTransaction`; `ok`, `error`), `upstream_third_party` (the upstream call of a third-party WRITE until its response head, not cache hits or the cap's 429; `ok`, `error`), `forward` (a forwarded WRITE until the head of the answer; `answered`, `replay`, `declined`, `failed`). Stages overlap (`hub` and `standby` run concurrently; `forward` spans the receiving gateway's own stages) and do not cover everything (decryption, a fallback confirmation after a short hub acknowledgement): read them one by one, do not sum them. |
| `ohttp_replay_hub_check_total` | `network, path` | WRITE nonce checks at a hub peer with a replica acknowledgement: `pipelined` (`SET NX` and `WAIT` in one round trip) or `main` (`SET NX` on the main connection, then the acknowledgement: no idle `WAIT` connection at that moment, or `REPLAY_WAIT_CONNS=1`). |
| `ohttp_write_forward_total` | `network, result` | WRITEs a read origin forwarded (`REPLAY_WRITE_FORWARD_URL`): `answered` (the sealed answer streamed back), `replay` (the hub store held the nonce), `connect` / `declined` / `declined_once` / `skipped` (not run by the receiving gateway: decided at the read origin as without forwarding; `skipped` = within `REPLAY_WRITE_FORWARD_BACKOFF_MS` after a lasting reason, an `unclear` answer or three `declined_once` in a row), `timeout` / `transport` / `unclear` (failed closed: sent without an answer, or the receiving gateway's store gave no verdict after the nonce may have been stored). Each forwarded WRITE also counts at the read origin in `ohttp_requests_total{status="forwarded"}`, with the client's `ohttp_request_duration_seconds`, and at the receiving gateway with `mode="forwarded"`, without a request duration. `ohttp_replay_rejected_total`: an outer 409 of the receiving gateway is counted by the read origin, a replay answered in the sealed answer by the receiving gateway. |
| `ohttp_replay_write_fallback_total` | `network, path, result` | WRITE nonces decided at a second store. `path`: `short_ack` (the local acknowledgement was short), `local_unavailable` (the local store gave no verdict, `REPLAY_UNAVAILABLE_FALLBACK`), `hub_short_ack` / `hub_unavailable` (the same for the hub of an `async-reads` origin), `check` / `window` (`failover` mode: the check of every WRITE at the peers, `window` within one nonce TTL after startup or a local store failover), `hub_check` / `hub_window` (the same at the standby stores of an `async-reads` origin), `peer_tolerated` (a peer that gave no verdict was tolerated: `REPLAY_PEER_FAIL_CLOSED=0` in `sync` mode, `REPLAY_PEER_FAIL_CLOSED_WRITES=0`). `result`: `accepted`, `replay`, `unavailable`, `unacknowledged`, `overflow`, `one_sided_refused` (only one store took the nonce and the route is not on `REPLAY_ONE_SIDED_WRITE_ROUTES`: fail-closed). |
| `ohttp_replay_read_fallback_total` | `network, result` | READ nonces decided at the peers (the hub, for an `async-reads` origin) because the local store gave no verdict (`REPLAY_UNAVAILABLE_FALLBACK`). |
| `ohttp_replay_fallback_check` | `network` | 1 when every WRITE this gateway admits is also checked at a fallback store synchronously; `REPLAY_UNAVAILABLE_FALLBACK` is safe only while every gateway with peers reports 1. |
| `ohttp_replay_serving_via_fallback` | `network` | 1 while the security Redis does not answer and this gateway keeps serving (`/healthz` healthy) because the peer stores decide its requests: `REPLAY_UNAVAILABLE_FALLBACK` with `ohttp_replay_local_fallback` 1, the check of every WRITE on, and every peer answering its last housekeeping PING (every 10 s). 0 when the security Redis answers, or when nothing can decide (then `/healthz` fails). WRITEs beyond the write-back capacity still fail closed (`ohttp_replay_write_fallback_total{result="overflow"}`). |
| `ohttp_replay_local_fallback` | `network` | 1 when a request the security Redis gives no verdict on is decided at the peer stores instead of failing closed (`REPLAY_UNAVAILABLE_FALLBACK`): `failover` mode, or `async-reads` without standby stores and with `REPLAY_WRITE_WAIT_REPLICAS` (the own store is the fallback store; the hub decides). |
| `ohttp_replay_unavailable_fallback` | `network, target` | 1 for the store the unavailable fallback replaces on this gateway (`local`, `standby`, `local_replicas`); all 0 when off, and on an `async-reads` origin with `REPLAY_PEER_FAIL_CLOSED_WRITES=0`, where only its own store is replaced (`ohttp_replay_local_fallback`). |
| `ohttp_replay_write_back_total` | `network, result` | Nonces admitted through the peers rewritten to the local store: `written` (acknowledged by its replicas) or `expired`. |
| `ohttp_replay_write_back_pending` | `network` | Such nonces still waiting for the local replicas. |
| `ohttp_replay_fallback_writes_failing` | `network` | 1 while the last `REPLAY_FALLBACK_HEALTH_FAILURES` WRITEs decided at the peer stores for an unreachable security Redis all failed closed; `/healthz` then no longer stays 200 through the fallback. |
| `ohttp_replay_wait_saturated_total` | `network, store` | WRITE nonces whose replica wait found every dedicated `WAIT` connection of the store (`local`, or a `peer`) busy for the whole wait budget (`REPLAY_WAIT_CONNS`); decided as a short acknowledgement once a `SET XX` found the nonce. Rises while the store's replicas resync. |
| `ohttp_key_config_info` | `network, fingerprint, signing_key_id` | Always 1: first 16 hex of SHA-256 of `/ohttp-configs` and the signing key id. |
| `ohttp_origin_info` | `network, origin` | Always 1: `ORIGIN_ID`. |
| `ohttp_replay_peers_configured` | `network` | Number of `REPLAY_PEER_URLS`. |
| `ohttp_replay_standby_stores_configured` | `network` | Number of `REPLAY_STANDBY_URLS`. Their per-peer series use `peer` labels after the `REPLAY_PEER_URLS` ones (one peer: the first standby store is `peer="1"`). |
| `ohttp_replay_peer_connected` | `network, peer` | Peer store PING, per peer index. |
| `ohttp_replay_standby_connected` | `network, peer` | Standby store (`REPLAY_STANDBY_URLS`) PING; separate from `ohttp_replay_peer_connected`, which only covers the peers. |
| `ohttp_replay_peer_total` | `network, peer, result` | Nonce writes to peers: `fresh`, `replay`, `replay_async`, `error`, `timeout`, `disconnected`. |
| `ohttp_replay_peer_consecutive_failures` | `network, peer` | Failures since the last success. |
| `ohttp_replay_class_total` | `network, class` | Inner requests classified `read` / `write` (only with peers). |
| `ohttp_replay_mode_effective` | `network, mode` | 1 for the mode in effect: `sync`, `async-reads`, `async-reads-strict`, `failover`. |
| `ohttp_replay_mode_switches_total` | `network, to, reason` | Switches between background and synchronous READ replication. |
| `ohttp_replay_replication_lag_seconds` | `network, peer` | Background replication lag (histogram). |
| `ohttp_replay_replication_healthy` | `network, peer` | 1 while background replication to the peer is healthy. |
| `ohttp_replay_async_queue_depth` | `network, peer` | Nonces waiting for background replication. |
| `ohttp_replay_async_dropped_total` | `network, peer, reason` | Nonces not replicated: `overflow`, `expired`. |
| `ohttp_replay_local_aof_total` | `network, result` | WRITE nonces checked for a local AOF fsync (`REPLAY_LOCAL_WAITAOF_MS`). |
| `ohttp_replay_local_aof_seconds` | `network` | Time to that fsync (histogram). |

`edge` in `ohttp_relay_requests_total` is a three-letter edge location code taken from an edge
request-id header when the relay's network adds one, else `-`; it names a part of the relay's
network, never a client.

## License

AGPL-3.0-only with commercial licensing available; see the repository's
[LICENSE](../LICENSE), [LICENSE-EXCEPTIONS.md](../LICENSE-EXCEPTIONS.md) and
[COMMERCIAL-LICENSE.md](../COMMERCIAL-LICENSE.md).

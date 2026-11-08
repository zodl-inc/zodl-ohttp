# Gateway configuration

Every setting of the gateway is an environment variable, read once at startup. Defaults are
the values in the code; "unset" means the variable is absent or empty unless a row says
otherwise. A malformed value is a startup error unless a row says it falls back to the default.

## Mode, network, listener

| Variable | Default | Meaning |
|---|---|---|
| `GATEWAY_MODE` | `ohttp` | `ohttp`: only Encapsulated Requests on `POST /gateway`; any other path or method answers 426. `proxy`: additionally a plaintext gRPC passthrough to lightwalletd on every other path (testing only, no privacy). |
| `NETWORK` | `mainnet` | `mainnet` or `testnet`: the network label of logs and metrics, the `network` the signed key configuration is bound to, and the Sapling activation height used by the permanent tier. If unset and `GATEWAY_MODE` is `mainnet` or `testnet`, that value is used. |
| `PORT` | `8080` | Public listener (`/gateway`, `/ohttp-configs`, `/ohttp-configs/signed`, `/healthz`, `/health/startup`). The observability listener is set by `INTERNAL_BIND_ADDR`. |
| `INTERNAL_BIND_ADDR` | `0.0.0.0:9090` | Bind address of the internal observability listener (`/health`, `/health/live`, `/health/ready`, `/metrics`): an IP address (port 9090) or `IP:port` (`[v6]:port` for IPv6). The default listens on all interfaces so that Prometheus on other hosts can scrape it. The internal port serves metrics and health and has no authentication: it should not be reachable from untrusted networks (restrict it by firewall or security group, or bind it to a private or loopback address). An unparsable value stops the gateway at startup. |
| `HEADER_READ_TIMEOUT_SECS` | `300` | Request header read timeout of both listeners (HTTP/1.1 only). Also bounds how long a keep-alive connection may sit idle, so it must exceed the idle timeout of every proxy that reuses connections to the gateway; values from 1 to 130 are refused, `0` disables it. |
| `RUST_LOG` | `info` | `tracing` filter for the JSON logs (`trace`, `debug`, `info`, `warn`, `error`, or per-module directives). |
| `LOG_OUTER_HEADER_NAMES` | `false` | `1`/`true`: log the names (never the values) of the outer headers each request arrives with. A privacy audit aid. |

## Relay authentication

| Variable | Default | Meaning |
|---|---|---|
| `RELAY_SECRET` | unset | Comma-separated list of accepted `X-Relay-Secret` values. An entry is `name=secret` (`name`: 1 to 32 characters of `a-z0-9-`, used as the `relay` label of metrics and logs) or a bare secret, named `relay-<position>`. A remainder of `=` only is base64 padding, not a name. Duplicate names or duplicate secrets are a startup error. Required in `ohttp` mode unless `ALLOW_UNAUTHENTICATED_RELAY` is set. Presented secrets are compared as SHA-256 digests against every entry in constant time. |
| `RELAY_SECRETS` | unset | Same as `RELAY_SECRET`, same grammar. Setting both is a startup error. |
| `ALLOW_UNAUTHENTICATED_RELAY` | `false` | `1`/`true`: run `ohttp` mode without relay secrets. Insecure: only for local tests, or behind an edge that admits authorised relays alone. Logged as a warning. |
| `RELAY_SECRET_ON_KEY_CONFIG` | `off` | `require`: `GET /ohttp-configs` and `GET /ohttp-configs/signed` also need exactly one valid `X-Relay-Secret` (otherwise 401), so the key configuration can only be fetched through a relay. Needs relay secrets. Before switching it on, check that every relay forwards the header on these GETs. |

## Keys

| Variable | Default | Meaning |
|---|---|---|
| `HPKE_KEYS` | unset | Advertised HPKE keys, `<key_id>:<hex X25519 private key>,...`, preferred first. Takes precedence over `HPKE_PRIVATE_KEY`. |
| `HPKE_PRIVATE_KEY` | unset | A single advertised key (hex X25519 private key, 32 bytes), with id `HPKE_KEY_ID`; ignored when `HPKE_KEYS` is set. In `ohttp` mode one of `HPKE_KEYS` or `HPKE_PRIVATE_KEY` is required: the gateway never generates a key and refuses to start without one. In `proxy` mode no key is loaded and the key-configuration endpoints answer 503. |
| `HPKE_KEY_ID` | `1` | Key id (0 to 255) of `HPKE_PRIVATE_KEY`. |
| `HPKE_ACCEPT_ONLY_KEYS` | unset | Keys accepted for decapsulation but not published, same format as `HPKE_KEYS`. Used during a rotation. Key ids must be distinct across both lists. |
| `CONFIGS_SIGNING_SEED_HEX` | unset | Ed25519 seed (64 hex characters) that signs `/ohttp-configs/signed`. Unset: that endpoint answers 503. An invalid seed is a startup error in `ohttp` mode. |

## Routing and backends

| Variable | Default | Meaning |
|---|---|---|
| `LWD_ADDR` | `localhost:9067` | lightwalletd gRPC address (`host:port`, plaintext HTTP/2). |
| `GATEWAY_HOSTS` | unset | The gateway's own host names (comma-separated, lower-cased, port stripped). An inner request whose `:authority` is one of them goes to lightwalletd. Unset: every authority that is not a `BACKENDS` alias goes to lightwalletd (permissive, warned at startup). An empty `:authority` is always refused. |
| `BACKENDS` | unset | Third-party aliases, `alias=https://base-url,...`. An inner request whose `:authority` equals an alias (case-insensitive) is sent to that base URL. `lwd` is reserved. `http://` is accepted for tests. |
| `BACKEND_HEADERS` | unset | Headers set on requests to an alias, `alias=Header-Name:value,...` (e.g. an API key). Of the client's inner headers only `content-type`, `grpc-timeout`, `grpc-encoding` and `grpc-accept-encoding` are forwarded and, for `FLEXA_ALIAS` only, the headers listed under `FLEXA_PUBLISHABLE_KEY` and `Authorization`; client cookies never reach a backend. |
| `BACKENDS_POLICY` | unset | Allowed operations per authority, `alias=METHOD /path,METHOD /prefix/*;alias2=...` (`*` method = any; `/*` suffix = prefix match on a segment boundary). A request to an alias without an entry is refused with inner 403 unless `BACKENDS_POLICY_DEFAULT=allow`. An entry for a `GATEWAY_HOSTS` host restricts the lightwalletd routes too. An entry for any other authority is never applied (warned). |
| `BACKENDS_POLICY_DEFAULT` | deny | `allow`: aliases without a `BACKENDS_POLICY` entry accept every operation. Insecure. |
| `PROXY_ALLOW_SUFFIXES` | unset | Parsed into the configuration (comma-separated domain suffixes, lower-cased) but not used for routing: only exact `BACKENDS` aliases and `GATEWAY_HOSTS` are ever forwarded. Kept for configuration compatibility; setting it has no effect. |
| `FLEXA_ALIAS` | unset | The `BACKENDS` alias whose upstream is the Flexa API. Requests to it get the Flexa header handling (see `FLEXA_PUBLISHABLE_KEY`), a `text/event-stream` answer is streamed, and its answers are never cached. Unset: no alias gets this handling. |
| `FLEXA_PUBLISHABLE_KEY` | unset | Publishable key for `FLEXA_ALIAS`. It replaces only the apps' placeholder credential (`Authorization: Basic` of `:publishable_live_zodl_gateway_placeholder`); any other `Authorization` value passes through. That alias also forwards `accept`, `flexa-app`, `flexa-version`, `client-trace-id` and `last-event-id`. |
| `NEAR_ALIAS` | unset | The `BACKENDS` alias of the NEAR Intents 1Click API. Only its public `GET /v0/tokens` may appear in `THIRD_PARTY_CACHE_ROUTES` (startup error otherwise). |
| `THIRD_PARTY_CACHE_ROUTES` | unset | Cached third-party routes, `alias=METHOD /path@TTL_SECS,...;alias2=...`. Only `GET` answers with status 200 are stored; concurrent misses for one key are coalesced. Never for `FLEXA_ALIAS`. Needs the cache Redis. |
| `THIRD_PARTY_RATE_LIMITS` | unset | Per-alias cap on upstream calls (cache hits do not count), `alias=REQUESTS/WINDOWs,...` (e.g. `prices.example=120/60s`). Over the cap the inner answer is 429 with `retry-after`. Fixed window, per process. |
| `CACHE_KEY_BACKEND` | `LWD_ADDR` | Backend name written into cache keys. For an instance that fills the cache from a different lightwalletd address than the serving gateways use. |

## Limits and timeouts

| Variable | Default | Meaning |
|---|---|---|
| `MAX_INFLIGHT_REQUESTS` | `1024` | OHTTP requests in flight per process, counted from after relay authentication and the content-type check until the response body ends. Above it: outer 503 with `Retry-After: 1`. Must be a positive integer. |
| `MAX_UPSTREAM_RESPONSE_BYTES` | `67108864` (64 MiB) | Largest upstream response body; a larger one is cut and answered with an error. Clients accept at most 256 MiB, so keep it at or below that. |
| `MAX_INFLIGHT_UPSTREAM` | `256` | Upstream calls in flight per process, all backends together. |
| `MAX_INFLIGHT_PER_BACKEND` | `64` | Upstream calls in flight per backend alias. |
| `MAX_INFLIGHT_LWD` | `128` | lightwalletd calls in flight per process. |
| `MAX_INFLIGHT_LWD_HEAVY` | `MAX_INFLIGHT_LWD / 4` (at least 1) | Of those, "heavy" calls at once: long `GetBlockRange`, `GetTransaction`, transparent-address and subtree queries. The rest stay free for `SendTransaction`, `GetLatestBlock`, `GetTreeState` and short ranges. |
| `LWD_HEAVY_BLOCK_RANGE` | `100` | `GetBlockRange` spans above this many blocks count as heavy. |
| `LWD_PERMIT_WAIT_MS` | `2000` | How long a lightwalletd call waits for a permit before it is refused with `UNAVAILABLE`; `0` refuses at once. A waiting call holds no permit. |
| `LWD_PERMIT_MAX_WAITERS` | `0` | Calls allowed to wait per class (heavy, general); beyond it they are refused at once. `0` means 4 times the permit count of each class. |
| `MAX_BLOCK_RANGE` | `10000` | Largest `GetBlockRange` span; larger spans get grpc-status 3. |
| `LWD_TIMEOUT_SECS` | `80` | Total time (head and body) for one upstream call, lightwalletd or third party. |
| `LWD_UNARY_TIMEOUT_SECS` | `10` | Total time of a lightwalletd RPC with one answer (`GetLatestBlock`, `GetTreeState`, `GetTransaction`, `SendTransaction`, ...), at most `LWD_TIMEOUT_SECS`. A lightwalletd that accepts the connection but does not answer costs a call this long, so the client's retry can reach another instance. A `SendTransaction` cut by it may still be broadcast by that lightwalletd; the client's retry is a new request, and the node refuses a transaction it already has. |
| `LWD_STREAM_IDLE_SECS` | `20` | For a server-streaming lightwalletd RPC (`GetBlockRange`, `GetSubtreeRoots`, ...): the longest wait for the response head and for each next frame. A stream that keeps sending runs up to `LWD_TIMEOUT_SECS`. `GetMempoolStream` keeps the long-poll settings below. The transparent-address RPCs (`GetTaddressBalance*`, `GetTaddressTxids`, `GetAddressUtxos*`) keep `LWD_TIMEOUT_SECS` for their first answer, which waits for an address query of the node; their streams get this bound between frames. |
| `LWD_CONNECTION_POOL` | `false` | `1`/`true`/`on`: reuse pooled HTTP/2 connections to lightwalletd (idle 60 s, keep-alive PINGs every 20 s, closed when a PING is not answered within 5 s), saving a handshake per call. A call that runs into one of the deadlines above replaces the pool, so new calls open new connections. Default: a new connection per call, so a call never lands on a lightwalletd instance that has been taken out of service. |
| `LONG_POLL_MAX_INITIAL_SILENCE_SECS` | `25` | `GetMempoolStream`: the stream ends cleanly (grpc-status 0) if no message arrives within this time. Values above 25 are clamped to 25. |
| `LONG_POLL_IDLE_SECS` | `3` | `GetMempoolStream`: the stream ends cleanly after this much silence following a message. Clamped to 25. |
| `SSE_KEEPALIVE_SECS` | `20` | For a `text/event-stream` answer, a `: keep-alive` comment is sent after this much upstream silence. `0` falls back to 20; values above 25 are clamped to 25. |
| `MAX_CACHE_GET_CONCURRENCY` | `64` | Cache lookups in flight; beyond it a request bypasses the cache. |
| `MAX_LARGE_RESPONSE_CONCURRENCY` | `1` | Buffered upstream responses above `LARGE_RESPONSE_THRESHOLD` that may be held at once; when exhausted, the response still proceeds and a warning is logged. |
| `LARGE_RESPONSE_THRESHOLD` | `8388608` (8 MiB) | Size above which a buffered response counts as large. |
| `REDIS_OP_TIMEOUT_MS` | `250` | Timeout of one cache or security Redis operation. |

The Encapsulated Request body is limited to 10 MiB (outer 413 above it) and must arrive within
30 s of the read starting (outer 400 otherwise). Neither is configurable.

## Responses

| Variable | Default | Meaning |
|---|---|---|
| `CHUNK_SIZE` | `16384` | Size of every non-final chunk of a chunked OHTTP response, in bytes; 1024 to 65536 (the client refuses response chunks above 64 KiB), anything else refuses to start. |
| `CHUNK_FLUSH_MS` | `50` | When upstream data stalls for this long, the bytes collected so far are sent as a short chunk. |
| `RESPONSE_PADDING` | `on` | `on`: the final chunk is zero-padded to `CHUNK_SIZE`, so response sizes are rounded up to whole chunks. `sensitive`: `GetLatestBlock`, `GetLightdInfo` and `SendTransaction` answers are left unpadded, every other answer is padded. `off`: no padding. |

## Replay protection and freshness

| Variable | Default | Meaning |
|---|---|---|
| `REDIS_SECURITY_URL` | unset | Redis (`redis://` or `rediss://`) for replay nonces and the cache epoch; must use `maxmemory-policy noeviction`. Required in `ohttp` mode together with `REDIS_URL`. While it is unreachable at startup the gateway retries every 5 s before listening. |
| `REPLAY_FRESHNESS` | `observe` | Inner `ohttp-freshness` timestamp check. `off`: ignored. `observe`: missing or stale timestamps are counted (`ohttp_freshness_total`) but served. `enforce`: refused with inner 400 carrying `ohttp-freshness: rejected`. |
| `REPLAY_FRESHNESS_WINDOW_SECS` | `300` | Accepted distance from the gateway clock, either direction. At most half the nonce TTL (600 s). |
| `REPLAY_WRITE_WAIT_REPLICAS` | `0` | When above 0, a WRITE request (anything not on `REPLAY_READ_ROUTES`) runs only after its nonce is acknowledged by this many replicas of the security Redis (`WAIT` on a dedicated connection); otherwise it is refused with inner 503 (grpc-status 14 for lightwalletd calls). For a replicated store with automatic failover. |
| `REPLAY_WRITE_WAIT_MS` | `100` | `WAIT` timeout for `REPLAY_WRITE_WAIT_REPLICAS`. After a failover of the store, WRITEs are admitted again once the promoted primary has this many replicas: with one replica in total, that is when the old primary has rejoined as a replica. With `REPLAY_PEER_URLS` and `REPLAY_PEER_WAIT_REPLICAS` >= 1, a WRITE whose nonce is new on the local primary but short of acknowledgements is confirmed at the peer stores instead (new there and acknowledged by their replicas; held there = replay; otherwise fail-closed) and written back locally later; see `docs/architecture.md`. |

## Multiple origins

All of these are inert unless `REPLAY_PEER_URLS` is set (except `ORIGIN_ID`, which is a label
only, and `REPLAY_STANDBY_URLS`). See `docs/architecture.md`, "Multiple origins".

| Variable | Default | Meaning |
|---|---|---|
| `ORIGIN_ID` | `-` | Label of this origin, at most 32 characters of `[A-Za-z0-9._-]`. Log field `origin` and metric `ohttp_origin_info`; never sent to clients. |
| `REPLAY_PEER_URLS` | unset | The other origins' security Redis, comma-separated `redis://` / `rediss://` URLs, no duplicates. A nonce that any store already holds is a replay. |
| `REPLAY_PEER_TIMEOUT_MS` | `150` | Budget for the concurrent peer round trips of one request. |
| `REPLAY_PEER_FAIL_CLOSED` | `false` | `1`/`true`: a peer error or timeout refuses the request like a local security Redis failure. Default: the local verdict stands and the failure is counted. |
| `REPLAY_PEER_MODE` | `sync` | `sync`: every nonce is written to every peer before the request runs. `async-reads`: READ requests are checked locally and their nonces replicated to the peers in the background; WRITEs stay synchronous. `failover`: every request is checked locally and every nonce replicated in the background (active/passive pair). |
| `REPLAY_PEER_FAIL_CLOSED_WRITES` | `true` | In `async-reads`: whether an unreachable peer refuses a WRITE. `0`/`false`: a WRITE runs on the local check alone while the peers are unreachable; the nonce is then replicated to those peers in the background once they are reachable again (until the nonce TTL). |
| `REPLAY_STANDBY_URLS` | unset | The security Redis of each standby origin (one that runs WRITEs on its own store while the peers' store is unreachable), comma-separated `redis://` / `rediss://` URLs, none of them also in `REPLAY_PEER_URLS`. Every WRITE that passed the replay checks is also replicated there in the background (queue per store, retried until the nonce TTL). The hand-off never delays or refuses a request; with `REPLAY_PEER_WAIT_REPLICAS` >= 1 the stores also confirm `async-reads` WRITEs synchronously while the peers' store cannot acknowledge, and for one nonce TTL after startup or a disruption of it (a nonce held there is a replay; see `docs/architecture.md`). Set it on every origin whose WRITE check goes to a store the standby does not receive from (for example a read origin in `async-reads` checking WRITEs at the primary origin's store). |
| `REPLAY_READ_ROUTES` | every read-only lightwalletd RPC | READ allowlist for `async-reads`, in `BACKENDS_POLICY` syntax; the pseudo-authority `lwd` stands for the gateway's own lightwalletd. Anything not listed is a WRITE. The default lists no third-party route; a value replaces the default entirely, so include the `lwd=` entry. |
| `REPLAY_ASYNC_MAX_LAG_MS` | `500` | Background replication counts as degraded when its lag exceeds this; READs then use the synchronous path. |
| `REPLAY_ASYNC_RECOVERY_SECS` | `30` | How long replication must be healthy again before READs return to the background path. |
| `REPLAY_ASYNC_FAILURES_BEFORE_STRICT` | `3` | Consecutive peer failures that degrade background replication. |
| `REPLAY_PEER_WAIT_REPLICAS` | `1` | A WRITE nonce stored synchronously at a peer must reach this many replicas of that peer's store (`WAIT`) before the request runs; `0` turns it off (a peer store without replicas). |
| `REPLAY_PEER_WAIT_MS` | `100` | `WAIT` timeout at the peer; a failed attempt is retried once. Both settings also apply to the standby stores (`REPLAY_STANDBY_URLS`) when the hub fallback confirms a WRITE there. |
| `REPLAY_UNAVAILABLE_FALLBACK` | `false` | `1`/`true`: when the store that decides a request gives no verdict at all (unreachable, a timeout, an error), the request is decided at the fallback store instead of failing closed. `failover` mode (the local store is the deciding one): READs by `SET NX` at the peers, WRITEs by `SET NX` + the peers' `WAIT`. `async-reads` with `REPLAY_PEER_FAIL_CLOSED_WRITES` on (the hub is the deciding one): WRITEs confirmed at the standby stores (`SET NX` + `WAIT`), or by the local replicas when the origin has `REPLAY_WRITE_WAIT_REPLICAS`. A nonce held there is a replay, anything else fails closed, and a WRITE nonce is written back to the deciding store (READ nonces are not: a replayed READ changes nothing). Turn it on only once every origin that checks at the same stores reports `ohttp_replay_fallback_check` 1, i.e. runs a version that checks every WRITE at the fallback store and has the settings for it (`failover`: `REPLAY_WRITE_WAIT_REPLICAS` and `REPLAY_PEER_WAIT_REPLICAS` >= 1; `async-reads`: standby stores with `REPLAY_PEER_WAIT_REPLICAS` >= 1, or its own replica wait); see `docs/architecture.md`. Gauge `ohttp_replay_unavailable_fallback`. In `failover` mode it also changes `/healthz`: while the local store does not answer but every peer answered its last housekeeping PING (every 10 s), `/healthz` stays 200 (`ohttp_replay_serving_via_fallback` 1), so a load balancer keeps the origin; it fails when no store can decide. |
| `REPLAY_LOCAL_WAITAOF_MS` | auto (`2000`) | Only in `async-reads` with `REPLAY_PEER_FAIL_CLOSED_WRITES=0`: a WRITE whose nonce no peer took runs only after the local security Redis has fsynced it (`WAITAOF 1 0`). Unset: on if the store answers a `WAITAOF` probe at startup, off otherwise. `0`: off. A positive value: required (startup fails without AOF), with that timeout. |

## Caches

| Variable | Default | Meaning |
|---|---|---|
| `REDIS_URL` | unset | Cache Redis (`redis://` or `rediss://`), an evicting policy such as `allkeys-lfu`. Required in `ohttp` mode. |
| `LOCAL_CACHE_BYTES` | `268435456` (256 MiB) | In-process LRU in front of the cache Redis for blocks and tree states; `0` disables it. |
| `LOCAL_CACHE_MAX_ENTRY_BYTES` | `65536` | Values larger than this are not admitted to the in-process LRU. |
| `PERMANENT_REDIS_URL` | unset | Disk-backed store speaking the Redis protocol, without eviction, for final blocks (100 or more below the tip). Unreachable at startup: disabled until the next restart. |
| `PERMANENT_MIN_HEIGHT` | Sapling activation of `NETWORK` | Lowest height kept in the permanent tier. |
| `PERMANENT_OP_TIMEOUT_MS` | `2000` (serving), `5000` (`backfill`) | Timeout of one permanent-tier operation. |
| `CHAIN_TIP_STALE_SECS` | `150` | A stored chain tip unmoved for longer makes the chain follower's other processes compare it with their own lightwalletd: one that is ahead serves its own tip and, still ahead on the next check, takes the leader lock over. |
| `REDIS_PINNED_URL` | unset | Optional Redis (no eviction) for `GetTreeState` answers by height. Needs `PINNED_TREESTATE_RANGE`. |
| `PINNED_TREESTATE_RANGE` | unset | Inclusive height range for the pinned tier, `start-end` or `start-` (open end); `start` at least 1. |
| `PINNED_BACKFILL_WORKERS` | `0` | Background workers per process that fill the pinned range; `0`: write-through only. |

## `ohttp-gateway backfill`

The `backfill` subcommand fills the permanent tier from lightwalletd and exits. It reads
`NETWORK`, `LWD_ADDR`, `LWD_TIMEOUT_SECS`, `MAX_INFLIGHT_LWD`, `PERMANENT_REDIS_URL` (required),
`PERMANENT_OP_TIMEOUT_MS`, `PERMANENT_MIN_HEIGHT` and the variables below (a malformed
`BACKFILL_*` number falls back to its default):

| Variable | Default | Meaning |
|---|---|---|
| `BACKFILL_START` | `PERMANENT_MIN_HEIGHT` | First height. |
| `BACKFILL_END` | tip - 100 | Last height; capped at tip - 100. |
| `BACKFILL_BATCH` | `500` | Heights per batch. |
| `BACKFILL_CONCURRENCY` | `2` | Batches in flight. |
| `BACKFILL_PAUSE_MS` | `200` | Pause after every run fetched and written. |
| `BACKFILL_POOL` | empty | Pool filter variant to fill; the empty filter is what wallets request. |

The run is resumable: present heights are skipped and a checkpoint is kept in the store.

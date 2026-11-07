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
| `/healthz` | GET | `200 ok` while the security Redis answers and lightwalletd is reachable, else `503 unavailable`. Unauthenticated, no I/O, no details in the body: a monitor path for a load balancer. |
| `/health/startup` | GET | `200` once the process is listening. Does not depend on lightwalletd. |

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
cargo test                       # Redis-backed tests need a Redis on 127.0.0.1:6379, else they are skipped
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
identical envelope within a slot. Clients pin the public key of `CONFIGS_SIGNING_SEED_HEX` at
build time; `../docs/signed-configs-test-vector.json` is a test vector with a test key.

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
  that process (`CHAIN_TIP_STALE_SECS`).
- Blocks (`GetBlockRange` per block, `GetBlock`, `GetBlockNullifiers`) are served only while
  their hash matches the index; final blocks can live in the permanent tier
  (`PERMANENT_REDIS_URL`). `GetTreeState`, mined `GetTransaction` and `GetSubtreeRoots` entries
  are validated against the index the same way. Tip-scoped answers (`GetLightdInfo`,
  `GetLatestTreeState`, `GetAddressUtxos*`) are keyed by the tip hash. `GetLatestBlock` is
  answered from the follower's tip.
- `GetMempoolStream` subscribers share one upstream stream per process; identical upstream calls
  in flight are coalesced; `SendTransaction` is never cached or coalesced.
- A shared epoch counter in the security Redis is part of every cache key: incrementing it
  flushes every cached answer at once.
- Third-party answers are cached only for the routes in `THIRD_PARTY_CACHE_ROUTES`.

## Timeouts and relays

A relay typically closes a response that stays silent for too long between bytes. The gateway
keeps long answers moving: `GetMempoolStream` ends cleanly after `LONG_POLL_MAX_INITIAL_SILENCE_SECS`
without a first message and `LONG_POLL_IDLE_SECS` after the last one; `text/event-stream`
answers get keep-alive comments every `SSE_KEEPALIVE_SECS`; partial data is flushed as a short
chunk after `CHUNK_FLUSH_MS`. Every upstream call is bounded by `LWD_TIMEOUT_SECS` in total, and
a lightwalletd call by its class: an RPC with one answer by `LWD_UNARY_TIMEOUT_SECS`, a
server-streaming RPC by `LWD_STREAM_IDLE_SECS` of silence (for the head and between frames). An
upstream that sends no response head at all (an unresponsive backend) can still exceed a relay's
silence limit; the client then sees the relay's error.

## Metrics

All metrics are registered in `src/health.rs` and served on `:9090/metrics`. Request ids and
trace ids are never labels. `network` is `NETWORK`.

| Metric | Labels | Meaning |
|---|---|---|
| `ohttp_requests_total` | `status, mode, network, hop, method, http_status, grpc_status, backend, route_class` | Requests by outcome. |
| `ohttp_request_duration_seconds` | `network, hop, backend` | Request duration (histogram). |
| `ohttp_requests_in_flight` | `network` | Requests in flight. |
| `ohttp_relay_requests_total` | `network, relay, edge` | Authenticated `POST /gateway` by relay name and edge location (below). |
| `ohttp_relay_request_id_total` | `network, state` | Relay correlation id `present`, `missing` or `invalid`. |
| `ohttp_decrypt_errors_total` | - | Requests that did not decapsulate. |
| `ohttp_encrypt_errors_total` | - | Registered for compatibility; no longer incremented. |
| `ohttp_policy_denied_total` | `alias` | Inner requests refused by `BACKENDS_POLICY`. |
| `ohttp_freshness_total` | `network, result` | Freshness verdicts: `fresh`, `missing`, `malformed`, `stale`. |
| `ohttp_chunks_sent_total` | `network, kind` | Sealed response chunks: `full`, `flush`, `final`. |
| `ohttp_response_truncated_total` | `network` | Upstream answers cut at `MAX_UPSTREAM_RESPONSE_BYTES`. |
| `ohttp_upstream_requests_total` | `network, backend, rpc, http_status, grpc_status` | Upstream requests. `rpc` is a known lightwalletd method name or `other`. |
| `ohttp_upstream_request_duration_seconds` | `network, backend, rpc` | Upstream duration (histogram). |
| `ohttp_upstream_errors_total` | `network, backend, error_type` | Upstream errors. |
| `ohttp_upstream_calls_total` | `network, rpc` | Calls actually sent to lightwalletd, after caches and coalescing. |
| `ohttp_upstream_blocks_total` | `network` | Blocks fetched from lightwalletd for `GetBlockRange`. |
| `ohttp_singleflight_joins_total` | `network, rpc` | Calls that joined an identical call in flight. |
| `ohttp_lwd_errors_total` | - | lightwalletd forwarding errors. |
| `ohttp_lwd_connect_retries_total` | - | lightwalletd calls retried after a failed connection attempt. |
| `ohttp_lwd_reachable` | `network` | 1 while lightwalletd is reachable. |
| `ohttp_lwd_shed_total` | `network, class` | lightwalletd calls refused because their class was at its cap. |
| `ohttp_lwd_timeouts_total` | `network, class, phase` | lightwalletd calls cut by their deadline. `class`: `unary`, `stream`; `phase`: `head` (no response head in time), `body` (the call's overall deadline: the unary deadline, or `LWD_TIMEOUT_SECS` for a stream), `gap` (a stream silent too long). |
| `ohttp_lwd_pool_resets_total` | `network` | Pooled lightwalletd clients replaced after a call ran into its deadline (`LWD_CONNECTION_POOL`). |
| `ohttp_lwd_permit_waited_total` | `network, class` | Calls that waited for a permit. |
| `ohttp_lwd_permit_wait_seconds` | `network, class` | Permit wait time (histogram). |
| `ohttp_third_party_cache_total` | `network, authority, result` | Third-party cache `hit` / `miss`. |
| `ohttp_third_party_limited_total` | `network, authority` | Third-party calls refused by `THIRD_PARTY_RATE_LIMITS`. |
| `ohttp_redis_connected` | `network` | 1 while both the cache and the security Redis are connected. |
| `ohttp_cache_redis_connected` | `network` | Cache Redis connection. |
| `ohttp_security_redis_connected` | `network` | Security Redis PING (0 also when not configured). |
| `ohttp_redis_op_timeout_total` | `network, operation` | Redis operation timeouts. |
| `ohttp_cache_requests_total` | `network, rpc, result` | Cache lookups by result. |
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
| `ohttp_chain_tip_age_seconds` | `network` | Seconds since the leader last moved the stored tip, as this process sees it (`-1`: unknown). |
| `ohttp_chain_stale_leader_total` | `network, action` | Times this process found the stored tip unmoved past `CHAIN_TIP_STALE_SECS` with its own lightwalletd ahead: `local_tip` (served its own tip), `takeover` (took the leader lock). |
| `ohttp_chain_reorgs_total` | `network` | Reorgs detected. |
| `ohttp_chain_reorg_depth` | - | Blocks invalidated per reorg (histogram). |
| `ohttp_mempool_subscribers` | `network` | Clients subscribed to the mempool fan-out. |
| `ohttp_mempool_upstream_streams_total` | `network, reason` | Upstream `GetMempoolStream` sessions ended, by reason. |
| `ohttp_replay_rejected_total` | `network` | Requests refused as replays. |
| `ohttp_replay_write_wait_total` | `network, result` | WRITE nonces checked for replica acknowledgement (`REPLAY_WRITE_WAIT_REPLICAS`). |
| `ohttp_replay_write_wait_seconds` | `network` | Time to that acknowledgement (histogram). |
| `ohttp_replay_write_fallback_total` | `network, path, result` | WRITE nonces decided at a second store. `path`: `short_ack` (the local acknowledgement was short), `local_unavailable` (the local store gave no verdict, `REPLAY_UNAVAILABLE_FALLBACK`), `hub_short_ack` / `hub_unavailable` (the same for the hub of an `async-reads` origin), `check` / `window` (`failover` mode: the check of every WRITE at the peers, `window` within one nonce TTL after startup or a local store failover), `hub_check` / `hub_window` (the same at the standby stores of an `async-reads` origin). `result`: `accepted`, `replay`, `unavailable`, `unacknowledged`, `overflow`. |
| `ohttp_replay_read_fallback_total` | `network, result` | READ nonces decided at the peers because the local store gave no verdict (`REPLAY_UNAVAILABLE_FALLBACK`). |
| `ohttp_replay_fallback_check` | `network` | 1 when every WRITE this gateway admits is also checked at a fallback store synchronously; `REPLAY_UNAVAILABLE_FALLBACK` is safe only while every gateway with peers reports 1. |
| `ohttp_replay_unavailable_fallback` | `network, target` | 1 for the store the unavailable fallback replaces on this gateway (`local`, `standby`, `local_replicas`); all 0 when off. |
| `ohttp_replay_write_back_total` | `network, result` | Nonces admitted through the peers rewritten to the local store: `written` (acknowledged by its replicas) or `expired`. |
| `ohttp_replay_write_back_pending` | `network` | Such nonces still waiting for the local replicas. |
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

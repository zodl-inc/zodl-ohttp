# CHANGES

Behaviour changes of the gateway, the relay simulator and the e2e client. The client library
keeps its own log in [client/CHANGELOG.md](client/CHANGELOG.md).

## Unreleased

### Gateway

- Every WRITE is checked at the fallback store. Where the WRITE fallback exists (`failover` mode
  with peers that acknowledge on their replicas; `async-reads` with standby stores that do), the
  nonce of every WRITE admitted by the deciding store is also `SET NX` at the fallback store
  synchronously, not only for one nonce TTL after startup or a disruption; a nonce held there is
  a replay, an unreachable store keeps the first verdict. One more round trip to that store per
  WRITE. New `path` values `check`, `hub_check` of `ohttp_replay_write_fallback_total` (`window`,
  `hub_window` now only mark checks inside that time).
- `REPLAY_UNAVAILABLE_FALLBACK` (off by default): a deciding store that gives no verdict at all
  (unreachable, a timeout, an error) is replaced by the fallback store instead of failing closed.
  A `failover`-mode gateway decapsulates and classifies the request first, then decides READs by
  `SET NX` and WRITEs by `SET NX` + `WAIT` at its peers; a WRITE whose local `WAIT` got no answer
  takes the short-acknowledgement path. An `async-reads` origin confirms WRITEs whose hub gave no
  verdict at its standby stores or by its local replicas. Same rules as the other fallbacks, WRITE
  nonces written back. Turn it on only once every origin with peers reports
  `ohttp_replay_fallback_check` 1 (this version, with the settings of the WRITE fallback); a
  gateway that would not check WRITEs at the fallback store logs a warning at startup. New `path`
  values `local_unavailable`, `hub_unavailable`, new series `ohttp_replay_read_fallback_total`,
  `ohttp_replay_unavailable_fallback`, `ohttp_replay_fallback_check`.
- Chain follower: a stored tip that has not moved for `CHAIN_TIP_STALE_SECS` (default 150) makes
  the other processes compare it with their own lightwalletd; one that is ahead serves its own tip
  at once and, still ahead on the next check (10 s later), takes the leader lock over while the
  stored tip is unchanged, then leads from that tick on. The leader stores when it moved the tip
  (`{chain}tip_at`), and writes the tip only while it holds the lock (one script), so a leader
  replaced during a tick cannot move the stored tip back. A lightwalletd answering with a lower
  tip that is on the indexed chain is now treated as behind, not as a reorg. New series `ohttp_chain_tip_age_seconds`, `ohttp_chain_stale_leader_total`.
- The permanent tier store's role is checked (`INFO replication` at startup and every 10 s, and a
  write refused with `READONLY`): while it is a read-only replica its writes are skipped and final
  blocks stay in the cache tier. New series `ohttp_permanent_store_replica`,
  `ohttp_permanent_writes_skipped_total`.
- Per-class lightwalletd deadlines: an RPC with one answer is bounded by
  `LWD_UNARY_TIMEOUT_SECS` (default 10), a server-streaming RPC by `LWD_STREAM_IDLE_SECS` (default
  20) for its head and between frames (it still runs up to `LWD_TIMEOUT_SECS` while it keeps
  sending); the transparent-address RPCs keep `LWD_TIMEOUT_SECS` for their first answer. With
  `LWD_CONNECTION_POOL` a call cut by a deadline replaces the pooled client, and a
  keep-alive PING not answered within 5 s closes its connection. New series
  `ohttp_lwd_timeouts_total`, `ohttp_lwd_pool_resets_total`.
- Hub path of the WRITE fallback. In `async-reads`, when the peer store (the hub) took a WRITE
  nonce as new but its replica acknowledgement was short (the hub resyncs after a failover), the
  WRITE is confirmed at a second store instead of failing closed: at the standby stores
  (`REPLAY_STANDBY_URLS`: `SET NX` + `WAIT` there, `REPLAY_PEER_WAIT_REPLICAS` and `REPLAY_PEER_WAIT_MS`
  apply to that fallback; the background hand-off is unchanged), or,
  where the origin has its own replica wait, by its local replicas. Same rules as the local
  fallback (new and acknowledged = runs, held = replay, otherwise fail-closed); the nonce is
  written back to the hub. A read origin with standby stores also checks every WRITE there for
  one nonce TTL after startup or a hub disruption (`SET NX`, a held nonce = replay, an unreachable
  store keeps the hub's verdict). The hub write-back has its own peer connection. New `path` values `hub_short_ack`, `hub_window` of
  `ohttp_replay_write_fallback_total`.
- Peer fallback of the WRITE replica wait. With `REPLAY_PEER_URLS` and `REPLAY_PEER_WAIT_REPLICAS`
  >= 1, a WRITE whose nonce the local primary stored as new but whose `WAIT` came back short (the
  replicas resynchronise after a failover of the store) is confirmed at the peer stores: `SET NX`
  there (already done in `async-reads`), then the peer's own `WAIT`. It runs only if every peer
  took the nonce as new and acknowledged it; a peer holding it makes the request a replay; any
  other outcome fails closed as before. The nonce is written back to the local store until its
  replicas acknowledge it. In `failover` mode the background replication of a WRITE nonce now
  starts after the local verdict, and for one nonce TTL after startup, a short acknowledgement or a
  replaced store connection every WRITE is also checked at the peers. The write-back has its own
  store connection and replaces it after ~10 s of short acknowledgements. Without peers that
  acknowledge on their replicas nothing changes. New series `ohttp_replay_write_fallback_total{network,path,result}`,
  `ohttp_replay_write_back_total{network,result}`, `ohttp_replay_write_back_pending{network}`.
- `CHUNK_SIZE` is bounded above as well: a value over 65536 refuses to start, since the client
  (0.1.1) refuses response chunks with more than 64 KiB of plaintext. The default stays 16384
  and the minimum 1024.
- The replay stores follow a failover of a managed Redis. A connection whose node was demoted
  (`READONLY`, `MOVED`, a `WAIT` refused on a replica, `UNBLOCKED`, `LOADING`, `MASTERDOWN`), broke,
  or stopped answering is replaced by a new one, which resolves the endpoint name again and is
  used only once its node reports `ROLE master`; until then requests keep failing closed. The
  WRITE acknowledgement retries once on the new connection within its budget, and refuses a
  WRITE whose nonce is not on the node it reached (`SET XX` found nothing) instead of confirming
  it. The same applies to the `REPLAY_LOCAL_WAITAOF_MS` connection and the replay peers; the
  cache, pinned and permanent stores replace broken or hung connections only (some are read
  replicas on purpose). Housekeeping checks `ROLE` on the replay store connections, so an idle
  gateway also moves. New counter `ohttp_store_reconnect_total{network,store,reason}`.
- `REPLAY_STANDBY_URLS`: the security stores of standby origins. Every WRITE that passed the
  replay checks is also replicated there in the background (the `failover` queue: pipelined
  batches, retried until the nonce TTL), never delaying or refusing the request. An origin that
  checks its WRITEs at another origin's store sets it, so that a standby which takes over the
  WRITEs after losing that store refuses a replay of a WRITE admitted here shortly before. New
  gauge `ohttp_replay_standby_stores_configured`; the standby stores' per-peer series continue
  the `peer` numbering after `REPLAY_PEER_URLS`.
- `async-reads` with `REPLAY_PEER_FAIL_CLOSED_WRITES=0`: a WRITE that ran while a peer did not take
  its nonce is replicated to that peer in the background once it is reachable again (until the
  nonce TTL), so the origins checking at that peer refuse its replay after the switch back.

## 0.1.0 — initial public release

### Gateway

- Oblivious Gateway Resource for RFC 9458 with the chunked encoding
  (draft-ietf-ohai-chunked-ohttp) only: requests are opened as they arrive, responses are sealed
  and streamed chunk by chunk. Suite DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
- Relay authentication with one or more named `X-Relay-Secret` values, compared in constant
  time; optionally required on the key-configuration GETs as well.
- Key configuration at `/ohttp-configs` and as an Ed25519-signed, network-bound envelope at
  `/ohttp-configs/signed`, issued per hour and identical on every gateway with the same keys.
  Advertised and accept-only HPKE keys for rotation without failed requests.
- Replay protection: every Encapsulated Request is accepted once per nonce TTL, fail-closed, with
  an inner freshness timestamp that bounds replays beyond the TTL; optional replica
  acknowledgement of nonces of state-changing requests.
- Routing by inner `:authority` to the gateway's own lightwalletd or to exact third-party
  aliases, each with a method and path allowlist; gateway-owned upstream credentials; request and
  response header allowlists; strict authority and path validation.
- Bounded resources: request size and read deadline, request header read timeout, in-flight
  limits per process, per backend and per lightwalletd call class with a bounded wait, block
  range and response size limits, upstream timeouts; relay-friendly keep-alives for long polls
  and event streams.
- Response padding to whole chunks (configurable).
- Chain-aware caching of lightwalletd answers (follower with reorg handling, per-block cache,
  permanent tier for final blocks with a backfill subcommand, in-process LRU, request
  coalescing, shared mempool stream) and optional caching and rate limiting of third-party
  routes.
- Multi-origin operation: origin labels, cross-origin replay protection with synchronous,
  asynchronous-read and active/passive modes, health endpoint for load balancers.
- Structured JSON logs without client data, relay ids logged only under a per-process HMAC,
  Prometheus metrics.
- `INTERNAL_BIND_ADDR` sets the bind address of the internal health and metrics listener
  (default unchanged: `0.0.0.0:9090`).
- A GetBlockRange whose span overflows 64 bits counts as a heavy call (fail closed).
- A replication backlog overflow increments `ohttp_replay_async_dropped_total{reason="overflow"}`
  once per dropped nonce (it was counted twice).
- A lightwalletd answer whose body is cut by `LWD_TIMEOUT_SECS` is an upstream error, not a
  partial success, for the gateway's own buffered calls (chain tip, block ranges).

### Relay simulator

- A test relay that forwards sealed requests and key-configuration GETs to a gateway with a
  relay secret and its own request id, strips client headers and enforces the relay header
  allowlists. For tests only.

### e2e client

- One real OHTTP exchange through a relay, with signed, unsigned or DNS-over-HTTPS key
  configurations and options to probe relay behaviour; used by `scripts/test-e2e.sh`.

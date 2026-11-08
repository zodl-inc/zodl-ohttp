# OHTTP Architecture

## Overview

Oblivious HTTP (RFC 9458) splits what a light wallet reveals between two parties that do not
collude:

- the **relay**, run by an independent operator, sees the wallet's IP address but only an
  encrypted blob;
- the **gateway** (this repository, run by the gateway operator) sees the request but only the relay's address.

The wallet encrypts every request with HPKE (RFC 9180) to the gateway's public key before it
leaves the device. The gateway uses the chunked variant (draft-ietf-ohai-chunked-ohttp) only, so
long answers such as a `GetBlockRange` stream back as they are produced.

## Hops

```
┌───────────────┐
│ Wallet (Zodl) │  1. obtain and verify the gateway's signed key configuration
│ zodl-ohttp-   │  2. encode the request as Binary HTTP, seal it with HPKE
│ client        │  3. POST message/ohttp-chunked-req to the relay
└───────┬───────┘
        │ sealed request (client IP visible here)
┌───────▼───────┐
│ Relay         │  forwards the body unchanged, drops client-identifying headers,
│ (independent  │  adds its own X-Request-Id and X-Relay-Secret
│  operator)    │
└───────┬───────┘
        │ sealed request (only the relay's address visible here)
┌───────▼───────┐
│ OHTTP Gateway │  authenticates the relay, checks replay, opens the request,
│ (this repo)   │  enforces the routing policy, seals the answer as it streams
└───┬───────┬───┘
    │       │ plaintext inner request
┌───▼────┐ ┌▼──────────────────────────┐
│ light- │ │ allowlisted third-party   │
│ walletd│ │ HTTP APIs (BACKENDS)      │
│ (gRPC) │ │                           │
└───┬────┘ └───────────────────────────┘
┌───▼────┐
│ Zebra  │  full node
└────────┘
```

The answer travels back the same way: the gateway seals it under a key derived from the
request's HPKE context, the relay returns it unchanged, and only the wallet can open it.

The inner request's `:authority` selects the upstream: a `GATEWAY_HOSTS` name goes to
lightwalletd, an exact `BACKENDS` alias to that alias's base URL, anything else is refused with
an inner 403. Every alias has an explicit allowlist of methods and paths (`BACKENDS_POLICY`).
Only an allowlist of request and response headers crosses the gateway; credentials an upstream
needs are injected by the gateway (`BACKEND_HEADERS`) and never come from the client.

## Privacy model

| Party | Sees | Does not see |
|---|---|---|
| Relay | client IP, timing, sizes of sealed requests and responses | request or response content, which upstream is called |
| Gateway | request and response content, timing, sizes, the relay's address | client IP |
| Upstream (lightwalletd, third-party API) | the request the gateway forwards, the gateway's address | client IP, relay |

Linking a client address to request content requires the relay operator and the gateway
operator to combine their records. The gateway is built so that its own records do not help:

- The gateway logs no client address (it never receives one) and no request content beyond the
  method, the path (for third-party aliases, the policy pattern that admitted it, not the
  concrete path or query) and status.
- The relay's `X-Request-Id` is logged only as an HMAC under a random key that exists only in the
  memory of the running process; after a restart nobody can map relay ids to gateway log lines.
- Only `X-Client-Trace-Id`, which a client sends only when deliberately debugging, appears in
  both the relay's and the gateway's logs.
- Response padding (below) coarsens the answer sizes the relay sees.

What remains is timing and size correlation by colluding operators, which OHTTP does not
address.

## Relay authentication

`POST /gateway` requires exactly one `X-Relay-Secret` header whose value matches one entry of
`RELAY_SECRET`; anything else is an outer 401. Each entry can be named (`name=secret`), so one
gateway serves several relays and the metric `ohttp_relay_requests_total{relay}` and the log field
`relay` say which relay forwarded a request. Rotating a relay's secret means listing the old and
the new secret for that relay for the length of the switch. Secrets are compared as SHA-256
digests against every entry in constant time.

With `RELAY_SECRET_ON_KEY_CONFIG=require` the key-configuration GETs need the secret too, so the
configuration is only obtainable through a relay. `ALLOW_UNAUTHENTICATED_RELAY` removes the
check; it is meant for local tests, or for an origin that admits authorised relays by other means
(source address allowlist, mutual TLS) in front of it.

## Key configuration and rotation

The gateway's HPKE keys are X25519 private keys from `HPKE_KEYS` (or `HPKE_PRIVATE_KEY`); it
never generates one in `ohttp` mode. The suite is DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
AES-128-GCM. `/ohttp-configs` publishes the advertised keys, preferred first;
`HPKE_ACCEPT_ONLY_KEYS` are accepted for decapsulation but not published, which is what makes a
rotation safe: a key is accepted before it is advertised and after it stops being advertised
until every cached configuration has expired (procedure: `gateway/README.md`, "HPKE key
rotation"). A request sealed to a key the gateway no longer has fails with an outer 400; the
client then drops its cached configuration, fetches a fresh one and sends the request once more,
sealed afresh.

`/ohttp-configs/signed` wraps the same document in an Ed25519-signed JSON envelope bound to the
network and to a validity window (`gateway/README.md`, "Signed key configuration"). The wallet
trusts a key configuration only through that envelope.

## Key configuration discovery

A network is OHTTP-capable in a wallet build only when its gateway host
(`ZODL_OHTTP_GATEWAY_HOST_MAINNET` / `_TESTNET`), relay URL (`ZODL_OHTTP_RELAY_URL_*`, `https://`
only), signing key (`ZODL_OHTTP_SIGNING_PUBKEY_*`, 64 hex digits) and keys DNS name
(`ZODL_OHTTP_KEYS_DNS_NAME_*`) are all set at build time (`client/src/relays.rs`, validated by
`client/build.rs`). There is no built-in value and no runtime override. With none of a network's
four values set, OHTTP is off for that network; a partial set, a malformed value or a value
shared by mainnet and testnet fails the build.

1. **Through the relay.** The client fetches `GET /ohttp-configs/signed` through its relay (the
   URL is derived from the relay URL, `signed_config_url`). The relay forwards the GET to the
   gateway and returns the answer unchanged, so the gateway never sees the client's address here
   either.
2. **DNS, last resort.** If that fails and the build set `ZODL_OHTTP_KEYS_DNS_NAME_MAINNET` /
   `_TESTNET`, the client may read the envelope from a DNS TXT record of that name over
   DNS-over-HTTPS, JSON API, using the public resolvers in `client/src/dns.rs` (`DOH_RESOLVERS`,
   tried in order; `doh_query_url` builds the query and disables EDNS Client Subnet where the
   resolver supports the parameter). `envelope_from_doh_json` accepts only a `Status` 0 answer
   with TXT records (type 16) for exactly the queried name, concatenates the character-strings
   of the record in order (presentation format, `\"`, `\\` and `\DDD` decimal escapes), requires
   exactly one distinct TXT value, and base64-decodes it into the envelope, refusing anything
   over 64 KiB (`MAX_KEY_CONFIG_BYTES`). Without a DNS name for the network this source is off.
   The library supplies the parsing; the wallet SDK performs the HTTPS fetch over its own
   transport.

Either way the envelope is then verified the same way (`verify_signed_config`, `client/src/signed.rs`):

- version 1, `network` equal to the network the build bound to the gateway host, `key_id`
  equal to the first four bytes of SHA-256 of the pinned key, a valid Ed25519 signature by the
  network's pinned key (`ZODL_OHTTP_SIGNING_PUBKEY_*`) over the exact signed message;
- `not_before < not_after`, `not_after - not_before` at most 86400 s, `not_after` at most
  86400 s ahead of the device clock, and the device clock within the window widened by
  `CLOCK_SKEW_SECS` (60 s) on each side;
- the envelope at most 64 KiB, the decoded document at most 4096 bytes, repeated JSON keys
  refused, unknown fields ignored;
- the remaining policy options (base64 strictness, strict or standard Ed25519 verification) as
  the caller's `SignedConfigPolicy` sets them.

A verified configuration is used until its `not_after`. The key selected from it is the first
configuration that offers the suite.

## Replay protection and freshness

The gateway stores SHA-256 of every Encapsulated Request in the security Redis
(`REDIS_SECURITY_URL`, no eviction) for 600 s; the same body again within that time is a replay
(outer 409). The check fails closed: without the security Redis no request is served (outer
503). Because a client seals every attempt afresh (new ephemeral key, new ciphertext), a
legitimate retry never collides with its predecessor.

Inner requests carry `ohttp-freshness: <unix seconds>`, the client's estimate of the gateway
clock; every sealed response carries `ohttp-server-time`, from which the client learns its
offset. With `REPLAY_FRESHNESS=enforce` the gateway refuses timestamps further than
`REPLAY_FRESHNESS_WINDOW_SECS` (at most half the nonce TTL) from its clock with an inner 400
marked `ohttp-freshness: rejected`; the client corrects its offset from that response and
retries once. Together the two make an Encapsulated Request executable at most once: inside the
window its nonce is still held, outside it the timestamp is refused.

For a replicated security Redis, `REPLAY_WRITE_WAIT_REPLICAS` delays every WRITE (any inner request
not on `REPLAY_READ_ROUTES`, which defaults to the read-only lightwalletd RPCs) until its nonce is on that many replicas, so a failover of the store
cannot forget it. READs are not delayed: replaying one changes nothing and its answer is sealed
to the original client.

After a failover of such a store, the promoted primary resynchronises its replicas and cannot
acknowledge anything for a while. With replay peers (`REPLAY_PEER_URLS`, below), a WRITE whose
nonce the local primary took as new but whose acknowledgement came back short is confirmed at
the peer stores instead: the nonce must be new there too and acknowledged by the peer's own
replicas (`REPLAY_PEER_WAIT_REPLICAS`), else the WRITE fails closed as before; a peer holding the
nonce makes it a replay. The nonce is then written back to the local store until its replicas
have it. A replay is refused even if the local store lost the nonce before the write-back (for
example because the gateway that admitted it stopped), because every WRITE is also checked at the
peers (below). Without peers that acknowledge on their replicas nothing changes.

The same applies to an `async-reads` origin's WRITE check at the hub (its peer store): a short
acknowledgement there is covered by the standby stores (`REPLAY_STANDBY_URLS`, `SET NX` + `WAIT`)
or by the origin's own replica wait, and the nonce is written back to the hub.

Every WRITE that the deciding store (the local store in `failover` mode, the hub in
`async-reads`) admitted is also `SET NX` synchronously at the fallback store (the peers, or a read
origin's standby stores), and a nonce held there is a replay; an unreachable fallback store keeps
the first verdict. With `REPLAY_UNAVAILABLE_FALLBACK` a deciding store that gives no verdict at
all (unreachable, a timeout, an error) is replaced by the fallback store, under the same rules:
new and acknowledged there runs, held there is a replay, anything else fails closed, and a WRITE
nonce is written back. A `failover`-mode gateway decides READs that way too (`SET NX` at the
peers, not written back: a replayed READ changes nothing), after decapsulating the request to
classify it. A request refused or failed closed after its nonce was stored stays refused for
those exact bytes; a client seals every attempt afresh, so its retry is a new nonce.

An `async-reads` origin whose own store is the fallback store (no standby stores, its own replica
wait: the standby origin and its read spoke) does the same when its own store gives no verdict:
the hub, which decides its WRITEs anyway, decides the request alone (READ: `SET NX`; WRITE: `SET
NX` + the hub's `WAIT`), and a WRITE nonce is written back to the own store. That holds with
`REPLAY_PEER_FAIL_CLOSED_WRITES=0` too (an unreachable hub is tolerated there, an unreachable own
store is not). Every other origin keeps the hub's verdict while the fallback store is silent and
asks both while it answers, so this adds no new way to admit a nonce twice: two admissions still
need one gateway that reached only the hub and another that reached only the fallback store at
the same time.

Such a gateway also stays healthy for a load balancer: `/healthz` answers 200
while its own store does not answer but every peer answered the last housekeeping PING (every
10 s), and 503 once no store can decide. The state can lag by one round (up to 10 s plus the peer
timeout) in either direction. WRITEs decided this way are queued for write-back to the local
store; if that queue is full, further WRITEs fail closed (`result="overflow"`) while READs keep
being served.

Why the check of every WRITE: two gateways run the same WRITE only if each found its nonce new at
a store the other did not ask. Every gateway asks every store it reaches, the deciding store is
replaced only by the fallback store, and `SET NX` on one store admits a key once, so that takes a
gateway that reached only the deciding store and another that reached only the fallback store at
the same time: two failures at once. A nonce admitted at one store only reaches the other by the
write-back or the background hand-off as soon as it is reachable. The guarantee needs the check on
every gateway that asks the deciding store (gauge `ohttp_replay_fallback_check`, with the settings
of the WRITE fallback), so the fallback stays off until all of them report it.

## Response framing: chunks and padding

Every response is a chunked OHTTP message: a response nonce, then non-final chunks of
`CHUNK_SIZE` plaintext bytes (shorter after a stall, below) and a final chunk, each sealed with AES-128-GCM under keys derived from the
request's HPKE context. Chunk boundaries never follow message boundaries. When upstream data
stalls for `CHUNK_FLUSH_MS`, the bytes collected so far go out as a shorter chunk, so a stream
keeps moving. With `RESPONSE_PADDING=on` (default) the final chunk is zero-padded to
`CHUNK_SIZE`, so a response that does not stall is a whole number of chunks and its size says
little about which blocks or transactions were fetched. `sensitive` leaves a
few small, uninformative answers unpadded.

## Multiple origins

Several gateways can serve one gateway host name, for example behind a load balancer that
routes by geography or fails over between origins. They then must share the HPKE keys, the
signing seed and the relay secrets; `ohttp_key_config_info` and the startup log line let an
operator check that every origin publishes the same configuration (identical envelopes within an
issuance slot, because signing is deterministic). `ORIGIN_ID` labels logs and metrics; it is never
sent to clients.

Replay protection spans origins when each one lists the others' security Redis in
`REPLAY_PEER_URLS`: a nonce held by any store is a replay. `REPLAY_PEER_MODE` chooses how:

- `sync`: every nonce is written to every peer before the request runs;
- `async-reads`: READ requests (`REPLAY_READ_ROUTES`) are checked locally and replicated in the
  background, WRITEs stay synchronous; when replication lags or a peer fails, READs fall back to
  the synchronous path until the peers have recovered;
- `failover`: every request is checked locally and replicated in the background, for an
  active/passive pair whose passive store must already hold every nonce when traffic moves.

A standby origin, one that runs WRITEs on its own store only while the peers' store is
unreachable, refuses a replay of a WRITE only if its store already holds the nonce. The origin
that owns the shared store replicates its own requests there (`failover`); an origin that checks
its WRITEs at the shared store lists the standby store in `REPLAY_STANDBY_URLS`, which hands every
WRITE nonce it admits to that store in the background. In the other direction, a WRITE the standby
ran on its own store reaches the shared store once it is reachable again; until the standby has
reconnected (backoff up to 5 s) an origin checking only at the shared store would not see it.

The settings that decide what happens when a peer is unreachable (`REPLAY_PEER_FAIL_CLOSED`,
`REPLAY_PEER_FAIL_CLOSED_WRITES`, `REPLAY_PEER_WAIT_REPLICAS`, `REPLAY_LOCAL_WAITAOF_MS`) are
described in `gateway/CONFIG.md`. Without `REPLAY_PEER_URLS` none of this is active.

## Bounded resources

Every input is bounded before it is processed: the Encapsulated Request (10 MiB, read within
30 s), concurrent requests, concurrent upstream calls in total, per alias and per lightwalletd
call class (long scans cannot starve `SendTransaction` or `GetLatestBlock`), `GetBlockRange`
spans, upstream response size and time, and the request header read time per connection. All
limits are in `gateway/CONFIG.md`. Malformed `:authority` and `:path` values are refused before
any upstream URI is built, and the URI built is checked against the selected upstream.

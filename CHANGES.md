# CHANGES

Behaviour changes of the gateway, the relay simulator and the e2e client. The client library
keeps its own log in [client/CHANGELOG.md](client/CHANGELOG.md).

## Unreleased

### Configuration file

- The routing policy can come from a TOML configuration file (`schema = 1`): the variables
  `GATEWAY_HOSTS`, `BACKENDS`, `BACKENDS_POLICY(_DEFAULT)`, `BACKEND_HEADERS`, `FLEXA_ALIAS`,
  `NEAR_ALIAS`, `THIRD_PARTY_*` (cache routes, rate limits, query rules, value sources, host
  list), `REPLAY_READ_ROUTES`, `REPLAY_ONE_SIDED_WRITE_ROUTES`, `DYNAMIC_HOST_SOURCES`,
  `DYNAMIC_HOSTS_DENY_CIDRS` and `RELAY_SECRET_ON_KEY_CONFIG`, grouped by alias, each entry in
  its variable's grammar, header secrets named in `[secrets]` (a variable or a file). The file
  is turned into those variables, which the same parsers read. `CONFIG_SOURCE=env|compare|file`
  chooses the source; the default `env` is the behaviour so far (no file is read). New command
  line actions `--check-config [--secrets=require|skip]`, `--print-effective-config` and
  `--export-config` (with `--config <path>` or `GATEWAY_CONFIG_FILE`); without a flag the
  binary serves as before, `backfill` (and whatever follows it) is unchanged. An unknown
  option, or two actions, now exit with 2 (arguments that are no option are still ignored).
  New metrics `ohttp_config_info{source,digest}`
  (every process) and `ohttp_config_compare_match` (`compare` only). The image carries the label
  `org.zodl.ohttp-gateway.check-config=1`. See `gateway/CONFIG.md` and
  `gateway/config.example.toml`.

### Integrations crate

- New library crate `zodl-ohttp-integrations` (`integrations/`, not published), linked into the
  gateway: the route grammar shared by the alias policy, the dynamic hosts and the replay
  classes, the parsers of `BACKENDS`, `BACKENDS_POLICY` and `BACKEND_HEADERS`, a `Provider`
  interface and the generic provider (route policy, fixed upstream headers). It does no I/O. The
  gateway asks it for the policy verdict and the credential headers of an alias; behaviour,
  error messages, log fields and metrics are unchanged. The gateway image now builds from the
  repository root (`docker build -f gateway/Dockerfile .`).
- The query rules (`THIRD_PARTY_QUERY_RULES`) and the value sources
  (`THIRD_PARTY_QUERY_VALUE_SOURCES`: grammar, JSON pointer extraction, list acceptance) move
  into the integrations crate, as do the request path checks their parsers share with the
  forwarder; the gateway keeps reading the variables, fetching the lists, logging and recording
  the metrics. New provider kinds `cmc` and `swapkit` (cargo features, on by default): keyed
  providers, the generic provider that cannot be built unless every route has a query rule and
  the alias carries a header credential, for the configuration file to come; no environment
  variable assigns them, so every alias stays generic. Verdicts, error messages, log fields and
  metrics are unchanged.
- The Flexa and NEAR handling become providers of the integrations crate (cargo features
  `flexa`, `near`, on by default): the registry gives the alias named by `FLEXA_ALIAS` the Flexa
  provider (forwarded headers, placeholder swap) and the one named by `NEAR_ALIAS` the NEAR
  provider, whose only cacheable route stays `GET /v0/tokens`. Both cache restrictions apply
  in every build; a build without one of the two features refuses to start when its alias is
  set. The two copies of the Flexa header code in the collected and the streamed forward are
  now one provider call. Credentials are built by the crate's signers (a header template, the
  placeholder swap). The parsers of `THIRD_PARTY_CACHE_ROUTES` and `THIRD_PARTY_RATE_LIMITS` and
  the fixed-window cap move into the crate too; the cache store, its single flight and the cap state stay in the gateway. The
  upstream headers (names, values, order), startup errors, log fields and metrics are
  unchanged; a new test pins the exact upstream header list of every kind of authority on both
  forward paths.

### Crate names

- The gateway crate is renamed `zodl-ohttp-gateway` (library `zodl_ohttp_gateway`, binary
  `zodl-ohttp-gateway`) and marked `publish = false`: the name `ohttp-gateway` on crates.io belongs
  to an unrelated crate. The image is still `ohttp-gateway`, its entrypoint is
  `/app/zodl-ohttp-gateway`, and `/app/ohttp-gateway` stays as a link to it. Nothing on the wire
  changes: the upstream `User-Agent`, the `/ohttp-gateway/...` paths, the metric names and the
  environment are the same. Two things a log or process reader sees change: the `target` of every
  log line is now `zodl_ohttp_gateway[::module]` (a per-module `RUST_LOG` directive must use that
  prefix; a plain level such as `info` is unaffected), and the process name is the new binary's
  (truncated to `zodl-ohttp-gate` by the kernel). The relay simulator and the e2e client are
  marked `publish = false` too. A release tag now looks for `zodl-ohttp-gateway` in the lock
  files; a commit from before the rename cannot be tagged with this check.

### Images and releases

- A release tag no longer rebuilds the images: it adds the version tag to the `sha-<short>`
  multi-platform index the main build of the tagged commit pushed, so the version and
  `sha-<short>` name the same digest (the one that was tested). All three images pass a
  preflight before any tag is written; it fails, and tags nothing, if an index is missing, is
  not a linux/amd64 + linux/arm64 index whose platform images are labelled with the tagged
  commit, if the index or one of its platform images lacks the main build's signature or
  provenance attestation for that commit and that image (an attestation of another image does
  not count), or if a version tag already names another digest.
  Only a registry "manifest not found" answer for exactly the requested reference counts as an
  absent tag, in a single-line answer; local tool, authorisation and transport errors and mixed
  diagnostics are fatal. Values read from the registry (revision labels, platforms, tag object
  headers, file names) are printed only when well-formed; malformed data gets a fixed message. A re-run after a failed write completes the rest.
  Nothing is signed or attested on a release (`scripts/promote-image.sh`).
- Release tags must be signed annotated tags `vMAJOR.MINOR.PATCH[-PRERELEASE]` (SemVer, at most
  128 characters after the `v`) by a key of `.github/release-signing-keys.asc`, whose signed
  tag object carries the tag's name and names the commit directly, on a commit of `main`, and
  match the gateway and relay-simulator crate versions and lock entries. The
  gateway and relay-simulator crates are at 1.1.0, the latest release.
- `scripts/verify-image.sh` verifies a release image by the main build's signer identity; the
  tag identity is accepted only for the images listed by digest in
  `scripts/legacy-release-digests.txt` (ohttp-e2e 1.0.1 and the three 1.1.0 images, which their
  tag builds rebuilt and signed). The three 1.0.0 images verify through the main build's
  identity; ohttp-gateway and ohttp-relay-simulator 1.0.1 were never signed and cannot be
  verified. The attestation must name the verified digest. New `--commit <sha>`: only
  certificates issued to a build run at that commit, with an attestation naming it; Sign
  Existing Image signatures only with `--allow-sign-existing` (then bound to the commit only by
  their attestation). The attestation must name the image: subject named after the image's
  repository, and `invocation.parameters.image` when present. The output names the image by
  short name and digest.
- The main build signs and attests the index and each platform image (`scripts/sign-image.sh`),
  so a platform digest verifies on its own. The provenance names the image
  (`invocation.parameters.image`). A digest that already carries the signature
  (attestation) is not signed (attested) again, and an existing `sha-<short>` index is kept if
  it is the index of the run's platform pushes, with the same descriptors (media type, digest,
  size and platform; annotations are not compared)
  (`scripts/publish-index.sh`; otherwise the run fails), so "Re-run failed jobs" of a failed
  publish completes on an immutable registry; the platform digests are kept 14 days for it.
  Before writing, the pushes must be exactly one linux/amd64 and one linux/arm64 image labelled
  with the commit, whose descriptors match their configurations (os, architecture, variant,
  os.version, os.features). The provenance names the repository it was built in, `buildStartedOn` is
  the time the run's first job began (was the commit time), and the predicate no longer claims
  complete parameters.
- `Sign Existing Image` runs only from `main` (a dispatch from another branch gets no
  credentials; `scripts/sign-image.sh` also refuses to sign in a workflow run not on `main`),
  signs `ohttp-e2e` too, works with a registry path prefix and in any
  repository (identity and provenance from the repository it runs in), fails if the digest does
  not exist, signs and attests the platform images of an index, and writes no `buildStartedOn`.
- The test Redis images are pinned by digest. Checkouts keep no credentials (the release check
  passes the token to its one fetch only); the AWS account ID is masked in the logs; tool
  output (stdout and stderr, of successful and failed commands) is shown only with
  `IMAGE_TOOLS_VERBOSE=1` or in a debug run. Options without a value are refused with a
  message; `verify-image.sh --commit` requires a full commit SHA.

### Gateway

- New, off by default: **WRITE forwarding** (`REPLAY_WRITE_FORWARD_URL`,
  `REPLAY_WRITE_FORWARD_SECRET`, `..._CONNECT_TIMEOUT_MS` 1000, `..._TIMEOUT_SECS` 90,
  `..._BACKOFF_MS` 5000 on a read origin, which must be `async-reads` with `REPLAY_PEER_URLS`
  and not with its own replica wait but no standby stores;
  `WRITE_FORWARD_BIND_ADDR` and `WRITE_FORWARD_SECRETS` on the receiving gateway). A read origin
  posts the Encapsulated Request of each WRITE (after its own local check) to a gateway next to
  the hub store, which handles it like a request from a relay on a listener of its own
  (cleartext HTTP/2 only, preface deadline, connection cap), always as a WRITE: it opens it
  first, then the hub store's nonce, replica wait and fallback-store check, freshness, route
  policy, third-party rules, upstream; the read origin streams its sealed answer back unchanged.
  A WRITE then costs the read origin one round trip to that gateway instead of the hub check plus
  the upstream call. Failure semantics: a `409` there is a peer replay; any other answer of that
  gateway (a refused secret, busy, not every replay store connected, a requirement it cannot
  meet, a request it cannot open) or no
  connection means it did not run the WRITE, and the read origin decides it as before (and,
  after a lasting reason, an unclear store answer there or three one-off declines in a row,
  without trying for the backoff); a WRITE sent without an answer in
  time, or whose connection broke, or whose store there gave no verdict after the nonce may have
  been stored, fails closed (inner 503 / grpc-status 14). The read origin states what its own
  decision requires (`ohttp-write-forward-requires`: `second-store`, `replica-ack=N`) and the
  receiving gateway declines what it cannot meet. The receiving gateway's own security store
  must be the read origins' hub store and its second store their standby stores, with the same
  one-sided routes and fail-closed settings (not checked). The forwarding connection is PINGed every 2 s and closed after 5 s without an
  answer. READs and the caches are unchanged. New metric
  `ohttp_write_forward_total{network, result}` and stage `forward` of
  `ohttp_write_stage_duration_seconds`. Each forwarded WRITE is counted once on each side, told
  apart: the read origin counts it in `ohttp_requests_total{status="forwarded", hop="forward"}`
  and observes the duration the client saw in `ohttp_request_duration_seconds` (until the head
  of the answer); the receiving gateway counts its own outcome with `mode="forwarded"` and
  observes no request duration, so sums over all gateways count every request once when
  `mode="forwarded"` is left out; a replay is counted in `ohttp_replay_rejected_total` once, by
  the read origin for the receiving gateway's outer 409 and by the receiving gateway when its
  sealed answer refuses it. `POST /gateway` is
  unchanged; the forwarded-WRITE route exists only on the new listener.
- The forwarded-WRITE listener (`WRITE_FORWARD_BIND_ADDR`) turns Nagle off on its connections
  (`TCP_NODELAY`). Without it the answer to a forwarded WRITE, written as a HEADERS frame and then
  DATA frames, waited for the read origin's acknowledgement of the first write: about one extra
  round trip (plus the delayed acknowledgement) per forwarded WRITE, which ate the gain of
  forwarding (with 90 ms of added round-trip delay on the listener port: 231 ms per forwarded
  WRITE before, 99 ms after). The forwarding client also keeps its pooled connection open while
  idle (it was closed after 60 s without WRITEs, so the next one paid a TCP handshake); its PINGs
  (every 2 s, 5 s timeout) still close a dead one. The test
  `a_forwarded_write_costs_one_round_trip` measures it behind an added delay on the listener port
  (`OHTTP_FORWARD_RTT_PORT`, `OHTTP_FORWARD_RTT_MAX_MS`; skipped unless set).
- The hub check of a WRITE at an `async-reads` origin (its peer store, with
  `REPLAY_PEER_WAIT_REPLICAS` >= 1) takes one round trip instead of two: the nonce's `SET NX`
  and the peer's `WAIT` go out as one pipeline on one of the peer's `WAIT` connections. A `WAIT`
  covers every earlier write of its connection, so the nonce it acknowledges is the one that
  `SET NX` stored, exactly as `SET NX` followed by `SET XX` + `WAIT` before. Verdicts, metrics
  and every fallback path are unchanged: taken and acknowledged runs; held is a replay; taken
  but short (fewer replicas) gets the one remaining attempt (`SET XX` + `WAIT`), then the
  short-acknowledgement path (`hub_short_ack`). An error the store answers, which may be that of
  `SET NX` or of `WAIT`, is resolved with one `SET key value NX GET` on the main connection
  (this request's value or nil = taken by this request, with one attempt of the acknowledgement
  left; another value = replay; like the existing `SET NX` retry this needs Redis >= 7.0 at the
  hub, an older store gives no verdict). A pipeline without a clear answer (none within
  `REPLAY_PEER_TIMEOUT_MS` + `REPLAY_PEER_WAIT_MS`, or its connection broke), whose `SET NX` may
  have landed, is asked again at once with `SET ... NX GET` on another `WAIT` connection, for
  every route (before, only a both-stores WRITE retried a `SET NX` timeout); it is counted once
  decided (`ohttp_replay_peer_total`: `timeout_retry` and the retry's outcome) and is a
  disruption of the hub (which opens the hub window) only if that retry gives no verdict either.
  A hub that does not answer at all is therefore declared unavailable after that sum plus one
  `REPLAY_PEER_TIMEOUT_MS` instead of one `REPLAY_PEER_TIMEOUT_MS`. The pipeline only uses a
  `WAIT` connection no other request uses at that moment, in a pool of at least two
  (`REPLAY_WAIT_CONNS` >= 2), so a pipelined `SET NX` never queues behind another request's
  `WAIT`; otherwise, and when no connection is idle at once (more WRITEs in flight than
  `REPLAY_WAIT_CONNS`), the hub is asked as before (`SET NX` on its main connection, then the
  acknowledgement), so the saturated path (`ohttp_replay_wait_saturated_total`) is unchanged;
  `ohttp_replay_hub_check_total{path="pipelined"|"main"}` counts which one ran. The pipeline
  holds its connection alone, also in shared mode, so two pipelines without an answer on
  different connections within 5 s replace the whole `WAIT` pool, as in exclusive mode. The verdict and the acknowledgement now
  come from the same connection: the old `SET XX` on the `WAIT` connection also noticed a nonce
  missing on the node the `WAIT` connection reached, which matters only while two primaries are
  reachable under one address. The concurrent check at the standby stores is unchanged.
- New histogram **`ohttp_write_stage_duration_seconds{network, stage, result}`**: the time of
  each stage of a WRITE, for latency budgets per stage. `stage`: `local` (the local `SET NX`;
  `new`, `unavailable`), `hub` (a read origin's hub `SET NX` and replica wait: `acknowledged`,
  `short`, `failed`, `fresh` without a wait, `replay`, `unavailable`), `standby` (its concurrent
  standby `SET NX`: `fresh`, `replay`, `unavailable`), `replica_wait` (the local replica wait:
  `acknowledged`, `failed`), `upstream_lwd` (the light client server call of a WRITE, e.g.
  `SendTransaction`, which had no upstream histogram: `ok`, `error`), `upstream_third_party`
  (the upstream call of a third-party WRITE until its response head, cache hits and the cap's
  429 excluded: `ok`, `error` for a transport error or a 5xx). Buckets from 0.5 ms to 10 s, every
  25 to 50 ms between 25 and 300 ms, then 400 ms. No request identifiers; at most a few dozen
  series per network.
- New, off by default: **`THIRD_PARTY_QUERY_RULES`**, per-route query string allowlists for
  `BACKENDS` aliases (`alias=METHOD /path?name=VALUE&name2=VALUE2,METHOD /path?;alias2=...`;
  VALUE a literal, `{in:A|B|C}` (alternatives of `[A-Za-z0-9._~-]`), `{upper:MIN-MAX}` (MAX at most
  32) or `{from:name}` of a source of the same alias). `BACKENDS_POLICY`
  admits a method and path with any query string, so a client could use an alias whose
  credential the gateway injects as a general proxy of that API, and every new query string was
  a new third-party cache key spending upstream quota. A request to a route with a rule must
  carry exactly the rule's parameters in the rule's order, with matching values (byte for byte
  on the raw query, never rewritten, so the checked string is the cache key and the upstream
  request); otherwise it gets the inner 403 `policy denied` of a `BACKENDS_POLICY` denial (same
  metric, log reason `query not allowed`), before the third-party cache and the upstream cap.
  This bounds the distinct cache keys of a route by its admitted values (`/path?` and `/path`
  are two keys); answers that are not a 200 are still not cached, and `THIRD_PARTY_RATE_LIMITS`
  still bounds the upstream calls they cost. `{in:...}` or `{from:...}` is recommended for
  credentialed upstreams. Unset: no change. Startup errors: malformed rules, prefix paths or
  paths the request side refuses, aliases outside `BACKENDS`, routes `BACKENDS_POLICY` does not
  allow, and `BACKENDS_POLICY` entries that admit a rule's path through a `*` method, a `/*`
  prefix or another method without a rule, or that contain `?`. A `THIRD_PARTY_QUERY_RULES`
  value that is not UTF-8 is a startup error.
- New, off by default: **`THIRD_PARTY_QUERY_VALUE_SOURCES`**, allowed-value lists read from
  the upstream itself for the `{from:name}` pattern of `THIRD_PARTY_QUERY_RULES`
  (`name=alias GET /path#/json/pointer@REFRESH_SECS[@fallback=A|B|C];...`). Each process fetches
  each source in the background 0 to 5 s after startup, then every `REFRESH_SECS` (300..=604800),
  after a failure again in 60 s doubling up to `REFRESH_SECS`, every wait +-10 % (lists of
  different processes can differ for up to `REFRESH_SECS`); a `GET` through the forwarder with
  the alias's `BACKEND_HEADERS` (its permits, upstream metrics and logs), 10 s deadline, at most
  256 KiB read, outside the third-party cache and `THIRD_PARTY_RATE_LIMITS`. A JSON pointer (`*` iterates an array, at most two) selects
  string values (1 to 64 characters of `[A-Za-z0-9._~-]`; others are skipped and counted; more
  than 2048 rejects the document, the walk stopping there). A failed refresh of any kind, including one with fewer valid values than half the list admitted
  now (`too_few`), keeps the last accepted list. A list smaller than half the admitted one is therefore never
  accepted by refreshes: it is held until a restart (with a smaller or no fallback) or a
  configuration change; alert on `result="too_few"` and on a stale last success (0 = never).
  Before the first accepted list the `fallback` list is admitted (the first accepted list
  replaces it), without one `{from:name}` admits nothing. The query verdict of a request is
  taken once, so the handler's precheck and both forwards agree even if a list is replaced
  meanwhile. New metrics `ohttp_query_value_source_refresh_total{network,source,result}`,
  `ohttp_query_value_source_values{network,source}`,
  `ohttp_query_value_source_last_success_timestamp_seconds{network,source}` (0 until the first
  success) and `ohttp_query_value_source_skipped_total{network,source}`; one log line per
  accepted change (counts only), failures logged with status and error (never the body).
- New histogram `ohttp_traced_request_duration_seconds` (labels `network, hop, backend, rpc`,
  the buckets of `ohttp_request_duration_seconds`): every duration observed in
  `ohttp_request_duration_seconds` for a request whose outer request carried a valid
  `X-Client-Trace-Id` is observed here too. Release clients send no trace id, so it holds only
  synthetic checks, test tools and debug builds; subtracting it per bucket from
  `ohttp_request_duration_seconds` gives real-user latency. Existing metrics are unchanged.
  Aggregate both sides to the same labels and use `main - (traced or main * 0)`: label sets
  that never saw traced traffic have no traced series. Only answered requests are observed,
  and the split needs relays that forward `X-Client-Trace-Id`.
- New, off by default: **dynamic third-party hosts** (`DYNAMIC_HOST_SOURCES`, a JSON array of
  sources). A source is the URL of a JSON document plus, per list in it, a JSON pointer to an
  array of URLs and the routes those hosts get. The gateway reads each source every
  `refresh_secs` (default 60) and serves the listed hosts like a `BACKENDS` alias whose target
  is the host itself, without a restart. Static configuration wins: a `BACKENDS` alias, a
  `GATEWAY_HOSTS` name and the host of a `BACKENDS` target or of `LWD_ADDR` are never served
  from a source. A listed URL must be a plain
  `https://host[:port]` whose host is a DNS name or a public IPv4 address (port 443 unless the
  source allows another); requests to dynamic hosts use a client that connects to public
  addresses only, so a listed name that resolves to a private, loopback or link-local address
  is not connected to (`DYNAMIC_HOSTS_DENY_CIDRS` adds blocks of the operator's choice). Dynamic
  hosts get only their list's routes, no `BACKEND_HEADERS`
  credentials, the per-backend in-flight limit and an optional per-host `rate_limit`; their
  replay class comes from their list's `read_routes` alone (`REPLAY_READ_ROUTES` and
  `REPLAY_ONE_SIDED_WRITE_ROUTES` are not consulted for them). Bounded
  by `max_hosts`, `max_new_hosts_per_refresh`, `DYNAMIC_HOSTS_MAX_DOCUMENT_BYTES` and
  `DYNAMIC_HOSTS_FETCH_TIMEOUT_SECS`; optional detached Ed25519 signature of the document
  (`signature_url`, `signature_keys`). Failure semantics: any failed refresh (fetch, status,
  size, JSON, missing list, no valid host, too many hosts, signature) keeps the hosts of the
  last accepted document; a source that is down at startup does not stop the start and its
  hosts are missing until it answers. Every process refreshes on its own. New metrics
  `ohttp_dynamic_hosts`, `ohttp_dynamic_hosts_refresh_total`,
  `ohttp_dynamic_hosts_last_success_timestamp_seconds`, `ohttp_dynamic_hosts_held`,
  `ohttp_dynamic_hosts_rejected`, `ohttp_dynamic_hosts_shadowed`; the `backend` label of a
  dynamic host is `dynamic:<source>`. See gateway/CONFIG.md "Dynamic third-party hosts".
- New, off by default: **the third-party host list for wallets**
  (`THIRD_PARTY_HOSTS_PUBLISH=dynamic|all`, `THIRD_PARTY_HOSTS_MAX_AGE_SECS`). The inner request
  `GET /ohttp-gateway/v1/third-party-hosts` to a `GATEWAY_HOSTS` name, through OHTTP only, is
  answered by the gateway with the hosts it carries and their routes (versioned JSON with a
  `revision` that names the document, a `scope`, `etag`/`if-none-match`,
  `cache-control: max-age`; an inner 503 while the process has no complete list). Only the names wallets address
  are published, never an alias target or a credential. With the default `off` the path is
  handled as before.
- The replay class of an inner request (READ or WRITE) is decided once per request instead of
  at each replay stage; the result is the same for every existing route.
- Logs: the path of an inner request whose authority is neither a `GATEWAY_HOSTS` name nor a
  `BACKENDS` alias (refused with the inner 403) is logged as `(unknown authority)` instead of
  the path the client sent, which could carry resource ids of a third party. Paths to the
  gateway's own hosts and to aliases are logged as before.
- The tip a follower holds from its own lightwalletd while the leader's tip stopped moving is
  served for at most 30 s in total after its lightwalletd last answered with it (it is served
  as seen then and goes stale at that bound; before, every tick served it anew, so it could
  stay fresh for up to about 60 s, and it stayed fresh after it was dropped). Once it is dropped
  and the stored tip is not confirmed, no tip is served (requests go upstream) until the next
  confirmation. A follower that takes the lock over keeps serving the tip it held while what it
  indexes is lower, until the hold ends (it stepped back to the lower indexed tip at the
  takeover). It is dropped earlier by a reorg it indexes, and when it takes the lock and the
  stored chain is no longer the one the tip was held on, or could not be checked (the index
  entry at the last stored height it saw is missing or unreadable: a follower checks again on
  its next read, a process taking the lock drops the held tip), and when it indexes a lower
  tip that is not a block of the held tip's chain (its lightwalletd moved to another fork that
  extends the indexed tip without a reorg). That chain is fetched from the follower's own
  lightwalletd with the held tip (one `GetBlockRange` of at most 100 blocks above the stored
  tip, only when the held tip changes); without it (more blocks, or the fetch failed) the held
  tip is served until the hold ends in that case; a fetch that gave nothing is not repeated
  until the stored tip or the follower's own tip changes. A follower uses that chain too: a
  stored tip that is not the block the held tip's chain has at that height drops the held tip
  at once (it waited for the index check or the hold's end), on an ordinary read and on a
  scheduled probe alike: such a probe asks nothing and starts no new observation, the stored
  tip is served. A scheduled probe that keeps the held tip
  keeps the stored tip it is checked against too (it replaced it with the current stored tip
  unchecked). The held tip is also dropped when the
  stored chain is seen to fork above the stored tip it was first observed with: another block
  at or below the last stored height read while holding, or an index entry at that height that
  no longer names the block read there (only a fork at or below the first observed height
  dropped it before).
- The leader confirms the indexed tip (`{chain}tip_seen`) only while the tip moved at most
  10 minutes ago by `{chain}tip_at`, the time stored with the tip, instead of for 300 ticks with
  the same tip and 15 ticks behind it in a row: the counters started again on every leader
  change and on alternating answers (behind, then at the tip), so a tip could stay confirmed
  indefinitely while no process saw a new block. The 15-tick bound behind the tip still
  applies, and still hands the lock over. A leader that continues a stored tip without
  `tip_at` (written by a leader of an older version) counts from when it took it over and
  writes `tip_at` with its first confirmation. `ohttp_chain_tip_age_seconds` of a leader that
  took over now reports the stored tip's age (it reported the age of the last tip that process
  itself wrote, or nothing).
- Leftover confirmations. A confirmation value is never below the stored `tip_at`, and higher
  than the previous one per process: above the last value the same process wrote, not
  necessarily above one another process wrote. A follower that reads a `tip_seen` older than
  `tip_at` takes it for a leftover of an earlier leader (the tip was moved by a leader that
  does not confirm) and refreshes the tip on every read at once, but only within the age
  bound: while the tip moved at most 10 minutes ago by `tip_at`; an older one is refreshed
  only by a changed `tip_seen` (see below). Before, a follower restarted under such a leader
  had no tip until the stored tip next moved (up to one block interval).
- A leader that takes over a stored `tip_at` ahead of its clock (written by a process whose
  clock is ahead) counts the 10-minute confirmation bound from the takeover at the latest, not
  from that future time (the bound could last for the skew on top). Its confirmations stay at
  or above the stored `tip_at` (only the age is clamped), so followers do not take them for
  leftovers, which they would refresh on every read for as long as that `tip_at` looks recent
  to them. A leader never writes the same `tip_at` twice in a row (a tip in the same
  millisecond as the previous one, or as the `tip_at` in the store when it took the tip over,
  a leftover included, gets the next value); otherwise `tip_at` is its clock, also
  after the clock stepped back, and the bound counts from that clock.
- After a rollback to a leader that writes neither `tip_at` nor `tip_seen`, the keys of the
  newer leader stay behind. A follower that sees the stored tip change while `tip_at` does not
  treats that `tip_at` as unknown until it changes: the tip is refreshed on every read, as
  under a leader without `tip_at` (it went stale 10 minutes after the leftover `tip_at`), and
  no stale-leader probe is based on it. A process that takes the lock in that state counts
  the tip's age from then and writes `tip_at` with its first confirmation. This is decided per
  process, from two of its own reads: a process started under such a leader has no earlier
  read and takes the leftover `tip_at` as the tip's time on its first read, until the stored
  tip next changes (about one block interval; meanwhile the tip is refreshed only within
  10 minutes of that `tip_at`, as under a leader of this version). The verdict stays until
  `tip_at` changes. Only consecutive values differ: a `tip_at` equal to one a follower read
  several tips earlier (reads missed in between, the same millisecond) is taken for a leftover
  until it changes.
- A follower under a leader it takes for one that does not confirm (a `tip_seen` older than
  `tip_at`, or one that stays the same while the stored tip changes) refreshes the tip on
  every read only while the tip moved at most 10 minutes ago by `tip_at`; an older tip is
  refreshed only by a changed `tip_seen` and goes stale otherwise, the same as under a leader
  of this version (it was refreshed without a bound). Without a stored `tip_at`, or without a
  `tip_seen` key, such a leader is followed as before.
- The pinned backfill workers and the sweep write through the store they chose, bound to the
  generation of that choice, like the cursor: once another store is chosen (the write store
  connected, the store found read-only or writable again), a fill in flight sends no entry and
  the worker chooses its store again; a sweep pass sends no further entry, hole or mark and
  ends. Before, the fill chose its store again on its own, so a height claimed on one store's
  cursor could be written to another. The generation is checked in the gateway before a
  command is sent, not by the store: a command already sent completes on the store it was
  bound to (for an entry an idempotent `SET NX` of a finalized height), never on another, and
  a sweep claim is still renewed and released by its own token on its own store. A sweep fill
  in flight checks every second whether its store was replaced and is then abandoned (its
  upstream fetch too) and its claim released, instead of being renewed until the fill timeout
  (60 s; the batch stayed claimed meanwhile). The check does not run while a renewal of the
  claim waits for the store, so the fill ends within a second plus the bound of one claim
  command (four store timeouts, at least 2 s on a separate write store) of the change; the
  release of the claim is one more such command, checked by its token. Such a fill is counted (`ohttp_cache_requests_total{rpc="GetTreeState",
  result="pinned_sweep_superseded"}`, new; a fill whose claim was lost to another process is
  not), and so is the height a worker had claimed when its store is replaced during the fill
  (`result="pinned_backfill_superseded"`, new; that store's sweep finds the height if it is
  chosen again). The backfill cursor's `INCR`/`DECR` on a separate write store are bounded like
  the sweep's commands there (four store timeouts, at least 2 s); they had four store timeouts. A worker
  checks whether a height is present on that store too (it checked `REDIS_PINNED_URL`, which
  with `REDIS_PINNED_WRITE_URL` set is a replica of it), and the existence checks and the
  sweep's commands on a separate write store are bounded like its writes (at least 2 s), so a
  slow answer is not taken for a missing entry.
- A `ROLE` probe that was in flight when another pinned write store was chosen no longer acts
  on that store: it neither lifts its pause (a write store that connects is asked before its
  first use) nor pauses it when the probed store answered as a replica or not at all; a
  read-only answer to a write pauses pinned writes only while the store and the choice it was
  written under are still current. Callers that ask the same store at the same time after a
  pause all get it once it answers as writable.
- Pinned backfill workers (`PINNED_BACKFILL_WORKERS`) are started also when the store the
  entries go to is a read replica at startup: they wait and start once it takes writes (asked
  again every 5 minutes, as pinned writes are), so a promoted replica gets its backfill without
  a restart. Every worker, and the sweep behind the cursor, uses the same store, bound to the
  generation of that choice: when the store changes (the write store connected, the store found
  read-only or writable again) or its cursor fails, the workers choose again and wait while none
  takes writes; the sweep skips its passes meanwhile. A
  `REDIS_PINNED_WRITE_URL` that is unreachable at startup is connected in the background
  (backoff 1 s up to 60 s) instead of staying off until a restart; once connected, its `ROLE` is
  asked before the first write to it.
- The pinned backfill and sweep no longer fill heights below the network's Sapling activation
  (419200 for the network label `mainnet`, 280000, the testnet one, for `testnet` and any other
  label), whatever `PINNED_TREESTATE_RANGE` says: there is no tree state there and lightwalletd
  answers those heights with an error, so with a range that starts lower every one of them
  became a hole of the sweep, retried 10 times (up to 100 holes per pass, three failing upstream calls each), while
  the sweep's mark crawled through them. The workers move the shared cursor past them in one
  step (forward only; the cursor still counts from the range start), the sweep starts its mark
  there, and holes below it are dropped without an upstream call; they are counted, and
  logged (one line with their number at most once a minute), once the store has removed them
  (a store that refuses the removal keeps them for a later pass). That includes holes below
  the range start, left over after `PINNED_TREESTATE_RANGE` was raised. A cursor step that
  fails is logged (at most once a minute) and tried again before the worker's next claim,
  until a claim is past those heights. `result="pinned_sweep_dropped"` now has two causes: a hole
  below that height, and a hole whose 10 answered retries are used up. Lookups in the range
  are unchanged, and so is the handling of every other failing height (three attempts, then a
  hole, dropped after 10 answered retries; no answer counts nothing): an error status of the
  upstream is not taken as a verdict about the height, since lightwalletd answers every
  failure of this call, an unreachable node included, with the same status. A batch whose
  heights are all holes still moves the mark on.
- A follower bounds the age of the stored tip from below by how long it has read the same
  stored record (the tip, its `tip_at` and, when the stamp below vouches for the read, the
  stamp's nonce) on its own monotonic clock. A `tip_at` ahead of a follower's clock (a writer
  clock ahead, or its own clock behind) read as an age of 0 for the skew, which delayed by as
  much the stale-leader probe and the takeover after it, the 10-minute bound on following a
  leader that does not confirm, and, after a takeover, the new leader's confirmation bound. Each
  of them now comes at the same read as before or at an earlier one: a follower meets the
  probe condition `CHAIN_TIP_STALE_SECS` after its first read of an unmoved record, whatever
  the skew, and a process that takes the lock counts the confirmation bound from its first
  read of that record as a follower (from the takeover without one, as before). Nothing stored
  changes. Another record starts the count again (the stamp key alone lost: see below); a read
  with a tip and no `tip_at` that counts clears it, a read that returns no tip (a store error,
  no key) leaves it, and a `tip_at` the process writes as leader clears it.
  `ohttp_chain_tip_age_seconds` on followers reports the larger of the two ages. New gauge
  `ohttp_chain_tip_time_ahead_seconds{network}`: how far the stored `tip_at` was ahead of the
  process's clock at its last read as a follower or at a takeover (0 when it was not, or
  without a `tip_at`): a discrepancy between the stored time and this clock (a writer clock
  ahead, this clock behind, or a clock step), not a proven cause. One warning per record when
  the probe condition is met by the local count alone.
- New chain key `{chain}tip_stamp` =
  `1:<tip_at, Unix ms>:<nonce, 16 lowercase hex digits>:<lowercase hex of the stored tip value>`,
  written by the leader in the same fenced script as every `tip_at` it writes (with a new tip,
  and the pending `tip_at` of the first confirmation of a tip taken over without one), with a
  new random nonce per write (see below for the one derived nonce) and the TTL of the other chain keys; never without `tip_at`, never
  for a `tip_at` it only read. Followers (and a process taking the lock) read it in the same
  `MGET` as the tip and use it as positive evidence only: a stamp that names exactly the stored
  tip and `tip_at` makes that `tip_at` the tip's time, unless the process remembers a leftover
  verdict for that `tip_at`, or read this stamp value before next to another stored tip (a
  leader that writes no `tip_at` moved the tip away and back). Two tips written with the same
  millisecond, a handover between leaders with skewed clocks and reads a follower missed are
  thus no longer taken for a tip written without its time while the stamp is there. Any other
  stamp (absent, unparsable, another tip or time) leaves the inference from two reads as it
  was. Mixed versions: older followers ignore the key, older leaders do not write it (followers
  of this version then infer as before); the other keys keep their format, meaning and
  writers' rules; after a rollback the key expires.
- A fill of the pinned sweep that is abandoned (another store chosen, its claim lost, or its
  60 s fill timeout) no longer cancels its upstream `GetTreeState` call in flight: the sweep's
  calls run in a task of their own and the fill only stops waiting for it; the call runs to
  its own end and its answer is dropped, no write is started for it (as before, a store
  command already sent completes on the store it was bound to: an idempotent `SET NX` of a
  finalized height). A cancelled call can cost the node behind lightwalletd an RPC slot. Each
  call holds one of 3 permits per cache from before it is spawned until its task is gone
  (completed, panicked, or dropped at shutdown), so at most 3 sweep-started upstream calls are
  alive per cache, awaited or abandoned. A fill waits for a permit only while all three are,
  within its fill timeout (checking every pause whether its store is still the one chosen; the wait is not an
  attempt), and one that got none ends like a fill that timed out (no answer: the height
  becomes a hole of the batch, nothing counted against it). A call that panics is a failed
  attempt. New `ohttp_cache_requests_total{rpc="GetTreeState",result="pinned_fetch_detached"}`:
  a sweep fill was abandoned while one of its calls was in flight. The backfill workers are
  unchanged (they never abandon a fill). The fetch given to the backfill must end by itself
  within a bound; the gateway's (`proxy::forward_to_backend`) is bounded as a whole by
  `LWD_TIMEOUT_SECS`.
- The gateway's store-backed tests (the test Redis on `127.0.0.1:6379`) follow one policy:
  with the store they run; without it they fail, with a message naming the store address, the
  error of the first connection and the opt-out. New test-only `OHTTP_TEST_ALLOW_NO_STORE=1`
  makes them return early instead (passed, one line on stderr), and is ignored when `CI` is
  set. Before, most of them were skipped silently without a store unless `CI` was set. For
  the cache, store-connection and `tests/set_nx_retry.rs` tests the check is the test's own
  first connection (bounded to 5 s); the handler tests (`store_up`) probe with a bounded
  connection of their own, as they connect through their configuration. A store lost during
  a test fails it. A test store that refuses `CONFIG SET appendonly` (an error reply; needed
  by the local AOF test) is handled by the same policy (it passed silently); a store lost
  there fails the test. `tests/store_failover.rs` (opt-in by `OHTTP_FAILOVER_REDIS`, its own
  primary/replica pair) and `cache_retry_test.rs` (uses the store only if it is there) keep
  their own rules. No production code changes.
- The attempt that loses a hedged lightwalletd read is no longer cancelled: it runs to its end
  in a task of its own and its answer is discarded. Cancelling a call makes lightwalletd
  cancel the node RPC behind it, which can cost the node an RPC slot. The detached attempt's
  head is still bounded by the call's head deadline; its body is read to the end (a server
  stream sends its head while the call still runs) for at most 10 s and 8 MiB (a frame
  without data counts as one byte; the reader gives way to other tasks every 64 frames). One cut by
  these bounds is cancelled then, as any call that runs into its deadline: an instance that
  does not answer within the call's head deadline still gets that one cancellation, the
  detached attempt saves the ones that answer after the race and within it. A loser whose
  request was not given to a connection yet (still connecting) is dropped as before: nothing
  of it was sent. Each holds a permit
  of a second set of `LWD_HEDGE_MAX_INFLIGHT` permits until it ends, none of the hedge permits
  (those go back when the race ends, as before) and none of `MAX_INFLIGHT_LWD` (the caller's
  permit covers the attempt whose answer it reads): hedging now adds at most twice
  `LWD_HEDGE_MAX_INFLIGHT` concurrent lightwalletd calls instead of once, and no request waits
  for a detached attempt. With all of them in use the loser is cancelled as before. Whatever a
  detached attempt ends with settles nothing, as when it was cancelled: no `/healthz` outcome,
  no timeout counted, its instance neither skipped nor cleared (a late head does not reset the
  count of lost hedges). New values of `ohttp_lwd_hedges_total{event}`: `loser_detached`,
  `loser_cancelled`, `loser_expired`. Both attempts are still dropped when the caller itself
  goes away. No new variable.
- A lightwalletd call whose connection ended before the request was written to it is sent once
  more on a new connection (to another instance when `LWD_ENDPOINTS` has one), within the same
  deadline, `SendTransaction` included; before, only a connect error was followed by that retry
  for a `SendTransaction`. "Not written" is exactly what the HTTP client reports as such: it
  got the request back unsent (the connection was not ready, or its task ended with the request
  still queued), or the connection was closed between its handshake and the request. The
  client already resends such a request itself on a reused pooled connection; this covers a
  connection that was new. Every other error still fails a `SendTransaction` without a retry,
  as does a deadline: a failed handshake, a request the connection refused to start and a
  failure after the request was written are one error kind to the gateway, and a stream the
  peer refused or a connection it is shutting down count as written. New
  `ohttp_lwd_unsent_retries_total{network,call="send|other"}`; reads retried for this reason
  count in `ohttp_lwd_read_retries_total` as before.
- A chain leader that takes over a stored tip whose `tip_at` is more than 2 s ahead of its
  clock replaces it: its first confirmation of that tip writes, in the confirmation's fenced
  script, `tip_at` = the time it counts the tip's age from (the takeover, or its first read of
  the record as a follower) and the stamp for it, as it already did for a tip taken over
  without `tip_at`. The leader's own confirmation bound is unchanged; followers now read the
  same age instead of 0 for the skew. Within 2 s the value is kept as stored, as before. A
  leader whose own clock stepped back by more than 2 s since it wrote or took over the tip
  does the same with its next confirmation, when the step leaves the stored `tip_at` more
  than 2 s ahead of its clock: the tip's time becomes now, less the local
  (monotonic) time since the tip moved. Whatever the step, a leader now also counts its
  confirmation bound on its local clock since the tip moved (or since the time it took over
  with): the bound ends 10 minutes after the tip moved instead of the step later, and a tip
  past it by the local clock is not confirmed again by a step back. (A wall clock that
  jumped ahead still ends the confirmations early, and they resume when it is corrected
  while the tip is within the bound by the local clock, as before.) A follower of this
  version keeps its local count of the tip's age across
  such a replacement: the tip did not move. It recognises one by the stamp: the leader stamps
  a `tip_at` that replaces a stamped one with the next nonce of that stamp's line (the same
  upper 32 bits, the lower 32 bits one higher; every other stamp still gets a random nonce,
  and the stamp's format is unchanged), and the follower goes on counting for the same tip
  with an earlier `tip_at` and another nonce of the line it read, however many replacements
  it did not read in between (a line has 2^32 nonces). A `tip_at` that had no stamp the leader read, and any other
  write of the same tip (it may have moved away and back; a random nonce is on the line by
  a coincidence of 32 bits), is another record as before. Mixed
  versions: a follower of the previous version finds the stamp vouching for the new value and
  starts its local count again, once; one
  that knows no stamp reads `tip_at` as it always did (a `tip_at` that changes under an
  unchanged tip is never taken for a leftover), and it is the write such a version does itself
  for a tip without `tip_at`, with that write's limit: such a follower, if it missed the
  value replaced, takes the tip's time for a leftover when the replacement is, to the
  millisecond, the `tip_at` it read with the tip before (a leader that replaces its own
  `tip_at` avoids the value last stored with the tip before; it does not know an earlier
  value of that tip that was itself replaced, and a new leader knows neither). A tip past the confirmation bound is not confirmed and not
  rewritten. New `ohttp_chain_tip_at_rewrites_total{network}`.
- When only the `{chain}tip_stamp` key is lost (evicted) while the tip and `tip_at` it vouched
  for on a process's last read stay, the process keeps what the stamp said: `tip_at` is the
  tip's time and the record is the same one, so the local count of its age goes on (it
  started again before) and a takeover counts from the first read. That ends when the tip or
  `tip_at` changes or any stamp value is read. New `ohttp_chain_tip_stamp_lost_total{network}`
  (counted when a loss is first read; again when the stamp came back and was lost again).
- Known limits of the chain follower and the pinned backfill after these changes:
  - The drop of a held tip on a scheduled probe without a new observation applies to a held
    tip that is still held when the probe starts (the stored tip is not on its own chain).
    When the index check itself drops the held tip on a probe tick (the stored chain changed
    at or below the stored tip it was checked against), that probe goes on as an ordinary new
    observation of the process's own lightwalletd tip, as before these changes: a stored tip
    that has not moved for the stale bound while its own lightwalletd is ahead is what the
    stale-leader handling serves.
  - A `tip_at` ahead of the clocks by at most 2 s and one of a tip that is past the
    confirmation bound stay stored until the tip next moves: processes of this version bound
    its age by their own reads of the record, older followers in a mixed fleet keep their
    uncompensated age. A leader whose clock is behind the others by more than 2 s replaces a
    correct `tip_at` of a tip it takes over by its own older time (as every tip it writes
    carries): followers probe their lightwalletd more often until the tip next moves; a
    leader whose clock is ahead of the one that wrote `tip_at` reads the tip as that much
    older and may stop confirming it early, as before. A
    process restarted during a stall (every process, after a restart of
    the whole fleet) counts again from its first read while the skew lasts; the store's clock
    is not used. The local count can exceed the record's age only after a state the process
    missed: a leader of an earlier version moved the tip away and back to the same block with
    the same `tip_at` value between two of its reads (the same millisecond again, or no
    `tip_at` written at all), or the store went back to an older copy of the record (a
    failover that lost writes); the effects are those of a writer clock behind (probes of its
    own lightwalletd, a takeover only with that lightwalletd ahead twice, an early end of the
    refresh under a leader that does not confirm, or of a taken-over tip's confirmations).
    After a takeover the age origin is a wall-clock value again; a backward step of the
    leader's clock no longer extends its confirmation bound (counted on its local clock too),
    and the stored `tip_at` is replaced only when the step leaves it more than 2 s ahead:
    after a smaller step, or one that leaves `tip_at` in the past, followers read the tip
    as younger by the step (never younger than their own count of it).
  - Without a stamp that vouches for the read the inference from two reads keeps its limits:
    for tips written by a leader of an earlier version (a rolling upgrade, a rollback) and a
    tip a leader took over without rewriting `tip_at`, until a leader of this version writes
    the next tip; when the stamp key alone was lost (evicted) while `tip_at` stays and the
    process did not read the stamp next to that tip before, or the tip then moves with the
    same `tip_at` and no stamp again (with
    writers of this version a wrong verdict then needs the same millisecond twice); a process
    that starts under a leader that writes no `tip_at` trusts a leftover `tip_at` on its first
    read, as before (the stamp never says "leftover"); and a leftover verdict stays until
    `tip_at` changes.
  - An abandoned sweep call keeps the request-path concurrency permits it holds until it
    ends (up to 3 sweep calls per cache instead of 1). Upstream calls are still cancelled by
    the fetch's own timeouts, by a caller that goes away, by the losing attempt of a hedged
    read when no detached permit is free or its bounds cut it, and when the process or
    runtime stops, as on every request path. A sweep fill that waits for a permit (three
    sweep-started calls alive) is delayed up to its fill timeout; a fetch that never
    ended would keep its permit (the gateway's is bounded by `LWD_TIMEOUT_SECS`).
  - With `OHTTP_TEST_ALLOW_NO_STORE=1` outside CI the store-backed tests pass without
    running (each prints one line); only their first connection is checked, a store lost
    later fails the test.
- A pinned store whose `ROLE` does not answer in time (or fails on the connection) is treated as
  not writable and asked again after 30 s, instead of as writable: pinned writes and the
  backfill wait meanwhile. A store without the `ROLE` command (an error answer) stays writable.
- Pooled third-party HTTPS connections are kept idle for 30 s instead of 60 s, below the 60 s
  idle timeout common for servers and load balancers: with equal timeouts a request could be
  written to a connection the server was closing at that moment and fail.
- Tip-scoped `GetLatestTreeState` answers are cached and served only when their height and hash
  are the tip of their key, `GetLightdInfo` answers only when their `blockHeight` is at least
  the tip height (it carries no hash: this catches an instance that is behind, not one on
  another fork at the same height), on the client path and in the prefetch. An instance one
  block behind, or on a losing fork, could fill the entry of the new tip for its whole lifetime,
  and the prefetch never corrected it. An answer that does not match is not cached; a stored
  entry that does not match (written by an older gateway during a rolling upgrade) is deleted
  on read, answered as a miss and fetched again. Both are counted in the new
  `ohttp_cache_tip_mismatch_total{phase="store|lookup"}`; `ohttp_cache_requests_total` keeps one
  result per request. In normal operation every instance answers at the tip, so the hit rate
  does not change.
- The prefetch fetches a `GetTreeState` or `GetTransaction` entry again when the stored one is
  no longer current against the index (left from before a reorg), instead of treating any
  stored value as present.
- A `GetSubtreeRoots` end marker is never lowered for the same tip: a Client's fetch answered
  by an instance that is behind no longer replaces the prefetch's count from the tip block with
  a smaller one, which hid the roots above it from every request at that tip. The marker is
  written by one compare-and-set script on the cache Redis (after the epoch check); a store
  error writes nothing.
- The lightwalletd protocol files the gateway's hand-written messages follow
  (`compact_formats.proto`, `service.proto`) are vendored in `gateway/proto/lightwalletd` from a
  pinned upstream tag, and tests check the field numbers the gateway decodes against them.
- The prefetch's "one run at a time" flag is cleared however a run ends (a panic or a
  cancelled task included), so one failed run no longer stops every later prefetch.
- **Hedged lightwalletd reads** replace the retry at half of the head deadline: a read without
  a response head after `LWD_HEDGE_DELAY_MS` (new, default half of the head deadline, the old
  cut-off; `0` turns it off) is sent to a *different* `LWD_ENDPOINTS` instance as well, while the
  first attempt keeps running; the first head wins and the other attempt is cancelled. Both
  share the call's whole head deadline, so a read that takes 6 s of a 10 s deadline no longer
  fails on both attempts. Without `LWD_ENDPOINTS` (or with one instance) reads are not hedged,
  and the one attempt keeps the whole deadline (before, it was cut at half and retried on a new
  connection to `LWD_ADDR`). Never hedged: `SendTransaction` and any path that is not a
  `CompactTxStreamer` read, heavy calls (long block ranges, transactions, transparent-address
  and subtree queries), `GetMempoolStream`, and calls to other backends; a call is still
  retried after a connect error (any call) or a transport error (reads) as before, but never
  after a hedge was sent. The loser of a hedge race is not a failure (not counted as a timeout
  or as a failed call, no pool replacement); an attempt that fails is settled as failed even
  when the other one answers. An instance that loses two hedges in a row, without a response
  head from it in between, is skipped for 30 s at that and each further loss
  (`event="loser_skipped"`), so one that accepts calls and never answers leaves the rotation
  after its second slow read (it was skipped after the first before) and is tried again every
  30 s. Two bounds: a hedge takes a permit of `LWD_HEDGE_MAX_INFLIGHT` (new, default an eighth
  of `MAX_INFLIGHT_LWD`, at most 16, at least 1; up to the semaphore maximum) on top of the
  caller's lightwalletd permit (hedges are not counted in `MAX_INFLIGHT_LWD`), taken when the
  hedge is sent and held until the race ends (a read that is not hedged holds none); and a rate cap: six hedges a minute are always allowed, above that
  hedges stay at most one in ten of the hedgeable reads of the last minute. New metric
  `ohttp_lwd_hedges_total{event="started|won|no_permit|rate_limited|loser_skipped"}`;
  `ohttp_lwd_read_retries_total{reason="timeout"}` is no longer produced.
- The call's head deadline is fixed before `LWD_ENDPOINTS` is resolved and covers the
  resolution and every attempt (a slow resolution extended it). One resolution runs at a time
  (abandoned after 30 s); callers use the previous list meanwhile and wait (at most 1 s) only
  for the first one, instead of every caller resolving again when the list expired.
- Log lines at warn and info level no longer carry lightwalletd instance addresses or the
  resolved names: the instance of a failed attempt, the target of a retry or hedge, the
  `LWD_ENDPOINTS` name and `LWD_ADDR` (the startup line's `lwd` field, the backend of the
  cache connection line, the permanent tier backfill line) are logged at debug level only.
- `SendTransaction` has its own deadline class again: `LWD_SEND_TIMEOUT_SECS` (new, default
  `LWD_TIMEOUT_SECS`, as before the unary deadline existed) instead of `LWD_UNARY_TIMEOUT_SECS`
  (10 s), which cut slow broadcasts and showed the client an error for a transaction that may
  have been sent. Counted as `class="send"` in `ohttp_lwd_timeouts_total`. A slow broadcast can
  thus hold its request up to `LWD_TIMEOUT_SECS` (default 80 s) again: relay and client
  timeouts must allow that, or `LWD_SEND_TIMEOUT_SECS` must be set lower.
- Transparent-address streams (`GetTaddressTxids`, `GetTaddressTransactions`,
  `GetAddressUtxosStream`) keep the rest of `LWD_TIMEOUT_SECS` until their first complete
  message (its 5-byte prefix and the whole length it declares), not only for the response head:
  a lightwalletd that sends the head, or part of the first message, before the node's address
  query ends is no longer cut after `LWD_STREAM_IDLE_SECS`.
- A late response head of `GetMempoolStream` (an empty mempool) or of a transparent-address RPC
  (a slow node query) no longer counts as a lightwalletd failure in the `/healthz` error window
  and no longer ejects the instance; only connect and transport errors do. A `GetMempoolStream`
  without a head within its deadline ends cleanly (grpc-status 0) and is counted in the new
  `ohttp_lwd_mempool_no_head_total`, so an instance that does not answer stays visible.
- With `LWD_CONNECTION_POOL`, the pooled client is replaced after three calls within 10 s ran
  into a deadline (at most once per 5 s), instead of after any single one.
- Chain follower fencing: every index entry is now written together with its cached block, and
  every deletion of a reorg (index entries and the cached blocks, nullifiers, tree states and
  subtree roots above the fork), only while the writer holds the leader lock with its own token,
  in the same kind of script as the tip (they were plain writes, and only the tip was fenced).
  A leader replaced while a tick was in flight (a slow block fetch, a pause) could otherwise
  write the index and blocks of another fork, or delete what its successor wrote, before its
  tip write was refused; now the refused batch and every later one are not written and it
  stops leading. The fenced writes no longer accept an absent lock: a paused leader cannot
  write an older tip after the process that replaced it released or lost the lock again; one
  whose own lock lapsed acquires it again on its next tick. A store error or timeout in a fenced
  write (after a timeout its outcome is unknown) now stops the tick and hands the lock over,
  instead of going on without it. One script carries
  at most 32 blocks and 1 MiB of block payload (a larger block goes alone), so large blocks do
  not make a script outlast the store's operation timeout.
- Leader work that runs longer than the lock TTL (a cold start, a catch-up) keeps renewing the
  lock with its own token, and is cancelled as soon as a renewal finds the lock held by another
  process (or no renewal succeeded for a whole TTL), instead of running on until its next write
  was refused.
- The leader confirms the stored tip on every tick its lightwalletd answers with it, in a new
  key `{chain}tip_seen`, and followers refresh their tip only when that value changed (no
  clock comparison between processes), so a tip the leader no longer confirms goes stale on
  every gateway after 30 s; before, followers refreshed whatever was stored on every read. The
  leader stops confirming after 300 ticks with the same tip (at least 10 minutes: a
  lightwalletd stuck at the tip height; at a 75 s block spacing such a gap is rarer than one
  block in a thousand, and during one requests are answered from upstream). A leader whose
  lightwalletd stays below the indexed tip for 15 ticks in a row (about 30 s) gives the lock up
  and does not try to take it again for 5 ticks, so a process with another lightwalletd leads.
  During a rolling upgrade, a leader of the previous version does not write `tip_seen`: its
  followers of this version refresh on every read as before, both while the key is absent and
  while a key left by an earlier leader of this version stays unchanged as the stored tip moves
  (until the value changes again). Older followers ignore the key.
- Stale-leader takeover: a follower takes the lock over only on a second probe in a row with
  the same stored tip (height and hash) and the same lock holder, re-read on every probe, in one
  script that checks both; a refused takeover or another holder starts the observation again.
  Two followers that saw the same stale tip no longer take it from each other, and a holder
  change between probes no longer blocks the takeover forever.
- What a follower serves while its own lightwalletd is ahead of a stale leader follows one
  rule: the highest tip its own lightwalletd answered, for at most 30 s after it last did, while
  the stored tip stays below it on the same chain. A failed or lower probe never makes it step
  back (it used to fall back to the lower stored tip and back up again between probes); it
  serves the stored tip again once the held tip ages out, the stored tip catches up, or the
  stored chain changes at or below the observed height.
- `REPLAY_WRITE_WAIT_MS` and `REPLAY_PEER_WAIT_MS` must stay below about 1.25 s (the budget of a
  housekeeping check of a `WAIT` connection); a pool of one `WAIT` connection is not PINGed
  while it hands out its connection exclusively. A reopen of a `WAIT` connection that starts
  again after a success starts its backoff over.
- A quiet replacement turned into a failover one by a failover signal is counted in
  `ohttp_store_reconnect_total` under that signal's reason as well (it was only counted as a
  timeout). A reopen error other than `LOADING` within a `LOADING` period keeps the backoff
  step reached instead of starting it over.
- Housekeeping also checks the last idle `WAIT` connection of a pool of several (it was never
  checked while the others were busy), as shared work that a WRITE in shared mode still uses
  meanwhile, and no shared check runs while the pool hands out its connections exclusively.
- A replay peer's `WAIT` or retry connection reset while its reopen finished is opened again by
  that reopen (it was left closed until the next request or housekeeping round). A command on a
  `WAIT` or retry connection whose task panics replaces that connection before its slot goes
  back to the pool.
- The third-party cache get/put errors and the permanent store errors are logged at most once a
  minute per kind, like the other per-request store warnings.
- While a switched epoch is in force, a refresh from the security store still counts as done,
  so requests do not each read the store again. The epoch switch warnings and the per-request
  cache store errors (get, set, delete, pinned get and set) are logged at most once a minute per
  kind.
- `confirm_write_nonce` refuses a `PeerCheck` whose peer stage found a replay (fail-closed),
  whatever the caller did with that verdict.
- `WAIT` pool timeouts: the pool round of a timeout is checked under the lock it only moves
  under; a `WAIT` that timed out queued on a shared connection replaces at most that connection
  (only exclusive ones count toward replacing the whole pool). Housekeeping counts a closed
  connection neither as checked nor as the one left free, and a late timeout of a replaced local
  `WAIT` connection is not counted against its replacement. After a failover signal the retry
  prefers the failed connection's replacement for at most one command timeout, then takes any
  usable connection.
- A quiet replacement of a `WAIT` connection that finds the connection already replaced gives
  up only if no failover signal arrived meanwhile; one that did starts its reconnect instead of
  being dropped. A reopen attempt that fails for another reason than `LOADING` starts the
  `LOADING` backoff over.
- A failed command on a replay peer's connection is handled in one place: the failing
  connection is dropped, and the peer's other connections (main, `WAIT`, retry) only if it was
  still the installed one and the error says the node is no longer the primary. The replicator's
  batch path now also drops the `WAIT` and retry connections on such a signal. The PING-failure
  and `ROLE` replica paths replace the peer's connections only if the main connection they
  checked is still installed (its compare-and-swap succeeded), and only then its `WAIT` and
  retry connections; whether a failed `WAIT` or retry connection was still installed is the
  result of its own compare-and-swap. A main
  connection that comes back wakes the requests waiting for a `WAIT` or retry connection, and
  the main reconnect is jittered like the others.
- **New `REPLAY_ONE_SIDED_WRITE_ROUTES` (default empty); WRITEs that are not on it no longer run
  on the verdict of one replay store.** One network partition between the region of the store
  that decides a WRITE and the region of the second store could run the same request twice: a
  `failover`-mode gateway that got no answer from its peer kept its local verdict, and an
  `async-reads` origin on the other side that got no answer from the hub ran it on its own store
  (`REPLAY_PEER_FAIL_CLOSED_WRITES=0`, or `REPLAY_UNAVAILABLE_FALLBACK` with its own replicas),
  so the same sealed bytes delivered to both ran at both. The earlier statement that this needed
  two failures at once was wrong. A WRITE now runs only once both the deciding store and the
  second store the gateway consults synchronously took its nonce as new; every path that would
  admit it on one store's verdict fails it closed (inner 503 / grpc-status 14), counted as
  `ohttp_replay_write_fallback_total{result="one_sided_refused"}`: a peer tolerated by
  `REPLAY_PEER_FAIL_CLOSED=0` (`sync` mode) or `REPLAY_PEER_FAIL_CLOSED_WRITES=0` (new
  `path="peer_tolerated"`), a fallback store that did not answer the check of every WRITE
  (`check`, `window`, `hub_check`, `hub_window`), and the unavailable fallback
  (`local_unavailable`, `hub_unavailable`). The short-acknowledgement paths are unchanged (both
  stores took the nonce there). Routes on the new list (same syntax as `REPLAY_READ_ROUTES`) keep
  every one-sided path; list only routes whose upstream refuses a second copy of the same request,
  e.g. `lwd=POST /cash.z.wallet.sdk.rpc.CompactTxStreamer/SendTransaction`. **Upgrading:** a
  deployment that relies on WRITEs running while a peer, the hub or a standby store is
  unreachable must list those routes before it upgrades, or those WRITEs fail closed during such
  an outage. READs are not affected. A `failover`-mode origin without the peer fallback consults
  no second store and is unchanged.
  A both-stores WRITE whose peer or standby `SET NX` timed out (on the check, the fallbacks and
  the `sync`-mode peer check) asks that store once more, at once, over another connection (one
  of its `WAIT` connections, or, only with `REPLAY_PEER_WAIT_REPLICAS=0`, one retry connection of
  its own per peer and standby store, kept warm by housekeeping)
  (`SET key value NX GET` with the request's own value): **needs Redis >= 7.0 at those stores;
  older ones answer an error and the WRITE fails closed as before.** With
  `REPLAY_PEER_FAIL_CLOSED=1` a `sync`-mode peer whose `SET NX` only timed out is asked again
  the same way once the request is classified (READs too) before the request fails closed. The
  admission API takes the local check's result (`LocalCheck`, from `check_replay_detailed`) in
  every later step, and the peer stage's result (`PeerCheck`, no public constructor, bound to
  the request's nonce) in the steps after it, so what a check saw can neither be dropped nor
  forged nor used for another request.
- The local replica wait of a WRITE sends `SET XX` and `WAIT` as one pipeline on one
  connection (the peer wait already did). Sent as two commands, a reconnect of the connection
  between them had the `WAIT` count the replicas of a new session, possibly on another node
  where the nonce never was. The retry after a failover signal sends both again, so the nonce
  is looked up again on the node the connection now reaches.
- New `REPLAY_WAIT_CONNS` (default 8, 1 to 32): every store (the local security Redis, each
  peer, each standby store) gets a fixed pool of dedicated `WAIT` connections instead of one.
  `WAIT` blocks its connection, so during a resync, when every `WAIT` takes its whole timeout,
  concurrent WRITEs queued on the single connection and the later ones ran out of time, which
  counted as "no answer" and failed closed instead of taking the short-acknowledgement fallback.
  While a store's `WAIT`s are fast the pool is shared (many `WAIT`s in flight per connection,
  round robin, no cap on the WRITE rate, as with one connection before); for 10 s after one took
  longer than its round trip plus half its timeout, came back short or timed out, each
  connection serves one WRITE at a time, which caps the WRITEs waiting for that store at
  `REPLAY_WAIT_CONNS / (round trip + WAIT time)` per second (40 per second per pod for a store
  100 ms away with a 100 ms `WAIT`). A WRITE that cannot get a connection while its whole `WAIT`
  still fits in its budget is decided as a short acknowledgement once a `SET XX` on the main
  (primary-checked) connection found its nonce (`ohttp_replay_wait_saturated_total`), and fails
  closed as before when no fallback can confirm it. A connection stays with its WRITE until its
  `WAIT` is answered, also when the request gave up (a reply that never comes replaces the
  connection after 5 s more), so no WRITE queues behind another's `WAIT` there. Connections per
  gateway: up to `REPLAY_WAIT_CONNS - 1` (7 by default) more per store than before. A peer's
  `WAIT` connections are opened and reopened in the background (jittered backoff); confirming a
  WRITE at a peer runs under one deadline for both attempts and waits for a connection to open
  only while none of that peer's pool is open, instead of up to 2 s per attempt. An I/O error or
  timeout on a peer `WAIT` connection no longer drops the peer's main connection; only a signal
  that the node is no longer the primary does.
  A connection is leased only once no shared `WAIT` is left on it, never used shared while
  leased, and every command keeps its connection until answered. Only an open connection that
  reaches the primary is handed out; a request waits for one to be released or (re)opened until
  the last moment its whole `WAIT` still fits, then takes the saturated path if every open one
  was busy, or fails closed if none was open. A `WAIT` without an answer in its budget replaces
  that one connection (only if it is still the current one, never its replacement); a second
  connection of the store doing so within 5 s replaces all of them. A timeout of a connection
  or a pool replaced since its command went out is ignored. A command is never sent once its
  request's deadline has passed, and the task that owns it records its outcome (the pool's mode,
  the connection's timeout) also when the request went away meanwhile.
- Replay refusals ("Replay detected", "Replay detected at a peer origin") are no longer logged
  with the request's hash (`body_hash`, the replay nonce): it identifies one user request. The
  counts stay in `ohttp_replay_rejected_total`.
- `/healthz` counts the security Redis as down while its connection is pinned to a demoted
  primary: its last `ROLE` answer said replica, or a reconnect after a failover signal has been
  pending for more than 2 s (the endpoint does not yet reach a node that says `ROLE master`; a
  reconnect done within that does not count). `PING` still succeeds on such a node, so
  `/healthz` stayed 200 while every replay write was refused there.
- `/healthz` also fails while the peer stores decide for an unreachable security Redis
  (`REPLAY_UNAVAILABLE_FALLBACK`) but the WRITEs decided there keep failing closed although every
  peer answers its PING (a peer short of replicas, a full write-back queue, a broken peer `WAIT`
  connection; and WRITEs refused for `REPLAY_ONE_SIDED_WRITE_ROUTES` because the own store gives
  no verdict, not those a peer's silence refused): new `REPLAY_FALLBACK_HEALTH_FAILURES` (default
  20 in a row, `0` = off) and `REPLAY_FALLBACK_HEALTH_WINDOW_SECS` (default 60: failures further
  apart start a new count), gauge `ohttp_replay_fallback_writes_failing`. Once withdrawn the
  gateway stays so until the security Redis answers again (a request's replay check or a
  housekeeping PING) or a WRITE through the fallback runs.
  READs that still arrive are decided at the peers as before.
- New `REPLAY_STARTUP_STORES_WAIT_SECS` (default 10): at startup `/healthz` and `/health/startup`
  answer 503 (`ohttp_replay_stores_pending` 1) until every replay peer and standby store is
  connected, with an open `WAIT` connection where its replica acknowledgement is required, and
  the local `WAIT` pool has a usable connection, at most that long, then report ready with a
  warning. Without it a read origin that had just started saw its standby store disconnected
  and refused the WRITEs that both stores must take.
- Housekeeping PINGs the idle peer `WAIT` connections and replaces one that does not answer in
  the background (a middlebox reset an idle connection), and asks every peer that answers its
  PING for its `ROLE`: a peer whose endpoint still reaches a demoted primary is reconnected
  (`ohttp_store_reconnect_total{store="replay_peer",reason="role"}`) instead of being found by
  the next `READONLY`.
- A store connection that keeps meeting a node that answers `LOADING` (restarted, reading its
  data set) backs off between reconnects and between the attempts of one reconnect (0.5 s
  doubling to 8 s, reset by the next successful command) instead of reconnecting every 0.5 s;
  the reopen loops of a replay peer's main, `WAIT` and retry connections apply the same backoff
  after a `LOADING` answer.
  Housekeeping runs every check of a round (the
  epoch sync, the cache store, the dedicated `WAIT` / `WAITAOF` connections, the security store,
  each peer and standby store) concurrently under one 5 s deadline; a check not done by then
  counts as failed; one `WAIT` connection per store is checked per round, in turn, only while
  no request holds it and another one stays idle, and no request gets it until its check is
  answered; a peer's main connection and its `WAIT` (or retry) connections are checked at the
  same time. A peer whose node says it is no longer the primary (`ROLE` replica, `READONLY`)
  loses its `WAIT` and retry connections too, and lends none until its main connection is
  accepted on a primary again. Whether a peer answers is its main connection's verdict alone
  (a slow check of its `WAIT` connections does not change it), and a peer whose `ROLE` says replica is not
  usable for that round. `ROLE` checks have a 1 s budget (was 5 s). Any other failover signal
  ends a `LOADING` backoff at once. Repeated store warnings are logged at most once a minute per
  kind, and store errors in log lines carry only their I/O kind or a listed server code (never
  the server's text after it, nor an address).
- An `async-reads` origin with its own replica wait that tolerates an unreachable peer
  (`REPLAY_PEER_FAIL_CLOSED_WRITES=0`, a route on `REPLAY_ONE_SIDED_WRITE_ROUTES`) queued the
  WRITE's nonce for that peer before its local replica wait; when the wait then failed the WRITE
  closed, the peer still got the nonce later, for bytes that never ran. The hand-off now follows
  the final admission, for any number of peers.
- A store whose ACL does not allow `ROLE` (`NOPERM`) is treated like a store without `ROLE`: its
  connections are accepted without the check against a demoted node (a write on a replica still
  fails with `READONLY`, so replay checks stay fail-closed), and the gateway warns once. Before,
  every primary-checked connection to it was refused: replay peer connections never connected,
  and after the first failover signal the security and `WAIT` connections never got a
  replacement, so every request failed closed until a restart. Granting `ROLE` keeps the check.
- The pinned backfill no longer loses a height for good when the `INCR` that claimed it times
  out after the store counted it (or a worker gives up on it): about every 10 minutes (jittered
  by 10 %) a sweep checks the heights the shared cursor passed, from a shared mark
  (`backfill_verified`, next to the cursor) up to a margin below the cursor (none once the range
  is done), with pipelined `EXISTS` on the store the entries are written to, 500 at a time with a
  short pause in between, and fills the missing ones (`ohttp_cache_requests_total{rpc=
  "GetTreeState",result="pinned_sweep"|"pinned_sweep_failed"}`). Each batch is claimed for all
  processes (`SET NX` with a TTL), so one process sweeps it. A height that cannot be filled is
  kept in a set (`backfill_holes`) and retried by later passes; the mark only moves past a batch
  whose every height is present or kept there. The first pass after an upgrade checks the whole
  range already passed once.
  Batches are aligned to their size, so every process claims the same heights under one key. A
  claim carries a random token of its own, holds 120 s (less than the sweep interval), is
  renewed before and during every fill (each bounded to 60 s) and released by compare-and-delete
  on every way out of the batch, so one that expired and was taken over is never released by
  its first holder; the mark is read again once a batch is claimed and moved only by the
  claim's holder (a fenced script). The hole retries are claimed the same way; a hole that
  failed 10 retries on which the upstream answered is dropped (`result="pinned_sweep_dropped"`;
  passes during an upstream outage do not count), and each height is checked
  again right before it is filled. The sweep of a bounded range ends only once a count of the
  holes says 0.
- The shared cache epoch lives in the security store; while that store gave no answer (the peer
  stores deciding in its place) the gateway kept its last value and missed any operator bump.
  Housekeeping now also reads the replay peers' epochs (one `GET` per peer every 10 s) and keeps
  each as that store's baseline while the own store answers. While the own store is silent, the
  first peer in `REPLAY_PEER_URLS` order that answers is compared with its own baseline; a
  change, or a peer without a baseline yet, moves the epoch here to a fresh random 64-bit value,
  so entries of the old epoch are missed instead of served (`ohttp_epoch_bump_seen_at_peer_total`).
  The peer's value itself is never used (each store keeps its own counter), and once the own
  store answers its value applies again: an operator flush must still increment every store.
  A switched epoch stays until the own store has answered three housekeeping rounds in a row
  (one answer during a flapping outage does not bring the old entries back; the local and the
  peer reads run concurrently under the round's deadline, and a local read not done by then
  starts the count again), then the peers' baselines are taken again. The epoch, the switch and
  the peers' baselines change under one lock, so a refresh from the own store that read it
  before a switch never overwrites the switched epoch.
- A read origin with a confirming standby store (`REPLAY_STANDBY_URLS` with
  `REPLAY_PEER_WAIT_REPLICAS`) asks the standby store about a WRITE's nonce (`SET NX`) at the same
  time as the hub (`SET NX`, then the hub's replica wait), instead of after the hub answered. A
  WRITE now costs the longer of the two paths rather than their sum, which is one round trip to
  the standby store less per WRITE. The verdict is unchanged: a nonce held by either store is a
  replay, and the short-acknowledgement and unavailable-hub fallbacks use the answer the
  standby store already gave instead of asking again. A nonce the standby store took for a
  request the hub then refuses stays held there until its TTL, like the nonce of any request
  that fails closed. Side effects: two copies of one request arriving at two origins within a
  round trip may now both be refused (one takes the hub, the other the standby store), never
  both run; a WRITE the hub refuses now also waits for the standby store's answer (bounded by
  `REPLAY_PEER_TIMEOUT_MS`); and the standby store's peer metrics also count WRITEs the hub
  refused.
- `ohttp_request_duration_seconds` and `ohttp_upstream_request_duration_seconds` use finer
  buckets: 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.15, 0.25, 0.35, 0.5, 0.75, 1, 1.5, 2.5, 5 and
  10 s (were 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5 and 5 s). Calls that cross a long network path
  took one or a few round trips of 50 to 300 ms each, and their quantiles were interpolated
  across buckets up to 0.5 s wide. Every old bound is kept, but rates and quantiles across the
  upgrade are not comparable: the new bounds have no history before a process's upgrade, so
  over a range that reaches back before it (even for a single process) a rate of a new bound
  covers only the part after the upgrade while `+Inf` and the old bounds cover all of it. During
  a rolling upgrade an aggregate such as
  `histogram_quantile(0.99, sum by (le) (rate(..._bucket[5m])))` also adds processes with and
  without the new bounds, with the same effect. Until every process runs the new version and
  the query range starts after that, compute quantiles over the old bounds only
  (`le=~"0.01|0.05|0.1|0.25|0.5|1|2.5|5|\\+Inf"`) or per version. The number of series of both
  histograms roughly doubles.
- **`GATEWAY_HOSTS` is required in `ohttp` mode:** the gateway refuses to start when it is unset
  or empty, instead of warning and sending every unknown authority to lightwalletd. A deployment
  that already sets it is unaffected; one that does not must set it to the gateway's own host
  names before upgrading.
- Third-party backend calls (`BACKENDS`, `https://`) reuse pooled HTTPS connections (idle
  30 s, at most 16 idle per host) instead of a new connection per request, which saves the TCP
  and TLS handshake on every call after the first. Same TLS connector, roots and HTTP/1.1 as
  before; headers, credentials and timeouts stay per request, and a response body that is not
  read to its end (an event stream cut at its timeout) closes its connection instead of
  returning it to the pool.
- A pinned store (`REDIS_PINNED_URL`) that is a read replica is recognised: the gateway asks its
  `ROLE` at startup (and after a `READONLY` answer) and stops sending it pinned writes, which
  only failed and logged a `pinned set error` warning for every such miss. It asks again every
  5 minutes, so a promoted replica is written to again.
- New `REDIS_PINNED_WRITE_URL`: the store pinned entries are written to when `REDIS_PINNED_URL`
  is a read replica (its primary). A final height a replica misses is then fetched once and
  written where every replica gets it, instead of missing on every request at every gateway
  reading a replica. The pinned backfill cursor moves to this store as well.
- `GetTreeState` heights within 100 blocks of a fresh tip are no longer looked up in the pinned
  tier: they are never written there, so the lookup could only miss. They go straight to the
  chain-validated cache, one Redis round trip earlier, and no longer count as
  `ohttp_cache_requests_total{result="pinned_miss"}`, which now counts only final heights the
  tier does not have.
- New `PREFETCH_TREE_STATE` (default off): the chain follower's leader fetches `GetTreeState`
  of each new tip height once and caches it under a Client's key. Wallets ask for the tree
  state at the height they last synced to, so with it these requests are cache hits instead of
  one upstream call per height per gateway. Counted as `result="prefetched"`.
- The `rpc` label of a third-party (`BACKENDS`) request is the method and path pattern of the
  `BACKENDS_POLICY` entry that admitted it (`GET /v0/status`, `GET /*`) instead of `other`, in
  `ohttp_upstream_requests_total`, `ohttp_upstream_request_duration_seconds` and
  `ohttp_request_duration_seconds`. The values stay bounded by the configuration; a request's
  own path, query or ids never become labels. A request no entry admits stays `other`.
  Queries that selected these series with `rpc="other"` need `backend` (or the new values).
- `GetTaddressTransactions` has its own `rpc` label value instead of `other`.

### e2e client

- The key-configuration source is explicit: `OHTTP_E2E_KEY_CONFIG_SOURCE=signed|plain` (any
  other non-empty value fails the run). Unset, the old guess stays as a fallback: signed when
  the config URL contains `/signed` or the answer is labelled `application/json`; such a run
  prints a line saying the source was guessed. An explicit `plain` is never verified as signed,
  whatever the answer is labelled.
- `scripts/test-e2e.sh` always sets the source: `plain` unless the caller sets
  `OHTTP_E2E_KEY_CONFIG_SOURCE`. A signed `CONFIGS_URL` therefore now needs
  `OHTTP_E2E_KEY_CONFIG_SOURCE=signed` (it used to be recognised by its URL). For a relay
  simulator the script sets `OHTTP_E2E_PLAIN_HTTP_RELAY=1`. It exports `NETWORK` (default
  `testnet`), so the e2e client verifies a signed configuration for the network the script
  announces; when the caller had not exported it the client used to fall back to mainnet.
- A relay URL the configuration rules refuse fails the run before anything is sent, instead of
  being posted to as given. Every `OHTTP_E2E_REPLAY_URLS` entry is checked and canonicalized the
  same way, all of them before the first send; an error names the entry's position and the
  rule, never the URL. An `http://` relay or replay URL (a relay or an origin checked over plain
  HTTP in a test network) needs the new `OHTTP_E2E_PLAIN_HTTP_RELAY=1`, which applies the same
  rules but the scheme; invocations that post to an `http://` relay URL must set it (the error
  of a run without it names the variable). Any value other than `1` fails the run.
- `OHTTP_E2E_KEY_CONFIG_SOURCE`, `NETWORK`, `OHTTP_E2E_PLAIN_HTTP_RELAY` and
  `OHTTP_E2E_REPLAY_URLS`: an empty variable counts as unset, and a value that is not Unicode
  fails the run, naming the variable, instead of being read as unset. An empty
  `OHTTP_E2E_REPLAY_URLS` therefore runs the normal exchange (it used to send nothing), and
  one that is set but names no URL (`,`) fails the run instead of sending nothing.
- `NETWORK` is checked before the key configuration is fetched, for every run (an invalid
  non-empty value used to be ignored when the configuration was unsigned), and only the
  validated network name is printed.
- The DNS-over-HTTPS query sends the library's fixed key-fetch headers (`Accept-Encoding`,
  `Accept-Language`, `User-Agent`) next to `Accept: application/dns-json`, instead of `Accept`
  alone.
- The selected HPKE key id is no longer printed (`key selected: kem=... kdf=... aead=...`, and
  `key selected` in the DNS mode).
- The key-configuration source guess (`OHTTP_E2E_KEY_CONFIG_SOURCE` unset) is deprecated: such
  a run also prints a warning on standard error saying so. A later version will require the
  variable; scripts should set it now.
- `OHTTP_E2E_DUMP_HEADERS` is on with `1` only, read with the other settings before anything
  is sent: empty is off, and any other value (`0` included, which used to turn it on, as did
  an empty value) fails the run, as does a value that is not Unicode.
- A non-Unicode `OHTTP_E2E_GATEWAY_HOST_<NET>`, `OHTTP_E2E_RELAY_URL_<NET>`,
  `OHTTP_E2E_KEYS_DNS_NAME_<NET>` or `OHTTP_E2E_SIGNING_PUBKEY_<NET>` fails the run, naming the
  variable, instead of being read as unset: every exchange run before anything is sent,
  whatever the key source (a run with an unsigned source used not to read these variables, and
  still does not check their contents), and the DNS mode when it reads its configuration.
- A relay or replay URL whose scheme is not in lower case (`HTTP://`, `HTTPS://`) is refused,
  with or without `OHTTP_E2E_PLAIN_HTTP_RELAY=1`, by an error saying so: the scheme is read as
  written, as the configuration rules read `https://` (an upper-case `HTTP://` used to get the
  misleading error that the URL must be `https://`).
- An `OHTTP_E2E_REPLAY_URLS` entry is named in an error by its position in the value as
  written, from 0, empty entries counted (`a,,b`: `b` is entry 2); empty entries used to be
  dropped before numbering. The output (`[XREPLAY i]`, trace suffix `-r<i>`) still numbers the
  sends in the order sent.
- `scripts/test-e2e.sh` prints a `FAIL:` line when the e2e client itself exits non-zero (the
  script used to end without one), and takes `RELAY_SIMULATOR=1|0` to say whether `RELAY_URL`
  is a relay simulator; unset, empty or `auto`, it still looks for the text `relay-simulator`
  in `RELAY_URL`. The unknown-authority step runs with `OHTTP_E2E_EXPECT_OK` empty, so a
  caller's `OHTTP_E2E_EXPECT_OK=1` does not turn the expected inner 403 into a failure.
- `OHTTP_E2E_REPLAY` and `OHTTP_E2E_EXPECT_OK` are on with `1` only, read by an exchange run
  with the other settings before anything is sent: empty is off, any other value (`0`, `true`:
  they used to mean off) or a non-Unicode one fails the run.
- `OHTTP_E2E_REPLAY_GAP_MS` is read then too and must be decimal digits: any other value, or a
  non-Unicode one, fails the run naming the variable (a value that did not parse as a number
  used to count as 0, silently; only digits are accepted now, so `+5` is refused too). Unset or
  empty is 0, as before.
- `OHTTP_E2E_REQUEST_ID` and `OHTTP_E2E_EXTRA_HEADERS` are read then too, and checked for
  Unicode only: a non-Unicode value fails the run instead of being read as unset. As before, an
  extra-headers entry without a `:` is ignored, and a header name or value HTTP does not allow
  is refused when a request carrying it is built: for the extra headers that is the
  key-configuration request, before anything is sent. The request id goes only on the relay
  request of a run without `OHTTP_E2E_REPLAY=1` and `OHTTP_E2E_REPLAY_URLS` (an empty one as an
  empty `X-Request-Id`); with either it is neither sent nor refused. The DNS mode reads none
  of these settings.
- The warning about a guessed key source is printed after these checks, so an exchange run that
  fails on one of them no longer prints it first.
- `scripts/test-e2e.sh` no longer prints `RELAY_URL`, `CONFIGS_URL` or the trace id, and a relay
  simulator's `RELAY_URL` that does not end in `/relay` fails the script (exit 2) unless
  `CONFIGS_URL` is set, instead of deriving a wrong key-configuration URL.
- New tests run the binary against a local server, each run killed and failed after 120 s (with
  what it wrote): an explicit `signed` source refuses an unsigned answer and a tampered
  envelope, the explicit source wins over the answer's `Content-Type` either way, a refused
  setting sends no request at all (a bad later replay entry, an upper-case scheme,
  `OHTTP_E2E_DUMP_HEADERS=0`, `OHTTP_E2E_EXPECT_OK=0`, `OHTTP_E2E_REPLAY=true`, a bad
  `OHTTP_E2E_REPLAY_GAP_MS`, `NETWORK` or source, an `http://` relay without the opt-in, and on
  Unix a non-Unicode per-network variable, `OHTTP_E2E_REQUEST_ID` or `OHTTP_E2E_EXTRA_HEADERS`),
  and the header count is printed with `OHTTP_E2E_DUMP_HEADERS=1` only. The tests keep the
  inherited environment but the tool's own and the proxy variables, and their server logs a
  connection that sends nothing as such.
- New tests (Unix, with bash) run `scripts/test-e2e.sh` in a temporary copy of the layout it
  expects, with a fake e2e client that records its calls: `PASS` without either URL or the
  trace id in the output, the `FAIL:` line of each step, `OHTTP_E2E_EXPECT_OK` emptied for the
  unknown-authority step only, the `/relay` rule and its `CONFIGS_URL` exception, and
  `RELAY_SIMULATOR` (`1`, `0`, unset, empty, `auto`, another value).

## 1.1.0

The gateway caches `GetSubtreeRoots` for the Ironwood pool and writes its subtree end markers before
the tip RPCs; all images are published for linux/amd64 and linux/arm64; the client library
(`zodl-ohttp-client` 1.1.0) sends one fixed User-Agent to the relay (see its changelog), and the
e2e client follows its version.

### Images

- The gateway, relay simulator and e2e client images are published for linux/amd64 and
  linux/arm64. Each tag names a multi-platform index; the signature and the provenance
  attestation are on the index digest, which is the digest to pin.

### Gateway

- `GetSubtreeRoots` requests for the Ironwood pool (shielded protocol 2) are now served via the
  per-entry cache, as Sapling and Orchard requests already were. Wallets syncing the Ironwood pool
  after a network upgrade that activates it see the same cache hit rate as for the other pools.
  Requests for unknown protocols still take the generic per-request path.
- The tip prefetch writes the `GetSubtreeRoots` end markers of a new tip before it asks
  lightwalletd for the tip-scoped answers, instead of after. The markers come from the tip block
  the chain follower already stored, so they need no upstream call. Wallets that ask for subtree
  roots right after a block no longer fall through to lightwalletd while the tip RPCs are in
  flight, which on a gateway far from its lightwalletd took one or more round trips per tip. No
  new settings or metrics.

## 1.0.1

crates.io metadata, no code change: `zodl-ohttp-client` 1.0.1 is published on crates.io, the e2e
client follows its version. The gateway and the relay simulator are unchanged.

## 1.0.0

The first stable release of the gateway, the relay simulator, the e2e client and the client
library (`zodl-ohttp-client` 1.0.0, all at version 1.0.0). Since the initial release: multi-origin
replay protection that survives a failover of its store, lightwalletd calls with deadlines,
retries and health accounting, a self-correcting chain follower, an OHTTP configuration that
clients take at runtime instead of from their build, and requests padded to fixed size buckets.

### Client library

- The OHTTP configuration of each network (gateway host, relay URL, keys DNS name, signing key)
  is passed in at runtime as `OhttpConfig` (built from the named fields of `OhttpConfigParams`)
  / `OhttpNetworks`, validated when it is built, instead
  of being compiled in; a network without one has OHTTP off. The build-time variables are gone.
  Details in [client/CHANGELOG.md](client/CHANGELOG.md).
- Requests are padded to fixed size buckets with zero bytes after the Binary HTTP message:
  `SendTransaction` to 16 KiB (32 KiB if larger, then multiples of 32 KiB), every other request
  to multiples of 4 KiB, never past the 10 MiB sealed-request cap.

### e2e client

- Reads the OHTTP configuration at runtime from `OHTTP_E2E_GATEWAY_HOST_<NET>`,
  `OHTTP_E2E_RELAY_URL_<NET>`, `OHTTP_E2E_KEYS_DNS_NAME_<NET>` and `OHTTP_E2E_SIGNING_PUBKEY_<NET>`
  (`<NET>` = `MAINNET` or `TESTNET`), all four or none per network, for signed key configurations
  and the DNS source. The image carries no configuration and is built without secrets.

### Gateway

- A request's Binary HTTP message may be followed by zero padding only: a non-zero byte after
  its trailer section refuses the request as a parse error (inner 400). Zero padding was already
  skipped.

- `REPLAY_UNAVAILABLE_FALLBACK` on an `async-reads` origin whose own store is the fallback store
  (no standby stores, `REPLAY_WRITE_WAIT_REPLICAS`, peers with `REPLAY_PEER_WAIT_REPLICAS` >= 1):
  while its own store gives no verdict (a promotion, a cut), requests are decided at the hub
  instead of failing closed, as a `failover`-mode gateway does at its peers: READs by `SET NX`,
  WRITEs by `SET NX` + the hub's `WAIT`, a nonce held there is a replay, anything else fails
  closed, and a WRITE nonce is written back to the own store once it answers. `/healthz` stays up
  meanwhile while the hub answers (`ohttp_replay_serving_via_fallback`). This also holds with
  `REPLAY_PEER_FAIL_CLOSED_WRITES=0`: an unreachable hub is tolerated there, an unreachable own
  store is not. New gauge `ohttp_replay_local_fallback`.
- lightwalletd calls: a connection must be established within `LWD_CONNECT_TIMEOUT_MS` (default
  2000), so an instance whose network is cut costs a connect error instead of the call's whole
  deadline. A read (every lightwalletd RPC except `SendTransaction`) that got a transport error or
  no response head within half of its head deadline (not `GetMempoolStream` and the
  transparent-address RPCs) is sent once more; a `SendTransaction` is
  retried only after a connect error, as before. Optional `LWD_ENDPOINTS` (a name that resolves to
  one address per instance) lets the gateway pick the instance itself: random among those that
  did not fail in the last 30 s, the retry on another one. New series
  `ohttp_lwd_read_retries_total`.
- `/healthz` also fails while too many lightwalletd calls fail (`HEALTHZ_LWD_ERROR_RATIO`, default
  0.2 of the calls in `HEALTHZ_LWD_ERROR_WINDOW_SECS` 30, at least `HEALTHZ_LWD_MIN_ERRORS` 5), also
  while the replay fallback keeps it up otherwise. New series `ohttp_healthz_lwd_error_ratio`.
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

# CHANGES

Behaviour changes of the gateway, the relay simulator and the e2e client. The client library
keeps its own log in [client/CHANGELOG.md](client/CHANGELOG.md).

## Unreleased

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
- Known limits of the chain follower and the pinned backfill after these changes:
  - The drop of a held tip on a scheduled probe without a new observation applies to a held
    tip that is still held when the probe starts (the stored tip is not on its own chain).
    When the index check itself drops the held tip on a probe tick (the stored chain changed
    at or below the stored tip it was checked against), that probe goes on as an ordinary new
    observation of the process's own lightwalletd tip, as before these changes: a stored tip
    that has not moved for the stale bound while its own lightwalletd is ahead is what the
    stale-leader handling serves.
  - A `tip_at` ahead of the clocks stays stored until the tip next moves, and a follower's
    own clock skew is not compensated. The leader stops confirming at the bound counted from
    its takeover, and followers need every confirmation. (Rewriting `tip_at` with a
    confirmation would change a key older versions read.)
  - A stored tip that changes while `tip_at` does not is taken for one written without its
    time. That is also the case for two tips written with the same millisecond by a leader of
    a previous version or across a handover between leaders with skewed clocks, and for a
    follower that missed the reads in between; the tip is then followed as one without
    `tip_at` until `tip_at` changes. (Telling these apart needs a writer epoch in the store,
    a change of the protocol between versions.)
  - A sweep fill abandoned because the store changed cancels its upstream call in flight, as
    the fill timeout and a lost claim do: at most one call per worker per change of store.
    (Letting it run would hold the batch's claim for the fetch timeout.)
  - The store-backed tests fail without a test store only when `CI` is set; elsewhere they
    are skipped, as the rest of the suite's store-backed tests are.
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

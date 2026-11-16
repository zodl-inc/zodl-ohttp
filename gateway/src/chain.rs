// Copyright © 2026 Znewco, Inc. (d/b/a Zcash Open Development Lab)
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of ZODL OHTTP.
//
// ZODL OHTTP is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License,
// version 3 only, as published by the Free Software Foundation.
//
// ZODL OHTTP is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Affero General Public License for more details.
//
// Commercial licensing: see COMMERCIAL-LICENSE.md.

//! Chain follower: one leader per network keeps the `height -> hash` index that validates
//! every cached block, tree state and transaction; the other gateway processes follow its index.
//!
//! - **Leader lock**: `SET {chain}leader {token} NX PX 10000`, renewed every tick with an
//!   atomic "extend if still mine" script, and every third of the TTL while leader work runs
//!   (a cold start or a catch-up can take longer than the TTL). Work whose renewal finds the lock
//!   held by another process, or that could not renew it for a whole TTL, is cancelled. A
//!   process that loses Redis stops leading; another takes over once the TTL lapses.
//!   Non-leaders read the tip from Redis every tick.
//! - **Confirmation**: on every tick its lightwalletd answers with the indexed tip (or moves
//!   it), the leader rewrites `{chain}tip_seen` under the lock (never below `{chain}tip_at`, and
//!   always a value higher than the last one this process wrote). Followers refresh their tip only when that value changed since their
//!   last read, so a tip the leader stops confirming goes stale everywhere after
//!   `store::TIP_STALE_AFTER`. The leader confirms only a tip that moved at most
//!   [`MAX_CONFIRM_AGE`] ago by `{chain}tip_at` (a lightwalletd stuck at the tip height, or
//!   behind it, cannot keep an old tip fresh; the age survives leader changes and alternating
//!   answers), and not after [`MAX_BEHIND_TICKS`] ticks behind it in a row. A leader that does
//!   not write `tip_seen` (an older version) is followed as before, every read refreshing the
//!   tip: that is the case when the key is absent, when its value is older than `tip_at` (the
//!   key is a leftover of an earlier leader: the tip moved since), and when its value stays the
//!   same while the stored tip changes, until the value changes again. With a `tip_seen` key
//!   and `tip_at` stored, such a leader is followed that way only while the tip moved at most
//!   [`MAX_CONFIRM_AGE`] ago (by `tip_at`, and by this process's own reads of the same record,
//!   see "Stale leader"): an older tip goes stale on followers as it does under a leader of
//!   this version, until a confirmation changes.
//! - **Stale leader**: a leader can keep its lock and still stop moving the tip (its
//!   lightwalletd answers with an old tip, or keeps failing the block fetch). With every tip it
//!   writes, the leader also stores when it moved it (`{chain}tip_at`), and in the same script a
//!   stamp that binds that time to that tip with a nonce of the write (`{chain}tip_stamp`,
//!   see `TipAtRead`; written with every `tip_at`, never without one). A follower that finds
//!   the stored tip unmoved for longer than [`DEFAULT_TIP_STALE_AFTER`]
//!   (`CHAIN_TIP_STALE_SECS`) asks its own lightwalletd every [`STALE_PROBE_EVERY`] ticks.
//!   If that is ahead, it serves its own tip at once, and if it is still ahead on the next
//!   probe, with the same stored tip (height and hash) and the same lock holder, it takes the
//!   lock over (one script that checks both) and continues the index from there in the same
//!   tick. So two followers that saw the same stale tip cannot take it from each other; a
//!   refused takeover, or another holder, starts the observation again. What a follower serves
//!   meanwhile follows one rule (`ChainFollower::follow_stored`): the highest tip its own
//!   lightwalletd answered, for at most [`HELD_TIP_MAX_AGE`] in total after it last did (the
//!   served tip itself goes stale then), while the stored tip stays below it on the same chain;
//!   a lower or failed probe, or a lower tip it indexes after taking over, never makes it step
//!   back; the stored tip again once it ages out, catches up, or the stored chain is seen to
//!   fork (another block at or below the last stored height it saw, or an index entry at that
//!   height that no longer names it), or the leader indexes a reorg, or, as leader, a lower
//!   tip that is not on the held tip's chain (fetched with the held tip, see `HeldChain`; a
//!   follower drops it the same way for a stored tip that is not on that chain). A
//!   check of the stored chain that finds no index entry is retried on the next read as a
//!   follower; when the lock is taken it drops the held tip.
//!   A chain that really has no new block leaves every lightwalletd at the stored tip,
//!   so nothing happens. The age is wall-clock time between processes, and at least as long
//!   as this process has read the same stored record (its monotonic clock, see `Unmoved`): a
//!   stored time ahead of a follower's clock delays the probe by at most the time that
//!   follower needs to see the record for the bound itself, whatever the skew. A writer clock
//!   behind makes followers probe more often, never take over from a leader whose tip moves. A
//!   leader that does not store the time (an older version) is never treated as stale, nor is
//!   one whose tip moves while the stored time stays (a leftover of a newer leader after a
//!   rollback, see `TipAtRead`; a stamp that vouches for the read says it is not one: it names
//!   the stored tip and time, no leftover verdict for that time is remembered, and this process
//!   did not read the same stamp value before next to another stored tip):
//!   such a tip is followed as one without a time. When only the stamp key is lost while the
//!   tip and time it vouched for stay, what it vouched for stands. A stored time ahead of a
//!   new leader's clock counts from its takeover, or from its first read of the same record as
//!   a follower, for [`MAX_CONFIRM_AGE`]; ahead by more than [`TIP_AT_MAX_AHEAD`], the leader's
//!   first confirmation replaces it by that time (`ChainFollower::adopt_tip_at`). Metrics
//!   `ohttp_chain_tip_at_rewrites_total`, `ohttp_chain_tip_stamp_lost_total`, `ohttp_chain_tip_age_seconds`,
//!   `ohttp_chain_tip_time_ahead_seconds`, `ohttp_chain_stale_leader_total`.
//! - **Fencing**: the tip, every index entry with its block (one script per batch of at most
//!   [`BLOCK_WRITE_BATCH`] blocks and [`BLOCK_WRITE_BATCH_BYTES`] of payload), the confirmation and every deletion of a reorg are written
//!   only while the writer holds the lock with its own token (an absent lock refuses too). A
//!   leader that was replaced while a tick was in flight (a slow block fetch, a pause) thus
//!   cannot write the index or blocks of another fork, delete what its successor wrote, or move
//!   the stored tip back; it stops leading. A store error in one of these writes stops the tick
//!   (and hands the lock over).
//! - **Lagging backend**: a leader whose lightwalletd answers with a lower tip that is on the
//!   indexed chain (the index has that block) treats it as behind, not as a reorg: the tip and
//!   the index stay. After [`MAX_BEHIND_TICKS`] such ticks in a row it gives the lock up and
//!   does not try to take it again for [`BEHIND_COOLDOWN_TICKS`], so a process with another
//!   lightwalletd leads.
//! - **Polling**: the leader calls `GetLatestBlock` once per tick, with a 2 s pause after each
//!   tick. On a new tip it fetches the new blocks once (`GetBlockRange`, at most
//!   [`MAX_CATCHUP`] per tick when advancing), checks `prevHash`
//!   continuity against the index, stores the blocks in the block cache and writes
//!   `index:{height} -> hash` for each, then the tip.
//! - **Reorg**: when the fetched blocks do not chain to the index (or the tip hash changed at the
//!   same or a lower height) it walks back in batches of eight until a canonical block matches
//!   the index or an index entry is missing (the fork point), deletes the index entries, cached blocks (every pool filter
//!   seen), nullifiers and tree states above it, refetches the canonical blocks and rewrites
//!   the index. Cached transactions above the fork are caught by validation (their stored block
//!   hash no longer matches the index) and refetched on demand.
//! - **Cold index**: after indexing its first tip, the leader fills the gaps of its window
//!   (`tip - INDEX_WINDOW ..= tip`) in batches of 100 heights per idle tick, so cached blocks
//!   inside the window become servable. A leader that takes over an existing index does not
//!   rescan it.
//! - **Permanent tier** (optional): blocks the leader fetches that are already final (depth >=
//!   `PERMANENT_DEPTH` below the tip, at or above the tier's floor) are written there instead
//!   of the cache Redis, and on every advance the heights that just became final are moved
//!   from the cache Redis (every pool filter seen, index-matched) to the permanent tier.
//!
//! Everything is fail-open: a Redis error demotes the leader (or stops its tick) and leaves the
//! tip unknown, and the request paths then answer from upstream.

use crate::block_cache::{block_key, grpc_frame, FetchedBlock, PoolKeys};
use crate::local::LocalCache;
use crate::store::{
    decode_tip, decode_tip_stamp, decode_unix_ms, encode_tip, encode_tip_stamp, encode_unix_ms,
    index_key, lock_key, permanent_block_key, tip_at_key, tip_key, tip_seen_key, tip_stamp_key,
    unix_ms_now, CacheStore, PermanentStore, Tip, INDEX_WINDOW, PERMANENT_DEPTH,
};
use anyhow::Result;
use bytes::Bytes;
use futures_util::future::BoxFuture;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Poll interval.
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Leader lock TTL; a dead leader is replaced after this.
pub const LOCK_TTL_MS: u64 = 10_000;
/// While a leader tick runs, its lock is renewed this often, so a tick that takes longer than
/// the TTL (a slow catch-up) keeps it. A tick that fails hands the lock over at once.
const LOCK_RENEW_EVERY: Duration = Duration::from_millis(LOCK_TTL_MS / 3);
/// New blocks fetched per tick at most.
pub const MAX_CATCHUP: u64 = 100;
/// Deepest walk-back before giving up and invalidating the whole span.
const MAX_WALK_BACK: u64 = 200;
/// Heights compared per walk-back step.
const WALK_BATCH: u64 = 8;
/// Index entries expire after this (they leave the window long before).
const INDEX_TTL_SECS: u64 = 7 * 86_400;
/// Heights checked per backfill tick.
const BACKFILL_BATCH: u64 = 100;
/// Non-leaders probe lightwalletd for the reachability gauge every this many ticks.
const HEALTH_PROBE_EVERY: u64 = 15;
/// A stored tip unmoved for this long makes followers compare it with their own lightwalletd:
/// two block intervals. A chain without new blocks costs only those probes.
pub const DEFAULT_TIP_STALE_AFTER: Duration = Duration::from_secs(150);
/// While the stored tip is older than the bound, followers ask their own lightwalletd every this
/// many ticks; a takeover needs two such probes in a row that are ahead.
pub const STALE_PROBE_EVERY: u64 = 5;
/// A follower that found its own lightwalletd ahead of an unmoved stored tip serves that tip for
/// at most this long in total after a probe last confirmed it (three probe intervals): the tip
/// is served as seen at that probe, so it goes stale at the bound whatever happens meanwhile.
/// Meanwhile it never falls back to the lower stored tip (a failed probe, a lagging answer or a
/// lower tip it indexes after a takeover does not count), so the tip it serves does not go back
/// and forth; once the bound passes without a confirmation it serves the stored tip again, if
/// the leader confirms that one (no tip otherwise, until a confirmation).
pub const HELD_TIP_MAX_AGE: Duration = Duration::from_secs(30);
// The served held tip goes stale at the hold bound, not later.
const _: () = assert!(HELD_TIP_MAX_AGE.as_millis() <= crate::store::TIP_STALE_AFTER.as_millis());
/// A leader whose lightwalletd answers below the indexed tip (on the indexed chain) keeps
/// serving and confirming the indexed tip for at most this many ticks in a row (about 30 s at
/// the poll interval), and only within [`MAX_CONFIRM_AGE`]. On the next one it stops
/// confirming it, releases the lock and does not try to take it again for
/// [`BEHIND_COOLDOWN_TICKS`], so that a process with another lightwalletd leads; the
/// unconfirmed tip goes stale everywhere after `store::TIP_STALE_AFTER` and the request paths
/// answer from upstream meanwhile. Any other outcome resets the count.
pub const MAX_BEHIND_TICKS: u64 = 15;
/// Ticks a leader that gave the lock up after [`MAX_BEHIND_TICKS`] waits before it tries to
/// take it again.
pub const BEHIND_COOLDOWN_TICKS: u64 = 5;
/// The leader confirms the indexed tip only while it moved at most this long ago (by
/// `{chain}tip_at`, the time the tip was written, whichever process wrote it), then stops: a
/// lightwalletd stuck at the tip height, or behind it, cannot keep an old tip fresh. The bound
/// does not restart on a leader change or with alternating answers. A gap of 10 minutes between
/// blocks is rare (well below 0.1 % of blocks at a 75 s target spacing), and during one the
/// request paths only answer from upstream. A new tip confirms again. The age is wall-clock time
/// between processes when the tip was written by another one: a clock ahead of that writer's
/// stops confirming earlier, one behind it later, but not later than this bound after the
/// takeover, or after this process's first read of the same record as a follower.
pub const MAX_CONFIRM_AGE: Duration = Duration::from_secs(600);
/// Blocks written per fenced script at most (two entries each: index and block).
const BLOCK_WRITE_BATCH: usize = 32;
/// Block payload bytes per fenced script at most: a script ends before the block that would
/// take it past this, so one script stays well inside the store's operation timeout whatever
/// the block sizes. A single block above it is written alone.
const BLOCK_WRITE_BATCH_BYTES: usize = 1 << 20;
/// Keys deleted per fenced script.
const DELETE_BATCH: usize = 256;

/// Where the follower reads the chain: lightwalletd, or a fake in tests.
pub trait ChainSource: Send + Sync {
    /// `GetLatestBlock`.
    fn latest(&self) -> BoxFuture<'static, Result<Tip>>;
    /// `GetBlockRange(start, end)` ascending, each block decoded.
    fn blocks(&self, start: u64, end: u64) -> BoxFuture<'static, Result<Vec<FetchedBlock>>>;
}

/// Told whenever this process, as leader, writes a new tip (the mempool fan-out ends its
/// session). Followers update their tip without telling listeners.
pub trait BlockListener: Send + Sync {
    fn on_new_block(&self, tip: &Tip);
}

/// What one tick did (for tests and logs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Not the leader this tick.
    Follower,
    /// Leader, no change.
    Idle,
    /// Leader, first tip indexed.
    Cold {
        tip: u64,
    },
    Advanced {
        from: u64,
        to: u64,
    },
    Reorg {
        fork: u64,
        depth: u64,
        tip: u64,
    },
    /// Leader, its lightwalletd answered with a lower tip on the indexed chain: kept `tip`.
    Behind {
        backend: u64,
        tip: u64,
    },
    /// Follower, the stored tip had not moved and its own lightwalletd was ahead: it serves
    /// its own tip (`to`). `took_over` (it holds the lock now) is internal: `tick` then goes on
    /// as the leader and returns the leader's outcome.
    StaleLeader {
        from: u64,
        to: u64,
        took_over: bool,
    },
    Error(String),
}

pub struct ChainFollower {
    store: Arc<dyn CacheStore>,
    source: Arc<dyn ChainSource>,
    local: Option<Arc<LocalCache>>,
    pools: Arc<PoolKeys>,
    listeners: parking_lot::Mutex<Vec<Arc<dyn BlockListener>>>,
    network: String,
    token: String,
    leader: AtomicBool,
    ticks: AtomicU64,
    /// The leader's indexed tip (what the index covers up to).
    last: parking_lot::Mutex<Option<Tip>>,
    /// Next height (downward) the cold backfill checks, `None` when done or not started.
    backfill_cursor: parking_lot::Mutex<Option<u64>>,
    permanent: Option<Arc<dyn PermanentStore>>,
    permanent_min_height: u64,
    /// See [`DEFAULT_TIP_STALE_AFTER`].
    stale_after: Duration,
    /// Follower: what the last probes of its own lightwalletd found (see [`HeldTip`]).
    stale: parking_lot::Mutex<Option<HeldTip>>,
    /// Leader: Unix milliseconds of when the indexed tip moved (`tip_at`: the last tip this
    /// process wrote, or the stored `tip_at` it took over, at most the time it took it over, or
    /// the time of its first read of the same record as a follower, see [`Unmoved`]; 0 = none).
    /// The [`MAX_CONFIRM_AGE`] bound counts from it.
    moved_at_ms: AtomicU64,
    /// Leader: the `tip_at` stored with the indexed tip, as stored (not clamped like
    /// `moved_at_ms`): confirmations are never below it (see [`Self::adopt_tip_at`]).
    tip_at_floor_ms: AtomicU64,
    /// Leader: the last `tip_at` this process wrote with a tip; the next one is another value
    /// (not necessarily a higher one), so that no two tips in a row it writes come with the
    /// same `tip_at` (see [`TipAtRead`]).
    tip_at_written_ms: AtomicU64,
    /// Leader: the `tip_at` in the store as this process last read or wrote it, whether it
    /// goes by it or not (a leftover, see [`TipAtRead`], is stored too); 0 = none. The next
    /// `tip_at` it writes with a tip is another value.
    tip_at_stored_ms: AtomicU64,
    /// Follower: the last fetch of a held tip's chain that gave nothing, as (stored tip, own
    /// tip): not asked again until one of them changes (see [`Self::held_chain`]).
    held_chain_unknown: parking_lot::Mutex<Option<(Tip, Tip)>>,
    /// Leader: the stored tip it took over had no `tip_at` (a leader that does not write it),
    /// or one further ahead of this clock than [`TIP_AT_MAX_AHEAD`]: `moved_at_ms` is the
    /// tip's time from here on, written with the next confirmation.
    tip_at_pending: AtomicBool,
    /// Leader: the pending `tip_at` replaces a stored one that was ahead of this clock (for
    /// `ohttp_chain_tip_at_rewrites_total`).
    tip_at_rewrite: AtomicBool,
    /// Leader: the local instant that `moved_at_ms` was when it was set (None: not known, a
    /// time further back than this clock can express). The confirmation bound counts from
    /// it as well as from `moved_at_ms` ([`Self::tip_confirmable`]), and it gives the tip its
    /// time again after this process's wall clock stepped back
    /// ([`Self::clock_stepped_back`]).
    moved_instant: parking_lot::Mutex<Option<tokio::time::Instant>>,
    /// Leader: the `tip_at` that was stored with the tip before the indexed one, when this
    /// process wrote the indexed tip (0: not known): a replaced `tip_at` of the indexed tip
    /// is never that value ([`replacement_tip_at`]).
    tip_at_before_ms: AtomicU64,
    /// Leader: the nonce of the stamp stored with the indexed tip's `tip_at`, when known:
    /// this process wrote it, or read it vouching for the record when it took the lock.
    stamp_nonce: parking_lot::Mutex<Option<u64>>,
    /// Leader: the last `tip_seen` value it wrote (each confirmation writes a higher one).
    seen_written_ms: AtomicU64,
    /// Leader: the indexed tip is past [`MAX_CONFIRM_AGE`] and that was logged.
    unconfirmed_logged: AtomicBool,
    /// Consecutive leader ticks whose lightwalletd was behind the indexed tip.
    behind_ticks: AtomicU64,
    /// No attempt to take the lock before this tick (after giving it up, see
    /// [`MAX_BEHIND_TICKS`]).
    cooldown_until: AtomicU64,
    /// Follower: the last `tip_seen` value read and the stored tip read with it (see
    /// [`SeenTip`]); the tip is refreshed only when the value changes.
    last_seen: parking_lot::Mutex<Option<SeenTip>>,
    /// Follower: the stored tip and `tip_at` read last (see [`TipAtRead`]).
    last_tip_at: parking_lot::Mutex<Option<TipAtRead>>,
    /// The last `{chain}tip_stamp` value read while it named another tip than the stored one
    /// (as a follower or when taking the lock, first reads included): it is never evidence for
    /// a stored tip later (see [`TipAtRead`]).
    stamp_beside_other: parking_lot::Mutex<Option<Bytes>>,
    /// The stored record read unchanged since a local instant (see [`Unmoved`]).
    unmoved: parking_lot::Mutex<Option<Unmoved>>,
}

/// A follower's last read of the stored tip and its `tip_at`. A leader of this version writes
/// both in one script and never the same `tip_at` twice in a row, so a stored tip that changed while
/// `tip_at` did not was written by a leader that does not write `tip_at` (an older version
/// leading after a rollback, with the keys of a newer one left over): that `tip_at` is not
/// the time of this tip, and the tip is followed as one without `tip_at` (every read refreshes
/// it, no stale-leader probe), until `tip_at` changes again.
///
/// Two limits, both accepted. The verdict is made per process, from two of its own reads: a
/// process that starts under such a leader has no earlier read and trusts the leftover
/// `tip_at` on its first one, until the stored tip next changes (about one block interval;
/// meanwhile the tip is bound by that `tip_at`'s age as under a leader of this version). And
/// the verdict stays until `tip_at` changes: a leader of this version always writes another
/// one with its next tip, and one that only continues the stored tip writes it with its first
/// confirmation only if it saw the leftover itself (`ChainFollower::lead`). Only consecutive
/// writes differ: a `tip_at` equal to the one a follower read several tips earlier (it missed
/// the reads in between, and the clock value was the same millisecond, e.g. after the
/// leader's clock stepped back) is taken for a leftover until `tip_at` changes.
///
/// The stamp (`{chain}tip_stamp`, see `store::tip_stamp_key`) only ever turns a leftover
/// verdict this read would newly make into "not a leftover": when it names exactly the stored
/// tip and the stored `tip_at` (a leader of this version wrote all three in one script, read by
/// one `MGET`), unless a leftover verdict for this same `tip_at` is remembered, or this process
/// read this exact stamp value before next to another stored tip (a leader that writes no
/// `tip_at` moved the tip away and back to the stamped block). Then `tip_at` is the tip's time,
/// whatever the inference from two reads would say: two tips with the same millisecond (a
/// leader of an earlier version, a handover between leaders with skewed clocks) and reads a
/// follower missed are no longer taken for leftovers. Any other stamp (absent, unparsable,
/// another tip or time) is no evidence either way: the inference above decides, on its own
/// state, as without a stamp.
///
/// One exception: the stamp key alone lost. No stamp key at all, read next to the very tip
/// and `tip_at` a stamp vouched for on this process's last read, means that only that key is
/// gone (evicted; nothing deletes it, and a leader writes it with every `tip_at`). The
/// absence is not evidence against what the stamp said: the verdict stands and the record is
/// still the one vouched for, with its nonce, so the local count of its age ([`Unmoved`]) goes
/// on instead of starting again; the inference is not asked and its state not touched. That
/// lasts while the tip and `tip_at` stay and no stamp value is read: a tip or `tip_at` that
/// changes, or any stamp, is judged by the rules above.
#[derive(Clone, Debug)]
struct TipAtRead {
    tip: Tip,
    tip_at: Option<u64>,
    /// The stored `tip_at` is a leftover (see above).
    leftover: bool,
    /// The nonce of the stamp that vouched for this tip and `tip_at`, on this read or, with
    /// the stamp key lost since, on an earlier one.
    nonce: Option<u64>,
    /// The stamp key was gone on this read (`nonce` is from an earlier one).
    stamp_lost: bool,
}

/// The identity of a stored tip record as read: the tip, its effective `tip_at`
/// ([`ChainFollower::effective_tip_at`]) and the nonce of the stamp when the stamp vouches for
/// the read (a leader of this version draws a new one for every `tip_at` it writes, so two of
/// its writes are never the same record). Without a vouching stamp the identity is the pair.
#[derive(Clone, Debug, PartialEq)]
struct TipRecord {
    tip: Tip,
    tip_at: u64,
    nonce: Option<u64>,
}

impl TipRecord {
    /// `next` is this record with its `tip_at` replaced by a leader (the tip did not move):
    /// the same tip, an earlier `tip_at`, and a stamp whose nonce is another one of this
    /// record's line ([`next_stamp_nonce`]: the same upper half), whatever the number of
    /// replacements this process did not read in between (short of the 2^32 that bring the
    /// line back to this record's own nonce). A nonce of another line is a
    /// write of its own (the tip may have moved away and back).
    fn replaced_by(&self, next: &TipRecord) -> bool {
        let (Some(nonce), Some(replacing)) = (self.nonce, next.nonce) else {
            return false;
        };
        self.tip == next.tip
            && next.tip_at < self.tip_at
            && nonce != replacing
            && nonce & !STAMP_NONCE_STEP_MASK == replacing & !STAMP_NONCE_STEP_MASK
    }
}

/// The stored record this process has read unchanged since `since` (the local monotonic
/// clock): it is at least `since.elapsed()` old, whatever the wall clocks say. That is a lower
/// bound of the tip's age next to the wall-clock age `now - tip_at` (two clocks: a writer clock
/// ahead of this one makes that read 0 for the skew), so a `tip_at` ahead of this clock delays
/// the stale-leader probe, the bound on following a leader that does not confirm and the
/// confirmation bound after a takeover by at most the time this process needs to see the
/// record itself for that long.
///
/// A read of another record (another tip, `tip_at` or nonce, or a stamp that is there and no
/// longer vouches) starts it again; the stamp key alone lost does not (`TipAtRead`), nor
/// does the same tip with an earlier `tip_at` whose stamp carries a nonce of the line of the
/// one read before ([`next_stamp_nonce`]: a leader replaced a `tip_at` ahead of its clock, the
/// tip did not move, and a count that started again would delay the stale-leader probe by
/// the stale bound once more); a read
/// with a tip and no effective `tip_at` clears it; a read without a
/// tip (a store error or no key: not told apart) leaves it. Taking the lock consumes it (its
/// elapsed time counts at the takeover only if it is of the record continued), and a `tip_at`
/// this process writes as leader clears it. The bound can exceed the record's true age only if
/// this process missed an intermediate state: a leader of an earlier version moved the tip
/// away and back to the same block with the same `tip_at` (the same millisecond again, or no
/// `tip_at` written at all), or the store went back to an older copy of the record (a failover
/// that lost writes). The effects are then those of a writer clock behind (probes, a takeover
/// only with its own lightwalletd ahead twice, a refresh or a confirmation bound that ends
/// early).
#[derive(Clone, Debug)]
struct Unmoved {
    record: TipRecord,
    since: tokio::time::Instant,
    /// The stale-leader probe condition was met on the local bound alone, and logged.
    warned: bool,
}

/// A stored `tip_at` further ahead of the clock of a process that takes the lock than this is
/// replaced by that process's own time with its first confirmation
/// ([`ChainFollower::adopt_tip_at`]). Within it the value is kept as stored: clocks that are
/// kept in step differ by less, and a rewrite changes the stored record (a follower of this
/// version keeps its local count of the tip's age across it, see `ChainFollower::observe`;
/// one of the version before starts that count again).
pub const TIP_AT_MAX_AHEAD: Duration = Duration::from_secs(2);

/// The stored tip's age as a follower sees it: by the wall clocks (`now - tip_at`) and the
/// local lower bound ([`Unmoved`]). It holds the inputs, not a value: every use computes the
/// larger of the two at that moment, so work awaited between the read and the use (a probe, a
/// block fetch, a lock command) counts in the age as it did with the wall clock alone.
#[derive(Clone, Copy, Debug)]
struct TipAge {
    /// The effective `tip_at` read.
    tip_at: u64,
    /// Since when this process has read the record (None: no observation, a read without a
    /// stored tip).
    since: Option<tokio::time::Instant>,
}

impl TipAge {
    fn wall(&self) -> Duration {
        age_of(self.tip_at)
    }

    fn local(&self) -> Duration {
        self.since.map_or(Duration::ZERO, |s| s.elapsed())
    }

    fn get(&self) -> Duration {
        self.wall().max(self.local())
    }
}

/// A follower's last read of the leader's confirmation.
#[derive(Clone, Debug)]
struct SeenTip {
    /// The `tip_seen` value.
    seen: Bytes,
    /// The stored tip read with it.
    tip: Tip,
    /// The stored tip changed while `seen` did not, or `seen` is older than `tip_at`: the
    /// leader does not write `tip_seen` (a leader of this version writes both in one script,
    /// and never a `seen` below `tip_at`), and `seen` is a leftover of an earlier one. The
    /// confirmation is treated as absent (every read refreshes) until `seen` changes again,
    /// and only while the tip moved at most [`MAX_CONFIRM_AGE`] ago by `tip_at` (when stored).
    unconfirming_leader: bool,
}

/// A follower's view of a leader whose tip stopped moving (see [`ChainFollower::follow_stored`]
/// for the exact rule of what it serves).
#[derive(Clone, Debug)]
struct HeldTip {
    /// The stored tip (height and hash) the observation is bound to.
    stored: Tip,
    /// The last stored tip read while the tip is held: the stored chain must keep extending it
    /// (see [`ChainFollower::revalidate_held`]).
    last_stored: Tip,
    /// The tip it serves meanwhile: the highest its own lightwalletd answered since the
    /// observation began (a lower answer does not replace it).
    own: Tip,
    /// When a probe last answered `own` (or higher): the held tip is served for at most
    /// [`HELD_TIP_MAX_AGE`] after it, as seen then (it goes stale at that bound).
    confirmed_at: tokio::time::Instant,
    /// The last probe found its own lightwalletd ahead of `stored` with the lock held by
    /// `holder`: the next such probe is a second one in a row. A probe that failed changes
    /// nothing; one that was not ahead, a refused takeover or another holder clears it.
    ahead: bool,
    /// The lock holder when the observation was made (`""` = not held; None = it could not be
    /// read, no takeover): a takeover requires the lock to still be held by it, so that two
    /// followers that saw the same stale tip do not take the lock from each other.
    holder: Option<String>,
    /// The last check of the stored chain against `last_stored` found no index entry there
    /// (missing or unreadable): no evidence either way yet. A follower checks again on its next
    /// read; taking the lock drops the held tip ([`ChainFollower::drop_unresolved`]), since no later read
    /// as a follower would check again.
    unresolved: bool,
    /// The blocks of `own`'s chain above the stored tip it was first seen over, as its own
    /// lightwalletd answered them then (None: not known, see [`HeldChain`]).
    chain: Option<HeldChain>,
}

/// The hashes of the blocks `from ..= own.height` of a held tip's chain, fetched from this
/// process's own lightwalletd when the tip was first held (at most [`MAX_CATCHUP`] blocks, and
/// only an answer that is a chain ending at the held tip). A leader that indexes a lower tip
/// that is not on it (its lightwalletd moved to another fork, without a reorg of the index)
/// no longer serves the held tip, and neither does a follower that reads a stored tip that
/// is not on it (the stored chain forked from the held tip's), on an ordinary read
/// (`ChainFollower::follow_stored`) or on a scheduled probe
/// (`ChainFollower::check_stale_leader`, which then starts no new observation).
#[derive(Clone, Debug)]
struct HeldChain {
    from: u64,
    hashes: Vec<Vec<u8>>,
}

impl HeldTip {
    fn fresh(&self) -> bool {
        self.confirmed_at.elapsed() <= HELD_TIP_MAX_AGE
    }

    /// Whether `tip` (below `own`) is known not to be a block of `own`'s chain. A height the
    /// fetched chain does not cover (or no fetched chain) is no evidence.
    fn off_chain(&self, tip: &Tip) -> bool {
        let Some(chain) = &self.chain else {
            return false;
        };
        tip.height
            .checked_sub(chain.from)
            .and_then(|i| chain.hashes.get(usize::try_from(i).ok()?))
            .is_some_and(|hash| *hash != tip.hash)
    }
}

/// What [`ChainFollower::revalidate_held`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Revalidation {
    /// No held tip, or the stored chain still extends the one it was held on.
    Kept,
    /// The stored chain changed under it: dropped.
    Dropped,
    /// No index entry at the last stored height read (missing or unreadable): kept, with its
    /// anchor, and marked unresolved.
    Unknown,
}

impl ChainFollower {
    pub fn new(
        store: Arc<dyn CacheStore>,
        source: Arc<dyn ChainSource>,
        local: Option<Arc<LocalCache>>,
        pools: Arc<PoolKeys>,
        network: String,
    ) -> Self {
        Self {
            store,
            source,
            local,
            pools,
            listeners: parking_lot::Mutex::new(Vec::new()),
            network,
            token: uuid::Uuid::new_v4().to_string(),
            leader: AtomicBool::new(false),
            ticks: AtomicU64::new(0),
            last: parking_lot::Mutex::new(None),
            backfill_cursor: parking_lot::Mutex::new(None),
            permanent: None,
            permanent_min_height: 0,
            stale_after: DEFAULT_TIP_STALE_AFTER,
            stale: parking_lot::Mutex::new(None),
            moved_at_ms: AtomicU64::new(0),
            tip_at_floor_ms: AtomicU64::new(0),
            tip_at_written_ms: AtomicU64::new(0),
            tip_at_stored_ms: AtomicU64::new(0),
            held_chain_unknown: parking_lot::Mutex::new(None),
            tip_at_pending: AtomicBool::new(false),
            tip_at_rewrite: AtomicBool::new(false),
            moved_instant: parking_lot::Mutex::new(None),
            tip_at_before_ms: AtomicU64::new(0),
            stamp_nonce: parking_lot::Mutex::new(None),
            seen_written_ms: AtomicU64::new(0),
            unconfirmed_logged: AtomicBool::new(false),
            behind_ticks: AtomicU64::new(0),
            cooldown_until: AtomicU64::new(0),
            last_seen: parking_lot::Mutex::new(None),
            last_tip_at: parking_lot::Mutex::new(None),
            stamp_beside_other: parking_lot::Mutex::new(None),
            unmoved: parking_lot::Mutex::new(None),
        }
    }

    /// The bound after which an unmoved stored tip makes followers check their own lightwalletd.
    pub fn with_stale_after(mut self, stale_after: Duration) -> Self {
        self.stale_after = stale_after;
        self
    }

    /// Attach the permanent tier for heights `>= min_height`.
    pub fn with_permanent(mut self, permanent: Arc<dyn PermanentStore>, min_height: u64) -> Self {
        self.permanent = Some(permanent);
        self.permanent_min_height = min_height;
        self
    }

    /// Whether a block at `height` is final against a tip at `tip_height` and goes to the
    /// permanent tier (not while that is a read-only replica: the block then stays in the cache
    /// tier, and the move of newly final blocks is skipped; they reach the tier on a later read
    /// once it takes writes).
    fn permanent_height(&self, height: u64, tip_height: u64) -> bool {
        self.permanent.as_ref().is_some_and(|p| p.writable())
            && height >= self.permanent_min_height
            && height.saturating_add(PERMANENT_DEPTH) <= tip_height
    }

    pub fn add_listener(&self, l: Arc<dyn BlockListener>) {
        self.listeners.lock().push(l);
    }

    pub fn is_leader(&self) -> bool {
        self.leader.load(Ordering::Relaxed)
    }

    /// The tip for answering requests (`None` when unknown or stale).
    pub fn tip(&self) -> Option<Tip> {
        self.store.tip_cell().get()
    }

    /// Run forever: one tick, then a pause of [`POLL_INTERVAL`].
    pub async fn run(self: Arc<Self>) {
        loop {
            let outcome = self.tick().await;
            match &outcome {
                Outcome::Error(e) => {
                    warn!(network = %self.network, error = %e, "chain follower tick failed")
                }
                Outcome::Follower
                | Outcome::Idle
                | Outcome::Behind { .. }
                | Outcome::StaleLeader {
                    took_over: false, ..
                } => {}
                other => info!(network = %self.network, outcome = ?other, "chain follower"),
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    fn set_leader(&self, is: bool) {
        let was = self.leader.swap(is, Ordering::Relaxed);
        if was != is {
            info!(network = %self.network, leader = is, "chain follower role changed");
            if !is {
                *self.last.lock() = None;
                *self.backfill_cursor.lock() = None;
            }
        }
        crate::health::record_chain_leader(&self.network, is);
    }

    fn notify_new_block(&self, tip: &Tip) {
        self.serve_tip(tip);
        for l in self.listeners.lock().iter() {
            l.on_new_block(tip);
        }
    }

    /// Leader: serve its indexed tip `tip` (fresh now), unless a tip held from its own
    /// lightwalletd before (see [`HeldTip`]) is higher and still within [`HELD_TIP_MAX_AGE`]:
    /// a takeover, or a lower answer of its lightwalletd after one, does not make the served tip
    /// step back. The held tip is served as seen at its probe, so it goes stale at that bound,
    /// and the next confirmation serves the indexed tip. It is dropped earlier by a reorg this
    /// process indexes ([`Self::reorg`]) and, when the lock is taken, by a stored chain that
    /// is no longer the one it was held on, or could not be checked ([`Self::lead`]). It is
    /// dropped too when `tip` is a block the held tip's chain does not have at that height
    /// ([`HeldChain`]: its lightwalletd answers on another fork that extends the indexed tip
    /// without a reorg). What remains: a held tip whose chain is not known (more than
    /// [`MAX_CATCHUP`] blocks above the stored tip, or the fetch failed) is served until the
    /// bound in that case.
    fn serve_tip(&self, tip: &Tip) {
        {
            let mut held = self.stale.lock();
            match held.as_ref() {
                Some(h) if h.fresh() && h.own.height > tip.height && !h.off_chain(tip) => return,
                Some(h) => {
                    if h.fresh() && h.own.height > tip.height {
                        info!(network = %self.network, tip = tip.height, held = h.own.height, "chain follower: the indexed tip is not on the held tip's chain; serving the indexed tip");
                    }
                    *held = None;
                }
                None => {}
            }
        }
        self.store.tip_cell().set(tip.clone());
        crate::health::record_cache_tip_height(&self.network, tip.height);
    }

    /// Leader: take the time the indexed tip moved from the stored `tip_at` (read with the
    /// stored tip it continues from). Without one (a leader that does not write it), the time
    /// is now, and the next confirmation writes it, so that the [`MAX_CONFIRM_AGE`] bound holds
    /// across leader changes.
    ///
    /// A `tip_at` ahead of this clock (written by a process whose clock is ahead) counts from
    /// now at the latest, and from the first read of the same record as a follower when there
    /// was one (`observed`): the bound is at most [`MAX_CONFIRM_AGE`] after the takeover, or
    /// after that first read, not that plus the skew.
    ///
    /// Ahead by at most [`TIP_AT_MAX_AHEAD`], only the age is clamped and the stored value
    /// stays. The confirmations stay at or above it
    /// (`tip_at_floor_ms`, see [`Self::confirm`]): followers take a `tip_seen` below `tip_at`
    /// for a leftover of a leader that does not confirm and then refresh on every read, and
    /// with a `tip_at` in the future (an age of zero on their clocks) that would keep the tip
    /// fresh on them for the skew past the bound. So the leader stops confirming at most
    /// [`MAX_CONFIRM_AGE`] after it took over (or after that first read), and the followers
    /// still need each confirmation.
    ///
    /// Further ahead, the stored value is replaced: the clamped time (now, less `observed`)
    /// is this tip's `tip_at` from here on, written with its stamp by the next confirmation,
    /// in the confirmation's fenced script, exactly as the `tip_at` of a tip taken over
    /// without one (`tip_at_pending`). The leader's own bound is the same as with the value
    /// kept; what changes is that the store says it too, so followers no longer read an age
    /// of zero for the skew. To a follower this is the same tip with another `tip_at`: one of
    /// this version finds the stamp vouching for it and, when the replaced `tip_at` had a
    /// stamp it read, recognises the replacement by the new stamp's nonce
    /// ([`next_stamp_nonce`]) and keeps its local count of the tip's age
    /// (`ChainFollower::observe`: the tip did not move), next to a wall-clock age that
    /// is real now; the version before it starts that count again, once; an earlier version that knows no stamp
    /// reads `tip_at` as it always did, and a `tip_at` that changes under an unchanged tip is
    /// never a leftover to it (that verdict needs the tip to change while `tip_at` stays). It
    /// is the write such a version does itself for a tip it took over without `tip_at`, with
    /// the limit of that write: a reader that knows no stamp and missed the value replaced
    /// takes the tip's time for a leftover if the replacement is, to the millisecond, the
    /// `tip_at` it read with the tip before (a new leader does not know that value; one that
    /// replaces its own `tip_at` avoids the value last stored with the tip before,
    /// [`replacement_tip_at`], not an earlier one of that tip that was itself replaced). A
    /// tip that is past the bound already is not confirmed, so nothing is written for it. A
    /// leader whose own clock is behind the others by more than the allowance thus replaces a
    /// correct time by its own, older one, which every tip it writes itself carries anyway:
    /// followers probe their lightwalletd more often meanwhile, until the tip next moves.
    /// A leader's own `tip_at` that its clock stepped back from is replaced the same way
    /// ([`Self::clock_stepped_back`]).
    ///
    /// `observed` is how long this process has read the same record as a follower before
    /// ([`Unmoved`], zero without such a read): the age counts from that much before now at the
    /// latest, so a `tip_at` ahead of this clock that it already watched for a while does not
    /// get the full bound again at the takeover.
    ///
    /// `stored_ms` is the `tip_at` in the store, whether `tip_at_ms` goes by it or not (a
    /// leftover does not count as the tip's time, but the next tip must not come with it).
    ///
    /// `nonce` is the nonce of the stamp that vouched for the stored `tip_at` when it was
    /// read (None: no such stamp): a replacement is stamped with the next nonce of its line
    /// ([`next_stamp_nonce`]), which tells followers that the tip did not move.
    fn adopt_tip_at(
        &self,
        tip_at_ms: Option<u64>,
        stored_ms: Option<u64>,
        observed: Duration,
        nonce: Option<u64>,
    ) {
        *self.stamp_nonce.lock() = nonce;
        // The tip before the one taken over was not written by this process.
        self.tip_at_before_ms.store(0, Ordering::Relaxed);
        self.tip_at_stored_ms
            .store(stored_ms.unwrap_or(0), Ordering::Relaxed);
        let now = unix_ms_now();
        match tip_at_ms {
            Some(ms) => {
                let origin = now.saturating_sub(observed.as_millis() as u64);
                crate::health::record_chain_tip_time_ahead(
                    &self.network,
                    Duration::from_millis(ms.saturating_sub(now)),
                );
                let moved_at = ms.min(origin).max(1);
                self.moved_at_ms.store(moved_at, Ordering::Relaxed);
                *self.moved_instant.lock() = tokio::time::Instant::now()
                    .checked_sub(Duration::from_millis(now.saturating_sub(moved_at)));
                let rewrite = ms > now.saturating_add(TIP_AT_MAX_AHEAD.as_millis() as u64);
                if rewrite {
                    info!(network = %self.network, ahead_secs = (ms - now) / 1000, "chain follower: the stored tip time is ahead of this clock; its next confirmation replaces it with this process's time");
                }
                // The value the store has, or will have with the next confirmation.
                self.tip_at_floor_ms
                    .store(if rewrite { moved_at } else { ms }, Ordering::Relaxed);
                self.tip_at_pending.store(rewrite, Ordering::Relaxed);
                self.tip_at_rewrite.store(rewrite, Ordering::Relaxed);
            }
            None => {
                crate::health::record_chain_tip_time_ahead(&self.network, Duration::ZERO);
                self.moved_at_ms.store(now, Ordering::Relaxed);
                *self.moved_instant.lock() = Some(tokio::time::Instant::now());
                self.tip_at_floor_ms.store(now, Ordering::Relaxed);
                self.tip_at_pending.store(true, Ordering::Relaxed);
                self.tip_at_rewrite.store(false, Ordering::Relaxed);
            }
        }
        self.unconfirmed_logged.store(false, Ordering::Relaxed);
    }

    /// Follower (and leader taking the lock): the `tip_at` to go by for the stored tip `tip`
    /// read with `tip_at` and the stamp `stamp`, and the stamp's nonce when the stamp vouches
    /// for the read. None when `tip_at` is a leftover ([`TipAtRead`]): the tip changed since
    /// the last read while `tip_at` did not, and it has not changed since. Decided from this
    /// process's own reads only: its first read takes `tip_at` as stored, and a leftover stays
    /// one until `tip_at` changes. A stamp that names exactly this tip and this `tip_at`, unless
    /// a leftover verdict for this `tip_at` is remembered or this process read this stamp value
    /// next to another stored tip, makes `tip_at` this tip's time instead; and so it stays,
    /// with the same nonce, when the stamp key is then gone while this tip and `tip_at` stay.
    fn effective_tip_at(
        &self,
        tip: &Tip,
        tip_at: Option<u64>,
        stamp: Option<&Bytes>,
    ) -> (Option<u64>, Option<u64>) {
        let encoded = encode_tip(tip);
        let mut beside_other = self.stamp_beside_other.lock();
        let mut last = self.last_tip_at.lock();
        let vouching = match stamp.and_then(|raw| Some((raw, decode_tip_stamp(raw)?))) {
            Some((raw, s)) if s.tip.as_slice() != &encoded[..] => {
                // Says nothing about the stored tip, and never will (see `TipAtRead`).
                *beside_other = Some(raw.clone());
                None
            }
            Some((raw, s)) => (tip_at == Some(s.tip_at_ms)
                && !last
                    .as_ref()
                    .is_some_and(|p| p.leftover && p.tip_at == tip_at)
                && beside_other.as_ref() != Some(raw))
            .then_some(s.nonce),
            None => None,
        };
        // The stamp key alone lost (`TipAtRead`): what it vouched for on the last read stands.
        let kept = match (stamp, last.as_ref()) {
            (None, Some(prev)) if tip_at.is_some() && prev.tip_at == tip_at && prev.tip == *tip => {
                prev.nonce.map(|nonce| (nonce, prev.stamp_lost))
            }
            _ => None,
        };
        if let Some((nonce, counted)) = kept {
            if !counted {
                info!(network = %self.network, tip = tip.height, "chain follower: the stamp of the stored tip time is gone while the tip and its time stay; keeping what it vouched for");
                crate::health::record_chain_tip_stamp_lost(&self.network);
            }
            *last = Some(TipAtRead {
                tip: tip.clone(),
                tip_at,
                leftover: false,
                nonce: Some(nonce),
                stamp_lost: true,
            });
            return (tip_at, Some(nonce));
        }
        if vouching.is_some() {
            *last = Some(TipAtRead {
                tip: tip.clone(),
                tip_at,
                leftover: false,
                nonce: vouching,
                stamp_lost: false,
            });
            return (tip_at, vouching);
        }
        let leftover = match last.as_ref() {
            Some(prev) if tip_at.is_some() && prev.tip_at == tip_at => {
                prev.leftover || prev.tip != *tip
            }
            _ => false,
        };
        if leftover && !last.as_ref().is_some_and(|p| p.leftover) {
            info!(network = %self.network, tip = tip.height, "chain follower: the stored tip moved without its time; following it as a leader that does not store the time");
        }
        *last = Some(TipAtRead {
            tip: tip.clone(),
            tip_at,
            leftover,
            nonce: None,
            stamp_lost: false,
        });
        (tip_at.filter(|_| !leftover), None)
    }

    /// Follower: note the read of the stored record (`tip`, its effective `tip_at`, the nonce
    /// of a vouching stamp, see [`Unmoved`]) and return the tip's age, None without an effective
    /// `tip_at` (no age, as without a stored time). Also sets
    /// `ohttp_chain_tip_time_ahead_seconds`.
    fn observe(&self, tip: &Tip, tip_at: Option<u64>, nonce: Option<u64>) -> Option<TipAge> {
        let mut unmoved = self.unmoved.lock();
        let Some(at) = tip_at else {
            *unmoved = None;
            crate::health::record_chain_tip_time_ahead(&self.network, Duration::ZERO);
            return None;
        };
        let record = TipRecord {
            tip: tip.clone(),
            tip_at: at,
            nonce,
        };
        if !unmoved.as_ref().is_some_and(|u| u.record == record) {
            // The same tip with an earlier `tip_at`, stamped with a nonce of the line of the
            // one read before: a leader replaced a `tip_at` that was ahead of its clock
            // (`adopt_tip_at`, `next_stamp_nonce`). The tip did not move, so the count of how
            // long it has been read goes on. A nonce of another line is a write of its own
            // (the tip may have moved away and back): another record.
            let (since, warned) = unmoved
                .as_ref()
                .filter(|u| u.record.replaced_by(&record))
                .map_or((tokio::time::Instant::now(), false), |u| {
                    (u.since, u.warned)
                });
            *unmoved = Some(Unmoved {
                record,
                since,
                warned,
            });
        }
        let since = unmoved.as_ref().map(|u| u.since);
        crate::health::record_chain_tip_time_ahead(
            &self.network,
            Duration::from_millis(at.saturating_sub(unix_ms_now())),
        );
        Some(TipAge { tip_at: at, since })
    }

    /// Taking the lock: consume the observation ([`Unmoved`]: none is left afterwards) and
    /// return how long this process has read the record it continues (`tip`, `tip_at`,
    /// `nonce`) unchanged as a follower, measured now; zero when the observation was of another
    /// record, or there was none. A record that only had its `tip_at` replaced since
    /// ([`TipRecord::replaced_by`]) is the one observed: the tip did not move.
    fn consume_observed(&self, tip: &Tip, tip_at: u64, nonce: Option<u64>) -> Duration {
        let record = TipRecord {
            tip: tip.clone(),
            tip_at,
            nonce,
        };
        self.unmoved
            .lock()
            .take()
            .filter(|u| u.record == record || u.record.replaced_by(&record))
            .map_or(Duration::ZERO, |u| u.since.elapsed())
    }

    /// Leader: the `tip_at` in the store for the indexed tip (`tip_at_floor_ms`: what this
    /// process wrote or took over) is further ahead of this clock than [`TIP_AT_MAX_AHEAD`].
    /// A takeover never leaves that ([`Self::adopt_tip_at`]), so this process's wall clock
    /// stepped back since. The tip's age would read 0 for the step, here (the confirmation
    /// bound that much longer) and on followers. The tip gets its time again on this clock:
    /// now, less the local time since it moved (`moved_instant`), written with its stamp by
    /// the next confirmation as a pending `tip_at`. So the bound is [`MAX_CONFIRM_AGE`] after
    /// the tip moved again, whatever the step; a tip that is older than that by the local
    /// clock is not confirmed any more, and nothing is written for it. Without the local
    /// instant nothing changes. A smaller step (the stored time not that far ahead) leaves
    /// the stored time alone; the bound holds all the same, on the local clock
    /// ([`Self::tip_confirmable`]).
    fn clock_stepped_back(&self) {
        let now = unix_ms_now();
        let floor = self.tip_at_floor_ms.load(Ordering::Relaxed);
        if floor <= now.saturating_add(TIP_AT_MAX_AHEAD.as_millis() as u64) {
            return;
        }
        let Some(since) = *self.moved_instant.lock() else {
            return;
        };
        let moved_at = replacement_tip_at(
            now.saturating_sub(since.elapsed().as_millis() as u64)
                .max(1),
            self.tip_at_before_ms.load(Ordering::Relaxed),
        );
        info!(network = %self.network, ahead_secs = (floor - now) / 1000, "chain follower: the time stored with the indexed tip is ahead of this clock (the clock stepped back); its next confirmation replaces it");
        self.moved_at_ms.store(moved_at, Ordering::Relaxed);
        self.tip_at_floor_ms.store(moved_at, Ordering::Relaxed);
        self.tip_at_pending.store(true, Ordering::Relaxed);
        self.tip_at_rewrite.store(true, Ordering::Relaxed);
        self.unconfirmed_logged.store(false, Ordering::Relaxed);
    }

    /// Leader: whether the indexed tip moved recently enough to be confirmed (see
    /// [`MAX_CONFIRM_AGE`]), by the wall clock and by the local clock since it moved
    /// (`moved_instant`, when known); logs once when it is not.
    fn tip_confirmable(&self, tip: &Tip) -> bool {
        self.clock_stepped_back();
        let moved_at = self.moved_at_ms.load(Ordering::Relaxed);
        // The larger of the wall-clock age and the local time since the tip moved: a wall
        // clock that stepped back, by however little, does not make the tip younger.
        let local =
            (*self.moved_instant.lock()).map_or(0, |since| since.elapsed().as_millis() as u64);
        let age = unix_ms_now().saturating_sub(moved_at).max(local);
        if moved_at > 0 && age <= MAX_CONFIRM_AGE.as_millis() as u64 {
            return true;
        }
        if !self.unconfirmed_logged.swap(true, Ordering::Relaxed) {
            warn!(network = %self.network, tip = tip.height, age_secs = age / 1000, "chain follower: the indexed tip has not moved for too long; it is no longer confirmed");
        }
        false
    }

    /// The stored tip, when the leader moved it in Unix milliseconds (`tip_at`, None: not
    /// stored, e.g. by a leader that does not write it), the leader's last confirmation
    /// (`tip_seen`, None: not stored) and the stamp that binds `tip_at` to its tip
    /// (`tip_stamp`, raw, None: not stored), in one `MGET`.
    async fn read_stored(&self) -> (Option<Tip>, Option<u64>, Option<Bytes>, Option<Bytes>) {
        let chain = self.store.chain_prefix();
        let mut values = self
            .store
            .mget(vec![
                tip_key(&chain),
                tip_at_key(&chain),
                tip_seen_key(&chain),
                tip_stamp_key(&chain),
            ])
            .await
            .into_iter();
        let tip = values.next().flatten().and_then(|b| decode_tip(&b));
        let tip_at = values.next().flatten().and_then(|b| decode_unix_ms(&b));
        let seen = values.next().flatten();
        let stamp = values.next().flatten();
        (tip, tip_at, seen, stamp)
    }

    /// Drop the held tip (see [`HeldTip`]) when the stored chain is no longer the one it was
    /// seen on: a stored tip at or below the last stored height read while holding with
    /// another block (a reorg of the stored chain), or a higher one while the index entry at
    /// that height names another block (the stored chain forked above it). An index entry that
    /// is missing or could not be read is no evidence either way: the held tip stays, and so
    /// does the last stored tip it is checked against ([`Revalidation::Unknown`]); a follower
    /// checks again on its next read, and the caller that takes the lock drops it instead
    /// ([`Self::drop_unresolved`]). Only a stored tip seen to extend it (the entry was read and
    /// names its block) becomes the last stored tip read, and only here.
    async fn revalidate_held(&self, stored: &Tip) -> Revalidation {
        let Some(last) = self.stale.lock().as_ref().map(|h| h.last_stored.clone()) else {
            return Revalidation::Kept;
        };
        // Some(true): `stored` extends `last`; Some(false): it does not; None: unknown.
        let same_chain = if *stored == last {
            Some(true)
        } else if stored.height <= last.height {
            Some(false)
        } else {
            let key = index_key(&self.store.chain_prefix(), last.height);
            self.store
                .mget(vec![key])
                .await
                .into_iter()
                .next()
                .flatten()
                .map(|h| h.as_ref() == last.hash.as_slice())
        };
        let mut held = self.stale.lock();
        match same_chain {
            Some(false) => {
                if held.is_some() {
                    info!(network = %self.network, stored = stored.height, last = last.height, "chain follower: the stored chain changed under the held tip; serving the stored tip");
                }
                *held = None;
                Revalidation::Dropped
            }
            Some(true) => {
                if let Some(h) = held.as_mut() {
                    h.last_stored = stored.clone();
                    h.unresolved = false;
                }
                Revalidation::Kept
            }
            None => match held.as_mut() {
                Some(h) => {
                    h.unresolved = true;
                    Revalidation::Unknown
                }
                None => Revalidation::Kept,
            },
        }
    }

    /// Taking the lock: drop a held tip whose last check of the stored chain found no index
    /// entry ([`Revalidation::Unknown`]). As leader this process does not read the stored chain
    /// as a follower again, so nothing would check it later. True when one was dropped.
    fn drop_unresolved(&self) -> bool {
        let mut held = self.stale.lock();
        if !held.as_ref().is_some_and(|h| h.unresolved) {
            return false;
        }
        info!(network = %self.network, "chain follower: the stored chain under the held tip could not be checked when the lock was taken; serving what it indexes");
        *held = None;
        true
    }

    /// The hashes of `own`'s chain above `stored` from this process's own lightwalletd (see
    /// [`HeldChain`]); None when that is more than [`MAX_CATCHUP`] blocks, the fetch fails, or
    /// the answer is not a chain of exactly those heights ending at `own`. The caller does not
    /// ask again for the same two tips after a None (`held_chain_unknown`): without the chain
    /// the held tip is served as before this check existed, never longer.
    async fn held_chain(&self, stored: &Tip, own: &Tip) -> Option<HeldChain> {
        let from = stored.height.checked_add(1)?;
        let count = own.height.checked_sub(from)?.checked_add(1)?;
        if count > MAX_CATCHUP {
            return None;
        }
        let blocks = match self.source.blocks(from, own.height).await {
            Ok(b) => b,
            Err(e) => {
                debug!(network = %self.network, error = %e, "stale tip check: the held tip's blocks are not available");
                return None;
            }
        };
        let complete = blocks.len() as u64 == count
            && blocks
                .iter()
                .enumerate()
                .all(|(i, b)| b.height == Some(from + i as u64) && !b.hash.is_empty())
            && blocks.last().is_some_and(|b| b.hash == own.hash)
            && chained(&blocks);
        complete.then(|| HeldChain {
            from,
            hashes: blocks.into_iter().map(|b| b.hash).collect(),
        })
    }

    /// Follower tick with a stored tip that has not moved for `age`: compare it with this
    /// process's own lightwalletd (every [`STALE_PROBE_EVERY`] ticks). A held tip whose own
    /// chain does not have the stored tip is dropped first, without a probe and without a new
    /// observation on this tick; that applies to a held tip still held when the probe starts.
    /// When the index check ([`Self::revalidate_held`]) dropped the held tip on this tick (the
    /// stored chain changed at or below the stored tip it was checked against), the probe goes
    /// on as an ordinary new observation of this process's own lightwalletd tip, as it always
    /// did: a stored tip unmoved for the stale bound with its own lightwalletd ahead is what
    /// this handling serves. None = nothing to do
    /// (the caller serves the stored tip, or the tip held from an earlier probe, see
    /// [`Self::follow_stored`]). `age` is the stored tip's age (wall clock and local bound, see
    /// [`Unmoved`]), None without an effective `tip_at`. See the module docs, "Stale leader".
    async fn check_stale_leader(
        &self,
        n: u64,
        stored: &Tip,
        tip_at_ms: Option<u64>,
        nonce: Option<u64>,
        age: Option<TipAge>,
    ) -> Option<Outcome> {
        if age.is_none_or(|a| a.get() <= self.stale_after) || !n.is_multiple_of(STALE_PROBE_EVERY) {
            return None;
        }
        // Met by the local bound alone: the stored time is ahead of this clock (a writer clock
        // ahead, this one behind, or a clock step). Logged once per record.
        if let Some(a) = age.filter(|a| a.wall() <= self.stale_after) {
            let mut unmoved = self.unmoved.lock();
            if let Some(u) = unmoved.as_mut().filter(|u| !u.warned) {
                u.warned = true;
                warn!(network = %self.network, stored = stored.height, local_secs = a.local().as_secs(), wall_secs = a.wall().as_secs(), "chain follower: the stored tip has not changed for longer than the stale bound by this process's clock, while its stored time is recent or ahead of this clock; probing its own lightwalletd");
            }
        }
        // A stored tip the held tip's own chain does not have (`HeldChain`): the held tip is
        // dropped here as on any other read (`follow_stored`), before anything is asked. No
        // new observation on this probe (it would hold the same tip again, for a full hold,
        // over a chain fetched from above the stored tip): the stored tip is served, and a
        // later probe starts an ordinary observation.
        let conflicting = {
            let mut held = self.stale.lock();
            let conflicting = held
                .as_ref()
                .is_some_and(|h| h.fresh() && h.off_chain(stored));
            if conflicting {
                *held = None;
            }
            conflicting
        };
        if conflicting {
            info!(network = %self.network, stored = stored.height, "chain follower: the stored tip is not on the held tip's chain; serving the stored tip");
            // Unknown until the caller serves the stored tip (if the leader confirms it).
            self.store.tip_cell().clear();
            return None;
        }
        let own = match self.source.latest().await {
            Ok(t) => {
                crate::health::record_lwd_reachable(&self.network, true);
                t
            }
            Err(e) => {
                crate::health::record_lwd_reachable(&self.network, false);
                debug!(network = %self.network, error = %e, "stale tip check: own lightwalletd unavailable");
                return None;
            }
        };
        if own.height <= stored.height || own.hash.is_empty() {
            // Not ahead (now): no takeover on the next probe. A tip held from an earlier probe
            // is kept until it ages out (see `follow_stored`).
            if let Some(held) = self.stale.lock().as_mut() {
                held.ahead = false;
            }
            return None;
        }
        // The chain of the tip it is about to hold, unless a held tip that stays (a higher
        // one, or this one with its chain known already) makes that unnecessary.
        let chain_known = self
            .stale
            .lock()
            .as_ref()
            .filter(|h| h.fresh() && !h.off_chain(stored))
            .is_some_and(|p| p.own.height > own.height || (p.own == own && p.chain.is_some()));
        // A fetch that gave nothing is not repeated for the same stored and own tip.
        let asked = (stored.clone(), own.clone());
        let fetched = if chain_known || self.held_chain_unknown.lock().as_ref() == Some(&asked) {
            None
        } else {
            let fetched = self.held_chain(stored, &own).await;
            *self.held_chain_unknown.lock() = fetched.is_none().then_some(asked);
            fetched
        };
        // Bind the observation to the current holder of the lock.
        let chain = self.store.chain_prefix();
        let holder = self
            .store
            .lock_holder(lock_key(&chain))
            .await
            .map(|h| h.unwrap_or_default());
        let now = tokio::time::Instant::now();
        let (served, seen_before, confirmed_at) = {
            let mut held = self.stale.lock();
            // `revalidate_held` dropped it already if the stored chain changed under it, and
            // the early drop above ended one whose own chain does not have the stored tip
            // (returning before this point). The `off_chain` filters here and where the chain
            // fetch is decided are a guard for that same case, not another path.
            let previous = held.take().filter(|h| h.fresh() && !h.off_chain(stored));
            // Never lower than a held tip that is still fresh: a lower answer (another instance
            // behind the same name, a lagging one) does not replace it, nor reset its age.
            let (served, confirmed_at, held_chain) = match &previous {
                Some(p) if p.own.height > own.height => {
                    (p.own.clone(), p.confirmed_at, p.chain.clone())
                }
                Some(p) if p.own == own && fetched.is_none() => (own.clone(), now, p.chain.clone()),
                _ => (own.clone(), now, fetched),
            };
            let seen_before = previous.as_ref().is_some_and(|p| {
                p.ahead && p.stored == *stored && p.holder.is_some() && p.holder == holder
            });
            // The stored tip the held tip is checked against moves only in `revalidate_held`
            // (where the stored chain was seen to extend it): a held tip that stays keeps it,
            // and whether its last check was resolved. A new observation starts at `stored`.
            let (last_stored, unresolved) = match &previous {
                Some(p) => (p.last_stored.clone(), p.unresolved),
                None => (stored.clone(), false),
            };
            *held = Some(HeldTip {
                stored: stored.clone(),
                last_stored,
                own: served.clone(),
                confirmed_at,
                ahead: holder.is_some(),
                holder: holder.clone(),
                unresolved,
                chain: held_chain,
            });
            (served, seen_before, confirmed_at)
        };
        // As seen at its probe: stale at the hold bound, not later.
        self.store.tip_cell().set_at(served.clone(), confirmed_at);
        crate::health::record_cache_tip_height(&self.network, served.height);
        let age_secs = age.map_or(0, |a| a.get().as_secs());
        let Some(holder) = holder.filter(|_| seen_before) else {
            warn!(network = %self.network, stored = stored.height, own = own.height, age_secs, "chain tip has not moved and this process's lightwalletd is ahead: serving its tip");
            crate::health::record_chain_stale_leader(&self.network, "local_tip");
            return Some(Outcome::StaleLeader {
                from: stored.height,
                to: served.height,
                took_over: false,
            });
        };
        let took_over = self
            .store
            .take_lock_if(
                lock_key(&chain),
                self.token.clone(),
                LOCK_TTL_MS,
                tip_key(&chain),
                encode_tip(stored),
                (!holder.is_empty()).then_some(holder),
            )
            .await
            == Some(true);
        if took_over {
            warn!(network = %self.network, stored = stored.height, own = own.height, age_secs, "chain follower took over from a leader whose tip stopped moving");
            crate::health::record_chain_stale_leader(&self.network, "takeover");
            self.set_leader(true);
            *self.last.lock() = Some(stored.clone());
            *self.backfill_cursor.lock() = None;
            self.behind_ticks.store(0, Ordering::Relaxed);
            // The age counts from the first read of this record at the latest, measured now
            // (after the probe and the lock commands); the observation is consumed.
            let observed = match tip_at_ms {
                Some(at) => self.consume_observed(stored, at, nonce),
                None => {
                    *self.unmoved.lock() = None;
                    Duration::ZERO
                }
            };
            self.adopt_tip_at(tip_at_ms, tip_at_ms, observed, nonce);
            // The held tip stays: what it indexes as leader does not make the served tip step
            // back within the hold (`serve_tip`). Unless the stored chain under it could not be
            // checked: no read as a follower checks it again.
            if self.drop_unresolved() {
                self.store.tip_cell().clear();
            }
            if let Some(held) = self.stale.lock().as_mut() {
                held.ahead = false;
            }
        } else if let Some(held) = self.stale.lock().as_mut() {
            // Refused (the tip or the holder changed meanwhile): start the observation again.
            held.ahead = false;
        }
        Some(Outcome::StaleLeader {
            from: stored.height,
            to: served.height,
            took_over,
        })
    }

    /// Follower: what to serve for the stored tip `stored`. The rule:
    ///
    /// - A held tip (its own lightwalletd ahead, see [`HeldTip`]) is served while it is fresh
    ///   (confirmed less than [`HELD_TIP_MAX_AGE`] ago, and served as seen then, so it goes
    ///   stale at that bound), still above `stored`, and the stored chain still extends the
    ///   stored tips read meanwhile ([`Self::revalidate_held`]). It never steps back meanwhile,
    ///   whatever probes answer.
    /// - Otherwise the held tip is dropped (aged out, caught up, or the stored chain forked:
    ///   `forked`, or a stored tip that is not the block the held tip's own chain has at that
    ///   height, when that chain is known) and the stored tip is served: one step back at most, after the age bound or a
    ///   fork. A stored tip that is not confirmed is not served instead: the tip is unknown.
    /// - The stored tip is refreshed only when the leader confirmed it since the last read
    ///   (`seen` changed), so a tip the leader stopped confirming goes stale here too. A leader
    ///   that does not write `seen` is followed as before, every read refreshing the tip: that
    ///   is the case without `seen`, with a `seen` older than `tip_at` (the key left by an
    ///   earlier leader, and the tip moved since), and with a `seen` that stays the same while
    ///   the stored tip changes (see [`SeenTip`]), until `seen` changes again. In the last two
    ///   cases only while the tip moved at most [`MAX_CONFIRM_AGE`] ago by `tip_at` (when
    ///   stored): an older tip is refreshed only by a changed `seen`, as under a leader of this
    ///   version.
    ///
    /// `age` is the stored tip's age ([`TipAge`]: the larger of the wall-clock age and the
    /// local bound), None without an effective `tip_at`.
    fn follow_stored(
        &self,
        stored: &Tip,
        tip_at_ms: Option<u64>,
        age: Option<TipAge>,
        seen: Option<Bytes>,
        forked: bool,
    ) {
        let (held, dropped) = {
            let mut held = self.stale.lock();
            // Not a stored tip the held tip's chain is known not to have (`HeldChain`): the
            // stored chain forked from it, seen without waiting for the index check.
            let keep = held
                .as_ref()
                .filter(|h| h.own.height > stored.height && h.fresh() && !h.off_chain(stored))
                .map(|h| (h.own.clone(), h.confirmed_at));
            let dropped = forked || (held.is_some() && keep.is_none());
            if keep.is_none() {
                *held = None;
            }
            (keep, dropped)
        };
        // A leader of this version never writes a `seen` below `tip_at`.
        let leftover_seen = matches!(
            (seen.as_deref().and_then(decode_unix_ms), tip_at_ms),
            (Some(seen), Some(at)) if seen < at
        );
        // A leader taken for one that does not confirm is followed on every read only while
        // the tip moved at most `MAX_CONFIRM_AGE` ago, the bound a leader of this version
        // confirms within: an older tip is refreshed only by a new confirmation. Without
        // `tip_at` there is no age to bound by.
        let legacy_fresh = age.is_none_or(|a| a.get() <= MAX_CONFIRM_AGE);
        let confirmed = match seen {
            None => {
                *self.last_seen.lock() = None;
                true
            }
            Some(seen) => {
                let mut last = self.last_seen.lock();
                let (confirmed, unconfirming_leader) = match last.as_ref() {
                    Some(prev) if prev.seen == seen => {
                        let unconfirming =
                            leftover_seen || prev.unconfirming_leader || prev.tip != *stored;
                        (unconfirming && legacy_fresh, unconfirming)
                    }
                    // First read, or a new confirmation: refreshed; the strict rule applies
                    // (again) unless the value is a leftover.
                    _ => (true, leftover_seen),
                };
                *last = Some(SeenTip {
                    seen,
                    tip: stored.clone(),
                    unconfirming_leader,
                });
                confirmed
            }
        };
        match held {
            Some((own, at)) => {
                crate::health::record_cache_tip_height(&self.network, own.height);
                self.store.tip_cell().set_at(own, at);
            }
            None if confirmed => {
                crate::health::record_cache_tip_height(&self.network, stored.height);
                self.store.tip_cell().set(stored.clone());
            }
            // The held tip is gone and the stored tip is not confirmed: neither is served.
            None if dropped => self.store.tip_cell().clear(),
            None => {}
        }
    }

    /// One poll. Public so tests drive the follower deterministically.
    pub async fn tick(&self) -> Outcome {
        let n = self.ticks.fetch_add(1, Ordering::Relaxed);
        let lock = lock_key(&self.store.chain_prefix());
        let held = if self.is_leader() {
            self.store
                .pexpire_if_equal(lock, self.token.clone(), LOCK_TTL_MS)
                .await
        } else if n < self.cooldown_until.load(Ordering::Relaxed) {
            // Gave the lock up a moment ago (its lightwalletd stays behind): let another lead.
            Some(false)
        } else {
            self.store
                .set_nx_px(lock, self.token.clone(), LOCK_TTL_MS)
                .await
        };
        let became_leader = held == Some(true) && !self.is_leader();
        self.set_leader(held == Some(true));

        if !self.is_leader() {
            // Follow the leader's tip unless it stopped moving while this process's own
            // lightwalletd moved on; probe lightwalletd now and then for the health gauge.
            let (stored, tip_at, seen, stamp) = self.read_stored().await;
            let (tip_at, nonce, age) = match &stored {
                Some(tip) => {
                    let (tip_at, nonce) = self.effective_tip_at(tip, tip_at, stamp.as_ref());
                    (tip_at, nonce, self.observe(tip, tip_at, nonce))
                }
                // No tip read (a store error or no key): no record to observe, the observation
                // is kept; no stored time to compare with this clock.
                None => {
                    crate::health::record_chain_tip_time_ahead(&self.network, Duration::ZERO);
                    (
                        tip_at,
                        None,
                        tip_at.map(|at| TipAge {
                            tip_at: at,
                            since: None,
                        }),
                    )
                }
            };
            crate::health::record_chain_tip_age(&self.network, age.map(|a| a.get()));
            let mut took_over = false;
            if let Some(tip) = stored {
                let forked = self.revalidate_held(&tip).await == Revalidation::Dropped;
                match self.check_stale_leader(n, &tip, tip_at, nonce, age).await {
                    // Leader now: this tick continues as one (below), so the stored tip moves
                    // before another process could take it over too.
                    Some(Outcome::StaleLeader {
                        took_over: true, ..
                    }) => took_over = true,
                    Some(outcome) => return outcome,
                    None => self.follow_stored(&tip, tip_at, age, seen, forked),
                }
            }
            if !took_over {
                if n.is_multiple_of(HEALTH_PROBE_EVERY) {
                    crate::health::record_lwd_reachable(
                        &self.network,
                        self.source.latest().await.is_ok(),
                    );
                }
                return Outcome::Follower;
            }
        }

        // The lock is renewed (exact token) while the tick runs, so leader work longer than the
        // TTL (a cold start, a catch-up) keeps it. When a renewal finds the lock held by another
        // process, or renewals fail for a whole TTL (the lease may have lapsed), the work is
        // cancelled at once: it could only be refused at its next fenced write. A tick that
        // fails (lightwalletd unreachable, an answer that does not chain) releases the lock,
        // so another process, maybe with another lightwalletd, can lead from its next tick
        // instead of after the TTL.
        let renew = async {
            let mut renewed_at = tokio::time::Instant::now();
            loop {
                tokio::time::sleep(LOCK_RENEW_EVERY).await;
                match self
                    .store
                    .pexpire_if_equal(
                        lock_key(&self.store.chain_prefix()),
                        self.token.clone(),
                        LOCK_TTL_MS,
                    )
                    .await
                {
                    Some(true) => renewed_at = tokio::time::Instant::now(),
                    Some(false) => return "the lock is held by another process",
                    None if renewed_at.elapsed() >= Duration::from_millis(LOCK_TTL_MS) => {
                        return "the lock could not be renewed for its whole TTL"
                    }
                    None => {}
                }
            }
        };
        let outcome = tokio::select! {
            o = self.lead(n, became_leader) => o,
            why = renew => {
                info!(network = %self.network, why, "chain follower: leader work cancelled");
                self.set_leader(false);
                Outcome::Follower
            }
        };
        if let Outcome::Error(e) = &outcome {
            if self.is_leader() {
                debug!(network = %self.network, error = %e, "chain follower: handing the lock over after a failed tick");
                self.store
                    .release_lock(lock_key(&self.store.chain_prefix()), self.token.clone())
                    .await;
                self.set_leader(false);
            }
        }
        outcome
    }

    /// Confirm the indexed tip `tip` (the lightwalletd answered with it, or the leader keeps it
    /// while its lightwalletd is behind): rewrite `tip_seen` under the lock, then refresh the
    /// tip here. The value is the time now, but never below the stored `tip_at` (followers
    /// take a lower one for a leftover of an earlier leader; a `tip_at` in the future counts as
    /// stored, see [`Self::adopt_tip_at`]) nor at or below the value this process wrote last
    /// (each of its confirmations is new to followers). With a `tip_at` still to write (see
    /// [`Self::adopt_tip_at`]: none was stored, or one too far ahead of this clock) the same
    /// script writes it. False when the lock is held by another
    /// process (the caller stops leading). A store error only skips this confirmation.
    async fn confirm(&self, tip: &Tip) -> bool {
        let chain = self.store.chain_prefix();
        let moved_at = self.moved_at_ms.load(Ordering::Relaxed);
        let seen = unix_ms_now()
            .max(moved_at)
            .max(self.tip_at_floor_ms.load(Ordering::Relaxed))
            .max(self.seen_written_ms.load(Ordering::Relaxed) + 1);
        let pending = self.tip_at_pending.load(Ordering::Relaxed);
        let mut entries = vec![(tip_seen_key(&chain), encode_unix_ms(seen), INDEX_TTL_SECS)];
        let mut stamped = None;
        if pending {
            // `tip_at` with its stamp for the indexed tip. This script does not compare the
            // stored tip: in a store that lost writes the stamp may name another tip than the
            // stored one, and is then no evidence for readers.
            // A `tip_at` that replaces a stamped one (the tip did not move) gets the
            // next nonce of that stamp's line, any other a random nonce of its own.
            let replaced =
                (*self.stamp_nonce.lock()).filter(|_| self.tip_at_rewrite.load(Ordering::Relaxed));
            let nonce = replaced.map_or_else(rand::random::<u64>, next_stamp_nonce);
            stamped = Some(nonce);
            entries.push((tip_at_key(&chain), encode_unix_ms(moved_at), INDEX_TTL_SECS));
            entries.push((
                tip_stamp_key(&chain),
                encode_tip_stamp(moved_at, nonce, tip),
                INDEX_TTL_SECS,
            ));
        }
        match self
            .store
            .set_if_lock_held(lock_key(&chain), self.token.clone(), LOCK_TTL_MS, entries)
            .await
        {
            Some(true) => {
                self.seen_written_ms.store(seen, Ordering::Relaxed);
                if pending {
                    *self.stamp_nonce.lock() = stamped;
                    self.tip_at_pending.store(false, Ordering::Relaxed);
                    if self.tip_at_rewrite.swap(false, Ordering::Relaxed) {
                        crate::health::record_chain_tip_at_rewrite(&self.network);
                    }
                    self.tip_at_stored_ms.store(moved_at, Ordering::Relaxed);
                    *self.unmoved.lock() = None;
                    // Its own time from now on.
                    crate::health::record_chain_tip_time_ahead(&self.network, Duration::ZERO);
                }
                self.serve_tip(tip);
                true
            }
            Some(false) => {
                self.lost_lock("tip confirmation");
                false
            }
            None => true,
        }
    }

    /// The leader's part of tick `n`.
    async fn lead(&self, n: u64, became_leader: bool) -> Outcome {
        if became_leader {
            // Continue from the previous leader's index, and from the time it moved the tip
            // (the confirmation bound does not restart with a new leader). A tip held from its
            // own lightwalletd stays (`serve_tip`) only if the stored chain it continues is
            // still the one the tip was held on: the stored tip may have changed since this
            // process last read it as a follower (another leader in between), and no reorg is
            // indexed for a chain it merely continues.
            // A `tip_at` this process saw left over by a leader that does not write it (as a
            // follower, see `TipAtRead`) does not count: the time is now, written with the next
            // confirmation.
            // The age counts from this process's first read of the same record as a follower
            // at the latest (`Unmoved`).
            let (stored, tip_at, _, stamp) = self.read_stored().await;
            let stored_raw_tip_at = tip_at;
            let (dropped, tip_at, observed, nonce) = match &stored {
                Some(stored) => {
                    let dropped = match self.revalidate_held(stored).await {
                        Revalidation::Kept => false,
                        Revalidation::Dropped => true,
                        // As leader nothing reads the stored chain to check it again.
                        Revalidation::Unknown => self.drop_unresolved(),
                    };
                    let (tip_at, nonce) = self.effective_tip_at(stored, tip_at, stamp.as_ref());
                    let observed = match tip_at {
                        Some(at) => self.consume_observed(stored, at, nonce),
                        None => Duration::ZERO,
                    };
                    (dropped, tip_at, observed, nonce)
                }
                None => (
                    self.stale.lock().take().is_some(),
                    tip_at,
                    Duration::ZERO,
                    None,
                ),
            };
            // Consumed by the takeover, whatever it continues.
            *self.unmoved.lock() = None;
            if dropped {
                // Unknown until this tick serves what it indexes.
                self.store.tip_cell().clear();
            }
            *self.last.lock() = stored;
            self.adopt_tip_at(tip_at, stored_raw_tip_at, observed, nonce);
            *self.backfill_cursor.lock() = None;
            self.behind_ticks.store(0, Ordering::Relaxed);
        }

        let latest = match self.source.latest().await {
            Ok(t) => t,
            Err(e) => {
                crate::health::record_lwd_reachable(&self.network, false);
                return Outcome::Error(format!("GetLatestBlock: {e}"));
            }
        };
        crate::health::record_lwd_reachable(&self.network, true);
        if latest.height == 0 || latest.hash.is_empty() {
            return Outcome::Error("GetLatestBlock returned an empty tip".to_string());
        }

        let moved_at = self.moved_at_ms.load(Ordering::Relaxed);
        crate::health::record_chain_tip_age(
            &self.network,
            (moved_at > 0).then(|| Duration::from_millis(unix_ms_now().saturating_sub(moved_at))),
        );
        let last = self.last.lock().clone();
        let outcome = match last {
            None => self.index_cold(&latest).await,
            Some(last) if last == latest => {
                if self.tip_confirmable(&last) && !self.confirm(&last).await {
                    return Outcome::Follower;
                }
                Ok(Outcome::Idle)
            }
            Some(last) if latest.height > last.height => self.advance(&last, &latest).await,
            Some(last) if latest.height < last.height && self.on_index(&latest).await => {
                // A lightwalletd that is behind (e.g. one of several behind a load-balanced
                // address), not a reorg: keep the tip and the index.
                debug!(network = %self.network, backend = latest.height, tip = last.height, "chain follower: lightwalletd behind the indexed tip");
                let behind = self.behind_ticks.fetch_add(1, Ordering::Relaxed) + 1;
                if behind <= MAX_BEHIND_TICKS {
                    if self.tip_confirmable(&last) && !self.confirm(&last).await {
                        return Outcome::Follower;
                    }
                } else {
                    warn!(network = %self.network, backend = latest.height, tip = last.height, ticks = behind, "chain follower: lightwalletd stays behind the indexed tip; giving the lock up");
                    self.store
                        .release_lock(lock_key(&self.store.chain_prefix()), self.token.clone())
                        .await;
                    self.set_leader(false);
                    self.cooldown_until
                        .store(n + 1 + BEHIND_COOLDOWN_TICKS, Ordering::Relaxed);
                }
                Ok(Outcome::Behind {
                    backend: latest.height,
                    tip: last.height,
                })
            }
            Some(last) => self.reorg(&last, &latest, latest.height).await,
        };
        if !matches!(outcome, Ok(Outcome::Behind { .. })) {
            self.behind_ticks.store(0, Ordering::Relaxed);
        }
        match outcome {
            Ok(o) => {
                if matches!(o, Outcome::Idle) && self.is_leader() {
                    self.backfill_step().await;
                }
                o
            }
            Err(e) => Outcome::Error(e.to_string()),
        }
    }

    /// First tip ever indexed: fetch the tip block, write index and tip, start the backfill.
    async fn index_cold(&self, latest: &Tip) -> Result<Outcome> {
        let blocks = self.source.blocks(latest.height, latest.height).await?;
        let tip = match blocks.last() {
            Some(b) if b.height == Some(latest.height) && !b.hash.is_empty() => Tip {
                height: latest.height,
                hash: b.hash.clone(),
            },
            _ => latest.clone(),
        };
        if !self.store_blocks(&blocks, tip.height).await? {
            return Ok(Outcome::Follower);
        }
        if !self.write_tip(&tip).await? {
            return Ok(Outcome::Follower);
        }
        *self.backfill_cursor.lock() = Some(tip.height.saturating_sub(1));
        Ok(Outcome::Cold { tip: tip.height })
    }

    /// New blocks above the indexed tip.
    async fn advance(&self, last: &Tip, latest: &Tip) -> Result<Outcome> {
        let from = last.height + 1;
        let to = latest.height.min(from + MAX_CATCHUP - 1);
        let blocks = self.source.blocks(from, to).await?;
        if blocks.is_empty() {
            return Ok(Outcome::Idle);
        }
        let first = &blocks[0];
        if first.height != Some(from) {
            anyhow::bail!("GetBlockRange({from},{to}) started at {:?}", first.height);
        }
        if !first.prev_hash.is_empty() && first.prev_hash != last.hash {
            return self.reorg(last, latest, last.height).await;
        }
        if !chained(&blocks) {
            anyhow::bail!("GetBlockRange({from},{to}) is not a chain");
        }
        let new_tip = tip_of(&blocks).unwrap_or_else(|| latest.clone());
        if !self.store_blocks(&blocks, new_tip.height).await? {
            return Ok(Outcome::Follower);
        }
        if !self.write_tip(&new_tip).await? {
            return Ok(Outcome::Follower);
        }
        self.promote_final(last.height, &new_tip).await;
        Ok(Outcome::Advanced {
            from,
            to: new_tip.height,
        })
    }

    /// The chain moved under the index: find the fork point below `from`, invalidate above
    /// it, refetch and rewrite up to `latest`.
    async fn reorg(&self, last: &Tip, latest: &Tip, from: u64) -> Result<Outcome> {
        let chain = self.store.chain_prefix();
        let mut top = from.min(last.height);
        let floor = top.saturating_sub(MAX_WALK_BACK).max(1);
        let mut fork: Option<u64> = None;
        while fork.is_none() && top >= floor {
            let start = top.saturating_sub(WALK_BATCH - 1).max(floor);
            let canonical = self.source.blocks(start, top).await?;
            let heights: Vec<u64> = (start..=top).collect();
            let keys: Vec<String> = heights.iter().map(|h| index_key(&chain, *h)).collect();
            let index = self.store.mget(keys).await;
            for (i, h) in heights.iter().copied().enumerate().rev() {
                let canon = canonical.iter().find(|b| b.height == Some(h));
                match (canon, index.get(i).cloned().flatten()) {
                    // No index entry: nothing cached is validated here; stop.
                    (_, None) => {
                        fork = Some(h);
                        break;
                    }
                    (Some(b), Some(idx)) if b.hash.as_slice() == idx.as_ref() => {
                        fork = Some(h);
                        break;
                    }
                    _ => {}
                }
            }
            if start <= floor {
                break;
            }
            top = start - 1;
        }
        let fork = fork.unwrap_or(floor.saturating_sub(1));
        let depth = last.height.saturating_sub(fork);
        warn!(
            network = %self.network,
            fork,
            depth,
            old_tip = last.height,
            new_tip = latest.height,
            "chain reorg: invalidating above the fork point"
        );
        crate::health::record_chain_reorg(&self.network, depth);
        // A reorg is the one case the served tip may step back within the hold.
        *self.stale.lock() = None;

        // Invalidate fork+1 ..= old tip (and anything above, up to the new tip): the index
        // entries and the payload (cached blocks of every pool filter seen, nullifiers, tree
        // states, non-final subtree roots), only while this process still holds the lock: a
        // leader replaced while this tick was in flight must not delete what the one that
        // replaced it wrote. A refusal or a store error stops the tick.
        let upper = last.height.max(latest.height);
        let epoch = self.store.epoch().await;
        let prefix = self.store.key_prefix(epoch);
        let pools = self.pools.all();
        let mut keys = Vec::new();
        for h in fork + 1..=upper {
            keys.push(index_key(&chain, h));
            for p in &pools {
                keys.push(block_key(&prefix, p, h));
            }
            keys.push(crate::cache::height_key(&prefix, "nullifiers", h));
            keys.push(crate::cache::height_key(&prefix, "treestate", h));
        }
        // Non-final subtree roots completing above the fork (and their height pointers).
        keys.extend(crate::subtree_cache::reorg_keys(&*self.store, &prefix, fork + 1, upper).await);
        for chunk in keys.chunks(DELETE_BATCH) {
            match self
                .store
                .del_if_lock_held(lock_key(&chain), self.token.clone(), chunk.to_vec())
                .await
            {
                Some(true) => {}
                Some(false) => {
                    self.lost_lock("reorg invalidation");
                    return Ok(Outcome::Follower);
                }
                None => anyhow::bail!(
                    "reorg invalidation: store error or timeout (after a timeout the outcome is unknown)"
                ),
            }
            if let Some(local) = &self.local {
                for k in chunk {
                    local.invalidate(k);
                }
            }
        }

        // Refetch the canonical chain above the fork and rewrite the index.
        let to = latest.height.min(fork + MAX_CATCHUP + MAX_WALK_BACK);
        let blocks = self.source.blocks(fork + 1, to).await?;
        if !chained(&blocks) {
            anyhow::bail!("GetBlockRange({},{to}) is not a chain", fork + 1);
        }
        let new_tip = tip_of(&blocks).unwrap_or_else(|| latest.clone());
        if !self.store_blocks(&blocks, new_tip.height).await? {
            return Ok(Outcome::Follower);
        }
        if !self.write_tip(&new_tip).await? {
            return Ok(Outcome::Follower);
        }
        self.promote_final(last.height, &new_tip).await;
        Ok(Outcome::Reorg {
            fork,
            depth,
            tip: new_tip.height,
        })
    }

    /// Store `blocks` (pool filter none) and their index entries: final blocks against
    /// `tip_height` go to the permanent tier, the rest to the block cache.
    ///
    /// The index entry and the cache-tier block of every block are written together, in
    /// scripts that write only while this process holds the lock with its own token (the same
    /// fence as the tip, [`Self::write_tip`]), at most [`BLOCK_WRITE_BATCH`] blocks and
    /// [`BLOCK_WRITE_BATCH_BYTES`] of block payload per script (see [`write_batches`]). The
    /// epoch is checked once before (as an epoch-checked write does); while it is not current
    /// only the index is written. Ok(false) when the lock is held by another process (or by
    /// none): this one was replaced while its tick was in flight, so the batch and every later
    /// one are not written and it stops leading; a fetch of another fork that was in flight
    /// cannot overwrite the new leader's index or blocks. Err on a store error or timeout
    /// (after a timeout the script may or may not have run): the tick stops (and hands the lock
    /// over). Final blocks go to the permanent tier after the
    /// fenced batches (they are below any reorg depth).
    async fn store_blocks(&self, blocks: &[FetchedBlock], tip_height: u64) -> Result<bool> {
        let chain = self.store.chain_prefix();
        let epoch = self.store.epoch().await;
        let prefix = self.store.key_prefix(epoch);
        let blocks_current = self.store.epoch_current(epoch).await == Some(true);
        let mut permanent: Vec<(String, Bytes)> = Vec::new();
        let usable: Vec<&FetchedBlock> = blocks
            .iter()
            .filter(|b| b.height.is_some() && !b.hash.is_empty())
            .collect();
        // The payload a block adds to its script: nothing when it goes to the permanent tier
        // or is not written (only its index entry is).
        let payload = |b: &&FetchedBlock| match b.height {
            Some(h) if blocks_current && !self.permanent_height(h, tip_height) => b.message().len(),
            _ => 0,
        };
        let sizes: Vec<usize> = usable.iter().map(payload).collect();
        for range in write_batches(&sizes, BLOCK_WRITE_BATCH, BLOCK_WRITE_BATCH_BYTES) {
            let batch = &usable[range];
            let mut entries: Vec<(String, Bytes, u64)> = Vec::with_capacity(batch.len() * 2);
            let mut cached: Vec<(String, Bytes)> = Vec::new();
            for b in batch {
                let Some(h) = b.height else { continue };
                entries.push((
                    index_key(&chain, h),
                    Bytes::from(b.hash.clone()),
                    INDEX_TTL_SECS,
                ));
                if self.permanent_height(h, tip_height) {
                    permanent.push((permanent_block_key(&self.network, "", h), b.message()));
                } else if blocks_current {
                    let bk = block_key(&prefix, "", h);
                    entries.push((bk.clone(), b.message(), 0));
                    cached.push((bk, b.message()));
                }
            }
            match self
                .store
                .set_if_lock_held(lock_key(&chain), self.token.clone(), LOCK_TTL_MS, entries)
                .await
            {
                Some(true) => {}
                Some(false) => {
                    self.lost_lock("block write");
                    return Ok(false);
                }
                None => anyhow::bail!(
                    "fenced block write: store error or timeout (after a timeout the outcome is unknown)"
                ),
            }
            if let Some(local) = &self.local {
                for (k, v) in cached {
                    local.insert(k, v);
                }
            }
        }
        if let (Some(perm), false) = (&self.permanent, permanent.is_empty()) {
            if let Some(local) = &self.local {
                for (k, v) in &permanent {
                    local.insert(k.clone(), v.clone());
                }
            }
            let n = permanent.len() as u64;
            if perm.set_many(permanent).await {
                crate::health::record_block_permanent(&self.network, "stored", n);
            }
        }
        crate::health::record_upstream_blocks(&self.network, blocks.len() as u64);
        Ok(true)
    }

    /// A fenced write found the lock held by another process (or by none): stop leading.
    fn lost_lock(&self, what: &str) {
        info!(network = %self.network, what, "chain follower: the lock is no longer held, write refused");
        self.set_leader(false);
    }

    /// Move the blocks that became final with the advance from `old_tip` to `new_tip` from the
    /// cache Redis to the permanent tier: every pool filter seen, only entries whose hash
    /// matches the index. Missing entries are left to write-through.
    async fn promote_final(&self, old_tip: u64, new_tip: &Tip) {
        let Some(perm) = self.permanent.as_ref().filter(|p| p.writable()) else {
            return;
        };
        let Some(hi) = new_tip.height.checked_sub(PERMANENT_DEPTH) else {
            return;
        };
        let lo = (old_tip + 1)
            .saturating_sub(PERMANENT_DEPTH)
            .max(self.permanent_min_height)
            .max(1);
        if lo > hi {
            return;
        }
        let heights: Vec<u64> = (lo..=hi).collect();
        let epoch = self.store.epoch().await;
        let prefix = self.store.key_prefix(epoch);
        let chain = self.store.chain_prefix();
        let index = self
            .store
            .mget(heights.iter().map(|h| index_key(&chain, *h)).collect())
            .await;
        let mut moved = 0u64;
        for pool in self.pools.all() {
            let keys: Vec<String> = heights
                .iter()
                .map(|h| block_key(&prefix, &pool, *h))
                .collect();
            let values = self.store.mget(keys.clone()).await;
            let mut entries = Vec::new();
            let mut drop = Vec::new();
            for (i, h) in heights.iter().copied().enumerate() {
                let (Some(bytes), Some(canonical)) = (
                    values.get(i).cloned().flatten(),
                    index.get(i).cloned().flatten(),
                ) else {
                    continue;
                };
                let block = FetchedBlock::from_frame(grpc_frame(&bytes));
                if block.height != Some(h) || block.hash.as_slice() != canonical.as_ref() {
                    continue;
                }
                entries.push((permanent_block_key(&self.network, &pool, h), bytes));
                drop.push(keys[i].clone());
            }
            if entries.is_empty() {
                continue;
            }
            let n = entries.len() as u64;
            if perm.set_many(entries).await {
                moved += n;
                if let Some(local) = &self.local {
                    for k in &drop {
                        local.invalidate(k);
                    }
                }
                self.store.del(drop).await;
            }
        }
        if moved > 0 {
            crate::health::record_block_permanent(&self.network, "promoted", moved);
            debug!(network = %self.network, lo, hi, moved, "final blocks moved to the permanent tier");
        }
    }

    /// Whether `tip` (a lower height than the indexed tip) is a block of the indexed chain.
    async fn on_index(&self, tip: &Tip) -> bool {
        if tip.hash.is_empty() {
            return false;
        }
        let key = index_key(&self.store.chain_prefix(), tip.height);
        self.store
            .mget(vec![key])
            .await
            .into_iter()
            .next()
            .flatten()
            .is_some_and(|h| h.as_ref() == tip.hash.as_slice())
    }

    /// Store `tip`, when it moved and that it is confirmed, only while this process holds the
    /// lock. Ok(false) when it does not any more (replaced by another process during this
    /// tick): it stops leading and leaves the stored tip alone. Err when the store did not
    /// answer: the tick stops (the tip is not taken over in memory either).
    async fn write_tip(&self, tip: &Tip) -> Result<bool> {
        let chain = self.store.chain_prefix();
        // The clock value, as stored `tip_at`: it follows the clock, also back (a value kept
        // ahead of the clock would look fresh to followers for as long as the step). Only
        // never the `tip_at` stored with the previous tip (two tips in one millisecond): a tip
        // that moves with an unchanged `tip_at` was written by a leader that does not write it
        // (`TipAtRead`). So neither the last value this process wrote nor the one in the store
        // when it took the tip over or last wrote it, a leftover it does not go by included.
        let wall = unix_ms_now();
        let now = tip_at_to_write(
            wall,
            self.tip_at_written_ms.load(Ordering::Relaxed),
            self.tip_at_stored_ms.load(Ordering::Relaxed),
        );
        // A new confirmation, never below `tip_at` (see `confirm`).
        let seen = now.max(self.seen_written_ms.load(Ordering::Relaxed) + 1);
        // The stamp binds `tip_at` to this tip, with a nonce of this write (`TipAtRead`).
        let nonce = rand::random::<u64>();
        let written = self
            .store
            .set_if_lock_held(
                lock_key(&chain),
                self.token.clone(),
                LOCK_TTL_MS,
                vec![
                    (tip_key(&chain), encode_tip(tip), INDEX_TTL_SECS),
                    (tip_at_key(&chain), encode_unix_ms(now), INDEX_TTL_SECS),
                    (tip_seen_key(&chain), encode_unix_ms(seen), INDEX_TTL_SECS),
                    (
                        tip_stamp_key(&chain),
                        encode_tip_stamp(now, nonce, tip),
                        INDEX_TTL_SECS,
                    ),
                ],
            )
            .await;
        match written {
            Some(true) => {}
            Some(false) => {
                warn!(network = %self.network, height = tip.height, "chain follower lost the leader lock during this tick: tip not written");
                self.set_leader(false);
                return Ok(false);
            }
            None => anyhow::bail!(
                "tip write: store error or timeout (after a timeout the outcome is unknown)"
            ),
        }
        // As in `adopt_tip_at`: the age counts from this clock, never from a stored value ahead
        // of it (after the clock stepped back, the confirmation bound would last for the step
        // on top); the confirmations stay at or above the value stored.
        self.moved_at_ms.store(now.min(wall), Ordering::Relaxed);
        *self.moved_instant.lock() = Some(tokio::time::Instant::now());
        *self.stamp_nonce.lock() = Some(nonce);
        self.tip_at_floor_ms.store(now, Ordering::Relaxed);
        self.tip_at_written_ms.store(now, Ordering::Relaxed);
        self.tip_at_before_ms.store(
            self.tip_at_stored_ms.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.tip_at_stored_ms.store(now, Ordering::Relaxed);
        self.seen_written_ms.store(seen, Ordering::Relaxed);
        self.tip_at_pending.store(false, Ordering::Relaxed);
        self.tip_at_rewrite.store(false, Ordering::Relaxed);
        self.unconfirmed_logged.store(false, Ordering::Relaxed);
        *self.unmoved.lock() = None;
        // Its own time from now on.
        crate::health::record_chain_tip_time_ahead(&self.network, Duration::ZERO);
        *self.last.lock() = Some(tip.clone());
        self.notify_new_block(tip);
        Ok(true)
    }

    /// Fill index gaps inside the window, one batch per idle tick.
    async fn backfill_step(&self) {
        let (cursor, tip) = {
            let c = *self.backfill_cursor.lock();
            let Some(c) = c else { return };
            let Some(t) = self.last.lock().clone() else {
                return;
            };
            (c, t.height)
        };
        let low_bound = tip.saturating_sub(INDEX_WINDOW).max(1);
        if cursor < low_bound {
            *self.backfill_cursor.lock() = None;
            info!(network = %self.network, "chain index backfill done");
            return;
        }
        let start = cursor.saturating_sub(BACKFILL_BATCH - 1).max(low_bound);
        let chain = self.store.chain_prefix();
        let keys: Vec<String> = (start..=cursor).map(|h| index_key(&chain, h)).collect();
        let present = self.store.mget(keys).await;
        // Missing heights, grouped into maximal contiguous runs.
        let mut runs: Vec<(u64, u64)> = Vec::new();
        for (i, h) in (start..=cursor).enumerate() {
            if present.get(i).map(|v| v.is_some()).unwrap_or(false) {
                continue;
            }
            match runs.last_mut() {
                Some((_, e)) if *e + 1 == h => *e = h,
                _ => runs.push((h, h)),
            }
        }
        for (s, e) in runs {
            match self.source.blocks(s, e).await {
                Ok(blocks) => {
                    debug!(network = %self.network, start = s, end = e, n = blocks.len(), "chain index backfill");
                    match self.store_blocks(&blocks, tip).await {
                        Ok(true) => {}
                        Ok(false) => return,
                        Err(err) => {
                            warn!(network = %self.network, error = %err, "chain index backfill write failed");
                            return;
                        }
                    }
                }
                Err(err) => {
                    warn!(network = %self.network, start = s, end = e, error = %err, "chain index backfill fetch failed");
                    return;
                }
            }
        }
        *self.backfill_cursor.lock() = Some(start.saturating_sub(1));
    }
}

/// The nonce of the stamp a leader writes when it replaces the `tip_at` of a tip that did not
/// move (a `tip_at` ahead of its clock, see [`ChainFollower::adopt_tip_at`]), from the nonce
/// of the stamp it replaces: the same upper half, the lower half one higher (wrapping).
/// The upper half is the line of a write of the tip; a reader that read a stamp of the
/// line recognises every later replacement by it, however many it missed in between, and
/// goes on counting how long it has read the tip ([`TipRecord::replaced_by`]). Every other
/// stamp carries a random nonce, which is on the line only by a coincidence of 32 bits (and
/// is then taken for a replacement only next to the same tip with an earlier `tip_at`).
fn next_stamp_nonce(nonce: u64) -> u64 {
    (nonce & !STAMP_NONCE_STEP_MASK) | u64::from((nonce as u32).wrapping_add(1))
}

/// The half of a stamp's nonce that replacements change ([`next_stamp_nonce`]).
const STAMP_NONCE_STEP_MASK: u64 = 0xFFFF_FFFF;

/// The `tip_at` to give a tip whose stored one is replaced (`at`, the tip's time on this
/// clock), given the `tip_at` of the tip before it when this process knows it (`before`, 0:
/// not known): never that value, so that a tip does not come with the `tip_at` of the tip
/// before it by this write either (see [`tip_at_to_write`]: a reader that knows no stamp and
/// missed the value replaced would take it for a leftover).
fn replacement_tip_at(at: u64, before: u64) -> u64 {
    if at != before {
        at
    } else if at > 1 {
        at - 1
    } else {
        at + 1
    }
}

/// The `tip_at` to write with a new tip at clock time `wall`: `wall`, or the next value that is
/// neither `written` (the last one this process wrote) nor `stored` (the one in the store).
fn tip_at_to_write(wall: u64, written: u64, stored: u64) -> u64 {
    let mut at = wall;
    while at == written || at == stored {
        at += 1;
    }
    at
}

/// How long ago the Unix millisecond time `ms` was (zero for a time ahead of this clock).
fn age_of(ms: u64) -> Duration {
    Duration::from_millis(unix_ms_now().saturating_sub(ms))
}

/// Split items of `sizes` bytes into consecutive batches of at most `max_items` items and
/// `max_bytes` bytes each; an item larger than `max_bytes` is a batch of its own.
fn write_batches(
    sizes: &[usize],
    max_items: usize,
    max_bytes: usize,
) -> Vec<std::ops::Range<usize>> {
    let mut batches = Vec::new();
    let (mut start, mut bytes) = (0, 0usize);
    for (i, size) in sizes.iter().enumerate() {
        if i > start && (i - start >= max_items || bytes.saturating_add(*size) > max_bytes) {
            batches.push(start..i);
            start = i;
            bytes = 0;
        }
        bytes = bytes.saturating_add(*size);
    }
    if start < sizes.len() {
        batches.push(start..sizes.len());
    }
    batches
}

/// Whether consecutive blocks chain (`prev_hash` of each equals the hash of the previous and the
/// heights are consecutive). A pair where either hash is empty is not checked.
pub fn chained(blocks: &[FetchedBlock]) -> bool {
    blocks.windows(2).all(|w| {
        w[0].hash.is_empty()
            || w[1].prev_hash.is_empty()
            || (w[1].prev_hash == w[0].hash && w[1].height == w[0].height.map(|h| h + 1))
    })
}

fn tip_of(blocks: &[FetchedBlock]) -> Option<Tip> {
    let b = blocks.last()?;
    Some(Tip {
        height: b.height?,
        hash: b.hash.clone(),
    })
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::block_cache::test_support::FakeChain;
    use crate::block_cache::{grpc_frame, FetchedBlock};

    /// The fake lightwalletd's chain view as a `ChainSource`.
    pub struct FakeChainSource(pub Arc<FakeChain>);

    /// `ChainFollower::write_tip`, for the tests against a real store.
    pub async fn write_tip(f: &ChainFollower, tip: &Tip) -> Result<bool> {
        f.write_tip(tip).await
    }

    impl ChainSource for FakeChainSource {
        fn latest(&self) -> BoxFuture<'static, Result<Tip>> {
            let c = self.0.clone();
            Box::pin(async move {
                c.latest_calls.fetch_add(1, Ordering::SeqCst);
                let delay = c.latest_delay_ms.load(Ordering::SeqCst);
                if delay > 0 {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                if c.down.load(Ordering::SeqCst) {
                    anyhow::bail!("lwd down");
                }
                let tip = c.tip();
                Ok(Tip {
                    height: tip,
                    hash: c.hash_at(tip),
                })
            })
        }
        fn blocks(&self, start: u64, end: u64) -> BoxFuture<'static, Result<Vec<FetchedBlock>>> {
            let c = self.0.clone();
            Box::pin(async move {
                c.range_calls.lock().unwrap().push((start, end));
                let delay = c.blocks_delay_ms.load(Ordering::SeqCst);
                if delay > 0 {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                if c.down.load(Ordering::SeqCst) {
                    anyhow::bail!("lwd down");
                }
                let tip = c.tip();
                Ok((start..=end.min(tip))
                    .map(|h| FetchedBlock::from_frame(grpc_frame(&c.msg(h))))
                    .collect())
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::block_cache::test_support::{hash_at, FakeChain};
    use crate::store::test_support::{MemPermanent, MemStore};

    fn follower(
        store: Arc<MemStore>,
        chain: Arc<FakeChain>,
        local: Option<Arc<LocalCache>>,
    ) -> Arc<ChainFollower> {
        Arc::new(ChainFollower::new(
            store,
            Arc::new(FakeChainSource(chain)),
            local,
            Arc::new(PoolKeys::default()),
            "testnet".to_string(),
        ))
    }

    #[tokio::test]
    async fn leader_writes_final_blocks_permanently_and_promotes_on_advance() {
        let store = Arc::new(MemStore::default());
        let perm = Arc::new(MemPermanent::default());
        let chain = Arc::new(FakeChain::new(1000));
        let local = Arc::new(LocalCache::new(1 << 20, "testnet".to_string()));
        let f = Arc::new(
            ChainFollower::new(
                store.clone(),
                Arc::new(FakeChainSource(chain.clone())),
                Some(local.clone()),
                Arc::new(PoolKeys::default()),
                "testnet".to_string(),
            )
            .with_permanent(perm.clone(), 500),
        );
        let prefix = store.key_prefix(42);
        assert_eq!(f.tick().await, Outcome::Cold { tip: 1000 });
        // The idle tick backfills 900..=999: 900 is final (depth 100) -> permanent, 901.. cache.
        assert_eq!(f.tick().await, Outcome::Idle);
        assert_eq!(
            perm.get(&permanent_block_key("testnet", "", 900)),
            Some(Bytes::from(chain.msg(900)))
        );
        assert_eq!(store.get(&block_key(&prefix, "", 900)), None);
        assert_eq!(perm.get(&permanent_block_key("testnet", "", 901)), None);
        assert!(store.get(&block_key(&prefix, "", 901)).is_some());
        assert!(local
            .get(&permanent_block_key("testnet", "", 900))
            .is_some());
        // Advance by one: 901 becomes final and is moved.
        chain.set_tip(1001);
        assert_eq!(
            f.tick().await,
            Outcome::Advanced {
                from: 1001,
                to: 1001
            }
        );
        assert_eq!(
            perm.get(&permanent_block_key("testnet", "", 901)),
            Some(Bytes::from(chain.msg(901)))
        );
        assert_eq!(
            store.get(&block_key(&prefix, "", 901)),
            None,
            "moved, not copied"
        );
        assert_eq!(local.get(&block_key(&prefix, "", 901)), None);
        assert!(
            store.get(&block_key(&prefix, "", 902)).is_some(),
            "902 not final yet"
        );
        // Advance by several: 902..=905 move; the second idle backfill tick (800..=899, all
        // final) goes straight to the permanent tier.
        chain.set_tip(1005);
        assert!(matches!(f.tick().await, Outcome::Advanced { to: 1005, .. }));
        for h in 902..=905 {
            assert!(
                perm.get(&permanent_block_key("testnet", "", h)).is_some(),
                "{h}"
            );
            assert_eq!(store.get(&block_key(&prefix, "", h)), None, "{h}");
        }
        assert!(perm.get(&permanent_block_key("testnet", "", 906)).is_none());
        assert_eq!(f.tick().await, Outcome::Idle);
        assert!(perm.get(&permanent_block_key("testnet", "", 850)).is_some());
        assert_eq!(store.get(&block_key(&prefix, "", 850)), None);
        // Below the floor: cache tier (idle ticks reach 400..=499 eventually).
        for _ in 0..4 {
            assert_eq!(f.tick().await, Outcome::Idle);
        }
        assert!(perm.get(&permanent_block_key("testnet", "", 450)).is_none());
        assert!(store.get(&block_key(&prefix, "", 450)).is_some());
        // Index entries exist for everything, whichever tier.
        assert_eq!(index_of(&store, 900), Some(hash_at(900, 0)));
        assert_eq!(index_of(&store, 450), Some(hash_at(450, 0)));
    }

    fn index_of(store: &MemStore, h: u64) -> Option<Vec<u8>> {
        store
            .get(&index_key(&store.chain_prefix(), h))
            .map(|b| b.to_vec())
    }

    #[tokio::test]
    async fn cold_start_indexes_tip_then_backfills_the_window() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(1500));
        let f = follower(store.clone(), chain.clone(), None);
        assert_eq!(f.tick().await, Outcome::Cold { tip: 1500 });
        assert!(f.is_leader());
        assert_eq!(index_of(&store, 1500), Some(hash_at(1500, 0)));
        assert_eq!(f.tip().unwrap().height, 1500);
        assert_eq!(store.tip.get().unwrap().hash, hash_at(1500, 0));
        // The tip block is in the block cache.
        assert_eq!(
            store.get(&block_key(&store.key_prefix(42), "", 1500)),
            Some(Bytes::from(chain.msg(1500)))
        );
        // Idle ticks backfill 100 heights each until tip - INDEX_WINDOW.
        for _ in 0..12 {
            assert_eq!(f.tick().await, Outcome::Idle);
        }
        assert_eq!(index_of(&store, 1499), Some(hash_at(1499, 0)));
        assert_eq!(index_of(&store, 500), Some(hash_at(500, 0)));
        assert_eq!(index_of(&store, 499), None, "below the window");
        // Backfill fetched each missing height once, as whole batches.
        let calls = chain.range_calls.lock().unwrap().clone();
        assert!(calls.contains(&(1400, 1499)), "{calls:?}");
        assert!(calls.contains(&(500, 599)), "{calls:?}");
        assert_eq!(calls.len(), 11, "{calls:?}");
        // Backfill does not refetch what is present.
        assert_eq!(f.tick().await, Outcome::Idle);
        assert_eq!(chain.range_calls.lock().unwrap().len(), 11);
    }

    #[tokio::test]
    async fn advance_fetches_new_blocks_once_and_notifies() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(1000));
        let f = follower(store.clone(), chain.clone(), None);
        struct Seen(std::sync::Mutex<Vec<u64>>);
        impl BlockListener for Seen {
            fn on_new_block(&self, tip: &Tip) {
                self.0.lock().unwrap().push(tip.height);
            }
        }
        let seen = Arc::new(Seen(std::sync::Mutex::new(vec![])));
        f.add_listener(seen.clone());
        assert_eq!(f.tick().await, Outcome::Cold { tip: 1000 });
        chain.set_tip(1003);
        assert_eq!(
            f.tick().await,
            Outcome::Advanced {
                from: 1001,
                to: 1003
            }
        );
        assert_eq!(f.tick().await, Outcome::Idle);
        for h in 1001..=1003 {
            assert_eq!(index_of(&store, h), Some(hash_at(h, 0)));
            assert!(store
                .get(&block_key(&store.key_prefix(42), "", h))
                .is_some());
        }
        assert_eq!(*seen.0.lock().unwrap(), vec![1000, 1003]);
        let calls = chain.range_calls.lock().unwrap().clone();
        assert_eq!(&calls[..2], &[(1000, 1000), (1001, 1003)]);
    }

    #[tokio::test]
    async fn reorg_of_depth_three_rewrites_the_index_and_drops_cached_entries() {
        let store = Arc::new(MemStore::default());
        let local = Arc::new(LocalCache::new(1 << 20, "testnet".to_string()));
        let chain = Arc::new(FakeChain::new(2000));
        let f = follower(store.clone(), chain.clone(), Some(local.clone()));
        assert_eq!(f.tick().await, Outcome::Cold { tip: 2000 });
        chain.set_tip(2010);
        assert_eq!(
            f.tick().await,
            Outcome::Advanced {
                from: 2001,
                to: 2010
            }
        );
        let prefix = store.key_prefix(42);
        // Cached answers at the heights about to be replaced.
        store.put(
            &crate::cache::height_key(&prefix, "treestate", 2009),
            b"ts".to_vec(),
        );
        store.put(
            &crate::cache::height_key(&prefix, "nullifiers", 2008),
            b"nf".to_vec(),
        );
        local.insert(block_key(&prefix, "", 2010), Bytes::from_static(b"x"));
        assert!(local.get(&block_key(&prefix, "", 2010)).is_some());
        // A non-final subtree root completing at 2009 (entry + height pointer) and one at 2005.
        store.put(
            &crate::subtree_cache::subtree_key(&prefix, 1, 7),
            b"root".to_vec(),
        );
        store.put(
            &crate::subtree_cache::subtree_at_key(&prefix, 1, 2009),
            7u32.to_be_bytes().to_vec(),
        );
        store.put(
            &crate::subtree_cache::subtree_key(&prefix, 0, 3),
            b"root".to_vec(),
        );
        store.put(
            &crate::subtree_cache::subtree_at_key(&prefix, 0, 2005),
            3u32.to_be_bytes().to_vec(),
        );

        // Fork: heights 2008..=2010 replaced, same tip height.
        chain.reorg_from(2008, 1);
        assert_eq!(
            f.tick().await,
            Outcome::Reorg {
                fork: 2007,
                depth: 3,
                tip: 2010
            }
        );
        for h in 2008..=2010 {
            assert_eq!(index_of(&store, h), Some(hash_at(h, 1)), "{h}");
            assert_eq!(
                store.get(&block_key(&prefix, "", h)),
                Some(Bytes::from(chain.msg(h))),
                "{h}"
            );
        }
        assert_eq!(index_of(&store, 2007), Some(hash_at(2007, 0)));
        assert!(store
            .get(&crate::cache::height_key(&prefix, "treestate", 2009))
            .is_none());
        assert!(store
            .get(&crate::cache::height_key(&prefix, "nullifiers", 2008))
            .is_none());
        assert!(store
            .get(&crate::subtree_cache::subtree_key(&prefix, 1, 7))
            .is_none());
        assert!(store
            .get(&crate::subtree_cache::subtree_at_key(&prefix, 1, 2009))
            .is_none());
        assert!(
            store
                .get(&crate::subtree_cache::subtree_key(&prefix, 0, 3))
                .is_some(),
            "a root completing below the fork stays"
        );
        assert_eq!(
            local.get(&block_key(&prefix, "", 2010)),
            Some(Bytes::from(chain.msg(2010))),
            "local copy replaced by the canonical block"
        );
        assert_eq!(store.tip.get().unwrap().hash, hash_at(2010, 1));
        assert_eq!(f.tick().await, Outcome::Idle);
    }

    #[tokio::test]
    async fn reorg_to_a_lower_tip_and_then_forward() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(3000));
        let f = follower(store.clone(), chain.clone(), None);
        f.tick().await;
        chain.set_tip(3005);
        f.tick().await;
        // The new chain is one block shorter: 3004..=3005 replaced by 3004'.
        chain.reorg_from(3004, 2);
        chain.set_tip(3004);
        assert_eq!(
            f.tick().await,
            Outcome::Reorg {
                fork: 3003,
                depth: 2,
                tip: 3004
            }
        );
        assert_eq!(index_of(&store, 3004), Some(hash_at(3004, 2)));
        assert_eq!(index_of(&store, 3005), None);
        chain.set_tip(3006);
        assert_eq!(
            f.tick().await,
            Outcome::Advanced {
                from: 3005,
                to: 3006
            }
        );
        assert_eq!(index_of(&store, 3005), Some(hash_at(3005, 2)));
    }

    #[tokio::test]
    async fn upstream_failure_keeps_the_index_and_marks_the_error() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(100));
        let f = follower(store.clone(), chain.clone(), None);
        f.tick().await;
        chain.down.store(true, Ordering::SeqCst);
        assert!(matches!(f.tick().await, Outcome::Error(_)));
        assert_eq!(index_of(&store, 100), Some(hash_at(100, 0)));
        chain.down.store(false, Ordering::SeqCst);
        assert_eq!(f.tick().await, Outcome::Idle);
    }

    #[tokio::test(start_paused = true)]
    async fn second_follower_takes_over_after_the_lock_ttl() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(500));
        let a = follower(store.clone(), chain.clone(), None);
        let b = follower(store.clone(), chain.clone(), None);
        assert_eq!(a.tick().await, Outcome::Cold { tip: 500 });
        assert_eq!(b.tick().await, Outcome::Follower);
        assert!(!b.is_leader());
        // b follows a's tip from the store.
        assert_eq!(b.tip().unwrap().height, 500);
        // a keeps renewing: b never gets the lock.
        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(4)).await;
            assert_eq!(a.tick().await, Outcome::Idle);
            assert_eq!(b.tick().await, Outcome::Follower);
        }
        // a dies (stops ticking); after the TTL b acquires the lock and continues the index.
        tokio::time::advance(Duration::from_millis(LOCK_TTL_MS + 100)).await;
        chain.set_tip(502);
        assert_eq!(b.tick().await, Outcome::Advanced { from: 501, to: 502 });
        assert!(b.is_leader());
        assert_eq!(index_of(&store, 502), Some(hash_at(502, 0)));
        // a comes back: it is a follower now and reads b's tip.
        assert_eq!(a.tick().await, Outcome::Follower);
        assert!(!a.is_leader());
        assert_eq!(a.tip().unwrap().height, 502);
    }

    #[tokio::test(start_paused = true)]
    async fn redis_outage_demotes_the_leader_and_recovers() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(700));
        let f = follower(store.clone(), chain.clone(), None);
        f.tick().await;
        assert!(f.is_leader());
        store.down.store(true, Ordering::SeqCst);
        assert_eq!(f.tick().await, Outcome::Follower);
        assert!(!f.is_leader());
        store.down.store(false, Ordering::SeqCst);
        chain.set_tip(701);
        // Its own old lock still stands: a follower until it lapses.
        assert_eq!(f.tick().await, Outcome::Follower);
        tokio::time::advance(Duration::from_millis(LOCK_TTL_MS + 100)).await;
        // Back as leader, continuing from the stored tip.
        assert_eq!(f.tick().await, Outcome::Advanced { from: 701, to: 701 });
    }

    /// A `tip_at` long ago, another one on every call (each stored tip a test writes comes with
    /// its own, as a leader writes them).
    fn old_tip_at() -> Bytes {
        static AT: AtomicU64 = AtomicU64::new(1);
        encode_unix_ms(AT.fetch_add(1, Ordering::SeqCst))
    }

    /// Two processes on one store, each with its own lightwalletd view.
    fn pair(
        store: &Arc<MemStore>,
        leader_chain: &Arc<FakeChain>,
        follower_chain: &Arc<FakeChain>,
    ) -> (Arc<ChainFollower>, Arc<ChainFollower>) {
        let make = |chain: &Arc<FakeChain>| {
            Arc::new(
                ChainFollower::new(
                    store.clone(),
                    Arc::new(FakeChainSource(chain.clone())),
                    None,
                    Arc::new(PoolKeys::default()),
                    "testnet".to_string(),
                )
                .with_stale_after(Duration::from_millis(1)),
            )
        };
        (make(leader_chain), make(follower_chain))
    }

    /// Let the stored tip age past the 1 ms bound (wall clock, not the paused tokio clock).
    fn age_the_tip() {
        std::thread::sleep(Duration::from_millis(5));
    }

    #[tokio::test(start_paused = true)]
    async fn a_follower_takes_over_a_leader_whose_tip_stopped_moving() {
        let store = Arc::new(MemStore::default());
        // The leader's lightwalletd is stuck at 1000; the follower's moves on.
        let stuck = Arc::new(FakeChain::new(1000));
        let live = Arc::new(FakeChain::new(1000));
        let (leader, follower) = pair(&store, &stuck, &live);
        assert_eq!(leader.tick().await, Outcome::Cold { tip: 1000 });
        live.set_tip(1006);
        age_the_tip();

        // First probe: its own tip is served at once, no takeover yet.
        assert_eq!(
            follower.tick().await,
            Outcome::StaleLeader {
                from: 1000,
                to: 1006,
                took_over: false
            }
        );
        assert_eq!(follower.tip().unwrap().height, 1006);
        // Between probes it keeps serving that tip, never the older stored one.
        for _ in 1..STALE_PROBE_EVERY {
            assert_eq!(follower.tick().await, Outcome::Follower);
            assert_eq!(follower.tip().unwrap().height, 1006);
            assert_eq!(leader.tick().await, Outcome::Idle);
        }
        // Second probe, still ahead: it takes the lock over and continues the index in the
        // same tick.
        assert_eq!(
            follower.tick().await,
            Outcome::Advanced {
                from: 1001,
                to: 1006
            }
        );
        assert!(follower.is_leader());
        assert_eq!(index_of(&store, 1006), Some(hash_at(1006, 0)));
        // A tick of the old leader that was in flight during the takeover cannot move the
        // stored tip back: its write is refused and it stops leading.
        let stale_tip = Tip {
            height: 1000,
            hash: hash_at(1000, 0),
        };
        assert!(!leader.write_tip(&stale_tip).await.unwrap());
        assert!(!leader.is_leader());
        assert_eq!(
            store
                .get(&tip_key(&store.chain_prefix()))
                .and_then(|b| decode_tip(&b))
                .map(|t| t.height),
            Some(1006)
        );
        // The old leader follows and does not take the lock back: its own lightwalletd is
        // behind the stored tip.
        assert_eq!(leader.tick().await, Outcome::Follower);
        assert!(!leader.is_leader());
        assert_eq!(leader.tip().unwrap().height, 1006);
        age_the_tip();
        for _ in 0..(2 * STALE_PROBE_EVERY) {
            assert_eq!(leader.tick().await, Outcome::Follower);
        }
        assert!(follower.is_leader());
    }

    #[tokio::test(start_paused = true)]
    async fn an_unmoved_tip_is_kept_when_no_lightwalletd_is_ahead() {
        let store = Arc::new(MemStore::default());
        let a = Arc::new(FakeChain::new(2000));
        let b = Arc::new(FakeChain::new(2000));
        let (leader, follower) = pair(&store, &a, &b);
        assert_eq!(leader.tick().await, Outcome::Cold { tip: 2000 });
        age_the_tip();
        // No new block anywhere (a slow block): nothing to take over, the stored tip is served.
        for _ in 0..(2 * STALE_PROBE_EVERY + 1) {
            assert_eq!(follower.tick().await, Outcome::Follower);
            assert_eq!(follower.tip().unwrap().height, 2000);
        }
        assert!(leader.tick().await == Outcome::Idle && leader.is_leader());
        // The leader moves the tip again before a second probe: no takeover either.
        b.set_tip(2003);
        assert!(matches!(
            follower.tick().await,
            Outcome::Follower
                | Outcome::StaleLeader {
                    took_over: false,
                    ..
                }
        ));
        a.set_tip(2003);
        assert_eq!(
            leader.tick().await,
            Outcome::Advanced {
                from: 2001,
                to: 2003
            }
        );
        for _ in 0..(2 * STALE_PROBE_EVERY) {
            assert_eq!(follower.tick().await, Outcome::Follower);
        }
        assert!(leader.is_leader());
        assert_eq!(follower.tip().unwrap().height, 2003);
    }

    #[tokio::test(start_paused = true)]
    async fn a_takeover_needs_the_same_unmoved_tip_on_both_probes() {
        let store = Arc::new(MemStore::default());
        let slow = Arc::new(FakeChain::new(3000));
        let fast = Arc::new(FakeChain::new(3000));
        let (leader, follower) = pair(&store, &slow, &fast);
        leader.tick().await;
        fast.set_tip(3004);
        age_the_tip();
        assert!(matches!(
            follower.tick().await,
            Outcome::StaleLeader {
                took_over: false,
                ..
            }
        ));
        // The leader moves a little (its lightwalletd is slow, not stuck).
        slow.set_tip(3001);
        assert_eq!(
            leader.tick().await,
            Outcome::Advanced {
                from: 3001,
                to: 3001
            }
        );
        age_the_tip();
        for _ in 1..STALE_PROBE_EVERY {
            follower.tick().await;
        }
        // A new stored tip: a first sighting again, not a takeover.
        assert_eq!(
            follower.tick().await,
            Outcome::StaleLeader {
                from: 3001,
                to: 3004,
                took_over: false
            }
        );
        assert!(leader.is_leader() && !follower.is_leader());
    }

    #[tokio::test(start_paused = true)]
    async fn a_lagging_lightwalletd_is_not_a_reorg() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(4000));
        let f = follower(store.clone(), chain.clone(), None);
        assert_eq!(f.tick().await, Outcome::Cold { tip: 4000 });
        // Fill the index window below the tip.
        assert_eq!(f.tick().await, Outcome::Idle);
        // A lightwalletd behind on the same chain answers.
        chain.set_tip(3995);
        assert_eq!(
            f.tick().await,
            Outcome::Behind {
                backend: 3995,
                tip: 4000
            }
        );
        assert_eq!(f.tip().unwrap().height, 4000);
        assert_eq!(index_of(&store, 4000), Some(hash_at(4000, 0)));
        // A lower tip off the indexed chain is still a reorg.
        chain.reorg_from(3990, 1);
        assert!(matches!(f.tick().await, Outcome::Reorg { .. }));
    }

    #[tokio::test(start_paused = true)]
    async fn the_leader_stores_when_it_moved_the_tip() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(5000));
        let f = follower(store.clone(), chain.clone(), None);
        let before = unix_ms_now();
        f.tick().await;
        let at = store
            .get(&tip_at_key(&store.chain_prefix()))
            .and_then(|b| decode_unix_ms(&b))
            .unwrap();
        assert!(at >= before && at <= unix_ms_now());
        // Unchanged while idle.
        f.tick().await;
        assert_eq!(
            store
                .get(&tip_at_key(&store.chain_prefix()))
                .and_then(|b| decode_unix_ms(&b)),
            Some(at)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn final_blocks_stay_in_the_cache_tier_while_the_permanent_tier_is_a_replica() {
        let store = Arc::new(MemStore::default());
        let perm = Arc::new(MemPermanent::default());
        perm.replica.store(true, Ordering::SeqCst);
        let chain = Arc::new(FakeChain::new(1000));
        let f = Arc::new(
            ChainFollower::new(
                store.clone(),
                Arc::new(FakeChainSource(chain.clone())),
                None,
                Arc::new(PoolKeys::default()),
                "testnet".to_string(),
            )
            .with_permanent(perm.clone(), 500),
        );
        let prefix = store.key_prefix(42);
        assert_eq!(f.tick().await, Outcome::Cold { tip: 1000 });
        assert_eq!(f.tick().await, Outcome::Idle);
        chain.set_tip(1001);
        assert!(matches!(f.tick().await, Outcome::Advanced { .. }));
        assert_eq!(
            perm.writes.load(Ordering::SeqCst),
            0,
            "no write to a replica"
        );
        // The final block 900 is in the cache tier instead, and still there after the advance.
        assert!(store.get(&block_key(&prefix, "", 900)).is_some());
        assert!(store.get(&block_key(&prefix, "", 901)).is_some());
        // Promoted to a primary: final blocks go to the permanent tier again.
        perm.replica.store(false, Ordering::SeqCst);
        chain.set_tip(1002);
        assert!(matches!(f.tick().await, Outcome::Advanced { .. }));
        assert!(perm.get(&permanent_block_key("testnet", "", 902)).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn a_leader_tick_longer_than_the_lock_ttl_keeps_the_lock_and_writes() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(6000));
        let a = follower(store.clone(), chain.clone(), None);
        let b = follower(store.clone(), chain.clone(), None);
        assert_eq!(a.tick().await, Outcome::Cold { tip: 6000 });
        // A slow catch-up: the block fetch takes three lock TTLs; the other process ticks
        // meanwhile.
        chain.set_tip(6010);
        chain
            .blocks_delay_ms
            .store(3 * LOCK_TTL_MS, Ordering::SeqCst);
        let other = async {
            let mut outcomes = Vec::new();
            for _ in 0..12 {
                tokio::time::sleep(POLL_INTERVAL).await;
                outcomes.push(b.tick().await);
            }
            outcomes
        };
        let (outcome, others) = tokio::join!(a.tick(), other);
        assert_eq!(
            outcome,
            Outcome::Advanced {
                from: 6001,
                to: 6010
            }
        );
        assert!(a.is_leader() && !b.is_leader());
        assert!(others.iter().all(|o| *o == Outcome::Follower), "{others:?}");
        assert_eq!(
            store
                .get(&tip_key(&store.chain_prefix()))
                .and_then(|b| decode_tip(&b))
                .map(|t| t.height),
            Some(6010)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_leader_tick_hands_the_lock_over() {
        let store = Arc::new(MemStore::default());
        let broken = Arc::new(FakeChain::new(7000));
        let fine = Arc::new(FakeChain::new(7000));
        let (a, b) = pair(&store, &broken, &fine);
        assert_eq!(a.tick().await, Outcome::Cold { tip: 7000 });
        broken.down.store(true, Ordering::SeqCst);
        assert!(matches!(a.tick().await, Outcome::Error(_)));
        assert!(!a.is_leader());
        // The other process leads from its next tick, not after the TTL.
        fine.set_tip(7002);
        assert_eq!(
            b.tick().await,
            Outcome::Advanced {
                from: 7001,
                to: 7002
            }
        );
        assert!(b.is_leader());
    }

    fn stored_tip(store: &MemStore) -> Option<u64> {
        store
            .get(&tip_key(&store.chain_prefix()))
            .and_then(|b| decode_tip(&b))
            .map(|t| t.height)
    }

    #[tokio::test(start_paused = true)]
    async fn a_displaced_leader_with_a_fetch_in_flight_writes_no_index() {
        let store = Arc::new(MemStore::default());
        // The leader's lightwalletd is stuck at 1000 and then answers with another fork above
        // it, slowly; the follower's is ahead on the canonical chain.
        let stuck = Arc::new(FakeChain::new(1000));
        let live = Arc::new(FakeChain::new(1000));
        let (leader, follower) = pair(&store, &stuck, &live);
        assert_eq!(leader.tick().await, Outcome::Cold { tip: 1000 });
        live.set_tip(1006);
        age_the_tip();
        assert!(matches!(
            follower.tick().await,
            Outcome::StaleLeader {
                took_over: false,
                ..
            }
        ));
        // The leader's next tick fetches fork-1 blocks 1001..=1003 for 20 s; meanwhile the
        // follower's second probe takes the lock over and indexes the canonical chain.
        stuck.reorg_from(1001, 1);
        stuck.set_tip(1003);
        stuck.blocks_delay_ms.store(20_000, Ordering::SeqCst);
        let other = async {
            let mut outcomes = Vec::new();
            for _ in 1..=STALE_PROBE_EVERY {
                tokio::time::sleep(POLL_INTERVAL).await;
                outcomes.push(follower.tick().await);
            }
            outcomes
        };
        let (displaced, outcomes) = tokio::join!(leader.tick(), other);
        assert_eq!(
            outcomes.last(),
            Some(&Outcome::Advanced {
                from: 1001,
                to: 1006
            }),
            "{outcomes:?}"
        );
        assert_eq!(displaced, Outcome::Follower);
        assert!(!leader.is_leader() && follower.is_leader());
        for h in 1001..=1006 {
            assert_eq!(index_of(&store, h), Some(hash_at(h, 0)), "height {h}");
        }
        assert_eq!(stored_tip(&store), Some(1006));
    }

    #[tokio::test(start_paused = true)]
    async fn a_released_lock_does_not_let_a_paused_leader_write() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(800));
        let f = follower(store.clone(), chain.clone(), None);
        assert_eq!(f.tick().await, Outcome::Cold { tip: 800 });
        // Another process took the lock over, wrote a newer tip and released the lock again.
        store.locks.lock().unwrap().clear();
        let newer = Tip {
            height: 805,
            hash: hash_at(805, 0),
        };
        store.put(&tip_key(&store.chain_prefix()), encode_tip(&newer));
        let older = Tip {
            height: 801,
            hash: hash_at(801, 0),
        };
        assert!(
            !f.write_tip(&older).await.unwrap(),
            "an absent lock refuses the write"
        );
        assert!(!f.is_leader());
        assert_eq!(stored_tip(&store), Some(805));
        let block = FetchedBlock::from_frame(grpc_frame(&chain.msg(801)));
        assert!(!f.store_blocks(&[block], 801).await.unwrap());
        assert_eq!(index_of(&store, 801), None);
    }

    #[tokio::test(start_paused = true)]
    async fn two_followers_do_not_take_the_lock_from_each_other() {
        let store = Arc::new(MemStore::default());
        let stuck = Arc::new(FakeChain::new(1000));
        let live_b = Arc::new(FakeChain::new(1000));
        let live_c = Arc::new(FakeChain::new(1000));
        let (leader, b) = pair(&store, &stuck, &live_b);
        let (_, c) = pair(&store, &stuck, &live_c);
        assert_eq!(leader.tick().await, Outcome::Cold { tip: 1000 });
        live_b.set_tip(1006);
        live_c.set_tip(1006);
        age_the_tip();
        // Both see the stale tip on their first probe.
        for f in [&b, &c] {
            assert!(matches!(
                f.tick().await,
                Outcome::StaleLeader {
                    took_over: false,
                    ..
                }
            ));
        }
        for _ in 1..STALE_PROBE_EVERY {
            assert_eq!(b.tick().await, Outcome::Follower);
            assert_eq!(c.tick().await, Outcome::Follower);
            assert_eq!(leader.tick().await, Outcome::Idle);
        }
        // b takes over and is still fetching its blocks when c probes the same stale tip.
        live_b.blocks_delay_ms.store(5_000, Ordering::SeqCst);
        let (outcome_b, outcome_c) = tokio::join!(b.tick(), c.tick());
        assert_eq!(
            outcome_b,
            Outcome::Advanced {
                from: 1001,
                to: 1006
            }
        );
        assert_eq!(
            outcome_c,
            Outcome::StaleLeader {
                from: 1000,
                to: 1006,
                took_over: false
            }
        );
        assert!(b.is_leader() && !c.is_leader());
        assert_eq!(stored_tip(&store), Some(1006));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_probe_does_not_send_the_served_tip_back() {
        let store = Arc::new(MemStore::default());
        let stuck = Arc::new(FakeChain::new(1000));
        let live = Arc::new(FakeChain::new(1000));
        let (leader, follower) = pair(&store, &stuck, &live);
        assert_eq!(leader.tick().await, Outcome::Cold { tip: 1000 });
        live.set_tip(1006);
        age_the_tip();
        assert!(matches!(
            follower.tick().await,
            Outcome::StaleLeader {
                took_over: false,
                ..
            }
        ));
        assert_eq!(follower.tip().unwrap().height, 1006);
        // Its own lightwalletd fails from now on: every tick, the probes included, keeps 1006.
        live.down.store(true, Ordering::SeqCst);
        for _ in 0..(2 * STALE_PROBE_EVERY) {
            assert_eq!(follower.tick().await, Outcome::Follower);
            assert_eq!(follower.tip().unwrap().height, 1006);
            assert_eq!(leader.tick().await, Outcome::Idle);
        }
        // Bounded: without a confirmation for HELD_TIP_MAX_AGE it serves the stored tip again.
        let mut waited = Duration::ZERO;
        while waited <= HELD_TIP_MAX_AGE {
            tokio::time::advance(Duration::from_secs(3)).await;
            waited += Duration::from_secs(3);
            assert_eq!(leader.tick().await, Outcome::Idle);
            follower.tick().await;
        }
        assert_eq!(follower.tip().unwrap().height, 1000);
        assert!(leader.is_leader() && !follower.is_leader());
    }

    #[tokio::test(start_paused = true)]
    async fn a_lightwalletd_stuck_behind_gives_the_lock_up() {
        let store = Arc::new(MemStore::default());
        let stuck = Arc::new(FakeChain::new(4000));
        let fine = Arc::new(FakeChain::new(4000));
        let f = follower(store.clone(), stuck.clone(), None);
        let other = follower(store.clone(), fine.clone(), None);
        assert_eq!(f.tick().await, Outcome::Cold { tip: 4000 });
        assert_eq!(f.tick().await, Outcome::Idle);
        assert_eq!(other.tick().await, Outcome::Follower);
        stuck.set_tip(3995);
        for _ in 0..MAX_BEHIND_TICKS {
            assert!(matches!(f.tick().await, Outcome::Behind { .. }));
            assert!(f.is_leader());
        }
        assert_eq!(f.tip().unwrap().height, 4000);
        // One more: it gives the lock up and stays away from it for the cooldown.
        assert!(matches!(f.tick().await, Outcome::Behind { .. }));
        assert!(!f.is_leader());
        for _ in 0..BEHIND_COOLDOWN_TICKS {
            assert_eq!(f.tick().await, Outcome::Follower);
        }
        // Nobody confirms the tip any more: it goes stale on both.
        tokio::time::advance(crate::store::TIP_STALE_AFTER + Duration::from_secs(1)).await;
        assert_eq!(f.tip(), None);
        assert_eq!(other.tip(), None);
        // The other process leads from its next tick and moves on.
        fine.set_tip(4001);
        assert_eq!(
            other.tick().await,
            Outcome::Advanced {
                from: 4001,
                to: 4001
            }
        );
        assert_eq!(f.tick().await, Outcome::Follower);
        assert_eq!(f.tip().unwrap().height, 4001);
    }

    #[tokio::test(start_paused = true)]
    async fn followers_keep_the_tip_fresh_only_while_the_leader_confirms_it() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(9000));
        let leader = follower(store.clone(), chain.clone(), None);
        let f = follower(store.clone(), chain.clone(), None);
        assert_eq!(leader.tick().await, Outcome::Cold { tip: 9000 });
        // Normal operation: a chain without a new block for a while, every tick confirmed.
        for _ in 0..12 {
            tokio::time::advance(Duration::from_secs(5)).await;
            assert_eq!(leader.tick().await, Outcome::Idle);
            assert_eq!(f.tick().await, Outcome::Follower);
            assert_eq!(f.tip().unwrap().height, 9000);
        }
        // The lightwalletd is stuck at the tip height: once the tip moved MAX_CONFIRM_AGE ago
        // the leader stops confirming, and the followers' tip ages out although they still
        // read it every tick (the wall clock is not paused: the move is put back in time).
        leader.moved_at_ms.store(
            unix_ms_now() - MAX_CONFIRM_AGE.as_millis() as u64 - 1_000,
            Ordering::Relaxed,
        );
        assert_eq!(leader.tick().await, Outcome::Idle);
        f.tick().await;
        for _ in 0..7 {
            tokio::time::advance(Duration::from_secs(5)).await;
            assert_eq!(leader.tick().await, Outcome::Idle);
            assert_eq!(f.tick().await, Outcome::Follower);
        }
        assert_eq!(f.tip(), None);
        assert_eq!(leader.tip(), None);
        // A new block: confirmed and fresh again.
        chain.set_tip(9001);
        assert!(matches!(leader.tick().await, Outcome::Advanced { .. }));
        f.tick().await;
        assert_eq!(f.tip().unwrap().height, 9001);
    }

    #[tokio::test(start_paused = true)]
    async fn leader_work_longer_than_the_lease_keeps_it_without_another_process() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(6500));
        let f = follower(store.clone(), chain.clone(), None);
        // A cold start whose block fetch takes three lock TTLs.
        chain
            .blocks_delay_ms
            .store(3 * LOCK_TTL_MS, Ordering::SeqCst);
        assert_eq!(f.tick().await, Outcome::Cold { tip: 6500 });
        assert!(f.is_leader());
        assert_eq!(stored_tip(&store), Some(6500));
    }

    #[tokio::test(start_paused = true)]
    async fn leader_work_is_cancelled_when_its_lease_is_taken() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(6600));
        let f = follower(store.clone(), chain.clone(), None);
        assert_eq!(f.tick().await, Outcome::Cold { tip: 6600 });
        chain.set_tip(6610);
        chain
            .blocks_delay_ms
            .store(10 * LOCK_TTL_MS, Ordering::SeqCst);
        let lock = lock_key(&store.chain_prefix());
        let thief = async {
            tokio::time::sleep(Duration::from_millis(LOCK_TTL_MS / 2)).await;
            store.locks.lock().unwrap().insert(
                lock.clone(),
                (
                    "other".to_string(),
                    tokio::time::Instant::now() + Duration::from_secs(3600),
                ),
            );
        };
        let start = tokio::time::Instant::now();
        let (outcome, _) = tokio::join!(f.tick(), thief);
        assert_eq!(outcome, Outcome::Follower);
        assert!(!f.is_leader());
        assert!(
            start.elapsed() < Duration::from_millis(2 * LOCK_TTL_MS),
            "cancelled at the next renewal, not after the fetch"
        );
        assert_eq!(stored_tip(&store), Some(6600));
        assert_eq!(index_of(&store, 6601), None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_displacement_between_two_batches_stops_the_rest() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(1000));
        let f = follower(store.clone(), chain.clone(), None);
        assert_eq!(f.tick().await, Outcome::Cold { tip: 1000 });
        chain.set_tip(1100);
        // The first block batch of the next tick is accepted, then another process takes the
        // lock before the second batch.
        *store.steal_lock_after.lock().unwrap() = Some((1, "other".to_string()));
        assert_eq!(f.tick().await, Outcome::Follower);
        assert!(!f.is_leader());
        let prefix = store.key_prefix(store.epoch);
        let last_written = 1000 + BLOCK_WRITE_BATCH as u64;
        for h in 1001..=last_written {
            assert_eq!(index_of(&store, h), Some(hash_at(h, 0)), "height {h}");
            assert!(store.get(&block_key(&prefix, "", h)).is_some(), "block {h}");
        }
        for h in last_written + 1..=1100 {
            assert_eq!(index_of(&store, h), None, "height {h}");
            assert!(store.get(&block_key(&prefix, "", h)).is_none(), "block {h}");
        }
        assert_eq!(stored_tip(&store), Some(1000));
    }

    #[test]
    fn write_batches_end_at_the_item_or_the_byte_bound() {
        assert!(write_batches(&[], 4, 100).is_empty());
        assert_eq!(
            write_batches(&[1, 1, 1, 1, 1], 2, 100),
            vec![0..2, 2..4, 4..5]
        );
        // 40 + 40 fit, the third would pass 100; an item above the bound goes alone.
        assert_eq!(
            write_batches(&[40, 40, 40, 250, 10, 10], 32, 100),
            vec![0..2, 2..3, 3..4, 4..6]
        );
        assert_eq!(write_batches(&[60, 40, 1], 32, 100), vec![0..2, 2..3]);
        assert_eq!(write_batches(&[0, 0, 0], 32, 0), vec![0..3]);
    }

    /// A block at `height` whose message is `size` bytes (the follower stores it as it is).
    fn sized_block(height: u64, size: usize) -> FetchedBlock {
        FetchedBlock {
            height: Some(height),
            hash: hash_at(height, 0),
            prev_hash: Vec::new(),
            frame: Bytes::from(vec![0u8; 5 + size]),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn large_blocks_are_written_in_scripts_bounded_by_bytes() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(1000));
        let f = follower(store.clone(), chain.clone(), None);
        assert_eq!(f.tick().await, Outcome::Cold { tip: 1000 });
        let third = BLOCK_WRITE_BATCH_BYTES * 2 / 5;
        let sizes = [third, third, third, 2 * BLOCK_WRITE_BATCH_BYTES, 10, 10];
        let blocks: Vec<FetchedBlock> = sizes
            .iter()
            .enumerate()
            .map(|(i, size)| sized_block(1001 + i as u64, *size))
            .collect();
        store.fenced_writes.lock().unwrap().clear();
        assert!(f.store_blocks(&blocks, 1006).await.unwrap());
        // Two blocks fit, the third would pass the bound, the large one goes alone, then the
        // rest: the index entry and the block of a height always in the same script.
        let chain_prefix = store.chain_prefix();
        let prefix = store.key_prefix(store.epoch);
        let script = |heights: std::ops::RangeInclusive<u64>| -> Vec<String> {
            heights
                .flat_map(|h| [index_key(&chain_prefix, h), block_key(&prefix, "", h)])
                .collect()
        };
        assert_eq!(
            *store.fenced_writes.lock().unwrap(),
            vec![
                script(1001..=1002),
                script(1003..=1003),
                script(1004..=1004),
                script(1005..=1006)
            ]
        );
        for (i, size) in sizes.iter().enumerate() {
            let h = 1001 + i as u64;
            assert_eq!(store.get(&block_key(&prefix, "", h)).unwrap().len(), *size);
        }

        // Displaced between two such scripts: the rest is not written.
        let blocks: Vec<FetchedBlock> = sizes
            .iter()
            .enumerate()
            .map(|(i, size)| sized_block(2001 + i as u64, *size))
            .collect();
        *store.steal_lock_after.lock().unwrap() = Some((1, "other".to_string()));
        assert!(!f.store_blocks(&blocks, 2006).await.unwrap());
        assert!(!f.is_leader());
        for h in 2001..=2002 {
            assert!(index_of(&store, h).is_some(), "height {h}");
            assert!(store.get(&block_key(&prefix, "", h)).is_some(), "block {h}");
        }
        for h in 2003..=2006 {
            assert_eq!(index_of(&store, h), None, "height {h}");
            assert!(store.get(&block_key(&prefix, "", h)).is_none(), "block {h}");
        }
    }

    /// A leader simulated by its keys only: it holds the lock and writes the stored tip, so
    /// the follower's tip cell is written by the follower alone.
    struct KeysOnlyLeader {
        store: Arc<MemStore>,
        /// The last `tip_at` written: every tip it moves comes with another one, as with a
        /// leader of this version.
        at: AtomicU64,
        /// The last `tip_seen` written.
        seen: AtomicU64,
    }

    impl KeysOnlyLeader {
        fn new(store: &Arc<MemStore>) -> Self {
            store.locks.lock().unwrap().insert(
                lock_key(&store.chain_prefix()),
                (
                    "another-process".to_string(),
                    tokio::time::Instant::now() + Duration::from_secs(86_400),
                ),
            );
            Self {
                store: store.clone(),
                at: AtomicU64::new(0),
                seen: AtomicU64::new(0),
            }
        }

        /// Move the stored tip to `height`, as every version that writes `tip_at` does.
        fn move_tip(&self, height: u64) {
            self.move_tip_only(height);
            let at = unix_ms_now().max(self.at.load(Ordering::SeqCst) + 1);
            self.at.store(at, Ordering::SeqCst);
            self.store
                .put(&tip_at_key(&self.store.chain_prefix()), encode_unix_ms(at));
        }

        /// Move the stored tip to `height` without `tip_at`, as a leader that writes neither
        /// `tip_at` nor `tip_seen` does.
        fn move_tip_only(&self, height: u64) {
            let tip = Tip {
                height,
                hash: hash_at(height, 0),
            };
            self.store
                .put(&tip_key(&self.store.chain_prefix()), encode_tip(&tip));
        }

        /// Confirm the stored tip (`tip_seen`), as this version does (a time not below
        /// `tip_at`, above its last one); `n` makes the value new.
        fn confirm(&self, n: u64) {
            let seen = (unix_ms_now() + n)
                .max(self.at.load(Ordering::SeqCst))
                .max(self.seen.load(Ordering::SeqCst) + 1);
            self.seen.store(seen, Ordering::SeqCst);
            self.store.put(
                &tip_seen_key(&self.store.chain_prefix()),
                encode_unix_ms(seen),
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_leader_that_does_not_confirm_is_followed_as_before() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(100));
        let f = follower(store.clone(), chain, None);
        let leader = KeysOnlyLeader::new(&store);
        // A leader of this version: it moves the tip and confirms it.
        leader.move_tip(100);
        leader.confirm(1);
        assert_eq!(f.tick().await, Outcome::Follower);
        assert_eq!(f.tip().unwrap().height, 100);
        // Then one that does not write the confirmation leads: the key stays as it was while
        // the tip moves. The follower follows it ...
        for height in [101, 102] {
            leader.move_tip(height);
            tokio::time::advance(Duration::from_secs(5)).await;
            assert_eq!(f.tick().await, Outcome::Follower);
            assert_eq!(f.tip().unwrap().height, height);
        }
        // ... and keeps the tip fresh while that leader idles, as with no key at all.
        let mut idle = Duration::ZERO;
        while idle <= crate::store::TIP_STALE_AFTER * 2 {
            tokio::time::advance(Duration::from_secs(5)).await;
            idle += Duration::from_secs(5);
            assert_eq!(f.tick().await, Outcome::Follower);
            assert_eq!(f.tip().unwrap().height, 102);
        }

        // A leader that confirms again: the strict rule applies again.
        leader.move_tip(103);
        leader.confirm(2);
        assert_eq!(f.tick().await, Outcome::Follower);
        assert_eq!(f.tip().unwrap().height, 103);
        // It stops confirming (and moving): the tip goes stale although it is read every tick.
        let mut idle = Duration::ZERO;
        while idle <= crate::store::TIP_STALE_AFTER {
            assert_eq!(f.tip().unwrap().height, 103);
            tokio::time::advance(Duration::from_secs(5)).await;
            idle += Duration::from_secs(5);
            assert_eq!(f.tick().await, Outcome::Follower);
        }
        assert_eq!(f.tip(), None);
        // The next confirmation makes it fresh again.
        leader.confirm(3);
        assert_eq!(f.tick().await, Outcome::Follower);
        assert_eq!(f.tip().unwrap().height, 103);
    }

    #[tokio::test(start_paused = true)]
    async fn a_store_error_in_a_fenced_write_stops_the_tick() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(2000));
        let f = follower(store.clone(), chain.clone(), None);
        let block = FetchedBlock::from_frame(grpc_frame(&chain.msg(2000)));
        assert_eq!(f.tick().await, Outcome::Cold { tip: 2000 });
        store.down.store(true, Ordering::SeqCst);
        assert!(f.store_blocks(&[block], 2000).await.is_err());
        assert!(f
            .write_tip(&Tip {
                height: 2001,
                hash: hash_at(2001, 0)
            })
            .await
            .is_err());
        store.down.store(false, Ordering::SeqCst);
        assert_eq!(stored_tip(&store), Some(2000));
    }

    #[tokio::test(start_paused = true)]
    async fn a_lower_probe_does_not_replace_a_higher_held_tip() {
        let store = Arc::new(MemStore::default());
        let stuck = Arc::new(FakeChain::new(1000));
        let live = Arc::new(FakeChain::new(1000));
        let (leader, follower) = pair(&store, &stuck, &live);
        assert_eq!(leader.tick().await, Outcome::Cold { tip: 1000 });
        live.set_tip(1006);
        age_the_tip();
        assert!(matches!(
            follower.tick().await,
            Outcome::StaleLeader { to: 1006, .. }
        ));
        // Another instance behind the same name answers lower, still ahead of the stored tip
        // (and another holder, so that this probe is a new observation, not a takeover).
        live.set_tip(1003);
        store.locks.lock().unwrap().insert(
            lock_key(&store.chain_prefix()),
            (
                "third".to_string(),
                tokio::time::Instant::now() + Duration::from_secs(3600),
            ),
        );
        for _ in 1..STALE_PROBE_EVERY {
            follower.tick().await;
            assert_eq!(follower.tip().unwrap().height, 1006);
        }
        assert_eq!(
            follower.tick().await,
            Outcome::StaleLeader {
                from: 1000,
                to: 1006,
                took_over: false
            }
        );
        assert_eq!(follower.tip().unwrap().height, 1006);
    }

    #[tokio::test(start_paused = true)]
    async fn the_held_tip_rule() {
        let store = Arc::new(MemStore::default());
        let stuck = Arc::new(FakeChain::new(1000));
        let live = Arc::new(FakeChain::new(1000));
        let (_leader, follower) = pair(&store, &stuck, &live);
        let chain = store.chain_prefix();
        let tip = |h: u64, f: u8| Tip {
            height: h,
            hash: hash_at(h, f),
        };
        let put_stored = |t: &Tip| {
            store.put(&tip_key(&chain), encode_tip(t));
            store.put(&tip_at_key(&chain), old_tip_at());
        };
        // A leader that holds the lock and does not move (it never ticks here).
        store.locks.lock().unwrap().insert(
            lock_key(&chain),
            (
                "stuck-leader".to_string(),
                tokio::time::Instant::now() + Duration::from_secs(3600),
            ),
        );
        put_stored(&tip(1000, 0));
        store.put(&tip_at_key(&chain), encode_unix_ms(1));
        live.set_tip(1006);
        assert!(matches!(
            follower.tick().await,
            Outcome::StaleLeader { to: 1006, .. }
        ));
        // The stored tip moves but stays below: the held tip is kept (no step back).
        put_stored(&tip(1002, 0));
        follower.tick().await;
        assert_eq!(follower.tip().unwrap().height, 1006);
        // The stored chain changes at the held observation's height (a reorg of the stored
        // chain): the held tip is dropped and the stored tip served.
        put_stored(&tip(1000, 7));
        follower.tick().await;
        assert_eq!(follower.tip(), Some(tip(1000, 7)));
        // A fresh observation; then it ages out without a confirmation: one step back to the
        // stored tip, not before.
        put_stored(&tip(1000, 0));
        for _ in 0..STALE_PROBE_EVERY {
            follower.tick().await;
        }
        assert_eq!(follower.tip().unwrap().height, 1006);
        live.down.store(true, Ordering::SeqCst);
        tokio::time::advance(HELD_TIP_MAX_AGE - Duration::from_secs(1)).await;
        follower.tick().await;
        assert_eq!(follower.tip().unwrap().height, 1006);
        tokio::time::advance(Duration::from_secs(2)).await;
        follower.tick().await;
        assert_eq!(follower.tip(), Some(tip(1000, 0)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_holder_change_between_probes_starts_a_new_observation() {
        let store = Arc::new(MemStore::default());
        let stuck = Arc::new(FakeChain::new(1000));
        let live = Arc::new(FakeChain::new(1000));
        let (leader, follower) = pair(&store, &stuck, &live);
        assert_eq!(leader.tick().await, Outcome::Cold { tip: 1000 });
        live.set_tip(1006);
        age_the_tip();
        assert!(matches!(
            follower.tick().await,
            Outcome::StaleLeader {
                took_over: false,
                ..
            }
        ));
        // Another process holds the lock now (the stale leader's lapsed, a third one took it,
        // and it is stuck too).
        let lock = lock_key(&store.chain_prefix());
        store.locks.lock().unwrap().insert(
            lock.clone(),
            (
                "third".to_string(),
                tokio::time::Instant::now() + Duration::from_secs(3600),
            ),
        );
        for _ in 1..STALE_PROBE_EVERY {
            follower.tick().await;
        }
        // Second probe: another holder than observed, no takeover yet (a new observation).
        assert!(matches!(
            follower.tick().await,
            Outcome::StaleLeader {
                took_over: false,
                ..
            }
        ));
        assert!(!follower.is_leader());
        for _ in 1..STALE_PROBE_EVERY {
            follower.tick().await;
        }
        // Third probe, the same holder twice in a row: it takes over.
        assert_eq!(
            follower.tick().await,
            Outcome::Advanced {
                from: 1001,
                to: 1006
            }
        );
        assert!(follower.is_leader());
    }

    #[tokio::test(start_paused = true)]
    async fn a_held_tip_is_served_for_at_most_the_hold_in_total() {
        let store = Arc::new(MemStore::default());
        let live = Arc::new(FakeChain::new(1000));
        let (_, follower) = pair(&store, &Arc::new(FakeChain::new(1000)), &live);
        let leader = KeysOnlyLeader::new(&store);
        // A leader of this version whose tip stopped moving long ago and that no longer
        // confirms it.
        leader.move_tip(1000);
        store.put(&tip_at_key(&store.chain_prefix()), encode_unix_ms(1));
        leader.confirm(0);
        live.set_tip(1006);
        assert!(matches!(
            follower.tick().await,
            Outcome::StaleLeader {
                to: 1006,
                took_over: false,
                ..
            }
        ));
        // No probe confirms the held tip again: it is served for the hold, re-served on every
        // tick, and then neither it nor the unconfirmed stored tip is.
        live.down.store(true, Ordering::SeqCst);
        let mut waited = Duration::ZERO;
        while waited < HELD_TIP_MAX_AGE {
            assert_eq!(follower.tip().unwrap().height, 1006, "after {waited:?}");
            tokio::time::advance(Duration::from_secs(5)).await;
            waited += Duration::from_secs(5);
            assert_eq!(follower.tick().await, Outcome::Follower);
        }
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            follower.tip(),
            None,
            "stale at the bound, without another tick"
        );
        assert_eq!(follower.tick().await, Outcome::Follower);
        assert_eq!(follower.tip(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_takeover_does_not_step_the_served_tip_back() {
        let store = Arc::new(MemStore::default());
        let stuck = Arc::new(FakeChain::new(1000));
        let live = Arc::new(FakeChain::new(1000));
        let (leader, follower) = pair(&store, &stuck, &live);
        assert_eq!(leader.tick().await, Outcome::Cold { tip: 1000 });
        live.set_tip(1006);
        age_the_tip();
        assert!(matches!(
            follower.tick().await,
            Outcome::StaleLeader {
                to: 1006,
                took_over: false,
                ..
            }
        ));
        for _ in 1..STALE_PROBE_EVERY {
            assert_eq!(follower.tick().await, Outcome::Follower);
            assert_eq!(follower.tip().unwrap().height, 1006);
        }
        // Another instance behind the same name answers lower, still ahead of the stored tip:
        // the second probe takes over and indexes up to that lower tip.
        live.set_tip(1003);
        assert_eq!(
            follower.tick().await,
            Outcome::Advanced {
                from: 1001,
                to: 1003
            }
        );
        assert!(follower.is_leader());
        assert_eq!(stored_tip(&store), Some(1003));
        assert_eq!(follower.tip().unwrap().height, 1006, "no step back");
        // Confirmed leader ticks keep it within the hold, then serve the indexed tip.
        let mut waited = Duration::ZERO;
        while waited <= HELD_TIP_MAX_AGE {
            assert_eq!(follower.tick().await, Outcome::Idle);
            assert_eq!(follower.tip().unwrap().height, 1006, "after {waited:?}");
            tokio::time::advance(Duration::from_secs(5)).await;
            waited += Duration::from_secs(5);
        }
        assert_eq!(follower.tick().await, Outcome::Idle);
        assert_eq!(follower.tip().unwrap().height, 1003);
    }

    #[tokio::test(start_paused = true)]
    async fn a_fork_of_the_stored_chain_above_the_observation_drops_the_held_tip() {
        let store = Arc::new(MemStore::default());
        let live = Arc::new(FakeChain::new(1000));
        let (_, follower) = pair(&store, &Arc::new(FakeChain::new(1000)), &live);
        let _leader = KeysOnlyLeader::new(&store);
        let chain = store.chain_prefix();
        let tip = |h: u64, f: u8| Tip {
            height: h,
            hash: hash_at(h, f),
        };
        let index = |h: u64, f: u8| store.put(&index_key(&chain, h), Bytes::from(hash_at(h, f)));
        // A stored tip that stopped moving long ago (no confirmation key: every read counts).
        let put_stored = |t: &Tip| {
            store.put(&tip_key(&chain), encode_tip(t));
            store.put(&tip_at_key(&chain), old_tip_at());
        };
        for h in 990..=1000 {
            index(h, 0);
        }
        put_stored(&tip(1000, 0));
        live.set_tip(1006);
        assert!(matches!(
            follower.tick().await,
            Outcome::StaleLeader { to: 1006, .. }
        ));
        // The stored chain moves on, still below: the held tip is kept.
        index(1001, 0);
        index(1002, 0);
        put_stored(&tip(1002, 0));
        assert_eq!(follower.tick().await, Outcome::Follower);
        assert_eq!(follower.tip().unwrap().height, 1006);
        // It forks above the observation (at 1001): the index at the last stored height seen
        // names another block now. The held tip is dropped.
        for h in 1001..=1004 {
            index(h, 1);
        }
        put_stored(&tip(1004, 1));
        assert_eq!(follower.tick().await, Outcome::Follower);
        assert_eq!(follower.tip(), Some(tip(1004, 1)));

        // A new observation on that chain (the follower's lightwalletd is on it now); then
        // another block at a height above the observed stored tip but at the last one seen:
        // dropped too.
        live.reorg_from(1001, 1);
        for _ in 3..STALE_PROBE_EVERY {
            assert_eq!(follower.tick().await, Outcome::Follower);
        }
        assert!(matches!(
            follower.tick().await,
            Outcome::StaleLeader {
                from: 1004,
                to: 1006,
                ..
            }
        ));
        index(1005, 1);
        put_stored(&tip(1005, 1));
        assert_eq!(follower.tick().await, Outcome::Follower);
        assert_eq!(follower.tip().unwrap().height, 1006);
        index(1005, 2);
        put_stored(&tip(1005, 2));
        assert_eq!(follower.tick().await, Outcome::Follower);
        assert_eq!(follower.tip(), Some(tip(1005, 2)));
    }

    #[tokio::test(start_paused = true)]
    async fn the_confirmation_bound_survives_leader_changes_and_alternating_answers() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(9000));
        let a = follower(store.clone(), chain.clone(), None);
        let b = follower(store.clone(), chain.clone(), None);
        let prefix = store.chain_prefix();
        assert_eq!(a.tick().await, Outcome::Cold { tip: 9000 });
        // Fill the index below the tip (a lower answer on it is "behind").
        assert_eq!(a.tick().await, Outcome::Idle);
        // The tip moved long ago (the wall clock is not paused: the move is put back in time).
        let old = unix_ms_now() - MAX_CONFIRM_AGE.as_millis() as u64 - 1_000;
        store.put(&tip_at_key(&prefix), encode_unix_ms(old));
        a.moved_at_ms.store(old, Ordering::Relaxed);
        let seen = || store.get(&tip_seen_key(&prefix));
        let before = seen();
        assert_eq!(a.tick().await, Outcome::Idle);
        assert_eq!(seen(), before, "too old to be confirmed");
        // Another process leads (the lock lapsed): the bound does not start again.
        store.locks.lock().unwrap().clear();
        assert_eq!(b.tick().await, Outcome::Idle);
        assert!(b.is_leader());
        assert_eq!(seen(), before);
        // Nor with answers alternating between behind and the tip.
        for _ in 0..5 {
            chain.set_tip(8995);
            assert!(matches!(b.tick().await, Outcome::Behind { .. }));
            chain.set_tip(9000);
            assert_eq!(b.tick().await, Outcome::Idle);
        }
        assert_eq!(seen(), before);
        // Still leading (renewed every tick), the tip unconfirmed: it goes stale.
        for _ in 0..7 {
            tokio::time::advance(Duration::from_secs(5)).await;
            assert_eq!(b.tick().await, Outcome::Idle);
        }
        assert!(b.is_leader());
        assert_eq!(seen(), before);
        assert_eq!(b.tip(), None);
        // A new block is confirmed again.
        chain.set_tip(9001);
        assert!(matches!(b.tick().await, Outcome::Advanced { .. }));
        assert_ne!(seen(), before);
        assert_eq!(b.tip().unwrap().height, 9001);
    }

    #[tokio::test(start_paused = true)]
    async fn a_leader_that_continues_a_tip_without_tip_at_writes_it() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(500));
        let f = follower(store.clone(), chain.clone(), None);
        let prefix = store.chain_prefix();
        // A tip stored by a leader that does not write `tip_at`; its lock lapsed.
        store.put(
            &tip_key(&prefix),
            encode_tip(&Tip {
                height: 500,
                hash: hash_at(500, 0),
            }),
        );
        let before = unix_ms_now();
        assert_eq!(f.tick().await, Outcome::Idle);
        assert!(f.is_leader());
        let at = store
            .get(&tip_at_key(&prefix))
            .and_then(|b| decode_unix_ms(&b))
            .expect("tip_at written with the confirmation");
        assert!(at >= before && at <= unix_ms_now());
        let seen = store
            .get(&tip_seen_key(&prefix))
            .and_then(|b| decode_unix_ms(&b))
            .unwrap();
        assert!(seen >= at);
    }

    #[tokio::test(start_paused = true)]
    async fn a_follower_started_under_a_leader_that_does_not_confirm_keeps_the_tip() {
        let store = Arc::new(MemStore::default());
        let leader = KeysOnlyLeader::new(&store);
        // A leader of this version confirmed the tip once; then one that does not write the
        // confirmation moved it (its `tip_at` is newer than the key left behind).
        leader.move_tip(100);
        leader.confirm(0);
        std::thread::sleep(Duration::from_millis(5));
        leader.move_tip(101);
        // A follower that starts now follows it on every read, from the first one on.
        let f = follower(store.clone(), Arc::new(FakeChain::new(101)), None);
        let mut idle = Duration::ZERO;
        while idle <= crate::store::TIP_STALE_AFTER * 2 {
            assert_eq!(f.tick().await, Outcome::Follower);
            assert_eq!(f.tip().unwrap().height, 101, "after {idle:?}");
            tokio::time::advance(Duration::from_secs(5)).await;
            idle += Duration::from_secs(5);
        }
        // A leader of this version confirms again: the strict rule applies again.
        leader.confirm(1);
        assert_eq!(f.tick().await, Outcome::Follower);
        tokio::time::advance(crate::store::TIP_STALE_AFTER + Duration::from_secs(1)).await;
        assert_eq!(f.tick().await, Outcome::Follower);
        assert_eq!(f.tip(), None);
    }

    /// A follower that holds 1006 (its own lightwalletd) over a stored chain at 1002 on fork
    /// 0, under a leader simulated by its keys. Returns the store, the follower and its chain.
    async fn holding_follower() -> (Arc<MemStore>, Arc<ChainFollower>, Arc<FakeChain>) {
        let store = Arc::new(MemStore::default());
        let live = Arc::new(FakeChain::new(1000));
        let (_, follower) = pair(&store, &Arc::new(FakeChain::new(1000)), &live);
        let _leader = KeysOnlyLeader::new(&store);
        let chain = store.chain_prefix();
        for h in 990..=1002 {
            store.put(&index_key(&chain, h), Bytes::from(hash_at(h, 0)));
        }
        let put_stored = |h: u64| {
            let tip = Tip {
                height: h,
                hash: hash_at(h, 0),
            };
            store.put(&tip_key(&chain), encode_tip(&tip));
            store.put(&tip_at_key(&chain), old_tip_at());
        };
        put_stored(1000);
        live.set_tip(1006);
        assert!(matches!(
            follower.tick().await,
            Outcome::StaleLeader { to: 1006, .. }
        ));
        put_stored(1002);
        assert_eq!(follower.tick().await, Outcome::Follower);
        assert_eq!(follower.tip().unwrap().height, 1006);
        (store, follower, live)
    }

    #[tokio::test(start_paused = true)]
    async fn a_lock_taken_after_a_fork_of_the_stored_chain_drops_the_held_tip() {
        let (store, follower, live) = holding_follower().await;
        let chain = store.chain_prefix();
        // Another leader rewrote the stored chain from 1001 on (fork 1) up to 1003, and its
        // lock lapsed; this process's lightwalletd answers on that fork now.
        for h in 1001..=1003 {
            store.put(&index_key(&chain, h), Bytes::from(hash_at(h, 1)));
        }
        let forked = Tip {
            height: 1003,
            hash: hash_at(1003, 1),
        };
        store.put(&tip_key(&chain), encode_tip(&forked));
        store.put(&tip_at_key(&chain), encode_unix_ms(unix_ms_now()));
        store.locks.lock().unwrap().clear();
        live.reorg_from(1001, 1);
        live.set_tip(1003);
        // An ordinary acquisition of the lock: it continues the stored chain without a reorg.
        assert_eq!(follower.tick().await, Outcome::Idle);
        assert!(follower.is_leader());
        assert_eq!(follower.tip(), Some(forked));
    }

    #[tokio::test(start_paused = true)]
    async fn a_lock_taken_on_the_same_stored_chain_keeps_the_held_tip() {
        let (store, follower, live) = holding_follower().await;
        // The leader's lock lapsed; another instance behind the same name answers lower.
        store.locks.lock().unwrap().clear();
        live.set_tip(1003);
        assert_eq!(
            follower.tick().await,
            Outcome::Advanced {
                from: 1003,
                to: 1003
            }
        );
        assert!(follower.is_leader());
        assert_eq!(stored_tip(&store), Some(1003));
        assert_eq!(follower.tip().unwrap().height, 1006, "no step back");

        // No stored tip at all when the lock is taken: nothing to hold a tip against.
        let (store, follower, live) = holding_follower().await;
        store.locks.lock().unwrap().clear();
        store
            .data
            .lock()
            .unwrap()
            .remove(&tip_key(&store.chain_prefix()));
        live.set_tip(1003);
        assert_eq!(follower.tick().await, Outcome::Cold { tip: 1003 });
        assert_eq!(follower.tip().unwrap().height, 1003);
    }

    /// Put the stored `tip_at` `ago` in the past (the wall clock is not paused).
    fn age_tip_at(store: &MemStore, ago: Duration) -> u64 {
        let at = unix_ms_now() - ago.as_millis() as u64;
        store.put(&tip_at_key(&store.chain_prefix()), encode_unix_ms(at));
        at
    }

    /// Tick `f` every 5 s for a little longer than the tip stays fresh without a refresh.
    async fn tick_past_the_stale_bound(f: &ChainFollower) {
        let mut waited = Duration::ZERO;
        while waited <= crate::store::TIP_STALE_AFTER {
            tokio::time::advance(Duration::from_secs(5)).await;
            waited += Duration::from_secs(5);
            assert_eq!(f.tick().await, Outcome::Follower);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_leader_taken_for_one_that_does_not_confirm_keeps_an_old_tip_fresh_no_longer() {
        let past_the_bound = MAX_CONFIRM_AGE + Duration::from_secs(1);
        // (a) A leader that writes `tip_at` but no confirmation moved the tip (the confirmation
        // key is a leftover); then nobody confirms.
        let store = Arc::new(MemStore::default());
        let leader = KeysOnlyLeader::new(&store);
        let f = follower(store.clone(), Arc::new(FakeChain::new(101)), None);
        leader.move_tip(100);
        leader.confirm(0);
        assert_eq!(f.tick().await, Outcome::Follower);
        std::thread::sleep(Duration::from_millis(5));
        leader.move_tip(101);
        // While the tip moved recently it is refreshed on every read.
        tick_past_the_stale_bound(&f).await;
        assert_eq!(f.tip().unwrap().height, 101);
        // Once it moved longer ago than a leader of this version confirms it, it goes stale.
        age_tip_at(&store, past_the_bound);
        tick_past_the_stale_bound(&f).await;
        assert_eq!(f.tip(), None);
        // A changed confirmation refreshes it again.
        leader.confirm(1);
        assert_eq!(f.tick().await, Outcome::Follower);
        assert_eq!(f.tip().unwrap().height, 101);

        // (b) A confirming leader whose confirmations are below `tip_at` (written by a process
        // whose clock was ahead) stops confirming.
        let store = Arc::new(MemStore::default());
        let leader = KeysOnlyLeader::new(&store);
        let f = follower(store.clone(), Arc::new(FakeChain::new(200)), None);
        let chain = store.chain_prefix();
        leader.move_tip(200);
        let at = age_tip_at(&store, past_the_bound);
        let confirm_below = |n: u64| store.put(&tip_seen_key(&chain), encode_unix_ms(at - 100 + n));
        for n in 0..3 {
            confirm_below(n);
            tokio::time::advance(Duration::from_secs(20)).await;
            assert_eq!(f.tick().await, Outcome::Follower);
            assert_eq!(f.tip().unwrap().height, 200, "confirmation {n}");
        }
        tick_past_the_stale_bound(&f).await;
        assert_eq!(f.tip(), None);
        confirm_below(3);
        assert_eq!(f.tick().await, Outcome::Follower);
        assert_eq!(f.tip().unwrap().height, 200);
    }

    #[tokio::test(start_paused = true)]
    async fn an_unreadable_index_entry_does_not_hide_a_fork_from_the_held_tip() {
        let fork_the_stored_chain = |store: &MemStore| {
            let chain = store.chain_prefix();
            // The stored chain forks at 1001 and reaches 1004; the index entry at the last
            // stored height the follower saw (1002) is not there yet.
            for h in [1001, 1003, 1004] {
                store.put(&index_key(&chain, h), Bytes::from(hash_at(h, 1)));
            }
            store.data.lock().unwrap().remove(&index_key(&chain, 1002));
            let forked = Tip {
                height: 1004,
                hash: hash_at(1004, 1),
            };
            store.put(&tip_key(&chain), encode_tip(&forked));
            store.put(&tip_at_key(&chain), encode_unix_ms(unix_ms_now()));
            forked
        };
        let index_1002 = |store: &MemStore| {
            store.put(
                &index_key(&store.chain_prefix(), 1002),
                Bytes::from(hash_at(1002, 1)),
            )
        };

        // As a follower: no evidence on the first read (the held tip stays), and the next
        // read still checks against the stored tip seen before the fork.
        let (store, follower, _live) = holding_follower().await;
        // The held tip's chain is not known here (it would show the fork by itself).
        follower.stale.lock().as_mut().unwrap().chain = None;
        let forked = fork_the_stored_chain(&store);
        assert_eq!(follower.tick().await, Outcome::Follower);
        assert_eq!(follower.tip().unwrap().height, 1006);
        index_1002(&store);
        assert_eq!(follower.tick().await, Outcome::Follower);
        assert_eq!(follower.tip(), Some(forked));

        // The same when the lock is taken in between.
        let (store, follower, live) = holding_follower().await;
        // The held tip's chain is not known here (it would show the fork by itself).
        follower.stale.lock().as_mut().unwrap().chain = None;
        let forked = fork_the_stored_chain(&store);
        assert_eq!(follower.tick().await, Outcome::Follower);
        assert_eq!(follower.tip().unwrap().height, 1006);
        index_1002(&store);
        store.locks.lock().unwrap().clear();
        live.reorg_from(1001, 1);
        live.set_tip(1004);
        assert_eq!(follower.tick().await, Outcome::Idle);
        assert!(follower.is_leader());
        assert_eq!(follower.tip(), Some(forked));
    }
    /// The stored chain forks under a held tip while the index entry it is checked against is
    /// missing; a scheduled probe that finds its own lightwalletd still ahead keeps the held
    /// tip, and with it the stored tip it is checked against, so the fork is seen once the
    /// entry is there.
    #[tokio::test(start_paused = true)]
    async fn a_stale_probe_keeps_the_held_tip_checked_against_its_anchor() {
        let (store, follower, _live) = holding_follower().await;
        // The held tip's chain is not known here (it would show the fork by itself).
        follower.stale.lock().as_mut().unwrap().chain = None;
        let chain = store.chain_prefix();
        for h in [1001, 1003, 1004] {
            store.put(&index_key(&chain, h), Bytes::from(hash_at(h, 1)));
        }
        store.data.lock().unwrap().remove(&index_key(&chain, 1002));
        let forked = Tip {
            height: 1004,
            hash: hash_at(1004, 1),
        };
        store.put(&tip_key(&chain), encode_tip(&forked));
        // Moved long ago: the follower keeps probing its own lightwalletd.
        store.put(&tip_at_key(&chain), old_tip_at());
        let mut probed = false;
        for _ in 0..STALE_PROBE_EVERY {
            match follower.tick().await {
                Outcome::StaleLeader {
                    to: 1006,
                    took_over: false,
                    ..
                } => probed = true,
                Outcome::Follower => {}
                other => panic!("{other:?}"),
            }
            assert_eq!(follower.tip().unwrap().height, 1006);
            if probed {
                break;
            }
        }
        assert!(probed, "a scheduled probe found its lightwalletd ahead");
        store.put(&index_key(&chain, 1002), Bytes::from(hash_at(1002, 1)));
        assert_eq!(follower.tick().await, Outcome::Follower);
        assert_eq!(follower.tip(), Some(forked));
    }

    /// A lock taken in the ordinary way while the stored chain under the held tip cannot be
    /// checked (the index entry is missing) drops the held tip: as leader nothing checks it
    /// again. The entry becoming readable afterwards changes nothing.
    #[tokio::test(start_paused = true)]
    async fn a_lock_taken_while_the_stored_chain_cannot_be_checked_drops_the_held_tip() {
        let (store, follower, live) = holding_follower().await;
        let chain = store.chain_prefix();
        // Only the unresolved check can drop it here (no known chain of the held tip).
        follower.stale.lock().as_mut().unwrap().chain = None;
        for h in [1001, 1003, 1004] {
            store.put(&index_key(&chain, h), Bytes::from(hash_at(h, 1)));
        }
        store.data.lock().unwrap().remove(&index_key(&chain, 1002));
        let forked = Tip {
            height: 1004,
            hash: hash_at(1004, 1),
        };
        store.put(&tip_key(&chain), encode_tip(&forked));
        store.put(&tip_at_key(&chain), encode_unix_ms(unix_ms_now()));
        store.locks.lock().unwrap().clear();
        live.reorg_from(1001, 1);
        live.set_tip(1004);
        assert_eq!(follower.tick().await, Outcome::Idle);
        assert!(follower.is_leader());
        assert_eq!(follower.tip(), Some(forked.clone()));
        store.put(&index_key(&chain, 1002), Bytes::from(hash_at(1002, 1)));
        assert_eq!(follower.tick().await, Outcome::Idle);
        assert_eq!(follower.tip(), Some(forked));
    }

    /// A leader that holds a tip from its own lightwalletd and indexes a lower tip of another
    /// fork, which extends the stored tip without a reorg of the index, serves the indexed tip.
    #[tokio::test(start_paused = true)]
    async fn a_leader_whose_lightwalletd_moves_to_a_lower_fork_drops_the_held_tip() {
        let (store, follower, live) = holding_follower().await;
        assert!(
            follower.stale.lock().as_ref().unwrap().chain.is_some(),
            "the held tip's chain was fetched with it"
        );
        store.locks.lock().unwrap().clear();
        live.reorg_from(1003, 1);
        live.set_tip(1004);
        assert_eq!(
            follower.tick().await,
            Outcome::Advanced {
                from: 1003,
                to: 1004
            }
        );
        assert!(follower.is_leader());
        assert_eq!(
            follower.tip(),
            Some(Tip {
                height: 1004,
                hash: hash_at(1004, 1)
            })
        );
    }

    /// A stored `tip_at` far ahead of the leader's clock: the confirmation bound counts from
    /// the takeover (the age is clamped), and the first confirmation replaces the stored value
    /// by that time, with its stamp, in one fenced script. Followers then read the tip's real
    /// age, and still need every confirmation.
    #[tokio::test(start_paused = true)]
    async fn a_tip_at_in_the_future_is_replaced_with_the_first_confirmation() {
        let network = format!("testnet-tip-at-rewrite-{}", std::process::id());
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(500));
        let f = follower_on(store.clone(), chain.clone(), &network);
        let prefix = store.chain_prefix();
        let future = unix_ms_now() + 3_600_000;
        let tip = put_record(&store, 500, future, Some(9));
        let read_ms = |key: String| store.get(&key).and_then(|b| decode_unix_ms(&b));
        let stamp = || decode_tip_stamp(&store.get(&tip_stamp_key(&prefix)).unwrap()).unwrap();
        let before = unix_ms_now();
        assert_eq!(f.tick().await, Outcome::Idle);
        assert!(f.is_leader());
        let moved_at = f.moved_at_ms.load(Ordering::Relaxed);
        assert!(moved_at >= before && moved_at <= unix_ms_now(), "clamped");
        let at = read_ms(tip_at_key(&prefix)).unwrap();
        assert_eq!(at, moved_at, "replaced by the time the age counts from");
        let written = std::mem::take(&mut *store.fenced_writes.lock().unwrap());
        assert_eq!(
            written,
            vec![vec![
                tip_seen_key(&prefix),
                tip_at_key(&prefix),
                tip_stamp_key(&prefix)
            ]],
            "with the confirmation, in one fenced script"
        );
        let stamped = stamp();
        assert_eq!(stamped.tip_at_ms, at);
        assert_eq!(stamped.tip, encode_tip(&tip).to_vec());
        assert_eq!(
            stamped.nonce,
            next_stamp_nonce(9),
            "the next nonce of the replaced stamp's line"
        );
        let seen = read_ms(tip_seen_key(&prefix)).unwrap();
        assert!(seen >= at, "never below the stored tip_at");
        assert_eq!(crate::health::chain_tip_at_rewrites(&network), 1);
        assert_eq!(crate::health::chain_tip_time_ahead(&network), 0);
        // Once: the next confirmations are plain ones.
        assert_eq!(f.tick().await, Outcome::Idle);
        assert_eq!(read_ms(tip_at_key(&prefix)), Some(at));
        assert_eq!(stamp(), stamped);
        assert!(read_ms(tip_seen_key(&prefix)).unwrap() > seen);
        assert_eq!(crate::health::chain_tip_at_rewrites(&network), 1);
        // A follower takes them for confirmations of a leader of this version, and the stamp
        // vouches for the rewritten time.
        let g = follower(store.clone(), chain.clone(), None);
        assert_eq!(g.tick().await, Outcome::Follower);
        assert_eq!(g.tip(), Some(tip.clone()));
        assert!(!g.last_seen.lock().as_ref().unwrap().unconfirming_leader);
        let read = g.last_tip_at.lock().clone().unwrap();
        assert_eq!(
            (read.tip_at, read.leftover, read.nonce),
            (Some(at), false, Some(stamped.nonce))
        );
        // A follower that knows no stamp (an earlier version rolled back in) read the time
        // ahead and now reads the rewritten one under the same tip: not a leftover.
        let old = plain_follower();
        assert_eq!(
            old.effective_tip_at(&tip, Some(future), None),
            (Some(future), None)
        );
        assert_eq!(old.effective_tip_at(&tip, Some(at), None), (Some(at), None));
        // Once the bound passed since the takeover the leader stops confirming, and the tip
        // goes stale on the follower.
        f.moved_at_ms.store(
            moved_at - MAX_CONFIRM_AGE.as_millis() as u64 - 1_000,
            Ordering::Relaxed,
        );
        let seen = read_ms(tip_seen_key(&prefix));
        for _ in 0..8 {
            tokio::time::advance(Duration::from_secs(5)).await;
            assert_eq!(f.tick().await, Outcome::Idle);
            assert_eq!(g.tick().await, Outcome::Follower);
        }
        assert_eq!(read_ms(tip_seen_key(&prefix)), seen);
        assert_eq!(g.tip(), None);
    }

    /// A follower that has read a tip with a `tip_at` ahead of its clock keeps its count of
    /// how long it has read that tip when a new leader replaces the `tip_at`: the tip did not
    /// move. Another tip, or a later `tip_at`, starts the count again as before.
    #[tokio::test(start_paused = true)]
    async fn a_replaced_tip_at_does_not_restart_a_followers_count() {
        let store = Arc::new(MemStore::default());
        let _leader = KeysOnlyLeader::new(&store);
        let f = follower(store.clone(), Arc::new(FakeChain::new(1000)), None);
        let since = || f.unmoved.lock().as_ref().map(|u| u.since);
        let ahead = unix_ms_now() + 3_600_000;
        let tip = put_record(&store, 1000, ahead, Some(1));
        assert_eq!(f.tick().await, Outcome::Follower);
        let first = since().expect("observed");
        tokio::time::advance(Duration::from_secs(100)).await;
        // A leader replaced the time by its own, with the stamp of a replacement.
        let replaced = unix_ms_now() - 1_000;
        let successor = next_stamp_nonce(1);
        put_record(&store, 1000, replaced, Some(successor));
        assert_eq!(f.tick().await, Outcome::Follower);
        assert_eq!(since(), Some(first), "the count goes on");
        assert_eq!(
            f.unmoved.lock().as_ref().unwrap().record,
            TipRecord {
                tip,
                tip_at: replaced,
                nonce: Some(successor)
            }
        );
        assert_eq!(first.elapsed(), Duration::from_secs(100));
        // The same tip written again with an earlier time and a nonce of another line (it
        // may have moved away and back meanwhile): another record.
        tokio::time::advance(Duration::from_secs(1)).await;
        put_record(&store, 1000, replaced - 1, Some(77 << 32));
        assert_eq!(f.tick().await, Outcome::Follower);
        let again = since().expect("observed");
        assert_ne!(again, first, "a write of its own: started again");
        // Without a stamp that vouches for it, an earlier time is another record.
        tokio::time::advance(Duration::from_secs(1)).await;
        put_record(&store, 1000, replaced - 2, None);
        assert_eq!(f.tick().await, Outcome::Follower);
        let second = since().expect("observed");
        assert_ne!(second, again, "no stamp: started again");
        // Another tip with an earlier time: started again.
        tokio::time::advance(Duration::from_secs(1)).await;
        put_record(&store, 1001, replaced - 3, Some(3));
        assert_eq!(f.tick().await, Outcome::Follower);
        assert_ne!(since().expect("observed"), second, "another tip");
    }

    /// What counts as a replaced `tip_at` of the same record.
    #[test]
    fn a_replaced_record_is_recognised_by_its_line_of_nonces() {
        let record = |height: u64, tip_at: u64, nonce: Option<u64>| TipRecord {
            tip: tip_n(height),
            tip_at,
            nonce,
        };
        let start: u64 = 0x0123_4567_89ab_cdef;
        let first = record(1, 1_000, Some(start));
        let line = |steps: u32| (0..steps).fold(start, |nonce, _| next_stamp_nonce(nonce));
        assert_eq!(line(1), start + 1);
        assert!(first.replaced_by(&record(1, 900, Some(line(1)))));
        // Replacements this reader missed in between, however many.
        assert!(first.replaced_by(&record(1, 900, Some(line(2)))));
        assert!(first.replaced_by(&record(1, 900, Some(line(1_000)))));
        // The step wraps inside its half and stays on the line.
        let last = 0x0123_4567_ffff_ffff;
        assert_eq!(next_stamp_nonce(last), 0x0123_4567_0000_0000);
        assert!(record(1, 1_000, Some(last)).replaced_by(&record(
            1,
            900,
            Some(next_stamp_nonce(last))
        )));
        // Not the record itself, not a nonce of another line, another time or tip, nor a
        // record without a stamp.
        assert!(!first.replaced_by(&first));
        assert!(!first.replaced_by(&record(1, 900, Some(start))));
        assert!(!first.replaced_by(&record(1, 900, Some(start ^ (1 << 32)))));
        assert!(!first.replaced_by(&record(1, 900, None)));
        assert!(!first.replaced_by(&record(1, 1_000, Some(line(1)))));
        assert!(!first.replaced_by(&record(1, 1_100, Some(line(1)))));
        assert!(!first.replaced_by(&record(2, 900, Some(line(1)))));
        assert!(!record(1, 1_000, None).replaced_by(&record(1, 900, Some(line(1)))));
        for nonce in [0, 1, u64::from(u32::MAX), u64::MAX, start] {
            assert_ne!(next_stamp_nonce(nonce), nonce);
        }
    }

    #[test]
    fn a_replacement_is_never_the_tip_at_of_the_tip_before() {
        assert_eq!(replacement_tip_at(1_000, 0), 1_000);
        assert_eq!(replacement_tip_at(1_000, 999), 1_000);
        assert_eq!(replacement_tip_at(1_000, 1_000), 999);
        assert_eq!(replacement_tip_at(1, 1), 2);
    }

    /// A leader that wrote two tips and whose clock then stepped back does not give the
    /// second one the `tip_at` of the first when it replaces its `tip_at`.
    #[tokio::test(start_paused = true)]
    async fn a_leader_remembers_the_tip_at_of_the_tip_before() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(500));
        let f = follower(store.clone(), chain.clone(), None);
        let prefix = store.chain_prefix();
        let tip_at = || {
            store
                .get(&tip_at_key(&prefix))
                .and_then(|b| decode_unix_ms(&b))
                .unwrap()
        };
        assert_eq!(f.tick().await, Outcome::Cold { tip: 500 });
        let first = tip_at();
        assert_eq!(f.tip_at_before_ms.load(Ordering::Relaxed), 0);
        chain.set_tip(501);
        assert!(matches!(f.tick().await, Outcome::Advanced { .. }));
        assert_eq!(f.tip_at_before_ms.load(Ordering::Relaxed), first);
        assert_ne!(tip_at(), first);
        // A takeover forgets it: the tip before was not written by this process.
        f.adopt_tip_at(Some(tip_at()), Some(tip_at()), Duration::ZERO, None);
        assert_eq!(f.tip_at_before_ms.load(Ordering::Relaxed), 0);
    }

    /// A process that takes the lock over a record whose `tip_at` was replaced since its last
    /// read as a follower (it meets the replacement only when it takes the lock) counts the
    /// tip's age from its first read all the same: the tip did not move. An unrelated write
    /// of the same tip counts from the takeover.
    #[tokio::test(start_paused = true)]
    async fn a_takeover_over_a_replaced_tip_at_counts_from_the_first_read() {
        for (nonce_of, continued) in [
            (next_stamp_nonce as fn(u64) -> u64, true),
            ((|_: u64| 77u64 << 32) as fn(u64) -> u64, false),
        ] {
            let store = Arc::new(MemStore::default());
            let _leader = KeysOnlyLeader::new(&store);
            let f = follower(store.clone(), Arc::new(FakeChain::new(500)), None);
            let ahead = unix_ms_now() + 3_600_000;
            put_record(&store, 500, ahead, Some(3));
            assert_eq!(f.tick().await, Outcome::Follower);
            tokio::time::advance(Duration::from_secs(400)).await;
            // Another leader wrote a `tip_at` for the same tip, still ahead of this clock;
            // this process takes the lock before it reads that as a follower.
            put_record(&store, 500, ahead - 1_800_000, Some(nonce_of(3)));
            store.locks.lock().unwrap().clear();
            let before = unix_ms_now();
            assert_eq!(f.tick().await, Outcome::Idle);
            assert!(f.is_leader());
            let moved_at = f.moved_at_ms.load(Ordering::Relaxed);
            let watched = if continued { 400_000 } else { 0 };
            assert!(
                moved_at + watched >= before && moved_at + watched <= unix_ms_now(),
                "continued {continued}: counted from {} ms before the takeover",
                unix_ms_now() - moved_at
            );
        }
    }

    /// A leader whose own clock stepped back: the `tip_at` it wrote is ahead of its clock
    /// now. Its next confirmation replaces it by the tip's time on this clock (now, less the
    /// local time since the tip moved); a tip that moved longer ago than the confirmation
    /// bound by the local clock is not confirmed any more, whatever the step.
    #[tokio::test(start_paused = true)]
    async fn a_leader_whose_clock_stepped_back_replaces_its_tip_at() {
        let network = format!("testnet-tip-at-step-back-{}", std::process::id());
        // Lead for `led` after writing the tip (a confirmation every 5 s), then find the
        // stored time an hour ahead of the clock, as after a step back of the clock.
        async fn lead_then_step_back(
            network: &str,
            led: Duration,
        ) -> (Arc<MemStore>, ChainFollower, u64) {
            let store = Arc::new(MemStore::default());
            let f = follower_on(store.clone(), Arc::new(FakeChain::new(500)), network);
            assert_eq!(f.tick().await, Outcome::Cold { tip: 500 });
            let mut waited = Duration::ZERO;
            while waited < led {
                tokio::time::advance(Duration::from_secs(5)).await;
                waited += Duration::from_secs(5);
                f.tick().await;
            }
            assert!(f.is_leader());
            let ahead = unix_ms_now() + 3_600_000;
            store.put(&tip_at_key(&store.chain_prefix()), encode_unix_ms(ahead));
            f.moved_at_ms.store(ahead, Ordering::Relaxed);
            f.tip_at_floor_ms.store(ahead, Ordering::Relaxed);
            f.tip_at_written_ms.store(ahead, Ordering::Relaxed);
            f.tip_at_stored_ms.store(ahead, Ordering::Relaxed);
            store.fenced_writes.lock().unwrap().clear();
            (store, f, ahead)
        }
        let read_ms =
            |store: &MemStore, key: String| store.get(&key).and_then(|b| decode_unix_ms(&b));

        let (store, f, _) = lead_then_step_back(&network, Duration::from_secs(100)).await;
        let prefix = store.chain_prefix();
        let seen_before = read_ms(&store, tip_seen_key(&prefix));
        let before = unix_ms_now();
        f.tick().await;
        assert!(f.is_leader());
        let at = read_ms(&store, tip_at_key(&prefix)).unwrap();
        assert!(
            at + 100_000 >= before && at + 100_000 <= unix_ms_now(),
            "the tip's time on this clock: 100 s ago"
        );
        assert_eq!(f.moved_at_ms.load(Ordering::Relaxed), at);
        let written = std::mem::take(&mut *store.fenced_writes.lock().unwrap());
        assert!(
            written.contains(&vec![
                tip_seen_key(&prefix),
                tip_at_key(&prefix),
                tip_stamp_key(&prefix)
            ]),
            "with the confirmation, in one fenced script: {written:?}"
        );
        let stamp = decode_tip_stamp(&store.get(&tip_stamp_key(&prefix)).unwrap()).unwrap();
        assert_eq!(stamp.tip_at_ms, at);
        assert_eq!(stamp.tip, encode_tip(&tip_n(500)).to_vec());
        let seen = read_ms(&store, tip_seen_key(&prefix)).unwrap();
        assert!(seen >= at);
        assert_ne!(Some(seen), seen_before, "confirmed");
        assert_eq!(crate::health::chain_tip_at_rewrites(&network), 1);
        // Plain confirmations from here on.
        tokio::time::advance(Duration::from_secs(5)).await;
        f.tick().await;
        assert_eq!(read_ms(&store, tip_at_key(&prefix)), Some(at));
        assert_ne!(read_ms(&store, tip_seen_key(&prefix)), Some(seen));
        assert_eq!(crate::health::chain_tip_at_rewrites(&network), 1);

        // The tip moved longer ago than the bound by the local clock (the leader stopped
        // confirming it there already): still not confirmed once the stored time is found
        // ahead, and nothing written for it.
        let (store, f, ahead) =
            lead_then_step_back(&network, MAX_CONFIRM_AGE + Duration::from_secs(5)).await;
        let seen = read_ms(&store, tip_seen_key(&prefix));
        f.tick().await;
        assert!(f.is_leader());
        assert_eq!(
            read_ms(&store, tip_seen_key(&prefix)),
            seen,
            "no confirmation"
        );
        assert_eq!(read_ms(&store, tip_at_key(&prefix)), Some(ahead));
        assert_eq!(crate::health::chain_tip_at_rewrites(&network), 1);
    }

    /// The confirmation bound counts on the leader's local clock as well as on its wall
    /// clock: a wall clock that lags or stepped back (here it does not advance at all while
    /// the local clock does) does not keep an unmoved tip confirmed past the bound.
    #[tokio::test(start_paused = true)]
    async fn the_confirmation_bound_counts_on_the_local_clock_too() {
        let store = Arc::new(MemStore::default());
        let f = follower(store.clone(), Arc::new(FakeChain::new(500)), None);
        let seen = || store.get(&tip_seen_key(&store.chain_prefix()));
        assert_eq!(f.tick().await, Outcome::Cold { tip: 500 });
        let step = Duration::from_secs(5);
        let mut waited = Duration::ZERO;
        let mut last = seen();
        while waited + step < MAX_CONFIRM_AGE {
            tokio::time::advance(step).await;
            waited += step;
            f.tick().await;
            assert_ne!(seen(), last, "confirmed after {waited:?}");
            last = seen();
        }
        // The tick at the bound itself may still confirm; the ones past it, by the local
        // clock alone, do not.
        tokio::time::advance(step).await;
        f.tick().await;
        let last = seen();
        for _ in 0..3 {
            tokio::time::advance(step).await;
            f.tick().await;
        }
        assert!(f.is_leader());
        assert_eq!(seen(), last, "no confirmation past the bound");
        assert!(
            unix_ms_now().saturating_sub(f.moved_at_ms.load(Ordering::Relaxed))
                < MAX_CONFIRM_AGE.as_millis() as u64,
            "the wall clock alone would still confirm"
        );
    }

    /// A stored `tip_at` ahead of the leader's clock by no more than the allowance is kept as
    /// stored (the age is clamped, the confirmations stay at or above it): nothing rewritten.
    #[tokio::test(start_paused = true)]
    async fn a_tip_at_ahead_within_the_allowance_is_kept_as_stored() {
        let network = format!("testnet-tip-at-kept-{}", std::process::id());
        let store = Arc::new(MemStore::default());
        let f = follower_on(store.clone(), Arc::new(FakeChain::new(500)), &network);
        let prefix = store.chain_prefix();
        let ahead = unix_ms_now() + TIP_AT_MAX_AHEAD.as_millis() as u64 / 2;
        put_record(&store, 500, ahead, Some(9));
        let read_ms = |key: String| store.get(&key).and_then(|b| decode_unix_ms(&b));
        assert_eq!(f.tick().await, Outcome::Idle);
        assert!(f.is_leader());
        assert!(
            f.moved_at_ms.load(Ordering::Relaxed) <= unix_ms_now(),
            "clamped"
        );
        assert_eq!(read_ms(tip_at_key(&prefix)), Some(ahead), "kept as stored");
        assert!(read_ms(tip_seen_key(&prefix)).unwrap() >= ahead);
        let stamp = decode_tip_stamp(&store.get(&tip_stamp_key(&prefix)).unwrap()).unwrap();
        assert_eq!(stamp.nonce, 9, "the stamp is not rewritten either");
        let written = std::mem::take(&mut *store.fenced_writes.lock().unwrap());
        assert_eq!(written, vec![vec![tip_seen_key(&prefix)]]);
        assert_eq!(crate::health::chain_tip_at_rewrites(&network), 0);
    }

    /// After a rollback to a leader that writes neither `tip_at` nor `tip_seen`, the keys of a
    /// newer leader are left over: a tip that moves while `tip_at` stays is followed as one
    /// without `tip_at` (every read refreshes it), and a process that then takes the lock
    /// counts the tip's age from then, not from the leftover.
    #[tokio::test(start_paused = true)]
    async fn a_tip_moved_without_its_time_is_followed_as_one_without_tip_at() {
        let store = Arc::new(MemStore::default());
        let leader = KeysOnlyLeader::new(&store);
        let lwd = Arc::new(FakeChain::new(100));
        let f = follower(store.clone(), lwd.clone(), None);
        let prefix = store.chain_prefix();
        // A leader of this version moved the tip and confirmed it, long ago.
        leader.move_tip(100);
        leader.confirm(0);
        age_tip_at(&store, MAX_CONFIRM_AGE + Duration::from_secs(1));
        assert_eq!(f.tick().await, Outcome::Follower);
        assert_eq!(f.tip().unwrap().height, 100);
        // The rollback: the tip moves, its time and the confirmation stay.
        leader.move_tip_only(101);
        lwd.set_tip(101);
        let mut idle = Duration::ZERO;
        while idle <= crate::store::TIP_STALE_AFTER * 2 {
            assert_eq!(f.tick().await, Outcome::Follower);
            assert_eq!(f.tip().unwrap().height, 101, "after {idle:?}");
            tokio::time::advance(Duration::from_secs(5)).await;
            idle += Duration::from_secs(5);
        }
        // The lock lapses and this process leads.
        store.locks.lock().unwrap().clear();
        let before = unix_ms_now();
        assert_eq!(f.tick().await, Outcome::Idle);
        assert!(f.is_leader());
        let read_ms = |key: String| store.get(&key).and_then(|b| decode_unix_ms(&b));
        let at = read_ms(tip_at_key(&prefix)).unwrap();
        assert!(at >= before, "the leftover time does not count");
        assert!(read_ms(tip_seen_key(&prefix)).unwrap() >= at);
    }
    /// After the leader's clock stepped back the `tip_at` it writes follows the clock (it is
    /// not kept above the last one it wrote), differs from the previous one, and the tip's age
    /// counts from the clock. Two tips in a row never come with the same `tip_at`.
    #[tokio::test(start_paused = true)]
    async fn the_tip_at_written_follows_the_clock_back_and_differs_from_the_last_one() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(700));
        let f = follower(store.clone(), chain.clone(), None);
        assert_eq!(f.tick().await, Outcome::Cold { tip: 700 });
        let read_ms = |key: String| store.get(&key).and_then(|b| decode_unix_ms(&b));
        let prefix = store.chain_prefix();
        // The clock stepped back by an hour since this process wrote its last tip.
        let ahead = unix_ms_now() + 3_600_000;
        f.tip_at_written_ms.store(ahead, Ordering::Relaxed);
        f.tip_at_stored_ms.store(ahead, Ordering::Relaxed);
        chain.set_tip(701);
        assert!(matches!(f.tick().await, Outcome::Advanced { .. }));
        let at = read_ms(tip_at_key(&prefix)).unwrap();
        assert!(at <= unix_ms_now() + 1, "it follows the clock back");
        assert_ne!(at, ahead);
        assert!(f.moved_at_ms.load(Ordering::Relaxed) <= unix_ms_now());
        assert!(read_ms(tip_seen_key(&prefix)).unwrap() >= at);
        // Tips written in the same millisecond: another `tip_at` each time.
        let mut last = at;
        for height in 702..=720 {
            chain.set_tip(height);
            assert!(matches!(f.tick().await, Outcome::Advanced { .. }));
            let at = read_ms(tip_at_key(&prefix)).unwrap();
            assert_ne!(at, last, "height {height}");
            assert!(f.moved_at_ms.load(Ordering::Relaxed) <= unix_ms_now());
            last = at;
        }
    }
    #[test]
    fn the_tip_at_to_write_is_neither_the_last_written_nor_the_stored_one() {
        // Nothing to avoid: the clock value.
        assert_eq!(tip_at_to_write(1_000, 0, 0), 1_000);
        assert_eq!(tip_at_to_write(1_000, 999, 1_001), 1_000);
        // Each value alone.
        assert_eq!(tip_at_to_write(1_000, 1_000, 0), 1_001);
        assert_eq!(tip_at_to_write(1_000, 0, 1_000), 1_001);
        // The clock equal to one, the next value equal to the other: neither.
        assert_eq!(tip_at_to_write(1_000, 1_000, 1_001), 1_002);
        assert_eq!(tip_at_to_write(1_000, 1_001, 1_000), 1_002);
    }

    /// `write_tip` avoids the last `tip_at` this process wrote and the one in the store, each
    /// on its own and both at once (the values are set to the clock right before each write,
    /// so the write lands on them unless a millisecond passes in between).
    #[tokio::test(start_paused = true)]
    async fn a_tip_is_never_written_with_the_tip_at_written_or_stored_before() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(700));
        let f = follower(store.clone(), chain.clone(), None);
        assert_eq!(f.tick().await, Outcome::Cold { tip: 700 });
        let prefix = store.chain_prefix();
        let mut height = 700;
        // (last written, stored) as offsets from the clock; None: a value never met.
        for (written, stored) in [
            (Some(0), None),
            (None, Some(0)),
            (Some(0), Some(1)),
            (Some(1), Some(0)),
        ] {
            for _ in 0..50 {
                let wall = unix_ms_now();
                let written = written.map_or(1, |d| wall + d);
                let stored = stored.map_or(1, |d| wall + d);
                f.tip_at_written_ms.store(written, Ordering::Relaxed);
                f.tip_at_stored_ms.store(stored, Ordering::Relaxed);
                height += 1;
                chain.set_tip(height);
                assert!(matches!(f.tick().await, Outcome::Advanced { .. }));
                let at = store
                    .get(&tip_at_key(&prefix))
                    .and_then(|b| decode_unix_ms(&b))
                    .unwrap();
                assert_ne!(at, written, "the last one written");
                assert_ne!(at, stored, "the stored one");
                assert!(at >= wall);
                assert!(f.moved_at_ms.load(Ordering::Relaxed) <= unix_ms_now());
            }
        }
    }

    /// The `tip_at` in the store is remembered when a tip is taken over, also one that does
    /// not count as the tip's time (a leftover): the next tip is not written with it.
    #[tokio::test(start_paused = true)]
    async fn the_stored_tip_at_is_remembered_whether_it_counts_or_not() {
        let store = Arc::new(MemStore::default());
        let f = follower(store, Arc::new(FakeChain::new(100)), None);
        f.adopt_tip_at(None, Some(77), Duration::ZERO, None);
        assert_eq!(f.tip_at_stored_ms.load(Ordering::Relaxed), 77);
        assert!(f.tip_at_pending.load(Ordering::Relaxed));
        f.adopt_tip_at(Some(88), Some(88), Duration::ZERO, None);
        assert_eq!(f.tip_at_stored_ms.load(Ordering::Relaxed), 88);
        f.adopt_tip_at(None, None, Duration::ZERO, None);
        assert_eq!(f.tip_at_stored_ms.load(Ordering::Relaxed), 0);
    }

    /// A follower drops its held tip at once when the stored tip is a block its held tip's
    /// own chain does not have at that height, although the index entry at the last stored
    /// height it saw still names the same block (the stored chain forked above it).
    #[tokio::test(start_paused = true)]
    async fn a_follower_drops_a_held_tip_whose_chain_the_stored_tip_is_not_on() {
        let (store, follower, _live) = holding_follower().await;
        let chain = store.chain_prefix();
        // The stored chain goes on from 1002 with another block at 1003.
        let forked = Tip {
            height: 1003,
            hash: hash_at(1003, 1),
        };
        store.put(&index_key(&chain, 1003), Bytes::from(hash_at(1003, 1)));
        store.put(&tip_key(&chain), encode_tip(&forked));
        store.put(&tip_at_key(&chain), encode_unix_ms(unix_ms_now()));
        assert_eq!(follower.tick().await, Outcome::Follower);
        assert_eq!(follower.tip(), Some(forked));

        // A stored tip that is on the held tip's chain keeps it.
        let (store, follower, _live) = holding_follower().await;
        let same = Tip {
            height: 1003,
            hash: hash_at(1003, 0),
        };
        store.put(&index_key(&chain, 1003), Bytes::from(hash_at(1003, 0)));
        store.put(&tip_key(&chain), encode_tip(&same));
        store.put(&tip_at_key(&chain), encode_unix_ms(unix_ms_now()));
        assert_eq!(follower.tick().await, Outcome::Follower);
        assert_eq!(follower.tip().unwrap().height, 1006);
    }

    /// A lightwalletd view whose block fetches can be made to fail while its tip answers.
    struct FailingBlocks {
        inner: FakeChainSource,
        fail: AtomicBool,
        fetches: AtomicU64,
    }

    impl ChainSource for FailingBlocks {
        fn latest(&self) -> BoxFuture<'static, Result<Tip>> {
            self.inner.latest()
        }
        fn blocks(&self, start: u64, end: u64) -> BoxFuture<'static, Result<Vec<FetchedBlock>>> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Box::pin(async { anyhow::bail!("block fetch failed") });
            }
            self.inner.blocks(start, end)
        }
    }

    /// A failed fetch of the held tip's chain is not repeated on every probe: only once the
    /// stored tip or its own tip changes.
    #[tokio::test(start_paused = true)]
    async fn a_failed_fetch_of_the_held_chain_is_not_repeated_for_the_same_tips() {
        let store = Arc::new(MemStore::default());
        let live = Arc::new(FakeChain::new(1006));
        let source = Arc::new(FailingBlocks {
            inner: FakeChainSource(live.clone()),
            fail: AtomicBool::new(true),
            fetches: AtomicU64::new(0),
        });
        let follower = ChainFollower::new(
            store.clone(),
            source.clone(),
            None,
            Arc::new(PoolKeys::default()),
            "testnet".to_string(),
        )
        .with_stale_after(Duration::from_millis(1));
        let chain = store.chain_prefix();
        let stored = Tip {
            height: 1000,
            hash: hash_at(1000, 0),
        };
        store.put(&tip_key(&chain), encode_tip(&stored));
        store.put(&tip_at_key(&chain), old_tip_at());
        // Another holder of the lock on every probe: observations only, no takeover.
        let hold = |name: &str| {
            store.locks.lock().unwrap().insert(
                lock_key(&chain),
                (
                    name.to_string(),
                    tokio::time::Instant::now() + Duration::from_secs(3600),
                ),
            );
        };
        let probe = |holder: &'static str| {
            hold(holder);
            let follower = &follower;
            async move {
                for _ in 0..STALE_PROBE_EVERY {
                    if let Outcome::StaleLeader { took_over, .. } = follower.tick().await {
                        assert!(!took_over);
                        return;
                    }
                }
                panic!("no probe found its lightwalletd ahead");
            }
        };
        probe("first").await;
        assert_eq!(source.fetches.load(Ordering::SeqCst), 1);
        assert!(follower.stale.lock().as_ref().unwrap().chain.is_none());
        // The same stored and own tip: not asked again.
        probe("second").await;
        probe("third").await;
        assert_eq!(source.fetches.load(Ordering::SeqCst), 1);
        assert_eq!(follower.tip().unwrap().height, 1006);
        // Its own tip changes: asked again, and the chain is known once the fetch answers.
        live.set_tip(1007);
        source.fail.store(false, Ordering::SeqCst);
        probe("fourth").await;
        assert_eq!(source.fetches.load(Ordering::SeqCst), 2);
        assert!(follower.stale.lock().as_ref().unwrap().chain.is_some());
        probe("fifth").await;
        assert_eq!(
            source.fetches.load(Ordering::SeqCst),
            2,
            "known: not fetched again"
        );
    }
    /// A scheduled probe that is the first read of a stored tip the held tip's chain does not
    /// have drops the held tip without a new observation: the stored tip is served and
    /// nothing is asked of its lightwalletd. A stored tip on that chain keeps the hold.
    #[tokio::test(start_paused = true)]
    async fn a_probe_that_finds_the_stored_tip_off_the_held_chain_drops_the_held_tip() {
        let move_stored_on_the_next_probe = |store: &MemStore, fork: u8| {
            let chain = store.chain_prefix();
            let tip = Tip {
                height: 1003,
                hash: hash_at(1003, fork),
            };
            store.put(&index_key(&chain, 1003), Bytes::from(hash_at(1003, fork)));
            store.put(&tip_key(&chain), encode_tip(&tip));
            // Its time still looks old (a leader whose clock is behind): a probe is due.
            store.put(&tip_at_key(&chain), old_tip_at());
            tip
        };
        // Ticks 0 and 1 are done; 2, 3 and 4 are ordinary reads, 5 is the next probe.
        let (store, follower, live) = holding_follower().await;
        for _ in 2..STALE_PROBE_EVERY {
            assert_eq!(follower.tick().await, Outcome::Follower);
            assert_eq!(follower.tip().unwrap().height, 1006);
        }
        let forked = move_stored_on_the_next_probe(&store, 1);
        let asked = (
            live.latest_calls.load(Ordering::SeqCst),
            live.range_calls.lock().unwrap().len(),
        );
        assert_eq!(follower.tick().await, Outcome::Follower);
        assert_eq!(follower.tip(), Some(forked));
        assert!(follower.stale.lock().is_none(), "no hold after the probe");
        assert_eq!(
            asked,
            (
                live.latest_calls.load(Ordering::SeqCst),
                live.range_calls.lock().unwrap().len()
            ),
            "nothing was asked of its lightwalletd"
        );

        // A stored tip on the held tip's chain: the probe keeps the hold, as before.
        let (store, follower, _live) = holding_follower().await;
        for _ in 2..STALE_PROBE_EVERY {
            assert_eq!(follower.tick().await, Outcome::Follower);
        }
        move_stored_on_the_next_probe(&store, 0);
        assert_eq!(
            follower.tick().await,
            Outcome::StaleLeader {
                from: 1003,
                to: 1006,
                took_over: false
            }
        );
        assert_eq!(follower.tip().unwrap().height, 1006);
        assert!(follower.stale.lock().is_some());
    }

    /// Store the tip `height` (fork 0) with `tip_at` and, with a nonce, the stamp a leader of
    /// this version writes with them (without one: no stamp, as an earlier version writes).
    fn put_record(store: &MemStore, height: u64, tip_at: u64, nonce: Option<u64>) -> Tip {
        let chain = store.chain_prefix();
        let tip = Tip {
            height,
            hash: hash_at(height, 0),
        };
        store.put(&tip_key(&chain), encode_tip(&tip));
        store.put(&tip_at_key(&chain), encode_unix_ms(tip_at));
        match nonce {
            Some(n) => store.put(&tip_stamp_key(&chain), encode_tip_stamp(tip_at, n, &tip)),
            None => {
                store.data.lock().unwrap().remove(&tip_stamp_key(&chain));
            }
        }
        tip
    }

    /// A `tip_at` an hour ahead of this clock (the writer's clock is ahead) and a leader that
    /// stopped moving the tip: the probe comes once the stale bound passed on this process's
    /// own clock since its first read of the record (by the wall clocks the tip never ages
    /// within the hour), and the second probe takes over.
    #[tokio::test(start_paused = true)]
    async fn a_tip_at_ahead_of_this_clock_is_probed_after_the_stale_bound_of_local_time() {
        let store = Arc::new(MemStore::default());
        let _leader = KeysOnlyLeader::new(&store);
        let live = Arc::new(FakeChain::new(1006));
        let f = follower(store.clone(), live, None);
        put_record(&store, 1000, unix_ms_now() + 3_600_000, Some(1));
        let step = Duration::from_secs(5);
        let mut waited = Duration::ZERO;
        let probed_at = loop {
            match f.tick().await {
                Outcome::Follower => {}
                Outcome::StaleLeader {
                    from: 1000,
                    to: 1006,
                    took_over: false,
                } => break waited,
                other => panic!("{other:?} after {waited:?}"),
            }
            assert!(waited <= 2 * DEFAULT_TIP_STALE_AFTER, "never probed");
            tokio::time::advance(step).await;
            waited += step;
        };
        assert!(
            probed_at > DEFAULT_TIP_STALE_AFTER,
            "not before the bound: {probed_at:?}"
        );
        assert!(
            probed_at <= DEFAULT_TIP_STALE_AFTER + step * STALE_PROBE_EVERY as u32,
            "at the first scheduled probe after it: {probed_at:?}"
        );
        assert_eq!(f.tip().unwrap().height, 1006, "its own tip at once");
        for _ in 1..STALE_PROBE_EVERY {
            tokio::time::advance(step).await;
            assert_eq!(f.tick().await, Outcome::Follower);
        }
        tokio::time::advance(step).await;
        assert_eq!(
            f.tick().await,
            Outcome::Advanced {
                from: 1001,
                to: 1006
            }
        );
        assert!(f.is_leader());
    }

    /// A tip that moves on every read is never probed, whatever its `tip_at` says (here ahead
    /// of this clock): every read is another record.
    #[tokio::test(start_paused = true)]
    async fn a_tip_that_keeps_moving_with_a_tip_at_ahead_is_never_probed() {
        let store = Arc::new(MemStore::default());
        let _leader = KeysOnlyLeader::new(&store);
        let f = follower(store.clone(), Arc::new(FakeChain::new(5000)), None);
        let ahead = unix_ms_now() + 3_600_000;
        let reads = 2 * DEFAULT_TIP_STALE_AFTER.as_secs() / 5 + 2 * STALE_PROBE_EVERY;
        for i in 0..reads {
            // Stamped or not (a leader of an earlier version): another tip on every read.
            put_record(&store, 1000 + i, ahead + i, (i % 2 == 0).then_some(i));
            assert_eq!(f.tick().await, Outcome::Follower, "read {i}");
            assert_eq!(f.tip().unwrap().height, 1000 + i);
            tokio::time::advance(Duration::from_secs(5)).await;
        }
    }

    /// Under a leader taken for one that does not confirm (its `tip_seen` is older than
    /// `tip_at`), with a `tip_at` ahead of this clock, the tip is refreshed on every read only
    /// for MAX_CONFIRM_AGE after the first read of the record, then it goes stale (by the wall
    /// clocks alone it stayed fresh for the skew).
    #[tokio::test(start_paused = true)]
    async fn a_leader_that_does_not_confirm_is_followed_for_the_bound_after_the_first_read() {
        let store = Arc::new(MemStore::default());
        let _leader = KeysOnlyLeader::new(&store);
        // Its own lightwalletd is at the stored tip: probes find nothing to take over.
        let f = follower(store.clone(), Arc::new(FakeChain::new(1000)), None);
        put_record(&store, 1000, unix_ms_now() + 3_600_000, Some(7));
        store.put(&tip_seen_key(&store.chain_prefix()), encode_unix_ms(1));
        assert_eq!(f.tick().await, Outcome::Follower);
        let step = Duration::from_secs(5);
        let mut waited = Duration::ZERO;
        while waited < MAX_CONFIRM_AGE {
            tokio::time::advance(step).await;
            waited += step;
            assert_eq!(f.tick().await, Outcome::Follower);
            assert_eq!(f.tip().unwrap().height, 1000, "after {waited:?}");
        }
        while waited <= MAX_CONFIRM_AGE + crate::store::TIP_STALE_AFTER + step {
            tokio::time::advance(step).await;
            waited += step;
            assert_eq!(f.tick().await, Outcome::Follower);
        }
        assert_eq!(f.tip(), None);
    }

    /// A process that read a record with a `tip_at` ahead of its clock as a follower and then
    /// takes the lock counts the confirmation bound from that first read: after more than
    /// MAX_CONFIRM_AGE it does not confirm at all; after less, the age starts that much earlier.
    /// Without an earlier read it counts from the takeover
    /// (`a_tip_at_in_the_future_is_replaced_with_the_first_confirmation`). The first
    /// confirmation replaces the stored `tip_at` by that origin; without a confirmation the
    /// stored value stays.
    #[tokio::test(start_paused = true)]
    async fn a_takeover_counts_the_confirmation_bound_from_the_first_read_as_follower() {
        for (watched, confirmed) in [
            (MAX_CONFIRM_AGE + Duration::from_secs(10), false),
            (Duration::from_secs(400), true),
        ] {
            let store = Arc::new(MemStore::default());
            let _leader = KeysOnlyLeader::new(&store);
            let f = follower(store.clone(), Arc::new(FakeChain::new(500)), None);
            let prefix = store.chain_prefix();
            let future = unix_ms_now() + 3_600_000;
            put_record(&store, 500, future, Some(3));
            assert_eq!(f.tick().await, Outcome::Follower);
            tokio::time::advance(watched).await;
            // The leader's lock lapses; this process leads from its next tick.
            store.locks.lock().unwrap().clear();
            let before = unix_ms_now();
            assert_eq!(f.tick().await, Outcome::Idle);
            assert!(f.is_leader());
            let moved_at = f.moved_at_ms.load(Ordering::Relaxed);
            let watched_ms = watched.as_millis() as u64;
            assert!(
                moved_at + watched_ms >= before && moved_at + watched_ms <= unix_ms_now(),
                "the age counts from the first read: {watched:?}"
            );
            assert_eq!(
                store.get(&tip_seen_key(&prefix)).is_some(),
                confirmed,
                "{watched:?}"
            );
            let stored_at = store
                .get(&tip_at_key(&prefix))
                .and_then(|b| decode_unix_ms(&b));
            if confirmed {
                let seen = store
                    .get(&tip_seen_key(&prefix))
                    .and_then(|b| decode_unix_ms(&b))
                    .unwrap();
                assert_eq!(
                    stored_at,
                    Some(moved_at),
                    "replaced by the origin the age counts from"
                );
                assert!(seen >= moved_at, "never below the stored tip_at");
            } else {
                assert_eq!(stored_at, Some(future), "nothing confirmed: kept as stored");
            }
        }
    }

    /// The local observation: kept over a failed read and over reads of the same record;
    /// started again by another tip, another `tip_at`, another nonce with the same tip and
    /// `tip_at`, and a stamp that is there and no longer vouches (not by the stamp key alone
    /// lost); cleared by a read without an effective
    /// `tip_at`; consumed when the lock is taken (the clearing by a leader's own `tip_at`
    /// write: `a_tip_at_written_as_leader_clears_the_local_observation`).
    #[tokio::test(start_paused = true)]
    async fn the_local_observation_is_kept_started_again_and_cleared() {
        let store = Arc::new(MemStore::default());
        let _leader = KeysOnlyLeader::new(&store);
        let chain = Arc::new(FakeChain::new(1000));
        let f = follower(store.clone(), chain.clone(), None);
        let since = || f.unmoved.lock().as_ref().map(|u| u.since);
        let at = unix_ms_now() + 3_600_000;
        let tip = put_record(&store, 1000, at, Some(1));
        assert_eq!(f.tick().await, Outcome::Follower);
        let first = since().expect("observed");
        tokio::time::advance(Duration::from_secs(10)).await;
        // A failed read in between (the store does not answer): kept.
        store.down.store(true, Ordering::SeqCst);
        assert_eq!(f.tick().await, Outcome::Follower);
        store.down.store(false, Ordering::SeqCst);
        assert_eq!(since(), Some(first));
        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(f.tick().await, Outcome::Follower);
        assert_eq!(since(), Some(first));
        assert_eq!(first.elapsed(), Duration::from_secs(20));
        assert_eq!(
            f.unmoved.lock().as_ref().unwrap().record,
            TipRecord {
                tip: tip.clone(),
                tip_at: at,
                nonce: Some(1)
            }
        );
        let mut last = first;
        let mut started_again = |what: &str| {
            let now = since().expect(what);
            assert_ne!(now, last, "{what}");
            last = now;
        };
        // Another nonce, with the same tip and tip_at.
        tokio::time::advance(Duration::from_secs(1)).await;
        put_record(&store, 1000, at, Some(2));
        f.tick().await;
        started_again("another nonce");
        // Another tip_at.
        tokio::time::advance(Duration::from_secs(1)).await;
        put_record(&store, 1000, at + 1, Some(2));
        f.tick().await;
        started_again("another tip_at");
        // Another tip.
        tokio::time::advance(Duration::from_secs(1)).await;
        put_record(&store, 1001, at + 1, Some(2));
        f.tick().await;
        started_again("another tip");
        // The stamp key alone lost: still the record it vouched for, the count goes on.
        let before_the_loss = since();
        tokio::time::advance(Duration::from_secs(1)).await;
        store
            .data
            .lock()
            .unwrap()
            .remove(&tip_stamp_key(&store.chain_prefix()));
        f.tick().await;
        assert_eq!(since(), before_the_loss, "the stamp key lost");
        assert_eq!(
            f.unmoved.lock().as_ref().unwrap().record.nonce,
            Some(2),
            "the nonce it was vouched with"
        );
        // A stamp that is there and does not vouch (another time): another record.
        tokio::time::advance(Duration::from_secs(1)).await;
        store.put(
            &tip_stamp_key(&store.chain_prefix()),
            stamp_of(at + 5, 2, 1001),
        );
        f.tick().await;
        started_again("a stamp that does not vouch");
        // No tip_at: cleared.
        store
            .data
            .lock()
            .unwrap()
            .remove(&tip_at_key(&store.chain_prefix()));
        f.tick().await;
        assert_eq!(since(), None, "no tip_at");
        // Taking the lock consumes it (a leader's own tip_at write clears it too, see
        // `a_tip_at_written_as_leader_clears_the_local_observation`).
        put_record(&store, 1001, at + 2, Some(3));
        f.tick().await;
        assert!(since().is_some());
        store.locks.lock().unwrap().clear();
        chain.set_tip(1002);
        assert_eq!(
            f.tick().await,
            Outcome::Advanced {
                from: 1002,
                to: 1002
            }
        );
        assert_eq!(
            since(),
            None,
            "consumed at the takeover; nothing is observed while leading"
        );
    }

    fn tip_n(height: u64) -> Tip {
        Tip {
            height,
            hash: hash_at(height, 0),
        }
    }

    fn stamp_of(at: u64, nonce: u64, height: u64) -> Bytes {
        encode_tip_stamp(at, nonce, &tip_n(height))
    }

    fn plain_follower() -> Arc<ChainFollower> {
        follower(
            Arc::new(MemStore::default()),
            Arc::new(FakeChain::new(1)),
            None,
        )
    }

    /// A leader stamps every `tip_at` it writes, in the same fenced script, with that value,
    /// the stored tip and a nonce of its own per write; the pending `tip_at` of a confirmation
    /// too; a plain confirmation writes neither.
    #[tokio::test(start_paused = true)]
    async fn the_leader_stamps_every_tip_at_it_writes() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(500));
        let f = follower(store.clone(), chain.clone(), None);
        let prefix = store.chain_prefix();
        let keys = [
            tip_key(&prefix),
            tip_at_key(&prefix),
            tip_seen_key(&prefix),
            tip_stamp_key(&prefix),
        ];
        let stamp = || decode_tip_stamp(&store.get(&tip_stamp_key(&prefix)).unwrap()).unwrap();
        let tip_at = || {
            store
                .get(&tip_at_key(&prefix))
                .and_then(|b| decode_unix_ms(&b))
                .unwrap()
        };
        let scripts = || std::mem::take(&mut *store.fenced_writes.lock().unwrap());
        let writes = |scripts: &[Vec<String>], key: &String| {
            scripts.iter().filter(|s| s.contains(key)).count()
        };
        assert_eq!(f.tick().await, Outcome::Cold { tip: 500 });
        let written = scripts();
        assert!(written.contains(&keys.to_vec()), "{written:?}");
        assert_eq!(writes(&written[..], &keys[3]), 1);
        let first = stamp();
        assert_eq!(first.tip_at_ms, tip_at());
        assert_eq!(first.tip, store.get(&keys[0]).unwrap().to_vec());
        chain.set_tip(501);
        assert!(matches!(f.tick().await, Outcome::Advanced { .. }));
        let written = scripts();
        assert!(written.contains(&keys.to_vec()), "{written:?}");
        let second = stamp();
        assert_eq!(second.tip_at_ms, tip_at());
        assert_eq!(second.tip, store.get(&keys[0]).unwrap().to_vec());
        assert_ne!(second.nonce, first.nonce, "a nonce per write");
        // A plain confirmation: `tip_seen` only.
        assert_eq!(f.tick().await, Outcome::Idle);
        let written = scripts();
        assert!(written.contains(&vec![keys[2].clone()]), "{written:?}");
        assert_eq!(
            writes(&written[..], &keys[1]) + writes(&written[..], &keys[3]),
            0
        );

        // A tip taken over without `tip_at`: the first confirmation writes it with its stamp.
        let store = Arc::new(MemStore::default());
        let f = follower(store.clone(), Arc::new(FakeChain::new(500)), None);
        store.put(&keys[0], encode_tip(&tip_n(500)));
        assert_eq!(f.tick().await, Outcome::Idle);
        let written = std::mem::take(&mut *store.fenced_writes.lock().unwrap());
        assert_eq!(
            written,
            vec![vec![keys[2].clone(), keys[1].clone(), keys[3].clone()]]
        );
        let stamp = decode_tip_stamp(&store.get(&keys[3]).unwrap()).unwrap();
        assert_eq!(
            Some(stamp.tip_at_ms),
            store.get(&keys[1]).and_then(|b| decode_unix_ms(&b))
        );
        assert_eq!(stamp.tip, encode_tip(&tip_n(500)).to_vec());
    }

    /// Two tips with the same `tip_at`, each stamped by its write: not a leftover (without the
    /// stamps the inference from two reads takes the second for one).
    #[test]
    fn a_stamped_tip_with_the_same_tip_at_is_not_a_leftover() {
        let a = 1_700_000_000_000;
        let f = plain_follower();
        assert_eq!(
            f.effective_tip_at(&tip_n(1), Some(a), Some(&stamp_of(a, 1, 1))),
            (Some(a), Some(1))
        );
        assert_eq!(
            f.effective_tip_at(&tip_n(2), Some(a), Some(&stamp_of(a, 2, 2))),
            (Some(a), Some(2))
        );
        assert!(!f.last_tip_at.lock().as_ref().unwrap().leftover);
        let g = plain_follower();
        assert_eq!(
            g.effective_tip_at(&tip_n(1), Some(a), None),
            (Some(a), None)
        );
        assert_eq!(g.effective_tip_at(&tip_n(2), Some(a), None), (None, None));
    }

    /// A follower that missed the reads in between: (T1, a), then (T3, a) stamped for T3.
    #[test]
    fn a_stamped_tip_after_skipped_reads_is_not_a_leftover() {
        let a = 1_700_000_000_000;
        let f = plain_follower();
        assert_eq!(
            f.effective_tip_at(&tip_n(1), Some(a), None),
            (Some(a), None)
        );
        assert_eq!(
            f.effective_tip_at(&tip_n(3), Some(a), Some(&stamp_of(a, 9, 3))),
            (Some(a), Some(9))
        );
        let g = plain_follower();
        assert_eq!(
            g.effective_tip_at(&tip_n(1), Some(a), None),
            (Some(a), None)
        );
        assert_eq!(g.effective_tip_at(&tip_n(3), Some(a), None), (None, None));
    }

    /// A stamp that names another tip with the same `tip_at` (a leader that writes no
    /// `tip_at` moved the tip after a rollback) is no evidence: the inference from two reads
    /// decides. On the way back to the stamped block, a process that saw the other tip in
    /// between (as a later read, or as its first read) gets that inference's verdict; one that
    /// read nothing in between trusts the time, as the inference does.
    #[test]
    fn a_stamp_of_another_tip_is_no_evidence() {
        let a = 1_700_000_000_000;
        let s1 = stamp_of(a, 1, 1);
        // Saw the stamped tip, then the other one, then the stamped one again.
        let f = plain_follower();
        assert_eq!(
            f.effective_tip_at(&tip_n(1), Some(a), Some(&s1)),
            (Some(a), Some(1))
        );
        assert_eq!(
            f.effective_tip_at(&tip_n(2), Some(a), Some(&s1)),
            (None, None)
        );
        assert_eq!(
            f.effective_tip_at(&tip_n(1), Some(a), Some(&s1)),
            (None, None),
            "a leftover verdict for this tip_at is remembered"
        );
        // First read beside the other tip: trusted (first read), then not on the way back.
        let g = plain_follower();
        assert_eq!(
            g.effective_tip_at(&tip_n(2), Some(a), Some(&s1)),
            (Some(a), None)
        );
        assert_eq!(
            g.effective_tip_at(&tip_n(1), Some(a), Some(&s1)),
            (None, None),
            "the stamp was seen beside another tip"
        );
        // Read nothing in between: an unchanged record, trusted.
        let h = plain_follower();
        for _ in 0..2 {
            assert_eq!(
                h.effective_tip_at(&tip_n(1), Some(a), Some(&s1)),
                (Some(a), Some(1))
            );
        }
    }

    /// A stamp with another time, an absent and an unparsable one, and a stamp without a
    /// stored `tip_at`: the inference from two reads, as without a stamp.
    #[test]
    fn a_stamp_of_another_time_absent_or_unparsable_is_no_evidence() {
        let a = 1_700_000_000_000;
        for second in [
            Some(stamp_of(a + 1, 5, 2)),
            None,
            Some(Bytes::from_static(b"not a stamp")),
            Some(Bytes::from(stamp_of(a, 5, 2).to_ascii_uppercase())),
        ] {
            let f = plain_follower();
            assert_eq!(
                f.effective_tip_at(&tip_n(1), Some(a), None),
                (Some(a), None)
            );
            assert_eq!(
                f.effective_tip_at(&tip_n(2), Some(a), second.as_ref()),
                (None, None),
                "{second:?}"
            );
            assert!(f.last_tip_at.lock().as_ref().unwrap().leftover);
        }
        let f = plain_follower();
        assert_eq!(
            f.effective_tip_at(&tip_n(2), None, Some(&stamp_of(a, 5, 2))),
            (None, None)
        );
    }

    /// The stamp key lost after it vouched (evicted while the tip and `tip_at` stay): the
    /// verdict and the record stand, with the nonce it was vouched with, counted once per loss
    /// (again when the stamp came back and was lost again). A tip
    /// that then moves with the same `tip_at` and no stamp is a leftover, as without stamps.
    #[test]
    fn a_stamp_lost_after_a_match_keeps_the_verdict() {
        let a = 1_700_000_000_000;
        let network = format!("testnet-stamp-lost-{}", std::process::id());
        let f = follower_on(
            Arc::new(MemStore::default()),
            Arc::new(FakeChain::new(1)),
            &network,
        );
        let lost = || crate::health::chain_tip_stamp_lost(&network);
        assert_eq!(
            f.effective_tip_at(&tip_n(1), Some(a), Some(&stamp_of(a, 1, 1))),
            (Some(a), Some(1))
        );
        assert_eq!(lost(), 0);
        for _ in 0..3 {
            assert_eq!(
                f.effective_tip_at(&tip_n(1), Some(a), None),
                (Some(a), Some(1))
            );
            assert_eq!(lost(), 1, "once per loss");
        }
        // The stamp is back, then lost again: another loss.
        let g = follower_on(
            Arc::new(MemStore::default()),
            Arc::new(FakeChain::new(1)),
            &network,
        );
        for losses in 2..=3 {
            assert_eq!(
                g.effective_tip_at(&tip_n(1), Some(a), Some(&stamp_of(a, 1, 1))),
                (Some(a), Some(1))
            );
            assert_eq!(
                g.effective_tip_at(&tip_n(1), Some(a), None),
                (Some(a), Some(1))
            );
            assert_eq!(lost(), losses);
        }
        assert_eq!(f.effective_tip_at(&tip_n(2), Some(a), None), (None, None));
        assert!(f.last_tip_at.lock().as_ref().unwrap().leftover);
        assert_eq!(lost(), 3);
    }

    /// What ends the kept verdict, and what it does not cover.
    #[test]
    fn a_lost_stamp_is_kept_only_for_the_tip_and_time_it_vouched_for() {
        let a = 1_700_000_000_000;
        let vouched_then_lost = || {
            let f = plain_follower();
            assert_eq!(
                f.effective_tip_at(&tip_n(1), Some(a), Some(&stamp_of(a, 1, 1))),
                (Some(a), Some(1))
            );
            assert_eq!(
                f.effective_tip_at(&tip_n(1), Some(a), None),
                (Some(a), Some(1))
            );
            f
        };
        // The stamp is back with another nonce: another record, by the stamp.
        let f = vouched_then_lost();
        assert_eq!(
            f.effective_tip_at(&tip_n(1), Some(a), Some(&stamp_of(a, 2, 1))),
            (Some(a), Some(2))
        );
        // Another `tip_at` under the same tip, no stamp: taken as stored, no nonce; and the
        // first one again is then judged without the stamp it once had.
        let f = vouched_then_lost();
        assert_eq!(
            f.effective_tip_at(&tip_n(1), Some(a + 1), None),
            (Some(a + 1), None)
        );
        assert_eq!(
            f.effective_tip_at(&tip_n(1), Some(a), None),
            (Some(a), None)
        );
        // No `tip_at` any more: nothing to go by.
        let f = vouched_then_lost();
        assert_eq!(f.effective_tip_at(&tip_n(1), None, None), (None, None));
        // A stamp that is there and does not vouch (another time, unparsable) is not a lost
        // key: the inference decides, without a nonce.
        for present in [stamp_of(a + 1, 1, 1), Bytes::from_static(b"not a stamp")] {
            let f = vouched_then_lost();
            assert_eq!(
                f.effective_tip_at(&tip_n(1), Some(a), Some(&present)),
                (Some(a), None),
                "{present:?}"
            );
        }
        // Never vouched: a read without a stamp keeps no nonce, as before.
        let f = plain_follower();
        for _ in 0..2 {
            assert_eq!(
                f.effective_tip_at(&tip_n(1), Some(a), None),
                (Some(a), None)
            );
        }
        // A remembered leftover verdict is not overturned by a missing stamp.
        let f = plain_follower();
        assert_eq!(
            f.effective_tip_at(&tip_n(1), Some(a), None),
            (Some(a), None)
        );
        assert_eq!(f.effective_tip_at(&tip_n(2), Some(a), None), (None, None));
        assert_eq!(f.effective_tip_at(&tip_n(2), Some(a), None), (None, None));
    }

    /// A process that takes the lock after the stamp key was lost counts the confirmation
    /// bound from its first read of the record, as with the stamp still there.
    #[tokio::test(start_paused = true)]
    async fn a_lost_stamp_does_not_restart_the_age_at_a_takeover() {
        let store = Arc::new(MemStore::default());
        let _leader = KeysOnlyLeader::new(&store);
        let f = follower(store.clone(), Arc::new(FakeChain::new(500)), None);
        let at = unix_ms_now() + TIP_AT_MAX_AHEAD.as_millis() as u64 / 2;
        put_record(&store, 500, at, Some(3));
        assert_eq!(f.tick().await, Outcome::Follower);
        tokio::time::advance(Duration::from_secs(200)).await;
        store
            .data
            .lock()
            .unwrap()
            .remove(&tip_stamp_key(&store.chain_prefix()));
        assert_eq!(f.tick().await, Outcome::Follower);
        tokio::time::advance(Duration::from_secs(200)).await;
        store.locks.lock().unwrap().clear();
        let before = unix_ms_now();
        assert_eq!(f.tick().await, Outcome::Idle);
        assert!(f.is_leader());
        let moved_at = f.moved_at_ms.load(Ordering::Relaxed);
        assert!(
            moved_at + 400_000 >= before && moved_at + 400_000 <= unix_ms_now(),
            "the age counts from the first read, before the stamp was lost"
        );
    }

    /// A follower constructed on a network label of its own (for the gauges).
    fn follower_on(store: Arc<MemStore>, chain: Arc<FakeChain>, network: &str) -> ChainFollower {
        ChainFollower::new(
            store,
            Arc::new(FakeChainSource(chain)),
            None,
            Arc::new(PoolKeys::default()),
            network.to_string(),
        )
    }

    /// The takeover's age origin is measured when the lock is taken, not at the read: work
    /// awaited between the read and the takeover (here a slow fetch of the held tip's chain on
    /// the second probe) counts in it.
    #[tokio::test(start_paused = true)]
    async fn the_takeover_counts_the_time_awaited_after_the_read() {
        let store = Arc::new(MemStore::default());
        let _leader = KeysOnlyLeader::new(&store);
        let live = Arc::new(FakeChain::new(1006));
        let f = follower(store.clone(), live.clone(), None);
        put_record(&store, 1000, unix_ms_now() + 3_600_000, Some(1));
        let start = tokio::time::Instant::now();
        // The first probe (tick 35, local age 175 s).
        loop {
            match f.tick().await {
                Outcome::Follower => tokio::time::advance(Duration::from_secs(5)).await,
                Outcome::StaleLeader {
                    took_over: false, ..
                } => break,
                other => panic!("{other:?}"),
            }
        }
        for _ in 1..STALE_PROBE_EVERY {
            tokio::time::advance(Duration::from_secs(1)).await;
            assert_eq!(f.tick().await, Outcome::Follower);
        }
        tokio::time::advance(Duration::from_secs(1)).await;
        // The second probe: its own tip moved on, so the chain of the new tip is fetched, for
        // 8 s, and then its lightwalletd fails: the lock is taken over, and the tick then fails
        // and hands the lock over, leaving the adopted age origin to be read.
        live.set_tip(1007);
        live.blocks_delay_ms.store(8_000, Ordering::SeqCst);
        let read_at = start.elapsed();
        let (outcome, ()) = tokio::join!(f.tick(), async {
            tokio::time::sleep(Duration::from_secs(4)).await;
            live.down.store(true, Ordering::SeqCst);
        });
        assert!(matches!(outcome, Outcome::Error(_)), "{outcome:?}");
        let age_ms = unix_ms_now().saturating_sub(f.moved_at_ms.load(Ordering::Relaxed));
        let awaited = Duration::from_secs(8);
        assert!(
            age_ms >= (read_at + awaited).as_millis() as u64,
            "the age at the takeover includes the awaited fetch: {age_ms} ms, read at {read_at:?}"
        );
        assert!(age_ms < (read_at + awaited).as_millis() as u64 + 5_000);
    }

    /// Taking the lock consumes the observation: after a leadership without a `tip_at` write
    /// and the lock lost again, the next read of the same record starts a new one.
    #[tokio::test(start_paused = true)]
    async fn taking_the_lock_consumes_the_local_observation() {
        let store = Arc::new(MemStore::default());
        let _leader = KeysOnlyLeader::new(&store);
        let f = follower(store.clone(), Arc::new(FakeChain::new(500)), None);
        // Ahead of this clock, within the allowance: kept as stored at the takeover.
        put_record(
            &store,
            500,
            unix_ms_now() + TIP_AT_MAX_AHEAD.as_millis() as u64 / 2,
            Some(4),
        );
        assert_eq!(f.tick().await, Outcome::Follower);
        let first = f.unmoved.lock().as_ref().unwrap().since;
        tokio::time::advance(Duration::from_secs(10)).await;
        store.locks.lock().unwrap().clear();
        // Leads without writing `tip_at` (it continues the stored one; confirmations only).
        assert_eq!(f.tick().await, Outcome::Idle);
        assert!(f.is_leader());
        assert!(f.unmoved.lock().is_none(), "consumed");
        // Another process takes the lock; this one follows the same record again.
        store.locks.lock().unwrap().insert(
            lock_key(&store.chain_prefix()),
            (
                "another-process".to_string(),
                tokio::time::Instant::now() + Duration::from_secs(3600),
            ),
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(f.tick().await, Outcome::Follower);
        let since = f.unmoved.lock().as_ref().unwrap().since;
        assert_ne!(since, first);
        assert_eq!(since.elapsed(), Duration::ZERO, "a new observation");
    }

    /// `ohttp_chain_tip_time_ahead_seconds`: how far the effective stored `tip_at` is ahead at
    /// a follower's read; 0 on a read without a tip (the observation is kept) or without an
    /// effective `tip_at`, and once this process wrote its own `tip_at` as leader.
    #[tokio::test(start_paused = true)]
    async fn the_time_ahead_gauge() {
        let network = format!("testnet-time-ahead-{}", std::process::id());
        let store = Arc::new(MemStore::default());
        let _leader = KeysOnlyLeader::new(&store);
        let chain = Arc::new(FakeChain::new(1000));
        let f = follower_on(store.clone(), chain.clone(), &network);
        let gauge = || crate::health::chain_tip_time_ahead(&network);
        let at = unix_ms_now() + 3_600_000;
        put_record(&store, 1000, at, Some(1));
        assert_eq!(f.tick().await, Outcome::Follower);
        assert!((3_595..=3_600).contains(&gauge()), "{}", gauge());
        // A read without a tip: 0, the observation kept.
        let since = f.unmoved.lock().as_ref().unwrap().since;
        store.down.store(true, Ordering::SeqCst);
        assert_eq!(f.tick().await, Outcome::Follower);
        store.down.store(false, Ordering::SeqCst);
        assert_eq!(gauge(), 0);
        assert_eq!(f.unmoved.lock().as_ref().unwrap().since, since);
        assert_eq!(f.tick().await, Outcome::Follower);
        assert!(gauge() > 0);
        // Without `tip_at`: 0.
        store
            .data
            .lock()
            .unwrap()
            .remove(&tip_at_key(&store.chain_prefix()));
        assert_eq!(f.tick().await, Outcome::Follower);
        assert_eq!(gauge(), 0);
        put_record(&store, 1000, at, Some(1));
        assert_eq!(f.tick().await, Outcome::Follower);
        assert!(gauge() > 0);
        // It leads and writes its own `tip_at`: 0.
        store.locks.lock().unwrap().clear();
        chain.set_tip(1001);
        assert_eq!(
            f.tick().await,
            Outcome::Advanced {
                from: 1001,
                to: 1001
            }
        );
        assert_eq!(gauge(), 0);
    }

    /// A `tip_at` this process writes as leader clears the observation: with a new tip and
    /// with the pending `tip_at` of a confirmation; a plain confirmation (no `tip_at`) leaves
    /// it. Seeded directly: nothing observes while leading.
    #[tokio::test(start_paused = true)]
    async fn a_tip_at_written_as_leader_clears_the_local_observation() {
        let store = Arc::new(MemStore::default());
        let chain = Arc::new(FakeChain::new(500));
        let f = follower(store.clone(), chain.clone(), None);
        assert_eq!(f.tick().await, Outcome::Cold { tip: 500 });
        let seed = || {
            *f.unmoved.lock() = Some(Unmoved {
                record: TipRecord {
                    tip: tip_n(500),
                    tip_at: 1,
                    nonce: None,
                },
                since: tokio::time::Instant::now(),
                warned: false,
            });
        };
        seed();
        chain.set_tip(501);
        assert!(matches!(f.tick().await, Outcome::Advanced { .. }));
        assert!(f.unmoved.lock().is_none(), "a new tip written");
        seed();
        assert_eq!(f.tick().await, Outcome::Idle);
        assert!(f.unmoved.lock().is_some(), "a confirmation without tip_at");
        f.tip_at_pending.store(true, Ordering::Relaxed);
        assert!(f.confirm(&tip_n(501)).await);
        assert!(f.unmoved.lock().is_none(), "the pending tip_at written");
    }

    /// The bound on following a leader that does not confirm is checked when it is used, not
    /// at the read: a read just under MAX_CONFIRM_AGE by the local observation whose tick then
    /// waits for a slow probe of its own lightwalletd past the bound does not refresh the tip.
    #[tokio::test(start_paused = true)]
    async fn awaited_work_after_the_read_counts_in_the_bound_on_an_unconfirming_leader() {
        let store = Arc::new(MemStore::default());
        let _leader = KeysOnlyLeader::new(&store);
        let lwd = Arc::new(FakeChain::new(1000));
        let f = follower(store.clone(), lwd.clone(), None);
        put_record(&store, 1000, unix_ms_now() + 3_600_000, Some(7));
        store.put(&tip_seen_key(&store.chain_prefix()), encode_unix_ms(1));
        let step = Duration::from_secs(5);
        assert_eq!(f.tick().await, Outcome::Follower);
        // Ticks 1 ..= 119, the last one at 595 s: still refreshed.
        for _ in 1..120 {
            tokio::time::advance(step).await;
            assert_eq!(f.tick().await, Outcome::Follower);
        }
        assert_eq!(f.tip().unwrap().height, 1000);
        let refreshed_at = tokio::time::Instant::now();
        // Tick 120 (a scheduled probe) reads at 598 s; the probe takes 5 s.
        tokio::time::advance(Duration::from_secs(3)).await;
        lwd.latest_delay_ms.store(5_000, Ordering::SeqCst);
        assert_eq!(f.tick().await, Outcome::Follower);
        lwd.latest_delay_ms.store(0, Ordering::SeqCst);
        // Not refreshed on that tick: stale once the bound passed since 595 s.
        let stale_at = refreshed_at + crate::store::TIP_STALE_AFTER + Duration::from_secs(1);
        tokio::time::advance(stale_at.saturating_duration_since(tokio::time::Instant::now())).await;
        assert_eq!(f.tip(), None);
    }

    /// The stale-leader probe condition is checked after the index check of a held tip: a read
    /// just under the stale bound by the local observation whose index check is slow probes on
    /// that tick.
    #[tokio::test(start_paused = true)]
    async fn awaited_work_after_the_read_counts_in_the_probe_condition() {
        let store = Arc::new(MemStore::default());
        let _leader = KeysOnlyLeader::new(&store);
        let f = follower(store.clone(), Arc::new(FakeChain::new(1006)), None);
        put_record(&store, 1002, unix_ms_now() + 3_600_000, Some(2));
        store.put(
            &index_key(&store.chain_prefix(), 1000),
            Bytes::from(hash_at(1000, 0)),
        );
        let step = Duration::from_secs(5);
        assert_eq!(f.tick().await, Outcome::Follower);
        // Ticks 1 ..= 29, the last one at 145 s: no probe.
        for _ in 1..30 {
            tokio::time::advance(step).await;
            assert_eq!(f.tick().await, Outcome::Follower);
        }
        // A tip held over 1000 (checked against the index at 1000 on the next read), and that
        // index read takes 5 s. Tick 30 (a scheduled probe) reads at 148 s.
        tokio::time::advance(Duration::from_secs(3)).await;
        *f.stale.lock() = Some(HeldTip {
            stored: tip_n(1000),
            last_stored: tip_n(1000),
            own: tip_n(1006),
            confirmed_at: tokio::time::Instant::now(),
            ahead: false,
            holder: None,
            unresolved: false,
            chain: None,
        });
        *store.slow_mget.lock().unwrap() = Some((":index:".to_string(), Duration::from_secs(5)));
        assert_eq!(
            f.tick().await,
            Outcome::StaleLeader {
                from: 1002,
                to: 1006,
                took_over: false
            }
        );
    }
}

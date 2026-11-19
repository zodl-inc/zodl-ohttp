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

//! The unavailable-store fallback (`write_fallback.rs`, "Unavailable store",
//! `REPLAY_UNAVAILABLE_FALLBACK`) and the check of every WRITE at the fallback store.
//!
//! Stores: `P` (the primary store: the primary-region gateways' own store, the hub of the other
//! origins) and `F` (the fallback store: their peer / standby store). Origins: a primary-region
//! gateway (`failover`, own store `P`, peer `F`), a read origin (`async-reads`, hub `P`, standby
//! store `F`) and a spoke (`async-reads`, own store `F`, hub `P`).
//!
//! Checked: while `P` does not answer (refused or silently dropped) each origin decides at `F`
//! (new and acknowledged = runs, held = replay, anything else = fail-closed); the nonce is
//! written back to `P`; an origin that still reaches `P` refuses a replay of a WRITE admitted at
//! `F`; the same request sent to several origins at once runs at most once; without the setting
//! nothing changes. The stores are in-process fakes; `WAIT` answers whatever the test sets.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use zodl_ohttp_gateway::cache::{
    FallbackHealth, LocalReplayCheck, ReplayPeers, ResponseCache, WriteAdmission, WritePolicy,
    WriteWaitConfig, DEFAULT_REPLAY_WAIT_CONNS, REPLAY_TTL_SECS,
};
use zodl_ohttp_gateway::origin::{ReplayPeerMode, RouteClass};
use zodl_ohttp_gateway::replication::ReplicationConfig;

// ---------------------------------------------------------------------------------------------
// A link that can be lost: a TCP proxy. `lose` kills the open connections (at their next
// byte) and refuses new ones until `restore`; `hang` keeps every connection open and accepts
// new ones but delivers nothing until `restore` (a network that drops packets: TCP delivers
// what was sent once the path is back).

struct Link {
    target: SocketAddr,
    down: AtomicBool,
    hung: AtomicBool,
    /// Incremented by every `lose`; a connection opened before the current value is dead.
    epoch: AtomicU64,
}

impl Link {
    async fn start(target: SocketAddr) -> (Arc<Self>, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let link = Arc::new(Self {
            target,
            down: AtomicBool::new(false),
            hung: AtomicBool::new(false),
            epoch: AtomicU64::new(0),
        });
        let l = link.clone();
        tokio::spawn(async move {
            while let Ok((inbound, _)) = listener.accept().await {
                if l.down.load(Ordering::SeqCst) {
                    drop(inbound);
                    continue;
                }
                let l = l.clone();
                tokio::spawn(async move {
                    let born = l.epoch.load(Ordering::SeqCst);
                    let Ok(upstream) = TcpStream::connect(l.target).await else {
                        return;
                    };
                    let (ri, wi) = inbound.into_split();
                    let (ru, wu) = upstream.into_split();
                    tokio::spawn(pump(ri, wu, l.clone(), born));
                    tokio::spawn(pump(ru, wi, l, born));
                });
            }
        });
        (link, port)
    }

    fn lose(&self) {
        self.down.store(true, Ordering::SeqCst);
        self.epoch.fetch_add(1, Ordering::SeqCst);
    }

    fn hang(&self) {
        self.hung.store(true, Ordering::SeqCst);
    }

    fn restore(&self) {
        self.down.store(false, Ordering::SeqCst);
        self.hung.store(false, Ordering::SeqCst);
    }
}

async fn pump(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    link: Arc<Link>,
    born: u64,
) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        if born < link.epoch.load(Ordering::SeqCst) {
            return;
        }
        while link.hung.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if born < link.epoch.load(Ordering::SeqCst) {
                return;
            }
        }
        if to.write_all(&buf[..n]).await.is_err() {
            return;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// A fake store (always a primary): SET [NX|XX] [EX], WAIT (answers `acks`), ROLE, PING;
// anything else +OK.

struct Store {
    keys: Mutex<HashSet<String>>,
    /// The values of the keys SET with one (GET answers them).
    values: Mutex<HashMap<String, String>>,
    /// The answer to WAIT: the replicas that acknowledged (0 = a primary whose replicas resync).
    acks: AtomicI64,
    /// WAIT gets no answer at all (the node stops answering after the SET).
    wait_hangs: AtomicBool,
    /// The next `SET ... NX` is applied and answered only after this many ms (a reply that
    /// arrives after the client gave up).
    set_nx_delay_once_ms: AtomicU64,
    /// WAIT blocks its connection for its whole timeout before answering, as a real store does
    /// while its replicas do not acknowledge.
    wait_blocks: AtomicBool,
    /// Every connection is a session with a number; the commands of each, in arrival order:
    /// (session, "SET XX <key>" | "WAIT" | other command name).
    sessions: AtomicU64,
    session_log: Mutex<Vec<(u64, String)>>,
    /// The next `SET ... XX` is applied, then its connection closed without an answer.
    close_after_set_xx_once: AtomicBool,
    /// Every WAIT waits this long before answering (a slow store or a long way to it).
    wait_delay_ms: AtomicU64,
    /// Hold each `SET ... XX` reply until the next command of its session has arrived; count
    /// those not followed by a WAIT within a second.
    hold_set_xx_until_wait: AtomicBool,
    set_xx_unpipelined: AtomicU64,
    /// Blocking WAITs in progress, and the most at once.
    waits_inflight: AtomicU64,
    waits_max: AtomicU64,
    /// `ROLE` says replica (a demoted primary that still answers PING).
    replica: AtomicBool,
    /// The next WAIT closes its connection instead of answering (a reset of that one
    /// connection).
    close_on_wait_once: AtomicBool,
    /// `ROLE` is refused by the ACL (`NOPERM`).
    role_noperm: AtomicBool,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            keys: Mutex::default(),
            values: Mutex::default(),
            acks: AtomicI64::new(1),
            wait_hangs: AtomicBool::new(false),
            set_nx_delay_once_ms: AtomicU64::new(0),
            wait_blocks: AtomicBool::new(false),
            sessions: AtomicU64::new(0),
            session_log: Mutex::default(),
            close_after_set_xx_once: AtomicBool::new(false),
            wait_delay_ms: AtomicU64::new(0),
            hold_set_xx_until_wait: AtomicBool::new(false),
            set_xx_unpipelined: AtomicU64::new(0),
            waits_inflight: AtomicU64::new(0),
            waits_max: AtomicU64::new(0),
            replica: AtomicBool::new(false),
            close_on_wait_once: AtomicBool::new(false),
            role_noperm: AtomicBool::new(false),
        }
    }
}

impl Store {
    async fn start() -> (Arc<Self>, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let store = Arc::new(Self::default());
        let s = store.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                tokio::spawn(s.clone().serve(sock));
            }
        });
        (store, addr)
    }

    fn has(&self, key: &str) -> bool {
        self.keys.lock().unwrap().contains(key)
    }

    fn put(&self, key: &str) {
        self.keys.lock().unwrap().insert(key.to_string());
    }

    fn set_acks(&self, n: i64) {
        self.acks.store(n, Ordering::SeqCst);
    }

    /// The commands of `session`, in order.
    fn session_commands(&self, session: u64) -> Vec<String> {
        self.session_log
            .lock()
            .unwrap()
            .iter()
            .filter(|(s, _)| *s == session)
            .map(|(_, c)| c.clone())
            .collect()
    }

    /// The sessions in which `SET XX key` arrived.
    fn set_xx_sessions(&self, key: &str) -> Vec<u64> {
        let entry = format!("SET XX {key}");
        self.session_log
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, c)| *c == entry)
            .map(|(s, _)| *s)
            .collect()
    }

    fn set_value(&self, key: &str, value: &str) {
        self.keys.lock().unwrap().insert(key.to_string());
        self.values
            .lock()
            .unwrap()
            .insert(key.to_string(), value.to_string());
    }

    async fn serve(self: Arc<Self>, sock: TcpStream) {
        let session = self.sessions.fetch_add(1, Ordering::SeqCst);
        let (r, mut w) = sock.into_split();
        let mut r = BufReader::new(r);
        // SELECT n: this connection's keys live under "n/" (n > 0).
        let mut db = String::new();
        // A command read ahead (`hold_set_xx_until_wait`), handled next.
        let mut next: Option<Vec<String>> = None;
        loop {
            let mut args = match next.take() {
                Some(a) => a,
                None => match read_command(&mut r).await {
                    Some(a) => a,
                    None => return,
                },
            };
            let name = args
                .first()
                .map(|a| a.to_ascii_uppercase())
                .unwrap_or_default();
            if name == "SELECT" {
                db = args
                    .get(1)
                    .cloned()
                    .filter(|d| d != "0")
                    .unwrap_or_default();
            }
            if !db.is_empty() && matches!(name.as_str(), "SET" | "GET" | "EXISTS") && args.len() > 1
            {
                args[1] = format!("{db}/{}", args[1]);
            }
            let is = |c: &str| args.first().is_some_and(|a| a.eq_ignore_ascii_case(c));
            let xx = is("SET") && args.iter().skip(3).any(|a| a.eq_ignore_ascii_case("XX"));
            self.session_log.lock().unwrap().push((
                session,
                if xx {
                    format!("SET XX {}", args[1])
                } else {
                    name.clone()
                },
            ));
            if xx && self.close_after_set_xx_once.swap(false, Ordering::SeqCst) {
                let _ = self.answer(&args);
                return;
            }
            // The SET XX reply is held back until the WAIT after it has arrived: a client that
            // sends the two as one pipeline gets both; one that waits for the SET XX reply
            // before sending the WAIT gets it only after a second (counted as unpipelined).
            if xx && self.hold_set_xx_until_wait.load(Ordering::SeqCst) {
                let answer = self.answer(&args);
                match tokio::time::timeout(Duration::from_secs(1), read_command(&mut r)).await {
                    Ok(Some(after)) => {
                        if !after
                            .first()
                            .is_some_and(|a| a.eq_ignore_ascii_case("WAIT"))
                        {
                            self.set_xx_unpipelined.fetch_add(1, Ordering::SeqCst);
                        }
                        next = Some(after);
                    }
                    Ok(None) => return,
                    Err(_) => {
                        self.set_xx_unpipelined.fetch_add(1, Ordering::SeqCst);
                    }
                }
                if w.write_all(answer.as_bytes()).await.is_err() {
                    return;
                }
                continue;
            }
            if is("SET") && args.iter().skip(3).any(|a| a.eq_ignore_ascii_case("NX")) {
                let ms = self.set_nx_delay_once_ms.swap(0, Ordering::SeqCst);
                if ms > 0 {
                    tokio::time::sleep(Duration::from_millis(ms)).await;
                }
            }
            if is("WAIT") && self.close_on_wait_once.swap(false, Ordering::SeqCst) {
                return;
            }
            if is("WAIT") && self.wait_hangs.load(Ordering::SeqCst) {
                // Never answered: every later reply on this connection waits behind it.
                std::future::pending::<()>().await;
            }
            let delay = self.wait_delay_ms.load(Ordering::SeqCst);
            if is("WAIT") && (delay > 0 || self.wait_blocks.load(Ordering::SeqCst)) {
                let ms = if delay > 0 {
                    delay
                } else {
                    args.get(2).and_then(|t| t.parse::<u64>().ok()).unwrap_or(0)
                };
                let now = self.waits_inflight.fetch_add(1, Ordering::SeqCst) + 1;
                self.waits_max.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(ms)).await;
                self.waits_inflight.fetch_sub(1, Ordering::SeqCst);
            }
            if w.write_all(self.answer(&args).as_bytes()).await.is_err() {
                return;
            }
        }
    }

    fn answer(&self, args: &[String]) -> String {
        let cmd = args
            .first()
            .map(|c| c.to_ascii_uppercase())
            .unwrap_or_default();
        match cmd.as_str() {
            "PING" => "+PONG\r\n".into(),
            "ROLE" if self.role_noperm.load(Ordering::SeqCst) => {
                "-NOPERM User default has no permissions to run the 'role' command\r\n".into()
            }
            "ROLE" if self.replica.load(Ordering::SeqCst) => "*1\r\n$5\r\nslave\r\n".into(),
            "ROLE" => "*3\r\n$6\r\nmaster\r\n:0\r\n*0\r\n".into(),
            "SET" => {
                let key = args[1].clone();
                let flags: Vec<String> = args[3..].iter().map(|a| a.to_ascii_uppercase()).collect();
                let mut keys = self.keys.lock().unwrap();
                let exists = keys.contains(&key);
                // SET ... NX GET: the old value when the key exists (nothing set), else set + nil.
                if flags.iter().any(|f| f == "NX") && flags.iter().any(|f| f == "GET") {
                    if exists {
                        let v = self
                            .values
                            .lock()
                            .unwrap()
                            .get(&key)
                            .cloned()
                            .unwrap_or_else(|| "1".to_string());
                        return format!("${}\r\n{v}\r\n", v.len());
                    }
                    self.values
                        .lock()
                        .unwrap()
                        .insert(key.clone(), args[2].clone());
                    keys.insert(key);
                    return "$-1\r\n".into();
                }
                if (flags.iter().any(|f| f == "NX") && exists)
                    || (flags.iter().any(|f| f == "XX") && !exists)
                {
                    return "$-1\r\n".into();
                }
                if let Some(v) = args.get(2) {
                    self.values.lock().unwrap().insert(key.clone(), v.clone());
                }
                keys.insert(key);
                "+OK\r\n".into()
            }
            "WAIT" => format!(":{}\r\n", self.acks.load(Ordering::SeqCst)),
            "GET" => match args
                .get(1)
                .and_then(|k| self.values.lock().unwrap().get(k).cloned())
            {
                Some(v) => format!("${}\r\n{v}\r\n", v.len()),
                None => "$-1\r\n".into(),
            },
            _ => "+OK\r\n".into(),
        }
    }
}

async fn read_command<R: tokio::io::AsyncBufRead + Unpin>(r: &mut R) -> Option<Vec<String>> {
    let mut line = String::new();
    if r.read_line(&mut line).await.ok()? == 0 {
        return None;
    }
    let n: usize = line.trim_end().strip_prefix('*')?.parse().ok()?;
    let mut args = Vec::with_capacity(n);
    for _ in 0..n {
        line.clear();
        r.read_line(&mut line).await.ok()?;
        let len: usize = line.trim_end().strip_prefix('$')?.parse().ok()?;
        let mut data = vec![0u8; len + 2];
        r.read_exact(&mut data).await.ok()?;
        data.truncate(len);
        args.push(String::from_utf8_lossy(&data).into_owned());
    }
    Some(args)
}

// ---------------------------------------------------------------------------------------------
// The origins.

fn url(port: u16) -> String {
    format!("redis://127.0.0.1:{port}")
}

fn addr_url(addr: SocketAddr) -> String {
    format!("redis://{addr}")
}

fn request(tag: &str) -> Vec<u8> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    Sha256::digest(format!("{tag} {nanos} {}", std::process::id())).to_vec()
}

fn key(network: &str, hash: &[u8]) -> String {
    format!("replay:{network}:{}", hex::encode(hash))
}

const WAIT: WriteWaitConfig = WriteWaitConfig {
    replicas: 1,
    timeout_ms: 50,
};

fn replication(network: &str, mode: ReplayPeerMode) -> ReplicationConfig {
    let mut c = ReplicationConfig::new(network, mode, 1000, 1, 250, REPLAY_TTL_SECS, 3);
    c.batch_interval = Duration::from_millis(20);
    c.probe_interval = Duration::from_millis(100);
    c
}

async fn cache_store() -> String {
    let (cache, addr) = Store::start().await;
    std::mem::forget(cache);
    addr_url(addr)
}

/// A primary-region gateway: `failover` mode, its own store `primary` (with the replica wait),
/// the fallback store `fallback` as its peer.
async fn primary_origin(network: &str, primary: &str, fallback: &str, on: bool) -> ResponseCache {
    primary_origin_conns(network, primary, fallback, on, 4).await
}

/// `primary_origin` with `conns` dedicated `WAIT` connections (`REPLAY_WAIT_CONNS`).
async fn primary_origin_conns(
    network: &str,
    primary: &str,
    fallback: &str,
    on: bool,
    conns: usize,
) -> ResponseCache {
    primary_origin_wait(network, primary, fallback, on, conns, WAIT).await
}

/// `primary_origin_conns` with its own local `WAIT` settings.
async fn primary_origin_wait(
    network: &str,
    primary: &str,
    fallback: &str,
    on: bool,
    conns: usize,
    wait: WriteWaitConfig,
) -> ResponseCache {
    zodl_ohttp_gateway::health::init_metrics();
    let c = ResponseCache::connect(
        &cache_store().await,
        Some(primary),
        network.to_string(),
        "lwd.example.com:9067".to_string(),
        250,
        100,
        &HashMap::new(),
    )
    .await
    .unwrap();
    let peers = ReplayPeers::connect(&[fallback.to_string()], network.to_string(), 250, false)
        .await
        .with_mode(ReplayPeerMode::Failover, true)
        .with_wait(Some(WAIT));
    c.with_replay_peers(peers)
        .with_async_replication(replication(network, ReplayPeerMode::Failover))
        .with_write_wait_conns(primary, wait, conns)
        .await
        .unwrap()
        .with_unavailable_fallback(on)
}

/// A read origin: `async-reads`, a local store without the replica wait, WRITEs checked at the
/// hub (the primary store), the fallback store as its standby store.
async fn read_origin(network: &str, hub: &str, fallback: &str, on: bool) -> ResponseCache {
    read_origin_with(network, hub, fallback, on, true).await
}

async fn read_origin_with(
    network: &str,
    hub: &str,
    fallback: &str,
    on: bool,
    fail_closed_writes: bool,
) -> ResponseCache {
    zodl_ohttp_gateway::health::init_metrics();
    let (local, l_addr) = Store::start().await;
    std::mem::forget(local);
    let c = ResponseCache::connect(
        &cache_store().await,
        Some(&addr_url(l_addr)),
        network.to_string(),
        "lwd.example.com:9067".to_string(),
        250,
        100,
        &HashMap::new(),
    )
    .await
    .unwrap();
    let peers = ReplayPeers::connect(&[hub.to_string()], network.to_string(), 250, false)
        .await
        .with_mode(ReplayPeerMode::AsyncReads, fail_closed_writes)
        .with_wait(Some(WAIT));
    let standby =
        ReplayPeers::connect_standby(&[fallback.to_string()], network.to_string(), 250, 1)
            .await
            .with_wait(Some(WAIT));
    let c = c
        .with_replay_peers(peers)
        .with_async_replication(replication(network, ReplayPeerMode::AsyncReads))
        .with_standby_replication(standby, replication(network, ReplayPeerMode::Failover))
        .with_unavailable_fallback(on);
    until("standby store connected", Duration::from_secs(10), || {
        gauge("ohttp_replay_standby_connected", network)
    })
    .await;
    c
}

/// `read_origin`, with its local store at `local` (a link the test can cut).
async fn read_origin_at(network: &str, local: &str, hub: &str, fallback: &str) -> ResponseCache {
    zodl_ohttp_gateway::health::init_metrics();
    let c = ResponseCache::connect(
        &cache_store().await,
        Some(local),
        network.to_string(),
        "lwd.example.com:9067".to_string(),
        250,
        100,
        &HashMap::new(),
    )
    .await
    .unwrap();
    let peers = ReplayPeers::connect(&[hub.to_string()], network.to_string(), 250, false)
        .await
        .with_mode(ReplayPeerMode::AsyncReads, true)
        .with_wait(Some(WAIT));
    let standby =
        ReplayPeers::connect_standby(&[fallback.to_string()], network.to_string(), 250, 1)
            .await
            .with_wait(Some(WAIT));
    c.with_replay_peers(peers)
        .with_async_replication(replication(network, ReplayPeerMode::AsyncReads))
        .with_standby_replication(standby, replication(network, ReplayPeerMode::Failover))
        .with_unavailable_fallback(true)
}

/// The origin whose own store is the fallback store (with the replica wait), WRITEs checked
/// at the hub, refused while the hub is unreachable (`REPLAY_PEER_FAIL_CLOSED_WRITES` default).
async fn spoke_origin(network: &str, own: &str, hub: &str, on: bool) -> ResponseCache {
    spoke_origin_with(network, own, hub, on, true).await
}

/// `spoke_origin`; `fail_closed_writes` false = the standby origin, which admits WRITEs on its
/// own store while the hub is unreachable (`REPLAY_PEER_FAIL_CLOSED_WRITES=0`).
async fn spoke_origin_with(
    network: &str,
    own: &str,
    hub: &str,
    on: bool,
    fail_closed_writes: bool,
) -> ResponseCache {
    zodl_ohttp_gateway::health::init_metrics();
    let c = ResponseCache::connect(
        &cache_store().await,
        Some(own),
        network.to_string(),
        "lwd.example.com:9067".to_string(),
        250,
        100,
        &HashMap::new(),
    )
    .await
    .unwrap();
    let peers = ReplayPeers::connect(&[hub.to_string()], network.to_string(), 250, false)
        .await
        .with_mode(ReplayPeerMode::AsyncReads, fail_closed_writes)
        .with_wait(Some(WAIT));
    c.with_replay_peers(peers)
        .with_async_replication(replication(network, ReplayPeerMode::AsyncReads))
        .with_write_wait(own, WAIT)
        .await
        .unwrap()
        .with_unavailable_fallback(on)
}

/// The gateway's admission (main.rs) of a WRITE route on `REPLAY_ONE_SIDED_WRITE_ROUTES` (and
/// of READs). Ok(true) = runs; Ok(false) = replay; Err = fail-closed.
async fn admit(c: &ResponseCache, hash: &[u8], class: RouteClass) -> anyhow::Result<bool> {
    admit_with(c, hash, class, WritePolicy::ONE_SIDED).await
}

/// `admit` for a WRITE route that is not on `REPLAY_ONE_SIDED_WRITE_ROUTES` (the default).
async fn admit_strict(c: &ResponseCache, hash: &[u8], class: RouteClass) -> anyhow::Result<bool> {
    admit_with(c, hash, class, WritePolicy::BOTH_STORES).await
}

async fn admit_with(
    c: &ResponseCache,
    hash: &[u8],
    class: RouteClass,
    policy: WritePolicy,
) -> anyhow::Result<bool> {
    let local = c.check_replay_detailed(hash).await?;
    if local.verdict() == LocalReplayCheck::Replay {
        return Ok(false);
    }
    let check = if local.verdict() == LocalReplayCheck::Unavailable {
        c.admit_without_local(&local, class, policy).await?
    } else {
        c.replicate_nonce_checked(&local, class, policy).await?
    };
    if check.replay() {
        return Ok(false);
    }
    if class == RouteClass::Write
        && c.write_wait().is_some()
        && !check.local_bypassed()
        && c.confirm_write_nonce(&local, &check).await? == WriteAdmission::Replay
    {
        return Ok(false);
    }
    if class == RouteClass::Write {
        c.replicate_write_to_standby(&local, check);
    }
    Ok(true)
}

fn counter(name: &str, labels: &[(&str, &str)]) -> f64 {
    zodl_ohttp_gateway::health::REGISTRY
        .gather()
        .iter()
        .find(|f| f.get_name() == name)
        .and_then(|f| {
            f.get_metric()
                .iter()
                .find(|m| {
                    labels.iter().all(|(n, v)| {
                        m.get_label()
                            .iter()
                            .any(|l| l.get_name() == *n && l.get_value() == *v)
                    })
                })
                .map(|m| m.get_counter().get_value())
        })
        .unwrap_or(0.0)
}

fn fallback(network: &str, path: &str, result: &str) -> f64 {
    counter(
        "ohttp_replay_write_fallback_total",
        &[("network", network), ("path", path), ("result", result)],
    )
}

fn read_fallback(network: &str, result: &str) -> f64 {
    counter(
        "ohttp_replay_read_fallback_total",
        &[("network", network), ("result", result)],
    )
}

fn gauge(name: &str, network: &str) -> bool {
    zodl_ohttp_gateway::health::REGISTRY
        .gather()
        .iter()
        .find(|f| f.get_name() == name)
        .is_some_and(|f| {
            f.get_metric().iter().any(|m| {
                m.get_label()
                    .iter()
                    .any(|l| l.get_name() == "network" && l.get_value() == network)
                    && m.get_gauge().get_value() == 1.0
            })
        })
}

async fn until(what: &str, max: Duration, f: impl Fn() -> bool) {
    let started = Instant::now();
    while !f() {
        assert!(started.elapsed() < max, "{what}: not within {max:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The primary store `P` and the fallback store `F`; every origin reaches each through a link
/// of its own, so one origin can lose a store while the others keep it.
struct World {
    p: Arc<Store>,
    f: Arc<Store>,
    p_addr: SocketAddr,
    f_addr: SocketAddr,
}

impl World {
    async fn new() -> Self {
        let (p, p_addr) = Store::start().await;
        let (f, f_addr) = Store::start().await;
        Self {
            p,
            f,
            p_addr,
            f_addr,
        }
    }

    /// A link of its own to `P` / `F`.
    async fn to_p(&self) -> (Arc<Link>, String) {
        let (l, port) = Link::start(self.p_addr).await;
        (l, url(port))
    }

    async fn to_f(&self) -> (Arc<Link>, String) {
        let (l, port) = Link::start(self.f_addr).await;
        (l, url(port))
    }
}

#[tokio::test]
async fn primary_origin_decides_at_the_peer_while_its_own_store_is_unreachable() {
    let net = "testnet-ufb-primary";
    let w = World::new().await;
    let (p_link, p_url) = w.to_p().await;
    let (_f_link, f_url) = w.to_f().await;
    let primary = primary_origin(net, &p_url, &f_url, true).await;
    assert_eq!(primary.unavailable_fallback_target(), Some("local"));
    // A read origin that still reaches both stores.
    let (_rp, rp_url) = w.to_p().await;
    let (_rf, rf_url) = w.to_f().await;
    let reader = read_origin(net, &rp_url, &rf_url, true).await;

    // The primary store stops answering (packets dropped): READs and WRITEs are decided at F.
    p_link.hang();
    let write = request("write, own store unreachable");
    assert!(admit(&primary, &write, RouteClass::Write).await.unwrap());
    assert!(
        w.f.has(&key(net, &write)),
        "confirmed at the fallback store"
    );
    assert!(!w.p.has(&key(net, &write)));
    assert_eq!(fallback(net, "local_unavailable", "accepted"), 1.0);
    let read = request("read, own store unreachable");
    assert!(admit(&primary, &read, RouteClass::Read).await.unwrap());
    assert_eq!(read_fallback(net, "accepted"), 1.0);

    // Replays: refused at F by the same gateway, and by another origin that reaches P (where
    // the nonce is not yet): the check of every WRITE at F.
    assert!(!admit(&primary, &write, RouteClass::Write).await.unwrap());
    assert!(!admit(&primary, &read, RouteClass::Read).await.unwrap());
    assert!(!admit(&reader, &write, RouteClass::Write).await.unwrap());
    assert!(fallback(net, "hub_window", "replay") + fallback(net, "hub_check", "replay") >= 1.0);

    // P answers again: the nonce is written back there, and the replay is refused locally.
    p_link.restore();
    until(
        "written back to the primary store",
        Duration::from_secs(20),
        || primary.write_fallback().unwrap().pending_len() == 0,
    )
    .await;
    assert!(w.p.has(&key(net, &write)));
    // Decided at its own store again.
    let before = fallback(net, "local_unavailable", "accepted");
    let after = request("write after the outage");
    assert!(admit(&primary, &after, RouteClass::Write).await.unwrap());
    assert!(w.p.has(&key(net, &after)));
    assert_eq!(fallback(net, "local_unavailable", "accepted"), before);
}

#[tokio::test]
async fn primary_origin_fails_closed_when_no_store_answers() {
    let net = "testnet-ufb-nothing";
    let w = World::new().await;
    let (p_link, p_url) = w.to_p().await;
    let (f_link, f_url) = w.to_f().await;
    let primary = primary_origin(net, &p_url, &f_url, true).await;
    p_link.hang();
    // F without replica: fail-closed.
    w.f.set_acks(0);
    let write = request("fallback store without replica");
    assert!(admit(&primary, &write, RouteClass::Write).await.is_err());
    assert_eq!(fallback(net, "local_unavailable", "unacknowledged"), 1.0);
    // F unreachable too: fail-closed, READs as well.
    w.f.set_acks(1);
    f_link.hang();
    let write = request("no store answers");
    assert!(admit(&primary, &write, RouteClass::Write).await.is_err());
    let read = request("no store answers, read");
    assert!(admit(&primary, &read, RouteClass::Read).await.is_err());
    assert_eq!(fallback(net, "local_unavailable", "accepted"), 0.0);
}

#[tokio::test]
async fn without_the_setting_an_unreachable_store_fails_closed_as_before() {
    let net = "testnet-ufb-off";
    let w = World::new().await;
    let (p_link, p_url) = w.to_p().await;
    let (_f_link, f_url) = w.to_f().await;
    let primary = primary_origin(net, &p_url, &f_url, false).await;
    assert_eq!(primary.unavailable_fallback_target(), None);
    p_link.hang();
    let write = request("off");
    assert!(admit(&primary, &write, RouteClass::Write).await.is_err());
    assert!(!w.f.has(&key(net, &write)));
    // A read origin whose hub is refused fails its WRITEs closed, as before.
    let (rp_link, rp_url) = w.to_p().await;
    let (_rf, rf_url) = w.to_f().await;
    let reader = read_origin(net, &rp_url, &rf_url, false).await;
    rp_link.lose();
    let write = request("off, read origin");
    assert!(admit(&reader, &write, RouteClass::Write).await.is_err());
    assert_eq!(fallback(net, "hub_unavailable", "accepted"), 0.0);
    assert_eq!(fallback(net, "local_unavailable", "accepted"), 0.0);
}

#[tokio::test]
async fn read_origin_confirms_at_the_fallback_store_while_the_hub_is_unreachable() {
    let net = "testnet-ufb-reader";
    let w = World::new().await;
    let (rp_link, rp_url) = w.to_p().await;
    let (_rf, rf_url) = w.to_f().await;
    let reader = read_origin(net, &rp_url, &rf_url, true).await;
    assert_eq!(reader.unavailable_fallback_target(), Some("standby"));
    // A primary-region gateway that still reaches both stores.
    let (_pp, pp_url) = w.to_p().await;
    let (_pf, pf_url) = w.to_f().await;
    let primary = primary_origin(net, &pp_url, &pf_url, true).await;

    // The hub is refused (connections reset), then dropped silently.
    for (i, cut) in ["lose", "hang"].iter().enumerate() {
        if *cut == "lose" {
            rp_link.lose();
        } else {
            rp_link.restore();
            tokio::time::sleep(Duration::from_millis(500)).await;
            rp_link.hang();
        }
        let write = request(&format!("write, hub unreachable ({cut})"));
        assert!(
            admit(&reader, &write, RouteClass::Write).await.unwrap(),
            "{cut}"
        );
        assert!(w.f.has(&key(net, &write)));
        assert_eq!(fallback(net, "hub_unavailable", "accepted"), (i + 1) as f64);
        // Its replay: refused at F by the read origin and by the primary-region gateway, which
        // reaches P (where the nonce is not) and checks every WRITE at F.
        assert!(!admit(&reader, &write, RouteClass::Write).await.unwrap());
        assert!(!admit(&primary, &write, RouteClass::Write).await.unwrap());
        // A WRITE the primary-region gateway admitted: refused at F by the read origin.
        let there = request(&format!("admitted by the primary-region gateway ({cut})"));
        assert!(admit(&primary, &there, RouteClass::Write).await.unwrap());
        assert!(w.f.has(&key(net, &there)), "checked at F synchronously");
        assert!(!admit(&reader, &there, RouteClass::Write).await.unwrap());
        // READs stay local.
        let read = request(&format!("read, hub unreachable ({cut})"));
        assert!(admit(&reader, &read, RouteClass::Read).await.unwrap());
    }
    assert!(fallback(net, "hub_unavailable", "replay") >= 2.0);

    // The fallback store refuses to acknowledge: fail-closed.
    w.f.set_acks(0);
    let write = request("hub unreachable, fallback store without replica");
    assert!(admit(&reader, &write, RouteClass::Write).await.is_err());
    assert_eq!(fallback(net, "hub_unavailable", "unacknowledged"), 1.0);
    w.f.set_acks(1);

    // The hub is back: the nonces admitted at F are written back to it.
    rp_link.restore();
    until("written back to the hub", Duration::from_secs(20), || {
        reader.hub_fallback().unwrap().pending_len() == 0
    })
    .await;
}

#[tokio::test]
async fn spoke_confirms_with_its_own_replicas_while_the_hub_is_unreachable() {
    let net = "testnet-ufb-spoke";
    let w = World::new().await;
    let (hub_link, hub_url) = w.to_p().await;
    let (_own, own_url) = w.to_f().await;
    let spoke = spoke_origin(net, &own_url, &hub_url, true).await;
    assert_eq!(spoke.unavailable_fallback_target(), Some("local_replicas"));
    hub_link.lose();
    let first = request("spoke write, hub unreachable");
    assert!(admit(&spoke, &first, RouteClass::Write).await.unwrap());
    assert_eq!(fallback(net, "hub_unavailable", "accepted"), 1.0);
    assert!(!admit(&spoke, &first, RouteClass::Write).await.unwrap());
    w.f.set_acks(0);
    let write = request("spoke write, hub unreachable, no local replica");
    assert!(admit(&spoke, &write, RouteClass::Write).await.is_err());
    assert_eq!(fallback(net, "hub_unavailable", "unacknowledged"), 1.0);
    w.f.set_acks(1);
    hub_link.restore();
    until("written back to the hub", Duration::from_secs(20), || {
        spoke.hub_fallback().unwrap().pending_len() == 0
    })
    .await;
    assert!(w.p.has(&key(net, &first)));
}

/// The split-brain case: one gateway still reaches the primary store, another does not, and
/// the same request reaches both at once. Exactly one may run it.
#[tokio::test]
async fn a_nonce_never_runs_twice_across_a_partial_partition() {
    let net = "testnet-ufb-split";
    let w = World::new().await;
    let (_pp, pp_url) = w.to_p().await;
    let (_pf, pf_url) = w.to_f().await;
    let healthy = primary_origin(net, &pp_url, &pf_url, true).await;
    let (cut_p, cp_url) = w.to_p().await;
    let (_cf, cf_url) = w.to_f().await;
    let cut = primary_origin(net, &cp_url, &cf_url, true).await;
    let (rp_link, rp_url) = w.to_p().await;
    let (_rf, rf_url) = w.to_f().await;
    let reader = read_origin(net, &rp_url, &rf_url, true).await;
    cut_p.hang();
    rp_link.lose();
    let mut ran = [0usize; 3];
    for i in 0..20 {
        let write = request(&format!("split {i}"));
        let (a, b, c) = tokio::join!(
            admit(&healthy, &write, RouteClass::Write),
            admit(&cut, &write, RouteClass::Write),
            admit(&reader, &write, RouteClass::Write),
        );
        let runs = [a, b, c].map(|r| matches!(r, Ok(true)));
        assert_eq!(
            runs.iter().filter(|r| **r).count(),
            1,
            "request {i} must run at exactly one origin: {runs:?}"
        );
        for (n, r) in ran.iter_mut().zip(runs) {
            *n += usize::from(r);
        }
        // Afterwards every origin refuses it.
        for c in [&healthy, &cut, &reader] {
            assert!(!matches!(
                admit(c, &write, RouteClass::Write).await,
                Ok(true)
            ));
        }
    }
    assert_eq!(ran.iter().sum::<usize>(), 20, "{ran:?}");
}

#[tokio::test]
async fn every_write_of_a_primary_origin_is_checked_at_the_peer() {
    let net = "testnet-ufb-check";
    let w = World::new().await;
    let (_pp, pp_url) = w.to_p().await;
    let (_pf, pf_url) = w.to_f().await;
    let primary = primary_origin(net, &pp_url, &pf_url, false).await;
    primary.write_fallback().unwrap().close_window();
    // Admitted elsewhere at F only (an origin cut from P): refused here, outside any window.
    let elsewhere = request("admitted at F only");
    w.f.put(&key(net, &elsewhere));
    assert!(!admit(&primary, &elsewhere, RouteClass::Write)
        .await
        .unwrap());
    assert_eq!(fallback(net, "check", "replay"), 1.0);
    let write = request("normal write");
    assert!(admit(&primary, &write, RouteClass::Write).await.unwrap());
    assert!(
        w.f.has(&key(net, &write)),
        "at F synchronously, before it runs"
    );
    assert_eq!(fallback(net, "check", "accepted"), 1.0);
}

#[tokio::test]
async fn primary_origin_falls_back_when_its_wait_gets_no_answer() {
    let net = "testnet-ufb-waithang";
    let w = World::new().await;
    let (_p, p_url) = w.to_p().await;
    let (_f, f_url) = w.to_f().await;
    let primary = primary_origin(net, &p_url, &f_url, true).await;
    // The outer SET NX succeeds, the WAIT is never answered.
    w.p.wait_hangs.store(true, Ordering::SeqCst);
    let write = request("own store stops answering after the SET");
    assert!(admit(&primary, &write, RouteClass::Write).await.unwrap());
    assert!(w.p.has(&key(net, &write)) && w.f.has(&key(net, &write)));
    assert_eq!(fallback(net, "local_unavailable", "accepted"), 1.0);
    // Without the setting the same case fails closed, as before.
    let net = "testnet-ufb-waithang-off";
    let w = World::new().await;
    let (_p, p_url) = w.to_p().await;
    let (_f, f_url) = w.to_f().await;
    let primary = primary_origin(net, &p_url, &f_url, false).await;
    w.p.wait_hangs.store(true, Ordering::SeqCst);
    let write = request("own store stops answering after the SET, off");
    assert!(admit(&primary, &write, RouteClass::Write).await.is_err());
    assert_eq!(fallback(net, "local_unavailable", "accepted"), 0.0);
}

#[tokio::test]
async fn primary_origin_fails_closed_at_once_without_a_connected_peer() {
    let net = "testnet-ufb-nopeer";
    let w = World::new().await;
    let (p_link, p_url) = w.to_p().await;
    let (f_link, f_url) = w.to_f().await;
    f_link.lose();
    let primary = primary_origin(net, &p_url, &f_url, true).await;
    p_link.hang();
    let started = Instant::now();
    let read = request("nothing to decide at");
    assert!(admit(&primary, &read, RouteClass::Read).await.is_err());
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(
        read_fallback(net, "accepted") + read_fallback(net, "unavailable"),
        0.0
    );
}

/// An `async-reads` origin that runs WRITEs on its local verdict while its hub is unreachable
/// (`REPLAY_PEER_FAIL_CLOSED_WRITES=0`) still asks the fallback store synchronously.
#[tokio::test]
async fn an_origin_that_tolerates_an_unreachable_hub_still_asks_the_fallback_store() {
    let net = "testnet-ufb-tolerant";
    let w = World::new().await;
    let (hub_link, hub_url) = w.to_p().await;
    let (_rf, rf_url) = w.to_f().await;
    let tolerant = read_origin_with(net, &hub_url, &rf_url, false, false).await;
    assert!(tolerant.checks_writes_at_fallback_store());
    let (_pp, pp_url) = w.to_p().await;
    let (_pf, pf_url) = w.to_f().await;
    let primary = primary_origin(net, &pp_url, &pf_url, false).await;
    assert!(primary.checks_writes_at_fallback_store());
    hub_link.lose();
    let write = request("tolerant origin, hub unreachable");
    assert!(admit(&tolerant, &write, RouteClass::Write).await.unwrap());
    assert!(w.f.has(&key(net, &write)), "asked synchronously");
    assert!(!w.p.has(&key(net, &write)));
    assert!(!admit(&primary, &write, RouteClass::Write).await.unwrap());
    for i in 0..10 {
        let write = request(&format!("tolerant split {i}"));
        let (a, b) = tokio::join!(
            admit(&tolerant, &write, RouteClass::Write),
            admit(&primary, &write, RouteClass::Write),
        );
        let runs = [a, b].iter().filter(|r| matches!(r, Ok(true))).count();
        assert_eq!(runs, 1, "request {i}");
    }
}

#[tokio::test]
async fn primary_origin_stays_healthy_while_the_peer_decides_for_its_unreachable_store() {
    use zodl_ohttp_gateway::health::{
        healthz_ok, is_replay_serving_via_fallback, is_security_redis_connected,
    };
    let net = "testnet-ufb-healthz";
    let w = World::new().await;
    let (p_link, p_url) = w.to_p().await;
    let (f_link, f_url) = w.to_f().await;
    let primary = primary_origin(net, &p_url, &f_url, true).await;
    let healthz = || {
        healthz_ok(
            is_security_redis_connected(net),
            is_replay_serving_via_fallback(net),
            true,
            true,
        )
    };
    primary.ping_redis().await;
    assert!(is_security_redis_connected(net));
    assert!(!is_replay_serving_via_fallback(net));
    assert!(healthz());

    // The own store stops answering, the peer answers: healthy, serving through the peer.
    p_link.hang();
    primary.ping_redis().await;
    assert!(!is_security_redis_connected(net));
    assert!(primary.serves_without_local_store());
    assert!(is_replay_serving_via_fallback(net));
    assert!(healthz());
    let write = request("write while healthy through the peer");
    assert!(admit(&primary, &write, RouteClass::Write).await.unwrap());

    // Neither store answers: unhealthy, and requests fail closed.
    f_link.hang();
    primary.ping_redis().await;
    assert!(!primary.serves_without_local_store());
    assert!(!is_replay_serving_via_fallback(net));
    assert!(!healthz());
    assert!(
        admit(&primary, &request("no store answers"), RouteClass::Write)
            .await
            .is_err()
    );

    // The peer is back: healthy through it again. Each round with the own store hung also waits
    // for that store's checks, so the bound is generous.
    f_link.restore();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        primary.ping_redis().await;
        if is_replay_serving_via_fallback(net) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "not healthy through the peer again"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(healthz());

    // The own store is back: healthy on its own, the fallback gauge clears.
    p_link.restore();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        primary.ping_redis().await;
        if is_security_redis_connected(net) {
            break;
        }
        assert!(Instant::now() < deadline, "own store not back");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!is_replay_serving_via_fallback(net));
    assert!(healthz());
}

#[tokio::test]
async fn without_the_setting_an_unreachable_store_still_fails_healthz() {
    use zodl_ohttp_gateway::health::{
        healthz_ok, is_replay_serving_via_fallback, is_security_redis_connected,
    };
    let net = "testnet-ufb-healthz-off";
    let w = World::new().await;
    let (p_link, p_url) = w.to_p().await;
    let (_f_link, f_url) = w.to_f().await;
    let primary = primary_origin(net, &p_url, &f_url, false).await;
    p_link.hang();
    primary.ping_redis().await;
    assert!(!primary.serves_without_local_store());
    assert!(!is_replay_serving_via_fallback(net));
    assert!(!healthz_ok(
        is_security_redis_connected(net),
        is_replay_serving_via_fallback(net),
        true,
        true
    ));
}

// ---------------------------------------------------------------------------------------------
// An origin whose own store is the fallback store (the spoke, the standby origin) while that
// store gives no verdict: decided at the hub (`admit_without_local`).

#[tokio::test]
async fn spoke_decides_at_the_hub_while_its_own_store_is_unreachable() {
    use zodl_ohttp_gateway::health::{
        healthz_ok, is_replay_serving_via_fallback, is_security_redis_connected,
    };
    let net = "testnet-ufb-spoke-own";
    let w = World::new().await;
    let (_hub, hub_url) = w.to_p().await;
    let (own_link, own_url) = w.to_f().await;
    let spoke = spoke_origin(net, &own_url, &hub_url, true).await;
    assert!(spoke.decides_at_peers_without_local());
    // A primary-region gateway that reaches both stores.
    let (_pp, pp_url) = w.to_p().await;
    let (_pf, pf_url) = w.to_f().await;
    let primary = primary_origin(net, &pp_url, &pf_url, true).await;

    // The own store stops answering (a promotion): healthy, serving through the hub.
    own_link.hang();
    spoke.ping_redis().await;
    assert!(!is_security_redis_connected(net));
    assert!(spoke.serves_without_local_store());
    assert!(is_replay_serving_via_fallback(net));
    assert!(healthz_ok(
        is_security_redis_connected(net),
        is_replay_serving_via_fallback(net),
        true,
        true
    ));

    let read = request("spoke read, own store unreachable");
    assert!(admit(&spoke, &read, RouteClass::Read).await.unwrap());
    assert!(w.p.has(&key(net, &read)), "READ decided at the hub");
    assert_eq!(read_fallback(net, "accepted"), 1.0);
    let write = request("spoke write, own store unreachable");
    assert!(admit(&spoke, &write, RouteClass::Write).await.unwrap());
    assert!(w.p.has(&key(net, &write)), "WRITE decided at the hub");
    assert!(!w.f.has(&key(net, &write)));
    assert_eq!(fallback(net, "local_unavailable", "accepted"), 1.0);

    // Replays: refused at the hub, by the spoke and by a gateway that reaches both stores.
    assert!(!admit(&spoke, &write, RouteClass::Write).await.unwrap());
    assert!(!admit(&spoke, &read, RouteClass::Read).await.unwrap());
    assert!(!admit(&primary, &write, RouteClass::Write).await.unwrap());
    assert_eq!(fallback(net, "local_unavailable", "replay"), 1.0);

    // The hub's replicas do not acknowledge: the WRITE fails closed; READs still run.
    w.p.set_acks(0);
    let short = request("spoke write, own store unreachable, hub without replica");
    assert!(admit(&spoke, &short, RouteClass::Write).await.is_err());
    assert_eq!(fallback(net, "local_unavailable", "unacknowledged"), 1.0);
    assert!(admit(
        &spoke,
        &request("spoke read, hub without replica"),
        RouteClass::Read
    )
    .await
    .unwrap());
    w.p.set_acks(1);

    // The own store answers again: the WRITE nonce is written back there (not the READ), and
    // requests are decided locally again.
    own_link.restore();
    until(
        "written back to the own store",
        Duration::from_secs(20),
        || spoke.write_fallback().unwrap().pending_len() == 0,
    )
    .await;
    assert!(w.f.has(&key(net, &write)));
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        spoke.ping_redis().await;
        if is_security_redis_connected(net) {
            break;
        }
        assert!(Instant::now() < deadline, "own store not back");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!is_replay_serving_via_fallback(net));
    let before = fallback(net, "local_unavailable", "accepted");
    let after = request("spoke write after the promotion");
    assert!(admit(&spoke, &after, RouteClass::Write).await.unwrap());
    assert!(w.f.has(&key(net, &after)) && w.p.has(&key(net, &after)));
    assert_eq!(fallback(net, "local_unavailable", "accepted"), before);
}

#[tokio::test]
async fn spoke_fails_closed_when_neither_its_own_store_nor_the_hub_answers() {
    use zodl_ohttp_gateway::health::is_replay_serving_via_fallback;
    let net = "testnet-ufb-spoke-nothing";
    let w = World::new().await;
    let (hub_link, hub_url) = w.to_p().await;
    let (own_link, own_url) = w.to_f().await;
    for tolerant in [false, true] {
        let spoke = spoke_origin_with(net, &own_url, &hub_url, true, !tolerant).await;
        own_link.hang();
        hub_link.lose();
        spoke.ping_redis().await;
        assert!(!spoke.serves_without_local_store());
        assert!(!is_replay_serving_via_fallback(net));
        for class in [RouteClass::Read, RouteClass::Write] {
            let r = request(&format!("nothing answers {tolerant} {}", class.as_str()));
            assert!(
                admit(&spoke, &r, class).await.is_err(),
                "tolerant {tolerant}"
            );
            assert!(!w.p.has(&key(net, &r)) && !w.f.has(&key(net, &r)));
        }
        own_link.restore();
        hub_link.restore();
    }
}

/// The standby origin (`REPLAY_PEER_FAIL_CLOSED_WRITES=0`) tolerates an unreachable hub, not an
/// unreachable own store: without it the hub decides, with the same rules as for the spoke.
#[tokio::test]
async fn standby_origin_decides_at_the_hub_while_its_own_store_is_unreachable() {
    let net = "testnet-ufb-standby-own";
    let w = World::new().await;
    let (_hub, hub_url) = w.to_p().await;
    let (own_link, own_url) = w.to_f().await;
    let standby = spoke_origin_with(net, &own_url, &hub_url, true, false).await;
    assert!(standby.decides_at_peers_without_local());
    own_link.hang();
    standby.ping_redis().await;
    assert!(standby.serves_without_local_store());
    let write = request("standby write, own store unreachable");
    assert!(admit(&standby, &write, RouteClass::Write).await.unwrap());
    assert!(w.p.has(&key(net, &write)));
    assert!(!admit(&standby, &write, RouteClass::Write).await.unwrap());
    own_link.restore();
    until(
        "written back to the own store",
        Duration::from_secs(20),
        || standby.write_fallback().unwrap().pending_len() == 0,
    )
    .await;
    assert!(w.f.has(&key(net, &write)));
}

/// Only an origin whose own store is the fallback store: a read origin (standby stores, no
/// replica wait), the setting off, or no replica wait at all leave a local store without a
/// verdict failing closed, as before.
#[tokio::test]
async fn other_async_reads_origins_still_fail_closed_without_their_own_store() {
    let net = "testnet-ufb-spoke-unchanged";
    let w = World::new().await;
    let (_rp, rp_url) = w.to_p().await;
    let (_rf, rf_url) = w.to_f().await;
    let (local, local_addr) = Store::start().await;
    let (local_link, local_port) = Link::start(local_addr).await;
    let reader = read_origin_at(net, &url(local_port), &rp_url, &rf_url).await;
    assert!(!reader.decides_at_peers_without_local());
    local_link.hang();
    reader.ping_redis().await;
    assert!(!reader.serves_without_local_store());
    let r = request("read origin, local store unreachable");
    assert!(admit(&reader, &r, RouteClass::Write).await.is_err());
    assert!(!w.p.has(&key(net, &r)) && !w.f.has(&key(net, &r)));
    local_link.restore();
    drop(local);
    let (_hub, hub_url) = w.to_p().await;
    let (own_link, own_url) = w.to_f().await;
    let off = spoke_origin(net, &own_url, &hub_url, false).await;
    assert!(!off.decides_at_peers_without_local());
    own_link.hang();
    off.ping_redis().await;
    assert!(!off.serves_without_local_store());
    let r = request("setting off, own store unreachable");
    assert!(admit(&off, &r, RouteClass::Write).await.is_err());
    assert!(!w.p.has(&key(net, &r)));
}

/// The split-brain case for the spoke: it has lost its own store (the fallback store) and
/// decides at the hub, while the other origins reach both stores; the same request at all of
/// them at once never runs twice.
#[tokio::test]
async fn a_nonce_never_runs_twice_while_the_spoke_decides_at_the_hub() {
    let net = "testnet-ufb-spoke-split";
    let w = World::new().await;
    let (_sp, sp_url) = w.to_p().await;
    let (own_link, own_url) = w.to_f().await;
    let spoke = spoke_origin(net, &own_url, &sp_url, true).await;
    let (_tp, tp_url) = w.to_p().await;
    let (_tf, tf_url) = w.to_f().await;
    let standby = spoke_origin_with(net, &tf_url, &tp_url, true, false).await;
    let (_pp, pp_url) = w.to_p().await;
    let (_pf, pf_url) = w.to_f().await;
    let primary = primary_origin(net, &pp_url, &pf_url, true).await;
    let (_rp, rp_url) = w.to_p().await;
    let (_rf, rf_url) = w.to_f().await;
    let reader = read_origin(net, &rp_url, &rf_url, true).await;
    own_link.hang();
    for i in 0..20 {
        let write = request(&format!("spoke split {i}"));
        let (a, b, c, d) = tokio::join!(
            admit(&spoke, &write, RouteClass::Write),
            admit(&standby, &write, RouteClass::Write),
            admit(&primary, &write, RouteClass::Write),
            admit(&reader, &write, RouteClass::Write),
        );
        // At most once. (Zero is possible here: the same bytes at four origins at once can be
        // held at each store by another of them first; a client sends one request to one origin.)
        let runs = [a, b, c, d].map(|r| matches!(r, Ok(true)));
        assert!(
            runs.iter().filter(|r| **r).count() <= 1,
            "request {i} ran at more than one origin: {runs:?}"
        );
        for c in [&spoke, &standby, &primary, &reader] {
            assert!(!matches!(
                admit(c, &write, RouteClass::Write).await,
                Ok(true)
            ));
        }
    }
}

/// A refused connection (not a silent one): the own store gets the WRITE nonce only through the
/// write-back, never from a buffered request.
#[tokio::test]
async fn spoke_writes_back_a_nonce_its_refusing_store_never_saw() {
    let net = "testnet-ufb-spoke-refused";
    let w = World::new().await;
    let (_hub, hub_url) = w.to_p().await;
    let (own_link, own_url) = w.to_f().await;
    let spoke = spoke_origin(net, &own_url, &hub_url, true).await;
    own_link.lose();
    let write = request("spoke write, own store refusing");
    assert!(admit(&spoke, &write, RouteClass::Write).await.unwrap());
    assert!(w.p.has(&key(net, &write)));
    assert!(!w.f.has(&key(net, &write)));
    assert_eq!(spoke.write_fallback().unwrap().pending_len(), 1);
    assert!(!admit(&spoke, &write, RouteClass::Write).await.unwrap());
    own_link.restore();
    until(
        "written back to the own store",
        Duration::from_secs(30),
        || spoke.write_fallback().unwrap().pending_len() == 0,
    )
    .await;
    assert!(w.f.has(&key(net, &write)));
}

// ---------------------------------------------------------------------------------------------
// Partition tolerance (`REPLAY_ONE_SIDED_WRITE_ROUTES`, write_fallback.rs): a WRITE that is not
// on the list runs only once both the store that decides it and the second store it consults
// took its nonce as new. Every path that would admit it on one store's verdict fails it closed
// (`result="one_sided_refused"`); a WRITE on the list (`admit`) keeps those paths.

fn refused(network: &str, path: &str) -> f64 {
    fallback(network, path, "one_sided_refused")
}

/// A `sync`-mode origin: its own store `own`, the peer `peer` asked on every request, an
/// unreachable peer tolerated (`REPLAY_PEER_FAIL_CLOSED=0`).
async fn sync_origin(network: &str, own: &str, peer: &str) -> ResponseCache {
    zodl_ohttp_gateway::health::init_metrics();
    let c = ResponseCache::connect(
        &cache_store().await,
        Some(own),
        network.to_string(),
        "lwd.example.com:9067".to_string(),
        250,
        100,
        &HashMap::new(),
    )
    .await
    .unwrap();
    let peers = ReplayPeers::connect(&[peer.to_string()], network.to_string(), 250, false)
        .await
        .with_mode(ReplayPeerMode::Sync, true)
        .with_wait(Some(WAIT));
    c.with_replay_peers(peers)
}

/// The inter-region partition: the link between the hub region (store `P`, a `failover`-mode
/// gateway whose peer is `F`) and the standby region (store `F`, the standby origin, which
/// tolerates an unreachable hub) is cut; each side still reaches its own store. The same sealed
/// bytes delivered to both sides (a relay that sends a request twice) used to run at both.
#[tokio::test]
async fn an_inter_region_partition_never_runs_a_write_twice_unless_its_route_is_one_sided() {
    let net = "testnet-onesided-partition";
    let w = World::new().await;
    let (_hp, hp_url) = w.to_p().await;
    let (hf_link, hf_url) = w.to_f().await;
    let hub_side = primary_origin(net, &hp_url, &hf_url, true).await;
    let (sp_link, sp_url) = w.to_p().await;
    let (_sf, sf_url) = w.to_f().await;
    let standby_side = spoke_origin_with(net, &sf_url, &sp_url, true, false).await;

    // Both stores reachable: a WRITE that is not on the list runs on either side.
    for (side, c) in [("hub", &hub_side), ("standby", &standby_side)] {
        let write = request(&format!("both stores reachable at the {side} side"));
        assert!(
            admit_strict(c, &write, RouteClass::Write).await.unwrap(),
            "{side}"
        );
        assert!(w.p.has(&key(net, &write)) && w.f.has(&key(net, &write)));
        assert!(!admit_strict(c, &write, RouteClass::Write).await.unwrap());
    }

    hf_link.lose();
    sp_link.lose();
    for i in 0..5 {
        let write = request(&format!("partition, not on the list {i}"));
        let (a, b) = tokio::join!(
            admit_strict(&hub_side, &write, RouteClass::Write),
            admit_strict(&standby_side, &write, RouteClass::Write),
        );
        assert!(
            a.is_err(),
            "hub side ran it on its own store's verdict: {a:?}"
        );
        assert!(
            b.is_err(),
            "standby side ran it on its own store's verdict: {b:?}"
        );
    }
    assert!(refused(net, "check") + refused(net, "window") >= 5.0);
    assert!(refused(net, "peer_tolerated") >= 5.0);

    // A route on the list keeps the one-sided paths: each side runs it once. Its upstream must
    // refuse the second copy (a transaction the chain already has).
    let write = request("partition, on the list");
    let (a, b) = tokio::join!(
        admit(&hub_side, &write, RouteClass::Write),
        admit(&standby_side, &write, RouteClass::Write),
    );
    assert!(a.unwrap() && b.unwrap());
    // READs are not affected.
    for c in [&hub_side, &standby_side] {
        assert!(
            admit_strict(c, &request("partition, read"), RouteClass::Read)
                .await
                .unwrap()
        );
    }
}

#[tokio::test]
async fn primary_origin_refuses_a_strict_write_its_peer_did_not_confirm() {
    let net = "testnet-onesided-primary-peer";
    let w = World::new().await;
    let (_p, p_url) = w.to_p().await;
    let (f_link, f_url) = w.to_f().await;
    // Also without the unavailable fallback: the check of every WRITE at the peer keeps the
    // local verdict when the peer does not answer.
    let primary = primary_origin(net, &p_url, &f_url, false).await;
    primary.write_fallback().unwrap().close_window();
    f_link.hang();
    let write = request("peer silent, not on the list");
    assert!(admit_strict(&primary, &write, RouteClass::Write)
        .await
        .is_err());
    assert_eq!(refused(net, "check"), 1.0);
    assert_eq!(fallback(net, "check", "unavailable"), 0.0);
    let write = request("peer silent, on the list");
    assert!(admit(&primary, &write, RouteClass::Write).await.unwrap());
    assert_eq!(fallback(net, "check", "unavailable"), 1.0);
}

#[tokio::test]
async fn primary_origin_refuses_a_strict_write_while_its_own_store_is_unreachable() {
    let net = "testnet-onesided-primary-own";
    let w = World::new().await;
    let (p_link, p_url) = w.to_p().await;
    let (_f, f_url) = w.to_f().await;
    let primary = primary_origin(net, &p_url, &f_url, true).await;
    p_link.hang();
    let write = request("own store silent, not on the list");
    assert!(admit_strict(&primary, &write, RouteClass::Write)
        .await
        .is_err());
    assert_eq!(refused(net, "local_unavailable"), 1.0);
    assert!(
        !w.f.has(&key(net, &write)),
        "refused before the peer is asked"
    );
    // READs and listed WRITEs are still decided at the peer.
    assert!(admit_strict(
        &primary,
        &request("own store silent, read"),
        RouteClass::Read
    )
    .await
    .unwrap());
    let listed = request("own store silent, on the list");
    assert!(admit(&primary, &listed, RouteClass::Write).await.unwrap());
    assert_eq!(fallback(net, "local_unavailable", "accepted"), 1.0);
}

/// The short-acknowledgement paths ask both stores (the local `SET NX` took the nonce, the peer
/// took and acknowledged it): they stay open to every WRITE.
#[tokio::test]
async fn a_short_local_acknowledgement_still_admits_a_strict_write() {
    let net = "testnet-onesided-short";
    let w = World::new().await;
    let (_p, p_url) = w.to_p().await;
    let (_f, f_url) = w.to_f().await;
    let primary = primary_origin(net, &p_url, &f_url, true).await;
    w.p.set_acks(0);
    let write = request("local resync, not on the list");
    assert!(admit_strict(&primary, &write, RouteClass::Write)
        .await
        .unwrap());
    assert!(w.p.has(&key(net, &write)) && w.f.has(&key(net, &write)));
    assert_eq!(fallback(net, "short_ack", "accepted"), 1.0);
    w.p.set_acks(1);
}

#[tokio::test]
async fn read_origin_refuses_a_strict_write_without_the_hub() {
    let net = "testnet-onesided-reader-hub";
    let w = World::new().await;
    let (rp_link, rp_url) = w.to_p().await;
    let (_rf, rf_url) = w.to_f().await;
    let reader = read_origin(net, &rp_url, &rf_url, true).await;
    rp_link.lose();
    let write = request("hub unreachable, not on the list");
    assert!(admit_strict(&reader, &write, RouteClass::Write)
        .await
        .is_err());
    assert_eq!(refused(net, "hub_unavailable"), 1.0);
    assert_eq!(fallback(net, "hub_unavailable", "accepted"), 0.0);
    let write = request("hub unreachable, on the list");
    assert!(admit(&reader, &write, RouteClass::Write).await.unwrap());
    assert_eq!(fallback(net, "hub_unavailable", "accepted"), 1.0);
}

#[tokio::test]
async fn read_origin_refuses_a_strict_write_its_standby_store_did_not_confirm() {
    let net = "testnet-onesided-reader-standby";
    let w = World::new().await;
    let (_rp, rp_url) = w.to_p().await;
    let (rf_link, rf_url) = w.to_f().await;
    let reader = read_origin(net, &rp_url, &rf_url, true).await;
    let write = request("standby reachable, not on the list");
    assert!(admit_strict(&reader, &write, RouteClass::Write)
        .await
        .unwrap());
    rf_link.lose();
    let write = request("standby unreachable, not on the list");
    assert!(admit_strict(&reader, &write, RouteClass::Write)
        .await
        .is_err());
    assert!(w.p.has(&key(net, &write)), "the hub took it");
    assert_eq!(refused(net, "hub_check") + refused(net, "hub_window"), 1.0);
    let write = request("standby unreachable, on the list");
    assert!(admit(&reader, &write, RouteClass::Write).await.unwrap());
    assert_eq!(
        fallback(net, "hub_check", "unavailable") + fallback(net, "hub_window", "unavailable"),
        1.0
    );
}

#[tokio::test]
async fn spoke_refuses_a_strict_write_without_the_hub() {
    let net = "testnet-onesided-spoke-hub";
    let w = World::new().await;
    let (hub_link, hub_url) = w.to_p().await;
    let (_own, own_url) = w.to_f().await;
    // The unavailable fallback with the local replicas as target (the hub's verdict is
    // replaced by the own replicas), and the standby origin's tolerance of an unreachable hub.
    for (tolerant, path) in [(false, "hub_unavailable"), (true, "peer_tolerated")] {
        let spoke = spoke_origin_with(net, &own_url, &hub_url, true, !tolerant).await;
        hub_link.lose();
        let write = request(&format!("hub unreachable, not on the list, {path}"));
        assert!(
            admit_strict(&spoke, &write, RouteClass::Write)
                .await
                .is_err(),
            "{path}"
        );
        assert_eq!(refused(net, path), 1.0, "{path}");
        let write = request(&format!("hub unreachable, on the list, {path}"));
        assert!(
            admit(&spoke, &write, RouteClass::Write).await.unwrap(),
            "{path}"
        );
        hub_link.restore();
    }
}

#[tokio::test]
async fn spoke_refuses_a_strict_write_while_its_own_store_is_unreachable() {
    let net = "testnet-onesided-spoke-own";
    let w = World::new().await;
    let (_hub, hub_url) = w.to_p().await;
    let (own_link, own_url) = w.to_f().await;
    let spoke = spoke_origin(net, &own_url, &hub_url, true).await;
    own_link.hang();
    let write = request("own store silent, not on the list");
    assert!(admit_strict(&spoke, &write, RouteClass::Write)
        .await
        .is_err());
    assert_eq!(refused(net, "local_unavailable"), 1.0);
    assert!(!w.p.has(&key(net, &write)));
    let write = request("own store silent, on the list");
    assert!(admit(&spoke, &write, RouteClass::Write).await.unwrap());
    assert!(w.p.has(&key(net, &write)));
}

#[tokio::test]
async fn sync_mode_refuses_a_strict_write_a_peer_did_not_take() {
    let net = "testnet-onesided-sync";
    let w = World::new().await;
    let (_own, own_url) = w.to_p().await;
    let (peer_link, peer_url) = w.to_f().await;
    let origin = sync_origin(net, &own_url, &peer_url).await;
    let write = request("sync, peer reachable");
    assert!(admit_strict(&origin, &write, RouteClass::Write)
        .await
        .unwrap());
    assert!(w.f.has(&key(net, &write)));
    peer_link.lose();
    let write = request("sync, peer unreachable, not on the list");
    assert!(admit_strict(&origin, &write, RouteClass::Write)
        .await
        .is_err());
    assert_eq!(refused(net, "peer_tolerated"), 1.0);
    let write = request("sync, peer unreachable, on the list");
    assert!(admit(&origin, &write, RouteClass::Write).await.unwrap());
    assert_eq!(fallback(net, "peer_tolerated", "accepted"), 1.0);
    // A READ is tolerated as before (REPLAY_PEER_FAIL_CLOSED=0).
    assert!(admit_strict(
        &origin,
        &request("sync, peer unreachable, read"),
        RouteClass::Read
    )
    .await
    .unwrap());
}

/// A WRITE that both stores must take, whose peer `SET NX` answer came after the budget: asked
/// once more (`SET key value NX GET`), it runs when its own first `SET NX` landed and is
/// refused when another request holds the nonce.
#[tokio::test]
async fn a_strict_write_retries_a_peer_set_nx_that_timed_out() {
    let net = "testnet-onesided-retry";
    let w = World::new().await;
    let primary = primary_origin(net, &addr_url(w.p_addr), &addr_url(w.f_addr), false).await;
    w.f.set_nx_delay_once_ms.store(400, Ordering::SeqCst);
    let write = request("peer answers late");
    assert!(admit_strict(&primary, &write, RouteClass::Write)
        .await
        .unwrap());
    assert!(w.f.has(&key(net, &write)));
    assert_eq!(
        counter(
            "ohttp_replay_peer_total",
            &[("network", net), ("result", "timeout_retry")]
        ),
        1.0
    );
    assert_eq!(refused(net, "check") + refused(net, "window"), 0.0);
    // Held at the peer by another request, and the first answer late: a replay.
    let other = request("held at the peer, answer late");
    w.f.put(&key(net, &other));
    w.f.set_nx_delay_once_ms.store(400, Ordering::SeqCst);
    assert!(!admit_strict(&primary, &other, RouteClass::Write)
        .await
        .unwrap());
}

// ---------------------------------------------------------------------------------------------
// The replica wait itself: `SET XX` + `WAIT` as one pipeline, and a small pool of dedicated
// `WAIT` connections per store (`REPLAY_WAIT_CONNS`).

fn saturated(network: &str, store: &str) -> f64 {
    counter(
        "ohttp_replay_wait_saturated_total",
        &[("network", network), ("store", store)],
    )
}

#[tokio::test]
async fn the_local_wait_rewrites_and_waits_in_one_pipeline() {
    let net = "testnet-wait-pipeline";
    let w = World::new().await;
    let primary = primary_origin(net, &addr_url(w.p_addr), &addr_url(w.f_addr), false).await;
    // The store answers a SET XX only once the WAIT of the same session has arrived: sent as two
    // commands, the WAIT would only follow the SET XX reply.
    w.p.hold_set_xx_until_wait.store(true, Ordering::SeqCst);
    // Each SET XX is followed by its WAIT on the same session: a reconnect between the two
    // would have the WAIT count the replicas of another session.
    for i in 0..5 {
        let write = request(&format!("pipelined wait {i}"));
        assert!(admit_strict(&primary, &write, RouteClass::Write)
            .await
            .unwrap());
        let k = key(net, &write);
        let sessions = w.p.set_xx_sessions(&k);
        assert_eq!(sessions.len(), 1, "{sessions:?}");
        let cmds = w.p.session_commands(sessions[0]);
        let at = cmds
            .iter()
            .position(|c| *c == format!("SET XX {k}"))
            .unwrap();
        assert_eq!(
            cmds.get(at + 1).map(String::as_str),
            Some("WAIT"),
            "{cmds:?}"
        );
    }
    // The connection breaks after the SET XX: the retry sends both again, on a new session.
    w.p.close_after_set_xx_once.store(true, Ordering::SeqCst);
    let write = request("pipelined wait, connection lost");
    assert!(admit_strict(&primary, &write, RouteClass::Write)
        .await
        .unwrap());
    let k = key(net, &write);
    let sessions = w.p.set_xx_sessions(&k);
    assert_eq!(sessions.len(), 2, "{sessions:?}");
    assert_ne!(sessions[0], sessions[1]);
    let first = w.p.session_commands(sessions[0]);
    assert_eq!(
        first.last(),
        Some(&format!("SET XX {k}")),
        "closed after it"
    );
    let retry = w.p.session_commands(sessions[1]);
    let at = retry
        .iter()
        .position(|c| *c == format!("SET XX {k}"))
        .unwrap();
    assert_eq!(
        retry.get(at + 1).map(String::as_str),
        Some("WAIT"),
        "{retry:?}"
    );
    assert_eq!(w.p.set_xx_unpipelined.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn concurrent_writes_wait_on_separate_connections() {
    let net = "testnet-wait-pool";
    let w = World::new().await;
    let primary =
        primary_origin_conns(net, &addr_url(w.p_addr), &addr_url(w.f_addr), false, 4).await;
    w.p.wait_blocks.store(true, Ordering::SeqCst);
    let writes: Vec<Vec<u8>> = (0..8).map(|i| request(&format!("pool {i}"))).collect();
    let results = futures_util::future::join_all(
        writes
            .iter()
            .map(|h| admit_strict(&primary, h, RouteClass::Write)),
    )
    .await;
    for r in results {
        assert!(r.unwrap());
    }
    let max = w.p.waits_max.load(Ordering::SeqCst);
    assert!((2..=4).contains(&max), "WAITs in flight at once: {max}");
}

/// While the replicas resync every `WAIT` takes its whole timeout. WRITEs beyond what the
/// connections can wait for are decided as short acknowledgements (the nonce checked on the
/// security connection) instead of running out of time and failing closed.
#[tokio::test]
async fn writes_beyond_the_wait_connections_are_short_acknowledgements() {
    let net = "testnet-wait-saturated";
    let w = World::new().await;
    // One WAIT connection, and the unavailable fallback off: an outer timeout would fail closed.
    let primary =
        primary_origin_conns(net, &addr_url(w.p_addr), &addr_url(w.f_addr), false, 1).await;
    w.p.set_acks(0);
    w.p.wait_blocks.store(true, Ordering::SeqCst);
    // The first short acknowledgement switches the pool to exclusive leasing.
    assert!(
        admit_strict(&primary, &request("resync starts"), RouteClass::Write)
            .await
            .unwrap()
    );
    assert!(primary.local_wait_exclusive());
    let writes: Vec<Vec<u8>> = (0..20).map(|i| request(&format!("resync {i}"))).collect();
    let results = futures_util::future::join_all(
        writes
            .iter()
            .map(|h| admit_strict(&primary, h, RouteClass::Write)),
    )
    .await;
    for (i, r) in results.into_iter().enumerate() {
        assert!(r.unwrap(), "write {i}");
    }
    assert!(saturated(net, "local") >= 1.0);
    assert_eq!(fallback(net, "short_ack", "accepted"), 21.0);
    assert_eq!(fallback(net, "local_unavailable", "accepted"), 0.0);
    for h in &writes {
        assert!(w.f.has(&key(net, h)), "confirmed at the peer");
    }
}

/// The same at a peer: a read origin whose hub resyncs, with one `WAIT` connection to it.
#[tokio::test]
async fn writes_beyond_the_peer_wait_connections_are_short_acknowledgements() {
    let net = "testnet-wait-saturated-peer";
    let w = World::new().await;
    zodl_ohttp_gateway::health::init_metrics();
    let (local, l_addr) = Store::start().await;
    std::mem::forget(local);
    let c = ResponseCache::connect(
        &cache_store().await,
        Some(&addr_url(l_addr)),
        net.to_string(),
        "lwd.example.com:9067".to_string(),
        250,
        100,
        &HashMap::new(),
    )
    .await
    .unwrap();
    let peers = ReplayPeers::connect(&[addr_url(w.p_addr)], net.to_string(), 250, false)
        .await
        .with_mode(ReplayPeerMode::AsyncReads, true)
        .with_wait_conns(Some(WAIT), 1);
    let standby = ReplayPeers::connect_standby(&[addr_url(w.f_addr)], net.to_string(), 250, 1)
        .await
        .with_wait(Some(WAIT));
    let reader = c
        .with_replay_peers(peers)
        .with_async_replication(replication(net, ReplayPeerMode::AsyncReads))
        .with_standby_replication(standby, replication(net, ReplayPeerMode::Failover));
    until("standby store connected", Duration::from_secs(10), || {
        gauge("ohttp_replay_standby_connected", net)
    })
    .await;
    w.p.set_acks(0);
    w.p.wait_blocks.store(true, Ordering::SeqCst);
    // The first short acknowledgement switches the peer's pool to exclusive leasing.
    assert!(
        admit_strict(&reader, &request("hub resync starts"), RouteClass::Write)
            .await
            .unwrap()
    );
    let writes: Vec<Vec<u8>> = (0..10)
        .map(|i| request(&format!("hub resync {i}")))
        .collect();
    let results = futures_util::future::join_all(
        writes
            .iter()
            .map(|h| admit_strict(&reader, h, RouteClass::Write)),
    )
    .await;
    for (i, r) in results.into_iter().enumerate() {
        assert!(r.unwrap(), "write {i}");
    }
    assert!(saturated(net, "peer") >= 1.0);
    assert_eq!(fallback(net, "hub_short_ack", "accepted"), 11.0);
}
// ---------------------------------------------------------------------------------------------
// The adaptive WAIT pool: shared while WAITs are fast, exclusive while they are slow.

/// A link with a fixed one-way delay that keeps pipelining: every chunk is delivered `delay`
/// after it was read, without waiting for the ones before it to be answered.
async fn slow_link(target: SocketAddr, delay: Duration) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((inbound, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(upstream) = TcpStream::connect(target).await else {
                    return;
                };
                let (ri, wi) = inbound.into_split();
                let (ru, wu) = upstream.into_split();
                tokio::spawn(delayed_pump(ri, wu, delay));
                tokio::spawn(delayed_pump(ru, wi, delay));
            });
        }
    });
    port
}

async fn delayed_pump(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    delay: Duration,
) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
    tokio::spawn(async move {
        while let Some((at, data)) = rx.recv().await {
            tokio::time::sleep_until(at).await;
            if to.write_all(&data).await.is_err() {
                return;
            }
        }
    });
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        if tx
            .send((tokio::time::Instant::now() + delay, buf[..n].to_vec()))
            .is_err()
        {
            return;
        }
    }
}

/// 200 WRITEs at once to a local store 100 ms away whose replicas acknowledge at once: shared
/// connections, no WRITE waits for a connection.
#[tokio::test]
async fn fast_waits_share_the_connections_without_a_cap() {
    let net = "testnet-wait-shared";
    let w = World::new().await;
    let port = slow_link(w.p_addr, Duration::from_millis(50)).await;
    let wait = WriteWaitConfig {
        replicas: 1,
        timeout_ms: 200,
    };
    let primary = primary_origin_wait(net, &url(port), &addr_url(w.f_addr), false, 8, wait).await;
    for i in 0..3 {
        assert!(
            admit_strict(&primary, &request(&format!("warm {i}")), RouteClass::Write)
                .await
                .unwrap()
        );
    }
    assert!(!primary.local_wait_exclusive());
    let writes: Vec<Vec<u8>> = (0..200).map(|i| request(&format!("burst {i}"))).collect();
    let started = Instant::now();
    let results = futures_util::future::join_all(
        writes
            .iter()
            .map(|h| admit_strict(&primary, h, RouteClass::Write)),
    )
    .await;
    for (i, r) in results.into_iter().enumerate() {
        assert!(r.unwrap(), "write {i}");
    }
    // Exclusive leasing would admit 8 per round trip: 25 round trips, past every budget.
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(saturated(net, "local"), 0.0);
    assert_eq!(fallback(net, "short_ack", "accepted"), 0.0);
    assert!(!primary.local_wait_exclusive());
    // A WAIT that takes much longer than the round trip: exclusive from now on.
    w.p.wait_delay_ms.store(400, Ordering::SeqCst);
    assert!(
        admit_strict(&primary, &request("slow replicas"), RouteClass::Write)
            .await
            .unwrap()
    );
    assert!(primary.local_wait_exclusive());
}

/// A connection given back just after the last moment a WAIT still fits in the budget is not
/// used for one that would run out of time: that WRITE takes the saturated path instead.
#[tokio::test]
async fn a_lease_freed_too_late_for_a_whole_wait_is_not_taken() {
    let net = "testnet-wait-cutoff";
    let w = World::new().await;
    // Budget 400 + 4 x 250 = 1400 ms; a lease needs 400 + 2 x 250 = 900 ms of it left, so it is
    // taken at most 500 ms after the WRITE started.
    let wait = WriteWaitConfig {
        replicas: 1,
        timeout_ms: 400,
    };
    let primary = primary_origin_wait(
        net,
        &addr_url(w.p_addr),
        &addr_url(w.f_addr),
        false,
        1,
        wait,
    )
    .await;
    w.p.set_acks(0);
    assert!(
        admit_strict(&primary, &request("exclusive"), RouteClass::Write)
            .await
            .unwrap()
    );
    assert!(primary.local_wait_exclusive());
    w.p.set_acks(1);
    // The one connection is busy for 700 ms: freed 200 ms after the other WRITE's cutoff, and
    // 200 ms before the time a lease would leave no room for a WAIT at all: taking it then
    // would run out of time (700 + 700 > 1400).
    w.p.wait_delay_ms.store(700, Ordering::SeqCst);
    let (a, b) = (request("holds the connection"), request("waits for it"));
    let (ra, rb) = tokio::join!(admit_strict(&primary, &a, RouteClass::Write), async {
        tokio::time::sleep(Duration::from_millis(5)).await;
        admit_strict(&primary, &b, RouteClass::Write).await
    });
    assert!(ra.unwrap());
    assert!(
        rb.unwrap(),
        "decided as a short acknowledgement, not timed out"
    );
    assert_eq!(saturated(net, "local"), 1.0);
    assert_eq!(fallback(net, "short_ack", "accepted"), 2.0);
}

/// WRITEs given up by their callers while their WAITs run (cancelled under load) keep their
/// connections until those WAITs are answered.
#[tokio::test]
async fn cancelled_writes_keep_their_wait_connections_until_answered() {
    let net = "testnet-wait-cancel";
    let w = World::new().await;
    let primary =
        primary_origin_conns(net, &addr_url(w.p_addr), &addr_url(w.f_addr), false, 2).await;
    w.p.set_acks(0);
    assert!(
        admit_strict(&primary, &request("exclusive"), RouteClass::Write)
            .await
            .unwrap()
    );
    w.p.set_acks(1);
    w.p.wait_delay_ms.store(300, Ordering::SeqCst);
    let writes: Vec<Vec<u8>> = (0..10)
        .map(|i| request(&format!("cancelled {i}")))
        .collect();
    let cancelled = futures_util::future::join_all(writes.iter().map(|h| {
        tokio::time::timeout(
            Duration::from_millis(100),
            admit_strict(&primary, h, RouteClass::Write),
        )
    }))
    .await;
    assert!(cancelled.iter().all(|r| r.is_err()), "all given up");
    assert_eq!(
        primary.local_wait_idle(),
        0,
        "both still busy with their WAITs"
    );
    until("WAITs answered", Duration::from_secs(5), || {
        primary.local_wait_idle() == 2
    })
    .await;
    let max = w.p.waits_max.load(Ordering::SeqCst);
    assert!(max <= 2, "never more WAITs at once than connections: {max}");
    w.p.wait_delay_ms.store(0, Ordering::SeqCst);
    assert!(admit_strict(&primary, &request("after"), RouteClass::Write)
        .await
        .unwrap());
}

// ---------------------------------------------------------------------------------------------
// Connections and health: the peers' WAIT connections, a security connection pinned to a
// demoted primary, and WRITEs that keep failing while the peers decide.

fn reconnects(network: &str, store: &str, reason: &str) -> f64 {
    counter(
        "ohttp_store_reconnect_total",
        &[("network", network), ("store", store), ("reason", reason)],
    )
}

fn healthz(network: &str) -> bool {
    use zodl_ohttp_gateway::health::{
        healthz_ok, is_replay_serving_via_fallback, is_security_redis_connected,
    };
    healthz_ok(
        is_security_redis_connected(network),
        is_replay_serving_via_fallback(network),
        true,
        true,
    )
}

async fn all_wait_conns_open(c: &ResponseCache, n: usize) {
    until(
        "peer WAIT connections open",
        Duration::from_secs(10),
        || c.replay_peers().unwrap().wait_conns_open() == vec![n],
    )
    .await;
}

#[tokio::test]
async fn a_broken_peer_wait_connection_leaves_the_main_connection() {
    let net = "testnet-conn-wait-io";
    let w = World::new().await;
    let primary = primary_origin(net, &addr_url(w.p_addr), &addr_url(w.f_addr), false).await;
    all_wait_conns_open(&primary, DEFAULT_REPLAY_WAIT_CONNS).await;
    // The local replicas resync: the WRITE is confirmed at the peer, whose first WAIT
    // connection breaks.
    w.p.set_acks(0);
    w.f.close_on_wait_once.store(true, Ordering::SeqCst);
    let write = request("peer WAIT connection reset");
    assert!(admit_strict(&primary, &write, RouteClass::Write)
        .await
        .unwrap());
    assert_eq!(fallback(net, "short_ack", "accepted"), 1.0);
    assert!(primary.replay_peers().unwrap().any_connected());
    assert_eq!(reconnects(net, "replay_peer", "error"), 0.0);
    // The broken one is reopened in the background.
    all_wait_conns_open(&primary, DEFAULT_REPLAY_WAIT_CONNS).await;
}

#[tokio::test]
async fn housekeeping_replaces_peer_wait_connections_reset_while_idle() {
    let net = "testnet-conn-wait-idle";
    let w = World::new().await;
    let (f_link, f_url) = w.to_f().await;
    let primary = primary_origin(net, &addr_url(w.p_addr), &f_url, false).await;
    all_wait_conns_open(&primary, DEFAULT_REPLAY_WAIT_CONNS).await;
    // Every open connection to the peer dies (a middlebox dropped them while idle).
    f_link.lose();
    f_link.restore();
    // Housekeeping finds and replaces them without any WRITE.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        primary.ping_redis().await;
        if primary.replay_peers().unwrap().all_answering() {
            break;
        }
        assert!(Instant::now() < deadline, "peer not answering again");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    all_wait_conns_open(&primary, DEFAULT_REPLAY_WAIT_CONNS).await;
    // The next WRITE through the peer's WAIT needs no retry.
    w.p.set_acks(0);
    let write = request("after housekeeping");
    assert!(admit_strict(&primary, &write, RouteClass::Write)
        .await
        .unwrap());
    assert_eq!(
        counter(
            "ohttp_replay_peer_total",
            &[("network", net), ("result", "wait_retry")]
        ),
        0.0
    );
}

#[tokio::test]
async fn housekeeping_leaves_a_peer_that_became_a_replica() {
    let net = "testnet-conn-peer-role";
    let w = World::new().await;
    let primary = primary_origin(net, &addr_url(w.p_addr), &addr_url(w.f_addr), false).await;
    primary.ping_redis().await;
    assert!(primary.replay_peers().unwrap().any_connected());
    // The peer's endpoint still reaches the demoted node, which answers PING.
    w.f.replica.store(true, Ordering::SeqCst);
    primary.ping_redis().await;
    assert_eq!(reconnects(net, "replay_peer", "role"), 1.0);
    assert!(!primary.replay_peers().unwrap().any_connected());
    w.f.replica.store(false, Ordering::SeqCst);
    until("peer reconnected", Duration::from_secs(10), || {
        primary.replay_peers().unwrap().any_connected()
    })
    .await;
}

#[tokio::test]
async fn healthz_fails_while_the_security_connection_waits_for_a_primary() {
    use zodl_ohttp_gateway::health::is_security_redis_connected;
    let net = "testnet-conn-demoted";
    let w = World::new().await;
    let primary = primary_origin(net, &addr_url(w.p_addr), &addr_url(w.f_addr), false).await;
    primary.ping_redis().await;
    assert!(is_security_redis_connected(net) && healthz(net));
    // Demoted: PING still answers, ROLE says replica, and no node of the endpoint is a primary.
    w.p.replica.store(true, Ordering::SeqCst);
    // At most one ROLE check per second and connection.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    primary.ping_redis().await;
    assert!(!is_security_redis_connected(net));
    assert!(!healthz(net));
    // A primary again: the reconnect succeeds and the store counts as up.
    w.p.replica.store(false, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        primary.ping_redis().await;
        if is_security_redis_connected(net) {
            break;
        }
        assert!(Instant::now() < deadline, "security store not back");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(healthz(net));
}

#[tokio::test]
async fn healthz_fails_when_every_write_decided_at_the_peer_fails() {
    use zodl_ohttp_gateway::health::is_replay_serving_via_fallback;
    let net = "testnet-conn-fallback-health";
    let w = World::new().await;
    let (p_link, p_url) = w.to_p().await;
    let primary = primary_origin(net, &p_url, &addr_url(w.f_addr), true)
        .await
        .with_fallback_health(FallbackHealth::new(3, Duration::from_secs(60)));
    p_link.hang();
    primary.ping_redis().await;
    assert!(is_replay_serving_via_fallback(net) && healthz(net));
    // The peer answers its PINGs but cannot acknowledge on its replicas: every WRITE decided
    // there fails closed.
    w.f.set_acks(0);
    for i in 0..3 {
        let write = request(&format!("peer without replica {i}"));
        assert!(admit(&primary, &write, RouteClass::Write).await.is_err());
    }
    assert_eq!(fallback(net, "local_unavailable", "unacknowledged"), 3.0);
    assert!(primary.fallback_writes_failing());
    primary.ping_redis().await;
    assert!(!is_replay_serving_via_fallback(net));
    assert!(!healthz(net));
    // READs that still arrive are decided at the peer.
    assert!(
        admit(&primary, &request("read while unhealthy"), RouteClass::Read)
            .await
            .unwrap()
    );
    // The peer acknowledges again: the next WRITE runs and the gateway is healthy again.
    w.f.set_acks(1);
    assert!(admit(&primary, &request("peer back"), RouteClass::Write)
        .await
        .unwrap());
    assert!(!primary.fallback_writes_failing());
    primary.ping_redis().await;
    assert!(is_replay_serving_via_fallback(net) && healthz(net));
}

/// A withdrawn gateway is trusted again as soon as a request's local check gets an answer, not
/// only from the next housekeeping round on.
#[tokio::test]
async fn a_local_answer_ends_the_withdrawal_between_housekeeping_rounds() {
    let net = "testnet-conn-fallback-recovery";
    let w = World::new().await;
    let (p_link, p_url) = w.to_p().await;
    let primary = primary_origin(net, &p_url, &addr_url(w.f_addr), true)
        .await
        .with_fallback_health(FallbackHealth::new(2, Duration::from_secs(60)));
    p_link.hang();
    primary.ping_redis().await;
    w.f.set_acks(0);
    for i in 0..2 {
        let write = request(&format!("recovery peer without replica {i}"));
        assert!(admit(&primary, &write, RouteClass::Write).await.is_err());
    }
    assert!(primary.fallback_writes_failing());
    // The security store answers again; no housekeeping round runs from here on.
    p_link.restore();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut i = 0;
    while primary.fallback_writes_failing() {
        assert!(Instant::now() < deadline, "still withdrawn");
        i += 1;
        let _ = primary
            .check_replay_detailed(&request(&format!("recovery read {i}")))
            .await;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[test]
fn fallback_health_withdraws_after_consecutive_failures_until_a_recovery() {
    let h = FallbackHealth::new(2, Duration::from_millis(100));
    assert!(!h.failing());
    h.failed();
    assert!(!h.failing());
    h.failed();
    assert!(h.failing());
    // Withdrawn stays withdrawn: no return on a timer alone.
    std::thread::sleep(Duration::from_millis(250));
    assert!(h.failing());
    // A WRITE through the fallback ran: back.
    h.accepted();
    assert!(!h.failing());
    assert_eq!(h.consecutive_failures(), 0);
    // Failures further apart than the window do not add up.
    h.failed();
    std::thread::sleep(Duration::from_millis(250));
    h.failed();
    assert_eq!(h.consecutive_failures(), 1);
    assert!(!h.failing());
    h.failed();
    assert!(h.failing());
    // The local store answers again: back.
    h.local_answered();
    assert!(!h.failing());
    let off = FallbackHealth::new(0, Duration::from_secs(60));
    for _ in 0..100 {
        off.failed();
    }
    assert!(!off.failing());
    assert!(FallbackHealth::parse(Some("x"), None).is_err());
    assert!(FallbackHealth::parse(None, Some("0")).is_err());
    assert!(FallbackHealth::parse(Some("0"), Some("10")).is_ok());
}

#[test]
fn fallback_health_is_consistent_under_concurrent_updates() {
    let h = Arc::new(FallbackHealth::new(1000, Duration::from_secs(60)));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let h = h.clone();
            std::thread::spawn(move || {
                for _ in 0..500 {
                    h.failed();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(h.consecutive_failures(), 4000, "no update lost");
    assert!(h.failing());
    // Failures and recoveries racing: whatever the order, the state is one of the two.
    let h = Arc::new(FallbackHealth::new(3, Duration::from_secs(60)));
    let threads: Vec<_> = (0..8)
        .map(|i| {
            let h = h.clone();
            std::thread::spawn(move || {
                for _ in 0..500 {
                    if i % 2 == 0 {
                        h.failed();
                    } else {
                        h.accepted();
                    }
                    let (failing, n) = (h.failing(), h.consecutive_failures());
                    assert!(n <= 4000);
                    let _ = failing;
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    h.accepted();
    assert!(!h.failing() && h.consecutive_failures() == 0);
}

// ---------------------------------------------------------------------------------------------
// Startup: /healthz waits for the stores both-store admission needs.

async fn reader_with_standby_at(network: &str, hub: &str, standby: &str) -> ResponseCache {
    zodl_ohttp_gateway::health::init_metrics();
    let c = ResponseCache::connect(
        &cache_store().await,
        Some(&cache_store().await),
        network.to_string(),
        "lwd.example.com:9067".to_string(),
        250,
        100,
        &HashMap::new(),
    )
    .await
    .unwrap();
    let peers = ReplayPeers::connect(&[hub.to_string()], network.to_string(), 250, false)
        .await
        .with_mode(ReplayPeerMode::AsyncReads, true)
        .with_wait(Some(WAIT));
    let standby = ReplayPeers::connect_standby(&[standby.to_string()], network.to_string(), 250, 1)
        .await
        .with_wait(Some(WAIT));
    c.with_replay_peers(peers)
        .with_async_replication(replication(network, ReplayPeerMode::AsyncReads))
        .with_standby_replication(standby, replication(network, ReplayPeerMode::Failover))
}

#[tokio::test]
async fn a_read_origin_reports_ready_once_its_standby_store_is_connected() {
    use zodl_ohttp_gateway::health::is_replay_stores_ready;
    let net = "testnet-ready-standby";
    let w = World::new().await;
    let (f_link, f_url) = w.to_f().await;
    f_link.lose();
    let reader = reader_with_standby_at(net, &addr_url(w.p_addr), &f_url).await;
    let gate = zodl_ohttp_gateway::cache::spawn_replay_stores_gate(
        reader.clone(),
        Duration::from_secs(10),
    );
    assert!(
        !is_replay_stores_ready(net),
        "not ready without the standby store"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!is_replay_stores_ready(net));
    f_link.restore();
    assert!(
        gate.await.unwrap(),
        "every store connected within the bound"
    );
    assert!(is_replay_stores_ready(net));
    // A WRITE that both stores must take runs at once.
    assert!(
        admit_strict(&reader, &request("after startup"), RouteClass::Write)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_read_origin_reports_ready_after_the_bound_without_its_standby_store() {
    use zodl_ohttp_gateway::health::is_replay_stores_ready;
    let net = "testnet-ready-bound";
    let w = World::new().await;
    let (f_link, f_url) = w.to_f().await;
    f_link.lose();
    let reader = reader_with_standby_at(net, &addr_url(w.p_addr), &f_url).await;
    let started = Instant::now();
    let gate = zodl_ohttp_gateway::cache::spawn_replay_stores_gate(
        reader.clone(),
        Duration::from_millis(500),
    );
    assert!(!is_replay_stores_ready(net));
    assert!(!gate.await.unwrap(), "the standby store never connected");
    assert!(started.elapsed() >= Duration::from_millis(450));
    assert!(is_replay_stores_ready(net), "ready after the bound");
}

/// Refusals of WRITEs that are not on `REPLAY_ONE_SIDED_WRITE_ROUTES` withdraw a gateway only
/// when its own store gave no verdict, not when a peer did not answer.
#[tokio::test]
async fn one_sided_refusals_count_toward_withdrawal_only_for_the_local_store() {
    let net = "testnet-conn-refusal-health";
    let w = World::new().await;
    let (p_link, p_url) = w.to_p().await;
    let (f_link, f_url) = w.to_f().await;
    let primary = primary_origin(net, &p_url, &f_url, true)
        .await
        .with_fallback_health(FallbackHealth::new(3, Duration::from_secs(60)));
    f_link.hang();
    for i in 0..5 {
        let write = request(&format!("peer silent {i}"));
        assert!(admit_strict(&primary, &write, RouteClass::Write)
            .await
            .is_err());
    }
    assert!(
        !primary.fallback_writes_failing(),
        "a peer's silence does not count"
    );
    f_link.restore();
    p_link.hang();
    for i in 0..3 {
        let write = request(&format!("own store silent {i}"));
        assert!(admit_strict(&primary, &write, RouteClass::Write)
            .await
            .is_err());
    }
    assert!(primary.fallback_writes_failing());
}

/// Several peers that stop answering are checked at once: one housekeeping round costs about
/// one peer's budget, not one per peer.
#[tokio::test]
async fn housekeeping_checks_hanging_peers_concurrently() {
    let net = "testnet-conn-hanging-peers";
    let w = World::new().await;
    zodl_ohttp_gateway::health::init_metrics();
    let mut links = Vec::new();
    let mut urls = Vec::new();
    for _ in 0..6 {
        let (l, u) = w.to_f().await;
        links.push(l);
        urls.push(u);
    }
    let c = ResponseCache::connect(
        &cache_store().await,
        Some(&addr_url(w.p_addr)),
        net.to_string(),
        "lwd.example.com:9067".to_string(),
        250,
        100,
        &HashMap::new(),
    )
    .await
    .unwrap();
    let peers = ReplayPeers::connect(&urls, net.to_string(), 250, false)
        .await
        .with_mode(ReplayPeerMode::Failover, true)
        .with_wait(Some(WAIT));
    let c = c.with_replay_peers(peers);
    until(
        "peer WAIT connections open",
        Duration::from_secs(10),
        || {
            c.replay_peers()
                .unwrap()
                .wait_conns_open()
                .iter()
                .all(|n| *n > 0)
        },
    )
    .await;
    c.ping_redis().await;
    assert!(c.replay_peers().unwrap().all_answering());
    for l in &links {
        l.hang();
    }
    let started = Instant::now();
    c.ping_redis().await;
    let took = started.elapsed();
    assert!(!c.replay_peers().unwrap().any_answering());
    // One peer: a PING (250 ms) and its WAIT connections' PINGs (300 ms). Six in a row: 3.3 s.
    assert!(took < Duration::from_millis(2200), "{took:?}");
    assert!(zodl_ohttp_gateway::health::is_security_redis_connected(net));
}

// ---------------------------------------------------------------------------------------------
// The asynchronous hand-off to a peer that did not take a WRITE's nonce (tolerated) follows the
// final admission: a WRITE that the local replica wait then fails closed never ran, and its
// nonce must not reach the peer.

#[tokio::test]
async fn a_tolerated_peer_gets_only_the_nonces_of_writes_that_ran() {
    let net = "testnet-handoff-ran";
    let w = World::new().await;
    let (hub_link, hub_url) = w.to_p().await;
    let (_own, own_url) = w.to_f().await;
    // The standby origin: own store with the replica wait, tolerates an unreachable hub.
    let standby = spoke_origin_with(net, &own_url, &hub_url, false, false).await;
    hub_link.lose();
    // The own replicas do not acknowledge: the WRITE fails closed after the hub check.
    w.f.set_acks(0);
    let refused = request("hub unreachable, own replicas short");
    assert!(admit(&standby, &refused, RouteClass::Write).await.is_err());
    // The own replicas acknowledge: the WRITE runs.
    w.f.set_acks(1);
    let ran = request("hub unreachable, own replicas acknowledge");
    assert!(admit(&standby, &ran, RouteClass::Write).await.unwrap());
    hub_link.restore();
    until(
        "the WRITE that ran reached the hub",
        Duration::from_secs(20),
        || w.p.has(&key(net, &ran)),
    )
    .await;
    // Batches go out every 20 ms in this test: the refused one would be there by now.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !w.p.has(&key(net, &refused)),
        "the nonce of a WRITE that failed closed was handed to the hub"
    );
}

/// More than 64 peers: the hand-off to the one that did not take the nonce still waits for the
/// WRITE's final admission.
#[tokio::test]
async fn the_hand_off_follows_the_admission_with_65_peers() {
    let net = "testnet-handoff-65";
    let w = World::new().await;
    zodl_ohttp_gateway::health::init_metrics();
    // 65 hub stores: databases 0..=64 of one fake store; the last one behind a link.
    let (link, link_url) = w.to_p().await;
    let mut urls: Vec<String> = (0..64)
        .map(|i| format!("{}/{i}", addr_url(w.p_addr)))
        .collect();
    urls.push(format!("{link_url}/64"));
    let own = addr_url(w.f_addr);
    let c = ResponseCache::connect(
        &cache_store().await,
        Some(&own),
        net.to_string(),
        "lwd.example.com:9067".to_string(),
        250,
        100,
        &HashMap::new(),
    )
    .await
    .unwrap();
    let peers = ReplayPeers::connect(&urls, net.to_string(), 250, false)
        .await
        .with_mode(ReplayPeerMode::AsyncReads, false)
        .with_wait_conns(Some(WAIT), 1);
    let standby = c
        .with_replay_peers(peers)
        .with_async_replication(replication(net, ReplayPeerMode::AsyncReads))
        .with_write_wait_conns(&own, WAIT, 1)
        .await
        .unwrap();
    link.lose();
    w.f.set_acks(0);
    let refused = request("65 peers, own replicas short");
    assert!(admit(&standby, &refused, RouteClass::Write).await.is_err());
    w.f.set_acks(1);
    let ran = request("65 peers, own replicas acknowledge");
    assert!(admit(&standby, &ran, RouteClass::Write).await.unwrap());
    assert!(
        w.p.has(&format!("63/{}", key(net, &ran))),
        "taken by peer 63 at once"
    );
    link.restore();
    until("handed to peer 64", Duration::from_secs(20), || {
        w.p.has(&format!("64/{}", key(net, &ran)))
    })
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!w.p.has(&format!("64/{}", key(net, &refused))));
}

// ---------------------------------------------------------------------------------------------
// A restricted ACL that does not allow `ROLE`: connections are accepted as for a store without
// `ROLE` (writes on a replica still fail with READONLY).

#[tokio::test]
async fn stores_whose_acl_refuses_role_are_still_connected() {
    let net = "testnet-noperm";
    let w = World::new().await;
    w.p.role_noperm.store(true, Ordering::SeqCst);
    w.f.role_noperm.store(true, Ordering::SeqCst);
    let (p_link, p_url) = w.to_p().await;
    let primary = primary_origin(net, &p_url, &addr_url(w.f_addr), false).await;
    // The peer connection is opened with the primary check at startup.
    assert!(primary.replay_peers().unwrap().any_connected());
    let write = request("ROLE not allowed");
    assert!(admit_strict(&primary, &write, RouteClass::Write)
        .await
        .unwrap());
    // A broken security connection is replaced (the replacement is primary-checked too).
    p_link.lose();
    p_link.restore();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let _ = admit_strict(&primary, &request("after the reset"), RouteClass::Write).await;
        if reconnects(net, "security", "replaced") >= 1.0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "security connection never replaced"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(admit_strict(
        &primary,
        &request("after the replacement"),
        RouteClass::Write
    )
    .await
    .unwrap());
}

// ---------------------------------------------------------------------------------------------
// The shared cache epoch while the security store gives no answer.

#[tokio::test]
async fn an_epoch_bump_at_the_peer_is_seen_while_the_own_store_is_silent() {
    let net = "testnet-epoch-peer";
    let epoch_key = format!("epoch:{net}");
    let w = World::new().await;
    let (p_link, p_url) = w.to_p().await;
    let primary = primary_origin(net, &p_url, &addr_url(w.f_addr), true).await;
    w.p.set_value(&epoch_key, "500");
    w.f.set_value(&epoch_key, "9000");
    // The own store's value is used, never the peer's.
    assert_eq!(primary.sync_epoch().await, 500);
    p_link.hang();
    // Silent own store, unchanged peer epoch: the last value stays.
    assert_eq!(primary.sync_epoch().await, 500);
    // An operator bump at the peer: entries of the old epoch are no longer served here.
    w.f.set_value(&epoch_key, "9001");
    let bumped = primary.sync_epoch().await;
    assert_ne!(bumped, 500);
    assert_eq!(primary.current_epoch(), bumped);
    assert_eq!(
        counter("ohttp_epoch_bump_seen_at_peer_total", &[("network", net)]),
        1.0
    );
    assert_eq!(primary.sync_epoch().await, bumped, "one bump, one change");
    // The own store answers again: its value applies again.
    p_link.restore();
    let deadline = Instant::now() + Duration::from_secs(20);
    while primary.sync_epoch().await != 500 {
        assert!(Instant::now() < deadline, "own epoch not read again");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
/// A cache whose security store is `own` and whose replay peers are `peers`, in that order.
async fn epoch_origin(network: &str, own: &str, peers: &[String]) -> ResponseCache {
    zodl_ohttp_gateway::health::init_metrics();
    let c = ResponseCache::connect(
        &cache_store().await,
        Some(own),
        network.to_string(),
        "lwd.example.com:9067".to_string(),
        250,
        100,
        &HashMap::new(),
    )
    .await
    .unwrap();
    let peers = ReplayPeers::connect(peers, network.to_string(), 250, false)
        .await
        .with_mode(ReplayPeerMode::Failover, true);
    c.with_replay_peers(peers)
}

/// Each peer is compared with its own baseline, the first answering one in configuration order.
#[tokio::test]
async fn epoch_baselines_are_kept_per_peer_store() {
    let net = "testnet-epoch-per-store";
    let epoch_key = format!("epoch:{net}");
    let w = World::new().await;
    let (g, g_addr) = Store::start().await;
    let (p_link, p_url) = w.to_p().await;
    let (f_link, f_url) = w.to_f().await;
    w.p.set_value(&epoch_key, "500");
    w.f.set_value(&epoch_key, "9000");
    g.set_value(&epoch_key, "77");
    let origin = epoch_origin(net, &p_url, &[f_url, addr_url(g_addr)]).await;
    assert_eq!(origin.sync_epoch().await, 500);
    p_link.hang();
    // The first peer is silent too: the second one is compared with its own baseline (77),
    // not with the first one's.
    f_link.hang();
    assert_eq!(origin.sync_epoch().await, 500);
    g.set_value(&epoch_key, "78");
    let bumped = origin.sync_epoch().await;
    assert_ne!(bumped, 500);
    assert_eq!(origin.sync_epoch().await, bumped);
    // The first peer answers again with its unchanged value: no further change.
    f_link.restore();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(origin.sync_epoch().await, bumped);
    assert_eq!(origin.sync_epoch().await, bumped);
}

/// Without a baseline (the own store was already silent when this gateway first read the
/// peers' epochs), nothing tells whether the peer was bumped: the epoch here is moved once.
#[tokio::test]
async fn an_epoch_without_a_baseline_is_invalidated_once() {
    let net = "testnet-epoch-no-baseline";
    let epoch_key = format!("epoch:{net}");
    let w = World::new().await;
    let (p_link, p_url) = w.to_p().await;
    w.p.set_value(&epoch_key, "500");
    w.f.set_value(&epoch_key, "9000");
    let origin = epoch_origin(net, &p_url, &[addr_url(w.f_addr)]).await;
    p_link.hang();
    let first = origin.sync_epoch().await;
    assert_ne!(first, 0);
    assert_eq!(
        counter("ohttp_epoch_bump_seen_at_peer_total", &[("network", net)]),
        1.0
    );
    assert_eq!(origin.sync_epoch().await, first, "once");
    // A later bump moves it to another fresh value.
    w.f.set_value(&epoch_key, "9001");
    let second = origin.sync_epoch().await;
    assert_ne!(second, first);
    assert_ne!(second, 500);
}

/// A switched epoch stays while the local store flaps: one answer in between does not bring
/// the old entries back; only answering rounds in a row do.
#[tokio::test]
async fn a_switched_epoch_outlasts_a_flapping_local_store() {
    let net = "testnet-epoch-flapping";
    let epoch_key = format!("epoch:{net}");
    let w = World::new().await;
    let (p_link, p_url) = w.to_p().await;
    w.p.set_value(&epoch_key, "500");
    w.f.set_value(&epoch_key, "9000");
    let origin = epoch_origin(net, &p_url, &[addr_url(w.f_addr)]).await;
    assert_eq!(origin.sync_epoch().await, 500);
    p_link.hang();
    w.f.set_value(&epoch_key, "9001");
    let switched = origin.sync_epoch().await;
    assert_ne!(switched, 500);
    // One answer of the local store, then silence again.
    p_link.restore();
    let deadline = Instant::now() + Duration::from_secs(20);
    while origin.get_shared_epoch().await != switched {
        assert!(Instant::now() < deadline);
    }
    assert_eq!(origin.sync_epoch().await, switched, "one answering round");
    assert_eq!(origin.current_epoch(), switched);
    p_link.hang();
    assert_eq!(origin.sync_epoch().await, switched);
    // Answering steadily: the own value applies again after three rounds in a row.
    p_link.restore();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut rounds = 0;
    loop {
        let e = origin.sync_epoch().await;
        rounds += 1;
        if e == 500 {
            break;
        }
        assert_eq!(e, switched);
        assert!(Instant::now() < deadline, "own epoch not back");
    }
    assert!(rounds >= 3, "{rounds}");
}

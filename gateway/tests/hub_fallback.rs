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

//! The hub path of the WRITE fallback (`write_fallback.rs`): an `async-reads` origin checks its
//! WRITEs at the hub store `H`; while `H` resyncs after a failover its `WAIT` comes back short.
//!
//! - A read origin (local store `L` without a replica wait, standby store `E` in
//!   `REPLAY_STANDBY_URLS`) confirms the WRITE at `E` instead (`SET NX` + `WAIT`), and inside its
//!   window (after startup or a hub disruption) checks every WRITE at `E` as well.
//! - The standby origin (its own store `E` with the replica wait, no standby stores) lets its own
//!   replicas decide.
//!
//! Checked: WRITEs run during the hub resync only when the second store took the nonce as new
//! and acknowledged it; replays held only by `E` are refused (fallback and window); a second
//! store that is unreachable or without replica fails closed; the nonce is written back to `H`;
//! without a second store nothing changes.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use zodl_ohttp_gateway::cache::{
    LocalReplayCheck, ReplayPeers, ResponseCache, WriteAdmission, WritePolicy, WriteWaitConfig,
    REPLAY_TTL_SECS,
};
use zodl_ohttp_gateway::origin::{ReplayPeerMode, RouteClass};
use zodl_ohttp_gateway::replication::ReplicationConfig;

// ---------------------------------------------------------------------------------------------
// A link that can be lost: a TCP proxy. `lose` kills the open connections (at their next
// byte) and refuses new ones until `restore`.

struct Link {
    target: SocketAddr,
    down: AtomicBool,
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

    fn restore(&self) {
        self.down.store(false, Ordering::SeqCst);
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
        if to.write_all(&buf[..n]).await.is_err() {
            return;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// A fake store (always a primary): SET [NX|XX] [EX], WAIT (answers `acks`), ROLE, PING;
// anything else +OK.

/// The commands the stores received, in arrival order ("<store> <COMMAND> [NX|XX]").
type CommandLog = Arc<Mutex<Vec<String>>>;

struct Store {
    /// The keys and their values.
    keys: Mutex<HashMap<String, String>>,
    /// Per connection (numbered in accept order): "<COMMAND> [NX|XX]" and whether the next
    /// command had already arrived when this one was read (sent in the same pipeline).
    by_conn: Mutex<Vec<(u64, String, bool)>>,
    conns: AtomicU64,
    /// WAIT answers an error (a store that refuses it).
    wait_error: AtomicBool,
    /// The next WAIT never answers (a stuck connection).
    hang_next_wait: AtomicBool,
    /// A SET read while nothing else waits on its connection holds its reply for up to 200 ms
    /// to see whether the next command arrives first: one that does was sent before the client
    /// could have read the reply, in the same pipeline (`by_conn`).
    detect_pipeline: AtomicBool,
    /// The next SET answers an error (a store that refuses it).
    fail_next_set: AtomicBool,
    /// The next SET is never processed nor answered (a stuck connection, the nonce not stored).
    hang_next_set: AtomicBool,
    /// The connection that reads the next WAIT is closed instead of answering it.
    close_on_next_wait: AtomicBool,
    /// The answer to WAIT: the replicas that acknowledged (0 = a primary whose replicas resync).
    acks: AtomicI64,
    /// Delay before each SET and WAIT reply, in ms: a store a long round trip away.
    delay_ms: AtomicU64,
    /// Arrival order of the commands across all stores (`record_into`), with this store's name.
    log: Mutex<Option<(String, CommandLog)>>,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            keys: Mutex::default(),
            by_conn: Mutex::default(),
            conns: AtomicU64::new(0),
            wait_error: AtomicBool::new(false),
            hang_next_wait: AtomicBool::new(false),
            detect_pipeline: AtomicBool::new(false),
            fail_next_set: AtomicBool::new(false),
            hang_next_set: AtomicBool::new(false),
            close_on_next_wait: AtomicBool::new(false),
            acks: AtomicI64::new(1),
            delay_ms: AtomicU64::new(0),
            log: Mutex::default(),
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
        self.keys.lock().unwrap().contains_key(key)
    }

    /// The node that holds the nonce is lost (a demoted primary the endpoint left behind).
    fn forget(&self, key: &str) {
        self.keys.lock().unwrap().remove(key);
    }

    fn put(&self, key: &str) {
        self.keys
            .lock()
            .unwrap()
            .insert(key.to_string(), "1".to_string());
    }

    /// The commands of every connection, in arrival order (`by_conn`).
    fn commands(&self) -> Vec<(u64, String, bool)> {
        self.by_conn.lock().unwrap().clone()
    }

    fn set_acks(&self, n: i64) {
        self.acks.store(n, Ordering::SeqCst);
    }

    fn set_delay(&self, ms: u64) {
        self.delay_ms.store(ms, Ordering::SeqCst);
    }

    /// Append "<name> <COMMAND> [flag]" to `log` when a command arrives (before any delay).
    fn record_into(&self, name: &str, log: CommandLog) {
        *self.log.lock().unwrap() = Some((name.to_string(), log));
    }

    async fn serve(self: Arc<Self>, sock: TcpStream) {
        let conn = self.conns.fetch_add(1, Ordering::SeqCst);
        let (r, mut w) = sock.into_split();
        let mut r = BufReader::new(r);
        while let Some(args) = read_command(&mut r).await {
            let delay = self.delay_ms.load(Ordering::SeqCst);
            let cmd = args.first().map(|c| c.to_ascii_uppercase());
            {
                let flag = args
                    .iter()
                    .skip(3)
                    .map(|a| a.to_ascii_uppercase())
                    .find(|a| a == "NX" || a == "XX")
                    .unwrap_or_default();
                let get = args.iter().skip(3).any(|a| a.eq_ignore_ascii_case("GET"));
                let entry = format!(
                    "{} {flag}{}",
                    cmd.clone().unwrap_or_default(),
                    if get { " GET" } else { "" }
                );
                let mut pipelined = !r.buffer().is_empty();
                if !pipelined
                    && cmd.as_deref() == Some("SET")
                    && !get
                    && self.detect_pipeline.load(Ordering::SeqCst)
                {
                    pipelined = matches!(
                        tokio::time::timeout(Duration::from_millis(200), r.fill_buf()).await,
                        Ok(Ok(next)) if !next.is_empty()
                    );
                }
                self.by_conn
                    .lock()
                    .unwrap()
                    .push((conn, entry.trim_end().to_string(), pipelined));
            }
            if cmd.as_deref() == Some("WAIT") && self.hang_next_wait.swap(false, Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            if cmd.as_deref() == Some("SET") && self.hang_next_set.swap(false, Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            if cmd.as_deref() == Some("WAIT")
                && self.close_on_next_wait.swap(false, Ordering::SeqCst)
            {
                return;
            }
            if cmd.as_deref() == Some("SET") && self.fail_next_set.swap(false, Ordering::SeqCst) {
                if w.write_all(b"-ERR SET refused\r\n").await.is_err() {
                    return;
                }
                continue;
            }
            if let Some((name, log)) = self.log.lock().unwrap().as_ref() {
                let flag = args
                    .iter()
                    .skip(3)
                    .map(|a| a.to_ascii_uppercase())
                    .find(|a| a == "NX" || a == "XX")
                    .unwrap_or_default();
                let entry = format!("{name} {} {flag}", cmd.clone().unwrap_or_default());
                log.lock().unwrap().push(entry.trim_end().to_string());
            }
            if delay > 0 && matches!(cmd.as_deref(), Some("SET" | "WAIT")) {
                tokio::time::sleep(Duration::from_millis(delay)).await;
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
            "ROLE" => "*3\r\n$6\r\nmaster\r\n:0\r\n*0\r\n".into(),
            "SET" => {
                let key = args[1].clone();
                let flags: Vec<String> = args[3..].iter().map(|a| a.to_ascii_uppercase()).collect();
                let get = flags.iter().any(|f| f == "GET");
                let mut keys = self.keys.lock().unwrap();
                let old = keys.get(&key).cloned();
                let bulk = |v: &Option<String>| match v {
                    Some(v) => format!("${}\r\n{v}\r\n", v.len()),
                    None => "$-1\r\n".into(),
                };
                if (flags.iter().any(|f| f == "NX") && old.is_some())
                    || (flags.iter().any(|f| f == "XX") && old.is_none())
                {
                    return if get { bulk(&old) } else { "$-1\r\n".into() };
                }
                keys.insert(key, args[2].clone());
                if get {
                    bulk(&old)
                } else {
                    "+OK\r\n".into()
                }
            }
            "WAIT" if self.wait_error.load(Ordering::SeqCst) => "-ERR WAIT refused\r\n".into(),
            "WAIT" => format!(":{}\r\n", self.acks.load(Ordering::SeqCst)),
            "GET" => "$-1\r\n".into(),
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

/// An `async-reads` origin with security store `security` checking WRITEs at `hub`; standby
/// stores `standby` (REPLAY_STANDBY_URLS, with the peer wait when `standby_wait`); the local
/// replica wait when `local_wait`.
async fn origin(
    network: &str,
    security: &str,
    hub: &str,
    fail_closed_writes: bool,
    standby: Option<&str>,
    standby_wait: bool,
    local_wait: bool,
) -> ResponseCache {
    zodl_ohttp_gateway::health::init_metrics();
    let (_cache, cache_addr) = Store::start().await;
    std::mem::forget(_cache);
    let c = ResponseCache::connect(
        &addr_url(cache_addr),
        Some(security),
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
    let mut c = c
        .with_replay_peers(peers)
        .with_async_replication(replication(network, ReplayPeerMode::AsyncReads));
    if let Some(u) = standby {
        let s = ReplayPeers::connect_standby(&[u.to_string()], network.to_string(), 250, 1)
            .await
            .with_wait(standby_wait.then_some(WAIT));
        c = c.with_standby_replication(s, replication(network, ReplayPeerMode::Failover));
    }
    if local_wait {
        c = c.with_write_wait(security, WAIT).await.unwrap();
    }
    c
}

/// The gateway's admission (main.rs). Ok(true) = runs; Ok(false) = replay; Err = fail-closed.
async fn admit(c: &ResponseCache, hash: &[u8], class: RouteClass) -> anyhow::Result<bool> {
    let local = c.check_replay_detailed(hash).await?;
    match local.verdict() {
        LocalReplayCheck::Replay => return Ok(false),
        LocalReplayCheck::Unavailable => anyhow::bail!("no verdict from the local store"),
        _ => {}
    }
    let check = c
        .replicate_nonce_checked(&local, class, WritePolicy::ONE_SIDED)
        .await?;
    if check.replay() {
        return Ok(false);
    }
    if class == RouteClass::Write
        && c.write_wait().is_some()
        && c.confirm_write_nonce(&local, &check).await? == WriteAdmission::Replay
    {
        return Ok(false);
    }
    if class == RouteClass::Write {
        c.replicate_write_to_standby(&local, check);
    }
    Ok(true)
}

fn fallback(network: &str, path: &str, result: &str) -> f64 {
    zodl_ohttp_gateway::health::REGISTRY
        .gather()
        .iter()
        .find(|f| f.get_name() == "ohttp_replay_write_fallback_total")
        .and_then(|f| {
            f.get_metric()
                .iter()
                .find(|m| {
                    let has = |n: &str, v: &str| {
                        m.get_label()
                            .iter()
                            .any(|l| l.get_name() == n && l.get_value() == v)
                    };
                    has("network", network) && has("path", path) && has("result", result)
                })
                .map(|m| m.get_counter().get_value())
        })
        .unwrap_or(0.0)
}

async fn until(what: &str, max: Duration, f: impl Fn() -> bool) {
    let started = Instant::now();
    while !f() {
        assert!(started.elapsed() < max, "{what}: not within {max:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

struct World {
    hub: Arc<Store>,
    standby: Arc<Store>,
    standby_link: Arc<Link>,
    read_origin: ResponseCache,
}

async fn world(network: &str, standby_wait: bool) -> World {
    let (hub, h_addr) = Store::start().await;
    let (standby, e_addr) = Store::start().await;
    let (local, l_addr) = Store::start().await;
    std::mem::forget(local);
    let (standby_link, e_port) = Link::start(e_addr).await;
    let read_origin = origin(
        network,
        &addr_url(l_addr),
        &addr_url(h_addr),
        true,
        Some(&url(e_port)),
        standby_wait,
        false,
    )
    .await;
    // The standby stores are connected in the background after startup.
    until("standby store connected", Duration::from_secs(10), || {
        standby_connected(network)
    })
    .await;
    World {
        hub,
        standby,
        standby_link,
        read_origin,
    }
}

fn standby_connected(network: &str) -> bool {
    zodl_ohttp_gateway::health::REGISTRY
        .gather()
        .iter()
        .find(|f| f.get_name() == "ohttp_replay_standby_connected")
        .is_some_and(|f| {
            f.get_metric().iter().any(|m| {
                m.get_label()
                    .iter()
                    .any(|l| l.get_name() == "network" && l.get_value() == network)
                    && m.get_gauge().get_value() == 1.0
            })
        })
}

#[tokio::test]
async fn read_origin_confirms_at_the_standby_store_while_the_hub_resyncs() {
    let net = "testnet-hub-fb";
    let w = world(net, true).await;
    w.hub.set_acks(0);
    let write = request("write during the hub resync");
    assert!(admit(&w.read_origin, &write, RouteClass::Write)
        .await
        .unwrap());
    assert!(
        w.standby.has(&key(net, &write)),
        "confirmed at the standby store"
    );
    assert_eq!(fallback(net, "hub_short_ack", "accepted"), 1.0);
    assert!(!admit(&w.read_origin, &write, RouteClass::Write)
        .await
        .unwrap());

    // A WRITE admitted elsewhere, its nonce only at the standby store: refused.
    let elsewhere = request("only at the standby store");
    w.standby.put(&key(net, &elsewhere));
    assert!(!admit(&w.read_origin, &elsewhere, RouteClass::Write)
        .await
        .unwrap());
    assert_eq!(fallback(net, "hub_short_ack", "replay"), 1.0);

    // The hub is back; the window (open since startup) still asks the standby store.
    w.hub.set_acks(1);
    let elsewhere = request("only at the standby store, hub back");
    w.standby.put(&key(net, &elsewhere));
    assert!(!admit(&w.read_origin, &elsewhere, RouteClass::Write)
        .await
        .unwrap());
    assert_eq!(fallback(net, "hub_window", "replay"), 1.0);
    let fresh = request("fresh write in the window");
    assert!(admit(&w.read_origin, &fresh, RouteClass::Write)
        .await
        .unwrap());
    assert!(w.standby.has(&key(net, &fresh)));
    assert_eq!(fallback(net, "hub_window", "accepted"), 1.0);

    // The nonce admitted during the resync is written back to the hub.
    w.hub.forget(&key(net, &write));
    until("written back to the hub", Duration::from_secs(5), || {
        w.read_origin.hub_fallback().unwrap().pending_len() == 0
    })
    .await;
    assert!(w.hub.has(&key(net, &write)));
}

/// The standby store's `SET NX` runs concurrently with the hub's `SET NX` and replica wait, not
/// after them, and every path uses its answer instead of asking again. Checked by the order in
/// which the stores receive the commands, not by wall-clock time.
#[tokio::test]
async fn read_origin_asks_the_standby_store_concurrently_with_the_hub() {
    let net = "testnet-hub-fb-concurrent";
    let w = world(net, true).await;
    let log = Arc::new(Mutex::new(Vec::new()));
    w.hub.record_into("hub", log.clone());
    w.standby.record_into("standby", log.clone());
    // The hub answers slowly: its `SET NX` reply takes 100 ms, so a standby `SET NX` sent only
    // after it would arrive after the hub's `WAIT`.
    w.hub.set_delay(100);
    let taken = |log: &CommandLog| std::mem::take(&mut *log.lock().unwrap());
    let position = |log: &[String], entry: &str| {
        log.iter()
            .position(|e| e == entry)
            .unwrap_or_else(|| panic!("{entry} not sent: {log:?}"))
    };

    let write = request("concurrent check");
    assert!(admit(&w.read_origin, &write, RouteClass::Write)
        .await
        .unwrap());
    let sent = taken(&log);
    assert!(
        position(&sent, "standby SET NX") < position(&sent, "hub WAIT"),
        "the standby check waited for the hub: {sent:?}"
    );
    assert_eq!(
        sent.iter().filter(|e| *e == "standby SET NX").count(),
        1,
        "asked once: {sent:?}"
    );
    assert!(w.hub.has(&key(net, &write)) && w.standby.has(&key(net, &write)));
    assert_eq!(
        fallback(net, "hub_window", "accepted") + fallback(net, "hub_check", "accepted"),
        1.0
    );

    // Held only by the standby store: refused, although the hub took it as new.
    let elsewhere = request("concurrent, only at the standby store");
    w.standby.put(&key(net, &elsewhere));
    assert!(!admit(&w.read_origin, &elsewhere, RouteClass::Write)
        .await
        .unwrap());
    // Held only by the hub: refused; the standby store now holds it as well.
    let at_hub = request("concurrent, only at the hub");
    w.hub.put(&key(net, &at_hub));
    assert!(!admit(&w.read_origin, &at_hub, RouteClass::Write)
        .await
        .unwrap());
    assert!(w.standby.has(&key(net, &at_hub)));
    taken(&log);

    // The hub resyncs: the short-acknowledgement path takes the concurrent answer as its own
    // (asking again would find its own nonce and refuse) and confirms it there with `WAIT`.
    w.hub.set_delay(0);
    w.hub.set_acks(0);
    let resync = request("concurrent, hub resync");
    assert!(admit(&w.read_origin, &resync, RouteClass::Write)
        .await
        .unwrap());
    let sent = taken(&log);
    assert_eq!(
        sent.iter().filter(|e| *e == "standby SET NX").count(),
        1,
        "asked once: {sent:?}"
    );
    assert!(sent.iter().any(|e| e == "standby WAIT"), "{sent:?}");
    assert_eq!(fallback(net, "hub_short_ack", "accepted"), 1.0);
    assert!(w.standby.has(&key(net, &resync)));
}

#[tokio::test]
async fn read_origin_fails_closed_when_the_standby_store_cannot_confirm() {
    let net = "testnet-hub-fb-down";
    let w = world(net, true).await;
    w.hub.set_acks(0);
    w.standby.set_acks(0);
    let write = request("standby without replica");
    assert!(admit(&w.read_origin, &write, RouteClass::Write)
        .await
        .is_err());
    assert_eq!(fallback(net, "hub_short_ack", "unacknowledged"), 1.0);
    w.standby.set_acks(1);
    w.standby_link.lose();
    let write = request("standby unreachable");
    assert!(admit(&w.read_origin, &write, RouteClass::Write)
        .await
        .is_err());
    assert_eq!(fallback(net, "hub_short_ack", "unavailable"), 1.0);
    assert_eq!(fallback(net, "hub_short_ack", "accepted"), 0.0);
    // Hub back, standby still unreachable: the window keeps the hub's verdict.
    w.hub.set_acks(1);
    let write = request("hub back, standby unreachable");
    assert!(admit(&w.read_origin, &write, RouteClass::Write)
        .await
        .unwrap());
    assert_eq!(fallback(net, "hub_window", "unavailable"), 1.0);
}

#[tokio::test]
async fn read_origin_without_standby_wait_is_unchanged() {
    let net = "testnet-hub-fb-nowait";
    let w = world(net, false).await;
    w.hub.set_acks(0);
    let write = request("no standby wait");
    assert!(admit(&w.read_origin, &write, RouteClass::Write)
        .await
        .is_err());
    for r in [
        "accepted",
        "unavailable",
        "replay",
        "unacknowledged",
        "overflow",
    ] {
        assert_eq!(fallback(net, "hub_short_ack", r), 0.0, "{r}");
    }
    // Outside the resync the window does not apply without a confirming standby store.
    w.hub.set_acks(1);
    let write = request("hub back");
    assert!(admit(&w.read_origin, &write, RouteClass::Write)
        .await
        .unwrap());
    assert_eq!(fallback(net, "hub_window", "accepted"), 0.0);
    // The standby store still gets it asynchronously.
    until(
        "replicated to the standby store",
        Duration::from_secs(2),
        || w.standby.has(&key(net, &write)),
    )
    .await;
}

#[tokio::test]
async fn standby_origin_relies_on_its_own_replicas_while_the_hub_resyncs() {
    local_replicas_decide("testnet-hub-fb-standby", false).await;
}

/// The spoke: same stores, WRITEs refused while the hub is unreachable.
#[tokio::test]
async fn spoke_relies_on_its_own_replicas_while_the_hub_resyncs() {
    local_replicas_decide("testnet-hub-fb-spoke", true).await;
}

async fn local_replicas_decide(net: &str, fail_closed_writes: bool) {
    let (hub, h_addr) = Store::start().await;
    let (local, l_addr) = Store::start().await;
    let c = origin(
        net,
        &addr_url(l_addr),
        &addr_url(h_addr),
        fail_closed_writes,
        None,
        false,
        true,
    )
    .await;
    hub.set_acks(0);
    let write = request("standby write during the hub resync");
    assert!(admit(&c, &write, RouteClass::Write).await.unwrap());
    assert_eq!(fallback(net, "hub_short_ack", "accepted"), 1.0);
    assert!(local.has(&key(net, &write)) && hub.has(&key(net, &write)));
    // Both stores without replica: fail closed.
    local.set_acks(0);
    let write = request("no replica anywhere");
    assert!(admit(&c, &write, RouteClass::Write).await.is_err());
    assert_eq!(fallback(net, "hub_short_ack", "unacknowledged"), 1.0);
    // Write-back to the hub once it acknowledges.
    hub.set_acks(1);
    until("written back to the hub", Duration::from_secs(5), || {
        c.hub_fallback().unwrap().pending_len() == 0
    })
    .await;
}

/// Observations of `ohttp_write_stage_duration_seconds{network, stage, result}`.
fn stage_count(network: &str, stage: &str, result: &str) -> u64 {
    zodl_ohttp_gateway::health::REGISTRY
        .gather()
        .iter()
        .find(|f| f.get_name() == "ohttp_write_stage_duration_seconds")
        .and_then(|f| {
            f.get_metric()
                .iter()
                .find(|m| {
                    let has = |n: &str, v: &str| {
                        m.get_label()
                            .iter()
                            .any(|l| l.get_name() == n && l.get_value() == v)
                    };
                    has("network", network) && has("stage", stage) && has("result", result)
                })
                .map(|m| m.get_histogram().get_sample_count())
        })
        .unwrap_or(0)
}

/// Wait until every `WAIT` connection of the hub is open (opened in the background at startup).
async fn hub_wait_conns_open(c: &ResponseCache) {
    let peers = c.replay_peers().expect("a hub");
    until("hub WAIT connections open", Duration::from_secs(10), || {
        peers.wait_conns_open().iter().all(|n| *n > 0)
    })
    .await;
}

/// Admission of a WRITE that both stores must take (`WritePolicy::BOTH_STORES`).
async fn admit_both(c: &ResponseCache, hash: &[u8]) -> anyhow::Result<bool> {
    let local = c.check_replay_detailed(hash).await?;
    if local.verdict() == LocalReplayCheck::Replay {
        return Ok(false);
    }
    let check = c
        .replicate_nonce_checked(&local, RouteClass::Write, WritePolicy::BOTH_STORES)
        .await?;
    if check.replay() {
        return Ok(false);
    }
    c.replicate_write_to_standby(&local, check);
    Ok(true)
}

/// The hub's `SET NX` of a WRITE and its `WAIT` go out together, on one `WAIT` connection: the
/// `WAIT` had already arrived when the store read the `SET NX`, and no `SET XX` follows. The
/// verdicts are those of the two round trips before: taken and acknowledged runs; held at the
/// hub is a replay; short at the hub takes the short-acknowledgement path to the standby store.
#[tokio::test]
async fn read_origin_takes_the_hub_nonce_and_its_wait_in_one_round_trip() {
    let net = "testnet-hub-one-rtt";
    let w = world(net, true).await;
    hub_wait_conns_open(&w.read_origin).await;
    w.hub.detect_pipeline.store(true, Ordering::SeqCst);
    let write = request("one round trip");
    let before = w.hub.commands().len();
    assert!(admit(&w.read_origin, &write, RouteClass::Write)
        .await
        .unwrap());
    let sent: Vec<(u64, String, bool)> = w.hub.commands()[before..].to_vec();
    let set = sent
        .iter()
        .position(|(_, c, _)| c == "SET NX")
        .unwrap_or_else(|| panic!("no SET NX: {sent:?}"));
    let (conn, _, pipelined) = &sent[set];
    assert!(*pipelined, "the WAIT went out with the SET NX: {sent:?}");
    assert_eq!(
        sent.get(set + 1).map(|(c, cmd, _)| (*c, cmd.as_str())),
        Some((*conn, "WAIT")),
        "the WAIT right behind the SET NX on its connection: {sent:?}"
    );
    assert!(
        !sent.iter().any(|(_, c, _)| c == "SET XX"),
        "no second round trip: {sent:?}"
    );
    assert!(w.hub.has(&key(net, &write)) && w.standby.has(&key(net, &write)));
    assert_eq!(stage_count(net, "hub", "acknowledged"), 1);
    w.hub.detect_pipeline.store(false, Ordering::SeqCst);
    assert_eq!(stage_count(net, "standby", "fresh"), 1);

    // Held at the hub: a replay, as before.
    let held = request("held at the hub");
    w.hub.put(&key(net, &held));
    assert!(!admit(&w.read_origin, &held, RouteClass::Write)
        .await
        .unwrap());

    // Short at the hub: the second attempt (SET XX + WAIT) is short too, and the standby store
    // confirms it (the short-acknowledgement path, unchanged).
    w.hub.set_acks(0);
    let short = request("short at the hub");
    let before = w.hub.commands().len();
    assert!(admit(&w.read_origin, &short, RouteClass::Write)
        .await
        .unwrap());
    let sent: Vec<String> = w.hub.commands()[before..]
        .iter()
        .map(|(_, c, _)| c.clone())
        .collect();
    assert_eq!(
        sent.iter().filter(|c| *c == "SET XX").count(),
        1,
        "one more attempt after the pipelined WAIT: {sent:?}"
    );
    assert_eq!(fallback(net, "hub_short_ack", "accepted"), 1.0);
    assert_eq!(stage_count(net, "hub", "replay"), 1);
    assert_eq!(stage_count(net, "hub", "short"), 1);
}

/// A pipeline whose SET NX never reached the store (a stuck connection), and one whose
/// connection breaks after the SET NX: both are asked again on another connection and the
/// WRITE runs, for each policy, with the nonce at the hub exactly once.
#[tokio::test]
async fn read_origin_retries_a_pipeline_that_stuck_or_broke() {
    let net = "testnet-hub-stuck";
    let w = world(net, true).await;
    for (tag, both) in [("one-sided", false), ("both stores", true)] {
        for case in ["SET never processed", "connection closed on WAIT"] {
            hub_wait_conns_open(&w.read_origin).await;
            w.hub.detect_pipeline.store(true, Ordering::SeqCst);
            let before = w.hub.commands().len();
            match case {
                "SET never processed" => w.hub.hang_next_set.store(true, Ordering::SeqCst),
                _ => w.hub.close_on_next_wait.store(true, Ordering::SeqCst),
            }
            let write = request(&format!("{case}, {tag}"));
            let admitted = if both {
                admit_both(&w.read_origin, &write).await
            } else {
                admit(&w.read_origin, &write, RouteClass::Write).await
            };
            assert!(admitted.unwrap(), "{case}, {tag}");
            assert!(w.hub.has(&key(net, &write)), "{case}, {tag}");
            let sent = w.hub.commands()[before..].to_vec();
            assert!(
                sent.iter()
                    .find(|(_, c, _)| c == "SET NX")
                    .is_some_and(|e| e.2)
                    && sent.iter().any(|(_, c, _)| c == "SET NX GET"),
                "{case}, {tag}: the pipeline, then asked again: {sent:?}"
            );
            // A replay of it afterwards is still refused.
            assert!(!admit(&w.read_origin, &write, RouteClass::Write)
                .await
                .unwrap());
        }
    }
}

/// A `WAIT` the hub refuses with an error (it may also have been the `SET NX`'s): the nonce is
/// asked for once more (`SET ... NX GET`), found to be this request's, and the acknowledgement
/// fails closed as an attempt that failed before did. A pipeline that never answers (a stuck
/// connection) is asked again on another connection, for every policy: the nonce is this
/// request's, and the acknowledgement on a working connection lets the WRITE run.
#[tokio::test]
async fn read_origin_resolves_an_unclear_hub_answer_without_a_replay() {
    let net = "testnet-hub-unclear";
    let w = world(net, true).await;
    hub_wait_conns_open(&w.read_origin).await;

    w.hub.wait_error.store(true, Ordering::SeqCst);
    let refused = request("WAIT refused");
    let err = admit(&w.read_origin, &refused, RouteClass::Write)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not acknowledged"), "{err}");
    assert!(w.hub.has(&key(net, &refused)), "taken by this request");
    let sent: Vec<String> = w.hub.commands().iter().map(|(_, c, _)| c.clone()).collect();
    assert!(sent.iter().any(|c| c == "SET NX"), "{sent:?}");
    assert!(
        sent.iter().any(|c| c == "SET NX GET"),
        "asked for the nonce again: {sent:?}"
    );
    // The same error while another request holds the nonce: a replay, never admitted.
    let held = request("WAIT refused, held elsewhere");
    w.hub.put(&key(net, &held));
    assert!(!admit(&w.read_origin, &held, RouteClass::Write)
        .await
        .unwrap());
    w.hub.wait_error.store(false, Ordering::SeqCst);
    // An error on the SET itself (also asked again, the store refuses once): this request's
    // nonce was not stored by the pipeline, the second ask stores it.
    hub_wait_conns_open(&w.read_origin).await;
    w.hub.detect_pipeline.store(true, Ordering::SeqCst);
    let before = w.hub.commands().len();
    w.hub.fail_next_set.store(true, Ordering::SeqCst);
    let set_refused = request("SET refused once");
    assert!(admit(&w.read_origin, &set_refused, RouteClass::Write)
        .await
        .unwrap());
    assert!(w.hub.has(&key(net, &set_refused)));
    let sent = w.hub.commands()[before..].to_vec();
    assert!(
        sent.iter()
            .find(|(_, c, _)| c == "SET NX")
            .is_some_and(|e| e.2)
            && sent.iter().any(|(_, c, _)| c == "SET NX GET"),
        "the pipeline, then asked again: {sent:?}"
    );
    w.hub.detect_pipeline.store(false, Ordering::SeqCst);

    for (tag, both) in [("one-sided", false), ("both stores", true)] {
        // Every connection open again (a failed or stuck one is replaced in the background),
        // so the pipeline runs.
        hub_wait_conns_open(&w.read_origin).await;
        w.hub.detect_pipeline.store(true, Ordering::SeqCst);
        w.hub.hang_next_wait.store(true, Ordering::SeqCst);
        let before = w.hub.commands().len();
        let stuck = request(&format!("stuck pipeline, {tag}"));
        let admitted = if both {
            admit_both(&w.read_origin, &stuck).await
        } else {
            admit(&w.read_origin, &stuck, RouteClass::Write).await
        };
        assert!(
            admitted.unwrap(),
            "{tag}: asked again on another connection"
        );
        assert!(w.hub.has(&key(net, &stuck)));
        let sent = w.hub.commands()[before..].to_vec();
        let first = sent
            .iter()
            .find(|(_, c, _)| c == "SET NX")
            .unwrap_or_else(|| panic!("{tag}: no SET NX: {sent:?}"));
        let retry = sent
            .iter()
            .find(|(_, c, _)| c == "SET NX GET")
            .unwrap_or_else(|| panic!("{tag}: no retry: {sent:?}"));
        assert!(
            first.2 && retry.0 != first.0,
            "{tag}: the pipeline, then the retry on another connection: {sent:?}"
        );
    }
}

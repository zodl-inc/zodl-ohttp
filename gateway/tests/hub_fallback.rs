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

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ohttp_gateway::cache::{
    ReplayPeers, ResponseCache, WriteAdmission, WriteWaitConfig, REPLAY_TTL_SECS,
};
use ohttp_gateway::origin::{ReplayPeerMode, RouteClass};
use ohttp_gateway::replication::ReplicationConfig;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

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

struct Store {
    keys: Mutex<HashSet<String>>,
    /// The answer to WAIT: the replicas that acknowledged (0 = a primary whose replicas resync).
    acks: AtomicI64,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            keys: Mutex::default(),
            acks: AtomicI64::new(1),
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

    /// The node that holds the nonce is lost (a demoted primary the endpoint left behind).
    fn forget(&self, key: &str) {
        self.keys.lock().unwrap().remove(key);
    }

    fn put(&self, key: &str) {
        self.keys.lock().unwrap().insert(key.to_string());
    }

    fn set_acks(&self, n: i64) {
        self.acks.store(n, Ordering::SeqCst);
    }

    async fn serve(self: Arc<Self>, sock: TcpStream) {
        let (r, mut w) = sock.into_split();
        let mut r = BufReader::new(r);
        while let Some(args) = read_command(&mut r).await {
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
                let mut keys = self.keys.lock().unwrap();
                let exists = keys.contains(&key);
                if (flags.iter().any(|f| f == "NX") && exists)
                    || (flags.iter().any(|f| f == "XX") && !exists)
                {
                    return "$-1\r\n".into();
                }
                keys.insert(key);
                "+OK\r\n".into()
            }
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
    ohttp_gateway::health::init_metrics();
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
    if c.check_replay(hash).await? {
        return Ok(false);
    }
    let check = c.replicate_nonce_checked(hash, class).await?;
    if check.replay {
        return Ok(false);
    }
    if class == RouteClass::Write
        && c.write_wait().is_some()
        && c.confirm_write_nonce(hash, check).await? == WriteAdmission::Replay
    {
        return Ok(false);
    }
    if class == RouteClass::Write && !check.at_standby {
        c.replicate_write_to_standby(hash);
    }
    Ok(true)
}

fn fallback(network: &str, path: &str, result: &str) -> f64 {
    ohttp_gateway::health::REGISTRY
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
    ohttp_gateway::health::REGISTRY
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
    let net = "testnet-hub-fb-standby";
    let (hub, h_addr) = Store::start().await;
    let (local, l_addr) = Store::start().await;
    let c = origin(
        net,
        &addr_url(l_addr),
        &addr_url(h_addr),
        false,
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

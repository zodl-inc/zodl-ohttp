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

use ohttp_gateway::cache::{
    LocalReplayCheck, PeerCheck, ReplayPeers, ResponseCache, WriteAdmission, WriteWaitConfig,
    REPLAY_TTL_SECS,
};
use ohttp_gateway::origin::{ReplayPeerMode, RouteClass};
use ohttp_gateway::replication::ReplicationConfig;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

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
    /// The answer to WAIT: the replicas that acknowledged (0 = a primary whose replicas resync).
    acks: AtomicI64,
    /// WAIT gets no answer at all (the node stops answering after the SET).
    wait_hangs: AtomicBool,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            keys: Mutex::default(),
            acks: AtomicI64::new(1),
            wait_hangs: AtomicBool::new(false),
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

    async fn serve(self: Arc<Self>, sock: TcpStream) {
        let (r, mut w) = sock.into_split();
        let mut r = BufReader::new(r);
        while let Some(args) = read_command(&mut r).await {
            if args.first().is_some_and(|c| c.eq_ignore_ascii_case("WAIT"))
                && self.wait_hangs.load(Ordering::SeqCst)
            {
                // Never answered: every later reply on this connection waits behind it.
                std::future::pending::<()>().await;
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

async fn cache_store() -> String {
    let (cache, addr) = Store::start().await;
    std::mem::forget(cache);
    addr_url(addr)
}

/// A primary-region gateway: `failover` mode, its own store `primary` (with the replica wait),
/// the fallback store `fallback` as its peer.
async fn primary_origin(network: &str, primary: &str, fallback: &str, on: bool) -> ResponseCache {
    ohttp_gateway::health::init_metrics();
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
        .with_write_wait(primary, WAIT)
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
    ohttp_gateway::health::init_metrics();
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
    ohttp_gateway::health::init_metrics();
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
    ohttp_gateway::health::init_metrics();
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

/// The gateway's admission (main.rs). Ok(true) = runs; Ok(false) = replay; Err = fail-closed.
async fn admit(c: &ResponseCache, hash: &[u8], class: RouteClass) -> anyhow::Result<bool> {
    let local = c.check_replay_detailed(hash).await?;
    if local == LocalReplayCheck::Replay {
        return Ok(false);
    }
    let check = if local == LocalReplayCheck::Unavailable {
        match c.admit_without_local(hash, class).await? {
            WriteAdmission::Run => PeerCheck {
                local_bypassed: true,
                ..PeerCheck::default()
            },
            WriteAdmission::Replay => return Ok(false),
        }
    } else if c.replay_peers().is_some() {
        c.replicate_nonce_checked(hash, class).await?
    } else {
        PeerCheck::default()
    };
    if check.replay {
        return Ok(false);
    }
    if class == RouteClass::Write
        && c.write_wait().is_some()
        && !check.local_bypassed
        && c.confirm_write_nonce(hash, check).await? == WriteAdmission::Replay
    {
        return Ok(false);
    }
    if class == RouteClass::Write && !check.at_standby {
        c.replicate_write_to_standby(hash);
    }
    Ok(true)
}

fn counter(name: &str, labels: &[(&str, &str)]) -> f64 {
    ohttp_gateway::health::REGISTRY
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
    ohttp_gateway::health::REGISTRY
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
    use ohttp_gateway::health::{
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
    use ohttp_gateway::health::{
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
    use ohttp_gateway::health::{
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
    use ohttp_gateway::health::is_replay_serving_via_fallback;
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

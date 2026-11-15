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

//! Replay protection across the loss of the primary origin, with a read origin and a standby.
//!
//! Three origins and their security stores:
//!
//! - the primary origin's store `H` (shared: the other origins check WRITEs there),
//! - a read origin `R` (`async-reads`, WRITEs fail closed without `H`), local store `L`,
//! - a standby origin `S` (`async-reads`, `REPLAY_PEER_FAIL_CLOSED_WRITES=0`: it admits WRITEs
//!   on its own store `E` while `H` is unreachable).
//!
//! `H` sits behind a TCP proxy that can lose it (open connections die, new ones are refused) and
//! bring it back; `E` is reached by its own path, which the loss of `H` does not touch. The stores
//! are in-process fakes speaking just enough RESP. Each origin admits a request the way the
//! gateway does (`admit`).
//!
//! Checked: a WRITE admitted at `R` is refused at `S` after `H` is lost (with
//! `REPLAY_STANDBY_URLS` on `R`; without it the replay is admitted, which is the gap the setting
//! closes); a WRITE refused at `R` while `H` is lost does not burn its nonce at `E`; a WRITE `S`
//! admitted while `H` was lost reaches `H` once it is back, so `R` refuses its replay.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ohttp_gateway::cache::{
    LocalReplayCheck, PeerOutcome, ReplayPeers, ResponseCache, WritePolicy, REPLAY_TTL_SECS,
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
// A fake store (always a primary): SET [NX|XX] [EX], WAIT, ROLE, PING; anything else +OK.

#[derive(Default)]
struct Store {
    keys: Mutex<HashSet<String>>,
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
            "WAIT" => ":1\r\n".into(),
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

/// The replay key of `hash` on network `net`.
fn key(net: &str, hash: &[u8]) -> String {
    format!("replay:{net}:{}", hex::encode(hash))
}

fn replication(net: &str, mode: ReplayPeerMode) -> ReplicationConfig {
    let mut c = ReplicationConfig::new(net, mode, 1000, 1, 250, REPLAY_TTL_SECS, 3);
    c.batch_interval = Duration::from_millis(20);
    c.probe_interval = Duration::from_millis(100);
    c
}

/// An origin in `async-reads` whose security store is `security`, checking at the peer `hub`,
/// replicating admitted WRITEs to `standby` (REPLAY_STANDBY_URLS) when given.
async fn origin(
    net: &str,
    cache: &str,
    security: &str,
    hub: &str,
    fail_closed_writes: bool,
    standby: Option<&str>,
) -> ResponseCache {
    let c = ResponseCache::connect(
        cache,
        Some(security),
        net.to_string(),
        "lwd.example.com:9067".to_string(),
        250,
        100,
        &HashMap::new(),
    )
    .await
    .unwrap();
    let peers = ReplayPeers::connect(&[hub.to_string()], net.to_string(), 250, false)
        .await
        .with_mode(ReplayPeerMode::AsyncReads, fail_closed_writes);
    let c = c
        .with_replay_peers(peers)
        .with_async_replication(replication(net, ReplayPeerMode::AsyncReads));
    match standby {
        None => c,
        Some(u) => {
            let s = ReplayPeers::connect_standby(&[u.to_string()], net.to_string(), 250, 1).await;
            c.with_standby_replication(s, replication(net, ReplayPeerMode::Failover))
        }
    }
}

/// The gateway's admission of a request (main.rs): the local check, the peers by class, and
/// for an admitted WRITE the hand-off to the standby stores. Ok(true) = it runs; Ok(false) =
/// refused as a replay; Err = fail-closed.
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
    if class == RouteClass::Write {
        c.replicate_write_to_standby(&local, check);
    }
    Ok(true)
}

/// The value of `name{network=net, peer}`, None when the series does not exist. Each test has
/// a network of its own: the gauges are process-wide, and tests run concurrently.
fn gauge(net: &str, name: &str, peer: &str) -> Option<f64> {
    ohttp_gateway::health::REGISTRY
        .gather()
        .iter()
        .find(|f| f.get_name() == name)?
        .get_metric()
        .iter()
        .find(|m| {
            let l = m.get_label();
            l.iter()
                .any(|l| l.get_name() == "network" && l.get_value() == net)
                && l.iter()
                    .any(|l| l.get_name() == "peer" && l.get_value() == peer)
        })
        .map(|m| m.get_gauge().get_value())
}

async fn until(what: &str, max: Duration, f: impl Fn() -> bool) {
    let started = Instant::now();
    while !f() {
        assert!(started.elapsed() < max, "{what}: not within {max:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

struct World {
    net: &'static str,
    hub: Arc<Store>,
    standby_store: Arc<Store>,
    hub_link: Arc<Link>,
    read_origin: ResponseCache,
    standby: ResponseCache,
}

impl World {
    fn key(&self, hash: &[u8]) -> String {
        key(self.net, hash)
    }
}

async fn world(net: &'static str, read_origin_replicates_to_standby: bool) -> World {
    ohttp_gateway::health::init_metrics();
    let (_cache, cache_addr) = Store::start().await;
    let (hub, hub_addr) = Store::start().await;
    let (standby_store, e_addr) = Store::start().await;
    let (_local, l_addr) = Store::start().await;
    // The read origin and the standby both reach the hub over the link that is lost; the read
    // origin reaches the standby store over a path of its own.
    let (hub_link, hub_port) = Link::start(hub_addr).await;
    let (_e_link, e_port) = Link::start(e_addr).await;
    let cache = addr_url(cache_addr);
    let read_origin = origin(
        net,
        &cache,
        &addr_url(l_addr),
        &url(hub_port),
        true,
        read_origin_replicates_to_standby
            .then(|| url(e_port))
            .as_deref(),
    )
    .await;
    let standby = origin(net, &cache, &addr_url(e_addr), &url(hub_port), false, None).await;
    World {
        net,
        hub,
        standby_store,
        hub_link,
        read_origin,
        standby,
    }
}

#[tokio::test]
async fn write_admitted_at_a_read_origin_is_refused_at_the_standby_after_the_hub_is_lost() {
    let w = world("testnet-standby-refused", true).await;
    let write = request("write via the read origin");
    assert!(admit(&w.read_origin, &write, RouteClass::Write)
        .await
        .unwrap());
    assert!(
        w.hub.has(&w.key(&write)),
        "checked at the hub synchronously"
    );
    until("nonce at the standby store", Duration::from_secs(2), || {
        w.standby_store.has(&w.key(&write))
    })
    .await;

    // The standby store's connectivity has a gauge of its own: watchdogs read
    // ohttp_replay_peer_connected as "the hub is reachable", so it must only ever carry peer 0.
    until("standby store connected", Duration::from_secs(5), || {
        gauge(w.net, "ohttp_replay_standby_connected", "1") == Some(1.0)
    })
    .await;
    assert_eq!(gauge(w.net, "ohttp_replay_peer_connected", "1"), None);

    // The hub is lost. The standby admits WRITEs on its own store now ...
    w.hub_link.lose();
    let fresh = request("fresh write at the standby");
    assert!(
        admit(&w.standby, &fresh, RouteClass::Write).await.unwrap(),
        "the standby serves WRITEs while the hub is unreachable"
    );
    // ... but not the one the read origin already ran.
    assert!(
        !admit(&w.standby, &write, RouteClass::Write).await.unwrap(),
        "replay at the standby refused"
    );

    // A WRITE at the read origin fails closed while the hub is unreachable, and its nonce is
    // not handed to the standby (it never ran: the client's retry is not burnt there).
    let refused = request("write at the read origin, hub lost");
    assert!(admit(&w.read_origin, &refused, RouteClass::Write)
        .await
        .is_err());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!w.standby_store.has(&w.key(&refused)));
    // READs go on at the read origin; they are not replicated to the standby store.
    let read = request("read at the read origin, hub lost");
    assert!(admit(&w.read_origin, &read, RouteClass::Read)
        .await
        .unwrap());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!w.standby_store.has(&w.key(&read)));
}

#[tokio::test]
async fn without_standby_replication_the_replay_is_admitted_at_the_standby() {
    // The gap REPLAY_STANDBY_URLS closes, shown with the same setup minus the setting.
    let w = world("testnet-standby-without", false).await;
    let write = request("write via the read origin, no standby replication");
    assert!(admit(&w.read_origin, &write, RouteClass::Write)
        .await
        .unwrap());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!w.standby_store.has(&w.key(&write)));
    w.hub_link.lose();
    assert!(
        admit(&w.standby, &write, RouteClass::Write).await.unwrap(),
        "without the setting the standby runs the WRITE a second time"
    );
}

#[tokio::test]
async fn write_admitted_at_the_standby_while_the_hub_is_lost_reaches_the_hub_when_it_is_back() {
    let w = world("testnet-standby-back", true).await;
    w.hub_link.lose();
    let write = request("write at the standby, hub lost");
    assert!(admit(&w.standby, &write, RouteClass::Write).await.unwrap());
    assert!(!w.hub.has(&w.key(&write)));

    // The hub is back: the standby's queue delivers the nonce (reconnect backoff <= 5 s).
    w.hub_link.restore();
    until(
        "nonce at the hub after its return",
        Duration::from_secs(15),
        || w.hub.has(&w.key(&write)),
    )
    .await;

    // A replay at the read origin, which checks WRITEs at the hub again, is refused. Its own
    // connection to the hub died with the link, so the first attempt may fail closed; the
    // nonce is then in its local store already, and every later attempt is refused locally.
    // The whole recovery is bounded by one deadline (also a call that hangs).
    let deadline = Instant::now() + Duration::from_secs(15);
    let recovery = async {
        match admit(&w.read_origin, &write, RouteClass::Write).await {
            Ok(true) => {
                panic!("replay of a WRITE the standby ran was admitted after the switch back")
            }
            Ok(false) => {}
            Err(_) => assert!(
                !matches!(
                    admit(&w.read_origin, &write, RouteClass::Write).await,
                    Ok(true)
                ),
                "replay of a WRITE the standby ran was admitted after the switch back"
            ),
        }
        // The read origin reaches the hub again, which holds the nonce too ...
        let peers = w.read_origin.replay_peers().expect("the hub is a peer");
        loop {
            match peers.write_nonce(&w.key(&write), 60).await.as_slice() {
                [PeerOutcome::Replay] => break,
                [PeerOutcome::Fresh] => panic!("the hub admitted the replay"),
                _ => assert!(
                    Instant::now() < deadline,
                    "the read origin never reached the hub again"
                ),
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        // ... and a new WRITE admitted there is checked at the hub again (a new request per
        // attempt: one that failed closed is held locally from then on).
        let mut attempt = 0;
        let fresh = loop {
            attempt += 1;
            let fresh = request(&format!(
                "write at the read origin after the switch back {attempt}"
            ));
            match admit(&w.read_origin, &fresh, RouteClass::Write).await {
                Ok(true) => break fresh,
                Ok(false) => panic!("a new WRITE was refused as a replay"),
                Err(_) => assert!(
                    Instant::now() < deadline,
                    "no WRITE admitted after the switch back"
                ),
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        fresh
    };
    let fresh = tokio::time::timeout_at(deadline.into(), recovery)
        .await
        .expect("the recovery after the switch back did not finish within 15 s");
    assert!(w.hub.has(&w.key(&fresh)), "the new WRITE reached the hub");
}

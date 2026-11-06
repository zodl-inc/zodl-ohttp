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

//! The peer fallback of the WRITE replica wait (`write_fallback.rs`): while the local store's
//! replicas resynchronise after a failover (`WAIT` comes back short), a WRITE is confirmed at the
//! peer store instead.
//!
//! Two deployments, each with its local store `L` and the cross-region peer store `P`:
//!
//! - a primary origin in `failover` mode (no synchronous peer check normally): on a short local
//!   acknowledgement it writes the nonce to `P` (`SET NX`) and waits for `P`'s replicas;
//! - a standby origin in `async-reads` with `REPLAY_PEER_FAIL_CLOSED_WRITES=0`: it already wrote
//!   and acknowledged the nonce at `P` before the local wait, so the fallback uses that.
//!
//! Checked: WRITEs run during the local resync only when the peer took the nonce as new and
//! acknowledged it; a replay is refused even when the local store lost its copy (before and
//! after the resync: the window); a peer that is unreachable or has no replica fails closed;
//! the nonce is written back to the local store; without a peer nothing changes. The stores are
//! in-process fakes; `WAIT` answers whatever the test sets.

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

/// An origin whose security store is `security` (with the replica wait), checking at the peer
/// store `peer` in `mode` (None = no peer, like testnet).
async fn origin(
    network: &str,
    cache: &str,
    security: &str,
    peer: Option<(&str, ReplayPeerMode, bool)>,
) -> ResponseCache {
    origin_with_peer_wait(network, cache, security, peer, Some(WAIT)).await
}

async fn origin_with_peer_wait(
    network: &str,
    cache: &str,
    security: &str,
    peer: Option<(&str, ReplayPeerMode, bool)>,
    peer_wait: Option<WriteWaitConfig>,
) -> ResponseCache {
    ohttp_gateway::health::init_metrics();
    let c = ResponseCache::connect(
        cache,
        Some(security),
        network.to_string(),
        "lwd.example.com:9067".to_string(),
        250,
        100,
        &HashMap::new(),
    )
    .await
    .unwrap();
    let c = match peer {
        None => c,
        Some((url, mode, fail_closed_writes)) => {
            let peers = ReplayPeers::connect(&[url.to_string()], network.to_string(), 250, false)
                .await
                .with_mode(mode, fail_closed_writes)
                .with_wait(peer_wait);
            c.with_replay_peers(peers)
                .with_async_replication(replication(network, mode))
        }
    };
    c.with_write_wait(security, WAIT).await.unwrap()
}

/// The gateway's admission of a request (main.rs). Ok(true) = it runs; Ok(false) = refused as
/// a replay; Err = fail-closed.
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
    Ok(true)
}

/// `ohttp_replay_write_fallback_total{network, path, result}` (0 when absent).
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
    local: Arc<Store>,
    peer: Arc<Store>,
    peer_link: Arc<Link>,
    origin: ResponseCache,
}

async fn world(network: &str, mode: ReplayPeerMode, fail_closed_writes: bool) -> World {
    let (_cache, cache_addr) = Store::start().await;
    let (local, l_addr) = Store::start().await;
    let (peer, p_addr) = Store::start().await;
    let (peer_link, p_port) = Link::start(p_addr).await;
    let origin = origin(
        network,
        &addr_url(cache_addr),
        &addr_url(l_addr),
        Some((&url(p_port), mode, fail_closed_writes)),
    )
    .await;
    World {
        local,
        peer,
        peer_link,
        origin,
    }
}

#[tokio::test]
async fn failover_mode_write_is_confirmed_at_the_peer_while_the_local_replicas_resync() {
    let net = "testnet-wfb-failover";
    let w = world(net, ReplayPeerMode::Failover, true).await;
    w.local.set_acks(0);

    let write = request("write during the local resync");
    assert!(admit(&w.origin, &write, RouteClass::Write).await.unwrap());
    assert!(
        w.peer.has(&key(net, &write)),
        "confirmed at the peer synchronously"
    );
    assert_eq!(fallback(net, "short_ack", "accepted"), 1.0);

    // Its replay is refused locally, and still refused when the local store lost its copy
    // (the SET NX had landed on a node the endpoint no longer points at): at the peer, or
    // locally once the write-back rewrote it.
    assert!(!admit(&w.origin, &write, RouteClass::Write).await.unwrap());
    w.local.forget(&key(net, &write));
    assert!(!admit(&w.origin, &write, RouteClass::Write).await.unwrap());

    // A WRITE another origin already admitted (its nonce only at the peer store) is refused.
    let elsewhere = request("admitted at another origin");
    w.peer.put(&key(net, &elsewhere));
    assert!(!admit(&w.origin, &elsewhere, RouteClass::Write)
        .await
        .unwrap());
    assert!(fallback(net, "short_ack", "replay") >= 1.0);

    // The resync is over: inside the window the peer is still asked, and refuses such a nonce.
    w.local.set_acks(1);
    let elsewhere = request("admitted at another origin, after the resync");
    w.peer.put(&key(net, &elsewhere));
    assert!(!admit(&w.origin, &elsewhere, RouteClass::Write)
        .await
        .unwrap());
    assert_eq!(fallback(net, "window", "replay"), 1.0);
    // A new WRITE in the window: checked at the peer, runs.
    let fresh = request("write in the window");
    assert!(admit(&w.origin, &fresh, RouteClass::Write).await.unwrap());
    assert!(w.peer.has(&key(net, &fresh)));
    assert_eq!(fallback(net, "window", "accepted"), 1.0);
    // READs never wait or fall back.
    w.local.set_acks(0);
    let read = request("read during the resync");
    assert!(admit(&w.origin, &read, RouteClass::Read).await.unwrap());
}

#[tokio::test]
async fn admitted_nonce_is_written_back_to_the_local_store() {
    let net = "testnet-wfb-writeback";
    let w = world(net, ReplayPeerMode::Failover, true).await;
    w.local.set_acks(0);
    let write = request("write back");
    assert!(admit(&w.origin, &write, RouteClass::Write).await.unwrap());
    w.local.forget(&key(net, &write));
    assert_eq!(w.origin.write_fallback().unwrap().pending_len(), 1);
    // Not acknowledged locally yet: retried (and rewritten) until the replicas are back.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(w.origin.write_fallback().unwrap().pending_len(), 1);
    w.local.forget(&key(net, &write));
    w.local.set_acks(1);
    until("written back", Duration::from_secs(5), || {
        w.origin.write_fallback().unwrap().pending_len() == 0
    })
    .await;
    assert!(w.local.has(&key(net, &write)));
}

#[tokio::test]
async fn failover_mode_write_fails_closed_when_the_peer_cannot_confirm() {
    let net = "testnet-wfb-peerdown";
    let w = world(net, ReplayPeerMode::Failover, true).await;
    w.local.set_acks(0);

    // The peer has no replica either.
    w.peer.set_acks(0);
    let write = request("peer without replica");
    assert!(admit(&w.origin, &write, RouteClass::Write).await.is_err());
    assert_eq!(fallback(net, "short_ack", "unacknowledged"), 1.0);

    // The peer is unreachable.
    w.peer.set_acks(1);
    w.peer_link.lose();
    let write = request("peer unreachable");
    assert!(admit(&w.origin, &write, RouteClass::Write).await.is_err());
    assert_eq!(fallback(net, "short_ack", "unavailable"), 1.0);
    assert_eq!(fallback(net, "short_ack", "accepted"), 0.0);

    // Local replicas back: WRITEs run on the local verdict (inside the window the unreachable
    // peer keeps it, as outside).
    w.local.set_acks(1);
    let write = request("local ack, peer unreachable");
    assert!(admit(&w.origin, &write, RouteClass::Write).await.unwrap());
    assert_eq!(fallback(net, "window", "unavailable"), 1.0);
    // ... and the peer gets that nonce once it is reachable again.
    w.peer_link.restore();
    until(
        "replicated after the peer is back",
        Duration::from_secs(10),
        || w.peer.has(&key(net, &write)),
    )
    .await;
}

#[tokio::test]
async fn a_gateway_that_just_started_checks_writes_at_the_peer() {
    let net = "testnet-wfb-newpod";
    let (_cache, cache_addr) = Store::start().await;
    let (local, l_addr) = Store::start().await;
    let (peer, p_addr) = Store::start().await;
    // Another gateway admitted a WRITE through the peer, and the local store lost its copy
    // before the write-back (that gateway was replaced). A new gateway of the same store,
    // which never saw the failover, refuses the replay.
    let elsewhere = request("admitted by a gateway that is gone");
    peer.put(&key(net, &elsewhere));
    let c = origin(
        net,
        &addr_url(cache_addr),
        &addr_url(l_addr),
        Some((&addr_url(p_addr), ReplayPeerMode::Failover, true)),
    )
    .await;
    assert!(c.write_fallback().unwrap().window_open());
    assert!(!admit(&c, &elsewhere, RouteClass::Write).await.unwrap());
    assert_eq!(fallback(net, "window", "replay"), 1.0);
    assert!(local.has(&key(net, &elsewhere)), "checked locally first");
}

#[tokio::test]
async fn peers_without_replica_acknowledgement_get_no_fallback() {
    let net = "testnet-wfb-nopeerwait";
    let (_cache, cache_addr) = Store::start().await;
    let (local, l_addr) = Store::start().await;
    let (_peer, p_addr) = Store::start().await;
    // REPLAY_PEER_WAIT_REPLICAS=0.
    let c = origin_with_peer_wait(
        net,
        &addr_url(cache_addr),
        &addr_url(l_addr),
        Some((&addr_url(p_addr), ReplayPeerMode::Failover, true)),
        None,
    )
    .await;
    assert!(c.write_fallback().is_none());
    local.set_acks(0);
    let write = request("peer without wait");
    assert!(admit(&c, &write, RouteClass::Write).await.is_err());
    for r in [
        "accepted",
        "unavailable",
        "replay",
        "unacknowledged",
        "overflow",
    ] {
        assert_eq!(fallback(net, "short_ack", r), 0.0, "{r}");
    }
}

#[tokio::test]
async fn failover_mode_outside_the_window_replicates_after_the_local_ack() {
    let net = "testnet-wfb-normal";
    let w = world(net, ReplayPeerMode::Failover, true).await;
    // The startup window is over.
    w.origin.write_fallback().unwrap().close_window();
    let write = request("normal write");
    assert!(admit(&w.origin, &write, RouteClass::Write).await.unwrap());
    // Asynchronously, after the local verdict (never before: the peer must not hold a nonce
    // of a request still being decided).
    until("replicated to the peer", Duration::from_secs(2), || {
        w.peer.has(&key(net, &write))
    })
    .await;
    assert!(!w.origin.write_fallback().unwrap().window_open());
    assert_eq!(fallback(net, "window", "accepted"), 0.0);
    assert_eq!(fallback(net, "short_ack", "accepted"), 0.0);
}

#[tokio::test]
async fn async_reads_write_uses_the_peer_acknowledgement_it_already_has() {
    let net = "testnet-wfb-standby";
    // The standby: async-reads, WRITEs tolerated on the local store while the peer is lost.
    let w = world(net, ReplayPeerMode::AsyncReads, false).await;
    w.local.set_acks(0);
    let write = request("standby write during its local resync");
    assert!(admit(&w.origin, &write, RouteClass::Write).await.unwrap());
    assert_eq!(fallback(net, "short_ack", "accepted"), 1.0);
    assert!(
        !admit(&w.origin, &write, RouteClass::Write).await.unwrap(),
        "replay"
    );
    let elsewhere = request("admitted at the hub");
    w.peer.put(&key(net, &elsewhere));
    assert!(
        !admit(&w.origin, &elsewhere, RouteClass::Write)
            .await
            .unwrap(),
        "replay refused at the peer"
    );

    // The peer is lost: WRITEs on the local store alone need its replicas, as before.
    w.peer_link.lose();
    let write = request("standby write, peer lost, local resync");
    assert!(admit(&w.origin, &write, RouteClass::Write).await.is_err());
    assert_eq!(fallback(net, "short_ack", "unavailable"), 1.0);
    w.local.set_acks(1);
    let write = request("standby write, peer lost");
    assert!(admit(&w.origin, &write, RouteClass::Write).await.unwrap());
    assert_eq!(fallback(net, "short_ack", "accepted"), 1.0);
}

#[tokio::test]
async fn without_a_peer_nothing_changes() {
    let net = "testnet-wfb-nopeer";
    let (_cache, cache_addr) = Store::start().await;
    let (local, l_addr) = Store::start().await;
    let c = origin(net, &addr_url(cache_addr), &addr_url(l_addr), None).await;
    assert!(c.write_fallback().is_none());
    local.set_acks(0);
    let write = request("no peer");
    assert!(admit(&c, &write, RouteClass::Write).await.is_err());
    for r in [
        "accepted",
        "unavailable",
        "replay",
        "unacknowledged",
        "overflow",
    ] {
        assert_eq!(fallback(net, "short_ack", r), 0.0, "{r}");
    }
    local.set_acks(1);
    let write = request("no peer, replicas back");
    assert!(admit(&c, &write, RouteClass::Write).await.unwrap());
}

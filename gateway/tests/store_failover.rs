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

//! Security store failover: the replay store is reached through one endpoint name that a
//! managed Redis moves to the promoted replica, while the demoted primary keeps running (and
//! keeps its open connections) as a replica that answers writes with `READONLY`.
//!
//! The endpoint name is modelled by a TCP proxy: new connections go to the current target,
//! established ones stay where they were (or hang, when frozen). Two kinds of store sit behind
//! it:
//!
//! - in-process fake nodes speaking just enough RESP (always run);
//! - a real Redis primary and replica (`docker compose -f tests/failover/docker-compose.yml up`,
//!   then `OHTTP_FAILOVER_REDIS=1`), promoted with `REPLICAOF NO ONE` under a WRITE load.
//!
//! Checked: WRITEs recover within seconds after the switch, none is confirmed without the
//! replica acknowledgement or on a node that lacks its nonce, and no replay is accepted.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ohttp_gateway::cache::{ResponseCache, WriteWaitConfig};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

// ---------------------------------------------------------------------------------------------
// The endpoint name: a switchable TCP proxy.

struct Proxy {
    target: Mutex<SocketAddr>,
    /// Incremented by every `flip`; each connection remembers the value it was opened at.
    generation: AtomicU64,
    /// Connections opened before this generation drop everything (a hung connection, no RST).
    frozen_before: AtomicU64,
}

impl Proxy {
    async fn start(target: SocketAddr) -> (Arc<Self>, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let proxy = Arc::new(Self {
            target: Mutex::new(target),
            generation: AtomicU64::new(0),
            frozen_before: AtomicU64::new(0),
        });
        let p = proxy.clone();
        tokio::spawn(async move {
            while let Ok((inbound, _)) = listener.accept().await {
                let p = p.clone();
                tokio::spawn(async move {
                    let born = p.generation.load(Ordering::SeqCst);
                    let target = *p.target.lock().unwrap();
                    let Ok(upstream) = TcpStream::connect(target).await else {
                        return;
                    };
                    let (ri, wi) = inbound.into_split();
                    let (ru, wu) = upstream.into_split();
                    tokio::spawn(pump(ri, wu, p.clone(), born));
                    tokio::spawn(pump(ru, wi, p, born));
                });
            }
        });
        (proxy, port)
    }

    /// Point the name at `target`. Established connections stay on the old node; with
    /// `freeze` they stop delivering anything.
    fn flip(&self, target: SocketAddr, freeze: bool) {
        *self.target.lock().unwrap() = target;
        let g = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        if freeze {
            self.frozen_before.store(g, Ordering::SeqCst);
        }
    }
}

async fn pump(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    proxy: Arc<Proxy>,
    born: u64,
) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        if born < proxy.frozen_before.load(Ordering::SeqCst) {
            continue;
        }
        if to.write_all(&buf[..n]).await.is_err() {
            return;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// A fake store node: SET [NX|XX] [EX], WAIT, ROLE, PING, GET; anything else +OK.

#[derive(Default)]
struct Node {
    replica: AtomicBool,
    /// What WAIT answers on this node while it is a primary.
    acks: AtomicI64,
    keys: Mutex<HashSet<String>>,
}

impl Node {
    async fn start(replica: bool, acks: i64) -> (Arc<Self>, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let node = Arc::new(Self {
            replica: AtomicBool::new(replica),
            acks: AtomicI64::new(acks),
            keys: Mutex::new(HashSet::new()),
        });
        let n = node.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                tokio::spawn(n.clone().serve(sock));
            }
        });
        (node, addr)
    }

    fn has(&self, key: &str) -> bool {
        self.keys.lock().unwrap().contains(key)
    }

    async fn serve(self: Arc<Self>, sock: TcpStream) {
        let (r, mut w) = sock.into_split();
        let mut r = BufReader::new(r);
        loop {
            let Some(args) = read_command(&mut r).await else {
                return;
            };
            let reply = self.answer(&args);
            if w.write_all(reply.as_bytes()).await.is_err() {
                return;
            }
        }
    }

    fn answer(&self, args: &[String]) -> String {
        let cmd = args
            .first()
            .map(|c| c.to_ascii_uppercase())
            .unwrap_or_default();
        let replica = self.replica.load(Ordering::SeqCst);
        match cmd.as_str() {
            "PING" => "+PONG\r\n".into(),
            "ROLE" if replica => {
                "*5\r\n$5\r\nslave\r\n$9\r\n127.0.0.1\r\n:6379\r\n$9\r\nconnected\r\n:0\r\n".into()
            }
            "ROLE" => "*3\r\n$6\r\nmaster\r\n:0\r\n*0\r\n".into(),
            "SET" if replica => "-READONLY You can't write against a read only replica.\r\n".into(),
            "SET" => {
                let key = args[1].clone();
                let flags: Vec<String> = args[3..].iter().map(|a| a.to_ascii_uppercase()).collect();
                let mut keys = self.keys.lock().unwrap();
                let exists = keys.contains(&key);
                if flags.iter().any(|f| f == "NX") && exists {
                    return "$-1\r\n".into();
                }
                if flags.iter().any(|f| f == "XX") && !exists {
                    return "$-1\r\n".into();
                }
                keys.insert(key);
                "+OK\r\n".into()
            }
            "WAIT" if replica => "-ERR WAIT cannot be used with replica instances. Please also note that since Redis 4.0 if a replica is configured to be writable (which is not the default) writes to replicas are just local and are not propagated.\r\n".into(),
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

const NETWORK: &str = "testnet-failover";

fn nonce_hash(tag: &str, i: u64) -> Vec<u8> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    Sha256::digest(format!("{tag} {i} {nanos} {}", std::process::id())).to_vec()
}

fn nonce_key(hash: &[u8]) -> String {
    format!("replay:{NETWORK}:{}", hex::encode(hash))
}

/// A cache whose security store (replay check and the WRITE `WAIT` connection) is `security_url`.
async fn gateway(cache_url: &str, security_url: &str, wait_ms: u64) -> ResponseCache {
    ResponseCache::connect(
        cache_url,
        Some(security_url),
        NETWORK.to_string(),
        "lwd.example.com:9067".to_string(),
        250,
        100,
        &HashMap::new(),
    )
    .await
    .unwrap()
    .with_write_wait(
        security_url,
        WriteWaitConfig {
            replicas: 1,
            timeout_ms: wait_ms,
        },
    )
    .await
    .unwrap()
}

/// The gateway's WRITE admission: the replay check, then the replica acknowledgement.
/// Ok(true) = the WRITE may run; Ok(false) = refused as a replay; Err = fail-closed.
async fn admit_write(c: &ResponseCache, hash: &[u8]) -> anyhow::Result<bool> {
    if c.check_replay(hash).await? {
        return Ok(false);
    }
    c.confirm_nonce_replicated(hash).await?;
    Ok(true)
}

/// Promote `new`: it takes over the keys the old primary replicated, the old one turns into a
/// replica (open connections stay), and the name moves.
fn failover(old: &Node, new: &Node, proxy: &Proxy, new_addr: SocketAddr, copy: bool, freeze: bool) {
    if copy {
        let keys = old.keys.lock().unwrap().clone();
        new.keys.lock().unwrap().extend(keys);
    }
    new.acks.store(1, Ordering::SeqCst);
    new.replica.store(false, Ordering::SeqCst);
    old.replica.store(true, Ordering::SeqCst);
    proxy.flip(new_addr, freeze);
}

/// WRITE until one is admitted, refusing everything else; returns how long it took.
async fn until_admitted(c: &ResponseCache, tag: &str, max: Duration) -> Duration {
    let started = Instant::now();
    let mut i = 0;
    loop {
        i += 1;
        let h = nonce_hash(tag, i);
        if let Ok(true) = admit_write(c, &h).await {
            return started.elapsed();
        }
        assert!(started.elapsed() < max, "no WRITE admitted within {max:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn readonly_old_primary_is_left_within_seconds() {
    let (cache_node, cache_addr) = Node::start(false, 0).await;
    let _ = cache_node;
    let (a, a_addr) = Node::start(false, 1).await;
    let (b, b_addr) = Node::start(true, 0).await;
    let (proxy, port) = Proxy::start(a_addr).await;
    let c = gateway(
        &format!("redis://{cache_addr}"),
        &format!("redis://127.0.0.1:{port}"),
        100,
    )
    .await;

    let mut admitted = Vec::new();
    for i in 0..5 {
        let h = nonce_hash("before", i);
        assert!(admit_write(&c, &h).await.unwrap());
        admitted.push(h);
    }

    failover(&a, &b, &proxy, b_addr, true, false);
    let took = until_admitted(&c, "after", Duration::from_secs(10)).await;
    assert!(
        took < Duration::from_secs(3),
        "WRITEs recovered after {took:?}"
    );

    // The open connections were left: the demoted node is not written to any more.
    let h = nonce_hash("settled", 0);
    assert!(admit_write(&c, &h).await.unwrap());
    assert!(b.has(&nonce_key(&h)));
    assert!(!a.has(&nonce_key(&h)));
    // Every WRITE admitted before the failover is a replay after it.
    for h in &admitted {
        assert!(
            !admit_write(&c, h).await.unwrap(),
            "replay accepted after failover"
        );
    }
}

#[tokio::test]
async fn no_new_connection_until_the_name_reaches_the_primary() {
    let (_cache_node, cache_addr) = Node::start(false, 0).await;
    let (a, a_addr) = Node::start(false, 1).await;
    let (b, b_addr) = Node::start(true, 0).await;
    let (proxy, port) = Proxy::start(a_addr).await;
    let c = gateway(
        &format!("redis://{cache_addr}"),
        &format!("redis://127.0.0.1:{port}"),
        100,
    )
    .await;
    assert!(admit_write(&c, &nonce_hash("warm", 0)).await.unwrap());

    // Demoted, but the name still points at it for a while: new connections reach a replica
    // (ROLE slave) and are not used; every WRITE meanwhile fails closed.
    b.acks.store(1, Ordering::SeqCst);
    b.replica.store(false, Ordering::SeqCst);
    a.replica.store(true, Ordering::SeqCst);
    let until = Instant::now() + Duration::from_millis(1500);
    let mut i = 0;
    while Instant::now() < until {
        i += 1;
        let h = nonce_hash("stale-name", i);
        assert!(
            admit_write(&c, &h).await.is_err(),
            "WRITE admitted on a replica"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    proxy.flip(b_addr, false);
    let took = until_admitted(&c, "after-flip", Duration::from_secs(10)).await;
    assert!(
        took < Duration::from_secs(3),
        "WRITEs recovered after {took:?}"
    );
}

#[tokio::test]
async fn nonce_lost_in_the_failover_is_not_confirmed() {
    let (_cache_node, cache_addr) = Node::start(false, 0).await;
    let (a, a_addr) = Node::start(false, 1).await;
    let (b, b_addr) = Node::start(true, 0).await;
    let (proxy, port) = Proxy::start(a_addr).await;
    let c = gateway(
        &format!("redis://{cache_addr}"),
        &format!("redis://127.0.0.1:{port}"),
        100,
    )
    .await;
    assert!(admit_write(&c, &nonce_hash("warm", 0)).await.unwrap());

    // The replay check stored the nonce on the old primary, which fails over before it was
    // replicated: the WAIT connection meets READONLY, moves to the new primary, and must not
    // confirm a nonce that is not there.
    let h = nonce_hash("lost", 0);
    assert!(!c.check_replay(&h).await.unwrap());
    failover(&a, &b, &proxy, b_addr, false, false);
    let err = c
        .confirm_nonce_replicated(&h)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("fail-closed"), "{err}");
    assert!(!b.has(&nonce_key(&h)));
}

#[tokio::test]
async fn short_wait_is_never_admitted() {
    let (_cache_node, cache_addr) = Node::start(false, 0).await;
    // A primary whose replica is gone: WAIT 1 returns 0.
    let (_a, a_addr) = Node::start(false, 0).await;
    let (_proxy, port) = Proxy::start(a_addr).await;
    let c = gateway(
        &format!("redis://{cache_addr}"),
        &format!("redis://127.0.0.1:{port}"),
        30,
    )
    .await;
    for i in 0..5 {
        let err = admit_write(&c, &nonce_hash("short", i)).await.unwrap_err();
        assert!(err.to_string().contains("0 of 1 replica"), "{err}");
    }
}

#[tokio::test]
async fn hung_connection_is_replaced() {
    let (_cache_node, cache_addr) = Node::start(false, 0).await;
    let (_a, a_addr) = Node::start(false, 1).await;
    let (_b, b_addr) = Node::start(false, 1).await;
    let (proxy, port) = Proxy::start(a_addr).await;
    let c = gateway(
        &format!("redis://{cache_addr}"),
        &format!("redis://127.0.0.1:{port}"),
        100,
    )
    .await;
    assert!(admit_write(&c, &nonce_hash("warm", 0)).await.unwrap());

    // The old connections stop answering (no RST); the name points elsewhere.
    proxy.flip(b_addr, true);
    let took = until_admitted(&c, "after-hang", Duration::from_secs(15)).await;
    assert!(
        took < Duration::from_secs(5),
        "WRITEs recovered after {took:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// Real Redis: primary + replica from tests/failover/docker-compose.yml.

async fn redis_cmd(addr: &str, args: &[&str]) -> redis::RedisResult<redis::Value> {
    let client = redis::Client::open(format!("redis://{addr}"))?;
    let mut conn = client.get_multiplexed_async_connection().await?;
    let mut cmd = redis::cmd(args[0]);
    for a in &args[1..] {
        cmd.arg(*a);
    }
    cmd.query_async(&mut conn).await
}

async fn exists(addr: &str, key: &str) -> bool {
    matches!(
        redis_cmd(addr, &["EXISTS", key]).await,
        Ok(redis::Value::Int(1))
    )
}

async fn wait_replica_link(primary: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(redis::Value::Data(info)) = redis_cmd(primary, &["INFO", "replication"]).await {
            let info = String::from_utf8_lossy(&info);
            if info.contains("connected_slaves:1") && info.contains("state=online") {
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "replica never connected to {primary}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test]
async fn real_redis_promotion_under_write_load() {
    if std::env::var("OHTTP_FAILOVER_REDIS").is_err() {
        eprintln!("skipped: set OHTTP_FAILOVER_REDIS=1 with tests/failover/docker-compose.yml up");
        return;
    }
    // Host ports of the two nodes, and the names they use for each other.
    let a = "127.0.0.1:6391";
    let b = "127.0.0.1:6392";
    // Start from the compose state: a primary, b its replica.
    redis_cmd(a, &["REPLICAOF", "NO", "ONE"]).await.unwrap();
    redis_cmd(b, &["REPLICAOF", "redis-a", "6379"])
        .await
        .unwrap();
    wait_replica_link(a).await;

    let (proxy, port) = Proxy::start(a.parse().unwrap()).await;
    let c = Arc::new(
        gateway(
            "redis://127.0.0.1:6379",
            &format!("redis://127.0.0.1:{port}"),
            100,
        )
        .await,
    );

    // 50 WRITEs/s; record every admitted nonce and when the admissions stop and resume.
    let admitted = Arc::new(Mutex::new(Vec::<(Instant, Vec<u8>)>::new()));
    let failed = Arc::new(AtomicU64::new(0));
    // When a WRITE last met the demoted node (READONLY, WAIT refused on a replica).
    let last_on_old = Arc::new(Mutex::new(None::<Instant>));
    let stop = Arc::new(AtomicBool::new(false));
    let load = {
        let (c, admitted, failed, stop) =
            (c.clone(), admitted.clone(), failed.clone(), stop.clone());
        let last_on_old = last_on_old.clone();
        tokio::spawn(async move {
            let mut i = 0;
            let mut tick = tokio::time::interval(Duration::from_millis(20));
            while !stop.load(Ordering::SeqCst) {
                tick.tick().await;
                i += 1;
                let h = nonce_hash("load", i);
                match admit_write(&c, &h).await {
                    Ok(true) => admitted.lock().unwrap().push((Instant::now(), h)),
                    Ok(false) => panic!("fresh nonce reported as a replay"),
                    Err(e) => {
                        let e = e.to_string();
                        if e.contains("READONLY")
                            || e.contains("read only")
                            || e.contains("replica instances")
                        {
                            *last_on_old.lock().unwrap() = Some(Instant::now());
                        }
                        failed.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        })
    };
    tokio::time::sleep(Duration::from_secs(2)).await;
    let before = admitted.lock().unwrap().len();
    assert!(
        before > 50,
        "only {before} WRITEs admitted before the failover"
    );

    // The failover: b promoted, a demoted to b's replica (its clients stay connected and get
    // READONLY), the name moves to b.
    let switched = Instant::now();
    redis_cmd(b, &["REPLICAOF", "NO", "ONE"]).await.unwrap();
    redis_cmd(a, &["REPLICAOF", "redis-b", "6379"])
        .await
        .unwrap();
    proxy.flip(b.parse().unwrap(), false);

    // Recovery: the first WRITE admitted after the switch.
    let deadline = switched + Duration::from_secs(30);
    let recovered = loop {
        if let Some(t) = admitted
            .lock()
            .unwrap()
            .iter()
            .map(|(t, _)| *t)
            .find(|t| *t > switched)
        {
            break t - switched;
        }
        assert!(
            Instant::now() < deadline,
            "no WRITE admitted within 30 s of the failover"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    tokio::time::sleep(Duration::from_secs(2)).await;
    stop.store(true, Ordering::SeqCst);
    load.await.unwrap();
    let left_old = last_on_old
        .lock()
        .unwrap()
        .map(|t| t.saturating_duration_since(switched));
    eprintln!(
        "WRITE recovery after promotion: {recovered:?} (last WRITE on the demoted node {left_old:?}); admitted {}, failed closed {}",
        admitted.lock().unwrap().len(),
        failed.load(Ordering::SeqCst)
    );
    // The demoted node is left at once; admission then waits for the old primary to rejoin as
    // a replica (WAIT 1), which the compose stores do without a sync delay.
    assert!(
        left_old.unwrap_or_default() < Duration::from_secs(3),
        "WRITEs kept reaching the demoted node for {left_old:?}"
    );
    assert!(
        recovered < Duration::from_secs(10),
        "WRITEs recovered after {recovered:?}"
    );

    // No admitted WRITE was lost: every nonce is on the new primary and is refused as a replay.
    let admitted = admitted.lock().unwrap().clone();
    let mut replays_accepted = 0;
    for (_, h) in &admitted {
        assert!(
            exists(b, &nonce_key(h)).await,
            "admitted nonce missing on the new primary"
        );
        if admit_write(&c, h).await.unwrap_or(false) {
            replays_accepted += 1;
        }
    }
    assert_eq!(replays_accepted, 0);
}

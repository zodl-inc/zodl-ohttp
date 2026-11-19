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

//! The retry of a peer `SET NX` that timed out (`ReplayPeers::write_nonce_retrying`) against the
//! test Redis, through a proxy that loses one message of the first `SET NX`: its reply (the
//! nonce was stored, the answer never came), or the command itself (nothing was stored). The
//! retry goes over another connection to the store (`SET key value NX GET`) and tells new from
//! held. Needs the test Redis on 127.0.0.1:6379 (Redis >= 7.0): without it the tests fail, unless
//! `OHTTP_TEST_ALLOW_NO_STORE=1` outside CI (then they return early).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::collections::HashMap;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zodl_ohttp_gateway::cache::{
    LocalReplayCheck, PeerOutcome, ReplayPeers, ResponseCache, WritePolicy, WriteWaitConfig,
};
use zodl_ohttp_gateway::origin::{ReplayPeerMode, RouteClass};

const REDIS: &str = "127.0.0.1:6379";
/// What the proxy does to the next `SET ... NX` it sees (once, on any connection).
const PASS: u8 = 0;
const DROP_REPLY: u8 = 1;
const DROP_REQUEST: u8 = 2;
const DROP_REPLY_AND_CLOSE: u8 = 3;

/// A proxy to the test Redis that loses one message of the next `SET ... NX` (`arm`).
struct Proxy {
    mode: AtomicU8,
    /// How many `SET ... NX` commands in a row `mode` applies to.
    remaining: AtomicU8,
}

impl Proxy {
    async fn start() -> (Arc<Self>, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let proxy = Arc::new(Self {
            mode: AtomicU8::new(PASS),
            remaining: AtomicU8::new(0),
        });
        let p = proxy.clone();
        tokio::spawn(async move {
            let target: SocketAddr = REDIS.parse().unwrap();
            while let Ok((inbound, _)) = listener.accept().await {
                let p = p.clone();
                tokio::spawn(async move {
                    let Ok(upstream) = TcpStream::connect(target).await else {
                        return;
                    };
                    p.serve(inbound, upstream).await;
                });
            }
        });
        (proxy, port)
    }

    fn arm(&self, mode: u8) {
        self.arm_n(mode, 1);
    }

    fn arm_n(&self, mode: u8, n: u8) {
        self.remaining.store(n, Ordering::SeqCst);
        self.mode.store(mode, Ordering::SeqCst);
    }

    /// The mode for the next `SET ... NX` (PASS once used up).
    fn take(&self) -> u8 {
        let mut n = self.remaining.load(Ordering::SeqCst);
        while n > 0 {
            match self
                .remaining
                .compare_exchange(n, n - 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return self.mode.load(Ordering::SeqCst),
                Err(now) => n = now,
            }
        }
        PASS
    }

    /// Forward whole RESP frames both ways: every command is decided on by itself (also within
    /// a pipeline), and its reply is matched to it by order.
    async fn serve(self: Arc<Self>, inbound: TcpStream, upstream: TcpStream) {
        let (mut ri, mut wi) = inbound.into_split();
        let (mut ru, mut wu) = upstream.into_split();
        // Per command forwarded, in order: what to do with its reply.
        let (fate_tx, mut fate_rx) = tokio::sync::mpsc::unbounded_channel::<u8>();
        let me = self.clone();
        let up = tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut chunk = vec![0u8; 16 * 1024];
            loop {
                let n = match ri.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                buf.extend_from_slice(&chunk[..n]);
                while let Some(len) = frame_len(&buf) {
                    let frame: Vec<u8> = buf.drain(..len).collect();
                    let args = command_args(&frame);
                    let set_nx = args.first().is_some_and(|a| a.eq_ignore_ascii_case(b"SET"))
                        && args.iter().skip(3).any(|a| a.eq_ignore_ascii_case(b"NX"));
                    let mut fate = PASS;
                    if set_nx {
                        match me.take() {
                            DROP_REQUEST => continue,
                            m @ (DROP_REPLY | DROP_REPLY_AND_CLOSE) => fate = m,
                            _ => {}
                        }
                    }
                    if fate_tx.send(fate).is_err() || wu.write_all(&frame).await.is_err() {
                        return;
                    }
                }
            }
        });
        let mut buf = Vec::new();
        let mut chunk = vec![0u8; 16 * 1024];
        'conn: loop {
            let n = match ru.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            buf.extend_from_slice(&chunk[..n]);
            while let Some(len) = frame_len(&buf) {
                let frame: Vec<u8> = buf.drain(..len).collect();
                match fate_rx.recv().await.unwrap_or(PASS) {
                    DROP_REPLY => continue,
                    // The reply is lost, and the connection goes away after the client gave up
                    // on it (it is then replaced).
                    DROP_REPLY_AND_CLOSE => {
                        tokio::time::sleep(Duration::from_millis(400)).await;
                        break 'conn;
                    }
                    _ => {}
                }
                if wi.write_all(&frame).await.is_err() {
                    break 'conn;
                }
            }
        }
        up.abort();
    }
}

/// The length of the complete RESP value at the start of `buf`, None while it is incomplete.
fn frame_len(buf: &[u8]) -> Option<usize> {
    fn value(buf: &[u8], at: usize) -> Option<usize> {
        let line = buf
            .get(at..)?
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|p| at + p + 2)?;
        let n = || -> Option<i64> {
            std::str::from_utf8(&buf[at + 1..line - 2])
                .ok()?
                .parse()
                .ok()
        };
        match *buf.get(at)? {
            b'+' | b'-' | b':' | b'_' | b',' | b'#' | b'(' => Some(line),
            b'$' | b'=' | b'!' => match n()? {
                len if len < 0 => Some(line),
                len => {
                    let end = line + len as usize + 2;
                    (buf.len() >= end).then_some(end)
                }
            },
            b'*' | b'~' | b'>' | b'%' => {
                let count = n()?;
                let items = if buf[at] == b'%' { count * 2 } else { count };
                let mut next = line;
                for _ in 0..items.max(0) {
                    next = value(buf, next)?;
                }
                Some(next)
            }
            _ => None,
        }
    }
    value(buf, 0)
}

/// The arguments of a command frame (an array of bulk strings).
fn command_args(frame: &[u8]) -> Vec<Vec<u8>> {
    let mut args = Vec::new();
    let mut rest = frame;
    let next_line = |rest: &[u8]| -> Option<(Vec<u8>, usize)> {
        let p = rest.windows(2).position(|w| w == b"\r\n")?;
        Some((rest[..p].to_vec(), p + 2))
    };
    let Some((head, used)) = next_line(rest) else {
        return args;
    };
    rest = &rest[used..];
    let count: usize = std::str::from_utf8(&head[1..])
        .ok()
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    for _ in 0..count {
        let Some((len_line, used)) = next_line(rest) else {
            break;
        };
        let len: usize = std::str::from_utf8(&len_line[1..])
            .ok()
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        rest = &rest[used..];
        if rest.len() < len + 2 {
            break;
        }
        args.push(rest[..len].to_vec());
        rest = &rest[len + 2..];
    }
    args
}

/// The connection to the test Redis (database 9) the tests use, or None when they are to be
/// skipped: its first connection is bounded (5 s), and a missing store fails the test unless
/// `OHTTP_TEST_ALLOW_NO_STORE=1` and `CI` is not set (then the test returns early, with one
/// line on stderr: the policy of the crate's own store-backed tests).
async fn test_store() -> Option<redis::aio::MultiplexedConnection> {
    let connect = async {
        redis::Client::open(format!("redis://{REDIS}/9"))?
            .get_multiplexed_async_connection()
            .await
    };
    let error = match tokio::time::timeout(Duration::from_secs(5), connect).await {
        Ok(Ok(conn)) => return Some(conn),
        Ok(Err(e)) => e.to_string(),
        Err(_) => "no connection within 5 s".to_string(),
    };
    let ci = std::env::var_os("CI").is_some();
    let allowed = std::env::var("OHTTP_TEST_ALLOW_NO_STORE").is_ok_and(|v| v == "1");
    if !ci && allowed {
        eprintln!("test skipped: the test store {REDIS} is not reachable ({error}) and OHTTP_TEST_ALLOW_NO_STORE=1");
        return None;
    }
    panic!(
        "the test store {REDIS} is not reachable: {error}. Run a Redis there (CI has one as a \
         service), or set OHTTP_TEST_ALLOW_NO_STORE=1 outside CI to skip the tests that need it"
    );
}

fn unique_key(tag: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("replay:testnet-retry:{tag}:{nanos}:{}", std::process::id())
}

/// One peer (database 9 of the test Redis behind the proxy), with two WAIT connections open.
async fn peer(port: u16) -> ReplayPeers {
    let peers = ReplayPeers::connect(
        &[format!("redis://127.0.0.1:{port}/9")],
        "testnet-retry".to_string(),
        250,
        false,
    )
    .await
    .with_mode(ReplayPeerMode::Failover, true)
    .with_wait_conns(
        Some(WriteWaitConfig {
            replicas: 1,
            timeout_ms: 50,
        }),
        2,
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while peers.wait_conns_open() != vec![2] {
        assert!(Instant::now() < deadline, "WAIT connections not open");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    peers
}

async fn exists(store: &mut redis::aio::MultiplexedConnection, key: &str) -> bool {
    redis::cmd("EXISTS")
        .arg(key)
        .query_async::<_, bool>(store)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_lost_reply_of_a_set_nx_that_landed_is_new_on_the_retry() {
    let Some(mut store) = test_store().await else {
        return;
    };
    let (proxy, port) = Proxy::start().await;
    let peers = peer(port).await;
    let key = unique_key("lost-reply");
    proxy.arm(DROP_REPLY);
    assert_eq!(
        peers.write_nonce_retrying(&key, 60).await,
        vec![PeerOutcome::Fresh]
    );
    assert!(exists(&mut store, &key).await);
}

#[tokio::test]
async fn a_lost_set_nx_is_stored_by_the_retry() {
    let Some(mut store) = test_store().await else {
        return;
    };
    let (proxy, port) = Proxy::start().await;
    let peers = peer(port).await;
    let key = unique_key("lost-request");
    proxy.arm(DROP_REQUEST);
    assert_eq!(
        peers.write_nonce_retrying(&key, 60).await,
        vec![PeerOutcome::Fresh]
    );
    assert!(
        exists(&mut store, &key).await,
        "nil on the retry: stored by it"
    );
}

#[tokio::test]
async fn a_nonce_held_by_another_request_is_a_replay_on_the_retry() {
    let Some(mut store) = test_store().await else {
        return;
    };
    let (proxy, port) = Proxy::start().await;
    let peers = peer(port).await;
    let key = unique_key("held");
    let _: () = redis::cmd("SET")
        .arg(&key)
        .arg("1")
        .arg("EX")
        .arg(60)
        .query_async(&mut store)
        .await
        .unwrap();
    proxy.arm(DROP_REPLY);
    assert_eq!(
        peers.write_nonce_retrying(&key, 60).await,
        vec![PeerOutcome::Replay]
    );
}

#[tokio::test]
async fn the_retry_works_while_the_main_connection_is_replaced() {
    let Some(_store) = test_store().await else {
        return;
    };
    let (proxy, port) = Proxy::start().await;
    let peers = peer(port).await;
    let key = unique_key("replaced");
    proxy.arm(DROP_REPLY_AND_CLOSE);
    assert_eq!(
        peers.write_nonce_retrying(&key, 60).await,
        vec![PeerOutcome::Fresh]
    );
    // The main connection was lost with the reply; once replaced, the next nonce goes through it.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let next = unique_key("after-replacement");
        if peers.write_nonce(&next, 60).await == vec![PeerOutcome::Fresh] {
            break;
        }
        assert!(Instant::now() < deadline, "main connection not replaced");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Without a WAIT pool (REPLAY_PEER_WAIT_REPLICAS=0) the retry goes over the peer's own retry
/// connection.
#[tokio::test]
async fn the_retry_works_without_a_wait_pool() {
    let Some(mut store) = test_store().await else {
        return;
    };
    let (proxy, port) = Proxy::start().await;
    let peers = ReplayPeers::connect(
        &[format!("redis://127.0.0.1:{port}/9")],
        "testnet-retry-nowait".to_string(),
        250,
        false,
    )
    .await
    .with_mode(ReplayPeerMode::Failover, true)
    .with_wait(None);
    // The retry connection opens in the background.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let key = unique_key("no-wait-pool");
    proxy.arm(DROP_REPLY);
    assert_eq!(
        peers.write_nonce_retrying(&key, 60).await,
        vec![PeerOutcome::Fresh]
    );
    assert!(exists(&mut store, &key).await);
}

/// `sync` mode with REPLAY_PEER_FAIL_CLOSED=1: a peer whose `SET NX` timed out on the check is
/// asked again once the request is classified, and the request runs once it took the nonce
/// (a READ as well as a WRITE).
#[tokio::test]
async fn a_strict_sync_peer_that_timed_out_is_retried_after_classification() {
    let Some(_store) = test_store().await else {
        return;
    };
    let (proxy, port) = Proxy::start().await;
    let network = "testnet-retry-strict";
    let peers = ReplayPeers::connect(
        &[format!("redis://127.0.0.1:{port}/9")],
        network.to_string(),
        250,
        true,
    )
    .await
    .with_mode(ReplayPeerMode::Sync, true)
    .with_wait(None);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let security = format!("redis://{REDIS}/10");
    let c = ResponseCache::connect(
        &format!("redis://{REDIS}/0"),
        Some(security.as_str()),
        network.to_string(),
        "lwd.example.com:9067".to_string(),
        250,
        100,
        &HashMap::new(),
    )
    .await
    .unwrap()
    .with_replay_peers(peers);
    // First without a lost message: the same check twice is a replay. (A lost reply leaves the
    // main connection one reply behind, so this runs before the proxy loses any.)
    let hash = unique_key("strict-replay").into_bytes();
    let first = c.check_replay_detailed(&hash).await.unwrap();
    assert_eq!(first.verdict(), LocalReplayCheck::New);
    let again = c.check_replay_detailed(&hash).await.unwrap();
    assert_eq!(again.verdict(), LocalReplayCheck::Replay);
    for (tag, class) in [
        ("strict-read", RouteClass::Read),
        ("strict-write", RouteClass::Write),
    ] {
        let hash = unique_key(tag).into_bytes();
        proxy.arm(DROP_REPLY);
        let local = c.check_replay_detailed(&hash).await.unwrap();
        assert_eq!(
            local.verdict(),
            LocalReplayCheck::NewPeersUnconfirmed,
            "{tag}"
        );
        let check = c
            .replicate_nonce_checked(&local, class, WritePolicy::BOTH_STORES)
            .await
            .unwrap();
        assert!(!check.replay(), "{tag}");
    }
}

/// The retry's own reply is lost too: the outcome stays `Timeout` (fail-closed), the WAIT
/// connection the retry used is replaced, and the pool is whole and usable again afterwards.
#[tokio::test]
async fn a_retry_without_an_answer_replaces_its_connection() {
    let Some(_store) = test_store().await else {
        return;
    };
    let (proxy, port) = Proxy::start().await;
    let peers = peer(port).await;
    let key = unique_key("retry-lost");
    proxy.arm_n(DROP_REPLY, 2);
    assert_eq!(
        peers.write_nonce_retrying(&key, 60).await,
        vec![PeerOutcome::Timeout]
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while peers.wait_conns_open() != vec![2] {
        assert!(Instant::now() < deadline, "not reopened");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    proxy.arm(DROP_REPLY);
    assert_eq!(
        peers
            .write_nonce_retrying(&unique_key("retry-after"), 60)
            .await,
        vec![PeerOutcome::Fresh]
    );
}

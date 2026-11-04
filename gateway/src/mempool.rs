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

//! Mempool fan-out: one upstream `GetMempoolStream` per process per network, re-broadcast to every
//! subscriber.
//!
//! lightwalletd's `GetMempoolStream` sends the transactions in the mempool, then each new one
//! as it arrives, and closes the stream when a new block is mined. The gateway keeps those
//! semantics for the client while holding a single upstream stream per block interval: the
//! session's replay buffer (`singleflight::Shared`) holds every gRPC frame seen since the
//! session started, so a late subscriber first gets the transactions already seen in the
//! current interval and then follows live. Every subscriber's stream ends when the upstream
//! stream ends (lightwalletd's close at the new block, an error) or when the chain follower
//! reports a new tip; the next subscriber opens a fresh upstream stream.
//!
//! Each subscriber is also a long poll in the ZIP's sense ("Long-poll handling"): it is closed
//! with `grpc-status: 0` once nothing arrived for `LONG_POLL_IDLE_SECS` after at least one
//! transaction, after `LONG_POLL_MAX_INITIAL_SILENCE_SECS` without any, or after `LWD_TIMEOUT_SECS`
//! in any case (limits set by `with_limits`; `new` has none). The shared upstream stream stays open
//! for the other subscribers.

use crate::block_cache::GrpcSplitter;
use crate::chain::BlockListener;
use crate::chunked_stream::UpFrame;
use crate::singleflight::{RpcResponse, Shared};
use crate::store::Tip;
use anyhow::Result;
use bytes::Bytes;
use futures_util::future::BoxFuture;
use futures_util::{Stream, StreamExt};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

pub const GET_MEMPOOL_STREAM_PATH: &str =
    "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetMempoolStream";

/// Where the upstream stream comes from: lightwalletd, or a fake in tests.
pub trait MempoolSource: Send + Sync {
    /// Open one `GetMempoolStream`; its body ends when lightwalletd closes it.
    fn open(&self) -> BoxFuture<'static, Result<RpcResponse>>;
}

#[derive(Clone, Debug)]
enum Item {
    /// One whole gRPC frame (a RawTransaction).
    Frame(Bytes),
    /// The end of the session: the trailers every subscriber gets.
    End(Vec<(String, String)>),
}

struct Session {
    id: u64,
    shared: Arc<Shared<Item>>,
    task: tokio::task::AbortHandle,
}

pub struct MempoolFanout {
    source: Arc<dyn MempoolSource>,
    network: String,
    session: parking_lot::Mutex<Option<Arc<Session>>>,
    next_id: AtomicU64,
    /// Upstream streams opened (tests).
    opened: AtomicU64,
    /// A subscriber's idle cut after its first transaction.
    idle: Option<Duration>,
    /// Maximum silence before the first transaction (GW-SILENCE: ends cleanly).
    max_initial_silence: Option<Duration>,
    /// Overall cap (upstream timeout).
    max: Option<Duration>,
}

fn end_ok() -> Item {
    Item::End(vec![("grpc-status".to_string(), "0".to_string())])
}

fn end_err(code: &str, message: String) -> Item {
    Item::End(vec![
        ("grpc-status".to_string(), code.to_string()),
        ("grpc-message".to_string(), message),
    ])
}

impl MempoolFanout {
    pub fn new(source: Arc<dyn MempoolSource>, network: String) -> Self {
        Self {
            source,
            network,
            session: parking_lot::Mutex::new(None),
            next_id: AtomicU64::new(1),
            opened: AtomicU64::new(0),
            idle: None,
            max_initial_silence: None,
            max: None,
        }
    }

    /// The long-poll limits of every subscriber: closed with `grpc-status: 0` after `max_initial_silence`
    /// if no message arrives (GW-SILENCE: prevents relay timeout), after `idle` without a transaction
    /// (once one was sent), and after `max` in any case.
    pub fn with_limits(
        mut self,
        max_initial_silence: Duration,
        idle: Duration,
        max: Duration,
    ) -> Self {
        self.max_initial_silence = Some(max_initial_silence);
        self.idle = Some(idle);
        self.max = Some(max);
        self
    }

    pub fn upstream_opened(&self) -> u64 {
        self.opened.load(Ordering::SeqCst)
    }

    pub fn has_session(&self) -> bool {
        self.session
            .lock()
            .as_ref()
            .is_some_and(|s| !s.shared.is_done())
    }

    /// The live session, or a new one.
    fn session(self: &Arc<Self>) -> Arc<Session> {
        let mut guard = self.session.lock();
        if let Some(s) = guard.as_ref() {
            if !s.shared.is_done() {
                return s.clone();
            }
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let shared: Arc<Shared<Item>> = Arc::new(Shared::default());
        self.opened.fetch_add(1, Ordering::SeqCst);
        let this = self.clone();
        let buffer = shared.clone();
        let task = tokio::spawn(async move {
            let reason = this.run_upstream(&buffer).await;
            buffer.finish();
            crate::health::record_mempool_upstream_ended(&this.network, reason);
            let mut guard = this.session.lock();
            if guard.as_ref().is_some_and(|s| s.id == id) {
                *guard = None;
            }
        });
        let session = Arc::new(Session {
            id,
            shared,
            task: task.abort_handle(),
        });
        *guard = Some(session.clone());
        session
    }

    /// Forward one upstream stream into `buffer`, whole frames only. Returns the end reason.
    async fn run_upstream(&self, buffer: &Arc<Shared<Item>>) -> &'static str {
        crate::health::record_upstream_call(&self.network, "GetMempoolStream");
        debug!(network = %self.network, "mempool fan-out: opening upstream stream");
        let resp = match self.source.open().await {
            Ok(r) => r,
            Err(e) => {
                warn!(network = %self.network, error = %e, "mempool upstream call failed");
                buffer.push(end_err("14", format!("upstream unavailable: {e}")));
                return "error";
            }
        };
        if resp.status != 200 {
            buffer.push(end_err(
                "14",
                format!("upstream answered HTTP {}", resp.status),
            ));
            return "error";
        }
        if let Some(status) = resp
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("grpc-status"))
            .map(|(_, v)| v.clone())
        {
            // Trailers-only response.
            let trailers: Vec<(String, String)> = resp
                .headers
                .into_iter()
                .filter(|(k, _)| k.to_ascii_lowercase().starts_with("grpc-"))
                .collect();
            buffer.push(Item::End(trailers));
            return if status == "0" {
                "upstream_end"
            } else {
                "error"
            };
        }
        let mut splitter = GrpcSplitter::default();
        let mut trailers: Vec<(String, String)> = Vec::new();
        let mut body = resp.body;
        while let Some(frame) = body.next().await {
            match frame {
                Ok(UpFrame::Data(d)) => {
                    for f in splitter.push(&d) {
                        buffer.push(Item::Frame(f));
                    }
                }
                Ok(UpFrame::Trailers(t)) => trailers.extend(t),
                Err(e) => {
                    warn!(network = %self.network, error = %e, "mempool upstream stream failed");
                    buffer.push(end_err("13", format!("upstream stream failed: {e}")));
                    return "stream_error";
                }
            }
        }
        if !trailers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("grpc-status"))
        {
            trailers.push(("grpc-status".to_string(), "0".to_string()));
        }
        buffer.push(Item::End(trailers));
        debug!(network = %self.network, frames = buffer.len(), "mempool fan-out: upstream stream ended");
        "upstream_end"
    }

    /// Subscribe: the frames seen so far in this block interval, then live ones, then the
    /// trailers when the session ends.
    pub fn subscribe(self: &Arc<Self>) -> impl Stream<Item = Result<UpFrame>> + Send + 'static {
        let session = self.session();
        let mut reader = session.shared.reader();
        let network = self.network.clone();
        let (max_initial_silence, idle, max) = (self.max_initial_silence, self.idle, self.max);
        crate::health::record_mempool_subscribers(&network, 1);
        async_stream::stream! {
            let _guard = SubscriberGuard(network);
            let stream_start = tokio::time::Instant::now();
            let deadline = max.map(|m| stream_start + m);
            // GW-SILENCE: Two timeouts: max_initial_silence before first message (25s default to avoid
            // relay timeout), idle after first message (3s default for responsiveness).
            let mut last_frame: Option<tokio::time::Instant> = None;
            let mut ended = false;
            loop {
                let idle_at = match (max_initial_silence, idle, last_frame) {
                    (Some(mis), _, None) => Some(stream_start + mis), // Before first message: max initial silence
                    (_, Some(i), Some(t)) => Some(t + i), // After first message: idle timeout
                    _ => None,
                };
                // Both cuts are checked before reading on: a frame already waiting does not
                // extend a poll whose time is up.
                let now = tokio::time::Instant::now();
                if deadline.is_some_and(|d| now >= d) || idle_at.is_some_and(|i| now >= i) {
                    break;
                }
                let until = match (deadline, idle_at) {
                    (Some(d), Some(i)) => Some(d.min(i)),
                    (d, i) => d.or(i),
                };
                let item = match until {
                    None => reader.next().await,
                    Some(u) => match tokio::time::timeout_at(u, reader.next()).await {
                        Ok(item) => item,
                        // Long-poll cut: what arrived so far, as a success.
                        Err(_) => break,
                    },
                };
                match item {
                    Some(Item::Frame(f)) => {
                        last_frame = Some(tokio::time::Instant::now());
                        yield Ok(UpFrame::Data(f));
                    }
                    Some(Item::End(t)) => {
                        ended = true;
                        yield Ok(UpFrame::Trailers(t));
                        break;
                    }
                    None => break,
                }
            }
            if !ended {
                yield Ok(UpFrame::Trailers(vec![("grpc-status".to_string(), "0".to_string())]));
            }
        }
    }

    /// End the current session (the clients re-subscribe and get a fresh upstream stream).
    pub fn end_session(&self, reason: &'static str) {
        let session = self.session.lock().take();
        if let Some(s) = session {
            if !s.shared.is_done() {
                s.task.abort();
                s.shared.push(end_ok());
                s.shared.finish();
                crate::health::record_mempool_upstream_ended(&self.network, reason);
                info!(network = %self.network, reason, "mempool fan-out session ended");
            }
        }
    }
}

struct SubscriberGuard(String);

impl Drop for SubscriberGuard {
    fn drop(&mut self) {
        crate::health::record_mempool_subscribers(&self.0, -1);
    }
}

impl BlockListener for MempoolFanout {
    fn on_new_block(&self, _tip: &Tip) {
        self.end_session("new_block");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_cache::grpc_frame;
    use std::sync::Mutex;
    use tokio::sync::mpsc;

    /// A fake lightwalletd mempool: the test feeds bytes (possibly partial frames) and ends.
    struct FakeMempool {
        feeds: Mutex<Vec<mpsc::UnboundedSender<Result<UpFrame>>>>,
    }

    impl FakeMempool {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                feeds: Mutex::new(vec![]),
            })
        }
        fn send(&self, bytes: &[u8]) {
            for f in self.feeds.lock().unwrap().iter() {
                let _ = f.send(Ok(UpFrame::Data(Bytes::copy_from_slice(bytes))));
            }
        }
        /// lightwalletd closes the stream (a new block): clean end.
        fn close(&self) {
            for f in self.feeds.lock().unwrap().iter() {
                let _ = f.send(Ok(UpFrame::Trailers(vec![(
                    "grpc-status".to_string(),
                    "0".to_string(),
                )])));
            }
            self.feeds.lock().unwrap().clear();
        }
        fn opened(&self) -> usize {
            self.feeds.lock().unwrap().len()
        }
    }

    impl MempoolSource for FakeMempool {
        fn open(&self) -> BoxFuture<'static, Result<RpcResponse>> {
            let (tx, mut rx) = mpsc::unbounded_channel::<Result<UpFrame>>();
            self.feeds.lock().unwrap().push(tx);
            Box::pin(async move {
                let body = async_stream::stream! {
                    while let Some(item) = rx.recv().await {
                        let end = matches!(&item, Ok(UpFrame::Trailers(_)) | Err(_));
                        yield item;
                        if end {
                            break;
                        }
                    }
                };
                Ok(RpcResponse {
                    status: 200,
                    headers: vec![("content-type".to_string(), "application/grpc".to_string())],
                    body: Box::pin(body),
                })
            })
        }
    }

    fn tx(n: u8) -> Vec<u8> {
        grpc_frame(&[0x0a, 3, n, n, n, 0x10, 0]).to_vec()
    }

    async fn settle() {
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
    }

    /// Collect a subscriber stream: (frames, trailers).
    async fn drain(
        s: impl Stream<Item = Result<UpFrame>> + Send + 'static,
    ) -> (Vec<Vec<u8>>, Vec<(String, String)>) {
        let items: Vec<UpFrame> = s.map(|r| r.unwrap()).collect().await;
        let mut frames = Vec::new();
        let mut trailers = Vec::new();
        for i in items {
            match i {
                UpFrame::Data(d) => frames.push(d.to_vec()),
                UpFrame::Trailers(t) => trailers.extend(t),
            }
        }
        (frames, trailers)
    }

    #[tokio::test]
    async fn two_subscribers_one_upstream_late_joiner_replays_and_all_end_at_the_block() {
        let lwd = FakeMempool::new();
        let fan = Arc::new(MempoolFanout::new(lwd.clone(), "testnet".to_string()));
        let a = tokio::spawn(drain(fan.subscribe()));
        let b = tokio::spawn(drain(fan.subscribe()));
        settle().await;
        assert_eq!(lwd.opened(), 1, "one upstream stream for two subscribers");
        assert_eq!(fan.upstream_opened(), 1);
        // Frames arrive split across reads.
        let t1 = tx(1);
        lwd.send(&t1[..4]);
        lwd.send(&t1[4..]);
        lwd.send(&tx(2));
        settle().await;
        // A late subscriber first gets the two transactions already seen.
        let c = tokio::spawn(drain(fan.subscribe()));
        settle().await;
        lwd.send(&tx(3));
        assert_eq!(lwd.opened(), 1);
        // New block: lightwalletd closes; every subscriber ends with grpc-status 0.
        lwd.close();
        let (fa, ta) = a.await.unwrap();
        let (fb, tb) = b.await.unwrap();
        let (fc, tc) = c.await.unwrap();
        let want = vec![tx(1), tx(2), tx(3)];
        assert_eq!(fa, want);
        assert_eq!(fb, want);
        assert_eq!(fc, want, "late joiner replayed the interval");
        for t in [ta, tb, tc] {
            assert_eq!(t, vec![("grpc-status".to_string(), "0".to_string())]);
        }
        settle().await;
        assert!(!fan.has_session());
        // The next subscriber opens a fresh upstream stream with nothing replayed.
        let d = tokio::spawn(drain(fan.subscribe()));
        settle().await;
        assert_eq!(fan.upstream_opened(), 2);
        lwd.send(&tx(9));
        lwd.close();
        let (fd, _) = d.await.unwrap();
        assert_eq!(fd, vec![tx(9)]);
    }

    #[tokio::test]
    async fn follower_new_block_ends_the_session_and_the_next_subscriber_reconnects() {
        let lwd = FakeMempool::new();
        let fan = Arc::new(MempoolFanout::new(lwd.clone(), "testnet".to_string()));
        let a = tokio::spawn(drain(fan.subscribe()));
        settle().await;
        lwd.send(&tx(5));
        settle().await;
        fan.on_new_block(&Tip {
            height: 10,
            hash: vec![1],
        });
        let (frames, trailers) = a.await.unwrap();
        assert_eq!(frames, vec![tx(5)]);
        assert_eq!(trailers, vec![("grpc-status".to_string(), "0".to_string())]);
        assert!(!fan.has_session());
        // Frames the old upstream still sends go nowhere; a new subscriber gets a new stream.
        lwd.send(&tx(6));
        let b = tokio::spawn(drain(fan.subscribe()));
        settle().await;
        assert_eq!(fan.upstream_opened(), 2);
        lwd.send(&tx(7));
        lwd.close();
        let (frames, _) = b.await.unwrap();
        assert_eq!(frames, vec![tx(7)]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_subscriber_is_cut_after_idle_and_after_initial_silence_while_the_upstream_stays_open(
    ) {
        let lwd = FakeMempool::new();
        let fan = Arc::new(
            MempoolFanout::new(lwd.clone(), "testnet".to_string()).with_limits(
                Duration::from_secs(25),
                Duration::from_secs(3),
                Duration::from_secs(80),
            ),
        );
        // Idle cut: one transaction, then 3 s of silence.
        let a = tokio::spawn(drain(fan.subscribe()));
        settle().await;
        lwd.send(&tx(1));
        settle().await;
        tokio::time::sleep(Duration::from_secs(4)).await;
        let (frames, trailers) = a.await.unwrap();
        assert_eq!(frames, vec![tx(1)]);
        assert_eq!(trailers, vec![("grpc-status".to_string(), "0".to_string())]);
        assert!(fan.has_session(), "the upstream stream is still shared");
        // No transaction at all: no idle cut, the initial-silence cut ends it (the late joiner replays tx 1
        // first, so it is idle-cut too; a quiet session needs a fresh fan-out).
        let quiet = FakeMempool::new();
        let fan = Arc::new(
            MempoolFanout::new(quiet.clone(), "testnet".to_string()).with_limits(
                Duration::from_secs(25),
                Duration::from_secs(3),
                Duration::from_secs(80),
            ),
        );
        let b = tokio::spawn(drain(fan.subscribe()));
        settle().await;
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert!(!b.is_finished(), "no idle cut before the first transaction");
        tokio::time::sleep(Duration::from_secs(71)).await;
        let (frames, trailers) = b.await.unwrap();
        assert!(frames.is_empty());
        assert_eq!(trailers, vec![("grpc-status".to_string(), "0".to_string())]);
        assert_eq!(quiet.opened(), 1);
    }

    #[tokio::test]
    async fn upstream_failure_ends_every_subscriber_with_a_grpc_error() {
        struct Failing;
        impl MempoolSource for Failing {
            fn open(&self) -> BoxFuture<'static, Result<RpcResponse>> {
                Box::pin(async { Err(anyhow::anyhow!("lwd down")) })
            }
        }
        let fan = Arc::new(MempoolFanout::new(Arc::new(Failing), "testnet".to_string()));
        let (frames, trailers) = drain(fan.subscribe()).await;
        assert!(frames.is_empty());
        assert_eq!(trailers[0], ("grpc-status".to_string(), "14".to_string()));
        settle().await;
        assert!(!fan.has_session());
    }
}

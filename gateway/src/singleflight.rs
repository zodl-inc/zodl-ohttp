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

//! Singleflight for upstream calls: identical calls in flight share one upstream request.
//!
//! The call runs in its own task and appends every item to a replay buffer; every joiner reads
//! the buffer from the start, so late joiners see the whole response and a cancelled client
//! never takes the others down. The same buffer is the mempool fan-out's session (one
//! upstream `GetMempoolStream` per process, every subscriber replays what was seen so far).

use crate::chunked_stream::UpFrame;
use anyhow::Result;
use futures_util::future::BoxFuture;
use futures_util::stream::BoxStream;
use futures_util::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Notify;

#[derive(Default)]
struct State<T> {
    items: Vec<T>,
    done: bool,
}

/// A shared, append-only replay buffer with completion.
pub struct Shared<T> {
    state: parking_lot::Mutex<State<T>>,
    notify: Notify,
}

impl<T: Clone> Default for Shared<T> {
    fn default() -> Self {
        Self {
            state: parking_lot::Mutex::new(State {
                items: Vec::new(),
                done: false,
            }),
            notify: Notify::new(),
        }
    }
}

impl<T: Clone> Shared<T> {
    pub fn push(&self, item: T) {
        self.state.lock().items.push(item);
        self.notify.notify_waiters();
    }

    pub fn finish(&self) {
        self.state.lock().done = true;
        self.notify.notify_waiters();
    }

    pub fn is_done(&self) -> bool {
        self.state.lock().done
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.state.lock().items.len()
    }

    /// A reader starting at the first item.
    pub fn reader(self: &Arc<Self>) -> Reader<T> {
        Reader {
            shared: self.clone(),
            idx: 0,
        }
    }
}

/// Reads a [`Shared`] buffer in order, waiting for new items until it is finished.
pub struct Reader<T> {
    shared: Arc<Shared<T>>,
    idx: usize,
}

impl<T: Clone> Reader<T> {
    pub async fn next(&mut self) -> Option<T> {
        loop {
            // Created before the state is read: a notify_waiters() after this point wakes it.
            let notified = self.shared.notify.notified();
            {
                let st = self.shared.state.lock();
                if self.idx < st.items.len() {
                    let item = st.items[self.idx].clone();
                    self.idx += 1;
                    return Some(item);
                }
                if st.done {
                    return None;
                }
            }
            notified.await;
        }
    }
}

/// In-flight calls by key. `T` is the item type of the replay buffer.
pub struct Flights<T> {
    inflight: parking_lot::Mutex<HashMap<String, Arc<Shared<T>>>>,
}

impl<T: Clone + Send + Sync + 'static> Default for Flights<T> {
    fn default() -> Self {
        Self {
            inflight: parking_lot::Mutex::new(HashMap::new()),
        }
    }
}

impl<T: Clone + Send + Sync + 'static> Flights<T> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Join the call under `key`, or start it: `run` is spawned with the buffer to fill and the
    /// buffer is finished and removed when `run` returns. Returns the reader and whether the
    /// caller joined an existing call.
    pub fn join_or_start<F>(self: &Arc<Self>, key: String, run: F) -> (Reader<T>, bool)
    where
        F: FnOnce(Arc<Shared<T>>) -> BoxFuture<'static, ()> + Send + 'static,
    {
        let mut map = self.inflight.lock();
        if let Some(existing) = map.get(&key) {
            return (existing.reader(), true);
        }
        let shared: Arc<Shared<T>> = Arc::new(Shared::default());
        map.insert(key.clone(), shared.clone());
        drop(map);
        let this = self.clone();
        let leader = shared.clone();
        tokio::spawn(async move {
            run(leader.clone()).await;
            this.inflight.lock().remove(&key);
            leader.finish();
        });
        (shared.reader(), false)
    }

    pub fn in_flight(&self) -> usize {
        self.inflight.lock().len()
    }
}

/// One item of a shared upstream RPC call.
#[derive(Clone, Debug)]
pub enum RpcItem {
    /// The response head: HTTP status and the headers (`content-type`, `grpc-*`).
    Head(u16, Vec<(String, String)>),
    Frame(UpFrame),
    /// The call failed before or while streaming.
    Failed(String),
}

/// An upstream RPC answer as the gateway streams it.
pub struct RpcResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: BoxStream<'static, Result<UpFrame>>,
}

/// Where RPCs are sent: lightwalletd, or a fake in tests.
pub trait RpcSource: Send + Sync {
    /// Send `body` to `path`; `request_id` is forwarded for log correlation when known.
    fn call(
        &self,
        path: String,
        body: Vec<u8>,
        request_id: Option<uuid::Uuid>,
    ) -> BoxFuture<'static, Result<RpcResponse>>;

    /// [`Self::call`] with the Client's gRPC request metadata (`lwd::client_grpc_headers`); a
    /// source that has no use for it ignores it.
    fn call_with_headers(
        &self,
        path: String,
        body: Vec<u8>,
        request_id: Option<uuid::Uuid>,
        headers: Vec<(String, String)>,
    ) -> BoxFuture<'static, Result<RpcResponse>> {
        let _ = headers;
        self.call(path, body, request_id)
    }
}

/// Singleflight for lightwalletd RPCs. The leader's task forwards the upstream response into
/// the buffer and, when the response ends cleanly within `limit` bytes, hands the collected
/// inner response to `on_complete` (the cache's write path). Joiners only read.
pub struct RpcFlights {
    flights: Arc<Flights<RpcItem>>,
    source: Arc<dyn RpcSource>,
    network: String,
}

/// The collected response handed to the cache on a clean end.
pub type OnComplete = Box<dyn FnOnce(crate::ohttp::InnerResponse) + Send + 'static>;

impl RpcFlights {
    pub fn new(source: Arc<dyn RpcSource>, network: String) -> Self {
        Self {
            flights: Arc::new(Flights::new()),
            source,
            network,
        }
    }

    pub fn in_flight(&self) -> usize {
        self.flights.in_flight()
    }

    /// Call `path` with `body`, sharing the upstream call with identical ones in flight. The
    /// returned future resolves when the head arrives; the body streams after it. `rpc` is
    /// the metrics label.
    pub async fn call(
        &self,
        rpc: &str,
        path: &str,
        body: Vec<u8>,
        request_id: Option<uuid::Uuid>,
        limit: usize,
        on_complete: Option<OnComplete>,
    ) -> Result<RpcResponse> {
        self.call_with_headers(rpc, path, body, request_id, Vec::new(), limit, on_complete)
            .await
    }

    /// [`Self::call`] with the Client's gRPC request metadata. Only calls with the same metadata
    /// are shared, so one Client's `grpc-timeout` never cuts another Client's answer (a joiner
    /// with the same `grpc-timeout` shares the leader's deadline, which started earlier).
    #[allow(clippy::too_many_arguments)]
    pub async fn call_with_headers(
        &self,
        rpc: &str,
        path: &str,
        body: Vec<u8>,
        request_id: Option<uuid::Uuid>,
        headers: Vec<(String, String)>,
        limit: usize,
        on_complete: Option<OnComplete>,
    ) -> Result<RpcResponse> {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(path.as_bytes());
        h.update([0u8]);
        h.update(&body);
        for (name, value) in &headers {
            h.update([0u8]);
            h.update(name.as_bytes());
            h.update(b":");
            h.update(value.as_bytes());
        }
        let key = hex::encode(h.finalize());

        let source = self.source.clone();
        let network = self.network.clone();
        let rpc_label = rpc.to_string();
        let path_owned = path.to_string();
        let (mut reader, joined) =
            self.flights
                .join_or_start(key, move |shared| -> BoxFuture<'static, ()> {
                    Box::pin(async move {
                        crate::health::record_upstream_call(&network, &rpc_label);
                        let resp = match source
                            .call_with_headers(path_owned, body, request_id, headers)
                            .await
                        {
                            Ok(r) => r,
                            Err(e) => {
                                shared.push(RpcItem::Failed(e.to_string()));
                                return;
                            }
                        };
                        let status = resp.status;
                        let headers = resp.headers.clone();
                        shared.push(RpcItem::Head(status, headers.clone()));
                        let mut body = resp.body;
                        let mut collected: Vec<u8> = Vec::new();
                        let mut trailers: Vec<(String, String)> = Vec::new();
                        let mut over = false;
                        let mut failed = false;
                        while let Some(item) = body.next().await {
                            match item {
                                Ok(frame) => {
                                    match &frame {
                                        UpFrame::Data(d) => {
                                            if !over {
                                                if collected.len() + d.len() > limit {
                                                    over = true;
                                                    collected = Vec::new();
                                                } else {
                                                    collected.extend_from_slice(d);
                                                }
                                            }
                                        }
                                        UpFrame::Trailers(t) => trailers.extend(t.iter().cloned()),
                                    }
                                    shared.push(RpcItem::Frame(frame));
                                }
                                Err(e) => {
                                    failed = true;
                                    shared.push(RpcItem::Failed(e.to_string()));
                                    break;
                                }
                            }
                        }
                        if !failed && !over {
                            if let Some(f) = on_complete {
                                let mut all = headers;
                                all.extend(trailers);
                                f(crate::ohttp::InnerResponse {
                                    status,
                                    headers: all,
                                    body: collected,
                                });
                            }
                        }
                    })
                });
        if joined {
            crate::health::record_singleflight_join(&self.network, rpc);
        }
        match reader.next().await {
            Some(RpcItem::Head(status, headers)) => {
                let body = async_stream::stream! {
                    while let Some(item) = reader.next().await {
                        match item {
                            RpcItem::Frame(f) => yield Ok(f),
                            RpcItem::Failed(e) => {
                                yield Err(anyhow::anyhow!(e));
                                break;
                            }
                            RpcItem::Head(..) => {}
                        }
                    }
                };
                Ok(RpcResponse {
                    status,
                    headers,
                    body: Box::pin(body),
                })
            }
            Some(RpcItem::Failed(e)) => Err(anyhow::anyhow!(e)),
            Some(RpcItem::Frame(_)) | None => {
                Err(anyhow::anyhow!("upstream call ended without a head"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// A fake RPC source answering `path` with its body echoed after a delay.
    pub struct SlowEcho {
        pub calls: AtomicUsize,
        pub delay: std::time::Duration,
        pub seen: Mutex<Vec<String>>,
    }

    impl RpcSource for SlowEcho {
        fn call(
            &self,
            path: String,
            body: Vec<u8>,
            _request_id: Option<uuid::Uuid>,
        ) -> BoxFuture<'static, Result<RpcResponse>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen.lock().unwrap().push(path);
            let delay = self.delay;
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                let stream = async_stream::stream! {
                    yield Ok(UpFrame::Data(Bytes::from(body.clone())));
                    tokio::time::sleep(delay).await;
                    yield Ok(UpFrame::Data(Bytes::from_static(b"-tail")));
                    yield Ok(UpFrame::Trailers(vec![("grpc-status".to_string(), "0".to_string())]));
                };
                Ok(RpcResponse {
                    status: 200,
                    headers: vec![("content-type".to_string(), "application/grpc".to_string())],
                    body: Box::pin(stream),
                })
            })
        }
    }

    async fn collect(resp: RpcResponse) -> (Vec<u8>, Vec<(String, String)>) {
        let mut body = Vec::new();
        let mut trailers = Vec::new();
        let mut s = resp.body;
        while let Some(f) = s.next().await {
            match f.unwrap() {
                UpFrame::Data(d) => body.extend_from_slice(&d),
                UpFrame::Trailers(t) => trailers.extend(t),
            }
        }
        (body, trailers)
    }

    #[tokio::test]
    async fn identical_calls_share_one_upstream_call_and_one_store() {
        let src = Arc::new(SlowEcho {
            calls: AtomicUsize::new(0),
            delay: std::time::Duration::from_millis(30),
            seen: Mutex::new(vec![]),
        });
        let flights = Arc::new(RpcFlights::new(src.clone(), "testnet".to_string()));
        let stored = Arc::new(AtomicUsize::new(0));
        let call = |f: Arc<RpcFlights>, stored: Arc<AtomicUsize>| async move {
            let resp = f
                .call(
                    "GetTreeState",
                    "/x/GetTreeState",
                    b"body".to_vec(),
                    None,
                    1024,
                    Some(Box::new(move |r| {
                        assert_eq!(r.body, b"body-tail");
                        assert_eq!(r.header("grpc-status"), Some("0"));
                        stored.fetch_add(1, Ordering::SeqCst);
                    })),
                )
                .await
                .unwrap();
            collect(resp).await
        };
        let (a, b, c) = tokio::join!(
            call(flights.clone(), stored.clone()),
            call(flights.clone(), stored.clone()),
            call(flights.clone(), stored.clone()),
        );
        for (body, trailers) in [a, b, c] {
            assert_eq!(body, b"body-tail");
            assert_eq!(trailers, vec![("grpc-status".to_string(), "0".to_string())]);
        }
        assert_eq!(src.calls.load(Ordering::SeqCst), 1, "one upstream call");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(stored.load(Ordering::SeqCst), 1, "the leader stores once");
        assert_eq!(flights.in_flight(), 0);

        // A different body is a different call.
        let resp = flights
            .call(
                "GetTreeState",
                "/x/GetTreeState",
                b"other".to_vec(),
                None,
                1024,
                None,
            )
            .await
            .unwrap();
        assert_eq!(collect(resp).await.0, b"other-tail");
        assert_eq!(src.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn late_joiner_replays_from_the_start_and_cancelled_leader_does_not_cut_others() {
        let src = Arc::new(SlowEcho {
            calls: AtomicUsize::new(0),
            delay: std::time::Duration::from_millis(30),
            seen: Mutex::new(vec![]),
        });
        let flights = Arc::new(RpcFlights::new(src.clone(), "testnet".to_string()));
        let first = flights
            .call(
                "GetLightdInfo",
                "/x/GetLightdInfo",
                b"".to_vec(),
                None,
                1024,
                None,
            )
            .await
            .unwrap();
        // The first caller goes away after the head.
        drop(first);
        let second = flights
            .call(
                "GetLightdInfo",
                "/x/GetLightdInfo",
                b"".to_vec(),
                None,
                1024,
                None,
            )
            .await
            .unwrap();
        let (body, _) = collect(second).await;
        assert_eq!(body, b"-tail");
        assert_eq!(src.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn oversized_response_is_streamed_but_not_handed_over() {
        let src = Arc::new(SlowEcho {
            calls: AtomicUsize::new(0),
            delay: std::time::Duration::from_millis(1),
            seen: Mutex::new(vec![]),
        });
        let flights = Arc::new(RpcFlights::new(src, "testnet".to_string()));
        let stored = Arc::new(AtomicUsize::new(0));
        let s = stored.clone();
        let resp = flights
            .call(
                "GetTreeState",
                "/x/GetTreeState",
                vec![7u8; 100],
                None,
                50,
                Some(Box::new(move |_| {
                    s.fetch_add(1, Ordering::SeqCst);
                })),
            )
            .await
            .unwrap();
        let (body, _) = collect(resp).await;
        assert_eq!(body.len(), 105);
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(stored.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn failed_call_is_an_error_for_every_joiner() {
        struct Failing;
        impl RpcSource for Failing {
            fn call(
                &self,
                _: String,
                _: Vec<u8>,
                _: Option<uuid::Uuid>,
            ) -> BoxFuture<'static, Result<RpcResponse>> {
                Box::pin(async {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    Err(anyhow::anyhow!("down"))
                })
            }
        }
        let flights = Arc::new(RpcFlights::new(Arc::new(Failing), "testnet".to_string()));
        let (a, b) = tokio::join!(
            flights.call("Ping", "/x/Ping", vec![], None, 10, None),
            flights.call("Ping", "/x/Ping", vec![], None, 10, None),
        );
        assert!(a.is_err());
        assert!(b.is_err());
    }
}

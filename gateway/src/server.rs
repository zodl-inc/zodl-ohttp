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

//! The HTTP server loop: hyper's HTTP/1.1 connection builder with a timer and a request header
//! read timeout.
//!
//! `axum::serve` (0.8) builds `hyper_util::server::conn::auto::Builder` without a timer, so
//! hyper's `header_read_timeout` (default 30 s) is dropped with a warning and a peer that sends
//! part of a request head, or nothing at all, holds the connection (a file descriptor and a
//! task) for as long as the TCP connection lives. This loop is `axum::serve` with the timer set.
//!
//! What the timeout covers (hyper 1.12, `proto/h1/conn.rs`): the timer is armed when the
//! connection starts waiting for a request head and disarmed when the head has been parsed. It
//! is armed again after every response, so it also bounds the idle time of a keep-alive
//! connection between two requests (hyper: "we can close the connection if another header isn't
//! received in a timely manner"). A connection that expires idle is closed cleanly; one that
//! expires mid-header is closed without a response.
//!
//! Because of the second part, the value MUST be greater than the idle timeout of every proxy
//! that keeps connections to the gateway open: otherwise the gateway closes an idle connection
//! the proxy still considers reusable and the next request on it fails (502 at the edge). The
//! gateway assumes that proxies in front of it close idle connections at or below
//! [`MAX_PROXY_IDLE_TIMEOUT`] (for example a load balancer or TCP proxy configured for 130 s, or
//! reqwest's 90 s pool idle in the relay simulator); a deployment must check its own proxies.
//! With a larger value the proxy always closes first and the gateway never closes a connection
//! the proxy could still reuse. `header_read_timeout_from_env` refuses smaller values.
//!
//! HTTP/1.1 only: `axum::serve` lets hyper-util detect HTTP/1 or HTTP/2 per connection, and that
//! detection (`auto::Builder` without `http1_only`, `ReadVersion`) reads up to 24 bytes before any
//! hyper connection, and therefore any timer, exists, with no deadline of its own. A peer that
//! connects and sends nothing, or only a prefix of the HTTP/2 preface, would never reach the
//! header timer. With `http1_only()` the HTTP/1 connection starts at accept and the timer with
//! it. The gateway therefore expects HTTP/1.1 only: proxies in front of it must forward
//! HTTP/1.1, and reqwest clients using plain `http://` speak HTTP/1.1.

use std::convert::Infallible;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use hyper::body::Incoming;
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tower::Service;
use tracing::{debug, error};

/// Environment variable: request header read timeout in seconds; `0` disables it.
pub const HEADER_READ_TIMEOUT_ENV: &str = "HEADER_READ_TIMEOUT_SECS";

/// Default request header read timeout (also the keep-alive idle bound, see the module docs).
pub const DEFAULT_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(300);

/// The largest idle timeout assumed for proxies that keep connections to the gateway open (for
/// example a load balancer or TCP proxy configured for 130 s). The header read timeout must stay
/// above it (module docs).
pub const MAX_PROXY_IDLE_TIMEOUT: Duration = Duration::from_secs(130);

/// `HEADER_READ_TIMEOUT_SECS` from the environment: unset = the default, `0` = disabled, a
/// value at or below [`MAX_PROXY_IDLE_TIMEOUT`] is a configuration error.
pub fn header_read_timeout_from_env() -> anyhow::Result<Option<Duration>> {
    parse_header_read_timeout(std::env::var(HEADER_READ_TIMEOUT_ENV).ok().as_deref())
}

/// The parser behind [`header_read_timeout_from_env`].
pub fn parse_header_read_timeout(raw: Option<&str>) -> anyhow::Result<Option<Duration>> {
    let Some(raw) = raw else {
        return Ok(Some(DEFAULT_HEADER_READ_TIMEOUT));
    };
    let secs: u64 = raw
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("{HEADER_READ_TIMEOUT_ENV}={raw:?}: {e}"))?;
    if secs == 0 {
        return Ok(None);
    }
    let timeout = Duration::from_secs(secs);
    if timeout <= MAX_PROXY_IDLE_TIMEOUT {
        anyhow::bail!(
            "{HEADER_READ_TIMEOUT_ENV}={secs}: must be greater than {} s, the idle timeout of the \
             proxies in front of the gateway (hyper's header read timeout also closes idle \
             keep-alive connections; a smaller value makes the proxies reuse \
             connections the gateway has already closed)",
            MAX_PROXY_IDLE_TIMEOUT.as_secs()
        );
    }
    Ok(Some(timeout))
}

/// Environment variable: the address the internal server (`/health*`, `/metrics`) binds.
pub const INTERNAL_BIND_ADDR_ENV: &str = "INTERNAL_BIND_ADDR";

/// Port of the internal server when [`INTERNAL_BIND_ADDR_ENV`] gives only an IP address.
pub const INTERNAL_PORT: u16 = 9090;

/// Default internal bind address: all interfaces, port 9090 (Prometheus scrapes it from other
/// hosts).
pub const DEFAULT_INTERNAL_BIND_ADDR: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
    INTERNAL_PORT,
);

/// The internal server's bind address from [`INTERNAL_BIND_ADDR_ENV`] (unset or empty =
/// [`DEFAULT_INTERNAL_BIND_ADDR`]).
pub fn internal_bind_addr_from_env() -> anyhow::Result<SocketAddr> {
    parse_internal_bind_addr(std::env::var(INTERNAL_BIND_ADDR_ENV).ok().as_deref())
}

/// The parser behind [`internal_bind_addr_from_env`]: `IP` (port 9090) or `IP:port`
/// (`[v6]:port` for IPv6).
pub fn parse_internal_bind_addr(raw: Option<&str>) -> anyhow::Result<SocketAddr> {
    let raw = match raw.map(str::trim) {
        None | Some("") => return Ok(DEFAULT_INTERNAL_BIND_ADDR),
        Some(r) => r,
    };
    if let Ok(addr) = raw.parse::<SocketAddr>() {
        return Ok(addr);
    }
    raw.parse::<std::net::IpAddr>()
        .map(|ip| SocketAddr::new(ip, INTERNAL_PORT))
        .map_err(|_| {
            anyhow::anyhow!("{INTERNAL_BIND_ADDR_ENV}={raw:?}: expected an IP address or IP:port")
        })
}

/// Serve `make_service` on `listener` forever, one task per connection, HTTP/1.1 only (module
/// docs), with `header_read_timeout` armed from accept (`None` = no timeout, the previous
/// behaviour).
///
/// `make_service` is called with the peer address: `Router::into_make_service()` and
/// `Router::into_make_service_with_connect_info::<SocketAddr>()` both fit (the latter makes
/// `ConnectInfo<SocketAddr>` extractable).
pub async fn serve<M, S>(
    listener: TcpListener,
    mut make_service: M,
    header_read_timeout: Option<Duration>,
) -> io::Result<()>
where
    M: Service<SocketAddr, Response = S, Error = Infallible>,
    S: Service<Request<Incoming>, Response = axum::response::Response, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    loop {
        let (stream, remote_addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                handle_accept_error(e).await;
                continue;
            }
        };

        poll_fn(|cx| make_service.poll_ready(cx))
            .await
            .unwrap_or_else(|never| match never {});
        let service = make_service
            .call(remote_addr)
            .await
            .unwrap_or_else(|never| match never {});

        tokio::spawn(async move {
            // `http1_only`: no protocol detection phase, the HTTP/1 connection (and its timer)
            // starts at accept. The timer is what makes `header_read_timeout` take effect (hyper
            // panics on a configured timeout without one and drops the default with a warning).
            let mut builder = auto::Builder::new(TokioExecutor::new()).http1_only();
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(header_read_timeout);

            let io = TokioIo::new(stream);
            if let Err(err) = builder
                .serve_connection(io, TowerToHyperService::new(service))
                .await
            {
                // A header read timeout on a partial head ends here as hyper's "read header
                // from client timeout"; an idle keep-alive expiry closes cleanly (no error).
                debug!(peer = %remote_addr, error = %err, "connection ended with an error");
            }
        });
    }
}

/// `axum::serve`'s accept error handling: connection-level errors are skipped, anything else
/// (for example EMFILE) is logged and the loop waits a second before accepting again.
async fn handle_accept_error(e: io::Error) {
    if matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    ) {
        return;
    }
    error!("accept error: {e}");
    tokio::time::sleep(Duration::from_secs(1)).await;
}

#[cfg(test)]
mod tests {
    #[test]
    fn internal_bind_addr_default_and_overrides() {
        let d: SocketAddr = "0.0.0.0:9090".parse().unwrap();
        assert_eq!(
            parse_internal_bind_addr(None).unwrap(),
            d,
            "default unchanged"
        );
        assert_eq!(parse_internal_bind_addr(Some("")).unwrap(), d);
        assert_eq!(
            parse_internal_bind_addr(Some("127.0.0.1")).unwrap(),
            "127.0.0.1:9090".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_internal_bind_addr(Some("10.0.0.5:9191")).unwrap(),
            "10.0.0.5:9191".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_internal_bind_addr(Some("::1")).unwrap(),
            "[::1]:9090".parse::<SocketAddr>().unwrap()
        );
        assert!(parse_internal_bind_addr(Some("localhost")).is_err());
        assert!(parse_internal_bind_addr(Some("1.2.3.4:x")).is_err());
    }

    use super::*;
    use axum::routing::get;
    use axum::Router;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// Short enough for a test, long enough for a loaded CI runner.
    const TIMEOUT: Duration = Duration::from_millis(500);

    const REQUEST: &[u8] = b"GET /healthz HTTP/1.1\r\nHost: gateway.example\r\n\r\n";

    async fn start(header_read_timeout: Option<Duration>) -> SocketAddr {
        let app = Router::new().route("/healthz", get(|| async { "ok" }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
            header_read_timeout,
        ));
        addr
    }

    fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    /// One HTTP/1.1 response (head + `content-length` body); `None` if the peer closed first.
    async fn read_response(stream: &mut TcpStream) -> Option<Vec<u8>> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            if let Some(end) = find(&buf, b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
                let len = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .map(|value| value.trim().parse::<usize>().unwrap())
                    .unwrap_or(0);
                if buf.len() >= end + 4 + len {
                    return Some(buf);
                }
            }
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// `Ok(0)` (EOF) or an error (reset): the server closed the connection.
    fn is_closed(read: io::Result<usize>) -> bool {
        matches!(read, Ok(0) | Err(_))
    }

    #[tokio::test]
    async fn partial_headers_are_cut_at_the_timeout_not_before() {
        let addr = start(Some(TIMEOUT)).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        // A request line and one header, never the end of the head.
        client
            .write_all(b"POST /gateway HTTP/1.1\r\nHost: gateway.example\r\n")
            .await
            .unwrap();
        let mut byte = [0u8; 1];

        // Well inside the timeout the connection is still open: the read is pending.
        let early = tokio::time::timeout(TIMEOUT / 2, client.read(&mut byte)).await;
        assert!(
            early.is_err(),
            "connection closed before the header read timeout: {early:?}"
        );

        // Then the server closes it (no response: hyper sends nothing for a header timeout).
        let late = tokio::time::timeout(TIMEOUT * 4, client.read(&mut byte))
            .await
            .expect("connection still open long after the header read timeout");
        assert!(is_closed(late), "unexpected bytes from the server");
    }

    #[tokio::test]
    async fn a_silent_connection_and_an_h2_preface_prefix_are_cut_at_the_timeout() {
        let addr = start(Some(TIMEOUT)).await;
        // Nothing at all: with protocol detection (`axum::serve`) no timer ran here.
        let mut silent = TcpStream::connect(addr).await.unwrap();
        // One byte that is also the start of the HTTP/2 preface ("PRI * HTTP/2.0..."): protocol
        // detection would wait for the other 23 bytes; the HTTP/1 parser sees a partial head.
        let mut preface = TcpStream::connect(addr).await.unwrap();
        preface.write_all(b"P").await.unwrap();
        let mut byte = [0u8; 1];

        let early = tokio::time::timeout(TIMEOUT / 2, silent.read(&mut byte)).await;
        assert!(
            early.is_err(),
            "silent connection closed before the timeout: {early:?}"
        );
        let late = tokio::time::timeout(TIMEOUT * 4, silent.read(&mut byte))
            .await
            .expect("silent connection still open long after the timeout");
        assert!(is_closed(late), "unexpected bytes from the server");

        let late = tokio::time::timeout(TIMEOUT * 4, preface.read(&mut byte))
            .await
            .expect("preface prefix connection still open long after the timeout");
        assert!(is_closed(late), "unexpected bytes from the server");
    }

    #[tokio::test]
    async fn keep_alive_idle_below_the_timeout_is_kept_and_above_it_is_closed() {
        let addr = start(Some(TIMEOUT)).await;
        let mut client = TcpStream::connect(addr).await.unwrap();

        client.write_all(REQUEST).await.unwrap();
        let first = read_response(&mut client).await.expect("first response");
        assert!(first.starts_with(b"HTTP/1.1 200"), "{first:?}");

        // Idle for less than the timeout (every proxy in front of the gateway reuses a
        // connection only within its own, smaller, idle timeout): the same connection serves
        // the next request.
        tokio::time::sleep(TIMEOUT / 2).await;
        client.write_all(REQUEST).await.unwrap();
        let second = read_response(&mut client)
            .await
            .expect("second response on the kept connection");
        assert!(second.starts_with(b"HTTP/1.1 200"), "{second:?}");

        // Idle beyond the timeout: hyper closes the connection. This is the reason the value
        // must exceed the proxies' idle timeouts (`MAX_PROXY_IDLE_TIMEOUT`).
        tokio::time::sleep(TIMEOUT * 2).await;
        let mut byte = [0u8; 1];
        let closed = tokio::time::timeout(TIMEOUT * 2, client.read(&mut byte))
            .await
            .expect("connection still open long after the idle expiry");
        assert!(is_closed(closed), "unexpected bytes from the server");
    }

    #[tokio::test]
    async fn without_a_timeout_a_partial_head_is_kept_open() {
        // `None` is the behaviour before this module: nothing closes the connection.
        let addr = start(None).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"POST /gateway HTTP/1.1\r\n")
            .await
            .unwrap();
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(TIMEOUT * 2, client.read(&mut byte)).await;
        assert!(
            read.is_err(),
            "connection closed without a timeout: {read:?}"
        );
    }

    #[test]
    fn env_value_is_parsed_and_bounded() {
        assert_eq!(
            parse_header_read_timeout(None).unwrap(),
            Some(DEFAULT_HEADER_READ_TIMEOUT)
        );
        assert_eq!(parse_header_read_timeout(Some("0")).unwrap(), None);
        assert_eq!(
            parse_header_read_timeout(Some(" 131 ")).unwrap(),
            Some(Duration::from_secs(131))
        );
        assert!(DEFAULT_HEADER_READ_TIMEOUT > MAX_PROXY_IDLE_TIMEOUT);
        // At or below the proxies' idle timeout: refused (idle connections would be closed
        // under the proxies).
        assert!(parse_header_read_timeout(Some("130")).is_err());
        assert!(parse_header_read_timeout(Some("30")).is_err());
        assert!(parse_header_read_timeout(Some("abc")).is_err());
        assert!(parse_header_read_timeout(Some("-1")).is_err());
    }
}

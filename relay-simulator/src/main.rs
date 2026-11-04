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

// OHTTP relay simulator
//
// Simulates a production relay's behavior for RFC 9458 OHTTP.
//
// RFC 9458 Flow:
//   1. Client encapsulates request with HPKE (using gateway's public key)
//   2. Client sends encrypted blob to relay /relay endpoint
//   3. Relay forwards encrypted blob to gateway (oblivious to content)
//   4. Gateway decrypts, proxies to backend, encrypts response
//   5. Relay returns encrypted response to client
//   6. Client decrypts response
//
// Key property: Relay NEVER decrypts - it's oblivious to request content.
// This provides IP address privacy (gateway doesn't see client IP).

use axum::{
    body::{Body, Bytes},
    extract::State,
    extract::{ConnectInfo, DefaultBodyLimit},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use futures::stream::TryStreamExt;
use prometheus::{Encoder, HistogramVec, IntCounterVec, IntGaugeVec, Opts, Registry, TextEncoder};
use reqwest::Client;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

mod request_id;

lazy_static::lazy_static! {
    static ref REGISTRY: Registry = Registry::new();

    static ref RELAY_REQUESTS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("relay_requests_total", "Total relay requests by network and status"),
        &["network", "gateway_status"]
    )
    .unwrap();

    static ref RELAY_REQUEST_DURATION_SECONDS: HistogramVec = HistogramVec::new(
        prometheus::HistogramOpts::new("relay_request_duration_seconds", "Relay request duration in seconds")
            .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]),
        &["network"]
    )
    .unwrap();

    static ref RELAY_REQUESTS_IN_FLIGHT: IntGaugeVec = IntGaugeVec::new(
        Opts::new("relay_requests_in_flight", "Current relay requests in flight by network"),
        &["network"]
    )
    .unwrap();
}

fn init_metrics() {
    REGISTRY
        .register(Box::new(RELAY_REQUESTS_TOTAL.clone()))
        .ok();
    REGISTRY
        .register(Box::new(RELAY_REQUEST_DURATION_SECONDS.clone()))
        .ok();
    REGISTRY
        .register(Box::new(RELAY_REQUESTS_IN_FLIGHT.clone()))
        .ok();
}

struct RelayState {
    gateway_url: String,
    gateway_configs_url: String,
    relay_secret: String,
    client: Client,
    network: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()))
        .json()
        .init();

    init_metrics();

    let gateway_url =
        std::env::var("GATEWAY_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());
    let gateway_configs_url =
        std::env::var("GATEWAY_CONFIGS_URL").unwrap_or_else(|_| derive_configs_url(&gateway_url));
    let relay_secret =
        std::env::var("RELAY_SECRET").expect("RELAY_SECRET must be set (no default for security)");
    let network = std::env::var("NETWORK").unwrap_or_else(|_| "mainnet".to_string());
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8081".to_string())
        .parse::<u16>()?;

    // Client MUST NOT follow redirects. A malicious gateway could redirect the relay, with its
    // relay secret and the client's sealed request, to an attacker-controlled server. The relay
    // must return whatever the gateway returns, including 3xx responses, without following
    // Location headers.
    // ZIP "Relay behaviour": at least 120 s for the first byte, and a read timeout rather than a
    // total one, so a long stream is never cut while the gateway keeps sending.
    let client = Client::builder()
        .read_timeout(Duration::from_secs(120))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    info!(
        network = %network,
        gateway_url = %gateway_url,
        gateway_configs_url = %gateway_configs_url,
        port = port,
        "Relay simulator starting"
    );

    let state = Arc::new(RelayState {
        gateway_url,
        gateway_configs_url,
        relay_secret,
        client,
        network,
    });

    // ZIP conformance: ≥10 MiB request body limit (L609-611)
    let app = Router::new()
        .route("/relay", post(relay_handler))
        .route("/ohttp-configs", get(ohttp_configs_handler))
        .route("/ohttp-configs/signed", get(ohttp_configs_signed_handler))
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024)) // 10 MiB
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    info!(port = port, "Relay simulator listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn relay_handler(
    State(state): State<Arc<RelayState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let start = Instant::now();
    let network = state.network.clone();

    // Track in-flight requests
    RELAY_REQUESTS_IN_FLIGHT
        .with_label_values(&[&network])
        .inc();
    let _guard = scopeguard::guard((), |_| {
        RELAY_REQUESTS_IN_FLIGHT
            .with_label_values(&[&network])
            .dec();
    });

    // Validate Content-Type before proceeding (RFC 9458 §3, draft-ietf-ohai-chunked-ohttp-08)
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if content_type != "message/ohttp-chunked-req" {
        warn!(
            content_type = %content_type,
            "Relay received request with invalid Content-Type (expected message/ohttp-chunked-req)"
        );
        RELAY_REQUESTS_TOTAL
            .with_label_values(&[&network, "415"])
            .inc();
        return Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be message/ohttp-chunked-req".to_string(),
        ));
    }

    // Generate request_id (UUIDv4) — the relay ALWAYS generates this, never accepts from client.
    // If a client sends X-Request-Id, log at debug and drop it.
    if headers.get("x-request-id").is_some() || headers.get("X-Request-Id").is_some() {
        debug!("Dropping client-supplied X-Request-Id (relay generates its own)");
    }
    let request_id = Uuid::new_v4();

    // Extract and validate optional X-Client-Trace-Id from client (for debugging).
    // Privacy note: This is OPT-IN. A custom client_trace_id links the relay's view (client IP)
    // with the gateway's view (request content) for debugging. Do not use in regular traffic.
    let client_trace_id = request_id::extract_client_trace_id(&headers);
    if (headers.get("x-client-trace-id").is_some() || headers.get("X-Client-Trace-Id").is_some())
        && client_trace_id.is_none()
    {
        debug!("Dropping invalid X-Client-Trace-Id");
    }

    // RFC 9458 Section 3: Relay Operation
    // The relay receives an HPKE-encrypted Binary HTTP request from the client
    // and forwards it to the gateway WITHOUT decrypting it.
    // This provides IP address privacy - the gateway never sees the client's IP.
    //
    // The relay is the ONLY hop that learns the client address. Log it here (it is what an
    // independent relay operator would see) and never forward it: the request built below
    // carries no X-Forwarded-For / CF-Connecting-IP / X-Real-IP.
    let hdr = |n: &str| {
        headers
            .get(n)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
            .to_string()
    };
    let client_ip = hdr("cf-connecting-ip");
    let xff = hdr("x-forwarded-for");
    let bytes_in = body.len();

    if let Some(ref trace_id) = client_trace_id {
        info!(
            request_id = %request_id,
            client_trace_id = %trace_id,
            client_ip = %client_ip,
            xff = %xff,
            peer = %peer,
            bytes_in = bytes_in,
            network = %network,
            "Relay received request"
        );
    } else {
        info!(
            request_id = %request_id,
            client_ip = %client_ip,
            xff = %xff,
            peer = %peer,
            bytes_in = bytes_in,
            network = %network,
            "Relay received request"
        );
    }

    if body.is_empty() {
        warn!(request_id = %request_id, "Relay received empty body");
        RELAY_REQUESTS_TOTAL
            .with_label_values(&[&network, "400"])
            .inc();
        RELAY_REQUEST_DURATION_SECONDS
            .with_label_values(&[&network])
            .observe(start.elapsed().as_secs_f64());
        return Err((StatusCode::BAD_REQUEST, "Empty request body".to_string()));
    }

    // Forward the encrypted blob to the gateway
    // RFC 9458 §3.5: relay MUST strip all client-identifying headers and forward only:
    // - Content-Type (already validated as message/ohttp-chunked-req)
    // - Content-Length (set by reqwest)
    // - X-Relay-Secret (authentication)
    // - X-Request-Id (relay-generated correlation ID)
    // - X-Client-Trace-Id (opt-in debug identifier, if valid)
    // - User-Agent (fixed relay identifier)
    let mut req_builder = state
        .client
        .post(&state.gateway_url)
        .header("X-Relay-Secret", &state.relay_secret)
        .header("X-Request-Id", request_id.to_string())
        .header("Content-Type", content_type)
        .header("User-Agent", "zodl-ohttp-relay-simulator/1.0");

    if let Some(ref trace_id) = client_trace_id {
        req_builder = req_builder.header("X-Client-Trace-Id", trace_id);
    }

    let response = req_builder.body(body.to_vec()).send().await.map_err(|e| {
        error!(
            request_id = %request_id,
            error = %e,
            network = %network,
            "Relay failed to forward to gateway"
        );
        RELAY_REQUESTS_TOTAL
            .with_label_values(&[&network, "502"])
            .inc();
        RELAY_REQUEST_DURATION_SECONDS
            .with_label_values(&[&network])
            .observe(start.elapsed().as_secs_f64());
        (
            StatusCode::BAD_GATEWAY,
            format!("Gateway connection failed: {}", e),
        )
    })?;

    let gateway_status = response.status();
    let gateway_status_u16 = gateway_status.as_u16();
    let gateway_status_str = gateway_status_u16.to_string();

    // Extract response headers before moving response (for header filtering later)
    let response_cache_control = response.headers().get("cache-control").cloned();
    let response_retry_after = response.headers().get("retry-after").cloned();

    if !gateway_status.is_success() {
        let error_body = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        error!(
            request_id = %request_id,
            gateway_status = gateway_status_u16,
            error = %error_body,
            network = %network,
            "Relay: gateway returned error"
        );
        RELAY_REQUESTS_TOTAL
            .with_label_values(&[&network, &gateway_status_str])
            .inc();
        RELAY_REQUEST_DURATION_SECONDS
            .with_label_values(&[&network])
            .observe(start.elapsed().as_secs_f64());
        // The gateway's status with the headers a Relay forwards (ZIP "Relay behaviour" rule 3):
        // Retry-After is the back-off hint of a 429/503.
        let mut error_headers = HeaderMap::new();
        error_headers.insert("content-type", "text/plain".parse().unwrap());
        if let Some(cache_control) = response_cache_control {
            error_headers.insert("cache-control", cache_control);
        }
        if let Some(retry_after) = response_retry_after {
            error_headers.insert("retry-after", retry_after);
        }
        return Ok((gateway_status, error_headers, Body::from(error_body)));
    }

    // Stream the gateway's encrypted response to the client WITHOUT collecting it
    let response_stream = response.bytes_stream().map_err(std::io::Error::other);
    let response_body = Body::from_stream(response_stream);

    let duration_ms = start.elapsed().as_millis() as u64;
    if let Some(ref trace_id) = client_trace_id {
        info!(
            request_id = %request_id,
            client_trace_id = %trace_id,
            bytes_in = bytes_in,
            gateway_status = gateway_status_u16,
            duration_ms = duration_ms,
            network = %network,
            client_ip = %client_ip,
            "Relay request completed"
        );
    } else {
        info!(
            request_id = %request_id,
            bytes_in = bytes_in,
            gateway_status = gateway_status_u16,
            duration_ms = duration_ms,
            network = %network,
            client_ip = %client_ip,
            "Relay request completed"
        );
    }

    RELAY_REQUESTS_TOTAL
        .with_label_values(&[&network, &gateway_status_str])
        .inc();
    RELAY_REQUEST_DURATION_SECONDS
        .with_label_values(&[&network])
        .observe(start.elapsed().as_secs_f64());

    // Return with proper OHTTP response content type
    // RFC 9458 §3.5: relay MUST forward ONLY:
    // - Content-Type (message/ohttp-chunked-res)
    // - Content-Length (set by axum when known; absent on a streamed body)
    // - Cache-Control (if present)
    // - Retry-After (if present)
    // Drop everything else (cf-*, server, set-cookie, alt-svc, nel, report-to, etc.)
    let mut response_headers = HeaderMap::new();
    response_headers.insert("Content-Type", "message/ohttp-chunked-res".parse().unwrap());

    // Forward Cache-Control if present (typically "private, no-store" for OHTTP responses)
    if let Some(cache_control) = response_cache_control {
        response_headers.insert("cache-control", cache_control);
    }

    // Forward Retry-After if present (back-off hint on 429/503)
    if let Some(retry_after) = response_retry_after {
        response_headers.insert("retry-after", retry_after);
    }

    Ok((StatusCode::OK, response_headers, response_body))
}

async fn health() -> impl IntoResponse {
    StatusCode::OK
}

async fn metrics() -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();

    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        warn!("Failed to encode metrics: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to encode metrics",
        )
            .into_response();
    }

    let output = String::from_utf8(buffer).unwrap_or_else(|_| "# Encoding error\n".to_string());
    (StatusCode::OK, output).into_response()
}

/// Derive the configs URL from the gateway URL by replacing the path with /ohttp-configs
fn derive_configs_url(gateway_url: &str) -> String {
    if let Ok(mut url) = reqwest::Url::parse(gateway_url) {
        url.set_path("/ohttp-configs");
        url.set_query(None);
        url.to_string()
    } else {
        // Fallback: append /ohttp-configs if parse fails
        format!("{}/ohttp-configs", gateway_url.trim_end_matches('/'))
    }
}

/// Handler for GET /ohttp-configs - serves the gateway's OHTTP key config via the relay
async fn ohttp_configs_handler(
    State(state): State<Arc<RelayState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    forward_config_get(&state, state.gateway_configs_url.clone()).await
}

/// Handler for GET /ohttp-configs/signed - serves signed OHTTP key config via the relay
async fn ohttp_configs_signed_handler(
    State(state): State<Arc<RelayState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    forward_config_get(&state, format!("{}/signed", state.gateway_configs_url)).await
}

/// GET `url` at the gateway (with the relay secret, as on every path of the gateway origins) and
/// return its answer unchanged
/// (ZIP "Relay behaviour": a relay does not cache and forwards these GETs as they are): the
/// gateway's status and body, streamed, and of its headers the ones a Relay forwards (rule 3:
/// `Content-Type`, `Content-Length`, every `Cache-Control` field, `Retry-After`; `Location` and
/// the rest are dropped).
async fn forward_config_get(
    state: &RelayState,
    url: String,
) -> Result<(StatusCode, HeaderMap, Body), (StatusCode, String)> {
    let request_id = Uuid::new_v4();
    info!(
        request_id = %request_id,
        url = %url,
        network = %state.network,
        "Fetching key configuration from gateway"
    );

    let response = state
        .client
        .get(&url)
        .header("X-Relay-Secret", &state.relay_secret)
        .send()
        .await
        .map_err(|e| {
            error!(
                request_id = %request_id,
                error = %e,
                "Failed to fetch key configuration from gateway"
            );
            (
                StatusCode::BAD_GATEWAY,
                format!("Failed to fetch config: {}", e),
            )
        })?;

    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut response_headers = HeaderMap::new();
    for name in ["content-type", "content-length", "retry-after"] {
        if let Some(value) = response.headers().get(name) {
            response_headers.insert(name, value.clone());
        }
    }
    for cache_control in response.headers().get_all("cache-control") {
        response_headers.append("cache-control", cache_control.clone());
    }
    info!(
        request_id = %request_id,
        gateway_status = status.as_u16(),
        "Forwarding key configuration from gateway"
    );
    Ok((
        status,
        response_headers,
        Body::from_stream(response.bytes_stream()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_configs_url() {
        assert_eq!(
            derive_configs_url("http://localhost:8080/gateway"),
            "http://localhost:8080/ohttp-configs"
        );
        assert_eq!(
            derive_configs_url("https://gateway.example.com/relay"),
            "https://gateway.example.com/ohttp-configs"
        );
        assert_eq!(
            derive_configs_url("https://gateway.example.com:8443/gateway?foo=bar"),
            "https://gateway.example.com:8443/ohttp-configs"
        );
    }

    #[test]
    fn test_request_headers_allowlist() {
        // Request to gateway MUST include only:
        // - Content-Type: message/ohttp-chunked-req
        // - Content-Length (set by HTTP client)
        // - X-Relay-Secret
        // - X-Request-Id (relay-generated UUIDv4)
        // - X-Client-Trace-Id (if valid)
        // - User-Agent (fixed relay identifier)
        //
        // This test documents the allowlist; actual filtering is in relay_handler.
        let allowed = vec![
            "content-type",
            "content-length",
            "x-relay-secret",
            "x-request-id",
            "x-client-trace-id",
            "user-agent",
        ];

        let stripped = vec![
            "cf-connecting-ip",
            "x-forwarded-for",
            "x-real-ip",
            "forwarded",
            "cookie",
            "authorization",
            "accept-language",
            "referer",
            "origin",
            "dnt",
            "sec-ch-ua",
        ];

        // Assert that the lists are disjoint
        for header in &allowed {
            assert!(
                !stripped.contains(header),
                "Header '{}' is in both allowed and stripped lists",
                header
            );
        }
    }

    #[test]
    fn test_response_headers_allowlist() {
        // Response from gateway to client MUST include only:
        // - Content-Type
        // - Content-Length (set by HTTP server when known)
        // - Cache-Control
        // - Retry-After
        //
        // This test documents the allowlist; actual filtering is in relay_handler.
        let allowed = vec![
            "content-type",
            "content-length",
            "cache-control",
            "retry-after",
        ];

        let stripped = vec![
            "set-cookie",
            "alt-svc",
            "location",
            "link",
            "cf-ray",
            "cf-cache-status",
            "nel",
            "report-to",
            "server",
            "via",
            "x-served-by",
            "x-cache",
            "date",
            "vary",
            "www-authenticate",
            "access-control-allow-origin",
        ];

        // Assert that the lists are disjoint
        for header in &allowed {
            assert!(
                !stripped.contains(header),
                "Header '{}' is in both allowed and stripped lists",
                header
            );
        }
    }
}

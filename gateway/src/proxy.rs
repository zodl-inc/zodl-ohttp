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

// gRPC proxy — Forward inner requests to the lightwalletd backend over h2c.
//
// gRPC responses carry their status in HTTP/2 trailers. Because OHTTP is strictly
// request/response, the whole (possibly streaming) gRPC response is buffered and the
// trailers are folded into the header list of the InnerResponse so that the client can
// read `grpc-status` from the Binary HTTP header section.

use crate::dynamic_hosts::{DynamicHost, PublicResolver};
use crate::{config::Config, ohttp::InnerRequest, ohttp::InnerResponse, AppState};
use anyhow::{anyhow, Result};
use axum::{body::Bytes, extract::State, http::StatusCode, response::IntoResponse};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_tls::HttpsConnector;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioTimer},
};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// How long an idle connection to a third-party HTTPS backend is kept for reuse: 30 s, well
/// below the 60 s idle timeout common for servers and load balancers, so the gateway drops an
/// idle connection before the server closes it. With equal timeouts a request could be written
/// to a connection the server is closing at that moment and fail.
const BACKEND_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Idle connections kept per third-party backend host.
const BACKEND_POOL_MAX_IDLE_PER_HOST: usize = 16;

type BackendClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Client settings of the shared third-party backend pool, independent of the connector.
fn backend_pool_builder() -> hyper_util::client::legacy::Builder {
    let mut builder = Client::builder(TokioExecutor::new());
    builder
        .pool_timer(TokioTimer::new())
        .pool_idle_timeout(BACKEND_POOL_IDLE_TIMEOUT)
        .pool_max_idle_per_host(BACKEND_POOL_MAX_IDLE_PER_HOST);
    builder
}

/// The one client for all `https://` third-party backends, built on first use.
///
/// Connections are pooled per scheme and authority, so a request reuses an idle connection to
/// the same backend instead of a new TCP and TLS handshake. The connector is the default
/// `hyper_tls::HttpsConnector` (system roots, no ALPN, so HTTP/1.1). Headers, timeouts and
/// credentials stay per request; a response body dropped before its end closes its connection
/// instead of returning it to the pool.
fn https_backend_client() -> &'static BackendClient {
    static CLIENT: OnceLock<BackendClient> = OnceLock::new();
    CLIENT.get_or_init(|| backend_pool_builder().build(HttpsConnector::new()))
}

type DynamicBackendClient = Client<HttpsConnector<HttpConnector<PublicResolver>>, Full<Bytes>>;

/// The client for dynamic hosts (`DYNAMIC_HOST_SOURCES`): HTTPS only, and its connector gets
/// only the public addresses a host name resolves to ([`PublicResolver`]), so a listed name
/// that resolves to a private, loopback or link-local address is never connected to. The
/// connector does not resolve an address literal; a literal host is admitted only when it is
/// a public IPv4 address (when it is listed, and again in [`resolve_backend_in`]). Its pool is
/// separate from the static backends' pool. Like that one it follows no redirect.
fn dynamic_backend_client() -> &'static DynamicBackendClient {
    static CLIENT: OnceLock<DynamicBackendClient> = OnceLock::new();
    CLIENT.get_or_init(|| {
        let mut http = HttpConnector::new_with_resolver(PublicResolver);
        http.enforce_http(false);
        let mut https = HttpsConnector::new_with_connector(http);
        https.https_only(true);
        backend_pool_builder().build(https)
    })
}

/// The dynamic host an inner authority (lowercase) names, if any. Static configuration wins:
/// a `BACKENDS` alias or a `GATEWAY_HOSTS` name is never a dynamic host.
pub fn dynamic_host(config: &Config, authority_lower: &str) -> Option<Arc<DynamicHost>> {
    if config.backends.contains_key(authority_lower)
        || is_gateway_host(authority_lower, &config.gateway_hosts)
    {
        return None;
    }
    config.dynamic_hosts.lookup(authority_lower)
}

/// The dynamic-host view of one inner request, read from the served set exactly once.
///
/// The OHTTP handler resolves it before the replay stages and hands it to everything that
/// follows (replay class, policy, labels, logged route, limits, the forward itself), so one
/// request never mixes two versions of the dynamic hosts when a refresh swaps the set while
/// it is being handled. A request whose host is removed meanwhile completes on the entry it
/// holds.
#[derive(Clone, Default)]
pub struct RouteContext {
    dynamic: Option<Arc<DynamicHost>>,
    /// The `THIRD_PARTY_QUERY_RULES` verdict taken once for this request
    /// ([`RouteContext::with_query_verdict`]); `None`: evaluated where needed.
    query_admitted: Option<bool>,
}

impl RouteContext {
    /// Read the served set for `inner_request`'s authority. Static configuration wins: the
    /// context holds no entry for a `BACKENDS` alias or a `GATEWAY_HOSTS` name.
    pub fn resolve(config: &Config, inner_request: &InnerRequest) -> Self {
        Self {
            dynamic: dynamic_host(config, &inner_request.authority.to_ascii_lowercase()),
            query_admitted: None,
        }
    }

    /// Take the `THIRD_PARTY_QUERY_RULES` verdict for `inner_request` now, with the source lists
    /// of this moment, so that every later check of the request (the handler's precheck, the
    /// collected and the streamed forward) uses the same one: a list replaced meanwhile can
    /// neither admit a request the precheck refused (an upstream call past the cap) nor refuse
    /// one it admitted (a spent cap call for an inner 403).
    pub fn with_query_verdict(mut self, config: &Config, inner_request: &InnerRequest) -> Self {
        self.query_admitted = Some(config.third_party_query_rules.admits(
            &inner_request.authority,
            &inner_request.method,
            &inner_request.path,
        ));
        self
    }

    /// The dynamic host the request is for, if any.
    pub fn dynamic(&self) -> Option<&Arc<DynamicHost>> {
        self.dynamic.as_ref()
    }

    /// For a request to a dynamic host: whether it is a READ for the replay check, by that
    /// host's lists alone (`REPLAY_READ_ROUTES` names static authorities and is not consulted).
    /// `None`: not a dynamic host.
    pub fn dynamic_read(&self, inner_request: &InnerRequest) -> Option<bool> {
        self.dynamic
            .as_ref()
            .map(|host| host.is_read_route(&inner_request.method, &inner_request.path))
    }

    /// The replay class of the request, for every replay stage: for a dynamic host what its
    /// lists say ([`RouteContext::dynamic_read`]), and never `read_routes`, which names static
    /// authorities (and matches hosts without their port, so an entry for a static alias must
    /// not decide for a dynamic host of the same name on another port); for anything else
    /// `read_routes` (`REPLAY_READ_ROUTES`).
    pub fn replay_class(
        &self,
        read_routes: &crate::origin::ReadRoutes,
        is_lwd: bool,
        inner_request: &InnerRequest,
    ) -> crate::origin::RouteClass {
        match self.dynamic_read(inner_request) {
            Some(true) => crate::origin::RouteClass::Read,
            Some(false) => crate::origin::RouteClass::Write,
            None => read_routes.classify(
                is_lwd,
                &inner_request.authority,
                &inner_request.method,
                &inner_request.path,
            ),
        }
    }

    /// Whether a WRITE may run on one replay store's verdict (`REPLAY_ONE_SIDED_WRITE_ROUTES`,
    /// `routes`): never for a dynamic host.
    pub fn one_sided_write(
        &self,
        routes: &crate::origin::ReadRoutes,
        is_lwd: bool,
        inner_request: &InnerRequest,
    ) -> bool {
        self.dynamic.is_none()
            && routes.matches(
                is_lwd,
                &inner_request.authority,
                &inner_request.method,
                &inner_request.path,
            )
    }

    /// The `backend` metric label: `dynamic:<source>` for a dynamic host (bounded by the
    /// configured sources, never the host name), else [`crate::health::normalize_backend`].
    pub fn backend_label(&self, config: &Config, authority: &str) -> String {
        match &self.dynamic {
            Some(host) => host.label.clone(),
            None => {
                crate::health::normalize_backend(authority, &config.gateway_hosts, &config.backends)
            }
        }
    }
}

/// [`RouteContext::backend_label`] for a request that has no context yet.
#[allow(dead_code)]
pub fn backend_label(config: &Config, authority: &str) -> String {
    RouteContext {
        dynamic: dynamic_host(config, &authority.to_ascii_lowercase()),
        query_admitted: None,
    }
    .backend_label(config, authority)
}

/// Track the end offset of the last complete gRPC message in a buffer.
/// gRPC framing: 1 byte compressed flag + 4 bytes big-endian length + payload.
/// Returns the offset after the last complete message (0 if no complete messages).
pub(crate) fn last_complete_grpc_message_offset(buf: &[u8]) -> usize {
    let mut offset = 0;
    while offset + 5 <= buf.len() {
        let length = u32::from_be_bytes([
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
            buf[offset + 4],
        ]) as usize;
        let message_end = offset + 5 + length;
        if message_end <= buf.len() {
            offset = message_end;
        } else {
            // Message is incomplete, return offset before it
            break;
        }
    }
    offset
}

/// Count complete gRPC messages in a buffer up to the given offset.
pub(crate) fn count_grpc_messages(buf: &[u8], up_to: usize) -> usize {
    let mut count = 0;
    let mut offset = 0;
    while offset + 5 <= up_to && offset + 5 <= buf.len() {
        let length = u32::from_be_bytes([
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
            buf[offset + 4],
        ]) as usize;
        let message_end = offset + 5 + length;
        if message_end <= up_to {
            count += 1;
            offset = message_end;
        } else {
            break;
        }
    }
    count
}

/// The `BACKENDS_POLICY` entry of `policies` that admits `method` and `path`, if any.
///
/// Path matching semantics:
/// - EXACT unless entry ends with /*
/// - GET /v0/tokens matches only /v0/tokens (query OK), NOT /v0/tokens/extra or /v0/tokensX
/// - GET /rounds/* matches /rounds/<anything> (segment-bounded)
/// - GET /* matches everything
fn matching_rule<'a>(
    policies: &'a [(String, String)],
    method: &str,
    path: &str,
) -> Option<&'a (String, String)> {
    policies
        .iter()
        .find(|(allowed_method, allowed_path_prefix)| {
            // Method wildcard: * matches any method
            let method_matches =
                allowed_method == "*" || method.eq_ignore_ascii_case(allowed_method);
            method_matches
                && if let Some(prefix_without_wildcard) = allowed_path_prefix.strip_suffix("/*") {
                    // Wildcard case: /foo/* matches /foo/bar but NOT /foobar; /* matches everything
                    prefix_without_wildcard.is_empty()
                        || path == prefix_without_wildcard
                        || path.starts_with(&format!("{}/", prefix_without_wildcard))
                } else {
                    // Exact match: the prefix, or prefix + query string (no path extension)
                    path == allowed_path_prefix.as_str()
                        || path.starts_with(&format!("{}?", allowed_path_prefix))
                }
        })
}

/// The path of a `BACKENDS` (third-party) request as logged: the path pattern of the policy entry
/// that admitted it (`/v0/status`, `/commerce_sessions/*`), so that the logs keep the route but
/// not the query or the resource ids in the path (deposit addresses, session ids). One no entry
/// admits (refused with the inner 403) is logged as `(not in policy)`; a request to the
/// gateway's own hosts with its path (lightwalletd RPC names); one to any other authority as
/// `(unknown authority)`.
#[allow(dead_code)]
pub fn loggable_route(config: &Config, inner_request: &InnerRequest) -> String {
    loggable_route_in(
        config,
        inner_request,
        &RouteContext::resolve(config, inner_request),
    )
}

/// [`loggable_route`] in the request's [`RouteContext`]: a request to a dynamic host is logged
/// by its list's route pattern even after a refresh removed the host.
pub fn loggable_route_in(
    config: &Config,
    inner_request: &InnerRequest,
    route: &RouteContext,
) -> String {
    let authority = inner_request.authority.to_ascii_lowercase();
    if let Some(host) = route.dynamic() {
        return matching_rule(&host.routes, &inner_request.method, &inner_request.path)
            .map(|(_, pattern)| pattern.clone())
            .unwrap_or_else(|| "(not in policy)".to_string());
    }
    if !config.backends.contains_key(&authority) {
        // The light client server's paths are RPC names. A path sent to any other authority
        // (unknown, or a dynamic host this process does not serve) may carry resource ids.
        return if config.gateway_hosts.is_empty()
            || is_gateway_host(&inner_request.authority, &config.gateway_hosts)
        {
            inner_request.path.clone()
        } else {
            "(unknown authority)".to_string()
        };
    }
    config
        .backends_policy
        .get(&authority)
        .and_then(|policies| matching_rule(policies, &inner_request.method, &inner_request.path))
        .map(|(_, pattern)| pattern.clone())
        .unwrap_or_else(|| "(not in policy)".to_string())
}

/// The `rpc` metric label of `inner_request`: for a `BACKENDS` (third-party) request the method
/// and path pattern of the policy entry that admits it (`GET /v0/status`, `* /*`), so that the
/// label names the operation while its values stay bounded by the configuration (never the
/// request's own path, query or resource ids); `other` when no entry admits it. Any other
/// request: [`crate::health::normalize_rpc_name`].
#[allow(dead_code)]
pub fn rpc_label(config: &Config, inner_request: &InnerRequest) -> String {
    rpc_label_in(
        config,
        inner_request,
        &RouteContext::resolve(config, inner_request),
    )
}

/// [`rpc_label`] in the request's [`RouteContext`].
pub fn rpc_label_in(config: &Config, inner_request: &InnerRequest, route: &RouteContext) -> String {
    let authority = inner_request.authority.to_ascii_lowercase();
    if let Some(host) = route.dynamic() {
        return matching_rule(&host.routes, &inner_request.method, &inner_request.path)
            .map(|(method, pattern)| format!("{} {pattern}", method.to_ascii_uppercase()))
            .unwrap_or_else(|| "other".to_string());
    }
    if !config.backends.contains_key(&authority) {
        return crate::health::normalize_rpc_name(&inner_request.path, &inner_request.method);
    }
    config
        .backends_policy
        .get(&authority)
        .and_then(|policies| matching_rule(policies, &inner_request.method, &inner_request.path))
        .map(|(method, pattern)| format!("{} {pattern}", method.to_ascii_uppercase()))
        .unwrap_or_else(|| "other".to_string())
}

/// Paths no policy admits: directory traversal, encoded dots, double slashes.
fn path_trick(path: &str) -> Option<&'static str> {
    // Reject paths with directory traversal or encoding tricks
    if path.contains("..") || path.contains("%2e") || path.contains("%2E") {
        return Some("path contains directory traversal");
    }
    // Reject paths with double slashes (beyond the first byte; bytes, since the path is not
    // validated yet and may start with a multi-byte character)
    if path
        .as_bytes()
        .get(1..)
        .is_some_and(|rest| rest.windows(2).any(|w| w == b"//"))
    {
        return Some("path contains double slashes");
    }
    None
}

/// The request-side path rejections ([`path_trick`], [`validate_path`]) for a
/// `THIRD_PARTY_QUERY_RULES` rule path, checked at startup.
pub(crate) fn rule_path_rejection(path: &str) -> Option<&'static str> {
    path_trick(path).or_else(|| validate_path(path))
}

/// Whether a dynamic host's routes refuse `method path`: `None` if allowed, `Some(reason)` if
/// not. Only the routes of the host's list count; `BACKENDS_POLICY_DEFAULT` never applies.
fn check_dynamic_policy(host: &DynamicHost, method: &str, path: &str) -> Option<&'static str> {
    if let Some(reason) = path_trick(path) {
        return Some(reason);
    }
    if matching_rule(&host.routes, method, path).is_some() {
        None
    } else {
        Some("operation not in the dynamic host's routes")
    }
}

/// The policy verdict for a request the forwarder resolved: the routes of `dynamic` when the
/// authority is a dynamic host, the `BACKENDS_POLICY` of a `BACKENDS` alias otherwise.
fn route_denial(
    config: &Config,
    dynamic: Option<&DynamicHost>,
    query_admitted: Option<bool>,
    inner_request: &InnerRequest,
) -> Option<&'static str> {
    if let Some(host) = dynamic {
        return check_dynamic_policy(host, &inner_request.method, &inner_request.path);
    }
    if !config
        .backends
        .contains_key(&inner_request.authority.to_ascii_lowercase())
    {
        return None;
    }
    check_operation_policy_with(
        config,
        &inner_request.authority,
        &inner_request.method,
        &inner_request.path,
        query_admitted,
    )
}

/// Check if a request matches the per-alias operation policy and, for a route with a
/// `THIRD_PARTY_QUERY_RULES` entry, its query rule.
/// Returns None if allowed, Some(reason) if denied.
///
/// A policy may allow every method on `/*` for a host whose protocol is public and for which the
/// Gateway injects no credential; credential-carrying aliases should have exact entries.
fn check_operation_policy(
    config: &Config,
    authority: &str,
    method: &str,
    path: &str,
) -> Option<&'static str> {
    check_operation_policy_with(config, authority, method, path, None)
}

/// [`check_operation_policy`] with the request's query verdict when it was taken already
/// (`query_admitted`), else evaluated now.
fn check_operation_policy_with(
    config: &Config,
    authority: &str,
    method: &str,
    path: &str,
    query_admitted: Option<bool>,
) -> Option<&'static str> {
    if let Some(reason) = path_trick(path) {
        return Some(reason);
    }

    let authority_lower = authority.to_ascii_lowercase();

    // If policy exists for this alias, check it
    if let Some(policies) = config.backends_policy.get(&authority_lower) {
        if matching_rule(policies, method, path).is_none() {
            return Some("operation not in alias policy");
        }
    } else if config.backends.contains_key(&authority_lower)
        && !config.backends_policy_default_allow
    {
        // No policy for this alias: check default
        return Some("alias has no operation policy");
    }

    // An allowed operation whose exact route has a THIRD_PARTY_QUERY_RULES entry must carry
    // one of the query shapes listed there.
    let admitted = query_admitted.unwrap_or_else(|| {
        config
            .third_party_query_rules
            .admits(&authority_lower, method, path)
    });
    if !admitted {
        return Some("query not allowed");
    }

    None
}

/// Whether `inner_request` maps to a `BACKENDS` entry whose policy refuses it: such a request
/// gets the inner 403 before any third-party cache or upstream cap is consulted.
#[allow(dead_code)]
pub fn policy_denies(config: &Config, inner_request: &InnerRequest) -> bool {
    policy_denies_in(
        config,
        inner_request,
        &RouteContext::resolve(config, inner_request),
    )
}

/// [`policy_denies`] in the request's [`RouteContext`].
pub fn policy_denies_in(
    config: &Config,
    inner_request: &InnerRequest,
    route: &RouteContext,
) -> bool {
    if let Some(host) = route.dynamic() {
        return check_dynamic_policy(host, &inner_request.method, &inner_request.path).is_some();
    }
    config
        .backends
        .contains_key(&inner_request.authority.to_ascii_lowercase())
        && check_operation_policy_with(
            config,
            &inner_request.authority,
            &inner_request.method,
            &inner_request.path,
            route.query_admitted,
        )
        .is_some()
}

/// Whether a request to a `GATEWAY_HOSTS` authority (the light client server) is refused by
/// that host's `BACKENDS_POLICY` entry. A gateway host without an entry is not restricted.
/// Checked before the response cache, like a `BACKENDS` policy.
pub fn gateway_host_policy_denies(config: &Config, inner_request: &InnerRequest) -> bool {
    let host = inner_request
        .authority
        .to_ascii_lowercase()
        .split(':')
        .next()
        .unwrap_or("")
        .to_string();
    config.gateway_hosts.contains(&host)
        && config.backends_policy.contains_key(&host)
        && check_operation_policy(config, &host, &inner_request.method, &inner_request.path)
            .is_some()
}

/// A gRPC call (`content-type: application/grpc...`): its upstream also gets `grpc-request-id`.
fn is_grpc_request(inner_request: &InnerRequest) -> bool {
    inner_request.is_grpc()
}

/// Request headers that are forwarded to backends. Closed list for gRPC negotiation.
/// Authorization/Cookie/API-key headers are REPLACED (not forwarded) — see backend_headers injection
/// (the Flexa alias forwards a few more, see `flexa.rs`).
fn forward_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "content-type" | "grpc-timeout" | "grpc-encoding" | "grpc-accept-encoding"
    )
}

/// Response headers/trailers that are returned to the client.
fn return_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(lower.as_str(), "content-type" | "date") || lower.starts_with("grpc-")
}

/// A `text/event-stream` (SSE) response.
fn is_event_stream(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type")
            && value
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("text/event-stream")
    })
}

/// Validate an RFC 9292 :authority pseudo-header value.
/// Returns None if valid, Some(reason) if invalid.
///
/// Rules:
/// - Must be lowercase ASCII
/// - Optional :port (digits only, 1-65535)
/// - Host must match DNS label rules: [a-z0-9]([a-z0-9-]{0,61}[a-z0-9])? with dots
/// - No /, @, ?, #, spaces, control chars
/// - No leading/trailing dot
/// - Total length ≤ 253 chars
fn validate_authority(authority: &str) -> Option<&'static str> {
    if authority.is_empty() {
        return None; // Empty passes here; resolve_backend rejects it separately
    }

    if authority.len() > 253 {
        return Some("authority too long");
    }

    // Split host and port
    let (host, port_str) = if let Some(colon_idx) = authority.rfind(':') {
        let h = &authority[..colon_idx];
        let p = &authority[colon_idx + 1..];
        (h, Some(p))
    } else {
        (authority, None)
    };

    // Validate port if present
    if let Some(p) = port_str {
        if p.is_empty() || !p.chars().all(|c| c.is_ascii_digit()) {
            return Some("invalid port");
        }
        if let Ok(port_num) = p.parse::<u16>() {
            if port_num == 0 {
                return Some("port cannot be 0");
            }
        } else {
            return Some("port out of range");
        }
    }

    // Validate host
    if host.is_empty() {
        return Some("empty host");
    }

    if host.starts_with('.') || host.ends_with('.') {
        return Some("host has leading or trailing dot");
    }

    // Check for invalid characters and validate DNS label structure
    for c in host.chars() {
        if !c.is_ascii() {
            return Some("non-ASCII character in host");
        }
        if !c.is_ascii_alphanumeric() && c != '.' && c != '-' {
            return Some("invalid character in host");
        }
        if c.is_ascii_uppercase() {
            return Some("uppercase character in authority");
        }
    }

    // Validate each DNS label
    for label in host.split('.') {
        if label.is_empty() {
            return Some("empty DNS label");
        }
        if label.len() > 63 {
            return Some("DNS label too long");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Some("DNS label starts or ends with hyphen");
        }
    }

    None
}

/// Validate an RFC 9292 :path pseudo-header value.
/// Returns None if valid, Some(reason) if invalid.
///
/// Rules:
/// - Must start with /
/// - Only visible ASCII (0x21-0x7E)
/// - No # (fragment)
/// - No // immediately after start (could be read as authority)
/// - No .. path segments
/// - Length ≤ 8 KiB
fn validate_path(path: &str) -> Option<&'static str> {
    if path.is_empty() {
        return Some("empty path");
    }

    if !path.starts_with('/') {
        return Some("path does not start with /");
    }

    if path.len() > 8192 {
        return Some("path too long");
    }

    if path.starts_with("//") {
        return Some("path starts with //");
    }

    if path.contains('#') {
        return Some("path contains fragment");
    }

    // Check for visible ASCII only and .. segments
    for c in path.chars() {
        if !c.is_ascii() || (c as u8) < 0x21 || (c as u8) > 0x7E {
            return Some("path contains non-visible ASCII");
        }
    }

    // Check for .. segments
    for segment in path.split('/') {
        if segment == ".." {
            return Some("path contains .. segment");
        }
    }

    None
}

/// Create a 400 Binary HTTP response for malformed path.
/// Generic error body (no specifics to prevent information leakage).
fn create_malformed_path_response() -> InnerResponse {
    InnerResponse {
        status: 400,
        headers: vec![("content-type".to_string(), "text/plain".to_string())],
        body: b"bad request".to_vec(),
    }
}

/// Create a 403 Binary HTTP response for malformed authority.
/// Generic error body (no specifics to prevent information leakage).
fn create_malformed_authority_response(_reason: &str) -> InnerResponse {
    InnerResponse {
        status: 403,
        headers: vec![("content-type".to_string(), "text/plain".to_string())],
        body: b"forbidden".to_vec(),
    }
}

// Proxy mode handler (catches all paths for gRPC passthrough)
pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    // Proxy mode: Accept plain gRPC from mobile app, forward to LWD.
    // LWD only sees gateway IP, not client IP (basic privacy tier).
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    // Limit proxy mode request body to 10 MiB (not usize::MAX)
    let body_bytes = match axum::body::to_bytes(req.into_body(), 10_485_760).await {
        Ok(b) => b.to_vec(),
        Err(e) => {
            warn!("Failed to read proxy request body: {:?}", e);
            return (
                StatusCode::BAD_REQUEST,
                "request body too large or read error",
            )
                .into_response();
        }
    };

    // Preserve query string in path
    let path_with_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or_else(|| uri.path());

    let inner_request = InnerRequest {
        method: method.to_string(),
        path: path_with_query.to_string(),
        authority: headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string(),
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect(),
        body: body_bytes,
    };

    // Resolve backend first to check if cache is allowed (only for LWD).
    // The cache key is path + body only, so a cached lightwalletd answer must never be
    // returned to a request whose authority is unknown or maps to a third-party upstream.
    let cache_allowed = resolve_backend(&state.config, &inner_request).is_lwd();

    let inner_response = if let (Some(response_cache), true) = (state.cache.as_ref(), cache_allowed)
    {
        let method = inner_request.method.clone();
        let content_type = inner_request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        let path = inner_request.path.clone();
        let headers = inner_request.headers.clone();
        let body = inner_request.body.clone();
        let state_clone = state.clone();
        let inner = inner_request.clone();
        match response_cache
            .get_or_fetch(
                &method,
                content_type,
                &path,
                &headers,
                &body,
                &state.cache_get_semaphore,
                || async move {
                    let resp = forward_to_lwd(&state_clone, &inner).await?;
                    Ok(bincode::serialize(&resp)?)
                },
            )
            .await
        {
            Ok(bytes) => match bincode::deserialize::<crate::ohttp::InnerResponse>(&bytes) {
                Ok(r) => r,
                Err(e) => {
                    warn!("Cache deserialization error: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Cache error: {}", e),
                    )
                        .into_response();
                }
            },
            Err(e) => {
                warn!("LWD proxy error: {:?}", e);
                return (StatusCode::BAD_GATEWAY, format!("LWD error: {}", e)).into_response();
            }
        }
    } else {
        match forward_to_lwd(&state, &inner_request).await {
            Ok(r) => r,
            Err(e) => {
                warn!("LWD proxy error: {:?}", e);
                return (StatusCode::BAD_GATEWAY, format!("LWD error: {}", e)).into_response();
            }
        }
    };

    {
        let status = StatusCode::from_u16(inner_response.status).unwrap_or(StatusCode::OK);
        let mut response =
            axum::response::Response::new(axum::body::Body::from(inner_response.body));
        *response.status_mut() = status;
        for (k, v) in inner_response.headers {
            if let (Ok(name), Ok(value)) = (
                axum::http::HeaderName::try_from(k),
                axum::http::HeaderValue::try_from(v),
            ) {
                response.headers_mut().insert(name, value);
            }
        }
        response.into_response()
    }
}

/// Check if an authority matches any of the configured allowlist suffixes.
/// A suffix starting with '.' matches domain suffixes only (e.g., ".backend-provider.example" matches
/// "prod.vote-chain-primary.backend-provider.example" but not "backend-provider.example" itself).
/// A bare domain matches itself and any subdomain (e.g., "backend-api.example" matches
/// "backend-api.example" and "1click.backend-api.example").
#[cfg(test)]
fn matches_allowed_suffix(authority: &str, suffixes: &[String]) -> bool {
    for suffix in suffixes {
        if suffix.starts_with('.') {
            // Domain suffix match: must end with the suffix
            if authority.ends_with(suffix) {
                return true;
            }
        } else {
            // Bare domain: exact match or subdomain match
            if authority == suffix || authority.ends_with(&format!(".{}", suffix)) {
                return true;
            }
        }
    }
    false
}

/// Check if an authority matches the gateway's own hosts (case-insensitive, port-stripped).
fn is_gateway_host(authority: &str, gateway_hosts: &[String]) -> bool {
    let normalized = authority
        .to_ascii_lowercase()
        .split(':')
        .next()
        .unwrap_or("")
        .to_string();
    gateway_hosts.contains(&normalized)
}

/// Where an inner request goes, decided from its RFC 9292 `:authority` alone.
pub enum BackendTarget {
    /// Fully resolved upstream URI plus the metrics label.
    /// label is the actual authority (e.g., "api1.example.com") for per-alias semaphores.
    Upstream { uri: String, label: String },
    /// Unknown authority: answered with inner 403 and never served from the response cache.
    Rejected,
    /// Malformed authority: answered with a generic inner 403 (the reason is logged).
    MalformedAuthority(&'static str),
    /// Malformed path: answered with inner 400.
    MalformedPath(&'static str),
}

impl BackendTarget {
    /// True only for the gateway's own lightwalletd. The response cache is keyed by path + body
    /// (no authority), so it must be consulted for this target only — otherwise a cached
    /// lightwalletd answer could be handed to a rejected or third-party authority.
    pub fn is_lwd(&self) -> bool {
        matches!(self, BackendTarget::Upstream { label, .. } if label == "lwd")
    }
}

/// Build a validated URI from base URL and path, asserting that the result matches expected host.
/// This prevents injection attacks where a malicious path could redirect to a different host.
fn build_validated_uri(base_url: &str, path: &str, expected_host: &str) -> Result<String> {
    // Parse base URL to extract scheme and authority
    let base_uri: hyper::Uri = base_url
        .parse()
        .map_err(|e| anyhow!("Invalid base URL {}: {:?}", base_url, e))?;

    let scheme = base_uri
        .scheme_str()
        .ok_or_else(|| anyhow!("Base URL missing scheme"))?;
    let base_authority = base_uri
        .authority()
        .ok_or_else(|| anyhow!("Base URL missing authority"))?
        .as_str();

    // Build the URI from its parsed parts: the path can only ever be a path.
    if !path.starts_with('/') {
        return Err(anyhow!("Path must start with '/': {:?}", path));
    }
    let uri = hyper::Uri::builder()
        .scheme(scheme)
        .authority(base_authority)
        .path_and_query(path)
        .build()
        .map_err(|e| anyhow!("Failed to build URI from components: {:?}", e))?;
    let uri_str = uri.to_string();

    // Extract host from the built URI (normalize: strip port, lowercase)
    let built_host = uri
        .authority()
        .map(|a| {
            a.host()
                .to_ascii_lowercase()
                .split(':')
                .next()
                .unwrap_or("")
                .to_string()
        })
        .ok_or_else(|| anyhow!("Built URI missing authority"))?;

    // Normalize expected host (strip port, lowercase)
    let normalized_expected = expected_host
        .to_ascii_lowercase()
        .split(':')
        .next()
        .unwrap_or("")
        .to_string();

    // Assert that the built URI's host matches what we intended
    if built_host != normalized_expected {
        return Err(anyhow!(
            "URI host mismatch: built={} expected={} (possible injection attempt)",
            built_host,
            normalized_expected
        ));
    }
    // ... and that its whole origin (scheme, host and port) is exactly the selected upstream's,
    // before any credential is attached by the caller.
    if uri.scheme() != base_uri.scheme() || uri.authority() != base_uri.authority() {
        return Err(anyhow!(
            "URI origin mismatch: built={} selected={}://{} (possible injection attempt)",
            uri_str,
            scheme,
            base_authority
        ));
    }

    Ok(uri_str)
}

/// Resolution order with ZIP draft authority validation:
/// 1. Validate authority structurally (malformed, including upper case → generic 403)
/// 2. Validate path structurally (malformed → 400)
/// 3. Exact match of the lowercase authority in the backends map → mapped backend
/// 3b. A dynamic host (`DYNAMIC_HOST_SOURCES`) that is neither a backends alias nor a gateway
///     host → that host itself (`https://host[:port]`)
/// 4. Empty authority → 403
/// 5. If GATEWAY_HOSTS not configured (empty) → LWD fallback (permissive; the binary refuses to
///    start in ohttp mode without GATEWAY_HOSTS, so only a `Config` built in code reaches this)
/// 6. If authority matches gateway_hosts → LWD
/// 7. Otherwise → reject with 403
pub fn resolve_backend(config: &Config, inner_request: &InnerRequest) -> BackendTarget {
    resolve_backend_in(
        config,
        inner_request,
        &RouteContext::resolve(config, inner_request),
    )
}

/// [`resolve_backend`] in the request's [`RouteContext`]: the dynamic host, if the request is
/// for one, is the context's entry and the served set is not read again.
pub fn resolve_backend_in(
    config: &Config,
    inner_request: &InnerRequest,
    route: &RouteContext,
) -> BackendTarget {
    // Step 1: Validate authority structurally
    if let Some(reason) = validate_authority(&inner_request.authority) {
        warn!(
            authority = %inner_request.authority,
            reason = reason,
            "Rejecting request with malformed authority"
        );
        return BackendTarget::MalformedAuthority(reason);
    }

    // Step 2: Validate path structurally. The rejection logs `loggable_route`, the matching
    // policy rule rather than the raw third-party path.
    if let Some(reason) = validate_path(&inner_request.path) {
        warn!(
            authority = %inner_request.authority,
            path = %loggable_route_in(config, inner_request, route),
            reason = reason,
            "Rejecting request with malformed path"
        );
        return BackendTarget::MalformedPath(reason);
    }

    // Step 3: Normalize authority for lookups (lowercase, strip port for host-only comparison)
    let normalized_authority = inner_request
        .authority
        .to_ascii_lowercase()
        .split(':')
        .next()
        .unwrap_or("")
        .to_string();

    // Lowercase authority for case-insensitive backends map lookup
    let authority_lower = inner_request.authority.to_ascii_lowercase();

    // The context must be this request's, before anything is resolved: an entry read for
    // another authority must never lend its policy or limits to this one.
    if route
        .dynamic()
        .is_some_and(|host| crate::dynamic_hosts::authority_key(&authority_lower) != host.authority)
    {
        warn!("Route context of another authority");
        return BackendTarget::Rejected;
    }

    // Step 4: Check backends map (case-insensitive)
    if let Some(base_url) = config.backends.get(&authority_lower) {
        let full_base_url = if base_url.starts_with("http") {
            base_url.clone()
        } else {
            format!("http://{}", base_url)
        };

        // Extract the expected host from the base_url (the mapped target, not the original authority)
        let expected_host = if base_url.starts_with("http") {
            // Parse to extract host
            match base_url.parse::<hyper::Uri>() {
                Ok(u) => u
                    .authority()
                    .map(|a| a.host().to_string())
                    .unwrap_or_else(|| base_url.clone()),
                Err(_) => base_url.clone(),
            }
        } else {
            base_url.clone()
        };

        match build_validated_uri(&full_base_url, &inner_request.path, &expected_host) {
            Ok(uri) => {
                debug!(
                    authority = %inner_request.authority,
                    mapped_to = %uri,
                    "Mapped backend"
                );
                // Use actual authority as label for per-alias semaphores
                return BackendTarget::Upstream {
                    uri,
                    label: authority_lower.clone(),
                };
            }
            Err(e) => {
                warn!(
                    authority = %inner_request.authority,
                    error = %e,
                    "URI validation failed for mapped backend"
                );
                return BackendTarget::Rejected;
            }
        }
    }

    // Step 4b: a dynamic host (DYNAMIC_HOST_SOURCES), after the static map (static wins) and
    // never one of the gateway's own names. Its target is the listed host itself.
    if let Some(host) = route.dynamic() {
        let expected_host = host.authority.split(':').next().unwrap_or(&host.authority);
        // The connector does not ask the resolver for an address literal, so a literal is
        // checked here as well as when it was listed: only a public address is ever a target.
        if expected_host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| !crate::dynamic_hosts::is_connectable(ip))
        {
            warn!(backend = %host.label, "Dynamic host is a non-public address literal");
            return BackendTarget::Rejected;
        }
        return match build_validated_uri(&host.base_url, &inner_request.path, expected_host) {
            Ok(uri) => BackendTarget::Upstream {
                uri,
                label: host.label.clone(),
            },
            Err(e) => {
                warn!(
                    backend = %host.label,
                    error = %e,
                    "URI validation failed for dynamic host"
                );
                BackendTarget::Rejected
            }
        };
    }

    // Step 5: Suffix routing removed per security audit (SSRF surface)
    // Use exact BACKENDS map entries instead

    // Empty authority must NOT route to own-LWD, reject with inner 403
    if normalized_authority.is_empty() {
        warn!("Rejecting request with empty :authority");
        return BackendTarget::MalformedAuthority("empty authority");
    }

    // Step 6: Permissive fallback or gateway's own host → LWD
    if config.gateway_hosts.is_empty()
        || is_gateway_host(&inner_request.authority, &config.gateway_hosts)
    {
        match build_validated_uri(
            &format!("http://{}", config.lwd_addr),
            &inner_request.path,
            config
                .lwd_addr
                .split(':')
                .next()
                .unwrap_or(&config.lwd_addr),
        ) {
            Ok(uri) => {
                return BackendTarget::Upstream {
                    uri,
                    label: "lwd".to_string(),
                };
            }
            Err(e) => {
                warn!(
                    lwd_addr = %config.lwd_addr,
                    error = %e,
                    "URI validation failed for LWD"
                );
                return BackendTarget::Rejected;
            }
        }
    }

    // Step 7: Unknown authority → reject
    BackendTarget::Rejected
}

/// Count one upstream call against a dynamic host's cap: `Some(retry_after_secs)` when it is
/// spent (logged and counted by the source's label), `None` otherwise or for any other backend.
fn dynamic_host_limited(config: &Config, dynamic: Option<&DynamicHost>) -> Option<u64> {
    let host = dynamic?;
    let retry_after = host.check_rate().err()?;
    warn!(
        backend = %host.label,
        retry_after,
        network = %config.network,
        "dynamic host upstream cap reached (inner 429)"
    );
    crate::health::record_third_party_limited(&config.network, &host.label);
    crate::health::record_upstream_request(&config.network, &host.label, "other", 429, "-", 0.0);
    Some(retry_after)
}

/// Create a 403 Binary HTTP response for rejected authority.
fn create_rejected_authority_response() -> InnerResponse {
    InnerResponse {
        status: 403,
        headers: vec![("content-type".to_string(), "text/plain".to_string())],
        body: b"unknown authority".to_vec(),
    }
}

/// Forward an inner request to the correct backend, selected by the inner request's authority.
/// Routing follows `resolve_backend` (LWD for gateway hosts, or for any valid authority when
/// GATEWAY_HOSTS is empty).
pub async fn forward_to_lwd(
    state: &Arc<AppState>,
    inner_request: &InnerRequest,
) -> Result<InnerResponse> {
    forward_to_backend(state, inner_request).await
}

pub async fn forward_to_backend(
    state: &Arc<AppState>,
    inner_request: &InnerRequest,
) -> Result<InnerResponse> {
    forward_to_backend_internal(state, inner_request, None, None, None).await
}

/// [`forward_to_backend`] in the request's [`RouteContext`].
pub async fn forward_to_backend_in(
    state: &Arc<AppState>,
    inner_request: &InnerRequest,
    route: &RouteContext,
) -> Result<InnerResponse> {
    forward_to_backend_internal(state, inner_request, None, None, Some(route)).await
}

async fn forward_to_backend_internal(
    state: &Arc<AppState>,
    inner_request: &InnerRequest,
    request_id: Option<uuid::Uuid>,
    client_trace_id: Option<String>,
    route: Option<&RouteContext>,
) -> Result<InnerResponse> {
    let config = &state.config;
    use crate::health;
    let upstream_start = std::time::Instant::now();

    // Authority and path validation happens here AND in main.rs before the cache lookup (resolve_backend).
    let resolved;
    let route = match route {
        Some(route) => route,
        None => {
            resolved = RouteContext::resolve(config, inner_request);
            &resolved
        }
    };
    // The dynamic host entry of this request: target, routes, limits and labels all come from it.
    let dynamic = route.dynamic().cloned();
    let (lwd_uri, backend_type) = match resolve_backend_in(config, inner_request, route) {
        BackendTarget::Upstream { uri, label } => (uri, label),
        BackendTarget::Rejected => {
            // Unknown authority: reject with 403 per ZIP draft
            warn!(
                request_id = ?request_id,
                authority = %inner_request.authority,
                network = %config.network,
                "Rejecting request with unknown authority"
            );

            // Record rejection in metrics (use "other" for unbounded path)
            health::record_upstream_request(&config.network, "rejected", "other", 403, "-", 0.0);

            return Ok(create_rejected_authority_response());
        }
        BackendTarget::MalformedAuthority(reason) => {
            // Malformed authority: reject with a generic 403; the reason is logged
            warn!(
                request_id = ?request_id,
                authority = %inner_request.authority,
                reason = reason,
                network = %config.network,
                "Rejecting request with malformed authority"
            );

            // Record rejection in metrics (use "other" for unbounded path)
            health::record_upstream_request(&config.network, "rejected", "other", 403, "-", 0.0);

            return Ok(create_malformed_authority_response(reason));
        }
        BackendTarget::MalformedPath(reason) => {
            // Malformed path: reject with 400 (path logged as its policy pattern, see resolve_backend)
            warn!(
                request_id = ?request_id,
                path = %loggable_route_in(config, inner_request, route),
                reason = reason,
                network = %config.network,
                "Rejecting request with malformed path"
            );

            // Record rejection in metrics
            health::record_upstream_request(&config.network, "rejected", "other", 400, "-", 0.0);

            return Ok(create_malformed_path_response());
        }
    };

    // Check operation policy for mapped backends
    let authority_lower = inner_request.authority.to_ascii_lowercase();
    {
        if let Some(reason) = route_denial(
            config,
            dynamic.as_deref(),
            route.query_admitted,
            inner_request,
        ) {
            warn!(
                policy = "deny",
                request_id = ?request_id,
                authority = %inner_request.authority,
                method = %inner_request.method,
                path = %loggable_route_in(config, inner_request, route),
                reason = reason,
                network = %config.network,
                "Operation denied by policy"
            );
            health::record_upstream_request(
                &config.network,
                "policy_denied",
                "other",
                403,
                "-",
                0.0,
            );
            health::record_policy_denied(
                dynamic
                    .as_ref()
                    .map_or(inner_request.authority.as_str(), |h| h.label.as_str()),
            );
            // Policy denial returns "policy denied" per spec
            return Ok(InnerResponse {
                status: 403,
                headers: vec![("content-type".to_string(), "text/plain".to_string())],
                body: b"policy denied".to_vec(),
            });
        }
    }

    // The per-host cap of a dynamic host (its source's `rate_limit`): inner 429, no upstream call.
    if let Some(retry_after) = dynamic_host_limited(config, dynamic.as_deref()) {
        return Ok(crate::third_party_cache::create_rate_limited_response(
            retry_after,
        ));
    }

    // Block range enforcement for GetBlockRange gRPC calls
    if let Err(e) = crate::enforcement::check_block_range(
        &inner_request.path,
        &inner_request.body,
        config.max_block_range,
    ) {
        warn!(
            request_id = ?request_id,
            path = %inner_request.path,
            max_range = config.max_block_range,
            error = %e,
            "Block range limit exceeded"
        );
        health::record_upstream_request(&config.network, &backend_type, "other", 400, "-", 0.0);
        // Return gRPC INVALID_ARGUMENT (3)
        return Ok(InnerResponse {
            status: 200,
            headers: vec![
                ("content-type".to_string(), "application/grpc".to_string()),
                ("grpc-status".to_string(), "3".to_string()),
                (
                    "grpc-message".to_string(),
                    "Block range exceeds maximum".to_string(),
                ),
            ],
            body: vec![],
        });
    }

    // Semaphore acquisition: global first, then per-backend
    let _global_permit = match state.global_semaphore.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            warn!(
                request_id = ?request_id,
                backend = backend_type,
                "Global upstream limit reached"
            );
            health::record_upstream_request(&config.network, &backend_type, "other", 503, "-", 0.0);
            // Return inner 503 for HTTP or UNAVAILABLE (14) for gRPC
            if inner_request.path.contains("/cash.z.wallet.sdk.rpc.") {
                return Ok(InnerResponse {
                    status: 200,
                    headers: vec![
                        ("content-type".to_string(), "application/grpc".to_string()),
                        ("grpc-status".to_string(), "14".to_string()),
                        (
                            "grpc-message".to_string(),
                            "Service unavailable: too many concurrent requests".to_string(),
                        ),
                    ],
                    body: vec![],
                });
            } else {
                return Ok(InnerResponse {
                    status: 503,
                    headers: vec![("content-type".to_string(), "text/plain".to_string())],
                    body: b"Service unavailable: too many concurrent requests".to_vec(),
                });
            }
        }
    };

    // Log forwarding decision after the policy and global-limit checks
    if let Some(req_id) = request_id {
        if let Some(ref trace_id) = client_trace_id {
            info!(
                request_id = %req_id,
                client_trace_id = %trace_id,
                backend = backend_type,
                method = %inner_request.method,
                uri = %lwd_uri,
                network = %config.network,
                hop = "upstream",
                "Forwarding to backend"
            );
        } else {
            info!(
                request_id = %req_id,
                backend = backend_type,
                method = %inner_request.method,
                uri = %lwd_uri,
                network = %config.network,
                hop = "upstream",
                "Forwarding to backend"
            );
        }
    } else {
        debug!(
            "Forwarding to backend={}: {} {}",
            backend_type, inner_request.method, lwd_uri
        );
    }

    // Use dedicated lwd_semaphore for own-LWD, per_backend semaphores for backend aliases
    let backend_sem = if backend_type == "lwd" {
        state.lwd_semaphore.clone()
    } else if let Some(host) = &dynamic {
        // Per dynamic host, held in its entry (it goes away with the host).
        host.semaphore.clone()
    } else {
        crate::enforcement::get_backend_semaphore(
            &backend_type,
            config.max_inflight_per_backend,
            &state.per_backend_semaphores,
        )
    };
    let _backend_permit = match backend_sem.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            warn!(
                request_id = ?request_id,
                backend = backend_type,
                "Per-backend upstream limit reached"
            );
            health::record_upstream_request(&config.network, &backend_type, "other", 503, "-", 0.0);
            // Return inner 503 for HTTP or UNAVAILABLE (14) for gRPC
            if inner_request.path.contains("/cash.z.wallet.sdk.rpc.") {
                return Ok(InnerResponse {
                    status: 200,
                    headers: vec![
                        ("content-type".to_string(), "application/grpc".to_string()),
                        ("grpc-status".to_string(), "14".to_string()),
                        (
                            "grpc-message".to_string(),
                            "Service unavailable: backend limit reached".to_string(),
                        ),
                    ],
                    body: vec![],
                });
            } else {
                return Ok(InnerResponse {
                    status: 503,
                    headers: vec![("content-type".to_string(), "text/plain".to_string())],
                    body: b"Service unavailable: backend limit reached".to_vec(),
                });
            }
        }
    };

    let mut req_builder = Request::builder()
        .method(inner_request.method.as_str())
        .uri(&lwd_uri);

    // Gateway-owned X-Request-Id (replace any client value). Not for a dynamic host: a host a
    // published document chose gets no key that joins its logs to the gateway's.
    if let (Some(req_id), None) = (request_id, &dynamic) {
        req_builder = req_builder.header("X-Request-Id", req_id.to_string());
    }

    // Determine if we'll inject grpc-accept-encoding: identity (h2c backends only)
    let inject_identity_encoding = !lwd_uri.to_string().starts_with("https://");
    if let (true, Some(req_id), None) = (is_grpc_request(inner_request), request_id, &dynamic) {
        req_builder = req_builder.header("grpc-request-id", req_id.to_string());
    }

    // Forward only allowed gRPC negotiation headers from client
    // SKIP grpc-accept-encoding if we're injecting identity (replace, not append)
    for (name, value) in &inner_request.headers {
        if forward_header(name) {
            if inject_identity_encoding && name.eq_ignore_ascii_case("grpc-accept-encoding") {
                continue; // Will be replaced below
            }
            req_builder = req_builder.header(name.as_str(), value.as_str());
        }
    }
    if dynamic.is_none() && crate::flexa::is_alias(config.flexa_alias.as_deref(), &authority_lower)
    {
        for (name, value) in crate::flexa::upstream_headers(
            &inner_request.headers,
            config.flexa_publishable_key.as_deref(),
        ) {
            req_builder = req_builder.header(name, value);
        }
    }

    // Fixed user-agent
    req_builder = req_builder.header("User-Agent", "ohttp-gateway/1.0");

    // For gRPC backends (h2c, not https), inject grpc-accept-encoding: identity
    // (client's grpc-accept-encoding was filtered out above)
    if inject_identity_encoding {
        req_builder = req_builder.header("grpc-accept-encoding", "identity");
    }

    // Inject per-backend credentials (REPLACES any client auth, never appends). Never for a
    // dynamic host: credentials belong to `BACKENDS` aliases only.
    if let Some(extra) = config
        .backend_headers
        .get(&authority_lower)
        .filter(|_| dynamic.is_none())
    {
        for (name, value) in extra {
            req_builder = req_builder.header(name.as_str(), value.as_str());
        }
    }
    let http_request = req_builder
        .body(Full::new(Bytes::from(inner_request.body.clone())))
        .map_err(|e| anyhow!("Failed to build HTTP request: {:?}", e))?;

    let overall = Duration::from_secs(config.lwd_timeout_secs);
    let deadline = Instant::now() + overall;
    // GetMempoolStream stays open until the next block; return what LWD has sent once it goes idle.
    let is_long_poll = inner_request.path.ends_with("/GetMempoolStream");
    // Track if this is a gRPC backend (h2c) vs plain HTTPS backend
    let is_grpc_backend = !lwd_uri.starts_with("https://");
    let idle = Duration::from_secs(config.long_poll_idle_secs);

    // Use a TLS-capable client for https:// backends and an h2c client for http:// upstreams.
    let http_response = if dynamic.is_some() {
        // Dynamic hosts: the client whose resolver hands out public addresses only.
        timeout(overall, dynamic_backend_client().request(http_request))
            .await
            .map_err(|_| anyhow!("Backend did not respond within {:?}", overall))?
            .map_err(|e| anyhow!("HTTPS request failed: {:?}", e))?
    } else if lwd_uri.starts_with("https://") {
        timeout(overall, https_backend_client().request(http_request))
            .await
            .map_err(|_| anyhow!("Backend did not respond within {:?}", overall))?
            .map_err(|e| anyhow!("HTTPS request failed: {:?}", e))?
    } else {
        let call = crate::lwd_endpoints::CallOpts {
            network: &config.network,
            head: overall,
            class: None,
            pooled: false,
            may_hedge: !crate::enforcement::is_heavy_lwd_call(
                &inner_request.path,
                &inner_request.body,
                config.lwd_heavy_block_range,
            ),
        };
        match crate::lwd_endpoints::request(http_request, call).await {
            Ok(r) => r,
            Err(crate::lwd_endpoints::RequestError::Timeout) => {
                return Err(anyhow!("LWD did not respond within {:?}", overall))
            }
            Err(e) => return Err(anyhow!("HTTP request failed: {:?}", e)),
        }
    };

    let mut status = http_response.status().as_u16();
    let mut headers: Vec<(String, String)> = http_response
        .headers()
        .iter()
        .filter(|(k, _)| return_header(k.as_str()))
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let mut body = http_response.into_body();
    let mut body_bytes: Vec<u8> = Vec::new();
    let mut got_trailers = false;
    let max_response_bytes = config.max_upstream_response_bytes;
    let mut truncated = false;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            if is_long_poll {
                break;
            }
            return Err(anyhow!("LWD response exceeded {:?}", overall));
        }
        let wait = if is_long_poll {
            remaining.min(idle)
        } else {
            remaining
        };

        match timeout(wait, body.frame()).await {
            Ok(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => {
                    if body_bytes.len() + data.len() > max_response_bytes {
                        if is_grpc_backend {
                            // For gRPC backends: fill up to the cap, then truncate at the
                            // last complete message boundary.
                            let room = max_response_bytes.saturating_sub(body_bytes.len());
                            body_bytes.extend_from_slice(&data[..room.min(data.len())]);
                            let last_boundary = last_complete_grpc_message_offset(&body_bytes);
                            let message_count = count_grpc_messages(&body_bytes, last_boundary);
                            body_bytes.truncate(last_boundary);
                            truncated = true;

                            if let Some(req_id) = request_id {
                                warn!(
                                    request_id = %req_id,
                                    path = %loggable_route_in(config, inner_request, route),
                                    bytes_kept = last_boundary,
                                    message_count = message_count,
                                    "Response truncated at gateway size cap"
                                );
                            }

                            crate::health::record_response_truncated(&config.network);
                            break;
                        } else {
                            // For non-gRPC backends: keep existing error behavior
                            return Err(anyhow!(
                                "Response exceeded max size {} bytes",
                                max_response_bytes
                            ));
                        }
                    }
                    body_bytes.extend_from_slice(&data);
                }
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        for (k, v) in trailers.iter() {
                            if return_header(k.as_str()) {
                                headers.push((k.to_string(), v.to_str().unwrap_or("").to_string()));
                            }
                        }
                        got_trailers = true;
                    }
                }
            },
            Ok(Some(Err(e))) => return Err(anyhow!("LWD body error: {:?}", e)),
            Ok(None) => break,
            Err(_) => {
                if is_long_poll {
                    if let Some(req_id) = request_id {
                        info!(
                            request_id = %req_id,
                            idle_duration_secs = idle.as_secs(),
                            bytes = body_bytes.len(),
                            "Long-poll stream idle, closing with buffered data"
                        );
                    } else {
                        debug!(
                            "long-poll stream idle for {:?}; closing with {} bytes",
                            idle,
                            body_bytes.len()
                        );
                    }
                    break;
                }
                return Err(anyhow!("LWD stream idle beyond {:?}", overall));
            }
        }
    }

    // Handle grpc-status for gRPC backends
    if truncated {
        // Remove any upstream grpc-status and replace with truncation status
        headers.retain(|(k, _)| {
            !k.eq_ignore_ascii_case("grpc-status") && !k.eq_ignore_ascii_case("grpc-message")
        });
        headers.push(("grpc-status".to_string(), "8".to_string()));
        headers.push((
            "grpc-message".to_string(),
            "response truncated at gateway size cap".to_string(),
        ));
        status = 200;
    } else {
        let has_grpc_status = headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("grpc-status"));
        if !has_grpc_status {
            if is_long_poll && status == 200 {
                // Stream was cut on purpose; report success for the frames collected so far.
                headers.push(("grpc-status".to_string(), "0".to_string()));
            } else if status == 200 && is_grpc_backend {
                if let Some(req_id) = request_id {
                    warn!(
                        request_id = %req_id,
                        path = %inner_request.path,
                        bytes = body_bytes.len(),
                        got_trailers = got_trailers,
                        "LWD closed stream without grpc-status"
                    );
                } else {
                    warn!(
                        "LWD closed {} without trailers ({} bytes, trailers={})",
                        inner_request.path,
                        body_bytes.len(),
                        got_trailers
                    );
                }
                headers.push(("grpc-status".to_string(), "13".to_string()));
                headers.push((
                    "grpc-message".to_string(),
                    "lightwalletd closed stream without grpc-status".to_string(),
                ));
            }
        }
    }

    // Acquire large-response semaphore for responses above threshold to bound memory usage
    let _large_response_permit = if body_bytes.len() > config.large_response_threshold {
        match state.large_response_semaphore.try_acquire() {
            Ok(p) => Some(p),
            Err(_) => {
                warn!(
                    size = body_bytes.len(),
                    threshold = config.large_response_threshold,
                    "Large response semaphore exhausted, proceeding anyway"
                );
                None
            }
        }
    } else {
        None
    };

    let inner_response = InnerResponse {
        status,
        headers,
        body: body_bytes,
    };

    // Record upstream metrics for downstream granularity
    let grpc_status = inner_response
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("grpc-status"))
        .map(|(_, v)| v.as_str())
        .unwrap_or(if is_grpc_backend {
            // gRPC backend without status is an error
            "13"
        } else {
            // HTTP backend: no grpc-status expected
            "-"
        });

    let backend_label = match &dynamic {
        Some(host) => host.label.clone(),
        None => health::normalize_backend(
            &inner_request.authority,
            &config.gateway_hosts,
            &config.backends,
        ),
    };
    let rpc_name = rpc_label_in(config, inner_request, route);
    let duration_secs = upstream_start.elapsed().as_secs_f64();

    health::record_upstream_request(
        &config.network,
        &backend_label,
        &rpc_name,
        status,
        grpc_status,
        duration_secs,
    );

    Ok(inner_response)
}

/// Forward an inner request to a backend and return a streaming response.
///
/// Returns `(status_code, headers, stream)` where the stream yields `UpFrame` items as they arrive.
/// Enforces `MAX_UPSTREAM_RESPONSE_BYTES` incrementally by tracking cumulative bytes.
/// If the limit is exceeded mid-stream, stops and yields an error frame.
///
/// Performs the same backend resolution, policy checks, and credential injection as
/// `forward_to_backend`, but streams the response body instead of buffering it; `request_id` is
/// forwarded as `X-Request-Id` (and `grpc-request-id` for a gRPC call), except to a dynamic
/// host; `client_trace_id` is only logged.
#[allow(dead_code)]
pub async fn forward_to_backend_stream(
    state: &Arc<AppState>,
    inner_request: &InnerRequest,
    request_id: uuid::Uuid,
    client_trace_id: Option<String>,
) -> Result<StreamedAnswer> {
    let route = RouteContext::resolve(&state.config, inner_request);
    forward_to_backend_stream_in(state, inner_request, request_id, client_trace_id, &route).await
}

/// What a streaming forward returns: status, headers and the body frames.
pub type StreamedAnswer = (
    u16,
    Vec<(String, String)>,
    Pin<
        Box<
            dyn futures_util::Stream<Item = Result<crate::chunked_stream::UpFrame>>
                + Send
                + 'static,
        >,
    >,
);

/// [`forward_to_backend_stream`] in the request's [`RouteContext`].
pub async fn forward_to_backend_stream_in(
    state: &Arc<AppState>,
    inner_request: &InnerRequest,
    request_id: uuid::Uuid,
    client_trace_id: Option<String>,
    route: &RouteContext,
) -> Result<StreamedAnswer> {
    use crate::chunked_stream::UpFrame;
    use futures_util::stream;

    let config = &state.config;
    use crate::health;
    let upstream_start = std::time::Instant::now();

    // Authority and path validation
    // The dynamic host entry of this request: target, routes, limits and labels all come from it.
    let dynamic = route.dynamic().cloned();
    let (backend_uri, backend_type) = match resolve_backend_in(config, inner_request, route) {
        BackendTarget::Upstream { uri, label } => (uri, label),
        BackendTarget::Rejected => {
            warn!(
                request_id = ?request_id,
                authority = %inner_request.authority,
                network = %config.network,
                "Rejecting request with unknown authority"
            );
            health::record_upstream_request(&config.network, "rejected", "other", 403, "-", 0.0);
            let response = create_rejected_authority_response();
            return Ok((
                response.status,
                response.headers,
                Box::pin(stream::once(async move {
                    Ok(UpFrame::Data(Bytes::from(response.body)))
                })),
            ));
        }
        BackendTarget::MalformedAuthority(reason) => {
            warn!(
                request_id = ?request_id,
                authority = %inner_request.authority,
                reason = reason,
                network = %config.network,
                "Rejecting request with malformed authority"
            );
            health::record_upstream_request(&config.network, "rejected", "other", 403, "-", 0.0);
            let response = create_malformed_authority_response(reason);
            return Ok((
                response.status,
                response.headers,
                Box::pin(stream::once(async move {
                    Ok(UpFrame::Data(Bytes::from(response.body)))
                })),
            ));
        }
        BackendTarget::MalformedPath(reason) => {
            warn!(
                request_id = ?request_id,
                path = %loggable_route_in(config, inner_request, route),
                reason = reason,
                network = %config.network,
                "Rejecting request with malformed path"
            );
            health::record_upstream_request(&config.network, "rejected", "other", 400, "-", 0.0);
            let response = create_malformed_path_response();
            return Ok((
                response.status,
                response.headers,
                Box::pin(stream::once(async move {
                    Ok(UpFrame::Data(Bytes::from(response.body)))
                })),
            ));
        }
    };

    // Check operation policy for mapped backends
    let authority_lower = inner_request.authority.to_ascii_lowercase();
    {
        if let Some(reason) = route_denial(
            config,
            dynamic.as_deref(),
            route.query_admitted,
            inner_request,
        ) {
            warn!(
                policy = "deny",
                request_id = ?request_id,
                authority = %inner_request.authority,
                method = %inner_request.method,
                path = %loggable_route_in(config, inner_request, route),
                reason = reason,
                network = %config.network,
                "Operation denied by policy"
            );
            health::record_upstream_request(
                &config.network,
                "policy_denied",
                "other",
                403,
                "-",
                0.0,
            );
            health::record_policy_denied(
                dynamic
                    .as_ref()
                    .map_or(inner_request.authority.as_str(), |h| h.label.as_str()),
            );
            let response = InnerResponse {
                status: 403,
                headers: vec![("content-type".to_string(), "text/plain".to_string())],
                body: b"policy denied".to_vec(),
            };
            return Ok((
                response.status,
                response.headers,
                Box::pin(stream::once(async move {
                    Ok(UpFrame::Data(Bytes::from(response.body)))
                })),
            ));
        }
    }

    // The per-host cap of a dynamic host (its source's `rate_limit`): inner 429, no upstream call.
    if let Some(retry_after) = dynamic_host_limited(config, dynamic.as_deref()) {
        let response = crate::third_party_cache::create_rate_limited_response(retry_after);
        return Ok((
            response.status,
            response.headers,
            Box::pin(stream::once(async move {
                Ok(UpFrame::Data(Bytes::from(response.body)))
            })),
        ));
    }

    // Block range enforcement for GetBlockRange gRPC calls
    if let Err(e) = crate::enforcement::check_block_range(
        &inner_request.path,
        &inner_request.body,
        config.max_block_range,
    ) {
        warn!(
            request_id = ?request_id,
            path = %inner_request.path,
            max_range = config.max_block_range,
            error = %e,
            "Block range limit exceeded"
        );
        health::record_upstream_request(&config.network, &backend_type, "other", 400, "-", 0.0);
        let response = InnerResponse {
            status: 200,
            headers: vec![
                ("content-type".to_string(), "application/grpc".to_string()),
                ("grpc-status".to_string(), "3".to_string()),
                (
                    "grpc-message".to_string(),
                    "Block range exceeds maximum".to_string(),
                ),
            ],
            body: vec![],
        };
        return Ok((
            response.status,
            response.headers,
            Box::pin(stream::once(async move {
                Ok(UpFrame::Data(Bytes::from(response.body)))
            })),
        ));
    }

    // Semaphore acquisition: global first, then per-backend
    let _global_permit = match state.global_semaphore.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            warn!(
                request_id = ?request_id,
                backend = backend_type,
                "Global upstream limit reached"
            );
            health::record_upstream_request(&config.network, &backend_type, "other", 503, "-", 0.0);
            let response = if inner_request.path.contains("/cash.z.wallet.sdk.rpc.") {
                InnerResponse {
                    status: 200,
                    headers: vec![
                        ("content-type".to_string(), "application/grpc".to_string()),
                        ("grpc-status".to_string(), "14".to_string()),
                        (
                            "grpc-message".to_string(),
                            "Service unavailable: too many concurrent requests".to_string(),
                        ),
                    ],
                    body: vec![],
                }
            } else {
                InnerResponse {
                    status: 503,
                    headers: vec![("content-type".to_string(), "text/plain".to_string())],
                    body: b"Service unavailable: too many concurrent requests".to_vec(),
                }
            };
            return Ok((
                response.status,
                response.headers,
                Box::pin(stream::once(async move {
                    Ok(UpFrame::Data(Bytes::from(response.body)))
                })),
            ));
        }
    };

    // Log forwarding decision
    if let Some(ref trace_id) = client_trace_id {
        info!(
            request_id = %request_id,
            client_trace_id = %trace_id,
            backend = backend_type,
            method = %inner_request.method,
            path = %loggable_route_in(config, inner_request, route),
            network = %config.network,
            hop = "upstream",
            "Forwarding to backend (streaming)"
        );
    } else {
        info!(
            request_id = %request_id,
            backend = backend_type,
            method = %inner_request.method,
            path = %loggable_route_in(config, inner_request, route),
            network = %config.network,
            hop = "upstream",
            "Forwarding to backend (streaming)"
        );
    }

    // Use dedicated lwd_semaphore for own-LWD, per_backend semaphores for backend aliases
    let backend_sem = if backend_type == "lwd" {
        state.lwd_semaphore.clone()
    } else if let Some(host) = &dynamic {
        // Per dynamic host, held in its entry (it goes away with the host).
        host.semaphore.clone()
    } else {
        crate::enforcement::get_backend_semaphore(
            &backend_type,
            config.max_inflight_per_backend,
            &state.per_backend_semaphores,
        )
    };
    let _backend_permit = match backend_sem.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            warn!(
                request_id = ?request_id,
                backend = backend_type,
                "Per-backend upstream limit reached"
            );
            health::record_upstream_request(&config.network, &backend_type, "other", 503, "-", 0.0);
            let response = if inner_request.path.contains("/cash.z.wallet.sdk.rpc.") {
                InnerResponse {
                    status: 200,
                    headers: vec![
                        ("content-type".to_string(), "application/grpc".to_string()),
                        ("grpc-status".to_string(), "14".to_string()),
                        (
                            "grpc-message".to_string(),
                            "Service unavailable: backend limit reached".to_string(),
                        ),
                    ],
                    body: vec![],
                }
            } else {
                InnerResponse {
                    status: 503,
                    headers: vec![("content-type".to_string(), "text/plain".to_string())],
                    body: b"Service unavailable: backend limit reached".to_vec(),
                }
            };
            return Ok((
                response.status,
                response.headers,
                Box::pin(stream::once(async move {
                    Ok(UpFrame::Data(Bytes::from(response.body)))
                })),
            ));
        }
    };

    // Build HTTP request
    let mut req_builder = Request::builder()
        .method(inner_request.method.as_str())
        .uri(&backend_uri);

    // Gateway-owned X-Request-Id. Not for a dynamic host: a host a published document chose
    // gets no key that joins its logs to the gateway's.
    if dynamic.is_none() {
        req_builder = req_builder.header("X-Request-Id", request_id.to_string());
    }

    // Determine if we'll inject grpc-accept-encoding: identity (h2c backends only)
    let inject_identity_encoding = !backend_uri.to_string().starts_with("https://");
    if dynamic.is_none() && is_grpc_request(inner_request) {
        req_builder = req_builder.header("grpc-request-id", request_id.to_string());
    }

    // Forward only allowed gRPC negotiation headers from client
    for (name, value) in &inner_request.headers {
        if forward_header(name) {
            if inject_identity_encoding && name.eq_ignore_ascii_case("grpc-accept-encoding") {
                continue; // Will be replaced below
            }
            req_builder = req_builder.header(name.as_str(), value.as_str());
        }
    }
    if dynamic.is_none() && crate::flexa::is_alias(config.flexa_alias.as_deref(), &authority_lower)
    {
        for (name, value) in crate::flexa::upstream_headers(
            &inner_request.headers,
            config.flexa_publishable_key.as_deref(),
        ) {
            req_builder = req_builder.header(name, value);
        }
    }

    // Fixed user-agent
    req_builder = req_builder.header("User-Agent", "ohttp-gateway/1.0");

    // For gRPC backends (h2c, not https), inject grpc-accept-encoding: identity
    if inject_identity_encoding {
        req_builder = req_builder.header("grpc-accept-encoding", "identity");
    }

    // Inject per-backend credentials. Never for a dynamic host: credentials belong to
    // `BACKENDS` aliases only.
    if let Some(extra) = config
        .backend_headers
        .get(&authority_lower)
        .filter(|_| dynamic.is_none())
    {
        for (name, value) in extra {
            req_builder = req_builder.header(name.as_str(), value.as_str());
        }
    }

    let http_request = req_builder
        .body(Full::new(Bytes::from(inner_request.body.clone())))
        .map_err(|e| anyhow!("Failed to build HTTP request: {:?}", e))?;

    let overall = Duration::from_secs(config.lwd_timeout_secs);

    // Make the HTTP request
    // GW-SILENCE: The head wait (status + headers) is bounded by the overall timeout (LWD_TIMEOUT_SECS).
    // For SSE responses, if the head takes >25s, keep-alives cannot prevent relay timeout
    // (we cannot send the inner head until we receive the upstream head, and we cannot send
    // keep-alives before the inner head). This is acceptable because:
    // (a) Normal SSE backends (Flexa) send headers immediately and stream events.
    // (b) The overall timeout bounds the worst case.
    // (c) A backend that takes >25s to send headers is effectively unavailable.
    let http_response = if dynamic.is_some() {
        // Dynamic hosts: the client whose resolver hands out public addresses only.
        timeout(overall, dynamic_backend_client().request(http_request))
            .await
            .map_err(|_| anyhow!("Backend did not respond within {:?}", overall))?
            .map_err(|e| anyhow!("HTTPS request failed: {:?}", e))?
    } else if backend_uri.starts_with("https://") {
        timeout(overall, https_backend_client().request(http_request))
            .await
            .map_err(|_| anyhow!("Backend did not respond within {:?}", overall))?
            .map_err(|e| anyhow!("HTTPS request failed: {:?}", e))?
    } else {
        let call = crate::lwd_endpoints::CallOpts {
            network: &config.network,
            head: overall,
            class: None,
            pooled: false,
            may_hedge: !crate::enforcement::is_heavy_lwd_call(
                &inner_request.path,
                &inner_request.body,
                config.lwd_heavy_block_range,
            ),
        };
        match crate::lwd_endpoints::request(http_request, call).await {
            Ok(r) => r,
            Err(crate::lwd_endpoints::RequestError::Timeout) => {
                return Err(anyhow!("LWD did not respond within {:?}", overall))
            }
            Err(e) => return Err(anyhow!("HTTP request failed: {:?}", e)),
        }
    };

    let status = http_response.status().as_u16();
    let headers: Vec<(String, String)> = http_response
        .headers()
        .iter()
        .filter(|(k, _)| return_header(k.as_str()))
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let event_stream = is_event_stream(&headers);

    let body_stream = http_response.into_body();
    let max_response_bytes = config.max_upstream_response_bytes;
    let network = config.network.clone();
    let backend_label = backend_type.clone();

    // Computed before the stream, which captures no borrowed references.
    let rpc_name = rpc_label_in(config, inner_request, route);

    // GW-SILENCE: SSE keep-alive interval to prevent relay between-bytes timeouts
    let sse_keepalive = if event_stream {
        Duration::from_secs(config.sse_keepalive_secs)
    } else {
        Duration::ZERO
    };

    // Create the streaming response
    let frame_stream = async_stream::stream! {
        let mut body_out = body_stream;
        let mut bytes_read: usize = 0;
        let mut trailer_headers: Vec<(String, String)> = Vec::new();
        // Track the last few bytes sent to check for event boundaries in SSE streams.
        // An event boundary is after \n\n or \r\n\r\n, or at stream start.
        let mut last_bytes: Vec<u8> = Vec::new();

        // The upstream timeout bounds the total time since the upstream call started (head + body),
        // not just the body wait time. This prevents a non-SSE call from waiting 80s for head
        // plus 80s for body. An event stream (SSE) is cut once the upstream timeout
        // has passed since it was forwarded, without a final chunk: the SDKs reconnect after a
        // broken stream (Android not after an end).
        // GW-SILENCE: For SSE, emit keep-alive comments to prevent relay timeouts.
        // Keep-alives start as soon as this stream yields to the responder (inner head sent).
        let mut upstream_wait = Duration::ZERO;
        loop {
            let waiting = Instant::now();
            let budget = overall.saturating_sub(upstream_start.elapsed());
            // GW-SILENCE: For SSE, wait at most sse_keepalive_secs for the next frame
            let wait_time = if event_stream && !sse_keepalive.is_zero() && budget > sse_keepalive {
                sse_keepalive
            } else {
                budget
            };
            // Checked before polling: a frame that is already buffered must not extend the cap.
            let next = if budget.is_zero() {
                Err(())
            } else {
                timeout(wait_time, body_out.frame()).await.map_err(|_| ())
            };
            let elapsed = waiting.elapsed();
            upstream_wait += elapsed;

            // GW-SILENCE: If SSE keep-alive timeout expired (not the overall budget), emit a keep-alive comment
            // only at an event boundary (stream start, or after \n\n or \r\n\r\n).
            if next.is_err() && event_stream && !sse_keepalive.is_zero() && elapsed >= sse_keepalive && budget > sse_keepalive {
                let at_boundary = last_bytes.is_empty() ||
                    last_bytes.ends_with(b"\n\n") ||
                    last_bytes.ends_with(b"\r\n\r\n");
                if at_boundary {
                    // Emit SSE keep-alive comment (valid SSE: colon starts a comment, ended by \n\n)
                    yield Ok(UpFrame::Data(Bytes::from_static(b": keep-alive\n\n")));
                    // The keep-alive itself ends with \n\n, so we're still at a boundary
                    last_bytes.clear();
                    last_bytes.extend_from_slice(b"\n\n");
                }
                continue;
            }

            let next = match next {
                Ok(next) => next,
                Err(()) if event_stream => {
                    info!(
                        request_id = %request_id,
                        backend = backend_label,
                        bytes_read,
                        "Event stream cut at the upstream timeout"
                    );
                    yield Err(anyhow!("Event stream cut at {:?}", overall));
                    break;
                }
                Err(()) => {
                    warn!(
                        request_id = %request_id,
                        backend = backend_label,
                        bytes_read,
                        "Backend body stalled beyond the upstream timeout"
                    );
                    yield Err(anyhow!("Backend body stalled beyond {:?}", overall));
                    break;
                }
            };
            match next {
                Some(Ok(frame)) => {
                    match frame.into_data() {
                        Ok(data) => {
                            let data_len = data.len();
                            if bytes_read + data_len > max_response_bytes {
                                // Exceeded limit mid-stream
                                warn!(
                                    request_id = %request_id,
                                    bytes_read,
                                    data_len,
                                    max_response_bytes,
                                    "Response exceeded max size mid-stream"
                                );
                                health::record_response_truncated(&network);
                                yield Err(anyhow!(
                                    "Response exceeded max size {} bytes",
                                    max_response_bytes
                                ));
                                break;
                            }
                            bytes_read += data_len;
                            // Update last_bytes for SSE event boundary tracking. Keep only the last
                            // 4 bytes, enough to check for \n\n or \r\n\r\n.
                            if event_stream {
                                last_bytes.extend_from_slice(&data);
                                if last_bytes.len() > 4 {
                                    last_bytes.drain(0..last_bytes.len() - 4);
                                }
                            }
                            yield Ok(UpFrame::Data(data));
                        }
                        Err(frame) => {
                            // Try to extract trailers
                            if let Ok(trailers) = frame.into_trailers() {
                                for (k, v) in trailers.iter() {
                                    if return_header(k.as_str()) {
                                        trailer_headers.push((k.to_string(), v.to_str().unwrap_or("").to_string()));
                                    }
                                }
                            }
                        }
                    }
                }
                Some(Err(e)) => {
                    yield Err(anyhow!("Backend body error: {:?}", e));
                    break;
                }
                None => {
                    // End of stream - send trailers if any
                    if !trailer_headers.is_empty() {
                        yield Ok(UpFrame::Trailers(trailer_headers));
                    }
                    break;
                }
            }
        }

        // Log completion
        let duration_secs = upstream_start.elapsed().as_secs_f64();
        health::record_upstream_request(
            &network,
            &backend_label,
            &rpc_name,
            status,
            "-", // grpc-status not known here in streaming mode
            duration_secs,
        );

        info!(
            request_id = %request_id,
            client_trace_id = client_trace_id.as_deref().unwrap_or("-"),
            backend = backend_label,
            status,
            bytes_out = bytes_read,
            duration_ms = (duration_secs * 1000.0) as u64,
            network = network,
            "Backend streaming response ended"
        );
    };

    Ok((status, headers, Box::pin(frame_stream)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suffix_matching_dot_prefix() {
        let suffixes = vec![
            ".backend-provider.example".to_string(),
            ".backend-staging.example".to_string(),
        ];

        // Should match subdomain
        assert!(matches_allowed_suffix(
            "prod.vote-chain-primary.backend-provider.example",
            &suffixes
        ));
        assert!(matches_allowed_suffix(
            "voting.backend-staging.example",
            &suffixes
        ));

        // Should NOT match the bare domain when suffix has dot prefix
        assert!(!matches_allowed_suffix(
            "backend-provider.example",
            &suffixes
        ));
        assert!(!matches_allowed_suffix(
            "backend-staging.example",
            &suffixes
        ));

        // Should NOT match similar but not exact suffix
        assert!(!matches_allowed_suffix(
            "evilbackend-provider.example",
            &suffixes
        ));
        assert!(!matches_allowed_suffix(
            "malicious.backend-provider.example.attacker.example",
            &suffixes
        ));
    }

    #[test]
    fn test_suffix_matching_bare_domain() {
        let suffixes = vec!["backend-api.example".to_string()];

        // Should match exact domain
        assert!(matches_allowed_suffix("backend-api.example", &suffixes));

        // Should match subdomain
        assert!(matches_allowed_suffix(
            "1click.backend-api.example",
            &suffixes
        ));
        assert!(matches_allowed_suffix("api.backend-api.example", &suffixes));

        // Should NOT match partial match
        assert!(!matches_allowed_suffix("notbackend-api.example", &suffixes));
        assert!(!matches_allowed_suffix(
            "backend-api.example.attacker.example",
            &suffixes
        ));
    }

    #[test]
    fn test_suffix_matching_with_port() {
        let suffixes = vec![".backend-provider.example".to_string()];

        // Authority with port should be stripped before matching
        let authority_with_port = "prod.vote-chain-primary.backend-provider.example:443";
        let normalized = authority_with_port.split(':').next().unwrap();
        assert!(matches_allowed_suffix(normalized, &suffixes));
    }

    #[test]
    fn test_suffix_matching_empty() {
        let suffixes: Vec<String> = vec![];

        // Empty suffixes list should not match anything
        assert!(!matches_allowed_suffix("any.domain.example", &suffixes));
        assert!(!matches_allowed_suffix(
            "prod.backend-provider.example",
            &suffixes
        ));
    }

    #[test]
    fn test_suffix_matching_mixed() {
        let suffixes = vec![
            ".backend-provider.example".to_string(),
            ".backend-staging.example".to_string(),
            "backend-api.example".to_string(),
        ];

        // Dot-prefixed suffixes
        assert!(matches_allowed_suffix(
            "prod.vote-chain-primary.backend-provider.example",
            &suffixes
        ));
        assert!(!matches_allowed_suffix(
            "backend-provider.example",
            &suffixes
        ));

        // Bare domain
        assert!(matches_allowed_suffix("backend-api.example", &suffixes));
        assert!(matches_allowed_suffix(
            "1click.backend-api.example",
            &suffixes
        ));

        // Non-matching
        assert!(!matches_allowed_suffix("example.com", &suffixes));
        assert!(!matches_allowed_suffix(
            "evil.vote-provider.example",
            &suffixes
        ));
    }

    #[test]
    fn test_is_gateway_host_exact_match() {
        let gateway_hosts = vec![
            "ohttp-gateway.example".to_string(),
            "ohttp-gateway-testnet.example".to_string(),
        ];

        // Exact match (case-insensitive)
        assert!(is_gateway_host("ohttp-gateway.example", &gateway_hosts));
        assert!(is_gateway_host("OHTTP-GATEWAY.EXAMPLE", &gateway_hosts));
        assert!(is_gateway_host(
            "ohttp-gateway-testnet.example",
            &gateway_hosts
        ));

        // No match
        assert!(!is_gateway_host("example.com", &gateway_hosts));
        assert!(!is_gateway_host(
            "evil.ohttp-gateway.example",
            &gateway_hosts
        ));
        assert!(!is_gateway_host(
            "ohttp-gateway.example.attacker.example",
            &gateway_hosts
        ));
    }

    #[test]
    fn test_is_gateway_host_with_port() {
        let gateway_hosts = vec!["ohttp-gateway.example".to_string()];

        // Port should be stripped
        assert!(is_gateway_host("ohttp-gateway.example:443", &gateway_hosts));
        assert!(is_gateway_host(
            "ohttp-gateway.example:8080",
            &gateway_hosts
        ));
        assert!(is_gateway_host(
            "OHTTP-GATEWAY.EXAMPLE:9000",
            &gateway_hosts
        ));

        // Different host with port should not match
        assert!(!is_gateway_host("example.com:443", &gateway_hosts));
    }

    #[test]
    fn test_is_gateway_host_empty() {
        let gateway_hosts: Vec<String> = vec![];

        // Empty list should not match anything
        assert!(!is_gateway_host("ohttp-gateway.example", &gateway_hosts));
        assert!(!is_gateway_host("any.domain.example", &gateway_hosts));
    }

    fn test_config(gateway_hosts: &[&str]) -> Config {
        let mut backends = std::collections::HashMap::new();
        backends.insert(
            "api1.example.com".to_string(),
            "https://prices-upstream.example".to_string(),
        );
        Config {
            port: 8080,
            lwd_addr: "lwd:9067".to_string(),
            mode: "ohttp".to_string(),
            relay_secrets: vec![],
            allow_unauthenticated_relay: true,
            hpke_private_key: None,
            hpke_key_id: 1,
            hpke_keys: vec![],
            lwd_timeout_secs: 30,
            long_poll_max_initial_silence_secs: 25,
            long_poll_idle_secs: 3,
            sse_keepalive_secs: 20,
            redis_url: String::new(),
            redis_security_url: String::new(),
            backends,
            backend_headers: std::collections::HashMap::new(),
            backends_policy: std::collections::HashMap::new(),
            backends_policy_default_allow: true,
            max_inflight_lwd: 128,
            max_inflight_lwd_heavy: 32,
            lwd_heavy_block_range: 100,
            lwd_permit_wait_ms: 2000,
            lwd_permit_max_waiters: 0,
            redis_op_timeout_ms: 250,
            max_cache_get_concurrency: 64,
            max_large_response_concurrency: 2,
            large_response_threshold: 8 * 1024 * 1024,
            proxy_allow_suffixes: vec![],
            network: "testnet".to_string(),
            log_outer_header_names: false,
            gateway_hosts: gateway_hosts.iter().map(|s| s.to_string()).collect(),
            configs_signing_seed: None,
            max_upstream_response_bytes: 64 * 1024 * 1024,
            max_inflight_upstream: 256,
            max_inflight_per_backend: 64,
            max_block_range: 1000,
            chunk_size: 16384,
            chunk_flush_ms: 50,
            flexa_publishable_key: None,
            flexa_alias: None,
            near_alias: None,
            dynamic_hosts: Default::default(),
            host_list: Default::default(),
            third_party_query_rules: Default::default(),
            relay_secret_on_key_config: crate::config::RelaySecretOnKeyConfig::Off,
        }
    }

    fn req(authority: &str) -> InnerRequest {
        InnerRequest {
            method: "POST".to_string(),
            path: "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock".to_string(),
            authority: authority.to_string(),
            headers: vec![],
            body: vec![0, 0, 0, 0, 0],
        }
    }

    #[test]
    fn test_gateway_host_policy() {
        let mut cfg = test_config(&["gw.example.com"]);
        let r = |authority: &str, method: &str, path: &str| InnerRequest {
            method: method.to_string(),
            path: path.to_string(),
            ..req(authority)
        };
        let lwd = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock";
        // No entry: the gateway host is not restricted.
        assert!(!gateway_host_policy_denies(
            &cfg,
            &r("gw.example.com", "GET", "/anything")
        ));
        cfg.backends_policy.insert(
            "gw.example.com".to_string(),
            vec![(
                "POST".to_string(),
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/*".to_string(),
            )],
        );
        assert!(!gateway_host_policy_denies(
            &cfg,
            &r("gw.example.com", "POST", lwd)
        ));
        assert!(!gateway_host_policy_denies(
            &cfg,
            &r("GW.example.com:443", "POST", lwd)
        ));
        assert!(gateway_host_policy_denies(
            &cfg,
            &r("gw.example.com", "GET", lwd)
        ));
        assert!(gateway_host_policy_denies(
            &cfg,
            &r(
                "gw.example.com",
                "POST",
                "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
            )
        ));
        assert!(gateway_host_policy_denies(
            &cfg,
            &r(
                "gw.example.com",
                "POST",
                "/cash.z.wallet.sdk.rpc.CompactTxStreamerX/GetLatestBlock"
            )
        ));
        // Other authorities are not affected (BACKENDS entries have their own check).
        assert!(!gateway_host_policy_denies(
            &cfg,
            &r("api1.example.com", "GET", "/x")
        ));
    }

    #[test]
    fn test_resolve_backend_own_host_is_lwd_and_cacheable() {
        let cfg = test_config(&["ohttp-gateway-testnet.example"]);
        let t = resolve_backend(&cfg, &req("ohttp-gateway-testnet.example"));
        assert!(t.is_lwd());
        match t {
            BackendTarget::Upstream { uri, label } => {
                assert_eq!(label, "lwd");
                assert_eq!(
                    uri,
                    "http://lwd:9067/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock"
                );
            }
            BackendTarget::Rejected => panic!("own host rejected"),
            BackendTarget::MalformedAuthority(r) => panic!("own host malformed authority: {}", r),
            BackendTarget::MalformedPath(r) => panic!("own host malformed path: {}", r),
        }
        // Empty authority must be rejected, not routed to LWD
        assert!(matches!(
            resolve_backend(&cfg, &req("")),
            BackendTarget::MalformedAuthority("empty authority")
        ));
        // Uppercase authority is now rejected as malformed
        let uppercase_result = resolve_backend(&cfg, &req("OHTTP-GATEWAY-TESTNET.example:443"));
        assert!(matches!(
            uppercase_result,
            BackendTarget::MalformedAuthority(_)
        ));
    }

    #[test]
    fn test_resolve_backend_unknown_authority_rejected_not_cacheable() {
        let cfg = test_config(&["ohttp-gateway-testnet.example"]);
        let t = resolve_backend(&cfg, &req("evil.example.com"));
        assert!(matches!(t, BackendTarget::Rejected));
        assert!(!t.is_lwd());
    }

    #[test]
    fn test_resolve_backend_mapped_not_cacheable() {
        let cfg = test_config(&["ohttp-gateway-testnet.example"]);
        match resolve_backend(&cfg, &req("api1.example.com")) {
            BackendTarget::Upstream { uri, label } => {
                // label is the actual authority for per-alias semaphores
                assert_eq!(label, "api1.example.com");
                assert!(uri.starts_with("https://prices-upstream.example/"));
            }
            BackendTarget::Rejected => panic!("mapped rejected"),
            BackendTarget::MalformedAuthority(r) => panic!("mapped malformed authority: {}", r),
            BackendTarget::MalformedPath(r) => panic!("mapped malformed path: {}", r),
        }
        assert!(!resolve_backend(&cfg, &req("api1.example.com")).is_lwd());

        // Suffix routing removed per security audit; unknown authorities are now rejected
        let t = resolve_backend(&cfg, &req("voting.backend-staging.example"));
        assert!(matches!(t, BackendTarget::Rejected));
        assert!(!t.is_lwd());
    }

    #[test]
    fn test_resolve_backend_permissive_when_gateway_hosts_empty() {
        let cfg = test_config(&[]);
        assert!(resolve_backend(&cfg, &req("anything.example.com")).is_lwd());
    }

    #[test]
    fn test_create_rejected_authority_response() {
        let response = create_rejected_authority_response();

        assert_eq!(response.status, 403);
        assert_eq!(response.body, b"unknown authority");
        assert_eq!(response.headers.len(), 1);
        assert_eq!(response.headers[0].0, "content-type");
        assert_eq!(response.headers[0].1, "text/plain");
    }

    #[test]
    fn test_validate_authority_valid() {
        assert_eq!(validate_authority(""), None); // Empty is valid
        assert_eq!(validate_authority("example.com"), None);
        assert_eq!(validate_authority("sub.example.com"), None);
        assert_eq!(validate_authority("example.com:443"), None);
        assert_eq!(validate_authority("example.com:9067"), None);
        assert_eq!(
            validate_authority("voting.backend-staging.example:443"),
            None
        );
        assert_eq!(validate_authority("192.0.2.1"), None); // IP-like is OK (just labels)
    }

    #[test]
    fn test_validate_authority_invalid() {
        // Uppercase
        assert!(validate_authority("API1.example.com").is_some());
        assert!(validate_authority("Example.COM").is_some());

        // Attack vectors from spec
        assert!(validate_authority("api1.example.com.attacker.example/x").is_some()); // slash
        assert!(validate_authority("attacker.example/x.backend-staging.example").is_some()); // slash

        // Invalid characters
        assert!(validate_authority("example.com@attacker").is_some());
        assert!(validate_authority("example.com?query").is_some());
        assert!(validate_authority("example.com#fragment").is_some());
        assert!(validate_authority("example.com with space").is_some());
        assert!(validate_authority("example.com\x00").is_some()); // control char

        // Port issues
        assert!(validate_authority("example.com:").is_some()); // empty port
        assert!(validate_authority("example.com:0").is_some()); // port 0
        assert!(validate_authority("example.com:65536").is_some()); // port out of range
        assert!(validate_authority("example.com:abc").is_some()); // non-numeric port

        // DNS label issues
        assert!(validate_authority(".example.com").is_some()); // leading dot
        assert!(validate_authority("example.com.").is_some()); // trailing dot
        assert!(validate_authority("-example.com").is_some()); // label starts with hyphen
        assert!(validate_authority("example-.com").is_some()); // label ends with hyphen
        assert!(validate_authority("example..com").is_some()); // empty label

        // Too long
        let long_host = "a".repeat(254);
        assert!(validate_authority(&long_host).is_some());

        // Label too long (>63 chars)
        let long_label = format!("{}.com", "a".repeat(64));
        assert!(validate_authority(&long_label).is_some());
    }

    #[test]
    fn test_validate_path_valid() {
        assert_eq!(validate_path("/"), None);
        assert_eq!(validate_path("/path"), None);
        assert_eq!(validate_path("/path/to/resource"), None);
        assert_eq!(validate_path("/path?query=value"), None);
        assert_eq!(validate_path("/v1/key/info"), None);
        assert_eq!(
            validate_path("/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock"),
            None
        );
    }

    #[test]
    fn test_validate_path_invalid() {
        // Missing leading slash
        assert!(validate_path("path").is_some());
        assert!(validate_path("").is_some());

        // Starts with //
        assert!(validate_path("//attacker.example/x").is_some());

        // Contains fragment
        assert!(validate_path("/path#fragment").is_some());

        // Contains .. segment
        assert!(validate_path("/path/../etc/passwd").is_some());
        assert!(validate_path("/../etc/passwd").is_some());

        // Non-visible ASCII (space, tab, newline)
        assert!(validate_path("/path with space").is_some());
        assert!(validate_path("/path\t").is_some());
        assert!(validate_path("/path\n").is_some());
        assert!(validate_path("/path\x00").is_some()); // null byte
        assert!(validate_path("/path\x1f").is_some()); // control char

        // Too long (> 8 KiB)
        let long_path = format!("/{}", "a".repeat(8200));
        assert!(validate_path(&long_path).is_some());
    }

    #[test]
    fn test_resolve_backend_attack_vectors() {
        let cfg = test_config(&["ohttp-gateway-testnet.example"]);

        // Attack 1: authority with slash (api1.example.com.attacker.example/x)
        let attack1 = req("api1.example.com.attacker.example/x");
        let result = resolve_backend(&cfg, &attack1);
        assert!(matches!(result, BackendTarget::MalformedAuthority(_)));

        // Attack 2: authority suffix bypass (attacker.example/x.backend-staging.example)
        let attack2 = req("attacker.example/x.backend-staging.example");
        let result = resolve_backend(&cfg, &attack2);
        assert!(matches!(result, BackendTarget::MalformedAuthority(_)));

        // Attack 3: path with space
        let mut attack3 = req("ohttp-gateway-testnet.example");
        attack3.path = "/path with space".to_string();
        let result = resolve_backend(&cfg, &attack3);
        assert!(matches!(result, BackendTarget::MalformedPath(_)));

        // Attack 4: path with fragment
        let mut attack4 = req("ohttp-gateway-testnet.example");
        attack4.path = "/path#fragment".to_string();
        let result = resolve_backend(&cfg, &attack4);
        assert!(matches!(result, BackendTarget::MalformedPath(_)));

        // Attack 5: path with .. segment
        let mut attack5 = req("ohttp-gateway-testnet.example");
        attack5.path = "/../etc/passwd".to_string();
        let result = resolve_backend(&cfg, &attack5);
        assert!(matches!(result, BackendTarget::MalformedPath(_)));

        // Attack 6: an uppercase alias (API1.example.com) is rejected as malformed
        let uppercase_alias = req("API1.example.com");
        let result = resolve_backend(&cfg, &uppercase_alias);
        // Should be rejected for uppercase (malformed authority)
        assert!(matches!(result, BackendTarget::MalformedAuthority(_)));
    }

    #[test]
    fn test_resolve_backend_valid_mapped() {
        let cfg = test_config(&["ohttp-gateway-testnet.example"]);

        // Valid mapped backend (lowercase)
        let result = resolve_backend(&cfg, &req("api1.example.com"));
        match result {
            BackendTarget::Upstream { uri, label } => {
                // label is the actual authority for per-alias semaphores
                assert_eq!(label, "api1.example.com");
                assert!(uri.starts_with("https://prices-upstream.example/"));
                assert!(uri.contains("/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock"));
            }
            BackendTarget::Rejected => panic!("mapped rejected"),
            BackendTarget::MalformedAuthority(reason) => {
                panic!("mapped authority considered malformed: {}", reason)
            }
            BackendTarget::MalformedPath(reason) => {
                panic!("mapped path considered malformed: {}", reason)
            }
        }
    }

    #[test]
    fn test_resolve_backend_suffix_routing_removed() {
        let cfg = test_config(&["ohttp-gateway-testnet.example"]);

        // Suffix routing removed per security audit; all unknown authorities rejected
        let result = resolve_backend(&cfg, &req("voting.backend-staging.example:443"));
        assert!(matches!(result, BackendTarget::Rejected));
    }

    #[test]
    fn test_build_validated_uri_success() {
        // Test that valid URIs are built correctly
        let base = "https://prices-upstream.example";
        let path = "/v1/key/info";
        let expected_host = "prices-upstream.example";

        let result = build_validated_uri(base, path, expected_host);
        assert!(result.is_ok());

        let uri = result.unwrap();
        assert_eq!(uri, "https://prices-upstream.example/v1/key/info");
    }

    #[test]
    fn test_build_validated_uri_host_mismatch() {
        // Test that URI host mismatch is detected (this shouldn't happen in practice because
        // we validate authority first, but demonstrates the safety check)
        let base = "https://prices-upstream.example";
        let path = "/v1/key/info";
        let wrong_expected_host = "attacker.example";

        let result = build_validated_uri(base, path, wrong_expected_host);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("host mismatch"));
    }

    #[test]
    fn test_build_validated_uri_path_is_only_a_path() {
        let base = "https://prices-upstream.example";
        let host = "prices-upstream.example";
        assert_eq!(
            build_validated_uri(base, "//attacker.example/x", host).unwrap(),
            "https://prices-upstream.example//attacker.example/x"
        );
        assert!(build_validated_uri(base, "@attacker.example/x", host).is_err());
        assert!(build_validated_uri(base, "/a b", host).is_err());
    }
}

#[cfg(test)]
mod policy_enforcement_tests {
    use super::*;
    use std::collections::HashMap;

    fn test_config() -> Config {
        let mut backends = HashMap::new();
        backends.insert(
            "api2.example.com".to_string(),
            "https://1click.backend-api.example".to_string(),
        );
        backends.insert(
            "vote.example".to_string(),
            "https://voting.backend-staging.example".to_string(),
        );
        backends.insert(
            "api1.example.com".to_string(),
            "https://prices-upstream.example".to_string(),
        );

        let mut backends_policy = HashMap::new();
        backends_policy.insert(
            "api2.example.com".to_string(),
            vec![
                ("GET".to_string(), "/v0/tokens".to_string()),
                ("POST".to_string(), "/v0/quote".to_string()),
                ("GET".to_string(), "/v0/status".to_string()),
                ("POST".to_string(), "/v0/deposit/submit".to_string()),
            ],
        );
        backends_policy.insert(
            "vote.example".to_string(),
            vec![("GET".to_string(), "/*".to_string())],
        );
        backends_policy.insert(
            "api1.example.com".to_string(),
            vec![
                (
                    "GET".to_string(),
                    "/v1/cryptocurrency/quotes/latest".to_string(),
                ),
                ("POST".to_string(), "/v1/key/info".to_string()),
            ],
        );

        Config {
            port: 8080,
            lwd_addr: "localhost:9067".to_string(),
            mode: "ohttp".to_string(),
            relay_secrets: vec![],
            hpke_private_key: None,
            hpke_key_id: 1,
            hpke_keys: vec![],
            lwd_timeout_secs: 80,
            long_poll_max_initial_silence_secs: 25,
            long_poll_idle_secs: 3,
            sse_keepalive_secs: 20,
            redis_url: String::new(),
            redis_security_url: String::new(),
            backends,
            backend_headers: HashMap::new(),
            backends_policy,
            backends_policy_default_allow: false,
            max_inflight_lwd: 128,
            max_inflight_lwd_heavy: 32,
            lwd_heavy_block_range: 100,
            lwd_permit_wait_ms: 2000,
            lwd_permit_max_waiters: 0,
            redis_op_timeout_ms: 250,
            max_cache_get_concurrency: 64,
            max_large_response_concurrency: 2,
            large_response_threshold: 8 * 1024 * 1024,
            max_upstream_response_bytes: 67108864,
            max_inflight_upstream: 256,
            max_inflight_per_backend: 64,
            max_block_range: 1000,
            allow_unauthenticated_relay: false,
            proxy_allow_suffixes: vec![],
            network: "mainnet".to_string(),
            log_outer_header_names: false,
            gateway_hosts: vec!["ohttp-gateway.example".to_string()],
            configs_signing_seed: None,
            chunk_size: 16384,
            chunk_flush_ms: 50,
            flexa_publishable_key: None,
            flexa_alias: None,
            near_alias: None,
            dynamic_hosts: Default::default(),
            host_list: Default::default(),
            third_party_query_rules: Default::default(),
            relay_secret_on_key_config: crate::config::RelaySecretOnKeyConfig::Off,
        }
    }

    #[test]
    fn test_backends_policy_enforcement() {
        let config = test_config();

        // Test denied: api2.example.com GET /v0/nonexistent
        let result = check_operation_policy(&config, "api2.example.com", "GET", "/v0/nonexistent");
        assert_eq!(
            result,
            Some("operation not in alias policy"),
            "api2.example.com GET /v0/nonexistent should be denied"
        );

        // Test allowed: api2.example.com GET /v0/tokens
        let result = check_operation_policy(&config, "api2.example.com", "GET", "/v0/tokens");
        assert_eq!(
            result, None,
            "api2.example.com GET /v0/tokens should be allowed"
        );

        // Test allowed: vote.example GET /anything (wildcard)
        let result = check_operation_policy(
            &config,
            "vote.example",
            "GET",
            "/prod/dynamic-voting-config.json",
        );
        assert_eq!(result, None, "vote.example GET /* should be allowed");

        // Test allowed: api1.example.com POST /v1/key/info (POST is in the policy)
        let result = check_operation_policy(&config, "api1.example.com", "POST", "/v1/key/info");
        assert_eq!(
            result, None,
            "api1.example.com POST /v1/key/info should be allowed per config"
        );
    }

    #[test]
    fn third_party_requests_are_logged_by_their_policy_pattern() {
        let config = test_config();
        let req = |authority: &str, method: &str, path: &str| InnerRequest {
            method: method.to_string(),
            authority: authority.to_string(),
            path: path.to_string(),
            headers: vec![],
            body: vec![],
        };
        assert_eq!(
            loggable_route(
                &config,
                &req("api2.example.com", "GET", "/v0/tokens?depositAddress=t1x")
            ),
            "/v0/tokens"
        );
        assert_eq!(
            loggable_route(
                &config,
                &req("vote.example", "GET", "/rounds/cs_abcdefgh/votes")
            ),
            "/*"
        );
        assert_eq!(
            loggable_route(
                &config,
                &req("api2.example.com", "DELETE", "/v0/tokens/cs_abcdefgh")
            ),
            "(not in policy)"
        );
        // Not a BACKENDS authority (the light client server): the path as it is.
        assert_eq!(
            loggable_route(
                &config,
                &req(
                    "ohttp-gateway.example",
                    "POST",
                    "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock"
                )
            ),
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock"
        );
    }

    #[test]
    fn third_party_requests_are_labelled_by_their_policy_entry() {
        let config = test_config();
        let req = |authority: &str, method: &str, path: &str| InnerRequest {
            method: method.to_string(),
            authority: authority.to_string(),
            path: path.to_string(),
            headers: vec![],
            body: vec![],
        };
        // The entry that admits the request: method and pattern, never the request's own path,
        // query or ids; the authority's case does not matter.
        assert_eq!(
            rpc_label(
                &config,
                &req("api2.example.com", "GET", "/v0/status?depositAddress=t1x")
            ),
            "GET /v0/status"
        );
        assert_eq!(
            rpc_label(&config, &req("API2.example.com", "post", "/v0/quote")),
            "POST /v0/quote"
        );
        assert_eq!(
            rpc_label(
                &config,
                &req("vote.example", "GET", "/rounds/cs_abcdefgh/votes")
            ),
            "GET /*"
        );
        // No entry admits it: "other".
        assert_eq!(
            rpc_label(
                &config,
                &req("api2.example.com", "DELETE", "/v0/tokens/cs_abcdefgh")
            ),
            "other"
        );
        // Not a BACKENDS authority: the light client server's method names, as before.
        assert_eq!(
            rpc_label(
                &config,
                &req(
                    "ohttp-gateway.example",
                    "POST",
                    "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTreeState"
                )
            ),
            "GetTreeState"
        );
        assert_eq!(
            rpc_label(&config, &req("unknown.example", "GET", "/v1/anything")),
            "other"
        );
    }

    #[test]
    fn test_policy_denies_only_mapped_backends_outside_their_policy() {
        let config = test_config();
        let req = |authority: &str, method: &str, path: &str| InnerRequest {
            method: method.to_string(),
            authority: authority.to_string(),
            path: path.to_string(),
            headers: vec![],
            body: vec![],
        };
        assert!(policy_denies(
            &config,
            &req("api2.example.com", "GET", "/v0/nonexistent")
        ));
        assert!(!policy_denies(
            &config,
            &req("api2.example.com", "GET", "/v0/tokens")
        ));
        assert!(!policy_denies(
            &config,
            &req("unknown.example.com", "GET", "/v0/tokens")
        ));
        assert!(!policy_denies(
            &config,
            &req(
                "ohttp-gateway.example",
                "POST",
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock"
            )
        ));
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    fn make_test_config(policy: Vec<(&str, Vec<(&str, &str)>)>) -> Config {
        let mut backends_policy = std::collections::HashMap::new();
        for (authority, policies) in policy {
            backends_policy.insert(
                authority.to_string(),
                policies
                    .into_iter()
                    .map(|(m, p)| (m.to_string(), p.to_string()))
                    .collect(),
            );
        }

        Config {
            port: 8080,
            lwd_addr: "".to_string(),
            mode: "ohttp".to_string(),
            relay_secrets: vec![],
            hpke_private_key: None,
            hpke_key_id: 1,
            hpke_keys: vec![],
            lwd_timeout_secs: 80,
            long_poll_max_initial_silence_secs: 25,
            long_poll_idle_secs: 3,
            sse_keepalive_secs: 20,
            redis_url: "".to_string(),
            redis_security_url: "".to_string(),
            backends: std::collections::HashMap::new(),
            backend_headers: std::collections::HashMap::new(),
            backends_policy,
            backends_policy_default_allow: false,
            max_inflight_lwd: 128,
            max_inflight_lwd_heavy: 32,
            lwd_heavy_block_range: 100,
            lwd_permit_wait_ms: 2000,
            lwd_permit_max_waiters: 0,
            redis_op_timeout_ms: 250,
            max_cache_get_concurrency: 64,
            max_large_response_concurrency: 2,
            large_response_threshold: 8 * 1024 * 1024,
            max_upstream_response_bytes: 64 * 1024 * 1024,
            max_inflight_upstream: 256,
            max_inflight_per_backend: 64,
            max_block_range: 1000,
            allow_unauthenticated_relay: false,
            proxy_allow_suffixes: vec![],
            network: "testnet".to_string(),
            log_outer_header_names: false,
            gateway_hosts: vec![],
            configs_signing_seed: None,
            chunk_size: 16384,
            chunk_flush_ms: 50,
            flexa_publishable_key: None,
            flexa_alias: None,
            near_alias: None,
            dynamic_hosts: Default::default(),
            host_list: Default::default(),
            third_party_query_rules: Default::default(),
            relay_secret_on_key_config: crate::config::RelaySecretOnKeyConfig::Off,
        }
    }

    #[test]
    fn test_segment_bounded_prefix_exact_match() {
        let config = make_test_config(vec![("api.example.com", vec![("GET", "/v1/info")])]);
        assert!(check_operation_policy(&config, "api.example.com", "GET", "/v1/info").is_none());
    }

    #[test]
    fn test_segment_bounded_prefix_no_leak() {
        let config = make_test_config(vec![("api.example.com", vec![("GET", "/v1/info")])]);
        // /v1/information should NOT match /v1/info
        assert!(
            check_operation_policy(&config, "api.example.com", "GET", "/v1/information").is_some()
        );
    }

    #[test]
    fn test_segment_bounded_with_slash() {
        // Exact match semantics: /v1 does NOT match /v1/info (need /v1/* for that)
        let config = make_test_config(vec![("api.example.com", vec![("GET", "/v1")])]);
        // /v1 exact should match
        assert!(check_operation_policy(&config, "api.example.com", "GET", "/v1").is_none());
        // /v1/info should NOT match (need wildcard /v1/* for that)
        assert!(check_operation_policy(&config, "api.example.com", "GET", "/v1/info").is_some());
        // /v1xyz should NOT match
        assert!(check_operation_policy(&config, "api.example.com", "GET", "/v1xyz").is_some());
    }

    #[test]
    fn test_segment_bounded_with_query() {
        let config = make_test_config(vec![("api.example.com", vec![("GET", "/search")])]);
        // /search?q=test should match /search (with ?)
        assert!(
            check_operation_policy(&config, "api.example.com", "GET", "/search?q=test").is_none()
        );
    }

    #[test]
    fn test_wildcard_match() {
        let config = make_test_config(vec![("api.example.com", vec![("GET", "/api/*")])]);
        // /api/v1 should match /api/*
        assert!(check_operation_policy(&config, "api.example.com", "GET", "/api/v1").is_none());
        // /apiv1 should NOT match
        assert!(check_operation_policy(&config, "api.example.com", "GET", "/apiv1").is_some());
    }

    #[test]
    fn test_directory_traversal_rejected() {
        let config = make_test_config(vec![("api.example.com", vec![("GET", "/api/*")])]);
        assert!(check_operation_policy(&config, "api.example.com", "GET", "/api/../etc").is_some());
    }

    #[test]
    fn test_encoded_dots_rejected() {
        let config = make_test_config(vec![("api.example.com", vec![("GET", "/api/*")])]);
        assert!(
            check_operation_policy(&config, "api.example.com", "GET", "/api/%2e%2e/etc").is_some()
        );
        assert!(
            check_operation_policy(&config, "api.example.com", "GET", "/api/%2E%2E/etc").is_some()
        );
    }

    #[test]
    fn test_double_slashes_rejected() {
        let config = make_test_config(vec![("api.example.com", vec![("GET", "/api/*")])]);
        assert!(check_operation_policy(&config, "api.example.com", "GET", "/api//v1").is_some());
    }

    #[test]
    fn test_non_ascii_first_character_does_not_panic() {
        let config = make_test_config(vec![("api.example.com", vec![("GET", "/*")])]);
        assert!(check_operation_policy(&config, "api.example.com", "GET", "é").is_none());
        assert!(check_operation_policy(&config, "api.example.com", "GET", "é//x").is_some());
        assert!(check_operation_policy(&config, "api.example.com", "GET", "/é//x").is_some());
    }
}

#[cfg(test)]
mod method_wildcard_tests {
    use super::*;

    #[test]
    fn test_method_wildcard_matches_all() {
        use std::collections::HashMap;
        let mut backends_policy = HashMap::new();
        backends_policy.insert(
            "wildcard.example".to_string(),
            vec![("*".to_string(), "/api/*".to_string())],
        );
        let config = Config {
            port: 9292,
            lwd_addr: "lwd:9067".to_string(),
            mode: "ohttp".to_string(),
            relay_secrets: vec![],
            hpke_private_key: None,
            hpke_key_id: 0,
            hpke_keys: vec![],
            lwd_timeout_secs: 30,
            long_poll_max_initial_silence_secs: 25,
            long_poll_idle_secs: 30,
            sse_keepalive_secs: 20,
            redis_url: "".to_string(),
            redis_security_url: "".to_string(),
            backends: HashMap::new(),
            backend_headers: HashMap::new(),
            backends_policy,
            backends_policy_default_allow: false,
            max_inflight_lwd: 128,
            max_inflight_lwd_heavy: 32,
            lwd_heavy_block_range: 100,
            lwd_permit_wait_ms: 2000,
            lwd_permit_max_waiters: 0,
            redis_op_timeout_ms: 250,
            max_cache_get_concurrency: 64,
            max_large_response_concurrency: 2,
            large_response_threshold: 8 * 1024 * 1024,
            max_upstream_response_bytes: 64 * 1024 * 1024,
            max_inflight_upstream: 256,
            max_inflight_per_backend: 64,
            max_block_range: 1000,
            allow_unauthenticated_relay: false,
            proxy_allow_suffixes: vec![],
            network: "testnet".to_string(),
            log_outer_header_names: false,
            gateway_hosts: vec![],
            configs_signing_seed: None,
            chunk_size: 16384,
            chunk_flush_ms: 50,
            flexa_publishable_key: None,
            flexa_alias: None,
            near_alias: None,
            dynamic_hosts: Default::default(),
            host_list: Default::default(),
            third_party_query_rules: Default::default(),
            relay_secret_on_key_config: crate::config::RelaySecretOnKeyConfig::Off,
        };

        // Test that * wildcard matches all methods
        for method in &["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"] {
            let result = check_operation_policy(&config, "wildcard.example", method, "/api/test");
            assert_eq!(result, None, "{} should match * wildcard", method);
        }

        // Test that non-matching path is still denied
        let result = check_operation_policy(&config, "wildcard.example", "GET", "/other/path");
        assert_eq!(
            result,
            Some("operation not in alias policy"),
            "/other/path should not match /api/*"
        );
    }
}

#[cfg(test)]
mod path_semantics_tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_exact_path_no_extension() {
        // Exact paths must NOT match path extensions (e.g. /tokens doesn't match /tokensX)
        let mut backends_policy = HashMap::new();
        backends_policy.insert(
            "test.example".to_string(),
            vec![("GET".to_string(), "/v0/tokens".to_string())],
        );
        let config = Config {
            port: 9292,
            lwd_addr: "lwd:9067".to_string(),
            mode: "ohttp".to_string(),
            relay_secrets: vec![],
            hpke_private_key: None,
            hpke_key_id: 0,
            hpke_keys: vec![],
            lwd_timeout_secs: 30,
            long_poll_max_initial_silence_secs: 25,
            long_poll_idle_secs: 30,
            sse_keepalive_secs: 20,
            redis_url: "".to_string(),
            redis_security_url: "".to_string(),
            backends: HashMap::new(),
            backend_headers: HashMap::new(),
            backends_policy,
            backends_policy_default_allow: false,
            max_inflight_lwd: 128,
            max_inflight_lwd_heavy: 32,
            lwd_heavy_block_range: 100,
            lwd_permit_wait_ms: 2000,
            lwd_permit_max_waiters: 0,
            redis_op_timeout_ms: 250,
            max_cache_get_concurrency: 64,
            max_large_response_concurrency: 2,
            large_response_threshold: 8 * 1024 * 1024,
            max_upstream_response_bytes: 64 * 1024 * 1024,
            max_inflight_upstream: 256,
            max_inflight_per_backend: 64,
            max_block_range: 1000,
            allow_unauthenticated_relay: false,
            proxy_allow_suffixes: vec![],
            network: "testnet".to_string(),
            log_outer_header_names: false,
            gateway_hosts: vec![],
            configs_signing_seed: None,
            chunk_size: 16384,
            chunk_flush_ms: 50,
            flexa_publishable_key: None,
            flexa_alias: None,
            near_alias: None,
            dynamic_hosts: Default::default(),
            host_list: Default::default(),
            third_party_query_rules: Default::default(),
            relay_secret_on_key_config: crate::config::RelaySecretOnKeyConfig::Off,
        };

        // Exact match should be allowed
        assert_eq!(
            check_operation_policy(&config, "test.example", "GET", "/v0/tokens"),
            None
        );

        // Query string should be allowed
        assert_eq!(
            check_operation_policy(&config, "test.example", "GET", "/v0/tokens?foo=bar"),
            None
        );

        // Path extension should be DENIED
        assert_eq!(
            check_operation_policy(&config, "test.example", "GET", "/v0/tokens/extra"),
            Some("operation not in alias policy")
        );

        // Similar prefix should be DENIED
        assert_eq!(
            check_operation_policy(&config, "test.example", "GET", "/v0/tokensX"),
            Some("operation not in alias policy")
        );
    }

    #[test]
    fn test_wildcard_path_matches_children() {
        // Wildcard paths match segment-bounded children (e.g. /foo/* matches /foo/bar but not /foobar)
        let mut backends_policy = HashMap::new();
        backends_policy.insert(
            "test.example".to_string(),
            vec![("GET".to_string(), "/shielded-vote/v1/rounds/*".to_string())],
        );
        let config = Config {
            port: 9292,
            lwd_addr: "lwd:9067".to_string(),
            mode: "ohttp".to_string(),
            relay_secrets: vec![],
            hpke_private_key: None,
            hpke_key_id: 0,
            hpke_keys: vec![],
            lwd_timeout_secs: 30,
            long_poll_max_initial_silence_secs: 25,
            long_poll_idle_secs: 30,
            sse_keepalive_secs: 20,
            redis_url: "".to_string(),
            redis_security_url: "".to_string(),
            backends: HashMap::new(),
            backend_headers: HashMap::new(),
            backends_policy,
            backends_policy_default_allow: false,
            max_inflight_lwd: 128,
            max_inflight_lwd_heavy: 32,
            lwd_heavy_block_range: 100,
            lwd_permit_wait_ms: 2000,
            lwd_permit_max_waiters: 0,
            redis_op_timeout_ms: 250,
            max_cache_get_concurrency: 64,
            max_large_response_concurrency: 2,
            large_response_threshold: 8 * 1024 * 1024,
            max_upstream_response_bytes: 64 * 1024 * 1024,
            max_inflight_upstream: 256,
            max_inflight_per_backend: 64,
            max_block_range: 1000,
            allow_unauthenticated_relay: false,
            proxy_allow_suffixes: vec![],
            network: "testnet".to_string(),
            log_outer_header_names: false,
            gateway_hosts: vec![],
            configs_signing_seed: None,
            chunk_size: 16384,
            chunk_flush_ms: 50,
            flexa_publishable_key: None,
            flexa_alias: None,
            near_alias: None,
            dynamic_hosts: Default::default(),
            host_list: Default::default(),
            third_party_query_rules: Default::default(),
            relay_secret_on_key_config: crate::config::RelaySecretOnKeyConfig::Off,
        };

        // Prefix itself should match
        assert_eq!(
            check_operation_policy(&config, "test.example", "GET", "/shielded-vote/v1/rounds"),
            None
        );

        // Children should match
        assert_eq!(
            check_operation_policy(
                &config,
                "test.example",
                "GET",
                "/shielded-vote/v1/rounds/abc123"
            ),
            None
        );
        assert_eq!(
            check_operation_policy(
                &config,
                "test.example",
                "GET",
                "/shielded-vote/v1/rounds/abc123/votes"
            ),
            None
        );

        // Siblings should NOT match
        assert_eq!(
            check_operation_policy(&config, "test.example", "GET", "/shielded-vote/v1/other"),
            Some("operation not in alias policy")
        );
    }

    #[test]
    fn test_root_wildcard_matches_everything() {
        // Root wildcard /* matches all paths
        let mut backends_policy = HashMap::new();
        backends_policy.insert(
            "test.example".to_string(),
            vec![("*".to_string(), "/*".to_string())],
        );
        let config = Config {
            port: 9292,
            lwd_addr: "lwd:9067".to_string(),
            mode: "ohttp".to_string(),
            relay_secrets: vec![],
            hpke_private_key: None,
            hpke_key_id: 0,
            hpke_keys: vec![],
            lwd_timeout_secs: 30,
            long_poll_max_initial_silence_secs: 25,
            long_poll_idle_secs: 30,
            sse_keepalive_secs: 20,
            redis_url: "".to_string(),
            redis_security_url: "".to_string(),
            backends: HashMap::new(),
            backend_headers: HashMap::new(),
            backends_policy,
            backends_policy_default_allow: false,
            max_inflight_lwd: 128,
            max_inflight_lwd_heavy: 32,
            lwd_heavy_block_range: 100,
            lwd_permit_wait_ms: 2000,
            lwd_permit_max_waiters: 0,
            redis_op_timeout_ms: 250,
            max_cache_get_concurrency: 64,
            max_large_response_concurrency: 2,
            large_response_threshold: 8 * 1024 * 1024,
            max_upstream_response_bytes: 64 * 1024 * 1024,
            max_inflight_upstream: 256,
            max_inflight_per_backend: 64,
            max_block_range: 1000,
            allow_unauthenticated_relay: false,
            proxy_allow_suffixes: vec![],
            network: "testnet".to_string(),
            log_outer_header_names: false,
            gateway_hosts: vec![],
            configs_signing_seed: None,
            chunk_size: 16384,
            chunk_flush_ms: 50,
            flexa_publishable_key: None,
            flexa_alias: None,
            near_alias: None,
            dynamic_hosts: Default::default(),
            host_list: Default::default(),
            third_party_query_rules: Default::default(),
            relay_secret_on_key_config: crate::config::RelaySecretOnKeyConfig::Off,
        };

        // Any path should match
        assert_eq!(
            check_operation_policy(&config, "test.example", "GET", "/"),
            None
        );
        assert_eq!(
            check_operation_policy(&config, "test.example", "POST", "/foo"),
            None
        );
        assert_eq!(
            check_operation_policy(&config, "test.example", "DELETE", "/bar/baz"),
            None
        );
    }
}

#[test]
fn test_grpc_framing_single_message() {
    // Single complete message: compressed=0, length=5, payload="hello"
    let buf = vec![0, 0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o'];
    assert_eq!(last_complete_grpc_message_offset(&buf), 10);
    assert_eq!(count_grpc_messages(&buf, 10), 1);
}

#[test]
fn test_grpc_framing_incomplete_message() {
    // Incomplete message: header complete, payload partial
    let buf = vec![0, 0, 0, 0, 10, b'a', b'b', b'c'];
    assert_eq!(last_complete_grpc_message_offset(&buf), 0);
    assert_eq!(count_grpc_messages(&buf, 0), 0);
}

#[test]
fn test_grpc_framing_multiple_messages() {
    // Two complete messages
    let mut buf = vec![0, 0, 0, 0, 3, b'f', b'o', b'o'];
    buf.extend_from_slice(&[0, 0, 0, 0, 3, b'b', b'a', b'r']);
    assert_eq!(last_complete_grpc_message_offset(&buf), 16);
    assert_eq!(count_grpc_messages(&buf, 16), 2);
}

#[test]
fn test_grpc_framing_partial_at_end() {
    // One complete + one incomplete
    let mut buf = vec![0, 0, 0, 0, 3, b'f', b'o', b'o'];
    buf.extend_from_slice(&[0, 0, 0, 0, 5, b'x']);
    assert_eq!(last_complete_grpc_message_offset(&buf), 8);
    assert_eq!(count_grpc_messages(&buf, 8), 1);
}

#[test]
fn test_grpc_framing_empty() {
    let buf = vec![];
    assert_eq!(last_complete_grpc_message_offset(&buf), 0);
    assert_eq!(count_grpc_messages(&buf, 0), 0);
}

#[test]
fn test_grpc_framing_header_only() {
    let buf = vec![0, 0, 0, 0];
    assert_eq!(last_complete_grpc_message_offset(&buf), 0);
    assert_eq!(count_grpc_messages(&buf, 0), 0);
}

#[test]
fn test_grpc_framing_zero_length_message() {
    let buf = vec![0, 0, 0, 0, 0];
    assert_eq!(last_complete_grpc_message_offset(&buf), 5);
    assert_eq!(count_grpc_messages(&buf, 5), 1);
}

#[test]
fn test_grpc_framing_split_across_frames() {
    // Message split: first part has header + 2 bytes, cap hit mid-message
    let buf = vec![0, 0, 0, 0, 10, b'a', b'b'];
    assert_eq!(last_complete_grpc_message_offset(&buf), 0);
    assert_eq!(count_grpc_messages(&buf, 0), 0);
}

#[test]
fn test_grpc_framing_cap_hit_exactly_on_boundary() {
    // Two messages, cap hit exactly at boundary
    let mut buf = vec![0, 0, 0, 0, 3, b'f', b'o', b'o'];
    buf.extend_from_slice(&[0, 0, 0, 0, 3, b'b', b'a', b'r']);
    assert_eq!(last_complete_grpc_message_offset(&buf), 16);
    assert_eq!(count_grpc_messages(&buf, 16), 2);
}

#[cfg(test)]
mod stream_tests {
    use super::*;
    use crate::chunked_stream::UpFrame;
    use axum::body::Bytes;
    use futures_util::StreamExt;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use std::sync::Arc;
    use tokio::net::TcpListener;

    async fn make_test_server(
        response_body: Vec<u8>,
        chunk_size: usize,
        delay_between_chunks_ms: u64,
        headers: Vec<(String, String)>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);

            let body_clone = response_body.clone();
            let service = service_fn(move |_req: Request<hyper::body::Incoming>| {
                let body = body_clone.clone();
                let headers = headers.clone();
                async move {
                    // Stream the body in chunks
                    use futures_util::stream;
                    let chunk_stream = stream::unfold(
                        (body, 0, chunk_size),
                        move |(body, offset, chunk_size)| async move {
                            if offset >= body.len() {
                                return None;
                            }
                            if delay_between_chunks_ms > 0 {
                                tokio::time::sleep(tokio::time::Duration::from_millis(
                                    delay_between_chunks_ms,
                                ))
                                .await;
                            }
                            let end = std::cmp::min(offset + chunk_size, body.len());
                            let chunk = body[offset..end].to_vec();
                            Some((
                                Ok::<_, Infallible>(hyper::body::Frame::data(Bytes::from(chunk))),
                                (body, end, chunk_size),
                            ))
                        },
                    );

                    let mut response = Response::builder().status(200);
                    for (k, v) in headers {
                        response = response.header(k, v);
                    }
                    Ok::<_, Infallible>(
                        response
                            .body(http_body_util::StreamBody::new(chunk_stream))
                            .unwrap(),
                    )
                }
            });

            if let Err(err) =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(io, service)
                    .await
            {
                eprintln!("server error: {}", err);
            }
        });

        format!("http://127.0.0.1:{}", addr.port())
    }

    fn make_test_state(base_url: &str, max_upstream_response_bytes: usize) -> Arc<AppState> {
        let mut backends = std::collections::HashMap::new();
        backends.insert("test.example.com".to_string(), base_url.to_string());

        let config = Config {
            port: 8080,
            lwd_addr: "lwd:9067".to_string(),
            mode: "ohttp".to_string(),
            relay_secrets: vec![],
            allow_unauthenticated_relay: true,
            hpke_private_key: None,
            hpke_key_id: 1,
            hpke_keys: vec![],
            lwd_timeout_secs: 5,
            long_poll_max_initial_silence_secs: 25,
            long_poll_idle_secs: 3,
            sse_keepalive_secs: 20,
            redis_url: String::new(),
            redis_security_url: String::new(),
            backends,
            backend_headers: std::collections::HashMap::new(),
            backends_policy: std::collections::HashMap::new(),
            backends_policy_default_allow: true,
            max_inflight_lwd: 128,
            max_inflight_lwd_heavy: 32,
            lwd_heavy_block_range: 100,
            lwd_permit_wait_ms: 2000,
            lwd_permit_max_waiters: 0,
            redis_op_timeout_ms: 250,
            max_cache_get_concurrency: 64,
            max_large_response_concurrency: 2,
            large_response_threshold: 8 * 1024 * 1024,
            proxy_allow_suffixes: vec![],
            network: "testnet".to_string(),
            log_outer_header_names: false,
            gateway_hosts: vec!["ohttp-gateway.example".to_string()],
            configs_signing_seed: None,
            max_upstream_response_bytes,
            max_inflight_upstream: 256,
            max_inflight_per_backend: 64,
            max_block_range: 1000,
            chunk_size: 16384,
            chunk_flush_ms: 50,
            flexa_publishable_key: None,
            flexa_alias: None,
            near_alias: None,
            dynamic_hosts: Default::default(),
            host_list: Default::default(),
            third_party_query_rules: Default::default(),
            relay_secret_on_key_config: crate::config::RelaySecretOnKeyConfig::Off,
        };

        let lwd_semaphore = Arc::new(tokio::sync::Semaphore::new(128));
        let sources = Arc::new(crate::lwd::LwdSources::new(
            config.clone(),
            lwd_semaphore.clone(),
        ));
        let flights = Arc::new(crate::singleflight::RpcFlights::new(
            sources.clone(),
            config.network.clone(),
        ));
        let mempool = Arc::new(crate::mempool::MempoolFanout::new(
            sources.clone(),
            config.network.clone(),
        ));

        Arc::new(AppState {
            config,
            origin: crate::origin::OriginSettings::default(),
            cache: None,
            hpke: None,
            block_cache: None,
            subtree_cache: None,
            follower: None,
            mempool,
            flights,
            sources,
            signing: None,
            lwd_semaphore,
            global_semaphore: Arc::new(tokio::sync::Semaphore::new(256)),
            cache_get_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            large_response_semaphore: Arc::new(tokio::sync::Semaphore::new(2)),
            third_party: Default::default(),
            per_backend_semaphores: Arc::new(parking_lot::RwLock::new(
                std::collections::HashMap::new(),
            )),
            request_semaphore: Arc::new(tokio::sync::Semaphore::new(1024)),
        })
    }

    #[tokio::test]
    async fn test_stream_arrives_incrementally() {
        // Test that data arrives before the upstream finishes sending
        let body = b"Hello World from streaming backend!".repeat(100);
        let server_url = make_test_server(
            body.clone(),
            512,
            10,
            vec![("content-type".to_string(), "application/json".to_string())],
        )
        .await;

        let state = make_test_state(&server_url, 10 * 1024 * 1024);
        let inner_request = InnerRequest {
            method: "GET".to_string(),
            path: "/test".to_string(),
            authority: "test.example.com".to_string(),
            headers: vec![],
            body: vec![],
        };

        let request_id = uuid::Uuid::new_v4();
        let (status, headers, mut stream) =
            forward_to_backend_stream(&state, &inner_request, request_id, None)
                .await
                .unwrap();

        assert_eq!(status, 200);
        assert!(headers.iter().any(|(k, _)| k == "content-type"));

        // First data frame should arrive before all data is sent
        let first_frame = stream.next().await.unwrap().unwrap();
        match first_frame {
            UpFrame::Data(data) => {
                assert!(!data.is_empty());
                assert!(data.len() < body.len(), "First frame should be partial");
            }
            _ => panic!("Expected data frame"),
        }

        // Collect the rest
        let mut total_bytes = 0;
        while let Some(Ok(frame)) = stream.next().await {
            match frame {
                UpFrame::Data(data) => {
                    total_bytes += data.len();
                }
                UpFrame::Trailers(_) => {}
            }
        }
        assert!(total_bytes > 0);
    }

    #[tokio::test]
    async fn test_stream_full_body_matches_upstream() {
        // Test that the complete body matches what the upstream sent
        let body = b"Test response body with some content!".to_vec();
        let server_url = make_test_server(body.clone(), 10, 0, vec![]).await;

        let state = make_test_state(&server_url, 1024 * 1024);
        let inner_request = InnerRequest {
            method: "GET".to_string(),
            path: "/test".to_string(),
            authority: "test.example.com".to_string(),
            headers: vec![],
            body: vec![],
        };

        let request_id = uuid::Uuid::new_v4();
        let (_status, _headers, mut stream) =
            forward_to_backend_stream(&state, &inner_request, request_id, None)
                .await
                .unwrap();

        let mut collected = Vec::new();
        while let Some(Ok(frame)) = stream.next().await {
            if let UpFrame::Data(data) = frame {
                collected.extend_from_slice(&data);
            }
        }

        assert_eq!(collected, body);
    }

    #[tokio::test]
    async fn test_stream_headers_filtered() {
        // Test that response headers are filtered correctly
        let body = b"response".to_vec();
        let server_url = make_test_server(
            body.clone(),
            100,
            0,
            vec![
                ("content-type".to_string(), "application/json".to_string()),
                (
                    "x-custom-header".to_string(),
                    "should-be-filtered".to_string(),
                ),
                ("date".to_string(), "2024-01-01".to_string()),
            ],
        )
        .await;

        let state = make_test_state(&server_url, 1024);
        let inner_request = InnerRequest {
            method: "GET".to_string(),
            path: "/test".to_string(),
            authority: "test.example.com".to_string(),
            headers: vec![],
            body: vec![],
        };

        let request_id = uuid::Uuid::new_v4();
        let (_status, headers, _stream) =
            forward_to_backend_stream(&state, &inner_request, request_id, None)
                .await
                .unwrap();

        // Should include content-type and date
        assert!(headers.iter().any(|(k, _)| k == "content-type"));
        assert!(headers.iter().any(|(k, _)| k == "date"));
        // Should NOT include x-custom-header
        assert!(!headers.iter().any(|(k, _)| k == "x-custom-header"));
    }

    #[tokio::test]
    async fn test_stream_credentials_injected() {
        // Smoke test of the credential-injection path: the request succeeds (the test server does
        // not echo headers, so their arrival is not asserted here)
        let body = b"authenticated response".to_vec();
        let server_url = make_test_server(body.clone(), 100, 0, vec![]).await;

        let mut backend_headers = std::collections::HashMap::new();
        backend_headers.insert(
            "test.example.com".to_string(),
            vec![("Authorization".to_string(), "Bearer test-token".to_string())],
        );

        let mut backends = std::collections::HashMap::new();
        backends.insert("test.example.com".to_string(), server_url.clone());

        let config = Config {
            port: 8080,
            lwd_addr: "lwd:9067".to_string(),
            mode: "ohttp".to_string(),
            relay_secrets: vec![],
            allow_unauthenticated_relay: true,
            hpke_private_key: None,
            hpke_key_id: 1,
            hpke_keys: vec![],
            lwd_timeout_secs: 5,
            long_poll_max_initial_silence_secs: 25,
            long_poll_idle_secs: 3,
            sse_keepalive_secs: 20,
            redis_url: String::new(),
            redis_security_url: String::new(),
            backends,
            backend_headers,
            backends_policy: std::collections::HashMap::new(),
            backends_policy_default_allow: true,
            max_inflight_lwd: 128,
            max_inflight_lwd_heavy: 32,
            lwd_heavy_block_range: 100,
            lwd_permit_wait_ms: 2000,
            lwd_permit_max_waiters: 0,
            redis_op_timeout_ms: 250,
            max_cache_get_concurrency: 64,
            max_large_response_concurrency: 2,
            large_response_threshold: 8 * 1024 * 1024,
            proxy_allow_suffixes: vec![],
            network: "testnet".to_string(),
            log_outer_header_names: false,
            gateway_hosts: vec!["ohttp-gateway.example".to_string()],
            configs_signing_seed: None,
            max_upstream_response_bytes: 1024 * 1024,
            max_inflight_upstream: 256,
            max_inflight_per_backend: 64,
            max_block_range: 1000,
            chunk_size: 16384,
            chunk_flush_ms: 50,
            flexa_publishable_key: None,
            flexa_alias: None,
            near_alias: None,
            dynamic_hosts: Default::default(),
            host_list: Default::default(),
            third_party_query_rules: Default::default(),
            relay_secret_on_key_config: crate::config::RelaySecretOnKeyConfig::Off,
        };

        let lwd_semaphore_2 = Arc::new(tokio::sync::Semaphore::new(128));
        let sources_2 = Arc::new(crate::lwd::LwdSources::new(
            config.clone(),
            lwd_semaphore_2.clone(),
        ));
        let flights_2 = Arc::new(crate::singleflight::RpcFlights::new(
            sources_2.clone(),
            config.network.clone(),
        ));
        let mempool_2 = Arc::new(crate::mempool::MempoolFanout::new(
            sources_2.clone(),
            config.network.clone(),
        ));

        let state = Arc::new(AppState {
            config,
            origin: crate::origin::OriginSettings::default(),
            cache: None,
            hpke: None,
            block_cache: None,
            subtree_cache: None,
            follower: None,
            mempool: mempool_2,
            flights: flights_2,
            sources: sources_2,
            signing: None,
            lwd_semaphore: lwd_semaphore_2,
            global_semaphore: Arc::new(tokio::sync::Semaphore::new(256)),
            cache_get_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            large_response_semaphore: Arc::new(tokio::sync::Semaphore::new(2)),
            third_party: Default::default(),
            per_backend_semaphores: Arc::new(parking_lot::RwLock::new(
                std::collections::HashMap::new(),
            )),
            request_semaphore: Arc::new(tokio::sync::Semaphore::new(1024)),
        });

        let inner_request = InnerRequest {
            method: "GET".to_string(),
            path: "/test".to_string(),
            authority: "test.example.com".to_string(),
            headers: vec![],
            body: vec![],
        };

        let request_id = uuid::Uuid::new_v4();
        let (status, _headers, mut stream) =
            forward_to_backend_stream(&state, &inner_request, request_id, None)
                .await
                .unwrap();

        assert_eq!(status, 200);

        // Consume the stream
        while stream.next().await.is_some() {}
    }

    /// A backend that answers every request with its request headers, one `name: value` per line.
    async fn make_echo_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let service = service_fn(|req: Request<hyper::body::Incoming>| async move {
                    let mut lines: Vec<String> = req
                        .headers()
                        .iter()
                        .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
                        .collect();
                    lines.sort();
                    Ok::<_, Infallible>(Response::new(http_body_util::Full::new(Bytes::from(
                        lines.join("\n"),
                    ))))
                });
                tokio::spawn(async move {
                    let _ = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
                });
            }
        });
        format!("http://127.0.0.1:{}", addr.port())
    }

    /// The Flexa alias of these tests (`FLEXA_ALIAS`).
    const FLEXA_TEST_ALIAS: &str = "pay.example";

    /// A Flexa policy: the operations the Flexa Android and iOS SDKs call.
    const FLEXA_POLICY: &str =
        "GET /accounts/me,POST /accounts,POST /accounts/me/initiate_deletion,\
        PUT /accounts/me/one_time_keys,DELETE /app_notifications/*,GET /assets,GET /assets/*,\
        GET /brands,POST /commerce_sessions,GET /commerce_sessions/*,PATCH /commerce_sessions/*,\
        POST /commerce_sessions/*,GET /events,GET /exchange_rates,POST /tokens,PATCH /tokens/*,\
        DELETE /tokens/*,GET /transaction_fees,PATCH /transactions/*";

    fn flexa_state(base_url: &str, key: Option<&str>, lwd_timeout_secs: u64) -> Arc<AppState> {
        let state = make_test_state(base_url, 1024 * 1024);
        let mut config = state.config.clone();
        config.flexa_alias = Some(FLEXA_TEST_ALIAS.to_string());
        config.backends = [(FLEXA_TEST_ALIAS.to_string(), base_url.to_string())].into();
        config.backends_policy = [(
            FLEXA_TEST_ALIAS.to_string(),
            FLEXA_POLICY
                .split(',')
                .map(|op| {
                    let (m, p) = op.trim().split_once(' ').unwrap();
                    (m.to_string(), p.to_string())
                })
                .collect(),
        )]
        .into();
        config.backends_policy_default_allow = false;
        config.flexa_publishable_key = key.map(str::to_string);
        config.lwd_timeout_secs = lwd_timeout_secs;
        let state = Arc::try_unwrap(state).ok().unwrap();
        Arc::new(AppState { config, ..state })
    }

    fn flexa_request(method: &str, path: &str, headers: &[(&str, &str)]) -> InnerRequest {
        InnerRequest {
            method: method.to_string(),
            path: path.to_string(),
            authority: FLEXA_TEST_ALIAS.to_string(),
            headers: headers
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
            body: vec![],
        }
    }

    async fn collect_body(state: &Arc<AppState>, request: &InnerRequest) -> (u16, String) {
        let (status, _headers, mut stream) =
            forward_to_backend_stream(state, request, uuid::Uuid::new_v4(), None)
                .await
                .unwrap();
        let mut body = Vec::new();
        while let Some(Ok(frame)) = stream.next().await {
            if let UpFrame::Data(data) = frame {
                body.extend_from_slice(&data);
            }
        }
        (status, String::from_utf8(body).unwrap())
    }

    #[tokio::test]
    async fn test_flexa_placeholder_replaced_upstream() {
        let url = make_echo_server().await;
        let state = flexa_state(&url, Some("publishable_live_real"), 5);
        let placeholder =
            crate::flexa::basic_authorization(crate::flexa::PLACEHOLDER_PUBLISHABLE_KEY);
        for (method, path) in [
            ("POST", "/tokens"),
            ("PATCH", "/tokens/tok_1"),
            ("POST", "/accounts"),
        ] {
            let (status, seen) = collect_body(
                &state,
                &flexa_request(method, path, &[("Authorization", &placeholder)]),
            )
            .await;
            assert_eq!(status, 200);
            let expected = format!(
                "authorization: {}",
                crate::flexa::basic_authorization("publishable_live_real")
            );
            assert!(seen.lines().any(|l| l == expected), "{seen}");
            assert!(!seen.contains(crate::flexa::PLACEHOLDER_PUBLISHABLE_KEY));
            assert!(!seen.contains(&placeholder["Basic ".len()..]));
        }

        // No key configured: the placeholder is dropped, never sent upstream.
        let state = flexa_state(&url, None, 5);
        let (_, seen) = collect_body(
            &state,
            &flexa_request("POST", "/tokens", &[("Authorization", &placeholder)]),
        )
        .await;
        assert!(!seen.contains("authorization:"), "{seen}");
    }

    #[tokio::test]
    async fn test_flexa_user_token_and_headers_pass_through() {
        let url = make_echo_server().await;
        let state = flexa_state(&url, Some("publishable_live_real"), 5);
        let token = crate::flexa::basic_authorization("eyJhbGciOiJFUzI1NiJ9.user.sig");
        let (status, seen) = collect_body(
            &state,
            &flexa_request(
                "GET",
                "/events?type=commerce_session.created,commerce_session.closed",
                &[
                    ("Authorization", &token),
                    ("Accept", "text/event-stream"),
                    ("Last-Event-ID", "evt_42"),
                    ("Flexa-Version", "2025-11-04"),
                    ("Cookie", "session=1"),
                    ("User-Agent", "iOS/18.1 Flexa/1.1.4"),
                ],
            ),
        )
        .await;
        assert_eq!(status, 200);
        let lines: Vec<&str> = seen.lines().collect();
        assert!(
            lines.contains(&format!("authorization: {token}").as_str()),
            "{seen}"
        );
        assert!(lines.contains(&"accept: text/event-stream"), "{seen}");
        assert!(lines.contains(&"last-event-id: evt_42"), "{seen}");
        assert!(lines.contains(&"flexa-version: 2025-11-04"), "{seen}");
        assert!(lines.contains(&"user-agent: ohttp-gateway/1.0"), "{seen}");
        assert!(!seen.contains("cookie"), "{seen}");
        assert!(!seen.contains("publishable_live_real"));
    }

    #[tokio::test]
    async fn test_flexa_policy_denies_other_operations() {
        let url = make_echo_server().await;
        let state = flexa_state(&url, Some("publishable_live_real"), 5);
        for (method, path) in [
            ("GET", "/accounts/other"),
            ("DELETE", "/accounts/me"),
            ("GET", "/tokens"),
            ("POST", "/events"),
            ("GET", "/eventsx"),
            ("PATCH", "/accounts/me"),
            ("GET", "/"),
        ] {
            let (status, body) = collect_body(&state, &flexa_request(method, path, &[])).await;
            assert_eq!(
                (status, body.as_str()),
                (403, "policy denied"),
                "{method} {path}"
            );
        }
        for (method, path) in [
            ("GET", "/accounts/me"),
            ("GET", "/events?type=commerce_session.created"),
            ("POST", "/commerce_sessions/cs_1/approve"),
            ("PATCH", "/transactions/cs_1"),
            ("DELETE", "/app_notifications/n_1"),
            ("GET", "/brands?limit=100&query=-legacy_flexcodes:null"),
        ] {
            let (status, _) = collect_body(&state, &flexa_request(method, path, &[])).await;
            assert_eq!(status, 200, "{method} {path}");
        }
    }

    /// A backend that records the path and query of every request it gets and answers `ok`.
    async fn make_recording_server() -> (String, Arc<parking_lot::Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let recorded = seen.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let recorded = recorded.clone();
                let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let recorded = recorded.clone();
                    async move {
                        recorded.lock().push(
                            req.uri()
                                .path_and_query()
                                .map(|pq| pq.as_str().to_string())
                                .unwrap_or_default(),
                        );
                        Ok::<_, Infallible>(Response::new(http_body_util::Full::new(
                            Bytes::from_static(b"ok"),
                        )))
                    }
                });
                tokio::spawn(async move {
                    let _ = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
                });
            }
        });
        (format!("http://127.0.0.1:{}", addr.port()), seen)
    }

    #[tokio::test]
    async fn test_query_rules_refuse_before_the_upstream() {
        let (url, seen) = make_recording_server().await;
        let state = make_test_state(&url, 1024 * 1024);
        let mut config = state.config.clone();
        config.backends_policy = [(
            "test.example.com".to_string(),
            vec![
                ("GET".to_string(), "/v1/quotes".to_string()),
                ("GET".to_string(), "/v1/other".to_string()),
            ],
        )]
        .into();
        config.backends_policy_default_allow = false;
        config.third_party_query_rules = crate::query_rules::QueryRules::parse(
            "test.example.com=GET /v1/quotes?symbol=ZEC&convert={upper:3-5}",
        )
        .unwrap();
        config
            .third_party_query_rules
            .validate(&config.backends, &config.backends_policy)
            .unwrap();
        let state = Arc::try_unwrap(state).ok().unwrap();
        let state = Arc::new(AppState { config, ..state });
        let request = |path: &str| InnerRequest {
            method: "GET".to_string(),
            path: path.to_string(),
            authority: "test.example.com".to_string(),
            headers: vec![],
            body: vec![],
        };

        for path in [
            "/v1/quotes",
            "/v1/quotes?symbol=ZEC",
            "/v1/quotes?symbol=ZEC&convert=usd",
            "/v1/quotes?symbol=ZEC&convert=USD&limit=5000",
            "/v1/quotes?symbol=ZEC&convert=USD&convert=EUR",
            "/v1/quotes?symbol=BTC&convert=USD",
            "/v1/quotes?convert=USD&symbol=ZEC",
        ] {
            assert!(policy_denies(&state.config, &request(path)), "{path}");
            // Streamed path.
            let (status, body) = collect_body(&state, &request(path)).await;
            assert_eq!((status, body.as_str()), (403, "policy denied"), "{path}");
            // Collected path (the one the third-party cache and upstream cap call).
            let resp = forward_to_backend(&state, &request(path)).await.unwrap();
            assert_eq!(
                (resp.status, resp.body.as_slice()),
                (403, &b"policy denied"[..]),
                "{path}"
            );
        }
        assert!(seen.lock().is_empty(), "{:?}", seen.lock());

        // Allowed shapes, and a route without a query rule, reach the upstream unchanged.
        let allowed = [
            "/v1/quotes?symbol=ZEC&convert=USD",
            "/v1/quotes?symbol=ZEC&convert=EURO",
            "/v1/other?anything=1",
        ];
        for path in allowed {
            assert!(!policy_denies(&state.config, &request(path)), "{path}");
            let (status, body) = collect_body(&state, &request(path)).await;
            assert_eq!((status, body.as_str()), (200, "ok"), "{path}");
            let resp = forward_to_backend(&state, &request(path)).await.unwrap();
            assert_eq!(resp.status, 200, "{path}");
        }
        let expected: Vec<String> = allowed
            .iter()
            .flat_map(|p| [p.to_string(), p.to_string()])
            .collect();
        assert_eq!(*seen.lock(), expected);
    }

    /// THIRD_PARTY_QUERY_VALUE_SOURCES end to end against one mock upstream that serves the
    /// list and the quotes route: the list is fetched through the forwarder (with the alias's
    /// credential), a value in it passes, one not in it is refused before anything goes
    /// upstream (so before the third-party cache and cap, see `policy_denies`), a changed list
    /// is picked up by the next refresh, and a failed refresh keeps the last accepted list.
    #[tokio::test]
    async fn test_query_value_source_lists_admit_values_from_the_upstream() {
        crate::health::init_metrics();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        // The list document (status, body), and every request: path and query, API key.
        let list = Arc::new(parking_lot::Mutex::new((
            200u16,
            r#"{"data":[{"symbol":"USD"},{"symbol":"EUR"}]}"#.to_string(),
        )));
        let seen = Arc::new(parking_lot::Mutex::new(Vec::<String>::new()));
        let (served, recorded) = (list.clone(), seen.clone());
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let (served, recorded) = (served.clone(), recorded.clone());
                let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let path = req
                        .uri()
                        .path_and_query()
                        .map(|pq| pq.as_str().to_string())
                        .unwrap_or_default();
                    let key = req
                        .headers()
                        .get("x-api-key")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("-")
                        .to_string();
                    recorded.lock().push(format!("{path} {key}"));
                    let (status, body) = if path == "/v1/fiat/map" {
                        served.lock().clone()
                    } else {
                        (200, "ok".to_string())
                    };
                    async move {
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(status)
                                .body(http_body_util::Full::new(Bytes::from(body)))
                                .unwrap(),
                        )
                    }
                });
                tokio::spawn(async move {
                    let _ = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
                });
            }
        });

        let state = make_test_state(&url, 4 * 1024 * 1024);
        let mut config = state.config.clone();
        config.backend_headers = [(
            "test.example.com".to_string(),
            vec![("X-API-KEY".to_string(), "k1".to_string())],
        )]
        .into();
        config.backends_policy = [(
            "test.example.com".to_string(),
            vec![
                ("GET".to_string(), "/v1/quotes".to_string()),
                ("GET".to_string(), "/v1/fiat/map".to_string()),
            ],
        )]
        .into();
        config.backends_policy_default_allow = false;
        let sources = crate::query_value_sources::QueryValueSources::parse(
            "fiat=test.example.com GET /v1/fiat/map#/data/*/symbol@300",
        )
        .unwrap();
        config.third_party_query_rules = crate::query_rules::QueryRules::parse_with_sources(
            "test.example.com=GET /v1/quotes?symbol=ZEC&convert={from:fiat}",
            sources.clone(),
        )
        .unwrap();
        config
            .third_party_query_rules
            .validate(&config.backends, &config.backends_policy)
            .unwrap();
        let state = Arc::try_unwrap(state).ok().unwrap();
        let state = Arc::new(AppState { config, ..state });
        let quotes = |convert: &str| InnerRequest {
            method: "GET".to_string(),
            path: format!("/v1/quotes?symbol=ZEC&convert={convert}"),
            authority: "test.example.com".to_string(),
            headers: vec![],
            body: vec![],
        };
        let status = |convert: &str| {
            let state = state.clone();
            let request = quotes(convert);
            async move { collect_body(&state, &request).await }
        };

        // No fallback, no fetch yet: nothing is admitted (fail closed), nothing goes upstream.
        assert!(policy_denies(&state.config, &quotes("USD")));
        assert_eq!(status("USD").await, (403, "policy denied".to_string()));
        assert!(seen.lock().is_empty());

        // The first refresh: the list is a GET of the alias with its credential.
        use crate::query_value_sources::Outcome;
        assert_eq!(sources.refresh(&state, "fiat").await, Outcome::Ok);
        assert_eq!(*seen.lock(), vec!["/v1/fiat/map k1".to_string()]);
        assert_eq!(status("USD").await, (200, "ok".to_string()));
        assert_eq!(status("EUR").await, (200, "ok".to_string()));
        for refused in ["JPY", "usd", "USD%20", "US"] {
            assert!(policy_denies(&state.config, &quotes(refused)), "{refused}");
            assert_eq!(
                status(refused).await,
                (403, "policy denied".to_string()),
                "{refused}"
            );
        }
        assert_eq!(seen.lock().len(), 3, "{:?}", seen.lock());

        // The verdict is taken once per request (the handler does it before its precheck):
        // a list replaced before the forward does not change it either way.
        let decided = |convert: &str| {
            RouteContext::resolve(&state.config, &quotes(convert))
                .with_query_verdict(&state.config, &quotes(convert))
        };
        let (usd_admitted, jpy_refused) = (decided("USD"), decided("JPY"));

        // A changed list is picked up by the next refresh.
        list.lock().1 = r#"{"data":[{"symbol":"JPY"},{"symbol":"EUR"}]}"#.to_string();
        assert_eq!(sources.refresh(&state, "fiat").await, Outcome::Ok);
        assert!(!policy_denies_in(
            &state.config,
            &quotes("USD"),
            &usd_admitted
        ));
        assert!(policy_denies_in(
            &state.config,
            &quotes("JPY"),
            &jpy_refused
        ));
        let before = seen.lock().len();
        for (convert, route, expected) in [
            ("USD", &usd_admitted, (200, "ok")),
            ("JPY", &jpy_refused, (403, "policy denied")),
        ] {
            let (status, _, mut stream) = forward_to_backend_stream_in(
                &state,
                &quotes(convert),
                uuid::Uuid::new_v4(),
                None,
                route,
            )
            .await
            .unwrap();
            let mut body = Vec::new();
            while let Some(Ok(frame)) = stream.next().await {
                if let UpFrame::Data(data) = frame {
                    body.extend_from_slice(&data);
                }
            }
            assert_eq!(
                (status, String::from_utf8(body).unwrap().as_str()),
                expected,
                "{convert}"
            );
            let resp = forward_to_backend_in(&state, &quotes(convert), route)
                .await
                .unwrap();
            assert_eq!(resp.status, expected.0, "{convert}");
        }
        // Only the decided USD went upstream (twice: streamed and collected).
        assert_eq!(seen.lock().len(), before + 2);
        assert_eq!(status("JPY").await, (200, "ok".to_string()));
        assert_eq!(status("USD").await, (403, "policy denied".to_string()));

        // Failed refreshes keep it: an error status, a document without the pointer.
        *list.lock() = (500, "{}".to_string());
        assert_eq!(sources.refresh(&state, "fiat").await, Outcome::Status);
        *list.lock() = (200, r#"{"status":"ok"}"#.to_string());
        assert_eq!(sources.refresh(&state, "fiat").await, Outcome::Pointer);
        *list.lock() = (
            200,
            "x".repeat(crate::query_value_sources::MAX_BODY_BYTES + 1),
        );
        assert_eq!(sources.refresh(&state, "fiat").await, Outcome::Oversize);
        assert_eq!(status("JPY").await, (200, "ok".to_string()));
        assert_eq!(status("USD").await, (403, "policy denied".to_string()));
    }

    #[tokio::test]
    async fn test_event_stream_streamed_and_cut_at_the_upstream_timeout() {
        // 40 events 100 ms apart (4 s) against a 1 s upstream timeout.
        let body = b"id: evt\nevent: commerce_session.created\ndata: {}\n\n".repeat(40);
        let chunk = body.len() / 40;
        let url = make_test_server(
            body.clone(),
            chunk,
            100,
            vec![("content-type".to_string(), "text/event-stream".to_string())],
        )
        .await;
        let state = flexa_state(&url, None, 1);
        let started = Instant::now();
        let (status, headers, mut stream) = forward_to_backend_stream(
            &state,
            &flexa_request("GET", "/events", &[("Accept", "text/event-stream")]),
            uuid::Uuid::new_v4(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(status, 200);
        assert!(headers
            .iter()
            .any(|(k, v)| k == "content-type" && v == "text/event-stream"));

        let mut first_event_at = None;
        let mut received = 0;
        let mut cut = false;
        while let Some(frame) = stream.next().await {
            match frame {
                Ok(UpFrame::Data(data)) => {
                    first_event_at.get_or_insert_with(|| started.elapsed());
                    received += data.len();
                }
                Ok(UpFrame::Trailers(_)) => {}
                Err(_) => {
                    cut = true;
                    break;
                }
            }
        }
        let elapsed = started.elapsed();
        assert!(cut, "the stream ends without a clean end");
        assert!(first_event_at.unwrap() < Duration::from_millis(600));
        assert!(received > 0 && received < body.len());
        assert!(
            elapsed >= Duration::from_millis(900) && elapsed < Duration::from_secs(3),
            "{elapsed:?}"
        );
    }

    #[tokio::test]
    async fn test_event_stream_cut_even_when_frames_are_buffered() {
        // The whole stream arrives at once; the reader is slower than the cap.
        let body = b"data: {}\n\n".repeat(2000);
        let url = make_test_server(
            body.clone(),
            1000,
            0,
            vec![("content-type".to_string(), "text/event-stream".to_string())],
        )
        .await;
        let state = flexa_state(&url, None, 1);
        let (_, _, mut stream) = forward_to_backend_stream(
            &state,
            &flexa_request("GET", "/events", &[]),
            uuid::Uuid::new_v4(),
            None,
        )
        .await
        .unwrap();
        let mut received = match stream.next().await {
            Some(Ok(UpFrame::Data(data))) => data.len(),
            other => panic!("{:?}", other.map(|r| r.is_ok())),
        };
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let mut cut = false;
        while let Some(frame) = stream.next().await {
            match frame {
                Ok(UpFrame::Data(data)) => received += data.len(),
                Ok(UpFrame::Trailers(_)) => {}
                Err(_) => {
                    cut = true;
                    break;
                }
            }
        }
        assert!(cut);
        assert!(received < body.len(), "{received}");
    }

    #[tokio::test]
    async fn test_stream_oversize_error() {
        // Test that oversized responses are rejected mid-stream
        let body = b"X".repeat(10000); // 10KB body
        let server_url = make_test_server(body.clone(), 1000, 0, vec![]).await;

        let state = make_test_state(&server_url, 5000); // 5KB limit
        let inner_request = InnerRequest {
            method: "GET".to_string(),
            path: "/test".to_string(),
            authority: "test.example.com".to_string(),
            headers: vec![],
            body: vec![],
        };

        let request_id = uuid::Uuid::new_v4();
        let (_status, _headers, mut stream) =
            forward_to_backend_stream(&state, &inner_request, request_id, None)
                .await
                .unwrap();

        let mut bytes_received = 0;
        let mut got_error = false;
        while let Some(result) = stream.next().await {
            match result {
                Ok(UpFrame::Data(data)) => {
                    bytes_received += data.len();
                }
                Err(_) => {
                    got_error = true;
                    break;
                }
                _ => {}
            }
        }

        assert!(
            got_error,
            "Should have received an error for oversized response"
        );
        assert!(
            bytes_received <= 5000,
            "Should not have received more than the limit"
        );
    }

    /// A keep-alive HTTP/1.1 server that counts accepted connections. `/open` answers with one
    /// chunk and then never ends its body; every other path answers `ok`.
    async fn counting_server() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
                let service = service_fn(|req: Request<hyper::body::Incoming>| async move {
                    use futures_util::stream;
                    let first = stream::once(async {
                        Ok::<_, Infallible>(hyper::body::Frame::data(Bytes::from_static(b"ok")))
                    });
                    let body: futures_util::stream::BoxStream<'static, _> =
                        if req.uri().path() == "/open" {
                            Box::pin(first.chain(stream::pending()))
                        } else {
                            Box::pin(first)
                        };
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(200)
                            .body(http_body_util::StreamBody::new(body))
                            .unwrap(),
                    )
                });
                tokio::spawn(async move {
                    let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        (format!("http://{}", addr), accepted)
    }

    fn get(url: &str) -> Request<Full<Bytes>> {
        Request::builder()
            .uri(url)
            .body(Full::new(Bytes::new()))
            .unwrap()
    }

    #[tokio::test]
    async fn backend_pool_reuses_connection_for_sequential_requests() {
        let (base, accepted) = counting_server().await;
        let client: Client<HttpConnector, Full<Bytes>> =
            backend_pool_builder().build(HttpConnector::new());
        for _ in 0..3 {
            let resp = client.request(get(&format!("{base}/a"))).await.unwrap();
            assert_eq!(resp.status(), 200);
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(&body[..], b"ok");
            // The connection goes back to the pool in a background task once its body ended;
            // let it run, else the next request races a new connect against the checkout.
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn backend_pool_does_not_reuse_connection_of_unfinished_body() {
        let (base, accepted) = counting_server().await;
        let client: Client<HttpConnector, Full<Bytes>> =
            backend_pool_builder().build(HttpConnector::new());
        // A stream read in part and then dropped, like an event stream cut at its timeout.
        let resp = client.request(get(&format!("{base}/open"))).await.unwrap();
        let mut body = resp.into_body();
        let frame = body.frame().await.unwrap().unwrap();
        assert_eq!(&frame.into_data().unwrap()[..], b"ok");
        drop(body);
        // The next request must get a complete answer on a new connection.
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            client.request(get(&format!("{base}/a"))),
        )
        .await
        .unwrap()
        .unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"ok");
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn https_backend_client_is_shared() {
        assert!(std::ptr::eq(https_backend_client(), https_backend_client()));
    }
}

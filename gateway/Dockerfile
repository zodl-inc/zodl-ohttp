# Multi-stage build for OHTTP Gateway (Rust)

# Build stage
FROM rust:1-alpine@sha256:7cc1c22d77d9432f7fe012a70e6d3e555af54c2a6832700ed7d553f1769ae89f AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig

# Build context: the repository root (the integrations crate is a path dependency).
WORKDIR /build

# Cache dependencies (manifests only, stub sources)
COPY integrations/Cargo.toml integrations/Cargo.lock ./integrations/
COPY gateway/Cargo.toml gateway/Cargo.lock ./gateway/
RUN mkdir -p integrations/src gateway/src && \
    echo "pub fn placeholder() {}" > integrations/src/lib.rs && \
    echo "fn main() {}" > gateway/src/main.rs && \
    echo "pub fn placeholder() {}" > gateway/src/lib.rs && \
    cd gateway && cargo build --release --locked && \
    cd .. && rm -rf integrations/src gateway/src

# Build application
COPY integrations/src ./integrations/src
COPY gateway/src ./gateway/src
WORKDIR /build/gateway
RUN touch ../integrations/src/lib.rs src/main.rs src/lib.rs && \
    cargo build --release --locked --bin zodl-ohttp-gateway && \
    strip target/release/zodl-ohttp-gateway

# Runtime stage
FROM alpine:3.21@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507

# Install runtime dependencies. The emSign roots are distrusted: eight eMudhra intermediates'
# private keys were disclosed (https://emudhra.we-have-a-problem.com/); drop this
# once Alpine's ca-certificates removes them. Upstreams that chain to eMudhra will fail TLS.
RUN apk add --no-cache ca-certificates tzdata && \
    sed -i -E 's@^(mozilla/emSign[^/]*\.crt)$@!\1@' /etc/ca-certificates.conf && \
    update-ca-certificates 2>/dev/null && \
    ! grep -q '^mozilla/emSign' /etc/ca-certificates.conf && \
    ! ls /etc/ssl/certs | grep -qi emsign && \
    adduser -D -u 1000 gateway

WORKDIR /app

# Copy binary from builder. /app/ohttp-gateway, the binary's former name, stays as a link for
# callers that still name it.
COPY --from=builder /build/gateway/target/release/zodl-ohttp-gateway /app/zodl-ohttp-gateway
RUN ln -s zodl-ohttp-gateway /app/ohttp-gateway

# Set ownership
RUN chown -R gateway:gateway /app

# Switch to non-root user
USER gateway

# Expose HTTP port
EXPOSE 8080

# Health check: /health/startup is on the public port (8080); /health lives on the metrics port.
# Used by Docker itself; orchestrators that run their own probes ignore HEALTHCHECK.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health/startup || exit 1

# Run
# The image reads a configuration file (--config, --check-config): hosts that deliver one check
# for this label before they run --check-config with it.
LABEL org.zodl.ohttp-gateway.check-config=1
# The image reads every setting from the files as well ([settings], --host-config).
LABEL org.zodl.ohttp-gateway.host-config=1

ENTRYPOINT ["/app/zodl-ohttp-gateway"]

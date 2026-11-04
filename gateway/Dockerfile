# Multi-stage build for OHTTP Gateway (Rust)

# Build stage
FROM rust:1-alpine@sha256:7cc1c22d77d9432f7fe012a70e6d3e555af54c2a6832700ed7d553f1769ae89f AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig

WORKDIR /build

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    echo "pub fn placeholder() {}" > src/lib.rs && \
    cargo build --release --locked && \
    rm -rf src

# Build application
COPY src ./src
RUN touch src/main.rs src/lib.rs && \
    cargo build --release --locked --bin ohttp-gateway && \
    strip target/release/ohttp-gateway

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

# Copy binary from builder
COPY --from=builder /build/target/release/ohttp-gateway /app/ohttp-gateway

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
ENTRYPOINT ["/app/ohttp-gateway"]

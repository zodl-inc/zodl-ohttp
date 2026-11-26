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

# CA bundle stage: the emSign roots are distrusted: eight eMudhra intermediates' private keys
# were disclosed (https://emudhra.we-have-a-problem.com/); they are dropped from the bundle the
# runtime image carries. Remove this once the distribution's ca-certificates removes them.
# Upstreams that chain to eMudhra will fail TLS.
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS certs
RUN apk upgrade --no-cache && \
    apk add --no-cache ca-certificates && \
    sed -i -E 's@^(mozilla/emSign[^/]*\.crt)$@!\1@' /etc/ca-certificates.conf && \
    update-ca-certificates 2>/dev/null && \
    ! grep -q '^mozilla/emSign' /etc/ca-certificates.conf && \
    ! ls /etc/ssl/certs | grep -qi emsign && \
    [ "$(grep -c 'BEGIN CERTIFICATE' /etc/ssl/certs/ca-certificates.crt)" -gt 100 ]

# Runtime stage: distroless, no shell and no package manager. The binary is statically linked
# (musl), so the static base is enough; it carries the time zone data and the base files.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5

COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

WORKDIR /app

# Copy binary from builder
COPY --from=builder --chmod=0555 /build/gateway/target/release/zodl-ohttp-gateway /app/zodl-ohttp-gateway

# Non-root user: the numeric id the deployments run as (files they mount are owned by it)
USER 1000:1000

# Expose HTTP port
EXPOSE 8080

# Run
# The image reads a configuration file (--config, --check-config): hosts that deliver one check
# for this label before they run --check-config with it.
LABEL org.zodl.ohttp-gateway.check-config=1
# The image reads every setting from the files as well ([settings], --host-config).
LABEL org.zodl.ohttp-gateway.host-config=1
# The image reads its configuration from the files only (--config, --host-config, secrets as
# files): a deployment that still configures it by environment variables must not run it.
LABEL org.zodl.ohttp-gateway.files-only=1

ENTRYPOINT ["/app/zodl-ohttp-gateway"]

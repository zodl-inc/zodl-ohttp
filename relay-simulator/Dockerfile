FROM rust:1-slim@sha256:f47a8de237dcbb0b0ce1099901e60a89728e3d51f24e664b40e947171538ade7 AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked

FROM debian:bookworm-slim@sha256:e67eeead736ff7bbe258ef088bff683635c561b1fcfefad0806c1df4ab49ce0e
# emSign roots distrusted (eMudhra intermediates' keys disclosed); see gateway/Dockerfile.
RUN apt-get update && apt-get upgrade -y && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/* && \
    sed -i -E 's@^(mozilla/emSign[^/]*\.crt)$@!\1@' /etc/ca-certificates.conf && \
    update-ca-certificates --fresh >/dev/null && \
    ! grep -q '^mozilla/emSign' /etc/ca-certificates.conf && \
    ! ls /etc/ssl/certs | grep -qi emsign

COPY --from=builder /build/target/release/ohttp-relay-simulator /usr/local/bin/

ENV PORT=8081
ENV GATEWAY_URL=http://ohttp-gateway:8080
ENV RUST_LOG=info

EXPOSE 8081
CMD ["ohttp-relay-simulator"]

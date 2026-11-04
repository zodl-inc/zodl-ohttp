# ohttp-e2e image: the e2e client for manual checks, or for a periodic scripted loop that runs one
# real exchange through each relay. Build context: repository root (the client crate is a path
# dependency). Python stays in the runtime image so that such a loop can be scripted.
FROM rust:1-slim@sha256:f47a8de237dcbb0b0ce1099901e60a89728e3d51f24e664b40e947171538ade7 AS builder
WORKDIR /build
COPY client ./client
COPY e2e-client ./e2e-client
# Compile once without endpoint configuration, so that the dependencies are built in a cacheable
# layer.
RUN cd e2e-client && cargo build --release --locked

# Build-time endpoint configuration of the client crate (client/src/relays.rs), as build secrets
# with the variable's name as id (`docker build --secret id=ZODL_OHTTP_...,env=...`): each one is
# exported for this cargo build only and never stored in a layer, a build argument or the image
# history. A network gets all four of its values or none; none = no built-in endpoints for that
# network in this binary (explicit URLs still work). BuildKit does not key the layer cache on
# secret values, so builds that pass them exclude this stage from the cache
# (`--no-cache-filter configured`).
FROM builder AS configured
RUN --mount=type=secret,id=ZODL_OHTTP_GATEWAY_HOST_MAINNET \
    --mount=type=secret,id=ZODL_OHTTP_GATEWAY_HOST_TESTNET \
    --mount=type=secret,id=ZODL_OHTTP_RELAY_URL_MAINNET \
    --mount=type=secret,id=ZODL_OHTTP_RELAY_URL_TESTNET \
    --mount=type=secret,id=ZODL_OHTTP_KEYS_DNS_NAME_MAINNET \
    --mount=type=secret,id=ZODL_OHTTP_KEYS_DNS_NAME_TESTNET \
    --mount=type=secret,id=ZODL_OHTTP_SIGNING_PUBKEY_MAINNET \
    --mount=type=secret,id=ZODL_OHTTP_SIGNING_PUBKEY_TESTNET \
    set -eu; \
    for var in ZODL_OHTTP_GATEWAY_HOST_MAINNET ZODL_OHTTP_GATEWAY_HOST_TESTNET \
               ZODL_OHTTP_RELAY_URL_MAINNET ZODL_OHTTP_RELAY_URL_TESTNET \
               ZODL_OHTTP_KEYS_DNS_NAME_MAINNET ZODL_OHTTP_KEYS_DNS_NAME_TESTNET \
               ZODL_OHTTP_SIGNING_PUBKEY_MAINNET ZODL_OHTTP_SIGNING_PUBKEY_TESTNET; do \
        if [ -s "/run/secrets/$var" ]; then export "$var=$(cat "/run/secrets/$var")"; fi; \
    done; \
    cd e2e-client && cargo build --release --locked

FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
COPY --from=configured /build/e2e-client/target/release/ohttp-e2e /usr/local/bin/ohttp-e2e
USER 65534:65534
ENTRYPOINT ["ohttp-e2e"]

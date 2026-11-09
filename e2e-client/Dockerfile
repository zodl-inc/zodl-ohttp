# ohttp-e2e image: the e2e client for manual checks, or for a periodic scripted loop that runs one
# real exchange through each relay. Build context: repository root (the client crate is a path
# dependency). Python stays in the runtime image so that such a loop can be scripted.
FROM rust:1-slim@sha256:f47a8de237dcbb0b0ce1099901e60a89728e3d51f24e664b40e947171538ade7 AS builder
WORKDIR /build
COPY client ./client
COPY e2e-client ./e2e-client
# The image carries no OHTTP configuration: the e2e client reads it at runtime from its
# environment (OHTTP_E2E_*_MAINNET / _TESTNET, see e2e-client/README.md).
RUN cd e2e-client && cargo build --release --locked

FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
COPY --from=builder /build/e2e-client/target/release/ohttp-e2e /usr/local/bin/ohttp-e2e
USER 65534:65534
ENTRYPOINT ["ohttp-e2e"]

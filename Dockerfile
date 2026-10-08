# syntax=docker/dockerfile:1
# Multi-stage build: static-ish release binaries in a minimal runtime image, non-root, no shell.
# bookworm on both sides: the binaries need the glibc of the runtime image (the untagged slim moved to a newer Debian)
FROM rust:1.97-slim-bookworm AS build
WORKDIR /src
# No system packages: TLS is rustls with built-in roots, there is no OpenSSL or pkg-config to install.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p aegis-gateway -p aegis-cli

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/aegis-gateway /usr/local/bin/aegis-gateway
COPY --from=build /src/target/release/aegis /usr/local/bin/aegis
# Config and keys are mounted at run time (see docs/ADMIN.md); nothing secret is baked in.
USER nonroot
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/aegis-gateway"]
CMD ["/etc/aegis/gateway.json"]

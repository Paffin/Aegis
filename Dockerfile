# syntax=docker/dockerfile:1
# Multi-stage build: static-ish release binaries in a minimal runtime image, non-root, no shell.
FROM rust:1.97-slim AS build
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config ca-certificates && rm -rf /var/lib/apt/lists/*
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

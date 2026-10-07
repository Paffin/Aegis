#!/usr/bin/env bash
# REQ: SEC-09, NFR-10 — supply chain: licenses, bans, advisories, sources (deny.toml), versions
# pinned by Cargo.lock. In CI the same check runs in the `supply-chain` job, which also builds the
# SBOM; `.github/workflows/release.yml` signs the image and publishes binaries with checksums.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v cargo-deny >/dev/null || { echo "cargo install cargo-deny --locked"; exit 1; }
cargo deny check
git diff --quiet -- Cargo.lock || { echo "Cargo.lock is not committed"; exit 1; }
cargo metadata --locked --format-version 1 >/dev/null
echo "SUPPLY CHAIN OK"

#!/usr/bin/env bash
# REQ: CFG-07 — build kryoptic, a PKCS#11 software token written in Rust, for the HSM tests
# (crates/aegis-hsm/tests). It is a real token: PIN, persistent objects, C_InitToken, non-extractable keys.
#
# Usage: scripts/build-kryoptic.sh [dir]     prints the path of libkryoptic_pkcs11.so on the last line
#        AEGIS_TEST_KRYOPTIC=$(scripts/build-kryoptic.sh | tail -1) cargo test -p aegis-hsm
#
# kryoptic needs OpenSSL 3.2 or later; Ubuntu LTS has 3.0, so OpenSSL 3.5 is built from source and
# linked statically (about 3 minutes on 4 cores). Only the library is kept in `dir`, and a build is
# skipped when it is there, which is what the CI cache relies on.
# Needs: curl, tar, perl, make, a C compiler, clang (bindgen) and cargo. The sources are checked
# against fixed SHA-256 sums; nothing is installed on the system.
set -euo pipefail

KRYOPTIC=1.5.3
KRYOPTIC_SHA256=df1306deb2b611e4295a5c4399dfb7761c398418337014cbc6cce8bdbbe29e0e
OPENSSL=3.5.0
OPENSSL_SHA256=344d0a79f1a9b08029b0744e2cc401a43f9c90acd1044d09a530b4885a8e9fc0

OUT="${1:-${TMPDIR:-/tmp}/aegis-kryoptic}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
LIB="$OUT/libkryoptic_pkcs11.so"

if [ ! -f "$LIB" ]; then
  cd "$OUT"
  [ -f "kryoptic-$KRYOPTIC.crate" ] || curl -fsSL -o "kryoptic-$KRYOPTIC.crate" "https://static.crates.io/crates/kryoptic/kryoptic-$KRYOPTIC.crate"
  echo "$KRYOPTIC_SHA256  kryoptic-$KRYOPTIC.crate" | sha256sum -c - >&2
  [ -f "openssl-$OPENSSL.tar.gz" ] || curl -fsSL -o "openssl-$OPENSSL.tar.gz" "https://www.openssl.org/source/openssl-$OPENSSL.tar.gz"
  echo "$OPENSSL_SHA256  openssl-$OPENSSL.tar.gz" | sha256sum -c - >&2
  rm -rf "kryoptic-$KRYOPTIC" "openssl-$OPENSSL"
  tar xzf "kryoptic-$KRYOPTIC.crate"
  tar xzf "openssl-$OPENSSL.tar.gz"
  # A static OpenSSL is selected through the default features of the `ossl` crate, which the
  # published manifest of the token switches off (it is built that way for the dynamic case).
  awk '/^\[dependencies\.ossl\]/ {s=1; print; next} /^\[/ {s=0} !(s && /^default-features = false/) {print}' \
    "kryoptic-$KRYOPTIC/Cargo.toml" > "kryoptic-$KRYOPTIC/Cargo.toml.new"
  mv "kryoptic-$KRYOPTIC/Cargo.toml.new" "kryoptic-$KRYOPTIC/Cargo.toml"
  (
    cd "kryoptic-$KRYOPTIC"
    KRYOPTIC_OPENSSL_SOURCES="$OUT/openssl-$OPENSSL" CONFDIR=/etc CARGO_TARGET_DIR="$OUT/target" \
      cargo build --release --no-default-features --features standard >&2
  )
  # keep the library only: the sources and the build tree are several hundred megabytes
  cp "$OUT/target/release/libkryoptic_pkcs11.so" "$LIB"
  rm -rf "$OUT/target" "$OUT/kryoptic-$KRYOPTIC" "$OUT/openssl-$OPENSSL" "$OUT"/*.crate "$OUT"/*.tar.gz
fi
test -f "$LIB" || { echo "kryoptic was not built" >&2; exit 1; }
echo "$LIB"

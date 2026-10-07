#!/usr/bin/env bash
# REQ: CMP-01, CMP-02, CMP-03, CMP-05, EGR-01, EGR-02, NFR-05, NFR-08, QA-09
# Deliverables that are documents or configuration files, not code: they must exist and say what
# the requirements demand. A missing sentence is a failing check, like a missing test.
set -euo pipefail
cd "$(dirname "$0")/.."
fail() { echo "FAIL $1"; exit 1; }
has() { grep -qiE -- "$2" "$1" || fail "$1 does not mention: $2 ($3)"; echo "ok   $3"; }

# CMP-01: the product speaks of pseudonymization; "de-identified" claims are forbidden
if grep -rniE "данные обезличен|можно передавать (ПДн|персональные данные) за рубеж" README.md README.en.md docs --include=*.md \
   | grep -viE "нельзя|запрещ|[Нн]е делает|[Нн]е делают|[Нн]е снимает|вместо|формулировки|утверждения" ; then
  fail "CMP-01: a forbidden claim in the documents"
fi
has docs/COMPLIANCE.md "Это не обезличивание" "CMP-01: COMPLIANCE says pseudonymization is not anonymization"

# CMP-02: processing description for security and legal: what, where, how long
for w in "Какие данные, где и сколько хранятся" "Только в памяти" "Что в аудите" "Что видит провайдер"; do
  has docs/COMPLIANCE.md "$w" "CMP-02: COMPLIANCE has «$w»"
done

# CMP-03: audit retention is configurable and the hash caveat is written down
has docs/COMPLIANCE.md "logrotate" "CMP-03: retention by rotation, with an example"
has docs/COMPLIANCE.md "могут считаться персональными данными" "CMP-03: hashes with a key may be personal data"

# CMP-05: provider-side settings
has docs/COMPLIANCE.md "zero data retention" "CMP-05: zero data retention"
has docs/COMPLIANCE.md "обучени" "CMP-05: no training on customer data"

# EGR-01: domain list and reference configs for proxy, DNS, firewall
test -s deploy/egress/ai-domains.txt || fail "EGR-01: deploy/egress/ai-domains.txt"
for f in squid.conf rpz.zone.example nftables.example; do test -s "deploy/egress/$f" || fail "EGR-01: deploy/egress/$f"; done
grep -q "api.anthropic.com" deploy/egress/ai-domains.txt && grep -q "api.openai.com" deploy/egress/ai-domains.txt || fail "EGR-01: domain list"
echo "ok   EGR-01: domain list, Squid, RPZ and nftables examples"

# EGR-02: how to switch clients over
has docs/CLIENTS.md "ANTHROPIC_BASE_URL" "EGR-02: Claude Code variables"
has docs/CLIENTS.md "config.toml" "EGR-02: Codex settings file"

# NFR-05: stateless, with the balancer advice; NFR-08: no internet needed
has docs/ADMIN.md "не хранит состояния между запросами" "NFR-05: stateless node"
has docs/ADMIN.md "хеширование по заголовку" "NFR-05: consistent hashing advice"
has docs/ADMIN.md "Без доступа в интернет" "NFR-08: air-gapped operation"

# QA-09: the quality gates run in CI and block a release
for g in "aegis-bench -- recall" "aegis-bench -- fp" "aegis-bench -- perf" "aegis-bench -- load" "cargo test --workspace" "scripts/smoke.sh" "scripts/trace.sh" "cargo deny\|cargo-deny-action"; do
  grep -q -- "$g" .github/workflows/ci.yml || fail "QA-09: CI lacks «$g»"
done
echo "ok   QA-09: tests, detection and load gates, smoke, trace and supply chain run in CI"
echo "DOCS OK"

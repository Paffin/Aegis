#!/usr/bin/env bash
# T0-12: requirement -> tests report. Tests mark themselves with `// REQ: PSE-04, RST-05`
# (ranges like `PSE-05..PSE-09` and `PSE-05…PSE-09` are expanded).
# Usage: scripts/trace.sh [--strict]   (strict: fail if an Э1 requirement has no test)
set -euo pipefail
cd "$(dirname "$0")/.."
python3 - "$@" <<'PY'
import re, sys, glob
strict = "--strict" in sys.argv
spec = open("docs/SPEC.md", encoding="utf-8").read()
# requirement rows: | ID | Этап | ...
reqs = {}
for m in re.finditer(r"^\| ([A-Z]{2,4}-\d+) \| (Э\d) \|", spec, re.M):
    reqs[m.group(1)] = m.group(2)
for m in re.finditer(r"^\| (INV-\d) \|", spec, re.M):
    reqs[m.group(1)] = "Э1"

def expand(a, b):
    pa, na = a.rsplit("-", 1); pb, nb = b.rsplit("-", 1)
    return [f"{pa}-{n:02d}" if len(na) == 2 else f"{pa}-{n}" for n in range(int(na), int(nb) + 1)] if pa == pb else [a, b]

covered = {}
for f in glob.glob("crates/**/*.rs", recursive=True) + glob.glob("crates/**/tests/**/*.rs", recursive=True):
    for i, line in enumerate(open(f, encoding="utf-8"), 1):
        mm = re.search(r"REQ:\s*(.*)", line)
        if not mm:
            continue
        text = mm.group(1)
        for a, b in re.findall(r"([A-Z]{2,4}-\d+)\s*(?:\.\.|…)\s*([A-Z]{2,4}-\d+)", text):
            for r in expand(a, b):
                covered.setdefault(r, set()).add(f"{f}:{i}")
        for r in re.findall(r"[A-Z]{2,4}-\d+", text):
            covered.setdefault(r, set()).add(f"{f}:{i}")

for stage in ("Э0", "Э1"):
    ids = sorted(r for r, s in reqs.items() if s == stage)
    have = [r for r in ids if r in covered]
    miss = [r for r in ids if r not in covered]
    print(f"{stage}: {len(have)}/{len(ids)} requirements have tests")
    if miss and stage == "Э1":
        print("  without tests: " + " ".join(miss))
unknown = sorted(r for r in covered if r not in reqs)
if unknown:
    print("REQ markers that are not in the spec: " + " ".join(unknown))
    sys.exit(1)
if strict and [r for r, s in reqs.items() if s == "Э1" and r not in covered]:
    sys.exit(1)
PY

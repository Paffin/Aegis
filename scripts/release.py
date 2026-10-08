#!/usr/bin/env python3
"""Prepare a release: pick the next version from the commits since the last tag, move the
"Не выпущено" section of CHANGELOG.md under it, and update Cargo.toml and Cargo.lock.

  scripts/release.py              next version from commits (feat -> minor, anything else -> patch,
                                  `!` or BREAKING CHANGE -> major, but minor while the version is 0.x)
  scripts/release.py --version X  choose it by hand
  scripts/release.py --dry-run    print the version and the commits, change nothing

The changelog is written by hand (it says what changed for a user, which commit subjects do not),
so the script refuses to release while "Не выпущено" is empty. It does not commit, tag or push:
the workflows `release-prepare` (opens the pull request) and `release-tag` (tags on merge) do.
"""
import argparse
import datetime
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CARGO = ROOT / "Cargo.toml"
CHANGELOG = ROOT / "CHANGELOG.md"
HEADING = "## [Не выпущено]"


def sh(*cmd):
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, check=False)


def current_version():
    m = re.search(r'(?ms)^\[workspace\.package\].*?^version\s*=\s*"(\d+\.\d+\.\d+)"', CARGO.read_text())
    if not m:
        sys.exit("Cargo.toml: no [workspace.package] version")
    return m.group(1)


def commits_since_tag():
    tag = sh("git", "describe", "--tags", "--abbrev=0", "--match", "v*").stdout.strip()
    rng = f"{tag}..HEAD" if tag else "HEAD"
    out = sh("git", "log", "--format=%s%x1f%b%x1e", rng).stdout
    items = []
    for rec in out.split("\x1e"):
        if rec.strip():
            subject, _, body = rec.partition("\x1f")
            items.append((subject.strip(), body))
    return tag, items


def bump(version, commits):
    major, minor, patch = map(int, version.split("."))
    breaking = any(re.match(r"^\w+(\([^)]*\))?!:", s) or "BREAKING CHANGE" in b for s, b in commits)
    feature = any(re.match(r"^feat(\([^)]*\))?:", s) for s, _ in commits)
    if breaking and major > 0:
        return f"{major + 1}.0.0"
    if breaking or feature:
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    tag, commits = commits_since_tag()
    cur = current_version()
    base = tag[1:] if tag else cur
    new = a.version or bump(base, commits)
    if not re.fullmatch(r"\d+\.\d+\.\d+", new):
        sys.exit(f"not a version: {new}")
    print(f"last tag: {tag or '-'}; Cargo.toml: {cur}; next: {new}; commits: {len(commits)}")
    for s, _ in commits[:40]:
        print("  ", s)
    if a.dry_run:
        return

    text = CHANGELOG.read_text()
    if HEADING not in text:
        sys.exit(f"CHANGELOG.md has no «{HEADING}»")
    head, rest = text.split(HEADING, 1)
    body = re.split(r"(?m)^## \[", rest, maxsplit=1)
    unreleased = body[0].strip()
    if not unreleased:
        sys.exit("«Не выпущено» is empty: describe the changes first")
    if f"## [{new}]" in text:
        sys.exit(f"CHANGELOG.md already has {new}")
    tail = ("## [" + body[1]) if len(body) > 1 else ""
    today = datetime.date.today().isoformat()
    CHANGELOG.write_text(f"{head}{HEADING}\n\n## [{new}] — {today}\n\n{unreleased}\n\n{tail}")

    CARGO.write_text(re.sub(r'(?ms)(^\[workspace\.package\].*?^version\s*=\s*")[^"]+(")', rf"\g<1>{new}\g<2>", CARGO.read_text(), count=1))
    r = sh("cargo", "update", "--workspace", "--offline")
    if r.returncode != 0:
        sys.exit("cargo update failed:\n" + r.stderr)
    print(f"released {new}: Cargo.toml, Cargo.lock, CHANGELOG.md updated")


if __name__ == "__main__":
    main()

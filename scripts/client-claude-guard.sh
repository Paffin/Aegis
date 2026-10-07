#!/usr/bin/env bash
# REQ: AGG-01, AGG-02, QA-14
# Real Claude Code with aegis-guard as its PreToolUse hook: a call to read a private key is stopped
# before the tool runs (the file never reaches the model), a call to read an ordinary file goes on.
# No gateway here: the mock provider is the model. Skips when `claude` is not installed.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v claude >/dev/null || { echo "skip: claude is not installed"; exit 0; }
cargo build -q --release -p aegis-guard
W=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"' EXIT
UP=$((20000 + RANDOM % 20000))
mkdir -p "$W/home/.ssh" "$W/home/.claude" "$W/work"; : > "$W/provider.log"
printf 'PRIVATE-KEY-CONTENT-DO-NOT-SHOW\n' > "$W/home/.ssh/id_x"
printf 'ORDINARY-FILE-CONTENT\n' > "$W/work/ok.txt"
TOOLMODE=1 MOCK_DIR="$W" python3 scripts/mock_anthropic.py "$UP" "$W/provider.log" &
cat > "$W/guard.yaml" <<YAML
version: 1
paths: { action: deny }
YAML
GUARD="$PWD/target/release/aegis-guard"
cat > "$W/home/.claude/settings.json" <<JSON
{"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "$GUARD hook --config $W/guard.yaml"}]}]}}
JSON
sleep 0.5
cd "$W/work"
HOME="$W/home" CLAUDE_CONFIG_DIR="$W/home/.claude" NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost \
  ANTHROPIC_BASE_URL="http://127.0.0.1:$UP" ANTHROPIC_API_KEY=test-key DISABLE_AUTOUPDATER=1 \
  timeout 120 claude -p "GUARD: прочитай оба файла." --allowedTools Read --output-format json < /dev/null > "$W/claude.json" || true

python3 - "$W" <<'PY'
import json, sys
w = sys.argv[1]
rows = [json.loads(l) for l in open(f"{w}/provider.log")]
bodies = " ".join(r["body"] for r in rows if r["method"] == "POST")
def check(name, ok):
    print(("ok   " if ok else "FAIL ") + name)
    if not ok:
        print(open(f"{w}/claude.json").read()[-800:])
        print(bodies[-1500:])
        sys.exit(1)
check("the model got the answer for both calls", "toolu_01S" in bodies and "toolu_01T" in bodies)
check("the private key never reached the model", "PRIVATE-KEY-CONTENT" not in bodies)
check("the refusal names the rule", "Aegis Guard" in bodies and "G-01" in bodies)
check("the ordinary file was read", "ORDINARY-FILE-CONTENT" in bodies)
PY
echo "CLIENT OK"

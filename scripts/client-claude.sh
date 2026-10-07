#!/usr/bin/env bash
# Real-client check: the Claude Code CLI (headless) talks to Aegis, Aegis talks to a mock provider.
# Verifies with the real client's own requests: the query string (`?beta=true`) and the beta headers
# reach the provider, values are masked, the provider key replaces the client key, a tool call that
# would carry a secret out never reaches the client, and the next turn (the client's history with
# our rewritten answer and its tool result) is masked again. Skips when `claude` is not installed.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v claude >/dev/null || { echo "skip: claude is not installed"; exit 0; }
cargo build -q --release -p aegis-gateway
W=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"' EXIT
PORT=$((20000 + RANDOM % 20000)); ADMIN=$((PORT + 1)); UP=$((PORT + 2))
mkdir -p "$W/home" "$W/work"; : > "$W/provider.log"
TOOLMODE=1 python3 scripts/mock_anthropic.py "$UP" "$W/provider.log" &
HASH=$(printf %s aegis-vk-claude | sha256sum | cut -d' ' -f1)
cat > "$W/gw.json" <<JSON
{"listen":"127.0.0.1:$PORT","admin_listen":"127.0.0.1:$ADMIN","anthropic_base_url":"http://127.0.0.1:$UP",
 "internal_zones":["corp.local"],"audit_path":"$W/audit.jsonl","virtual_keys":[{"sha256":"$HASH","principal":"u:claude"}]}
JSON
AEGIS_K_TENANT=0123456789abcdef0123456789abcdef AEGIS_K_AUDIT=fedcba9876543210fedcba9876543210 \
  AEGIS_ANTHROPIC_KEY=provider-secret-key target/release/aegis-gateway "$W/gw.json" > "$W/gw.log" 2>&1 &
for _ in $(seq 1 50); do curl -sf "http://127.0.0.1:$ADMIN/readyz" >/dev/null 2>&1 && break; sleep 0.1; done

cd "$W/work"
# --bare: no OAuth, no plugin sync; the client uses exactly ANTHROPIC_API_KEY and ANTHROPIC_BASE_URL
HOME="$W/home" CLAUDE_CONFIG_DIR="$W/home/.claude" NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost \
  ANTHROPIC_BASE_URL="http://127.0.0.1:$PORT" ANTHROPIC_API_KEY=aegis-vk-claude DISABLE_AUTOUPDATER=1 \
  timeout 120 claude --bare -p "Не подключается к prod-db01.corp.local, password=Jd8@2jd82k. Проверь." \
  --allowedTools Bash --output-format json < /dev/null > "$W/claude.json"

python3 - "$W" <<'PY'
import json, sys
w = sys.argv[1]
rows = [json.loads(l) for l in open(f"{w}/provider.log")]
posts = [r for r in rows if r["method"] == "POST"]
def check(name, ok):
    print(("ok   " if ok else "FAIL ") + name)
    if not ok:
        sys.exit(1)
check("the client got an answer", json.load(open(f"{w}/claude.json")).get("stop_reason") == "end_turn")
check("every request kept ?beta=true", all(r["path"] == "/v1/messages?beta=true" for r in posts))
check("provider key replaced the client key", all(r["headers"].get("x-api-key") == "provider-secret-key" for r in posts))
check("anthropic-beta reached the provider", all("claude-code" in r["headers"].get("anthropic-beta", "") for r in posts))
bodies = " ".join(r["body"] for r in posts)
check("no real value reached the provider", "prod-db01" not in bodies and "Jd8@2jd82k" not in bodies)
tool_turns = [json.loads(r["body"]) for r in posts if json.loads(r["body"]).get("tools")]
check("a second turn with history happened", any(len(t["messages"]) >= 4 for t in tool_turns))
hist = json.dumps(tool_turns[-1]["messages"], ensure_ascii=False)
check("the exfiltrating call never reached the client (not in its history)", "exfil.example" not in hist)
check("the harmless call did (and its result was masked again)", "toolu_01A" in hist and "CONNECT h-" in hist)
check("the denial is explained in the history", "[Aegis]" in hist)
audit = open(f"{w}/audit.jsonl").read()
check("audit holds no values", "prod-db01" not in audit and "Jd8@2jd82k" not in audit)
PY
echo "CLIENT OK"

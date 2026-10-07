#!/usr/bin/env bash
# REQ: QA-14, PRO-16, RSP-07, INV-6
# Real-client check: OpenCode (`opencode run`) talks to Aegis over Chat Completions (a custom OpenAI-compatible
# provider), Aegis talks to a mock provider. OpenCode is taken from PATH or installed with npm into a temporary
# directory. Same checks as client-qwen.sh. Skips without OpenCode.
set -euo pipefail
cd "$(dirname "$0")/.."
W=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"' EXIT
OC=$(command -v opencode || true)
if [ -z "$OC" ]; then
  npm install --silent --prefix "$W/npm" opencode-ai >/dev/null 2>&1 || { echo "skip: opencode is not installed and npm cannot fetch it"; exit 0; }
  OC="$W/npm/node_modules/.bin/opencode"
fi
cargo build -q --release -p aegis-gateway
PORT=$((20000 + RANDOM % 20000)); ADMIN=$((PORT + 1)); UP=$((PORT + 2))
mkdir -p "$W/home" "$W/work"; : > "$W/provider.log"
TOOLMODE=bash python3 scripts/mock_openai.py "$UP" "$W/provider.log" &
HASH=$(printf %s aegis-vk-opencode | sha256sum | cut -d' ' -f1)
cat > "$W/gw.json" <<JSON
{"listen":"127.0.0.1:$PORT","admin_listen":"127.0.0.1:$ADMIN","openai_base_url":"http://127.0.0.1:$UP",
 "internal_zones":["corp.local"],"audit_path":"$W/audit.jsonl","virtual_keys":[{"sha256":"$HASH","principal":"u:opencode"}]}
JSON
AEGIS_K_TENANT=0123456789abcdef0123456789abcdef AEGIS_K_AUDIT=fedcba9876543210fedcba9876543210 \
  AEGIS_OPENAI_KEY=provider-secret-key target/release/aegis-gateway "$W/gw.json" > "$W/gw.log" 2>&1 &
for _ in $(seq 1 50); do curl -sf "http://127.0.0.1:$ADMIN/readyz" >/dev/null 2>&1 && break; sleep 0.1; done

cat > "$W/work/opencode.json" <<JSON
{"\$schema":"https://opencode.ai/config.json",
 "provider":{"aegis":{"npm":"@ai-sdk/openai-compatible","name":"Aegis","options":{"baseURL":"http://127.0.0.1:$PORT/v1","apiKey":"aegis-vk-opencode"},"models":{"test":{"name":"test","tool_call":true}}}},
 "permission":{"bash":"allow","edit":"allow","webfetch":"allow"},"autoupdate":false,"share":"disabled"}
JSON
cd "$W/work"
HOME="$W/home" XDG_CONFIG_HOME="$W/home/.config" XDG_DATA_HOME="$W/home/.local/share" XDG_CACHE_HOME="$W/home/.cache" \
  NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost \
  timeout 180 "$OC" run -m aegis/test "Не подключается к prod-db01.corp.local, password=Jd8!2jd82k. Проверь." \
  < /dev/null > "$W/opencode.out" 2>&1

python3 - "$W" <<'PY'
import json, sys
w = sys.argv[1]
rows = [json.loads(l) for l in open(f"{w}/provider.log")]
posts = [r for r in rows if r["method"] == "POST"]
def check(name, ok):
    print(("ok   " if ok else "FAIL ") + name)
    if not ok:
        print(open(f"{w}/opencode.out").read()[-1500:])
        sys.exit(1)
check("OpenCode got the final answer", "Готово. Всё работает." in open(f"{w}/opencode.out").read())
check("requests went to /v1/chat/completions", posts and all(r["path"] == "/v1/chat/completions" for r in posts))
check("provider key replaced the client key", all(r["headers"].get("authorization") == "Bearer provider-secret-key" for r in posts))
bodies = " ".join(r["body"] for r in posts)
check("no real value reached the provider, in any request or in the history", "prod-db01" not in bodies and "Jd8!2jd82k" not in bodies)
agent = [json.loads(r["body"]) for r in posts if len(json.loads(r["body"])["messages"]) > 2 and json.loads(r["body"]).get("tools")]
hist = json.dumps(agent[-1]["messages"], ensure_ascii=False)
check("the harmless command's output is masked in the next request", "CONNECT h-" in hist)
check("the exfiltrating call never reached the client", "exfil.example" not in hist)
check("the denial is explained in the history", "[Aegis]" in hist)
audit = open(f"{w}/audit.jsonl").read() + open(f"{w}/gw.log").read()
check("audit and log hold no values", "prod-db01" not in audit and "Jd8!2jd82k" not in audit)
PY
echo "CLIENT OK"

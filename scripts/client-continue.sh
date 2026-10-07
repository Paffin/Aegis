#!/usr/bin/env bash
# REQ: QA-14, PRO-16, RSP-07, INV-6
# Real-client check: Continue CLI (`cn -p`) talks to Aegis over Chat Completions, Aegis talks to a mock provider.
# Continue is taken from PATH or installed with npm into a temporary directory. Same checks as client-qwen.sh.
# Skips without Continue.
set -euo pipefail
cd "$(dirname "$0")/.."
W=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"' EXIT
CN=$(command -v cn || true)
if [ -z "$CN" ]; then
  npm install --silent --prefix "$W/npm" @continuedev/cli >/dev/null 2>&1 || { echo "skip: cn is not installed and npm cannot fetch it"; exit 0; }
  CN="$W/npm/node_modules/.bin/cn"
fi
cargo build -q --release -p aegis-gateway
PORT=$((20000 + RANDOM % 20000)); ADMIN=$((PORT + 1)); UP=$((PORT + 2))
mkdir -p "$W/home/.continue" "$W/work"; : > "$W/provider.log"
TOOLMODE=Bash python3 scripts/mock_openai.py "$UP" "$W/provider.log" &
HASH=$(printf %s aegis-vk-continue | sha256sum | cut -d' ' -f1)
cat > "$W/gw.json" <<JSON
{"listen":"127.0.0.1:$PORT","admin_listen":"127.0.0.1:$ADMIN","openai_base_url":"http://127.0.0.1:$UP",
 "internal_zones":["corp.local"],"audit_path":"$W/audit.jsonl","virtual_keys":[{"sha256":"$HASH","principal":"u:continue"}]}
JSON
AEGIS_K_TENANT=0123456789abcdef0123456789abcdef AEGIS_K_AUDIT=fedcba9876543210fedcba9876543210 \
  AEGIS_OPENAI_KEY=provider-secret-key target/release/aegis-gateway "$W/gw.json" > "$W/gw.log" 2>&1 &
for _ in $(seq 1 50); do curl -sf "http://127.0.0.1:$ADMIN/readyz" >/dev/null 2>&1 && break; sleep 0.1; done

cat > "$W/home/.continue/config.yaml" <<YAML
name: aegis-test
version: 1.0.0
schema: v1
models:
  - name: test
    provider: openai
    model: test
    apiBase: http://127.0.0.1:$PORT/v1
    apiKey: aegis-vk-continue
    roles: [chat]
YAML
cd "$W/work"
HOME="$W/home" NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost CONTINUE_GLOBAL_DIR="$W/home/.continue" \
  timeout 150 "$CN" -p --config "$W/home/.continue/config.yaml" --auto \
  "Не подключается к prod-db01.corp.local, password=Jd8!2jd82k. Проверь." < /dev/null > "$W/cn.out" 2>&1

python3 - "$W" <<'PY'
import json, sys
w = sys.argv[1]
rows = [json.loads(l) for l in open(f"{w}/provider.log")]
posts = [r for r in rows if r["method"] == "POST"]
def check(name, ok):
    print(("ok   " if ok else "FAIL ") + name)
    if not ok:
        print(open(f"{w}/cn.out").read()[-1500:])
        sys.exit(1)
check("Continue got the final answer", "Готово. Всё работает." in open(f"{w}/cn.out").read())
check("requests went to /v1/chat/completions", posts and all(r["path"] == "/v1/chat/completions" for r in posts))
check("provider key replaced the client key", all(r["headers"].get("authorization") == "Bearer provider-secret-key" for r in posts))
bodies = " ".join(r["body"] for r in posts)
check("no real value reached the provider, in any request or in the history", "prod-db01" not in bodies and "Jd8!2jd82k" not in bodies)
agent = [json.loads(r["body"]) for r in posts if len(json.loads(r["body"])["messages"]) > 2]
hist = json.dumps(agent[-1]["messages"], ensure_ascii=False)
check("the harmless command's output is masked in the next request", "CONNECT h-" in hist)
check("the exfiltrating call never reached the client", "exfil.example" not in hist)
check("the denial is explained, on its own line", "[Aegis]" in hist and "\\n[Aegis]" in hist)
audit = open(f"{w}/audit.jsonl").read() + open(f"{w}/gw.log").read()
check("audit and log hold no values", "prod-db01" not in audit and "Jd8!2jd82k" not in audit)
PY
echo "CLIENT OK"

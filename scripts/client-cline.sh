#!/usr/bin/env bash
# REQ: QA-14, PRO-16, RSP-07, INV-6
# Real-client check: Cline CLI (`cline -y`) talks to Aegis over Chat Completions (an OpenAI-compatible provider),
# Aegis talks to a mock provider. Cline is taken from PATH or installed with npm into a temporary directory.
# The mock ends the task the way Cline expects, with the `submit_and_exit` tool. Same checks as client-qwen.sh.
# Skips without Cline.
set -euo pipefail
cd "$(dirname "$0")/.."
W=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"' EXIT
if command -v cline >/dev/null; then CLINE=(cline); else
  npm install --silent --prefix "$W/npm" cline >/dev/null 2>&1 || { echo "skip: cline is not installed and npm cannot fetch it"; exit 0; }
  CLINE=(node "$W/npm/node_modules/cline/bin/cline")
fi
cargo build -q --release -p aegis-gateway
PORT=$((20000 + RANDOM % 20000)); ADMIN=$((PORT + 1)); UP=$((PORT + 2))
mkdir -p "$W/home" "$W/work" "$W/data"; : > "$W/provider.log"
TOOLMODE=run_commands python3 scripts/mock_openai.py "$UP" "$W/provider.log" &
HASH=$(printf %s aegis-vk-cline | sha256sum | cut -d' ' -f1)
cat > "$W/gw.json" <<JSON
{"listen":"127.0.0.1:$PORT","admin_listen":"127.0.0.1:$ADMIN","openai_base_url":"http://127.0.0.1:$UP",
 "internal_zones":["corp.local"],"audit_path":"$W/audit.jsonl","virtual_keys":[{"sha256":"$HASH","principal":"u:cline"}]}
JSON
AEGIS_K_TENANT=0123456789abcdef0123456789abcdef AEGIS_K_AUDIT=fedcba9876543210fedcba9876543210 \
  AEGIS_OPENAI_KEY=provider-secret-key target/release/aegis-gateway "$W/gw.json" > "$W/gw.log" 2>&1 &
for _ in $(seq 1 50); do curl -sf "http://127.0.0.1:$ADMIN/readyz" >/dev/null 2>&1 && break; sleep 0.1; done

cd "$W/work"
export HOME="$W/home" NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost
"${CLINE[@]}" auth openai -k aegis-vk-cline -m test -b "http://127.0.0.1:$PORT/v1" --data-dir "$W/data" > /dev/null 2>&1
timeout 120 "${CLINE[@]}" --data-dir "$W/data" -y -P openai -m test -t 100 \
  "Не подключается к prod-db01.corp.local, password=Jd8!2jd82k. Проверь." < /dev/null > "$W/cline.out" 2>&1

python3 - "$W" <<'PY'
import json, sys
w = sys.argv[1]
rows = [json.loads(l) for l in open(f"{w}/provider.log")]
posts = [r for r in rows if r["method"] == "POST"]
out = open(f"{w}/cline.out").read()
def check(name, ok):
    print(("ok   " if ok else "FAIL ") + name)
    if not ok:
        print(out[-1500:])
        sys.exit(1)
check("Cline finished the task (submit_and_exit)", "Submission recorded" in out)
check("requests went to /v1/chat/completions", posts and all(r["path"] == "/v1/chat/completions" for r in posts))
check("provider key replaced the client key", all(r["headers"].get("authorization") == "Bearer provider-secret-key" for r in posts))
bodies = " ".join(r["body"] for r in posts)
check("no real value reached the provider, in any request or in the history", "prod-db01" not in bodies and "Jd8!2jd82k" not in bodies)
agent = [json.loads(r["body"]) for r in posts if len(json.loads(r["body"])["messages"]) > 2]
hist = json.dumps(agent[-1]["messages"], ensure_ascii=False)
check("the harmless command's output is masked in the next request", "CONNECT h-" in hist)
check("the exfiltrating call never reached the client", "exfil.example" not in hist)
check("the denial is explained, on its own line", "[Aegis]" in hist and "\\n[Aegis]" in hist)
check("the harmless command ran with the real host, the summary got it back", "CONNECT prod-db01.corp.local" in out and "Проверил prod-db01.corp.local" in out)
audit = open(f"{w}/audit.jsonl").read() + open(f"{w}/gw.log").read()
check("audit and log hold no values", "prod-db01" not in audit and "Jd8!2jd82k" not in audit)
PY
echo "CLIENT OK"

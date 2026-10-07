#!/usr/bin/env bash
# Real-client check: Gemini CLI (`gemini -p`) talks to Aegis over the Gemini API (SSE), Aegis talks to a mock
# provider. Gemini CLI is taken from PATH or installed with npm into a temporary directory.
# Same checks as client-codex.sh. Skips without Gemini CLI.
set -euo pipefail
cd "$(dirname "$0")/.."
W=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"' EXIT
GEMINI=$(command -v gemini || true)
if [ -z "$GEMINI" ]; then
  npm install --silent --prefix "$W/npm" @google/gemini-cli >/dev/null 2>&1 || { echo "skip: gemini is not installed and npm cannot fetch it"; exit 0; }
  GEMINI="$W/npm/node_modules/.bin/gemini"
fi
cargo build -q --release -p aegis-gateway
PORT=$((20000 + RANDOM % 20000)); ADMIN=$((PORT + 1)); UP=$((PORT + 2))
mkdir -p "$W/home/.gemini" "$W/work"; : > "$W/provider.log"
echo '{"security":{"auth":{"selectedType":"gemini-api-key"}},"telemetry":{"enabled":false},"general":{"disableAutoUpdate":true}}' > "$W/home/.gemini/settings.json"
TOOLMODE=run_shell_command python3 scripts/mock_gemini.py "$UP" "$W/provider.log" &
HASH=$(printf %s aegis-vk-gemini | sha256sum | cut -d' ' -f1)
cat > "$W/gw.json" <<JSON
{"listen":"127.0.0.1:$PORT","admin_listen":"127.0.0.1:$ADMIN","gemini_base_url":"http://127.0.0.1:$UP",
 "internal_zones":["corp.local"],"audit_path":"$W/audit.jsonl","virtual_keys":[{"sha256":"$HASH","principal":"u:gemini"}]}
JSON
AEGIS_K_TENANT=0123456789abcdef0123456789abcdef AEGIS_K_AUDIT=fedcba9876543210fedcba9876543210 \
  AEGIS_GEMINI_KEY=provider-secret-key target/release/aegis-gateway "$W/gw.json" > "$W/gw.log" 2>&1 &
for _ in $(seq 1 50); do curl -sf "http://127.0.0.1:$ADMIN/readyz" >/dev/null 2>&1 && break; sleep 0.1; done

cd "$W/work"
HOME="$W/home" GEMINI_API_KEY=aegis-vk-gemini GOOGLE_GEMINI_BASE_URL="http://127.0.0.1:$PORT" \
  NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost GEMINI_CLI_TRUST_WORKSPACE=true \
  timeout 120 "$GEMINI" -m gemini-test --yolo -p "Не подключается к prod-db01.corp.local, password=Jd8!2jd82k. Проверь." \
  < /dev/null > "$W/gemini.out" 2>&1

python3 - "$W" <<'PY'
import json, sys
w = sys.argv[1]
rows = [json.loads(l) for l in open(f"{w}/provider.log")]
posts = [r for r in rows if r["method"] == "POST"]
def check(name, ok):
    print(("ok   " if ok else "FAIL ") + name)
    if not ok:
        print(open(f"{w}/gemini.out").read()[-1500:])
        sys.exit(1)
out = open(f"{w}/gemini.out").read()
check("Gemini CLI got the final answer", "Готово. Всё работает." in out)
gen = [r for r in posts if ":streamGenerateContent" in r["path"]]
check("streaming requests keep ?alt=sse", gen and all(r["path"].endswith("?alt=sse") for r in gen))
check("provider key replaced the client key", all(r["headers"].get("x-goog-api-key") == "provider-secret-key" for r in posts))
bodies = " ".join(r["body"] for r in posts)
check("no real value reached the provider, in any request or in the history", "prod-db01" not in bodies and "Jd8!2jd82k" not in bodies)
turns = [json.loads(r["body"]) for r in gen if "functionResponse" in r["body"]]
check("a second turn with the tool result happened", bool(turns))
hist = json.dumps(turns[-1]["contents"], ensure_ascii=False)
check("the harmless command's output is masked in the next request", "CONNECT h-" in hist)
check("the exfiltrating call never reached the client", "exfil.example" not in hist)
check("the denial is explained in the history", "[Aegis]" in hist)
check("the harmless command ran with the real host", "CONNECT prod-db01.corp.local" in out or "prod-db01.corp.local" in out)
audit = open(f"{w}/audit.jsonl").read() + open(f"{w}/gw.log").read()
check("audit and log hold no values", "prod-db01" not in audit and "Jd8!2jd82k" not in audit)
PY
echo "CLIENT OK"

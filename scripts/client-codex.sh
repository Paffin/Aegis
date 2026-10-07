#!/usr/bin/env bash
# Real-client check: the Codex CLI (`codex exec`) talks to Aegis over the Responses API, Aegis talks to a
# mock provider. Codex is taken from PATH or installed with npm into a temporary directory.
# Verifies: values are masked, the provider key replaces the client key, the harmless command runs
# with the real value, its output is masked again on the next turn, a call that would carry the secret
# out is replaced by an explanation, and neither audit nor logs hold values. Skips without Codex.
set -euo pipefail
cd "$(dirname "$0")/.."
W=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"' EXIT
CODEX=$(command -v codex || true)
if [ -z "$CODEX" ]; then
  npm install --silent --prefix "$W/npm" @openai/codex >/dev/null 2>&1 || { echo "skip: codex is not installed and npm cannot fetch it"; exit 0; }
  CODEX="$W/npm/node_modules/.bin/codex"
fi
cargo build -q --release -p aegis-gateway
PORT=$((20000 + RANDOM % 20000)); ADMIN=$((PORT + 1)); UP=$((PORT + 2))
mkdir -p "$W/home" "$W/work"; : > "$W/provider.log"
TOOLMODE=exec_command python3 scripts/mock_openai.py "$UP" "$W/provider.log" &
HASH=$(printf %s aegis-vk-codex | sha256sum | cut -d' ' -f1)
cat > "$W/gw.json" <<JSON
{"listen":"127.0.0.1:$PORT","admin_listen":"127.0.0.1:$ADMIN","openai_base_url":"http://127.0.0.1:$UP",
 "internal_zones":["corp.local"],"audit_path":"$W/audit.jsonl","virtual_keys":[{"sha256":"$HASH","principal":"u:codex"}]}
JSON
AEGIS_K_TENANT=0123456789abcdef0123456789abcdef AEGIS_K_AUDIT=fedcba9876543210fedcba9876543210 \
  AEGIS_OPENAI_KEY=provider-secret-key target/release/aegis-gateway "$W/gw.json" > "$W/gw.log" 2>&1 &
for _ in $(seq 1 50); do curl -sf "http://127.0.0.1:$ADMIN/readyz" >/dev/null 2>&1 && break; sleep 0.1; done

cd "$W/work"
# Codex sends a `web_search` tool by default: Aegis refuses server-side tools, so it is switched off.
CODEX_HOME="$W/home" HOME="$W/home" AEGIS_API_KEY=aegis-vk-codex NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost \
  timeout 120 "$CODEX" exec --skip-git-repo-check -s workspace-write \
  -c model_provider=aegis -c "model_providers.aegis={name=\"Aegis\",base_url=\"http://127.0.0.1:$PORT/v1\",env_key=\"AEGIS_API_KEY\",wire_api=\"responses\"}" \
  -c model=gpt-test -c web_search=disabled \
  "Не подключается к prod-db01.corp.local, password=Jd8@2jd82k. Проверь." < /dev/null > "$W/codex.out" 2>&1

python3 - "$W" <<'PY'
import json, sys
w = sys.argv[1]
rows = [json.loads(l) for l in open(f"{w}/provider.log")]
posts = [r for r in rows if r["method"] == "POST"]
def check(name, ok):
    print(("ok   " if ok else "FAIL ") + name)
    if not ok:
        print(open(f"{w}/codex.out").read()[-1500:])
        sys.exit(1)
out = open(f"{w}/codex.out").read()
check("Codex got the final answer", "Готово. Всё работает." in out)
check("requests went to /v1/responses", posts and all(r["path"] == "/v1/responses" for r in posts))
check("provider key replaced the client key", all(r["headers"].get("authorization") == "Bearer provider-secret-key" for r in posts))
bodies = " ".join(r["body"] for r in posts)
check("no real value reached the provider", "prod-db01" not in bodies and "Jd8@2jd82k" not in bodies)
check("store is false (Aegis is stateless)", all(json.loads(r["body"]).get("store") is False for r in posts))
second = json.loads(posts[-1]["body"])["input"]
hist = json.dumps(second, ensure_ascii=False)
check("the harmless command ran with the real host (its output came back)", "CONNECT prod-db01.corp.local" in out)
check("its output is masked again in the next request", "CONNECT h-" in hist)
check("the exfiltrating call is replaced by an explanation", "exfil.example" not in hist and "[Aegis]" in hist)
audit = open(f"{w}/audit.jsonl").read() + open(f"{w}/gw.log").read()
check("audit and log hold no values", "prod-db01" not in audit and "Jd8@2jd82k" not in audit)
PY
echo "CLIENT OK"

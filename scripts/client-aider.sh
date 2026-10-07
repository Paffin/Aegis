#!/usr/bin/env bash
# Real-client check: Aider (`aider --message`) talks to Aegis over Chat Completions (streaming), Aegis talks to
# a mock provider. Aider is taken from PATH or installed with `uv tool install`. Aider has no tool calls: the point
# is that the prompt and the content of the files added to the chat are masked. Skips without Aider.
set -euo pipefail
cd "$(dirname "$0")/.."
AIDER=$(command -v aider || true)
if [ -z "$AIDER" ]; then
  command -v uv >/dev/null && uv tool install --python 3.12 aider-chat >/dev/null 2>&1 && AIDER=$(command -v aider || echo "$HOME/.local/bin/aider")
  [ -x "${AIDER:-/nonexistent}" ] || { echo "skip: aider is not installed and cannot be fetched"; exit 0; }
fi
W=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"' EXIT
cargo build -q --release -p aegis-gateway
PORT=$((20000 + RANDOM % 20000)); ADMIN=$((PORT + 1)); UP=$((PORT + 2))
mkdir -p "$W/home" "$W/work"; : > "$W/provider.log"
python3 scripts/mock_openai.py "$UP" "$W/provider.log" &
HASH=$(printf %s aegis-vk-aider | sha256sum | cut -d' ' -f1)
cat > "$W/gw.json" <<JSON
{"listen":"127.0.0.1:$PORT","admin_listen":"127.0.0.1:$ADMIN","openai_base_url":"http://127.0.0.1:$UP",
 "internal_zones":["corp.local"],"audit_path":"$W/audit.jsonl","virtual_keys":[{"sha256":"$HASH","principal":"u:aider"}]}
JSON
AEGIS_K_TENANT=0123456789abcdef0123456789abcdef AEGIS_K_AUDIT=fedcba9876543210fedcba9876543210 \
  AEGIS_OPENAI_KEY=provider-secret-key target/release/aegis-gateway "$W/gw.json" > "$W/gw.log" 2>&1 &
for _ in $(seq 1 50); do curl -sf "http://127.0.0.1:$ADMIN/readyz" >/dev/null 2>&1 && break; sleep 0.1; done

cd "$W/work"
printf 'DB_URL=postgres://svc:Xk9pQ2vL8m@prod-db01.pay.corp.local:5432/clients\n' > app.env
HOME="$W/home" OPENAI_API_BASE="http://127.0.0.1:$PORT/v1" OPENAI_API_KEY=aegis-vk-aider \
  NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost AIDER_ANALYTICS_DISABLE=1 \
  timeout 150 "$AIDER" --model openai/test --no-git --yes-always --no-show-model-warnings --no-check-update \
  --no-analytics --no-gitignore --map-tokens 0 \
  --message "Не подключается к prod-db01.corp.local, password=Jd8!2jd82k. Проверь." app.env \
  < /dev/null > "$W/aider.out" 2>&1

python3 - "$W" <<'PY'
import json, sys
w = sys.argv[1]
rows = [json.loads(l) for l in open(f"{w}/provider.log")]
posts = [r for r in rows if r["method"] == "POST"]
def check(name, ok):
    print(("ok   " if ok else "FAIL ") + name)
    if not ok:
        print(open(f"{w}/aider.out").read()[-1500:])
        sys.exit(1)
check("Aider got the answer", "Готово. Всё работает." in open(f"{w}/aider.out").read())
check("the request went to /v1/chat/completions", posts and all(r["path"] == "/v1/chat/completions" for r in posts))
check("provider key replaced the client key", all(r["headers"].get("authorization") == "Bearer provider-secret-key" for r in posts))
bodies = " ".join(r["body"] for r in posts)
check("neither the prompt nor the file reached the provider with real values",
      "prod-db01" not in bodies and "Jd8!2jd82k" not in bodies and "Xk9pQ2vL8m" not in bodies)
check("the file content is there, masked", "postgres://" in bodies and "aegis.invalid" in bodies)
audit = open(f"{w}/audit.jsonl").read() + open(f"{w}/gw.log").read()
check("audit and log hold no values", "prod-db01" not in audit and "Jd8!2jd82k" not in audit and "Xk9pQ2vL8m" not in audit)
PY
echo "CLIENT OK"

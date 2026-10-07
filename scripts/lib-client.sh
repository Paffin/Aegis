# Shared by the client-*.sh scripts for clients that speak OpenAI Chat Completions.
# REQ: QA-14. Usage (after `source`):
#   start_stack <label> <tool name>   # sets W (work dir), PORT; mock provider + gateway are running
#   check_chat <client output file> <client name> <tool name>
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

start_stack() {
  LABEL=$1; TOOL=$2
  W=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"' EXIT
  cargo build -q --release -p aegis-gateway
  PORT=$((20000 + RANDOM % 20000)); ADMIN=$((PORT + 1)); UP=$((PORT + 2))
  mkdir -p "$W/home" "$W/work"; : > "$W/provider.log"
  TOOLMODE=$TOOL python3 scripts/mock_openai.py "$UP" "$W/provider.log" &
  local hash; hash=$(printf %s "aegis-vk-$LABEL" | sha256sum | cut -d' ' -f1)
  cat > "$W/gw.json" <<JSON
{"listen":"127.0.0.1:$PORT","admin_listen":"127.0.0.1:$ADMIN","openai_base_url":"http://127.0.0.1:$UP",
 "internal_zones":["corp.local"],"audit_path":"$W/audit.jsonl","virtual_keys":[{"sha256":"$hash","principal":"u:$LABEL"}]}
JSON
  AEGIS_K_TENANT=0123456789abcdef0123456789abcdef AEGIS_K_AUDIT=fedcba9876543210fedcba9876543210 \
    AEGIS_OPENAI_KEY=provider-secret-key target/release/aegis-gateway "$W/gw.json" > "$W/gw.log" 2>&1 &
  for _ in $(seq 1 50); do curl -sf "http://127.0.0.1:$ADMIN/readyz" >/dev/null 2>&1 && break; sleep 0.1; done
}

PROMPT='Не подключается к prod-db01.corp.local, password=Jd8!2jd82k. Проверь.'

check_chat() {
  python3 - "$W" "$1" "$2" "$3" <<'PY'
import json, sys
w, out, name, tool = sys.argv[1:5]
rows = [json.loads(l) for l in open(f"{w}/provider.log")]
posts = [r for r in rows if r["method"] == "POST"]
def check(what, ok):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        print(open(out).read()[-1500:])
        sys.exit(1)
check(f"{name} got the final answer", "Готово. Всё работает." in open(out).read())
check("requests went to /v1/chat/completions", bool(posts) and all(r["path"] == "/v1/chat/completions" for r in posts))
check("provider key replaced the client key", all(r["headers"].get("authorization") == "Bearer provider-secret-key" for r in posts))
bodies = " ".join(r["body"] for r in posts)
check("no real value reached the provider, in any request or in the history", "prod-db01" not in bodies and "Jd8!2jd82k" not in bodies)
agent = [json.loads(r["body"]) for r in posts if f'"{tool}"' in r["body"] and len(json.loads(r["body"])["messages"]) > 2]
check("a second turn with the tool output was sent", bool(agent))
hist = json.dumps(agent[-1]["messages"], ensure_ascii=False)
check("the harmless command's output is masked in the next request", "CONNECT h-" in hist)
check("the exfiltrating call never reached the client", "exfil.example" not in hist)
check("the denial is explained", "[Aegis]" in hist)
audit = open(f"{w}/audit.jsonl").read() + open(f"{w}/gw.log").read()
check("audit and log hold no values", "prod-db01" not in audit and "Jd8!2jd82k" not in audit)
PY
}

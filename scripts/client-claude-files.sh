#!/usr/bin/env bash
# REQ: QA-14, QA-06, RST-05, RST-08, INV-5, INV-6
# Real-client check of the file scenario from the concept: Claude Code reads a config file, the model (a mock)
# edits that file with the secret marker in the text and edits another file the same way. The first edit is
# allowed (a secret may return to the file it came from), the second is refused, and the file on disk
# holds the real value without any marker. Skips when `claude` is not installed.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v claude >/dev/null || { echo "skip: claude is not installed"; exit 0; }
cargo build -q --release -p aegis-gateway
W=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"' EXIT
PORT=$((20000 + RANDOM % 20000)); ADMIN=$((PORT + 1)); UP=$((PORT + 2))
mkdir -p "$W/home" "$W/work"; : > "$W/provider.log"
printf 'DB_HOST=prod-db01.corp.local\nDB_PASSWORD=Jd8!2jd82k\n' > "$W/work/config.env"
printf 'NOTE=x\n' > "$W/work/other.env"
TOOLMODE=1 MOCK_DIR="$W/work" python3 scripts/mock_anthropic.py "$UP" "$W/provider.log" &
HASH=$(printf %s aegis-vk-claude | sha256sum | cut -d' ' -f1)
cat > "$W/gw.json" <<JSON
{"listen":"127.0.0.1:$PORT","admin_listen":"127.0.0.1:$ADMIN","anthropic_base_url":"http://127.0.0.1:$UP",
 "internal_zones":["corp.local"],"audit_path":"$W/audit.jsonl","virtual_keys":[{"sha256":"$HASH","principal":"u:claude"}]}
JSON
AEGIS_K_TENANT=0123456789abcdef0123456789abcdef AEGIS_K_AUDIT=fedcba9876543210fedcba9876543210 \
  AEGIS_ANTHROPIC_KEY=provider-secret-key target/release/aegis-gateway "$W/gw.json" > "$W/gw.log" 2>&1 &
for _ in $(seq 1 50); do curl -sf "http://127.0.0.1:$ADMIN/readyz" >/dev/null 2>&1 && break; sleep 0.1; done

cd "$W/work"
HOME="$W/home" CLAUDE_CONFIG_DIR="$W/home/.claude" NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost \
  ANTHROPIC_BASE_URL="http://127.0.0.1:$PORT" ANTHROPIC_API_KEY=aegis-vk-claude DISABLE_AUTOUPDATER=1 \
  timeout 120 claude --bare -p "FILES: поправь config.env, подключение к базе не работает." \
  --allowedTools Read Edit --output-format json < /dev/null > "$W/claude.json"

python3 - "$W" <<'PY'
import json, os, sys
w = sys.argv[1]
rows = [json.loads(l) for l in open(f"{w}/provider.log")]
posts = [r for r in rows if r["method"] == "POST"]
def check(name, ok):
    print(("ok   " if ok else "FAIL ") + name)
    if not ok:
        print(open(f"{w}/claude.json").read()[-800:])
        sys.exit(1)
cfg = open(f"{w}/work/config.env").read()
other = open(f"{w}/work/other.env").read()
check("the edit of the origin file put the real password back, with the new text", "DB_PASSWORD=Jd8!2jd82k # rotate" in cfg and "DB_HOST=prod-db01.corp.local" in cfg)
check("no marker or pseudonym reached the disk", "[[" not in cfg and "aegis.invalid" not in cfg)
check("the refused edit left the other file as it was", other == "NOTE=x\n")
bodies = " ".join(r["body"] for r in posts)
check("no real value reached the provider", "prod-db01" not in bodies and "Jd8!2jd82k" not in bodies)
turns = [json.loads(r["body"]) for r in posts if json.loads(r["body"]).get("tools")]
check("the file content came to the provider masked", any("toolu_01R" in json.dumps(t) and "[[SECRET_" in json.dumps(t) for t in turns))
last = json.dumps(turns[-1]["messages"], ensure_ascii=False)
check("the allowed edit is in the history, masked again", "toolu_01W" in last and "# rotate" in last and "Jd8!2jd82k" not in last)
check("the refused edit is not in the history", "toolu_01X" not in last and "other.env" not in last)
check("the refusal is explained", "[Aegis]" in last)
audit = open(f"{w}/audit.jsonl").read() + open(f"{w}/gw.log").read()
check("audit and log hold no values", "prod-db01" not in audit and "Jd8!2jd82k" not in audit)
PY
echo "CLIENT OK"

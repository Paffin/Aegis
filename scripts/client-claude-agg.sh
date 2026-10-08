#!/usr/bin/env bash
# REQ: AGG-03, AGG-05, QA-14
# Real Claude Code with Agent Guard AND the gateway: the credential comes from `aegis-guard credential`
# (apiKeyHelper) with a signed device token; the gateway sees the token, restores the real e-mail into a
# local command instead of refusing it (RST-09), and the PreToolUse hook of the guard receives the command
# with the real address and asks the user (G-05). Then the same without the token: the gateway refuses.
# The model is a mock. Skips when `claude` is not installed.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v claude >/dev/null || { echo "skip: claude is not installed"; exit 0; }
cargo build -q --release -p aegis-gateway -p aegis-guard
W=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null || true; if [ -n "${KEEP:-}" ]; then echo "kept: $W"; else rm -rf "$W"; fi' EXIT
PORT=$((20000 + RANDOM % 20000)); ADMIN=$((PORT + 1)); UP=$((PORT + 2))
G="$PWD/target/release/aegis-guard"
mkdir -p "$W/home/.claude" "$W/work"; : > "$W/provider.log"
printf 'aegis-vk-agg\n' > "$W/vk"
PUB=$("$G" enroll --id laptop-ci --key-file "$W/device.key" | sed -n 's/.*"public_key": "\([0-9a-f]*\)".*/\1/p')
[ ${#PUB} -eq 64 ] || { echo "FAIL: enroll printed no public key"; exit 1; }
TOOLMODE=1 python3 scripts/mock_anthropic.py "$UP" "$W/provider.log" &
HASH=$(printf %s aegis-vk-agg | sha256sum | cut -d' ' -f1)
cat > "$W/gw.json" <<JSON
{"listen":"127.0.0.1:$PORT","admin_listen":"127.0.0.1:$ADMIN","anthropic_base_url":"http://127.0.0.1:$UP",
 "internal_zones":["corp.local","company.ru"],"audit_path":"$W/audit.jsonl",
 "guard":{"devices":[{"id":"laptop-ci","public_key":"$PUB"}]},
 "virtual_keys":[{"sha256":"$HASH","principal":"u:claude"}]}
JSON
AEGIS_K_TENANT=0123456789abcdef0123456789abcdef AEGIS_K_AUDIT=fedcba9876543210fedcba9876543210 \
  AEGIS_ANTHROPIC_KEY=provider-secret-key target/release/aegis-gateway "$W/gw.json" > "$W/gw.log" 2>&1 &
for _ in $(seq 1 50); do curl -sf "http://127.0.0.1:$ADMIN/readyz" >/dev/null 2>&1 && break; sleep 0.1; done

# The hook records what it was given and then asks the real guard.
cat > "$W/hook.sh" <<SH
#!/usr/bin/env bash
tee -a "$W/hook-input.log" | "$G" hook --config "$W/guard.yaml" | tee -a "$W/hook-output.log"
SH
chmod +x "$W/hook.sh"; printf 'version: 1\n' > "$W/guard.yaml"

run() { # <label> <apiKeyHelper command or empty>
  : > "$W/hook-input.log"; : > "$W/hook-output.log"
  local helper=${2:-}
  cat > "$W/home/.claude/settings.json" <<JSON
{"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "$W/hook.sh"}]}]}
 $( [ -n "$helper" ] && printf ', "apiKeyHelper": "%s"' "$helper" )}
JSON
  # (a clean environment: inside a cloud session Claude Code would use the session's own OAuth token)
  ( cd "$W/work"; env -i PATH="$PATH" HOME="$W/home" CLAUDE_CONFIG_DIR="$W/home/.claude" NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost \
    ANTHROPIC_BASE_URL="http://127.0.0.1:$PORT" DISABLE_AUTOUPDATER=1 ${3:-} \
    timeout 120 claude -p "PII: напиши письмо ivan.petrov@company.ru про отпуск" --allowedTools Bash --output-format json \
    < /dev/null > "$W/claude-$1.json" 2>&1 || true )
}

run guard "$G credential --vk-file $W/vk --key-file $W/device.key"
cp "$W/hook-input.log" "$W/hook-guard.log"; cp "$W/hook-output.log" "$W/hook-guard-out.log"; cp "$W/audit.jsonl" "$W/audit-guard.jsonl"
: > "$W/audit.jsonl"
run plain "" "ANTHROPIC_API_KEY=aegis-vk-agg"
cp "$W/hook-input.log" "$W/hook-plain.log"

python3 - "$W" <<'PY'
import json, sys
w = sys.argv[1]
def check(name, ok):
    print(("ok   " if ok else "FAIL ") + name)
    if not ok:
        for f in ("claude-guard.json", "claude-plain.json"):
            print("---", f); print(open(f"{w}/{f}").read()[-700:])
        print("--- hook-guard"); print(open(f"{w}/hook-guard.log").read()[-500:])
        sys.exit(1)
hook_guard = open(f"{w}/hook-guard.log").read()
hook_plain = open(f"{w}/hook-plain.log").read()
audit_guard = open(f"{w}/audit-guard.jsonl").read()
audit_plain = open(f"{w}/audit.jsonl").read()
bodies = " ".join(json.loads(l)["body"] for l in open(f"{w}/provider.log") if l.strip())
check("with the token the command reached the client with the real address", "echo MAIL ivan.petrov@company.ru" in hook_guard)
out_guard = open(f"{w}/hook-guard-out.log").read()
check("the guard on the machine asked the user about it (G-05)", '"permissionDecision":"ask"' in out_guard and "G-05" in out_guard)
check("the audit names the device", '"guard":"laptop-ci"' in audit_guard)
check("without the token the gateway refused the command", "ivan.petrov@company.ru" not in hook_plain)
check("without the token the audit has no device", '"guard"' not in audit_plain)
check("the provider never saw the address", "ivan.petrov" not in bodies)
PY
echo "CLIENT OK"

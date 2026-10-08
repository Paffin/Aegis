#!/usr/bin/env bash
# REQ: AGG-04, AGG-06, QA-14
# Real Claude Code with the managed settings written by `aegis-guard install --lock`: the user (settings
# of the user, of the project, a --settings flag, the shell environment) cannot switch the hook off, cannot
# run own hooks, cannot send the traffic past the gateway; the credential comes from the managed
# apiKeyHelper. Then the sandbox: without bubblewrap the client refuses to work (failIfUnavailable)
# instead of running without it. Needs root (the managed file is /etc/claude-code/managed-settings.json
# and is removed afterwards) and `claude`; otherwise skips. The model is a mock.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v claude >/dev/null || { echo "skip: claude is not installed"; exit 0; }
[ "$(id -u)" = 0 ] || { echo "skip: needs root (managed settings live in /etc)"; exit 0; }
MP=/etc/claude-code/managed-settings.json
[ ! -e "$MP" ] || { echo "skip: $MP exists, not touching it"; exit 0; }
cargo build -q --release -p aegis-guard
W=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"; rm -f "$MP"' EXIT
P=$((20000 + RANDOM % 20000)); UP=$P; DECOY=$((P + 1))
G="$PWD/target/release/aegis-guard"
mkdir -p "$W/home/.ssh" "$W/home/.claude" "$W/work/.claude"; : > "$W/provider.log"; : > "$W/decoy.log"
printf 'PRIVATE-KEY-CONTENT-DO-NOT-SHOW\n' > "$W/home/.ssh/id_x"
printf 'ORDINARY-FILE-CONTENT\n' > "$W/work/ok.txt"
printf 'aegis-vk-managed\n' > "$W/vk"
"$G" enroll --id laptop-ci --key-file "$W/device.key" >/dev/null
printf 'version: 1\npaths: { action: deny }\n' > "$W/guard.yaml"
TOOLMODE=1 MOCK_DIR="$W" python3 scripts/mock_anthropic.py "$UP" "$W/provider.log" &
python3 scripts/mock_anthropic.py "$DECOY" "$W/decoy.log" &
sleep 0.5

# --- the installation, the way an administrator does it
"$G" install --aegis-guard "$G" --config "$W/guard.yaml" --gateway "http://127.0.0.1:$UP" \
  --vk-file "$W/vk" --key-file "$W/device.key" --lock >/dev/null
"$G" doctor --aegis-guard "$G" --config "$W/guard.yaml" >/dev/null || { echo "FAIL: doctor on a fresh installation"; exit 1; }

# --- the user does everything to get rid of it
cat > "$W/home/.claude/settings.json" <<JSON
{"disableAllHooks": true,
 "env": {"ANTHROPIC_BASE_URL": "http://127.0.0.1:$DECOY"},
 "permissions": {"defaultMode": "bypassPermissions"},
 "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "touch $W/user-hook-ran"}]}]}}
JSON
printf '{"disableAllHooks": true, "env": {"ANTHROPIC_BASE_URL": "http://127.0.0.1:%s"}}\n' "$DECOY" > "$W/work/.claude/settings.local.json"
printf '{"disableAllHooks": true, "env": {"ANTHROPIC_BASE_URL": "http://127.0.0.1:%s"}}\n' "$DECOY" > "$W/flag.json"
( cd "$W/work"; env -i PATH="$PATH" HOME="$W/home" CLAUDE_CONFIG_DIR="$W/home/.claude" NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost \
    ANTHROPIC_BASE_URL="http://127.0.0.1:$DECOY" DISABLE_AUTOUPDATER=1 \
    timeout 120 claude -p "GUARD: прочитай оба файла." --allowedTools Read --settings "$W/flag.json" --output-format json \
    < /dev/null > "$W/claude.json" 2>&1 || true )

python3 - "$W" <<'PY'
import json, os, sys
w = sys.argv[1]
def check(name, ok):
    print(("ok   " if ok else "FAIL ") + name)
    if not ok:
        print(open(f"{w}/claude.json").read()[-800:])
        sys.exit(1)
rows = [json.loads(l) for l in open(f"{w}/provider.log") if l.strip()]
bodies = " ".join(r["body"] for r in rows if r["method"] == "POST")
decoy = [l for l in open(f"{w}/decoy.log") if l.strip()]
check("the hook ran although the user, the project and --settings switched hooks off", "Aegis Guard" in bodies and "G-01" in bodies)
check("the private key never reached the model", "PRIVATE-KEY-CONTENT" not in bodies)
check("the ordinary file was read", "ORDINARY-FILE-CONTENT" in bodies)
check("the user's own hook did not run (allowManagedHooksOnly)", not os.path.exists(f"{w}/user-hook-ran"))
check("no request went to the address the user set (managed env wins)", len(decoy) == 0 and len(rows) > 0)
auth = " ".join(v for r in rows for k, v in r["headers"].items() if k in ("authorization", "x-api-key"))
check("the credential came from the managed apiKeyHelper: key and signed device token", "aegis-vk-managed~ag1" in auth)
PY

# --- doctor sees a broken installation
chmod 666 "$MP"
if "$G" doctor --strict --aegis-guard "$G" --config "$W/guard.yaml" >/dev/null 2>&1; then echo "FAIL: doctor --strict accepted a managed file writable by everybody"; exit 1; fi
echo "ok   doctor --strict refuses a managed file that everybody can write"
chmod 644 "$MP"
mv "$MP" "$MP.off"
if "$G" doctor --aegis-guard "$G" >/dev/null 2>&1; then echo "FAIL: doctor accepted a machine without managed settings"; exit 1; fi
echo "ok   doctor refuses a machine without managed settings"
mv "$MP.off" "$MP"

# --- the sandbox with a network policy: no bubblewrap -> the client stops, it does not run without
"$G" install --aegis-guard "$G" --config "$W/guard.yaml" --gateway "http://127.0.0.1:$UP" --lock --sandbox --allow-host pypi.org >/dev/null
if command -v bwrap >/dev/null && command -v socat >/dev/null; then
  echo "ok   sandbox tools present: settings accepted (enforcement is not driven by this script)"
else
  OUT=$( cd "$W/work"; env -i PATH="$PATH" HOME="$W/home" CLAUDE_CONFIG_DIR="$W/home/.claude" NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost \
    ANTHROPIC_API_KEY=x DISABLE_AUTOUPDATER=1 timeout 60 claude -p "hi" --output-format json < /dev/null 2>&1 || true )
  echo "$OUT" | grep -q "sandbox required but unavailable" || { echo "FAIL: client did not refuse without the sandbox"; echo "$OUT" | tail -c 500; exit 1; }
  echo "ok   without bubblewrap the client refuses to run (sandbox.failIfUnavailable)"
fi
echo "CLIENT OK"

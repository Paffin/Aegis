#!/usr/bin/env bash
# REQ: QA-14, PRO-16, RSP-07, INV-6
# Real-client check: Crush (Charm; `crush run`, provider type openai-compat) talks to Aegis over Chat
# Completions, Aegis talks to a mock provider. Crush is taken from PATH or installed with npm into a
# temporary directory. Skips without Crush.
source "$(dirname "$0")/lib-client.sh"
CRUSH=$(command -v crush || true)
if [ -z "$CRUSH" ]; then
  T=$(mktemp -d)
  npm install --silent --prefix "$T/npm" @charmland/crush >/dev/null 2>&1 || { echo "skip: crush is not installed and npm cannot fetch it"; exit 0; }
  CRUSH="$T/npm/node_modules/.bin/crush"
fi
start_stack crush bash
mkdir -p "$W/home/.config/crush"
cat > "$W/home/.config/crush/crush.json" <<JSON
{"providers":{"aegis":{"type":"openai-compat","name":"Aegis","base_url":"http://127.0.0.1:$PORT/v1","api_key":"aegis-vk-crush",
   "models":[{"id":"crush-test","name":"crush-test","context_window":128000,"default_max_tokens":4096}]}},
 "models":{"large":{"provider":"aegis","model":"crush-test"},"small":{"provider":"aegis","model":"crush-test"}},
 "options":{"disable_provider_auto_update":true,"disable_metrics":true}}
JSON
cd "$W/work"
HOME="$W/home" XDG_CONFIG_HOME="$W/home/.config" XDG_DATA_HOME="$W/home/.local/share" NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost \
  timeout 180 "$CRUSH" run -q -D "$W/data" "$PROMPT" < /dev/null > "$W/out" 2>&1 || true
check_chat "$W/out" Crush bash
echo "CLIENT OK"

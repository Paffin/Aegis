#!/usr/bin/env bash
# REQ: QA-14, PRO-16, RSP-07, INV-6
# Real-client check: Kilo Code CLI (`kilo run`; a fork of OpenCode, custom provider through
# @ai-sdk/openai-compatible) talks to Aegis over Chat Completions, Aegis talks to a mock provider. Kilo is
# taken from PATH or installed with npm into a temporary directory. Skips without Kilo.
source "$(dirname "$0")/lib-client.sh"
KILO=$(command -v kilo || true)
if [ -z "$KILO" ]; then
  T=$(mktemp -d)
  npm install --silent --prefix "$T/npm" @kilocode/cli >/dev/null 2>&1 || { echo "skip: kilo is not installed and npm cannot fetch it"; exit 0; }
  KILO="$T/npm/node_modules/.bin/kilo"
fi
start_stack kilo bash
cat > "$W/work/kilo.json" <<JSON
{"\$schema":"https://opencode.ai/config.json",
 "provider":{"aegis":{"npm":"@ai-sdk/openai-compatible","name":"Aegis","options":{"baseURL":"http://127.0.0.1:$PORT/v1","apiKey":"aegis-vk-kilo"},"models":{"test":{"name":"test","tool_call":true}}}},
 "permission":{"bash":"allow","edit":"allow","webfetch":"allow"},"autoupdate":false,"share":"disabled"}
JSON
cd "$W/work"
HOME="$W/home" XDG_CONFIG_HOME="$W/home/.config" XDG_DATA_HOME="$W/home/.local/share" XDG_CACHE_HOME="$W/home/.cache" \
  NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost \
  timeout 180 "$KILO" run -m aegis/test "$PROMPT" < /dev/null > "$W/out" 2>&1 || true
check_chat "$W/out" Kilo bash
echo "CLIENT OK"

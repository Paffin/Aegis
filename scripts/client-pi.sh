#!/usr/bin/env bash
# REQ: QA-14, PRO-16, RSP-07, INV-6
# Real-client check: Pi (pi-coding-agent; `pi -p`, custom provider with api openai-completions in
# models.json) talks to Aegis over Chat Completions, Aegis talks to a mock provider. Pi is taken from PATH or
# installed with npm into a temporary directory. Skips without Pi.
source "$(dirname "$0")/lib-client.sh"
PI=$(command -v pi || true)
if [ -z "$PI" ]; then
  T=$(mktemp -d)
  npm install --silent --prefix "$T/npm" @mariozechner/pi-coding-agent >/dev/null 2>&1 || { echo "skip: pi is not installed and npm cannot fetch it"; exit 0; }
  PI="$T/npm/node_modules/.bin/pi"
fi
start_stack pi bash
mkdir -p "$W/home/.pi/agent"
cat > "$W/home/.pi/agent/models.json" <<JSON
{"providers":{"aegis":{"baseUrl":"http://127.0.0.1:$PORT/v1","api":"openai-completions","apiKey":"aegis-vk-pi",
  "models":[{"id":"pi-test","name":"pi-test","reasoning":false,"input":["text"],"contextWindow":128000,"maxTokens":4096}]}}}
JSON
cd "$W/work"
HOME="$W/home" PI_CODING_AGENT_DIR="$W/home/.pi/agent" NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost \
  timeout 180 "$PI" --provider aegis --model pi-test -p "$PROMPT" < /dev/null > "$W/out" 2>&1 || true
check_chat "$W/out" Pi bash
echo "CLIENT OK"

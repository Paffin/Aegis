#!/usr/bin/env bash
# REQ: QA-14, PRO-16, RSP-07, INV-6
# Real-client check: GitHub Copilot CLI (`copilot -p`; bring-your-own-model through COPILOT_PROVIDER_*,
# which needs no GitHub login) talks to Aegis over Chat Completions, Aegis talks to a mock provider. Copilot
# is taken from PATH or installed with npm into a temporary directory. Skips without Copilot.
source "$(dirname "$0")/lib-client.sh"
COP=$(command -v copilot || true)
if [ -z "$COP" ]; then
  T=$(mktemp -d)
  npm install --silent --prefix "$T/npm" @github/copilot >/dev/null 2>&1 || { echo "skip: copilot is not installed and npm cannot fetch it"; exit 0; }
  COP="$T/npm/node_modules/.bin/copilot"
fi
start_stack copilot bash
cd "$W/work"
HOME="$W/home" XDG_CONFIG_HOME="$W/home/.config" COPILOT_HOME="$W/home/.copilot" COPILOT_OFFLINE=true \
  COPILOT_PROVIDER_BASE_URL="http://127.0.0.1:$PORT/v1" COPILOT_PROVIDER_TYPE=openai COPILOT_PROVIDER_API_KEY=aegis-vk-copilot \
  COPILOT_PROVIDER_WIRE_API=completions COPILOT_MODEL=copilot-test NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost \
  timeout 180 "$COP" --allow-all-tools --allow-all-paths -p "$PROMPT" < /dev/null > "$W/out" 2>&1 || true
check_chat "$W/out" Copilot bash
echo "CLIENT OK"

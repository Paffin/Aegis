#!/usr/bin/env bash
# REQ: QA-14, PRO-16, RSP-07, INV-6
# Real-client check: Mistral Vibe (`vibe -p`; provider with api_style openai in config.toml) talks to Aegis
# over Chat Completions, Aegis talks to a mock provider. Vibe is taken from PATH or installed with pip into a
# temporary virtual environment. Skips without Vibe.
source "$(dirname "$0")/lib-client.sh"
VIBE=$(command -v vibe || true)
if [ -z "$VIBE" ]; then
  T=$(mktemp -d)
  { python3 -m venv "$T/venv" && "$T/venv/bin/pip" install -q mistral-vibe; } >/dev/null 2>&1 || { echo "skip: vibe is not installed and pip cannot fetch it"; exit 0; }
  VIBE="$T/venv/bin/vibe"
fi
start_stack vibe bash
mkdir -p "$W/home/.vibe"
cat > "$W/home/.vibe/config.toml" <<TOML
active_model = "aegis-test"

[[providers]]
name = "aegis"
api_base = "http://127.0.0.1:$PORT/v1"
api_key_env_var = "AEGIS_VIBE_KEY"
api_style = "openai"
backend = "generic"

[[models]]
name = "vibe-test"
provider = "aegis"
alias = "aegis-test"
temperature = 0.2
input_price = 0.0
output_price = 0.0
TOML
cd "$W/work"
HOME="$W/home" VIBE_HOME="$W/home/.vibe" AEGIS_VIBE_KEY=aegis-vk-vibe MISTRAL_API_KEY=unused NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost \
  timeout 180 "$VIBE" --trust --auto-approve -p "$PROMPT" < /dev/null > "$W/out" 2>&1 || true
check_chat "$W/out" Vibe bash
echo "CLIENT OK"

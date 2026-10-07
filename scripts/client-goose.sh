#!/usr/bin/env bash
# REQ: QA-14, PRO-16, RSP-07, INV-6
# Real-client check: Goose (`goose run`, provider `openai` with OPENAI_HOST) talks to Aegis over Chat
# Completions, Aegis talks to a mock provider. Goose is taken from PATH or downloaded as a release archive
# (Linux) into a temporary directory. Skips without Goose.
source "$(dirname "$0")/lib-client.sh"
GOOSE=$(command -v goose || true)
if [ -z "$GOOSE" ]; then
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) T=goose-x86_64-unknown-linux-gnu ;;
    Linux-aarch64) T=goose-aarch64-unknown-linux-gnu ;;
    Darwin-arm64) T=goose-aarch64-apple-darwin ;;
    *) echo "skip: goose is not installed and no release for this platform"; exit 0 ;;
  esac
  D=$(mktemp -d)
  { curl -fsSL -m 300 -o "$D/g.tar.bz2" "https://github.com/aaif-goose/goose/releases/latest/download/$T.tar.bz2" && tar -xjf "$D/g.tar.bz2" -C "$D"; } >/dev/null 2>&1 \
    || { echo "skip: goose is not installed and the release cannot be fetched"; exit 0; }
  GOOSE=$(find "$D" -name goose -type f | head -1)
  [ -n "$GOOSE" ] || { echo "skip: goose not found in the archive"; exit 0; }
fi
start_stack goose shell
cd "$W/work"
HOME="$W/home" XDG_CONFIG_HOME="$W/home/.config" XDG_DATA_HOME="$W/home/.local/share" XDG_STATE_HOME="$W/home/.local/state" \
  GOOSE_PROVIDER=openai OPENAI_HOST="http://127.0.0.1:$PORT" OPENAI_BASE_PATH=v1/chat/completions OPENAI_API_KEY=aegis-vk-goose \
  GOOSE_MODEL=goose-test GOOSE_MODE=auto GOOSE_DISABLE_KEYRING=1 NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost \
  timeout 180 "$GOOSE" run --with-builtin developer -t "$PROMPT" < /dev/null > "$W/out" 2>&1 || true
check_chat "$W/out" Goose shell
echo "CLIENT OK"

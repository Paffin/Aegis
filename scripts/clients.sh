#!/usr/bin/env bash
# All real-client checks in turn: Claude Code, Codex, Qwen Code, Gemini CLI against Aegis and a mock provider.
# A client that is not installed (and cannot be fetched with npm) is skipped, not failed.
set -uo pipefail
cd "$(dirname "$0")"
fail=0
for s in client-claude.sh client-codex.sh client-qwen.sh client-gemini.sh; do
  echo "== $s"
  ./"$s" || { echo "FAILED: $s"; fail=1; }
done
exit $fail

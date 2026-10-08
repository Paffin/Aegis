#!/usr/bin/env bash
# All real-client checks in turn: Claude Code, Codex, Qwen Code, Gemini CLI, OpenCode, Aider, Continue, Cline,
# Hermes Agent, OpenClaw, Crush, Kilo Code, Pi, Goose, GitHub Copilot CLI and Mistral Vibe against Aegis and a
# mock provider.
# A client that is not installed (and cannot be fetched with npm) is skipped, not failed.
set -uo pipefail
cd "$(dirname "$0")"
fail=0
for s in client-claude.sh client-claude-files.sh client-claude-guard.sh client-claude-agg.sh client-codex.sh client-qwen.sh client-gemini.sh client-opencode.sh client-aider.sh client-continue.sh client-cline.sh client-hermes.sh client-openclaw.sh client-crush.sh client-kilo.sh client-pi.sh client-goose.sh client-copilot.sh client-vibe.sh; do
  echo "== $s"
  ./"$s" || { echo "FAILED: $s"; fail=1; }
done
exit $fail

#!/usr/bin/env bash
# REQ: QA-14, QA-06
# Real clients against a REAL provider through Aegis. By default the provider is OpenRouter (it speaks
# Chat Completions, Responses and the Anthropic Messages API), but any HTTPS base works.
#
#   REAL_KEY=sk-or-... bash scripts/client-real.sh hermes openclaw crush      # some clients
#   REAL_KEY=sk-or-... bash scripts/client-real.sh all                        # every client below
#
# Environment: REAL_KEY (required; never written to a file or printed), REAL_BASE (default
# https://openrouter.ai/api), REAL_MODEL (default openai/gpt-4o-mini), REAL_CLAUDE_MODEL (default
# anthropic/claude-haiku-4.5), AEGIS_CLIENT_CACHE (where clients are installed).
#
# A thin tap (scripts/real_tap.py) sits between Aegis and the provider and records what the provider
# really received. Hard checks: every answer 200, the provider key was the one Aegis holds, no real value
# (host, password) in any request the provider got, none in Aegis's audit or log. Soft (reported, not
# failed): the model used the command tool, the real host came back to the client.
set -uo pipefail
cd "$(dirname "$0")/.."
: "${REAL_KEY:?set REAL_KEY}"
REAL_BASE=${REAL_BASE:-https://openrouter.ai/api}
M=${REAL_MODEL:-openai/gpt-4o-mini}
CM=${REAL_CLAUDE_MODEL:-anthropic/claude-haiku-4.5}
CACHE=${AEGIS_CLIENT_CACHE:-${TMPDIR:-/tmp}/aegis-clients}
ALL="claude codex qwen opencode aider continue cline hermes openclaw crush kilo pi goose copilot vibe"
PROMPT='Не подключается к prod-db01.corp.local, password=Jd8!2jd82k. Выполни одну команду echo CHECK prod-db01.corp.local и ответь одной строкой, что она вывела.'
if [ "${REAL_SCENARIO:-command}" = files ]; then
  PROMPT='Прочитай файл config.env и добавь в его конец строку "# rotated 2026". Ничего другого в файле не меняй. Ответь одним словом: готово.'
fi
mkdir -p "$CACHE"
cargo build -q --release -p aegis-gateway || exit 1

npm_bin() { # <dir> <package> <bin>
  [ -x "$CACHE/$1/node_modules/.bin/$3" ] || npm install --silent --prefix "$CACHE/$1" "$2" >/dev/null 2>&1
  [ -x "$CACHE/$1/node_modules/.bin/$3" ] && echo "$CACHE/$1/node_modules/.bin/$3"
}
pip_bin() { # <dir> <package> <bin>
  [ -x "$CACHE/$1/bin/$3" ] || { python3 -m venv "$CACHE/$1" && "$CACHE/$1/bin/pip" install -q "$2"; } >/dev/null 2>&1
  [ -x "$CACHE/$1/bin/$3" ] && echo "$CACHE/$1/bin/$3"
}
bin_of() {
  case $1 in
    claude) command -v claude ;;
    codex) command -v codex || npm_bin codex @openai/codex codex ;;
    qwen) command -v qwen || npm_bin qwen @qwen-code/qwen-code qwen ;;
    opencode) command -v opencode || npm_bin opencode opencode-ai opencode ;;
    cline) command -v cline || { [ -f "$CACHE/cline/node_modules/cline/bin/cline" ] || npm install --silent --prefix "$CACHE/cline" cline >/dev/null 2>&1; echo "$CACHE/cline/node_modules/cline/bin/cline"; } ;;
    continue) command -v cn || npm_bin continue @continuedev/cli cn ;;
    aider) command -v aider || echo "$HOME/.local/bin/aider" ;;
    hermes) command -v hermes || pip_bin hermes hermes-agent hermes ;;
    openclaw) command -v openclaw || npm_bin openclaw openclaw openclaw ;;
    crush) command -v crush || npm_bin crush @charmland/crush crush ;;
    kilo) command -v kilo || npm_bin kilo @kilocode/cli kilo ;;
    pi) command -v pi || npm_bin pi @mariozechner/pi-coding-agent pi ;;
    copilot) command -v copilot || npm_bin copilot @github/copilot copilot ;;
    vibe) command -v vibe || pip_bin vibe mistral-vibe vibe ;;
    goose)
      command -v goose && return
      [ -x "$CACHE/goose/goose" ] || {
        mkdir -p "$CACHE/goose"
        case "$(uname -s)-$(uname -m)" in
          Linux-x86_64) t=goose-x86_64-unknown-linux-gnu ;; Linux-aarch64) t=goose-aarch64-unknown-linux-gnu ;;
          Darwin-arm64) t=goose-aarch64-apple-darwin ;; *) return ;;
        esac
        curl -fsSL -m 300 -o "$CACHE/goose/g.tar.bz2" "https://github.com/aaif-goose/goose/releases/latest/download/$t.tar.bz2" \
          && tar -xjf "$CACHE/goose/g.tar.bz2" -C "$CACHE/goose" >/dev/null 2>&1
      }
      [ -x "$CACHE/goose/goose" ] && echo "$CACHE/goose/goose" ;;
  esac
}

run_one() {
  local c=$1 B
  B=$(bin_of "$c" 2>/dev/null | head -1)
  if [ -z "$B" ] || [ ! -e "$B" ]; then echo "SKIP $c: not installed and cannot be fetched"; return 0; fi
  local W; W=$(mktemp -d)
  local TAPP=$((20000 + RANDOM % 20000)) PORT ADMIN
  PORT=$((TAPP + 1)); ADMIN=$((TAPP + 2))
  : > "$W/tap.log"; mkdir -p "$W/home" "$W/work"
  TAP_KEY=$REAL_KEY python3 scripts/real_tap.py "$TAPP" "$W/tap.log" "$REAL_BASE" & local TP=$!
  local hash; hash=$(printf %s aegis-vk-real | sha256sum | cut -d' ' -f1)
  cat > "$W/gw.json" <<JSON
{"listen":"127.0.0.1:$PORT","admin_listen":"127.0.0.1:$ADMIN","openai_base_url":"http://127.0.0.1:$TAPP",
 "anthropic_base_url":"http://127.0.0.1:$TAPP","anthropic_auth":"bearer",
 "internal_zones":["corp.local"],"audit_path":"$W/audit.jsonl","virtual_keys":[{"sha256":"$hash","principal":"u:real"}]}
JSON
  AEGIS_K_TENANT=0123456789abcdef0123456789abcdef AEGIS_K_AUDIT=fedcba9876543210fedcba9876543210 \
    AEGIS_OPENAI_KEY=$REAL_KEY AEGIS_ANTHROPIC_KEY=$REAL_KEY target/release/aegis-gateway "$W/gw.json" > "$W/gw.log" 2>&1 & local GP=$!
  for _ in $(seq 1 50); do curl -sf "http://127.0.0.1:$ADMIN/readyz" >/dev/null 2>&1 && break; sleep 0.1; done
  local NP=127.0.0.1,localhost V=aegis-vk-real U="http://127.0.0.1:$PORT"
  cd "$W/work"
  if [ "${REAL_SCENARIO:-command}" = files ]; then printf 'DB_HOST=prod-db01.corp.local\nDB_PASSWORD=Jd8!2jd82k\nDB_USER=svc_payment\n' > config.env; fi
  case $c in
    claude)
      HOME=$W/home CLAUDE_CONFIG_DIR=$W/home/.claude NO_PROXY=$NP no_proxy=$NP ANTHROPIC_BASE_URL=$U ANTHROPIC_API_KEY=$V DISABLE_AUTOUPDATER=1 \
        ANTHROPIC_SMALL_FAST_MODEL=$CM ANTHROPIC_DEFAULT_HAIKU_MODEL=$CM \
        timeout 180 "$B" --bare -p "$PROMPT" --model "$CM" --allowedTools Bash --output-format json < /dev/null > "$W/out" 2>&1 ;;
    codex)
      CODEX_HOME=$W/home HOME=$W/home AEGIS_API_KEY=$V NO_PROXY=$NP no_proxy=$NP timeout 180 "$B" exec --skip-git-repo-check -s workspace-write \
        -c model_provider=aegis -c "model_providers.aegis={name=\"Aegis\",base_url=\"$U/v1\",env_key=\"AEGIS_API_KEY\",wire_api=\"responses\"}" \
        -c "model=$M" -c web_search=disabled "$PROMPT" < /dev/null > "$W/out" 2>&1 ;;
    qwen)
      HOME=$W/home OPENAI_API_KEY=$V OPENAI_BASE_URL=$U/v1 OPENAI_MODEL=$M NO_PROXY=$NP no_proxy=$NP QWEN_CODE_SUPPRESS_YOLO_WARNING=1 \
        timeout 180 "$B" --auth-type openai --yolo -p "$PROMPT" < /dev/null > "$W/out" 2>&1 ;;
    opencode|kilo)
      cat > "$W/work/opencode.json" <<JSON
{"\$schema":"https://opencode.ai/config.json","provider":{"aegis":{"npm":"@ai-sdk/openai-compatible","name":"Aegis","options":{"baseURL":"$U/v1","apiKey":"$V"},"models":{"$M":{"name":"m","tool_call":true}}}},
 "permission":{"bash":"allow","edit":"allow","webfetch":"allow","read":"allow","external_directory":"allow"},"autoupdate":false,"share":"disabled"}
JSON
      cp "$W/work/opencode.json" "$W/work/kilo.json"
      HOME=$W/home XDG_CONFIG_HOME=$W/home/.config XDG_DATA_HOME=$W/home/.local/share XDG_CACHE_HOME=$W/home/.cache NO_PROXY=$NP no_proxy=$NP \
        timeout 180 "$B" run $([ "$c" = kilo ] && echo --auto) -m "aegis/$M" "$PROMPT" < /dev/null > "$W/out" 2>&1 ;;
    aider)
      HOME=$W/home OPENAI_API_BASE=$U/v1 OPENAI_API_KEY=$V NO_PROXY=$NP no_proxy=$NP AIDER_ANALYTICS_DISABLE=1 timeout 180 "$B" --model "openai/$M" \
        --no-git --yes-always --no-show-model-warnings --no-check-update --no-analytics --no-gitignore --map-tokens 0 --message "$PROMPT" $([ "${REAL_SCENARIO:-command}" = files ] && echo config.env) < /dev/null > "$W/out" 2>&1 ;;
    continue)
      mkdir -p "$W/home/.continue"
      cat > "$W/home/.continue/config.yaml" <<YAML
name: aegis-real
version: 1.0.0
schema: v1
models:
  - name: real
    provider: openai
    model: $M
    apiBase: $U/v1
    apiKey: $V
    roles: [chat]
YAML
      HOME=$W/home NO_PROXY=$NP no_proxy=$NP CONTINUE_GLOBAL_DIR=$W/home/.continue timeout 180 "$B" -p --config "$W/home/.continue/config.yaml" --auto "$PROMPT" < /dev/null > "$W/out" 2>&1 ;;
    cline)
      export HOME=$W/home NO_PROXY=$NP no_proxy=$NP
      CL=("$B"); [ -x "$B" ] || CL=(node "$B")
      "${CL[@]}" auth openai -k $V -m "$M" -b "$U/v1" --data-dir "$W/data" > /dev/null 2>&1
      timeout 180 "${CL[@]}" --data-dir "$W/data" -y -P openai -m "$M" -t 150 "$PROMPT" < /dev/null > "$W/out" 2>&1 ;;
    hermes)
      mkdir -p "$W/home/.hermes"
      printf 'model:\n  provider: custom\n  default: %s\n  base_url: %s/v1\n  api_key: %s\n  context_length: 128000\n' "$M" "$U" "$V" > "$W/home/.hermes/config.yaml"
      HOME=$W/home HERMES_HOME=$W/home/.hermes NO_PROXY=$NP no_proxy=$NP timeout 180 "$B" -z "$PROMPT" --yolo < /dev/null > "$W/out" 2>&1 ;;
    openclaw)
      mkdir -p "$W/home/.openclaw"
      cat > "$W/home/.openclaw/openclaw.json" <<JSON
{"models":{"providers":{"aegis":{"baseUrl":"$U/v1","apiKey":"$V","api":"openai-completions","models":[{"id":"$M","name":"m","reasoning":false,"input":["text"],"contextWindow":128000,"maxTokens":4096}]}}},
 "agents":{"defaults":{"model":{"primary":"aegis/$M"},"models":{"aegis/$M":{}}}}}
JSON
      HOME=$W/home NO_PROXY=$NP no_proxy=$NP timeout 180 "$B" agent --local --agent main --timeout 150 --message "$PROMPT" < /dev/null > "$W/out" 2>&1 ;;
    crush)
      mkdir -p "$W/home/.config/crush"
      cat > "$W/home/.config/crush/crush.json" <<JSON
{"providers":{"aegis":{"type":"openai-compat","name":"Aegis","base_url":"$U/v1","api_key":"$V","models":[{"id":"$M","name":"m","context_window":128000,"default_max_tokens":4096}]}},
 "models":{"large":{"provider":"aegis","model":"$M"},"small":{"provider":"aegis","model":"$M"}},"options":{"disable_provider_auto_update":true,"disable_metrics":true}}
JSON
      HOME=$W/home XDG_CONFIG_HOME=$W/home/.config XDG_DATA_HOME=$W/home/.local/share NO_PROXY=$NP no_proxy=$NP timeout 180 "$B" run -q -D "$W/data" "$PROMPT" < /dev/null > "$W/out" 2>&1 ;;
    pi)
      mkdir -p "$W/home/.pi/agent"
      cat > "$W/home/.pi/agent/models.json" <<JSON
{"providers":{"aegis":{"baseUrl":"$U/v1","api":"openai-completions","apiKey":"$V","models":[{"id":"$M","name":"m","reasoning":false,"input":["text"],"contextWindow":128000,"maxTokens":4096}]}}}
JSON
      HOME=$W/home PI_CODING_AGENT_DIR=$W/home/.pi/agent NO_PROXY=$NP no_proxy=$NP timeout 180 "$B" --provider aegis --model "$M" -p "$PROMPT" < /dev/null > "$W/out" 2>&1 ;;
    goose)
      HOME=$W/home XDG_CONFIG_HOME=$W/home/.config XDG_DATA_HOME=$W/home/.local/share XDG_STATE_HOME=$W/home/.local/state GOOSE_PROVIDER=openai \
        OPENAI_HOST=$U OPENAI_BASE_PATH=v1/chat/completions OPENAI_API_KEY=$V GOOSE_MODEL=$M GOOSE_MODE=auto GOOSE_DISABLE_KEYRING=1 NO_PROXY=$NP no_proxy=$NP \
        timeout 180 "$B" run --with-builtin developer -t "$PROMPT" < /dev/null > "$W/out" 2>&1 ;;
    copilot)
      HOME=$W/home XDG_CONFIG_HOME=$W/home/.config COPILOT_HOME=$W/home/.copilot COPILOT_OFFLINE=true COPILOT_PROVIDER_BASE_URL=$U/v1 COPILOT_PROVIDER_TYPE=openai \
        COPILOT_PROVIDER_API_KEY=$V COPILOT_PROVIDER_WIRE_API=completions COPILOT_MODEL=$M NO_PROXY=$NP no_proxy=$NP \
        timeout 180 "$B" --allow-all-tools --allow-all-paths -p "$PROMPT" < /dev/null > "$W/out" 2>&1 ;;
    vibe)
      mkdir -p "$W/home/.vibe"
      cat > "$W/home/.vibe/config.toml" <<TOML
active_model = "real"

[[providers]]
name = "aegis"
api_base = "$U/v1"
api_key_env_var = "AEGIS_VIBE_KEY"
api_style = "openai"
backend = "generic"

[[models]]
name = "$M"
provider = "aegis"
alias = "real"
temperature = 0.2
input_price = 0.0
output_price = 0.0
TOML
      HOME=$W/home VIBE_HOME=$W/home/.vibe AEGIS_VIBE_KEY=$V MISTRAL_API_KEY=unused NO_PROXY=$NP no_proxy=$NP timeout 180 "$B" --trust --auto-approve -p "$PROMPT" < /dev/null > "$W/out" 2>&1 ;;
  esac
  local rc=$?
  cd - >/dev/null
  kill $GP $TP 2>/dev/null; wait $GP $TP 2>/dev/null
  python3 - "$c" "$W" "$rc" "${REAL_SCENARIO:-command}" <<'PY'
import json, re, sys
c, w, rc, scenario = sys.argv[1:5]
rows = [json.loads(l) for l in open(f"{w}/tap.log") if l.strip()]
out = open(f"{w}/out", errors="replace").read()
audit = ""
for f in ("audit.jsonl", "gw.log"):
    try: audit += open(f"{w}/{f}").read()
    except OSError: pass
problems, notes = [], []
posts = [r for r in rows if r["method"] == "POST"]
if not posts: problems.append("the provider received no request")
bad = [r for r in rows if r["status"] != 200]
for r in bad[:2]: problems.append(f"provider answered {r['status']} to {r['path']}: {r.get('answer','')[:200]!r}")
if posts and not all(r["key_ok"] for r in posts): problems.append("the provider did not get the key Aegis holds")
bodies = " ".join(r["body"] for r in rows)
for v in ("prod-db01", "Jd8!2jd82k", "Jd8"): 
    if v in bodies: problems.append(f"REAL VALUE {v!r} REACHED THE PROVIDER")
for v in ("prod-db01", "Jd8!2jd82k"):
    if v in audit: problems.append(f"real value {v!r} in audit or log")
if scenario == "files":
    try:
        f = open(f"{w}/work/config.env").read()
    except OSError:
        f = ""; problems.append("config.env is gone")
    if f:
        if "[[" in f or "aegis.invalid" in f: problems.append("A MARKER OR PSEUDONYM REACHED THE DISK: " + f.replace("\n", " | ")[:200])
        elif "DB_PASSWORD=Jd8!2jd82k" not in f or "DB_HOST=prod-db01.corp.local" not in f:
            # a weak model sometimes writes only the new line over the whole file: its doing, not a leak
            notes.append("the model replaced the file's content (" + f.replace("\n", " | ")[:40] + ")")
        notes.append("file edited" if "rotated" in f else "file NOT edited")
tool_turn = any(re.search(r'"role":\s*"tool"|tool_result|function_call_output|"role":\s*"function"', r["body"]) for r in posts)
notes.append("tool used" if tool_turn else "no tool turn")
if "[Aegis]" in out: notes.append("AEGIS REFUSED A CALL: " + re.sub(r"\s+", " ", out[out.index("[Aegis]"):][:170]))
notes.append("real host back at the client" if "prod-db01.corp.local" in out else "real host not seen in client output")
if "aegis.invalid" in out or "[[SECRET_" in out: notes.append("PSEUDONYM VISIBLE TO THE USER")
answer = re.sub(r"\s+", " ", out.strip())[-160:]
print(("FAIL " if problems else "ok   ") + f"{c}: {len(posts)} requests; " + "; ".join(notes))
for p in problems: print("     !! " + p)
print("     answer: ..." + answer)
sys.exit(1 if problems else 0)
PY
  local st=$?
  if [ -n "${REAL_KEEP:-}" ]; then echo "     kept: $W"; else rm -rf "$W"; fi
  return $st
}

args=("$@"); [ "${args[0]:-all}" = all ] && args=($ALL)
fail=0
for c in "${args[@]}"; do run_one "$c" || fail=1; done
exit $fail

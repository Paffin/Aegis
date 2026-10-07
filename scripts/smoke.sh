#!/usr/bin/env bash
# End-to-end smoke test with the real binaries: aegis CLI -> signed bundle -> aegis-gateway -> mock provider.
# Checks: the bundle supplies policy and virtual keys, a provider never sees real values,
# a new bundle (key revoked) takes effect without a restart, a corrupt bundle changes nothing,
# and the audit file holds no values.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p aegis-cli -p aegis-gateway
BIN=target/debug
W=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"' EXIT
PORT=$((20000 + RANDOM % 20000)); ADMIN=$((PORT + 1)); UP=$((PORT + 2))

cat > "$W/policy.yaml" <<'YAML'
version: 1
tenant: smoke
zones: { internal: [corp.local] }
rules:
  - id: R-112
    when: { sink: [shell_network, network] }
    restore: { SECRET: deny, INFRA: internal_only }
YAML
cat > "$W/tests.yaml" <<'YAML'
ingress:
  - text: "host prod-db01.corp.local password=Jd8@2jd82k"
    expect:
      - { contains: "prod-db01.corp.local", type: HOST, action: mask }
      - { contains: "Jd8@2jd82k", type: SECRET, action: mask }
YAML

$BIN/aegis keys generate --out "$W/sign.key" > "$W/keys.txt"
PUB=$(sed -n 's/^public key: //p' "$W/keys.txt")
KEY1=$($BIN/aegis vkey issue --principal u:one --file "$W/vkeys.json" 2>/dev/null)
KEY2=$($BIN/aegis vkey issue --principal u:two --file "$W/vkeys.json" 2>/dev/null)
$BIN/aegis bundle build --policy "$W/policy.yaml" --tests "$W/tests.yaml" --key "$W/sign.key" \
  --version v1 --vkeys "$W/vkeys.json" -o "$W/bundle.json" 2>/dev/null
$BIN/aegis bundle verify "$W/bundle.json" --trusted "$PUB" >/dev/null

# mock provider: records every request body, answers with a fixed Anthropic message
python3 - "$UP" "$W/provider.log" <<'PY' &
import sys, http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('content-length', 0)))
        open(sys.argv[2], 'ab').write(body + b"\n")
        out = json.dumps({"type":"message","role":"assistant","stop_reason":"end_turn","content":[{"type":"text","text":"ok"}]}).encode()
        self.send_response(200); self.send_header('content-type','application/json'); self.send_header('content-length', str(len(out))); self.end_headers(); self.wfile.write(out)
    def log_message(self, *a): pass
http.server.HTTPServer(('127.0.0.1', int(sys.argv[1])), H).serve_forever()
PY

cat > "$W/gw.json" <<JSON
{"listen":"127.0.0.1:$PORT","admin_listen":"127.0.0.1:$ADMIN","upstream_base_url":"http://127.0.0.1:$UP",
 "audit_path":"$W/audit.jsonl",
 "bundle":{"source":"$W/bundle.json","cache_path":"$W/cache.json","trusted_keys":["$PUB"],"reload_seconds":1}}
JSON
export AEGIS_K_TENANT=0123456789abcdef0123456789abcdef AEGIS_K_AUDIT=fedcba9876543210fedcba9876543210 AEGIS_PROVIDER_KEY=pk
$BIN/aegis-gateway "$W/gw.json" > "$W/gw.log" 2>&1 &
sleep 1.5

req() { curl -s -m 5 -o /dev/null -w '%{http_code}' -X POST -H "x-api-key: $1" "http://127.0.0.1:$PORT/v1/messages" \
  -d '{"model":"m","messages":[{"role":"user","content":"host prod-db01.corp.local password=Jd8@2jd82k"}]}'; }
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: expected $3, got $2"; exit 1; fi; }

check "readyz with a valid bundle"                 "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$ADMIN/readyz)" 200
check "key from the bundle is accepted"            "$(req "$KEY1")" 200
check "key from the bundle is accepted (u:two)"    "$(req "$KEY2")" 200
check "unknown key is refused"                     "$(req nope)" 401
if grep -q -e 'Jd8@2jd82k' -e 'prod-db01' "$W/provider.log"; then echo "FAIL provider saw real values"; exit 1; else echo "ok   provider saw no real values"; fi

# revoke u:two, publish a new bundle: applied within the reload interval, no restart
$BIN/aegis vkey revoke --principal u:two --file "$W/vkeys.json" 2>/dev/null
$BIN/aegis bundle build --policy "$W/policy.yaml" --tests "$W/tests.yaml" --key "$W/sign.key" \
  --version v2 --vkeys "$W/vkeys.json" -o "$W/bundle.tmp" 2>/dev/null && mv "$W/bundle.tmp" "$W/bundle.json"
sleep 2.5
check "revoked key is refused after reload"        "$(req "$KEY2")" 401
check "other key still works"                      "$(req "$KEY1")" 200
curl -s http://127.0.0.1:$ADMIN/metrics | grep -q 'aegis_bundle_info{.*version="v2"' && echo "ok   metrics show bundle v2" || { echo "FAIL metrics"; exit 1; }

# corrupt bundle: nothing changes, error is counted
echo corrupt > "$W/bundle.json"; sleep 2.5
check "gateway keeps serving after a corrupt bundle" "$(req "$KEY1")" 200
curl -s http://127.0.0.1:$ADMIN/metrics | grep -q 'aegis_bundle_errors_total' && echo "ok   bundle error is counted" || { echo "FAIL error metric"; exit 1; }

# audit and logs hold no values
sleep 0.5
if grep -q -e 'Jd8@2jd82k' -e 'prod-db01' "$W/audit.jsonl" "$W/gw.log"; then echo "FAIL values in audit or logs"; exit 1; else echo "ok   audit and logs hold no values"; fi
test -s "$W/audit.jsonl" && echo "ok   audit has $(wc -l < "$W/audit.jsonl") events"
echo "SMOKE OK"

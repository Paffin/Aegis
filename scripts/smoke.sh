#!/usr/bin/env bash
# REQ: NFR-06, NFR-09, CFG-02, SEC-01, SEC-05
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
        if b'"stream":true' in body.replace(b' ', b''):
            # slow SSE: 6 text deltas, half a second apart
            import time
            self.send_response(200); self.send_header('content-type','text/event-stream'); self.end_headers()
            ev = lambda n, d: (f"event: {n}\ndata: {json.dumps(d)}\n\n").encode()
            self.wfile.write(ev('message_start', {"type":"message_start","message":{"id":"m","role":"assistant","content":[]}}))
            self.wfile.write(ev('content_block_start', {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}))
            for i in range(6):
                self.wfile.write(ev('content_block_delta', {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":f"part{i} "}})); self.wfile.flush(); time.sleep(0.5)
            self.wfile.write(ev('content_block_stop', {"type":"content_block_stop","index":0}))
            self.wfile.write(ev('message_stop', {"type":"message_stop"})); self.wfile.flush()
            return
        out = json.dumps({"type":"message","role":"assistant","stop_reason":"end_turn","content":[{"type":"text","text":"ok"}]}).encode()
        self.send_response(200); self.send_header('content-type','application/json'); self.send_header('content-length', str(len(out))); self.end_headers(); self.wfile.write(out)
    def log_message(self, *a): pass
http.server.HTTPServer(('127.0.0.1', int(sys.argv[1])), H).serve_forever()
PY

cat > "$W/gw.json" <<JSON
{"listen":"127.0.0.1:$PORT","admin_listen":"127.0.0.1:$ADMIN","anthropic_base_url":"http://127.0.0.1:$UP",
 "audit_path":"$W/audit.jsonl",
 "bundle":{"source":"$W/bundle.json","cache_path":"$W/cache.json","trusted_keys":["$PUB"],"reload_seconds":1}}
JSON
export AEGIS_K_TENANT=0123456789abcdef0123456789abcdef AEGIS_K_AUDIT=fedcba9876543210fedcba9876543210 AEGIS_ANTHROPIC_KEY=pk
if $BIN/aegis-gateway check "$W/gw.json" > "$W/check.log" 2>&1 && ! grep -q "0123456789abcdef\|fedcba9876543210" "$W/check.log"; then echo "ok   aegis-gateway check passes and prints no key"; else echo "FAIL aegis-gateway check"; cat "$W/check.log"; exit 1; fi
$BIN/aegis-gateway "$W/gw.json" > "$W/gw.log" 2>&1 &
GW=$!
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
# graceful stop: SIGTERM while a stream is in flight must not cut it (NFR-06)
curl -s -N -m 20 -X POST -H "x-api-key: $KEY1" "http://127.0.0.1:$PORT/v1/messages" \
  -d '{"model":"m","stream":true,"messages":[{"role":"user","content":"hi"}]}' > "$W/stream.out" &
CURL=$!
sleep 1.2; kill -TERM $GW
wait $CURL || true
if grep -q 'part5' "$W/stream.out" && grep -q 'message_stop' "$W/stream.out"; then echo "ok   in-flight stream completed after SIGTERM"; else echo "FAIL stream was cut: $(tr '\n' ' ' < "$W/stream.out" | head -c 300)"; exit 1; fi
for i in $(seq 1 30); do kill -0 $GW 2>/dev/null || break; sleep 0.1; done
if kill -0 $GW 2>/dev/null; then echo "FAIL gateway still running after the stream ended"; exit 1; else echo "ok   gateway exited after the stream finished"; fi

# TLS and mTLS on the main port (SEC-05), with the real binary and certificates made by openssl
T=$((PORT + 10))
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/ca.key" -out "$W/ca.pem" -subj "/CN=smoke-ca" -days 2 >/dev/null 2>&1
mkleaf() { # name
  openssl req -newkey rsa:2048 -nodes -keyout "$W/$1.key" -out "$W/$1.csr" -subj "/CN=$1" >/dev/null 2>&1
  printf 'subjectAltName=IP:127.0.0.1\n' > "$W/$1.ext"
  openssl x509 -req -in "$W/$1.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -CAcreateserial -out "$W/$1.pem" -days 2 -extfile "$W/$1.ext" >/dev/null 2>&1
}
mkleaf server; mkleaf client
cat > "$W/gw-tls.json" <<JSON
{"listen":"127.0.0.1:$T","admin_listen":"127.0.0.1:$((T + 1))","anthropic_base_url":"http://127.0.0.1:$UP",
 "virtual_keys":[{"sha256":"$(printf %s tlskey | sha256sum | cut -d' ' -f1)","principal":"u:tls"}],
 "tls":{"cert_file":"$W/server.pem","key_file":"$W/server.key","client_ca_file":"$W/ca.pem"}}
JSON
if ! $BIN/aegis-gateway check "$W/gw-tls.json" > "$W/check-tls.log" 2>&1; then echo "FAIL check with tls"; cat "$W/check-tls.log"; exit 1; fi
grep -q "mTLS" "$W/check-tls.log" && echo "ok   check sees TLS and mTLS"
$BIN/aegis-gateway "$W/gw-tls.json" > "$W/gw-tls.log" 2>&1 &
GT=$!
sleep 1.5
tls_req() { curl -s -m 5 -o /dev/null -w '%{http_code}' "$@" -X POST -H "x-api-key: tlskey" "https://127.0.0.1:$T/v1/messages" \
  -d '{"model":"m","messages":[{"role":"user","content":"hi"}]}'; }
check "mTLS: a client with a certificate is served"      "$(tls_req --cacert "$W/ca.pem" --cert "$W/client.pem" --key "$W/client.key")" 200
check "mTLS: a client without a certificate is refused"  "$(tls_req --cacert "$W/ca.pem" || true)" 000
check "TLS: an unknown CA is refused"                    "$(tls_req --cert "$W/client.pem" --key "$W/client.key" || true)" 000
kill $GT 2>/dev/null || true
echo "SMOKE OK"

"""Transparent tap between Aegis and a real provider, for scripts/client-real.sh.

Forwards every request unchanged to UPSTREAM (HTTPS) and streams the answer back. Appends one JSON line per
request to LOG: method, path, request body, the status the provider answered and, for errors, the start of
its answer. The key the provider receives is never written: only whether it equals the key in TAP_KEY.
Usage: real_tap.py PORT LOG UPSTREAM   (TAP_KEY in the environment; TAP_RESPONSES=1 also records the
answer's chunks, to replay a failure exactly)
"""
import http.server, json, os, sys, urllib.request, urllib.error

PORT, LOG, UPSTREAM = int(sys.argv[1]), sys.argv[2], sys.argv[3].rstrip("/")
KEY = os.environ.get("TAP_KEY", "")
DROP = {"host", "content-length", "transfer-encoding", "connection", "accept-encoding"}


class H(http.server.BaseHTTPRequestHandler):
    def handle_any(self):
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(n) if n else b""
        auth = self.headers.get("authorization", "")
        key_ok = bool(KEY) and (auth == f"Bearer {KEY}" or self.headers.get("x-api-key") == KEY)
        req = urllib.request.Request(UPSTREAM + self.path, data=body if self.command != "GET" else None, method=self.command)
        for k, v in self.headers.items():
            if k.lower() not in DROP:
                req.add_header(k, v)
        rec = {"method": self.command, "path": self.path, "body": body.decode("utf-8", "replace"), "key_ok": key_ok}
        try:
            resp = urllib.request.urlopen(req, timeout=300)
            status, headers = resp.status, resp.getheaders()
        except urllib.error.HTTPError as e:
            resp, status, headers = e, e.code, list(e.headers.items())
        rec["status"] = status
        self.send_response(status)
        for k, v in headers:
            if k.lower() not in DROP:
                self.send_header(k, v)
        self.send_header("connection", "close")
        self.end_headers()
        first = b""
        chunks = []
        try:
            while True:
                chunk = resp.read1(4096) if hasattr(resp, "read1") else resp.read(4096)
                if not chunk:
                    break
                if len(first) < 600:
                    first += chunk[:600]
                chunks.append(chunk.decode("utf-8", "replace"))
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        if status >= 400:
            rec["answer"] = first.decode("utf-8", "replace")[:600]
        if os.environ.get("TAP_RESPONSES"):
            # what the provider sent, in the pieces it arrived in (it holds pseudonyms, never real values)
            rec["chunks"] = chunks
        with open(LOG, "a") as f:
            f.write(json.dumps(rec) + "\n")

    do_GET = do_POST = do_PUT = do_DELETE = handle_any

    def log_message(self, *a):
        pass


http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()

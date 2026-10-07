//! REQ: MCP-01 — the Streamable HTTP proxy: clients talk to `aegis-mcp` at `/<server>`, it talks
//! to the server's `url`. Answers come back as JSON or as an event stream; both are filtered.

use crate::audit::Audit;
use crate::config::Config;
use crate::filter::Filter;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Response;
use axum::routing::any;
use axum::Router;
use bytes::Bytes;
use futures_util::StreamExt;
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Clone)]
pub struct State_ {
    pub cfg: Arc<Config>,
    pub http: reqwest::Client,
    pub audit: Audit,
}

pub fn app(cfg: Arc<Config>, audit: Audit) -> Router {
    let st = State_ {
        cfg,
        http: reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default(),
        audit,
    };
    Router::new()
        .route("/:server", any(handle))
        .layer(axum::extract::DefaultBodyLimit::max(16 * 1024 * 1024))
        .with_state(st)
}

fn json_response(status: u16, v: &Value) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(v.to_string()))
        .unwrap_or_default()
}

/// Server-sent events: whole events are filtered, the rest is passed untouched.
pub struct Sse {
    buf: Vec<u8>,
}

impl Sse {
    pub fn new() -> Self {
        Self { buf: vec![] }
    }

    /// Feed bytes; get back the bytes of the events that were completed (and not dropped).
    pub fn feed(&mut self, chunk: &[u8], f: &mut dyn FnMut(Value) -> Option<Value>) -> Vec<u8> {
        self.buf.extend_from_slice(chunk);
        let mut out = vec![];
        while let Some((end, sep)) = find_boundary(&self.buf) {
            let event: Vec<u8> = self.buf.drain(..end + sep).collect();
            out.extend(rewrite_event(&event[..end], f));
        }
        out
    }

    /// The end of the stream: whatever is left is one event without the blank line.
    pub fn finish(&mut self, f: &mut dyn FnMut(Value) -> Option<Value>) -> Vec<u8> {
        if self.buf.iter().all(|b| b.is_ascii_whitespace()) {
            return vec![];
        }
        let rest = std::mem::take(&mut self.buf);
        rewrite_event(&rest, f)
    }
}

impl Default for Sse {
    fn default() -> Self {
        Self::new()
    }
}

fn find_boundary(b: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    while i < b.len() {
        if b[i..].starts_with(b"\n\n") {
            return Some((i, 2));
        }
        if b[i..].starts_with(b"\r\n\r\n") {
            return Some((i, 4));
        }
        i += 1;
    }
    None
}

fn rewrite_event(event: &[u8], f: &mut dyn FnMut(Value) -> Option<Value>) -> Vec<u8> {
    let text = String::from_utf8_lossy(event);
    let mut keep = vec![];
    let mut data = vec![];
    for line in text.lines() {
        match line.strip_prefix("data:") {
            Some(d) => data.push(d.strip_prefix(' ').unwrap_or(d).to_string()),
            None => keep.push(line.to_string()),
        }
    }
    if data.is_empty() {
        // comments (keep-alive), ids, retry: nothing to filter
        return format!("{}\n\n", text.trim_end()).into_bytes();
    }
    let joined = data.join("\n");
    let Ok(msg) = serde_json::from_str::<Value>(&joined) else {
        // data that is not JSON is not a message any rule has seen: dropped
        return vec![];
    };
    match f(msg) {
        Some(m) => {
            let mut out = keep.join("\n");
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&format!("data: {m}\n\n"));
            out.into_bytes()
        }
        None => vec![],
    }
}

fn upstream_headers(
    st: &State_,
    server: &crate::config::Server,
    h: &HeaderMap,
) -> Result<reqwest::header::HeaderMap, String> {
    let mut out = reqwest::header::HeaderMap::new();
    for name in [
        "content-type",
        "accept",
        "mcp-session-id",
        "mcp-protocol-version",
        "last-event-id",
    ] {
        if let Some(v) = h.get(name) {
            if let (Ok(n), Ok(v)) = (
                reqwest::header::HeaderName::from_bytes(name.as_bytes()),
                reqwest::header::HeaderValue::from_bytes(v.as_bytes()),
            ) {
                out.insert(n, v);
            }
        }
    }
    let _ = st;
    for (hdr, env) in &server.headers_env {
        let val = std::env::var(env).map_err(|_| format!("переменная {env} не задана"))?;
        out.insert(
            reqwest::header::HeaderName::from_bytes(hdr.as_bytes()).map_err(|e| e.to_string())?,
            reqwest::header::HeaderValue::from_str(&val).map_err(|e| e.to_string())?,
        );
    }
    Ok(out)
}

async fn handle(
    State(st): State<State_>,
    Path(name): Path<String>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(server) = st.cfg.servers.get(&name).cloned() else {
        return json_response(404, &json!({"error": "Aegis: сервер не настроен"}));
    };
    let Some(url) = server.url.clone() else {
        return json_response(404, &json!({"error": "Aegis: для сервера не задан url"}));
    };
    let up_headers = match upstream_headers(&st, &server, &headers) {
        Ok(h) => h,
        Err(e) => return json_response(502, &json!({"error": format!("Aegis: {e}")})),
    };
    let mut filter = Filter::new(server.clone(), st.audit.clone());
    let mut answers: Vec<Value> = vec![];
    let forward_body: Option<Bytes> = if method == Method::POST {
        let Ok(msg) = serde_json::from_slice::<Value>(&body) else {
            return json_response(
                400,
                &json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "Aegis: сообщение не является JSON"}}),
            );
        };
        let batch = msg.is_array();
        let o = filter.client(msg);
        answers = o.answers;
        match o.forward {
            Some(m) => Some(Bytes::from(m.to_string())),
            None => {
                // everything was answered here; the server never saw it
                let v = if batch {
                    Value::Array(answers)
                } else {
                    answers.into_iter().next().unwrap_or(Value::Null)
                };
                return json_response(200, &v);
            }
        }
    } else {
        None
    };
    let m =
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::POST);
    let mut req = st.http.request(m, &url).headers(up_headers);
    if let Some(b) = forward_body {
        req = req.body(b);
    }
    let Ok(up) = req.send().await else {
        return json_response(502, &json!({"error": "Aegis: сервер недоступен"}));
    };
    let status = StatusCode::from_u16(up.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let ct = up
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let session = up.headers().get("mcp-session-id").cloned();
    let mut resp = Response::builder().status(status);
    if let Some(s) = session {
        resp = resp.header("mcp-session-id", s.as_bytes());
    }
    if ct.starts_with("text/event-stream") {
        let filter = Arc::new(std::sync::Mutex::new(filter));
        let mut sse = Sse::new();
        let mut first = answers
            .into_iter()
            .map(|a| format!("data: {a}\n\n").into_bytes())
            .collect::<Vec<_>>();
        let f2 = filter.clone();
        let stream = up.bytes_stream().map(move |c| {
            let mut out: Vec<u8> = first.drain(..).flatten().collect();
            if let Ok(c) = c {
                let mut f = |m: Value| f2.lock().ok().and_then(|mut f| f.server(m));
                out.extend(sse.feed(&c, &mut f));
            }
            Ok::<_, std::io::Error>(Bytes::from(out))
        });
        return resp
            .header("content-type", "text/event-stream")
            .header("cache-control", "no-cache")
            .body(Body::from_stream(stream))
            .unwrap_or_default();
    }
    let Ok(bytes) = up.bytes().await else {
        return json_response(502, &json!({"error": "Aegis: ответ сервера оборван"}));
    };
    if ct.starts_with("application/json") {
        let out = match serde_json::from_slice::<Value>(&bytes) {
            Ok(v) => {
                let mut v = filter.server(v);
                if !answers.is_empty() {
                    let mut all = match v.take() {
                        Some(Value::Array(a)) => a,
                        Some(o) => vec![o],
                        None => vec![],
                    };
                    all.extend(answers);
                    v = Some(Value::Array(all));
                }
                v.map(|v| v.to_string()).unwrap_or_default()
            }
            // a body that is not JSON is not passed on
            Err(_) => String::new(),
        };
        return resp
            .header("content-type", "application/json")
            .body(Body::from(out))
            .unwrap_or_default();
    }
    // 202 for notifications, errors without a body, and the like
    resp.body(Body::from(bytes)).unwrap_or_default()
}

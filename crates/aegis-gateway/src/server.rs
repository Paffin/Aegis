//! REQ: PRO-01, PRO-10, IAM-01, IAM-02, IAM-03, API-01, API-02, API-03, OBS-04, NFR-07, RSP-09.
//!
//! HTTP surface of the gateway: virtual-key authentication, provider key injection,
//! protocol adapters, streaming.

use crate::anthropic::{transform_request, transform_response, ReqMeta};
use crate::engine::Engine;
use crate::stream::StreamTransformer;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::Router;
use bytes::Bytes;
use futures_util::StreamExt;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// NFR-07
pub const MAX_BODY: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Principal {
    pub id: String,
    pub groups: Vec<String>,
}

pub struct Upstream {
    pub base_url: String,
    /// Provider credentials stay inside Aegis (IAM-02).
    pub api_key: String,
}

pub struct AppState {
    pub engine: Engine,
    pub upstream: Upstream,
    /// SHA-256 (hex) of the virtual key → principal (IAM-03: keys are stored as hashes only).
    pub keys: HashMap<String, Principal>,
    pub http: reqwest::Client,
    counter: AtomicU64,
}

impl AppState {
    pub fn new(engine: Engine, upstream: Upstream, keys: HashMap<String, Principal>) -> Self {
        Self {
            engine,
            upstream,
            keys,
            http: reqwest::Client::new(),
            counter: AtomicU64::new(0),
        }
    }

    fn request_id(&self) -> String {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let d = Sha256::digest(format!("{t}:{n}").as_bytes());
        format!(
            "{:x}-{:04x}",
            t / 1_000_000,
            u16::from_be_bytes([d[0], d[1]])
        )
    }
}

pub fn hash_key(key: &str) -> String {
    Sha256::digest(key.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn client_key(h: &HeaderMap) -> Option<String> {
    if let Some(k) = h.get("x-api-key").and_then(|v| v.to_str().ok()) {
        return Some(k.to_string());
    }
    h.get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(String::from)
}

fn err_response(status: u16, kind: &str, message: &str) -> Response {
    let body =
        serde_json::to_vec(&json!({"type": "error", "error": {"type": kind, "message": message}}))
            .unwrap_or_default();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap_or_default()
}

pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/messages", any(messages))
        .route("/v1/messages/count_tokens", any(count_tokens))
        .route("/v1/models", get(models))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(state)
}

/// OBS-04: served on a separate port (SEC-06).
pub fn admin_app() -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(|| async { "ready" }))
}

async fn not_found(uri: Uri) -> Response {
    // PRO-10: unknown endpoints are refused, never proxied blindly.
    err_response(
        404,
        "not_found_error",
        &format!("Aegis: эндпоинт {} не поддерживается", uri.path()),
    )
}

fn upstream_headers(h: &HeaderMap, st: &AppState) -> reqwest::header::HeaderMap {
    let mut out = reqwest::header::HeaderMap::new();
    for name in [
        "anthropic-version",
        "anthropic-beta",
        "content-type",
        "accept",
        "user-agent",
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
    if let Ok(v) = reqwest::header::HeaderValue::from_str(&st.upstream.api_key) {
        out.insert("x-api-key", v);
    }
    out
}

fn authenticate(h: &HeaderMap, st: &AppState) -> Result<Principal, Box<Response>> {
    let deny = |m: &str| Box::new(err_response(401, "authentication_error", m));
    let key = client_key(h).ok_or_else(|| deny("Aegis: требуется виртуальный ключ"))?;
    st.keys
        .get(&hash_key(&key))
        .cloned()
        .ok_or_else(|| deny("Aegis: неверный или отозванный ключ"))
}

fn with_aegis_headers(mut r: Response, request_id: &str, summary: &str) -> Response {
    let h = r.headers_mut();
    if let Ok(v) = HeaderValue::from_str(request_id) {
        h.insert(HeaderName::from_static("x-aegis-request-id"), v);
    }
    if let Ok(v) = HeaderValue::from_str(summary) {
        h.insert(HeaderName::from_static("x-aegis-summary"), v);
    }
    r
}

async fn messages(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if method != Method::POST {
        return err_response(405, "invalid_request_error", "Aegis: ожидается POST");
    }
    let principal = match authenticate(&headers, &st) {
        Ok(p) => p,
        Err(r) => return *r,
    };
    let rid = st.request_id();
    let conv = headers
        .get("x-aegis-conversation")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let t0 = Instant::now();
    let meta = ReqMeta {
        principal: &principal.id,
        conversation: conv.as_deref(),
        request_id: &rid,
    };
    let (new_body, ctx) = match transform_request(&st.engine, &meta, &body) {
        Ok(x) => x,
        Err(rej) => {
            return with_aegis_headers(
                Response::builder()
                    .status(rej.status)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(rej.body()))
                    .unwrap_or_default(),
                &rid,
                "",
            )
        }
    };
    let overhead_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let summary = ctx.stats.summary();
    tracing::info!(request_id = %rid, principal = %principal.id, summary = %summary, blocks = ctx.stats.blocks_total, scanned = ctx.stats.blocks_scanned, overhead_ms, "request transformed");

    let streaming = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("stream").and_then(|s| s.as_bool()))
        .unwrap_or(false);
    let url = format!("{}/v1/messages", st.upstream.base_url.trim_end_matches('/'));
    let up = st
        .http
        .post(url)
        .headers(upstream_headers(&headers, &st))
        .body(new_body)
        .send()
        .await;
    let up = match up {
        Ok(r) => r,
        Err(_) => {
            return with_aegis_headers(
                err_response(502, "api_error", "Aegis: провайдер недоступен"),
                &rid,
                &summary,
            )
        }
    };
    let status = up.status().as_u16();
    let is_sse = up
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/event-stream"));

    if streaming && is_sse && status == 200 {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(32);
        let st2 = st.clone();
        tokio::spawn(async move {
            let mut t = StreamTransformer::new(&st2.engine, ctx);
            let mut s = up.bytes_stream();
            while let Some(chunk) = s.next().await {
                let Ok(chunk) = chunk else { break };
                let out = t.feed(&chunk);
                if !out.is_empty() && tx.send(Ok(Bytes::from(out))).await.is_err() {
                    return;
                }
            }
            let rest = t.finish();
            if !rest.is_empty() {
                let _ = tx.send(Ok(Bytes::from(rest))).await;
            }
        });
        let r = Response::builder()
            .status(200)
            .header(header::CONTENT_TYPE, "text/event-stream")
            .header(header::CACHE_CONTROL, "no-cache")
            .body(Body::from_stream(tokio_stream_from(rx)))
            .unwrap_or_default();
        return with_aegis_headers(r, &rid, &summary);
    }

    let ct = up.headers().get(header::CONTENT_TYPE).cloned();
    let Ok(bytes) = up.bytes().await else {
        return with_aegis_headers(
            err_response(502, "api_error", "Aegis: ответ провайдера оборван"),
            &rid,
            &summary,
        );
    };
    let mut ctx = ctx;
    // RSP-09: non-2xx bodies are provider errors and pass through.
    let out = if status == 200 {
        transform_response(&st.engine, &mut ctx, &bytes)
    } else {
        bytes.to_vec()
    };
    let mut r = Response::builder().status(status);
    if let Some(ct) = ct {
        r = r.header(header::CONTENT_TYPE, ct);
    }
    with_aegis_headers(r.body(Body::from(out)).unwrap_or_default(), &rid, &summary)
}

fn tokio_stream_from(
    mut rx: tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>,
) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> {
    futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx))
}

async fn count_tokens(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let principal = match authenticate(&headers, &st) {
        Ok(p) => p,
        Err(r) => return *r,
    };
    let rid = st.request_id();
    let meta = ReqMeta {
        principal: &principal.id,
        conversation: headers
            .get("x-aegis-conversation")
            .and_then(|v| v.to_str().ok()),
        request_id: &rid,
    };
    let (new_body, ctx) = match transform_request(&st.engine, &meta, &body) {
        Ok(x) => x,
        Err(rej) => {
            return Response::builder()
                .status(rej.status)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(rej.body()))
                .unwrap_or_default()
        }
    };
    let url = format!(
        "{}/v1/messages/count_tokens",
        st.upstream.base_url.trim_end_matches('/')
    );
    match st
        .http
        .post(url)
        .headers(upstream_headers(&headers, &st))
        .body(new_body)
        .send()
        .await
    {
        Ok(r) => {
            let status = r.status().as_u16();
            let bytes = r.bytes().await.unwrap_or_default();
            with_aegis_headers(
                Response::builder()
                    .status(status)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(bytes))
                    .unwrap_or_default(),
                &rid,
                &ctx.stats.summary(),
            )
        }
        Err(_) => err_response(502, "api_error", "Aegis: провайдер недоступен"),
    }
}

async fn models(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = authenticate(&headers, &st) {
        return *r;
    }
    let url = format!("{}/v1/models", st.upstream.base_url.trim_end_matches('/'));
    match st
        .http
        .get(url)
        .headers(upstream_headers(&headers, &st))
        .send()
        .await
    {
        Ok(r) => {
            let status = r.status().as_u16();
            let bytes = r.bytes().await.unwrap_or_default();
            Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(bytes))
                .unwrap_or_default()
        }
        Err(_) => err_response(502, "api_error", "Aegis: провайдер недоступен"),
    }
}

impl IntoResponse for crate::anthropic::Reject {
    fn into_response(self) -> Response {
        Response::builder()
            .status(self.status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(self.body()))
            .unwrap_or_default()
    }
}

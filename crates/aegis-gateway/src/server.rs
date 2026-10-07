//! REQ: PRO-01, PRO-10, IAM-01, IAM-02, IAM-03, API-01, API-02, API-03, OBS-04, NFR-07, RSP-09.
//!
//! HTTP surface of the gateway: virtual-key authentication, provider key injection,
//! protocol adapters, streaming.

use crate::anthropic::{transform_request, transform_response, ReqMeta};
use crate::audit::{Audit, AuditEvent, EventMeta};
use crate::engine::Engine;
use crate::metrics::Metrics;
use crate::openai_chat::{self, ChatStreamTransformer};
use crate::openai_responses::{self, ResponsesStreamTransformer};
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
pub struct VKey {
    pub principal: Principal,
    /// Unix seconds; `None` = no expiry.
    pub expires: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct BundleStatus {
    pub version: String,
    pub expires_at: i64,
    pub key_id: String,
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

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
    /// Replaced atomically when a new bundle is applied (CFG-02).
    pub engine: arc_swap::ArcSwap<Engine>,
    pub upstream: Upstream,
    /// OpenAI-compatible provider (Chat Completions, Responses).
    pub openai: Option<Upstream>,
    /// SHA-256 (hex) of the virtual key → principal (IAM-03: keys are stored as hashes only).
    pub keys: arc_swap::ArcSwap<HashMap<String, VKey>>,
    /// Present once a bundle was applied; `bundle_required` makes its absence or expiry fail-closed (NFR-09).
    pub bundle: std::sync::Mutex<Option<BundleStatus>>,
    pub bundle_required: bool,
    pub http: reqwest::Client,
    pub audit: Audit,
    pub metrics: Arc<Metrics>,
    counter: AtomicU64,
}

impl AppState {
    pub fn new(engine: Engine, upstream: Upstream, keys: HashMap<String, Principal>) -> Self {
        let keys = keys
            .into_iter()
            .map(|(h, p)| {
                (
                    h,
                    VKey {
                        principal: p,
                        expires: None,
                    },
                )
            })
            .collect();
        Self {
            engine: arc_swap::ArcSwap::from_pointee(engine),
            upstream,
            openai: None,
            keys: arc_swap::ArcSwap::from_pointee(keys),
            bundle: std::sync::Mutex::new(None),
            bundle_required: false,
            http: reqwest::Client::new(),
            audit: Audit::disabled(),
            metrics: Arc::new(Metrics::default()),
            counter: AtomicU64::new(0),
        }
    }

    /// NFR-09, CFG-04: with a bundle configured, no valid bundle means no traffic.
    pub fn readiness(&self) -> Result<(), String> {
        if !self.bundle_required {
            return Ok(());
        }
        match self.bundle.lock().ok().and_then(|b| b.clone()) {
            None => Err("бандл политики не загружен".into()),
            Some(b) if b.expires_at <= now_unix() => {
                Err(format!("срок действия бандла {} истёк", b.version))
            }
            Some(_) => Ok(()),
        }
    }

    pub fn bundle_version(&self) -> String {
        self.bundle
            .lock()
            .ok()
            .and_then(|b| b.as_ref().map(|b| b.version.clone()))
            .unwrap_or_else(|| "dev".into())
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

fn err_response_for(p: Protocol, status: u16, kind: &'static str, message: &str) -> Response {
    if p != Protocol::Anthropic {
        let body = crate::anthropic::Reject {
            status,
            kind,
            message: message.to_string(),
        }
        .body_openai();
        return Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap_or_default();
    }
    err_response(status, kind, message)
}

fn err_response(status: u16, kind: &'static str, message: &str) -> Response {
    let body =
        serde_json::to_vec(&json!({"type": "error", "error": {"type": kind, "message": message}}))
            .unwrap_or_default();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap_or_default()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Anthropic,
    OpenAiChat,
    OpenAiResponses,
}

impl Protocol {
    fn path(&self) -> &'static str {
        match self {
            Protocol::Anthropic => "/v1/messages",
            Protocol::OpenAiChat => "/v1/chat/completions",
            Protocol::OpenAiResponses => "/v1/responses",
        }
    }
    fn route(&self) -> &'static str {
        match self {
            Protocol::Anthropic => "anthropic-default",
            Protocol::OpenAiChat => "openai-chat-default",
            Protocol::OpenAiResponses => "openai-responses-default",
        }
    }
}

enum AnyStream<'e> {
    A(Box<StreamTransformer<'e>>),
    C(Box<ChatStreamTransformer<'e>>),
    R(Box<ResponsesStreamTransformer<'e>>),
}

impl AnyStream<'_> {
    fn feed(&mut self, b: &[u8]) -> Vec<u8> {
        match self {
            AnyStream::A(t) => t.feed(b),
            AnyStream::C(t) => t.feed(b),
            AnyStream::R(t) => t.feed(b),
        }
    }
    fn finish(&mut self) -> Vec<u8> {
        match self {
            AnyStream::A(t) => t.finish(),
            AnyStream::C(t) => t.finish(),
            AnyStream::R(t) => t.finish(),
        }
    }
    fn ctx(&self) -> &crate::engine::RequestCtx {
        match self {
            AnyStream::A(t) => &t.ctx,
            AnyStream::C(t) => &t.ctx,
            AnyStream::R(t) => &t.ctx,
        }
    }
}

pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/messages", any(messages))
        .route("/v1/chat/completions", any(chat_completions))
        .route("/v1/responses", any(responses))
        .route("/v1/messages/count_tokens", any(count_tokens))
        .route("/v1/models", get(models))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(state)
}

/// OBS-04, OBS-01: served on a separate port (SEC-06).
pub fn admin_app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/readyz",
            get(|State(st): State<Arc<AppState>>| async move {
                match st.readiness() {
                    Ok(()) => (axum::http::StatusCode::OK, "ready".to_string()),
                    Err(why) => (axum::http::StatusCode::SERVICE_UNAVAILABLE, why),
                }
            }),
        )
        .route(
            "/metrics",
            get(|State(st): State<Arc<AppState>>| async move {
                // OBS-01: bundle version and time to expiry
                if let Some(b) = st.bundle.lock().ok().and_then(|b| b.clone()) {
                    st.metrics.set_gauge(
                        "aegis_bundle_expires_in_seconds",
                        &[],
                        (b.expires_at - now_unix()) as f64,
                    );
                    st.metrics.set_gauge(
                        "aegis_bundle_info",
                        &[("version", &b.version), ("signer", &b.key_id)],
                        1.0,
                    );
                }
                st.metrics.render()
            }),
        )
        .with_state(state)
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
    let keys = st.keys.load();
    match keys.get(&hash_key(&key)) {
        Some(k) if k.expires.is_none_or(|e| e > now_unix()) => Ok(k.principal.clone()),
        _ => Err(deny("Aegis: неверный или отозванный ключ")),
    }
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

struct ReqInfo {
    principal: String,
    client: String,
    model: String,
    request_bytes: usize,
    route: &'static str,
}

fn client_name(h: &HeaderMap) -> String {
    let raw = h
        .get("x-aegis-client")
        .or_else(|| h.get(header::USER_AGENT))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");
    raw.split(['/', ' '])
        .next()
        .unwrap_or("unknown")
        .chars()
        .take(40)
        .collect()
}

/// Single completion point: audit event (AUD-01) and metrics (OBS-01) for every request.
fn complete(
    st: &AppState,
    ctx: &crate::engine::RequestCtx,
    info: &ReqInfo,
    decision: &'static str,
) {
    let m = &st.metrics;
    m.inc("aegis_requests_total", &[("decision", decision)], 1);
    for (class, n) in &ctx.stats.by_class {
        m.inc("aegis_entities_total", &[("class", class)], *n as u64);
    }
    for r in &ctx.stats.sinks {
        if r.decision == "deny" {
            m.inc(
                "aegis_denied_total",
                &[("rule", &r.rule), ("sink", r.sink)],
                1,
            );
        }
    }
    for (stage, ms) in &ctx.stats.timings_ms {
        m.observe_ms("aegis_stage_ms", &[("stage", stage)], *ms);
    }
    let scanned = ctx.stats.blocks_scanned as u64;
    m.inc(
        "aegis_detect_blocks_total",
        &[("result", "scanned")],
        scanned,
    );
    m.inc(
        "aegis_detect_blocks_total",
        &[("result", "cached")],
        (ctx.stats.blocks_total as u64).saturating_sub(scanned),
    );
    m.inc(
        "aegis_pseudonym_collisions_total",
        &[],
        ctx.mapping.collisions as u64,
    );
    let engine = st.engine.load();
    let bundle_version = st.bundle_version();
    let meta = EventMeta {
        tenant: &engine.keys.tenant,
        principal: &info.principal,
        client: &info.client,
        route: info.route,
        model: &info.model,
        request_bytes: info.request_bytes,
        bundle_version: &bundle_version,
        trifecta_mode: match engine.trifecta.mode {
            aegis_core::policy::TrifectaMode::Enforce => "enforce",
            aegis_core::policy::TrifectaMode::Monitor => "monitor",
        },
    };
    if st
        .audit
        .emit(&AuditEvent::from_ctx(ctx, &meta, decision))
        .is_err()
    {
        m.inc("aegis_audit_overflow_total", &[], 1);
    }
}

async fn messages(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    proxy(st, Protocol::Anthropic, method, headers, body).await
}

async fn responses(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    proxy(st, Protocol::OpenAiResponses, method, headers, body).await
}

async fn chat_completions(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    proxy(st, Protocol::OpenAiChat, method, headers, body).await
}

fn upstream_for(st: &AppState, p: Protocol) -> Option<&Upstream> {
    match p {
        Protocol::Anthropic => Some(&st.upstream),
        Protocol::OpenAiChat | Protocol::OpenAiResponses => st.openai.as_ref(),
    }
}

fn provider_headers(h: &HeaderMap, p: Protocol, up: &Upstream) -> reqwest::header::HeaderMap {
    let mut out = reqwest::header::HeaderMap::new();
    let allow: &[&str] = match p {
        Protocol::Anthropic => &[
            "anthropic-version",
            "anthropic-beta",
            "content-type",
            "accept",
            "user-agent",
        ],
        Protocol::OpenAiChat | Protocol::OpenAiResponses => {
            &["openai-beta", "content-type", "accept", "user-agent"]
        }
    };
    for name in allow {
        if let Some(v) = h.get(*name) {
            if let (Ok(n), Ok(v)) = (
                reqwest::header::HeaderName::from_bytes(name.as_bytes()),
                reqwest::header::HeaderValue::from_bytes(v.as_bytes()),
            ) {
                out.insert(n, v);
            }
        }
    }
    // IAM-02: the provider key is injected here and nowhere else.
    match p {
        Protocol::Anthropic => {
            if let Ok(v) = reqwest::header::HeaderValue::from_str(&up.api_key) {
                out.insert("x-api-key", v);
            }
        }
        Protocol::OpenAiChat | Protocol::OpenAiResponses => {
            if let Ok(v) = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", up.api_key))
            {
                out.insert(reqwest::header::AUTHORIZATION, v);
            }
        }
    }
    out
}

async fn proxy(
    st: Arc<AppState>,
    proto: Protocol,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fail = |status, kind, msg: &str| err_response_for(proto, status, kind, msg);
    if method != Method::POST {
        return fail(405, "invalid_request_error", "Aegis: ожидается POST");
    }
    if let Err(why) = st.readiness() {
        st.metrics
            .inc("aegis_requests_total", &[("decision", "fail_closed")], 1);
        return fail(
            503,
            "api_error",
            &format!("Aegis: {why}; запросы остановлены (fail-closed)"),
        );
    }
    let engine = st.engine.load_full();
    let principal = match authenticate(&headers, &st) {
        Ok(p) => p,
        Err(r) => {
            return if proto == Protocol::Anthropic {
                *r
            } else {
                fail(
                    401,
                    "authentication_error",
                    "Aegis: требуется действительный виртуальный ключ",
                )
            }
        }
    };
    let Some(up_cfg) = upstream_for(&st, proto) else {
        return fail(
            404,
            "not_found_error",
            "Aegis: провайдер для этого протокола не настроен",
        );
    };
    let rid = st.request_id();
    // AUD-04: with `audit.required` traffic stops when the audit queue overflowed (fail-closed).
    if !st.audit.has_room() {
        return with_aegis_headers(
            fail(
                503,
                "api_error",
                "Aegis: аудит недоступен, запрос не выполнен",
            ),
            &rid,
            "",
        );
    }
    let conv = headers
        .get("x-aegis-conversation")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let parsed: Option<serde_json::Value> = serde_json::from_slice(&body).ok();
    let info = ReqInfo {
        principal: principal.id.clone(),
        client: client_name(&headers),
        model: parsed
            .as_ref()
            .and_then(|v| v.get("model"))
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .chars()
            .take(80)
            .collect(),
        request_bytes: body.len(),
        route: proto.route(),
    };
    let streaming = parsed
        .as_ref()
        .and_then(|v| v.get("stream"))
        .and_then(|s| s.as_bool())
        .unwrap_or(false);
    drop(parsed);

    let t0 = Instant::now();
    let meta = ReqMeta {
        principal: &principal.id,
        conversation: conv.as_deref(),
        request_id: &rid,
        route: proto.route(),
    };
    let transformed = match proto {
        Protocol::Anthropic => transform_request(&engine, &meta, &body),
        Protocol::OpenAiChat => openai_chat::transform_request(&engine, &meta, &body),
        Protocol::OpenAiResponses => openai_responses::transform_request(&engine, &meta, &body),
    };
    let (new_body, ctx) = match transformed {
        Ok(x) => x,
        Err(rej) => {
            complete(
                &st,
                &crate::engine::RequestCtx::empty(&rid),
                &info,
                "rejected",
            );
            let b = if proto == Protocol::Anthropic {
                rej.body()
            } else {
                rej.body_openai()
            };
            return with_aegis_headers(
                Response::builder()
                    .status(rej.status)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(b))
                    .unwrap_or_default(),
                &rid,
                "",
            );
        }
    };
    let summary = ctx.stats.summary();
    tracing::info!(request_id = %rid, principal = %principal.id, summary = %summary, blocks = ctx.stats.blocks_total, scanned = ctx.stats.blocks_scanned, overhead_ms = t0.elapsed().as_secs_f64() * 1000.0, "request transformed");

    let url = format!("{}{}", up_cfg.base_url.trim_end_matches('/'), proto.path());
    let up = st
        .http
        .post(url)
        .headers(provider_headers(&headers, proto, up_cfg))
        .body(new_body)
        .send()
        .await;
    let up = match up {
        Ok(r) => r,
        Err(_) => {
            complete(&st, &ctx, &info, "upstream_error");
            return with_aegis_headers(
                fail(502, "api_error", "Aegis: провайдер недоступен"),
                &rid,
                &summary,
            );
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
            let mut t = match proto {
                Protocol::Anthropic => AnyStream::A(Box::new(StreamTransformer::new(&engine, ctx))),
                Protocol::OpenAiChat => {
                    AnyStream::C(Box::new(ChatStreamTransformer::new(&engine, ctx)))
                }
                Protocol::OpenAiResponses => {
                    AnyStream::R(Box::new(ResponsesStreamTransformer::new(&engine, ctx)))
                }
            };
            let mut s = up.bytes_stream();
            while let Some(chunk) = s.next().await {
                let Ok(chunk) = chunk else { break };
                let out = t.feed(&chunk);
                if !out.is_empty() && tx.send(Ok(Bytes::from(out))).await.is_err() {
                    break;
                }
            }
            let rest = t.finish();
            if !rest.is_empty() {
                let _ = tx.send(Ok(Bytes::from(rest))).await;
            }
            // The audit event is written when the stream is over, so it contains the tool call decisions.
            complete(&st2, t.ctx(), &info, "allow");
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
        complete(&st, &ctx, &info, "upstream_error");
        return with_aegis_headers(
            fail(502, "api_error", "Aegis: ответ провайдера оборван"),
            &rid,
            &summary,
        );
    };
    let mut ctx = ctx;
    // RSP-09: non-2xx bodies are provider errors and pass through.
    let out = if status == 200 {
        match proto {
            Protocol::Anthropic => transform_response(&engine, &mut ctx, &bytes),
            Protocol::OpenAiChat => openai_chat::transform_response(&engine, &mut ctx, &bytes),
            Protocol::OpenAiResponses => {
                openai_responses::transform_response(&engine, &mut ctx, &bytes)
            }
        }
    } else {
        bytes.to_vec()
    };
    complete(
        &st,
        &ctx,
        &info,
        if status == 200 {
            "allow"
        } else {
            "upstream_error"
        },
    );
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
    if let Err(why) = st.readiness() {
        return err_response(
            503,
            "api_error",
            &format!("Aegis: {why}; запросы остановлены (fail-closed)"),
        );
    }
    let engine = st.engine.load_full();
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
        route: Protocol::Anthropic.route(),
    };
    let (new_body, ctx) = match transform_request(&engine, &meta, &body) {
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

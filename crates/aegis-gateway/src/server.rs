//! REQ: PRO-01, PRO-10, IAM-01, IAM-02, IAM-03, API-01, API-02, API-03, OBS-04, NFR-07, RSP-09.
//!
//! HTTP surface of the gateway: virtual-key authentication, provider key injection,
//! protocol adapters, streaming.

use crate::anthropic::{transform_request, transform_response, ReqMeta};
use crate::audit::{Audit, AuditEvent, EventMeta};
use crate::engine::Engine;
use crate::gemini::{self, GeminiStreamTransformer};
use crate::metrics::Metrics;
use crate::openai_chat::{self, ChatStreamTransformer};
use crate::openai_completions::{self, CompletionsStreamTransformer};
use crate::openai_embeddings;
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
use std::time::{Duration, Instant};

/// NFR-07
pub const MAX_BODY: usize = 64 * 1024 * 1024;

/// NFR-04 asks for 200 streams per node; the default leaves room above that.
pub const DEFAULT_MAX_IN_FLIGHT: usize = 1000;

/// HTTP client of the provider calls: a provider that does not answer or stalls mid-stream
/// must not hold a connection (and its memory) forever. The read timeout is per read: a long
/// stream is fine as long as it keeps moving.
pub fn client_with(connect: Duration, read: Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(connect)
        .read_timeout(read)
        .build()
        .unwrap_or_default()
}

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

/// How the provider expects its credential (IAM-02).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Auth {
    /// `x-api-key: <key>` (Anthropic).
    XApiKey,
    /// `Authorization: Bearer <key>` (OpenAI, vLLM, most gateways).
    Bearer,
    /// `api-key: <key>` (Azure OpenAI).
    ApiKeyHeader,
    /// `x-goog-api-key: <key>` (Gemini).
    GoogApiKey,
    /// Local models without credentials (Ollama, llama.cpp, vLLM without a key).
    Nothing,
}

impl Auth {
    pub fn parse(s: &str) -> Option<Auth> {
        Some(match s {
            "x-api-key" => Auth::XApiKey,
            "bearer" => Auth::Bearer,
            "api-key" => Auth::ApiKeyHeader,
            "x-goog-api-key" => Auth::GoogApiKey,
            "none" => Auth::Nothing,
            _ => return None,
        })
    }
}

pub struct Upstream {
    pub base_url: String,
    /// Provider credentials stay inside Aegis (IAM-02).
    pub api_key: String,
    pub auth: Auth,
    /// Path before `/chat/completions` and the other OpenAI endpoints (`/v1` by default;
    /// `/api/paas/v4` for Zhipu, `/api/v3` for Volcengine).
    pub api_prefix: String,
}

impl Upstream {
    pub fn with_prefix(mut self, prefix: &str) -> Self {
        self.api_prefix = format!("/{}", prefix.trim_matches('/'));
        if self.api_prefix == "/" {
            self.api_prefix.clear();
        }
        self
    }
    pub fn with_auth(mut self, auth: Auth) -> Self {
        self.auth = auth;
        self
    }

    pub fn anthropic(base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            api_key: api_key.into(),
            auth: Auth::XApiKey,
            api_prefix: "/v1".into(),
        }
    }
    pub fn openai(base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            api_key: api_key.into(),
            auth: Auth::Bearer,
            api_prefix: "/v1".into(),
        }
    }
    pub fn gemini(base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            api_key: api_key.into(),
            auth: Auth::GoogApiKey,
            api_prefix: String::new(),
        }
    }

    fn url(&self, path: &str, query: &str) -> String {
        let base = self.base_url.trim_end_matches('/');
        if query.is_empty() {
            format!("{base}{path}")
        } else {
            format!("{base}{path}?{query}")
        }
    }

    /// IAM-02: the provider key is injected here and nowhere else.
    fn authorize(&self, out: &mut reqwest::header::HeaderMap) {
        let (name, value) = match self.auth {
            Auth::XApiKey => ("x-api-key", self.api_key.clone()),
            Auth::Bearer => ("authorization", format!("Bearer {}", self.api_key)),
            Auth::ApiKeyHeader => ("api-key", self.api_key.clone()),
            Auth::GoogApiKey => ("x-goog-api-key", self.api_key.clone()),
            Auth::Nothing => return,
        };
        if let Ok(v) = reqwest::header::HeaderValue::from_str(&value) {
            out.insert(reqwest::header::HeaderName::from_static(name), v);
        }
    }
}

pub struct AppState {
    /// Replaced atomically when a new bundle is applied (CFG-02).
    pub engine: arc_swap::ArcSwap<Engine>,
    /// Anthropic Messages.
    pub anthropic: Option<Upstream>,
    /// OpenAI-compatible provider (Chat Completions, Responses, Completions, Embeddings).
    pub openai: Option<Upstream>,
    /// Google Gemini (`generateContent`).
    pub gemini: Option<Upstream>,
    /// SHA-256 (hex) of the virtual key → principal (IAM-03: keys are stored as hashes only).
    pub keys: arc_swap::ArcSwap<HashMap<String, VKey>>,
    /// Present once a bundle was applied; `bundle_required` makes its absence or expiry fail-closed (NFR-09).
    pub bundle: std::sync::Mutex<Option<BundleStatus>>,
    pub bundle_required: bool,
    pub http: reqwest::Client,
    /// Requests in flight (a request holds its permit until its response body is over): beyond
    /// the limit a request is refused at once instead of piling up bodies in memory.
    pub limiter: Arc<tokio::sync::Semaphore>,
    /// RTE-02: client-visible model name → the provider's name.
    pub model_aliases: std::collections::BTreeMap<String, String>,
    pub audit: Audit,
    pub metrics: Arc<Metrics>,
    counter: AtomicU64,
}

impl AppState {
    pub fn new(
        engine: Engine,
        anthropic: Option<Upstream>,
        keys: HashMap<String, Principal>,
    ) -> Self {
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
            anthropic,
            openai: None,
            gemini: None,
            keys: arc_swap::ArcSwap::from_pointee(keys),
            bundle: std::sync::Mutex::new(None),
            bundle_required: false,
            http: client_with(Duration::from_secs(10), Duration::from_secs(300)),
            limiter: Arc::new(tokio::sync::Semaphore::new(DEFAULT_MAX_IN_FLIGHT)),
            model_aliases: Default::default(),
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

/// The virtual key as the client sends it: every common SDK convention is accepted.
fn client_key(h: &HeaderMap, query: &str) -> Option<String> {
    for name in ["x-api-key", "x-goog-api-key", "api-key"] {
        if let Some(k) = h.get(name).and_then(|v| v.to_str().ok()) {
            return Some(k.to_string());
        }
    }
    if let Some(k) = h
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        return Some(k.to_string());
    }
    // Gemini clients may put the key into the query string; it is removed before forwarding.
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix("key="))
        .map(String::from)
}

/// The query string without the client's key (never forwarded, never logged).
fn forward_query(query: &str) -> String {
    query
        .split('&')
        .filter(|kv| !kv.is_empty() && !kv.starts_with("key="))
        .collect::<Vec<_>>()
        .join("&")
}

fn err_response_for(p: Protocol, status: u16, kind: &'static str, message: &str) -> Response {
    if p == Protocol::Anthropic {
        return err_response(status, kind, message);
    }
    let rej = crate::anthropic::Reject {
        status,
        kind,
        message: message.to_string(),
    };
    let body = if p == Protocol::Gemini {
        rej.body_gemini()
    } else {
        rej.body_openai()
    };
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap_or_default()
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
    /// Legacy `/v1/completions` (autocomplete, fill-in-the-middle).
    OpenAiCompletions,
    /// `/v1/embeddings`: code indexing sends file contents here.
    OpenAiEmbeddings,
    Gemini,
}

impl Protocol {
    /// Path of the endpoint below the provider's API prefix.
    fn endpoint(&self) -> &'static str {
        match self {
            Protocol::Anthropic => "/v1/messages",
            Protocol::OpenAiChat => "/chat/completions",
            Protocol::OpenAiResponses => "/responses",
            Protocol::OpenAiCompletions => "/completions",
            Protocol::OpenAiEmbeddings => "/embeddings",
            Protocol::Gemini => "",
        }
    }
    fn route(&self) -> &'static str {
        match self {
            Protocol::Anthropic => "anthropic-default",
            Protocol::OpenAiChat => "openai-chat-default",
            Protocol::OpenAiResponses => "openai-responses-default",
            Protocol::OpenAiCompletions => "openai-completions-default",
            Protocol::OpenAiEmbeddings => "openai-embeddings-default",
            Protocol::Gemini => "gemini-default",
        }
    }
}

/// What a Gemini URL asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GemKind {
    Generate,
    Stream,
    /// `countTokens`, `embedContent`, `batchEmbedContents`: the request is checked, the answer
    /// carries no text.
    Other,
}

struct GemTarget {
    path: String,
    query: String,
    model: String,
    kind: GemKind,
}

enum AnyStream<'e> {
    A(Box<StreamTransformer<'e>>),
    C(Box<ChatStreamTransformer<'e>>),
    R(Box<ResponsesStreamTransformer<'e>>),
    P(Box<CompletionsStreamTransformer<'e>>),
    G(Box<GeminiStreamTransformer<'e>>),
}

impl AnyStream<'_> {
    fn feed(&mut self, b: &[u8]) -> Vec<u8> {
        match self {
            AnyStream::A(t) => t.feed(b),
            AnyStream::C(t) => t.feed(b),
            AnyStream::R(t) => t.feed(b),
            AnyStream::P(t) => t.feed(b),
            AnyStream::G(t) => t.feed(b),
        }
    }
    fn finish(&mut self) -> Vec<u8> {
        match self {
            AnyStream::A(t) => t.finish(),
            AnyStream::C(t) => t.finish(),
            AnyStream::R(t) => t.finish(),
            AnyStream::P(t) => t.finish(),
            AnyStream::G(t) => t.finish(),
        }
    }
    fn ctx(&self) -> &crate::engine::RequestCtx {
        match self {
            AnyStream::A(t) => &t.ctx,
            AnyStream::C(t) => &t.ctx,
            AnyStream::R(t) => &t.ctx,
            AnyStream::P(t) => &t.ctx,
            AnyStream::G(t) => &t.ctx,
        }
    }
}

pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/messages", any(messages))
        .route("/v1/chat/completions", any(chat_completions))
        .route("/v1/responses", any(responses))
        .route("/v1/completions", any(completions))
        .route("/v1/embeddings", any(embeddings))
        .route("/v1/messages/count_tokens", any(count_tokens))
        .route("/v1/models", get(models))
        .route("/v1/models/*rest", any(models_item))
        .route("/v1beta/models", get(gemini_list))
        .route("/v1beta/models/*rest", any(gemini_model))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(axum::middleware::from_fn_with_state(state.clone(), limit))
        .with_state(state)
}

/// Refuse a request beyond `max_concurrent_requests` before its body is read, and keep the
/// permit until the response body has been sent (a stream counts for its whole life).
async fn limit(
    State(st): State<Arc<AppState>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let path = req.uri().path().to_string();
    let Ok(permit) = st.limiter.clone().try_acquire_owned() else {
        st.metrics
            .inc("aegis_requests_total", &[("decision", "overloaded")], 1);
        let proto = if path.starts_with("/v1beta/") || path.contains(":generateContent") {
            Protocol::Gemini
        } else if path.starts_with("/v1/messages") {
            Protocol::Anthropic
        } else {
            Protocol::OpenAiChat
        };
        let mut r = err_response_for(
            proto,
            503,
            "overloaded_error",
            "Aegis: слишком много одновременных запросов, повторите позже",
        );
        r.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return r;
    };
    let resp = next.run(req).await;
    let (parts, body) = resp.into_parts();
    let held = body.into_data_stream().map(move |chunk| {
        let _held = &permit;
        chunk
    });
    Response::from_parts(parts, Body::from_stream(held))
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

fn authenticate(h: &HeaderMap, st: &AppState) -> Result<Principal, Box<Response>> {
    authenticate_q(h, st, "")
}

fn authenticate_q(h: &HeaderMap, st: &AppState, query: &str) -> Result<Principal, Box<Response>> {
    let deny = |m: &str| Box::new(err_response(401, "authentication_error", m));
    let key = client_key(h, query).ok_or_else(|| deny("Aegis: требуется виртуальный ключ"))?;
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
    for r in &ctx.stats.sinks {
        if r.decision == "warn" {
            m.inc(
                "aegis_warned_total",
                &[("rule", &r.rule), ("sink", r.sink)],
                1,
            );
        }
    }
    for (stage, ms) in &ctx.stats.timings_ms {
        m.observe_ms("aegis_stage_ms", &[("stage", stage)], *ms);
    }
    for f in &ctx.stats.detector_faults {
        m.inc("aegis_detector_faults_total", &[("kind", f)], 1);
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
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let query = uri.query().unwrap_or("").to_string();
    proxy(st, Protocol::Anthropic, method, headers, body, None, query).await
}

async fn responses(
    State(st): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let query = uri.query().unwrap_or("").to_string();
    proxy(
        st,
        Protocol::OpenAiResponses,
        method,
        headers,
        body,
        None,
        query,
    )
    .await
}

async fn chat_completions(
    State(st): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let query = uri.query().unwrap_or("").to_string();
    proxy(st, Protocol::OpenAiChat, method, headers, body, None, query).await
}

async fn completions(
    State(st): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let query = uri.query().unwrap_or("").to_string();
    proxy(
        st,
        Protocol::OpenAiCompletions,
        method,
        headers,
        body,
        None,
        query,
    )
    .await
}

async fn embeddings(
    State(st): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let query = uri.query().unwrap_or("").to_string();
    proxy(
        st,
        Protocol::OpenAiEmbeddings,
        method,
        headers,
        body,
        None,
        query,
    )
    .await
}

/// `/v1beta/models/<model>:<action>` and `/v1/models/<model>:<action>`.
async fn gemini_model(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
    body: Bytes,
) -> Response {
    let path = uri.path().to_string();
    let query = uri.query().unwrap_or("").to_string();
    let last = path.rsplit('/').next().unwrap_or("").to_string();
    let Some((model, action)) = last.split_once(':') else {
        // Model information and listings carry no user data.
        return passthrough_get(&st, &headers, &path, &query).await;
    };
    let kind = match action {
        "generateContent" => GemKind::Generate,
        "streamGenerateContent" => GemKind::Stream,
        "countTokens" | "embedContent" | "batchEmbedContents" => GemKind::Other,
        // Anything else (batches, cached contents, tuning) takes content Aegis cannot follow.
        _ => {
            return err_response_for(
                Protocol::Gemini,
                404,
                "not_found_error",
                &format!("Aegis: действие {action} не поддерживается"),
            )
        }
    };
    let target = GemTarget {
        path,
        query,
        model: model.chars().take(80).collect(),
        kind,
    };
    proxy(
        st,
        Protocol::Gemini,
        method,
        headers,
        body,
        Some(target),
        String::new(),
    )
    .await
}

async fn gemini_list(State(st): State<Arc<AppState>>, headers: HeaderMap, uri: Uri) -> Response {
    passthrough_get(&st, &headers, uri.path(), uri.query().unwrap_or("")).await
}

/// `/v1/models` is shared by Anthropic, OpenAI and Gemini (v1) clients.
async fn models(State(st): State<Arc<AppState>>, headers: HeaderMap, uri: Uri) -> Response {
    passthrough_get(&st, &headers, uri.path(), uri.query().unwrap_or("")).await
}

/// `/v1/models/<id>`: a Gemini action or a model lookup.
async fn models_item(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
    body: Bytes,
) -> Response {
    if method == Method::POST {
        return gemini_model(State(st), method, headers, uri, body).await;
    }
    passthrough_get(&st, &headers, uri.path(), uri.query().unwrap_or("")).await
}

fn upstream_for(st: &AppState, p: Protocol) -> Option<&Upstream> {
    match p {
        Protocol::Anthropic => st.anthropic.as_ref(),
        Protocol::Gemini => st.gemini.as_ref(),
        Protocol::OpenAiChat
        | Protocol::OpenAiResponses
        | Protocol::OpenAiCompletions
        | Protocol::OpenAiEmbeddings => st.openai.as_ref(),
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
        Protocol::Gemini => &["content-type", "accept", "user-agent"],
        _ => &["openai-beta", "content-type", "accept", "user-agent"],
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
    up.authorize(&mut out);
    out
}

/// Compressed request bodies cannot be scanned; refusing them is the fail-closed answer.
fn check_encoding(h: &HeaderMap, p: Protocol) -> Option<Response> {
    let enc = h.get(header::CONTENT_ENCODING)?.to_str().ok()?.trim();
    if enc.is_empty() || enc.eq_ignore_ascii_case("identity") {
        return None;
    }
    Some(err_response_for(
        p,
        415,
        "invalid_request_error",
        "Aegis: сжатые тела запросов не поддерживаются; отключите сжатие запроса в клиенте",
    ))
}

/// Which provider answers a `GET` on a shared path.
fn pick_family(st: &AppState, h: &HeaderMap, path: &str) -> Option<Protocol> {
    if path.starts_with("/v1beta/") || h.contains_key("x-goog-api-key") {
        return st.gemini.as_ref().map(|_| Protocol::Gemini);
    }
    let anthropic_style = h.contains_key("anthropic-version") || h.contains_key("x-api-key");
    match (anthropic_style, st.anthropic.is_some(), st.openai.is_some()) {
        (true, true, _) => Some(Protocol::Anthropic),
        (_, _, true) => Some(Protocol::OpenAiChat),
        (_, true, false) => Some(Protocol::Anthropic),
        _ => st.gemini.as_ref().map(|_| Protocol::Gemini),
    }
}

/// Read-only calls (model lists) carry no user data and go through after authentication.
async fn passthrough_get(st: &AppState, headers: &HeaderMap, path: &str, query: &str) -> Response {
    let Some(proto) = pick_family(st, headers, path) else {
        return err_response(404, "not_found_error", "Aegis: провайдер не настроен");
    };
    if let Err(why) = st.readiness() {
        return err_response_for(
            proto,
            503,
            "api_error",
            &format!("Aegis: {why}; запросы остановлены (fail-closed)"),
        );
    }
    if let Err(r) = authenticate_q(headers, st, query) {
        return *r;
    }
    let Some(up) = upstream_for(st, proto) else {
        return err_response(404, "not_found_error", "Aegis: провайдер не настроен");
    };
    // OpenAI-style providers keep their models below the API prefix (`/api/paas/v4/models`).
    let upstream_path = match proto {
        Protocol::OpenAiChat => path.replacen("/v1", &up.api_prefix, 1),
        _ => path.to_string(),
    };
    match st
        .http
        .get(up.url(&upstream_path, &forward_query(query)))
        .headers(provider_headers(headers, proto, up))
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

/// RTE-02: the top-level `model` of the (already transformed) body, renamed when it is an alias.
fn rename_model(body: Vec<u8>, aliases: &std::collections::BTreeMap<String, String>) -> Vec<u8> {
    let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return body;
    };
    let Some(real) = v
        .get("model")
        .and_then(|m| m.as_str())
        .and_then(|m| aliases.get(m))
    else {
        return body;
    };
    v["model"] = serde_json::Value::String(real.clone());
    serde_json::to_vec(&v).unwrap_or(body)
}

/// RTE-02 for Gemini, where the model is part of the path (`/v1beta/models/<model>:action`).
fn alias_gemini_path(
    path: &str,
    model: &str,
    aliases: &std::collections::BTreeMap<String, String>,
) -> String {
    match aliases.get(model) {
        Some(real) => path.replacen(&format!("/{model}:"), &format!("/{real}:"), 1),
        None => path.to_string(),
    }
}

async fn proxy(
    st: Arc<AppState>,
    proto: Protocol,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
    gem: Option<GemTarget>,
    query: String,
) -> Response {
    let fail = |status, kind, msg: &str| err_response_for(proto, status, kind, msg);
    if method != Method::POST {
        return fail(405, "invalid_request_error", "Aegis: ожидается POST");
    }
    if let Some(r) = check_encoding(&headers, proto) {
        return r;
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
    let raw_query = gem.as_ref().map_or(query.as_str(), |g| g.query.as_str());
    let principal = match authenticate_q(&headers, &st, raw_query) {
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
    let model = match &gem {
        Some(g) => g.model.clone(),
        None => parsed
            .as_ref()
            .and_then(|v| v.get("model"))
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .chars()
            .take(80)
            .collect(),
    };
    let info = ReqInfo {
        principal: principal.id.clone(),
        client: client_name(&headers),
        model,
        request_bytes: body.len(),
        route: proto.route(),
    };
    let streaming = match &gem {
        Some(g) => g.kind == GemKind::Stream,
        None => parsed
            .as_ref()
            .and_then(|v| v.get("stream"))
            .and_then(|s| s.as_bool())
            .unwrap_or(false),
    };
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
        Protocol::OpenAiCompletions => openai_completions::transform_request(&engine, &meta, &body),
        Protocol::OpenAiEmbeddings => openai_embeddings::transform_request(&engine, &meta, &body),
        Protocol::Gemini => gemini::transform_request(&engine, &meta, &body),
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
            let b = match proto {
                Protocol::Anthropic => rej.body(),
                Protocol::Gemini => rej.body_gemini(),
                _ => rej.body_openai(),
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

    let new_body = if st.model_aliases.is_empty() || gem.is_some() {
        new_body
    } else {
        rename_model(new_body, &st.model_aliases)
    };
    let url = match &gem {
        Some(g) => up_cfg.url(
            &alias_gemini_path(&g.path, &g.model, &st.model_aliases),
            &forward_query(&g.query),
        ),
        // The query goes through (Claude Code sends `?beta=true`), minus the client's `key=`.
        None => up_cfg.url(
            &match proto {
                Protocol::Anthropic => proto.endpoint().to_string(),
                _ => format!("{}{}", up_cfg.api_prefix, proto.endpoint()),
            },
            &forward_query(&query),
        ),
    };
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
                Protocol::OpenAiChat | Protocol::OpenAiEmbeddings => {
                    AnyStream::C(Box::new(ChatStreamTransformer::new(&engine, ctx)))
                }
                Protocol::OpenAiResponses => {
                    AnyStream::R(Box::new(ResponsesStreamTransformer::new(&engine, ctx)))
                }
                Protocol::OpenAiCompletions => {
                    AnyStream::P(Box::new(CompletionsStreamTransformer::new(&engine, ctx)))
                }
                Protocol::Gemini => {
                    AnyStream::G(Box::new(GeminiStreamTransformer::new(&engine, ctx)))
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
            Protocol::OpenAiCompletions => {
                openai_completions::transform_response(&engine, &mut ctx, &bytes)
            }
            // Vectors carry no text to restore.
            Protocol::OpenAiEmbeddings => bytes.to_vec(),
            Protocol::Gemini if gem.as_ref().is_some_and(|g| g.kind == GemKind::Other) => {
                bytes.to_vec()
            }
            Protocol::Gemini => gemini::transform_response(&engine, &mut ctx, &bytes),
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
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(r) = check_encoding(&headers, Protocol::Anthropic) {
        return r;
    }
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
    let Some(up) = st.anthropic.as_ref() else {
        return err_response(404, "not_found_error", "Aegis: провайдер не настроен");
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
    match st
        .http
        .post(up.url(
            "/v1/messages/count_tokens",
            &forward_query(uri.query().unwrap_or("")),
        ))
        .headers(provider_headers(&headers, Protocol::Anthropic, up))
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

impl IntoResponse for crate::anthropic::Reject {
    fn into_response(self) -> Response {
        Response::builder()
            .status(self.status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(self.body()))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod client_tests {
    use super::*;

    // REQ: IAM-05 — `X-Aegis-Client` wins over `User-Agent`; both are only a label.
    #[test]
    fn client_comes_from_the_header_or_the_user_agent() {
        let mut h = HeaderMap::new();
        assert_eq!(client_name(&h), "unknown");
        h.insert(
            header::USER_AGENT,
            "claude-cli/2.1.0 (external)".parse().unwrap(),
        );
        assert_eq!(client_name(&h), "claude-cli");
        h.insert("x-aegis-client", "codex".parse().unwrap());
        assert_eq!(client_name(&h), "codex");
        h.insert("x-aegis-client", "x".repeat(200).parse().unwrap());
        assert_eq!(client_name(&h).len(), 40);
    }
}

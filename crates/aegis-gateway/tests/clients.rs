#![allow(clippy::unwrap_used)]
//! Other clients and providers over real HTTP: Gemini, legacy completions, embeddings,
//! Azure-style and keyless providers, provider path prefixes (Zhipu, Volcengine),
//! model lists, compressed bodies.
//! REQ: PRO-14, PRO-15, PRO-16, PRO-13, PRO-08, IAM-01, IAM-02, API-01.

use aegis_core::crypto::TenantKeys;
use aegis_core::detect::{DetectConfig, Dictionary};
use aegis_gateway::engine::Engine;
use aegis_gateway::server::{app, hash_key, AppState, Auth, Principal, Upstream};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::Router;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const PASSWORD: &str = "Jd8@2jd82k";
const HOST: &str = "prod-db01.pay.corp.local";

struct Call {
    method: String,
    path: String,
    query: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

type Responder = Arc<dyn Fn(&Call) -> (String, Vec<u8>) + Send + Sync>;

struct Mock {
    calls: Mutex<Vec<Call>>,
    respond: Responder,
}

async fn record(
    State(m): State<Arc<Mock>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let call = Call {
        method: method.to_string(),
        path: uri.path().to_string(),
        query: uri.query().unwrap_or("").to_string(),
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect(),
        body: body.to_vec(),
    };
    let (ct, out) = (m.respond)(&call);
    m.calls.lock().unwrap().push(call);
    (StatusCode::OK, [("content-type", ct)], out)
}

async fn mock(respond: Responder) -> (String, Arc<Mock>) {
    let m = Arc::new(Mock {
        calls: Mutex::new(vec![]),
        respond,
    });
    let router = Router::new().fallback(record).with_state(m.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
    (format!("http://{addr}"), m)
}

fn json_ok(v: Value) -> Responder {
    Arc::new(move |_| ("application/json".into(), v.to_string().into_bytes()))
}

async fn gateway(configure: impl FnOnce(&mut AppState)) -> String {
    let keys = TenantKeys::from_secrets("t1", b"k-tenant", b"k-audit");
    let det = DetectConfig {
        internal_zones: vec!["corp.local".into()],
        ..Default::default()
    };
    let engine = Engine::new(keys, det, Dictionary::default());
    let mut vk = HashMap::new();
    vk.insert(
        hash_key("aegis-vk-dev"),
        Principal {
            id: "u:dev".into(),
            groups: vec![],
        },
    );
    let mut st = AppState::new(engine, None, vk);
    configure(&mut st);
    let st = Arc::new(st);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app(st)).await.unwrap() });
    format!("http://{addr}")
}

fn no_real_values(body: &[u8]) {
    let s = String::from_utf8_lossy(body);
    assert!(
        !s.contains(PASSWORD) && !s.contains(HOST),
        "real value reached the provider: {s}"
    );
}

fn host_pseudonym(body: &[u8]) -> String {
    Regex::new(r"h-[a-z2-7]{8}\.[a-z]+\.[a-z]+\.z-[a-z2-7]{8}\.aegis\.invalid")
        .unwrap()
        .find(&String::from_utf8_lossy(body))
        .expect("pseudonym in the forwarded body")
        .as_str()
        .to_string()
}

fn gemini_request() -> Value {
    json!({
        "contents": [{"role": "user", "parts": [{"text": format!("Проверь подключение к {HOST}, password=\"{PASSWORD}\"")}]}],
        "generationConfig": {"temperature": 0.1}
    })
}

// REQ: PRO-14, PRO-16, IAM-01, IAM-02 — the virtual key may arrive in the query (Gemini SDKs) or in the header;
// the provider sees neither the query key nor the client's header, only its own.
#[tokio::test]
async fn gemini_round_trip_with_key_in_query_and_header() {
    let (up, m) = mock(Arc::new(|c: &Call| {
        let host = host_pseudonym(&c.body);
        (
            "application/json".into(),
            json!({"candidates": [{"content": {"role": "model", "parts": [{"text": format!("{host} недоступен")}]}, "finishReason": "STOP"}]})
                .to_string()
                .into_bytes(),
        )
    }))
    .await;
    let gw = gateway(|st| st.gemini = Some(Upstream::gemini(up, "GEMINI-PROVIDER-SECRET"))).await;
    let c = reqwest::Client::new();
    let url = format!("{gw}/v1beta/models/gemini-2.5-pro:generateContent");

    let r1 = c
        .post(format!("{url}?key=aegis-vk-dev&other=1"))
        .json(&gemini_request())
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 200);
    let r1: Value = r1.json().await.unwrap();
    assert_eq!(
        r1["candidates"][0]["content"]["parts"][0]["text"],
        format!("{HOST} недоступен")
    );
    let r2 = c
        .post(&url)
        .header("x-goog-api-key", "aegis-vk-dev")
        .json(&gemini_request())
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 200);

    let calls = m.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    for call in calls.iter() {
        assert_eq!(call.path, "/v1beta/models/gemini-2.5-pro:generateContent");
        assert!(
            !call.query.contains("key="),
            "client key leaked: {}",
            call.query
        );
        assert_eq!(call.headers["x-goog-api-key"], "GEMINI-PROVIDER-SECRET");
        no_real_values(&call.body);
    }
    assert_eq!(calls[0].query, "other=1");
    let sent: Value = serde_json::from_slice(&calls[0].body).unwrap();
    assert!(sent["systemInstruction"]["parts"][0]["text"]
        .as_str()
        .unwrap()
        .starts_with("Aegis notice"));
}

#[tokio::test]
async fn gemini_streaming_is_restored_and_keeps_alt_sse() {
    let (up, m) = mock(Arc::new(|c: &Call| {
        let host = host_pseudonym(&c.body);
        let full = format!("Сервер {host} не отвечает, проверьте {host} ещё раз");
        let chars: Vec<char> = full.chars().collect();
        let mut out = String::new();
        let pieces: Vec<String> = chars.chunks(5).map(|p| p.iter().collect()).collect();
        for (i, p) in pieces.iter().enumerate() {
            let mut cand =
                json!({"content": {"role": "model", "parts": [{"text": p}]}, "index": 0});
            if i + 1 == pieces.len() {
                cand["finishReason"] = json!("STOP");
            }
            out.push_str(&format!("data: {}\r\n\r\n", json!({"candidates": [cand]})));
        }
        ("text/event-stream".into(), out.into_bytes())
    }))
    .await;
    let gw = gateway(|st| st.gemini = Some(Upstream::gemini(up, "GEMINI-PROVIDER-SECRET"))).await;
    let r = reqwest::Client::new()
        .post(format!(
            "{gw}/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse"
        ))
        .header("x-goog-api-key", "aegis-vk-dev")
        .json(&gemini_request())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(r.headers()["content-type"]
        .to_str()
        .unwrap()
        .starts_with("text/event-stream"));
    let text = r.text().await.unwrap();
    let mut got = String::new();
    for line in text.lines() {
        if let Some(d) = line.strip_prefix("data: ") {
            let v: Value = serde_json::from_str(d).unwrap();
            for p in v["candidates"][0]["content"]["parts"].as_array().unwrap() {
                got.push_str(p["text"].as_str().unwrap_or(""));
            }
        }
    }
    assert_eq!(
        got,
        format!("Сервер {HOST} не отвечает, проверьте {HOST} ещё раз")
    );
    let calls = m.calls.lock().unwrap();
    assert_eq!(calls[0].query, "alt=sse");
    no_real_values(&calls[0].body);
}

#[tokio::test]
async fn gemini_other_actions_models_and_errors() {
    let (up, m) = mock(Arc::new(|c: &Call| {
        if c.method == "GET" {
            return (
                "application/json".into(),
                br#"{"models":[{"name":"models/gemini-2.5-pro"}]}"#.to_vec(),
            );
        }
        ("application/json".into(), br#"{"totalTokens":7}"#.to_vec())
    }))
    .await;
    let gw = gateway(|st| st.gemini = Some(Upstream::gemini(up, "K"))).await;
    let c = reqwest::Client::new();

    // countTokens is checked like any request and answered as is
    let r = c
        .post(format!("{gw}/v1beta/models/gemini-2.5-pro:countTokens"))
        .header("x-goog-api-key", "aegis-vk-dev")
        .json(&gemini_request())
        .send()
        .await
        .unwrap();
    assert_eq!(r.json::<Value>().await.unwrap()["totalTokens"], 7);
    no_real_values(&m.calls.lock().unwrap()[0].body);

    // model list
    let r = c
        .get(format!("{gw}/v1beta/models?key=aegis-vk-dev"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(m.calls.lock().unwrap()[1].query, "");

    // actions Aegis cannot follow are refused in Google's error format
    let r = c
        .post(format!(
            "{gw}/v1beta/models/gemini-2.5-pro:batchGenerateContent"
        ))
        .header("x-goog-api-key", "aegis-vk-dev")
        .json(&gemini_request())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    assert_eq!(
        r.json::<Value>().await.unwrap()["error"]["status"],
        "NOT_FOUND"
    );

    // server-side tools are refused, a missing key is 401 in Google's format
    let mut bad = gemini_request();
    bad["tools"] = json!([{"googleSearch": {}}]);
    let r = c
        .post(format!("{gw}/v1beta/models/gemini-2.5-pro:generateContent"))
        .header("x-goog-api-key", "aegis-vk-dev")
        .json(&bad)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let r = c
        .post(format!("{gw}/v1beta/models/gemini-2.5-pro:generateContent"))
        .json(&gemini_request())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(
        r.json::<Value>().await.unwrap()["error"]["status"],
        "UNAUTHENTICATED"
    );
    assert_eq!(
        m.calls.lock().unwrap().len(),
        2,
        "nothing refused reached the provider"
    );
}

// REQ: PRO-13, PRO-08 — autocomplete (prefix and suffix) and indexing (embeddings) are masked;
// the vectors pass through byte for byte.
#[tokio::test]
async fn completions_and_embeddings() {
    let vectors = br#"{"object":"list","data":[{"embedding":[0.1,0.2],"index":0}]}"#.to_vec();
    let v2 = vectors.clone();
    let (up, m) = mock(Arc::new(move |c: &Call| {
        if c.path.ends_with("/embeddings") {
            return ("application/json".into(), v2.clone());
        }
        let body: Value = serde_json::from_slice(&c.body).unwrap();
        let host = host_pseudonym(body["prompt"].as_str().unwrap().as_bytes());
        (
            "application/json".into(),
            json!({"choices": [{"index": 0, "text": format!("connect({host})"), "finish_reason": "stop"}]})
                .to_string()
                .into_bytes(),
        )
    }))
    .await;
    let gw = gateway(|st| st.openai = Some(Upstream::openai(up, "OPENAI-PROVIDER-SECRET"))).await;
    let c = reqwest::Client::new();

    let r = c
        .post(format!("{gw}/v1/completions"))
        .bearer_auth("aegis-vk-dev")
        .json(&json!({"model": "qwen2.5-coder", "prompt": format!("let h = \"{HOST}\";\n"), "suffix": format!("// password = \"{PASSWORD}\""), "max_tokens": 16}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let r: Value = r.json().await.unwrap();
    assert_eq!(r["choices"][0]["text"], format!("connect({HOST})"));

    let r = c
        .post(format!("{gw}/v1/embeddings"))
        .bearer_auth("aegis-vk-dev")
        .json(&json!({"model": "text-embedding-3-small", "input": [format!("DB={HOST} password=\"{PASSWORD}\""), "plain"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.bytes().await.unwrap().to_vec(), vectors);

    let calls = m.calls.lock().unwrap();
    assert_eq!(calls[0].path, "/v1/completions");
    assert_eq!(calls[1].path, "/v1/embeddings");
    assert_eq!(
        calls[1].headers["authorization"],
        "Bearer OPENAI-PROVIDER-SECRET"
    );
    for call in calls.iter() {
        no_real_values(&call.body);
    }
}

// REQ: PRO-15 — Azure OpenAI v1 (`api-key` header), Zhipu (`/api/paas/v4`), keyless local models.
#[tokio::test]
async fn provider_auth_styles_and_path_prefixes() {
    let ok = json_ok(
        json!({"id": "x", "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}]}),
    );
    let body =
        json!({"model": "m", "messages": [{"role": "user", "content": format!("host {HOST}")}]});

    // Azure: client sends `api-key`, provider gets `api-key` and no Authorization
    let (up, m) = mock(ok.clone()).await;
    let gw = gateway(|st| {
        st.openai = Some(
            Upstream::openai(format!("{up}/openai"), "AZURE-SECRET").with_auth(Auth::ApiKeyHeader),
        )
    })
    .await;
    let r = reqwest::Client::new()
        .post(format!("{gw}/v1/chat/completions"))
        .header("api-key", "aegis-vk-dev")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    {
        let calls = m.calls.lock().unwrap();
        assert_eq!(calls[0].path, "/openai/v1/chat/completions");
        assert_eq!(calls[0].headers["api-key"], "AZURE-SECRET");
        assert!(!calls[0].headers.contains_key("authorization"));
        no_real_values(&calls[0].body);
    }

    // Zhipu / Volcengine style prefix, DeepSeek style (no prefix)
    for (prefix, want) in [
        ("/v4", "/api/paas/v4/chat/completions"),
        ("/api/v3", "/api/paas/api/v3/chat/completions"),
        ("", "/api/paas/chat/completions"),
    ] {
        let (up, m) = mock(ok.clone()).await;
        let gw = gateway(|st| {
            st.openai =
                Some(Upstream::openai(format!("{up}/api/paas"), "ZHIPU-SECRET").with_prefix(prefix))
        })
        .await;
        let r = reqwest::Client::new()
            .post(format!("{gw}/v1/chat/completions"))
            .bearer_auth("aegis-vk-dev")
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(m.calls.lock().unwrap()[0].path, want, "prefix {prefix:?}");
    }

    // keyless local model: no credential header at all
    let (up, m) = mock(ok).await;
    let gw = gateway(|st| {
        st.openai = Some(Upstream::openai(up, "").with_auth(Auth::Nothing));
    })
    .await;
    let r = reqwest::Client::new()
        .post(format!("{gw}/v1/chat/completions"))
        .bearer_auth("aegis-vk-dev")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let calls = m.calls.lock().unwrap();
    assert!(!calls[0].headers.contains_key("authorization"));
    assert!(!calls[0]
        .headers
        .values()
        .any(|v| v.contains("aegis-vk-dev")));
}

// REQ: PRO-15 — Anthropic-compatible endpoints of Kimi, GLM, DeepSeek and others take a Bearer token.
#[tokio::test]
async fn anthropic_compatible_provider_with_bearer_token() {
    let (up, m) = mock(json_ok(json!({"id": "m", "type": "message", "role": "assistant", "content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn"}))).await;
    let gw = gateway(|st| {
        st.anthropic = Some(
            Upstream::anthropic(format!("{up}/anthropic"), "MOONSHOT-SECRET")
                .with_auth(Auth::Bearer),
        )
    })
    .await;
    let r = reqwest::Client::new()
        .post(format!("{gw}/v1/messages"))
        .header("x-api-key", "aegis-vk-dev")
        .json(&json!({"model": "kimi-k2", "max_tokens": 8, "messages": [{"role": "user", "content": format!("host {HOST}")}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let calls = m.calls.lock().unwrap();
    assert_eq!(calls[0].path, "/anthropic/v1/messages");
    assert_eq!(calls[0].headers["authorization"], "Bearer MOONSHOT-SECRET");
    assert!(!calls[0].headers.contains_key("x-api-key"));
    no_real_values(&calls[0].body);
}

// REQ: PRO-15, PRO-16 — `/v1/models` is answered by the provider the client's key style points at.
#[tokio::test]
async fn model_lists_follow_the_client_style() {
    let (a_up, a) = mock(json_ok(json!({"data": [{"id": "claude-x"}]}))).await;
    let (o_up, o) = mock(json_ok(json!({"data": [{"id": "gpt-x"}]}))).await;
    let gw = gateway(|st| {
        st.anthropic = Some(Upstream::anthropic(a_up, "A"));
        st.openai = Some(Upstream::openai(o_up, "O"));
    })
    .await;
    let c = reqwest::Client::new();
    let r: Value = c
        .get(format!("{gw}/v1/models"))
        .header("x-api-key", "aegis-vk-dev")
        .header("anthropic-version", "2023-06-01")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["data"][0]["id"], "claude-x");
    let r: Value = c
        .get(format!("{gw}/v1/models"))
        .bearer_auth("aegis-vk-dev")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["data"][0]["id"], "gpt-x");
    assert_eq!(a.calls.lock().unwrap()[0].headers["x-api-key"], "A");
    assert_eq!(
        o.calls.lock().unwrap()[0].headers["authorization"],
        "Bearer O"
    );
    // unauthenticated lists are refused
    assert_eq!(
        c.get(format!("{gw}/v1/models"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
}

// REQ: PRO-16 — A compressed body cannot be scanned, so it is refused instead of forwarded.
#[tokio::test]
async fn compressed_bodies_are_refused() {
    let (up, m) = mock(json_ok(json!({}))).await;
    let gw = gateway(|st| st.openai = Some(Upstream::openai(up, "K"))).await;
    let r = reqwest::Client::new()
        .post(format!("{gw}/v1/chat/completions"))
        .bearer_auth("aegis-vk-dev")
        .header("content-encoding", "zstd")
        .body(vec![0x28, 0xb5, 0x2f, 0xfd, 0, 0])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 415);
    assert!(m.calls.lock().unwrap().is_empty());
}

// REQ: PRO-15
#[tokio::test]
async fn protocol_without_a_provider_is_not_found() {
    let gw = gateway(|_| {}).await;
    let c = reqwest::Client::new();
    for path in ["/v1/messages", "/v1/chat/completions", "/v1/completions"] {
        let r = c
            .post(format!("{gw}{path}"))
            .bearer_auth("aegis-vk-dev")
            .json(&json!({"model": "m", "messages": [], "prompt": "x"}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404, "{path}");
    }
}

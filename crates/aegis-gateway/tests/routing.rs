#![allow(clippy::unwrap_used)]
//! REQ: RTE-02 — model aliases: the client asks for a stable name, the provider gets the real one.

use aegis_core::crypto::TenantKeys;
use aegis_core::detect::{DetectConfig, Dictionary};
use aegis_gateway::engine::Engine;
use aegis_gateway::server::{app, hash_key, AppState, Principal, Upstream};
use axum::extract::State;
use axum::http::Uri;
use axum::routing::any;
use axum::Router;
use bytes::Bytes;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// (path, body, authorization header)
type Seen = Arc<Mutex<Vec<(String, String, String)>>>;

async fn provider() -> (String, Seen) {
    let seen: Seen = Arc::default();
    let router = Router::new()
        .fallback(any(
            |State(s): State<Seen>, h: axum::http::HeaderMap, uri: Uri, b: Bytes| async move {
                let auth = h
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                s.lock().unwrap().push((
                    uri.path().to_string(),
                    String::from_utf8_lossy(&b).into(),
                    auth,
                ));
                "{}"
            },
        ))
        .with_state(seen.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
    (format!("http://{addr}"), seen)
}

async fn gateway(up: &str) -> String {
    let keys = TenantKeys::from_secrets("t1", b"k-tenant", b"k-audit");
    let engine = Engine::new(keys, DetectConfig::default(), Dictionary::default());
    let mut vk = HashMap::new();
    vk.insert(
        hash_key("vk"),
        Principal {
            id: "u:x".into(),
            groups: vec![],
        },
    );
    let mut st = AppState::new(engine, Some(Upstream::anthropic(up.to_string(), "k")), vk);
    st.openai = Some(Upstream::openai(up.to_string(), "k"));
    st.gemini = Some(Upstream::gemini(up.to_string(), "k"));
    st.model_aliases
        .insert("claude-default".into(), "claude-real-1".into());
    st.model_aliases
        .insert("gpt-default".into(), "gpt-real-2".into());
    st.model_aliases
        .insert("gem-default".into(), "gemini-real-3".into());
    let st = Arc::new(st);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app(st)).await.unwrap() });
    format!("http://{addr}")
}

#[tokio::test]
async fn aliases_are_replaced_for_the_provider_in_every_protocol() {
    let (up, seen) = provider().await;
    let gw = gateway(&up).await;
    let c = reqwest::Client::new();
    let msgs = json!([{"role": "user", "content": "hi"}]);
    c.post(format!("{gw}/v1/messages"))
        .header("x-api-key", "vk")
        .json(&json!({"model": "claude-default", "max_tokens": 4, "messages": msgs}))
        .send()
        .await
        .unwrap();
    c.post(format!("{gw}/v1/chat/completions"))
        .header("authorization", "Bearer vk")
        .json(&json!({"model": "gpt-default", "messages": msgs}))
        .send()
        .await
        .unwrap();
    // a name that is not an alias goes through unchanged
    c.post(format!("{gw}/v1/chat/completions"))
        .header("authorization", "Bearer vk")
        .json(&json!({"model": "other", "messages": msgs}))
        .send()
        .await
        .unwrap();
    c.post(format!("{gw}/v1beta/models/gem-default:generateContent"))
        .header("x-goog-api-key", "vk")
        .json(&json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}))
        .send()
        .await
        .unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 4);
    assert!(seen[0].1.contains("\"claude-real-1\"") && !seen[0].1.contains("claude-default"));
    assert!(seen[1].1.contains("\"gpt-real-2\""));
    assert!(seen[2].1.contains("\"other\""));
    assert_eq!(seen[3].0, "/v1beta/models/gemini-real-3:generateContent");
}

// ---- RTE-01 ----------------------------------------------------------------------------------

use aegis_gateway::server::{glob_match, Auth, Family, Route};

// REQ: RTE-01
#[test]
fn glob_patterns() {
    for (p, t, ok) in [
        ("deepseek-*", "deepseek-chat", true),
        ("deepseek-*", "deepseek-", true),
        ("deepseek-*", "xdeepseek-chat", false),
        ("*-coder", "qwen-coder", true),
        ("*-coder", "qwen-coder-v2", false),
        ("qwen*coder*", "qwen2.5-coder-32b", true),
        ("a*b*c", "abc", true),
        ("a*b*c", "acb", false),
        ("exact", "exact", true),
        ("exact", "exact2", false),
        ("*", "anything", true),
    ] {
        assert_eq!(glob_match(p, t), ok, "{p} vs {t}");
    }
}

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// A request goes to the route its model and its group select, with that route's credentials,
// and the audit event carries the route's name (the policy binds rules to it).
#[tokio::test]
async fn requests_follow_their_route() {
    let (default_up, default_seen) = provider().await;
    let (local_up, local_seen) = provider().await;
    let (team_up, team_seen) = provider().await;
    let keys = TenantKeys::from_secrets("t1", b"k-tenant", b"k-audit");
    let engine = Engine::new(keys, DetectConfig::default(), Dictionary::default());
    let mut vk = HashMap::new();
    vk.insert(
        hash_key("plain"),
        Principal {
            id: "u:plain".into(),
            groups: vec![],
        },
    );
    vk.insert(
        hash_key("dev"),
        Principal {
            id: "u:dev".into(),
            groups: vec!["devs".into()],
        },
    );
    let mut st = AppState::new(engine, None, vk);
    st.openai = Some(Upstream::openai(default_up, "default-key"));
    st.routes = vec![
        Route {
            name: "local-vllm".into(),
            family: Family::OpenAi,
            models: vec!["qwen*".into()],
            groups: vec![],
            upstream: Upstream::openai(local_up, "").with_auth(Auth::Nothing),
        },
        Route {
            name: "devs-only".into(),
            family: Family::OpenAi,
            models: vec!["gpt-*".into()],
            groups: vec!["devs".into()],
            upstream: Upstream::openai(team_up, "team-key"),
        },
    ];
    let buf = Buf::default();
    st.audit = aegis_gateway::audit::Audit::to_writer(buf.clone(), 100, false);
    let st = Arc::new(st);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gw = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app(st)).await.unwrap() });

    let c = reqwest::Client::new();
    let ask = |key: &'static str, model: &'static str| {
        let c = c.clone();
        let url = format!("{gw}/v1/chat/completions");
        async move {
            c.post(url)
                .header("authorization", format!("Bearer {key}"))
                .json(&json!({"model": model, "messages": [{"role": "user", "content": "hi"}]}))
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    ask("plain", "qwen2.5-coder").await; // by model → local
    ask("plain", "gpt-4o").await; // route for devs only → default
    ask("dev", "gpt-4o").await; // by model and group → team
    ask("dev", "other-model").await; // nothing matches → default
    assert_eq!(local_seen.lock().unwrap().len(), 1);
    assert_eq!(team_seen.lock().unwrap().len(), 1);
    assert_eq!(default_seen.lock().unwrap().len(), 2);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let audit = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    let routes: Vec<String> = audit
        .lines()
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["route"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(
        routes,
        [
            "local-vllm",
            "openai-chat-default",
            "devs-only",
            "openai-chat-default"
        ]
    );

    // credentials: the client's key never goes on; each route uses its own
    assert_eq!(local_seen.lock().unwrap()[0].2, "");
    assert_eq!(team_seen.lock().unwrap()[0].2, "Bearer team-key");
    assert!(default_seen
        .lock()
        .unwrap()
        .iter()
        .all(|s| s.2 == "Bearer default-key"));
}

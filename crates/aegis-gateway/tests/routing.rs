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

type Seen = Arc<Mutex<Vec<(String, String)>>>;

async fn provider() -> (String, Seen) {
    let seen: Seen = Arc::default();
    let router = Router::new()
        .fallback(any(
            |State(s): State<Seen>, uri: Uri, b: Bytes| async move {
                s.lock()
                    .unwrap()
                    .push((uri.path().to_string(), String::from_utf8_lossy(&b).into()));
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

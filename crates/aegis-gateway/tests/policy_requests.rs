#![allow(clippy::unwrap_used)]
//! REQ: POL-05, PRO-07, PRO-08 — the policy decides what happens to attachments and embeddings.

use aegis_core::crypto::TenantKeys;
use aegis_core::detect::{DetectConfig, Dictionary};
use aegis_gateway::engine::Engine;
use aegis_gateway::server::{app, hash_key, AppState, Principal, Upstream};
use axum::routing::any;
use axum::Router;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

async fn gateway(block_attachments: bool, block_embeddings: bool) -> String {
    let up = Router::new().fallback(any(|| async {
        axum::Json(
            json!({"id": "m", "type": "message", "role": "assistant", "model": "m",
            "content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1}, "data": [{"embedding": [0.1]}]}),
        )
    }));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, up).await.unwrap() });

    let keys = TenantKeys::from_secrets("t1", b"k-tenant", b"k-audit");
    let mut engine = Engine::new(keys, DetectConfig::default(), Dictionary::default());
    engine.request.block_attachments = block_attachments;
    engine.request.block_embeddings = block_embeddings;
    let mut vk = HashMap::new();
    vk.insert(
        hash_key("vk"),
        Principal {
            id: "u:x".into(),
            groups: vec![],
        },
    );
    let mut st = AppState::new(engine, Some(Upstream::anthropic(up_url.clone(), "k")), vk);
    st.openai = Some(Upstream::openai(up_url.clone(), "k"));
    st.gemini = Some(Upstream::gemini(up_url, "k"));
    let st = Arc::new(st);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app(st)).await.unwrap() });
    format!("http://{addr}")
}

fn with_image() -> serde_json::Value {
    json!({"model": "m", "max_tokens": 4, "messages": [{"role": "user", "content": [
        {"type": "text", "text": "what is this"},
        {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}}]}]})
}

#[tokio::test]
async fn attachments_are_replaced_by_default_and_refused_on_request() {
    let c = reqwest::Client::new();
    let gw = gateway(false, false).await;
    let r = c
        .post(format!("{gw}/v1/messages"))
        .header("x-api-key", "vk")
        .json(&with_image())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    let gw = gateway(true, false).await;
    let r = c
        .post(format!("{gw}/v1/messages"))
        .header("x-api-key", "vk")
        .json(&with_image())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    assert!(r.text().await.unwrap().contains("изображения и документы"));
    // text without attachments still goes
    let r = c
        .post(format!("{gw}/v1/messages"))
        .header("x-api-key", "vk")
        .json(&json!({"model": "m", "max_tokens": 4, "messages": [{"role": "user", "content": "hi"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}

#[tokio::test]
async fn embeddings_are_masked_by_default_and_refused_on_request() {
    let c = reqwest::Client::new();
    let body = json!({"model": "e", "input": "host prod-db01.corp.local"});
    let gw = gateway(false, false).await;
    let r = c
        .post(format!("{gw}/v1/embeddings"))
        .header("authorization", "Bearer vk")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    let gw = gateway(false, true).await;
    let r = c
        .post(format!("{gw}/v1/embeddings"))
        .header("authorization", "Bearer vk")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let r = c
        .post(format!("{gw}/v1beta/models/m:embedContent"))
        .header("x-goog-api-key", "vk")
        .json(&json!({"content": {"parts": [{"text": "x"}]}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    // chat is untouched
    let r = c
        .post(format!("{gw}/v1/chat/completions"))
        .header("authorization", "Bearer vk")
        .json(&json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}

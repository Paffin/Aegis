#![allow(clippy::unwrap_used)]
//! REQ: NFR-13, NFR-04, RSP-09 — what the gateway does when the provider is slow or silent
//! and when there are more requests than it can hold.

use aegis_core::crypto::TenantKeys;
use aegis_core::detect::{DetectConfig, Dictionary};
use aegis_gateway::engine::Engine;
use aegis_gateway::server::{app, client_with, hash_key, AppState, Principal, Upstream};
use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use bytes::Bytes;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A provider that streams for `secs` seconds, or never answers when `silent`.
async fn provider(secs: u64, silent: bool) -> String {
    let router = Router::new().route(
        "/v1/messages",
        post(move |_: Bytes| async move {
            if silent {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
            let stream = futures_util::stream::unfold(0u64, move |i| async move {
                if i > secs {
                    return None;
                }
                tokio::time::sleep(Duration::from_millis(if i == 0 { 0 } else { 1000 })).await;
                let ev = if i < secs {
                    "event: ping\ndata: {\"type\":\"ping\"}\n\n"
                } else {
                    "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
                };
                Some((Ok::<_, std::io::Error>(Bytes::from(ev)), i + 1))
            });
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/event-stream")
                .body(Body::from_stream(stream))
                .unwrap()
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
    format!("http://{addr}")
}

async fn gateway(up: String, max: usize, read_timeout: Duration) -> String {
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
    let mut st = AppState::new(engine, Some(Upstream::anthropic(up, "k")), vk);
    st.limiter = Arc::new(tokio::sync::Semaphore::new(max));
    st.http = client_with(Duration::from_secs(2), read_timeout);
    let st = Arc::new(st);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app(st)).await.unwrap() });
    format!("http://{addr}")
}

fn body() -> serde_json::Value {
    json!({"model": "m", "max_tokens": 4, "stream": true, "messages": [{"role": "user", "content": "hi"}]})
}

// More requests than the limit: the excess is refused at once, in the client's protocol, with
// Retry-After; a stream holds its place until its last byte, and the place is free afterwards.
#[tokio::test]
async fn requests_beyond_the_limit_are_refused_and_the_place_is_released() {
    let up = provider(2, false).await;
    let gw = gateway(up, 2, Duration::from_secs(10)).await;
    let c = reqwest::Client::new();
    let url = format!("{gw}/v1/messages");
    let start = |c: reqwest::Client, url: String| {
        tokio::spawn(async move {
            let r = c
                .post(url)
                .header("x-api-key", "vk")
                .json(&body())
                .send()
                .await
                .unwrap();
            let status = r.status();
            let _ = r.bytes().await; // read to the end: the stream ends the request
            status
        })
    };
    let a = start(c.clone(), url.clone());
    let b = start(c.clone(), url.clone());
    tokio::time::sleep(Duration::from_millis(500)).await;
    let r = c
        .post(&url)
        .header("x-api-key", "vk")
        .json(&body())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 503);
    assert_eq!(r.headers()["retry-after"], "1");
    let v: serde_json::Value = r.json().await.unwrap();
    assert_eq!(v["error"]["type"], "overloaded_error");
    // other protocols get their own error shape
    let r = c
        .post(format!("{gw}/v1/chat/completions"))
        .bearer_auth("vk")
        .json(&json!({"model": "m", "messages": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 503);
    assert_eq!(
        r.json::<serde_json::Value>().await.unwrap()["error"]["type"],
        "overloaded_error"
    );
    assert_eq!(a.await.unwrap(), 200);
    assert_eq!(b.await.unwrap(), 200);
    // both streams are over: the places are free
    let r = c
        .post(&url)
        .header("x-api-key", "vk")
        .json(&body())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}

// A provider that never answers does not hold the request: it ends in 502 after the read timeout.
#[tokio::test]
async fn a_silent_provider_ends_in_502_after_the_read_timeout() {
    let up = provider(0, true).await;
    let gw = gateway(up, 10, Duration::from_millis(800)).await;
    let t = Instant::now();
    let r = reqwest::Client::new()
        .post(format!("{gw}/v1/messages"))
        .header("x-api-key", "vk")
        .json(&body())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 502);
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
}

#![allow(clippy::unwrap_used)]
//! REQ: OBS-03 — one trace per request, by stage, joined to the client's trace, without values.

use aegis_core::crypto::TenantKeys;
use aegis_core::detect::{DetectConfig, Dictionary};
use aegis_gateway::engine::Engine;
use aegis_gateway::server::{app, client_with, hash_key, AppState, Principal, Upstream};
use aegis_gateway::trace::Tracer;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::Router;
use bytes::Bytes;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

type Got = Arc<Mutex<Vec<(HeaderMap, Value)>>>;

async fn collector() -> (String, Got) {
    let got: Got = Arc::default();
    let router = Router::new()
        .route(
            "/v1/traces",
            post(|State(g): State<Got>, h: HeaderMap, b: Bytes| async move {
                g.lock()
                    .unwrap()
                    .push((h, serde_json::from_slice(&b).unwrap()));
                "{}"
            }),
        )
        .with_state(got.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
    (format!("http://{addr}"), got)
}

async fn provider() -> String {
    let router = Router::new().route(
        "/v1/messages",
        post(|| async {
            axum::Json(
                json!({"id": "m", "type": "message", "role": "assistant", "model": "m",
                "content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1}}),
            )
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
    format!("http://{addr}")
}

async fn gateway(up: String, otlp: String) -> String {
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
    st.tracer = Some(Tracer::start(
        otlp,
        vec![("authorization".into(), "Bearer collector-token".into())],
        client_with(Duration::from_secs(2), Duration::from_secs(2)),
    ));
    let st = Arc::new(st);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app(st)).await.unwrap() });
    format!("http://{addr}")
}

fn spans(got: &Got) -> Vec<Value> {
    got.lock()
        .unwrap()
        .iter()
        .flat_map(|(_, b)| {
            b["resourceSpans"][0]["scopeSpans"][0]["spans"]
                .as_array()
                .unwrap()
                .clone()
        })
        .collect()
}

#[tokio::test]
async fn a_request_leaves_a_trace_with_stages_and_no_values() {
    let (otlp, got) = collector().await;
    let gw = gateway(provider().await, otlp).await;
    let c = reqwest::Client::new();
    let secret = "Jd8@2jd82kX";
    let tp_trace = "4bf92f3577b34da6a3ce929d0e0e4736";
    let r = c
        .post(format!("{gw}/v1/messages"))
        .header("x-api-key", "vk")
        .header("traceparent", format!("00-{tp_trace}-00f067aa0ba902b7-01"))
        .json(&json!({"model": "m", "max_tokens": 4, "messages": [{"role": "user", "content": format!("host prod-db01.corp.local password={secret}")}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    for _ in 0..50 {
        if !got.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let all = spans(&got);
    let names: Vec<&str> = all.iter().map(|s| s["name"].as_str().unwrap()).collect();
    for n in [
        "aegis.request",
        "aegis.parse",
        "aegis.detect",
        "aegis.transform",
        "aegis.upstream",
        "aegis.response",
    ] {
        assert!(names.contains(&n), "{n} in {names:?}");
    }
    // joined to the client's trace; the root hangs under the client's span
    let root = all.iter().find(|s| s["name"] == "aegis.request").unwrap();
    assert_eq!(root["traceId"], tp_trace);
    assert_eq!(root["parentSpanId"], "00f067aa0ba902b7");
    assert!(all
        .iter()
        .filter(|s| s["name"] != "aegis.request")
        .all(|s| s["parentSpanId"] == root["spanId"]));
    // attributes: counts and names
    let attrs = root["attributes"].to_string();
    assert!(attrs.contains("aegis.entities") && attrs.contains("aegis.decision"));
    // the collector's token reached the collector, and no value reached it
    assert_eq!(
        got.lock().unwrap()[0].0["authorization"],
        "Bearer collector-token"
    );
    let everything = got
        .lock()
        .unwrap()
        .iter()
        .map(|(_, b)| b.to_string())
        .collect::<String>();
    assert!(
        !everything.contains(secret)
            && !everything.contains("prod-db01")
            && !everything.contains("corp.local")
    );
}

#[tokio::test]
async fn a_dead_collector_does_not_touch_the_traffic() {
    let gw = gateway(provider().await, "http://127.0.0.1:1".into()).await;
    let c = reqwest::Client::new();
    for _ in 0..3 {
        let r = c
            .post(format!("{gw}/v1/messages"))
            .header("x-api-key", "vk")
            .json(&json!({"model": "m", "max_tokens": 4, "messages": [{"role": "user", "content": "hi"}]}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
    }
}

#![allow(clippy::unwrap_used)]
//! REQ: CFG-07, NFR-09 — a key in an HSM that fails does not let a request through: whatever the
//! pseudonyms would have been computed from is garbage, so the request is refused (503) and nothing
//! reaches the provider. The key here is a stand-in that fails on demand; the real token is in
//! `crates/aegis-hsm/tests`.

use aegis_core::crypto::{HmacPrf, KeyPair, Prf, TenantKeys};
use aegis_core::detect::{DetectConfig, Dictionary};
use aegis_gateway::engine::Engine;
use aegis_gateway::server::{admin_app, app, hash_key, AppState, Principal, Upstream};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::Router;
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// An HMAC key that behaves like `Pkcs11Key` when the token is gone: after `ok_calls` computations
/// it returns zeros, counts the failure and reports itself unhealthy.
struct Flaky {
    inner: HmacPrf,
    ok_calls: AtomicI64,
    faults: AtomicU64,
    down: AtomicBool,
}

impl Flaky {
    fn new(ok_calls: i64) -> Arc<Self> {
        Arc::new(Self {
            inner: HmacPrf::new(b"k-tenant-0123456789abcdef"),
            ok_calls: AtomicI64::new(ok_calls),
            faults: AtomicU64::new(0),
            down: AtomicBool::new(false),
        })
    }
}

impl Prf for Flaky {
    fn mac_raw(&self, data: &[u8]) -> [u8; 32] {
        if self.ok_calls.fetch_sub(1, Ordering::SeqCst) <= 0 {
            self.faults.fetch_add(1, Ordering::SeqCst);
            self.down.store(true, Ordering::SeqCst);
            return [0; 32];
        }
        self.inner.mac_raw(data)
    }
    fn faults(&self) -> u64 {
        self.faults.load(Ordering::SeqCst)
    }
    fn healthy(&self) -> bool {
        !self.down.load(Ordering::SeqCst)
    }
}

async fn spawn_mock(seen: Arc<Mutex<Vec<Vec<u8>>>>) -> String {
    async fn handler(
        State(seen): State<Arc<Mutex<Vec<Vec<u8>>>>>,
        body: Bytes,
    ) -> impl IntoResponse {
        seen.lock().unwrap().push(body.to_vec());
        (
            StatusCode::OK,
            [("content-type", "application/json")],
            r#"{"type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn"}"#,
        )
    }
    let app = Router::new()
        .route("/v1/messages", post(handler))
        .route("/v1/chat/completions", post(handler))
        .with_state(seen);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://{addr}")
}

async fn spawn_gateway(upstream: String, k_t: Arc<Flaky>) -> (String, String) {
    let keys = KeyPair {
        k_t,
        k_audit: Arc::new(HmacPrf::new(b"k-audit-0123456789abcdef")),
    };
    let engine = Engine::new(
        TenantKeys::from_pair("t1", &keys),
        DetectConfig::default(),
        Dictionary::default(),
    );
    let mut vk = HashMap::new();
    vk.insert(
        hash_key("aegis-vk-x"),
        Principal {
            id: "u:x".into(),
            groups: vec![],
        },
    );
    let mut st = AppState::new(
        engine,
        Some(Upstream::anthropic(upstream.clone(), "sk-p")),
        vk,
    );
    st.openai = Some(Upstream::openai(upstream, "sk-o"));
    let st = Arc::new(st);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let main = l.local_addr().unwrap();
    let st2 = st.clone();
    tokio::spawn(async move { axum::serve(l, app(st2)).await.unwrap() });
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, admin_app(st)).await.unwrap() });
    (format!("http://{main}"), format!("http://{admin}"))
}

const TEXT: &str = "host prod-db01.pay.corp.local, password: Jd8@2jd82k, ip 10.34.18.21";

async fn send(gw: &str, openai: bool) -> reqwest::Response {
    let (path, body) = if openai {
        (
            "/v1/chat/completions",
            json!({"model": "m", "messages": [{"role": "user", "content": TEXT}]}),
        )
    } else {
        (
            "/v1/messages",
            json!({"model": "m", "max_tokens": 10, "messages": [{"role": "user", "content": TEXT}]}),
        )
    };
    let mut r = reqwest::Client::new()
        .post(format!("{gw}{path}"))
        .header("x-aegis-conversation", "c1")
        .json(&body);
    r = if openai {
        r.bearer_auth("aegis-vk-x")
    } else {
        r.header("x-api-key", "aegis-vk-x")
            .header("anthropic-version", "2023-06-01")
    };
    r.send().await.unwrap()
}

// REQ: CFG-07 — the key works: the same gateway serves while it does.
#[tokio::test]
async fn a_working_key_serves() {
    let seen = Arc::new(Mutex::new(vec![]));
    let up = spawn_mock(seen.clone()).await;
    let (gw, admin) = spawn_gateway(up, Flaky::new(i64::MAX)).await;
    for openai in [false, true] {
        assert_eq!(send(&gw, openai).await.status(), 200);
    }
    assert_eq!(seen.lock().unwrap().len(), 2);
    let r = reqwest::get(format!("{admin}/readyz")).await.unwrap();
    assert_eq!(r.status(), 200);
}

// REQ: CFG-07, NFR-09 — the key fails in the middle of a request (after the salt, before the
// pseudonyms): the request is refused and the provider sees nothing.
#[tokio::test]
async fn a_key_that_fails_mid_request_stops_the_request() {
    // (a fresh gateway for every request: once a key has failed, readiness refuses the next ones
    // before they are read, and this test is about the check at the end of the pseudonymization)
    for ok_calls in [0, 1, 2, 5] {
        for openai in [false, true] {
            let seen = Arc::new(Mutex::new(vec![]));
            let up = spawn_mock(seen.clone()).await;
            let (gw, admin) = spawn_gateway(up, Flaky::new(ok_calls)).await;
            let r = send(&gw, openai).await;
            assert_eq!(r.status(), 503, "ok_calls={ok_calls} openai={openai}");
            let text = r.text().await.unwrap();
            assert!(text.contains("HSM"), "{text}");
            for leak in ["prod-db01", "Jd8@2jd82k", "10.34.18.21", "0000000000"] {
                assert!(!text.contains(leak), "{leak} in the answer: {text}");
            }
            assert!(
                seen.lock().unwrap().is_empty(),
                "ok_calls={ok_calls} openai={openai}: a request reached the provider"
            );
            // and the probe sees it
            let r = reqwest::get(format!("{admin}/readyz")).await.unwrap();
            assert_eq!(r.status(), 503);
            assert!(r.text().await.unwrap().contains("HSM"));
        }
    }
}

// REQ: CFG-07 — the keys can be shared by the engines a bundle reload builds.
#[test]
fn engines_share_the_keys_of_the_pair() {
    let k = Flaky::new(i64::MAX);
    let pair = KeyPair {
        k_t: k.clone(),
        k_audit: Arc::new(HmacPrf::new(b"k-audit-0123456789abcdef")),
    };
    let a = TenantKeys::from_pair("a", &pair);
    let b = TenantKeys::from_pair("b", &pair);
    let mark = a.fault_mark();
    assert!(!b.faulted_since(b.fault_mark()));
    k.ok_calls.store(0, Ordering::SeqCst);
    let _ = a.k_t.mac(&[b"x"]);
    assert!(a.faulted_since(mark));
    assert!(!b.healthy() && !a.healthy());
}

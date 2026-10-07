#![allow(clippy::unwrap_used)]
//! QA-07 canary test: values that policy masks must not appear in provider traffic, audit,
//! metrics, logs, headers or error bodies. REQ: QA-07, SEC-01, INV-6, AUD-02, OBS-02.

use aegis_core::crypto::TenantKeys;
use aegis_core::detect::{DetectConfig, Dictionary};
use aegis_gateway::audit::Audit;
use aegis_gateway::engine::Engine;
use aegis_gateway::server::{admin_app, app, hash_key, AppState, Principal, Upstream};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::Router;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};

const CANARIES: &[&str] = &[
    "canary-7f3a.pay.corp.local",
    "CANARYsecretValue99!",
    "canary.person7f3a@corp.ru",
    "10.77.31.9",
    "svc_canary7f3a",
    "Канарейкин Пётр",
    "4539 1488 0343 6467",
];

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);
impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
    type Writer = Buf;
    fn make_writer(&'a self) -> Buf {
        self.clone()
    }
}

fn logs() -> &'static Buf {
    static L: OnceLock<Buf> = OnceLock::new();
    L.get_or_init(|| {
        let b = Buf::default();
        tracing_subscriber::fmt()
            .with_writer(b.clone())
            .with_max_level(tracing::Level::TRACE)
            .init();
        b
    })
}

async fn mock(
    State(seen): State<Arc<Mutex<Vec<Vec<u8>>>>>,
    _h: HeaderMap,
    body: Bytes,
) -> impl axum::response::IntoResponse {
    seen.lock().unwrap().push(body.to_vec());
    let resp = json!({"type": "message", "role": "assistant", "stop_reason": "end_turn", "content": [{"type": "text", "text": "ok"}]});
    (
        [("content-type", "application/json")],
        serde_json::to_vec(&resp).unwrap(),
    )
}

#[tokio::test]
async fn masked_values_appear_nowhere_but_the_clients_own_response() {
    let log_buf = logs().clone();
    let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let up = Router::new()
        .route("/v1/messages", post(mock))
        .with_state(seen.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, up).await.unwrap() });

    let keys = TenantKeys::from_secrets("t1", b"k-tenant-0123456789", b"k-audit-0123456789");
    let det = DetectConfig {
        internal_zones: vec!["corp.local".into()],
        service_account_patterns: vec![r"svc_canary\w+".into()],
        ..Default::default()
    };
    let mut dict = Dictionary::default();
    dict.add_person("Пётр", "Канарейкин");
    let mut vk = HashMap::new();
    vk.insert(
        hash_key("vk-canary"),
        Principal {
            id: "u:canary".into(),
            groups: vec![],
        },
    );
    let mut state = AppState::new(
        Engine::new(keys, det, dict),
        Some(Upstream::anthropic(
            format!("http://{up_addr}"),
            "provider-key",
        )),
        vk,
    );
    let audit_buf = Buf::default();
    state.audit = Audit::to_writer(audit_buf.clone(), 64, false);
    let state = Arc::new(state);

    let serve = |router: Router| async move {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
        a
    };
    let gw = serve(app(state.clone())).await;
    let admin = serve(admin_app(state.clone())).await;

    let text = format!(
        "host {}, owner {} <{}>, ip {}, user {}, password=\"{}\", card {}",
        CANARIES[0], CANARIES[5], CANARIES[2], CANARIES[3], CANARIES[4], CANARIES[1], CANARIES[6]
    );
    let c = reqwest::Client::new();
    let r = c
        .post(format!("http://{gw}/v1/messages"))
        .header("x-api-key", "vk-canary")
        .json(&json!({"model": "m", "messages": [{"role": "user", "content": text}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let headers: String = r
        .headers()
        .iter()
        .map(|(k, v)| format!("{k}: {}\n", v.to_str().unwrap_or("")))
        .collect();
    let body = r.text().await.unwrap();

    // error paths must not echo values either
    let r = c
        .post(format!("http://{gw}/v1/messages"))
        .header("x-api-key", "vk-canary")
        .json(&json!({"model": "m", "mcp_servers": [{"x": CANARIES[0]}], "messages": []}))
        .send()
        .await
        .unwrap();
    let err_body = r.text().await.unwrap();
    let r = c
        .post(format!("http://{gw}/v1/messages"))
        .header("x-api-key", "vk-canary")
        .body(format!("{{\"broken\": \"{}", CANARIES[1]))
        .send()
        .await
        .unwrap();
    let err_body2 = r.text().await.unwrap();

    // let the audit thread and tracing flush
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let metrics = c
        .get(format!("http://{admin}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let audit = String::from_utf8(audit_buf.0.lock().unwrap().clone()).unwrap();
    let logs = String::from_utf8(log_buf.0.lock().unwrap().clone()).unwrap();
    let provider: String = seen
        .lock()
        .unwrap()
        .iter()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .collect();

    assert!(
        !provider.is_empty() && !audit.is_empty() && !metrics.is_empty() && !logs.is_empty(),
        "every channel produced output"
    );
    for canary in CANARIES {
        for (name, haystack) in [
            ("provider", &provider),
            ("audit", &audit),
            ("metrics", &metrics),
            ("logs", &logs),
            ("headers", &headers),
            ("response", &body),
            ("error 1", &err_body),
            ("error 2", &err_body2),
        ] {
            assert!(!haystack.contains(canary), "{canary:?} leaked into {name}");
        }
    }
    // the audit is still useful: types, counts and hashes are there
    let ev: Value = serde_json::from_str(audit.lines().next().unwrap()).unwrap();
    assert_eq!(ev["decision"], "allow");
    let types: Vec<&str> = ev["entities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["type"].as_str().unwrap())
        .collect();
    for t in ["HOST", "SECRET", "EMAIL", "IP", "SVC", "PERSON", "CARD"] {
        assert!(types.contains(&t), "{t} missing in {types:?}");
    }
    assert!(ev["entities"]
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["audit_hash"].as_str().unwrap().len() == 16));
    assert!(metrics.contains("aegis_entities_total{class=\"SECRET\"}"));
}

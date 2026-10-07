#![allow(clippy::unwrap_used)]
//! REQ: DET-20, DET-21 — a block that looks like a closed repository is handled by the policy of
//! that repository's classification; a rebuilt index is picked up.

use aegis_core::crypto::TenantKeys;
use aegis_core::detect::{DetectConfig, Dictionary};
use aegis_core::fingerprint::{CodeIndex, Fingerprinter, Repo};
use aegis_gateway::code_index::{CodeGuard, CodeIndexConfig};
use aegis_gateway::engine::Engine;
use aegis_gateway::server::{app, hash_key, AppState, Principal, Upstream};
use axum::body::Bytes;
use axum::extract::State;
use axum::routing::post;
use axum::Router;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

const PUBLIC: &str = r#"
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut total = 0u64;
    for a in &args[1..] {
        match a.parse::<u64>() {
            Ok(n) => total += n,
            Err(e) => eprintln!("skipping {a}: {e}"),
        }
    }
    println!("sum = {total}");
    if total > 1000 { std::process::exit(2); }
}
"#;

fn index_file(dir: &std::path::Path, repos: &[(&str, &str, &str)]) -> String {
    let fp = Fingerprinter::new(TENANT);
    let mut ix = CodeIndex::new(&fp);
    for (name, class, code) in repos {
        ix.set_repo(
            Repo {
                name: (*name).into(),
                classification: (*class).into(),
            },
            fp.of(code).0,
        )
        .unwrap();
    }
    let p = dir.join("code.idx");
    std::fs::write(&p, ix.to_bytes()).unwrap();
    p.to_string_lossy().into()
}

fn dir() -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let d = std::env::temp_dir().join(format!(
        "aegis-idx-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

async fn provider() -> (String, Arc<Mutex<Vec<String>>>) {
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let r = Router::new()
        .route(
            "/v1/messages",
            post(|State(s): State<Arc<Mutex<Vec<String>>>>, b: Bytes| async move {
                s.lock().unwrap().push(String::from_utf8_lossy(&b).into());
                axum::Json(json!({"id": "m", "type": "message", "role": "assistant", "model": "m", "content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn", "usage": {"input_tokens": 1, "output_tokens": 1}}))
            }),
        )
        .with_state(seen.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, r).await.unwrap() });
    (url, seen)
}

async fn gateway(up: String, guard: Arc<CodeGuard>) -> String {
    let keys = TenantKeys::from_secrets("t1", TENANT, b"k-audit-secret-key");
    let engine =
        Engine::new(keys, DetectConfig::default(), Dictionary::default()).with_code(Some(guard));
    let mut vk = HashMap::new();
    vk.insert(
        hash_key("vk"),
        Principal {
            id: "u:x".into(),
            groups: vec![],
        },
    );
    let st = Arc::new(AppState::new(
        engine,
        Some(Upstream::anthropic(up, "k")),
        vk,
    ));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gw = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app(st)).await.unwrap() });
    gw
}

fn with_file(code: &str) -> Value {
    json!({"model": "m", "max_tokens": 8, "messages": [
        {"role": "user", "content": "look at the ledger"},
        {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "ledger.go"}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": code}]}]})
}

fn cfg(path: String, actions: &[(&str, &str)]) -> CodeIndexConfig {
    serde_json::from_value(json!({"path": path, "min_tokens": 30, "actions": actions.iter().cloned().collect::<HashMap<_, _>>()})).unwrap()
}

#[tokio::test]
async fn closed_code_is_dropped_blocked_or_only_noted_by_classification() {
    let d = dir();
    let path = index_file(&d, &[("payments", "closed", LEDGER)]);
    let (up, seen) = provider().await;
    let c = reqwest::Client::new();
    let ask = |gw: String, body: Value| {
        let c = c.clone();
        async move {
            c.post(format!("{gw}/v1/messages"))
                .header("x-api-key", "vk")
                .json(&body)
                .send()
                .await
                .unwrap()
        }
    };

    // drop_block: the model gets a notice instead of the file; the rest of the request goes
    let gw = gateway(
        up.clone(),
        CodeGuard::load(&cfg(path.clone(), &[("closed", "drop_block")]), TENANT).unwrap(),
    )
    .await;
    assert_eq!(ask(gw.clone(), with_file(LEDGER)).await.status(), 200);
    let sent = seen.lock().unwrap().pop().unwrap();
    assert!(
        sent.contains("блок не проверен и удалён")
            && !sent.contains("ErrDuplicate")
            && sent.contains("look at the ledger")
    );
    // public code goes through untouched
    assert_eq!(ask(gw, with_file(PUBLIC)).await.status(), 200);
    assert!(seen.lock().unwrap().pop().unwrap().contains("skipping"));

    // block_request: the whole request is refused and nothing is sent
    let before = seen.lock().unwrap().len();
    let gw = gateway(
        up.clone(),
        CodeGuard::load(&cfg(path.clone(), &[("closed", "block_request")]), TENANT).unwrap(),
    )
    .await;
    let r = ask(gw, with_file(LEDGER)).await;
    assert_eq!(r.status(), 403);
    assert!(r.text().await.unwrap().contains("DET-20"));
    assert_eq!(seen.lock().unwrap().len(), before);

    // warn is the default: the code goes, the audit would say so
    let gw = gateway(up, CodeGuard::load(&cfg(path, &[]), TENANT).unwrap()).await;
    assert_eq!(ask(gw, with_file(LEDGER)).await.status(), 200);
    assert!(seen.lock().unwrap().pop().unwrap().contains("ErrDuplicate"));
}

#[tokio::test]
async fn a_rebuilt_index_replaces_the_old_one_and_a_broken_file_does_not() {
    let d = dir();
    let path = index_file(&d, &[("other", "closed", PUBLIC)]);
    let guard =
        CodeGuard::load(&cfg(path.clone(), &[("closed", "block_request")]), TENANT).unwrap();
    guard.watch(Duration::from_millis(100));
    let (up, _seen) = provider().await;
    let gw = gateway(up, guard).await;
    let c = reqwest::Client::new();
    let status = |code: &'static str| {
        let (c, gw) = (c.clone(), gw.clone());
        async move {
            c.post(format!("{gw}/v1/messages"))
                .header("x-api-key", "vk")
                .json(&with_file(code))
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(status(LEDGER).await, 200, "not in the index yet");

    tokio::time::sleep(Duration::from_millis(1100)).await;
    std::fs::write(&path, b"damaged").unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        status(PUBLIC).await,
        403,
        "the old index stays when the new file does not load"
    );

    tokio::time::sleep(Duration::from_millis(1100)).await;
    index_file(
        &d,
        &[("other", "closed", PUBLIC), ("payments", "closed", LEDGER)],
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        status(LEDGER).await,
        403,
        "the repository added by the rebuild is now recognized"
    );
}

#[test]
fn a_wrong_key_or_a_missing_file_stops_the_gateway_from_starting() {
    let d = dir();
    let path = index_file(&d, &[("payments", "closed", LEDGER)]);
    assert!(CodeGuard::load(&cfg(path.clone(), &[]), b"some other tenant key").is_err());
    assert!(CodeGuard::load(
        &cfg(d.join("none.idx").to_string_lossy().into(), &[]),
        TENANT
    )
    .is_err());
    assert!(CodeGuard::load(&cfg(path.clone(), &[("closed", "explode")]), TENANT).is_err());
    let mut bad = cfg(path, &[]);
    bad.threshold = 0.0;
    assert!(CodeGuard::load(&bad, TENANT).is_err());
}

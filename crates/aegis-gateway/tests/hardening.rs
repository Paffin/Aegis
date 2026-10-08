#![allow(clippy::unwrap_used)]
//! REQ: SEC-10, NFR-13, IAM-02, SEC-01 — findings of the internal security review, kept as tests:
//! paths that climb, the unauthenticated wait for a body, a body that stalls, provider redirects,
//! values copied into the audit through the model name, and configuration typos.

use aegis_core::crypto::TenantKeys;
use aegis_core::detect::{DetectConfig, Dictionary};
use aegis_gateway::config::ServerConfig;
use aegis_gateway::engine::Engine;
use aegis_gateway::server::{app, hash_key, AppState, Principal, Upstream};
use axum::extract::State;
use axum::routing::any;
use axum::Router;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Seen = Arc<Mutex<Vec<String>>>;

async fn recorder() -> (String, Seen) {
    let seen: Seen = Arc::default();
    let r = Router::new()
        .fallback(any(
            |State(s): State<Seen>, uri: axum::http::Uri, h: axum::http::HeaderMap| async move {
                let key = h
                    .get("x-api-key")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                s.lock().unwrap().push(format!("{} key={key}", uri.path()));
                "{}"
            },
        ))
        .with_state(seen.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, r).await.unwrap() });
    (url, seen)
}

async fn gateway_with(up: String, tweak: impl FnOnce(&mut AppState)) -> String {
    let keys = TenantKeys::from_secrets("t1", b"k-tenant-0123456789", b"k-audit-0123456789");
    let engine = Engine::new(keys, DetectConfig::default(), Dictionary::default());
    let mut vk = HashMap::new();
    vk.insert(
        hash_key("vk"),
        Principal {
            id: "u:x".into(),
            groups: vec![],
        },
    );
    let mut st = AppState::new(
        engine,
        Some(Upstream::anthropic(up.clone(), "PROVIDER-SECRET")),
        vk,
    );
    st.gemini = Some(Upstream::gemini(up, "PROVIDER-SECRET"));
    tweak(&mut st);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app(Arc::new(st))).await.unwrap() });
    format!("127.0.0.1:{}", addr.port())
}

/// One raw HTTP exchange: nothing normalizes the path on the way.
async fn raw(addr: &str, request: &str, wait: Duration) -> String {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(request.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(wait, s.read(&mut buf)).await {
        Ok(Ok(n)) => String::from_utf8_lossy(&buf[..n]).to_string(),
        _ => "TIMEOUT".into(),
    }
}

fn status_of(resp: &str) -> &str {
    resp.split_whitespace().nth(1).unwrap_or("none")
}

#[tokio::test]
async fn paths_that_climb_never_reach_the_provider() {
    let (up, seen) = recorder().await;
    let gw = gateway_with(up, |_| {}).await;
    for path in [
        "/v1/models/../files/file_abc/content",
        "/v1/models/%2e%2e/messages/batches/X/results",
        "/v1/models/%2E%2E%2Ffiles",
        "/v1beta/models/../cachedContents",
        "/v1beta/models/x/../../../other/v1/y:generateContent",
        "/v1beta/models/a%2fb:generateContent",
        "/v1beta/models/a%5cb:generateContent",
        "/v1beta/models/..:generateContent",
        "/v1/models/a\\b",
    ] {
        let r = raw(
            &gw,
            &format!(
                "GET {path} HTTP/1.1\r\nHost: x\r\nx-api-key: vk\r\nConnection: close\r\n\r\n"
            ),
            Duration::from_secs(3),
        )
        .await;
        assert_eq!(status_of(&r), "400", "{path}: {r}");
    }
    assert!(
        seen.lock().unwrap().is_empty(),
        "{:?}",
        seen.lock().unwrap()
    );
    // the ordinary forms still work
    let r = raw(
        &gw,
        "GET /v1/models/claude-x HTTP/1.1\r\nHost: x\r\nx-api-key: vk\r\nConnection: close\r\n\r\n",
        Duration::from_secs(3),
    )
    .await;
    assert_eq!(status_of(&r), "200", "{r}");
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn gemini_model_names_are_names_only() {
    let (up, seen) = recorder().await;
    let gw = gateway_with(up, |_| {}).await;
    for path in [
        "/v1beta/models/gem ini:generateContent",
        "/v1beta/models/x$y:generateContent",
        "/v1beta/models/a/b:generateContent",
    ] {
        let r = raw(&gw, &format!("POST {} HTTP/1.1\r\nHost: x\r\nx-goog-api-key: vk\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}", path.replace(' ', "%20")), Duration::from_secs(3)).await;
        assert!(matches!(status_of(&r), "400" | "404"), "{path}: {r}");
    }
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn nobody_without_a_key_makes_the_gateway_wait_for_a_body() {
    let (up, _) = recorder().await;
    // room for one request: a stranger must not be able to take it
    let gw = gateway_with(up, |st| {
        st.limiter = Arc::new(tokio::sync::Semaphore::new(1))
    })
    .await;
    let big = "POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Length: 67108864\r\nContent-Type: application/json\r\n\r\n{\"a\":";
    // the answer comes at once, before any body
    let r = raw(&gw, big, Duration::from_secs(2)).await;
    assert_eq!(status_of(&r), "401", "{r}");
    // a key that is wrong is no better
    let r = raw(
        &gw,
        &big.replace("Host: x", "Host: x\r\nx-api-key: nope"),
        Duration::from_secs(2),
    )
    .await;
    assert_eq!(status_of(&r), "401", "{r}");
    // and the one place is still free for the owner of a key
    let body =
        json!({"model": "m", "max_tokens": 4, "messages": [{"role": "user", "content": "hi"}]})
            .to_string();
    let ok = format!("POST /v1/messages HTTP/1.1\r\nHost: x\r\nx-api-key: vk\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    assert_eq!(
        status_of(&raw(&gw, &ok, Duration::from_secs(3)).await),
        "200"
    );
}

#[tokio::test]
async fn a_body_that_stops_arriving_is_cut_off_and_frees_its_place() {
    let (up, _) = recorder().await;
    let gw = gateway_with(up, |st| {
        st.limiter = Arc::new(tokio::sync::Semaphore::new(1));
        st.body_idle = Duration::from_millis(300);
    })
    .await;
    // an authenticated client that sends half a body and goes quiet
    let mut s = tokio::net::TcpStream::connect(&gw).await.unwrap();
    s.write_all(b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nx-api-key: vk\r\nContent-Length: 1000\r\n\r\n{\"model\":").await.unwrap();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let r = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(matches!(status_of(&r), "400" | "408"), "{r}");
    // the place is free again
    let body =
        json!({"model": "m", "max_tokens": 4, "messages": [{"role": "user", "content": "hi"}]})
            .to_string();
    let ok = format!("POST /v1/messages HTTP/1.1\r\nHost: x\r\nx-api-key: vk\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    assert_eq!(
        status_of(&raw(&gw, &ok, Duration::from_secs(3)).await),
        "200"
    );
}

#[tokio::test]
async fn a_redirect_from_the_provider_is_not_followed() {
    let (thief, stolen) = recorder().await;
    let target = thief.clone();
    let r = Router::new().fallback(any(move || {
        let t = target.clone();
        async move {
            axum::response::Response::builder()
                .status(307)
                .header("location", format!("{t}/steal"))
                .body(axum::body::Body::empty())
                .unwrap()
        }
    }));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, r).await.unwrap() });
    let gw = gateway_with(up, |_| {}).await;
    let body =
        json!({"model": "m", "max_tokens": 4, "messages": [{"role": "user", "content": "hi"}]})
            .to_string();
    let req = format!("POST /v1/messages HTTP/1.1\r\nHost: x\r\nx-api-key: vk\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    let _ = raw(&gw, &req, Duration::from_secs(3)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        stolen.lock().unwrap().is_empty(),
        "the provider key and the request went to {:?}",
        stolen.lock().unwrap()
    );
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

#[tokio::test]
async fn a_value_put_in_the_model_name_or_the_user_agent_does_not_reach_the_audit() {
    let (up, _) = recorder().await;
    let buf = Buf::default();
    let b2 = buf.clone();
    let gw = gateway_with(up, move |st| {
        st.audit = aegis_gateway::audit::Audit::to_writer(b2, 100, false)
    })
    .await;
    let key = "AKIAJ3KQ7P2WXNB5ZT4A";
    let body =
        json!({"model": key, "max_tokens": 4, "messages": [{"role": "user", "content": "hi"}]})
            .to_string();
    let req = format!("POST /v1/messages HTTP/1.1\r\nHost: x\r\nx-api-key: vk\r\nUser-Agent: {key}/1.0\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    let r = raw(&gw, &req, Duration::from_secs(3)).await;
    assert_eq!(status_of(&r), "403", "{r}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let audit = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(audit.contains("rejected"), "{audit}");
    assert!(!audit.contains(key) && !audit.contains("AKIA"), "{audit}");
}

#[test]
fn a_typo_in_the_configuration_is_an_error() {
    for bad in [
        r#"{"tsl": {"cert_file": "a", "key_file": "b"}}"#,
        r#"{"audit_requird": true}"#,
        r#"{"upstream_ca": "x"}"#,
    ] {
        assert!(serde_json::from_str::<ServerConfig>(bad).is_err(), "{bad}");
    }
    assert!(serde_json::from_str::<ServerConfig>(r#"{"audit_required": true}"#).is_ok());
}

#[tokio::test]
async fn a_value_in_the_gemini_model_name_is_not_sent_to_the_provider() {
    let (up, seen) = recorder().await;
    let gw = gateway_with(up, |_| {}).await;
    let r = raw(&gw, "POST /v1beta/models/AKIAJ3KQ7P2WXNB5ZT4A:generateContent HTTP/1.1\r\nHost: x\r\nx-goog-api-key: vk\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}", Duration::from_secs(3)).await;
    assert_eq!(status_of(&r), "400", "{r}");
    assert!(seen.lock().unwrap().is_empty());
}

// REQ: RTE-01 — counting tokens goes to the provider the route names, not always to the default.
#[tokio::test]
async fn count_tokens_follows_the_route() {
    let (default_up, default_seen) = recorder().await;
    let (team_up, team_seen) = recorder().await;
    let gw = gateway_with(default_up, move |st| {
        st.routes = vec![aegis_gateway::server::Route {
            name: "team".into(),
            family: aegis_gateway::server::Family::Anthropic,
            models: vec!["team-*".into()],
            groups: vec![],
            reroute_only: false,
            model: None,
            context_tokens: None,
            upstream: Upstream::anthropic(team_up, "TEAM-KEY"),
        }];
    })
    .await;
    for (model, _) in [("team-large", 0), ("other", 1)] {
        let body =
            json!({"model": model, "messages": [{"role": "user", "content": "hi"}]}).to_string();
        let req = format!("POST /v1/messages/count_tokens HTTP/1.1\r\nHost: x\r\nx-api-key: vk\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        assert_eq!(
            status_of(&raw(&gw, &req, Duration::from_secs(3)).await),
            "200"
        );
    }
    assert_eq!(team_seen.lock().unwrap().len(), 1);
    assert!(team_seen.lock().unwrap()[0].contains("TEAM-KEY"));
    assert_eq!(default_seen.lock().unwrap().len(), 1);
    assert!(default_seen.lock().unwrap()[0].contains("PROVIDER-SECRET"));
}

// SEC-10 — one address cannot hold more connections than allowed, and a closed one gives its place back.
#[tokio::test]
async fn connections_per_address_are_limited() {
    let router = Router::new().route("/", any(|| async { "ok" }));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(aegis_gateway::tls::serve_limited(
        l,
        router,
        None,
        2,
        std::future::pending(),
    ));
    let a = tokio::net::TcpStream::connect(addr).await.unwrap();
    let b = tokio::net::TcpStream::connect(addr).await.unwrap();
    // the third is accepted by the kernel and closed by the gateway
    let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf))
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(n, 0, "closed without an answer");
    // a place comes back when a connection ends
    drop(a);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let r = raw(
        &addr.to_string(),
        "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        Duration::from_secs(2),
    )
    .await;
    assert_eq!(status_of(&r), "200", "{r}");
    drop(b);
}

// REQ: CFG-05, CFG-07 — the real binary takes its keys from a program (a vault, KMS or HSM client), and
// `check` reports a key file that others can read.
#[cfg(unix)]
#[test]
fn keys_from_a_command_and_the_mode_of_a_key_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("aegis-keys-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("gw.json");
    std::fs::write(&cfg, format!(r#"{{"listen":"127.0.0.1:0","admin_listen":"127.0.0.1:0","anthropic_base_url":"http://127.0.0.1:1","virtual_keys":[{{"sha256":"{}","principal":"u:x"}}]}}"#, "ab".repeat(32))).unwrap();
    let bin = env!("CARGO_BIN_EXE_aegis-gateway");
    let check = |envs: &[(&str, &str)]| {
        let mut c = std::process::Command::new(bin);
        c.arg("check")
            .arg(&cfg)
            .env_clear()
            .env("AEGIS_ANTHROPIC_KEY", "provider-key")
            .env("PATH", std::env::var("PATH").unwrap());
        for (k, v) in envs {
            c.env(k, v);
        }
        let o = c.output().unwrap();
        (
            o.status.success(),
            String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr),
        )
    };
    // both keys from commands: nothing in the environment or on disk
    let (ok, out) = check(&[
        (
            "AEGIS_K_TENANT_COMMAND",
            "printf 'tenant-key-0123456789abc'",
        ),
        ("AEGIS_K_AUDIT_COMMAND", "printf 'audit-key-0123456789abcd'"),
    ]);
    assert!(ok, "{out}");
    // a command that fails is a missing key, and its error output does not appear
    let (ok, out) = check(&[
        (
            "AEGIS_K_TENANT_COMMAND",
            "sh -c 'echo LEAKED-IN-STDERR >&2; exit 1'",
        ),
        ("AEGIS_K_AUDIT_COMMAND", "printf 'audit-key-0123456789abcd'"),
    ]);
    assert!(!ok && !out.contains("LEAKED-IN-STDERR"), "{out}");
    // a key file open to others
    let f = dir.join("tenant.key");
    std::fs::write(&f, "tenant-key-0123456789abc").unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (ok, out) = check(&[
        ("AEGIS_K_TENANT_FILE", f.to_str().unwrap()),
        ("AEGIS_K_AUDIT_COMMAND", "printf 'audit-key-0123456789abcd'"),
    ]);
    assert!(!ok && out.contains("644"), "{out}");
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o400)).unwrap();
    let (ok, out) = check(&[
        ("AEGIS_K_TENANT_FILE", f.to_str().unwrap()),
        ("AEGIS_K_AUDIT_COMMAND", "printf 'audit-key-0123456789abcd'"),
    ]);
    assert!(ok, "{out}");
}

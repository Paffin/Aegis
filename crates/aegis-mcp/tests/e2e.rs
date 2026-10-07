#![allow(clippy::unwrap_used)]
//! REQ: MCP-01, MCP-02, MCP-03, MCP-04 — the real `aegis-mcp` binary in front of a real (mock)
//! MCP server over stdio, and the HTTP proxy in front of a Streamable HTTP server.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

const CFG: &str = r#"
version: 1
audit_path: AUDIT
servers:
  tracker:
    url: URL
    tools:
      allow: [get_issue, list_issues, query]
      sql_read_only: { query: [sql] }
    results:
      drop_fields: [email]
"#;

fn scratch(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("aegis-mcp-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn script() -> String {
    format!("{}/../../scripts/mock_mcp.py", env!("CARGO_MANIFEST_DIR"))
}

fn call(id: u64, tool: &str, args: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": args}})
}

#[test]
fn stdio_proxy_in_front_of_a_real_server() {
    let d = scratch("stdio");
    let (cfg, audit, mark) = (
        d.join("mcp.yaml"),
        d.join("audit.jsonl"),
        d.join("mark.txt"),
    );
    std::fs::write(
        &cfg,
        CFG.replace("AUDIT", audit.to_str().unwrap())
            .replace("URL", "http://unused"),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_aegis-mcp"))
        .args([
            "stdio",
            "--config",
            cfg.to_str().unwrap(),
            "--server",
            "tracker",
            "--",
            "python3",
            &script(),
            mark.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut ask = |m: Value| -> Value {
        writeln!(stdin, "{m}").unwrap();
        stdin.flush().unwrap();
        let mut line = String::new();
        out.read_line(&mut line).unwrap();
        // the server's non-JSON log line was dropped: the first thing read is an answer
        serde_json::from_str(&line).unwrap_or_else(|_| panic!("not JSON: {line:?}"))
    };

    assert_eq!(
        ask(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}))["result"]
            ["serverInfo"]["name"],
        "mock"
    );
    let list = ask(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["get_issue", "list_issues", "query"]);

    // minimized result
    let r = ask(call(3, "get_issue", json!({})));
    let text = r["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("Ann") && !text.contains("corp.local"),
        "{text}"
    );
    let r = ask(call(4, "list_issues", json!({})));
    assert_eq!(
        r["result"]["content"][0]["text"],
        "id,title\n1,crash\n2,slow\n"
    );

    // refused calls never reach the server
    let r = ask(call(5, "delete_repo", json!({})));
    assert_eq!(r["result"]["isError"], true);
    let r = ask(call(6, "query", json!({"sql": "DROP TABLE users"})));
    assert!(r["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("M-03"));
    // a read does
    let r = ask(call(7, "query", json!({"sql": "SELECT 1"})));
    assert_eq!(r["result"]["content"][0]["text"], "ok");
    // a line that is not JSON from the client gets a parse error, not a forward
    writeln!(stdin, "this is not json").unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    out.read_line(&mut line).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&line).unwrap()["error"]["code"],
        -32700
    );

    drop(stdin);
    assert!(child.wait().unwrap().success());
    let marks = std::fs::read_to_string(&mark).unwrap();
    assert_eq!(
        marks.trim(),
        "query: SELECT 1",
        "only the read was executed, delete_repo and DROP never were"
    );
    let audit = std::fs::read_to_string(&audit).unwrap();
    assert!(
        audit.contains("\"decision\":\"deny\"")
            && audit.contains("M-01")
            && audit.contains("M-03")
            && audit.contains("hide")
    );
    assert!(
        !audit.contains("DROP TABLE") && !audit.contains("ann@corp.local"),
        "no argument or result in the audit"
    );
}

// ---- Streamable HTTP -----------------------------------------------------------------------

use axum::body::Body;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use bytes::Bytes;

async fn http_server(sse: bool) -> (String, std::sync::Arc<std::sync::Mutex<Vec<Value>>>) {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
    let s2 = seen.clone();
    let router = Router::new().route(
        "/mcp",
        post(move |h: HeaderMap, b: Bytes| {
            let seen = s2.clone();
            async move {
                let m: Value = serde_json::from_slice(&b).unwrap();
                seen.lock().unwrap().push(json!({"msg": m, "auth": h.get("authorization").map(|v| v.to_str().unwrap().to_string())}));
                let id = m["id"].clone();
                let result = match m["method"].as_str() {
                    Some("tools/list") => json!({"tools": [{"name": "get_issue"}, {"name": "delete_repo"}]}),
                    Some("tools/call") => json!({"content": [{"type": "text", "text": json!({"title": "t", "email": "a@b"}).to_string()}]}),
                    _ => json!({}),
                };
                let reply = json!({"jsonrpc": "2.0", "id": id, "result": result});
                if sse {
                    let body = format!("event: message\ndata: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}}\n\nevent: message\ndata: {reply}\n\n");
                    Response::builder().header("content-type", "text/event-stream").header("mcp-session-id", "s-1").body(Body::from(body)).unwrap()
                } else {
                    Response::builder().header("content-type", "application/json").header("mcp-session-id", "s-1").body(Body::from(reply.to_string())).unwrap()
                }
            }
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/mcp", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
    (url, seen)
}

async fn proxy(url: &str) -> String {
    std::env::set_var("AEGIS_MCP_TEST_TOKEN", "Bearer upstream-token");
    let yaml = format!(
        "version: 1\nservers:\n  tracker:\n    url: {url}\n    headers_env: {{ Authorization: AEGIS_MCP_TEST_TOKEN }}\n    tools:\n      allow: [get_issue]\n    results:\n      drop_fields: [email]\n"
    );
    let cfg = std::sync::Arc::new(aegis_mcp::config::Config::from_yaml(&yaml).unwrap());
    let app = aegis_mcp::http::app(cfg, aegis_mcp::audit::Audit::discard());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://{addr}/tracker")
}

async fn exercise(sse: bool) {
    let (up, seen) = http_server(sse).await;
    let url = proxy(&up).await;
    let c = reqwest::Client::new();
    let post = |m: Value| {
        let c = c.clone();
        let url = url.clone();
        async move {
            c.post(url)
                .header("accept", "application/json, text/event-stream")
                .json(&m)
                .send()
                .await
                .unwrap()
        }
    };
    // the list loses the tool that is not allowed; the session header comes through
    let r = post(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})).await;
    assert_eq!(r.headers()["mcp-session-id"], "s-1");
    let text = r.text().await.unwrap();
    assert!(
        text.contains("get_issue") && !text.contains("delete_repo"),
        "{text}"
    );
    // the result loses the field
    let text = post(call(2, "get_issue", json!({})))
        .await
        .text()
        .await
        .unwrap();
    assert!(
        text.contains("\\\"title\\\"") && !text.contains("a@b"),
        "{text}"
    );
    // a refused call is answered by the proxy and never sent
    let before = seen.lock().unwrap().len();
    let text = post(call(3, "delete_repo", json!({})))
        .await
        .text()
        .await
        .unwrap();
    assert!(text.contains("M-01") && text.contains("isError"), "{text}");
    assert_eq!(seen.lock().unwrap().len(), before);
    // the server's credentials come from the proxy's environment, not from the client
    assert_eq!(seen.lock().unwrap()[0]["auth"], "Bearer upstream-token");
    // unknown server, and a body that is not JSON
    assert_eq!(
        c.post(url.replace("tracker", "nobody"))
            .body("{}")
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        c.post(&url).body("not json").send().await.unwrap().status(),
        400
    );
}

#[tokio::test]
async fn http_proxy_with_json_answers() {
    exercise(false).await;
}

#[tokio::test]
async fn http_proxy_with_event_stream_answers() {
    exercise(true).await;
}

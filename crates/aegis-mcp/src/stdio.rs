//! REQ: MCP-01 — the stdio proxy: `aegis-mcp stdio --server NAME -- command args…` starts the
//! MCP server as a child process and stands between it and the client that started `aegis-mcp`.

use crate::audit::Audit;
use crate::config::Config;
use crate::filter::Filter;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

/// A parse error answer for a line that is not JSON (id is unknown).
fn parse_error() -> Value {
    json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "Aegis: сообщение не является JSON"}})
}

/// Run the proxy over arbitrary streams: `client_in`/`client_out` face the client,
/// `server_in`/`server_out` the server. Returns when both directions are finished.
pub async fn pump<CI, CO, SI, SO>(
    filter: Filter,
    client_in: CI,
    client_out: CO,
    server_in: SI,
    server_out: SO,
) where
    CI: AsyncRead + Unpin + Send + 'static,
    CO: AsyncWrite + Unpin + Send + 'static,
    SI: AsyncWrite + Unpin + Send + 'static,
    SO: AsyncRead + Unpin + Send + 'static,
{
    let filter = Arc::new(std::sync::Mutex::new(filter));
    let (out_tx, mut out_rx) = mpsc::channel::<Value>(64);
    let writer = tokio::spawn(async move {
        let mut w = client_out;
        while let Some(v) = out_rx.recv().await {
            if w.write_all(format!("{v}\n").as_bytes()).await.is_err() || w.flush().await.is_err() {
                break;
            }
        }
    });

    // client → server
    let f1 = filter.clone();
    let tx1 = out_tx.clone();
    let up = tokio::spawn(async move {
        let mut server_in = server_in;
        let mut lines = BufReader::new(client_in).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if line.trim().is_empty() {
                continue;
            }
            let Ok(msg) = serde_json::from_str::<Value>(&line) else {
                let _ = tx1.send(parse_error()).await;
                continue;
            };
            let outcome = f1.lock().map(|mut f| f.client(msg)).unwrap_or_default();
            for a in outcome.answers {
                let _ = tx1.send(a).await;
            }
            if let Some(m) = outcome.forward {
                if server_in
                    .write_all(format!("{m}\n").as_bytes())
                    .await
                    .is_err()
                {
                    break;
                }
                let _ = server_in.flush().await;
            }
        }
        // the client is gone: tell the server (stdin closes when `server_in` is dropped)
        drop(server_in);
    });

    // server → client
    let f2 = filter;
    let down = tokio::spawn(async move {
        let mut lines = BufReader::new(server_out).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if line.trim().is_empty() {
                continue;
            }
            // a line that is not JSON (a server that logs to its stdout) is not passed on: it
            // could carry content that no rule has seen
            let Ok(msg) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if let Some(m) = f2.lock().ok().and_then(|mut f| f.server(msg)) {
                if out_tx.send(m).await.is_err() {
                    break;
                }
            }
        }
    });
    let _ = down.await;
    up.abort();
    let _ = writer.await;
}

/// Start the server command and proxy it over our own stdin and stdout. Returns its exit code.
pub async fn run(
    cfg: Arc<Config>,
    server: &str,
    command: &[String],
    audit: Audit,
) -> Result<i32, String> {
    let s = cfg
        .servers
        .get(server)
        .ok_or_else(|| format!("в конфигурации нет сервера «{server}»"))?;
    let (prog, args) = command.split_first().ok_or("не указана команда сервера")?;
    let mut child = tokio::process::Command::new(prog)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("не удалось запустить {prog}: {e}"))?;
    let (Some(sin), Some(sout)) = (child.stdin.take(), child.stdout.take()) else {
        return Err("нет каналов ввода-вывода у сервера".into());
    };
    let filter = Filter::new(s.clone(), audit);
    pump(filter, tokio::io::stdin(), tokio::io::stdout(), sin, sout).await;
    let status = child.wait().await.map_err(|e| e.to_string())?;
    Ok(status.code().unwrap_or(1))
}

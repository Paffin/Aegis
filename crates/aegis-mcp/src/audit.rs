//! Decisions of `aegis-mcp`, JSON lines. Names of servers and tools, the rule, the reason, sizes;
//! never an argument value or a result.

use serde_json::json;
use std::io::Write;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Audit {
    out: Arc<Mutex<Box<dyn Write + Send>>>,
}

impl Audit {
    pub fn to_writer(w: Box<dyn Write + Send>) -> Self {
        Self {
            out: Arc::new(Mutex::new(w)),
        }
    }

    pub fn open(path: Option<&str>) -> std::io::Result<Self> {
        Ok(match path {
            Some(p) => Self::to_writer(Box::new(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)?,
            )),
            None => Self::to_writer(Box::new(std::io::stderr())),
        })
    }

    pub fn discard() -> Self {
        Self::to_writer(Box::new(std::io::sink()))
    }

    /// `decision`: `allow`, `deny`, `hide` (tool left out of a list) or `minimize`.
    pub fn event(&self, server: &str, tool: &str, decision: &str, rule: &str, detail: &str) {
        let line = json!({
            "ts": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
            "component": "aegis-mcp", "server": server, "tool": tool, "decision": decision, "rule": rule, "detail": detail,
        });
        if let Ok(mut w) = self.out.lock() {
            let _ = writeln!(w, "{line}");
            let _ = w.flush();
        }
    }
}

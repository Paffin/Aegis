//! REQ: OBS-03 — OpenTelemetry traces by stage, without bodies.
//!
//! One trace per request: a root span and a span per stage (`parse`, `detect`, `transform`,
//! `upstream`, `response`). Attributes are counts, sizes, names of routes, models and decisions;
//! never a value, a pseudonym or a text. The export is OTLP over HTTP with JSON, in batches, and
//! it never delays or fails a request: a full queue or an unreachable collector drops spans.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::sync::mpsc;

/// W3C `traceparent`: `00-<trace id 32 hex>-<parent span id 16 hex>-<flags>`.
pub fn parse_traceparent(h: &str) -> Option<([u8; 16], [u8; 8])> {
    let mut p = h.trim().split('-');
    let (ver, tid, sid, _flags) = (p.next()?, p.next()?, p.next()?, p.next()?);
    if ver.len() != 2 || tid.len() != 32 || sid.len() != 16 || ver == "ff" {
        return None;
    }
    let tid = hex_array::<16>(tid)?;
    let sid = hex_array::<8>(sid)?;
    (tid != [0; 16] && sid != [0; 8]).then_some((tid, sid))
}

fn hex_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// What the gateway knows about one finished request.
#[derive(Debug, Clone)]
pub struct Finished {
    pub request_id: String,
    /// From the client's `traceparent`, if it sent one.
    pub parent: Option<([u8; 16], [u8; 8])>,
    pub start_unix_ns: u64,
    pub total_ms: f64,
    pub upstream_ms: f64,
    /// (stage, milliseconds) of the request side: parse, detect, transform.
    pub stages: Vec<(&'static str, f64)>,
    pub route: String,
    pub model: String,
    pub client: String,
    pub decision: &'static str,
    pub request_bytes: usize,
    pub blocks: u32,
    pub entities: u32,
    pub denied: u32,
}

fn attr(k: &str, v: Value) -> Value {
    let value = match v {
        Value::String(s) => json!({"stringValue": s}),
        Value::Number(n) if n.is_f64() => json!({"doubleValue": n}),
        Value::Number(n) => json!({"intValue": n.to_string()}),
        Value::Bool(b) => json!({"boolValue": b}),
        other => json!({"stringValue": other.to_string()}),
    };
    json!({"key": k, "value": value})
}

/// (trace id, span id, parent span id) in hex.
struct Ids<'a>(&'a str, &'a str, &'a str);

fn span(
    ids: Ids<'_>,
    name: &str,
    kind: u8,
    window: (u64, u64),
    attrs: Vec<Value>,
    ok: bool,
) -> Value {
    json!({
        "traceId": ids.0, "spanId": ids.1, "parentSpanId": ids.2, "name": name, "kind": kind,
        "startTimeUnixNano": window.0.to_string(), "endTimeUnixNano": window.1.to_string(),
        "attributes": attrs, "status": {"code": if ok { 1 } else { 2 }},
    })
}

fn ids(seed: &str) -> ([u8; 16], impl Fn(&str) -> [u8; 8]) {
    let t = Sha256::digest(format!("trace:{seed}").as_bytes());
    let mut tid = [0u8; 16];
    tid.copy_from_slice(&t[..16]);
    let seed = seed.to_string();
    (tid, move |n: &str| {
        let d = Sha256::digest(format!("span:{seed}:{n}").as_bytes());
        let mut s = [0u8; 8];
        s.copy_from_slice(&d[..8]);
        s
    })
}

/// The OTLP spans of one request.
pub fn spans(f: &Finished) -> Vec<Value> {
    let (own_tid, sid) = ids(&f.request_id);
    let (tid, parent) = match f.parent {
        Some((t, p)) => (t, hex(&p)),
        None => (own_tid, String::new()),
    };
    let trace = hex(&tid);
    let root_id = hex(&sid("root"));
    let ns = |ms: f64| (ms.max(0.0) * 1_000_000.0) as u64;
    let end = f.start_unix_ns + ns(f.total_ms);
    let mut out = vec![span(
        Ids(&trace, &root_id, &parent),
        "aegis.request",
        2,
        (f.start_unix_ns, end),
        vec![
            attr("aegis.request_id", json!(f.request_id)),
            attr("aegis.route", json!(f.route)),
            attr("aegis.model", json!(f.model)),
            attr("aegis.client", json!(f.client)),
            attr("aegis.decision", json!(f.decision)),
            attr("aegis.request_bytes", json!(f.request_bytes)),
            attr("aegis.blocks", json!(f.blocks)),
            attr("aegis.entities", json!(f.entities)),
            attr("aegis.denied", json!(f.denied)),
        ],
        f.decision == "allow",
    )];
    let mut t = f.start_unix_ns;
    let mut stages: Vec<(&str, f64)> = f.stages.clone();
    stages.push(("upstream", f.upstream_ms));
    let used: f64 = stages.iter().map(|s| s.1).sum();
    stages.push(("response", (f.total_ms - used).max(0.0)));
    for (name, ms) in stages {
        let e = (t + ns(ms)).min(end.max(t));
        out.push(span(
            Ids(&trace, &hex(&sid(name)), &root_id),
            &format!("aegis.{name}"),
            1,
            (t, e),
            vec![attr("aegis.stage", json!(name))],
            true,
        ));
        t = e;
    }
    out
}

/// The OTLP/HTTP JSON body for a batch.
pub fn body(batch: &[Finished]) -> Value {
    let all: Vec<Value> = batch.iter().flat_map(spans).collect();
    json!({"resourceSpans": [{
        "resource": {"attributes": [attr("service.name", json!("aegis-gateway")), attr("service.version", json!(env!("CARGO_PKG_VERSION")))]},
        "scopeSpans": [{"scope": {"name": "aegis"}, "spans": all}],
    }]})
}

/// Queue to the exporter task.
#[derive(Clone)]
pub struct Tracer {
    tx: mpsc::Sender<Finished>,
    dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl Tracer {
    /// Start the exporter. `headers` go with every export (an `Authorization` of the collector).
    pub fn start(endpoint: String, headers: Vec<(String, String)>, http: reqwest::Client) -> Self {
        let (tx, rx) = mpsc::channel(4096);
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let url = format!("{}/v1/traces", endpoint.trim_end_matches('/'));
        tokio::spawn(export_loop(rx, url, headers, http));
        Self { tx, dropped }
    }

    /// Never waits: with a full queue the trace is dropped.
    pub fn emit(&self, f: Finished) {
        if self.tx.try_send(f).is_err() {
            self.dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }
}

async fn export_loop(
    mut rx: mpsc::Receiver<Finished>,
    url: String,
    headers: Vec<(String, String)>,
    http: reqwest::Client,
) {
    let mut batch: Vec<Finished> = Vec::new();
    loop {
        let first = rx.recv().await;
        match first {
            Some(f) => batch.push(f),
            None => return,
        }
        // collect what arrives in the next moments, up to a batch
        let deadline = tokio::time::sleep(Duration::from_millis(500));
        tokio::pin!(deadline);
        while batch.len() < 128 {
            tokio::select! {
                f = rx.recv() => match f { Some(f) => batch.push(f), None => break },
                _ = &mut deadline => break,
            }
        }
        let mut req = http
            .post(&url)
            .timeout(Duration::from_secs(5))
            .json(&body(&batch));
        for (k, v) in &headers {
            req = req.header(k, v);
        }
        // a collector that is down costs the spans, not the traffic
        if let Err(e) = req.send().await.and_then(|r| r.error_for_status()) {
            tracing::warn!(error = %e.without_url(), "trace export failed, spans dropped");
        }
        batch.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: OBS-03
    #[test]
    fn traceparent_is_parsed_strictly() {
        let ok =
            parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").unwrap();
        assert_eq!(hex(&ok.0), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(hex(&ok.1), "00f067aa0ba902b7");
        for bad in [
            "",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e47zz-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902-01",
        ] {
            assert!(parse_traceparent(bad).is_none(), "{bad}");
        }
    }
}

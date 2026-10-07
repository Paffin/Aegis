//! Load test: concurrent streams and request rate through a real gateway, over real HTTP.
//! REQ: NFR-03, NFR-04, T0-09.
//!
//! A mock provider answers with a slow SSE stream (first event at once, then one delta per
//! `--delta-ms`). The gateway runs in this process. Requests carry a long agent conversation
//! (a file corpus, as in `perf`). The first phase compares time to first byte with and without
//! the gateway; the second keeps a request rate for a while and counts the streams in flight.
//! Load generator, gateway and mock share the machine, so the numbers are conservative for the
//! gateway's own CPU and optimistic for the network.

use aegis_core::crypto::TenantKeys;
use aegis_core::detect::{DetectConfig, Dictionary};
use aegis_gateway::engine::Engine;
use aegis_gateway::server::{app, hash_key, AppState, Principal, Upstream};
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::Router;
use bytes::Bytes;
use futures_util::StreamExt;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct Opts {
    pub kb: usize,
    pub rps: u32,
    pub seconds: u64,
    pub stream_secs: u64,
    pub ttfb_samples: usize,
    pub max_ttfb_overhead_p95_ms: Option<f64>,
    pub min_streams: Option<usize>,
}

fn pct(v: &mut [f64], p: f64) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    v[((v.len() as f64 * p).ceil() as usize).clamp(1, v.len()) - 1]
}

fn status_kb(field: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with(field))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|n| n.parse().ok()))
        })
        .unwrap_or(0)
}

struct Mock {
    deltas: usize,
    delta_ms: u64,
}

async fn mock_messages(State(m): State<Arc<Mock>>, body: Bytes) -> Response {
    drop(body);
    let (deltas, delta_ms) = (m.deltas, m.delta_ms);
    let stream = async_stream(deltas, delta_ms);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from_stream(stream))
        .unwrap_or_default()
}

fn ev(name: &str, data: Value) -> Bytes {
    Bytes::from(format!("event: {name}\ndata: {data}\n\n"))
}

fn async_stream(
    deltas: usize,
    delta_ms: u64,
) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> {
    futures_util::stream::unfold(0usize, move |i| async move {
        if i > deltas + 4 {
            return None;
        }
        if i >= 2 && i < deltas + 2 {
            tokio::time::sleep(Duration::from_millis(delta_ms)).await;
        }
        let item = match i {
            0 => ev(
                "message_start",
                json!({"type": "message_start", "message": {"id": "m", "type": "message", "role": "assistant", "content": [], "model": "m", "stop_reason": null, "usage": {"input_tokens": 1, "output_tokens": 1}}}),
            ),
            1 => ev(
                "content_block_start",
                json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
            ),
            n if n < deltas + 2 => ev(
                "content_block_delta",
                json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": format!("часть {n} ")}}),
            ),
            n if n == deltas + 2 => ev(
                "content_block_stop",
                json!({"type": "content_block_stop", "index": 0}),
            ),
            n if n == deltas + 3 => ev(
                "message_delta",
                json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 9}}),
            ),
            _ => ev("message_stop", json!({"type": "message_stop"})),
        };
        Some((Ok(item), i + 1))
    })
}

fn conversation_body(files: &[(String, String)], kb: usize) -> Vec<u8> {
    let mut msgs = vec![
        json!({"role": "user", "content": "Разберись, почему падает сборка. Хост стенда prod-db01.pay.corp.local."}),
    ];
    let mut size = 0;
    for (i, (path, text)) in files.iter().enumerate() {
        if size >= kb * 1024 {
            break;
        }
        size += text.len();
        let id = format!("toolu_{i}");
        msgs.push(json!({"role": "assistant", "content": [{"type": "tool_use", "id": id, "name": "Read", "input": {"file_path": path}}]}));
        msgs.push(json!({"role": "user", "content": [{"type": "tool_result", "tool_use_id": id, "content": text}]}));
    }
    serde_json::to_vec(&json!({"model": "m", "max_tokens": 64, "stream": true, "messages": msgs}))
        .unwrap_or_default()
}

/// Time to the first byte; with `drain` the stream is read to its end (it stays in flight).
async fn ttfb(
    c: &reqwest::Client,
    url: &str,
    key: &str,
    body: &[u8],
    drain: bool,
) -> Option<(f64, f64)> {
    let t = Instant::now();
    let r = c
        .post(url)
        .header("x-api-key", key)
        .header("content-type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .ok()?;
    if !r.status().is_success() {
        return None;
    }
    let mut s = r.bytes_stream();
    s.next().await?.ok()?;
    let first = t.elapsed().as_secs_f64() * 1000.0;
    if drain {
        while s.next().await.is_some() {}
    }
    Some((first, t.elapsed().as_secs_f64() * 1000.0))
}

pub fn run(dir: &Path, o: Opts) -> bool {
    let files = crate::perf::corpus(dir);
    let body = Arc::new(conversation_body(&files, o.kb));
    println!(
        "conversation: {} KB of JSON; request rate {} /s for {} s; stream {} s",
        body.len() / 1024,
        o.rps,
        o.seconds,
        o.stream_secs
    );
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("runtime: {e}");
            return false;
        }
    };
    rt.block_on(async move {
        let delta_ms = 100;
        let mock = Arc::new(Mock {
            deltas: (o.stream_secs * 1000 / delta_ms) as usize,
            delta_ms,
        });
        let ml = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let maddr = ml.local_addr().expect("addr");
        let mrouter = Router::new()
            .route("/v1/messages", axum::routing::post(mock_messages))
            .with_state(mock);
        tokio::spawn(async move {
            let _ = axum::serve(ml, mrouter).await;
        });

        let keys = TenantKeys::from_secrets("bench", b"k-tenant-0123456789", b"k-audit-0123456789");
        let det = DetectConfig {
            internal_zones: vec!["corp.local".into()],
            ..Default::default()
        };
        let mut vk = HashMap::new();
        vk.insert(
            hash_key("bench-key"),
            Principal {
                id: "u:bench".into(),
                groups: vec![],
            },
        );
        let st = AppState::new(
            Engine::new(keys, det, Dictionary::default()),
            Some(Upstream::anthropic(format!("http://{maddr}"), "provider-key")),
            vk,
        );
        let gl = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let gaddr = gl.local_addr().expect("addr");
        let st = Arc::new(st);
        tokio::spawn(async move {
            let _ = axum::serve(gl, app(st)).await;
        });
        let direct = format!("http://{maddr}/v1/messages");
        let via = format!("http://{gaddr}/v1/messages");
        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(512)
            .build()
            .expect("client");

        // Phase 1: time to first byte, with and without the gateway.
        let mock_short = o.stream_secs; // the stream itself is slow; only the first byte counts
        let _ = mock_short;
        let _ = ttfb(&client, &via, "bench-key", &body, false).await; // cold: fills the detection cache
        let mut d_direct = vec![];
        let mut d_gw = vec![];
        for _ in 0..o.ttfb_samples {
            // interleaved, so that drift hits both the same way
            if let Some((a, _)) = ttfb(&client, &direct, "x", &body, false).await {
                d_direct.push(a);
            }
            if let Some((a, _)) = ttfb(&client, &via, "bench-key", &body, false).await {
                d_gw.push(a);
            }
        }
        let (p50d, p95d) = (pct(&mut d_direct.clone(), 0.5), pct(&mut d_direct, 0.95));
        let (p50g, p95g) = (pct(&mut d_gw.clone(), 0.5), pct(&mut d_gw, 0.95));
        let overhead_p95 = p95g - p95d;
        println!("\nPhase 1: time to first byte, {} samples", o.ttfb_samples);
        println!("  direct to provider: p50 {p50d:.1} ms, p95 {p95d:.1} ms");
        println!("  through the gateway: p50 {p50g:.1} ms, p95 {p95g:.1} ms");
        println!("  added by the gateway: p50 {:.1} ms, p95 {overhead_p95:.1} ms   (NFR-03: p95 <= 50 ms)", p50g - p50d);

        // Phase 2: a steady request rate; every stream lasts `stream_secs`.
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let ok = Arc::new(AtomicUsize::new(0));
        let failed = Arc::new(AtomicUsize::new(0));
        let ttfbs = Arc::new(std::sync::Mutex::new(Vec::<f64>::new()));
        let started = Instant::now();
        let total = o.rps as u64 * o.seconds;
        let mut handles = vec![];
        let rss_before = status_kb("VmRSS:");
        for i in 0..total {
            let due = started + Duration::from_micros(i * 1_000_000 / o.rps as u64);
            tokio::time::sleep_until(tokio::time::Instant::from_std(due)).await;
            let (c, via, body) = (client.clone(), via.clone(), body.clone());
            let (inf, pk, okc, fl, tt) = (
                in_flight.clone(),
                peak.clone(),
                ok.clone(),
                failed.clone(),
                ttfbs.clone(),
            );
            handles.push(tokio::spawn(async move {
                let n = inf.fetch_add(1, Ordering::SeqCst) + 1;
                pk.fetch_max(n, Ordering::SeqCst);
                match ttfb(&c, &via, "bench-key", &body, true).await {
                    Some((first, _)) => {
                        okc.fetch_add(1, Ordering::SeqCst);
                        if let Ok(mut v) = tt.lock() {
                            v.push(first);
                        }
                    }
                    None => {
                        fl.fetch_add(1, Ordering::SeqCst);
                    }
                }
                inf.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            let _ = h.await;
        }
        let elapsed = started.elapsed().as_secs_f64();
        let mut t = ttfbs.lock().map(|v| v.clone()).unwrap_or_default();
        let peak_streams = peak.load(Ordering::SeqCst);
        println!("\nPhase 2: {} requests at {} /s", total, o.rps);
        println!(
            "  ok {}, failed {}; peak streams in flight {} (NFR-04: >= 200); took {elapsed:.1} s",
            ok.load(Ordering::SeqCst),
            failed.load(Ordering::SeqCst),
            peak_streams
        );
        println!(
            "  time to first byte under load: p50 {:.1} ms, p95 {:.1} ms, p99 {:.1} ms",
            pct(&mut t.clone(), 0.5),
            pct(&mut t.clone(), 0.95),
            pct(&mut t, 0.99)
        );
        println!(
            "  memory: {} MB before, peak {} MB (generator, gateway and mock in one process)",
            rss_before / 1024,
            status_kb("VmHWM:") / 1024
        );

        let mut pass = failed.load(Ordering::SeqCst) == 0;
        if let Some(max) = o.max_ttfb_overhead_p95_ms {
            if overhead_p95 > max {
                eprintln!("FAIL: gateway adds {overhead_p95:.1} ms at p95, limit {max}");
                pass = false;
            }
        }
        if let Some(min) = o.min_streams {
            if peak_streams < min {
                eprintln!("FAIL: peak {peak_streams} streams, need {min}");
                pass = false;
            }
        }
        pass
    })
}

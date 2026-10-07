//! Latency of the request transformation on a long agent conversation. REQ: NFR-01, NFR-02, NFR-12, T0-09.
//!
//! The conversation is built from real source files: the agent "reads" files one after another
//! (tool_use + tool_result), the way a coding agent fills its context.

use aegis_core::crypto::TenantKeys;
use aegis_core::detect::{DetectConfig, Dictionary};
use aegis_gateway::anthropic::{transform_request, ReqMeta};
use aegis_gateway::engine::Engine;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Instant;

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect(&p, out);
        } else if p
            .extension()
            .and_then(|x| x.to_str())
            .is_some_and(|x| matches!(x, "rs" | "toml" | "md" | "yml" | "json"))
        {
            out.push(p);
        }
    }
}

fn pct(v: &mut [f64], p: f64) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    v[((v.len() as f64 * p).ceil() as usize).clamp(1, v.len()) - 1]
}

fn conversation(files: &[(String, String)], kb: usize) -> Vec<Value> {
    let mut msgs = vec![
        json!({"role": "user", "content": "Разберись, почему падает сборка, и исправь. Хост стенда prod-db01.pay.corp.local."}),
    ];
    let mut size = 0;
    for (i, (path, text)) in files.iter().enumerate() {
        if size >= kb * 1024 {
            break;
        }
        size += text.len();
        let id = format!("toolu_{i}");
        msgs.push(json!({"role": "assistant", "content": [{"type": "text", "text": format!("Читаю {path}")}, {"type": "tool_use", "id": id, "name": "Read", "input": {"file_path": path}}]}));
        msgs.push(json!({"role": "user", "content": [{"type": "tool_result", "tool_use_id": id, "content": text}]}));
    }
    msgs
}

/// The text files a coding agent would read: every 7th source file of the corpus.
pub fn corpus(dir: &Path) -> Vec<(String, String)> {
    let mut paths = vec![];
    collect(dir, &mut paths);
    paths.sort();
    paths
        .iter()
        .step_by(7)
        .filter_map(|p| {
            std::fs::read_to_string(p)
                .ok()
                .filter(|t| t.len() > 500 && t.len() < 60_000)
                .map(|t| (p.strip_prefix(dir).unwrap_or(p).display().to_string(), t))
        })
        .collect()
}

pub fn run(kb: usize, iterations: usize, dir: &Path, max_warm_p95_ms: Option<f64>) {
    let files = corpus(dir);
    let mut msgs = conversation(&files, kb);
    let history_kb = msgs.iter().map(|m| m.to_string().len()).sum::<usize>() / 1024;
    let keys = TenantKeys::from_secrets("bench", b"k-tenant-0123456789", b"k-audit-0123456789");
    let det = DetectConfig {
        internal_zones: vec!["company.ru".into()],
        ..Default::default()
    };
    let meta = ReqMeta {
        principal: "u:bench",
        conversation: Some("c1"),
        request_id: "r",
        route: "anthropic-default",
    };
    let body = |msgs: &Vec<Value>| {
        serde_json::to_vec(&json!({"model": "m", "max_tokens": 4096, "system": "You are an agent.", "messages": msgs})).unwrap_or_default()
    };

    let mut cold = vec![];
    let mut warm = vec![];
    let mut scanned_cold = 0;
    let mut scanned_warm = 0;
    let mut entities = 0;
    for it in 0..iterations {
        // a fresh engine has an empty cache: this is the first turn of a long session
        let e = Engine::new(
            TenantKeys::from_secrets("bench", b"k-tenant-0123456789", b"k-audit-0123456789"),
            det.clone(),
            Dictionary::default(),
        );
        let b = body(&msgs);
        let t = Instant::now();
        let r = transform_request(&e, &meta, &b);
        cold.push(t.elapsed().as_secs_f64() * 1000.0);
        if let Ok((_, ctx)) = r {
            scanned_cold = ctx.stats.blocks_scanned;
            entities = ctx.stats.by_class.values().sum::<u32>();
        }
        // next turn: the same history plus one new tool result (the agent loop)
        msgs.push(json!({"role": "assistant", "content": [{"type": "text", "text": format!("шаг {it}")}]}));
        msgs.push(json!({"role": "user", "content": format!("результат шага {it}: ok")}));
        let b2 = body(&msgs);
        let t = Instant::now();
        // warm path: the same engine saw the history
        let r2 = transform_request(&e, &meta, &b2);
        let _ = r2
            .as_ref()
            .map(|(_, c)| scanned_warm = c.stats.blocks_scanned);
        // the first warm call above already includes the new blocks; time a second identical turn too
        warm.push(t.elapsed().as_secs_f64() * 1000.0);
        let _ = keys.tenant.len();
    }
    // steady state: one engine, many consecutive turns
    let e = Engine::new(
        TenantKeys::from_secrets("bench", b"k-tenant-0123456789", b"k-audit-0123456789"),
        det,
        Dictionary::default(),
    );
    let mut steady = vec![];
    let mut stage: std::collections::BTreeMap<&str, f64> = Default::default();
    let _ = transform_request(&e, &meta, &body(&msgs));
    for it in 0..iterations {
        msgs.push(json!({"role": "assistant", "content": [{"type": "text", "text": format!("ещё шаг {it}")}]}));
        msgs.push(json!({"role": "user", "content": format!("результат: {it}")}));
        let b = body(&msgs);
        let t = Instant::now();
        let r = transform_request(&e, &meta, &b);
        steady.push(t.elapsed().as_secs_f64() * 1000.0);
        if let Ok((_, c)) = r {
            for (k, v) in &c.stats.timings_ms {
                *stage.entry(*k).or_insert(0.0) += v / iterations as f64;
            }
        }
    }

    println!("conversation: {} messages, ~{history_kb} KB of JSON (~{} k tokens), {entities} entities masked", msgs.len(), history_kb / 4);
    println!(
        "cold (first turn, empty cache): p50 {:.1} ms, p95 {:.1} ms; blocks scanned {scanned_cold}",
        pct(&mut cold.clone(), 0.5),
        pct(&mut cold.clone(), 0.95)
    );
    println!(
        "next turn on a warm engine:     p50 {:.1} ms, p95 {:.1} ms; blocks scanned {scanned_warm}",
        pct(&mut warm.clone(), 0.5),
        pct(&mut warm.clone(), 0.95)
    );
    let (p50, p95) = (
        pct(&mut steady.clone(), 0.5),
        pct(&mut steady.clone(), 0.95),
    );
    println!("steady state (warm, +1 turn):   p50 {p50:.1} ms, p95 {p95:.1} ms");
    println!("warm stage means (ms): {stage:.1?}");
    println!("targets: NFR-01 warm p50 <= 20 ms, p95 <= 100 ms; NFR-02 cold p95 <= 400 ms");
    if let Some(max) = max_warm_p95_ms {
        if p95 > max {
            eprintln!("FAIL: warm p95 {p95:.1} ms exceeds {max} ms");
            std::process::exit(1);
        }
    }
}

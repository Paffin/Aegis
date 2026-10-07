#![allow(clippy::unwrap_used)]
//! REQ: DET-09, DET-03, NFR-09 — a detector that fails or takes too long drops the block, never
//! lets it through unchecked and never rejects the whole request; the cache stays inside its limit.

use aegis_core::crypto::TenantKeys;
use aegis_core::detect::{Candidate, DetectConfig, Detector, Dictionary};
use aegis_gateway::anthropic::{transform_request, ReqMeta};
use aegis_gateway::engine::Engine;
use serde_json::json;
use std::time::Duration;

struct Slow;
impl Detector for Slow {
    fn id(&self) -> &str {
        "slow"
    }
    fn scan(&self, text: &str, _: &mut Vec<Candidate>) {
        if text.contains("SLOW") {
            std::thread::sleep(Duration::from_millis(60));
        }
    }
}

struct Broken;
impl Detector for Broken {
    fn id(&self) -> &str {
        "broken"
    }
    fn scan(&self, text: &str, _: &mut Vec<Candidate>) {
        assert!(!text.contains("BREAK"), "detector bug");
    }
}

fn engine(budget_ms: u64) -> Engine {
    let keys = TenantKeys::from_secrets("t1", b"k-tenant", b"k-audit");
    let mut e = Engine::new(keys, DetectConfig::default(), Dictionary::default())
        .with_limits(1 << 20, Duration::from_millis(budget_ms));
    e.pipeline.add_detector(Box::new(Slow));
    e.pipeline.add_detector(Box::new(Broken));
    e
}

fn meta() -> ReqMeta<'static> {
    ReqMeta {
        principal: "u:x",
        conversation: Some("c"),
        request_id: "r",
        route: "t",
    }
}

fn run(e: &Engine, texts: &[&str]) -> (String, aegis_gateway::engine::RequestCtx) {
    let msgs: Vec<_> = texts
        .iter()
        .map(|t| json!({"role": "user", "content": t}))
        .collect();
    let body =
        serde_json::to_vec(&json!({"model": "m", "max_tokens": 4, "messages": msgs})).unwrap();
    let (out, ctx) = match transform_request(e, &meta(), &body) {
        Ok(x) => x,
        Err(_) => panic!("the request must not be rejected"),
    };
    (String::from_utf8(out).unwrap(), ctx)
}

#[test]
fn a_block_that_exceeds_the_budget_is_dropped_and_the_rest_goes_on() {
    let e = engine(20);
    let (out, ctx) = run(&e, &["SLOW password=Jd8@2jd82k", "обычный текст"]);
    assert!(out.contains("[Aegis: блок не проверен и удалён]"));
    assert!(!out.contains("Jd8@2jd82k") && !out.contains("SLOW"));
    assert!(out.contains("обычный текст"));
    assert_eq!(ctx.stats.detector_faults, vec!["timeout"]);
}

#[test]
fn a_detector_that_panics_drops_the_block() {
    let e = engine(2000);
    let (out, ctx) = run(
        &e,
        &["BREAK token=ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ok"],
    );
    assert!(out.contains("[Aegis: блок не проверен и удалён]"));
    assert!(!out.contains("ghp_"));
    assert_eq!(ctx.stats.detector_faults, vec!["error"]);
}

#[test]
fn a_fault_is_not_cached_so_the_next_request_is_checked_again() {
    let e = engine(2000);
    let (_, c1) = run(&e, &["BREAK"]);
    let after_first = e.cache_len();
    let (_, c2) = run(&e, &["BREAK"]);
    assert_eq!(c1.stats.detector_faults.len(), 1);
    assert_eq!(c2.stats.detector_faults.len(), 1);
    assert_eq!(
        e.cache_len(),
        after_first,
        "the faulty block must not be cached"
    );
}

#[test]
fn the_cache_stays_inside_its_memory_limit() {
    let keys = TenantKeys::from_secrets("t1", b"k-tenant", b"k-audit");
    // room for roughly a hundred entries
    let e = Engine::new(keys, DetectConfig::default(), Dictionary::default())
        .with_limits(100 * 100, Duration::from_secs(2));
    for i in 0..5000 {
        e.scan(&format!("block number {i} host-{i}.example.org"));
    }
    assert!(e.cache_len() <= 100, "{} entries", e.cache_len());
    assert!(e.cache_len() > 10);
}

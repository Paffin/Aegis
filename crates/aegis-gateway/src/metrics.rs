//! REQ: OBS-01, OBS-02, NFR-12 — Prometheus text metrics.
//!
//! Label values come from closed vocabularies (class, stage, rule id, status). They are
//! sanitised so that nothing else can be smuggled in (OBS-02).

use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::Mutex;

const BUCKETS_MS: [f64; 10] = [1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 250.0, 500.0, 1000.0];

#[derive(Default)]
struct Hist {
    buckets: [u64; 10],
    sum: f64,
    count: u64,
}

#[derive(Default)]
pub struct Metrics {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    counters: BTreeMap<String, u64>,
    hists: BTreeMap<String, Hist>,
}

fn label(v: &str) -> String {
    v.chars()
        .take(48)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | ':') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn key(name: &str, labels: &[(&str, &str)]) -> String {
    if labels.is_empty() {
        return name.to_string();
    }
    let l: Vec<String> = labels
        .iter()
        .map(|(k, v)| format!("{k}=\"{}\"", label(v)))
        .collect();
    format!("{name}{{{}}}", l.join(","))
}

impl Metrics {
    pub fn inc(&self, name: &str, labels: &[(&str, &str)], n: u64) {
        if let Ok(mut i) = self.inner.lock() {
            *i.counters.entry(key(name, labels)).or_insert(0) += n;
        }
    }

    pub fn observe_ms(&self, name: &str, labels: &[(&str, &str)], ms: f64) {
        if let Ok(mut i) = self.inner.lock() {
            let h = i.hists.entry(key(name, labels)).or_default();
            for (b, le) in h.buckets.iter_mut().zip(BUCKETS_MS) {
                if ms <= le {
                    *b += 1;
                }
            }
            h.sum += ms;
            h.count += 1;
        }
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        let Ok(i) = self.inner.lock() else { return out };
        for (k, v) in &i.counters {
            let _ = writeln!(out, "{k} {v}");
        }
        for (k, h) in &i.hists {
            let (name, lbl) = match k.split_once('{') {
                Some((n, l)) => (n, l.trim_end_matches('}')),
                None => (k.as_str(), ""),
            };
            let sep = if lbl.is_empty() { "" } else { "," };
            for (b, le) in h.buckets.iter().zip(BUCKETS_MS) {
                let _ = writeln!(out, "{name}_bucket{{{lbl}{sep}le=\"{le}\"}} {b}");
            }
            let _ = writeln!(out, "{name}_bucket{{{lbl}{sep}le=\"+Inf\"}} {}", h.count);
            let _ = writeln!(out, "{name}_sum{{{lbl}}} {}", h.sum);
            let _ = writeln!(out, "{name}_count{{{lbl}}} {}", h.count);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: OBS-01
    #[test]
    fn counters_and_histograms_render() {
        let m = Metrics::default();
        m.inc("aegis_entities_total", &[("class", "SECRET")], 2);
        m.inc("aegis_entities_total", &[("class", "SECRET")], 1);
        m.observe_ms("aegis_stage_ms", &[("stage", "detect")], 7.0);
        m.observe_ms("aegis_stage_ms", &[("stage", "detect")], 300.0);
        let t = m.render();
        assert!(
            t.contains("aegis_entities_total{class=\"SECRET\"} 3"),
            "{t}"
        );
        assert!(
            t.contains("aegis_stage_ms_bucket{stage=\"detect\",le=\"10\"} 1"),
            "{t}"
        );
        assert!(
            t.contains("aegis_stage_ms_bucket{stage=\"detect\",le=\"+Inf\"} 2"),
            "{t}"
        );
        assert!(t.contains("aegis_stage_ms_count{stage=\"detect\"} 2"));
    }

    // REQ: OBS-02 — hostile label values cannot inject text or exceed the vocabulary.
    #[test]
    fn labels_are_sanitised() {
        let m = Metrics::default();
        m.inc(
            "x",
            &[("rule", "prod-db01\"} 1\nevil{a=\"b\" Jd8@2jd82k")],
            1,
        );
        let t = m.render();
        assert_eq!(t.lines().count(), 1, "{t}");
        assert!(!t.contains('@') && !t.contains("\nevil"));
    }
}

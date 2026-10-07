//! REQ: DET-09, AUD-01, AUD-02, AUD-03, AUD-04, AUD-06, API-06, SEC-01 — audit without values.
//!
//! Events carry types, hashes (HMAC on `K_audit`), counts and rule ids. A value or a
//! pseudonym never appears here.

use crate::engine::RequestCtx;
use serde::Serialize;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};

#[derive(Serialize, Debug, Clone)]
pub struct AuditEvent {
    pub ts: String,
    pub request_id: String,
    pub tenant: String,
    pub principal: String,
    pub client: String,
    pub route: String,
    pub model: String,
    pub conversation: String,
    pub bundle_version: String,
    pub decision: &'static str,
    pub sizes: Sizes,
    pub latency_ms: std::collections::BTreeMap<&'static str, f64>,
    pub entities: Vec<EntityEvent>,
    pub trifecta: TrifectaEvent,
    pub sinks: Vec<SinkEvent>,
    /// DET-09: blocks that were not checked and were dropped (`timeout`, `error`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub detector_faults: Vec<&'static str>,
    /// DET-20: blocks that looked like a closed repository (names, never code).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub code_blocks: Vec<CodeBlockEvent>,
}

#[derive(Serialize, Debug, Clone)]
pub struct CodeBlockEvent {
    pub repo: String,
    pub classification: String,
    pub action: &'static str,
}

#[derive(Serialize, Debug, Clone)]
pub struct Sizes {
    pub request_bytes: usize,
    pub blocks: u32,
    pub blocks_scanned: u32,
}

#[derive(Serialize, Debug, Clone)]
pub struct EntityEvent {
    #[serde(rename = "type")]
    pub ty: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<&'static str>,
    pub audit_hash: String,
    pub count: u32,
    pub action: &'static str,
    pub rule: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct TrifectaEvent {
    pub private: bool,
    pub untrusted: bool,
    pub mode: &'static str,
}

#[derive(Serialize, Debug, Clone)]
pub struct SinkEvent {
    pub tool: String,
    pub sink: &'static str,
    pub decision: &'static str,
    pub rule: String,
    pub classes: Vec<&'static str>,
}

pub struct EventMeta<'a> {
    pub tenant: &'a str,
    pub principal: &'a str,
    pub client: &'a str,
    pub route: &'a str,
    pub model: &'a str,
    pub request_bytes: usize,
    pub bundle_version: &'a str,
    pub trifecta_mode: &'static str,
}

impl AuditEvent {
    pub fn from_ctx(ctx: &RequestCtx, m: &EventMeta<'_>, decision: &'static str) -> Self {
        let mut entities: Vec<EntityEvent> = ctx
            .stats
            .entities
            .iter()
            .map(|((ty, kind, hash), agg)| EntityEvent {
                ty,
                kind: *kind,
                audit_hash: hash.clone(),
                count: agg.count,
                action: agg.action,
                rule: agg.rule.clone(),
            })
            .collect();
        entities.sort_by(|a, b| (a.ty, &a.audit_hash).cmp(&(b.ty, &b.audit_hash)));
        Self {
            ts: iso8601_now(),
            request_id: ctx.request_id.clone(),
            tenant: m.tenant.into(),
            principal: m.principal.into(),
            client: m.client.into(),
            route: m.route.into(),
            model: m.model.into(),
            conversation: ctx.conversation_hash.clone(),
            bundle_version: m.bundle_version.into(),
            decision,
            sizes: Sizes {
                request_bytes: m.request_bytes,
                blocks: ctx.stats.blocks_total,
                blocks_scanned: ctx.stats.blocks_scanned,
            },
            latency_ms: ctx.stats.timings_ms.clone(),
            entities,
            trifecta: TrifectaEvent {
                private: ctx.trifecta.private,
                untrusted: ctx.trifecta.untrusted,
                mode: m.trifecta_mode,
            },
            sinks: ctx
                .stats
                .sinks
                .iter()
                .map(|s| SinkEvent {
                    tool: s.tool.clone(),
                    sink: s.sink,
                    decision: s.decision,
                    rule: s.rule.clone(),
                    classes: s.classes.clone(),
                })
                .collect(),
            detector_faults: ctx.stats.detector_faults.clone(),
            code_blocks: ctx
                .stats
                .code_blocks
                .iter()
                .map(|(repo, classification, action)| CodeBlockEvent {
                    repo: repo.clone(),
                    classification: classification.clone(),
                    action,
                })
                .collect(),
        }
    }
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` without a date library.
pub fn iso8601_now() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    iso8601(d.as_secs(), d.subsec_millis())
}

pub fn iso8601(secs: u64, ms: u32) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // civil-from-days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{ms:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[derive(Debug)]
pub struct AuditFull;

/// Asynchronous JSONL sink with a bounded queue (AUD-04).
pub struct Audit {
    tx: Option<SyncSender<String>>,
    /// `audit.required`: a full queue stops traffic instead of dropping events.
    pub required: bool,
    pub dropped: AtomicU64,
}

impl Audit {
    pub fn disabled() -> Self {
        Self {
            tx: None,
            required: false,
            dropped: AtomicU64::new(0),
        }
    }

    pub fn to_writer<W: Write + Send + 'static>(mut w: W, capacity: usize, required: bool) -> Self {
        let (tx, rx) = sync_channel::<String>(capacity);
        std::thread::spawn(move || {
            for line in rx {
                if writeln!(w, "{line}").and_then(|_| w.flush()).is_err() {
                    // Nothing sensible to do; the next lines will retry.
                }
            }
        });
        Self {
            tx: Some(tx),
            required,
            dropped: AtomicU64::new(0),
        }
    }

    pub fn emit(&self, ev: &AuditEvent) -> Result<(), AuditFull> {
        let Some(tx) = &self.tx else { return Ok(()) };
        let line = serde_json::to_string(ev).unwrap_or_default();
        match tx.try_send(line) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                if self.required {
                    Err(AuditFull)
                } else {
                    Ok(())
                }
            }
        }
    }

    /// In `required` mode a request is only forwarded when the queue can take its event.
    pub fn has_room(&self) -> bool {
        !self.required || self.tx.is_none() || self.dropped.load(Ordering::Relaxed) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn event() -> AuditEvent {
        AuditEvent {
            ts: iso8601(0, 0),
            request_id: "r".into(),
            tenant: "t".into(),
            principal: "p".into(),
            client: "c".into(),
            route: "r".into(),
            model: "m".into(),
            conversation: "c".into(),
            bundle_version: "dev".into(),
            decision: "allow",
            sizes: Sizes {
                request_bytes: 1,
                blocks: 1,
                blocks_scanned: 1,
            },
            latency_ms: Default::default(),
            entities: vec![],
            trifecta: TrifectaEvent {
                private: false,
                untrusted: false,
                mode: "enforce",
            },
            sinks: vec![],
            detector_faults: vec![],
            code_blocks: vec![],
        }
    }

    #[test]
    fn iso8601_known_dates() {
        assert_eq!(iso8601(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601(1_791_368_595, 42), "2026-10-07T10:23:15.042Z");
        assert_eq!(iso8601(951_782_400, 0), "2000-02-29T00:00:00.000Z");
        assert_eq!(iso8601(4_107_542_399, 999), "2100-02-28T23:59:59.999Z");
    }

    // REQ: AUD-04
    #[test]
    fn writes_jsonl_and_full_queue_drops_or_fails() {
        let buf = Buf::default();
        let a = Audit::to_writer(buf.clone(), 8, false);
        a.emit(&event()).unwrap();
        for _ in 0..50 {
            std::thread::sleep(std::time::Duration::from_millis(10));
            if !buf.0.lock().unwrap().is_empty() {
                break;
            }
        }
        let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        let v: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(v["decision"], "allow");

        // a writer that never returns keeps the queue full
        struct Stuck;
        impl Write for Stuck {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                std::thread::sleep(std::time::Duration::from_secs(5));
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let lossy = Audit::to_writer(Stuck, 1, false);
        for _ in 0..5 {
            assert!(lossy.emit(&event()).is_ok(), "traffic is not blocked");
        }
        assert!(lossy.dropped.load(Ordering::Relaxed) > 0);
        let strict = Audit::to_writer(Stuck, 1, true);
        let results: Vec<_> = (0..5).map(|_| strict.emit(&event()).is_ok()).collect();
        assert!(
            results.contains(&false),
            "required mode reports the overflow"
        );
        assert!(!strict.has_room());
    }
}

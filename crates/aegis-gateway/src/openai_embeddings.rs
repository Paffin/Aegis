//! REQ: PRO-02, PRO-10 — `/v1/embeddings`: code indexing in editors and agents sends file
//! contents here. The text is masked like any other request; the answer is vectors and passes
//! through. Pseudonyms are stable within a conversation salt, so the vectors of one indexing run
//! stay comparable.

use crate::anthropic::{Reject, ReqMeta};
use crate::common::{bad_request, finish_request, Draft};
use crate::engine::{Blk, Engine, RequestCtx};
use crate::json::{self, Node};
use aegis_core::pseudo::Source;

pub fn transform_request(
    engine: &Engine,
    meta: &ReqMeta<'_>,
    body: &[u8],
) -> Result<(Vec<u8>, RequestCtx), Reject> {
    let t = std::time::Instant::now();
    let root = json::parse(body).map_err(|e| bad_request(e.message()))?;
    if !matches!(root, Node::Obj { .. }) {
        return Err(bad_request("ожидался объект JSON"));
    }
    let parse_ms = t.elapsed().as_secs_f64() * 1000.0;
    let mut d = Draft::default();
    match root.get("input") {
        Some(s @ Node::Str { .. }) => push(&mut d, s, body),
        Some(Node::Arr { items, .. }) => {
            for it in items {
                match it {
                    Node::Str { .. } => push(&mut d, it, body),
                    // Token ids cannot be scanned.
                    _ => return Err(bad_request("input в виде токенов не поддерживается")),
                }
            }
        }
        _ => {}
    }
    finish_request(engine, meta, body, &root, d, parse_ms)
}

fn push<'n>(d: &mut Draft<'n>, node: &'n Node, body: &[u8]) {
    let text = node.string(body).unwrap_or_default();
    d.first_user.push(text.clone());
    d.blocks.push(Blk {
        node,
        text,
        source: Source::User,
        is_system: false,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::crypto::TenantKeys;
    use aegis_core::detect::{DetectConfig, Dictionary};
    use serde_json::json;

    fn engine() -> Engine {
        let keys = TenantKeys::from_secrets("t1", b"k-tenant-0123456789", b"k-audit-0123456789");
        let det = DetectConfig {
            internal_zones: vec!["corp.local".into()],
            ..Default::default()
        };
        Engine::new(keys, det, Dictionary::default())
    }

    fn meta() -> ReqMeta<'static> {
        ReqMeta {
            principal: "u:dev",
            conversation: Some("idx-1"),
            request_id: "r1",
            route: "test",
        }
    }

    // REQ: PRO-08 — file contents sent for indexing are masked.
    #[test]
    fn indexed_files_are_masked() {
        let file = "DB_URL=postgres://svc:Jd8@2jd82k@prod-db01.pay.corp.local/x\nAWS_KEY=AKIAIOSFODNN7EXAMPLE";
        for input in [json!(file), json!([file, "plain text"])] {
            let body = json!({"model":"text-embedding-3-small","input":input}).to_string();
            let (out, ctx) = transform_request(&engine(), &meta(), body.as_bytes()).unwrap();
            let s = String::from_utf8(out).unwrap();
            assert!(!s.contains("Jd8@2jd82k") && !s.contains("prod-db01"), "{s}");
            assert!(ctx.stats.blocks_total >= 1);
        }
    }

    // REQ: PRO-08
    #[test]
    fn same_text_gets_same_vector_input_within_a_run() {
        let a = json!({"model":"m","input":"host prod-db01.pay.corp.local"}).to_string();
        let (x, _) = transform_request(&engine(), &meta(), a.as_bytes()).unwrap();
        let (y, _) = transform_request(&engine(), &meta(), a.as_bytes()).unwrap();
        assert_eq!(x, y);
    }

    // REQ: PRO-08
    #[test]
    fn token_input_is_refused() {
        let b = json!({"model":"m","input":[[1,2],[3]]}).to_string();
        assert!(transform_request(&engine(), &meta(), b.as_bytes()).is_err());
    }
}

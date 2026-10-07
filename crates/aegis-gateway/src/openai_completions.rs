//! REQ: PRO-02, PRO-10, RSP-01 — legacy `/v1/completions`: autocomplete and fill-in-the-middle
//! (Continue, Tabby, llama.cpp, vLLM). The request carries a code prefix (`prompt`) and a code
//! suffix (`suffix`); the answer is plain text per choice.

use crate::anthropic::{Reject, ReqMeta};
use crate::common::{bad_request, finish_request, restore_text, Draft};
use crate::engine::{Blk, Engine, RequestCtx};
use crate::json::{self, Node};
use crate::stream::{safe_prefix_len, SseParser};
use aegis_core::pseudo::Source;
use serde_json::Value;
use std::collections::HashMap;

const HINT: &str = "\n[Aegis: значение секрета скрыто]";

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
    for key in ["prompt", "suffix"] {
        match root.get(key) {
            Some(s @ Node::Str { .. }) => push(&mut d, s, body, key == "prompt"),
            Some(Node::Arr { items, .. }) => {
                for it in items {
                    match it {
                        Node::Str { .. } => push(&mut d, it, body, key == "prompt"),
                        // Token ids cannot be scanned.
                        _ => return Err(bad_request("prompt в виде токенов не поддерживается")),
                    }
                }
            }
            _ => {}
        }
    }
    finish_request(engine, meta, body, &root, d, parse_ms)
}

fn push<'n>(d: &mut Draft<'n>, node: &'n Node, body: &[u8], first: bool) {
    let text = node.string(body).unwrap_or_default();
    if first {
        d.first_user.push(text.clone());
    }
    d.blocks.push(Blk {
        node,
        text,
        source: Source::User,
        is_system: false,
        key: None,
    });
}

pub fn transform_response(engine: &Engine, ctx: &mut RequestCtx, body: &[u8]) -> Vec<u8> {
    let Ok(mut v) = serde_json::from_slice::<Value>(body) else {
        return body.to_vec();
    };
    if v.get("error").is_some() {
        return body.to_vec(); // RSP-09
    }
    let Some(choices) = v.get_mut("choices").and_then(|c| c.as_array_mut()) else {
        return body.to_vec();
    };
    for ch in choices {
        if let Some(t) = ch.get("text").and_then(|t| t.as_str()).map(String::from) {
            let (mut out, hinted) = restore_text(engine, ctx, &t);
            if hinted {
                out.push_str(HINT);
            }
            ch["text"] = Value::String(out);
        }
    }
    serde_json::to_vec(&v).unwrap_or_else(|_| body.to_vec())
}

#[derive(Default)]
struct Choice {
    pending: String,
    hinted: bool,
    done: bool,
}

pub struct CompletionsStreamTransformer<'e> {
    engine: &'e Engine,
    pub ctx: RequestCtx,
    choices: HashMap<u64, Choice>,
    parser: SseParser,
    base: Option<Value>,
}

fn frame(v: &Value) -> Vec<u8> {
    format!("data: {}\n\n", serde_json::to_string(v).unwrap_or_default()).into_bytes()
}

impl<'e> CompletionsStreamTransformer<'e> {
    pub fn new(engine: &'e Engine, ctx: RequestCtx) -> Self {
        Self {
            engine,
            ctx,
            choices: HashMap::new(),
            parser: SseParser::default(),
            base: None,
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![];
        for ev in self.parser.push(bytes) {
            out.extend(self.event(ev.data, ev.raw));
        }
        out
    }

    /// Text still held back when the provider closes the stream without a finish reason.
    pub fn finish(&mut self) -> Vec<u8> {
        let mut out = vec![];
        let mut idxs: Vec<u64> = self.choices.keys().copied().collect();
        idxs.sort_unstable();
        for idx in idxs {
            let Some(st) = self.choices.get_mut(&idx) else {
                continue;
            };
            if st.done || st.pending.is_empty() {
                continue;
            }
            let tail = std::mem::take(&mut st.pending);
            let (mut text, h) = restore_text(self.engine, &self.ctx, &tail);
            if st.hinted || h {
                text.push_str(HINT);
            }
            if let Some(mut c) = self.base.clone() {
                c["choices"] =
                    serde_json::json!([{"index": idx, "text": text, "finish_reason": null}]);
                out.extend(frame(&c));
            }
        }
        out.extend(self.parser.rest());
        out
    }

    fn event(&mut self, data: String, raw: Vec<u8>) -> Vec<u8> {
        let Ok(mut v) = serde_json::from_str::<Value>(&data) else {
            return raw;
        };
        if v.get("choices").and_then(|c| c.as_array()).is_none() {
            return raw;
        }
        let mut base = v.clone();
        base["choices"] = serde_json::json!([]);
        let Some(choices) = v.get_mut("choices").and_then(|c| c.as_array_mut()) else {
            return raw;
        };
        for ch in choices {
            let idx = ch.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
            let st = self.choices.entry(idx).or_default();
            let finish = ch.get("finish_reason").is_some_and(|f| !f.is_null());
            if let Some(t) = ch.get("text").and_then(|t| t.as_str()) {
                st.pending.push_str(t);
            } else if !finish {
                continue;
            }
            let release: String = if finish {
                st.done = true;
                std::mem::take(&mut st.pending)
            } else {
                let cut = safe_prefix_len(&st.pending);
                st.pending.drain(..cut).collect()
            };
            let (mut text, h) = restore_text(self.engine, &self.ctx, &release);
            st.hinted |= h;
            if finish && st.hinted {
                text.push_str(HINT);
            }
            ch["text"] = Value::String(text);
        }
        self.base = Some(base);
        frame(&v)
    }
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
            conversation: Some("c1"),
            request_id: "r1",
            route: "test",
        }
    }

    // REQ: PRO-13 — prompt and suffix of fill-in-the-middle are both scanned.
    #[test]
    fn prompt_and_suffix_are_masked() {
        let body = json!({"model":"m","prompt":"let url = \"postgres://prod-db01.pay.corp.local/x\";\n","suffix":"// password = \"Jd8@2jd82k\"\n","max_tokens":16}).to_string();
        let (out, ctx) = transform_request(&engine(), &meta(), body.as_bytes()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(!s.contains("prod-db01") && !s.contains("Jd8@2jd82k"), "{s}");
        assert!(s.contains("aegis.invalid"));
        assert!(ctx.stats.blocks_total >= 2);
    }

    #[test]
    fn prompt_array_and_token_ids() {
        let body =
            json!({"model":"m","prompt":["a host prod-db01.pay.corp.local","b"]}).to_string();
        let (out, _) = transform_request(&engine(), &meta(), body.as_bytes()).unwrap();
        assert!(!String::from_utf8(out).unwrap().contains("prod-db01"));
        let tokens = json!({"model":"m","prompt":[[1,2,3]]}).to_string();
        assert!(transform_request(&engine(), &meta(), tokens.as_bytes()).is_err());
        let tokens = json!({"model":"m","prompt":[1,2,3]}).to_string();
        assert!(transform_request(&engine(), &meta(), tokens.as_bytes()).is_err());
    }

    // REQ: PRO-13, RST-01 — the pseudonym in the completion is restored for the editor.
    #[test]
    fn response_and_stream_restore_text() {
        let e = engine();
        let body =
            json!({"model":"m","prompt":"connect to prod-db01.pay.corp.local now"}).to_string();
        let (out, mut ctx) = transform_request(&e, &meta(), body.as_bytes()).unwrap();
        let sent: Value = serde_json::from_slice(&out).unwrap();
        let masked = sent["prompt"].as_str().unwrap();
        let host = masked.split_whitespace().nth(2).unwrap().to_string();
        assert!(host.ends_with(".aegis.invalid"));

        let resp = json!({"choices":[{"index":0,"text":format!("use {host} here"),"finish_reason":"stop"}]}).to_string();
        let r = transform_response(&e, &mut ctx, resp.as_bytes());
        let r: Value = serde_json::from_slice(&r).unwrap();
        assert_eq!(r["choices"][0]["text"], "use prod-db01.pay.corp.local here");

        // the same text, streamed in 3-byte pieces and split inside the pseudonym
        let full = format!("use {host} here");
        let mut t = CompletionsStreamTransformer::new(&e, ctx);
        let mut wire = String::new();
        let chars: Vec<char> = full.chars().collect();
        for (i, c) in chars.chunks(3).enumerate() {
            let last = (i + 1) * 3 >= chars.len();
            let piece: String = c.iter().collect();
            let ev = json!({"id":"x","choices":[{"index":0,"text":piece,"finish_reason": if last {json!("stop")} else {Value::Null}}]});
            wire.push_str(&format!("data: {ev}\n\n"));
        }
        wire.push_str("data: [DONE]\n\n");
        let mut got = String::new();
        let mut bytes = t.feed(wire.as_bytes());
        bytes.extend(t.finish());
        for line in String::from_utf8(bytes).unwrap().lines() {
            if let Some(d) = line.strip_prefix("data: ") {
                if let Ok(v) = serde_json::from_str::<Value>(d) {
                    got.push_str(v["choices"][0]["text"].as_str().unwrap_or(""));
                }
            }
        }
        assert_eq!(got, "use prod-db01.pay.corp.local here");
    }
}

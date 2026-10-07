#![allow(clippy::unwrap_used)]
//! Parser-differential bypasses: input that our parser and the provider's parser could read
//! differently must be refused, never scanned partially. REQ: SEC-10, PRO-10, PRO-04.

use aegis_core::crypto::TenantKeys;
use aegis_core::detect::{DetectConfig, Dictionary};
use aegis_gateway::anthropic::{transform_request, ReqMeta};
use aegis_gateway::engine::Engine;
use aegis_gateway::{openai_chat, openai_responses};

fn engine() -> &'static Engine {
    static E: std::sync::OnceLock<Engine> = std::sync::OnceLock::new();
    E.get_or_init(build)
}

fn build() -> Engine {
    let keys = TenantKeys::from_secrets("t1", b"k-tenant-0123456789", b"k-audit-0123456789");
    Engine::new(
        keys,
        DetectConfig {
            internal_zones: vec!["corp.local".into()],
            ..Default::default()
        },
        Dictionary::default(),
    )
}

fn meta() -> ReqMeta<'static> {
    ReqMeta {
        principal: "u",
        conversation: Some("c"),
        request_id: "r",
        route: "t",
    }
}

const SECRET: &str = "password=Jd8@2jd82k host prod-db01.corp.local";

type Transform =
    fn(
        &Engine,
        &ReqMeta<'_>,
        &[u8],
    )
        -> Result<(Vec<u8>, aegis_gateway::engine::RequestCtx), aegis_gateway::anthropic::Reject>;

fn all() -> Vec<(&'static str, Transform)> {
    vec![
        ("anthropic", transform_request as Transform),
        ("chat", openai_chat::transform_request as Transform),
        (
            "responses",
            openai_responses::transform_request as Transform,
        ),
    ]
}

/// Whatever the outcome, the secret must not leave in the body that would be forwarded.
fn assert_safe(name: &str, body: &str) {
    for (proto, f) in all() {
        match f(engine(), &meta(), body.as_bytes()) {
            Err(_) => {} // refused: fine
            Ok((out, _)) => {
                let s = String::from_utf8_lossy(&out);
                assert!(
                    !s.contains("Jd8@2jd82k") && !s.contains("prod-db01"),
                    "{name}/{proto}: secret would be forwarded: {s}"
                );
            }
        }
    }
}

#[test]
fn duplicate_keys_cannot_hide_content() {
    // a parser that takes the first `messages` sees clean text; one that takes the last sees the secret
    assert_safe(
        "dup messages",
        &format!(
            r#"{{"model":"m","messages":[{{"role":"user","content":"hi"}}],"messages":[{{"role":"user","content":"{SECRET}"}}]}}"#
        ),
    );
    assert_safe(
        "dup content",
        &format!(
            r#"{{"model":"m","messages":[{{"role":"user","content":"hi","content":"{SECRET}"}}]}}"#
        ),
    );
    assert_safe(
        "dup input",
        &format!(r#"{{"model":"m","input":"hi","input":"{SECRET}"}}"#),
    );
    assert_safe(
        "dup system",
        &format!(r#"{{"model":"m","system":"x","system":"{SECRET}","messages":[]}}"#),
    );
    assert_safe(
        "dup text",
        &format!(
            r#"{{"model":"m","messages":[{{"role":"user","content":[{{"type":"text","text":"a","text":"{SECRET}"}}]}}]}}"#
        ),
    );
}

#[test]
fn undecodable_strings_cannot_hide_content() {
    // lone surrogate: strict decoders refuse it, lenient ones keep the rest of the text
    assert_safe(
        "lone surrogate",
        &format!(r#"{{"model":"m","messages":[{{"role":"user","content":"\ud800 {SECRET}"}}]}}"#),
    );
    assert_safe(
        "bad escape",
        &format!(r#"{{"model":"m","messages":[{{"role":"user","content":"\q {SECRET}"}}]}}"#),
    );
    assert_safe(
        "short unicode escape",
        &format!(r#"{{"model":"m","messages":[{{"role":"user","content":"\u12 {SECRET}"}}]}}"#),
    );
    let invalid_utf8 = [
        br#"{"model":"m","messages":[{"role":"user","content":""#.as_slice(),
        &[0xff, 0xfe],
        format!(" {SECRET}\"}}]}}").as_bytes(),
    ]
    .concat();
    for (proto, f) in all() {
        if let Ok((out, _)) = f(engine(), &meta(), &invalid_utf8) {
            let s = String::from_utf8_lossy(&out);
            assert!(!s.contains("Jd8@2jd82k"), "invalid utf-8/{proto}: {s}");
        }
    }
}

#[test]
fn malformed_literals_are_refused() {
    for lit in [
        "abc", "01", "1.", ".5", "+1", "0x10", "NaN", "Infinity", "tru", "nul", "1e", "--1",
    ] {
        let body = format!(
            r#"{{"model":"m","max_tokens":{lit},"messages":[{{"role":"user","content":"{SECRET}"}}]}}"#
        );
        for (proto, f) in all() {
            assert!(
                f(engine(), &meta(), body.as_bytes()).is_err(),
                "{proto}: literal {lit:?} must be refused"
            );
        }
    }
    for ok in [
        "0", "-0", "1", "-12", "1.5", "1e3", "1E+3", "2.5e-10", "true", "false", "null",
    ] {
        let body = format!(
            r#"{{"model":"m","max_tokens":{ok},"messages":[{{"role":"user","content":"hello"}}]}}"#
        );
        assert!(
            transform_request(engine(), &meta(), body.as_bytes()).is_ok(),
            "{ok}"
        );
    }
}

#[test]
fn bom_and_trailing_garbage_are_refused() {
    let body = format!(r#"{{"model":"m","messages":[{{"role":"user","content":"{SECRET}"}}]}}"#);
    for (proto, f) in all() {
        assert!(
            f(
                engine(),
                &meta(),
                &[b"\xEF\xBB\xBF".as_slice(), body.as_bytes()].concat()
            )
            .is_err(),
            "{proto} BOM"
        );
        assert!(
            f(engine(), &meta(), format!("{body} {{}}").as_bytes()).is_err(),
            "{proto} trailing"
        );
    }
}

// REQ: PRO-10 — a value in any string field is scanned, not only in the fields the adapter knows.
#[test]
fn secrets_in_unexpected_fields_are_masked() {
    let v = SECRET;
    let cases: Vec<(&str, &str, String)> = vec![
        (
            "anthropic",
            "tool schema description",
            format!(
                r#"{{"model":"m","tools":[{{"name":"t","description":"d","input_schema":{{"type":"object","properties":{{"x":{{"type":"string","description":"{v}"}}}}}}}}],"messages":[]}}"#
            ),
        ),
        (
            "anthropic",
            "metadata",
            format!(r#"{{"model":"m","metadata":{{"user_id":"{v}"}},"messages":[]}}"#),
        ),
        (
            "anthropic",
            "stop_sequences",
            format!(r#"{{"model":"m","stop_sequences":["{v}"],"messages":[]}}"#),
        ),
        (
            "anthropic",
            "unknown top-level field",
            format!(r#"{{"model":"m","x_custom":"{v}","messages":[]}}"#),
        ),
        (
            "anthropic",
            "unknown nested field",
            format!(
                r#"{{"model":"m","messages":[{{"role":"user","content":"hi","x_note":{{"a":["{v}"]}}}}]}}"#
            ),
        ),
        (
            "anthropic",
            "tool_choice",
            format!(
                r#"{{"model":"m","tool_choice":{{"type":"tool","note":"{v}"}},"messages":[]}}"#
            ),
        ),
        (
            "chat",
            "function parameters",
            format!(
                r#"{{"model":"m","tools":[{{"type":"function","function":{{"name":"f","parameters":{{"type":"object","description":"{v}"}}}}}}],"messages":[]}}"#
            ),
        ),
        (
            "chat",
            "response_format schema",
            format!(
                r#"{{"model":"m","response_format":{{"type":"json_schema","json_schema":{{"name":"n","schema":{{"description":"{v}"}}}}}},"messages":[]}}"#
            ),
        ),
        (
            "chat",
            "user field",
            format!(r#"{{"model":"m","user":"{v}","messages":[]}}"#),
        ),
        (
            "chat",
            "metadata",
            format!(r#"{{"model":"m","metadata":{{"k":"{v}"}},"messages":[]}}"#),
        ),
        (
            "chat",
            "unknown message field",
            format!(
                r#"{{"model":"m","messages":[{{"role":"user","content":"hi","extra":"{v}"}}]}}"#
            ),
        ),
        (
            "responses",
            "tool parameters",
            format!(
                r#"{{"model":"m","store":false,"tools":[{{"type":"function","name":"f","parameters":{{"description":"{v}"}}}}],"input":"hi"}}"#
            ),
        ),
        (
            "responses",
            "text format schema",
            format!(
                r#"{{"model":"m","store":false,"text":{{"format":{{"type":"json_schema","name":"n","schema":{{"description":"{v}"}}}}}},"input":"hi"}}"#
            ),
        ),
        (
            "responses",
            "metadata",
            format!(r#"{{"model":"m","store":false,"metadata":{{"k":"{v}"}},"input":"hi"}}"#),
        ),
        (
            "responses",
            "unknown item field",
            format!(
                r#"{{"model":"m","store":false,"input":[{{"type":"message","role":"user","content":"hi","note":"{v}"}}]}}"#
            ),
        ),
    ];
    for (proto, what, body) in cases {
        let f = all().into_iter().find(|(n, _)| *n == proto).unwrap().1;
        match f(engine(), &meta(), body.as_bytes()) {
            Err(_) => {}
            Ok((out, _)) => {
                let s = String::from_utf8_lossy(&out);
                assert!(
                    !s.contains("Jd8@2jd82k") && !s.contains("prod-db01"),
                    "{proto}/{what}: not masked: {s}"
                );
            }
        }
    }
}

// The fields the provider needs intact stay intact.
#[test]
fn structural_fields_are_not_touched() {
    let body = r#"{"model":"claude-sonnet-x","max_tokens":10,"tools":[{"name":"get_weather","description":"Weather","input_schema":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}}],"tool_choice":{"type":"tool","name":"get_weather"},"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]},{"role":"assistant","content":[{"type":"tool_use","id":"toolu_01ABC","name":"get_weather","input":{"city":"Paris"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_01ABC","content":"sunny"}]}]}"#;
    let (out, _) = transform_request(engine(), &meta(), body.as_bytes()).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["model"], "claude-sonnet-x");
    assert_eq!(v["tools"][0]["name"], "get_weather");
    assert_eq!(v["tool_choice"]["name"], "get_weather");
    assert_eq!(v["messages"][1]["content"][0]["id"], "toolu_01ABC");
    assert_eq!(v["messages"][2]["content"][0]["tool_use_id"], "toolu_01ABC");
    assert_eq!(v["tools"][0]["input_schema"]["required"][0], "city");
}

// REQ: PRO-10 — identifiers, keys and numbers cannot carry a value either: they must stay
// intact for the provider, so the request is refused instead of masked.
#[test]
fn secrets_in_identifiers_keys_and_numbers_are_refused() {
    let v = SECRET;
    let cases: Vec<(&str, &str, String)> = vec![
        (
            "anthropic",
            "tool_use id",
            format!(
                r#"{{"model":"m","messages":[{{"role":"assistant","content":[{{"type":"tool_use","id":"{v}","name":"t","input":{{}}}}]}}]}}"#
            ),
        ),
        (
            "anthropic",
            "object key",
            format!(r#"{{"model":"m","metadata":{{"{v}":"x"}},"messages":[]}}"#),
        ),
        (
            "anthropic",
            "tool name",
            format!(
                r#"{{"model":"m","tools":[{{"name":"{v}","input_schema":{{}}}}],"messages":[]}}"#
            ),
        ),
        (
            "chat",
            "number",
            r#"{"model":"m","messages":[],"card_number":4111111111111111}"#.to_string(),
        ),
        (
            "chat",
            "nested argument key",
            format!(
                r#"{{"model":"m","messages":[{{"role":"assistant","tool_calls":[{{"id":"c1","type":"function","function":{{"name":"f","arguments":"{{\"{v}\":1}}"}}}}]}}]}}"#
            ),
        ),
        (
            "responses",
            "call_id",
            format!(
                r#"{{"model":"m","store":false,"input":[{{"type":"function_call_output","call_id":"{v}","output":"x"}}]}}"#
            ),
        ),
    ];
    for (proto, what, body) in cases {
        let f = all().into_iter().find(|(n, _)| *n == proto).unwrap().1;
        match f(engine(), &meta(), body.as_bytes()) {
            Err(r) => assert!(r.status == 403 || r.status == 400, "{proto}/{what}"),
            Ok((out, _)) => {
                let s = String::from_utf8_lossy(&out);
                assert!(
                    !s.contains("Jd8@2jd82k") && !s.contains("4111111111111111"),
                    "{proto}/{what}: leaked: {s}"
                );
            }
        }
    }
}

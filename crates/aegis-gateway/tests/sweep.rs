#![allow(clippy::unwrap_used)]
//! REQ: DET-35 — a secret found in one block of a request is masked in the other blocks that hold
//! the same text: the output of a program that prints the password it read has no keyword around it.

use aegis_core::crypto::TenantKeys;
use aegis_core::detect::{DetectConfig, Dictionary};
use aegis_gateway::anthropic::{transform_request, ReqMeta};
use aegis_gateway::engine::Engine;
use serde_json::{json, Value};

const PW: &str = "p%4ss#w0rd9";

fn engine(sweep: bool) -> Engine {
    let keys = TenantKeys::from_secrets("t1", b"k-tenant-0123456789", b"k-audit-0123456789");
    let det = DetectConfig {
        internal_zones: vec!["corp.local".into()],
        sweep_secrets: sweep,
        ..Default::default()
    };
    Engine::new(keys, det, Dictionary::default())
}

/// The conversation: the agent read `config.ini`, then ran a script whose output is `printed`.
fn sent(e: &Engine, printed: &str) -> String {
    let req = json!({"model": "m", "max_tokens": 1024, "messages": [
        {"role": "user", "content": "fix the login"},
        {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "config.ini"}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": format!("[db]\npassword = {PW}\n")}]},
        {"role": "assistant", "content": [{"type": "tool_use", "id": "t2", "name": "Bash", "input": {"command": "python3 -c 'import cfg; print(cfg.password())'"}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t2", "content": printed}]}]});
    let (out, _) = transform_request(
        e,
        &ReqMeta {
            principal: "u",
            conversation: Some("c"),
            request_id: "r",
            route: "t",
        },
        req.to_string().as_bytes(),
    )
    .unwrap();
    let v: Value = serde_json::from_slice(&out).unwrap();
    v.to_string()
}

fn pseudonyms(s: &str) -> Vec<String> {
    s.match_indices("[[SECRET_")
        .map(|(i, _)| s[i..].split("]]").next().unwrap().to_string())
        .collect()
}

#[test]
fn a_secret_printed_by_a_program_is_masked_like_the_one_in_the_file() {
    let e = engine(true);
    for printed in [
        "OK 'p%4ss#w0rd9'".to_string(),
        PW.to_string(),
        format!("got {PW}\nsecond line"),
        format!("[{PW}]"),
    ] {
        let out = sent(&e, &printed);
        assert!(!out.contains(PW), "{printed}: {out}");
        // one value, one pseudonym, in both blocks
        let ps = pseudonyms(&out);
        assert_eq!(ps.len(), 2, "{printed}: {out}");
        assert_eq!(ps[0], ps[1], "{printed}: {out}");
    }
}

#[test]
fn only_the_whole_token_is_swept() {
    let e = engine(true);
    // part of a longer word is another string
    let out = sent(&e, &format!("x{PW}y and {PW}_tail and a{PW}"));
    assert_eq!(out.matches(PW).count(), 3, "{out}");
    // the switch
    let out = sent(&engine(false), &format!("OK {PW}"));
    assert!(out.contains(PW), "{out}");
}

#[test]
fn a_short_value_is_not_swept() {
    // a six-character password in a file: the keyword rules find it there, the same six characters
    // in prose are a word more often than not
    let e = engine(true);
    let req = json!({"model": "m", "max_tokens": 64, "messages": [
        {"role": "user", "content": "password = Ab3!xy"},
        {"role": "user", "content": "the value Ab3!xy was printed"}]});
    let (out, _) = transform_request(
        &e,
        &ReqMeta {
            principal: "u",
            conversation: Some("c"),
            request_id: "r",
            route: "t",
        },
        req.to_string().as_bytes(),
    )
    .unwrap();
    let out = String::from_utf8(out).unwrap();
    assert!(out.contains("the value Ab3!xy was printed"), "{out}");
}

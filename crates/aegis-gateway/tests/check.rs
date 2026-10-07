#![allow(clippy::unwrap_used)]
//! REQ: CFG-04, CFG-05, NFR-09 — `aegis-gateway check`.

use std::process::{Command, Output};

fn check(cfg: &str, env: &[(&str, &str)]) -> (Output, String) {
    let dir =
        std::env::temp_dir().join(format!("aegis-check-{}-{}", std::process::id(), cfg.len()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gateway.json");
    std::fs::write(&path, cfg).unwrap();
    let mut c = Command::new(env!("CARGO_BIN_EXE_aegis-gateway"));
    c.args(["check", path.to_str().unwrap()])
        .env_remove("AEGIS_K_TENANT")
        .env_remove("AEGIS_K_AUDIT")
        .env_remove("AEGIS_ANTHROPIC_KEY")
        .env_remove("AEGIS_PROVIDER_KEY")
        .env_remove("AEGIS_OPENAI_KEY")
        .env_remove("AEGIS_GEMINI_KEY");
    for (k, v) in env {
        c.env(k, v);
    }
    let o = c.output().unwrap();
    let text = String::from_utf8_lossy(&o.stdout).to_string();
    let _ = std::fs::remove_dir_all(&dir);
    (o, text)
}

const KEYS: &[(&str, &str)] = &[
    ("AEGIS_K_TENANT", "0123456789abcdef0123456789abcdef"),
    ("AEGIS_K_AUDIT", "fedcba9876543210fedcba9876543210"),
];

fn with(extra: &[(&'static str, &'static str)]) -> Vec<(&'static str, &'static str)> {
    KEYS.iter().chain(extra).copied().collect()
}

// A healthy configuration passes, and the output names what was checked without printing a key.
#[test]
fn a_healthy_configuration_passes_and_prints_no_key() {
    let cfg = r#"{"listen":"127.0.0.1:0","admin_listen":"127.0.0.1:0","anthropic_base_url":"https://user:pw@api.anthropic.com/x?token=abc",
        "virtual_keys":[{"sha256":"ab","principal":"u:x"}]}"#;
    let (o, text) = check(
        cfg,
        &with(&[("AEGIS_ANTHROPIC_KEY", "sk-ant-VERY-SECRET-KEY-123")]),
    );
    assert!(o.status.success(), "{text}");
    assert!(text.contains("провайдер Anthropic") && text.contains("Всё в порядке"));
    for leak in ["VERY-SECRET", "user:pw", "token=abc", "0123456789abcdef"] {
        assert!(!text.contains(leak), "{leak} printed: {text}");
    }
    // plain HTTP on a public address is called out
    let (_, text) = check(
        &cfg.replace("127.0.0.1:0\",\"admin", "0.0.0.0:0\",\"admin"),
        &with(&[("AEGIS_ANTHROPIC_KEY", "k")]),
    );
    assert!(text.contains("TLS завершайте"), "{text}");
}

// Everything that would stop the gateway is reported at once, and the exit status is 1.
#[test]
fn problems_are_all_reported() {
    // no keys, no provider key, no clients
    let (o, text) = check(
        r#"{"listen":"127.0.0.1:0","admin_listen":"127.0.0.1:0","anthropic_base_url":"http://x"}"#,
        &[],
    );
    assert_eq!(o.status.code(), Some(1));
    assert!(
        text.contains("AEGIS_K_TENANT не задан") && text.contains("AEGIS_K_AUDIT не задан"),
        "{text}"
    );
    assert!(text.contains("AEGIS_ANTHROPIC_KEY"), "{text}");
    // short and equal keys
    let (o, text) = check(
        r#"{"listen":"127.0.0.1:0","admin_listen":"127.0.0.1:0","anthropic_base_url":"http://x","virtual_keys":[{"sha256":"ab","principal":"u"}]}"#,
        &[
            ("AEGIS_K_TENANT", "short"),
            ("AEGIS_K_AUDIT", "short"),
            ("AEGIS_ANTHROPIC_KEY", "k"),
        ],
    );
    assert_eq!(o.status.code(), Some(1));
    assert!(text.contains("короче 16"), "{text}");
    // nobody can authenticate
    let (o, text) = check(
        r#"{"listen":"127.0.0.1:0","admin_listen":"127.0.0.1:0","anthropic_base_url":"http://x"}"#,
        &with(&[("AEGIS_ANTHROPIC_KEY", "k")]),
    );
    assert_eq!(o.status.code(), Some(1));
    assert!(text.contains("ни один клиент не пройдёт"), "{text}");
    // no provider at all, a broken file, a missing bundle, a busy port
    let (o, text) = check(
        r#"{"virtual_keys":[{"sha256":"ab","principal":"u"}]}"#,
        &with(&[]),
    );
    assert_eq!(o.status.code(), Some(1));
    assert!(text.contains("no provider"), "{text}");
    let (o, text) = check("{not json", &with(&[]));
    assert_eq!(o.status.code(), Some(1));
    assert!(text.contains("конфигурация"), "{text}");
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let busy = l.local_addr().unwrap();
    let (o, text) = check(
        &format!(
            r#"{{"listen":"{busy}","admin_listen":"127.0.0.1:0","anthropic_base_url":"http://x","virtual_keys":[{{"sha256":"ab","principal":"u"}}]}}"#
        ),
        &with(&[("AEGIS_ANTHROPIC_KEY", "k")]),
    );
    assert_eq!(o.status.code(), Some(1));
    assert!(
        text.contains("основной порт") && text.contains("FAIL"),
        "{text}"
    );
    let cfg = r#"{"listen":"127.0.0.1:0","admin_listen":"127.0.0.1:0","anthropic_base_url":"http://x",
        "bundle":{"source":"/nonexistent/bundle.json","trusted_keys":["00"],"reload_seconds":15}}"#;
    let (o, text) = check(cfg, &with(&[("AEGIS_ANTHROPIC_KEY", "k")]));
    assert_eq!(o.status.code(), Some(1));
    assert!(text.contains("FAIL"), "{text}");
}

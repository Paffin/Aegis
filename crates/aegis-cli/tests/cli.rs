#![allow(clippy::unwrap_used)]
//! The administration flow with the real binary. REQ: CFG-03, CFG-04, POL-09, IAM-03, CFG-01.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn aegis(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_aegis"))
        .args(args)
        .output()
        .unwrap()
}

fn ok(o: &Output) -> String {
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

fn err(o: &Output) -> String {
    assert!(
        !o.status.success(),
        "expected failure, got: {}",
        String::from_utf8_lossy(&o.stdout)
    );
    String::from_utf8_lossy(&o.stderr).to_string()
}

struct Dir(PathBuf);
impl Dir {
    fn new(name: &str) -> Self {
        let d = std::env::temp_dir().join(format!("aegis-cli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Dir(d)
    }
    fn p(&self, f: &str) -> String {
        self.0.join(f).to_str().unwrap().to_string()
    }
    fn write(&self, f: &str, c: &str) -> String {
        std::fs::write(self.0.join(f), c).unwrap();
        self.p(f)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const POLICY: &str = r#"
version: 1
tenant: acme
zones: { internal: [corp.local] }
detectors:
  custom:
    - id: acme-token
      type: SECRET
      regex: 'ACME-TKN-([A-Z0-9]{12})'
      group: 1
      examples: { matches: ["ACME-TKN-AB12CD34EF56"], non_matches: ["ACME-TKN-x"] }
rules:
  - id: R-112
    when: { sink: [shell_network, network] }
    restore: { SECRET: deny, INFRA: internal_only }
"#;

const TESTS: &str = r#"
ingress:
  - text: "token ACME-TKN-AB12CD34EF56 on prod-db01.corp.local"
    expect:
      - { contains: "AB12CD34EF56", type: SECRET, kind: custom, action: mask }
      - { contains: "prod-db01.corp.local", type: HOST, action: mask }
restore:
  - { sink: shell_network, type: SECRET, action: deny, rule: R-112 }
"#;

// REQ: CFG-03, CFG-01, CFG-04, POL-09, IAM-03
#[test]
fn full_admin_flow() {
    let d = Dir::new("flow");
    let key = d.p("signing.key");
    let out = ok(&aegis(&["keys", "generate", "--out", &key]));
    let public = out
        .lines()
        .find_map(|l| l.strip_prefix("public key: "))
        .unwrap()
        .to_string();
    assert_eq!(public.len(), 64);
    assert_eq!(ok(&aegis(&["keys", "public", &key])), public);
    assert!(
        err(&aegis(&["keys", "generate", "--out", &key])).contains("не перезаписывается"),
        "never overwrite a signing key"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    // virtual keys: printed once, only hashes land in the list
    let vfile = d.p("vkeys.json");
    let vk = ok(&aegis(&[
        "vkey",
        "issue",
        "--principal",
        "u:ivanov",
        "--groups",
        "dev",
        "--file",
        &vfile,
    ]));
    assert!(vk.starts_with("aegis-vk-") && vk.len() > 40);
    let list = std::fs::read_to_string(&vfile).unwrap();
    assert!(!list.contains(&vk), "the key itself is never stored");
    assert!(list.contains(&ok(&aegis(&["vkey", "hash", &vk]))));
    assert!(err(&aegis(&[
        "vkey",
        "issue",
        "--principal",
        "u:ivanov",
        "--file",
        &vfile
    ]))
    .contains("уже выпущен"));

    let policy = d.write("policy.yaml", POLICY);
    let tests = d.write("tests.yaml", TESTS);
    assert!(ok(&aegis(&["policy", "check", &policy])).contains("корректна"));
    assert!(ok(&aegis(&["policy", "test", &policy, &tests])).contains("проверок пройдено"));

    let bundle = d.p("bundle.json");
    let b = aegis(&[
        "bundle",
        "build",
        "--policy",
        &policy,
        "--tests",
        &tests,
        "--key",
        &key,
        "--version",
        "2026.10.07-1",
        "--vkeys",
        &vfile,
        "-o",
        &bundle,
    ]);
    assert!(ok(&b).contains("2026.10.07-1"));
    assert!(
        ok(&aegis(&["bundle", "verify", &bundle, "--trusted", &public]))
            .contains("виртуальных ключей: 1")
    );

    // wrong signer, and tampering
    let other = d.p("other.key");
    let other_pub = ok(&aegis(&["keys", "generate", "--out", &other]))
        .lines()
        .next()
        .unwrap()
        .replace("public key: ", "");
    assert!(err(&aegis(&[
        "bundle",
        "verify",
        &bundle,
        "--trusted",
        &other_pub
    ]))
    .contains("не входит в список доверенных"));
    let mut raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&bundle).unwrap()).unwrap();
    raw["payload"] =
        serde_json::Value::String(raw["payload"].as_str().unwrap().replacen('e', "f", 1));
    let tampered = d.write("tampered.json", &raw.to_string());
    assert!(
        !aegis(&["bundle", "verify", &tampered, "--trusted", &public])
            .status
            .success()
    );

    // revocation removes the principal from the list; the next bundle no longer carries it
    ok(&aegis(&[
        "vkey",
        "revoke",
        "--principal",
        "u:ivanov",
        "--file",
        &vfile,
    ]));
    assert_eq!(std::fs::read_to_string(&vfile).unwrap().trim(), "[]");
    assert!(err(&aegis(&[
        "vkey",
        "revoke",
        "--principal",
        "u:ivanov",
        "--file",
        &vfile
    ]))
    .contains("не найден"));
}

// REQ: CFG-03, POL-09 — a failing test, a missing test file or a broken detector stops the build.
#[test]
fn build_stops_on_any_failure() {
    let d = Dir::new("stop");
    let key = d.p("k.key");
    ok(&aegis(&["keys", "generate", "--out", &key]));
    let out = d.p("b.json");
    let build = |policy: &str, tests: Option<&str>, no_tests: bool| {
        let mut a = vec![
            "bundle",
            "build",
            "--policy",
            policy,
            "--key",
            &key,
            "--version",
            "v",
            "-o",
            &out,
        ];
        if let Some(t) = tests {
            a.extend(["--tests", t]);
        }
        if no_tests {
            a.push("--no-tests");
        }
        aegis(&a)
    };
    let policy = d.write("p.yaml", POLICY);
    let failing = d.write(
        "fail.yaml",
        "restore:\n  - { sink: text, type: SECRET, action: deny }\n",
    );
    let e = err(&build(&policy, Some(&failing), false));
    assert!(
        e.contains("бандл не собран") && e.contains("ожидалось deny"),
        "{e}"
    );
    assert!(!Path::new(&out).exists(), "no bundle on failure");

    assert!(
        err(&build(&policy, None, false)).contains("--no-tests"),
        "tests are mandatory unless waived explicitly"
    );
    assert!(!Path::new(&out).exists());

    let no_examples = d.write(
        "noex.yaml",
        &POLICY.replace(
            r#"examples: { matches: ["ACME-TKN-AB12CD34EF56"], non_matches: ["ACME-TKN-x"] }"#,
            "examples: { matches: [] }",
        ),
    );
    assert!(
        err(&build(&no_examples, Some(&d.write("t.yaml", TESTS)), false)).contains("нет примеров")
    );
    let bad_yaml = d.write("bad.yaml", "version: 1\nunknown: true\n");
    assert!(err(&build(&bad_yaml, None, true)).contains("unknown field"));
    assert!(!Path::new(&out).exists());

    // an explicit waiver works and warns
    let o = build(&policy, None, true);
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("без тестов"));
}

// REQ: AUD-05 — report by period and by conversation, from an audit file without values.
#[test]
fn report_summarises_audit_without_values() {
    let d = Dir::new("report");
    let ev = |ts: &str, conv: &str, secret: u32, deny: bool| {
        serde_json::json!({
            "ts": ts, "request_id": "r", "tenant": "t", "principal": "u:ivanov", "client": "claude-code", "route": "x", "model": "m",
            "conversation": conv, "bundle_version": "v1", "decision": "allow",
            "sizes": {"request_bytes": 1, "blocks": 10, "blocks_scanned": 2},
            "latency_ms": {}, "entities": [{"type": "SECRET", "kind": "password", "audit_hash": "7b21e09c4f1a2d3b", "count": secret, "action": "mask", "rule": "default"},
                                           {"type": "HOST", "audit_hash": "4c1e88a0b2d14f90", "count": 3, "action": "mask", "rule": "default"}],
            "trifecta": {"private": true, "untrusted": deny, "mode": "enforce"},
            "sinks": if deny { vec![serde_json::json!({"tool": "Bash", "sink": "shell_network", "decision": "deny", "rule": "R-112", "classes": ["SECRET"]})] } else { vec![] }
        })
        .to_string()
    };
    let lines = [
        ev("2026-10-07T10:00:00.000Z", "aaaa", 1, false),
        ev("2026-10-07T11:00:00.000Z", "aaaa", 1, true),
        ev("2026-10-08T09:00:00.000Z", "bbbb", 2, false),
    ]
    .join("\n")
        + "\nnot json\n";
    let f = d.write("audit.jsonl", &lines);

    let all = aegis(&["report", &f]);
    let out = ok(&all);
    assert!(out.contains("запросов: 3"), "{out}");
    assert!(out.contains("SECRET=4") && out.contains("HOST=9"), "{out}");
    assert!(out.contains("R-112 (Bash → shell_network)=1"), "{out}");
    assert!(out.contains("приватными данными и недоверенным контентом: 1"));
    assert!(
        out.contains("SECRET 7b21e09c4f1a2d3b: 4"),
        "values seen repeatedly are reported by hash"
    );
    assert!(String::from_utf8_lossy(&all.stderr).contains("не удалось разобрать: 1"));

    let one = ok(&aegis(&["report", &f, "--conversation", "aaaa"]));
    assert!(
        one.contains("запросов: 2 (разговор aaaa)") && one.contains("SECRET=2"),
        "{one}"
    );
    let day = ok(&aegis(&["report", &f, "--since", "2026-10-08T00:00:00Z"]));
    assert!(day.contains("запросов: 1"), "{day}");
    let none = ok(&aegis(&["report", &f, "--until", "2026-10-07T10:30:00Z"]));
    assert!(none.contains("запросов: 1"), "{none}");
    assert!(err(&aegis(&["report", &f, "--since", "yesterday"])).contains("YYYY-MM-DD"));
}

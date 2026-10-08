#![allow(clippy::unwrap_used)]
//! REQ: QA-04, SEC-10, INV-1, INV-3, INV-4, INV-5 — property-based tests of the core.
//!
//! Random text is built from noise and from fragments that carry known sensitive values; the
//! properties must hold for every combination, not only for hand-picked examples.

use aegis_core::bundle::PolicyDoc;
use aegis_core::crypto::{derive_salt, Salt, SaltInput, TenantKeys};
use aegis_core::detect::{DetectConfig, Dictionary, Pipeline};
use aegis_core::policy::{RestorePolicy, Sink, TrifectaConfig, TrifectaState};
use aegis_core::pseudo::{transform_blocks, Mapping, PseudoConfig, Pseudonymizer, Source};
use aegis_core::restore::{restore, SinkContext};
use aegis_core::shell::{self, ShellClass};
use proptest::prelude::*;

struct Fx {
    keys: TenantKeys,
    salt: Salt,
    pcfg: PseudoConfig,
    det: DetectConfig,
    pipe: Pipeline,
}

fn fx() -> &'static Fx {
    static F: std::sync::OnceLock<Fx> = std::sync::OnceLock::new();
    F.get_or_init(build_fx)
}

fn build_fx() -> Fx {
    let keys = TenantKeys::from_secrets("t1", b"k-tenant-0123456789", b"k-audit-0123456789");
    let (salt, _) = derive_salt(
        &keys,
        &SaltInput {
            principal: "u",
            header: Some("c1"),
            session_field: None,
            first_user_message: &[],
        },
    );
    let det = DetectConfig {
        internal_zones: vec!["corp.local".into(), "company.ru".into()],
        company_ranges: vec![(u32::from_be_bytes([10, 50, 0, 0]), 16)],
        ..Default::default()
    };
    let mut d = Dictionary::default();
    d.add_person("Иван", "Петров");
    Fx {
        keys,
        salt,
        pcfg: PseudoConfig::default(),
        pipe: Pipeline::new(det.clone(), d),
        det,
    }
}

fn mask(f: &Fx, blocks: &[String]) -> (Vec<String>, Mapping) {
    let p = Pseudonymizer {
        keys: &f.keys,
        salt: &f.salt,
        cfg: &f.pcfg,
        detect: &f.det,
    };
    let b: Vec<(String, Source)> = blocks.iter().map(|t| (t.clone(), Source::User)).collect();
    let mut m = Mapping::default();
    (transform_blocks(&p, &f.pipe, &b, &mut m), m)
}

/// A fragment with its value (what must not survive) and the context that makes it detectable.
const SENSITIVE: &[(&str, &str)] = &[
    (
        "host prod-db01.pay.corp.local is down",
        "prod-db01.pay.corp.local",
    ),
    ("password: \"Jd8@2jd82k\"", "Jd8@2jd82k"),
    (
        "aws_access_key_id = AKIAJ3KQ7P2WXNB5ZT4A",
        "AKIAJ3KQ7P2WXNB5ZT4A",
    ),
    (
        "token ghp_R7xQm2Kd9LpW4vTn8YbZc3JhGfS6aEu1XoNi",
        "ghp_R7xQm2Kd9LpW4vTn8YbZc3JhGfS6aEu1XoNi",
    ),
    ("owner ivan.petrov@company.ru", "ivan.petrov@company.ru"),
    ("gateway 10.50.3.7 answers", "10.50.3.7"),
    ("card number 4111 1111 1111 1111", "4111 1111 1111 1111"),
    ("Владелец Иван Петров", "Иван Петров"),
    (
        "url: jdbc:postgresql://svc:Xk9pQ2vL8m@prod-db02.pay.corp.local:5432/clients",
        "Xk9pQ2vL8m",
    ),
    ("DB_PASSWORD=Qw7!rT2#zL9x", "Qw7!rT2#zL9x"),
    ("export API_TOKEN='Zq4$mN8@vB2k'", "Zq4$mN8@vB2k"),
    ("curl -u admin:Tg5%hY1&jK3p https://prod-api.corp.local/x", "Tg5%hY1&jK3p"),
    ("Пароль от УЗ: Nf6^bV3*cX8z", "Nf6^bV3*cX8z"),
    ("redis://:Lm2-pO9_iU4w@cache01.pay.corp.local:6379/0", "Lm2-pO9_iU4w"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAxkq3\n-----END RSA PRIVATE KEY-----", "MIIEowIBAAKCAQEAxkq3"),
    ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuv", "abcdefghijklmnopqrstuv"),
];

/// How the surrounding text may wrap a fragment: code fence, comment, quote, indentation.
const WRAPS: &[&str] = &[
    "{}",
    "```\n{}\n```",
    "// {}",
    "<!-- {} -->",
    "> {}",
    "\t{}",
    "    {}",
];

fn noise() -> impl Strategy<Value = String> {
    prop_oneof![
        "[ -~]{0,16}",
        "[а-яА-Я ]{0,12}",
        Just("let x = foo(bar);".to_string()),
        Just("## Heading\n- item".to_string()),
        Just("{\"a\": [1, 2, 3]}".to_string()),
        Just("[[not a marker]]".to_string()),
    ]
}

/// Text made of noise and sensitive fragments, separated so that fragments stay detectable.
fn text_with_values() -> impl Strategy<Value = (String, Vec<&'static str>)> {
    prop::collection::vec(
        prop_oneof![
            noise().prop_map(|n| (n, None)),
            (0..SENSITIVE.len()).prop_map(|i| (SENSITIVE[i].0.to_string(), Some(SENSITIVE[i].1))),
        ],
        0..8,
    )
    .prop_map(|parts| {
        let mut text = String::new();
        let mut values = vec![];
        for (i, (t, v)) in parts.into_iter().enumerate() {
            let t = if v.is_some() {
                WRAPS[i % WRAPS.len()].replace("{}", &t)
            } else {
                t
            };
            text.push_str(&t);
            text.push('\n');
            if let Some(v) = v {
                values.push(v);
            }
        }
        (text, values)
    })
}

/// 64 cases per property in the normal run; `PROPTEST_CASES=5000` for a long hunt.
fn config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(64);
    ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    /// Detectors accept any text; spans are inside the text, on character boundaries, ordered.
    #[test]
    fn detection_never_panics_and_spans_are_valid(s in "\\PC{0,200}") {
        let f = fx();
        let ents = f.pipe.scan(&s);
        let mut prev_end = 0;
        for e in &ents {
            prop_assert!(e.span.start < e.span.end && e.span.end <= s.len());
            prop_assert!(s.is_char_boundary(e.span.start) && s.is_char_boundary(e.span.end));
            prop_assert!(e.span.start >= prev_end, "overlap: {:?}", ents);
            prev_end = e.span.end;
        }
    }

    /// No detected value survives masking, whatever surrounds it (INV-6 on the request path).
    #[test]
    fn sensitive_values_never_survive_masking((text, values) in text_with_values()) {
        let f = fx();
        let (out, _) = mask(f, std::slice::from_ref(&text));
        for v in values {
            prop_assert!(!out[0].contains(v), "{v:?} survived in {:?}", out[0]);
        }
    }

    /// INV-1: same input, same output; a block does not depend on the other blocks.
    #[test]
    fn masking_is_deterministic_and_block_local(
        (a, _) in text_with_values(),
        (b, _) in text_with_values(),
    ) {
        let f = fx();
        let alone = mask(f, std::slice::from_ref(&a)).0;
        let again = mask(f, std::slice::from_ref(&a)).0;
        prop_assert_eq!(&alone, &again);
        let together = mask(f, &[a.clone(), b.clone()]).0;
        prop_assert_eq!(&alone[0], &together[0]);
        let reversed = mask(f, &[b, a]).0;
        prop_assert_eq!(&alone[0], &reversed[1]);
    }

    /// INV-3: restoring a masked text and masking it again gives the same masked text
    /// (the original block stays in the request, as in a real conversation history).
    #[test]
    fn restore_then_mask_is_stable((text, _) in text_with_values()) {
        let f = fx();
        let (masked, m) = mask(f, std::slice::from_ref(&text));
        let tri = TrifectaConfig::default();
        let ctx = SinkContext {
            sink: Sink::Text,
            tool: "",
            target_path: None,
            detect: &f.det,
            trifecta_cfg: &tri,
            trifecta: TrifectaState::default(),
            precleared: false,
            guard: false,
        };
        let restored = restore(&masked[0], &m, &RestorePolicy::default(), &ctx).text;
        let again = mask(f, &[text.clone(), restored]).0;
        prop_assert_eq!(&again[0], &masked[0]);
        prop_assert_eq!(&again[1], &masked[0], "P(R(P(v))) != P(v)");
    }

    /// INV-4: Aegis-looking strings that are not in the mapping are never replaced.
    #[test]
    fn foreign_markers_are_never_restored(
        id in "[a-z2-7]{8}",
        zid in "[a-z2-7]{8}",
        ty in prop::sample::select(vec!["SECRET", "EMAIL", "PERSON", "DB", "SVC", "HOST"]),
        (text, _) in text_with_values(),
    ) {
        let f = fx();
        let (_, m) = mask(f, &[text]);
        let foreign = format!(
            "a [[{ty}_{id}]] b h-{id}.db.prod.z-{zid}.aegis.invalid c [[{ty}_{id} kind=password has=at]]"
        );
        let tri = TrifectaConfig::default();
        for sink in [Sink::Text, Sink::FileWrite, Sink::ShellLocal, Sink::ShellNetwork, Sink::Mcp] {
            let ctx = SinkContext {
                sink,
                tool: "",
                target_path: Some("x"),
                detect: &f.det,
                trifecta_cfg: &tri,
                trifecta: TrifectaState::default(),
                precleared: false,
            guard: false,
            };
            let out = restore(&foreign, &m, &RestorePolicy::default(), &ctx);
            prop_assert_eq!(&out.text, &foreign, "sink {:?}", sink);
        }
    }

    /// INV-5: a call that writes a file never reaches the client with a marker in it: it is
    /// denied, or every marker was replaced by its value.
    #[test]
    fn files_never_receive_markers(
        (text, _) in text_with_values(),
        foreign in prop::option::of("[a-z2-7]{8}"),
        path in prop::sample::select(vec!["x", "src/a.rs", "config/database.yaml"]),
    ) {
        let f = fx();
        let (masked, m) = mask(f, std::slice::from_ref(&text));
        let mut body = masked[0].clone();
        if let Some(id) = foreign {
            body.push_str(&format!("\n[[SECRET_{id} kind=password]]"));
        }
        let tri = TrifectaConfig::default();
        let ctx = SinkContext {
            sink: Sink::FileWrite,
            tool: "Write",
            target_path: Some(path),
            detect: &f.det,
            trifecta_cfg: &tri,
            trifecta: TrifectaState::default(),
            precleared: false,
            guard: false,
        };
        let out = restore(&body, &m, &RestorePolicy::default(), &ctx);
        if out.allowed() {
            prop_assert!(
                !aegis_core::pseudo::marker_grammar().is_match(&out.text)
                    && !out.text.contains(".aegis.invalid"),
                "marker written to a file: {:?}",
                out.text
            );
        }
    }

    /// A command with a network program is never classified as local (RST-07).
    #[test]
    fn network_programs_are_never_local(
        prog in prop::sample::select(vec![
            "curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "sftp", "rsync", "telnet",
            "ftp", "socat", "dig", "nslookup", "ping", "git push", "git fetch", "npm publish",
            "pip install", "docker push", "kubectl apply",
        ]),
        arg in "[a-zA-Z0-9./:=@_-]{0,20}",
        wrap in prop::sample::select(vec![
            "{}", "echo hi; {}", "echo hi && {}", "cat f | {}", "bash -c '{}'", "sh -c \"{}\"",
            "eval \"{}\"", "env X=1 {}", "sudo {}", "time {}", "(cd /tmp && {})", "x=$({})",
        ]),
    ) {
        let cmd = wrap.replace("{}", &format!("{prog} {arg}"));
        let class = shell::analyze(&cmd).class;
        prop_assert!(class != ShellClass::Local, "classified local: {cmd}");
    }

    /// The shell lexer, the policy and the restore engine accept any text.
    #[test]
    fn parsers_never_panic(s in "\\PC{0,300}", t in "[ -~\\n]{0,300}") {
        let _ = shell::analyze(&s);
        let _ = shell::analyze(&t);
        let _ = PolicyDoc::from_yaml(&s);
        let _ = PolicyDoc::from_yaml(&t);
        let f = fx();
        let tri = TrifectaConfig::default();
        let (_, m) = mask(f, std::slice::from_ref(&s));
        for sink in [Sink::Text, Sink::FileWrite, Sink::ShellNetwork, Sink::Unknown] {
            let ctx = SinkContext {
                sink,
                tool: "t",
                target_path: Some("p"),
                detect: &f.det,
                trifecta_cfg: &tri,
                trifecta: TrifectaState::default(),
                precleared: false,
            guard: false,
            };
            let _ = restore(&s, &m, &RestorePolicy::default(), &ctx);
            let _ = restore(&t, &m, &RestorePolicy::default(), &ctx);
        }
    }
}

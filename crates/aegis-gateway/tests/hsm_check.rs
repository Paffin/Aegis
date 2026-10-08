#![allow(clippy::unwrap_used)]
//! REQ: CFG-07, CFG-04, NFR-09 — `aegis-gateway check` and the start of the gateway with keys in an
//! HSM: a key that cannot be used is reported (never with the PIN or the key), the process does not
//! start without it. The real token is kryoptic (`scripts/build-kryoptic.sh`, `AEGIS_TEST_KRYOPTIC`);
//! without it only the cases that need no token run.

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use std::process::{Command, Output};

const CFG: &str = r#"{"listen":"127.0.0.1:0","admin_listen":"127.0.0.1:0","anthropic_base_url":"https://api.anthropic.com","virtual_keys":[{"sha256":"ab","principal":"u:x"}]}"#;
const PIN: &str = "pin-9f3a-not-for-printing";

fn bin(cfg_dir: &std::path::Path, sub: &str, env: &[(&str, String)]) -> (Output, String) {
    let path = cfg_dir.join("gateway.json");
    std::fs::write(&path, CFG).unwrap();
    let mut c = Command::new(env!("CARGO_BIN_EXE_aegis-gateway"));
    if sub == "check" {
        c.args(["check", path.to_str().unwrap()]);
    } else {
        c.arg(path.to_str().unwrap());
    }
    for k in [
        "AEGIS_K_TENANT",
        "AEGIS_K_AUDIT",
        "AEGIS_K_TENANT_FILE",
        "AEGIS_K_AUDIT_FILE",
        "AEGIS_K_TENANT_PKCS11",
        "AEGIS_K_AUDIT_PKCS11",
        "AEGIS_HSM_PIN",
        "AEGIS_HSM_PIN_FILE",
        "AEGIS_PROVIDER_KEY",
    ] {
        c.env_remove(k);
    }
    c.env("AEGIS_ANTHROPIC_KEY", "k");
    for (k, v) in env {
        c.env(k, v);
    }
    // (a gateway that does start would serve for ever: it is killed after a while and fails the test)
    c.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = c.spawn().unwrap();
    let start = std::time::Instant::now();
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() > std::time::Duration::from_secs(30) {
            child.kill().unwrap();
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let o = child.wait_with_output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    (o, text)
}

fn temp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("aegis-hsm-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

// REQ: CFG-07 — what is wrong with the description of a key is reported without the PIN, and stops the gateway.
#[test]
fn a_broken_hsm_key_is_reported_and_stops_the_gateway() {
    let dir = temp("broken");
    let ok_key = "0123456789abcdef0123456789abcdef".to_string();
    let spec = |s: &str| ("AEGIS_K_TENANT_PKCS11", s.to_string());
    let cases: Vec<(Vec<(&str, String)>, &str)> = vec![
        // a module that is not there
        (
            vec![
                spec("module=/nonexistent/libnone.so;token=t;label=k"),
                ("AEGIS_HSM_PIN", PIN.into()),
            ],
            "модуль PKCS#11",
        ),
        // a PIN in the description: refused, not echoed
        (
            vec![spec(&format!("module=/m.so;token=t;label=k;pin={PIN}"))],
            "неизвестный параметр",
        ),
        // a part that is not name=value (maybe a PIN): not echoed
        (
            vec![spec(&format!("module=/m.so;token=t;label=k;{PIN}"))],
            "без «=»",
        ),
        // the same key from two places
        (
            vec![
                spec("module=/m.so;token=t;label=k"),
                ("AEGIS_K_TENANT", ok_key.clone()),
            ],
            "оставьте один источник",
        ),
    ];
    for (env, expect) in cases {
        let mut env = env;
        env.push(("AEGIS_K_AUDIT", ok_key.replace('0', "9")));
        let (o, text) = bin(&dir, "check", &env);
        assert_eq!(o.status.code(), Some(1), "{text}");
        assert!(text.contains(expect), "{expect}: {text}");
        assert!(!text.contains(PIN), "the PIN is printed: {text}");
        // and the gateway itself does not start
        let (o, text) = bin(&dir, "run", &env);
        assert_eq!(o.status.code(), Some(2), "{text}");
        assert!(!text.contains(PIN), "the PIN is printed: {text}");
    }
    let _ = std::fs::remove_dir_all(dir);
}

fn kryoptic() -> Option<std::path::PathBuf> {
    let found = std::env::var("AEGIS_TEST_KRYOPTIC")
        .ok()
        .map(std::path::PathBuf::from)
        .filter(|p| p.exists());
    // CI sets this: a missing token there is a broken setup, not a reason to skip
    assert!(
        found.is_some() || std::env::var("AEGIS_REQUIRE_TOKEN").is_err(),
        "AEGIS_REQUIRE_TOKEN is set but kryoptic was not found (AEGIS_TEST_KRYOPTIC)"
    );
    found
}

// REQ: CFG-07, CFG-04 — keys in a real token: `check` says what it found and how long a HMAC takes,
// a wrong PIN or a missing key fails it, and nothing secret is printed.
#[test]
fn check_opens_the_keys_in_a_real_token() {
    let Some(module) = kryoptic() else {
        eprintln!("SKIPPED: set AEGIS_TEST_KRYOPTIC (scripts/build-kryoptic.sh)");
        return;
    };
    let dir = temp("real");
    let conf = dir.join("token.conf");
    std::fs::write(
        &conf,
        format!(
            "[[slots]]\nslot = 1\ndbtype = \"sqlite\"\ndbargs = \"{}\"\n",
            dir.join("t.sql").display()
        ),
    )
    .unwrap();
    // make the token the way an administrator would: initialize, set the PIN, then create the keys
    std::env::set_var("KRYOPTIC_CONF", &conf);
    let ctx = Pkcs11::new(&module).unwrap();
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    let slot = ctx.get_all_slots().unwrap()[0];
    let so = AuthPin::new("so-pin-0000".into());
    ctx.init_token(slot, &so, "aegis-check").unwrap();
    let s = ctx.open_rw_session(slot).unwrap();
    s.login(UserType::So, Some(&so)).unwrap();
    s.init_pin(&AuthPin::new(PIN.into())).unwrap();
    drop(s);
    let m = module.display();
    for label in ["k_t", "k_audit"] {
        let spec = format!("module={m};token=aegis-check;label={label}")
            .parse()
            .unwrap();
        aegis_hsm::create_key(&spec, PIN, aegis_hsm::Material::Generate(32)).unwrap();
    }

    let good = |pin: &str| -> Vec<(&str, String)> {
        vec![
            ("KRYOPTIC_CONF", conf.display().to_string()),
            (
                "AEGIS_K_TENANT_PKCS11",
                format!("module={m};token=aegis-check;label=k_t"),
            ),
            (
                "AEGIS_K_AUDIT_PKCS11",
                format!("module={m};token=aegis-check;label=k_audit"),
            ),
            ("AEGIS_HSM_PIN", pin.to_string()),
        ]
    };
    let (o, text) = bin(&dir, "check", &good(PIN));
    assert!(o.status.success(), "{text}");
    assert!(
        text.contains("AEGIS_K_TENANT_PKCS11: токен «aegis-check»"),
        "{text}"
    );
    assert!(
        text.contains("AEGIS_K_AUDIT_PKCS11") && text.contains("HMAC через токен"),
        "{text}"
    );
    assert!(
        text.contains("256 бит, не извлекаемый") && text.contains("Всё в порядке"),
        "{text}"
    );
    assert!(!text.contains(PIN), "the PIN is printed: {text}");

    // the PIN from a file works the same, and a file that others can read is called out
    let pin_file = dir.join("pin");
    std::fs::write(&pin_file, format!("{PIN}\n")).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&pin_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let mut env = good(PIN);
    env.retain(|(k, _)| *k != "AEGIS_HSM_PIN");
    env.push(("AEGIS_HSM_PIN_FILE", pin_file.display().to_string()));
    let (o, text) = bin(&dir, "check", &env);
    assert_eq!(o.status.code(), Some(1), "{text}");
    assert!(
        text.contains("AEGIS_HSM_PIN_FILE") && text.contains("644"),
        "{text}"
    );
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&pin_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let (o, text) = bin(&dir, "check", &env);
    assert!(o.status.success(), "{text}");

    // wrong PIN: reported once per key without trying the same PIN twice, nothing printed
    let wrong = "wrong-pin-7c1d-not-for-printing";
    let (o, text) = bin(&dir, "check", &good(wrong));
    assert_eq!(o.status.code(), Some(1), "{text}");
    assert!(
        text.contains("PinIncorrect") || text.contains("не принял PIN"),
        "{text}"
    );
    assert!(!text.contains(wrong) && !text.contains(PIN), "{text}");
    let (o, text) = bin(&dir, "run", &good(wrong));
    assert_eq!(
        o.status.code(),
        Some(2),
        "the gateway started with a wrong PIN: {text}"
    );
    assert!(!text.contains(wrong), "{text}");

    // a key that is not in the token
    let mut env = good(PIN);
    env[1].1 = format!("module={m};token=aegis-check;label=nope");
    let (o, text) = bin(&dir, "check", &env);
    assert_eq!(o.status.code(), Some(1), "{text}");
    assert!(text.contains("«nope» не найден"), "{text}");
    let (o, text) = bin(&dir, "run", &env);
    assert_eq!(o.status.code(), Some(2), "{text}");

    // the audit key must be another object
    let mut env = good(PIN);
    env[2].1 = env[1].1.clone();
    let (o, text) = bin(&dir, "check", &env);
    assert_eq!(o.status.code(), Some(1), "{text}");
    assert!(text.contains("один ключ в токене"), "{text}");
    let _ = std::fs::remove_dir_all(dir);
}

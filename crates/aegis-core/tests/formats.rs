#![allow(clippy::unwrap_used)]
//! REQ: DET-04, INV-3 — the same password in the formats that tools and files put around it.
//!
//! Found the hard way: Hermes Agent numbers the lines it reads (`2|DB_PASSWORD=…`) and Mistral Vibe
//! returns a file as JSON with `\n` in a string; the detector missed both and the password reached a
//! real provider. This table is every wrapper we could think of; a password must be found in each.

use aegis_core::detect::{DetectConfig, Dictionary, Pipeline};
use aegis_core::types::EntityType;

const PW: &str = "Jd8!2jd82k";

fn found(text: &str) -> Vec<String> {
    let pipe = Pipeline::new(
        DetectConfig {
            internal_zones: vec!["corp.local".into()],
            ..Default::default()
        },
        Dictionary::default(),
    );
    pipe.scan(text)
        .into_iter()
        .filter(|e| e.ty == EntityType::Secret)
        .map(|e| text[e.span.start..e.span.end].to_string())
        .collect()
}

/// (name, text with the password in it)
fn wrapped() -> Vec<(&'static str, String)> {
    let p = PW;
    let mut v: Vec<(&'static str, String)> = vec![];
    let mut add = |n, t: String| v.push((n, t));
    // viewers and numbering
    add(
        "cat -n",
        format!("     1\tDB_HOST=db\n     2\tDB_PASSWORD={p}\n     3\tDB_USER=u\n"),
    );
    add(
        "pipe numbers",
        format!("1|DB_HOST=db\n2|DB_PASSWORD={p}\n3|DB_USER=u"),
    );
    add(
        "arrow numbers",
        format!("  1\u{2192}DB_HOST=db\n  2\u{2192}DB_PASSWORD={p}"),
    );
    add(
        "colon numbers",
        format!("1: DB_HOST=db\n2: DB_PASSWORD={p}"),
    );
    add(
        "box numbers",
        format!("1\u{2502}DB_HOST=db\n2\u{2502}DB_PASSWORD={p}"),
    );
    add("L numbers", format!("L1: DB_HOST=db\nL2: DB_PASSWORD={p}"));
    add("padded pipe", format!("   12 | DB_PASSWORD={p}"));
    add("cat -A", format!("DB_HOST=db$\nDB_PASSWORD={p}$\n"));
    // search and diff
    add("grep -n", format!("config.env:2:DB_PASSWORD={p}"));
    add("grep -n context", format!("config.env-2-DB_PASSWORD={p}"));
    add("grep", format!("config.env:DB_PASSWORD={p}"));
    add(
        "diff +",
        format!("@@ -1,2 +1,3 @@\n DB_HOST=db\n+DB_PASSWORD={p}\n"),
    );
    add("diff -", format!("-DB_PASSWORD={p}\n+DB_PASSWORD=[[X]]"));
    add("diff context", format!(" DB_PASSWORD={p}\n DB_USER=u"));
    // markdown
    add("quote", format!("> DB_PASSWORD={p}"));
    add("bullet", format!("- DB_PASSWORD={p}"));
    add("numbered list", format!("1. DB_PASSWORD={p}"));
    add("fence", format!("```env\nDB_PASSWORD={p}\n```"));
    add(
        "table",
        format!("| key | value |\n|---|---|\n| DB_PASSWORD | {p} |"),
    );
    add("inline code", format!("set `DB_PASSWORD={p}` in the file"));
    // escaping
    add(
        "json-escaped newlines",
        format!("DB_HOST=db\\nDB_PASSWORD={p}\\nDB_USER=u"),
    );
    add(
        "json-escaped crlf",
        format!("DB_HOST=db\\r\\nDB_PASSWORD={p}\\r\\n"),
    );
    add("json-escaped tab", format!("a\\tDB_PASSWORD={p}\\tb"));
    add(
        "tool result object",
        format!("{{\"content\":\"DB_HOST=db\\nDB_PASSWORD={p}\\nDB_USER=u\\n\",\"lines\":3}}"),
    );
    add(
        "numbered in object",
        format!("{{\"content\":\"1|DB_HOST=db\\n2|DB_PASSWORD={p}\"}}"),
    );
    add(
        "quote-escaped object",
        format!("{{\"text\":\"{{\\\"DB_PASSWORD\\\": \\\"{p}\\\"}}\"}}"),
    );
    add("html-escaped", format!("DB_PASSWORD=&quot;{p}&quot;"));
    add(
        "crlf",
        format!("DB_HOST=db\r\nDB_PASSWORD={p}\r\nDB_USER=u\r\n"),
    );
    add("bom", format!("\u{feff}DB_PASSWORD={p}"));
    // languages and config formats
    add("export", format!("export DB_PASSWORD='{p}'"));
    add("export unquoted", format!("export DB_PASSWORD={p}"));
    add("double quoted", format!("DB_PASSWORD=\"{p}\""));
    add("powershell", format!("$env:DB_PASSWORD = \"{p}\""));
    add("cmd set", format!("set DB_PASSWORD={p}"));
    add("dockerfile ENV", format!("ENV DB_PASSWORD={p}"));
    add("docker -e", format!("docker run -e DB_PASSWORD={p} img"));
    add(
        "compose",
        format!("    environment:\n      - DB_PASSWORD={p}"),
    );
    add("yaml", format!("db:\n  password: {p}\n  user: u"));
    add("yaml quoted", format!("db:\n  password: \"{p}\""));
    add(
        "yaml list",
        format!("env:\n  - name: DB_PASSWORD\n    value: \"{p}\""),
    );
    add("json", format!("{{\"db\": {{\"password\": \"{p}\"}}}}"));
    add("json compact", format!("{{\"DB_PASSWORD\":\"{p}\"}}"));
    add("toml", format!("[db]\npassword = \"{p}\""));
    add("ini", format!("[db]\nPassword={p}\nUser=u"));
    add(
        "properties dotted",
        format!("spring.datasource.password={p}"),
    );
    add("properties colon", format!("db.password: {p}"));
    add("xml element", format!("<password>{p}</password>"));
    add(
        "xml attribute",
        format!("<add key=\"DbPassword\" value=\"{p}\"/>"),
    );
    add("python assign", format!("DB_PASSWORD = \"{p}\""));
    add(
        "python environ",
        format!("os.environ[\"DB_PASSWORD\"] = \"{p}\""),
    );
    add(
        "python default",
        format!("pw = os.getenv(\"DB_PASSWORD\", \"{p}\")"),
    );
    add(
        "js object",
        format!("const cfg = {{ password: '{p}', user: 'u' }};"),
    );
    add("go struct", format!("cfg := Config{{Password: \"{p}\"}}"));
    add("java", format!("String password = \"{p}\";"));
    add(
        "conn string",
        format!("Server=db;User Id=sa;Password={p};Database=x;"),
    );
    add(
        "curl -u",
        format!("curl -u admin:{p} https://x.corp.local/api"),
    );
    add(
        "env in log",
        format!("2026-10-08 12:00:01 INFO starting with DB_PASSWORD={p} pool=5"),
    );
    add("indented", format!("        DB_PASSWORD={p}"));
    add("tab indented", format!("\t\tDB_PASSWORD={p}"));
    add(
        "after comment",
        format!("# prod\nDB_PASSWORD={p}  # rotate in march"),
    );
    add("russian label", format!("Пароль: {p}"));
    v
}

#[test]
fn the_password_is_found_in_every_wrapper() {
    let mut missed = vec![];
    for (name, text) in wrapped() {
        let hits = found(&text);
        // some detector must cover the whole password (a longer match is fine, a shorter one is not)
        if !hits.iter().any(|h| h.contains(PW)) {
            missed.push(format!("{name}: {text:?} -> {hits:?}"));
        }
    }
    assert!(
        missed.is_empty(),
        "{} not found:\n{}",
        missed.len(),
        missed.join("\n")
    );
}

#[test]
fn what_is_found_does_not_swallow_the_next_line() {
    // a value ends where its line ends, whatever the wrapper
    for (name, text) in wrapped() {
        for h in found(&text) {
            assert!(
                !h.contains("DB_USER") && !h.contains("\\n") && !h.contains('\n'),
                "{name}: {h:?}"
            );
        }
    }
}

// ---- the same for the other kinds of values ----

fn found_all(text: &str) -> Vec<(EntityType, String)> {
    let pipe = Pipeline::new(
        DetectConfig {
            internal_zones: vec!["corp.local".into()],
            ..Default::default()
        },
        Dictionary::default(),
    );
    pipe.scan(text)
        .into_iter()
        .map(|e| (e.ty, text[e.span.start..e.span.end].to_string()))
        .collect()
}

/// Wrappers that do not depend on the kind of value: `{v}` is replaced by the value.
fn generic_wrappers() -> Vec<(&'static str, &'static str)> {
    vec![
        ("plain", "connect to {v} now"),
        ("cat -n", "     3\tHOST={v}\n"),
        ("pipe numbers", "3|HOST={v}\n4|X=1"),
        ("json-escaped", "A=1\\nHOST={v}\\nB=2"),
        ("json object", "{\"content\":\"HOST={v}\\nB=2\"}"),
        ("json in json", "{\"text\":\"{\\\"host\\\": \\\"{v}\\\"}\"}"),
        ("grep -n", "config.env:3:HOST={v}"),
        ("diff", "@@ -1 +1 @@\n+HOST={v}\n"),
        ("table", "| host | {v} |"),
        ("inline code", "run `ping {v}` first"),
        ("xml", "<host>{v}</host>"),
        ("xml attr", "<add key=\"Host\" value=\"{v}\"/>"),
        ("html escaped", "HOST=&quot;{v}&quot;"),
        ("yaml", "db:\n  host: {v}\n"),
        ("url", "https://{v}/health"),
        ("bom", "\u{feff}HOST={v}"),
        ("crlf", "A=1\r\nHOST={v}\r\n"),
        ("markdown link", "[dashboard](https://{v}/d)"),
        ("log line", "2026-10-08 INFO upstream={v} status=502"),
    ]
}

#[test]
fn hosts_and_addresses_in_every_wrapper() {
    let mut missed = vec![];
    for (kind, value, ty) in [
        ("host", "prod-db01.pay.corp.local", EntityType::Host),
        ("ipv4", "10.20.30.41", EntityType::Ip),
    ] {
        for (name, tpl) in generic_wrappers() {
            if name == "url" && kind == "ipv4" {
                continue;
            }
            let text = tpl.replace("{v}", value);
            let hits = found_all(&text);
            if !hits.iter().any(|(t, v)| *t == ty && v.contains(value)) {
                missed.push(format!("{kind} / {name}: {text:?} -> {hits:?}"));
            }
        }
    }
    assert!(missed.is_empty(), "{} not found:\n{}", missed.len(), missed.join("\n"));
}

#[test]
fn keys_and_mail_in_every_wrapper() {
    let mut missed = vec![];
    for (kind, value, ty) in [
        ("aws key", "AKIAJ3KQ7P2WXNB5ZT4A", EntityType::Secret),
        ("github token", "ghp_16C7e42F292c6912E7710c838347Ae178B4a", EntityType::Secret),
        ("email", "ivan.petrov@company.ru", EntityType::Email),
    ] {
        for (name, tpl) in generic_wrappers() {
            if name == "url" || name == "markdown link" {
                continue;
            }
            let text = tpl.replace("{v}", value);
            let hits = found_all(&text);
            if !hits.iter().any(|(t, v)| *t == ty && v.contains(value)) {
                missed.push(format!("{kind} / {name}: {text:?} -> {hits:?}"));
            }
        }
    }
    assert!(missed.is_empty(), "{} not found:\n{}", missed.len(), missed.join("\n"));
}

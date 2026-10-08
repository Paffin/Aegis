//! REQ: DET-01, DET-04, DET-05, DET-06, DET-07, DET-08, DET-09 — L0 detectors.
//!
//! Detectors only report positions and types; values stay in the scanned text.

use crate::types::{Entity, EntityType, Span};
use aho_corasick::{AhoCorasick, MatchKind};
use regex::Regex;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

pub const DETECTOR_VERSION: u32 = 1;

/// Interface shared by all detectors (T0-02).
/// Why the scan of a block was aborted (DET-09).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanFault {
    /// The time budget for the block was exceeded.
    Timeout,
    /// A detector panicked.
    Error,
}

impl ScanFault {
    pub fn as_str(self) -> &'static str {
        match self {
            ScanFault::Timeout => "timeout",
            ScanFault::Error => "error",
        }
    }
}

pub trait Detector: Send + Sync {
    fn id(&self) -> &str;
    fn version(&self) -> u32 {
        DETECTOR_VERSION
    }
    fn scan(&self, text: &str, out: &mut Vec<Candidate>);
}

#[derive(Clone, Debug)]
pub struct Candidate {
    pub entity: Entity,
    /// Higher wins when spans overlap.
    pub priority: u8,
}

fn cand(
    start: usize,
    end: usize,
    ty: EntityType,
    kind: Option<&'static str>,
    detector: &'static str,
    priority: u8,
) -> Candidate {
    Candidate {
        entity: Entity {
            span: Span { start, end },
            ty,
            kind,
            detector,
            person_key: None,
        },
        priority,
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct DetectConfig {
    /// Internal DNS zones, without leading dot: `corp.local`, `company.ru`.
    pub internal_zones: Vec<String>,
    /// Extra private ranges of the company as `(base, prefix_len)`.
    pub company_ranges: Vec<(u32, u8)>,
    /// E-mail domains that are not personal data.
    pub public_email_domains: Vec<String>,
    /// Values containing these markers are test data (DET-05).
    pub placeholder_markers: Vec<String>,
    /// Regexes of service accounts (DET-04 SVC); the company extends them in the bundle.
    pub service_account_patterns: Vec<String>,
}

impl Default for DetectConfig {
    fn default() -> Self {
        Self {
            internal_zones: vec![],
            company_ranges: vec![],
            public_email_domains: [
                "github.com",
                "example.com",
                "example.org",
                "users.noreply.github.com",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            placeholder_markers: [
                "example",
                "dummy",
                "placeholder",
                "changeme",
                "your",
                "xxxx",
                "****",
                "redacted",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            service_account_patterns: vec![],
        }
    }
}

const BUILTIN_ZONES: &[&str] = &["local", "internal", "corp", "lan", "intranet"];

impl DetectConfig {
    pub fn is_internal_host(&self, host: &str) -> bool {
        let h = host.to_ascii_lowercase();
        let h = h.trim_end_matches('.');
        BUILTIN_ZONES
            .iter()
            .map(|z| z.to_string())
            .chain(self.internal_zones.iter().cloned())
            .any(|z| h == z || h.ends_with(&format!(".{z}")))
    }

    /// Free-text variant of [`is_internal_host`]: a built-in zone such as `.local` also appears as a
    /// method call in code (`listener.local`), so it needs at least two labels before it, or a
    /// label that looks like a host name (`prod-db01.local`).
    pub fn is_internal_host_in_text(&self, host: &str) -> bool {
        let h = host.to_ascii_lowercase();
        let h = h.trim_end_matches('.');
        if self
            .internal_zones
            .iter()
            .any(|z| h == z || h.ends_with(&format!(".{z}")))
        {
            return true;
        }
        let labels: Vec<&str> = h.split('.').collect();
        let (zone, before) = match labels.split_last() {
            Some((z, b)) => (*z, b),
            None => return false,
        };
        if !BUILTIN_ZONES.contains(&zone) || before.is_empty() {
            return false;
        }
        // `self.engine.internal`, `args.local`: member access in code, not a host name
        const CODE_RECEIVERS: &[&str] = &[
            "self", "this", "cls", "super", "args", "opts", "options", "config", "cfg", "ctx",
            "state", "inner", "node", "info", "data", "item", "req", "res", "conn", "stream",
            "socket", "server", "client", "listener", "mock", "builder", "handle", "engine",
            "settings", "params",
        ];
        if CODE_RECEIVERS.contains(&before[0])
            || (before.len() >= 2 && before.iter().any(|l| CODE_RECEIVERS.contains(l)))
        {
            return false;
        }
        before.len() >= 2
            || before[0].contains('-')
            || before[0].chars().any(|c| c.is_ascii_digit())
    }

    pub fn is_private_ipv4(&self, ip: u32) -> bool {
        let in_range = |base: u32, len: u8| {
            let mask = if len == 0 {
                0
            } else {
                u32::MAX << (32 - len as u32)
            };
            ip & mask == base & mask
        };
        in_range(0x0A00_0000, 8)
            || in_range(0xAC10_0000, 12)
            || in_range(0xC0A8_0000, 16)
            || in_range(0x6440_0000, 10)
            || self.company_ranges.iter().any(|&(b, l)| in_range(b, l))
    }

    fn is_placeholder(&self, v: &str) -> bool {
        let l = v.to_ascii_lowercase();
        if matches!(
            l.as_str(),
            "password"
                | "secret"
                | "token"
                | "null"
                | "none"
                | "true"
                | "false"
                | "test"
                | "string"
        ) {
            return true;
        }
        if v.chars()
            .all(|c| c == '*' || c == 'x' || c == 'X' || c == '.' || c == '-')
        {
            return true;
        }
        self.placeholder_markers
            .iter()
            .any(|m| l.contains(m.as_str()))
    }
}

// ---------------------------------------------------------------------------
// Secrets (L0)
// ---------------------------------------------------------------------------

pub struct SecretDetector {
    known: Vec<(Regex, &'static str)>,
    pem: Regex,
    /// `password = "value"`, `password := "value"`, `"password": "value"`, `password => 'value'`.
    quoted: Regex,
    /// `password: "abc` cut off, or `password: "two words"`: a quote after the keyword, any text.
    open_quote: Regex,
    /// `setdefault("PASSWORD", "value")`: the key and the value are two literals.
    pair: Regex,
    /// `- name: DB_PASSWORD` followed by `value: "..."` (Kubernetes, CI).
    kv_lines: Regex,
    /// `PASSWORD=value` or `password: value` alone on a line (env, ini, YAML).
    config: Regex,
    /// `host x password=value` in free text: `=` only, key delimited on the left.
    inline_eq: Regex,
    /// `Пароль от УЗ: value`, `пароль - value`: the keyword, up to three words, then `:` or a dash.
    inline_prose: Regex,
    /// `--password value`, `?token=value`.
    flag: Regex,
    /// `curl -u user:pass`, `sshpass -p pass`, `redis-cli -a pass`, `mysql -ppass`.
    cli_creds: Regex,
    basic: Regex,
    bearer: Regex,
    cfg: DetectConfig,
}

/// The line number that file viewers put before a line (`2|`, `  2→`, `L2:`, `2│`): a configuration
/// line read through such a tool is `2|DB_PASSWORD=value`, and the key is not at the start of the line.
const LINE_NO: &str = r"(?:L?\d{1,6}[ \t]*[|:\u{2502}\u{2192}][ \t]?)?";

/// English and Russian keywords that mark the following value as a secret.
const KEYWORDS: &str = r"(?:password|passwd|pwd|passphrase|pass(?:[_\-]|\b)|secret|token|credentials?|creds?\b|api[_\-]?key|apikey|access[_\-]?key|private[_\-]?key|client[_\-]?secret|парол\w*|токен\w*|секрет\w*)";

/// Does the name of a JSON member say that its value is a secret (`db_password`, `REDIS_PASS`,
/// `credentials`, `apiToken`)? Then the value is scanned with its name in front of it, as a line
/// `name: value`, so that the detectors that need the name see it.
pub fn secretish_key(key: &str) -> bool {
    let k = key.to_lowercase();
    [
        "pass",
        "pwd",
        "secret",
        "token",
        "credential",
        "cred",
        "apikey",
        "api_key",
        "api-key",
        "access_key",
        "access-key",
        "private_key",
        "private-key",
        "auth",
        "парол",
        "токен",
        "секрет",
    ]
    .iter()
    .any(|w| k.contains(w))
}

/// An Aegis pseudonym (`[[TYPE_id ...`) is already masked: it is not a value to mask again
/// (a model's earlier answer that echoes `password: [[SECRET_...]]` comes back in the history).
fn starts_with_marker(t: &str) -> bool {
    let Some(rest) = t.strip_prefix("[[") else {
        return false;
    };
    let ty = rest.chars().take_while(|c| c.is_ascii_uppercase()).count();
    let Some(after) = rest[ty..].strip_prefix('_') else {
        return false;
    };
    (2..=10).contains(&ty)
        && after.len() >= 8
        && after.as_bytes()[..8]
            .iter()
            .all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
}

/// `${DB_PASS}`, `$DB_PASS`, `{{ vault.x }}`, `<your-token>`: a reference, not a value.
fn is_reference(v: &str) -> bool {
    let t = v.trim_matches(['"', '\'']);
    let braced = t.starts_with("${") && t.ends_with('}');
    let env_style = t.starts_with('$')
        && t.len() > 1
        && t[1..]
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        && t[1..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_uppercase() || c == '_');
    braced
        || env_style
        || starts_with_marker(t)
        || t.starts_with("{{")
        || t.starts_with("<")
        || t.starts_with("%(")
        || t.starts_with("%{")
}

/// A value that reads like code or a type rather than a secret (DET-05): identifiers,
/// paths, calls, generics. `quoted` values come from a string literal and are judged less strictly.
fn looks_like_code_value(v: &str, quoted: bool) -> bool {
    let lower = v.to_ascii_lowercase();
    let always = v.contains("::")
        || v.contains(['(', ')', '<', '>', '{', '}'])
        || is_dotted_path(v)
        || is_abnf_repetition(v)
        || is_reference(v)
        || lower.starts_with("os.environ")
        || lower.starts_with("process.env")
        || lower.starts_with("env(")
        || lower.starts_with("getenv")
        // an identifier made only of lowercase letters and underscores (`access_token`)
        || (!v.is_empty() && v.chars().all(|c| c.is_ascii_lowercase() || c == '_') && v.len() >= 3)
        // CamelCase type names (`Struct`, `StrOrBytes`) without digits or symbols
        || (v.chars().next().is_some_and(|c| c.is_ascii_uppercase()) && v.chars().all(|c| c.is_ascii_alphabetic()) && v.chars().skip(1).any(|c| c.is_ascii_lowercase()) && v.len() <= 24);
    if always {
        return true;
    }
    if quoted {
        v.starts_with("--")
    } else {
        // `::path`, `&str`, `*const T`, `--flag`
        v.starts_with([':', '&', '*']) || v.starts_with("--")
    }
}

/// `1*tchar` (ABNF repetition)
fn is_abnf_repetition(v: &str) -> bool {
    v.split_once('*').is_some_and(|(n, r)| {
        n.chars().all(|c| c.is_ascii_digit())
            && r.chars().all(|c| c.is_ascii_alphabetic())
            && !r.is_empty()
    })
}

/// `args.password`, `config.db.token` — a member path, not a value.
fn is_dotted_path(v: &str) -> bool {
    v.contains('.')
        && v.split('.').all(|p| {
            !p.is_empty()
                && p.chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
}

fn has_digit_or_symbol(v: &str) -> bool {
    v.chars()
        .any(|c| c.is_ascii_digit() || !(c.is_alphanumeric() || c == '_'))
}

impl SecretDetector {
    pub fn new(cfg: DetectConfig) -> Self {
        let k = |p: &str, kind: &'static str| (Regex::new(p).expect("static regex"), kind);
        let re = |p: String| Regex::new(&p).expect("static regex");
        Self {
            known: vec![
                k(r"\bAKIA[0-9A-Z]{16}\b", "aws"),
                k(r"\bASIA[0-9A-Z]{16}\b", "aws"),
                // fixed length: no trailing `\b`, the last character may be `-`
                k(r"\bAIza[0-9A-Za-z_\-]{35}", "gcp"),
                k(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "github"),
                k(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b", "github"),
                k(r"\bglpat-[A-Za-z0-9_\-]{20,}", "gitlab"),
                k(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}", "slack"),
                k(r"\bsk-ant-[A-Za-z0-9_\-]{20,}", "anthropic"),
                k(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}", "openai"),
                k(r"\bnpm_[A-Za-z0-9]{36}\b", "npm"),
                k(r"\bpypi-[A-Za-z0-9_\-]{50,}", "pypi"),
                k(r"\bhvs\.[A-Za-z0-9_\-]{20,}", "vault"),
                k(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}", "jwt"),
                k(r"AccountKey=[A-Za-z0-9+/=]{40,}", "azure"),
            ],
            pem: re(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----".into()),
            open_quote: re(format!(r#"(?i){KEYWORDS}[\w\-]*["']?\s*(?::=|=>|[:=])\s*(["'])([^"'\n]{{4,}})"#)),
            quoted: re(format!(r#"(?i){KEYWORDS}[\w\-]*["']?\s*(?::=|=>|[:=])\s*["']([^"'\s]{{4,}})["']"#)),
            pair: re(format!(r#"(?i)["'][\w.\-]*{KEYWORDS}[\w.\-]*["']\s*,\s*["']([^"'\s]{{4,}})["']"#)),
            kv_lines: re(format!(r#"(?im)^[ \t]*-?[ \t]*(?:name|key):[ \t]*["']?[\w.\-]*{KEYWORDS}[\w.\-]*["']?[ \t]*\r?\n[ \t]*(?:value|default):[ \t]*["']?([^\s"']{{4,}})["']?"#)),
            config: re(format!(r#"(?im)^[ \t]*{LINE_NO}(?:export[ \t]+)?[\w.\-]*{KEYWORDS}[\w.\-]*[ \t]*[:=][ \t]*([^\s"'#]{{6,}})[ \t\r]*$"#)),
            inline_eq: re(format!(r#"(?i)(?:^|[\s,;(\[{{&?|\\\u{{2502}}\u{{2192}}])[\w.\-]*{KEYWORDS}[\w.\-]*[ \t]*=[ \t]*((?:[^\s"',;)\]}}#\\]|\\[^nrt"'\s]){{6,}})"#)),
            inline_prose: re(format!(r#"(?i)(?:^|[\s,;(\[{{])(?:{KEYWORDS})(?:[ \t]+\p{{L}}+){{0,3}}[ \t]*(?::|[ \t][-\u{{2013}}\u{{2014}}])[ \t]+([^\s"',;)\]}}#]{{6,}})"#)),
            flag: re(r#"(?i)(?:--(?:password|passwd|token|secret|api-key)(?:=|[ \t]+)|[?&](?:password|passwd|pwd|token|secret|api_?key|access_?token)=)([^\s"'&)\]>]{6,})"#.into()),
            cli_creds: re(r#"(?i)(?:(?:^|[\s;|&(])(?:-u|--user|--proxy-user)(?:[ \t]+|=)["']?[^\s:"']+:|\bsshpass\s+-p[ \t]*["']?|\bredis-cli\b[^\n|;&]*?\s-a[ \t]+["']?|\bmysql(?:dump|admin)?\b[^\n|;&]*?\s-p["']?)([^\s"']{4,})"#.into()),
            basic: re(r"(?i)authorization:\s*basic\s+([A-Za-z0-9+/=]{16,})".into()),
            bearer: re(r"(?i)\bbearer\s+([A-Za-z0-9._\-]{20,})".into()),
            cfg,
        }
    }
}

impl Detector for SecretDetector {
    fn id(&self) -> &str {
        "secret.l0"
    }

    fn scan(&self, text: &str, out: &mut Vec<Candidate>) {
        for (re, kind) in &self.known {
            for m in re.find_iter(text) {
                out.push(cand(
                    m.start(),
                    m.end(),
                    EntityType::Secret,
                    Some(kind),
                    "secret.known",
                    90,
                ));
            }
        }
        for m in self.pem.find_iter(text) {
            out.push(cand(
                m.start(),
                m.end(),
                EntityType::Secret,
                Some("pem"),
                "secret.pem",
                100,
            ));
        }
        // (regex, value is a quoted literal, needs a digit or symbol)
        for (re, quoted, need_symbol) in [
            (&self.quoted, true, false),
            (&self.pair, true, false),
            (&self.kv_lines, true, false),
            (&self.config, false, true),
            (&self.inline_eq, false, true),
            (&self.inline_prose, false, true),
            (&self.flag, false, true),
            (&self.cli_creds, false, false),
        ] {
            for c in re.captures_iter(text) {
                let Some(v) = c.get(1) else { continue };
                let val = v.as_str().trim_end_matches([',', ';']);
                let kw_inside = ["password", "secret", "token", "пароль", "токен", "секрет"]
                    .iter()
                    .any(|k| val.to_lowercase() == *k);
                if self.cfg.is_placeholder(val)
                    || looks_like_code_value(val, quoted)
                    || kw_inside
                    || (need_symbol && !has_digit_or_symbol(val))
                {
                    continue;
                }
                out.push(cand(
                    v.start(),
                    v.start() + val.len(),
                    EntityType::Secret,
                    Some("password"),
                    "secret.assign",
                    60,
                ));
            }
        }
        // A literal that is not a single closed word: cut off by the end of the text or the line
        // (a truncated paste, a log line, a broken JSON), or a passphrase with spaces.
        for c in self.open_quote.captures_iter(text) {
            let (Some(q), Some(rest)) = (c.get(1), c.get(2)) else {
                continue;
            };
            let closed = text[rest.end()..].starts_with(q.as_str());
            let word = rest.as_str().split_whitespace().next().unwrap_or("");
            let (start, val) = if closed {
                if !rest.as_str().contains(char::is_whitespace) {
                    continue; // one closed word: the `quoted` pattern has it
                }
                // a passphrase needs a digit or a symbol, or any sentence would match
                if !has_digit_or_symbol(rest.as_str()) {
                    continue;
                }
                (rest.start(), rest.as_str())
            } else {
                (rest.start(), word)
            };
            let val = val.trim_end().trim_end_matches([',', ';']);
            if val.chars().count() < 4
                || self.cfg.is_placeholder(val)
                || looks_like_code_value(val, true)
                || ["password", "secret", "token", "пароль", "токен", "секрет"]
                    .iter()
                    .any(|k| val.to_lowercase() == *k)
            {
                continue;
            }
            out.push(cand(
                start,
                start + val.len(),
                EntityType::Secret,
                Some("password"),
                "secret.assign",
                60,
            ));
        }
        for c in self.basic.captures_iter(text) {
            if let Some(v) = c.get(1) {
                out.push(cand(
                    v.start(),
                    v.end(),
                    EntityType::Secret,
                    Some("basic"),
                    "secret.basic",
                    80,
                ));
            }
        }
        for c in self.bearer.captures_iter(text) {
            if let Some(v) = c.get(1) {
                out.push(cand(
                    v.start(),
                    v.end(),
                    EntityType::Secret,
                    Some("bearer"),
                    "secret.bearer",
                    70,
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Infrastructure (L0)
// ---------------------------------------------------------------------------

pub struct InfraDetector {
    cfg: DetectConfig,
    ipv4: Regex,
    ipv6: Regex,
    fqdn: Regex,
    uri: Regex,
    svc: Vec<Regex>,
    /// `user: svc_payment` — the built-in pattern applies only in an account context, because
    /// `svc_` is also a common prefix of variable names in code.
    svc_context: Regex,
}

impl InfraDetector {
    pub fn new(cfg: DetectConfig) -> Self {
        let svc = cfg
            .service_account_patterns
            .iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect();
        Self {
            svc,
            svc_context: Regex::new(r#"(?i)\b(?:user(?:name)?|login|account|principal|owner|run_?as|service_?account|db_?user)\b["']?(?:\s*[:=]\s*|\s+)["']?((?:svc|srv)[_\-][A-Za-z0-9][A-Za-z0-9_\-]*)|(?:^|\s)-[uUl]\s+((?:svc|srv)[_\-][A-Za-z0-9][A-Za-z0-9_\-]*)"#).expect("static regex"),
            cfg,
            ipv4: Regex::new(r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?").expect("static regex"),
            ipv6: Regex::new(r"(?i)\bf[cd][0-9a-f]{2}(?::[0-9a-f]{0,4}){2,7}(?:/\d{1,3})?").expect("static regex"),
            fqdn: Regex::new(r"(?i)[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)+")
                .expect("static regex"),
            // scheme://[user[:password]@]host[:port][/path]; the password may be an Aegis marker
            // (an answer that was restored in the history keeps secrets masked)
            uri: Regex::new(
                r#"(?i)\b([a-z][a-z0-9+.\-]*)://(?:([^\s:/@"']+)(?::(\[\[[A-Z]{2,10}_[a-z2-7]{8}(?: [a-z]+=[a-z0-9,]{1,40}){0,4}\]\]|[^\s/"']*))?@)?([^\s:/?#"'<>@]+)(?::(\d+))?(/[^\s?#"'<>]*)?"#,
            )
            .expect("static regex"),
        }
    }
}

pub fn parse_ipv4(s: &str) -> Option<u32> {
    let mut parts = s.split('.');
    let mut v: u32 = 0;
    for _ in 0..4 {
        let p = parts.next()?;
        if p.is_empty() || p.len() > 3 || (p.len() > 1 && p.starts_with('0')) {
            return None;
        }
        v = (v << 8) | p.parse::<u8>().ok()? as u32;
    }
    parts.next().is_none().then_some(v)
}

fn byte_before(text: &str, i: usize) -> Option<char> {
    text[..i].chars().next_back()
}

fn byte_after(text: &str, i: usize) -> Option<char> {
    text[i..].chars().next()
}

const DB_SCHEMES: &[&str] = &[
    "postgres",
    "postgresql",
    "mysql",
    "mariadb",
    "mongodb",
    "mongodb+srv",
    "redis",
    "amqp",
    "sqlserver",
    "oracle",
];

impl Detector for InfraDetector {
    fn id(&self) -> &str {
        "infra.l0"
    }

    fn scan(&self, text: &str, out: &mut Vec<Candidate>) {
        // URIs and connection strings: report the parts, keep scheme/port/path structure.
        for c in self.uri.captures_iter(text) {
            let scheme = c
                .get(1)
                .map(|m| m.as_str().to_ascii_lowercase())
                .unwrap_or_default();
            if let Some(u) = c.get(2) {
                let placeholder_user = matches!(
                    u.as_str().to_ascii_lowercase().as_str(),
                    "user"
                        | "username"
                        | "login"
                        | "name"
                        | "foo"
                        | "bar"
                        | "example"
                        | "test"
                        | "me"
                        | "u"
                        | "a"
                );
                if c.get(3).is_some() && !placeholder_user {
                    out.push(cand(
                        u.start(),
                        u.end(),
                        EntityType::Svc,
                        None,
                        "infra.uri.user",
                        70,
                    ));
                }
            }
            if let Some(p) = c.get(3) {
                if p.as_str().len() >= 4
                    && !self.cfg.is_placeholder(p.as_str())
                    && !looks_like_code_value(p.as_str(), true)
                {
                    out.push(cand(
                        p.start(),
                        p.end(),
                        EntityType::Secret,
                        Some("password"),
                        "infra.uri.password",
                        85,
                    ));
                }
            }
            if let Some(h) = c.get(4) {
                let hs = h.as_str();
                let is_ip = parse_ipv4(hs).is_some();
                let single_label = !hs.contains('.');
                // `[2001:db8::1]`: IPv6 literals are reported by the IPv6 scan, not as hosts.
                let ipv6_literal = hs.starts_with('[');
                // A single label is a host name only if it looks like one (`db01`, `prod-db`).
                let hostlike_label = single_label
                    && hs.len() >= 3
                    && (hs.contains('-') || hs.chars().any(|c| c.is_ascii_digit()))
                    && hs
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
                let internal = !ipv6_literal
                    && (self.cfg.is_internal_host(hs)
                        || (is_ip
                            && parse_ipv4(hs)
                                .map(|ip| self.cfg.is_private_ipv4(ip))
                                .unwrap_or(false))
                        || hostlike_label);
                if internal && !is_ip {
                    out.push(cand(
                        h.start(),
                        h.end(),
                        EntityType::Host,
                        None,
                        "infra.uri.host",
                        75,
                    ));
                }
                // Private IPs in URIs are reported by the IPv4 scan below.
            }
            if let Some(path) = c.get(6) {
                let seg = path
                    .as_str()
                    .trim_start_matches('/')
                    .split('/')
                    .next()
                    .unwrap_or("");
                let db_scheme = DB_SCHEMES.contains(&scheme.as_str())
                    || text[..c.get(0).map(|m| m.start()).unwrap_or(0)].ends_with("jdbc:");
                if db_scheme
                    && !seg.is_empty()
                    && !seg.contains(['{', '$', '<'])
                    && !seg.chars().all(|c| c.is_ascii_digit())
                {
                    let start = path.start() + 1;
                    out.push(cand(
                        start,
                        start + seg.len(),
                        EntityType::Db,
                        None,
                        "infra.uri.db",
                        70,
                    ));
                }
            }
        }

        for re in &self.svc {
            for m in re.find_iter(text) {
                out.push(cand(
                    m.start(),
                    m.end(),
                    EntityType::Svc,
                    None,
                    "infra.svc",
                    58,
                ));
            }
        }
        for c in self.svc_context.captures_iter(text) {
            if let Some(m) = c.get(1).or_else(|| c.get(2)) {
                out.push(cand(
                    m.start(),
                    m.end(),
                    EntityType::Svc,
                    None,
                    "infra.svc",
                    58,
                ));
            }
        }

        for m in self.ipv4.find_iter(text) {
            let s = m.as_str();
            // Do not match inside longer dotted numbers or identifiers.
            if byte_before(text, m.start()).is_some_and(|c| {
                c.is_ascii_alphanumeric()
                    || c == '.'
                        && text[..m.start()]
                            .chars()
                            .rev()
                            .nth(1)
                            .is_some_and(|d| d.is_ascii_digit())
            }) {
                continue;
            }
            if byte_after(text, m.end()).is_some_and(|c| {
                c.is_ascii_alphanumeric()
                    || c == '.'
                        && text[m.end() + 1..]
                            .chars()
                            .next()
                            .is_some_and(|d| d.is_ascii_digit())
            }) {
                continue;
            }
            let (addr, _) = s.split_once('/').unwrap_or((s, ""));
            if let Some(ip) = parse_ipv4(addr) {
                if self.cfg.is_private_ipv4(ip) {
                    out.push(cand(
                        m.start(),
                        m.end(),
                        EntityType::Ip,
                        None,
                        "infra.ipv4",
                        65,
                    ));
                }
            }
        }
        for m in self.ipv6.find_iter(text) {
            out.push(cand(
                m.start(),
                m.end(),
                EntityType::Ip,
                None,
                "infra.ipv6",
                65,
            ));
        }

        for m in self.fqdn.find_iter(text) {
            let s = m.as_str();
            if parse_ipv4(s).is_some() {
                continue;
            }
            // A match inside a longer identifier (`client_1.local_addr`) is not a host.
            let prev = byte_before(text, m.start());
            let next = byte_after(text, m.end());
            // `user@host` belongs to an address (the e-mail detector reports it), but `]]@host`
            // after a masked password does not: there the host stands alone.
            let after_at = prev == Some('@') && {
                let before_at = text[..m.start() - 1].chars().next_back();
                before_at.is_some_and(|c| {
                    c.is_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-')
                })
            };
            if prev.is_some_and(|c| c.is_alphanumeric() || matches!(c, '_' | '.' | '-'))
                || after_at
                || next.is_some_and(|c| {
                    c.is_alphanumeric()
                        || matches!(c, '_' | '(')
                        // `host[0]` is indexing, but `host[Aegis]` is a host that an Aegis
                        // explanation was glued to
                        || c == '[' && !text[m.end()..].starts_with("[Aegis")
                        || c == '.'
                            && text[m.end() + 1..]
                                .chars()
                                .next()
                                .is_some_and(|d| d.is_alphanumeric())
                })
            {
                continue;
            }
            // An unquoted dotted chain on a built-in zone is member access (`crypto.packet.local`);
            // a host name there appears in quotes, after `://` or `=`, or in prose.
            let configured = self.cfg.internal_zones.iter().any(|z| {
                s.eq_ignore_ascii_case(z) || s.to_ascii_lowercase().ends_with(&format!(".{z}"))
            });
            let hostlike_first = s
                .split('.')
                .next()
                .is_some_and(|l| l.contains('-') && l.chars().any(|c| c.is_ascii_alphabetic()));
            // After whitespace the previous word decides: prose ("на db01.local") continues a word,
            // code (`= crypto.header.local;`, `(a.local`) follows an operator or bracket.
            let after_word = |t: &str| {
                t.trim_end().chars().next_back().is_some_and(|c| {
                    c.is_alphanumeric() || matches!(c, ':' | '-' | '\u{2014}' | '\u{2013}')
                })
            };
            let quoted_ctx = prev.is_none_or(|c| {
                (c.is_whitespace() && after_word(&text[..m.start()]) && next != Some(';'))
                    || matches!(c, '"' | '\'' | '`' | '/' | ':' | ',' | '<' | '>')
                    || (c == '=' && !matches!(next, Some(';')))
            });
            if !configured && !hostlike_first && !quoted_ctx {
                continue;
            }
            if self.cfg.is_internal_host_in_text(s) {
                out.push(cand(
                    m.start(),
                    m.end(),
                    EntityType::Host,
                    None,
                    "infra.fqdn",
                    55,
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PII with checksums (L0)
// ---------------------------------------------------------------------------

pub struct PiiDetector {
    cfg: DetectConfig,
    email: Regex,
    phone_ru: Regex,
    phone_intl: Regex,
    snils: Regex,
    digits10_12: Regex,
    card: Regex,
    card_bare: Regex,
    passport: Regex,
    acct: Regex,
}

impl PiiDetector {
    pub fn new(cfg: DetectConfig) -> Self {
        Self {
            cfg,
            email: Regex::new(
                r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}",
            )
            .expect("static regex"),
            phone_ru: Regex::new(
                r"(?:\+7|\b8)[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}\b",
            )
            .expect("static regex"),
            phone_intl: Regex::new(
                r"\+\d{1,3}[\s\-]?\(?\d{2,4}\)?[\s\-]?\d{3}[\s\-]?\d{2,4}[\s\-]?\d{2,4}\b",
            )
            .expect("static regex"),
            snils: Regex::new(r"\b\d{3}-\d{3}-\d{3}[ \-]\d{2}\b").expect("static regex"),
            digits10_12: Regex::new(r"\b\d{10}(?:\d{2})?\b").expect("static regex"),
            // 4-4-4-4 (or Amex 4-6-5) with separators: a card number by format alone.
            card: Regex::new(r"\b\d{4}(?:[ \-]\d{4}){3}\b|\b3[47]\d{2}[ \-]\d{6}[ \-]\d{5}\b")
                .expect("static regex"),
            // unseparated digits: only with a known issuer prefix and card context
            card_bare: Regex::new(r"\b\d{13,19}\b").expect("static regex"),
            passport: Regex::new(r"\b\d{2}\s?\d{2}\s?\d{6}\b").expect("static regex"),
            acct: Regex::new(r"\b\d{20}\b").expect("static regex"),
        }
    }
}

fn context_before(text: &str, start: usize, words: &[&str]) -> bool {
    let from = text[..start]
        .char_indices()
        .rev()
        .nth(40)
        .map(|(i, _)| i)
        .unwrap_or(0);
    let ctx = text[from..start].to_lowercase();
    words.iter().any(|w| ctx.contains(w))
}

pub fn luhn_ok(digits: &str) -> bool {
    let ds: Vec<u32> = digits.chars().filter_map(|c| c.to_digit(10)).collect();
    if ds.len() < 13 || ds.len() > 19 {
        return false;
    }
    let sum: u32 = ds
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let x = d * 2;
                if x > 9 {
                    x - 9
                } else {
                    x
                }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

pub fn snils_ok(s: &str) -> bool {
    let d: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if d.len() != 11 {
        return false;
    }
    let sum: u32 = d[..9]
        .iter()
        .enumerate()
        .map(|(i, &x)| x * (9 - i as u32))
        .sum();
    let control = match sum {
        0..=99 => sum,
        100 | 101 => 0,
        _ => {
            let r = sum % 101;
            if r == 100 {
                0
            } else {
                r
            }
        }
    };
    control == d[9] * 10 + d[10]
}

pub fn inn_ok(s: &str) -> bool {
    let d: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    let check = |coef: &[u32], n: usize| -> bool {
        let sum: u32 = coef.iter().zip(&d).map(|(c, x)| c * x).sum();
        sum % 11 % 10 == d[n]
    };
    match d.len() {
        10 => check(&[2, 4, 10, 3, 5, 9, 4, 6, 8], 9),
        12 => {
            check(&[7, 2, 4, 10, 3, 5, 9, 4, 6, 8], 10)
                && check(&[3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8], 11)
        }
        _ => false,
    }
}

impl Detector for PiiDetector {
    fn id(&self) -> &str {
        "pii.l0"
    }

    fn scan(&self, text: &str, out: &mut Vec<Candidate>) {
        for m in self.email.find_iter(text) {
            let domain = m
                .as_str()
                .rsplit('@')
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            if self.cfg.public_email_domains.contains(&domain) || m.as_str().starts_with("noreply@")
            {
                continue;
            }
            out.push(cand(
                m.start(),
                m.end(),
                EntityType::Email,
                None,
                "pii.email",
                80,
            ));
        }
        for (re, intl) in [(&self.phone_ru, false), (&self.phone_intl, true)] {
            for m in re.find_iter(text) {
                // an international number is written in groups; one hyphen is a numeric literal
                if intl
                    && m.as_str()
                        .chars()
                        .filter(|c| c.is_whitespace() || matches!(c, '-' | '(' | ')'))
                        .count()
                        < 2
                {
                    continue;
                }
                // a number inside a longer numeric literal (`+292277026596-12`) is not a phone
                if byte_after(text, m.end())
                    .is_some_and(|c| c.is_ascii_digit() || c == '-' || c == '.')
                    || byte_before(text, m.start()).is_some_and(|c| c.is_alphanumeric() || c == '_')
                {
                    continue;
                }
                out.push(cand(
                    m.start(),
                    m.end(),
                    EntityType::Phone,
                    None,
                    "pii.phone",
                    50,
                ));
            }
        }
        for m in self.snils.find_iter(text) {
            if snils_ok(m.as_str()) {
                out.push(cand(
                    m.start(),
                    m.end(),
                    EntityType::Snils,
                    None,
                    "pii.snils",
                    75,
                ));
            }
        }
        for m in self.digits10_12.find_iter(text) {
            if inn_ok(m.as_str()) && context_before(text, m.start(), &["инн", "inn"]) {
                out.push(cand(
                    m.start(),
                    m.end(),
                    EntityType::Inn,
                    None,
                    "pii.inn",
                    75,
                ));
            }
        }
        for m in self.card_bare.find_iter(text) {
            let v = m.as_str();
            let iin_ok = matches!(v.as_bytes()[0], b'2'..=b'6');
            let adjacent =
                byte_before(text, m.start()).is_some_and(|c| c == '.' || c == '-' || c == '_');
            if iin_ok
                && !adjacent
                && luhn_ok(v)
                && context_before(
                    text,
                    m.start(),
                    &[
                        "card",
                        "карт",
                        "visa",
                        "mastercard",
                        "pan ",
                        "pan:",
                        "cc ",
                        "cc:",
                        "cc=",
                    ],
                )
            {
                out.push(cand(
                    m.start(),
                    m.end(),
                    EntityType::Card,
                    None,
                    "pii.card",
                    75,
                ));
            }
        }
        for m in self.card.find_iter(text) {
            if luhn_ok(m.as_str()) {
                out.push(cand(
                    m.start(),
                    m.end(),
                    EntityType::Card,
                    None,
                    "pii.card",
                    75,
                ));
            }
        }
        for m in self.passport.find_iter(text) {
            if context_before(text, m.start(), &["паспорт", "passport"]) {
                out.push(cand(
                    m.start(),
                    m.end(),
                    EntityType::Passport,
                    None,
                    "pii.passport",
                    75,
                ));
            }
        }
        for m in self.acct.find_iter(text) {
            if context_before(
                text,
                m.start(),
                &["счет", "счёт", "р/с", "account", "acct", "iban"],
            ) {
                out.push(cand(
                    m.start(),
                    m.end(),
                    EntityType::Acct,
                    None,
                    "pii.acct",
                    70,
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Dictionaries: employees (with declensions) and company names
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct DictEntry {
    pub form: String,
    pub ty: EntityType,
    /// Canonical key: for persons the sorted transliterated tokens (`ivan|petrov`).
    pub key: String,
}

#[derive(Clone, Debug, Default)]
pub struct Person {
    pub key: String,
    /// Transliteration variants of the first and last name.
    pub first: BTreeSet<String>,
    pub last: BTreeSet<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Dictionary {
    pub entries: Vec<DictEntry>,
    pub persons: Vec<Person>,
}

/// ICAO-style transliteration plus the variants people use in e-mail names.
pub fn translit_variants(word: &str) -> BTreeSet<String> {
    fn tr(word: &str, ju: &str, ja: &str, j: &str, kh: &str) -> String {
        let mut s = String::new();
        for c in word.to_lowercase().chars() {
            let t: &str = match c {
                'а' => "a",
                'б' => "b",
                'в' => "v",
                'г' => "g",
                'д' => "d",
                'е' | 'ё' | 'э' => "e",
                'ж' => "zh",
                'з' => "z",
                'и' => "i",
                'й' => j,
                'к' => "k",
                'л' => "l",
                'м' => "m",
                'н' => "n",
                'о' => "o",
                'п' => "p",
                'р' => "r",
                'с' => "s",
                'т' => "t",
                'у' => "u",
                'ф' => "f",
                'х' => kh,
                'ц' => "ts",
                'ч' => "ch",
                'ш' => "sh",
                'щ' => "shch",
                'ъ' | 'ь' => "",
                'ы' => "y",
                'ю' => ju,
                'я' => ja,
                c if c.is_ascii_alphabetic() => {
                    s.push(c);
                    continue;
                }
                _ => continue,
            };
            s.push_str(t);
        }
        s
    }
    let mut v = BTreeSet::new();
    for (ju, ja, j, kh) in [
        ("iu", "ia", "i", "kh"),
        ("yu", "ya", "y", "kh"),
        ("yu", "ya", "y", "h"),
        ("iu", "ia", "y", "kh"),
    ] {
        v.insert(tr(word, ju, ja, j, kh));
    }
    v
}

/// Declined forms of a Russian surname or first name by simple suffix rules.
/// The production dictionary is generated by `aegis-cli` from OpenCorpora (T1-16);
/// this keeps the engine usable without it.
pub fn declensions(word: &str) -> Vec<String> {
    let w = word.trim();
    let lower = w.to_lowercase();
    let chars: Vec<char> = w.chars().collect();
    let cap = |s: String| -> String {
        let mut it = s.chars();
        match it.next() {
            Some(f) => f.to_uppercase().collect::<String>() + it.as_str(),
            None => s,
        }
    };
    let mut forms = vec![w.to_string()];
    let stem_of = |n: usize| -> String { chars[..chars.len().saturating_sub(n)].iter().collect() };
    let add = |forms: &mut Vec<String>, stem: &str, sfx: &[&str]| {
        for s in sfx {
            forms.push(format!("{stem}{s}"));
        }
    };
    if lower.ends_with("ов")
        || lower.ends_with("ев")
        || lower.ends_with("ин")
        || lower.ends_with("ын")
    {
        add(&mut forms, w, &["а", "у", "ым", "е", "ых", "ым"]);
        if lower.ends_with("ин") || lower.ends_with("ын") {
            // Ильин → Ильиным
            forms.push(format!("{w}ым"));
        } else {
            forms.push(format!("{w}ым"));
        }
    } else if lower.ends_with("ова")
        || lower.ends_with("ева")
        || lower.ends_with("ина")
        || lower.ends_with("ына")
    {
        let st = stem_of(1);
        add(&mut forms, &st, &["ой", "у", "ую"]);
    } else if lower.ends_with("ский") || lower.ends_with("цкий") {
        let st = stem_of(2);
        add(&mut forms, &st, &["ого", "ому", "им", "ом"]);
    } else if lower.ends_with("ская") || lower.ends_with("цкая") {
        let st = stem_of(2);
        add(&mut forms, &st, &["ой", "ую"]);
    } else if lower.ends_with("ий") {
        let st = stem_of(2);
        add(&mut forms, &st, &["ия", "ию", "ием", "ии"]);
    } else if lower.ends_with('й') {
        let st = stem_of(1);
        add(&mut forms, &st, &["я", "ю", "ем", "е"]);
    } else if lower.ends_with('а') {
        let st = stem_of(1);
        add(&mut forms, &st, &["ы", "е", "у", "ой", "и"]);
    } else if lower.ends_with('я') {
        let st = stem_of(1);
        add(&mut forms, &st, &["и", "е", "ю", "ей"]);
    } else if lower.ends_with('ь') {
        let st = stem_of(1);
        add(&mut forms, &st, &["я", "ю", "ем", "е"]);
    } else if chars
        .last()
        .is_some_and(|c| "бвгджзклмнпрстфхцчшщ".contains(*c))
    {
        add(&mut forms, w, &["а", "у", "ом", "е"]);
    }
    forms.sort();
    forms.dedup();
    forms
        .into_iter()
        .map(|f| {
            if f.chars().next().is_some_and(|c| c.is_uppercase()) {
                f
            } else {
                cap(f)
            }
        })
        .collect()
}

impl Dictionary {
    /// Add an employee with all name orders and declined forms.
    pub fn add_person(&mut self, first: &str, last: &str) {
        let f_tr = translit_variants(first);
        let l_tr = translit_variants(last);
        let key = {
            let mut toks = [
                f_tr.iter().next().cloned().unwrap_or_default(),
                l_tr.iter().next().cloned().unwrap_or_default(),
            ];
            toks.sort();
            toks.join("|")
        };
        let fs = declensions(first);
        let ls = declensions(last);
        for f in &fs {
            for l in &ls {
                for form in [format!("{f} {l}"), format!("{l} {f}")] {
                    self.entries.push(DictEntry {
                        form,
                        ty: EntityType::Person,
                        key: key.clone(),
                    });
                }
            }
        }
        for l in &ls {
            if l.chars().count() >= 5 {
                self.entries.push(DictEntry {
                    form: l.clone(),
                    ty: EntityType::Person,
                    key: key.clone(),
                });
            }
        }
        self.persons.push(Person {
            key,
            first: f_tr,
            last: l_tr,
        });
    }

    pub fn add_term(&mut self, form: &str, ty: EntityType) {
        self.entries.push(DictEntry {
            form: form.to_string(),
            ty,
            key: form.to_lowercase(),
        });
    }
}

pub struct DictionaryDetector {
    dict: Dictionary,
    ac: Option<AhoCorasick>,
}

impl DictionaryDetector {
    pub fn new(dict: Dictionary) -> Self {
        let pats: Vec<String> = dict.entries.iter().map(|e| e.form.to_lowercase()).collect();
        let ac = if pats.is_empty() {
            None
        } else {
            AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostLongest)
                .build(&pats)
                .ok()
        };
        Self { dict, ac }
    }

    pub fn dictionary(&self) -> &Dictionary {
        &self.dict
    }
}

/// Lowercase `text`, returning for each byte of the result the offset in `text`.
fn lower_with_map(text: &str) -> (String, Vec<usize>) {
    let mut lowered = String::with_capacity(text.len());
    let mut map = Vec::with_capacity(text.len() + 1);
    for (i, c) in text.char_indices() {
        for lc in c.to_lowercase() {
            let before = lowered.len();
            lowered.push(lc);
            for _ in before..lowered.len() {
                map.push(i);
            }
        }
    }
    map.push(text.len());
    (lowered, map)
}

impl Detector for DictionaryDetector {
    fn id(&self) -> &str {
        "dict.l0"
    }

    fn scan(&self, text: &str, out: &mut Vec<Candidate>) {
        let Some(ac) = &self.ac else { return };
        let (lowered, map) = lower_with_map(text);
        for m in ac.find_iter(&lowered) {
            let (s, e) = (map[m.start()], map[m.end()]);
            if byte_before(text, s).is_some_and(|c| c.is_alphanumeric() || c == '_') {
                continue;
            }
            if byte_after(text, e).is_some_and(|c| c.is_alphanumeric() || c == '_') {
                continue;
            }
            let entry = &self.dict.entries[m.pattern().as_usize()];
            let mut c = cand(s, e, entry.ty, None, "dict", 72);
            if entry.ty == EntityType::Person {
                c.entity.person_key = Some(entry.key.clone());
            }
            out.push(c);
        }
    }
}

// ---------------------------------------------------------------------------
// Company detectors from the bundle (DET-08)
// ---------------------------------------------------------------------------

/// A regex detector defined by the company. `regex` is the `regex` crate, which guarantees
/// linear time (SEC-11); `group` selects the capture group that holds the value.
pub struct CustomDetector {
    id: String,
    ty: EntityType,
    kind: Option<&'static str>,
    re: Regex,
    group: usize,
}

impl CustomDetector {
    pub fn new(id: &str, ty: EntityType, regex: &str, group: usize) -> Result<Self, String> {
        let re = regex::RegexBuilder::new(regex)
            .size_limit(1 << 20)
            .build()
            .map_err(|e| format!("detector {id}: {e}"))?;
        if group >= re.captures_len() {
            return Err(format!("detector {id}: group {group} does not exist"));
        }
        let kind = (ty == EntityType::Secret).then_some("custom");
        Ok(Self {
            id: id.to_string(),
            ty,
            kind,
            re,
            group,
        })
    }
}

impl Detector for CustomDetector {
    fn id(&self) -> &str {
        &self.id
    }

    fn scan(&self, text: &str, out: &mut Vec<Candidate>) {
        for c in self.re.captures_iter(text) {
            if let Some(m) = c.get(self.group) {
                out.push(cand(m.start(), m.end(), self.ty, self.kind, "custom", 85));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

pub struct Pipeline {
    detectors: Vec<Box<dyn Detector>>,
    dict: Dictionary,
}

impl Pipeline {
    pub fn new(cfg: DetectConfig, dict: Dictionary) -> Self {
        let detectors: Vec<Box<dyn Detector>> = vec![
            Box::new(SecretDetector::new(cfg.clone())),
            Box::new(InfraDetector::new(cfg.clone())),
            Box::new(PiiDetector::new(cfg)),
            Box::new(DictionaryDetector::new(dict.clone())),
        ];
        Self { detectors, dict }
    }

    pub fn add_detector(&mut self, d: Box<dyn Detector>) {
        self.detectors.push(d);
    }

    /// Fingerprint of detector set and versions; part of the detection cache key (DET-02).
    pub fn version_tag(&self) -> String {
        self.detectors
            .iter()
            .map(|d| format!("{}@{}", d.id(), d.version()))
            .collect::<Vec<_>>()
            .join(",")
    }

    pub fn scan(&self, text: &str) -> Vec<Entity> {
        let mut cands = Vec::new();
        for d in &self.detectors {
            d.scan(text, &mut cands);
        }
        let mut entities = resolve_overlaps(cands);
        self.link_people(text, &mut entities);
        entities
    }

    /// DET-09: like [`scan`](Self::scan), but a detector that panics or leaves the time budget
    /// behind aborts the scan of the block. The caller must not trust a partial result, so none
    /// is returned.
    pub fn scan_limited(&self, text: &str, budget: Duration) -> Result<Vec<Entity>, ScanFault> {
        let start = Instant::now();
        let mut cands = Vec::new();
        for d in &self.detectors {
            let ran =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| d.scan(text, &mut cands)));
            if ran.is_err() {
                return Err(ScanFault::Error);
            }
            if start.elapsed() > budget {
                return Err(ScanFault::Timeout);
            }
        }
        let mut entities = resolve_overlaps(cands);
        self.link_people(text, &mut entities);
        Ok(entities)
    }

    /// DET-07: an e-mail whose local part carries first and last name of a known person
    /// belongs to that person, independent of the order of appearance.
    fn link_people(&self, text: &str, entities: &mut [Entity]) {
        for e in entities.iter_mut().filter(|e| e.ty == EntityType::Email) {
            let local = text[e.span.start..e.span.end]
                .split('@')
                .next()
                .unwrap_or("")
                .to_lowercase();
            let toks: Vec<&str> = local
                .split(|c: char| !c.is_ascii_alphabetic())
                .filter(|t| !t.is_empty())
                .collect();
            for p in &self.dict.persons {
                let first_ok = toks.iter().any(|t| {
                    p.first.contains(*t)
                        || p.first.iter().any(|f| f.starts_with(*t) && t.len() == 1)
                });
                let last_ok = toks.iter().any(|t| p.last.contains(*t));
                if first_ok && last_ok {
                    e.person_key = Some(p.key.clone());
                    break;
                }
            }
        }
    }
}

/// Greedy resolution: higher priority first, then longer, then earlier.
pub fn resolve_overlaps(mut cands: Vec<Candidate>) -> Vec<Entity> {
    cands.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then(b.entity.span.len().cmp(&a.entity.span.len()))
            .then(a.entity.span.start.cmp(&b.entity.span.start))
    });
    let mut accepted: Vec<Entity> = Vec::new();
    for c in cands {
        if c.entity.span.is_empty() {
            continue;
        }
        if accepted.iter().all(|a| !a.span.overlaps(&c.entity.span)) {
            accepted.push(c.entity);
        }
    }
    accepted.sort_by_key(|e| e.span.start);
    accepted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pipe() -> Pipeline {
        let cfg = DetectConfig {
            internal_zones: vec!["company.ru".into()],
            ..Default::default()
        };
        let mut d = Dictionary::default();
        d.add_person("Иван", "Петров");
        d.add_term("InternalPaymentSystem", EntityType::System);
        Pipeline::new(cfg, d)
    }

    fn found(text: &str) -> Vec<(EntityType, String)> {
        pipe()
            .scan(text)
            .into_iter()
            .map(|e| (e.ty, text[e.span.start..e.span.end].to_string()))
            .collect()
    }

    // REQ: DET-04 — found with Hermes Agent against a real model: its file viewer prefixes lines with
    // `2|`, and the password on such a line went to the provider. Every viewer's numbering counts.
    #[test]
    fn passwords_on_numbered_lines_are_found() {
        for t in [
            "1|DB_HOST=db\n2|DB_PASSWORD=Jd8!2jd82k\n3|DB_USER=u\n",
            "  2\u{2192}DB_PASSWORD=Jd8!2jd82k",
            "    2\tDB_PASSWORD=Jd8!2jd82k",
            "L2: DB_PASSWORD=Jd8!2jd82k",
            "2\u{2502}DB_PASSWORD=Jd8!2jd82k",
            "12: password: Jd8!2jd82k",
            "     7 | export API_PASSWORD=Jd8!2jd82k",
        ] {
            let f = found(t);
            assert!(
                f.iter()
                    .any(|(ty, v)| *ty == EntityType::Secret && v.starts_with("Jd8!2jd82k")),
                "{t:?}: {f:?}"
            );
        }
        // numbers and bars alone are not passwords
        for t in ["2|DB_HOST=db.internal", "3|retries=5", "10: timeout: 30s"] {
            assert!(
                found(t).iter().all(|(ty, _)| *ty != EntityType::Secret),
                "{t}"
            );
        }
    }

    // REQ: DET-04 — found with Mistral Vibe against a real model: a file read by a tool comes back as a
    // JSON document inside a string, with line breaks written `\n` (two characters).
    #[test]
    fn passwords_in_escaped_text_are_found() {
        for t in [
            r#"DB_HOST=db\nDB_PASSWORD=Jd8!2jd82k\nDB_USER=u\n"#,
            r#"{"content":"DB_HOST=db\nDB_PASSWORD=Jd8!2jd82k\nDB_USER=svc_payment\n","lines":3}"#,
            r#"a=1\r\nAPI_TOKEN=Jd8!2jd82k\r\nb=2"#,
            r#"x\tPASSWORD=Jd8!2jd82k\tz"#,
        ] {
            let f = found(t);
            let hit = f
                .iter()
                .find(|(ty, v)| *ty == EntityType::Secret && v.starts_with("Jd8!2jd82k"));
            assert!(hit.is_some(), "{t}: {f:?}");
            // the value ends where the line ends: the next key is not swallowed
            assert!(
                !hit.unwrap().1.contains("DB_USER") && !hit.unwrap().1.contains("\\n"),
                "{t}: {f:?}"
            );
        }
        // a backslash inside a password stays inside it
        let f = found(r#"PASSWORD=ab\cd12!x"#);
        assert!(f.iter().any(|(_, v)| v == r#"ab\cd12!x"#), "{f:?}");
    }

    // REQ: DET-04 — a literal that is cut off (truncated paste, broken JSON, log line) or
    // holds a passphrase still hides its value; found by the mutation property test.
    #[test]
    fn unterminated_and_spaced_literals() {
        for (t, want) in [
            ("password: \"Jd8@2jd82k", "Jd8@2jd82k"),
            ("password: 'Jd8@2jd82k", "Jd8@2jd82k"),
            ("password: \"Jd8@2jd82k rest of the line", "Jd8@2jd82k"),
            ("password=\"Jd8@2jd82kurl: foo", "Jd8@2jd82kurl:"),
            (
                "password: \"correct horse 9 staple\"",
                "correct horse 9 staple",
            ),
            (
                "{\"password\": \"Jd8@2jd82k, \"user\": \"u\"}",
                "Jd8@2jd82k,",
            ),
        ] {
            let f = found(t);
            assert!(
                f.iter().any(|(ty, v)| *ty == EntityType::Secret
                    && v.starts_with(want.trim_end_matches(','))),
                "{t}: {f:?}"
            );
        }
        // sentences and messages are not passwords
        for t in [
            "password: \"Enter your password\"",
            "msg = \"password is required\"",
            "password: \"\"",
        ] {
            assert!(
                !found(t).iter().any(|(ty, _)| *ty == EntityType::Secret),
                "{t}"
            );
        }
    }

    // REQ: DET-04 — a host with an Aegis explanation glued to it is still a host (the real
    // Qwen Code client sent `prod-db01.corp.local[Aegis] ...` back in the history), `host[0]` is not.
    #[test]
    fn host_before_an_aegis_explanation() {
        let f = found("Проверяю prod-db01.pay.corp.local[Aegis] Вызов отклонён");
        assert!(
            f.iter().any(|(_, v)| v == "prod-db01.pay.corp.local"),
            "{f:?}"
        );
        assert!(!found("x = rows.pay.corp.local[0]")
            .iter()
            .any(|(_, v)| v.contains("corp.local")));
    }

    // REQ: DET-04 — credentials on a command line (found by the property test).
    #[test]
    fn command_line_credentials() {
        for (t, want) in [
            (
                "curl -u admin:Tg5%hY1&jK3p https://x.example",
                "Tg5%hY1&jK3p",
            ),
            ("curl --user bob:s3cr3tPw https://x.example", "s3cr3tPw"),
            ("sshpass -p hunter22x ssh a@b", "hunter22x"),
            ("redis-cli -h h -a Gx7vQ2mP ping", "Gx7vQ2mP"),
            ("mysql -h db -u root -pRt5nK8wq1 -e 'x'", "Rt5nK8wq1"),
        ] {
            assert!(
                found(t)
                    .iter()
                    .any(|(ty, v)| *ty == EntityType::Secret && v == want),
                "{t}: {:?}",
                found(t)
            );
        }
        for t in [
            "curl -u $USER:$PASS https://x",
            "curl -u admin https://x",
            "mysql -P 3306 -h x",
        ] {
            assert!(
                !found(t).iter().any(|(ty, _)| *ty == EntityType::Secret),
                "{t}"
            );
        }
    }

    // REQ: PSE-11 — an Aegis marker after a keyword is already masked, not a value to mask again;
    // an answer restored in the history keeps its secrets as markers and its other values hidden.
    #[test]
    fn markers_are_not_values_and_do_not_hide_their_neighbours() {
        let t = "aws_access_key_id = [[SECRET_ylcrmwav kind=aws]]\npassword: [[SECRET_25jn7v3u kind=password has=at]]";
        assert!(found(t).is_empty(), "{:?}", found(t));
        let u = "jdbc:postgresql://svc:[[SECRET_lv6qeor6 kind=password]]@prod-db02.pay.corp.local:5432/clients";
        let f = found(u);
        for want in ["svc", "prod-db02.pay.corp.local", "clients"] {
            assert!(f.iter().any(|(_, v)| v == want), "{want}: {f:?}");
        }
    }

    // REQ: DET-04
    #[test]
    fn known_secret_formats() {
        let t = "k=AKIAIOSFODNN7EXAMPLE g=ghp_abcdefghijklmnopqrstuvwxyz0123456789 gl=glpat-abcdefghij1234567890 jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop";
        let f = found(t);
        assert!(
            f.iter()
                .any(|(ty, v)| *ty == EntityType::Secret && v.starts_with("AKIA")),
            "{f:?}"
        );
        assert!(f.iter().any(|(_, v)| v.starts_with("ghp_")));
        assert!(f.iter().any(|(_, v)| v.starts_with("glpat-")));
        assert!(f.iter().any(|(_, v)| v.starts_with("eyJ")));
    }

    // REQ: DET-04
    #[test]
    fn pem_block_is_one_entity() {
        let t = "x\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nabc\n-----END RSA PRIVATE KEY-----\ny";
        let f = found(t);
        assert_eq!(f.len(), 1);
        assert!(f[0].1.starts_with("-----BEGIN") && f[0].1.ends_with("KEY-----"));
    }

    // REQ: DET-04 — the scenario from the concept.
    #[test]
    fn connection_string_is_split_into_parts() {
        let t = "jdbc:postgresql://prod-db01.pay.corp.local:5432/clients user=svc";
        let f = found(t);
        assert!(
            f.contains(&(EntityType::Host, "prod-db01.pay.corp.local".into())),
            "{f:?}"
        );
        assert!(f.contains(&(EntityType::Db, "clients".into())), "{f:?}");
        let t2 = "postgresql://svc_payment:Jd8@2jd82k@prod-db01:5432/payment";
        let f2 = found(t2);
        assert!(
            f2.contains(&(EntityType::Svc, "svc_payment".into())),
            "{f2:?}"
        );
        assert!(
            f2.iter()
                .any(|(ty, v)| *ty == EntityType::Secret && v.starts_with("Jd8")),
            "{f2:?}"
        );
        assert!(
            f2.contains(&(EntityType::Host, "prod-db01".into())),
            "{f2:?}"
        );
    }

    #[test]
    fn password_assignment_and_placeholders() {
        let f = found("DB_PASSWORD = \"Jd8@2jd82k\"\nPASSWORD: ${DB_PASS}\npassword: changeme\ntoken: <your-token>");
        assert_eq!(
            f.iter().filter(|(t, _)| *t == EntityType::Secret).count(),
            1,
            "{f:?}"
        );
    }

    // REQ: DET-04
    #[test]
    fn private_ips_only() {
        let f = found("a 10.34.18.21 b 8.8.8.8 c 192.168.1.1/24 d 1.2.3.4.5 e 10.1.2.3.4");
        let ips: Vec<_> = f
            .iter()
            .filter(|(t, _)| *t == EntityType::Ip)
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(ips, vec!["10.34.18.21", "192.168.1.1/24"]);
    }

    #[test]
    fn internal_hosts_by_zone() {
        let f = found("see jira.company.ru and github.com and platform-appdb01p.prod.corp.local");
        let hosts: Vec<_> = f
            .iter()
            .filter(|(t, _)| *t == EntityType::Host)
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(
            hosts,
            vec!["jira.company.ru", "platform-appdb01p.prod.corp.local"]
        );
    }

    // REQ: DET-04 — checksums.
    #[test]
    fn pii_checksums() {
        assert!(snils_ok("112-233-445 95"));
        assert!(!snils_ok("112-233-445 96"));
        assert!(inn_ok("7707083893"));
        assert!(!inn_ok("7707083894"));
        assert!(luhn_ok("4539 1488 0343 6467"));
        assert!(!luhn_ok("4539 1488 0343 6468"));
        let f = found("ИНН 7707083893, карта 4539 1488 0343 6467, СНИЛС 112-233-445 95, паспорт 4510 123456, тел +7 999 123-45-67");
        for ty in [
            EntityType::Inn,
            EntityType::Card,
            EntityType::Snils,
            EntityType::Passport,
            EntityType::Phone,
        ] {
            assert!(f.iter().any(|(t, _)| *t == ty), "{ty:?} missing in {f:?}");
        }
    }

    #[test]
    fn bare_numbers_are_not_pii() {
        let f = found("build 7707083893 count 4510123456 id 1234567890123456");
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn email_excludes_public_domains() {
        let f = found("ivan.petrov@corp.ru noreply@github.com a@example.com");
        assert_eq!(f.len(), 1);
    }

    // REQ: DET-06 — all declined forms map to the same person key.
    #[test]
    fn declined_names_share_key() {
        let p = pipe();
        let t = "Иван Петров написал. Ивану Петрову ответили. С Иваном Петровым созвонились. Петрова нет.";
        let keys: Vec<_> = p
            .scan(t)
            .into_iter()
            .filter(|e| e.ty == EntityType::Person)
            .map(|e| e.person_key.unwrap())
            .collect();
        assert!(keys.len() >= 4, "{keys:?}");
        assert!(keys.windows(2).all(|w| w[0] == w[1]));
    }

    // REQ: DET-07 — order independent.
    #[test]
    fn email_links_to_person() {
        let p = pipe();
        for t in [
            "ivan.petrov@corp.ru и Иван Петров",
            "Иван Петров и ivan.petrov@corp.ru",
        ] {
            let es = p.scan(t);
            let person = es
                .iter()
                .find(|e| e.ty == EntityType::Person)
                .and_then(|e| e.person_key.clone());
            let email = es
                .iter()
                .find(|e| e.ty == EntityType::Email)
                .and_then(|e| e.person_key.clone());
            assert!(
                person.is_some() && person == email,
                "{t}: {person:?} vs {email:?}"
            );
        }
    }

    #[test]
    fn dictionary_terms_respect_word_boundaries() {
        let f = found("InternalPaymentSystem и MyInternalPaymentSystemX");
        assert_eq!(
            f.iter().filter(|(t, _)| *t == EntityType::System).count(),
            1
        );
    }

    // REQ: DET-05 — constructs found as false positives on 1.8M lines of open-source code.
    #[test]
    fn ordinary_code_is_not_sensitive() {
        let code = [
            "    password: String,",
            "    tokens: TokenStream,",
            "token: Option<Token>,",
            "Secret: FromRef<S>,",
            "let t = Token::String(field1);",
            "sig.fn_token.span = sig.asyncness.take().unwrap().span;",
            "generics.lt_token = Some(Token![<]);",
            "///       token          = 1*tchar",
            "let a = self.engine.internal;",
            "let b = listener.local;",
            "let p = client_1.local_addr().unwrap();",
            "let e = crypto.header.local;",
            "const X: u64 = 2251799813685228;",
            "let big = 1072319116312658;",
            "let dt = +292277026596-12;",
            "let u = \"http://[2001:db8::1]:8080/\";",
            "let u = \"http://username:password@example.org/\";",
            "let svc_err = Error::new_user_service(recvd);",
            "let svc_fn = service_fn(|_| async {});",
            "let tok = os.environ[\"TOKEN\"]",
            "password = args.password",
            "PASSWORD: ${DB_PASS}",
            "token = $TOKEN",
        ];
        for line in code {
            let f = found(line);
            assert!(f.is_empty(), "false positive on {line:?}: {f:?}");
        }
    }

    // REQ: DET-04 — forms found as missed on the synthetic positive corpus.
    #[test]
    fn secret_forms_from_the_positive_corpus() {
        let cases = [
            ("password := \"Jd8@2jd82k\"", "Jd8@2jd82k"),
            (
                "os.environ.setdefault(\"DB_PASSWORD\", \"Jd8@2jd82k\")",
                "Jd8@2jd82k",
            ),
            (
                "    - name: SECRET_KEY\n      value: \"hctjoUi&Fla7C62857\"",
                "hctjoUi&Fla7C62857",
            ),
            (
                "Пароль от УЗ: OhG-jxCKiXU1WB307, никому не передавать",
                "OhG-jxCKiXU1WB307",
            ),
            ("пароль от базы - FzVj!jOL34", "FzVj!jOL34"),
            ("Логин: svc_app, пароль: Jd8@2jd82k", "Jd8@2jd82k"),
            ("токен: ab12cd34ef56", "ab12cd34ef56"),
            (
                "DATABASE_URL=postgresql://svc_x:$0bZVG048OQL7885@db-prod01.corp.local:5432/p",
                "$0bZVG048OQL7885",
            ),
            (
                "DATABASE_URL=postgresql://svc_x:-x34Z5QFiaQcq2583@db-prod01.corp.local:5432/p",
                "-x34Z5QFiaQcq2583",
            ),
            (
                "key = \"AIzaSokrEgTR0cD0x6TE8XLsiL5xzMF6hBu56K-\"",
                "AIzaSokrEgTR0cD0x6TE8XLsiL5xzMF6hBu56K-",
            ),
        ];
        for (text, value) in cases {
            let f = found(text);
            assert!(
                f.iter()
                    .any(|(t, v)| *t == EntityType::Secret && v == value),
                "{text:?} -> {f:?}"
            );
        }
        for text in [
            "mysql -u svc_etl -p",
            "user svc_payment",
            "login: svc_billing",
            "DB_USER=svc_reports",
        ] {
            assert!(
                found(text)
                    .iter()
                    .any(|(t, v)| *t == EntityType::Svc && v.starts_with("svc_")),
                "{text:?}"
            );
        }
    }

    // REQ: DET-04 — unquoted card numbers need a format or context.
    #[test]
    fn card_numbers_need_format_or_context() {
        assert!(
            found("n = 4539148803436467").is_empty(),
            "a bare Luhn-valid integer is not a card"
        );
        assert!(found("карта 4539148803436467 срок")
            .iter()
            .any(|(t, _)| *t == EntityType::Card));
        assert!(found("card: 4539 1488 0343 6467")
            .iter()
            .any(|(t, _)| *t == EntityType::Card));
        assert!(found("amex 3782 822463 10005")
            .iter()
            .any(|(t, _)| *t == EntityType::Card));
    }

    #[test]
    fn overlaps_prefer_secret_over_host() {
        // a password that looks like a host must stay a single secret
        let f = found("password=prod-db01.corp.local");
        assert!(f.iter().all(|(t, _)| *t == EntityType::Secret), "{f:?}");
    }
}

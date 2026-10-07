//! REQ: DET-01, DET-04, DET-05, DET-06, DET-07, DET-08 — L0 detectors.
//!
//! Detectors only report positions and types; values stay in the scanned text.

use crate::types::{Entity, EntityType, Span};
use aho_corasick::{AhoCorasick, MatchKind};
use regex::Regex;
use std::collections::BTreeSet;

pub const DETECTOR_VERSION: u32 = 1;

/// Interface shared by all detectors (T0-02).
pub trait Detector: Send + Sync {
    fn id(&self) -> &'static str;
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
}

impl Default for DetectConfig {
    fn default() -> Self {
        Self {
            internal_zones: vec![],
            company_ranges: vec![],
            public_email_domains: ["github.com", "example.com", "example.org", "users.noreply.github.com"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            placeholder_markers: ["example", "dummy", "placeholder", "changeme", "your", "xxxx", "****", "redacted"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

const BUILTIN_ZONES: &[&str] = &["local", "internal", "corp", "lan", "intranet"];

impl DetectConfig {
    fn is_internal_host(&self, host: &str) -> bool {
        let h = host.to_ascii_lowercase();
        let h = h.trim_end_matches('.');
        BUILTIN_ZONES
            .iter()
            .map(|z| z.to_string())
            .chain(self.internal_zones.iter().cloned())
            .any(|z| h == z || h.ends_with(&format!(".{z}")))
    }

    pub fn is_private_ipv4(&self, ip: u32) -> bool {
        let in_range = |base: u32, len: u8| {
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len as u32) };
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
        if matches!(l.as_str(), "password" | "secret" | "token" | "null" | "none" | "true" | "false" | "test" | "string") {
            return true;
        }
        if v.chars().all(|c| c == '*' || c == 'x' || c == 'X' || c == '.' || c == '-') {
            return true;
        }
        self.placeholder_markers.iter().any(|m| l.contains(m.as_str()))
    }
}

// ---------------------------------------------------------------------------
// Secrets (L0)
// ---------------------------------------------------------------------------

pub struct SecretDetector {
    known: Vec<(Regex, &'static str)>,
    pem: Regex,
    assign: Regex,
    basic: Regex,
    bearer: Regex,
    cfg: DetectConfig,
}

impl SecretDetector {
    pub fn new(cfg: DetectConfig) -> Self {
        let k = |p: &str, kind: &'static str| (Regex::new(p).expect("static regex"), kind);
        Self {
            known: vec![
                k(r"\bAKIA[0-9A-Z]{16}\b", "aws"),
                k(r"\bASIA[0-9A-Z]{16}\b", "aws"),
                k(r"\bAIza[0-9A-Za-z_\-]{35}\b", "gcp"),
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
            pem: Regex::new(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----")
                .expect("static regex"),
            assign: Regex::new(
                r#"(?i)(?:password|passwd|pwd|passphrase|secret|token|api[_\-]?key|apikey|access[_\-]?key|private[_\-]?key|client[_\-]?secret)[\w\-]*["']?\s*[:=]\s*["']?([^\s"'`,;{}<>\[\]()$]{4,})"#,
            )
            .expect("static regex"),
            basic: Regex::new(r"(?i)authorization:\s*basic\s+([A-Za-z0-9+/=]{16,})").expect("static regex"),
            bearer: Regex::new(r"(?i)\bbearer\s+([A-Za-z0-9._\-]{20,})").expect("static regex"),
            cfg,
        }
    }
}

impl Detector for SecretDetector {
    fn id(&self) -> &'static str {
        "secret.l0"
    }

    fn scan(&self, text: &str, out: &mut Vec<Candidate>) {
        for (re, kind) in &self.known {
            for m in re.find_iter(text) {
                out.push(cand(m.start(), m.end(), EntityType::Secret, Some(kind), "secret.known", 90));
            }
        }
        for m in self.pem.find_iter(text) {
            out.push(cand(m.start(), m.end(), EntityType::Secret, Some("pem"), "secret.pem", 100));
        }
        for c in self.assign.captures_iter(text) {
            if let Some(v) = c.get(1) {
                if !self.cfg.is_placeholder(v.as_str()) {
                    out.push(cand(v.start(), v.end(), EntityType::Secret, Some("password"), "secret.assign", 60));
                }
            }
        }
        for c in self.basic.captures_iter(text) {
            if let Some(v) = c.get(1) {
                out.push(cand(v.start(), v.end(), EntityType::Secret, Some("basic"), "secret.basic", 80));
            }
        }
        for c in self.bearer.captures_iter(text) {
            if let Some(v) = c.get(1) {
                out.push(cand(v.start(), v.end(), EntityType::Secret, Some("bearer"), "secret.bearer", 70));
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
}

impl InfraDetector {
    pub fn new(cfg: DetectConfig) -> Self {
        Self {
            cfg,
            ipv4: Regex::new(r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?").expect("static regex"),
            ipv6: Regex::new(r"(?i)\bf[cd][0-9a-f]{2}(?::[0-9a-f]{0,4}){2,7}(?:/\d{1,3})?").expect("static regex"),
            fqdn: Regex::new(r"(?i)[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)+")
                .expect("static regex"),
            // scheme://[user[:password]@]host[:port][/path]
            uri: Regex::new(
                r#"(?i)\b([a-z][a-z0-9+.\-]*)://(?:([^\s:/@"']+)(?::([^\s/"']*))?@)?([^\s:/?#"'<>@]+)(?::(\d+))?(/[^\s?#"'<>]*)?"#,
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

const DB_SCHEMES: &[&str] = &["postgres", "postgresql", "mysql", "mariadb", "mongodb", "mongodb+srv", "redis", "amqp", "sqlserver", "oracle"];

impl Detector for InfraDetector {
    fn id(&self) -> &'static str {
        "infra.l0"
    }

    fn scan(&self, text: &str, out: &mut Vec<Candidate>) {
        // URIs and connection strings: report the parts, keep scheme/port/path structure.
        for c in self.uri.captures_iter(text) {
            let scheme = c.get(1).map(|m| m.as_str().to_ascii_lowercase()).unwrap_or_default();
            if let Some(u) = c.get(2) {
                if c.get(3).is_some() {
                    out.push(cand(u.start(), u.end(), EntityType::Svc, None, "infra.uri.user", 70));
                }
            }
            if let Some(p) = c.get(3) {
                if !p.as_str().is_empty() && !self.cfg.is_placeholder(p.as_str()) {
                    out.push(cand(p.start(), p.end(), EntityType::Secret, Some("password"), "infra.uri.password", 85));
                }
            }
            if let Some(h) = c.get(4) {
                let hs = h.as_str();
                let is_ip = parse_ipv4(hs).is_some();
                let single_label = !hs.contains('.');
                let internal = self.cfg.is_internal_host(hs)
                    || (is_ip && parse_ipv4(hs).map(|ip| self.cfg.is_private_ipv4(ip)).unwrap_or(false))
                    || (single_label && !hs.eq_ignore_ascii_case("localhost") && !hs.contains('{') && !hs.contains('$'));
                if internal && !is_ip {
                    out.push(cand(h.start(), h.end(), EntityType::Host, None, "infra.uri.host", 75));
                }
                // Private IPs in URIs are reported by the IPv4 scan below.
            }
            if let Some(path) = c.get(6) {
                let seg = path.as_str().trim_start_matches('/').split('/').next().unwrap_or("");
                let db_scheme = DB_SCHEMES.contains(&scheme.as_str())
                    || text[..c.get(0).map(|m| m.start()).unwrap_or(0)].ends_with("jdbc:");
                if db_scheme && !seg.is_empty() && !seg.contains('{') && !seg.contains('$') {
                    let start = path.start() + 1;
                    out.push(cand(start, start + seg.len(), EntityType::Db, None, "infra.uri.db", 70));
                }
            }
        }

        for m in self.ipv4.find_iter(text) {
            let s = m.as_str();
            // Do not match inside longer dotted numbers or identifiers.
            if byte_before(text, m.start()).is_some_and(|c| c.is_ascii_alphanumeric() || c == '.' && text[..m.start()].chars().rev().nth(1).is_some_and(|d| d.is_ascii_digit())) {
                continue;
            }
            if byte_after(text, m.end()).is_some_and(|c| c.is_ascii_alphanumeric() || c == '.' && text[m.end() + 1..].chars().next().is_some_and(|d| d.is_ascii_digit())) {
                continue;
            }
            let (addr, _) = s.split_once('/').unwrap_or((s, ""));
            if let Some(ip) = parse_ipv4(addr) {
                if self.cfg.is_private_ipv4(ip) {
                    out.push(cand(m.start(), m.end(), EntityType::Ip, None, "infra.ipv4", 65));
                }
            }
        }
        for m in self.ipv6.find_iter(text) {
            out.push(cand(m.start(), m.end(), EntityType::Ip, None, "infra.ipv6", 65));
        }

        for m in self.fqdn.find_iter(text) {
            let s = m.as_str();
            if parse_ipv4(s).is_some() {
                continue;
            }
            // Skip file names and dotted identifiers that merely end in an internal-looking label.
            if byte_before(text, m.start()).is_some_and(|c| c == '@' || c == '/' && false) {
                continue;
            }
            if self.cfg.is_internal_host(s) {
                out.push(cand(m.start(), m.end(), EntityType::Host, None, "infra.fqdn", 55));
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
    passport: Regex,
    acct: Regex,
}

impl PiiDetector {
    pub fn new(cfg: DetectConfig) -> Self {
        Self {
            cfg,
            email: Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}").expect("static regex"),
            phone_ru: Regex::new(r"(?:\+7|\b8)[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}\b").expect("static regex"),
            phone_intl: Regex::new(r"\+\d{1,3}[\s\-]?\(?\d{2,4}\)?[\s\-]?\d{3}[\s\-]?\d{2,4}[\s\-]?\d{2,4}\b").expect("static regex"),
            snils: Regex::new(r"\b\d{3}-\d{3}-\d{3}[ \-]\d{2}\b").expect("static regex"),
            digits10_12: Regex::new(r"\b\d{10}(?:\d{2})?\b").expect("static regex"),
            card: Regex::new(r"\b\d{4}(?:[ \-]?\d{4}){2,3}(?:[ \-]?\d{1,3})?\b").expect("static regex"),
            passport: Regex::new(r"\b\d{2}\s?\d{2}\s?\d{6}\b").expect("static regex"),
            acct: Regex::new(r"\b\d{20}\b").expect("static regex"),
        }
    }
}

fn context_before(text: &str, start: usize, words: &[&str]) -> bool {
    let from = text[..start].char_indices().rev().nth(40).map(|(i, _)| i).unwrap_or(0);
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
        .map(|(i, &d)| if i % 2 == 1 { let x = d * 2; if x > 9 { x - 9 } else { x } } else { d })
        .sum();
    sum % 10 == 0
}

pub fn snils_ok(s: &str) -> bool {
    let d: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if d.len() != 11 {
        return false;
    }
    let sum: u32 = d[..9].iter().enumerate().map(|(i, &x)| x * (9 - i as u32)).sum();
    let control = match sum {
        0..=99 => sum,
        100 | 101 => 0,
        _ => {
            let r = sum % 101;
            if r == 100 { 0 } else { r }
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
        12 => check(&[7, 2, 4, 10, 3, 5, 9, 4, 6, 8], 10) && check(&[3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8], 11),
        _ => false,
    }
}

impl Detector for PiiDetector {
    fn id(&self) -> &'static str {
        "pii.l0"
    }

    fn scan(&self, text: &str, out: &mut Vec<Candidate>) {
        for m in self.email.find_iter(text) {
            let domain = m.as_str().rsplit('@').next().unwrap_or("").to_ascii_lowercase();
            if self.cfg.public_email_domains.iter().any(|d| *d == domain) || m.as_str().starts_with("noreply@") {
                continue;
            }
            out.push(cand(m.start(), m.end(), EntityType::Email, None, "pii.email", 80));
        }
        for re in [&self.phone_ru, &self.phone_intl] {
            for m in re.find_iter(text) {
                out.push(cand(m.start(), m.end(), EntityType::Phone, None, "pii.phone", 50));
            }
        }
        for m in self.snils.find_iter(text) {
            if snils_ok(m.as_str()) {
                out.push(cand(m.start(), m.end(), EntityType::Snils, None, "pii.snils", 75));
            }
        }
        for m in self.digits10_12.find_iter(text) {
            if inn_ok(m.as_str()) && context_before(text, m.start(), &["инн", "inn"]) {
                out.push(cand(m.start(), m.end(), EntityType::Inn, None, "pii.inn", 75));
            }
        }
        for m in self.card.find_iter(text) {
            if luhn_ok(m.as_str()) {
                out.push(cand(m.start(), m.end(), EntityType::Card, None, "pii.card", 75));
            }
        }
        for m in self.passport.find_iter(text) {
            if context_before(text, m.start(), &["паспорт", "passport"]) {
                out.push(cand(m.start(), m.end(), EntityType::Passport, None, "pii.passport", 75));
            }
        }
        for m in self.acct.find_iter(text) {
            if context_before(text, m.start(), &["счет", "счёт", "р/с", "account", "acct", "iban"]) {
                out.push(cand(m.start(), m.end(), EntityType::Acct, None, "pii.acct", 70));
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
                'а' => "a", 'б' => "b", 'в' => "v", 'г' => "g", 'д' => "d", 'е' | 'ё' | 'э' => "e",
                'ж' => "zh", 'з' => "z", 'и' => "i", 'й' => j, 'к' => "k", 'л' => "l", 'м' => "m",
                'н' => "n", 'о' => "o", 'п' => "p", 'р' => "r", 'с' => "s", 'т' => "t", 'у' => "u",
                'ф' => "f", 'х' => kh, 'ц' => "ts", 'ч' => "ch", 'ш' => "sh", 'щ' => "shch",
                'ъ' | 'ь' => "", 'ы' => "y", 'ю' => ju, 'я' => ja,
                c if c.is_ascii_alphabetic() => { s.push(c); continue; }
                _ => continue,
            };
            s.push_str(t);
        }
        s
    }
    let mut v = BTreeSet::new();
    for (ju, ja, j, kh) in [("iu", "ia", "i", "kh"), ("yu", "ya", "y", "kh"), ("yu", "ya", "y", "h"), ("iu", "ia", "y", "kh")] {
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
    if lower.ends_with("ов") || lower.ends_with("ев") || lower.ends_with("ин") || lower.ends_with("ын") {
        add(&mut forms, w, &["а", "у", "ым", "е", "ых", "ым"]);
        if lower.ends_with("ин") || lower.ends_with("ын") {
            // Ильин → Ильиным
            forms.push(format!("{w}ым"));
        } else {
            forms.push(format!("{w}ым"));
        }
    } else if lower.ends_with("ова") || lower.ends_with("ева") || lower.ends_with("ина") || lower.ends_with("ына") {
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
    } else if chars.last().is_some_and(|c| "бвгджзклмнпрстфхцчшщ".contains(*c)) {
        add(&mut forms, w, &["а", "у", "ом", "е"]);
    }
    forms.sort();
    forms.dedup();
    forms.into_iter().map(|f| if f.chars().next().is_some_and(|c| c.is_uppercase()) { f } else { cap(f) }).collect()
}

impl Dictionary {
    /// Add an employee with all name orders and declined forms.
    pub fn add_person(&mut self, first: &str, last: &str) {
        let f_tr = translit_variants(first);
        let l_tr = translit_variants(last);
        let key = {
            let mut toks = vec![
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
                    self.entries.push(DictEntry { form, ty: EntityType::Person, key: key.clone() });
                }
            }
        }
        for l in &ls {
            if l.chars().count() >= 5 {
                self.entries.push(DictEntry { form: l.clone(), ty: EntityType::Person, key: key.clone() });
            }
        }
        self.persons.push(Person { key, first: f_tr, last: l_tr });
    }

    pub fn add_term(&mut self, form: &str, ty: EntityType) {
        self.entries.push(DictEntry { form: form.to_string(), ty, key: form.to_lowercase() });
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
            AhoCorasick::builder().match_kind(MatchKind::LeftmostLongest).build(&pats).ok()
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
    fn id(&self) -> &'static str {
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
        self.detectors.iter().map(|d| format!("{}@{}", d.id(), d.version())).collect::<Vec<_>>().join(",")
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

    /// DET-07: an e-mail whose local part carries first and last name of a known person
    /// belongs to that person, independent of the order of appearance.
    fn link_people(&self, text: &str, entities: &mut [Entity]) {
        for e in entities.iter_mut().filter(|e| e.ty == EntityType::Email) {
            let local = text[e.span.start..e.span.end].split('@').next().unwrap_or("").to_lowercase();
            let toks: Vec<&str> = local.split(|c: char| !c.is_ascii_alphabetic()).filter(|t| !t.is_empty()).collect();
            for p in &self.dict.persons {
                let first_ok = toks.iter().any(|t| p.first.contains(*t) || p.first.iter().any(|f| f.starts_with(*t) && t.len() == 1));
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
        let cfg = DetectConfig { internal_zones: vec!["company.ru".into()], ..Default::default() };
        let mut d = Dictionary::default();
        d.add_person("Иван", "Петров");
        d.add_term("InternalPaymentSystem", EntityType::System);
        Pipeline::new(cfg, d)
    }

    fn found(text: &str) -> Vec<(EntityType, String)> {
        pipe().scan(text).into_iter().map(|e| (e.ty, text[e.span.start..e.span.end].to_string())).collect()
    }

    // REQ: DET-04
    #[test]
    fn known_secret_formats() {
        let t = "k=AKIAIOSFODNN7EXAMPLE g=ghp_abcdefghijklmnopqrstuvwxyz0123456789 gl=glpat-abcdefghij1234567890 jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop";
        let f = found(t);
        assert!(f.iter().any(|(ty, v)| *ty == EntityType::Secret && v.starts_with("AKIA")), "{f:?}");
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
        assert!(f.contains(&(EntityType::Host, "prod-db01.pay.corp.local".into())), "{f:?}");
        assert!(f.contains(&(EntityType::Db, "clients".into())), "{f:?}");
        let t2 = "postgresql://svc_payment:Jd8@2jd82k@prod-db01:5432/payment";
        let f2 = found(t2);
        assert!(f2.contains(&(EntityType::Svc, "svc_payment".into())), "{f2:?}");
        assert!(f2.iter().any(|(ty, v)| *ty == EntityType::Secret && v.starts_with("Jd8")), "{f2:?}");
        assert!(f2.contains(&(EntityType::Host, "prod-db01".into())), "{f2:?}");
    }

    #[test]
    fn password_assignment_and_placeholders() {
        let f = found("DB_PASSWORD = \"Jd8@2jd82k\"\nPASSWORD: ${DB_PASS}\npassword: changeme\ntoken: <your-token>");
        assert_eq!(f.iter().filter(|(t, _)| *t == EntityType::Secret).count(), 1, "{f:?}");
    }

    // REQ: DET-04
    #[test]
    fn private_ips_only() {
        let f = found("a 10.34.18.21 b 8.8.8.8 c 192.168.1.1/24 d 1.2.3.4.5 e 10.1.2.3.4");
        let ips: Vec<_> = f.iter().filter(|(t, _)| *t == EntityType::Ip).map(|(_, v)| v.as_str()).collect();
        assert_eq!(ips, vec!["10.34.18.21", "192.168.1.1/24"]);
    }

    #[test]
    fn internal_hosts_by_zone() {
        let f = found("see jira.company.ru and github.com and platform-appdb01p.prod.corp.local");
        let hosts: Vec<_> = f.iter().filter(|(t, _)| *t == EntityType::Host).map(|(_, v)| v.as_str()).collect();
        assert_eq!(hosts, vec!["jira.company.ru", "platform-appdb01p.prod.corp.local"]);
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
        for ty in [EntityType::Inn, EntityType::Card, EntityType::Snils, EntityType::Passport, EntityType::Phone] {
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
        let keys: Vec<_> = p.scan(t).into_iter().filter(|e| e.ty == EntityType::Person).map(|e| e.person_key.unwrap()).collect();
        assert!(keys.len() >= 4, "{keys:?}");
        assert!(keys.windows(2).all(|w| w[0] == w[1]));
    }

    // REQ: DET-07 — order independent.
    #[test]
    fn email_links_to_person() {
        let p = pipe();
        for t in ["ivan.petrov@corp.ru и Иван Петров", "Иван Петров и ivan.petrov@corp.ru"] {
            let es = p.scan(t);
            let person = es.iter().find(|e| e.ty == EntityType::Person).and_then(|e| e.person_key.clone());
            let email = es.iter().find(|e| e.ty == EntityType::Email).and_then(|e| e.person_key.clone());
            assert!(person.is_some() && person == email, "{t}: {person:?} vs {email:?}");
        }
    }

    #[test]
    fn dictionary_terms_respect_word_boundaries() {
        let f = found("InternalPaymentSystem и MyInternalPaymentSystemX");
        assert_eq!(f.iter().filter(|(t, _)| *t == EntityType::System).count(), 1);
    }

    #[test]
    fn overlaps_prefer_secret_over_host() {
        // a password that looks like a host must stay a single secret
        let f = found("password=prod-db01.corp.local");
        assert!(f.iter().all(|(t, _)| *t == EntityType::Secret), "{f:?}");
    }
}

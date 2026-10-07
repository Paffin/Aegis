//! REQ: POL-09, CFG-03 — executable examples for a policy.
//!
//! A bundle is not built when its policy tests fail.

use crate::bundle::{Compiled, PolicyDoc};
use crate::detect::Pipeline;
use crate::policy::{Action, Ingress, Sink};
use crate::types::{Class, EntityType};
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TestDoc {
    #[serde(default)]
    pub ingress: Vec<IngressCase>,
    #[serde(default)]
    pub restore: Vec<RestoreCase>,
    #[serde(default)]
    pub trifecta: Vec<TrifectaCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressCase {
    pub text: String,
    #[serde(default = "d_route")]
    pub route: String,
    #[serde(default)]
    pub expect: Vec<Expect>,
    /// Substrings that must not be detected.
    #[serde(default)]
    pub absent: Vec<String>,
}

fn d_route() -> String {
    "anthropic-default".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    pub contains: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub kind: Option<String>,
    /// `allow|mask|drop_block|block_request`
    pub action: String,
    pub rule: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreCase {
    pub sink: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub kind: Option<String>,
    pub action: String,
    pub rule: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrifectaCase {
    pub private: bool,
    pub untrusted: bool,
    pub sink: String,
    #[serde(default)]
    pub destinations: Vec<String>,
    pub blocked: bool,
}

impl TestDoc {
    pub fn from_yaml(t: &str) -> Result<Self, String> {
        serde_yaml_ng::from_str(t).map_err(|e| format!("тесты политики: {e}"))
    }
}

/// Detection pipeline of a compiled policy (built-in detectors, dictionary, custom detectors).
pub fn pipeline(c: &mut Compiled) -> Pipeline {
    let mut p = Pipeline::new(c.detect.clone(), std::mem::take(&mut c.dict));
    for d in std::mem::take(&mut c.custom) {
        p.add_detector(Box::new(d));
    }
    p
}

fn ty_of(s: &str) -> Result<EntityType, String> {
    EntityType::from_marker(s).ok_or_else(|| format!("неизвестный тип «{s}»"))
}

fn ingress_name(i: Ingress) -> &'static str {
    match i {
        Ingress::Allow => "allow",
        Ingress::Mask => "mask",
        Ingress::DropBlock => "drop_block",
        Ingress::BlockRequest => "block_request",
    }
}

fn action_name(a: Action) -> &'static str {
    match a {
        Action::Restore => "restore",
        Action::InternalOnly => "internal_only",
        Action::OriginOnly => "origin_only",
        Action::MarkerHint => "marker_hint",
        Action::KeepMasked => "keep_masked",
        Action::Deny => "deny",
    }
}

fn sink_of(s: &str) -> Result<Sink, String> {
    [
        Sink::Text,
        Sink::FileWrite,
        Sink::FileRead,
        Sink::ShellLocal,
        Sink::ShellExec,
        Sink::ShellNetwork,
        Sink::Network,
        Sink::Agent,
        Sink::Mcp,
        Sink::Unknown,
    ]
    .into_iter()
    .find(|k| k.as_str() == s)
    .ok_or_else(|| format!("неизвестное место назначения «{s}»"))
}

/// Run all cases; returns every failure (not just the first).
pub fn run(policy: &PolicyDoc, tests: &TestDoc) -> Result<usize, Vec<String>> {
    let mut c = policy.compile().map_err(|e| vec![e])?;
    let mut fails = vec![];
    let mut count = 0;
    let (ingress, restore, trifecta) = (c.ingress.clone(), c.restore.clone(), c.trifecta.clone());
    let pipe = pipeline(&mut c);

    for (i, case) in tests.ingress.iter().enumerate() {
        count += 1;
        let ents = pipe.scan(&case.text);
        let found = |sub: &str| -> Vec<&crate::types::Entity> {
            let Some(at) = case.text.find(sub) else {
                return vec![];
            };
            ents.iter()
                .filter(|e| e.span.start < at + sub.len() && at < e.span.end)
                .collect()
        };
        for ex in &case.expect {
            let want_ty = match ty_of(&ex.ty) {
                Ok(t) => t,
                Err(e) => {
                    fails.push(format!("ingress[{i}]: {e}"));
                    continue;
                }
            };
            let hits = found(&ex.contains);
            let Some(e) = hits
                .iter()
                .find(|e| e.ty == want_ty && (ex.kind.is_none() || e.kind == ex.kind.as_deref()))
            else {
                fails.push(format!(
                    "ingress[{i}]: «{}» не распознано как {}",
                    ex.contains, ex.ty
                ));
                continue;
            };
            let (act, rule) = ingress.decide(e, &case.route);
            if ingress_name(act) != ex.action {
                fails.push(format!(
                    "ingress[{i}]: «{}»: ожидалось {}, получено {} (правило {rule})",
                    ex.contains,
                    ex.action,
                    ingress_name(act)
                ));
            }
            if let Some(r) = &ex.rule {
                if *r != rule {
                    fails.push(format!(
                        "ingress[{i}]: «{}»: ожидалось правило {r}, сработало {rule}",
                        ex.contains
                    ));
                }
            }
        }
        for a in &case.absent {
            if !found(a).is_empty() {
                fails.push(format!("ingress[{i}]: «{a}» не должно распознаваться"));
            }
        }
    }

    for (i, case) in tests.restore.iter().enumerate() {
        count += 1;
        let (sink, ty) = match (sink_of(&case.sink), ty_of(&case.ty)) {
            (Ok(s), Ok(t)) => (s, t),
            (Err(e), _) | (_, Err(e)) => {
                fails.push(format!("restore[{i}]: {e}"));
                continue;
            }
        };
        let (act, rule) = restore.decide(ty, case.kind.as_deref(), sink);
        if action_name(act) != case.action {
            fails.push(format!(
                "restore[{i}]: {} @ {}: ожидалось {}, получено {} (правило {rule})",
                case.ty,
                case.sink,
                case.action,
                action_name(act)
            ));
        }
        if let Some(r) = &case.rule {
            if *r != rule {
                fails.push(format!(
                    "restore[{i}]: ожидалось правило {r}, сработало {rule}"
                ));
            }
        }
    }

    for (i, case) in tests.trifecta.iter().enumerate() {
        count += 1;
        let sink = match sink_of(&case.sink) {
            Ok(s) => s,
            Err(e) => {
                fails.push(format!("trifecta[{i}]: {e}"));
                continue;
            }
        };
        let classes: HashSet<Class> = if case.private {
            trifecta.private_classes.iter().copied().collect()
        } else {
            HashSet::new()
        };
        let st = trifecta.state(&classes, case.untrusted);
        let got = trifecta.blocks(st, sink, &case.destinations);
        if got != case.blocked {
            fails.push(format!(
                "trifecta[{i}]: ожидалось blocked={}, получено {got}",
                case.blocked
            ));
        }
    }
    if fails.is_empty() {
        Ok(count)
    } else {
        Err(fails)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"
version: 1
zones: { internal: [corp.local] }
trifecta: { allow_destinations: ["docs.python.org"] }
rules:
  - id: R-020
    when: { type: SECRET, kind: pem }
    ingress: block_request
  - id: R-112
    when: { sink: [shell_network, network] }
    restore: { SECRET: deny, INFRA: internal_only }
"#;

    const TESTS: &str = r#"
ingress:
  - text: "host prod-db01.corp.local password=Jd8@2jd82k"
    expect:
      - { contains: "prod-db01.corp.local", type: HOST, action: mask, rule: default }
      - { contains: "Jd8@2jd82k", type: SECRET, kind: password, action: mask }
    absent: ["password="]
  - text: "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"
    expect:
      - { contains: "BEGIN RSA", type: SECRET, kind: pem, action: block_request, rule: R-020 }
restore:
  - { sink: shell_network, type: SECRET, action: deny, rule: R-112 }
  - { sink: shell_network, type: HOST, action: internal_only }
  - { sink: text, type: HOST, action: restore, rule: default }
trifecta:
  - { private: true, untrusted: true, sink: network, destinations: ["evil.example"], blocked: true }
  - { private: true, untrusted: true, sink: network, destinations: ["docs.python.org"], blocked: false }
  - { private: true, untrusted: false, sink: network, blocked: false }
"#;

    // REQ: POL-09
    #[test]
    fn passing_suite() {
        let n = run(
            &PolicyDoc::from_yaml(POLICY).unwrap(),
            &TestDoc::from_yaml(TESTS).unwrap(),
        )
        .unwrap();
        assert_eq!(n, 8);
    }

    // REQ: POL-09 — every kind of mismatch is reported, all at once.
    #[test]
    fn failures_are_reported_together() {
        let bad = r#"
ingress:
  - text: "host prod-db01.corp.local"
    expect:
      - { contains: "prod-db01.corp.local", type: HOST, action: block_request }
      - { contains: "prod-db01.corp.local", type: IP, action: mask }
      - { contains: "prod-db01.corp.local", type: HOST, action: mask, rule: R-999 }
    absent: ["prod-db01"]
restore:
  - { sink: text, type: SECRET, action: deny }
  - { sink: moon, type: SECRET, action: deny }
trifecta:
  - { private: true, untrusted: true, sink: network, destinations: ["evil.example"], blocked: false }
"#;
        let errs = run(
            &PolicyDoc::from_yaml(POLICY).unwrap(),
            &TestDoc::from_yaml(bad).unwrap(),
        )
        .unwrap_err();
        assert_eq!(errs.len(), 7, "{errs:#?}");
        assert!(errs
            .iter()
            .any(|e| e.contains("ожидалось block_request, получено mask")));
        assert!(errs.iter().any(|e| e.contains("не распознано как IP")));
        assert!(errs.iter().any(|e| e.contains("ожидалось правило R-999")));
        assert!(errs.iter().any(|e| e.contains("не должно распознаваться")));
        assert!(errs
            .iter()
            .any(|e| e.contains("неизвестное место назначения")));
    }

    #[test]
    fn unknown_fields_in_tests_are_errors() {
        assert!(TestDoc::from_yaml("ingress:\n  - text: x\n    expects: []").is_err());
    }
}

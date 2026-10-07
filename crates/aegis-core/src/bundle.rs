//! REQ: CFG-01, CFG-03, CFG-04, POL-01, POL-02, POL-03, POL-09, DET-08, SEC-11 — policy document,
//! compilation and the signed bundle.
//!
//! Pure: parsing and verification take bytes and return values. Reading files, URLs and keys is
//! done by the callers (`aegis-cli`, the gateway).

use crate::detect::{CustomDetector, DetectConfig, Detector, Dictionary};
use crate::policy::{
    Action, Ingress, IngressPolicy, IngressRule, RestorePolicy, RestoreRule, Sink, TrifectaConfig,
    TrifectaMode,
};
use crate::pseudo::PseudoConfig;
use crate::types::{Class, EntityType};
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const FORMAT: &str = "aegis-bundle/1";

// ---------------------------------------------------------------------------
// Policy document (YAML)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PolicyDoc {
    pub version: u32,
    #[serde(default = "d_tenant")]
    pub tenant: String,
    #[serde(default)]
    pub zones: Zones,
    #[serde(default)]
    pub detectors: DetectorsDoc,
    #[serde(default)]
    pub dictionary: DictionaryDoc,
    #[serde(default)]
    pub trifecta: TrifectaDoc,
    #[serde(default)]
    pub response: ResponseDoc,
    #[serde(default)]
    pub defaults: DefaultsDoc,
    #[serde(default)]
    pub pseudonyms: PseudonymsDoc,
    #[serde(default)]
    pub rules: Vec<RuleDoc>,
}

fn d_tenant() -> String {
    "default".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Zones {
    #[serde(default)]
    pub internal: Vec<String>,
    /// CIDR, e.g. `10.50.0.0/16`.
    #[serde(default)]
    pub company_ranges: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DetectorsDoc {
    #[serde(default)]
    pub service_account_patterns: Vec<String>,
    #[serde(default)]
    pub public_email_domains: Vec<String>,
    #[serde(default)]
    pub placeholder_markers: Vec<String>,
    #[serde(default)]
    pub custom: Vec<CustomDoc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomDoc {
    pub id: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub regex: String,
    #[serde(default)]
    pub group: usize,
    pub examples: Examples,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Examples {
    #[serde(default)]
    pub matches: Vec<String>,
    #[serde(default)]
    pub non_matches: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DictionaryDoc {
    #[serde(default)]
    pub employees: Vec<EmployeeDoc>,
    #[serde(default)]
    pub terms: Vec<TermDoc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmployeeDoc {
    pub first: String,
    pub last: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TermDoc {
    pub form: String,
    #[serde(rename = "type")]
    pub ty: String,
}

/// Checks of the model's answer (RSP-06, RSP-10): `off`, `warn` or `deny`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ResponseDoc {
    /// A secret the model wrote itself in the arguments of a tool call (default `deny`).
    #[serde(default)]
    pub tool_secrets: Option<String>,
    /// The same in the content of a file the call writes (default `warn`).
    #[serde(default)]
    pub file_secrets: Option<String>,
    /// Dangerous commands in shell calls (default `warn`).
    #[serde(default)]
    pub dangerous_commands: Option<String>,
    /// More patterns for dangerous commands, regular expressions.
    #[serde(default)]
    pub dangerous_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrifectaDoc {
    #[serde(default = "d_enforce")]
    pub mode: String,
    #[serde(default = "d_private")]
    pub private_classes: Vec<String>,
    #[serde(default = "d_untrusted_tools")]
    pub untrusted_tools: Vec<String>,
    #[serde(default = "d_untrusted_paths")]
    pub untrusted_paths: Vec<String>,
    #[serde(default)]
    pub allow_destinations: Vec<String>,
    #[serde(default)]
    pub block_exec: bool,
}

fn d_enforce() -> String {
    "enforce".into()
}
fn d_private() -> Vec<String> {
    ["SECRET", "PII", "INFRA"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}
fn d_untrusted_tools() -> Vec<String> {
    ["WebFetch", "WebSearch"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}
fn d_untrusted_paths() -> Vec<String> {
    ["node_modules/", "vendor/", "third_party/", ".git/modules/"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

impl Default for TrifectaDoc {
    fn default() -> Self {
        Self {
            mode: d_enforce(),
            private_classes: d_private(),
            untrusted_tools: d_untrusted_tools(),
            untrusted_paths: d_untrusted_paths(),
            allow_destinations: vec![],
            block_exec: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DefaultsDoc {
    /// Class → `allow|mask|drop_block|block_request`.
    #[serde(default)]
    pub ingress: BTreeMap<String, String>,
    /// Only `drop_block` is implemented.
    #[serde(default)]
    pub attachments: Option<String>,
    /// Only `block_request` is implemented.
    #[serde(default)]
    pub embeddings: Option<String>,
    /// Only `block_request` is implemented.
    #[serde(default)]
    pub provider_server_tools: Option<String>,
    /// Subset of `kind`, `has`, `len`.
    #[serde(default)]
    pub secret_attributes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PseudonymsDoc {
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub envs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct When {
    pub class: Option<String>,
    #[serde(rename = "type")]
    pub ty: Option<String>,
    pub kind: Option<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    pub sink: Vec<String>,
    pub route: Option<String>,
}

fn one_or_many<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum V {
        One(String),
        Many(Vec<String>),
    }
    Ok(match V::deserialize(d)? {
        V::One(s) => vec![s],
        V::Many(v) => v,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ActionSpec {
    /// Applies to the entity selected by `when`.
    One(String),
    /// Class or type name → action.
    Map(BTreeMap<String, String>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDoc {
    pub id: String,
    #[serde(default)]
    pub when: When,
    pub ingress: Option<ActionSpec>,
    pub restore: Option<ActionSpec>,
}

// ---------------------------------------------------------------------------
// Compilation
// ---------------------------------------------------------------------------

/// Ready-to-use structures built from a policy document.
pub struct Compiled {
    pub tenant: String,
    pub detect: DetectConfig,
    pub dict: Dictionary,
    pub custom: Vec<CustomDetector>,
    pub restore: RestorePolicy,
    pub ingress: IngressPolicy,
    pub trifecta: TrifectaConfig,
    pub pseudo: PseudoConfig,
    pub response: crate::danger::ResponsePolicy,
}

fn class_of(s: &str) -> Option<Class> {
    match s {
        "SECRET" => Some(Class::Secret),
        "INFRA" => Some(Class::Infra),
        "PII" => Some(Class::Pii),
        "CORP" => Some(Class::Corp),
        _ => None,
    }
}

/// A selector name is a class (`INFRA`) or a type (`HOST`).
fn selector(name: &str) -> Result<(Option<Class>, Option<EntityType>), String> {
    if let Some(c) = class_of(name) {
        // `SECRET` is both a class and a type; as a type it selects every secret kind.
        return Ok((Some(c), None));
    }
    EntityType::from_marker(name)
        .map(|t| (None, Some(t)))
        .ok_or_else(|| format!("неизвестный класс или тип «{name}»"))
}

fn sink_of(s: &str) -> Result<Sink, String> {
    Ok(match s {
        "text" => Sink::Text,
        "file_write" => Sink::FileWrite,
        "file_read" => Sink::FileRead,
        "shell_local" => Sink::ShellLocal,
        "shell_exec" => Sink::ShellExec,
        "shell_network" => Sink::ShellNetwork,
        "network" => Sink::Network,
        "agent" => Sink::Agent,
        "mcp" => Sink::Mcp,
        "unknown" => Sink::Unknown,
        o => return Err(format!("неизвестное место назначения «{o}»")),
    })
}

fn ingress_of(s: &str) -> Result<Ingress, String> {
    Ok(match s {
        "allow" => Ingress::Allow,
        "mask" => Ingress::Mask,
        "drop_block" => Ingress::DropBlock,
        "block_request" => Ingress::BlockRequest,
        o => return Err(format!("неизвестное действие на входе «{o}»")),
    })
}

fn action_of(s: &str) -> Result<Action, String> {
    Ok(match s {
        "restore" => Action::Restore,
        "internal_only" => Action::InternalOnly,
        "origin_only" => Action::OriginOnly,
        "marker_hint" => Action::MarkerHint,
        "keep_masked" => Action::KeepMasked,
        "deny" => Action::Deny,
        o => return Err(format!("неизвестное действие подстановки «{o}»")),
    })
}

fn parse_cidr(s: &str) -> Option<(u32, u8)> {
    let (a, l) = s.split_once('/')?;
    let len: u8 = l.parse().ok()?;
    (len <= 32).then_some(())?;
    Some((crate::detect::parse_ipv4(a)?, len))
}

impl PolicyDoc {
    pub fn from_yaml(text: &str) -> Result<Self, String> {
        let doc: PolicyDoc = serde_yaml_ng::from_str(text).map_err(|e| format!("политика: {e}"))?;
        if doc.version != 1 {
            return Err(format!("политика: неподдерживаемая версия {}", doc.version));
        }
        Ok(doc)
    }

    pub fn compile(&self) -> Result<Compiled, String> {
        let mut detect = DetectConfig {
            internal_zones: self.zones.internal.clone(),
            ..Default::default()
        };
        for r in &self.zones.company_ranges {
            detect
                .company_ranges
                .push(parse_cidr(r).ok_or_else(|| format!("zones: неверный CIDR «{r}»"))?);
        }
        detect
            .service_account_patterns
            .extend(self.detectors.service_account_patterns.iter().cloned());
        for p in &detect.service_account_patterns {
            regex::Regex::new(p).map_err(|e| format!("service_account_patterns: {e}"))?;
        }
        detect
            .public_email_domains
            .extend(self.detectors.public_email_domains.iter().cloned());
        detect
            .placeholder_markers
            .extend(self.detectors.placeholder_markers.iter().cloned());

        let mut dict = Dictionary::default();
        for e in &self.dictionary.employees {
            dict.add_person(&e.first, &e.last);
        }
        for t in &self.dictionary.terms {
            let ty = match t.ty.as_str() {
                "PROJECT" => EntityType::Project,
                "SYSTEM" => EntityType::System,
                "ORG" => EntityType::Org,
                o => {
                    return Err(format!(
                        "dictionary.terms: тип «{o}» не поддерживается (PROJECT, SYSTEM, ORG)"
                    ))
                }
            };
            dict.add_term(&t.form, ty);
        }

        let mut custom = vec![];
        let mut seen = std::collections::HashSet::new();
        for c in &self.detectors.custom {
            if !seen.insert(c.id.clone()) {
                return Err(format!("detectors.custom: повторяющийся id «{}»", c.id));
            }
            let ty = EntityType::from_marker(&c.ty)
                .filter(|t| *t != EntityType::Lit)
                .ok_or_else(|| format!("detector {}: неизвестный тип «{}»", c.id, c.ty))?;
            custom.push(CustomDetector::new(&c.id, ty, &c.regex, c.group)?);
        }

        let tri_mode = match self.trifecta.mode.as_str() {
            "enforce" => TrifectaMode::Enforce,
            "monitor" => TrifectaMode::Monitor,
            o => return Err(format!("trifecta.mode: «{o}»")),
        };
        let private_classes = self
            .trifecta
            .private_classes
            .iter()
            .map(|c| class_of(c).ok_or_else(|| format!("trifecta.private_classes: «{c}»")))
            .collect::<Result<Vec<_>, _>>()?;
        let trifecta = TrifectaConfig {
            mode: tri_mode,
            private_classes,
            untrusted_tools: self.trifecta.untrusted_tools.clone(),
            untrusted_paths: self.trifecta.untrusted_paths.clone(),
            allow_destinations: self.trifecta.allow_destinations.clone(),
            block_exec: self.trifecta.block_exec,
        };

        // Rules in document order; class defaults go last so that user rules win ties (POL-03).
        let mut ingress = IngressPolicy::default();
        let mut restore = RestorePolicy::default();
        for r in &self.rules {
            if r.ingress.is_none() && r.restore.is_none() {
                return Err(format!("rule {}: нет ни ingress, ни restore", r.id));
            }
            let kind = r.when.kind.clone();
            let when_sel = match (&r.when.class, &r.when.ty) {
                (Some(_), Some(_)) => {
                    return Err(format!("rule {}: укажите class или type, не оба", r.id))
                }
                (Some(c), None) => Some(
                    class_of(c)
                        .map(|c| (Some(c), None))
                        .ok_or_else(|| format!("rule {}: класс «{c}»", r.id))?,
                ),
                (None, Some(t)) => Some(selector(t).map_err(|e| format!("rule {}: {e}", r.id))?),
                (None, None) => None,
            };
            if kind.is_some()
                && !matches!(
                    when_sel,
                    Some((_, Some(EntityType::Secret))) | Some((Some(Class::Secret), None))
                )
            {
                return Err(format!(
                    "rule {}: kind применим только к секретам (type: SECRET)",
                    r.id
                ));
            }
            // `type: SECRET` + kind selects a type+kind; plain `SECRET` is the class.
            let make_sel = |name_sel: (Option<Class>, Option<EntityType>),
                            kind: &Option<String>|
             -> (Option<Class>, Option<EntityType>) {
                if kind.is_some() && name_sel.0 == Some(Class::Secret) {
                    (None, Some(EntityType::Secret))
                } else {
                    name_sel
                }
            };
            if let Some(spec) = &r.ingress {
                match spec {
                    ActionSpec::One(a) => {
                        let (class, ty) = make_sel(when_sel.ok_or_else(|| format!("rule {}: для ingress в виде строки нужен when.class или when.type", r.id))?, &kind);
                        ingress.rules.push(IngressRule {
                            id: r.id.clone(),
                            class,
                            ty,
                            kind: kind.clone(),
                            route: r.when.route.clone(),
                            action: ingress_of(a).map_err(|e| format!("rule {}: {e}", r.id))?,
                        });
                    }
                    ActionSpec::Map(m) => {
                        for (name, a) in m {
                            let (class, ty) =
                                selector(name).map_err(|e| format!("rule {}: {e}", r.id))?;
                            ingress.rules.push(IngressRule {
                                id: r.id.clone(),
                                class,
                                ty,
                                kind: None,
                                route: r.when.route.clone(),
                                action: ingress_of(a).map_err(|e| format!("rule {}: {e}", r.id))?,
                            });
                        }
                    }
                }
            }
            if let Some(spec) = &r.restore {
                let sinks = r
                    .when
                    .sink
                    .iter()
                    .map(|s| sink_of(s).map_err(|e| format!("rule {}: {e}", r.id)))
                    .collect::<Result<Vec<_>, _>>()?;
                match spec {
                    ActionSpec::One(a) => {
                        let (class, ty) = make_sel(when_sel.ok_or_else(|| format!("rule {}: для restore в виде строки нужен when.class или when.type", r.id))?, &kind);
                        restore.rules.push(RestoreRule {
                            id: r.id.clone(),
                            sinks,
                            class,
                            ty,
                            kind: kind.clone(),
                            action: action_of(a).map_err(|e| format!("rule {}: {e}", r.id))?,
                        });
                    }
                    ActionSpec::Map(m) => {
                        for (name, a) in m {
                            let (class, ty) =
                                selector(name).map_err(|e| format!("rule {}: {e}", r.id))?;
                            restore.rules.push(RestoreRule {
                                id: r.id.clone(),
                                sinks: sinks.clone(),
                                class,
                                ty,
                                kind: None,
                                action: action_of(a).map_err(|e| format!("rule {}: {e}", r.id))?,
                            });
                        }
                    }
                }
            }
        }
        for (name, a) in &self.defaults.ingress {
            let class =
                class_of(name).ok_or_else(|| format!("defaults.ingress: класс «{name}»"))?;
            ingress.rules.push(IngressRule {
                id: "default".into(),
                class: Some(class),
                ty: None,
                kind: None,
                route: None,
                action: ingress_of(a).map_err(|e| format!("defaults.ingress: {e}"))?,
            });
        }
        for (k, v, want) in [
            ("attachments", &self.defaults.attachments, "drop_block"),
            ("embeddings", &self.defaults.embeddings, "block_request"),
            (
                "provider_server_tools",
                &self.defaults.provider_server_tools,
                "block_request",
            ),
        ] {
            if let Some(v) = v {
                if v != want {
                    return Err(format!("defaults.{k}: значение «{v}» пока не поддерживается, допустимо только «{want}»"));
                }
            }
        }

        let mut pseudo = PseudoConfig::default();
        if let Some(attrs) = &self.defaults.secret_attributes {
            for a in attrs {
                if !matches!(a.as_str(), "kind" | "has" | "len") {
                    return Err(format!("defaults.secret_attributes: «{a}»"));
                }
            }
            pseudo.secret_kind = attrs.iter().any(|a| a == "kind");
            pseudo.secret_has = attrs.iter().any(|a| a == "has");
            pseudo.secret_len = attrs.iter().any(|a| a == "len");
        }
        if !self.pseudonyms.roles.is_empty() {
            pseudo.roles = self.pseudonyms.roles.clone();
        }
        if !self.pseudonyms.envs.is_empty() {
            pseudo.envs = self.pseudonyms.envs.clone();
        }
        let mut response = crate::danger::ResponsePolicy::default();
        let act = |name: &str, v: &Option<String>, d: crate::danger::Act| match v {
            None => Ok(d),
            Some(s) => crate::danger::Act::parse(s)
                .ok_or_else(|| format!("response.{name}: «{s}», нужно off, warn или deny")),
        };
        response.tool_secrets = act(
            "tool_secrets",
            &self.response.tool_secrets,
            response.tool_secrets,
        )?;
        response.file_secrets = act(
            "file_secrets",
            &self.response.file_secrets,
            response.file_secrets,
        )?;
        response.dangerous = act(
            "dangerous_commands",
            &self.response.dangerous_commands,
            response.dangerous,
        )?;
        for p in &self.response.dangerous_patterns {
            response.extra.push(
                regex::RegexBuilder::new(p)
                    .size_limit(1 << 20)
                    .build()
                    .map_err(|e| format!("response.dangerous_patterns: «{p}»: {e}"))?,
            );
        }
        Ok(Compiled {
            tenant: self.tenant.clone(),
            detect,
            dict,
            custom,
            restore,
            ingress,
            trifecta,
            pseudo,
            response,
        })
    }

    /// CFG-03: every custom detector has examples, and they hold.
    pub fn check_examples(&self) -> Result<(), String> {
        for c in &self.detectors.custom {
            if c.examples.matches.is_empty() {
                return Err(format!(
                    "детектор {}: нет примеров (examples.matches), сборка остановлена",
                    c.id
                ));
            }
            let ty = EntityType::from_marker(&c.ty)
                .ok_or_else(|| format!("detector {}: тип «{}»", c.id, c.ty))?;
            let d = CustomDetector::new(&c.id, ty, &c.regex, c.group)?;
            let scan = |t: &str| {
                let mut out = vec![];
                d.scan(t, &mut out);
                out.len()
            };
            for m in &c.examples.matches {
                if scan(m) == 0 {
                    return Err(format!("детектор {}: пример «{m}» не обнаружен", c.id));
                }
            }
            for m in &c.examples.non_matches {
                if scan(m) != 0 {
                    return Err(format!("детектор {}: ложное срабатывание на «{m}»", c.id));
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Bundle
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VirtualKeyDoc {
    /// SHA-256 of the key, hex (IAM-03).
    pub sha256: String,
    pub principal: String,
    #[serde(default)]
    pub groups: Vec<String>,
    /// Optional expiry, `YYYY-MM-DDTHH:MM:SSZ`.
    #[serde(default)]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    pub version: String,
    pub created_at: String,
    pub expires_at: String,
    pub policy: PolicyDoc,
    #[serde(default)]
    pub virtual_keys: Vec<VirtualKeyDoc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub format: String,
    pub key_id: String,
    /// Base64 of the payload JSON bytes; the signature covers exactly these bytes.
    pub payload: String,
    pub signature: String,
}

#[derive(Debug)]
pub enum BundleError {
    Format(String),
    Signature,
    UnknownKey(String),
    Expired,
    Payload(String),
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BundleError::Format(m) => write!(f, "формат бандла: {m}"),
            BundleError::Signature => write!(f, "подпись бандла неверна"),
            BundleError::UnknownKey(k) => {
                write!(f, "ключ подписи {k} не входит в список доверенных")
            }
            BundleError::Expired => write!(f, "срок действия бандла истёк"),
            BundleError::Payload(m) => write!(f, "содержимое бандла: {m}"),
        }
    }
}

impl std::error::Error for BundleError {}

pub fn key_id(public: &[u8; 32]) -> String {
    public[..8].iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sign(payload: &Payload, key: &SigningKey) -> Result<Envelope, String> {
    let bytes = serde_json::to_vec(payload).map_err(|e| e.to_string())?;
    let sig = key.sign(&bytes);
    let b64 = base64::engine::general_purpose::STANDARD;
    Ok(Envelope {
        format: FORMAT.into(),
        key_id: key_id(&key.verifying_key().to_bytes()),
        payload: b64.encode(&bytes),
        signature: b64.encode(sig.to_bytes()),
    })
}

/// Verify signature against trusted keys, then parse. Expiry is checked separately by
/// [`Payload::is_expired`] so that callers can report both conditions.
pub fn verify(envelope_json: &[u8], trusted: &[VerifyingKey]) -> Result<Payload, BundleError> {
    let env: Envelope =
        serde_json::from_slice(envelope_json).map_err(|e| BundleError::Format(e.to_string()))?;
    if env.format != FORMAT {
        return Err(BundleError::Format(format!(
            "неизвестный формат «{}»",
            env.format
        )));
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let payload = b64
        .decode(&env.payload)
        .map_err(|e| BundleError::Format(e.to_string()))?;
    let sig_bytes: [u8; 64] = b64
        .decode(&env.signature)
        .map_err(|e| BundleError::Format(e.to_string()))?
        .try_into()
        .map_err(|_| BundleError::Signature)?;
    let sig = Signature::from_bytes(&sig_bytes);
    let key = trusted
        .iter()
        .find(|k| key_id(&k.to_bytes()) == env.key_id)
        .ok_or_else(|| BundleError::UnknownKey(env.key_id.clone()))?;
    key.verify(&payload, &sig)
        .map_err(|_| BundleError::Signature)?;
    serde_json::from_slice(&payload).map_err(|e| BundleError::Payload(e.to_string()))
}

/// `YYYY-MM-DDTHH:MM:SSZ` → Unix seconds.
pub fn parse_utc(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || !s.ends_with('Z')
    {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, m, d, hh, mm, ss) = (
        n(0..4)?,
        n(5..7)?,
        n(8..10)?,
        n(11..13)?,
        n(14..16)?,
        n(17..19)?,
    );
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // days-from-civil (Howard Hinnant)
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}

impl Payload {
    pub fn is_expired(&self, now_unix: i64) -> bool {
        parse_utc(&self.expires_at).is_none_or(|e| e <= now_unix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"
version: 1
tenant: acme
zones:
  internal: [corp.local, company.ru]
  company_ranges: ["10.50.0.0/16"]
detectors:
  service_account_patterns: ['\bacme_[a-z]+_svc\b']
  custom:
    - id: acme-ticket-token
      type: SECRET
      regex: 'ACME-TKN-([A-Z0-9]{12})'
      group: 1
      examples:
        matches: ["token ACME-TKN-AB12CD34EF56"]
        non_matches: ["ACME-TKN-short"]
dictionary:
  employees:
    - { first: Иван, last: Петров }
  terms:
    - { form: InternalPaymentSystem, type: SYSTEM }
trifecta:
  mode: enforce
  allow_destinations: ["docs.python.org"]
defaults:
  ingress: { SECRET: mask, INFRA: mask, PII: mask, CORP: mask }
  attachments: drop_block
  secret_attributes: [kind, has]
rules:
  - id: R-010
    when: { route: local-vllm }
    ingress: { INFRA: allow, PII: allow, CORP: allow }
  - id: R-020
    when: { type: SECRET, kind: pem }
    ingress: block_request
  - id: R-112
    when: { sink: [shell_network, network] }
    restore: { SECRET: deny, PII: deny, INFRA: internal_only }
"#;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn payload() -> Payload {
        Payload {
            version: "2026.10.07-1".into(),
            created_at: "2026-10-07T00:00:00Z".into(),
            expires_at: "2027-01-05T00:00:00Z".into(),
            policy: PolicyDoc::from_yaml(POLICY).unwrap(),
            virtual_keys: vec![],
        }
    }

    // REQ: POL-01 — the example policy of the spec is valid and compiles.
    #[test]
    fn example_policy_compiles() {
        let c = PolicyDoc::from_yaml(POLICY).unwrap().compile().unwrap();
        assert_eq!(c.tenant, "acme");
        assert_eq!(c.detect.company_ranges.len(), 1);
        assert_eq!(c.custom.len(), 1);
        assert_eq!(c.trifecta.allow_destinations, vec!["docs.python.org"]);
        assert!(c
            .restore
            .rules
            .iter()
            .any(|r| r.id == "R-112" && r.action == Action::InternalOnly));
        assert!(c.ingress.rules.iter().any(|r| r.id == "R-020"
            && r.kind.as_deref() == Some("pem")
            && r.ty == Some(EntityType::Secret)));
        assert!(c
            .ingress
            .rules
            .iter()
            .any(|r| r.id == "R-010" && r.route.as_deref() == Some("local-vllm")));
    }

    // REQ: RSP-10, RSP-06 — the policy sets the action for the model's own secrets and commands.
    #[test]
    fn response_section_compiles_with_defaults() {
        use crate::danger::Act;
        let d = PolicyDoc::from_yaml("version: 1")
            .unwrap()
            .compile()
            .unwrap()
            .response;
        assert_eq!(
            (d.tool_secrets, d.file_secrets, d.dangerous),
            (Act::Deny, Act::Warn, Act::Warn)
        );
        let y = "version: 1\nresponse:\n  tool_secrets: warn\n  file_secrets: deny\n  dangerous_commands: deny\n  dangerous_patterns: ['terraform\\s+destroy']\n";
        let r = PolicyDoc::from_yaml(y).unwrap().compile().unwrap().response;
        assert_eq!(
            (r.tool_secrets, r.file_secrets, r.dangerous),
            (Act::Warn, Act::Deny, Act::Deny)
        );
        assert_eq!(r.extra.len(), 1);
    }

    // REQ: POL-01 — strict schema: unknown fields and bad values are errors, never ignored.
    #[test]
    fn schema_is_strict() {
        for (bad, why) in [
            ("version: 1\nunknown_key: 1", "unknown field"),
            ("version: 2", "version"),
            ("version: 1\nrules:\n  - id: x\n    when: { type: HOST }\n    ingress: explode", "action"),
            ("version: 1\nrules:\n  - id: x\n    ingress: mask", "needs selector"),
            ("version: 1\nrules:\n  - id: x\n    when: { class: INFRA, type: HOST }\n    ingress: mask", "both"),
            ("version: 1\nrules:\n  - id: x\n    when: { type: HOST, kind: pem }\n    ingress: mask", "kind on non-secret"),
            ("version: 1\nzones: { company_ranges: ['10.0.0.0/99'] }", "cidr"),
            ("version: 1\ndefaults: { attachments: allow }", "unsupported value"),
            ("version: 1\ndefaults: { secret_attributes: [value] }", "attribute"),
            ("version: 1\ntrifecta: { mode: maybe }", "mode"),
            ("version: 1\nresponse: { tool_secrets: sometimes }", "tool_secrets"),
            ("version: 1\nresponse: { dangerous_patterns: ['('] }", "dangerous_patterns"),
            ("version: 1\nrules:\n  - id: x\n    when: { sink: [moon] }\n    restore: { SECRET: deny }", "sink"),
        ] {
            let r = PolicyDoc::from_yaml(bad).and_then(|d| d.compile().map(|_| ()));
            assert!(r.is_err(), "{why}: {bad}");
        }
    }

    // REQ: CFG-03 — custom detectors need examples that hold.
    #[test]
    fn custom_detector_examples_are_enforced() {
        PolicyDoc::from_yaml(POLICY)
            .unwrap()
            .check_examples()
            .unwrap();
        let mut p = PolicyDoc::from_yaml(POLICY).unwrap();
        p.detectors.custom[0].examples.matches.clear();
        assert!(p.check_examples().unwrap_err().contains("нет примеров"));
        let mut p = PolicyDoc::from_yaml(POLICY).unwrap();
        p.detectors.custom[0].examples.matches = vec!["nothing here".into()];
        assert!(p.check_examples().unwrap_err().contains("не обнаружен"));
        let mut p = PolicyDoc::from_yaml(POLICY).unwrap();
        p.detectors.custom[0].examples.non_matches = vec!["ACME-TKN-AB12CD34EF56".into()];
        assert!(p
            .check_examples()
            .unwrap_err()
            .contains("ложное срабатывание"));
    }

    // REQ: SEC-11 — an invalid or oversized regex is refused at compile time.
    #[test]
    fn bad_regexes_are_refused() {
        let mut p = PolicyDoc::from_yaml(POLICY).unwrap();
        p.detectors.custom[0].regex = "(unclosed".into();
        assert!(p.compile().is_err());
        p.detectors.custom[0].regex = "(a{1000}){1000}".into();
        assert!(p.compile().is_err(), "size limit");
        p.detectors.custom[0].regex = "x".into();
        p.detectors.custom[0].group = 3;
        assert!(p.compile().is_err(), "missing group");
    }

    // REQ: CFG-01, CFG-04
    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let k = key(7);
        let env = sign(&payload(), &k).unwrap();
        let bytes = serde_json::to_vec(&env).unwrap();
        let p = verify(&bytes, &[k.verifying_key()]).unwrap();
        assert_eq!(p.version, "2026.10.07-1");

        // wrong key
        let other = key(8).verifying_key();
        assert!(matches!(
            verify(&bytes, &[other]),
            Err(BundleError::UnknownKey(_))
        ));
        // tampered payload
        let mut t = env.clone();
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut raw = b64.decode(&t.payload).unwrap();
        let pos = raw.windows(7).position(|w| w == b"enforce").unwrap();
        raw[pos..pos + 7].copy_from_slice(b"monitor");
        t.payload = b64.encode(raw);
        assert!(matches!(
            verify(&serde_json::to_vec(&t).unwrap(), &[k.verifying_key()]),
            Err(BundleError::Signature)
        ));
        // forged signature from another key with the same key_id claim
        let forged = sign(&payload(), &key(9)).unwrap();
        let mut f = forged.clone();
        f.key_id = env.key_id.clone();
        assert!(matches!(
            verify(&serde_json::to_vec(&f).unwrap(), &[k.verifying_key()]),
            Err(BundleError::Signature)
        ));
        // garbage
        assert!(matches!(
            verify(b"nope", &[k.verifying_key()]),
            Err(BundleError::Format(_))
        ));
        let mut wrong = env;
        wrong.format = "x".into();
        assert!(matches!(
            verify(&serde_json::to_vec(&wrong).unwrap(), &[k.verifying_key()]),
            Err(BundleError::Format(_))
        ));
    }

    // REQ: CFG-04
    #[test]
    fn expiry() {
        let p = payload();
        let now = parse_utc("2026-10-07T12:00:00Z").unwrap();
        assert!(!p.is_expired(now));
        assert!(p.is_expired(parse_utc("2027-01-05T00:00:00Z").unwrap()));
        assert!(p.is_expired(parse_utc("2030-01-01T00:00:00Z").unwrap()));
        let mut bad = payload();
        bad.expires_at = "tomorrow".into();
        assert!(
            bad.is_expired(now),
            "an unparseable expiry counts as expired"
        );
    }

    #[test]
    fn parse_utc_known_values() {
        assert_eq!(parse_utc("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_utc("2026-10-07T10:23:15Z"), Some(1_791_368_595));
        assert_eq!(parse_utc("2000-02-29T00:00:00Z"), Some(951_782_400));
        assert_eq!(parse_utc("2026-13-01T00:00:00Z"), None);
        assert_eq!(parse_utc("2026-10-07 10:23:15"), None);
    }
}

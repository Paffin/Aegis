//! REQ: CFG-05, NFR-09, IAM-03, DET-06 — runtime configuration.
//!
//! Secrets (`K_t`, `K_audit`, provider key) come from the environment or files, never from
//! the config file. The signed bundle format (CFG-01) replaces this file later.

use crate::engine::Engine;
use crate::server::{AppState, Principal, Upstream};
use aegis_core::crypto::TenantKeys;
use aegis_core::detect::{DetectConfig, Dictionary};
use aegis_core::types::EntityType;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "d_listen")]
    pub listen: String,
    #[serde(default = "d_admin")]
    pub admin_listen: String,
    pub upstream_base_url: String,
    /// OpenAI-compatible provider; the key comes from `AEGIS_OPENAI_KEY`.
    #[serde(default)]
    pub openai_base_url: Option<String>,
    #[serde(default = "d_tenant")]
    pub tenant: String,
    #[serde(default)]
    pub internal_zones: Vec<String>,
    /// CIDR strings such as `10.50.0.0/16`.
    #[serde(default)]
    pub company_ranges: Vec<String>,
    #[serde(default)]
    pub service_account_patterns: Vec<String>,
    #[serde(default)]
    pub employees: Vec<Employee>,
    #[serde(default)]
    pub terms: Vec<Term>,
    #[serde(default)]
    pub virtual_keys: Vec<VirtualKey>,
    /// Signed policy bundle (CFG-01). When set, policy, dictionaries and virtual keys come from it.
    #[serde(default)]
    pub bundle: Option<BundleConf>,
    /// JSONL audit file; stdout when absent (AUD-04).
    #[serde(default)]
    pub audit_path: Option<String>,
    /// With `true` an overflowing audit queue stops traffic instead of dropping events.
    #[serde(default)]
    pub audit_required: bool,
    #[serde(default = "d_queue")]
    pub audit_queue: usize,
}

#[derive(Debug, Deserialize)]
pub struct BundleConf {
    /// File path or http(s) URL.
    pub source: String,
    /// Local copy of the last valid bundle (CFG-06).
    #[serde(default)]
    pub cache_path: Option<String>,
    /// Hex ed25519 public keys that may sign bundles.
    pub trusted_keys: Vec<String>,
    /// Poll interval; at most 30 seconds so that a new version is applied in time (CFG-02).
    #[serde(default = "d_reload")]
    pub reload_seconds: u64,
}

fn d_reload() -> u64 {
    15
}

fn d_queue() -> usize {
    10_000
}

#[derive(Debug, Deserialize)]
pub struct Employee {
    pub first: String,
    pub last: String,
}

#[derive(Debug, Deserialize)]
pub struct Term {
    pub form: String,
    /// `PROJECT`, `SYSTEM` or `ORG`.
    #[serde(rename = "type")]
    pub ty: String,
}

#[derive(Debug, Deserialize)]
pub struct VirtualKey {
    /// SHA-256 of the key, hex (IAM-03).
    pub sha256: String,
    pub principal: String,
    #[serde(default)]
    pub groups: Vec<String>,
}

fn d_listen() -> String {
    "127.0.0.1:8080".into()
}
fn d_admin() -> String {
    "127.0.0.1:9090".into()
}
fn d_tenant() -> String {
    "default".into()
}

#[derive(Debug)]
pub enum ConfigError {
    Missing(&'static str),
    Invalid(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Missing(v) => write!(f, "missing secret: {v}"),
            ConfigError::Invalid(m) => write!(f, "invalid config: {m}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Read a secret from `NAME` or from the file named by `NAME_FILE`.
pub fn secret(name: &'static str) -> Result<Vec<u8>, ConfigError> {
    if let Ok(path) = std::env::var(format!("{name}_FILE")) {
        let s = std::fs::read(&path).map_err(|_| ConfigError::Missing(name))?;
        return Ok(trim(s));
    }
    std::env::var(name)
        .map(|v| v.into_bytes())
        .map_err(|_| ConfigError::Missing(name))
}

fn trim(mut v: Vec<u8>) -> Vec<u8> {
    while v.last().is_some_and(|b| b.is_ascii_whitespace()) {
        v.pop();
    }
    v
}

pub fn parse_cidr(s: &str) -> Option<(u32, u8)> {
    let (a, l) = s.split_once('/')?;
    let len: u8 = l.parse().ok()?;
    (len <= 32).then_some(())?;
    Some((aegis_core::detect::parse_ipv4(a)?, len))
}

impl ServerConfig {
    pub fn build_audit(&self) -> Result<crate::audit::Audit, ConfigError> {
        use crate::audit::Audit;
        Ok(match &self.audit_path {
            Some(p) => {
                let f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)
                    .map_err(|e| ConfigError::Invalid(format!("audit file {p}: {e}")))?;
                Audit::to_writer(f, self.audit_queue, self.audit_required)
            }
            None => Audit::to_writer(std::io::stdout(), self.audit_queue, self.audit_required),
        })
    }

    pub fn build(
        &self,
        k_t: &[u8],
        k_audit: &[u8],
        provider_key: String,
        openai_key: Option<String>,
    ) -> Result<AppState, ConfigError> {
        // Short keys make pseudonyms guessable; refuse them (SEC-03).
        if k_t.len() < 16 || k_audit.len() < 16 {
            return Err(ConfigError::Invalid(
                "K_t and K_audit must be at least 16 bytes".into(),
            ));
        }
        let mut detect = DetectConfig {
            internal_zones: self.internal_zones.clone(),
            ..Default::default()
        };
        for r in &self.company_ranges {
            detect
                .company_ranges
                .push(parse_cidr(r).ok_or_else(|| ConfigError::Invalid(format!("bad CIDR {r}")))?);
        }
        detect
            .service_account_patterns
            .extend(self.service_account_patterns.iter().cloned());
        for p in &detect.service_account_patterns {
            regex::Regex::new(p)
                .map_err(|e| ConfigError::Invalid(format!("service account pattern: {e}")))?;
        }
        let mut dict = Dictionary::default();
        for e in &self.employees {
            dict.add_person(&e.first, &e.last);
        }
        for t in &self.terms {
            let ty = match t.ty.as_str() {
                "PROJECT" => EntityType::Project,
                "SYSTEM" => EntityType::System,
                "ORG" => EntityType::Org,
                other => return Err(ConfigError::Invalid(format!("unknown term type {other}"))),
            };
            dict.add_term(&t.form, ty);
        }
        if let Some(b) = &self.bundle {
            if b.trusted_keys.is_empty() {
                return Err(ConfigError::Invalid(
                    "bundle.trusted_keys must not be empty".into(),
                ));
            }
            if !(1..=30).contains(&b.reload_seconds) {
                return Err(ConfigError::Invalid(
                    "bundle.reload_seconds must be 1..=30".into(),
                ));
            }
            crate::bundle_loader::parse_trusted(&b.trusted_keys).map_err(ConfigError::Invalid)?;
        }
        let keys = TenantKeys::from_secrets(&self.tenant, k_t, k_audit);
        let engine = Engine::new(keys, detect, dict);
        let vk: HashMap<String, Principal> = self
            .virtual_keys
            .iter()
            .map(|k| {
                (
                    k.sha256.to_ascii_lowercase(),
                    Principal {
                        id: k.principal.clone(),
                        groups: k.groups.clone(),
                    },
                )
            })
            .collect();
        let openai = match (&self.openai_base_url, openai_key) {
            (Some(url), Some(k)) => Some(Upstream {
                base_url: url.clone(),
                api_key: k,
            }),
            (Some(_), None) => return Err(ConfigError::Missing("AEGIS_OPENAI_KEY")),
            (None, _) => None,
        };
        let mut st = AppState::new(
            engine,
            Upstream {
                base_url: self.upstream_base_url.clone(),
                api_key: provider_key,
            },
            vk,
        );
        st.openai = openai;
        st.bundle_required = self.bundle.is_some();
        Ok(st)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = r#"{
        "upstream_base_url": "https://api.anthropic.com",
        "internal_zones": ["corp.local"],
        "company_ranges": ["10.50.0.0/16"],
        "employees": [{"first": "Иван", "last": "Петров"}],
        "terms": [{"form": "InternalPaymentSystem", "type": "SYSTEM"}],
        "virtual_keys": [{"sha256": "AB12", "principal": "u:ivanov"}]
    }"#;

    #[test]
    fn parses_and_builds() {
        let c: ServerConfig = serde_json::from_str(CFG).unwrap();
        assert_eq!(c.listen, "127.0.0.1:8080");
        let st = c.build(&[1; 32], &[2; 32], "pk".into(), None).unwrap();
        assert!(
            st.keys.load().contains_key("ab12"),
            "hashes are matched case-insensitively"
        );
    }

    // REQ: SEC-03, NFR-09 — weak or missing keys stop the process.
    #[test]
    fn rejects_short_keys_and_bad_values() {
        let c: ServerConfig = serde_json::from_str(CFG).unwrap();
        assert!(c.build(b"short", &[2; 32], "pk".into(), None).is_err());
        let bad: ServerConfig =
            serde_json::from_str(&CFG.replace("10.50.0.0/16", "10.50.0.0/99")).unwrap();
        assert!(bad.build(&[1; 32], &[2; 32], "pk".into(), None).is_err());
        let bad: ServerConfig = serde_json::from_str(&CFG.replace("SYSTEM", "NOPE")).unwrap();
        assert!(bad.build(&[1; 32], &[2; 32], "pk".into(), None).is_err());
    }

    // REQ: CFG-02 — a bundle configuration is validated before start.
    #[test]
    fn bundle_section_is_validated() {
        let with = |extra: &str| -> ServerConfig {
            serde_json::from_str(
                &CFG.replace("\"virtual_keys\"", &format!("{extra} \"virtual_keys\"")),
            )
            .unwrap()
        };
        let hex = "00".repeat(32);
        let ok = with(&format!(
            "\"bundle\": {{\"source\": \"/etc/aegis/bundle.json\", \"trusted_keys\": [\"{}\"]}},",
            ValidKey::hex()
        ));
        let _ = &hex;
        let st = ok.build(&[1; 32], &[2; 32], "pk".into(), None).unwrap();
        assert!(
            st.bundle_required,
            "a configured bundle makes its absence fail-closed"
        );
        assert!(
            with("\"bundle\": {\"source\": \"x\", \"trusted_keys\": []},")
                .build(&[1; 32], &[2; 32], "pk".into(), None)
                .is_err()
        );
        assert!(with(&format!("\"bundle\": {{\"source\": \"x\", \"trusted_keys\": [\"{}\"], \"reload_seconds\": 60}},", ValidKey::hex())).build(&[1; 32], &[2; 32], "pk".into(), None).is_err(), "reload slower than 30 s");
        assert!(
            with("\"bundle\": {\"source\": \"x\", \"trusted_keys\": [\"nothex\"]},")
                .build(&[1; 32], &[2; 32], "pk".into(), None)
                .is_err()
        );
    }

    struct ValidKey;
    impl ValidKey {
        fn hex() -> String {
            ed25519_dalek::SigningKey::from_bytes(&[5; 32])
                .verifying_key()
                .to_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        }
    }

    #[test]
    fn cidr() {
        assert_eq!(parse_cidr("10.50.0.0/16"), Some((0x0A32_0000, 16)));
        assert_eq!(parse_cidr("10.50.0.0"), None);
    }
}

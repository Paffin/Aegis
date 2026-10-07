//! REQ: CFG-05, NFR-09, IAM-03, DET-06 — runtime configuration.
//!
//! Secrets (`K_t`, `K_audit`, provider key) come from the environment or files, never from
//! the config file. The signed bundle format (CFG-01) replaces this file later.

use crate::engine::Engine;
use crate::server::{AppState, Auth, Principal, Upstream};
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
    /// Anthropic Messages provider (also DeepSeek, Kimi, GLM, MiniMax, Qwen through their
    /// Anthropic-compatible endpoints). Key: `AEGIS_ANTHROPIC_KEY`.
    #[serde(default, alias = "upstream_base_url")]
    pub anthropic_base_url: Option<String>,
    /// `x-api-key` (default) or `bearer`.
    #[serde(default)]
    pub anthropic_auth: Option<String>,
    /// OpenAI-compatible provider: OpenAI, Azure OpenAI (`/openai`), DeepSeek, Qwen
    /// (`/compatible-mode`), Kimi, GLM, vLLM, Ollama. Key: `AEGIS_OPENAI_KEY`.
    #[serde(default)]
    pub openai_base_url: Option<String>,
    /// Path below the base URL before `/chat/completions`: `/v1` (default), `/v4` for Zhipu
    /// (`https://open.bigmodel.cn/api/paas`), `/api/v3` for Volcengine, empty for DeepSeek.
    #[serde(default)]
    pub openai_api_prefix: Option<String>,
    /// `bearer` (default), `api-key` (Azure) or `none` (local models).
    #[serde(default)]
    pub openai_auth: Option<String>,
    /// Google Gemini API. Key: `AEGIS_GEMINI_KEY`.
    #[serde(default)]
    pub gemini_base_url: Option<String>,
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
    /// Model aliases (RTE-02): the client asks for `claude-default`, the provider gets the real name.
    #[serde(default)]
    pub model_aliases: std::collections::BTreeMap<String, String>,
    /// RTE-01: static routes by model name and group; see [`RouteConfig`].
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    /// SEC-05: serve TLS (1.2+) on `listen`; with `client_ca_file` clients need a certificate (mTLS).
    #[serde(default)]
    pub tls: Option<crate::tls::TlsFiles>,
    /// SEC-05: the providers' certificates must chain to this CA (PEM) and no public one.
    #[serde(default)]
    pub upstream_ca_file: Option<String>,
    /// OBS-03: OTLP/HTTP collector (`http://collector:4318`); traces by stage without bodies.
    /// Headers for it (an `Authorization`): `AEGIS_OTLP_HEADERS="k=v,k2=v2"`.
    #[serde(default)]
    pub otlp_endpoint: Option<String>,
    /// DET-03: memory for the detection cache, in megabytes.
    #[serde(default = "d_cache_mb")]
    pub detect_cache_mb: usize,
    /// DET-09: milliseconds one block may be scanned; a block that takes longer is dropped.
    #[serde(default = "d_budget_ms")]
    pub detect_budget_ms: u64,
    /// Requests in flight; more are refused with 503 and `Retry-After`.
    #[serde(default = "d_max_in_flight")]
    pub max_concurrent_requests: usize,
    /// Seconds to connect to a provider.
    #[serde(default = "d_connect")]
    pub upstream_connect_timeout_secs: u64,
    /// Seconds a provider may stay silent (before the answer or between chunks of a stream).
    #[serde(default = "d_read")]
    pub upstream_read_timeout_secs: u64,
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

fn d_cache_mb() -> usize {
    1024
}
fn d_budget_ms() -> u64 {
    2000
}
fn d_max_in_flight() -> usize {
    crate::server::DEFAULT_MAX_IN_FLIGHT
}
fn d_connect() -> u64 {
    10
}
fn d_read() -> u64 {
    300
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

/// A route (RTE-01): which provider serves which models, for whom, under which name the policy
/// knows it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// The name rules of the policy use in `route:`.
    pub name: String,
    /// `anthropic`, `openai` or `gemini`: the protocol family the provider speaks.
    pub protocol: String,
    pub base_url: String,
    #[serde(default)]
    pub api_prefix: Option<String>,
    /// `x-api-key`, `bearer`, `api-key`, `x-goog-api-key` or `none`; the family's default if absent.
    #[serde(default)]
    pub auth: Option<String>,
    /// Name of the environment variable that holds the provider key (`NAME_FILE` works too).
    /// Not needed with `auth: none`.
    #[serde(default)]
    pub key_env: Option<String>,
    /// Model names the client may ask for; `*` is a wildcard. Empty: any model.
    #[serde(default)]
    pub models: Vec<String>,
    /// Groups of virtual keys the route is for. Empty: everyone.
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

/// Provider credentials; they stay inside the gateway (IAM-02).
#[derive(Default)]
pub struct ProviderKeys {
    pub anthropic: Option<String>,
    pub openai: Option<String>,
    pub gemini: Option<String>,
}

impl ProviderKeys {
    pub fn anthropic(key: &str) -> Self {
        Self {
            anthropic: Some(key.into()),
            ..Default::default()
        }
    }

    /// From `AEGIS_ANTHROPIC_KEY` (or the older `AEGIS_PROVIDER_KEY`), `AEGIS_OPENAI_KEY`,
    /// `AEGIS_GEMINI_KEY`; every one is optional here and required by its provider section.
    pub fn from_env() -> Self {
        let get = |n: &'static str| {
            secret(n)
                .ok()
                .and_then(|k| String::from_utf8(k).ok())
                .filter(|k| !k.is_empty())
        };
        Self {
            anthropic: get("AEGIS_ANTHROPIC_KEY").or_else(|| get("AEGIS_PROVIDER_KEY")),
            openai: get("AEGIS_OPENAI_KEY"),
            gemini: get("AEGIS_GEMINI_KEY"),
        }
    }
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
    secret_named(name).map_err(|_| ConfigError::Missing(name))
}

/// [`secret`] for a name that comes from the configuration.
fn secret_named(name: &str) -> Result<Vec<u8>, ()> {
    if let Ok(path) = std::env::var(format!("{name}_FILE")) {
        let s = std::fs::read(&path).map_err(|_| ())?;
        return Ok(trim(s));
    }
    std::env::var(name).map(|v| v.into_bytes()).map_err(|_| ())
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

    fn build_routes(&self) -> Result<Vec<crate::server::Route>, ConfigError> {
        use crate::server::{Family, Route};
        let bad = |name: &str, why: &str| ConfigError::Invalid(format!("route {name}: {why}"));
        let mut names = std::collections::HashSet::new();
        let mut out = vec![];
        for r in &self.routes {
            if r.name.is_empty()
                || !r
                    .name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            {
                return Err(bad(&r.name, "name: letters, digits, - _ . only"));
            }
            if !names.insert(r.name.clone()) {
                return Err(bad(&r.name, "the name is used twice"));
            }
            let family = Family::parse(&r.protocol)
                .ok_or_else(|| bad(&r.name, "protocol must be anthropic, openai or gemini"))?;
            let default_auth = match family {
                Family::Anthropic => Auth::XApiKey,
                Family::OpenAi => Auth::Bearer,
                Family::Gemini => Auth::GoogApiKey,
            };
            let auth = match &r.auth {
                None => default_auth,
                Some(a) => Auth::parse(a).ok_or_else(|| bad(&r.name, "unknown auth mode"))?,
            };
            let key = match (&r.key_env, auth) {
                (_, Auth::Nothing) => String::new(),
                (None, _) => {
                    return Err(bad(
                        &r.name,
                        "key_env: name the variable with the provider key",
                    ))
                }
                (Some(n), _) => secret_named(n)
                    .ok()
                    .and_then(|k| String::from_utf8(k).ok())
                    .filter(|k| !k.is_empty())
                    .ok_or_else(|| bad(&r.name, &format!("the secret {n} is not set")))?,
            };
            if r.base_url.is_empty() {
                return Err(bad(&r.name, "base_url"));
            }
            let mut up = Upstream {
                base_url: r.base_url.clone(),
                api_key: key,
                auth,
                api_prefix: if family == Family::Gemini {
                    String::new()
                } else {
                    "/v1".into()
                },
            };
            if let Some(p) = &r.api_prefix {
                up = up.with_prefix(p);
            }
            out.push(Route {
                name: r.name.clone(),
                family,
                models: r.models.clone(),
                groups: r.groups.clone(),
                upstream: up,
            });
        }
        Ok(out)
    }

    pub fn build(
        &self,
        k_t: &[u8],
        k_audit: &[u8],
        provider_keys: ProviderKeys,
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
        if self.detect_cache_mb == 0 || self.detect_budget_ms == 0 {
            return Err(ConfigError::Invalid(
                "detect_cache_mb and detect_budget_ms must be at least 1".into(),
            ));
        }
        let engine = Engine::new(keys, detect, dict).with_limits(
            self.detect_cache_mb.saturating_mul(1 << 20),
            std::time::Duration::from_millis(self.detect_budget_ms),
        );
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
        let provider = |base: &Option<String>,
                        auth: &Option<String>,
                        default: Auth,
                        key: Option<String>,
                        key_name: &'static str|
         -> Result<Option<Upstream>, ConfigError> {
            let Some(url) = base else { return Ok(None) };
            let auth = match auth {
                None => default,
                Some(a) => Auth::parse(a)
                    .ok_or_else(|| ConfigError::Invalid(format!("unknown auth mode {a}")))?,
            };
            let key = match (auth, key) {
                (Auth::Nothing, k) => k.unwrap_or_default(),
                (_, Some(k)) => k,
                (_, None) => return Err(ConfigError::Missing(key_name)),
            };
            Ok(Some(Upstream {
                base_url: url.clone(),
                api_key: key,
                auth,
                api_prefix: "/v1".into(),
            }))
        };
        let anthropic = provider(
            &self.anthropic_base_url,
            &self.anthropic_auth,
            Auth::XApiKey,
            provider_keys.anthropic,
            "AEGIS_ANTHROPIC_KEY",
        )?;
        let mut openai = provider(
            &self.openai_base_url,
            &self.openai_auth,
            Auth::Bearer,
            provider_keys.openai,
            "AEGIS_OPENAI_KEY",
        )?;
        if let Some(p) = &self.openai_api_prefix {
            openai = openai.map(|o| o.with_prefix(p));
        }
        let gemini = provider(
            &self.gemini_base_url,
            &None,
            Auth::GoogApiKey,
            provider_keys.gemini,
            "AEGIS_GEMINI_KEY",
        )?
        .map(|mut u| {
            u.api_prefix.clear();
            u
        });
        let routes = self.build_routes()?;
        if anthropic.is_none() && openai.is_none() && gemini.is_none() && routes.is_empty() {
            return Err(ConfigError::Invalid(
                "no provider: set anthropic_base_url, openai_base_url, gemini_base_url or routes"
                    .into(),
            ));
        }
        let mut st = AppState::new(engine, anthropic, vk);
        st.openai = openai;
        st.gemini = gemini;
        st.routes = routes;
        st.bundle_required = self.bundle.is_some();
        if self
            .model_aliases
            .iter()
            .any(|(a, m)| a.is_empty() || m.is_empty())
        {
            return Err(ConfigError::Invalid(
                "model_aliases: names must not be empty".into(),
            ));
        }
        st.model_aliases = self.model_aliases.clone();
        if self.max_concurrent_requests == 0 {
            return Err(ConfigError::Invalid(
                "max_concurrent_requests must be at least 1".into(),
            ));
        }
        st.limiter = std::sync::Arc::new(tokio::sync::Semaphore::new(self.max_concurrent_requests));
        let (connect, read) = (
            std::time::Duration::from_secs(self.upstream_connect_timeout_secs.max(1)),
            std::time::Duration::from_secs(self.upstream_read_timeout_secs.max(1)),
        );
        st.http = match &self.upstream_ca_file {
            Some(p) => {
                let pem = std::fs::read(p)
                    .map_err(|e| ConfigError::Invalid(format!("upstream_ca_file {p}: {e}")))?;
                crate::server::client_with_ca(connect, read, &pem)
                    .map_err(|e| ConfigError::Invalid(format!("upstream_ca_file {p}: {e}")))?
            }
            None => crate::server::client_with(connect, read),
        };
        if let Some(t) = &self.tls {
            crate::tls::server_config(t).map_err(|e| ConfigError::Invalid(format!("tls: {e}")))?;
        }
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
        let st = c
            .build(&[1; 32], &[2; 32], ProviderKeys::anthropic("pk"))
            .unwrap();
        assert!(
            st.keys.load().contains_key("ab12"),
            "hashes are matched case-insensitively"
        );
    }

    // REQ: NFR-13
    #[test]
    fn limits_have_defaults_and_are_validated() {
        let c: ServerConfig = serde_json::from_str(CFG).unwrap();
        assert_eq!(c.max_concurrent_requests, 1000);
        assert_eq!(
            (
                c.upstream_connect_timeout_secs,
                c.upstream_read_timeout_secs
            ),
            (10, 300)
        );
        let bad: ServerConfig = serde_json::from_str(&CFG.replace(
            "\"virtual_keys\"",
            "\"max_concurrent_requests\": 0, \"virtual_keys\"",
        ))
        .unwrap();
        assert!(bad
            .build(&[1; 32], &[2; 32], ProviderKeys::anthropic("pk"))
            .is_err());
    }

    // REQ: RTE-01 — routes are read, checked and given their own credentials.
    #[test]
    fn routes_are_validated() {
        std::env::set_var("AEGIS_TEST_ROUTE_KEY", "route-key");
        let build = |json: &str| {
            serde_json::from_str::<ServerConfig>(json).unwrap().build(
                &[1; 32],
                &[2; 32],
                ProviderKeys::default(),
            )
        };
        let ok = r#"{"routes": [
            {"name": "local", "protocol": "openai", "base_url": "http://vllm", "auth": "none", "models": ["qwen*"]},
            {"name": "deepseek", "protocol": "openai", "base_url": "https://api.deepseek.com", "api_prefix": "", "key_env": "AEGIS_TEST_ROUTE_KEY", "groups": ["devs"]}]}"#;
        let st = build(ok).unwrap();
        assert_eq!(st.routes.len(), 2);
        assert_eq!(st.routes[1].upstream.api_key, "route-key");
        assert_eq!(st.routes[1].upstream.api_prefix, "");
        for (bad, why) in [
            (
                r#"{"routes": [{"name": "a b", "protocol": "openai", "base_url": "http://x", "auth": "none"}]}"#,
                "name",
            ),
            (
                r#"{"routes": [{"name": "a", "protocol": "grpc", "base_url": "http://x", "auth": "none"}]}"#,
                "protocol",
            ),
            (
                r#"{"routes": [{"name": "a", "protocol": "openai", "base_url": "http://x"}]}"#,
                "key_env",
            ),
            (
                r#"{"routes": [{"name": "a", "protocol": "openai", "base_url": "http://x", "key_env": "AEGIS_TEST_NOT_SET"}]}"#,
                "not set",
            ),
            (
                r#"{"routes": [{"name": "a", "protocol": "openai", "base_url": "http://x", "auth": "none"}, {"name": "a", "protocol": "openai", "base_url": "http://y", "auth": "none"}]}"#,
                "twice",
            ),
            (
                r#"{"routes": [{"name": "a", "protocol": "openai", "base_url": "http://x", "auth": "none", "extra": 1}]}"#,
                "extra",
            ),
        ] {
            let r = serde_json::from_str::<ServerConfig>(bad)
                .map_err(|e| e.to_string())
                .and_then(|c| {
                    c.build(&[1; 32], &[2; 32], ProviderKeys::default())
                        .map(|_| ())
                        .map_err(|e| e.to_string())
                });
            assert!(r.unwrap_err().contains(why), "{bad}");
        }
    }

    // REQ: PRO-15 — providers are independent: a config with one OpenAI-compatible provider and
    // nothing else builds (found with the real Codex CLI), with and without a path prefix,
    // and keyless local models need no key.
    #[test]
    fn providers_are_independent() {
        let build = |json: &str, keys: ProviderKeys| -> Result<AppState, ConfigError> {
            serde_json::from_str::<ServerConfig>(json)
                .unwrap()
                .build(&[1; 32], &[2; 32], keys)
        };
        let openai_key = || ProviderKeys {
            openai: Some("ok".into()),
            ..Default::default()
        };
        let st = build(r#"{"openai_base_url": "http://x"}"#, openai_key()).unwrap();
        assert!(st.anthropic.is_none() && st.gemini.is_none());
        assert_eq!(st.openai.as_ref().unwrap().api_prefix, "/v1");
        let st = build(
            r#"{"openai_base_url": "http://x", "openai_api_prefix": "/api/v3"}"#,
            openai_key(),
        )
        .unwrap();
        assert_eq!(st.openai.as_ref().unwrap().api_prefix, "/api/v3");
        let st = build(
            r#"{"openai_base_url": "http://x", "openai_api_prefix": ""}"#,
            openai_key(),
        )
        .unwrap();
        assert_eq!(st.openai.as_ref().unwrap().api_prefix, "");
        // local model without a key
        let st = build(
            r#"{"openai_base_url": "http://x", "openai_auth": "none"}"#,
            ProviderKeys::default(),
        )
        .unwrap();
        assert!(st.openai.is_some());
        // a key is required when the provider needs one; at least one provider is required
        assert!(build(
            r#"{"openai_base_url": "http://x"}"#,
            ProviderKeys::default()
        )
        .is_err());
        assert!(build("{}", ProviderKeys::default()).is_err());
        let st = build(
            r#"{"gemini_base_url": "http://g", "anthropic_base_url": "http://a"}"#,
            ProviderKeys {
                gemini: Some("g".into()),
                anthropic: Some("a".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(st.gemini.is_some() && st.anthropic.is_some() && st.openai.is_none());
    }

    // REQ: SEC-03, NFR-09 — weak or missing keys stop the process.
    #[test]
    fn rejects_short_keys_and_bad_values() {
        let c: ServerConfig = serde_json::from_str(CFG).unwrap();
        assert!(c
            .build(b"short", &[2; 32], ProviderKeys::anthropic("pk"))
            .is_err());
        let bad: ServerConfig =
            serde_json::from_str(&CFG.replace("10.50.0.0/16", "10.50.0.0/99")).unwrap();
        assert!(bad
            .build(&[1; 32], &[2; 32], ProviderKeys::anthropic("pk"))
            .is_err());
        let bad: ServerConfig = serde_json::from_str(&CFG.replace("SYSTEM", "NOPE")).unwrap();
        assert!(bad
            .build(&[1; 32], &[2; 32], ProviderKeys::anthropic("pk"))
            .is_err());
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
        let st = ok
            .build(&[1; 32], &[2; 32], ProviderKeys::anthropic("pk"))
            .unwrap();
        assert!(
            st.bundle_required,
            "a configured bundle makes its absence fail-closed"
        );
        assert!(
            with("\"bundle\": {\"source\": \"x\", \"trusted_keys\": []},")
                .build(&[1; 32], &[2; 32], ProviderKeys::anthropic("pk"))
                .is_err()
        );
        assert!(with(&format!("\"bundle\": {{\"source\": \"x\", \"trusted_keys\": [\"{}\"], \"reload_seconds\": 60}},", ValidKey::hex())).build(&[1; 32], &[2; 32], ProviderKeys::anthropic("pk")).is_err(), "reload slower than 30 s");
        assert!(
            with("\"bundle\": {\"source\": \"x\", \"trusted_keys\": [\"nothex\"]},")
                .build(&[1; 32], &[2; 32], ProviderKeys::anthropic("pk"))
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

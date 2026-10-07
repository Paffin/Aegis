//! REQ: IAM-04 — OpenID Connect: a client may present an identity provider's JWT instead of a
//! virtual key; the principal and the groups come from its claims.
//!
//! Only what is needed to trust a token is implemented: RS256 and ES256 signatures against the
//! provider's JWKS, issuer, audience, expiry and not-before. Everything else (`none`, HMAC
//! algorithms, tokens without `exp`) is refused. The keys are fetched in the background, so
//! checking a token never waits for the network.

use crate::server::Principal;
use arc_swap::ArcSwap;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ring::signature;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// `oidc` in the gateway configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// The `iss` the tokens must carry.
    pub issuer: String,
    /// The `aud` the tokens must carry (the gateway's client id at the provider).
    pub audience: String,
    /// Where the provider's signing keys are (`…/.well-known/jwks.json`). Or a local file.
    #[serde(default)]
    pub jwks_url: Option<String>,
    #[serde(default)]
    pub jwks_file: Option<String>,
    /// Claim with the groups (a list of strings, or one string). Default `groups`.
    #[serde(default = "d_groups")]
    pub groups_claim: String,
    /// Claim that names the principal. Default `sub`; `email` and `preferred_username` are usual.
    #[serde(default = "d_principal")]
    pub principal_claim: String,
    /// Clock skew allowed for `exp` and `nbf`, seconds.
    #[serde(default = "d_leeway")]
    pub leeway_secs: i64,
    /// How often the keys are fetched again, seconds.
    #[serde(default = "d_refresh")]
    pub refresh_secs: u64,
}

fn d_groups() -> String {
    "groups".into()
}
fn d_principal() -> String {
    "sub".into()
}
fn d_leeway() -> i64 {
    60
}
fn d_refresh() -> u64 {
    300
}

#[derive(Debug, Clone)]
enum Key {
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
    },
    /// Uncompressed point `04 || x || y`.
    Ec256(Vec<u8>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum OidcError {
    Malformed,
    Algorithm,
    UnknownKey,
    Signature,
    Issuer,
    Audience,
    Expired,
    NotYet,
    Claim,
}

impl OidcError {
    /// For the client: enough to fix a setup, nothing about the keys.
    pub fn message(&self) -> &'static str {
        match self {
            OidcError::Malformed => "токен не разобран",
            OidcError::Algorithm => "алгоритм подписи не поддерживается",
            OidcError::UnknownKey => {
                "ключ подписи токена неизвестен (список ключей обновляется, повторите)"
            }
            OidcError::Signature => "подпись токена неверна",
            OidcError::Issuer => "токен выдан другим издателем",
            OidcError::Audience => "токен выдан для другого получателя",
            OidcError::Expired => "срок токена истёк",
            OidcError::NotYet => "токен ещё не действует",
            OidcError::Claim => "в токене нет нужного утверждения",
        }
    }
}

pub struct Verifier {
    cfg: OidcConfig,
    keys: ArcSwap<HashMap<String, Key>>,
    /// Asked for a fetch when a token names a key we do not have.
    wake: tokio::sync::Notify,
}

/// Looks like a JWT: three base64url segments, the first of which is a JSON header.
pub fn looks_like_jwt(s: &str) -> bool {
    s.starts_with("eyJ") && s.bytes().filter(|b| *b == b'.').count() == 2
}

fn parse_jwks(v: &Value) -> HashMap<String, Key> {
    let mut out = HashMap::new();
    for k in v
        .get("keys")
        .and_then(|k| k.as_array())
        .into_iter()
        .flatten()
    {
        if k.get("use")
            .and_then(|u| u.as_str())
            .is_some_and(|u| u != "sig")
        {
            continue;
        }
        let s = |f: &str| k.get(f).and_then(|x| x.as_str());
        let dec = |f: &str| s(f).and_then(|x| B64.decode(x).ok());
        let kid = s("kid").unwrap_or("").to_string();
        match s("kty") {
            Some("RSA") => {
                if let (Some(n), Some(e)) = (dec("n"), dec("e")) {
                    out.insert(kid, Key::Rsa { n, e });
                }
            }
            Some("EC") if s("crv") == Some("P-256") => {
                if let (Some(x), Some(y)) = (dec("x"), dec("y")) {
                    if x.len() == 32 && y.len() == 32 {
                        let mut p = vec![4u8];
                        p.extend(x);
                        p.extend(y);
                        out.insert(kid, Key::Ec256(p));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

impl Verifier {
    /// For tests and for a fixed set of keys; [`start`] is the one that keeps them fresh.
    pub fn from_jwks(cfg: OidcConfig, jwks: &Value) -> Self {
        Self {
            cfg,
            keys: ArcSwap::from_pointee(parse_jwks(jwks)),
            wake: tokio::sync::Notify::new(),
        }
    }

    /// Load the keys once (file or URL) and keep them fresh in the background.
    pub async fn start(cfg: OidcConfig, http: reqwest::Client) -> Result<Arc<Self>, String> {
        if cfg.jwks_url.is_none() == cfg.jwks_file.is_none() {
            return Err("oidc: нужен ровно один из jwks_url и jwks_file".into());
        }
        let v = Arc::new(Self {
            cfg,
            keys: ArcSwap::from_pointee(HashMap::new()),
            wake: tokio::sync::Notify::new(),
        });
        v.refresh(&http)
            .await
            .map_err(|e| format!("oidc: ключи не загружены: {e}"))?;
        let bg = v.clone();
        tokio::spawn(async move {
            let mut last = std::time::Instant::now();
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(bg.cfg.refresh_secs.max(10))) => {}
                    _ = bg.wake.notified() => {
                        // a token with an unknown key: fetch, but not more often than every 30 s
                        if last.elapsed() < Duration::from_secs(30) { continue }
                    }
                }
                last = std::time::Instant::now();
                if let Err(e) = bg.refresh(&http).await {
                    tracing::warn!(error = %e, "OIDC keys not refreshed, the old ones stay");
                }
            }
        });
        Ok(v)
    }

    async fn refresh(&self, http: &reqwest::Client) -> Result<(), String> {
        let v: Value = match (&self.cfg.jwks_url, &self.cfg.jwks_file) {
            (Some(u), _) => http
                .get(u)
                .timeout(Duration::from_secs(10))
                .send()
                .await
                .and_then(|r| r.error_for_status())
                .map_err(|e| e.without_url().to_string())?
                .json()
                .await
                .map_err(|e| e.without_url().to_string())?,
            (None, Some(f)) => {
                serde_json::from_slice(&std::fs::read(f).map_err(|e| format!("{f}: {e}"))?)
                    .map_err(|e| format!("{f}: {e}"))?
            }
            (None, None) => return Err("нет источника ключей".into()),
        };
        let keys = parse_jwks(&v);
        if keys.is_empty() {
            return Err("в списке нет ключей подписи".into());
        }
        self.keys.store(Arc::new(keys));
        Ok(())
    }

    /// Check a token and turn its claims into a principal.
    pub fn verify(&self, token: &str, now: i64) -> Result<Principal, OidcError> {
        let mut parts = token.split('.');
        let (Some(h), Some(p), Some(s), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(OidcError::Malformed);
        };
        let dec = |x: &str| B64.decode(x).map_err(|_| OidcError::Malformed);
        let header: Value = serde_json::from_slice(&dec(h)?).map_err(|_| OidcError::Malformed)?;
        let claims: Value = serde_json::from_slice(&dec(p)?).map_err(|_| OidcError::Malformed)?;
        let sig = dec(s)?;
        let alg = header.get("alg").and_then(|a| a.as_str()).unwrap_or("");
        if !matches!(alg, "RS256" | "ES256") {
            return Err(OidcError::Algorithm);
        }
        let keys = self.keys.load();
        let key = match header.get("kid").and_then(|k| k.as_str()) {
            Some(kid) => keys.get(kid),
            // no `kid`: only if there is no doubt which key it is
            None if keys.len() == 1 => keys.values().next(),
            None => None,
        };
        let Some(key) = key else {
            self.wake.notify_one();
            return Err(OidcError::UnknownKey);
        };
        let signed = format!("{h}.{p}");
        let ok = match (alg, key) {
            ("RS256", Key::Rsa { n, e }) => signature::RsaPublicKeyComponents {
                n: n.as_slice(),
                e: e.as_slice(),
            }
            .verify(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                signed.as_bytes(),
                &sig,
            )
            .is_ok(),
            ("ES256", Key::Ec256(point)) => {
                signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                    .verify(signed.as_bytes(), &sig)
                    .is_ok()
            }
            // an RSA key does not verify an ES256 token and the other way round
            _ => return Err(OidcError::Algorithm),
        };
        if !ok {
            return Err(OidcError::Signature);
        }
        if claims.get("iss").and_then(|i| i.as_str()) != Some(self.cfg.issuer.as_str()) {
            return Err(OidcError::Issuer);
        }
        let aud_ok = match claims.get("aud") {
            Some(Value::String(a)) => *a == self.cfg.audience,
            Some(Value::Array(a)) => a
                .iter()
                .any(|x| x.as_str() == Some(self.cfg.audience.as_str())),
            _ => false,
        };
        if !aud_ok {
            return Err(OidcError::Audience);
        }
        // `exp` is required: a token that never expires is not accepted
        let exp = claims
            .get("exp")
            .and_then(|e| e.as_i64())
            .ok_or(OidcError::Claim)?;
        if exp + self.cfg.leeway_secs < now {
            return Err(OidcError::Expired);
        }
        if claims
            .get("nbf")
            .and_then(|n| n.as_i64())
            .is_some_and(|nbf| nbf - self.cfg.leeway_secs > now)
        {
            return Err(OidcError::NotYet);
        }
        let who = claims
            .get(&self.cfg.principal_claim)
            .and_then(|c| c.as_str())
            .filter(|c| !c.is_empty() && c.len() <= 200)
            .ok_or(OidcError::Claim)?;
        let groups = match claims.get(&self.cfg.groups_claim) {
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(|g| g.as_str().map(String::from))
                .collect(),
            Some(Value::String(g)) => vec![g.clone()],
            _ => vec![],
        };
        Ok(Principal {
            id: format!("oidc:{who}"),
            groups,
        })
    }
}

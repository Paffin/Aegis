//! REQ: CFG-01, CFG-02, CFG-04, CFG-06, NFR-09, IAM-03, OBS-01 — loading, verifying and applying the
//! signed policy bundle without a restart.

use crate::engine::Engine;
use crate::server::{AppState, BundleStatus, Principal, VKey};
use aegis_core::bundle::{self, BundleError};
use aegis_core::crypto::TenantKeys;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug)]
pub enum Source {
    File(PathBuf),
    Url(String),
}

impl Source {
    pub fn parse(s: &str) -> Source {
        if s.starts_with("https://") || s.starts_with("http://") {
            Source::Url(s.to_string())
        } else {
            Source::File(PathBuf::from(s))
        }
    }
}

/// Secrets never come from the bundle (CFG-05). `K_t` and `K_audit` are bytes in memory or keys in
/// an HSM (CFG-07); a bundle reload shares them.
pub type Secrets = aegis_core::crypto::KeyPair;

pub struct Loader {
    pub source: Source,
    /// Last valid bundle, written after every successful apply (CFG-06).
    pub cache: Option<PathBuf>,
    pub trusted: Vec<VerifyingKey>,
    pub secrets: Secrets,
    pub interval: Duration,
}

pub fn parse_trusted(hex_keys: &[String]) -> Result<Vec<VerifyingKey>, String> {
    hex_keys
        .iter()
        .map(|h| {
            let b: Vec<u8> = (0..h.len())
                .step_by(2)
                .map(|i| {
                    u8::from_str_radix(h.get(i..i + 2).unwrap_or("zz"), 16)
                        .map_err(|_| format!("ключ {h}: не hex"))
                })
                .collect::<Result<_, _>>()?;
            let arr: [u8; 32] = b
                .try_into()
                .map_err(|_| format!("ключ {h}: нужно 32 байта"))?;
            VerifyingKey::from_bytes(&arr).map_err(|e| format!("ключ {h}: {e}"))
        })
        .collect()
}

/// Verify, compile and swap in a bundle. Nothing changes unless every step succeeds.
pub fn apply(
    st: &AppState,
    trusted: &[VerifyingKey],
    secrets: &Secrets,
    raw: &[u8],
) -> Result<String, String> {
    let payload = bundle::verify(raw, trusted).map_err(|e| match e {
        BundleError::Signature => "signature".to_string(),
        BundleError::UnknownKey(_) => "unknown_key".to_string(),
        other => format!("invalid: {other}"),
    })?;
    if payload.is_expired(crate::server::now_unix()) {
        return Err("expired".into());
    }
    // An older bundle that is still signed and not expired would bring back what a newer one
    // took away (a revoked key, a stricter rule). Time only moves forward.
    let created =
        bundle::parse_utc(&payload.created_at).ok_or_else(|| "invalid: created_at".to_string())?;
    if created < st.bundle_floor.load(std::sync::atomic::Ordering::Relaxed) {
        return Err("rollback: пакет старше уже применённого".into());
    }
    payload
        .policy
        .check_examples()
        .map_err(|e| format!("invalid: {e}"))?;
    let compiled = payload
        .policy
        .compile()
        .map_err(|e| format!("invalid: {e}"))?;
    let keys = TenantKeys::from_pair(&compiled.tenant, secrets);
    let old = st.engine.load();
    let (cache_bytes, budget) = old.limits();
    let engine = Engine::from_compiled(keys, compiled)
        .with_limits(cache_bytes, budget)
        .with_code(old.code.clone());
    let mut vk: HashMap<String, VKey> = HashMap::new();
    for k in &payload.virtual_keys {
        let expires = match &k.expires_at {
            Some(e) => Some(
                bundle::parse_utc(e)
                    .ok_or_else(|| format!("invalid: ключ {}: срок {e}", k.principal))?,
            ),
            None => None,
        };
        vk.insert(
            k.sha256.to_ascii_lowercase(),
            VKey {
                principal: Principal {
                    id: k.principal.clone(),
                    groups: k.groups.clone(),
                },
                expires,
            },
        );
    }
    let expires_at = bundle::parse_utc(&payload.expires_at).unwrap_or(0);
    let env: bundle::Envelope = serde_json::from_slice(raw).map_err(|e| format!("invalid: {e}"))?;
    st.engine.store(Arc::new(engine));
    st.keys.store(Arc::new(vk));
    if let Ok(mut b) = st.bundle.lock() {
        *b = Some(BundleStatus {
            version: payload.version.clone(),
            expires_at,
            key_id: env.key_id,
        });
    }
    st.bundle_floor
        .fetch_max(created, std::sync::atomic::Ordering::Relaxed);
    st.metrics.inc("aegis_bundle_applied_total", &[], 1);
    Ok(payload.version)
}

pub async fn fetch(http: &reqwest::Client, src: &Source) -> Result<Vec<u8>, String> {
    match src {
        Source::File(p) => std::fs::read(p).map_err(|e| format!("read {}: {e}", p.display())),
        Source::Url(u) => {
            let r = http
                .get(u)
                .timeout(Duration::from_secs(10))
                .send()
                .await
                .map_err(|e| format!("fetch: {}", e.without_url()))?;
            if !r.status().is_success() {
                return Err(format!("fetch: HTTP {}", r.status()));
            }
            r.bytes()
                .await
                .map(|b| b.to_vec())
                .map_err(|e| format!("fetch: {}", e.without_url()))
        }
    }
}

/// The bundle holds the employee dictionary: readable by the service user only (mode 0600).
fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    o.mode(0o600);
    o.open(path)?.write_all(data)
}

fn digest(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

impl Loader {
    /// One load attempt from the source; falls back to the local copy when the source is
    /// unreachable or invalid and nothing is loaded yet (CFG-06).
    pub async fn load_once(
        &self,
        st: &AppState,
        last: &mut Option<[u8; 32]>,
    ) -> Result<Option<String>, String> {
        // After a restart the floor comes from the last bundle this node applied, so an old
        // bundle offered by a compromised source is refused here too.
        if st.bundle_floor.load(std::sync::atomic::Ordering::Relaxed) == 0 {
            if let Some(raw) = self.cache.as_ref().and_then(|c| std::fs::read(c).ok()) {
                if let Ok(p) = bundle::verify(&raw, &self.trusted) {
                    if let Some(t) = bundle::parse_utc(&p.created_at) {
                        st.bundle_floor
                            .fetch_max(t, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
        }
        let fetched = fetch(&st.http, &self.source).await;
        match fetched {
            Ok(raw) => {
                let d = digest(&raw);
                if *last == Some(d) {
                    return Ok(None); // unchanged
                }
                match apply(st, &self.trusted, &self.secrets, &raw) {
                    Ok(v) => {
                        *last = Some(d);
                        if let Some(c) = &self.cache {
                            let tmp = c.with_extension("tmp");
                            if write_private(&tmp, &raw)
                                .and_then(|_| std::fs::rename(&tmp, c))
                                .is_err()
                            {
                                st.metrics.inc(
                                    "aegis_bundle_errors_total",
                                    &[("reason", "cache_write")],
                                    1,
                                );
                            }
                        }
                        Ok(Some(v))
                    }
                    Err(e) => {
                        st.metrics.inc(
                            "aegis_bundle_errors_total",
                            &[("reason", e.split(':').next().unwrap_or("error"))],
                            1,
                        );
                        self.fallback(st, last, &e).await
                    }
                }
            }
            Err(e) => {
                st.metrics
                    .inc("aegis_bundle_errors_total", &[("reason", "fetch")], 1);
                self.fallback(st, last, &e).await
            }
        }
    }

    async fn fallback(
        &self,
        st: &AppState,
        last: &mut Option<[u8; 32]>,
        why: &str,
    ) -> Result<Option<String>, String> {
        let loaded = st.bundle.lock().ok().is_some_and(|b| b.is_some());
        if loaded {
            // Keep running on the previous version; the error stays visible in metrics (CFG-04).
            return Err(format!("{why}; работа продолжается на предыдущей версии"));
        }
        let Some(c) = &self.cache else {
            return Err(why.to_string());
        };
        let raw = std::fs::read(c).map_err(|_| format!("{why}; локальной копии нет"))?;
        let v = apply(st, &self.trusted, &self.secrets, &raw)
            .map_err(|e| format!("{why}; локальная копия: {e}"))?;
        *last = Some(digest(&raw));
        Ok(Some(v))
    }

    /// CFG-02: poll, verify, apply. Runs for the life of the process.
    pub async fn watch(self: Arc<Self>, st: Arc<AppState>, mut last: Option<[u8; 32]>) {
        loop {
            tokio::time::sleep(self.interval).await;
            match self.load_once(&st, &mut last).await {
                Ok(Some(v)) => tracing::info!(version = %v, "bundle applied"),
                Ok(None) => {}
                Err(e) => tracing::warn!(error = %e, "bundle not applied"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::bundle::{sign, Payload, PolicyDoc, VirtualKeyDoc};
    use aegis_core::detect::{DetectConfig, Dictionary};
    use ed25519_dalek::SigningKey;

    fn secrets() -> Secrets {
        Secrets::from_bytes(&[1; 32], &[2; 32])
    }

    fn state() -> AppState {
        let e = Engine::new(
            TenantKeys::from_secrets("boot", &[1; 32], &[2; 32]),
            DetectConfig::default(),
            Dictionary::default(),
        );
        let mut st = AppState::new(
            e,
            Some(crate::server::Upstream::anthropic(
                "http://127.0.0.1:1",
                "k",
            )),
            HashMap::new(),
        );
        st.bundle_required = true;
        st
    }

    fn bundle(sk: &SigningKey, version: &str, expires: &str, policy: &str) -> Vec<u8> {
        bundle_at(sk, version, "2026-10-07T00:00:00Z", expires, policy)
    }

    fn bundle_at(
        sk: &SigningKey,
        version: &str,
        created: &str,
        expires: &str,
        policy: &str,
    ) -> Vec<u8> {
        let p = Payload {
            version: version.into(),
            created_at: created.into(),
            expires_at: expires.into(),
            policy: PolicyDoc::from_yaml(policy).unwrap(),
            virtual_keys: vec![VirtualKeyDoc {
                sha256: crate::server::hash_key("vk-1"),
                principal: "u:one".into(),
                groups: vec![],
                expires_at: None,
            }],
        };
        serde_json::to_vec(&sign(&p, sk).unwrap()).unwrap()
    }

    const P1: &str = "version: 1\ntenant: acme\nzones: { internal: [corp.local] }\n";
    const P2: &str = "version: 1\ntenant: acme\nzones: { internal: [corp.local, other.example] }\ntrifecta: { mode: monitor }\n";

    fn far() -> &'static str {
        "2099-01-01T00:00:00Z"
    }

    // REQ: CFG-04, IAM-03 — an older signed bundle cannot be put back over a newer one (it would
    // bring back a revoked key); the same bundle again, and newer ones, are fine.
    #[test]
    fn an_older_bundle_is_refused() {
        let sk = SigningKey::from_bytes(&[5; 32]);
        let st = state();
        let t = [sk.verifying_key()];
        let old = bundle_at(&sk, "v1", "2026-10-01T00:00:00Z", far(), P1);
        let new = bundle_at(&sk, "v2", "2026-10-05T00:00:00Z", far(), P2);
        apply(&st, &t, &secrets(), &old).unwrap();
        apply(&st, &t, &secrets(), &new).unwrap();
        let e = apply(&st, &t, &secrets(), &old).unwrap_err();
        assert!(e.starts_with("rollback"), "{e}");
        assert_eq!(st.bundle_version(), "v2");
        assert!(
            apply(&st, &t, &secrets(), &new).is_ok(),
            "the same bundle again is not a rollback"
        );
    }

    // REQ: NFR-09 — before any bundle the gateway is not ready and refuses traffic.
    #[test]
    fn no_bundle_means_not_ready() {
        let st = state();
        assert!(st.readiness().unwrap_err().contains("не загружен"));
    }

    // REQ: CFG-01, CFG-02, IAM-03
    #[test]
    fn apply_swaps_engine_keys_and_status() {
        let sk = SigningKey::from_bytes(&[5; 32]);
        let st = state();
        let v = apply(
            &st,
            &[sk.verifying_key()],
            &secrets(),
            &bundle(&sk, "v1", far(), P1),
        )
        .unwrap();
        assert_eq!(v, "v1");
        assert!(st.readiness().is_ok());
        assert_eq!(st.engine.load().keys.tenant, "acme");
        assert!(st
            .keys
            .load()
            .contains_key(&crate::server::hash_key("vk-1")));
        assert_eq!(st.bundle_version(), "v1");
        // second version changes the policy without a restart
        apply(
            &st,
            &[sk.verifying_key()],
            &secrets(),
            &bundle(&sk, "v2", far(), P2),
        )
        .unwrap();
        assert_eq!(st.bundle_version(), "v2");
        assert_eq!(
            st.engine.load().trifecta.mode,
            aegis_core::policy::TrifectaMode::Monitor
        );
    }

    // REQ: CFG-04 — a bad bundle changes nothing.
    #[test]
    fn invalid_bundles_leave_the_previous_state() {
        let sk = SigningKey::from_bytes(&[5; 32]);
        let other = SigningKey::from_bytes(&[6; 32]);
        let st = state();
        apply(
            &st,
            &[sk.verifying_key()],
            &secrets(),
            &bundle(&sk, "v1", far(), P1),
        )
        .unwrap();
        for (name, raw) in [
            ("wrong signer", bundle(&other, "v2", far(), P2)),
            ("expired", bundle(&sk, "v3", "2020-01-01T00:00:00Z", P2)),
            ("garbage", b"{}".to_vec()),
        ] {
            assert!(
                apply(&st, &[sk.verifying_key()], &secrets(), &raw).is_err(),
                "{name}"
            );
            assert_eq!(st.bundle_version(), "v1", "{name}");
            assert_eq!(
                st.engine.load().trifecta.mode,
                aegis_core::policy::TrifectaMode::Enforce,
                "{name}"
            );
        }
        // a policy that signs fine but fails its own checks is refused too
        let bad_examples = "version: 1\ndetectors:\n  custom:\n    - id: x\n      type: SECRET\n      regex: 'zzz'\n      examples: { matches: [] }\n";
        assert!(apply(
            &st,
            &[sk.verifying_key()],
            &secrets(),
            &bundle(&sk, "v4", far(), bad_examples)
        )
        .unwrap_err()
        .contains("нет примеров"));
        assert_eq!(st.bundle_version(), "v1");
    }

    // REQ: NFR-09, CFG-04 — an expired current bundle stops traffic.
    #[test]
    fn expiry_of_the_running_bundle_fails_closed() {
        let st = state();
        if let Ok(mut b) = st.bundle.lock() {
            *b = Some(BundleStatus {
                version: "old".into(),
                expires_at: 1,
                key_id: "k".into(),
            });
        }
        assert!(st.readiness().unwrap_err().contains("истёк"));
    }

    // REQ: CFG-06 — start from the local copy when the source is down; keep going when it breaks later.
    #[tokio::test]
    async fn local_copy_and_continuity() {
        let dir = std::env::temp_dir().join(format!("aegis-bl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (src, cache) = (dir.join("bundle.json"), dir.join("cache.json"));
        let sk = SigningKey::from_bytes(&[5; 32]);
        std::fs::write(&src, bundle(&sk, "v1", far(), P1)).unwrap();
        let l = Loader {
            source: Source::File(src.clone()),
            cache: Some(cache.clone()),
            trusted: vec![sk.verifying_key()],
            secrets: secrets(),
            interval: Duration::from_secs(1),
        };

        let st = state();
        let mut last = None;
        assert_eq!(
            l.load_once(&st, &mut last).await.unwrap().as_deref(),
            Some("v1")
        );
        assert!(cache.exists(), "last valid bundle is stored locally");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&cache).unwrap().permissions().mode() & 0o777,
                0o600,
                "the cache holds the employee dictionary"
            );
        }
        assert_eq!(
            l.load_once(&st, &mut last).await.unwrap(),
            None,
            "unchanged source is not re-applied"
        );

        // restart with the source gone: the local copy is used
        std::fs::remove_file(&src).unwrap();
        let st2 = state();
        let mut last2 = None;
        assert_eq!(
            l.load_once(&st2, &mut last2).await.unwrap().as_deref(),
            Some("v1")
        );
        assert!(st2.readiness().is_ok());

        // running node, source now serves garbage: stays on v1 and reports it
        std::fs::write(&src, b"corrupt").unwrap();
        let mut last3 = None;
        let err = l.load_once(&st2, &mut last3).await.unwrap_err();
        assert!(err.contains("предыдущей версии"), "{err}");
        assert_eq!(st2.bundle_version(), "v1");
        assert!(st2.metrics.render().contains("aegis_bundle_errors_total"));

        // no source, no copy: stays not ready
        let st3 = state();
        let none = Loader {
            source: Source::File(dir.join("missing.json")),
            cache: Some(dir.join("nope.json")),
            ..l
        };
        assert!(none.load_once(&st3, &mut None).await.is_err());
        assert!(st3.readiness().is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn trusted_key_parsing() {
        let sk = SigningKey::from_bytes(&[5; 32]);
        let hex: String = sk
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            parse_trusted(std::slice::from_ref(&hex)).unwrap()[0].to_bytes(),
            sk.verifying_key().to_bytes()
        );
        assert!(parse_trusted(&["zz".into()]).is_err());
        assert!(parse_trusted(&[hex[..10].to_string()]).is_err());
    }
}

//! REQ: CFG-04, CFG-05, NFR-09, IAM-02 — `aegis-gateway check <config>`: everything that would stop
//! the gateway from starting or serving, found before it starts and without changing anything.

#![allow(clippy::print_stdout)]

use crate::bundle_loader::{apply, fetch, parse_trusted, Secrets, Source};
use crate::config::{ProviderKeys, ServerConfig};
use crate::server::{now_unix, AppState};
use aegis_core::crypto::{KeyPair, Prf};
use aegis_hsm::{KeySource, Pkcs11Key};

struct Report {
    failed: bool,
}

impl Report {
    fn ok(&mut self, what: impl std::fmt::Display) {
        println!("ok    {what}");
    }
    fn warn(&mut self, what: impl std::fmt::Display) {
        println!("warn  {what}");
    }
    fn fail(&mut self, what: impl std::fmt::Display) {
        self.failed = true;
        println!("FAIL  {what}");
    }
}

fn is_local(url: &str) -> bool {
    let host = url
        .split("://")
        .nth(1)
        .unwrap_or("")
        .split(['/', ':'])
        .next()
        .unwrap_or("");
    host == "localhost"
        || host.starts_with("127.")
        || host == "[::1]"
        || host == "host.docker.internal"
}

/// A URL without credentials and query: safe to print.
fn shown(url: &str) -> String {
    let no_query = url.split(['?', '#']).next().unwrap_or(url);
    match no_query.split_once("://") {
        Some((scheme, rest)) => {
            let host = rest.rsplit('@').next().unwrap_or(rest);
            format!("{scheme}://{host}")
        }
        None => no_query.to_string(),
    }
}

/// One of the two keys: where it comes from and whether it can be used. A key in an HSM is opened,
/// which checks the module, the token, the PIN and the key object, and timed. Neither a key nor the
/// PIN is printed.
fn check_key(r: &mut Report, name: &'static str) -> Option<KeySource> {
    match aegis_hsm::spec_of(name) {
        Some(Err(e)) => {
            r.fail(e);
            None
        }
        Some(Ok(spec)) => match Pkcs11Key::open(&spec) {
            Ok(k) => {
                let timing = match k.measure(25) {
                    Ok(d) => format!("HMAC через токен {} мкс", d.as_micros()),
                    Err(e) => format!("HMAC через токен не вычислен: {e}"),
                };
                if !k.healthy() {
                    r.fail(format_args!("{name}_PKCS11: {}; {timing}", k.info()));
                } else {
                    r.ok(format_args!(
                        "{name}_PKCS11: {}; {timing}; PIN принят, ключ не покидает токен",
                        k.info()
                    ));
                }
                Some(KeySource::Hsm(k))
            }
            Err(e) => {
                r.fail(format_args!("{name}_PKCS11: {e}"));
                None
            }
        },
        None => match aegis_core::secrets::read(name) {
            Ok(b) => Some(KeySource::Bytes(zeroize::Zeroizing::new(b))),
            Err(_) => {
                r.fail(format_args!("{name} не задан"));
                None
            }
        },
    }
}

/// Returns `true` when nothing is wrong. Keys and values are never printed.
pub async fn run(path: &str) -> bool {
    let mut r = Report { failed: false };
    let cfg: ServerConfig = match std::fs::read(path)
        .map_err(|e| e.to_string())
        .and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
    {
        Ok(c) => {
            r.ok(format_args!("конфигурация {path} разобрана"));
            c
        }
        Err(e) => {
            r.fail(format_args!("конфигурация {path}: {e}"));
            return false;
        }
    };

    // secrets (CFG-05, CFG-07, SEC-03)
    let k_t = check_key(&mut r, "AEGIS_K_TENANT");
    let k_audit = check_key(&mut r, "AEGIS_K_AUDIT");
    match (&k_t, &k_audit) {
        (Some(KeySource::Bytes(t)), Some(KeySource::Bytes(a)))
            if t.len() >= 16 && a.len() >= 16 =>
        {
            r.ok("AEGIS_K_TENANT и AEGIS_K_AUDIT заданы, не короче 16 байт");
            if t == a {
                r.fail("AEGIS_K_TENANT и AEGIS_K_AUDIT совпадают: ключ аудита должен быть другим");
            }
        }
        _ => {
            // (a key that failed was reported by `check_key`)
            for (name, k) in [("AEGIS_K_TENANT", &k_t), ("AEGIS_K_AUDIT", &k_audit)] {
                if let Some(KeySource::Bytes(b)) = k {
                    if b.len() < 16 {
                        r.fail(format_args!("{name} короче 16 байт"));
                    }
                }
            }
        }
    }
    // one key object for both would make the audit hash a function of the pseudonym key
    if let (Some(Ok(t)), Some(Ok(a))) = (
        aegis_hsm::spec_of("AEGIS_K_TENANT"),
        aegis_hsm::spec_of("AEGIS_K_AUDIT"),
    ) {
        if t.identity() == a.identity() {
            r.fail("AEGIS_K_TENANT_PKCS11 и AEGIS_K_AUDIT_PKCS11 указывают на один ключ в токене: ключ аудита должен быть другим");
        }
    }

    // a key file or a PIN file that others can read is not a protected key (CFG-07)
    for name in ["AEGIS_K_TENANT", "AEGIS_K_AUDIT", "AEGIS_HSM_PIN"] {
        if let Some(p) = aegis_core::secrets::file_mode_problem(name) {
            r.fail(format_args!("{name}_FILE: {p}"));
        }
    }

    // providers and their keys (IAM-02)
    let placeholder = |fill: u8| -> std::sync::Arc<dyn Prf> {
        std::sync::Arc::new(aegis_core::crypto::HmacPrf::new(&[fill; 32]))
    };
    let keys = KeyPair {
        k_t: k_t
            .map(KeySource::into_prf)
            .unwrap_or_else(|| placeholder(0)),
        k_audit: k_audit
            .map(KeySource::into_prf)
            .unwrap_or_else(|| placeholder(1)),
    };
    let state: Option<AppState> = match cfg.build_keys(&keys, ProviderKeys::from_env()) {
        Ok(st) => {
            for (name, up) in [
                ("Anthropic", &st.anthropic),
                ("OpenAI-совместимый", &st.openai),
                ("Gemini", &st.gemini),
            ] {
                if let Some(u) = up {
                    if u.base_url.starts_with("http://") && !is_local(&u.base_url) {
                        r.warn(format_args!(
                            "провайдер {name}: адрес {} без TLS, ключ провайдера пойдёт открытым текстом",
                            shown(&u.base_url)
                        ));
                    }
                    r.ok(format_args!(
                        "провайдер {name}: {}, ключ {}",
                        shown(&u.base_url),
                        if u.api_key.is_empty() {
                            "не требуется"
                        } else {
                            "задан"
                        }
                    ));
                }
            }
            for rt in &st.routes {
                r.ok(format_args!(
                    "маршрут {}: {} → {}{}{}",
                    rt.name,
                    if rt.models.is_empty() {
                        "любая модель".to_string()
                    } else {
                        rt.models.join(", ")
                    },
                    shown(&rt.upstream.base_url),
                    if rt.groups.is_empty() {
                        String::new()
                    } else {
                        format!(", группы {}", rt.groups.join(", "))
                    },
                    if rt.upstream.api_key.is_empty() {
                        ", без ключа"
                    } else {
                        ", ключ задан"
                    },
                ));
            }
            Some(st)
        }
        Err(e) => {
            r.fail(e);
            None
        }
    };

    // the signed bundle (CFG-01, CFG-04, NFR-09)
    match (&cfg.bundle, &state) {
        (Some(b), Some(st)) => match parse_trusted(&b.trusted_keys) {
            Err(e) => r.fail(format_args!("trusted_keys: {e}")),
            Ok(trusted) => {
                let src = Source::parse(&b.source);
                let secrets: Secrets = keys.clone();
                match fetch(&st.http, &src).await {
                    Err(e) => {
                        r.fail(format_args!("бандл {}: {e}", shown(&b.source)));
                        match b
                            .cache_path
                            .as_ref()
                            .and_then(|p| std::fs::read(p).ok())
                        {
                            Some(raw) if apply(st, &trusted, &secrets, &raw).is_ok() => r.warn(
                                "есть действительная локальная копия: после перезапуска gateway стартует с ней",
                            ),
                            _ => {}
                        }
                    }
                    Ok(raw) => match apply(st, &trusted, &secrets, &raw) {
                        Ok(v) => {
                            let left = st
                                .bundle
                                .lock()
                                .ok()
                                .and_then(|g| g.as_ref().map(|b| (b.expires_at - now_unix()) / 86400));
                            r.ok(format_args!(
                                "бандл {v} проверен, действует ещё {} дн.",
                                left.unwrap_or(0)
                            ));
                            if left.is_some_and(|d| d < 14) {
                                r.warn("бандл истекает менее чем через 14 дней: опубликуйте новый заранее");
                            }
                        }
                        Err(e) => r.fail(format_args!("бандл не принят: {e}")),
                    },
                }
            }
        },
        (None, _) => r.warn(
            "бандл не настроен: политика, словари и виртуальные ключи берутся из конфигурации (режим разработки)",
        ),
        (Some(_), None) => {}
    }
    if cfg.bundle.is_none() && cfg.virtual_keys.is_empty() {
        r.fail("нет ни бандла, ни virtual_keys: ни один клиент не пройдёт проверку ключа");
    }

    // audit file (AUD-04)
    match &cfg.audit_path {
        Some(p) => {
            let existed = std::path::Path::new(p).exists();
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
            {
                Ok(_) => {
                    if !existed {
                        let _ = std::fs::remove_file(p);
                    }
                    r.ok(format_args!("файл аудита {p} доступен для записи"));
                }
                Err(e) => r.fail(format_args!("файл аудита {p}: {e}")),
            }
        }
        None => r.warn("audit_path не задан: аудит пишется в стандартный вывод"),
    }

    // ports (SEC-06)
    for (name, addr) in [("основной", &cfg.listen), ("служебный", &cfg.admin_listen)]
    {
        match tokio::net::TcpListener::bind(addr).await {
            Ok(_) => r.ok(format_args!("{name} порт {addr} свободен")),
            Err(e) => r.fail(format_args!("{name} порт {addr}: {e}")),
        }
    }
    match &cfg.tls {
        Some(t) => match crate::tls::server_config(t) {
            Ok(_) => r.ok(format_args!(
                "TLS на основном порту: сертификат и ключ читаются{}",
                if t.client_ca_file.is_some() {
                    ", клиенты по сертификату (mTLS)"
                } else {
                    ""
                }
            )),
            Err(e) => r.fail(format_args!("tls: {e}")),
        },
        None if !cfg.listen.starts_with("127.") && !cfg.listen.starts_with("localhost") => {
            r.warn("основной порт слушает не только локальный адрес: gateway говорит по обычному HTTP, TLS завершайте на балансировщике или включите `tls`");
        }
        None => {}
    }
    if let (Some(c), Some(st)) = (&cfg.code_index, &state) {
        match st.engine.load().code.as_ref() {
            Some(g) => r.ok(format_args!(
                "индекс закрытого кода {}: {} репозиториев",
                c.path,
                g.repos()
            )),
            None => r.fail("индекс закрытого кода не загружен"),
        }
    }
    if let Some(o) = &cfg.oidc {
        let http = crate::server::client_with(
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(10),
        );
        match crate::oidc::Verifier::start(o.clone(), http).await {
            Ok(_) => r.ok(format_args!("OIDC: ключи издателя {} загружены", o.issuer)),
            Err(e) => r.fail(e),
        }
    }
    if let Some(ep) = &cfg.otlp_endpoint {
        match reqwest::Url::parse(ep) {
            Ok(u) if matches!(u.scheme(), "http" | "https") => {
                r.ok(format_args!("трассировки уходят в {}", shown(ep)))
            }
            _ => r.fail("otlp_endpoint: нужен адрес http:// или https://"),
        }
    }
    if let Some(p) = &cfg.upstream_ca_file {
        match std::fs::read(p).map_err(|e| e.to_string()).and_then(|b| {
            crate::server::client_with_ca(
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(1),
                &b,
            )
            .map(|_| ())
        }) {
            Ok(()) => r.ok(format_args!("провайдеры доверяют только CA из {p}")),
            Err(e) => r.fail(format_args!("upstream_ca_file {p}: {e}")),
        }
    }
    if cfg.admin_listen.starts_with("0.0.0.0") || cfg.admin_listen.starts_with("[::]") {
        r.warn("служебный порт (/metrics, /readyz) слушает все адреса: закройте его от клиентов сетевой политикой");
    }

    println!();
    if r.failed {
        println!("Есть ошибки: gateway не стартует или не будет обслуживать запросы.");
    } else {
        println!("Всё в порядке.");
    }
    !r.failed
}

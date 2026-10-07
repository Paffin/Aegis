//! REQ: CFG-04, CFG-05, NFR-09, IAM-02 — `aegis-gateway check <config>`: everything that would stop
//! the gateway from starting or serving, found before it starts and without changing anything.

#![allow(clippy::print_stdout)]

use crate::bundle_loader::{apply, fetch, parse_trusted, Secrets, Source};
use crate::config::{secret, ProviderKeys, ServerConfig};
use crate::server::{now_unix, AppState};

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

    // secrets (CFG-05, SEC-03)
    let k_t = secret("AEGIS_K_TENANT");
    let k_audit = secret("AEGIS_K_AUDIT");
    match (&k_t, &k_audit) {
        (Ok(t), Ok(a)) if t.len() >= 16 && a.len() >= 16 => {
            r.ok("AEGIS_K_TENANT и AEGIS_K_AUDIT заданы, не короче 16 байт");
            if t == a {
                r.fail("AEGIS_K_TENANT и AEGIS_K_AUDIT совпадают: ключ аудита должен быть другим");
            }
        }
        (Ok(_), Ok(_)) => r.fail("AEGIS_K_TENANT или AEGIS_K_AUDIT короче 16 байт"),
        (t, a) => {
            if t.is_err() {
                r.fail("AEGIS_K_TENANT не задан");
            }
            if a.is_err() {
                r.fail("AEGIS_K_AUDIT не задан");
            }
        }
    }

    // providers and their keys (IAM-02)
    let (kt, ka) = (
        k_t.as_ref().ok().cloned().unwrap_or_else(|| vec![0; 32]),
        k_audit
            .as_ref()
            .ok()
            .cloned()
            .unwrap_or_else(|| vec![1; 32]),
    );
    let state: Option<AppState> = match cfg.build(&kt, &ka, ProviderKeys::from_env()) {
        Ok(st) => {
            for (name, up) in [
                ("Anthropic", &st.anthropic),
                ("OpenAI-совместимый", &st.openai),
                ("Gemini", &st.gemini),
            ] {
                if let Some(u) = up {
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
                let secrets = Secrets {
                    k_t: kt.clone(),
                    k_audit: ka.clone(),
                };
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

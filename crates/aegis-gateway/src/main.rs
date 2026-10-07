//! `aegis-gateway` binary. REQ: NFR-06, NFR-09, SEC-06, CFG-05, SEC-02.

use aegis_gateway::bundle_loader::{parse_trusted, Loader, Secrets, Source};
use aegis_gateway::config::{secret, ProviderKeys, ServerConfig};
use aegis_gateway::server::{admin_app, app};
use std::sync::Arc;
use std::time::Duration;

fn fail(msg: impl std::fmt::Display) -> ! {
    // Never print request data here; only configuration problems.
    eprintln!("aegis-gateway: {msg}");
    std::process::exit(2)
}

#[tokio::main]
async fn main() {
    // `aegis-gateway check <config>`: find what would stop the gateway, change nothing.
    if std::env::args().nth(1).as_deref() == Some("check") {
        let Some(path) = std::env::args().nth(2) else {
            fail("usage: aegis-gateway check <config.json>")
        };
        let ok = aegis_gateway::check::run(&path).await;
        std::process::exit(if ok { 0 } else { 1 });
    }
    // SEC-02: before any request data exists in memory
    let h = aegis_gateway::harden::apply();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();
    if h.core_dumps_disabled && h.non_dumpable {
        tracing::info!("process hardened: core dumps off, not dumpable");
    } else {
        tracing::warn!(
            core_dumps_disabled = h.core_dumps_disabled,
            non_dumpable = h.non_dumpable,
            "process hardening incomplete; disable core dumps in the service manager"
        );
    }
    let path = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("AEGIS_CONFIG").ok())
        .unwrap_or_else(|| fail("usage: aegis-gateway <config.json>"));
    let cfg: ServerConfig = std::fs::read(&path)
        .map_err(|e| e.to_string())
        .and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
        .unwrap_or_else(|e| fail(format!("cannot read config {path}: {e}")));

    // NFR-09: without keys the gateway does not start (fail-closed).
    let k_t = secret("AEGIS_K_TENANT").unwrap_or_else(|e| fail(e));
    let k_audit = secret("AEGIS_K_AUDIT").unwrap_or_else(|e| fail(e));
    let mut state = cfg
        .build(&k_t, &k_audit, ProviderKeys::from_env())
        .unwrap_or_else(|e| fail(e));
    state.audit = cfg.build_audit().unwrap_or_else(|e| fail(e));
    if let Some(o) = &cfg.oidc {
        let http =
            aegis_gateway::server::client_with(Duration::from_secs(5), Duration::from_secs(10));
        state.oidc = Some(
            aegis_gateway::oidc::Verifier::start(o.clone(), http)
                .await
                .unwrap_or_else(|e| fail(e)),
        );
        tracing::info!(issuer = %o.issuer, "OIDC tokens accepted");
    }
    if let Some(ep) = &cfg.otlp_endpoint {
        let headers = std::env::var("AEGIS_OTLP_HEADERS")
            .unwrap_or_default()
            .split(',')
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            .collect();
        state.tracer = Some(aegis_gateway::trace::Tracer::start(
            ep.clone(),
            headers,
            // not the provider client: it may trust only the provider's CA
            aegis_gateway::server::client_with(Duration::from_secs(5), Duration::from_secs(5)),
        ));
    }
    let state = Arc::new(state);

    // CFG-01, CFG-02, CFG-06: the signed bundle supplies policy, dictionaries and virtual keys.
    if let Some(b) = &cfg.bundle {
        let loader = Arc::new(Loader {
            source: Source::parse(&b.source),
            cache: b.cache_path.as_ref().map(std::path::PathBuf::from),
            trusted: parse_trusted(&b.trusted_keys).unwrap_or_else(|e| fail(e)),
            secrets: Secrets {
                k_t: k_t.clone(),
                k_audit: k_audit.clone(),
            },
            interval: Duration::from_secs(b.reload_seconds),
        });
        let mut last = None;
        match loader.load_once(&state, &mut last).await {
            Ok(Some(v)) => tracing::info!(version = %v, "bundle loaded"),
            Ok(None) => {}
            // Without a valid bundle the gateway serves 503 and keeps retrying (NFR-09).
            Err(e) => tracing::error!(error = %e, "no valid bundle yet; requests are refused"),
        }
        tokio::spawn(loader.watch(state.clone(), last));
    }

    let main_l = tokio::net::TcpListener::bind(&cfg.listen)
        .await
        .unwrap_or_else(|e| fail(format!("bind {}: {e}", cfg.listen)));
    let admin_l = tokio::net::TcpListener::bind(&cfg.admin_listen)
        .await
        .unwrap_or_else(|e| fail(format!("bind {}: {e}", cfg.admin_listen)));
    tracing::info!(listen = %cfg.listen, admin = %cfg.admin_listen, "aegis-gateway started");

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    // SIGTERM is what Kubernetes and systemd send; SIGINT is for interactive use.
    tokio::spawn(async move {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = async { match term.as_mut() { Some(t) => { t.recv().await; } None => std::future::pending::<()>().await } } => {}
        }
        let _ = stop_tx.send(true);
    });
    let admin_state = state.clone();
    let mut rx1 = stop_rx.clone();
    let mut rx2 = stop_rx.clone();
    let mut rx3 = stop_rx;
    tokio::spawn(async move {
        let _ = axum::serve(admin_l, admin_app(admin_state))
            .with_graceful_shutdown(async move {
                let _ = rx2.changed().await;
            })
            .await;
    });
    // NFR-06: after the stop signal active streams get up to 10 minutes, then the process exits.
    tokio::spawn(async move {
        let _ = rx3.changed().await;
        tokio::time::sleep(Duration::from_secs(600)).await;
        tracing::warn!("shutdown grace period of 10 minutes elapsed");
        std::process::exit(0);
    });
    let stop = async move {
        let _ = rx1.changed().await;
    };
    match &cfg.tls {
        Some(t) => {
            let tls = aegis_gateway::tls::reloading(t.clone(), Duration::from_secs(30))
                .unwrap_or_else(|e| fail(format!("tls: {e}")));
            tracing::info!(mtls = t.client_ca_file.is_some(), "TLS on the main port");
            aegis_gateway::tls::serve(main_l, app(state), tls, stop).await;
        }
        None => {
            let _ = axum::serve(main_l, app(state))
                .with_graceful_shutdown(stop)
                .await;
        }
    }
}

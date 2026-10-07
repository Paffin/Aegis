//! REQ: SEC-05 — TLS 1.2+ on the listening side, mTLS by configuration, certificate rotation
//! without a restart, and a pinned CA for the provider.
//!
//! Behind a load balancer that terminates TLS none of this is needed; it is for a gateway that
//! clients reach directly (a sidecar, a host without a balancer) and for networks where the hop
//! between balancer and gateway must be encrypted too.

use arc_swap::ArcSwap;
use axum::Router;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use serde::Deserialize;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio_rustls::TlsAcceptor;

/// `tls` in the gateway configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsFiles {
    /// Certificate chain, PEM.
    pub cert_file: String,
    /// Private key, PEM.
    pub key_file: String,
    /// With this set clients must present a certificate signed by one of these CAs (mTLS).
    #[serde(default)]
    pub client_ca_file: Option<String>,
}

fn certs(pem: &[u8], what: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let v: Vec<_> = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{what}: {e}"))?;
    if v.is_empty() {
        return Err(format!("{what}: no certificate in the file"));
    }
    Ok(v)
}

/// The rustls configuration for these files. Errors say which file and why, never print a key.
pub fn server_config(f: &TlsFiles) -> Result<ServerConfig, String> {
    let read = |p: &str| std::fs::read(p).map_err(|e| format!("{p}: {e}"));
    let chain = certs(&read(&f.cert_file)?, &f.cert_file)?;
    let key = PrivateKeyDer::from_pem_slice(&read(&f.key_file)?)
        .map_err(|e| format!("{}: {e}", f.key_file))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| e.to_string())?;
    let builder = match &f.client_ca_file {
        Some(ca) => {
            let mut roots = RootCertStore::empty();
            for c in certs(&read(ca)?, ca)? {
                roots.add(c).map_err(|e| format!("{ca}: {e}"))?;
            }
            let v = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| format!("{ca}: {e}"))?;
            builder.with_client_cert_verifier(v)
        }
        None => builder.with_no_client_auth(),
    };
    let mut cfg = builder
        .with_single_cert(chain, key)
        .map_err(|e| format!("{}: {e}", f.key_file))?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

fn stamp(f: &TlsFiles) -> Vec<Option<SystemTime>> {
    [
        Some(&f.cert_file),
        Some(&f.key_file),
        f.client_ca_file.as_ref(),
    ]
    .into_iter()
    .flatten()
    .map(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())
    .collect()
}

/// An acceptor that picks up renewed certificates: the files are looked at every `every`, and a
/// configuration that does not load is ignored (the old one stays).
pub fn reloading(f: TlsFiles, every: Duration) -> Result<Arc<ArcSwap<ServerConfig>>, String> {
    let cur = Arc::new(ArcSwap::from_pointee(server_config(&f)?));
    let slot = cur.clone();
    tokio::spawn(async move {
        let mut seen = stamp(&f);
        loop {
            tokio::time::sleep(every).await;
            let now = stamp(&f);
            if now == seen {
                continue;
            }
            match server_config(&f) {
                Ok(c) => {
                    slot.store(Arc::new(c));
                    seen = now;
                    tracing::info!("TLS certificate reloaded");
                }
                Err(e) => {
                    tracing::error!(error = %e, "TLS certificate not reloaded, the old one stays")
                }
            }
        }
    });
    Ok(cur)
}

/// Serve `router` over TLS until `stop` resolves, then let open connections finish.
pub async fn serve(
    listener: tokio::net::TcpListener,
    router: Router,
    tls: Arc<ArcSwap<ServerConfig>>,
    stop: impl std::future::Future<Output = ()>,
) {
    let graceful = GracefulShutdown::new();
    tokio::pin!(stop);
    loop {
        let (tcp, _) = tokio::select! {
            r = listener.accept() => match r {
                Ok(x) => x,
                Err(_) => { tokio::time::sleep(Duration::from_millis(50)).await; continue }
            },
            _ = &mut stop => break,
        };
        let acceptor = TlsAcceptor::from(tls.load_full());
        let svc = TowerToHyperService::new(router.clone());
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            // a client that does not finish the handshake does not hold a slot
            let Ok(Ok(stream)) =
                tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await
            else {
                return;
            };
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(30))
                .serve_connection(TokioIo::new(stream), svc);
            let _ = watcher.watch(conn).await;
        });
    }
    graceful.shutdown().await;
}

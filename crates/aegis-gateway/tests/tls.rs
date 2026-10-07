#![allow(clippy::unwrap_used)]
//! REQ: SEC-05 — TLS on the main port, mTLS, certificate rotation, a pinned CA for the provider.

use aegis_gateway::server::client_with_ca;
use aegis_gateway::tls::{self, TlsFiles};
use axum::routing::get;
use axum::Router;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn ca(name: &str) -> Ca {
    let mut p = CertificateParams::default();
    p.distinguished_name.push(DnType::CommonName, name);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate().unwrap();
    Ca {
        cert: p.self_signed(&key).unwrap(),
        key,
    }
}

/// (certificate PEM, key PEM) for 127.0.0.1, signed by `ca`.
fn leaf(ca: &Ca, name: &str) -> (String, String) {
    let mut p = CertificateParams::new(vec![]).unwrap();
    p.distinguished_name.push(DnType::CommonName, name);
    p.subject_alt_names = vec![SanType::IpAddress("127.0.0.1".parse().unwrap())];
    let key = KeyPair::generate().unwrap();
    let cert = p.signed_by(&key, &ca.cert, &ca.key).unwrap();
    (cert.pem(), key.serialize_pem())
}

fn dir() -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let d = std::env::temp_dir().join(format!(
        "aegis-tls-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write(d: &std::path::Path, name: &str, s: &str) -> String {
    let p = d.join(name);
    std::fs::write(&p, s).unwrap();
    p.to_string_lossy().into()
}

async fn serve(files: TlsFiles, every: Duration) -> String {
    let cfg = tls::reloading(files, every).unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let router = Router::new().route("/ping", get(|| async { "pong" }));
    tokio::spawn(tls::serve(l, router, cfg, std::future::pending()));
    format!("127.0.0.1:{}", addr.port())
}

fn client(trust: &Ca) -> reqwest::Client {
    let ca = reqwest::Certificate::from_pem(trust.cert.pem().as_bytes()).unwrap();
    reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .build()
        .unwrap()
}

#[tokio::test]
async fn serves_https_and_nothing_else() {
    let d = dir();
    let root = ca("root");
    let (c, k) = leaf(&root, "gw");
    let addr = serve(
        TlsFiles {
            cert_file: write(&d, "c.pem", &c),
            key_file: write(&d, "k.pem", &k),
            client_ca_file: None,
        },
        Duration::from_secs(60),
    )
    .await;
    let r = client(&root)
        .get(format!("https://{addr}/ping"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.text().await.unwrap(), "pong");
    // a client that does not know the CA refuses the server
    assert!(client(&ca("other"))
        .get(format!("https://{addr}/ping"))
        .send()
        .await
        .is_err());
    // plain HTTP on the TLS port gets nothing
    assert!(reqwest::get(format!("http://{addr}/ping")).await.is_err());
}

#[tokio::test]
async fn mtls_needs_a_client_certificate_from_the_configured_ca() {
    let d = dir();
    let root = ca("root");
    let clients = ca("clients");
    let (c, k) = leaf(&root, "gw");
    let addr = serve(
        TlsFiles {
            cert_file: write(&d, "c.pem", &c),
            key_file: write(&d, "k.pem", &k),
            client_ca_file: Some(write(&d, "ca.pem", &clients.cert.pem())),
        },
        Duration::from_secs(60),
    )
    .await;
    let url = format!("https://{addr}/ping");
    assert!(
        client(&root).get(&url).send().await.is_err(),
        "no certificate"
    );

    let ident = |ca: &Ca| {
        let (c, k) = leaf(ca, "dev");
        reqwest::Identity::from_pem(format!("{c}{k}").as_bytes()).unwrap()
    };
    let with = |i| {
        let r = reqwest::Certificate::from_pem(root.cert.pem().as_bytes()).unwrap();
        reqwest::Client::builder()
            .tls_built_in_root_certs(false)
            .add_root_certificate(r)
            .identity(i)
            .build()
            .unwrap()
    };
    assert_eq!(
        with(ident(&clients))
            .get(&url)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "pong"
    );
    assert!(
        with(ident(&ca("stranger"))).get(&url).send().await.is_err(),
        "certificate of another CA"
    );
}

#[tokio::test]
async fn a_renewed_certificate_is_picked_up_without_restart() {
    let d = dir();
    let old = ca("old");
    let new = ca("new");
    let (c, k) = leaf(&old, "gw");
    let files = TlsFiles {
        cert_file: write(&d, "c.pem", &c),
        key_file: write(&d, "k.pem", &k),
        client_ca_file: None,
    };
    let addr = serve(files.clone(), Duration::from_millis(100)).await;
    let url = format!("https://{addr}/ping");
    assert!(client(&old).get(&url).send().await.is_ok());
    assert!(client(&new).get(&url).send().await.is_err());

    // a broken file does not replace the working certificate
    tokio::time::sleep(Duration::from_millis(1100)).await;
    write(&d, "c.pem", "garbage");
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(client(&old).get(&url).send().await.is_ok());

    let (c, k) = leaf(&new, "gw");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    write(&d, "c.pem", &c);
    write(&d, "k.pem", &k);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(client(&new).get(&url).send().await.is_ok());
    assert!(client(&old).get(&url).send().await.is_err());
}

#[tokio::test]
async fn the_provider_connection_trusts_only_the_pinned_ca() {
    let d = dir();
    let root = ca("provider-ca");
    let (c, k) = leaf(&root, "provider");
    let addr = serve(
        TlsFiles {
            cert_file: write(&d, "c.pem", &c),
            key_file: write(&d, "k.pem", &k),
            client_ca_file: None,
        },
        Duration::from_secs(60),
    )
    .await;
    let url = format!("https://{addr}/ping");
    let pinned = client_with_ca(
        Duration::from_secs(2),
        Duration::from_secs(2),
        root.cert.pem().as_bytes(),
    )
    .unwrap();
    assert_eq!(
        pinned.get(&url).send().await.unwrap().text().await.unwrap(),
        "pong"
    );
    let other = client_with_ca(
        Duration::from_secs(2),
        Duration::from_secs(2),
        ca("other").cert.pem().as_bytes(),
    )
    .unwrap();
    assert!(other.get(&url).send().await.is_err());
    assert!(client_with_ca(Duration::from_secs(1), Duration::from_secs(1), b"nothing").is_err());
}

#[test]
fn bad_files_are_named_in_the_error() {
    let d = dir();
    let e = tls::server_config(&TlsFiles {
        cert_file: d.join("none.pem").to_string_lossy().into(),
        key_file: "x".into(),
        client_ca_file: None,
    })
    .unwrap_err();
    assert!(e.contains("none.pem"), "{e}");
    let root = ca("r");
    let (c, _) = leaf(&root, "gw");
    let e = tls::server_config(&TlsFiles {
        cert_file: write(&d, "c.pem", &c),
        key_file: write(&d, "k.pem", "no key"),
        client_ca_file: None,
    })
    .unwrap_err();
    assert!(e.contains("k.pem") && !e.contains("no key"), "{e}");
}

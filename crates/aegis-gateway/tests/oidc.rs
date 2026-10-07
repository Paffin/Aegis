#![allow(clippy::unwrap_used)]
//! REQ: IAM-04 — tokens of an OpenID Connect provider: what is accepted and, more to the point,
//! what is not.

use aegis_gateway::oidc::{looks_like_jwt, OidcConfig, OidcError, Verifier};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde_json::{json, Value};

const NOW: i64 = 1_800_000_000;

struct Idp {
    key: EcdsaKeyPair,
    jwks: Value,
}

fn idp(kid: &str) -> Idp {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let p = key.public_key().as_ref();
    let jwks = json!({"keys": [{"kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "alg": "ES256",
        "x": B64.encode(&p[1..33]), "y": B64.encode(&p[33..65])}]});
    Idp { key, jwks }
}

fn token_with(key: &EcdsaKeyPair, header: Value, claims: Value) -> String {
    let signed = format!(
        "{}.{}",
        B64.encode(header.to_string()),
        B64.encode(claims.to_string())
    );
    let sig = key.sign(&SystemRandom::new(), signed.as_bytes()).unwrap();
    format!("{signed}.{}", B64.encode(sig.as_ref()))
}

fn claims() -> Value {
    json!({"iss": "https://idp.example", "aud": "aegis", "sub": "alice", "exp": NOW + 600, "groups": ["devs", "ml"]})
}

fn verifier(i: &Idp) -> Verifier {
    let cfg: OidcConfig = serde_json::from_value(
        json!({"issuer": "https://idp.example", "audience": "aegis", "jwks_file": "unused"}),
    )
    .unwrap();
    Verifier::from_jwks(cfg, &i.jwks)
}

fn hdr() -> Value {
    json!({"alg": "ES256", "typ": "JWT", "kid": "k1"})
}

#[test]
fn a_good_token_gives_principal_and_groups() {
    let i = idp("k1");
    let v = verifier(&i);
    let t = token_with(&i.key, hdr(), claims());
    assert!(looks_like_jwt(&t));
    let p = v.verify(&t, NOW).unwrap();
    assert_eq!(p.id, "oidc:alice");
    assert_eq!(p.groups, ["devs", "ml"]);
    // audience as a list, groups as one string, no kid with a single key
    let mut c = claims();
    c["aud"] = json!(["other", "aegis"]);
    c["groups"] = json!("solo");
    let t = token_with(&i.key, json!({"alg": "ES256"}), c);
    assert_eq!(v.verify(&t, NOW).unwrap().groups, ["solo"]);
}

#[test]
fn everything_wrong_with_a_token_is_refused() {
    let i = idp("k1");
    let other = idp("k1"); // the same kid, another key: a forgery
    let v = verifier(&i);
    let ok = |c: Value| token_with(&i.key, hdr(), c);
    let with = |f: &dyn Fn(&mut Value)| {
        let mut c = claims();
        f(&mut c);
        c
    };
    let cases: Vec<(String, OidcError)> = vec![
        (
            token_with(&other.key, hdr(), claims()),
            OidcError::Signature,
        ),
        (
            ok(with(&|c| c["iss"] = json!("https://evil.example"))),
            OidcError::Issuer,
        ),
        (
            ok(with(&|c| c["aud"] = json!("someone-else"))),
            OidcError::Audience,
        ),
        (
            ok(with(&|c| {
                c.as_object_mut().unwrap().remove("aud");
            })),
            OidcError::Audience,
        ),
        (
            ok(with(&|c| c["exp"] = json!(NOW - 61))),
            OidcError::Expired,
        ),
        (
            ok(with(&|c| {
                c.as_object_mut().unwrap().remove("exp");
            })),
            OidcError::Claim,
        ),
        (
            ok(with(&|c| c["nbf"] = json!(NOW + 3600))),
            OidcError::NotYet,
        ),
        (
            ok(with(&|c| {
                c.as_object_mut().unwrap().remove("sub");
            })),
            OidcError::Claim,
        ),
        (
            token_with(&i.key, json!({"alg": "ES256", "kid": "nope"}), claims()),
            OidcError::UnknownKey,
        ),
        (
            token_with(&i.key, json!({"alg": "none", "kid": "k1"}), claims()),
            OidcError::Algorithm,
        ),
        (
            token_with(&i.key, json!({"alg": "HS256", "kid": "k1"}), claims()),
            OidcError::Algorithm,
        ),
        (
            token_with(&i.key, json!({"alg": "RS256", "kid": "k1"}), claims()),
            OidcError::Algorithm,
        ),
        ("eyJhbGciOiJub25lIn0.e30.".to_string(), OidcError::Algorithm),
        ("eyJ.garbage".to_string(), OidcError::Malformed),
        ("a.b.c.d".to_string(), OidcError::Malformed),
        (String::new(), OidcError::Malformed),
    ];
    for (t, want) in cases {
        assert_eq!(v.verify(&t, NOW).unwrap_err(), want, "{t}");
    }
    // within the allowed skew the token still works
    assert!(v
        .verify(&ok(with(&|c| c["exp"] = json!(NOW - 59))), NOW)
        .is_ok());
}

#[test]
fn a_tampered_payload_does_not_verify() {
    let i = idp("k1");
    let v = verifier(&i);
    let t = token_with(&i.key, hdr(), claims());
    let parts: Vec<&str> = t.split('.').collect();
    let mut c = claims();
    c["groups"] = json!(["admins"]);
    let forged = format!("{}.{}.{}", parts[0], B64.encode(c.to_string()), parts[2]);
    assert_eq!(v.verify(&forged, NOW).unwrap_err(), OidcError::Signature);
}

// ---- through the gateway: group → route ----------------------------------------------------

use aegis_core::crypto::TenantKeys;
use aegis_core::detect::{DetectConfig, Dictionary};
use aegis_gateway::engine::Engine;
use aegis_gateway::server::{app, AppState, Family, Route, Upstream};
use axum::routing::any;
use axum::Router;
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn tokens_are_accepted_by_the_gateway_and_groups_pick_the_route() {
    let hits: Arc<Mutex<Vec<&'static str>>> = Arc::default();
    let mock = |name: &'static str| {
        let hits = hits.clone();
        async move {
            let r = Router::new().fallback(any(move || {
                let hits = hits.clone();
                async move {
                    hits.lock().unwrap().push(name);
                    axum::Json(json!({"id": "c", "object": "chat.completion", "choices": []}))
                }
            }));
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", l.local_addr().unwrap());
            tokio::spawn(async move { axum::serve(l, r).await.unwrap() });
            url
        }
    };
    let (default_url, team_url) = (mock("default").await, mock("team").await);
    let i = idp("k1");
    let keys = TenantKeys::from_secrets("t1", b"k-tenant", b"k-audit");
    let engine = Engine::new(keys, DetectConfig::default(), Dictionary::default());
    let mut st = AppState::new(engine, None, Default::default());
    st.openai = Some(Upstream::openai(default_url, "k"));
    st.routes = vec![Route {
        name: "ml-team".into(),
        family: Family::OpenAi,
        models: vec![],
        groups: vec!["ml".into()],
        upstream: Upstream::openai(team_url, "k"),
    }];
    st.oidc = Some(Arc::new(verifier(&i)));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gw = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app(Arc::new(st))).await.unwrap() });

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut c = claims();
    c["exp"] = json!(now + 600);
    let ask = |t: String| {
        let url = format!("{gw}/v1/chat/completions");
        async move {
            reqwest::Client::new()
                .post(url)
                .header("authorization", format!("Bearer {t}"))
                .json(&json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]}))
                .send()
                .await
                .unwrap()
        }
    };
    assert_eq!(
        ask(token_with(&i.key, hdr(), c.clone())).await.status(),
        200
    );
    let mut other = c.clone();
    other["groups"] = json!(["devs"]);
    assert_eq!(ask(token_with(&i.key, hdr(), other)).await.status(), 200);
    assert_eq!(
        *hits.lock().unwrap(),
        ["team", "default"],
        "the group `ml` has its own route"
    );
    // a bad token is a 401 that says why, and a made-up key is refused as before
    let mut expired = c;
    expired["exp"] = json!(now - 3600);
    let r = ask(token_with(&i.key, hdr(), expired)).await;
    assert_eq!(r.status(), 401);
    assert!(r.text().await.unwrap().contains("срок токена истёк"));
    assert_eq!(ask("not-a-key".into()).await.status(), 401);
}

// RS256 is what most providers use. The key is made with the openssl command line (ring can
// sign with an RSA key but not make one); without openssl the test says so and passes.
#[test]
fn rs256_tokens_verify() {
    use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
    let dir = std::env::temp_dir().join(format!("aegis-oidc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (key_pem, key_der) = (dir.join("k.pem"), dir.join("k.der"));
    let sh = |args: &[&str]| std::process::Command::new("openssl").args(args).output();
    let Ok(out) = sh(&[
        "genrsa",
        "-traditional",
        "-out",
        key_pem.to_str().unwrap(),
        "2048",
    ]) else {
        eprintln!("openssl is not installed: RS256 test skipped");
        return;
    };
    assert!(out.status.success());
    let out = sh(&[
        "rsa",
        "-in",
        key_pem.to_str().unwrap(),
        "-traditional",
        "-outform",
        "DER",
        "-out",
        key_der.to_str().unwrap(),
    ])
    .unwrap();
    assert!(out.status.success());
    let der = std::fs::read(&key_der).unwrap();
    let pair = RsaKeyPair::from_der(&der).unwrap();
    // n and e from ring's own view of the public key (DER: SEQUENCE { INTEGER n, INTEGER e })
    let pk = pair.public().as_ref().to_vec();
    let int = |b: &[u8]| -> (Vec<u8>, usize) {
        assert_eq!(b[0], 0x02);
        let (len, hdr) = if b[1] & 0x80 == 0 {
            (b[1] as usize, 2)
        } else {
            let n = (b[1] & 0x7f) as usize;
            (
                b[2..2 + n].iter().fold(0usize, |a, x| a << 8 | *x as usize),
                2 + n,
            )
        };
        let mut v = b[hdr..hdr + len].to_vec();
        while v.first() == Some(&0) {
            v.remove(0);
        }
        (v, hdr + len)
    };
    let body = if pk[1] & 0x80 == 0 {
        &pk[2..]
    } else {
        &pk[2 + (pk[1] & 0x7f) as usize..]
    };
    let (n, used) = int(body);
    let (e, _) = int(&body[used..]);
    let jwks = json!({"keys": [{"kty": "RSA", "kid": "r1", "use": "sig", "n": B64.encode(n), "e": B64.encode(e)}]});
    let cfg: OidcConfig = serde_json::from_value(
        json!({"issuer": "https://idp.example", "audience": "aegis", "jwks_file": "unused"}),
    )
    .unwrap();
    let v = Verifier::from_jwks(cfg, &jwks);
    let signed = format!(
        "{}.{}",
        B64.encode(json!({"alg": "RS256", "kid": "r1"}).to_string()),
        B64.encode(claims().to_string())
    );
    let mut sig = vec![0u8; pair.public().modulus_len()];
    pair.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        signed.as_bytes(),
        &mut sig,
    )
    .unwrap();
    let token = format!("{signed}.{}", B64.encode(&sig));
    assert_eq!(v.verify(&token, NOW).unwrap().id, "oidc:alice");
    sig[10] ^= 1;
    let bad = format!("{signed}.{}", B64.encode(&sig));
    assert_eq!(v.verify(&bad, NOW).unwrap_err(), OidcError::Signature);
}

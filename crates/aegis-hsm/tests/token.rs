//! REQ: CFG-07 — keys in an HSM, against real PKCS#11 tokens (kryoptic, NSS softoken).
//!
//! Without a token module on the machine every test says SKIPPED and passes. In CI the token is
//! installed or built first (`scripts/build-kryoptic.sh`, `libnss3`), see `.github/workflows/ci.yml`.
#![allow(clippy::unwrap_used)]

mod support;

use aegis_core::crypto::{audit_hash, pseudonym_id, HmacPrf, Prf, Salt, TenantKeys};
use aegis_core::fingerprint::Fingerprinter;
use aegis_hsm::{create_key, HsmError, Material, Pkcs11Key};
use cryptoki::object::{Attribute, AttributeType};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use support::*;

/// Tests that log out, destroy keys or reset the spare token take turns.
static SPARE: Mutex<()> = Mutex::new(());

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 + 7) as u8).collect()
}

fn unique(t: &Token, what: &str) -> String {
    format!("{what}-{:?}-{}", t.kind, std::process::id())
}

// REQ: CFG-07 — the token's HMAC is the HMAC of the key bytes, byte for byte.
#[test]
fn the_token_computes_the_same_hmac_as_memory() {
    each(|t| {
        let key = b"k-0123456789abcdef-hsm-test-key!";
        let label = unique(t, "equal");
        t.put_key(&label, key, false);
        let k = Pkcs11Key::open_with_pin(&t.spec(&label), t.pin()).unwrap();
        assert_eq!(k.info().bits, Some(256));
        assert_eq!(k.info().key_type, "GENERIC_SECRET");
        // around the block size of SHA-256 (64), the one-shot limit (16 KiB) and well past it
        for len in [0, 1, 55, 56, 63, 64, 65, 200, 16384, 16385, 40000] {
            let data = pattern(len);
            assert_eq!(
                k.try_mac_raw(&data).unwrap(),
                expected(key, &data),
                "{len} bytes"
            );
            assert_eq!(k.mac_raw(&data), expected(key, &data));
        }
        // the framed form the pseudonyms use
        let mem = HmacPrf::new(key);
        let parts: [&[u8]; 3] = [b"aegis/v1", b"t1", b"HOST"];
        assert_eq!(k.mac(&parts), mem.mac(&parts));
        assert_ne!(k.mac(&[b"ab", b"c"]), k.mac(&[b"a", b"bc"]));
        // what is built on it: the index key, a pseudonym id, an audit hash
        assert_eq!(
            Fingerprinter::from_prf(&k).check(),
            Fingerprinter::new(key).check()
        );
        let hsm = TenantKeys {
            tenant: "t1".into(),
            k_t: Arc::new(k.clone()),
            k_audit: Arc::new(k),
        };
        let plain = TenantKeys::from_secrets("t1", key, key);
        let salt = Salt([9; 32]);
        for v in ["prod-db01", "10.1.2.3", "ivan@corp.ru"] {
            assert_eq!(
                pseudonym_id(&hsm, &salt, "HOST", v),
                pseudonym_id(&plain, &salt, "HOST", v)
            );
        }
        assert_eq!(
            audit_hash(&hsm, "SECRET", "x"),
            audit_hash(&plain, "SECRET", "x")
        );
        assert_eq!(hsm.fault_mark(), 0);
        assert!(hsm.healthy());
    });
}

// REQ: CFG-07 — the key cannot be read out of the token, with the PIN in hand.
#[test]
fn the_key_cannot_be_read_out_of_the_token() {
    each(|t| {
        let key = b"k-never-leaves-the-token-0123456";
        let label = unique(t, "sealed");
        t.put_key(&label, key, false);
        let s = t.inspector();
        let h = t.find(&s, &label).unwrap();
        // C_GetAttributeValue(CKA_VALUE) is refused (CKR_ATTRIBUTE_SENSITIVE): the attribute does not come back
        let got = attrs(&s, h, &[AttributeType::Value]);
        assert!(
            !got.iter().any(|a| matches!(a, Attribute::Value(_))),
            "the token handed out the key"
        );
        let got = attrs(
            &s,
            h,
            &[AttributeType::Extractable, AttributeType::Sensitive],
        );
        assert!(got.contains(&Attribute::Extractable(false)), "{got:?}");
        assert!(got.contains(&Attribute::Sensitive(true)), "{got:?}");
        // and it cannot be made extractable afterwards
        assert!(s
            .update_attributes(h, &[Attribute::Extractable(true)])
            .is_err());
        let again = attrs(&s, h, &[AttributeType::Value]);
        assert!(!again.iter().any(|a| matches!(a, Attribute::Value(_))));
        // the process that uses the key never sees it either: nothing printable holds it
        let k = Pkcs11Key::open_with_pin(&t.spec(&label), t.pin()).unwrap();
        let shown = format!("{k:?} {} {:?}", k.info(), k.spec());
        assert!(!shown.contains("never-leaves"), "{shown}");
    });
}

// REQ: CFG-07 — a key the token would give away is not used.
#[test]
fn an_extractable_key_is_refused() {
    each(|t| {
        let label = unique(t, "open-door");
        t.put_key(&label, b"k-extractable-0123456789abcdef", true);
        match Pkcs11Key::open_with_pin(&t.spec(&label), t.pin()) {
            Err(HsmError::Key(m)) => assert!(
                m.contains("CKA_EXTRACTABLE") || m.contains("CKA_SENSITIVE"),
                "{m}"
            ),
            Err(e) => panic!("another refusal: {e}"),
            Ok(_) => panic!("an extractable key was accepted"),
        }
    });
}

// REQ: CFG-07 — fail closed: no PIN, wrong PIN, no token, no key, no module.
#[test]
fn what_is_missing_or_wrong_is_refused() {
    each(|t| {
        let label = unique(t, "present");
        t.put_key(&label, b"k-present-0123456789abcdef-----", false);
        // no key of that label
        match Pkcs11Key::open_with_pin(&t.spec("no-such-key"), t.pin()) {
            Err(HsmError::Key(m)) => assert!(m.contains("не найден"), "{m}"),
            other => panic!("{:?}", other.err()),
        }
        // no token of that label
        let spec = t.spec_for("no-such-token", &label);
        assert!(matches!(
            Pkcs11Key::open_with_pin(&spec, t.pin()),
            Err(HsmError::Token(_))
        ));
        // no module
        let spec = "module=/nonexistent/libnone.so;token=x;label=y"
            .parse()
            .unwrap();
        assert!(matches!(
            Pkcs11Key::open_with_pin(&spec, Some("1")),
            Err(HsmError::Module(_))
        ));
        // a token that wants a PIN and gets none, or a wrong one
        if t.pin().is_some() {
            assert!(matches!(
                Pkcs11Key::open_with_pin(&t.spec(&label), None),
                Err(HsmError::Config(_))
            ));
        }
    });
}

// REQ: CFG-07 — the PIN comes from AEGIS_HSM_PIN-style variables, and a missing one is an error.
#[test]
fn the_key_source_reads_the_pin_from_the_environment() {
    each(|t| {
        if t.pin().is_none() {
            return;
        }
        let label = unique(t, "envkey");
        let key = b"k-from-the-env-0123456789abcdef!";
        t.put_key(&label, key, false);
        let (name, pin_var) = ("AEGIS_TEST_ENV_KEY", "AEGIS_TEST_ENV_PIN");
        let spec = format!(
            "module={};token={};label={label};pin_var={pin_var}",
            t.module.display(),
            t.label
        );
        std::env::set_var(format!("{name}_PKCS11"), &spec);
        std::env::remove_var(pin_var);
        let e = aegis_hsm::load(name).err().unwrap();
        assert!(e.contains(pin_var), "{e}");
        std::env::set_var(pin_var, USER_PIN);
        let prf = aegis_hsm::load_prf(name).unwrap();
        assert_eq!(prf.mac_raw(b"x"), expected(key, b"x"));
        // the same key also set the old way: two sources, no guessing
        std::env::set_var(name, "k-a-file-key-0123456789abcdef");
        let e = aegis_hsm::load(name).err().unwrap();
        assert!(e.contains("один источник"), "{e}");
        std::env::remove_var(name);
        std::env::remove_var(format!("{name}_PKCS11"));
        std::env::remove_var(pin_var);
    });
}

// REQ: CFG-07 — a wrong PIN is refused, once, and is not in any message. (Alone on the spare token
// and after a logout: the login belongs to the token, and a token that is logged in already answers
// "already logged in" to any PIN without looking at it.)
#[test]
fn a_wrong_pin_is_refused_and_not_printed() {
    let Some((slot, label)) = spare() else { return };
    let _turn = SPARE.lock().unwrap_or_else(|e| e.into_inner());
    let t = &tokens()[kryoptic_index()];
    let kl = "pinned";
    t.init_token(slot, &label);
    t.put_key_in(slot, kl, b"k-pinned-0123456789abcdef------", false);
    let wrong = "wrong-pin-do-not-print";
    let e = Pkcs11Key::open_with_pin(&t.spec_for(&label, kl), Some(wrong)).unwrap_err();
    assert!(matches!(e, HsmError::Pin(_)), "{e}");
    assert!(!e.to_string().contains(wrong), "the PIN is in the message");
    // the same wrong PIN from the environment: the token is not asked again, and nothing is printed
    let (name, pin_var) = ("AEGIS_TEST_PIN_KEY", "AEGIS_TEST_PIN_VAR");
    std::env::set_var(
        format!("{name}_PKCS11"),
        format!(
            "module={};token={label};label={kl};pin_var={pin_var}",
            t.module.display()
        ),
    );
    std::env::set_var(pin_var, wrong);
    let e = aegis_hsm::load(name).err().unwrap();
    assert!(e.contains("PIN") && !e.contains(wrong), "{e}");
    // one wrong PIN did not spoil the right one
    std::env::set_var(pin_var, USER_PIN);
    assert!(aegis_hsm::load(name).is_ok());
    std::env::remove_var(format!("{name}_PKCS11"));
    std::env::remove_var(pin_var);
}

// REQ: CFG-07 — many requests at once, a pool of fewer sessions.
#[test]
fn concurrent_callers_share_the_sessions() {
    each(|t| {
        let key = b"k-concurrent-0123456789abcdef---";
        let label = unique(t, "threads");
        t.put_key(&label, key, false);
        let k = Pkcs11Key::open_with_pin(&t.spec(&label), t.pin()).unwrap();
        let mut hs = vec![];
        for n in 0..8u32 {
            let k = k.clone();
            hs.push(std::thread::spawn(move || {
                for i in 0..60u32 {
                    let data = format!("thread {n} call {i}").into_bytes();
                    assert_eq!(k.mac_raw(&data), expected(key, &data));
                }
            }));
        }
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(k.faults(), 0);
        assert_eq!(k.reconnects(), 0);
    });
}

// REQ: CFG-07 — a session the token dropped (logged out) is replaced without the caller noticing.
#[test]
fn a_lost_login_is_repaired() {
    let Some((slot, label)) = spare() else { return };
    let _turn = SPARE.lock().unwrap_or_else(|e| e.into_inner());
    let t = &tokens()[kryoptic_index()];
    let key = b"k-lost-login-0123456789abcdef---";
    let kl = "lostlogin";
    t.put_key_in(slot, kl, key, false);
    let k = Pkcs11Key::open_with_pin(&t.spec_for(&label, kl), t.pin()).unwrap();
    assert_eq!(k.try_mac_raw(b"one").unwrap(), expected(key, b"one"));
    // the token forgets the login: private objects are gone for every session
    let s = t.ctx.open_rw_session(slot).unwrap();
    s.logout().ok();
    drop(s);
    assert_eq!(k.try_mac_raw(b"two").unwrap(), expected(key, b"two"));
    assert!(k.reconnects() >= 1, "the failure path was not exercised");
    assert_eq!(k.faults(), 0, "a repaired session is not a fault");
    assert!(k.healthy());
}

// REQ: CFG-07 — the key object was replaced in the token while the gateway runs.
#[test]
fn a_replaced_key_object_is_found_again() {
    let Some((slot, label)) = spare() else { return };
    let _turn = SPARE.lock().unwrap_or_else(|e| e.into_inner());
    let t = &tokens()[kryoptic_index()];
    let key = b"k-replaced-obj-0123456789abcdef-";
    let kl = "replaced";
    t.put_key_in(slot, kl, key, false);
    let k = Pkcs11Key::open_with_pin(&t.spec_for(&label, kl), t.pin()).unwrap();
    assert_eq!(k.try_mac_raw(b"one").unwrap(), expected(key, b"one"));
    let s = t.user_session(slot);
    let h = t.find(&s, kl).unwrap();
    s.destroy_object(h).unwrap();
    drop(s);
    t.put_key_in(slot, kl, key, false);
    k.close_sessions_for_test();
    assert_eq!(k.try_mac_raw(b"two").unwrap(), expected(key, b"two"));
    assert_eq!(k.faults(), 0);
}

// REQ: CFG-07 — token gone: the key refuses (zeros, a counter, unhealthy, a pause), then recovers.
#[test]
fn a_token_that_is_gone_fails_closed_and_comes_back() {
    let Some((slot, label)) = spare() else { return };
    let _turn = SPARE.lock().unwrap_or_else(|e| e.into_inner());
    let t = &tokens()[kryoptic_index()];
    let key = b"k-token-gone-0123456789abcdef---";
    let kl = "gone";
    t.init_token(slot, &label);
    t.put_key_in(slot, kl, key, false);
    let k = Pkcs11Key::open_with_pin(&t.spec_for(&label, kl), t.pin()).unwrap();
    let keys = TenantKeys {
        tenant: "t1".into(),
        k_t: Arc::new(k.clone()),
        k_audit: Arc::new(HmacPrf::new(b"k-audit-0123456789abcdef")),
    };
    let mark = keys.fault_mark();
    assert_eq!(k.try_mac_raw(b"before").unwrap(), expected(key, b"before"));
    assert!(!keys.faulted_since(mark));

    // the token is wiped and relabeled, the sessions of the module are gone with it
    k.close_sessions_for_test();
    t.init_token(slot, "aegis-test-2-wiped");
    assert!(k.try_mac_raw(b"after").is_err());
    assert_eq!(
        k.mac_raw(b"after"),
        [0u8; 32],
        "a failed computation must not look like a MAC"
    );
    assert!(
        keys.faulted_since(mark),
        "the request in flight is not told about the failure"
    );
    assert!(!k.healthy());
    assert!(!keys.healthy());
    // at once again: no new trip to the token
    assert!(matches!(k.try_mac_raw(b"again"), Err(HsmError::Down)));

    // the token is back (same label, key provisioned again)
    t.init_token(slot, &label);
    t.put_key_in(slot, kl, key, false);
    // nobody asks for a MAC: the key notices on its own that the token is back (readiness depends on it)
    let start = std::time::Instant::now();
    while !k.healthy() && start.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(k.healthy(), "the key did not notice that the token is back");
    assert_eq!(k.try_mac_raw(b"back").unwrap(), expected(key, b"back"));
    // what was counted stays counted: a request that began before is still refused
    assert!(keys.faulted_since(mark));
    assert!(!keys.faulted_since(keys.fault_mark()));
}

// REQ: CFG-07 — `aegis hsm init`: the key is made inside the token or imported once, and never extractable.
#[test]
fn a_key_is_created_inside_the_token() {
    each(|t| {
        if t.kind != Kind::Kryoptic {
            eprintln!("(this token keeps no persistent objects: create_key not run)");
            return;
        }
        let pin = t.pin().unwrap();
        // generated by the token
        let l1 = unique(t, "generated");
        let spec = t.spec(&l1);
        let info = create_key(&spec, pin, Material::Generate(32)).unwrap();
        assert_eq!((info.bits, info.key_type), (Some(256), "GENERIC_SECRET"));
        let k = Pkcs11Key::open_with_pin(&spec, Some(pin)).unwrap();
        let a = k.try_mac_raw(b"x").unwrap();
        assert_eq!(a, k.try_mac_raw(b"x").unwrap());
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, k.try_mac_raw(b"y").unwrap());
        let s = t.inspector();
        let h = t.find(&s, &l1).unwrap();
        let got = attrs(&s, h, &[AttributeType::Value]);
        assert!(!got.iter().any(|a| matches!(a, Attribute::Value(_))));
        // never replaced
        let e = create_key(&spec, pin, Material::Generate(32)).unwrap_err();
        assert!(e.to_string().contains("уже есть"), "{e}");
        assert_eq!(k.try_mac_raw(b"x").unwrap(), a);
        // imported: pseudonyms and the index built with the old key stay valid
        let l2 = unique(t, "imported");
        let old = b"the-old-file-key-0123456789abcdef";
        create_key(&t.spec(&l2), pin, Material::Import(old)).unwrap();
        let k2 = Pkcs11Key::open_with_pin(&t.spec(&l2), Some(pin)).unwrap();
        assert_eq!(k2.try_mac_raw(b"z").unwrap(), expected(old, b"z"));
        let h2 = t.find(&s, &l2).unwrap();
        assert!(!attrs(&s, h2, &[AttributeType::Value])
            .iter()
            .any(|a| matches!(a, Attribute::Value(_))));
        // too short
        assert!(create_key(&t.spec(&unique(t, "short")), pin, Material::Generate(8)).is_err());
        assert!(create_key(
            &t.spec(&unique(t, "short2")),
            pin,
            Material::Import(b"short")
        )
        .is_err());
    });
}

// REQ: CFG-07 — what a token round trip costs, and what the memo and the shape of the callers do
// with it (the numbers go to the test log; the assertions are loose on purpose).
#[test]
fn a_round_trip_through_the_token_is_measured() {
    each(|t| {
        let key = b"k-timing-0123456789abcdef-------";
        let label = unique(t, "timing");
        t.put_key(&label, key, false);
        let k = Pkcs11Key::open_with_pin(&t.spec(&label), t.pin()).unwrap();
        let per_call = k.measure(2000).unwrap();
        let mem = HmacPrf::new(key);
        let start = std::time::Instant::now();
        for i in 0..2000u32 {
            std::hint::black_box(mem.mac_raw(&i.to_be_bytes()));
        }
        let in_memory = start.elapsed() / 2000;
        // the memo: the same input again does not go to the token
        let _ = k.mac_raw(b"memo");
        let start = std::time::Instant::now();
        for _ in 0..2000 {
            std::hint::black_box(k.mac_raw(b"memo"));
        }
        let memo_hit = start.elapsed() / 2000;
        // the shapes the gateway asks for: an IPv4 host part of a /8 is 24 HMACs (Crypto-PAn)
        let hsm = TenantKeys {
            tenant: "t1".into(),
            k_t: Arc::new(k.clone()),
            k_audit: Arc::new(k.clone()),
        };
        let salt = Salt([3; 32]);
        let start = std::time::Instant::now();
        std::hint::black_box(aegis_core::crypto::pan_bits(
            &hsm,
            &salt,
            b"ip4/0",
            0x0a_22_12_15,
            24,
        ));
        let ipv4 = start.elapsed();
        let start = std::time::Instant::now();
        std::hint::black_box(aegis_core::crypto::pan_bits(
            &hsm,
            &salt,
            b"ip6/low",
            0x1234_5678_9abc_def0_1234,
            80,
        ));
        let ipv6 = start.elapsed();
        let start = std::time::Instant::now();
        for i in 0..100 {
            std::hint::black_box(pseudonym_id(&hsm, &salt, "HOST", &format!("prod-db{i:03}")));
        }
        let hundred_ids = start.elapsed();
        eprintln!(
            "TIMING {:?}: one HMAC through the token {:?} (memory {:?}, memo hit {:?}); Crypto-PAn IPv4/8 host part (24 HMACs) {:?}; IPv6 low 80 bits (80 HMACs) {:?}; 100 pseudonym ids {:?}",
            t.kind, per_call, in_memory, memo_hit, ipv4, ipv6, hundred_ids
        );
        assert!(per_call < Duration::from_millis(50), "{per_call:?}");
        assert!(memo_hit < Duration::from_millis(5), "{memo_hit:?}");
    });
}

/// The kryoptic token with a spare slot, if there is one.
fn spare() -> Option<(cryptoki::slot::Slot, String)> {
    tokens().iter().find_map(|t| t.spare.clone()).or_else(|| {
        eprintln!("SKIPPED: no token with a PIN and C_InitToken (kryoptic) on this machine");
        None
    })
}

fn kryoptic_index() -> usize {
    tokens().iter().position(|t| t.spare.is_some()).unwrap()
}

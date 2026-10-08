//! Real PKCS#11 tokens for the tests: nothing here is a mock.
//!
//! * `kryoptic` (https://github.com/latchset/kryoptic, a software token written in Rust): a full token
//!   with a PIN, persistent objects and `C_InitToken`. Found through `AEGIS_TEST_KRYOPTIC` (the path
//!   of `libkryoptic_pkcs11.so`, see `scripts/build-kryoptic.sh`).
//! * NSS softoken (`libsoftokn3.so`, from the `libnss3` package): found in the usual places. Started
//!   without a database it is a token with no PIN and with session objects only, which is enough for
//!   the mathematics and the attribute checks, not for PIN and reset tests.
//!
//! `AEGIS_TEST_PKCS11_MODULE` can name one more module (kind guessed from the file name). When nothing
//! is found the tests say so and pass: a missing token is not a failure of Aegis. With
//! `AEGIS_REQUIRE_TOKEN=1` (CI) both tokens must be there.
#![allow(dead_code, clippy::unwrap_used)]

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

pub const USER_PIN: &str = "1234-test-user-pin";
pub const SO_PIN: &str = "5678-test-so-pin";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Kryoptic,
    Nss,
}

pub struct Token {
    pub kind: Kind,
    pub module: PathBuf,
    pub ctx: Pkcs11,
    /// The slot and label of the token the tests share.
    pub slot: Slot,
    pub label: String,
    /// A second token that a test may reset (kryoptic only).
    pub spare: Option<(Slot, String)>,
    /// Session objects live as long as the session that made them.
    keep: Mutex<Vec<Session>>,
}

impl Token {
    pub fn spec(&self, key_label: &str) -> aegis_hsm::Pkcs11Spec {
        self.spec_for(&self.label, key_label)
    }

    pub fn spec_for(&self, token: &str, key_label: &str) -> aegis_hsm::Pkcs11Spec {
        format!(
            "module={};token={};label={};sessions=3;timeout_ms=3000",
            self.module.display(),
            token,
            key_label
        )
        .parse()
        .unwrap()
    }

    pub fn pin(&self) -> Option<&'static str> {
        (self.kind == Kind::Kryoptic).then_some(USER_PIN)
    }

    pub fn user_session(&self, slot: Slot) -> Session {
        let s = self.ctx.open_rw_session(slot).unwrap();
        if self.kind == Kind::Kryoptic {
            // (the login belongs to the token, not to the session: it may be there already)
            match s.login(UserType::User, Some(&AuthPin::new(USER_PIN.into()))) {
                Ok(())
                | Err(cryptoki::error::Error::Pkcs11(
                    cryptoki::error::RvError::UserAlreadyLoggedIn,
                    _,
                )) => {}
                Err(e) => panic!("login: {e}"),
            }
        }
        s
    }

    /// Put a key with known bytes into the token, the way the tests need it: never extractable
    /// unless the test wants to see that refused.
    pub fn put_key(&self, label: &str, bytes: &[u8], extractable: bool) -> ObjectHandle {
        self.put_key_in(self.slot, label, bytes, extractable)
    }

    pub fn put_key_in(
        &self,
        slot: Slot,
        label: &str,
        bytes: &[u8],
        extractable: bool,
    ) -> ObjectHandle {
        let persistent = self.kind == Kind::Kryoptic;
        let session = self.user_session(slot);
        let h = session
            .create_object(&[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::GENERIC_SECRET),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Token(persistent),
                Attribute::Private(persistent),
                Attribute::Sensitive(!extractable),
                Attribute::Extractable(extractable),
                Attribute::Sign(true),
                Attribute::Value(bytes.to_vec()),
            ])
            .unwrap();
        if persistent {
            drop(session);
        } else {
            self.keep.lock().unwrap().push(session);
        }
        h
    }

    /// A session logged in as the user, for looking at the key from outside.
    pub fn inspector(&self) -> Session {
        self.user_session(self.slot)
    }

    pub fn find(&self, session: &Session, label: &str) -> Option<ObjectHandle> {
        session
            .find_objects(&[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::Label(label.as_bytes().to_vec()),
            ])
            .unwrap()
            .first()
            .copied()
    }

    /// Wipe and set up a token again, as an administrator would with `softhsm2-util --init-token`.
    pub fn init_token(&self, slot: Slot, label: &str) {
        let so = AuthPin::new(SO_PIN.into());
        self.ctx.init_token(slot, &so, label).unwrap();
        let s = self.ctx.open_rw_session(slot).unwrap();
        s.login(UserType::So, Some(&so)).unwrap();
        s.init_pin(&AuthPin::new(USER_PIN.into())).unwrap();
    }
}

fn candidates() -> Vec<(Kind, PathBuf)> {
    let mut v = vec![];
    if let Ok(p) = std::env::var("AEGIS_TEST_KRYOPTIC") {
        v.push((Kind::Kryoptic, PathBuf::from(p)));
    }
    if let Ok(p) = std::env::var("AEGIS_TEST_PKCS11_MODULE") {
        let kind = if p.contains("kryoptic") {
            Kind::Kryoptic
        } else {
            Kind::Nss
        };
        v.push((kind, PathBuf::from(p)));
    }
    for p in [
        "/usr/lib/x86_64-linux-gnu/libsoftokn3.so",
        "/usr/lib/aarch64-linux-gnu/libsoftokn3.so",
        "/usr/lib64/libsoftokn3.so",
        "/usr/lib/libsoftokn3.so",
    ] {
        v.push((Kind::Nss, PathBuf::from(p)));
    }
    v.retain(|(_, p)| p.exists());
    v.dedup_by(|a, b| a.1 == b.1);
    v
}

fn start(kind: Kind, module: PathBuf) -> Token {
    if kind == Kind::Kryoptic {
        // the token is configured through the environment before the module starts
        let dir = std::env::temp_dir().join(format!("aegis-hsm-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("token.conf");
        let mut text = String::new();
        for n in 1..=2 {
            text.push_str(&format!(
                "[[slots]]\nslot = {n}\ndbtype = \"sqlite\"\ndbargs = \"{}\"\n\n",
                dir.join(format!("slot{n}.sql")).display()
            ));
        }
        std::fs::write(&conf, text).unwrap();
        std::env::set_var("KRYOPTIC_CONF", &conf);
    }
    let ctx = Pkcs11::new(&module).unwrap();
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    let t = match kind {
        Kind::Kryoptic => {
            let slots = ctx.get_all_slots().unwrap();
            assert!(slots.len() >= 2, "kryoptic slots: {slots:?}");
            Token {
                kind,
                module,
                slot: slots[0],
                label: "aegis-test-1".into(),
                spare: Some((slots[1], "aegis-test-2".into())),
                ctx,
                keep: Mutex::new(vec![]),
            }
        }
        Kind::Nss => {
            // slot 1 is the crypto token: no login, session objects
            let slot = ctx
                .get_slots_with_token()
                .unwrap()
                .into_iter()
                .find(|s| {
                    ctx.get_token_info(*s)
                        .map(|i| i.label().trim() == "NSS Generic Crypto Services")
                        .unwrap_or(false)
                })
                .unwrap();
            Token {
                kind,
                module,
                slot,
                label: "NSS Generic Crypto Services".into(),
                spare: None,
                ctx,
                keep: Mutex::new(vec![]),
            }
        }
    };
    if kind == Kind::Kryoptic {
        t.init_token(t.slot, &t.label);
        let (s, l) = t.spare.clone().unwrap();
        t.init_token(s, &l);
    }
    t
}

/// Every token module found on this machine, started once per test process.
pub fn tokens() -> &'static [Token] {
    static TOKENS: OnceLock<Vec<Token>> = OnceLock::new();
    TOKENS.get_or_init(|| {
        // one at a time: starting needs the environment of the module before anything else
        let list = candidates();
        // CI sets this: a missing token there is a broken setup, not a reason to skip
        if std::env::var("AEGIS_REQUIRE_TOKEN").is_ok() {
            assert!(
                list.iter().any(|(k, _)| *k == Kind::Kryoptic),
                "AEGIS_REQUIRE_TOKEN is set but kryoptic was not found (AEGIS_TEST_KRYOPTIC)"
            );
            assert!(
                list.iter().any(|(k, _)| *k == Kind::Nss),
                "AEGIS_REQUIRE_TOKEN is set but NSS softoken was not found (libnss3)"
            );
        }
        if list.is_empty() {
            eprintln!(
                "SKIPPED: no PKCS#11 token module found (set AEGIS_TEST_KRYOPTIC to libkryoptic_pkcs11.so, see scripts/build-kryoptic.sh, or install libnss3)"
            );
        }
        list.into_iter().map(|(k, p)| start(k, p)).collect()
    })
}

/// Run `f` against every token that is available, naming the token on a failure.
pub fn each(f: impl Fn(&Token)) {
    for t in tokens() {
        eprintln!("-- token module {:?} ({:?})", t.module, t.kind);
        f(t);
    }
}

pub fn expected(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut m = Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
    m.update(data);
    m.finalize().into_bytes().into()
}

pub fn attrs(session: &Session, h: ObjectHandle, types: &[AttributeType]) -> Vec<Attribute> {
    session.get_attributes(h, types).unwrap()
}

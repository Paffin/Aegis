//! REQ: CFG-07 — HMAC-SHA256 computed by a PKCS#11 token (`CKM_SHA256_HMAC`) with a key object that
//! cannot be extracted. The key bytes never enter this process: it hands data to the token and gets
//! 32 bytes back.
//!
//! What this holds together:
//! * a small pool of sessions (one operation at a time per session), a wait for a free one with a
//!   limit, so that a stuck token turns into refused requests and not into a growing queue;
//! * reconnection: a session the token no longer knows (reset, token pulled and put back, module
//!   restarted) is thrown away together with every other idle session, and the operation is tried
//!   once more on a new one (the slot is found again by the token label, the key by its label);
//! * a wrong PIN is never tried twice: a token locks after a few of those;
//! * a failure is a failure: `mac` cannot return an error (the [`Prf`] signature), so it returns zeros
//!   and moves a counter that the gateway compares before a request leaves (`TenantKeys::fault_mark`).
//!   After a failure the key refuses at once for a second instead of waiting for the token again.

use crate::spec::Pkcs11Spec;
use aegis_core::crypto::Prf;
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// After a failure the key refuses at once for this long before it asks the token again.
const COOLDOWN: Duration = Duration::from_secs(1);
/// How often an idle key asks the token whether it is still there.
const PROBE_EVERY: Duration = Duration::from_secs(10);
/// ... and while it is down.
const PROBE_EVERY_WHILE_DOWN: Duration = Duration::from_secs(2);
/// One `C_Sign` takes at most this much; longer input goes through `C_SignUpdate` in pieces.
const ONE_SHOT: usize = 16 * 1024;
/// The shortest key the gateway accepts anywhere (SEC-03).
pub const MIN_KEY_BYTES: u64 = 16;

#[derive(Debug)]
pub enum HsmError {
    /// The specification or the PIN source.
    Config(String),
    /// The module cannot be loaded or started.
    Module(String),
    /// No such token, or two of them.
    Token(String),
    /// The token refused the PIN. Not retried.
    Pin(String),
    /// No such key, two of them, or one that is not fit for the purpose.
    Key(String),
    /// A call to the token failed; `true` when a new session may help.
    Op(String, bool),
    /// No free session in time.
    Timeout,
    /// A recent failure; the token is not asked again yet.
    Down,
}

impl std::fmt::Display for HsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HsmError::Config(m) => write!(f, "настройка HSM: {m}"),
            HsmError::Module(m) => write!(f, "модуль PKCS#11: {m}"),
            HsmError::Token(m) => write!(f, "токен: {m}"),
            HsmError::Pin(m) => write!(f, "PIN: {m}"),
            HsmError::Key(m) => write!(f, "ключ в токене: {m}"),
            HsmError::Op(m, _) => write!(f, "токен: {m}"),
            HsmError::Timeout => write!(f, "токен не ответил вовремя"),
            HsmError::Down => write!(f, "токен недоступен (недавний сбой)"),
        }
    }
}

impl std::error::Error for HsmError {}

fn rv_name(e: &Error) -> String {
    match e {
        Error::Pkcs11(rv, f) => format!("{f}: {rv:?}"),
        other => other.to_string(),
    }
}

/// A failure after which a new session (and a fresh look for the token and the key) may help.
fn reconnectable(e: &Error) -> bool {
    matches!(
        e,
        Error::Pkcs11(
            RvError::SessionHandleInvalid
                | RvError::SessionClosed
                | RvError::DeviceRemoved
                | RvError::DeviceError
                | RvError::DeviceMemory
                | RvError::TokenNotPresent
                | RvError::TokenNotRecognized
                | RvError::UserNotLoggedIn
                | RvError::KeyHandleInvalid
                | RvError::ObjectHandleInvalid
                | RvError::CryptokiNotInitialized
                | RvError::SlotIdInvalid
                | RvError::GeneralError
                | RvError::FunctionFailed
                | RvError::OperationNotInitialized,
            _
        )
    )
}

pub(crate) fn op(e: Error) -> HsmError {
    HsmError::Op(rv_name(&e), reconnectable(&e))
}

/// One module is initialized once per process; the keys of a process share it.
pub(crate) fn module(path: &Path) -> Result<Pkcs11, HsmError> {
    static MODULES: OnceLock<Mutex<HashMap<PathBuf, Pkcs11>>> = OnceLock::new();
    let mut m = MODULES
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| HsmError::Module("внутренняя ошибка".into()))?;
    if let Some(p) = m.get(path) {
        return Ok(p.clone());
    }
    let p = Pkcs11::new(path).map_err(|e| HsmError::Module(format!("{}: {e}", path.display())))?;
    match p.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) | Err(Error::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
        Err(e) => {
            return Err(HsmError::Module(format!(
                "{}: C_Initialize: {}",
                path.display(),
                rv_name(&e)
            )))
        }
    }
    m.insert(path.to_path_buf(), p.clone());
    Ok(p)
}

/// PINs a token has rejected in this process, as `SHA-256(module, token, PIN)`. A second key on the
/// same token, opened after the first was refused, must not try the same wrong PIN again: tokens
/// lock after a handful of failures.
fn rejected_pins() -> &'static Mutex<std::collections::HashSet<[u8; 32]>> {
    static SET: OnceLock<Mutex<std::collections::HashSet<[u8; 32]>>> = OnceLock::new();
    SET.get_or_init(Default::default)
}

fn pin_digest(spec: &Pkcs11Spec, pin: &str) -> [u8; 32] {
    Sha256::new()
        .chain_update(spec.module.as_os_str().as_encoded_bytes())
        .chain_update([0])
        .chain_update(spec.token.as_deref().unwrap_or("").as_bytes())
        .chain_update(spec.slot.unwrap_or(u64::MAX).to_be_bytes())
        .chain_update([0])
        .chain_update(pin.as_bytes())
        .finalize()
        .into()
}

/// What the token says about itself and the key; nothing here is secret.
#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub token_label: String,
    pub manufacturer: String,
    pub model: String,
    pub slot: u64,
    pub key_label: String,
    /// `GENERIC_SECRET` or `SHA256_HMAC`.
    pub key_type: &'static str,
    /// Length of the key in bits when the token tells.
    pub bits: Option<u64>,
}

impl std::fmt::Display for KeyInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "токен «{}» ({} {}), слот {}, ключ «{}» {}",
            self.token_label,
            self.manufacturer,
            self.model,
            self.slot,
            self.key_label,
            self.key_type
        )?;
        match self.bits {
            Some(b) => write!(f, " {b} бит, не извлекаемый"),
            None => write!(f, ", не извлекаемый"),
        }
    }
}

/// The slot of the token the specification names.
pub(crate) struct Found {
    pub slot: Slot,
    pub label: String,
    pub manufacturer: String,
    pub model: String,
    pub login_required: bool,
}

pub(crate) fn find_slot(ctx: &Pkcs11, spec: &Pkcs11Spec) -> Result<Found, HsmError> {
    let slots = ctx
        .get_slots_with_token()
        .map_err(|e| HsmError::Token(rv_name(&e)))?;
    let mut hits = vec![];
    for s in slots {
        let Ok(info) = ctx.get_token_info(s) else {
            continue;
        };
        let label = info.label().trim().to_string();
        let wanted = match (&spec.token, spec.slot) {
            (Some(t), _) => *t == label,
            (None, Some(n)) => s.id() == n,
            (None, None) => false,
        };
        if wanted {
            hits.push(Found {
                slot: s,
                label,
                manufacturer: info.manufacturer_id().trim().to_string(),
                model: info.model().trim().to_string(),
                login_required: info.login_required(),
            });
        }
    }
    match hits.len() {
        1 => Ok(hits.remove(0)),
        0 => Err(HsmError::Token(match (&spec.token, spec.slot) {
            (Some(t), _) => format!("токен «{t}» не найден в модуле {}", spec.module.display()),
            (_, Some(n)) => format!("в слоте {n} нет токена"),
            _ => "не указан токен".into(),
        })),
        _ => Err(HsmError::Token(
            "под описание подходит несколько токенов: уточните token или slot".into(),
        )),
    }
}

/// Log in as the user, once per token (the login is shared by all sessions of the process). A PIN
/// the token rejects is reported as [`HsmError::Pin`].
pub(crate) fn login(session: &Session, pin: &AuthPin) -> Result<(), HsmError> {
    match session.login(UserType::User, Some(pin)) {
        Ok(()) | Err(Error::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(()),
        Err(Error::Pkcs11(
            rv @ (RvError::PinIncorrect
            | RvError::PinLocked
            | RvError::PinExpired
            | RvError::PinInvalid
            | RvError::PinLenRange
            | RvError::UserPinNotInitialized),
            _,
        )) => Err(HsmError::Pin(format!("токен не принял PIN ({rv:?})"))),
        Err(e) => Err(op(e)),
    }
}

fn key_template(spec: &Pkcs11Spec) -> Vec<Attribute> {
    let mut t = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::Label(spec.label.as_bytes().to_vec()),
    ];
    if let Some(id) = &spec.id {
        t.push(Attribute::Id(id.clone()));
    }
    t
}

/// The one key object the specification names, checked to be a key that stays in the token.
fn find_key(session: &Session, spec: &Pkcs11Spec) -> Result<(ObjectHandle, KeyInfoPart), HsmError> {
    let found = session.find_objects(&key_template(spec)).map_err(op)?;
    let h = match found.len() {
        1 => found[0],
        0 => {
            return Err(HsmError::Key(format!(
            "объект «{}» не найден (после входа PIN-ом; закрытые объекты видны только после входа)",
            spec.label
        )))
        }
        n => {
            return Err(HsmError::Key(format!(
                "под метку «{}» подходит {n} объектов: задайте id",
                spec.label
            )))
        }
    };
    let attrs = session
        .get_attributes(
            h,
            &[
                AttributeType::KeyType,
                AttributeType::Extractable,
                AttributeType::Sensitive,
                AttributeType::ValueLen,
            ],
        )
        .map_err(op)?;
    let (mut kt, mut ext, mut sens, mut len) = (None, None, None, None);
    for a in attrs {
        match a {
            Attribute::KeyType(k) => kt = Some(k),
            Attribute::Extractable(b) => ext = Some(b),
            Attribute::Sensitive(b) => sens = Some(b),
            Attribute::ValueLen(n) => len = Some(u64::from(n)),
            _ => {}
        }
    }
    let key_type = match kt {
        Some(k) if k == KeyType::GENERIC_SECRET => "GENERIC_SECRET",
        Some(k) if k == KeyType::SHA256_HMAC => "SHA256_HMAC",
        _ => {
            return Err(HsmError::Key(
                "нужен CKK_GENERIC_SECRET или CKK_SHA256_HMAC".into(),
            ))
        }
    };
    // Whoever has the PIN could read an extractable key out with one call, and then the HSM
    // would be a vault with the door open (CFG-07).
    if ext != Some(false) {
        return Err(HsmError::Key(
            "ключ извлекаемый или токен не сообщает CKA_EXTRACTABLE: нужен CKA_EXTRACTABLE=false"
                .into(),
        ));
    }
    if sens != Some(true) {
        return Err(HsmError::Key(
            "ключ не помечен CKA_SENSITIVE=true или токен не сообщает атрибут".into(),
        ));
    }
    if len.is_some_and(|n| n < MIN_KEY_BYTES) {
        return Err(HsmError::Key(format!(
            "ключ короче {MIN_KEY_BYTES} байт (SEC-03)"
        )));
    }
    Ok((
        h,
        KeyInfoPart {
            key_type,
            bits: len.map(|n| n * 8),
        },
    ))
}

pub(crate) struct KeyInfoPart {
    key_type: &'static str,
    bits: Option<u64>,
}

struct Conn {
    session: Session,
    key: ObjectHandle,
    epoch: u64,
}

#[derive(Default)]
struct Pool {
    idle: Vec<Conn>,
    /// Sessions that exist, idle or in use.
    live: usize,
    /// Raised when sessions are thrown away: every older one is thrown away too.
    epoch: u64,
}

struct Memo {
    map: HashMap<[u8; 32], [u8; 32]>,
    cap: usize,
}

struct Inner {
    spec: Pkcs11Spec,
    ctx: Pkcs11,
    /// `None` for a token that needs no login.
    pin: Option<AuthPin>,
    /// Which PIN this is, for the memo of rejected PINs.
    pin_id: [u8; 32],
    pool: Mutex<Pool>,
    free: Condvar,
    faults: AtomicU64,
    reconnects: AtomicU64,
    down: AtomicBool,
    pin_rejected: AtomicBool,
    retry_at: Mutex<Option<Instant>>,
    memo: Mutex<Memo>,
    /// Random per process: the memo is indexed by `SHA-256(nonce ‖ input)`, never by the input.
    nonce: [u8; 32],
}

/// A key held by a PKCS#11 token. Cloning shares the key and its sessions.
#[derive(Clone)]
pub struct Pkcs11Key {
    inner: Arc<Inner>,
    info: Arc<KeyInfo>,
}

impl Inner {
    fn connect(&self, epoch: u64) -> Result<(Conn, KeyInfo), HsmError> {
        let found = find_slot(&self.ctx, &self.spec)?;
        let session = self.ctx.open_ro_session(found.slot).map_err(op)?;
        if found.login_required {
            let Some(pin) = &self.pin else {
                return Err(HsmError::Config(format!(
                    "токен требует PIN: задайте {0}, {0}_FILE или {0}_COMMAND",
                    self.spec.pin_var
                )));
            };
            let digest = self.pin_id;
            if rejected_pins().lock().is_ok_and(|s| s.contains(&digest)) {
                self.pin_rejected.store(true, Ordering::SeqCst);
                return Err(HsmError::Pin(
                    "токен уже отклонил этот PIN в этом процессе, повторной попытки нет".into(),
                ));
            }
            login(&session, pin).inspect_err(|e| {
                if matches!(e, HsmError::Pin(_)) {
                    self.pin_rejected.store(true, Ordering::SeqCst);
                    if let Ok(mut s) = rejected_pins().lock() {
                        s.insert(digest);
                    }
                }
            })?;
        }
        let (key, part) = find_key(&session, &self.spec)?;
        Ok((
            Conn {
                session,
                key,
                epoch,
            },
            KeyInfo {
                token_label: found.label,
                manufacturer: found.manufacturer,
                model: found.model,
                slot: found.slot.id(),
                key_label: self.spec.label.clone(),
                key_type: part.key_type,
                bits: part.bits,
            },
        ))
    }

    fn checkout(&self) -> Result<Conn, HsmError> {
        let deadline = Instant::now() + self.spec.timeout;
        let mut pool = self.pool.lock().map_err(|_| HsmError::Down)?;
        loop {
            while let Some(c) = pool.idle.pop() {
                if c.epoch == pool.epoch {
                    return Ok(c);
                }
                pool.live -= 1;
            }
            if pool.live < self.spec.sessions {
                pool.live += 1;
                let epoch = pool.epoch;
                drop(pool);
                return match self.connect(epoch) {
                    Ok((c, _)) => Ok(c),
                    Err(e) => {
                        if let Ok(mut p) = self.pool.lock() {
                            p.live -= 1;
                        }
                        self.free.notify_one();
                        Err(e)
                    }
                };
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(HsmError::Timeout);
            }
            pool = self
                .free
                .wait_timeout(pool, left)
                .map_err(|_| HsmError::Down)?
                .0;
        }
    }

    fn checkin(&self, c: Conn) {
        if let Ok(mut p) = self.pool.lock() {
            if c.epoch == p.epoch {
                p.idle.push(c);
            } else {
                p.live -= 1;
            }
        }
        self.free.notify_one();
    }

    /// The session is no good, and the others are probably not either.
    fn discard(&self, c: Conn) {
        self.reconnects.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut p) = self.pool.lock() {
            p.live -= 1;
            p.epoch += 1;
        }
        // (what the memo holds came from a key object that may be another one now)
        if let Ok(mut m) = self.memo.lock() {
            m.map.clear();
        }
        self.free.notify_all();
        drop(c);
    }

    fn sign(&self, c: &Conn, data: &[u8]) -> Result<[u8; 32], Error> {
        let mech = Mechanism::Sha256Hmac;
        let out = if data.len() <= ONE_SHOT {
            c.session.sign(&mech, c.key, data)?
        } else {
            c.session.sign_init(&mech, c.key)?;
            for piece in data.chunks(ONE_SHOT) {
                c.session.sign_update(piece)?;
            }
            c.session.sign_final()?
        };
        out.try_into().map_err(|_| Error::InvalidValue)
    }

    /// One HMAC by the token, on a session of the pool; a session that fails is replaced once.
    fn compute(&self, data: &[u8]) -> Result<[u8; 32], HsmError> {
        if self.pin_rejected.load(Ordering::SeqCst) {
            return Err(HsmError::Pin(
                "токен отклонил PIN, повторных попыток нет".into(),
            ));
        }
        if let Ok(g) = self.retry_at.lock() {
            if g.is_some_and(|t| Instant::now() < t) {
                return Err(HsmError::Down);
            }
        }
        for attempt in 0..2 {
            let conn = self.checkout()?;
            match self.sign(&conn, data) {
                Ok(m) => {
                    self.checkin(conn);
                    return Ok(m);
                }
                Err(e) if reconnectable(&e) => {
                    self.discard(conn);
                    if attempt == 1 {
                        return Err(op(e));
                    }
                }
                Err(e) => {
                    self.checkin(conn);
                    return Err(op(e));
                }
            }
        }
        Err(HsmError::Down)
    }

    fn fail(&self, e: &HsmError) {
        self.faults.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut g) = self.retry_at.lock() {
            if !matches!(e, HsmError::Down) {
                *g = Some(Instant::now() + COOLDOWN);
            }
        }
        if !self.down.swap(true, Ordering::SeqCst) {
            tracing::error!(error = %e, "HSM key unavailable; requests that need it are refused");
        }
    }

    fn ok(&self) {
        if self.down.swap(false, Ordering::SeqCst) {
            tracing::info!("HSM key available again");
        }
    }

    fn memo_key(&self, data: &[u8]) -> [u8; 32] {
        Sha256::new()
            .chain_update(self.nonce)
            .chain_update(data)
            .finalize()
            .into()
    }

    fn mac(&self, data: &[u8], use_memo: bool) -> Result<[u8; 32], HsmError> {
        let k = (use_memo && self.spec.memo > 0).then(|| self.memo_key(data));
        if let Some(k) = &k {
            if let Some(v) = self.memo.lock().ok().and_then(|m| m.map.get(k).copied()) {
                return Ok(v);
            }
        }
        match self.compute(data) {
            Ok(v) => {
                self.ok();
                if let (Some(k), Ok(mut m)) = (k, self.memo.lock()) {
                    if m.map.len() >= m.cap {
                        // a whole turn of the memo is dropped at once: cheaper than ordering entries
                        m.map.clear();
                    }
                    m.map.insert(k, v);
                }
                Ok(v)
            }
            Err(e) => {
                self.fail(&e);
                Err(e)
            }
        }
    }
}

impl Pkcs11Key {
    /// Open the key the specification names: load the module, find the token, log in with the PIN
    /// from `AEGIS_HSM_PIN` (or `_FILE`, `_COMMAND`; the name is `pin_var` of the specification),
    /// find the key object, check that it stays in the token and that the token computes with it.
    pub fn open(spec: &Pkcs11Spec) -> Result<Self, HsmError> {
        // (a token that needs no login needs no PIN; whether this one does is known after the
        // token is found)
        let pin = aegis_core::secrets::read(&spec.pin_var)
            .ok()
            .map(Zeroizing::new);
        let pin = match &pin {
            Some(p) => Some(
                std::str::from_utf8(p).map_err(|_| HsmError::Config("PIN не в UTF-8".into()))?,
            ),
            None => None,
        };
        Self::open_with_pin(spec, pin)
    }

    pub fn open_with_pin(spec: &Pkcs11Spec, pin: Option<&str>) -> Result<Self, HsmError> {
        if pin.is_some_and(str::is_empty) {
            return Err(HsmError::Config("PIN пуст".into()));
        }
        let ctx = module(&spec.module)?;
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| HsmError::Config("нет случайных чисел".into()))?;
        let inner = Arc::new(Inner {
            spec: spec.clone(),
            ctx,
            pin: pin.map(|p| AuthPin::new(p.to_string().into_boxed_str())),
            pin_id: pin_digest(spec, pin.unwrap_or("")),
            pool: Mutex::new(Pool {
                live: 1,
                ..Default::default()
            }),
            free: Condvar::new(),
            faults: AtomicU64::new(0),
            reconnects: AtomicU64::new(0),
            down: AtomicBool::new(false),
            pin_rejected: AtomicBool::new(false),
            retry_at: Mutex::new(None),
            memo: Mutex::new(Memo {
                map: HashMap::new(),
                cap: spec.memo,
            }),
            nonce,
        });
        let (conn, info) = inner.connect(0)?;
        // the token must really compute with this key, not only own it
        let probe = inner.sign(&conn, b"aegis-hsm-open").map_err(op)?;
        if probe == [0u8; 32] {
            return Err(HsmError::Key("токен вернул нулевой HMAC".into()));
        }
        inner
            .pool
            .lock()
            .map_err(|_| HsmError::Down)?
            .idle
            .push(conn);
        let key = Self {
            inner,
            info: Arc::new(info),
        };
        key.spawn_probe();
        Ok(key)
    }

    pub fn info(&self) -> &KeyInfo {
        &self.info
    }

    /// How many times a session was thrown away because the token no longer accepted it.
    pub fn reconnects(&self) -> u64 {
        self.inner.reconnects.load(Ordering::SeqCst)
    }

    pub fn spec(&self) -> &Pkcs11Spec {
        &self.inner.spec
    }

    /// An HMAC that reports a failure instead of returning zeros. Not memoized.
    pub fn try_mac_raw(&self, data: &[u8]) -> Result<[u8; 32], HsmError> {
        self.inner.mac(data, false)
    }

    /// The mean time of `n` HMACs of a short input by the token, for sizing. Not memoized.
    pub fn measure(&self, n: usize) -> Result<Duration, HsmError> {
        let n = n.max(1);
        let start = Instant::now();
        for i in 0..n {
            self.try_mac_raw(&(i as u64).to_be_bytes())?;
        }
        Ok(start.elapsed() / n as u32)
    }

    /// A key that is asked now and then notices a token that went away, and a token that came back,
    /// without waiting for a request.
    fn spawn_probe(&self) {
        let weak: Weak<Inner> = Arc::downgrade(&self.inner);
        let _ = std::thread::Builder::new()
            .name("aegis-hsm-probe".into())
            .spawn(move || {
                let mut last = Instant::now();
                loop {
                    std::thread::sleep(Duration::from_millis(200));
                    let Some(inner) = weak.upgrade() else { return };
                    // (a key that is down is asked more often: readiness waits for it)
                    let every = if inner.down.load(Ordering::SeqCst) {
                        PROBE_EVERY_WHILE_DOWN
                    } else {
                        PROBE_EVERY
                    };
                    if last.elapsed() >= every {
                        last = Instant::now();
                        // (a failure is recorded inside)
                        let _ = inner.mac(b"aegis-hsm-probe", false);
                    }
                }
            });
    }

    /// For tests: close every pooled session, as a restart of the module would. The next operation
    /// finds the token again and opens new ones.
    #[doc(hidden)]
    pub fn close_sessions_for_test(&self) {
        let old = match self.inner.pool.lock() {
            Ok(mut p) => {
                p.epoch += 1;
                p.live -= p.idle.len();
                std::mem::take(&mut p.idle)
            }
            Err(_) => return,
        };
        drop(old);
    }
}

impl Prf for Pkcs11Key {
    fn mac_raw(&self, data: &[u8]) -> [u8; 32] {
        self.inner.mac(data, true).unwrap_or([0u8; 32])
    }

    fn faults(&self) -> u64 {
        self.inner.faults.load(Ordering::SeqCst)
    }

    fn healthy(&self) -> bool {
        !self.inner.down.load(Ordering::SeqCst) && !self.inner.pin_rejected.load(Ordering::SeqCst)
    }
}

impl std::fmt::Debug for Pkcs11Key {
    /// INV-6: the specification has no secret, the PIN is not kept in a printable form.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pkcs11Key({})", self.inner.spec.label)
    }
}

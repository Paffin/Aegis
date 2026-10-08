//! REQ: CFG-07 — keys in an HSM over PKCS#11: the token computes the HMAC, the key never enters
//! the memory of Aegis.
//!
//! `NAME_PKCS11` (for `AEGIS_K_TENANT`, `AEGIS_K_AUDIT`) names a key object in a token instead of
//! `NAME`, `NAME_FILE` or `NAME_COMMAND`; the PIN comes from `AEGIS_HSM_PIN` (or `_FILE`,
//! `_COMMAND`). Everything that uses a key goes through [`aegis_core::crypto::Prf`], so the
//! gateway and the CLI do not care where the bytes are.
#![cfg_attr(test, allow(clippy::unwrap_used))]

mod admin;
mod spec;
mod token;

pub use admin::{create_key, Material};
pub use spec::Pkcs11Spec;
pub use token::{HsmError, KeyInfo, Pkcs11Key};

use aegis_core::crypto::{HmacPrf, KeyPair, Prf};
use std::sync::Arc;
use zeroize::Zeroizing;

pub use token::MIN_KEY_BYTES;

/// The key named `name`, as the configuration gives it.
pub enum KeySource {
    /// The bytes, from `NAME`, `NAME_FILE` or `NAME_COMMAND`.
    Bytes(Zeroizing<Vec<u8>>),
    /// A key object in a token, from `NAME_PKCS11`.
    Hsm(Pkcs11Key),
}

/// The HSM description in `NAME_PKCS11`, if there is one. `Err` when it is there and wrong, or when
/// another source of the same key is set too: two sources mean someone forgot to remove one, and
/// guessing which one wins is how a key stays on a disk after it was "moved" to an HSM.
pub fn spec_of(name: &str) -> Option<Result<Pkcs11Spec, String>> {
    let var = format!("{name}_PKCS11");
    let value = std::env::var(&var).ok()?;
    for other in [
        name.to_string(),
        format!("{name}_FILE"),
        format!("{name}_COMMAND"),
    ] {
        if std::env::var(&other).is_ok() {
            return Some(Err(format!(
                "{var} и {other} заданы вместе: оставьте один источник ключа"
            )));
        }
    }
    Some(value.parse().map_err(|e| format!("{var}: {e}")))
}

/// Read the key `name` from wherever it is configured. An HSM key is opened (and so checked) here.
pub fn load(name: &str) -> Result<KeySource, String> {
    match spec_of(name) {
        Some(spec) => {
            let spec = spec?;
            Pkcs11Key::open(&spec)
                .map(KeySource::Hsm)
                .map_err(|e| format!("{name}_PKCS11: {e}"))
        }
        None => aegis_core::secrets::read(name)
            .map(|b| KeySource::Bytes(Zeroizing::new(b)))
            .map_err(|e| format!("{name}: {e}")),
    }
}

impl KeySource {
    pub fn into_prf(self) -> Arc<dyn Prf> {
        match self {
            KeySource::Bytes(b) => Arc::new(HmacPrf::new(&b)),
            KeySource::Hsm(k) => Arc::new(k),
        }
    }

    /// `false` for bytes shorter than [`MIN_KEY_BYTES`]. A key in a token is checked when it is
    /// opened.
    pub fn long_enough(&self) -> bool {
        match self {
            KeySource::Bytes(b) => b.len() as u64 >= MIN_KEY_BYTES,
            KeySource::Hsm(_) => true,
        }
    }
}

/// The key `name` ready to use; a key that is too short is an error.
pub fn load_prf(name: &str) -> Result<Arc<dyn Prf>, String> {
    let k = load(name)?;
    if !k.long_enough() {
        return Err(format!("{name}: ключ короче {MIN_KEY_BYTES} байт"));
    }
    Ok(k.into_prf())
}

/// `AEGIS_K_TENANT` and `AEGIS_K_AUDIT`. They must not be the same key.
pub fn load_pair() -> Result<KeyPair, String> {
    let (t, a) = (spec_of("AEGIS_K_TENANT"), spec_of("AEGIS_K_AUDIT"));
    if let (Some(Ok(t)), Some(Ok(a))) = (&t, &a) {
        if t.identity() == a.identity() {
            return Err("AEGIS_K_TENANT и AEGIS_K_AUDIT указывают на один ключ в токене: ключ аудита должен быть другим".into());
        }
    }
    Ok(KeyPair {
        k_t: load_prf("AEGIS_K_TENANT")?,
        k_audit: load_prf("AEGIS_K_AUDIT")?,
    })
}

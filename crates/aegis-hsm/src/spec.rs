//! REQ: CFG-07 — the description of a key object in a PKCS#11 token, as written in the configuration.
//!
//! `AEGIS_K_TENANT_PKCS11="module=/usr/lib/softhsm/libsofthsm2.so;token=aegis;label=k_t"`.
//! The PIN is not part of it: it comes from `AEGIS_HSM_PIN`, `AEGIS_HSM_PIN_FILE` or
//! `AEGIS_HSM_PIN_COMMAND`, so that nothing printed or logged from the specification can hold it.

use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

/// Sessions opened to the token at most (one HMAC at a time per session).
pub const DEFAULT_SESSIONS: usize = 4;
/// How long a caller waits for a free session, and the longest reconnect it tolerates.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(5000);
/// Results of the last computations kept in memory (outputs of the PRF, indexed by a keyed hash of
/// the input, not by the input).
pub const DEFAULT_MEMO: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkcs11Spec {
    /// The PKCS#11 module (`libsofthsm2.so`, the vendor's library).
    pub module: PathBuf,
    /// The label of the token. Slot numbers change when a token is plugged in again, labels do not.
    pub token: Option<String>,
    /// The slot number, for modules whose tokens have no usable label.
    pub slot: Option<u64>,
    /// `CKA_LABEL` of the secret key object.
    pub label: String,
    /// `CKA_ID` of the key object (hex), when the label is not unique.
    pub id: Option<Vec<u8>>,
    pub sessions: usize,
    pub timeout: Duration,
    /// The name of the variable family that holds the PIN (`NAME`, `NAME_FILE`, `NAME_COMMAND`).
    pub pin_var: String,
    /// 0 turns the memo off.
    pub memo: usize,
}

impl Pkcs11Spec {
    /// Which key object this is, for telling two specifications apart: the audit key must not be
    /// the tenant key.
    pub fn identity(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.module.display(),
            self.token.as_deref().unwrap_or(""),
            self.slot.map(|s| s.to_string()).unwrap_or_default(),
            self.label,
            self.id.as_deref().map(hex).unwrap_or_default()
        )
    }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || s.len() % 2 == 1 || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

impl FromStr for Pkcs11Spec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let mut spec = Pkcs11Spec {
            module: PathBuf::new(),
            token: None,
            slot: None,
            label: String::new(),
            id: None,
            sessions: DEFAULT_SESSIONS,
            timeout: DEFAULT_TIMEOUT,
            pin_var: "AEGIS_HSM_PIN".into(),
            memo: DEFAULT_MEMO,
        };
        let mut seen = std::collections::HashSet::new();
        for (n, part) in s
            .split(';')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .enumerate()
        {
            // (the text of a malformed part is not repeated: someone may have put a PIN there)
            let (k, v) = part
                .split_once('=')
                .ok_or_else(|| format!("часть {} без «=»: ожидается имя=значение", n + 1))?;
            let (k, v) = (k.trim(), v.trim());
            if !seen.insert(k.to_string()) {
                return Err(format!("{k} указан дважды"));
            }
            if v.is_empty() {
                return Err(format!("{k}: пустое значение"));
            }
            let num = |what: &str| {
                v.parse::<u64>()
                    .map_err(|_| format!("{what}: нужно целое число"))
            };
            match k {
                "module" => spec.module = PathBuf::from(v),
                "token" => spec.token = Some(v.to_string()),
                "slot" => spec.slot = Some(num("slot")?),
                "label" => spec.label = v.to_string(),
                "id" => spec.id = Some(unhex(v).ok_or("id: нужна шестнадцатеричная строка")?),
                "sessions" => {
                    let n = num("sessions")?;
                    if !(1..=32).contains(&n) {
                        return Err("sessions: от 1 до 32".into());
                    }
                    spec.sessions = n as usize;
                }
                "timeout_ms" => {
                    let n = num("timeout_ms")?;
                    if !(100..=120_000).contains(&n) {
                        return Err("timeout_ms: от 100 до 120000".into());
                    }
                    spec.timeout = Duration::from_millis(n);
                }
                "pin_var" => {
                    if !v
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                    {
                        return Err("pin_var: имя переменной, A-Z, 0-9 и _".into());
                    }
                    spec.pin_var = v.to_string();
                }
                "memo" => spec.memo = num("memo")?.min(10_000_000) as usize,
                other => {
                    return Err(format!(
                        "неизвестный параметр «{}» (есть module, token, slot, label, id, sessions, timeout_ms, pin_var, memo)",
                        other.chars().take(24).collect::<String>()
                    ))
                }
            }
        }
        if spec.module.as_os_str().is_empty() {
            return Err("не указан module (библиотека PKCS#11)".into());
        }
        if spec.label.is_empty() {
            return Err("не указан label (метка ключа в токене)".into());
        }
        if spec.token.is_none() && spec.slot.is_none() {
            return Err("нужен token (метка токена) или slot".into());
        }
        if spec.token.is_some() && spec.slot.is_some() {
            return Err("token и slot вместе не нужны: оставьте одно".into());
        }
        Ok(spec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: CFG-07
    #[test]
    fn a_specification_is_parsed_and_checked() {
        let s: Pkcs11Spec = "module=/usr/lib/softhsm/libsofthsm2.so; token=aegis ;label=k_t;id=0a0b;sessions=2;timeout_ms=900;memo=0;"
            .parse()
            .unwrap();
        assert_eq!(s.module, PathBuf::from("/usr/lib/softhsm/libsofthsm2.so"));
        assert_eq!(s.token.as_deref(), Some("aegis"));
        assert_eq!((s.label.as_str(), s.sessions, s.memo), ("k_t", 2, 0));
        assert_eq!(s.id, Some(vec![0x0a, 0x0b]));
        assert_eq!(s.timeout, Duration::from_millis(900));
        assert_eq!(s.pin_var, "AEGIS_HSM_PIN");
        // a value may hold `=`
        let s: Pkcs11Spec = "module=/a=b.so;slot=3;label=x".parse().unwrap();
        assert_eq!((s.module, s.slot), (PathBuf::from("/a=b.so"), Some(3)));

        for bad in [
            "",
            "module=/m;label=k",
            "module=/m;token=t",
            "label=k;token=t",
            "module=/m;token=t;slot=1;label=k",
            "module=/m;token=t;label=k;label=j",
            "module=/m;token=t;label=k;pin=1234",
            "module=/m;token=t;label=k;sessions=0",
            "module=/m;token=t;label=k;sessions=99",
            "module=/m;token=t;label=k;timeout_ms=5",
            "module=/m;token=t;label=k;id=xyz",
            "module=/m;token=t;label=k;pin_var=lower",
            "module=/m;token=t;label=",
            "module=/m;token=t;label=k;stray",
        ] {
            assert!(bad.parse::<Pkcs11Spec>().is_err(), "{bad:?}");
        }
        // the specification has no place for a PIN, and says so
        let e = "module=/m;token=t;label=k;pin=1234"
            .parse::<Pkcs11Spec>()
            .unwrap_err();
        assert!(!e.contains("1234"), "{e}");
    }

    // REQ: CFG-07
    #[test]
    fn two_specifications_name_the_same_key_when_they_agree() {
        let a: Pkcs11Spec = "module=/m;token=t;label=k".parse().unwrap();
        let b: Pkcs11Spec = "module=/m;token=t;label=k;sessions=2".parse().unwrap();
        let c: Pkcs11Spec = "module=/m;token=t;label=j".parse().unwrap();
        assert_eq!(a.identity(), b.identity());
        assert_ne!(a.identity(), c.identity());
    }
}

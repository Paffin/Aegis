//! REQ: AGG-05 — Agent Guard devices the gateway trusts, and the check of the token a request carries.

use aegis_core::guardtoken::{self, GuardError};
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use std::collections::HashMap;

/// `guard` in the gateway configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardConfig {
    /// Devices made with `aegis-guard enroll`: the id and the public key (hex).
    pub devices: Vec<GuardDevice>,
    /// How long a token counts, seconds. The specification says five minutes (default). A client that
    /// cannot refresh its credential needs more; the longer, the longer a stolen token is worth something.
    #[serde(default = "d_age")]
    pub max_age_secs: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardDevice {
    pub id: String,
    pub public_key: String,
}

fn d_age() -> i64 {
    300
}

pub struct GuardRegistry {
    devices: HashMap<String, VerifyingKey>,
    max_age: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// A valid token of this device.
    Valid(String),
    /// A token was sent and is not good (expired, unknown device, forged). Treated as no guard.
    Invalid(GuardError),
    Absent,
}

impl GuardRegistry {
    pub fn new(cfg: &GuardConfig) -> Result<Self, String> {
        if !(30..=8 * 3600).contains(&cfg.max_age_secs) {
            return Err("guard.max_age_secs: от 30 секунд до 8 часов".into());
        }
        let mut devices = HashMap::new();
        for d in &cfg.devices {
            if !guardtoken::valid_device_id(&d.id) {
                return Err(format!(
                    "guard: имя устройства «{}»: буквы, цифры, - _, до 40 знаков",
                    d.id
                ));
            }
            let key = crate::bundle_loader::parse_trusted(std::slice::from_ref(&d.public_key))
                .map_err(|e| format!("guard: устройство {}: {e}", d.id))?
                .remove(0);
            if devices.insert(d.id.clone(), key).is_some() {
                return Err(format!("guard: устройство {} указано дважды", d.id));
            }
        }
        if devices.is_empty() {
            return Err("guard.devices: пусто".into());
        }
        Ok(Self {
            devices,
            max_age: cfg.max_age_secs,
        })
    }

    pub fn check(&self, token: Option<&str>, conversation: Option<&str>, now: i64) -> Verdict {
        let Some(t) = token else {
            return Verdict::Absent;
        };
        match guardtoken::verify(
            t,
            &|id| self.devices.get(id).copied(),
            now,
            self.max_age,
            conversation,
        ) {
            Ok(id) => Verdict::Valid(id),
            Err(e) => Verdict::Invalid(e),
        }
    }
}

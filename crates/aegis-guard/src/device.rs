//! REQ: AGG-05 — the device key of this machine: made once by `enroll`, used to sign short tokens.

use aegis_core::guardtoken;
use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};

pub fn default_key_file() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".config/aegis/device.key")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Make a key pair, write the private part (mode 0600, never overwritten), and return the device id
/// and the public key in hex: what the administrator puts into `guard.devices` of the gateway.
pub fn enroll(path: &Path, id: &str) -> Result<(String, String), String> {
    if !guardtoken::valid_device_id(id) {
        return Err("имя устройства: буквы, цифры, - _, до 40 знаков".into());
    }
    if path.exists() {
        return Err(format!(
            "{} уже есть: ключ не перезаписывается (удалите файл, если нужен новый)",
            path.display()
        ));
    }
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("нет случайных чисел: {e}"))?;
    let key = SigningKey::from_bytes(&seed);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let body = format!("{{\"id\":\"{id}\",\"seed\":\"{}\"}}\n", hex(&seed));
    write_private(path, body.as_bytes()).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok((id.to_string(), hex(key.verifying_key().as_bytes())))
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    o.mode(0o600);
    o.open(path)?.write_all(data)
}

pub fn load(path: &Path) -> Result<(String, SigningKey), String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("{}: {e} (сначала `aegis-guard enroll`)", path.display()))?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let id = v["id"]
        .as_str()
        .filter(|i| guardtoken::valid_device_id(i))
        .ok_or("в ключе нет имени устройства")?;
    let seed: [u8; 32] = unhex(v["seed"].as_str().unwrap_or(""))
        .and_then(|b| b.try_into().ok())
        .ok_or("в ключе нет 32 байт")?;
    Ok((id.to_string(), SigningKey::from_bytes(&seed)))
}

pub fn token(path: &Path, conversation: Option<&str>) -> Result<String, String> {
    let (id, key) = load(path)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    Ok(guardtoken::issue(&id, &key, now, conversation))
}

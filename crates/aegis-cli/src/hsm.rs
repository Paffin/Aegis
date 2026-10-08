//! `aegis hsm`: keys in a PKCS#11 token (CFG-07).
//!
//! `init` puts the key object into the token, `check` opens it the way the gateway does and times the
//! token. The token, the module and the key label come from `NAME_PKCS11` (the same variable the
//! gateway reads) or `--spec`; the PIN from `AEGIS_HSM_PIN`, `_FILE` or `_COMMAND`. Neither a PIN
//! nor key bytes are ever printed.

use aegis_hsm::{create_key, Material, Pkcs11Key, Pkcs11Spec};
use zeroize::Zeroizing;

/// The key names the gateway reads.
const NAMES: [&str; 2] = ["AEGIS_K_TENANT", "AEGIS_K_AUDIT"];

fn spec(name: &str, explicit: Option<&str>) -> Result<Pkcs11Spec, String> {
    let text = match explicit {
        Some(s) => s.to_string(),
        None => std::env::var(format!("{name}_PKCS11")).map_err(|_| {
            format!("{name}_PKCS11 не задан (module=…;token=…;label=…) и нет --spec")
        })?,
    };
    text.parse()
        .map_err(|e| format!("описание ключа {name}: {e}"))
}

fn pin(spec: &Pkcs11Spec) -> Result<Zeroizing<String>, String> {
    let raw = aegis_core::secrets::read(&spec.pin_var).map_err(|e| {
        format!(
            "PIN не получен ({e}); задайте {0}, {0}_FILE или {0}_COMMAND",
            spec.pin_var
        )
    })?;
    String::from_utf8(raw)
        .map(Zeroizing::new)
        .map_err(|_| "PIN не в UTF-8".to_string())
}

/// Create the key object. `import`: take the bytes of the key as the gateway reads it today
/// (`NAME`, `NAME_FILE`, `NAME_COMMAND`) so that pseudonyms and the code index stay valid; otherwise
/// the token generates a new random key that exists nowhere else.
pub fn init(name: &str, explicit: Option<&str>, bytes: usize, import: bool) -> Result<(), String> {
    let spec = spec(name, explicit)?;
    let pin = pin(&spec)?;
    let info = if import {
        let key = Zeroizing::new(
            aegis_core::secrets::read(name)
                .map_err(|e| format!("--import: {name} (или _FILE, _COMMAND) не читается: {e}"))?,
        );
        create_key(&spec, &pin, Material::Import(&key)).map_err(|e| e.to_string())?
    } else {
        create_key(&spec, &pin, Material::Generate(bytes)).map_err(|e| e.to_string())?
    };
    println!("ok    {name}: ключ создан: {info}");
    if import {
        println!(
            "      ключ был в памяти этого процесса один раз; удалите его старый источник ({name}, {name}_FILE или {name}_COMMAND) и задайте {name}_PKCS11"
        );
    } else {
        println!(
            "      ключ создан внутри токена и нигде больше не существует: копии нет, сделайте резервную копию токена средствами HSM"
        );
    }
    Ok(())
}

/// Open the keys as the gateway does, report, and time one HMAC. Returns `false` if anything failed.
pub fn check(names: &[String], explicit: Option<&str>) -> Result<bool, String> {
    let names: Vec<String> = if names.is_empty() {
        NAMES
            .iter()
            .filter(|n| std::env::var(format!("{n}_PKCS11")).is_ok())
            .map(|n| n.to_string())
            .collect()
    } else {
        names.to_vec()
    };
    if names.is_empty() && explicit.is_none() {
        return Err("нечего проверять: задайте AEGIS_K_TENANT_PKCS11 или --spec".into());
    }
    let names = if names.is_empty() {
        vec!["--spec".to_string()]
    } else {
        names
    };
    let mut all_ok = true;
    for name in &names {
        let line = spec(name, explicit)
            .map_err(|e| e.to_string())
            .and_then(|s| Pkcs11Key::open(&s).map_err(|e| e.to_string()));
        match line {
            Ok(k) => {
                let t = k.measure(100).map_err(|e| e.to_string());
                match t {
                    Ok(d) => println!(
                        "ok    {name}: {}; HMAC через токен {} мкс (среднее из 100)",
                        k.info(),
                        d.as_micros()
                    ),
                    Err(e) => {
                        all_ok = false;
                        println!("FAIL  {name}: {}; HMAC не вычислен: {e}", k.info());
                    }
                }
            }
            Err(e) => {
                all_ok = false;
                println!("FAIL  {name}: {e}");
            }
        }
    }
    Ok(all_ok)
}

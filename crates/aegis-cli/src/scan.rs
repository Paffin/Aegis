//! `aegis scan`: what would Aegis mask in these files? Runs the same detectors and the same
//! ingress rules as the gateway, locally, with no network and no keys. Values are never printed;
//! `--mask` writes the masked text instead.

use aegis_core::bundle::PolicyDoc;
use aegis_core::crypto::{derive_salt, SaltInput, TenantKeys};
use aegis_core::detect::{DetectConfig, Dictionary, Pipeline};
use aegis_core::policy::{Ingress, IngressPolicy};
use aegis_core::policytest;
use aegis_core::pseudo::{Mapping, PseudoConfig, Pseudonymizer, Source};
use aegis_core::types::Entity;
use std::io::Read;
use std::path::{Path, PathBuf};

const SKIP_DIRS: &[&str] = &[".git", "target", "node_modules", ".venv", "vendor", "dist"];
const MAX_FILE: u64 = 4 * 1024 * 1024;

pub struct Options {
    pub paths: Vec<PathBuf>,
    pub policy: Option<PathBuf>,
    pub zones: Vec<String>,
    pub mask: bool,
    pub json: bool,
}

struct Scanner {
    pipe: Pipeline,
    ingress: IngressPolicy,
    detect: DetectConfig,
}

fn collect(path: &Path, out: &mut Vec<PathBuf>) {
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    if meta.is_file() {
        if meta.len() <= MAX_FILE {
            out.push(path.to_path_buf());
        }
        return;
    }
    let Ok(rd) = std::fs::read_dir(path) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if p.is_dir() && SKIP_DIRS.contains(&name) {
            continue;
        }
        collect(&p, out);
    }
}

fn line_col(text: &str, at: usize) -> (usize, usize) {
    let before = &text[..at];
    let line = before.matches('\n').count() + 1;
    let col = before
        .rfind('\n')
        .map_or(before, |i| &before[i + 1..])
        .chars()
        .count()
        + 1;
    (line, col)
}

fn action_name(a: Ingress) -> &'static str {
    match a {
        Ingress::Allow => "allow",
        Ingress::Mask => "mask",
        Ingress::DropBlock => "drop_block",
        Ingress::BlockRequest => "block_request",
    }
}

pub fn run(o: Options) -> Result<bool, String> {
    let sc = match &o.policy {
        Some(p) => {
            let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
            let doc = PolicyDoc::from_yaml(&text)?;
            let mut c = doc.compile()?;
            Scanner {
                ingress: c.ingress.clone(),
                detect: c.detect.clone(),
                pipe: policytest::pipeline(&mut c),
            }
        }
        None => {
            let detect = DetectConfig {
                internal_zones: o.zones.clone(),
                ..Default::default()
            };
            Scanner {
                pipe: Pipeline::new(detect.clone(), Dictionary::default()),
                ingress: IngressPolicy::default(),
                detect,
            }
        }
    };

    let mut files = vec![];
    let mut stdin = false;
    for p in &o.paths {
        if p.as_os_str() == "-" {
            stdin = true;
        } else {
            collect(p, &mut files);
        }
    }
    if o.mask && files.len() + usize::from(stdin) != 1 {
        return Err("--mask works on exactly one file (or `-` for standard input)".into());
    }

    let mut inputs: Vec<(String, String)> = vec![];
    if stdin {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| format!("stdin: {e}"))?;
        inputs.push(("<stdin>".into(), s));
    }
    for f in files {
        // Binary and non-UTF-8 files are skipped, not guessed at.
        if let Ok(s) = std::fs::read_to_string(&f) {
            inputs.push((f.display().to_string(), s));
        }
    }

    let mut total = 0usize;
    let mut by_type: std::collections::BTreeMap<String, usize> = Default::default();
    let mut files_hit = 0usize;
    for (name, text) in &inputs {
        let ents = sc.pipe.scan(text);
        let mut masked: Vec<Entity> = vec![];
        let mut hit = false;
        for e in ents {
            let (act, rule) = sc.ingress.decide(&e, "scan");
            if act == Ingress::Allow {
                continue;
            }
            hit = true;
            total += 1;
            let ty = e.ty.marker();
            let label = match e.kind {
                Some(k) => format!("{ty}/{k}"),
                None => ty.to_string(),
            };
            *by_type.entry(label.clone()).or_default() += 1;
            let (line, col) = line_col(text, e.span.start);
            if !o.mask {
                if o.json {
                    println!(
                        "{}",
                        serde_json::json!({"file": name, "line": line, "col": col, "type": ty, "kind": e.kind, "action": action_name(act), "rule": rule})
                    );
                } else {
                    println!(
                        "{name}:{line}:{col}  {label:<18} {}  [{rule}]",
                        action_name(act)
                    );
                }
            }
            if act == Ingress::Mask {
                masked.push(e);
            }
        }
        files_hit += usize::from(hit);
        if o.mask {
            // Ephemeral keys: the pseudonyms of this run cannot be linked to any other run.
            let mut k = [0u8; 32];
            getrandom::getrandom(&mut k).map_err(|e| e.to_string())?;
            let keys = TenantKeys::from_secrets("scan", &k, &k);
            let (salt, _) = derive_salt(
                &keys,
                &SaltInput {
                    principal: "cli",
                    header: Some("scan"),
                    session_field: None,
                    first_user_message: &[],
                },
            );
            let cfg = PseudoConfig::default();
            let p = Pseudonymizer {
                keys: &keys,
                salt: &salt,
                cfg: &cfg,
                detect: &sc.detect,
            };
            let mut map = Mapping::default();
            p.register(text, &masked, &Source::User, &mut map);
            print!("{}", p.render(text, &masked, &mut map));
        }
    }

    if !o.mask && !o.json {
        eprintln!();
        if total == 0 {
            eprintln!("Ничего не найдено: {} файлов проверено.", inputs.len());
        } else {
            eprintln!(
                "Найдено {total} в {files_hit} из {} файлов (значения не выводятся):",
                inputs.len()
            );
            for (t, n) in &by_type {
                eprintln!("  {t:<18} {n}");
            }
            eprintln!("Замаскированный текст: aegis scan --mask <файл>");
        }
    }
    Ok(total > 0)
}

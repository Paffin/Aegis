//! `aegis index`: the fingerprint index of closed source code (DET-20, DET-21).
//!
//! `build` reads repositories and writes fingerprints, never code. Running it again for a
//! repository replaces that repository's fingerprints, so a nightly job or a Git hook keeps the
//! index current. The tenant key comes from `AEGIS_K_TENANT` (or `_FILE`, or `_COMMAND`), the same
//! as the gateway's: an index only works with the key it was built with.

use aegis_core::fingerprint::{CodeIndex, Fingerprinter, Repo};
use std::path::{Path, PathBuf};

const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    ".venv",
    "vendor",
    "dist",
    "build",
    "__pycache__",
    ".idea",
];
const CODE: &[&str] = &[
    "rs", "py", "go", "java", "kt", "kts", "scala", "js", "jsx", "ts", "tsx", "c", "h", "cc",
    "cpp", "hpp", "cs", "rb", "php", "swift", "m", "sql", "sh", "lua", "ex", "exs", "clj", "dart",
    "tf", "vue", "svelte", "pl", "r", "zig",
];
const MAX_FILE: u64 = 2 * 1024 * 1024;

pub fn fingerprinter() -> Result<Fingerprinter, String> {
    let key = aegis_core::secrets::read("AEGIS_K_TENANT").map_err(|e| {
        format!(
            "ключ тенанта (AEGIS_K_TENANT, AEGIS_K_TENANT_FILE или AEGIS_K_TENANT_COMMAND): {e}"
        )
    })?;
    if key.len() < 16 {
        return Err("ключ тенанта короче 16 байт".into());
    }
    Ok(Fingerprinter::new(&key))
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let p = e.path();
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            if !SKIP_DIRS.iter().any(|s| e.file_name() == *s) {
                files(&p, out);
            }
        } else if ft.is_file()
            && p.extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| CODE.contains(&x.to_lowercase().as_str()))
            && e.metadata().is_ok_and(|m| m.len() <= MAX_FILE)
        {
            out.push(p);
        }
    }
}

/// `name=path` or `name=path:classification`.
pub fn parse_repo(s: &str) -> Result<(String, PathBuf, String), String> {
    let (name, rest) = s.split_once('=').ok_or("ожидается имя=путь")?;
    let (path, class) = match rest.rsplit_once(':') {
        Some((p, c)) if !c.contains('/') && !c.is_empty() => (p, c),
        _ => (rest, "closed"),
    };
    if name.is_empty() || name.len() > 200 || class.len() > 200 {
        return Err("имя репозитория или классификация слишком длинные или пусты".into());
    }
    Ok((name.to_string(), PathBuf::from(path), class.to_string()))
}

/// Build or update. Prints a line per repository; no code, no file names.
pub fn build(repos: &[String], out: &Path, update: bool) -> Result<(), String> {
    let fp = fingerprinter()?;
    let mut ix = if update && out.exists() {
        CodeIndex::from_bytes(
            &std::fs::read(out).map_err(|e| format!("{}: {e}", out.display()))?,
            &fp,
        )
        .map_err(|e| e.to_string())?
    } else {
        CodeIndex::new(&fp)
    };
    for r in repos {
        let (name, path, class) = parse_repo(r)?;
        let mut list = vec![];
        files(&path, &mut list);
        if list.is_empty() {
            return Err(format!("{name}: в {} нет файлов с кодом", path.display()));
        }
        let mut all = std::collections::BTreeSet::new();
        let mut tokens = 0usize;
        for f in &list {
            let Ok(text) = std::fs::read_to_string(f) else {
                continue;
            };
            let (set, n) = fp.of(&text);
            tokens += n;
            all.extend(set);
        }
        println!(
            "{name}: {} файлов, {tokens} токенов, {} отпечатков, классификация {class}",
            list.len(),
            all.len()
        );
        ix.set_repo(
            Repo {
                name,
                classification: class,
            },
            all,
        )
        .map_err(|e| e.to_string())?;
    }
    // written beside, then moved: a gateway that reads the file never sees half of it
    let tmp = out.with_extension("tmp");
    std::fs::write(&tmp, ix.to_bytes()).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, out).map_err(|e| format!("{}: {e}", out.display()))?;
    println!(
        "индекс: {} репозиториев, {} отпечатков -> {}",
        ix.repos().len(),
        ix.len(),
        out.display()
    );
    Ok(())
}

pub fn info(path: &Path) -> Result<(), String> {
    let fp = fingerprinter()?;
    let ix = CodeIndex::from_bytes(
        &std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?,
        &fp,
    )
    .map_err(|e| e.to_string())?;
    for r in ix.repos() {
        println!("{}: классификация {}", r.name, r.classification);
    }
    println!("{} отпечатков", ix.len());
    Ok(())
}

/// Which repository do these files look like? Prints names and shares, never content.
pub fn check(
    path: &Path,
    targets: &[PathBuf],
    threshold: f32,
    min_tokens: usize,
) -> Result<bool, String> {
    let fp = fingerprinter()?;
    let ix = CodeIndex::from_bytes(
        &std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?,
        &fp,
    )
    .map_err(|e| e.to_string())?;
    let mut list = vec![];
    for t in targets {
        if t.is_dir() {
            files(t, &mut list);
        } else {
            list.push(t.clone());
        }
    }
    let mut found = false;
    for f in list {
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        if let Some(m) = ix.lookup(&fp, &text, threshold, min_tokens) {
            println!(
                "{}: {} ({}), доля {:.0}%",
                f.display(),
                m.repo,
                m.classification,
                m.share * 100.0
            );
            found = true;
        }
    }
    Ok(found)
}

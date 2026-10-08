#![allow(clippy::print_stdout, clippy::print_stderr)]
//! `aegis-guard`. REQ: AGG-01, AGG-04, AGG-06, AGG-07.

use aegis_guard::config::{GuardDoc, Rules};
use aegis_guard::hook::{run, Format};
use std::io::Read;

fn usage() -> ! {
    eprintln!("aegis-guard hook [--config файл] [--format claude-code|generic]\naegis-guard settings [--config файл] [--aegis-guard путь] [--gateway URL] [--vk-file файл] [--sandbox] [--allow-host узел]... [--lock]   настройки Claude Code\naegis-guard install [те же флаги] [--managed-path файл]   записать их в управляемый файл настроек машины (нужен root)\naegis-guard doctor [--config файл] [--aegis-guard путь] [--managed-path файл] [--strict]   держится ли установка\naegis-guard check [--config файл]\naegis-guard enroll [--id имя] [--key-file файл]   ключ этого устройства; печатает строку для guard.devices\naegis-guard token [--key-file файл] [--conversation id]\naegis-guard credential (--vk-file файл | --vk-env ИМЯ) [--key-file файл]   `ключ~токен` для apiKeyHelper");
    std::process::exit(2)
}

fn load(path: Option<String>) -> Result<Rules, String> {
    let path = path.or_else(|| std::env::var("AEGIS_GUARD_CONFIG").ok());
    let candidates: Vec<String> = match path {
        Some(p) => vec![p],
        None => {
            let home = std::env::var("HOME").unwrap_or_default();
            vec![
                format!("{home}/.config/aegis/guard.yaml"),
                "/etc/aegis/guard.yaml".into(),
            ]
        }
    };
    for p in &candidates {
        match std::fs::read_to_string(p) {
            Ok(t) => {
                return GuardDoc::from_yaml(&t)?
                    .compile()
                    .map_err(|e| format!("{p}: {e}"))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && candidates.len() > 1 => continue,
            Err(e) => return Err(format!("{p}: {e}")),
        }
    }
    // no file anywhere: the built-in rules
    GuardDoc::default().compile()
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }
    let cmd = args.remove(0);
    let take = |args: &mut Vec<String>, flag: &str| -> Option<String> {
        let i = args.iter().position(|a| a == flag)?;
        args.remove(i);
        (i < args.len()).then(|| args.remove(i))
    };
    let config = take(&mut args, "--config");
    let format = take(&mut args, "--format");
    let binary = take(&mut args, "--aegis-guard");
    let key_file = take(&mut args, "--key-file")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(aegis_guard::device::default_key_file);
    let fail = |e: String| -> ! {
        eprintln!("aegis-guard: {e}");
        std::process::exit(1)
    };
    match cmd.as_str() {
        "enroll" => {
            let id = take(&mut args, "--id").unwrap_or_else(|| {
                std::env::var("HOSTNAME")
                    .or_else(|_| std::env::var("HOST"))
                    .unwrap_or_else(|_| "device".into())
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
                    .take(40)
                    .collect()
            });
            match aegis_guard::device::enroll(&key_file, &id) {
                Ok((id, public)) => {
                    println!("устройство {id}, ключ записан в {}", key_file.display());
                    println!("добавьте в конфигурацию gateway, раздел guard.devices:");
                    println!("  {{\"id\": \"{id}\", \"public_key\": \"{public}\"}}");
                }
                Err(e) => fail(e),
            }
        }
        "token" => match aegis_guard::device::token(&key_file, take(&mut args, "--conversation").as_deref()) {
            Ok(t) => println!("{t}"),
            Err(e) => fail(e),
        },
        "credential" => {
            let vk = match (take(&mut args, "--vk-file"), take(&mut args, "--vk-env")) {
                (Some(f), None) => std::fs::read_to_string(&f).map_err(|e| format!("{f}: {e}")),
                (None, Some(n)) => std::env::var(&n).map_err(|_| format!("переменная {n} не задана")),
                _ => Err("нужен один из --vk-file и --vk-env".into()),
            };
            match vk.and_then(|v| aegis_guard::device::token(&key_file, None).map(|t| format!("{}~{t}", v.trim()))) {
                Ok(c) => println!("{c}"),
                Err(e) => fail(e),
            }
        }
        "hook" => {
            let fmt = match format.as_deref() {
                None | Some("claude-code") => Format::ClaudeCode,
                Some("generic") => Format::Generic,
                Some(_) => usage(),
            };
            // a guard that cannot load its rules refuses: the rules are the administrator's
            let rules = match load(config) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("aegis-guard: {e}");
                    let d = aegis_guard::decide::Decision {
                        action: aegis_guard::decide::Action::Deny,
                        rule: "G-00".into(),
                        reason: "правила Aegis Guard не загружены".into(),
                    };
                    let (out, code) = aegis_guard::hook::answer(&d, fmt);
                    println!("{out}");
                    std::process::exit(if code == 0 { 2 } else { code });
                }
            };
            let mut input = String::new();
            let _ = std::io::stdin().take(4 << 20).read_to_string(&mut input);
            let home = std::env::var("HOME").unwrap_or_default();
            let cwd = std::env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| "/".into());
            let (out, code) = run(&rules, &input, &home, &cwd, fmt);
            if !out.is_empty() {
                println!("{out}");
            }
            std::process::exit(code);
        }
        "check" => match load(config) {
            Ok(r) => println!(
                "правила загружены: чтение закрыто для {} шаблонов, запись для {}, исключений {}, команд своих {}, узлов в списке {}",
                r.deny_read.len(),
                r.deny_write.len(),
                r.allow.len(),
                r.deny_commands.len(),
                r.allow_hosts.len()
            ),
            Err(e) => {
                eprintln!("aegis-guard: {e}");
                std::process::exit(1)
            }
        },
        "settings" | "install" => {
            let bin = binary.unwrap_or_else(|| "aegis-guard".into());
            let mut allow_hosts = vec![];
            while let Some(h) = take(&mut args, "--allow-host") {
                allow_hosts.push(h);
            }
            let flag = |args: &mut Vec<String>, f: &str| match args.iter().position(|a| a == f) {
                Some(i) => {
                    args.remove(i);
                    true
                }
                None => false,
            };
            let sandbox = flag(&mut args, "--sandbox");
            let lock = flag(&mut args, "--lock");
            let managed_path = take(&mut args, "--managed-path")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(aegis_guard::managed::managed_path);
            let opts = aegis_guard::managed::Options {
                binary: bin,
                // the hook runs as the user: a relative path would point somewhere else
                config: config.as_ref().map(|c| {
                    std::fs::canonicalize(c)
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_else(|_| c.clone())
                }),
                gateway: take(&mut args, "--gateway"),
                vk_file: take(&mut args, "--vk-file"),
                key_file: (key_file != aegis_guard::device::default_key_file())
                    .then(|| key_file.to_string_lossy().into_owned()),
                sandbox,
                allow_hosts,
                rule_hosts: load(config.clone()).map(|r| r.allow_hosts).unwrap_or_default(),
                lock,
            };
            let text = match aegis_guard::managed::claude(&opts) {
                Ok(v) => serde_json::to_string_pretty(&v).unwrap_or_default() + "\n",
                Err(e) => fail(e),
            };
            if cmd == "install" {
                if let Err(e) = aegis_guard::managed::install(&managed_path, &text) {
                    fail(format!("{e} (запись в управляемый файл требует root)"));
                }
                println!("записано: {}", managed_path.display());
                println!("проверьте: aegis-guard doctor --strict --aegis-guard {}", opts.binary);
            } else {
                print!("{text}");
            }
        }
        "doctor" => {
            let strict = args.iter().any(|a| a == "--strict");
            let managed_path = take(&mut args, "--managed-path")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(aegis_guard::managed::managed_path);
            let bin = binary.unwrap_or_else(|| "aegis-guard".into());
            let bin_path = std::fs::canonicalize(&bin).unwrap_or_else(|_| bin.clone().into());
            let cfg = config.as_ref().map(std::path::PathBuf::from);
            let checks = aegis_guard::managed::doctor(&managed_path, &bin_path, cfg.as_deref(), strict);
            let mut bad = 0;
            for c in &checks {
                println!("{} {}", if c.ok { "ok  " } else { "FAIL" }, c.what);
                bad += usize::from(!c.ok);
            }
            if bad > 0 {
                eprintln!("aegis-guard: {bad} из {} проверок не прошли", checks.len());
                std::process::exit(1)
            }
        }
        _ => usage(),
    }
}

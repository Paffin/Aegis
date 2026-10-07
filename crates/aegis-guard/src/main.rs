#![allow(clippy::print_stdout, clippy::print_stderr)]
//! `aegis-guard`. REQ: AGG-01, AGG-04, AGG-06, AGG-07.

use aegis_guard::config::{GuardDoc, Rules};
use aegis_guard::hook::{run, Format};
use std::io::Read;

fn usage() -> ! {
    eprintln!("aegis-guard hook [--config файл] [--format claude-code|generic]\naegis-guard settings [--config файл] [--aegis-guard путь]\naegis-guard check [--config файл]");
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
    match cmd.as_str() {
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
        "settings" => {
            let bin = binary.unwrap_or_else(|| "aegis-guard".into());
            let cfg = config.map(|c| format!(" --config {c}")).unwrap_or_default();
            print!("{}", aegis_guard::hook::claude_settings(&bin, &cfg));
        }
        _ => usage(),
    }
}

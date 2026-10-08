//! REQ: AGG-02, AGG-07 — the decision about one tool call.

use crate::config::{Act, Rules};
use aegis_core::danger;
use aegis_core::policy::{is_shell_tool, Sink};
use aegis_core::shell;
use serde_json::Value;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    Allow,
    Ask,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub action: Action,
    /// `G-01` files read, `G-02` files written, `G-03` commands, `G-04` hosts.
    pub rule: String,
    pub reason: String,
}

impl Decision {
    fn allow() -> Self {
        Decision {
            action: Action::Allow,
            rule: "-".into(),
            reason: String::new(),
        }
    }
}

pub struct Env<'a> {
    pub home: &'a str,
    pub cwd: &'a str,
}

/// The path as the file system will see it: `~` and `$HOME` expanded, relative to the working
/// directory, `.` and `..` resolved, symbolic links resolved when the file exists. The checks
/// look at this form, not at what was written.
pub fn normalize(raw: &str, env: &Env<'_>) -> String {
    let mut p = raw.trim().to_string();
    for var in ["$HOME", "${HOME}"] {
        if p.starts_with(var) {
            p = format!("{}{}", env.home, &p[var.len()..]);
        }
    }
    if p == "~" || p.starts_with("~/") {
        p = format!("{}{}", env.home, &p[1..]);
    }
    let abs = if Path::new(&p).is_absolute() {
        PathBuf::from(&p)
    } else {
        Path::new(env.cwd).join(&p)
    };
    let mut out = PathBuf::new();
    for c in abs.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    // a link to a forbidden file is the file; for a file that does not exist yet, its directory
    let resolved = out.canonicalize().ok().or_else(|| {
        let name = out.file_name()?.to_owned();
        out.parent()?.canonicalize().ok().map(|d| d.join(name))
    });
    resolved.unwrap_or(out).to_string_lossy().into_owned()
}

/// Rules written with `~` mean the user's home.
fn expand_pattern(pat: &str, home: &str) -> String {
    match pat.strip_prefix("~/") {
        Some(rest) => format!("{home}/{rest}"),
        None if pat == "~" => home.to_string(),
        None => pat.to_string(),
    }
}

fn listed(globs: &[crate::config::Glob], path: &str, home: &str) -> Option<String> {
    globs.iter().find_map(|g| {
        let expanded = expand_pattern(&g.1, home);
        let ex = crate::config::Glob::new(&expanded).ok()?;
        ex.matches(path).then(|| g.1.clone())
    })
}

const PATH_KEYS: &[&str] = &[
    "file_path",
    "filePath",
    "path",
    "absolute_path",
    "target_file",
    "notebook_path",
    "filename",
    "file",
];

/// Files a file tool names.
fn tool_paths(input: &Value) -> Vec<String> {
    let mut v = vec![];
    if let Some(o) = input.as_object() {
        for k in PATH_KEYS {
            if let Some(Value::String(s)) = o.get(*k) {
                v.push(s.clone());
            }
        }
        if let Some(Value::Array(files)) = o.get("files") {
            for f in files {
                if let Some(p) = f.get("path").and_then(|p| p.as_str()) {
                    v.push(p.to_string());
                }
            }
        }
    }
    v
}

/// Words of a command that may be paths.
fn path_words(cmd: &str) -> Vec<String> {
    cmd.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '"' | '\'' | ';' | '|' | '&' | '<' | '>' | '(' | ')' | '=' | ','
            )
    })
    .filter(|w| {
        w.starts_with('/')
            || w.starts_with('~')
            || w.starts_with('.')
            || w.starts_with("$HOME")
            || w.contains('/')
    })
    .map(String::from)
    .collect()
}

/// Programs and operators that write the files they are given.
fn writes(cmd: &str) -> bool {
    cmd.contains('>')
        || cmd
            .split(|c: char| c.is_whitespace() || matches!(c, ';' | '|' | '&'))
            .any(|w| {
                matches!(
                    w.rsplit('/').next().unwrap_or(w),
                    "tee"
                        | "cp"
                        | "mv"
                        | "ln"
                        | "install"
                        | "dd"
                        | "truncate"
                        | "touch"
                        | "chmod"
                        | "chown"
                        | "rm"
                        | "rsync"
                )
            })
        || cmd.contains("sed -i")
}

/// AGG-03: the kind of personal data in a command, if any. The gateway restores real values into local
/// commands for a machine that has a guard; this is where the user is asked before they run.
///
/// A small set of patterns, not the detectors of the gateway: those take 40 ms to set up and the
/// decision has 20 ms for everything, the start of the process included (AGG-07).
fn personal_data(cmd: &str) -> Option<&'static str> {
    use regex::Regex;
    use std::sync::OnceLock;
    struct Pats {
        email: Regex,
        phone: Regex,
        id_doc: Regex,
        card: Regex,
    }
    static P: OnceLock<Pats> = OnceLock::new();
    let digits = cmd.chars().filter(|c| c.is_ascii_digit()).count();
    if !cmd.contains('@') && digits < 9 {
        return None;
    }
    let p = P.get_or_init(|| {
        let re = |s: &str| Regex::new(s).expect("static regex");
        Pats {
            email: re(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})*\.[A-Za-z]{2,}"),
            phone: re(r"(?:\+7|\b8)[ \-(]*\d{3}[ \-)]*\d{3}[ \-]*\d{2}[ \-]*\d{2}\b|\+\d{1,3}[ \-(]*\d{2,4}[ \-)]*\d{3}[ \-]*\d{2,4}[ \-]*\d{2,4}\b"),
            id_doc: re(r"(?i)(паспорт|инн|снилс|passport|tax id)[^0-9\n]{0,25}(\d[\d \-]{7,18}\d)"),
            card: re(r"\b(?:\d[ \-]?){13,19}\b"),
        }
    });
    if p.email.is_match(cmd) {
        return Some("почта");
    }
    if p.phone.is_match(cmd) {
        return Some("телефон");
    }
    if let Some(c) = p.id_doc.captures(cmd) {
        return Some(match c[1].to_lowercase().as_str() {
            "паспорт" | "passport" => "паспорт",
            "снилс" => "СНИЛС",
            _ => "ИНН",
        });
    }
    // a card number is a run of 13-19 digits that passes the Luhn check
    for m in p.card.find_iter(cmd) {
        let d: Vec<u32> = m.as_str().chars().filter_map(|c| c.to_digit(10)).collect();
        if (13..=19).contains(&d.len()) && luhn(&d) {
            return Some("номер карты");
        }
    }
    None
}

fn luhn(d: &[u32]) -> bool {
    let sum: u32 = d
        .iter()
        .rev()
        .enumerate()
        .map(|(i, x)| {
            if i % 2 == 1 {
                let y = x * 2;
                if y > 9 {
                    y - 9
                } else {
                    y
                }
            } else {
                *x
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

fn worst(a: Decision, b: Decision) -> Decision {
    if b.action > a.action {
        b
    } else {
        a
    }
}

fn asked(a: Act) -> Action {
    match a {
        Act::Ask => Action::Ask,
        Act::Deny => Action::Deny,
    }
}

pub fn decide(rules: &Rules, env: &Env<'_>, tool: &str, input: &Value) -> Decision {
    let mut d = Decision::allow();
    let sink = Sink::from_tool(tool);

    // files named by the call
    if matches!(sink, Some(Sink::FileRead | Sink::FileWrite)) {
        for raw in tool_paths(input) {
            let p = normalize(&raw, env);
            if listed(&rules.allow, &p, env.home).is_some() {
                continue;
            }
            let write = sink == Some(Sink::FileWrite);
            let hit = listed(&rules.deny_read, &p, env.home)
                .map(|g| ("G-01", g))
                .or_else(|| {
                    if write {
                        listed(&rules.deny_write, &p, env.home).map(|g| ("G-02", g))
                    } else {
                        None
                    }
                });
            if let Some((rule, g)) = hit {
                d = worst(
                    d,
                    Decision {
                        action: asked(rules.path_action),
                        rule: rule.into(),
                        reason: format!(
                            "{} файла по правилу {g}: {p}",
                            if rule == "G-01" {
                                "чтение"
                            } else {
                                "запись"
                            }
                        ),
                    },
                );
            }
        }
    }

    // commands
    let command =
        if is_shell_tool(tool) || input.get("command").is_some() || input.get("cmd").is_some() {
            ["command", "cmd"]
                .iter()
                .find_map(|k| match input.get(*k) {
                    Some(Value::String(s)) => Some(s.clone()),
                    Some(Value::Array(a)) => Some(
                        a.iter()
                            .filter_map(|x| x.as_str())
                            .collect::<Vec<_>>()
                            .join(" "),
                    ),
                    _ => None,
                })
                .or_else(|| match input.get("commands") {
                    Some(Value::Array(a)) => Some(
                        a.iter()
                            .filter_map(|x| x.as_str())
                            .collect::<Vec<_>>()
                            .join("\n"),
                    ),
                    _ => None,
                })
        } else {
            None
        };
    if let Some(cmd) = command {
        if let Some(id) = danger::dangerous(&cmd, &rules.deny_commands) {
            d = worst(
                d,
                Decision {
                    action: asked(rules.command_action),
                    rule: "G-03".into(),
                    reason: format!("опасная команда ({id})"),
                },
            );
        }
        if let (Some(act), Some(kind)) = (rules.personal_data, personal_data(&cmd)) {
            d = worst(
                d,
                Decision {
                    action: asked(act),
                    rule: "G-05".into(),
                    reason: format!(
                        "в команде персональные данные ({kind}); подтвердите выполнение"
                    ),
                },
            );
        }
        let write = writes(&cmd);
        for w in path_words(&cmd) {
            let p = normalize(&w, env);
            if listed(&rules.allow, &p, env.home).is_some() {
                continue;
            }
            let hit = listed(&rules.deny_read, &p, env.home)
                .map(|g| ("G-01", g))
                .or_else(|| {
                    if write {
                        listed(&rules.deny_write, &p, env.home).map(|g| ("G-02", g))
                    } else {
                        None
                    }
                });
            if let Some((rule, g)) = hit {
                d = worst(
                    d,
                    Decision {
                        action: asked(rules.path_action),
                        rule: rule.into(),
                        reason: format!("команда обращается к {p} (правило {g})"),
                    },
                );
            }
        }
        let a = shell::analyze(&cmd);
        if a.class == shell::ShellClass::Network {
            for h in &a.destinations {
                if !rules.host_allowed(h) || h == "!ambiguous" {
                    d = worst(
                        d,
                        Decision {
                            action: asked(rules.host_action),
                            rule: "G-04".into(),
                            reason: format!("обращение к узлу вне списка: {h}"),
                        },
                    );
                }
            }
        }
    }

    // fetches
    if sink == Some(Sink::Network) {
        let urls: Vec<String> = ["url", "uri", "href"]
            .iter()
            .filter_map(|k| input.get(*k).and_then(|v| v.as_str()).map(String::from))
            .collect();
        for u in urls {
            for h in shell::url_destinations(&u) {
                if !rules.host_allowed(&h) || h == "!ambiguous" {
                    d = worst(
                        d,
                        Decision {
                            action: asked(rules.host_action),
                            rule: "G-04".into(),
                            reason: format!("обращение к узлу вне списка: {h}"),
                        },
                    );
                }
            }
        }
    }
    d
}

//! REQ: AGG-02 — the rules, strict YAML. The defaults are what a company wants even before it
//! writes a line: keys and cloud credentials are not read, shell start-up files and hooks are not
//! written, dangerous commands ask a human.

use regex::Regex;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct GuardDoc {
    #[serde(default = "one")]
    pub version: u32,
    #[serde(default)]
    pub paths: PathsDoc,
    #[serde(default)]
    pub commands: CommandsDoc,
    #[serde(default)]
    pub network: NetworkDoc,
}

fn one() -> u32 {
    1
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PathsDoc {
    /// Added to the built-in list of files that are never read.
    #[serde(default)]
    pub deny_read: Vec<String>,
    /// Added to the built-in list of files that are never written.
    #[serde(default)]
    pub deny_write: Vec<String>,
    /// Exceptions to both lists (a test key in the repository, for example).
    #[serde(default)]
    pub allow: Vec<String>,
    /// `ask` (default) or `deny` for a path on the lists.
    #[serde(default)]
    pub action: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CommandsDoc {
    /// More patterns (regular expressions over the command text) that need a decision.
    #[serde(default)]
    pub deny: Vec<String>,
    /// What happens to a dangerous command (built-in list and `deny`): `ask` (default), `deny`.
    #[serde(default)]
    pub action: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NetworkDoc {
    /// Hosts a command or a fetch may contact; `*.corp.local` and exact names. Empty: no
    /// restriction on hosts.
    #[serde(default)]
    pub allow_hosts: Vec<String>,
    /// What happens to a host that is not on the list: `ask` (default) or `deny`.
    #[serde(default)]
    pub action: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Act {
    Ask,
    Deny,
}

fn act(name: &str, v: &Option<String>) -> Result<Act, String> {
    match v.as_deref() {
        None | Some("ask") => Ok(Act::Ask),
        Some("deny") => Ok(Act::Deny),
        Some(o) => Err(format!("{name}: «{o}», нужно ask или deny")),
    }
}

pub struct Glob(Regex, pub String);

impl Glob {
    /// `**` crosses directories, `*` and `?` do not.
    pub fn new(pattern: &str) -> Result<Self, String> {
        // `dir/**` is the directory and everything below it
        if let Some(dir) = pattern.strip_suffix("/**") {
            let inner = Glob::new(dir)?;
            let body = inner
                .0
                .as_str()
                .trim_start_matches('^')
                .trim_end_matches('$')
                .to_string();
            return Regex::new(&format!("^{body}(?:/.*)?$"))
                .map(|r| Glob(r, pattern.to_string()))
                .map_err(|e| format!("шаблон «{pattern}»: {e}"));
        }
        let mut re = String::from("^");
        let c: Vec<char> = pattern.chars().collect();
        let mut i = 0;
        while i < c.len() {
            match c[i] {
                '*' if c.get(i + 1) == Some(&'*') => {
                    i += 1;
                    // `dir/**` matches the directory's contents and the directory itself
                    re.push_str(".*");
                }
                '*' => re.push_str("[^/]*"),
                '?' => re.push_str("[^/]"),
                ch => re.push_str(&regex::escape(&ch.to_string())),
            }
            i += 1;
        }
        re.push('$');
        Regex::new(&re)
            .map(|r| Glob(r, pattern.to_string()))
            .map_err(|e| format!("шаблон «{pattern}»: {e}"))
    }

    pub fn matches(&self, path: &str) -> bool {
        self.0.is_match(path)
    }
}

pub struct Rules {
    pub deny_read: Vec<Glob>,
    pub deny_write: Vec<Glob>,
    pub allow: Vec<Glob>,
    pub path_action: Act,
    pub deny_commands: Vec<Regex>,
    pub command_action: Act,
    pub allow_hosts: Vec<String>,
    pub host_action: Act,
}

/// Never read: credentials and keys of the user.
const READ: &[&str] = &[
    "~/.ssh/**",
    "~/.aws/**",
    "~/.kube/**",
    "~/.config/gcloud/**",
    "~/.azure/**",
    "~/.docker/config.json",
    "~/.netrc",
    "~/.gnupg/**",
    "~/.git-credentials",
    "~/.npmrc",
    "~/.pypirc",
    "/etc/shadow",
    "/etc/sudoers",
    "**/id_rsa",
    "**/id_ed25519",
    "**/*.pem",
    "**/*.p12",
];
/// Never written: what runs by itself later, and what opens doors.
const WRITE: &[&str] = &[
    "~/.ssh/**",
    "~/.bashrc",
    "~/.bash_profile",
    "~/.zshrc",
    "~/.zprofile",
    "~/.profile",
    "~/.config/fish/**",
    "~/.gitconfig",
    "~/.config/git/**",
    "**/.git/hooks/**",
    "/etc/**",
    "~/Library/LaunchAgents/**",
    "~/.config/systemd/**",
    "~/.claude/settings.json",
    "~/.claude/settings.local.json",
    "**/.claude/settings.json",
    "**/.claude/settings.local.json",
    "~/.codex/config.toml",
];

impl GuardDoc {
    pub fn from_yaml(text: &str) -> Result<GuardDoc, String> {
        let d: GuardDoc = serde_yaml_ng::from_str(text).map_err(|e| format!("правила: {e}"))?;
        if d.version != 1 {
            return Err(format!("правила: версия {} не поддерживается", d.version));
        }
        Ok(d)
    }

    pub fn compile(&self) -> Result<Rules, String> {
        let globs = |defaults: &[&str], extra: &[String]| -> Result<Vec<Glob>, String> {
            defaults
                .iter()
                .map(|s| s.to_string())
                .chain(extra.iter().cloned())
                .map(|p| Glob::new(&p))
                .collect()
        };
        Ok(Rules {
            deny_read: globs(READ, &self.paths.deny_read)?,
            deny_write: globs(WRITE, &self.paths.deny_write)?,
            allow: globs(&[], &self.paths.allow)?,
            path_action: act("paths.action", &self.paths.action)?,
            deny_commands: self
                .commands
                .deny
                .iter()
                .map(|p| {
                    regex::RegexBuilder::new(p)
                        .size_limit(1 << 20)
                        .build()
                        .map_err(|e| format!("commands.deny: «{p}»: {e}"))
                })
                .collect::<Result<_, _>>()?,
            command_action: act("commands.action", &self.commands.action)?,
            allow_hosts: self
                .network
                .allow_hosts
                .iter()
                .map(|h| h.to_lowercase())
                .collect(),
            host_action: act("network.action", &self.network.action)?,
        })
    }
}

impl Rules {
    pub fn host_allowed(&self, host: &str) -> bool {
        if self.allow_hosts.is_empty() {
            return true;
        }
        let h = host.to_lowercase();
        self.allow_hosts.iter().any(|p| match p.strip_prefix("*.") {
            Some(suffix) => h.ends_with(&format!(".{suffix}")) || h == suffix,
            None => *p == h,
        })
    }
}

//! REQ: AGG-04, AGG-06 — the settings that put the guard on a machine so that the user cannot turn it
//! off, the sandbox with a network policy, and `doctor`, which checks that the installation holds.
//!
//! Claude Code reads a *managed* settings file that has the highest rank: a user, a project or a command
//! line flag cannot override it (`scripts/client-claude-managed.sh` proves that on the real client). The
//! hook only helps while three things stay out of the user's reach: that file, the guard binary and its
//! rules. `doctor` looks at all three.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// What `aegis-guard settings` and `install` put into the managed settings.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Path of the guard binary as the client will start it.
    pub binary: String,
    /// Rules file (`--config` of the hook).
    pub config: Option<String>,
    /// Address of the gateway: `ANTHROPIC_BASE_URL` of the client.
    pub gateway: Option<String>,
    /// File with the virtual key: the client asks `aegis-guard credential` for `key~token` (AGG-05).
    pub vk_file: Option<String>,
    /// Device key (default `~/.config/aegis/device.key`).
    pub key_file: Option<String>,
    /// Turn the client's sandbox on with a network policy (AGG-04).
    pub sandbox: bool,
    /// Hosts that commands in the sandbox may reach: `network.allow_hosts` of the rules plus these.
    pub allow_hosts: Vec<String>,
    /// Hosts from the rules file.
    pub rule_hosts: Vec<String>,
    /// Keep the user from switching the protection off (AGG-06): only managed hooks run, the bypass
    /// mode of permissions is closed.
    pub lock: bool,
}

/// Where Claude Code looks for the managed settings on this system.
pub fn managed_path() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/ClaudeCode/managed-settings.json")
    } else if cfg!(windows) {
        PathBuf::from(r"C:\Program Files\ClaudeCode\managed-settings.json")
    } else {
        PathBuf::from("/etc/claude-code/managed-settings.json")
    }
}

/// `https://aegis.corp.local:8443/x` -> `aegis.corp.local`.
pub fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let auth = rest.split(['/', '?', '#']).next()?;
    let auth = auth.rsplit('@').next()?;
    let host = if let Some(v6) = auth.strip_prefix('[') {
        v6.split(']').next()?
    } else {
        auth.split(':').next()?
    };
    (!host.is_empty()).then(|| host.to_lowercase())
}

fn quote(s: &str) -> String {
    if s.is_empty() || s.contains(|c: char| c.is_whitespace() || "\"'\\".contains(c)) {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        s.to_string()
    }
}

/// The managed settings for Claude Code.
pub fn claude(o: &Options) -> Result<Value, String> {
    let mut v: Value = serde_json::from_str(&crate::hook::claude_settings(
        &quote(&o.binary),
        &o.config
            .as_ref()
            .map(|c| format!(" --config {}", quote(c)))
            .unwrap_or_default(),
    ))
    .map_err(|e| e.to_string())?;
    let gateway_host = match &o.gateway {
        Some(g) => Some(host_of(g).ok_or("адрес gateway: нужен вид https://узел[:порт]")?),
        None => None,
    };
    if let Some(g) = &o.gateway {
        v["env"] = json!({"ANTHROPIC_BASE_URL": g});
    }
    if let Some(f) = &o.vk_file {
        let key = o
            .key_file
            .as_ref()
            .map(|k| format!(" --key-file {}", quote(k)))
            .unwrap_or_default();
        v["apiKeyHelper"] = json!(format!(
            "{} credential --vk-file {}{key}",
            quote(&o.binary),
            quote(f)
        ));
    }
    if o.lock {
        v["allowManagedHooksOnly"] = json!(true);
        v["permissions"]["disableBypassPermissionsMode"] = json!("disable");
    }
    if o.sandbox {
        let mut hosts: Vec<String> = vec![];
        for h in gateway_host
            .iter()
            .chain(&o.rule_hosts)
            .chain(&o.allow_hosts)
        {
            let h = h.to_lowercase();
            if !hosts.contains(&h) {
                hosts.push(h);
            }
        }
        v["sandbox"] = json!({
            "enabled": true,
            // no sandbox on this machine is a stop, not a silent run without one
            "failIfUnavailable": true,
            // a command that did not fit the sandbox is not run outside it
            "allowUnsandboxedCommands": false,
            "network": {
                "allowedDomains": hosts,
                "allowManagedDomainsOnly": true,
            },
            "filesystem": {
                "denyRead": ["~/.ssh", "~/.aws", "~/.kube", "~/.config/gcloud", "~/.gnupg", "~/.netrc"],
                "denyWrite": ["~/.bashrc", "~/.zshrc", "~/.profile", "~/.gitconfig"],
            },
        });
    }
    Ok(v)
}

/// Write the file so that a reader never sees half of it.
pub fn install(path: &Path, text: &str) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).map_err(|e| format!("{}: {e}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

#[derive(Debug)]
pub struct Check {
    pub ok: bool,
    pub what: String,
}

fn check(out: &mut Vec<Check>, ok: bool, what: impl Into<String>) {
    out.push(Check {
        ok,
        what: what.into(),
    });
}

/// Is this path out of the reach of an ordinary user: owned by root, not writable by group or others?
/// `None` when the system has no such notion (not Unix) or the path is missing.
#[cfg(unix)]
fn closed(path: &Path) -> Option<Result<(), String>> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).ok()?;
    if m.uid() != 0 {
        return Some(Err(format!("владелец не root (uid {})", m.uid())));
    }
    if m.mode() & 0o022 != 0 {
        return Some(Err(format!(
            "права {:o}: запись открыта группе или всем",
            m.mode() & 0o777
        )));
    }
    Some(Ok(()))
}

#[cfg(not(unix))]
fn closed(_: &Path) -> Option<Result<(), String>> {
    None
}

fn closed_chain(out: &mut Vec<Check>, label: &str, path: &Path) {
    // the file and every directory above it: a user who owns the directory renames the file
    let mut p = Some(path);
    while let Some(cur) = p {
        if cur.as_os_str().is_empty() {
            break;
        }
        match closed(cur) {
            Some(Err(e)) => {
                check(out, false, format!("{label}: {} — {e}", cur.display()));
                return;
            }
            Some(Ok(())) => {}
            None => {}
        }
        p = cur.parent();
    }
    check(
        out,
        true,
        format!("{label}: вне досягаемости обычного пользователя"),
    );
}

/// AGG-06: does the installation on this machine hold? Looks at the managed file, the binary, the rules.
pub fn doctor(managed: &Path, binary: &Path, config: Option<&Path>, strict: bool) -> Vec<Check> {
    let mut out = vec![];
    let text = std::fs::read_to_string(managed);
    match &text {
        Err(e) => check(
            &mut out,
            false,
            format!("управляемый файл настроек {}: {e}", managed.display()),
        ),
        Ok(t) => match serde_json::from_str::<Value>(t) {
            Err(e) => check(
                &mut out,
                false,
                format!("{}: не JSON: {e}", managed.display()),
            ),
            Ok(v) => {
                let cmd = v["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
                    .as_str()
                    .unwrap_or("");
                check(
                    &mut out,
                    cmd.contains(&binary.to_string_lossy().to_string()) && cmd.contains(" hook"),
                    "хук PreToolUse запускает этот aegis-guard",
                );
                check(
                    &mut out,
                    v["hooks"]["PreToolUse"][0]["matcher"] == "*",
                    "хук стоит на всех инструментах",
                );
                check(
                    &mut out,
                    v["allowManagedHooksOnly"] == true,
                    "пользовательские и проектные хуки не запускаются (allowManagedHooksOnly)",
                );
                check(
                    &mut out,
                    v["permissions"]["disableBypassPermissionsMode"] == "disable",
                    "режим без запросов закрыт (disableBypassPermissionsMode)",
                );
                if v.get("sandbox").is_some() {
                    check(
                        &mut out,
                        v["sandbox"]["enabled"] == true
                            && v["sandbox"]["allowUnsandboxedCommands"] == false,
                        "песочница включена, команды вне песочницы не запускаются",
                    );
                    check(
                        &mut out,
                        v["sandbox"]["network"]["allowManagedDomainsOnly"] == true
                            && v["sandbox"]["network"]["allowedDomains"]
                                .as_array()
                                .is_some_and(|a| !a.is_empty()),
                        "сетевая политика песочницы задана только управляемыми настройками",
                    );
                } else {
                    check(
                        &mut out,
                        !strict,
                        "песочница не настроена (--sandbox при установке)",
                    );
                }
            }
        },
    }
    if strict {
        if let Some(r) = closed(managed) {
            check(
                &mut out,
                r.is_ok(),
                format!(
                    "управляемый файл закрыт для записи: {}",
                    r.err().unwrap_or_else(|| "root, права 0644".into())
                ),
            );
        }
        closed_chain(&mut out, "бинарник aegis-guard", binary);
        if let Some(c) = config {
            closed_chain(&mut out, "правила", c);
        }
    }
    check(
        &mut out,
        binary.is_file(),
        format!("бинарник {} есть", binary.display()),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_of_url() {
        assert_eq!(
            host_of("https://Aegis.Corp.local:8443/x").as_deref(),
            Some("aegis.corp.local")
        );
        assert_eq!(host_of("http://u:p@10.0.0.1/").as_deref(), Some("10.0.0.1"));
        assert_eq!(host_of("http://[::1]:80/").as_deref(), Some("::1"));
        assert_eq!(host_of("nonsense"), None);
    }

    // REQ: AGG-04, AGG-06 — locked settings with a sandbox and a network policy
    #[test]
    fn locked_sandbox_settings() {
        let o = Options {
            binary: "/usr/local/bin/aegis-guard".into(),
            config: Some("/etc/aegis/guard.yaml".into()),
            gateway: Some("https://aegis.corp.local:8443".into()),
            vk_file: Some("/etc/aegis/vk".into()),
            sandbox: true,
            lock: true,
            rule_hosts: vec!["*.corp.local".into()],
            allow_hosts: vec!["pypi.org".into(), "aegis.corp.local".into()],
            ..Default::default()
        };
        let v = claude(&o).unwrap();
        assert_eq!(
            v["env"]["ANTHROPIC_BASE_URL"],
            "https://aegis.corp.local:8443"
        );
        assert_eq!(v["allowManagedHooksOnly"], true);
        assert_eq!(v["permissions"]["disableBypassPermissionsMode"], "disable");
        assert_eq!(
            v["apiKeyHelper"],
            "/usr/local/bin/aegis-guard credential --vk-file /etc/aegis/vk"
        );
        let hosts = v["sandbox"]["network"]["allowedDomains"].to_string();
        assert_eq!(hosts, r#"["aegis.corp.local","*.corp.local","pypi.org"]"#);
        assert_eq!(v["sandbox"]["allowUnsandboxedCommands"], false);
        assert_eq!(v["sandbox"]["failIfUnavailable"], true);
        // the hook stays
        assert!(v["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .ends_with("hook --config /etc/aegis/guard.yaml"));
    }

    // REQ: AGG-06 — an address that is not a URL is refused at install time
    #[test]
    fn a_bad_gateway_address_is_refused() {
        let o = Options {
            binary: "aegis-guard".into(),
            gateway: Some("aegis.corp.local".into()),
            ..Default::default()
        };
        assert!(claude(&o).is_err());
    }

    #[test]
    fn paths_with_spaces_are_quoted() {
        let o = Options {
            binary: "/opt/Aegis Guard/aegis-guard".into(),
            config: Some("/etc/aegis/guard.yaml".into()),
            ..Default::default()
        };
        let v = claude(&o).unwrap();
        assert!(v["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .starts_with("\"/opt/Aegis Guard/aegis-guard\" hook"));
    }
}

//! REQ: AGG-01 — the hook protocol of Claude Code (`PreToolUse`) and a plain one.
//!
//! Claude Code starts the hook with the call as JSON on standard input. An answer `allow` would
//! skip the user's own permission prompts, so the guard never says it: when it has nothing
//! against a call it prints nothing, and the client decides as it would have without the guard.

use crate::config::Rules;
use crate::decide::{decide, Action, Decision, Env};
use serde_json::{json, Value};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Format {
    ClaudeCode,
    Generic,
}

/// The call as the client sends it. `Err` when it is not a tool call the guard can read.
pub fn parse(stdin: &str) -> Result<(String, Value, Option<String>), String> {
    let v: Value = serde_json::from_str(stdin).map_err(|e| format!("вход не JSON: {e}"))?;
    let tool = v
        .get("tool_name")
        .or_else(|| v.get("tool"))
        .and_then(|t| t.as_str())
        .ok_or("нет tool_name")?;
    let input = v
        .get("tool_input")
        .or_else(|| v.get("input"))
        .cloned()
        .unwrap_or(Value::Null);
    let cwd = v.get("cwd").and_then(|c| c.as_str()).map(String::from);
    Ok((tool.to_string(), input, cwd))
}

/// (what to print on standard output, exit status)
pub fn answer(d: &Decision, fmt: Format) -> (String, i32) {
    match fmt {
        Format::ClaudeCode => match d.action {
            Action::Allow => (String::new(), 0),
            a => {
                let word = if a == Action::Deny { "deny" } else { "ask" };
                let reason = format!("[Aegis Guard, правило {}] {}", d.rule, d.reason);
                (
                    json!({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": word, "permissionDecisionReason": reason}}).to_string(),
                    0,
                )
            }
        },
        Format::Generic => {
            let word = match d.action {
                Action::Allow => "allow",
                Action::Ask => "ask",
                Action::Deny => "deny",
            };
            (
                json!({"decision": word, "rule": d.rule, "reason": d.reason}).to_string(),
                if d.action == Action::Deny { 2 } else { 0 },
            )
        }
    }
}

/// The whole hook: stdin text in, (stdout, status) out. A call that cannot be read is refused:
/// what cannot be judged is not allowed.
pub fn run(
    rules: &Rules,
    stdin: &str,
    home: &str,
    fallback_cwd: &str,
    fmt: Format,
) -> (String, i32) {
    match parse(stdin) {
        Ok((tool, input, cwd)) => {
            let cwd = cwd.unwrap_or_else(|| fallback_cwd.to_string());
            let d = decide(rules, &Env { home, cwd: &cwd }, &tool, &input);
            answer(&d, fmt)
        }
        Err(e) => answer(
            &Decision {
                action: Action::Deny,
                rule: "G-00".into(),
                reason: format!("вызов не разобран: {e}"),
            },
            fmt,
        ),
    }
}

/// Settings for Claude Code that start the guard before every tool call and close the files
/// that no call should touch, so that the client's own permission system says no as well
/// (AGG-04, AGG-06). Put in the managed settings file of the machine, the user cannot override it.
pub fn claude_settings(binary: &str, extra_args: &str) -> String {
    let deny: Vec<String> = [
        "~/.ssh/**",
        "~/.aws/**",
        "~/.kube/**",
        "~/.config/gcloud/**",
        "~/.gnupg/**",
        "~/.netrc",
    ]
    .iter()
    .flat_map(|p| [format!("Read({p})"), format!("Edit({p})")])
    .collect();
    serde_json::to_string_pretty(&json!({
        "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": format!("{binary} hook{extra_args}")}]}]},
        "permissions": {"deny": deny},
    }))
    .unwrap_or_default()
        + "\n"
}

//! REQ: RST-01, RST-03, RST-04, POL-03, POL-07, POL-08, ДОП-6.
//!
//! Restoration policy: (class | type | type+kind) × sink → action, and the
//! three-condition rule.

use crate::types::{Class, Entity, EntityType};
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Sink {
    Text,
    FileWrite,
    FileRead,
    ShellLocal,
    ShellExec,
    ShellNetwork,
    Network,
    Agent,
    Mcp,
    Unknown,
}

impl Sink {
    pub fn as_str(&self) -> &'static str {
        match self {
            Sink::Text => "text",
            Sink::FileWrite => "file_write",
            Sink::FileRead => "file_read",
            Sink::ShellLocal => "shell_local",
            Sink::ShellExec => "shell_exec",
            Sink::ShellNetwork => "shell_network",
            Sink::Network => "network",
            Sink::Agent => "agent",
            Sink::Mcp => "mcp",
            Sink::Unknown => "unknown",
        }
    }

    /// RST-04: sink by tool name for Claude Code and Codex. `Bash`/`shell` need
    /// the command analysed, so they return `None` here.
    pub fn from_tool(tool: &str) -> Option<Sink> {
        if is_shell_tool(tool) {
            return None;
        }
        Some(match tool {
            "Write"
            | "Edit"
            | "MultiEdit"
            | "NotebookEdit"
            | "apply_patch"
            | "write_to_file"
            | "replace_in_file"
            | "edit_file"
            | "str_replace_editor"
            | "str_replace_based_edit_tool"
            // Gemini CLI and Qwen Code, OpenCode, Continue, Cursor-style agents
            | "write_file"
            | "replace"
            | "write"
            | "edit"
            | "create_file"
            | "insert_edit_into_file"
            | "apply_diff"
            | "patch" => Sink::FileWrite,
            "Read" | "Glob" | "Grep" | "NotebookRead" | "LS" | "read_file" | "list_files"
            | "search_files" | "list_dir" | "grep_search" | "read" | "glob" | "grep" | "list"
            | "read_many_files" | "list_directory" | "search_file_content" | "view_image" => {
                Sink::FileRead
            }
            "WebFetch" | "WebSearch" | "web_search" | "browser_action" | "web_fetch" | "webfetch"
            | "google_web_search" => Sink::Network,
            "Task" | "task" => Sink::Agent,
            "use_mcp_tool" | "access_mcp_resource" => Sink::Mcp,
            t if t.starts_with("mcp__") || t.starts_with("mcp_") => Sink::Mcp,
            _ => Sink::Unknown,
        })
    }

    pub fn is_network_like(&self) -> bool {
        matches!(self, Sink::Network | Sink::ShellNetwork | Sink::Unknown)
    }
}

/// Tools that run a shell command (Claude Code `Bash`, Codex `shell`/`local_shell`, common agents).
pub fn is_shell_tool(tool: &str) -> bool {
    matches!(
        tool,
        "Bash"
            | "shell"
            | "local_shell"
            | "execute_command"
            | "run_terminal_cmd"
            | "run_command"
            | "shell_command"
            | "container.exec"
            // Codex (`exec_command`, `cmd`), Gemini CLI and Qwen Code, OpenCode, Amazon Q
            | "exec_command"
            | "run_shell_command"
            | "bash"
            | "execute_bash"
            | "run_terminal_command"
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Restore,
    InternalOnly,
    OriginOnly,
    MarkerHint,
    KeepMasked,
    Deny,
}

#[derive(Clone, Debug)]
pub struct RestoreRule {
    pub id: String,
    pub sinks: Vec<Sink>,
    pub class: Option<Class>,
    pub ty: Option<EntityType>,
    pub kind: Option<String>,
    pub action: Action,
}

#[derive(Clone, Debug, Default)]
pub struct RestorePolicy {
    pub rules: Vec<RestoreRule>,
}

/// RST-03 default table. CORP behaves like PII.
fn default_action(class: Class, sink: Sink) -> Action {
    use Action::*;
    use Sink::*;
    match class {
        Class::Lit => Restore,
        Class::Infra => match sink {
            Text | FileWrite | FileRead | ShellLocal | ShellExec | Agent => Restore,
            ShellNetwork | Network | Mcp | Unknown => InternalOnly,
        },
        Class::Pii | Class::Corp => match sink {
            Text | FileWrite | FileRead | Agent => Restore,
            ShellLocal | ShellExec | ShellNetwork | Network | Mcp | Unknown => Deny,
        },
        Class::Secret => match sink {
            Text => MarkerHint,
            FileWrite => OriginOnly,
            Agent => KeepMasked,
            FileRead | ShellLocal | ShellExec | ShellNetwork | Network | Mcp | Unknown => Deny,
        },
    }
}

impl RestorePolicy {
    /// POL-03: specificity first (type+kind, type, class), then order, then defaults.
    pub fn decide(&self, ty: EntityType, kind: Option<&str>, sink: Sink) -> (Action, String) {
        let class = ty.class();
        let mut best: Option<(u8, &RestoreRule)> = None;
        for r in &self.rules {
            if !r.sinks.is_empty() && !r.sinks.contains(&sink) {
                continue;
            }
            let spec = match (&r.ty, &r.kind, &r.class) {
                (Some(t), Some(k), _) if *t == ty && Some(k.as_str()) == kind => 3,
                (Some(t), None, _) if *t == ty => 2,
                (None, None, Some(c)) if *c == class => 1,
                _ => continue,
            };
            if best.is_none_or(|(s, _)| spec > s) {
                best = Some((spec, r));
            }
        }
        match best {
            Some((_, r)) => (r.action, r.id.clone()),
            None => (default_action(class, sink), "default".into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Three-condition rule (POL-07, POL-08)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrifectaMode {
    Enforce,
    Monitor,
}

#[derive(Clone, Debug)]
pub struct TrifectaConfig {
    pub mode: TrifectaMode,
    pub private_classes: Vec<Class>,
    pub untrusted_tools: Vec<String>,
    pub untrusted_paths: Vec<String>,
    pub allow_destinations: Vec<String>,
    pub block_exec: bool,
}

impl Default for TrifectaConfig {
    fn default() -> Self {
        Self {
            mode: TrifectaMode::Enforce,
            private_classes: vec![Class::Secret, Class::Pii, Class::Infra],
            untrusted_tools: vec!["WebFetch".into(), "WebSearch".into()],
            untrusted_paths: ["node_modules/", "vendor/", "third_party/", ".git/modules/"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            allow_destinations: vec![],
            block_exec: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TrifectaState {
    /// P: private data in the request.
    pub private: bool,
    /// U: untrusted content in the request.
    pub untrusted: bool,
}

impl TrifectaConfig {
    /// Files of the working repository are trusted (ДОП-6) except configured paths.
    pub fn path_is_untrusted(&self, path: &str) -> bool {
        self.untrusted_paths
            .iter()
            .any(|p| path.contains(p.as_str()))
    }

    pub fn tool_is_untrusted(&self, tool: &str) -> bool {
        self.untrusted_tools.iter().any(|t| t == tool)
    }

    pub fn state(&self, classes: &HashSet<Class>, untrusted: bool) -> TrifectaState {
        TrifectaState {
            private: self.private_classes.iter().any(|c| classes.contains(c)),
            untrusted,
        }
    }

    pub fn active(&self, st: TrifectaState) -> bool {
        st.private && st.untrusted
    }

    /// Returns true when the call must be blocked.
    pub fn blocks(&self, st: TrifectaState, sink: Sink, destinations: &[String]) -> bool {
        if self.mode == TrifectaMode::Monitor || !self.active(st) {
            return false;
        }
        match sink {
            Sink::ShellExec => self.block_exec,
            s if s.is_network_like() => {
                destinations.is_empty()
                    || !destinations.iter().all(|d| {
                        self.allow_destinations
                            .iter()
                            .any(|a| d == a || d.ends_with(&format!(".{a}")))
                    })
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(
        id: &str,
        sinks: &[Sink],
        class: Option<Class>,
        ty: Option<EntityType>,
        kind: Option<&str>,
        action: Action,
    ) -> RestoreRule {
        RestoreRule {
            id: id.into(),
            sinks: sinks.to_vec(),
            class,
            ty,
            kind: kind.map(String::from),
            action,
        }
    }

    // REQ: RST-03 — full default table.
    #[test]
    fn default_table() {
        use Action::*;
        use Sink::*;
        let p = RestorePolicy::default();
        let d = |ty, sink| p.decide(ty, None, sink).0;
        let cases = [
            (EntityType::Host, Text, Restore),
            (EntityType::Host, FileWrite, Restore),
            (EntityType::Host, FileRead, Restore),
            (EntityType::Host, ShellLocal, Restore),
            (EntityType::Host, ShellExec, Restore),
            (EntityType::Host, ShellNetwork, InternalOnly),
            (EntityType::Host, Network, InternalOnly),
            (EntityType::Host, Agent, Restore),
            (EntityType::Host, Mcp, InternalOnly),
            (EntityType::Person, Text, Restore),
            (EntityType::Person, FileWrite, Restore),
            (EntityType::Person, ShellLocal, Deny),
            (EntityType::Person, ShellExec, Deny),
            (EntityType::Person, ShellNetwork, Deny),
            (EntityType::Person, Network, Deny),
            (EntityType::Person, Agent, Restore),
            (EntityType::Person, Mcp, Deny),
            (EntityType::Project, Text, Restore),
            (EntityType::Project, ShellNetwork, Deny),
            (EntityType::Secret, Text, MarkerHint),
            (EntityType::Secret, FileWrite, OriginOnly),
            (EntityType::Secret, FileRead, Deny),
            (EntityType::Secret, ShellLocal, Deny),
            (EntityType::Secret, ShellNetwork, Deny),
            (EntityType::Secret, Network, Deny),
            (EntityType::Secret, Agent, KeepMasked),
            (EntityType::Secret, Mcp, Deny),
            (EntityType::Lit, ShellNetwork, Restore),
            (EntityType::Lit, FileWrite, Restore),
        ];
        for (ty, sink, want) in cases {
            assert_eq!(d(ty, sink), want, "{ty:?} @ {sink:?}");
        }
    }

    // REQ: POL-03 — type+kind beats type beats class, independent of order.
    #[test]
    fn specificity_beats_order() {
        let p = RestorePolicy {
            rules: vec![
                rule(
                    "R-class",
                    &[Sink::Text],
                    Some(Class::Secret),
                    None,
                    None,
                    Action::Deny,
                ),
                rule(
                    "R-type",
                    &[Sink::Text],
                    None,
                    Some(EntityType::Secret),
                    None,
                    Action::KeepMasked,
                ),
                rule(
                    "R-kind",
                    &[Sink::Text],
                    None,
                    Some(EntityType::Secret),
                    Some("pem"),
                    Action::Restore,
                ),
            ],
        };
        assert_eq!(
            p.decide(EntityType::Secret, Some("pem"), Sink::Text),
            (Action::Restore, "R-kind".into())
        );
        assert_eq!(
            p.decide(EntityType::Secret, Some("jwt"), Sink::Text),
            (Action::KeepMasked, "R-type".into())
        );
        assert_eq!(
            p.decide(EntityType::Secret, None, Sink::FileRead).1,
            "default"
        );
    }

    #[test]
    fn first_wins_within_same_specificity() {
        let p = RestorePolicy {
            rules: vec![
                rule("A", &[], Some(Class::Infra), None, None, Action::Deny),
                rule("B", &[], Some(Class::Infra), None, None, Action::Restore),
            ],
        };
        assert_eq!(p.decide(EntityType::Host, None, Sink::Text).1, "A");
    }

    // REQ: RST-04
    #[test]
    fn sinks_by_tool() {
        assert_eq!(Sink::from_tool("Edit"), Some(Sink::FileWrite));
        assert_eq!(Sink::from_tool("apply_patch"), Some(Sink::FileWrite));
        assert_eq!(Sink::from_tool("Read"), Some(Sink::FileRead));
        assert_eq!(Sink::from_tool("WebFetch"), Some(Sink::Network));
        assert_eq!(Sink::from_tool("Task"), Some(Sink::Agent));
        assert_eq!(
            Sink::from_tool("mcp__gitlab__create_issue"),
            Some(Sink::Mcp)
        );
        assert_eq!(Sink::from_tool("Bash"), None);
        assert_eq!(Sink::from_tool("shell"), None);
        assert_eq!(Sink::from_tool("execute_command"), None);
        assert_eq!(Sink::from_tool("write_to_file"), Some(Sink::FileWrite));
        assert_eq!(Sink::from_tool("SomethingNew"), Some(Sink::Unknown));
    }

    // REQ: RST-04 — tool names of the other agents (the real Codex CLI sends `exec_command`).
    #[test]
    fn sinks_by_tool_of_other_agents() {
        for shell in ["exec_command", "run_shell_command", "bash", "execute_bash"] {
            assert!(is_shell_tool(shell), "{shell}");
            assert_eq!(Sink::from_tool(shell), None);
        }
        for (tool, sink) in [
            ("write_file", Sink::FileWrite),
            ("replace", Sink::FileWrite),
            ("write", Sink::FileWrite),
            ("edit", Sink::FileWrite),
            ("read_many_files", Sink::FileRead),
            ("list_directory", Sink::FileRead),
            ("search_file_content", Sink::FileRead),
            ("web_fetch", Sink::Network),
            ("webfetch", Sink::Network),
            ("google_web_search", Sink::Network),
            ("task", Sink::Agent),
            ("use_mcp_tool", Sink::Mcp),
            ("mcp_github_create_issue", Sink::Mcp),
        ] {
            assert_eq!(Sink::from_tool(tool), Some(sink), "{tool}");
        }
    }

    // REQ: POL-07, POL-08, ДОП-6
    #[test]
    fn trifecta_blocks_network_only_when_p_and_u() {
        let mut cfg = TrifectaConfig::default();
        let classes: HashSet<Class> = [Class::Infra].into_iter().collect();
        let on = cfg.state(&classes, true);
        let no_u = cfg.state(&classes, false);
        let no_p = cfg.state(&HashSet::new(), true);
        assert!(cfg.blocks(on, Sink::Network, &["evil.example".into()]));
        assert!(
            cfg.blocks(on, Sink::ShellNetwork, &[]),
            "unknown destinations are blocked"
        );
        assert!(!cfg.blocks(on, Sink::ShellLocal, &[]));
        assert!(
            !cfg.blocks(on, Sink::ShellExec, &[]),
            "tests keep working by default"
        );
        assert!(!cfg.blocks(no_u, Sink::Network, &[]));
        assert!(!cfg.blocks(no_p, Sink::Network, &[]));
        cfg.allow_destinations = vec!["docs.python.org".into()];
        assert!(!cfg.blocks(on, Sink::Network, &["docs.python.org".into()]));
        assert!(cfg.blocks(
            on,
            Sink::Network,
            &["docs.python.org".into(), "evil.example".into()]
        ));
        cfg.block_exec = true;
        assert!(cfg.blocks(on, Sink::ShellExec, &[]));
        cfg.mode = TrifectaMode::Monitor;
        assert!(!cfg.blocks(on, Sink::Network, &["evil.example".into()]));
    }

    #[test]
    fn repo_files_are_trusted_by_default() {
        let cfg = TrifectaConfig::default();
        assert!(!cfg.path_is_untrusted("README.md"));
        assert!(!cfg.path_is_untrusted("src/main.rs"));
        assert!(cfg.path_is_untrusted("web/node_modules/x/README.md"));
        assert!(cfg.tool_is_untrusted("WebFetch"));
    }
}

// ---------------------------------------------------------------------------
// Ingress policy (PSE-12)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ingress {
    Allow,
    Mask,
    DropBlock,
    BlockRequest,
}

#[derive(Clone, Debug)]
pub struct IngressRule {
    pub id: String,
    pub class: Option<Class>,
    pub ty: Option<EntityType>,
    pub kind: Option<String>,
    /// Applies only to requests on this route (POL-02).
    pub route: Option<String>,
    pub action: Ingress,
}

#[derive(Clone, Debug, Default)]
pub struct IngressPolicy {
    pub rules: Vec<IngressRule>,
}

impl IngressPolicy {
    /// PSE-12: default is `mask`; specificity as in POL-03 (type+kind, type, class), then order.
    /// A rule bound to the request's route beats an unbound rule of the same specificity.
    pub fn decide(&self, e: &Entity, route: &str) -> (Ingress, String) {
        let mut best: Option<(u8, &IngressRule)> = None;
        for r in &self.rules {
            if r.route.as_deref().is_some_and(|rt| rt != route) {
                continue;
            }
            let base = match (&r.ty, &r.kind, &r.class) {
                (Some(t), Some(k), _) if *t == e.ty && Some(k.as_str()) == e.kind => 3,
                (Some(t), None, _) if *t == e.ty => 2,
                (None, None, Some(c)) if *c == e.ty.class() => 1,
                _ => continue,
            };
            let spec = base * 2 + u8::from(r.route.is_some());
            if best.is_none_or(|(s, _)| spec > s) {
                best = Some((spec, r));
            }
        }
        match best {
            Some((_, r)) => (r.action, r.id.clone()),
            None => (Ingress::Mask, "default".into()),
        }
    }
}

#[cfg(test)]
mod ingress_tests {
    use super::*;
    use crate::types::Span;

    fn ent(ty: EntityType, kind: Option<&'static str>) -> Entity {
        Entity {
            span: Span { start: 0, end: 1 },
            ty,
            kind,
            detector: "t",
            person_key: None,
        }
    }

    fn rule(
        id: &str,
        class: Option<Class>,
        ty: Option<EntityType>,
        kind: Option<&str>,
        route: Option<&str>,
        a: Ingress,
    ) -> IngressRule {
        IngressRule {
            id: id.into(),
            class,
            ty,
            kind: kind.map(String::from),
            route: route.map(String::from),
            action: a,
        }
    }

    // REQ: PSE-12
    #[test]
    fn default_is_mask() {
        assert_eq!(
            IngressPolicy::default().decide(&ent(EntityType::Host, None), "r"),
            (Ingress::Mask, "default".into())
        );
    }

    // REQ: POL-03, POL-02 — specificity, then route-bound rules, independent of order.
    #[test]
    fn specificity_and_route() {
        let p = IngressPolicy {
            rules: vec![
                rule(
                    "R-class",
                    Some(Class::Secret),
                    None,
                    None,
                    None,
                    Ingress::Mask,
                ),
                rule(
                    "R-pem",
                    None,
                    Some(EntityType::Secret),
                    Some("pem"),
                    None,
                    Ingress::BlockRequest,
                ),
                rule(
                    "R-local",
                    Some(Class::Infra),
                    None,
                    None,
                    Some("local"),
                    Ingress::Allow,
                ),
            ],
        };
        assert_eq!(
            p.decide(&ent(EntityType::Secret, Some("pem")), "any").1,
            "R-pem"
        );
        assert_eq!(
            p.decide(&ent(EntityType::Secret, Some("jwt")), "any").1,
            "R-class"
        );
        assert_eq!(
            p.decide(&ent(EntityType::Host, None), "local"),
            (Ingress::Allow, "R-local".into())
        );
        assert_eq!(
            p.decide(&ent(EntityType::Host, None), "external").0,
            Ingress::Mask,
            "route-bound rule does not leak to other routes"
        );
    }
}

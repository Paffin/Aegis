//! REQ: RST-01, RST-03, RST-04, POL-03, POL-07, POL-08, ДОП-6.
//!
//! Restoration policy: (class | type | type+kind) × sink → action, and the
//! three-condition rule.

use crate::types::{Class, EntityType};
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
        Some(match tool {
            "Write" | "Edit" | "MultiEdit" | "NotebookEdit" | "apply_patch" => Sink::FileWrite,
            "Read" | "Glob" | "Grep" | "NotebookRead" | "LS" => Sink::FileRead,
            "WebFetch" | "WebSearch" => Sink::Network,
            "Task" => Sink::Agent,
            "Bash" | "shell" | "local_shell" => return None,
            t if t.starts_with("mcp__") => Sink::Mcp,
            _ => Sink::Unknown,
        })
    }

    pub fn is_network_like(&self) -> bool {
        matches!(self, Sink::Network | Sink::ShellNetwork | Sink::Unknown)
    }
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
        assert_eq!(Sink::from_tool("SomethingNew"), Some(Sink::Unknown));
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

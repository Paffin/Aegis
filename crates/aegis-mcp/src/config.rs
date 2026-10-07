//! REQ: MCP-02, MCP-03, MCP-04, MCP-05 — the configuration of `aegis-mcp`: strict, so a typo is
//! an error and not a rule that silently does not apply.

use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpConfig {
    pub version: u32,
    /// Where decisions are written, JSON lines, without argument values. Empty: standard error.
    #[serde(default)]
    pub audit_path: Option<String>,
    pub servers: BTreeMap<String, ServerDoc>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerDoc {
    /// `trusted` (default) or `untrusted`: content from this server is not the company's own
    /// (an issue tracker anyone can write to, a web fetcher). It arms the `U` flag of the
    /// three-condition rule in the gateway (MCP-05).
    #[serde(default)]
    pub trust: Option<String>,
    /// Calls to this server leave the perimeter (a chat, a public repository, e-mail). The
    /// gateway treats its tools as network sinks (MCP-05).
    #[serde(default)]
    pub egress: bool,
    /// Streamable HTTP only: where the server is.
    #[serde(default)]
    pub url: Option<String>,
    /// Streamable HTTP only: header → name of the environment variable that holds its value.
    #[serde(default)]
    pub headers_env: BTreeMap<String, String>,
    pub tools: ToolsDoc,
    #[serde(default)]
    pub results: ResultsDoc,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolsDoc {
    /// Names, `*` is a wildcard. Required: a server without an allow-list is not configured.
    /// `["*"]` allows everything on purpose.
    pub allow: Vec<String>,
    /// Constraints on the arguments of a tool: tool name → argument path → rule.
    #[serde(default)]
    pub args: BTreeMap<String, ArgsDoc>,
    /// SQL tools: tool name → names of the arguments that carry SQL; only reads pass.
    #[serde(default)]
    pub sql_read_only: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ArgsDoc {
    /// (The other keys are argument paths; an argument cannot itself be called `unknown`.)
    /// `deny` refuses arguments that have no rule here; `allow` (default) lets them through.
    #[serde(default)]
    pub unknown: Option<String>,
    #[serde(flatten)]
    pub rules: BTreeMap<String, ArgRuleDoc>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ArgRuleDoc {
    /// The whole value must match (regular expression, anchored by the checker).
    #[serde(default)]
    pub pattern: Option<String>,
    /// The value must not match.
    #[serde(default)]
    pub forbid_pattern: Option<String>,
    #[serde(default, rename = "enum")]
    pub one_of: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub max_length: Option<usize>,
    /// The argument must be there.
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ResultsDoc {
    /// Keys (and CSV columns) removed from results, any depth, case-insensitive. Irreversible.
    #[serde(default)]
    pub drop_fields: Vec<String>,
    /// Longest text of a result, bytes; longer is cut with a note.
    #[serde(default)]
    pub max_bytes: Option<usize>,
}

/// Compiled, checked form.
#[derive(Debug)]
pub struct Server {
    pub name: String,
    pub untrusted: bool,
    pub egress: bool,
    pub url: Option<String>,
    pub headers_env: BTreeMap<String, String>,
    pub allow: Vec<String>,
    pub args: BTreeMap<String, ArgSet>,
    pub sql: BTreeMap<String, Vec<String>>,
    pub drop_fields: Vec<String>,
    pub max_bytes: Option<usize>,
}

#[derive(Debug)]
pub struct ArgSet {
    pub deny_unknown: bool,
    pub rules: BTreeMap<String, ArgRule>,
}

#[derive(Debug)]
pub struct ArgRule {
    pub pattern: Option<Regex>,
    pub forbid: Option<Regex>,
    pub one_of: Option<Vec<serde_json::Value>>,
    pub max_length: Option<usize>,
    pub required: bool,
}

#[derive(Debug)]
pub struct Config {
    pub audit_path: Option<String>,
    pub servers: BTreeMap<String, Arc<Server>>,
}

pub use aegis_core::policy::glob_match as glob;

impl Config {
    pub fn from_yaml(text: &str) -> Result<Config, String> {
        let doc: McpConfig =
            serde_yaml_ng::from_str(text).map_err(|e| format!("конфигурация: {e}"))?;
        if doc.version != 1 {
            return Err(format!(
                "конфигурация: версия {} не поддерживается",
                doc.version
            ));
        }
        let re = |what: &str, p: &str| {
            regex::RegexBuilder::new(p)
                .size_limit(1 << 20)
                .build()
                .map_err(|e| format!("{what}: «{p}»: {e}"))
        };
        let mut servers = BTreeMap::new();
        for (name, s) in doc.servers {
            let untrusted = match s.trust.as_deref() {
                None | Some("trusted") => false,
                Some("untrusted") => true,
                Some(o) => return Err(format!("{name}: trust «{o}», нужно trusted или untrusted")),
            };
            if s.tools.allow.is_empty() {
                return Err(format!(
                    "{name}: tools.allow пуст: ни один инструмент не разрешён"
                ));
            }
            let mut args = BTreeMap::new();
            for (tool, a) in s.tools.args {
                let deny_unknown = match a.unknown.as_deref() {
                    None | Some("allow") => false,
                    Some("deny") => true,
                    Some(o) => {
                        return Err(format!(
                            "{name}.{tool}: unknown «{o}», нужно allow или deny"
                        ))
                    }
                };
                let mut rules = BTreeMap::new();
                for (path, r) in a.rules {
                    let what = format!("{name}.{tool}.{path}");
                    rules.insert(
                        path,
                        ArgRule {
                            pattern: r
                                .pattern
                                .as_deref()
                                .map(|p| re(&what, &format!("^(?:{p})$")))
                                .transpose()?,
                            forbid: r
                                .forbid_pattern
                                .as_deref()
                                .map(|p| re(&what, p))
                                .transpose()?,
                            one_of: r.one_of,
                            max_length: r.max_length,
                            required: r.required,
                        },
                    );
                }
                args.insert(
                    tool,
                    ArgSet {
                        deny_unknown,
                        rules,
                    },
                );
            }
            servers.insert(
                name.clone(),
                Arc::new(Server {
                    name,
                    untrusted,
                    egress: s.egress,
                    url: s.url,
                    headers_env: s.headers_env,
                    allow: s.tools.allow,
                    args,
                    sql: s.tools.sql_read_only,
                    drop_fields: s
                        .results
                        .drop_fields
                        .iter()
                        .map(|f| f.to_lowercase())
                        .collect(),
                    max_bytes: s.results.max_bytes,
                }),
            );
        }
        if servers.is_empty() {
            return Err("конфигурация: servers пуст".into());
        }
        Ok(Config {
            audit_path: doc.audit_path,
            servers,
        })
    }

    /// The fragment of a gateway policy that makes the gateway treat these servers' tools as
    /// untrusted content and as network sinks (MCP-05). Tool names differ by client: Claude Code
    /// calls them `mcp__<server>__<tool>`, others `<server>__<tool>` or `mcp_<server>_<tool>`.
    pub fn policy_snippet(&self) -> String {
        let mut untrusted = vec![];
        let mut egress = vec![];
        for s in self.servers.values() {
            for pat in [format!("mcp__{}__*", s.name), format!("mcp_{}_*", s.name)] {
                if s.untrusted {
                    untrusted.push(pat.clone());
                }
                if s.egress {
                    egress.push(pat);
                }
            }
        }
        let list = |v: &[String]| {
            format!(
                "[{}]",
                v.iter()
                    .map(|x| format!("\"{x}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        format!(
            "# добавьте в политику gateway (раздел trifecta); существующие значения сохраните\ntrifecta:\n  untrusted_tools: {}\n  egress_tools: {}\n",
            list(&untrusted),
            list(&egress)
        )
    }
}

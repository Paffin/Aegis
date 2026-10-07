//! REQ: MCP-02, MCP-03, MCP-04 — the decisions, over JSON-RPC messages, independent of the
//! transport (stdio or HTTP).

use crate::audit::Audit;
use crate::config::{glob, ArgRule, Server};
use crate::sql;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

enum Pending {
    ToolsList,
    Call(String),
}

/// What the client's message turns into.
#[derive(Debug, Default)]
pub struct Outcome {
    /// To the server: the message, or what is left of a batch. `None`: nothing to send.
    pub forward: Option<Value>,
    /// To the client, instead of the server's answer.
    pub answers: Vec<Value>,
}

pub struct Filter {
    server: Arc<Server>,
    audit: Audit,
    pending: HashMap<String, Pending>,
}

fn key(id: &Value) -> String {
    id.to_string()
}

/// A tool result the model understands: it says what was refused and why.
fn refusal(id: &Value, rule: &str, why: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": {
        "content": [{"type": "text", "text": format!("[Aegis] Вызов отклонён (правило {rule}): {why}")}],
        "isError": true}})
}

fn get_path<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(v, |cur, k| cur.get(k))
}

fn check_value(path: &str, r: &ArgRule, v: &Value) -> Result<(), String> {
    let scalars: Vec<&Value> = match v {
        Value::Array(a) => a.iter().collect(),
        other => vec![other],
    };
    for s in scalars {
        if let Some(allowed) = &r.one_of {
            if !allowed.contains(s) {
                return Err(format!("аргумент {path}: значение не из списка допустимых"));
            }
        }
        let text = match s {
            Value::String(t) => Some(t.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        };
        if let Some(t) = text {
            if r.max_length.is_some_and(|m| t.chars().count() > m) {
                return Err(format!("аргумент {path}: длиннее допустимого"));
            }
            if r.pattern.as_ref().is_some_and(|p| !p.is_match(&t)) {
                return Err(format!("аргумент {path}: не соответствует шаблону"));
            }
            if r.forbid.as_ref().is_some_and(|p| p.is_match(&t)) {
                return Err(format!("аргумент {path}: содержит запрещённое"));
            }
        } else if r.pattern.is_some() {
            return Err(format!("аргумент {path}: ожидается строка или число"));
        }
    }
    Ok(())
}

impl Filter {
    pub fn new(server: Arc<Server>, audit: Audit) -> Self {
        Self {
            server,
            audit,
            pending: HashMap::new(),
        }
    }

    fn allowed(&self, tool: &str) -> bool {
        self.server.allow.iter().any(|p| glob(p, tool))
    }

    /// `Err((rule, why))` when the call must not reach the server.
    fn check_call(&self, tool: &str, args: &Value) -> Result<(), (&'static str, String)> {
        if !self.allowed(tool) {
            return Err((
                "M-01",
                format!(
                    "инструмент «{tool}» не входит в список разрешённых для сервера {}",
                    self.server.name
                ),
            ));
        }
        if let Some(set) = self.server.args.get(tool) {
            for (path, rule) in &set.rules {
                match get_path(args, path) {
                    Some(v) => check_value(path, rule, v).map_err(|e| ("M-02", e))?,
                    None if rule.required => {
                        return Err(("M-02", format!("нет обязательного аргумента {path}")))
                    }
                    None => {}
                }
            }
            if set.deny_unknown {
                if let Some(o) = args.as_object() {
                    let known: Vec<&str> = set
                        .rules
                        .keys()
                        .map(|p| p.split('.').next().unwrap_or(""))
                        .collect();
                    if let Some(k) = o.keys().find(|k| !known.contains(&k.as_str())) {
                        return Err(("M-02", format!("неизвестный аргумент «{k}»")));
                    }
                }
            }
        }
        if let Some(names) = self.server.sql.get(tool) {
            for n in names {
                match get_path(args, n) {
                    Some(Value::String(q)) => {
                        sql::read_only(q).map_err(|e| ("M-03", format!("аргумент {n}: {e}")))?
                    }
                    Some(_) => {
                        return Err(("M-03", format!("аргумент {n}: ожидался текст запроса")))
                    }
                    None => {}
                }
            }
        }
        Ok(())
    }

    pub fn client(&mut self, msg: Value) -> Outcome {
        match msg {
            Value::Array(items) => {
                let mut out = Outcome::default();
                let mut forward = vec![];
                for m in items {
                    let o = self.client_one(m);
                    forward.extend(o.forward);
                    out.answers.extend(o.answers);
                }
                if !forward.is_empty() {
                    out.forward = Some(Value::Array(forward));
                }
                out
            }
            m => self.client_one(m),
        }
    }

    fn client_one(&mut self, msg: Value) -> Outcome {
        let method = msg.get("method").and_then(|m| m.as_str()).map(String::from);
        let id = msg.get("id").cloned();
        match (method.as_deref(), id) {
            (Some("tools/list"), Some(id)) => {
                self.pending.insert(key(&id), Pending::ToolsList);
                Outcome {
                    forward: Some(msg),
                    answers: vec![],
                }
            }
            (Some("tools/call"), id) => {
                let tool = msg
                    .pointer("/params/name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();
                let args = msg
                    .pointer("/params/arguments")
                    .cloned()
                    .unwrap_or(Value::Null);
                // arguments of something other than an object cannot be checked: refused
                let verdict = if !args.is_null() && !args.is_object() {
                    Err(("M-02", "аргументы вызова должны быть объектом".to_string()))
                } else {
                    self.check_call(&tool, &args)
                };
                match verdict {
                    Ok(()) => {
                        self.audit.event(&self.server.name, &tool, "allow", "-", "");
                        if let Some(id) = id {
                            self.pending.insert(key(&id), Pending::Call(tool));
                        }
                        Outcome {
                            forward: Some(msg),
                            answers: vec![],
                        }
                    }
                    Err((rule, why)) => {
                        self.audit
                            .event(&self.server.name, &tool, "deny", rule, &why);
                        Outcome {
                            forward: None,
                            answers: id.map(|i| refusal(&i, rule, &why)).into_iter().collect(),
                        }
                    }
                }
            }
            _ => Outcome {
                forward: Some(msg),
                answers: vec![],
            },
        }
    }

    pub fn server(&mut self, msg: Value) -> Option<Value> {
        match msg {
            Value::Array(items) => {
                let out: Vec<Value> = items
                    .into_iter()
                    .filter_map(|m| self.server_one(m))
                    .collect();
                (!out.is_empty()).then_some(Value::Array(out))
            }
            m => self.server_one(m),
        }
    }

    fn server_one(&mut self, mut msg: Value) -> Option<Value> {
        let is_response = msg.get("method").is_none()
            && (msg.get("result").is_some() || msg.get("error").is_some());
        let Some(id) = msg.get("id").filter(|_| is_response).cloned() else {
            return Some(msg);
        };
        match self.pending.remove(&key(&id)) {
            Some(Pending::ToolsList) => {
                if let Some(tools) = msg
                    .pointer_mut("/result/tools")
                    .and_then(|t| t.as_array_mut())
                {
                    let before = tools.len();
                    let server = self.server.clone();
                    let audit = self.audit.clone();
                    tools.retain(|t| {
                        let name = t.get("name").and_then(|n| n.as_str()).unwrap_or("");
                        let keep = server.allow.iter().any(|p| glob(p, name));
                        if !keep {
                            audit.event(&server.name, name, "hide", "M-01", "");
                        }
                        keep
                    });
                    let _ = before;
                }
                Some(msg)
            }
            Some(Pending::Call(tool)) => {
                if let Some(result) = msg.get_mut("result") {
                    let n = self.minimize(result);
                    if n > 0 {
                        self.audit.event(
                            &self.server.name,
                            &tool,
                            "minimize",
                            "M-10",
                            &format!("{n} изменений"),
                        );
                    }
                }
                Some(msg)
            }
            None => Some(msg),
        }
    }

    /// MCP-04: take the configured fields out of a tool result. Returns how much was changed.
    fn minimize(&self, result: &mut Value) -> usize {
        let mut n = 0;
        if let Some(items) = result.get_mut("content").and_then(|c| c.as_array_mut()) {
            for it in items {
                let slot = match it.get("type").and_then(|t| t.as_str()) {
                    Some("text") => it.get_mut("text"),
                    Some("resource") => it.get_mut("resource").and_then(|r| r.get_mut("text")),
                    _ => None,
                };
                if let Some(Value::String(t)) = slot {
                    n += self.minimize_text(t);
                }
            }
        }
        if let Some(sc) = result.get_mut("structuredContent") {
            n += drop_keys(sc, &self.server.drop_fields);
        }
        n
    }

    fn minimize_text(&self, text: &mut String) -> usize {
        let mut n = 0;
        let drop = &self.server.drop_fields;
        if !drop.is_empty() {
            let t = text.trim_start();
            if t.starts_with('{') || t.starts_with('[') {
                if let Ok(mut v) = serde_json::from_str::<Value>(text) {
                    let k = drop_keys(&mut v, drop);
                    if k > 0 {
                        *text = v.to_string();
                        n += k;
                    }
                }
            } else if let Some((out, k)) = drop_columns(text, drop) {
                *text = out;
                n += k;
            }
        }
        if let Some(max) = self.server.max_bytes {
            if text.len() > max {
                let mut cut = max;
                while !text.is_char_boundary(cut) {
                    cut -= 1;
                }
                text.truncate(cut);
                text.push_str("\n[Aegis: результат обрезан]");
                n += 1;
            }
        }
        n
    }
}

/// Remove keys (lower-case names) at any depth; returns how many.
pub fn drop_keys(v: &mut Value, names: &[String]) -> usize {
    match v {
        Value::Object(o) => {
            let before = o.len();
            o.retain(|k, _| !names.contains(&k.to_lowercase()));
            let mut n = before - o.len();
            for x in o.values_mut() {
                n += drop_keys(x, names);
            }
            n
        }
        Value::Array(a) => a.iter_mut().map(|x| drop_keys(x, names)).sum(),
        _ => 0,
    }
}

/// CSV or TSV text with a header: the columns named in `names` removed. `None` when the text is
/// not such a table or has nothing to remove. A table that cannot be cut safely (quotes, ragged
/// rows) is withheld whole: the field is gone either way.
fn drop_columns(text: &str, names: &[String]) -> Option<(String, usize)> {
    let mut lines = text.lines();
    let header = lines.next()?;
    let delim =
        if header.matches('\t').count() >= header.matches(',').count() && header.contains('\t') {
            '\t'
        } else if header.contains(',') {
            ','
        } else {
            return None;
        };
    let cells: Vec<String> = header
        .split(delim)
        .map(|c| c.trim().trim_matches(['"', '\'', '`']).to_lowercase())
        .collect();
    let hit: Vec<usize> = cells
        .iter()
        .enumerate()
        .filter(|(_, c)| names.contains(c))
        .map(|(i, _)| i)
        .collect();
    if hit.is_empty() {
        return None;
    }
    let withheld = || {
        Some((
            "[Aegis: результат скрыт: из таблицы нельзя безопасно убрать колонку]".to_string(),
            hit.len(),
        ))
    };
    if text.contains('"') {
        return withheld();
    }
    let mut out = String::new();
    for (i, line) in text.lines().enumerate() {
        let parts: Vec<&str> = line.split(delim).collect();
        if parts.len() != cells.len() {
            if line.trim().is_empty() && i > 0 {
                continue;
            }
            return withheld();
        }
        let kept: Vec<&str> = parts
            .iter()
            .enumerate()
            .filter(|(j, _)| !hit.contains(j))
            .map(|(_, p)| *p)
            .collect();
        out.push_str(&kept.join(&delim.to_string()));
        out.push('\n');
    }
    if !text.ends_with('\n') {
        out.pop();
    }
    Some((out, hit.len()))
}

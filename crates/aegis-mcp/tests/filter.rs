#![allow(clippy::unwrap_used)]
//! REQ: MCP-02, MCP-03, MCP-04, MCP-05 — the decisions of the filter over JSON-RPC messages.

use aegis_mcp::audit::Audit;
use aegis_mcp::config::Config;
use aegis_mcp::filter::Filter;
use serde_json::{json, Value};

const CFG: &str = r#"
version: 1
servers:
  tracker:
    trust: untrusted
    egress: true
    tools:
      allow: [get_issue, list_*, create_issue, query]
      args:
        create_issue:
          unknown: deny
          repo: { pattern: 'acme/[a-z-]+', max_length: 40, required: true }
          labels: { enum: [bug, feature] }
          title: { forbid_pattern: '(?i)password|secret' }
        get_issue:
          "filter.project": { enum: [WEB, API] }
      sql_read_only:
        query: [sql]
    results:
      drop_fields: [email, SSN]
      max_bytes: 2000
"#;

fn filter() -> Filter {
    let cfg = Config::from_yaml(CFG).unwrap();
    Filter::new(cfg.servers["tracker"].clone(), Audit::discard())
}

fn call(id: u64, tool: &str, args: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": args}})
}

fn refused(o: &aegis_mcp::filter::Outcome) -> String {
    assert!(o.forward.is_none(), "must not reach the server");
    let a = &o.answers[0];
    assert_eq!(a["result"]["isError"], true);
    a["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string()
}

// REQ: MCP-02
#[test]
fn tools_outside_the_allow_list_are_hidden_and_refused() {
    let mut f = filter();
    let o = f.client(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}));
    assert!(o.forward.is_some());
    let listed = json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
        {"name": "get_issue"}, {"name": "list_issues"}, {"name": "delete_repo"}, {"name": "drop_db"}], "nextCursor": "c"}});
    let out = f.server(listed).unwrap();
    let names: Vec<&str> = out["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["get_issue", "list_issues"]);
    assert_eq!(out["result"]["nextCursor"], "c");

    let r = refused(&f.client(call(2, "delete_repo", json!({}))));
    assert!(r.contains("M-01") && r.contains("delete_repo"));
    // a hidden tool cannot be called by guessing its name, nor by changing its case or spelling
    for t in ["Delete_Repo", "delete_repo ", "list", ""] {
        assert!(f.client(call(3, t, json!({}))).forward.is_none(), "{t:?}");
    }
    // allowed ones go through
    assert!(f
        .client(call(4, "list_issues", json!({})))
        .forward
        .is_some());
}

// REQ: MCP-03
#[test]
fn arguments_are_checked_against_the_rules() {
    let mut f = filter();
    let ok = json!({"repo": "acme/web", "labels": ["bug"], "title": "crash on start"});
    assert!(f.client(call(1, "create_issue", ok)).forward.is_some());
    for (args, why) in [
        (json!({"repo": "evil/web"}), "шаблону"),
        (
            json!({"repo": "acme/web", "labels": ["bug", "urgent"]}),
            "списка",
        ),
        (
            json!({"repo": "acme/web", "title": "my PASSWORD is"}),
            "запрещённое",
        ),
        (
            json!({"repo": "acme/web-with-a-very-long-name-that-goes-on-and-on"}),
            "длиннее",
        ),
        (json!({"labels": ["bug"]}), "обязательного"),
        (json!({"repo": "acme/web", "assignee": "x"}), "неизвестный"),
        (json!("not an object"), "объектом"),
    ] {
        let r = refused(&f.client(call(2, "create_issue", args.clone())));
        assert!(r.contains("M-02") && r.contains(why), "{args}: {r}");
    }
    // dotted paths reach into nested arguments
    assert!(f
        .client(call(3, "get_issue", json!({"filter": {"project": "WEB"}})))
        .forward
        .is_some());
    assert!(f
        .client(call(4, "get_issue", json!({"filter": {"project": "HR"}})))
        .forward
        .is_none());
}

// REQ: MCP-03
#[test]
fn sql_tools_take_only_reads() {
    let mut f = filter();
    assert!(f
        .client(call(
            1,
            "query",
            json!({"sql": "SELECT id FROM users LIMIT 5"})
        ))
        .forward
        .is_some());
    for q in [
        "DELETE FROM users",
        "SELECT 1; DROP TABLE users",
        "UPDATE users SET admin = true",
    ] {
        let r = refused(&f.client(call(2, "query", json!({"sql": q}))));
        assert!(r.contains("M-03"), "{q}: {r}");
    }
    assert!(f
        .client(call(3, "query", json!({"sql": 42})))
        .forward
        .is_none());
}

// REQ: MCP-04
#[test]
fn results_lose_the_configured_fields() {
    let mut f = filter();
    f.client(call(7, "get_issue", json!({"filter": {"project": "WEB"}})));
    let body = json!({"id": 7, "reporter": {"name": "Ann", "Email": "ann@corp.local", "ssn": "123"}, "title": "t"});
    let msg = json!({"jsonrpc": "2.0", "id": 7, "result": {
        "content": [{"type": "text", "text": body.to_string()}],
        "structuredContent": {"rows": [{"email": "x@y", "n": 1}]}}});
    let out = f.server(msg).unwrap();
    let text = out["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        !text.contains("ann@corp.local") && !text.contains("123") && text.contains("Ann"),
        "{text}"
    );
    assert_eq!(
        out["result"]["structuredContent"]["rows"][0],
        json!({"n": 1})
    );
}

// REQ: MCP-04
#[test]
fn tables_lose_columns_and_odd_ones_are_withheld() {
    let mut f = filter();
    let run = |f: &mut Filter, id: u64, text: &str| -> String {
        f.client(call(id, "list_issues", json!({})));
        let out = f.server(json!({"jsonrpc": "2.0", "id": id, "result": {"content": [{"type": "text", "text": text}]}})).unwrap();
        out["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(
        run(&mut f, 1, "id,name,email\n1,Ann,ann@x\n2,Bob,bob@x\n"),
        "id,name\n1,Ann\n2,Bob\n"
    );
    assert_eq!(run(&mut f, 2, "id\tssn\n1\t123"), "id\n1");
    // quotes or ragged rows: the whole text goes, not a guess
    assert!(run(&mut f, 3, "id,email\n1,\"a,b@x\"\n").contains("скрыт"));
    assert!(run(&mut f, 4, "id,email\n1\n").contains("скрыт"));
    // text without such a table is left alone
    assert_eq!(
        run(&mut f, 5, "just words, with a comma"),
        "just words, with a comma"
    );
}

#[test]
fn long_results_are_cut() {
    let mut f = filter();
    f.client(call(1, "list_issues", json!({})));
    let big = "я".repeat(3000);
    let out = f.server(json!({"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": big}]}})).unwrap();
    let t = out["result"]["content"][0]["text"].as_str().unwrap();
    assert!(t.len() < 2100 && t.contains("обрезан"));
}

#[test]
fn batches_and_other_traffic() {
    let mut f = filter();
    // a batch: the refused call is answered here, the rest goes on
    let o = f.client(json!([
        call(1, "list_issues", json!({})),
        call(2, "drop_db", json!({}))
    ]));
    assert_eq!(o.forward.as_ref().unwrap().as_array().unwrap().len(), 1);
    assert_eq!(o.answers.len(), 1);
    assert_eq!(o.answers[0]["id"], 2);
    // everything else is not touched
    for m in [
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "id": 9, "method": "initialize", "params": {}}),
        json!({"jsonrpc": "2.0", "id": 10, "method": "resources/read", "params": {"uri": "x"}}),
    ] {
        assert_eq!(f.client(m.clone()).forward.unwrap(), m);
    }
    // server-initiated messages pass
    let sampling =
        json!({"jsonrpc": "2.0", "id": "s1", "method": "sampling/createMessage", "params": {}});
    assert_eq!(f.server(sampling.clone()).unwrap(), sampling);
    // a notification call (no id) that is refused gets no answer, but does not reach the server
    let o = f.client(json!({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "drop_db", "arguments": {}}}));
    assert!(o.forward.is_none() && o.answers.is_empty());
}

// REQ: MCP-05
#[test]
fn trust_labels_become_a_policy_fragment() {
    let cfg = Config::from_yaml(CFG).unwrap();
    let s = cfg.policy_snippet();
    assert!(
        s.contains("mcp__tracker__*")
            && s.contains("untrusted_tools")
            && s.contains("egress_tools"),
        "{s}"
    );
    let trusted =
        Config::from_yaml("version: 1\nservers:\n  docs:\n    tools: { allow: ['*'] }\n").unwrap();
    let s = trusted.policy_snippet();
    assert!(
        s.contains("untrusted_tools: []") && s.contains("egress_tools: []"),
        "{s}"
    );
}

#[test]
fn the_configuration_is_strict() {
    for (bad, why) in [
        (
            "version: 2\nservers: {a: {tools: {allow: ['*']}}}",
            "версия",
        ),
        ("version: 1\nservers: {}", "пуст"),
        (
            "version: 1\nservers: {a: {tools: {allow: []}}}",
            "allow пуст",
        ),
        ("version: 1\nservers: {a: {tools: {}}}", "allow"),
        (
            "version: 1\nservers: {a: {trust: maybe, tools: {allow: ['*']}}}",
            "trust",
        ),
        (
            "version: 1\nservers: {a: {tools: {allow: ['*'], args: {t: {x: {pattern: '('}}}}}}",
            "t.x",
        ),
        (
            "version: 1\nservers: {a: {tools: {allow: ['*']}, extra: 1}}",
            "extra",
        ),
        (
            "version: 1\nservers: {a: {tools: {allow: ['*'], args: {t: {unknown: sometimes}}}}}",
            "unknown",
        ),
    ] {
        let e = Config::from_yaml(bad).unwrap_err();
        assert!(e.contains(why), "{bad}: {e}");
    }
}

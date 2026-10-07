//! REQ: MCP-03 — "read only" for SQL tools.
//!
//! A conservative check, not a parser: whatever it cannot be sure about is refused, because a
//! refused query can be rewritten and a write that got through cannot be undone. The query must be
//! one statement that starts like a read, contain none of the words that write, and must not use
//! quoting or comment forms that databases read differently (so a hidden second statement is not
//! possible). The database user should still be read-only; this is the second lock.

/// `Ok` when the query is a single read-only statement; otherwise why not.
pub fn read_only(sql: &str) -> Result<(), String> {
    let stripped = strip(sql)?;
    let lower = stripped.to_lowercase();
    // one statement: a trailing `;` is fine, anything after one is not
    let body = lower.trim().trim_end_matches(';').trim_end();
    if body.contains(';') {
        return Err("несколько операторов в одном запросе".into());
    }
    let words: Vec<&str> = body
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .collect();
    let first = words.first().copied().unwrap_or("");
    if !matches!(
        first,
        "select" | "with" | "explain" | "show" | "describe" | "desc" | "values" | "table"
    ) {
        return Err(format!(
            "запрос начинается с «{first}», разрешены только чтение и описание схемы"
        ));
    }
    const WRITES: &[&str] = &[
        "insert",
        "update",
        "delete",
        "merge",
        "drop",
        "alter",
        "create",
        "truncate",
        "grant",
        "revoke",
        "into",
        "outfile",
        "dumpfile",
        "call",
        "exec",
        "execute",
        "copy",
        "vacuum",
        "reindex",
        "cluster",
        "refresh",
        "attach",
        "detach",
        "load_file",
        "lo_import",
        "lo_export",
        "pg_read_file",
        "pg_read_binary_file",
        "pg_ls_dir",
        "pg_sleep",
        "sleep",
        "benchmark",
        "waitfor",
        "dblink",
        "xp_cmdshell",
        "set_config",
        "nextval",
        "setval",
        "pg_terminate_backend",
        "pg_cancel_backend",
    ];
    if let Some(w) = words.iter().find(|w| WRITES.contains(w)) {
        return Err(format!(
            "слово «{w}» не допускается в запросе только для чтения"
        ));
    }
    // `FOR UPDATE`, `FOR SHARE`, `FOR NO KEY UPDATE`: locks rows
    for pair in words.windows(2) {
        if pair[0] == "for" && matches!(pair[1], "update" | "share" | "no" | "key") {
            return Err("блокировка строк (FOR UPDATE и подобные) не допускается".into());
        }
    }
    Ok(())
}

/// The query without comments and without the content of literals and quoted identifiers, or an
/// error for forms whose meaning depends on the database.
fn strip(sql: &str) -> Result<String, String> {
    let c: Vec<char> = sql.chars().collect();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0;
    while i < c.len() {
        match c[i] {
            q @ ('\'' | '"' | '`') => {
                i += 1;
                loop {
                    match c.get(i) {
                        None => return Err("незакрытая кавычка".into()),
                        Some('\\') => {
                            return Err(
                                "обратная косая черта внутри кавычек: базы читают её по-разному"
                                    .into(),
                            )
                        }
                        Some(&x) if x == q => {
                            if c.get(i + 1) == Some(&q) {
                                i += 2; // doubled quote
                                continue;
                            }
                            i += 1;
                            break;
                        }
                        Some(_) => i += 1,
                    }
                }
                out.push(' ');
            }
            '-' if c.get(i + 1) == Some(&'-') => {
                // `-- ` is a comment everywhere; `--x` is one in some databases and an operator
                // in others
                match c.get(i + 2) {
                    None | Some('\n') | Some(' ') | Some('\t') | Some('\r') => {
                        while i < c.len() && c[i] != '\n' {
                            i += 1;
                        }
                    }
                    _ => {
                        return Err(
                            "`--` без пробела: комментарий это или нет, зависит от базы".into()
                        )
                    }
                }
            }
            '/' if c.get(i + 1) == Some(&'*') => {
                if matches!(c.get(i + 2), Some('!') | Some('+')) {
                    return Err("комментарий-подсказка или исполняемый комментарий MySQL".into());
                }
                i += 2;
                loop {
                    match (c.get(i), c.get(i + 1)) {
                        (Some('*'), Some('/')) => {
                            i += 2;
                            break;
                        }
                        (Some(_), _) => i += 1,
                        (None, _) => return Err("незакрытый комментарий".into()),
                    }
                }
                out.push(' ');
            }
            '$' if c
                .get(i + 1)
                .is_some_and(|x| *x == '$' || x.is_alphabetic() || *x == '_') =>
            {
                // `$$…$$` and `$tag$…$tag$` are string literals in PostgreSQL only
                return Err("долларовые кавычки: смысл зависит от базы".into());
            }
            ch => {
                out.push(ch);
                i += 1;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: MCP-03
    #[test]
    fn reads_pass() {
        for q in [
            "SELECT * FROM users WHERE id = 1",
            "select name, email from customers order by created_at desc limit 10;",
            "WITH t AS (SELECT 1) SELECT * FROM t",
            "SELECT 'a;b', \"col;umn\" FROM t -- trailing comment",
            "/* hint */ SELECT count(*) FROM orders",
            "SELECT comment, updated_at, deleted FROM posts",
            "SELECT replace(name, 'a', 'b') FROM t",
            "EXPLAIN SELECT * FROM t",
            "SHOW TABLES",
            "DESCRIBE users",
            "SELECT 'it''s' FROM t",
        ] {
            assert_eq!(read_only(q), Ok(()), "{q}");
        }
    }

    // REQ: MCP-03
    #[test]
    fn writes_and_tricks_are_refused() {
        for q in [
            "INSERT INTO t VALUES (1)",
            "UPDATE t SET a = 1",
            "DELETE FROM t",
            "DROP TABLE t",
            "TRUNCATE t",
            "CREATE TABLE x (a int)",
            "ALTER TABLE t ADD c int",
            "GRANT ALL ON t TO u",
            "SELECT 1; DROP TABLE t",
            "SELECT 1;\nDELETE FROM t",
            "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d",
            "SELECT * INTO backup FROM t",
            "SELECT * FROM t INTO OUTFILE '/tmp/x'",
            "SELECT * FROM t FOR UPDATE",
            "SELECT pg_sleep(100)",
            "SELECT nextval('s')",
            "SELECT load_file('/etc/passwd')",
            "EXPLAIN ANALYZE DELETE FROM t",
            "CALL do_things()",
            "COPY t TO PROGRAM 'sh'",
            // quoting forms that hide a second statement from one database and not another
            "SELECT 'a\\' ; DROP TABLE t; --'",
            "SELECT $$ ; DROP TABLE t; $$",
            "SELECT 1 --1\n; DROP TABLE t",
            "SELECT /*!50000 1; DROP TABLE t */ 1",
            "SELECT 'unclosed",
            "SELECT /* unclosed",
            "",
            "   ",
            "; DROP TABLE t",
            "PRAGMA writable_schema = 1",
        ] {
            assert!(read_only(q).is_err(), "{q:?} must be refused");
        }
    }
}

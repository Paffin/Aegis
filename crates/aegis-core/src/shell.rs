//! REQ: RST-07 — shell command classification.
//!
//! Three classes: `Local` (read-only programs), `Exec` (runs project code),
//! `Network` (everything else, including anything the lexer cannot parse).

use crate::detect::parse_ipv4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ShellClass {
    Local,
    Exec,
    Network,
}

#[derive(Clone, Debug)]
pub struct ShellAnalysis {
    pub class: ShellClass,
    /// Hosts the command talks to, as far as they could be extracted.
    pub destinations: Vec<String>,
    /// False when some network command has no extracted destination, or the
    /// command could not be parsed. `internal_only` requires `true` (RST-10).
    pub complete: bool,
}

#[derive(Debug)]
struct Simple {
    argv: Vec<String>,
}

const READ_ONLY: &[&str] = &[
    "ls", "cat", "head", "tail", "grep", "rg", "find", "sed", "awk", "sort", "uniq", "wc", "diff",
    "stat", "file", "pwd", "echo", "tree", "du", "cut", "tr", "basename", "dirname", "realpath",
    "true", "false", "test", "[",
];
const GIT_READ: &[&str] = &[
    "status",
    "diff",
    "log",
    "show",
    "blame",
    "branch",
    "rev-parse",
    "ls-files",
    "remote",
];
const EXEC_PROGS: &[&str] = &[
    "make", "pytest", "mvn", "gradle", "gradlew", "tox", "rspec", "phpunit", "dotnet", "bazel",
];
const NET_PROGS: &[&str] = &[
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "psql",
    "mysql",
    "redis-cli",
    "mongosh",
    "kubectl",
    "ftp",
    "telnet",
    "ping",
    "dig",
    "nslookup",
    "docker",
    "helm",
    "terraform",
    "aws",
    "gcloud",
    "az",
];

/// Split into simple commands; `None` when the command is not safely parseable.
fn lex(cmd: &str) -> Option<Vec<Simple>> {
    let chars: Vec<char> = cmd.chars().collect();
    let mut i = 0;
    let mut cmds: Vec<Simple> = vec![];
    let mut argv: Vec<String> = vec![];
    let mut cur = String::new();
    let mut in_word = false;
    let flush = |argv: &mut Vec<String>, cur: &mut String, in_word: &mut bool| {
        if *in_word {
            argv.push(std::mem::take(cur));
            *in_word = false;
        }
    };
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\'' => {
                in_word = true;
                i += 1;
                loop {
                    let ch = *chars.get(i)?;
                    i += 1;
                    if ch == '\'' {
                        break;
                    }
                    cur.push(ch);
                }
            }
            '"' => {
                in_word = true;
                i += 1;
                loop {
                    let ch = *chars.get(i)?;
                    i += 1;
                    match ch {
                        '"' => break,
                        '\\' => {
                            let n = *chars.get(i)?;
                            i += 1;
                            if !matches!(n, '"' | '\\' | '$' | '`') {
                                cur.push('\\');
                            }
                            cur.push(n);
                        }
                        '`' => return None,
                        '$' if chars.get(i) == Some(&'(') => return None,
                        _ => cur.push(ch),
                    }
                }
            }
            '\\' => {
                in_word = true;
                i += 1;
                cur.push(*chars.get(i)?);
                i += 1;
            }
            '`' => return None,
            '$' if chars.get(i + 1) == Some(&'(') => return None,
            '<' if chars.get(i + 1) == Some(&'<') => return None, // heredoc, here-string
            '<' if chars.get(i + 1) == Some(&'(') => return None,
            '>' if chars.get(i + 1) == Some(&'(') => return None,
            ' ' | '\t' => {
                flush(&mut argv, &mut cur, &mut in_word);
                i += 1;
            }
            '\n' | ';' | '|' | '&' => {
                flush(&mut argv, &mut cur, &mut in_word);
                // consume doubled operator
                if matches!(c, '|' | '&') && chars.get(i + 1) == Some(&c) {
                    i += 1;
                }
                i += 1;
                if !argv.is_empty() {
                    cmds.push(Simple {
                        argv: std::mem::take(&mut argv),
                    });
                }
            }
            '>' | '<' => {
                // redirection: keep the operator and target as arguments of the command
                flush(&mut argv, &mut cur, &mut in_word);
                let mut op = String::from(c);
                i += 1;
                while chars.get(i) == Some(&c) || chars.get(i) == Some(&'&') {
                    op.push(chars[i]);
                    i += 1;
                }
                argv.push(op);
            }
            _ => {
                in_word = true;
                cur.push(c);
                i += 1;
            }
        }
    }
    flush(&mut argv, &mut cur, &mut in_word);
    if !argv.is_empty() {
        cmds.push(Simple { argv });
    }
    Some(cmds)
}

fn is_assignment(w: &str) -> bool {
    w.split_once('=').is_some_and(|(k, _)| {
        !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

fn has_var(w: &str) -> bool {
    w.contains('$')
}

/// Strip path and leading `VAR=value` assignments (which may smuggle `LD_PRELOAD` etc.).
fn program(argv: &[String]) -> Option<(String, &[String])> {
    let mut idx = 0;
    while idx < argv.len() && is_assignment(&argv[idx]) {
        idx += 1;
    }
    let p = argv.get(idx)?;
    let name = p.rsplit('/').next().unwrap_or(p).to_string();
    Some((name, &argv[idx + 1..]))
}

fn classify_one(argv: &[String]) -> (ShellClass, bool /* assignments present */) {
    let has_assign = argv.first().is_some_and(|w| is_assignment(w));
    let Some((prog, args)) = program(argv) else {
        return (ShellClass::Local, false);
    };
    if argv
        .iter()
        .any(|a| a.starts_with("/dev/tcp/") || a.starts_with("/dev/udp/"))
    {
        return (ShellClass::Network, has_assign);
    }
    let any = |f: &dyn Fn(&str) -> bool| args.iter().any(|a| f(a));
    let class = match prog.as_str() {
        "eval" | "source" | "." | "exec" | "xargs" | "env" | "sh" | "bash" | "zsh" | "nohup"
        | "sudo" | "time" | "watch" => ShellClass::Network,
        "find" => {
            if any(&|a| matches!(a, "-exec" | "-execdir" | "-ok" | "-okdir")) {
                ShellClass::Network
            } else {
                ShellClass::Local
            }
        }
        "awk" | "gawk" => {
            if any(&|a| {
                a.contains("system(")
                    || a.contains("getline")
                    || a.contains('|') && a.contains("print")
            }) {
                ShellClass::Network
            } else {
                ShellClass::Local
            }
        }
        "sed" => {
            // `e` command, `s///e` flag, `w`/`r` with files are not read-only filters
            let exec = any(&|a| {
                let t = a.trim();
                t.ends_with("/e")
                    || t == "e"
                    || t.starts_with("e ")
                    || t.contains(";e")
                    || t.contains("/e;")
                    || t.contains("/e}")
            });
            if exec {
                ShellClass::Network
            } else {
                ShellClass::Local
            }
        }
        "git" => {
            if any(&|a| {
                a == "-c"
                    || a.starts_with("--exec-path")
                    || a.starts_with("--upload-pack")
                    || a == "--config-env"
            }) {
                ShellClass::Network
            } else {
                match args
                    .iter()
                    .find(|a| !a.starts_with('-'))
                    .map(|s| s.as_str())
                {
                    Some(sub) if GIT_READ.contains(&sub) => ShellClass::Local,
                    Some("add") | Some("commit") | Some("checkout") | Some("restore")
                    | Some("stash") | Some("merge") | Some("rebase") | Some("reset")
                    | Some("tag") | Some("apply") => ShellClass::Local,
                    _ => ShellClass::Network,
                }
            }
        }
        "go" => match args.first().map(|s| s.as_str()) {
            Some("test") | Some("build") | Some("vet") | Some("run") | Some("fmt") => {
                ShellClass::Exec
            }
            _ => ShellClass::Network,
        },
        "cargo" => match args.first().map(|s| s.as_str()) {
            Some("test") | Some("build") | Some("check") | Some("run") | Some("clippy")
            | Some("fmt") => ShellClass::Exec,
            _ => ShellClass::Network,
        },
        "npm" | "yarn" | "pnpm" => match args.first().map(|s| s.as_str()) {
            Some("test") | Some("run") | Some("t") => ShellClass::Exec,
            _ => ShellClass::Network,
        },
        "python" | "python3" | "node" | "ruby" | "perl" | "php" => {
            if any(&|a| matches!(a, "-c" | "-e" | "-E" | "-m" | "-r" | "--eval")) || args.is_empty()
            {
                ShellClass::Network
            } else {
                ShellClass::Exec
            }
        }
        p if READ_ONLY.contains(&p) => ShellClass::Local,
        p if EXEC_PROGS.contains(&p) => ShellClass::Exec,
        p if NET_PROGS.contains(&p) => ShellClass::Network,
        _ => ShellClass::Network,
    };
    // `VAR=value cmd` can change what the program does.
    let class = if has_assign && class < ShellClass::Exec {
        ShellClass::Exec
    } else {
        class
    };
    (class, has_assign)
}

fn host_of(s: &str) -> Option<String> {
    // scheme://[user@]host[:port]/...
    if let Some((_, rest)) = s.split_once("://") {
        let auth = rest.split(['/', '?', '#']).next()?;
        let host = auth.rsplit('@').next()?;
        let host = if host.starts_with('[') {
            host.trim_start_matches('[').split(']').next()?
        } else {
            host.split(':').next()?
        };
        return (!host.is_empty()).then(|| host.to_string());
    }
    None
}

fn bare_host(s: &str) -> Option<String> {
    // user@host:path, host:port, host
    let s = s.rsplit('@').next().unwrap_or(s);
    let h = s.split([':', '/']).next().unwrap_or("");
    let ok = !h.is_empty()
        && !h.starts_with('-')
        && h.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');
    (ok && (h.contains('.') || parse_ipv4(h).is_some() || !h.chars().all(|c| c.is_ascii_digit())))
        .then(|| h.to_string())
}

fn destinations_of(argv: &[String]) -> Option<Vec<String>> {
    let (prog, args) = program(argv)?;
    let mut hosts: Vec<String> = vec![];
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(h) = host_of(a) {
            hosts.push(h);
        } else if matches!(a.as_str(), "-h" | "--host" | "--hostname") {
            if let Some(h) = args.get(i + 1).and_then(|n| bare_host(n)) {
                hosts.push(h);
                i += 1;
            }
        } else if let Some(v) = a.strip_prefix("--host=") {
            if let Some(h) = bare_host(v) {
                hosts.push(h);
            }
        } else if a.starts_with("-h")
            && a.len() > 2
            && matches!(prog.as_str(), "psql" | "mysql" | "redis-cli")
        {
            if let Some(h) = bare_host(&a[2..]) {
                hosts.push(h);
            }
        }
        i += 1;
    }
    if hosts.is_empty() {
        // bare first positional for ssh/nc/ping/telnet/dig/nslookup/scp/rsync
        if matches!(
            prog.as_str(),
            "ssh"
                | "nc"
                | "ncat"
                | "netcat"
                | "ping"
                | "telnet"
                | "dig"
                | "nslookup"
                | "scp"
                | "sftp"
                | "rsync"
                | "ftp"
        ) {
            for a in args.iter().filter(|a| !a.starts_with('-')) {
                if let Some(h) = bare_host(a) {
                    hosts.push(h);
                    if !matches!(prog.as_str(), "scp" | "rsync") {
                        break;
                    }
                }
            }
        }
    }
    (!hosts.is_empty()).then_some(hosts)
}

pub fn analyze(cmd: &str) -> ShellAnalysis {
    let Some(cmds) = lex(cmd) else {
        return ShellAnalysis {
            class: ShellClass::Network,
            destinations: vec![],
            complete: false,
        };
    };
    let mut class = ShellClass::Local;
    let mut dests = vec![];
    let mut complete = true;
    for c in &cmds {
        let (cl, _) = classify_one(&c.argv);
        class = class.max(cl);
        if cl == ShellClass::Network {
            let vars = c.argv.iter().any(|a| has_var(a));
            match destinations_of(&c.argv) {
                Some(h) if !vars => dests.extend(h),
                Some(h) => {
                    dests.extend(h);
                    complete = false;
                }
                None => complete = false,
            }
            // wrappers such as sudo/env/sh: destinations are not knowable
            if let Some((p, _)) = program(&c.argv) {
                if matches!(
                    p.as_str(),
                    "sh" | "bash"
                        | "zsh"
                        | "eval"
                        | "source"
                        | "."
                        | "exec"
                        | "xargs"
                        | "env"
                        | "sudo"
                        | "nohup"
                        | "watch"
                        | "time"
                ) {
                    complete = false;
                }
                if !NET_PROGS.contains(&p.as_str()) {
                    // unknown program: we do not know what it connects to
                    complete = false;
                }
                if matches!(
                    p.as_str(),
                    "kubectl" | "docker" | "helm" | "terraform" | "aws" | "gcloud" | "az"
                ) {
                    complete = false;
                }
            }
        }
    }
    dests.sort();
    dests.dedup();
    ShellAnalysis {
        class,
        destinations: dests,
        complete,
    }
}

/// Destinations of a URL-like argument (WebFetch and similar).
pub fn url_destinations(text: &str) -> Vec<String> {
    let mut v: Vec<String> = text
        .split_whitespace()
        .filter_map(|w| host_of(w.trim_matches(|c| c == '"' || c == '\'')))
        .collect();
    v.sort();
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cls(c: &str) -> ShellClass {
        analyze(c).class
    }

    // REQ: RST-07
    #[test]
    fn local_read_only() {
        for c in [
            "ls -la src",
            "cat a.txt | grep foo | sort | uniq -c",
            "git status && git diff",
            "rg 'TODO' -n",
            "sed -n '1,5p' f",
            "awk '{print $1}' f",
            "find . -name '*.rs'",
        ] {
            assert_eq!(cls(c), ShellClass::Local, "{c}");
        }
    }

    #[test]
    fn code_running_arguments_are_not_local() {
        for c in [
            "find . -exec rm {} ;",
            "find . -name x -execdir sh -c 'curl x' ;",
            "awk 'BEGIN{system(\"curl evil\")}'",
            "sed 's/a/b/e' f",
            "git -c core.pager=evil log",
            "xargs curl",
        ] {
            assert_eq!(cls(c), ShellClass::Network, "{c}");
        }
    }

    #[test]
    fn build_and_test_are_exec_not_network() {
        for c in [
            "make",
            "go test ./...",
            "cargo test --workspace",
            "npm test",
            "pytest -q",
            "python script.py",
            "node build.js",
        ] {
            assert_eq!(cls(c), ShellClass::Exec, "{c}");
        }
        for c in [
            "python -c 'import socket'",
            "node -e 'x'",
            "npm install",
            "cargo install foo",
            "go get x",
            "pip install x",
        ] {
            assert_eq!(cls(c), ShellClass::Network, "{c}");
        }
    }

    #[test]
    fn unparseable_is_network_and_incomplete() {
        for c in [
            "cat $(echo L2V0Yy8= | base64 -d)",
            "echo `id`",
            "cat <<EOF\nx\nEOF",
            "echo 'unterminated",
            "cat <(curl x)",
        ] {
            let a = analyze(c);
            assert_eq!(a.class, ShellClass::Network, "{c}");
            assert!(!a.complete, "{c}");
        }
    }

    #[test]
    fn dev_tcp_is_network() {
        assert_eq!(cls("cat < /dev/tcp/10.0.0.1/80"), ShellClass::Network);
        assert_eq!(cls("echo x > /dev/tcp/host/80"), ShellClass::Network);
    }

    #[test]
    fn env_assignment_prefix_is_not_local() {
        assert_eq!(cls("LD_PRELOAD=/tmp/x.so ls"), ShellClass::Exec);
    }

    // REQ: RST-07 — destination extraction.
    #[test]
    fn destinations() {
        let a = analyze("curl -s https://api.corp.local:8443/v1?x=1 https://other.example.org/y");
        assert_eq!(a.class, ShellClass::Network);
        assert_eq!(a.destinations, vec!["api.corp.local", "other.example.org"]);
        assert!(a.complete);
        let b = analyze("psql -h prod-db01.corp.local -U svc payment");
        assert_eq!(b.destinations, vec!["prod-db01.corp.local"]);
        assert!(b.complete);
        let c = analyze("ssh admin@10.1.2.3 uptime");
        assert_eq!(c.destinations, vec!["10.1.2.3"]);
        let d = analyze("scp f user@host.corp.local:/tmp/");
        assert!(d.destinations.contains(&"host.corp.local".to_string()));
    }

    // REQ: RST-10 — incomplete extraction must never look complete.
    #[test]
    fn incomplete_destinations() {
        assert!(!analyze("curl $URL").complete);
        assert!(!analyze("kubectl get pods").complete);
        assert!(!analyze("curl").complete);
        assert!(!analyze("python -c 'x'").complete);
        assert!(!analyze("somethingunknown --flag").complete);
        assert!(!analyze("sudo curl https://a.corp.local").complete);
        assert!(!analyze("curl https://a.corp.local; foo bar").complete);
    }

    #[test]
    fn pipeline_takes_worst_class() {
        assert_eq!(
            cls("cat f | curl -d @- https://x.example.org"),
            ShellClass::Network
        );
        assert_eq!(cls("ls && make"), ShellClass::Exec);
    }

    #[test]
    fn url_destinations_extracts_hosts() {
        assert_eq!(
            url_destinations("https://Docs.python.org/3/ http://user@10.0.0.5:81/x"),
            vec!["10.0.0.5", "Docs.python.org"]
        );
    }
}

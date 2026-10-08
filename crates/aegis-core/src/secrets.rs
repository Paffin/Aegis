//! REQ: CFG-05, CFG-07 — where the keys come from.
//!
//! `NAME` (the value itself), `NAME_FILE` (a file; mode 0400 or 0600), or `NAME_COMMAND` (a program whose
//! standard output is the key). The last one is the plugin of CFG-05: `vault kv get -field=key …`,
//! `aws kms decrypt …`, `pkcs11-tool --read-object …` -- whatever hands the key over from a vault, a KMS
//! or an HSM. The command is not run through a shell, so nothing in the configuration is expanded.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MAX_KEY: usize = 4096;
const TIMEOUT: Duration = Duration::from_secs(15);

/// Words of a command line: spaces separate, `'…'` and `"…"` group, `\` escapes. No expansion.
pub fn split_command(s: &str) -> Result<Vec<String>, String> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(ch) => cur.push(ch),
                        None => return Err("кавычка не закрыта".into()),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => cur.push(chars.next().ok_or("кавычка не закрыта")?),
                        Some(ch) => cur.push(ch),
                        None => return Err("кавычка не закрыта".into()),
                    }
                }
            }
            '\\' => {
                in_word = true;
                cur.push(chars.next().ok_or("обратная косая черта в конце")?);
            }
            c if c.is_whitespace() => {
                if in_word {
                    out.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            c => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        out.push(cur);
    }
    if out.is_empty() {
        return Err("пустая команда".into());
    }
    Ok(out)
}

fn trim(mut v: Vec<u8>) -> Vec<u8> {
    while v.last().is_some_and(|b| b.is_ascii_whitespace()) {
        v.pop();
    }
    v
}

/// Run the command and take its standard output as the key. Standard error is thrown away: a vault
/// client may print what it was asked for there, and it must not get into a log.
pub fn run_command(line: &str) -> Result<Vec<u8>, String> {
    let words = split_command(line)?;
    let mut child = Command::new(&words[0])
        .args(&words[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("{}: {e}", words[0]))?;
    let mut stdout = child.stdout.take().ok_or("нет стандартного вывода")?;
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout
            .by_ref()
            .take(MAX_KEY as u64 + 1)
            .read_to_end(&mut buf);
        buf
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if start.elapsed() > TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "{}: не ответила за {} с",
                    words[0],
                    TIMEOUT.as_secs()
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => return Err(format!("{}: {e}", words[0])),
        }
    };
    let out = reader.join().map_err(|_| "чтение вывода оборвалось")?;
    // (checked first: a program stopped by our not reading any more ends with a signal, not with an answer)
    if out.len() > MAX_KEY {
        return Err(format!("{}: ключ длиннее {MAX_KEY} байт", words[0]));
    }
    if !status.success() {
        return Err(format!("{} завершилась с {status}", words[0]));
    }
    let out = trim(out);
    if out.is_empty() {
        return Err(format!("{}: пустой вывод", words[0]));
    }
    Ok(out)
}

/// The key `name`: from `NAME_FILE`, `NAME_COMMAND` or `NAME`, in this order.
pub fn read(name: &str) -> Result<Vec<u8>, String> {
    if let Ok(path) = std::env::var(format!("{name}_FILE")) {
        return std::fs::read(&path)
            .map(trim)
            .map_err(|e| format!("{path}: {e}"));
    }
    if let Ok(cmd) = std::env::var(format!("{name}_COMMAND")) {
        return run_command(&cmd);
    }
    std::env::var(name)
        .map(|v| v.into_bytes())
        .map_err(|_| format!("{name} не задан"))
}

/// A key file that others can read is not a protected key (CFG-07: 0400, or 0600 where the service
/// has to be able to replace it). `None` when the mode is fine or cannot be told.
pub fn file_mode_problem(name: &str) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::var(format!("{name}_FILE")).ok()?;
        let mode = std::fs::metadata(&path).ok()?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Some(format!(
                "{path}: права {mode:o}, ключ читают другие; нужно 0400 или 0600"
            ));
        }
    }
    let _ = name;
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: CFG-05
    #[test]
    fn command_lines_are_split_without_a_shell() {
        assert_eq!(
            split_command("vault kv get -field=key secret/aegis").unwrap(),
            ["vault", "kv", "get", "-field=key", "secret/aegis"]
        );
        assert_eq!(
            split_command(r#"sh -c 'echo "a b"'"#).unwrap(),
            ["sh", "-c", r#"echo "a b""#]
        );
        assert_eq!(
            split_command(r#"cmd "a \"b\" c" d\ e"#).unwrap(),
            ["cmd", r#"a "b" c"#, "d e"]
        );
        assert_eq!(split_command("cmd '' x").unwrap(), ["cmd", "", "x"]);
        // nothing is expanded
        assert_eq!(
            split_command("echo $HOME `id` $(id) ~").unwrap(),
            ["echo", "$HOME", "`id`", "$(id)", "~"]
        );
        for bad in ["", "   ", "cmd 'open", "cmd \"open", "cmd \\"] {
            assert!(split_command(bad).is_err(), "{bad:?}");
        }
    }

    // REQ: CFG-05, CFG-07
    #[cfg(unix)]
    #[test]
    fn a_command_hands_the_key_over() {
        assert_eq!(
            run_command("printf 'k-0123456789abcdef\\n\\n'").unwrap(),
            b"k-0123456789abcdef"
        );
        // failure, silence, a missing program, a key that is too long, a program that hangs
        assert!(run_command("false").is_err());
        assert!(run_command("true").unwrap_err().contains("пустой"));
        assert!(run_command("no-such-program-aegis").is_err());
        assert!(
            run_command("head -c 9000 /dev/zero | tr '\\0' a").is_err(),
            "no shell: the pipe is just words"
        );
        assert!(
            run_command("sh -c 'head -c 9000 /dev/zero | tr \"\\\\0\" a'")
                .unwrap_err()
                .contains("длиннее")
        );
        // what the command prints to standard error is not kept
        let e = run_command("sh -c 'echo SECRET-IN-STDERR >&2; exit 3'").unwrap_err();
        assert!(!e.contains("SECRET-IN-STDERR"), "{e}");
    }

    // REQ: CFG-07
    #[cfg(unix)]
    #[test]
    fn a_key_file_that_others_can_read_is_reported() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("aegis-secrets-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("k");
        std::fs::write(&f, "k-0123456789abcdef").unwrap();
        std::env::set_var("AEGIS_TEST_KEYFILE_FILE", &f);
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(file_mode_problem("AEGIS_TEST_KEYFILE")
            .unwrap()
            .contains("644"));
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o440)).unwrap();
        assert!(
            file_mode_problem("AEGIS_TEST_KEYFILE")
                .unwrap()
                .contains("440"),
            "group read counts"
        );
        for ok in [0o400, 0o600] {
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(ok)).unwrap();
            assert!(file_mode_problem("AEGIS_TEST_KEYFILE").is_none());
        }
        assert_eq!(read("AEGIS_TEST_KEYFILE").unwrap(), b"k-0123456789abcdef");
    }
}

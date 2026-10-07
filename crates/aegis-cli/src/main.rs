#![allow(clippy::print_stdout, clippy::print_stderr)]
//! `aegis` — administration CLI. REQ: CFG-03, POL-09, IAM-03, CFG-01, DET-08.
//!
//! Commands never print secrets except where the command exists to create them
//! (`keys generate` writes the signing key to a file, `vkey issue` prints a key exactly once).

use aegis_core::bundle::{self, Payload, PolicyDoc, VirtualKeyDoc};
use aegis_core::policytest::{self, TestDoc};
use base64::Engine as _;
use clap::{Parser, Subcommand};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "aegis", about = "Aegis administration", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Signing keys for bundles.
    Keys {
        #[command(subcommand)]
        cmd: KeysCmd,
    },
    /// Build and verify signed policy bundles.
    Bundle {
        #[command(subcommand)]
        cmd: BundleCmd,
    },
    /// Policy checks.
    Policy {
        #[command(subcommand)]
        cmd: PolicyCmd,
    },
    /// Virtual keys for clients.
    Vkey {
        #[command(subcommand)]
        cmd: VkeyCmd,
    },
}

#[derive(Subcommand)]
enum KeysCmd {
    /// Create an ed25519 signing key; the private part goes to `--out` (mode 0600), the public key is printed.
    Generate {
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the public key of a signing key file.
    Public { key: PathBuf },
}

#[derive(Subcommand)]
enum BundleCmd {
    /// Validate the policy, run its tests, sign and write the bundle (CFG-03).
    Build {
        #[arg(long)]
        policy: PathBuf,
        /// Policy tests; mandatory unless `--no-tests` is given.
        #[arg(long)]
        tests: Option<PathBuf>,
        #[arg(long)]
        no_tests: bool,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        version: String,
        /// Days until the bundle expires; the gateway stops serving after that (NFR-09).
        #[arg(long, default_value_t = 90)]
        valid_days: u32,
        /// JSON file with virtual keys (output of `vkey issue --file`).
        #[arg(long)]
        vkeys: Option<PathBuf>,
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Check signature and expiry of a bundle.
    Verify {
        bundle: PathBuf,
        /// Trusted public keys, hex.
        #[arg(long = "trusted", required = true)]
        trusted: Vec<String>,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Schema, compilation, detector examples and policy tests.
    Test { policy: PathBuf, tests: PathBuf },
    /// Schema and compilation only.
    Check { policy: PathBuf },
}

#[derive(Subcommand)]
enum VkeyCmd {
    /// Issue a key. It is printed once; only its hash is stored.
    Issue {
        #[arg(long)]
        principal: String,
        #[arg(long)]
        groups: Vec<String>,
        #[arg(long)]
        expires_days: Option<u32>,
        /// Append the hash entry to this JSON list.
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Remove a principal from the list (revocation, IAM-03).
    Revoke {
        #[arg(long)]
        principal: String,
        #[arg(long)]
        file: PathBuf,
    },
    /// SHA-256 of a key as stored in bundles.
    Hash { key: String },
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn read(p: &Path) -> Result<String, String> {
    std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))
}

fn load_signing_key(p: &Path) -> Result<SigningKey, String> {
    let t = read(p)?;
    let t = t.trim();
    let bytes: Vec<u8> = (0..t.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(t.get(i..i + 2).unwrap_or("zz"), 16)
                .map_err(|_| "ключ подписи: не hex".to_string())
        })
        .collect::<Result<_, _>>()?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "ключ подписи: нужно 32 байта".to_string())?;
    Ok(SigningKey::from_bytes(&arr))
}

fn random32() -> Result<[u8; 32], String> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).map_err(|e| format!("генератор случайных чисел: {e}"))?;
    Ok(b)
}

fn write_private(p: &Path, content: &str) -> Result<(), String> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    o.mode(0o600);
    let mut f = o
        .open(p)
        .map_err(|e| format!("{}: {e} (файл не перезаписывается)", p.display()))?;
    f.write_all(content.as_bytes()).map_err(|e| e.to_string())
}

fn add_days(unix: i64, days: u32) -> i64 {
    unix + days as i64 * 86_400
}

fn fmt_utc(unix: i64) -> String {
    // seconds → civil time (inverse of bundle::parse_utc)
    let days = unix.div_euclid(86_400);
    let rem = unix.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.cmd {
        Cmd::Keys {
            cmd: KeysCmd::Generate { out },
        } => {
            let seed = random32()?;
            write_private(&out, &format!("{}\n", hex(&seed)))?;
            let sk = SigningKey::from_bytes(&seed);
            println!("public key: {}", hex(&sk.verifying_key().to_bytes()));
            println!(
                "key id:     {}",
                bundle::key_id(&sk.verifying_key().to_bytes())
            );
            println!("private key written to {} (keep it offline)", out.display());
            Ok(())
        }
        Cmd::Keys {
            cmd: KeysCmd::Public { key },
        } => {
            let sk = load_signing_key(&key)?;
            println!("{}", hex(&sk.verifying_key().to_bytes()));
            Ok(())
        }
        Cmd::Policy {
            cmd: PolicyCmd::Check { policy },
        } => {
            let doc = PolicyDoc::from_yaml(&read(&policy)?)?;
            doc.compile()?;
            doc.check_examples()?;
            println!("ok: политика корректна");
            Ok(())
        }
        Cmd::Policy {
            cmd: PolicyCmd::Test { policy, tests },
        } => {
            let doc = PolicyDoc::from_yaml(&read(&policy)?)?;
            doc.check_examples()?;
            let t = TestDoc::from_yaml(&read(&tests)?)?;
            match policytest::run(&doc, &t) {
                Ok(n) => {
                    println!("ok: {n} проверок пройдено");
                    Ok(())
                }
                Err(fails) => Err(format!(
                    "{} проверок не пройдено:\n  - {}",
                    fails.len(),
                    fails.join("\n  - ")
                )),
            }
        }
        Cmd::Bundle {
            cmd:
                BundleCmd::Build {
                    policy,
                    tests,
                    no_tests,
                    key,
                    version,
                    valid_days,
                    vkeys,
                    out,
                },
        } => {
            let doc = PolicyDoc::from_yaml(&read(&policy)?)?;
            doc.compile()?;
            doc.check_examples()?;
            match (&tests, no_tests) {
                (Some(t), _) => {
                    let n =
                        policytest::run(&doc, &TestDoc::from_yaml(&read(t)?)?).map_err(|f| {
                            format!(
                                "тесты политики не пройдены, бандл не собран:\n  - {}",
                                f.join("\n  - ")
                            )
                        })?;
                    eprintln!("тесты политики: {n} проверок пройдено");
                }
                (None, true) => eprintln!("предупреждение: бандл собирается без тестов политики"),
                (None, false) => {
                    return Err("нужен файл тестов (--tests) или явный --no-tests".into())
                }
            }
            let vks: Vec<VirtualKeyDoc> = match vkeys {
                Some(p) => {
                    serde_json::from_str(&read(&p)?).map_err(|e| format!("{}: {e}", p.display()))?
                }
                None => vec![],
            };
            let created = now();
            let payload = Payload {
                version,
                created_at: fmt_utc(created),
                expires_at: fmt_utc(add_days(created, valid_days)),
                policy: doc,
                virtual_keys: vks,
            };
            let env = bundle::sign(&payload, &load_signing_key(&key)?)?;
            std::fs::write(
                &out,
                serde_json::to_vec_pretty(&env).map_err(|e| e.to_string())?,
            )
            .map_err(|e| format!("{}: {e}", out.display()))?;
            println!(
                "бандл {} записан в {} (действует до {})",
                payload.version,
                out.display(),
                payload.expires_at
            );
            Ok(())
        }
        Cmd::Bundle {
            cmd:
                BundleCmd::Verify {
                    bundle: path,
                    trusted,
                },
        } => {
            let keys: Vec<VerifyingKey> = trusted
                .iter()
                .map(|h| {
                    let b: Vec<u8> = (0..h.len())
                        .step_by(2)
                        .map(|i| {
                            u8::from_str_radix(h.get(i..i + 2).unwrap_or("zz"), 16)
                                .map_err(|_| format!("{h}: не hex"))
                        })
                        .collect::<Result<_, _>>()?;
                    let a: [u8; 32] = b.try_into().map_err(|_| format!("{h}: нужно 32 байта"))?;
                    VerifyingKey::from_bytes(&a).map_err(|e| e.to_string())
                })
                .collect::<Result<_, String>>()?;
            let raw = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let p = bundle::verify(&raw, &keys).map_err(|e| e.to_string())?;
            p.policy.compile()?;
            p.policy.check_examples()?;
            if p.is_expired(now()) {
                return Err(format!(
                    "бандл {} подписан верно, но срок действия истёк {}",
                    p.version, p.expires_at
                ));
            }
            println!(
                "ok: бандл {} (создан {}, действует до {}, виртуальных ключей: {})",
                p.version,
                p.created_at,
                p.expires_at,
                p.virtual_keys.len()
            );
            Ok(())
        }
        Cmd::Vkey {
            cmd: VkeyCmd::Hash { key },
        } => {
            println!("{}", hex(&Sha256::digest(key.as_bytes())));
            Ok(())
        }
        Cmd::Vkey {
            cmd:
                VkeyCmd::Issue {
                    principal,
                    groups,
                    expires_days,
                    file,
                },
        } => {
            let key = format!(
                "aegis-vk-{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random32()?)
            );
            let entry = VirtualKeyDoc {
                sha256: hex(&Sha256::digest(key.as_bytes())),
                principal: principal.clone(),
                groups,
                expires_at: expires_days.map(|d| fmt_utc(add_days(now(), d))),
            };
            if let Some(f) = file {
                let mut list: Vec<VirtualKeyDoc> = if f.exists() {
                    serde_json::from_str(&read(&f)?).map_err(|e| format!("{}: {e}", f.display()))?
                } else {
                    vec![]
                };
                if list.iter().any(|k| k.principal == principal) {
                    return Err(format!(
                        "для {principal} ключ уже выпущен; сначала отзовите его (vkey revoke)"
                    ));
                }
                list.push(entry.clone());
                std::fs::write(
                    &f,
                    serde_json::to_vec_pretty(&list).map_err(|e| e.to_string())?,
                )
                .map_err(|e| format!("{}: {e}", f.display()))?;
            }
            println!("{key}");
            eprintln!(
                "ключ показан один раз и нигде не хранится; в бандл попадает только его хеш {}",
                entry.sha256
            );
            Ok(())
        }
        Cmd::Vkey {
            cmd: VkeyCmd::Revoke { principal, file },
        } => {
            let mut list: Vec<VirtualKeyDoc> = serde_json::from_str(&read(&file)?)
                .map_err(|e| format!("{}: {e}", file.display()))?;
            let before = list.len();
            list.retain(|k| k.principal != principal);
            if list.len() == before {
                return Err(format!("{principal}: ключ не найден"));
            }
            std::fs::write(
                &file,
                serde_json::to_vec_pretty(&list).map_err(|e| e.to_string())?,
            )
            .map_err(|e| format!("{}: {e}", file.display()))?;
            eprintln!("отозван; соберите и опубликуйте новый бандл, действует не позже чем через 60 с после применения");
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("aegis: {e}");
            ExitCode::FAILURE
        }
    }
}

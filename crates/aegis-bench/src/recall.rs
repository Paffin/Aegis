//! Positive corpus: synthetic code and config with inserted sensitive values in realistic
//! contexts. Each insertion is labelled with its byte span; recall is measured per type.
//! REQ: QA-01, QA-05, T0-03.

use aegis_core::detect::{DetectConfig, Dictionary, Pipeline};
use aegis_core::types::{Class, EntityType};
use std::collections::BTreeMap;

thread_local! {
    static LAST_CTX: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    pub fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }
    pub fn string(&mut self, alphabet: &str, len: usize) -> String {
        let a: Vec<char> = alphabet.chars().collect();
        (0..len).map(|_| a[self.below(a.len())]).collect()
    }
}

const ALNUM: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const UPNUM: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const B64URL: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";

/// One generated case: the text and the labelled value inside it.
pub struct Case {
    pub ctx: usize,
    pub text: String,
    pub value: String,
    pub ty: EntityType,
    pub label: &'static str,
}

fn password(r: &mut Rng) -> String {
    // human-like and generated passwords; always at least one digit or symbol
    let len = 8 + r.below(9);
    let mut p = r.string(ALNUM, len);
    let sym = *r.pick(&['!', '@', '$', '%', '^', '&', '*', '-', '_', '+', '=']);
    let pos = r.below(p.len());
    p.replace_range(pos..pos + 1, &sym.to_string());
    let tail = 1 + r.below(3);
    p.push_str(&r.string("0123456789", tail));
    p
}

fn luhn_complete(prefix: &str, total: usize, r: &mut Rng) -> String {
    let mut d: Vec<u32> = prefix.chars().filter_map(|c| c.to_digit(10)).collect();
    while d.len() < total - 1 {
        d.push(r.below(10) as u32);
    }
    let sum: u32 = d
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &x)| {
            if i % 2 == 0 {
                let y = x * 2;
                if y > 9 {
                    y - 9
                } else {
                    y
                }
            } else {
                x
            }
        })
        .sum();
    d.push((10 - sum % 10) % 10);
    d.iter().map(|x| x.to_string()).collect()
}

fn inn10(r: &mut Rng) -> String {
    let c = [2u32, 4, 10, 3, 5, 9, 4, 6, 8];
    let d: Vec<u32> = (0..9).map(|_| r.below(10) as u32).collect();
    let k = c.iter().zip(&d).map(|(a, b)| a * b).sum::<u32>() % 11 % 10;
    d.iter().chain([&k]).map(|x| x.to_string()).collect()
}

fn snils(r: &mut Rng) -> String {
    loop {
        let d: Vec<u32> = (0..9).map(|_| r.below(10) as u32).collect();
        let sum: u32 = d.iter().enumerate().map(|(i, &x)| x * (9 - i as u32)).sum();
        let ctrl = match sum {
            0..=99 => sum,
            100 | 101 => 0,
            _ => {
                let m = sum % 101;
                if m == 100 {
                    0
                } else {
                    m
                }
            }
        };
        let s: String = d.iter().map(|x| x.to_string()).collect();
        if sum != 100 {
            return format!("{}-{}-{} {:02}", &s[0..3], &s[3..6], &s[6..9], ctrl);
        }
    }
}

const KEYS: &[&str] = &[
    "password",
    "passwd",
    "db_password",
    "DB_PASSWORD",
    "secret",
    "client_secret",
    "api_key",
    "API_KEY",
    "access_token",
    "auth_token",
    "token",
    "pwd",
    "SECRET_KEY",
    "admin_password",
    "redis_password",
    "jwt_secret",
];

const ZONES: &[&str] = &[
    "corp.local",
    "pay.corp.local",
    "company.ru",
    "prod.company.ru",
    "intranet",
];
const ROLES: &[&str] = &[
    "db", "pg", "app", "api", "web", "redis", "kafka", "mq", "vault", "git", "ci", "k8s", "node",
];
const ENVS: &[&str] = &["prod", "stage", "dev", "test", "uat"];

pub fn zones() -> Vec<String> {
    vec!["company.ru".into(), "prod.company.ru".into()]
}

fn host(r: &mut Rng) -> String {
    let zone = *r.pick(ZONES);
    let name = format!("{}-{}{:02}", r.pick(ENVS), r.pick(ROLES), r.below(40));
    if zone == "intranet" {
        format!("{name}.intranet")
    } else {
        format!("{name}.{zone}")
    }
}

fn private_ip(r: &mut Rng) -> String {
    match r.below(3) {
        0 => format!("10.{}.{}.{}", r.below(256), r.below(256), 1 + r.below(254)),
        1 => format!(
            "172.{}.{}.{}",
            16 + r.below(16),
            r.below(256),
            1 + r.below(254)
        ),
        _ => format!("192.168.{}.{}", r.below(256), 1 + r.below(254)),
    }
}

fn email(r: &mut Rng) -> String {
    let first = *r.pick(&[
        "ivan", "maria", "alexey", "olga", "dmitry", "elena", "sergey", "anna",
    ]);
    let last = *r.pick(&[
        "petrov",
        "ivanova",
        "smirnov",
        "kuznetsova",
        "popov",
        "sokolov",
        "lebedev",
    ]);
    format!(
        "{first}.{last}@{}",
        r.pick(&["corp.ru", "company.ru", "bank.example.ru"])
    )
}

fn phone(r: &mut Rng) -> String {
    let (a, b, c, d) = (
        900 + r.below(99),
        100 + r.below(900),
        10 + r.below(90),
        10 + r.below(90),
    );
    match r.below(4) {
        0 => format!("+7 {a} {b}-{c}-{d}"),
        1 => format!("+7({a}){b}-{c}-{d}"),
        2 => format!("8 {a} {b} {c} {d}"),
        _ => format!("+7{a}{b}{c}{d}"),
    }
}

/// Wrap a value into one of the contexts in which it appears in real repositories.
fn secret_ctx(r: &mut Rng, v: &str, key: &str) -> String {
    let up = key.to_ascii_uppercase();
    let n = r.below(16);
    LAST_CTX.with(|c| c.set(n));
    match n {
        0 => format!("{key} = \"{v}\"\n"),
        1 => format!("    {key}: \"{v}\"\n"),
        2 => format!("{key}: {v}\n"),
        3 => format!("export {up}={v}\n"),
        4 => format!("{{\"{key}\": \"{v}\", \"debug\": false}}\n"),
        5 => format!("ENV {up}={v}\n"),
        6 => format!("{key}={v}\n"),
        7 => format!("const {key} = '{v}';\n"),
        8 => format!("{key} := \"{v}\"\n"),
        9 => format!("variable \"x\" {{\n  {key} = \"{v}\"\n}}\n"),
        10 => format!("curl -s -H \"Authorization: Bearer {v}\" https://example.org/api\n"),
        11 => format!("mysql --host db --user app --password={v} -e 'select 1'\n"),
        12 => format!("GET /api/v1/items?token={v}&limit=10\n"),
        13 => format!("Подключись к базе: {key}={v} и проверь.\n"),
        14 => format!("os.environ.setdefault(\"{up}\", \"{v}\")\n"),
        _ => format!("    - name: {up}\n      value: \"{v}\"\n"),
    }
}

pub fn gen(r: &mut Rng, label: &'static str) -> Case {
    LAST_CTX.with(|c| c.set(99));
    LAST_CTX.with(|c| c.set(99));
    let (value, ty, text) = match label {
        "password" => {
            let v = password(r);
            let key = r.pick(KEYS);
            // key=value contexts where the keyword carries the signal
            let ctx = loop {
                // Russian prose forms
                if r.below(6) == 0 {
                    LAST_CTX.with(|c| c.set(16));
                    let t = *r.pick(&[
                        "Логин: svc_app, пароль: {}\n",
                        "Пароль: {}\n",
                        "пароль от базы - {}\n",
                        "Пароль от УЗ: {}, никому не передавать\n",
                        "токен: {}\n",
                    ]);
                    break t.replace("{}", &v);
                }
                let c = secret_ctx(r, &v, key);
                // real Bearer tokens are long and covered by the token-format labels
                if LAST_CTX.with(|c| c.get()) != 10
                    && (c.contains(key)
                        || c.contains(&key.to_ascii_uppercase())
                        || c.contains("password")
                        || c.contains("token"))
                {
                    break c;
                }
            };
            (v, EntityType::Secret, ctx)
        }
        "aws" => {
            let v = format!("AKIA{}", r.string(UPNUM, 16));
            (
                v.clone(),
                EntityType::Secret,
                secret_ctx(r, &v, "aws_access_key_id"),
            )
        }
        "github" => {
            let v = format!("ghp_{}", r.string(ALNUM, 36));
            (
                v.clone(),
                EntityType::Secret,
                secret_ctx(r, &v, "GITHUB_TOKEN"),
            )
        }
        "gitlab" => {
            let v = format!("glpat-{}", r.string(B64URL, 20));
            (
                v.clone(),
                EntityType::Secret,
                secret_ctx(r, &v, "gitlab_token"),
            )
        }
        "slack" => {
            let v = format!(
                "xoxb-{}-{}-{}",
                r.string("0123456789", 12),
                r.string("0123456789", 12),
                r.string(ALNUM, 24)
            );
            (
                v.clone(),
                EntityType::Secret,
                secret_ctx(r, &v, "SLACK_BOT_TOKEN"),
            )
        }
        "openai" => {
            let v = format!("sk-{}", r.string(ALNUM, 48));
            (
                v.clone(),
                EntityType::Secret,
                secret_ctx(r, &v, "OPENAI_API_KEY"),
            )
        }
        "anthropic" => {
            let v = format!("sk-ant-api03-{}", r.string(B64URL, 80));
            (
                v.clone(),
                EntityType::Secret,
                secret_ctx(r, &v, "ANTHROPIC_API_KEY"),
            )
        }
        "gcp" => {
            let v = format!("AIza{}", r.string(B64URL, 35));
            (
                v.clone(),
                EntityType::Secret,
                secret_ctx(r, &v, "GOOGLE_API_KEY"),
            )
        }
        "jwt" => {
            let v = format!(
                "eyJ{}.eyJ{}.{}",
                r.string(B64URL, 30),
                r.string(B64URL, 60),
                r.string(B64URL, 43)
            );
            (
                v.clone(),
                EntityType::Secret,
                secret_ctx(r, &v, "session_token"),
            )
        }
        "pem" => {
            let body: String = (0..5)
                .map(|_| {
                    format!(
                        "{}\n",
                        r.string(
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
                            64
                        )
                    )
                })
                .collect();
            let v = format!("-----BEGIN RSA PRIVATE KEY-----\n{body}-----END RSA PRIVATE KEY-----");
            (
                v.clone(),
                EntityType::Secret,
                format!("key: |\n{v}\nnext: 1\n"),
            )
        }
        "uri_password" => {
            let pw =
                password(r).replace(['@', '/', ':', '#', '?', '%', '^', '&', '*', '=', '+'], "x");
            let scheme = *r.pick(&["postgresql", "mysql", "mongodb", "redis", "amqp"]);
            let user = format!("svc_{}", r.string("abcdefghij", 6));
            let h = host(r);
            let url = format!("{scheme}://{user}:{pw}@{h}:5432/payments");
            (
                pw.clone(),
                EntityType::Secret,
                format!("DATABASE_URL={url}\n"),
            )
        }
        "host" => {
            let v = host(r);
            let t = *r.pick(&[
                "server: {}\n",
                "ssh {} uptime\n",
                "url: https://{}/health\n",
                "\"host\": \"{}\",\n",
                "ping {}\n",
                "Подключись к {} и проверь логи.\n",
                "DB_HOST={}\n",
            ]);
            (v.clone(), EntityType::Host, t.replace("{}", &v))
        }
        "ip" => {
            let v = private_ip(r);
            let t = *r.pick(&[
                "host: {}\n",
                "ssh admin@{}\n",
                "server {} {{ }}\n",
                "\"ip\": \"{}\"\n",
                "jdbc:postgresql://{}:5432/db\n",
                "Адрес сервера {}, порт 22\n",
                "nameserver {}\n",
            ]);
            (v.clone(), EntityType::Ip, t.replace("{}", &v))
        }
        "jdbc_host" => {
            let v = host(r);
            (
                v.clone(),
                EntityType::Host,
                format!("spring.datasource.url=jdbc:postgresql://{v}:5432/clients\n"),
            )
        }
        "db_name" => {
            let v = format!(
                "{}_{}",
                r.pick(&["prod", "pay", "crm", "bill"]),
                r.pick(&["clients", "accounts", "orders", "ledger"])
            );
            (
                v.clone(),
                EntityType::Db,
                format!("postgresql://app:pw12345@db-prod01.company.ru:5432/{v}\n"),
            )
        }
        "svc_user" => {
            let v = format!("svc_{}", r.pick(&["payment", "billing", "reports", "etl"]));
            let t = *r.pick(&[
                "user: {}\n",
                "login: {}\n",
                "username={}\n",
                "DB_USER: {}\n",
                "-u {}\n",
            ]);
            (v.clone(), EntityType::Svc, t.replace("{}", &v))
        }
        "email" => {
            let v = email(r);
            let t = *r.pick(&[
                "owner: {}\n",
                "Написал {} вчера.\n",
                "contact=<{}>\n",
                "\"email\": \"{}\"\n",
                "git config user.email {}\n",
            ]);
            (v.clone(), EntityType::Email, t.replace("{}", &v))
        }
        "phone" => {
            let v = phone(r);
            let t = *r.pick(&[
                "Телефон: {}\n",
                "phone={}\n",
                "позвони по номеру {} завтра\n",
                "\"tel\": \"{}\"\n",
            ]);
            (v.clone(), EntityType::Phone, t.replace("{}", &v))
        }
        "snils" => {
            let v = snils(r);
            (v.clone(), EntityType::Snils, format!("СНИЛС: {v}\n"))
        }
        "inn" => {
            let v = inn10(r);
            (
                v.clone(),
                EntityType::Inn,
                format!("ИНН {v}, КПП 770101001\n"),
            )
        }
        "card" => {
            let v = luhn_complete(r.pick(&["4", "51", "55", "37"]), 16, r);
            let sep = *r.pick(&["", " ", "-"]);
            let shown = if sep.is_empty() {
                v.clone()
            } else {
                format!(
                    "{}{sep}{}{sep}{}{sep}{}",
                    &v[0..4],
                    &v[4..8],
                    &v[8..12],
                    &v[12..16]
                )
            };
            let t = if sep.is_empty() {
                format!("карта {shown} срок 12/29\n")
            } else {
                format!("card: {shown}\n")
            };
            (shown, EntityType::Card, t)
        }
        "passport" => {
            let v = format!("{} {}", 4500 + r.below(99), 100000 + r.below(899999));
            (
                v.clone(),
                EntityType::Passport,
                format!("Паспорт: {v}, выдан ОВД\n"),
            )
        }
        _ => unreachable!("unknown label {label}"),
    };
    Case {
        ctx: LAST_CTX.with(|c| c.get()),
        text,
        value,
        ty,
        label,
    }
}

pub const LABELS: &[&str] = &[
    "password",
    "aws",
    "github",
    "gitlab",
    "slack",
    "openai",
    "anthropic",
    "gcp",
    "jwt",
    "pem",
    "uri_password",
    "host",
    "ip",
    "jdbc_host",
    "db_name",
    "svc_user",
    "email",
    "phone",
    "snils",
    "inn",
    "card",
    "passport",
];

pub struct Report {
    pub miss_ctx: BTreeMap<(&'static str, usize), usize>,
    pub per_label: BTreeMap<&'static str, (usize, usize)>,
    pub misses: BTreeMap<&'static str, Vec<String>>,
}

/// Does a detected entity of the right class cover the labelled value?
fn covered(ents: &[aegis_core::types::Entity], text: &str, value: &str, ty: EntityType) -> bool {
    let Some(at) = text.find(value) else {
        return false;
    };
    let (s, e) = (at, at + value.len());
    ents.iter().any(|x| {
        let same = x.ty == ty || (ty.class() == Class::Secret && x.ty.class() == Class::Secret);
        same && x.span.start <= s && x.span.end >= e
    })
}

pub fn run(n_per_label: usize, seed: u64) -> Report {
    let det = DetectConfig {
        internal_zones: zones(),
        ..Default::default()
    };
    let pipe = Pipeline::new(det, Dictionary::default());
    let mut rep = Report {
        miss_ctx: BTreeMap::new(),
        per_label: BTreeMap::new(),
        misses: BTreeMap::new(),
    };
    for (li, label) in LABELS.iter().enumerate() {
        let mut r = Rng::new(seed ^ ((li as u64 + 1) * 0x1234_5678_9ABC));
        for _ in 0..n_per_label {
            let c = gen(&mut r, label);
            let ents = pipe.scan(&c.text);
            let ok = covered(&ents, &c.text, &c.value, c.ty);
            let e = rep.per_label.entry(c.label).or_insert((0, 0));
            e.0 += 1;
            if ok {
                e.1 += 1;
            } else {
                *rep.miss_ctx.entry((c.label, c.ctx)).or_insert(0) += 1;
                let m = rep.misses.entry(c.label).or_default();
                if m.len() < 4 {
                    m.push(
                        c.text
                            .trim_end()
                            .replace('\n', "\\n")
                            .chars()
                            .take(110)
                            .collect(),
                    );
                }
            }
        }
    }
    rep
}

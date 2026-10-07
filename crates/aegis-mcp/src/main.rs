#![allow(clippy::print_stdout, clippy::print_stderr)]
//! `aegis-mcp`. REQ: MCP-01, MCP-05.

use aegis_mcp::audit::Audit;
use aegis_mcp::config::Config;
use clap::{Parser, Subcommand};
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "aegis-mcp", about = "Фильтр между клиентом MCP и сервером MCP")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Проверить конфигурацию и вывести, что она разрешает
    Check { config: String },
    /// Запустить сервер MCP как дочерний процесс и встать между ним и клиентом (stdio)
    Stdio {
        #[arg(long)]
        config: String,
        #[arg(long)]
        server: String,
        /// Команда сервера после `--`
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Принимать Streamable HTTP на /<сервер> и пересылать на url сервера
    Http {
        #[arg(long)]
        config: String,
        #[arg(long, default_value = "127.0.0.1:9100")]
        listen: String,
    },
    /// Фрагмент политики gateway для меток доверия и выхода наружу (MCP-05)
    PolicySnippet { config: String },
}

fn load(path: &str) -> Config {
    std::fs::read_to_string(path)
        .map_err(|e| format!("{path}: {e}"))
        .and_then(|t| Config::from_yaml(&t))
        .unwrap_or_else(|e| {
            eprintln!("aegis-mcp: {e}");
            std::process::exit(2)
        })
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Check { config } => {
            let cfg = load(&config);
            for s in cfg.servers.values() {
                println!(
                    "{}: инструменты {:?}; доверие {}; выход наружу {}; правил аргументов {}; SQL только чтение {}; убирает поля {:?}",
                    s.name,
                    s.allow,
                    if s.untrusted { "untrusted" } else { "trusted" },
                    if s.egress { "да" } else { "нет" },
                    s.args.len(),
                    s.sql.len(),
                    s.drop_fields
                );
            }
        }
        Cmd::PolicySnippet { config } => print!("{}", load(&config).policy_snippet()),
        Cmd::Stdio {
            config,
            server,
            command,
        } => {
            let cfg = Arc::new(load(&config));
            let audit = Audit::open(cfg.audit_path.as_deref()).unwrap_or_else(|e| {
                eprintln!("aegis-mcp: аудит: {e}");
                std::process::exit(2)
            });
            match aegis_mcp::stdio::run(cfg, &server, &command, audit).await {
                Ok(code) => std::process::exit(code),
                Err(e) => {
                    eprintln!("aegis-mcp: {e}");
                    std::process::exit(2)
                }
            }
        }
        Cmd::Http { config, listen } => {
            let cfg = Arc::new(load(&config));
            let audit = Audit::open(cfg.audit_path.as_deref()).unwrap_or_else(|e| {
                eprintln!("aegis-mcp: аудит: {e}");
                std::process::exit(2)
            });
            let l = tokio::net::TcpListener::bind(&listen)
                .await
                .unwrap_or_else(|e| {
                    eprintln!("aegis-mcp: {listen}: {e}");
                    std::process::exit(2)
                });
            eprintln!("aegis-mcp: слушает {listen}");
            let _ = axum::serve(l, aegis_mcp::http::app(cfg, audit)).await;
        }
    }
}

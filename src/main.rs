//! Igris Guardian entry point. Hand-rolled arg dispatch (3 subcommands, no clap).

use igris_guardian::config::Config;
use igris_guardian::{adapter_hook, adapter_scan, adapter_serve, stage2};
use std::path::PathBuf;

fn usage() -> ! {
    eprintln!(
        "igris — prompt-injection firewall\n\
         \n\
         USAGE:\n\
         \x20 igris scan [--config PATH] [TEXT]   scan stdin/arg, print JSON verdict\n\
         \x20 igris hook [--config PATH]          Claude Code hook adapter (stdin JSON)\n\
         \x20 igris serve [--config PATH]         filtering reverse proxy\n"
    );
    std::process::exit(64);
}

#[tokio::main]
async fn main() {
    // Self-protection: refuse to run with a tampered guard prompt.
    stage2::verify_prompt();

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }

    let cmd = args[0].as_str();
    let rest = &args[1..];
    let (config_path, positional) = parse_config_flag(rest);

    let cfg = match Config::load(config_path.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("igris: config error: {e}");
            std::process::exit(78);
        }
    };
    if !cfg.stage2.enabled {
        eprintln!("igris: stage-2 classifier disabled — running stage-1 (offline) only");
    }

    let code = match cmd {
        "scan" => adapter_scan::run(cfg, positional.into_iter().next()).await,
        "hook" => adapter_hook::run(cfg).await,
        "serve" => adapter_serve::run(cfg).await,
        "-h" | "--help" | "help" => usage(),
        _ => usage(),
    };
    std::process::exit(code);
}

/// Extract `--config PATH`, returning it plus any remaining positional args.
fn parse_config_flag(args: &[String]) -> (Option<PathBuf>, Vec<String>) {
    let mut config = None;
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                if i + 1 < args.len() {
                    config = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else {
                    i += 1;
                }
            }
            other => {
                positional.push(other.to_string());
                i += 1;
            }
        }
    }
    (config, positional)
}

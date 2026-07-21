//! Igris Guardian entry point. Hand-rolled arg dispatch (4 subcommands, no clap).

use igris_guardian::config::Config;
use igris_guardian::Trust;
use igris_guardian::{adapter_hook, adapter_scan, adapter_serve, console, stage2};
use std::path::PathBuf;

fn usage() -> ! {
    eprintln!(
        "igris — prompt-injection firewall\n\
         \n\
         USAGE:\n\
         \x20 igris scan [--config PATH] [--trust user] [TEXT]\n\
         \x20                                     scan stdin/arg, print JSON verdict\n\
         \x20 igris hook [--config PATH]          Claude Code hook adapter (stdin JSON)\n\
         \x20 igris serve [--config PATH]         filtering reverse proxy\n\
         \x20 igris console [--config PATH]       live audit-log dashboard (read-only)\n\
         \n\
         \x20 --trust user   text the operator typed themselves; countermanding\n\
         \x20                standing instructions warns instead of blocking.\n\
         \x20                Defaults to untrusted.\n"
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
    let (config_path, trust, positional) = parse_flags(rest);

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
        "scan" => adapter_scan::run(cfg, positional.into_iter().next(), trust).await,
        "hook" => adapter_hook::run(cfg).await,
        "serve" => adapter_serve::run(cfg).await,
        // Synchronous and blocking, which is fine: it is the only thing this
        // process is doing, and it owns the terminal until the user quits.
        "console" => console::run(cfg),
        "-h" | "--help" | "help" => usage(),
        _ => usage(),
    };
    std::process::exit(code);
}

/// Extract `--config PATH` and `--trust user|untrusted`, returning them plus any
/// remaining positional args. Trust defaults to untrusted: the safe answer for a
/// caller that has not thought about provenance.
fn parse_flags(args: &[String]) -> (Option<PathBuf>, Trust, Vec<String>) {
    let mut config = None;
    let mut trust = Trust::Untrusted;
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
            "--trust" => {
                if i + 1 < args.len() {
                    if args[i + 1] == "user" {
                        trust = Trust::User;
                    }
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
    (config, trust, positional)
}

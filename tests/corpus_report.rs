//! Corpus report: prints every failing case at once instead of aborting on the
//! first, and reports the measured precision/recall of stage 1.
//!
//! `cargo test --test corpus_report -- --nocapture`. Kept separate from
//! `corpus_test.rs` so the gate stays a hard pass/fail and this stays a
//! diagnostic. This is the number that replaces the design report's unsourced
//! ">99% detection rate" claim.

use igris_guardian::config::Config;
use igris_guardian::engine::Engine;
use igris_guardian::Action;
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct CorpusLine {
    text: String,
    note: Option<String>,
}

fn load(path: &str) -> Vec<CorpusLine> {
    let data = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    data.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("parse {path} line {l:?}: {e}")))
        .collect()
}

fn engine() -> Engine {
    let mut cfg = Config::default();
    cfg.stage2.enabled = false;
    Engine::new(cfg)
}

const RESET: &str = "\x1b[0m";
const RED: &str = "\x1b[38;2;255;82;82m";
const ORANGE: &str = "\x1b[38;2;255;173;64m";
const GREEN: &str = "\x1b[38;2;93;214;143m";
const DIM: &str = "\x1b[38;2;154;164;178m";
const BOLD: &str = "\x1b[1m";

fn markdown_to_terminal(text: &str) -> String {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            let line = line.trim_start_matches('#').trim_start();
            let line = line.replace("**", "").replace('`', "");
            Some(match line.strip_prefix("- ") {
                Some(item) => format!("* {item}"),
                None => line,
            })
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn print_panel(title: &str, color: &str, entries: &[(String, Option<String>, u8, Vec<String>)]) {
    println!(
        "\n{color}+====================[ {title}: {} ]====================+{RESET}",
        entries.len()
    );
    if entries.is_empty() {
        println!("{color}|{RESET} {GREEN}CLEAR{RESET} {DIM}Nothing to review.{RESET}");
        return;
    }

    for (index, (text, note, score, reasons)) in entries.iter().enumerate() {
        println!(
            "{color}|--[{}/{}]-------------------------------------------------{RESET}",
            index + 1,
            entries.len()
        );
        println!(
            "{color}|{RESET} {BOLD}RISK {score:>3}/100{RESET}  {DIM}{}\n{RESET}",
            reasons.join(", ")
        );
        for line in markdown_to_terminal(text).lines() {
            println!("{color}|{RESET} {line}");
        }
        if let Some(note) = note {
            println!("{color}|{RESET} {DIM}source: {note}{RESET}");
        }
    }
    println!("{color}+--------------------------------------------------------------+{RESET}");
}

#[test]
fn report() {
    let eng = engine();
    println!(
        "\n{RED}  ___ ___ ___ ___ ___{RESET}\n{RED} |_ _| __| _ \\_ _/ __|{RESET}\n{RED}  | || _||   /| |\\__ \\{RESET}\n{RED} |___|___|_|_\\___|___/{RESET}\n{DIM}             GUARDIAN CORPUS REPORT{RESET}"
    );
    let mut malicious_missed = Vec::new();
    let mut malicious_total = 0usize;

    for file in [
        "tests/corpus/injections.jsonl",
        "tests/corpus/unicode.jsonl",
        "tests/corpus/encoded.jsonl",
    ] {
        for c in load(file) {
            malicious_total += 1;
            let v = eng.scan_stage1(&c.text);
            if v.action != Action::Block {
                malicious_missed.push((file, c.text, c.note, v.score, v.reasons));
            }
        }
    }

    let mut benign = load("tests/corpus/benign.jsonl");
    benign.extend(load("tests/corpus/benign_hard.jsonl"));
    let mut benign_blocked = Vec::new();
    for c in &benign {
        let v = eng.scan_stage1(&c.text);
        if v.action == Action::Block {
            benign_blocked.push((c.text.clone(), c.note.clone(), v.score, v.reasons));
        }
    }

    let missed_count = malicious_missed.len();
    let missed = malicious_missed
        .into_iter()
        .map(|(file, text, note, score, reasons)| {
            (text, note.map(|n| format!("{file} - {n}")), score, reasons)
        })
        .collect::<Vec<_>>();
    print_panel("MISSED MALICIOUS", RED, &missed);
    print_panel("BLOCKED BENIGN", ORANGE, &benign_blocked);

    let caught = malicious_total - missed_count;
    let recall = 100.0 * caught as f64 / malicious_total as f64;
    let fp_rate = 100.0 * benign_blocked.len() as f64 / benign.len() as f64;
    println!(
        "\n{GREEN}+====================[ STAGE 1 - OFFLINE ]====================+{RESET}\n{GREEN}|{RESET} Recall       {BOLD}{recall:>5.1}%{RESET}  {DIM}({caught}/{malicious_total} malicious blocked){RESET}\n{GREEN}|{RESET} False positive {BOLD}{fp_rate:>4.1}%{RESET}  {DIM}({}/{} benign blocked){RESET}\n{GREEN}+---------------------------------------------------------------+{RESET}\n",
        benign_blocked.len(),
        benign.len()
    );
}

#[test]
fn markdown_is_rendered_as_terminal_text() {
    assert_eq!(
        markdown_to_terminal("# Threat Model\n\n## Assets\n- **System** `prompt`"),
        "Threat Model\nAssets\n* System prompt"
    );
}

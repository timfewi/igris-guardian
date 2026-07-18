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

#[test]
fn report() {
    let eng = engine();
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

    println!("\n=== MISSED MALICIOUS ({}) ===", malicious_missed.len());
    for (f, t, n, s, r) in &malicious_missed {
        println!("  [{f}] score={s} {r:?}\n    text: {t}\n    note: {n:?}");
    }
    println!("\n=== BLOCKED BENIGN ({}) ===", benign_blocked.len());
    for (t, n, s, r) in &benign_blocked {
        println!("  score={s} {r:?}\n    text: {t}\n    note: {n:?}");
    }

    let caught = malicious_total - malicious_missed.len();
    let recall = 100.0 * caught as f64 / malicious_total as f64;
    let fp_rate = 100.0 * benign_blocked.len() as f64 / benign.len() as f64;
    println!(
        "\n=== STAGE 1 (offline, no LLM) ===\n  recall:  {recall:.1}% ({caught}/{malicious_total} malicious blocked)\n  FP rate: {fp_rate:.1}% ({}/{} benign blocked)\n",
        benign_blocked.len(),
        benign.len()
    );
}

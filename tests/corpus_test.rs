//! Stage-1 corpus gate. PHASE-1A.
//!
//! Loads tests/corpus/{injections,benign,unicode,encoded}.jsonl through
//! `Engine::scan_stage1` (stage 2 disabled — deterministic, offline) and
//! asserts the acceptance gate: all injections/unicode/encoded cases block,
//! all benign cases pass.

use igris_guardian::config::Config;
use igris_guardian::engine::Engine;
use igris_guardian::Action;
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct CorpusLine {
    text: String,
    #[allow(dead_code)]
    note: Option<String>,
}

fn load_corpus(path: &str) -> Vec<CorpusLine> {
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
fn injections_block_with_score_at_least_80() {
    let eng = engine();
    let corpus = load_corpus("tests/corpus/injections.jsonl");
    assert!(
        corpus.len() >= 100,
        "need >=100 injection cases, got {}",
        corpus.len()
    );
    for c in &corpus {
        let v = eng.scan_stage1(&c.text);
        assert!(
            v.action == Action::Block && v.score >= 80,
            "expected block score>=80 for {:?} (note: {:?}) — got score={} action={:?} reasons={:?}",
            c.text,
            c.note,
            v.score,
            v.action,
            v.reasons
        );
    }
}

#[test]
fn benign_passes() {
    let eng = engine();
    let corpus = load_corpus("tests/corpus/benign.jsonl");
    assert!(
        corpus.len() >= 50,
        "need >=50 benign cases, got {}",
        corpus.len()
    );
    for c in &corpus {
        let v = eng.scan_stage1(&c.text);
        assert!(
            v.action == Action::Pass,
            "expected pass for {:?} (note: {:?}) — got score={} action={:?} reasons={:?}",
            c.text,
            c.note,
            v.score,
            v.action,
            v.reasons
        );
    }
}

#[test]
fn unicode_smuggling_blocks() {
    let eng = engine();
    let corpus = load_corpus("tests/corpus/unicode.jsonl");
    assert!(!corpus.is_empty(), "unicode corpus must not be empty");
    for c in &corpus {
        let v = eng.scan_stage1(&c.text);
        assert!(
            v.action == Action::Block,
            "expected block for {:?} (note: {:?}) — got score={} reasons={:?}",
            c.text,
            c.note,
            v.score,
            v.reasons
        );
    }
}

#[test]
fn encoded_payloads_block() {
    let eng = engine();
    let corpus = load_corpus("tests/corpus/encoded.jsonl");
    assert!(!corpus.is_empty(), "encoded corpus must not be empty");
    for c in &corpus {
        let v = eng.scan_stage1(&c.text);
        assert!(
            v.action == Action::Block,
            "expected block for {:?} (note: {:?}) — got score={} reasons={:?}",
            c.text,
            c.note,
            v.score,
            v.reasons
        );
    }
}

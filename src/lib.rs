//! Igris Guardian — a prompt-injection firewall.
//!
//! Constitution (enforced by *code*, not prompt):
//! - It only ever classifies untrusted text and returns a [`Verdict`].
//! - It never rewrites, sanitizes, answers, or acts. Pass-or-block only.
//! - It has no tools, no shell, and writes nothing but an append-only audit log.
//!
//! There is deliberately no code path for anything else.

pub mod adapter_hook;
pub mod adapter_scan;
pub mod adapter_serve;
pub mod audit;
pub mod config;
pub mod engine;
pub mod normalize;
pub mod rules;
pub mod stage2;

use serde::Serialize;

/// What the Guardian decided to do with a piece of text. Never "rewrite".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Content is clean; forward unchanged.
    Pass,
    /// Suspicious or scanned in a degraded mode; forward but flag.
    Warn,
    /// Injection/jailbreak/policy violation; do not forward.
    Block,
}

/// The single output type of the entire system.
#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    /// True iff `action != Block`.
    pub safe: bool,
    /// 0–100 aggregate risk score.
    pub score: u8,
    pub action: Action,
    /// Rule ids and/or the stage-2 reason. Never contains scanned content verbatim.
    pub reasons: Vec<String>,
}

impl Verdict {
    pub fn new(score: u8, action: Action, reasons: Vec<String>) -> Self {
        Verdict {
            safe: action != Action::Block,
            score,
            action,
            reasons,
        }
    }

    /// A clean pass with no findings.
    pub fn pass() -> Self {
        Verdict::new(0, Action::Pass, Vec::new())
    }
}

/// How an adapter wants the engine to behave when stage 2 cannot render a verdict.
///
/// Set by the adapter, never by config — this is a safety property, not a knob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailMode {
    /// Unreachable/ambiguous guard → Block. Used by `scan` and `serve`.
    Close,
    /// Unreachable guard → keep the deterministic stage-1 verdict + Warn.
    /// Used by `hook` so a network blip never wedges the editor.
    DegradeStage1,
}

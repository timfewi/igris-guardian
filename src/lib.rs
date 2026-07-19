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
pub mod console;
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

/// How much the evidence behind a [`Verdict`] can be trusted.
///
/// Exposed in the JSON output so a caller can choose its own posture: block on
/// `Ambiguous` if it is a hardened proxy, annotate-only if it is an editor
/// integration where a false positive costs more than a miss.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// At least one detection fired that benign text essentially never produces.
    Certain,
    /// Only corroborating signals fired — patterns that legitimately occur in
    /// documentation, source code, and ordinary speech.
    Ambiguous,
}

/// The single output type of the entire system.
#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    /// True iff `action != Block`.
    pub safe: bool,
    /// 0–100 aggregate risk score.
    pub score: u8,
    pub action: Action,
    /// Strength of the evidence, independent of `score`.
    pub confidence: Confidence,
    /// Rule ids and/or the stage-2 reason. Never contains scanned content verbatim.
    pub reasons: Vec<String>,
}

impl Verdict {
    pub fn new(score: u8, action: Action, confidence: Confidence, reasons: Vec<String>) -> Self {
        Verdict {
            safe: action != Action::Block,
            score,
            action,
            confidence,
            reasons,
        }
    }

    /// A clean pass with no findings.
    pub fn pass() -> Self {
        Verdict::new(0, Action::Pass, Confidence::Ambiguous, Vec::new())
    }
}

/// Where a piece of text came from, which decides whether overriding the agent
/// is an attack or a prerogative.
///
/// Prompt injection is a confused-deputy problem: it matters because *untrusted*
/// content reaches a channel the operator's instructions occupy. An operator
/// typing "ignore the previous instructions, start over" to their own agent is
/// not attacking anyone — they could edit the system prompt directly. Scanning
/// their keystrokes with the same severity as a fetched web page produces
/// nothing but false positives, and a firewall that fights its own operator gets
/// switched off.
///
/// Set by the adapter from provenance it already knows. There is deliberately no
/// config key for it: it is a property of the channel, not a preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// Authored by the operator in their own session.
    User,
    /// Arrived from a tool result, a fetched page, a file, an MCP server, or an
    /// upstream model. The actual prompt-injection threat surface.
    Untrusted,
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

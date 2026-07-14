//! Orchestration: stage 1 (offline) → escalate → stage 2 → verdict, plus fail
//! modes and audit. PHASE-1A owns the stage-1 half; PHASE-3 wires escalation and
//! fail modes end to end.

use crate::audit::Audit;
use crate::config::Config;
use crate::normalize;
use crate::rules::RuleSet;
use crate::stage2::{self, Classification};
use crate::{Action, FailMode, Verdict};

pub struct Engine {
    rules: RuleSet,
    cfg: Config,
    audit: Audit,
}

impl Engine {
    pub fn new(cfg: Config) -> Engine {
        let audit = Audit::open(&cfg.audit_path());
        Engine {
            rules: RuleSet::load(),
            cfg,
            audit,
        }
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Stage-1-only deterministic scan (no network). Used directly by corpus tests.
    pub fn scan_stage1(&self, text: &str) -> Verdict {
        let capped = cap(text, self.cfg.max_scan_bytes);
        let (norm, findings) = normalize::analyze(capped);

        // Union of every fired rule (across the normalized text and its decoded
        // variants) plus the unicode findings, deduped by id keeping the max
        // weight. One aggregate so findings and rule hits stack together, and so a
        // keyword recovered only in a decoded/stripped variant counts.
        let mut weights: std::collections::BTreeMap<String, u8> = std::collections::BTreeMap::new();
        let mut variants = vec![norm.clone()];
        variants.extend(normalize::decode_variants(&norm));
        for v in &variants {
            for (id, w) in self.rules.hits(v) {
                let e = weights.entry(id.to_string()).or_insert(0);
                *e = (*e).max(w);
            }
        }
        for f in &findings {
            let e = weights.entry(f.id.to_string()).or_insert(0);
            *e = (*e).max(f.weight);
        }

        let (score, reasons) = crate::rules::aggregate(&weights);
        let action = if score >= self.cfg.block_threshold {
            Action::Block
        } else {
            Action::Pass
        };
        Verdict::new(score, action, reasons)
    }

    /// Full scan including stage-2 escalation. `source` labels the audit line.
    pub async fn scan(&self, text: &str, source: &str, fail_mode: FailMode) -> Verdict {
        let mut v = self.scan_stage1(text);

        let escalate = v.action != Action::Block
            && v.score >= self.cfg.escalate_threshold
            && self.cfg.stage2.enabled;

        if escalate {
            v = self.apply_stage2(text, v, fail_mode).await;
        }

        if v.action != Action::Pass {
            self.audit
                .record(source, text, &v, self.cfg.stage2.enabled && escalate);
        }
        v
    }

    async fn apply_stage2(&self, text: &str, stage1: Verdict, fail_mode: FailMode) -> Verdict {
        match stage2::classify(&self.cfg.stage2, text).await {
            Classification::Injection
            | Classification::Jailbreak
            | Classification::PolicyViolation => {
                let mut reasons = stage1.reasons;
                reasons.push("stage2-injection".to_string());
                Verdict::new(stage1.score.max(90), Action::Block, reasons)
            }
            Classification::Suspicious => {
                let mut reasons = stage1.reasons;
                reasons.push("stage2-suspicious".to_string());
                Verdict::new(65, Action::Warn, reasons)
            }
            Classification::Safe => Verdict::new(stage1.score, Action::Pass, stage1.reasons),
            Classification::Failed => match fail_mode {
                FailMode::Close => {
                    let mut reasons = stage1.reasons;
                    reasons.push("stage2-unavailable-fail-close".to_string());
                    Verdict::new(stage1.score.max(90), Action::Block, reasons)
                }
                FailMode::DegradeStage1 => {
                    let mut reasons = stage1.reasons;
                    reasons.push("stage2-unavailable-degraded".to_string());
                    let action = if stage1.action == Action::Block {
                        Action::Block
                    } else {
                        Action::Warn
                    };
                    Verdict::new(stage1.score, action, reasons)
                }
            },
        }
    }
}

/// Truncate to a byte cap on a char boundary.
pub fn cap(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

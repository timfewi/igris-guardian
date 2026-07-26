//! Orchestration: stage 1 (offline) → escalate → stage 2 → verdict, plus fail
//! modes and audit. PHASE-1A owns the stage-1 half; PHASE-3 wires escalation and
//! fail modes end to end.

use crate::audit::Audit;
use crate::config::Config;
use crate::normalize;
use crate::rules::RuleSet;
use crate::stage2::{self, Classification};
use crate::{Action, Confidence, FailMode, Trust, Verdict};

pub struct Engine {
    rules: RuleSet,
    cfg: Config,
    audit: Audit,
}

impl Engine {
    pub fn new(cfg: Config) -> Engine {
        let audit = Audit::open(&cfg.audit_path(), cfg.audit_excerpt);
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
    ///
    /// Blocks only on [`Confidence::Certain`] evidence. Text that scores past the
    /// threshold on corroborating signals alone comes back as `Pass` with
    /// `Confidence::Ambiguous` and a score at/above `escalate_threshold`, which is
    /// [`Engine::scan`]'s cue to ask stage 2 rather than to convict on its own.
    pub fn scan_stage1(&self, text: &str) -> Verdict {
        let capped = cap(text, self.cfg.max_scan_bytes);
        let (norm, findings) = normalize::analyze(capped);

        // Union of every fired rule (across the normalized text and its decoded
        // variants) plus the unicode findings, deduped by id keeping the strongest
        // evidence. One aggregate so findings and rule hits stack together, and so a
        // keyword recovered only in a decoded/stripped variant counts.
        let mut hits: std::collections::BTreeMap<String, crate::rules::Hit> = Default::default();
        let mut variants = vec![norm.clone()];
        variants.extend(normalize::decode_variants(&norm));
        for v in &variants {
            for h in self.rules.hits(v) {
                crate::rules::merge_hit(&mut hits, h);
            }
            // Per variant, not just the original: leetspeak folds "p@ssw0rd"
            // back to a noun the feeler recognises.
            for h in crate::rules::feeler_hits(v, self.cfg.escalate_threshold) {
                crate::rules::merge_hit(&mut hits, h);
            }
        }
        for f in &findings {
            crate::rules::merge_hit(
                &mut hits,
                crate::rules::Hit {
                    id: f.id,
                    weight: f.weight,
                    tier: f.tier,
                    quoted: false,
                },
            );
        }

        let (score, reasons, decisive) = crate::rules::aggregate(&hits);
        let confidence = if decisive {
            Confidence::Certain
        } else {
            Confidence::Ambiguous
        };
        // Ambiguous evidence never blocks here, however high it scores — that is
        // the whole point of the tier. It leaves as a Pass carrying its score, and
        // `scan` routes it to stage 2.
        let action = if score >= self.cfg.block_threshold && decisive {
            Action::Block
        } else {
            Action::Pass
        };
        Verdict::new(score, action, confidence, reasons)
    }

    /// Full scan including stage-2 escalation. `source` labels the audit line.
    ///
    /// Most callers want [`Trust::Untrusted`]; see [`Engine::scan_trusted`].
    pub async fn scan(&self, text: &str, source: &str, fail_mode: FailMode) -> Verdict {
        self.scan_trusted(text, source, Trust::Untrusted, fail_mode)
            .await
    }

    /// As [`Engine::scan`], but told where the text came from.
    ///
    /// [`Trust::User`] text is not blocked for merely countermanding standing
    /// instructions — the operator owns the system prompt and could edit it
    /// directly, so doing it by sentence is a prerogative, not an attack. It still
    /// blocks on:
    ///
    /// - unicode smuggling, because invisible control characters are not something
    ///   a person types; their presence means the text was pasted from somewhere
    ///   the operator does not control, which puts it back on the untrusted side;
    /// - jailbreak, forged-authority and action-demand evidence, which is about
    ///   what the model is induced to do and stays meaningful whoever typed it.
    pub async fn scan_trusted(
        &self,
        text: &str,
        source: &str,
        trust: Trust,
        fail_mode: FailMode,
    ) -> Verdict {
        let mut v = self.scan_stage1(text);

        // The downgrade is final, not provisional: it says this class of evidence
        // does not apply to this channel at all. Letting it escalate would put the
        // verdict straight back in front of stage 2, and a fail-closed adapter
        // would then reinstate the block the operator was just excused from.
        if trust == Trust::User
            && v.action == Action::Block
            && !has_smuggling(&v)
            && crate::rules::only_operator_prerogative(&v.reasons)
        {
            v = Verdict::new(
                v.score,
                Action::Warn,
                v.confidence,
                with(v.reasons, "operator-authored-downgrade"),
            );
            self.audit.record(source, text, &v, false);
            return v;
        }

        // Stage 1 convicts only on certain evidence, so anything still passing at
        // or above the escalate threshold wants a second opinion. The case that
        // matters is ambiguous evidence scoring past `block_threshold`: it used to
        // hard-block with no appeal, and is now adjudicated by stage 2 instead.
        let escalate = v.action != Action::Block
            && v.score >= self.cfg.escalate_threshold
            && self.cfg.stage2.enabled;

        if escalate {
            v = self.apply_stage2(text, v, fail_mode).await;
        } else if v.action != Action::Block && v.score >= self.cfg.block_threshold {
            // Block-worthy score on ambiguous evidence with stage 2 switched off:
            // nothing can adjudicate it, so the adapter's posture decides. This
            // must never fall through as a silent Pass.
            v = unadjudicated(v, fail_mode);
        }

        if v.action != Action::Pass {
            self.audit
                .record(source, text, &v, self.cfg.stage2.enabled && escalate);
        }
        v
    }

    async fn apply_stage2(&self, text: &str, stage1: Verdict, fail_mode: FailMode) -> Verdict {
        match stage2::classify(&self.cfg.stage2, text).await {
            // Stage 2 adjudicated it: the verdict is now certain regardless of how
            // ambiguous stage 1's evidence was on its own.
            Classification::Injection
            | Classification::Jailbreak
            | Classification::PolicyViolation => Verdict::new(
                stage1.score.max(90),
                Action::Block,
                Confidence::Certain,
                with(stage1.reasons, "stage2-injection"),
            ),
            Classification::Suspicious => Verdict::new(
                65,
                Action::Warn,
                Confidence::Ambiguous,
                with(stage1.reasons, "stage2-suspicious"),
            ),
            // Stage 2 cleared it. Stage-1 evidence was ambiguous by construction
            // (certain evidence never reaches here), so this is a real acquittal.
            Classification::Safe => Verdict::new(
                stage1.score,
                Action::Pass,
                Confidence::Ambiguous,
                with(stage1.reasons, "stage2-safe"),
            ),
            Classification::Failed => unadjudicated(stage1, fail_mode),
        }
    }
}

/// Resolve a verdict that wanted a second opinion and could not get one, by the
/// adapter's declared posture. `Close` (scan, serve) treats an unavailable guard
/// as hostile; `DegradeStage1` (hook) keeps the editor usable and only warns.
fn unadjudicated(v: Verdict, fail_mode: FailMode) -> Verdict {
    match fail_mode {
        FailMode::Close => Verdict::new(
            v.score.max(90),
            Action::Block,
            v.confidence,
            with(v.reasons, "unadjudicated-fail-close"),
        ),
        FailMode::DegradeStage1 => Verdict::new(
            v.score,
            // Certain stage-1 evidence still blocks; only the ambiguous case degrades.
            if v.action == Action::Block {
                Action::Block
            } else {
                Action::Warn
            },
            v.confidence,
            with(v.reasons, "unadjudicated-degraded"),
        ),
    }
}

fn with(mut reasons: Vec<String>, reason: &str) -> Vec<String> {
    reasons.push(reason.to_string());
    reasons
}

/// Whether a verdict rests on unicode smuggling — invisible characters that a
/// person does not type, so their presence survives the operator-authored
/// downgrade.
fn has_smuggling(v: &Verdict) -> bool {
    v.reasons
        .iter()
        .any(|r| matches!(r.as_str(), "zero-width" | "bidi-override" | "tag-block"))
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

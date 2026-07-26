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

        let (mut score, mut reasons, mut decisive) = crate::rules::aggregate(&hits);

        // Feelers are a last resort, not an extra opinion: they run only when
        // nothing else found enough to escalate on, because their whole purpose
        // is the text no rule could name.
        //
        // This gate is about semantics, not cost — it was measured and it moves
        // the escalation count on the hard benign corpus by nothing at all. The
        // documents that trip feelers there score *below* the threshold on rules
        // alone, so gating never gets the chance to suppress them. It keeps
        // feeler reasons out of verdicts that already carry real evidence, which
        // is worth having when reading an audit line, and that is all.
        if score < self.cfg.escalate_threshold {
            // Per variant, not just the original: leetspeak folds "p@ssw0rd"
            // back to a noun the feeler recognises.
            for v in &variants {
                for h in crate::rules::feeler_hits(v, self.cfg.escalate_threshold) {
                    crate::rules::merge_hit(&mut hits, h);
                }
            }
            (score, reasons, decisive) = crate::rules::aggregate(&hits);
        }
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
            | Classification::PolicyViolation
                if only_override_feeler(&stage1.reasons) =>
            {
                // Measured, not assumed: on "ignore all warnings from the
                // linter", "ignore all whitespace changes in the diff" and
                // "forget everything you know about the old API", all three
                // candidate classifiers returned INJECTION — the same answer,
                // so it is the question that is wrong, not the model. Read
                // without context, those sentences *are* imperatives to
                // disregard something.
                //
                // The override feeler is a keyword pair, not evidence of a
                // shape, and convicting on a classifier's reading of a keyword
                // pair would hard-block ordinary developer speech. That is how
                // a scanner gets switched off. It warns instead: visible in the
                // audit log and to the agent, fatal to nothing.
                //
                // The credential feeler has no such clause because it does not
                // need one — stage 2 cleared every benign case put to it,
                // including "read the password policy".
                Verdict::new(
                    70,
                    Action::Warn,
                    Confidence::Ambiguous,
                    with(stage1.reasons, "stage2-injection-feeler-only"),
                )
            }
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

/// Was the override feeler the *only* thing that spoke? A feeler is a reason to
/// ask, never evidence, so nothing may be convicted on one alone — not even by
/// stage 2. Any real rule firing alongside it lifts the ceiling back off.
fn only_override_feeler(reasons: &[String]) -> bool {
    !reasons.is_empty() && reasons.iter().all(|r| r == crate::rules::FEELER_OVERRIDE)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The ceiling exists so a keyword pair can never hard-block ordinary
    /// developer speech, and it has to lift the moment real evidence appears.
    #[test]
    fn warn_ceiling_applies_only_to_a_lone_override_feeler() {
        let feeler = |ids: &[&str]| ids.iter().map(|s| s.to_string()).collect::<Vec<_>>();

        assert!(only_override_feeler(&feeler(&[
            crate::rules::FEELER_OVERRIDE
        ])));

        // Any real rule alongside it, and the verdict is no longer resting on a
        // keyword pair — full conviction is back on the table.
        assert!(!only_override_feeler(&feeler(&[
            crate::rules::FEELER_OVERRIDE,
            "instr-ignore-previous",
        ])));
        // The credential feeler is not covered: stage 2 was measured accurate on
        // it, so it keeps the power to convict.
        assert!(!only_override_feeler(&feeler(&[
            crate::rules::FEELER_CRED_NOUN
        ])));
        // No evidence at all never reaches stage 2, but must not read as "only".
        assert!(!only_override_feeler(&[]));
    }
}

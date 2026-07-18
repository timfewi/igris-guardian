//! Stage-1 static ruleset (deterministic, offline). PHASE-1A fills this in.
//!
//! Contract: `RuleSet::load()` builds the compiled ruleset once; `score` returns
//! the aggregate stage-1 score and the ids of every rule that fired for `text`
//! (already NFKC-normalized by the caller).
//!
//! Categories port report section 3.1 (instruction-override, role-theft,
//! jailbreak-names, tool/code-injection, encoding-hints) plus the exact 14
//! `INJECTION_PATTERNS` + 4 `SUMMARISATION_PATTERNS` + 4 `MARKDOWN_LINK_PATTERNS`
//! from `gsd-read-injection-scanner.js`, ported 1:1 except where the JS used a
//! regex feature (negative lookahead) the `regex` crate does not support — those
//! two cases are re-expressed as capture + post-check below.

use regex::Regex;
use std::sync::OnceLock;

/// How much a fired rule is worth as *evidence*, independent of its weight.
///
/// This is the fix for the scanner's original failure mode: a document that
/// *describes* prompt injection (this repo's own source, an OWASP page, a CTF
/// writeup) contains the same phrases as a document that *performs* it. Weight
/// alone cannot tell them apart, so a high-weight regex hard-blocked on prose.
///
/// Tier separates "this phrase is present" from "this is decisively an attack".
/// Only [`Tier::Certain`] evidence may block on its own; [`Tier::Ambiguous`]
/// evidence escalates to the stage-2 classifier instead (see [`crate::engine`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Effectively never present in benign text. Safe to block on alone.
    Certain,
    /// Legitimately appears in technical writing, source code, and normal
    /// speech. Never blocks alone — it escalates or warns.
    Ambiguous,
}

/// A single compiled detection rule.
pub struct Rule {
    pub id: &'static str,
    pub weight: u8,
}

struct CompiledRule {
    id: &'static str,
    weight: u8,
    tier: Tier,
    re: Regex,
}

pub struct RuleSet {
    _private: (),
}

static RULES: OnceLock<Vec<CompiledRule>> = OnceLock::new();

fn rules() -> &'static Vec<CompiledRule> {
    RULES.get_or_init(build_rules)
}

fn rule(id: &'static str, weight: u8, tier: Tier, pattern: &str) -> CompiledRule {
    CompiledRule {
        id,
        weight,
        tier,
        re: Regex::new(pattern).unwrap_or_else(|e| panic!("bad regex for {id}: {e}")),
    }
}

/// Blocks on its own. Reserve for patterns with no benign reading.
fn certain(id: &'static str, weight: u8, pattern: &str) -> CompiledRule {
    rule(id, weight, Tier::Certain, pattern)
}

/// Never blocks on its own — escalates to stage 2 or warns.
fn ambiguous(id: &'static str, weight: u8, pattern: &str) -> CompiledRule {
    rule(id, weight, Tier::Ambiguous, pattern)
}

fn build_rules() -> Vec<CompiledRule> {
    vec![
        // --- exact INJECTION_PATTERNS (14), from gsd-read-injection-scanner.js ---
        // The canonical override payloads. Outside a quoting context (see
        // `definition_context`) these read as imperatives aimed at the agent.
        certain(
            "instr-ignore-previous",
            85,
            r"(?i)ignore\s+(all\s+)?previous\s+instructions",
        ),
        certain(
            "instr-ignore-above",
            85,
            r"(?i)ignore\s+(all\s+)?above\s+instructions",
        ),
        certain(
            "instr-disregard-previous",
            85,
            r"(?i)disregard\s+(all\s+)?previous",
        ),
        certain(
            "instr-forget-instructions",
            85,
            r"(?i)forget\s+(all\s+)?(your\s+)?instructions",
        ),
        certain(
            "instr-override-system",
            85,
            r"(?i)override\s+(system|previous)\s+(prompt|instructions)",
        ),
        certain(
            "instr-you-are-now",
            85,
            r"(?i)you\s+are\s+now\s+(?:a|an|the)\s+",
        ),
        // "act as a/an/the <word>" excluding plan/phase/wave — handled below (no lookahead in `regex`).
        certain(
            "instr-pretend",
            85,
            r"(?i)pretend\s+(?:you(?:'re| are)\s+|to\s+be\s+)",
        ),
        certain(
            "instr-from-now-on",
            85,
            r"(?i)from\s+now\s+on,?\s+you\s+(?:are|will|should|must)",
        ),
        certain(
            "instr-reveal-prompt",
            85,
            r"(?i)(?:print|output|reveal|show|display|repeat)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions)",
        ),
        certain(
            "instr-fake-role-tags",
            85,
            r"(?i)</?(?:system|assistant|human)>",
        ),
        // `[SYSTEM]` is ubiquitous in ordinary log output ("[SYSTEM] service started"),
        // so it cannot block alone — unlike the llama-template tags below, which are
        // vanishingly rare outside a chat template or an attack.
        ambiguous("instr-system-bracket", 60, r"(?i)\[SYSTEM\]"),
        certain("instr-inst-bracket", 85, r"(?i)\[INST\]"),
        certain("instr-sys-bracket", 85, r"(?i)<<\s*SYS\s*>>"),
        // --- report section 3.1: system-prompt-override extras not in the 14 ---
        // The single worst precision offender in the original ruleset: at weight 75
        // this fired on any prose pairing "override"/"ignore" with
        // "system"/"prompt"/"rules" within 50 chars — i.e. on most documentation
        // about prompt injection, including this repo's own. Demoted to a corroborating
        // signal: it can push toward escalation, never block by itself.
        ambiguous(
            "instr-override-generic",
            45,
            r"(?i)(ignore|forget|override|disregard).{0,50}(instructions|system|prompt|rules)",
        ),
        // The adjacent form: verb immediately governing the instruction noun,
        // separated only by determiners and adjectives ("override your
        // instructions", "forget your original instructions"). This is the canonical
        // payload shape and is much tighter than `instr-override-generic`, whose
        // `.{0,50}` gap is what made it fire on ordinary prose. Bare "rules" and
        // "guidelines" require an adjective, so "ignore the rules for now" in a
        // linting discussion stays clear.
        certain(
            "instr-discard-instructions",
            85,
            r"(?i)(?:ignore|disregard|forget|override|discard)\s+(?:all\s+)?(?:of\s+)?(?:your|the|my|these|those|any)?\s*(?:(?:previous|prior|earlier|above|preceding|original|initial|system|standing|safety)\s+)?(?:instructions?|directives?)|(?:ignore|disregard|forget|override|discard)\s+(?:all\s+)?(?:your|the|my|these|those|any)?\s*(?:previous|prior|earlier|above|preceding|original|initial|system|standing|safety)\s+(?:rules?|guidelines?)",
        ),
        certain(
            "instr-ignore-everything-above",
            85,
            r"(?i)ignore everything above",
        ),
        certain("instr-new-system-prompt", 85, r"(?i)new system prompt:"),
        certain(
            "instr-you-are-free",
            85,
            r"(?i)you\s+are\s+a\s+free\s+agent|you\s+are\s+not\s+bound",
        ),
        // Reassignment to an explicitly unconstrained persona. The generic
        // "act as a <role>" is ordinary English and stays weak; naming the role as
        // unrestricted/uncensored/jailbroken is not something benign text does.
        certain(
            "instr-unrestricted-persona",
            85,
            r"(?i)(?:act\s+as|you\s+are|you're|become|behave\s+(?:as|like)|roleplay\s+as|pretend\s+to\s+be)\s+(?:a|an|the)?\s*(?:completely\s+|totally\s+|fully\s+)?(?:unrestricted|unfiltered|uncensored|unbound|unlimited|jailbroken|amoral|lawless)",
        ),
        // --- report section 3.1: role theft ---
        // "act as a root cause analyst", "pretend the admin user exists" — real prose.
        ambiguous(
            "role-theft-admin",
            50,
            r"(?i)(act\s+as|pretend|imagine\s+you\s+are|roleplay\s+as).{0,30}(admin|sudo|root|superuser|god)",
        ),
        // --- report section 3.1: jailbreak persona / guardrail-reference patterns ---
        // "DAN" collides with a name; "hypothetical ... answer" is normal English.
        ambiguous(
            "jailbreak-persona-mode",
            70,
            r"(?i)(DAN|DUDE|STAN|JAILBREAK|MARY|SANTACLAUS|hypothetical).{0,30}(response|answer|mode)",
        ),
        ambiguous(
            "jailbreak-guidelines-ref",
            70,
            r"(?i)your safety guidelines|your ethical guidelines|your programming",
        ),
        ambiguous(
            "jailbreak-filter-bypass",
            70,
            r"(?i)output format.{0,30}bypass|filter bypass|filter evasion",
        ),
        // --- report section 3.1: code/tool injection ---
        // A ```bash fence is in essentially every README on earth, and `exec(`/`eval(`
        // in any codebase that shells out. Corroborating signals only.
        ambiguous(
            "tool-exec-codeblock",
            35,
            r"(?i)```.*(shell|bash|sh|zsh|powershell|cmd)",
        ),
        ambiguous(
            "tool-exec-run",
            40,
            r"(?i)run this command|execute the following|system\(|exec\(|eval\(",
        ),
        // --- report section 3.1: token-smuggling / encoding hints ---
        ambiguous(
            "encoding-hint-mention",
            30,
            r"(?i)base64.{0,10}decode|reverse.{0,10}string|rot13",
        ),
        ambiguous(
            "encoding-hint-charbychar",
            30,
            r"(?i)character.{0,3}by.{0,3}character|letter.{0,3}by.{0,3}letter",
        ),
        // --- exact SUMMARISATION_PATTERNS (4), from gsd-read-injection-scanner.js ---
        // Context-persistence attacks. Specific enough phrasing that benign prose
        // essentially never produces them.
        certain(
            "summ-retain-on-summarize",
            60,
            r"(?i)when\s+(?:summari[sz]ing|compressing|compacting),?\s+(?:retain|preserve|keep)\s+(?:this|these)",
        ),
        certain(
            "summ-permanent-directive",
            60,
            r"(?i)this\s+(?:instruction|directive|rule)\s+is\s+(?:permanent|persistent|immutable)",
        ),
        certain(
            "summ-preserve-rules",
            60,
            r"(?i)preserve\s+(?:these|this)\s+(?:rules?|instructions?|directives?)\s+(?:in|through|after|during)",
        ),
        certain(
            "summ-retain-through-compress",
            60,
            r"(?i)(?:retain|keep)\s+(?:this|these)\s+(?:in|through|after)\s+(?:summar|compress|compact)",
        ),
        // --- exact MARKDOWN_LINK_PATTERNS (4), from gsd-read-injection-scanner.js ---
        // Credential-leak shapes in links. `?token=` appears throughout API docs, so
        // these corroborate rather than convict.
        ambiguous("MD-LINK-JS-SCHEME", 25, r"(?i)\]\(\s*javascript:"),
        // MD-LINK-DATA-SCHEME handled separately below (needs the safe-mime predicate).
        ambiguous(
            "MD-LINK-USERINFO",
            25,
            r"(?i)\]\(\s*https?://[^/\s]+:[^/@\s]+@",
        ),
        ambiguous(
            "MD-LINK-TOKEN-IN-QUERY",
            25,
            r"(?i)[?&](token|access_token|id_token|refresh_token|api_key|apikey|secret|password|client_secret|code)=",
        ),
    ]
}

// --- "act as a/an/the <word>" excluding plan/phase/wave (JS used a negative
// lookahead; the `regex` crate has none, so capture + post-check instead). ---

static ACT_AS_RE: OnceLock<Regex> = OnceLock::new();

fn act_as_re() -> &'static Regex {
    ACT_AS_RE.get_or_init(|| Regex::new(r"(?i)act\s+as\s+(?:a|an|the)\s+(\w+)").unwrap())
}

fn fires_act_as(text: &str) -> bool {
    match act_as_re().captures(text) {
        Some(caps) => {
            let word = caps.get(1).unwrap().as_str().to_ascii_lowercase();
            !matches!(word.as_str(), "plan" | "phase" | "wave")
        }
        None => false,
    }
}

// --- markdown data: link, excluding the JS's safe-mime allowlist. ---

static MD_DATA_RE: OnceLock<Regex> = OnceLock::new();
static MD_DATA_SAFE_RE: OnceLock<Regex> = OnceLock::new();

fn md_data_re() -> &'static Regex {
    MD_DATA_RE.get_or_init(|| Regex::new(r"(?i)\]\(\s*(data:[^)]*)").unwrap())
}

fn md_data_safe_re() -> &'static Regex {
    MD_DATA_SAFE_RE.get_or_init(|| {
        Regex::new(r"(?i)^data:(image/(png|jpe?g|gif|webp|bmp|ico|avif|heic)|font/(woff2?|otf|ttf))(;[^,]*)?,")
            .unwrap()
    })
}

fn fires_md_data_unsafe(text: &str) -> bool {
    for line in text.lines() {
        if let Some(caps) = md_data_re().captures(line) {
            let val = caps.get(1).unwrap().as_str();
            if !md_data_safe_re().is_match(val) {
                return true;
            }
        }
    }
    false
}

/// One fired rule.
#[derive(Debug, Clone, Copy)]
pub struct Hit {
    pub id: &'static str,
    pub weight: u8,
    pub tier: Tier,
    /// Every occurrence sat in a quoting/defining context, so this is a mention
    /// of the pattern rather than a use of it. Quoted hits still score, but they
    /// can neither convict alone nor take part in a decisive combination.
    pub quoted: bool,
}

/// True if *every* occurrence of `re` in `text` sits in a context that quotes or
/// defines the pattern rather than utters it: inside a fenced code block, a regex
/// literal, a quoted string, or a JSONL corpus row.
///
/// This is what separates a document *about* prompt injection from one
/// *performing* it. A ruleset, a test fixture, an OWASP page and a CTF writeup all
/// contain the payload as data; an attack contains it as an imperative.
///
/// ponytail: window heuristic, not a parser. Ceiling: an attacker can wrap a
/// payload in quotes to earn the downgrade. Accepted — quoting also weakens the
/// payload against the target model, and a downgrade only routes to stage 2, it
/// never skips the check. Upgrade path if that stops holding: honour only
/// fenced/regex-literal context and drop the bare-quote case.
///
/// Note the check runs on the lines a match *spans*, not on single lines: `\s+`
/// crosses newlines in the `regex` crate even though `.` does not, so a payload
/// phrase wrapped across two lines of a comment is one match over two lines.
fn quoted_everywhere(re: &Regex, text: &str) -> bool {
    let mut saw_match = false;
    for m in re.find_iter(text) {
        saw_match = true;
        // Widen the match to whole lines so the surrounding syntax is visible.
        let start = text[..m.start()].rfind('\n').map_or(0, |i| i + 1);
        let end = text[m.end()..]
            .find('\n')
            .map_or(text.len(), |i| m.end() + i);
        let window = &text[start..end];

        if inside_fence(text, m.start())
            || window.lines().any(is_definition_line)
            || is_quoted_span(window, m.start() - start, m.end() - start)
        {
            continue;
        }
        return false; // one bare utterance is enough to convict
    }
    saw_match
}

/// Whether `offset` falls inside a fenced code block, by parity of the fence
/// markers opened before it.
fn inside_fence(text: &str, offset: usize) -> bool {
    text[..offset]
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with("```") || t.starts_with("~~~")
        })
        .count()
        % 2
        == 1
}

/// A line that declares a pattern rather than speaking it: a regex literal, a
/// corpus row, or a comment describing detection.
fn is_definition_line(line: &str) -> bool {
    let l = line.trim_start();
    l.starts_with("//")
        || l.starts_with('#')
        || l.starts_with('*')
        || l.starts_with("- ")
        || l.starts_with(r#"{"text":"#)
        || l.starts_with(r#"{ "text":"#)
        || line.contains("(?i)")
        || line.contains("Regex::new")
        || line.contains("re.compile")
        || line.contains("\\s+")
}

/// True if the byte range `[start, end)` of `window` lies inside a quoted span.
/// Counts quote characters before the match; an odd count means one is open.
fn is_quoted_span(window: &str, start: usize, end: usize) -> bool {
    for q in ['"', '\'', '`'] {
        let before = window[..start].matches(q).count();
        let after = window[end..].matches(q).count();
        if before % 2 == 1 && after > 0 {
            return true;
        }
    }
    false
}

impl RuleSet {
    pub fn load() -> RuleSet {
        RuleSet { _private: () }
    }

    /// Raw fired rules for already-normalized text — no aggregation. The engine
    /// unions these across text variants and unicode findings before scoring, so
    /// everything stacks toward the threshold together.
    ///
    /// A [`Tier::Certain`] rule whose every occurrence is quoted is demoted to
    /// [`Tier::Ambiguous`] at half weight: still evidence, no longer a conviction.
    pub fn hits(&self, text: &str) -> Vec<Hit> {
        let mut hits: Vec<Hit> = Vec::new();
        for rule in rules() {
            // Whole-text `is_match` stays the cheap gate; the line walk that
            // establishes quoting context only runs for rules that actually fired.
            if !rule.re.is_match(text) {
                continue;
            }
            hits.push(demote_if_quoted(
                Hit {
                    id: rule.id,
                    weight: rule.weight,
                    tier: rule.tier,
                    quoted: false,
                },
                &rule.re,
                text,
            ));
        }
        if fires_act_as(text) {
            hits.push(demote_if_quoted(
                // "act as a reverse proxy", "act as a tiebreaker" — overwhelmingly
                // benign English. Scores, never convicts, never combines.
                Hit {
                    id: "instr-act-as",
                    weight: 45,
                    tier: Tier::Ambiguous,
                    quoted: false,
                },
                act_as_re(),
                text,
            ));
        }
        if fires_md_data_unsafe(text) {
            hits.push(Hit {
                id: "MD-LINK-DATA-SCHEME",
                weight: 25,
                tier: Tier::Ambiguous,
                quoted: false,
            });
        }
        hits
    }

    /// Returns `(score, fired_rule_ids)` for already-normalized text.
    /// Score = max fired weight + 10 * (extra distinct rules), capped 100.
    pub fn score(&self, text: &str) -> (u8, Vec<String>) {
        let mut hits: std::collections::BTreeMap<String, Hit> = std::collections::BTreeMap::new();
        for h in self.hits(text) {
            merge_hit(&mut hits, h);
        }
        let (score, reasons, _) = aggregate(&hits);
        (score, reasons)
    }
}

fn demote_if_quoted(hit: Hit, re: &Regex, text: &str) -> Hit {
    if !quoted_everywhere(re, text) {
        return hit;
    }
    Hit {
        // A quoted certain hit is only a mention: it keeps half its weight as a
        // signal but loses the power to convict.
        tier: Tier::Ambiguous,
        weight: if hit.tier == Tier::Certain {
            hit.weight / 2
        } else {
            hit.weight
        },
        quoted: true,
        ..hit
    }
}

/// Fold a hit into the deduped map, keeping the strongest evidence for that id.
/// An unquoted occurrence anywhere outweighs a quoted one.
pub fn merge_hit(map: &mut std::collections::BTreeMap<String, Hit>, hit: Hit) {
    let e = map.entry(hit.id.to_string()).or_insert(hit);
    if hit.weight > e.weight {
        e.weight = hit.weight;
    }
    if hit.tier == Tier::Certain {
        e.tier = Tier::Certain;
    }
    if !hit.quoted {
        e.quoted = false;
    }
}

/// What an individually-ambiguous signal is evidence *of*.
///
/// Two ambiguous signals from **different** categories convict; any number from
/// the same one does not. That asymmetry is what tells a ruleset apart from an
/// attack: a detection ruleset, a threat-model doc or a CTF writeup enumerates
/// many patterns of one kind, while a real payload has to both claim authority
/// and issue a directive.
///
/// Membership is an explicit allowlist rather than an id-prefix rule, because
/// every entry needs to survive the question "would benign tool output pair this
/// with something from another category?". Signals too common to answer that
/// safely — a ```bash fence, "act as a reverse proxy" — are deliberately absent
/// and can only ever contribute score, never a conviction.
#[derive(PartialEq, Eq, Clone, Copy)]
enum Category {
    /// Impersonates a system/role turn: `[SYSTEM]`, `<<SYS>>`, fake role tags.
    Authority,
    /// Countermands standing instructions or reassigns the agent's identity.
    Override,
    /// Targets the safety layer specifically: personas, guardrail references.
    Jailbreak,
    /// Demands a concrete agent action: run this, send that.
    Action,
}

fn category(id: &str) -> Option<Category> {
    Some(match id {
        "instr-system-bracket"
        | "instr-fake-role-tags"
        | "instr-inst-bracket"
        | "instr-sys-bracket" => Category::Authority,

        "instr-override-generic"
        | "instr-override-system"
        | "instr-discard-instructions"
        | "instr-unrestricted-persona"
        | "instr-ignore-previous"
        | "instr-ignore-above"
        | "instr-ignore-everything-above"
        | "instr-disregard-previous"
        | "instr-forget-instructions"
        | "instr-new-system-prompt"
        | "instr-you-are-now"
        | "instr-you-are-free"
        | "instr-from-now-on"
        | "instr-pretend"
        | "instr-reveal-prompt" => Category::Override,

        "jailbreak-persona-mode"
        | "jailbreak-guidelines-ref"
        | "jailbreak-filter-bypass"
        | "role-theft-admin" => Category::Jailbreak,

        "tool-exec-run" => Category::Action,

        // Everything else — `instr-act-as`, ```bash fences, encoding hints, link
        // shapes, unicode findings — scores but never combines. Each is common
        // enough in benign tool output that pairing it would reintroduce the
        // false positives this whole mechanism exists to remove.
        _ => return None,
    })
}

/// True when signals from two or more distinct categories fired unquoted, so the
/// combination convicts even though no single signal does.
fn decisive_combination(hits: &std::collections::BTreeMap<String, Hit>) -> bool {
    let mut seen: Vec<Category> = Vec::new();
    for h in hits.values().filter(|h| !h.quoted) {
        if let Some(c) = category(h.id) {
            if !seen.contains(&c) {
                seen.push(c);
            }
            if seen.len() >= 2 {
                return true;
            }
        }
    }
    false
}

/// Aggregate deduped hits: max weight + 10 * (extra distinct), cap 100.
///
/// Returns `(score, fired_rule_ids, decisive)`. `decisive` is true when at least
/// one unquoted [`Tier::Certain`] hit survived, or when a decisive combination of
/// individually-ambiguous signals fired. The engine hard-blocks only on that.
pub fn aggregate(hits: &std::collections::BTreeMap<String, Hit>) -> (u8, Vec<String>, bool) {
    if hits.is_empty() {
        return (0, Vec::new(), false);
    }
    let max_weight = hits.values().map(|h| h.weight).max().unwrap() as u32;
    let extra = (hits.len() - 1) as u32;
    let mut score = (max_weight + 10 * extra).min(100) as u8;
    let mut reasons: Vec<String> = hits.keys().cloned().collect();

    let certain = hits.values().any(|h| h.tier == Tier::Certain && !h.quoted);
    let combination = decisive_combination(hits);
    if combination {
        // The pairing is stronger evidence than either half, and neither half's
        // weight reflects that. Name it in the output so a blocked caller can see
        // *why* two weak signals convicted.
        reasons.push(COMBO_FORGED_TURN.to_string());
        score = score.max(85);
    }
    (score, reasons, certain || combination)
}

/// Synthesised reason id emitted when [`decisive_combination`] convicts.
pub const COMBO_FORGED_TURN: &str = "combo-forged-system-turn";

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

/// A single compiled detection rule.
pub struct Rule {
    pub id: &'static str,
    pub weight: u8,
}

struct CompiledRule {
    id: &'static str,
    weight: u8,
    re: Regex,
}

pub struct RuleSet {
    _private: (),
}

static RULES: OnceLock<Vec<CompiledRule>> = OnceLock::new();

fn rules() -> &'static Vec<CompiledRule> {
    RULES.get_or_init(build_rules)
}

fn r(id: &'static str, weight: u8, pattern: &str) -> CompiledRule {
    CompiledRule {
        id,
        weight,
        re: Regex::new(pattern).unwrap_or_else(|e| panic!("bad regex for {id}: {e}")),
    }
}

fn build_rules() -> Vec<CompiledRule> {
    vec![
        // --- exact INJECTION_PATTERNS (14), from gsd-read-injection-scanner.js ---
        // instruction-override: weight 70-90.
        r("instr-ignore-previous", 85, r"(?i)ignore\s+(all\s+)?previous\s+instructions"),
        r("instr-ignore-above", 85, r"(?i)ignore\s+(all\s+)?above\s+instructions"),
        r("instr-disregard-previous", 85, r"(?i)disregard\s+(all\s+)?previous"),
        r("instr-forget-instructions", 85, r"(?i)forget\s+(all\s+)?(your\s+)?instructions"),
        r("instr-override-system", 85, r"(?i)override\s+(system|previous)\s+(prompt|instructions)"),
        r("instr-you-are-now", 85, r"(?i)you\s+are\s+now\s+(?:a|an|the)\s+"),
        // "act as a/an/the <word>" excluding plan/phase/wave — handled below (no lookahead in `regex`).
        r("instr-pretend", 85, r"(?i)pretend\s+(?:you(?:'re| are)\s+|to\s+be\s+)"),
        r("instr-from-now-on", 85, r"(?i)from\s+now\s+on,?\s+you\s+(?:are|will|should|must)"),
        r(
            "instr-reveal-prompt",
            85,
            r"(?i)(?:print|output|reveal|show|display|repeat)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions)",
        ),
        r("instr-fake-role-tags", 85, r"(?i)</?(?:system|assistant|human)>"),
        r("instr-system-bracket", 85, r"(?i)\[SYSTEM\]"),
        r("instr-inst-bracket", 85, r"(?i)\[INST\]"),
        r("instr-sys-bracket", 85, r"(?i)<<\s*SYS\s*>>"),
        // --- report section 3.1: system-prompt-override extras not in the 14 ---
        r(
            "instr-override-generic",
            75,
            r"(?i)(ignore|forget|override|disregard).{0,50}(instructions|system|prompt|rules)",
        ),
        r("instr-ignore-everything-above", 85, r"(?i)ignore everything above"),
        r("instr-new-system-prompt", 85, r"(?i)new system prompt:"),
        r("instr-you-are-free", 85, r"(?i)you\s+are\s+a\s+free\s+agent|you\s+are\s+not\s+bound"),
        // --- report section 3.1: role theft ---
        r(
            "role-theft-admin",
            50,
            r"(?i)(act\s+as|pretend|imagine\s+you\s+are|roleplay\s+as).{0,30}(admin|sudo|root|superuser|god)",
        ),
        // --- report section 3.1: jailbreak persona / guardrail-reference patterns ---
        r(
            "jailbreak-persona-mode",
            70,
            r"(?i)(DAN|DUDE|STAN|JAILBREAK|MARY|SANTACLAUS|hypothetical).{0,30}(response|answer|mode)",
        ),
        r(
            "jailbreak-guidelines-ref",
            70,
            r"(?i)your safety guidelines|your ethical guidelines|your programming",
        ),
        r(
            "jailbreak-filter-bypass",
            70,
            r"(?i)output format.{0,30}bypass|filter bypass|filter evasion",
        ),
        // --- report section 3.1: code/tool injection ---
        r(
            "tool-exec-codeblock",
            70,
            r"(?i)```.*(shell|bash|sh|zsh|powershell|cmd)",
        ),
        r(
            "tool-exec-run",
            70,
            r"(?i)run this command|execute the following|system\(|exec\(|eval\(",
        ),
        // --- report section 3.1: token-smuggling / encoding hints ---
        r(
            "encoding-hint-mention",
            30,
            r"(?i)base64.{0,10}decode|reverse.{0,10}string|rot13",
        ),
        r(
            "encoding-hint-charbychar",
            30,
            r"(?i)character.{0,3}by.{0,3}character|letter.{0,3}by.{0,3}letter",
        ),
        // --- exact SUMMARISATION_PATTERNS (4), from gsd-read-injection-scanner.js ---
        r(
            "summ-retain-on-summarize",
            60,
            r"(?i)when\s+(?:summari[sz]ing|compressing|compacting),?\s+(?:retain|preserve|keep)\s+(?:this|these)",
        ),
        r(
            "summ-permanent-directive",
            60,
            r"(?i)this\s+(?:instruction|directive|rule)\s+is\s+(?:permanent|persistent|immutable)",
        ),
        r(
            "summ-preserve-rules",
            60,
            r"(?i)preserve\s+(?:these|this)\s+(?:rules?|instructions?|directives?)\s+(?:in|through|after|during)",
        ),
        r(
            "summ-retain-through-compress",
            60,
            r"(?i)(?:retain|keep)\s+(?:this|these)\s+(?:in|through|after)\s+(?:summar|compress|compact)",
        ),
        // --- exact MARKDOWN_LINK_PATTERNS (4), from gsd-read-injection-scanner.js ---
        r("MD-LINK-JS-SCHEME", 25, r"(?i)\]\(\s*javascript:"),
        // MD-LINK-DATA-SCHEME handled separately below (needs the safe-mime predicate).
        r(
            "MD-LINK-USERINFO",
            25,
            r"(?i)\]\(\s*https?://[^/\s]+:[^/@\s]+@",
        ),
        r(
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

impl RuleSet {
    pub fn load() -> RuleSet {
        RuleSet { _private: () }
    }

    /// Raw fired rules `(id, weight)` for already-normalized text — no
    /// aggregation. The engine unions these across text variants and unicode
    /// findings before scoring, so everything stacks toward the threshold together.
    pub fn hits(&self, text: &str) -> Vec<(&'static str, u8)> {
        let mut hits: Vec<(&'static str, u8)> = Vec::new();
        for rule in rules() {
            if rule.re.is_match(text) {
                hits.push((rule.id, rule.weight));
            }
        }
        if fires_act_as(text) {
            hits.push(("instr-act-as", 85));
        }
        if fires_md_data_unsafe(text) {
            hits.push(("MD-LINK-DATA-SCHEME", 25));
        }
        hits
    }

    /// Returns `(score, fired_rule_ids)` for already-normalized text.
    /// Score = max fired weight + 10 * (extra distinct rules), capped 100.
    pub fn score(&self, text: &str) -> (u8, Vec<String>) {
        let mut weights: std::collections::BTreeMap<String, u8> = std::collections::BTreeMap::new();
        for (id, w) in self.hits(text) {
            let e = weights.entry(id.to_string()).or_insert(0);
            *e = (*e).max(w);
        }
        aggregate(&weights)
    }
}

/// Aggregate deduped `id -> weight` hits: max weight + 10 * (extra distinct), cap 100.
pub fn aggregate(weights: &std::collections::BTreeMap<String, u8>) -> (u8, Vec<String>) {
    if weights.is_empty() {
        return (0, Vec::new());
    }
    let max_weight = weights.values().copied().max().unwrap() as u32;
    let extra = (weights.len() - 1) as u32;
    let score = (max_weight + 10 * extra).min(100) as u8;
    (score, weights.keys().cloned().collect())
}

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
        // Bare "disregard all previous <anything>" convicted "disregard previous
        // comments on this thread". The form that matters — disregarding previous
        // *instructions* — is covered as Certain by `instr-discard-instructions`.
        ambiguous(
            "instr-disregard-previous",
            45,
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
        // Reassignment of the agent's *nature*, not of a human role. The original
        // "you are now a/an/the <anything>" convicted "you are now a maintainer on
        // this repo" and "you are now the on-call engineer" — access grants and
        // handover notes, which are everywhere in team chat and tool output.
        certain(
            "instr-you-are-now",
            85,
            r"(?i)you\s+are\s+now\s+(?:a|an|the)\s+(?:\w+\s+){0,2}(?:AI|A\.I\.|assistant|model|chatbot|bot|agent|LLM|GPT|persona|character)\b",
        ),
        // "act as a/an/the <word>" excluding plan/phase/wave — handled below (no lookahead in `regex`).
        // "Pretend to be offline in this test" is ordinary test-scaffolding speech,
        // so this corroborates rather than convicts.
        ambiguous(
            "instr-pretend",
            45,
            r"(?i)pretend\s+(?:you(?:'re| are)\s+|to\s+be\s+)",
        ),
        // "From now on you must run the formatter before pushing" — every
        // contributing guide ever written. Corroborating only.
        ambiguous(
            "instr-from-now-on",
            45,
            r"(?i)from\s+now\s+on,?\s+you\s+(?:are|will|should|must)",
        ),
        // Requires the possessive: exfiltrating *your* prompt is the attack, while
        // "print instructions for the failing migration" and "display instructions
        // on stderr" are ordinary CLI-help prose that the unqualified form convicted.
        certain(
            "instr-reveal-prompt",
            85,
            r"(?i)(?:print|output|reveal|show|display|repeat|dump|echo)\s+(?:me\s+)?(?:your|the)\s+(?:system\s+|initial\s+|original\s+|hidden\s+)?(?:prompt|instructions|system\s+message)",
        ),
        certain(
            "instr-fake-role-tags",
            85,
            r"(?i)</?(?:system|assistant|human)>",
        ),
        // Chat-template markers. All three are described in bare prose by ordinary
        // LLM documentation ("the Llama 2 template wraps system content in <<SYS>>
        // tags and each user turn in [INST] blocks"), so none convicts alone. They
        // carry the Authority category instead, which convicts when paired with a
        // directive — a forged turn, rather than a description of one.
        ambiguous("instr-system-bracket", 60, r"(?i)\[SYSTEM\]"),
        ambiguous("instr-inst-bracket", 60, r"(?i)\[INST\]"),
        ambiguous("instr-sys-bracket", 60, r"(?i)<<\s*SYS\s*>>"),
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
            r"(?i)(?:ignore|disregard|forget|override|discard)\s+(?:all\s+)?(?:of\s+)?(?:your|the|my|these|those|any)?\s*(?:(?:previous|prior|earlier|above|preceding|original|initial|system|standing|safety|content)\s+){0,3}(?:instructions?|directives?)|(?:ignore|disregard|forget|override|discard)\s+(?:all\s+)?(?:your|the|my|these|those|any)?\s*(?:(?:previous|prior|earlier|above|preceding|original|initial|system|standing|safety|content)\s+){1,3}(?:rules?|guidelines?|guidance|polic(?:y|ies))",
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
            r"(?i)(?:act\s+as|you\s+are|you're|become|behave\s+(?:as|like)|roleplay\s+as|pretend\s+(?:to\s+be|you(?:'re| are)))\s+(?:a|an|the)?\s*(?:completely\s+|totally\s+|fully\s+)?(?:(?:unrestricted|unfiltered|uncensored|unbound|unlimited|jailbroken|amoral|lawless)|(?:\w+\s+){0,2}with\s+(?:no|zero|without\s+any)\s+(?:restrictions?|limits?|filters?|rules?|content\s+polic|guidelines?|safety))",
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
        // Direct assignment of a known jailbreak persona. The generic
        // `jailbreak-persona-mode` above needs a trailing "mode"/"answer"/"response",
        // so bare "you are DAN" — the actual canonical form — slipped past it.
        // The persona token is matched case-sensitively on purpose: "you are DAN"
        // is the jailbreak, "you are Dan" is someone addressing a colleague.
        certain(
            "jailbreak-persona-assign",
            85,
            r"(?i)you\s+are\s+(?:now\s+)?(?-i:DAN|STAN|AIM|DUDE|KEVIN)\b|(?i)you\s+are\s+(?:now\s+)?in\s+developer\s+mode",
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

        // Structural enclosure is proof, not inference: the payload is demonstrably
        // delimited as data, and a test fixture or corpus row is entitled to contain
        // a complete attack string, exfiltration verb and all.
        if inside_fence(text, m.start())
            || is_quoted_span(window, m.start() - start, m.end() - start)
        {
            continue;
        }

        // The remaining three signals are inferences about intent, and none of them
        // survives a live directive. Without this veto they were trivially
        // defeated — prefixing "# " or "For example," to a working payload turned a
        // block into a warning, which in the hook adapter means it goes through.
        if carries_action_demand(window) {
            return false;
        }

        if window.lines().any(is_definition_line)
            || describes_rather_than_utters(window)
            || bound_to_named_artifact(window, m.end() - start)
        {
            continue;
        }
        return false; // one bare utterance is enough to convict
    }
    saw_match
}

/// Whether the window contains a concrete directive — something to do, and often
/// somewhere to send it.
///
/// Documentation describes attacks; it does not also carry a live exfiltration
/// target. Checked per-window rather than per-document on purpose: a SECURITY.md
/// that says "Email security@example.com" in its reporting section must not have
/// that address veto a demotion twenty lines away.
fn carries_action_demand(window: &str) -> bool {
    action_demand_re().is_match(window)
}

static ACTION_DEMAND_RE: OnceLock<Regex> = OnceLock::new();

fn action_demand_re() -> &'static Regex {
    ACTION_DEMAND_RE.get_or_init(|| {
        Regex::new(concat!(
            // Verbs that are their own evidence.
            r"(?i)\b(?:exfiltrat|leak\s+the|steal\s+the)\w*",
            // Transmission verb with a destination.
            r"|(?i)\b(?:send|email|e-mail|post|upload|transmit|forward|deliver)\b[^.\n]{0,60}",
            r"(?:https?://|[\w.-]+@[\w.-]+|\b(?:to|at)\s+[\w.-]+\.[a-z]{2,})",
            // Demanding the agent's own secrets.
            r"|(?i)\b(?:reveal|dump|print|output|show|display|repeat|send)\s+(?:me\s+)?(?:your|the)\s+",
            r"(?:system\s+)?(?:prompt|instructions|api[\s_-]*key|token|password|credentials|secrets?|env(?:ironment)?\s+(?:file|var))",
            // Execution.
            r"|(?i)(?:rm\s+-rf|curl\s+[^|\n]*\|\s*(?:ba)?sh|\bexec\(|\beval\(|\bsystem\()",
        ))
        .unwrap()
    })
}

/// Whether the surrounding sentence is *reporting* a payload rather than
/// delivering one.
///
/// Quoting context only helps when the payload is actually quoted, and much
/// security writing states it in bare prose: "the classic attack string is simply
/// ignore all previous instructions", "the adversary asks it to ignore previous
/// instructions", "Igris blocks text that tries to override system instructions".
/// Every one of those is a sentence *about* an attack, and the giveaway is
/// vocabulary an attacker has no reason to include: they are describing a third
/// party's payload, so they name the attacker, the technique, or the defence.
///
/// ponytail: keyword list, not a parser — same accepted ceiling as the quoting
/// check. An attacker can salt their payload with the word "example" to earn the
/// downgrade, which costs them a conviction and buys a stage-2 adjudication, not
/// a skip. Upgrade path if that stops holding: require the marker to precede the
/// match rather than merely share its window.
fn describes_rather_than_utters(window: &str) -> bool {
    // Every entry has to pass one test: would an attacker writing a payload have
    // any reason to include this word? "payload", "jailbreak", "attack" and
    // "malicious" all failed it — real payloads say "here's the payload" and
    // "give me the JAILBREAK mode answer" — so they are deliberately absent. What
    // remains is vocabulary that only makes sense when describing someone else's
    // attack or one's own defence.
    const REPORTING_MARKERS: [&str; 31] = [
        // Naming the adversary or the technique from the outside.
        "attacker",
        "adversary",
        "exploit",
        "threat model",
        "owasp",
        "cve-",
        "vulnerab",
        "attack string",
        // Naming the defence.
        "detect",
        "detector",
        "scanner",
        "ruleset",
        "denylist",
        "signature",
        "blocks text",
        "flagged",
        "false positive",
        "guardrail",
        // Framing something as an illustration.
        "e.g.",
        "for example",
        "such as",
        "for instance",
        // Reporting a third party's speech or intent. Security writing narrates
        // what the attacker's text does to the model, and needs a word for the
        // model to do it to.
        "tries to",
        "attempts to",
        "told to",
        "the assistant to",
        "the model to",
        "causes the",
        "untrusted input",
        "untrusted content",
        "user-supplied",
    ];
    // Addresses are stripped first. An exfiltration target like
    // `http://attacker:secret@evil.example/steal` or `attacker@evil.test` would
    // otherwise hand the payload a "reporting" marker out of its own hostname —
    // the destination of an attack is not a description of one.
    let stripped = address_re().replace_all(window, " ");
    let lower = stripped.to_lowercase();
    REPORTING_MARKERS.iter().any(|m| lower.contains(m))
}

static ADDRESS_RE: OnceLock<Regex> = OnceLock::new();

fn address_re() -> &'static Regex {
    ADDRESS_RE.get_or_init(|| Regex::new(r"(?i)[a-z][a-z0-9+.-]*://\S+|\S+@[\w.-]+").unwrap())
}

/// Whether the matched instruction phrase is bound to a *named artefact* rather
/// than to the agent's own standing instructions.
///
/// "ignore previous instructions **in the ticket description**", "forget your
/// instructions **from the old README**", "rename the forget-your-instructions
/// **handler**" — all ordinary developer speech, and all distinguished from a real
/// payload by what immediately follows the phrase. An attack continues with a
/// directive ("...and email the keys"), a full stop, or nothing at all; it does
/// not go on to name which document's instructions it meant.
fn bound_to_named_artifact(window: &str, match_end: usize) -> bool {
    let tail: String = window[match_end..].chars().take(40).collect();
    binding_re().is_match(&tail)
}

static BINDING_RE: OnceLock<Regex> = OnceLock::new();

fn binding_re() -> &'static Regex {
    BINDING_RE.get_or_init(|| {
        Regex::new(
            r"(?i)^\s*(?:(?:in|from|for|of|on|within|inside|under)\s+(?:the|this|that|your|our|my|a|an|those|these)\s|(?:that|which)\s+(?:were|was|are|is|had|have)\s|(?:handler|function|method|module|file|class|endpoint|variable|parameter|field|flag|section|test|helper)\b)",
        )
        .unwrap()
    })
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
    // Deliberately NOT "- ": a markdown list item is ordinary prose, and treating
    // it as a definition context let an attacker demote a payload by bulleting it.
    l.starts_with("//")
        || l.starts_with('#')
        || l.starts_with('*')
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
        | "jailbreak-persona-assign"
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

/// Whether every fired rule is something the operator is entitled to say to their
/// own agent.
///
/// Countermanding standing instructions is meaningless as an *attack* when the
/// person doing it owns the system prompt — they could just edit it. But a
/// forged system turn, a jailbreak persona, or a demand that the agent run
/// something are about what the model is induced to *do*, and stay meaningful no
/// matter who typed them. Only the first kind is a prerogative.
pub fn only_operator_prerogative(reasons: &[String]) -> bool {
    !reasons.iter().any(|r| {
        r == COMBO_FORGED_TURN
            || matches!(
                category(r),
                Some(Category::Authority) | Some(Category::Jailbreak) | Some(Category::Action)
            )
    })
}

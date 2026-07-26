//! `igris hook` — Claude Code and Codex hook adapter. PHASE-2A.
//!
//! Reads one hook JSON object on stdin, dispatches on `hook_event_name`
//! (UserPromptSubmit, PostToolUse), emits hook-protocol JSON. FailMode::DegradeStage1.
//! Any internal error / unparseable stdin → exit 0 silently (never wedge the editor).

use crate::config::Config;
use crate::engine::Engine;
use crate::{Action, FailMode, Trust, Verdict};
use serde_json::Value;
use std::io::Read;

pub async fn run(cfg: Config) -> i32 {
    // Enforce the "never wedge the editor" guarantee against panics too (e.g. a
    // future bad regex): any panic in hook mode exits 0 silently rather than 101.
    // Fail-open here matches DegradeStage1 — no decision emitted means content passes.
    std::panic::set_hook(Box::new(|_| std::process::exit(0)));

    let mut buf = String::new();
    if std::io::stdin().read_to_string(&mut buf).is_err() {
        return 0;
    }
    if buf.trim().is_empty() {
        return 0;
    }
    let data: Value = match serde_json::from_str(&buf) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let event = match data.get("hook_event_name").and_then(|v| v.as_str()) {
        Some(e) => e,
        None => return 0,
    };

    let engine = Engine::new(cfg);
    match event {
        "UserPromptSubmit" => handle_user_prompt_submit(&engine, &data).await,
        "PostToolUse" => handle_post_tool_use(&engine, &data).await,
        _ => 0,
    }
}

async fn handle_user_prompt_submit(engine: &Engine, data: &Value) -> i32 {
    let prompt = match data.get("prompt").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return 0,
    };

    let verdict = engine
        // The operator typed this. Phrasing alone must not lock them out of their
        // own session; smuggled control characters still block, since those mean
        // the text was pasted from somewhere they do not control.
        .scan_trusted(prompt, "user-prompt", Trust::User, FailMode::DegradeStage1)
        .await;
    match verdict.action {
        Action::Block => {
            let out = serde_json::json!({
                "decision": "block",
                "reason": format!(
                    "Igris blocked prompt (score {}): {}",
                    verdict.score,
                    verdict.reasons.join(", ")
                ),
            });
            println!("{out}");
        }
        Action::Warn => {
            let out = serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "UserPromptSubmit",
                    "additionalContext": format!(
                        "IGRIS WARN [score {}] {}",
                        verdict.score,
                        verdict.reasons.join(", ")
                    ),
                }
            });
            println!("{out}");
        }
        Action::Pass => {}
    }
    0
}

async fn handle_post_tool_use(engine: &Engine, data: &Value) -> i32 {
    let tool_name = match data.get("tool_name").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => return 0,
    };
    let is_mcp = tool_name.starts_with("mcp__");
    let scanned = matches!(
        tool_name.as_str(),
        "Read" | "WebFetch" | "Bash" | "WebSearch"
    ) || is_mcp;
    if !scanned {
        return 0;
    }

    let empty = Value::Null;
    let tool_input = data.get("tool_input").unwrap_or(&empty);
    let tool_response = data.get("tool_response").unwrap_or(&empty);

    let content = match tool_name.as_str() {
        "Read" | "WebFetch" => extract_content_field(tool_response),
        "Bash" => extract_bash(tool_response),
        _ => extract_text_nodes(tool_response), // WebSearch, mcp__*
    };
    if content.len() < 20 {
        return 0;
    }

    let source = source_label(&tool_name, tool_input);
    let mut verdict = engine
        .scan(&content, &source, FailMode::DegradeStage1)
        .await;

    // Excluded paths (Read only, mirrors gsd-read-injection-scanner.js): downgrade, never skip.
    if tool_name == "Read" && verdict.action == Action::Block {
        if let Some(fp) = tool_input.get("file_path").and_then(|v| v.as_str()) {
            if is_excluded_path(fp) {
                verdict = Verdict::new(
                    verdict.score,
                    Action::Warn,
                    verdict.confidence,
                    verdict.reasons,
                );
            }
        }
    }

    match verdict.action {
        Action::Block => {
            let advisory = build_advisory(&verdict, &tool_name, &source);
            let out = serde_json::json!({
                "decision": "block",
                "reason": format!("Prompt-injection blocked ({tool_name}): {advisory}"),
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": advisory,
                }
            });
            println!("{out}");
        }
        Action::Warn => {
            let advisory = build_advisory(&verdict, &tool_name, &source);
            let out = serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": advisory,
                }
            });
            println!("{out}");
        }
        Action::Pass => {}
    }
    0
}

fn build_advisory(v: &Verdict, tool_name: &str, source: &str) -> String {
    format!(
        "IGRIS [{:?} score={}] ({tool_name}) \"{source}\": {}",
        v.action,
        v.score,
        v.reasons.join(", ")
    )
}

/// Every string value in a JSON response, one per line.
///
/// The scanner must be given the *text*, never the document that carries it.
/// `serde_json::to_string` wraps every payload string in double quotes, and
/// [`crate::rules`]'s quoting rule then reads the payload as a mention rather
/// than an utterance — demoting Certain evidence to Ambiguous at half weight.
/// That took a real `mcp__*` payload from score 100 (block) down to 45, which is
/// below `escalate_threshold`, so it passed without even reaching stage 2.
/// Harvesting the leaves hands the scanner the same bytes the model will read.
///
/// Newline-joined on purpose: the bounded-gap rules (`.{0,50}`, `[^.\n]{0,60}`)
/// do not cross a newline, so two unrelated fields cannot combine into a match
/// that neither of them contains.
fn extract_text_nodes(resp: &Value) -> String {
    let mut out = Vec::new();
    collect_strings(resp, &mut out);
    out.join("\n")
}

/// Depth is bounded by serde_json's own 128-level nesting limit, so a hostile
/// response cannot recurse this into a stack overflow.
fn collect_strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| collect_strings(x, out)),
        // Values only. Keys are field names the tool chose, not content.
        // ponytail: a server that smuggles a payload into a key evades this —
        // add `out.push(k.clone())` here if that ever shows up in the wild.
        Value::Object(o) => o.values().for_each(|x| collect_strings(x, out)),
        _ => {}
    }
}

/// Mirrors `data.tool_response` extraction for Read/WebFetch in
/// gsd-read-injection-scanner.js: string, `.content` (string | array of
/// `{text}`), else every string in the response.
fn extract_content_field(resp: &Value) -> String {
    match resp {
        Value::String(s) => s.clone(),
        Value::Object(_) => match resp.get("content") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Array(arr)) => arr
                .iter()
                .map(|b| match b {
                    Value::String(s) => s.clone(),
                    // A block that keeps its text somewhere other than `.text`
                    // gets scanned rather than silently dropped.
                    _ => b
                        .get("text")
                        .and_then(|t| t.as_str())
                        .map(str::to_string)
                        .unwrap_or_else(|| extract_text_nodes(b)),
                })
                .collect::<Vec<_>>()
                .join("\n"),
            // No usable `.content`: scan whatever text the response does carry.
            _ => extract_text_nodes(resp),
        },
        other => extract_text_nodes(other),
    }
}

fn extract_bash(resp: &Value) -> String {
    let stdout = resp.get("stdout").and_then(|v| v.as_str()).unwrap_or("");
    let stderr = resp.get("stderr").and_then(|v| v.as_str()).unwrap_or("");
    format!("{stdout}\n{stderr}")
}

fn source_label(tool_name: &str, tool_input: &Value) -> String {
    match tool_name {
        "Read" => tool_input
            .get("file_path")
            .and_then(|v| v.as_str())
            .unwrap_or(tool_name)
            .to_string(),
        "WebFetch" => tool_input
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or(tool_name)
            .to_string(),
        "Bash" => truncate(
            tool_input
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
            80,
        ),
        _ => tool_name.to_string(),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

/// Port of `isExcludedPath` from gsd-read-injection-scanner.js. Deliberately a
/// little broader than the JS regexes (substring checks vs anchored regex) —
/// safe here because the only effect of a false-positive match is
/// Block -> Warn (downgrade), never a skip.
fn is_excluded_path(file_path: &str) -> bool {
    let p = file_path.replace('\\', "/").to_lowercase();
    if p.contains("/.planning/") || p.contains(".planning/") {
        return true;
    }
    let basename = p.rsplit('/').next().unwrap_or(&p);
    if basename == "review.md" || basename.contains("checkpoint") {
        return true;
    }
    if p.contains("/security/")
        || p.contains("/security.")
        || p.contains("/techsec/")
        || p.contains("/techsec.")
        || p.contains("/injection/")
        || p.contains("/injection.")
        || p.ends_with("security.cjs")
    {
        return true;
    }
    if p.contains("/.claude/hooks/") {
        return true;
    }
    false
}

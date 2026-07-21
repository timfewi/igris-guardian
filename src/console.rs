//! `igris console` — a full-screen, read-only viewer over the append-only audit
//! log. It opens the log O_RDONLY and never writes a byte anywhere: no stats
//! file, no cursor file, no cache. The Guardian's constitution says it writes
//! nothing but the audit log, and a dashboard that adds a second writer would
//! quietly break that claim.
//!
//! Everything rendered here is backed by a field that `audit.rs` actually
//! records. The audit log contains ONE LINE PER NON-PASS VERDICT — passes are
//! never logged, and there is no latency, no scanned total and no pass count in
//! the file. So there is no pass-rate panel and no latency panel: inventing
//! those numbers from a log that cannot support them would make the dashboard a
//! liar, which is a worse failure for a security tool than a missing panel.
//!
//! Zero new dependencies by design — this is a supply-chain-sensitive binary.
//! Raw ANSI, `std`, the already-present `serde_json`, and the POSIX `stty`
//! binary for raw mode and terminal size.

use crate::config::Config;
use crate::stage2::GUARDIAN_PROMPT_SHA256;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

// ── palette ─────────────────────────────────────────────────────────────────
// 24-bit truecolor only. ponytail: no 256-color fallback — detecting it means
// parsing $TERM/$COLORTERM and maintaining a second palette, which is real code
// for a case that basically does not occur on a machine running a Rust agent
// firewall in 2025. Ceiling: on a 16-color terminal the SGR sequences are
// ignored and the layout still renders, just monochrome. Upgrade path: gate the
// consts behind a `truecolor: bool` read from $COLORTERM.
const C_RED: &str = "\x1b[38;2;229;57;63m";
const C_TEXT: &str = "\x1b[38;2;207;210;214m";
const C_BRIGHT: &str = "\x1b[38;2;248;249;251m";
const C_PASS: &str = "\x1b[38;2;98;217;150m";
const C_WARN: &str = "\x1b[38;2;232;179;60m";
const C_BLOCK: &str = "\x1b[38;2;255;77;77m";
const C_DIM: &str = "\x1b[38;2;95;99;104m";
const C_DIMMER: &str = "\x1b[38;2;74;78;85m";
const C_BORDER: &str = "\x1b[38;2;107;43;48m";
const C_BAR_HOT: &str = "\x1b[38;2;196;53;53m";
const C_BAR_COOL: &str = "\x1b[38;2;138;61;61m";
const RESET: &str = "\x1b[0m";

const KNIGHT_ART: &str = include_str!("../assets/knight.txt");
const KNIGHT_COLORS: &str = include_str!("../assets/knight.colors");
/// Terminal rows below which the knight is dropped entirely.
///
/// It is drawn whole or not at all. Cropping line art of a *figure* severs it
/// mid-torso and reads as a rendering bug rather than a deliberate emblem, so
/// either the terminal can seat all 18 rows with a usable event feed still under
/// them, or the header is the banner alone, which looks intentional.
const KNIGHT_MIN_ROWS: usize = 44;
/// Palette indices used by `knight.colors`: 0..=3.
const KNIGHT_PALETTE: [(u8, u8, u8); 4] = [
    (0xF0, 0x80, 0x80),
    (0xA5, 0x2A, 0x2A),
    (0xCD, 0x5C, 0x5C),
    (0xFA, 0x80, 0x72),
];

const BANNER: &str = r#"███ ▄██ ██▄ ███ ▄██
 █  █   █ █  █  █
 █  █ █ ██▀  █   ▀█
███ ▀██ █ █ ███ ██▀
"#;

/// Redraw cadence. 4 Hz is fast enough to feel live and slow enough that the
/// per-frame `stty size` + full repaint costs nothing measurable.
const TICK: Duration = Duration::from_millis(250);

/// Cap on records held in memory. ponytail: a flat cap, not a ring buffer —
/// aggregates are recomputed from the whole vec each frame, which is a 5k-element
/// pass at 4 Hz and invisible. Ceiling: if the cap ever needs to be 10x this,
/// switch to incremental counters plus a ring for the event tail.
const MAX_RECORDS: usize = 5000;

/// Bytes of an existing log read at startup. ponytail: a 4 MiB tail window
/// rather than a reverse line scan — a huge log costs one bounded read instead
/// of stalling startup. Ceiling: the oldest visible event is whatever landed in
/// the last 4 MiB. Upgrade path: chunked backwards scan until 5000 newlines.
const STARTUP_TAIL_BYTES: u64 = 4 * 1024 * 1024;

// ── audit record ────────────────────────────────────────────────────────────

/// One parsed line of the audit log. Field-for-field what `audit.rs` writes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rec {
    ts: u64,
    source: String,
    action: String,
    score: u8,
    confidence: String,
    rules: Vec<String>,
    stage2: bool,
    sha256: String,
    excerpt: Option<String>,
}

/// Parse one JSONL line. Returns `None` for anything that is not a well-formed
/// record — blank lines, a torn line from a concurrent append, a future schema.
/// The console must never panic on log content: the log is written by a process
/// that is scanning hostile input, and half a line is the normal case when the
/// writer is mid-append.
fn parse_line(line: &str) -> Option<Rec> {
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    let o = v.as_object()?;
    // `action` is the one field that must exist and be meaningful; without it
    // the record cannot be counted as anything.
    let action = o.get("action")?.as_str()?.to_string();
    if action != "warn" && action != "block" {
        return None;
    }
    Some(Rec {
        ts: o.get("ts").and_then(|x| x.as_u64()).unwrap_or(0),
        source: o
            .get("source")
            .and_then(|x| x.as_str())
            .unwrap_or("?")
            .to_string(),
        action,
        score: o
            .get("score")
            .and_then(|x| x.as_u64())
            .unwrap_or(0)
            .min(100) as u8,
        confidence: o
            .get("confidence")
            .and_then(|x| x.as_str())
            .unwrap_or("ambiguous")
            .to_string(),
        rules: o
            .get("rules")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|r| r.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        stage2: o.get("stage2").and_then(|x| x.as_bool()).unwrap_or(false),
        sha256: o
            .get("sha256")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        excerpt: o
            .get("excerpt")
            .and_then(|x| x.as_str())
            .map(str::to_string),
    })
}

/// Split newly-read text into complete lines, retaining any trailing fragment in
/// `partial` for the next read. This is what makes tailing safe against a line
/// being appended while we read it.
fn take_lines(partial: &mut String, chunk: &str) -> Vec<String> {
    partial.push_str(chunk);
    let mut out: Vec<String> = partial.split('\n').map(str::to_string).collect();
    // `split` always yields at least one element; the last one is the fragment
    // after the final newline (empty if the chunk ended cleanly).
    *partial = out.pop().unwrap_or_default();
    out
}

// ── tailer ──────────────────────────────────────────────────────────────────

struct Tail {
    path: PathBuf,
    offset: u64,
    partial: String,
}

impl Tail {
    fn new(path: PathBuf) -> Tail {
        Tail {
            path,
            offset: 0,
            partial: String::new(),
        }
    }

    /// Seed from an existing log over the startup tail window. Deliberately the
    /// same code path as `poll`: `read_from` sets `offset` from what was actually
    /// consumed (not a stale `metadata` len, which double-counts anything the
    /// Guardian appends during startup) and stashes a torn final line in
    /// `partial` so the next poll completes it instead of losing that record.
    ///
    /// When the window starts mid-file the first line is a fragment; parse_line
    /// rejects it, so no special case is needed. The run loop trims to
    /// `MAX_RECORDS` before the first frame.
    fn prime(&mut self) -> Vec<Rec> {
        let len = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        self.read_from(len.saturating_sub(STARTUP_TAIL_BYTES), len)
    }

    /// Read whatever has been appended since the last call. The `bool` is true
    /// if the file shrank (truncated or rotated), meaning the caller's
    /// aggregates are stale and must be rebuilt.
    fn poll(&mut self) -> (bool, Vec<Rec>) {
        let Ok(meta) = std::fs::metadata(&self.path) else {
            return (false, Vec::new());
        };
        let len = meta.len();
        if len < self.offset {
            self.offset = 0;
            self.partial.clear();
            let recs = self.read_from(0, len);
            return (true, recs);
        }
        if len == self.offset {
            return (false, Vec::new());
        }
        (false, self.read_from(self.offset, len))
    }

    fn read_from(&mut self, start: u64, len: u64) -> Vec<Rec> {
        let Ok(mut f) = std::fs::File::open(&self.path) else {
            return Vec::new();
        };
        if f.seek(SeekFrom::Start(start)).is_err() {
            return Vec::new();
        }
        let mut buf = vec![0u8; (len - start) as usize];
        let Ok(n) = f.read(&mut buf) else {
            return Vec::new();
        };
        self.offset = start + n as u64;
        // ponytail: lossy decode per chunk, not per line. Ceiling: a multi-byte
        // char straddling a read boundary becomes two U+FFFD instead of being
        // reassembled. Contained — U+FFFD is legal inside a JSON string, so the
        // record still parses and only excerpt glyphs are affected. Upgrade path:
        // make `partial` a Vec<u8> and decode each complete line.
        let text = String::from_utf8_lossy(&buf[..n]).into_owned();
        take_lines(&mut self.partial, &text)
            .iter()
            .filter_map(|l| parse_line(l))
            .collect()
    }
}

// ── aggregates ──────────────────────────────────────────────────────────────

struct Agg {
    total: usize,
    warn: usize,
    block: usize,
    stage2: usize,
    certain: usize,
    min: u8,
    median: u8,
    p95: u8,
    max: u8,
    rules: Vec<(String, usize)>,
    recent_scores: Vec<u8>,
}

/// Nearest-rank percentile over a sorted slice. No interpolation: these are
/// integer risk scores, and a made-up value between two real ones is noise.
fn pct(sorted: &[u8], p: f64) -> u8 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((p * sorted.len() as f64).ceil() as usize).max(1);
    sorted[(rank - 1).min(sorted.len() - 1)]
}

fn percent(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 * 100.0 / whole as f64
    }
}

fn aggregate(recs: &[Rec]) -> Agg {
    let mut scores: Vec<u8> = recs.iter().map(|r| r.score).collect();
    scores.sort_unstable();

    let mut counts: HashMap<&str, usize> = HashMap::new();
    for r in recs {
        for rule in &r.rules {
            *counts.entry(rule.as_str()).or_insert(0) += 1;
        }
    }
    let mut rules: Vec<(String, usize)> = counts
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    // Count desc, then id asc so the order is stable frame to frame.
    rules.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rules.truncate(6);

    Agg {
        total: recs.len(),
        warn: recs.iter().filter(|r| r.action == "warn").count(),
        block: recs.iter().filter(|r| r.action == "block").count(),
        stage2: recs.iter().filter(|r| r.stage2).count(),
        certain: recs.iter().filter(|r| r.confidence == "certain").count(),
        min: scores.first().copied().unwrap_or(0),
        median: pct(&scores, 0.5),
        p95: pct(&scores, 0.95),
        max: scores.last().copied().unwrap_or(0),
        rules,
        recent_scores: recs.iter().rev().take(40).rev().map(|r| r.score).collect(),
    }
}

const SPARKS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// Bucket a 0..=100 score into one of eight spark glyphs on a **fixed** scale.
/// Auto-scaling to the window's own min/max would make a flat run of 12s look
/// identical to a flat run of 95s, which is exactly the distinction that matters.
fn spark_idx(score: u8) -> usize {
    (score as usize * 8 / 101).min(7)
}

fn sparkline(scores: &[u8]) -> String {
    scores.iter().map(|s| SPARKS[spark_idx(*s)]).collect()
}

// ── ANSI-aware text helpers ─────────────────────────────────────────────────

/// Visible column count, ignoring SGR escape sequences.
fn vis_len(s: &str) -> usize {
    let mut n = 0;
    let mut esc = false;
    for c in s.chars() {
        if esc {
            if c.is_ascii_alphabetic() {
                esc = false;
            }
        } else if c == '\x1b' {
            esc = true;
        } else {
            n += 1;
        }
    }
    n
}

/// Truncate to `w` visible columns, keeping escape sequences intact.
///
/// A truncated string ends in `…` rather than stopping mid-word, so a clipped
/// rule id reads as `combo-forged-system…` instead of `combo-forged-system-tu`,
/// which looks like a rule that is actually named that.
fn clip(s: &str, w: usize) -> String {
    let truncating = vis_len(s) > w;
    // Reserve the last column for the ellipsis when one is coming.
    let budget = if truncating { w.saturating_sub(1) } else { w };
    let mut out = String::new();
    let mut n = 0;
    let mut esc = false;
    for c in s.chars() {
        if esc {
            out.push(c);
            if c.is_ascii_alphabetic() {
                esc = false;
            }
        } else if c == '\x1b' {
            out.push(c);
            esc = true;
        } else {
            if n == budget {
                break;
            }
            out.push(c);
            n += 1;
        }
    }
    if truncating && w > 0 {
        out.push('…');
    }
    out.push_str(RESET);
    out
}

fn pad(s: &str, w: usize) -> String {
    let l = vis_len(s);
    if l >= w {
        clip(s, w)
    } else {
        format!("{s}{}", " ".repeat(w - l))
    }
}

/// Reduce untrusted text to printable ASCII.
///
/// SECURITY: `excerpt` is a verbatim slice of content the Guardian was asked to
/// scan — i.e. attacker-controlled. Writing it to a terminal unfiltered lets an
/// injected `\x1b[` sequence repaint the dashboard, move the cursor, or (on some
/// emulators) drive a response back onto stdin. Everything from the log goes
/// through here before it reaches the screen.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if ('\x20'..='\x7e').contains(&c) {
                c
            } else {
                '·'
            }
        })
        .collect()
}

// ── box drawing ─────────────────────────────────────────────────────────────

/// A bordered panel with its label inset into the top border:
/// `┌─ VERDICTS ─────┐`.
fn boxed(label: &str, w: usize, body: &[String], body_h: usize) -> Vec<String> {
    let inner = w.saturating_sub(4);
    let mut out = Vec::with_capacity(body_h + 2);
    // A label longer than the border it sits in makes the top row wider than the
    // box and shears off the closing corner. Clip it here, once, for every panel.
    let label: String = label.chars().take(inner.saturating_sub(1)).collect();
    let fill = w.saturating_sub(5 + label.chars().count());
    out.push(format!(
        "{C_BORDER}┌─ {C_BRIGHT}{label}{C_BORDER} {}┐{RESET}",
        "─".repeat(fill)
    ));
    for i in 0..body_h {
        let line = body.get(i).map(String::as_str).unwrap_or("");
        out.push(format!(
            "{C_BORDER}│{RESET} {} {C_BORDER}│{RESET}",
            pad(line, inner)
        ));
    }
    out.push(format!(
        "{C_BORDER}└{}┘{RESET}",
        "─".repeat(w.saturating_sub(2))
    ));
    out
}

/// Join equal-height blocks side by side. Each block must already be padded to
/// its own width.
fn hjoin(blocks: &[Vec<String>], gap: usize) -> Vec<String> {
    let h = blocks.iter().map(Vec::len).max().unwrap_or(0);
    let sep = " ".repeat(gap);
    (0..h)
        .map(|i| {
            blocks
                .iter()
                .map(|b| b.get(i).cloned().unwrap_or_default())
                .collect::<Vec<_>>()
                .join(&sep)
        })
        .collect()
}

/// Split `total` columns into `n` cells separated by `gap`, remainder to the left.
fn split(total: usize, n: usize, gap: usize) -> Vec<usize> {
    let avail = total.saturating_sub(gap * (n - 1));
    let base = avail / n;
    let rem = avail % n;
    (0..n).map(|i| base + usize::from(i < rem)).collect()
}

// ── knight ──────────────────────────────────────────────────────────────────

/// Quadrant glyphs indexed by a 4-bit mask of the set cells in a 2x2 source
/// block: bit 3 top-left, 2 top-right, 1 bottom-left, 0 bottom-right.
const QUADRANTS: [char; 16] = [
    ' ', '▗', '▖', '▄', '▝', '▐', '▞', '▟', '▘', '▚', '▌', '▙', '▀', '▜', '▛', '█',
];

/// Render the knight at half scale: each 2x2 block of source cells collapses to
/// one quadrant glyph, so 36x27 becomes 18x14 with the aspect ratio intact.
///
/// This is a silhouette, not the original drawing. The source is *line* art —
/// the `]U[` and `.Y;` glyphs are the strokes — and any downsample trades those
/// strokes for solid blocks. At 2:1 the plume, pauldrons and legs still read;
/// that is the ceiling. ponytail: if it ever needs to be smaller than this it
/// wants a hand-drawn mark, not a finer resampler.
fn knight_rows() -> Vec<String> {
    let art: Vec<Vec<char>> = KNIGHT_ART.lines().map(|l| l.chars().collect()).collect();
    let col: Vec<Vec<char>> = KNIGHT_COLORS.lines().map(|l| l.chars().collect()).collect();
    let width = art.iter().map(|l| l.len()).max().unwrap_or(0);

    // A set cell yields its palette index; whitespace and out-of-bounds yield None.
    let cell = |y: usize, x: usize| -> Option<usize> {
        match art.get(y).and_then(|l| l.get(x)) {
            Some(&c) if c != ' ' => Some(
                col.get(y)
                    .and_then(|l| l.get(x))
                    .and_then(|c| c.to_digit(10))
                    .unwrap_or(0) as usize,
            ),
            _ => None,
        }
    };

    let mut rows = Vec::with_capacity(art.len().div_ceil(2));
    for y in (0..art.len()).step_by(2) {
        let mut line = String::new();
        let mut pen: Option<(u8, u8, u8)> = None;
        for x in (0..width).step_by(2) {
            let quad = [
                cell(y, x),
                cell(y, x + 1),
                cell(y + 1, x),
                cell(y + 1, x + 1),
            ];
            let mut mask = 0usize;
            for (i, c) in quad.iter().enumerate() {
                if c.is_some() {
                    mask |= 8 >> i;
                }
            }
            if mask == 0 {
                // Close the run rather than paint color under whitespace.
                if pen.take().is_some() {
                    line.push_str(RESET);
                }
                line.push(' ');
                continue;
            }
            // First set cell in reading order wins the block's color. Averaging
            // four palette entries lands between them and muddies the figure.
            let idx = quad.iter().flatten().next().copied().unwrap_or(0);
            let rgb = KNIGHT_PALETTE[idx.min(3)];
            // Only re-emit SGR when the color actually changes — adjacent glyphs
            // usually share one.
            if pen != Some(rgb) {
                line.push_str(&format!("\x1b[38;2;{};{};{}m", rgb.0, rgb.1, rgb.2));
                pen = Some(rgb);
            }
            line.push(QUADRANTS[mask]);
        }
        if pen.is_some() {
            line.push_str(RESET);
        }
        rows.push(line);
    }
    rows
}

// ── terminal ────────────────────────────────────────────────────────────────

fn stty_capture(args: &[&str]) -> Option<String> {
    let out = Command::new("stty")
        .args(args)
        .stdin(Stdio::inherit())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Owns every terminal mutation the console makes, holding the exact `stty -g`
/// state captured before raw mode. `Drop` runs on normal return *and* on panic
/// unwind, so a bug in the render path cannot leave the user with an invisible
/// cursor in raw mode on the alt screen.
///
/// ponytail: `Drop` does not cover asynchronous termination. Ceiling: SIGTERM or
/// SIGHUP kills the process with raw mode still set and the alt screen active,
/// and the user has to blind-type `stty sane`. Ctrl-C is fine (raw mode clears
/// ISIG, so it arrives as byte 0x03 and quits through the normal path). Upgrade
/// path: a `sigaction` handler, which means libc — a new dependency on a binary
/// that deliberately has almost none, for a case the operator can recover from.
struct Term(String);

impl Term {
    /// `None` if stdin is not a terminal — `stty -g` is the tty test, and it is
    /// free because we need the saved state anyway.
    fn enter() -> Option<Term> {
        let saved = stty_capture(&["-g"])?;
        // `stty raw` clears ISIG, so Ctrl-C no longer raises SIGINT — it arrives
        // as byte 0x03 on stdin and is handled in the input loop. Restoring the
        // saved state in Drop puts ISIG back.
        let _ = stty_capture(&["raw", "-echo"]);
        let mut out = std::io::stdout();
        let _ = out.write_all(b"\x1b[?1049h\x1b[?25l");
        let _ = out.flush();
        Some(Term(saved))
    }
}

impl Drop for Term {
    fn drop(&mut self) {
        let mut out = std::io::stdout();
        let _ = out.write_all(b"\x1b[?25h\x1b[?1049l\x1b[0m");
        let _ = out.flush();
        let _ = stty_capture(&[self.0.as_str()]);
    }
}

fn term_size() -> (usize, usize) {
    let parsed = stty_capture(&["size"]).and_then(|s| {
        let mut it = s.split_whitespace();
        let r: usize = it.next()?.parse().ok()?;
        let c: usize = it.next()?.parse().ok()?;
        (r > 0 && c > 0).then_some((r, c))
    });
    parsed.unwrap_or((24, 80))
}

// ── formatting bits ─────────────────────────────────────────────────────────

/// `HH:MM:SS` from a second count — event wall-clock and session uptime alike.
fn clock(secs: u64) -> String {
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Truncate a path from the *left*. The interesting part of an audit path is
/// the filename, not `/home/…`.
fn tail_path(s: &str, w: usize) -> String {
    let n = s.chars().count();
    if n <= w || w == 0 {
        return s.to_string();
    }
    format!("…{}", s.chars().skip(n - (w - 1)).collect::<String>())
}

/// SECURITY: `sha256` is a log field like any other. `audit.rs` only ever writes
/// hex, but a tampered or corrupted log is exactly what this dashboard would be
/// used to look at, so it gets the same treatment as `excerpt`: sanitized before
/// display, and sliced by *chars* — byte slicing arbitrary UTF-8 panics on a
/// non-ASCII boundary, and one bad line must not kill the operator's live view.
fn short_sha(sha: &str) -> String {
    let s = sanitize(sha);
    let n = s.chars().count();
    if n < 8 {
        return "sha —".to_string();
    }
    let head: String = s.chars().take(4).collect();
    let tail: String = s.chars().skip(n - 4).collect();
    format!("sha {head}…{tail}")
}

/// A proportional two-segment bar. Non-zero segments always claim at least one
/// cell so "one block in ten thousand warns" is still visible.
fn stacked_bar(w: usize, warn: usize, block: usize) -> String {
    let total = warn + block;
    if total == 0 || w == 0 {
        return format!("{C_DIMMER}{}{RESET}", "░".repeat(w));
    }
    let mut wc = warn * w / total;
    if warn > 0 && wc == 0 {
        wc = 1;
    }
    if block > 0 && wc == w {
        wc = w - 1;
    }
    format!(
        "{C_WARN}{}{C_BLOCK}{}{RESET}",
        "█".repeat(wc),
        "█".repeat(w - wc)
    )
}

/// Rules from the instruction-override, combination and exfiltration families
/// are the ones that mean an actual attack rather than a stylistic smell, so
/// they get the hotter bar.
fn rule_is_hot(id: &str) -> bool {
    id.starts_with("instr") || id.starts_with("combo") || id.starts_with("exfil")
}

// ── events view ─────────────────────────────────────────────────────────────

const SORT_NAMES: [&str; 4] = ["time", "score", "source", "action"];

/// Interactive state of the events table: substring filter, sort column and
/// cursor. Lives outside the frame so it survives redraws.
#[derive(Default)]
struct View {
    filter: String,
    /// True while `/` filter input is being typed in the footer.
    typing: bool,
    /// Index into `SORT_NAMES`; 0 = time = raw log order.
    sort: usize,
    /// Selected record, counted from the bottom of the display order (0 = last).
    /// ponytail: bottom-anchored, so a live append shifts the selection by one
    /// record — press `p` while inspecting. Upgrade path: anchor to (ts, sha).
    sel: usize,
    /// Bottom-most visible record, same coordinates as `sel`.
    scroll: usize,
}

/// Records visible under the current filter and sort, in display order — the
/// last element renders at the bottom of the panel. Sorts are stable, so ties
/// keep their log order.
fn view_rows<'a>(recs: &'a [Rec], v: &View) -> Vec<&'a Rec> {
    let f = v.filter.to_lowercase();
    let mut rows: Vec<&Rec> = recs
        .iter()
        .filter(|r| {
            f.is_empty()
                || r.source.to_lowercase().contains(&f)
                || r.action.contains(&f)
                || r.confidence.contains(&f)
                || r.rules.iter().any(|id| id.to_lowercase().contains(&f))
                || r.excerpt
                    .as_deref()
                    .is_some_and(|e| e.to_lowercase().contains(&f))
                || r.sha256.starts_with(&f)
        })
        .collect();
    match v.sort {
        // Ascending: the highest score / last name lands at the bottom, which is
        // where the bottom-aligned panel puts the eye.
        1 => rows.sort_by_key(|r| r.score),
        2 => rows.sort_by(|a, b| a.source.cmp(&b.source)),
        3 => rows.sort_by(|a, b| a.action.cmp(&b.action)),
        _ => {}
    }
    rows
}

// ── panels ──────────────────────────────────────────────────────────────────

fn panel_verdicts(w: usize, a: &Agg) -> Vec<String> {
    let inner = w.saturating_sub(4);
    // `total` is what is held in memory, which is capped. Once the cap is hit the
    // count stops rising and every percentage below describes the window, not the
    // log — say so rather than let "logged N" read as a lifetime total. The
    // qualifier leads so it is the last thing clipped on a narrow terminal.
    let scope = if a.total >= MAX_RECORDS {
        "non-pass · last 5k"
    } else {
        "non-pass"
    };
    let body = vec![
        format!("{C_DIM}{scope}{RESET}  {C_BRIGHT}{}{RESET}", a.total),
        format!(
            "{C_WARN}warn{RESET}  {C_BRIGHT}{:<4}{RESET}{C_DIM}{:.1}%{RESET}",
            a.warn,
            percent(a.warn, a.total)
        ),
        format!(
            "{C_BLOCK}block{RESET} {C_BRIGHT}{:<4}{RESET}{C_DIM}{:.1}%{RESET}",
            a.block,
            percent(a.block, a.total)
        ),
        stacked_bar(inner, a.warn, a.block),
    ];
    boxed("VERDICTS", w, &body, 4)
}

fn panel_pipeline(w: usize, a: &Agg) -> Vec<String> {
    let s1 = a.total.saturating_sub(a.stage2);
    let amb = a.total.saturating_sub(a.certain);
    let body = vec![
        format!(
            "{C_DIM}stage-2{RESET}  {C_BRIGHT}{:<6}{RESET}{C_DIM}{:.1}%{RESET}",
            a.stage2,
            percent(a.stage2, a.total)
        ),
        format!(
            "{C_DIM}stage-1{RESET}  {C_BRIGHT}{:<6}{RESET}{C_DIM}{:.1}%{RESET}",
            s1,
            percent(s1, a.total)
        ),
        String::new(),
        format!(
            "{C_DIM}certain{RESET} {C_BRIGHT}{}{RESET}  {C_DIM}ambiguous{RESET} {C_BRIGHT}{}{RESET}",
            a.certain, amb
        ),
    ];
    boxed("PIPELINE", w, &body, 4)
}

fn panel_scores(w: usize, a: &Agg) -> Vec<String> {
    let spark = sparkline(&a.recent_scores);
    let body = vec![
        format!(
            "{C_DIM}min{RESET} {C_BRIGHT}{:<5}{RESET}{C_DIM}median{RESET} {C_BRIGHT}{}{RESET}",
            a.min, a.median
        ),
        format!(
            "{C_DIM}p95{RESET} {C_BRIGHT}{:<5}{RESET}{C_DIM}max{RESET}    {C_BRIGHT}{}{RESET}",
            a.p95, a.max
        ),
        String::new(),
        // `boxed` pads/clips every body line to the panel's inner width already.
        format!("{C_RED}{spark}{RESET}"),
    ];
    boxed("SCORES", w, &body, 4)
}

fn panel_config(w: usize, cfg: &Config) -> Vec<String> {
    let onoff = |b: bool| {
        if b {
            format!("{C_PASS}on{RESET}")
        } else {
            format!("{C_DIM}off{RESET}")
        }
    };
    let kv = |k: &str, v: String| format!("{C_DIM}{k:<20}{RESET}{C_TEXT}{v}{RESET}");
    let body = vec![
        kv("block_threshold", cfg.block_threshold.to_string()),
        kv("escalate_threshold", cfg.escalate_threshold.to_string()),
        kv("max_scan_bytes", cfg.max_scan_bytes.to_string()),
        kv("audit_excerpt", onoff(cfg.audit_excerpt)),
        kv("stage2", onoff(cfg.stage2.enabled)),
        // The fail mode is a property of the adapter, not config: `scan`/`serve`
        // fail closed, `hook` degrades to stage 1. Stating both is the truth;
        // showing a single value would imply a knob that does not exist.
        kv(
            "fail mode",
            format!("{C_TEXT}closed{RESET} {C_DIM}(hook: degrade-s1){RESET}"),
        ),
    ];
    boxed("CONFIG", w, &body, 6)
}

fn panel_rules(w: usize, a: &Agg) -> Vec<String> {
    let inner = w.saturating_sub(4);
    let max = a.rules.first().map(|r| r.1).unwrap_or(1).max(1);
    let bar_w = inner.saturating_sub(30);
    let mut body: Vec<String> = a
        .rules
        .iter()
        .map(|(id, n)| {
            let cells = (n * bar_w / max).max(usize::from(*n > 0));
            let color = if rule_is_hot(id) {
                C_BAR_HOT
            } else {
                C_BAR_COOL
            };
            // `pad`, not `{:<22}`: the string carries SGR escapes and the format
            // width counts them as columns, which shifts every row differently.
            format!(
                "{C_TEXT}{}{RESET}{C_BRIGHT}{:>5} {RESET}{color}{}{RESET}",
                pad(&sanitize(id), 22),
                n,
                "▮".repeat(cells)
            )
        })
        .collect();
    if body.is_empty() {
        body.push(format!("{C_DIM}no rules fired yet{RESET}"));
    }
    boxed("TOP RULES · NON-PASS VERDICTS", w, &body, 6)
}

fn panel_events(
    w: usize,
    h: usize,
    total: usize,
    rows: &[&Rec],
    v: &mut View,
    waiting: Option<&Path>,
) -> Vec<String> {
    let inner = w.saturating_sub(4);
    // time(8) src(14) detail(flex) ACTION(5) score(3) s2(2), single-space gaps.
    let fixed = 8 + 1 + 14 + 1 + 1 + 5 + 1 + 3 + 1 + 2;
    let detail_w = inner.saturating_sub(fixed);

    // Clamp the cursor to what the filter left visible, then walk the window up
    // until the selected record fits: records are 1 or 2 lines tall, so "fits"
    // is a height sum, not an index difference.
    let n = rows.len();
    if n == 0 {
        (v.sel, v.scroll) = (0, 0);
    } else {
        v.sel = v.sel.min(n - 1);
        v.scroll = v.scroll.min(v.sel);
        let height = |i: usize| 1 + usize::from(!rows[n - 1 - i].rules.is_empty());
        while v.scroll < v.sel && (v.scroll..=v.sel).map(height).sum::<usize>() > h {
            v.scroll += 1;
        }
    }

    let mut lines: Vec<String> = Vec::new();
    for (i, r) in rows.iter().rev().enumerate().skip(v.scroll) {
        if lines.len() >= h {
            break;
        }
        // Built newest-first (reversed at the end), so the reasons line is
        // emitted before the event it belongs to.
        let mut pair: Vec<String> = Vec::with_capacity(2);
        if !r.rules.is_empty() {
            let joined = sanitize(&r.rules.join(", "));
            pair.push(format!(
                "{C_DIMMER}└ {C_BAR_COOL}{}{RESET}",
                clip(&joined, inner.saturating_sub(2))
            ));
        }
        // Never fabricate content: with `audit_excerpt` off (the default) the
        // log holds only a hash, so that is what gets shown.
        let detail = match &r.excerpt {
            Some(e) => sanitize(e),
            None => short_sha(&r.sha256),
        };
        let (ac, act) = if r.action == "block" {
            (C_BLOCK, "BLOCK")
        } else {
            (C_WARN, " WARN")
        };
        let s2 = if r.stage2 {
            format!("{C_RED}S2{RESET}")
        } else {
            format!("{C_DIMMER}··{RESET}")
        };
        pair.push(format!(
            "{C_DIM}{}{RESET} {C_TEXT}{}{RESET} {} {ac}{act}{RESET} {C_BRIGHT}{:>3}{RESET} {s2}",
            // ponytail: UTC, not local time — local time needs the tz database,
            // i.e. chrono or libc, i.e. a new dependency on a binary that
            // deliberately has almost none. Upgrade path: honour a fixed $TZ.
            clock(r.ts % 86_400),
            pad(&sanitize(&r.source), 14),
            // `pad` clips when the string is too wide; no second clip needed.
            pad(&format!("{C_DIM}{detail}{RESET}"), detail_w),
            r.score
        ));
        if i == v.sel {
            // Re-arm inverse after every SGR reset the line already carries, so
            // the highlight survives the per-field color changes.
            for l in pair.iter_mut() {
                *l = format!("\x1b[7m{}\x1b[27m", l.replace(RESET, "\x1b[0;7m"));
            }
        }
        // With only one row left, drop the reasons line rather than render it
        // orphaned above an event that got cut.
        let room = h - lines.len();
        if pair.len() > room {
            pair.drain(..pair.len() - room);
        }
        lines.extend(pair);
    }
    lines.reverse();

    if lines.is_empty() {
        lines.push(match (v.filter.is_empty(), waiting) {
            (false, _) => format!("{C_DIM}no events match \"{}\"{RESET}", sanitize(&v.filter)),
            (true, Some(p)) => format!(
                "{C_DIM}waiting for {}{RESET}",
                sanitize(&p.to_string_lossy())
            ),
            (true, None) => format!("{C_DIM}no non-pass verdicts logged yet{RESET}"),
        });
    }
    // Bottom-align: newest event sits on the last row of the panel.
    while lines.len() < h {
        lines.insert(0, String::new());
    }

    let mut label = String::from("EVENTS · LIVE");
    if v.sort != 0 {
        label.push_str(&format!(" · SORT {}", SORT_NAMES[v.sort].to_uppercase()));
    }
    if !v.filter.is_empty() {
        label.push_str(&format!(" · {n}/{total} \"{}\"", sanitize(&v.filter)));
    }
    boxed(&label, w, &lines, h)
}

// ── header ──────────────────────────────────────────────────────────────────

fn meta_block(w: usize, cfg: &Config, uptime: Duration) -> Vec<String> {
    let kv = |k: &str, v: String| pad(&format!("{C_DIM}{k:<9}{RESET}{C_TEXT}{v}{RESET}"), w);
    let path = cfg.audit_path();
    let path = path.to_string_lossy();
    vec![
        kv("version", env!("CARGO_PKG_VERSION").to_string()),
        // verify_prompt() aborts the process on mismatch before any subcommand
        // runs, so reaching this line proves the pinned hash matched.
        kv(
            "guard",
            format!(
                "{C_PASS}verified{RESET} {C_DIM}{}{RESET}",
                &GUARDIAN_PROMPT_SHA256[..12]
            ),
        ),
        kv("audit", tail_path(&sanitize(&path), w.saturating_sub(9))),
        kv(
            "stage-2",
            format!(
                "{} {C_DIM}{}{RESET}",
                sanitize(&cfg.stage2.model),
                if cfg.stage2.enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            ),
        ),
        kv(
            "thresh",
            format!(
                "block {} · escalate {}",
                cfg.block_threshold, cfg.escalate_threshold
            ),
        ),
        kv("uptime", clock(uptime.as_secs())),
    ]
}

fn vcenter(mut lines: Vec<String>, h: usize, w: usize) -> Vec<String> {
    for l in lines.iter_mut() {
        *l = pad(l, w);
    }
    while lines.len() < h {
        if lines.len().is_multiple_of(2) {
            lines.insert(0, " ".repeat(w));
        } else {
            lines.push(" ".repeat(w));
        }
    }
    lines.truncate(h);
    lines
}

fn header(w: usize, rows: usize, cfg: &Config, uptime: Duration) -> Vec<String> {
    // One if-statement, not a layout engine: the knight only appears when there
    // is unambiguously room for it.
    let show_knight = rows >= KNIGHT_MIN_ROWS && w >= 107;
    let knight = if show_knight {
        knight_rows()
    } else {
        Vec::new()
    };
    let kw = if show_knight { 14 } else { 0 };
    // Without the knight the header is exactly the centre block: 4 banner rows,
    // a blank, the wordmark and the tagline. Anything less truncates the tagline
    // off the bottom, which is header content the design has unconditionally.
    let h = if show_knight { knight.len() } else { 7 };

    let meta_w = 46.min(w / 3);
    let center_w = w.saturating_sub(kw + meta_w + if show_knight { 4 } else { 2 });

    let mut center: Vec<String> = BANNER
        .lines()
        .map(|l| format!("{C_RED}{l}{RESET}"))
        .collect();
    center.push(String::new());
    center.push(format!("{C_BRIGHT}G U A R D I A N{RESET}"));
    center.push(format!(
        "{C_DIM}prompt-injection firewall · verdict-only · pass or block{RESET}"
    ));

    let mut blocks = Vec::new();
    if show_knight {
        blocks.push(knight);
    }
    blocks.push(vcenter(center, h, center_w));
    blocks.push(vcenter(meta_block(meta_w, cfg, uptime), h, meta_w));
    hjoin(&blocks, 2)
}

// ── frame ───────────────────────────────────────────────────────────────────

/// Fixed chrome above the events panel: header 7, blank, stat row 6, blank,
/// config/rules 8, blank. Plus the events box (2 border rows + at least 1) and
/// the footer, that is the smallest terminal this layout actually fits in — and
/// the guard has to say so, because `ev_h.max(1)` builds an oversize frame that
/// `truncate` then silently shears the events panel and the quit hint off of.
const MIN_ROWS: usize = 28;
const MIN_COLS: usize = 60;

fn frame(
    rows: usize,
    cols: usize,
    cfg: &Config,
    recs: &[Rec],
    uptime: Duration,
    paused: bool,
    view: &mut View,
) -> String {
    let w = cols.min(160);
    if cols < MIN_COLS || rows < MIN_ROWS {
        return format!(
            "\x1b[H\x1b[2J{C_DIM}igris console needs at least {MIN_COLS}x{MIN_ROWS}{RESET}\r\n"
        );
    }

    let a = aggregate(recs);
    let mut out: Vec<String> = Vec::with_capacity(rows);

    out.extend(header(w, rows, cfg, uptime));
    out.push(String::new());

    let c3 = split(w, 3, 1);
    out.extend(hjoin(
        &[
            panel_verdicts(c3[0], &a),
            panel_pipeline(c3[1], &a),
            panel_scores(c3[2], &a),
        ],
        1,
    ));
    out.push(String::new());

    let c2 = split(w, 2, 1);
    out.extend(hjoin(
        &[panel_config(c2[0], cfg), panel_rules(c2[1], &a)],
        1,
    ));
    out.push(String::new());

    // Events take whatever is left, minus its own border and the footer.
    let ev_h = rows.saturating_sub(out.len() + 3).max(1);
    let log = cfg.audit_path();
    let missing = !log.exists();
    let vrows = view_rows(recs, view);
    out.extend(panel_events(
        w,
        ev_h,
        recs.len(),
        &vrows,
        view,
        missing.then_some(log.as_path()),
    ));

    // A monitor that cannot distinguish "quiet" from "blind" is the wrong
    // failure mode: once any record has been read the waiting note is gone, so
    // a log that is deleted or rotated away has to show up in the indicator.
    let (dot, label, color) = if paused {
        ("●", "PAUSED", C_WARN)
    } else if missing {
        ("●", "NO LOG", C_BLOCK)
    } else if (uptime.as_millis() / 500).is_multiple_of(2) {
        ("●", "LIVE", C_PASS)
    } else {
        ("○", "LIVE", C_PASS)
    };
    let left = if view.typing {
        format!(
            "{C_DIM}filter{RESET} {C_BRIGHT}{}▏{RESET}  {C_DIM}enter{RESET} keep  {C_DIM}esc{RESET} clear",
            sanitize(&view.filter)
        )
    } else {
        format!(
            "{C_DIM}q{RESET} quit  {C_DIM}p{RESET} pause  {C_DIM}/{RESET} filter  {C_DIM}s{RESET} sort·{}  {C_DIM}↑↓{RESET} nav",
            SORT_NAMES[view.sort]
        )
    };
    let right = format!("{color}{dot} {label}{RESET}");
    let gap = w.saturating_sub(vis_len(&left) + vis_len(&right));
    out.push(format!("{left}{}{right}", " ".repeat(gap)));

    out.truncate(rows);
    // -opost is set by `stty raw`, so newlines do not get a carriage return for
    // free: every line must end \r\n or the frame walks off to the right. The
    // separator goes *between* lines, never after the last one — a newline on
    // the bottom row scrolls the whole frame up by one.
    let body: Vec<String> = out.iter().map(|l| clip(l, w)).collect();
    format!("\x1b[H\x1b[2J{}", body.join("\r\n"))
}

// ── run loop ────────────────────────────────────────────────────────────────

/// Spawn a thread that pumps stdin bytes into a channel. Blocking reads on a
/// dedicated thread beat any amount of nonblocking-fd cleverness, and cost one
/// thread that dies with the process.
fn input_thread() -> Receiver<u8> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = [0u8; 64];
        let stdin = std::io::stdin();
        loop {
            let n = match stdin.lock().read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            for b in &buf[..n] {
                if tx.send(*b).is_err() {
                    return;
                }
            }
        }
    });
    rx
}

/// Entry point for `igris console`. Returns a process exit code.
pub fn run(cfg: Config) -> i32 {
    let Some(_term) = Term::enter() else {
        eprintln!("igris: console needs a terminal on stdin (not a pipe or CI job)");
        return 64;
    };

    let mut tail = Tail::new(cfg.audit_path());
    let mut recs = tail.prime();
    let rx = input_thread();
    let start = Instant::now();
    let mut paused = false;
    let mut view = View::default();

    loop {
        loop {
            let b = match rx.try_recv() {
                Ok(b) => b,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return 0,
            };
            if view.typing {
                match b {
                    0x03 => return 0,
                    b'\r' | b'\n' => view.typing = false,
                    0x1b => {
                        view.typing = false;
                        view.filter.clear();
                    }
                    0x7f | 0x08 => {
                        view.filter.pop();
                    }
                    0x20..=0x7e => view.filter.push(b as char),
                    _ => {}
                }
                continue;
            }
            match b {
                // 0x03 is Ctrl-C: `stty raw` cleared ISIG, so it arrives as a
                // byte instead of a signal and we must quit on it ourselves.
                b'q' | b'Q' | 0x03 | 0x04 => return 0,
                b'p' | b'P' => paused = !paused,
                b'/' => view.typing = true,
                b's' | b'S' => {
                    view.sort = (view.sort + 1) % SORT_NAMES.len();
                    (view.sel, view.scroll) = (0, 0);
                }
                b'k' | b'K' => view.sel += 1,
                b'j' | b'J' => view.sel = view.sel.saturating_sub(1),
                // ponytail: arrow keys are 3 bytes; the input thread reads up to
                // 64 at once, so both trailing bytes are almost always already
                // in the channel. If one straddles a read, the key is dropped
                // for a frame — j/k always work.
                0x1b => match (rx.try_recv(), rx.try_recv()) {
                    (Ok(b'['), Ok(b'A')) => view.sel += 1,
                    (Ok(b'['), Ok(b'B')) => view.sel = view.sel.saturating_sub(1),
                    (Ok(b'['), Ok(_)) => {}
                    _ => view.filter.clear(),
                },
                _ => {}
            }
        }

        if !paused {
            let (reset, fresh) = tail.poll();
            if reset {
                recs.clear();
            }
            recs.extend(fresh);
            if recs.len() > MAX_RECORDS {
                recs.drain(..recs.len() - MAX_RECORDS);
            }
        }

        let (rows, cols) = term_size();
        let text = frame(rows, cols, &cfg, &recs, start.elapsed(), paused, &mut view);
        // One write per frame: partial frames are what tearing looks like.
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(text.as_bytes());
        let _ = out.flush();
        drop(out);

        std::thread::sleep(TICK);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"{"ts":1700000000,"source":"scan","action":"block","score":92,"confidence":"certain","rules":["instr.override","exfil.url"],"stage2":true,"sha256":"4c9f0011223344556677889900aabbccddeeff00112233445566778899aabbe2d1"}"#;

    #[test]
    fn parses_a_record_without_an_excerpt() {
        let r = parse_line(GOOD).expect("valid record");
        assert_eq!(r.ts, 1_700_000_000);
        assert_eq!(r.action, "block");
        assert_eq!(r.score, 92);
        assert!(r.stage2);
        assert_eq!(r.rules.len(), 2);
        assert_eq!(r.excerpt, None);
    }

    #[test]
    fn parses_an_excerpt_when_present() {
        let line = r#"{"ts":1,"source":"hook","action":"warn","score":50,"confidence":"ambiguous","rules":[],"stage2":false,"sha256":"aa","excerpt":"hello"}"#;
        assert_eq!(parse_line(line).unwrap().excerpt.as_deref(), Some("hello"));
    }

    #[test]
    fn malformed_and_pass_lines_are_skipped_not_panicked_on() {
        // Torn line from a concurrent append, junk, blank, and a verdict the
        // audit log never actually writes.
        assert!(parse_line(&GOOD[..40]).is_none());
        assert!(parse_line("not json at all").is_none());
        assert!(parse_line("").is_none());
        assert!(parse_line(r#"{"action":"pass","score":0}"#).is_none());
        assert!(parse_line(r#"{"score":5}"#).is_none());
        assert!(parse_line("[1,2,3]").is_none());
    }

    #[test]
    fn partial_trailing_line_survives_two_reads() {
        let mut partial = String::new();
        // First read ends mid-record.
        let first = take_lines(&mut partial, "{\"a\":1}\n{\"b\":2}\n{\"c\":");
        assert_eq!(first, vec!["{\"a\":1}", "{\"b\":2}"]);
        assert_eq!(partial, "{\"c\":");
        // Second read completes it and starts another fragment.
        let second = take_lines(&mut partial, "3}\n{\"d\"");
        assert_eq!(second, vec!["{\"c\":3}"]);
        assert_eq!(partial, "{\"d\"");
    }

    fn rec(action: &str, score: u8, stage2: bool, conf: &str, rules: &[&str]) -> Rec {
        Rec {
            ts: 0,
            source: "t".into(),
            action: action.into(),
            score,
            confidence: conf.into(),
            rules: rules.iter().map(|s| s.to_string()).collect(),
            stage2,
            sha256: String::new(),
            excerpt: None,
        }
    }

    #[test]
    fn aggregate_counts_and_percentages() {
        let recs = vec![
            rec("warn", 10, false, "ambiguous", &["a"]),
            rec("warn", 20, false, "ambiguous", &["a"]),
            rec("block", 90, true, "certain", &["a", "b"]),
            rec("block", 100, true, "certain", &[]),
        ];
        let a = aggregate(&recs);
        assert_eq!((a.total, a.warn, a.block), (4, 2, 2));
        assert_eq!((a.stage2, a.certain), (2, 2));
        assert_eq!(percent(a.warn, a.total), 50.0);
        assert_eq!(percent(0, 0), 0.0, "empty log must not divide by zero");
        assert_eq!(a.rules[0], ("a".to_string(), 3));
        assert_eq!(a.rules[1], ("b".to_string(), 1));
    }

    #[test]
    fn score_percentiles_use_nearest_rank() {
        let recs: Vec<Rec> = [10u8, 20, 30, 40, 50, 60, 70, 80, 90, 100]
            .iter()
            .map(|s| rec("warn", *s, false, "ambiguous", &[]))
            .collect();
        let a = aggregate(&recs);
        assert_eq!((a.min, a.max), (10, 100));
        assert_eq!(a.median, 50); // rank ceil(0.5*10) = 5 -> sorted[4]
        assert_eq!(a.p95, 100); // rank ceil(0.95*10) = 10 -> sorted[9]

        let empty = aggregate(&[]);
        assert_eq!(
            (empty.min, empty.median, empty.p95, empty.max),
            (0, 0, 0, 0)
        );
    }

    #[test]
    fn sparkline_buckets_on_a_fixed_zero_to_hundred_scale() {
        assert_eq!(spark_idx(0), 0);
        assert_eq!(spark_idx(100), 7);
        assert!(spark_idx(50) > spark_idx(10));
        assert_eq!(sparkline(&[0, 100]), "▁█");
        assert_eq!(sparkline(&[]), "");
    }

    #[test]
    fn sanitize_strips_escape_sequences_from_untrusted_excerpts() {
        // An excerpt is attacker-controlled; a live escape here would repaint
        // the dashboard.
        let evil = "ok\x1b[2Jgone\n";
        let clean = sanitize(evil);
        assert!(!clean.contains('\x1b'));
        assert_eq!(clean, "ok·[2Jgone·");
    }

    #[test]
    fn short_sha_survives_a_hostile_sha_field() {
        // Non-ASCII: byte slicing this panics on a char boundary, and one bad
        // line must not take the dashboard down.
        assert_eq!(short_sha("日本語テストです"), "sha ····…····");
        // Live escapes: `clip` deliberately preserves SGR, so an unsanitized sha
        // would put attacker bytes (incl. a DSR that writes to our own stdin)
        // straight into the frame.
        let evil = short_sha("\x1b[2Jabcdefgh\x1b[6n");
        assert!(!evil.contains('\x1b'));
        // Short and empty are the "no usable hash" path, not a slice.
        assert_eq!(short_sha("aa"), "sha —");
        assert_eq!(short_sha(""), "sha —");
        assert_eq!(short_sha("4c9f00112233e2d1"), "sha 4c9f…e2d1");
    }

    #[test]
    fn view_rows_filters_case_insensitively_and_sorts() {
        let recs = vec![
            rec("warn", 30, false, "ambiguous", &["zeta.rule"]),
            rec("block", 90, true, "certain", &["instr.override"]),
            rec("warn", 10, false, "ambiguous", &[]),
        ];
        let f = View {
            filter: "Instr".into(),
            ..Default::default()
        };
        let hit = view_rows(&recs, &f);
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].score, 90);

        let by_score = View {
            sort: 1,
            ..Default::default()
        };
        let s: Vec<u8> = view_rows(&recs, &by_score)
            .iter()
            .map(|r| r.score)
            .collect();
        assert_eq!(s, vec![10, 30, 90]);

        let by_action = View {
            sort: 3,
            ..Default::default()
        };
        let a: Vec<&str> = view_rows(&recs, &by_action)
            .iter()
            .map(|r| r.action.as_str())
            .collect();
        assert_eq!(a, vec!["block", "warn", "warn"]);
    }

    #[test]
    fn selection_clamps_and_scrolls_into_view() {
        let recs: Vec<Rec> = (0..10u8)
            .map(|i| rec("warn", i, false, "ambiguous", &["r"]))
            .collect();
        let rows: Vec<&Rec> = recs.iter().collect();
        let mut v = View {
            sel: 99,
            ..Default::default()
        };
        let out = panel_events(60, 4, 10, &rows, &mut v, None);
        assert_eq!(v.sel, 9, "cursor clamps to the visible set");
        // 2-line records in a 4-row body: the window holds exactly two records,
        // ending at the one below the cursor.
        assert_eq!(v.scroll, 8);
        assert_eq!(out.len(), 6, "body plus two border rows");
    }

    #[test]
    fn panel_label_never_outruns_a_narrow_box() {
        // The widest label in the dashboard, in the narrowest half-panel the
        // min-width guard allows. Every row of the box must be the same width.
        let b = boxed("TOP RULES · NON-PASS VERDICTS", 29, &[], 1);
        let widths: Vec<usize> = b.iter().map(|l| vis_len(l)).collect();
        assert_eq!(widths, vec![29, 29, 29]);
        assert!(b[0].contains('┐'), "top border must still close");
    }

    #[test]
    fn vis_len_and_clip_ignore_color_codes() {
        let s = format!("{C_RED}abcdef{RESET}");
        assert_eq!(vis_len(&s), 6);
        assert_eq!(vis_len(&clip(&s, 3)), 3);
        assert_eq!(vis_len(&pad("ab", 5)), 5);
    }
}

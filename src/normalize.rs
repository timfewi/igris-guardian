//! Unicode normalization + smuggling detection + decode-and-rescan. PHASE-1A.
//!
//! Contract: `analyze` returns NFKC-normalized text plus scored findings for
//! invisible/bidi/tag-block characters (detected BEFORE any stripping).
//! `decode_variants` yields one-level-deep decoded forms (base64/rot13/leetspeak)
//! for the engine to rescan.

use crate::rules::Tier;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use unicode_normalization::UnicodeNormalization;

/// A unicode smuggling finding, expressed as a rule id + weight + tier so the
/// engine folds it into the same scoring as static rules.
pub struct Finding {
    pub id: &'static str,
    pub weight: u8,
    pub tier: crate::rules::Tier,
}

/// Returns `(nfkc_text, findings)`.
pub fn analyze(text: &str) -> (String, Vec<Finding>) {
    let mut has_zero_width = false;
    let mut has_bidi = false;
    let mut has_tag_block = false;

    // Scan the RAW text first — detection must happen before any transform.
    for c in text.chars() {
        let cp = c as u32;
        if (0x200B..=0x200F).contains(&cp) || cp == 0xFEFF {
            has_zero_width = true;
        } else if (0x202A..=0x202E).contains(&cp) || (0x2066..=0x2069).contains(&cp) {
            has_bidi = true;
        } else if (0xE0000..=0xE007F).contains(&cp) {
            has_tag_block = true;
        }
    }

    // Zero-width and bidi controls have legitimate uses — ZWJ in emoji sequences,
    // ZWNJ in Persian/Arabic/Indic scripts, RLM/LRM in mixed-direction text — so
    // their presence alone corroborates rather than convicts. Unicode tag
    // characters (U+E0000..U+E007F) have no legitimate use in agent-visible text
    // and exist in the wild essentially only to smuggle instructions.
    let mut findings = Vec::new();
    if has_zero_width {
        findings.push(Finding { id: "zero-width", weight: 40, tier: Tier::Ambiguous });
    }
    if has_bidi {
        findings.push(Finding { id: "bidi-override", weight: 40, tier: Tier::Ambiguous });
    }
    if has_tag_block {
        findings.push(Finding { id: "tag-block", weight: 70, tier: Tier::Certain });
    }

    let nfkc: String = text.nfkc().collect();
    (nfkc, findings)
}

/// One-level-deep decoded forms of `text` to rescan (never recursed).
pub fn decode_variants(text: &str) -> Vec<String> {
    let mut out = base64_variants(text);
    out.push(rot13(text));
    out.push(leet_demap(text));
    // Invisible-stripped variant: a keyword split by a zero-width/bidi/tag byte
    // (e.g. "ig\u{200B}nore all previous instructions") is invisible to every
    // regex until the smuggling bytes are removed. `analyze` already SCORED their
    // presence; this variant lets the underlying keyword match too, so the attack
    // both flags AND blocks instead of passing at the sub-escalation finding score.
    let stripped = strip_invisible(text);
    if stripped != text {
        out.push(stripped);
    }
    out
}

/// Remove zero-width, bidi-control, and tag-block characters. Same ranges
/// [`analyze`] detects — kept in sync deliberately.
fn strip_invisible(text: &str) -> String {
    text.chars()
        .filter(|c| {
            let cp = *c as u32;
            !((0x200B..=0x200F).contains(&cp)
                || cp == 0xFEFF
                || (0x202A..=0x202E).contains(&cp)
                || (0x2066..=0x2069).contains(&cp)
                || (0xE0000..=0xE007F).contains(&cp))
        })
        .collect()
}

/// Decodes every maximal run of >=24 base64-alphabet chars that is valid UTF-8
/// once decoded.
fn base64_variants(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    let n = bytes.len();

    let is_b64 = |b: u8| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=';

    for i in 0..=n {
        let cur_is_b64 = i < n && is_b64(bytes[i]);
        if cur_is_b64 {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            if i - s >= 24 {
                // Slicing is safe: base64-alphabet bytes are all single-byte ASCII.
                if let Ok(decoded) = STANDARD.decode(&text[s..i]) {
                    if let Ok(decoded_text) = String::from_utf8(decoded) {
                        out.push(decoded_text);
                    }
                }
            }
        }
    }
    out
}

/// Full-text ROT13 (letters only; self-inverse).
fn rot13(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_lowercase() {
                (((c as u8 - b'a' + 13) % 26) + b'a') as char
            } else if c.is_ascii_uppercase() {
                (((c as u8 - b'A' + 13) % 26) + b'A') as char
            } else {
                c
            }
        })
        .collect()
}

/// Full-text leetspeak demap (single pass, digit/symbol -> letter).
fn leet_demap(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '0' => 'o',
            '1' => 'i',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            '8' => 'b',
            '@' => 'a',
            '$' => 's',
            other => other,
        })
        .collect()
}

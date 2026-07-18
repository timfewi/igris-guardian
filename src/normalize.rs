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
        findings.push(Finding {
            id: "zero-width",
            weight: 40,
            tier: Tier::Ambiguous,
        });
    }
    if has_bidi {
        findings.push(Finding {
            id: "bidi-override",
            weight: 40,
            tier: Tier::Ambiguous,
        });
    }
    if has_tag_block {
        findings.push(Finding {
            id: "tag-block",
            weight: 70,
            tier: Tier::Certain,
        });
    }

    let nfkc: String = text.nfkc().collect();
    (nfkc, findings)
}

/// One-level-deep decoded forms of `text` to rescan (never recursed).
///
/// Each transform recovers a keyword an attacker hid behind an encoding a target
/// model would still read through: percent-escapes and HTML entities render back
/// to plain text in most surfaces, and confusable-folding defeats homoglyph
/// substitution (`Ignоrе` with a Cyrillic о and е). The rescan is deliberately
/// one level deep — decoding recursively would let a crafted blob steer the
/// scanner — and each variant that actually differs from the input is pushed so
/// the engine scores it alongside the original.
pub fn decode_variants(text: &str) -> Vec<String> {
    let mut out = base64_variants(text);
    out.push(rot13(text));
    out.push(leet_demap(text));

    for decoded in [
        percent_decode(text),
        html_entity_decode(text),
        fold_confusables(text),
    ] {
        if decoded != text {
            out.push(decoded);
        }
    }

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

/// Decode `%XX` percent-escapes (and `+` as space) where they form valid UTF-8;
/// leaves any malformed escape untouched. Catches `Ignore%20all%20previous...`.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    // Only accept the decode if it is valid UTF-8; otherwise keep the original so a
    // binary blob full of `%` never produces mojibake that matches nothing useful.
    String::from_utf8(out).unwrap_or_else(|_| text.to_string())
}

/// Decode numeric HTML entities (`&#73;`, `&#x49;`) and the handful of named ones
/// that matter for injection markup (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`).
/// Catches `&#73;&#103;&#110;&#111;&#114;&#101;` = "Ignore".
fn html_entity_decode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let tail = &rest[amp..];
        let end = tail.find(';').filter(|&e| e <= 10);
        match end.and_then(|e| decode_entity(&tail[1..e]).map(|c| (c, e))) {
            Some((c, e)) => {
                out.push(c);
                rest = &tail[e + 1..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn decode_entity(body: &str) -> Option<char> {
    let cp = if let Some(hex) = body.strip_prefix("#x").or_else(|| body.strip_prefix("#X")) {
        u32::from_str_radix(hex, 16).ok()?
    } else if let Some(dec) = body.strip_prefix('#') {
        dec.parse().ok()?
    } else {
        return match body {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => None,
        };
    };
    char::from_u32(cp)
}

/// Fold the common Latin-lookalike Cyrillic and Greek letters back to ASCII so a
/// homoglyph-substituted keyword matches. Only unambiguous single-letter
/// lookalikes are mapped; this is intentionally small, since over-folding would
/// corrupt legitimate non-Latin text.
fn fold_confusables(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            // Cyrillic → Latin
            'а' => 'a',
            'е' => 'e',
            'о' => 'o',
            'р' => 'p',
            'с' => 'c',
            'х' => 'x',
            'у' => 'y',
            'і' => 'i',
            'ѕ' => 's',
            'ԁ' => 'd',
            'һ' => 'h',
            'ј' => 'j',
            'А' => 'A',
            'Е' => 'E',
            'О' => 'O',
            'Р' => 'P',
            'С' => 'C',
            'Х' => 'X',
            'В' => 'B',
            'Н' => 'H',
            'К' => 'K',
            'М' => 'M',
            'Т' => 'T',
            // Greek → Latin. Folding here can only add a rescan variant, never
            // change how the original scores, so the lowercase lookalikes are safe
            // to include even though they are not perfect glyph matches.
            'ο' => 'o',
            'ρ' => 'p',
            'α' => 'a',
            'ν' => 'v',
            'ε' => 'e',
            'ι' => 'i',
            'κ' => 'k',
            'τ' => 't',
            'υ' => 'u',
            'χ' => 'x',
            'γ' => 'y',
            'ϲ' => 'c',
            'Ι' => 'I',
            'Α' => 'A',
            'Ο' => 'O',
            'Ρ' => 'P',
            'Ε' => 'E',
            'Τ' => 'T',
            'Κ' => 'K',
            'Β' => 'B',
            'Η' => 'H',
            'Μ' => 'M',
            'Ν' => 'N',
            'Χ' => 'X',
            other => other,
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_recovers_text_and_leaves_malformed() {
        assert_eq!(percent_decode("a%20b+c"), "a b c");
        // A lone/malformed escape is left as-is, not dropped.
        assert_eq!(percent_decode("100%done %zz"), "100%done %zz");
        // Invalid UTF-8 decode falls back to the original.
        assert_eq!(percent_decode("%ff%fe"), "%ff%fe");
    }

    #[test]
    fn html_entity_decode_handles_dec_hex_named() {
        assert_eq!(html_entity_decode("&#73;&#103;&#110;"), "Ign");
        assert_eq!(html_entity_decode("&#x49;&#x67;"), "Ig");
        assert_eq!(html_entity_decode("&lt;system&gt;"), "<system>");
        // A bare ampersand and an unknown entity survive untouched.
        assert_eq!(html_entity_decode("a & b &nope;"), "a & b &nope;");
    }

    #[test]
    fn fold_confusables_maps_cyrillic_and_greek() {
        // "Ignоrе" with a Cyrillic о (U+043E) and е (U+0435) folds to ASCII.
        assert_eq!(fold_confusables("Ign\u{043E}r\u{0435}"), "Ignore");
        // Pure ASCII is unchanged.
        assert_eq!(fold_confusables("Ignore"), "Ignore");
    }

    #[test]
    fn decode_variants_only_emits_differing_forms() {
        // A plain-ASCII string with no encoding yields no percent/html/fold variant
        // equal to itself (they are only pushed when they differ).
        let v = decode_variants("hello world");
        assert!(v
            .iter()
            .all(|s| s != "hello world" || v.iter().filter(|x| *x == "hello world").count() <= 1));
    }
}

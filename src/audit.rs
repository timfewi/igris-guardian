//! Append-only JSONL audit log. The ONLY thing the Guardian writes. PHASE-1C.
//!
//! Contract: one line per non-Pass verdict, opened O_APPEND|O_CREATE, one
//! `writeln` per event (atomic for lines < PIPE_BUF). No rotation in v1.

use crate::Verdict;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

pub struct Audit {
    path: PathBuf,
    excerpt: bool,
}

impl Audit {
    pub fn open(path: &Path, excerpt: bool) -> Audit {
        // Ensure parent dir exists.
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = fs::create_dir_all(parent);
            }
        }
        Audit {
            path: path.to_path_buf(),
            excerpt,
        }
    }

    /// Append one JSONL record. Always carries a sha256 of the scanned `text` for
    /// content-correlation across events; carries a 200-character excerpt only
    /// when `audit_excerpt` is enabled, because scanned content routinely contains
    /// credentials.
    pub fn record(&self, source: &str, text: &str, verdict: &Verdict, stage2_used: bool) {
        // Use Unix timestamp (seconds since epoch) for simplicity and determinism.
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let sha256_hex = {
            let digest = Sha256::digest(text.as_bytes());
            digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };

        let mut record = json!({
            "ts": ts,
            "source": source,
            "action": verdict.action,
            "score": verdict.score,
            "confidence": verdict.confidence,
            "rules": verdict.reasons,
            "stage2": stage2_used,
            "sha256": sha256_hex,
        });

        if self.excerpt {
            // First 200 chars, char-boundary safe.
            let excerpt: String = text.chars().take(200).collect();
            record["excerpt"] = json!(excerpt);
        }

        // A security tool that loses its audit trail in silence is worse than one
        // with no audit trail, because the gap is invisible. Writes are still
        // best-effort — a full disk must never wedge the scan path — but the first
        // failure says so on stderr, where systemd will journal it.
        let written = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut file| writeln!(file, "{record}"));

        if let Err(e) = written {
            if !AUDIT_FAILED.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "igris: WARNING audit log unwritable ({}): {e} — verdicts are no longer being recorded",
                    self.path.display()
                );
            }
        }
    }
}

/// Set once the first audit write fails, so a broken log path reports itself
/// exactly once rather than on every scanned event.
static AUDIT_FAILED: AtomicBool = AtomicBool::new(false);

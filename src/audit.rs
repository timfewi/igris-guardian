//! Append-only JSONL audit log. The ONLY thing the Guardian writes. PHASE-1C.
//!
//! Contract: one line per non-Pass verdict, opened O_APPEND|O_CREATE, one
//! `writeln` per event (atomic for lines < PIPE_BUF). No rotation in v1.

use crate::Verdict;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub struct Audit {
    path: PathBuf,
}

impl Audit {
    pub fn open(path: &Path) -> Audit {
        // Ensure parent dir exists.
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = fs::create_dir_all(parent);
            }
        }
        Audit {
            path: path.to_path_buf(),
        }
    }

    /// Append one JSONL record. Carries a sha256 of the scanned `text` for
    /// content-correlation across events, plus a short escaped excerpt — never the
    /// full content.
    pub fn record(&self, source: &str, text: &str, verdict: &Verdict, stage2_used: bool) {
        // Use Unix timestamp (seconds since epoch) for simplicity and determinism.
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let sha256_hex = {
            let digest = Sha256::digest(text.as_bytes());
            digest.iter().map(|b| format!("{b:02x}")).collect::<String>()
        };

        // Excerpt: first 200 chars of the scanned text (char-boundary safe).
        let excerpt: String = text.chars().take(200).collect();

        let record = json!({
            "ts": ts,
            "source": source,
            "action": verdict.action,
            "score": verdict.score,
            "rules": verdict.reasons,
            "stage2": stage2_used,
            "sha256": sha256_hex,
            "excerpt": excerpt,
        });

        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = writeln!(file, "{}", record);
        }
    }
}

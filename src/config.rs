//! Configuration. `deny_unknown_fields` everywhere is a security property: an
//! unknown key is a startup error, so no capability flag can ever be smuggled in.
//! There is deliberately no field that disables scanning, overrides the guard
//! prompt, or adds an "allow" mode.

use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Score at/above which content is blocked. Clamped to 60..=100 at load.
    pub block_threshold: u8,
    /// Score at/above which stage 2 is consulted. Clamped to 20..block_threshold.
    pub escalate_threshold: u8,
    /// Max bytes scanned. Serve blocks over-cap payloads; other adapters truncate.
    pub max_scan_bytes: usize,
    /// Append-only JSONL audit log path (`~` expanded).
    pub audit_log: String,
    /// Record a 200-character excerpt of scanned content alongside each verdict.
    ///
    /// Off by default, and it should stay off outside deliberate tuning sessions:
    /// the scanner sees command output, file contents and request bodies, so the
    /// excerpt is an excellent way to end up with credentials in a log file that
    /// nothing rotates. The sha256 is always recorded and is enough to correlate
    /// repeat offenders without retaining their content.
    pub audit_excerpt: bool,
    pub stage2: Stage2Config,
    pub serve: ServeConfig,
    pub hook: HookConfig,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            block_threshold: 80,
            escalate_threshold: 50,
            max_scan_bytes: 2_000_000,
            audit_log: "~/.local/state/igris/audit.jsonl".to_string(),
            audit_excerpt: false,
            stage2: Stage2Config::default(),
            serve: ServeConfig::default(),
            hook: HookConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HookConfig {
    /// Substrings of `Read` file paths whose Block verdicts downgrade to Warn.
    ///
    /// For repositories that legitimately contain payloads — this project's own
    /// source, corpus fixtures, threat models. This is a *downgrade*, not an
    /// exemption: the scan still runs, the audit line is still written, and the
    /// warning still reaches the agent. There is deliberately no way to skip
    /// scanning a path entirely.
    pub downgrade_paths: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Stage2Config {
    /// When false, only stage 1 runs (deterministic offline floor). Logged at startup.
    pub enabled: bool,
    pub base_url: String,
    pub model: String,
    /// Env var name holding the API key (never the key itself).
    pub api_key_env: String,
    /// Path to a file holding the API key, for secret managers that decrypt to a
    /// file rather than an env var (agenix `/run/agenix/*`, systemd
    /// `LoadCredential`, Docker/K8s secrets). Takes precedence over
    /// `api_key_env`. Empty = unused. Never the key itself.
    pub api_key_file: String,
    pub timeout_ms: u64,
    /// Send OpenRouter's `provider: {"zdr": true}` routing preference so the
    /// request can only reach Zero-Data-Retention endpoints — misrouting to a
    /// retaining provider becomes an upstream error instead of a silent leak.
    /// OpenRouter-specific: leave false for other OpenAI-compatible endpoints,
    /// which may reject the unknown field.
    pub zdr_only: bool,
    /// `reasoning_effort` sent with each request (`"low"`/`"medium"`/`"high"`,
    /// empty = not sent). Reasoning models (Mercury 2 et al.) otherwise spend
    /// their latency budget thinking before the first verdict token.
    pub reasoning_effort: String,
}

impl Default for Stage2Config {
    fn default() -> Self {
        Stage2Config {
            enabled: true,
            base_url: "https://api.openai.com/v1".to_string(),
            model: "deepseek-v4-pro".to_string(),
            api_key_env: "IGRIS_STAGE2_KEY".to_string(),
            api_key_file: String::new(),
            timeout_ms: 5000,
            zdr_only: false,
            reasoning_effort: String::new(),
        }
    }
}

impl Stage2Config {
    /// The API key: `api_key_file` if set, else the `api_key_env` env var.
    /// Trailing whitespace is trimmed — secret files almost always end in a
    /// newline, and a stray `\n` in a bearer header is a 401 that looks like a
    /// bad key. Returns `None` if unset, unreadable, or empty.
    pub fn api_key(&self) -> Option<String> {
        let raw = if self.api_key_file.is_empty() {
            std::env::var(&self.api_key_env).ok()?
        } else {
            std::fs::read_to_string(expand_tilde(&self.api_key_file)).ok()?
        };
        let key = raw.trim();
        (!key.is_empty()).then(|| key.to_string())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServeConfig {
    pub listen: String,
    pub upstream: String,
    /// Env var name for an optional bearer token required from local clients.
    /// Empty = no client auth.
    pub auth_token_env: String,
}

impl Default for ServeConfig {
    fn default() -> Self {
        ServeConfig {
            listen: "127.0.0.1:8787".to_string(),
            upstream: "https://api.anthropic.com".to_string(),
            auth_token_env: String::new(),
        }
    }
}

impl Config {
    /// Load from an explicit path, else `~/.config/igris/config.toml`, else defaults.
    /// Applies `IGRIS_*` env overrides for endpoint fields only, then clamps thresholds.
    pub fn load(explicit: Option<&Path>) -> Result<Config, String> {
        let path = explicit.map(PathBuf::from).or_else(default_config_path);

        let mut cfg = match path {
            Some(p) if p.exists() => {
                let text = std::fs::read_to_string(&p)
                    .map_err(|e| format!("read {}: {e}", p.display()))?;
                toml::from_str(&text).map_err(|e| format!("parse {}: {e}", p.display()))?
            }
            _ => Config::default(),
        };

        cfg.apply_env_overrides();
        cfg.clamp();
        Ok(cfg)
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("IGRIS_STAGE2_BASE_URL") {
            self.stage2.base_url = v;
        }
        if let Ok(v) = std::env::var("IGRIS_STAGE2_MODEL") {
            self.stage2.model = v;
        }
        if let Ok(v) = std::env::var("IGRIS_SERVE_UPSTREAM") {
            self.serve.upstream = v;
        }
        if let Ok(v) = std::env::var("IGRIS_SERVE_LISTEN") {
            self.serve.listen = v;
        }
        if let Ok(v) = std::env::var("IGRIS_AUDIT_LOG") {
            self.audit_log = v;
        }
    }

    fn clamp(&mut self) {
        self.block_threshold = self.block_threshold.clamp(60, 100);
        let hi = self.block_threshold.saturating_sub(1);
        self.escalate_threshold = self.escalate_threshold.clamp(20, hi);
    }

    /// Expanded audit log path.
    pub fn audit_path(&self) -> PathBuf {
        expand_tilde(&self.audit_log)
    }
}

fn default_config_path() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".config/igris/config.toml"))
}

pub fn expand_tilde(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_keeps_escalate_below_block() {
        let mut c = Config {
            block_threshold: 50,
            escalate_threshold: 90,
            ..Config::default()
        };
        c.clamp();
        assert_eq!(c.block_threshold, 60);
        assert!(c.escalate_threshold < c.block_threshold);
    }

    #[test]
    fn unknown_field_is_rejected() {
        let err = toml::from_str::<Config>("allow_mode = true\n");
        assert!(err.is_err(), "unknown fields must be a hard error");
    }

    #[test]
    fn api_key_file_takes_precedence_and_trims() {
        let p = std::env::temp_dir().join(format!("igris-key-test-{}", std::process::id()));
        // Secret files from agenix/LoadCredential end in a newline; a stray \n in
        // the bearer header is a 401 that looks like a bad key.
        std::fs::write(&p, "sk-from-file\n").expect("write temp key");

        let from_file = Stage2Config {
            api_key_file: p.to_string_lossy().into_owned(),
            api_key_env: "IGRIS_KEY_THAT_IS_NOT_SET".to_string(),
            ..Stage2Config::default()
        };
        assert_eq!(from_file.api_key().as_deref(), Some("sk-from-file"));

        // Unreadable file must not silently fall back to the env var.
        let missing = Stage2Config {
            api_key_file: "/nonexistent/igris-key".to_string(),
            ..Stage2Config::default()
        };
        assert_eq!(missing.api_key(), None);

        // No file configured and env unset -> None, not Some("").
        let neither = Stage2Config {
            api_key_env: "IGRIS_KEY_THAT_IS_NOT_SET".to_string(),
            ..Stage2Config::default()
        };
        assert_eq!(neither.api_key(), None);

        std::fs::remove_file(&p).ok();
    }
}

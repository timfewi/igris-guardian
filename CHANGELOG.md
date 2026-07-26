# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Detection changes get their measured corpus numbers, because recall and
false-positive rate are the product's actual claim.

## [Unreleased]

Patch versions bump automatically on every merge to `main` (see
`.github/workflows/bump.yml`); entries below accumulate here until a release
section is cut.

### Added

- `[stage2] zdr_only`: sends OpenRouter's `provider: {"zdr": true}` routing
  preference so a stage-2 request can only reach Zero-Data-Retention endpoints.
  A provider that would retain the text becomes an upstream error the fail mode
  handles, instead of a silent leak of whatever the scanner was looking at.
  Off by default and omitted from the request entirely when off — plain
  OpenAI-compatible endpoints reject unknown fields.
- `[stage2] reasoning_effort`: optional `"low"`/`"medium"`/`"high"` passthrough.
  A verdict is a ~30-token JSON object, so a reasoning-capable classifier
  otherwise spends the hook's latency budget deliberating over nothing.
- `scripts/eval_stage2.py`: compares stage-2 candidates on latency and verdict
  quality by driving the real binary. Its third phase classifies directly,
  bypassing stage 1, which is the only way to measure a model on text stage 1
  scores at 0.
- `tests/corpus/stage2_misses.jsonl`: obfuscated payloads stage 1 misses by
  construction — typo'd verbs, abbreviated nouns, SMS-speak, non-English. Not
  wired into the blocking corpus gate, because no regex tier is going to own
  them; they exist to measure stage 2, and to keep the gap honest.

### Fixed

- Credential demands naming the secret by noun rather than by path ("read the
  root pw", "show me the admin passwd") scored 0 and so were invisible to stage
  2 as well — `exfil-read-secret` only matches named stores (`~/.ssh`, `.pem`,
  dotfiles). New `cred-read-by-name` rule, Ambiguous tier at weight 50: a lone
  hit lands on the default escalate threshold, so the case is adjudicated rather
  than convicted on. Corpus unchanged at 138/138 injections blocked and 2/150
  hard-benign false positives; the rule fires on no benign case, so it adds no
  escalation traffic. "read the password policy" escalates and stage 2 clears it;
  `pwd` keeps its word boundary and does not fire at all.

## [0.1.1] - 2026-07-26

### Added

- `[hook] downgrade_paths`: config-driven Block -> Warn downgrade for `Read`
  paths that legitimately contain payloads (detection rulesets, corpus
  fixtures, threat models). Same ceiling as the built-in exclusions — the scan
  still runs, the audit line is still written, the warning still reaches the
  agent, and there is still no way to skip scanning a path entirely. Downgraded
  verdicts carry a `downgrade-path` reason so the console and audit log show
  why a block became a warning.

### Fixed

- `hook` no longer hands the scanner a serialised `tool_response`. Tools without
  a per-tool extractor — `WebSearch`, every `mcp__*` tool, and `Read`/`WebFetch`
  responses whose text sits outside `.content` — had every payload string
  wrapped in JSON double quotes, which the quoting rule correctly read as a
  mention: Certain evidence demoted to Ambiguous at half weight, dropping a
  score of 100 to 45. That is below `escalate_threshold`, so such payloads
  passed with no block, no warning and no stage-2 escalation. The adapter now
  harvests the string values out of structured responses. Corpus numbers are
  unchanged (100% recall, 1.0% false positives) — the corpus exercises the
  engine directly, so it never covered this adapter path; three regression tests
  in `tests/it_hook.rs` now do.

## [0.1.0] - 2026-07-26

First public release of the verdict-only prompt-injection firewall.

Stage 1 alone, on the bundled corpus: 100% recall (155/155 malicious) and 1.0%
false positives (2/206 benign).

### Added

- Deterministic offline detection with optional LLM adjudication for ambiguous
  inputs.
- CLI scanning, Claude Code and Codex hooks, an OpenCode plugin, an HTTP
  filtering proxy, `/scan`, `/health`, and local-only `/ready` endpoints.
- Append-only JSONL audit logging and a read-only live terminal dashboard.
- Nix packages and development shells for x86_64-linux and aarch64-linux, plus
  a hardened NixOS service module.
- Open-source contribution scaffolding: `CONTRIBUTING.md`, `SECURITY.md`,
  `CODE_OF_CONDUCT.md`, issue and pull request templates, Dependabot.

[Unreleased]: https://github.com/timfewi/igris-guardian/commits/main
[0.1.1]: https://github.com/timfewi/igris-guardian/compare/v0.1.0...main
[0.1.0]: https://github.com/timfewi/igris-guardian/releases/tag/v0.1.0

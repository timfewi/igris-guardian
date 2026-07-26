# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Detection changes get their measured corpus numbers, because recall and
false-positive rate are the product's actual claim.

## [Unreleased]

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
[0.1.0]: https://github.com/timfewi/igris-guardian/releases/tag/v0.1.0

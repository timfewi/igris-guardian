# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Detection changes get their measured corpus numbers, because recall and
false-positive rate are the product's actual claim.

## [Unreleased]

Nothing released yet. `0.1.0` is in development: a two-stage prompt-injection
scanner with a deterministic offline stage 1 and an optional LLM classifier for
stage 2. Verdict-only — no rewriting, no acting, no shell.

Stage 1 alone, on the bundled corpus: 100% recall (155/155 malicious), 1.0%
false positives (2/203 benign).

### Added

- Open-source contribution scaffolding: `CONTRIBUTING.md`, `SECURITY.md`,
  `CODE_OF_CONDUCT.md`, issue and pull request templates, Dependabot.

[Unreleased]: https://github.com/timfewi/igris-guardian/commits/main

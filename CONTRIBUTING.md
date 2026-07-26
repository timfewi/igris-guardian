# Contributing to Igris Guardian

Thanks for looking. Igris is a prompt-injection firewall: it reads untrusted
text and returns a verdict. Contributions are judged against that scope, so it
is worth knowing where the line is before you spend an evening on something.

## The most useful contribution: corpus cases

Detection quality is a measured number, not an opinion. The corpus is how it
gets measured, and it is where help is most valuable:

- A **benign** string that Igris currently blocks (false positive)
- A **malicious** string that Igris currently passes (false negative)

Either one is a bug report with the fix attached. Add it to
`tests/corpus/*.jsonl` as one JSON object per line:

```json
{"text": "the string as an attacker or a user would actually send it", "note": "why this is benign/malicious and where it came from"}
```

Rules for corpus entries:

- **Real text, not synthetic.** Cases lifted from actual WAF rulesets, CTF
  writeups, pytest fixtures, docs, or logs are worth more than invented ones.
- **No secrets, no personal data, no customer content.** Redact before pasting.
  A corpus file is public forever.
- **One phenomenon per entry.** If it takes three sentences to explain what the
  case is testing, it is probably two cases.
- **`note` is mandatory.** Six months from now it is the only thing separating a
  deliberate case from a typo.

Then check what you changed:

```console
$ cargo test --test corpus_report -- --nocapture
```

If your case flips a number, say so in the PR — recall and false-positive rate
are product claims, and a PR that moves them needs to move them on purpose.

## Development

```console
$ nix develop          # or bring your own cargo
$ cargo test
$ cargo test --test corpus_report -- --nocapture   # detection numbers
$ cargo clippy --all-targets -- -D warnings
$ cargo fmt
```

CI runs `fmt --check`, `clippy -D warnings`, and the full test suite. Run them
locally first; it is faster than a round trip.

## Scope: what Igris will not become

These are refusals, not backlog items. A PR implementing one of them will be
declined however good the code is:

- **Rewriting, sanitising, or redacting input.** Igris emits a verdict and
  nothing else. A scanner that can rewrite is a scanner that can be talked into
  rewriting. This is the core security property.
- **Answering, acting, running tools, or shelling out.** No code path, on
  purpose.
- **Runtime override of the stage-2 system prompt.** It is compiled in and
  SHA-256 verified at startup. Config cannot reach it, and that is the point.
- **Writing anything but the append-only audit log.**

New detection rules, new languages, corpus cases, adapters, performance work,
and documentation are all in scope.

## Adding detection rules

Stage 1 is deterministic and offline, so every rule is a permanent
false-positive risk on somebody's benign text. Before adding one:

1. Add the malicious case to the corpus **first** and watch it fail.
2. Add the nearest benign lookalike you can construct — the case that would
   trip a sloppy version of your rule — and make sure it still passes.
3. Keep the reason string stable and machine-readable (`instr-ignore-previous`,
   not `Detected an ignore-previous attempt`). Downstream policy reads these.

Some attack families are deliberately left to stage 2 (tool-use social
engineering, conditional triggers, payloads quoted as data). See the Limits
section of the README before trying to convict on them at the regex layer.

## Pull requests

- Branch off `main`, one logical change per PR.
- **Versioning is automatic.** Every merge to `main` bumps the patch version by
  one via CI (`.github/workflows/bump.yml`) — do not bump it in your PR. Minor
  and major bumps are deliberate maintainer releases, landed as a PR whose
  squash title starts with `release:`, which CI leaves untouched.
- Explain what an attacker or user does differently because of this change.
- Tests for anything that isn't a typo fix.
- If you changed detection behaviour, paste the before/after corpus numbers.

By submitting a contribution, you agree to license it under the repository's
[MIT License](LICENSE). See [LICENSING.md](LICENSING.md) for the boundary
between the open-source code, project trademarks, and future enterprise
offerings.

## Reporting security issues

Do not open a public issue for a vulnerability in Igris itself. See
[SECURITY.md](SECURITY.md) — it also explains which bypasses are ordinary bug
reports (most of them) and which are not.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).

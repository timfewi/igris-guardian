## What this changes

<!-- One or two sentences. What does an attacker or a user do differently now? -->

## Type

- [ ] Corpus case (benign that blocked / malicious that passed)
- [ ] Detection rule
- [ ] Bug fix
- [ ] Feature or adapter
- [ ] Docs
- [ ] Chore / refactor

## Detection impact

<!-- Skip if this cannot affect verdicts. Otherwise paste before/after from:
     cargo test --test corpus_report -- --nocapture -->

| | Before | After |
|---|---|---|
| Recall | | |
| False positives | | |

## Checklist

- [ ] `cargo test` passes
- [ ] `cargo clippy --all-targets -- -D warnings` is clean
- [ ] `cargo fmt` applied
- [ ] New detection rule ships with both a malicious case and its nearest benign lookalike
- [ ] No secrets, personal data, or customer content in corpus entries
- [ ] Stays within scope — no rewriting, acting, or overriding the compiled system prompt (see CONTRIBUTING.md)

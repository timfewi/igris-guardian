# Security Policy

Igris Guardian is a security tool, so "is this a vulnerability or a bug?" comes
up more here than in most projects. This document draws that line.

## Supported versions

Pre-1.0. Only the latest release on `main` receives fixes.

| Version | Supported |
| ------- | --------- |
| latest `main` | ✅ |
| anything older | ❌ |

## What is an ordinary bug report (open a public issue)

**A detection miss is not a vulnerability.** Igris is documented as a filter,
not a guarantee, and the README's Limits section names the classes it knowingly
does not convict on at stage 1. So please open a **public** issue — ideally with
a corpus case attached — for:

- A malicious string that passes (false negative)
- A benign string that gets blocked (false positive)
- A novel phrasing, encoding, or language that evades stage 1
- Anything already described under Limits behaving as described

These are the project's daily work. Filing them publicly is how the corpus grows.

## What is a vulnerability (report privately)

Report privately if you can break a property Igris claims to hold, or if the
scanner itself is the attack surface:

- **Prompt integrity** — making the stage-2 system prompt differ from the
  compiled, SHA-256-verified copy, or getting the process past a mismatch
  instead of aborting.
- **Verdict-only bounds** — inducing Igris to write, rewrite, execute, fetch,
  or act on anything beyond emitting a verdict and its audit log line.
- **Memory safety, panics, or crashes** reachable from scanned input,
  including denial of service against `serve`.
- **Audit log integrity** — forging, suppressing, or corrupting entries, or
  escaping the append-only property.
- **Secret or content leakage** — config values, local file contents, or scanned
  text reaching a place the docs do not say it goes (including stage-2 traffic
  going somewhere other than the configured endpoint).
- **Supply chain** — a compromised dependency, build, or release artefact.

## How to report

Use GitHub's [private vulnerability
reporting](https://github.com/timfewi/igris-guardian/security/advisories/new)
on this repository. If that is unavailable to you, email
**hello@timwitter.com** with
`[igris-security]` in the subject.

Please include:

- What property you broke, and the version or commit
- Reproduction steps or a proof of concept — the smallest one that works
- Impact as you see it, and any config required to reach it

## What to expect

- **Acknowledgement within 72 hours.**
- An assessment, and agreement on whether it is a vulnerability or a bug, within
  7 days.
- A fix or a documented mitigation before public disclosure, coordinated with
  you on timing. 90 days is the default ceiling.
- Credit in the advisory and changelog unless you would rather not be named.

This is a single-maintainer project with no bug bounty. Reports are read and
answered by a human on a normal schedule.

## Please don't

- Test against systems you do not own or have permission to test.
- Run denial-of-service or automated scanning against third-party deployments.
- Access, modify, or retain other people's data while demonstrating an issue.

## Using Igris safely

Restating the README's Limits, because they matter for how you deploy it:

- Igris is **one layer.** Keep least-privilege tool scoping, human confirmation
  on destructive actions, and egress controls. A filter does not replace them.
- **Stage 2 sends escalated content off-box** when enabled. Point it at a local
  model, or leave it disabled, if that is unacceptable in your environment.
- **Text only.** Injection inside images, audio, or PDFs is invisible to it.
- Input beyond `max_scan_bytes` is truncated by `scan` and `hook`; `serve`
  refuses oversized responses rather than scanning part of one.

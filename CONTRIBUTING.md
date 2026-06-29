# Contributing

Thanks for your interest in `wimsey`. This document covers how to propose
changes.

## Developer Certificate of Origin (DCO)

All commits must be signed off under the
[Developer Certificate of Origin](https://developercertificate.org/). Sign off
by adding a `Signed-off-by` line to each commit message:

```text
Signed-off-by: Your Name <your.email@example.com>
```

`git commit -s` adds this automatically. CI rejects pull requests whose commits
lack a sign-off.

## Before you open a pull request

Run the same checks CI runs:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

## Guidelines

- One logical change per commit; keep refactors separate from behaviour
  changes.
- Reference the relevant draft section for spec-driven code, and keep
  [`SPEC-MAP.md`](SPEC-MAP.md) accurate when a pinned revision changes.
- Add or update conformance vectors alongside behaviour changes.
- Security-sensitive code must fail closed and be covered by negative tests.

## Reporting security issues

Do not open a public issue for vulnerabilities. Follow the
[security policy](SECURITY.md).

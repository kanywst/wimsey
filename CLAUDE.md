# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`wimsey` is a vendor-neutral reference implementation, in Rust, of the IETF **WIMSE**
(Workload Identity in Multi System Environments) drafts. It targets CNCF-Sandbox quality:
spec-faithful, deterministic, and validated against cross-implementation conformance vectors.

## Commands

```bash
cargo build --workspace
cargo test --workspace --all-targets   # unit + integration tests
cargo test --workspace --doc           # doctests (crate examples run as tests)
cargo test -p wimsey-wit               # one crate
cargo test -p wimsey-httpsig sign      # tests whose name matches "sign"
cargo fmt --all -- --check             # CI runs this; must be clean
cargo clippy --workspace --all-targets -- -D warnings   # pedantic; warnings fail CI
cargo install --path crates/cli        # installs the `wimsey` binary
cargo run -p wimsey-issuer             # runs the experimental HTTP issuer
```

CI (`.github/workflows/ci.yml`) gates on: fmt, clippy (`-D warnings`), tests, doctests,
`cargo-deny`, the conformance suite, conformance-vector freshness, and a DCO sign-off check on
every PR commit.

## Non-negotiable invariants

These are the things that break silently or fail CI in non-obvious ways.

- **Conformance vectors are CI-gated twice.** `wimsey-conformance` owns both the generator and
  the runner, so the format has one definition. CI regenerates and diffs (any drift in the
  recorded bytes fails), *and* runs the suite (any change in accept/reject behaviour fails).
  Every vector carries `negative` cases naming a language-neutral error code — an input rejected
  for the wrong reason is a failure, not a pass. Format spec: `conformance/README.md`.

  ```bash
  cargo run -q -p wimsey-conformance -- run --dir conformance          # check
  cargo run -q -p wimsey-conformance -- generate --out conformance     # regenerate
  ```

- **Determinism is a design constraint, not an accident.** All signing is EdDSA/Ed25519
  (RFC 8037), which is deterministic, so tokens and signatures are byte-for-byte reproducible.
  Do not introduce non-deterministic crypto or randomize what a vector captures. Time is
  **injected** (a `Validation`/verify config carries `now`) so time-dependent tests are
  reproducible — never call a wall clock inside verification logic.

- **Byte-exactness in `httpsig`.** The RFC 9421 signature base (§2.5) is verified byte-for-byte
  against the RFC's worked example, and verification reuses the *received* structured-field
  parameter substring verbatim rather than re-serializing. Structured-field parsing is
  quote-aware. Changing whitespace/quoting in the signature base will break interop and the vector.

- **base64 alphabet split.** Tokens use URL-safe **no-pad** (`URL_SAFE_NO_PAD`); RFC 8941 byte
  sequences use **standard** base64. Don't unify these.

- **Every parser is fuzzed.** `fuzz/` carries a target per untrusted-input
  surface — the identifier, WIT, WPT, `Signature-Input` and DER X.509 — and CI
  runs each for 30 seconds against a corpus seeded from the conformance vectors
  (`fuzz/seed-corpus.sh`). Adding a parser without a target leaves a hole; the
  targets need nightly, which is why `fuzz/` is excluded from the workspace.

  ```bash
  ./fuzz/seed-corpus.sh
  cargo +nightly fuzz run httpsig_verify -- -max_total_time=600
  ```

- **Draft pins are deliberate.** Each crate targets one pinned Internet-Draft revision (see
  `SPEC-MAP.md`). Bumping a pin is a reviewed change, not a drive-by.

## Architecture

A Rust workspace; each protocol element is one crate, layered by dependency:

- **`wimsey-identifier`** — the workload identifier URI (`spiffe://<trust-domain>/<path>`),
  SPIFFE-ID-compatible. The leaf dependency the token/cert crates build on.
- **`wimsey-wit`** — Workload Identity Token: a JWT (`typ: wit+jwt`) signed by an *issuer*,
  carrying the identifier in `sub` and a proof-of-possession public key in `cnf`.
- **`wimsey-wpt`** — Workload Proof Token (`typ: wpt+jwt`): short-lived, signed by the
  workload's PoP key (the private half of the WIT's `cnf`). Bound to a specific WIT via
  `wth = base64url(SHA-256(WIT))` and to an audience via `aud`; verification recomputes `wth`
  so a proof can't be replayed against a different WIT or service.
- **`wimsey-httpsig`** — the HTTP Message Signatures transport binding (RFC 9421 profile).
  The caller signs the request (including the WIT-bearing header) with its PoP key; the
  receiver recovers the key from the WIT `cnf` and verifies.
- **`wimsey-mtls`** — the mTLS binding. Issues/verifies a Workload Identity Certificate (WIC):
  an X.509 client cert (X.509-SVID shape) with the identifier in a URI SAN, signed by a workload
  CA. `verify` intentionally checks only the *directly provided* CA — chain building is the
  caller's job; rustls wiring is left to the caller.
- **`wimsey-cli`** (`wimsey` binary) — subcommands `key`, `wit`, `wpt`, `httpsig`.
- **`wimsey-conformance`** (`wimsey-conformance` binary) — generates and runs the
  cross-implementation vectors under `conformance/`. Not a protocol element; the harness that
  makes the vectors a contract other implementations can hold this one to.
- **`wimsey-issuer`** — an **experimental** axum HTTP issuer: `POST /wit`, `GET /jwks`,
  `GET /healthz`. Binds `127.0.0.1` by default (not `0.0.0.0`) and warns loudly on ephemeral
  keys / no attestation. Reference/experimentation scope only.

The trust chain end to end: an issuer signs a **WIT** binding an identifier to a PoP key → the
workload proves possession per-request with a **WPT** or an **httpsig** signature (HTTP) or a
**WIC** (mTLS) → the peer recovers the PoP key from the WIT and verifies.

## Conventions enforced by the workspace

- Lints are workspace-wide (`[workspace.lints]`): `unsafe_code = "forbid"`, `missing_docs = "warn"`,
  clippy `all` + `pedantic`. Every crate opts in with `[lints] workspace = true` — if a new crate
  omits this it silently escapes pedantic lints, so always add it.
- MSRV is Rust 1.85, edition 2021. Keep public items documented (missing docs warn → fail under `-D warnings`).
- Commits need a DCO `Signed-off-by` line (`git commit -s`); CI rejects PR commits without one.

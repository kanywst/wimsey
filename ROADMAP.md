# Roadmap

The North Star is a clean, conformance-tested WIMSE implementation in a neutral
home, ready to apply for **CNCF Sandbox**. Work proceeds in phases; each phase
has a verification gate that must be green before the next begins. Each phase
carries a **Status** line; re-check it against the code whenever the roadmap is
reviewed, since a stale status misleads more than a missing one.

## Phase 0 — Foundation

- Cargo workspace, one crate per protocol element, with a small audited
  dependency set (`cargo-deny` gates licenses and advisories).
- Apache-2.0, CI (fmt / clippy / test / cargo-deny / DCO), `SPEC-MAP.md`,
  project-hygiene docs.
- **Gate:** `cargo check` / `clippy -D warnings` / `cargo fmt --check` green;
  CLI runs.
- **Status: met.** The workspace now has ten crates (the original seven plus
  `wimsey-jose`, `wimsey-conformance` and `wimsey-demo`). "Zero external
  dependencies" was the original aim and was dropped: signing uses
  `ed25519-dalek` and `p256`, the CLI `clap`, the issuer `axum`.

## Phase 1 — WIT core (`wimsey-wit`)

- WIT issuance and verification: `typ: wit+jwt`, `cnf` confirmation, `sub` =
  workload identifier, `iss` / `exp` / `iat` / `jti`.
- WIC: the X.509 profile for workload certificates.
- JWK handling; conformance vectors from the draft's non-normative examples.
- **Gate:** round-trip plus draft example vectors pass; negative tests (bad
  `typ`, missing `cnf`) fail closed.
- **Status: met.** `EdDSA` and `ES256`. The WIC landed in `wimsey-mtls` rather
  than here.

## Phase 2 — WPT core (`wimsey-wpt`)

- Workload Proof Token: signed JWT with `aud` / `exp` / `jti` / `wth`, media
  type `application/wimse-proof+jwt`.
- Bind a WPT to a WIT and verify possession.
- **Gate:** PoP verification passes; replay and expiry negative tests fail
  closed.
- **Status: met**, at `draft-ietf-wimse-wpt-02` (`tth`/`oth` binding). The `WPT`
  HTTP authentication scheme itself is the caller's; see `SPEC-MAP.md`.

## Phase 3 — Transport bindings

- `wimsey-httpsig`: the RFC 9421 binding — covered components, signature
  headers, carriage of WIT and WPT.
- `wimsey-mtls`: the mTLS binding, client cert = WIC.
- **Gate:** a signed request survives an intermediary; tamper detection test
  fails closed.
- **Status: met.** `wimsey-httpsig` follows `http-signature-07`, including
  signed responses and tag-based selection alongside an intermediary's own
  signature. `wimsey-mtls` issues and verifies the WIC but does not depend on
  `rustls`: wiring it into a TLS stack, and PKIX chain building, are left to
  the caller (`SPEC-MAP.md`, Known divergences).

## Phase 4 — Issuer, CLI and demo

- `wimsey-issuer`: an experimental issuer with a SPIFFE Workload API shim
  (interoperate, do not compete).
- `wimsey-cli`: subcommands per protocol element — `key`, `wit`, `wpt`, `wic`,
  `httpsig` — each with its own issue/sign and verify.
- An end-to-end demo: two services and a middlebox (`cargo run -p wimsey-demo`).
- **Gate:** the end-to-end demo runs green in CI.
- **Status: gate met, one item open.** The demo asserts at every step and CI
  runs it, so the gate fails the build rather than a reader. The issuer exists
  (`POST /wit`, `GET /jwks`) but the SPIFFE Workload API shim does not.

## Phase 5 — Interop and conformance

- `conformance/`: JSON test vectors and a runner, covering every protocol
  element — identifier, WIT, WPT, HTTP signature and WIC.
- Cross-implementation interop in CI against a Go implementation (e.g. Cofide
  `minispire`).
- Publish the vectors for other implementers.
- **Gate:** cross-language interop passes.
- **Status: in progress.** Vectors for all five elements, in both algorithms,
  are published and CI-gated (regenerate-and-diff plus run), and a third party
  has run the httpsig vectors against their own RFC 9421 implementation. There
  is no Go interop job in CI yet, so the gate is not met.

## Phase 6 — CNCF Sandbox readiness

- Move to a neutral org; finalise governance, maintainers and adopters.
- OpenSSF Best Practices badge and Scorecard in CI.
- Engage the WIMSE WG; get listed in the drafts' RFC 7942 implementation
  status sections.
- File the CNCF Sandbox application.
- **Gate:** Sandbox application submitted.
- **Status: in progress.** Done: OpenSSF Scorecard in CI, and listed in the
  Implementation Status sections of `http-signature` and `workload-creds`.
  Open: neutral org, second maintainer, OpenSSF Best Practices badge, the
  application itself.

## Known risks

- **Single maintainer.** Sandbox values vendor-neutral governance and a
  committer base beyond one person. Mitigation: recruit a second maintainer
  early and engage the WG and the SPIFFE community.
- **Overlap with SPIFFE/SPIRE.** Mitigation: scope the issuer as
  reference/experimentation only and interoperate via the SPIFFE Workload API
  rather than replacing SPIRE.
- **Moving specs.** Mitigation: pin draft revisions (`SPEC-MAP.md`) and treat
  bumps as reviewed changes.

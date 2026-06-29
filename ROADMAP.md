# Roadmap

The North Star is a clean, conformance-tested WIMSE implementation in a neutral
home, ready to apply for **CNCF Sandbox**. Work proceeds in phases; each phase
has a verification gate that must be green before the next begins.

## Phase 0 — Foundation

- Cargo workspace with the seven crates, zero external dependencies.
- Apache-2.0, CI (fmt / clippy / test / cargo-deny / DCO), `SPEC-MAP.md`,
  project-hygiene docs.
- **Gate:** `cargo check` / `clippy -D warnings` / `cargo fmt --check` green;
  CLI runs.

## Phase 1 — WIT core (`wimsey-wit`)

- WIT issuance and verification: `typ: wit+jwt`, `cnf` confirmation, `sub` =
  workload identifier, `iss` / `exp` / `iat` / `jti`.
- WIC: the X.509 profile for workload certificates.
- JWK handling; conformance vectors from the draft's non-normative examples.
- **Gate:** round-trip plus draft example vectors pass; negative tests (bad
  `typ`, missing `cnf`) fail closed.

## Phase 2 — WPT core (`wimsey-wpt`)

- Workload Proof Token: signed JWT with `aud` / `exp` / `jti` / `wth`, media
  type `application/wimse-proof+jwt`.
- Bind a WPT to a WIT and verify possession.
- **Gate:** PoP verification passes; replay and expiry negative tests fail
  closed.

## Phase 3 — Transport bindings

- `wimsey-httpsig`: the RFC 9421 binding — covered components, signature
  headers, carriage of WIT and WPT.
- `wimsey-mtls`: the mTLS binding with `rustls`, client cert = WIC.
- **Gate:** a signed request survives an intermediary; tamper detection test
  fails closed.

## Phase 4 — Issuer, CLI and demo

- `wimsey-issuer`: an experimental issuer with a SPIFFE Workload API shim
  (interoperate, do not compete).
- `wimsey-cli`: `issue` / `verify` / `inspect` subcommands.
- An end-to-end demo: two services and a middlebox.
- **Gate:** the end-to-end demo runs green in CI.

## Phase 5 — Interop and conformance

- `conformance/`: JSON test vectors and a runner.
- Cross-implementation interop in CI against a Go implementation (e.g. Cofide
  `minispire`).
- Publish the vectors for other implementers.
- **Gate:** cross-language interop passes.

## Phase 6 — CNCF Sandbox readiness

- Move to a neutral org; finalise governance, maintainers and adopters.
- OpenSSF Best Practices badge and Scorecard in CI.
- Engage the WIMSE WG; get listed in the drafts' RFC 7942 implementation
  status sections.
- File the CNCF Sandbox application.
- **Gate:** Sandbox application submitted.

## Known risks

- **Single maintainer.** Sandbox values vendor-neutral governance and a
  committer base beyond one person. Mitigation: recruit a second maintainer
  early and engage the WG and the SPIFFE community.
- **Overlap with SPIFFE/SPIRE.** Mitigation: scope the issuer as
  reference/experimentation only and interoperate via the SPIFFE Workload API
  rather than replacing SPIRE.
- **Moving specs.** Mitigation: pin draft revisions (`SPEC-MAP.md`) and treat
  bumps as reviewed changes.

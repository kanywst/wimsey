# CNCF Sandbox readiness

This document tracks `wimsey`'s readiness to apply to the
[CNCF Sandbox](https://github.com/cncf/sandbox) and drafts the application. It is
a living checklist, not a claim of acceptance.

## Why CNCF, and why not a duplicate

WIMSE (Workload Identity in Multi System Environments) is an IETF working group
standardising how workloads authenticate to one another across systems. The WG
publishes specifications but ships no reference code, and the existing
implementations are vendor-tied and almost all in Go.

`wimsey` is a vendor-neutral, spec-faithful reference implementation in Rust,
with cross-implementation conformance vectors other implementers can validate
against. It is **not** a SPIFFE/SPIRE competitor: WIC is compatible with the
X.509-SVID shape, the issuer is scoped to reference/experimentation with a SPIFFE
Workload API shim planned, and the value is a neutral reference plus test
vectors that the whole ecosystem — SPIFFE included — can use. That neutrality is
exactly what a CNCF home protects.

## Criteria checklist

| Criterion | Status | Notes |
| --- | --- | --- |
| OSI-approved license | Done | Apache-2.0 (`LICENSE`) |
| Code of Conduct | Done | CNCF CoC (`CODE_OF_CONDUCT.md`) |
| Governance documented | Done | `GOVERNANCE.md` |
| Maintainers listed | Done | `MAINTAINERS.md` |
| Contributing guide | Done | `CONTRIBUTING.md` (DCO) |
| DCO or CLA | Done | DCO, enforced in CI |
| Security disclosure policy | Done | `SECURITY.md` |
| Adopters page | Done | `ADOPTERS.md` (seeking adopters) |
| Changelog | Done | `CHANGELOG.md` |
| CI: build, lint, test | Done | fmt, clippy (pedantic), tests, doctests |
| Supply-chain: dependency review | Done | Dependabot + `cargo-deny` |
| OpenSSF Scorecard | Done | `.github/workflows/scorecard.yml` |
| OpenSSF Best Practices badge | To do | Register at bestpractices.dev and add the badge |
| Vendor-neutral home | To do | Move from a personal namespace to a neutral org |
| Multi-organization maintainers | To do | Recruit a second maintainer (biggest gap) |
| Roadmap | Done | `ROADMAP.md` |
| Release + versioning | To do | Cut a tagged `0.1.0` under SemVer |

## Known gaps before applying

1. **A single maintainer from one organization.** Sandbox values a vendor-neutral
   committer base. Recruit at least a second maintainer — the SPIFFE sig-spec,
   Defakto, Teleport and Cofide communities are natural places to ask — and get
   `wimsey` listed in the drafts' RFC 7942 implementation-status sections.
2. **Personal namespace.** Move the repository to a neutral GitHub organisation
   before or as part of the donation.
3. **No tagged release yet.** Cut `0.1.0` so there is a referenceable artifact.

## Draft application answers

Answers for the [CNCF Sandbox application](https://github.com/cncf/sandbox)
issue form:

- **Name:** wimsey
- **Description:** A vendor-neutral reference implementation, in Rust, of the
  IETF WIMSE specifications for workload identity — Workload Identity Token,
  Workload Proof Token, the RFC 9421 HTTP Message Signatures binding, and the
  mTLS / Workload Identity Certificate binding — with cross-implementation
  conformance vectors.
- **Alignment with CNCF:** Workload identity is core cloud-native security
  infrastructure. `wimsey` gives the emerging IETF WIMSE standards a neutral
  reference and a conformance suite, complementing SPIFFE/SPIRE rather than
  competing with it.
- **Sandbox, not Incubating:** the project is young and pre-1.0; it seeks a
  neutral home and community, which is what the Sandbox tier is for.
- **License:** Apache-2.0.
- **Existing sponsors/adopters:** none yet; actively seeking maintainers and
  adopters (see `ADOPTERS.md`).

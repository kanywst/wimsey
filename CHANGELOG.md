# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the versioning on
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The project is
pre-1.0, so per SemVer clause 4 the public API is not yet stable: a breaking
change bumps the **minor** and everything else bumps the **patch**. Cargo treats
`0.2` and `0.3` as incompatible, so a breaking release never reaches a caller
silently.

## [Unreleased]

## [0.3.0] - 2026-08-23

The first release published to crates.io, and the one that brings every draft
pin up to the current revision.

Breaking throughout: tokens, signatures and certificates produced by 0.2.0 will
not verify against 0.3.0, and vice versa. Nothing was published before this, so
nothing outside the repository can be relying on the old behaviour.

### Changed

- **Breaking:** draft pins advanced — `http-signature` -03 → -06,
  `workload-creds` -01 → -02, `identifier` -02 → -03, `mutual-tls` -01 → -02.
  See [`SPEC-MAP.md`](SPEC-MAP.md).
- **Breaking:** `wimsey-httpsig` now implements the profile in Section 3 of the
  http-signature draft. `keyid` and `alg` are forbidden signature parameters;
  `created`, `expires`, `nonce`, `tag` (`wimse-workload-to-workload`) and
  `wimse-aud` are mandatory. Enforcement is opt-in via
  `VerifyConfig::wimse_profile`, so the crate still works as a plain RFC 9421
  implementation.
- **Breaking:** `wimsey-wit` requires the `alg` member inside the `cnf` JWK,
  which pins the algorithm the proof of possession must be produced with. A WIT
  without it no longer verifies.
- **Breaking:** `WitClaims.iss`, `.iat` and `.jti` are now `Option`, matching
  workload-creds -02, where only `sub`, `exp` and `cnf` are mandatory. They are
  omitted from the serialization when unset.
- **Breaking:** `ParseError::MissingScheme` is replaced by
  `ParseError::UnsupportedScheme`.
- **Breaking:** `wimsey httpsig sign` drops `--keyid` and gains `--aud`,
  `--nonce`, `--expires-in` and `--sign-response`; `wimsey httpsig verify` gains
  a required `--aud`. `wimsey wit issue --iss` is now optional.
- `wimsey-mtls` issues WICs with the `id-kp-clientAuth` and `id-kp-serverAuth`
  extended key usages the mutual-TLS draft asks for.

### Added

- `wimsey-identifier` supports the `wimse://` scheme defined in Section 4.4 of
  identifier -03 alongside `spiffe://`, and enforces the generic rules of
  Section 4.1: no query, fragment, user-information or port component.
  `WorkloadIdentifier::scheme` and `::origin` are new. Percent-escapes in a
  `wimse` path must be in RFC 3986 Section 6.2.2 normalized form — uppercase
  hex, and never encoding an unreserved character — so that an identifier has
  exactly one spelling and Section 4.3 whole-URI comparison is sound.
- `wimsey-httpsig` models the `@request-target` derived component, which the
  profile requires, and the `wimse-aud`, `wimse-sign-response` and
  `wimse-req-nonce` signature parameters.
- Ten new conformance cases covering the profile's parameter rules and the
  `cnf` JWK algorithm rules: 35 assertions, up from 25.

- `wimsey-demo`, an end-to-end demo of the whole trust chain — a WIT is issued,
  a request is signed, a middlebox forwards it, the far end verifies, and the
  same middlebox is then refused when it reroutes the request. Every step
  asserts and CI runs it, which closes the Phase 4 roadmap gate.
- Conformance vectors for the workload identifier: 22 cases covering both
  schemes, the Section 4.1 prohibitions, and the spellings normalization would
  rewrite. The suite is now 57 assertions, up from 25 before this release.
- A README for every published crate, so the crates.io page is not blank, and
  the Apache-2.0 licence text now ships inside each package as Section 4(a)
  requires.

- **Breaking:** `wimsey-mtls` no longer generates the workload's private key.
  `WorkloadCa::issue` takes the workload's *public* key and returns just the
  certificate; `IssuedWic` and `issue_wic` are gone. A CA that mints the key it
  certifies can impersonate every workload it ever issued to, which is the
  opposite of what a workload identity CA is for.
- **Breaking:** a CA is now loaded from a key the caller keeps —
  `WorkloadCa::from_ed25519` or `::from_pkcs8_der` — so it survives a restart
  with the same certificate. `WorkloadCa::generate` remains for tests and demos
  and now takes a validity window, as does every other certificate this crate
  mints; the previous default ran to the year 4096.
- Conformance vectors for the WIC: 8 cases, including a validly signed
  certificate that carries no workload identifier. Byte-exact re-issuance is
  possible precisely because issuance no longer invents a key. Every protocol
  element now has vectors, and the suite is 65 assertions.

### Known gaps

- Response signing (`@status`, `;req` components, `wimse-req-nonce` on a
  response) is parsed and carried but not yet produced or verified.
- ES256, which workload-creds -02 requires general-purpose implementations to
  support, is recognised and reported as unsupported rather than implemented.
  This crate remains Ed25519-only so that signing stays deterministic.

## [0.2.0] - 2026-08-16

No protocol behaviour changed in this release: token and signature encodings are
byte-for-byte identical to 0.1.0 and the committed conformance vectors are
unchanged. The version bump is driven by a dependency whose types are part of the
public API.

### Changed

- **Breaking:** `ed25519-dalek` updated from 2.2 to 3.0. `wimsey-wit`,
  `wimsey-wpt` and `wimsey-httpsig` re-export `SigningKey` and `VerifyingKey`
  from that crate, so callers holding `ed25519-dalek` 2.x keys must upgrade in
  step for the types to line up.
- `base64` updated from 0.22 to 0.23. Internal only — the URL-safe no-pad /
  standard alphabet split described in the docs is unaffected.

## [0.1.0] - 2026-07-07

### Added

- `wimsey-identifier`: a SPIFFE-ID compatible workload identifier parser.
- `wimsey-wit`: Workload Identity Token issuance and verification (EdDSA), with
  a mandatory `cnf` proof-of-possession key and an injected clock.
- `wimsey-wpt`: Workload Proof Token, bound to a WIT via `wth`.
- `wimsey-httpsig`: the RFC 9421 HTTP Message Signatures binding, verified
  byte-for-byte against the RFC's worked example.
- `wimsey-mtls`: Workload Identity Certificate (WIC) issuance and verification —
  an X.509-SVID with a URI SAN, checked against a CA.
- `wimsey-cli`: the `wimsey` command-line tool (`key`, `wit`, `wpt`, `httpsig`).
- `wimsey-issuer`: an experimental HTTP WIT issuer with a `/jwks` endpoint.
- Conformance vectors for WIT, WPT and the HTTP signature binding, gated for
  freshness in CI.
- Project governance, security policy, contributing guide (DCO), and OpenSSF
  Scorecard automation.

[Unreleased]: https://github.com/kanywst/wimsey/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/kanywst/wimsey/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/kanywst/wimsey/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kanywst/wimsey/releases/tag/v0.1.0

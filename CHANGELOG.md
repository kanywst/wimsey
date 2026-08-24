# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the versioning on
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The project is
pre-1.0, so per SemVer clause 4 the public API is not yet stable: a breaking
change bumps the **minor** and everything else bumps the **patch**. Cargo treats
`0.2` and `0.3` as incompatible, so a breaking release never reaches a caller
silently.

## [Unreleased]

## [0.4.0] - 2026-08-25

Three breaking changes, so per the pre-1.0 rule this is a minor bump. Cargo
treats `0.3` and `0.4` as incompatible, so nothing picks this up silently.

Between them they close the two remaining algorithm and protocol gaps against
the pinned drafts: response signing for `http-signature-06`, and ES256 for
`workload-creds-02`. `SPEC-MAP.md`'s known divergences are down from three to
two, and both survivors are mTLS certificate concerns the mutual-TLS draft does
not actually require.

### Changed

- **Breaking:** the conformance vector format is now `wimse-conformance/v2`.
  Keys are recorded as JWKs rather than raw bytes, because raw bytes do not say
  which algorithm they are for and so left nowhere to put an ES256 vector. The
  key fields are renamed accordingly — `issuer_signing_key_seed_b64u` becomes
  `issuer_signing_key`, and likewise across the WPT, httpsig and mTLS vectors —
  and the `*-basic` token vectors are replaced by `*-eddsa` and `*-es256`.
  Consumers already reject a `format` they do not recognise, so this is a
  declared change rather than a silent one.
- **Breaking:** `PrivateJwk`'s `Debug` redacts the private component. It
  previously printed `d` in full, which was a regression against the CLI key
  type it replaced; serializing still writes it, since that is the type's
  purpose.

### Added

- **ES256 support**, which closes the last algorithm divergence:
  `draft-ietf-wimse-workload-creds-02` Section 5.1 requires it of
  general-purpose implementations, and the draft's own example WIT is signed
  with it. WIT, WPT and the HTTP-signature binding all accept it, in any
  combination — an EdDSA issuer with an ES256 confirmation key is exactly the
  draft's example shape.

  The invariant survives: ECDSA is normally non-deterministic, but the RFC 6979
  nonce derivation makes ES256 signatures reproducible, so conformance vectors
  can still record signature bytes. There is a test asserting it for both
  algorithms.

- `wimsey-jose`, a new crate holding the keys, algorithms and JWK that WIT, WPT
  and httpsig share. They previously each re-exported `ed25519-dalek`'s key
  types, which made a second algorithm a change in three places.

  `Jwk::to_verifying_key` dispatches on `alg` and then requires `kty` and `crv`
  to agree. Reading the key type first and treating `alg` as a hint would let a
  token name one algorithm and be verified under another.

- `wimsey key generate --alg ES256`, and key files in the `EC` / `P-256` shape
  alongside `OKP` / `Ed25519`.

- A `jwk_parse` fuzz target. A JWK is untrusted input twice over — inside a
  WIT's `cnf` claim and inside a fetched JWKS — and the target asserts that
  anything which decodes survives a round trip back to the same key.

- ES256 conformance vectors for WIT, WPT and the HTTP-signature binding, and a
  `declared-algorithm` check so a vector cannot name one algorithm while
  carrying keys for another. That check exists because it happened: the field
  regenerated identically every time and nothing read it, so both CI gates
  stayed green while the vector lied to its only audience. 118 assertions, up
  from 71.

- Fuzz targets for every parser that reads untrusted bytes, seeded from the
  conformance vectors rather than from committed blobs, with a 30-second
  regression run per target in CI.

- Response signing for `wimsey-httpsig`, closing the last gap against
  `http-signature-06`: the `@status` and `;req` covered components, the
  `wimse-req-nonce` parameter, `check_response_profile`, and
  `VerifyConfig::wimse_response_profile` / `::expected_req_nonce`. Sign an
  `HttpExchange` — a response together with the request it answers — so the
  `;req` components resolve from that request and a signed response cannot be
  lifted onto a different one.
- Conformance coverage for the four gaps Yaron Sheffer reported after running
  the vectors against his own RFC 9421 implementation: a signed-response vector
  with its two bindings, `wimse-sign-response` on the golden request, and a
  `missing-created` negative. The httpsig negatives now recover the
  proof-of-possession key from the WIT rather than from the vector's seed, so an
  implementation cannot skip the WIT-before-signature ordering and still pass.
  71 assertions, up from 65.

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

[Unreleased]: https://github.com/kanywst/wimsey/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/kanywst/wimsey/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/kanywst/wimsey/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/kanywst/wimsey/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kanywst/wimsey/releases/tag/v0.1.0

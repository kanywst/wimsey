# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it
reaches a first release.

## [Unreleased]

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

[Unreleased]: https://github.com/kanywst/wimsey/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kanywst/wimsey/releases/tag/v0.1.0

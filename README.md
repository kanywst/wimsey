# wimsey

[![ci](https://github.com/kanywst/wimsey/actions/workflows/ci.yml/badge.svg)](https://github.com/kanywst/wimsey/actions/workflows/ci.yml)

A vendor-neutral WIMSE reference implementation in Rust.

[WIMSE](https://datatracker.ietf.org/wg/wimse/about/) (Workload Identity in
Multi System Environments) is an IETF working group standardising how software
workloads prove their identity to one another. `wimsey` implements the WIMSE
credential formats and transport bindings as a clean, spec-faithful Rust
workspace, with cross-implementation conformance vectors so other implementers
can test against it.

> Status: pre-alpha. The specs are Internet-Drafts (no RFC yet) and `wimsey`
> pins specific draft revisions — see [`SPEC-MAP.md`](SPEC-MAP.md). Nothing here
> is production-ready.

## Why this exists

The IETF WIMSE working group publishes specs but no reference code. Existing
implementations are vendor-tied and mostly Go (SPIFFE/SPIRE, Teleport, Defakto,
Cofide). `wimsey` aims to be a neutral, readable, conformance-tested
implementation that any vendor can validate against, and a candidate for
donation to a neutral home (e.g. CNCF Sandbox).

## Workspace layout

| Crate | Purpose | Spec |
| --- | --- | --- |
| `wimsey-identifier` | Workload Identifier URI scheme | `draft-ietf-wimse-identifier` |
| `wimsey-wit` | Workload Identity Token + Certificate | `draft-ietf-wimse-workload-creds` |
| `wimsey-wpt` | Workload Proof Token (PoP) | `draft-ietf-wimse-wpt` |
| `wimsey-httpsig` | HTTP Message Signatures binding | `draft-ietf-wimse-http-signature` |
| `wimsey-mtls` | Mutual TLS binding | `draft-ietf-wimse-mutual-tls` |
| `wimsey-issuer` | Experimental issuer + SPIFFE Workload API shim | — |
| `wimsey-cli` | The `wimsey` command-line tool | — |

## Building

```bash
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p wimsey-cli
```

## Using the `wimsey` CLI

The `wimsey` binary ties the crates together. Keys are Ed25519, stored as OKP
JSON Web Keys.

```bash
# Generate an issuer key and a workload proof-of-possession key.
cargo run -p wimsey-cli -- key generate --out issuer.jwk
cargo run -p wimsey-cli -- key generate --out pop.jwk

# Issue a Workload Identity Token (its cnf is the pop public key).
wimsey wit issue --issuer-key issuer.jwk --cnf-key pop.jwk \
  --sub spiffe://example.org/api --iss https://issuer.example > wit.txt

# Verify it, or decode it without verifying.
wimsey wit verify --issuer-jwk issuer.jwk --token-file wit.txt
wimsey wit inspect --token-file wit.txt

# Create a Workload Proof Token bound to the WIT, then verify the pair.
wimsey wpt new --pop-key pop.jwk --wit "$(cat wit.txt)" \
  --aud https://service.example/transfer > wpt.txt
wimsey wpt verify --issuer-jwk issuer.jwk --wit "$(cat wit.txt)" \
  --aud https://service.example/transfer --proof "$(cat wpt.txt)"
```

`wpt verify` verifies the WIT with the issuer key first, then checks the proof
against the WIT's confirmation key — success establishes the workload identity,
not merely possession of some key.

## Roadmap

See [`ROADMAP.md`](ROADMAP.md) for the phased plan from scaffold to CNCF
Sandbox readiness.

## Contributing

Contributions are welcome under the [DCO](CONTRIBUTING.md). Please read the
[Code of Conduct](CODE_OF_CONDUCT.md) and [security policy](SECURITY.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

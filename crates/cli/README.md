# wimsey-cli

**The `wimsey` command-line tool.**

A command-line tool for WIMSE credentials, useful for inspecting them,
producing fixtures, and checking another implementation by hand.

```bash
cargo install wimsey-cli

wimsey key generate --out issuer.jwk
wimsey key generate --out pop.jwk

wimsey wit issue --issuer-key issuer.jwk --cnf-key pop.jwk \
  --sub wimse://example.org/api > wit.txt

wimsey httpsig sign --pop-key pop.jwk --authority service.example \
  --path /transfer --wit "$(cat wit.txt)" \
  --aud https://service.example/transfer
```

Subcommands: `key`, `wit`, `wpt`, `httpsig`. Run `wimsey --help` for the rest.

Part of [`wimsey`](https://github.com/kanywst/wimsey), a vendor-neutral reference
implementation of the IETF [WIMSE](https://datatracker.ietf.org/wg/wimse/about/)
workload-identity drafts, in Rust.

> **Pre-alpha.** The specs are Internet-Drafts, not RFCs. This crate pins one
> revision; see [`SPEC-MAP.md`](https://github.com/kanywst/wimsey/blob/main/SPEC-MAP.md)
> for the pin and for the requirements it does not yet meet.

All signing is EdDSA over Ed25519, which is deterministic, so output is
byte-for-byte reproducible. Time is injected rather than read from a clock, so
verification is reproducible too. Cross-implementation test vectors live in
[`conformance/`](https://github.com/kanywst/wimsey/tree/main/conformance).

Licensed under Apache-2.0.

# wimsey-issuer

**An experimental HTTP issuer for WIMSE credentials.**

> **Experimental.** Reference and experimentation scope only. It binds
> `127.0.0.1` by default, warns loudly about ephemeral keys, and performs **no
> workload attestation** — it will issue a WIT to anyone who asks. Do not put it
> in front of anything that matters.

A small axum service that issues Workload Identity Tokens: `POST /wit`,
`GET /jwks`, `GET /healthz`.

```bash
cargo run -p wimsey-issuer
```

It exists to exercise the protocol end to end. For real workload identity —
attestation, key management, rotation — use a platform built for it, such as
SPIRE.

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

# wimsey-wit

**The WIMSE Workload Identity Token.**

Issues and verifies the Workload Identity Token: a JWT with JOSE header
`typ: wit+jwt`, signed by an identity server, carrying the workload's identifier
in `sub` and a proof-of-possession public key in `cnf`.

```rust
use wimsey_wit::{issue, verify, Confirmation, Jwk, Validation, WitClaims};

let claims = WitClaims {
    iss: Some("https://issuer.example".to_owned()),
    sub: "wimse://example.org/api".parse()?,
    iat: Some(1_700_000_000),
    exp: 1_700_003_600,
    jti: Some("a1b2c3".to_owned()),
    cnf: Confirmation { jwk: Jwk::from_ed25519(&pop_key.verifying_key()) },
};
let token = issue(&claims, Some("issuer-key-1"), &issuer_key)?;
let verified = verify(&token, &issuer_key.verifying_key(), &Validation::at(1_700_000_000))?;
```

A WIT is never a bearer token. The holder must prove possession of the key in
`cnf` on every use — with `wimsey-wpt`, `wimsey-httpsig`, or mTLS — and the
`alg` member inside that `cnf` JWK pins the algorithm the proof must use.

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

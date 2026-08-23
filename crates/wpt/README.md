# wimsey-wpt

**The WIMSE Workload Proof Token.**

Issues and verifies the Workload Proof Token: a short-lived JWT with
`typ: wpt+jwt`, signed by the workload's proof-of-possession key — the private
half of the key its WIT names in `cnf`.

A proof is bound to one WIT and one audience. `wth` is
`base64url(SHA-256(WIT))`, and verification recomputes it from the WIT actually
presented, so a proof cannot be replayed against a different credential or a
different service.

```rust
use wimsey_wpt::{issue, verify, wit_thumbprint, Validation, WptClaims};

let claims = WptClaims {
    aud: "https://service.example/transfer".to_owned(),
    exp: 1_700_000_300,
    jti: "0123456789abcdef".to_owned(),
    wth: wit_thumbprint(wit),
    ath: None,
};
let proof = issue(&claims, &pop_key)?;
verify(&proof, &pop_key.verifying_key(),
       &Validation::new(1_700_000_000, "https://service.example/transfer", wit))?;
```

This is a stateless primitive: it does not track `jti`, so single-use replay
detection is the recipient's job.

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

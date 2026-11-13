# wimsey-wpt

**The WIMSE Workload Proof Token.**

Issues and verifies the Workload Proof Token: a short-lived JWT with
`typ: wpt+jwt`, signed by the workload's proof-of-possession key — the private
half of the key its WIT names in `cnf`.

A proof is bound to one WIT and one audience. `wth` is
`base64url(SHA-256(WIT))`, and verification recomputes it from the WIT actually
presented, so a proof cannot be replayed against a different credential or a
different service. `tth` and `oth` bind a Txn-Token and any other context token
in the request the same way.

```rust
use wimsey_wpt::{issue, scheme, verify, wit_thumbprint, Validation, WptClaims};

let claims = WptClaims {
    aud: "https://service.example/transfer".to_owned(),
    exp: 1_700_000_300,
    jti: "0123456789abcdef".to_owned(),
    wth: wit_thumbprint(wit),
    tth: None,
    oth: None,
};
let proof = issue(&claims, &pop_key)?;

// On the wire: `Authorization: WPT <proof>`.
let authorization = scheme::to_credentials(&proof);

// The recipient takes it back out of the request's one `Authorization` field.
let received = scheme::from_request([authorization.as_str()])?;
verify(received, &pop_key.verifying_key(),
       &Validation::new(1_700_000_000, "https://service.example/transfer", wit))?;
```

This is a stateless primitive: it does not track `jti`, so single-use replay
detection is the recipient's job. It is also not an HTTP server: answering a
rejected proof with `401` and `WWW-Authenticate: WPT` (`scheme::CHALLENGE`) is
the HTTP stack's.

Part of [`wimsey`](https://github.com/kanywst/wimsey), a vendor-neutral reference
implementation of the IETF [WIMSE](https://datatracker.ietf.org/wg/wimse/about/)
workload-identity drafts, in Rust.

> **Pre-alpha.** The specs are Internet-Drafts, not RFCs. This crate pins one
> revision; see [`SPEC-MAP.md`](https://github.com/kanywst/wimsey/blob/main/SPEC-MAP.md)
> for the pin and for the requirements it does not yet meet.

Signing is Ed25519 (RFC 8032, named `Ed25519` per RFC 9864) or ES256 with
RFC 6979 nonces, both deterministic, so output is byte-for-byte reproducible.
Time is injected rather than read from a clock, so verification is
reproducible too. Cross-implementation test vectors live in
[`conformance/`](https://github.com/kanywst/wimsey/tree/main/conformance).

Licensed under Apache-2.0.

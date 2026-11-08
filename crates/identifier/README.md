# wimsey-identifier

**The WIMSE workload identifier URI.**

Parses and validates the workload identifier URI that every other WIMSE
credential carries: `spiffe://<trust-domain>/<path>` as defined by SPIFFE, and
`wimse://<trust-domain>/<path>` as defined in Section 4.4 of the identifier
draft.

```rust
use wimsey_identifier::{Scheme, WorkloadIdentifier};

let id: WorkloadIdentifier = "wimse://trust.example.com/service/payment".parse()?;
assert_eq!(id.scheme(), Scheme::Wimse);
assert_eq!(id.trust_domain(), "trust.example.com");
assert_eq!(id.origin(), "wimse://trust.example.com");
# Ok::<(), wimsey_identifier::ParseError>(())
```

The draft tells consumers to compare *complete* URIs after RFC 3986
normalization. Rather than normalizing, this crate refuses the spellings
normalization would rewrite — an uppercase trust domain and a percent-escape
that is lowercase or encodes an unreserved character — so an accepted
identifier is already in normal form and compares byte for byte. It also
enforces the draft's own rules: a non-empty path (a bare trust domain is an
origin, not an identifier), no `.` or `..` segment, and an internationalized
trust domain written as A-labels.

Part of [`wimsey`](https://github.com/kanywst/wimsey), a vendor-neutral reference
implementation of the IETF [WIMSE](https://datatracker.ietf.org/wg/wimse/about/)
workload-identity drafts, in Rust.

> **Pre-alpha.** The specs are Internet-Drafts, not RFCs. This crate pins one
> revision; see [`SPEC-MAP.md`](https://github.com/kanywst/wimsey/blob/main/SPEC-MAP.md)
> for the pin and for the requirements it does not yet meet.

All signing is Ed25519 (RFC 8032), which is deterministic, so output is
byte-for-byte reproducible. Time is injected rather than read from a clock, so
verification is reproducible too. Cross-implementation test vectors live in
[`conformance/`](https://github.com/kanywst/wimsey/tree/main/conformance).

Licensed under Apache-2.0.

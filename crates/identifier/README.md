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

The draft tells consumers to compare *complete* URIs, which is only sound if an
identifier has exactly one spelling. So rather than normalizing, this crate
refuses the spellings RFC 3986 normalization would rewrite — an uppercase trust
domain, a `.` or `..` segment, and a percent-escape that is lowercase or encodes
an unreserved character.

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

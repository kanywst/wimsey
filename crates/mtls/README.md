# wimsey-mtls

**The WIMSE mutual-TLS binding.**

Issues and verifies the Workload Identity Certificate: an X.509 client
certificate in the X.509-SVID shape, carrying the workload identifier in a URI
subjectAltName and signed by a workload CA.

```rust
use wimsey_mtls::{verify, WorkloadCa};

let ca = WorkloadCa::generate()?;
let wic = ca.issue_wic(&"wimse://example.org/api".parse()?, not_before, not_after)?;
let identifier = verify(&wic.certificate_der, ca.certificate_der(), now)?;
```

`verify` deliberately checks only the CA it is handed. Chain building is the
caller's job, and so is wiring the certificate into a TLS stack — this crate
does not depend on rustls, and does not choose one for you.

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

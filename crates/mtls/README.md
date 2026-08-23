# wimsey-mtls

**The WIMSE mutual-TLS binding.**

Issues and verifies the Workload Identity Certificate: an X.509 client
certificate in the X.509-SVID shape, carrying the workload identifier in a URI
subjectAltName and signed by a workload CA.

```rust
use wimsey_identifier::WorkloadIdentifier;
use wimsey_mtls::{verify, SigningKey, WorkloadCa};

// The CA key is long-lived and kept by the operator, not by this process.
let ca = WorkloadCa::from_ed25519(&ca_key, ca_not_before, ca_not_after)?;

// The workload generates its own key. Only the public half reaches the CA.
let wic = ca.issue(&identifier, &workload_key.verifying_key(), not_before, not_after)?;

let presented = verify(&wic, ca.certificate_der(), now)?;
```

`issue` takes a public key, and there is no API here that returns a private one.
The workload keeps its own key, which is the custody model SPIFFE uses and what
stops a compromised CA from impersonating a workload it already certified — such
a CA can mint new certificates, but it cannot sign as an existing one.

A CA is loaded from a key you keep rather than conjured per process, so the same
key always yields the same CA certificate and a restart does not silently
invalidate every peer's trust anchor. Every certificate takes an explicit
validity window, including the CA's own; the underlying default would run to the
year 4096.

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

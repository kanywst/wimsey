//! `wimsey-mtls` — the WIMSE mutual TLS transport binding.
//!
//! Target spec: `draft-ietf-wimse-mutual-tls-01`. The workload authenticates
//! with a Workload Identity Certificate (WIC): an X.509 client certificate that
//! carries the workload identifier in a URI subjectAltName, signed by a workload
//! CA. This is the X.509-SVID shape SPIFFE uses.
//!
//! This crate issues WICs (Ed25519, CA-signed) and verifies a presented WIC
//! against a CA, returning the workload identifier. Wiring a WIC into a rustls
//! client/server configuration is left to the caller.
//!
//! # Scope and limitations
//!
//! [`verify`] checks that the WIC is signed by the *directly provided* CA
//! (Ed25519), is within its validity window, and carries a URI SAN. It is a
//! single-issuer trust model: it does not build or validate a chain, and does
//! not yet enforce `basicConstraints`, `keyUsage` or name constraints. Callers
//! needing full path validation should use a dedicated X.509 verifier.
//!
//! ```
//! use wimsey_identifier::WorkloadIdentifier;
//! use wimsey_mtls::{verify, WorkloadCa};
//!
//! let ca = WorkloadCa::generate().unwrap();
//! let id = WorkloadIdentifier::parse("spiffe://example.org/api").unwrap();
//! let wic = ca.issue_wic(&id, 1_700_000_000, 1_700_086_400).unwrap();
//!
//! // The peer verifies the presented WIC against the CA and learns who it is.
//! let verified = verify(&wic.certificate_der, ca.certificate_der(), 1_700_000_100).unwrap();
//! assert_eq!(verified.as_str(), "spiffe://example.org/api");
//! ```

mod error;
mod wic;

pub use error::MtlsError;
pub use wic::{verify, workload_identifier, IssuedWic, WorkloadCa};

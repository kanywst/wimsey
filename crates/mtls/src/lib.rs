//! `wimsey-mtls` — the WIMSE mutual TLS transport binding.
//!
//! Target spec: `draft-ietf-wimse-mutual-tls-02`. The workload authenticates
//! with a Workload Identity Certificate (WIC): an X.509 client certificate that
//! carries the workload identifier in a URI subjectAltName, signed by a workload
//! CA. This is the X.509-SVID shape SPIFFE uses.
//!
//! # Key custody
//!
//! The workload generates its own key pair and sends the CA only the public
//! half; [`WorkloadCa::issue`] takes a [`VerifyingKey`] and there is no way to
//! ask this crate for a private key. That is the custody model SPIFFE uses, and
//! it is what keeps a compromised CA from impersonating a workload it already
//! certified — such a CA can mint new certificates, but it cannot sign as an
//! existing one, because it never held that key.
//!
//! For the same reason a CA is loaded from a key the caller keeps
//! ([`WorkloadCa::from_ed25519`] or [`WorkloadCa::from_pkcs8_der`]) rather than
//! conjured per process. The same key always yields the same CA certificate, so
//! a restart does not quietly invalidate every peer's trust anchor.
//! [`WorkloadCa::generate`] exists for tests and demos, where a CA that dies
//! with the process is the point.
//!
//! Every certificate takes an explicit validity window, including the CA's own.
//! The underlying default would be a certificate valid until the year 4096,
//! which is not a lifetime anyone would pick deliberately.
//!
//! Certificates are Ed25519-only. The mutual-TLS draft does not require ES256
//! the way `workload-creds` does for the token path, so a P-256 key is refused
//! by [`WorkloadCa::issue`] rather than certified under an algorithm identifier
//! that would not match it.
//!
//! # Scope and limitations
//!
//! [`verify`] checks that the WIC is signed by the *directly provided* CA
//! (Ed25519), is within its validity window, and carries a URI SAN. It is a
//! single-issuer trust model: it does not build or validate a chain, and does
//! not yet enforce `basicConstraints`, `keyUsage` or name constraints. Callers
//! needing full path validation should use a dedicated X.509 verifier.
//!
//! Wiring a WIC into a rustls client or server configuration is left to the
//! caller; this crate does not depend on rustls and does not pick one.
//!
//! ```
//! use wimsey_identifier::WorkloadIdentifier;
//! use wimsey_mtls::{verify, SigningKey, WorkloadCa};
//!
//! // The CA key is long-lived and kept by the operator, not by this process.
//! let ca_key = SigningKey::from_ed25519_seed(&[3u8; 32]);
//! let ca = WorkloadCa::from_ed25519(&ca_key, 1_600_000_000, 1_900_000_000).unwrap();
//!
//! // The workload generates its own key. Only the public half reaches the CA.
//! let workload_key = SigningKey::from_ed25519_seed(&[7u8; 32]);
//! let id = WorkloadIdentifier::parse("spiffe://example.org/api").unwrap();
//! let wic = ca
//!     .issue(&id, &workload_key.verifying_key(), 1_700_000_000, 1_700_086_400)
//!     .unwrap();
//!
//! // The peer verifies the presented WIC against the CA and learns who it is.
//! let verified = verify(&wic, ca.certificate_der(), 1_700_000_100).unwrap();
//! assert_eq!(verified.as_str(), "spiffe://example.org/api");
//! ```

mod error;
mod wic;

pub use error::MtlsError;
pub use wic::{verify, workload_identifier, WorkloadCa};

// Re-exported so callers can name the key types without a direct dependency.
pub use wimsey_jose::{Algorithm, SigningKey, VerifyingKey};

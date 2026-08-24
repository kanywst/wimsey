//! `wimsey-wit` — WIMSE Workload Identity Token (WIT) issuance and verification.
//!
//! Target spec: `draft-ietf-wimse-workload-creds-02`. A WIT is a JWT with JOSE
//! header `typ: wit+jwt`, signed by an issuer, carrying the workload's
//! identifier in `sub` and a proof-of-possession key in `cnf`.
//!
//! Only `sub`, `exp` and `cnf` are mandatory; `iss`, `iat` and `jti` are
//! optional and are omitted from the serialization when unset. The `cnf` JWK
//! must carry an `alg` member, which pins the algorithm the proof of possession
//! has to be produced with.
//!
//! Signing uses `EdDSA` (Ed25519) or `ES256` (ECDSA P-256), the latter because
//! Section 5.1 requires it of general-purpose implementations. Both are
//! deterministic — ES256 through its RFC 6979 nonce — so a token is
//! byte-for-byte reproducible for a given key and input. See the conformance
//! vectors under `conformance/wit/`.
//!
//! The header's `alg` follows the signing key, and verification requires it to
//! match the key presented, so a token cannot name one algorithm and be checked
//! under another.
//!
//! ```
//! use wimsey_identifier::WorkloadIdentifier;
//! use wimsey_wit::{issue, verify, Confirmation, Jwk, SigningKey, Validation, WitClaims};
//!
//! let issuer_key = SigningKey::from_ed25519_seed(&[1u8; 32]);
//! let pop_key = SigningKey::from_p256_scalar(&[7u8; 32])?;
//!
//! let claims = WitClaims {
//!     iss: Some("https://issuer.example".to_owned()),
//!     sub: WorkloadIdentifier::parse("spiffe://example.org/api").unwrap(),
//!     iat: Some(1_700_000_000),
//!     exp: 1_700_003_600,
//!     jti: Some("a1b2c3".to_owned()),
//!     cnf: Confirmation { jwk: Jwk::from_verifying_key(&pop_key.verifying_key()) },
//! };
//!
//! let token = issue(&claims, Some("issuer-key-1"), &issuer_key)?;
//! let verified = verify(&token, &issuer_key.verifying_key(), &Validation::at(1_700_000_000))?;
//! assert_eq!(verified.claims.sub.trust_domain(), "example.org");
//!
//! // The confirmation key is an ES256 key, recovered ready to check a proof.
//! assert_eq!(verified.pop_key, pop_key.verifying_key());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod claims;
mod error;
mod token;

pub use claims::{Confirmation, WitClaims};
pub use error::WitError;
pub use token::{issue, verify, Validation, VerifiedWit, ALG, TYP};

// Re-exported so callers can name the key and JWK types without a direct
// dependency on `wimsey-jose`.
pub use wimsey_jose::{Algorithm, Jwk, SigningKey, VerifyingKey};

/// Returns the current time in seconds since the Unix epoch.
///
/// Provided as a convenience for callers building a [`Validation`]; the
/// verification path itself takes the time explicitly so it stays
/// deterministic.
#[must_use]
pub fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

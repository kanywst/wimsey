//! `wimsey-wpt` — WIMSE Workload Proof Token (WPT) issuance and verification.
//!
//! Target spec: `draft-ietf-wimse-wpt-01`. A WPT is a short-lived JWT with JOSE
//! header `typ: wpt+jwt`, signed by the workload's proof-of-possession key — the
//! key whose public half is carried in the bound WIT's `cnf` claim. It proves
//! the presenter holds that key for a specific audience and a specific WIT.
//!
//! The mandatory claims are `aud`, `exp`, `jti` and `wth`, where `wth` is the
//! Base64url-encoded SHA-256 hash of the WIT's ASCII value. Verification
//! recomputes `wth` from the presented WIT and checks the audience, so a proof
//! cannot be replayed against a different WIT or a different service.
//!
//! Signatures use `EdDSA` (Ed25519) and are deterministic, so a proof is
//! byte-for-byte reproducible for a given key and input.
//!
//! ```
//! use ed25519_dalek::SigningKey;
//! use wimsey_wpt::{issue, verify, wit_thumbprint, Validation, WptClaims};
//!
//! // The workload's proof-of-possession key (its public half is in the WIT cnf).
//! let pop_key = SigningKey::from_bytes(&[9u8; 32]);
//! let wit = "eyJ0eXAiOiJ3aXQrand0In0.payload.signature";
//!
//! let claims = WptClaims {
//!     aud: "https://workload.example.com/path".to_owned(),
//!     exp: 1_700_000_300,
//!     jti: "0123456789abcdef".to_owned(),
//!     wth: wit_thumbprint(wit),
//!     ath: None,
//! };
//!
//! let proof = issue(&claims, &pop_key).unwrap();
//!
//! let validation = Validation::new(1_700_000_000, "https://workload.example.com/path", wit);
//! let verified = verify(&proof, &pop_key.verifying_key(), &validation).unwrap();
//! assert_eq!(verified.claims.aud, "https://workload.example.com/path");
//! ```

mod claims;
mod error;
mod token;

pub use claims::WptClaims;
pub use error::WptError;
pub use token::{issue, verify, wit_thumbprint, Validation, VerifiedWpt, ALG, MAX_TOKEN_LEN, TYP};

// Re-exported so callers can name the key types without a direct dependency.
pub use ed25519_dalek::{SigningKey, VerifyingKey};

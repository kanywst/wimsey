//! `wimsey-jose` — the keys and signatures the WIMSE credential formats share.
//!
//! WIT, WPT and the HTTP-signature binding all need the same two things: a key
//! that can sign or verify, and a JWK to carry the public half in. This crate
//! holds them once so the three cannot drift apart, and so that adding an
//! algorithm is one change rather than three.
//!
//! Two algorithms are supported. `EdDSA` over Ed25519 is what this workspace
//! prefers, and `ES256` is there because Section 5.1 of
//! `draft-ietf-wimse-workload-creds` requires it of general-purpose
//! implementations, which is also the practical interop baseline.
//!
//! # Both are deterministic
//!
//! Ed25519 is deterministic by construction. ECDSA normally is not — it draws a
//! random nonce — but the RFC 6979 derivation used here computes that nonce from
//! the key and the message instead. So signing the same input twice produces the
//! same bytes under either algorithm, which is the property the conformance
//! vectors are built on.
//!
//! ```
//! use wimsey_jose::{Algorithm, Jwk, SigningKey};
//!
//! let key = SigningKey::from_p256_scalar(&[7u8; 32])?;
//! assert_eq!(key.algorithm(), Algorithm::Es256);
//! assert_eq!(key.sign(b"payload"), key.sign(b"payload"));
//!
//! let jwk = Jwk::from_verifying_key(&key.verifying_key());
//! assert_eq!(jwk.to_verifying_key()?, key.verifying_key());
//! # Ok::<(), wimsey_jose::JoseError>(())
//! ```

mod error;
mod jwk;
mod key;

pub use error::JoseError;
pub use jwk::{Jwk, PrivateJwk};
pub use key::{Algorithm, SigningKey, VerifyingKey, SIGNATURE_LEN};

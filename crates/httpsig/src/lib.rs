//! `wimsey-httpsig` — the WIMSE HTTP Message Signatures transport binding.
//!
//! Target spec: `draft-ietf-wimse-http-signature-03`, a profile of RFC 9421.
//! The calling workload signs the outgoing HTTP request — including the header
//! that carries its WIT — with its proof-of-possession key, so an intermediary
//! can read but not tamper with the covered components. The receiver recovers
//! the key from the WIT's `cnf` claim and verifies the signature.
//!
//! This crate implements the RFC 9421 signature base (Section 2.5) for the
//! derived components `@method`, `@authority`, `@path` and `@query` plus header
//! fields, signs with `ed25519` (Section 3.3.6), and serializes the
//! `Signature-Input` and `Signature` fields. The signature base is verified
//! byte-for-byte against the RFC's worked example.
//!
//! # Caller responsibilities and limitations
//!
//! - Verifying a signature proves only that the covered components were signed.
//!   Set [`VerifyConfig::required_components`] to demand the components you care
//!   about (`@method`, `@authority`, `@path`, `content-digest`, and the WIT
//!   header for the WIMSE profile).
//! - Covering `content-digest` protects only the header string. To bind the
//!   body, also call [`verify_content_digest`] over the received body.
//! - Exactly one signature per `Signature`/`Signature-Input` field is supported.
//! - `@authority` is lowercased but its default port is not stripped; pass a
//!   normalized authority.
//! - Freshness and replay defense (`nonce`, bounded `created` age) are the
//!   caller's responsibility; see [`VerifyConfig::max_age`].
//!
//! ```
//! use ed25519_dalek::SigningKey;
//! use wimsey_httpsig::{
//!     content_digest_sha256, sign, verify, verify_content_digest, Component, HttpRequest,
//!     SignatureParams, VerifyConfig, ALG,
//! };
//!
//! let pop_key = SigningKey::from_bytes(&[5u8; 32]);
//! let body = br#"{"hello":"world"}"#;
//!
//! let request = HttpRequest {
//!     method: "POST".to_owned(),
//!     authority: "service.example".to_owned(),
//!     path: "/transfer".to_owned(),
//!     query: None,
//!     headers: vec![
//!         ("Content-Digest".to_owned(), content_digest_sha256(body)),
//!         ("Workload-Identity-Token".to_owned(), "eyJ0eXAi.wit.value".to_owned()),
//!     ],
//! };
//! let components = vec![
//!     Component::Method,
//!     Component::Authority,
//!     Component::Path,
//!     Component::header("content-digest"),
//!     Component::header("workload-identity-token"),
//! ];
//! let params = SignatureParams {
//!     created: Some(1_700_000_000),
//!     keyid: Some("issuer-key-1".to_owned()),
//!     alg: Some(ALG.to_owned()),
//!     ..SignatureParams::default()
//! };
//!
//! let signed = sign(&request, &components, &params, "wimse", &pop_key).unwrap();
//!
//! // The receiver requires the critical components to be covered, and binds the
//! // body by checking the content-digest against it.
//! let config = VerifyConfig {
//!     now: Some(1_700_000_030),
//!     required_components: vec![
//!         Component::Method,
//!         Component::Path,
//!         Component::header("content-digest"),
//!         Component::header("workload-identity-token"),
//!     ],
//!     ..VerifyConfig::default()
//! };
//! let verified =
//!     verify(&request, &signed.signature_input, &signed.signature, &pop_key.verifying_key(), &config)
//!         .unwrap();
//! assert_eq!(verified.label, "wimse");
//! assert!(verify_content_digest("sha-256=:invalid:", body) == false);
//! ```

mod error;
mod message;
mod signature;

pub use error::HttpSigError;
pub use message::{content_digest_sha256, verify_content_digest, Component, HttpRequest};
pub use signature::{
    sign, signature_base, verify, SignatureParams, SignedSignature, VerifiedSignature,
    VerifyConfig, ALG,
};

// Re-exported so callers can name the key types without a direct dependency.
pub use ed25519_dalek::{SigningKey, VerifyingKey};

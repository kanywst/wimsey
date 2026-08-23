//! `wimsey-httpsig` — the WIMSE HTTP Message Signatures transport binding.
//!
//! Target spec: `draft-ietf-wimse-http-signature-06`, a profile of RFC 9421.
//! The calling workload signs the outgoing HTTP request — including the header
//! that carries its WIT — with its proof-of-possession key, so an intermediary
//! can read but not tamper with the covered components. The receiver recovers
//! the key from the WIT's `cnf` claim and verifies the signature.
//!
//! This crate implements the RFC 9421 signature base (Section 2.5) for the
//! derived components `@method`, `@authority`, `@path`, `@query` and
//! `@request-target` plus header fields, signs with Ed25519, and serializes the
//! `Signature-Input` and `Signature` fields. The signature base is verified
//! byte-for-byte against the RFC's worked example.
//!
//! # The WIMSE profile
//!
//! Section 3 of the draft narrows RFC 9421 considerably. Set
//! [`VerifyConfig::wimse_profile`] to enforce it, or call
//! [`check_request_profile`] directly:
//!
//! - `@method` and `@request-target` MUST be covered, along with `Content-Type`,
//!   `Content-Digest`, `Authorization`, `Txn-Token` and `Workload-Identity-Token`
//!   whenever the message carries them.
//! - `created`, `expires`, `nonce` and `tag` MUST all be present, with `tag`
//!   equal to [`WIMSE_TAG`] and a tight `expires` window (minutes, not hours).
//! - `wimse-aud` MUST be present on a request, naming the service the signature
//!   is for. A verifier binds itself to that audience with
//!   [`VerifyConfig::expected_audience`].
//! - `keyid` and `alg` MUST NOT be used: the key travels in the WIT and its
//!   `cnf` JWK pins the algorithm, so repeating either would only add confusion.
//!
//! The profile is off by default, so the crate can also be driven as a plain
//! RFC 9421 implementation.
//!
//! # Caller responsibilities and limitations
//!
//! - Verifying a signature proves only that the covered components were signed.
//!   Set [`VerifyConfig::required_components`] to demand the components you care
//!   about.
//! - Covering `content-digest` protects only the header string. To bind the
//!   body, also call [`verify_content_digest`] over the received body.
//! - Exactly one signature per `Signature`/`Signature-Input` field is supported.
//! - `@authority` is lowercased but its default port is not stripped; pass a
//!   normalized authority.
//! - Response signing (`@status`, `;req` components and `wimse-req-nonce`) is
//!   not implemented yet; [`SignatureParams::wimse_req_nonce`] is carried and
//!   verified, but this crate models requests only.
//! - Replay defense is the caller's: this crate checks that a `nonce` is present
//!   but does not remember the ones it has seen.
//!
//! ```
//! use ed25519_dalek::SigningKey;
//! use wimsey_httpsig::{
//!     content_digest_sha256, sign, verify, verify_content_digest, Component, HttpRequest,
//!     SignatureParams, VerifyConfig, WIMSE_TAG,
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
//!     Component::RequestTarget,
//!     Component::header("content-digest"),
//!     Component::header("workload-identity-token"),
//! ];
//! let params = SignatureParams {
//!     created: Some(1_700_000_000),
//!     expires: Some(1_700_000_300),
//!     nonce: Some("abcd1111".to_owned()),
//!     tag: Some(WIMSE_TAG.to_owned()),
//!     wimse_aud: Some("https://service.example/transfer".to_owned()),
//!     ..SignatureParams::default()
//! };
//!
//! let signed = sign(&request, &components, &params, "wimse", &pop_key).unwrap();
//!
//! // The receiver enforces the profile, pins the audience it answers to, and
//! // binds the body by checking the content-digest against it.
//! let config = VerifyConfig {
//!     now: Some(1_700_000_030),
//!     required_components: components.clone(),
//!     wimse_profile: true,
//!     expected_audience: Some("https://service.example/transfer".to_owned()),
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
    check_request_profile, sign, signature_base, verify, SignatureParams, SignedSignature,
    VerifiedSignature, VerifyConfig, ALG, WIMSE_LABEL, WIMSE_TAG,
};

// Re-exported so callers can name the key types without a direct dependency.
pub use ed25519_dalek::{SigningKey, VerifyingKey};

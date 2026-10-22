//! `wimsey-httpsig` — the WIMSE HTTP Message Signatures transport binding.
//!
//! Target spec: `draft-ietf-wimse-http-signature-08`, a profile of RFC 9421.
//! The calling workload signs the outgoing HTTP request — including the header
//! that carries its WIT — with its proof-of-possession key, so an intermediary
//! can read but not tamper with the covered components. The receiver recovers
//! the key from the WIT's `cnf` claim and verifies the signature.
//!
//! This crate implements the RFC 9421 signature base (Section 2.5) for the
//! derived components `@method`, `@authority`, `@path`, `@query` and
//! `@request-target`, `@status` and `;req`, plus header fields; signs with the
//! key's algorithm (Ed25519 or ES256); and serializes the `Signature-Input` and
//! `Signature` fields. The signature base is verified byte-for-byte against the
//! RFC's worked example.
//!
//! # The WIMSE profile
//!
//! Section 3 of the draft narrows RFC 9421 considerably. Set
//! [`VerifyConfig::wimse_profile`] to enforce it, or call
//! [`check_request_profile`] directly:
//!
//! - `@method`, `@path` and `@query` MUST be covered, along with `Content-Type`,
//!   `Content-Digest`, `Authorization`, `Txn-Token` and `Workload-Identity-Token`
//!   whenever the message carries them — [`request_components`] builds that set.
//!   `@authority` is not covered, because proxies rewrite it.
//! - A `CONNECT` is the exception: its target is `host:port`, so it covers
//!   `@method` and `@authority` instead and MUST NOT cover `@path` or `@query`
//!   (`@authority;req` in place of `@path;req` and `@query;req` on the signed
//!   response). [`request_components`] and [`response_components`] switch on the
//!   method, and the profile rejects a `CONNECT` covering what it forbids.
//! - `created`, `expires`, `nonce` and `tag` MUST all be present, with `tag`
//!   equal to [`WIMSE_TAG`] and a tight `expires` window (minutes, not hours).
//! - `wimse-aud` MUST be present on a request, naming the service the signature
//!   is for. A verifier binds itself to the audiences it answers to with
//!   [`VerifyConfig::expected_audiences`], compared by Simple String Comparison
//!   (RFC 3986 Section 6.2.1) — no normalization, so list every spelling.
//!   Under the profile the list is mandatory: left empty, every request fails.
//! - Each `nonce` MUST come from a CSPRNG with at least 64 bits of entropy. The
//!   crate signs the nonce it is handed and stays deterministic, so drawing one
//!   is the caller's.
//! - `keyid` and `alg` MUST NOT be used: the key travels in the WIT and its
//!   `cnf` JWK pins the algorithm, so repeating either would only add confusion.
//!   [`VerifyConfig::accepted_algorithms`] is the recipient's policy on which
//!   of those algorithms it accepts.
//! - The WIMSE signature is the one tagged [`WIMSE_TAG`], found by that tag and
//!   never by label, so an intermediary may add a signature of its own. Two
//!   signatures carrying the tag are rejected.
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
//! - `@authority` is lowercased but its default port is not stripped; pass a
//!   normalized authority.
//! - Response signing is supported: sign an [`HttpExchange`] rather than an
//!   [`HttpRequest`] over [`response_components`], enforce
//!   [`VerifyConfig::wimse_response_profile`], and check the returned nonce with
//!   [`VerifyConfig::expected_req_nonce`]. Rejecting an *unsigned* response to a
//!   request that set `wimse-sign-response` is the caller's, since there is no
//!   signature to hand this crate.
//! - Replay defense is the caller's: this crate checks that a `nonce` is present
//!   but does not remember the ones it has seen.
//! - Answering a failure is the server's. Any failed check on a signed request —
//!   the WIT or the signature, whichever [`HttpSigError`] it is — is a `400`
//!   with the [`PROBLEM_SIGNATURE_INVALID`] problem type, and the response MUST
//!   NOT say which check failed. A server that cannot honor
//!   `wimse-sign-response` answers `501` with
//!   [`PROBLEM_SIGNED_RESPONSE_UNSUPPORTED`], or `400` with
//!   [`PROBLEM_SIGNED_RESPONSE_UNAVAILABLE`] when it signs responses but not
//!   this one — never a successful unsigned response.
//!
//! ```
//! use wimsey_httpsig::{
//!     content_digest_sha256, request_components, sign, verify, verify_content_digest,
//!     HttpRequest, SignatureParams, SigningKey, VerifyConfig, WIMSE_TAG,
//! };
//!
//! let pop_key = SigningKey::from_ed25519_seed(&[5u8; 32]);
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
//! // `@method`, `@path`, `@query`, and the two headers the request carries.
//! let components = request_components(&request);
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
//!     expected_audiences: vec!["https://service.example/transfer".to_owned()],
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

pub use error::{
    HttpSigError, PROBLEM_SIGNATURE_INVALID, PROBLEM_SIGNED_RESPONSE_UNAVAILABLE,
    PROBLEM_SIGNED_RESPONSE_UNSUPPORTED,
};
pub use message::{
    content_digest_sha256, verify_content_digest, Component, ComponentSource, HttpExchange,
    HttpRequest, HttpResponse,
};
pub use signature::{
    check_request_profile, check_response_profile, request_components, response_components, sign,
    signature_base, verify, SignatureParams, SignedSignature, VerifiedSignature, VerifyConfig, ALG,
    WIMSE_LABEL, WIMSE_TAG,
};

// Re-exported so callers can name the key types without a direct dependency.
pub use wimsey_jose::{Algorithm, SigningKey, VerifyingKey};

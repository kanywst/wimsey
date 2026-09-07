//! Compact-JWS issuance and verification of Workload Proof Tokens.

use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wimsey_jose::{Algorithm, SigningKey, VerifyingKey, SIGNATURE_LEN};

use crate::claims::WptClaims;
use crate::error::WptError;

/// The JOSE `typ` of a Workload Proof Token.
pub const TYP: &str = "wpt+jwt";

/// The signature algorithm this crate prefers.
///
/// Not the only one: the proof must be produced with whatever the bound WIT's
/// `cnf` JWK names, which may be `ES256`. The algorithm is taken from the key.
pub const ALG: &str = "EdDSA";

/// The maximum accepted size, in bytes, of a compact WPT serialization.
pub const MAX_TOKEN_LEN: usize = 8192;

#[derive(Serialize, Deserialize)]
struct Header {
    typ: String,
    alg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    crit: Option<Vec<String>>,
}

/// The Base64url-encoded SHA-256 hash of a token's ASCII value, as used by the
/// `wth`, `tth` and `oth` claims.
fn sha256_b64u(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

/// Computes the `wth` value for a WIT: the Base64url-encoded SHA-256 hash of the
/// WIT's ASCII value.
#[must_use]
pub fn wit_thumbprint(wit: &str) -> String {
    sha256_b64u(wit)
}

/// Computes the `tth` value for a Txn-Token: the Base64url-encoded SHA-256 hash
/// of the token's ASCII value.
#[must_use]
pub fn txn_token_thumbprint(txn_token: &str) -> String {
    sha256_b64u(txn_token)
}

/// Computes an `oth` entry for a context token carried in an HTTP header field.
///
/// Returns the lowercased field name and the Base64url-encoded SHA-256 hash of
/// the field value with leading and trailing spaces removed, which is the
/// normalization the draft specifies (§2) in the absence of an application
/// profile saying otherwise.
#[must_use]
pub fn other_token_entry(header_name: &str, header_value: &str) -> (String, String) {
    (
        header_name.to_ascii_lowercase(),
        sha256_b64u(header_value.trim_matches(' ')),
    )
}

/// Parameters controlling WPT verification.
///
/// A WPT is only meaningful against a specific audience and a specific WIT, so
/// both are required. `now` is injected for deterministic time checks.
#[derive(Debug, Clone)]
pub struct Validation<'a> {
    /// The current time, in seconds since the Unix epoch.
    pub now: u64,
    /// Clock-skew tolerance, in seconds, applied to `exp`.
    pub leeway: u64,
    /// The audience the proof must be addressed to: the request target URI with
    /// query and fragment removed. The caller must strip those before passing
    /// it, to match how the issuer minted `aud`.
    pub audience: &'a str,
    /// The WIT value the proof must be bound to, used to recompute `wth`. It and
    /// the verifying key MUST come from the same verified WIT.
    pub wit: &'a str,
    /// The Txn-Token accompanying the request, if any. When set, the proof's
    /// `tth` claim must hash to it; when unset, the proof must carry no `tth`.
    pub txn_token: Option<&'a str>,
    /// Other tokens conveying end-user identity or authorization context that
    /// accompany the request, as raw HTTP header field values keyed by the
    /// **lowercased** field name.
    ///
    /// Every entry the proof's `oth` claim names must appear here and hash to
    /// the same value. An entry here that `oth` does not name is not an error —
    /// the draft leaves such a token unbound rather than forbidden — but the
    /// recipient MUST NOT use it to make authorization decisions. Read
    /// `VerifiedWpt::claims.oth` for the set that is actually bound.
    pub other_tokens: BTreeMap<String, &'a str>,
    /// If set, the proof's remaining lifetime (`exp - now`) must not exceed this
    /// many seconds — a guard against an over-permissive issuer widening the
    /// replay window.
    pub max_lifetime: Option<u64>,
}

impl<'a> Validation<'a> {
    /// Creates a validation for `audience` and `wit` at time `now`, with no
    /// clock-skew tolerance, no context-token bindings, and no lifetime cap.
    #[must_use]
    pub fn new(now: u64, audience: &'a str, wit: &'a str) -> Self {
        Self {
            now,
            leeway: 0,
            audience,
            wit,
            txn_token: None,
            other_tokens: BTreeMap::new(),
            max_lifetime: None,
        }
    }

    /// Sets the clock-skew tolerance, in seconds.
    #[must_use]
    pub fn with_leeway(mut self, leeway: u64) -> Self {
        self.leeway = leeway;
        self
    }

    /// Requires the proof to be bound (via `tth`) to `txn_token`.
    #[must_use]
    pub fn with_txn_token(mut self, txn_token: &'a str) -> Self {
        self.txn_token = Some(txn_token);
        self
    }

    /// Records a context token the request carried, so an `oth` entry naming
    /// `header_name` can be checked against it. The name is lowercased, matching
    /// how the claim is keyed.
    #[must_use]
    pub fn with_other_token(mut self, header_name: &str, header_value: &'a str) -> Self {
        self.other_tokens
            .insert(header_name.to_ascii_lowercase(), header_value);
        self
    }

    /// Rejects proofs whose remaining lifetime exceeds `seconds`.
    #[must_use]
    pub fn with_max_lifetime(mut self, seconds: u64) -> Self {
        self.max_lifetime = Some(seconds);
        self
    }
}

/// A WPT whose signature, audience, time and WIT binding have been verified.
#[derive(Debug, Clone)]
pub struct VerifiedWpt {
    /// The verified claim set.
    pub claims: WptClaims,
}

/// Issues a Workload Proof Token, signing `claims` with the workload's
/// proof-of-possession key.
///
/// The output is the compact JWS serialization, byte-for-byte reproducible for
/// a given key and claims.
///
/// # Errors
///
/// Returns [`WptError::Json`] if the header or claims cannot be serialized.
pub fn issue(claims: &WptClaims, pop_signing_key: &SigningKey) -> Result<String, WptError> {
    let header = Header {
        typ: TYP.to_owned(),
        alg: pop_signing_key.algorithm().as_str().to_owned(),
        crit: None,
    };
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
    let signing_input = format!("{header_b64}.{claims_b64}");
    let signature_b64 = URL_SAFE_NO_PAD.encode(pop_signing_key.sign(signing_input.as_bytes()));
    Ok(format!("{signing_input}.{signature_b64}"))
}

/// Verifies a Workload Proof Token.
///
/// `pop_key` is the confirmation key taken from the verified WIT (see
/// `wimsey_wit::VerifiedWit::pop_key`). It and `validation.wit` MUST come from
/// the same verified WIT, otherwise a proof bound to one WIT could be accepted
/// with another WIT's key. Checks, in order: size, structure, the
/// `typ`/`alg`/`crit` header fields, the signature, expiry, the optional
/// lifetime cap, the audience, the `wth` binding to the presented WIT, the
/// `tth` binding to any accompanying Txn-Token, and every `oth` binding to the
/// context tokens the request carried. Fails closed on any deviation.
///
/// This is a stateless primitive: it does not track `jti`, so the recipient is
/// responsible for single-use replay detection within the proof's lifetime.
///
/// # Errors
///
/// Returns the corresponding [`WptError`] for a malformed or oversized token, a
/// wrong `typ`/`alg`, an unsupported critical header, a bad signature, an
/// expired proof, a too-long lifetime, an audience mismatch, a WIT-binding
/// mismatch, a Txn-Token-binding mismatch, or a context-token-binding mismatch.
pub fn verify(
    wpt: &str,
    pop_key: &VerifyingKey,
    validation: &Validation<'_>,
) -> Result<VerifiedWpt, WptError> {
    if wpt.len() > MAX_TOKEN_LEN {
        return Err(WptError::TokenTooLong);
    }

    let mut parts = wpt.split('.');
    let (Some(header_b64), Some(claims_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(WptError::MalformedToken);
    };

    let header: Header = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_b64)?)?;
    // `typ` is pinned to the exact draft value; the media-type spelling
    // `application/wpt+jwt` is intentionally not accepted here.
    if header.typ != TYP {
        return Err(WptError::WrongType { found: header.typ });
    }
    // The proof MUST be produced with the algorithm the WIT's `cnf` JWK names,
    // and `pop_key` came out of that JWK — so requiring the header to match the
    // key is what enforces the binding.
    let alg = Algorithm::parse(&header.alg).map_err(|e| match e {
        wimsey_jose::JoseError::UnsupportedAlg { found }
        | wimsey_jose::JoseError::ForbiddenAlg { found } => WptError::UnsupportedAlg { found },
        _ => WptError::UnsupportedAlg {
            found: header.alg.clone(),
        },
    })?;
    if alg != pop_key.algorithm() {
        return Err(WptError::AlgorithmMismatch);
    }
    if header.crit.is_some() {
        return Err(WptError::UnsupportedCritical);
    }

    // Decode the signature straight into a stack buffer to avoid a heap
    // allocation on the verify path. `decode_slice` rejects an output buffer
    // smaller than its (conservative) length estimate, so the buffer is sized
    // above the 64 bytes a signature decodes to; the exact decoded length is
    // then pinned.
    let mut signature_buf = [0u8; 96];
    let signature_len = URL_SAFE_NO_PAD
        .decode_slice(signature_b64, &mut signature_buf)
        .map_err(|_| WptError::MalformedToken)?;
    if signature_len != SIGNATURE_LEN {
        return Err(WptError::MalformedToken);
    }

    let signing_input = format!("{header_b64}.{claims_b64}");
    pop_key
        .verify(signing_input.as_bytes(), &signature_buf[..signature_len])
        .map_err(|_| WptError::InvalidSignature)?;

    let claims: WptClaims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims_b64)?)?;

    // Per RFC 7519 the current time must be strictly before `exp`.
    if validation.now >= claims.exp.saturating_add(validation.leeway) {
        return Err(WptError::Expired);
    }
    if let Some(max) = validation.max_lifetime {
        if claims.exp.saturating_sub(validation.now) > max {
            return Err(WptError::LifetimeTooLong);
        }
    }
    if claims.aud != validation.audience {
        return Err(WptError::AudienceMismatch);
    }
    if claims.wth != wit_thumbprint(validation.wit) {
        return Err(WptError::WitBindingMismatch);
    }
    // `tth` binds the proof to an accompanying Txn-Token. It must be present
    // exactly when such a token is, and must hash to it.
    match (validation.txn_token, claims.tth.as_deref()) {
        (None, None) => {}
        (Some(txn_token), Some(tth)) if tth == txn_token_thumbprint(txn_token) => {}
        _ => return Err(WptError::TxnTokenBindingMismatch),
    }
    // `oth` binds other context tokens, keyed by header field name. Every entry
    // must name a token the request actually carried and hash to it: the draft
    // requires a proof carrying an entry the recipient cannot understand to be
    // rejected. A token the request carried that `oth` does *not* name is left
    // unbound rather than rejected — the draft forbids using it for an
    // authorization decision, which is the caller's obligation, not something
    // verification can enforce here.
    if let Some(oth) = &claims.oth {
        for (name, hash) in oth {
            let presented = validation
                .other_tokens
                .get(name.as_str())
                .ok_or_else(|| WptError::OtherTokenBindingMismatch { name: name.clone() })?;
            if *hash != other_token_entry(name, presented).1 {
                return Err(WptError::OtherTokenBindingMismatch { name: name.clone() });
            }
        }
    }

    Ok(VerifiedWpt { claims })
}

#[cfg(test)]
mod tests {
    use wimsey_jose::SigningKey;

    use std::collections::BTreeMap;

    use super::{
        issue, other_token_entry, txn_token_thumbprint, verify, wit_thumbprint, Validation,
    };
    use crate::claims::WptClaims;
    use crate::error::WptError;

    const WIT: &str = "eyJ0eXAiOiJ3aXQrand0In0.payload.signature";
    const AUD: &str = "https://workload.example.com/path";

    fn sample_claims() -> WptClaims {
        WptClaims {
            aud: AUD.to_owned(),
            exp: 1_700_000_300,
            jti: "0123456789abcdef".to_owned(),
            wth: wit_thumbprint(WIT),
            tth: None,
            oth: None,
        }
    }

    fn valid_at(now: u64) -> Validation<'static> {
        Validation::new(now, AUD, WIT)
    }

    #[test]
    fn round_trips() {
        let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
        let claims = sample_claims();
        let wpt = issue(&claims, &key).unwrap();

        let verified = verify(&wpt, &key.verifying_key(), &valid_at(1_700_000_000)).unwrap();
        assert_eq!(verified.claims, claims);
    }

    #[test]
    fn rejects_a_tampered_payload() {
        let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
        let wpt = issue(&sample_claims(), &key).unwrap();

        let mut parts: Vec<&str> = wpt.split('.').collect();
        let mut payload = parts[1].to_owned();
        let last = payload.pop().unwrap();
        payload.push(if last == 'A' { 'B' } else { 'A' });
        parts[1] = &payload;
        let tampered = parts.join(".");

        let err = verify(&tampered, &key.verifying_key(), &valid_at(1_700_000_000));
        assert!(matches!(err, Err(WptError::InvalidSignature)));
    }

    #[test]
    fn rejects_the_wrong_pop_key() {
        let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
        let other = SigningKey::from_ed25519_seed(&[8u8; 32]);
        let wpt = issue(&sample_claims(), &key).unwrap();

        let err = verify(&wpt, &other.verifying_key(), &valid_at(1_700_000_000));
        assert!(matches!(err, Err(WptError::InvalidSignature)));
    }

    #[test]
    fn rejects_an_expired_proof() {
        let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
        let wpt = issue(&sample_claims(), &key).unwrap();

        let err = verify(&wpt, &key.verifying_key(), &valid_at(1_700_000_300));
        assert!(matches!(err, Err(WptError::Expired)));
    }

    #[test]
    fn rejects_a_wrong_audience() {
        let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
        let wpt = issue(&sample_claims(), &key).unwrap();

        let validation = Validation::new(1_700_000_000, "https://evil.example/path", WIT);
        let err = verify(&wpt, &key.verifying_key(), &validation);
        assert!(matches!(err, Err(WptError::AudienceMismatch)));
    }

    #[test]
    fn rejects_a_mismatched_wit_binding() {
        let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
        let wpt = issue(&sample_claims(), &key).unwrap();

        // A different WIT than the one the proof was bound to.
        let validation = Validation::new(1_700_000_000, AUD, "a.different.wit");
        let err = verify(&wpt, &key.verifying_key(), &validation);
        assert!(matches!(err, Err(WptError::WitBindingMismatch)));
    }

    #[test]
    fn rejects_an_oversized_token() {
        let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
        let oversized = "a".repeat(super::MAX_TOKEN_LEN + 1);

        let err = verify(&oversized, &key.verifying_key(), &valid_at(1_700_000_000));
        assert!(matches!(err, Err(WptError::TokenTooLong)));
    }

    #[test]
    fn rejects_too_few_parts() {
        let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
        let err = verify("only.two", &key.verifying_key(), &valid_at(1_700_000_000));
        assert!(matches!(err, Err(WptError::MalformedToken)));
    }

    #[test]
    fn rejects_a_wrong_length_signature() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
        let wpt = issue(&sample_claims(), &key).unwrap();

        // Swap in a 32-byte (too short) signature segment.
        let mut parts: Vec<&str> = wpt.split('.').collect();
        let short = URL_SAFE_NO_PAD.encode([0u8; 32]);
        parts[2] = &short;
        let bad = parts.join(".");

        let err = verify(&bad, &key.verifying_key(), &valid_at(1_700_000_000));
        assert!(matches!(err, Err(WptError::MalformedToken)));
    }

    #[test]
    fn rejects_a_critical_header() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
        let header = URL_SAFE_NO_PAD.encode(r#"{"typ":"wpt+jwt","alg":"EdDSA","crit":["exp"]}"#);
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&sample_claims()).unwrap());
        let signing_input = format!("{header}.{claims}");
        let signature = URL_SAFE_NO_PAD.encode(key.sign(signing_input.as_bytes()));
        let wpt = format!("{signing_input}.{signature}");

        let err = verify(&wpt, &key.verifying_key(), &valid_at(1_700_000_000));
        assert!(matches!(err, Err(WptError::UnsupportedCritical)));
    }

    #[test]
    fn is_deterministic() {
        let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
        let claims = sample_claims();
        assert_eq!(issue(&claims, &key).unwrap(), issue(&claims, &key).unwrap());
    }

    const TXN_TOKEN: &str = "txn-token-abcdef";
    const CTX_HEADER: &str = "Ctx-Token";
    const CTX_VALUE: &str = "ctx-token-abcdef";

    fn claims_with_tth() -> WptClaims {
        WptClaims {
            tth: Some(txn_token_thumbprint(TXN_TOKEN)),
            ..sample_claims()
        }
    }

    fn claims_with_oth(name: &str, value: &str) -> WptClaims {
        let (key, hash) = other_token_entry(name, value);
        WptClaims {
            oth: Some(BTreeMap::from([(key, hash)])),
            ..sample_claims()
        }
    }

    #[test]
    fn binds_to_the_matching_txn_token() {
        let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
        let wpt = issue(&claims_with_tth(), &key).unwrap();

        let validation = valid_at(1_700_000_000).with_txn_token(TXN_TOKEN);
        assert!(verify(&wpt, &key.verifying_key(), &validation).is_ok());
    }

    #[test]
    fn rejects_a_different_txn_token() {
        let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
        let wpt = issue(&claims_with_tth(), &key).unwrap();

        let validation = valid_at(1_700_000_000).with_txn_token("a-different-token");
        let err = verify(&wpt, &key.verifying_key(), &validation);
        assert!(matches!(err, Err(WptError::TxnTokenBindingMismatch)));
    }

    #[test]
    fn rejects_tth_present_but_no_txn_token_in_request() {
        let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
        let wpt = issue(&claims_with_tth(), &key).unwrap();

        let err = verify(&wpt, &key.verifying_key(), &valid_at(1_700_000_000));
        assert!(matches!(err, Err(WptError::TxnTokenBindingMismatch)));
    }

    #[test]
    fn rejects_txn_token_in_request_but_no_tth() {
        let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
        let wpt = issue(&sample_claims(), &key).unwrap();

        let validation = valid_at(1_700_000_000).with_txn_token(TXN_TOKEN);
        let err = verify(&wpt, &key.verifying_key(), &validation);
        assert!(matches!(err, Err(WptError::TxnTokenBindingMismatch)));
    }

    #[test]
    fn binds_to_a_context_token_by_header_name() {
        let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
        let wpt = issue(&claims_with_oth(CTX_HEADER, CTX_VALUE), &key).unwrap();

        let validation = valid_at(1_700_000_000).with_other_token(CTX_HEADER, CTX_VALUE);
        assert!(verify(&wpt, &key.verifying_key(), &validation).is_ok());
    }

    #[test]
    fn matches_a_context_token_header_name_case_insensitively() {
        let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
        // The claim is keyed lowercase whatever case the issuer used, and the
        // verifier lowercases what it was handed, so the two meet.
        let wpt = issue(&claims_with_oth("CTX-TOKEN", CTX_VALUE), &key).unwrap();

        let validation = valid_at(1_700_000_000).with_other_token("ctx-token", CTX_VALUE);
        assert!(verify(&wpt, &key.verifying_key(), &validation).is_ok());
    }

    #[test]
    fn ignores_surrounding_spaces_in_a_context_token_value() {
        let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
        let wpt = issue(&claims_with_oth(CTX_HEADER, CTX_VALUE), &key).unwrap();

        let padded = format!("  {CTX_VALUE}  ");
        let validation = valid_at(1_700_000_000).with_other_token(CTX_HEADER, &padded);
        assert!(verify(&wpt, &key.verifying_key(), &validation).is_ok());
    }

    #[test]
    fn rejects_a_different_context_token() {
        let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
        let wpt = issue(&claims_with_oth(CTX_HEADER, CTX_VALUE), &key).unwrap();

        let validation = valid_at(1_700_000_000).with_other_token(CTX_HEADER, "a-different-token");
        let err = verify(&wpt, &key.verifying_key(), &validation);
        assert!(matches!(
            err,
            Err(WptError::OtherTokenBindingMismatch { ref name }) if name == "ctx-token"
        ));
    }

    #[test]
    fn rejects_an_oth_entry_the_request_did_not_carry() {
        let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
        let wpt = issue(&claims_with_oth(CTX_HEADER, CTX_VALUE), &key).unwrap();

        // The draft requires rejecting an `oth` entry the recipient cannot
        // understand, and a header it never received is exactly that.
        let err = verify(&wpt, &key.verifying_key(), &valid_at(1_700_000_000));
        assert!(matches!(
            err,
            Err(WptError::OtherTokenBindingMismatch { ref name }) if name == "ctx-token"
        ));
    }

    #[test]
    fn leaves_a_context_token_oth_does_not_name_unbound() {
        let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
        let wpt = issue(&sample_claims(), &key).unwrap();

        // The draft does not forbid the token; it forbids *relying* on it. The
        // proof still verifies, and `claims.oth` names nothing, which is how the
        // caller can tell the token is unbound.
        let validation = valid_at(1_700_000_000).with_other_token(CTX_HEADER, CTX_VALUE);
        let verified = verify(&wpt, &key.verifying_key(), &validation).unwrap();
        assert!(verified.claims.oth.is_none());
    }

    #[test]
    fn rejects_a_lifetime_over_the_cap() {
        let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
        let wpt = issue(&sample_claims(), &key).unwrap();

        // exp - now == 300s; cap at 120s.
        let validation = valid_at(1_700_000_000).with_max_lifetime(120);
        let err = verify(&wpt, &key.verifying_key(), &validation);
        assert!(matches!(err, Err(WptError::LifetimeTooLong)));
    }

    #[test]
    fn accepts_a_lifetime_within_the_cap() {
        let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
        let wpt = issue(&sample_claims(), &key).unwrap();

        let validation = valid_at(1_700_000_000).with_max_lifetime(600);
        assert!(verify(&wpt, &key.verifying_key(), &validation).is_ok());
    }
}

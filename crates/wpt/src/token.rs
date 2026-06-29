//! Compact-JWS issuance and verification of Workload Proof Tokens.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::claims::WptClaims;
use crate::error::WptError;

/// The JOSE `typ` of a Workload Proof Token.
pub const TYP: &str = "wpt+jwt";

/// The only signature algorithm supported by this crate.
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
/// `wth` and `ath` claims.
fn sha256_b64u(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

/// Computes the `wth` value for a WIT: the Base64url-encoded SHA-256 hash of the
/// WIT's ASCII value.
#[must_use]
pub fn wit_thumbprint(wit: &str) -> String {
    sha256_b64u(wit)
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
    /// The OAuth access token accompanying the request, if any. When set, the
    /// proof's `ath` claim must hash to it; when unset, the proof must carry no
    /// `ath`.
    pub access_token: Option<&'a str>,
    /// If set, the proof's remaining lifetime (`exp - now`) must not exceed this
    /// many seconds — a guard against an over-permissive issuer widening the
    /// replay window.
    pub max_lifetime: Option<u64>,
}

impl<'a> Validation<'a> {
    /// Creates a validation for `audience` and `wit` at time `now`, with no
    /// clock-skew tolerance, no access-token binding, and no lifetime cap.
    #[must_use]
    pub fn new(now: u64, audience: &'a str, wit: &'a str) -> Self {
        Self {
            now,
            leeway: 0,
            audience,
            wit,
            access_token: None,
            max_lifetime: None,
        }
    }

    /// Sets the clock-skew tolerance, in seconds.
    #[must_use]
    pub fn with_leeway(mut self, leeway: u64) -> Self {
        self.leeway = leeway;
        self
    }

    /// Requires the proof to be bound (via `ath`) to `access_token`.
    #[must_use]
    pub fn with_access_token(mut self, access_token: &'a str) -> Self {
        self.access_token = Some(access_token);
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
        alg: ALG.to_owned(),
        crit: None,
    };
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
    let signing_input = format!("{header_b64}.{claims_b64}");
    let signature: Signature = pop_signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    Ok(format!("{signing_input}.{signature_b64}"))
}

/// Verifies a Workload Proof Token.
///
/// `pop_key` is the confirmation key taken from the verified WIT (see
/// `wimsey_wit::VerifiedWit::pop_key`). It and `validation.wit` MUST come from
/// the same verified WIT, otherwise a proof bound to one WIT could be accepted
/// with another WIT's key. Checks, in order: size, structure, the
/// `typ`/`alg`/`crit` header fields, the signature, expiry, the optional
/// lifetime cap, the audience, the `wth` binding to the presented WIT, and the
/// `ath` binding to any accompanying access token. Fails closed on any
/// deviation.
///
/// This is a stateless primitive: it does not track `jti`, so the recipient is
/// responsible for single-use replay detection within the proof's lifetime.
///
/// # Errors
///
/// Returns the corresponding [`WptError`] for a malformed or oversized token, a
/// wrong `typ`/`alg`, an unsupported critical header, a bad signature, an
/// expired proof, a too-long lifetime, an audience mismatch, a WIT-binding
/// mismatch, or an access-token-binding mismatch.
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
    if header.alg != ALG {
        return Err(WptError::UnsupportedAlg { found: header.alg });
    }
    if header.crit.is_some() {
        return Err(WptError::UnsupportedCritical);
    }

    let signature_bytes = URL_SAFE_NO_PAD.decode(signature_b64)?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| WptError::MalformedToken)?;
    let signature = Signature::from_bytes(&signature_array);

    let signing_input = format!("{header_b64}.{claims_b64}");
    pop_key
        .verify_strict(signing_input.as_bytes(), &signature)
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
    // `ath` binds the proof to an accompanying access token. It must be present
    // exactly when an access token is, and must hash to it.
    match (validation.access_token, claims.ath.as_deref()) {
        (None, None) => {}
        (Some(access_token), Some(ath)) if ath == sha256_b64u(access_token) => {}
        _ => return Err(WptError::AccessTokenBindingMismatch),
    }

    Ok(VerifiedWpt { claims })
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::{issue, verify, wit_thumbprint, Validation};
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
            ath: None,
        }
    }

    fn valid_at(now: u64) -> Validation<'static> {
        Validation::new(now, AUD, WIT)
    }

    #[test]
    fn round_trips() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let claims = sample_claims();
        let wpt = issue(&claims, &key).unwrap();

        let verified = verify(&wpt, &key.verifying_key(), &valid_at(1_700_000_000)).unwrap();
        assert_eq!(verified.claims, claims);
    }

    #[test]
    fn rejects_a_tampered_payload() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
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
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let other = SigningKey::from_bytes(&[8u8; 32]);
        let wpt = issue(&sample_claims(), &key).unwrap();

        let err = verify(&wpt, &other.verifying_key(), &valid_at(1_700_000_000));
        assert!(matches!(err, Err(WptError::InvalidSignature)));
    }

    #[test]
    fn rejects_an_expired_proof() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let wpt = issue(&sample_claims(), &key).unwrap();

        let err = verify(&wpt, &key.verifying_key(), &valid_at(1_700_000_300));
        assert!(matches!(err, Err(WptError::Expired)));
    }

    #[test]
    fn rejects_a_wrong_audience() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let wpt = issue(&sample_claims(), &key).unwrap();

        let validation = Validation::new(1_700_000_000, "https://evil.example/path", WIT);
        let err = verify(&wpt, &key.verifying_key(), &validation);
        assert!(matches!(err, Err(WptError::AudienceMismatch)));
    }

    #[test]
    fn rejects_a_mismatched_wit_binding() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let wpt = issue(&sample_claims(), &key).unwrap();

        // A different WIT than the one the proof was bound to.
        let validation = Validation::new(1_700_000_000, AUD, "a.different.wit");
        let err = verify(&wpt, &key.verifying_key(), &validation);
        assert!(matches!(err, Err(WptError::WitBindingMismatch)));
    }

    #[test]
    fn rejects_an_oversized_token() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let oversized = "a".repeat(super::MAX_TOKEN_LEN + 1);

        let err = verify(&oversized, &key.verifying_key(), &valid_at(1_700_000_000));
        assert!(matches!(err, Err(WptError::TokenTooLong)));
    }

    #[test]
    fn rejects_too_few_parts() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let err = verify("only.two", &key.verifying_key(), &valid_at(1_700_000_000));
        assert!(matches!(err, Err(WptError::MalformedToken)));
    }

    #[test]
    fn rejects_a_critical_header() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use ed25519_dalek::Signer;

        let key = SigningKey::from_bytes(&[9u8; 32]);
        let header = URL_SAFE_NO_PAD.encode(r#"{"typ":"wpt+jwt","alg":"EdDSA","crit":["exp"]}"#);
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&sample_claims()).unwrap());
        let signing_input = format!("{header}.{claims}");
        let signature = URL_SAFE_NO_PAD.encode(key.sign(signing_input.as_bytes()).to_bytes());
        let wpt = format!("{signing_input}.{signature}");

        let err = verify(&wpt, &key.verifying_key(), &valid_at(1_700_000_000));
        assert!(matches!(err, Err(WptError::UnsupportedCritical)));
    }

    #[test]
    fn is_deterministic() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let claims = sample_claims();
        assert_eq!(issue(&claims, &key).unwrap(), issue(&claims, &key).unwrap());
    }

    const ACCESS_TOKEN: &str = "access-token-abcdef";

    fn claims_with_ath() -> WptClaims {
        WptClaims {
            ath: Some(wit_thumbprint(ACCESS_TOKEN)),
            ..sample_claims()
        }
    }

    #[test]
    fn binds_to_the_matching_access_token() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let wpt = issue(&claims_with_ath(), &key).unwrap();

        let validation = valid_at(1_700_000_000).with_access_token(ACCESS_TOKEN);
        assert!(verify(&wpt, &key.verifying_key(), &validation).is_ok());
    }

    #[test]
    fn rejects_a_different_access_token() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let wpt = issue(&claims_with_ath(), &key).unwrap();

        let validation = valid_at(1_700_000_000).with_access_token("a-different-token");
        let err = verify(&wpt, &key.verifying_key(), &validation);
        assert!(matches!(err, Err(WptError::AccessTokenBindingMismatch)));
    }

    #[test]
    fn rejects_ath_present_but_no_access_token_in_request() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let wpt = issue(&claims_with_ath(), &key).unwrap();

        let err = verify(&wpt, &key.verifying_key(), &valid_at(1_700_000_000));
        assert!(matches!(err, Err(WptError::AccessTokenBindingMismatch)));
    }

    #[test]
    fn rejects_access_token_in_request_but_no_ath() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let wpt = issue(&sample_claims(), &key).unwrap();

        let validation = valid_at(1_700_000_000).with_access_token(ACCESS_TOKEN);
        let err = verify(&wpt, &key.verifying_key(), &validation);
        assert!(matches!(err, Err(WptError::AccessTokenBindingMismatch)));
    }

    #[test]
    fn rejects_a_lifetime_over_the_cap() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let wpt = issue(&sample_claims(), &key).unwrap();

        // exp - now == 300s; cap at 120s.
        let validation = valid_at(1_700_000_000).with_max_lifetime(120);
        let err = verify(&wpt, &key.verifying_key(), &validation);
        assert!(matches!(err, Err(WptError::LifetimeTooLong)));
    }

    #[test]
    fn accepts_a_lifetime_within_the_cap() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let wpt = issue(&sample_claims(), &key).unwrap();

        let validation = valid_at(1_700_000_000).with_max_lifetime(600);
        assert!(verify(&wpt, &key.verifying_key(), &validation).is_ok());
    }
}

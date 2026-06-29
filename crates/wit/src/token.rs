//! Compact-JWS issuance and verification of Workload Identity Tokens.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::claims::WitClaims;
use crate::error::WitError;

/// The JOSE `typ` of a Workload Identity Token.
pub const TYP: &str = "wit+jwt";

/// The only signature algorithm supported by this crate.
pub const ALG: &str = "EdDSA";

/// The maximum accepted size, in bytes, of a compact WIT serialization.
///
/// Verification bounds its input before doing any unauthenticated decoding.
pub const MAX_TOKEN_LEN: usize = 8192;

#[derive(Serialize, Deserialize)]
struct Header {
    typ: String,
    alg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    crit: Option<Vec<String>>,
}

/// Parameters controlling WIT verification.
///
/// `now` is injected rather than read from the system clock so that
/// time-dependent behaviour is deterministic and reproducible in tests.
#[derive(Debug, Clone)]
pub struct Validation {
    /// The current time, in seconds since the Unix epoch.
    pub now: u64,
    /// Clock-skew tolerance, in seconds, applied to `exp` and `iat`.
    pub leeway: u64,
    /// If set, the token's `iss` must equal this value.
    pub expected_issuer: Option<String>,
}

impl Validation {
    /// Creates a validation that only checks the signature and time, with no
    /// clock skew and no issuer check.
    #[must_use]
    pub fn at(now: u64) -> Self {
        Self {
            now,
            leeway: 0,
            expected_issuer: None,
        }
    }

    /// Sets the clock-skew tolerance, in seconds.
    #[must_use]
    pub fn with_leeway(mut self, leeway: u64) -> Self {
        self.leeway = leeway;
        self
    }

    /// Requires the token's issuer to equal `issuer`.
    #[must_use]
    pub fn expect_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.expected_issuer = Some(issuer.into());
        self
    }
}

/// A WIT whose signature and time claims have been verified.
#[derive(Debug, Clone)]
pub struct VerifiedWit {
    /// The verified claim set.
    pub claims: WitClaims,
    /// The `kid` from the JOSE header, if present.
    pub kid: Option<String>,
    /// The validated Ed25519 proof-of-possession key from the `cnf` claim. A
    /// Workload Proof Token is later checked against this key.
    pub pop_key: VerifyingKey,
}

/// Issues a Workload Identity Token, signing `claims` with `signing_key`.
///
/// The result is the compact JWS serialization. For a fixed key, `kid` and
/// `claims`, the output is byte-for-byte reproducible.
///
/// # Errors
///
/// Returns [`WitError::Json`] if the header or claims cannot be serialized.
pub fn issue(
    claims: &WitClaims,
    kid: Option<&str>,
    signing_key: &SigningKey,
) -> Result<String, WitError> {
    let header = Header {
        typ: TYP.to_owned(),
        alg: ALG.to_owned(),
        kid: kid.map(ToOwned::to_owned),
        crit: None,
    };
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
    let signing_input = format!("{header_b64}.{claims_b64}");
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    Ok(format!("{signing_input}.{signature_b64}"))
}

/// Verifies a Workload Identity Token against `verifying_key` and `validation`.
///
/// Checks, in order: the structure, the `typ` and `alg` header fields, the
/// signature, the claim set (which must include `cnf`), and the time and issuer
/// constraints. The verification fails closed on any deviation.
///
/// # Errors
///
/// Returns the corresponding [`WitError`] variant for a malformed token, a
/// wrong `typ` or `alg`, a bad signature, an expired or not-yet-valid token, or
/// an issuer mismatch.
pub fn verify(
    token: &str,
    verifying_key: &VerifyingKey,
    validation: &Validation,
) -> Result<VerifiedWit, WitError> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(WitError::TokenTooLong);
    }

    let mut parts = token.split('.');
    let (Some(header_b64), Some(claims_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(WitError::MalformedToken);
    };

    let header: Header = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_b64)?)?;
    // `typ` is pinned to the exact draft value; media-type spellings such as
    // `application/wit+jwt` are intentionally not accepted here.
    if header.typ != TYP {
        return Err(WitError::WrongType { found: header.typ });
    }
    if header.alg != ALG {
        return Err(WitError::UnsupportedAlg { found: header.alg });
    }
    // This crate understands no critical extensions, so any `crit` is fatal.
    if header.crit.is_some() {
        return Err(WitError::UnsupportedCritical);
    }

    let signature_bytes = URL_SAFE_NO_PAD.decode(signature_b64)?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| WitError::MalformedToken)?;
    let signature = Signature::from_bytes(&signature_array);

    let signing_input = format!("{header_b64}.{claims_b64}");
    verifying_key
        .verify_strict(signing_input.as_bytes(), &signature)
        .map_err(|_| WitError::InvalidSignature)?;

    let claims: WitClaims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims_b64)?)?;

    // Per RFC 7519 the current time must be strictly before `exp`.
    if validation.now >= claims.exp.saturating_add(validation.leeway) {
        return Err(WitError::Expired);
    }
    if claims.iat > validation.now.saturating_add(validation.leeway) {
        return Err(WitError::IssuedInFuture);
    }
    if let Some(expected) = &validation.expected_issuer {
        if &claims.iss != expected {
            return Err(WitError::IssuerMismatch);
        }
    }

    // A verified WIT must carry a usable confirmation key.
    let pop_key = claims.cnf.jwk.to_ed25519()?;

    Ok(VerifiedWit {
        claims,
        kid: header.kid,
        pop_key,
    })
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use wimsey_identifier::WorkloadIdentifier;

    use super::{issue, verify, Validation};
    use crate::claims::{Confirmation, WitClaims};
    use crate::error::WitError;
    use crate::jwk::Jwk;

    fn sample_claims() -> WitClaims {
        let cnf_key = SigningKey::from_bytes(&[7u8; 32]);
        WitClaims {
            iss: "https://issuer.example".to_owned(),
            sub: WorkloadIdentifier::parse("spiffe://example.org/workload/api").unwrap(),
            iat: 1_700_000_000,
            exp: 1_700_003_600,
            jti: "a1b2c3".to_owned(),
            cnf: Confirmation {
                jwk: Jwk::from_ed25519(&cnf_key.verifying_key()),
            },
        }
    }

    #[test]
    fn round_trips() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let claims = sample_claims();
        let token = issue(&claims, Some("issuer-key-1"), &key).unwrap();

        let verified =
            verify(&token, &key.verifying_key(), &Validation::at(1_700_000_000)).unwrap();
        assert_eq!(verified.claims, claims);
        assert_eq!(verified.kid.as_deref(), Some("issuer-key-1"));
    }

    #[test]
    fn rejects_a_tampered_payload() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let token = issue(&sample_claims(), None, &key).unwrap();

        // Flip the last character of the payload segment.
        let mut parts: Vec<&str> = token.split('.').collect();
        let mut payload = parts[1].to_owned();
        let last = payload.pop().unwrap();
        payload.push(if last == 'A' { 'B' } else { 'A' });
        parts[1] = &payload;
        let tampered = parts.join(".");

        let err = verify(
            &tampered,
            &key.verifying_key(),
            &Validation::at(1_700_000_000),
        );
        assert!(matches!(err, Err(WitError::InvalidSignature)));
    }

    #[test]
    fn rejects_the_wrong_key() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let other = SigningKey::from_bytes(&[2u8; 32]);
        let token = issue(&sample_claims(), None, &key).unwrap();

        let err = verify(
            &token,
            &other.verifying_key(),
            &Validation::at(1_700_000_000),
        );
        assert!(matches!(err, Err(WitError::InvalidSignature)));
    }

    #[test]
    fn rejects_an_expired_token() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let token = issue(&sample_claims(), None, &key).unwrap();

        let err = verify(&token, &key.verifying_key(), &Validation::at(1_700_003_601));
        assert!(matches!(err, Err(WitError::Expired)));
    }

    #[test]
    fn honours_leeway_on_expiry() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let token = issue(&sample_claims(), None, &key).unwrap();

        let validation = Validation::at(1_700_003_601).with_leeway(30);
        assert!(verify(&token, &key.verifying_key(), &validation).is_ok());
    }

    #[test]
    fn rejects_a_token_issued_in_the_future() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let token = issue(&sample_claims(), None, &key).unwrap();

        let err = verify(&token, &key.verifying_key(), &Validation::at(1_699_999_999));
        assert!(matches!(err, Err(WitError::IssuedInFuture)));
    }

    #[test]
    fn enforces_the_expected_issuer() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let token = issue(&sample_claims(), None, &key).unwrap();

        let validation = Validation::at(1_700_000_000).expect_issuer("https://other.example");
        let err = verify(&token, &key.verifying_key(), &validation);
        assert!(matches!(err, Err(WitError::IssuerMismatch)));
    }

    #[test]
    fn rejects_a_token_with_too_few_parts() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let err = verify(
            "only.two",
            &key.verifying_key(),
            &Validation::at(1_700_000_000),
        );
        assert!(matches!(err, Err(WitError::MalformedToken)));
    }

    #[test]
    fn is_deterministic() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let claims = sample_claims();
        let a = issue(&claims, Some("k"), &key).unwrap();
        let b = issue(&claims, Some("k"), &key).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_at_exactly_expiry() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let token = issue(&sample_claims(), None, &key).unwrap();

        // `now == exp`: the token is no longer valid (RFC 7519 requires before).
        let err = verify(&token, &key.verifying_key(), &Validation::at(1_700_003_600));
        assert!(matches!(err, Err(WitError::Expired)));
    }

    #[test]
    fn exposes_the_validated_pop_key() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let pop_key = SigningKey::from_bytes(&[7u8; 32]);
        let token = issue(&sample_claims(), None, &key).unwrap();

        let verified =
            verify(&token, &key.verifying_key(), &Validation::at(1_700_000_000)).unwrap();
        assert_eq!(verified.pop_key, pop_key.verifying_key());
    }

    #[test]
    fn rejects_an_invalid_confirmation_key() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let mut claims = sample_claims();
        claims.cnf.jwk = Jwk {
            kty: "OKP".to_owned(),
            crv: "Ed25519".to_owned(),
            x: "not-a-valid-key".to_owned(),
        };
        let token = issue(&claims, None, &key).unwrap();

        let err = verify(&token, &key.verifying_key(), &Validation::at(1_700_000_000));
        assert!(matches!(err, Err(WitError::InvalidKey)));
    }

    #[test]
    fn rejects_an_oversized_token() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let oversized = "a".repeat(super::MAX_TOKEN_LEN + 1);

        let err = verify(
            &oversized,
            &key.verifying_key(),
            &Validation::at(1_700_000_000),
        );
        assert!(matches!(err, Err(WitError::TokenTooLong)));
    }

    #[test]
    fn rejects_a_critical_header() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use ed25519_dalek::Signer;

        let key = SigningKey::from_bytes(&[1u8; 32]);
        // A well-signed token whose header marks an extension critical.
        let header = URL_SAFE_NO_PAD.encode(r#"{"typ":"wit+jwt","alg":"EdDSA","crit":["exp"]}"#);
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&sample_claims()).unwrap());
        let signing_input = format!("{header}.{claims}");
        let signature = URL_SAFE_NO_PAD.encode(key.sign(signing_input.as_bytes()).to_bytes());
        let token = format!("{signing_input}.{signature}");

        let err = verify(&token, &key.verifying_key(), &Validation::at(1_700_000_000));
        assert!(matches!(err, Err(WitError::UnsupportedCritical)));
    }
}

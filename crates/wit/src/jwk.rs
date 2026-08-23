//! A minimal JSON Web Key for Ed25519 public keys (`OKP` / `Ed25519`).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::error::WitError;

/// The confirmation-key `alg` this crate can verify proofs with.
pub const ALG: &str = "EdDSA";

/// JOSE `alg` values a confirmation key MUST NOT carry.
///
/// Section 5.1 of `draft-ietf-wimse-workload-creds` forbids three families:
/// `none`, algorithms used with symmetric keys (a shared secret cannot prove
/// possession), and encryption algorithms (which would need key distribution
/// outside the WIT). They are listed explicitly so a WIT carrying one is
/// rejected as a spec violation rather than as merely unsupported.
const FORBIDDEN_ALGS: &[&str] = &[
    // The unsecured JWS algorithm.
    "none",
    // JWS algorithms used with symmetric keys (RFC 7518 Section 3.2).
    "HS256",
    "HS384",
    "HS512",
    // JWE key-management algorithms (RFC 7518 Section 4.1).
    "RSA1_5",
    "RSA-OAEP",
    "RSA-OAEP-256",
    "RSA-OAEP-384",
    "RSA-OAEP-512",
    "A128KW",
    "A192KW",
    "A256KW",
    "dir",
    "ECDH-ES",
    "ECDH-ES+A128KW",
    "ECDH-ES+A192KW",
    "ECDH-ES+A256KW",
    "A128GCMKW",
    "A192GCMKW",
    "A256GCMKW",
    "PBES2-HS256+A128KW",
    "PBES2-HS384+A192KW",
    "PBES2-HS512+A256KW",
];

/// An `OKP` JSON Web Key holding an Ed25519 public key (RFC 8037).
///
/// This is the public confirmation key carried in a WIT's `cnf` claim: the
/// workload proves possession of the matching private key in a Workload Proof
/// Token or an HTTP message signature.
///
/// Section 5.1 of `draft-ietf-wimse-workload-creds` requires the `alg` member to
/// be present and binds the proof to it — "the presented proof MUST be produced
/// with the algorithm specified in this field". It is modelled as an `Option` so
/// that a WIT omitting it parses and then fails with
/// [`WitError::MissingConfirmationAlg`], rather than failing as unreadable JSON.
///
/// The member order below is the order these keys serialize in, which keeps
/// issued tokens byte-for-byte reproducible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    /// The algorithm the proof of possession must be produced with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// Key type; always `OKP` here.
    pub kty: String,
    /// Curve; always `Ed25519` here.
    pub crv: String,
    /// The Base64url-encoded public key.
    pub x: String,
}

impl Jwk {
    /// Builds a JWK from an Ed25519 verifying key, with `alg` set to `EdDSA`.
    #[must_use]
    pub fn from_ed25519(key: &VerifyingKey) -> Self {
        Self {
            alg: Some(ALG.to_owned()),
            kty: "OKP".to_owned(),
            crv: "Ed25519".to_owned(),
            x: URL_SAFE_NO_PAD.encode(key.to_bytes()),
        }
    }

    /// Checks the `alg` member and returns it.
    ///
    /// # Errors
    ///
    /// Returns [`WitError::MissingConfirmationAlg`] if `alg` is absent,
    /// [`WitError::ForbiddenConfirmationAlg`] if it names an algorithm the draft
    /// forbids, or [`WitError::UnsupportedConfirmationAlg`] if it names an
    /// algorithm this crate cannot verify a proof with.
    pub fn validated_alg(&self) -> Result<&str, WitError> {
        let alg = self
            .alg
            .as_deref()
            .ok_or(WitError::MissingConfirmationAlg)?;
        if FORBIDDEN_ALGS.iter().any(|f| f.eq_ignore_ascii_case(alg)) {
            return Err(WitError::ForbiddenConfirmationAlg {
                found: alg.to_owned(),
            });
        }
        if alg != ALG {
            return Err(WitError::UnsupportedConfirmationAlg {
                found: alg.to_owned(),
            });
        }
        Ok(alg)
    }

    /// Decodes this JWK into an Ed25519 verifying key.
    ///
    /// # Errors
    ///
    /// Returns the error from [`Jwk::validated_alg`] if `alg` is missing,
    /// forbidden or unsupported, or [`WitError::InvalidKey`] if the key type or
    /// curve is not Ed25519, or if `x` is not a valid 32-byte Ed25519 public key.
    pub fn to_ed25519(&self) -> Result<VerifyingKey, WitError> {
        self.validated_alg()?;
        if self.kty != "OKP" || self.crv != "Ed25519" {
            return Err(WitError::InvalidKey);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.x)
            .map_err(|_| WitError::InvalidKey)?;
        let array: [u8; 32] = bytes.try_into().map_err(|_| WitError::InvalidKey)?;
        VerifyingKey::from_bytes(&array).map_err(|_| WitError::InvalidKey)
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::{Jwk, ALG};
    use crate::error::WitError;

    fn jwk() -> Jwk {
        Jwk::from_ed25519(&SigningKey::from_bytes(&[7u8; 32]).verifying_key())
    }

    #[test]
    fn sets_alg_when_built_from_a_key() {
        assert_eq!(jwk().alg.as_deref(), Some(ALG));
    }

    #[test]
    fn round_trips_through_json() {
        let json = serde_json::to_string(&jwk()).unwrap();
        assert!(json.starts_with(r#"{"alg":"EdDSA","kty":"OKP","crv":"Ed25519""#));
        let back: Jwk = serde_json::from_str(&json).unwrap();
        assert_eq!(back, jwk());
    }

    #[test]
    fn rejects_a_missing_alg() {
        let mut jwk = jwk();
        jwk.alg = None;
        assert!(matches!(
            jwk.to_ed25519(),
            Err(WitError::MissingConfirmationAlg)
        ));
    }

    #[test]
    fn rejects_the_unsecured_alg() {
        let mut jwk = jwk();
        jwk.alg = Some("none".to_owned());
        assert!(matches!(
            jwk.to_ed25519(),
            Err(WitError::ForbiddenConfirmationAlg { .. })
        ));
    }

    #[test]
    fn rejects_a_symmetric_alg() {
        let mut jwk = jwk();
        jwk.alg = Some("HS256".to_owned());
        assert!(matches!(
            jwk.to_ed25519(),
            Err(WitError::ForbiddenConfirmationAlg { .. })
        ));
    }

    #[test]
    fn rejects_an_encryption_alg() {
        let mut jwk = jwk();
        jwk.alg = Some("ECDH-ES+A128KW".to_owned());
        assert!(matches!(
            jwk.to_ed25519(),
            Err(WitError::ForbiddenConfirmationAlg { .. })
        ));
    }

    // ES256 is a legal confirmation algorithm the draft even requires general
    // purpose implementations to support; this crate is Ed25519-only, so it must
    // say "unsupported", not "forbidden".
    #[test]
    fn reports_es256_as_unsupported_rather_than_forbidden() {
        let mut jwk = jwk();
        jwk.alg = Some("ES256".to_owned());
        assert!(matches!(
            jwk.to_ed25519(),
            Err(WitError::UnsupportedConfirmationAlg { found }) if found == "ES256"
        ));
    }

    #[test]
    fn rejects_an_invalid_key_even_with_a_good_alg() {
        let mut jwk = jwk();
        jwk.x = "not-a-valid-key".to_owned();
        assert!(matches!(jwk.to_ed25519(), Err(WitError::InvalidKey)));
    }
}

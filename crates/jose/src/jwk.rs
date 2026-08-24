//! The JSON Web Key that carries a public key inside a WIMSE credential.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};

use crate::error::JoseError;
use crate::key::{Algorithm, VerifyingKey};

/// A public JSON Web Key, in the two shapes WIMSE uses.
///
/// `OKP` with `crv: Ed25519` and an `x` (RFC 8037), or `EC` with `crv: P-256`
/// and both `x` and `y` (RFC 7518 Section 6.2). This is the shape a WIT's `cnf`
/// claim carries, so the workload can prove possession of the matching private
/// key.
///
/// Section 5.1 of `draft-ietf-wimse-workload-creds` requires `alg` to be present
/// and binds the proof to it — "the presented proof MUST be produced with the
/// algorithm specified in this field". It is modelled as an `Option` so that a
/// key omitting it parses and then fails with [`JoseError::MissingAlg`], rather
/// than failing earlier as unreadable JSON.
///
/// The field order below is the order these members serialize in, which keeps
/// issued tokens byte-for-byte reproducible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    /// The algorithm a proof of possession must be produced with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// Key type: `OKP` for Ed25519, `EC` for P-256.
    pub kty: String,
    /// Curve: `Ed25519` or `P-256`.
    pub crv: String,
    /// The Base64url-encoded public key, or the x coordinate for `EC`.
    pub x: String,
    /// The Base64url-encoded y coordinate. Present for `EC` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

impl Jwk {
    /// Builds a JWK from a public key, with `alg` set to match it.
    ///
    /// # Panics
    ///
    /// Never in practice: an uncompressed SEC1 encoding of a valid P-256 point
    /// always carries both coordinates, and the input is a key that has already
    /// been validated.
    #[must_use]
    pub fn from_verifying_key(key: &VerifyingKey) -> Self {
        match key {
            VerifyingKey::Ed25519(key) => Self {
                alg: Some(Algorithm::EdDsa.as_str().to_owned()),
                kty: "OKP".to_owned(),
                crv: "Ed25519".to_owned(),
                x: URL_SAFE_NO_PAD.encode(key.to_bytes()),
                y: None,
            },
            VerifyingKey::P256(key) => {
                let point = key.to_sec1_point(false);
                Self {
                    alg: Some(Algorithm::Es256.as_str().to_owned()),
                    kty: "EC".to_owned(),
                    crv: "P-256".to_owned(),
                    // Uncompressed SEC1 is `0x04 || x || y`, and the JWK carries
                    // the two coordinates separately.
                    x: URL_SAFE_NO_PAD.encode(
                        point
                            .x()
                            .expect("an uncompressed point has an x coordinate"),
                    ),
                    y: Some(
                        URL_SAFE_NO_PAD
                            .encode(point.y().expect("an uncompressed point has a y coordinate")),
                    ),
                }
            }
        }
    }

    /// Checks the `alg` member and returns the algorithm it names.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::MissingAlg`] if it is absent,
    /// [`JoseError::ForbiddenAlg`] if it names an algorithm the draft forbids,
    /// or [`JoseError::UnsupportedAlg`] if it names one this crate cannot use.
    pub fn validated_alg(&self) -> Result<Algorithm, JoseError> {
        Algorithm::parse(self.alg.as_deref().ok_or(JoseError::MissingAlg)?)
    }

    /// Decodes this JWK into a public key.
    ///
    /// # Errors
    ///
    /// Returns the error from [`Jwk::validated_alg`], or
    /// [`JoseError::InvalidKey`] if the key type, curve or coordinates do not
    /// match the algorithm the `alg` member names.
    pub fn to_verifying_key(&self) -> Result<VerifyingKey, JoseError> {
        // The algorithm is decided by `alg`, and `kty`/`crv` are then required
        // to agree. Reading the key type first and treating `alg` as a hint
        // would let a token name one algorithm and be verified under another.
        match self.validated_alg()? {
            Algorithm::EdDsa => {
                if self.kty != "OKP" || self.crv != "Ed25519" || self.y.is_some() {
                    return Err(JoseError::InvalidKey);
                }
                let x = coordinate(&self.x)?;
                ed25519_dalek::VerifyingKey::from_bytes(&x)
                    .map(|key| VerifyingKey::Ed25519(Box::new(key)))
                    .map_err(|_| JoseError::InvalidKey)
            }
            Algorithm::Es256 => {
                if self.kty != "EC" || self.crv != "P-256" {
                    return Err(JoseError::InvalidKey);
                }
                let x = coordinate(&self.x)?;
                let y = coordinate(self.y.as_deref().ok_or(JoseError::InvalidKey)?)?;
                let mut sec1 = [0u8; 65];
                sec1[0] = 0x04;
                sec1[1..33].copy_from_slice(&x);
                sec1[33..].copy_from_slice(&y);
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                    .map(|key| VerifyingKey::P256(Box::new(key)))
                    .map_err(|_| JoseError::InvalidKey)
            }
        }
    }
}

/// Decodes one Base64url coordinate, which must be exactly 32 bytes.
///
/// The fixed length matters: RFC 7518 Section 6.2.1.2 requires the octet length
/// to match the curve, so a short `x` must be rejected rather than zero-padded
/// into a different key.
fn coordinate(value: &str) -> Result<[u8; 32], JoseError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| JoseError::InvalidEncoding)?
        .try_into()
        .map_err(|_| JoseError::InvalidKey)
}

#[cfg(test)]
mod tests {
    use super::Jwk;
    use crate::error::JoseError;
    use crate::key::SigningKey;

    fn ed25519() -> SigningKey {
        SigningKey::from_ed25519_seed(&[7u8; 32])
    }

    fn p256() -> SigningKey {
        SigningKey::from_p256_scalar(&[7u8; 32]).unwrap()
    }

    #[test]
    fn round_trips_both_key_types() {
        for key in [ed25519(), p256()] {
            let jwk = Jwk::from_verifying_key(&key.verifying_key());
            assert_eq!(jwk.to_verifying_key().unwrap(), key.verifying_key());
        }
    }

    #[test]
    fn serializes_in_a_fixed_member_order() {
        let ed =
            serde_json::to_string(&Jwk::from_verifying_key(&ed25519().verifying_key())).unwrap();
        assert!(ed.starts_with(r#"{"alg":"EdDSA","kty":"OKP","crv":"Ed25519","x":"#));
        assert!(!ed.contains("\"y\""), "an OKP key has no y coordinate");

        let ec = serde_json::to_string(&Jwk::from_verifying_key(&p256().verifying_key())).unwrap();
        assert!(ec.starts_with(r#"{"alg":"ES256","kty":"EC","crv":"P-256","x":"#));
        assert!(ec.contains("\"y\""));
    }

    #[test]
    fn requires_the_alg_member() {
        let mut jwk = Jwk::from_verifying_key(&ed25519().verifying_key());
        jwk.alg = None;
        assert!(matches!(jwk.to_verifying_key(), Err(JoseError::MissingAlg)));
    }

    // `alg` decides which algorithm a proof must use, so the key material has to
    // agree with it. If `kty` won instead, a token could name one algorithm and
    // be verified under another.
    #[test]
    fn rejects_a_key_type_that_contradicts_alg() {
        let mut jwk = Jwk::from_verifying_key(&ed25519().verifying_key());
        jwk.alg = Some("ES256".to_owned());
        assert!(matches!(jwk.to_verifying_key(), Err(JoseError::InvalidKey)));

        let mut jwk = Jwk::from_verifying_key(&p256().verifying_key());
        jwk.alg = Some("EdDSA".to_owned());
        assert!(matches!(jwk.to_verifying_key(), Err(JoseError::InvalidKey)));
    }

    #[test]
    fn rejects_an_ec_key_without_y() {
        let mut jwk = Jwk::from_verifying_key(&p256().verifying_key());
        jwk.y = None;
        assert!(matches!(jwk.to_verifying_key(), Err(JoseError::InvalidKey)));
    }

    #[test]
    fn rejects_an_okp_key_carrying_y() {
        let mut jwk = Jwk::from_verifying_key(&ed25519().verifying_key());
        jwk.y = Some("AAAA".to_owned());
        assert!(matches!(jwk.to_verifying_key(), Err(JoseError::InvalidKey)));
    }

    // RFC 7518 Section 6.2.1.2 fixes the coordinate length to the curve's, so a
    // short value must be refused rather than padded into a different key.
    #[test]
    fn rejects_a_short_coordinate() {
        let mut jwk = Jwk::from_verifying_key(&p256().verifying_key());
        jwk.x =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [1u8; 31]);
        assert!(matches!(jwk.to_verifying_key(), Err(JoseError::InvalidKey)));
    }

    #[test]
    fn rejects_a_point_that_is_not_on_the_curve() {
        let mut jwk = Jwk::from_verifying_key(&p256().verifying_key());
        jwk.y = Some(base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            [9u8; 32],
        ));
        assert!(matches!(jwk.to_verifying_key(), Err(JoseError::InvalidKey)));
    }

    #[test]
    fn rejects_a_forbidden_alg() {
        let mut jwk = Jwk::from_verifying_key(&ed25519().verifying_key());
        jwk.alg = Some("HS256".to_owned());
        assert!(matches!(
            jwk.to_verifying_key(),
            Err(JoseError::ForbiddenAlg { .. })
        ));
    }
}

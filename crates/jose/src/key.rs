//! Signing and verifying keys for the algorithms WIMSE credentials use.

use ed25519_dalek::Signer as _;
use p256::ecdsa::signature::Verifier as _;

use crate::error::JoseError;

/// A JOSE signature algorithm this workspace can produce and verify.
///
/// Both are asymmetric and, crucially, both are **deterministic**: Ed25519 by
/// construction (RFC 8032) and ECDSA P-256 through the RFC 6979 nonce the
/// `ecdsa` crate derives from the key and message. That is what lets a
/// conformance vector record signature bytes at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Algorithm {
    /// `EdDSA` over Ed25519 (RFC 8037).
    EdDsa,
    /// `ES256`: ECDSA using P-256 and SHA-256 (RFC 7518 Section 3.4).
    Es256,
}

impl Algorithm {
    /// The JOSE `alg` value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EdDsa => "EdDSA",
            Self::Es256 => "ES256",
        }
    }

    /// Parses a JOSE `alg` value.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::ForbiddenAlg`] for `none`, a symmetric algorithm or
    /// an encryption algorithm — the families a proof of possession may never
    /// use — and [`JoseError::UnsupportedAlg`] for anything else this crate
    /// cannot produce.
    pub fn parse(alg: &str) -> Result<Self, JoseError> {
        match alg {
            "EdDSA" => Ok(Self::EdDsa),
            "ES256" => Ok(Self::Es256),
            other if crate::error::is_forbidden_alg(other) => Err(JoseError::ForbiddenAlg {
                found: other.to_owned(),
            }),
            other => Err(JoseError::UnsupportedAlg {
                found: other.to_owned(),
            }),
        }
    }
}

/// The length of a JOSE signature for either supported algorithm.
///
/// Ed25519 signatures are 64 bytes (RFC 8032) and an ES256 signature is `R || S`
/// with each half 32 bytes (RFC 7518 Section 3.4). They coincide, which lets the
/// token formats carry one fixed-size signature. Adding ES384 or ES512 would
/// break that assumption, and every use of this constant is where it breaks.
pub const SIGNATURE_LEN: usize = 64;

/// A private key that can sign.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SigningKey {
    /// An Ed25519 signing key.
    Ed25519(Box<ed25519_dalek::SigningKey>),
    /// A P-256 signing key.
    P256(Box<p256::ecdsa::SigningKey>),
}

impl SigningKey {
    /// Builds an Ed25519 signing key from its 32-byte seed.
    #[must_use]
    pub fn from_ed25519_seed(seed: &[u8; 32]) -> Self {
        Self::Ed25519(Box::new(ed25519_dalek::SigningKey::from_bytes(seed)))
    }

    /// Builds a P-256 signing key from its 32-byte scalar.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::InvalidKey`] if the bytes are not a valid non-zero
    /// scalar below the curve order.
    pub fn from_p256_scalar(scalar: &[u8; 32]) -> Result<Self, JoseError> {
        p256::ecdsa::SigningKey::from_bytes(scalar.into())
            .map(|key| Self::P256(Box::new(key)))
            .map_err(|_| JoseError::InvalidKey)
    }

    /// The algorithm this key signs with.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        match self {
            Self::Ed25519(_) => Algorithm::EdDsa,
            Self::P256(_) => Algorithm::Es256,
        }
    }

    /// The matching public key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        match self {
            Self::Ed25519(key) => VerifyingKey::Ed25519(Box::new(key.verifying_key())),
            Self::P256(key) => VerifyingKey::P256(Box::new(*key.verifying_key())),
        }
    }

    /// The private scalar or seed, as the 32 bytes it is stored from.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        match self {
            Self::Ed25519(key) => key.to_bytes(),
            Self::P256(key) => key.to_bytes().into(),
        }
    }

    /// Signs `message`, producing [`SIGNATURE_LEN`] bytes.
    ///
    /// Deterministic for both algorithms, so the same key and message always
    /// produce the same bytes.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        match self {
            Self::Ed25519(key) => key.sign(message).to_bytes(),
            Self::P256(key) => {
                let signature: p256::ecdsa::Signature = key.sign(message);
                signature.to_bytes().into()
            }
        }
    }
}

/// A public key that can verify.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyingKey {
    /// An Ed25519 verifying key.
    Ed25519(Box<ed25519_dalek::VerifyingKey>),
    /// A P-256 verifying key.
    P256(Box<p256::ecdsa::VerifyingKey>),
}

impl VerifyingKey {
    /// The algorithm this key verifies.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        match self {
            Self::Ed25519(_) => Algorithm::EdDsa,
            Self::P256(_) => Algorithm::Es256,
        }
    }

    /// The raw public key bytes: the 32-byte Ed25519 point, or the 65-byte
    /// uncompressed SEC1 encoding of a P-256 point.
    ///
    /// The two are different lengths and neither is self-describing, so
    /// [`VerifyingKey::from_raw_bytes`] has to be told which algorithm it is
    /// reading. Prefer a [`Jwk`](crate::Jwk) anywhere the algorithm has to
    /// travel with the key.
    #[must_use]
    pub fn to_raw_bytes(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(key) => key.to_bytes().to_vec(),
            Self::P256(key) => key.to_sec1_point(false).as_bytes().to_vec(),
        }
    }

    /// Parses raw public key bytes for `algorithm`.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::InvalidKey`] if the bytes are the wrong length for
    /// the algorithm, or are not a valid point.
    pub fn from_raw_bytes(algorithm: Algorithm, bytes: &[u8]) -> Result<Self, JoseError> {
        match algorithm {
            Algorithm::EdDsa => {
                let bytes: [u8; 32] = bytes.try_into().map_err(|_| JoseError::InvalidKey)?;
                ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                    .map(|key| Self::Ed25519(Box::new(key)))
                    .map_err(|_| JoseError::InvalidKey)
            }
            Algorithm::Es256 => p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
                .map(|key| Self::P256(Box::new(key)))
                .map_err(|_| JoseError::InvalidKey),
        }
    }

    /// Verifies `signature` over `message`.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::InvalidSignature`] if it does not verify.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JoseError> {
        let signature: [u8; SIGNATURE_LEN] = signature
            .try_into()
            .map_err(|_| JoseError::InvalidSignature)?;
        match self {
            Self::Ed25519(key) => key
                // `verify_strict` rejects small-order and torsion components,
                // which plain `verify` accepts; two verifiers disagreeing about
                // one signature is exactly the interop break to avoid.
                .verify_strict(message, &ed25519_dalek::Signature::from_bytes(&signature))
                .map_err(|_| JoseError::InvalidSignature),
            Self::P256(key) => {
                let signature = p256::ecdsa::Signature::from_bytes(&signature.into())
                    .map_err(|_| JoseError::InvalidSignature)?;
                key.verify(message, &signature)
                    .map_err(|_| JoseError::InvalidSignature)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Algorithm, SigningKey, VerifyingKey};
    use crate::error::JoseError;

    fn keys() -> [SigningKey; 2] {
        [
            SigningKey::from_ed25519_seed(&[7u8; 32]),
            SigningKey::from_p256_scalar(&[7u8; 32]).unwrap(),
        ]
    }

    #[test]
    fn round_trips_for_both_algorithms() {
        for key in keys() {
            let signature = key.sign(b"payload");
            assert!(key.verifying_key().verify(b"payload", &signature).is_ok());
            assert!(key.verifying_key().verify(b"other", &signature).is_err());
        }
    }

    // The whole conformance-vector design rests on this: a recorded signature is
    // only a contract if signing is reproducible.
    #[test]
    fn signing_is_deterministic_for_both_algorithms() {
        for key in keys() {
            assert_eq!(key.sign(b"payload"), key.sign(b"payload"));
        }
    }

    #[test]
    fn a_signature_does_not_verify_under_the_other_algorithm() {
        let [ed, p256] = keys();
        let signature = ed.sign(b"payload");
        assert!(p256.verifying_key().verify(b"payload", &signature).is_err());
    }

    #[test]
    fn rejects_a_wrong_length_signature() {
        for key in keys() {
            let err = key.verifying_key().verify(b"payload", &[0u8; 32]);
            assert!(matches!(err, Err(JoseError::InvalidSignature)));
        }
    }

    #[test]
    fn parses_the_supported_algorithms() {
        assert_eq!(Algorithm::parse("EdDSA").unwrap(), Algorithm::EdDsa);
        assert_eq!(Algorithm::parse("ES256").unwrap(), Algorithm::Es256);
        assert_eq!(Algorithm::EdDsa.as_str(), "EdDSA");
        assert_eq!(Algorithm::Es256.as_str(), "ES256");
    }

    // A forbidden algorithm and an unimplemented one are different failures: one
    // is a spec violation, the other is this crate's limit.
    #[test]
    fn separates_forbidden_from_merely_unsupported() {
        for forbidden in ["none", "HS256", "ECDH-ES+A128KW"] {
            assert!(
                matches!(
                    Algorithm::parse(forbidden),
                    Err(JoseError::ForbiddenAlg { .. })
                ),
                "{forbidden} must be forbidden"
            );
        }
        assert!(matches!(
            Algorithm::parse("ES384"),
            Err(JoseError::UnsupportedAlg { .. })
        ));
    }

    #[test]
    fn rejects_an_invalid_p256_scalar() {
        assert!(matches!(
            SigningKey::from_p256_scalar(&[0u8; 32]),
            Err(JoseError::InvalidKey)
        ));
    }

    #[test]
    fn reports_its_algorithm() {
        let [ed, p256] = keys();
        assert_eq!(ed.algorithm(), Algorithm::EdDsa);
        assert_eq!(p256.algorithm(), Algorithm::Es256);
        assert_eq!(ed.verifying_key().algorithm(), Algorithm::EdDsa);
        assert_eq!(p256.verifying_key().algorithm(), Algorithm::Es256);
    }

    #[test]
    fn keys_round_trip_through_their_bytes() {
        let [ed, p256] = keys();
        assert_eq!(
            SigningKey::from_ed25519_seed(&ed.to_bytes()).verifying_key(),
            ed.verifying_key()
        );
        assert_eq!(
            SigningKey::from_p256_scalar(&p256.to_bytes())
                .unwrap()
                .verifying_key(),
            p256.verifying_key()
        );
    }

    #[test]
    fn raw_public_key_bytes_round_trip() {
        for key in keys() {
            let public = key.verifying_key();
            let raw = public.to_raw_bytes();
            assert_eq!(
                VerifyingKey::from_raw_bytes(public.algorithm(), &raw).unwrap(),
                public
            );
        }
        // The encodings are different lengths, which is why the algorithm has
        // to be supplied rather than inferred.
        let [ed, p256] = keys();
        assert_eq!(ed.verifying_key().to_raw_bytes().len(), 32);
        assert_eq!(p256.verifying_key().to_raw_bytes().len(), 65);
    }

    #[test]
    fn rejects_raw_bytes_of_the_wrong_length() {
        assert!(matches!(
            VerifyingKey::from_raw_bytes(Algorithm::EdDsa, &[0u8; 65]),
            Err(JoseError::InvalidKey)
        ));
        assert!(matches!(
            VerifyingKey::from_raw_bytes(Algorithm::Es256, &[0u8; 32]),
            Err(JoseError::InvalidKey)
        ));
    }

    #[test]
    fn verifying_keys_compare_by_value() {
        let [ed, _] = keys();
        let same: VerifyingKey = SigningKey::from_ed25519_seed(&[7u8; 32]).verifying_key();
        assert_eq!(ed.verifying_key(), same);
    }
}

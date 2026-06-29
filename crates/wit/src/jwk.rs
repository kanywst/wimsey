//! A minimal JSON Web Key for Ed25519 public keys (`OKP` / `Ed25519`).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::error::WitError;

/// An `OKP` JSON Web Key holding an Ed25519 public key (RFC 8037).
///
/// This is the public confirmation key carried in a WIT's `cnf` claim: the
/// workload proves possession of the matching private key in a Workload Proof
/// Token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type; always `OKP` here.
    pub kty: String,
    /// Curve; always `Ed25519` here.
    pub crv: String,
    /// The Base64url-encoded public key.
    pub x: String,
}

impl Jwk {
    /// Builds a JWK from an Ed25519 verifying key.
    #[must_use]
    pub fn from_ed25519(key: &VerifyingKey) -> Self {
        Self {
            kty: "OKP".to_owned(),
            crv: "Ed25519".to_owned(),
            x: URL_SAFE_NO_PAD.encode(key.to_bytes()),
        }
    }

    /// Decodes this JWK into an Ed25519 verifying key.
    ///
    /// # Errors
    ///
    /// Returns [`WitError::InvalidKey`] if the key type or curve is not Ed25519,
    /// or if `x` is not a valid 32-byte Ed25519 public key.
    pub fn to_ed25519(&self) -> Result<VerifyingKey, WitError> {
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

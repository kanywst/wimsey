//! OKP (Ed25519) JSON Web Key files used by the CLI.
//!
//! A private key file is an OKP JWK with the `d` member (the 32-byte seed); a
//! public key file omits `d`.

use std::path::Path;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::Result;

/// An OKP/Ed25519 JSON Web Key.
#[derive(Serialize, Deserialize)]
pub struct JwkKey {
    /// Key type; always `OKP`.
    pub kty: String,
    /// Curve; always `Ed25519`.
    pub crv: String,
    /// The Base64url-encoded public key.
    pub x: String,
    /// The Base64url-encoded 32-byte private seed, for private keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
}

impl JwkKey {
    /// Builds a private JWK from an Ed25519 signing key.
    pub fn from_signing_key(key: &SigningKey) -> Self {
        Self {
            kty: "OKP".to_owned(),
            crv: "Ed25519".to_owned(),
            x: URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
            d: Some(URL_SAFE_NO_PAD.encode(key.to_bytes())),
        }
    }

    /// A copy of this key with the private component removed.
    pub fn to_public(&self) -> Self {
        Self {
            kty: self.kty.clone(),
            crv: self.crv.clone(),
            x: self.x.clone(),
            d: None,
        }
    }

    fn check_type(&self) -> Result<()> {
        if self.kty != "OKP" || self.crv != "Ed25519" {
            return Err("unsupported key: expected kty=OKP, crv=Ed25519".into());
        }
        Ok(())
    }

    /// The Ed25519 signing key; errors if this is a public-only key or if the
    /// stored public key `x` does not match the private seed `d`.
    pub fn signing_key(&self) -> Result<SigningKey> {
        self.check_type()?;
        let d = self
            .d
            .as_ref()
            .ok_or("key file has no private component `d`")?;
        let bytes = URL_SAFE_NO_PAD.decode(d)?;
        let seed: [u8; 32] = bytes.try_into().map_err(|_| "`d` is not 32 bytes")?;
        let signing_key = SigningKey::from_bytes(&seed);

        let advertised: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&self.x)?
            .try_into()
            .map_err(|_| "`x` is not 32 bytes")?;
        if advertised != signing_key.verifying_key().to_bytes() {
            return Err("private key `d` does not match public key `x`".into());
        }
        Ok(signing_key)
    }

    /// The Ed25519 verifying (public) key.
    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        self.check_type()?;
        let bytes = URL_SAFE_NO_PAD.decode(&self.x)?;
        let public: [u8; 32] = bytes.try_into().map_err(|_| "`x` is not 32 bytes")?;
        VerifyingKey::from_bytes(&public).map_err(|_| "`x` is not a valid Ed25519 key".into())
    }
}

/// Reads a JWK key file.
pub fn load(path: &Path) -> Result<JwkKey> {
    let bytes = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Serializes a JWK as pretty JSON.
pub fn to_json(key: &JwkKey) -> Result<String> {
    Ok(serde_json::to_string_pretty(key)?)
}

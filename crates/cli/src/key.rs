//! Private JSON Web Key files used by the CLI.
//!
//! Two shapes, matching the two algorithms WIMSE credentials use: `OKP` with
//! `crv: Ed25519` and an `x`, or `EC` with `crv: P-256` and both `x` and `y`. A
//! private key file adds `d`; a public key file omits it.

use std::path::Path;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use wimsey_jose::{Algorithm, Jwk, SigningKey, VerifyingKey};

use crate::Result;

/// A JSON Web Key as stored on disk, private half included when present.
#[derive(Serialize, Deserialize)]
pub struct JwkKey {
    /// Key type: `OKP` for Ed25519, `EC` for P-256.
    pub kty: String,
    /// Curve: `Ed25519` or `P-256`.
    pub crv: String,
    /// The Base64url-encoded public key, or the x coordinate for `EC`.
    pub x: String,
    /// The Base64url-encoded y coordinate. Present for `EC` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    /// The Base64url-encoded 32-byte private seed or scalar, for private keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
}

impl JwkKey {
    /// Builds a private JWK from a signing key.
    pub fn from_signing_key(key: &SigningKey) -> Self {
        let public = Jwk::from_verifying_key(&key.verifying_key());
        Self {
            kty: public.kty,
            crv: public.crv,
            x: public.x,
            y: public.y,
            d: Some(URL_SAFE_NO_PAD.encode(key.to_bytes())),
        }
    }

    /// A copy of this key with the private component removed.
    pub fn to_public(&self) -> Self {
        Self {
            kty: self.kty.clone(),
            crv: self.crv.clone(),
            x: self.x.clone(),
            y: self.y.clone(),
            d: None,
        }
    }

    /// The algorithm this key file describes, from its key type and curve.
    fn algorithm(&self) -> Result<Algorithm> {
        match (self.kty.as_str(), self.crv.as_str()) {
            ("OKP", "Ed25519") => Ok(Algorithm::EdDsa),
            ("EC", "P-256") => Ok(Algorithm::Es256),
            (kty, crv) => {
                Err(format!("unsupported key: kty={kty}, crv={crv} is not Ed25519 or P-256").into())
            }
        }
    }

    /// The signing key.
    ///
    /// Errors if this is a public-only key, or if the stored public key does not
    /// match the private component — a mismatch there would mean signing with
    /// one key while advertising another.
    pub fn signing_key(&self) -> Result<SigningKey> {
        let algorithm = self.algorithm()?;
        let d = self
            .d
            .as_ref()
            .ok_or("key file has no private component `d`")?;
        let bytes = URL_SAFE_NO_PAD.decode(d.trim())?;
        let secret: [u8; 32] = bytes.try_into().map_err(|_| "`d` is not 32 bytes")?;

        let signing_key = match algorithm {
            Algorithm::EdDsa => SigningKey::from_ed25519_seed(&secret),
            Algorithm::Es256 => SigningKey::from_p256_scalar(&secret)
                .map_err(|_| "`d` is not a valid P-256 scalar")?,
            other => return Err(format!("this key file format cannot hold a {other:?} key").into()),
        };
        if signing_key.verifying_key() != self.verifying_key()? {
            return Err("private key `d` does not match the public key".into());
        }
        Ok(signing_key)
    }

    /// The verifying (public) key.
    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        let algorithm = self.algorithm()?;
        Jwk {
            alg: Some(algorithm.as_str().to_owned()),
            kty: self.kty.clone(),
            crv: self.crv.clone(),
            x: self.x.clone(),
            y: self.y.clone(),
        }
        .to_verifying_key()
        .map_err(|e| format!("invalid public key: {e}").into())
    }
}

/// Reads a JWK key file.
pub fn load(path: &Path) -> Result<JwkKey> {
    let bytes = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("parsing {}: {e}", path.display()).into())
}

/// Serializes a JWK as pretty JSON.
pub fn to_json(key: &JwkKey) -> Result<String> {
    Ok(serde_json::to_string_pretty(key)?)
}

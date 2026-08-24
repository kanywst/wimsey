//! Private JSON Web Key files used by the CLI.
//!
//! The file *is* a JWK: `OKP` with `crv: Ed25519`, or `EC` with `crv: P-256`,
//! plus `d` for a private key. The shape and its validation live in
//! `wimsey-jose`, so a key file and a key inside a credential cannot disagree
//! about what a JWK means.

use std::path::Path;

use wimsey_jose::{Jwk, PrivateJwk, SigningKey, VerifyingKey};

use crate::Result;

/// A JSON Web Key as stored on disk, private half included when present.
///
/// `d` is optional here because a public key file omits it, which
/// [`PrivateJwk`] cannot express.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct JwkKey {
    /// The algorithm this key is for.
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
    /// The Base64url-encoded 32-byte private seed or scalar, for private keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
}

impl JwkKey {
    /// Builds a private JWK from a signing key.
    pub fn from_signing_key(key: &SigningKey) -> Self {
        let jwk = PrivateJwk::from_signing_key(key);
        Self {
            alg: jwk.alg,
            kty: jwk.kty,
            crv: jwk.crv,
            x: jwk.x,
            y: jwk.y,
            d: Some(jwk.d),
        }
    }

    /// A copy of this key with the private component removed.
    pub fn to_public(&self) -> Self {
        Self {
            d: None,
            alg: self.alg.clone(),
            kty: self.kty.clone(),
            crv: self.crv.clone(),
            x: self.x.clone(),
            y: self.y.clone(),
        }
    }

    /// The public JWK, with `alg` filled in from the key type when the file
    /// omits it — older key files predate the member.
    fn public_jwk(&self) -> Result<Jwk> {
        let alg = match self.alg.as_deref() {
            Some(alg) => alg.to_owned(),
            None => match (self.kty.as_str(), self.crv.as_str()) {
                ("OKP", "Ed25519") => "EdDSA".to_owned(),
                ("EC", "P-256") => "ES256".to_owned(),
                (kty, crv) => {
                    return Err(format!("unsupported key: kty={kty}, crv={crv}").into());
                }
            },
        };
        Ok(Jwk {
            alg: Some(alg),
            kty: self.kty.clone(),
            crv: self.crv.clone(),
            x: self.x.clone(),
            y: self.y.clone(),
        })
    }

    /// The signing key.
    ///
    /// Errors if this is a public-only key, or if the stored public half does
    /// not match `d` — a mismatch would mean signing with one key while
    /// advertising another.
    pub fn signing_key(&self) -> Result<SigningKey> {
        let public = self.public_jwk()?;
        let d = self
            .d
            .as_ref()
            .ok_or("key file has no private component `d`")?;
        PrivateJwk {
            alg: public.alg.clone(),
            kty: public.kty.clone(),
            crv: public.crv.clone(),
            x: public.x.clone(),
            y: public.y.clone(),
            d: d.trim().to_owned(),
        }
        .to_signing_key()
        .map_err(|e| format!("invalid private key: {e}").into())
    }

    /// The verifying (public) key.
    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        self.public_jwk()?
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

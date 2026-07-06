//! The `wimsey-issuer` binary: an experimental WIT issuer over HTTP.
//!
//! Configuration comes from the environment:
//!
//! - `WIMSEY_ISSUER_KEY` — the Ed25519 signing seed (32 bytes, Base64url). A
//!   random ephemeral key is generated if unset.
//! - `WIMSEY_ISSUER_ISS` — the `iss` value (default `https://issuer.local`).
//! - `WIMSEY_ISSUER_KID` — an optional JOSE `kid`.
//! - `WIMSEY_ISSUER_TTL` — the default WIT lifetime in seconds (default 3600).
//! - `WIMSEY_ISSUER_ADDR` — the listen address (default `127.0.0.1:8080`).

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use wimsey_issuer::{router, Issuer};
use wimsey_wit::SigningKey;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();

    let issuer_id =
        std::env::var("WIMSEY_ISSUER_ISS").unwrap_or_else(|_| "https://issuer.local".to_owned());
    let kid = std::env::var("WIMSEY_ISSUER_KID").ok();
    let ttl = if let Ok(value) = std::env::var("WIMSEY_ISSUER_TTL") {
        let ttl: u64 = value
            .parse()
            .map_err(|e| format!("invalid WIMSEY_ISSUER_TTL: {e}"))?;
        if ttl == 0 {
            return Err("WIMSEY_ISSUER_TTL must be greater than 0".into());
        }
        ttl
    } else {
        3600
    };

    let issuer = Issuer::new(load_key()?, issuer_id, kid, ttl);
    tracing::warn!(
        "this issuer performs no workload attestation and will issue a WIT for \
         any requested subject; experimental use only"
    );
    tracing::info!(public_jwk = %serde_json::to_string(&issuer.public_jwk())?);

    let addr = std::env::var("WIMSEY_ISSUER_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("wimsey-issuer listening on http://{addr}");
    axum::serve(listener, router(Arc::new(issuer))).await?;
    Ok(())
}

fn load_key() -> Result<SigningKey> {
    if let Ok(seed) = std::env::var("WIMSEY_ISSUER_KEY") {
        let bytes = URL_SAFE_NO_PAD.decode(seed.trim().trim_end_matches('='))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "WIMSEY_ISSUER_KEY must be a 32-byte Base64url seed")?;
        Ok(SigningKey::from_bytes(&seed))
    } else {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| format!("getrandom: {e}"))?;
        tracing::warn!("WIMSEY_ISSUER_KEY not set; generated an ephemeral key");
        Ok(SigningKey::from_bytes(&seed))
    }
}

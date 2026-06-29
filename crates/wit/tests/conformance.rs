//! Conformance test driven by the shared vectors under `conformance/wit/`.
//!
//! These assert that issuance is reproducible (re-issuing from the recorded key
//! and claims yields the exact recorded token) and that verification accepts the
//! token at the recorded time and rejects it once expired. Other WIMSE
//! implementations can consume the same vectors to check interoperability.

use std::path::PathBuf;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use wimsey_wit::{issue, verify, SigningKey, Validation, WitClaims, WitError};

#[derive(Deserialize)]
struct Vector {
    issuer_signing_key_seed_b64u: String,
    kid: Option<String>,
    verify_now: u64,
    claims: WitClaims,
    token: String,
}

fn load(name: &str) -> Vector {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/wit")
        .join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).expect("vector is valid json")
}

fn signing_key(seed_b64u: &str) -> SigningKey {
    let seed = URL_SAFE_NO_PAD
        .decode(seed_b64u)
        .expect("seed is base64url");
    let seed: [u8; 32] = seed.try_into().expect("seed is 32 bytes");
    SigningKey::from_bytes(&seed)
}

#[test]
fn issuance_is_reproducible() {
    let vector = load("issue-basic.json");
    let key = signing_key(&vector.issuer_signing_key_seed_b64u);

    let reissued = issue(&vector.claims, vector.kid.as_deref(), &key).expect("issue");
    assert_eq!(
        reissued, vector.token,
        "re-issuing from the vector must reproduce the recorded token byte-for-byte"
    );
}

#[test]
fn verifies_at_the_recorded_time() {
    let vector = load("issue-basic.json");
    let key = signing_key(&vector.issuer_signing_key_seed_b64u);

    let verified = verify(
        &vector.token,
        &key.verifying_key(),
        &Validation::at(vector.verify_now),
    )
    .expect("verify");
    assert_eq!(verified.claims, vector.claims);
}

#[test]
fn rejects_once_expired() {
    let vector = load("issue-basic.json");
    let key = signing_key(&vector.issuer_signing_key_seed_b64u);

    let err = verify(
        &vector.token,
        &key.verifying_key(),
        &Validation::at(vector.claims.exp + 1),
    );
    assert!(matches!(err, Err(WitError::Expired)));
}

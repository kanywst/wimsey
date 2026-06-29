//! Conformance test driven by the shared vectors under `conformance/wpt/`.
//!
//! Asserts that proof issuance is reproducible and that the full WIT-to-WPT
//! flow verifies: a real WIT is parsed for its confirmation key, and the WPT is
//! verified against that key, audience and WIT binding.

use std::path::PathBuf;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use wimsey_wit::{verify as verify_wit, Validation as WitValidation};
use wimsey_wpt::{
    issue, verify, wit_thumbprint, SigningKey, Validation, VerifyingKey, WptClaims, WptError,
};

#[derive(Deserialize)]
struct Vector {
    pop_signing_key_seed_b64u: String,
    issuer_verifying_key_b64u: String,
    verify_now: u64,
    audience: String,
    wit: String,
    claims: WptClaims,
    proof: String,
}

fn load(name: &str) -> Vector {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/wpt")
        .join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).expect("vector is valid json")
}

fn pop_key(seed_b64u: &str) -> SigningKey {
    let seed = URL_SAFE_NO_PAD
        .decode(seed_b64u)
        .expect("seed is base64url");
    let seed: [u8; 32] = seed.try_into().expect("seed is 32 bytes");
    SigningKey::from_bytes(&seed)
}

fn verifying_key(b64u: &str) -> VerifyingKey {
    let bytes = URL_SAFE_NO_PAD.decode(b64u).expect("key is base64url");
    let bytes: [u8; 32] = bytes.try_into().expect("key is 32 bytes");
    VerifyingKey::from_bytes(&bytes).expect("valid Ed25519 key")
}

#[test]
fn issuance_is_reproducible() {
    let vector = load("proof-basic.json");
    let key = pop_key(&vector.pop_signing_key_seed_b64u);

    let reissued = issue(&vector.claims, &key).expect("issue");
    assert_eq!(
        reissued, vector.proof,
        "re-issuing from the vector must reproduce the recorded proof byte-for-byte"
    );
}

#[test]
fn wth_matches_the_recorded_wit() {
    let vector = load("proof-basic.json");
    assert_eq!(vector.claims.wth, wit_thumbprint(&vector.wit));
}

#[test]
fn full_wit_to_wpt_flow_verifies() {
    let vector = load("proof-basic.json");

    // The issuer's public key is recorded in the vector, so the WIT trust
    // anchor cannot drift away from the generator.
    let issuer_key = verifying_key(&vector.issuer_verifying_key_b64u);
    let verified_wit = verify_wit(
        &vector.wit,
        &issuer_key,
        &WitValidation::at(vector.verify_now),
    )
    .expect("WIT verifies");

    // The WPT must verify against the WIT's confirmation key.
    let validation = Validation::new(vector.verify_now, &vector.audience, &vector.wit);
    let verified = verify(&vector.proof, &verified_wit.pop_key, &validation).expect("WPT verifies");
    assert_eq!(verified.claims, vector.claims);
}

#[test]
fn rejects_proof_for_a_different_wit() {
    let vector = load("proof-basic.json");
    let key = pop_key(&vector.pop_signing_key_seed_b64u);

    let validation = Validation::new(vector.verify_now, &vector.audience, "another.wit.value");
    let err = verify(&vector.proof, &key.verifying_key(), &validation);
    assert!(matches!(err, Err(WptError::WitBindingMismatch)));
}

//! Conformance test driven by the shared vectors under `conformance/httpsig/`.
//!
//! Asserts that signing is reproducible and that the full WIMSE flow verifies:
//! a real WIT is parsed for its confirmation key, and the HTTP message
//! signature is verified against that key.

use std::path::PathBuf;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use wimsey_httpsig::{
    sign, verify, verify_content_digest, Component, HttpRequest, SignatureParams, SigningKey,
    VerifyConfig, VerifyingKey,
};
use wimsey_wit::{verify as verify_wit, Validation as WitValidation};

#[derive(Deserialize)]
struct VectorRequest {
    method: String,
    authority: String,
    path: String,
    query: Option<String>,
    headers: Vec<(String, String)>,
}

#[derive(Deserialize)]
struct VectorParams {
    created: u64,
    keyid: String,
    alg: String,
}

#[derive(Deserialize)]
struct Vector {
    pop_signing_key_seed_b64u: String,
    issuer_verifying_key_b64u: String,
    verify_now: u64,
    label: String,
    components: Vec<String>,
    params: VectorParams,
    request: VectorRequest,
    body: String,
    wit: String,
    signature_input: String,
    signature: String,
}

fn load(name: &str) -> Vector {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/httpsig")
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

fn verifying_key(b64u: &str) -> VerifyingKey {
    let bytes = URL_SAFE_NO_PAD.decode(b64u).expect("key is base64url");
    let bytes: [u8; 32] = bytes.try_into().expect("key is 32 bytes");
    VerifyingKey::from_bytes(&bytes).expect("valid Ed25519 key")
}

fn request(vector: &Vector) -> HttpRequest {
    HttpRequest {
        method: vector.request.method.clone(),
        authority: vector.request.authority.clone(),
        path: vector.request.path.clone(),
        query: vector.request.query.clone(),
        headers: vector.request.headers.clone(),
    }
}

fn components(vector: &Vector) -> Vec<Component> {
    vector
        .components
        .iter()
        .map(|id| Component::from_quoted_id(id).expect("known component identifier"))
        .collect()
}

#[test]
fn signing_is_reproducible() {
    let vector = load("sign-basic.json");
    let key = signing_key(&vector.pop_signing_key_seed_b64u);
    let params = SignatureParams {
        created: Some(vector.params.created),
        keyid: Some(vector.params.keyid.clone()),
        alg: Some(vector.params.alg.clone()),
        ..SignatureParams::default()
    };

    let signed = sign(
        &request(&vector),
        &components(&vector),
        &params,
        &vector.label,
        &key,
    )
    .expect("sign");
    assert_eq!(signed.signature_input, vector.signature_input);
    assert_eq!(signed.signature, vector.signature);
}

#[test]
fn full_wit_to_http_signature_flow_verifies() {
    let vector = load("sign-basic.json");
    let issuer_key = verifying_key(&vector.issuer_verifying_key_b64u);

    // Recover the proof-of-possession key from the WIT carried in the request.
    let verified_wit = verify_wit(
        &vector.wit,
        &issuer_key,
        &WitValidation::at(vector.verify_now),
    )
    .expect("WIT verifies");

    // Model the safe receiver: require the critical components to be covered.
    let config = VerifyConfig {
        now: Some(vector.verify_now),
        required_components: vec![
            Component::Method,
            Component::Authority,
            Component::Path,
            Component::header("content-digest"),
            Component::header("workload-identity-token"),
        ],
        ..VerifyConfig::default()
    };
    let request = request(&vector);
    let verified = verify(
        &request,
        &vector.signature_input,
        &vector.signature,
        &verified_wit.pop_key,
        &config,
    )
    .expect("HTTP signature verifies");
    assert_eq!(verified.label, vector.label);

    // Bind the body: the signed content-digest header must match the payload.
    let content_digest = request
        .headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("content-digest"))
        .map(|(_, v)| v.as_str())
        .expect("content-digest header present");
    assert!(verify_content_digest(
        content_digest,
        vector.body.as_bytes()
    ));
}

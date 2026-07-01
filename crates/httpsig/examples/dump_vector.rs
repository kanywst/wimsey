//! Regenerates the `conformance/httpsig/sign-basic.json` test vector.
//!
//! Run with `cargo run -p wimsey-httpsig --example dump_vector`. It issues a
//! real WIT, carries it in a `Workload-Identity-Token` header, and signs the
//! request with the proof-of-possession key, exercising the full WIMSE HTTP
//! Message Signatures flow. The output is deterministic.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::SigningKey;
use serde::Serialize;
use wimsey_httpsig::{content_digest_sha256, sign, Component, HttpRequest, SignatureParams, ALG};
use wimsey_identifier::WorkloadIdentifier;
use wimsey_wit::{issue as issue_wit, Confirmation, Jwk, WitClaims};

#[derive(Serialize)]
struct VectorRequest {
    method: String,
    authority: String,
    path: String,
    query: Option<String>,
    headers: Vec<(String, String)>,
}

#[derive(Serialize)]
struct VectorParams {
    created: u64,
    keyid: String,
    alg: String,
}

#[derive(Serialize)]
struct Vector {
    description: String,
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

fn main() {
    let issuer_key = SigningKey::from_bytes(&[1u8; 32]);
    let pop_seed = [9u8; 32];
    let pop_key = SigningKey::from_bytes(&pop_seed);

    let wit_claims = WitClaims {
        iss: "https://issuer.example".to_owned(),
        sub: WorkloadIdentifier::parse("spiffe://example.org/workload/api").unwrap(),
        iat: 1_700_000_000,
        exp: 1_700_003_600,
        jti: "a1b2c3".to_owned(),
        cnf: Confirmation {
            jwk: Jwk::from_ed25519(&pop_key.verifying_key()),
        },
    };
    let wit = issue_wit(&wit_claims, Some("issuer-key-1"), &issuer_key).unwrap();

    let body = br#"{"amount":100}"#;
    let request = HttpRequest {
        method: "POST".to_owned(),
        authority: "service.example".to_owned(),
        path: "/transfer".to_owned(),
        query: None,
        headers: vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("Content-Digest".to_owned(), content_digest_sha256(body)),
            ("Workload-Identity-Token".to_owned(), wit.clone()),
        ],
    };
    let components = vec![
        Component::Method,
        Component::Authority,
        Component::Path,
        Component::header("content-digest"),
        Component::header("workload-identity-token"),
    ];
    let params = SignatureParams {
        created: Some(1_700_000_000),
        keyid: Some("issuer-key-1".to_owned()),
        alg: Some(ALG.to_owned()),
        ..SignatureParams::default()
    };

    let signed = sign(&request, &components, &params, "wimse", &pop_key).unwrap();

    let vector = Vector {
        description: "WIMSE HTTP Message Signature (RFC 9421, ed25519) carrying a WIT".to_owned(),
        pop_signing_key_seed_b64u: URL_SAFE_NO_PAD.encode(pop_seed),
        issuer_verifying_key_b64u: URL_SAFE_NO_PAD.encode(issuer_key.verifying_key().to_bytes()),
        verify_now: 1_700_000_100,
        label: "wimse".to_owned(),
        components: components.iter().map(Component::quoted_id).collect(),
        params: VectorParams {
            created: 1_700_000_000,
            keyid: "issuer-key-1".to_owned(),
            alg: ALG.to_owned(),
        },
        request: VectorRequest {
            method: request.method,
            authority: request.authority,
            path: request.path,
            query: request.query,
            headers: request.headers,
        },
        body: String::from_utf8(body.to_vec()).unwrap(),
        wit,
        signature_input: signed.signature_input,
        signature: signed.signature,
    };

    println!("{}", serde_json::to_string_pretty(&vector).unwrap());
}

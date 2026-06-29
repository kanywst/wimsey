//! Regenerates the `conformance/wpt/proof-basic.json` test vector.
//!
//! Run with `cargo run -p wimsey-wpt --example dump_vector`. It issues a real
//! WIT (whose `cnf` is the proof-of-possession public key) and then a WPT bound
//! to that WIT, so the vector exercises the full WIT-to-WPT flow. The output is
//! deterministic.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::SigningKey;
use serde::Serialize;
use wimsey_identifier::WorkloadIdentifier;
use wimsey_wit::{issue as issue_wit, Confirmation, Jwk, WitClaims};
use wimsey_wpt::{issue as issue_wpt, wit_thumbprint, WptClaims};

#[derive(Serialize)]
struct Vector {
    description: String,
    alg: String,
    pop_signing_key_seed_b64u: String,
    issuer_verifying_key_b64u: String,
    verify_now: u64,
    audience: String,
    wit: String,
    claims: WptClaims,
    proof: String,
}

fn main() {
    let issuer_key = SigningKey::from_bytes(&[1u8; 32]);
    let pop_seed = [9u8; 32];
    let pop_key = SigningKey::from_bytes(&pop_seed);

    // A WIT whose confirmation key is the proof-of-possession public key.
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

    let audience = "https://workload.example.com/path".to_owned();
    let claims = WptClaims {
        aud: audience.clone(),
        exp: 1_700_000_300,
        jti: "0123456789abcdef".to_owned(),
        wth: wit_thumbprint(&wit),
        ath: None,
    };
    let proof = issue_wpt(&claims, &pop_key).unwrap();

    let vector = Vector {
        description: "WPT bound to a WIT, EdDSA (Ed25519), draft-ietf-wimse-wpt-01".to_owned(),
        alg: "EdDSA".to_owned(),
        pop_signing_key_seed_b64u: URL_SAFE_NO_PAD.encode(pop_seed),
        issuer_verifying_key_b64u: URL_SAFE_NO_PAD.encode(issuer_key.verifying_key().to_bytes()),
        verify_now: 1_700_000_000,
        audience,
        wit,
        claims,
        proof,
    };

    println!("{}", serde_json::to_string_pretty(&vector).unwrap());
}

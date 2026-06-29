//! Regenerates the `conformance/wit/issue-basic.json` test vector.
//!
//! Run with `cargo run -p wimsey-wit --example dump_vector`. The output is
//! deterministic: piping it to the vector file should produce no diff unless the
//! token format intentionally changed.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::SigningKey;
use serde::Serialize;
use wimsey_identifier::WorkloadIdentifier;
use wimsey_wit::{issue, Confirmation, Jwk, WitClaims};

#[derive(Serialize)]
struct Vector {
    description: String,
    alg: String,
    issuer_signing_key_seed_b64u: String,
    kid: Option<String>,
    verify_now: u64,
    claims: WitClaims,
    token: String,
}

fn main() {
    let issuer_seed = [1u8; 32];
    let issuer_key = SigningKey::from_bytes(&issuer_seed);
    let pop_key = SigningKey::from_bytes(&[7u8; 32]);

    let claims = WitClaims {
        iss: "https://issuer.example".to_owned(),
        sub: WorkloadIdentifier::parse("spiffe://example.org/workload/api").unwrap(),
        iat: 1_700_000_000,
        exp: 1_700_003_600,
        jti: "a1b2c3".to_owned(),
        cnf: Confirmation {
            jwk: Jwk::from_ed25519(&pop_key.verifying_key()),
        },
    };

    let kid = Some("issuer-key-1".to_owned());
    let token = issue(&claims, kid.as_deref(), &issuer_key).unwrap();

    let vector = Vector {
        description: "WIT issuance with EdDSA (Ed25519), draft-ietf-wimse-workload-creds-01"
            .to_owned(),
        alg: "EdDSA".to_owned(),
        issuer_signing_key_seed_b64u: URL_SAFE_NO_PAD.encode(issuer_seed),
        kid,
        verify_now: 1_700_000_000,
        claims,
        token,
    };

    println!("{}", serde_json::to_string_pretty(&vector).unwrap());
}

//! An end-to-end WIMSE demo: two services with a middlebox between them.
//!
//! Run it with `cargo run -p wimsey-demo`. Every step asserts, so the process
//! exits non-zero the moment the trust chain stops holding — which is what makes
//! this a CI gate and not just a printout.
//!
//! The point the demo exists to make is the one that is hard to see from the
//! crate docs alone: an HTTP-signature-bound WIMSE request survives an
//! intermediary that reads and *adds to* it, and fails the instant that
//! intermediary changes anything the signature covers.
//!
//! Keys and timestamps are fixed, and Ed25519 is deterministic, so every run
//! prints the same bytes. The one exception is the mTLS step, whose certificate
//! keys are generated fresh; nothing in its output is byte-compared.

use ed25519_dalek::SigningKey;
use wimsey_httpsig::{
    content_digest_sha256, verify_content_digest, Component, HttpRequest, SignatureParams,
    VerifyConfig, WIMSE_LABEL, WIMSE_TAG,
};
use wimsey_identifier::WorkloadIdentifier;
use wimsey_mtls::WorkloadCa;
use wimsey_wit::{Confirmation, Jwk, WitClaims};
use wimsey_wpt::{wit_thumbprint, WptClaims};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The identity server's signing key. Fixed so the demo reproduces.
const ISSUER_SEED: [u8; 32] = [1u8; 32];
/// Service A's proof-of-possession key. Its public half goes in the WIT `cnf`.
const POP_SEED: [u8; 32] = [9u8; 32];

const ISSUER: &str = "https://identity.demo.example";
const SERVICE_A: &str = "wimse://demo.example/service/a";
const SERVICE_B_AUDIENCE: &str = "https://b.demo.example/transfer";

const NOW: u64 = 1_700_000_000;
/// When service B does its verifying — a few seconds after A signed.
const LATER: u64 = NOW + 5;

fn rule(title: &str) {
    // Count characters, not bytes: the titles carry an em dash, and padding by
    // `len()` would leave the rules ragged.
    let width = 64_usize.saturating_sub(title.chars().count());
    println!("\n── {title} {}", "─".repeat(width));
}

fn main() -> Result<()> {
    println!("WIMSE end-to-end demo — service A calls service B through a middlebox");

    let issuer_key = SigningKey::from_bytes(&ISSUER_SEED);
    let pop_key = SigningKey::from_bytes(&POP_SEED);

    let wit = issue_wit(&issuer_key, &pop_key)?;
    let body = br#"{"amount":100,"to":"acct-42"}"#;
    let signed = sign_request(&pop_key, &wit, body)?;

    forwarded_by_a_middlebox(&issuer_key, &wit, &signed, body)?;
    tampered_by_a_middlebox(&issuer_key, &wit, &signed, body)?;
    proof_token_instead(&issuer_key, &pop_key, &wit)?;
    mutual_tls_instead()?;

    println!("\nAll steps held. The trust chain is intact end to end.");
    Ok(())
}

/// Step 1 — the identity server binds service A's identifier to its `cnf` key.
fn issue_wit(issuer_key: &SigningKey, pop_key: &SigningKey) -> Result<String> {
    rule("1. the identity server issues a WIT to service A");

    let claims = WitClaims {
        iss: Some(ISSUER.to_owned()),
        sub: WorkloadIdentifier::parse(SERVICE_A)?,
        iat: Some(NOW),
        exp: NOW + 3600,
        jti: Some("wit-0001".to_owned()),
        cnf: Confirmation {
            jwk: Jwk::from_ed25519(&pop_key.verifying_key()),
        },
    };
    let wit = wimsey_wit::issue(&claims, Some("issuer-key-1"), issuer_key)?;

    println!("   subject      {SERVICE_A}");
    println!(
        "   confirmation {} (the key A must prove it holds)",
        claims.cnf.jwk.alg.as_deref().unwrap_or("?")
    );
    println!("   WIT          {}…{}", &wit[..24], &wit[wit.len() - 8..]);
    Ok(wit)
}

/// Step 2 — service A signs the outgoing request with the key the WIT names.
fn sign_request(
    pop_key: &SigningKey,
    wit: &str,
    body: &[u8],
) -> Result<wimsey_httpsig::SignedSignature> {
    rule("2. service A signs its request to service B");

    let request = request_as_sent(wit, body, "/transfer", &[]);
    let params = SignatureParams {
        created: Some(NOW),
        expires: Some(NOW + 300),
        nonce: Some("nonce-0001".to_owned()),
        tag: Some(WIMSE_TAG.to_owned()),
        wimse_aud: Some(SERVICE_B_AUDIENCE.to_owned()),
        ..SignatureParams::default()
    };
    let signed = wimsey_httpsig::sign(&request, &covered(), &params, WIMSE_LABEL, pop_key)?;

    println!(
        "   covered      {}",
        covered()
            .iter()
            .map(Component::quoted_id)
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!("   audience     {SERVICE_B_AUDIENCE}");
    println!("   Signature-Input: {}", signed.signature_input);
    Ok(signed)
}

/// Step 3 — the middlebox reads the request and adds to it. B still verifies.
fn forwarded_by_a_middlebox(
    issuer_key: &SigningKey,
    wit: &str,
    signed: &wimsey_httpsig::SignedSignature,
    body: &[u8],
) -> Result<()> {
    rule("3. a middlebox forwards it, adding a header of its own");

    // The middlebox can read the WIT — it is a header, not a secret — and can
    // annotate the request. Neither touches a covered component.
    let seen = wimsey_wit::verify(
        wit,
        &issuer_key.verifying_key(),
        &wimsey_wit::Validation::at(LATER),
    )?;
    println!("   middlebox sees the caller is {}", seen.claims.sub);
    println!("   middlebox adds X-Forwarded-By: middlebox.demo.example");

    let forwarded = request_as_sent(
        wit,
        body,
        "/transfer",
        &[("X-Forwarded-By", "middlebox.demo.example")],
    );
    let identifier = service_b_verifies(issuer_key, wit, signed, &forwarded, body)?;
    println!("   service B accepted a request from {identifier}");
    Ok(())
}

/// Step 4 — the same middlebox rewrites a covered component. B must refuse.
fn tampered_by_a_middlebox(
    issuer_key: &SigningKey,
    wit: &str,
    signed: &wimsey_httpsig::SignedSignature,
    body: &[u8],
) -> Result<()> {
    rule("4. the middlebox reroutes the request — service B must refuse");

    // `@request-target` is covered, so redirecting /transfer to /admin breaks the
    // signature even though every byte of the credential is still valid.
    let rerouted = request_as_sent(wit, body, "/admin", &[]);
    let outcome = service_b_verifies(issuer_key, wit, signed, &rerouted, body);
    let error = outcome.expect_err("a rerouted request must not verify");
    println!("   middlebox rewrote @request-target from /transfer to /admin");
    println!("   service B rejected it: {error}");

    // And the same for the body, which the digest — not the signature — pins.
    let swapped = br#"{"amount":999,"to":"acct-99"}"#;
    let request = request_as_sent(wit, body, "/transfer", &[]);
    assert!(
        !verify_content_digest(
            &request.component_value(&Component::header("content-digest"))?,
            swapped,
        ),
        "a swapped body must not match the signed Content-Digest"
    );
    println!("   middlebox swapped the body: Content-Digest no longer matches");
    Ok(())
}

/// Step 5 — the same trust chain carried by a Workload Proof Token instead.
fn proof_token_instead(issuer_key: &SigningKey, pop_key: &SigningKey, wit: &str) -> Result<()> {
    rule("5. the same proof, carried as a WPT instead of a signature");

    let claims = WptClaims {
        aud: SERVICE_B_AUDIENCE.to_owned(),
        exp: NOW + 120,
        jti: "wpt-0001".to_owned(),
        wth: wit_thumbprint(wit),
        ath: None,
    };
    let proof = wimsey_wpt::issue(&claims, pop_key)?;

    // Service B recovers the key from the WIT it just verified, never from the
    // proof itself — that is what binds the two together.
    let verified_wit = wimsey_wit::verify(
        wit,
        &issuer_key.verifying_key(),
        &wimsey_wit::Validation::at(LATER),
    )?;
    let validation = wimsey_wpt::Validation::new(LATER, SERVICE_B_AUDIENCE, wit);
    let verified = wimsey_wpt::verify(&proof, &verified_wit.pop_key, &validation)?;

    println!(
        "   wth          {} (SHA-256 of the WIT)",
        verified.claims.wth
    );
    println!(
        "   service B accepted the proof for {}",
        verified_wit.claims.sub
    );

    // A proof minted for one WIT must not travel with another.
    let other_wit = wimsey_wit::issue(
        &WitClaims {
            jti: Some("wit-0002".to_owned()),
            ..rebuild_claims(pop_key)?
        },
        Some("issuer-key-1"),
        issuer_key,
    )?;
    let replayed = wimsey_wpt::Validation::new(LATER, SERVICE_B_AUDIENCE, &other_wit);
    let error = wimsey_wpt::verify(&proof, &verified_wit.pop_key, &replayed)
        .expect_err("a proof bound to one WIT must not verify against another");
    println!("   replayed against a different WIT: {error}");
    Ok(())
}

/// Step 6 — the same identifier, carried by an X.509 certificate instead.
fn mutual_tls_instead() -> Result<()> {
    rule("6. the same identity over mTLS, as a WIC");

    let ca = WorkloadCa::generate()?;
    let identifier = WorkloadIdentifier::parse(SERVICE_A)?;
    let wic = ca.issue_wic(&identifier, NOW, NOW + 86_400)?;

    let presented = wimsey_mtls::verify(&wic.certificate_der, ca.certificate_der(), LATER)?;
    assert_eq!(presented, identifier, "the WIC must carry A's identifier");
    println!("   certificate URI SAN {presented}");

    // A certificate from an unrelated CA must not be accepted as this one's peer.
    let stranger = WorkloadCa::generate()?;
    let error = wimsey_mtls::verify(&wic.certificate_der, stranger.certificate_der(), LATER)
        .expect_err("a WIC must not verify against a CA that did not sign it");
    println!("   verified against an unrelated CA: {error}");
    Ok(())
}

/// The components the WIMSE profile requires this request to cover.
fn covered() -> Vec<Component> {
    vec![
        Component::Method,
        Component::RequestTarget,
        Component::header("content-type"),
        Component::header("content-digest"),
        Component::header("workload-identity-token"),
    ]
}

/// The request as it appears on the wire, optionally with headers a middlebox
/// added along the way.
fn request_as_sent(wit: &str, body: &[u8], path: &str, extra: &[(&str, &str)]) -> HttpRequest {
    let mut headers = vec![
        ("Content-Type".to_owned(), "application/json".to_owned()),
        ("Content-Digest".to_owned(), content_digest_sha256(body)),
        ("Workload-Identity-Token".to_owned(), wit.to_owned()),
    ];
    headers.extend(
        extra
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    );
    HttpRequest {
        method: "POST".to_owned(),
        authority: "b.demo.example".to_owned(),
        path: path.to_owned(),
        query: None,
        headers,
    }
}

/// Everything service B does on receipt, in order: the WIT first, then the
/// signature under the key that WIT names, then the body against its digest.
fn service_b_verifies(
    issuer_key: &SigningKey,
    wit: &str,
    signed: &wimsey_httpsig::SignedSignature,
    request: &HttpRequest,
    body: &[u8],
) -> Result<WorkloadIdentifier> {
    let verified_wit = wimsey_wit::verify(
        wit,
        &issuer_key.verifying_key(),
        &wimsey_wit::Validation::at(LATER),
    )?;

    let config = VerifyConfig {
        now: Some(LATER),
        required_components: covered(),
        label: Some(WIMSE_LABEL.to_owned()),
        wimse_profile: true,
        expected_audience: Some(SERVICE_B_AUDIENCE.to_owned()),
        ..VerifyConfig::default()
    };
    wimsey_httpsig::verify(
        request,
        &signed.signature_input,
        &signed.signature,
        &verified_wit.pop_key,
        &config,
    )?;

    let digest = request.component_value(&Component::header("content-digest"))?;
    if !verify_content_digest(&digest, body) {
        return Err("the body does not match the signed Content-Digest".into());
    }
    Ok(verified_wit.claims.sub)
}

/// The WIT claim set, rebuilt so a second token can be issued for the replay
/// case with a different `jti`.
fn rebuild_claims(pop_key: &SigningKey) -> Result<WitClaims> {
    Ok(WitClaims {
        iss: Some(ISSUER.to_owned()),
        sub: WorkloadIdentifier::parse(SERVICE_A)?,
        iat: Some(NOW),
        exp: NOW + 3600,
        jti: Some("wit-0001".to_owned()),
        cnf: Confirmation {
            jwk: Jwk::from_ed25519(&pop_key.verifying_key()),
        },
    })
}

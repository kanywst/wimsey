//! Drives the issuer router directly with `tower::oneshot` (no network) and
//! verifies the issued WIT end to end.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use wimsey_issuer::{router, Issuer};
use wimsey_wit::{Jwk, SigningKey, Validation};

fn app(signing_key: SigningKey) -> axum::Router {
    router(Arc::new(Issuer::new(
        signing_key,
        "https://issuer.example",
        Some("issuer-key-1".to_owned()),
        3600,
    )))
}

async fn post_wit(app: axum::Router, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let response = app
        .oneshot(
            Request::post("/wit")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn issues_a_verifiable_wit() {
    let issuer_key = SigningKey::from_bytes(&[1u8; 32]);
    let pop_key = SigningKey::from_bytes(&[9u8; 32]);

    let body = serde_json::json!({
        "sub": "spiffe://example.org/api",
        "cnf_jwk": Jwk::from_ed25519(&pop_key.verifying_key()),
    });
    let (status, json) = post_wit(app(issuer_key.clone()), body).await;
    assert_eq!(status, StatusCode::OK);

    let wit = json["wit"].as_str().expect("wit field");
    let verified = wimsey_wit::verify(
        wit,
        &issuer_key.verifying_key(),
        &Validation::at(wimsey_wit::now_unix()).expect_issuer("https://issuer.example"),
    )
    .expect("WIT verifies");
    assert_eq!(verified.claims.sub.as_str(), "spiffe://example.org/api");
    assert_eq!(verified.pop_key, pop_key.verifying_key());
    assert_eq!(verified.kid.as_deref(), Some("issuer-key-1"));
}

#[tokio::test]
async fn rejects_a_bad_subject() {
    let pop_key = SigningKey::from_bytes(&[9u8; 32]);
    let body = serde_json::json!({
        "sub": "not-a-spiffe-id",
        "cnf_jwk": Jwk::from_ed25519(&pop_key.verifying_key()),
    });
    let (status, _) = post_wit(app(SigningKey::from_bytes(&[1u8; 32])), body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rejects_an_invalid_confirmation_key() {
    let body = serde_json::json!({
        "sub": "spiffe://example.org/api",
        "cnf_jwk": { "kty": "OKP", "crv": "Ed25519", "x": "not-a-key" },
    });
    let (status, _) = post_wit(app(SigningKey::from_bytes(&[1u8; 32])), body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn healthz_and_jwks() {
    let issuer_key = SigningKey::from_bytes(&[1u8; 32]);
    let app = app(issuer_key.clone());

    let health = app
        .clone()
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);

    let jwks = app
        .oneshot(Request::get("/jwks").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let bytes = jwks.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["keys"][0]["kty"], "OKP");
    assert_eq!(json["keys"][0]["kid"], "issuer-key-1");
    assert_eq!(
        json["keys"][0]["x"],
        serde_json::to_value(Jwk::from_ed25519(&issuer_key.verifying_key()).x).unwrap()
    );
}

#[tokio::test]
async fn rejects_an_excessive_ttl() {
    let pop_key = SigningKey::from_bytes(&[9u8; 32]);
    let body = serde_json::json!({
        "sub": "spiffe://example.org/api",
        "cnf_jwk": Jwk::from_ed25519(&pop_key.verifying_key()),
        "ttl": 100_000,
    });
    // The app's default (and maximum) ttl is 3600.
    let (status, _) = post_wit(app(SigningKey::from_bytes(&[1u8; 32])), body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rejects_a_zero_ttl() {
    let pop_key = SigningKey::from_bytes(&[9u8; 32]);
    let body = serde_json::json!({
        "sub": "spiffe://example.org/api",
        "cnf_jwk": Jwk::from_ed25519(&pop_key.verifying_key()),
        "ttl": 0,
    });
    let (status, _) = post_wit(app(SigningKey::from_bytes(&[1u8; 32])), body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

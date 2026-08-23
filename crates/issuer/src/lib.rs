//! `wimsey-issuer` — an experimental WIMSE credential issuer.
//!
//! An HTTP service that issues Workload Identity Tokens. A workload presents its
//! own identifier and proof-of-possession public key (as an OKP JWK); the issuer
//! returns a WIT signed by its key, binding the identifier to that key. The
//! issuer publishes its public key at `/jwks` so verifiers can validate WITs.
//!
//! This is scoped as a reference/experimentation issuer (a Rust counterpart to
//! Cofide's `minispire`), not a SPIRE replacement; a SPIFFE Workload API shim is
//! a planned addition.
//!
//! **Warning:** this issuer performs **no workload attestation or
//! authentication** — it will issue a WIT for any `sub` any caller asks for. It
//! is for experimentation only and must not be exposed to untrusted callers.
//!
//! Routes: `POST /wit`, `GET /jwks`, `GET /healthz`. Build the router with
//! [`router`] and serve it, or drive it directly in tests.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use wimsey_identifier::WorkloadIdentifier;
use wimsey_wit::{Confirmation, Jwk, SigningKey, WitClaims};

/// The issuer's configuration and signing key.
pub struct Issuer {
    signing_key: SigningKey,
    iss: String,
    kid: Option<String>,
    default_ttl: u64,
    /// The JWKS document served at `/jwks`, pre-rendered to JSON bytes so the
    /// handler neither serializes nor deep-clones on each request.
    jwks: axum::body::Bytes,
}

impl Issuer {
    /// Creates an issuer that signs WITs with `signing_key`, claiming `iss`,
    /// stamping the JOSE `kid`, and defaulting to a `default_ttl`-second lifetime.
    ///
    /// # Panics
    ///
    /// Panics if `default_ttl` is 0, since that would reject every request that
    /// does not set an explicit TTL.
    #[must_use]
    pub fn new(
        signing_key: SigningKey,
        iss: impl Into<String>,
        kid: Option<String>,
        default_ttl: u64,
    ) -> Self {
        assert!(default_ttl > 0, "default_ttl must be greater than 0");
        // The JWKS is static, so render it once. Advertise the `kid` so verifiers
        // can match it to the WIT's JOSE header.
        let mut jwk = json!(Jwk::from_ed25519(&signing_key.verifying_key()));
        if let (Some(object), Some(kid)) = (jwk.as_object_mut(), kid.as_ref()) {
            object.insert("kid".to_owned(), json!(kid));
        }
        let jwks = serde_json::to_vec(&json!({ "keys": [jwk] }))
            .expect("a JWKS of strings always serializes");
        Self {
            signing_key,
            iss: iss.into(),
            kid,
            default_ttl,
            jwks: axum::body::Bytes::from(jwks),
        }
    }

    /// The issuer's public key as an OKP JWK.
    #[must_use]
    pub fn public_jwk(&self) -> Jwk {
        Jwk::from_ed25519(&self.signing_key.verifying_key())
    }
}

/// A request to issue a WIT for a workload.
#[derive(Deserialize)]
pub struct IssueRequest {
    /// The workload identifier to place in `sub`.
    pub sub: String,
    /// The workload's proof-of-possession public key, placed in `cnf`.
    pub cnf_jwk: Jwk,
    /// An optional lifetime in seconds; the issuer default is used if omitted.
    pub ttl: Option<u64>,
}

/// The issued WIT.
#[derive(Serialize)]
pub struct IssueResponse {
    /// The compact WIT.
    pub wit: String,
}

/// An error returned by the issuer, rendered as a JSON body with a status code.
#[derive(Debug)]
pub enum IssueError {
    /// The request was malformed (400).
    BadRequest(String),
    /// The issuer failed to produce a token (500).
    Internal(String),
}

impl IntoResponse for IssueError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, message),
            // Do not leak internal error detail to the client; log it instead.
            Self::Internal(detail) => {
                tracing::error!("issuer internal error: {detail}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_owned(),
                )
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

/// Builds the issuer's HTTP router over the shared [`Issuer`] state.
pub fn router(issuer: Arc<Issuer>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/jwks", get(jwks))
        .route("/wit", post(issue_wit))
        .with_state(issuer)
}

async fn healthz() -> &'static str {
    "ok"
}

async fn jwks(State(issuer): State<Arc<Issuer>>) -> impl IntoResponse {
    // The bytes are pre-rendered; `Bytes::clone` is a cheap refcount bump. The
    // JWKS is static, so it is cacheable; the media type is the RFC 7517 one.
    (
        [
            (axum::http::header::CONTENT_TYPE, "application/jwk-set+json"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        issuer.jwks.clone(),
    )
}

async fn issue_wit(
    State(issuer): State<Arc<Issuer>>,
    Json(request): Json<IssueRequest>,
) -> Result<Json<IssueResponse>, IssueError> {
    let sub = WorkloadIdentifier::parse(request.sub.trim())
        .map_err(|e| IssueError::BadRequest(format!("invalid sub: {e}")))?;
    // Reject a confirmation key that is not a usable Ed25519 key.
    request
        .cnf_jwk
        .to_ed25519()
        .map_err(|_| IssueError::BadRequest("invalid cnf_jwk".to_owned()))?;

    // `default_ttl` is also the maximum a client may request.
    let ttl = request.ttl.unwrap_or(issuer.default_ttl);
    if ttl == 0 {
        return Err(IssueError::BadRequest(
            "ttl must be greater than 0".to_owned(),
        ));
    }
    if ttl > issuer.default_ttl {
        return Err(IssueError::BadRequest(format!(
            "requested ttl {ttl}s exceeds the maximum of {}s",
            issuer.default_ttl
        )));
    }
    let iat = wimsey_wit::now_unix();
    let exp = iat
        .checked_add(ttl)
        .ok_or_else(|| IssueError::BadRequest("ttl overflows the expiry time".to_owned()))?;

    let claims = WitClaims {
        iss: Some(issuer.iss.clone()),
        sub,
        iat: Some(iat),
        exp,
        jti: Some(random_id().map_err(|e| IssueError::Internal(e.to_string()))?),
        cnf: Confirmation {
            jwk: request.cnf_jwk,
        },
    };
    let wit = wimsey_wit::issue(&claims, issuer.kid.as_deref(), &issuer.signing_key)
        .map_err(|e| IssueError::Internal(e.to_string()))?;
    Ok(Json(IssueResponse { wit }))
}

fn random_id() -> Result<String, getrandom::Error> {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)?;
    let mut id = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        id.push(HEX[(byte >> 4) as usize] as char);
        id.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(id)
}

//! Deterministic generation of the conformance vectors.
//!
//! Everything here is fixed: the key seeds are constants, the timestamps are
//! constants, and `EdDSA` is deterministic, so regenerating must reproduce the
//! committed files byte for byte. CI relies on that — it regenerates and diffs,
//! so an unintended encoding change shows up as a failing build rather than as a
//! silent interop break.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use wimsey_httpsig::{
    content_digest_sha256, response_components, sign, Component, HttpExchange, HttpRequest,
    HttpResponse, SignatureParams, WIMSE_TAG,
};
use wimsey_identifier::WorkloadIdentifier;
use wimsey_jose::{Algorithm, Jwk as JoseJwk, PrivateJwk, SigningKey};
use wimsey_mtls::WorkloadCa;
use wimsey_wit::{issue as issue_wit, Confirmation, Jwk, WitClaims};
use wimsey_wpt::{issue as issue_wpt, wit_thumbprint, WptClaims};

use crate::vectors::{
    ErrorCode, Header, HttpSigAccepted, HttpSigNegative, HttpSigVector, IdentifierAccept,
    IdentifierReject, IdentifierVector, Manifest, ManifestEntry, MtlsNegative, MtlsVector,
    ResponseNegative, VectorParams, VectorRequest, VectorResponse, WitNegative, WitVector,
    WptNegative, WptVector, FORMAT,
};

/// Builds a signing key of `algorithm` from a fixed seed.
///
/// The same seed under either algorithm, so an `EdDSA` vector and its `ES256`
/// twin differ only in the algorithm and not in which secret they use.
///
/// # Panics
///
/// Panics if the fixed seed is not a valid scalar for the algorithm, which
/// would mean the constants below stopped being usable.
fn key(algorithm: Algorithm, seed: [u8; 32]) -> SigningKey {
    match algorithm {
        Algorithm::Es256 => {
            SigningKey::from_p256_scalar(&seed).expect("the fixed seeds are valid P-256 scalars")
        }
        _ => SigningKey::from_ed25519_seed(&seed),
    }
}

/// The issuer's seed. Fixed so the vectors are reproducible.
const ISSUER_SEED: [u8; 32] = [1u8; 32];
/// A second issuer, used only as the wrong trust anchor in a negative case.
const OTHER_ISSUER_SEED: [u8; 32] = [2u8; 32];
/// The proof-of-possession seed used by the WIT vector.
const WIT_POP_SEED: [u8; 32] = [7u8; 32];
/// The proof-of-possession seed used by the WPT and httpsig vectors.
const POP_SEED: [u8; 32] = [9u8; 32];
/// The responding workload's own proof-of-possession seed.
const RESPONDER_POP_SEED: [u8; 32] = [11u8; 32];

const ISSUER: &str = "https://issuer.example";
const SUBJECT: &str = "spiffe://example.org/workload/api";
/// The responding workload.
const RESPONDER_SUBJECT: &str = "spiffe://example.org/workload/ledger";
const KID: &str = "issuer-key-1";
const IAT: u64 = 1_700_000_000;
const EXP: u64 = 1_700_003_600;
/// The fixed `nonce` for the httpsig vector. A real sender MUST generate a
/// unique one per recipient; it is pinned here so the vector reproduces.
const NONCE: &str = "abcd1111";
/// The fixed `wimse-aud` for the httpsig vector.
const AUDIENCE: &str = "https://service.example/transfer";
/// The responding peer's own `nonce`, distinct from the request's.
const RESPONSE_NONCE: &str = "abcd2222";

const WIT_SPEC: &str = "draft-ietf-wimse-workload-creds-02";
const WPT_SPEC: &str = "draft-ietf-wimse-wpt-01";
const HTTPSIG_SPEC: &str = "draft-ietf-wimse-http-signature-06";

/// Names a vector after what it covers and which algorithm it covers it with.
fn vector_id(base: &str, algorithm: Algorithm) -> String {
    format!("{base}-{}", algorithm.as_str().to_ascii_lowercase())
}

fn header(suite: &str, id: impl Into<String>, spec: &str, description: &str) -> Header {
    Header {
        format: FORMAT.to_owned(),
        suite: suite.to_owned(),
        id: id.into(),
        spec: spec.to_owned(),
        description: description.to_owned(),
    }
}

fn wit_claims(sub: &str, pop: &SigningKey) -> WitClaims {
    WitClaims {
        iss: Some(ISSUER.to_owned()),
        sub: WorkloadIdentifier::parse(sub).expect("the fixed subject is a valid identifier"),
        iat: Some(IAT),
        exp: EXP,
        jti: Some("a1b2c3".to_owned()),
        cnf: Confirmation {
            jwk: Jwk::from_verifying_key(&pop.verifying_key()),
        },
    }
}

/// Re-issues `claims` with the `cnf` JWK's `alg` member replaced (or removed).
///
/// The token is genuinely signed, so a verifier that rejects it is rejecting the
/// confirmation algorithm and not a broken signature.
fn reissue_with_cnf_alg(
    claims: &WitClaims,
    alg: Option<&str>,
    kid: Option<&str>,
    issuer_key: &SigningKey,
) -> String {
    let mut altered = claims.clone();
    altered.cnf.jwk.alg = alg.map(ToOwned::to_owned);
    issue_wit(&altered, kid, issuer_key).expect("the altered claims are still serializable")
}

/// A negative case with every override left unset; callers fill in the ones
/// that make it invalid via struct update syntax.
fn wit_neg(id: &str, description: &str, expect: ErrorCode) -> WitNegative {
    WitNegative {
        id: id.to_owned(),
        description: description.to_owned(),
        expect,
        token: None,
        verify_now: None,
        issuer_verifying_key: None,
        expected_iss: None,
    }
}

fn wpt_neg(id: &str, description: &str, expect: ErrorCode) -> WptNegative {
    WptNegative {
        id: id.to_owned(),
        description: description.to_owned(),
        expect,
        proof: None,
        verify_now: None,
        audience: None,
        wit: None,
    }
}

fn httpsig_neg(id: &str, description: &str, expect: ErrorCode) -> HttpSigNegative {
    HttpSigNegative {
        id: id.to_owned(),
        description: description.to_owned(),
        expect,
        request: None,
        body: None,
        signature_input: None,
        signature: None,
        verify_now: None,
        accept_label: None,
        accept_audience: None,
        max_age: None,
        required_components: None,
    }
}

fn response_neg(id: &str, description: &str, expect: ErrorCode) -> ResponseNegative {
    ResponseNegative {
        id: id.to_owned(),
        description: description.to_owned(),
        expect,
        signature_input: None,
        signature: None,
        request: None,
        wit: None,
        expected_req_nonce: None,
    }
}

/// Re-signs a token's payload under a different JOSE header.
///
/// Used to mint negative cases that are *validly signed* but wrong in some other
/// way — a token with `typ: jwt` must be rejected for its type, not because the
/// signature happens not to check out.
fn resign_with_header(token: &str, header_json: &str, key: &SigningKey) -> String {
    let payload = token.split('.').nth(1).expect("token has three parts");
    let signing_input = format!("{}.{payload}", URL_SAFE_NO_PAD.encode(header_json));
    let signature = key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

/// Rewrites one claim value in a token's payload, leaving the signature alone.
///
/// `from` and `to` must be the same length so the payload stays valid JSON: the
/// case has to fail on the signature, not on a parse error.
fn tamper_payload(token: &str, from: &str, to: &str) -> String {
    assert_eq!(
        from.len(),
        to.len(),
        "replacement must not change the length"
    );
    let mut parts = token.split('.');
    let header = parts.next().expect("token has a header");
    let payload = parts.next().expect("token has a payload");
    let signature = parts.next().expect("token has a signature");

    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .expect("payload is base64url");
    let decoded = String::from_utf8(decoded).expect("payload is utf-8");
    assert!(decoded.contains(from), "payload does not contain {from}");

    let tampered = URL_SAFE_NO_PAD.encode(decoded.replace(from, to));
    format!("{header}.{tampered}.{signature}")
}

/// The inputs a WIT verifier must reject, given the positive case's token.
fn wit_negatives(
    claims: &WitClaims,
    token: &str,
    kid: Option<&str>,
    issuer_key: &SigningKey,
    other_issuer: &SigningKey,
) -> Vec<WitNegative> {
    vec![
        WitNegative {
            verify_now: Some(EXP + 1),
            ..wit_neg(
                "expired",
                "verified one second after `exp`",
                ErrorCode::Expired,
            )
        },
        WitNegative {
            verify_now: Some(IAT - 1),
            ..wit_neg(
                "issued-in-future",
                "verified one second before `iat`",
                ErrorCode::IssuedInFuture,
            )
        },
        WitNegative {
            token: Some(resign_with_header(
                token,
                r#"{"typ":"jwt","alg":"EdDSA","kid":"issuer-key-1"}"#,
                issuer_key,
            )),
            ..wit_neg(
                "wrong-typ",
                "validly signed, but the JOSE `typ` is `jwt` and not `wit+jwt`",
                ErrorCode::WrongType,
            )
        },
        WitNegative {
            token: Some(tamper_payload(token, "a1b2c3", "a1b2c4")),
            ..wit_neg(
                "tampered-payload",
                "`jti` was altered after signing; the payload is still valid JSON",
                ErrorCode::InvalidSignature,
            )
        },
        WitNegative {
            issuer_verifying_key: Some(JoseJwk::from_verifying_key(&other_issuer.verifying_key())),
            ..wit_neg(
                "wrong-issuer-key",
                "verified against an issuer key that did not sign the token",
                ErrorCode::InvalidSignature,
            )
        },
        WitNegative {
            expected_iss: Some("https://other-issuer.example".to_owned()),
            ..wit_neg(
                "issuer-mismatch",
                "the verifier expects a different `iss` than the token carries",
                ErrorCode::IssuerMismatch,
            )
        },
        // The `alg` member of the `cnf` JWK pins the algorithm the proof must be
        // produced with. Without it nothing constrains the proof, so a WIT that
        // omits it must not verify.
        WitNegative {
            token: Some(reissue_with_cnf_alg(claims, None, kid, issuer_key)),
            ..wit_neg(
                "cnf-missing-alg",
                "the `cnf` JWK omits the `alg` member the draft requires",
                ErrorCode::MissingConfirmationAlg,
            )
        },
        WitNegative {
            token: Some(reissue_with_cnf_alg(claims, Some("HS256"), kid, issuer_key)),
            ..wit_neg(
                "cnf-symmetric-alg",
                "the `cnf` JWK names a symmetric algorithm, which cannot prove possession",
                ErrorCode::ForbiddenConfirmationAlg,
            )
        },
        WitNegative {
            token: Some(reissue_with_cnf_alg(claims, Some("none"), kid, issuer_key)),
            ..wit_neg(
                "cnf-unsecured-alg",
                "the `cnf` JWK names `none`, which the draft forbids outright",
                ErrorCode::ForbiddenConfirmationAlg,
            )
        },
    ]
}

/// Builds the WIT vector.
///
/// # Panics
///
/// Panics if the fixed inputs in this module stop being valid — which would
/// mean the implementation can no longer issue its own reference credentials.
#[must_use]
pub fn wit_vector(algorithm: Algorithm) -> WitVector {
    let issuer_key = key(algorithm, ISSUER_SEED);
    let pop_key = key(algorithm, WIT_POP_SEED);

    let claims = wit_claims(SUBJECT, &pop_key);
    let kid = Some(KID.to_owned());
    let token = issue_wit(&claims, kid.as_deref(), &issuer_key).expect("issue");
    let negative = wit_negatives(
        &claims,
        &token,
        kid.as_deref(),
        &issuer_key,
        &key(algorithm, OTHER_ISSUER_SEED),
    );

    WitVector {
        header: header(
            "wit",
            vector_id("issue", algorithm),
            WIT_SPEC,
            &format!(
                "WIT issuance with {}, plus the inputs a verifier must reject",
                algorithm.as_str()
            ),
        ),
        alg: algorithm.as_str().to_owned(),
        issuer_signing_key: PrivateJwk::from_signing_key(&issuer_key),
        kid,
        verify_now: IAT,
        claims,
        token,
        negative,
    }
}

/// Builds the WPT vector.
///
/// # Panics
///
/// Panics if the fixed inputs in this module stop being valid — which would
/// mean the implementation can no longer issue its own reference credentials.
#[must_use]
pub fn wpt_vector(algorithm: Algorithm) -> WptVector {
    let issuer_key = key(algorithm, ISSUER_SEED);
    let pop_key = key(algorithm, POP_SEED);

    let wit = issue_wit(&wit_claims(SUBJECT, &pop_key), Some(KID), &issuer_key).expect("issue WIT");
    // A second, equally valid WIT for the same key: the proof is bound to the
    // first one, so presenting it with this one must fail on `wth`.
    let other_wit = issue_wit(
        &wit_claims("spiffe://example.org/workload/other", &pop_key),
        Some(KID),
        &issuer_key,
    )
    .expect("issue the second WIT");

    let audience = "https://workload.example.com/path".to_owned();
    let claims = WptClaims {
        aud: audience.clone(),
        exp: 1_700_000_300,
        jti: "0123456789abcdef".to_owned(),
        wth: wit_thumbprint(&wit),
        ath: None,
    };
    let proof = issue_wpt(&claims, &pop_key).expect("issue WPT");

    let negative = vec![
        WptNegative {
            verify_now: Some(claims.exp + 1),
            ..wpt_neg(
                "expired",
                "verified one second after `exp`",
                ErrorCode::Expired,
            )
        },
        WptNegative {
            audience: Some("https://other.example.com/path".to_owned()),
            ..wpt_neg(
                "audience-mismatch",
                "presented to a service other than the one named in `aud`",
                ErrorCode::AudienceMismatch,
            )
        },
        WptNegative {
            wit: Some(other_wit),
            ..wpt_neg(
                "wit-binding-mismatch",
                "replayed alongside a different, otherwise valid WIT",
                ErrorCode::WitBindingMismatch,
            )
        },
        WptNegative {
            proof: Some(resign_with_header(
                &proof,
                r#"{"typ":"jwt","alg":"EdDSA"}"#,
                &pop_key,
            )),
            ..wpt_neg(
                "wrong-typ",
                "validly signed, but the JOSE `typ` is `jwt` and not `wpt+jwt`",
                ErrorCode::WrongType,
            )
        },
        WptNegative {
            proof: Some(tamper_payload(
                &proof,
                "0123456789abcdef",
                "0123456789abcdee",
            )),
            ..wpt_neg(
                "tampered-payload",
                "`jti` was altered after signing; the payload is still valid JSON",
                ErrorCode::InvalidSignature,
            )
        },
    ];

    WptVector {
        header: header(
            "wpt",
            vector_id("proof", algorithm),
            WPT_SPEC,
            "WPT bound to a WIT via `wth`, plus the inputs a verifier must reject",
        ),
        alg: algorithm.as_str().to_owned(),
        pop_signing_key: PrivateJwk::from_signing_key(&pop_key),
        issuer_verifying_key: JoseJwk::from_verifying_key(&issuer_key.verifying_key()),
        verify_now: IAT,
        audience,
        wit,
        claims,
        proof,
        negative,
    }
}

/// Builds the httpsig vector.
///
/// # Panics
///
/// Panics if the fixed inputs in this module stop being valid — which would
/// mean the implementation can no longer issue its own reference credentials.
#[must_use]
pub fn httpsig_vector(algorithm: Algorithm) -> HttpSigVector {
    let issuer_key = key(algorithm, ISSUER_SEED);
    let pop_key = key(algorithm, POP_SEED);
    let wit = issue_wit(&wit_claims(SUBJECT, &pop_key), Some(KID), &issuer_key).expect("issue WIT");

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
    // Exactly the set Section 3 of the http-signature draft mandates: the two
    // derived components, plus each listed header the message actually carries.
    let components = vec![
        Component::Method,
        Component::RequestTarget,
        Component::header("content-type"),
        Component::header("content-digest"),
        Component::header("workload-identity-token"),
    ];
    // No `keyid` and no `alg`: the profile forbids both.
    let params = SignatureParams {
        created: Some(IAT),
        expires: Some(IAT + 300),
        nonce: Some(NONCE.to_owned()),
        tag: Some(WIMSE_TAG.to_owned()),
        wimse_aud: Some(AUDIENCE.to_owned()),
        wimse_sign_response: Some(true),
        ..SignatureParams::default()
    };
    let signed = sign(&request, &components, &params, "wimse", &pop_key).expect("sign");

    let vector_request = VectorRequest {
        method: request.method.clone(),
        authority: request.authority.clone(),
        path: request.path.clone(),
        query: request.query.clone(),
        headers: request.headers.clone(),
    };
    let negative = httpsig_negatives(&vector_request, &request, &components, &params, &pop_key);
    let accepted = httpsig_accepted(&vector_request);
    let response = httpsig_response(&request, &vector_request, &wit, &issuer_key, algorithm);

    HttpSigVector {
        header: header(
            "httpsig",
            vector_id("sign", algorithm),
            HTTPSIG_SPEC,
            &format!(
                "WIMSE HTTP Message Signature (RFC 9421, {}) carrying a WIT, plus the inputs a verifier must reject",
                algorithm.as_str()
            ),
        ),
        pop_signing_key: PrivateJwk::from_signing_key(&pop_key),
        issuer_verifying_key: JoseJwk::from_verifying_key(&issuer_key.verifying_key()),
        verify_now: 1_700_000_100,
        label: "wimse".to_owned(),
        components: components.iter().map(Component::quoted_id).collect(),
        params: VectorParams {
            created: IAT,
            expires: IAT + 300,
            nonce: NONCE.to_owned(),
            tag: WIMSE_TAG.to_owned(),
            wimse_aud: AUDIENCE.to_owned(),
            wimse_sign_response: Some(true),
            wimse_req_nonce: None,
        },
        request: vector_request,
        body: String::from_utf8(body.to_vec()).expect("the fixed body is utf-8"),
        wit,
        signature_input: signed.signature_input,
        signature: signed.signature,
        negative,
        accepted,
        response: Some(response),
    }
}

/// The authority the boundary cases rewrite the request to.
const REWRITTEN_AUTHORITY: &str = "attacker.example.net";

/// Altered requests that must still verify.
///
/// `@authority` is not in the set Section 3 mandates, so rewriting the host
/// leaves the signature valid. Paired with `authority-rewritten-inside-the-
/// covered-set`, which covers it and therefore rejects the same rewrite.
fn httpsig_accepted(signed_request: &VectorRequest) -> Vec<HttpSigAccepted> {
    vec![HttpSigAccepted {
        id: "authority-rewritten-outside-the-covered-set".to_owned(),
        description:
            "`@authority` is not covered, so a rewritten host leaves the signature valid: a \
             signature protects the components it covers and no others"
                .to_owned(),
        request: Some(VectorRequest {
            authority: REWRITTEN_AUTHORITY.to_owned(),
            ..signed_request.clone()
        }),
    }]
}

/// Builds the signed response to the golden request.
///
/// The request set `wimse-sign-response`, so the peer owes a signed answer. The
/// two bindings that make it an *answer* rather than a free-standing message are
/// the `;req` covered components, taken from the request, and `wimse-req-nonce`,
/// which carries the request's own nonce back.
fn httpsig_response(
    request: &HttpRequest,
    vector_request: &VectorRequest,
    request_wit: &str,
    issuer_key: &SigningKey,
    algorithm: Algorithm,
) -> VectorResponse {
    // Its own key and its own WIT, from the same issuer.
    let pop_key = key(algorithm, RESPONDER_POP_SEED);
    let wit = issue_wit(
        &wit_claims(RESPONDER_SUBJECT, &pop_key),
        Some(KID),
        issuer_key,
    )
    .expect("issue the responder's WIT");

    let body = br#"{"status":"accepted"}"#;
    let response = HttpResponse {
        status: 200,
        headers: vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("Content-Digest".to_owned(), content_digest_sha256(body)),
            ("Workload-Identity-Token".to_owned(), wit.clone()),
        ],
    };
    let exchange = HttpExchange {
        response: &response,
        request,
    };
    let components = response_components(&response.headers);
    let params = SignatureParams {
        created: Some(IAT),
        expires: Some(IAT + 300),
        nonce: Some(RESPONSE_NONCE.to_owned()),
        tag: Some(WIMSE_TAG.to_owned()),
        // No `wimse-aud`: it names the service a request is for, and means
        // nothing coming back.
        wimse_req_nonce: Some(NONCE.to_owned()),
        ..SignatureParams::default()
    };
    let signed =
        sign(&exchange, &components, &params, "wimse", &pop_key).expect("sign the response");

    let rerouted = VectorRequest {
        path: "/admin".to_owned(),
        ..vector_request.clone()
    };

    VectorResponse {
        wit: wit.clone(),
        pop_signing_key: PrivateJwk::from_signing_key(&pop_key),
        status: response.status,
        headers: response.headers.clone(),
        body: String::from_utf8(body.to_vec()).expect("the fixed body is utf-8"),
        components: components.iter().map(Component::quoted_id).collect(),
        params: VectorParams {
            created: IAT,
            expires: IAT + 300,
            nonce: RESPONSE_NONCE.to_owned(),
            tag: WIMSE_TAG.to_owned(),
            wimse_aud: String::new(),
            wimse_sign_response: None,
            wimse_req_nonce: Some(NONCE.to_owned()),
        },
        signature_input: signed.signature_input,
        signature: signed.signature,
        expected_req_nonce: NONCE.to_owned(),
        negative: {
            let mut cases = response_profile_negatives(&exchange, &components, &params, &pop_key);
            cases.extend([
                ResponseNegative {
                    request: Some(rerouted),
                    ..response_neg(
                        "lifted-onto-another-request",
                        "the same signed response, verified against a different request",
                        ErrorCode::InvalidSignature,
                    )
                },
                ResponseNegative {
                    expected_req_nonce: Some("some-other-nonce".to_owned()),
                    ..response_neg(
                        "wrong-req-nonce",
                        "the client's nonce is not the one the response carries back",
                        ErrorCode::RequestNonceMismatch,
                    )
                },
                ResponseNegative {
                    wit: Some(request_wit.to_owned()),
                    ..response_neg(
                        "verified-with-the-requester-key",
                        "the response is verified against the identity in the request's WIT \
                         rather than the one it carries itself",
                        ErrorCode::InvalidSignature,
                    )
                },
            ]);
            cases
        },
    }
}

/// The response-profile rejection cases, one broken rule each.
///
/// The response profile is not the request one: `wimse-aud` is forbidden rather
/// than required, and `wimse-req-nonce` takes its place. Every case is a
/// genuinely signed response, so what turns it away is the rule.
fn response_profile_negatives(
    exchange: &HttpExchange<'_>,
    components: &[Component],
    params: &SignatureParams,
    pop_key: &SigningKey,
) -> Vec<ResponseNegative> {
    let profile_case = |id: &str, description: &str, expect, altered: SignatureParams| {
        let signed = sign(exchange, components, &altered, "wimse", pop_key)
            .expect("the fixed response-profile inputs are signable");
        ResponseNegative {
            signature_input: Some(signed.signature_input),
            signature: Some(signed.signature),
            ..response_neg(id, description, expect)
        }
    };

    vec![
        profile_case(
            "response-carries-wimse-aud",
            "the response signature carries `wimse-aud`, which names the service a *request* is \
             for and is forbidden coming back",
            ErrorCode::ForbiddenParameter,
            SignatureParams {
                wimse_aud: Some(AUDIENCE.to_owned()),
                ..params.clone()
            },
        ),
        profile_case(
            "response-missing-req-nonce",
            "the client asked for a signed response, so the response must carry back its \
             `wimse-req-nonce`",
            ErrorCode::MissingParameter,
            SignatureParams {
                wimse_req_nonce: None,
                ..params.clone()
            },
        ),
        profile_case(
            "response-forbidden-alg-parameter",
            "the response signature carries the `alg` parameter, which the profile forbids",
            ErrorCode::ForbiddenParameter,
            SignatureParams {
                alg: Some("ed25519".to_owned()),
                ..params.clone()
            },
        ),
        profile_case(
            "response-forbidden-keyid-parameter",
            "the response signature carries the `keyid` parameter, which the profile forbids",
            ErrorCode::ForbiddenParameter,
            SignatureParams {
                keyid: Some(KID.to_owned()),
                ..params.clone()
            },
        ),
        profile_case(
            "response-missing-created",
            "the response signature omits the mandatory `created` parameter",
            ErrorCode::MissingParameter,
            SignatureParams {
                created: None,
                ..params.clone()
            },
        ),
        profile_case(
            "response-missing-expires",
            "the response signature omits the mandatory `expires` parameter",
            ErrorCode::MissingParameter,
            SignatureParams {
                expires: None,
                ..params.clone()
            },
        ),
        profile_case(
            "response-missing-nonce",
            "the response signature omits the mandatory `nonce` parameter",
            ErrorCode::MissingParameter,
            SignatureParams {
                nonce: None,
                ..params.clone()
            },
        ),
        profile_case(
            "response-wrong-tag",
            "the response signature's `tag` is not `wimse-workload-to-workload`",
            ErrorCode::WrongTag,
            SignatureParams {
                tag: Some("some-other-protocol".to_owned()),
                ..params.clone()
            },
        ),
    ]
}

/// The rejection cases that break one rule of the WIMSE profile each.
///
/// Every case is a *genuinely signed* message, so what the verifier turns away
/// is the broken rule and not a bad signature.
fn httpsig_profile_negatives(
    request: &HttpRequest,
    components: &[Component],
    params: &SignatureParams,
    pop_key: &SigningKey,
) -> Vec<HttpSigNegative> {
    let profile_case = |id: &str, description: &str, expect, altered: SignatureParams| {
        let signed = sign(request, components, &altered, "wimse", pop_key)
            .expect("the fixed profile-negative inputs are signable");
        HttpSigNegative {
            signature_input: Some(signed.signature_input),
            signature: Some(signed.signature),
            ..httpsig_neg(id, description, expect)
        }
    };

    vec![
        profile_case(
            "forbidden-alg-parameter",
            "the signature carries the `alg` parameter, which the profile forbids",
            ErrorCode::ForbiddenParameter,
            SignatureParams {
                alg: Some("ed25519".to_owned()),
                ..params.clone()
            },
        ),
        profile_case(
            "forbidden-keyid-parameter",
            "the signature carries the `keyid` parameter, which the profile forbids",
            ErrorCode::ForbiddenParameter,
            SignatureParams {
                keyid: Some(KID.to_owned()),
                ..params.clone()
            },
        ),
        profile_case(
            "missing-nonce",
            "the signature omits the mandatory `nonce` parameter",
            ErrorCode::MissingParameter,
            SignatureParams {
                nonce: None,
                ..params.clone()
            },
        ),
        profile_case(
            "missing-created",
            "the signature omits the mandatory `created` parameter",
            ErrorCode::MissingParameter,
            SignatureParams {
                created: None,
                ..params.clone()
            },
        ),
        profile_case(
            "missing-expires",
            "the signature omits the mandatory `expires` parameter",
            ErrorCode::MissingParameter,
            SignatureParams {
                expires: None,
                ..params.clone()
            },
        ),
        profile_case(
            "missing-wimse-aud",
            "the request signature omits the mandatory `wimse-aud` parameter",
            ErrorCode::MissingParameter,
            SignatureParams {
                wimse_aud: None,
                ..params.clone()
            },
        ),
        profile_case(
            "wrong-tag",
            "the signature's `tag` is not `wimse-workload-to-workload`",
            ErrorCode::WrongTag,
            SignatureParams {
                tag: Some("some-other-protocol".to_owned()),
                ..params.clone()
            },
        ),
    ]
}

/// The inputs an httpsig verifier must reject, given the signed request.
///
/// Note that `accept_label`, `max_age` and `required_components` describe how
/// strict the *receiver* is rather than anything about the message: the case
/// asserts that a receiver configured that way turns the request away.
fn httpsig_negatives(
    signed_request: &VectorRequest,
    request: &HttpRequest,
    components: &[Component],
    params: &SignatureParams,
    pop_key: &SigningKey,
) -> Vec<HttpSigNegative> {
    let rerouted = VectorRequest {
        path: "/admin".to_owned(),
        ..signed_request.clone()
    };
    let rehosted = VectorRequest {
        authority: REWRITTEN_AUTHORITY.to_owned(),
        ..signed_request.clone()
    };
    // The same rewrite the `accepted` case tolerates, signed over a component
    // set that does include `@authority`.
    let covering_authority: Vec<Component> = components
        .iter()
        .cloned()
        .chain([Component::Authority])
        .collect();
    let signed_over_authority = sign(request, &covering_authority, params, "wimse", pop_key)
        .expect("the fixed request is signable over `@authority`");

    let mut cases = httpsig_profile_negatives(request, components, params, pop_key);
    cases.extend([
        HttpSigNegative {
            accept_audience: Some("https://other.example/inbox".to_owned()),
            ..httpsig_neg(
                "audience-mismatch",
                "the signature was minted for a different service than the one verifying it",
                ErrorCode::AudienceMismatch,
            )
        },
        HttpSigNegative {
            body: Some(r#"{"amount":999}"#.to_owned()),
            ..httpsig_neg(
                "tampered-body",
                "the body no longer hashes to the signed `Content-Digest`",
                ErrorCode::ContentDigestMismatch,
            )
        },
        HttpSigNegative {
            request: Some(rerouted),
            ..httpsig_neg(
                "rerouted-path",
                "an intermediary changed `@path` after the signature was made",
                ErrorCode::InvalidSignature,
            )
        },
        HttpSigNegative {
            request: Some(rehosted),
            signature_input: Some(signed_over_authority.signature_input),
            signature: Some(signed_over_authority.signature),
            ..httpsig_neg(
                "authority-rewritten-inside-the-covered-set",
                "this signature does cover `@authority`, so the same rewritten host that the \
                 accepted case tolerates now breaks the signature",
                ErrorCode::InvalidSignature,
            )
        },
        HttpSigNegative {
            verify_now: Some(IAT - 1),
            ..httpsig_neg(
                "created-in-future",
                "the signature's `created` is ahead of the verifier's clock",
                ErrorCode::CreatedInFuture,
            )
        },
        HttpSigNegative {
            // Inside the signature's own `expires` window, so what rejects this
            // is the verifier's stricter `max_age` and not plain expiry.
            verify_now: Some(IAT + 120),
            max_age: Some(30),
            ..httpsig_neg(
                "too-old",
                "the signature is still unexpired but older than the verifier's `max_age`",
                ErrorCode::TooOld,
            )
        },
        HttpSigNegative {
            accept_label: Some("other".to_owned()),
            ..httpsig_neg(
                "label-mismatch",
                "the verifier only accepts a label the request does not carry",
                ErrorCode::LabelMismatch,
            )
        },
        HttpSigNegative {
            required_components: Some(vec![r#""authorization""#.to_owned()]),
            ..httpsig_neg(
                "missing-required-component",
                "the verifier requires a component the signature does not cover",
                ErrorCode::MissingRequiredComponent,
            )
        },
    ]);
    cases
}

/// Builds the manifest that indexes every vector.
#[must_use]
pub fn manifest() -> Manifest {
    Manifest {
        format: FORMAT.to_owned(),
        vectors: vec![
            ManifestEntry {
                suite: "identifier".to_owned(),
                path: "identifier/parse-basic.json".to_owned(),
                spec: IDENTIFIER_SPEC.to_owned(),
            },
            ManifestEntry {
                suite: "wit".to_owned(),
                path: "wit/issue-eddsa.json".to_owned(),
                spec: WIT_SPEC.to_owned(),
            },
            ManifestEntry {
                suite: "wit".to_owned(),
                path: "wit/issue-es256.json".to_owned(),
                spec: WIT_SPEC.to_owned(),
            },
            ManifestEntry {
                suite: "wpt".to_owned(),
                path: "wpt/proof-eddsa.json".to_owned(),
                spec: WPT_SPEC.to_owned(),
            },
            ManifestEntry {
                suite: "wpt".to_owned(),
                path: "wpt/proof-es256.json".to_owned(),
                spec: WPT_SPEC.to_owned(),
            },
            ManifestEntry {
                suite: "httpsig".to_owned(),
                path: "httpsig/sign-eddsa.json".to_owned(),
                spec: HTTPSIG_SPEC.to_owned(),
            },
            ManifestEntry {
                suite: "httpsig".to_owned(),
                path: "httpsig/sign-es256.json".to_owned(),
                spec: HTTPSIG_SPEC.to_owned(),
            },
            ManifestEntry {
                suite: "mtls".to_owned(),
                path: "mtls/wic-basic.json".to_owned(),
                spec: MTLS_SPEC.to_owned(),
            },
        ],
    }
}

const IDENTIFIER_SPEC: &str = "draft-ietf-wimse-identifier-03";

fn accept(id: &str, description: &str, identifier: &str) -> IdentifierAccept {
    let parsed =
        WorkloadIdentifier::parse(identifier).expect("the fixed accept cases are all valid");
    IdentifierAccept {
        id: id.to_owned(),
        description: description.to_owned(),
        identifier: identifier.to_owned(),
        scheme: parsed.scheme().as_str().to_owned(),
        trust_domain: parsed.trust_domain().to_owned(),
        path: parsed.path().to_owned(),
        origin: parsed.origin().to_owned(),
    }
}

fn reject(id: &str, description: &str, identifier: &str, expect: ErrorCode) -> IdentifierReject {
    IdentifierReject {
        id: id.to_owned(),
        description: description.to_owned(),
        identifier: identifier.to_owned(),
        expect,
    }
}

/// Builds the workload identifier vector.
///
/// # Panics
///
/// Panics if an identifier listed under `accept` stops parsing, which would mean
/// the implementation no longer accepts its own reference identifiers.
#[must_use]
pub fn identifier_vector() -> IdentifierVector {
    IdentifierVector {
        header: header(
            "identifier",
            "parse-basic",
            IDENTIFIER_SPEC,
            "Workload identifier syntax for the spiffe and wimse schemes, plus the inputs a parser must reject",
        ),
        accept: identifier_accepts(),
        reject: identifier_rejects(),
    }
}

/// The identifiers that must parse, with the decomposition each must yield.
fn identifier_accepts() -> Vec<IdentifierAccept> {
    vec![
        accept(
            "spiffe-basic",
            "the SPIFFE scheme the architecture draft cites as a conforming identifier",
            "spiffe://example.org/workload/api",
        ),
        accept(
            "wimse-basic",
            "the wimse scheme defined in Section 4.4",
            "wimse://trust.example.com/service/payment",
        ),
        accept(
            "trust-domain-only",
            "the path is optional; an identifier may be a bare trust domain",
            "spiffe://prod.trust.domain",
        ),
        accept(
            "wimse-pchar-path",
            "Section 4.4 leaves the wimse path to the generic RFC 3986 pchar set",
            "wimse://example.org/a~b!c$d&e'f(g)h*i+j,k;l=m:n@o",
        ),
        accept(
            "wimse-encoded-reserved",
            "a reserved character stays encodable: %2F is a `/` that is data, not a delimiter",
            "wimse://example.org/a%2Fb",
        ),
        accept(
            "deep-path",
            "the path may encode structured information within the trust domain",
            "spiffe://prod.trust.domain/ns/prod-01/sa/foo-service",
        ),
    ]
}

/// The identifiers a parser must refuse, and the reason for each.
fn identifier_rejects() -> Vec<IdentifierReject> {
    vec![
        reject(
            "unsupported-scheme",
            "an https URI is not a workload identifier",
            "https://example.org/x",
            ErrorCode::UnsupportedScheme,
        ),
        // Section 4.1: no query, fragment, user information or port.
        reject(
            "has-query",
            "Section 4.1 forbids a query component",
            "wimse://example.org/a?b=c",
            ErrorCode::HasQuery,
        ),
        reject(
            "has-fragment",
            "Section 4.1 forbids a fragment component",
            "wimse://example.org/a#frag",
            ErrorCode::HasFragment,
        ),
        reject(
            "has-user-info",
            "Section 4.1 forbids user information",
            "wimse://user@example.org/a",
            ErrorCode::HasUserInfo,
        ),
        reject(
            "has-port",
            "Section 4.1 forbids a port component",
            "wimse://example.org:8443/a",
            ErrorCode::HasPort,
        ),
        reject(
            "empty-trust-domain",
            "Section 4.1 requires a non-empty authority",
            "spiffe:///path",
            ErrorCode::EmptyTrustDomain,
        ),
        // The rest are spellings that RFC 3986 normalization would rewrite.
        // Accepting any of them would break the Section 4.3 rule that
        // consumers compare complete URIs.
        reject(
            "uppercase-trust-domain",
            "the authority is case-insensitive, so mixed case is a second spelling",
            "spiffe://Example.org/x",
            ErrorCode::InvalidTrustDomainChar,
        ),
        reject(
            "trailing-slash",
            "a trailing slash is an empty final segment",
            "spiffe://example.org/x/",
            ErrorCode::EmptyPathSegment,
        ),
        reject(
            "empty-path-segment",
            "`//` in a path is an empty segment normalization would collapse",
            "spiffe://example.org/x//y",
            ErrorCode::EmptyPathSegment,
        ),
        reject(
            "dot-segment",
            "`..` is removed by RFC 3986 Section 6 dot-segment removal",
            "spiffe://example.org/a/../b",
            ErrorCode::DotSegment,
        ),
        reject(
            "encoded-dot-segment",
            "%2E%2E decodes to `..`, so it must not slip past the dot-segment check",
            "wimse://example.org/%2E%2E/api",
            ErrorCode::NonNormalizedPercentEncoding,
        ),
        reject(
            "encoded-unreserved",
            "%61 decodes to `a`, making this a second spelling of /api",
            "wimse://example.org/%61pi",
            ErrorCode::NonNormalizedPercentEncoding,
        ),
        reject(
            "lowercase-escape-hex",
            "RFC 3986 Section 6.2.2.1 uppercases the hex digits of an escape",
            "wimse://example.org/a%2fb",
            ErrorCode::NonNormalizedPercentEncoding,
        ),
        reject(
            "malformed-escape",
            "a percent-escape must be `%` followed by two hex digits",
            "wimse://example.org/a%zz",
            ErrorCode::BadPercentEncoding,
        ),
        reject(
            "invalid-path-char",
            "a space is outside the pchar set",
            "wimse://example.org/a b",
            ErrorCode::InvalidPathChar,
        ),
        reject(
            "spiffe-path-charset-is-narrower",
            "`~` is a legal pchar but outside the SPIFFE ID path charset",
            "spiffe://example.org/a~b",
            ErrorCode::InvalidPathChar,
        ),
    ]
}

const MTLS_SPEC: &str = "draft-ietf-wimse-mutual-tls-02";
/// The workload CA's seed. Fixed so the CA certificate is reproducible.
const CA_SEED: [u8; 32] = [3u8; 32];
/// A second CA, used only as the wrong trust anchor in a negative case.
const OTHER_CA_SEED: [u8; 32] = [4u8; 32];
/// The CA certificate outlives the WICs it issues.
const CA_NBF: u64 = 1_600_000_000;
const CA_NAF: u64 = 1_900_000_000;
/// The WIC's own window.
const WIC_NBF: u64 = IAT;
const WIC_NAF: u64 = IAT + 86_400;

fn mtls_neg(id: &str, description: &str, expect: ErrorCode) -> MtlsNegative {
    MtlsNegative {
        id: id.to_owned(),
        description: description.to_owned(),
        expect,
        wic_der_b64u: None,
        ca_certificate_der_b64u: None,
        verify_now: None,
    }
}

/// Builds the WIC vector.
///
/// # Panics
///
/// Panics if the fixed inputs stop being valid, which would mean the
/// implementation can no longer issue its own reference certificates.
#[must_use]
pub fn mtls_vector() -> MtlsVector {
    let ca_key = SigningKey::from_ed25519_seed(&CA_SEED);
    let workload_key = SigningKey::from_ed25519_seed(&POP_SEED);
    let identifier =
        WorkloadIdentifier::parse(SUBJECT).expect("the fixed subject is a valid identifier");

    let ca = WorkloadCa::from_ed25519(&ca_key, CA_NBF, CA_NAF).expect("load the fixed CA");
    let wic = ca
        .issue(&identifier, &workload_key.verifying_key(), WIC_NBF, WIC_NAF)
        .expect("issue the fixed WIC");

    let other_ca = WorkloadCa::from_ed25519(
        &SigningKey::from_ed25519_seed(&OTHER_CA_SEED),
        CA_NBF,
        CA_NAF,
    )
    .expect("load the second CA");

    let negative = vec![
        MtlsNegative {
            ca_certificate_der_b64u: Some(URL_SAFE_NO_PAD.encode(other_ca.certificate_der())),
            ..mtls_neg(
                "wrong-ca",
                "verified against a CA that did not sign the certificate",
                ErrorCode::InvalidSignature,
            )
        },
        MtlsNegative {
            verify_now: Some(WIC_NAF + 1),
            ..mtls_neg(
                "expired",
                "verified one second after the certificate's notAfter",
                ErrorCode::CertificateNotValid,
            )
        },
        MtlsNegative {
            verify_now: Some(WIC_NBF - 1),
            ..mtls_neg(
                "not-yet-valid",
                "verified one second before the certificate's notBefore",
                ErrorCode::CertificateNotValid,
            )
        },
        // The CA certificate is a perfectly valid, correctly signed certificate
        // that simply carries no URI SAN. An implementation that only checks the
        // signature will accept it and then have no identifier to authorize.
        MtlsNegative {
            wic_der_b64u: Some(URL_SAFE_NO_PAD.encode(ca.certificate_der())),
            ..mtls_neg(
                "no-uri-san",
                "a validly signed certificate that carries no workload identifier",
                ErrorCode::MissingIdentifier,
            )
        },
        MtlsNegative {
            wic_der_b64u: Some(URL_SAFE_NO_PAD.encode(b"not a certificate")),
            ..mtls_neg(
                "not-a-certificate",
                "the presented bytes are not DER X.509 at all",
                ErrorCode::CertificateParseError,
            )
        },
    ];

    MtlsVector {
        header: header(
            "mtls",
            "wic-basic",
            MTLS_SPEC,
            "Workload Identity Certificate issuance over a workload-supplied public key, plus the inputs a verifier must reject",
        ),
        ca_signing_key: PrivateJwk::from_signing_key(&ca_key),
        ca_not_before: CA_NBF,
        ca_not_after: CA_NAF,
        workload_signing_key: PrivateJwk::from_signing_key(&workload_key),
        identifier: SUBJECT.to_owned(),
        not_before: WIC_NBF,
        not_after: WIC_NAF,
        ca_certificate_der_b64u: URL_SAFE_NO_PAD.encode(ca.certificate_der()),
        wic_der_b64u: URL_SAFE_NO_PAD.encode(&wic),
        verify_now: WIC_NBF + 100,
        negative,
    }
}

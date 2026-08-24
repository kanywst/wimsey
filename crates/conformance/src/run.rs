//! Running the conformance vectors against this implementation.
//!
//! Each vector produces a list of named checks. Positive checks assert that the
//! recorded bytes are reproducible and that verification accepts them; negative
//! checks assert that verification **fails with the recorded reason**, which is
//! the half that a `git diff` of regenerated output can never cover.

use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Serialize;
use wimsey_httpsig::{
    sign, verify as verify_httpsig, verify_content_digest, Component, HttpExchange, HttpRequest,
    HttpResponse, SignatureParams, VerifyConfig, VerifyingKey,
};
use wimsey_identifier::WorkloadIdentifier;
use wimsey_jose::{Algorithm, SigningKey};
use wimsey_mtls::{verify as verify_mtls, WorkloadCa};
use wimsey_wit::{issue as issue_wit, verify as verify_wit, Validation as WitValidation};
use wimsey_wpt::{issue as issue_wpt, verify as verify_wpt, wit_thumbprint, Validation};

use crate::vectors::{
    ErrorCode, HttpSigVector, IdentifierVector, Manifest, MtlsVector, VectorRequest,
    VectorResponse, WitVector, WptVector, FORMAT,
};

/// Something that stopped the runner before it could reach a verdict.
#[derive(Debug)]
pub enum Error {
    /// A vector file or the manifest could not be read.
    Io(PathBuf, std::io::Error),
    /// A vector file or the manifest was not valid JSON in the expected shape.
    Parse(PathBuf, serde_json::Error),
    /// A file declared a `format` this runner does not understand.
    UnknownFormat(PathBuf, String),
    /// The manifest named a suite the runner has no checks for.
    UnknownSuite(String),
    /// A vector file exists on disk but the manifest does not list it.
    Unlisted(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(path, e) => write!(f, "reading {}: {e}", path.display()),
            Self::Parse(path, e) => write!(f, "parsing {}: {e}", path.display()),
            Self::UnknownFormat(path, found) => write!(
                f,
                "{}: unknown format `{found}`, this runner speaks `{FORMAT}`",
                path.display()
            ),
            Self::UnknownSuite(suite) => write!(f, "manifest names unknown suite `{suite}`"),
            Self::Unlisted(path) => {
                write!(f, "{path} is present but the manifest does not list it")
            }
        }
    }
}

impl std::error::Error for Error {}

/// One assertion, and whether this implementation satisfied it.
#[derive(Debug, Serialize)]
pub struct Check {
    /// The vector the check came from, as `suite/id`.
    pub vector: String,
    /// What was asserted.
    pub name: String,
    /// Whether the assertion held.
    pub passed: bool,
    /// What went wrong, when it did not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The outcome of a whole run.
#[derive(Debug, Default, Serialize)]
pub struct Report {
    /// Every check, in run order.
    pub checks: Vec<Check>,
}

impl Report {
    fn pass(&mut self, vector: &str, name: &str) {
        self.checks.push(Check {
            vector: vector.to_owned(),
            name: name.to_owned(),
            passed: true,
            detail: None,
        });
    }

    fn fail(&mut self, vector: &str, name: &str, detail: String) {
        self.checks.push(Check {
            vector: vector.to_owned(),
            name: name.to_owned(),
            passed: false,
            detail: Some(detail),
        });
    }

    fn record(&mut self, vector: &str, name: &str, outcome: Result<(), String>) {
        match outcome {
            Ok(()) => self.pass(vector, name),
            Err(detail) => self.fail(vector, name, detail),
        }
    }

    /// The number of checks that held.
    #[must_use]
    pub fn passed(&self) -> usize {
        self.checks.iter().filter(|c| c.passed).count()
    }

    /// The number of checks that did not hold.
    #[must_use]
    pub fn failed(&self) -> usize {
        self.checks.len() - self.passed()
    }

    /// Whether every check held.
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.failed() == 0
    }
}

fn signing_key(seed_b64u: &str) -> Result<SigningKey, String> {
    let seed = URL_SAFE_NO_PAD
        .decode(seed_b64u)
        .map_err(|e| format!("seed is not base64url: {e}"))?;
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| "seed is not 32 bytes".to_owned())?;
    Ok(SigningKey::from_ed25519_seed(&seed))
}

/// Decodes a recorded public key.
///
/// The v1 vector format records raw key bytes rather than a JWK, which only
/// works because every v1 vector is Ed25519. Carrying the algorithm with the key
/// is what a JWK is for, and is what an ES256 vector will need.
fn verifying_key(b64u: &str) -> Result<VerifyingKey, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(b64u)
        .map_err(|e| format!("key is not base64url: {e}"))?;
    VerifyingKey::from_raw_bytes(Algorithm::EdDsa, &bytes)
        .map_err(|e| format!("key is not a valid Ed25519 point: {e}"))
}

fn expect_reject(expected: ErrorCode, actual: Result<(), ErrorCode>) -> Result<(), String> {
    match actual {
        Ok(()) => Err(format!("accepted; it must be rejected as {expected:?}")),
        Err(found) if found == expected => Ok(()),
        Err(found) => Err(format!("rejected as {found:?}, expected {expected:?}")),
    }
}

fn components(quoted: &[String]) -> Result<Vec<Component>, String> {
    quoted
        .iter()
        .map(|id| Component::from_quoted_id(id).map_err(|e| format!("component `{id}`: {e}")))
        .collect()
}

fn http_request(request: &VectorRequest) -> HttpRequest {
    HttpRequest {
        method: request.method.clone(),
        authority: request.authority.clone(),
        path: request.path.clone(),
        query: request.query.clone(),
        headers: request.headers.clone(),
    }
}

fn content_digest(request: &VectorRequest) -> Option<&str> {
    request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-digest"))
        .map(|(_, value)| value.as_str())
}

/// Runs the workload identifier vector.
///
/// There is nothing to re-sign here, so the two checks are the whole contract:
/// an `accept` case must parse *and decompose* exactly as recorded, and a
/// `reject` case must be refused for the recorded reason.
pub fn run_identifier(vector: &IdentifierVector, report: &mut Report) {
    let name = format!("{}/{}", vector.header.suite, vector.header.id);

    for case in &vector.accept {
        let outcome = match WorkloadIdentifier::parse(&case.identifier) {
            Err(e) => Err(format!("must parse, but was rejected: {e}")),
            Ok(parsed) => {
                let got = (
                    parsed.scheme().as_str(),
                    parsed.trust_domain(),
                    parsed.path(),
                    parsed.origin(),
                );
                let want = (
                    case.scheme.as_str(),
                    case.trust_domain.as_str(),
                    case.path.as_str(),
                    case.origin.as_str(),
                );
                if got == want {
                    Ok(())
                } else {
                    Err(format!("decomposed as {got:?}, expected {want:?}"))
                }
            }
        };
        report.record(&name, &format!("accept/{}", case.id), outcome);
    }

    for case in &vector.reject {
        let actual = WorkloadIdentifier::parse(&case.identifier)
            .map(|_| ())
            .map_err(|e| ErrorCode::from(&e));
        report.record(
            &name,
            &format!("reject/{}", case.id),
            expect_reject(case.expect, actual),
        );
    }
}

/// Runs the WIC vector: reproducibility, acceptance, and every rejection.
///
/// The reproduce check is the interesting one. The vector records seeds rather
/// than a finished certificate, so an implementation has to re-issue the WIC and
/// match it byte for byte — which is only a fair demand because issuance takes
/// the workload's public key and has no per-issuance secret to differ on.
pub fn run_mtls(vector: &MtlsVector, report: &mut Report) {
    let name = format!("{}/{}", vector.header.suite, vector.header.id);

    let inputs = seed(&vector.ca_signing_key_seed_b64u).and_then(|ca_seed| {
        let workload = seed(&vector.workload_signing_key_seed_b64u)?;
        let identifier = WorkloadIdentifier::parse(&vector.identifier)
            .map_err(|e| format!("the recorded identifier does not parse: {e}"))?;
        Ok((
            SigningKey::from_ed25519_seed(&ca_seed),
            SigningKey::from_ed25519_seed(&workload),
            identifier,
        ))
    });
    let (ca_key, workload_key, identifier) = match inputs {
        Ok(inputs) => inputs,
        Err(detail) => {
            report.fail(&name, "load the recorded inputs", detail);
            return;
        }
    };

    let ca = match WorkloadCa::from_ed25519(&ca_key, vector.ca_not_before, vector.ca_not_after) {
        Ok(ca) => ca,
        Err(e) => {
            report.fail(&name, "rebuild the CA", format!("{e}"));
            return;
        }
    };

    report.record(
        &name,
        "reproduce",
        ca.issue(
            &identifier,
            &workload_key.verifying_key(),
            vector.not_before,
            vector.not_after,
        )
        .map_err(|e| format!("re-issuing failed: {e}"))
        .and_then(|reissued| {
            if URL_SAFE_NO_PAD.encode(&reissued) == vector.wic_der_b64u {
                Ok(())
            } else {
                Err("the re-issued certificate differs from the recorded one".to_owned())
            }
        }),
    );

    report.record(
        &name,
        "ca-certificate",
        if URL_SAFE_NO_PAD.encode(ca.certificate_der()) == vector.ca_certificate_der_b64u {
            Ok(())
        } else {
            Err("the rebuilt CA certificate differs from the recorded one".to_owned())
        },
    );

    let recorded = der(&vector.wic_der_b64u).and_then(|wic| {
        let ca_der = der(&vector.ca_certificate_der_b64u)?;
        let got = verify_mtls(&wic, &ca_der, vector.verify_now).map_err(|e| format!("{e}"))?;
        if got == identifier {
            Ok(())
        } else {
            Err(format!("verified as {got}, expected {identifier}"))
        }
    });
    report.record(&name, "verify", recorded);

    for case in &vector.negative {
        let outcome =
            der(case.wic_der_b64u.as_ref().unwrap_or(&vector.wic_der_b64u)).and_then(|wic| {
                let ca_der = der(case
                    .ca_certificate_der_b64u
                    .as_ref()
                    .unwrap_or(&vector.ca_certificate_der_b64u))?;
                let actual =
                    verify_mtls(&wic, &ca_der, case.verify_now.unwrap_or(vector.verify_now))
                        .map(|_| ())
                        .map_err(|e| ErrorCode::from(&e));
                expect_reject(case.expect, actual)
            });
        report.record(&name, &format!("reject/{}", case.id), outcome);
    }
}

/// Decodes a recorded base64url seed into 32 bytes.
fn seed(b64u: &str) -> Result<[u8; 32], String> {
    URL_SAFE_NO_PAD
        .decode(b64u)
        .map_err(|e| format!("seed is not base64url: {e}"))?
        .try_into()
        .map_err(|_| "seed is not 32 bytes".to_owned())
}

/// Decodes a recorded base64url DER blob.
fn der(b64u: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(b64u)
        .map_err(|e| format!("DER is not base64url: {e}"))
}

/// Runs the WIT vector: reproducibility, acceptance, and every rejection.
pub fn run_wit(vector: &WitVector, report: &mut Report) {
    let name = format!("{}/{}", vector.header.suite, vector.header.id);
    let key = match signing_key(&vector.issuer_signing_key_seed_b64u) {
        Ok(key) => key,
        Err(detail) => {
            report.fail(&name, "load issuer key", detail);
            return;
        }
    };

    report.record(
        &name,
        "reproduce",
        issue_wit(&vector.claims, vector.kid.as_deref(), &key)
            .map_err(|e| format!("re-issuing failed: {e}"))
            .and_then(|reissued| {
                if reissued == vector.token {
                    Ok(())
                } else {
                    Err("re-issued token differs from the recorded one".to_owned())
                }
            }),
    );

    report.record(
        &name,
        "verify",
        verify_wit(
            &vector.token,
            &key.verifying_key(),
            &WitValidation::at(vector.verify_now),
        )
        .map_err(|e| format!("verification failed: {e}"))
        .and_then(|verified| {
            if verified.claims == vector.claims {
                Ok(())
            } else {
                Err("verified claims differ from the recorded ones".to_owned())
            }
        }),
    );

    for case in &vector.negative {
        let token = case.token.as_deref().unwrap_or(&vector.token);
        let now = case.verify_now.unwrap_or(vector.verify_now);
        let key = match case.issuer_verifying_key_b64u.as_deref() {
            Some(b64u) => verifying_key(b64u),
            None => Ok(key.verifying_key()),
        };
        let outcome = key.and_then(|key| {
            let mut validation = WitValidation::at(now);
            validation.expected_issuer.clone_from(&case.expected_iss);
            let actual = verify_wit(token, &key, &validation)
                .map(|_| ())
                .map_err(|e| ErrorCode::from(&e));
            expect_reject(case.expect, actual)
        });
        report.record(&name, &format!("reject/{}", case.id), outcome);
    }
}

/// Runs the WPT vector: reproducibility, the full WIT-to-WPT flow, and every
/// rejection.
pub fn run_wpt(vector: &WptVector, report: &mut Report) {
    let name = format!("{}/{}", vector.header.suite, vector.header.id);
    let pop = match signing_key(&vector.pop_signing_key_seed_b64u) {
        Ok(key) => key,
        Err(detail) => {
            report.fail(&name, "load proof-of-possession key", detail);
            return;
        }
    };

    report.record(
        &name,
        "reproduce",
        issue_wpt(&vector.claims, &pop)
            .map_err(|e| format!("re-issuing failed: {e}"))
            .and_then(|reissued| {
                if reissued == vector.proof {
                    Ok(())
                } else {
                    Err("re-issued proof differs from the recorded one".to_owned())
                }
            }),
    );

    report.record(
        &name,
        "wit-thumbprint",
        if wit_thumbprint(&vector.wit) == vector.claims.wth {
            Ok(())
        } else {
            Err("`wth` does not match the hash of the recorded WIT".to_owned())
        },
    );

    // The full flow: recover the proof-of-possession key from the WIT rather
    // than from the vector, so a break in the WIT-to-WPT chain shows up here.
    let flow = verifying_key(&vector.issuer_verifying_key_b64u).and_then(|issuer| {
        let verified_wit = verify_wit(&vector.wit, &issuer, &WitValidation::at(vector.verify_now))
            .map_err(|e| format!("the bound WIT did not verify: {e}"))?;
        let validation = Validation::new(vector.verify_now, &vector.audience, &vector.wit);
        let verified = verify_wpt(&vector.proof, &verified_wit.pop_key, &validation)
            .map_err(|e| format!("the proof did not verify: {e}"))?;
        if verified.claims == vector.claims {
            Ok(())
        } else {
            Err("verified claims differ from the recorded ones".to_owned())
        }
    });
    report.record(&name, "verify", flow);

    for case in &vector.negative {
        let proof = case.proof.as_deref().unwrap_or(&vector.proof);
        let now = case.verify_now.unwrap_or(vector.verify_now);
        let audience = case.audience.as_deref().unwrap_or(&vector.audience);
        let wit = case.wit.as_deref().unwrap_or(&vector.wit);

        let validation = Validation::new(now, audience, wit);
        let actual = verify_wpt(proof, &pop.verifying_key(), &validation)
            .map(|_| ())
            .map_err(|e| ErrorCode::from(&e));
        report.record(
            &name,
            &format!("reject/{}", case.id),
            expect_reject(case.expect, actual),
        );
    }
}

/// Runs the httpsig vector: reproducibility, the full flow, and every rejection.
pub fn run_httpsig(vector: &HttpSigVector, report: &mut Report) {
    let name = format!("{}/{}", vector.header.suite, vector.header.id);
    let pop = match signing_key(&vector.pop_signing_key_seed_b64u) {
        Ok(key) => key,
        Err(detail) => {
            report.fail(&name, "load proof-of-possession key", detail);
            return;
        }
    };
    let covered = match components(&vector.components) {
        Ok(covered) => covered,
        Err(detail) => {
            report.fail(&name, "parse covered components", detail);
            return;
        }
    };

    let params = SignatureParams {
        created: Some(vector.params.created),
        expires: Some(vector.params.expires),
        nonce: Some(vector.params.nonce.clone()),
        tag: Some(vector.params.tag.clone()),
        wimse_aud: Some(vector.params.wimse_aud.clone()),
        wimse_sign_response: vector.params.wimse_sign_response,
        wimse_req_nonce: vector.params.wimse_req_nonce.clone(),
        ..SignatureParams::default()
    };
    let request = http_request(&vector.request);

    report.record(
        &name,
        "reproduce",
        sign(&request, &covered, &params, &vector.label, &pop)
            .map_err(|e| format!("re-signing failed: {e}"))
            .and_then(|signed| {
                if signed.signature_input != vector.signature_input {
                    Err("re-signed `Signature-Input` differs from the recorded one".to_owned())
                } else if signed.signature != vector.signature {
                    Err("re-signed `Signature` differs from the recorded one".to_owned())
                } else {
                    Ok(())
                }
            }),
    );

    let flow = verifying_key(&vector.issuer_verifying_key_b64u).and_then(|issuer| {
        let verified_wit = verify_wit(&vector.wit, &issuer, &WitValidation::at(vector.verify_now))
            .map_err(|e| format!("the carried WIT did not verify: {e}"))?;
        let config = VerifyConfig {
            now: Some(vector.verify_now),
            required_components: covered.clone(),
            wimse_profile: true,
            expected_audience: Some(vector.params.wimse_aud.clone()),
            ..VerifyConfig::default()
        };
        let verified = verify_httpsig(
            &request,
            &vector.signature_input,
            &vector.signature,
            &verified_wit.pop_key,
            &config,
        )
        .map_err(|e| format!("the signature did not verify: {e}"))?;
        if verified.label == vector.label {
            Ok(())
        } else {
            Err("verified label differs from the recorded one".to_owned())
        }
    });
    report.record(&name, "verify", flow);

    report.record(
        &name,
        "content-digest",
        match content_digest(&vector.request) {
            None => Err("the request carries no `Content-Digest` header".to_owned()),
            Some(digest) if verify_content_digest(digest, vector.body.as_bytes()) => Ok(()),
            Some(_) => Err("`Content-Digest` does not match the recorded body".to_owned()),
        },
    );

    run_httpsig_negatives(vector, &covered, &name, report);
    if let Some(response) = &vector.response {
        run_httpsig_response(vector, response, &name, report);
    }
}

/// Runs the signed-response half of an httpsig vector.
///
/// A response is only an *answer* if it is tied to the request it answers, so
/// the two things worth checking are exactly those bindings: the `;req`
/// components, which resolve from the request, and `wimse-req-nonce`, which
/// carries the request's own nonce back.
fn run_httpsig_response(
    vector: &HttpSigVector,
    response: &VectorResponse,
    name: &str,
    report: &mut Report,
) {
    let pop_key = match verifying_key(&vector.issuer_verifying_key_b64u).and_then(|issuer| {
        verify_wit(&vector.wit, &issuer, &WitValidation::at(vector.verify_now))
            .map(|verified| verified.pop_key)
            .map_err(|e| format!("the carried WIT did not verify: {e}"))
    }) {
        Ok(key) => key,
        Err(detail) => {
            report.fail(name, "response/recover the key from the WIT", detail);
            return;
        }
    };
    let covered = match components(&response.components) {
        Ok(covered) => covered,
        Err(detail) => {
            report.fail(name, "response/parse covered components", detail);
            return;
        }
    };

    let http_response = HttpResponse {
        status: response.status,
        headers: response.headers.clone(),
    };
    let request = http_request(&vector.request);
    let exchange = HttpExchange {
        response: &http_response,
        request: &request,
    };

    let params = SignatureParams {
        created: Some(response.params.created),
        expires: Some(response.params.expires),
        nonce: Some(response.params.nonce.clone()),
        tag: Some(response.params.tag.clone()),
        wimse_req_nonce: response.params.wimse_req_nonce.clone(),
        ..SignatureParams::default()
    };
    // Re-signing needs the private half; verification below uses the public half
    // recovered from the WIT, so the two checks stay independent.
    let signing = match signing_key(&vector.pop_signing_key_seed_b64u) {
        Ok(key) => key,
        Err(detail) => {
            report.fail(name, "response/load the signing key", detail);
            return;
        }
    };
    report.record(
        name,
        "response/reproduce",
        sign(&exchange, &covered, &params, &vector.label, &signing)
            .map_err(|e| format!("re-signing the response failed: {e}"))
            .and_then(|signed| {
                if signed.signature_input != response.signature_input {
                    Err("re-signed response `Signature-Input` differs".to_owned())
                } else if signed.signature != response.signature {
                    Err("re-signed response `Signature` differs".to_owned())
                } else {
                    Ok(())
                }
            }),
    );

    let config = |expected_req_nonce: &str| VerifyConfig {
        now: Some(vector.verify_now),
        required_components: covered.clone(),
        label: Some(vector.label.clone()),
        wimse_response_profile: true,
        expected_req_nonce: Some(expected_req_nonce.to_owned()),
        ..VerifyConfig::default()
    };

    report.record(
        name,
        "response/verify",
        verify_httpsig(
            &exchange,
            &response.signature_input,
            &response.signature,
            &pop_key,
            &config(&response.expected_req_nonce),
        )
        .map(|_| ())
        .map_err(|e| format!("the response signature did not verify: {e}")),
    );

    report.record(
        name,
        "response/content-digest",
        match response
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("content-digest"))
        {
            None => Err("the response carries no `Content-Digest` header".to_owned()),
            Some((_, digest)) if verify_content_digest(digest, response.body.as_bytes()) => Ok(()),
            Some(_) => Err("`Content-Digest` does not match the recorded body".to_owned()),
        },
    );

    run_response_negatives(
        vector,
        response,
        &http_response,
        &pop_key,
        &config,
        name,
        report,
    );
}

/// Runs the signed-response rejection cases.
fn run_response_negatives(
    vector: &HttpSigVector,
    response: &VectorResponse,
    http_response: &HttpResponse,
    pop_key: &VerifyingKey,
    config: &impl Fn(&str) -> VerifyConfig,
    name: &str,
    report: &mut Report,
) {
    for case in &response.negative {
        let case_request = case
            .request
            .as_ref()
            .map_or_else(|| http_request(&vector.request), http_request);
        let case_exchange = HttpExchange {
            response: http_response,
            request: &case_request,
        };
        let expected_nonce = case
            .expected_req_nonce
            .as_deref()
            .unwrap_or(&response.expected_req_nonce);
        let actual = verify_httpsig(
            &case_exchange,
            case.signature_input
                .as_deref()
                .unwrap_or(&response.signature_input),
            case.signature.as_deref().unwrap_or(&response.signature),
            pop_key,
            &config(expected_nonce),
        )
        .map(|_| ())
        .map_err(|e| ErrorCode::from(&e));
        report.record(
            name,
            &format!("response/reject/{}", case.id),
            expect_reject(case.expect, actual),
        );
    }
}

/// Runs the httpsig rejection cases.
fn run_httpsig_negatives(
    vector: &HttpSigVector,
    covered: &[Component],
    name: &str,
    report: &mut Report,
) {
    // Section 3 requires validating the WIT before the message signature, so the
    // negatives recover the key from it rather than from the vector's seed —
    // otherwise an implementation could skip the WIT entirely and still pass.
    let pop_key = match verifying_key(&vector.issuer_verifying_key_b64u).and_then(|issuer| {
        verify_wit(&vector.wit, &issuer, &WitValidation::at(vector.verify_now))
            .map(|verified| verified.pop_key)
            .map_err(|e| format!("the carried WIT did not verify: {e}"))
    }) {
        Ok(key) => key,
        Err(detail) => {
            report.fail(
                name,
                "recover the proof-of-possession key from the WIT",
                detail,
            );
            return;
        }
    };
    for case in &vector.negative {
        let case_request = case.request.as_ref().unwrap_or(&vector.request);
        let body = case.body.as_deref().unwrap_or(&vector.body);

        // A body that no longer matches its digest is caught by the digest
        // check, not by the signature: the signature still covers the original
        // header verbatim and would happily verify.
        if case.expect == ErrorCode::ContentDigestMismatch {
            let outcome = match content_digest(case_request) {
                None => Err(ErrorCode::MissingComponent),
                Some(digest) if verify_content_digest(digest, body.as_bytes()) => Ok(()),
                Some(_) => Err(ErrorCode::ContentDigestMismatch),
            };
            report.record(
                name,
                &format!("reject/{}", case.id),
                expect_reject(case.expect, outcome),
            );
            continue;
        }

        let required = match case.required_components.as_deref() {
            Some(quoted) => components(quoted),
            None => Ok(covered.to_vec()),
        };
        let outcome = required.and_then(|required| {
            let config = VerifyConfig {
                now: Some(case.verify_now.unwrap_or(vector.verify_now)),
                label: case.accept_label.clone(),
                required_components: required,
                max_age: case.max_age,
                wimse_profile: true,
                expected_audience: Some(
                    case.accept_audience
                        .clone()
                        .unwrap_or_else(|| vector.params.wimse_aud.clone()),
                ),
                ..VerifyConfig::default()
            };
            let actual = verify_httpsig(
                &http_request(case_request),
                case.signature_input
                    .as_deref()
                    .unwrap_or(&vector.signature_input),
                case.signature.as_deref().unwrap_or(&vector.signature),
                &pop_key,
                &config,
            )
            .map(|_| ())
            .map_err(|e| ErrorCode::from(&e));
            expect_reject(case.expect, actual)
        });
        report.record(name, &format!("reject/{}", case.id), outcome);
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, Error> {
    let bytes = fs::read(path).map_err(|e| Error::Io(path.to_owned(), e))?;
    serde_json::from_slice(&bytes).map_err(|e| Error::Parse(path.to_owned(), e))
}

/// Checks that every `.json` file under the suite directories is listed in the
/// manifest, so a vector cannot be added and quietly never run.
fn check_listed(dir: &Path, manifest: &Manifest) -> Result<(), Error> {
    let listed: HashSet<&str> = manifest.vectors.iter().map(|v| v.path.as_str()).collect();
    let suites: BTreeSet<&str> = manifest.vectors.iter().map(|v| v.suite.as_str()).collect();

    for suite in suites {
        let suite_dir = dir.join(suite);
        let Ok(reader) = fs::read_dir(&suite_dir) else {
            continue;
        };
        for file in reader {
            let file = file.map_err(|e| Error::Io(suite_dir.clone(), e))?;
            if file.path().extension().is_some_and(|ext| ext == "json") {
                let relative = format!("{suite}/{}", file.file_name().to_string_lossy());
                if !listed.contains(relative.as_str()) {
                    return Err(Error::Unlisted(relative));
                }
            }
        }
    }
    Ok(())
}

/// Loads `manifest.json` from `dir` and runs every vector it lists.
///
/// # Errors
///
/// Returns an error if the manifest or a vector cannot be read or parsed, if a
/// file declares an unknown format, or if a vector file on disk is missing from
/// the manifest. A vector that merely *fails* is reported in the [`Report`], not
/// as an error.
pub fn run_dir(dir: &Path) -> Result<Report, Error> {
    let manifest_path = dir.join("manifest.json");
    let manifest: Manifest = read_json(&manifest_path)?;
    if manifest.format != FORMAT {
        return Err(Error::UnknownFormat(manifest_path, manifest.format));
    }
    check_listed(dir, &manifest)?;

    let mut report = Report::default();
    for entry in &manifest.vectors {
        let path = dir.join(&entry.path);
        match entry.suite.as_str() {
            "identifier" => {
                let vector: IdentifierVector = read_json(&path)?;
                check_format(&path, &vector.header.format)?;
                run_identifier(&vector, &mut report);
            }
            "mtls" => {
                let vector: MtlsVector = read_json(&path)?;
                check_format(&path, &vector.header.format)?;
                run_mtls(&vector, &mut report);
            }
            "wit" => {
                let vector: WitVector = read_json(&path)?;
                check_format(&path, &vector.header.format)?;
                run_wit(&vector, &mut report);
            }
            "wpt" => {
                let vector: WptVector = read_json(&path)?;
                check_format(&path, &vector.header.format)?;
                run_wpt(&vector, &mut report);
            }
            "httpsig" => {
                let vector: HttpSigVector = read_json(&path)?;
                check_format(&path, &vector.header.format)?;
                run_httpsig(&vector, &mut report);
            }
            other => return Err(Error::UnknownSuite(other.to_owned())),
        }
    }
    Ok(report)
}

fn check_format(path: &Path, found: &str) -> Result<(), Error> {
    if found == FORMAT {
        Ok(())
    } else {
        Err(Error::UnknownFormat(path.to_owned(), found.to_owned()))
    }
}

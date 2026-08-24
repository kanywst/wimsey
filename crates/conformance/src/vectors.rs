//! The on-disk conformance vector format.
//!
//! Every file carries its `format` string so a consumer can refuse a version it
//! does not understand, and every negative case names the reason it must be
//! rejected as a language-neutral [`ErrorCode`] rather than as a Rust error
//! variant. A negative case only records the fields it overrides; anything it
//! omits is taken from the positive case in the same file.

use serde::{Deserialize, Serialize};
use wimsey_httpsig::HttpSigError;
use wimsey_identifier::ParseError;
use wimsey_jose::{Jwk, PrivateJwk};
use wimsey_mtls::MtlsError;
use wimsey_wit::{WitClaims, WitError};
use wimsey_wpt::{WptClaims, WptError};

/// The format identifier written into every vector file and the manifest.
///
/// Consumers MUST reject a file whose `format` they do not recognise rather
/// than guessing at the shape.
///
/// v2 replaced the raw key bytes of v1 with JWKs. v1 recorded a public key as
/// 32 base64url bytes, which only worked because every v1 vector was Ed25519;
/// a JWK carries its own algorithm, so one suite can hold both `EdDSA` and
/// `ES256` vectors.
pub const FORMAT: &str = "wimse-conformance/v2";

/// The index of every vector in the suite, written to `manifest.json`.
///
/// A runner reads this rather than globbing, so adding a vector without listing
/// it is a visible omission.
#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    /// Always [`FORMAT`].
    pub format: String,
    /// Every vector file, in run order.
    pub vectors: Vec<ManifestEntry>,
}

/// One entry in the [`Manifest`].
#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Which suite the file belongs to: `wit`, `wpt` or `httpsig`.
    pub suite: String,
    /// The file path, relative to the directory holding the manifest.
    pub path: String,
    /// The Internet-Draft revision the vector was generated against.
    pub spec: String,
}

/// The fields every vector file carries, whatever its suite.
#[derive(Debug, Serialize, Deserialize)]
pub struct Header {
    /// Always [`FORMAT`].
    pub format: String,
    /// Which suite the file belongs to: `wit`, `wpt` or `httpsig`.
    pub suite: String,
    /// A stable identifier for this vector, unique within its suite.
    pub id: String,
    /// The Internet-Draft revision the vector was generated against.
    pub spec: String,
    /// What the vector exercises, in prose.
    pub description: String,
}

/// The reason a negative case must be rejected.
///
/// These are deliberately independent of any implementation's error type: a
/// consumer maps them onto whatever its own verifier returns. The point of
/// recording them is that "rejected" is not good enough — an implementation
/// that rejects an expired token because it failed to parse is still wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorCode {
    /// The compact serialization was not three parts, or a part was missized.
    MalformedToken,
    /// The input exceeded the accepted maximum size.
    TokenTooLong,
    /// A critical JOSE header extension was not understood.
    UnsupportedCritical,
    /// A Base64 or JSON component could not be decoded.
    InvalidEncoding,
    /// The JOSE `typ` header was not the one this token type requires.
    WrongType,
    /// The `alg` header or signature parameter named an unsupported algorithm.
    UnsupportedAlg,
    /// The signature did not verify against the key.
    InvalidSignature,
    /// The token or signature has expired.
    Expired,
    /// The token's `iat` is ahead of the verifier's clock.
    IssuedInFuture,
    /// The token's `iss` did not match the expected issuer.
    IssuerMismatch,
    /// A key could not be decoded.
    InvalidKey,
    /// The proof's `aud` did not match the expected audience.
    AudienceMismatch,
    /// The proof's `wth` did not match the hash of the presented WIT.
    WitBindingMismatch,
    /// The proof's `ath` and the presented access token did not agree.
    AccessTokenBindingMismatch,
    /// The proof's remaining lifetime exceeded the verifier's maximum.
    LifetimeTooLong,
    /// A covered component was absent from the message.
    MissingComponent,
    /// A component identifier was not supported.
    UnsupportedComponent,
    /// A component value contained a bare CR or LF.
    InvalidComponentValue,
    /// A component the verifier requires was not covered by the signature.
    MissingRequiredComponent,
    /// The signature's `expires` precedes its `created`.
    InvalidTimeWindow,
    /// The signature's `created` is older than the verifier's maximum age.
    TooOld,
    /// A structured field could not be parsed.
    ParseError,
    /// The `Signature-Input` and `Signature` labels disagreed, or the requested
    /// label was absent.
    LabelMismatch,
    /// The signature byte sequence was not valid Base64 or not 64 bytes.
    MalformedSignature,
    /// The signature's `created` is in the future.
    CreatedInFuture,
    /// The `Content-Digest` header did not match the body.
    ContentDigestMismatch,
    /// A signature parameter the WIMSE profile requires was absent.
    MissingParameter,
    /// A signature parameter the WIMSE profile forbids was present.
    ForbiddenParameter,
    /// The signature's `tag` was not `wimse-workload-to-workload`.
    WrongTag,
    /// A signed response carried back a `wimse-req-nonce` that is not the nonce
    /// the client sent.
    RequestNonceMismatch,
    /// The `cnf` JWK omitted the required `alg` member.
    MissingConfirmationAlg,
    /// The `cnf` JWK named `none`, a symmetric, or an encryption algorithm.
    ForbiddenConfirmationAlg,
    /// The `cnf` JWK named a legal algorithm the implementation cannot use.
    UnsupportedConfirmationAlg,
    /// A workload identifier exceeded the maximum accepted length.
    IdentifierTooLong,
    /// A workload identifier did not use a scheme the implementation knows.
    UnsupportedScheme,
    /// A workload identifier carried a query component.
    HasQuery,
    /// A workload identifier carried a fragment component.
    HasFragment,
    /// A workload identifier carried user information in its authority.
    HasUserInfo,
    /// A workload identifier carried a port in its authority.
    HasPort,
    /// A workload identifier had an empty trust domain.
    EmptyTrustDomain,
    /// A trust domain exceeded the maximum length its scheme allows.
    TrustDomainTooLong,
    /// A trust domain contained a character its scheme does not allow.
    InvalidTrustDomainChar,
    /// A path had an empty segment, including a trailing slash.
    EmptyPathSegment,
    /// A path had a `.` or `..` segment.
    DotSegment,
    /// A path segment contained a character its scheme does not allow.
    InvalidPathChar,
    /// A percent-escape was not `%` followed by two hex digits.
    BadPercentEncoding,
    /// A percent-escape was well-formed but not in RFC 3986 normalized form:
    /// lowercase hex, or encoding an unreserved character.
    NonNormalizedPercentEncoding,
    /// A certificate could not be parsed as DER X.509.
    CertificateParseError,
    /// A certificate is outside its validity window at the given time.
    CertificateNotValid,
    /// A certificate carries no URI SAN workload identifier.
    MissingIdentifier,
    /// A certificate carries more than one URI SAN.
    MultipleIdentifiers,
    /// The implementation rejected the input for a reason this table does not
    /// name.
    ///
    /// Never write this into a vector: it exists so that an unmapped error
    /// surfaces as an obvious mismatch instead of being silently folded into a
    /// plausible-looking neighbour.
    Unmapped,
}

impl From<&WitError> for ErrorCode {
    fn from(error: &WitError) -> Self {
        match error {
            WitError::MalformedToken => Self::MalformedToken,
            WitError::TokenTooLong => Self::TokenTooLong,
            WitError::UnsupportedCritical => Self::UnsupportedCritical,
            WitError::Base64(_) | WitError::Json(_) => Self::InvalidEncoding,
            WitError::WrongType { .. } => Self::WrongType,
            WitError::UnsupportedAlg { .. } => Self::UnsupportedAlg,
            WitError::InvalidSignature => Self::InvalidSignature,
            WitError::Expired => Self::Expired,
            WitError::IssuedInFuture => Self::IssuedInFuture,
            WitError::IssuerMismatch => Self::IssuerMismatch,
            WitError::InvalidKey => Self::InvalidKey,
            WitError::MissingConfirmationAlg => Self::MissingConfirmationAlg,
            WitError::ForbiddenConfirmationAlg { .. } => Self::ForbiddenConfirmationAlg,
            WitError::UnsupportedConfirmationAlg { .. } => Self::UnsupportedConfirmationAlg,
            // `WitError` is `#[non_exhaustive]`; a variant added upstream is a
            // gap in this table, not something to guess at.
            _ => Self::Unmapped,
        }
    }
}

impl From<&ParseError> for ErrorCode {
    fn from(error: &ParseError) -> Self {
        match error {
            ParseError::TooLong => Self::IdentifierTooLong,
            ParseError::UnsupportedScheme => Self::UnsupportedScheme,
            ParseError::HasQuery => Self::HasQuery,
            ParseError::HasFragment => Self::HasFragment,
            ParseError::HasUserInfo => Self::HasUserInfo,
            ParseError::HasPort => Self::HasPort,
            ParseError::EmptyTrustDomain => Self::EmptyTrustDomain,
            ParseError::TrustDomainTooLong => Self::TrustDomainTooLong,
            ParseError::InvalidTrustDomainChar(_) => Self::InvalidTrustDomainChar,
            ParseError::EmptyPathSegment => Self::EmptyPathSegment,
            ParseError::DotSegment => Self::DotSegment,
            ParseError::InvalidPathChar(_) => Self::InvalidPathChar,
            ParseError::BadPercentEncoding => Self::BadPercentEncoding,
            ParseError::NonNormalizedPercentEncoding(_) => Self::NonNormalizedPercentEncoding,
            _ => Self::Unmapped,
        }
    }
}

impl From<&MtlsError> for ErrorCode {
    fn from(error: &MtlsError) -> Self {
        match error {
            MtlsError::Parse => Self::CertificateParseError,
            MtlsError::UnsupportedAlgorithm => Self::UnsupportedAlg,
            MtlsError::InvalidKey => Self::InvalidKey,
            MtlsError::InvalidSignature => Self::InvalidSignature,
            MtlsError::NotValid => Self::CertificateNotValid,
            MtlsError::MissingIdentifier => Self::MissingIdentifier,
            MtlsError::MultipleIdentifiers => Self::MultipleIdentifiers,
            MtlsError::Identifier(e) => Self::from(e),
            _ => Self::Unmapped,
        }
    }
}

impl From<&WptError> for ErrorCode {
    fn from(error: &WptError) -> Self {
        match error {
            WptError::MalformedToken => Self::MalformedToken,
            WptError::TokenTooLong => Self::TokenTooLong,
            WptError::Base64(_) | WptError::Json(_) => Self::InvalidEncoding,
            WptError::WrongType { .. } => Self::WrongType,
            WptError::UnsupportedAlg { .. } => Self::UnsupportedAlg,
            WptError::UnsupportedCritical => Self::UnsupportedCritical,
            WptError::InvalidSignature => Self::InvalidSignature,
            WptError::Expired => Self::Expired,
            WptError::AudienceMismatch => Self::AudienceMismatch,
            WptError::WitBindingMismatch => Self::WitBindingMismatch,
            WptError::AccessTokenBindingMismatch => Self::AccessTokenBindingMismatch,
            WptError::LifetimeTooLong => Self::LifetimeTooLong,
            _ => Self::Unmapped,
        }
    }
}

impl From<&HttpSigError> for ErrorCode {
    fn from(error: &HttpSigError) -> Self {
        match error {
            HttpSigError::MissingComponent(_) => Self::MissingComponent,
            HttpSigError::UnsupportedComponent(_) => Self::UnsupportedComponent,
            HttpSigError::InvalidComponentValue(_) => Self::InvalidComponentValue,
            HttpSigError::MissingRequiredComponent(_) => Self::MissingRequiredComponent,
            HttpSigError::UnsupportedAlg { .. } => Self::UnsupportedAlg,
            HttpSigError::InvalidTimeWindow => Self::InvalidTimeWindow,
            HttpSigError::TooOld => Self::TooOld,
            HttpSigError::Parse(_) => Self::ParseError,
            HttpSigError::LabelMismatch => Self::LabelMismatch,
            HttpSigError::MalformedSignature => Self::MalformedSignature,
            HttpSigError::InvalidSignature => Self::InvalidSignature,
            HttpSigError::Expired => Self::Expired,
            HttpSigError::CreatedInFuture => Self::CreatedInFuture,
            HttpSigError::MissingParameter(_) => Self::MissingParameter,
            HttpSigError::ForbiddenParameter(_) => Self::ForbiddenParameter,
            HttpSigError::WrongTag { .. } => Self::WrongTag,
            HttpSigError::AudienceMismatch => Self::AudienceMismatch,
            HttpSigError::RequestNonceMismatch => Self::RequestNonceMismatch,
            _ => Self::Unmapped,
        }
    }
}

/// A WIT issuance and verification vector.
#[derive(Debug, Serialize, Deserialize)]
pub struct WitVector {
    /// The common header fields.
    #[serde(flatten)]
    pub header: Header,
    /// The JWS algorithm; always `EdDSA` for WIMSE.
    pub alg: String,
    /// The issuer's private key, so the token can be re-signed from scratch.
    pub issuer_signing_key: PrivateJwk,
    /// The JOSE `kid` header, if the token carries one.
    pub kid: Option<String>,
    /// The time at which the positive case must verify.
    pub verify_now: u64,
    /// The claims the token encodes.
    pub claims: WitClaims,
    /// The expected token, byte for byte.
    pub token: String,
    /// Inputs that MUST be rejected, and why.
    pub negative: Vec<WitNegative>,
}

/// A WIT verification input that must fail, and the reason it must fail with.
#[derive(Debug, Serialize, Deserialize)]
pub struct WitNegative {
    /// A stable identifier, unique within the file.
    pub id: String,
    /// What makes this input invalid, in prose.
    pub description: String,
    /// The reason verification must report.
    pub expect: ErrorCode,
    /// Replaces the positive case's `token`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Replaces the positive case's `verify_now`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_now: Option<u64>,
    /// Verify against this key instead of the vector's issuer key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_verifying_key: Option<Jwk>,
    /// Require this `iss` on the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_iss: Option<String>,
}

/// A WPT vector, bound to a real WIT.
#[derive(Debug, Serialize, Deserialize)]
pub struct WptVector {
    /// The common header fields.
    #[serde(flatten)]
    pub header: Header,
    /// The JWS algorithm; always `EdDSA` for WIMSE.
    pub alg: String,
    /// The workload's proof-of-possession private key.
    pub pop_signing_key: PrivateJwk,
    /// The issuer's public key, the trust anchor for `wit`.
    pub issuer_verifying_key: Jwk,
    /// The time at which the positive case must verify.
    pub verify_now: u64,
    /// The audience the proof is addressed to.
    pub audience: String,
    /// The WIT the proof is bound to; its `cnf` is the proof-of-possession key.
    pub wit: String,
    /// The claims the proof encodes.
    pub claims: WptClaims,
    /// The expected proof, byte for byte.
    pub proof: String,
    /// Inputs that MUST be rejected, and why.
    pub negative: Vec<WptNegative>,
}

/// A WPT verification input that must fail, and the reason it must fail with.
#[derive(Debug, Serialize, Deserialize)]
pub struct WptNegative {
    /// A stable identifier, unique within the file.
    pub id: String,
    /// What makes this input invalid, in prose.
    pub description: String,
    /// The reason verification must report.
    pub expect: ErrorCode,
    /// Replaces the positive case's `proof`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    /// Replaces the positive case's `verify_now`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_now: Option<u64>,
    /// Replaces the positive case's `audience`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Replaces the positive case's `wit`, so `wth` no longer matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wit: Option<String>,
}

/// The HTTP request a signature covers, in the shape the signature base needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorRequest {
    /// The request method, uppercase.
    pub method: String,
    /// The request authority, `host[:port]`.
    pub authority: String,
    /// The absolute request path.
    pub path: String,
    /// The query string without its leading `?`, if any.
    pub query: Option<String>,
    /// The header fields, in wire order.
    pub headers: Vec<(String, String)>,
}

/// The signature parameters recorded alongside an httpsig vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorParams {
    /// The `created` parameter, in seconds since the Unix epoch.
    pub created: u64,
    /// The `expires` parameter, in seconds since the Unix epoch.
    pub expires: u64,
    /// The `nonce` parameter, unique per recipient.
    pub nonce: String,
    /// The `tag` parameter; always `wimse-workload-to-workload`.
    pub tag: String,
    /// The `wimse-aud` parameter: the audience the request is intended for.
    pub wimse_aud: String,
    /// The `wimse-sign-response` Boolean parameter, when the client requires a
    /// signed response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wimse_sign_response: Option<bool>,
    /// The `wimse-req-nonce` parameter, carried on a response signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wimse_req_nonce: Option<String>,
}

/// An RFC 9421 signing and verification vector carrying a WIT.
#[derive(Debug, Serialize, Deserialize)]
pub struct HttpSigVector {
    /// The common header fields.
    #[serde(flatten)]
    pub header: Header,
    /// The workload's proof-of-possession private key.
    pub pop_signing_key: PrivateJwk,
    /// The issuer's public key, the trust anchor for `wit`.
    pub issuer_verifying_key: Jwk,
    /// The time at which the positive case must verify.
    pub verify_now: u64,
    /// The signature label.
    pub label: String,
    /// The covered component identifiers, quoted as they appear on the wire.
    pub components: Vec<String>,
    /// The signature parameters.
    pub params: VectorParams,
    /// The request being signed.
    pub request: VectorRequest,
    /// The request body the `Content-Digest` header covers.
    pub body: String,
    /// The WIT carried in the `Workload-Identity-Token` header.
    pub wit: String,
    /// The expected `Signature-Input` field value, byte for byte.
    pub signature_input: String,
    /// The expected `Signature` field value, byte for byte.
    pub signature: String,
    /// Inputs that MUST be rejected, and why.
    pub negative: Vec<HttpSigNegative>,
    /// The signed response to this request, when the request asked for one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<VectorResponse>,
}

/// A signed response, and the request-bound checks a client must apply to it.
///
/// It lives inside the request vector rather than in a file of its own because
/// the binding between the two is the point: the request's `nonce` is what must
/// come back as the response's `wimse-req-nonce`, and the `;req` covered
/// components resolve from that same request.
#[derive(Debug, Serialize, Deserialize)]
pub struct VectorResponse {
    /// The status code, covered as `@status`.
    pub status: u16,
    /// Response header fields as `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// The response body the `Content-Digest` header covers.
    pub body: String,
    /// The covered component identifiers, in order, including the `;req` ones.
    pub components: Vec<String>,
    /// The signature parameters.
    pub params: VectorParams,
    /// The expected `Signature-Input` field value.
    pub signature_input: String,
    /// The expected `Signature` field value.
    pub signature: String,
    /// The nonce the client put on its request, which the response must return.
    pub expected_req_nonce: String,
    /// Inputs that MUST be rejected, and why.
    pub negative: Vec<ResponseNegative>,
}

/// A response verification input that must fail, and the reason it must fail.
#[derive(Debug, Serialize, Deserialize)]
pub struct ResponseNegative {
    /// A stable identifier, unique within the file.
    pub id: String,
    /// What makes this input invalid, in prose.
    pub description: String,
    /// The reason verification must report.
    pub expect: ErrorCode,
    /// Replaces the response's `Signature-Input`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_input: Option<String>,
    /// Replaces the response's `Signature`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Replaces the request the response is verified against, which is what the
    /// `;req` components resolve from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<VectorRequest>,
    /// Replaces the nonce the client claims to have sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_req_nonce: Option<String>,
}

/// An httpsig verification input that must fail, and the reason it must fail
/// with.
///
/// The request is replaced wholesale rather than patched field by field: a
/// conformance vector that needs prose to explain what it means is not doing its
/// job.
#[derive(Debug, Serialize, Deserialize)]
pub struct HttpSigNegative {
    /// A stable identifier, unique within the file.
    pub id: String,
    /// What makes this input invalid, in prose.
    pub description: String,
    /// The reason verification must report.
    pub expect: ErrorCode,
    /// Replaces the positive case's `request`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<VectorRequest>,
    /// Replaces the positive case's `body`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Replaces the positive case's `signature_input`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_input: Option<String>,
    /// Replaces the positive case's `signature`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Replaces the positive case's `verify_now`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_now: Option<u64>,
    /// The only label the verifier accepts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_label: Option<String>,
    /// The only audience the verifier answers to, instead of the vector's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_audience: Option<String>,
    /// The verifier's maximum signature age, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age: Option<u64>,
    /// Components the verifier requires, instead of the default set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_components: Option<Vec<String>>,
}

/// A workload identifier parsing vector.
///
/// Unlike the token suites there is nothing to re-sign here, so the contract is
/// different in shape but the same in spirit: an identifier in `accept` must
/// parse *and decompose* exactly as recorded, and one in `reject` must be
/// refused for the recorded reason.
#[derive(Debug, Serialize, Deserialize)]
pub struct IdentifierVector {
    /// The common header fields.
    #[serde(flatten)]
    pub header: Header,
    /// Identifiers that must parse, with the decomposition they must yield.
    pub accept: Vec<IdentifierAccept>,
    /// Identifiers that MUST be rejected, and why.
    pub reject: Vec<IdentifierReject>,
}

/// An identifier that must parse, and the components it must decompose into.
#[derive(Debug, Serialize, Deserialize)]
pub struct IdentifierAccept {
    /// A stable identifier, unique within the file.
    pub id: String,
    /// What this case establishes, in prose.
    pub description: String,
    /// The identifier under test.
    pub identifier: String,
    /// The scheme name, without `://`.
    pub scheme: String,
    /// The authority component.
    pub trust_domain: String,
    /// The path including its leading `/`, or `""` when there is none.
    pub path: String,
    /// The scheme and trust domain with the path omitted.
    pub origin: String,
}

/// An identifier that must be rejected, and the reason it must be rejected for.
#[derive(Debug, Serialize, Deserialize)]
pub struct IdentifierReject {
    /// A stable identifier, unique within the file.
    pub id: String,
    /// What makes this identifier invalid, in prose.
    pub description: String,
    /// The identifier under test.
    pub identifier: String,
    /// The reason parsing must report.
    pub expect: ErrorCode,
}

/// A Workload Identity Certificate vector.
///
/// Both keys are recorded as seeds rather than as finished certificates, so a
/// consumer can re-issue the WIC from scratch and compare bytes. That is only
/// possible because issuance takes the workload's *public* key: there is no
/// per-issuance secret for an implementation to disagree about.
#[derive(Debug, Serialize, Deserialize)]
pub struct MtlsVector {
    /// The common header fields.
    #[serde(flatten)]
    pub header: Header,
    /// The CA's private key, so the CA certificate can be rebuilt.
    pub ca_signing_key: PrivateJwk,
    /// The CA certificate's validity window, in seconds since the Unix epoch.
    pub ca_not_before: u64,
    /// The end of the CA certificate's validity window.
    pub ca_not_after: u64,
    /// The workload's private key. Only its public half is certified; it is
    /// recorded in full so a consumer can derive that public half.
    pub workload_signing_key: PrivateJwk,
    /// The workload identifier the WIC must carry in its URI SAN.
    pub identifier: String,
    /// The WIC's validity window, in seconds since the Unix epoch.
    pub not_before: u64,
    /// The end of the WIC's validity window.
    pub not_after: u64,
    /// The expected CA certificate, DER-encoded.
    pub ca_certificate_der_b64u: String,
    /// The expected WIC, DER-encoded, byte for byte.
    pub wic_der_b64u: String,
    /// The time at which the positive case must verify.
    pub verify_now: u64,
    /// Inputs that MUST be rejected, and why.
    pub negative: Vec<MtlsNegative>,
}

/// A WIC verification input that must fail, and the reason it must fail with.
#[derive(Debug, Serialize, Deserialize)]
pub struct MtlsNegative {
    /// A stable identifier, unique within the file.
    pub id: String,
    /// What makes this input invalid, in prose.
    pub description: String,
    /// The reason verification must report.
    pub expect: ErrorCode,
    /// Replaces the positive case's WIC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wic_der_b64u: Option<String>,
    /// Replaces the positive case's CA certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_certificate_der_b64u: Option<String>,
    /// Replaces the positive case's `verify_now`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_now: Option<u64>,
}

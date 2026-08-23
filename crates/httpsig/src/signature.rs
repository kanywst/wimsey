//! RFC 9421 signature parameters, signature-base construction, signing and
//! verification.

use std::fmt::Write as _;

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::error::HttpSigError;
use crate::message::{Component, HttpRequest};

/// The signature algorithm name this crate emits and accepts (RFC 9421
/// Section 3.3.6).
///
/// The WIMSE profile forbids the `alg` parameter outright — the algorithm is
/// pinned by the `cnf` JWK in the WIT — so this is only used when the crate is
/// driven as a plain RFC 9421 implementation.
pub const ALG: &str = "ed25519";

/// The `tag` value identifying a WIMSE workload-to-workload signature.
pub const WIMSE_TAG: &str = "wimse-workload-to-workload";

/// The signature label the draft recommends when a message carries a single
/// signature.
pub const WIMSE_LABEL: &str = "wimse";

/// RFC 9421 signature parameters, serialized after the covered-component list.
///
/// The last three are the signature metadata parameters registered by
/// `draft-ietf-wimse-http-signature`; the rest are the RFC 9421 originals. Field
/// order is the serialization order, which keeps a signature base reproducible.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignatureParams {
    /// Creation time, in seconds since the Unix epoch (`created`).
    pub created: Option<u64>,
    /// Expiry time, in seconds since the Unix epoch (`expires`).
    pub expires: Option<u64>,
    /// The key identifier (`keyid`). Forbidden by the WIMSE profile.
    pub keyid: Option<String>,
    /// The signature algorithm (`alg`). Forbidden by the WIMSE profile.
    pub alg: Option<String>,
    /// A unique nonce (`nonce`).
    pub nonce: Option<String>,
    /// An application-specific tag (`tag`); [`WIMSE_TAG`] under the profile.
    pub tag: Option<String>,
    /// The audience the request is intended for (`wimse-aud`). Required on a
    /// WIMSE request signature.
    pub wimse_aud: Option<String>,
    /// Whether the client requires the response to be signed
    /// (`wimse-sign-response`). A Boolean parameter: `true` serializes as a bare
    /// parameter name, per RFC 8941 Section 4.1.1.2.
    pub wimse_sign_response: Option<bool>,
    /// On a response signature, the `nonce` from the request being answered
    /// (`wimse-req-nonce`), which binds the response to that request.
    pub wimse_req_nonce: Option<String>,
}

/// The header field values produced by [`sign`].
#[derive(Debug, Clone)]
pub struct SignedSignature {
    /// The `Signature-Input` field value (for example `sig1=(...);created=...`).
    pub signature_input: String,
    /// The `Signature` field value (for example `sig1=:<base64>:`).
    pub signature: String,
}

/// The outcome of a successful [`verify`].
#[derive(Debug, Clone)]
pub struct VerifiedSignature {
    /// The signature label.
    pub label: String,
    /// The covered components, in order.
    pub components: Vec<Component>,
    /// The parsed signature parameters.
    pub params: SignatureParams,
}

/// Options controlling [`verify`].
///
/// A bare successful [`verify`] proves only that *some* set of components was
/// signed with the key. To bind the request, set `required_components` to the
/// components that must be covered (for the WIMSE profile: `@method`,
/// `@authority`, `@path`, `content-digest`, and the WIT header).
#[derive(Debug, Clone, Default)]
pub struct VerifyConfig {
    /// The current time, in seconds since the Unix epoch. When set, `created`
    /// and `expires` are checked against it.
    pub now: Option<u64>,
    /// Clock-skew tolerance, in seconds.
    pub leeway: u64,
    /// If set, only this signature label is accepted.
    pub label: Option<String>,
    /// Components that MUST be covered by the signature; verification fails if
    /// any is absent.
    pub required_components: Vec<Component>,
    /// If set (together with `now`), the signature's `created` must be present
    /// and within this many seconds of `now`.
    pub max_age: Option<u64>,
    /// Enforce the WIMSE request-signature profile on the received parameters:
    /// `created`, `expires`, `nonce`, `tag` and `wimse-aud` must all be present,
    /// `tag` must be [`WIMSE_TAG`], and `keyid` and `alg` must be absent.
    ///
    /// Off by default so the crate can also be driven as a plain RFC 9421
    /// implementation.
    pub wimse_profile: bool,
    /// If set, the signature's `wimse-aud` must equal this value. A signature
    /// is only bound to *this* service if the audience it names is checked.
    pub expected_audience: Option<String>,
}

/// Errors unless `params` satisfies the WIMSE profile for a **request**
/// signature (Section 3 of `draft-ietf-wimse-http-signature`).
///
/// The profile makes `created`, `expires`, `nonce` and `tag` mandatory on every
/// message and `wimse-aud` mandatory on requests, and forbids `keyid` and `alg`
/// — the signing key travels in the WIT and the algorithm is pinned by that
/// WIT's `cnf` JWK, so repeating either here would only invite confusion.
///
/// # Errors
///
/// Returns [`HttpSigError::MissingParameter`], [`HttpSigError::ForbiddenParameter`]
/// or [`HttpSigError::WrongTag`] for the first rule the parameters break.
pub fn check_request_profile(params: &SignatureParams) -> Result<(), HttpSigError> {
    if params.keyid.is_some() {
        return Err(HttpSigError::ForbiddenParameter("keyid"));
    }
    if params.alg.is_some() {
        return Err(HttpSigError::ForbiddenParameter("alg"));
    }
    if params.created.is_none() {
        return Err(HttpSigError::MissingParameter("created"));
    }
    if params.expires.is_none() {
        return Err(HttpSigError::MissingParameter("expires"));
    }
    if params.nonce.is_none() {
        return Err(HttpSigError::MissingParameter("nonce"));
    }
    match params.tag.as_deref() {
        None => return Err(HttpSigError::MissingParameter("tag")),
        Some(tag) if tag != WIMSE_TAG => {
            return Err(HttpSigError::WrongTag {
                found: tag.to_owned(),
            })
        }
        Some(_) => {}
    }
    if params.wimse_aud.is_none() {
        return Err(HttpSigError::MissingParameter("wimse-aud"));
    }
    Ok(())
}

fn sf_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

fn serialize_params_value(components: &[Component], params: &SignatureParams) -> String {
    let inner = components
        .iter()
        .map(Component::quoted_id)
        .collect::<Vec<_>>()
        .join(" ");
    let mut s = format!("({inner})");
    if let Some(created) = params.created {
        let _ = write!(s, ";created={created}");
    }
    if let Some(expires) = params.expires {
        let _ = write!(s, ";expires={expires}");
    }
    if let Some(keyid) = &params.keyid {
        let _ = write!(s, ";keyid={}", sf_string(keyid));
    }
    if let Some(alg) = &params.alg {
        let _ = write!(s, ";alg={}", sf_string(alg));
    }
    if let Some(nonce) = &params.nonce {
        let _ = write!(s, ";nonce={}", sf_string(nonce));
    }
    if let Some(tag) = &params.tag {
        let _ = write!(s, ";tag={}", sf_string(tag));
    }
    if let Some(aud) = &params.wimse_aud {
        let _ = write!(s, ";wimse-aud={}", sf_string(aud));
    }
    if let Some(sign_response) = params.wimse_sign_response {
        // RFC 8941 Section 4.1.1.2: a Boolean `true` parameter MUST omit its
        // value, so it serializes as the bare parameter name.
        if sign_response {
            s.push_str(";wimse-sign-response");
        } else {
            s.push_str(";wimse-sign-response=?0");
        }
    }
    if let Some(req_nonce) = &params.wimse_req_nonce {
        let _ = write!(s, ";wimse-req-nonce={}", sf_string(req_nonce));
    }
    s
}

fn signature_base_from_params_str(
    request: &HttpRequest,
    components: &[Component],
    params_value: &str,
) -> Result<String, HttpSigError> {
    // The received parameter substring is untrusted; a bare CR or LF in it would
    // forge extra signature-base lines.
    if params_value.contains(['\r', '\n']) {
        return Err(HttpSigError::Parse(
            "signature parameters contain CR or LF".to_owned(),
        ));
    }
    let mut base = String::new();
    for component in components {
        let value = request.component_value(component)?;
        // A bare CR or LF in a value would forge extra signature-base lines.
        if value.contains(['\r', '\n']) {
            return Err(HttpSigError::InvalidComponentValue(component.quoted_id()));
        }
        base.push_str(&component.quoted_id());
        base.push_str(": ");
        base.push_str(&value);
        base.push('\n');
    }
    base.push_str("\"@signature-params\": ");
    base.push_str(params_value);
    Ok(base)
}

/// Builds the RFC 9421 signature base for `request` over `components` with
/// `params`.
///
/// # Errors
///
/// Returns [`HttpSigError::MissingComponent`] if a covered header is absent.
pub fn signature_base(
    request: &HttpRequest,
    components: &[Component],
    params: &SignatureParams,
) -> Result<String, HttpSigError> {
    let params_value = serialize_params_value(components, params);
    signature_base_from_params_str(request, components, &params_value)
}

/// Signs `request` over `components`, producing `Signature-Input` and
/// `Signature` field values under `label`.
///
/// # Errors
///
/// Returns [`HttpSigError::MissingComponent`] if a covered header is absent.
pub fn sign(
    request: &HttpRequest,
    components: &[Component],
    params: &SignatureParams,
    label: &str,
    signing_key: &SigningKey,
) -> Result<SignedSignature, HttpSigError> {
    let params_value = serialize_params_value(components, params);
    let base = signature_base_from_params_str(request, components, &params_value)?;
    let signature: Signature = signing_key.sign(base.as_bytes());
    Ok(SignedSignature {
        signature_input: format!("{label}={params_value}"),
        signature: format!("{label}=:{}:", STANDARD.encode(signature.to_bytes())),
    })
}

/// Splits a single-member dictionary field value `label=rest` at the first `=`.
fn split_member(value: &str) -> Result<(&str, &str), HttpSigError> {
    let value = value.trim();
    let eq = value
        .find('=')
        .ok_or_else(|| HttpSigError::Parse("missing `=` in dictionary member".to_owned()))?;
    let label = value[..eq].trim();
    if label.is_empty() {
        return Err(HttpSigError::Parse("empty signature label".to_owned()));
    }
    Ok((label, &value[eq + 1..]))
}

fn parse_sf_string(token: &str) -> Result<String, HttpSigError> {
    let inner = token
        .strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .ok_or_else(|| HttpSigError::Parse(format!("not a string: {token}")))?;
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(next @ ('\\' | '"')) => out.push(next),
                _ => return Err(HttpSigError::Parse("bad string escape".to_owned())),
            }
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

/// The byte index of the first unescaped, unquoted `target` in `s`, respecting
/// RFC 8941 string quoting so a delimiter inside a `"..."` value is skipped.
fn find_unquoted(s: &str, target: char) -> Option<usize> {
    let mut in_quotes = false;
    let mut escaped = false;
    for (idx, c) in s.char_indices() {
        if escaped {
            escaped = false;
        } else if in_quotes && c == '\\' {
            escaped = true;
        } else if c == '"' {
            in_quotes = !in_quotes;
        } else if c == target && !in_quotes {
            return Some(idx);
        }
    }
    None
}

/// Splits `s` on unquoted `;`, keeping delimiters inside `"..."` values intact.
fn split_unquoted_semicolons(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut escaped = false;
    for (idx, c) in s.char_indices() {
        if escaped {
            escaped = false;
        } else if in_quotes && c == '\\' {
            escaped = true;
        } else if c == '"' {
            in_quotes = !in_quotes;
        } else if c == ';' && !in_quotes {
            parts.push(&s[start..idx]);
            start = idx + 1;
        }
    }
    parts.push(&s[start..]);
    parts
}

fn parse_params(rest: &str, params: &mut SignatureParams) -> Result<(), HttpSigError> {
    for part in split_unquoted_semicolons(rest) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let Some((name, raw)) = part.split_once('=') else {
            // A valueless parameter is Boolean `true`, per RFC 8941
            // Section 4.1.1.2. Unknown ones are still ignored.
            if part == "wimse-sign-response" {
                params.wimse_sign_response = Some(true);
            }
            continue;
        };
        let name = name.trim();
        let raw = raw.trim();
        match name {
            "created" => {
                params.created = Some(parse_int(raw)?);
            }
            "expires" => {
                params.expires = Some(parse_int(raw)?);
            }
            "keyid" => params.keyid = Some(parse_sf_string(raw)?),
            "alg" => params.alg = Some(parse_sf_string(raw)?),
            "nonce" => params.nonce = Some(parse_sf_string(raw)?),
            "tag" => params.tag = Some(parse_sf_string(raw)?),
            "wimse-aud" => params.wimse_aud = Some(parse_sf_string(raw)?),
            "wimse-sign-response" => params.wimse_sign_response = Some(parse_sf_boolean(raw)?),
            "wimse-req-nonce" => params.wimse_req_nonce = Some(parse_sf_string(raw)?),
            // Unknown parameters are ignored, per structured-field extensibility.
            _ => {}
        }
    }
    Ok(())
}

/// Parses an RFC 8941 Boolean (`?0` or `?1`) given explicitly.
fn parse_sf_boolean(raw: &str) -> Result<bool, HttpSigError> {
    match raw {
        "?1" => Ok(true),
        "?0" => Ok(false),
        other => Err(HttpSigError::Parse(format!("not a boolean: {other}"))),
    }
}

fn parse_int(raw: &str) -> Result<u64, HttpSigError> {
    raw.trim()
        .parse()
        .map_err(|_| HttpSigError::Parse(format!("not an integer: {raw}")))
}

/// Parses a `Signature-Input` field value into its label, covered components,
/// parameters, and the verbatim parameters substring used in the base.
fn parse_signature_input(
    value: &str,
) -> Result<(String, Vec<Component>, SignatureParams, String), HttpSigError> {
    let (label, rest) = split_member(value)?;
    let rest = rest.trim();
    if !rest.starts_with('(') {
        return Err(HttpSigError::Parse(
            "inner list must start with `(`".to_owned(),
        ));
    }
    // Find the inner list's closing `)`, ignoring any `)` inside a quoted value.
    let close = find_unquoted(rest, ')')
        .ok_or_else(|| HttpSigError::Parse("missing `)` in inner list".to_owned()))?;
    let inner = &rest[1..close];

    let mut components = Vec::new();
    for token in inner.split_whitespace() {
        components.push(Component::from_quoted_id(token)?);
    }

    let mut params = SignatureParams::default();
    parse_params(&rest[close + 1..], &mut params)?;

    Ok((label.to_owned(), components, params, rest.to_owned()))
}

/// Parses a `Signature` field value into its label and 64-byte signature.
fn parse_signature(value: &str) -> Result<(String, [u8; 64]), HttpSigError> {
    let (label, rest) = split_member(value)?;
    let b64 = rest
        .trim()
        .strip_prefix(':')
        .and_then(|t| t.strip_suffix(':'))
        .ok_or_else(|| HttpSigError::Parse("byte sequence must be wrapped in `:`".to_owned()))?;
    let bytes = STANDARD
        .decode(b64)
        .map_err(|_| HttpSigError::MalformedSignature)?;
    let array: [u8; 64] = bytes
        .try_into()
        .map_err(|_| HttpSigError::MalformedSignature)?;
    Ok((label.to_owned(), array))
}

/// Verifies an HTTP message signature on `request`.
///
/// Reconstructs the signature base from the components named in
/// `signature_input` (using the received parameter string verbatim, so the base
/// is byte-exact), verifies it against `verifying_key`, and applies the checks
/// in `config`. Fails closed on any deviation.
///
/// A successful return proves only that the covered components were signed with
/// `verifying_key`. It does **not** by itself guarantee any particular
/// component was covered — use [`VerifyConfig::required_components`] to require
/// them — nor does it check the message body: if `content-digest` is covered,
/// the caller MUST also recompute and compare it against the received body with
/// [`verify_content_digest`](crate::verify_content_digest). Freshness and
/// replay defense (unique `nonce` / bounded age) are also the caller's
/// responsibility; see `max_age`.
///
/// # Errors
///
/// Returns the corresponding [`HttpSigError`] for an unparsable field, a label
/// mismatch, a missing covered header, an unexpected `alg`, a malformed or
/// invalid signature, a missing required component, or a stale, expired,
/// future-dated, or inverted-window signature.
pub fn verify(
    request: &HttpRequest,
    signature_input: &str,
    signature: &str,
    verifying_key: &VerifyingKey,
    config: &VerifyConfig,
) -> Result<VerifiedSignature, HttpSigError> {
    let (input_label, components, params, params_value) = parse_signature_input(signature_input)?;
    let (sig_label, sig_bytes) = parse_signature(signature)?;

    if input_label != sig_label {
        return Err(HttpSigError::LabelMismatch);
    }
    if let Some(expected) = &config.label {
        if expected != &input_label {
            return Err(HttpSigError::LabelMismatch);
        }
    }
    if config.wimse_profile {
        check_request_profile(&params)?;
    }
    if let Some(alg) = &params.alg {
        if alg != ALG {
            return Err(HttpSigError::UnsupportedAlg { found: alg.clone() });
        }
    }
    // The audience is checked before the signature so an unparsable or
    // misdirected signature costs no verification work; both checks must pass.
    if let Some(expected) = &config.expected_audience {
        if params.wimse_aud.as_ref() != Some(expected) {
            return Err(HttpSigError::AudienceMismatch);
        }
    }

    let base = signature_base_from_params_str(request, &components, &params_value)?;
    let signature = Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify_strict(base.as_bytes(), &signature)
        .map_err(|_| HttpSigError::InvalidSignature)?;

    for required in &config.required_components {
        if !components.contains(required) {
            return Err(HttpSigError::MissingRequiredComponent(required.quoted_id()));
        }
    }

    if let (Some(created), Some(expires)) = (params.created, params.expires) {
        if expires < created {
            return Err(HttpSigError::InvalidTimeWindow);
        }
    }
    // A `max_age` without a `now` would silently skip the freshness check; fail
    // closed rather than give a false sense of enforcement.
    if config.max_age.is_some() && config.now.is_none() {
        return Err(HttpSigError::TooOld);
    }
    if let Some(now) = config.now {
        if let Some(expires) = params.expires {
            if now > expires.saturating_add(config.leeway) {
                return Err(HttpSigError::Expired);
            }
        }
        if let Some(created) = params.created {
            if created > now.saturating_add(config.leeway) {
                return Err(HttpSigError::CreatedInFuture);
            }
        }
        if let Some(max_age) = config.max_age {
            let created = params.created.ok_or(HttpSigError::TooOld)?;
            if now.saturating_sub(created) > max_age {
                return Err(HttpSigError::TooOld);
            }
        }
    }

    Ok(VerifiedSignature {
        label: input_label,
        components,
        params,
    })
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::{sign, signature_base, verify, SignatureParams, VerifyConfig, ALG};
    use crate::error::HttpSigError;
    use crate::message::{Component, HttpRequest};

    // The canonical RFC 9421 test request (Section 2.5).
    fn rfc_request() -> HttpRequest {
        HttpRequest {
            method: "POST".to_owned(),
            authority: "example.com".to_owned(),
            path: "/foo".to_owned(),
            query: Some("param=Value&Pet=dog".to_owned()),
            headers: vec![
                ("Host".to_owned(), "example.com".to_owned()),
                ("Date".to_owned(), "Tue, 20 Apr 2021 02:07:55 GMT".to_owned()),
                ("Content-Type".to_owned(), "application/json".to_owned()),
                (
                    "Content-Digest".to_owned(),
                    "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:".to_owned(),
                ),
                ("Content-Length".to_owned(), "18".to_owned()),
            ],
        }
    }

    fn rfc_components() -> Vec<Component> {
        vec![
            Component::Method,
            Component::Authority,
            Component::Path,
            Component::header("content-digest"),
            Component::header("content-length"),
            Component::header("content-type"),
        ]
    }

    // Known-answer test: the signature base must match RFC 9421 Section 2.5
    // byte-for-byte.
    #[test]
    fn signature_base_matches_rfc_9421() {
        let params = SignatureParams {
            created: Some(1_618_884_473),
            keyid: Some("test-key-rsa-pss".to_owned()),
            ..SignatureParams::default()
        };
        let base = signature_base(&rfc_request(), &rfc_components(), &params).unwrap();

        let expected = concat!(
            "\"@method\": POST\n",
            "\"@authority\": example.com\n",
            "\"@path\": /foo\n",
            "\"content-digest\": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:\n",
            "\"content-length\": 18\n",
            "\"content-type\": application/json\n",
            "\"@signature-params\": (\"@method\" \"@authority\" \"@path\" \"content-digest\" \"content-length\" \"content-type\");created=1618884473;keyid=\"test-key-rsa-pss\""
        );
        assert_eq!(base, expected);
    }

    fn ed25519_params() -> SignatureParams {
        SignatureParams {
            created: Some(1_700_000_000),
            keyid: Some("issuer-key-1".to_owned()),
            alg: Some(ALG.to_owned()),
            ..SignatureParams::default()
        }
    }

    #[test]
    fn round_trips() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let request = rfc_request();
        let components = rfc_components();
        let signed = sign(&request, &components, &ed25519_params(), "sig1", &key).unwrap();

        let verified = verify(
            &request,
            &signed.signature_input,
            &signed.signature,
            &key.verifying_key(),
            &VerifyConfig::default(),
        )
        .unwrap();
        assert_eq!(verified.label, "sig1");
        assert_eq!(verified.components, components);
        assert_eq!(verified.params.keyid.as_deref(), Some("issuer-key-1"));
    }

    #[test]
    fn rejects_a_tampered_request() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let mut request = rfc_request();
        let components = rfc_components();
        let signed = sign(&request, &components, &ed25519_params(), "sig1", &key).unwrap();

        // Change a covered header after signing.
        request
            .headers
            .push(("Content-Length".to_owned(), "19".to_owned()));
        request
            .headers
            .retain(|(n, v)| !(n == "Content-Length" && v == "18"));

        let err = verify(
            &request,
            &signed.signature_input,
            &signed.signature,
            &key.verifying_key(),
            &VerifyConfig::default(),
        );
        assert!(matches!(err, Err(HttpSigError::InvalidSignature)));
    }

    #[test]
    fn rejects_the_wrong_key() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let other = SigningKey::from_bytes(&[6u8; 32]);
        let request = rfc_request();
        let signed = sign(&request, &rfc_components(), &ed25519_params(), "sig1", &key).unwrap();

        let err = verify(
            &request,
            &signed.signature_input,
            &signed.signature,
            &other.verifying_key(),
            &VerifyConfig::default(),
        );
        assert!(matches!(err, Err(HttpSigError::InvalidSignature)));
    }

    #[test]
    fn rejects_a_missing_covered_header() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let request = HttpRequest {
            headers: vec![],
            ..rfc_request()
        };
        let err = sign(&request, &rfc_components(), &ed25519_params(), "sig1", &key);
        assert!(matches!(err, Err(HttpSigError::MissingComponent(_))));
    }

    #[test]
    fn enforces_expiry() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let request = rfc_request();
        let params = SignatureParams {
            created: Some(1_700_000_000),
            expires: Some(1_700_000_300),
            keyid: Some("k".to_owned()),
            alg: Some(ALG.to_owned()),
            ..SignatureParams::default()
        };
        let signed = sign(&request, &rfc_components(), &params, "sig1", &key).unwrap();

        let config = VerifyConfig {
            now: Some(1_700_000_301),
            ..VerifyConfig::default()
        };
        let err = verify(
            &request,
            &signed.signature_input,
            &signed.signature,
            &key.verifying_key(),
            &config,
        );
        assert!(matches!(err, Err(HttpSigError::Expired)));
    }

    #[test]
    fn rejects_a_label_mismatch() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let request = rfc_request();
        let signed = sign(&request, &rfc_components(), &ed25519_params(), "sig1", &key).unwrap();

        let config = VerifyConfig {
            label: Some("other".to_owned()),
            ..VerifyConfig::default()
        };
        let err = verify(
            &request,
            &signed.signature_input,
            &signed.signature,
            &key.verifying_key(),
            &config,
        );
        assert!(matches!(err, Err(HttpSigError::LabelMismatch)));
    }

    #[test]
    fn is_deterministic() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let request = rfc_request();
        let components = rfc_components();
        let a = sign(&request, &components, &ed25519_params(), "sig1", &key).unwrap();
        let b = sign(&request, &components, &ed25519_params(), "sig1", &key).unwrap();
        assert_eq!(a.signature_input, b.signature_input);
        assert_eq!(a.signature, b.signature);
    }

    #[test]
    fn rejects_a_missing_required_component() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let request = rfc_request();
        // Signature covers method and path only.
        let signed = sign(
            &request,
            &[Component::Method, Component::Path],
            &ed25519_params(),
            "sig1",
            &key,
        )
        .unwrap();

        let config = VerifyConfig {
            required_components: vec![Component::header("content-digest")],
            ..VerifyConfig::default()
        };
        let err = verify(
            &request,
            &signed.signature_input,
            &signed.signature,
            &key.verifying_key(),
            &config,
        );
        assert!(matches!(
            err,
            Err(HttpSigError::MissingRequiredComponent(_))
        ));
    }

    #[test]
    fn rejects_a_non_ed25519_alg() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let request = rfc_request();
        let params = SignatureParams {
            created: Some(1_700_000_000),
            keyid: Some("k".to_owned()),
            alg: Some("rsa-pss".to_owned()),
            ..SignatureParams::default()
        };
        let signed = sign(&request, &rfc_components(), &params, "sig1", &key).unwrap();

        let err = verify(
            &request,
            &signed.signature_input,
            &signed.signature,
            &key.verifying_key(),
            &VerifyConfig::default(),
        );
        assert!(matches!(err, Err(HttpSigError::UnsupportedAlg { .. })));
    }

    #[test]
    fn rejects_crlf_in_a_covered_header() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let mut request = rfc_request();
        request
            .headers
            .push(("X-Evil".to_owned(), "ok\n\"@path\": /evil".to_owned()));

        let err = sign(
            &request,
            &[Component::Method, Component::header("x-evil")],
            &ed25519_params(),
            "sig1",
            &key,
        );
        assert!(matches!(err, Err(HttpSigError::InvalidComponentValue(_))));
    }

    #[test]
    fn rejects_an_inverted_time_window() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let request = rfc_request();
        let params = SignatureParams {
            created: Some(1_700_000_300),
            expires: Some(1_700_000_000),
            keyid: Some("k".to_owned()),
            alg: Some(ALG.to_owned()),
            ..SignatureParams::default()
        };
        let signed = sign(&request, &rfc_components(), &params, "sig1", &key).unwrap();

        let err = verify(
            &request,
            &signed.signature_input,
            &signed.signature,
            &key.verifying_key(),
            &VerifyConfig::default(),
        );
        assert!(matches!(err, Err(HttpSigError::InvalidTimeWindow)));
    }

    #[test]
    fn enforces_max_age() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let request = rfc_request();
        // created is 1_700_000_000.
        let signed = sign(&request, &rfc_components(), &ed25519_params(), "sig1", &key).unwrap();

        let config = VerifyConfig {
            now: Some(1_700_000_400),
            max_age: Some(60),
            ..VerifyConfig::default()
        };
        let err = verify(
            &request,
            &signed.signature_input,
            &signed.signature,
            &key.verifying_key(),
            &config,
        );
        assert!(matches!(err, Err(HttpSigError::TooOld)));
    }

    #[test]
    fn tolerates_unknown_boolean_parameters() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use ed25519_dalek::Signer;

        let key = SigningKey::from_bytes(&[5u8; 32]);
        let request = rfc_request();
        // A params value carrying a boolean parameter `;ext` (no value).
        let params_value = "(\"@method\" \"@path\");created=1700000000;ext";
        let base = format!(
            "\"@method\": {}\n\"@path\": {}\n\"@signature-params\": {params_value}",
            request.method, request.path,
        );
        let signature = STANDARD.encode(key.sign(base.as_bytes()).to_bytes());
        let signature_input = format!("sig1={params_value}");
        let signature = format!("sig1=:{signature}:");

        let verified = verify(
            &request,
            &signature_input,
            &signature,
            &key.verifying_key(),
            &VerifyConfig::default(),
        )
        .unwrap();
        assert_eq!(verified.params.created, Some(1_700_000_000));
    }

    #[test]
    fn content_digest_helper_binds_the_body() {
        use crate::message::{content_digest_sha256, verify_content_digest};

        let body = br#"{"amount":100}"#;
        let header = content_digest_sha256(body);
        assert!(verify_content_digest(&header, body));
        assert!(!verify_content_digest(&header, b"tampered"));
    }

    #[test]
    fn round_trips_params_with_quoted_delimiters() {
        // A keyid whose value legitimately contains `;`, `)` and `"` (all valid
        // inside an RFC 8941 string) must survive the round trip.
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let request = rfc_request();
        let params = SignatureParams {
            created: Some(1_700_000_000),
            keyid: Some("weird;key)with\"quote".to_owned()),
            alg: Some(ALG.to_owned()),
            ..SignatureParams::default()
        };
        let signed = sign(&request, &rfc_components(), &params, "sig1", &key).unwrap();

        let verified = verify(
            &request,
            &signed.signature_input,
            &signed.signature,
            &key.verifying_key(),
            &VerifyConfig::default(),
        )
        .unwrap();
        assert_eq!(
            verified.params.keyid.as_deref(),
            Some("weird;key)with\"quote")
        );
    }

    #[test]
    fn rejects_crlf_in_signature_params() {
        use base64::{engine::general_purpose::STANDARD, Engine};

        let key = SigningKey::from_bytes(&[5u8; 32]);
        let request = rfc_request();
        // A newline smuggled into the parameters (parses, but must be rejected).
        let signature_input = "sig1=(\"@method\")\n;created=1700000000";
        let signature = format!("sig1=:{}:", STANDARD.encode([0u8; 64]));

        let err = verify(
            &request,
            signature_input,
            &signature,
            &key.verifying_key(),
            &VerifyConfig::default(),
        );
        assert!(matches!(err, Err(HttpSigError::Parse(_))));
    }

    // --- The WIMSE profile (draft-ietf-wimse-http-signature Section 3) ---

    use super::{check_request_profile, WIMSE_TAG};

    /// A parameter set that satisfies every rule of the profile.
    fn wimse_params() -> SignatureParams {
        SignatureParams {
            created: Some(1_700_000_000),
            expires: Some(1_700_000_300),
            nonce: Some("abcd1111".to_owned()),
            tag: Some(WIMSE_TAG.to_owned()),
            wimse_aud: Some("https://svcb.example.com/gimme-ice-cream".to_owned()),
            ..SignatureParams::default()
        }
    }

    fn wimse_config() -> VerifyConfig {
        VerifyConfig {
            wimse_profile: true,
            ..VerifyConfig::default()
        }
    }

    fn sign_with(params: &SignatureParams) -> (SigningKey, HttpRequest, super::SignedSignature) {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let request = rfc_request();
        let signed = sign(&request, &rfc_components(), params, "wimse", &key).unwrap();
        (key, request, signed)
    }

    #[test]
    fn accepts_a_profile_conforming_signature() {
        let (key, request, signed) = sign_with(&wimse_params());
        let verified = verify(
            &request,
            &signed.signature_input,
            &signed.signature,
            &key.verifying_key(),
            &wimse_config(),
        )
        .unwrap();
        assert_eq!(verified.params.tag.as_deref(), Some(WIMSE_TAG));
    }

    // `keyid` and `alg` MUST NOT be used: the key travels in the WIT and the
    // algorithm is pinned by that WIT's `cnf` JWK.
    #[test]
    fn profile_rejects_keyid_and_alg() {
        for (label, params) in [
            (
                "keyid",
                SignatureParams {
                    keyid: Some("k".to_owned()),
                    ..wimse_params()
                },
            ),
            (
                "alg",
                SignatureParams {
                    alg: Some(ALG.to_owned()),
                    ..wimse_params()
                },
            ),
        ] {
            let (key, request, signed) = sign_with(&params);
            let err = verify(
                &request,
                &signed.signature_input,
                &signed.signature,
                &key.verifying_key(),
                &wimse_config(),
            );
            assert!(
                matches!(err, Err(HttpSigError::ForbiddenParameter(p)) if p == label),
                "expected `{label}` to be rejected, got {err:?}"
            );
        }
    }

    #[test]
    fn profile_requires_the_mandatory_parameters() {
        let cases: [(&str, SignatureParams); 5] = [
            (
                "created",
                SignatureParams {
                    created: None,
                    ..wimse_params()
                },
            ),
            (
                "expires",
                SignatureParams {
                    expires: None,
                    ..wimse_params()
                },
            ),
            (
                "nonce",
                SignatureParams {
                    nonce: None,
                    ..wimse_params()
                },
            ),
            (
                "tag",
                SignatureParams {
                    tag: None,
                    ..wimse_params()
                },
            ),
            (
                "wimse-aud",
                SignatureParams {
                    wimse_aud: None,
                    ..wimse_params()
                },
            ),
        ];
        for (name, params) in cases {
            let err = check_request_profile(&params);
            assert!(
                matches!(err, Err(HttpSigError::MissingParameter(p)) if p == name),
                "expected `{name}` to be required, got {err:?}"
            );
        }
    }

    #[test]
    fn profile_rejects_a_foreign_tag() {
        let params = SignatureParams {
            tag: Some("something-else".to_owned()),
            ..wimse_params()
        };
        let (key, request, signed) = sign_with(&params);
        let err = verify(
            &request,
            &signed.signature_input,
            &signed.signature,
            &key.verifying_key(),
            &wimse_config(),
        );
        assert!(matches!(err, Err(HttpSigError::WrongTag { .. })));
    }

    // A signature is only bound to this service if its `wimse-aud` is checked;
    // one minted for a peer must not verify here.
    #[test]
    fn rejects_a_signature_minted_for_another_audience() {
        let (key, request, signed) = sign_with(&wimse_params());
        let config = VerifyConfig {
            expected_audience: Some("https://svcc.example.com/other".to_owned()),
            ..wimse_config()
        };
        let err = verify(
            &request,
            &signed.signature_input,
            &signed.signature,
            &key.verifying_key(),
            &config,
        );
        assert!(matches!(err, Err(HttpSigError::AudienceMismatch)));
    }

    #[test]
    fn accepts_the_matching_audience() {
        let (key, request, signed) = sign_with(&wimse_params());
        let config = VerifyConfig {
            expected_audience: Some("https://svcb.example.com/gimme-ice-cream".to_owned()),
            ..wimse_config()
        };
        assert!(verify(
            &request,
            &signed.signature_input,
            &signed.signature,
            &key.verifying_key(),
            &config,
        )
        .is_ok());
    }

    // RFC 8941: a Boolean `true` parameter is written bare, with no value.
    #[test]
    fn serializes_sign_response_as_a_bare_boolean() {
        let params = SignatureParams {
            wimse_sign_response: Some(true),
            ..wimse_params()
        };
        let (key, request, signed) = sign_with(&params);
        assert!(signed.signature_input.ends_with(";wimse-sign-response"));

        let verified = verify(
            &request,
            &signed.signature_input,
            &signed.signature,
            &key.verifying_key(),
            &wimse_config(),
        )
        .unwrap();
        assert_eq!(verified.params.wimse_sign_response, Some(true));
    }

    #[test]
    fn round_trips_an_explicit_false_sign_response() {
        let params = SignatureParams {
            wimse_sign_response: Some(false),
            ..wimse_params()
        };
        let (key, request, signed) = sign_with(&params);
        assert!(signed.signature_input.ends_with(";wimse-sign-response=?0"));

        let verified = verify(
            &request,
            &signed.signature_input,
            &signed.signature,
            &key.verifying_key(),
            &wimse_config(),
        )
        .unwrap();
        assert_eq!(verified.params.wimse_sign_response, Some(false));
    }

    #[test]
    fn round_trips_the_response_nonce_binding() {
        let params = SignatureParams {
            wimse_req_nonce: Some("abcd1111".to_owned()),
            ..wimse_params()
        };
        let (key, request, signed) = sign_with(&params);
        let verified = verify(
            &request,
            &signed.signature_input,
            &signed.signature,
            &key.verifying_key(),
            &wimse_config(),
        )
        .unwrap();
        assert_eq!(verified.params.wimse_req_nonce.as_deref(), Some("abcd1111"));
    }

    // The profile is opt-in: a plain RFC 9421 signature must still verify with
    // the default config, which is what the known-answer test above relies on.
    #[test]
    fn profile_is_off_by_default() {
        let (key, request, signed) = sign_with(&ed25519_params());
        assert!(verify(
            &request,
            &signed.signature_input,
            &signed.signature,
            &key.verifying_key(),
            &VerifyConfig::default(),
        )
        .is_ok());
    }

    #[test]
    fn rejects_max_age_without_now() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let request = rfc_request();
        let signed = sign(&request, &rfc_components(), &ed25519_params(), "sig1", &key).unwrap();

        // `max_age` set but `now` unset must fail closed, not silently skip.
        let config = VerifyConfig {
            max_age: Some(60),
            ..VerifyConfig::default()
        };
        let err = verify(
            &request,
            &signed.signature_input,
            &signed.signature,
            &key.verifying_key(),
            &config,
        );
        assert!(matches!(err, Err(HttpSigError::TooOld)));
    }
}

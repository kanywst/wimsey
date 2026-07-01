//! RFC 9421 signature parameters, signature-base construction, signing and
//! verification.

use std::fmt::Write as _;

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::error::HttpSigError;
use crate::message::{Component, HttpRequest};

/// The signature algorithm name this crate emits and accepts (RFC 9421
/// Section 3.3.6).
pub const ALG: &str = "ed25519";

/// RFC 9421 signature parameters, serialized after the covered-component list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignatureParams {
    /// Creation time, in seconds since the Unix epoch (`created`).
    pub created: Option<u64>,
    /// Expiry time, in seconds since the Unix epoch (`expires`).
    pub expires: Option<u64>,
    /// The key identifier (`keyid`).
    pub keyid: Option<String>,
    /// The signature algorithm (`alg`); `ed25519` for this crate.
    pub alg: Option<String>,
    /// A unique nonce (`nonce`).
    pub nonce: Option<String>,
    /// An application-specific tag (`tag`).
    pub tag: Option<String>,
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
            // A valueless (boolean) parameter, per RFC 8941; not used here.
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
            // Unknown parameters are ignored, per structured-field extensibility.
            _ => {}
        }
    }
    Ok(())
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
    if let Some(alg) = &params.alg {
        if alg != ALG {
            return Err(HttpSigError::UnsupportedAlg { found: alg.clone() });
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

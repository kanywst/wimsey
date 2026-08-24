//! Minimal HTTP request and response models, and the covered-component values
//! derived from them, per RFC 9421 Section 2.

use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};

use crate::error::HttpSigError;

/// A covered component of an HTTP message signature.
///
/// This crate supports the derived components `@method`, `@authority`, `@path`,
/// `@query`, `@request-target` and `@status`, plus plain header fields and the
/// `;req` component parameter. `@target-uri` and the other parameters (for
/// example `;sf` or `;key`) are not modeled.
#[derive(Debug, Clone)]
pub enum Component {
    /// The request method (`@method`).
    Method,
    /// The request authority (`@authority`), lowercased.
    Authority,
    /// The absolute path (`@path`).
    Path,
    /// The query string including the leading `?` (`@query`).
    Query,
    /// The request target (`@request-target`): the absolute path followed by
    /// `?` and the query when one is present (RFC 9421 Section 2.2.5,
    /// origin-form). The WIMSE profile requires this component to be signed.
    RequestTarget,
    /// The response status code (`@status`), RFC 9421 Section 2.2.9. Only
    /// meaningful on a response.
    Status,
    /// A component taken from the *request* a response answers, written with
    /// the `;req` parameter (RFC 9421 Section 2.4) — for example
    /// `"@method";req`. The WIMSE profile requires two of these on a signed
    /// response, so that the response cannot be lifted onto a different
    /// request.
    Req(Box<Component>),
    /// A header field, identified by its lowercase name.
    Header(String),
}

// Header names are compared case-insensitively so a component built directly as
// `Component::Header("Content-Type".into())` still matches a parsed, lowercased
// one — for example in `VerifyConfig::required_components`.
impl PartialEq for Component {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Method, Self::Method)
            | (Self::Authority, Self::Authority)
            | (Self::Path, Self::Path)
            | (Self::Query, Self::Query)
            | (Self::RequestTarget, Self::RequestTarget)
            | (Self::Status, Self::Status) => true,
            (Self::Req(a), Self::Req(b)) => a == b,
            (Self::Header(a), Self::Header(b)) => a.eq_ignore_ascii_case(b),
            _ => false,
        }
    }
}

impl Eq for Component {}

impl Component {
    /// A header component from any-case `name`.
    #[must_use]
    pub fn header(name: &str) -> Self {
        Self::Header(name.to_ascii_lowercase())
    }

    /// The quoted component identifier as it appears in the signature base and
    /// the inner list (for example `"@method"` or `"content-type"`).
    #[must_use]
    pub fn quoted_id(&self) -> String {
        match self {
            Self::Method => "\"@method\"".to_owned(),
            Self::Authority => "\"@authority\"".to_owned(),
            Self::Path => "\"@path\"".to_owned(),
            Self::Query => "\"@query\"".to_owned(),
            Self::RequestTarget => "\"@request-target\"".to_owned(),
            Self::Status => "\"@status\"".to_owned(),
            // The parameter sits outside the quotes: `"@method";req`.
            Self::Req(inner) => format!("{};req", inner.quoted_id()),
            Self::Header(name) => format!("\"{name}\""),
        }
    }

    /// Parses a quoted component identifier back into a [`Component`].
    ///
    /// # Errors
    ///
    /// Returns [`HttpSigError::UnsupportedComponent`] for an identifier this
    /// crate does not model (including any carrying parameters), and
    /// [`HttpSigError::Parse`] if the token is not a quoted string.
    pub fn from_quoted_id(token: &str) -> Result<Self, HttpSigError> {
        // `;req` is the only component parameter this crate models.
        if let Some(base) = token.strip_suffix(";req") {
            return Ok(Self::Req(Box::new(Self::from_quoted_id(base)?)));
        }
        let inner = token
            .strip_prefix('"')
            .and_then(|t| t.strip_suffix('"'))
            .ok_or_else(|| HttpSigError::Parse(format!("not a quoted identifier: {token}")))?;
        match inner {
            "@method" => Ok(Self::Method),
            "@authority" => Ok(Self::Authority),
            "@path" => Ok(Self::Path),
            "@query" => Ok(Self::Query),
            "@request-target" => Ok(Self::RequestTarget),
            "@status" => Ok(Self::Status),
            name if name.starts_with('@') => {
                Err(HttpSigError::UnsupportedComponent(inner.to_owned()))
            }
            // RFC 9421 Section 2.1: header component identifiers are lowercase.
            name => Ok(Self::Header(name.to_ascii_lowercase())),
        }
    }
}

/// A minimal HTTP request, sufficient to derive RFC 9421 component values.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// The request method, used as-is (case sensitive).
    pub method: String,
    /// The authority (`host[:port]`). It is lowercased for `@authority`, but the
    /// default port is not stripped (the scheme is not modeled), so the caller
    /// must remove a default port (`:80`/`:443`) itself to interoperate.
    pub authority: String,
    /// The absolute path; an empty path derives as `/`.
    pub path: String,
    /// The query string without the leading `?`, if any.
    pub query: Option<String>,
    /// Header fields as `(name, value)` pairs; names may be any case.
    pub headers: Vec<(String, String)>,
}

impl HttpRequest {
    /// The derived value of `component` for this request.
    ///
    /// # Errors
    ///
    /// Returns [`HttpSigError::MissingComponent`] if a header component is not
    /// present in the request.
    pub fn component_value(&self, component: &Component) -> Result<String, HttpSigError> {
        match component {
            Component::Method => Ok(self.method.clone()),
            Component::Authority => Ok(self.authority.to_ascii_lowercase()),
            Component::Path => Ok(if self.path.is_empty() {
                "/".to_owned()
            } else {
                self.path.clone()
            }),
            Component::Query => Ok(format!("?{}", self.query.as_deref().unwrap_or(""))),
            Component::RequestTarget => Ok(self.request_target()),
            Component::Header(name) => self.header_value(name),
            // A request has no status, and nothing for `;req` to refer back to.
            Component::Status | Component::Req(_) => {
                Err(HttpSigError::UnsupportedComponent(component.quoted_id()))
            }
        }
    }

    /// The origin-form request target: the absolute path, with `?` and the query
    /// appended only when a query component is present.
    ///
    /// Unlike `@query` — which derives as a bare `?` when there is no query —
    /// `@request-target` omits the delimiter entirely, so `/foo` and `/foo?`
    /// stay distinguishable.
    fn request_target(&self) -> String {
        let path = if self.path.is_empty() {
            "/"
        } else {
            &self.path
        };
        match &self.query {
            Some(query) => format!("{path}?{query}"),
            None => path.to_owned(),
        }
    }

    /// The RFC 9421 field value for header `name`.
    fn header_value(&self, name: &str) -> Result<String, HttpSigError> {
        header_value(&self.headers, name)
    }
}

/// A minimal HTTP response, sufficient to derive RFC 9421 component values.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// The status code, derived as `@status`.
    pub status: u16,
    /// Header fields as `(name, value)` pairs; names may be any case.
    pub headers: Vec<(String, String)>,
}

/// A response together with the request it answers.
///
/// Both are needed to sign or verify a response: `;req` components are taken
/// from the request, which is what stops a signed response being lifted onto a
/// different one.
#[derive(Debug, Clone, Copy)]
pub struct HttpExchange<'a> {
    /// The response being signed or verified.
    pub response: &'a HttpResponse,
    /// The request it answers.
    pub request: &'a HttpRequest,
}

/// Something a signature base can read covered component values from.
///
/// Requests and response exchanges resolve components differently, but the
/// signature base is built by one piece of code over this trait rather than
/// duplicated per message kind — the base is byte-exact, and two
/// implementations of it would eventually disagree.
pub trait ComponentSource {
    /// The derived value of `component` for this message.
    ///
    /// # Errors
    ///
    /// Returns [`HttpSigError::MissingComponent`] if a covered header is absent,
    /// or [`HttpSigError::UnsupportedComponent`] if the component cannot be
    /// derived from this kind of message.
    fn component_value(&self, component: &Component) -> Result<String, HttpSigError>;
}

impl ComponentSource for HttpRequest {
    fn component_value(&self, component: &Component) -> Result<String, HttpSigError> {
        HttpRequest::component_value(self, component)
    }
}

impl ComponentSource for HttpExchange<'_> {
    fn component_value(&self, component: &Component) -> Result<String, HttpSigError> {
        match component {
            Component::Status => Ok(self.response.status.to_string()),
            Component::Req(inner) => self.request.component_value(inner),
            Component::Header(name) => header_value(&self.response.headers, name),
            // The rest are request-only, and on a response must be written `;req`.
            other => Err(HttpSigError::UnsupportedComponent(other.quoted_id())),
        }
    }
}

/// The RFC 9421 field value for header `name`: every matching field, each
/// trimmed of leading and trailing whitespace, joined with `, `.
fn header_value(headers: &[(String, String)], name: &str) -> Result<String, HttpSigError> {
    let mut values = headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
        .peekable();
    if values.peek().is_none() {
        return Err(HttpSigError::MissingComponent(name.to_owned()));
    }
    Ok(values.collect::<Vec<_>>().join(", "))
}

/// Computes a `Content-Digest` field value over `body` using SHA-256, in the
/// RFC 9530 dictionary form `sha-256=:<base64>:`.
#[must_use]
pub fn content_digest_sha256(body: &[u8]) -> String {
    format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(body)))
}

/// Checks a `Content-Digest` header value against `body` for the SHA-256 form.
///
/// Covering the `content-digest` header in a signature only integrity-protects
/// the header *string*. To bind the actual body, the receiver MUST also call
/// this (and MUST have covered `content-digest` in the signature). Returns
/// `true` only if `header_value` exactly equals the recomputed
/// `sha-256=:<base64>:` digest of `body`; other digest algorithms or multi-member
/// values are not recognized and return `false`.
#[must_use]
pub fn verify_content_digest(header_value: &str, body: &[u8]) -> bool {
    header_value == content_digest_sha256(body)
}

#[cfg(test)]
mod tests {
    use super::{content_digest_sha256, verify_content_digest, Component, HttpRequest};

    #[test]
    fn parses_header_identifiers_case_insensitively() {
        // RFC 9421 identifiers are lowercase; a mixed-case one normalizes so it
        // matches a component built with `Component::header`.
        let parsed = Component::from_quoted_id("\"Content-Type\"").unwrap();
        assert_eq!(parsed, Component::header("content-type"));
    }

    #[test]
    fn joins_repeated_headers_and_trims() {
        let request = HttpRequest {
            method: "GET".to_owned(),
            authority: "EXAMPLE.com".to_owned(),
            path: String::new(),
            query: None,
            headers: vec![
                ("Accept".to_owned(), "  text/plain ".to_owned()),
                ("accept".to_owned(), "application/json".to_owned()),
            ],
        };
        assert_eq!(
            request
                .component_value(&Component::header("accept"))
                .unwrap(),
            "text/plain, application/json"
        );
        // `@authority` is lowercased; an empty `@path` becomes `/`.
        assert_eq!(
            request.component_value(&Component::Authority).unwrap(),
            "example.com"
        );
        assert_eq!(request.component_value(&Component::Path).unwrap(), "/");
    }

    // `@request-target` is origin-form: path plus `?query` only when a query is
    // actually present, unlike `@query`, which always emits the `?`.
    #[test]
    fn derives_the_request_target() {
        let mut request = HttpRequest {
            method: "POST".to_owned(),
            authority: "example.com".to_owned(),
            path: "/foo".to_owned(),
            query: Some("param=Value&Pet=dog".to_owned()),
            headers: vec![],
        };
        assert_eq!(
            request.component_value(&Component::RequestTarget).unwrap(),
            "/foo?param=Value&Pet=dog"
        );

        request.query = None;
        assert_eq!(
            request.component_value(&Component::RequestTarget).unwrap(),
            "/foo"
        );

        request.path = String::new();
        assert_eq!(
            request.component_value(&Component::RequestTarget).unwrap(),
            "/"
        );

        // An empty-but-present query keeps its delimiter.
        request.query = Some(String::new());
        assert_eq!(
            request.component_value(&Component::RequestTarget).unwrap(),
            "/?"
        );
    }

    #[test]
    fn parses_the_request_target_identifier() {
        assert_eq!(
            Component::from_quoted_id("\"@request-target\"").unwrap(),
            Component::RequestTarget
        );
        assert_eq!(Component::RequestTarget.quoted_id(), "\"@request-target\"");
    }

    #[test]
    fn content_digest_round_trips() {
        let body = b"payload";
        assert!(verify_content_digest(&content_digest_sha256(body), body));
    }

    #[test]
    fn header_components_compare_case_insensitively() {
        assert_eq!(
            Component::Header("Content-Type".to_owned()),
            Component::header("content-type")
        );
        assert_ne!(Component::header("a"), Component::header("b"));
    }
}

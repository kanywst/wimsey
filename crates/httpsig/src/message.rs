//! A minimal HTTP request model and the covered-component values derived from
//! it, per RFC 9421 Section 2.

use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};

use crate::error::HttpSigError;

/// A covered component of an HTTP message signature.
///
/// This crate supports the derived components `@method`, `@authority`, `@path`
/// and `@query`, plus plain header fields. `@target-uri` and component
/// parameters (for example `;sf` or `;key`) are not modeled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Component {
    /// The request method (`@method`).
    Method,
    /// The request authority (`@authority`), lowercased.
    Authority,
    /// The absolute path (`@path`).
    Path,
    /// The query string including the leading `?` (`@query`).
    Query,
    /// A header field, identified by its lowercase name.
    Header(String),
}

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
        let inner = token
            .strip_prefix('"')
            .and_then(|t| t.strip_suffix('"'))
            .ok_or_else(|| HttpSigError::Parse(format!("not a quoted identifier: {token}")))?;
        match inner {
            "@method" => Ok(Self::Method),
            "@authority" => Ok(Self::Authority),
            "@path" => Ok(Self::Path),
            "@query" => Ok(Self::Query),
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
            Component::Header(name) => self.header_value(name),
        }
    }

    /// The RFC 9421 field value for header `name`: every matching field, each
    /// trimmed of leading and trailing whitespace, joined with `, `.
    fn header_value(&self, name: &str) -> Result<String, HttpSigError> {
        let mut values = self
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim())
            .peekable();
        if values.peek().is_none() {
            return Err(HttpSigError::MissingComponent(name.to_owned()));
        }
        Ok(values.collect::<Vec<_>>().join(", "))
    }
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

    #[test]
    fn content_digest_round_trips() {
        let body = b"payload";
        assert!(verify_content_digest(&content_digest_sha256(body), body));
    }
}

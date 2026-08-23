//! `wimsey-identifier` — the WIMSE Workload Identifier URI.
//!
//! Target spec: `draft-ietf-wimse-identifier-03`.
//!
//! A workload identifier is an absolute URI whose authority component names the
//! trust domain the identifier is scoped to. The draft deliberately does *not*
//! fix a single scheme (Section 4.1): it defines the generic requirements every
//! identifier must satisfy, and lets each scheme add its own. This crate
//! supports the two schemes the draft names:
//!
//! - **`spiffe`** — defined by the SPIFFE ID specification, which constrains the
//!   trust domain to `[a-z0-9._-]` and each path segment to `[A-Za-z0-9._-]`.
//! - **`wimse`** — defined in Section 4.4 of the draft (and registered with IANA
//!   in Section 8.1). Its path is explicitly deployment-specific and
//!   uninterpreted, so segments accept the generic RFC 3986 `pchar` set.
//!
//! Both schemes are held to the generic requirements of Section 4.1: a
//! non-empty authority, no query, fragment, user-information or port component,
//! and a total length of at most [`MAX_ID_LEN`] bytes.
//!
//! # Normalization is rejected, not performed
//!
//! Section 4.3 requires consumers to "compare and authorize Workload
//! Identifiers using the complete URI". Comparing whole URIs is only sound if
//! each identifier has exactly one spelling, so this crate rejects the forms
//! that would otherwise need normalizing before comparison — an uppercase trust
//! domain, an empty path segment, and a `.` or `..` segment — rather than
//! silently rewriting them. Parsing therefore fails closed on any input that
//! could compare unequal to a semantically identical peer.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The maximum length, in bytes, of a workload identifier.
///
/// Section 4.1 of the draft requires implementations to support identifiers of
/// at least 2048 bytes and recommends that identifiers not exceed it.
pub const MAX_ID_LEN: usize = 2048;

/// The maximum length, in bytes, of a `spiffe` trust domain.
///
/// This bound comes from the SPIFFE ID specification and applies only to the
/// `spiffe` scheme; a `wimse` trust domain is bounded only by [`MAX_ID_LEN`].
pub const MAX_TRUST_DOMAIN_LEN: usize = 255;

/// A URI scheme a workload identifier may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Scheme {
    /// The `spiffe` scheme, as defined by the SPIFFE ID specification.
    Spiffe,
    /// The `wimse` scheme, as defined in Section 4.4 of
    /// `draft-ietf-wimse-identifier`.
    Wimse,
}

impl Scheme {
    /// Returns the scheme name, without the `://` delimiter.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Spiffe => "spiffe",
            Self::Wimse => "wimse",
        }
    }

    /// Returns the scheme prefix, including the `://` delimiter.
    const fn prefix(self) -> &'static str {
        match self {
            Self::Spiffe => "spiffe://",
            Self::Wimse => "wimse://",
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An error returned when parsing a [`WorkloadIdentifier`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// The identifier is longer than [`MAX_ID_LEN`] bytes.
    #[error("identifier exceeds {MAX_ID_LEN} bytes")]
    TooLong,
    /// The identifier does not use a supported scheme.
    #[error("identifier must start with `spiffe://` or `wimse://`")]
    UnsupportedScheme,
    /// The identifier carries a query component, which is forbidden.
    #[error("identifier must not contain a query component")]
    HasQuery,
    /// The identifier carries a fragment component, which is forbidden.
    #[error("identifier must not contain a fragment component")]
    HasFragment,
    /// The authority carries user information, which is forbidden.
    #[error("identifier must not contain user information")]
    HasUserInfo,
    /// The authority carries a port, which is forbidden.
    #[error("identifier must not contain a port component")]
    HasPort,
    /// The trust domain is empty.
    #[error("trust domain is empty")]
    EmptyTrustDomain,
    /// The trust domain is longer than [`MAX_TRUST_DOMAIN_LEN`] bytes.
    #[error("trust domain exceeds {MAX_TRUST_DOMAIN_LEN} bytes")]
    TrustDomainTooLong,
    /// The trust domain contains a character the scheme does not allow.
    #[error("trust domain contains an invalid character: {0:?}")]
    InvalidTrustDomainChar(char),
    /// A path segment is empty (for example a `//` or a trailing `/`).
    #[error("path contains an empty segment or a trailing slash")]
    EmptyPathSegment,
    /// A path segment is `.` or `..`, which are not allowed.
    #[error("path contains a `.` or `..` segment")]
    DotSegment,
    /// A path segment contains a character the scheme does not allow.
    #[error("path contains an invalid character: {0:?}")]
    InvalidPathChar(char),
    /// A percent-escape in the path is not `%` followed by two hex digits.
    #[error("path contains a malformed percent-escape")]
    BadPercentEncoding,
}

/// A validated WIMSE workload identifier.
///
/// Construct one with [`WorkloadIdentifier::parse`] or [`str::parse`]. The value
/// is guaranteed to be a well-formed `spiffe://` or `wimse://` identifier that
/// satisfies the generic requirements of Section 4.1 of the draft.
///
/// ```
/// use wimsey_identifier::{Scheme, WorkloadIdentifier};
///
/// let id: WorkloadIdentifier = "wimse://trust.example.com/service/payment".parse()?;
/// assert_eq!(id.scheme(), Scheme::Wimse);
/// assert_eq!(id.trust_domain(), "trust.example.com");
/// assert_eq!(id.path(), "/service/payment");
/// assert_eq!(id.origin(), "wimse://trust.example.com");
/// # Ok::<(), wimsey_identifier::ParseError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WorkloadIdentifier {
    uri: String,
    scheme: Scheme,
    /// Byte length of the trust domain, used to slice `uri`.
    trust_domain_len: usize,
}

impl WorkloadIdentifier {
    /// Parses and validates a workload identifier.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] if `input` is not a well-formed `spiffe://` or
    /// `wimse://` workload identifier.
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        if input.len() > MAX_ID_LEN {
            return Err(ParseError::TooLong);
        }

        let (scheme, rest) = [Scheme::Spiffe, Scheme::Wimse]
            .into_iter()
            .find_map(|s| input.strip_prefix(s.prefix()).map(|rest| (s, rest)))
            .ok_or(ParseError::UnsupportedScheme)?;

        // Section 4.1: no query and no fragment. Neither delimiter may appear
        // anywhere after the scheme; a percent-escaped `%3F` or `%23` is data,
        // not a delimiter, and is left to the per-scheme path check.
        if rest.contains('?') {
            return Err(ParseError::HasQuery);
        }
        if rest.contains('#') {
            return Err(ParseError::HasFragment);
        }

        let (trust_domain, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, ""),
        };

        // Section 4.1: no user information and no port. Both live in the
        // authority, so they are checked before the scheme's charset, which
        // would otherwise report a less specific error.
        if trust_domain.contains('@') {
            return Err(ParseError::HasUserInfo);
        }
        if trust_domain.contains(':') {
            return Err(ParseError::HasPort);
        }

        validate_trust_domain(scheme, trust_domain)?;
        validate_path(scheme, path)?;

        Ok(Self {
            uri: input.to_owned(),
            scheme,
            trust_domain_len: trust_domain.len(),
        })
    }

    /// Returns the full identifier, including the scheme.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.uri
    }

    /// Returns the scheme this identifier uses.
    #[must_use]
    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// Returns the trust domain (the authority component).
    #[must_use]
    pub fn trust_domain(&self) -> &str {
        let start = self.scheme.prefix().len();
        &self.uri[start..start + self.trust_domain_len]
    }

    /// Returns the path, including the leading `/`, or `""` when there is none.
    #[must_use]
    pub fn path(&self) -> &str {
        let start = self.scheme.prefix().len() + self.trust_domain_len;
        &self.uri[start..]
    }

    /// Returns the identifier's *origin* — the scheme and trust domain with the
    /// path omitted, as defined in Section 4.6 of the draft.
    #[must_use]
    pub fn origin(&self) -> &str {
        let end = self.scheme.prefix().len() + self.trust_domain_len;
        &self.uri[..end]
    }
}

fn validate_trust_domain(scheme: Scheme, td: &str) -> Result<(), ParseError> {
    if td.is_empty() {
        return Err(ParseError::EmptyTrustDomain);
    }
    // The 255-byte bound is a SPIFFE ID rule; a `wimse` trust domain is bounded
    // only by the identifier's overall length.
    if scheme == Scheme::Spiffe && td.len() > MAX_TRUST_DOMAIN_LEN {
        return Err(ParseError::TrustDomainTooLong);
    }
    // Both schemes take a lowercase host-shaped trust domain. RFC 3986 treats
    // the authority as case-insensitive, so accepting mixed case would let two
    // spellings of one identifier compare unequal; reject instead.
    for c in td.chars() {
        if !matches!(c, 'a'..='z' | '0'..='9' | '.' | '-' | '_') {
            return Err(ParseError::InvalidTrustDomainChar(c));
        }
    }
    Ok(())
}

fn validate_path(scheme: Scheme, path: &str) -> Result<(), ParseError> {
    if path.is_empty() {
        return Ok(());
    }
    // A non-empty path must begin with `/` and split into non-empty segments.
    for segment in path.split('/').skip(1) {
        if segment.is_empty() {
            return Err(ParseError::EmptyPathSegment);
        }
        // `.` and `..` are removed by RFC 3986 Section 6 normalization, so two
        // identifiers differing only by a dot segment would denote the same
        // workload while comparing unequal byte-for-byte.
        if segment == "." || segment == ".." {
            return Err(ParseError::DotSegment);
        }
        match scheme {
            Scheme::Spiffe => validate_spiffe_segment(segment)?,
            Scheme::Wimse => validate_pchar_segment(segment)?,
        }
    }
    Ok(())
}

/// The SPIFFE ID path charset: `[A-Za-z0-9._-]`.
fn validate_spiffe_segment(segment: &str) -> Result<(), ParseError> {
    for c in segment.chars() {
        if !matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '-' | '_') {
            return Err(ParseError::InvalidPathChar(c));
        }
    }
    Ok(())
}

/// The generic RFC 3986 `pchar` set, which Section 4.4 leaves the `wimse` path
/// to: `unreserved / pct-encoded / sub-delims / ":" / "@"`.
fn validate_pchar_segment(segment: &str) -> Result<(), ParseError> {
    let bytes = segment.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .ok_or(ParseError::BadPercentEncoding)?;
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return Err(ParseError::BadPercentEncoding);
            }
            i += 3;
            continue;
        }
        if !is_pchar_byte(b) {
            // `segment` is a `str`, so a non-ASCII byte here is the lead byte of
            // a multi-byte character; report the character, not the byte.
            let c = segment[i..]
                .chars()
                .next()
                .unwrap_or(char::REPLACEMENT_CHARACTER);
            return Err(ParseError::InvalidPathChar(c));
        }
        i += 1;
    }
    Ok(())
}

const fn is_pchar_byte(b: u8) -> bool {
    matches!(b,
        // unreserved
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
        // sub-delims
        | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
        // explicitly permitted in a path segment
        | b':' | b'@'
    )
}

impl fmt::Display for WorkloadIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.uri)
    }
}

impl FromStr for WorkloadIdentifier {
    type Err = ParseError;

    /// Parses a workload identifier.
    ///
    /// # Errors
    ///
    /// See [`WorkloadIdentifier::parse`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<String> for WorkloadIdentifier {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<WorkloadIdentifier> for String {
    fn from(value: WorkloadIdentifier) -> Self {
        value.uri
    }
}

impl Serialize for WorkloadIdentifier {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.uri)
    }
}

impl<'de> Deserialize<'de> for WorkloadIdentifier {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_simple_identifier() {
        let id = WorkloadIdentifier::parse("spiffe://example.org/workload/api").unwrap();
        assert_eq!(id.scheme(), Scheme::Spiffe);
        assert_eq!(id.trust_domain(), "example.org");
        assert_eq!(id.path(), "/workload/api");
        assert_eq!(id.as_str(), "spiffe://example.org/workload/api");
    }

    #[test]
    fn parses_a_wimse_scheme_identifier() {
        let id = WorkloadIdentifier::parse("wimse://trust.example.com/service/payment").unwrap();
        assert_eq!(id.scheme(), Scheme::Wimse);
        assert_eq!(id.trust_domain(), "trust.example.com");
        assert_eq!(id.path(), "/service/payment");
    }

    #[test]
    fn parses_a_trust_domain_only_identifier() {
        let id = WorkloadIdentifier::parse("spiffe://example.org").unwrap();
        assert_eq!(id.trust_domain(), "example.org");
        assert_eq!(id.path(), "");
    }

    #[test]
    fn reports_the_origin() {
        let id = WorkloadIdentifier::parse("wimse://trust.corp.example.com/workload/1").unwrap();
        assert_eq!(id.origin(), "wimse://trust.corp.example.com");

        let bare = WorkloadIdentifier::parse("spiffe://prod.trust.domain").unwrap();
        assert_eq!(bare.origin(), "spiffe://prod.trust.domain");
    }

    #[test]
    fn rejects_an_unsupported_scheme() {
        assert_eq!(
            WorkloadIdentifier::parse("https://example.org/x"),
            Err(ParseError::UnsupportedScheme)
        );
    }

    #[test]
    fn rejects_empty_trust_domain() {
        assert_eq!(
            WorkloadIdentifier::parse("spiffe:///path"),
            Err(ParseError::EmptyTrustDomain)
        );
        assert_eq!(
            WorkloadIdentifier::parse("wimse:///path"),
            Err(ParseError::EmptyTrustDomain)
        );
    }

    #[test]
    fn rejects_uppercase_trust_domain() {
        assert_eq!(
            WorkloadIdentifier::parse("spiffe://Example.org/x"),
            Err(ParseError::InvalidTrustDomainChar('E'))
        );
    }

    // Section 4.1: a Workload Identifier URI MUST NOT contain a query, a
    // fragment, user information, or a port.
    #[test]
    fn rejects_a_query_component() {
        assert_eq!(
            WorkloadIdentifier::parse("wimse://example.org/a?b=c"),
            Err(ParseError::HasQuery)
        );
        assert_eq!(
            WorkloadIdentifier::parse("spiffe://example.org?b=c"),
            Err(ParseError::HasQuery)
        );
    }

    #[test]
    fn rejects_a_fragment_component() {
        assert_eq!(
            WorkloadIdentifier::parse("wimse://example.org/a#frag"),
            Err(ParseError::HasFragment)
        );
        assert_eq!(
            WorkloadIdentifier::parse("spiffe://example.org#frag"),
            Err(ParseError::HasFragment)
        );
    }

    #[test]
    fn rejects_user_information() {
        assert_eq!(
            WorkloadIdentifier::parse("wimse://user@example.org/a"),
            Err(ParseError::HasUserInfo)
        );
    }

    #[test]
    fn rejects_a_port() {
        assert_eq!(
            WorkloadIdentifier::parse("wimse://example.org:8443/a"),
            Err(ParseError::HasPort)
        );
    }

    #[test]
    fn rejects_trailing_slash() {
        assert_eq!(
            WorkloadIdentifier::parse("spiffe://example.org/x/"),
            Err(ParseError::EmptyPathSegment)
        );
    }

    #[test]
    fn rejects_double_slash_in_path() {
        assert_eq!(
            WorkloadIdentifier::parse("spiffe://example.org/x//y"),
            Err(ParseError::EmptyPathSegment)
        );
    }

    #[test]
    fn rejects_dot_segment() {
        assert_eq!(
            WorkloadIdentifier::parse("spiffe://example.org/a/../b"),
            Err(ParseError::DotSegment)
        );
        assert_eq!(
            WorkloadIdentifier::parse("wimse://example.org/a/./b"),
            Err(ParseError::DotSegment)
        );
    }

    #[test]
    fn rejects_invalid_path_char() {
        assert_eq!(
            WorkloadIdentifier::parse("spiffe://example.org/a b"),
            Err(ParseError::InvalidPathChar(' '))
        );
        assert_eq!(
            WorkloadIdentifier::parse("wimse://example.org/a b"),
            Err(ParseError::InvalidPathChar(' '))
        );
    }

    // Section 4.4 leaves the `wimse` path to the generic RFC 3986 `pchar` set,
    // which is wider than the SPIFFE ID charset.
    #[test]
    fn wimse_path_accepts_the_generic_pchar_set() {
        let id =
            WorkloadIdentifier::parse("wimse://example.org/a~b!c$d&e'f(g)h*i+j,k;l=m:n@o").unwrap();
        assert_eq!(id.path(), "/a~b!c$d&e'f(g)h*i+j,k;l=m:n@o");
    }

    #[test]
    fn spiffe_path_rejects_what_the_wimse_path_allows() {
        assert_eq!(
            WorkloadIdentifier::parse("spiffe://example.org/a~b"),
            Err(ParseError::InvalidPathChar('~'))
        );
    }

    #[test]
    fn wimse_path_accepts_percent_encoding() {
        let id = WorkloadIdentifier::parse("wimse://example.org/a%2Fb").unwrap();
        assert_eq!(id.path(), "/a%2Fb");
    }

    #[test]
    fn rejects_malformed_percent_encoding() {
        assert_eq!(
            WorkloadIdentifier::parse("wimse://example.org/a%zz"),
            Err(ParseError::BadPercentEncoding)
        );
        assert_eq!(
            WorkloadIdentifier::parse("wimse://example.org/a%4"),
            Err(ParseError::BadPercentEncoding)
        );
    }

    #[test]
    fn rejects_non_ascii_in_a_path() {
        assert_eq!(
            WorkloadIdentifier::parse("wimse://example.org/aあb"),
            Err(ParseError::InvalidPathChar('あ'))
        );
    }

    // Section 4.1 requires support for identifiers of at least 2048 bytes.
    #[test]
    fn accepts_an_identifier_at_the_length_limit() {
        let prefix = "wimse://example.org/";
        let id = format!("{prefix}{}", "a".repeat(MAX_ID_LEN - prefix.len()));
        assert_eq!(id.len(), MAX_ID_LEN);
        assert!(WorkloadIdentifier::parse(&id).is_ok());
    }

    #[test]
    fn rejects_too_long_identifier() {
        let long = format!("spiffe://example.org/{}", "a".repeat(MAX_ID_LEN));
        assert_eq!(WorkloadIdentifier::parse(&long), Err(ParseError::TooLong));
    }

    #[test]
    fn round_trips_through_json() {
        let id = WorkloadIdentifier::parse("spiffe://example.org/workload/api").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"spiffe://example.org/workload/api\"");
        let back: WorkloadIdentifier = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn rejects_invalid_identifier_during_deserialization() {
        let err = serde_json::from_str::<WorkloadIdentifier>("\"https://nope\"");
        assert!(err.is_err());
    }
}

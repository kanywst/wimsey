//! `wimsey-identifier` — the WIMSE Workload Identifier URI scheme.
//!
//! Target spec: `draft-ietf-wimse-identifier-02`. The architecture draft cites
//! the SPIFFE ID (`spiffe://<trust-domain>/<path>`) as a conforming workload
//! identifier, so this crate parses and validates SPIFFE-ID-compatible
//! identifiers.
//!
//! Validation follows the SPIFFE ID constraints: a `spiffe` scheme, a non-empty
//! trust domain of at most 255 bytes drawn from `[a-z0-9._-]`, and a path of
//! `/`-separated non-empty segments drawn from `[A-Za-z0-9._-]` with no `.` or
//! `..` segments and no trailing slash. The whole identifier is at most 2048
//! bytes.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The maximum length, in bytes, of a workload identifier.
pub const MAX_ID_LEN: usize = 2048;

/// The maximum length, in bytes, of a trust domain.
pub const MAX_TRUST_DOMAIN_LEN: usize = 255;

const SCHEME: &str = "spiffe://";

/// An error returned when parsing a [`WorkloadIdentifier`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// The identifier is longer than [`MAX_ID_LEN`] bytes.
    #[error("identifier exceeds {MAX_ID_LEN} bytes")]
    TooLong,
    /// The identifier does not start with the `spiffe://` scheme.
    #[error("identifier must start with `spiffe://`")]
    MissingScheme,
    /// The trust domain is empty.
    #[error("trust domain is empty")]
    EmptyTrustDomain,
    /// The trust domain is longer than [`MAX_TRUST_DOMAIN_LEN`] bytes.
    #[error("trust domain exceeds {MAX_TRUST_DOMAIN_LEN} bytes")]
    TrustDomainTooLong,
    /// The trust domain contains a character outside `[a-z0-9._-]`.
    #[error("trust domain contains an invalid character: {0:?}")]
    InvalidTrustDomainChar(char),
    /// A path segment is empty (for example a `//` or a trailing `/`).
    #[error("path contains an empty segment or a trailing slash")]
    EmptyPathSegment,
    /// A path segment is `.` or `..`, which are not allowed.
    #[error("path contains a `.` or `..` segment")]
    DotSegment,
    /// A path segment contains a character outside `[A-Za-z0-9._-]`.
    #[error("path contains an invalid character: {0:?}")]
    InvalidPathChar(char),
}

/// A validated WIMSE workload identifier (SPIFFE-ID compatible).
///
/// Construct one with [`WorkloadIdentifier::parse`] or [`str::parse`]. The value
/// is guaranteed to be a well-formed `spiffe://` identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WorkloadIdentifier {
    uri: String,
    /// Byte length of the trust domain, used to slice `uri`.
    trust_domain_len: usize,
}

impl WorkloadIdentifier {
    /// Parses and validates a workload identifier.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] if `input` is not a well-formed,
    /// SPIFFE-ID-compatible `spiffe://` identifier.
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        if input.len() > MAX_ID_LEN {
            return Err(ParseError::TooLong);
        }
        let rest = input
            .strip_prefix(SCHEME)
            .ok_or(ParseError::MissingScheme)?;

        let (trust_domain, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, ""),
        };

        validate_trust_domain(trust_domain)?;
        validate_path(path)?;

        Ok(Self {
            uri: input.to_owned(),
            trust_domain_len: trust_domain.len(),
        })
    }

    /// Returns the full identifier, including the `spiffe://` scheme.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.uri
    }

    /// Returns the trust domain (the authority component).
    #[must_use]
    pub fn trust_domain(&self) -> &str {
        let start = SCHEME.len();
        &self.uri[start..start + self.trust_domain_len]
    }

    /// Returns the path, including the leading `/`, or `""` when there is none.
    #[must_use]
    pub fn path(&self) -> &str {
        let start = SCHEME.len() + self.trust_domain_len;
        &self.uri[start..]
    }
}

fn validate_trust_domain(td: &str) -> Result<(), ParseError> {
    if td.is_empty() {
        return Err(ParseError::EmptyTrustDomain);
    }
    if td.len() > MAX_TRUST_DOMAIN_LEN {
        return Err(ParseError::TrustDomainTooLong);
    }
    for c in td.chars() {
        if !matches!(c, 'a'..='z' | '0'..='9' | '.' | '-' | '_') {
            return Err(ParseError::InvalidTrustDomainChar(c));
        }
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), ParseError> {
    if path.is_empty() {
        return Ok(());
    }
    // A non-empty path must begin with `/` and split into non-empty segments.
    for segment in path.split('/').skip(1) {
        if segment.is_empty() {
            return Err(ParseError::EmptyPathSegment);
        }
        if segment == "." || segment == ".." {
            return Err(ParseError::DotSegment);
        }
        for c in segment.chars() {
            if !matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '-' | '_') {
                return Err(ParseError::InvalidPathChar(c));
            }
        }
    }
    Ok(())
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
        assert_eq!(id.trust_domain(), "example.org");
        assert_eq!(id.path(), "/workload/api");
        assert_eq!(id.as_str(), "spiffe://example.org/workload/api");
    }

    #[test]
    fn parses_a_trust_domain_only_identifier() {
        let id = WorkloadIdentifier::parse("spiffe://example.org").unwrap();
        assert_eq!(id.trust_domain(), "example.org");
        assert_eq!(id.path(), "");
    }

    #[test]
    fn rejects_missing_scheme() {
        assert_eq!(
            WorkloadIdentifier::parse("https://example.org/x"),
            Err(ParseError::MissingScheme)
        );
    }

    #[test]
    fn rejects_empty_trust_domain() {
        assert_eq!(
            WorkloadIdentifier::parse("spiffe:///path"),
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
    }

    #[test]
    fn rejects_invalid_path_char() {
        assert_eq!(
            WorkloadIdentifier::parse("spiffe://example.org/a b"),
            Err(ParseError::InvalidPathChar(' '))
        );
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

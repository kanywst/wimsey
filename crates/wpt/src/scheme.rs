//! The `WPT` HTTP authentication scheme: how a proof travels in a request and
//! how a recipient asks for one.
//!
//! Draft -02 (§2) carries the WPT in the request's `Authorization` field using
//! a scheme of its own, with the proof as the `token68` credentials:
//!
//! ```text
//! credentials = "WPT" 1*SP token68
//! ```
//!
//! A compact JWS is a valid `token68`, so the credentials are the proof
//! verbatim. The scheme name is case-insensitive (RFC 9110 §11.1); the
//! credentials are not. A recipient that rejects a request because of the WPT
//! answers `401` with a `WWW-Authenticate: WPT` challenge (§2.1), for which
//! the draft defines no parameters.
//!
//! This module is the field-value syntax only. Reading the `Authorization`
//! fields out of a request, sending the `401`, and attaching the challenge to
//! it are the HTTP stack's job.

use crate::error::WptError;

/// The authentication scheme name the draft registers (§4.3).
///
/// Compared case-insensitively when parsing, since RFC 9110 §11.1 makes every
/// scheme name so; emitted in this spelling.
pub const SCHEME: &str = "WPT";

/// The `WWW-Authenticate` field value a recipient that accepts WPTs sends with
/// a `401` (§2.1).
///
/// The draft defines no authentication parameters for the challenge, so it is
/// the bare scheme name.
pub const CHALLENGE: &str = "WPT";

/// The longest `auth-scheme` [`from_credentials`] will name in a
/// [`WptError::WrongScheme`]; anything longer is reported as malformed
/// without being echoed. Every registered scheme is far shorter.
const MAX_SCHEME_LEN: usize = 32;

/// Formats a proof as the `Authorization` field value that carries it:
/// `WPT <proof>`.
///
/// The proof is expected to be a compact JWS from [`issue`](crate::issue),
/// which is a valid `token68` by construction; this function does not check
/// it, and a value that is not would be refused by [`from_credentials`] on the
/// receiving side.
#[must_use]
pub fn to_credentials(proof: &str) -> String {
    format!("{SCHEME} {proof}")
}

/// Extracts the proof from an `Authorization` field value.
///
/// Accepts exactly `WPT 1*SP token68`, with the scheme name in any case.
/// Leading and trailing whitespace around the field value is ignored, since an
/// HTTP field value never includes it (RFC 9110 §5.5) and a parser that keeps
/// it is not a reason to refuse the proof.
///
/// # Errors
///
/// - [`WptError::WrongScheme`] when the credentials use another scheme, such
///   as `Bearer`. The draft gives the WPT sole occupancy of the field (§2.2),
///   so a bearer token where the proof should be is a rejection, not a
///   fallback. The scheme is named in the error only when it looks like one:
///   at most 32 bytes and followed by a space. A proof sent without its
///   scheme, or glued to it, is all `tchar` and would otherwise be copied
///   into the error's `Display`, which §3.1.5 asks implementations never to
///   log.
/// - [`WptError::MalformedCredentials`] when the field is empty, when the
///   scheme is `WPT` but what follows is not `1*SP` and a single `token68`
///   (nothing at all, an `auth-param` list, a tab instead of a space, or a
///   character outside the `token68` alphabet), or when the scheme is neither
///   `WPT` nor shaped like a scheme name.
///
/// The returned proof has been checked against the `token68` grammar only.
/// Hand it to [`verify`](crate::verify), which checks it is a WPT.
pub fn from_credentials(field_value: &str) -> Result<&str, WptError> {
    let value = field_value.trim_matches([' ', '\t']);
    let scheme_len = value.bytes().take_while(|&b| is_tchar(b)).count();
    let (scheme, rest) = value.split_at(scheme_len);
    if scheme.is_empty() {
        return Err(WptError::MalformedCredentials);
    }
    if !scheme.eq_ignore_ascii_case(SCHEME) {
        // Name the scheme only when it is shaped like one: short, and followed
        // by the SP that separates it from its credentials. A compact JWS is
        // all `tchar`, so a proof sent without its scheme, or glued to it,
        // would otherwise be copied whole into the error's `Display` (§3.1.5:
        // never log a raw WPT).
        if scheme.len() > MAX_SCHEME_LEN || !rest.starts_with(' ') {
            return Err(WptError::MalformedCredentials);
        }
        return Err(WptError::WrongScheme {
            found: scheme.to_owned(),
        });
    }
    // `1*SP`: a space, not any whitespace.
    let proof = rest.trim_start_matches(' ');
    if proof.len() < rest.len() && is_token68(proof) {
        Ok(proof)
    } else {
        Err(WptError::MalformedCredentials)
    }
}

/// Extracts the proof from a request's `Authorization` field values.
///
/// Draft §2 requires that there is exactly one `Authorization` field in the
/// request and that it uses the `WPT` scheme, so `fields` must yield every
/// `Authorization` field value the request carries, in any order. A field
/// whose value is not valid UTF-8 must still be yielded (as `""`, say), not
/// skipped: dropping it would let a second field slip past the count.
///
/// # Errors
///
/// - [`WptError::MissingCredentials`] when the request has no `Authorization`
///   field. The recipient answers with the [`CHALLENGE`].
/// - [`WptError::MultipleAuthorizationFields`] when it has more than one. The
///   field holds a single set of credentials, not a list (RFC 9110 §11.6.2),
///   so two fields is a malformed request regardless of what they carry.
/// - Whatever [`from_credentials`] returns for the one field.
pub fn from_request<'a, I>(fields: I) -> Result<&'a str, WptError>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut fields = fields.into_iter();
    let Some(first) = fields.next() else {
        return Err(WptError::MissingCredentials);
    };
    if fields.next().is_some() {
        return Err(WptError::MultipleAuthorizationFields);
    }
    from_credentials(first)
}

/// RFC 9110 §5.6.2 `tchar`: what an `auth-scheme` is made of.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// RFC 9110 §11.2: `1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`.
fn is_token68(s: &str) -> bool {
    let body = s.trim_end_matches('=');
    !body.is_empty()
        && body.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
}

#[cfg(test)]
mod tests {
    use wimsey_jose::SigningKey;

    use super::{from_credentials, from_request, to_credentials, CHALLENGE, SCHEME};
    use crate::claims::WptClaims;
    use crate::error::WptError;
    use crate::token::{issue, verify, wit_thumbprint, Validation};

    const WIT: &str = "eyJ0eXAiOiJ3aXQrand0In0.payload.signature";
    const AUD: &str = "https://workload.example.com/path";

    fn sample_proof() -> (String, SigningKey) {
        let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
        let claims = WptClaims {
            aud: AUD.to_owned(),
            exp: 1_700_000_300,
            jti: "0123456789abcdef".to_owned(),
            wth: wit_thumbprint(WIT),
            tth: None,
            oth: None,
        };
        (issue(&claims, &key).unwrap(), key)
    }

    #[test]
    fn an_issued_proof_round_trips_through_the_field() {
        let (proof, key) = sample_proof();
        let field = to_credentials(&proof);
        assert_eq!(field, format!("WPT {proof}"));

        let carried = from_credentials(&field).unwrap();
        assert_eq!(carried, proof);

        let validation = Validation::new(1_700_000_000, AUD, WIT);
        verify(carried, &key.verifying_key(), &validation).unwrap();
    }

    #[test]
    fn the_scheme_name_is_case_insensitive() {
        for scheme in ["WPT", "wpt", "Wpt", "wPT"] {
            assert_eq!(
                from_credentials(&format!("{scheme} a.b.c")).unwrap(),
                "a.b.c"
            );
        }
    }

    #[test]
    fn accepts_more_than_one_space_and_surrounding_whitespace() {
        assert_eq!(from_credentials("WPT    a.b.c").unwrap(), "a.b.c");
        assert_eq!(from_credentials("  WPT a.b.c \t").unwrap(), "a.b.c");
    }

    #[test]
    fn accepts_the_whole_token68_alphabet() {
        let token = "AZaz09-._~+/==";
        assert_eq!(from_credentials(&format!("WPT {token}")).unwrap(), token);
    }

    #[test]
    fn refuses_another_scheme() {
        for field in [
            "Bearer a.b.c",
            "Basic YWxhZGRpbjpvcGVuc2VzYW1l",
            "WPTS a.b.c",
            "DPoP a.b.c",
        ] {
            let err = from_credentials(field).unwrap_err();
            assert!(
                matches!(err, WptError::WrongScheme { ref found } if field.starts_with(found.as_str())),
                "{field}: {err}"
            );
        }
    }

    #[test]
    fn does_not_echo_a_proof_sent_without_its_scheme() {
        let (proof, _) = sample_proof();
        let long_scheme = format!("{} a.b.c", "A".repeat(33));
        for field in [proof.clone(), format!("WPT{proof}"), long_scheme] {
            let err = from_credentials(&field).unwrap_err();
            assert!(matches!(err, WptError::MalformedCredentials), "{err}");
            assert!(!err.to_string().contains(&proof[..40]), "{err}");
        }
        // Right at the limit a scheme is still named.
        let err = from_credentials(&format!("{} a.b.c", "A".repeat(32))).unwrap_err();
        assert!(matches!(err, WptError::WrongScheme { ref found } if found.len() == 32));
    }

    #[test]
    fn refuses_the_scheme_without_credentials() {
        for field in ["WPT", "WPT ", "WPT   ", "", "  "] {
            let err = from_credentials(field).unwrap_err();
            assert!(
                matches!(err, WptError::MalformedCredentials),
                "{field:?}: {err}"
            );
        }
    }

    #[test]
    fn refuses_credentials_that_are_not_a_token68() {
        for field in [
            "WPT\ta.b.c",          // HTAB is not SP
            "WPT\t a.b.c",         // nor is it a prefix of `1*SP`
            "WPT/a.b.c",           // `/` ends the scheme without a SP
            "\u{e9}WPT a.b.c",     // no scheme at all
            "W\u{e9} a.b.c",       // the scheme ends where ASCII does, with no SP
            "Bearer",              // a scheme with no credentials and no SP
            "WPT a.b.c extra",     // two tokens
            "WPT a.b.c,WPT d.e.f", // a list where a single credentials belongs
            "WPT realm=\"x\"",     // auth-param instead of token68
            "WPT ==",              // padding with nothing to pad
            "WPT a=b",             // `=` only trails
            "WPT a.b.c\u{e9}",     // outside ASCII
            "WPT a b",             // internal SP
        ] {
            let err = from_credentials(field).unwrap_err();
            assert!(
                matches!(err, WptError::MalformedCredentials),
                "{field:?}: {err}"
            );
        }
    }

    #[test]
    fn a_request_needs_exactly_one_authorization_field() {
        let err = from_request([]).unwrap_err();
        assert!(matches!(err, WptError::MissingCredentials));

        let err = from_request(["WPT a.b.c", "WPT a.b.c"]).unwrap_err();
        assert!(matches!(err, WptError::MultipleAuthorizationFields));

        // Two fields are refused before either is read, so a bearer token next
        // to a proof does not get as far as the scheme check.
        let err = from_request(["WPT a.b.c", "Bearer t"]).unwrap_err();
        assert!(matches!(err, WptError::MultipleAuthorizationFields));

        // One field that is not a WPT propagates its own error.
        let err = from_request(["Bearer t"]).unwrap_err();
        assert!(matches!(err, WptError::WrongScheme { ref found } if found == "Bearer"));

        assert_eq!(from_request(["wpt a.b.c"]).unwrap(), "a.b.c");
    }

    #[test]
    fn the_challenge_is_the_bare_scheme() {
        assert_eq!(CHALLENGE, SCHEME);
        assert_eq!(CHALLENGE, "WPT");
    }
}

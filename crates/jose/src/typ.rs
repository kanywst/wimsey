//! Matching the JOSE `typ` header against a media type.

/// Whether a JOSE `typ` value conveys the media type `application/<subtype>`.
///
/// RFC 7515 Section 4.1.9: a recipient treats a `typ` that contains no `/` as
/// if `application/` were prepended, so `wit+jwt` and `application/wit+jwt`
/// name the same media type. Media type names are case-insensitive (RFC 2045
/// Section 5.1). Both WIMSE token drafts ask the recipient to check that `typ`
/// "conveys a media type of" their subtype, which is this comparison.
///
/// ```
/// use wimsey_jose::typ_conveys;
///
/// assert!(typ_conveys("wit+jwt", "wit+jwt"));
/// assert!(typ_conveys("Application/WIT+JWT", "wit+jwt"));
/// assert!(!typ_conveys("text/wit+jwt", "wit+jwt"));
/// assert!(!typ_conveys("jwt", "wit+jwt"));
/// ```
#[must_use]
pub fn typ_conveys(typ: &str, subtype: &str) -> bool {
    let found = match typ.split_once('/') {
        Some((kind, found)) if kind.eq_ignore_ascii_case("application") => found,
        Some(_) => return false,
        None => typ,
    };
    found.eq_ignore_ascii_case(subtype)
}

//! The claim set carried by a Workload Proof Token.

use serde::{Deserialize, Serialize};

/// The claims of a Workload Proof Token (`draft-ietf-wimse-wpt-01`).
///
/// `aud`, `exp`, `jti` and `wth` are mandatory. `ath` (the hash of an
/// accompanying OAuth access token) is included only when such a token is
/// present in the request. The field order is fixed so issued proofs are
/// byte-for-byte reproducible for a given key and input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WptClaims {
    /// The audience: the HTTP target URI of the request, without query or
    /// fragment.
    pub aud: String,
    /// Expiry time, in seconds since the Unix epoch. WPT lifetimes are short.
    pub exp: u64,
    /// A unique proof identifier, for replay detection by the recipient. The
    /// caller must supply at least 128 bits of entropy; this crate does not
    /// generate or validate it.
    pub jti: String,
    /// The Base64url-encoded SHA-256 hash of the ASCII WIT value this proof is
    /// bound to.
    pub wth: String,
    /// The Base64url-encoded SHA-256 hash of an accompanying OAuth access
    /// token, present only if such a token is in the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
}

//! The claim set carried by a Workload Proof Token.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The claims of a Workload Proof Token (`draft-ietf-wimse-wpt-02`).
///
/// `aud`, `exp`, `jti` and `wth` are mandatory. `tth` and `oth` bind tokens that
/// convey *end-user* identity or authorization context rather than the calling
/// workload's, and each is mandatory exactly when the corresponding token is in
/// the request (draft §2).
///
/// The field order is fixed and `oth` is a [`BTreeMap`], so the JSON
/// serialization is a function of the values alone and an issued proof is
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
    /// The Base64url-encoded SHA-256 hash of an accompanying Txn-Token
    /// (`draft-ietf-oauth-transaction-tokens`), present only if such a token is
    /// in the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tth: Option<String>,
    /// Hashes of any other tokens in the request that convey end-user identity
    /// or authorization context, keyed by the **lowercased** name of the header
    /// field carrying each one. Each value is the Base64url-encoded SHA-256 hash
    /// of the ASCII header field value with leading and trailing spaces removed.
    ///
    /// This claim names exactly the tokens the proof binds. A recipient MUST NOT
    /// make authorization decisions using a context token the claim does not
    /// cover.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oth: Option<BTreeMap<String, String>>,
}

//! The claim set carried by a Workload Identity Token.

use serde::{Deserialize, Serialize};
use wimsey_identifier::WorkloadIdentifier;

use wimsey_jose::Jwk;

/// The `cnf` (confirmation) claim binding a proof-of-possession key to the WIT.
///
/// Per `draft-ietf-wimse-workload-creds`, a WIT carries a confirmation key the
/// workload proves possession of when presenting the token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confirmation {
    /// The proof-of-possession public key.
    pub jwk: Jwk,
}

/// The registered claims of a Workload Identity Token.
///
/// Section 5.1 of `draft-ietf-wimse-workload-creds` makes only `sub`, `exp` and
/// `cnf` mandatory. `iss` is RECOMMENDED but optional, and `jti` is OPTIONAL
/// ("some token generation environments do not support it"); `iat` is not in the
/// required set either. The optional claims are modelled as `Option` and omitted
/// from the serialization when absent, so this crate neither invents claims an
/// issuer did not set nor rejects a spec-conforming token that omits them.
///
/// The field order is significant: it is the order these claims are serialized
/// in, which keeps issued tokens byte-for-byte reproducible for a given key and
/// input. The `cnf` claim is mandatory, so a token missing it fails to parse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitClaims {
    /// The issuer of the token. RECOMMENDED, and useful for auditing, but a
    /// conforming WIT may omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// The subject: the workload's identifier.
    pub sub: WorkloadIdentifier,
    /// Issued-at time, in seconds since the Unix epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    /// Expiry time, in seconds since the Unix epoch.
    pub exp: u64,
    /// A unique token identifier. OPTIONAL. Callers that need replay protection
    /// must track it themselves; verification does not maintain a replay store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// The confirmation (proof-of-possession) key.
    pub cnf: Confirmation,
}

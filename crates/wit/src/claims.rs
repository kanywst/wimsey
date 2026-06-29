//! The claim set carried by a Workload Identity Token.

use serde::{Deserialize, Serialize};
use wimsey_identifier::WorkloadIdentifier;

use crate::jwk::Jwk;

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
/// The field order is significant: it is the order these claims are serialized
/// in, which keeps issued tokens byte-for-byte reproducible for a given key and
/// input. The `cnf` claim is mandatory, so a token missing it fails to parse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitClaims {
    /// The issuer of the token.
    pub iss: String,
    /// The subject: the workload's identifier.
    pub sub: WorkloadIdentifier,
    /// Issued-at time, in seconds since the Unix epoch.
    pub iat: u64,
    /// Expiry time, in seconds since the Unix epoch.
    pub exp: u64,
    /// A unique token identifier. Callers that need replay protection must
    /// track it themselves; verification does not maintain a replay store.
    pub jti: String,
    /// The confirmation (proof-of-possession) key.
    pub cnf: Confirmation,
}

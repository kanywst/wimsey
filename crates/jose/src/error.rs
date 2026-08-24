//! Error type for JOSE key and signature handling.

/// JOSE `alg` values a WIMSE credential may never carry.
///
/// Section 5.1 of `draft-ietf-wimse-workload-creds` rules out three families for
/// a confirmation key: `none`, algorithms used with symmetric keys (a shared
/// secret cannot prove possession), and encryption algorithms (which would need
/// key distribution outside the token). They are listed so that one of them is
/// reported as a spec violation rather than as merely unimplemented.
const FORBIDDEN_ALGS: &[&str] = &[
    // The unsecured JWS algorithm.
    "none",
    // JWS algorithms used with symmetric keys (RFC 7518 Section 3.2).
    "HS256",
    "HS384",
    "HS512",
    // JWE key-management algorithms (RFC 7518 Section 4.1).
    "RSA1_5",
    "RSA-OAEP",
    "RSA-OAEP-256",
    "RSA-OAEP-384",
    "RSA-OAEP-512",
    "A128KW",
    "A192KW",
    "A256KW",
    "dir",
    "ECDH-ES",
    "ECDH-ES+A128KW",
    "ECDH-ES+A192KW",
    "ECDH-ES+A256KW",
    "A128GCMKW",
    "A192GCMKW",
    "A256GCMKW",
    "PBES2-HS256+A128KW",
    "PBES2-HS384+A192KW",
    "PBES2-HS512+A256KW",
];

pub(crate) fn is_forbidden_alg(alg: &str) -> bool {
    FORBIDDEN_ALGS.iter().any(|f| f.eq_ignore_ascii_case(alg))
}

/// An error from parsing a key, an algorithm, or a signature.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JoseError {
    /// The `alg` member was absent where the draft requires it.
    #[error("the key is missing the required `alg` member")]
    MissingAlg,
    /// The algorithm is one a proof of possession may never use.
    #[error("the algorithm `{found}` is forbidden for a proof of possession")]
    ForbiddenAlg {
        /// The `alg` value that was found.
        found: String,
    },
    /// The algorithm is legal but this crate cannot produce or verify it.
    #[error("unsupported algorithm `{found}`, expected `EdDSA` or `ES256`")]
    UnsupportedAlg {
        /// The `alg` value that was found.
        found: String,
    },
    /// The key type or curve does not match the algorithm, or the encoded key is
    /// not a valid point or scalar.
    #[error("invalid key")]
    InvalidKey,
    /// The signature did not verify, or was not the expected length.
    #[error("signature verification failed")]
    InvalidSignature,
    /// A Base64url component could not be decoded.
    #[error("invalid base64url")]
    InvalidEncoding,
}

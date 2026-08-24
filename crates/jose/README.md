# wimsey-jose

**The keys and signatures the WIMSE credential formats share.**

WIT, WPT and the HTTP-signature binding all need the same two things: a key that
can sign or verify, and a JWK to carry the public half in. This crate holds them
once, so the three cannot drift apart and so that adding an algorithm is one
change rather than three.

Two algorithms are supported. `EdDSA` over Ed25519 is what this workspace
prefers, and `ES256` is here because Section 5.1 of
`draft-ietf-wimse-workload-creds` requires it of general-purpose implementations
— it is also the practical interop baseline.

```rust
use wimsey_jose::{Algorithm, Jwk, SigningKey};

let key = SigningKey::from_p256_scalar(&[7u8; 32])?;
assert_eq!(key.algorithm(), Algorithm::Es256);

let jwk = Jwk::from_verifying_key(&key.verifying_key());
assert_eq!(jwk.to_verifying_key()?, key.verifying_key());
# Ok::<(), wimsey_jose::JoseError>(())
```

## Both algorithms are deterministic

Ed25519 is deterministic by construction. ECDSA normally is not — it draws a
random nonce — but the RFC 6979 derivation used here computes that nonce from the
key and the message instead. Signing the same input twice produces the same bytes
under either algorithm, which is what makes byte-exact conformance vectors
possible at all.

## `alg` decides, the key type follows

`Jwk::to_verifying_key` dispatches on the `alg` member and then requires `kty`
and `crv` to agree with it. Reading the key type first and treating `alg` as a
hint would let a token name one algorithm and be verified under another.

The three algorithm families a proof of possession may never use — `none`,
symmetric, and encryption — are rejected as spec violations, distinct from an
algorithm that is merely not implemented here.

Part of [`wimsey`](https://github.com/kanywst/wimsey), a vendor-neutral reference
implementation of the IETF
[WIMSE](https://datatracker.ietf.org/wg/wimse/about/) workload-identity drafts,
in Rust.

> **Pre-alpha.** The specs are Internet-Drafts, not RFCs.

Licensed under Apache-2.0.

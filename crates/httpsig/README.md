# wimsey-httpsig

**The WIMSE HTTP Message Signatures binding.**

An RFC 9421 HTTP Message Signatures implementation and the WIMSE profile of
it. The caller signs the outgoing request — including the header carrying its
WIT — with its proof-of-possession key, so an intermediary can read the request
but cannot alter anything the signature covers.

The RFC 9421 signature base is verified byte-for-byte against the worked example
in Section 2.5, and verification reuses the *received* parameter substring
verbatim rather than re-serializing it.

The WIMSE profile (Section 3 of the http-signature draft) narrows RFC 9421
considerably, and is enforced by opting in with `VerifyConfig::wimse_profile`:

- `@method` and `@request-target` must be covered, plus `Content-Type`,
  `Content-Digest`, `Authorization`, `Txn-Token` and `Workload-Identity-Token`
  whenever the message carries them;
- `created`, `expires`, `nonce` and `tag` are mandatory, with `tag` fixed to
  `wimse-workload-to-workload`;
- `wimse-aud` is mandatory on a request and names the service it is for;
- `keyid` and `alg` are forbidden — the key travels in the WIT, and its `cnf`
  JWK pins the algorithm.

Responses are signed the same way, with the profile's own rules: `@status` plus
`@method;req` and `@request-target;req`, and `wimse-req-nonce` carrying back the
nonce from the request being answered. Both bindings exist so that a signed
response cannot be lifted onto a different request.

With the profile off, the crate is a plain RFC 9421 implementation.

Part of [`wimsey`](https://github.com/kanywst/wimsey), a vendor-neutral reference
implementation of the IETF [WIMSE](https://datatracker.ietf.org/wg/wimse/about/)
workload-identity drafts, in Rust.

> **Pre-alpha.** The specs are Internet-Drafts, not RFCs. This crate pins one
> revision; see [`SPEC-MAP.md`](https://github.com/kanywst/wimsey/blob/main/SPEC-MAP.md)
> for the pin and for the requirements it does not yet meet.

All signing is EdDSA over Ed25519, which is deterministic, so output is
byte-for-byte reproducible. Time is injected rather than read from a clock, so
verification is reproducible too. Cross-implementation test vectors live in
[`conformance/`](https://github.com/kanywst/wimsey/tree/main/conformance).

Licensed under Apache-2.0.

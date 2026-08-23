# Spec map

`wimsey` targets the IETF WIMSE working group documents. The specs are
Internet-Drafts and revise frequently, so each crate **pins a specific draft
revision**. Bumping a pin is a deliberate, reviewed change.

## Pinned revisions

| Draft | Revision | Crate | Notes |
| --- | --- | --- | --- |
| `draft-ietf-wimse-arch` | -08 | — | Architecture; design guidance only |
| `draft-ietf-wimse-identifier` | -03 | `wimsey-identifier` | URI scheme; `spiffe` and `wimse` |
| `draft-ietf-wimse-workload-creds` | -02 | `wimsey-wit` | Defines WIT and WIC |
| `draft-ietf-wimse-wpt` | -01 | `wimsey-wpt` | Workload Proof Token (DPoP-style PoP) |
| `draft-ietf-wimse-http-signature` | -06 | `wimsey-httpsig` | Profile of RFC 9421 |
| `draft-ietf-wimse-mutual-tls` | -02 | `wimsey-mtls` | mTLS binding, client cert = WIC |
| `draft-ietf-wimse-workload-identity-practices` | -06 | — | Informational; with the IESG |

Every pin above is the current revision as of 2026-08-23.

## Known divergences

A reference implementation should be explicit about where it does not yet meet
the pinned drafts.

| Requirement | Draft | Status |
| --- | --- | --- |
| ES256 MUST be supported by general-purpose implementations | `workload-creds` §5.1 | Not implemented. This crate is Ed25519-only so signing stays deterministic and vectors stay byte-reproducible. An ES256 `cnf` is reported as unsupported, never silently accepted. |
| Response signing (`@status`, `;req`, `wimse-req-nonce`) | `http-signature` §3.4 | Parameters are parsed and carried; producing and verifying a response signature is not implemented. |
| Trust-domain match on the TLS peer certificate | `mutual-tls` §4 | Left to the caller: `wimsey-mtls::verify` returns the identifier and the caller compares it, since chain building and rustls wiring are out of scope. |

## Related specs

These are not WIMSE WG documents but are normatively referenced or closely
related.

| Spec | Relevance |
| --- | --- |
| RFC 9421 | HTTP Message Signatures, profiled by the httpsig binding |
| RFC 7519 | JWT, the basis for WIT and WPT |
| RFC 7515 / 7517 / 7518 | JOSE: JWS, JWK, JWA |
| X.509 (RFC 5280) | The basis for WIC |
| SPIFFE / SVID | WIC is compatible with X509-SVID; WIT-SVID is in progress |
| `draft-ietf-oauth-spiffe-client-auth` | Uses WIT-SVID for OAuth client auth |

## Bumping a pin

1. Read the diff between the current and target revision of the draft.
2. Update the affected crate(s) and their conformance vectors.
3. Update the revision in this file and in the crate's module docs.
4. Note the change in the changelog and the PR description.

# Spec map

`wimsey` targets the IETF WIMSE working group documents. The specs are
Internet-Drafts and revise frequently, so each crate **pins a specific draft
revision**. Bumping a pin is a deliberate, reviewed change.

## Pinned revisions

| Draft | Revision | Crate | Notes |
| --- | --- | --- | --- |
| `draft-ietf-wimse-arch` | -07 | — | Architecture; design guidance only |
| `draft-ietf-wimse-identifier` | -02 | `wimsey-identifier` | URI scheme, SPIFFE-ID compatible |
| `draft-ietf-wimse-workload-creds` | -01 | `wimsey-wit` | Defines WIT and WIC |
| `draft-ietf-wimse-wpt` | -01 | `wimsey-wpt` | Workload Proof Token (DPoP-style PoP) |
| `draft-ietf-wimse-http-signature` | -03 | `wimsey-httpsig` | Profile of RFC 9421 |
| `draft-ietf-wimse-mutual-tls` | -01 | `wimsey-mtls` | mTLS binding, client cert = WIC |

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

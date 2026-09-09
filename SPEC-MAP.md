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
| `draft-ietf-wimse-wpt` | -02 | `wimsey-wpt` | Workload Proof Token (DPoP-style PoP) |
| `draft-ietf-wimse-http-signature` | -06 | `wimsey-httpsig` | Profile of RFC 9421 |
| `draft-ietf-wimse-mutual-tls` | -02 | `wimsey-mtls` | mTLS binding, client cert = WIC |
| `draft-ietf-wimse-workload-identity-practices` | -06 | — | Informational; with the IESG |

Every pin above is the current *published* revision as of 2026-09-08.

## Drafts in progress upstream

A pin tracks what the datatracker has published, and the editors' repositories
run ahead of that. The revision a working copy is heading for is named by the
first entry of its Document History section.

| Draft | Published | Editors' copy | Bearing on this workspace |
| --- | --- | --- | --- |
| `identifier` | -03 | -03 | — |
| `workload-creds` | -02 | -03 | Adds a "Validating the WIT" procedure for recipients; `wimsey-wit` already satisfies every item except trust-anchor selection, which is a divergence below. |
| `wpt` | -02 | -03 | Moves the key-management section to `workload-creds`; no normative change for `wimsey-wpt`. |
| `http-signature` | -06 | -07 | Editorial, plus a reference to the `workload-creds` WIT validation procedure. |
| `mutual-tls` | -02 | -03 | Editorial (capitalization of defined terms). |

Checked 2026-09-08, and re-checked by `scripts/check-draft-revisions.sh`.

## Known divergences

A reference implementation should be explicit about where it does not yet meet
the pinned drafts.

| Requirement | Draft | Status |
| --- | --- | --- |
| Trust-domain match on the TLS peer certificate | `mutual-tls` §4 | Left to the caller: `wimsey-mtls::verify` returns the identifier and the caller compares it, since chain building and rustls wiring are out of scope. |
| Chain building, `basicConstraints`, `keyUsage`, name constraints | `mutual-tls` §4 | Not enforced. `verify` is a single-issuer model that checks the directly provided CA only; deployments needing full PKIX path validation should use a dedicated X.509 verifier. |
| Selecting the trust anchor from the `sub` trust domain | `workload-creds` §3 | Left to the caller: `wimsey_wit::verify` takes the issuer's verifying key as an argument, so mapping the trust domain of `sub` to its configured anchors — and picking the key within them, by `kid` where one is present — is the deployment's. This also means anchor material can never be resolved from the token's own `iss`, which the draft forbids. |
| The `WPT` HTTP authentication scheme and its `WWW-Authenticate` challenge | `wpt` §2, §2.1 | Not implemented. `wimsey-wpt` is the token, not its transport: it issues and verifies the proof, and placing it in `Authorization: WPT <proof>` — and answering a rejection with `401` and `WWW-Authenticate: WPT` — is the caller's. The `wpt` CLI subcommand prints the bare proof for the same reason. |

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

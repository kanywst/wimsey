# Spec map

`wimsey` targets the IETF WIMSE working group documents. The specs are
Internet-Drafts and revise frequently, so each crate **pins a specific draft
revision**. Bumping a pin is a deliberate, reviewed change.

## Pinned revisions

| Draft | Revision | Crate | Notes |
| --- | --- | --- | --- |
| `draft-ietf-wimse-arch` | -08 | — | Architecture; design guidance only |
| `draft-ietf-wimse-identifier` | -04 | `wimsey-identifier` | URI scheme; `spiffe` and `wimse` |
| `draft-ietf-wimse-workload-creds` | -03 | `wimsey-wit` | Defines WIT and WIC |
| `draft-ietf-wimse-wpt` | -02 | `wimsey-wpt` | Workload Proof Token (DPoP-style PoP) |
| `draft-ietf-wimse-http-signature` | -08 | `wimsey-httpsig` | Profile of RFC 9421 |
| `draft-ietf-wimse-mutual-tls` | -02 | `wimsey-mtls` | mTLS binding, client cert = WIC |
| `draft-ietf-wimse-workload-identity-practices` | -07 | — | Informational; with the IESG |

Every pin above is the current *published* revision as of 2026-10-22.

## Drafts in progress upstream

A pin tracks what the datatracker has published, and the editors' repositories
run ahead of that. The revision a working copy is heading for is named by the
first entry of its Document History section.

| Draft | Published | Editors' copy | Bearing on this workspace |
| --- | --- | --- | --- |
| `identifier` | -04 | -04 | — |
| `workload-creds` | -03 | -03 | — |
| `wpt` | -02 | -03 | Moves the key-management section to `workload-creds`; no normative change for `wimsey-wpt`. |
| `http-signature` | -08 | -08 | — |
| `mutual-tls` | -02 | -03 | Editorial (capitalization of defined terms). |

Checked 2026-09-29 (`http-signature` 2026-10-22), and re-checked by
`scripts/check-draft-revisions.sh`.

The editors'-copy column is a forecast, not a diff. It described
`http-signature` -07 as editorial on 2026-09-08; the WG Last Call then landed
normative changes in the same revision — `@path`/`@query` in place of
`@request-target`, selecting the WIMSE signature by `tag`, and `wimse-req-nonce`
on every signed response. Diff the published text before bumping a pin.

## Known divergences

A reference implementation should be explicit about where it does not yet meet
the pinned drafts.

| Requirement | Draft | Status |
| --- | --- | --- |
| Accepting a non-normalized `wimse` spelling and normalizing it | `identifier` §4.3 | Stricter than the draft: `WorkloadIdentifier::parse` refuses an uppercase trust domain, a lowercase-hex escape, an escape of an unreserved character, an empty path segment and an IPv6-literal trust domain instead of normalizing them, so every accepted identifier is already in normal form and byte comparison is the §4.3 comparison. The draft would accept the first three after normalizing. |
| Matching the trust domain against an allowlist of trusted domains | `identifier` §6.3 | Left to the caller: the crate parses and exposes `trust_domain()` (always ASCII, A-labels for IDNs), and deciding which trust domains are trusted is the deployment's. |
| Mapping an external handle (DNS name, service name) to the expected identifier | `identifier` §5 | Left to the caller: the crate has no notion of how a workload was addressed. |
| Accepting the fully-specified `Ed25519` algorithm identifier (RFC 9864) | `workload-creds` §5.1 | Not yet: -03's example WIT, like the `http-signature` -08 examples, names `Ed25519` in `cnf.jwk.alg` in place of the deprecated `EdDSA`. `wimsey-jose` emits and accepts `EdDSA` only, so such a WIT is rejected with `unsupported_confirmation_alg`. The text still allows any registered value, so this is an interop gap rather than a violation; switching needs the key to carry its `alg` label, because `wpt` requires the proof's `alg` to string-equal the WIT's, and is tracked separately. |
| Requiring `jti` in every WIT when a deployment runs a status list or `jti` deny-list | `workload-creds` §9.3.1 | Left to the caller: `jti` is optional in `WitClaims`, and only the deployment knows whether it revokes. |
| Trust-domain match on the TLS peer certificate | `mutual-tls` §4 | Left to the caller: `wimsey-mtls::verify` returns the identifier and the caller compares it, since chain building and rustls wiring are out of scope. |
| Chain building, `basicConstraints`, `keyUsage`, name constraints | `mutual-tls` §4 | Not enforced. `verify` is a single-issuer model that checks the directly provided CA only; deployments needing full PKIX path validation should use a dedicated X.509 verifier. |
| Selecting the trust anchor from the `sub` trust domain | `workload-creds` §3 | Left to the caller: `wimsey_wit::verify` takes the issuer's verifying key as an argument, so mapping the trust domain of `sub` to its configured anchors — and picking the key within them, by `kid` where one is present — is the deployment's. This also means anchor material can never be resolved from the token's own `iss`, which -03 removed and §9.1 describes as an attack. Validating a credential only against the anchors of its own trust domain (§3, new in -03) is part of the same mapping. |
| Local policy on the peer's algorithm per trust domain | `http-signature` §3.1 | Partly left to the caller: `VerifyConfig::accepted_algorithms` rejects an algorithm outside the configured set, but choosing that set by the peer's trust domain is the deployment's. |
| Rejecting an unsigned response the client required (`wimse-sign-response`) | `http-signature` §3.5 | Left to the caller: with no signature there is nothing to hand `verify`, so the client that set the parameter has to treat a missing `Signature` as a failure. |
| Replay cache for `nonce` | `http-signature` §3 | Left to the caller: `verify` checks that a `nonce` is present but does not remember the ones it has seen. |
| Generating the `nonce` from a CSPRNG with at least 64 bits of entropy | `http-signature` §3 | Left to the caller: `sign` takes the nonce as a parameter so signing stays deterministic. The `wimsey httpsig sign` subcommand draws 128 bits from the OS when `--nonce` is omitted. |
| Answering a failure with `400`/`501` and the registered problem types | `http-signature` §3.6 | Left to the caller: the crate is not an HTTP server. It exports the three problem type URIs (`PROBLEM_SIGNATURE_INVALID` and the two `PROBLEM_SIGNED_RESPONSE_*`); every `HttpSigError` on a request maps to `400` with the first, without telling the peer which check failed. |
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

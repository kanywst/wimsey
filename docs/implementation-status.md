# Implementation status entries

[RFC 7942](https://www.rfc-editor.org/rfc/rfc7942) asks Internet-Drafts to carry an "Implementation Status" section listing known implementations, so a working group can weigh a document against running code. This file holds `wimsey`'s entries: the two that are published, kept as they were actually merged, and the three that are not.

Keep it current with the code. An entry that overstates coverage is worse than no entry, because it is published in a document the WG uses to make decisions. Nobody upstream sends a reminder when an entry goes stale, so re-read the entries whenever a draft revises; `scripts/check-draft-revisions.sh` reports when that has happened.

## Where the entries go

The drafts are kramdown-rfc markdown. Four of the five live in one repository:

| Draft | Repository | Entry |
| --- | --- | --- |
| `draft-ietf-wimse-http-signature` | `ietf-wg-wimse/draft-ietf-wimse-s2s-protocol` | Published |
| `draft-ietf-wimse-workload-creds` | `ietf-wg-wimse/draft-ietf-wimse-s2s-protocol` | Published |
| `draft-ietf-wimse-wpt` | `ietf-wg-wimse/draft-ietf-wimse-s2s-protocol` | No section; proposal withdrawn ([s2s#310](https://github.com/ietf-wg-wimse/draft-ietf-wimse-s2s-protocol/pull/310)) |
| `draft-ietf-wimse-mutual-tls` | `ietf-wg-wimse/draft-ietf-wimse-s2s-protocol` | No section; proposal withdrawn ([s2s#311](https://github.com/ietf-wg-wimse/draft-ietf-wimse-s2s-protocol/pull/311)) |
| `draft-ietf-wimse-identifier` | `ietf-wg-wimse/draft-ietf-wimse-identifier` | Proposed with the section in [identifier#98](https://github.com/ietf-wg-wimse/draft-ietf-wimse-identifier/pull/98) |

Two things to know before opening a pull request:

- Contributing to these repositories makes the text an IETF Contribution under BCP 78 and 79 — their `CONTRIBUTING.md` says so explicitly. It is not the same as a normal open-source pull request. Neither repository asks for a DCO sign-off.
- The `Contact:` line is published on a permanently archived page. The two published entries use a link to the GitHub profile rather than an email address; keep the rest consistent with that.

## Published entries

Merged upstream in [#296](https://github.com/ietf-wg-wimse/draft-ietf-wimse-s2s-protocol/pull/296) on 2026-09-01. The editors condensed the `Coverage` line to a short list, dropped the `Notes`, and filled in `Contact`, so the merged text below is shorter than what was proposed. It is reproduced as merged, since that is what future edits are made against.

The detailed coverage prose is kept under [What the short coverage lines stand for](#what-the-short-coverage-lines-stand-for).

### `draft-ietf-wimse-http-signature`

The date was refreshed in [#309](https://github.com/ietf-wg-wimse/draft-ietf-wimse-s2s-protocol/pull/309), after re-verifying the coverage against the code.

```markdown
## wimsey

* Organization: independent
* Implementation: <https://github.com/kanywst/wimsey>
* Maturity:
    * WIT + HTTP Message Signatures: alpha
* Coverage: WIT, HTTP Message Signatures, signed responses
* License: Apache 2.0
* Contact: [kanywst on GitHub](https://github.com/kanywst)
* Last updated: 08-Sep-2026
```

### `draft-ietf-wimse-workload-creds`

Note that this document's entries carry neither `License` nor `Last updated` — none of the four do, so wimsey's follows the file rather than the other document.

```markdown
wimsey

* Organization: independent
* Implementation: <https://github.com/kanywst/wimsey>
* Maturity:
    * Workload Identity Token: alpha
    * Workload Identity Certificate: alpha
* Coverage: WIT, Workload Identity Certificate
* Contact: [kanywst on GitHub](https://github.com/kanywst)
```

## Entries not published

None of these three documents has an Implementation Status section, so an entry means adding the [section boilerplate](#section-boilerplate) too.

That is not always wanted. Adding the section to the WPT draft drew a preference against having one at all ([s2s#310](https://github.com/ietf-wg-wimse/draft-ietf-wimse-s2s-protocol/pull/310)), so that proposal and the matching one for mutual TLS were withdrawn. Ask before proposing a section again; the entries below stay ready for the day a document grows one. [identifier#98](https://github.com/ietf-wg-wimse/draft-ietf-wimse-identifier/pull/98) is open in the other repository.

### `draft-ietf-wimse-wpt`

```markdown
## wimsey

* Organization: independent
* Implementation: <https://github.com/kanywst/wimsey>
* Maturity:
    * Workload Proof Token: alpha, not for production
* Coverage: Issuance and verification with the mandatory `aud`, `exp`, `jti`
  and `wth` claims and the conditional `tth` and `oth`, under `EdDSA` or
  `ES256`. Verification recomputes `wth` from the WIT actually presented and
  takes the proof-of-possession key from that WIT, and requires the proof's
  `alg` to be the one that WIT's `cnf` names. Single-use `jti` tracking is left
  to the caller, as is the `WPT` HTTP authentication scheme that conveys the
  proof — this is the token, not its transport.
* License: Apache 2.0
* Contact: [kanywst on GitHub](https://github.com/kanywst)
* Last updated: 08-Sep-2026
```

### `draft-ietf-wimse-mutual-tls`

```markdown
## wimsey

* Organization: independent
* Implementation: <https://github.com/kanywst/wimsey>
* Maturity:
    * Workload Identity Certificate: alpha, not for production
* Coverage: Issues and verifies a WIC carrying the identifier in a URI SAN,
  with `id-kp-clientAuth` and `id-kp-serverAuth`, under `EdDSA` or `ES256`.
  The signature algorithm a verifier accepts follows the CA's own key rather
  than the certificate's claim. Issuance takes the workload's public key only,
  so the CA never holds the key it certifies.
  Verification is a single-issuer model against a directly provided CA: it
  does not build a chain, and does not enforce `basicConstraints`, `keyUsage`
  or name constraints. Wiring into a TLS stack is left to the caller.
* License: Apache 2.0
* Contact: [kanywst on GitHub](https://github.com/kanywst)
* Last updated: 08-Sep-2026
```

### `draft-ietf-wimse-identifier`

```markdown
## wimsey

* Organization: independent
* Implementation: <https://github.com/kanywst/wimsey>
* Maturity:
    * Workload Identifier: alpha, not for production
* Coverage: Parses and validates both the `spiffe` scheme and the `wimse`
  scheme of Section 4.4, enforcing the Section 4.1 prohibitions on query,
  fragment, user-information and port components. Section 4.3 requires
  comparing complete URIs, so rather than normalizing, it rejects any spelling
  RFC 3986 Section 6.2.2 normalization would rewrite: an uppercase trust
  domain, a dot segment, and a percent-escape that is lowercase or encodes an
  unreserved character. Whether the draft intends normalizing or rejecting is
  an open question raised on the mailing list.
* License: Apache 2.0
* Contact: [kanywst on GitHub](https://github.com/kanywst)
* Last updated: 08-Sep-2026
```

## What the short coverage lines stand for

The published entries compress this into a few words. Verified against the code on 2026-09-08.

**`http-signature` — "WIT, HTTP Message Signatures, signed responses".** The Section 3 profile for both requests and responses. Requests: the mandatory covered components, `created`/`expires`/`nonce`/`tag`, `wimse-aud`, and rejection of the forbidden `keyid` and `alg` parameters. Responses: `@status`, the `;req` covered components, `wimse-req-nonce`, and a response profile in which `wimse-aud` is forbidden. The `wimse-sign-response` parameter added in -06 is implemented, and serializes as a bare Boolean. Replay detection is left to the caller; the implementation checks that a `nonce` is present but does not remember the ones it has seen. Cross-implementation test vectors, whose negative cases each name the reason the input must be rejected, are published at <https://github.com/kanywst/wimsey/tree/main/conformance>; Yaron Sheffer ran them against his own RFC 9421 implementation and reported that they pass.

**`workload-creds` — "WIT, Workload Identity Certificate".** WIT issuance and verification with the mandatory `sub`, `exp` and `cnf` claims, the optional `iss`, `iat` and `jti`, and the required `alg` member inside the `cnf` JWK, which is enforced as the algorithm the proof must use. Both `EdDSA` and `ES256`, in any combination — an EdDSA issuer with an ES256 confirmation key is exercised by a conformance vector. WIC issuance and verification with the identifier in a URI SAN, under either algorithm. Selecting the trust anchor from the trust domain of `sub` (Section 3) is left to the caller, which is recorded in `SPEC-MAP.md`; verification takes the issuer key as an argument, so anchor material can never be resolved from the token's own `iss`.

## Section boilerplate

For the three documents with no Implementation Status section yet. Copied verbatim from `draft-ietf-wimse-http-signature.md`; it is identical across documents.

```markdown
# Implementation Status

<cref>Note to RFC Editor: please remove this section, as well as the reference to RFC 7942, before publication.</cref>

This section records the status of known implementations of the protocol defined by this specification at the time of posting of this Internet-Draft, and is based on a proposal described in {{!RFC7942}}. The description of implementations in this section is intended to assist the IETF in its decision processes in progressing drafts to RFCs.  Please note that the listing of any individual implementation here does not imply endorsement by the IETF.  Furthermore, no effort has been spent to verify the information presented here that was supplied by IETF contributors. This is not intended as, and must not be construed to be, a catalog of available implementations or their features.  Readers are advised to note that other implementations may exist.

According to RFC 7942, "this will allow reviewers and working groups to assign due consideration to documents that have the benefit of running code, which may serve as evidence of valuable experimentation and feedback that have made the implemented protocols more mature.  It is up to the individual working groups to use this information as they see fit".
```

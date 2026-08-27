# Implementation status entries

[RFC 7942](https://www.rfc-editor.org/rfc/rfc7942) asks Internet-Drafts to carry an "Implementation Status" section listing known implementations, so a working group can weigh a document against running code. This file holds `wimsey`'s entries, ready to paste, so that responding to an editor's invitation is a copy rather than a writing exercise.

Keep it current with the code. An entry that overstates coverage is worse than no entry, because it is published in a document the WG uses to make decisions.

## Where the entries go

The drafts are kramdown-rfc markdown. Four of the five live in one repository:

| Draft | Repository |
| --- | --- |
| `draft-ietf-wimse-http-signature` | `ietf-wg-wimse/draft-ietf-wimse-s2s-protocol` |
| `draft-ietf-wimse-workload-creds` | `ietf-wg-wimse/draft-ietf-wimse-s2s-protocol` |
| `draft-ietf-wimse-wpt` | `ietf-wg-wimse/draft-ietf-wimse-s2s-protocol` |
| `draft-ietf-wimse-mutual-tls` | `ietf-wg-wimse/draft-ietf-wimse-s2s-protocol` |
| `draft-ietf-wimse-identifier` | `ietf-wg-wimse/draft-ietf-wimse-identifier` |

Only `http-signature` and `workload-creds` have an Implementation Status section today; the other three need the [section boilerplate](#section-boilerplate) as well as the entry.

Two things to know before opening a pull request:

- Contributing to these repositories makes the text an IETF Contribution under BCP 78 and 79 — their `CONTRIBUTING.md` says so explicitly. It is not the same as a normal open-source pull request.
- The `Contact:` line is left blank in every entry below. It is published on a permanently archived page, so which address goes there is a decision, not a detail.

## Entries

### `draft-ietf-wimse-http-signature`

Append after the existing `## Cofide` block.

```markdown
## wimsey

* Organization: independent
* Implementation: <https://github.com/kanywst/wimsey>
* Maturity:
    * WIT + HTTP Message Signatures: alpha, not for production
* Coverage: The Section 3 profile for both requests and responses. Requests:
  the mandatory covered components, `created`/`expires`/`nonce`/`tag`,
  `wimse-aud`, and rejection of the forbidden `keyid` and `alg` parameters.
  Responses: `@status`, the `;req` covered components, `wimse-req-nonce`, and
  a response profile in which `wimse-aud` is forbidden. Replay detection is
  left to the caller; the implementation checks that a `nonce` is present but
  does not remember the ones it has seen.
* License: Apache 2.0
* Contact:
* Last updated: 27-Aug-2026
* Notes: Publishes cross-implementation test vectors whose negative cases each
  name the reason the input must be rejected, with one vector per signature
  algorithm: <https://github.com/kanywst/wimsey/tree/main/conformance>. Yaron
  Sheffer ran them against his own RFC 9421 implementation and reported that
  they pass.
```

### `draft-ietf-wimse-workload-creds`

Append after the existing SPIFFE entry.

```markdown
## wimsey

* Organization: independent
* Implementation: <https://github.com/kanywst/wimsey>
* Maturity:
    * Workload Identity Token: alpha, not for production
    * Workload Identity Certificate: alpha, not for production
* Coverage: WIT issuance and verification with the mandatory `sub`, `exp` and
  `cnf` claims, the optional `iss`, `iat` and `jti`, and the required `alg`
  member inside the `cnf` JWK, which is enforced as the algorithm the proof
  must use. Both `EdDSA` and `ES256`, in any combination — an EdDSA issuer with
  an ES256 confirmation key is exercised by a conformance vector. WIC issuance
  and verification with the identifier in a URI SAN, under either algorithm.
* License: Apache 2.0
* Contact:
* Last updated: 27-Aug-2026
```

### `draft-ietf-wimse-wpt`

Needs the section boilerplate.

```markdown
## wimsey

* Organization: independent
* Implementation: <https://github.com/kanywst/wimsey>
* Maturity:
    * Workload Proof Token: alpha, not for production
* Coverage: Issuance and verification with the mandatory `aud`, `exp`, `jti`
  and `wth` claims and the optional `ath`, under `EdDSA` or `ES256`.
  Verification recomputes `wth` from the WIT actually presented and takes the
  proof-of-possession key from that WIT, and requires the proof's `alg` to be
  the one that WIT's `cnf` names. Single-use `jti` tracking is left to the
  caller.
* License: Apache 2.0
* Contact:
* Last updated: 27-Aug-2026
```

### `draft-ietf-wimse-mutual-tls`

Needs the section boilerplate.

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
* Contact:
* Last updated: 27-Aug-2026
```

### `draft-ietf-wimse-identifier`

Needs the section boilerplate.

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
* Contact:
* Last updated: 27-Aug-2026
```

## Section boilerplate

For the three documents with no Implementation Status section yet. Copied verbatim from `draft-ietf-wimse-http-signature.md`; it is identical across documents.

```markdown
# Implementation Status

<cref>Note to RFC Editor: please remove this section, as well as the reference to RFC 7942, before publication.</cref>

This section records the status of known implementations of the protocol defined by this specification at the time of posting of this Internet-Draft, and is based on a proposal described in {{!RFC7942}}. The description of implementations in this section is intended to assist the IETF in its decision processes in progressing drafts to RFCs.  Please note that the listing of any individual implementation here does not imply endorsement by the IETF.  Furthermore, no effort has been spent to verify the information presented here that was supplied by IETF contributors. This is not intended as, and must not be construed to be, a catalog of available implementations or their features.  Readers are advised to note that other implementations may exist.

According to RFC 7942, "this will allow reviewers and working groups to assign due consideration to documents that have the benefit of running code, which may serve as evidence of valuable experimentation and feedback that have made the implemented protocols more mature.  It is up to the individual working groups to use this information as they see fit".
```

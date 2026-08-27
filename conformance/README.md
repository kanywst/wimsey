# WIMSE conformance vectors

These vectors are a contract, not a snapshot of what `wimsey` happens to emit. Any WIMSE implementation, in any language, should be able to read them and answer three questions:

1. Given the recorded inputs, do I produce the recorded bytes?
2. Do I accept the positive case?
3. Do I reject every negative case **for the reason recorded**, not merely reject it?
4. Do I still accept every `accepted` case — an input altered outside what the signature covers?

The third question is the one that matters most and the one a byte-diff of regenerated output can never answer. An implementation that rejects an expired token because it failed to parse the payload is still wrong, and it will still interoperate badly.

The fourth is its mirror: the first three can all be passed by refusing more than the spec asks. Over-strictness reads as diligence and surfaces only against someone else's signer.

Signing is EdDSA over Ed25519 (RFC 8037) or ES256 (ECDSA P-256), and both are deterministic — ES256 through its RFC 6979 nonce — so the recorded bytes are reproducible. Time is an input (`verify_now`), never a wall clock.

## Layout

```text
conformance/
  manifest.json                    index of every vector
  identifier/parse-basic.json      draft-ietf-wimse-identifier-03
  wit/issue-eddsa.json             draft-ietf-wimse-workload-creds-02
  wit/issue-es256.json             draft-ietf-wimse-workload-creds-02
  wpt/proof-eddsa.json             draft-ietf-wimse-wpt-01
  wpt/proof-es256.json             draft-ietf-wimse-wpt-01
  httpsig/sign-eddsa.json          draft-ietf-wimse-http-signature-06
  httpsig/sign-es256.json          draft-ietf-wimse-http-signature-06
  mtls/wic-basic.json              draft-ietf-wimse-mutual-tls-02
```

Each token suite has one vector per signature algorithm. `ES256` is not an
extra credit: Section 5.1 of `draft-ietf-wimse-workload-creds` requires it of
general-purpose implementations, and the draft's own example WIT is signed with
it, so passing only the `eddsa` half is not passing. Certificates are Ed25519
only, because the mutual-TLS draft makes no such requirement.

Start at `manifest.json`. Do not glob the directories — the manifest is the list, and a runner that globs will silently skip a vector whose suite it does not recognise.

## Format

Every file, including the manifest, carries a `format` field:

```json
{ "format": "wimse-conformance/v3" }
```

**v2 replaced the raw key bytes of v1 with JWKs.** v1 recorded a public key as 32 base64url bytes, which only worked because every v1 vector was Ed25519 — the bytes do not say which algorithm they are for. A JWK carries its own `alg`, so one suite can hold vectors for both. A private key is a JWK with `d`, so a consumer can re-sign from scratch as before.

**v3 added the `accepted` array to the httpsig vectors**, so a file can record what must still verify and not only what must be rejected. It is a version bump rather than a plain addition because a v2 reader skips the new cases silently: it would report a pass having run fewer checks than the file asks for.

**v4 gave the responder its own identity.** The response now carries `wit` and `pop_signing_key` of its own, where through v3 it reused the requester's. A v3 reader recovers the key from the request's WIT and fails to verify the response, which is loud rather than silent — but it fails for the wrong reason, so update the reader rather than reading the failure as a bad signature.

Reject a file whose `format` you do not recognise rather than guessing at its shape. The version changes when the format changes, not when a vector is added.

Each vector file additionally carries `suite`, `id`, `spec` (the pinned Internet-Draft revision it was generated against) and a prose `description`.

### Encoding conventions

| Field | Encoding |
| --- | --- |
| A key (`issuer_signing_key`, `issuer_verifying_key`, …) | A JWK: `OKP`/`Ed25519` or `EC`/`P-256`, with `d` when private |
| `_der_b64u` | DER, base64url **without** padding |
| JWT compact serialization | base64url without padding, per RFC 7515 |
| RFC 8941 byte sequences (the `Signature` field) | **standard** base64, with padding |

The two base64 alphabets are not interchangeable. Mixing them is a common interop bug, which is why both appear in these vectors.

### Negative cases

Every vector has a `negative` array. Each entry records **only the fields it overrides**; anything it omits is taken from the positive case in the same file. So this entry means "the positive case, verified one second after `exp`":

```json
{
  "id": "expired",
  "description": "verified one second after `exp`",
  "expect": "expired",
  "verify_now": 1700003601
}
```

`expect` is a language-neutral error code, not a Rust error name. Map it onto whatever your verifier returns.

| Code | Meaning |
| --- | --- |
| `malformed_token` | Not three parts, or a part was the wrong size |
| `token_too_long` | Larger than the accepted maximum |
| `unsupported_critical` | A critical JOSE header extension was not understood |
| `invalid_encoding` | A Base64 or JSON component could not be decoded |
| `wrong_type` | The JOSE `typ` was not the one this token type requires |
| `unsupported_alg` | The `alg` header or signature parameter was not supported |
| `invalid_signature` | The signature did not verify against the key |
| `expired` | The token or signature has expired |
| `issued_in_future` | `iat` is ahead of the verifier's clock |
| `issuer_mismatch` | `iss` did not match the expected issuer |
| `invalid_key` | A key could not be decoded |
| `audience_mismatch` | `aud` did not match the expected audience |
| `wit_binding_mismatch` | `wth` did not match the hash of the presented WIT |
| `access_token_binding_mismatch` | `ath` and the presented access token disagreed |
| `lifetime_too_long` | The proof's remaining lifetime exceeded the maximum |
| `missing_component` | A covered component was absent from the message |
| `unsupported_component` | A component identifier was not supported |
| `invalid_component_value` | A component value contained a bare CR or LF |
| `missing_required_component` | A component the verifier requires was not covered |
| `invalid_time_window` | `expires` precedes `created` |
| `too_old` | `created` is older than the verifier's maximum age |
| `parse_error` | A structured field could not be parsed |
| `label_mismatch` | The signature labels disagreed, or the label was absent |
| `malformed_signature` | Not valid Base64, or not 64 bytes |
| `created_in_future` | `created` is ahead of the verifier's clock |
| `content_digest_mismatch` | `Content-Digest` did not match the body |
| `missing_parameter` | A signature parameter the WIMSE profile requires was absent |
| `forbidden_parameter` | A signature parameter the WIMSE profile forbids was present |
| `wrong_tag` | `tag` was not `wimse-workload-to-workload` |
| `missing_confirmation_alg` | The `cnf` JWK omitted the required `alg` member |
| `forbidden_confirmation_alg` | The `cnf` JWK named `none`, a symmetric, or an encryption algorithm |
| `unsupported_confirmation_alg` | The `cnf` JWK named a legal algorithm the implementation cannot use |
| `identifier_too_long` | A workload identifier exceeded the maximum length |
| `unsupported_scheme` | The identifier used a scheme the implementation does not know |
| `has_query` / `has_fragment` | Section 4.1 forbids a query and a fragment component |
| `has_user_info` / `has_port` | Section 4.1 forbids user information and a port |
| `empty_trust_domain` | The authority component was empty |
| `trust_domain_too_long` | The trust domain exceeded the length its scheme allows |
| `invalid_trust_domain_char` | The trust domain held a character its scheme disallows |
| `empty_path_segment` | A path segment was empty, including a trailing slash |
| `dot_segment` | A path held a `.` or `..` segment |
| `invalid_path_char` | A path segment held a character its scheme disallows |
| `bad_percent_encoding` | A percent-escape was not `%` plus two hex digits |
| `non_normalized_percent_encoding` | A percent-escape was lowercase, or encoded an unreserved character |
| `certificate_parse_error` | The presented bytes were not DER X.509 |
| `certificate_not_valid` | The certificate is outside its validity window |
| `missing_identifier` | The certificate carries no URI SAN workload identifier |
| `multiple_identifiers` | The certificate carries more than one URI SAN |

No vector records `unmapped`. The runner reports that code when an implementation rejects an input for a reason the table does not name, so an unrecognised failure shows up as a mismatch instead of being folded into a plausible-looking neighbour.

## What to check per suite

### `identifier`

There is nothing to re-sign here, so the two checks are the whole contract.

- Every entry in `accept` must parse **and decompose** into the recorded `scheme`, `trust_domain`, `path` and `origin`. Parsing without checking the decomposition would let a parser that silently normalizes still pass.
- Every entry in `reject` must be refused for the recorded reason.

Most of the reject cases are not malformed URIs at all — they are *second spellings*. `spiffe://Example.org/x`, `spiffe://example.org/a/../b`, `wimse://example.org/%2E%2E/api` and `wimse://example.org/%61pi` each denote something an accepted identifier already denotes, once RFC 3986 Section 6.2.2 normalization is applied. Section 4.3 tells consumers to compare complete URIs, which is only sound if an identifier has exactly one spelling, so a conforming parser has to either normalize or refuse. This suite requires refusing, because a parser that normalizes silently will disagree with one that does not, and the disagreement will be about who is authorized.

Note `wimse://example.org/a%2Fb` in `accept`: `%2F` encodes a **reserved** character, which normalization does *not* decode, so it is a legitimate identifier rather than a second spelling of `/a/b`. An implementation that percent-decodes indiscriminately will wrongly reject it — or worse, wrongly equate it with `a/b`.

### `wit`

- Re-issue from `claims`, `kid` and `issuer_signing_key`; the result must equal `token` byte for byte.
- Verify `token` at `verify_now` against the seed's public half; the recovered claims must equal `claims`.
- Run every negative case. Unless it overrides `issuer_verifying_key`, verify against the issuer key's public half; `expected_iss`, when present, is an issuer the verifier must require.

### `wpt`

- Re-issue from `claims` and `pop_signing_key`; the result must equal `proof`.
- `claims.wth` must equal `base64url(SHA-256(wit))`, computed over the WIT's ASCII compact serialization.
- Verify the full chain: verify `wit` against `issuer_verifying_key`, take the proof-of-possession key from its `cnf`, then verify `proof` against that key with `audience` and `wit`. Recovering the key from the WIT rather than from the vector is the point — it is what catches a break in the WIT-to-WPT binding.
- Run every negative case against the proof-of-possession key.

Note `wit-binding-mismatch`: the substituted WIT is itself perfectly valid and signed by the same issuer for the same key. Only `wth` distinguishes them. An implementation that checks the signature but not the binding will pass everything else and fail here.

### `httpsig`

- Re-sign `request` with `components`, `params`, `label` and `pop_signing_key`; both `signature_input` and `signature` must match byte for byte. The signature base is byte-exact (RFC 9421 section 2.5); whitespace and quoting are not free choices.
- Verify the full chain: verify `wit`, take the proof-of-possession key from its `cnf`, then verify the signature over `request`, requiring every component in `components` to be covered.
- Enforce the profile in Section 3 of the http-signature draft: `created`, `expires`, `nonce` and `tag` must be present, `tag` must be `wimse-workload-to-workload`, `wimse-aud` must be present and must equal the audience the verifier answers to, and `keyid` and `alg` must be absent.
- Check `verify_content_digest(Content-Digest header, body)`.
- Run every negative case. `required_components`, `accept_label`, `accept_audience` and `max_age` are verifier configuration, not message content: they describe how strict the receiver is, and the case asserts that a receiver configured that way rejects the message.
- Run every `accepted` case the same way, except that verification MUST succeed. Each entry overrides fields of the positive case exactly as a negative one does.
- Run the `response` half. It carries its own `wit` and `pop_signing_key`, and the covered components include `@status` and the `;req` ones, which resolve from the request in the same file. Verify it against the key in **its own** WIT, check `wimse-req-nonce` equals the `nonce` the request sent, and run its negative cases.

The responder is a different workload from the caller — a different identifier, a different WIT, a different key. `verified-with-the-requester-key` substitutes the request's WIT and must fail: a client that carries request-side identity state into the response check passes every other assertion here.

The `authority` pair answers a question that has come up twice on the WIMSE list. `@authority` is not in the set Section 3 mandates, so `authority-rewritten-outside-the-covered-set` rewrites the host and must **still verify** — `wimse-aud` names the service a request is for, not where it was routed. Its pair carries a signature that does cover `@authority`, and the same rewrite then fails. Cover it if you need the host bound.

The `tampered-body` case is deliberately not a signature failure. The signature covers the `Content-Digest` **header string**, which is untouched, so the signature still verifies — the body is caught by the digest check alone. An implementation that only verifies signatures and never re-hashes the body will accept a swapped payload.

The six profile cases (`forbidden-alg-parameter`, `forbidden-keyid-parameter`, `missing-nonce`, `missing-expires`, `missing-wimse-aud`, `wrong-tag`) each carry their own `signature_input` and `signature`, and each one is a genuinely valid signature. What must reject them is the profile rule, not a broken signature — an implementation that verifies the signature and stops will accept all six.

### `mtls`

- Rebuild the CA from `ca_signing_key` and its validity window; the result must equal `ca_certificate_der_b64u`.
- Re-issue the WIC for the workload's **public** key — the public half of `workload_signing_key` — over `identifier` and the recorded window. It must equal `wic_der_b64u` byte for byte.
- Verify `wic_der_b64u` against `ca_certificate_der_b64u` at `verify_now`; the URI SAN must decode to `identifier`.
- Run every negative case.

Certificates are usually a poor fit for byte-exact vectors, because issuing one normally invents a key and a serial. Neither happens here. The workload generates its own key pair and sends only the public half, so there is no per-issuance secret, and the serial is derived from that public key rather than drawn at random. That leaves nothing non-deterministic, so a consumer can re-issue from seeds instead of taking a frozen blob on trust.

The `no-uri-san` case is the one worth reading twice: the input is the CA's own certificate, which is validly signed by the CA it is checked against and entirely well-formed. It simply carries no workload identifier. An implementation that verifies the signature and stops will accept it and then have nothing to authorize.

## Running them

This repository's runner both generates and checks the vectors, so the format has one definition:

```bash
cargo run -p wimsey-conformance -- run --dir conformance
cargo run -p wimsey-conformance -- run --dir conformance --format json
```

It exits non-zero if any check fails. CI runs it, and separately regenerates the vectors and diffs them, so neither the recorded bytes nor the pass/fail behaviour can drift unnoticed.

Regenerating is a deliberate act, reviewed like any other behaviour change:

```bash
cargo run -p wimsey-conformance -- generate --out conformance
```

## Adding a vector

1. Add its construction to `crates/conformance/src/generate.rs`, including the negative cases, and list it in `manifest()`.
2. Teach `crates/conformance/src/run.rs` any check the new suite needs.
3. Regenerate, then run. The runner refuses to start if a `.json` file exists under a suite directory that the manifest does not list, so a vector cannot be added and quietly never run.

Keep generation deterministic: fixed key seeds, fixed timestamps, no randomness, no wall clock.

## Reporting a disagreement

If your implementation disagrees with a vector, that is worth an issue either way — the vectors are as likely to be wrong as your code, and a disagreement is exactly the interop bug this directory exists to surface. Open one at <https://github.com/kanywst/wimsey/issues> with the vector `id`, the check that failed, and what your implementation produced instead.

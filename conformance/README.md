# WIMSE conformance vectors

These vectors are a contract, not a snapshot of what `wimsey` happens to emit. Any WIMSE implementation, in any language, should be able to read them and answer three questions:

1. Given the recorded inputs, do I produce the recorded bytes?
2. Do I accept the positive case?
3. Do I reject every negative case **for the reason recorded**, not merely reject it?

The third question is the one that matters most and the one a byte-diff of regenerated output can never answer. An implementation that rejects an expired token because it failed to parse the payload is still wrong, and it will still interoperate badly.

Everything here is EdDSA over Ed25519 (RFC 8037), which is deterministic, so the recorded bytes are reproducible. Time is an input (`verify_now`), never a wall clock.

## Layout

```text
conformance/
  manifest.json                 index of every vector
  wit/issue-basic.json          draft-ietf-wimse-workload-creds-01
  wpt/proof-basic.json          draft-ietf-wimse-wpt-01
  httpsig/sign-basic.json       draft-ietf-wimse-http-signature-03
```

Start at `manifest.json`. Do not glob the directories — the manifest is the list, and a runner that globs will silently skip a vector whose suite it does not recognise.

## Format

Every file, including the manifest, carries a `format` field:

```json
{ "format": "wimse-conformance/v1" }
```

Reject a file whose `format` you do not recognise rather than guessing at its shape. The version changes when the format changes, not when a vector is added.

Each vector file additionally carries `suite`, `id`, `spec` (the pinned Internet-Draft revision it was generated against) and a prose `description`.

### Encoding conventions

| Field suffix | Encoding |
| --- | --- |
| `_seed_b64u` | 32-byte Ed25519 private seed, base64url **without** padding |
| `_key_b64u` | 32-byte Ed25519 public key, base64url **without** padding |
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

No vector records `unmapped`. The runner reports that code when an implementation rejects an input for a reason the table does not name, so an unrecognised failure shows up as a mismatch instead of being folded into a plausible-looking neighbour.

## What to check per suite

### `wit`

- Re-issue from `claims`, `kid` and `issuer_signing_key_seed_b64u`; the result must equal `token` byte for byte.
- Verify `token` at `verify_now` against the seed's public half; the recovered claims must equal `claims`.
- Run every negative case. Unless it overrides `issuer_verifying_key_b64u`, verify against the seed's public half; `expected_iss`, when present, is an issuer the verifier must require.

### `wpt`

- Re-issue from `claims` and `pop_signing_key_seed_b64u`; the result must equal `proof`.
- `claims.wth` must equal `base64url(SHA-256(wit))`, computed over the WIT's ASCII compact serialization.
- Verify the full chain: verify `wit` against `issuer_verifying_key_b64u`, take the proof-of-possession key from its `cnf`, then verify `proof` against that key with `audience` and `wit`. Recovering the key from the WIT rather than from the vector is the point — it is what catches a break in the WIT-to-WPT binding.
- Run every negative case against the proof-of-possession key.

Note `wit-binding-mismatch`: the substituted WIT is itself perfectly valid and signed by the same issuer for the same key. Only `wth` distinguishes them. An implementation that checks the signature but not the binding will pass everything else and fail here.

### `httpsig`

- Re-sign `request` with `components`, `params`, `label` and the proof-of-possession seed; both `signature_input` and `signature` must match byte for byte. The signature base is byte-exact (RFC 9421 section 2.5); whitespace and quoting are not free choices.
- Verify the full chain: verify `wit`, take the proof-of-possession key from its `cnf`, then verify the signature over `request`, requiring every component in `components` to be covered.
- Check `verify_content_digest(Content-Digest header, body)`.
- Run every negative case. `required_components`, `accept_label` and `max_age` are verifier configuration, not message content: they describe how strict the receiver is, and the case asserts that a receiver configured that way rejects the message.

The `tampered-body` case is deliberately not a signature failure. The signature covers the `Content-Digest` **header string**, which is untouched, so the signature still verifies — the body is caught by the digest check alone. An implementation that only verifies signatures and never re-hashes the body will accept a swapped payload.

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

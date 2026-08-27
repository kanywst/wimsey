#!/usr/bin/env bash
# Seeds each fuzz target's corpus from the conformance vectors.
#
# The vectors already hold well-formed tokens, signatures and certificates, so
# handing them to the fuzzer starts it inside the shape the parsers care about
# instead of making it rediscover "three base64url parts separated by dots"
# from random bytes. It also means the corpus has one definition rather than a
# directory of opaque blobs nobody can regenerate.
#
# Usage: fuzz/seed-corpus.sh [conformance-dir]
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
vectors=${1:-$here/../conformance}

write() { # write <target> <name> <<< content
  local dir="$here/corpus/$1"
  mkdir -p "$dir"
  cat > "$dir/seed-$2"
}

# Identifiers: everything the parser must accept, and everything it must not.
jq -r '[.accept[].identifier, .reject[].identifier] | .[]' \
  "$vectors/identifier/parse-basic.json" |
  while IFS= read -r id; do
    printf '%s' "$id" | write identifier_parse "id-$(printf '%s' "$id" | shasum | cut -c1-8)"
  done

# Tokens, including the negative cases: those are the interesting ones, being
# well-formed enough to reach deep into the parser before being refused.
jq -r '[.token] + [.negative[].token // empty] | .[]' \
  "$vectors"/wit/issue-*.json |
  while IFS= read -r token; do
    printf '%s' "$token" | write wit_verify "wit-$(printf '%s' "$token" | shasum | cut -c1-8)"
  done

jq -r '[.proof] + [.negative[].proof // empty] | .[]' \
  "$vectors"/wpt/proof-*.json |
  while IFS= read -r proof; do
    printf '%s' "$proof" | write wpt_verify "wpt-$(printf '%s' "$proof" | shasum | cut -c1-8)"
  done

jq -r '[.signature_input] + [.negative[].signature_input // empty]
       + [.response.signature_input // empty]
       + [.response.negative[]?.signature_input // empty] | .[]' \
  "$vectors"/httpsig/sign-*.json |
  while IFS= read -r input; do
    printf '%s' "$input" | write httpsig_verify "sig-$(printf '%s' "$input" | shasum | cut -c1-8)"
  done

# Every JWK the vectors carry: confirmation keys, issuer keys, and the private
# ones. A JWK reaches a parser from a `cnf` claim and from a fetched JWKS, so
# both shapes are worth seeding.
jq -c '[.claims.cnf.jwk // empty, .issuer_verifying_key // empty,
        .issuer_signing_key // empty, .pop_signing_key // empty,
        .ca_signing_key // empty, .workload_signing_key // empty] | .[]' \
  "$vectors"/*/*.json 2>/dev/null | sort -u |
  while IFS= read -r jwk; do
    printf '%s' "$jwk" | write jwk_parse "jwk-$(printf '%s' "$jwk" | shasum | cut -c1-8)"
  done

# Certificates are base64url in the vector and raw DER to the parser.
jq -r '[.wic_der_b64u, .ca_certificate_der_b64u]
       + [.negative[].wic_der_b64u // empty] | .[]' \
  "$vectors"/mtls/wic-*.json |
  while IFS= read -r b64u; do
    printf '%s' "$b64u" | tr '_-' '/+' | base64 -d 2>/dev/null |
      write wic_parse "wic-$(printf '%s' "$b64u" | shasum | cut -c1-8)" || true
  done

for dir in "$here"/corpus/*/; do
  printf '%s: %s seeds\n' "$(basename "$dir")" "$(find "$dir" -name 'seed-*' | wc -l | tr -d ' ')"
done

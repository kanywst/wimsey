# Fuzzing

Every WIMSE credential arrives as bytes from somebody else. A WIT is three base64url segments and two JSON documents, a `Signature-Input` is a hand-parsed structured field, a WIC is DER — and all of it is parsed *before* anything has been authenticated. A panic in that code is a denial of service reachable by anyone who can reach the port.

These targets exist to keep that surface honest. They run under [cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html), which needs a nightly toolchain for libFuzzer's instrumentation; the rest of the workspace stays on stable.

## Targets

| Target | What it feeds |
| --- | --- |
| `identifier_parse` | `WorkloadIdentifier::parse`, then every accessor, since they slice the stored string by offsets the parser computed |
| `wit_verify` | A compact JWS as a WIT: base64url segments, a JOSE header, a claim set |
| `wpt_verify` | A proof, plus the WIT string it is bound to, plus the audience |
| `httpsig_verify` | `Signature-Input` and `Signature`, plus a header name and value that reach the signature base |
| `wic_parse` | DER X.509, both as a presented certificate and as the trust anchor it is checked against |

Nothing is expected to verify. What is being tested is that every rejection is a returned error rather than a panic, an overflow, or a hang.

`identifier_parse` goes further and asserts round-trip properties on whatever it accepts: the input is returned unmodified, the origin is a prefix, the origin and path partition the identifier, and re-parsing lands in the same place. That last one is what whole-URI comparison depends on, so it is worth having a fuzzer looking for a counter-example rather than only the unit tests.

## Running them

```bash
cargo install cargo-fuzz
rustup toolchain install nightly

# Seed each corpus from the conformance vectors first. Skipping this makes the
# fuzzer rediscover "three base64url segments separated by dots" from random
# bytes, which wastes most of a short run.
./fuzz/seed-corpus.sh

cargo +nightly fuzz run httpsig_verify
```

It runs until it finds something or you stop it. To bound it:

```bash
cargo +nightly fuzz run httpsig_verify -- -max_total_time=600
```

A crash is written to `fuzz/artifacts/<target>/` and replays with:

```bash
cargo +nightly fuzz run httpsig_verify fuzz/artifacts/httpsig_verify/crash-<hash>
```

## The corpus comes from the conformance vectors

`seed-corpus.sh` extracts seeds from `conformance/` rather than committing a directory of opaque blobs. The vectors already hold well-formed tokens, signatures and certificates, including the negative cases — which are the valuable seeds, being well-formed enough to reach deep into a parser before being refused.

It also means the corpus has one definition. A blob nobody can regenerate is a blob nobody will maintain.

Corpora and crash artifacts are not committed; `.gitignore` covers both.

## What CI does, and does not

CI runs each target for 30 seconds against the seeded corpus. That is a regression gate: long enough to catch a parser that panics on something the vectors already cover, short enough that nobody starts skipping CI.

It is not a hunt. Finding new bugs needs runs measured in hours, which is what the commands above are for. If a longer local run turns something up, add the crashing input to the conformance vectors as a negative case — then it is covered by the suite forever, in every implementation, not just by a fuzzer that happens to be run again.

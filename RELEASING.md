# Releasing

## Cadence

Releases are **time-based, not feature-based**: cut one at least every six weeks even if the only changes are dependency bumps. Waiting for a feature to be ready is how a project quietly goes stale, and how the gap between what users run and what the tree contains grows until upgrading is a project of its own.

A release with nothing but `deps:` and `ci:` commits is a legitimate release.

## Versioning

The project is pre-1.0, so [SemVer](https://semver.org/) reads as: breaking changes bump the **minor**, everything else bumps the **patch**.

Determine the bump from the [Conventional Commits](https://www.conventionalcommits.org/) since the last tag — `fix:` is a patch, `feat:` is a minor, `!` is breaking — with one rule that is easy to miss:

> A dependency bump is a breaking change if that dependency's types are part of our public API.

`wimsey-wit`, `wimsey-wpt` and `wimsey-httpsig` each carry `pub use ed25519_dalek::{SigningKey, VerifyingKey}`. Bumping `ed25519-dalek` across a major therefore breaks every caller holding the old version's keys, even though no line of our own code changed. That is what made 0.2.0 a minor release out of ten commits that were all `deps:` and `ci:`.

## Cutting a release

1. Take stock of what has landed:

   ```bash
   git log --oneline "$(git describe --tags --abbrev=0)"..HEAD
   ```

2. Decide the version per the rules above.

3. Update `[workspace.package] version` in the root `Cargo.toml`. Every crate inherits it with `version.workspace = true`, so this is the only version to edit — but the `wimsey-*` entries under `[workspace.dependencies]` pin a `version` too, and those must move in step.

   Every internal dependency belongs in that one table. A crate that pins a sibling inline, as `{ path = "../mtls", version = "0.2.0" }`, is a version that will be missed on some future release and only surface as a publish failure.

4. Add the section to `CHANGELOG.md` and update the link definitions at the bottom. Say what changed *for a caller*; if nothing observable changed, say that explicitly and say what drove the bump.

5. Refresh `Cargo.lock` and verify:

   ```bash
   cargo check --workspace
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace --all-targets
   cargo test --workspace --doc
   cargo run -q -p wimsey-conformance -- run --dir conformance
   ```

6. Open a `chore(release): X.Y.Z` PR, let CI pass, merge it.

7. Tag the merge commit and push the tag:

   ```bash
   git checkout main && git pull --ff-only
   git tag -a vX.Y.Z -m "wimsey X.Y.Z"
   git push origin vX.Y.Z
   ```

Pushing the tag is the trigger; everything after it is automated, including the crates.io publish.

## What the tag triggers

`.github/workflows/release.yml` runs on any `v*` tag:

| Stage | What it does |
| --- | --- |
| `guard` | Refuses to go further unless the tag, `[workspace.package] version` and a `## [X.Y.Z]` section in `CHANGELOG.md` all agree |
| `build` | Builds `wimsey` natively for four targets: x86-64 and arm64 Linux, x86-64 and Apple-silicon macOS |
| `publish` | SPDX SBOM, `SHA256SUMS`, a cosign keyless Sigstore bundle for every asset, SLSA build provenance for the tarballs, then creates the release and uploads it all |
| `crates-io` | Publishes the workspace to crates.io, only if `publish` succeeded |

The guard exists because the failure it prevents is silent: a tag that says `v0.3.0` on a tree that still says `0.2.0` produces a release whose binaries report the wrong version, and nobody notices until someone files a confusing bug.

The workflow also takes a `workflow_dispatch` with a tag input, for retrying a release whose `publish` stage failed partway or attaching artifacts to an older tag. Every step is idempotent — assets are uploaded with `--clobber` and the verification notes are appended only if absent — so a re-run replaces rather than duplicates:

```bash
gh workflow run release.yml -f tag=vX.Y.Z
```

One thing to understand about a dispatched run: **the Sigstore identity follows the ref the workflow ran from, not the tag it built**. A tag push signs as `…/release.yml@refs/tags/vX.Y.Z`; a dispatch from `main` signs as `…/release.yml@refs/heads/main`. Both are honest statements of what produced the assets, and the workflow writes whichever one applies into the release notes. A tag push is the better provenance, so back-filling is for repair, not the normal path.

Signing is keyless, so there is no release key anywhere — the Sigstore certificate binds each signature to this repository's release workflow at the ref described above. Each asset gets a `<name>.sigstore.json` bundle holding its signature and certificate together, which is what cosign v4 wants; the separate `--output-signature`/`--output-certificate` pair is deprecated and silently ignored. The published notes carry the `cosign verify-blob` invocation with the identity that actually signed, so the verification instructions land on the page people actually download from — and match what they are verifying.

## What is deliberately not automated

**Version bumping and the changelog.** The obvious candidates are [release-please](https://github.com/googleapis/release-please) and [release-plz](https://release-plz.dev/), and both are a poor fit as things stand:

- This workspace sets the version once in `[workspace.package]` and inherits it everywhere with `version.workspace = true`. Neither tool's handling of that inheritance is something to take on faith — release-please's `cargo-workspace` plugin is built around per-crate `version` fields, and release-plz derives the next version by comparing against what is published on crates.io, which this project is not.
- The manual work is one line in `Cargo.toml` and a changelog section, a few times a year. The automation would carry more configuration surface and more failure modes than the thing it replaces.

This is worth revisiting — but by trialling one of them on a branch and watching what it does to the root manifest, not by adopting it and finding out during a release.

**Publishing to crates.io.** Automated, but gated. The `crates-io` job in `release.yml` runs after the signed release succeeds, so nothing reaches a registry it cannot be withdrawn from until the tag has produced verified artifacts. A version can be yanked but never deleted, and the name is taken forever.

It runs one command:

```bash
cargo publish --workspace --locked
```

`--workspace` walks the crates in dependency order and waits for each to land on the index before the next resolves it — the tedious part, and the part that is easy to get wrong by hand. Crates marked `publish = false` are skipped by cargo itself, so those decisions live in the manifests rather than in a list inside the workflow:

| Crate | Why it is not published |
| --- | --- |
| `wimsey-conformance` | A harness, not a library |
| `wimsey-demo` | A demo, not a library |
| `wimsey-issuer` | Performs no workload attestation — it mints a WIT for anyone who asks. Publishing it puts `cargo install wimsey-issuer` one command away from a running, unauthenticated credential minter, for someone who never read the warning |

Two things have to be set up once:

- **`CARGO_REGISTRY_TOKEN`** as a repository secret, from <https://crates.io/settings/tokens>. The first publish needs the `publish-new` scope, which cannot be restricted to crates that do not exist yet; afterwards the token can be rotated for one scoped to `publish-update` on the `wimsey-*` crates only.
- **A `crates-io` environment** with a required reviewer, under Settings → Environments. The job names that environment, so adding the rule turns the one irreversible step in the release into something a human has to approve. Without the rule the job still runs, just unattended.

A partial failure — some crates uploaded, then an error — is the one case needing hands. Re-running the job will fail on the versions already published, so finish the remainder with `cargo publish -p <crate>` in dependency order.

Before releasing, confirm the packages actually contain what they claim to:

```bash
cargo package -p wimsey-identifier --list   # README.md and LICENSE must be present
```

Both are easy to lose. `readme` has to be set per crate, and `LICENSE` has to sit *inside* each crate directory — a copy at the workspace root is outside every package, which means shipping an Apache-2.0 crate with no licence text.

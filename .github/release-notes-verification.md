## Verifying this release

Every asset is signed with [cosign](https://docs.sigstore.dev/) keyless, so there is no long-lived key to leak or rotate. The certificate binds the signature to the workflow run that produced these assets — a signature made by anything else will not verify, whatever the file is called.

Start with `SHA256SUMS`: verify its signature, then let it vouch for everything else.

```bash
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "__IDENTITY__" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

sha256sum --check --ignore-missing SHA256SUMS
```

The identity above is the exact one these assets were signed under. It usually ends in `refs/tags/__TAG__`; if it ends in a branch instead, the assets were attached by a re-run of the release workflow from that branch rather than by the original tag push.

Each asset also has its own `<name>.sigstore.json` bundle, carrying that asset's signature and certificate together, if you would rather verify one directly.

The tarballs carry SLSA build provenance, which says which workflow run built them from which commit:

```bash
gh attestation verify wimsey-__TAG__-<target>.tar.gz --repo __REPO__
```

An SPDX software bill of materials is attached as `wimsey-__TAG__-sbom.spdx.json`.

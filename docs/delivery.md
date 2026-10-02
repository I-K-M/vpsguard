# Delivery and verification

PRs run with read-only repository permissions on disposable GitHub-hosted runners. Actions are pinned to commits. Only a successful semantic-version tag run can publish; the publication job receives tested payloads, checks SHA256SUMS, attests provenance and signs/verifies the checksum file with the exact workflow identity. It performs no repository checkout.

To create a release, review the commit, tag it `vX.Y.Z` and push that tag. Releases are never created automatically from arbitrary main commits. The tag pipeline reruns required tests. A release workflow is implemented here; successful main CI alone does not prove a release has been published.

Verify downloads before execution:

```bash
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/I-K-M/vpsguard/.github/workflows/security.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum --check SHA256SUMS
gh attestation verify ARTIFACT --repo I-K-M/vpsguard
```

Replace vpsguard, version and ARTIFACT with the actual repository and release. A valid signature proves artifact integrity and workflow identity, not absence of vulnerabilities.

Require `CI passed` on main, prohibit force pushes/deletion, limit bypasses and enable private vulnerability reporting in repository settings. CODEOWNERS alone does not enforce review. These administrative settings cannot be supplied by a workflow. Full CI evidence is retained for 30 days. No license is assumed for repository-owned code; third-party components retain their own licenses.

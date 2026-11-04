#!/usr/bin/env bash
# Verify OHTTP images signed with cosign + SLSA attestation
set -euo pipefail

usage() {
  cat <<USAGE
Usage: $0 <image>@<digest>

Verifies:
1. Cosign signature (keyless, GitHub OIDC)
2. SLSA provenance attestation

Accepted signers (certificate identities, matched as whole strings):
  https://github.com/\$GITHUB_ORG/\$GITHUB_REPO/.github/workflows/ohttp-build.yml@refs/heads/main
  https://github.com/\$GITHUB_ORG/\$GITHUB_REPO/.github/workflows/ohttp-build.yml@refs/tags/v<N>...
  https://github.com/\$GITHUB_ORG/\$GITHUB_REPO/.github/workflows/sign-existing-image.yml@refs/heads/main
(GITHUB_ORG defaults to zodl-inc, GITHUB_REPO to zodl-ohttp.)

Example:
  $0 your-registry.example.com/ohttp-gateway@sha256:abc123...
USAGE
  exit 1
}

# Escape every regex metacharacter of a literal string (Go RE2 / POSIX ERE).
re_escape() {
  printf '%s' "$1" | sed -e 's/[]\.*^$+?(){}|[]/\\&/g'
}

GITHUB_ORG="${GITHUB_ORG:-zodl-inc}"
GITHUB_REPO="${GITHUB_REPO:-zodl-ohttp}"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

# Anchored identity regexes. Only main (and, for the build workflow, which also signs on tag
# pushes, release tags v<digit>...) may sign: a workflow run from any other branch is refused.
build_identities() {
  local base
  base="^$(re_escape "https://github.com/$GITHUB_ORG/$GITHUB_REPO/.github/workflows/")"
  EXPECTED_IDENTITY_BUILD="${base}ohttp-build\\.yml@refs/(heads/main|tags/v[0-9][0-9A-Za-z._+-]*)\$"
  EXPECTED_IDENTITY_SIGN="${base}sign-existing-image\\.yml@refs/heads/main\$"
}

main() {
  [[ $# -eq 1 ]] || usage
  local IMAGE="$1"
  build_identities

  echo "Verifying $IMAGE"
  echo "Accepted workflow identities:"
  echo "  - Build: $EXPECTED_IDENTITY_BUILD"
  echo "  - Sign:  $EXPECTED_IDENTITY_SIGN"
  echo

  echo "==> Verifying cosign signature..."
  # Try build workflow identity first, then signing workflow
  if cosign verify \
    --certificate-identity-regexp "$EXPECTED_IDENTITY_BUILD" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    "$IMAGE" &>/dev/null; then
    echo "✓ Signature verified (build workflow)"
  elif cosign verify \
    --certificate-identity-regexp "$EXPECTED_IDENTITY_SIGN" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    "$IMAGE" &>/dev/null; then
    echo "✓ Signature verified (signing workflow)"
  else
    echo "✗ Signature verification FAILED"
    exit 1
  fi

  echo
  echo "==> Verifying SLSA provenance attestation..."
  # Try build workflow identity first, then signing workflow
  if cosign verify-attestation \
    --type slsaprovenance \
    --certificate-identity-regexp "$EXPECTED_IDENTITY_BUILD" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    "$IMAGE" &>/dev/null; then
    echo "✓ Attestation verified (build workflow)"
  elif cosign verify-attestation \
    --type slsaprovenance \
    --certificate-identity-regexp "$EXPECTED_IDENTITY_SIGN" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    "$IMAGE" &>/dev/null; then
    echo "✓ Attestation verified (signing workflow)"
  else
    echo "✗ Attestation verification FAILED"
    exit 1
  fi

  echo
  echo "✓ All verifications passed for $IMAGE"
}

# Sourced (scripts/verify-image-test.sh): define the functions only.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi

#!/usr/bin/env bash
# Verify OHTTP images signed with cosign + SLSA attestation
set -euo pipefail

usage() {
  cat <<USAGE
Usage: $0 [--commit <sha> [--allow-sign-existing]] <image>@<digest>

Verifies:
1. Cosign signature (keyless, GitHub OIDC)
2. SLSA provenance attestation (naming this digest; with --commit, also that source commit)

Accepted signers (certificate identities, matched as whole strings):
  https://github.com/\$GITHUB_ORG/\$GITHUB_REPO/.github/workflows/ohttp-build.yml@refs/heads/main
  https://github.com/\$GITHUB_ORG/\$GITHUB_REPO/.github/workflows/sign-existing-image.yml@refs/heads/main
  https://github.com/\$GITHUB_ORG/\$GITHUB_REPO/.github/workflows/ohttp-build.yml@refs/tags/v<version>
    only for the digests listed with that version in legacy-release-digests.txt: the
    ohttp-e2e 1.0.1 image and the three 1.1.0 images, which their tag builds rebuilt and
    signed. The three 1.0.0 images verify through the main build's identity. The ohttp-gateway
    and ohttp-relay-simulator 1.0.1 images were never signed and cannot be verified.
(GITHUB_ORG defaults to zodl-inc, GITHUB_REPO to zodl-ohttp; VERIFY_LEGACY_DIGESTS overrides
the allowlist file.)

A release image (version tag) is the sha-<short> digest of its commit, promoted without a
rebuild or a new signature: it verifies through the main build's signature and attestation.
Platform images of an index carry their own signature and attestation (images published
after this rule; older ones only through their index).

Without --commit, any of the identities above verifies, and the commit is not checked.

--commit <sha>: only identities whose certificates are bound to <sha> are accepted: the main
build and the legacy tag builds, whose certificates must have been issued to a run at <sha>
(certificate workflow SHA); their attestation must also name <sha> as its source commit.
--allow-sign-existing also accepts the Sign Existing Image identity, whose certificate is bound
to the commit that workflow ran at, not to the image's: for it, the only link to <sha> is the
source commit its attestation names (a weaker guarantee).

The attestation must name the image: its subject is named after the image's repository
(<registry>/<image>, so the image must be verified under its own repository name, not under a
copy with another name), and a predicate that names the image (invocation.parameters.image,
images published since the predicate carries it) must name this one. Images published before
carry only the subject name, which binds them alone.

The output names the image by its short name and digest; IMAGE_TOOLS_VERBOSE=1 (or
RUNNER_DEBUG=1) shows the tool output, which carries full registry references.

Example:
  $0 your-registry.example.com/ohttp-gateway@sha256:abc123...
USAGE
  exit 1
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=image-lib.sh
source "$SCRIPT_DIR/image-lib.sh"

GITHUB_ORG="${GITHUB_ORG:-zodl-inc}"
GITHUB_REPO="${GITHUB_REPO:-zodl-ohttp}"
LEGACY_DIGESTS="${VERIFY_LEGACY_DIGESTS:-$SCRIPT_DIR/legacy-release-digests.txt}"

# Anchored identity regexes. Only main may sign: a workflow run from any other branch or tag is
# refused. Release tags no longer sign (scripts/promote-image.sh only adds the version tag to the
# main build's signed digest); the tag identity is accepted only through the allowlist below.
build_identities() {
  local repository="$GITHUB_ORG/$GITHUB_REPO"
  EXPECTED_IDENTITY_BUILD="$(workflow_identity "$repository" ohttp-build.yml refs/heads/main)"
  EXPECTED_IDENTITY_SIGN="$(workflow_identity "$repository" sign-existing-image.yml refs/heads/main)"
}

# Identity of the tag build of a legacy release.
legacy_identity() {
  workflow_identity "$GITHUB_ORG/$GITHUB_REPO" ohttp-build.yml "refs/tags/v$1"
}

# Versions under which <name> <digest> is allowlisted (well-formed lines only).
legacy_versions() {
  local name="$1" digest="$2" img ver dig rest
  [[ -f "$LEGACY_DIGESTS" ]] || return 0
  while read -r img ver dig rest; do
    [[ "$img" =~ $IMAGES_RE && "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$dig" =~ $DIGEST_RE && -z "$rest" ]] ||
      continue
    if [[ "$img" == "$name" && "$dig" == "$digest" ]]; then
      printf '%s\n' "$ver"
    fi
  done <"$LEGACY_DIGESTS"
}

main() {
  local commit="" commit_given=0 allow_sign_existing=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --commit)
        [[ $# -ge 2 ]] || usage
        commit="$2"
        commit_given=1
        shift 2
        ;;
      --allow-sign-existing) allow_sign_existing=1; shift ;;
      -h | --help) usage ;;
      -*) usage ;;
      *) break ;;
    esac
  done
  [[ $# -eq 1 ]] || usage
  if [[ $commit_given -eq 1 && ! "$commit" =~ $COMMIT_RE ]]; then
    echo "error: --commit needs a full 40-hex commit SHA" >&2
    usage
  fi
  [[ $allow_sign_existing -eq 0 || $commit_given -eq 1 ]] || die "--allow-sign-existing needs --commit"
  local IMAGE="$1" digest name
  digest="${IMAGE##*@}"
  [[ "$IMAGE" == *@* && "$digest" =~ $DIGEST_RE ]] || die "give the image as <image>@sha256:<digest>"
  name="${IMAGE%@*}"
  name="${name##*/}"
  name="${name%%:*}"
  [[ "$name" =~ $IMAGES_RE ]] ||
    die "the image must be named ohttp-gateway, ohttp-relay-simulator or ohttp-e2e (its repository name)"
  build_identities

  # label|identity|certificate workflow SHA
  local -a ids=("build workflow|$EXPECTED_IDENTITY_BUILD|$commit")
  # With --commit, the signing workflow (not bound to the commit by its certificate) only on
  # request; its attestation must then name the commit.
  if [[ -z "$commit" || $allow_sign_existing -eq 1 ]]; then
    ids+=("signing workflow|$EXPECTED_IDENTITY_SIGN|")
  fi
  local v
  while read -r v; do
    [[ -n "$v" ]] && ids+=("v$v tag build (allowlisted legacy release)|$(legacy_identity "$v")|$commit")
  done < <(legacy_versions "$name" "$digest")

  echo "Verifying $name@$digest"
  echo "Accepted workflow identities:"
  local entry rest label identity wsha
  for entry in "${ids[@]}"; do
    echo "  - ${entry%%|*}: $(cut -d'|' -f2 <<<"$entry")"
  done
  if [[ -n "$commit" ]]; then echo "Source commit: $commit"; fi
  echo

  echo "==> Verifying cosign signature..."
  local ok=""
  for entry in "${ids[@]}"; do
    label="${entry%%|*}"
    rest="${entry#*|}"
    identity="${rest%|*}"
    wsha="${rest##*|}"
    if signature_verified "$IMAGE" "$identity" "$wsha"; then ok="$label"; break; fi
  done
  if [[ -z "$ok" ]]; then
    echo "✗ Signature verification FAILED"
    exit 1
  fi
  echo "✓ Signature verified ($ok)"

  echo
  echo "==> Verifying SLSA provenance attestation..."
  ok=""
  for entry in "${ids[@]}"; do
    label="${entry%%|*}"
    rest="${entry#*|}"
    identity="${rest%|*}"
    wsha="${rest##*|}"
    if attestation_verified "$IMAGE" "$digest" "$identity" "$wsha" "$commit" "$name" subject; then
      ok="$label"
      break
    fi
  done
  if [[ -z "$ok" ]]; then
    echo "✗ Attestation verification FAILED"
    exit 1
  fi
  echo "✓ Attestation verified ($ok)"

  echo
  echo "✓ All verifications passed for $name@$digest"
}

# Sourced (scripts/verify-image-test.sh): define the functions only.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi

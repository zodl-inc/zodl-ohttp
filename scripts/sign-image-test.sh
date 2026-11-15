#!/usr/bin/env bash
# Copyright © 2026 Znewco, Inc. (d/b/a Zcash Open Development Lab)
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of ZODL OHTTP.
#
# ZODL OHTTP is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License,
# version 3 only, as published by the Free Software Foundation.
#
# ZODL OHTTP is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Affero General Public License for more details.
#
# Commercial licensing: see COMMERCIAL-LICENSE.md.

# Checks sign-image.sh against the fake registry of testing/fake-registry.sh (stub tools, no
# network): what is signed and attested, re-runs on immutable signature tags, failures.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testing/fake-registry.sh
source "$SCRIPT_DIR/testing/fake-registry.sh"
# shellcheck source=image-lib.sh
source "$SCRIPT_DIR/image-lib.sh"

# The tests run outside a workflow's main-branch guard (CI runs them on pull requests).
export GITHUB_ACTIONS=false
fail=0
expect() {
  local want="$1" got=ok
  shift
  if ! out="$("$@" 2>&1)"; then got=fail; fi
  if [[ "$got" != "$want" ]]; then
    echo "FAIL: $got (want $want): $*"
    printf '%s\n' "$out" | sed 's/^/    /'
    fail=1
  fi
}
contains() {
  if ! grep -qF -- "$1" <<<"$out"; then
    echo "FAIL: output lacks: $1"
    printf '%s\n' "$out" | sed 's/^/    /'
    fail=1
  fi
}
writes() { fake_writes | awk '{ print $1 }' | sort | uniq -c | awk '{ printf "%s=%s ", $2, $1 }'; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
R=registry.example.com/private
C=0123456789abcdef0123456789abcdef01234567
OTHER=89abcdef0123456789abcdef0123456789abcdef
REPO=example-org/example-repo
E="https://github.com/$REPO/.github/workflows"
MAIN="$E/ohttp-build.yml@refs/heads/main"
SIGN="$E/sign-existing-image.yml@refs/heads/main"
BUILD_ID="$(workflow_identity "$REPO" ohttp-build.yml refs/heads/main)"
n=0
fresh() {
  n=$((n + 1))
  rm -rf "$tmp/reg"
  fake_registry_init "$tmp/reg"
  fake_release_image "$R/ohttp-gateway" sha-0123456 "$C" --nonce "$n" "$@"
}
SI() {
  bash "$SCRIPT_DIR/sign-image.sh" --registry "$R" --image ohttp-gateway --digest "$FAKE_DIGEST" \
    --repository "$REPO" --run-id 42 "$@"
}
as_signer() { FAKE_SIGNER_IDENTITY="$1" FAKE_SIGNER_SHA="$2" SI "${@:3}"; }
build() {
  FAKE_SIGNER_IDENTITY="$MAIN" FAKE_SIGNER_SHA="$C" \
    SI --workflow ohttp-build.yml --commit "$C" --workflow-sha "$C" "$@"
}

# A new index: the index and both platform images are signed and attested once.
fresh --no-sign --no-attest
expect ok build --started-on 2026-01-01T00:00:00Z
[[ "$(writes)" == "attest=3 sign=3 " ]] || { echo "FAIL: writes $(writes)"; fail=1; }
for d in "$FAKE_DIGEST" "${FAKE_PLATFORMS[@]}"; do
  signature_verified "$R/ohttp-gateway@$d" "$BUILD_ID" "$C" || { echo "FAIL: $d not signed"; fail=1; }
  attestation_verified "$R/ohttp-gateway@$d" "$d" "$BUILD_ID" "$C" "$C" || { echo "FAIL: $d not attested"; fail=1; }
done
# The predicate: this repository, the commit, the start time, no completeness claim.
stmt="$(cut -f3 "$FAKE_STORE/atts/$FAKE_DIGEST")"
jq -e --arg c "$C" '.predicate
  | .buildType == "https://github.com/example-org/example-repo/.github/workflows/ohttp-build.yml@main"
    and .invocation.configSource.uri == "https://github.com/example-org/example-repo"
    and .invocation.configSource.digest.sha1 == $c
    and .materials == [{uri: "https://github.com/example-org/example-repo", digest: {sha1: $c}}]
    and .metadata.buildStartedOn == "2026-01-01T00:00:00Z"
    and .metadata.completeness.parameters == false
    and .invocation.parameters.image == "ohttp-gateway"' >/dev/null <<<"$stmt" ||
  { echo "FAIL: predicate $stmt"; fail=1; }
if grep -q "registry.example.com" <<<"$out"; then echo "FAIL: the registry is logged"; fail=1; fi
jq -e '.subject[0].name | endswith("/ohttp-gateway")' >/dev/null <<<"$stmt" ||
  { echo "FAIL: the subject is not named after the image"; fail=1; }
# An attestation of another image (same digest, predicate naming ohttp-e2e) does not count as
# done for ohttp-gateway, and the image-bound check refuses it.
attestation_verified "$R/ohttp-gateway@$FAKE_DIGEST" "$FAKE_DIGEST" "$BUILD_ID" "$C" "$C" ohttp-e2e &&
  { echo "FAIL: an ohttp-gateway attestation verified as ohttp-e2e"; fail=1; }

# A re-run writes nothing (immutable signature tags would refuse it).
: >"$FAKE_STORE/writes"
expect ok build --started-on 2026-01-01T00:00:00Z
[[ -z "$(writes)" ]] || { echo "FAIL: re-run wrote $(writes)"; fail=1; }
contains "already signed, kept"

# A publish that failed after the index: only the platform images are completed.
fresh --index-only
expect ok build
[[ "$(writes)" == "attest=2 sign=2 " ]] || { echo "FAIL: partial writes $(writes)"; fail=1; }

# A signature at another commit does not count as done; the immutable tag then refuses the
# new signature and the run fails rather than claiming success.
fresh --no-attest
echo -n >"$FAKE_STORE/sigs/$FAKE_DIGEST"
fake_sign "$FAKE_DIGEST" "$MAIN" "$OTHER"
expect fail build
contains "signing failed"

# Failures: missing digest, wrong commit, unlabelled platform, mixed revisions, registry error.
fresh --no-sign --no-attest
digest="$FAKE_DIGEST"
FAKE_DIGEST="sha256:$(printf 'e%.0s' $(seq 1 64))"
expect fail build
contains "does not exist"
FAKE_DIGEST="$digest"
expect fail as_signer "$MAIN" "$C" --workflow ohttp-build.yml --commit "$OTHER"
contains "expected $OTHER"
fresh --no-sign --no-attest --no-labels linux/arm64
expect fail build
contains "has no org.opencontainers.image.revision label"
fresh --no-sign --no-attest --revision linux/arm64 "$OTHER"
expect fail build
contains "different revisions"
fresh --no-sign --no-attest --revision linux/arm64 $'registry.example.com\n\e[31m'
expect fail build
contains "malformed revision label"
if grep -q "registry.example.com" <<<"$out"; then echo "FAIL: hostile label printed"; fail=1; fi
fresh --no-sign --no-attest
fake_fail "@sha256:"
expect fail build
contains "registry lookup failed"
[[ -z "$(writes)" ]] || { echo "FAIL: wrote despite a registry error"; fail=1; }

# A malformed descriptor after a valid first one: nothing is signed (the enumeration is checked
# as a whole before any write); nothing of it is printed.
fresh --no-sign --no-attest
jq -c '.manifests = [.manifests[0], {"platform": "sentinel.example.net"}] + .manifests[1:]' \
  "$FAKE_STORE/manifests/$FAKE_DIGEST" >"$tmp/idx" && cp "$tmp/idx" "$FAKE_STORE/manifests/$FAKE_DIGEST"
expect fail build
contains "malformed descriptor in the index"
[[ -z "$(writes)" ]] || { echo "FAIL: signed despite a malformed descriptor: $(writes)"; fail=1; }
if grep -q "sentinel.example.net" <<<"$out"; then echo "FAIL: malformed descriptor printed"; fail=1; fi

# In a workflow, only a run of main signs: anything else stops before any write.
fresh --no-sign --no-attest
for ref in refs/heads/feature refs/pull/1/merge refs/tags/v1.2.3 ""; do
  expect fail env GITHUB_ACTIONS=true GITHUB_REF="$ref" FAKE_SIGNER_IDENTITY="$MAIN" FAKE_SIGNER_SHA="$C" \
    bash "$SCRIPT_DIR/sign-image.sh" --registry "$R" --image ohttp-gateway --digest "$FAKE_DIGEST" \
    --repository "$REPO" --run-id 42 --workflow ohttp-build.yml --commit "$C" --workflow-sha "$C"
  contains "signing runs only from main"
done
[[ -z "$(writes)" ]] || { echo "FAIL: signed outside main: $(writes)"; fail=1; }
expect ok env GITHUB_ACTIONS=true GITHUB_REF=refs/heads/main FAKE_SIGNER_IDENTITY="$MAIN" FAKE_SIGNER_SHA="$C" \
  bash "$SCRIPT_DIR/sign-image.sh" --registry "$R" --image ohttp-gateway --digest "$FAKE_DIGEST" \
  --repository "$REPO" --run-id 42 --workflow ohttp-build.yml --commit "$C" --workflow-sha "$C"

# Every descriptor is checked before anything is excluded: one without a platform, an
# attestation descriptor (unknown/unknown) with a malformed digest, a platform of another
# charset. All fatal, nothing signed.
for filter in '.manifests += [{"digest": .manifests[0].digest}]' \
  '.manifests |= map(if .platform.os == "unknown" then .digest = "sentinel.example.net" else . end)' \
  '.manifests += [{"digest": .manifests[0].digest, "platform": {"os": "Linux!", "architecture": "amd64"}}]'; do
  fresh --no-sign --no-attest
  jq -c "$filter" "$FAKE_STORE/manifests/$FAKE_DIGEST" >"$tmp/idx" && cp "$tmp/idx" "$FAKE_STORE/manifests/$FAKE_DIGEST"
  expect fail build
  contains "malformed descriptor in the index"
  [[ -z "$(writes)" ]] || { echo "FAIL: signed with a malformed descriptor ($filter)"; fail=1; }
  if grep -q "sentinel.example.net" <<<"$out"; then echo "FAIL: malformed descriptor printed"; fail=1; fi
done

# Only the exact unknown/unknown form is left out: unknown/amd64 is a platform image (here
# without a configuration: refused before anything is signed).
fresh --no-sign --no-attest
jq -c '.manifests += [.manifests[] | select(.platform.os == "unknown") | .platform.architecture = "amd64"]' \
  "$FAKE_STORE/manifests/$FAKE_DIGEST" >"$tmp/idx" && cp "$tmp/idx" "$FAKE_STORE/manifests/$FAKE_DIGEST"
expect fail build
contains "cannot read the image configuration"
[[ -z "$(writes)" ]] || { echo "FAIL: signed with an unknown/amd64 descriptor: $(writes)"; fail=1; }

# Sign Existing Image: commit from the label, no buildStartedOn, its own identity; an earlier
# run of it (another workflow SHA) counts as done.
fresh --no-sign --no-attest
expect ok as_signer "$SIGN" "$OTHER" --workflow sign-existing-image.yml
[[ "$(writes)" == "attest=3 sign=3 " ]] || { echo "FAIL: sign-existing writes $(writes)"; fail=1; }
stmt="$(cut -f3 "$FAKE_STORE/atts/$FAKE_DIGEST")"
jq -e --arg c "$C" '.predicate | (.metadata | has("buildStartedOn") | not)
  and .invocation.configSource.digest.sha1 == $c
  and .invocation.configSource.entryPoint == ".github/workflows/sign-existing-image.yml"' >/dev/null <<<"$stmt" ||
  { echo "FAIL: sign-existing predicate $stmt"; fail=1; }
: >"$FAKE_STORE/writes"
expect ok as_signer "$SIGN" "$C" --workflow sign-existing-image.yml
[[ -z "$(writes)" ]] || { echo "FAIL: sign-existing re-run wrote $(writes)"; fail=1; }

# The stub, like cosign, refuses certificates of another OIDC issuer.
if cosign verify --certificate-identity-regexp '.*' --certificate-oidc-issuer https://issuer.example.com \
  "$R/ohttp-gateway@$FAKE_DIGEST" >/dev/null 2>&1 ||
  cosign verify --certificate-identity-regexp '.*' "$R/ohttp-gateway@$FAKE_DIGEST" >/dev/null 2>&1; then
  echo "FAIL: the cosign stub accepted a wrong or missing issuer"
  fail=1
fi

# Arguments.
expect fail SI --workflow other.yml
expect fail SI --workflow ohttp-build.yml --started-on yesterday
expect fail bash "$SCRIPT_DIR/sign-image.sh" --registry "$R" --image other --digest "$FAKE_DIGEST" \
  --workflow ohttp-build.yml --repository "$REPO" --run-id 42
expect fail bash "$SCRIPT_DIR/sign-image.sh" --registry "$R" --image ohttp-gateway --digest sha256:abc \
  --workflow ohttp-build.yml --repository "$REPO" --run-id 42

if [[ $fail -ne 0 ]]; then
  exit 1
fi
echo "sign-image: OK"

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

# Checks the certificate identity regexes of verify-image.sh against accepted and refused
# identities (grep -E; the constructs used behave the same in Go RE2, which cosign uses), the
# legacy release allowlist, and verify-image.sh end to end against the fake registry of
# testing/fake-registry.sh (stub cosign, no network).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
unset GITHUB_ORG GITHUB_REPO VERIFY_LEGACY_DIGESTS
# shellcheck source=verify-image.sh
source "$SCRIPT_DIR/verify-image.sh"
# shellcheck source=testing/fake-registry.sh
source "$SCRIPT_DIR/testing/fake-registry.sh"
build_identities

fail=0
check() {
  local want="$1" re="$2" id="$3" got=no
  if printf '%s\n' "$id" | grep -Eq -- "$re"; then got=yes; fi
  if [[ "$got" != "$want" ]]; then
    echo "FAIL: match=$got (want $want): $id"
    fail=1
  fi
}

W=https://github.com/zodl-inc/zodl-ohttp/.github/workflows
B="$EXPECTED_IDENTITY_BUILD"
S="$EXPECTED_IDENTITY_SIGN"

check yes "$B" "$W/ohttp-build.yml@refs/heads/main"
check yes "$S" "$W/sign-existing-image.yml@refs/heads/main"

check no "$B" "$W/ohttp-build.yml@refs/heads/feature"
check no "$B" "$W/ohttp-build.yml@refs/heads/main-evil"
check no "$B" "$W/ohttp-build.yml@refs/pull/1/merge"
# Release tags never sign; the legacy tag identities are not part of the build identity.
for t in v0.1.0 v1.0.0 v1.0.1 v1.1.0 v1.2.0 v1.2.3-rc.1 x1; do
  check no "$B" "$W/ohttp-build.yml@refs/tags/$t"
done
check no "$B" "$W/ohttp-buildXyml@refs/heads/main"
check no "$B" "https://githubXcom/zodl-inc/zodl-ohttp/.github/workflows/ohttp-build.yml@refs/heads/main"
check no "$B" "https://github.com/zodl-inc/zodl-ohttpX/.github/workflows/ohttp-build.yml@refs/heads/main"
check no "$B" "https://github.com/evil/zodl-ohttp/.github/workflows/ohttp-build.yml@refs/heads/main"
check no "$B" "$W/sign-existing-image.yml@refs/heads/main"
check no "$S" "$W/sign-existing-image.yml@refs/heads/feature"
check no "$S" "$W/sign-existing-image.yml@refs/tags/v0.1.0"
check no "$S" "$W/sign-existing-imageXyml@refs/heads/main"

# Legacy identity: exactly the version's tag.
L="$(legacy_identity 1.0.0)"
check yes "$L" "$W/ohttp-build.yml@refs/tags/v1.0.0"
check no "$L" "$W/ohttp-build.yml@refs/tags/v1x0x0"
check no "$L" "$W/ohttp-build.yml@refs/tags/v1.0.00"
check no "$L" "$W/ohttp-build.yml@refs/tags/v1.0.0-rc.1"
check no "$L" "$W/ohttp-build.yml@refs/heads/v1.0.0"

# Metacharacters in an override are literal.
GITHUB_ORG="a.b" GITHUB_REPO="c+d" build_identities
check yes "$EXPECTED_IDENTITY_BUILD" "https://github.com/a.b/c+d/.github/workflows/ohttp-build.yml@refs/heads/main"
check no "$EXPECTED_IDENTITY_BUILD" "https://github.com/aXb/ccd/.github/workflows/ohttp-build.yml@refs/heads/main"
build_identities

# The committed allowlist: every line a comment or `<image> <x.y.z> sha256:<64 hex>`, and
# exactly the images signed only by their tag build: ohttp-e2e 1.0.1 and the three 1.1.0
# images (the 1.0.0 images verify through the main build; gateway and relay-simulator 1.0.1
# were never signed).
listed=""
while IFS= read -r line; do
  [[ -z "$line" || "$line" == \#* ]] && continue
  if [[ ! "$line" =~ ^(ohttp-gateway|ohttp-relay-simulator|ohttp-e2e)\ (1\.0\.1|1\.1\.0)\ sha256:[0-9a-f]{64}$ ]]; then
    echo "FAIL: malformed or unexpected allowlist line: $line"
    fail=1
  fi
  listed+="$(awk '{ print $1, $2 }' <<<"$line")"$'\n'
done <"$SCRIPT_DIR/legacy-release-digests.txt"
want=$'ohttp-e2e 1.0.1\nohttp-e2e 1.1.0\nohttp-gateway 1.1.0\nohttp-relay-simulator 1.1.0'
if [[ "$(grep . <<<"$listed" | sort)" != "$want" ]]; then
  echo "FAIL: the allowlist must list exactly: $(tr '\n' ',' <<<"$want") (got $(grep . <<<"$listed" | sort | tr '\n' ','))"
  fail=1
fi

# ---- verify-image.sh end to end against the fake registry.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fake_registry_init "$tmp/reg"
R=registry.example.com/test
C=0123456789abcdef0123456789abcdef01234567
OTHER=89abcdef0123456789abcdef0123456789abcdef
E=https://github.com/example-org/example-repo/.github/workflows
export GITHUB_ORG=example-org GITHUB_REPO=example-repo
VI() { bash "$SCRIPT_DIR/verify-image.sh" "$@"; }
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

# Main build (incl. a promoted release image: the same digest).
fake_release_image "$R/ohttp-gateway" sha-0123456 "$C" --index-only \
  --identity "$E/ohttp-build.yml@refs/heads/main"
main_digest="$FAKE_DIGEST"
expect ok VI "$R/ohttp-gateway@$main_digest"
expect ok VI --commit "$C" "$R/ohttp-gateway@$main_digest"
expect fail VI --commit "$OTHER" "$R/ohttp-gateway@$main_digest"
expect fail VI "$R/ohttp-gateway:sha-0123456"
# --commit: a full SHA when given; no value, an empty or a short value is a usage error.
expect fail VI --commit
grep -q "Usage:" <<<"$out" || { echo "FAIL: --commit without a value is not a usage error"; fail=1; }
expect fail VI --commit "" "$R/ohttp-gateway@$main_digest"
grep -q "needs a full 40-hex commit SHA" <<<"$out" || { echo "FAIL: empty --commit"; fail=1; }
expect fail VI --commit "${C:0:7}" "$R/ohttp-gateway@$main_digest"
expect fail VI --commit "$R/ohttp-gateway@$main_digest"
expect fail VI --allow-sign-existing "$R/ohttp-gateway@$main_digest"
# The output names the image by short name and digest, not by registry.
expect ok VI "$R/ohttp-gateway@$main_digest"
if grep -q "registry.example.com" <<<"$out"; then echo "FAIL: the registry is printed"; fail=1; fi
grep -qF "Verifying ohttp-gateway@$main_digest" <<<"$out" || { echo "FAIL: short name missing"; fail=1; }
# Cross-SHA: signed and attested by a main build at workflow SHA D whose predicate names C.
fake_release_image "$R/ohttp-gateway" sha-3333333 "$C" --nonce cross --index-only \
  --identity "$E/ohttp-build.yml@refs/heads/main" --no-sign --no-attest
cross="$FAKE_DIGEST"
fake_sign "$cross" "$E/ohttp-build.yml@refs/heads/main" "$OTHER"
fake_attest "$cross" "$E/ohttp-build.yml@refs/heads/main" "$OTHER" "$C" "$cross" "$R/ohttp-gateway"
expect fail VI --commit "$C" "$R/ohttp-gateway@$cross"
expect fail VI --commit "$C" --allow-sign-existing "$R/ohttp-gateway@$cross"
expect ok VI "$R/ohttp-gateway@$cross"
# A platform image with its own signature and attestation (sign-image.sh) verifies; one without
# does not.
plat="${FAKE_PLATFORMS[0]}"
expect fail VI "$R/ohttp-gateway@$plat"
fake_sign "$plat" "$E/ohttp-build.yml@refs/heads/main" "$C"
fake_attest "$plat" "$E/ohttp-build.yml@refs/heads/main" "$C" "$C" "$plat" "$R/ohttp-gateway"
expect ok VI --commit "$C" "$R/ohttp-gateway@$plat"
# An attestation for another digest does not count.
fake_release_image "$R/ohttp-gateway" sha-1111111 "$C" --nonce wrong-subject \
  --identity "$E/ohttp-build.yml@refs/heads/main" --attest-subject "$main_digest"
expect fail VI "$R/ohttp-gateway@$FAKE_DIGEST"

# Tag build signatures: accepted only for an allowlisted digest under its own version.
fake_release_image "$R/ohttp-e2e" 1.0.0 "$C" --nonce legacy --identity "$E/ohttp-build.yml@refs/tags/v1.0.0"
legacy="$FAKE_DIGEST"
printf '# test allowlist\nohttp-e2e 1.0.0 %s\n' "$legacy" >"$tmp/allow.txt"
expect ok env VERIFY_LEGACY_DIGESTS="$tmp/allow.txt" bash "$SCRIPT_DIR/verify-image.sh" "$R/ohttp-e2e@$legacy"
grep -q "allowlisted legacy release" <<<"$out" || { echo "FAIL: legacy path not reported"; fail=1; }
expect ok env VERIFY_LEGACY_DIGESTS="$tmp/allow.txt" bash "$SCRIPT_DIR/verify-image.sh" --commit "$C" "$R/ohttp-e2e@$legacy"
# Not listed, listed under another version, another image, a placeholder, no file.
: >"$tmp/empty.txt"
printf 'ohttp-e2e 1.0.1 %s\n' "$legacy" >"$tmp/otherver.txt"
printf 'ohttp-gateway 1.0.0 %s\n' "$legacy" >"$tmp/otherimg.txt"
printf 'ohttp-e2e 1.0.0 sha256:PLACEHOLDER\n' >"$tmp/placeholder.txt"
printf 'ohttp-e2e 1.0.0 %s extra\n' "$legacy" >"$tmp/malformed.txt"
for f in empty otherver otherimg placeholder malformed missing; do
  expect fail env VERIFY_LEGACY_DIGESTS="$tmp/$f.txt" bash "$SCRIPT_DIR/verify-image.sh" "$R/ohttp-e2e@$legacy"
done
# The committed allowlist does not list the test digest.
expect fail VI "$R/ohttp-e2e@$legacy"
# A tag build signature of a non-legacy release is refused even when allowlisted by mistake.
fake_release_image "$R/ohttp-e2e" 1.2.0 "$C" --nonce newtag --identity "$E/ohttp-build.yml@refs/tags/v1.2.0"
printf 'ohttp-e2e 1.0.0 %s\n' "$FAKE_DIGEST" >"$tmp/newtag.txt"
expect fail env VERIFY_LEGACY_DIGESTS="$tmp/newtag.txt" bash "$SCRIPT_DIR/verify-image.sh" "$R/ohttp-e2e@$FAKE_DIGEST"
# Signing workflow signatures: certificate at the signing run's workflow SHA (D), predicate
# naming the image's commit C. Accepted without --commit; with --commit only on request, and
# then only for the commit the attestation names.
fake_release_image "$R/ohttp-relay-simulator" sha-0123456 "$C" --nonce sign --index-only \
  --identity "$E/sign-existing-image.yml@refs/heads/main" --no-sign --no-attest
se="$FAKE_DIGEST"
fake_sign "$se" "$E/sign-existing-image.yml@refs/heads/main" "$OTHER"
fake_attest "$se" "$E/sign-existing-image.yml@refs/heads/main" "$OTHER" "$C" "$se" "$R/ohttp-relay-simulator"
expect ok VI "$R/ohttp-relay-simulator@$se"
expect fail VI --commit "$C" "$R/ohttp-relay-simulator@$se"
expect ok VI --commit "$C" --allow-sign-existing "$R/ohttp-relay-simulator@$se"
expect fail VI --commit "$OTHER" --allow-sign-existing "$R/ohttp-relay-simulator@$se"
expect fail VI --allow-sign-existing "$R/ohttp-relay-simulator@$se"
# The image role: an attestation is bound to its image by the subject name (all images) and by
# invocation.parameters.image when present (images published since it is set).
fake_release_image "$R/ohttp-e2e" sha-4444444 "$C" --nonce role --index-only \
  --identity "$E/ohttp-build.yml@refs/heads/main"
role="$FAKE_DIGEST"
expect ok VI --commit "$C" "$R/ohttp-e2e@$role"
expect fail VI "$R/ohttp-gateway@$role"                 # e2e artifacts verified as the gateway
expect fail VI --commit "$C" "$R/ohttp-gateway@$role"
# Subject named after the gateway, predicate naming ohttp-e2e: refused.
fake_release_image "$R/ohttp-gateway" sha-5555555 "$C" --nonce role2 --index-only \
  --identity "$E/ohttp-build.yml@refs/heads/main" --no-attest
fake_attest "$FAKE_DIGEST" "$E/ohttp-build.yml@refs/heads/main" "$C" "$C" "$FAKE_DIGEST" "$R/ohttp-gateway" ohttp-e2e
expect fail VI "$R/ohttp-gateway@$FAKE_DIGEST"
# An older attestation (no invocation.parameters): bound by the subject name alone.
old_stmt="$(jq -c --arg hex "${FAKE_DIGEST#sha256:}" --arg c "$C" --arg n "$R/ohttp-gateway" '{
  predicateType: "https://slsa.dev/provenance/v0.2", subject: [{name: $n, digest: {sha256: $hex}}],
  predicate: {invocation: {configSource: {digest: {sha1: $c}}}, materials: [{digest: {sha1: $c}}]}}' <<<'{}')"
printf '%s\t%s\t%s\n' "$E/ohttp-build.yml@refs/heads/main" "$C" "$old_stmt" >"$FAKE_STORE/atts/$FAKE_DIGEST"
expect ok VI --commit "$C" "$R/ohttp-gateway@$FAKE_DIGEST"
expect fail VI "$R/ohttp-e2e@$FAKE_DIGEST"
# Malformed attestation payloads are skipped, never printed.
printf '%s\t%s\t%s\n' "$E/ohttp-build.yml@refs/heads/main" "$C" '"sentinel.example.net"' >"$FAKE_STORE/atts/$FAKE_DIGEST"
expect fail VI "$R/ohttp-gateway@$FAKE_DIGEST"
if grep -q "sentinel.example.net" <<<"$out"; then echo "FAIL: malformed payload printed"; fail=1; fi
# Another image name than the three is refused.
expect fail VI "$R/other@$FAKE_DIGEST"

# Feature branch signature.
fake_release_image "$R/ohttp-relay-simulator" sha-2222222 "$C" --nonce feature \
  --identity "$E/ohttp-build.yml@refs/heads/feature"
expect fail VI "$R/ohttp-relay-simulator@$FAKE_DIGEST"

if [[ $fail -ne 0 ]]; then
  exit 1
fi
echo "verify-image: OK"

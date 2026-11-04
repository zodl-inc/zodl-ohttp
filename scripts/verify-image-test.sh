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
# identities (grep -E; the constructs used behave the same in Go RE2, which cosign uses).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
unset GITHUB_ORG GITHUB_REPO
# shellcheck source=verify-image.sh
source "$SCRIPT_DIR/verify-image.sh"
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
check yes "$B" "$W/ohttp-build.yml@refs/tags/v0.1.0"
check yes "$S" "$W/sign-existing-image.yml@refs/heads/main"

check no "$B" "$W/ohttp-build.yml@refs/heads/feature"
check no "$B" "$W/ohttp-build.yml@refs/heads/main-evil"
check no "$B" "$W/ohttp-build.yml@refs/pull/1/merge"
check no "$B" "$W/ohttp-build.yml@refs/tags/x1"
check no "$B" "$W/ohttp-buildXyml@refs/heads/main"
check no "$B" "https://githubXcom/zodl-inc/zodl-ohttp/.github/workflows/ohttp-build.yml@refs/heads/main"
check no "$B" "https://github.com/zodl-inc/zodl-ohttpX/.github/workflows/ohttp-build.yml@refs/heads/main"
check no "$B" "https://github.com/evil/zodl-ohttp/.github/workflows/ohttp-build.yml@refs/heads/main"
check no "$B" "$W/sign-existing-image.yml@refs/heads/main"
check no "$S" "$W/sign-existing-image.yml@refs/heads/feature"
check no "$S" "$W/sign-existing-image.yml@refs/tags/v0.1.0"
check no "$S" "$W/sign-existing-imageXyml@refs/heads/main"

# Metacharacters in an override are literal.
GITHUB_ORG="a.b" GITHUB_REPO="c+d" build_identities
check yes "$EXPECTED_IDENTITY_BUILD" "https://github.com/a.b/c+d/.github/workflows/ohttp-build.yml@refs/heads/main"
check no "$EXPECTED_IDENTITY_BUILD" "https://github.com/aXb/ccd/.github/workflows/ohttp-build.yml@refs/heads/main"

if [[ $fail -ne 0 ]]; then
  exit 1
fi
echo "verify-image identity regexes: OK"

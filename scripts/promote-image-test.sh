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

# Checks promote-image.sh without network: the release tag checks against a throwaway git
# repository with a throwaway signing key, and the promotion against the fake registry of
# testing/fake-registry.sh (the real registry-facing code paths, with stub tools).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROMOTE="$SCRIPT_DIR/promote-image.sh"
# shellcheck source=promote-image.sh
source "$PROMOTE"
# shellcheck source=testing/fake-registry.sh
source "$SCRIPT_DIR/testing/fake-registry.sh"

fail=0
expect() {
  local want="$1"
  shift
  local got=ok
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
lacks() {
  if grep -qF -- "$1" <<<"$out"; then
    echo "FAIL: output has: $1"
    fail=1
  fi
}

tmp="$(mktemp -d /tmp/promote-test.XXXXXX)"
cleanup() {
  if [[ -n "${GNUPGHOME:-}" ]]; then gpgconf --kill all >/dev/null 2>&1 || true; fi
  rm -rf "$tmp"
}
trap cleanup EXIT

# ---- Tag syntax (SemVer 2.0.0, no build metadata, version at most 128 characters).
for t in v1.0.0 v1.1.0 v0.1.0 v10.20.30 v1.2.3-rc.1 v1.2.3-alpha-2 v1.2.3-0 v1.2.3-0a v1.2.3-x.0.y \
  v1.2.3--- v1.2.3-a.10.b; do
  expect ok tag_version "$t"
done
for t in 1.0.0 v1 v1.2 v1.2.3.4 v01.2.3 v1.02.3 v1.2.03 v1.2.3+build v1.2.3- v1.2.3-rc..1 \
  v1.2.3-01 v1.2.3-rc.01 v1.2.3-00 v1.2.3-rc.1_ vx.y.z "v1.2.3 " "" v1.2.3-é; do
  expect fail tag_version "$t"
done
pre="$(printf 'a%.0s' $(seq 1 122))" # 1.2.3- (6) + 122 = 128
expect ok tag_version "v1.2.3-$pre"
expect fail tag_version "v1.2.3-${pre}a"

# ---- Versions of this checkout: the crates and every lock entry agree.
gw="$(git -C "$ROOT" show HEAD:gateway/Cargo.toml | crate_version)"
expect ok check_versions "$gw" "$ROOT" HEAD
expect fail check_versions "9.9.9" "$ROOT" HEAD

# ---- check-tag against a throwaway repository and signing keys.
export GNUPGHOME="$tmp/g"
mkdir -m 700 "$GNUPGHOME"
printf 'quiet\nno-auto-check-trustdb\n' >"$GNUPGHOME/gpg.conf"
genkey() {
  gpg --batch --quiet --pinentry-mode loopback --passphrase '' \
    --quick-gen-key "$1" ed25519 sign never 2>/dev/null
  gpg --list-keys --with-colons "$1" | awk -F: '/^fpr/ { print $10; exit }'
}
release_key="$(genkey 'Release <release@example.com>')"
other_key="$(genkey 'Other <other@example.com>')"

repo="$tmp/repo"
git init -q -b main "$repo"
g() { git -C "$repo" -c user.name=test -c user.email=test@example.com "$@"; }
sg() { g -c "user.signingkey=$1" -c gpg.program=gpg "${@:2}"; }
write_versions() { # gateway-crate relay-crate [gateway-lock] [relay-lock] [client-lock]
  mkdir -p "$repo/gateway" "$repo/relay-simulator" "$repo/client"
  printf '[package]\nname = "zodl-ohttp-gateway"\nversion = "%s"\n\n[dependencies]\nversion = "9.9.9"\n' "$1" \
    >"$repo/gateway/Cargo.toml"
  printf '[package]\nname = "ohttp-relay-simulator"\nversion = "%s"\n' "$2" >"$repo/relay-simulator/Cargo.toml"
  printf '[[package]]\nname = "aes"\nversion = "0.8.4"\n\n[[package]]\nname = "zodl-ohttp-gateway"\nversion = "%s"\n' \
    "${3:-$1}" >"$repo/gateway/Cargo.lock"
  printf '[[package]]\nname = "ohttp-relay-simulator"\nversion = "%s"\n' "${4:-$2}" >"$repo/relay-simulator/Cargo.lock"
  printf '[[package]]\nname = "zodl-ohttp-gateway"\nversion = "%s"\n\n[[package]]\nname = "zodl-ohttp-client"\nversion = "3.0.0"\n' \
    "${5:-$1}" >"$repo/client/Cargo.lock"
}
mkdir -p "$repo/.github"
gpg --armor --export "$release_key" >"$repo/.github/release-signing-keys.asc"
: >"$repo/.github/empty.asc"
write_versions 1.2.0 1.2.0
g add -A && g commit -q -m one
on_main="$(g rev-parse HEAD)"
sg "$release_key" tag -s v1.2.0 -m v1.2.0
sg "$release_key" tag -s v1.3.0 -m v1.3.0
g tag v9.0.1
g tag -a v9.0.2 -m unsigned
sg "$other_key" tag -s v9.0.3 -m other
g checkout -q -b side
write_versions 1.4.0 1.4.0
g commit -q -am side
off_main="$(g rev-parse HEAD)"
sg "$release_key" tag -s v1.4.0 -m v1.4.0
write_versions 1.5.0 1.5.0 1.4.0
g commit -q -am lock
lock_mismatch="$(g rev-parse HEAD)"
sg "$release_key" tag -s v1.5.0 -m v1.5.0
write_versions 1.6.0 1.6.0 1.6.0 1.6.0 1.5.0
g commit -q -am client-lock
client_mismatch="$(g rev-parse HEAD)"
sg "$release_key" tag -s v1.6.0 -m v1.6.0
write_versions 1.7.0 1.6.0
g commit -q -am crate-mismatch
crate_mismatch="$(g rev-parse HEAD)"
sg "$release_key" tag -s v1.7.0 -m v1.7.0
write_versions 1.8.0 1.8.0
printf '[[package]]\nname = "aes"\nversion = "1.8.0"\n' >"$repo/gateway/Cargo.lock"
g commit -q -am no-entry
no_entry="$(g rev-parse HEAD)"
sg "$release_key" tag -s v1.8.0 -m v1.8.0
write_versions 1.9.0 1.9.0
git -C "$repo" add -A
git -C "$repo" rm -q -f relay-simulator/Cargo.toml
g commit -q -m no-toml
no_toml="$(g rev-parse HEAD)"
sg "$release_key" tag -s v1.9.0 -m v1.9.0
g checkout -q main
# A good signed tag object under another name; a signed tag of a (signed) tag.
git -C "$repo" update-ref refs/tags/v1.2.1 "$(git -C "$repo" rev-parse refs/tags/v1.2.0)"
sg "$release_key" -c advice.nestedTag=false tag -s v1.2.2 -m v1.2.2 v1.2.0
g merge -q --no-ff -m merge side
g checkout -q "$on_main"

ct() { bash "$PROMOTE" check-tag --root "$repo" --main-ref main "$@"; }
expect ok ct --tag v1.2.0 --commit "$on_main"
contains "version=1.2.0"
expect fail ct --tag v1.3.0 --commit "$on_main"
contains "differs from the gateway crate version 1.2.0"
expect fail ct --tag v1.2.0 --commit "$off_main"
contains "names $on_main"
expect fail ct --tag v1.4.0 --commit "$off_main" --main-ref "$on_main"
contains "is not on"
expect fail ct --tag v9.9.9 --commit "$on_main"
contains "not in the checkout"
expect fail ct --tag v1.2.0 --commit "$on_main" --main-ref nope
contains "not available"
# Signatures: lightweight, unsigned, unknown key, keys file missing or empty.
expect fail ct --tag v9.0.1 --commit "$on_main"
contains "not an annotated tag"
expect fail ct --tag v9.0.2 --commit "$on_main"
contains "no good signature"
expect fail ct --tag v9.0.3 --commit "$on_main"
contains "no good signature"
expect fail ct --tag v1.2.0 --commit "$on_main" --keys-file .github/missing.asc
contains "no release signing keys"
expect fail ct --tag v1.2.0 --commit "$on_main" --keys-file .github/empty.asc
contains "no release signing keys"
expect fail ct --tag v1.2.0 --commit "$on_main" --keys-file ""
# Merged side commits are on main; lock files and crate versions are checked.
expect ok ct --tag v1.4.0 --commit "$off_main"
expect fail ct --tag v1.5.0 --commit "$lock_mismatch"
contains "gateway/Cargo.lock has zodl-ohttp-gateway 1.4.0"
expect fail ct --tag v1.6.0 --commit "$client_mismatch"
contains "client/Cargo.lock has zodl-ohttp-gateway 1.5.0"
expect fail ct --tag v1.7.0 --commit "$crate_mismatch"
contains "differs from the relay-simulator crate version 1.6.0"
expect fail ct --tag v1.8.0 --commit "$no_entry"
contains "gateway/Cargo.lock has no zodl-ohttp-gateway entry"
expect fail ct --tag v1.9.0 --commit "$no_toml"
contains "relay-simulator/Cargo.toml is missing at $no_toml"
# A tag object with a malformed name header (an escape character): a fixed message.
bad_obj="$(printf 'object %s\ntype commit\ntag sentinel.example.net\033[31m\ntagger t <t@example.com> 0 +0000\n\nx\n' "$on_main" |
  git -C "$repo" hash-object -t tag -w --literally --stdin)"
git -C "$repo" update-ref refs/tags/v1.2.9 "$bad_obj"
expect fail ct --tag v1.2.9 --commit "$on_main"
contains "has a malformed name"
if grep -q "sentinel.example.net" <<<"$out"; then echo "FAIL: malformed tag header printed"; fail=1; fi
# The tag object must be this release: named as the ref, naming the commit directly.
expect fail ct --tag v1.2.1 --commit "$on_main"
contains "the tag object under v1.2.1 is named 'v1.2.0'"
expect fail ct --tag v1.2.2 --commit "$on_main"
contains "tag v1.2.2 points at a tag, not a commit"

# ---- promote against the fake registry.
R=registry.example.com/test
C=0123456789abcdef0123456789abcdef01234567
OTHER=89abcdef0123456789abcdef0123456789abcdef
MAIN_ID="https://github.com/example-org/example-repo/.github/workflows/ohttp-build.yml@refs/heads/main"
declare -A SRC=()
n=0
# The plain fixture (no options) is built once per registry name and copied for each case.
setup() { # [image option...]: options of fake_release_image for one image
  n=$((n + 1))
  rm -rf "$tmp/reg"
  local img key
  key="$(printf '%s' "$R" | sha256sum | cut -c1-12)"
  if [[ $# -eq 0 && -d "$tmp/template-$key" ]]; then
    cp -a "$tmp/template-$key" "$tmp/reg"
    export FAKE_STORE="$tmp/reg/store"
    while read -r img d; do SRC[$img]="$d"; done <"$tmp/template-$key.src"
    return 0
  fi
  fake_registry_init "$tmp/reg"
  for img in ohttp-gateway ohttp-relay-simulator ohttp-e2e; do
    if [[ "${1:-}" == "$img" ]]; then
      fake_release_image "$R/$img" sha-0123456 "$C" --nonce "$n" "${@:2}"
    else
      fake_release_image "$R/$img" sha-0123456 "$C" --nonce "$n"
    fi
    SRC[$img]="$FAKE_DIGEST"
  done
  if [[ $# -eq 0 ]]; then
    cp -a "$tmp/reg" "$tmp/template-$key"
    for img in ohttp-gateway ohttp-relay-simulator ohttp-e2e; do echo "$img ${SRC[$img]}"; done >"$tmp/template-$key.src"
  fi
}
P() { bash "$PROMOTE" promote --registry "$R" --commit "$C" --version 1.2.3 --repository example-org/example-repo "$@"; }
tag_of() { cat "$FAKE_STORE/tags/$(fake_key "$R/$1:1.2.3")" 2>/dev/null || true; }
no_writes() {
  if [[ -s "$FAKE_STORE/writes" ]]; then
    echo "FAIL: registry writes despite a failed preflight: $(fake_writes | tr '\n' ' ')"
    fail=1
  fi
}

setup
expect ok P
for img in ohttp-gateway ohttp-relay-simulator ohttp-e2e; do
  [[ "$(tag_of $img)" == "${SRC[$img]}" ]] || { echo "FAIL: $img:1.2.3 is not ${SRC[$img]}"; fail=1; }
  contains "$img: 1.2.3 = ${SRC[$img]}"
done
[[ "$(fake_writes | grep -c '^create ')" -eq 3 ]] || { echo "FAIL: expected 3 tag writes"; fail=1; }
if fake_writes | grep -qE '^(sign|attest) '; then echo "FAIL: a release signed or attested"; fail=1; fi
lacks "registry.example.com"
# A re-run changes nothing.
: >"$FAKE_STORE/writes"
expect ok P
no_writes
contains "1.2.3 already names it"

# Partly tagged (same digest): only the others are written.
setup
fake_tag "$R/ohttp-gateway:1.2.3" "${SRC[ohttp-gateway]}"
expect ok P
[[ "$(fake_writes | tr '\n' ' ')" == "create $R/ohttp-relay-simulator:1.2.3 create $R/ohttp-e2e:1.2.3 " ]] ||
  { echo "FAIL: partial: $(fake_writes | tr '\n' ' ')"; fail=1; }

# --check-only writes nothing.
setup
expect ok P --check-only
no_writes
contains "preflight passed"

# Every preflight failure leaves the registry untouched, also for the images checked before.
pf() { # case name, expected message, then the setup arguments
  local what="$1" msg="$2" before="$fail"
  shift 2
  setup "$@"
  expect fail P
  contains "$msg"
  no_writes
  lacks "registry.example.com"
  if [[ "$fail" -ne "$before" ]]; then echo "  (case: $what)"; fi
}
pf "unsigned" "has no signature of the main build" ohttp-e2e --no-sign
pf "signed by a branch" "has no signature of the main build" ohttp-e2e \
  --identity "https://github.com/example-org/example-repo/.github/workflows/ohttp-build.yml@refs/heads/feature"
pf "signed by another repository" "has no signature of the main build" ohttp-e2e \
  --identity "https://github.com/evil/example-repo/.github/workflows/ohttp-build.yml@refs/heads/main"
pf "no attestation" "has no provenance attestation" ohttp-e2e --no-attest
pf "attestation of another commit" "has no provenance attestation" ohttp-e2e --attest-commit "$OTHER"
pf "attestation of another digest" "has no provenance attestation" ohttp-e2e \
  --attest-subject "sha256:$(printf 'f%.0s' $(seq 1 64))"
pf "platform without labels" "linux/arm64 image has no org.opencontainers.image.revision label" \
  ohttp-e2e --no-labels linux/arm64
pf "platform without the revision label" "linux/amd64 image has no org.opencontainers.image.revision label" \
  ohttp-e2e --no-revision linux/amd64
pf "platform of another commit" "linux/arm64 image is labelled with revision $OTHER" \
  ohttp-e2e --revision linux/arm64 "$OTHER"
pf "single platform" "has 0 images for linux/arm64" ohttp-e2e --only-amd64
pf "extra platform" "has 3 platform images" ohttp-e2e --extra linux/s390x
pf "last platform unsigned" "has no signature of the main build" ohttp-e2e --unsigned-platform linux/arm64
pf "last platform unattested" "has no provenance attestation" ohttp-e2e --unattested-platform linux/arm64
pf "platforms neither signed nor attested" "has no signature of the main build" ohttp-e2e --index-only
# Malformed registry data (index, descriptors, image configuration): a fixed message, nothing
# of it printed, nothing written.
S=sentinel.example.net
for raw in '{"mediaType": "application/vnd.oci.image.index.v1+json", "manifests": "'"$S"'"}' \
  '{"mediaType": "application/vnd.oci.image.index.v1+json", "manifests": ["'"$S"'"]}' \
  '{"mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [{"digest": "'"$S"'", "platform": {"os": "linux", "architecture": "amd64"}}]}' \
  '{"mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [{"digest": "x", "platform": "'"$S"'"}]}' \
  '["'"$S"'"]' '{"mediaType": ["'"$S"'"]}'; do
  setup
  printf '%s' "$raw" >"$FAKE_STORE/manifests/${SRC[ohttp-e2e]}"
  expect fail P
  if grep -q "$S" <<<"$out"; then echo "FAIL: malformed index printed: $raw"; fail=1; fi
  no_writes
done
for cfg in '"'"$S"'"' '{"config": "'"$S"'"}' '{"config": {"Labels": ["'"$S"'"]}}' \
  '{"config": {"Labels": {"org.opencontainers.image.revision": ["'"$S"'"]}}}' '['; do
  setup
  printf '%s' "$cfg" >"$FAKE_STORE/images/$(jq -r '.manifests[] | select(.platform.architecture == "arm64") | .digest' \
    "$FAKE_STORE/manifests/${SRC[ohttp-e2e]}")"
  expect fail P
  if grep -q "$S" <<<"$out"; then echo "FAIL: malformed configuration printed: $cfg"; fail=1; fi
  no_writes
done

# Every descriptor is checked before anything is excluded (only the exact unknown/unknown
# attestation form is): a descriptor without a platform, an attestation descriptor with a
# malformed digest. Fatal, nothing written.
for filter in '.manifests += [{"digest": .manifests[0].digest}]' \
  '.manifests |= map(if .platform.os == "unknown" then .digest = "sentinel.example.net" else . end)'; do
  setup
  jq -c "$filter" "$FAKE_STORE/manifests/${SRC[ohttp-e2e]}" >"$tmp/idx"
  cp "$tmp/idx" "$FAKE_STORE/manifests/${SRC[ohttp-e2e]}"
  expect fail P
  contains "malformed descriptor in the index"
  if grep -q "sentinel.example.net" <<<"$out"; then echo "FAIL: malformed descriptor printed"; fail=1; fi
  no_writes
done

# Hostile revision labels are not printed.
for bad in $'0123456789abcdef0123456789abcdef01234567\nregistry.example.com' $'\e[31mred' "registry.example.com"; do
  setup ohttp-e2e --revision linux/arm64 "$bad"
  expect fail P
  contains "the linux/arm64 image has a malformed revision label"
  if grep -q "registry.example.com" <<<"$out" || [[ "$out" == *$'\e'* ]]; then
    echo "FAIL: hostile revision label printed"
    fail=1
  fi
  no_writes
done

# The artifacts of one image under another image's name (the e2e index, signed and attested
# for ohttp-e2e, copied into the gateway repository): refused.
setup
fake_tag "$R/ohttp-gateway:sha-0123456" "${SRC[ohttp-e2e]}"
expect fail P
contains "ohttp-gateway:sha-0123456: ${SRC[ohttp-e2e]} has no provenance attestation of the main build"
no_writes
# Each half of the binding counts: the subject named after the gateway but the predicate
# naming ohttp-e2e, and the other way round.
for half in "$R/ohttp-gateway ohttp-e2e" "$R/ohttp-e2e ohttp-gateway"; do
  setup
  : >"$FAKE_STORE/atts/${SRC[ohttp-gateway]}"
  fake_attest "${SRC[ohttp-gateway]}" "$MAIN_ID" "$C" "$C" "${SRC[ohttp-gateway]}" ${half}
  expect fail P
  contains "ohttp-gateway:sha-0123456: ${SRC[ohttp-gateway]} has no provenance attestation of the main build"
  no_writes
done

# Only a registry "manifest not found" answer is "absent"; local tool, authorisation and
# transport errors are fatal, also when mixed with such an answer.
for text in "ERROR: {ref}: not found" "{ref}: manifest unknown: manifest unknown" \
  'failed to resolve {ref}: {"errors":[{"code":"MANIFEST_UNKNOWN","message":"Requested image not found"}]}' \
  "unexpected status from HEAD request to {url}: 404 Not Found"; do
  setup
  fake_notfound_text "$text"
  expect ok P --check-only
  contains "1.2.3 to be created"
done
for text in "unexpected status: 403 Forbidden" "error: 4040 bytes read" \
  'error getting credentials - err: exec: "docker-credential-helper": executable file not found in $PATH, out: ``' \
  $'error getting credentials - err: exec: "docker-credential-helper": executable file not found in $PATH\nERROR: {ref}: not found' \
  "failed to fetch oauth token: unexpected status from GET request to https://auth.example.com/token: 404 Not Found" \
  $'failed to authorize: failed to fetch anonymous token\n{ref}: manifest unknown' \
  "dial tcp: lookup registry.example.com: no such host" \
  "failed to do request: Head \"{url}\": net/http: TLS handshake timeout" \
  "unexpected status from HEAD request to {url}: 500 Internal Server Error" \
  "ERROR: other.example.com/test/ohttp-gateway:1.2.3: not found" "ERROR: {ref}-other: not found" \
  "manifest unknown: manifest unknown" \
  "unexpected status from HEAD request to https://other.example.com/v2/x/manifests/1.2.3: 404 Not Found" \
  "unexpected status from HEAD request to {otherurl}: 404 Not Found" \
  "{ref}-rc1: manifest unknown" "ERROR: {ref}-rc1: not found" "ERROR: x{ref}: not found" \
  "{url}-rc1: 404 Not Found" \
  $'warning: retrying\nERROR: {ref}: not found' $'ERROR: {ref}: not found\nERROR: {ref}: not found' \
  $'ERROR: {ref}: not found\nerror: something else' \
  $'ERROR: {ref}: not found\r' $'ERROR: x\rERROR: {ref}: not found' $'\nERROR: {ref}: not found' \
  $'\n\nERROR: {ref}: not found' $'ERROR: {ref}: not found\n\nERROR: {ref}: not found' "junk {ref}: not found" "ERROR: {ref}: not found " \
  "{ref}: manifest unknownish" "{ref}: xmanifest unknown" \
  $'warning: retry\r{ref}: manifest unknown' $'warning: retry\n{ref}: manifest unknown' \
  "ERROR: something went wrong"; do
  setup
  fake_notfound_text "$text"
  expect fail P --check-only
  contains "registry lookup failed"
done
# Words of a registry host, repository path or tag ("token", "credentials", "tls", "eof",
# "denied") do not turn a real "not found" into an error; local errors stay fatal.
R_SAVED="$R"
R=tls-token.example.com/credentials/denied-eof
for text in "ERROR: {ref}: not found" "unexpected status from HEAD request to {url}: 404 Not Found"; do
  setup
  fake_notfound_text "$text"
  expect ok P --check-only
  expect ok bash "$PROMOTE" promote --registry "$R" --commit "$C" --version 1.2.3-token.tls-eof \
    --repository example-org/example-repo --check-only
done
setup
fake_notfound_text $'error getting credentials - err: executable file not found\nERROR: {ref}: not found'
expect fail P --check-only
contains "registry lookup failed"
R="$R_SAVED"
# A missing docker (exit 127) is never "absent".
setup
mkdir -p "$tmp/nodocker"
printf '#!/usr/bin/env bash\necho "docker: not found" >&2\nexit 127\n' >"$tmp/nodocker/docker"
chmod +x "$tmp/nodocker/docker"
expect fail env PATH="$tmp/nodocker:$PATH" bash "$PROMOTE" promote --registry "$R" --commit "$C" \
  --version 1.2.3 --repository example-org/example-repo --check-only
contains "registry lookup failed"

# Verbose output (IMAGE_TOOLS_VERBOSE=1 or RUNNER_DEBUG=1): the tools' stdout and stderr, of
# successful and failed commands, on stderr; nothing of it otherwise.
setup
for v in IMAGE_TOOLS_VERBOSE=1 RUNNER_DEBUG=1 none; do
  expect ok env "${v/none/X=1}" bash "$PROMOTE" promote --registry "$R" --commit "$C" \
    --version 1.2.3 --repository example-org/example-repo --check-only
  if [[ "$v" == none ]]; then
    lacks '"critical"'
    lacks "$R/ohttp-gateway:1.2.3: not found"
  else
    contains '"critical"'                         # stdout of a successful cosign verify
    contains "$R/ohttp-gateway:1.2.3: not found"  # stderr of a failed lookup
  fi
done

# Signed at another commit (certificate workflow SHA) by the main build.
setup
echo -n >"$FAKE_STORE/sigs/${SRC[ohttp-e2e]}"
fake_sign "${SRC[ohttp-e2e]}" "$MAIN_ID" "$OTHER"
expect fail P
contains "has no signature of the main build at $C"
no_writes

# Missing source image.
setup
rm "$FAKE_STORE/tags/$(fake_key "$R/ohttp-relay-simulator:sha-0123456")"
expect fail P
contains "ohttp-relay-simulator:sha-0123456 does not exist"
no_writes

# A version tag on another digest.
setup
fake_tag "$R/ohttp-e2e:1.2.3" "${SRC[ohttp-gateway]}"
expect fail P
contains "ohttp-e2e:1.2.3 already exists as ${SRC[ohttp-gateway]}"
no_writes

# A registry error is never taken for an absent tag.
setup
fake_fail "ohttp-e2e:1.2.3"
expect fail P
contains "ohttp-e2e:1.2.3: registry lookup failed"
lacks "401"
no_writes
setup
fake_fail "ohttp-gateway:sha-"
expect fail P
contains "registry lookup failed"
no_writes
# The tool output is shown only verbosely.
setup
fake_fail "ohttp-e2e:1.2.3"
expect fail env IMAGE_TOOLS_VERBOSE=1 bash "$PROMOTE" promote --registry "$R" --commit "$C" \
  --version 1.2.3 --repository example-org/example-repo
contains "401 Unauthorized"

# A failed write, then the re-run of the job (recovery).
setup
fake_fail_create "ohttp-e2e:1.2.3"
expect fail P
contains "ohttp-e2e: writing 1.2.3 failed; re-run the job"
[[ "$(tag_of ohttp-gateway)" == "${SRC[ohttp-gateway]}" && -z "$(tag_of ohttp-e2e)" ]] ||
  { echo "FAIL: partial write state"; fail=1; }
fake_clear_failures
: >"$FAKE_STORE/writes"
expect ok P
[[ "$(fake_writes | tr '\n' ' ')" == "create $R/ohttp-e2e:1.2.3 " ]] ||
  { echo "FAIL: recovery wrote: $(fake_writes | tr '\n' ' ')"; fail=1; }

# Arguments.
setup
expect fail P --version v1.2.3
expect fail P --version 1.2
expect fail P --version "1.2.3;true"
expect fail bash "$PROMOTE" promote --registry "bad host" --commit "$C" --version 1.2.3 --repository a/b
expect fail bash "$PROMOTE" promote --registry "$R" --commit abc --version 1.2.3 --repository a/b
expect fail bash "$PROMOTE" promote --registry "$R" --commit "$C" --version 1.2.3 --repository a
no_writes

if [[ $fail -ne 0 ]]; then
  exit 1
fi
echo "promote-image: OK"

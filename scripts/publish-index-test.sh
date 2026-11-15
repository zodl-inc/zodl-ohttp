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

# Checks publish-index.sh against the fake registry of testing/fake-registry.sh (stub tools, no
# network): creation, a re-run with the same platform pushes, a conflicting existing index.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testing/fake-registry.sh
source "$SCRIPT_DIR/testing/fake-registry.sh"

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

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
R=registry.example.com/test
C=0123456789abcdef0123456789abcdef01234567
fake_registry_init "$tmp/reg"

# A platform push as build-push-action leaves it: an index of the image and its attestation
# manifest. Its digest goes into the digests directory <dir>.
push() { # dir platform nonce [descriptor platform, default: the image's] [config variant]
  #        [extra config fields (jq object)] [revision]
  local os="${2%/*}" arch="${2#*/}" img att dos dar cv="${5:-}" extra="${6:-{\}}" rev="${7:-$C}"
  dos="${4:-$2}"
  dar="${dos#*/}"
  dos="${dos%/*}"
  fake_put manifests "$(jq -cn --arg n "$3$2" '{mediaType: "application/vnd.oci.image.manifest.v1+json", n: $n}')"
  img="$FAKE_PUT"
  jq -cn --arg os "$os" --arg a "$arch" --arg c "$rev" --arg v "$cv" --argjson x "$extra" \
    '{os: $os, architecture: $a, config: {Labels: {"org.opencontainers.image.revision": $c}}}
      + (if $v != "" then {variant: $v} else {} end) + $x' >"$FAKE_STORE/images/$img"
  fake_put manifests "$(jq -cn --arg d "$img" '{mediaType: "application/vnd.oci.image.manifest.v1+json", attests: $d}')"
  att="$FAKE_PUT"
  local si sa
  si="$(wc -c <"$FAKE_STORE/manifests/$img")"
  sa="$(wc -c <"$FAKE_STORE/manifests/$att")"
  # As buildkit pushes it: the image and its attestation manifest (annotated with the image).
  fake_put manifests "$(jq -cn --arg i "$img" --arg a "$att" --arg os "$dos" --arg ar "$dar" \
    --argjson si "$si" --argjson sa "$sa" '{schemaVersion: 2,
    mediaType: "application/vnd.oci.image.index.v1+json", manifests: [
      {mediaType: "application/vnd.oci.image.manifest.v1+json", digest: $i, size: $si,
        platform: {architecture: $ar, os: $os}},
      {mediaType: "application/vnd.oci.image.manifest.v1+json", digest: $a, size: $sa,
        annotations: {"vnd.docker.reference.digest": $i, "vnd.docker.reference.type": "attestation-manifest"},
        platform: {architecture: "unknown", os: "unknown"}}]}')"
  mkdir -p "$1"
  touch "$1/${FAKE_PUT#sha256:}"
}
PI() { bash "$SCRIPT_DIR/publish-index.sh" --registry "$R" --image ohttp-gateway --commit "$C" "$@"; }
tagged() { cat "$FAKE_STORE/tags/$(fake_key "$R/ohttp-gateway:sha-0123456")"; }

push "$tmp/run1" linux/amd64 one
push "$tmp/run1" linux/arm64 one
expect ok PI --digests-dir "$tmp/run1" --output "$tmp/out1"
digest="$(tagged)"
contains "created ($digest)"
[[ "$(cat "$tmp/out1")" == "digest=$digest" ]] || { echo "FAIL: output file"; fail=1; }
jq -e '[.manifests[].platform | "\(.os)/\(.architecture)"] | sort
  == ["linux/amd64", "linux/arm64", "unknown/unknown", "unknown/unknown"]' "$FAKE_STORE/manifests/$digest" >/dev/null ||
  { echo "FAIL: index content"; fail=1; }
if grep -q "registry.example.com" <<<"$out"; then echo "FAIL: the registry is logged"; fail=1; fi

# Re-run with the same pushes: the existing index is kept, nothing is written.
: >"$FAKE_STORE/writes"
expect ok PI --digests-dir "$tmp/run1" --output "$tmp/out2"
contains "is the index of this run's platform images ($digest), kept"
[[ ! -s "$FAKE_STORE/writes" && "$(cat "$tmp/out2")" == "digest=$digest" ]] ||
  { echo "FAIL: re-run wrote or reported another digest"; fail=1; }

# Other pushes (a rebuild) under an existing sha-<short>: refused.
push "$tmp/run2" linux/amd64 two
push "$tmp/run2" linux/arm64 two
expect fail PI --digests-dir "$tmp/run2"
contains "($digest) is not the index of this run's platform images"
# Only one platform of the run matches: refused.
mkdir -p "$tmp/mixed"
cp "$tmp/run1"/* "$tmp/mixed/"
rm "$tmp/mixed/$(ls "$tmp/run1" | head -n 1)"
cp "$tmp/run2/$(ls "$tmp/run2" | head -n 1)" "$tmp/mixed/"
expect fail PI --digests-dir "$tmp/mixed"
[[ "$(tagged)" == "$digest" ]] || { echo "FAIL: the existing index changed"; fail=1; }

# An existing index made of run1's descriptors, transformed by a jq filter (on the list).
existing() {
  local idx
  idx="$(for f in "$tmp/run1"/*; do jq -c '.manifests[]' "$FAKE_STORE/manifests/sha256:$(basename "$f")"; done |
    jq -sc "$1"' | {schemaVersion: 2, mediaType: "application/vnd.oci.image.index.v1+json", manifests: .}')"
  fake_put manifests "$idx"
  fake_tag "$R/ohttp-gateway:sha-0123456" "$FAKE_PUT"
}
rm -rf "$tmp/reg" && fake_registry_init "$tmp/reg"
rm -rf "$tmp/run1" && push "$tmp/run1" linux/amd64 one && push "$tmp/run1" linux/arm64 one
amd='.platform.architecture == "amd64"'
arm='.platform.architecture == "arm64"'
# The same descriptors (in another order, annotations changed): kept.
existing 'reverse'
expect ok PI --digests-dir "$tmp/run1"
existing "map(del(.annotations))"
expect ok PI --digests-dir "$tmp/run1"
# Anything else of a descriptor differs: refused.
for filter in \
  "map(if $amd then .platform.architecture = \"arm64\" elif $arm then .platform.architecture = \"amd64\" else . end)" \
  "map(if $amd then .size += 1 else . end)" \
  "map(if $arm then .mediaType = \"application/vnd.docker.distribution.manifest.v2+json\" else . end)" \
  "map(if $arm then .platform.variant = \"v8\" else . end)" \
  "map(if $amd then .platform[\"os.version\"] = \"1\" else . end)" \
  "map(select($arm | not))" \
  ". + [.[0]]"; do
  existing "$filter"
  expect fail PI --digests-dir "$tmp/run1"
  contains "is not the index of this run's platform images"
done
[[ ! -s "$FAKE_STORE/writes" ]] || { echo "FAIL: wrote over an existing index"; fail=1; }

# Plain image manifests as pushes (no attestation manifests): descriptors from the registry's
# descriptor and the image configuration.
rm -rf "$tmp/reg" && fake_registry_init "$tmp/reg"
push "$tmp/full" linux/amd64 plain
push "$tmp/full" linux/arm64 plain
mkdir -p "$tmp/plain"
for f in "$tmp/full"/*; do
  d="$(jq -r '.manifests[] | select(.platform.os != "unknown") | .digest' "$FAKE_STORE/manifests/sha256:$(basename "$f")")"
  touch "$tmp/plain/${d#sha256:}"
done
expect ok PI --digests-dir "$tmp/plain"
: >"$FAKE_STORE/writes"
expect ok PI --digests-dir "$tmp/plain"
[[ ! -s "$FAKE_STORE/writes" ]] || { echo "FAIL: plain re-run wrote"; fail=1; }

# Variant: compared between descriptor and configuration (absent == absent).
rm -rf "$tmp/reg" && fake_registry_init "$tmp/reg"
push "$tmp/var" linux/amd64 var
push "$tmp/var" linux/arm64 var "" v8
expect fail PI --digests-dir "$tmp/var"
contains "says linux/arm64, its configuration linux/arm64/v8"

# Hostile metadata is never printed: platform strings with a space, a control character, a
# host name; a configuration with a newline in its architecture.
for bad in "linux registry.example.com/amd64" $'linux\e[31m/amd64' $'linux/amd64\nregistry.example.com'; do
  rm -rf "$tmp/reg" "$tmp/bad" && fake_registry_init "$tmp/reg"
  push "$tmp/bad" linux/amd64 bad "$bad"
  push "$tmp/bad" linux/arm64 bad
  expect fail PI --digests-dir "$tmp/bad"
  contains "malformed platform in a descriptor"
  if grep -q "registry.example.com" <<<"$out" || [[ "$out" == *$'\e'* ]]; then
    echo "FAIL: hostile platform printed"
    fail=1
  fi
done
rm -rf "$tmp/reg" "$tmp/bad" && fake_registry_init "$tmp/reg"
push "$tmp/bad" linux/amd64 badcfg
push "$tmp/bad" linux/arm64 badcfg
for f in "$FAKE_STORE"/images/*; do
  jq -c 'if .architecture == "arm64" then .architecture = "arm64\nregistry.example.com" else . end' "$f" >"$f.new"
  mv "$f.new" "$f"
done
expect fail PI --digests-dir "$tmp/bad"
contains "malformed platform in the image configuration"
if grep -q "registry.example.com" <<<"$out"; then echo "FAIL: hostile configuration printed"; fail=1; fi

# Before any write: two images of one platform; a descriptor whose platform is not the image's.
rm -rf "$tmp/reg" && fake_registry_init "$tmp/reg"
push "$tmp/dup" linux/amd64 four
push "$tmp/dup" linux/amd64 five
expect fail PI --digests-dir "$tmp/dup"
contains "images for 'linux/amd64 linux/amd64 '"
push "$tmp/lie" linux/amd64 six linux/arm64
push "$tmp/lie" linux/arm64 six linux/amd64
expect fail PI --digests-dir "$tmp/lie"
contains ", its configuration linux/"
[[ ! -s "$FAKE_STORE/writes" ]] || { echo "FAIL: wrote despite invalid pushes"; fail=1; }

# os.version / os.features: present in the configuration but not in the descriptor.
for extra in '{"os.version": "10.0.1"}' '{"os.features": ["win32k"]}'; do
  rm -rf "$tmp/reg" "$tmp/osv" && fake_registry_init "$tmp/reg"
  push "$tmp/osv" linux/amd64 osv "" "" "$extra"
  push "$tmp/osv" linux/arm64 osv
  expect fail PI --digests-dir "$tmp/osv"
  contains "os.version / os.features differ"
done

# The pushed images must be labelled with this commit.
rm -rf "$tmp/reg" "$tmp/rev" && fake_registry_init "$tmp/reg"
push "$tmp/rev" linux/amd64 rev
push "$tmp/rev" linux/arm64 rev "" "" "{}" 89abcdef0123456789abcdef0123456789abcdef
expect fail PI --digests-dir "$tmp/rev"
contains "the linux/arm64 image is labelled with revision 89abcdef0123456789abcdef0123456789abcdef, expected $C"
rm -rf "$tmp/reg" "$tmp/rev" && fake_registry_init "$tmp/reg"
push "$tmp/rev" linux/amd64 rev2 "" "" "{}" $'sentinel.example.net\n'
push "$tmp/rev" linux/arm64 rev2
expect fail PI --digests-dir "$tmp/rev"
contains "malformed revision label"
[[ ! -s "$FAKE_STORE/writes" ]] || { echo "FAIL: wrote with a wrong revision"; fail=1; }

# Malformed registry data is reported with a fixed message: nothing of it is printed.
S=sentinel.example.net
malformed() { # raw push manifest
  rm -rf "$tmp/reg" "$tmp/mal" && fake_registry_init "$tmp/reg"
  push "$tmp/mal" linux/amd64 mal
  fake_put manifests "$1"
  touch "$tmp/mal/${FAKE_PUT#sha256:}"
  expect fail PI --digests-dir "$tmp/mal"
  if grep -q "$S" <<<"$out"; then echo "FAIL: malformed data printed: $1"; fail=1; fi
  [[ ! -s "$FAKE_STORE/writes" ]] || { echo "FAIL: wrote with malformed data"; fail=1; }
}
malformed '{"mediaType": "application/vnd.oci.image.index.v1+json", "manifests": "'"$S"'"}'
malformed '{"mediaType": "application/vnd.oci.image.index.v1+json", "manifests": ["'"$S"'"]}'
malformed '{"mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [{"digest": {"x": "'"$S"'"}, "platform": "'"$S"'"}]}'
malformed '{"mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:'"$(printf 'a%.0s' $(seq 1 64))"'", "size": 1, "platform": {"os": "linux", "architecture": "arm64", "'"$S"'": 1}}]}'
malformed '["'"$S"'"]'
malformed '"'"$S"'"'
# A malformed image configuration.
for cfg in '"'"$S"'"' '{"os": "linux", "architecture": "arm64", "config": "'"$S"'"}' \
  '{"os": "linux", "architecture": "arm64", "config": {"Labels": ["'"$S"'"]}}' \
  '{"os": ["'"$S"'"], "architecture": "arm64"}'; do
  rm -rf "$tmp/reg" "$tmp/mal" && fake_registry_init "$tmp/reg"
  push "$tmp/mal" linux/amd64 malcfg
  push "$tmp/mal" linux/arm64 malcfg
  for f in "$FAKE_STORE"/images/*; do
    if jq -e '.architecture == "arm64"' "$f" >/dev/null; then printf '%s' "$cfg" >"$f"; fi
  done
  expect fail PI --digests-dir "$tmp/mal"
  if grep -q "$S" <<<"$out"; then echo "FAIL: malformed configuration printed: $cfg"; fail=1; fi
done
# A file in the digests directory that is not named by a digest.
rm -rf "$tmp/reg" "$tmp/mal" && fake_registry_init "$tmp/reg"
mkdir -p "$tmp/mal" && touch "$tmp/mal/$S"
expect fail PI --digests-dir "$tmp/mal"
contains "a file in the digests directory is not named by a digest"
if grep -q "$S" <<<"$out"; then echo "FAIL: file name printed"; fail=1; fi

# One platform push only, a registry error, bad arguments.
rm -rf "$tmp/reg" && fake_registry_init "$tmp/reg"
push "$tmp/one" linux/amd64 three
expect fail PI --digests-dir "$tmp/one"
contains "1 platform pushes, expected 2"
push "$tmp/one" linux/arm64 three
fake_fail "ohttp-gateway:sha-"
expect fail PI --digests-dir "$tmp/one"
contains "registry lookup failed"
[[ ! -s "$FAKE_STORE/writes" ]] || { echo "FAIL: wrote despite a registry error"; fail=1; }
expect fail bash "$SCRIPT_DIR/publish-index.sh" --registry "$R" --image other --commit "$C" --digests-dir "$tmp/one"
expect fail bash "$SCRIPT_DIR/publish-index.sh" --registry "$R" --image ohttp-gateway --commit abc --digests-dir "$tmp/one"
expect fail bash "$SCRIPT_DIR/publish-index.sh" --registry "$R" --image ohttp-gateway --commit "$C" --digests-dir
contains "--digests-dir needs a value"

if [[ $fail -ne 0 ]]; then
  exit 1
fi
echo "publish-index: OK"

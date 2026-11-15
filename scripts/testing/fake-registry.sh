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

# A fake registry for the script tests (sourced): `docker buildx imagetools` and `cosign` stubs
# on PATH, backed by files, without network. Tags and signature/attestation records are
# immutable like those of the registry the images are pushed to: a second write of one fails.
#
#   fake_registry_init <dir>              stubs in <dir>/bin (prepended to PATH), store in <dir>/store
#   fake_release_image <repo> <tag> <commit> [options]   -> FAKE_DIGEST (index), FAKE_PLATFORMS
#   fake_tag <ref> <digest>; fake_sign <digest> <identity> <workflow-sha>
#   fake_attest <digest> <identity> <workflow-sha> <commit> [<subject digest>]
#   fake_fail <substring>                 inspect/create of a matching reference fails (401)
#   fake_fail_create <substring>          only the tag write of a matching reference fails (500)
#   fake_clear_failures
#   fake_writes                           the writes so far ("create <ref>", "sign <d>", "attest <d>")

fake_registry_init() {
  FAKE_DIR="$1"
  export FAKE_STORE="$FAKE_DIR/store"
  mkdir -p "$FAKE_DIR/bin" "$FAKE_STORE"/{tags,manifests,images,sigs,atts}
  : >"$FAKE_STORE/writes"
  : >"$FAKE_STORE/fail"
  : >"$FAKE_STORE/fail-create"
  cat >"$FAKE_DIR/bin/docker" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
S="$FAKE_STORE"
key() { printf '%s' "$1" | tr '/:@' '___'; }
fail_check() {
  local pat
  while read -r pat; do
    if [[ -n "$pat" && "$1" == *"$pat"* ]]; then
      echo "ERROR: failed to authorize: 401 Unauthorized" >&2
      exit 1
    fi
  done <"$S/fail"
}
resolve() {
  local ref="$1" d
  if [[ "$ref" == *@sha256:* ]]; then
    d="${ref##*@}"
    if [[ -f "$S/manifests/$d" ]]; then echo "$d"; fi
  elif [[ -f "$S/tags/$(key "$ref")" ]]; then
    cat "$S/tags/$(key "$ref")"
  fi
}
[[ "${1:-} ${2:-}" == "buildx imagetools" ]] || { echo "docker stub: unsupported: $*" >&2; exit 2; }
sub="$3"
shift 3
case "$sub" in
  inspect)
    ref="$1"
    shift
    fail_check "$ref"
    d="$(resolve "$ref")"
    if [[ -z "$d" ]]; then
      if [[ -s "$S/notfound-text" ]]; then
        # {ref} and {url} (the manifest URL of the reference) are filled in.
        name="${ref%@*}"
        tagpart="${ref##*@}"
        if [[ "$name" == "$ref" ]]; then name="${ref%:*}"; tagpart="${ref##*:}"; fi
        url="https://${name%%/*}/v2/${name#*/}/manifests/$tagpart"
        t="$(cat "$S/notfound-text")"
        t="${t//\{ref\}/$ref}"
        t="${t//\{url\}/$url}"
        t="${t//\{otherurl\}/https://other.example.com/v2/${name#*/}/manifests/$tagpart}"
        printf '%s\n' "$t" >&2
      else
        echo "ERROR: $ref: not found" >&2
      fi
      exit 1
    fi
    case "${1:-}" in
      --raw) cat "$S/manifests/$d" ;;
      --format)
        case "$2" in
          '{{json .Manifest}}')
            jq -c --arg d "$d" --argjson n "$(wc -c <"$S/manifests/$d")" '{mediaType, digest: $d, size: $n}' "$S/manifests/$d"
            ;;
          '{{json .Image}}')
            [[ -f "$S/images/$d" ]] || { echo "ERROR: no image configuration" >&2; exit 1; }
            cat "$S/images/$d"
            ;;
          *) echo "docker stub: unsupported format $2" >&2; exit 2 ;;
        esac
        ;;
      *) echo "docker stub: unsupported inspect $*" >&2; exit 2 ;;
    esac
    ;;
  create)
    [[ "$1" == "-t" && $# -ge 3 ]] || { echo "docker stub: unsupported create $*" >&2; exit 2; }
    dst="$2"
    src="$3"
    shift 2
    fail_check "$dst"
    while read -r pat; do
      if [[ -n "$pat" && "$dst" == *"$pat"* ]]; then
        echo "ERROR: failed to write: 500 Internal Server Error" >&2
        exit 1
      fi
    done <"$S/fail-create"
    if [[ $# -eq 1 ]]; then
      d="$(resolve "$src")"
      [[ -n "$d" ]] || { echo "ERROR: $src: not found" >&2; exit 1; }
    else
      # Several sources: one index of their manifests (an index source is flattened).
      m="[]"
      for src in "$@"; do
        sd="$(resolve "$src")"
        [[ -n "$sd" ]] || { echo "ERROR: $src: not found" >&2; exit 1; }
        if jq -e '.manifests' "$S/manifests/$sd" >/dev/null 2>&1; then
          m="$(jq -c --slurpfile i "$S/manifests/$sd" '. + $i[0].manifests' <<<"$m")"
        else
          m="$(jq -c --arg d "$sd" --slurpfile c "$S/images/$sd" --argjson n "$(wc -c <"$S/manifests/$sd")" \
            '. + [{mediaType: "application/vnd.oci.image.manifest.v1+json", digest: $d, size: $n,
              platform: ({os: $c[0].os, architecture: $c[0].architecture}
                + (if $c[0].variant then {variant: $c[0].variant} else {} end))}]' <<<"$m")"
        fi
      done
      idx="$(jq -cn --argjson m "$m" '{schemaVersion: 2, mediaType: "application/vnd.oci.image.index.v1+json", manifests: $m}')"
      d="sha256:$(printf '%s' "$idx" | sha256sum | cut -c1-64)"
      printf '%s' "$idx" >"$S/manifests/$d"
    fi
    k="$S/tags/$(key "$dst")"
    [[ ! -e "$k" ]] || { echo "ERROR: tag invalid: the image tag already exists" >&2; exit 1; }
    echo "$d" >"$k"
    echo "create $dst" >>"$S/writes"
    ;;
  *) echo "docker stub: unsupported $sub" >&2; exit 2 ;;
esac
STUB
  cat >"$FAKE_DIR/bin/cosign" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
S="$FAKE_STORE"
cmd="$1"
shift
re="" wsha="" pred="" ref="" type="" issuer=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --certificate-identity-regexp) re="$2"; shift 2 ;;
    --certificate-oidc-issuer) issuer="$2"; shift 2 ;;
    --certificate-github-workflow-sha) wsha="$2"; shift 2 ;;
    --type) type="$2"; shift 2 ;;
    --predicate) pred="$2"; shift 2 ;;
    --yes) shift ;;
    -*) echo "cosign stub: unsupported flag $1" >&2; exit 2 ;;
    *) ref="$1"; shift ;;
  esac
done
[[ "$ref" == *@sha256:* ]] || { echo "cosign stub: not a digest reference" >&2; exit 2; }
d="${ref##*@}"
[[ -f "$S/manifests/$d" ]] || { echo "Error: $ref: not found" >&2; exit 1; }
matching() {
  local file="$1" id sha rest
  [[ -f "$file" ]] || return 0
  while IFS=$'\t' read -r id sha rest; do
    if printf '%s\n' "$id" | grep -Eq -- "$re" && [[ -z "$wsha" || "$wsha" == "$sha" ]]; then
      printf '%s\n' "${rest:-x}"
    fi
  done <"$file"
}
case "$cmd" in
  verify | verify-attestation)
    # Certificates are issued by the GitHub Actions OIDC issuer only.
    if [[ "$issuer" != "https://token.actions.githubusercontent.com" ]]; then
      echo "Error: none of the certificates matched the OIDC issuer '$issuer'" >&2
      exit 1
    fi
    ;;
esac
case "$cmd" in
  verify)
    [[ -n "$re" ]] || exit 2
    out="$(matching "$S/sigs/$d")"
    [[ -n "$out" ]] || { echo "Error: no matching signatures" >&2; exit 1; }
    echo '[{"critical":{}}]'
    ;;
  verify-attestation)
    [[ -n "$re" && "$type" == "slsaprovenance" ]] || exit 2
    out="$(matching "$S/atts/$d")"
    [[ -n "$out" ]] || { echo "Error: no matching attestations" >&2; exit 1; }
    while read -r stmt; do
      jq -cn --arg p "$(printf '%s' "$stmt" | base64 -w0)" '{payloadType: "application/vnd.in-toto+json", payload: $p}'
    done <<<"$out"
    ;;
  sign)
    [[ ! -e "$S/sigs/$d" ]] || { echo "Error: signature tag already exists (immutable)" >&2; exit 1; }
    printf '%s\t%s\tx\n' "$FAKE_SIGNER_IDENTITY" "$FAKE_SIGNER_SHA" >"$S/sigs/$d"
    echo "sign $d" >>"$S/writes"
    ;;
  attest)
    [[ "$type" == "slsaprovenance" && -f "$pred" ]] || exit 2
    [[ ! -e "$S/atts/$d" ]] || { echo "Error: attestation tag already exists (immutable)" >&2; exit 1; }
    # Like cosign: the subject is named after the repository of the reference.
    stmt="$(jq -c --arg hex "${d#sha256:}" --arg name "${ref%@*}" '{predicateType: "https://slsa.dev/provenance/v0.2",
      subject: [{name: $name, digest: {sha256: $hex}}], predicate: .}' "$pred")"
    printf '%s\t%s\t%s\n' "$FAKE_SIGNER_IDENTITY" "$FAKE_SIGNER_SHA" "$stmt" >"$S/atts/$d"
    echo "attest $d" >>"$S/writes"
    ;;
  *) echo "cosign stub: unsupported $cmd" >&2; exit 2 ;;
esac
STUB
  chmod +x "$FAKE_DIR/bin/docker" "$FAKE_DIR/bin/cosign"
  export PATH="$FAKE_DIR/bin:$PATH"
}

fake_key() { printf '%s' "$1" | tr '/:@' '___'; }

fake_put() {
  local kind="$1" json="$2" d
  d="sha256:$(printf '%s' "$json" | sha256sum | cut -c1-64)"
  printf '%s' "$json" >"$FAKE_STORE/$kind/$d"
  FAKE_PUT="$d"
}

fake_tag() { echo "$2" >"$FAKE_STORE/tags/$(fake_key "$1")"; }

fake_fail() { echo "$1" >>"$FAKE_STORE/fail"; }

fake_fail_create() { echo "$1" >>"$FAKE_STORE/fail-create"; }

fake_clear_failures() { : >"$FAKE_STORE/fail"; : >"$FAKE_STORE/fail-create"; }

fake_writes() { cat "$FAKE_STORE/writes"; }

fake_sign() { printf '%s\t%s\tx\n' "$2" "$3" >>"$FAKE_STORE/sigs/$1"; }

# fake_attest <digest> <identity> <workflow-sha> <commit> [<subject digest>] [<repository>]
# [<image>]: the subject is named <repository>; the predicate names <image> (default: the last
# path element of <repository>).
fake_attest() {
  local d="$1" identity="$2" wsha="$3" commit="$4" subject="${5:-$1}" name="${6:-}" img="${7:-}" stmt
  img="${img:-${name##*/}}"
  stmt="$(jq -cn --arg hex "${subject#sha256:}" --arg c "$commit" --arg name "$name" --arg img "$img" '{
    predicateType: "https://slsa.dev/provenance/v0.2",
    subject: [{name: $name, digest: {sha256: $hex}}],
    predicate: {invocation: {configSource: {digest: {sha1: $c}},
      parameters: {image: $img}}, materials: [{digest: {sha1: $c}}]}}')"
  printf '%s\t%s\t%s\n' "$identity" "$wsha" "$stmt" >>"$FAKE_STORE/atts/$d"
}

# A published image as the main build leaves it: platform images (labelled with the commit),
# an attestation manifest per platform, the index tagged <tag>, signed and attested by
# <identity> (default: the main build of example-org/example-repo) at <commit>.
# Options: --no-labels P, --no-revision P, --revision P REV, --only-amd64, --extra P,
#          --no-sign, --no-attest, --identity ID, --attest-commit C, --attest-subject D,
#          --nonce N (distinct digests for equal inputs), --index-only (platform images neither
#          signed nor attested), --unsigned-platform P, --unattested-platform P.
fake_release_image() {
  local repo="$1" tag="$2" commit="$3"
  shift 3
  local identity="https://github.com/example-org/example-repo/.github/workflows/ohttp-build.yml@refs/heads/main"
  local sign=1 attest=1 attest_commit="$commit" attest_subject="" nonce="" index_only=0
  local -A labels=() rev=() unsigned=() unattested=() pdig=()
  local -a plats=(linux/amd64 linux/arm64)
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --no-labels) labels[$2]=none; shift 2 ;;
      --no-revision) labels[$2]=norev; shift 2 ;;
      --revision) rev[$2]="$3"; shift 3 ;;
      --only-amd64) plats=(linux/amd64); shift ;;
      --extra) plats+=("$2"); shift 2 ;;
      --no-sign) sign=0; shift ;;
      --no-attest) attest=0; shift ;;
      --identity) identity="$2"; shift 2 ;;
      --attest-commit) attest_commit="$2"; shift 2 ;;
      --attest-subject) attest_subject="$2"; shift 2 ;;
      --nonce) nonce="$2"; shift 2 ;;
      --index-only) index_only=1; shift ;;
      --unsigned-platform) unsigned[$2]=1; shift 2 ;;
      --unattested-platform) unattested[$2]=1; shift 2 ;;
      *) echo "fake_release_image: unknown option $1" >&2; return 2 ;;
    esac
  done
  local manifests="[]" p os arch cfg r
  FAKE_PLATFORMS=()
  for p in "${plats[@]}"; do
    os="${p%/*}"
    arch="${p#*/}"
    r="${rev[$p]:-$commit}"
    case "${labels[$p]:-ok}" in
      none) cfg="$(jq -cn --arg os "$os" --arg a "$arch" --arg n "$nonce$repo$tag" '{os: $os, architecture: $a, config: {}, n: $n}')" ;;
      norev) cfg="$(jq -cn --arg os "$os" --arg a "$arch" --arg n "$nonce$repo$tag" '{os: $os, architecture: $a, config: {Labels: {"org.opencontainers.image.title": "x"}}, n: $n}')" ;;
      *) cfg="$(jq -cn --arg os "$os" --arg a "$arch" --arg r "$r" --arg n "$nonce$repo$tag" '{os: $os, architecture: $a, config: {Labels: {"org.opencontainers.image.revision": $r}}, n: $n}')" ;;
    esac
    fake_put manifests "$(jq -cn --arg c "$cfg" '{mediaType: "application/vnd.oci.image.manifest.v1+json", c: $c}')"
    printf '%s' "$cfg" >"$FAKE_STORE/images/$FAKE_PUT"
    FAKE_PLATFORMS+=("$FAKE_PUT")
    pdig[$p]="$FAKE_PUT"
    manifests="$(jq -c --arg d "$FAKE_PUT" --arg os "$os" --arg a "$arch" \
      '. + [{mediaType: "application/vnd.oci.image.manifest.v1+json", digest: $d, platform: {os: $os, architecture: $a}}]' <<<"$manifests")"
    fake_put manifests "$(jq -cn --arg d "$FAKE_PUT" '{mediaType: "application/vnd.oci.image.manifest.v1+json", attests: $d}')"
    manifests="$(jq -c --arg d "$FAKE_PUT" \
      '. + [{mediaType: "application/vnd.oci.image.manifest.v1+json", digest: $d, platform: {os: "unknown", architecture: "unknown"}}]' <<<"$manifests")"
  done
  fake_put manifests "$(jq -cn --argjson m "$manifests" '{schemaVersion: 2, mediaType: "application/vnd.oci.image.index.v1+json", manifests: $m}')"
  FAKE_DIGEST="$FAKE_PUT"
  fake_tag "$repo:$tag" "$FAKE_DIGEST"
  if [[ $sign -eq 1 ]]; then
    fake_sign "$FAKE_DIGEST" "$identity" "$commit"
  fi
  if [[ $attest -eq 1 ]]; then
    fake_attest "$FAKE_DIGEST" "$identity" "$commit" "$attest_commit" "${attest_subject:-$FAKE_DIGEST}" "$repo"
  fi
  [[ $index_only -eq 0 ]] || return 0
  for p in "${plats[@]}"; do
    if [[ $sign -eq 1 && -z "${unsigned[$p]:-}" ]]; then
      fake_sign "${pdig[$p]}" "$identity" "$commit"
    fi
    if [[ $attest -eq 1 && -z "${unattested[$p]:-}" ]]; then
      fake_attest "${pdig[$p]}" "$identity" "$commit" "$attest_commit" "${pdig[$p]}" "$repo"
    fi
  done
}

# The registry answers a missing reference with this text instead of "ERROR: <ref>: not found"
# ({ref}: the reference, {url}: its manifest URL, {otherurl}: the same on another host).
fake_notfound_text() { printf '%s\n' "$1" >"$FAKE_STORE/notfound-text"; }

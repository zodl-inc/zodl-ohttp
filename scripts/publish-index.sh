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

# Creates the multi-platform index of a main build, re-run safe on a registry with immutable tags.
#
#   publish-index.sh --registry <host[/prefix]> --image <name> --commit <sha>
#                    --digests-dir <dir> [--output <file>]
#
# <dir> holds one empty file per platform image pushed by this run, named by the hex digest (the
# build job's artifacts); there must be one per platform (2). If <image>:sha-<short> does not
# exist, it is created from those digests (docker buildx imagetools create). If it exists (a
# re-run after a later step failed), it is kept only if it is exactly the index of these
# pushes: the same descriptors (media type, digest, size, platform) as the pushes contribute (an index
# push contributes its manifests, as imagetools create flattens it); otherwise the run fails.
# Before any write, the pushed images must be exactly one linux/amd64 and one linux/arm64 image,
# each descriptor's platform that of the image's configuration; the resulting index is checked
# the same way. A full re-run of the workflow rebuilds the images with new digests and is
# refused once sha-<short> exists: re-run the failed jobs only, or push a new commit. Prints,
# and appends to <file> if given, `digest=<index digest>`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=image-lib.sh
source "$SCRIPT_DIR/image-lib.sh"

# Canonical descriptors of an index (stdin), one compact JSON object per line with sorted
# keys: mediaType, digest, size and the whole platform object (os, architecture, variant,
# os.version, os.features, whatever is present). Annotations are left out: buildx may add or
# rewrite descriptor annotations when it combines indexes, and they do not select or identify
# an image (the attestation manifests' references to their image are by digest in the
# attestation itself).
canonical_descriptors() {
  jq_data "$1" -c -S '.manifests[] | if type == "object" then {mediaType, digest, size, platform}
    else error("x") end'
}

# The canonical platform object (sorted keys, only the fields present) of a JSON value given
# as $p in jq: os and architecture, and variant, os.version, os.features when present; every
# value of a strict charset, else null.
PLATFORM_JQ='def chk(re): type == "string" and test(re);
  if ($p | type) == "object"
     and ($p | keys - ["architecture", "os", "variant", "os.version", "os.features"] | length) == 0
     and ($p.os | chk("^[a-z0-9_]+$")) and ($p.architecture | chk("^[a-z0-9_]+$"))
     and ($p.variant == null or ($p.variant | chk("^[a-z0-9_]+$")))
     and ($p["os.version"] == null or ($p["os.version"] | chk("^[A-Za-z0-9._-]+$")))
     and ($p["os.features"] == null or (($p["os.features"] | type) == "array"
          and all($p["os.features"][]; chk("^[A-Za-z0-9._+-]+$"))))
  then $p | to_entries | map(select(.value != null)) | sort_by(.key) | from_entries
  else null end'

# Checks a canonical descriptor line from a registry (digest, media type, size, platform all
# well-formed; fields separated by \x1f, not whitespace, so that an empty field does not shift
# the others); prints "<digest> <os>/<arch>[/<variant>] <canonical platform JSON>". Values are
# printed by the callers only after these checks.
descriptor_platform() {
  local line="$1" label="$2" out d mt size pl pobj
  out="$(jq_data "$label" -r -S "(.platform) as \$p | ($PLATFORM_JQ) as \$c
    | [ (.digest | if type == \"string\" then . else \"\" end),
        (.mediaType | if type == \"string\" then . else \"\" end),
        (.size | if type == \"number\" and . >= 0 and floor == . then tostring else \"\" end),
        (if \$c == null then \"\" else \"\(\$c.os)/\(\$c.architecture)\(if \$c.variant then \"/\" + \$c.variant else \"\" end)\" end),
        (if \$c == null then \"\" else (\$c | tojson) end) ] | join(\"\\u001f\")" <<<"$line")" || exit 1
  IFS=$'\x1f' read -r d mt size pl pobj <<<"$out"
  [[ "$d" =~ $DIGEST_RE ]] || die "$label: malformed digest in a descriptor"
  [[ "$mt" =~ ^application/[a-z0-9.+-]+$ ]] || die "$label: malformed media type in a descriptor"
  [[ "$size" =~ ^[0-9]+$ ]] || die "$label: malformed size in a descriptor"
  [[ "$pl" =~ $PLATFORM_RE && -n "$pobj" ]] || die "$label: malformed platform in a descriptor"
  printf '%s %s %s\n' "$d" "$pl" "$pobj"
}

# An image's configuration: IMAGE_PLATFORM ("<os>/<arch>[/<variant>]"), IMAGE_PLATFORM_JSON
# (the canonical platform object of PLATFORM_JQ) and REVISION, all checked.
image_platform() {
  local out
  image_revision "$1" "$2"
  out="$(jq_data "$2" -r -S "(. | if type == \"object\" then {os, architecture, variant,
      \"os.version\": .[\"os.version\"], \"os.features\": .[\"os.features\"]} else null end) as \$p
    | ($PLATFORM_JQ) as \$c
    | if \$c == null then \"\" else
        \"\(\$c.os)/\(\$c.architecture)\(if \$c.variant then \"/\" + \$c.variant else \"\" end)\u001f\(\$c | tojson)\" end" \
    <<<"$IMAGE_CONFIG")" || exit 1
  IFS=$'\x1f' read -r IMAGE_PLATFORM IMAGE_PLATFORM_JSON <<<"$out"
  [[ "$IMAGE_PLATFORM" =~ $PLATFORM_RE && -n "$IMAGE_PLATFORM_JSON" ]] ||
    die "$2: malformed platform in the image configuration"
}

main() {
  local registry="" image="" commit="" dir="" output=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --registry) need_value "$@"; registry="$2"; shift 2 ;;
      --image) need_value "$@"; image="$2"; shift 2 ;;
      --commit) need_value "$@"; commit="$2"; shift 2 ;;
      --digests-dir) need_value "$@"; dir="$2"; shift 2 ;;
      --output) need_value "$@"; output="$2"; shift 2 ;;
      *) die "unknown argument '$1'" ;;
    esac
  done
  [[ "$registry" =~ $REGISTRY_RE ]] || die "the registry is not a registry name"
  [[ "$image" =~ $IMAGES_RE ]] || die "image '$image' is not one of the published images"
  [[ "$commit" =~ $COMMIT_RE ]] || die "commit '$commit' is not a full commit SHA"
  [[ -d "$dir" ]] || die "no digests directory"

  local repo="$registry/$image" tag="sha-${commit:0:7}" f d
  local -a pushed=() sources=()
  for f in "$dir"/*; do
    [[ -e "$f" ]] || continue
    d="sha256:$(basename "$f")"
    [[ "$d" =~ $DIGEST_RE ]] || die "$image: a file in the digests directory is not named by a digest"
    pushed+=("$d")
    sources+=("$repo@$d")
  done
  # Both platforms must be present; never tag an index that misses one.
  [[ ${#pushed[@]} -eq ${#REQUIRED_PLATFORMS[@]} ]] ||
    die "$image: ${#pushed[@]} platform pushes, expected ${#REQUIRED_PLATFORMS[@]}"

  # The descriptors this run's pushes contribute to the index ("<digest> <os>/<arch>[/<variant>]";
  # an index push contributes its manifests, as imagetools create flattens it; attestation
  # manifests are unknown/unknown). Each image descriptor's platform must be that of the image's
  # configuration, and the images must be exactly one linux/amd64 and one linux/arm64.
  local expected="" line images="" platforms="" pl pobj desc out
  for d in "${pushed[@]}"; do
    inspect_raw "$repo@$d" "$image@$d"
    if is_index "$RAW"; then
      out="$(canonical_descriptors "$image@$d" <<<"$RAW")" || exit 1
      expected+="$out"$'\n'
    else
      capture docker buildx imagetools inspect "$repo@$d" --format '{{json .Manifest}}' ||
        die "$image@$d: cannot read its descriptor"
      desc="$CAPTURED"
      image_platform "$repo@$d" "$image@$d"
      out="$(jq_data "$image@$d" -c -S -n --argjson m "$desc" --argjson p "$IMAGE_PLATFORM_JSON" \
        'if ($m | type) == "object" then {mediaType: $m.mediaType, digest: $m.digest, size: $m.size,
          platform: $p} else error("x") end')" || exit 1
      expected+="$out"$'\n'
    fi
  done
  expected="$(grep . <<<"$expected" | sort)"
  # Every descriptor well-formed; each image descriptor's platform (os, architecture, variant,
  # os.version and os.features: absent == absent, present must be equal) that of the image's
  # configuration, and the image labelled with this commit; attestation manifests
  # (unknown/unknown) allowed and left out of the platform set.
  while IFS= read -r line; do
    out="$(descriptor_platform "$line" "$image")" || exit 1
    read -r d pl pobj <<<"$out"
    [[ "$pl" == unknown/unknown ]] && continue
    image_platform "$repo@$d" "$image@$d"
    [[ "$pobj" == "$IMAGE_PLATFORM_JSON" ]] ||
      die "$image: the descriptor of $d says $pl, its configuration $IMAGE_PLATFORM (or their os.version / os.features differ)"
    [[ -n "$REVISION" ]] || die "$image: the $pl image has no org.opencontainers.image.revision label"
    [[ "$REVISION" =~ $COMMIT_RE ]] || die "$image: the $pl image has a malformed revision label"
    [[ "$REVISION" == "$commit" ]] ||
      die "$image: the $pl image is labelled with revision $REVISION, expected $commit"
    images+="$d $pl"$'\n'
    platforms+="$(cut -d/ -f1-2 <<<"$pl")"$'\n'
  done <<<"$expected"
  platforms="$(grep . <<<"$platforms" | sort | tr '\n' ' ')"
  [[ "$platforms" == "linux/amd64 linux/arm64 " ]] ||
    die "$image: the pushes contain images for '$platforms', expected one linux/amd64 and one linux/arm64"
  images="$(grep . <<<"$images")"

  local digest actual existed=0
  if lookup_digest "$repo:$tag" "$image:$tag"; then
    digest="$LOOKUP"
    existed=1
    log "$image:$tag already exists ($digest); checking it is the index of this run's pushes"
  else
    capture docker buildx imagetools create -t "$repo:$tag" "${sources[@]}" ||
      die "$image: creating $tag failed"
    lookup_digest "$repo:$tag" "$image:$tag" || die "$image:$tag is missing after its creation"
    digest="$LOOKUP"
    log "$image:$tag created ($digest)"
  fi
  # The index (new or existing) must be exactly these descriptors: media type, digest, size and
  # platform.
  inspect_raw "$repo@$digest" "$image:$tag"
  is_index "$RAW" || die "$image:$tag is not an index"
  actual="$(canonical_descriptors "$image:$tag" <<<"$RAW")" || exit 1
  actual="$(sort <<<"$actual")"
  [[ "$actual" == "$expected" ]] ||
    die "$image:$tag ($digest) is not the index of this run's platform images; tags are never overwritten"
  while read -r d line; do
    log "$image:$tag $line = $d"
  done <<<"$images"
  if [[ $existed -eq 1 ]]; then
    log "$image:$tag is the index of this run's platform images ($digest), kept"
  fi
  printf 'digest=%s\n' "$digest"
  if [[ -n "$output" ]]; then
    printf 'digest=%s\n' "$digest" >>"$output"
  fi
}

main "$@"

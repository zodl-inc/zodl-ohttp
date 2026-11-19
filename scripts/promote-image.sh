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

# Release tags promote the images the main build of the tagged commit already pushed, instead of
# building them again: the version tag names the same multi-platform index digest as
# sha-<short>, the digest that was tested and that deployments pin. A release signs nothing: the
# digest keeps the signature and the provenance attestation of the main build, which is what
# scripts/verify-image.sh checks for a release image.
#
#   promote-image.sh check-tag --tag <vX.Y.Z> --commit <sha> [--main-ref <ref>] [--root <dir>]
#                              [--keys-file <path>]
#     Refuses a tag that is not SemVer (vMAJOR.MINOR.PATCH[-PRERELEASE], at most 128 characters
#     after the v), that is not an annotated tag with a good signature by a key of <keys-file>
#     (a path in the repository, read from <main-ref>; default .github/release-signing-keys.asc;
#     missing or empty = refused), whose tag object is not named <tag> or does not name the
#     commit <sha> directly, that does not resolve to <sha>, whose commit is not an ancestor of
#     <main-ref> (default origin/main), or whose version differs from the gateway or
#     relay-simulator crate version or from their entries in the commit's Cargo.lock files.
#     Prints `version=<X.Y.Z>`.
#
#   promote-image.sh promote --registry <host[/prefix]> --commit <sha> --version <X.Y.Z>
#                            --repository <org/repo> [--check-only]
#     Preflight, for every image (ohttp-gateway, ohttp-relay-simulator, ohttp-e2e) before any
#     write: <image>:sha-<short> exists; it is an index with one linux/amd64 and one linux/arm64
#     image, each labelled org.opencontainers.image.revision=<sha>; the index and each platform
#     image carry the signature and the SLSA provenance attestation of ohttp-build.yml on
#     refs/heads/main of <org/repo> at <sha> (certificate workflow SHA), each attestation naming
#     its digest, <sha> and the image (subject name and invocation.parameters.image; images
#     published before the predicate named the image cannot be promoted);
#     <image>:<version> is absent or already names the same digest. Only then, for every image
#     not yet tagged, `docker buildx imagetools create -t <version>` from that one digest (one
#     index source: the index bytes, and so the digest, are kept) and a check that the tag
#     resolves to the digest. --check-only stops after the preflight.
#
#     Registry writes are not transactional: if a tag write fails after others succeeded, run
#     the job again; images already tagged with the same digest are accepted and the rest are
#     tagged. A version tag never names another digest (preflight, then a check after each write).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=image-lib.sh
source "$SCRIPT_DIR/image-lib.sh"

# SemVer 2.0.0 without build metadata (`+` is not valid in an image tag): numeric identifiers
# without leading zeros; pre-release identifiers alphanumeric or hyphen.
NUM_ID='(0|[1-9][0-9]*)'
PRE_ID='(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
TAG_RE="^v${NUM_ID}\\.${NUM_ID}\\.${NUM_ID}(-${PRE_ID}(\\.${PRE_ID})*)?\$"
# An image tag is at most 128 characters.
MAX_VERSION_LEN=128
DEFAULT_KEYS_FILE=".github/release-signing-keys.asc"
RELEASE_IMAGES=(ohttp-gateway ohttp-relay-simulator ohttp-e2e)

tag_version() {
  [[ "$1" =~ $TAG_RE ]] || die "tag '$1' is not vMAJOR.MINOR.PATCH[-PRERELEASE] (SemVer)"
  local version="${1#v}"
  [[ ${#version} -le $MAX_VERSION_LEN ]] ||
    die "version is ${#version} characters, an image tag allows $MAX_VERSION_LEN"
  printf '%s\n' "$version"
}

# The `version` of the [package] section of a Cargo.toml (stdin).
crate_version() {
  awk '
    /^\[/ { in_pkg = ($0 == "[package]") }
    in_pkg && /^version[ \t]*=/ {
      v = $0
      sub(/^version[ \t]*=[ \t]*"/, "", v)
      sub(/".*$/, "", v)
      print v
      exit
    }
  '
}

# "<name> <version>" of every [[package]] of a Cargo.lock (stdin).
lock_packages() {
  awk '
    /^\[\[package\]\]/ { name = ""; next }
    /^name = "/ { name = $3; gsub(/"/, "", name); next }
    /^version = "/ && name != "" { v = $3; gsub(/"/, "", v); print name, v; name = "" }
  '
}

# The crate versions and lock entries are read from the tagged commit, not from the working tree.
check_versions() {
  local version="$1" root="$2" commit="$3" crate v lock name lv found
  for crate in gateway relay-simulator; do
    git -C "$root" cat-file -e "$commit:$crate/Cargo.toml" 2>/dev/null ||
      die "$crate/Cargo.toml is missing at $commit"
    v="$(git -C "$root" show "$commit:$crate/Cargo.toml" | crate_version)"
    [[ -n "$v" ]] || die "no package version in $crate/Cargo.toml"
    [[ "$v" == "$version" ]] ||
      die "tag version $version differs from the $crate crate version $v (bump it before tagging)"
  done
  # Every lock file of the commit that has an entry for one of the two crates (path
  # dependencies) must carry the version; each crate's own lock must have its entry.
  for lock in gateway relay-simulator client e2e-client fuzz; do
    git -C "$root" cat-file -e "$commit:$lock/Cargo.lock" 2>/dev/null || continue
    found=""
    while read -r name lv; do
      case "$name" in
        zodl-ohttp-gateway | ohttp-relay-simulator)
          [[ "$lv" == "$version" ]] ||
            die "$lock/Cargo.lock has $name $lv, expected $version (update the lock file)"
          found="$found $name"
          ;;
      esac
    done < <(git -C "$root" show "$commit:$lock/Cargo.lock" | lock_packages)
    case "$lock" in
      gateway) [[ "$found" == *" zodl-ohttp-gateway"* ]] || die "gateway/Cargo.lock has no zodl-ohttp-gateway entry" ;;
      relay-simulator)
        [[ "$found" == *" ohttp-relay-simulator"* ]] ||
          die "relay-simulator/Cargo.lock has no ohttp-relay-simulator entry"
        ;;
    esac
  done
  for lock in gateway relay-simulator; do
    git -C "$root" cat-file -e "$commit:$lock/Cargo.lock" 2>/dev/null || die "$lock/Cargo.lock is missing"
  done
}

check_ancestor() {
  local root="$1" commit="$2" main_ref="$3"
  git -C "$root" rev-parse --verify --quiet "${main_ref}^{commit}" >/dev/null ||
    die "$main_ref is not available (fetch the main branch first)"
  git -C "$root" merge-base --is-ancestor "$commit" "$main_ref" ||
    die "commit $commit is not on $main_ref: release tags must name a commit of main"
}

# The tag must be an annotated tag with a good signature by a key of the keys file of main.
# The signed tag object itself must be this release: its `tag` header is the ref name and its
# `object` the commit, directly (type commit, not a tag of a tag). A signed tag object pushed
# under another name, or one that names something else, is refused.
check_tag_object() {
  local root="$1" tag="$2" commit="$3" obj header_obj header_type header_tag
  [[ "$(git -C "$root" cat-file -t "refs/tags/$tag" 2>/dev/null)" == "tag" ]] ||
    die "tag $tag is not an annotated tag"
  obj="$(git -C "$root" cat-file tag "refs/tags/$tag")"
  header_obj="$(sed -n '1,/^$/{s/^object //p}' <<<"$obj" | head -n 1)"
  header_type="$(sed -n '1,/^$/{s/^type //p}' <<<"$obj" | head -n 1)"
  header_tag="$(sed -n '1,/^$/{s/^tag //p}' <<<"$obj" | head -n 1)"
  # Header values are printed only when well-formed.
  if [[ "$header_tag" != "$tag" ]]; then
    [[ "$header_tag" =~ ^[A-Za-z0-9._+-]{1,140}$ ]] || die "the tag object under $tag has a malformed name"
    die "the tag object under $tag is named '$header_tag'"
  fi
  if [[ "$header_type" != "commit" ]]; then
    [[ "$header_type" =~ ^(tag|tree|blob)$ ]] || die "the tag object of $tag has a malformed type"
    die "tag $tag points at a $header_type, not a commit"
  fi
  if [[ "$header_obj" != "$commit" ]]; then
    [[ "$header_obj" =~ $COMMIT_RE ]] || die "the tag object of $tag names a malformed object"
    die "the tag object of $tag names $header_obj, not $commit"
  fi
}

# Runs in a subshell: the temporary keyring is removed however it ends.
check_signature() (
  local root="$1" tag="$2" main_ref="$3" keys_file="$4" gnupghome status rc
  [[ "$(git -C "$root" cat-file -t "refs/tags/$tag" 2>/dev/null)" == "tag" ]] ||
    die "tag $tag is not an annotated tag"
  gnupghome="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "gpgconf --homedir '$gnupghome' --kill all >/dev/null 2>&1 || true; rm -rf '$gnupghome'" EXIT
  if ! git -C "$root" show "$main_ref:$keys_file" >"$gnupghome/keys.asc" 2>/dev/null ||
    ! grep -q 'BEGIN PGP PUBLIC KEY BLOCK' "$gnupghome/keys.asc"; then
    die "no release signing keys in $keys_file on $main_ref: refusing the tag"
  fi
  GNUPGHOME="$gnupghome" gpg --batch --quiet --import "$gnupghome/keys.asc" >/dev/null 2>&1 ||
    die "cannot import the release signing keys of $keys_file"
  set +e
  status="$(GNUPGHOME="$gnupghome" git -C "$root" verify-tag --raw "$tag" 2>&1 >/dev/null)"
  rc=$?
  set -e
  verbose "$status"
  [[ $rc -eq 0 ]] || die "tag $tag has no good signature by a release signing key"
  grep -q '^\[GNUPG:\] GOODSIG ' <<<"$status" && grep -q '^\[GNUPG:\] VALIDSIG ' <<<"$status" ||
    die "tag $tag has no good signature by a release signing key"
  if grep -qE '^\[GNUPG:\] (BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG) ' <<<"$status"; then
    die "tag $tag is signed by an expired or revoked key, or its signature is bad"
  fi
)

cmd_check_tag() {
  local tag="" commit="" main_ref="origin/main" root="." keys_file="$DEFAULT_KEYS_FILE" version tagged
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --tag) need_value "$@"; tag="$2"; shift 2 ;;
      --commit) need_value "$@"; commit="$2"; shift 2 ;;
      --main-ref) need_value "$@"; main_ref="$2"; shift 2 ;;
      --root) need_value "$@"; root="$2"; shift 2 ;;
      --keys-file) need_value "$@"; keys_file="$2"; shift 2 ;;
      *) die "check-tag: unknown argument '$1'" ;;
    esac
  done
  [[ "$commit" =~ $COMMIT_RE ]] || die "commit '$commit' is not a full commit SHA"
  version="$(tag_version "$tag")"
  [[ -n "$keys_file" ]] || die "no release signing keys file given"
  tagged="$(git -C "$root" rev-parse --verify --quiet "refs/tags/${tag}^{commit}")" ||
    die "tag $tag is not in the checkout"
  [[ "$tagged" == "$commit" ]] || die "tag $tag names $tagged, not $commit"
  check_tag_object "$root" "$tag" "$commit"
  check_ancestor "$root" "$commit" "$main_ref"
  check_signature "$root" "$tag" "$main_ref" "$keys_file"
  check_versions "$version" "$root" "$commit"
  printf 'version=%s\n' "$version"
}

cmd_promote() {
  local registry="" commit="" version="" repository="" check_only=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --registry) need_value "$@"; registry="$2"; shift 2 ;;
      --commit) need_value "$@"; commit="$2"; shift 2 ;;
      --version) need_value "$@"; version="$2"; shift 2 ;;
      --repository) need_value "$@"; repository="$2"; shift 2 ;;
      --check-only) check_only=1; shift ;;
      *) die "promote: unknown argument '$1'" ;;
    esac
  done
  [[ "$registry" =~ $REGISTRY_RE ]] || die "the registry is not a registry name"
  [[ "$commit" =~ $COMMIT_RE ]] || die "commit '$commit' is not a full commit SHA"
  [[ "$repository" =~ $REPOSITORY_RE ]] || die "repository '$repository' is not <org>/<repo>"
  tag_version "v$version" >/dev/null

  local source_tag="sha-${commit:0:7}" main_identity image repo digest
  main_identity="$(workflow_identity "$repository" ohttp-build.yml refs/heads/main)"
  local -a digests=() todo=()

  # Preflight: every image, before any write.
  for image in "${RELEASE_IMAGES[@]}"; do
    repo="$registry/$image"
    lookup_digest "$repo:$source_tag" "$image:$source_tag" ||
      die "$image:$source_tag does not exist: the main build of $commit must publish it before the release"
    digest="$LOOKUP"
    check_release_index "$repo" "$digest" "$commit" "$image:$source_tag"
    # The index and each of its platform images: signature and attestation of the main build.
    local d
    for d in "$digest" "${PLATFORM_DIGESTS[@]}"; do
      signature_verified "$repo@$d" "$main_identity" "$commit" ||
        die "$image:$source_tag: $d has no signature of the main build at $commit"
      attestation_verified "$repo@$d" "$d" "$main_identity" "$commit" "$commit" "$image" ||
        die "$image:$source_tag: $d has no provenance attestation of the main build for $commit"
    done
    if lookup_digest "$repo:$version" "$image:$version"; then
      [[ "$LOOKUP" == "$digest" ]] ||
        die "$image:$version already exists as $LOOKUP, not $digest; tags are never overwritten"
      todo+=(no)
      log "$image: $source_tag = $digest, $version already names it"
    else
      todo+=(yes)
      log "$image: $source_tag = $digest, signed and attested by the main build; $version to be created"
    fi
    digests+=("$digest")
  done
  if [[ $check_only -eq 1 ]]; then
    log "preflight passed (--check-only: no tag written)"
    return 0
  fi

  local i
  for i in "${!RELEASE_IMAGES[@]}"; do
    image="${RELEASE_IMAGES[$i]}"
    repo="$registry/$image"
    digest="${digests[$i]}"
    if [[ "${todo[$i]}" == "yes" ]]; then
      capture docker buildx imagetools create -t "$repo:$version" "$repo@$digest" ||
        die "$image: writing $version failed; re-run the job (tags already written are kept and accepted)"
    fi
    lookup_digest "$repo:$version" "$image:$version" ||
      die "$image:$version is missing after the write"
    [[ "$LOOKUP" == "$digest" ]] ||
      die "$image:$version names $LOOKUP after the write, expected $digest"
    log "$image: $version = $digest"
  done
  log "promoted $source_tag to $version"
}

main() {
  local sub="${1:-}"
  [[ $# -gt 0 ]] && shift
  case "$sub" in
    check-tag) cmd_check_tag "$@" ;;
    promote) cmd_promote "$@" ;;
    *) die "usage: $0 check-tag|promote ... (see the header of this script)" ;;
  esac
}

# Sourced (scripts/promote-image-test.sh): define the functions only.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi

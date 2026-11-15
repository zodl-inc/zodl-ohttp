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

# Registry and signature helpers shared by promote-image.sh and sign-image.sh (sourced only).
#
# Logs name an image by its short name (ohttp-gateway, ...), a tag and a digest, never by the
# registry it lives in. The output of the external tools (which carries full registry
# references, and for tag signatures GPG key IDs) is shown only with IMAGE_TOOLS_VERBOSE=1 or in
# a debug run of the workflow (RUNNER_DEBUG=1).

OIDC_ISSUER="https://token.actions.githubusercontent.com"
SLSA_PREDICATE_TYPE="https://slsa.dev/provenance/v0.2"
IMAGES_RE='^(ohttp-gateway|ohttp-relay-simulator|ohttp-e2e)$'
COMMIT_RE='^[0-9a-f]{40}$'
DIGEST_RE='^sha256:[0-9a-f]{64}$'
REGISTRY_RE='^[A-Za-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)*$'
REPOSITORY_RE='^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'
REQUIRED_PLATFORMS=(linux/amd64 linux/arm64)

die() {
  echo "error: $*" >&2
  exit 1
}

# An option that takes a value: `--x) need_value "$@"; x="$2"; shift 2 ;;`.
need_value() {
  [[ $# -ge 2 ]] || die "$1 needs a value"
}

log() {
  printf '%s\n' "$*"
}

verbose() {
  if [[ "${IMAGE_TOOLS_VERBOSE:-0}" == "1" || "${RUNNER_DEBUG:-0}" == "1" ]]; then
    printf '%s\n' "$*" >&2
  fi
}

# Escape every regex metacharacter of a literal string (Go RE2 / POSIX ERE).
re_escape() {
  printf '%s' "$1" | sed -e 's/[]\.*^$+?(){}|[]/\\&/g'
}

# Anchored certificate identity of a workflow of <org>/<repo> at a ref.
workflow_identity() {
  local repository="$1" workflow="$2" ref="$3"
  printf '^%s$' "$(re_escape "https://github.com/$repository/.github/workflows/$workflow@$ref")"
}

# Runs a command; its stdout goes to CAPTURED, its stderr to CAPTURED_ERR (shown only verbosely).
capture() {
  local errf rc
  errf="$(mktemp)"
  set +e
  CAPTURED="$("$@" 2>"$errf" </dev/null)"
  rc=$?
  set -e
  CAPTURED_ERR="$(cat "$errf")"
  rm -f "$errf"
  # Verbose: the command's output, successful or not, on stderr (the values stay in CAPTURED
  # and CAPTURED_ERR for parsing).
  if [[ -n "$CAPTURED" ]]; then verbose "$CAPTURED"; fi
  if [[ -n "$CAPTURED_ERR" ]]; then verbose "$CAPTURED_ERR"; fi
  return $rc
}

# jq on data from a registry or a tool: its errors (which may quote that data) are never shown;
# a failure is a fixed message. Prints jq's output.
jq_data() {
  local label="$1" out
  shift
  out="$(jq "$@" 2>/dev/null)" || die "$label: malformed registry or tool data"
  printf '%s\n' "$out"
}

# The digest a reference names, in LOOKUP. Returns 0 if it exists and 1 only if the registry
# answered, in a single line without control characters, that the manifest of exactly this
# reference does not exist:
#   ERROR: <ref>: not found  |  <ref>: not found   (the whole line; docker buildx's real form)
#   ... <ref>[:] ... manifest unknown | MANIFEST_UNKNOWN ...   (<ref> and the words bounded)
#   ... https://<host>/v2/<path>/manifests/<tag-or-digest>[":] 404 ...  (same host and path)
# Anything else is fatal, so that an error is never taken for an absent tag: several lines,
# blank lines or a carriage return (mixed or ambiguous diagnostics), another, a longer or a
# prefixed reference, local tool errors and
# authorisation or transport errors (a missing credential helper, "executable file not found",
# a 404 of the token service, a timeout). The reference, its manifest URL, the registry host
# and the repository path are taken out of the line before it is searched for those errors, so
# that words in a registry or repository name ("token", "tls", ...) do not count. The buildx
# answer was confirmed against the registry with the real tools.
LOCAL_ERROR_RE='(executable file not found|credential|unauthori[sz]ed|authenticat|authori[sz]|denied|forbidden|token|x509|certificate|tls|timeout|timed out|connection (refused|reset)|no such host|dial tcp|i/o |EOF|context deadline|(^|[[:space:]])(401|403|429|5[0-9][0-9])([[:space:]]|$))'
lookup_digest() {
  local ref="$1" label="$2" rc name last tagpart host path text lines
  LOOKUP=""
  if capture docker buildx imagetools inspect "$ref" --format '{{json .Manifest}}'; then
    LOOKUP="$(jq -r 'if type == "object" and (.digest | type) == "string" then .digest else empty end' \
      <<<"$CAPTURED" 2>/dev/null || true)"
    [[ "$LOOKUP" =~ $DIGEST_RE ]] || die "$label: the registry answered without a valid digest"
    return 0
  else
    rc=$?
  fi
  # <host>/<path>[:<tag>|@<digest>]
  last="${ref##*/}"
  if [[ "$last" == *@* ]]; then
    tagpart="${ref##*@}"
    name="${ref%@*}"
  elif [[ "$last" == *:* ]]; then
    tagpart="${ref##*:}"
    name="${ref%:*}"
  else
    tagpart="latest"
    name="$ref"
  fi
  host="${name%%/*}"
  path="${name#*/}"
  # One line, no control characters (a carriage return could join two diagnostics); the
  # placeholders contain \x01, which such a line cannot.
  local R=$'\x01REF\x01' U=$'\x01MANIFEST\x01' H=$'\x01HOST\x01' P=$'\x01PATH\x01'
  if [[ $rc -ne 126 && $rc -ne 127 && -n "$CAPTURED_ERR" && "$CAPTURED_ERR" != *[[:cntrl:]]* ]]; then
    text="$CAPTURED_ERR"
    text="${text//"https://$host/v2/$path/manifests/$tagpart"/$U}"
    text="${text//"$ref"/$R}"
    text="${text//"$host"/$H}"
    text="${text//"$path"/$P}"
    if ! grep -qiE -- "$LOCAL_ERROR_RE" <<<"$text"; then
      if [[ "$text" == "ERROR: $R: not found" || "$text" == "$R: not found" ]] ||
        { [[ "$text" =~ (^|[[:space:]])"$R"(:|[[:space:]]|$) ]] &&
          grep -qiE -- '(^|[^A-Za-z0-9_])manifest[ _]unknown([^A-Za-z0-9_]|$)' <<<"$text"; } ||
        [[ "$text" =~ (^|[[:space:]\"])"$U"\"?:?\ 404([[:space:]]|$) ]]; then
        return 1
      fi
    fi
  fi
  die "$label: registry lookup failed (not a 'manifest not found' answer; IMAGE_TOOLS_VERBOSE=1 shows it)"
}

# Raw manifest of a digest reference, in RAW (a JSON object).
inspect_raw() {
  local ref="$1" label="$2"
  capture docker buildx imagetools inspect "$ref" --raw || die "$label: cannot read the manifest"
  RAW="$CAPTURED"
  jq -e 'type == "object"' >/dev/null 2>&1 <<<"$RAW" || die "$label: the manifest is not a JSON object"
}

# An index: a JSON object of an index media type whose manifests are an array of objects.
is_index() {
  case "$(jq -r 'if (.mediaType | type) == "string" then .mediaType else "" end' <<<"$1" 2>/dev/null)" in
    application/vnd.oci.image.index.v1+json | application/vnd.docker.distribution.manifest.list.v2+json)
      jq -e '(.manifests | type) == "array" and all(.manifests[]; type == "object")' >/dev/null 2>&1 <<<"$1" ||
        die "malformed index: its manifests are not a list of descriptors"
      return 0
      ;;
    *) return 1 ;;
  esac
}

# A platform string from a registry, printed only if it is well-formed.
PLATFORM_RE='^[a-z0-9_]+/[a-z0-9_]+(/[a-z0-9_]+)?$'

# Platform images of an index: lines "<os>/<arch>[/<variant>] <digest>". Every descriptor is
# checked first (digest, platform of a strict charset); only the exact attestation form
# unknown/unknown is then left out; anything malformed is fatal, with a fixed message. The
# index must have passed is_index.
index_platform_images() {
  local label="$1" out line p d result=""
  out="$(jq_data "$label" -r '.manifests[]
    | if (.platform | type) == "object" and (.platform.os | type) == "string"
        and (.platform.architecture | type) == "string" and (.digest | type) == "string"
        and (.platform.variant == null or (.platform.variant | type) == "string")
      then "\(.platform.os)/\(.platform.architecture)\(if .platform.variant then "/" + .platform.variant else "" end) \(.digest)"
      else "malformed" end' <<<"$RAW")" || exit 1
  while IFS= read -r line; do
    p="${line%% *}"
    d="${line#* }"
    [[ "$line" == *" "* && "$p" =~ $PLATFORM_RE && "$d" =~ $DIGEST_RE ]] ||
      die "$label: malformed descriptor in the index"
    [[ "$p" == unknown/unknown ]] && continue
    result+="$line"$'\n'
  done <<<"$out"
  printf '%s' "$result"
}

# The org.opencontainers.image.revision label of a platform image, in REVISION (empty if the
# config has no labels or no such label; a label of another type is malformed).
image_revision() {
  local ref="$1" label="$2"
  capture docker buildx imagetools inspect "$ref" --format '{{json .Image}}' ||
    die "$label: cannot read the image configuration"
  IMAGE_CONFIG="$CAPTURED"
  REVISION="$(jq_data "$label" -r 'if type != "object" then error("x")
    elif .config == null then ""
    elif (.config | type) != "object" then error("x")
    elif .config.Labels == null then ""
    elif (.config.Labels | type) != "object" then error("x")
    else (.config.Labels["org.opencontainers.image.revision"] // "")
      | if type == "string" then . else error("x") end end' <<<"$IMAGE_CONFIG")" || exit 1
}

# Checks that <repo>@<digest> is an index with exactly one image per required platform, no other
# platform image, and that every platform image is labelled with <commit>. PLATFORM_DIGESTS gets
# the platform image digests.
check_release_index() {
  local repo="$1" digest="$2" commit="$3" label="$4" lines p count d
  inspect_raw "$repo@$digest" "$label"
  is_index "$RAW" || die "$label: $digest is not a multi-platform index"
  lines="$(index_platform_images "$label")" || exit 1
  PLATFORM_DIGESTS=()
  for p in "${REQUIRED_PLATFORMS[@]}"; do
    # os/arch, whatever the variant.
    count="$(awk -v p="$p" '{ split($1, a, "/") } a[1] "/" a[2] == p' <<<"$lines" | wc -l)"
    [[ "$count" -eq 1 ]] || die "$label: $digest has $count images for $p, expected 1"
    d="$(awk -v p="$p" '{ split($1, a, "/") } a[1] "/" a[2] == p { print $2 }' <<<"$lines")"
    image_revision "$repo@$d" "$label ($p)"
    [[ -n "$REVISION" ]] || die "$label: the $p image has no org.opencontainers.image.revision label"
    [[ "$REVISION" =~ $COMMIT_RE ]] || die "$label: the $p image has a malformed revision label"
    [[ "$REVISION" == "$commit" ]] ||
      die "$label: the $p image is labelled with revision $REVISION, expected $commit"
    PLATFORM_DIGESTS+=("$d")
  done
  count="$(grep -c . <<<"$lines" || true)"
  [[ "$count" -eq "${#REQUIRED_PLATFORMS[@]}" ]] ||
    die "$label: $digest has $count platform images, expected ${REQUIRED_PLATFORMS[*]}"
}

# cosign verify of a digest reference; workflow_sha (optional) binds the certificate to the
# commit the signing workflow ran at.
signature_verified() {
  local ref="$1" identity="$2" workflow_sha="${3:-}" args=()
  args=(--certificate-identity-regexp "$identity" --certificate-oidc-issuer "$OIDC_ISSUER")
  if [[ -n "$workflow_sha" ]]; then
    args+=(--certificate-github-workflow-sha "$workflow_sha")
  fi
  capture cosign verify "${args[@]}" "$ref"
}

# cosign verify-attestation (SLSA provenance) of <repo>@<digest>; then, in the verified
# statements, one whose subject is <digest> and whose source commit (configSource and
# materials) is <commit>. With <image>, the subject must be named after that image (cosign
# names it after the repository, <registry>/<image>), and the predicate's
# invocation.parameters.image must be <image>: required with image_mode "strict" (promotion,
# signing: images of this workflow carry it), checked only when present with "subject"
# (verify-image.sh: older images do not carry it). So the attestation of one image cannot stand
# in for another's. commit, workflow_sha and image are optional. Malformed statements are
# skipped; jq's errors are never shown.
attestation_verified() {
  local ref="$1" digest="$2" identity="$3" workflow_sha="${4:-}" commit="${5:-}" image="${6:-}"
  local image_mode="${7:-strict}" args=()
  args=(--type slsaprovenance --certificate-identity-regexp "$identity"
    --certificate-oidc-issuer "$OIDC_ISSUER")
  if [[ -n "$workflow_sha" ]]; then
    args+=(--certificate-github-workflow-sha "$workflow_sha")
  fi
  capture cosign verify-attestation "${args[@]}" "$ref" || return 1
  jq -e -s --arg type "$SLSA_PREDICATE_TYPE" --arg hex "${digest#sha256:}" --arg commit "$commit" \
    --arg image "$image" --arg mode "$image_mode" '
    def str: type == "string";
    [ .[] | select(type == "object" and (.payload | str))
      | (try (.payload | @base64d | fromjson) catch null) | select(type == "object")
      | select(.predicateType == $type and (.subject | type) == "array"
          and (.predicate | type) == "object")
      | select(any(.subject[]; type == "object" and (.digest | type) == "object"
          and .digest.sha256 == $hex
          and ($image == "" or ((.name | str) and (.name | split("/") | last) == $image))))
      | (.predicate.invocation | if type == "object" then . else {} end) as $inv
      | ($inv.parameters | if type == "object" then . else {} end) as $par
      | select($image == ""
          or $par.image == $image
          or ($mode == "subject" and ($par | has("image") | not)))
      | select($commit == ""
          or (($inv.configSource | type) == "object"
              and ($inv.configSource.digest | type) == "object"
              and $inv.configSource.digest.sha1 == $commit
              and (.predicate.materials | type) == "array"
              and any(.predicate.materials[]; type == "object" and (.digest | type) == "object"
                and .digest.sha1 == $commit))) ]
    | length > 0' >/dev/null 2>&1 <<<"$CAPTURED"
}

# SLSA v0.2 provenance predicate of the image <image> of <org>/<repo> at <commit>
# (invocation.parameters.image names it). buildStartedOn only when a start time is known.
provenance_predicate() {
  local repository="$1" commit="$2" workflow_ref="$3" entry="$4" run_id="$5" started="${6:-}" image="$7"
  jq -n \
    --arg image "$image" \
    --arg builder "$workflow_ref" \
    --arg repo "https://github.com/$repository" \
    --arg build_type "https://github.com/$repository/$entry@main" \
    --arg entry "$entry" \
    --arg sha "$commit" \
    --arg run_id "$run_id" \
    --arg started "$started" \
    '{
      builder: {id: $builder},
      buildType: $build_type,
      invocation: {
        configSource: {uri: $repo, digest: {sha1: $sha}, entryPoint: $entry},
        parameters: {image: $image}
      },
      metadata: ({
        buildInvocationId: $run_id,
        completeness: {parameters: false, environment: false, materials: false}
      } + (if $started == "" then {} else {buildStartedOn: $started} end)),
      materials: [{uri: $repo, digest: {sha1: $sha}}]
    }'
}

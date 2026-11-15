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

# Signs an image and attests its SLSA provenance, re-run safe on a registry with immutable tags.
#
#   sign-image.sh --registry <host[/prefix]> --image <name> --digest <sha256:...>
#                 --workflow <ohttp-build.yml|sign-existing-image.yml> --repository <org/repo>
#                 --run-id <id> [--commit <sha>] [--workflow-sha <sha>] [--started-on <time>]
#
# The targets are the digest and, for a multi-platform index, each of its platform images, so
# that a verifier that resolves the index to one platform finds a signature and an attestation
# on that platform image too. Every platform image must carry the same
# org.opencontainers.image.revision label (= --commit if given; it is the source commit of the
# provenance). The digest must exist; a missing image is an error. The predicate names the
# image (invocation.parameters.image) and cosign names the subject after its repository.
#
# A target that already carries a signature (an attestation) of the workflow on refs/heads/main
# of <org/repo> (at --workflow-sha, if given) is not signed (attested) again: cosign keeps them
# under tags derived from the digest, which an immutable registry refuses to rewrite, so a
# re-run of a job that failed half-way completes without rewriting any of them. The predicate
# carries buildStartedOn only with --started-on.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=image-lib.sh
source "$SCRIPT_DIR/image-lib.sh"

main() {
  local registry="" image="" digest="" workflow="" repository="" run_id="" commit=""
  local workflow_sha="" started=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --registry) need_value "$@"; registry="$2"; shift 2 ;;
      --image) need_value "$@"; image="$2"; shift 2 ;;
      --digest) need_value "$@"; digest="$2"; shift 2 ;;
      --workflow) need_value "$@"; workflow="$2"; shift 2 ;;
      --repository) need_value "$@"; repository="$2"; shift 2 ;;
      --run-id) need_value "$@"; run_id="$2"; shift 2 ;;
      --commit) need_value "$@"; commit="$2"; shift 2 ;;
      --workflow-sha) need_value "$@"; workflow_sha="$2"; shift 2 ;;
      --started-on) need_value "$@"; started="$2"; shift 2 ;;
      *) die "unknown argument '$1'" ;;
    esac
  done
  [[ "$registry" =~ $REGISTRY_RE ]] || die "the registry is not a registry name"
  [[ "$image" =~ $IMAGES_RE ]] || die "image '$image' is not one of the published images"
  [[ "$digest" =~ $DIGEST_RE ]] || die "digest '$digest' is not sha256:<64 hex>"
  case "$workflow" in
    ohttp-build.yml | sign-existing-image.yml) ;;
    *) die "workflow '$workflow' does not sign images" ;;
  esac
  [[ "$repository" =~ $REPOSITORY_RE ]] || die "repository '$repository' is not <org>/<repo>"
  [[ "$run_id" =~ ^[0-9]+$ ]] || die "run id '$run_id' is not a number"
  [[ -z "$commit" || "$commit" =~ $COMMIT_RE ]] || die "commit '$commit' is not a full commit SHA"
  [[ -z "$workflow_sha" || "$workflow_sha" =~ $COMMIT_RE ]] ||
    die "workflow SHA '$workflow_sha' is not a full commit SHA"
  [[ -z "$started" || "$started" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] ||
    die "start time '$started' is not YYYY-MM-DDTHH:MM:SSZ"

  # In a workflow, only a run of main signs (also checked by the workflows themselves).
  if [[ "${GITHUB_ACTIONS:-}" == "true" && "${GITHUB_REF:-}" != "refs/heads/main" ]]; then
    die "signing runs only from main"
  fi

  local repo="$registry/$image" label="$image@$digest"
  lookup_digest "$repo@$digest" "$label" || die "$label does not exist"
  [[ "$LOOKUP" == "$digest" ]] || die "$label: the registry answered for another digest"

  # The targets and the source commit.
  local -a targets=("$digest")
  local revision="" p d platform_lines
  inspect_raw "$repo@$digest" "$label"
  if is_index "$RAW"; then
    # The whole enumeration first, its status checked: a malformed descriptor anywhere in the
    # index stops the run before anything is signed.
    platform_lines="$(index_platform_images "$label")" || exit 1
    while read -r p d; do
      [[ -n "$p" ]] || continue
      [[ "$d" =~ $DIGEST_RE ]] || die "$label: invalid platform digest"
      [[ "$p" =~ $PLATFORM_RE ]] || die "$label: malformed platform in the index"
      image_revision "$repo@$d" "$label ($p)"
      [[ -n "$REVISION" ]] || die "$label: the $p image has no org.opencontainers.image.revision label"
      [[ "$REVISION" =~ $COMMIT_RE ]] || die "$label: the $p image has a malformed revision label"
      [[ -z "$revision" || "$revision" == "$REVISION" ]] ||
        die "$label: platform images are labelled with different revisions"
      revision="$REVISION"
      targets+=("$d")
    done <<<"$platform_lines"
    [[ ${#targets[@]} -gt 1 ]] || die "$label: the index has no platform image"
  else
    image_revision "$repo@$digest" "$label"
    revision="$REVISION"
  fi
  [[ -n "$revision" ]] || die "$label: no org.opencontainers.image.revision label"
  [[ "$revision" =~ $COMMIT_RE ]] || die "$label: malformed revision label"
  [[ -z "$commit" || "$commit" == "$revision" ]] ||
    die "$label: labelled with revision $revision, expected $commit"
  commit="$revision"

  local identity predicate t
  identity="$(workflow_identity "$repository" "$workflow" refs/heads/main)"
  predicate="$(mktemp)"
  # shellcheck disable=SC2064
  trap "rm -f '$predicate'" EXIT
  provenance_predicate "$repository" "$commit" "${GITHUB_WORKFLOW_REF:-}" \
    ".github/workflows/$workflow" "$run_id" "$started" "$image" >"$predicate"

  for t in "${targets[@]}"; do
    if signature_verified "$repo@$t" "$identity" "$workflow_sha"; then
      log "$image@$t: already signed, kept"
    else
      capture cosign sign --yes "$repo@$t" || die "$image@$t: signing failed"
      signature_verified "$repo@$t" "$identity" "$workflow_sha" ||
        die "$image@$t: the new signature does not verify"
      log "$image@$t: signed"
    fi
    if attestation_verified "$repo@$t" "$t" "$identity" "$workflow_sha" "$commit" "$image"; then
      log "$image@$t: already attested, kept"
    else
      capture cosign attest --yes --predicate "$predicate" --type slsaprovenance "$repo@$t" ||
        die "$image@$t: attesting failed"
      attestation_verified "$repo@$t" "$t" "$identity" "$workflow_sha" "$commit" "$image" ||
        die "$image@$t: the new attestation does not verify"
      log "$image@$t: attested"
    fi
  done
  log "$image@$digest: ${#targets[@]} digest(s) signed and attested for $commit"
}

main "$@"

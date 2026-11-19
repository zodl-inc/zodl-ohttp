# Contributing to ZODL OHTTP

Thank you for your interest in ZODL OHTTP.

## Bug reports and feature requests

Issues are welcome: bugs, interoperability findings against RFC 9458 / chunked OHTTP, performance
observations and feature requests go through this repository's issue tracker. Security issues
must not be filed publicly; see [SECURITY.md](SECURITY.md).

## Code contributions and licensing

ZODL OHTTP is licensed under the AGPL-3.0-only and is also offered by Znewco, Inc. under
commercial terms (see [LICENSE](LICENSE), [LICENSE-EXCEPTIONS.md](LICENSE-EXCEPTIONS.md) and
[COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md)). Contributions are accepted under the project's
licence. Because the dual licensing requires Znewco to hold sufficient rights in the whole code
base, Znewco may require a contributor licence agreement before a contribution from outside the
ZODL team can be merged. Please contact licensing@zodl.com before starting substantial work so
that the terms are clear up front.

## Pull requests

- Every new first-party source file starts with the licence header in [AGENTS.md](AGENTS.md).
- `cargo fmt`, `cargo clippy` (no warnings) and `cargo test` must pass for the crate you touch.
  CI runs `cargo test` for the gateway, the relay simulator and the client library (`rustfmt` and
  `clippy` as well for the client library), builds the e2e client, and runs every fuzz target
  for 60 s.
- Behaviour changes are recorded in [CHANGES.md](CHANGES.md) (gateway, relay simulator, e2e
  client) or [client/CHANGELOG.md](client/CHANGELOG.md) (client library).
- Keep the gateway's privacy properties: nothing that lets the gateway learn or log a client's
  network address, and nothing that lets the relay read request content, is accepted.
- Pull requests are reviewed by the maintainers of this repository.

## Releases

- Release tags are created by repository admins only (a tag ruleset); that ruleset is the
  security boundary. The release-check job of the tag build is a consistency check, not an
  access control.
- A release is an annotated, signed tag `vMAJOR.MINOR.PATCH` (optionally `-PRERELEASE`, SemVer;
  at most 128 characters after the `v`) on a commit of `main` that the main build has already
  published, signed and attested. Tag the merge commit the main build ran for, after that build
  has finished; images of a main build from before this workflow (platform images signed and
  attested, provenance naming the image) cannot be promoted. The tag signature must verify against a key in `.github/release-signing-keys.asc`
  on `main` (no such file, or an empty one: every tag is refused), and the signed tag object
  must carry the tag's own name and name the commit directly (`git tag -s vX.Y.Z <commit>`).
  The release key in that file expires on 2028-11-08; after that date every tag is refused
  until a new (or extended) key is on `main`.
- A release builds and signs nothing: it adds the version tag to the `sha-<short>` images of
  that commit (the same digests), which keep the main build's signature and attestation;
  `scripts/verify-image.sh` checks those. Without `--commit` it accepts any of its identities;
  with `--commit <sha>` only certificates issued to a build run at `<sha>` (main build, legacy
  tag builds) whose attestation names `<sha>`, and Sign Existing Image signatures only with
  `--allow-sign-existing`, where the link to `<sha>` is only the source commit their
  attestation names (that workflow's certificate is bound to the commit it ran at). A
  promoted image keeps the main build's labels, including `org.opencontainers.image.version`
  (the main build's value, `main`, not the release version).
- All three images pass the preflight (index, platforms, revision labels, signature and
  attestation of the index and of each platform image, version tag absent or already the same
  digest) before any version tag is
  written. Registry writes are not transactional: if the job fails while writing tags, run it
  again; tags already written with the same digest are accepted and the rest are written. If a
  version tag names another digest, the job stops; such a tag cannot be overwritten, only
  removed by a registry administrator.
- A tag on a revision older than the release-check job runs that revision's workflow, which
  rebuilds and signs under the tag identity. `scripts/verify-image.sh` refuses that identity
  except for the images listed by digest in `scripts/legacy-release-digests.txt`: ohttp-e2e
  1.0.1 and the three 1.1.0 images. The three 1.0.0 images verify through the main build's
  identity; the ohttp-gateway and ohttp-relay-simulator 1.0.1 images were never signed and
  cannot be verified. Deployments pin `sha-<short>` digests verified with the main build's
  identity.
- The registry checks of the scripts are tested against stub tools. `scripts/promote-image.sh
  promote --check-only` runs the whole preflight with the real tools and writes nothing; it
  passes only for a commit whose main build ran with this workflow (index and platform images
  signed and attested). Before the first release, run it on the first main build after this
  workflow was merged; that also confirms the registry's "not found" wording.
- Sign Existing Image runs only from `main`. Existing artifacts of a digest must be absent or
  already verify under that workflow and the expected image/commit policy: the registry's tags
  are immutable, so foreign or incompatible signatures or attestations cannot be replaced. To
  backfill the platform images of an index that is already signed, run it with each platform
  digest.
- `scripts/verify-image.sh` binds an attestation to its image by the subject name (the image's
  repository, `<registry>/<image>`: verify an image under its own repository name) and, for
  images whose provenance names the image (`invocation.parameters.image`), by that name too.
- A failed publish: use "Re-run failed jobs", which reuses the build jobs' platform digests
  (kept 14 days) and completes the index, signatures and attestations without rewriting
  anything. A full re-run rebuilds the images with new digests and is refused once
  `sha-<short>` exists; push a new commit instead.
- Logs name images by short name, tag and digest. `IMAGE_TOOLS_VERBOSE=1`, and a workflow run
  with debug logging (`RUNNER_DEBUG=1`), also print the tools' output, which contains full
  registry references and GPG key IDs.
- The tag version must equal the `version` of `gateway/Cargo.toml` and
  `relay-simulator/Cargo.toml` and their entries in every `Cargo.lock` of the commit (gateway,
  relay simulator, client, e2e client, fuzz); CI refuses the tag otherwise. Bump both in the
  release pull request, also for a release that changes neither.
- The gateway crate (`zodl-ohttp-gateway`), the integrations crate (`zodl-ohttp-integrations`),
  the relay simulator and the e2e client are not published on crates.io (`publish = false`).
  The gateway and relay simulator versions name the images; the integrations crate's version
  names nothing and is not checked.
- The client library (`zodl-ohttp-client`) keeps its own version, published on crates.io, and is
  not checked against the tag; the e2e client follows the client library version. Record both
  in the release notes.

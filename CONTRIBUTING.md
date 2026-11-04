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
- Pull requests are reviewed by the maintainers listed in `.github/CODEOWNERS`.

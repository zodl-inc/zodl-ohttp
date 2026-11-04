# Agent guidelines for ZODL OHTTP

Guidance for coding agents (and humans) working in this repository.

## License headers (REQUIRED)

Every **new first-party source code file** MUST start with the ZODL
OHTTP license header, verbatim, as the very first lines of the file:

```text
// Copyright © 2026 Znewco, Inc. (d/b/a Zcash Open Development Lab)
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of ZODL OHTTP.
//
// ZODL OHTTP is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License,
// version 3 only, as published by the Free Software Foundation.
//
// ZODL OHTTP is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Affero General Public License for more details.
//
// Commercial licensing: see COMMERCIAL-LICENSE.md.
```

Rules:

- The header goes above everything else in the file, followed by one
  blank line. In Rust files, inner doc comments (`//!`) and attributes
  (`#![...]`) come after the header, never before it.
- This applies to all first-party source files, whatever the language —
  today that is Rust (`.rs`) under `client/`, `gateway/`, `e2e-client/`,
  `relay-simulator/` and `fuzz/`. Use the language's line-comment syntax if
  it is not `//`.
- Do NOT add the header to:
  - Generated code (none today) — generated output is left unstamped.
  - Non-source files: `Cargo.toml`, lockfiles, JSON/YAML config,
    Markdown docs, protobuf definitions.
  - Any third-party code vendored into the tree in future: vendored forks
    keep their own upstream license headers and terms; never restamp them.
- When copying the header into a new file, copy it exactly — same
  wording, same year, same punctuation — from any existing stamped file
  (e.g. `client/src/lib.rs`).

A new source file without this header must be treated as a defect and
fixed before the change is committed.

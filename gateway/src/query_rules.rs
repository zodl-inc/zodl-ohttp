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

//! `THIRD_PARTY_QUERY_RULES`: per-route query string allowlists for `BACKENDS` aliases.
//!
//! ```text
//! THIRD_PARTY_QUERY_RULES=alias=GET /v1/quotes?symbol=ZEC&convert={in:USD|EUR},GET /v1/map?;alias2=...
//! ```
//!
//! The grammar, the startup checks and the matching are
//! [`zodl_ohttp_integrations::core::query`]; this module reads the variables. A request whose
//! alias, method and exact path match a rule must carry exactly the rule's parameters, in the
//! rule's order, each once, and no other; otherwise it is refused like a `BACKENDS_POLICY`
//! denial (inner 403 `policy denied`), before the third-party cache and the upstream cap. The
//! query is never rewritten: the string checked is the cache key and the upstream request.
//! Routes without a rule are not affected; unset = no rule.

use std::collections::HashMap;

use anyhow::bail;
use zodl_ohttp_integrations::core::query as core;

use crate::query_value_sources::QueryValueSources;

pub use zodl_ohttp_integrations::core::query::ENV;

/// The parsed `THIRD_PARTY_QUERY_RULES` ([`zodl_ohttp_integrations::core::query::QueryRules`])
/// and the `THIRD_PARTY_QUERY_VALUE_SOURCES` their `{from:name}` values come from, with their
/// refreshes.
#[derive(Clone, Default)]
pub struct QueryRules {
    rules: core::QueryRules,
    /// The same lists as those of `rules` (a handle), with the refreshes.
    sources: QueryValueSources,
}

impl std::fmt::Debug for QueryRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.rules.fmt(f)
    }
}

impl QueryRules {
    /// Parse `THIRD_PARTY_QUERY_RULES` and `THIRD_PARTY_QUERY_VALUE_SOURCES` from the
    /// environment. Unset or blank: no rule (no source); a value that is not UTF-8 is an error.
    pub fn from_env() -> anyhow::Result<Self> {
        let sources = QueryValueSources::from_env()?;
        match crate::config_source::var(ENV) {
            Ok(raw) if raw.trim().is_empty() => Self::parse_with_sources("", sources),
            Ok(raw) => Self::parse_with_sources(&raw, sources),
            Err(std::env::VarError::NotPresent) => Self::parse_with_sources("", sources),
            Err(std::env::VarError::NotUnicode(_)) => bail!("Invalid {ENV}: not valid UTF-8"),
        }
    }

    /// The value sources of `{from:name}`.
    pub fn sources(&self) -> &QueryValueSources {
        &self.sources
    }

    /// [`Self::parse`] with value sources; an empty `raw` = no rule (then `sources` must be
    /// empty too, see [`Self::validate`]).
    pub fn parse_with_sources(raw: &str, sources: QueryValueSources) -> anyhow::Result<Self> {
        Ok(Self {
            rules: core::QueryRules::parse_with_sources(raw, sources.core().clone())?,
            sources,
        })
    }

    /// Parse `alias=METHOD /path?QUERY,METHOD /path?QUERY;alias2=...`; any malformed part is an
    /// error.
    #[allow(dead_code)]
    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        Ok(Self {
            rules: core::QueryRules::parse(raw)?,
            sources: QueryValueSources::default(),
        })
    }

    /// Startup checks against the rest of the configuration
    /// ([`zodl_ohttp_integrations::core::query::QueryRules::validate`]).
    pub fn validate(
        &self,
        backends: &HashMap<String, String>,
        backends_policy: &HashMap<String, Vec<(String, String)>>,
    ) -> anyhow::Result<()> {
        self.rules.validate(backends, backends_policy)
    }

    /// Number of route rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Whether the query rules let `method path` (path with its raw query) to `authority`
    /// through: always when no rule names this alias, method and exact path; otherwise when the
    /// query matches one of those rules.
    pub fn admits(&self, authority: &str, method: &str, path: &str) -> bool {
        self.rules.admits(authority, method, path)
    }
}

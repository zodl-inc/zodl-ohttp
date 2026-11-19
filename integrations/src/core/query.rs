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
//! `BACKENDS_POLICY` admits a request by method and path; any query string passes. For an alias
//! whose credential the gateway injects (`BACKEND_HEADERS`), that lets a client use the gateway
//! as a general proxy of the API, and every distinct query string is a new third-party cache key
//! that spends upstream quota. A query rule fixes the query shape of one exact route:
//!
//! ```text
//! THIRD_PARTY_QUERY_RULES=alias=GET /v1/quotes?symbol=ZEC&convert={in:USD|EUR},GET /v1/map?;alias2=...
//! ```
//!
//! A request whose alias, method and exact path match a rule must carry exactly the rule's
//! parameters, in the rule's order, each once, and no other; every value must match: a literal
//! byte for byte (on the raw, still percent-encoded query), `{in:A|B|C}` one of the listed
//! literals byte for byte, `{upper:MIN-MAX}` MIN..=MAX ASCII uppercase letters, `{from:name}` one
//! value of the current list of a `THIRD_PARTY_QUERY_VALUE_SOURCES` source. `/path?` = no
//! parameter at all (no query string, or an empty one). With several rules for one route,
//! matching any of them is enough. Otherwise the request is refused like a `BACKENDS_POLICY`
//! denial (inner 403 `policy denied`), before the third-party cache and the upstream cap. The
//! query is never rewritten: the string checked is the cache key and the upstream request.
//! Routes without a rule are not affected; unset = no rule.

use std::collections::HashMap;

use anyhow::{anyhow, bail};

use crate::core::value_source::{self, QueryValueSources};

/// The environment variable.
pub const ENV: &str = "THIRD_PARTY_QUERY_RULES";

/// Longest `{upper:MIN-MAX}` value.
pub const MAX_UPPER_LEN: usize = 32;

/// Most alternatives of one `{in:...}`.
pub const MAX_ALTERNATIVES: usize = 256;

/// The value a query parameter must have.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ValueRule {
    /// Exactly these bytes (raw, percent-encoding included).
    Literal(String),
    /// `{in:A|B|C}`: exactly one of these literals.
    OneOf(Vec<String>),
    /// `{upper:MIN-MAX}`: MIN..=MAX ASCII uppercase letters.
    Upper { min: usize, max: usize },
    /// `{from:name}`: one value of the current list of source `name`.
    From(String),
}

impl ValueRule {
    fn parse(raw: &str, route: &str) -> anyhow::Result<Self> {
        if raw.starts_with('{') || raw.ends_with('}') {
            let body = raw.strip_suffix('}');
            if let Some(list) = body.and_then(|b| b.strip_prefix("{in:")) {
                return Self::parse_in(raw, list, route);
            }
            if let Some(range) = body.and_then(|b| b.strip_prefix("{upper:")) {
                return Self::parse_upper(raw, range, route);
            }
            if let Some(name) = body.and_then(|b| b.strip_prefix("{from:")) {
                if !value_source::valid_name(name) {
                    bail!(
                        "Invalid {ENV} pattern '{raw}' in '{route}': a source name is [a-z0-9_-]{{1,32}}"
                    );
                }
                return Ok(Self::From(name.to_string()));
            }
            bail!(
                "Invalid {ENV} value '{raw}' in '{route}': the only patterns are {{in:A|B|C}}, {{upper:MIN-MAX}} and {{from:name}}"
            );
        }
        if raw.contains(['{', '}']) {
            bail!(
                "Invalid {ENV} value '{raw}' in '{route}': '{{' and '}}' only in the patterns {{in:A|B|C}}, {{upper:MIN-MAX}} and {{from:name}}"
            );
        }
        check_token(raw, "value", route, &['&', '#'])?;
        Ok(Self::Literal(raw.to_string()))
    }

    fn parse_in(raw: &str, list: &str, route: &str) -> anyhow::Result<Self> {
        let mut alternatives: Vec<String> = Vec::new();
        for alternative in list.split('|') {
            if alternative.is_empty() {
                bail!("Invalid {ENV} pattern '{raw}' in '{route}': empty alternative");
            }
            if !value_source::valid_value(alternative) {
                bail!(
                    "Invalid {ENV} alternative '{alternative}' in '{route}': {}",
                    value_source::VALUE_RULE
                );
            }
            if alternatives.iter().any(|a| a == alternative) {
                bail!("Invalid {ENV} pattern '{raw}' in '{route}': alternative '{alternative}' listed twice");
            }
            alternatives.push(alternative.to_string());
        }
        if alternatives.len() > MAX_ALTERNATIVES {
            bail!(
                "Invalid {ENV} pattern '{raw}' in '{route}': {} alternatives, at most {MAX_ALTERNATIVES}",
                alternatives.len()
            );
        }
        Ok(Self::OneOf(alternatives))
    }

    fn parse_upper(raw: &str, range: &str, route: &str) -> anyhow::Result<Self> {
        let bound = |s: &str| -> Option<usize> {
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            s.parse().ok()
        };
        let (min, max) = range
            .split_once('-')
            .and_then(|(min, max)| Some((bound(min)?, bound(max)?)))
            .ok_or_else(|| {
                anyhow!(
                    "Invalid {ENV} pattern '{raw}' in '{route}': must be {{upper:MIN-MAX}} with decimal MIN and MAX"
                )
            })?;
        if min == 0 || min > max || max > MAX_UPPER_LEN {
            bail!(
                "Invalid {ENV} pattern '{raw}' in '{route}': need 1 <= MIN <= MAX <= {MAX_UPPER_LEN} (an empty value is the literal 'name=')"
            );
        }
        Ok(Self::Upper { min, max })
    }

    fn matches<'a>(&'a self, value: &str, lists: &mut Lists<'a>) -> bool {
        match self {
            Self::Literal(literal) => literal == value,
            Self::OneOf(alternatives) => alternatives.iter().any(|a| a == value),
            Self::From(name) => lists.contains(name, value),
            Self::Upper { min, max } => {
                (*min..=*max).contains(&value.len())
                    && value.bytes().all(|b| b.is_ascii_uppercase())
            }
        }
    }
}

/// Visible ASCII only, none of `forbidden`.
fn check_token(token: &str, what: &str, route: &str, forbidden: &[char]) -> anyhow::Result<()> {
    if let Some(c) = token
        .chars()
        .find(|c| !c.is_ascii_graphic() || forbidden.contains(c))
    {
        bail!("Invalid {ENV} {what} '{token}' in '{route}': character {c:?} not allowed");
    }
    Ok(())
}

/// One route's allowed query shape.
#[derive(Clone, Debug, PartialEq, Eq)]
struct QueryRule {
    /// Uppercase.
    method: String,
    /// Exact path, without the query.
    path: String,
    /// Parameter names (unique) and their values, in the required order.
    params: Vec<(String, ValueRule)>,
}

impl QueryRule {
    /// Whether `query` (the raw query string, `None` without `?`) has exactly this rule's shape:
    /// the rule's parameters in the rule's order, nothing else.
    fn admits<'a>(&'a self, query: Option<&str>, lists: &mut Lists<'a>) -> bool {
        let query = query.unwrap_or("");
        if query.is_empty() {
            return self.params.is_empty();
        }
        let mut pairs = query.split('&');
        for (name, rule) in &self.params {
            let Some((got_name, value)) = pairs.next().and_then(|p| p.split_once('=')) else {
                return false;
            };
            if got_name != name || !rule.matches(value, lists) {
                return false;
            }
        }
        pairs.next().is_none()
    }
}

/// The source lists of one query evaluation: each list is read once, on first use, and kept
/// for every later `{from:}` parameter of the same request.
struct Lists<'a> {
    sources: &'a QueryValueSources,
    read: Vec<(
        &'a str,
        Option<std::sync::Arc<std::collections::HashSet<String>>>,
    )>,
}

impl<'a> Lists<'a> {
    fn contains(&mut self, name: &'a str, value: &str) -> bool {
        if let Some((_, list)) = self.read.iter().find(|(n, _)| *n == name) {
            return list.as_ref().is_some_and(|l| l.contains(value));
        }
        let list = self.sources.list(name);
        let found = list.as_ref().is_some_and(|l| l.contains(value));
        self.read.push((name, list));
        found
    }
}

/// The parsed `THIRD_PARTY_QUERY_RULES`: alias (lowercase) -> its routes' query rules, and the
/// `THIRD_PARTY_QUERY_VALUE_SOURCES` their `{from:name}` values come from.
#[derive(Clone, Debug, Default)]
pub struct QueryRules {
    rules: HashMap<String, Vec<QueryRule>>,
    sources: QueryValueSources,
}

impl QueryRules {
    /// The value sources of `{from:name}`.
    pub fn sources(&self) -> &QueryValueSources {
        &self.sources
    }

    /// [`Self::parse`] with value sources; an empty `raw` = no rule (then `sources` must be
    /// empty too, see [`Self::validate`]).
    pub fn parse_with_sources(raw: &str, sources: QueryValueSources) -> anyhow::Result<Self> {
        let mut rules = if raw.trim().is_empty() {
            Self::default()
        } else {
            Self::parse(raw)?
        };
        rules.sources = sources;
        Ok(rules)
    }

    /// Parse `alias=METHOD /path?QUERY,METHOD /path?QUERY;alias2=...`; any malformed part is an
    /// error.
    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        let mut rules: HashMap<String, Vec<QueryRule>> = HashMap::new();
        for entry in raw.split(';') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let (alias, routes) = entry.split_once('=').ok_or_else(|| {
                anyhow!("Malformed {ENV} entry '{entry}': must be 'alias=METHOD /path?QUERY,...'")
            })?;
            let alias = alias.trim().to_ascii_lowercase();
            if alias.is_empty() {
                bail!("Malformed {ENV}: missing alias in '{entry}'");
            }
            if rules.contains_key(&alias) {
                bail!("Malformed {ENV}: alias '{alias}' listed twice (put all its routes in one entry)");
            }
            let mut list = Vec::new();
            for route in routes.split(',') {
                let route = route.trim();
                if route.is_empty() {
                    bail!("Malformed {ENV}: empty route in '{entry}'");
                }
                list.push(parse_route(route)?);
            }
            rules.insert(alias, list);
        }
        if rules.is_empty() {
            bail!("Malformed {ENV}: no entries");
        }
        Ok(Self {
            rules,
            sources: QueryValueSources::default(),
        })
    }

    /// Startup checks against the rest of the configuration: every alias is a `BACKENDS` alias
    /// (never a `GATEWAY_HOSTS` name or a dynamic host) whose own `BACKENDS_POLICY` entry
    /// allows each rule's route through exact entries only (see [`guard_route`]); every
    /// `{from:name}` names a configured source, and every source is used, is a `GET` of a
    /// `BACKENDS` alias allowed in the same way, and is not refused by a query rule.
    pub fn validate(
        &self,
        backends: &HashMap<String, String>,
        backends_policy: &HashMap<String, Vec<(String, String)>>,
    ) -> anyhow::Result<()> {
        let mut aliases: Vec<&String> = self.rules.keys().collect();
        aliases.sort();
        for alias in aliases {
            let rules = &self.rules[alias];
            for rule in rules {
                guard_route(
                    alias,
                    &rule.method,
                    &rule.path,
                    backends,
                    backends_policy,
                    rules,
                )?;
                for (name, value) in &rule.params {
                    if let ValueRule::From(source) = value {
                        let Some(spec) = self.sources.spec(source) else {
                            bail!(
                                "Invalid {ENV}: '{name}={{from:{source}}}' in '{} {}' of '{alias}' names no {} source",
                                rule.method,
                                rule.path,
                                value_source::ENV
                            );
                        };
                        if spec.alias != *alias {
                            bail!(
                                "Invalid {ENV}: '{name}={{from:{source}}}' in '{} {}' of '{alias}' uses a list read from another alias ('{}'); a source's values are only valid for its own alias",
                                rule.method,
                                rule.path,
                                spec.alias
                            );
                        }
                    }
                }
            }
        }
        let source_env = value_source::ENV;
        for spec in self.sources.specs() {
            let used = self.rules.values().flatten().any(|r| {
                r.params
                    .iter()
                    .any(|(_, v)| matches!(v, ValueRule::From(n) if *n == spec.name))
            });
            if !used {
                bail!(
                    "Invalid {source_env}: source '{}' is used by no {{from:{}}} in {ENV}",
                    spec.name,
                    spec.name
                );
            }
            let no_rules = Vec::new();
            let rules = self.rules.get(&spec.alias).unwrap_or(&no_rules);
            guard_route(
                &spec.alias,
                "GET",
                spec.route(),
                backends,
                backends_policy,
                rules,
            )
            .map_err(|e| anyhow!("{source_env} source '{}': {e}", spec.name))?;
            // The fetch is an ordinary request to the alias: a query rule of its route must
            // admit it, without any source list (none is known when it first runs).
            let without_lists = Self {
                rules: self.rules.clone(),
                sources: QueryValueSources::default(),
            };
            if !without_lists.admits(&spec.alias, "GET", &spec.path) {
                bail!(
                    "Invalid {source_env}: the request of source '{}' ('GET {}') is refused by {ENV} (a {{from:}} value cannot admit it)",
                    spec.name,
                    spec.path
                );
            }
        }
        Ok(())
    }

    /// Number of route rules.
    pub fn len(&self) -> usize {
        self.rules.values().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Whether `alias` (lowercase) has a rule for `method` (any case) on the exact path
    /// `path` (no query).
    pub fn has_rule(&self, alias: &str, method: &str, path: &str) -> bool {
        self.rules.get(alias).is_some_and(|rules| {
            rules
                .iter()
                .any(|r| r.path == path && method.eq_ignore_ascii_case(&r.method))
        })
    }

    /// Whether the query rules let `method path` (path with its raw query) to `authority`
    /// through: always when no rule names this alias, method and exact path; otherwise when the
    /// query matches one of those rules.
    pub fn admits(&self, authority: &str, method: &str, path: &str) -> bool {
        let Some(rules) = self.rules.get(&authority.to_ascii_lowercase()) else {
            return true;
        };
        let (route, query) = match path.split_once('?') {
            Some((route, query)) => (route, Some(query)),
            None => (path, None),
        };
        let mut applicable = rules
            .iter()
            .filter(|r| r.path == route && method.eq_ignore_ascii_case(&r.method))
            .peekable();
        if applicable.peek().is_none() {
            return true;
        }
        // One read of each source list per request, shared by all its `{from:}` parameters.
        let mut lists = Lists {
            sources: &self.sources,
            read: Vec::new(),
        };
        applicable.any(|r| r.admits(query, &mut lists))
    }
}

/// The startup guard of one route (`method route`, no query) of `alias`: `alias` is a
/// `BACKENDS` alias whose `BACKENDS_POLICY` entry admits the route for `method` through an
/// exact entry, and no entry of it admits the route through a `*` method, a `/*` prefix, or a
/// method without a rule of its own in `rules` (any of those would reach the route with any
/// query).
fn guard_route(
    alias: &str,
    method: &str,
    route: &str,
    backends: &HashMap<String, String>,
    backends_policy: &HashMap<String, Vec<(String, String)>>,
    rules: &[QueryRule],
) -> anyhow::Result<()> {
    if !backends.contains_key(alias) {
        bail!(
            "Invalid {ENV}: '{alias}' is not a BACKENDS alias (query rules apply to BACKENDS aliases only, not to GATEWAY_HOSTS or dynamic hosts)"
        );
    }
    let policies = backends_policy.get(alias).ok_or_else(|| {
        anyhow!("Invalid {ENV}: '{alias}' has no BACKENDS_POLICY entry allowing its routes")
    })?;
    if let Some((entry_method, pattern)) = policies.iter().find(|(_, p)| p.contains('?')) {
        bail!(
            "Invalid {ENV}: BACKENDS_POLICY entry '{entry_method} {pattern}' of '{alias}' contains '?'; an alias with query rules or value sources needs plain path entries, so that a rule's route and the entries that admit it compare exactly"
        );
    }
    let mut allowed = false;
    for (entry_method, pattern) in policies
        .iter()
        .filter(|(_, pattern)| crate::core::route::path_matches(pattern, route))
    {
        if entry_method == "*" {
            bail!(
                "Invalid {ENV}: BACKENDS_POLICY entry '* {pattern}' of '{alias}' admits '{route}' with every method, so methods without a query rule would reach it with any query; list exact 'METHOD {route}' entries instead"
            );
        }
        if pattern.ends_with("/*") {
            bail!(
                "Invalid {ENV}: BACKENDS_POLICY entry '{entry_method} {pattern}' of '{alias}' is a prefix entry admitting '{route}', so variants of that path would bypass its query rule; list '{entry_method} {route}' as an exact entry instead"
            );
        }
        if entry_method.eq_ignore_ascii_case(method) {
            allowed = true;
        } else if !rules
            .iter()
            .any(|r| r.path == route && entry_method.eq_ignore_ascii_case(&r.method))
        {
            bail!(
                "Invalid {ENV}: BACKENDS_POLICY entry '{entry_method} {pattern}' of '{alias}' admits '{route}' with a method that has no query rule, so that method would reach it with any query; add a rule for '{} {route}' or remove the entry",
                entry_method.to_ascii_uppercase()
            );
        }
    }
    if !allowed {
        bail!("Invalid {ENV}: '{method} {route}' of '{alias}' is not allowed by its BACKENDS_POLICY entry");
    }
    Ok(())
}

/// `METHOD /path?QUERY`.
fn parse_route(route: &str) -> anyhow::Result<QueryRule> {
    let (method, target) = route
        .split_once(' ')
        .ok_or_else(|| anyhow!("Malformed {ENV} route '{route}': must be 'METHOD /path?QUERY'"))?;
    let method = method.to_ascii_uppercase();
    if !matches!(
        method.as_str(),
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH"
    ) {
        bail!(
            "Invalid {ENV} method '{method}' in '{route}': must be GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH"
        );
    }
    let (path, query) = target.trim().split_once('?').ok_or_else(|| {
        anyhow!("Malformed {ENV} route '{route}': missing '?' (write '/path?' for no query string)")
    })?;
    // The rejections of the request side: a rule for a path no request can have is a mistake.
    if let Some(reason) = crate::core::route::rule_path_rejection(path) {
        bail!("Invalid {ENV} path '{path}' in '{route}': {reason}");
    }
    if path.contains('*') {
        bail!(
            "Invalid {ENV} path '{path}' in '{route}': must be an exact path (no prefix pattern)"
        );
    }
    let mut params: Vec<(String, ValueRule)> = Vec::new();
    if !query.is_empty() {
        for pair in query.split('&') {
            let (name, value) = pair.split_once('=').ok_or_else(|| {
                anyhow!("Malformed {ENV} parameter '{pair}' in '{route}': must be 'name=VALUE'")
            })?;
            if name.is_empty() {
                bail!("Malformed {ENV} parameter '{pair}' in '{route}': empty name");
            }
            if name.contains(['{', '}']) {
                bail!("Invalid {ENV} name '{name}' in '{route}': '{{' and '}}' not allowed");
            }
            check_token(name, "name", route, &['&', '=', '#'])?;
            if params.iter().any(|(n, _)| n == name) {
                bail!("Malformed {ENV} route '{route}': parameter '{name}' listed twice");
            }
            params.push((name.to_string(), ValueRule::parse(value, route)?));
        }
    }
    Ok(QueryRule {
        method,
        path: path.to_string(),
        params,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: &str = "Prices.Example=GET /v1/quotes?symbol=ZEC&convert={upper:3-5},\
                         GET /v1/map?,GET /v1/pair?base={in:ZEC|BTC|a.b~c}&quote=USD;\
                         other.example=POST /v2/lookup?id=a%2Bb&mode=x+y";

    fn rules() -> QueryRules {
        QueryRules::parse(RULES).unwrap()
    }

    fn err(raw: &str) -> String {
        QueryRules::parse(raw).unwrap_err().to_string()
    }

    #[test]
    fn valid_rules_parse() {
        let parsed = rules();
        assert_eq!(parsed.len(), 4);
        assert!(!parsed.is_empty());
        let prices = &parsed.rules["prices.example"];
        assert_eq!(prices[0].method, "GET");
        assert_eq!(prices[0].path, "/v1/quotes");
        assert_eq!(
            prices[0].params,
            vec![
                ("symbol".to_string(), ValueRule::Literal("ZEC".to_string())),
                ("convert".to_string(), ValueRule::Upper { min: 3, max: 5 }),
            ]
        );
        assert!(prices[1].params.is_empty());
        assert_eq!(
            prices[2].params[0].1,
            ValueRule::OneOf(vec!["ZEC".into(), "BTC".into(), "a.b~c".into()])
        );
        // Whitespace around entries and routes, empty `;` segments, lowercase methods, an empty
        // literal value, the largest pattern bounds.
        let loose =
            QueryRules::parse(" ; a.example = get /x?k= , POST /y?n={upper:1-32}&m={in:A} ;")
                .unwrap();
        assert_eq!(loose.len(), 2);
        assert_eq!(
            loose.rules["a.example"][0].params,
            vec![("k".to_string(), ValueRule::Literal(String::new()))]
        );
        let many: Vec<String> = (0..MAX_ALTERNATIVES).map(|i| format!("V{i}")).collect();
        QueryRules::parse(&format!("a.example=GET /x?k={{in:{}}}", many.join("|"))).unwrap();
        assert_eq!(QueryRules::default().len(), 0);
        assert!(QueryRules::default().is_empty());
    }

    #[test]
    fn invalid_rules_are_startup_errors() {
        let too_many: Vec<String> = (0..=MAX_ALTERNATIVES).map(|i| format!("V{i}")).collect();
        let too_many = format!("a.example=GET /x?k={{in:{}}}", too_many.join("|"));
        for (raw, expected) in [
            (";", "no entries"),
            ("a.example", "must be 'alias=METHOD"),
            ("=GET /x?", "missing alias"),
            ("a.example=GET /x?,", "empty route"),
            ("a.example=GET", "must be 'METHOD /path?QUERY'"),
            ("a.example=FETCH /x?", "method 'FETCH'"),
            ("a.example=* /x?", "method '*'"),
            ("a.example=GET /x", "missing '?'"),
            ("a.example=GET x?", "does not start with /"),
            ("a.example=GET /x/*?", "exact path"),
            ("a.example=GET /x*?", "exact path"),
            // The request side's path rejections.
            ("a.example=GET /x/../y?", "traversal"),
            ("a.example=GET /x/%2e%2e/y?", "traversal"),
            ("a.example=GET /x/%2E/y?", "traversal"),
            ("a.example=GET //x?", "//"),
            ("a.example=GET /x//y?", "double slashes"),
            ("a.example=GET /x#f?", "fragment"),
            ("a.example=GET /x\u{e9}?", "non-visible ASCII"),
            ("a.example=GET /x\u{7f}?", "non-visible ASCII"),
            ("a.example=GET /x?k", "must be 'name=VALUE'"),
            ("a.example=GET /x?=v", "empty name"),
            ("a.example=GET /x?k=v&", "must be 'name=VALUE'"),
            ("a.example=GET /x?k=v&k=w", "listed twice"),
            ("a.example=GET /x?k={lower:1-3}", "only patterns"),
            ("a.example=GET /x?k={upper:3}", "decimal MIN and MAX"),
            ("a.example=GET /x?k={upper:a-3}", "decimal MIN and MAX"),
            ("a.example=GET /x?k={upper:+1-3}", "decimal MIN and MAX"),
            ("a.example=GET /x?k={upper:0-3}", "1 <= MIN <= MAX <= 32"),
            ("a.example=GET /x?k={upper:5-3}", "1 <= MIN <= MAX <= 32"),
            ("a.example=GET /x?k={upper:1-33}", "1 <= MIN <= MAX <= 32"),
            ("a.example=GET /x?k={upper:1-3", "only patterns"),
            ("a.example=GET /x?k=upper:1-3}", "only patterns"),
            ("a.example=GET /x?k={in:A|B", "only patterns"),
            ("a.example=GET /x?k={in:}", "empty alternative"),
            ("a.example=GET /x?k={in:A||B}", "empty alternative"),
            ("a.example=GET /x?k={in:A|B|A}", "listed twice"),
            ("a.example=GET /x?k={in:A}B}", "[A-Za-z0-9._~-]"),
            ("a.example=GET /x?k={in:A=B}", "[A-Za-z0-9._~-]"),
            ("a.example=GET /x?k={in:A B}", "[A-Za-z0-9._~-]"),
            ("a.example=GET /x?k={in:A#B}", "[A-Za-z0-9._~-]"),
            ("a.example=GET /x?k={in:A%2B}", "[A-Za-z0-9._~-]"),
            ("a.example=GET /x?k={in:A+B}", "[A-Za-z0-9._~-]"),
            ("a.example=GET /x?k={in:A:B}", "[A-Za-z0-9._~-]"),
            (too_many.as_str(), "at most 256"),
            ("a.example=GET /x?k=a{b", "only in the patterns"),
            ("a.example=GET /x?k{=v", "not allowed"),
            ("a.example=GET /x?k=v#f", "not allowed"),
            ("a.example=GET /x?k=v w", "not allowed"),
            ("a.example=GET /x?k=\u{e9}", "not allowed"),
            ("a.example=GET /x?;A.example=GET /y?", "listed twice"),
        ] {
            let text = err(raw);
            assert!(text.contains(expected), "{raw}: {text}");
            assert!(text.contains(ENV), "{raw}: {text}");
        }
    }

    #[test]
    fn exact_names_each_once_in_the_rule_order() {
        let r = rules();
        let ok = |path: &str| r.admits("prices.example", "GET", path);
        assert!(ok("/v1/quotes?symbol=ZEC&convert=USD"));
        // The wrong order is refused: no reordering, the checked string is the forwarded one.
        assert!(!ok("/v1/quotes?convert=USD&symbol=ZEC"));
        // Missing, extra and duplicate parameters.
        assert!(!ok("/v1/quotes?symbol=ZEC"));
        assert!(!ok("/v1/quotes?convert=USD"));
        assert!(!ok("/v1/quotes"));
        assert!(!ok("/v1/quotes?"));
        assert!(!ok("/v1/quotes?symbol=ZEC&convert=USD&aux=1"));
        assert!(!ok("/v1/quotes?aux=1&symbol=ZEC&convert=USD"));
        assert!(!ok("/v1/quotes?symbol=ZEC&convert=USD&convert=EUR"));
        assert!(!ok("/v1/quotes?symbol=ZEC&symbol=ZEC&convert=USD"));
        // Empty pieces, a name without '=', case of names and literals.
        assert!(!ok("/v1/quotes?symbol=ZEC&&convert=USD"));
        assert!(!ok("/v1/quotes?symbol=ZEC&convert=USD&"));
        assert!(!ok("/v1/quotes?symbol&convert=USD"));
        assert!(!ok("/v1/quotes?Symbol=ZEC&convert=USD"));
        assert!(!ok("/v1/quotes?symbol=zec&convert=USD"));
        assert!(!ok("/v1/quotes?symbol=ZEC2&convert=USD"));
    }

    #[test]
    fn upper_pattern_lengths_and_class() {
        let r = rules();
        let convert = |v: &str| {
            r.admits(
                "prices.example",
                "GET",
                &format!("/v1/quotes?symbol=ZEC&convert={v}"),
            )
        };
        assert!(convert("USD"));
        assert!(convert("USDT"));
        assert!(convert("ABCDE"));
        assert!(!convert("US"));
        assert!(!convert("ABCDEF"));
        assert!(!convert(""));
        assert!(!convert("usd"));
        assert!(!convert("US1"));
        assert!(!convert("U%53D"));
        assert!(!convert("US+D"));
        assert!(!convert("US,EU"));
        assert!(!convert("\u{c9}UR"));
    }

    #[test]
    fn in_pattern_is_exact_equality_with_one_alternative() {
        let r = rules();
        let base = |v: &str| {
            r.admits(
                "prices.example",
                "GET",
                &format!("/v1/pair?base={v}&quote=USD"),
            )
        };
        assert!(base("ZEC"));
        assert!(base("BTC"));
        assert!(base("a.b~c"));
        for refused in [
            "zec", "ZE", "ZECC", "", "ZEC|BTC", "a.b%7Ec", "a.b~C", "%5AEC", "ETH",
        ] {
            assert!(!base(refused), "{refused}");
        }
    }

    #[test]
    fn empty_query_rule_admits_no_parameter_only() {
        let r = rules();
        let ok = |path: &str| r.admits("prices.example", "GET", path);
        assert!(ok("/v1/map"));
        assert!(ok("/v1/map?"));
        assert!(!ok("/v1/map?start=1"));
        assert!(!ok("/v1/map?&"));
        assert!(!ok("/v1/map?="));
    }

    #[test]
    fn percent_encoded_values_match_byte_identical_literals_only() {
        let r = rules();
        let ok = |path: &str| r.admits("other.example", "POST", path);
        assert!(ok("/v2/lookup?id=a%2Bb&mode=x+y"));
        // The decoded or differently encoded forms do not match.
        assert!(!ok("/v2/lookup?id=a+b&mode=x+y"));
        assert!(!ok("/v2/lookup?id=a%2bb&mode=x+y"));
        assert!(!ok("/v2/lookup?id=a%2Bb&mode=x%20y"));
        assert!(!ok("/v2/lookup?id=a%2Bb&mode=x y"));
        // An encoded name is not the literal name.
        assert!(!ok("/v2/lookup?%69d=a%2Bb&mode=x+y"));
    }

    #[test]
    fn rules_apply_only_to_their_alias_method_and_exact_path() {
        let r = rules();
        // Other alias, other method, other path (a child, a trailing slash): no rule applies.
        assert!(r.admits("unlisted.example", "GET", "/v1/quotes?anything=1"));
        assert!(r.admits("prices.example", "POST", "/v1/quotes?anything=1"));
        assert!(r.admits("prices.example", "GET", "/v1/quotes/x?anything=1"));
        assert!(r.admits("prices.example", "GET", "/v1/info?anything=1"));
        // Alias and method are case-insensitive, the path is not.
        assert!(!r.admits("PRICES.example", "get", "/v1/quotes?anything=1"));
        assert!(r.admits("prices.example", "GET", "/V1/quotes?anything=1"));
        // Several rules for one route: any of them admits.
        let two = QueryRules::parse("a.example=GET /x?k=A,GET /x?k=B&n={upper:1-2}").unwrap();
        assert!(two.admits("a.example", "GET", "/x?k=A"));
        assert!(two.admits("a.example", "GET", "/x?k=B&n=Q"));
        assert!(!two.admits("a.example", "GET", "/x?n=Q&k=B"));
        assert!(!two.admits("a.example", "GET", "/x?k=B"));
        assert!(!two.admits("a.example", "GET", "/x?k=A&n=Q"));
        // No rule at all: everything passes.
        assert!(QueryRules::default().admits("a.example", "GET", "/x?k=anything"));
    }

    fn policy(entries: &[(&str, &[(&str, &str)])]) -> HashMap<String, Vec<(String, String)>> {
        entries
            .iter()
            .map(|(alias, ops)| {
                (
                    alias.to_string(),
                    ops.iter()
                        .map(|(m, p)| (m.to_string(), p.to_string()))
                        .collect(),
                )
            })
            .collect()
    }

    fn backends() -> HashMap<String, String> {
        [
            ("prices.example", "https://api.prices.example"),
            ("other.example", "https://api.other.example"),
        ]
        .iter()
        .map(|(a, u)| (a.to_string(), u.to_string()))
        .collect()
    }

    const PRICES_POLICY: &[(&str, &str)] = &[
        ("GET", "/v1/quotes"),
        ("get", "/v1/map"),
        ("GET", "/v1/pair"),
        ("GET", "/v1/info"),
        ("GET", "/v1/assets/*"),
    ];

    #[test]
    fn rules_must_name_backends_aliases_allowed_by_their_policy() {
        let backends = backends();
        let full = policy(&[
            ("prices.example", PRICES_POLICY),
            ("other.example", &[("POST", "/v2/lookup"), ("*", "/v3/*")]),
        ]);
        rules().validate(&backends, &full).unwrap();

        // An alias that is not in BACKENDS (a gateway host, a dynamic host, a typo).
        let unknown = QueryRules::parse("ohttp-gateway.example=GET /x?").unwrap();
        let text = unknown.validate(&backends, &full).unwrap_err().to_string();
        assert!(text.contains("not a BACKENDS alias"), "{text}");

        // No BACKENDS_POLICY entry for the alias (BACKENDS_POLICY_DEFAULT=allow does not count).
        let missing = policy(&[("prices.example", PRICES_POLICY)]);
        let text = rules()
            .validate(&backends, &missing)
            .unwrap_err()
            .to_string();
        assert!(text.contains("no BACKENDS_POLICY entry"), "{text}");

        // A route its policy does not allow (another path), or allows only for another method
        // (which then has no query rule).
        let narrow = policy(&[
            ("prices.example", PRICES_POLICY),
            ("other.example", &[("POST", "/v2/lookups")]),
        ]);
        let text = rules()
            .validate(&backends, &narrow)
            .unwrap_err()
            .to_string();
        assert!(
            text.contains("is not allowed by its BACKENDS_POLICY"),
            "{text}"
        );
        let narrow = policy(&[
            ("prices.example", PRICES_POLICY),
            ("other.example", &[("PUT", "/v2/lookup")]),
        ]);
        let text = rules()
            .validate(&backends, &narrow)
            .unwrap_err()
            .to_string();
        assert!(text.contains("has no query rule"), "{text}");
    }

    #[test]
    fn wildcard_entries_admitting_a_rule_path_are_startup_errors() {
        let backends = backends();
        let with = |ops: &'static [(&'static str, &'static str)]| {
            let p = policy(&[("prices.example", PRICES_POLICY), ("other.example", ops)]);
            rules().validate(&backends, &p).map_err(|e| e.to_string())
        };
        // A `*`-method entry, exact or prefix, that admits the rule's path.
        let text = with(&[("POST", "/v2/lookup"), ("*", "/v2/lookup")]).unwrap_err();
        assert!(text.contains("with every method"), "{text}");
        let text = with(&[("*", "/v2/*")]).unwrap_err();
        assert!(text.contains("with every method"), "{text}");
        // A prefix entry of the rule's method, including `/*`.
        let text = with(&[("POST", "/v2/*")]).unwrap_err();
        assert!(text.contains("prefix entry"), "{text}");
        let text = with(&[("POST", "/v2/lookup"), ("POST", "/*")]).unwrap_err();
        assert!(text.contains("prefix entry"), "{text}");
        // Another method on the same path without a rule of its own.
        let text = with(&[("POST", "/v2/lookup"), ("GET", "/v2/lookup")]).unwrap_err();
        assert!(text.contains("has no query rule"), "{text}");
        assert!(text.contains("'GET /v2/lookup'"), "{text}");
        // Entries for other paths do not matter, wildcards included.
        with(&[
            ("POST", "/v2/lookup"),
            ("*", "/v3/*"),
            ("GET", "/v2/lookups"),
        ])
        .unwrap();
        // Another method with a rule of its own is fine.
        let both = QueryRules::parse("other.example=POST /v2/lookup?id=A,GET /v2/lookup?").unwrap();
        let p = policy(&[(
            "other.example",
            &[("POST", "/v2/lookup"), ("GET", "/v2/lookup")],
        )]);
        both.validate(&backends, &p).unwrap();
    }

    #[test]
    fn from_patterns_use_the_current_source_list() {
        let sources = QueryValueSources::parse(
            "fiat=prices.example GET /v1/fiat/map#/data/*/symbol@21600@fallback=USD|EUR",
        )
        .unwrap();
        let rules = QueryRules::parse_with_sources(
            "prices.example=GET /v1/quotes?symbol=ZEC&convert={from:fiat}",
            sources.clone(),
        )
        .unwrap();
        assert_eq!(
            rules.rules["prices.example"][0].params[1].1,
            ValueRule::From("fiat".to_string())
        );
        let ok = |v: &str| {
            rules.admits(
                "prices.example",
                "GET",
                &format!("/v1/quotes?symbol=ZEC&convert={v}"),
            )
        };
        // The fallback before the first accepted refresh, then the accepted list.
        assert!(ok("USD") && ok("EUR") && !ok("JPY") && !ok("usd"));
        let doc = br#"{"data":[{"symbol":"JPY"}]}"#.to_vec();
        assert_eq!(
            sources.update("fiat", Ok(doc)).unwrap().outcome,
            crate::core::value_source::Outcome::Ok
        );
        assert!(ok("JPY") && !ok("USD"));
        // One evaluation reads each list once, however many `{from:}` parameters use it.
        let twice = QueryRules::parse_with_sources(
            "prices.example=GET /v1/pair?base={from:fiat}&quote={from:fiat}",
            sources.clone(),
        )
        .unwrap();
        let reads = sources.reads("fiat");
        assert!(twice.admits("prices.example", "GET", "/v1/pair?base=JPY&quote=JPY"));
        assert_eq!(sources.reads("fiat"), reads + 1);
        assert!(!twice.admits("prices.example", "GET", "/v1/pair?base=JPY&quote=USD"));
        assert_eq!(sources.reads("fiat"), reads + 2);
        // Grammar of the pattern.
        for (raw, expected) in [
            ("a.example=GET /x?k={from:Fiat}", "source name"),
            ("a.example=GET /x?k={from:}", "source name"),
            ("a.example=GET /x?k={from:fiat", "only patterns"),
        ] {
            let text = err(raw);
            assert!(text.contains(expected), "{raw}: {text}");
        }
    }

    #[test]
    fn sources_are_checked_against_the_rules_and_the_policy() {
        let backends = backends();
        let fiat = "fiat=prices.example GET /v1/fiat/map#/data/*/symbol@21600";
        let check = |rules: &str, sources: &str, ops: &'static [(&'static str, &'static str)]| {
            let sources = QueryValueSources::parse(sources).unwrap();
            QueryRules::parse_with_sources(rules, sources)
                .unwrap()
                .validate(&backends, &policy(&[("prices.example", ops)]))
                .map_err(|e| e.to_string())
        };
        let rule = "prices.example=GET /v1/quotes?convert={from:fiat}";
        let exact: &[(&str, &str)] = &[("GET", "/v1/quotes"), ("GET", "/v1/fiat/map")];
        check(rule, fiat, exact).unwrap();
        // An unknown source name.
        let text = check(
            "prices.example=GET /v1/quotes?convert={from:other}",
            fiat,
            exact,
        )
        .unwrap_err();
        assert!(
            text.contains("names no THIRD_PARTY_QUERY_VALUE_SOURCES source"),
            "{text}"
        );
        // A source no rule uses (also: sources without any rule).
        let text = check("prices.example=GET /v1/quotes?convert=USD", fiat, exact).unwrap_err();
        assert!(text.contains("used by no {from:fiat}"), "{text}");
        let text = check("", fiat, exact).unwrap_err();
        assert!(text.contains("used by no {from:fiat}"), "{text}");
        // The source route: not allowed, through a prefix entry, a `*` method, or with another
        // method without a rule.
        let text = check(rule, fiat, &[("GET", "/v1/quotes")]).unwrap_err();
        assert!(
            text.contains("source 'fiat'") && text.contains("is not allowed"),
            "{text}"
        );
        let text = check(rule, fiat, &[("GET", "/v1/quotes"), ("GET", "/v1/fiat/*")]).unwrap_err();
        assert!(text.contains("prefix entry"), "{text}");
        let text = check(rule, fiat, &[("GET", "/v1/quotes"), ("*", "/v1/fiat/map")]).unwrap_err();
        assert!(text.contains("with every method"), "{text}");
        let text = check(
            rule,
            fiat,
            &[
                ("GET", "/v1/quotes"),
                ("GET", "/v1/fiat/map"),
                ("POST", "/v1/fiat/map"),
            ],
        )
        .unwrap_err();
        assert!(text.contains("has no query rule"), "{text}");
        // A source alias outside BACKENDS.
        let text = check(rule, "fiat=gw.example GET /v1/fiat/map#/data@300", exact).unwrap_err();
        // (its alias must be the rule's, which is checked against BACKENDS)
        assert!(text.contains("another alias ('gw.example')"), "{text}");
        // The source's own request must pass a query rule of its route.
        let listed = "prices.example=GET /v1/quotes?convert={from:fiat},GET /v1/fiat/map?";
        check(listed, fiat, exact).unwrap();
        let text = check(
            listed,
            "fiat=prices.example GET /v1/fiat/map?limit=10#/data@300",
            exact,
        )
        .unwrap_err();
        assert!(
            text.contains("is refused by THIRD_PARTY_QUERY_RULES"),
            "{text}"
        );
        let circular =
            "prices.example=GET /v1/quotes?convert={from:fiat},GET /v1/fiat/map?c={from:fiat}";
        let text = check(
            circular,
            "fiat=prices.example GET /v1/fiat/map?c=USD#/data@300",
            exact,
        )
        .unwrap_err();
        assert!(
            text.contains("is refused by THIRD_PARTY_QUERY_RULES"),
            "{text}"
        );
    }

    #[test]
    fn a_question_mark_in_a_policy_entry_of_a_guarded_alias_is_a_startup_error() {
        let backends = backends();
        let p = policy(&[
            ("prices.example", PRICES_POLICY),
            (
                "other.example",
                &[("POST", "/v2/lookup"), ("GET", "/v2/list?all=1")],
            ),
        ]);
        let text = rules().validate(&backends, &p).unwrap_err().to_string();
        assert!(text.contains("contains '?'"), "{text}");
        // The same entry on an alias without rules or sources is not checked here.
        let only_prices = QueryRules::parse("prices.example=GET /v1/quotes?").unwrap();
        only_prices.validate(&backends, &p).unwrap();
        // A source on such an alias too.
        let sources =
            QueryValueSources::parse("ids=other.example GET /v2/lookup#/ids/*@300").unwrap();
        let with_source =
            QueryRules::parse_with_sources("other.example=POST /v2/lookup?id={from:ids}", sources)
                .unwrap();
        let text = with_source.validate(&backends, &p).unwrap_err().to_string();
        assert!(text.contains("contains '?'"), "{text}");
    }

    #[test]
    fn a_source_is_only_used_by_rules_of_its_own_alias() {
        let backends = backends();
        let sources =
            QueryValueSources::parse("fiat=other.example GET /v2/fiat#/data/*@300").unwrap();
        let p = policy(&[
            ("prices.example", &[("GET", "/v1/quotes")]),
            (
                "other.example",
                &[("GET", "/v2/fiat"), ("GET", "/v2/quotes")],
            ),
        ]);
        let cross = QueryRules::parse_with_sources(
            "prices.example=GET /v1/quotes?convert={from:fiat}",
            sources.clone(),
        )
        .unwrap();
        let text = cross.validate(&backends, &p).unwrap_err().to_string();
        assert!(text.contains("another alias ('other.example')"), "{text}");
        let own = QueryRules::parse_with_sources(
            "other.example=GET /v2/quotes?convert={from:fiat}",
            sources,
        )
        .unwrap();
        own.validate(&backends, &p).unwrap();
    }
}

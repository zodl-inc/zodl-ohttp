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

//! Credentials a provider adds to its upstream requests.
//!
//! - [`Header`]: one header, its value a template in which `{secret}` stands for a secret
//!   (`X-Api-Key: {secret}`, `Authorization: Bearer {secret}`); without a secret the value is
//!   taken as it is (a fixed `BACKEND_HEADERS` entry).
//! - [`PlaceholderSwap`]: the client sends an agreed placeholder in `Authorization` (HTTP Basic
//!   with an empty user name and the placeholder as password); the gateway puts the real secret
//!   in its place and passes any other `Authorization` through untouched.
//!
//! Signed credentials (a JWT per request) come with the providers that need them.

use base64::Engine;

/// A credential of a provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Signer<'a> {
    Header(Header<'a>),
    PlaceholderSwap(PlaceholderSwap<'a>),
}

impl Signer<'_> {
    /// The headers this credential adds to an upstream request whose inner request carries
    /// `headers`.
    pub fn headers(&self, headers: &[(String, String)]) -> Vec<(String, String)> {
        match self {
            Signer::Header(header) => vec![header.header()],
            Signer::PlaceholderSwap(swap) => {
                let client = headers
                    .iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case("authorization"))
                    .map(|(_, v)| v.as_str());
                swap.authorization(client)
                    .map(|v| ("authorization".to_string(), v))
                    .into_iter()
                    .collect()
            }
        }
    }
}

/// One header: `name` and a `value` template; with a `secret`, every `{secret}` in the template
/// is replaced by it, without one the template is the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header<'a> {
    pub name: &'a str,
    pub value: &'a str,
    pub secret: Option<&'a str>,
}

impl<'a> Header<'a> {
    /// A fixed header (no secret).
    pub fn literal(name: &'a str, value: &'a str) -> Self {
        Self {
            name,
            value,
            secret: None,
        }
    }

    /// The header as sent: its name and value, unchanged otherwise.
    pub fn header(&self) -> (String, String) {
        let value = match self.secret {
            Some(secret) => self.value.replace("{secret}", secret),
            None => self.value.to_string(),
        };
        (self.name.to_string(), value)
    }
}

/// `Basic base64(":" + secret)`: HTTP Basic with an empty user name.
pub fn basic_authorization(secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!(":{secret}"))
    )
}

/// The swap of a placeholder credential for the real secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlaceholderSwap<'a> {
    /// What the client sends as the password of `Basic base64(":" + placeholder)`.
    pub placeholder: &'a str,
    /// The real secret; `None`: not configured, the placeholder is dropped.
    pub secret: Option<&'a str>,
}

impl PlaceholderSwap<'_> {
    /// Whether `value` is the placeholder credential: scheme `Basic` (any case), and a
    /// credential that decodes to exactly `":" + placeholder`.
    pub fn is_placeholder(&self, value: &str) -> bool {
        let Some((scheme, credential)) = value.trim().split_once(' ') else {
            return false;
        };
        scheme.eq_ignore_ascii_case("basic")
            && base64::engine::general_purpose::STANDARD
                .decode(credential.trim())
                .is_ok_and(|decoded| decoded == format!(":{}", self.placeholder).as_bytes())
    }

    /// The `Authorization` value that goes upstream for the client's `client` (the first one it
    /// sent): the real secret for the placeholder (none when no secret is configured: the
    /// placeholder is never sent), any other value untouched, none for none.
    pub fn authorization(&self, client: Option<&str>) -> Option<String> {
        match client {
            Some(v) if self.is_placeholder(v) => self.secret.map(basic_authorization),
            Some(v) => Some(v.to_string()),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn header_templates() {
        let literal = Header::literal("X-Fixed", "a {secret} b");
        assert_eq!(literal.header(), ("X-Fixed".into(), "a {secret} b".into()));
        let bearer = Header {
            name: "Authorization",
            value: "Bearer {secret}",
            secret: Some("jwt-1"),
        };
        assert_eq!(
            Signer::Header(bearer).headers(&h(&[("Authorization", "Bearer client")])),
            h(&[("Authorization", "Bearer jwt-1")])
        );
        let key = Header {
            name: "x-api-key",
            value: "{secret}",
            secret: Some("k"),
        };
        assert_eq!(key.header(), ("x-api-key".into(), "k".into()));
    }

    #[test]
    fn placeholder_swap() {
        let swap = PlaceholderSwap {
            placeholder: "placeholder-1",
            secret: Some("real-1"),
        };
        let placeholder = basic_authorization("placeholder-1");
        assert_eq!(placeholder, "Basic OnBsYWNlaG9sZGVyLTE=");
        assert_eq!(
            swap.authorization(Some(&placeholder)),
            Some(basic_authorization("real-1"))
        );
        assert_eq!(
            swap.authorization(Some(&placeholder.replace("Basic", "bAsIc"))),
            Some(basic_authorization("real-1"))
        );
        for other in [
            "Bearer placeholder-1",
            "Basic cGxhY2Vob2xkZXItMTo=",
            "Basic !",
        ] {
            assert_eq!(swap.authorization(Some(other)), Some(other.to_string()));
        }
        assert_eq!(swap.authorization(None), None);
        let unset = PlaceholderSwap {
            secret: None,
            ..swap
        };
        assert_eq!(unset.authorization(Some(&placeholder)), None);
        // The first Authorization of the request counts.
        assert_eq!(
            Signer::PlaceholderSwap(swap).headers(&h(&[
                ("authorization", &placeholder),
                ("Authorization", "Basic other"),
            ])),
            h(&[("authorization", &basic_authorization("real-1"))])
        );
        assert!(Signer::PlaceholderSwap(swap).headers(&[]).is_empty());
    }
}

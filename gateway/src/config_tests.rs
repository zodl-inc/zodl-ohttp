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

#[cfg(test)]
mod security_tests {
    use super::super::*;
    use crate::config_source::with_vars;

    /// No variable at all: the configuration of a process whose files set nothing.
    const NONE: [(&str, &str); 0] = [];

    #[test]
    fn test_ohttp_defaults_have_no_relay_secret_and_no_bypass() {
        let config = with_vars([("GATEWAY_MODE", "ohttp")], Config::from_env).unwrap();
        // The parsed defaults: no secret and no bypass flag, which startup refuses in OHTTP mode
        assert!(config.relay_secrets.is_empty() && !config.allow_unauthenticated_relay);
    }

    #[test]
    fn test_hpke_keys_parsing() {
        let config = with_vars([("HPKE_KEYS", "0:aabbccdd11223344556677889900112233445566778899001122334455667788,1:1122334455667788990011223344556677889900112233445566778899001122")], Config::from_env).unwrap();
        assert_eq!(config.hpke_keys.len(), 2);
        assert_eq!(config.hpke_keys[0].0, 0);
        assert_eq!(config.hpke_keys[1].0, 1);
    }

    #[test]
    fn test_hpke_keys_empty() {
        let config = with_vars(NONE, Config::from_env).unwrap();
        assert!(config.hpke_keys.is_empty());
    }

    #[test]
    fn test_hpke_keys_malformed() {
        // Malformed HPKE_KEYS entries should cause a startup error instead of being silently ignored
        let result = with_vars([("HPKE_KEYS", "not:a:valid:format")], Config::from_env);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid key_id"));
    }

    #[test]
    fn test_invalid_method_rejected() {
        // Invalid method should cause startup error (prevents silent denial)
        let result = with_vars(
            [("BACKENDS_POLICY", "test.example=INVALID /api/*")],
            Config::from_env,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid BACKENDS_POLICY method"));
    }

    #[test]
    fn test_method_wildcard_accepted() {
        // * wildcard should be accepted as valid method
        let config =
            with_vars([("BACKENDS_POLICY", "test.example=* /*")], Config::from_env).unwrap();
        assert_eq!(
            config.backends_policy.get("test.example").unwrap()[0].0,
            "*"
        );
    }

    #[test]
    fn test_relay_secret_on_key_config_parse() {
        assert_eq!(
            RelaySecretOnKeyConfig::parse("").unwrap(),
            RelaySecretOnKeyConfig::Off
        );
        assert_eq!(
            RelaySecretOnKeyConfig::parse("off").unwrap(),
            RelaySecretOnKeyConfig::Off
        );
        assert_eq!(
            RelaySecretOnKeyConfig::parse("require").unwrap(),
            RelaySecretOnKeyConfig::Require
        );
        let err = RelaySecretOnKeyConfig::parse("yes")
            .unwrap_err()
            .to_string();
        assert!(err.contains("Invalid RELAY_SECRET_ON_KEY_CONFIG"));
    }

    #[test]
    fn test_authenticated_relay() {
        use axum::http::{HeaderMap, HeaderValue};
        let secrets = parse_relay_secrets("edge-a=s3cret-a,edge-b=s3cret-b").unwrap();
        let with = |values: &[&[u8]]| {
            let mut headers = HeaderMap::new();
            for v in values {
                headers.append("X-Relay-Secret", HeaderValue::from_bytes(v).unwrap());
            }
            authenticated_relay(&secrets, &headers)
        };
        assert_eq!(with(&[]), None);
        assert_eq!(with(&[b"s3cret-b"]), Some(1));
        assert_eq!(with(&[b"wrong"]), None);
        assert_eq!(with(&[b"s3cret-a", b"s3cret-a"]), None);
        assert_eq!(with(&[b"s3cret-\xff"]), None);
        assert_eq!(authenticated_relay(&[], &HeaderMap::new()), None);
    }

    #[test]
    fn gateway_hosts_required_in_ohttp_mode() {
        let hosts = vec!["ohttp-gateway.example".to_string()];
        assert!(require_gateway_hosts("ohttp", &hosts).is_ok());
        let err = require_gateway_hosts("ohttp", &[]).unwrap_err().to_string();
        assert!(err.contains("GATEWAY_HOSTS is required"), "{err}");
        // Proxy mode does not route by authority.
        assert!(require_gateway_hosts("proxy", &[]).is_ok());
    }

    #[test]
    fn gateway_hosts_empty_entries_count_as_unset() {
        let hosts = with_vars([("GATEWAY_HOSTS", " , ")], Config::from_env)
            .map(|c| c.gateway_hosts)
            .expect("config loads");
        assert!(hosts.is_empty());
        assert!(require_gateway_hosts("ohttp", &hosts).is_err());
    }
}

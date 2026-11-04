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
    use std::env;

    #[test]
    fn test_ohttp_defaults_have_no_relay_secret_and_no_bypass() {
        let _env = crate::config::test_env_lock();
        env::remove_var("RELAY_SECRET");
        env::remove_var("RELAY_SECRETS");
        env::remove_var("ALLOW_UNAUTHENTICATED_RELAY");
        env::set_var("GATEWAY_MODE", "ohttp");

        let config = Config::from_env().unwrap();
        // The parsed defaults: no secret and no bypass flag, which startup refuses in OHTTP mode
        assert!(config.relay_secrets.is_empty() && !config.allow_unauthenticated_relay);
    }

    #[test]
    fn test_hpke_keys_parsing() {
        let _env = crate::config::test_env_lock();
        env::set_var("HPKE_KEYS", "0:aabbccdd11223344556677889900112233445566778899001122334455667788,1:1122334455667788990011223344556677889900112233445566778899001122");
        let config = Config::from_env().unwrap();
        assert_eq!(config.hpke_keys.len(), 2);
        assert_eq!(config.hpke_keys[0].0, 0);
        assert_eq!(config.hpke_keys[1].0, 1);
        env::remove_var("HPKE_KEYS");
    }

    #[test]
    fn test_hpke_keys_empty() {
        let _env = crate::config::test_env_lock();
        env::remove_var("HPKE_KEYS");
        let config = Config::from_env().unwrap();
        assert!(config.hpke_keys.is_empty());
    }

    #[test]
    fn test_hpke_keys_malformed() {
        let _env = crate::config::test_env_lock();
        // Malformed HPKE_KEYS entries should cause a startup error instead of being silently ignored
        env::set_var("HPKE_KEYS", "not:a:valid:format");
        let result = Config::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid key_id"));
        env::remove_var("HPKE_KEYS");
    }

    #[test]
    fn test_invalid_method_rejected() {
        let _env = crate::config::test_env_lock();
        // Invalid method should cause startup error (prevents silent denial)
        env::set_var("BACKENDS_POLICY", "test.example=INVALID /api/*");
        let result = Config::from_env();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid BACKENDS_POLICY method"));
        env::remove_var("BACKENDS_POLICY");
    }

    #[test]
    fn test_method_wildcard_accepted() {
        let _env = crate::config::test_env_lock();
        // * wildcard should be accepted as valid method
        env::set_var("BACKENDS_POLICY", "test.example=* /*");
        let config = Config::from_env().unwrap();
        assert_eq!(
            config.backends_policy.get("test.example").unwrap()[0].0,
            "*"
        );
        env::remove_var("BACKENDS_POLICY");
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
}

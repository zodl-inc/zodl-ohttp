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

//! RFC 9458 §3 key configurations: which of the gateway's keys a request is sealed to, under
//! the rules each client applies to the `application/ohttp-keys` document. The sealing itself
//! is chunked OHTTP, in [`crate::chunked`].

use crate::Error;

/// RFC 9180 identifiers of the one suite spoken.
pub(crate) const KEM_X25519: u16 = 0x0020;
pub(crate) const KDF_HKDF_SHA256: u16 = 0x0001;
pub(crate) const AEAD_AES_128_GCM: u16 = 0x0001;
/// AES-128-GCM's key and nonce lengths (`Nk`, `Nn`).
pub(crate) const N_K: usize = 16;
pub(crate) const N_N: usize = 12;
/// An X25519 public key (`Npk`).
pub(crate) const N_PK: usize = 32;
/// AES-GCM's authentication tag (`Nt`).
pub(crate) const N_T: usize = 16;
/// The length of [`KeyConfig::to_bytes`].
pub const KEY_BYTES: usize = 1 + N_PK;
/// The most configurations of one `application/ohttp-keys` document that are looked at before
/// the document is refused: a gateway lists a handful, and each costs a parse.
pub(crate) const MAX_CONFIGS: usize = 4096;

/// One key configuration of a gateway, in the suite spoken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyConfig {
    key_id: u8,
    public_key: [u8; N_PK],
}

/// What to do with a configuration whose KEM is not X25519.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnsupportedKem {
    /// Skip it unread and look at the next configuration (RFC 9458 §3.2 lets a gateway list
    /// several KEMs).
    Skip,
    /// Fail the whole document on the first such configuration.
    Reject,
}

/// How strictly one configuration's internal lengths are checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryLayout {
    /// The public key and the suite list must fill the configuration exactly, the suite list
    /// being a whole number of `(kdf_id, aead_id)` pairs.
    Strict,
    /// The public key and the suite list must lie within the configuration; bytes left after
    /// them, and a trailing partial suite pair, are ignored.
    Lenient,
}

/// The rules [`KeyConfig::select_with`] applies to a key-configuration document. Where the
/// three wallet clients differed when this was written, each has a preset
/// ([`crate::ClientProfile`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeySelection {
    /// A configuration whose KEM is not X25519.
    pub unsupported_kem: UnsupportedKem,
    /// How a configuration's lengths are checked.
    pub entry_layout: EntryLayout,
    /// Whether to seal to the chosen key at selection time, failing the document if HPKE
    /// refuses the key, rather than failing every later request.
    pub validate_key: bool,
    /// The most configurations looked at (skipped ones included) before the document is
    /// refused. Every preset uses 4096.
    pub max_configs: usize,
}

impl KeySelection {
    /// This library's own rules: other KEMs skipped, exact lengths, the key validated.
    pub const LIBRARY: KeySelection = KeySelection {
        unsupported_kem: UnsupportedKem::Skip,
        entry_layout: EntryLayout::Strict,
        validate_key: true,
        max_configs: MAX_CONFIGS,
    };
    /// The Android SDK (`OhttpKeyConfig.parseSupported`): other KEMs skipped (the ZIP's
    /// "Mandatory cipher suite"; the Kotlin parser failed on them), lenient lengths, the key is
    /// first used when sealing.
    pub const ANDROID: KeySelection = KeySelection {
        unsupported_kem: UnsupportedKem::Skip,
        entry_layout: EntryLayout::Lenient,
        validate_key: false,
        max_configs: MAX_CONFIGS,
    };
    /// The Swift SDK (`OHTTPKeyConfig.parseSupported`): other KEMs skipped, lenient lengths.
    pub const IOS: KeySelection = KeySelection {
        unsupported_kem: UnsupportedKem::Skip,
        entry_layout: EntryLayout::Lenient,
        validate_key: false,
        max_configs: MAX_CONFIGS,
    };
    /// Slipstream (`KeyConfig::parse_supported`): same rules as iOS.
    pub const SLIPSTREAM: KeySelection = KeySelection {
        unsupported_kem: UnsupportedKem::Skip,
        entry_layout: EntryLayout::Lenient,
        validate_key: false,
        max_configs: MAX_CONFIGS,
    };
}

impl KeyConfig {
    /// [`KeyConfig::select_with`] under [`KeySelection::LIBRARY`].
    pub fn select(document: &[u8]) -> Result<Self, Error> {
        Self::select_with(document, &KeySelection::LIBRARY)
    }

    /// The first configuration of an `application/ohttp-keys` document (RFC 9458 §3.2: the
    /// gateway lists its preferred key first) that offers the suite spoken, under the rules
    /// `selection` gives. A malformed configuration before it fails the whole document.
    pub fn select_with(document: &[u8], selection: &KeySelection) -> Result<Self, Error> {
        let malformed = |what: &str| Error::KeyConfig(what.to_string());
        let mut rest = document;
        let mut seen = 0usize;
        while !rest.is_empty() {
            seen += 1;
            if seen > selection.max_configs {
                return Err(malformed("too many configurations"));
            }
            let (len, tail) = take_u16(rest).ok_or_else(|| malformed("truncated"))?;
            if tail.len() < len as usize {
                return Err(malformed("truncated"));
            }
            let (config, tail) = tail.split_at(len as usize);
            rest = tail;
            if let Some(config) = Self::parse(config, selection)? {
                if selection.validate_key {
                    // A key HPKE refuses would otherwise be kept and fail every request.
                    let Ok(_) = crate::chunked::encapsulate_chunked_request(&config, &[]) else {
                        return Err(malformed("the gateway's key is not a usable X25519 key"));
                    };
                }
                return Ok(config);
            }
        }
        Err(malformed(
            "no configuration offers X25519, HKDF-SHA256 and AES-128-GCM",
        ))
    }

    /// One configuration, `key_id(8) kem_id(16) public_key(Npk) symmetric_len(16)
    /// (kdf_id(16) aead_id(16))*`: `Ok(None)` if it offers another suite, an error if it is
    /// malformed. A KEM other than X25519 is skipped unread (its key length being its own)
    /// or refused, as `selection` says.
    fn parse(config: &[u8], selection: &KeySelection) -> Result<Option<Self>, Error> {
        let malformed = || Error::KeyConfig("malformed".to_string());
        let (&key_id, rest) = config.split_first().ok_or_else(malformed)?;
        let (kem, rest) = take_u16(rest).ok_or_else(malformed)?;
        if kem != KEM_X25519 {
            return match selection.unsupported_kem {
                UnsupportedKem::Skip => Ok(None),
                UnsupportedKem::Reject => {
                    Err(Error::KeyConfig(format!("unsupported KEM 0x{kem:04x}")))
                }
            };
        }
        let public_key: [u8; N_PK] = rest
            .get(..N_PK)
            .ok_or_else(malformed)?
            .try_into()
            .map_err(|_| malformed())?;
        let (symmetric_len, rest) = take_u16(&rest[N_PK..]).ok_or_else(malformed)?;
        let symmetric_len = symmetric_len as usize;
        let suites = match selection.entry_layout {
            EntryLayout::Strict => {
                if rest.len() != symmetric_len || symmetric_len & 3 != 0 {
                    return Err(malformed());
                }
                rest
            }
            EntryLayout::Lenient => rest.get(..symmetric_len).ok_or_else(malformed)?,
        };
        let offered = suites.as_chunks::<4>().0.iter().any(|suite| {
            suite[..2] == KDF_HKDF_SHA256.to_be_bytes()
                && suite[2..] == AEAD_AES_128_GCM.to_be_bytes()
        });
        Ok(offered.then_some(KeyConfig { key_id, public_key }))
    }

    /// The configuration as 33 bytes, `key_id || public_key`: what a client keeps in its cache
    /// and hands to a foreign-function boundary. Public data, not a secret.
    pub fn to_bytes(&self) -> [u8; KEY_BYTES] {
        let mut bytes = [0; KEY_BYTES];
        bytes[0] = self.key_id;
        bytes[1..].copy_from_slice(&self.public_key);
        bytes
    }

    /// The configuration [`KeyConfig::to_bytes`] wrote; `None` for any other length. The
    /// key is not checked to be a valid X25519 key until it is sealed to (or selected under
    /// [`KeySelection::validate_key`]).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (&key_id, public_key) = bytes.split_first()?;
        Some(KeyConfig {
            key_id,
            public_key: public_key.try_into().ok()?,
        })
    }

    /// The configuration's key id.
    pub fn key_id(&self) -> u8 {
        self.key_id
    }

    /// The gateway's X25519 public key.
    pub fn public_key(&self) -> &[u8; N_PK] {
        &self.public_key
    }
}

fn take_u16(bytes: &[u8]) -> Option<(u16, &[u8])> {
    match bytes {
        [a, b, rest @ ..] => Some((u16::from_be_bytes([*a, *b]), rest)),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A document of one usable configuration, key id 4.
    pub(crate) fn usable_document() -> Vec<u8> {
        config_bytes(4, KEM_X25519, &[(1, 1)])
    }

    fn config_bytes(key_id: u8, kem: u16, suites: &[(u16, u16)]) -> Vec<u8> {
        let mut config = vec![key_id];
        config.extend_from_slice(&kem.to_be_bytes());
        config.extend_from_slice(&[key_id; N_PK]);
        config.extend_from_slice(&((suites.len() * 4) as u16).to_be_bytes());
        for (kdf, aead) in suites {
            config.extend_from_slice(&kdf.to_be_bytes());
            config.extend_from_slice(&aead.to_be_bytes());
        }
        let mut prefixed = (config.len() as u16).to_be_bytes().to_vec();
        prefixed.extend_from_slice(&config);
        prefixed
    }

    #[test]
    fn the_first_configuration_offering_the_suite_is_chosen() {
        // P-256, then X25519 with ChaCha20-Poly1305 only: both skipped.
        let mut document = config_bytes(1, 0x0010, &[(1, 1)]);
        document.extend(config_bytes(2, KEM_X25519, &[(1, 3)]));
        document.extend(config_bytes(3, KEM_X25519, &[(1, 3), (1, 1)]));
        document.extend(config_bytes(4, KEM_X25519, &[(1, 1)]));
        let config = KeyConfig::select(&document).unwrap();
        assert_eq!(
            config,
            KeyConfig {
                key_id: 3,
                public_key: [3; N_PK]
            }
        );
    }

    #[test]
    fn a_document_without_the_suite_or_truncated_is_refused() {
        let Err(Error::KeyConfig(_)) = KeyConfig::select(&config_bytes(2, KEM_X25519, &[(1, 3)]))
        else {
            panic!("a document without the suite gave a configuration");
        };
        let document = config_bytes(4, KEM_X25519, &[(1, 1)]);
        for cut in 1..document.len() {
            let Err(Error::KeyConfig(_)) = KeyConfig::select(&document[..cut]) else {
                panic!("a document cut at {cut} parsed");
            };
        }
        let Err(Error::KeyConfig(_)) = KeyConfig::select(&[]) else {
            panic!("an empty document gave a configuration");
        };
    }

    #[test]
    fn a_key_hpke_cannot_seal_to_is_refused() {
        let mut document = config_bytes(0, KEM_X25519, &[(1, 1)]); // all-zero key
        document.extend(usable_document());
        let Err(Error::KeyConfig(_)) = KeyConfig::select(&document) else {
            panic!("an all-zero key was selected");
        };
    }

    #[test]
    fn a_key_configuration_survives_its_byte_form() {
        let key = KeyConfig::select(&usable_document()).unwrap();
        let bytes = key.to_bytes();
        assert_eq!(bytes.len(), KEY_BYTES);
        assert_eq!(bytes[0], 4);
        assert_eq!(KeyConfig::from_bytes(&bytes), Some(key));
        assert_eq!(KeyConfig::from_bytes(&bytes[1..]), None);
        assert_eq!(KeyConfig::from_bytes(&[]), None);
        assert_eq!(KeyConfig::from_bytes(&[0; 34]), None);
    }

    #[test]
    fn a_selected_key_seals_a_chunked_request_with_its_key_id() {
        // The key id and the suite identifiers lead the sealed request; two sealings of the same
        // request differ (a fresh ephemeral key each time).
        let key = KeyConfig::select(&usable_document()).unwrap();
        let (sealed, _) = crate::chunked::encapsulate_chunked_request(&key, b"request").unwrap();
        assert_eq!(&sealed[..7], [4, 0, 0x20, 0, 1, 0, 1]);
        let (again, _) = crate::chunked::encapsulate_chunked_request(&key, b"request").unwrap();
        assert_ne!(sealed[7..], again[7..]);
    }

    /// Strict and lenient layouts, every shape of short entry: an error, never a read past the
    /// end (the Kotlin and Swift parsers read the key before checking the length).
    #[test]
    fn a_short_configuration_is_an_error_under_every_selection() {
        for selection in [
            KeySelection::LIBRARY,
            KeySelection::ANDROID,
            KeySelection::IOS,
            KeySelection::SLIPSTREAM,
        ] {
            // An entry that stops inside the public key, inside the suite length, and inside
            // the suite list, each behind a correct outer length.
            let full = {
                let mut config = vec![1u8, 0x00, 0x20];
                config.extend_from_slice(&[7; N_PK]);
                config.extend_from_slice(&[0, 4, 0, 1, 0, 1]);
                config
            };
            for cut in 0..full.len() {
                let mut document = (cut as u16).to_be_bytes().to_vec();
                document.extend_from_slice(&full[..cut]);
                let Err(Error::KeyConfig(_)) = KeyConfig::select_with(&document, &selection) else {
                    panic!("a configuration cut at {cut} selected under {selection:?}");
                };
            }
            // A suite length claiming more than the entry holds.
            let mut lying = full.clone();
            lying[3 + N_PK + 1] = 200;
            let mut document = (lying.len() as u16).to_be_bytes().to_vec();
            document.extend_from_slice(&lying);
            let Err(Error::KeyConfig(_)) = KeyConfig::select_with(&document, &selection) else {
                panic!("a lying suite length selected under {selection:?}");
            };
        }
    }

    #[test]
    fn a_document_of_too_many_configurations_is_refused_before_it_is_parsed() {
        // Four thousand and ninety-six configurations of another KEM, all skippable, then a
        // usable one: refused under the cap of 4096, selected under a cap of 5000.
        let mut document = Vec::new();
        for _ in 0..4096 {
            document.extend(config_bytes(1, 0x0010, &[(1, 1)]));
        }
        document.extend(usable_document());
        let Err(Error::KeyConfig(_)) = KeyConfig::select(&document) else {
            panic!("a document of 4097 configurations selected");
        };
        let lax = KeySelection {
            max_configs: 5000,
            ..KeySelection::LIBRARY
        };
        assert!(KeyConfig::select_with(&document, &lax).is_ok());
        // Every preset carries the cap.
        for selection in [
            KeySelection::LIBRARY,
            KeySelection::ANDROID,
            KeySelection::IOS,
            KeySelection::SLIPSTREAM,
        ] {
            assert_eq!(selection.max_configs, 4096);
        }
        // Empty configurations consume two bytes each and are counted, not looped on.
        let empties = vec![0u8; 2 * 10_000];
        assert!(KeyConfig::select(&empties).is_err());
    }
}

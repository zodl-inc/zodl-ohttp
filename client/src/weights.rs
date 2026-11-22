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

//! Relay weights: the shares of a network's relays, from a separately signed block that the
//! gateway's key-configuration envelope may carry (`relay_weights`, see `docs/relay-weights.md`).
//!
//! The application's configuration fixes the relays and their order; without a block each one
//! gets an equal share. A block can change the shares only: it holds one integer per position
//! of the application's list, with a fingerprint of that list ([`relay_set`]), and is signed
//! with a key of its own ([`crate::OhttpConfig::with_relay_weights_key`]), distinct from the
//! key-configuration signing key. A block that does not check out is ignored, and never affects
//! the envelope that carries it.
//!
//! An accepted block is held in memory only (nothing is persisted), per weights key and relay
//! list, and checked again at every use: once it expires the shares are equal again, whether
//! or not a new envelope was fetched.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, OnceLock};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::relays::Relay;
use crate::signed::{top_level_keys, Network, SignatureCheck, CLOCK_SKEW_SECS};

/// The domain separator of a block's signed message.
pub const RELAY_WEIGHTS_DOMAIN: &[u8] = b"zodl-ohttp-relay-weights-v1";
/// The longest validity (`not_after - not_before`) a block may claim: 30 days.
pub const MAX_RELAY_WEIGHTS_VALIDITY_SECS: u64 = 30 * 86_400;
/// The most bytes of a block's JSON text that are read.
pub const MAX_RELAY_WEIGHTS_BLOCK_BYTES: usize = 4096;
/// What a block's shares add up to.
pub const RELAY_WEIGHTS_TOTAL: u32 = 100;
/// The name of the block's field in the envelope.
pub const RELAY_WEIGHTS_FIELD: &str = "relay_weights";
/// An Ed25519 signature in base64, padded.
const MAX_SIG_BASE64_CHARS: usize = 88;
/// The block's fields, each required once.
const BLOCK_FIELDS: [&str; 10] = [
    "v",
    "network",
    "seq",
    "not_before",
    "not_after",
    "n",
    "set",
    "weights",
    "key_id",
    "sig",
];
/// The most weights keys and relay lists whose block is held at once.
const MAX_HELD_BLOCKS: usize = 16;

/// The time now, in Unix seconds (0 before 1970).
pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The fingerprint of an ordered list of canonical relay URLs (as
/// [`crate::OhttpConfig::relays`] keeps them): the first 8 bytes of SHA-256 over each URL
/// followed by one line feed (`\n`), in list order, as 16 lower-case hex digits.
pub fn relay_set<'a>(canonical_urls: impl IntoIterator<Item = &'a str>) -> String {
    hex::encode(relay_set_bytes(canonical_urls))
}

pub(crate) fn relay_set_bytes<'a>(canonical_urls: impl IntoIterator<Item = &'a str>) -> [u8; 8] {
    let mut hasher = Sha256::new();
    for url in canonical_urls {
        hasher.update(url.as_bytes());
        hasher.update(b"\n");
    }
    let digest = hasher.finalize();
    let mut set = [0u8; 8];
    set.copy_from_slice(&digest[..8]);
    set
}

/// Why a relay weights block was not taken. Names no value of the block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RelayWeightsIgnored {
    /// The configuration has no relay weights key: the block is not read at all.
    #[error("no relay weights key configured")]
    NoKey,
    /// The envelope carries no block.
    #[error("no relay weights block")]
    Absent,
    /// Over [`MAX_RELAY_WEIGHTS_BLOCK_BYTES`].
    #[error("relay weights block too large")]
    Oversized,
    /// Not a JSON object of the block's fields with their types, or a field repeated.
    #[error("relay weights block malformed")]
    Malformed,
    /// A field the block does not have.
    #[error("relay weights block has an unknown field")]
    UnknownField,
    /// A version other than 1.
    #[error("relay weights block of an unknown version")]
    Version,
    /// Signed for the other network.
    #[error("relay weights block for another network")]
    Network,
    /// `n` or the number of weights is not the number of relays configured.
    #[error("relay weights block for another number of relays")]
    Count,
    /// `set` is not the fingerprint of the configured relay list ([`relay_set`]).
    #[error("relay weights block for another relay list")]
    Set,
    /// A weight over 100, or weights that do not add up to 100.
    #[error("relay weights out of bounds")]
    Bounds,
    /// `not_before` not before `not_after`, or valid for more than 30 days.
    #[error("relay weights block valid for too long")]
    Validity,
    /// Not valid now (60 s of clock skew allowed on both ends).
    #[error("relay weights block expired or not yet valid")]
    Expired,
    /// `seq` more than 60 s ahead of the clock.
    #[error("relay weights block from the future")]
    SeqAhead,
    /// The signature does not check out under the configured key.
    #[error("relay weights block badly signed")]
    Signature,
    /// `seq` lower than that of the block held, or equal to it with another block id.
    #[error("relay weights block older than the one held")]
    Rollback,
    /// The process holds blocks (valid or expired: none is forgotten) for as many keys and
    /// relay lists as it keeps.
    #[error("relay weights blocks of too many configurations held")]
    StoreFull,
}

/// The block as it is written.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireBlock {
    v: u8,
    network: String,
    seq: u64,
    not_before: u64,
    not_after: u64,
    n: u8,
    set: String,
    weights: Vec<u8>,
    #[allow(dead_code)]
    key_id: String,
    sig: String,
}

/// A checked relay weights block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayWeights {
    seq: u64,
    not_before: u64,
    not_after: u64,
    weights: Vec<u8>,
    id: [u8; 32],
}

impl RelayWeights {
    /// The block id: SHA-256 of the signed message, 64 lower-case hex digits. What the public
    /// log and a diagnostics screen show.
    pub fn id(&self) -> String {
        hex::encode(self.id)
    }

    /// The block's sequence number (its signing time, in Unix seconds).
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// The start of its validity, Unix seconds.
    pub fn not_before(&self) -> u64 {
        self.not_before
    }

    /// The end of its validity, Unix seconds.
    pub fn not_after(&self) -> u64 {
        self.not_after
    }

    /// The share of each relay, in the order of the configured list; they add up to 100.
    pub fn weights(&self) -> Vec<u32> {
        self.weights.iter().map(|&w| u32::from(w)).collect()
    }

    /// Whether the block applies at `now` (Unix seconds): within its validity, 60 s of clock
    /// skew allowed on each end.
    pub fn valid_at(&self, now: u64) -> bool {
        now >= self.not_before.saturating_sub(CLOCK_SKEW_SECS)
            && now <= self.not_after.saturating_add(CLOCK_SKEW_SECS)
    }
}

/// The shares a network's relays get now ([`crate::OhttpConfig::relay_weights`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RelayWeightsStatus {
    /// The application's own shares: no valid block is held (none received, or the one held
    /// expired, or no relay weights key is configured).
    AppDefaults,
    /// The shares of a block.
    Block(RelayWeights),
}

/// The signed message of a block.
pub(crate) fn signed_message(
    network: &str,
    seq: u64,
    not_before: u64,
    not_after: u64,
    set: &[u8; 8],
    weights: &[u8],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(RELAY_WEIGHTS_DOMAIN.len() + network.len() + 36);
    message.extend_from_slice(RELAY_WEIGHTS_DOMAIN);
    message.push(0);
    message.extend_from_slice(network.as_bytes());
    message.push(0);
    message.extend_from_slice(&seq.to_be_bytes());
    message.extend_from_slice(&not_before.to_be_bytes());
    message.extend_from_slice(&not_after.to_be_bytes());
    // At most `MAX_RELAYS` (8) weights reach here.
    message.push(weights.len() as u8);
    message.extend_from_slice(set);
    message.extend_from_slice(weights);
    message
}

/// Checks the block `block` (its JSON text) for `network`, a list of `relay_count` relays whose
/// fingerprint is `set`, under the weights key `key`, at `now` (Unix seconds). The checks, in
/// order: size, JSON form (exactly the block's fields, each once, of their types), version,
/// network, number of relays, relay list, bounds, validity (at most 30 days, valid now), `seq`
/// at most 60 s ahead, signature. `key_id` is not checked.
pub(crate) fn check_block(
    block: &[u8],
    network: Network,
    key: &VerifyingKey,
    relay_count: usize,
    set: &[u8; 8],
    now: u64,
    signature: SignatureCheck,
) -> Result<RelayWeights, RelayWeightsIgnored> {
    use RelayWeightsIgnored as Ignored;
    if block.len() > MAX_RELAY_WEIGHTS_BLOCK_BYTES {
        return Err(Ignored::Oversized);
    }
    let keys = top_level_keys(block).map_err(|_| Ignored::Malformed)?;
    for (i, name) in keys.iter().enumerate() {
        if !BLOCK_FIELDS.contains(&name.as_str()) {
            return Err(Ignored::UnknownField);
        }
        if keys[..i].contains(name) {
            return Err(Ignored::Malformed);
        }
    }
    let wire: WireBlock = serde_json::from_slice(block).map_err(|_| Ignored::Malformed)?;
    if wire.v != 1 {
        return Err(Ignored::Version);
    }
    if wire.network != network.as_str() {
        return Err(Ignored::Network);
    }
    if usize::from(wire.n) != relay_count || wire.weights.len() != relay_count {
        return Err(Ignored::Count);
    }
    let lower_hex = wire.set.len() == 16
        && wire
            .set
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !lower_hex || hex::decode(&wire.set).ok().as_deref() != Some(&set[..]) {
        return Err(Ignored::Set);
    }
    let total: u32 = wire.weights.iter().map(|&w| u32::from(w)).sum();
    if wire
        .weights
        .iter()
        .any(|&w| u32::from(w) > RELAY_WEIGHTS_TOTAL)
        || total != RELAY_WEIGHTS_TOTAL
    {
        return Err(Ignored::Bounds);
    }
    if wire.not_before >= wire.not_after
        || wire.not_after - wire.not_before > MAX_RELAY_WEIGHTS_VALIDITY_SECS
    {
        return Err(Ignored::Validity);
    }
    let checked = RelayWeights {
        seq: wire.seq,
        not_before: wire.not_before,
        not_after: wire.not_after,
        weights: wire.weights,
        id: [0; 32],
    };
    if !checked.valid_at(now) {
        return Err(Ignored::Expired);
    }
    if wire.seq > now.saturating_add(CLOCK_SKEW_SECS) {
        return Err(Ignored::SeqAhead);
    }
    if wire.sig.len() > MAX_SIG_BASE64_CHARS {
        return Err(Ignored::Signature);
    }
    let sig = BASE64
        .decode(&wire.sig)
        .ok()
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .ok_or(Ignored::Signature)?;
    let message = signed_message(
        network.as_str(),
        checked.seq,
        checked.not_before,
        checked.not_after,
        set,
        &checked.weights,
    );
    match signature {
        SignatureCheck::Strict => key.verify_strict(&message, &sig),
        SignatureCheck::Standard => key.verify(&message, &sig),
    }
    .map_err(|_| Ignored::Signature)?;
    let mut id = [0u8; 32];
    id.copy_from_slice(&Sha256::digest(&message));
    Ok(RelayWeights { id, ..checked })
}

/// The block an envelope carries, as its JSON text: `Ok(None)` when it carries none,
/// `Err(Malformed)` when the envelope cannot be read for it (a repeated field included).
pub(crate) fn block_of_envelope(
    envelope: &[u8],
) -> Result<Option<&serde_json::value::RawValue>, RelayWeightsIgnored> {
    // Borrowed: nothing of the block is copied before its size is checked. An explicit
    // `null` is no block, as an absent field is.
    #[derive(Deserialize)]
    struct Carrier<'a> {
        #[serde(default, borrow)]
        relay_weights: Option<&'a serde_json::value::RawValue>,
    }
    serde_json::from_slice::<Carrier<'_>>(envelope)
        .map(|carrier| carrier.relay_weights)
        .map_err(|_| RelayWeightsIgnored::Malformed)
}

/// Checks the block the envelope `envelope` carries for `config` (the configuration of
/// `network`) and takes it into the process's store if it is valid at `now` and not older than
/// the one held. The envelope itself must already be checked. Without a relay weights key the
/// envelope is not read at all.
pub(crate) fn take_from_envelope(
    config: &crate::OhttpConfig,
    envelope: &[u8],
    network: Network,
    now: u64,
    signature: SignatureCheck,
) -> Result<RelayWeights, RelayWeightsIgnored> {
    let Some(key) = config.relay_weights_key() else {
        return Err(RelayWeightsIgnored::NoKey);
    };
    let block = block_of_envelope(envelope)?.ok_or(RelayWeightsIgnored::Absent)?;
    let set = config.relay_set_bytes();
    let checked = check_block(
        block.get().as_bytes(),
        network,
        key,
        config.relays().len(),
        &set,
        now,
        signature,
    )?;
    WeightsStore::global().offer(key, &set, checked.clone())?;
    Ok(checked)
}

/// Where a held block is filed: the weights key and the relay list's fingerprint.
type HeldKey = ([u8; 32], [u8; 8]);

/// The blocks a process holds, one per weights key and relay list; in memory only.
#[derive(Default)]
pub(crate) struct WeightsStore {
    held: Mutex<HashMap<HeldKey, RelayWeights>>,
}

impl WeightsStore {
    /// The store [`crate::OhttpConfig::choose_relay`] and the envelope checks share.
    pub(crate) fn global() -> &'static WeightsStore {
        static GLOBAL: OnceLock<WeightsStore> = OnceLock::new();
        GLOBAL.get_or_init(WeightsStore::default)
    }

    fn held(&self) -> MutexGuard<'_, HashMap<HeldKey, RelayWeights>> {
        // Nothing is left half-written under this lock, so a poisoned one is still usable.
        self.held.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Takes the checked block `block` for `key` and `set`, unless it is older than
    /// the one held: a lower `seq`, or the same `seq` with another id. The same block again
    /// changes nothing. With [`MAX_HELD_BLOCKS`] keys and lists held, a block for another one
    /// is refused: an entry is only ever replaced in place.
    pub(crate) fn offer(
        &self,
        key: &VerifyingKey,
        set: &[u8; 8],
        block: RelayWeights,
    ) -> Result<(), RelayWeightsIgnored> {
        let mut held = self.held();
        let at = (key.to_bytes(), *set);
        if let Some(current) = held.get(&at) {
            if block.seq < current.seq || (block.seq == current.seq && block.id != current.id) {
                return Err(RelayWeightsIgnored::Rollback);
            }
        }
        if !held.contains_key(&at) && held.len() >= MAX_HELD_BLOCKS {
            // Only a process with many configurations gets here. Nothing held is ever
            // forgotten, expired or not, so that no older block can come back (a lower `seq`
            // may well end later): the new one is refused.
            return Err(RelayWeightsIgnored::StoreFull);
        }
        held.insert(at, block);
        Ok(())
    }

    /// The block held for `key` and `set` that applies at `now`, if any.
    pub(crate) fn active(
        &self,
        key: &VerifyingKey,
        set: &[u8; 8],
        now: u64,
    ) -> Option<RelayWeights> {
        self.held()
            .get(&(key.to_bytes(), *set))
            .filter(|block| block.valid_at(now))
            .cloned()
    }
}

/// `relays` with the shares of `block` (in list order).
pub(crate) fn reweighted(relays: &[Relay], block: &RelayWeights) -> Vec<Relay> {
    relays
        .iter()
        .zip(&block.weights)
        .map(|(relay, &w)| relay.with_weight(u32::from(w)))
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::signed::SignedConfigPolicy;
    use crate::{OhttpConfig, OhttpConfigParams, OhttpNetworks};
    use ed25519_dalek::{Signer as _, SigningKey};

    /// `docs/relay-weights-test-vector.json`, as the crate ships it.
    pub(crate) const VECTOR: &str = include_str!("../testdata/relay-weights-test-vector.json");

    #[derive(Deserialize)]
    struct Vector {
        seed_hex: String,
        public_key_hex: String,
        key_id: String,
        relay_urls_as_written: Vec<String>,
        relay_urls_canonical: Vec<String>,
        set: String,
        network: String,
        seq: u64,
        not_before: u64,
        not_after: u64,
        weights: Vec<u8>,
        signed_message_hex: String,
        signature_base64: String,
        block_json: String,
        block_id: String,
        negative: Vec<Negative>,
    }

    #[derive(Deserialize)]
    struct Negative {
        name: String,
        block_json: String,
        now: u64,
        reason: String,
    }

    fn vector() -> Vector {
        serde_json::from_str(VECTOR).unwrap()
    }

    pub(crate) const A: &str = "https://relay-a.example/relay";
    pub(crate) const B: &str = "https://relay-b.example/gateway-path";
    const NOW: u64 = 1_767_225_600;

    /// A testnet configuration of the relays `relays` (a `relay_url` list) with the weights key
    /// of the seed `[weights_seed; 32]`.
    pub(crate) fn config_with(relays: &str, weights_seed: u8) -> OhttpConfig {
        OhttpConfig::new(OhttpConfigParams {
            gateway_host: "ohttp-gateway-testnet.example",
            relay_url: relays,
            keys_dns_name: "testnet.ohttp-keys.example",
            signing_pubkey: &crate::config::tests::key_hex(2),
        })
        .unwrap()
        .with_relay_weights_key(&crate::config::tests::key_hex(weights_seed))
        .unwrap()
    }

    /// The fields of a block, to sign and tamper with.
    #[derive(Clone)]
    pub(crate) struct Fields {
        pub(crate) v: serde_json::Value,
        pub(crate) network: serde_json::Value,
        pub(crate) seq: serde_json::Value,
        pub(crate) not_before: serde_json::Value,
        pub(crate) not_after: serde_json::Value,
        pub(crate) n: serde_json::Value,
        pub(crate) set: serde_json::Value,
        pub(crate) weights: serde_json::Value,
        pub(crate) key_id: serde_json::Value,
    }

    impl Fields {
        /// A block for `config` with `weights`, signed at `seq`, valid a week from `seq - 300`.
        pub(crate) fn new(config: &OhttpConfig, seq: u64, weights: &[u8]) -> Self {
            Fields {
                v: 1.into(),
                network: "testnet".into(),
                seq: seq.into(),
                not_before: (seq - 300).into(),
                not_after: (seq - 300 + 7 * 86_400).into(),
                n: config.relays().len().into(),
                set: config.relay_set().into(),
                weights: weights.to_vec().into(),
                key_id: "00000000".into(),
            }
        }

        /// The signed message of these fields, when each has its proper type.
        fn message(&self, domain: &[u8]) -> Vec<u8> {
            let set: [u8; 8] = hex::decode(self.set.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let weights: Vec<u8> = self
                .weights
                .as_array()
                .unwrap()
                .iter()
                .map(|w| w.as_u64().unwrap() as u8)
                .collect();
            let mut message = signed_message(
                self.network.as_str().unwrap(),
                self.seq.as_u64().unwrap(),
                self.not_before.as_u64().unwrap(),
                self.not_after.as_u64().unwrap(),
                &set,
                &weights,
            );
            message.splice(..RELAY_WEIGHTS_DOMAIN.len(), domain.iter().copied());
            message
        }

        /// The block JSON, signed with the seed `[seed; 32]` over these fields.
        pub(crate) fn signed(&self, seed: u8) -> Vec<u8> {
            self.signed_as(seed, RELAY_WEIGHTS_DOMAIN)
        }

        /// [`signed`](Self::signed) with `domain` as the domain separator.
        pub(crate) fn signed_as(&self, seed: u8, domain: &[u8]) -> Vec<u8> {
            let sig = SigningKey::from_bytes(&[seed; 32]).sign(&self.message(domain));
            self.with_sig(&BASE64.encode(sig.to_bytes()))
        }

        /// The block JSON with the signature `sig`.
        pub(crate) fn with_sig(&self, sig: &str) -> Vec<u8> {
            serde_json::json!({
                "v": self.v, "network": self.network, "seq": self.seq,
                "not_before": self.not_before, "not_after": self.not_after, "n": self.n,
                "set": self.set, "weights": self.weights, "key_id": self.key_id, "sig": sig,
            })
            .to_string()
            .into_bytes()
        }
    }

    fn check(
        config: &OhttpConfig,
        block: &[u8],
        now: u64,
    ) -> Result<RelayWeights, RelayWeightsIgnored> {
        check_block(
            block,
            Network::Testnet,
            config.relay_weights_key().unwrap(),
            config.relays().len(),
            &config.relay_set_bytes(),
            now,
            SignatureCheck::Strict,
        )
    }

    fn two() -> OhttpConfig {
        config_with(&format!("{A},{B}"), 9)
    }

    #[test]
    fn the_test_vector_checks_out() {
        let v = vector();
        // The set, from the URLs as written, through the configuration's canonical form.
        let written = v.relay_urls_as_written.join(",");
        let config = OhttpConfig::new(OhttpConfigParams {
            gateway_host: "ohttp-gateway-testnet.example",
            relay_url: &written,
            keys_dns_name: "testnet.ohttp-keys.example",
            signing_pubkey: &crate::config::tests::key_hex(2),
        })
        .unwrap()
        .with_relay_weights_key(&v.public_key_hex)
        .unwrap();
        let canonical: Vec<&str> = config.relays().iter().map(Relay::url).collect();
        assert_eq!(canonical, v.relay_urls_canonical);
        assert_eq!(config.relay_set(), v.set);
        assert_eq!(
            relay_set(v.relay_urls_canonical.iter().map(String::as_str)),
            v.set
        );
        // The key, the message, the signature and the id.
        let seed: [u8; 32] = hex::decode(&v.seed_hex).unwrap().try_into().unwrap();
        let key = SigningKey::from_bytes(&seed);
        assert_eq!(
            hex::encode(key.verifying_key().as_bytes()),
            v.public_key_hex
        );
        assert_eq!(
            hex::encode(&Sha256::digest(key.verifying_key().as_bytes())[..4]),
            v.key_id
        );
        let set: [u8; 8] = hex::decode(&v.set).unwrap().try_into().unwrap();
        let message = signed_message(
            &v.network,
            v.seq,
            v.not_before,
            v.not_after,
            &set,
            &v.weights,
        );
        assert_eq!(hex::encode(&message), v.signed_message_hex);
        assert_eq!(
            BASE64.encode(key.sign(&message).to_bytes()),
            v.signature_base64
        );
        let block = check(&config, v.block_json.as_bytes(), v.seq).unwrap();
        assert_eq!(block.id(), v.block_id);
        assert_eq!(hex::encode(Sha256::digest(&message)), v.block_id);
        assert_eq!(block.weights(), vec![70, 30]);
        assert_eq!(
            (block.seq(), block.not_before(), block.not_after()),
            (v.seq, v.not_before, v.not_after)
        );
        // Both signature checks take it.
        assert!(check_block(
            v.block_json.as_bytes(),
            Network::Testnet,
            config.relay_weights_key().unwrap(),
            2,
            &set,
            v.seq,
            SignatureCheck::Standard
        )
        .is_ok());
    }

    #[test]
    fn the_vectors_negative_blocks_are_ignored_for_their_reason() {
        let v = vector();
        let config = OhttpConfig::new(OhttpConfigParams {
            gateway_host: "ohttp-gateway-testnet.example",
            relay_url: &v.relay_urls_canonical.join(","),
            keys_dns_name: "testnet.ohttp-keys.example",
            signing_pubkey: &crate::config::tests::key_hex(2),
        })
        .unwrap()
        .with_relay_weights_key(&v.public_key_hex)
        .unwrap();
        assert_eq!(v.negative.len(), 12);
        for case in &v.negative {
            let why = check(&config, case.block_json.as_bytes(), case.now).unwrap_err();
            assert_eq!(format!("{why:?}"), case.reason, "{}", case.name);
            // The envelope that carries it still opens.
            let networks = OhttpNetworks::new(None, Some(config.clone())).unwrap();
            let envelope = with_block(case.block_json.as_bytes(), case.now);
            crate::verify_signed_config(
                &networks,
                &envelope,
                Network::Testnet,
                case.now,
                &SignedConfigPolicy::LIBRARY,
            )
            .unwrap();
        }
    }

    #[test]
    fn the_set_follows_the_canonical_rule() {
        let one = config_with(
            "https://relay-a.example/relay,https://relay-b.example/gateway-path",
            9,
        );
        for variant in [
            "https://RELAY-A.example:443/relay/,https://relay-b.example/gateway-path",
            "https://relay-a.example/x/../relay,https://Relay-B.Example/gateway-path/",
        ] {
            assert_eq!(
                config_with(variant, 9).relay_set(),
                one.relay_set(),
                "{variant}"
            );
        }
        // Another port, path, order or relay: another set.
        for other in [
            "https://relay-a.example:8443/relay,https://relay-b.example/gateway-path",
            "https://relay-a.example/Relay,https://relay-b.example/gateway-path",
            "https://relay-b.example/gateway-path,https://relay-a.example/relay",
            "https://relay-a.example/relay,https://relay-c.example/gateway-path",
            "https://relay-a.example/relay",
        ] {
            assert_ne!(
                config_with(other, 9).relay_set(),
                one.relay_set(),
                "{other}"
            );
        }
    }

    #[test]
    fn a_good_block_checks_out_and_100_0_is_accepted() {
        let config = two();
        for weights in [[50u8, 50], [100, 0], [0, 100], [1, 99]] {
            let block = Fields::new(&config, NOW, &weights).signed(9);
            let checked = check(&config, &block, NOW).unwrap();
            assert_eq!(checked.weights(), weights.map(u32::from).to_vec());
        }
    }

    #[test]
    fn every_signed_field_is_covered_but_key_id_is_not() {
        let config = two();
        let good = Fields::new(&config, NOW, &[70, 30]);
        let sig = {
            let block: serde_json::Value = serde_json::from_slice(&good.signed(9)).unwrap();
            block["sig"].as_str().unwrap().to_owned()
        };
        assert!(check(&config, &good.with_sig(&sig), NOW).is_ok());
        // key_id alone changed: still good.
        let mut other_id = good.clone();
        other_id.key_id = "ffffffff".into();
        assert!(check(&config, &other_id.with_sig(&sig), NOW).is_ok());
        // Every other field changed, the signature kept: refused (each for a reason of its
        // own where the change is checked before the signature).
        let mut cases: Vec<(Fields, RelayWeightsIgnored)> = Vec::new();
        let mut f = good.clone();
        f.seq = (NOW - 1).into();
        cases.push((f, RelayWeightsIgnored::Signature));
        let mut f = good.clone();
        f.not_before = (NOW - 301).into();
        cases.push((f, RelayWeightsIgnored::Signature));
        let mut f = good.clone();
        f.not_after = (NOW + 86_400).into();
        cases.push((f, RelayWeightsIgnored::Signature));
        let mut f = good.clone();
        f.weights = vec![71u8, 29].into();
        cases.push((f, RelayWeightsIgnored::Signature));
        let mut f = good.clone();
        f.network = "mainnet".into();
        cases.push((f, RelayWeightsIgnored::Network));
        let mut f = good.clone();
        f.n = 3.into();
        cases.push((f, RelayWeightsIgnored::Count));
        let mut f = good.clone();
        f.set = "0000000000000000".into();
        cases.push((f, RelayWeightsIgnored::Set));
        for (fields, why) in cases {
            assert_eq!(check(&config, &fields.with_sig(&sig), NOW), Err(why));
        }
        // A signature with one bit flipped.
        let mut sig_bytes = BASE64.decode(&sig).unwrap();
        sig_bytes[10] ^= 1;
        assert_eq!(
            check(&config, &good.with_sig(&BASE64.encode(&sig_bytes)), NOW),
            Err(RelayWeightsIgnored::Signature)
        );
    }

    #[test]
    fn keys_are_separate() {
        let config = two();
        let fields = Fields::new(&config, NOW, &[70, 30]);
        // The key-configuration signing key (seed 2) is not the weights key.
        assert_eq!(
            check(&config, &fields.signed(2), NOW),
            Err(RelayWeightsIgnored::Signature)
        );
        // The weights key over the envelope's domain string.
        assert_eq!(
            check(&config, &fields.signed_as(9, b"zodl-ohttp-configs-v1"), NOW),
            Err(RelayWeightsIgnored::Signature)
        );
        // The other network's weights key, signing for this network: refused here.
        assert_eq!(
            check(&config, &fields.signed(10), NOW),
            Err(RelayWeightsIgnored::Signature)
        );
        // A block signed for mainnet by this key is refused on testnet.
        let mut mainnet = fields.clone();
        mainnet.network = "mainnet".into();
        assert_eq!(
            check(&config, &mainnet.signed(9), NOW),
            Err(RelayWeightsIgnored::Network)
        );
    }

    #[test]
    fn a_block_for_another_list_is_ignored() {
        let config = two();
        let reordered = config_with(&format!("{B},{A}"), 9);
        let changed = config_with(&format!("{A},https://relay-c.example/gateway-path"), 9);
        let three = config_with(&format!("{A},{B},https://relay-c.example/x"), 9);
        // Signed for the list of another configuration.
        assert_eq!(
            check(
                &config,
                &Fields::new(&reordered, NOW, &[70, 30]).signed(9),
                NOW
            ),
            Err(RelayWeightsIgnored::Set)
        );
        assert_eq!(
            check(
                &config,
                &Fields::new(&changed, NOW, &[70, 30]).signed(9),
                NOW
            ),
            Err(RelayWeightsIgnored::Set)
        );
        assert_eq!(
            check(
                &config,
                &Fields::new(&three, NOW, &[40, 30, 30]).signed(9),
                NOW
            ),
            Err(RelayWeightsIgnored::Count)
        );
        // n right, weights of another length; and the other way round.
        let mut f = Fields::new(&config, NOW, &[70, 30]);
        f.weights = vec![40u8, 30, 30].into();
        assert_eq!(
            check(&config, &f.signed(9), NOW),
            Err(RelayWeightsIgnored::Count)
        );
        let mut f = Fields::new(&config, NOW, &[70, 30]);
        f.n = 3.into();
        assert_eq!(
            check(&config, &f.signed(9), NOW),
            Err(RelayWeightsIgnored::Count)
        );
        // The set as written is lower-case hex: an upper-case one, or one of another length,
        // is refused.
        for set in [
            config
                .relay_set()
                .replace(|c: char| c.is_ascii_digit(), "A"),
            config.relay_set()[..14].to_owned(),
            format!("{}00", config.relay_set()),
        ] {
            let mut f = Fields::new(&config, NOW, &[70, 30]);
            f.set = set.into();
            assert_eq!(
                check(&config, &f.with_sig("AAAA"), NOW),
                Err(RelayWeightsIgnored::Set)
            );
        }
    }

    #[test]
    fn weights_out_of_bounds_are_ignored() {
        let config = two();
        let base = Fields::new(&config, NOW, &[70, 30]);
        for weights in [
            serde_json::json!([70, 29]),
            serde_json::json!([70, 31]),
            serde_json::json!([101, 0]),
            serde_json::json!([0, 0]),
        ] {
            let mut f = base.clone();
            f.weights = weights.clone();
            assert_eq!(
                check(&config, &f.signed(9), NOW),
                Err(RelayWeightsIgnored::Bounds),
                "{weights}"
            );
        }
        for weights in [
            serde_json::json!([-1, 101]),
            serde_json::json!([50.5, 49.5]),
            serde_json::json!([50.0, 50]),
            serde_json::json!(["50", 50]),
            serde_json::json!([256, 0]),
            serde_json::json!(50),
        ] {
            let mut f = base.clone();
            f.weights = weights.clone();
            assert_eq!(
                check(&config, &f.with_sig("AAAA"), NOW),
                Err(RelayWeightsIgnored::Malformed),
                "{weights}"
            );
        }
    }

    #[test]
    fn freshness_is_checked() {
        let config = two();
        let f = Fields::new(&config, NOW, &[70, 30]);
        let block = f.signed(9);
        let not_after = NOW - 300 + 7 * 86_400;
        assert!(check(&config, &block, not_after + 60).is_ok());
        assert_eq!(
            check(&config, &block, not_after + 61),
            Err(RelayWeightsIgnored::Expired)
        );
        // Not yet valid: 60 s of skew before not_before.
        let mut later = f.clone();
        later.not_before = (NOW + 1_000).into();
        let later = later.signed(9);
        assert_eq!(
            check(&config, &later, NOW + 939),
            Err(RelayWeightsIgnored::Expired)
        );
        assert!(check(&config, &later, NOW + 940).is_ok());
        // Exactly 30 days is accepted, a second more is not.
        let mut long = f.clone();
        long.not_after = (NOW - 300 + MAX_RELAY_WEIGHTS_VALIDITY_SECS).into();
        assert!(check(&config, &long.signed(9), NOW).is_ok());
        long.not_after = (NOW - 300 + MAX_RELAY_WEIGHTS_VALIDITY_SECS + 1).into();
        assert_eq!(
            check(&config, &long.signed(9), NOW),
            Err(RelayWeightsIgnored::Validity)
        );
        let mut inverted = f.clone();
        inverted.not_after = (NOW - 300).into();
        assert_eq!(
            check(&config, &inverted.signed(9), NOW),
            Err(RelayWeightsIgnored::Validity)
        );
        // seq at most 60 s ahead.
        assert!(check(&config, &block, NOW - 60).is_ok());
        assert_eq!(
            check(&config, &block, NOW - 61),
            Err(RelayWeightsIgnored::SeqAhead)
        );
    }

    #[test]
    fn a_malformed_block_is_ignored() {
        let config = two();
        let good = Fields::new(&config, NOW, &[70, 30]).signed(9);
        let good_text = String::from_utf8(good.clone()).unwrap();
        let mut version = Fields::new(&config, NOW, &[70, 30]);
        version.v = 2.into();
        assert_eq!(
            check(&config, &version.signed(9), NOW),
            Err(RelayWeightsIgnored::Version)
        );
        let unknown = good_text.replacen('{', r#"{"extra":1,"#, 1);
        assert_eq!(
            check(&config, unknown.as_bytes(), NOW),
            Err(RelayWeightsIgnored::UnknownField)
        );
        let repeated = good_text.replacen('{', r#"{"v":1,"#, 1);
        assert_eq!(
            check(&config, repeated.as_bytes(), NOW),
            Err(RelayWeightsIgnored::Malformed)
        );
        let missing = good_text.replacen(r#""key_id":"00000000","#, "", 1);
        assert_eq!(
            check(&config, missing.as_bytes(), NOW),
            Err(RelayWeightsIgnored::Malformed)
        );
        for text in ["", "[]", "null", "\"x\"", "{", "{} {}"] {
            assert_eq!(
                check(&config, text.as_bytes(), NOW),
                Err(RelayWeightsIgnored::Malformed),
                "{text}"
            );
        }
        let padded = format!("{}{}", good_text, " ".repeat(MAX_RELAY_WEIGHTS_BLOCK_BYTES));
        assert_eq!(
            check(&config, padded.as_bytes(), NOW),
            Err(RelayWeightsIgnored::Oversized)
        );
        for sig in ["", "not base64!", "AAAA", &"A".repeat(200)] {
            let f = Fields::new(&config, NOW, &[70, 30]);
            assert_eq!(
                check(&config, &f.with_sig(sig), NOW),
                Err(RelayWeightsIgnored::Signature),
                "{sig}"
            );
        }
    }

    #[test]
    fn the_store_refuses_rollback_and_forgets_an_expired_block_at_use() {
        let store = WeightsStore::default();
        let config = two();
        let key = config.relay_weights_key().unwrap();
        let set = config.relay_set_bytes();
        let first = check(
            &config,
            &Fields::new(&config, NOW, &[70, 30]).signed(9),
            NOW,
        )
        .unwrap();
        store.offer(key, &set, first.clone()).unwrap();
        // The same block again: fine, nothing changes.
        store.offer(key, &set, first.clone()).unwrap();
        // Equal seq, another block: refused.
        let twin = check(
            &config,
            &Fields::new(&config, NOW, &[60, 40]).signed(9),
            NOW,
        )
        .unwrap();
        assert_eq!(
            store.offer(key, &set, twin),
            Err(RelayWeightsIgnored::Rollback)
        );
        // Lower seq: refused.
        let older = check(
            &config,
            &Fields::new(&config, NOW - 10, &[0, 100]).signed(9),
            NOW,
        )
        .unwrap();
        assert_eq!(
            store.offer(key, &set, older),
            Err(RelayWeightsIgnored::Rollback)
        );
        assert_eq!(store.active(key, &set, NOW), Some(first.clone()));
        // Higher seq: taken.
        let newer = check(
            &config,
            &Fields::new(&config, NOW + 10, &[100, 0]).signed(9),
            NOW + 10,
        )
        .unwrap();
        store.offer(key, &set, newer.clone()).unwrap();
        assert_eq!(store.active(key, &set, NOW + 10), Some(newer.clone()));
        // Expired at use time, no new offer needed; still remembered against rollback.
        assert_eq!(store.active(key, &set, newer.not_after() + 61), None);
        assert_eq!(
            store.offer(key, &set, first),
            Err(RelayWeightsIgnored::Rollback)
        );
        // Another list or key: nothing held.
        assert_eq!(store.active(key, &[0; 8], NOW + 10), None);
        let other = config_with(&format!("{A},{B}"), 10);
        assert_eq!(
            store.active(other.relay_weights_key().unwrap(), &set, NOW + 10),
            None
        );
    }

    #[test]
    fn two_stores_given_the_same_block_hold_the_same_state() {
        let config = two();
        let block = Fields::new(&config, NOW, &[70, 30]).signed(9);
        let (a, b) = (WeightsStore::default(), WeightsStore::default());
        for store in [&a, &b] {
            store
                .offer(
                    config.relay_weights_key().unwrap(),
                    &config.relay_set_bytes(),
                    check(&config, &block, NOW).unwrap(),
                )
                .unwrap();
        }
        assert_eq!(*a.held(), *b.held());
        assert_eq!(a.held().len(), 1);
    }

    /// A signed envelope for testnet under the key-configuration key of seed 2 (what
    /// `config_with` configures), carrying `extra` top-level text before its closing brace.
    pub(crate) fn envelope_with(extra: &str, now: u64) -> Vec<u8> {
        let key = SigningKey::from_bytes(&[2; 32]);
        let document = crate::encapsulation::tests::usable_document();
        let (not_before, not_after) = (now - 60, now + 3_600);
        let mut message = b"zodl-ohttp-configs-v1\0testnet\0".to_vec();
        message.extend_from_slice(&not_before.to_be_bytes());
        message.extend_from_slice(&not_after.to_be_bytes());
        message.extend_from_slice(&document);
        let envelope = serde_json::json!({
            "v": 1,
            "network": "testnet",
            "configs": BASE64.encode(&document),
            "not_before": not_before,
            "not_after": not_after,
            "key_id": hex::encode(&Sha256::digest(key.verifying_key().as_bytes())[..4]),
            "sig": BASE64.encode(key.sign(&message).to_bytes()),
        })
        .to_string();
        let mut text = envelope[..envelope.len() - 1].to_owned();
        text.push_str(extra);
        text.push('}');
        text.into_bytes()
    }

    fn with_block(block: &[u8], now: u64) -> Vec<u8> {
        envelope_with(
            &format!(",\"relay_weights\":{}", String::from_utf8_lossy(block)),
            now,
        )
    }

    #[test]
    fn an_envelope_with_a_block_opens_in_every_preset_and_a_repeated_block_is_refused() {
        let config = two();
        let networks = OhttpNetworks::new(None, Some(config.clone())).unwrap();
        let block = Fields::new(&config, NOW, &[70, 30]).signed(9);
        let now = NOW;
        let envelope = with_block(&block, now);
        let signer = SigningKey::from_bytes(&[2; 32]).verifying_key();
        for policy in [
            SignedConfigPolicy::LIBRARY,
            SignedConfigPolicy::ANDROID,
            SignedConfigPolicy::IOS,
            SignedConfigPolicy::SLIPSTREAM,
        ] {
            // A client that knows nothing of blocks (the signer only).
            crate::verify_signed_config_with(&envelope, "testnet", &signer, now, &policy).unwrap();
            crate::verify_signed_config(&networks, &envelope, Network::Testnet, now, &policy)
                .unwrap();
        }
        let twice = envelope_with(
            &format!(
                ",\"relay_weights\":{0},\"relay_weights\":{0}",
                String::from_utf8_lossy(&block)
            ),
            now,
        );
        assert!(crate::verify_signed_config_with(
            &twice,
            "testnet",
            &signer,
            now,
            &SignedConfigPolicy::LIBRARY
        )
        .is_err());
        assert!(crate::verify_signed_config(
            &networks,
            &twice,
            Network::Testnet,
            now,
            &SignedConfigPolicy::LIBRARY
        )
        .is_err());
    }

    #[test]
    fn a_bad_block_never_breaks_the_envelope() {
        let now = NOW;
        let config = config_with(&format!("{A},{B}"), 11);
        let networks = OhttpNetworks::new(None, Some(config.clone())).unwrap();
        let good = Fields::new(&config, now, &[70, 30]);
        let mut bad_version = good.clone();
        bad_version.v = 2.into();
        // The signature of other weights: a bad signature for these.
        let other = Fields::new(&config, NOW, &[60, 40]).signed(11);
        let other: serde_json::Value = serde_json::from_slice(&other).unwrap();
        let sig = good.with_sig(other["sig"].as_str().unwrap());
        let oversized = format!("\"{}\"", "x".repeat(MAX_RELAY_WEIGHTS_BLOCK_BYTES + 10));
        let unknown = String::from_utf8(good.signed(11))
            .unwrap()
            .replacen('{', r#"{"x":1,"#, 1);
        for block in [
            sig,
            bad_version.signed(11),
            unknown.into_bytes(),
            b"[1,2]".to_vec(),
            b"\"text\"".to_vec(),
            b"null".to_vec(),
            oversized.into_bytes(),
        ] {
            let envelope = with_block(&block, now);
            let keys = crate::verify_signed_config(
                &networks,
                &envelope,
                Network::Testnet,
                now,
                &SignedConfigPolicy::LIBRARY,
            )
            .unwrap();
            assert!(!keys.document.is_empty());
            assert_eq!(
                config.relay_weights_at(now),
                RelayWeightsStatus::AppDefaults
            );
        }
    }

    #[test]
    fn with_no_weights_key_the_block_is_never_read() {
        let now = NOW;
        let keyed = config_with(&format!("{A},{B}"), 12);
        let plain = OhttpConfig::new(OhttpConfigParams {
            gateway_host: "ohttp-gateway-testnet.example",
            relay_url: &format!("{A},{B}"),
            keys_dns_name: "testnet.ohttp-keys.example",
            signing_pubkey: &crate::config::tests::key_hex(2),
        })
        .unwrap();
        let block = Fields::new(&keyed, now, &[100, 0]).signed(12);
        assert_eq!(
            crate::weights::take_from_envelope(
                &plain,
                &with_block(&block, now),
                Network::Testnet,
                now,
                SignatureCheck::Strict
            ),
            Err(RelayWeightsIgnored::NoKey)
        );
        assert_eq!(plain.relay_weights_at(now), RelayWeightsStatus::AppDefaults);
        assert!(plain.relay_weights_key().is_none());
    }

    #[test]
    fn an_old_valid_block_in_a_new_envelope_follows_its_own_rules() {
        // The block's validity is its own: a fresh envelope does not extend it, an expired
        // envelope is not needed to end it.
        let now = NOW;
        let config = config_with(&format!("{A},{B}"), 13);
        let mut old = Fields::new(&config, now - 2 * 86_400, &[100, 0]);
        old.not_before = (now - 2 * 86_400 - 300).into();
        old.not_after = (now + 3_000).into();
        let envelope = with_block(&old.signed(13), now);
        let networks = OhttpNetworks::new(None, Some(config.clone())).unwrap();
        crate::verify_signed_config(
            &networks,
            &envelope,
            Network::Testnet,
            now,
            &SignedConfigPolicy::LIBRARY,
        )
        .unwrap();
        let RelayWeightsStatus::Block(held) = config.relay_weights_at(now) else {
            panic!("the block was not taken");
        };
        assert_eq!(held.weights(), vec![100, 0]);
        assert_eq!(
            config.relay_weights_at(now + 3_000 + 61),
            RelayWeightsStatus::AppDefaults
        );
    }

    #[test]
    fn the_dns_source_gives_the_same_result_as_a_relay() {
        let now = NOW;
        let config = OhttpConfig::new(OhttpConfigParams {
            gateway_host: "ohttp-gateway-testnet.example",
            relay_url: &format!("{A},{B}"),
            keys_dns_name: "testnet.ohttp-keys.example",
            signing_pubkey: &crate::config::tests::key_hex(2),
        })
        .unwrap()
        .with_relay_weights_key(&crate::config::tests::key_hex(14))
        .unwrap();
        let networks = OhttpNetworks::new(None, Some(config.clone())).unwrap();
        let envelope = with_block(&Fields::new(&config, now, &[30, 70]).signed(14), now);
        let b64 = BASE64.encode(&envelope);
        let data: Vec<String> = b64
            .as_bytes()
            .chunks(255)
            .map(|c| format!("\\\"{}\\\"", std::str::from_utf8(c).unwrap()))
            .collect();
        let doh = format!(
            r#"{{"Status":0,"Answer":[{{"name":"testnet.ohttp-keys.example.","type":16,"TTL":300,"data":"{}"}}]}}"#,
            data.join(" ")
        );
        let from_dns =
            crate::envelope_from_doh_json(&networks, doh.as_bytes(), Network::Testnet).unwrap();
        assert_eq!(from_dns, envelope);
        crate::verify_signed_config(
            &networks,
            &from_dns,
            Network::Testnet,
            now,
            &SignedConfigPolicy::LIBRARY,
        )
        .unwrap();
        let RelayWeightsStatus::Block(held) = config.relay_weights_at(now) else {
            panic!("the block from DNS was not taken");
        };
        assert_eq!(held.weights(), vec![30, 70]);
    }

    #[test]
    fn choices_follow_the_block_and_a_relay_of_weight_zero_is_only_a_fallback() {
        use crate::{RelayBackoff, RelaySelector};
        use std::time::Instant;
        let config = config_with(&format!("{A},{B}"), 15);
        let block = Fields::new(&config, NOW, &[70, 30]).signed(15);
        take_from_envelope(
            &config,
            &with_block(&block, NOW),
            Network::Testnet,
            NOW,
            SignatureCheck::Strict,
        )
        .unwrap();
        let relays = config.weighted_relays_at(NOW);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let now = Instant::now();
        // The draw's point is floor(draw * 100 / 2^64): below 70 the first relay, from 70 the
        // second. 0.7 * 2^64 rounded up is the first draw of the second relay.
        let boundary: u64 = 12_912_720_851_596_686_132;
        assert_eq!(selector.choose_with(&relays, 0, now, &backoff), 0);
        assert_eq!(
            selector.choose_with(&relays, boundary - 1, now, &backoff),
            0
        );
        assert_eq!(selector.choose_with(&relays, boundary, now, &backoff), 1);
        assert_eq!(selector.choose_with(&relays, u64::MAX, now, &backoff), 1);
        // The same draw gives the same relay whatever came before: picks are independent.
        for draw in [boundary - 1, boundary, 5, u64::MAX - 5] {
            let first = selector.choose_with(&relays, draw, now, &backoff);
            for _ in 0..3 {
                selector.choose_with(&relays, draw ^ 0x5555, now, &backoff);
                assert_eq!(selector.choose_with(&relays, draw, now, &backoff), first);
            }
        }
        // Without a block (another key, nothing held): equal shares, the boundary at 2^63.
        let plain = config_with(&format!("{A},{B}"), 16);
        let equal = plain.weighted_relays_at(NOW);
        assert_eq!(
            selector.choose_with(&equal, (1 << 63) - 1, now, &backoff),
            0
        );
        assert_eq!(selector.choose_with(&equal, 1 << 63, now, &backoff), 1);
        // Once the block expires, the shares are equal again.
        let after = NOW - 300 + 7 * 86_400 + 61;
        assert!(matches!(
            config.relay_weights_at(after),
            RelayWeightsStatus::AppDefaults
        ));
        let expired = config.weighted_relays_at(after);
        assert_eq!(
            selector.choose_with(&expired, (1 << 63) - 1, now, &backoff),
            0
        );
        assert_eq!(selector.choose_with(&expired, 1 << 63, now, &backoff), 1);

        // 100/0: the second relay is never drawn, only taken over to.
        let config = config_with(&format!("{A},{B}"), 17);
        let block = Fields::new(&config, NOW, &[100, 0]).signed(17);
        take_from_envelope(
            &config,
            &with_block(&block, NOW),
            Network::Testnet,
            NOW,
            SignatureCheck::Strict,
        )
        .unwrap();
        let relays = config.weighted_relays_at(NOW);
        let selector = RelaySelector::new();
        for draw in [0, boundary, 1 << 63, u64::MAX] {
            assert_eq!(selector.choose_with(&relays, draw, now, &backoff), 0);
        }
        selector.note_failure_at(A, now);
        for draw in [0, u64::MAX] {
            assert_eq!(selector.choose_with(&relays, draw, now, &backoff), 1);
        }
        // The fallback stays in the list.
        assert_eq!(
            selector.alternative_with(&relays, 1, now, &backoff),
            Some(0)
        );
    }

    #[test]
    fn a_full_store_never_forgets_a_valid_block() {
        let store = WeightsStore::default();
        let blocks: Vec<(OhttpConfig, RelayWeights)> = (0..MAX_HELD_BLOCKS)
            .map(|i| {
                let config = config_with(&format!("{A},https://relay-{i}.example/relay"), 9);
                let block = check(
                    &config,
                    &Fields::new(&config, NOW, &[50, 50]).signed(9),
                    NOW,
                )
                .unwrap();
                (config, block)
            })
            .collect();
        for (config, block) in &blocks {
            store
                .offer(
                    config.relay_weights_key().unwrap(),
                    &config.relay_set_bytes(),
                    block.clone(),
                )
                .unwrap();
        }
        let extra = config_with(&format!("{A},https://relay-extra.example/relay"), 9);
        let block = check(&extra, &Fields::new(&extra, NOW, &[50, 50]).signed(9), NOW).unwrap();
        let key = extra.relay_weights_key().unwrap();
        assert_eq!(
            store.offer(key, &extra.relay_set_bytes(), block.clone()),
            Err(RelayWeightsIgnored::StoreFull)
        );
        // Every block held still refuses an older one.
        let (config, _) = &blocks[0];
        let older = check(
            config,
            &Fields::new(config, NOW - 5, &[0, 100]).signed(9),
            NOW,
        )
        .unwrap();
        assert_eq!(
            store.offer(key, &config.relay_set_bytes(), older),
            Err(RelayWeightsIgnored::Rollback)
        );
        // Not even once they have expired: a lower seq may end later than a higher one.
        let later = NOW - 300 + 7 * 86_400 + 61;
        let fresh = check(
            &extra,
            &Fields::new(&extra, later, &[50, 50]).signed(9),
            later,
        )
        .unwrap();
        assert_eq!(
            store.offer(key, &extra.relay_set_bytes(), fresh),
            Err(RelayWeightsIgnored::StoreFull)
        );
        // A long-lived lower seq is still refused after a short-lived higher one expired.
        let (config, _) = &blocks[1];
        let mut short = Fields::new(config, NOW + 10, &[50, 50]);
        short.not_after = (NOW + 3_600).into();
        let short = check(config, &short.signed(9), NOW + 10).unwrap();
        store.offer(key, &config.relay_set_bytes(), short).unwrap();
        let mut long = Fields::new(config, NOW + 5, &[0, 100]);
        long.not_after = (NOW + 20 * 86_400).into();
        let long = check(config, &long.signed(9), NOW + 7_200).unwrap();
        assert_eq!(
            store.offer(key, &config.relay_set_bytes(), long),
            Err(RelayWeightsIgnored::Rollback)
        );
    }

    #[test]
    fn rollback_is_refused_across_envelopes() {
        let config = config_with(&format!("{A},{B}"), 18);
        let newer = Fields::new(&config, NOW, &[100, 0]).signed(18);
        let older = Fields::new(&config, NOW - 100, &[0, 100]).signed(18);
        take_from_envelope(
            &config,
            &with_block(&newer, NOW),
            Network::Testnet,
            NOW,
            SignatureCheck::Strict,
        )
        .unwrap();
        assert_eq!(
            take_from_envelope(
                &config,
                &with_block(&older, NOW),
                Network::Testnet,
                NOW,
                SignatureCheck::Strict
            ),
            Err(RelayWeightsIgnored::Rollback)
        );
        // An envelope without a block, or with a bad one, leaves the block held in force.
        assert_eq!(
            take_from_envelope(
                &config,
                &envelope_with("", NOW),
                Network::Testnet,
                NOW,
                SignatureCheck::Strict
            ),
            Err(RelayWeightsIgnored::Absent)
        );
        assert_eq!(
            take_from_envelope(
                &config,
                &envelope_with(",\"relay_weights\":null", NOW),
                Network::Testnet,
                NOW,
                SignatureCheck::Strict
            ),
            Err(RelayWeightsIgnored::Absent)
        );
        let RelayWeightsStatus::Block(held) = config.relay_weights_at(NOW) else {
            panic!("the block held was dropped");
        };
        assert_eq!(held.weights(), vec![100, 0]);
    }

    #[test]
    fn a_valid_block_in_an_envelope_that_does_not_check_out_is_not_taken() {
        let config = config_with(&format!("{A},{B}"), 19);
        let networks = OhttpNetworks::new(None, Some(config.clone())).unwrap();
        let block = Fields::new(&config, NOW, &[100, 0]).signed(19);
        let mut envelope = with_block(&block, NOW);
        // Another network named: the envelope fails, the block is never looked at.
        let text = String::from_utf8(envelope.clone()).unwrap().replacen(
            "\"network\":\"testnet\"",
            "\"network\":\"mainnet\"",
            1,
        );
        envelope = text.into_bytes();
        assert!(crate::verify_signed_config(
            &networks,
            &envelope,
            Network::Testnet,
            NOW,
            &SignedConfigPolicy::LIBRARY
        )
        .is_err());
        assert_eq!(
            config.relay_weights_at(NOW),
            RelayWeightsStatus::AppDefaults
        );
    }

    #[test]
    fn a_tampered_signature_fails_the_standard_check_too() {
        let config = two();
        let good = Fields::new(&config, NOW, &[70, 30]);
        let block: serde_json::Value = serde_json::from_slice(&good.signed(9)).unwrap();
        let mut sig = BASE64.decode(block["sig"].as_str().unwrap()).unwrap();
        sig[40] ^= 0x80;
        let tampered = good.with_sig(&BASE64.encode(&sig));
        for signature in [SignatureCheck::Strict, SignatureCheck::Standard] {
            assert_eq!(
                check_block(
                    &tampered,
                    Network::Testnet,
                    config.relay_weights_key().unwrap(),
                    2,
                    &config.relay_set_bytes(),
                    NOW,
                    signature
                ),
                Err(RelayWeightsIgnored::Signature)
            );
        }
    }

    #[test]
    fn three_relays_fail_over_by_weight_and_zero_stays_last() {
        use crate::{RelayBackoff, RelaySelector};
        use std::time::Instant;
        let c = "https://relay-c.example/relay";
        let config = config_with(&format!("{A},{B},{c}"), 20);
        let block = Fields::new(&config, NOW, &[10, 0, 90]).signed(20);
        take_from_envelope(
            &config,
            &with_block(&block, NOW),
            Network::Testnet,
            NOW,
            SignatureCheck::Strict,
        )
        .unwrap();
        let relays = config.weighted_relays_at(NOW);
        let selector = RelaySelector::new();
        let backoff = RelayBackoff::new();
        let now = Instant::now();
        // Draws: below 0.1 the first relay, above it the third; never the second.
        assert_eq!(selector.choose_with(&relays, 0, now, &backoff), 0);
        assert_eq!(
            selector.choose_with(&relays, u64::MAX / 2, now, &backoff),
            2
        );
        assert_eq!(selector.choose_with(&relays, u64::MAX, now, &backoff), 2);
        // The third held: its draws go to the first (weight 10), not to the weight-0 relay.
        selector.note_failure_at(c, now);
        assert_eq!(selector.choose_with(&relays, u64::MAX, now, &backoff), 0);
        // The first held too: only then the weight-0 relay.
        selector.note_failure_at(A, now);
        assert_eq!(selector.choose_with(&relays, u64::MAX, now, &backoff), 1);
        // Through the networks' choice with a criterion: a weight-0 relay alone eligible is taken.
        // On the system clock, so a block signed now.
        let live = config_with(&format!("{A},{B},{c}"), 25);
        let now_unix = unix_now();
        let block = Fields::new(&live, now_unix, &[10, 0, 90]).signed(25);
        take_from_envelope(
            &live,
            &with_block(&block, now_unix),
            Network::Testnet,
            now_unix,
            SignatureCheck::Strict,
        )
        .unwrap();
        assert!(matches!(live.relay_weights(), RelayWeightsStatus::Block(_)));
        let networks = OhttpNetworks::new(None, Some(live)).unwrap();
        let (url, _) = networks
            .choose_relay_for_where("ohttp-gateway-testnet.example", |url| url == B)
            .unwrap();
        assert_eq!(url, B);
        // The first and the weight-0 relay eligible: always the first (equal shares would
        // give the second half the time).
        for _ in 0..64 {
            let (url, _) = networks
                .choose_relay_for_where("ohttp-gateway-testnet.example", |url| url != c)
                .unwrap();
            assert_eq!(url, A);
        }
        assert!(networks
            .choose_relay_for_where("ohttp-gateway-testnet.example", |url| url != A
                && url != B
                && url != c)
            .is_none());
    }

    #[test]
    fn a_rejecting_policy_still_takes_an_envelope_with_a_block() {
        use crate::signed::UnknownFields;
        let config = config_with(&format!("{A},{B}"), 21);
        let networks = OhttpNetworks::new(None, Some(config.clone())).unwrap();
        let envelope = with_block(&Fields::new(&config, NOW, &[30, 70]).signed(21), NOW);
        let strict = SignedConfigPolicy {
            unknown_fields: UnknownFields::Reject,
            ..SignedConfigPolicy::LIBRARY
        };
        crate::verify_signed_config(&networks, &envelope, Network::Testnet, NOW, &strict).unwrap();
        let RelayWeightsStatus::Block(held) = config.relay_weights_at(NOW) else {
            panic!("the block was not taken");
        };
        assert_eq!(held.weights(), vec![30, 70]);
    }

    #[test]
    fn an_empty_key_clears_the_relay_weights_key() {
        let config = config_with(&format!("{A},{B}"), 22);
        assert!(config.relay_weights_key().is_some());
        assert!(config
            .with_relay_weights_key("")
            .unwrap()
            .relay_weights_key()
            .is_none());
    }

    #[test]
    fn a_weights_key_is_one_networks_alone() {
        let mainnet = |weights_seed: u8| {
            OhttpConfig::new(OhttpConfigParams {
                gateway_host: "ohttp-gateway.example",
                relay_url: "https://relay-mainnet.example/relay",
                keys_dns_name: "mainnet.ohttp-keys.example",
                signing_pubkey: &crate::config::tests::key_hex(1),
            })
            .unwrap()
            .with_relay_weights_key(&crate::config::tests::key_hex(weights_seed))
            .unwrap()
        };
        let testnet = config_with(&format!("{A},{B}"), 23);
        // Testnet's weights key (23), or testnet's signing key (2), as mainnet's weights key.
        for seed in [23, 2] {
            assert_eq!(
                OhttpNetworks::new(Some(mainnet(seed)), Some(testnet.clone())),
                Err(crate::ConfigError::SharedAcrossNetworks {
                    field: crate::ConfigField::SigningPubkey
                })
            );
        }
        assert!(OhttpNetworks::new(Some(mainnet(24)), Some(testnet)).is_ok());
    }
}

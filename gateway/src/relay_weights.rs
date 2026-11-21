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

//! The relay weights block the signed key-configuration envelope carries (`relay_weights`,
//! `docs/relay-weights.md`), served from a file as it is: the gateway never signs, parses beyond
//! "one JSON object" or edits it. The block is signed by someone else, with a key the gateway
//! does not hold; clients check it.
//!
//! The file (`relay_weights_file`) is read once at startup and then every [`REREAD_INTERVAL`]
//! by a background task, so a new block is served without a restart and no request ever waits
//! for the file. A missing (or empty) file means no block. A file that is not one JSON object
//! of at most [`MAX_BLOCK_BYTES`] bytes is not served (logged, counted). A read that fails or
//! takes longer than [`READ_TIMEOUT`] keeps what was read before. Replace the file by renaming
//! a new one over it, so that no read sees half of it.

use std::io::Read as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde_json::value::RawValue;
use tracing::{info, warn};

/// How often the file is read again.
pub const REREAD_INTERVAL: Duration = Duration::from_secs(10);
/// How long one read of the file may take.
pub const READ_TIMEOUT: Duration = Duration::from_secs(2);
/// The most bytes of a block that are served (what clients read, too).
pub const MAX_BLOCK_BYTES: usize = 4096;
/// The most bytes of the file that are read: a block and some whitespace around it.
const MAX_FILE_BYTES: u64 = 2 * MAX_BLOCK_BYTES as u64;

/// What the file holds, as last read.
#[derive(Clone, Debug)]
pub enum BlockFile {
    /// No file.
    Absent,
    /// A block to serve.
    Block(Box<RawValue>),
    /// A file that is no block (not served).
    Invalid(&'static str),
}

impl PartialEq for BlockFile {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (BlockFile::Absent, BlockFile::Absent) => true,
            (BlockFile::Block(a), BlockFile::Block(b)) => a.get() == b.get(),
            (BlockFile::Invalid(a), BlockFile::Invalid(b)) => a == b,
            _ => false,
        }
    }
}

/// The block file and what was last read from it.
pub struct RelayWeightsFile {
    path: PathBuf,
    network: String,
    /// `None` until the first read.
    last: Mutex<Option<BlockFile>>,
    /// One read at a time.
    reading: tokio::sync::Mutex<()>,
    /// A blocking read still running (one that outlived [`READ_TIMEOUT`]): no other is started
    /// until it ends, so a stalled file costs one thread at most.
    in_flight: Arc<std::sync::atomic::AtomicBool>,
}

impl RelayWeightsFile {
    /// The block file at `path`, for the logs and metrics of `network`. Nothing is read yet.
    pub fn new(path: impl Into<PathBuf>, network: impl Into<String>) -> Self {
        RelayWeightsFile {
            path: path.into(),
            network: network.into(),
            last: Mutex::new(None),
            reading: tokio::sync::Mutex::new(()),
            in_flight: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Reads the file now, and then every [`REREAD_INTERVAL`] in a background task for as long
    /// as the returned value (or a clone of it) lives elsewhere.
    pub async fn start(self) -> Arc<Self> {
        let file = Arc::new(self);
        file.refresh().await;
        let weak = Arc::downgrade(&file);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(REREAD_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await;
            loop {
                tick.tick().await;
                let Some(file) = weak.upgrade() else { return };
                file.refresh().await;
            }
        });
        file
    }

    /// The block to serve now, if any: the file as last read. Never reads the file.
    pub fn current(&self) -> Option<Box<RawValue>> {
        match &*self.last.lock() {
            Some(BlockFile::Block(block)) => Some(block.clone()),
            _ => None,
        }
    }

    /// Reads the file and keeps what it holds; a read that fails or times out keeps the
    /// previous state. One read at a time: a refresh asked for while one runs waits for it,
    /// and one asked for while an earlier read is still stalled past [`READ_TIMEOUT`] is
    /// skipped.
    pub async fn refresh(&self) {
        use std::sync::atomic::Ordering;
        let _reading = self.reading.lock().await;
        // The previous read has not ended (a stalled file): skip this one.
        if self.in_flight.swap(true, Ordering::AcqRel) {
            return;
        }
        let path = self.path.clone();
        // Released when the read ends, however it ends (a panic, or a task dropped unstarted).
        let release = scopeguard::guard(self.in_flight.clone(), |flag| {
            flag.store(false, Ordering::Release)
        });
        let read = tokio::time::timeout(
            READ_TIMEOUT,
            tokio::task::spawn_blocking(move || {
                let _release = release;
                read_block(&path)
            }),
        )
        .await;
        let read = match read {
            Ok(Ok(Some(read))) => read,
            // An I/O error, a stall, or a read task that did not finish: keep what was read.
            Ok(Ok(None)) | Ok(Err(_)) | Err(_) => {
                if self.last.lock().is_none() {
                    warn!(
                        network = self.network.as_str(),
                        "relay weights: the block file could not be read"
                    );
                    *self.last.lock() = Some(BlockFile::Invalid("unreadable"));
                    crate::health::record_relay_weights(&self.network, "invalid");
                }
                return;
            }
        };
        let changed = self.last.lock().as_ref() != Some(&read);
        if changed {
            self.report(&read);
            *self.last.lock() = Some(read);
        }
    }

    /// Logs and records a change of what the file holds (the block itself is public, but it
    /// is not logged: its id is what the log and the clients show).
    fn report(&self, read: &BlockFile) {
        let network = self.network.as_str();
        match read {
            BlockFile::Absent => {
                info!(network, "relay weights: no block file, none served");
                crate::health::record_relay_weights(network, "absent");
                crate::health::record_relay_weights_not_after(network, 0);
            }
            BlockFile::Block(block) => {
                info!(
                    network,
                    bytes = block.get().len(),
                    "relay weights: serving the block file"
                );
                crate::health::record_relay_weights(network, "served");
                crate::health::record_relay_weights_not_after(network, not_after_of(block));
            }
            BlockFile::Invalid(why) => {
                warn!(network, why, "relay weights: the block file is not served");
                crate::health::record_relay_weights(network, "invalid");
                crate::health::record_relay_weights_not_after(network, 0);
            }
        }
    }
}

/// The `not_after` a block names, for the metric only (nothing is checked; 0 without one).
fn not_after_of(block: &RawValue) -> u64 {
    #[derive(serde::Deserialize)]
    struct NotAfter {
        #[serde(default)]
        not_after: u64,
    }
    serde_json::from_str::<NotAfter>(block.get()).map_or(0, |b| b.not_after)
}

/// What the file at `path` holds; `None` when it cannot be read (an I/O error other than "not
/// found"). Only a regular file is read, and at most [`MAX_FILE_BYTES`] of it.
fn read_block(path: &std::path::Path) -> Option<BlockFile> {
    // Checked before opening: opening a FIFO would block.
    match std::fs::metadata(path) {
        Ok(meta) if !meta.is_file() => return Some(BlockFile::Invalid("not a regular file")),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(BlockFile::Absent),
        Err(_) => return None,
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // Never wait in `open` should the path become a FIFO between the two checks.
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(BlockFile::Absent),
        Err(_) => return None,
    };
    match file.metadata() {
        Ok(meta) if !meta.is_file() => return Some(BlockFile::Invalid("not a regular file")),
        Ok(_) => {}
        Err(_) => return None,
    }
    let mut bytes = Vec::new();
    if file
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return None;
    }
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Some(BlockFile::Invalid("larger than 4096 bytes"));
    }
    Some(parse_block(&bytes))
}

/// `bytes` as a block to serve: one JSON object, at most [`MAX_BLOCK_BYTES`] bytes once leading
/// and trailing ASCII whitespace (a file's final newline) is removed, served exactly as it is
/// in between. An empty file is no block.
pub fn parse_block(bytes: &[u8]) -> BlockFile {
    let text = bytes.trim_ascii();
    if text.is_empty() {
        return BlockFile::Absent;
    }
    if text.len() > MAX_BLOCK_BYTES {
        return BlockFile::Invalid("larger than 4096 bytes");
    }
    let Ok(text) = std::str::from_utf8(text) else {
        return BlockFile::Invalid("not UTF-8");
    };
    if !text.starts_with('{') {
        return BlockFile::Invalid("not a JSON object");
    }
    // `RawValue` keeps the text as written, once it is checked to be exactly one JSON value
    // (the test above makes it an object).
    match RawValue::from_string(text.to_owned()) {
        Ok(block) => BlockFile::Block(block),
        Err(_) => BlockFile::Invalid("not one JSON object"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCK: &str = r#"{"v":1,"network":"testnet","seq":1767225600,"not_before":1767225300,"not_after":1769817300,"n":2,"set":"377f979ac611fd84","weights":[70,30],"key_id":"6c8f8607","sig":"16NrlaikzHWg1hF9VcLm7gCq2FfA9bgkz1qIq+vhbUnxQnJxrt5T5eG3tK8CXtzM4Gdwz4lFiMZfSmdheFtrDg=="}"#;

    #[test]
    fn a_block_is_kept_byte_for_byte() {
        for spelling in [
            BLOCK.to_owned(),
            format!("{BLOCK}\n"),
            format!(" \r\n{BLOCK}\n\n"),
        ] {
            let BlockFile::Block(block) = parse_block(spelling.as_bytes()) else {
                panic!("not a block: {spelling}");
            };
            assert_eq!(block.get(), BLOCK);
        }
        // Inner whitespace and key order are the file's, untouched.
        let spaced = "{ \"weights\" : [ 50 , 50 ] ,\n \"v\":1 }";
        let BlockFile::Block(block) = parse_block(spaced.as_bytes()) else {
            panic!("not a block");
        };
        assert_eq!(block.get(), spaced);
    }

    #[test]
    fn anything_else_is_not_served() {
        assert_eq!(parse_block(b""), BlockFile::Absent);
        assert_eq!(parse_block(b" \n"), BlockFile::Absent);
        for bad in [
            &b"[1,2]"[..],
            b"\"text\"",
            b"null",
            b"{",
            b"{} {}",
            b"{}x",
            b"\xff{}",
        ] {
            assert!(
                matches!(parse_block(bad), BlockFile::Invalid(_)),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        let large = format!("{{\"x\":\"{}\"}}", "a".repeat(MAX_BLOCK_BYTES));
        assert_eq!(
            parse_block(large.as_bytes()),
            BlockFile::Invalid("larger than 4096 bytes")
        );
    }

    #[tokio::test]
    async fn the_file_is_read_by_refresh_only_and_a_failed_read_keeps_the_last_state() {
        let dir = std::env::temp_dir().join(format!("relay-weights-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("relay-weights.json");
        let _ = std::fs::remove_file(&path);
        let file = RelayWeightsFile::new(&path, "relay-weights-test");
        assert!(file.current().is_none());
        file.refresh().await;
        assert!(file.current().is_none());
        std::fs::write(&path, format!("{BLOCK}\n")).unwrap();
        // Not read until the next refresh.
        assert!(file.current().is_none());
        file.refresh().await;
        assert_eq!(file.current().unwrap().get(), BLOCK);
        // A broken file stops the block from being served; a removed one too.
        std::fs::write(&path, b"{not json").unwrap();
        file.refresh().await;
        assert!(file.current().is_none());
        std::fs::write(&path, BLOCK).unwrap();
        file.refresh().await;
        assert!(file.current().is_some());
        // Too large: refused without reading it all.
        std::fs::write(&path, vec![b' '; 3 * MAX_BLOCK_BYTES]).unwrap();
        file.refresh().await;
        assert!(file.current().is_none());
        std::fs::write(&path, BLOCK).unwrap();
        file.refresh().await;
        assert!(file.current().is_some());
        // A directory is no block file.
        let as_dir = RelayWeightsFile::new(&dir, "relay-weights-test");
        as_dir.refresh().await;
        assert!(as_dir.current().is_none());
        std::fs::remove_file(&path).unwrap();
        file.refresh().await;
        assert!(file.current().is_none());
        let _ = std::fs::remove_dir(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_fifo_is_no_block_file_and_never_blocks() {
        let dir = std::env::temp_dir().join(format!("relay-weights-f-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("relay-weights.json");
        let _ = std::fs::remove_file(&path);
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());
        let file = RelayWeightsFile::new(&path, "relay-weights-test");
        for _ in 0..4 {
            tokio::time::timeout(Duration::from_secs(5), file.refresh())
                .await
                .expect("a refresh waited on the FIFO");
            assert!(file.current().is_none());
        }
        assert!(!file.in_flight.load(std::sync::atomic::Ordering::Acquire));
        std::fs::remove_file(&path).unwrap();
        let _ = std::fs::remove_dir(&dir);
    }

    #[tokio::test]
    async fn concurrent_refreshes_end_with_the_file_as_it_is() {
        let dir = std::env::temp_dir().join(format!("relay-weights-c-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("relay-weights.json");
        std::fs::write(&path, BLOCK).unwrap();
        let file = Arc::new(RelayWeightsFile::new(&path, "relay-weights-test"));
        let tasks: Vec<_> = (0..16)
            .map(|_| {
                let file = file.clone();
                tokio::spawn(async move { file.refresh().await })
            })
            .collect();
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(file.current().unwrap().get(), BLOCK);
        std::fs::remove_file(&path).unwrap();
        let _ = std::fs::remove_dir(&dir);
    }
}

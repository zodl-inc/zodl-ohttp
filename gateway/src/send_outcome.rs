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

//! The outcome of a `SendTransaction`, as a bounded label.
//!
//! lightwalletd answers every `SendTransaction` it could pass to its node with gRPC OK; the node's
//! verdict is in the `SendResponse` message: `errorCode` 0 (accepted, `errorMessage` = the
//! transaction id) or the node's error code and message. A count of non-zero codes alone mixes
//! real failures with benign answers: a wallet that broadcasts a transaction again after it was
//! mined, or while it is still in the node's mempool, gets an error although its transaction is
//! fine.
//!
//! [`observe`] passes a lightwalletd answer through unchanged, reads the first `SendResponse` of
//! it (at most [`MAX_INSPECTED_BYTES`]), and counts one [`SendOutcome`] in
//! `ohttp_send_tx_results_total{network, relay, result}`. Nothing of the answer is kept or logged:
//! the message can name the transaction or the outputs it spends, and only the class leaves this
//! module.

use crate::chunked_stream::UpFrame;
use crate::health;
use anyhow::Result;
use futures_util::{Stream, StreamExt};

/// Bytes of the answer read for the classification. A `SendResponse` is a few hundred bytes;
/// past this the rest of the stream is forwarded without being looked at.
pub const MAX_INSPECTED_BYTES: usize = 4096;

/// What one `SendTransaction` came to. `label()` is the metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    /// `errorCode` 0: the node took the transaction.
    Accepted,
    /// The transaction is already in the node's mempool or queued for it (a repeated broadcast).
    Duplicate,
    /// The transaction is already in the chain (a broadcast after it was mined).
    Mined,
    /// The chain reached the transaction's expiry height.
    Expired,
    /// An input or note of it is already spent, in the chain or by another mempool transaction.
    DoubleSpend,
    /// Refused for its fee (too low for a full mempool, evicted by a higher fee).
    Fee,
    /// Failed consensus or policy validation for another reason.
    Invalid,
    /// The bytes are not a transaction (the node could not parse them).
    Malformed,
    /// The node could not take transactions at that moment (mempool disabled, queue full,
    /// verification timed out).
    Unavailable,
    /// The node cancelled the verification (a new block mined it, or a chain reset).
    Cancelled,
    /// An error the classification does not know.
    Other,
    /// No `SendResponse`: a gRPC error, a stream that ended early, or an answer that could not
    /// be read.
    NoAnswer,
}

impl SendOutcome {
    pub fn label(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Duplicate => "duplicate",
            Self::Mined => "mined",
            Self::Expired => "expired",
            Self::DoubleSpend => "double_spend",
            Self::Fee => "fee",
            Self::Invalid => "invalid",
            Self::Malformed => "malformed",
            Self::Unavailable => "unavailable",
            Self::Cancelled => "cancelled",
            Self::Other => "other",
            Self::NoAnswer => "no_answer",
        }
    }

    /// Every outcome, in a fixed order.
    #[cfg(test)]
    pub const ALL: [SendOutcome; 12] = [
        Self::Accepted,
        Self::Duplicate,
        Self::Mined,
        Self::Expired,
        Self::DoubleSpend,
        Self::Fee,
        Self::Invalid,
        Self::Malformed,
        Self::Unavailable,
        Self::Cancelled,
        Self::Other,
        Self::NoAnswer,
    ];
}

/// Legacy (zcashd-style) RPC error codes the classification uses.
const RPC_DESERIALIZATION_ERROR: i64 = -22;
const RPC_VERIFY_ALREADY_IN_CHAIN: i64 = -27;

/// The class of a node error, from its code and message. The message texts are those of the
/// common full nodes behind lightwalletd; anything else is `Other`, never a guess.
pub fn classify_error(code: i64, message: &str) -> SendOutcome {
    if code == 0 {
        return SendOutcome::Accepted;
    }
    let m = message.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| m.contains(*n));
    if code == RPC_DESERIALIZATION_ERROR || has(&["parse error", "deserializ", "tx decode failed"])
    {
        SendOutcome::Malformed
    } else if has(&[
        "already exists in mempool",
        "already queued",
        "txn-already-in-mempool",
        "txn-already-known",
    ]) {
        SendOutcome::Duplicate
    } else if code == RPC_VERIFY_ALREADY_IN_CHAIN
        || has(&[
            "already in state",
            "committed to the best chain",
            "already in block chain",
        ])
    {
        SendOutcome::Mined
    } else if has(&["expiry height", "expired", "expiring-soon"]) {
        SendOutcome::Expired
    } else if has(&[
        "inputs were spent",
        "already spent",
        "spent some of its inputs",
        "duplicate sprout nullifier",
        "duplicate sapling nullifier",
        "duplicate orchard nullifier",
        "inputs-spent",
        "missingorspent",
        "double-spen",
        "txn-mempool-conflict",
    ]) {
        SendOutcome::DoubleSpend
    } else if has(&["fee", "evicted"]) {
        SendOutcome::Fee
    } else if has(&[
        "mempool is disabled",
        "queue is full",
        "timeout waiting for verification",
    ]) {
        SendOutcome::Unavailable
    } else if has(&["cancelled", "canceled"]) {
        SendOutcome::Cancelled
    } else if has(&[
        "consensus validation",
        "standard validation",
        "non-standard",
        "mempool policy",
        "failed to validate",
        "could not validate",
        "bad-txns",
        "mandatory-script-verify",
    ]) {
        SendOutcome::Invalid
    } else {
        SendOutcome::Other
    }
}

/// Reads a base-128 varint at `*pos`.
fn varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *buf.get(*pos)?;
        *pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// A `SendResponse` message as far as it could be read.
struct Fields {
    /// `errorCode` (field 1, int32); `None` when the message read has none.
    code: Option<i64>,
    /// `errorMessage` (field 2, string), possibly cut.
    message: String,
    /// Every field was read whole (no cut, no unknown wire type).
    whole: bool,
}

/// The fields of a `SendResponse` message. Unknown fields are skipped; at a cut or an unreadable
/// field the reading stops with what it has and `whole = false`.
fn send_response_fields(msg: &[u8]) -> Fields {
    let mut f = Fields {
        code: None,
        message: String::new(),
        whole: false,
    };
    let mut pos = 0;
    while pos < msg.len() {
        let Some(key) = varint(msg, &mut pos) else {
            return f;
        };
        let (field, wire) = (key >> 3, key & 7);
        match wire {
            0 => {
                let Some(v) = varint(msg, &mut pos) else {
                    return f;
                };
                if field == 1 {
                    // int32 on the wire: a negative value is sign-extended to 64 bits.
                    f.code = Some(i64::from(v as i32));
                }
            }
            2 => {
                let Some(len) = varint(msg, &mut pos) else {
                    return f;
                };
                let end = pos.saturating_add(usize::try_from(len).unwrap_or(usize::MAX));
                if field == 2 {
                    f.message = String::from_utf8_lossy(&msg[pos..end.min(msg.len())]).into_owned();
                }
                if end > msg.len() {
                    return f;
                }
                pos = end;
            }
            1 | 5 => {
                let end = pos.saturating_add(if wire == 1 { 8 } else { 4 });
                if end > msg.len() {
                    return f;
                }
                pos = end;
            }
            _ => return f,
        }
    }
    f.whole = true;
    f
}

/// The outcome of a lightwalletd `SendTransaction` answer: the start of its body (gRPC
/// length-prefixed messages) and its `grpc-status` (`None` = none seen).
pub fn classify_answer(body: &[u8], grpc_status: Option<&str>) -> SendOutcome {
    if grpc_status.is_some_and(|s| s.trim() != "0") {
        return SendOutcome::NoAnswer;
    }
    // One gRPC message: compressed flag (1 byte), length (4 bytes, big-endian), message.
    let Some(header) = body.get(..5) else {
        return SendOutcome::NoAnswer;
    };
    if header[0] != 0 {
        // A compressed answer is not decoded here.
        return SendOutcome::Other;
    }
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    let msg = &body[5..];
    let complete = msg.len() >= len;
    let f = send_response_fields(&msg[..len.min(msg.len())]);
    match f.code {
        // A code read whole: the class needs only the start of the message (a long message
        // can be cut by MAX_INSPECTED_BYTES).
        Some(code) => classify_error(code, &f.message),
        // proto3 leaves a zero errorCode out: only a whole, readable message without it is
        // code 0, never a cut or garbled one.
        None if complete && f.whole => classify_error(0, &f.message),
        None => SendOutcome::NoAnswer,
    }
}

/// Counts one `SendTransaction` that got no lightwalletd answer at all (the call failed or was
/// refused before it reached lightwalletd).
pub fn record_no_answer(network: &str, relay: &str) {
    health::record_send_tx_result(network, relay, SendOutcome::NoAnswer.label());
}

/// Forwards `upstream` unchanged and counts its outcome once it ends, fails or is dropped
/// (`enabled = false`: forwards only). `head_status`: the `grpc-status` of the response head,
/// if it carried one (a Trailers-Only answer).
pub fn observe<S>(
    enabled: bool,
    network: &str,
    relay: &str,
    head_status: Option<String>,
    upstream: S,
) -> impl Stream<Item = Result<UpFrame>> + Send + 'static
where
    S: Stream<Item = Result<UpFrame>> + Send + 'static,
{
    struct Tally {
        enabled: bool,
        network: String,
        relay: String,
        body: Vec<u8>,
        status: Option<String>,
        done: bool,
    }
    impl Tally {
        fn finish(&mut self) {
            if self.enabled && !self.done {
                self.done = true;
                let outcome = classify_answer(&self.body, self.status.as_deref());
                health::record_send_tx_result(&self.network, &self.relay, outcome.label());
                // Nothing of the answer is held past its classification.
                self.body = Vec::new();
            }
        }
    }
    impl Drop for Tally {
        fn drop(&mut self) {
            self.finish();
        }
    }

    let mut tally = Tally {
        enabled,
        network: network.to_string(),
        relay: relay.to_string(),
        body: Vec::new(),
        status: head_status,
        done: false,
    };
    async_stream::stream! {
        let mut upstream = Box::pin(upstream);
        while let Some(item) = upstream.next().await {
            if tally.enabled {
                match &item {
                    Ok(UpFrame::Data(d)) => {
                        let room = MAX_INSPECTED_BYTES.saturating_sub(tally.body.len());
                        tally.body.extend_from_slice(&d[..d.len().min(room)]);
                    }
                    Ok(UpFrame::Trailers(t)) => {
                        if let Some((_, v)) =
                            t.iter().find(|(k, _)| k.eq_ignore_ascii_case("grpc-status"))
                        {
                            tally.status = Some(v.clone());
                        }
                    }
                    // A failed stream is no answer, whatever status came before.
                    Err(_) => tally.status = Some("13".to_string()),
                }
            }
            yield item;
        }
        tally.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    /// A gRPC-framed `SendResponse` with `code` and `message`, as lightwalletd writes it.
    fn answer(code: i32, message: &str) -> Vec<u8> {
        let mut msg = Vec::new();
        if code != 0 {
            msg.push(0x08);
            let mut v = i64::from(code) as u64;
            loop {
                let byte = (v & 0x7f) as u8;
                v >>= 7;
                if v == 0 {
                    msg.push(byte);
                    break;
                }
                msg.push(byte | 0x80);
            }
        }
        if !message.is_empty() {
            msg.push(0x12);
            let mut n = message.len();
            while n >= 0x80 {
                msg.push((n as u8 & 0x7f) | 0x80);
                n >>= 7;
            }
            msg.push(n as u8);
            msg.extend_from_slice(message.as_bytes());
        }
        let mut out = vec![0];
        out.extend_from_slice(&(msg.len() as u32).to_be_bytes());
        out.extend_from_slice(&msg);
        out
    }

    const ID: &str = r#"WtxId("private")"#;

    #[test]
    fn node_answers_map_to_their_class() {
        let cases: Vec<(i32, String, SendOutcome)> =
            vec![
            (0, format!("\"{}\"", "ab".repeat(32)), SendOutcome::Accepted),
            (-22, "parse error: bad tx header".into(), SendOutcome::Malformed),
            (-1, "transaction already exists in mempool".into(), SendOutcome::Duplicate),
            (
                -1,
                "transaction dropped because it is already queued for download".into(),
                SendOutcome::Duplicate,
            ),
            (-26, "txn-already-in-mempool".into(), SendOutcome::Duplicate),
            (
                -25,
                format!("failed to validate tx: {ID}, error: transaction is already in state"),
                SendOutcome::Mined,
            ),
            (
                -1,
                "any transaction with the same effects will be rejected from the mempool until a \
                 chain reset: transaction was committed to the best chain"
                    .into(),
                SendOutcome::Mined,
            ),
            (-27, "transaction already in block chain".into(), SendOutcome::Mined),
            (
                -1,
                "any transaction with the same effects will be rejected from the mempool until a \
                 chain reset: best chain tip has reached transaction expiry height"
                    .into(),
                SendOutcome::Expired,
            ),
            (-26, "tx-expiring-soon".into(), SendOutcome::Expired),
            (
                -25,
                "transaction rejected because another transaction in the mempool has already \
                 spent some of its inputs"
                    .into(),
                SendOutcome::DoubleSpend,
            ),
            (
                -1,
                "any transaction with the same effects will be rejected from the mempool until a \
                 chain reset: transaction inputs were spent, or nullifiers were revealed, in the \
                 best chain"
                    .into(),
                SendOutcome::DoubleSpend,
            ),
            (
                -25,
                format!(
                    "failed to validate tx: {ID}, error: transaction did not pass consensus \
                     validation: duplicate Orchard nullifier"
                ),
                SendOutcome::DoubleSpend,
            ),
            (
                -25,
                "transaction rejected because the mempool is full and it pays too low a fee"
                    .into(),
                SendOutcome::Fee,
            ),
            (-26, "min relay fee not met".into(), SendOutcome::Fee),
            (
                -1,
                "mempool is disabled since synchronization is behind the chain tip".into(),
                SendOutcome::Unavailable,
            ),
            (
                -1,
                "transaction dropped because the queue is full".into(),
                SendOutcome::Unavailable,
            ),
            (-25, "verification cancelled".into(), SendOutcome::Cancelled),
            (
                -25,
                format!(
                    "failed to validate tx: {ID}, error: transaction did not pass consensus \
                     validation: could not contextually validate transaction on best chain: \
                     unshielded transparent coinbase spend"
                ),
                SendOutcome::Invalid,
            ),
            (-26, "bad-txns-oversize".into(), SendOutcome::Invalid),
            (-25, "something new".into(), SendOutcome::Other),
            (-25, String::new(), SendOutcome::Other),
        ];
        for (code, message, want) in cases {
            assert_eq!(
                classify_answer(&answer(code, &message), Some("0")),
                want,
                "{code} {message:?}"
            );
        }
    }

    #[test]
    fn errors_and_unreadable_answers() {
        // A gRPC error, in the head or the trailers: no SendResponse.
        assert_eq!(classify_answer(&[], Some("3")), SendOutcome::NoAnswer);
        assert_eq!(
            classify_answer(&answer(0, "\"00\""), Some("13")),
            SendOutcome::NoAnswer
        );
        // No body at all, or a cut frame header.
        assert_eq!(classify_answer(&[], None), SendOutcome::NoAnswer);
        assert_eq!(
            classify_answer(&[0, 0, 0], Some("0")),
            SendOutcome::NoAnswer
        );
        // A compressed message is not decoded.
        let mut compressed = answer(-25, "transaction is already in state");
        compressed[0] = 1;
        assert_eq!(classify_answer(&compressed, Some("0")), SendOutcome::Other);
        // An empty SendResponse (all fields default) is errorCode 0.
        assert_eq!(
            classify_answer(&answer(0, ""), Some("0")),
            SendOutcome::Accepted
        );
        // A message cut inside the text still has its code.
        let full = answer(-22, "parse error: bad tx header");
        assert_eq!(
            classify_answer(&full[..full.len() - 10], Some("0")),
            SendOutcome::Malformed
        );
        // A message cut before its code is no answer, not an accepted one.
        assert_eq!(
            classify_answer(&full[..5], Some("0")),
            SendOutcome::NoAnswer
        );
        // Cut or garbled messages without a code are never "accepted".
        for msg in [
            &[0x08][..],             // the code's varint cut
            &[0x12, 0x05, b'a'][..], // the message cut
            &[0x1d, 0x01][..],       // a fixed32 field cut
            &[0x0b][..],             // an unknown wire type (start group)
        ] {
            let mut framed = vec![0];
            framed.extend_from_slice(&(msg.len() as u32).to_be_bytes());
            framed.extend_from_slice(msg);
            assert_eq!(
                classify_answer(&framed, Some("0")),
                SendOutcome::NoAnswer,
                "{msg:?}"
            );
        }
        // A cut message whose code was read keeps its code (a long message cut at the cap).
        let mut cut = vec![0x08, 0x01, 0x12, 0x7f];
        cut.extend_from_slice(b"transaction already exists in mempool");
        let mut framed = vec![0];
        framed.extend_from_slice(&(cut.len() as u32 + 100).to_be_bytes());
        framed.extend_from_slice(&cut);
        assert_eq!(classify_answer(&framed, Some("0")), SendOutcome::Duplicate);
        // An unknown field before the known ones is skipped.
        let mut msg = vec![0x18, 0x05, 0x08, 0x00];
        msg.extend_from_slice(&[0x12, 0x02, b'"', b'"']);
        let mut framed = vec![0];
        framed.extend_from_slice(&(msg.len() as u32).to_be_bytes());
        framed.extend_from_slice(&msg);
        assert_eq!(classify_answer(&framed, Some("0")), SendOutcome::Accepted);
    }

    #[test]
    fn labels_are_distinct() {
        let mut labels: Vec<_> = SendOutcome::ALL.iter().map(|o| o.label()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), SendOutcome::ALL.len());
    }

    async fn run(
        enabled: bool,
        net: &str,
        head: Option<&str>,
        frames: Vec<Result<UpFrame>>,
    ) -> Vec<Result<UpFrame>> {
        let s = observe(
            enabled,
            net,
            "relay-a",
            head.map(str::to_string),
            futures_util::stream::iter(frames),
        );
        s.collect().await
    }

    #[tokio::test]
    async fn observe_forwards_unchanged_and_counts_once() {
        health::init_metrics();
        let net = "send-outcome-test";
        let body = answer(
            -25,
            &format!("failed to validate tx: {ID}, error: transaction is already in state"),
        );
        let (a, b) = body.split_at(7);
        let frames = vec![
            UpFrame::Data(Bytes::copy_from_slice(a)),
            UpFrame::Data(Bytes::copy_from_slice(b)),
            UpFrame::Trailers(vec![("grpc-status".into(), "0".into())]),
        ];
        let out = run(true, net, None, frames.iter().cloned().map(Ok).collect()).await;
        assert_eq!(
            out.into_iter().map(|r| r.unwrap()).collect::<Vec<_>>(),
            frames,
            "frames pass through unchanged"
        );
        assert_eq!(health::send_tx_results(net, "relay-a", "mined"), 1);

        // An accepted answer split across frames, then a gRPC error in the trailers.
        let ok = answer(0, &format!("\"{}\"", "cd".repeat(32)));
        run(true, net, None, vec![Ok(UpFrame::Data(ok.clone().into()))]).await;
        assert_eq!(health::send_tx_results(net, "relay-a", "accepted"), 1);
        run(
            true,
            net,
            None,
            vec![
                Ok(UpFrame::Data(ok.clone().into())),
                Ok(UpFrame::Trailers(vec![("grpc-status".into(), "14".into())])),
            ],
        )
        .await;
        assert_eq!(health::send_tx_results(net, "relay-a", "no_answer"), 1);
        // A Trailers-Only error answer (status in the head).
        run(true, net, Some("3"), vec![]).await;
        assert_eq!(health::send_tx_results(net, "relay-a", "no_answer"), 2);
        // A failed stream.
        run(true, net, None, vec![Err(anyhow::anyhow!("cut"))]).await;
        assert_eq!(health::send_tx_results(net, "relay-a", "no_answer"), 3);
        // A whole accepted answer and an OK status, then the stream fails: no answer.
        run(
            true,
            net,
            None,
            vec![
                Ok(UpFrame::Data(ok.clone().into())),
                Ok(UpFrame::Trailers(vec![("grpc-status".into(), "0".into())])),
                Err(anyhow::anyhow!("cut")),
            ],
        )
        .await;
        assert_eq!(health::send_tx_results(net, "relay-a", "no_answer"), 4);
        assert_eq!(health::send_tx_results(net, "relay-a", "accepted"), 1);
        // Disabled: nothing counted.
        let other = "send-outcome-test-off";
        run(false, other, None, vec![Ok(UpFrame::Data(ok.into()))]).await;
        for o in SendOutcome::ALL {
            assert_eq!(health::send_tx_results(other, "relay-a", o.label()), 0);
        }
    }

    #[tokio::test]
    async fn observe_counts_a_dropped_stream_and_caps_what_it_reads() {
        health::init_metrics();
        let net = "send-outcome-drop";
        let body = answer(-1, "transaction already exists in mempool");
        // Dropped after the first frame: what was read is classified.
        {
            let s = observe(
                true,
                net,
                "relay-b",
                None,
                futures_util::stream::iter(vec![
                    Ok(UpFrame::Data(body.clone().into())),
                    Ok(UpFrame::Data(Bytes::from_static(b"more"))),
                ]),
            );
            let mut s = Box::pin(s);
            assert!(s.next().await.is_some());
        }
        assert_eq!(health::send_tx_results(net, "relay-b", "duplicate"), 1);
        // A huge body: forwarded whole, only the start is read.
        let mut big = body.clone();
        big.extend(vec![0u8; 3 * MAX_INSPECTED_BYTES]);
        let out = run(true, net, None, vec![Ok(UpFrame::Data(big.clone().into()))]).await;
        match &out[0] {
            Ok(UpFrame::Data(d)) => assert_eq!(d.len(), big.len()),
            other => panic!("unexpected {other:?}"),
        }
        // (`run` sends through "relay-a".)
        assert_eq!(health::send_tx_results(net, "relay-a", "duplicate"), 1);
        assert_eq!(health::send_tx_results(net, "relay-b", "duplicate"), 1);
    }
}

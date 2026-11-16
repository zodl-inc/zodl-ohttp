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

//! The `ohttp-e2e` binary run as a subprocess against a local HTTP server that serves a key
//! configuration and plays the relay (always answering 500, so a run that gets as far as the
//! relay fails after one POST). Each test checks what the tool sent: which key-configuration
//! source it used, and that nothing at all is sent when a setting is refused.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The signing key of the tests' envelopes.
fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

/// An `application/ohttp-keys` document of one configuration of the suite the client speaks
/// (X25519, HKDF-SHA256, AES-128-GCM), its public key the X25519 base point.
fn plain_document() -> Vec<u8> {
    let mut config = vec![1u8];
    config.extend_from_slice(&0x0020u16.to_be_bytes());
    let mut public_key = [0u8; 32];
    public_key[0] = 9;
    config.extend_from_slice(&public_key);
    config.extend_from_slice(&4u16.to_be_bytes());
    config.extend_from_slice(&0x0001u16.to_be_bytes());
    config.extend_from_slice(&0x0001u16.to_be_bytes());
    let mut document = (config.len() as u16).to_be_bytes().to_vec();
    document.extend_from_slice(&config);
    document
}

/// A mainnet envelope of [`plain_document`], valid now, signed by [`signing_key`]; with
/// `tampered`, a byte of the document is changed after signing.
fn envelope(tampered: bool) -> Vec<u8> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (not_before, not_after) = (now - 60, now + 3600);
    let mut document = plain_document();
    let mut message = b"zodl-ohttp-configs-v1".to_vec();
    message.push(0);
    message.extend_from_slice(b"mainnet");
    message.push(0);
    message.extend_from_slice(&not_before.to_be_bytes());
    message.extend_from_slice(&not_after.to_be_bytes());
    message.extend_from_slice(&document);
    let key = signing_key();
    let sig = key.sign(&message);
    if tampered {
        document[10] ^= 1;
    }
    let key_id = hex::encode(&Sha256::digest(key.verifying_key().as_bytes())[..4]);
    format!(
        r#"{{"v":1,"network":"mainnet","configs":"{}","not_before":{not_before},"not_after":{not_after},"key_id":"{key_id}","sig":"{}"}}"#,
        BASE64.encode(&document),
        BASE64.encode(sig.to_bytes()),
    )
    .into_bytes()
}

/// The log entry of a connection closed (or timed out) before it sent a byte.
const NO_REQUEST: &str = "<connection without a request>";

/// A local HTTP/1.1 server: `GET /keys` answers `keys` (body, `Content-Type`), any other
/// request 500. Every request line it gets is logged, as soon as the request's head is read; a
/// connection that sends nothing is logged as [`NO_REQUEST`] and not answered.
struct Server {
    base: String,
    log: Arc<Mutex<Vec<String>>>,
}

impl Server {
    fn start(keys: Vec<u8>, content_type: &'static str) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let log = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&log);
        // Serves until the test process ends.
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                // A client that stops sending does not hold up the requests after it.
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                    head.push(byte[0]);
                }
                if head.is_empty() {
                    seen.lock().unwrap().push(NO_REQUEST.to_string());
                    continue;
                }
                let head = String::from_utf8_lossy(&head).to_string();
                let length: usize = head
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, value)| value.trim().parse().ok())
                    .unwrap_or(0);
                // Logged once its head is read, whether or not its body arrives.
                let line = head.lines().next().unwrap_or_default();
                let request: String = line.split(' ').take(2).collect::<Vec<_>>().join(" ");
                seen.lock().unwrap().push(request.clone());
                let mut body = vec![0u8; length];
                let _ = stream.read_exact(&mut body);
                let (status, content_type, body) = if request == "GET /keys" {
                    ("200 OK", content_type, keys.as_slice())
                } else {
                    ("500 Internal Server Error", "text/plain", &b"no"[..])
                };
                let answer = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(answer.as_bytes());
                let _ = stream.write_all(body);
            }
        });
        Server { base, log }
    }

    fn requests(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

/// Whether the inherited variable `name` could change what a run of the tool does: its own
/// settings and the proxy variables of its HTTP stack.
fn affects_the_tool(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.starts_with("OHTTP_E2E_")
        || upper == "NETWORK"
        || ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"].contains(&upper.as_str())
}

/// `ohttp-e2e`, without the inherited variables that [`affect the tool`](affects_the_tool):
/// the rest of the environment (on Windows `SystemRoot`, which sockets need) is kept, so the
/// tests do not depend on what a process does with an empty environment.
fn tool() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ohttp-e2e"));
    for (name, _) in std::env::vars_os() {
        if name.to_str().is_none_or(affects_the_tool) {
            command.env_remove(name);
        }
    }
    command
}

/// How long a run of the tool may take before it is killed and the test fails: longer than
/// the tool's own HTTP timeout, so that a stalled exchange is reported by the tool first.
const DEADLINE: Duration = Duration::from_secs(120);

/// The output of `command` ([`run_captured`] with the [`DEADLINE`], no ready marker and
/// [`COLLECT`]).
fn output_of(command: &mut Command) -> Output {
    run_captured(command, None, DEADLINE, COLLECT)
}

/// How long the output of a command that exited (or was killed) is waited for, both streams
/// together: a descendant that still holds its standard output or error keeps them open.
const COLLECT: Duration = Duration::from_secs(5);

/// A pipe read to its end by a thread of its own. What was read so far stays available, so
/// that a pipe a descendant keeps open can still be shown up to that point.
struct Collected {
    bytes: Arc<Mutex<Vec<u8>>>,
    ended: std::sync::mpsc::Receiver<()>,
}

impl Collected {
    fn new(mut pipe: impl Read + Send + 'static) -> Collected {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let (sender, ended) = std::sync::mpsc::channel();
        let shared = Arc::clone(&bytes);
        std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            loop {
                match pipe.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => shared.lock().unwrap().extend_from_slice(&buffer[..n]),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
            let _ = sender.send(());
        });
        Collected { bytes, ended }
    }

    /// Everything the pipe carried if it ends by `until`, otherwise what was read until then.
    fn until(&self, until: Instant) -> Result<Vec<u8>, Vec<u8>> {
        let wait = until.saturating_duration_since(Instant::now());
        let ended = !matches!(
            self.ended.recv_timeout(wait),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        );
        let bytes = self.bytes.lock().unwrap().clone();
        if ended {
            Ok(bytes)
        } else {
            Err(bytes)
        }
    }
}

/// The text of a stream for a failure message; a stream that was still open is marked as
/// partial.
fn shown(collected: &Result<Vec<u8>, Vec<u8>>) -> String {
    match collected {
        Ok(bytes) => String::from_utf8_lossy(bytes).to_string(),
        Err(bytes) => format!(
            "{}<still open, a descendant holds it: the output so far>",
            String::from_utf8_lossy(bytes)
        ),
    }
}

/// The output of `command`, run with its standard output and error captured, each read by a
/// thread of its own. A run that has not exited by `deadline` is killed, reaped and fails the
/// test, with what it wrote. After the exit (or the kill) the output is waited for `collect`
/// at most; a stream a descendant still holds open then fails the test too (also when the
/// command itself exited), with the output read up to that point, marked as partial. The
/// test then no longer waits for such a stream; its reader thread ends only when the
/// descendant closes it.
///
/// With `ready`, the deadline counts from when that path exists (so that a test does not race
/// the command's own setup); a command that creates neither it nor exits within [`DEADLINE`]
/// is killed and fails the test.
fn run_captured(
    command: &mut Command,
    ready: Option<&Path>,
    deadline: Duration,
    collect: Duration,
) -> Output {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = Collected::new(child.stdout.take().unwrap());
    let stderr = Collected::new(child.stderr.take().unwrap());
    let spawned = Instant::now();
    let mut started = ready.is_none().then_some(spawned);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.is_none() && ready.is_some_and(Path::exists) {
            started = Some(Instant::now());
        }
        let late = match started {
            Some(started) => started.elapsed() > deadline,
            None => spawned.elapsed() > DEADLINE,
        };
        if late {
            let _ = child.kill();
            let _ = child.wait();
            // What it wrote until then, to tell where it stopped.
            let until = Instant::now() + collect;
            let (stderr, stdout) = (stderr.until(until), stdout.until(until));
            let what = match started {
                Some(_) => format!("did not exit within {deadline:?}"),
                None => format!("neither became ready nor exited within {DEADLINE:?}"),
            };
            panic!(
                "the command {what}: killed\nstderr: {}\nstdout: {}",
                shown(&stderr),
                shown(&stdout)
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let until = Instant::now() + collect;
    match (stdout.until(until), stderr.until(until)) {
        (Ok(stdout), Ok(stderr)) => Output {
            status,
            stdout,
            stderr,
        },
        (stdout, stderr) => panic!(
            "the command exited, but a descendant kept its output open for {collect:?}\n\
             stderr: {}\nstdout: {}",
            shown(&stderr),
            shown(&stdout)
        ),
    }
}

/// [`tool`] with `config_url`, the relay at `relay_url`, the mainnet configuration (signed by
/// [`signing_key`]) and the plain-HTTP opt-in.
fn command(config_url: &str, relay_url: &str) -> Command {
    let pubkey = hex::encode(signing_key().verifying_key().as_bytes());
    let mut command = tool();
    command
        .args([
            config_url,
            relay_url,
            "lightwalletd.example",
            "POST",
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock",
        ])
        .env("OHTTP_E2E_GATEWAY_HOST_MAINNET", "ohttp-gateway.example")
        .env("OHTTP_E2E_RELAY_URL_MAINNET", "https://relay.example/relay")
        .env(
            "OHTTP_E2E_KEYS_DNS_NAME_MAINNET",
            "mainnet.ohttp-keys.example",
        )
        .env("OHTTP_E2E_SIGNING_PUBKEY_MAINNET", pubkey)
        .env("OHTTP_E2E_PLAIN_HTTP_RELAY", "1");
    command
}

/// [`command`] run with `env` added.
fn run(config_url: &str, relay_url: &str, env: &[(&str, &str)]) -> Output {
    let mut command = command(config_url, relay_url);
    for (name, value) in env {
        command.env(name, value);
    }
    output_of(&mut command)
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}

/// Runs the tool against `server`, returning stdout and stderr; asserts that it failed.
fn run_failing(server: &Server, env: &[(&str, &str)]) -> (String, String) {
    let output = run(
        &format!("{}/keys", server.base),
        &format!("{}/relay", server.base),
        env,
    );
    assert!(!output.status.success());
    (text(&output.stdout), text(&output.stderr))
}

const SIGNED: (&str, &str) = ("OHTTP_E2E_KEY_CONFIG_SOURCE", "signed");
const PLAIN: (&str, &str) = ("OHTTP_E2E_KEY_CONFIG_SOURCE", "plain");

#[test]
fn an_explicit_signed_source_refuses_an_unsigned_answer() {
    let server = Server::start(plain_document(), "application/ohttp-keys");
    let (stdout, stderr) = run_failing(&server, &[SIGNED]);
    assert!(stdout.contains("[1] signed config"), "{stdout}");
    assert!(!stdout.contains("signed-configs: OK"), "{stdout}");
    // Refused for what it is, not for some other failure.
    assert!(stderr.contains("not a signed envelope"), "{stderr}");
    assert!(!stderr.contains("deprecated"), "{stderr}");
    // The relay was never posted to.
    assert_eq!(server.requests(), ["GET /keys"]);
}

#[test]
fn an_explicit_signed_source_refuses_a_tampered_envelope() {
    let server = Server::start(envelope(true), "application/json");
    let (stdout, stderr) = run_failing(&server, &[SIGNED]);
    assert!(stdout.contains("[1] signed config"), "{stdout}");
    assert!(stderr.contains("bad signature"), "{stderr}");
    assert_eq!(server.requests(), ["GET /keys"]);
}

/// The control of the two tests above: the same envelope untampered is accepted, also when
/// the answer is labelled as the unsigned document (the explicit source wins over the label),
/// and the run goes on to the relay.
#[test]
fn an_explicit_signed_source_wins_over_the_answers_content_type() {
    let server = Server::start(envelope(false), "application/ohttp-keys");
    let (stdout, stderr) = run_failing(&server, &[SIGNED]);
    assert!(stdout.contains("signed-configs: OK"), "{stdout}");
    assert!(stderr.contains("relay returned 500"), "{stderr}");
    assert_eq!(server.requests(), ["GET /keys", "POST /relay"]);
}

/// An explicit `plain` is never verified as signed, even when the answer is labelled
/// `application/json`; the guess (deprecated, with its warning) would verify that answer.
#[test]
fn an_explicit_plain_source_wins_over_the_answers_content_type() {
    let server = Server::start(plain_document(), "application/json");
    let (stdout, stderr) = run_failing(&server, &[PLAIN]);
    assert!(stdout.contains("[1] key config"), "{stdout}");
    assert!(!stdout.contains("signed config"), "{stdout}");
    assert!(stderr.contains("relay returned 500"), "{stderr}");
    assert!(!stderr.contains("deprecated"), "{stderr}");
    assert_eq!(server.requests(), ["GET /keys", "POST /relay"]);

    let guessed = Server::start(plain_document(), "application/json");
    let (stdout, stderr) = run_failing(&guessed, &[]);
    assert!(
        stderr.contains("warning: guessing the key-configuration source"),
        "{stderr}"
    );
    assert!(stderr.contains("deprecated"), "{stderr}");
    assert!(stdout.contains("[1] signed config"), "{stdout}");
    assert_eq!(guessed.requests(), ["GET /keys"]);
}

/// A refused setting fails the run before any request: not even the key configuration is
/// fetched. The error names the setting, never the value.
#[test]
fn nothing_is_sent_when_a_setting_is_refused() {
    let server = Server::start(plain_document(), "application/ohttp-keys");
    let good = format!("{}/relay", server.base);
    let later_bad = format!("{good},,https://replay.example/relay?x=1");
    let later_plain = format!("{good}, HTTP://replay.example/relay");
    for (env, error) in [
        (
            vec![PLAIN, ("OHTTP_E2E_REPLAY_URLS", later_bad.as_str())],
            "OHTTP_E2E_REPLAY_URLS entry 2: ",
        ),
        (
            vec![PLAIN, ("OHTTP_E2E_REPLAY_URLS", later_plain.as_str())],
            "OHTTP_E2E_REPLAY_URLS entry 1: the scheme must be written in lower case",
        ),
        (
            vec![PLAIN, ("OHTTP_E2E_DUMP_HEADERS", "0")],
            "OHTTP_E2E_DUMP_HEADERS must be 1 or unset",
        ),
        (
            vec![PLAIN, ("NETWORK", "regtest")],
            "NETWORK must be mainnet or testnet",
        ),
        (
            vec![PLAIN, ("OHTTP_E2E_EXPECT_OK", "0")],
            "OHTTP_E2E_EXPECT_OK must be 1 or unset",
        ),
        (
            vec![PLAIN, ("OHTTP_E2E_REPLAY", "true")],
            "OHTTP_E2E_REPLAY must be 1 or unset",
        ),
        (
            vec![PLAIN, ("OHTTP_E2E_REPLAY_GAP_MS", "soon")],
            "OHTTP_E2E_REPLAY_GAP_MS must be a number of milliseconds",
        ),
        // The guessed source: the run fails on the setting without warning about the guess.
        (
            vec![("NETWORK", "regtest")],
            "NETWORK must be mainnet or testnet",
        ),
        (
            vec![("OHTTP_E2E_KEY_CONFIG_SOURCE", "dns")],
            "OHTTP_E2E_KEY_CONFIG_SOURCE must be signed or plain",
        ),
    ] {
        let (_, stderr) = run_failing(&server, &env);
        assert!(stderr.contains(error), "{env:?}: {stderr}");
        assert!(!stderr.contains("replay.example"), "{stderr}");
        assert!(!stderr.contains("regtest"), "{stderr}");
        assert!(!stderr.contains("soon"), "{stderr}");
        assert!(!stderr.contains("deprecated"), "{stderr}");
        assert!(server.requests().is_empty(), "{env:?}");
    }
    // The relay URL itself: without the opt-in, an http:// relay URL is refused.
    let keys_url = format!("{}/keys", server.base);
    let output = output_of(tool().env("OHTTP_E2E_KEY_CONFIG_SOURCE", "plain").args([
        keys_url.as_str(),
        good.as_str(),
        "lightwalletd.example",
        "POST",
        "/",
    ]));
    assert!(!output.status.success());
    assert!(text(&output.stderr).contains("OHTTP_E2E_PLAIN_HTTP_RELAY=1"));
    assert!(server.requests().is_empty());
    // The control: the same server does answer a run whose settings are accepted.
    let (_, stderr) = run_failing(&server, &[PLAIN]);
    assert!(stderr.contains("relay returned 500"), "{stderr}");
    assert_eq!(server.requests(), ["GET /keys", "POST /relay"]);
}

/// A per-network variable, `OHTTP_E2E_REQUEST_ID` or `OHTTP_E2E_EXTRA_HEADERS` that is not
/// Unicode fails every run before anything is sent, also one with the unsigned source, which
/// does not use the network's configuration.
#[cfg(unix)]
#[test]
fn nothing_is_sent_when_a_network_variable_is_not_unicode() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt as _;
    let server = Server::start(plain_document(), "application/ohttp-keys");
    let (keys, relay) = (
        format!("{}/keys", server.base),
        format!("{}/relay", server.base),
    );
    for name in [
        "OHTTP_E2E_KEYS_DNS_NAME_MAINNET",
        "OHTTP_E2E_GATEWAY_HOST_TESTNET",
        "OHTTP_E2E_REQUEST_ID",
        "OHTTP_E2E_EXTRA_HEADERS",
    ] {
        for source in [PLAIN, SIGNED] {
            let output = output_of(
                command(&keys, &relay)
                    .env(source.0, source.1)
                    .env(name, OsStr::from_bytes(b"not-shown\xff")),
            );
            assert!(!output.status.success());
            let stderr = text(&output.stderr);
            assert!(
                stderr.contains(&format!("{name} is not valid Unicode")),
                "{stderr}"
            );
            assert!(!stderr.contains("not-shown"), "{stderr}");
            assert!(server.requests().is_empty(), "{name}");
        }
    }
    // An incomplete, invalid configuration is not checked by a run with the unsigned source.
    let output = output_of(
        command(&keys, &relay)
            .env(PLAIN.0, PLAIN.1)
            .env("OHTTP_E2E_GATEWAY_HOST_TESTNET", "Not A Host"),
    );
    assert!(text(&output.stderr).contains("relay returned 500"));
    assert_eq!(server.requests(), ["GET /keys", "POST /relay"]);
}

/// The header count is printed with `OHTTP_E2E_DUMP_HEADERS=1` only; empty is off.
#[test]
fn the_header_count_is_printed_with_1_only() {
    let server = Server::start(plain_document(), "application/ohttp-keys");
    let (stdout, _) = run_failing(&server, &[PLAIN, ("OHTTP_E2E_DUMP_HEADERS", "1")]);
    assert!(stdout.contains(" response headers"), "{stdout}");
    let (stdout, _) = run_failing(&server, &[PLAIN, ("OHTTP_E2E_DUMP_HEADERS", "")]);
    assert!(!stdout.contains(" response headers"), "{stdout}");
}

/// The server's log tells a connection that sent nothing from a request.
#[test]
fn a_connection_without_a_request_is_logged_as_such() {
    let server = Server::start(plain_document(), "application/ohttp-keys");
    drop(std::net::TcpStream::connect(server.base.trim_start_matches("http://")).unwrap());
    let started = std::time::Instant::now();
    while server.requests().is_empty() && started.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(server.requests(), [NO_REQUEST]);
}

/// A new directory of mode 0700 under the temporary directory, with a name of its own;
/// removed when dropped, so also when a test or its setup fails after creating it.
#[cfg(unix)]
struct TempDir(std::path::PathBuf);

#[cfg(unix)]
impl TempDir {
    fn new(case: &str) -> TempDir {
        use std::os::unix::fs::DirBuilderExt as _;
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ohttp-e2e-test-{}-{nanos}-{}-{case}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        // Created here, private to this user, and never an existing path: `create` fails if
        // there is one, and nothing is removed first.
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("a new private temporary directory");
        TempDir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

#[cfg(unix)]
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The message of the panic `run` ends in.
#[cfg(unix)]
fn panic_message(run: impl FnOnce() -> Output + std::panic::UnwindSafe) -> String {
    let payload = std::panic::catch_unwind(run).unwrap_err();
    payload
        .downcast_ref::<String>()
        .cloned()
        .unwrap_or_default()
}

/// `script` run by `sh` with the directory `dir` as its first argument.
#[cfg(unix)]
fn sh(script: &str, dir: &TempDir) -> Command {
    let mut command = Command::new("sh");
    command.args(["-c", script, "sh"]).arg(dir.path());
    command
}

/// Ends, when dropped, the descendant whose pid a script wrote to the file `pid` in a
/// directory: on every path out of a test, also a failing one. Nothing is signalled when the
/// file is missing or does not hold a process id above 1, and no error is reported, so that
/// a failure of the test itself is what is shown.
#[cfg(unix)]
struct Descendant(std::path::PathBuf);

#[cfg(unix)]
impl Descendant {
    fn of(dir: &TempDir) -> Descendant {
        Descendant(dir.path().join("pid"))
    }
}

#[cfg(unix)]
impl Drop for Descendant {
    fn drop(&mut self) {
        let Ok(written) = std::fs::read_to_string(&self.0) else {
            return;
        };
        let Ok(pid) = written.trim().parse::<u32>() else {
            return;
        };
        if pid > 1 {
            let _ = Command::new("kill")
                .arg(pid.to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

/// A [`TempDir`] is removed when a panic unwinds past it, with what was written in it.
#[cfg(unix)]
#[test]
fn a_temporary_directory_is_removed_on_unwinding() {
    let created = Mutex::new(None);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let dir = TempDir::new("unwinding");
        std::fs::write(dir.path().join("file"), b"content").unwrap();
        assert!(dir.path().join("file").exists());
        *created.lock().unwrap() = Some(dir.path().to_path_buf());
        panic!("a step failing after the directory was created");
    }));
    assert!(result.is_err());
    let path = created.lock().unwrap().take().expect("the directory");
    assert!(!path.exists(), "{} was left behind", path.display());
}

/// A run that does not exit is killed at the deadline, with a message saying so and what
/// the run wrote until then. The deadline counts from when the script has written its
/// output, so a slow start of `sh` does not change the result.
#[cfg(unix)]
#[test]
fn a_run_past_the_deadline_is_killed() {
    let dir = TempDir::new("deadline");
    let started = Instant::now();
    let message = panic_message(|| {
        run_captured(
            &mut sh(r#"echo partial >&2; : > "$1/ready"; exec sleep 60"#, &dir),
            Some(&dir.path().join("ready")),
            Duration::from_millis(100),
            COLLECT,
        )
    });
    assert!(message.contains("did not exit within"), "{message}");
    assert!(message.contains("stderr: partial\n"), "{message}");
    assert!(!message.contains("still open"), "{message}");
    assert!(started.elapsed() < Duration::from_secs(20));
}

/// A descendant that keeps the output open does not make a run wait for it: past the deadline
/// the run fails within the bound with the output read so far on both streams, marked as
/// still open, and a command that exits while its descendant holds the output fails as well,
/// with its output. The shell starts the descendant and writes its pid before the deadline
/// counts or the command exits; the test ends the descendant on every path.
#[cfg(unix)]
#[test]
fn a_descendant_holding_the_output_does_not_block() {
    let collect = Duration::from_secs(1);
    let started = Instant::now();

    {
        let dir = TempDir::new("descendant-killed");
        let _descendant = Descendant::of(&dir);
        let message = panic_message(|| {
            run_captured(
                &mut sh(
                    r#"sleep 60 & echo $! > "$1/pid"; echo out; echo partial >&2; : > "$1/ready"; wait"#,
                    &dir,
                ),
                Some(&dir.path().join("ready")),
                Duration::from_millis(100),
                collect,
            )
        });
        assert!(message.contains("did not exit within"), "{message}");
        assert!(
            message.contains("stderr: partial\n<still open, a descendant holds it"),
            "{message}"
        );
        assert!(
            message.contains("stdout: out\n<still open, a descendant holds it"),
            "{message}"
        );
    }

    {
        let dir = TempDir::new("descendant-exited");
        let _descendant = Descendant::of(&dir);
        let message = panic_message(|| {
            run_captured(
                &mut sh(r#"sleep 60 & echo $! > "$1/pid"; echo done"#, &dir),
                None,
                DEADLINE,
                collect,
            )
        });
        assert!(
            message.contains("a descendant kept its output open"),
            "{message}"
        );
        assert!(
            message.contains("stdout: done\n<still open, a descendant holds it"),
            "{message}"
        );
    }

    // Both well before either `sleep` ends.
    assert!(started.elapsed() < Duration::from_secs(20));
}

/// `scripts/test-e2e.sh`, run with bash in a copy of the repository layout it expects, the
/// e2e client replaced by a fake that records how it was called.
#[cfg(unix)]
mod script {
    use super::{output_of, text, TempDir};
    use std::ffi::OsStr;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    /// The fake e2e client. It appends one line per run to `record` next to itself (the run's
    /// number, the settings the script exports and its arguments) and answers as the step
    /// expects: inner 200 with grpc-status 0, or inner 403 for the unknown authority. With
    /// `FAKE_FAIL=first` or `FAKE_FAIL=neg` it exits non-zero in that step instead.
    const FAKE: &str = r#"#!/bin/sh
dir=$(dirname "$0")
n=$(cat "$dir/count" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > "$dir/count"
echo "run=$n expect_ok=[${OHTTP_E2E_EXPECT_OK-unset}] plain_http=[${OHTTP_E2E_PLAIN_HTTP_RELAY-unset}] source=[${OHTTP_E2E_KEY_CONFIG_SOURCE-unset}] network=[${NETWORK-unset}] args=$*" >> "$dir/record"
if [ "$3" = evil.example ]; then step=neg; else step=first; fi
if [ "${FAKE_FAIL-}" = "$step" ]; then echo "fake failure"; exit 1; fi
if [ "$step" = first ]; then
  echo "[4] inner response status=200"
  echo "    (trailer) grpc-status: 0"
else
  echo "[4] inner response status=403"
fi
"#;

    /// Whether the variable `name` is kept from the script: one the script, the tool or the
    /// fake reads, one that changes how bash runs the script, or a name that is not Unicode.
    fn cleared(name: &OsStr) -> bool {
        name.to_str().is_none_or(|name| {
            name.starts_with("OHTTP_E2E_")
                || [
                    "NETWORK",
                    "GATEWAY_HOST",
                    "RELAY_URL",
                    "CONFIGS_URL",
                    "RELAY_SIMULATOR",
                    "FAKE_FAIL",
                    // What would change how bash runs the script (a caller's
                    // `SHELLOPTS=xtrace` would trace the URLs).
                    "BASH_ENV",
                    "ENV",
                    "SHELLOPTS",
                    "BASHOPTS",
                    // The prefix of `set -x` lines, run through expansions.
                    "PS4",
                ]
                .contains(&name)
                // Exported functions, which bash imports and could run as commands of the
                // script.
                || name.starts_with("BASH_FUNC_")
        })
    }

    /// The variables that change how bash runs the script are cleared, as are the script's
    /// own; the rest of the environment is inherited.
    #[test]
    fn the_shell_and_script_variables_are_cleared() {
        use std::os::unix::ffi::OsStrExt as _;
        for name in [
            "BASH_ENV",
            "ENV",
            "SHELLOPTS",
            "BASHOPTS",
            "PS4",
            "BASH_FUNC_x%%",
            "BASH_FUNC_echo%%",
            "OHTTP_E2E_EXPECT_OK",
            "NETWORK",
            "RELAY_URL",
        ] {
            assert!(cleared(OsStr::new(name)), "{name}");
        }
        assert!(cleared(OsStr::from_bytes(b"NOT_UNICODE_\xff")));
        for name in [
            "PATH",
            "HOME",
            "BASH",
            "PS1",
            "ENVIRONMENT",
            "MY_BASH_FUNC_x",
        ] {
            assert!(!cleared(OsStr::new(name)), "{name}");
        }
    }

    /// A temporary tree with `scripts/test-e2e.sh` and the fake at
    /// `e2e-client/target/release/ohttp-e2e`, in a [`TempDir`]: removed when dropped, also
    /// when its setup fails after the directory was created.
    struct Tree {
        dir: TempDir,
    }

    impl Tree {
        fn new(case: &str) -> Tree {
            // Owned by the guard from here on: a failing step below removes it on unwinding.
            let dir = TempDir::new(&format!("script-{case}"));
            let root = dir.path();
            let bin_dir = root.join("e2e-client/target/release");
            std::fs::create_dir_all(root.join("scripts")).unwrap();
            std::fs::create_dir_all(&bin_dir).unwrap();
            let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../scripts/test-e2e.sh");
            std::fs::copy(script, root.join("scripts/test-e2e.sh")).unwrap();
            // The executable is written by `cp`, not by this process: a file this process had
            // open for writing could still be open in a child another test is spawning, and
            // executing it would then fail as busy.
            let source = root.join("fake.src");
            std::fs::write(&source, FAKE).unwrap();
            let fake = bin_dir.join("ohttp-e2e");
            let copied = output_of(Command::new("cp").arg(&source).arg(&fake));
            assert!(copied.status.success());
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
            Tree { dir }
        }

        /// The script run with `env` (and none of the variables it, the tool or bash's startup
        /// reads inherited) and the trace id `trace-not-shown`: exit code, stdout, stderr.
        fn run(&self, env: &[(&str, &str)]) -> (Option<i32>, String, String) {
            let mut command = Command::new("bash");
            for (name, _) in std::env::vars_os() {
                let ours = cleared(&name);
                if ours {
                    command.env_remove(name);
                }
            }
            command
                .arg(self.root().join("scripts/test-e2e.sh"))
                .arg("trace-not-shown")
                .env("GATEWAY_HOST", "ohttp-gateway.example");
            for (name, value) in env {
                command.env(name, value);
            }
            let output = output_of(&mut command);
            (
                output.status.code(),
                text(&output.stdout),
                text(&output.stderr),
            )
        }

        fn root(&self) -> &Path {
            self.dir.path()
        }

        /// The fake's record, one line per run; empty when it never ran.
        fn record(&self) -> Vec<String> {
            std::fs::read_to_string(self.root().join("e2e-client/target/release/record"))
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect()
        }
    }

    /// Whether bash can be run; without it the tests pass with a note, except in CI (the
    /// variable `CI` set and not empty), where they fail: the coverage is not lost silently.
    fn bash() -> bool {
        let found = Command::new("bash").arg("--version").output().is_ok();
        if !found {
            let ci = std::env::var_os("CI").is_some_and(|value| !value.is_empty());
            assert!(
                !ci,
                "bash is not on PATH: scripts/test-e2e.sh cannot be tested"
            );
            eprintln!("note: bash is not on PATH, scripts/test-e2e.sh is not tested");
        }
        found
    }

    const RELAY: (&str, &str) = ("RELAY_URL", "https://relay.example/relay");
    const GET_LATEST_BLOCK: &str = "POST /cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock";

    #[test]
    fn a_passing_run_prints_pass_and_neither_url_nor_the_trace_id() {
        if !bash() {
            return;
        }
        let tree = Tree::new("pass");
        let (code, stdout, stderr) = tree.run(&[RELAY]);
        assert_eq!(code, Some(0), "{stdout}{stderr}");
        assert!(stdout.trim_end().ends_with("PASS"), "{stdout}");
        for hidden in ["relay.example", "ohttp-configs", "trace-not-shown"] {
            assert!(
                !stdout.contains(hidden) && !stderr.contains(hidden),
                "{stdout}{stderr}"
            );
        }
        // Both steps ran, with the defaults the script exports.
        assert_eq!(
            tree.record(),
            [
                format!(
                    "run=1 expect_ok=[unset] plain_http=[unset] source=[plain] network=[testnet] \
                     args=https://ohttp-gateway.example/ohttp-configs https://relay.example/relay \
                     ohttp-gateway.example {GET_LATEST_BLOCK} trace-not-shown"
                ),
                format!(
                    "run=2 expect_ok=[] plain_http=[unset] source=[plain] network=[testnet] \
                     args=https://ohttp-gateway.example/ohttp-configs https://relay.example/relay \
                     evil.example {GET_LATEST_BLOCK} trace-not-shown-neg"
                ),
            ]
        );
    }

    #[test]
    fn a_failing_e2e_client_prints_a_fail_line_in_either_step() {
        if !bash() {
            return;
        }
        for (step, line, runs) in [
            (
                "first",
                "FAIL: GetLatestBlock (the e2e client exited non-zero)",
                1,
            ),
            (
                "neg",
                "FAIL: unknown authority (the e2e client exited non-zero)",
                2,
            ),
        ] {
            let tree = Tree::new(&format!("fail-{step}"));
            let (code, stdout, stderr) = tree.run(&[RELAY, ("FAKE_FAIL", step)]);
            assert_eq!(code, Some(1), "{stdout}{stderr}");
            assert!(stdout.contains(line), "{stdout}");
            assert!(stdout.contains("fake failure"), "{stdout}");
            assert!(!stdout.contains("PASS"), "{stdout}");
            assert_eq!(tree.record().len(), runs);
        }
    }

    /// The caller's `OHTTP_E2E_EXPECT_OK=1` reaches the first step only: the expected inner
    /// 403 of the second would otherwise fail the e2e client.
    #[test]
    fn expect_ok_is_emptied_for_the_unknown_authority_step() {
        if !bash() {
            return;
        }
        let tree = Tree::new("expect-ok");
        let (code, stdout, stderr) = tree.run(&[RELAY, ("OHTTP_E2E_EXPECT_OK", "1")]);
        assert_eq!(code, Some(0), "{stdout}{stderr}");
        let record = tree.record();
        assert_eq!(record.len(), 2);
        assert!(record[0].starts_with("run=1 expect_ok=[1] "), "{record:?}");
        assert!(record[1].starts_with("run=2 expect_ok=[] "), "{record:?}");
    }

    #[test]
    fn a_simulator_relay_url_must_end_in_relay_unless_configs_url_is_set() {
        if !bash() {
            return;
        }
        let other_path = ("RELAY_URL", "http://sim.example:8080/x");
        let tree = Tree::new("simulator-path");
        let (code, stdout, stderr) = tree.run(&[other_path, ("RELAY_SIMULATOR", "1")]);
        assert_eq!(code, Some(2), "{stdout}{stderr}");
        assert!(stderr.contains("must end in /relay"), "{stderr}");
        assert!(!stderr.contains("sim.example"), "{stderr}");
        assert!(tree.record().is_empty());
        let (code, stdout, stderr) = tree.run(&[
            other_path,
            ("RELAY_SIMULATOR", "1"),
            ("CONFIGS_URL", "http://sim.example:8080/keys"),
        ]);
        assert_eq!(code, Some(0), "{stdout}{stderr}");
        let record = tree.record();
        assert!(
            record[0].contains(
                " plain_http=[1] source=[plain] network=[testnet] \
                 args=http://sim.example:8080/keys http://sim.example:8080/x "
            ),
            "{record:?}"
        );
    }

    #[test]
    fn the_simulator_is_explicit_or_detected_by_its_name() {
        if !bash() {
            return;
        }
        let named = ("RELAY_URL", "http://relay-simulator.example:8080/relay");
        // Explicitly not a simulator: no plain-HTTP opt-in, the gateway's key configuration.
        let tree = Tree::new("simulator-off");
        let (code, stdout, stderr) = tree.run(&[named, ("RELAY_SIMULATOR", "0")]);
        assert_eq!(code, Some(0), "{stdout}{stderr}");
        assert!(
            tree.record()[0].contains(
                " plain_http=[unset] source=[plain] network=[testnet] \
                 args=https://ohttp-gateway.example/ohttp-configs http://relay-simulator.example"
            ),
            "{:?}",
            tree.record()
        );
        // Unset, empty and auto: detected by the name; 1: whatever the name.
        for (case, env) in [
            ("unset", vec![named]),
            ("empty", vec![named, ("RELAY_SIMULATOR", "")]),
            ("auto", vec![named, ("RELAY_SIMULATOR", "auto")]),
            (
                "one",
                vec![
                    ("RELAY_URL", "http://sim.example:8080/relay"),
                    ("RELAY_SIMULATOR", "1"),
                ],
            ),
        ] {
            let tree = Tree::new(&format!("simulator-{case}"));
            let (code, stdout, stderr) = tree.run(&env);
            assert_eq!(code, Some(0), "{case}: {stdout}{stderr}");
            let record = tree.record();
            assert!(record[0].contains(" plain_http=[1] "), "{case}: {record:?}");
            assert!(
                record[0].contains(":8080/ohttp-configs http://"),
                "{case}: {record:?}"
            );
        }
        // Without the name and without the variable: not a simulator.
        let tree = Tree::new("simulator-unnamed");
        let (code, _, _) = tree.run(&[RELAY]);
        assert_eq!(code, Some(0));
        assert!(tree.record()[0].contains(" plain_http=[unset] "));
    }

    #[test]
    fn an_unknown_relay_simulator_value_is_refused() {
        if !bash() {
            return;
        }
        let tree = Tree::new("simulator-bogus");
        let (code, stdout, stderr) = tree.run(&[RELAY, ("RELAY_SIMULATOR", "bogus")]);
        assert_eq!(code, Some(2), "{stdout}{stderr}");
        assert!(stderr.contains("RELAY_SIMULATOR must be"), "{stderr}");
        assert!(tree.record().is_empty());
    }
}

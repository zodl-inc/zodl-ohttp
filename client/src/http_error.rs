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

//! The transport errors of `Client`, as a kind only.

use std::fmt;

/// What kind of transport failure an [`HttpError`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HttpErrorKind {
    /// No connection could be made (refused, unreachable, name not resolved).
    Connect,
    /// The TLS handshake failed (an untrusted or mismatched certificate, among others).
    Tls,
    /// The exchange did not finish within the timeout.
    Timeout,
    /// The key-configuration URL answered this error status.
    Status(u16),
    /// The key-configuration URL answered with a redirect, which is never followed.
    RedirectRefused,
    /// The answer's body broke off or could not be read.
    Body,
    /// The request could not be built or sent (for example a URL of a scheme other than
    /// `https://` past the constructor's checks).
    Request,
    /// Any other transport failure.
    Other,
}

impl fmt::Display for HttpErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpErrorKind::Connect => f.write_str("could not connect"),
            HttpErrorKind::Tls => f.write_str("TLS handshake failed"),
            HttpErrorKind::Timeout => f.write_str("timed out"),
            HttpErrorKind::Status(status) => write!(f, "status {status}"),
            HttpErrorKind::RedirectRefused => f.write_str("redirect refused"),
            HttpErrorKind::Body => f.write_str("the body broke off"),
            HttpErrorKind::Request => f.write_str("the request could not be sent"),
            HttpErrorKind::Other => f.write_str("transport error"),
        }
    }
}

/// A transport failure of `Client` ([`crate::Error::Http`]).
///
/// Its `Display` and `Debug` give the [`HttpErrorKind`] only: never a URL, host, address, port or
/// the text of the underlying error, so it can be logged. It has no
/// [`std::error::Error::source`], so error-chain printers do not reach the underlying error
/// either; [`HttpError::transport_error_not_log_safe`] hands that out explicitly.
pub struct HttpError {
    kind: HttpErrorKind,
    source: Option<reqwest::Error>,
}

impl HttpError {
    /// What kind of failure this is.
    pub fn kind(&self) -> HttpErrorKind {
        self.kind
    }

    /// The HTTP stack's own error, for debugging on a developer's machine. **Not log-safe:** its
    /// text and its sources can name the relay or key-configuration host, address, port and
    /// URL. `None` for a failure this crate detected itself (a refused redirect).
    pub fn transport_error_not_log_safe(&self) -> Option<&reqwest::Error> {
        self.source.as_ref()
    }

    pub(crate) fn new(kind: HttpErrorKind) -> Self {
        HttpError { kind, source: None }
    }

    pub(crate) fn from_reqwest(error: reqwest::Error) -> Self {
        HttpError {
            kind: classify(&error),
            source: Some(error.without_url()),
        }
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.kind, f)
    }
}

impl fmt::Debug for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl std::error::Error for HttpError {}

fn classify(error: &reqwest::Error) -> HttpErrorKind {
    if error.is_timeout() {
        HttpErrorKind::Timeout
    } else if is_tls(error) {
        HttpErrorKind::Tls
    } else if error.is_connect() {
        HttpErrorKind::Connect
    } else if let Some(status) = error.status() {
        HttpErrorKind::Status(status.as_u16())
    } else if error.is_redirect() {
        HttpErrorKind::RedirectRefused
    } else if error.is_body() || error.is_decode() {
        HttpErrorKind::Body
    } else if error.is_builder() || error.is_request() {
        HttpErrorKind::Request
    } else {
        HttpErrorKind::Other
    }
}

/// Whether a TLS error is somewhere in the chain of `error`: a rustls error, or (for a
/// connection that failed) an `InvalidData` I/O error, which is how the TLS stream reports a
/// failed handshake. An `std::io::Error` that wraps another error is looked into through
/// `get_ref`: its `source` skips the wrapped error itself (the connector wraps the TLS stream's
/// I/O error, which wraps the rustls error).
fn is_tls(error: &reqwest::Error) -> bool {
    let connecting = error.is_connect();
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(error) = current {
        if error.downcast_ref::<rustls::Error>().is_some() {
            return true;
        }
        current = match error.downcast_ref::<std::io::Error>() {
            Some(io) => {
                if connecting && io.kind() == std::io::ErrorKind::InvalidData {
                    return true;
                }
                match io.get_ref() {
                    Some(inner) => Some(inner as &(dyn std::error::Error + 'static)),
                    None => std::error::Error::source(io),
                }
            }
            None => std::error::Error::source(error),
        };
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kind_is_all_an_error_shows() {
        for kind in [
            HttpErrorKind::Connect,
            HttpErrorKind::Tls,
            HttpErrorKind::Timeout,
            HttpErrorKind::Status(404),
            HttpErrorKind::RedirectRefused,
            HttpErrorKind::Body,
            HttpErrorKind::Request,
            HttpErrorKind::Other,
        ] {
            let error = HttpError::new(kind);
            assert_eq!(error.to_string(), kind.to_string());
            assert_eq!(
                format!("{error:?}"),
                format!("HttpError {{ kind: {kind:?}, .. }}")
            );
            assert!(std::error::Error::source(&error).is_none());
            assert!(error.transport_error_not_log_safe().is_none());
        }
    }

    /// A request that cannot be built (a scheme other than `https://` on an https-only stack)
    /// is a kind, and the URL is in neither output.
    #[tokio::test]
    async fn a_refused_scheme_is_a_kind_without_its_url() {
        let http = reqwest::Client::builder().https_only(true).build().unwrap();
        let error = http
            .get("http://keys.example:8080/ohttp-configs/signed")
            .send()
            .await
            .unwrap_err();
        let error = HttpError::from_reqwest(error);
        assert_eq!(error.kind(), HttpErrorKind::Request);
        let shown = format!("{error} {error:?}");
        for part in ["keys.example", "8080", "/ohttp-configs"] {
            assert!(!shown.contains(part), "{shown}");
        }
    }
}

//! A hyper connector that dials through Tor.
//!
//! This is the seam between arti and hyper. It implements
//! [`tower_service::Service<Uri>`], which is exactly what
//! [`hyper_util::client::legacy::Client`] needs, so hypertor gets hyper's real
//! connection pool, keep-alive handling and HTTP/2 support instead of
//! reimplementing them.
//!
//! # Names are never resolved locally
//!
//! The connector always hands the *hostname* to arti and lets the exit relay
//! resolve it. Resolving locally — with `ToSocketAddrs`, a system resolver, or
//! anything else — would send a plaintext DNS query from your real IP for every
//! host you visit, which defeats the entire point of routing the traffic over
//! Tor. This is the single most common way a Tor integration leaks.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use arti_client::{StreamPrefs, TorClient as ArtiClient};
use http::Uri;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;
use tor_rtcompat::PreferredRuntime;
use tracing::debug;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::isolation::IsolationToken;
use crate::stream::TorStream;
use crate::tls::TlsConnector;

/// Where a request is going, in the form hyper hands us.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    pub host: String,
    pub port: u16,
    pub tls: bool,
}

impl Target {
    /// Parse a target out of a URI.
    ///
    /// Rejects anything hypertor cannot carry over Tor rather than guessing.
    pub(crate) fn from_uri(uri: &Uri) -> Result<Self> {
        let scheme = uri
            .scheme_str()
            .ok_or_else(|| Error::invalid_url("URL has no scheme; expected http:// or https://"))?;

        let tls = match scheme {
            "http" => false,
            "https" => true,
            other => {
                return Err(Error::invalid_url(format!(
                    "unsupported scheme `{other}`; expected http:// or https://"
                )));
            }
        };

        let host = uri
            .host()
            .ok_or_else(|| Error::invalid_url("URL has no host"))?;

        // A bracketed IPv6 literal arrives with its brackets; arti wants the
        // bare address.
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();

        if host.is_empty() {
            return Err(Error::invalid_url("URL has an empty host"));
        }

        let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });

        Ok(Self { host, port, tls })
    }

    /// Whether this target is an onion service.
    pub(crate) fn is_onion(&self) -> bool {
        self.host
            .rsplit('.')
            .next()
            .is_some_and(|tld| tld.eq_ignore_ascii_case("onion"))
    }
}

/// Dials Tor streams for hyper.
#[derive(Clone)]
pub(crate) struct TorConnector {
    tor: Arc<ArtiClient<PreferredRuntime>>,
    tls: Option<TlsConnector>,
    config: Arc<Config>,
    /// Isolation applied to every connection this connector makes.
    ///
    /// Requests needing their own isolation get their own connector, so this is
    /// fixed for the connector's lifetime and needs no interior mutability. That
    /// also means hyper's pool key is per-isolation-group, so an isolated
    /// request can never be handed a connection belonging to another group.
    isolation: Option<IsolationToken>,
}

impl TorConnector {
    pub(crate) fn new(
        tor: Arc<ArtiClient<PreferredRuntime>>,
        tls: Option<TlsConnector>,
        config: Arc<Config>,
        isolation: Option<IsolationToken>,
    ) -> Self {
        Self {
            tor,
            tls,
            config,
            isolation,
        }
    }

    async fn dial(self, uri: Uri) -> Result<TorIo> {
        let target = Target::from_uri(&uri)?;

        let mut prefs = StreamPrefs::new();
        if let Some(token) = self.isolation {
            prefs.set_isolation(token.inner());
        }

        // `.onion` targets are already end-to-end encrypted; asking arti to also
        // treat them as onion connections is implicit in the address itself.
        debug!(
            port = target.port,
            tls = target.tls,
            onion = target.is_onion(),
            "opening Tor stream"
        );

        let connect = self
            .tor
            .connect_with_prefs((target.host.as_str(), target.port), &prefs);

        let data_stream = tokio::time::timeout(self.config.connect_timeout, connect)
            .await
            .map_err(|_| Error::timeout("Tor connect", self.config.connect_timeout))?
            .map_err(|e| Error::connect(&target.host, target.port, e))?;

        let stream = if target.tls {
            let tls = self.tls.as_ref().ok_or_else(|| {
                Error::tls("https:// requires a TLS backend; enable the `rustls` feature")
            })?;

            let handshake = tls.connect(data_stream, &target.host);
            tokio::time::timeout(self.config.connect_timeout, handshake)
                .await
                .map_err(|_| Error::timeout("TLS handshake", self.config.connect_timeout))?
        } else {
            Ok(TorStream::plain(data_stream))
        }?;

        let negotiated_h2 = stream.alpn_is_h2();

        Ok(TorIo {
            io: TokioIo::new(stream),
            negotiated_h2,
        })
    }
}

impl tower_service::Service<Uri> for TorConnector {
    type Response = TorIo;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<TorIo>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<()>> {
        // Circuit capacity is arti's concern, and hyper already bounds the
        // number of in-flight connections through its pool.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let this = self.clone();
        Box::pin(this.dial(uri))
    }
}

/// A connected Tor stream, wrapped for hyper.
pub(crate) struct TorIo {
    io: TokioIo<TorStream>,
    negotiated_h2: bool,
}

impl Connection for TorIo {
    fn connected(&self) -> Connected {
        let connected = Connected::new();
        // Tell hyper's pool that this connection speaks HTTP/2, so it
        // multiplexes onto it instead of opening a second circuit.
        if self.negotiated_h2 {
            connected.negotiated_h2()
        } else {
            connected
        }
    }
}

impl Read for TorIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl Write for TorIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(s: &str) -> Uri {
        s.parse().expect("test URI parses")
    }

    #[test]
    fn parses_default_ports() {
        let http = Target::from_uri(&uri("http://example.onion/x")).expect("valid");
        assert_eq!(http.port, 80);
        assert!(!http.tls);

        let https = Target::from_uri(&uri("https://example.com/x")).expect("valid");
        assert_eq!(https.port, 443);
        assert!(https.tls);
    }

    #[test]
    fn honours_explicit_ports() {
        let t = Target::from_uri(&uri("http://example.onion:8080/")).expect("valid");
        assert_eq!(t.port, 8080);
    }

    #[test]
    fn strips_ipv6_brackets_for_arti() {
        let t = Target::from_uri(&uri("http://[::1]:8080/")).expect("valid");
        assert_eq!(t.host, "::1");
    }

    #[test]
    fn rejects_schemes_tor_cannot_carry() {
        // A silently-ignored scheme is how requests end up going somewhere the
        // caller did not intend.
        assert!(Target::from_uri(&uri("ftp://example.com/")).is_err());
        assert!(Target::from_uri(&uri("ws://example.onion/socket")).is_err());
    }

    #[test]
    fn rejects_urls_without_a_scheme_or_host() {
        assert!(Target::from_uri(&uri("/just/a/path")).is_err());
        assert!(Target::from_uri(&uri("example.onion")).is_err());
    }

    #[test]
    fn detects_onion_addresses() {
        assert!(
            Target::from_uri(&uri("http://abc.onion/"))
                .expect("valid")
                .is_onion()
        );
        assert!(
            Target::from_uri(&uri("http://ABC.ONION/"))
                .expect("valid")
                .is_onion()
        );
        assert!(
            !Target::from_uri(&uri("http://onion.example.com/"))
                .expect("valid")
                .is_onion()
        );
        assert!(
            !Target::from_uri(&uri("http://notonion/"))
                .expect("valid")
                .is_onion()
        );
    }
}

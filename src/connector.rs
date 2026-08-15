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

        let target = Self { host, port, tls };
        target.check_onion_address()?;
        Ok(target)
    }

    /// Reject an `.onion` name that cannot possibly resolve.
    ///
    /// arti would refuse these too, but only after the URL has travelled
    /// through the pool and the connector, where the failure reads as a network
    /// problem rather than a typo. The v2 case is worth naming outright: those
    /// addresses used 1024-bit RSA and SHA-1, were retired from the network in
    /// 2021, and someone holding one has stale information rather than a broken
    /// setup.
    fn check_onion_address(&self) -> Result<()> {
        if !self.is_onion() {
            return Ok(());
        }

        let label = self
            .host
            .rsplit_once('.')
            .map(|(label, _)| label)
            .unwrap_or(&self.host);
        // Only the last label before `.onion` is the address itself.
        let label = label.rsplit('.').next().unwrap_or(label);

        // v3 addresses are 56 characters of base32 (a 32-byte key, a 2-byte
        // checksum and a version byte).
        if label.len() == 56
            && label.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)
            })
        {
            return Ok(());
        }

        if label.len() == 16 {
            return Err(Error::invalid_url(
                "this is a version 2 onion address; v2 onion services were \
                 retired from the Tor network in 2021 and cannot be reached. \
                 The service may publish a 56-character v3 address instead",
            ));
        }

        Err(Error::invalid_url(format!(
            "`{label}.onion` is not a valid onion address: expected 56 \
             characters of base32, found {}",
            label.len()
        )))
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

    /// A syntactically valid v3 onion address (56 characters of base32).
    const V3: &str = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad";

    #[test]
    fn parses_default_ports() {
        let http = Target::from_uri(&uri(&format!("http://{V3}.onion/x"))).expect("valid");
        assert_eq!(http.port, 80);
        assert!(!http.tls);

        let https = Target::from_uri(&uri("https://example.com/x")).expect("valid");
        assert_eq!(https.port, 443);
        assert!(https.tls);
    }

    #[test]
    fn honours_explicit_ports() {
        let t = Target::from_uri(&uri(&format!("http://{V3}.onion:8080/"))).expect("valid");
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
        assert!(Target::from_uri(&uri(&format!("ws://{V3}.onion/socket"))).is_err());
    }

    #[test]
    fn rejects_urls_without_a_scheme_or_host() {
        assert!(Target::from_uri(&uri("/just/a/path")).is_err());
        assert!(Target::from_uri(&uri("example.onion")).is_err());
    }

    #[test]
    fn detects_onion_addresses() {
        assert!(
            Target::from_uri(&uri(&format!("http://{V3}.onion/")))
                .expect("valid")
                .is_onion()
        );
        assert!(
            Target::from_uri(&uri(&format!("http://{}.ONION/", V3.to_uppercase())))
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

    #[test]
    fn a_v3_onion_address_with_a_subdomain_is_accepted() {
        // Onion services routinely publish virtual hosts under the address.
        assert!(Target::from_uri(&uri(&format!("http://www.{V3}.onion/"))).is_ok());
    }

    #[test]
    fn version_2_onion_addresses_are_refused_by_name() {
        // v2 used 1024-bit RSA and SHA-1 and left the network in 2021. Letting
        // it fail as a connection error would send the caller looking for a
        // network problem that does not exist.
        let err = Target::from_uri(&uri("http://expyuzz4wqqyqhjn.onion/")).expect_err("refused");
        assert!(err.to_string().contains("version 2"), "unhelpful: {err}");
    }

    #[test]
    fn a_malformed_onion_address_is_refused_before_a_circuit_is_built() {
        // Otherwise the typo surfaces seconds later as an opaque connect
        // failure, having cost a circuit.
        for bad in ["http://nonsense.onion/", "http://TOO-SHORT.onion/"] {
            assert!(Target::from_uri(&uri(bad)).is_err(), "should refuse {bad}");
        }
    }
}

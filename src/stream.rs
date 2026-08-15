//! A Tor stream, optionally wrapped in TLS.
//!
//! Enum dispatch rather than `Box<dyn>`: no allocation for the wrapper and the
//! compiler can inline through it.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use arti_client::DataStream;
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// `pin_project!` cannot apply `#[cfg]` to individual variants, so the enum is
// declared once per TLS backend. Exactly one of these is ever compiled.

#[cfg(feature = "rustls")]
pin_project! {
    /// A byte stream carried over the Tor network.
    ///
    /// `Plain` is already anonymised and, for `.onion` targets, also encrypted
    /// and authenticated end-to-end by Tor itself. The TLS variant adds
    /// certificate-authenticated encryption for clearnet targets, which is
    /// necessary because the exit relay would otherwise see the plaintext.
    #[project = TorStreamProj]
    #[allow(missing_docs)]
    pub enum TorStream {
        /// An unwrapped Tor stream.
        Plain {
            #[pin]
            inner: DataStream,
        },
        /// A TLS session over a Tor stream.
        Tls {
            #[pin]
            inner: Box<tokio_rustls::client::TlsStream<DataStream>>,
        },
    }
}

#[cfg(all(feature = "native-tls", not(feature = "rustls")))]
pin_project! {
    /// A byte stream carried over the Tor network.
    #[project = TorStreamProj]
    #[allow(missing_docs)]
    pub enum TorStream {
        /// An unwrapped Tor stream.
        Plain {
            #[pin]
            inner: DataStream,
        },
        /// A TLS session over a Tor stream.
        Tls {
            #[pin]
            inner: Box<tokio_native_tls::TlsStream<DataStream>>,
        },
    }
}

#[cfg(not(any(feature = "rustls", feature = "native-tls")))]
pin_project! {
    /// A byte stream carried over the Tor network.
    #[project = TorStreamProj]
    #[allow(missing_docs)]
    pub enum TorStream {
        /// An unwrapped Tor stream.
        Plain {
            #[pin]
            inner: DataStream,
        },
    }
}

impl TorStream {
    /// Wrap a raw Tor stream.
    pub fn plain(stream: DataStream) -> Self {
        Self::Plain { inner: stream }
    }

    /// Wrap a completed rustls session.
    #[cfg(feature = "rustls")]
    pub fn rustls(stream: tokio_rustls::client::TlsStream<DataStream>) -> Self {
        Self::Tls {
            inner: Box::new(stream),
        }
    }

    /// Wrap a completed native-tls session.
    #[cfg(all(feature = "native-tls", not(feature = "rustls")))]
    pub fn native_tls(stream: tokio_native_tls::TlsStream<DataStream>) -> Self {
        Self::Tls {
            inner: Box::new(stream),
        }
    }

    /// Whether this stream is TLS-encrypted in addition to being carried by Tor.
    pub fn is_tls(&self) -> bool {
        !matches!(self, Self::Plain { .. })
    }

    /// Whether the TLS handshake negotiated HTTP/2 via ALPN.
    ///
    /// Always `false` for plain streams: without TLS there is no ALPN, so h2
    /// would require prior knowledge, which hypertor does not assume.
    pub fn alpn_is_h2(&self) -> bool {
        match self {
            Self::Plain { .. } => false,
            #[cfg(feature = "rustls")]
            Self::Tls { inner } => inner.get_ref().1.alpn_protocol() == Some(b"h2"),
            // native-tls exposes no ALPN accessor.
            #[cfg(all(feature = "native-tls", not(feature = "rustls")))]
            Self::Tls { .. } => false,
        }
    }
}

impl std::fmt::Debug for TorStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TorStream")
            .field("tls", &self.is_tls())
            .finish_non_exhaustive()
    }
}

impl AsyncRead for TorStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.project() {
            TorStreamProj::Plain { inner } => inner.poll_read(cx, buf),
            #[cfg(any(feature = "rustls", feature = "native-tls"))]
            TorStreamProj::Tls { inner } => inner.poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TorStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.project() {
            TorStreamProj::Plain { inner } => inner.poll_write(cx, buf),
            #[cfg(any(feature = "rustls", feature = "native-tls"))]
            TorStreamProj::Tls { inner } => inner.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            TorStreamProj::Plain { inner } => inner.poll_flush(cx),
            #[cfg(any(feature = "rustls", feature = "native-tls"))]
            TorStreamProj::Tls { inner } => inner.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            TorStreamProj::Plain { inner } => inner.poll_shutdown(cx),
            #[cfg(any(feature = "rustls", feature = "native-tls"))]
            TorStreamProj::Tls { inner } => inner.poll_shutdown(cx),
        }
    }
}

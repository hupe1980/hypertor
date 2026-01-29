//! Zero-cost stream abstraction using enum dispatch
//!
//! This module provides a unified stream type that can be either:
//! - Plain TCP over Tor (for HTTP)
//! - TLS-wrapped TCP over Tor (for HTTPS)
//!
//! Using an enum instead of `Box<dyn>` enables:
//! - Zero heap allocation for the wrapper itself
//! - Compile-time dispatch optimization
//! - Better inlining opportunities
//!
//! # TLS Backend Priority
//!
//! When both `rustls` and `native-tls` features are enabled, **rustls takes priority**
//! for better anonymity (consistent TLS fingerprint across platforms).

use arti_client::DataStream;
use pin_project_lite::pin_project;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(all(feature = "native-tls", not(feature = "rustls")))]
use tokio_native_tls::TlsStream as NativeTlsStream;

#[cfg(feature = "rustls")]
use tokio_rustls::client::TlsStream as RustlsStream;

// PRIORITY: rustls > native-tls (for consistent TLS fingerprinting)
// When rustls is enabled, use it regardless of native-tls
#[cfg(feature = "rustls")]
pin_project! {
    /// A stream that can be either plain or TLS-encrypted (rustls backend)
    #[project = TorStreamProj]
    #[allow(missing_docs)]
    pub enum TorStream {
        Plain {
            #[pin]
            inner: DataStream,
        },
        Rustls {
            #[pin]
            inner: RustlsStream<DataStream>,
        },
    }
}

// Only use native-tls when rustls is NOT enabled
#[cfg(all(feature = "native-tls", not(feature = "rustls")))]
pin_project! {
    /// A stream that can be either plain or TLS-encrypted (native-tls backend)
    #[project = TorStreamProj]
    #[allow(missing_docs)]
    pub enum TorStream {
        Plain {
            #[pin]
            inner: DataStream,
        },
        NativeTls {
            #[pin]
            inner: NativeTlsStream<DataStream>,
        },
    }
}

#[cfg(not(any(feature = "native-tls", feature = "rustls")))]
pin_project! {
    /// A stream that can be either plain or TLS-encrypted (no TLS backend)
    #[project = TorStreamProj]
    #[allow(missing_docs)]
    pub enum TorStream {
        Plain {
            #[pin]
            inner: DataStream,
        },
    }
}

impl TorStream {
    /// Create a new plain (non-TLS) stream
    pub fn plain(stream: DataStream) -> Self {
        Self::Plain { inner: stream }
    }

    /// Create a new TLS stream using native-tls
    #[cfg(all(feature = "native-tls", not(feature = "rustls")))]
    pub fn native_tls(stream: NativeTlsStream<DataStream>) -> Self {
        Self::NativeTls { inner: stream }
    }

    /// Create a new TLS stream using rustls
    #[cfg(feature = "rustls")]
    pub fn rustls(stream: RustlsStream<DataStream>) -> Self {
        Self::Rustls { inner: stream }
    }

    /// Returns true if this is a TLS-encrypted stream
    pub fn is_tls(&self) -> bool {
        match self {
            Self::Plain { .. } => false,
            #[cfg(all(feature = "native-tls", not(feature = "rustls")))]
            Self::NativeTls { .. } => true,
            #[cfg(feature = "rustls")]
            Self::Rustls { .. } => true,
        }
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
            #[cfg(all(feature = "native-tls", not(feature = "rustls")))]
            TorStreamProj::NativeTls { inner } => inner.poll_read(cx, buf),
            #[cfg(feature = "rustls")]
            TorStreamProj::Rustls { inner } => inner.poll_read(cx, buf),
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
            #[cfg(all(feature = "native-tls", not(feature = "rustls")))]
            TorStreamProj::NativeTls { inner } => inner.poll_write(cx, buf),
            #[cfg(feature = "rustls")]
            TorStreamProj::Rustls { inner } => inner.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            TorStreamProj::Plain { inner } => inner.poll_flush(cx),
            #[cfg(all(feature = "native-tls", not(feature = "rustls")))]
            TorStreamProj::NativeTls { inner } => inner.poll_flush(cx),
            #[cfg(feature = "rustls")]
            TorStreamProj::Rustls { inner } => inner.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            TorStreamProj::Plain { inner } => inner.poll_shutdown(cx),
            #[cfg(all(feature = "native-tls", not(feature = "rustls")))]
            TorStreamProj::NativeTls { inner } => inner.poll_shutdown(cx),
            #[cfg(feature = "rustls")]
            TorStreamProj::Rustls { inner } => inner.poll_shutdown(cx),
        }
    }
}

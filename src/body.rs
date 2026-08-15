//! Request bodies, and response body decoding.
//!
//! # Response bodies are decoded while they stream
//!
//! A few kilobytes of gzip can expand to gigabytes. hypertor therefore never
//! decompresses a buffer and then checks its size — it decompresses
//! incrementally and stops the moment the *decoded* output crosses the limit,
//! so a decompression bomb costs the limit and not a byte more. The same
//! machinery serves both the buffered [`Response`](crate::Response) and the
//! streaming [`Streaming`](crate::response::Streaming) API, so there is exactly
//! one place where this can be got wrong.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures::Stream;
use http::HeaderValue;
use http::header::CONTENT_ENCODING;
use http_body::{Frame, SizeHint};

use crate::error::{BoxedError, Error, Result};

// ===========================================================================
// Request bodies
// ===========================================================================

/// The body of an outgoing request.
///
/// Small bodies — JSON, forms, text — are held in memory and are therefore
/// *replayable*: hypertor can send them again on a new connection. A streaming
/// body can only be sent once, so a request carrying one is never retried
/// automatically, and cannot be replayed across a `307` either. Over Tor that
/// distinction matters more than elsewhere, because a retry is the normal
/// response to a bad relay.
///
/// ```rust,no_run
/// use hypertor::Body;
///
/// # async fn demo(client: &hypertor::TorClient) -> hypertor::Result<()> {
/// // In memory: retryable.
/// client.post("http://api.onion/items")?.json(&"payload").send().await?;
///
/// // Streamed from disk: never buffered, never retried.
/// client
///     .post("http://api.onion/upload")?
///     .body(Body::from_file("./large.bin").await?)
///     .send()
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct Body {
    kind: Kind,
}

enum Kind {
    /// Fully in memory, and therefore replayable.
    Bytes(Bytes),
    /// Produced lazily; can be sent exactly once.
    Stream {
        inner: Pin<Box<dyn Stream<Item = std::result::Result<Bytes, BoxedError>> + Send>>,
        size: Option<u64>,
    },
}

impl Body {
    /// An empty body.
    pub fn empty() -> Self {
        Self {
            kind: Kind::Bytes(Bytes::new()),
        }
    }

    /// A body held entirely in memory.
    pub fn bytes(data: impl Into<Bytes>) -> Self {
        Self {
            kind: Kind::Bytes(data.into()),
        }
    }

    /// A body streamed from a fallible stream of chunks.
    ///
    /// The length is unknown, so the request is sent with chunked transfer
    /// encoding on HTTP/1.1. Use [`sized_stream`](Self::sized_stream) when you
    /// know the length and want a `Content-Length` instead.
    pub fn from_stream<S, B, E>(stream: S) -> Self
    where
        S: Stream<Item = std::result::Result<B, E>> + Send + 'static,
        B: Into<Bytes>,
        E: Into<BoxedError>,
    {
        Self::stream_inner(stream, None)
    }

    /// A body streamed from a stream of chunks whose total length is known.
    ///
    /// `size` is sent as the `Content-Length`. A stream that yields a different
    /// number of bytes produces a malformed request, so only use this when the
    /// length is certain.
    pub fn sized_stream<S, B, E>(stream: S, size: u64) -> Self
    where
        S: Stream<Item = std::result::Result<B, E>> + Send + 'static,
        B: Into<Bytes>,
        E: Into<BoxedError>,
    {
        Self::stream_inner(stream, Some(size))
    }

    fn stream_inner<S, B, E>(stream: S, size: Option<u64>) -> Self
    where
        S: Stream<Item = std::result::Result<B, E>> + Send + 'static,
        B: Into<Bytes>,
        E: Into<BoxedError>,
    {
        use futures::StreamExt;

        Self {
            kind: Kind::Stream {
                inner: Box::pin(stream.map(|item| item.map(Into::into).map_err(Into::into))),
                size,
            },
        }
    }

    /// Stream a file from disk without reading it into memory.
    ///
    /// The file's length is read up front and sent as the `Content-Length`.
    /// Fails if the file cannot be opened.
    pub async fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let file = tokio::fs::File::open(path.as_ref()).await?;
        let size = file.metadata().await?.len();
        let stream = tokio_util::io::ReaderStream::new(file);
        Ok(Self::sized_stream(stream, size))
    }

    /// Whether this body can be sent more than once.
    ///
    /// Only in-memory bodies can. hypertor uses this to decide whether a
    /// request may be retried at all, and whether it may be replayed across a
    /// `307`/`308` redirect.
    pub fn is_replayable(&self) -> bool {
        matches!(self.kind, Kind::Bytes(_))
    }

    /// The body's length, when it is known before sending.
    pub fn len(&self) -> Option<u64> {
        match &self.kind {
            Kind::Bytes(bytes) => Some(bytes.len() as u64),
            Kind::Stream { size, .. } => *size,
        }
    }

    /// Whether this body is known to be empty.
    pub fn is_empty(&self) -> bool {
        self.len() == Some(0)
    }

    /// Clone this body if it is replayable.
    pub(crate) fn try_clone(&self) -> Option<Self> {
        match &self.kind {
            Kind::Bytes(bytes) => Some(Self::bytes(bytes.clone())),
            Kind::Stream { .. } => None,
        }
    }
}

impl Default for Body {
    fn default() -> Self {
        Self::empty()
    }
}

impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Body")
            .field("replayable", &self.is_replayable())
            .field("len", &self.len())
            .finish()
    }
}

impl From<Bytes> for Body {
    fn from(value: Bytes) -> Self {
        Self::bytes(value)
    }
}

impl From<Vec<u8>> for Body {
    fn from(value: Vec<u8>) -> Self {
        Self::bytes(value)
    }
}

impl From<&'static [u8]> for Body {
    fn from(value: &'static [u8]) -> Self {
        Self::bytes(Bytes::from_static(value))
    }
}

impl From<String> for Body {
    fn from(value: String) -> Self {
        Self::bytes(value.into_bytes())
    }
}

impl From<&'static str> for Body {
    fn from(value: &'static str) -> Self {
        Self::bytes(Bytes::from_static(value.as_bytes()))
    }
}

impl http_body::Body for Body {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, Error>>> {
        match &mut self.as_mut().get_mut().kind {
            Kind::Bytes(bytes) => {
                if bytes.is_empty() {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Ok(Frame::data(std::mem::take(bytes)))))
                }
            }
            Kind::Stream { inner, .. } => match inner.as_mut().poll_next(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Ready(Some(Ok(chunk))) => Poll::Ready(Some(Ok(Frame::data(chunk)))),
                Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(Error::Body {
                    message: "the request body stream failed".into(),
                    source: Some(e),
                }))),
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.kind {
            Kind::Bytes(bytes) => bytes.is_empty(),
            Kind::Stream { .. } => false,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self.len() {
            Some(len) => SizeHint::with_exact(len),
            None => SizeHint::default(),
        }
    }
}

// ===========================================================================
// Content encodings
// ===========================================================================

/// Content encodings hypertor can decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Encoding {
    /// No encoding.
    #[default]
    Identity,
    /// RFC 1952 gzip.
    Gzip,
    /// RFC 1950 zlib, as sent by servers for `deflate`.
    Deflate,
    /// RFC 7932 Brotli.
    Brotli,
    /// RFC 8878 Zstandard.
    Zstd,
}

impl Encoding {
    /// The value hypertor sends in `Accept-Encoding`.
    ///
    /// The order matches what Firefox 128 ESR sends, because
    /// [`DEFAULT_USER_AGENT`](crate::DEFAULT_USER_AGENT) claims to be Firefox
    /// 128 ESR. Advertising the same set in a different order would be a free
    /// distinguisher: it costs nothing to fix and nothing to keep, and an
    /// inconsistency between what a client says it is and how it behaves is
    /// exactly what fingerprinting looks for.
    ///
    /// See the `tls` module for why this only goes so far — hypertor is a
    /// library, not a browser, and does not claim otherwise.
    pub fn accept_encoding() -> HeaderValue {
        HeaderValue::from_static("gzip, deflate, br, zstd")
    }

    /// Parse a single `Content-Encoding` token.
    fn parse(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "gzip" | "x-gzip" => Some(Self::Gzip),
            "deflate" => Some(Self::Deflate),
            "br" => Some(Self::Brotli),
            "zstd" => Some(Self::Zstd),
            "identity" => Some(Self::Identity),
            _ => None,
        }
    }

    /// The encoding named by a response's `Content-Encoding` header.
    ///
    /// Only a single encoding is supported. A stacked encoding such as
    /// `gzip, br` is refused rather than half-decoded, because handing the
    /// caller bytes that look like a body but are still compressed is worse
    /// than an error.
    ///
    /// # Every header line is considered, not just the first
    ///
    /// RFC 9110 §5.2 makes repeated field lines equivalent to one line whose
    /// value is their comma-joined concatenation, and `HeaderMap` keeps them
    /// separate rather than joining them. Reading only the first line — the
    /// obvious `headers.get(..)` — meant a server sending
    ///
    /// ```text
    /// Content-Encoding: gzip
    /// Content-Encoding: br
    /// ```
    ///
    /// was seen as plain `gzip`: the stacked-encoding refusal below was
    /// bypassed, and the caller received gunzipped bytes that were still
    /// Brotli-compressed. That is precisely the outcome this function exists to
    /// prevent, so the check has to span all the lines that make up the field.
    pub fn from_headers(headers: &http::HeaderMap) -> Result<Self> {
        // Collected across every line of the field, so `gzip, br` and two
        // separate `gzip` / `br` lines are read the same way.
        let mut tokens = Vec::new();
        for value in headers.get_all(CONTENT_ENCODING) {
            let value = value
                .to_str()
                .map_err(|_| Error::decode("Content-Encoding is not valid ASCII"))?;
            tokens.extend(
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|t| !t.is_empty() && !t.eq_ignore_ascii_case("identity")),
            );
        }

        match tokens.as_slice() {
            [] => Ok(Self::Identity),
            [only] => Self::parse(only)
                .ok_or_else(|| Error::decode(format!("unsupported Content-Encoding `{only}`"))),
            stacked => Err(Error::decode(format!(
                "stacked Content-Encoding `{}` is not supported",
                stacked.join(", ")
            ))),
        }
    }
}

// ===========================================================================
// Response body decoding
// ===========================================================================

/// A stream of decoded response body chunks, bounded by a byte limit.
///
/// Decompression happens incrementally, so an oversized body — compressed or
/// not — is abandoned at the limit instead of being buffered first.
pub(crate) struct Decoder {
    inner: Pin<Box<dyn Stream<Item = std::io::Result<Bytes>> + Send>>,
    /// Decoded bytes still allowed through before the limit trips.
    remaining: usize,
    limit: usize,
    seen: usize,
}

impl Decoder {
    /// Wrap a response body, decoding `encoding` and enforcing `limit`.
    pub(crate) fn new<B>(body: B, encoding: Encoding, limit: usize) -> Self
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        use futures::StreamExt;
        use tokio_util::io::{ReaderStream, StreamReader};

        let raw = http_body_util::BodyStream::new(body).filter_map(|frame| async move {
            match frame {
                Ok(frame) => frame.into_data().ok().map(Ok),
                Err(e) => Some(Err(std::io::Error::other(e))),
            }
        });

        let inner: Pin<Box<dyn Stream<Item = std::io::Result<Bytes>> + Send>> = match encoding {
            Encoding::Identity => Box::pin(raw),
            other => {
                use async_compression::tokio::bufread;
                let reader = StreamReader::new(raw);
                match other {
                    Encoding::Gzip => {
                        Box::pin(ReaderStream::new(bufread::GzipDecoder::new(reader)))
                    }
                    Encoding::Deflate => {
                        Box::pin(ReaderStream::new(bufread::ZlibDecoder::new(reader)))
                    }
                    Encoding::Brotli => {
                        Box::pin(ReaderStream::new(bufread::BrotliDecoder::new(reader)))
                    }
                    Encoding::Zstd => {
                        Box::pin(ReaderStream::new(bufread::ZstdDecoder::new(reader)))
                    }
                    Encoding::Identity => unreachable!("handled above"),
                }
            }
        };

        Self {
            inner,
            remaining: limit,
            limit,
            seen: 0,
        }
    }

    /// The next decoded chunk, or `None` at the end of the body.
    pub(crate) async fn chunk(&mut self) -> Result<Option<Bytes>> {
        use futures::StreamExt;

        match self.inner.next().await {
            None => Ok(None),
            Some(Err(e)) => Err(Error::decode(format!("could not read response body: {e}"))),
            Some(Ok(chunk)) => {
                self.seen = self.seen.saturating_add(chunk.len());
                if chunk.len() > self.remaining {
                    return Err(Error::BodyTooLarge {
                        size: self.seen,
                        limit: self.limit,
                    });
                }
                self.remaining -= chunk.len();
                Ok(Some(chunk))
            }
        }
    }

    /// Drain the whole body into memory, respecting the limit.
    pub(crate) async fn collect(mut self) -> Result<Bytes> {
        use bytes::BufMut;

        // One chunk is the common case for small bodies; avoid the copy.
        let Some(first) = self.chunk().await? else {
            return Ok(Bytes::new());
        };
        let Some(second) = self.chunk().await? else {
            return Ok(first);
        };

        let mut buf = bytes::BytesMut::with_capacity(first.len() + second.len());
        buf.put(first);
        buf.put(second);
        while let Some(chunk) = self.chunk().await? {
            buf.put(chunk);
        }
        Ok(buf.freeze())
    }
}

// ===========================================================================
// Encoding helpers
// ===========================================================================

/// Percent-encode pairs using `application/x-www-form-urlencoded` rules.
pub fn form_encode(pairs: impl IntoIterator<Item = (impl AsRef<str>, impl AsRef<str>)>) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        serializer.append_pair(k.as_ref(), v.as_ref());
    }
    serializer.finish()
}

/// Build an HTTP Basic `Authorization` header value.
pub fn basic_auth(username: &str, password: &str) -> Result<HeaderValue> {
    use base64::Engine;

    let encoded =
        base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));

    let mut value = HeaderValue::from_str(&format!("Basic {encoded}"))
        .map_err(|_| Error::invalid_request("credentials are not valid in an HTTP header"))?;
    value.set_sensitive(true);
    Ok(value)
}

/// Build a Bearer `Authorization` header value.
pub fn bearer_auth(token: &str) -> Result<HeaderValue> {
    let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| Error::invalid_request("token is not valid in an HTTP header"))?;
    value.set_sensitive(true);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;
    use http_body_util::Full;

    fn headers_with(encoding: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(CONTENT_ENCODING, HeaderValue::from_str(encoding).unwrap());
        h
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    async fn decode(data: Vec<u8>, encoding: Encoding, limit: usize) -> Result<Bytes> {
        Decoder::new(Full::new(Bytes::from(data)), encoding, limit)
            .collect()
            .await
    }

    // ---- content-encoding negotiation --------------------------------------

    #[test]
    fn identity_when_no_header() {
        assert_eq!(
            Encoding::from_headers(&HeaderMap::new()).unwrap(),
            Encoding::Identity
        );
    }

    #[test]
    fn recognises_supported_encodings() {
        for (header, expected) in [
            ("gzip", Encoding::Gzip),
            ("GZIP", Encoding::Gzip),
            ("br", Encoding::Brotli),
            ("zstd", Encoding::Zstd),
            ("deflate", Encoding::Deflate),
            ("identity", Encoding::Identity),
        ] {
            assert_eq!(
                Encoding::from_headers(&headers_with(header)).unwrap(),
                expected,
                "header: {header}"
            );
        }
    }

    #[test]
    fn accept_encoding_matches_the_user_agent_it_claims_to_be() {
        // The default User-Agent claims Firefox 128 ESR. Announcing the same
        // encodings in a different order than Firefox does is a distinguisher
        // that costs nothing to avoid.
        assert_eq!(
            Encoding::accept_encoding().to_str().unwrap(),
            "gzip, deflate, br, zstd"
        );
        assert!(
            crate::DEFAULT_USER_AGENT.contains("Firefox/128"),
            "if the default UA changes, revisit the encoding order with it"
        );
    }

    #[test]
    fn every_advertised_encoding_can_actually_be_decoded() {
        // Asking for something we cannot decode turns a normal response into a
        // hard error for no benefit.
        for token in Encoding::accept_encoding().to_str().unwrap().split(',') {
            assert!(
                Encoding::parse(token).is_some(),
                "advertised `{token}` but cannot decode it"
            );
        }
    }

    #[test]
    fn rejects_stacked_and_unknown_encodings() {
        // Half-decoding is worse than refusing: the caller would get bytes that
        // look like a body but are still compressed.
        assert!(Encoding::from_headers(&headers_with("gzip, br")).is_err());
        assert!(Encoding::from_headers(&headers_with("exotic")).is_err());
    }

    #[test]
    fn a_stacked_encoding_split_across_header_lines_is_still_refused() {
        // RFC 9110 §5.2: repeated field lines mean the comma-joined value, and
        // `HeaderMap` keeps them apart rather than joining them. Reading only
        // the first line saw plain `gzip` here, gunzipped the body, and handed
        // back bytes that were still Brotli-compressed — the exact outcome the
        // stacked-encoding refusal exists to prevent, reachable by any server
        // that spells the field over two lines.
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        headers.append(CONTENT_ENCODING, HeaderValue::from_static("br"));

        let err = Encoding::from_headers(&headers).expect_err("must refuse");
        assert!(err.to_string().contains("stacked"), "unhelpful: {err}");
    }

    #[test]
    fn identity_lines_do_not_make_an_encoding_look_stacked() {
        // `identity` is the absence of an encoding, so it must not count
        // towards the one-encoding budget however it is spelled.
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_ENCODING, HeaderValue::from_static("identity"));
        headers.append(CONTENT_ENCODING, HeaderValue::from_static("gzip"));

        assert_eq!(Encoding::from_headers(&headers).unwrap(), Encoding::Gzip);
    }

    // ---- streaming decode --------------------------------------------------

    #[tokio::test]
    async fn round_trips_gzip() {
        let out = decode(gzip(b"hello over tor"), Encoding::Gzip, 1024)
            .await
            .unwrap();
        assert_eq!(&out[..], b"hello over tor");
    }

    #[tokio::test]
    async fn decompression_bomb_is_stopped_at_the_limit() {
        // 32 MiB of zeroes compresses to a few KiB. The decoder must give up at
        // the limit rather than materialising the whole expansion first.
        let bomb = gzip(&vec![0u8; 32 * 1024 * 1024]);
        assert!(bomb.len() < 64 * 1024, "test fixture should be small");

        let err = decode(bomb, Encoding::Gzip, 1024).await.unwrap_err();
        assert!(matches!(err, Error::BodyTooLarge { limit: 1024, .. }));
    }

    #[tokio::test]
    async fn body_exactly_at_the_limit_is_accepted() {
        let out = decode(gzip(&vec![b'x'; 1024]), Encoding::Gzip, 1024)
            .await
            .unwrap();
        assert_eq!(out.len(), 1024);
    }

    #[tokio::test]
    async fn malformed_bodies_error_rather_than_returning_garbage() {
        assert!(
            decode(b"not gzip at all".to_vec(), Encoding::Gzip, 1024)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn identity_bodies_pass_through() {
        let out = decode(b"plain".to_vec(), Encoding::Identity, 1024)
            .await
            .unwrap();
        assert_eq!(&out[..], b"plain");
    }

    // ---- request bodies ----------------------------------------------------

    #[test]
    fn in_memory_bodies_are_replayable() {
        let body = Body::bytes("hello");
        assert!(body.is_replayable());
        assert_eq!(body.len(), Some(5));
        assert!(body.try_clone().is_some());
    }

    #[test]
    fn streaming_bodies_are_not_replayable() {
        // Retrying a consumed stream would send a truncated request, so the
        // client must know not to try.
        let body = Body::from_stream(futures::stream::once(async {
            Ok::<_, std::io::Error>(Bytes::from_static(b"x"))
        }));
        assert!(!body.is_replayable());
        assert_eq!(body.len(), None);
        assert!(body.try_clone().is_none());
    }

    #[tokio::test]
    async fn streaming_bodies_yield_their_chunks() {
        use http_body_util::BodyExt;

        let body = Body::from_stream(futures::stream::iter([
            Ok::<_, std::io::Error>(Bytes::from_static(b"one ")),
            Ok(Bytes::from_static(b"two")),
        ]));

        let collected = body.collect().await.expect("collects").to_bytes();
        assert_eq!(&collected[..], b"one two");
    }

    #[tokio::test]
    async fn file_bodies_report_their_length() {
        let path = std::env::temp_dir().join("hypertor-body-file-test");
        tokio::fs::write(&path, b"file contents").await.unwrap();

        let body = Body::from_file(&path).await.expect("opens");
        assert_eq!(body.len(), Some(13));
        assert!(!body.is_replayable());

        tokio::fs::remove_file(&path).await.ok();
    }

    // ---- encoding helpers --------------------------------------------------

    #[test]
    fn form_encoding_escapes_separators() {
        let encoded = form_encode([("q", "rust & tor"), ("page", "1")]);
        assert_eq!(encoded, "q=rust+%26+tor&page=1");
    }

    #[test]
    fn auth_headers_are_marked_sensitive() {
        // Marking these sensitive keeps them out of HPACK's shared compression
        // table, where they would otherwise be a cross-request oracle.
        assert!(basic_auth("user", "pass").unwrap().is_sensitive());
        assert!(bearer_auth("tok").unwrap().is_sensitive());
    }

    #[test]
    fn basic_auth_matches_rfc7617() {
        let value = basic_auth("user", "pass").unwrap();
        assert_eq!(value.to_str().unwrap(), "Basic dXNlcjpwYXNz");
    }

    #[test]
    fn header_injection_via_credentials_is_rejected() {
        assert!(bearer_auth("tok\r\nX-Admin: 1").is_err());
    }
}

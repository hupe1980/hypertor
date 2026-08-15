//! HTTP responses.
//!
//! Two shapes, for the two things people actually do:
//!
//! - [`Response`] — the body is already read into memory, bounded by
//!   `max_response_size`. This is what [`send`](crate::RequestBuilder::send)
//!   returns, and what you want for an API call.
//! - [`Streaming`] — the headers have arrived and the body is still on the
//!   wire. This is what [`send_streaming`](crate::RequestBuilder::send_streaming)
//!   returns, and what you want for a download that should not be held in
//!   memory all at once.
//!
//! Both decode `Content-Encoding` incrementally, so the size limit bounds the
//! *decompressed* body in either case.

use bytes::Bytes;
use futures::Stream;
use http::{HeaderMap, StatusCode, Version};

use crate::body::{Decoder, Encoding};
use crate::error::{Error, Result};

/// Status, version and headers — everything that arrives before the body.
///
/// Deliberately crate-private: the redirect machinery needs to be generic over
/// [`Response`] and [`Streaming`], but making callers import a trait to reach
/// `status()` would be a tax on every single use of this library. Both types
/// carry the same methods inherently.
pub(crate) trait Head {
    fn status(&self) -> StatusCode;
    fn headers(&self) -> &HeaderMap;
}

/// The accessors shared by both response types.
macro_rules! head_accessors {
    () => {
        /// The status code.
        pub fn status(&self) -> StatusCode {
            self.status
        }

        /// The HTTP version the response was received over.
        pub fn version(&self) -> Version {
            self.version
        }

        /// The response headers.
        pub fn headers(&self) -> &HeaderMap {
            &self.headers
        }

        /// A single header value, if present and valid ASCII.
        pub fn header(&self, name: &str) -> Option<&str> {
            self.headers.get(name).and_then(|v| v.to_str().ok())
        }

        /// The `Content-Type` header.
        pub fn content_type(&self) -> Option<&str> {
            self.header("content-type")
        }

        /// Whether the status is 2xx.
        pub fn is_success(&self) -> bool {
            self.status.is_success()
        }
    };
}

/// Whether a status code may be accompanied by a body at all.
///
/// RFC 9110 §6.4.1: a 1xx, `204 No Content` or `304 Not Modified` response
/// never has one, whatever its headers claim.
fn status_allows_body(status: StatusCode) -> bool {
    !(status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED)
}

/// Build the error `error_for_status` returns.
fn status_error(status: StatusCode) -> Error {
    Error::Status {
        status,
        reason: status.canonical_reason().unwrap_or("").to_string(),
    }
}

// ===========================================================================
// Buffered
// ===========================================================================

/// A completed HTTP response with its body already read.
#[derive(Clone)]
pub struct Response {
    status: StatusCode,
    version: Version,
    headers: HeaderMap,
    body: Bytes,
}

impl Response {
    /// Assemble a response from parts. Mostly useful in tests.
    pub fn new(status: StatusCode, version: Version, headers: HeaderMap, body: Bytes) -> Self {
        Self {
            status,
            version,
            headers,
            body,
        }
    }

    head_accessors!();

    /// Return an error if the status is not 2xx.
    ///
    /// ```rust,no_run
    /// # async fn demo(client: &hypertor::TorClient) -> hypertor::Result<()> {
    /// let body = client.get("http://api.onion/v1")?
    ///     .send()
    ///     .await?
    ///     .error_for_status()?
    ///     .text()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn error_for_status(self) -> Result<Self> {
        if self.status.is_success() {
            Ok(self)
        } else {
            Err(status_error(self.status))
        }
    }

    /// The decoded body.
    pub fn bytes(&self) -> &Bytes {
        &self.body
    }

    /// Consume the response, returning the decoded body.
    pub fn into_bytes(self) -> Bytes {
        self.body
    }

    /// The body as UTF-8 text.
    ///
    /// hypertor does not transcode other charsets. A response declaring, say,
    /// `charset=shift_jis` fails here rather than silently producing mojibake;
    /// decode it yourself from [`bytes`](Self::bytes) if you need to.
    pub fn text(&self) -> Result<String> {
        text_from(&self.body, self.content_type())
    }

    /// Deserialise the body as JSON.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body)
            .map_err(|e| Error::decode(format!("response body is not valid JSON: {e}")))
    }

    /// The decoded body length in bytes.
    pub fn len(&self) -> usize {
        self.body.len()
    }

    /// Whether the decoded body is empty.
    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
    }
}

impl Head for Response {
    fn status(&self) -> StatusCode {
        self.status
    }
    fn headers(&self) -> &HeaderMap {
        &self.headers
    }
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("version", &self.version)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

// ===========================================================================
// Streaming
// ===========================================================================

/// A response whose headers have arrived and whose body is still being read.
///
/// The size limit still applies to the decoded total, so a body that outgrows
/// it fails partway through rather than being buffered first.
///
/// ```rust,no_run
/// # async fn demo(client: &hypertor::TorClient) -> hypertor::Result<()> {
/// let mut response = client.get("http://files.onion/big.iso")?.send_streaming().await?;
/// println!("{} {:?}", response.status(), response.header("content-length"));
///
/// let mut written = 0usize;
/// while let Some(chunk) = response.chunk().await? {
///     written += chunk.len();
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Timeouts
///
/// The client's request timeout covers the connection, the request and the
/// response *headers*. Once this value is handed back the deadline no longer
/// applies — a download that takes an hour is a legitimate thing to want, and
/// hypertor will not cut it off. Impose your own deadline around the read loop
/// if you need one.
pub struct Streaming {
    status: StatusCode,
    version: Version,
    headers: HeaderMap,
    decoder: Decoder,
}

impl Streaming {
    pub(crate) fn new(
        status: StatusCode,
        version: Version,
        headers: HeaderMap,
        decoder: Decoder,
    ) -> Self {
        Self {
            status,
            version,
            headers,
            decoder,
        }
    }

    /// Wrap a hyper response, decoding its `Content-Encoding` and bounding the
    /// decoded body at `limit` bytes.
    ///
    /// This is what the client uses internally. It is public because the
    /// limit-enforcing decoder is useful on its own — over an onion stream you
    /// speak yourself, say — and because a size guarantee you cannot test is
    /// not a guarantee.
    ///
    /// Use [`from_head_response`](Self::from_head_response) for the answer to a
    /// `HEAD` request: the metadata there describes a body that is not actually
    /// being sent.
    pub fn from_response<B>(response: http::Response<B>, limit: usize) -> Result<Self>
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        Self::build(response, limit, true)
    }

    /// Wrap the response to a `HEAD` request.
    ///
    /// RFC 9110 §9.3.2 says a `HEAD` response carries the header fields the
    /// equivalent `GET` would have sent — including `Content-Length` and
    /// `Content-Encoding` — while carrying no body at all. Treating those as
    /// describing real bytes would reject `HEAD` on any resource larger than
    /// the size limit, and would hand an empty stream to a decompressor that
    /// then reports a truncated member. Neither has anything to do with what is
    /// actually on the wire, which is nothing.
    pub fn from_head_response<B>(response: http::Response<B>, limit: usize) -> Result<Self>
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        Self::build(response, limit, false)
    }

    fn build<B>(response: http::Response<B>, limit: usize, method_allows_body: bool) -> Result<Self>
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        let (parts, body) = response.into_parts();

        // 1xx, 204 and 304 carry no body regardless of what the request was,
        // and may still carry the metadata of the body they are standing in for.
        let has_body = method_allows_body && status_allows_body(parts.status);

        // A server that declares an oversized body is refused before a byte of
        // it is read. This is only an optimisation — the streaming limit is what
        // actually enforces the bound, since Content-Length may be absent or lie.
        if has_body
            && let Some(declared) = parts
                .headers
                .get(http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<usize>().ok())
            && declared > limit
        {
            return Err(Error::BodyTooLarge {
                size: declared,
                limit,
            });
        }

        // `Content-Encoding` is still validated when there is no body, so a
        // stacked or unknown encoding is reported rather than passed over in
        // silence; it just is not applied to the empty stream.
        let declared = Encoding::from_headers(&parts.headers)?;
        let encoding = if has_body {
            declared
        } else {
            Encoding::Identity
        };

        Ok(Self::new(
            parts.status,
            parts.version,
            parts.headers,
            Decoder::new(body, encoding, limit),
        ))
    }

    head_accessors!();

    /// Return an error if the status is not 2xx.
    pub fn error_for_status(self) -> Result<Self> {
        if self.status.is_success() {
            Ok(self)
        } else {
            Err(status_error(self.status))
        }
    }

    /// The next decoded chunk, or `None` once the body has ended.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>> {
        self.decoder.chunk().await
    }

    /// The body as a [`Stream`] of decoded chunks.
    pub fn bytes_stream(self) -> impl Stream<Item = Result<Bytes>> + Send {
        futures::stream::try_unfold(self.decoder, |mut decoder| async move {
            Ok(decoder.chunk().await?.map(|chunk| (chunk, decoder)))
        })
    }

    /// Read the rest of the body into memory and return a buffered
    /// [`Response`].
    pub async fn buffered(self) -> Result<Response> {
        let body = self.decoder.collect().await?;
        Ok(Response {
            status: self.status,
            version: self.version,
            headers: self.headers,
            body,
        })
    }
}

impl Head for Streaming {
    fn status(&self) -> StatusCode {
        self.status
    }
    fn headers(&self) -> &HeaderMap {
        &self.headers
    }
}

impl std::fmt::Debug for Streaming {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Streaming")
            .field("status", &self.status)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

// ===========================================================================
// Shared internals
// ===========================================================================

/// Decode bytes as UTF-8, naming the declared charset when it is not.
fn text_from(body: &Bytes, content_type: Option<&str>) -> Result<String> {
    std::str::from_utf8(body).map(str::to_owned).map_err(|e| {
        let charset = content_type
            .and_then(|ct| {
                ct.split(';').find_map(|p| {
                    let p = p.trim();
                    p.strip_prefix("charset=")
                        .or_else(|| p.strip_prefix("charset ="))
                })
            })
            .map(|c| c.trim_matches('"').to_ascii_lowercase());

        match charset {
            Some(c) if c != "utf-8" && c != "us-ascii" => Error::decode(format!(
                "response body is {c}-encoded; hypertor only decodes UTF-8, \
                 use `bytes()` and transcode it yourself"
            )),
            _ => Error::decode(format!("response body is not valid UTF-8: {e}")),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;

    fn response_with(headers: Vec<(&str, &str)>, body: &[u8]) -> http::Response<Full<Bytes>> {
        let mut builder = http::Response::builder().status(200);
        for (k, v) in headers {
            builder = builder.header(k, v);
        }
        builder
            .body(Full::new(Bytes::copy_from_slice(body)))
            .expect("valid response")
    }

    async fn read(headers: Vec<(&str, &str)>, body: &[u8], limit: usize) -> Result<Response> {
        Streaming::from_response(response_with(headers, body), limit)?
            .buffered()
            .await
    }

    #[tokio::test]
    async fn reads_a_plain_body() {
        let resp = read(vec![], b"hello", 1024).await.expect("reads");
        assert_eq!(resp.text().unwrap(), "hello");
        assert!(resp.is_success());
    }

    #[tokio::test]
    async fn rejects_a_declared_oversized_body_before_reading() {
        let err = read(vec![("content-length", "999999")], b"x", 1024)
            .await
            .expect_err("must reject");

        assert!(matches!(
            err,
            Error::BodyTooLarge {
                size: 999999,
                limit: 1024
            }
        ));
    }

    #[tokio::test]
    async fn enforces_the_limit_on_an_undeclared_body() {
        // No usable Content-Length, so the limit must be caught while streaming.
        let err = read(vec![], &vec![b'x'; 4096], 1024)
            .await
            .expect_err("must reject");
        assert!(matches!(err, Error::BodyTooLarge { limit: 1024, .. }));
    }

    #[tokio::test]
    async fn a_head_response_is_not_judged_by_the_size_it_describes() {
        // RFC 9110 §9.3.2: these headers describe the body a GET would return.
        // Reading them as a real body made `client.head(url)` fail on every
        // resource larger than the limit, having transferred nothing at all.
        let response = Streaming::from_head_response(
            response_with(vec![("content-length", "999999999")], b""),
            1024,
        )
        .expect("a HEAD response is about metadata, not bytes");

        assert_eq!(
            response.header("content-length"),
            Some("999999999"),
            "the declared length must still be readable by the caller"
        );
        assert!(response.buffered().await.expect("empty body").is_empty());
    }

    #[tokio::test]
    async fn a_head_response_does_not_run_its_body_through_a_decompressor() {
        // An empty stream is not a truncated gzip member; it is no member.
        let response = Streaming::from_head_response(
            response_with(
                vec![("content-encoding", "gzip"), ("content-length", "42")],
                b"",
            ),
            1024,
        )
        .expect("splits")
        .buffered()
        .await
        .expect("an absent body cannot fail to decode");

        assert!(response.is_empty());
    }

    #[tokio::test]
    async fn a_304_carries_no_body_whatever_its_headers_claim() {
        let mut builder = http::Response::builder().status(StatusCode::NOT_MODIFIED);
        builder = builder.header("content-length", "999999999");
        let response = builder.body(Full::new(Bytes::new())).expect("valid");

        let out = Streaming::from_response(response, 1024)
            .expect("304 must not be refused on size")
            .buffered()
            .await
            .expect("no body to read");

        assert_eq!(out.status(), StatusCode::NOT_MODIFIED);
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn a_head_response_still_rejects_an_undecodable_encoding() {
        // The caller asked for metadata; metadata naming `gzip, br` is metadata
        // hypertor cannot honour, and saying so is better than implying it can.
        assert!(
            Streaming::from_head_response(
                response_with(vec![("content-encoding", "gzip, br")], b""),
                1024
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn decompresses_gzip_responses() {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"compressed over tor").unwrap();
        let gz = enc.finish().unwrap();

        let resp = read(vec![("content-encoding", "gzip")], &gz, 1024)
            .await
            .expect("reads");
        assert_eq!(resp.text().unwrap(), "compressed over tor");
    }

    #[tokio::test]
    async fn parses_json() {
        let resp = read(vec![], br#"{"ip":"1.2.3.4"}"#, 1024)
            .await
            .expect("reads");
        let value: serde_json::Value = resp.json().unwrap();
        assert_eq!(value["ip"], "1.2.3.4");
    }

    #[tokio::test]
    async fn streams_chunks_without_buffering_everything() {
        let mut streaming =
            Streaming::from_response(response_with(vec![], b"streamed"), 1024).expect("splits");
        assert_eq!(streaming.status(), StatusCode::OK);

        let mut seen = Vec::new();
        while let Some(chunk) = streaming.chunk().await.expect("chunk") {
            seen.extend_from_slice(&chunk);
        }
        assert_eq!(seen, b"streamed");
    }

    #[tokio::test]
    async fn a_streaming_body_is_still_bounded_by_the_limit() {
        // Otherwise the streaming API would be a way around the size limit.
        let mut streaming =
            Streaming::from_response(response_with(vec![], &vec![b'x'; 4096]), 16).expect("splits");
        let err = streaming.chunk().await.expect_err("must reject");
        assert!(matches!(err, Error::BodyTooLarge { limit: 16, .. }));
    }

    #[tokio::test]
    async fn bytes_stream_yields_the_whole_body() {
        use futures::TryStreamExt;

        let streaming =
            Streaming::from_response(response_with(vec![], b"via stream"), 1024).expect("splits");
        let chunks: Vec<Bytes> = streaming
            .bytes_stream()
            .try_collect()
            .await
            .expect("stream");
        let joined: Vec<u8> = chunks.concat();
        assert_eq!(joined, b"via stream");
    }

    #[test]
    fn error_for_status_rejects_non_2xx() {
        let resp = Response::new(
            StatusCode::NOT_FOUND,
            Version::HTTP_11,
            HeaderMap::new(),
            Bytes::new(),
        );
        let err = resp.error_for_status().expect_err("404 is an error");
        assert!(matches!(err, Error::Status { status, .. } if status == StatusCode::NOT_FOUND));
    }

    #[test]
    fn non_utf8_text_names_the_charset() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            "text/html; charset=shift_jis".parse().unwrap(),
        );
        let resp = Response::new(
            StatusCode::OK,
            Version::HTTP_11,
            headers,
            Bytes::from_static(&[0x82, 0xA0]),
        );

        let err = resp.text().expect_err("not utf-8");
        assert!(err.to_string().contains("shift_jis"), "got: {err}");
    }
}

//! HTTP responses.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::{HeaderMap, StatusCode, Version};
use http_body_util::BodyExt;

use crate::body::{self, Encoding};
use crate::error::{Error, Result};

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

    /// Read a hyper response, enforcing `limit` **as the body streams in**.
    ///
    /// The limit is checked per frame rather than after collecting, so a
    /// malicious or misconfigured server cannot make the client allocate an
    /// unbounded buffer before the check runs. It is applied a second time to
    /// the decompressed size, which is what bounds decompression bombs.
    pub(crate) async fn read<B>(response: http::Response<B>, limit: usize) -> Result<Self>
    where
        B: http_body::Body + Unpin,
        B::Data: Buf,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        let (parts, mut body) = response.into_parts();

        // If the server declares an oversized body, refuse before reading it.
        if let Some(declared) = parts
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

        let mut buf = BytesMut::new();

        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| Error::http_source("could not read response body", e))?;

            if let Ok(data) = frame.into_data() {
                let len = Buf::remaining(&data);
                if buf.len() + len > limit {
                    return Err(Error::BodyTooLarge {
                        size: buf.len() + len,
                        limit,
                    });
                }
                // `put` walks every chunk, so non-contiguous buffers are copied
                // in full rather than truncated to their first chunk.
                BufMut::put(&mut buf, data);
            }
        }

        let raw = buf.freeze();
        let encoding = Encoding::from_headers(&parts.headers)?;
        let body = body::decode(&raw, encoding, limit)?;

        Ok(Self {
            status: parts.status,
            version: parts.version,
            headers: parts.headers,
            body,
        })
    }

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
            Err(Error::Http {
                message: format!(
                    "server returned {} {}",
                    self.status.as_u16(),
                    self.status.canonical_reason().unwrap_or("")
                ),
                source: None,
            })
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
    /// `charset=shift_jis` will fail here rather than silently producing
    /// mojibake; decode it yourself from [`bytes`](Self::bytes) if you need to.
    pub fn text(&self) -> Result<String> {
        std::str::from_utf8(&self.body)
            .map(str::to_owned)
            .map_err(|e| {
                let charset = self
                    .content_type()
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

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("version", &self.version)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
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

    #[tokio::test]
    async fn reads_a_plain_body() {
        let resp = Response::read(response_with(vec![], b"hello"), 1024)
            .await
            .expect("reads");
        assert_eq!(resp.text().unwrap(), "hello");
        assert!(resp.is_success());
    }

    #[tokio::test]
    async fn rejects_a_declared_oversized_body_before_reading() {
        let err = Response::read(
            response_with(vec![("content-length", "999999")], b"x"),
            1024,
        )
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
        // No Content-Length, so the limit must be caught while streaming.
        let err = Response::read(response_with(vec![], &vec![b'x'; 4096]), 1024)
            .await
            .expect_err("must reject");
        assert!(matches!(err, Error::BodyTooLarge { limit: 1024, .. }));
    }

    #[tokio::test]
    async fn decompresses_gzip_responses() {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"compressed over tor").unwrap();
        let gz = enc.finish().unwrap();

        let resp = Response::read(response_with(vec![("content-encoding", "gzip")], &gz), 1024)
            .await
            .expect("reads");
        assert_eq!(resp.text().unwrap(), "compressed over tor");
    }

    #[tokio::test]
    async fn parses_json() {
        let resp = Response::read(response_with(vec![], br#"{"ip":"1.2.3.4"}"#), 1024)
            .await
            .expect("reads");
        let value: serde_json::Value = resp.json().unwrap();
        assert_eq!(value["ip"], "1.2.3.4");
    }

    #[test]
    fn error_for_status_rejects_non_2xx() {
        let resp = Response::new(
            StatusCode::NOT_FOUND,
            Version::HTTP_11,
            HeaderMap::new(),
            Bytes::new(),
        );
        assert!(resp.error_for_status().is_err());
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

//! HTTP Response wrapper
//!
//! Provides a convenient interface for working with HTTP responses,
//! including streaming body consumption, compression, and encoding detection.

use bytes::Bytes;
use http::{HeaderMap, StatusCode, Version};
use http_body_util::BodyExt;

use crate::compression::{Compression, decompress};
use crate::error::{Error, Result};

/// HTTP Response
pub struct Response {
    /// HTTP status code
    status: StatusCode,
    /// HTTP version
    version: Version,
    /// Response headers
    headers: HeaderMap,
    /// Response body (collected and decompressed)
    body: Bytes,
}

impl Response {
    /// Create a new response from parts
    pub fn new(status: StatusCode, version: Version, headers: HeaderMap, body: Bytes) -> Self {
        Self {
            status,
            version,
            headers,
            body,
        }
    }

    /// Create a response from a hyper response with automatic decompression
    pub async fn from_hyper<B>(response: http::Response<B>, max_size: usize) -> Result<Self>
    where
        B: http_body::Body,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        let (parts, body) = response.into_parts();

        // Collect body with size limit
        let collected = body
            .collect()
            .await
            .map_err(|e| Error::http_with_source("failed to read response body", e))?;

        let raw_bytes = collected.to_bytes();

        if raw_bytes.len() > max_size {
            return Err(Error::ResponseTooLarge {
                size: raw_bytes.len(),
                limit: max_size,
            });
        }

        // Detect and decompress if needed
        let content_encoding = parts
            .headers
            .get(http::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok());

        let compression = content_encoding
            .map(Compression::from_header)
            .unwrap_or(Compression::None);

        let body = if compression != Compression::None {
            let decompressed = decompress(&raw_bytes, compression)?;

            // Check decompressed size too (compression bombs)
            if decompressed.len() > max_size * 10 {
                return Err(Error::ResponseTooLarge {
                    size: decompressed.len(),
                    limit: max_size * 10,
                });
            }

            Bytes::from(decompressed)
        } else {
            raw_bytes
        };

        Ok(Self {
            status: parts.status,
            version: parts.version,
            headers: parts.headers,
            body,
        })
    }

    /// Get the HTTP status code
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Get the HTTP status code as a u16
    pub fn status_code(&self) -> u16 {
        self.status.as_u16()
    }

    /// Check if the response status is success (2xx)
    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }

    /// Check if the response status is a redirect (3xx)
    pub fn is_redirect(&self) -> bool {
        self.status.is_redirection()
    }

    /// Check if the response status is a client error (4xx)
    pub fn is_client_error(&self) -> bool {
        self.status.is_client_error()
    }

    /// Check if the response status is a server error (5xx)
    pub fn is_server_error(&self) -> bool {
        self.status.is_server_error()
    }

    /// Get the HTTP version
    pub fn version(&self) -> Version {
        self.version
    }

    /// Get the response headers
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Get a specific header value
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// Get the Content-Type header
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    /// Get the Content-Length header
    pub fn content_length(&self) -> Option<usize> {
        self.header("content-length").and_then(|v| v.parse().ok())
    }

    /// Get the response body as bytes
    pub fn bytes(&self) -> &Bytes {
        &self.body
    }

    /// Consume the response and return the body bytes
    pub fn into_bytes(self) -> Bytes {
        self.body
    }

    /// Get the response body as text
    ///
    /// Uses the charset from Content-Type header, defaulting to UTF-8.
    /// Currently supports UTF-8 only; other charsets are attempted as UTF-8.
    pub fn text(&self) -> Result<String> {
        // Parse charset from Content-Type if available
        // e.g., "text/html; charset=utf-8" or "application/json; charset=UTF-8"
        let _charset = self
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|ct| ct.to_str().ok())
            .and_then(|ct| {
                ct.split(';')
                    .filter_map(|part| {
                        let part = part.trim();
                        if part.to_lowercase().starts_with("charset=") {
                            Some(part[8..].trim_matches('"').to_lowercase())
                        } else {
                            None
                        }
                    })
                    .next()
            })
            .unwrap_or_else(|| "utf-8".to_string());

        // Currently only UTF-8 is fully supported
        // Other charsets would require encoding_rs crate
        String::from_utf8(self.body.to_vec())
            .map_err(|e| Error::http(format!("response is not valid UTF-8: {}", e)))
    }

    /// Consume the response and return the body as text
    pub fn into_text(self) -> Result<String> {
        String::from_utf8(self.body.to_vec())
            .map_err(|e| Error::http(format!("response is not valid UTF-8: {}", e)))
    }

    /// Get the length of the response body
    pub fn len(&self) -> usize {
        self.body.len()
    }

    /// Check if the response body is empty
    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
    }
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("version", &self.version)
            .field("headers", &self.headers)
            .field("body_len", &self.body.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_response_status() {
        let resp = Response::new(
            StatusCode::OK,
            Version::HTTP_11,
            HeaderMap::new(),
            Bytes::new(),
        );
        assert!(resp.is_success());
        assert_eq!(resp.status_code(), 200);
    }

    #[test]
    fn test_response_text() {
        let resp = Response::new(
            StatusCode::OK,
            Version::HTTP_11,
            HeaderMap::new(),
            Bytes::from("Hello, World!"),
        );
        assert_eq!(resp.text().unwrap(), "Hello, World!");
    }
}

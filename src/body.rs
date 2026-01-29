//! HTTP Body encoding utilities
//!
//! Provides form encoding, JSON encoding, and multipart support.

use bytes::Bytes;
use http::header::HeaderValue;

use crate::error::{Error, Result};

/// A request body with its content-type
#[derive(Debug, Clone)]
pub struct Body {
    /// The encoded body data
    pub data: Bytes,
    /// The content-type header value
    pub content_type: HeaderValue,
}

impl Body {
    /// Create a body from raw bytes with a content-type
    #[must_use]
    pub fn raw(data: impl Into<Bytes>, content_type: &str) -> Self {
        Self {
            data: data.into(),
            // Safety: content_type should be a valid header value
            content_type: HeaderValue::from_str(content_type)
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
        }
    }

    /// Create a JSON body
    ///
    /// Note: This does not serialize - it expects pre-serialized JSON
    #[must_use]
    pub fn json(json_str: impl Into<Bytes>) -> Self {
        Self {
            data: json_str.into(),
            content_type: HeaderValue::from_static("application/json; charset=utf-8"),
        }
    }

    /// Create a form-urlencoded body from key-value pairs
    pub fn form<I, K, V>(params: I) -> Result<Self>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let encoded: String = params
            .into_iter()
            .map(|(k, v)| format!("{}={}", url_encode(k.as_ref()), url_encode(v.as_ref())))
            .collect::<Vec<_>>()
            .join("&");

        Ok(Self {
            data: Bytes::from(encoded),
            content_type: HeaderValue::from_static("application/x-www-form-urlencoded"),
        })
    }

    /// Create a plain text body
    #[must_use]
    pub fn text(text: impl Into<Bytes>) -> Self {
        Self {
            data: text.into(),
            content_type: HeaderValue::from_static("text/plain; charset=utf-8"),
        }
    }

    /// Create an empty body
    #[must_use]
    pub fn empty() -> Self {
        Self {
            data: Bytes::new(),
            content_type: HeaderValue::from_static(""),
        }
    }

    /// Get the body length
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the body is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// URL-encode a string (percent encoding)
fn url_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for c in s.bytes() {
        match c {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(c as char);
            }
            b' ' => result.push('+'),
            _ => {
                result.push('%');
                result.push(HEX_CHARS[(c >> 4) as usize] as char);
                result.push(HEX_CHARS[(c & 0x0F) as usize] as char);
            }
        }
    }
    result
}

const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";

/// URL-decode a string
pub fn url_decode(s: &str) -> Result<String> {
    let mut result = Vec::with_capacity(s.len());
    let mut bytes = s.bytes();

    while let Some(c) = bytes.next() {
        match c {
            b'+' => result.push(b' '),
            b'%' => {
                let high = bytes
                    .next()
                    .ok_or_else(|| Error::http("incomplete percent encoding"))?;
                let low = bytes
                    .next()
                    .ok_or_else(|| Error::http("incomplete percent encoding"))?;
                let byte = hex_to_byte(high, low)
                    .ok_or_else(|| Error::http("invalid percent encoding"))?;
                result.push(byte);
            }
            _ => result.push(c),
        }
    }

    String::from_utf8(result).map_err(|_| Error::http("URL-decoded string is not valid UTF-8"))
}

/// Convert two hex characters to a byte
fn hex_to_byte(high: u8, low: u8) -> Option<u8> {
    let high = match high {
        b'0'..=b'9' => high - b'0',
        b'A'..=b'F' => high - b'A' + 10,
        b'a'..=b'f' => high - b'a' + 10,
        _ => return None,
    };
    let low = match low {
        b'0'..=b'9' => low - b'0',
        b'A'..=b'F' => low - b'A' + 10,
        b'a'..=b'f' => low - b'a' + 10,
        _ => return None,
    };
    Some((high << 4) | low)
}

/// Basic authentication header
pub fn basic_auth(username: &str, password: &str) -> HeaderValue {
    use base64::Engine;
    let credentials = format!("{}:{}", username, password);
    let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
    let header_value = format!("Basic {}", encoded);
    // Safety: base64 output is always valid header value
    HeaderValue::from_str(&header_value)
        .unwrap_or_else(|_| HeaderValue::from_static("Basic invalid"))
}

/// Bearer authentication header
pub fn bearer_auth(token: &str) -> Result<HeaderValue> {
    let header_value = format!("Bearer {}", token);
    HeaderValue::from_str(&header_value).map_err(|_| Error::http("invalid bearer token"))
}

/// Content-Length header
#[must_use]
pub fn content_length(len: usize) -> HeaderValue {
    // Safety: numbers are always valid header values
    HeaderValue::from_str(&len.to_string()).unwrap_or_else(|_| HeaderValue::from_static("0"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_url_encode() {
        assert_eq!(url_encode("hello world"), "hello+world");
        assert_eq!(url_encode("foo=bar&baz"), "foo%3Dbar%26baz");
        assert_eq!(url_encode("日本語"), "%E6%97%A5%E6%9C%AC%E8%AA%9E");
    }

    #[test]
    fn test_url_decode() {
        assert_eq!(url_decode("hello+world").unwrap(), "hello world");
        assert_eq!(url_decode("foo%3Dbar%26baz").unwrap(), "foo=bar&baz");
    }

    #[test]
    fn test_form_body() {
        let body = Body::form([("name", "John Doe"), ("age", "30")]).unwrap();
        assert_eq!(body.data.as_ref(), b"name=John+Doe&age=30");
        assert_eq!(
            body.content_type.to_str().unwrap(),
            "application/x-www-form-urlencoded"
        );
    }

    #[test]
    fn test_json_body() {
        let body = Body::json(r#"{"key": "value"}"#);
        assert_eq!(body.data.as_ref(), br#"{"key": "value"}"#);
        assert!(
            body.content_type
                .to_str()
                .unwrap()
                .contains("application/json")
        );
    }

    #[test]
    fn test_basic_auth() {
        let header = basic_auth("user", "pass");
        assert_eq!(header.to_str().unwrap(), "Basic dXNlcjpwYXNz");
    }
}

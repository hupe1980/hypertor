//! Request body encoding and response body decoding.

use bytes::Bytes;
use http::HeaderValue;
use http::header::CONTENT_ENCODING;

use crate::error::{Error, Result};

/// Content encodings hypertor can decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Encoding {
    /// No encoding.
    #[default]
    Identity,
    /// RFC 1952 gzip.
    Gzip,
    /// RFC 1950 zlib / deflate.
    Deflate,
    /// RFC 7932 Brotli.
    Brotli,
    /// RFC 8878 Zstandard.
    Zstd,
}

impl Encoding {
    /// The value hypertor sends in `Accept-Encoding`.
    pub fn accept_encoding() -> HeaderValue {
        HeaderValue::from_static("gzip, br, zstd, deflate")
    }

    /// Parse a single `Content-Encoding` token.
    pub fn parse(token: &str) -> Self {
        match token.trim().to_ascii_lowercase().as_str() {
            "gzip" | "x-gzip" => Self::Gzip,
            "deflate" => Self::Deflate,
            "br" => Self::Brotli,
            "zstd" => Self::Zstd,
            _ => Self::Identity,
        }
    }

    /// The encoding named by a response's `Content-Encoding` header.
    ///
    /// Only single-encoding responses are supported. A stacked encoding such as
    /// `gzip, br` is rejected rather than silently half-decoded.
    pub fn from_headers(headers: &http::HeaderMap) -> Result<Self> {
        let Some(value) = headers.get(CONTENT_ENCODING) else {
            return Ok(Self::Identity);
        };

        let value = value
            .to_str()
            .map_err(|_| Error::decode("Content-Encoding is not valid ASCII"))?;

        let mut encodings = value
            .split(',')
            .map(str::trim)
            .filter(|t| !t.is_empty() && !t.eq_ignore_ascii_case("identity"));

        let Some(first) = encodings.next() else {
            return Ok(Self::Identity);
        };

        if encodings.next().is_some() {
            return Err(Error::decode(format!(
                "stacked Content-Encoding `{value}` is not supported"
            )));
        }

        match Self::parse(first) {
            Self::Identity => Err(Error::decode(format!(
                "unsupported Content-Encoding `{first}`"
            ))),
            known => Ok(known),
        }
    }
}

/// Decode a response body.
///
/// `limit` bounds the *decompressed* size. Enforcing it here is what stops a
/// decompression bomb: a few kilobytes of gzip can expand to gigabytes, so the
/// limit has to apply to the output, not just the transferred bytes.
pub fn decode(data: &[u8], encoding: Encoding, limit: usize) -> Result<Bytes> {
    use std::io::Read;

    if encoding == Encoding::Identity {
        return Ok(Bytes::copy_from_slice(data));
    }

    // Read one byte past the limit so an exactly-at-limit body still succeeds
    // while an oversized one is detected without decoding all of it.
    let mut out = Vec::new();
    let budget = (limit as u64).saturating_add(1);

    let result = match encoding {
        Encoding::Gzip => flate2::read::GzDecoder::new(data)
            .take(budget)
            .read_to_end(&mut out),
        Encoding::Deflate => flate2::read::ZlibDecoder::new(data)
            .take(budget)
            .read_to_end(&mut out),
        Encoding::Brotli => brotli::Decompressor::new(data, 8192)
            .take(budget)
            .read_to_end(&mut out),
        Encoding::Zstd => zstd::stream::read::Decoder::new(data)
            .map_err(|e| Error::decode(format!("zstd: {e}")))?
            .take(budget)
            .read_to_end(&mut out),
        Encoding::Identity => unreachable!("handled above"),
    };

    result.map_err(|e| Error::decode(format!("{encoding:?} body is malformed: {e}")))?;

    if out.len() > limit {
        return Err(Error::BodyTooLarge {
            size: out.len(),
            limit,
        });
    }

    Ok(Bytes::from(out))
}

/// Percent-encode a string for use in a query or form value.
///
/// Uses the `application/x-www-form-urlencoded` rules: unreserved characters
/// pass through, spaces become `+`, everything else is percent-encoded.
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

    fn headers_with(encoding: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(CONTENT_ENCODING, HeaderValue::from_str(encoding).unwrap());
        h
    }

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
    fn rejects_stacked_and_unknown_encodings() {
        // Half-decoding is worse than refusing: the caller would get bytes that
        // look like a body but are still compressed.
        assert!(Encoding::from_headers(&headers_with("gzip, br")).is_err());
        assert!(Encoding::from_headers(&headers_with("exotic")).is_err());
    }

    #[test]
    fn round_trips_gzip() {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"hello over tor").unwrap();
        let compressed = enc.finish().unwrap();

        let out = decode(&compressed, Encoding::Gzip, 1024).unwrap();
        assert_eq!(&out[..], b"hello over tor");
    }

    #[test]
    fn decompression_bomb_is_stopped_at_the_limit() {
        use std::io::Write;
        // 4 MiB of zeroes compresses to a few KiB.
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(&vec![0u8; 4 * 1024 * 1024]).unwrap();
        let bomb = enc.finish().unwrap();
        assert!(bomb.len() < 64 * 1024, "test fixture should be small");

        let err = decode(&bomb, Encoding::Gzip, 1024).unwrap_err();
        assert!(matches!(err, Error::BodyTooLarge { limit: 1024, .. }));
    }

    #[test]
    fn body_exactly_at_the_limit_is_accepted() {
        use std::io::Write;
        let payload = vec![b'x'; 1024];
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&payload).unwrap();
        let compressed = enc.finish().unwrap();

        let out = decode(&compressed, Encoding::Gzip, 1024).unwrap();
        assert_eq!(out.len(), 1024);
    }

    #[test]
    fn malformed_bodies_error_rather_than_returning_garbage() {
        assert!(decode(b"not gzip at all", Encoding::Gzip, 1024).is_err());
    }

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

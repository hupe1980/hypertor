//! Compression support for HTTP responses.
//!
//! Supports automatic decompression of gzip, deflate, brotli, and zstd.

use crate::{Error, Result};
use std::io::Read;

/// Supported compression algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// No compression
    None,
    /// gzip compression
    Gzip,
    /// deflate compression
    Deflate,
    /// Brotli compression
    Brotli,
    /// Zstandard compression
    Zstd,
}

impl Compression {
    /// Detect compression from Content-Encoding header.
    pub fn from_header(value: &str) -> Self {
        match value.trim().to_lowercase().as_str() {
            "gzip" | "x-gzip" => Self::Gzip,
            "deflate" => Self::Deflate,
            "br" => Self::Brotli,
            "zstd" => Self::Zstd,
            _ => Self::None,
        }
    }

    /// Get the Accept-Encoding header value for all supported compressions.
    pub fn accept_encoding() -> &'static str {
        "gzip, deflate, br, zstd"
    }
}

/// Decompress data based on the compression algorithm.
pub fn decompress(data: &[u8], compression: Compression) -> Result<Vec<u8>> {
    match compression {
        Compression::None => Ok(data.to_vec()),
        Compression::Gzip => decompress_gzip(data),
        Compression::Deflate => decompress_deflate(data),
        Compression::Brotli => decompress_brotli(data),
        Compression::Zstd => decompress_zstd(data),
    }
}

fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| Error::http(format!("gzip decompression failed: {}", e)))?;
    Ok(decompressed)
}

fn decompress_deflate(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = flate2::read::DeflateDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| Error::http(format!("deflate decompression failed: {}", e)))?;
    Ok(decompressed)
}

fn decompress_brotli(data: &[u8]) -> Result<Vec<u8>> {
    let mut decompressed = Vec::new();
    brotli::BrotliDecompress(&mut std::io::Cursor::new(data), &mut decompressed)
        .map_err(|e| Error::http(format!("brotli decompression failed: {}", e)))?;
    Ok(decompressed)
}

fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>> {
    zstd::stream::decode_all(std::io::Cursor::new(data))
        .map_err(|e| Error::http(format!("zstd decompression failed: {}", e)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_compression_from_header() {
        assert_eq!(Compression::from_header("gzip"), Compression::Gzip);
        assert_eq!(Compression::from_header("br"), Compression::Brotli);
        assert_eq!(Compression::from_header("zstd"), Compression::Zstd);
        assert_eq!(Compression::from_header("deflate"), Compression::Deflate);
        assert_eq!(Compression::from_header("identity"), Compression::None);
    }

    #[test]
    fn test_gzip_roundtrip() {
        use flate2::write::GzEncoder;
        use std::io::Write;

        let original = b"Hello, Tor network! This is a test of compression.";
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = decompress(&compressed, Compression::Gzip).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_zstd_roundtrip() {
        let original = b"Hello, Tor network! This is a test of zstd compression.";
        let compressed = zstd::stream::encode_all(&original[..], 3).unwrap();

        let decompressed = decompress(&compressed, Compression::Zstd).unwrap();
        assert_eq!(decompressed, original);
    }
}

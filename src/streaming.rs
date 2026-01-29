//! Streaming response body support.
//!
//! Allows processing large responses without buffering entirely in memory.

use crate::{Error, Result};
use bytes::Bytes;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};
use tokio_stream::Stream;

/// A streaming response body that yields chunks as they arrive.
pub struct StreamingBody<R> {
    reader: R,
    buffer_size: usize,
    bytes_read: usize,
    max_size: Option<usize>,
}

impl<R: AsyncRead + Unpin> StreamingBody<R> {
    /// Create a new streaming body from an async reader.
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buffer_size: 8192,
            bytes_read: 0,
            max_size: None,
        }
    }

    /// Set the buffer size for reading chunks.
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    /// Set a maximum size limit for the response.
    pub fn with_max_size(mut self, max: usize) -> Self {
        self.max_size = Some(max);
        self
    }

    /// Get the number of bytes read so far.
    pub fn bytes_read(&self) -> usize {
        self.bytes_read
    }

    /// Read the entire body into memory.
    pub async fn collect(mut self) -> Result<Vec<u8>> {
        use tokio::io::AsyncReadExt;

        let mut buffer = Vec::new();
        let mut chunk = vec![0u8; self.buffer_size];

        loop {
            let n = self.reader.read(&mut chunk).await.map_err(|e| Error::Io {
                message: "Failed to read response body".to_string(),
                source: e,
            })?;

            if n == 0 {
                break;
            }

            self.bytes_read += n;

            if let Some(max) = self.max_size {
                if self.bytes_read > max {
                    return Err(Error::ResponseTooLarge {
                        size: self.bytes_read,
                        limit: max,
                    });
                }
            }

            buffer.extend_from_slice(&chunk[..n]);
        }

        Ok(buffer)
    }
}

impl<R: AsyncRead + Unpin> Stream for StreamingBody<R> {
    type Item = Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut buffer = vec![0u8; self.buffer_size];
        let mut read_buf = ReadBuf::new(&mut buffer);

        match Pin::new(&mut self.reader).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let filled = read_buf.filled();
                if filled.is_empty() {
                    Poll::Ready(None)
                } else {
                    self.bytes_read += filled.len();

                    if let Some(max) = self.max_size {
                        if self.bytes_read > max {
                            return Poll::Ready(Some(Err(Error::ResponseTooLarge {
                                size: self.bytes_read,
                                limit: max,
                            })));
                        }
                    }

                    Poll::Ready(Some(Ok(Bytes::copy_from_slice(filled))))
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(Error::Io {
                message: "Stream read error".to_string(),
                source: e,
            }))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Builder for creating streaming responses.
pub struct StreamingResponseBuilder {
    buffer_size: usize,
    max_size: Option<usize>,
}

impl Default for StreamingResponseBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamingResponseBuilder {
    /// Create a new builder with defaults.
    pub fn new() -> Self {
        Self {
            buffer_size: 8192,
            max_size: None,
        }
    }

    /// Set the buffer size.
    pub fn buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    /// Set maximum response size.
    pub fn max_size(mut self, max: usize) -> Self {
        self.max_size = Some(max);
        self
    }

    /// Build a streaming body from a reader.
    pub fn build<R: AsyncRead + Unpin>(self, reader: R) -> StreamingBody<R> {
        let mut body = StreamingBody::new(reader).with_buffer_size(self.buffer_size);
        if let Some(max) = self.max_size {
            body = body.with_max_size(max);
        }
        body
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_streaming_body_collect() {
        let data = b"Hello, streaming world!";
        let cursor = Cursor::new(data.to_vec());
        let body = StreamingBody::new(cursor);

        let collected = body.collect().await.unwrap();
        assert_eq!(collected, data);
    }

    #[tokio::test]
    async fn test_streaming_body_max_size() {
        let data = vec![0u8; 1000];
        let cursor = Cursor::new(data);
        let body = StreamingBody::new(cursor).with_max_size(100);

        let result = body.collect().await;
        assert!(result.is_err());
    }
}

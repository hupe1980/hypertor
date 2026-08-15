//! Streaming a large response, and streaming a large request body.
//!
//! ```console
//! $ cargo run --example streaming
//! ```
//!
//! Neither direction is ever held in memory in full. Over Tor that matters
//! twice over: bandwidth is scarce, and a buffered multi-gigabyte download
//! would be paid for entirely before the first byte reached your code.

use futures::StreamExt;
use hypertor::{Body, TorClient};

#[tokio::main]
async fn main() -> hypertor::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("hypertor=info")
        .init();

    let client = TorClient::builder()
        // The limit applies to the decoded body in both APIs, so raise it when
        // you genuinely mean to accept something large.
        .max_response_size(256 * 1024 * 1024)
        .build()
        .await?;

    // --- Downloading ------------------------------------------------------
    //
    // `send_streaming` returns as soon as the headers arrive. The request
    // timeout covers everything up to that point; reading the body afterwards
    // is yours to bound.
    let mut response = client
        .get("https://check.torproject.org/api/ip")?
        .send_streaming()
        .await?
        .error_for_status()?;

    println!(
        "{} {} — content-length: {:?}",
        response.status().as_u16(),
        response.status().canonical_reason().unwrap_or(""),
        response.header("content-length"),
    );

    let mut total = 0usize;
    while let Some(chunk) = response.chunk().await? {
        total += chunk.len();
    }
    println!("read {total} bytes without buffering the whole body");

    // The same body is also available as a `Stream`, for anything that already
    // speaks that language.
    let stream = client
        .get("https://check.torproject.org/api/ip")?
        .send_streaming()
        .await?
        .bytes_stream();
    tokio::pin!(stream);

    let chunks = stream.count().await;
    println!("second download arrived in {chunks} chunk(s)");

    // --- Uploading --------------------------------------------------------
    //
    // A file body is read lazily. Because a stream cannot be rewound, hypertor
    // will not retry such a request and will not replay it across a 307 — it
    // errors instead of silently sending a truncated body.
    let path = std::env::temp_dir().join("hypertor-upload-demo.bin");
    tokio::fs::write(&path, vec![b'x'; 1024 * 1024]).await?;

    let body = Body::from_file(&path).await?;
    println!(
        "uploading {} bytes, replayable: {}",
        body.len().unwrap_or(0),
        body.is_replayable(),
    );

    match client
        .post("https://httpbin.org/post")?
        .body(body)
        .send()
        .await
    {
        Ok(response) => println!("upload returned {}", response.status()),
        Err(e) => eprintln!("upload failed: {e}"),
    }

    tokio::fs::remove_file(&path).await.ok();
    Ok(())
}

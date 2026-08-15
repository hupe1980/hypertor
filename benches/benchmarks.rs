//! Benchmarks for hypertor's CPU-bound paths.
//!
//! Almost everything hypertor does is dominated by network latency: building a
//! Tor circuit takes seconds, and a request over an established one takes
//! hundreds of milliseconds. Microbenchmarking that would measure the Tor
//! network, not this crate.
//!
//! What *is* worth measuring is the work hypertor does per request on the CPU,
//! where an accidental quadratic or a redundant allocation would actually show
//! up: body decoding, routing and redirect resolution.

use std::hint::black_box;

use bytes::Bytes;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use http_body_util::Full;

use hypertor::Streaming;

fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).expect("compresses");
    encoder.finish().expect("finishes")
}

/// Read a body through the real decoding path, exactly as a response does.
async fn read(data: Bytes, encoding: Option<&str>, limit: usize) -> usize {
    let mut builder = http::Response::builder().status(200);
    if let Some(encoding) = encoding {
        builder = builder.header("content-encoding", encoding);
    }
    let response = builder.body(Full::new(data)).expect("valid response");

    Streaming::from_response(response, limit)
        .expect("splits")
        .buffered()
        .await
        .expect("decodes")
        .len()
}

/// Body decoding is the one place hypertor touches every byte of a response.
fn bench_body_decoding(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");

    let mut group = c.benchmark_group("body_decoding");

    for size in [1024usize, 64 * 1024, 1024 * 1024] {
        let payload = Bytes::from(vec![b'a'; size]);
        let compressed = Bytes::from(gzip(&payload));
        let limit = size * 2;

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("identity/{size}"), |b| {
            b.iter(|| {
                runtime.block_on(async { black_box(read(payload.clone(), None, limit).await) })
            })
        });

        group.bench_function(format!("gzip/{size}"), |b| {
            b.iter(|| {
                runtime.block_on(async {
                    black_box(read(compressed.clone(), Some("gzip"), limit).await)
                })
            })
        });
    }

    group.finish();
}

/// Redirect evaluation runs once per hop and does string work.
///
/// The policy and both URIs are built outside the loop on purpose: constructing
/// them inside it measured `Uri::from_str`, which is `http`'s code and not
/// something hypertor can make faster.
fn bench_redirect_evaluation(c: &mut Criterion) {
    use http::Uri;

    let policy = hypertor::RedirectPolicy::default();
    let base: Uri = "http://example.onion/a/b/c?q=1".parse().expect("valid");

    let same_origin: Uri = "http://example.onion/other".parse().expect("valid");
    let cross_origin: Uri = "https://elsewhere.example/other".parse().expect("valid");

    let mut group = c.benchmark_group("redirect");

    group.bench_function("same_origin", |b| {
        b.iter(|| black_box(policy.evaluate(black_box(&base), black_box(&same_origin))))
    });

    // The refusal path: an onion origin pointing out to clearnet, which is the
    // check that must never become expensive enough to be worth skipping.
    group.bench_function("onion_to_clearnet", |b| {
        b.iter(|| black_box(policy.evaluate(black_box(&base), black_box(&cross_origin))))
    });

    group.finish();
}

/// Request construction, which happens once per attempt.
fn bench_request_building(c: &mut Criterion) {
    c.bench_function("config/build", |b| {
        b.iter(|| {
            black_box(
                hypertor::Config::builder()
                    .timeout(std::time::Duration::from_secs(30))
                    .max_retries(2)
                    .build(),
            )
        })
    });
}

criterion_group!(
    benches,
    bench_body_decoding,
    bench_redirect_evaluation,
    bench_request_building
);
criterion_main!(benches);

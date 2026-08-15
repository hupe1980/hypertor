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

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

use hypertor::body::{Encoding, decode};

fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).expect("compresses");
    encoder.finish().expect("finishes")
}

/// Body decoding is the one place hypertor touches every byte of a response.
fn bench_body_decoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("body_decoding");

    for size in [1024usize, 64 * 1024, 1024 * 1024] {
        let payload = vec![b'a'; size];
        let compressed = gzip(&payload);
        let limit = size * 2;

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("identity/{size}"), |b| {
            b.iter(|| black_box(decode(black_box(&payload), Encoding::Identity, limit)))
        });

        group.bench_function(format!("gzip/{size}"), |b| {
            b.iter(|| black_box(decode(black_box(&compressed), Encoding::Gzip, limit)))
        });
    }

    group.finish();
}

/// Redirect resolution runs once per hop and does string work.
fn bench_redirect_resolution(c: &mut Criterion) {
    use http::Uri;

    let base: Uri = "http://example.onion/a/b/c?q=1".parse().expect("valid");

    c.bench_function("redirect/absolute", |b| {
        b.iter(|| {
            let policy = hypertor::RedirectPolicy::default();
            let target: Uri = "http://example.onion/other".parse().expect("valid");
            black_box(policy.evaluate(black_box(&base), black_box(&target)))
        })
    });
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
    bench_redirect_resolution,
    bench_request_building
);
criterion_main!(benches);

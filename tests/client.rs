//! Client behaviour that does not require a live Tor connection.
//!
//! Anything needing the real network lives behind `--ignored`, so `cargo test`
//! stays fast and deterministic.

use std::time::Duration;

use hypertor::{Body, Config, Error, IsolationLevel, IsolationToken, RedirectPolicy, TorClient};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[test]
fn config_rejects_nonsense() {
    assert!(Config::builder().timeout(Duration::ZERO).build().is_err());
    assert!(Config::builder().max_response_size(0).build().is_err());
    assert!(Config::builder().user_agent("").build().is_err());
}

#[test]
fn config_rejects_a_user_agent_that_would_inject_headers() {
    let result = Config::builder()
        .user_agent("Mozilla/5.0\r\nX-Injected: yes")
        .build();
    assert!(result.is_err(), "CRLF in the User-Agent must be rejected");
}

#[test]
fn default_config_is_safe() {
    let config = Config::default();

    assert!(
        config.tls.verify_certificates,
        "certificate verification must be on by default"
    );
    assert_eq!(
        config.isolation,
        IsolationLevel::PerHost,
        "the default must not share circuits across every destination"
    );
    assert!(
        config.connect_timeout <= config.timeout,
        "a connect budget larger than the request budget can never elapse"
    );
    assert!(
        !config
            .redirect
            .evaluate(
                &"http://a.onion/".parse().unwrap(),
                &"https://tracker.example/".parse().unwrap(),
            )
            .eq(&hypertor::RedirectAction::Follow),
        "onion-to-clearnet redirects must not be followed silently"
    );
}

// ---------------------------------------------------------------------------
// Isolation
// ---------------------------------------------------------------------------

#[test]
fn isolation_tokens_are_distinct() {
    let a = IsolationToken::new();
    let b = IsolationToken::new();
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------------
// Redirects
// ---------------------------------------------------------------------------

#[test]
fn redirect_policy_strips_credentials_across_origins() {
    let policy = RedirectPolicy::default();

    assert_eq!(
        policy.evaluate(
            &"http://a.onion/one".parse().unwrap(),
            &"http://a.onion/two".parse().unwrap()
        ),
        hypertor::RedirectAction::Follow
    );

    assert_eq!(
        policy.evaluate(
            &"http://a.onion/".parse().unwrap(),
            &"http://b.onion/".parse().unwrap()
        ),
        hypertor::RedirectAction::FollowStripped
    );
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[test]
fn errors_do_not_leak_hostnames() {
    let err = Error::Connect {
        host: safelog::Sensitive::new("hidden-service.onion".to_string()),
        port: 80,
        source: Box::new(std::io::Error::other("refused")),
    };

    let rendered = format!("{err}");
    assert!(
        !rendered.contains("hidden-service"),
        "error text leaked a hostname: {rendered}"
    );
    assert_eq!(err.host(), Some("hidden-service.onion"));
}

#[test]
fn io_errors_say_what_went_wrong() {
    // "I/O error" with the detail buried in the source chain is useless in a
    // log line, which is where these end up.
    let err = Error::from(std::io::Error::other("connection reset by peer"));
    assert!(
        err.to_string().contains("connection reset by peer"),
        "unhelpful error: {err}"
    );
}

#[test]
fn status_errors_carry_the_code() {
    use hypertor::Response;

    let response = Response::new(
        http::StatusCode::TOO_MANY_REQUESTS,
        http::Version::HTTP_11,
        http::HeaderMap::new(),
        bytes::Bytes::new(),
    );

    let err = response.error_for_status().expect_err("429 is an error");
    assert_eq!(err.status(), Some(http::StatusCode::TOO_MANY_REQUESTS));
    assert!(!err.is_retryable());
}

// ---------------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------------

#[test]
fn in_memory_bodies_can_be_retried_and_streams_cannot() {
    // The distinction is what stops a retry or a redirect from resending a
    // stream that has already been consumed.
    assert!(Body::bytes("payload").is_replayable());
    assert!(
        !Body::from_stream(futures::stream::once(async {
            Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"x"))
        }))
        .is_replayable()
    );
}

#[tokio::test]
async fn decompression_bombs_are_bounded_by_the_response_limit() {
    use std::io::Write;

    // 32 MiB of zeroes compresses to a few kilobytes. Decoding must stop at the
    // limit rather than materialising the expansion and checking afterwards.
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(&vec![0u8; 32 * 1024 * 1024]).unwrap();
    let bomb = encoder.finish().unwrap();

    assert!(
        bomb.len() < 64 * 1024,
        "fixture should be small on the wire"
    );

    let response = http::Response::builder()
        .header("content-encoding", "gzip")
        .body(http_body_util::Full::new(bytes::Bytes::from(bomb)))
        .unwrap();

    let err = hypertor::Streaming::from_response(response, 64 * 1024)
        .expect("splits")
        .buffered()
        .await
        .expect_err("must refuse");

    assert!(
        matches!(err, Error::BodyTooLarge { .. }),
        "expected a size error, got: {err}"
    );
}

#[test]
fn stacked_content_encodings_are_refused_rather_than_half_decoded() {
    use hypertor::Encoding;

    let mut headers = http::HeaderMap::new();
    headers.insert("content-encoding", "gzip, br".parse().unwrap());

    assert!(
        Encoding::from_headers(&headers).is_err(),
        "half-decoding would hand the caller bytes that are still compressed"
    );
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

/// Bootstrapping must not panic before it even reaches the network.
///
/// rustls can only infer a cryptography provider when exactly one is compiled
/// in, and *panics* rather than guessing otherwise — at the moment something
/// first builds a TLS configuration, which for hypertor is inside
/// `TorClient::new()`. hypertor used to force `ring` for its own TLS while arti
/// pulled in `aws-lc-rs` for Tor link TLS, so a default build had both and
/// aborted the process here. Every network test being `#[ignore]`d is what let
/// that ship.
///
/// hypertor's own graph now resolves to `aws-lc-rs` alone, but the explicit
/// install in `hypertor::tls` stays: as a *library*, hypertor cannot stop an
/// application from pulling rustls's `ring` feature in from somewhere else and
/// reintroducing the ambiguity — in which case the panic would land in that
/// application's build, at runtime, for a reason with nothing to do with its
/// own code.
///
/// # Why this builds a *lazy* client
///
/// The panic being guarded against happens while building the rustls
/// `ClientConfig`, which `TorClientBuilder::build` does on every path — see
/// `TorClient::from_arti`. Reaching it therefore needs no network, and a lazy
/// client reaches it without opening a single connection.
///
/// This test used to call `TorClient::new()` — a full eager bootstrap — under a
/// five-second `tokio::time::timeout`, on the theory that the deadline made the
/// network incidental. It does not. Cancelling the future does not stop the
/// background tasks arti has already spawned, and tearing the runtime down
/// afterwards waits on their `spawn_blocking` work, so on a runner where the
/// directory fetch stalls the test hangs for as long as CI will let it. It hung
/// for twenty minutes on Windows.
#[tokio::test]
async fn building_a_client_does_not_panic_on_an_ambiguous_crypto_provider() {
    let dir = std::env::temp_dir().join("hypertor-crypto-provider-test");
    // Never reuse the developer's real arti state: this test is about a panic
    // at construction, and it has no business reading or writing live keys.
    tokio::fs::remove_dir_all(&dir).await.ok();

    let client = TorClient::builder()
        .lazy_bootstrap(true)
        .state_dir(dir.join("state"))
        .cache_dir(dir.join("cache"))
        .build()
        .await
        .expect("building a client must not panic or fail before any network use");

    // Returning `Ok` at all is the assertion that matters: both branches of
    // `build` finish in `TorClient::from_arti`, which constructs the
    // `TlsConnector` — and therefore the rustls `ClientConfig` — and propagates
    // its failure. Getting a client back means that ran without aborting.
    assert!(client.config().tls.verify_certificates);

    tokio::fs::remove_dir_all(&dir).await.ok();
}

// ---------------------------------------------------------------------------
// Live network tests
// ---------------------------------------------------------------------------

/// Bootstrapping and reaching a real onion service.
///
/// Run with: `cargo test --test client -- --ignored --nocapture`
#[tokio::test]
#[ignore = "requires a live Tor connection"]
async fn reaches_an_onion_service() {
    let client = TorClient::new().await.expect("bootstraps");

    let response = client
        .get("http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/")
        .expect("valid url")
        .send()
        .await
        .expect("request succeeds");

    assert!(response.status().is_success() || response.status().is_redirection());
}

/// The second request to a host must reuse the pooled connection.
#[tokio::test]
#[ignore = "requires a live Tor connection"]
async fn pooling_makes_the_second_request_faster() {
    let client = TorClient::new().await.expect("bootstraps");
    let url = "https://check.torproject.org/api/ip";

    let cold = std::time::Instant::now();
    client
        .get(url)
        .unwrap()
        .send()
        .await
        .expect("first request");
    let cold = cold.elapsed();

    let warm = std::time::Instant::now();
    client
        .get(url)
        .unwrap()
        .send()
        .await
        .expect("second request");
    let warm = warm.elapsed();

    assert!(
        warm < cold,
        "a pooled connection should be faster: cold {cold:?}, warm {warm:?}"
    );
}

/// Different isolation tokens must land on different exit relays.
#[tokio::test]
#[ignore = "requires a live Tor connection"]
async fn isolation_yields_different_exits() {
    let client = TorClient::builder()
        .isolation(IsolationLevel::None)
        .build()
        .await
        .expect("bootstraps");

    let url = "https://check.torproject.org/api/ip";
    let mut seen = std::collections::HashSet::new();

    for _ in 0..3 {
        let value: serde_json::Value = client
            .get(url)
            .unwrap()
            .isolation(IsolationToken::new())
            .send()
            .await
            .expect("request")
            .json()
            .expect("json");

        if let Some(ip) = value["IP"].as_str() {
            seen.insert(ip.to_string());
        }
    }

    assert!(
        seen.len() > 1,
        "three isolated requests all used one exit relay: {seen:?}"
    );
}

/// A large download must not have to fit in memory.
#[tokio::test]
#[ignore = "requires a live Tor connection"]
async fn streams_a_body_without_buffering_it() {
    let client = TorClient::builder()
        // Far below the download size: the streaming API must not be bound by
        // the buffered default, only by what it is told.
        .max_response_size(64 * 1024 * 1024)
        .build()
        .await
        .expect("bootstraps");

    let mut response = client
        .get("https://check.torproject.org/api/ip")
        .expect("valid url")
        .send_streaming()
        .await
        .expect("headers arrive");

    let mut total = 0usize;
    while let Some(chunk) = response.chunk().await.expect("chunk") {
        total += chunk.len();
    }
    assert!(total > 0);
}

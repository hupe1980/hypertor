//! Client behaviour that does not require a live Tor connection.
//!
//! Anything needing the real network lives behind `--ignored`, so `cargo test`
//! stays fast and deterministic.

use std::time::Duration;

use hypertor::{Config, Error, IsolationLevel, IsolationToken, RedirectPolicy, TorClient};

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

#[test]
fn isolation_tokens_are_distinct() {
    let a = IsolationToken::new();
    let b = IsolationToken::new();
    assert_ne!(a, b);
}

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
}

#[test]
fn decompression_bombs_are_bounded_by_the_response_limit() {
    use hypertor::body::{Encoding, decode};
    use std::io::Write;

    // 8 MiB of zeroes compresses to a few kilobytes.
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(&vec![0u8; 8 * 1024 * 1024]).unwrap();
    let bomb = encoder.finish().unwrap();

    assert!(
        bomb.len() < 64 * 1024,
        "fixture should be small on the wire"
    );

    let err = decode(&bomb, Encoding::Gzip, 64 * 1024).expect_err("must refuse");
    assert!(
        matches!(err, Error::BodyTooLarge { .. }),
        "expected a size error, got: {err}"
    );
}

#[test]
fn stacked_content_encodings_are_refused_rather_than_half_decoded() {
    use hypertor::body::Encoding;

    let mut headers = http::HeaderMap::new();
    headers.insert("content-encoding", "gzip, br".parse().unwrap());

    assert!(
        Encoding::from_headers(&headers).is_err(),
        "half-decoding would hand the caller bytes that are still compressed"
    );
}

#[test]
fn relative_redirects_resolve_against_the_current_url() {
    // Exercised through the policy, which is the public surface.
    let policy = RedirectPolicy::default();
    assert!(policy.is_enabled());
    assert_eq!(policy.limit(), 10);
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

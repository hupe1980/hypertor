//! Onion service and HTTP framework behaviour.

use hypertor::{OnionServiceBuilder, ServeResponse};

#[test]
fn nicknames_are_validated_before_launch() {
    assert!(OnionServiceBuilder::new().nickname("valid-name").is_ok());
    assert!(OnionServiceBuilder::new().nickname("").is_err());
    assert!(OnionServiceBuilder::new().nickname("with spaces").is_err());
    assert!(OnionServiceBuilder::new().nickname("with/slash").is_err());
}

#[test]
fn response_headers_cannot_be_injected() {
    // A handler echoing user input must not be able to split the response.
    let response = ServeResponse::text("body").with_header("x-echo", "ok\r\nX-Admin: true");

    let rendered = format!("{response:?}");
    assert!(
        !rendered.contains("X-Admin"),
        "a CRLF header value was accepted: {rendered}"
    );
}

#[test]
fn json_responses_are_well_formed() {
    let response = ServeResponse::json(&serde_json::json!({"status": "ok"}));
    assert!(format!("{response:?}").contains("200"));
}

/// Launching a real service and serving a request over it.
///
/// Run with: `cargo test --test server -- --ignored --nocapture`
#[tokio::test]
#[ignore = "requires a live Tor connection"]
async fn serves_over_a_real_onion_service() {
    use hypertor::{OnionApp, TorClient};

    let app = OnionApp::new().get("/ping", |_req| async { ServeResponse::text("pong") });

    let service = OnionServiceBuilder::new()
        .nickname("hypertor-integration")
        .expect("valid nickname")
        .launch()
        .await
        .expect("launches");

    let address = service.onion_address().to_string();
    let serving = app.serve_on(service).await.expect("serves");

    // Publishing a descriptor takes a moment before clients can find it.
    tokio::time::sleep(std::time::Duration::from_secs(20)).await;

    let client = TorClient::new().await.expect("bootstraps");
    let response = client
        .get(&format!("http://{address}/ping"))
        .expect("valid url")
        .send()
        .await
        .expect("request succeeds");

    assert_eq!(response.text().expect("utf-8"), "pong");
    serving.shutdown();
}

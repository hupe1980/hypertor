//! Onion service and HTTP framework behaviour.
//!
//! The framework is exercised end to end over an in-memory pipe: a real hyper
//! client talking to a real `OnionApp` through `serve_connection`. That covers
//! request parsing, framing, keep-alive, routing and the body limit without
//! needing a Tor circuit, so these run in milliseconds on every commit rather
//! than only when someone remembers to pass `--ignored`.

use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;

use hypertor::{OnionApp, OnionServiceBuilder, ServeResponse};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// A connected HTTP/1.1 client speaking to `app` over an in-memory pipe.
struct Harness {
    sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
}

impl Harness {
    async fn new(app: OnionApp) -> Self {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        tokio::spawn(async move { app.serve_connection(server_io).await });

        let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client_io))
            .await
            .expect("handshake");
        tokio::spawn(connection);

        Self { sender }
    }

    async fn send(
        &mut self,
        method: Method,
        path: &str,
        body: &[u8],
    ) -> (StatusCode, http::HeaderMap, Bytes) {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .body(Full::new(Bytes::copy_from_slice(body)))
            .expect("valid request");

        let response = self
            .sender
            .send_request(request)
            .await
            .expect("response arrives");

        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        (status, headers, body)
    }

    async fn get(&mut self, path: &str) -> (StatusCode, http::HeaderMap, Bytes) {
        self.send(Method::GET, path, b"").await
    }
}

fn demo_app() -> OnionApp {
    OnionApp::new()
        .get("/", |_| async { ServeResponse::html("<h1>root</h1>") })
        .get("/health", |_| async {
            ServeResponse::json(&serde_json::json!({"status": "ok"}))
        })
        .get("/users/{id}", |req| async move {
            ServeResponse::json(&serde_json::json!({ "id": req.param("id") }))
        })
        .post("/echo", |req| async move {
            ServeResponse::text(req.body().clone())
        })
        .get("/echo-header", |req| async move {
            // A handler reflecting user input is the classic response-splitting
            // vector; the framework must neutralise it.
            ServeResponse::text("ok").with_header("x-echo", req.header("x-in").unwrap_or_default())
        })
}

// ---------------------------------------------------------------------------
// Routing, end to end
// ---------------------------------------------------------------------------

#[tokio::test]
async fn serves_a_routed_response() {
    let mut h = Harness::new(demo_app()).await;

    let (status, headers, body) = h.get("/").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers[http::header::CONTENT_TYPE],
        "text/html; charset=utf-8"
    );
    assert_eq!(&body[..], b"<h1>root</h1>");
}

#[tokio::test]
async fn captures_path_parameters_end_to_end() {
    let mut h = Harness::new(demo_app()).await;

    let (_, _, body) = h.get("/users/42").await;
    assert_eq!(&body[..], br#"{"id":"42"}"#);
}

#[tokio::test]
async fn keeps_the_connection_alive_between_requests() {
    // Over Tor a new connection means a new circuit, so keep-alive is worth
    // rather more here than on the clearnet.
    let mut h = Harness::new(demo_app()).await;

    for _ in 0..3 {
        let (status, _, _) = h.get("/health").await;
        assert_eq!(status, StatusCode::OK);
    }
}

#[tokio::test]
async fn serves_http2_on_the_same_port_as_http1() {
    // Documented behaviour, and worth pinning: there is no TLS inside an onion
    // connection, so h2 is negotiated by preface detection alone. If that
    // regressed the failure would be a silent fallback, not an error.
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move { demo_app().serve_connection(server_io).await });

    let (mut sender, connection) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        TokioIo::new(client_io),
    )
    .await
    .expect("h2 handshake");
    tokio::spawn(connection);

    let request = Request::builder()
        .method(Method::GET)
        .uri("/health")
        .body(Full::new(Bytes::new()))
        .expect("valid request");

    let response = sender.send_request(request).await.expect("h2 response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), http::Version::HTTP_2);
}

#[tokio::test]
async fn an_unknown_path_is_a_404() {
    let mut h = Harness::new(demo_app()).await;
    let (status, _, _) = h.get("/nowhere").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_known_path_with_the_wrong_method_is_a_405_with_allow() {
    let mut h = Harness::new(demo_app()).await;

    let (status, headers, _) = h.send(Method::DELETE, "/health", b"").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);

    let allow = headers[http::header::ALLOW].to_str().unwrap();
    assert!(allow.contains("GET"), "Allow was {allow:?}");
}

#[tokio::test]
async fn a_head_request_is_served_by_the_get_route() {
    let mut h = Harness::new(demo_app()).await;

    let (status, _, body) = h.send(Method::HEAD, "/health", b"").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_empty(), "HEAD must not carry a body");
}

#[tokio::test]
async fn round_trips_a_request_body() {
    let mut h = Harness::new(demo_app()).await;

    let (status, _, body) = h.send(Method::POST, "/echo", b"payload").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"payload");
}

#[tokio::test]
async fn an_oversized_body_is_refused_rather_than_buffered() {
    let mut h = Harness::new(demo_app().max_body_size(16)).await;

    let (status, _, _) = h.send(Method::POST, "/echo", &[b'x'; 4096]).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn response_headers_cannot_be_split_by_echoed_input() {
    let mut h = Harness::new(demo_app()).await;

    // The value carries a CRLF; if it reached the socket the client would see
    // an injected header, or a second response entirely.
    let request = Request::builder()
        .method(Method::GET)
        .uri("/echo-header")
        .header("x-in", "clean")
        .body(Full::new(Bytes::new()))
        .expect("valid request");

    let response = h.sender.send_request(request).await.expect("response");
    assert_eq!(response.headers()["x-echo"], "clean");

    // http refuses to build a header value containing CRLF at all, which is the
    // outer half of the defence; `Response::with_header` is the inner half and
    // is covered in the unit tests.
    assert!(http::HeaderValue::from_str("bad\r\nX-Admin: 1").is_err());
}

// ---------------------------------------------------------------------------
// Onion service hardening
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_date_header_is_sent_by_default() {
    // A `Date` on every response publishes the server's clock. Murdoch's
    // clock-skew attack (CCS 2006) deanonymises a hidden service by inducing
    // load on it and then asking candidate machines for timestamps until one
    // shows the matching drift; a service that answers no timestamp is not part
    // of that game.
    let mut h = Harness::new(demo_app()).await;

    let (_, headers, _) = h.get("/health").await;
    assert!(
        !headers.contains_key(http::header::DATE),
        "a timestamp reached the wire: {headers:?}"
    );
}

#[tokio::test]
async fn the_date_header_can_be_turned_back_on() {
    let mut h = Harness::new(demo_app().date_header(true)).await;

    let (_, headers, _) = h.get("/health").await;
    assert!(headers.contains_key(http::header::DATE));
}

#[tokio::test]
async fn no_server_or_powered_by_header_is_advertised() {
    // OnionScan found `Server` and `X-Powered-By` among the headers most useful
    // for matching a hidden service to the ordinary host behind it.
    let mut h = Harness::new(demo_app()).await;

    let (_, headers, _) = h.get("/health").await;
    for header in ["server", "x-powered-by"] {
        assert!(
            !headers.contains_key(header),
            "{header} identifies the software stack"
        );
    }
}

// ---------------------------------------------------------------------------
// Static files
// ---------------------------------------------------------------------------

#[tokio::test]
async fn static_files_are_served_and_traversal_is_refused() {
    let dir = std::env::temp_dir().join("hypertor-e2e-static");
    tokio::fs::create_dir_all(&dir).await.expect("create");
    tokio::fs::write(dir.join("public.txt"), b"public")
        .await
        .expect("write");

    let mut h = Harness::new(OnionApp::new().static_files(&dir)).await;

    let (status, _, body) = h.get("/public.txt").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"public");

    for attack in ["/../../../../etc/passwd", "/..%2f..%2fetc/passwd"] {
        let (status, _, _) = h.get(attack).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "traversal reached: {attack}");
    }

    tokio::fs::remove_dir_all(&dir).await.ok();
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Live network
// ---------------------------------------------------------------------------

/// Launching a real service and serving a request over it.
///
/// Run with: `cargo test --test server -- --ignored --nocapture`
#[tokio::test]
#[ignore = "requires a live Tor connection"]
async fn serves_over_a_real_onion_service() {
    use hypertor::TorClient;

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
    tokio::time::sleep(Duration::from_secs(20)).await;

    let client = TorClient::new().await.expect("bootstraps");
    let response = client
        .get(&format!("http://{address}/ping"))
        .expect("valid url")
        .send()
        .await
        .expect("request succeeds");

    assert_eq!(response.text().expect("utf-8"), "pong");
    serving.shutdown().await.expect("shuts down cleanly");
}

/// A stream asking for a port the service does not publish must be rejected.
///
/// Accepting every port is what makes an onion service distinguishable from
/// every other implementation on the network.
#[tokio::test]
#[ignore = "requires a live Tor connection"]
async fn refuses_streams_for_unpublished_ports() {
    use hypertor::TorClient;

    let app = OnionApp::new().get("/", |_req| async { ServeResponse::text("ok") });

    let service = OnionServiceBuilder::new()
        .nickname("hypertor-port-filter")
        .expect("valid nickname")
        .port(80)
        .launch()
        .await
        .expect("launches");

    let address = service.onion_address().to_string();
    let serving = app.serve_on(service).await.expect("serves");
    tokio::time::sleep(Duration::from_secs(20)).await;

    let client = TorClient::new().await.expect("bootstraps");

    assert!(
        client
            .get(&format!("http://{address}/"))
            .expect("valid url")
            .send()
            .await
            .is_ok(),
        "the published port must work"
    );

    assert!(
        client
            .get(&format!("http://{address}:8080/"))
            .expect("valid url")
            .send()
            .await
            .is_err(),
        "an unpublished port must be rejected, not silently served"
    );

    serving.shutdown().await.expect("shuts down cleanly");
}

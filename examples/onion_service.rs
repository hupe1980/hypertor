//! Hosting an onion service.
//!
//! ```console
//! $ cargo run --example onion_service --features server
//! ```
//!
//! Proof-of-work needs the `pow` feature, which pulls in LGPL-3.0 dependencies
//! and is therefore opt-in:
//!
//! ```console
//! $ cargo run --example onion_service --features "server,pow"
//! ```

use hypertor::{OnionApp, OnionService, ServeResponse};

#[tokio::main]
async fn main() -> hypertor::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("hypertor=info")
        .init();

    let app = OnionApp::new()
        .get("/", |_req| async {
            ServeResponse::html("<h1>Hello from a .onion service</h1>")
        })
        .get("/health", |_req| async {
            ServeResponse::json(&serde_json::json!({"status": "ok"}))
        })
        .get("/users/{id}", |req| async move {
            let id = req.param("id").unwrap_or("unknown").to_string();
            ServeResponse::json(&serde_json::json!({"id": id}))
        })
        .post("/echo", |req| async move {
            match req.text() {
                Ok(body) => ServeResponse::json(&serde_json::json!({"received": body})),
                Err(e) => {
                    ServeResponse::new(http::StatusCode::BAD_REQUEST).with_body(e.to_string())
                }
            }
        });

    // The nickname is the identity: the address is derived from a key arti
    // files under it. Relaunching with the same nickname republishes the same
    // .onion address — including without `state_dir`, which only chooses *where*
    // that key lives rather than whether it is kept.
    let service = OnionService::builder()
        .nickname("hypertor-example")?
        .state_dir("./onion-state")
        // Proof-of-work only engages under load, so it costs ordinary clients
        // nothing while raising the price of an introduction flood. Requires
        // the `pow` feature.
        .proof_of_work(cfg!(feature = "pow"))
        .launch()
        .await?;

    let serving = app.serve_on(service).await?;

    println!("\n  🧅 {}\n", serving.onion_address());
    println!("  reach it with any Tor-capable client, for example:");
    println!(
        "    curl --socks5-hostname 127.0.0.1:9050 http://{}/",
        serving.onion_address()
    );
    println!("  (run `cargo run --example socks_proxy` for that proxy)\n");

    serving.wait().await
}

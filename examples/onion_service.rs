//! Onion Service Example - Host a .onion website
//!
//! This example demonstrates how to create and run an anonymous
//! web service as a Tor onion (hidden service).
//!
//! Run with: cargo run --example onion_service --features server

use hypertor::{OnionApp, OnionAppConfig, Result, ServeRequest, ServeResponse};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

// =============================================================================
// Data Models
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Message {
    content: String,
    #[serde(default = "default_sender")]
    sender: String,
}

fn default_sender() -> String {
    "anonymous".to_string()
}

#[derive(Debug, Clone, Serialize)]
struct ServiceInfo {
    name: &'static str,
    version: &'static str,
    anonymous: bool,
    powered_by: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct HealthStatus {
    status: &'static str,
    tor_connected: bool,
    request_count: usize,
}

// =============================================================================
// Shared State
// =============================================================================

struct AppState {
    messages: parking_lot::Mutex<Vec<Message>>,
    request_count: AtomicUsize,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            messages: parking_lot::Mutex::new(Vec::new()),
            request_count: AtomicUsize::new(0),
        }
    }
}

// =============================================================================
// Main
// =============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("🧅 hypertor - Onion Service Example");
    println!("====================================");
    println!();

    // Create shared state
    let state = Arc::new(AppState::default());

    // Clone state for closures
    let state_health = Arc::clone(&state);
    let state_list = Arc::clone(&state);
    let state_create = Arc::clone(&state);

    // Build the OnionApp
    let config = OnionAppConfig::default();

    let app = OnionApp::with_config(config)
        // Root endpoint
        .get("/", |_req: ServeRequest| async {
            ServeResponse::json(&serde_json::json!({
                "service": "hypertor-example",
                "message": "Welcome to my anonymous onion service! 🧅",
                "endpoints": ["/", "/api/info", "/api/health", "/api/messages"]
            }))
            .unwrap_or_else(|_| ServeResponse::internal_error("JSON error"))
        })
        // Service info
        .get("/api/info", |_req: ServeRequest| async {
            ServeResponse::json(&ServiceInfo {
                name: "HyperTor Example Service",
                version: "1.0.0",
                anonymous: true,
                powered_by: "hypertor",
            })
            .unwrap_or_else(|_| ServeResponse::internal_error("JSON error"))
        })
        // Health check
        .get("/api/health", move |_req: ServeRequest| {
            let state = Arc::clone(&state_health);
            async move {
                let count = state.request_count.fetch_add(1, Ordering::Relaxed);
                ServeResponse::json(&HealthStatus {
                    status: "healthy",
                    tor_connected: true,
                    request_count: count,
                })
                .unwrap_or_else(|_| ServeResponse::internal_error("JSON error"))
            }
        })
        // Echo endpoint
        .post("/api/echo", |req: ServeRequest| async move {
            match req.json::<serde_json::Value>() {
                Ok(data) => ServeResponse::json(&serde_json::json!({
                    "echoed": data,
                    "message": "Your data was received anonymously!"
                }))
                .unwrap_or_else(|_| ServeResponse::internal_error("JSON error")),
                Err(_) => ServeResponse::new(400).with_body("Invalid JSON body"),
            }
        })
        // List messages
        .get("/api/messages", move |_req: ServeRequest| {
            let state = Arc::clone(&state_list);
            async move {
                let messages = state.messages.lock();
                ServeResponse::json(&serde_json::json!({
                    "count": messages.len(),
                    "messages": *messages
                }))
                .unwrap_or_else(|_| ServeResponse::internal_error("JSON error"))
            }
        })
        // Create message
        .post("/api/messages", move |req: ServeRequest| {
            let state = Arc::clone(&state_create);
            async move {
                match req.json::<Message>() {
                    Ok(message) => {
                        let mut messages = state.messages.lock();
                        messages.push(message.clone());
                        ServeResponse::json(&serde_json::json!({
                            "success": true,
                            "message": "Message created",
                            "data": message
                        }))
                        .unwrap_or_else(|_| ServeResponse::internal_error("JSON error"))
                    }
                    Err(_) => ServeResponse::new(400).with_body("Invalid JSON body"),
                }
            }
        });

    println!("Starting onion service...");
    println!();
    println!("This will:");
    println!("  1. Connect to the Tor network");
    println!("  2. Create an onion service");
    println!("  3. Print your .onion address");
    println!("  4. Start accepting connections");
    println!();
    println!("Press Ctrl+C to stop.");
    println!();

    // Run the service
    // This will print the .onion address once ready
    app.run().await?;

    Ok(())
}

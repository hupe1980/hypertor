---
title: "Onion Services"
permalink: /docs/server/
toc: true
---

Hosting a `.onion` service. Requires the `server` feature:

```toml
hypertor = { version = "0.3", features = ["server"] }
```

There are two layers. `OnionService` publishes the service and hands you raw inbound streams;
`OnionApp` puts a routed HTTP framework on top of it. Use `OnionApp` unless you are speaking a
protocol other than HTTP.

## An HTTP service

```rust
use hypertor::{OnionApp, ServeResponse};

#[tokio::main]
async fn main() -> hypertor::Result<()> {
    let app = OnionApp::new()
        .get("/", |_req| async { ServeResponse::html("<h1>hello</h1>") })
        .get("/health", |_req| async {
            ServeResponse::json(&serde_json::json!({"status": "ok"}))
        });

    let service = app.serve("my-service").await?;
    println!("live at {}", service.onion_address());
    service.wait().await
}
```

The HTTP itself is hyper's, so chunked bodies, keep-alive, pipelining and HTTP/2 behave exactly as
they do in any other hyper server.

## Keeping your address

A `.onion` address is derived from a keypair. **Without a persistent state directory, arti generates
a new keypair — and therefore a new address — on every start.**

```rust
use hypertor::OnionService;

let service = OnionService::builder()
    .nickname("my-service")?
    .state_dir("/var/lib/my-service")
    .launch()
    .await?;
```

Treat that directory as secret key material. Anyone who copies it can impersonate your service, and
there is no revocation.

## Routing

```rust
let app = OnionApp::new()
    .get("/", handler)
    .post("/api/items", handler)
    .put("/api/items/{id}", handler)
    .delete("/api/items/{id}", handler)
    .fallback(|_req| async { ServeResponse::not_found() });
```

Patterns capture path segments with `{name}` (or `:name`), available through `Request::param`.
Captured values are percent-decoded.

```rust
.get("/users/{id}/posts/{post}", |req| async move {
    let user = req.param("id").unwrap_or_default();
    let post = req.param("post").unwrap_or_default();
    ServeResponse::json(&serde_json::json!({ "user": user, "post": post }))
})
```

`HEAD` requests are served by the matching `GET` route.

## Requests

```rust
req.method();          // &Method
req.path();            // &str, without the query string
req.query("q");        // Option<&str>, decoded
req.param("id");       // Option<&str>, from the route pattern
req.headers();         // &HeaderMap
req.body();            // &Bytes
req.text()?;           // String
let value: T = req.json()?;
```

Request bodies are capped at 2 MiB by default; a larger body gets a `413` instead of allocating.

```rust
OnionApp::new().max_body_size(16 * 1024 * 1024)
```

## Responses

```rust
ServeResponse::text("plain");
ServeResponse::html("<h1>markup</h1>");
ServeResponse::json(&value);
ServeResponse::not_found();
ServeResponse::status(StatusCode::CREATED).with_body("done");

ServeResponse::text("body")
    .with_header("Cache-Control", "no-store")
    .with_status(StatusCode::ACCEPTED);
```

Header values containing CR or LF are refused rather than written to the socket. Without that, a
handler echoing user input into a header could split the response and inject headers of the
attacker's choosing.

## Static files

```rust
OnionApp::new().static_files("./public")
```

Served only for `GET` and `HEAD`, and only when no route matched. Paths are rejected before touching
the filesystem if they contain any traversal component, then canonicalised and confirmed to resolve
inside the root — so neither `../` nor a symlink pointing outside can be used to read arbitrary
files.

## Hardening

Every option below maps to an arti feature. hypertor implements none of this itself.

```rust
OnionService::builder()
    .nickname("high-value")?
    .state_dir("/var/lib/svc")
    .vanguards(hypertor::VanguardMode::Full)
    .proof_of_work(true)          // requires the `pow` feature
    .pow_queue_depth(16_000)
    .rate_limit_at_intro(10, 20)
    .max_streams_per_circuit(100)
    .num_intro_points(5)
    .launch()
    .await?;
```

### Vanguards

Onion services keep long-lived circuits, which is exactly the condition guard-discovery attacks
exploit: an adversary who can repeatedly cause your service to build circuits can, over time,
identify your guard relay and from there your location. Vanguards pin the middle positions of your
circuits to a slowly-rotating set, greatly raising that cost.

`VanguardMode::Full` is the strongest. Leaving it unset accepts arti's default, which already
enables vanguards-lite where it matters.

### Proof of work

`proof_of_work(true)` enables the Equi-X scheme from
[Tor proposal 327](https://spec.torproject.org/hspow-spec/). It engages only when the service is
under load, so ordinary clients pay nothing while an introduction flood becomes expensive.

**Requires the `pow` feature**, which is not part of `full`: the Equi-X crates (`equix`, `hashx`)
are LGPL-3.0-only while hypertor is MIT, so a default build stays permissively licensed.

```toml
hypertor = { version = "0.3", features = ["server", "pow"] }
```

Enabling it without the feature fails at launch rather than leaving you with a service you believe
is protected but is not.

### Restricted discovery

The strongest defence available. With clients authorised, the service descriptor is encrypted so
that only holders of the listed keys can find the introduction points — unauthorised clients cannot
discover the service at all, let alone connect to it.

```rust
OnionService::builder()
    .nickname("private")?
    .authorize_client("alice", alice_public_key)
    .authorize_client("bob", bob_public_key)
    .launch()
    .await?;
```

Clients generate their own keypairs with `arti hsc get-key` and send you only the public half.
**hypertor deliberately does not generate these for you:** the secret half must never exist on the
server, and an API that produced both would invite exactly that mistake. arti supports roughly 160
authorised clients per service.

## Raw streams

For protocols other than HTTP:

```rust
let mut service = OnionService::builder()
    .nickname("raw")?
    .port(1234)
    .launch()
    .await?;

while let Some(stream) = service.accept().await {
    tokio::spawn(async move {
        // `stream` is AsyncRead + AsyncWrite.
    });
}
```

## Shutdown

Dropping an `OnionService` retracts it and stops publishing its descriptor. `ServingApp::shutdown`
stops an `OnionApp`.

Note that a descriptor already published stays in the directory for a while after shutdown, so
clients may keep trying to reach you for several minutes.

## Timing

| Step | Typical |
|---|---|
| Bootstrapping Tor | 10–60 s cold, 1–5 s warm |
| Building introduction circuits | 5–30 s |
| Publishing the descriptor | 10–60 s |
| First client connection succeeding | up to ~2 minutes after launch |

A service is not reachable the instant `launch()` returns — the descriptor still has to propagate.

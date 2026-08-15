+++
title = "Onion services"
description = "Host a .onion service: routing, static files, persistence, shutdown and the hardening options arti exposes."
weight = 4
+++

Hosting a `.onion` service. Requires the `server` feature:

```bash
cargo add hypertor --features server
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

The HTTP itself is hyper's, so request parsing, chunked bodies and keep-alive behave exactly as they
do in any other hyper server.

**HTTP/1.1 and HTTP/2 are both served on the same virtual port.** There is no TLS inside an onion
connection — Tor already provides the encryption and authentication — so there is no ALPN either;
h2c is negotiated by detecting the HTTP/2 connection preface.

## Your address, and what decides it

A `.onion` address is derived from a keypair that arti files under the service **nickname**, inside
its state directory. The default state directory is a persistent per-user one — `~/.local/share/arti`
on Linux, `~/Library/Application Support/arti` on macOS — so:

**Relaunching with the same nickname republishes the same address, whether or not you set
`state_dir`.** There is no "ephemeral" mode: arti has to keep the key somewhere for the address to
mean anything at all.

```rust
use hypertor::OnionService;

let service = OnionService::builder()
    .nickname("my-service")?            // <- this is the identity
    .state_dir("/var/lib/my-service")   // <- this is only where it lives
    .launch()
    .await?;
```

Set `state_dir` when the key must survive being deployed to another machine, or must not be written
into the invoking user's home directory. To get a *different* address, change the nickname or point
`state_dir` at a directory that does not yet exist.

The default nickname is `hypertor`, which means two unrelated programs that both leave it alone
publish the same address on one machine and evict each other. Pick something specific.

Treat the directory as secret key material. Anyone who copies it can impersonate your service, and
there is no revocation.

## Virtual ports

```rust
OnionService::builder()
    .nickname("my-service")?
    .port(80)                 // replaces the default
    .launch()
    .await?;

OnionService::builder()
    .nickname("multi")?
    .ports([80, 443])         // several at once
    .launch()
    .await?;
```

The default is port 80. A stream asking for any other port is rejected with `END DONE`, and anything
that is not a `BEGIN` message — `BEGIN_DIR`, `RESOLVE` — is rejected too.

This is a privacy property, not just tidiness. arti's own documentation is explicit:

> for consistency with other onion service implementations, you should typically only accept BEGIN
> messages, and only check the port in those messages. **If you behave differently, your
> implementation will be distinguishable.**

Launching with an empty port list is an error, because such a service would publish a descriptor and
then refuse every client.

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

- `HEAD` requests are served by the matching `GET` route.
- A path that exists but not for the requested method returns **`405 Method Not Allowed`** with an
  `Allow` header, not a `404`. A `404` there would claim the path does not exist, which is untrue
  and sends the caller looking in the wrong place.
- Where several routes match, **the one matching the most segments literally wins**, regardless of
  registration order. So `/users/me` is reachable even when `/users/{id}` was registered first — the
  alternative is a handler that is never called and nothing anywhere saying why.

## Requests

```rust
req.method();          // &Method
req.path();            // &str, without the query string
req.query("q");        // Option<&str>, decoded
req.queries();         // &HashMap<String, String>
req.param("id");       // Option<&str>, from the route pattern
req.params();          // &HashMap<String, String>
req.headers();         // &HeaderMap
req.body();            // &Bytes
req.text()?;           // String
let value: T = req.json()?;
```

Request bodies are capped at 2 MiB by default; a larger body gets a `413` instead of allocating.
Routing happens *before* the body is read, so a request to a path that does not exist never makes
the service buffer anything.

```rust
OnionApp::new().max_body_size(16 * 1024 * 1024)
```

## Responses

```rust
ServeResponse::text("plain");
ServeResponse::html("<h1>markup</h1>");
ServeResponse::json(&value);
ServeResponse::json_raw(already_serialised);
ServeResponse::not_found();
ServeResponse::new(StatusCode::CREATED).with_body("done");

ServeResponse::text("body")
    .with_header("Cache-Control", "no-store")
    .with_status(StatusCode::ACCEPTED);

// Streamed from disk, never held in memory. Content-Length and Content-Type
// are filled in for you.
ServeResponse::from_file("./video.mp4").await?;
```

Reading back: `response.status()`, `response.headers()`, and `response.body()` — which returns
`None` for a streamed body, because inspecting one would mean consuming it.

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

A request for a directory serves its `index.html`. A directory without one is **not listed**:
publishing filenames the operator never chose to expose is a leak, not a convenience.

**Files are streamed off disk, not buffered.** A service that read whole files into memory could be
made to exhaust it with a handful of concurrent requests for a large one — and over Tor the
requester's address is hidden by the same network that hides the operator's.

Every file carries an `ETag`, and a request whose `If-None-Match` matches gets a `304` with no body.
Bandwidth is the scarce resource on an onion circuit, so that is worth rather more here than on the
clearnet. A `HEAD` request returns the same metadata without opening the file at all.

That `ETag` is **not** the usual `mtime-size` validator. OnionScan's survey of the dark web found
`ETag` and `Last-Modified` among the headers most useful for matching a hidden service to the
ordinary host serving the same files, and an `mtime-size` validator is reproducible by anyone
holding a copy. hypertor's is a keyed hash under a key generated at startup: it still changes exactly
when the file changes, but it cannot be recomputed off-host and it embeds no timestamp. No
`Last-Modified` is sent at all. The cost is that caches revalidate once after a restart.

Responses also carry `X-Content-Type-Options: nosniff`, since the content type is a guess from the
file extension and a browser overruling that guess is how an uploaded `.txt` becomes script.

## Serving over any transport

`OnionApp::serve_connection` serves one already-accepted stream and returns when it closes. That is
the seam `serve_on` is built from, and it is public so an app can be served over a Unix socket, a
local TCP listener during development, or an in-memory pipe in your tests.

```rust
let (client, server) = tokio::io::duplex(64 * 1024);
tokio::spawn(async move { app.serve_connection(server).await });
// `client` now speaks HTTP to the app — no Tor circuit involved.
```

hypertor's own test suite drives the framework this way, which is why routing, `405`s, body limits
and HTTP/2 are covered on every commit rather than only when someone runs the live tests.

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

`state_dir` and `vanguards` configure the Tor client, so they apply only when the builder launches
one of its own. If you pass an already-built client to `on_client` — to share one directory cache and
guard set with a `TorClient` — configure both there instead; hypertor logs a warning rather than
quietly ignoring them, because a state directory that is silently not used means a service at an
address its operator did not expect.

The HTTP layer adds its own limits:

```rust
use std::time::Duration;

OnionApp::new()
    .max_body_size(2 * 1024 * 1024)            // 413 beyond this
    .header_timeout(Duration::from_secs(30))   // slowloris defence
    .max_connections(256)                      // concurrent connections
    .date_header(false)                        // the default; see below
```

### The service publishes no timestamp

`Date` is **not sent** by default. A timestamp on every response is an oracle for Murdoch's
clock-skew attack ([CCS 2006](https://murdoch.is/papers/ccs06hotornot.pdf)): quartz crystals change
speed with temperature, so an attacker loads the hidden service to warm it, then requests timestamps
from candidate machines until one shows the matching drift.

hypertor also sends no `Server` and no `X-Powered-By`, both of which OnionScan found useful for
matching a service to the host behind it.

The counter-argument is hypertor's own — behaving differently is itself a fingerprint, and nginx and
Apache both send `Date`. It is weighed differently here: at the Tor protocol layer there is one
normal behaviour to blend into, which is why a service answers only `BEGIN`; at the HTTP layer onion
services are already wildly heterogeneous, so the blending buys little while the clock oracle costs
a lot. `date_header(true)` restores it.

`header_timeout` matters more here than on the clearnet. A client that opens a stream and then says
nothing holds a connection slot indefinitely, and against an onion service the attacker's address is
hidden by the same network that hides yours. Setting it to zero disables the deadline and re-opens
the hole.

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

```bash
cargo add hypertor --features server,pow
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
        // `stream` is an OnionStream: AsyncRead + AsyncWrite.
    });
}
```

Only streams asking for port 1234 reach the loop; everything else is rejected before it gets there.

## Shutdown

```rust
serving.shutdown().await?;   // stop accepting, let in-flight requests finish
serving.abort();             // drop connections mid-response
serving.is_finished();       // has it stopped? — for supervising it from your own loop
```

`shutdown` waits for open connections to close, or ten seconds, whichever comes first — a client is
not allowed to keep the service alive indefinitely by never finishing its request. Dropping an
`OnionService` retracts it and stops publishing its descriptor.

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

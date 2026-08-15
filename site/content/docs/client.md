+++
title = "Client"
description = "TorClient: requests, responses, streaming, circuit isolation, redirects, retries and connection pooling."
weight = 3
+++

`TorClient` sends HTTP requests over Tor. The API deliberately mirrors `reqwest`, so most of what
you already know transfers.

## Creating a client

```rust
use hypertor::TorClient;

// Defaults
let client = TorClient::new().await?;
```

```rust
use std::time::Duration;
use hypertor::{IsolationLevel, RedirectPolicy, TorClient};

let client = TorClient::builder()
    .timeout(Duration::from_secs(90))
    .connect_timeout(Duration::from_secs(30))
    .isolation(IsolationLevel::PerHost)
    .redirect(RedirectPolicy::limited(5))
    .max_retries(2)
    .user_agent("my-app/1.0")
    .build()
    .await?;
```

Bootstrapping is expensive. **Create one client and reuse it** — cloning is cheap and shares the
underlying Tor instance, circuits and connection pool.

### Starting without waiting

Bootstrapping takes tens of seconds on a cold cache, which is a long time to block a program's
startup — especially one that might never make a request.

```rust
let client = TorClient::builder().lazy_bootstrap(true).build().await?;
// returns immediately; the first request that needs the network bootstraps

client.bootstrap().await?;   // ...or pay the cost at a moment you choose
```

The cost is moved rather than removed, and so is the failure: without an explicit `bootstrap()`
call, a bootstrap failure surfaces on the first request instead of at construction.

### Defaults

| Setting | Default | Notes |
|---|---|---|
| `timeout` | 60 s | Covers the whole request, including redirects |
| `connect_timeout` | 30 s | One circuit build plus TLS handshake |
| `isolation` | `PerHost` | Different destinations never share a circuit |
| `redirect` | follow up to 10 | Credentials stripped across origins |
| `max_retries` | 2 | Idempotent methods with replayable bodies only |
| `max_response_size` | 16 MiB | Enforced against the *decoded* body, while streaming |
| `compression` | on | gzip, deflate, br, zstd — in Firefox's order |
| TLS provider | aws-lc-rs | post-quantum `X25519MLKEM768` first |
| TLS resumption | on, per isolation group | never shared across circuits |
| `user_agent` | Tor Browser's | Blends into the largest anonymity set |

`connect_timeout` is nested inside `timeout`: whichever elapses first ends the request, so a
connect budget larger than the request budget can never fire. The defaults are chosen so that
cannot happen by accident.

## Making requests

```rust
// Methods
client.get(url)?;
client.post(url)?;
client.put(url)?;
client.patch(url)?;
client.delete(url)?;
client.head(url)?;
client.options(url)?;
client.request(Method::from_bytes(b"PROPFIND")?, url)?;

// Bodies
client.post(url)?.json(&value).send().await?;
client.post(url)?.form([("key", "value")]).send().await?;
client.post(url)?.text("plain text").send().await?;
client.post(url)?.body(bytes).send().await?;

// Query parameters, percent-encoded for you
client.get(url)?.query([("q", "rust & tor")]).send().await?;

// Headers and auth
client.get(url)?
    .header("X-Custom", "value")        // replaces any existing value
    .append_header("Accept", "text/*")  // keeps them both, for repeatable headers
    .bearer_auth(token)
    .send()
    .await?;
```

Credential headers set by `basic_auth` and `bearer_auth` are marked sensitive, which keeps them out
of HTTP/2's shared header-compression table where they would otherwise be a cross-request oracle.

## Responses

```rust
let response = client.get(url)?.send().await?;

response.status();          // StatusCode
response.version();         // Version
response.is_success();      // 2xx?
response.headers();         // &HeaderMap
response.header("etag");    // Option<&str>

response.text()?;           // String (UTF-8 only)
response.bytes();           // &Bytes
let user: User = response.json()?;

// Turn a non-2xx status into an error
let response = client.get(url)?.send().await?.error_for_status()?;
```

`error_for_status` produces `Error::Status`, which carries the code — `Error::status()` gives it
back, so `404` and `503` can be handled differently without matching on a string.

`text()` decodes UTF-8 only. A response declaring another charset produces an error naming that
charset, rather than silently returning mojibake — use `bytes()` and transcode it yourself.

A `HEAD` response is handled as the metadata it is: RFC 9110 says its `Content-Length` and
`Content-Encoding` describe the body a `GET` *would* have returned, so hypertor does not test them
against `max_response_size` or feed the absent body to a decompressor. `client.head(url)` therefore
works on a resource far larger than the size limit, which is most of the point of asking.

## Streaming

`send()` reads the whole body into memory, bounded by `max_response_size`. For anything larger,
`send_streaming()` returns as soon as the response headers arrive.

```rust
let mut response = client
    .get("http://files.onion/big.iso")?
    .send_streaming()
    .await?
    .error_for_status()?;

println!("{} {:?}", response.status(), response.header("content-length"));

while let Some(chunk) = response.chunk().await? {
    file.write_all(&chunk).await?;
}
```

The body is also available as a `Stream`:

```rust
use futures::StreamExt;

let mut stream = client.get(url)?.send_streaming().await?.bytes_stream();
while let Some(chunk) = stream.next().await {
    let chunk = chunk?;
}
```

`buffered()` reads the rest into an ordinary `Response`, if you change your mind partway.

**The size limit still applies.** A streamed body is bounded by `max_response_size` exactly as a
buffered one is; the streaming API is not a way around it. Raise the limit if you mean to accept
something large.

**Timeouts differ.** `send()`'s deadline covers everything including the body. `send_streaming()`'s
covers everything up to and including the headers — once you hold the value, no deadline applies,
because a download that takes an hour is a legitimate thing to want. Wrap your own read loop in
`tokio::time::timeout` if you need one.

## Request bodies

```rust
use hypertor::Body;

Body::empty();
Body::bytes("in memory");
Body::from_file("./upload.bin").await?;          // streamed, Content-Length known
Body::from_stream(some_stream);                   // streamed, chunked
Body::sized_stream(some_stream, len);             // streamed, Content-Length set
```

An in-memory body is **replayable**: hypertor can send it again on a new connection. A streamed body
cannot be rewound, so a request carrying one is never retried automatically, and a `307`/`308`
redirect that would have to resend it fails with an explanatory error rather than sending a
truncated request. `Body::is_replayable()` tells you which you have.

## Circuit isolation

Two requests on the same circuit exit Tor from the same relay at the same moment, and are linkable
by anyone watching it. Isolation is how you decide which of your activities may be linked.

```rust
use hypertor::IsolationToken;

let alice = IsolationToken::new();
let bob = IsolationToken::new();

// Same token → same circuit.
client.get("http://forum.onion/inbox")?.isolation(alice).send().await?;
client.get("http://forum.onion/profile")?.isolation(alice).send().await?;

// Different token → guaranteed different circuit.
client.get("http://shop.onion/cart")?.isolation(bob).send().await?;
```

| Level | Behaviour | Cost |
|---|---|---|
| `None` | hypertor adds no isolation of its own | Cheapest |
| `PerHost` *(default)* | One circuit family per destination host | Reuses warm circuits |
| `PerRequest` | A fresh circuit for every request | Seconds per request |
| `Fixed(token)` | One explicit token for everything | — |

`PerRequest` makes connection reuse impossible by construction, so every request pays the full
circuit build. Use it when unlinkability matters more than latency.

Each isolation group gets its own connection pool **and its own TLS session-resumption store**, so
an isolated request can never be handed a connection belonging to another group — nor present a
session ticket that another group was issued. Sharing the resumption store would let a server link
exactly the requests the circuits kept apart; see
[Security](@/docs/security.md#session-resumption-cannot-cross-an-isolation-boundary).

`PerRequest` disables resumption entirely, since a connection used once can never benefit from it.
`TorWebSocket` honours the same setting.

## Redirects

A redirect is the server choosing your next request, which needs more care over Tor than elsewhere.

```rust
use hypertor::RedirectPolicy;

RedirectPolicy::default();              // follow up to 10
RedirectPolicy::limited(3);
RedirectPolicy::none();                 // return the 3xx as-is
RedirectPolicy::default().allow_onion_to_clearnet(true);
```

By default hypertor:

- **strips `Authorization`, `Proxy-Authorization` and `Cookie`** whenever the origin changes, so a
  redirect cannot replay your credentials to a host you never chose to trust;
- **refuses a redirect from a `.onion` out to clearnet**, which would move your traffic from an
  end-to-end encrypted onion connection onto a path through an untrusted exit relay;
- **refuses a `Location:` naming any scheme other than `http` or `https`** — `mailto:`,
  `javascript:` and `file:` are not things Tor carries, and refusing here produces an error that
  says so rather than a confusing URL-parsing failure from deep in the connector;
- rewrites `POST` to `GET` on 301, 302 and 303, and preserves the method on 307 and 308.

Moving *into* the Tor network — clearnet redirecting to `.onion` — is always allowed, since it is an
upgrade rather than a downgrade.

## Retries

A failed request is retried on a **new connection**, which is what recovers from the common case: a
pooled connection the peer had already closed, or a stream that could not be opened.

**A retry is not automatically a new circuit.** Whether the second attempt travels a different path
is decided by the isolation level, not by the retry. Only `PerRequest` resolves a fresh isolation
token per attempt and therefore guarantees a genuinely different circuit; under the default
`PerHost` the retry stays in the host's isolation group, so arti may route it over the circuit that
just failed. That is the right trade for the common case — rebuilding a circuit costs seconds, and
most retryable failures are not the path's fault — but if you are retrying specifically to route
*around* a bad relay, use `IsolationLevel::PerRequest`.

A request is retried only when all three hold:

- the method is idempotent (`GET`, `HEAD`, `OPTIONS`, `TRACE`, `PUT`, `DELETE`) — a `POST` is never
  retried automatically, because that could charge a card twice;
- the body is replayable, i.e. in memory rather than streamed;
- the failure is transient (`Error::is_retryable`).

```rust
let client = TorClient::builder().max_retries(3).build().await?;
```

## Connection pooling

The Tor connector plugs into hyper's pooling client, so a warm circuit is reused across requests.

```rust
client.get(url)?.send().await?;  // builds a circuit — seconds
client.get(url)?.send().await?;  // reuses it — hundreds of milliseconds
```

```rust
TorClient::builder()
    .pool_max_idle_per_host(8)
    .pool_idle_timeout(Duration::from_secs(300))
    .build()
    .await?;
```

A pooled connection is a live Tor circuit: cheap to hold, expensive to rebuild. The defaults are
generous for that reason.

## HTTP/2

Negotiated by ALPN on `https://` targets and used automatically when the server supports it, which
lets several concurrent requests share one circuit. Turn it off with `.http2(false)`.

HTTP/2 is not attempted on plain `http://`, including `.onion` URLs, because that would require
prior knowledge that the server speaks it. (An `OnionApp` you host *does* serve h2c — see
[Onion services](@/docs/server.md) — but a client cannot assume that of an arbitrary
service.)

## Errors

```rust
use hypertor::Error;

match client.get(url)?.send().await {
    Ok(response) => { /* ... */ }
    Err(e) if e.is_timeout() => { /* deadline passed */ }
    Err(e) if e.is_tor() => { /* bootstrap or circuit failure */ }
    Err(e) if e.status() == Some(StatusCode::NOT_FOUND) => { /* from error_for_status */ }
    Err(e) if e.is_retryable() => { /* transient */ }
    Err(e) => eprintln!("{e}"),
}
```

**Hostnames are scrubbed from error messages.** Errors end up in logs and bug reports, and
`connection to secretforum.onion:80 failed` is a leak. Use `Error::host()` when you need the value
programmatically; it never redacts.

## Cookies

There is no cookie jar, deliberately. A jar shared across requests would silently relink activities
that [circuit isolation](#circuit-isolation) exists to keep apart — the isolation would still be
real at the network layer while the application layer gave the correlation away for free.

Set `Cookie` yourself when you want one, and you decide its scope:

```rust
client.get(url)?.header("cookie", "session=abc").send().await?;
```

hypertor strips `Cookie` on any cross-origin redirect, as it does the other credential headers.

## Resolving names

```rust
let addrs  = client.resolve("example.com").await?;
let names = client.resolve_ptr("93.184.216.34".parse()?).await?;
```

The lookup is performed by an exit relay, never by your machine. You rarely need this: the client
resolves names over Tor automatically when connecting.

## Onion addresses

`.onion` URLs work like any other, and are checked before a circuit is built:

```rust
client.get("http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/")?;
```

A name that is not 56 characters of base32 cannot resolve, so hypertor refuses it at the call site
rather than spending seconds on a circuit to discover that. Version 2 addresses — 16 characters,
retired from the network in 2021 — are named explicitly in the error, because someone holding one
has stale information rather than a broken configuration.

### Reaching a restricted service

An onion service in *restricted discovery* mode encrypts its descriptor so that only clients holding
an authorised key can find it. Nothing extra is needed in your code: arti keeps a keystore under the
client's state directory and consults it automatically whenever it meets an onion address.

Install the key the service operator authorised for you, pointing `arti` at the same state directory
your client uses:

```bash
arti hsc get-key --onion-name <address>.onion
```

Then connect as usual. Hosting such a service is covered in
[Onion services](@/docs/server.md#restricted-discovery); hypertor deliberately does
not generate these keypairs, because the secret half must never exist on the server.

## Sharing one Tor instance

```rust
use std::sync::Arc;
use arti_client::config::TorClientConfig;
use hypertor::{Config, OnionService, TorClient};

// arti's `create_bootstrapped` already hands back an `Arc`.
let tor = arti_client::TorClient::create_bootstrapped(TorClientConfig::default()).await?;

let client = TorClient::from_arti(Arc::clone(&tor), Config::default())?;
let service = OnionService::builder()
    .nickname("shared")?
    .on_client(tor)
    .launch()
    .await?;
```

Both take an `Arc`, so the instance really is shared: one directory cache and one guard set, which
is both faster and better for anonymity than running two independent instances.

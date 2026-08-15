---
title: "Client"
permalink: /docs/client/
toc: true
---

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
    .timeout(Duration::from_secs(60))
    .connect_timeout(Duration::from_secs(90))
    .isolation(IsolationLevel::PerHost)
    .redirect(RedirectPolicy::limited(5))
    .max_retries(2)
    .user_agent("my-app/1.0")
    .build()
    .await?;
```

Bootstrapping is expensive. **Create one client and reuse it** — cloning is cheap and shares the
underlying Tor instance, circuits and connection pool.

### Defaults

| Setting | Default | Notes |
|---|---|---|
| `timeout` | 30 s | Covers the whole request, including redirects |
| `connect_timeout` | 60 s | One circuit build plus TLS handshake |
| `isolation` | `PerHost` | Different destinations never share a circuit |
| `redirect` | follow up to 10 | Credentials stripped across origins |
| `max_retries` | 2 | Idempotent methods only |
| `max_response_size` | 16 MiB | Enforced while streaming |
| `compression` | on | gzip, brotli, zstd, deflate |
| `user_agent` | Tor Browser's | Blends into the largest anonymity set |

## Making requests

```rust
// Methods
client.get(url)?;
client.post(url)?;
client.put(url)?;
client.patch(url)?;
client.delete(url)?;
client.head(url)?;
client.request(Method::OPTIONS, url)?;

// Bodies
client.post(url)?.json(&value).send().await?;
client.post(url)?.form([("key", "value")]).send().await?;
client.post(url)?.text("plain text").send().await?;
client.post(url)?.body(bytes).send().await?;

// Query parameters, percent-encoded for you
client.get(url)?.query([("q", "rust & tor")]).send().await?;

// Headers and auth
client.get(url)?
    .header("X-Custom", "value")
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
response.is_success();      // 2xx?
response.headers();         // &HeaderMap
response.header("etag");    // Option<&str>

response.text()?;           // String (UTF-8 only)
response.bytes();           // &Bytes
let user: User = response.json()?;

// Turn a non-2xx status into an error
let response = client.get(url)?.send().await?.error_for_status()?;
```

`text()` decodes UTF-8 only. A response declaring another charset produces an error naming that
charset, rather than silently returning mojibake — use `bytes()` and transcode it yourself.

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

Each isolation group gets its own connection pool, so an isolated request can never be handed a
connection belonging to another group.

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
- rewrites `POST` to `GET` on 301, 302 and 303, and preserves the method on 307 and 308.

Moving *into* the Tor network — clearnet redirecting to `.onion` — is always allowed, since it is an
upgrade rather than a downgrade.

## Retries

Failed requests are retried on a **fresh circuit**, which is the entire reason retrying is worth
doing: Tor picks a different path each time, so a bad relay is routed around rather than hit again.

Only idempotent methods are retried (`GET`, `HEAD`, `OPTIONS`, `TRACE`, `PUT`, `DELETE`) and only
for transient failures. A `POST` is never retried automatically — that could charge a card twice.

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
    .build()
    .await?;
```

## HTTP/2

Negotiated by ALPN on `https://` targets and used automatically when the server supports it, which
lets several concurrent requests share one circuit. Turn it off with `.http2(false)`.

HTTP/2 is not attempted on plain `http://`, including `.onion` URLs, because that would require
prior knowledge that the server speaks it.

## Errors

```rust
use hypertor::Error;

match client.get(url)?.send().await {
    Ok(response) => { /* ... */ }
    Err(e) if e.is_timeout() => { /* deadline passed */ }
    Err(e) if e.is_tor() => { /* bootstrap or circuit failure */ }
    Err(e) if e.is_retryable() => { /* transient */ }
    Err(e) => eprintln!("{e}"),
}
```

**Hostnames are scrubbed from error messages.** Errors end up in logs and bug reports, and
`connection to secretforum.onion:80 failed` is a leak. Use `Error::host()` when you need the value
programmatically; it never redacts.

## Resolving names

```rust
let addrs = client.resolve("example.com").await?;
```

The lookup is performed by an exit relay, never by your machine. You rarely need this: the client
resolves names over Tor automatically when connecting.

## Sharing one Tor instance

```rust
let tor = arti_client::TorClient::create_bootstrapped(config).await?;

let client = TorClient::from_arti(tor.clone(), Config::default())?;
let service = OnionService::builder().on_client(tor).launch().await?;
```

Sharing one arti client means one directory cache and one guard set, which is both faster and better
for anonymity than running two independent instances.

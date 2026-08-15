+++
title = "Python"
description = "The hypertor Python API: sync and async clients, circuit isolation, onion services and typing."
weight = 6
+++

```bash
pip install hypertor
```

Requires Python 3.10 or later. Wheels ship for Linux, macOS and Windows; no Rust toolchain needed.

## Client

```python
import hypertor

with hypertor.Client() as client:
    response = client.get("https://check.torproject.org/api/ip")
    response.raise_for_status()
    print(response.json())
```

Constructing a `Client` bootstraps Tor, which takes tens of seconds on a cold cache. **Create one
and reuse it** rather than one per request.

```python
client = hypertor.Client(
    timeout=60.0,                     # seconds, covers the whole request
    connect_timeout=30.0,             # one circuit build plus TLS handshake
    max_idle_per_host=4,              # pooled connections kept warm
    max_response_size=16 * 1024**2,   # applies to the decoded body
    isolation="per_host",             # "none" | "per_host" | "per_request"
    user_agent=None,                  # defaults to Tor Browser's
    verify=True,                      # TLS certificate verification
    max_redirects=10,
    max_retries=2,
)
```

### Requests

Every HTTP method is available, on both the sync and the async client:

```python
client.get(url, params={"q": "rust"}, headers={"X-Custom": "value"}, timeout=30.0)
client.head(url)
client.options(url)

client.post(url, json={"name": "Alice"})       # serialised with json.dumps
client.post(url, data={"field": "value"})      # form-urlencoded
client.post(url, body=b"raw bytes")

client.put(url, json={...})
client.patch(url, json={...})
client.delete(url)

client.request("PROPFIND", url, headers={"Depth": "1"})
```

`json=` is serialised by Python's own `json` module, so custom encoders and anything `json.dumps`
handles keep working.

### Responses

```python
response.status_code    # int
response.reason         # str, e.g. "Not Found"
response.ok             # bool, 2xx
response.headers        # dict[str, str], lowercased
response.text           # str
response.content        # bytes
response.http_version   # str, e.g. "HTTP/2.0"
response.json()         # parsed with Python's json module
response.raise_for_status()

len(response)           # body length in bytes
bool(response)          # the *status*, not the body length
```

`bool(response)` follows the status deliberately. Basing it on the body length would make a `204`,
or any successful `HEAD`, falsy — the opposite of what `if response:` reads as.

`raise_for_status()` raises `hypertor.StatusError`, a subclass of `HypertorError`.

## Circuit isolation

Two requests sharing a circuit leave Tor from the same exit relay at the same moment, and are
linkable by anyone watching it.

```python
# Client-wide policy.
client = hypertor.Client(isolation="per_request")
```

```python
# Per-request, for finer control: two personas that must never be linked.
alice = hypertor.IsolationToken()
bob = hypertor.IsolationToken()

client.get("http://forum.onion/inbox", isolation=alice)
client.get("http://forum.onion/profile", isolation=alice)   # same circuit as above
client.get("http://shop.onion/cart", isolation=bob)         # never the same circuit
```

A token is meaningful only within one process. Keep it alive for as long as the activities it groups
should stay linked to each other, and no longer.

## Async

```python
import asyncio
import hypertor

async def main():
    async with hypertor.AsyncClient() as client:
        # Concurrent, over separate circuits.
        responses = await asyncio.gather(
            client.get("http://a.onion/"),
            client.get("http://b.onion/"),
        )
        for response in responses:
            print(response.status_code)

asyncio.run(main())
```

`AsyncClient` exposes exactly the same methods and keyword arguments as `Client`; both surfaces are
generated from one definition, so they cannot drift apart.

## The GIL

Every network call releases the GIL for its duration, so a request that takes 30 seconds does not
freeze the rest of your program. Threads and asyncio tasks keep running normally.

## Onion services

The **nickname is the identity**: the `.onion` address is derived from a key filed under it, and
arti's default state directory is persistent. Relaunching with the same nickname republishes the
*same address*, with or without `state_dir` — that argument chooses *where* the key lives, not
whether it is kept. Change the nickname, or point `state_dir` at a fresh directory, for a different
address.

```python
import hypertor

app = hypertor.OnionApp(
    "my-service",                 # <- the identity
    port=80,                      # the only virtual port served
    ports=None,                   # ...or several: [80, 443]
    state_dir="./onion-state",    # where the key lives
    static_dir=None,              # optionally serve files for unrouted GETs
    max_body_size=2 * 1024**2,
    max_connections=256,
    header_timeout=30.0,          # slowloris defence, in seconds
)


@app.get("/")
def home(request):
    return "<h1>hello from .onion</h1>"


@app.get("/health")
def health(request):
    return {"status": "ok"}          # dicts and lists become JSON


@app.get("/users/{user_id}")
def get_user(request):
    return {"id": request.params["user_id"]}


@app.post("/echo")
def echo(request):
    return {"received": request.json()}


@app.route("PROPFIND", "/dav")
def propfind(request):
    return b"<xml/>"


if __name__ == "__main__":
    app.run()             # prints the .onion address, then serves
    # app.run(quiet=True) # ...or does not print it
```

`Ctrl-C` raises `KeyboardInterrupt` and shuts the service down cleanly, letting in-flight requests
finish.

Handlers may be `def` or `async def`, and run on a worker thread — one slow handler does not stall
the connections being served alongside it.

### What a handler may return

| Returned | Response |
|---|---|
| `str` | `200`, `text/plain` |
| `dict`, `list` | `200`, `application/json` |
| `bytes` | `200`, `application/octet-stream` |
| `None` | `204 No Content` |
| `(body, status)` | that status, `body` converted as above |
| `(body, status, headers)` | ...plus a `dict` of headers |
| anything else | `str(value)` as `text/plain` |

The tuple forms are Flask's convention:

```python
@app.get("/items/{item_id}")
def get_item(request):
    item = lookup(request.params["item_id"])
    if item is None:
        return {"error": "no such item"}, 404
    return item


@app.post("/items")
def create(request):
    item = store(request.json())
    return item, 201, {"location": f"/items/{item['id']}"}
```

A handler that raises produces a `500`; the exception is logged server-side and never sent to the
client.

### Request object

```python
request.method     # str
request.path       # str
request.query      # dict[str, str]
request.params     # dict[str, str], from the route pattern
request.headers    # dict[str, str]
request.body       # bytes
request.text()     # str
request.json()     # parsed JSON
```

## Errors

```python
import hypertor

try:
    response = client.get("http://unreachable.onion/")
    response.raise_for_status()
except hypertor.TimeoutError:
    ...
except hypertor.ConnectionError:       # bootstrap or connect failure
    ...
except hypertor.TlsError:
    ...
except hypertor.StatusError:           # non-2xx from raise_for_status
    ...
except hypertor.HypertorError:         # catches all of the above
    ...
```

Configuration mistakes — an unknown isolation level, a malformed HTTP method — raise `ValueError`
before any network work happens, so a typo fails immediately rather than after a minute of
bootstrapping.

Note that `hypertor.ConnectionError` and `hypertor.TimeoutError` shadow the builtins of the same
name inside a `from hypertor import *`; prefer the qualified form.

## Not exposed to Python

The SOCKS5 proxy and `TorWebSocket` are Rust-only for now. Run the proxy from a small Rust binary —
or `cargo run --example socks_proxy` — and point any Python SOCKS client at it with `socks5h://`.

Streaming responses (`send_streaming` in Rust) are also Rust-only: `response.content` is always the
fully-read body, bounded by `max_response_size`.

## Type hints

The package ships `py.typed` and complete stubs, so mypy and pyright check your usage:

```python
from hypertor import Client, Response

def fetch(client: Client, url: str) -> Response:
    return client.get(url)
```

## Building from source

```bash
git clone https://github.com/hupe1980/hypertor
cd hypertor/bindings/python

uv sync --all-extras
maturin develop

uv run pytest                # offline tests
uv run pytest -m network     # the ones needing a live Tor connection
```

Everything for the bindings lives in `bindings/python` — the Rust crate, the Python package, its
tests and examples. It is a separate crate that is not published to crates.io, so the Rust library
carries no pyo3 dependency.

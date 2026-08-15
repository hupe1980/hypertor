---
title: "Python"
permalink: /docs/python/
toc: true
---

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
    timeout=60.0,            # seconds, covers the whole request
    max_idle_per_host=4,     # pooled connections kept warm
    isolation="per_host",    # "none" | "per_host" | "per_request"
    user_agent=None,         # defaults to Tor Browser's
    verify=True,             # TLS certificate verification
)
```

### Requests

```python
client.get(url, params={"q": "rust"}, headers={"X-Custom": "value"}, timeout=30.0)

client.post(url, json={"name": "Alice"})       # serialised with json.dumps
client.post(url, data={"field": "value"})      # form-urlencoded
client.post(url, body=b"raw bytes")

client.put(url, json={...})
client.delete(url)
```

`json=` is serialised by Python's own `json` module, so custom encoders and anything `json.dumps`
handles keep working.

### Responses

```python
response.status_code    # int
response.ok             # bool, 2xx
response.headers        # dict[str, str], lowercased
response.text           # str
response.content        # bytes
response.json()         # parsed with Python's json module
response.raise_for_status()
len(response)           # body length in bytes
```

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

## The GIL

Every network call releases the GIL for its duration, so a request that takes 30 seconds does not
freeze the rest of your program. Threads and asyncio tasks keep running normally.

## Onion services

```python
import hypertor

# state_dir keeps the .onion address stable across restarts.
app = hypertor.OnionApp("my-service", state_dir="./onion-state")


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


if __name__ == "__main__":
    app.run()   # prints the .onion address, then serves
```

Handlers may be `def` or `async def`. Return values are converted as follows:

| Returned | Response |
|---|---|
| `str` | `text/plain` |
| `dict`, `list` | `application/json` |
| `bytes` | raw body |
| anything else | `str(value)` as `text/plain` |

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
except hypertor.TimeoutError:
    ...
except hypertor.ConnectionError:       # bootstrap or connect failure
    ...
except hypertor.TlsError:
    ...
except hypertor.HypertorError:         # catches all of the above
    ...
```

Note that `hypertor.ConnectionError` and `hypertor.TimeoutError` shadow the builtins of the same
name inside a `from hypertor import *`; prefer the qualified form.

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
cd hypertor
uv sync --all-extras
maturin develop --features python

pytest                # offline tests
pytest -m network     # includes tests needing a live Tor connection
```

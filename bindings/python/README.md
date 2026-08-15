# 🧅 hypertor

**Tor for Python.** Make HTTP requests over the Tor network, and host onion services.

No Tor daemon required — hypertor speaks the Tor protocol itself, through
[arti](https://gitlab.torproject.org/tpo/core/arti), the Tor Project's Rust implementation.

```bash
pip install hypertor
```

```python
import hypertor

with hypertor.Client() as client:
    response = client.get("https://check.torproject.org/api/ip")
    print(response.json())
```

## Requests

```python
client = hypertor.Client(
    timeout=60.0,                     # seconds, covers the whole request
    isolation="per_host",             # "none" | "per_host" | "per_request"
    max_response_size=16 * 1024**2,   # applies to the decoded body
    verify=True,
)

client.get(url, params={"q": "rust"}, headers={"X-Custom": "value"})
client.post(url, json={"name": "Alice"})
client.post(url, data={"field": "value"})       # form-urlencoded
client.request("PROPFIND", url)

response.status_code, response.ok, response.text, response.content
response.json()
response.raise_for_status()
```

Constructing a `Client` bootstraps Tor, which takes tens of seconds on a cold cache. **Create one
and reuse it.** Every network call releases the GIL, so a slow request never freezes the rest of
your program.

`AsyncClient` exposes exactly the same methods, awaitable:

```python
async with hypertor.AsyncClient() as client:
    responses = await asyncio.gather(
        client.get("http://a.onion/"),
        client.get("http://b.onion/"),
    )
```

## Circuit isolation

Two requests sharing a Tor circuit leave the network from the same exit relay at the same moment,
and are linkable by anyone watching it. Isolation decides which of your activities may be linked.

```python
alice = hypertor.IsolationToken()
bob = hypertor.IsolationToken()

client.get("http://forum.onion/inbox", isolation=alice)
client.get("http://forum.onion/profile", isolation=alice)   # same circuit
client.get("http://shop.onion/cart", isolation=bob)         # never the same circuit
```

## Hosting an onion service

```python
app = hypertor.OnionApp("my-service", state_dir="./onion-state")

@app.get("/")
def home(request):
    return "<h1>hello from .onion</h1>"

@app.get("/users/{user_id}")
def get_user(request):
    user = lookup(request.params["user_id"])
    if user is None:
        return {"error": "no such user"}, 404          # Flask-style (body, status)
    return user, 200, {"cache-control": "no-store"}

app.run()   # prints the .onion address, then serves until Ctrl-C
```

The **nickname is the identity**: the `.onion` address is derived from a key filed under it, so
relaunching with the same nickname republishes the same address.

## Errors

```python
except hypertor.TimeoutError: ...
except hypertor.ConnectionError: ...      # bootstrap or connect failure
except hypertor.TlsError: ...
except hypertor.StatusError: ...          # non-2xx from raise_for_status
except hypertor.HypertorError: ...        # catches all of the above
```

Hostnames are scrubbed from error messages, because error messages end up in logs.

## Type hints

The package ships `py.typed` and complete stubs, so mypy and pyright check your usage.

## Documentation

Full docs: **<https://hupe1980.github.io/hypertor/docs/python/>**

The Rust library lives at [crates.io/crates/hypertor](https://crates.io/crates/hypertor) and carries
no Python dependency; these bindings are built from `bindings/python` in the
[repository](https://github.com/hupe1980/hypertor).

## A word of caution

hypertor is not an anonymity system in its own right, and no library can be. Tor protects the
network path; it cannot protect you from an application that logs in with your real identity, from
timing patterns in your own traffic, or from a compromised machine. Read the
[Tor Project's guidance](https://support.torproject.org/) before relying on this for anything that
matters. Not affiliated with, endorsed by, or sponsored by the Tor Project.

## License

MIT.

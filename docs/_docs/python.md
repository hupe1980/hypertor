---
title: "Python Bindings"
permalink: /docs/python/
excerpt: "Full Python API via PyO3"
---

HyperTor provides native Python bindings via PyO3/Maturin, giving you the full power of the Rust library with Pythonic ergonomics.

## Installation

```bash
pip install hypertor
```

Or build from source:

```bash
uv venv && source .venv/bin/activate
uv pip install maturin
maturin develop
```

## AsyncClient

The main HTTP client for making requests over Tor.

### Basic Usage

```python
import asyncio
from hypertor import AsyncClient

async def main():
    async with AsyncClient(timeout=60) as client:
        # GET request
        resp = await client.get("https://check.torproject.org/api/ip")
        print(f"Status: {resp.status_code}")
        print(f"Body: {resp.text()}")

asyncio.run(main())
```

### Constructor

```python
AsyncClient(timeout=30)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `timeout` | `int` | 30 | Request timeout in seconds |

### HTTP Methods

```python
async with AsyncClient(timeout=60) as client:
    # GET
    resp = await client.get("https://example.com")
    
    # POST with JSON (note: json is a string)
    resp = await client.post(
        "https://httpbin.org/post",
        json='{"key": "value"}'
    )
    
    # POST with form data
    resp = await client.post(
        "https://httpbin.org/post",
        data="field=value&other=data"
    )
```

### Response Object

```python
resp = await client.get("https://example.com")

# Status code (int)
resp.status_code  # 200

# Body as text (method)
resp.text()  # "<!DOCTYPE html>..."

# Body as JSON (method)
resp.json()  # {"key": "value"}

# Response headers (dict)
resp.headers  # {"content-type": "application/json", ...}
```

## Error Handling

```python
from hypertor import (
    AsyncClient,
    HypertorError,     # Base exception for all errors
    TorBootstrapError, # Failed to connect to Tor network
    ConnectionError,   # Connection failed
    TimeoutError,      # Request timed out
)

async def safe_request():
    try:
        async with AsyncClient(timeout=60) as client:
            resp = await client.get("http://example.onion")
            return resp.json()
    except TimeoutError:
        print("Request timed out - Tor can be slow")
    except ConnectionError:
        print("Failed to connect")
    except TorBootstrapError:
        print("Could not connect to Tor network")
    except HypertorError as e:
        print(f"General error: {e}")
```

## OnionApp

FastAPI-like framework for hosting .onion services.

### Basic Usage

```python
from hypertor import OnionApp

app = OnionApp()

@app.get("/")
async def home():
    return {"message": "Welcome to my .onion service!"}

@app.get("/api/info")
async def info():
    return {"version": "1.0", "anonymous": True}

@app.post("/api/echo")
async def echo(request):
    body = await request.json()
    return {"echoed": body}

# Run the service
if __name__ == "__main__":
    import asyncio
    asyncio.run(app.run())
```

### Route Decorators

```python
@app.get("/path")      # GET requests
@app.post("/path")     # POST requests
@app.put("/path")      # PUT requests
@app.delete("/path")   # DELETE requests
```

### Request Handling

```python
@app.post("/api/data")
async def handle_data(request):
    # Get JSON body
    body = await request.json()
    
    # Access request info
    print(request.method)  # "POST"
    print(request.path)    # "/api/data"
    
    return {"received": body}
```

### Response Types

```python
@app.get("/text")
async def text_response():
    return "Plain text response"

@app.get("/json")
async def json_response():
    return {"key": "value"}  # Automatically serialized

@app.get("/status")
async def custom_status():
    return {"error": "Not found"}, 404  # Tuple with status code
```

### Middleware

```python
@app.middleware
async def log_requests(request, call_next):
    print(f"→ {request.method} {request.path}")
    response = await call_next(request)
    print(f"← {response.status_code}")
    return response
```

## Sync Client

For non-async code, use the synchronous client:

```python
from hypertor import Client

with Client(timeout=60) as client:
    resp = client.get("https://check.torproject.org/api/ip")
    print(resp.json())
```

## Complete Example: Secure API Client

```python
#!/usr/bin/env python3
"""Production-ready Tor API client with resilience patterns."""

from hypertor import AsyncClient, TimeoutError, HypertorError
import asyncio
import time


class SecureClient:
    """Tor client with retry and circuit breaker."""
    
    def __init__(self, base_url: str, max_retries: int = 3):
        self.base_url = base_url.rstrip("/")
        self.max_retries = max_retries
        self._client = None
        self._failures = 0
        self._circuit_open = False
    
    async def __aenter__(self):
        self._client = await AsyncClient(timeout=60).__aenter__()
        return self
    
    async def __aexit__(self, *args):
        if self._client:
            await self._client.__aexit__(*args)
    
    async def get(self, endpoint: str) -> dict:
        """GET with automatic retry."""
        if self._circuit_open:
            raise HypertorError("Circuit breaker open")
        
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        for attempt in range(self.max_retries):
            try:
                resp = await self._client.get(url)
                self._failures = 0
                return resp.json()
            except TimeoutError:
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                    continue
                self._failures += 1
                if self._failures >= 5:
                    self._circuit_open = True
                raise


async def main():
    async with SecureClient("https://httpbin.org") as client:
        data = await client.get("/ip")
        print(f"IP: {data}")


if __name__ == "__main__":
    asyncio.run(main())
```

## API Reference Summary

### Exports

```python
from hypertor import (
    # Clients
    AsyncClient,       # Async HTTP client
    Client,            # Sync HTTP client
    Response,          # Response object
    
    # Server
    OnionApp,          # FastAPI-like app
    AppConfig,         # App configuration
    Request,           # Incoming request
    AppResponse,       # Outgoing response
    
    # Exceptions
    HypertorError,     # Base exception
    TorBootstrapError, # Bootstrap failed
    ConnectionError,   # Connection error
    TimeoutError,      # Timeout error
)
```

### Type Hints

```python
from hypertor import AsyncClient, Response

async def fetch(url: str) -> dict:
    async with AsyncClient(timeout=60) as client:
        resp: Response = await client.get(url)
        return resp.json()
```

## Notes

1. **Tor Bootstrap**: First connection takes 30-60 seconds as Tor builds circuits
2. **Request Latency**: Expect 5-30 seconds per request due to Tor's onion routing
3. **JSON Strings**: The `json` parameter takes a string, not a dict
4. **Circuit Isolation**: Each `AsyncClient` instance has its own Tor circuits

## See Also

- [Python Examples](https://github.com/hupe1980/hypertor/tree/main/python_examples)
- [Rust TorClient](/docs/client/) - Full API with advanced features
- [Rust OnionApp](/docs/server/) - Full server API

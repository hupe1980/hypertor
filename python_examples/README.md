# HyperTor Python Examples

Examples demonstrating how to use HyperTor's Python bindings for building
anonymous applications over the Tor network.

## Installation

```bash
pip install hypertor
```

Or build from source:

```bash
# In the hypertor repository
uv venv && source .venv/bin/activate
uv pip install maturin
maturin develop
```

## Examples

### 1. Basic Client (`basic_client.py`)

Simple introduction to making HTTP requests over Tor:

```bash
python basic_client.py
```

Features demonstrated:
- Creating an `AsyncClient`
- GET requests over Tor
- POST requests with JSON
- Accessing .onion services
- Error handling with `TimeoutError` and `HypertorError`

### 2. Onion Service (`onion_service.py`)

Create your own anonymous web service with a FastAPI-like API:

```bash
python onion_service.py
```

Features demonstrated:
- `@app.get()` and `@app.post()` decorators
- Request handling with `await request.json()`
- Middleware for logging
- JSON responses
- Running a .onion service

### 3. Secure API Client (`secure_api_client.py`)

Production-ready client with resilience patterns:

```bash
python secure_api_client.py
```

Features demonstrated:
- Circuit breaker pattern
- Automatic retries with exponential backoff
- Rate limiting
- Response caching
- Error handling
- Statistics tracking

### 4. Multiple Identities (`multiple_identities.py`)

Circuit isolation for maintaining separate anonymous identities:

```bash
python multiple_identities.py
```

Features demonstrated:
- Multiple `AsyncClient` instances for identity separation
- IP address verification
- Parallel requests with isolation
- Use cases for privacy compartmentalization

### 6. SOCKS5 Proxy (`socks_proxy.py`)

Run a local SOCKS5 proxy to route any application through Tor:

```bash
python socks_proxy.py
# Then: curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

Features demonstrated:
- `Socks5Proxy` for universal Tor access
- Custom port configuration
- Authentication-based circuit isolation
- Multi-identity proxies on different ports

### 7. WebSocket Patterns (`websocket_client.py`)

Real-time communication patterns over Tor:

```bash
python websocket_client.py
```

Features demonstrated:
- Long polling pattern
- Server-Sent Events (SSE) concepts
- Bidirectional communication patterns
- Live polling demonstration

## API Reference

### AsyncClient (like `httpx`)

```python
from hypertor import AsyncClient, TimeoutError, HypertorError

async with AsyncClient(timeout=60) as client:
    # GET request
    resp = await client.get("https://check.torproject.org/api/ip")
    print(resp.status_code)  # 200
    print(resp.json())       # {"IP": "...", "IsTor": true}
    
    # POST with JSON
    resp = await client.post(
        "https://httpbin.org/post",
        json='{"message": "Hello from Tor!"}'
    )
    
    # Access .onion services
    resp = await client.get("http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion")
```

### OnionApp (like FastAPI)

```python
from hypertor import OnionApp

app = OnionApp()

@app.get("/")
async def home():
    return {"message": "Hello from Tor!"}

@app.post("/api/data")
async def create_data(request):
    body = await request.json()
    return {"received": body}

@app.middleware
async def log_requests(request, call_next):
    print(f"Request: {request.method} {request.path}")
    response = await call_next(request)
    return response

# Run the service
await app.run()
```

### Response Object

```python
resp = await client.get("https://example.com")

resp.status_code   # int: HTTP status code
resp.text()        # str: Response body as text
resp.json()        # dict: Response body parsed as JSON
resp.headers       # dict: Response headers
```

### Exceptions

```python
from hypertor import HypertorError, TimeoutError, ConnectionError, TorBootstrapError

try:
    resp = await client.get("http://example.onion")
except TimeoutError:
    print("Request timed out")
except ConnectionError:
    print("Failed to connect")
except TorBootstrapError:
    print("Failed to connect to Tor network")
except HypertorError as e:
    print(f"General error: {e}")
```

## Running the Examples

The examples connect to the real Tor network. Note:

1. **First run takes time** - Tor needs to bootstrap (~30-60 seconds)
2. **Requests are slow** - Tor adds latency (expect 5-30 seconds per request)
3. **Timeouts are normal** - In restricted networks or dev containers, some requests may timeout

```bash
# Run any example
cd python_examples
python basic_client.py
python onion_service.py
python secure_api_client.py
python multiple_identities.py
python socks_proxy.py
python websocket_client.py
```

## Comparison with Python Libraries

| Feature | hypertor | httpx | aiohttp |
|---------|----------|-------|---------|
| Tor Support | ✅ Built-in | ❌ Manual SOCKS | ❌ Manual SOCKS |
| Onion Hosting | ✅ FastAPI-like | ❌ No | ❌ No |
| Circuit Isolation | ✅ Per-client | ❌ N/A | ❌ N/A |
| Async | ✅ Native | ✅ Native | ✅ Native |

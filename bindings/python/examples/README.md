# Python examples

```bash
pip install hypertor          # or, from a checkout: maturin develop

python examples/client.py
python examples/async_client.py
python examples/isolation.py
python examples/onion_service.py
```

| Example | Shows |
|---|---|
| [`client.py`](client.py) | Requests, JSON, onion addresses |
| [`async_client.py`](async_client.py) | Concurrent requests with asyncio |
| [`isolation.py`](isolation.py) | Circuit isolation, by policy and by explicit token |
| [`onion_service.py`](onion_service.py) | Hosting a service, and returning statuses and headers |

Each script bootstraps Tor on start, which takes tens of seconds the first time.

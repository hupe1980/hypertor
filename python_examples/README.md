# Python examples

```bash
pip install hypertor          # or: maturin develop --features python

python python_examples/client.py
python python_examples/async_client.py
python python_examples/isolation.py
python python_examples/onion_service.py
```

| Example | Shows |
|---|---|
| [`client.py`](client.py) | Requests, JSON, onion addresses |
| [`async_client.py`](async_client.py) | Concurrent requests with asyncio |
| [`isolation.py`](isolation.py) | Keeping activities on separate circuits |
| [`onion_service.py`](onion_service.py) | Hosting a service, with a stable address |

Each script bootstraps Tor on start, which takes tens of seconds the first time.

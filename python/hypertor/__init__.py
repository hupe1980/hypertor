"""hypertor — Tor for Python.

Make HTTP requests over the Tor network, and host onion services.

    import hypertor

    with hypertor.Client() as client:
        response = client.get("https://check.torproject.org/api/ip")
        print(response.json()["IP"])

See https://hupe1980.github.io/hypertor for the full documentation.
"""

from hypertor._hypertor import (
    AsyncClient,
    Client,
    ConnectionError,
    HypertorError,
    OnionApp,
    Request,
    Response,
    TimeoutError,
    TlsError,
    __version__,
)

__all__ = [
    "AsyncClient",
    "Client",
    "ConnectionError",
    "HypertorError",
    "OnionApp",
    "Request",
    "Response",
    "TimeoutError",
    "TlsError",
    "__version__",
]

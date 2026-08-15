"""Type stubs for the hypertor extension module."""

from collections.abc import Callable
from types import TracebackType
from typing import Any, Literal, TypeVar

__version__: str

_Handler = TypeVar("_Handler", bound=Callable[..., Any])

Isolation = Literal["none", "per_host", "per_request"]

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class HypertorError(Exception):
    """Base class for every hypertor error."""

class ConnectionError(HypertorError):
    """Tor could not bootstrap, or the target could not be reached."""

class TimeoutError(HypertorError):
    """An operation exceeded its deadline."""

class TlsError(HypertorError):
    """A TLS handshake or configuration failure."""

class StatusError(HypertorError):
    """``raise_for_status`` was called on a non-2xx response."""

# ---------------------------------------------------------------------------
# Circuit isolation
# ---------------------------------------------------------------------------

class IsolationToken:
    """Identifies one circuit-sharing group.

    Requests carrying equal tokens may share a Tor circuit; requests carrying
    different tokens never do.

        alice = hypertor.IsolationToken()
        client.get(url, isolation=alice)
    """

    def __init__(self) -> None: ...
    def __repr__(self) -> str: ...

# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------

class Response:
    """An HTTP response with its body already read."""

    @property
    def status_code(self) -> int: ...
    @property
    def ok(self) -> bool:
        """Whether the status is 2xx."""

    @property
    def reason(self) -> str:
        """The status code's canonical reason phrase."""

    @property
    def headers(self) -> dict[str, str]:
        """Response headers, lowercased."""

    @property
    def content(self) -> bytes:
        """The raw response body."""

    @property
    def text(self) -> str:
        """The body decoded as UTF-8."""

    @property
    def http_version(self) -> str:
        """The HTTP version the response arrived over, e.g. ``HTTP/2.0``."""

    def json(self) -> Any:
        """The body parsed as JSON."""

    def raise_for_status(self) -> Response:
        """Raise :class:`StatusError` if the status is not 2xx."""

    def __len__(self) -> int: ...
    def __bool__(self) -> bool: ...
    def __repr__(self) -> str: ...

# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------

class Client:
    """A synchronous HTTP client that sends every request over Tor.

    Constructing one bootstraps Tor, which can take tens of seconds on a cold
    cache. Reuse a single client rather than creating one per request.
    """

    def __init__(
        self,
        timeout: float = 60.0,
        connect_timeout: float = 30.0,
        max_idle_per_host: int = 4,
        max_response_size: int = 16 * 1024 * 1024,
        isolation: Isolation = "per_host",
        user_agent: str | None = None,
        verify: bool = True,
        max_redirects: int = 10,
        max_retries: int = 2,
    ) -> None: ...
    def get(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        isolation: IsolationToken | None = None,
    ) -> Response: ...
    def head(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        isolation: IsolationToken | None = None,
    ) -> Response: ...
    def options(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        isolation: IsolationToken | None = None,
    ) -> Response: ...
    def post(
        self,
        url: str,
        *,
        body: bytes | None = None,
        json: Any | None = None,
        data: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        isolation: IsolationToken | None = None,
    ) -> Response: ...
    def put(
        self,
        url: str,
        *,
        body: bytes | None = None,
        json: Any | None = None,
        data: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        isolation: IsolationToken | None = None,
    ) -> Response: ...
    def patch(
        self,
        url: str,
        *,
        body: bytes | None = None,
        json: Any | None = None,
        data: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        isolation: IsolationToken | None = None,
    ) -> Response: ...
    def delete(
        self,
        url: str,
        *,
        body: bytes | None = None,
        json: Any | None = None,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        isolation: IsolationToken | None = None,
    ) -> Response: ...
    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        json: Any | None = None,
        data: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        isolation: IsolationToken | None = None,
    ) -> Response: ...
    def resolve(self, hostname: str) -> list[str]:
        """Resolve a hostname through Tor, never locally."""

    def __enter__(self) -> Client: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None = None,
        exc_val: BaseException | None = None,
        exc_tb: TracebackType | None = None,
    ) -> bool: ...

class AsyncClient:
    """An asyncio-compatible HTTP client that sends every request over Tor."""

    def __init__(
        self,
        timeout: float = 60.0,
        connect_timeout: float = 30.0,
        max_idle_per_host: int = 4,
        max_response_size: int = 16 * 1024 * 1024,
        isolation: Isolation = "per_host",
        user_agent: str | None = None,
        verify: bool = True,
        max_redirects: int = 10,
        max_retries: int = 2,
    ) -> None: ...
    async def get(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        isolation: IsolationToken | None = None,
    ) -> Response: ...
    async def head(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        isolation: IsolationToken | None = None,
    ) -> Response: ...
    async def options(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        isolation: IsolationToken | None = None,
    ) -> Response: ...
    async def post(
        self,
        url: str,
        *,
        body: bytes | None = None,
        json: Any | None = None,
        data: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        isolation: IsolationToken | None = None,
    ) -> Response: ...
    async def put(
        self,
        url: str,
        *,
        body: bytes | None = None,
        json: Any | None = None,
        data: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        isolation: IsolationToken | None = None,
    ) -> Response: ...
    async def patch(
        self,
        url: str,
        *,
        body: bytes | None = None,
        json: Any | None = None,
        data: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        isolation: IsolationToken | None = None,
    ) -> Response: ...
    async def delete(
        self,
        url: str,
        *,
        body: bytes | None = None,
        json: Any | None = None,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        isolation: IsolationToken | None = None,
    ) -> Response: ...
    async def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        json: Any | None = None,
        data: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        isolation: IsolationToken | None = None,
    ) -> Response: ...
    async def resolve(self, hostname: str) -> list[str]:
        """Resolve a hostname through Tor, never locally."""

    async def __aenter__(self) -> AsyncClient: ...
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None = None,
        exc_val: BaseException | None = None,
        exc_tb: TracebackType | None = None,
    ) -> bool: ...

# ---------------------------------------------------------------------------
# Onion services
# ---------------------------------------------------------------------------

class Request:
    """A request handed to an OnionApp handler."""

    @property
    def method(self) -> str: ...
    @property
    def path(self) -> str: ...
    @property
    def query(self) -> dict[str, str]: ...
    @property
    def params(self) -> dict[str, str]:
        """Path parameters captured by the route pattern."""

    @property
    def headers(self) -> dict[str, str]: ...
    @property
    def body(self) -> bytes: ...
    def text(self) -> str: ...
    def json(self) -> Any: ...

class OnionApp:
    """A FastAPI-shaped onion service.

    The ``nickname`` is the service's identity: the ``.onion`` address is
    derived from a key filed under it, so relaunching with the same nickname
    republishes the **same address**. That is true with or without
    ``state_dir``, which chooses *where* the key is kept rather than whether it
    is kept at all — the default location is persistent. Change the nickname,
    or point ``state_dir`` at a fresh directory, to get a different address.

    An invalid nickname raises :class:`ValueError` from the constructor, not
    from :meth:`run` — a bad identity should fail where it is written, not after
    every route has been registered and a bootstrap attempted.

    A handler returns one of:

    * ``str`` — a ``200`` with ``text/plain``
    * ``bytes`` — a ``200`` with ``application/octet-stream``
    * ``dict`` or ``list`` — a ``200`` with JSON
    * ``None`` — a ``204``
    * ``(body, status)`` or ``(body, status, headers)`` — Flask's convention,
      where ``body`` is any of the above
    """

    def __init__(
        self,
        nickname: str = "hypertor",
        *,
        port: int = 80,
        ports: list[int] | None = None,
        state_dir: str | None = None,
        static_dir: str | None = None,
        max_body_size: int = 2 * 1024 * 1024,
        max_connections: int = 256,
        header_timeout: float = 30.0,
    ) -> None: ...
    def get(self, path: str) -> Callable[[_Handler], _Handler]: ...
    def post(self, path: str) -> Callable[[_Handler], _Handler]: ...
    def put(self, path: str) -> Callable[[_Handler], _Handler]: ...
    def patch(self, path: str) -> Callable[[_Handler], _Handler]: ...
    def delete(self, path: str) -> Callable[[_Handler], _Handler]: ...
    def route(self, method: str, path: str) -> Callable[[_Handler], _Handler]: ...
    def run(self, *, quiet: bool = False) -> None:
        """Publish the service and serve until interrupted.

        ``Ctrl-C`` raises :class:`KeyboardInterrupt` and shuts the service down
        cleanly, letting in-flight requests finish.
        """

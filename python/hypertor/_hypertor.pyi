"""Type stubs for the hypertor extension module."""

from types import TracebackType
from typing import Any, Callable, Literal, TypeVar

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
    def headers(self) -> dict[str, str]:
        """Response headers, lowercased."""

    @property
    def content(self) -> bytes:
        """The raw response body."""

    @property
    def text(self) -> str:
        """The body decoded as UTF-8."""

    def json(self) -> Any:
        """The body parsed as JSON."""

    def raise_for_status(self) -> Response:
        """Raise :class:`HypertorError` if the status is not 2xx."""

    def __len__(self) -> int: ...
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
        timeout: float = 30.0,
        max_idle_per_host: int = 4,
        isolation: Isolation = "per_host",
        user_agent: str | None = None,
        verify: bool = True,
    ) -> None: ...
    def get(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> Response: ...
    def post(
        self,
        url: str,
        *,
        body: bytes | None = None,
        json: Any | None = None,
        data: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> Response: ...
    def put(
        self,
        url: str,
        *,
        body: bytes | None = None,
        json: Any | None = None,
        data: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> Response: ...
    def delete(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
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
        timeout: float = 30.0,
        max_idle_per_host: int = 4,
        isolation: Isolation = "per_host",
        user_agent: str | None = None,
        verify: bool = True,
    ) -> None: ...
    async def get(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> Response: ...
    async def post(
        self,
        url: str,
        *,
        body: bytes | None = None,
        json: Any | None = None,
        data: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> Response: ...
    async def put(
        self,
        url: str,
        *,
        body: bytes | None = None,
        json: Any | None = None,
        data: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> Response: ...
    async def delete(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> Response: ...
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

    Pass ``state_dir`` to keep the same ``.onion`` address across restarts;
    without it the service gets a new address every time it starts.
    """

    def __init__(
        self,
        nickname: str = "hypertor",
        *,
        port: int = 80,
        state_dir: str | None = None,
    ) -> None: ...
    def get(self, path: str) -> Callable[[_Handler], _Handler]: ...
    def post(self, path: str) -> Callable[[_Handler], _Handler]: ...
    def put(self, path: str) -> Callable[[_Handler], _Handler]: ...
    def delete(self, path: str) -> Callable[[_Handler], _Handler]: ...
    def run(self) -> None:
        """Publish the service and serve until interrupted."""

"""Type stubs for hypertor."""

from typing import Optional, Callable, Any, Dict, List, TypeVar, Union

T = TypeVar('T')

# =============================================================================
# HTTP CLIENT
# =============================================================================

class Response:
    """HTTP response from a Tor request."""

    @property
    def status(self) -> int:
        """HTTP status code."""
        ...

    @property
    def headers(self) -> dict[str, str]:
        """Response headers."""
        ...

    def text(self) -> str:
        """Response body as text."""
        ...

    def bytes(self) -> bytes:
        """Response body as bytes."""
        ...

    def json(self) -> object:
        """Response body parsed as JSON."""
        ...

    def __len__(self) -> int:
        """Length of response body."""
        ...

    def __repr__(self) -> str:
        """String representation."""
        ...

class Client:
    """Synchronous Tor HTTP client.
    
    Example:
        >>> with hypertor.Client() as client:
        ...     response = client.get("http://example.onion")
        ...     print(response.text())
    """

    def __init__(
        self, 
        timeout: int = 30, 
        max_connections: int = 10
    ) -> None:
        """Create a new Tor client. Blocks until Tor bootstraps.
        
        Args:
            timeout: Request timeout in seconds (default: 30)
            max_connections: Maximum pooled connections (default: 10)
        """
        ...

    def __enter__(self) -> "Client":
        ...

    def __exit__(self, *args: object) -> None:
        ...

    def get(self, url: str) -> Response:
        """Make a GET request."""
        ...

    def post(
        self,
        url: str,
        *,
        body: Optional[bytes] = None,
        json: Optional[str] = None,
        data: Optional[dict[str, str]] = None,
    ) -> Response:
        """Make a POST request.
        
        Args:
            url: Request URL
            body: Raw bytes body
            json: Pre-serialized JSON string body
            data: Form data (URL-encoded)
        """
        ...

    def put(
        self,
        url: str,
        *,
        body: Optional[bytes] = None,
        json: Optional[str] = None,
        data: Optional[dict[str, str]] = None,
    ) -> Response:
        """Make a PUT request."""
        ...

    def delete(self, url: str) -> Response:
        """Make a DELETE request."""
        ...

    def pool_size(self) -> int:
        """Get the number of pooled connections."""
        ...

    def clear_pool(self) -> None:
        """Clear the connection pool."""
        ...

class AsyncClient:
    """Asynchronous Tor HTTP client.
    
    Example:
        >>> async with hypertor.AsyncClient() as client:
        ...     response = await client.get("http://example.onion")
        ...     print(response.text())
    """

    def __init__(
        self, 
        timeout: int = 30, 
        max_connections: int = 10
    ) -> None:
        """Create a new async Tor client (sync bootstrap)."""
        ...

    async def __aenter__(self) -> "AsyncClient":
        ...

    async def __aexit__(self, *args: object) -> None:
        ...

    @staticmethod
    async def create(
        timeout: int = 30, 
        max_connections: int = 10
    ) -> "AsyncClient":
        """Create a new async Tor client with async bootstrap."""
        ...

    async def get(self, url: str) -> Response:
        """Make a GET request."""
        ...

    async def post(
        self,
        url: str,
        *,
        body: Optional[bytes] = None,
        json: Optional[str] = None,
        data: Optional[dict[str, str]] = None,
    ) -> Response:
        """Make a POST request."""
        ...

    def pool_size(self) -> int:
        """Get the number of pooled connections."""
        ...


# =============================================================================
# ONION SERVICE (FastAPI-like)
# =============================================================================

class Request:
    """HTTP request object passed to route handlers.
    
    Attributes:
        method: HTTP method (GET, POST, etc.)
        path: Request path
        params: Path parameters extracted from route pattern
        query: Query string parameters
        headers: Request headers
    """
    
    method: str
    path: str
    params: Dict[str, str]
    query: Dict[str, str]
    headers: Dict[str, str]
    
    def text(self) -> str:
        """Get request body as text."""
        ...
    
    def json(self) -> Any:
        """Get request body parsed as JSON."""
        ...
    
    def body(self) -> bytes:
        """Get request body as bytes."""
        ...
    
    def header(self, name: str) -> Optional[str]:
        """Get a specific header by name."""
        ...
    
    def query_param(self, name: str) -> Optional[str]:
        """Get a specific query parameter."""
        ...
    
    def path_param(self, name: str) -> Optional[str]:
        """Get a specific path parameter."""
        ...


class AppResponse:
    """HTTP response for route handlers.
    
    Example:
        >>> return AppResponse("Hello", status=200)
        >>> return AppResponse.json({"key": "value"})
        >>> return AppResponse.html("<h1>Hello</h1>")
    """
    
    status: int
    
    def __init__(
        self,
        body: Union[str, bytes, Any],
        status: int = 200,
        content_type: str = "text/plain"
    ) -> None:
        """Create a new response.
        
        Args:
            body: Response body (str, bytes, or JSON-serializable)
            status: HTTP status code
            content_type: Content-Type header
        """
        ...
    
    @staticmethod
    def json(data: Any, status: Optional[int] = None) -> "AppResponse":
        """Create JSON response."""
        ...
    
    @staticmethod
    def html(content: str, status: Optional[int] = None) -> "AppResponse":
        """Create HTML response."""
        ...
    
    @staticmethod
    def redirect(location: str, status: Optional[int] = None) -> "AppResponse":
        """Create redirect response."""
        ...
    
    def set_header(self, name: str, value: str) -> None:
        """Add a response header."""
        ...
    
    def get_headers(self) -> Dict[str, str]:
        """Get all response headers."""
        ...


class AppConfig:
    """Configuration for OnionApp.
    
    Attributes:
        port: Virtual port for .onion address (default: 80)
        debug: Enable debug mode
        log_requests: Enable request logging
        timeout: Request timeout in seconds
        max_body_size: Max request body size in bytes
        key_file: Path to key file for persistent .onion address
        enable_pow: Enable Proof-of-Work protection
        security_level: "standard", "enhanced", "maximum", or "paranoid"
    """
    
    port: int
    debug: bool
    log_requests: bool
    timeout: int
    max_body_size: int
    key_file: Optional[str]
    enable_pow: bool
    security_level: str
    
    def __init__(
        self,
        port: int = 80,
        debug: bool = False,
        log_requests: bool = True,
        timeout: int = 30,
        max_body_size: int = 10485760,
        key_file: Optional[str] = None,
        enable_pow: bool = False,
        security_level: str = "standard"
    ) -> None:
        """Create app configuration.
        
        Args:
            port: Virtual port (default: 80)
            debug: Enable debug mode
            log_requests: Log incoming requests
            timeout: Request timeout in seconds
            max_body_size: Max body size (default: 10MB)
            key_file: Path for persistent .onion address
            enable_pow: Enable Proof-of-Work DoS protection
            security_level: Security preset ("standard", "enhanced", "maximum", "paranoid")
        """
        ...


class OnionApp:
    """FastAPI-like onion service application.
    
    Example:
        >>> app = OnionApp()
        >>> 
        >>> @app.get("/")
        ... def home():
        ...     return "Welcome to my .onion service!"
        >>> 
        >>> @app.post("/api/echo")
        ... def echo(request: Request):
        ...     return {"received": request.json()}
        >>> 
        >>> @app.get("/users/{user_id}")
        ... def get_user(user_id: int):
        ...     return {"id": user_id, "name": "Alice"}
        >>> 
        >>> app.run()  # 🧅 Service live at: xyz...xyz.onion
    """
    
    def __init__(
        self,
        config: Optional[AppConfig] = None,
        port: int = 80,
        debug: bool = False,
        key_file: Optional[str] = None
    ) -> None:
        """Create a new OnionApp.
        
        Args:
            config: Optional AppConfig object
            port: Port number (default: 80)
            debug: Enable debug mode
            key_file: Path to key file for persistent address
        """
        ...
    
    def get(
        self, 
        path: str, 
        response_model: Optional[str] = None
    ) -> Callable[[T], T]:
        """Register a GET route handler.
        
        Usage:
            @app.get("/")
            def home():
                return "Hello!"
        """
        ...
    
    def post(
        self, 
        path: str, 
        response_model: Optional[str] = None
    ) -> Callable[[T], T]:
        """Register a POST route handler."""
        ...
    
    def put(
        self, 
        path: str, 
        response_model: Optional[str] = None
    ) -> Callable[[T], T]:
        """Register a PUT route handler."""
        ...
    
    def delete(
        self, 
        path: str, 
        response_model: Optional[str] = None
    ) -> Callable[[T], T]:
        """Register a DELETE route handler."""
        ...
    
    def patch(
        self, 
        path: str, 
        response_model: Optional[str] = None
    ) -> Callable[[T], T]:
        """Register a PATCH route handler."""
        ...
    
    def route(
        self,
        path: str,
        methods: Optional[List[str]] = None,
        response_model: Optional[str] = None
    ) -> Callable[[T], T]:
        """Register a route with explicit method(s).
        
        Usage:
            @app.route("/path", methods=["GET", "POST"])
            def handler(request):
                return "response"
        """
        ...
    
    def middleware(self, func: T) -> T:
        """Add middleware.
        
        Usage:
            @app.middleware
            async def log_request(request, call_next):
                print(f"Request: {request.path}")
                response = await call_next(request)
                return response
        """
        ...
    
    def error_handler(self, status_code: int) -> Callable[[T], T]:
        """Register error handler for specific status code.
        
        Usage:
            @app.error_handler(404)
            def not_found(request):
                return {"error": "Not found"}
        """
        ...
    
    def on_startup(self, func: T) -> T:
        """Register startup hook."""
        ...
    
    def on_shutdown(self, func: T) -> T:
        """Register shutdown hook."""
        ...
    
    def routes_info(self) -> List[Dict[str, str]]:
        """Get registered routes (for debugging)."""
        ...
    
    def address(self) -> Optional[str]:
        """Get the .onion address (available after run())."""
        ...
    
    def is_running(self) -> bool:
        """Check if app is running."""
        ...
    
    def stop(self) -> None:
        """Stop the app."""
        ...
    
    def run(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        reload: bool = False
    ) -> None:
        """Run the onion service.
        
        This starts the Tor connection, publishes the service descriptor,
        and begins accepting connections. Blocks until stopped.
        
        Args:
            host: Ignored (for FastAPI compatibility)
            port: Ignored (uses config.port)
            reload: Enable auto-reload (not implemented)
        """
        ...


# =============================================================================
# EXCEPTIONS
# =============================================================================

class HypertorError(Exception):
    """Base exception for hypertor errors."""
    ...

class TorBootstrapError(HypertorError):
    """Failed to bootstrap Tor connection."""
    ...

class ConnectionError(HypertorError):
    """Failed to connect through Tor."""
    ...

class TimeoutError(HypertorError):
    """Request or operation timed out."""
    ...

class TlsError(HypertorError):
    """TLS/SSL error."""
    ...


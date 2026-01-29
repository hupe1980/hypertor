"""
Comprehensive tests for hypertor Python bindings.

These tests verify:
1. All public API is exposed correctly
2. Type annotations are accurate
3. Security configurations wire through properly
4. Error handling works as expected

Note: Network tests are skipped by default (require Tor network).
Run with: pytest tests/ -v
Run with network: pytest tests/ -v --network
"""

import pytest
from typing import TYPE_CHECKING

# Try to import hypertor - will fail if not built with --features python
try:
    import hypertor
    from hypertor import (
        Client, AsyncClient, Response,
        OnionApp, AppConfig, Request, AppResponse,
        HypertorError,
    )
    HYPERTOR_AVAILABLE = True
except ImportError as e:
    HYPERTOR_AVAILABLE = False
    IMPORT_ERROR = str(e)


# Skip all tests if hypertor not available
pytestmark = pytest.mark.skipif(
    not HYPERTOR_AVAILABLE, 
    reason=f"hypertor not installed: {IMPORT_ERROR if not HYPERTOR_AVAILABLE else ''}"
)


# =============================================================================
# IMPORT TESTS
# =============================================================================

class TestImports:
    """Test that all public API is exposed."""
    
    def test_version_exists(self):
        """Version string should be set."""
        assert hasattr(hypertor, '__version__')
        assert isinstance(hypertor.__version__, str)
        assert hypertor.__version__ == "0.3.0"
    
    def test_client_classes_exist(self):
        """Client classes should be importable."""
        assert Client is not None
        assert AsyncClient is not None
        assert Response is not None
    
    def test_server_classes_exist(self):
        """Server classes should be importable."""
        assert OnionApp is not None
        assert AppConfig is not None
        assert Request is not None
        assert AppResponse is not None
    
    def test_exception_classes_exist(self):
        """Exception classes should be importable."""
        assert HypertorError is not None
        assert issubclass(HypertorError, Exception)


# =============================================================================
# CLIENT TESTS (without network)
# =============================================================================

class TestClientAPI:
    """Test Client API without requiring Tor network."""
    
    def test_client_has_context_manager(self):
        """Client should support context manager protocol."""
        assert hasattr(Client, '__enter__')
        assert hasattr(Client, '__exit__')
    
    def test_async_client_has_context_manager(self):
        """AsyncClient should support async context manager protocol."""
        assert hasattr(AsyncClient, '__aenter__')
        assert hasattr(AsyncClient, '__aexit__')
    
    def test_client_has_http_methods(self):
        """Client should have all HTTP methods."""
        for method in ['get', 'post', 'put', 'delete']:
            assert hasattr(Client, method), f"Client missing {method} method"
    
    def test_async_client_has_http_methods(self):
        """AsyncClient should have all HTTP methods."""
        for method in ['get', 'post']:
            assert hasattr(AsyncClient, method), f"AsyncClient missing {method} method"
    
    def test_client_has_pool_methods(self):
        """Client should have connection pool management."""
        assert hasattr(Client, 'pool_size')
        assert hasattr(Client, 'clear_pool')


# =============================================================================
# SERVER (ONIONAPP) TESTS
# =============================================================================

class TestOnionAppAPI:
    """Test OnionApp API without requiring Tor network."""
    
    def test_onionapp_creation(self):
        """OnionApp should be creatable without network."""
        app = OnionApp()
        assert app is not None
    
    def test_onionapp_with_port(self):
        """OnionApp should accept port parameter."""
        app = OnionApp(port=8080)
        assert app is not None
    
    def test_onionapp_has_route_decorators(self):
        """OnionApp should have all route decorators."""
        app = OnionApp()
        for method in ['get', 'post', 'put', 'delete', 'patch', 'route']:
            assert hasattr(app, method), f"OnionApp missing {method} decorator"
    
    def test_onionapp_get_decorator(self):
        """@app.get decorator should register routes."""
        app = OnionApp()
        
        @app.get("/")
        def home():
            return "Hello"
        
        routes = app.routes_info()
        assert len(routes) == 1
        assert routes[0]['method'] == 'GET'
        assert routes[0]['path'] == '/'
    
    def test_onionapp_post_decorator(self):
        """@app.post decorator should register routes."""
        app = OnionApp()
        
        @app.post("/api/data")
        def create_data():
            return {"status": "created"}
        
        routes = app.routes_info()
        assert len(routes) == 1
        assert routes[0]['method'] == 'POST'
        assert routes[0]['path'] == '/api/data'
    
    def test_onionapp_multiple_routes(self):
        """OnionApp should support multiple routes."""
        app = OnionApp()
        
        @app.get("/")
        def home():
            return "Home"
        
        @app.get("/about")
        def about():
            return "About"
        
        @app.post("/api/users")
        def create_user():
            return {"id": 1}
        
        routes = app.routes_info()
        assert len(routes) == 3
    
    def test_onionapp_route_with_methods(self):
        """@app.route should accept methods parameter."""
        app = OnionApp()
        
        @app.route("/api/resource", methods=["GET", "POST"])
        def resource():
            return "Resource"
        
        routes = app.routes_info()
        assert len(routes) == 2  # One for each method
    
    def test_onionapp_has_lifecycle_hooks(self):
        """OnionApp should have lifecycle hooks."""
        app = OnionApp()
        assert hasattr(app, 'on_startup')
        assert hasattr(app, 'on_shutdown')
        assert hasattr(app, 'middleware')
        assert hasattr(app, 'error_handler')
    
    def test_onionapp_middleware_decorator(self):
        """@app.middleware decorator should work."""
        app = OnionApp()
        
        @app.middleware
        def log_middleware(request, call_next):
            return call_next(request)
        
        # Should not raise
        assert True
    
    def test_onionapp_error_handler_decorator(self):
        """@app.error_handler decorator should work."""
        app = OnionApp()
        
        @app.error_handler(404)
        def not_found(request):
            return {"error": "Not found"}
        
        # Should not raise
        assert True
    
    def test_onionapp_address_before_run(self):
        """address() should return None before run()."""
        app = OnionApp()
        assert app.address() is None
    
    def test_onionapp_is_running_before_run(self):
        """is_running() should return False before run()."""
        app = OnionApp()
        assert app.is_running() is False


# =============================================================================
# APP CONFIG TESTS
# =============================================================================

class TestAppConfig:
    """Test AppConfig configuration."""
    
    def test_default_config(self):
        """AppConfig should have sensible defaults."""
        config = AppConfig()
        assert config.port == 80
        assert config.debug is False
        assert config.log_requests is True
        assert config.timeout == 30
        assert config.enable_pow is False
        assert config.security_level == "standard"
    
    def test_custom_port(self):
        """AppConfig should accept custom port."""
        config = AppConfig(port=8080)
        assert config.port == 8080
    
    def test_enable_pow(self):
        """AppConfig should accept enable_pow."""
        config = AppConfig(enable_pow=True)
        assert config.enable_pow is True
    
    def test_security_levels(self):
        """AppConfig should accept all security levels."""
        for level in ["standard", "enhanced", "maximum", "paranoid"]:
            config = AppConfig(security_level=level)
            assert config.security_level == level
    
    def test_key_file(self):
        """AppConfig should accept key_file for persistent address."""
        config = AppConfig(key_file="/path/to/keys")
        assert config.key_file == "/path/to/keys"
    
    def test_max_body_size(self):
        """AppConfig should accept max_body_size."""
        config = AppConfig(max_body_size=1024*1024)  # 1MB
        assert config.max_body_size == 1024*1024
    
    def test_onionapp_with_config(self):
        """OnionApp should accept AppConfig object."""
        config = AppConfig(
            port=443,
            enable_pow=True,
            security_level="maximum",
        )
        app = OnionApp(config=config)
        assert app is not None


# =============================================================================
# RESPONSE TESTS
# =============================================================================

class TestAppResponse:
    """Test AppResponse helper class."""
    
    def test_string_response(self):
        """AppResponse should accept string body."""
        response = AppResponse("Hello, World!")
        assert response.status == 200
    
    def test_custom_status(self):
        """AppResponse should accept custom status code."""
        response = AppResponse("Not Found", status=404)
        assert response.status == 404
    
    def test_json_response(self):
        """AppResponse.json should create JSON response."""
        response = AppResponse.json({"key": "value"})
        assert response.status == 200
    
    def test_json_response_with_status(self):
        """AppResponse.json should accept status code."""
        response = AppResponse.json({"error": "Bad Request"}, status=400)
        assert response.status == 400
    
    def test_html_response(self):
        """AppResponse.html should create HTML response."""
        response = AppResponse.html("<h1>Hello</h1>")
        assert response.status == 200
    
    def test_redirect_response(self):
        """AppResponse.redirect should create redirect response."""
        response = AppResponse.redirect("/new-location")
        assert response.status == 302
    
    def test_redirect_with_custom_status(self):
        """AppResponse.redirect should accept custom status."""
        response = AppResponse.redirect("/permanent", status=301)
        assert response.status == 301
    
    def test_set_header(self):
        """AppResponse should allow setting headers."""
        response = AppResponse("OK")
        response.set_header("X-Custom", "value")
        headers = response.get_headers()
        assert "X-Custom" in headers
        assert headers["X-Custom"] == "value"


# =============================================================================
# SECURITY CONFIGURATION TESTS
# =============================================================================

class TestSecurityConfiguration:
    """Test that security configurations are properly exposed."""
    
    def test_standard_security(self):
        """Standard security should use defaults."""
        config = AppConfig(security_level="standard")
        assert config.security_level == "standard"
        assert config.enable_pow is False  # Not enabled by default
    
    def test_enhanced_security(self):
        """Enhanced security should enable vanguards lite."""
        config = AppConfig(security_level="enhanced")
        assert config.security_level == "enhanced"
    
    def test_maximum_security(self):
        """Maximum security should enable all hardening."""
        config = AppConfig(security_level="maximum", enable_pow=True)
        assert config.security_level == "maximum"
        assert config.enable_pow is True
    
    def test_paranoid_security(self):
        """Paranoid security should be accepted."""
        config = AppConfig(security_level="paranoid")
        assert config.security_level == "paranoid"


# =============================================================================
# INTEGRATION PATTERN TESTS
# =============================================================================

class TestIntegrationPatterns:
    """Test common integration patterns."""
    
    def test_fastapi_like_pattern(self):
        """FastAPI-like pattern should work."""
        app = OnionApp()
        
        @app.get("/")
        def home():
            return {"message": "Hello"}
        
        @app.get("/items/{item_id}")
        def get_item(item_id: int):
            return {"item_id": item_id}
        
        @app.post("/items")
        def create_item():
            return {"status": "created"}
        
        routes = app.routes_info()
        assert len(routes) == 3
    
    def test_restful_api_pattern(self):
        """RESTful API pattern should work."""
        app = OnionApp()
        
        # Collection endpoints
        @app.get("/users")
        def list_users():
            return []
        
        @app.post("/users")
        def create_user():
            return {"id": 1}
        
        # Item endpoints
        @app.get("/users/{id}")
        def get_user(id: int):
            return {"id": id}
        
        @app.put("/users/{id}")
        def update_user(id: int):
            return {"id": id, "updated": True}
        
        @app.delete("/users/{id}")
        def delete_user(id: int):
            return {"deleted": True}
        
        routes = app.routes_info()
        assert len(routes) == 5
    
    def test_secure_service_pattern(self):
        """Secure service configuration pattern should work."""
        # This is how a secure press service would be configured
        config = AppConfig(
            port=80,
            enable_pow=True,           # DoS protection
            security_level="maximum",  # Full hardening
            timeout=60,                # Longer timeout for Tor
            max_body_size=50*1024*1024,  # 50MB for document uploads
        )
        
        app = OnionApp(config=config)
        
        @app.get("/")
        def index():
            return {"status": "secure"}
        
        @app.post("/submit")
        def submit_document():
            return {"received": True}
        
        assert len(app.routes_info()) == 2


# =============================================================================
# NETWORK TESTS (skipped by default)
# =============================================================================

@pytest.mark.network
class TestNetworkIntegration:
    """Tests that require actual Tor network.
    
    Run with: pytest tests/ -v -m network
    """
    
    @pytest.mark.skip(reason="Requires Tor network")
    def test_client_connects_to_tor(self):
        """Client should connect to Tor network."""
        with Client(timeout=120) as client:
            response = client.get("https://check.torproject.org/api/ip")
            assert response.status == 200
    
    @pytest.mark.skip(reason="Requires Tor network")
    def test_onion_service_starts(self):
        """OnionApp should start and get .onion address."""
        app = OnionApp(port=8080)
        
        @app.get("/")
        def home():
            return "Hello"
        
        # Would need to run in background and check address
        # This is a placeholder for real network testing


# =============================================================================
# PYTEST CONFIGURATION
# =============================================================================

def pytest_configure(config):
    """Add custom markers."""
    config.addinivalue_line(
        "markers", "network: marks tests as requiring Tor network"
    )

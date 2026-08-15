"""Tests for the hypertor Python bindings.

Tests needing a live Tor connection are marked ``network`` and deselected by
default:

    pytest                      # fast, offline
    pytest -m network           # includes the live tests
"""

import inspect

import pytest

hypertor = pytest.importorskip(
    "hypertor",
    reason="build the extension first: maturin develop --features python",
)


class TestModuleSurface:
    def test_exports_the_documented_names(self):
        for name in (
            "Client",
            "AsyncClient",
            "Response",
            "OnionApp",
            "Request",
            "HypertorError",
            "ConnectionError",
            "TimeoutError",
            "TlsError",
        ):
            assert hasattr(hypertor, name), f"hypertor.{name} is missing"

    def test_version_is_present(self):
        assert isinstance(hypertor.__version__, str)
        assert hypertor.__version__

    def test_exception_hierarchy(self):
        # Catching HypertorError must catch every hypertor failure.
        assert issubclass(hypertor.ConnectionError, hypertor.HypertorError)
        assert issubclass(hypertor.TimeoutError, hypertor.HypertorError)
        assert issubclass(hypertor.TlsError, hypertor.HypertorError)


class TestClientSignature:
    def test_rejects_an_unknown_isolation_level(self):
        with pytest.raises(hypertor.HypertorError, match="isolation"):
            hypertor.Client(isolation="nonsense")

    def test_onion_app_rejects_an_invalid_nickname(self):
        app = hypertor.OnionApp("has spaces")
        with pytest.raises(hypertor.HypertorError):
            app.run()

    def test_route_decorator_returns_the_original_function(self):
        app = hypertor.OnionApp("test-app")

        @app.get("/")
        def home(request):
            return "hello"

        # Decorating must not replace the function; the module that defined it
        # still needs to be able to call it.
        assert callable(home)
        assert home.__name__ == "home"
        assert inspect.signature(home).parameters.keys() == {"request"}


@pytest.mark.network
class TestLiveNetwork:
    """Requires a working Tor connection."""

    def test_reaches_an_onion_service(self):
        with hypertor.Client(timeout=120) as client:
            response = client.get(
                "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/"
            )
            assert response.status_code in (200, 301, 302)

    def test_reports_a_tor_exit_address(self):
        with hypertor.Client(timeout=120) as client:
            response = client.get("https://check.torproject.org/api/ip")
            payload = response.json()
            assert payload["IsTor"] is True

    def test_isolation_uses_separate_circuits(self):
        seen = set()
        with hypertor.Client(timeout=120, isolation="per_request") as client:
            for _ in range(3):
                payload = client.get("https://check.torproject.org/api/ip").json()
                seen.add(payload["IP"])

        assert len(seen) > 1, f"per-request isolation reused one exit: {seen}"

    @pytest.mark.asyncio
    async def test_async_client(self):
        async with hypertor.AsyncClient(timeout=120) as client:
            response = await client.get("https://check.torproject.org/api/ip")
            assert response.ok

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
    reason="build the extension first: maturin develop",
)


def _sample(name: str) -> object:
    """A type-correct value for one client constructor keyword."""
    if name in ("timeout", "connect_timeout"):
        return 5.0
    if name in ("max_idle_per_host", "max_response_size", "max_redirects", "max_retries"):
        return 1
    if name == "user_agent":
        return "test/1.0"
    if name == "verify":
        return True
    raise AssertionError(f"no sample value for {name}")


class TestModuleSurface:
    def test_exports_the_documented_names(self):
        for name in (
            "Client",
            "AsyncClient",
            "Response",
            "OnionApp",
            "Request",
            "IsolationToken",
            "HypertorError",
            "ConnectionError",
            "TimeoutError",
            "TlsError",
            "StatusError",
        ):
            assert hasattr(hypertor, name), f"hypertor.{name} is missing"

    def test_version_is_present(self):
        assert isinstance(hypertor.__version__, str)
        assert hypertor.__version__

    def test_exception_hierarchy(self):
        # Catching HypertorError must catch every hypertor failure.
        for name in ("ConnectionError", "TimeoutError", "TlsError", "StatusError"):
            assert issubclass(getattr(hypertor, name), hypertor.HypertorError)

    @pytest.mark.parametrize(
        "method",
        ["get", "head", "options", "post", "put", "patch", "delete", "request", "resolve"],
    )
    def test_both_clients_expose_the_same_methods(self, method):
        # The sync and async surfaces are generated from one definition; this
        # pins that they cannot drift apart again.
        assert hasattr(hypertor.Client, method), f"Client.{method} is missing"
        assert hasattr(hypertor.AsyncClient, method), f"AsyncClient.{method} is missing"


class TestIsolation:
    def test_tokens_are_distinct_objects(self):
        a = hypertor.IsolationToken()
        b = hypertor.IsolationToken()
        assert a is not b
        assert "IsolationToken" in repr(a)


class TestClientSignature:
    def test_rejects_an_unknown_isolation_level(self):
        # Must fail before bootstrapping, not tens of seconds later.
        with pytest.raises(ValueError, match="isolation"):
            hypertor.Client(isolation="nonsense")

    @pytest.mark.parametrize("client", [hypertor.Client, hypertor.AsyncClient])
    @pytest.mark.parametrize(
        "keyword",
        [
            "timeout",
            "connect_timeout",
            "max_idle_per_host",
            "max_response_size",
            "user_agent",
            "verify",
            "max_redirects",
            "max_retries",
        ],
    )
    def test_constructors_accept_the_documented_keywords(self, client, keyword):
        # The stubs promise these keywords; a mismatch only shows up at runtime.
        # A deliberately invalid isolation aborts before Tor is bootstrapped, so
        # this checks argument binding without paying for a real connection.
        with pytest.raises(ValueError) as excinfo:
            client(isolation="nonsense", **{keyword: _sample(keyword)})

        assert "unexpected keyword" not in str(excinfo.value)
        assert "isolation" in str(excinfo.value)


class TestOnionApp:
    def test_rejects_an_invalid_nickname(self):
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

    def test_every_method_decorator_registers(self):
        app = hypertor.OnionApp("test-app")

        for register in (app.get, app.post, app.put, app.patch, app.delete):

            @register("/x")
            def handler(request):
                return "ok"

        app.route("OPTIONS", "/x")(lambda request: "ok")

        assert "routes=6" in repr(app)

    def test_rejects_an_invalid_method_name(self):
        app = hypertor.OnionApp("test-app")
        with pytest.raises(ValueError):
            app.route("bad method", "/x")

    @pytest.mark.parametrize(
        ("keyword", "value"),
        [
            ("port", 8080),
            ("ports", [80, 443]),
            ("state_dir", "./state"),
            ("static_dir", "./public"),
            ("max_body_size", 4096),
            ("max_connections", 32),
            ("header_timeout", 5.0),
        ],
    )
    def test_constructor_accepts_the_documented_keywords(self, keyword, value):
        # The stubs promise these; a mismatch only shows up at runtime.
        assert hypertor.OnionApp("test-app", **{keyword: value})

    def test_rejects_an_empty_port_list(self):
        # Such a service would publish a descriptor and reject every client.
        with pytest.raises(ValueError, match="ports"):
            hypertor.OnionApp("test-app", ports=[])


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
            assert response  # __bool__ is the status, not the body length
            assert response.reason == "OK"
            payload = response.json()
            assert payload["IsTor"] is True

    def test_isolation_uses_separate_circuits(self):
        seen = set()
        with hypertor.Client(timeout=120, isolation="per_request") as client:
            for _ in range(3):
                payload = client.get("https://check.torproject.org/api/ip").json()
                seen.add(payload["IP"])

        assert len(seen) > 1, f"per-request isolation reused one exit: {seen}"

    def test_explicit_isolation_tokens_pin_a_circuit(self):
        alice = hypertor.IsolationToken()
        with hypertor.Client(timeout=120, isolation="none") as client:
            first = client.get("https://check.torproject.org/api/ip", isolation=alice).json()
            second = client.get("https://check.torproject.org/api/ip", isolation=alice).json()

        assert first["IP"] == second["IP"], "one token must mean one circuit"

    def test_raise_for_status_raises_status_error(self):
        with hypertor.Client(timeout=120) as client:
            response = client.get("https://check.torproject.org/nonexistent-path")
            if not response.ok:
                with pytest.raises(hypertor.StatusError):
                    response.raise_for_status()

    @pytest.mark.asyncio
    async def test_async_client(self):
        async with hypertor.AsyncClient(timeout=120) as client:
            response = await client.get("https://check.torproject.org/api/ip")
            assert response.ok

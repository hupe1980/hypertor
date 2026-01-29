#!/usr/bin/env python3
"""
Secure API Client - Production-Ready Example

This example shows how to build a production-grade Tor client
with retry logic, rate limiting, and error handling.

Similar to how you'd use `requests` or `httpx` in production,
but routed through Tor for anonymity.

Requirements:
    uv venv && source .venv/bin/activate
    uv pip install maturin && maturin develop

Run:
    python secure_api_client.py
"""

from hypertor import AsyncClient, TimeoutError, HypertorError
import asyncio
from dataclasses import dataclass
from typing import Optional, Any
import time


@dataclass
class ApiResponse:
    """Structured API response"""
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    latency_ms: float = 0.0
    cached: bool = False


class SimpleCache:
    """Simple in-memory cache with TTL"""
    
    def __init__(self, ttl_seconds: int = 60):
        self._cache: dict = {}
        self._ttl = ttl_seconds
    
    def get(self, key: str) -> Optional[Any]:
        if key in self._cache:
            value, timestamp = self._cache[key]
            if time.time() - timestamp < self._ttl:
                return value
            del self._cache[key]
        return None
    
    def set(self, key: str, value: Any):
        self._cache[key] = (value, time.time())


class SimpleRateLimiter:
    """Simple token bucket rate limiter"""
    
    def __init__(self, requests_per_second: float = 10.0):
        self._rate = requests_per_second
        self._last_request = 0.0
    
    async def acquire(self):
        now = time.time()
        min_interval = 1.0 / self._rate
        elapsed = now - self._last_request
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        self._last_request = time.time()


class SimpleCircuitBreaker:
    """Simple circuit breaker pattern"""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 30.0):
        self._failure_count = 0
        self._threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._last_failure_time = 0.0
        self._is_open = False
    
    def allow_request(self) -> bool:
        if not self._is_open:
            return True
        # Check if we should try again
        if time.time() - self._last_failure_time > self._recovery_timeout:
            self._is_open = False
            self._failure_count = 0
            return True
        return False
    
    def record_success(self):
        self._failure_count = 0
        self._is_open = False
    
    def record_failure(self):
        self._failure_count += 1
        self._last_failure_time = time.time()
        if self._failure_count >= self._threshold:
            self._is_open = True


class SecureApiClient:
    """
    Production-grade Tor API client with:
    - Automatic retries with exponential backoff
    - Circuit breaker pattern
    - Rate limiting
    - Response caching
    - Comprehensive error handling
    """
    
    def __init__(
        self,
        base_url: str,
        max_retries: int = 3,
        requests_per_second: float = 10.0,
        cache_ttl_seconds: int = 60,
        timeout: int = 60
    ):
        self.base_url = base_url.rstrip("/")
        self.max_retries = max_retries
        self.timeout = timeout
        
        # Resilience components
        self._client: Optional[AsyncClient] = None
        self._circuit_breaker = SimpleCircuitBreaker(
            failure_threshold=5,
            recovery_timeout=30.0
        )
        self._rate_limiter = SimpleRateLimiter(
            requests_per_second=requests_per_second
        )
        self._cache = SimpleCache(ttl_seconds=cache_ttl_seconds)
        
        # Statistics
        self.stats = {
            "requests": 0,
            "successes": 0,
            "failures": 0,
            "cache_hits": 0,
            "retries": 0
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        self._client = await AsyncClient(timeout=self.timeout).__aenter__()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self._client:
            await self._client.__aexit__(exc_type, exc_val, exc_tb)
    
    def _get_retry_delay(self, attempt: int) -> float:
        """Exponential backoff with jitter"""
        import random
        base_delay = 1.0
        max_delay = 30.0
        delay = min(base_delay * (2 ** attempt), max_delay)
        # Add jitter
        delay = delay * (0.5 + random.random())
        return delay
    
    async def get(
        self,
        endpoint: str,
        use_cache: bool = True
    ) -> ApiResponse:
        """
        Make a GET request with full resilience stack.
        
        Args:
            endpoint: API endpoint (relative to base_url)
            use_cache: Whether to use response caching
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        cache_key = f"GET:{url}"
        
        # Check cache first
        if use_cache:
            cached = self._cache.get(cache_key)
            if cached is not None:
                self.stats["cache_hits"] += 1
                return ApiResponse(
                    success=True,
                    data=cached,
                    cached=True
                )
        
        # Check circuit breaker
        if not self._circuit_breaker.allow_request():
            return ApiResponse(
                success=False,
                error="Circuit breaker is open - service unavailable"
            )
        
        # Rate limiting
        await self._rate_limiter.acquire()
        
        self.stats["requests"] += 1
        start_time = time.time()
        
        # Retry loop
        last_error = None
        for attempt in range(self.max_retries + 1):
            try:
                response = await self._client.get(url)
                
                if response.status_code >= 500:
                    raise Exception(f"Server error: {response.status_code}")
                
                if response.status_code >= 400:
                    return ApiResponse(
                        success=False,
                        error=f"Client error: {response.status_code}",
                        latency_ms=(time.time() - start_time) * 1000
                    )
                
                # Success!
                data = response.json()
                self._circuit_breaker.record_success()
                self.stats["successes"] += 1
                
                # Cache the response
                if use_cache:
                    self._cache.set(cache_key, data)
                
                return ApiResponse(
                    success=True,
                    data=data,
                    latency_ms=(time.time() - start_time) * 1000
                )
                
            except TimeoutError:
                last_error = "Request timed out"
                self._circuit_breaker.record_failure()
            except HypertorError as e:
                last_error = str(e)
                self._circuit_breaker.record_failure()
            except Exception as e:
                last_error = str(e)
                self._circuit_breaker.record_failure()
            
            if attempt < self.max_retries:
                self.stats["retries"] += 1
                delay = self._get_retry_delay(attempt)
                print(f"   ⚠️  Retry {attempt + 1}/{self.max_retries} after {delay:.1f}s: {last_error}")
                await asyncio.sleep(delay)
        
        self.stats["failures"] += 1
        return ApiResponse(
            success=False,
            error=f"All retries failed: {last_error}",
            latency_ms=(time.time() - start_time) * 1000
        )
    
    async def post(
        self,
        endpoint: str,
        json_data: Optional[str] = None
    ) -> ApiResponse:
        """Make a POST request with resilience stack."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        if not self._circuit_breaker.allow_request():
            return ApiResponse(
                success=False,
                error="Circuit breaker is open"
            )
        
        await self._rate_limiter.acquire()
        self.stats["requests"] += 1
        start_time = time.time()
        
        last_error = None
        for attempt in range(self.max_retries + 1):
            try:
                response = await self._client.post(url, json=json_data)
                
                if response.status_code >= 500:
                    raise Exception(f"Server error: {response.status_code}")
                
                data = response.json()
                
                self._circuit_breaker.record_success()
                self.stats["successes"] += 1
                
                return ApiResponse(
                    success=response.status_code < 400,
                    data=data,
                    error=None if response.status_code < 400 else f"Status: {response.status_code}",
                    latency_ms=(time.time() - start_time) * 1000
                )
                
            except TimeoutError:
                last_error = "Request timed out"
                self._circuit_breaker.record_failure()
            except HypertorError as e:
                last_error = str(e)
                self._circuit_breaker.record_failure()
            except Exception as e:
                last_error = str(e)
                self._circuit_breaker.record_failure()
            
            if attempt < self.max_retries:
                self.stats["retries"] += 1
                delay = self._get_retry_delay(attempt)
                await asyncio.sleep(delay)
        
        self.stats["failures"] += 1
        return ApiResponse(
            success=False,
            error=f"All retries failed: {last_error}",
            latency_ms=(time.time() - start_time) * 1000
        )
    
    def print_stats(self):
        """Print client statistics"""
        total = self.stats["requests"]
        if total == 0:
            print("   No requests made")
            return
        
        success_rate = (self.stats["successes"] / total) * 100
        cache_rate = (self.stats["cache_hits"] / (total + self.stats["cache_hits"])) * 100 if total else 0
        
        print(f"   📊 Statistics:")
        print(f"      Total Requests: {total}")
        print(f"      Successes: {self.stats['successes']} ({success_rate:.1f}%)")
        print(f"      Failures: {self.stats['failures']}")
        print(f"      Cache Hits: {self.stats['cache_hits']} ({cache_rate:.1f}%)")
        print(f"      Retries: {self.stats['retries']}")


# =============================================================================
# Demo
# =============================================================================

async def main():
    print("🧅 hypertor - Secure API Client Example")
    print("=" * 50)
    print()
    print("Note: Tor network requests can be slow. Please be patient.")
    print()
    
    try:
        async with SecureApiClient(
            base_url="https://httpbin.org",
            max_retries=2,
            requests_per_second=5.0,
            cache_ttl_seconds=30,
            timeout=60
        ) as client:
            
            # Test 1: Basic GET
            print("📡 Test 1: Basic GET request")
            resp = await client.get("/ip")
            if resp.success:
                print(f"   ✅ Your Tor IP: {resp.data}")
                print(f"   ⏱️  Latency: {resp.latency_ms:.0f}ms")
            else:
                print(f"   ❌ Error: {resp.error}")
            
            # Test 2: Cached request
            print("\n📡 Test 2: Cached request (same endpoint)")
            resp = await client.get("/ip")
            if resp.cached:
                print(f"   ✅ Cache hit! Instant response")
                print(f"   📦 Cached data: {resp.data}")
            else:
                print(f"   ⏱️  Latency: {resp.latency_ms:.0f}ms")
            
            # Test 3: POST with JSON
            print("\n📡 Test 3: POST JSON data")
            import json
            json_body = json.dumps({
                "secret_message": "Hello from Tor!",
                "anonymous": True
            })
            resp = await client.post("/post", json_data=json_body)
            if resp.success:
                print(f"   ✅ Response received")
                print(f"   ⏱️  Latency: {resp.latency_ms:.0f}ms")
            else:
                print(f"   ❌ Error: {resp.error}")
            
            # Print statistics
            print("\n" + "-" * 40)
            client.print_stats()
        
        print("\n✅ Secure API Client demo completed!")
        
    except KeyboardInterrupt:
        print("\n\n🛑 Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())

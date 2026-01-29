#!/usr/bin/env python3
"""
Basic Tor Client Usage - Python Example

This example demonstrates how to use hypertor's AsyncClient
for making HTTP requests over the Tor network.

Requirements:
    uv venv && source .venv/bin/activate
    uv pip install maturin && maturin develop

Run:
    python basic_client.py

Note: Tor network requests can be slow (30-60s+). If running in a
devcontainer or restricted network, timeouts are expected.
"""

from hypertor import AsyncClient, TimeoutError, HypertorError
import asyncio


async def main():
    print("🧅 hypertor - Basic Client Example")
    print("=" * 40)
    
    # Create an async Tor client with longer timeout for Tor network
    async with AsyncClient(timeout=60) as client:
        print("\n✅ Connected to Tor network\n")
        
        # Example 1: Simple GET request
        print("📡 Example 1: Check if we're using Tor")
        try:
            resp = await client.get("https://check.torproject.org/api/ip")
            data = resp.json()
            print(f"   Your Tor IP: {data.get('IP', 'unknown')}")
            print(f"   Using Tor: {data.get('IsTor', False)}")
        except TimeoutError:
            print("   ⏱️  Request timed out (Tor network can be slow)")
        except HypertorError as e:
            print(f"   ⚠️  Error: {e}")
        
        # Example 2: Access an onion service
        print("\n📡 Example 2: Access DuckDuckGo onion")
        try:
            resp = await client.get(
                "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
            )
            print(f"   Status: {resp.status_code}")
            print(f"   Content-Length: {len(resp.text())} bytes")
        except TimeoutError:
            print("   ⏱️  Request timed out (onion services can be slow)")
        except HypertorError as e:
            print(f"   ⚠️  Error: {e}")
        
        # Example 3: POST request with JSON
        print("\n📡 Example 3: POST JSON data")
        try:
            resp = await client.post(
                "https://httpbin.org/post",
                json='{"message": "Hello from Tor!", "anonymous": true}'
            )
            print(f"   Status: {resp.status_code}")
            print(f"   Echo: {resp.json().get('json', {})}")
        except TimeoutError:
            print("   ⏱️  Request timed out")
        except HypertorError as e:
            print(f"   ⚠️  Error: {e}")
        
    print("\n✅ Example completed!")
    print("\n💡 Tip: Tor requests are slow. Timeouts are normal in dev environments.")


if __name__ == "__main__":
    asyncio.run(main())

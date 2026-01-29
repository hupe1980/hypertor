#!/usr/bin/env python3
"""
Multiple Identities - Python Example

This example demonstrates how to use circuit isolation to
maintain multiple anonymous identities simultaneously.

Useful for:
- Accessing multiple accounts without correlation
- Testing from different Tor exit nodes
- Privacy-sensitive operations requiring separation

Each AsyncClient instance maintains its own Tor circuits,
providing natural identity separation.

Requirements:
    uv venv && source .venv/bin/activate
    uv pip install maturin && maturin develop

Run:
    python multiple_identities.py
"""

from hypertor import AsyncClient, TimeoutError, HypertorError
import asyncio


async def main():
    print("🧅 hypertor - Multiple Identities Example")
    print("=" * 50)
    print()
    print("Each AsyncClient creates separate Tor circuits,")
    print("appearing to come from different IP addresses.")
    print()

    # Create multiple isolated clients
    # Each AsyncClient instance has its own circuit isolation
    print("🔄 Creating 3 isolated identities...")
    print()

    identities = [
        AsyncClient(timeout=60),
        AsyncClient(timeout=60),
        AsyncClient(timeout=60),
    ]

    # Enter async contexts
    for i, client in enumerate(identities):
        await client.__aenter__()
        print(f"   Identity {i + 1}: Connected to Tor")

    print()

    # Check each identity's IP
    print("📡 Checking IP addresses for each identity:")
    print("-" * 40)

    ips = []
    for i, client in enumerate(identities):
        try:
            resp = await client.get("https://check.torproject.org/api/ip")
            data = resp.json()
            ip = data.get("IP", "unknown")
            ips.append(ip)
            print(f"   Identity {i + 1}: {ip}")
        except TimeoutError:
            print(f"   Identity {i + 1}: Timeout (Tor network slow)")
            ips.append(None)
        except HypertorError as e:
            print(f"   Identity {i + 1}: Error - {e}")
            ips.append(None)

    # Verify isolation
    print()
    valid_ips = [ip for ip in ips if ip is not None]
    unique_ips = set(valid_ips)

    if len(unique_ips) == len(valid_ips) and len(valid_ips) > 0:
        print("✅ All identities have different IPs!")
        print("   Circuit isolation is working correctly.")
    elif len(unique_ips) > 1:
        print("⚠️  Some identities share IPs (normal for same exit node)")
    elif len(valid_ips) > 0:
        print("⚠️  All identities have the same IP")
        print("   This can happen if Tor reuses the same exit node.")
    else:
        print("⚠️  No IPs retrieved - network may be slow")

    # Demonstrate parallel requests with isolation
    print()
    print("📡 Making parallel requests (isolated):")
    print("-" * 40)

    async def make_request(client, identity_num, url):
        """Make a request and return the result"""
        try:
            resp = await client.get(url)
            return f"Identity {identity_num}: Status {resp.status_code}"
        except TimeoutError:
            return f"Identity {identity_num}: Timeout"
        except HypertorError as e:
            return f"Identity {identity_num}: Error - {e}"

    # Each identity accesses a different service
    services = [
        "https://httpbin.org/ip",
        "https://api.ipify.org?format=json",
        "https://check.torproject.org/api/ip"
    ]

    tasks = [
        make_request(client, i + 1, url)
        for i, (client, url) in enumerate(zip(identities, services))
    ]

    results = await asyncio.gather(*tasks)
    for result in results:
        print(f"   {result}")

    # Cleanup
    print()
    print("🧹 Cleaning up identities...")
    for i, client in enumerate(identities):
        await client.__aexit__(None, None, None)
        print(f"   Identity {i + 1}: Disconnected")

    print()
    print("=" * 50)
    print()
    print("Use Cases for Multiple Identities:")
    print()
    print("1. 🔐 Account Separation")
    print("   - Access different accounts without correlation")
    print("   - Each login appears from a different location")
    print()
    print("2. 🧪 Testing & Scraping")
    print("   - Test geo-restricted content from different exits")
    print("   - Distribute requests across multiple IPs")
    print()
    print("3. 🛡️ Privacy Compartmentalization")
    print("   - Separate work and personal browsing")
    print("   - Isolate sensitive operations")
    print()
    print("✅ Multiple identities example completed!")


if __name__ == "__main__":
    asyncio.run(main())

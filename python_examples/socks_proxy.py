#!/usr/bin/env python3
"""
SOCKS5 Proxy Example

Run a local SOCKS5 proxy that routes any application through Tor.
Once running, any SOCKS5-compatible application can use the proxy.

Usage:
    python socks_proxy.py

Then test with:
    curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip

Or use with Python requests:
    import requests
    proxies = {'https': 'socks5h://127.0.0.1:9050'}
    requests.get('https://check.torproject.org/api/ip', proxies=proxies)
"""

import asyncio
from hypertor import Socks5Proxy, HypertorError


async def main():
    """Start a SOCKS5 proxy server."""
    
    print("=" * 60)
    print("  hypertor SOCKS5 Proxy")
    print("=" * 60)
    print()
    print("Starting SOCKS5 proxy on 127.0.0.1:9050...")
    print("This may take 30-60 seconds while connecting to Tor...")
    print()
    
    try:
        # Create SOCKS5 proxy with default settings
        # Binds to 127.0.0.1:9050 (standard Tor port)
        proxy = Socks5Proxy()
        
        print("✓ Proxy started!")
        print()
        print("Test with:")
        print("  curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip")
        print()
        print("Or in Python:")
        print("  import requests")
        print("  proxies = {'https': 'socks5h://127.0.0.1:9050'}")
        print("  requests.get('https://check.torproject.org/api/ip', proxies=proxies)")
        print()
        print("Press Ctrl+C to stop")
        print("-" * 60)
        
        # Run the proxy (blocks until stopped)
        await proxy.run()
        
    except HypertorError as e:
        print(f"✗ Failed to start proxy: {e}")
        return
    except KeyboardInterrupt:
        print("\n\nProxy stopped.")


async def custom_config_example():
    """Example with custom configuration."""
    
    from hypertor import Socks5Proxy, ProxyConfig
    
    # Custom configuration
    config = ProxyConfig(
        host="127.0.0.1",
        port=1080,  # Custom port
        isolation_by_auth=True,  # Different auth = different Tor circuit
    )
    
    proxy = Socks5Proxy(config=config)
    
    print("Custom SOCKS5 proxy on 127.0.0.1:1080")
    print("With authentication-based isolation enabled")
    
    await proxy.run()


async def multi_identity_proxies():
    """Run multiple proxies with separate identities."""
    
    from hypertor import Socks5Proxy, ProxyConfig
    
    # Create two proxies with different ports = different Tor circuits
    proxy1_config = ProxyConfig(host="127.0.0.1", port=9051)
    proxy2_config = ProxyConfig(host="127.0.0.1", port=9052)
    
    proxy1 = Socks5Proxy(config=proxy1_config)
    proxy2 = Socks5Proxy(config=proxy2_config)
    
    print("Multi-identity SOCKS5 proxies:")
    print("  - Identity A: 127.0.0.1:9051")
    print("  - Identity B: 127.0.0.1:9052")
    print()
    print("Each proxy uses a separate Tor circuit!")
    
    # Run both proxies concurrently
    await asyncio.gather(
        proxy1.run(),
        proxy2.run()
    )


if __name__ == "__main__":
    asyncio.run(main())

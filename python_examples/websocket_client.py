#!/usr/bin/env python3
"""
WebSocket over Tor - Conceptual Example

This example demonstrates conceptual patterns for WebSocket-like
real-time communication over Tor. While hypertor's current API
focuses on HTTP requests, you can achieve real-time patterns
using polling or Server-Sent Events.

For true WebSocket support over Tor, consider using:
- aiohttp with a SOCKS5 proxy (Tor)
- websockets library with PySocks

This example shows practical alternatives using hypertor's AsyncClient.

Requirements:
    uv venv && source .venv/bin/activate
    uv pip install maturin && maturin develop

Run:
    python websocket_client.py
"""

from hypertor import AsyncClient, TimeoutError, HypertorError
import asyncio
import json
import time


async def polling_realtime_example():
    """
    Simulate real-time updates using long polling over Tor.
    
    Long polling is a common pattern when WebSockets aren't available.
    The client makes a request that the server holds open until
    new data is available, then immediately makes another request.
    """
    print("🧅 Real-time Updates via Long Polling")
    print("-" * 40)
    print()
    print("Long polling pattern over Tor:")
    print()
    print("  1. Client sends request to server")
    print("  2. Server holds connection until data is available (or timeout)")
    print("  3. Server responds with new data")
    print("  4. Client immediately sends new request")
    print()
    
    # Demonstrate with a real HTTP endpoint
    async with AsyncClient(timeout=30) as client:
        print("📡 Demonstrating polling with httpbin.org via Tor...")
        print()
        
        # Simulate 3 polling cycles
        for i in range(3):
            start = time.time()
            
            # In real long-polling, this would be a /poll endpoint
            # that waits for new messages
            response = await client.get(
                f"https://httpbin.org/delay/1"  # Simulates server holding request
            )
            
            elapsed = time.time() - start
            
            if response.status_code == 200:
                print(f"   📥 Poll {i+1}: Got response after {elapsed:.1f}s")
                # In real app: process new messages here
            else:
                print(f"   ⚠️  Poll {i+1}: Status {response.status_code}")
            
            # Small delay before next poll (in real app, this would be immediate)
            if i < 2:
                await asyncio.sleep(0.5)
        
        print()
        print("   ✅ Polling demonstration complete")


async def event_stream_pattern():
    """
    Explain Server-Sent Events (SSE) pattern over Tor.
    
    SSE is a simpler alternative to WebSockets for server-to-client
    streaming. The server sends a stream of events over a single
    HTTP connection.
    """
    print("\n🧅 Server-Sent Events (SSE) Pattern")
    print("-" * 40)
    print()
    print("SSE is ideal for server→client streaming over Tor:")
    print()
    print("""
Example SSE Server (using OnionApp):

    from hypertor import OnionApp, Request
    
    app = OnionApp()
    
    @app.route("/events")
    async def event_stream(request: Request):
        async def generate():
            while True:
                data = await get_next_event()
                yield f"data: {json.dumps(data)}\\n\\n"
        
        return StreamingResponse(
            generate(),
            media_type="text/event-stream"
        )

Example SSE Client:

    async with AsyncClient(timeout=300) as client:
        # Long timeout for streaming
        response = await client.get("http://xxx.onion/events")
        
        # Process events as they arrive
        async for line in response.iter_lines():
            if line.startswith("data: "):
                event = json.loads(line[6:])
                process_event(event)
    """)


async def bidirectional_pattern():
    """
    Show pattern for bidirectional communication over Tor HTTP.
    
    Without WebSockets, you can achieve bidirectional communication
    using two separate connections: one for sending, one for receiving.
    """
    print("\n🧅 Bidirectional Communication Pattern")
    print("-" * 40)
    print()
    print("Achieve WebSocket-like bidirectional communication:")
    print()
    print("""
Pattern: Separate send/receive channels

    async def chat_client(onion_address: str):
        async with AsyncClient(timeout=60) as client:
            
            # Task 1: Send messages
            async def sender():
                while True:
                    message = await get_user_input()
                    await client.post(
                        f"http://{onion_address}/send",
                        json=json.dumps({"text": message})
                    )
            
            # Task 2: Receive messages (long polling)
            async def receiver():
                last_id = 0
                while True:
                    response = await client.get(
                        f"http://{onion_address}/poll?after={last_id}"
                    )
                    messages = response.json()
                    for msg in messages:
                        print(f"Received: {msg['text']}")
                        last_id = max(last_id, msg['id'])
            
            # Run both concurrently
            await asyncio.gather(sender(), receiver())
    """)


async def websocket_with_socks_example():
    """
    Show how to use actual WebSockets over Tor with external libraries.
    """
    print("\n🧅 True WebSockets over Tor (External Libraries)")
    print("-" * 40)
    print()
    print("For true WebSocket support, use these libraries with Tor's SOCKS proxy:")
    print()
    print("""
Option 1: websockets + python-socks

    import asyncio
    from python_socks.async_.asyncio.v2 import Proxy
    from websockets import connect
    
    async def ws_over_tor():
        proxy = Proxy.from_url("socks5://127.0.0.1:9050")
        
        async with connect(
            "wss://echo.websocket.events",
            proxy=proxy
        ) as ws:
            await ws.send("Hello via Tor!")
            response = await ws.recv()
            print(f"Received: {response}")

Option 2: aiohttp with SOCKS

    import aiohttp
    from aiohttp_socks import ProxyConnector
    
    async def ws_over_tor():
        connector = ProxyConnector.from_url("socks5://127.0.0.1:9050")
        
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.ws_connect("wss://echo.websocket.events") as ws:
                await ws.send_str("Hello via Tor!")
                msg = await ws.receive()
                print(f"Received: {msg.data}")

Note: These require Tor daemon running with SOCKS proxy on port 9050.
hypertor uses arti (Rust Tor implementation) which doesn't expose a SOCKS proxy.
    """)


async def demonstrate_http_chat():
    """
    Actually demonstrate a simple request/response pattern over Tor.
    """
    print("\n🧅 Live Demo: HTTP Request/Response over Tor")
    print("-" * 40)
    
    async with AsyncClient(timeout=60) as client:
        print("\n📡 Sending message to httpbin.org via Tor...")
        
        # Simulate sending a chat message
        message = {
            "user": "anonymous",
            "text": "Hello from Tor!",
            "timestamp": int(time.time())
        }
        
        response = await client.post(
            "https://httpbin.org/post",
            json=json.dumps(message)
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Message sent successfully")
            print(f"   📍 Via Tor exit: {data.get('origin', 'unknown')}")
            print(f"   📦 Server received: {data.get('json', {})}")
        else:
            print(f"   ❌ Error: {response.status_code}")


async def main():
    print("🧅 hypertor - Real-time Communication Patterns")
    print("=" * 50)
    print()
    print("While hypertor focuses on HTTP, you can achieve real-time")
    print("communication patterns. This example shows how.")
    print()
    
    try:
        # Show polling pattern with live demo
        await polling_realtime_example()
        
        # Show SSE pattern (documentation)
        await event_stream_pattern()
        
        # Show bidirectional pattern (documentation)
        await bidirectional_pattern()
        
        # Show WebSocket alternatives (documentation)
        await websocket_with_socks_example()
        
        # Live demo of HTTP chat pattern
        await demonstrate_http_chat()
        
        print("\n" + "=" * 50)
        print("✅ Real-time patterns demonstration completed!")
        print()
        print("Key takeaways:")
        print("  • Long polling works well for real-time over Tor")
        print("  • SSE provides server→client streaming")
        print("  • Bidirectional achieved with send/receive channels")
        print("  • True WebSockets need external libs + SOCKS proxy")
        
    except KeyboardInterrupt:
        print("\n\n🛑 Interrupted by user")
    except TimeoutError:
        print("\n❌ Request timed out (Tor network may be slow)")
    except HypertorError as e:
        print(f"\n❌ Hypertor error: {e}")
    except Exception as e:
        print(f"\n❌ Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())

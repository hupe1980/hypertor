#!/usr/bin/env python3
"""
Onion Service with FastAPI-like API - Python Example

This example demonstrates how to use hypertor's OnionApp
to create an anonymous web service hosted as a Tor onion.

The API is designed to feel like FastAPI/Flask with decorators.

Requirements:
    pip install hypertor

Run:
    python onion_service.py
"""

from hypertor import OnionApp
from dataclasses import dataclass
from typing import Optional
import json


# Create the OnionApp (like FastAPI())
app = OnionApp()


# =============================================================================
# Route Handlers - Just like FastAPI!
# =============================================================================

@app.get("/")
async def homepage():
    """Root endpoint - returns welcome message"""
    return {
        "service": "hypertor-example",
        "message": "Welcome to my anonymous onion service! 🧅",
        "endpoints": ["/", "/api/info", "/api/echo", "/api/health"]
    }


@app.get("/api/info")
async def service_info():
    """Returns service information"""
    return {
        "name": "HyperTor Example Service",
        "version": "1.0.0",
        "anonymous": True,
        "powered_by": "hypertor"
    }


@app.get("/api/health")
async def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy",
        "tor_connected": True
    }


@app.post("/api/echo")
async def echo(request):
    """Echo back the JSON body"""
    try:
        body = await request.json()
        return {
            "echoed": body,
            "message": "Your data was received anonymously!"
        }
    except Exception:
        return {"error": "Invalid JSON body"}, 400


# =============================================================================
# Data model example
# =============================================================================

@dataclass
class Message:
    content: str
    sender: Optional[str] = "anonymous"

# Simple in-memory storage (for demo purposes)
messages: list[Message] = []


@app.get("/api/messages")
async def list_messages():
    """List all messages"""
    return {
        "count": len(messages),
        "messages": [
            {"content": m.content, "sender": m.sender}
            for m in messages
        ]
    }


@app.post("/api/messages")
async def create_message(request):
    """Create a new message"""
    try:
        data = await request.json()
        msg = Message(
            content=data.get("content", ""),
            sender=data.get("sender", "anonymous")
        )
        messages.append(msg)
        return {
            "success": True,
            "message": "Message created",
            "data": {"content": msg.content, "sender": msg.sender}
        }, 201
    except Exception as e:
        return {"error": str(e)}, 400


# =============================================================================
# Middleware example
# =============================================================================

@app.middleware
async def logging_middleware(request, call_next):
    """Log all requests (anonymously - no IPs stored!)"""
    print(f"📨 Request: {request.method} {request.path}")
    response = await call_next(request)
    print(f"📤 Response: {response.status_code}")
    return response


# =============================================================================
# Main entry point
# =============================================================================

async def main():
    print("🧅 hypertor - Onion Service Example")
    print("=" * 50)
    print()
    print("Starting onion service...")
    print()
    
    # Run the service
    # This will:
    # 1. Connect to the Tor network
    # 2. Create an onion service
    # 3. Print your .onion address
    # 4. Start accepting connections
    
    await app.run(
        # Optional: specify a persistent key directory
        # key_dir="/path/to/keys",
        
        # Optional: set the port (default: 80)
        # port=8080,
    )


if __name__ == "__main__":
    import asyncio
    
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║  HyperTor Onion Service                                      ║
    ║                                                              ║
    ║  This will create a real .onion address accessible via Tor  ║
    ║  Share your .onion URL only with trusted parties!           ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass  # Graceful shutdown already handled

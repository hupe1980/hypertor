---
title: "Installation"
permalink: /docs/installation/
excerpt: "Platform-specific installation instructions"
---

Get hypertor installed on your system.

## Rust

### Requirements

- Rust 1.85+ (edition 2024)
- A C compiler (for native dependencies)

### Add to Cargo.toml

```toml
[dependencies]
hypertor = "0.4"
tokio = { version = "1", features = ["full"] }
```

### Optional Features

```toml
[dependencies]
hypertor = { version = "0.3", features = [
    "full",        # All features
    "metrics",     # Prometheus metrics
    "tracing",     # Distributed tracing
    "http2",       # HTTP/2 support
    "websocket",   # WebSocket support
    "grpc",        # gRPC support
] }
```

### Verify Installation

```rust
use hypertor::TorClient;

#[tokio::main]
async fn main() {
    println!("hypertor version: {}", hypertor::VERSION);
    
    // Create client (bootstraps Tor)
    let client = TorClient::new().await
        .expect("Failed to connect to Tor");
    
    println!("Connected to Tor network!");
}
```

## Python

### Requirements

- Python 3.9+
- Supported platforms: Linux (x86_64, aarch64), macOS (Intel, Apple Silicon), Windows

### Install from PyPI

```bash
# Install the latest version
pip install hypertor

# Or with optional dependencies
pip install hypertor[pydantic]  # For type validation
```

### Install from Source

For development or to get the latest features:

```bash
# Requires Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and install
git clone https://github.com/hupe1980/hypertor
cd hypertor
pip install maturin
maturin develop --release
```

### Verify Installation

```python
import hypertor

print(f"hypertor version: {hypertor.__version__}")

# Quick test
import asyncio
from hypertor import AsyncClient

async def test():
    async with AsyncClient(timeout=60) as client:
        print("Connected to Tor network!")

asyncio.run(test())
```

## Platform Notes

### Linux

hypertor works out of the box on most Linux distributions. For Debian/Ubuntu:

```bash
# Install build dependencies (if building from source)
sudo apt-get install build-essential pkg-config libssl-dev
```

### macOS

Works on both Intel and Apple Silicon. You may need:

```bash
# Install Xcode command line tools
xcode-select --install

# OpenSSL via Homebrew (if building from source)
brew install openssl
export OPENSSL_DIR=$(brew --prefix openssl)
```

### Windows

Pre-built wheels are available. For building from source, install Visual Studio Build Tools and Rust.

## Docker

Pre-built Docker images are available:

```bash
# Pull the image
docker pull ghcr.io/hupe1980/hypertor:latest

# Run with your application
docker run -it --rm ghcr.io/hupe1980/hypertor:latest
```

### Dockerfile Example

```dockerfile
FROM rust:1.75-slim AS builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/myapp /usr/local/bin/

CMD ["myapp"]
```

## Troubleshooting

### "Connection timeout" on first run

Tor bootstrapping can take 30-60 seconds on first connect while downloading consensus and building circuits. This is normal.

### OpenSSL not found (build from source)

Set the `OPENSSL_DIR` environment variable to your OpenSSL installation path:

```bash
# macOS
export OPENSSL_DIR=$(brew --prefix openssl)

# Linux
export OPENSSL_DIR=/usr
```

### "Permission denied" when running

hypertor needs network access. Make sure your firewall isn't blocking outgoing connections to Tor directory authorities and relays.

## Getting Help

- [GitHub Issues](https://github.com/hupe1980/hypertor/issues) — Bug reports and feature requests
- [GitHub Discussions](https://github.com/hupe1980/hypertor/discussions) — Questions and community help

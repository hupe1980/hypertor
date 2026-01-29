# hypertor justfile - common development tasks

# Default recipe
default:
    @just --list

# Run all checks (quick)
check: fmt-check lint test

# Run full pre-release checks
check-full:
    ./scripts/check.sh --full

# Run quick pre-release checks
check-quick:
    ./scripts/check.sh --quick

# Run release-ready checks
check-release:
    ./scripts/check.sh --release

# Format code
fmt:
    cargo fmt
    uvx ruff format python/

# Check formatting
fmt-check:
    cargo fmt --check
    uvx ruff format --check python/

# Lint
lint:
    cargo clippy --lib --all-features -- -D warnings
    uvx ruff check python/

# Run tests
test:
    cargo test --lib --features="client,server,http2,padding,native-tls"

# Run all tests including security and integration
test-all:
    cargo test --features="client,server,http2,padding,native-tls"
    cargo test --test security --features="client,server,http2,padding,native-tls"
    cargo test --test integration --features="client,server,http2,padding,native-tls"

# Run security tests only
test-security:
    cargo test --test security --features="client,server,http2,padding,native-tls"

# Run cargo deny checks
deny:
    cargo deny check

# Build Python wheel (development)
build-py:
    maturin develop --features python

# Build Python wheel (release)
build-py-release:
    maturin build --release --features python

# Install dev dependencies
setup:
    uv sync --all-extras

# Clean build artifacts
clean:
    cargo clean
    rm -rf target/ dist/ *.egg-info/

# Run example
example name="basic_usage":
    cargo run --example {{name}}

# Start SOCKS5 proxy (requires Tor bootstrap)
proxy port="9050":
    cargo run --example proxy -- --port {{port}}

# Serve documentation locally with GitHub Pages
docs:
    cd docs && bundle exec jekyll serve --livereload --config _config.yml,_config_dev.yml

# Install documentation dependencies
docs-setup:
    cd docs && bundle install

# hypertor — common development tasks

default:
    @just --list

# Fast pre-commit checks
check: fmt-check lint test

# Everything CI runs
check-all: fmt-check lint test test-py-rs test-features test-py typecheck-py docs site-build audit

# Format
fmt:
    cargo fmt --all
    cd bindings/python && uvx ruff format hypertor/ tests/ examples/

fmt-check:
    cargo fmt --all -- --check
    cd bindings/python && uvx ruff format --check hypertor/ tests/ examples/

# Lint
lint:
    cargo clippy --all-targets --features full -- -D warnings
    cargo clippy -p hypertor-python --all-targets -- -D warnings
    cd bindings/python && uvx ruff check hypertor/ tests/ examples/

# Rust tests (offline). The bindings are a separate crate and need an
# interpreter to link against, so they are a target of their own; see test-py-rs.
test:
    cargo test --features full

# The bindings crate's own Rust tests: the handler-return-value contract the
# Python OnionApp rests on. Needs a Python whose libdir exists — set PYO3_PYTHON
# if the default interpreter is a stub (macOS ships one under Xcode).
test-py-rs:
    cargo test -p hypertor-python

# Tests that need a live Tor connection
test-live:
    cargo test --features full -- --ignored --nocapture

# Python tests (offline)
test-py: build-py
    cd bindings/python && uv run pytest -v

# Python tests including live network
test-py-live: build-py
    cd bindings/python && uv run pytest -v -m network

# Type-check the Python stubs
typecheck-py:
    cd bindings/python && uv run mypy hypertor

# Feature-combination checks
test-features:
    cargo check --no-default-features
    cargo check --no-default-features --features "client,rustls"
    cargo check --no-default-features --features "client,native-tls"
    cargo check --no-default-features --features "server,rustls"
    cargo check --features full

# Docs
docs:
    cargo doc --features full --no-deps

docs-open:
    cargo doc --features full --no-deps --open

# Supply chain
audit:
    cargo audit
    cargo deny check bans advisories sources

# Benchmarks
bench:
    cargo bench --features full

# Python extension. Everything for the bindings — the Rust crate, the Python
# package, its tests, examples and pyproject.toml — lives in bindings/python.
build-py:
    cd bindings/python && maturin develop

build-py-release:
    cd bindings/python && maturin build --release

# Examples
example name="client":
    cargo run --example {{name}} --features full

# Documentation site (Zola). Install with: brew install zola
site:
    cd site && zola serve

site-build:
    cd site && zola build

# Fails on a broken internal link, which is what documentation actually suffers
# from. External links are checked too, so this needs the network.
site-check:
    cd site && zola check

# Dev environment
setup:
    cd bindings/python && uv sync --all-extras

clean:
    cargo clean
    rm -rf target/ dist/ *.egg-info/ site/public/

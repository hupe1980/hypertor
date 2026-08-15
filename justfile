# hypertor — common development tasks

default:
    @just --list

# Fast pre-commit checks
check: fmt-check lint test

# Everything CI runs
check-all: fmt-check lint test test-py docs audit

# Format
fmt:
    cargo fmt --all
    uvx ruff format python/ python_examples/

fmt-check:
    cargo fmt --all -- --check
    uvx ruff format --check python/ python_examples/

# Lint
lint:
    cargo clippy --all-targets --features full -- -D warnings
    uvx ruff check python/ python_examples/

# Rust tests (offline)
test:
    cargo test --features full

# Tests that need a live Tor connection
test-live:
    cargo test --features full -- --ignored --nocapture

# Python tests (offline)
test-py: build-py
    uv run pytest python/tests -v

# Python tests including live network
test-py-live: build-py
    uv run pytest python/tests -v -m network

# Feature-combination checks
test-features:
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

# Python extension
build-py:
    maturin develop --features python

build-py-release:
    maturin build --release --features python

# Examples
example name="client":
    cargo run --example {{name}} --features full

# Documentation site
site:
    cd docs && bundle exec jekyll serve --livereload --config _config.yml,_config_dev.yml

site-setup:
    cd docs && bundle install

# Dev environment
setup:
    uv sync --all-extras

clean:
    cargo clean
    rm -rf target/ dist/ *.egg-info/ docs/_site/

#!/usr/bin/env bash
# =============================================================================
# hypertor Pre-Release Check Script
# =============================================================================
# Run all CI checks locally before pushing or releasing.
# Usage: ./scripts/check.sh [--quick|--full|--release]
#
# Options:
#   --quick    Run fast checks only (fmt, clippy, unit tests)
#   --full     Run all checks including slow ones (default)
#   --release  Run release-ready checks (full + package verification)
# =============================================================================

set -uo pipefail

# Enable errexit for main script but not for subcommands
trap 'echo "Error on line $LINENO"; exit 1' ERR

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default mode
MODE="${1:---full}"

# Track results
PASSED=0
FAILED=0
SKIPPED=0

# -----------------------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------------------

print_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
}

print_step() {
    echo -e "\n${YELLOW}▶ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
    ((PASSED++))
}

print_failure() {
    echo -e "${RED}✗ $1${NC}"
    ((FAILED++))
}

print_skip() {
    echo -e "${YELLOW}⊘ $1 (skipped)${NC}"
    ((SKIPPED++))
}

run_check() {
    local name="$1"
    shift
    print_step "$name"
    if "$@" 2>&1; then
        print_success "$name passed"
        return 0
    else
        local exit_code=$?
        print_failure "$name failed (exit code: $exit_code)"
        return 1
    fi
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}Error: $1 is not installed${NC}"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Checks
# -----------------------------------------------------------------------------

check_toolchain() {
    print_header "Toolchain Verification"
    
    print_step "Checking Rust version"
    rustc --version
    cargo --version
    
    # Check MSRV compatibility
    local msrv="1.86"
    local current_version
    current_version=$(rustc --version | grep -oE '[0-9]+\.[0-9]+' | head -1)
    
    if [[ "$(printf '%s\n' "$msrv" "$current_version" | sort -V | head -n1)" == "$msrv" ]]; then
        print_success "Rust version >= $msrv (MSRV)"
    else
        print_failure "Rust version < $msrv (MSRV requires $msrv)"
    fi
}

check_tls_backend_required() {
    print_header "TLS Backend Validation"
    
    print_step "Verifying compile-time TLS requirement"
    
    # The library should fail to compile without a TLS backend
    # This validates our compile_error! guard works correctly
    local output
    output=$(cargo check --no-default-features 2>&1)
    
    # Check for our custom error message (may be split across lines)
    if echo "$output" | grep -q "requires a TLS backend"; then
        print_success "TLS backend requirement enforced correctly"
    else
        # Check if it actually compiled (which would be wrong)
        if echo "$output" | grep -q "Finished"; then
            print_failure "Library compiled without TLS backend (should fail)"
            return 1
        else
            print_failure "TLS backend check failed with unexpected error"
            echo "$output" | head -15
            return 1
        fi
    fi
}

check_format() {
    print_header "Code Formatting"
    echo "Running: cargo fmt --all -- --check"
    if cargo fmt --all -- --check 2>&1; then
        print_success "cargo fmt --check passed"
    else
        print_failure "cargo fmt --check failed"
        return 1
    fi
}

check_clippy_lib() {
    print_header "Clippy Lints (Library)"
    
    # Features to test (excluding python which requires Python env)
    # Using rustls as it's the default and recommended for security
    local features="client,server,http2,padding,rustls"
    
    run_check "cargo clippy (lib)" \
        cargo clippy --lib --features="$features" -- -D warnings
}

check_clippy_tests() {
    print_header "Clippy Lints (Tests & Examples)"
    
    local features="client,server,http2,padding,rustls"
    
    # For tests, allow common test patterns that would be warnings in production code
    run_check "cargo clippy (tests)" \
        cargo clippy --tests --examples --benches --features="$features"
}

check_unit_tests() {
    print_header "Unit Tests"
    
    local features="client,server,http2,padding,rustls"
    
    run_check "cargo test (lib)" \
        cargo test --lib --features="$features"
}

check_security_tests() {
    print_header "Security Tests"
    
    local features="client,server,http2,padding,rustls"
    
    run_check "cargo test (security)" \
        cargo test --test security --features="$features"
}

check_integration_tests() {
    print_header "Integration Tests"
    
    local features="client,server,http2,padding,rustls"
    
    run_check "cargo test (integration)" \
        cargo test --test integration --features="$features"
}

check_doc_tests() {
    print_header "Documentation Tests"
    
    local features="client,server,http2,padding,rustls"
    
    run_check "cargo test (doc)" \
        cargo test --doc --features="$features"
}

check_docs() {
    print_header "Documentation Build"
    
    run_check "cargo doc" \
        cargo doc --all-features --no-deps
}

check_feature_combinations() {
    print_header "Feature Combinations"
    
    local -a features=(
        ""
        "client"
        "server"
        "rustls"
        "native-tls"
        "http2"
        "padding"
        "client,server,http2"
    )
    
    for feat in "${features[@]}"; do
        local name="features: ${feat:-default}"
        run_check "$name" cargo check --features="$feat" || true
    done
}

check_deny() {
    print_header "Cargo Deny (Bans & Advisories)"
    
    if check_command cargo-deny; then
        # Skip license check - upstream crates change licenses frequently
        run_check "cargo deny" cargo deny check bans advisories sources
    else
        print_skip "cargo deny (install with: cargo install cargo-deny)"
    fi
}

check_audit() {
    print_header "Security Audit"
    
    if check_command cargo-audit; then
        # Note: We expect RUSTSEC-2023-0071 (rsa Marvin attack) due to arti dependencies
        # This is documented in deny.toml and cannot be fixed until arti updates
        if cargo audit --ignore RUSTSEC-2023-0071 2>&1; then
            print_success "cargo audit passed"
        else
            print_failure "cargo audit failed"
        fi
    else
        print_skip "cargo audit (install with: cargo install cargo-audit)"
    fi
}

check_semver() {
    print_header "Semver Compatibility"
    
    if check_command cargo-semver-checks; then
        # Note: For pre-1.0 versions, breaking changes are allowed per semver
        # This check is informational only - failures don't block release
        print_step "cargo semver-checks (informational for pre-1.0)"
        if cargo semver-checks check-release --default-features 2>&1; then
            print_success "cargo semver-checks passed"
        else
            echo -e "${YELLOW}⚠ Semver breaking changes detected (allowed for pre-1.0)${NC}"
            ((SKIPPED++))
        fi
    else
        print_skip "cargo semver-checks (install with: cargo install cargo-semver-checks)"
    fi
}

check_package() {
    print_header "Package Verification"
    
    local features="client,server,http2,padding,native-tls"
    run_check "cargo package" cargo package --features="$features" --allow-dirty
}

check_publish_dry_run() {
    print_header "Publish Dry Run"
    
    local features="client,server,http2,padding,native-tls"
    run_check "cargo publish --dry-run" cargo publish --dry-run --features="$features" --allow-dirty
}

check_benchmarks() {
    print_header "Benchmarks (Compile Only)"
    
    local features="client,server,http2,padding,native-tls"
    run_check "cargo bench (compile)" cargo bench --no-run --features="$features"
}

check_unsafe() {
    print_header "Unsafe Code Check"
    
    print_step "Checking for unexpected unsafe code"
    
    # Look for unsafe blocks that aren't properly documented
    local unsafe_count
    unsafe_count=$(grep -r "unsafe" src/*.rs 2>/dev/null | \
        grep -v "forbid(unsafe_code)" | \
        grep -v "// SAFETY:" | \
        grep -v "#\[" | \
        wc -l | tr -d '[:space:]' || echo "0")
    
    if [[ "$unsafe_count" -eq 0 ]]; then
        print_success "No unexpected unsafe code found"
    else
        echo "Found $unsafe_count potential unsafe usages:"
        grep -r "unsafe" src/*.rs 2>/dev/null | \
            grep -v "forbid(unsafe_code)" | \
            grep -v "// SAFETY:" | \
            grep -v "#\[" | head -5 || true
        print_failure "Found unexpected unsafe code"
    fi
}

check_todo_fixme() {
    print_header "TODO/FIXME Check"
    
    print_step "Checking for TODO/FIXME comments in source"
    
    local count
    count=$(grep -rE "TODO|FIXME" src/*.rs 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
    
    if [[ "$count" -eq 0 ]]; then
        print_success "No TODO/FIXME comments found"
    else
        echo "Found $count TODO/FIXME comments:"
        grep -rE "TODO|FIXME" src/*.rs 2>/dev/null | head -10 || true
        echo -e "${YELLOW}(This is informational, not a failure)${NC}"
        ((SKIPPED++))
    fi
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

main() {
    print_header "hypertor Pre-Release Checks"
    echo "Mode: $MODE"
    echo "Date: $(date)"
    
    # Always run these
    check_toolchain
    check_tls_backend_required
    check_format
    check_clippy_lib
    check_unit_tests
    
    if [[ "$MODE" == "--quick" ]]; then
        echo ""
        print_header "Quick checks complete (use --full for all checks)"
    else
        # Full checks
        check_clippy_tests
        check_security_tests
        check_integration_tests
        check_doc_tests
        check_docs
        check_feature_combinations
        check_deny
        check_unsafe
        check_todo_fixme
        
        if [[ "$MODE" == "--release" ]]; then
            # Release-specific checks
            check_audit
            check_semver
            check_benchmarks
            check_package
            check_publish_dry_run
        fi
    fi
    
    # Summary
    print_header "Summary"
    echo -e "${GREEN}Passed:  $PASSED${NC}"
    echo -e "${RED}Failed:  $FAILED${NC}"
    echo -e "${YELLOW}Skipped: $SKIPPED${NC}"
    
    if [[ "$FAILED" -gt 0 ]]; then
        echo ""
        echo -e "${RED}Some checks failed. Please fix issues before releasing.${NC}"
        exit 1
    else
        echo ""
        echo -e "${GREEN}All checks passed! Ready for release.${NC}"
        exit 0
    fi
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi

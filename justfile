# Show the project commands when `just` is run without arguments.
default:
    @just --list

# Run the same quality gates as CI.
check: fmt-check lint test opencode-test nix-eval

# Format Rust sources.
fmt:
    cargo fmt

# Verify formatting without changing files.
fmt-check:
    cargo fmt --check

# Reject compiler and Clippy warnings.
lint:
    cargo clippy --all-targets -- -D warnings

# Run the complete test suite.
test:
    cargo test --all-targets

# Test the OpenCode adapter.
opencode-test:
    node --test integrations/opencode.test.mjs

# Evaluate every supported Nix system without building.
nix-eval:
    nix flake check --all-systems --no-build

# Print detection quality metrics.
report:
    cargo test --test corpus_report -- --nocapture

# Build the optimized binary.
build:
    cargo build --release

# Open the live audit Console with default configuration.
console:
    cargo run -- console

# Open the live audit Console with an explicit configuration.
console-config config:
    cargo run -- console --config "{{ config }}"
